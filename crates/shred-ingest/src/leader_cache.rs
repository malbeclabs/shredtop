//! Leader schedule cache for shred race filtering.
//!
//! Fetches the Solana leader schedule and cluster node list via RPC, then
//! builds a `slot → leader_pubkey` map and a `gossip_ip → pubkey` map.
//!
//! Also fetches DZ serviceability program accounts to build a
//! `dz_overlay_ip → client_ip` map. This lets `is_leader` resolve a packet's
//! `src_ip` (which on DoubleZero multicast is the validator's DZ overlay IP,
//! not its gossip IP) back to the validator's identity pubkey.
//!
//! Resolution chain: `src_ip → [dz_ip_to_client_ip] → gossip_ip → pubkey → is_leader`
//!
//! Used by [`crate::shred_race::PublisherTracker`] to skip shred arrivals
//! whose source is not the scheduled slot leader.

use dashmap::DashMap;
use solana_client::rpc_client::RpcClient;
use solana_client::rpc_config::RpcProgramAccountsConfig;
use solana_client::rpc_filter::{Memcmp, RpcFilterType};
use solana_pubkey::Pubkey;
use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// DZ serviceability constants
// ---------------------------------------------------------------------------

/// On-chain program ID for the DoubleZero serviceability smart contract (mainnet).
const DZ_SERVICEABILITY_PROGRAM: &str = "ser2VaTMAcYTaauMrTSfSrxBaUDq7BLNs2xfUugTAGv";

/// Byte 0 of a DZ User account equals this discriminant (AccountType::User = 7).
const DZ_USER_DISCRIMINATOR: u8 = 7;

/// Byte offset of `ClientIp` ([u8; 4] BE) in a DZ User account.
const DZ_CLIENT_IP_OFFSET: usize = 116;

/// Byte offset of `DzIp` ([u8; 4] BE) in a DZ User account.
const DZ_DZ_IP_OFFSET: usize = 120;

/// Public mainnet RPC used to fetch DZ program accounts when no override is configured.
const DZ_DEFAULT_RPC: &str = "https://api.mainnet-beta.solana.com";

// ---------------------------------------------------------------------------
// LeaderCache
// ---------------------------------------------------------------------------

pub struct LeaderCache {
    /// Maps absolute slot → leader identity pubkey bytes.
    slot_to_pubkey: DashMap<u64, [u8; 32]>,
    /// Maps gossip IPv4 (big-endian u32) → validator identity pubkey bytes.
    gossip_ip_to_pubkey: DashMap<u32, [u8; 32]>,
    /// Maps DZ overlay IPv4 (big-endian u32) → client/gossip IPv4 (big-endian u32).
    dz_ip_to_client_ip: DashMap<u32, u32>,
}

impl LeaderCache {
    /// Spawns a background thread that populates and refreshes the cache.
    ///
    /// `rpc_url` is used for `getLeaderSchedule` and `getClusterNodes`.
    /// `dz_rpc_url` is used for `getProgramAccounts` on the DZ serviceability
    /// program; defaults to the public mainnet-beta RPC when `None`.
    pub fn new(rpc_url: &str, dz_rpc_url: Option<&str>) -> Arc<Self> {
        let cache = Arc::new(Self {
            slot_to_pubkey: DashMap::new(),
            gossip_ip_to_pubkey: DashMap::new(),
            dz_ip_to_client_ip: DashMap::new(),
        });
        let cache_bg = cache.clone();
        let url = rpc_url.to_string();
        let dz_url = dz_rpc_url.unwrap_or(DZ_DEFAULT_RPC).to_string();

        std::thread::Builder::new()
            .name("leader-cache".into())
            .spawn(move || {
                let client = RpcClient::new(url);
                let dz_client = RpcClient::new(dz_url);
                let mut last_epoch = u64::MAX;

                loop {
                    match client.get_epoch_info() {
                        Ok(ei) => {
                            if ei.epoch != last_epoch {
                                match refresh(&client, &dz_client, &cache_bg, ei.absolute_slot, ei.slot_index) {
                                    Ok(()) => {
                                        last_epoch = ei.epoch;
                                        tracing::info!(
                                            epoch = ei.epoch,
                                            slots = cache_bg.slot_to_pubkey.len(),
                                            gossip_nodes = cache_bg.gossip_ip_to_pubkey.len(),
                                            dz_users = cache_bg.dz_ip_to_client_ip.len(),
                                            "leader cache refreshed"
                                        );
                                    }
                                    Err(e) => {
                                        tracing::warn!("leader cache refresh failed: {}", e);
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!("leader cache: get_epoch_info failed: {}", e);
                        }
                    }

                    std::thread::sleep(std::time::Duration::from_secs(60));
                }
            })
            .expect("failed to spawn leader-cache thread");

        cache
    }

    /// Returns true if `src_ip` (big-endian u32) is the scheduled leader for `slot`.
    ///
    /// Resolution: DZ overlay IP → client/gossip IP → validator pubkey → leader check.
    /// Falls back to treating `src_ip` as a direct gossip IP if not found in the DZ map.
    /// Returns false if the slot is not in the cache or the IP cannot be resolved.
    pub fn is_leader(&self, slot: u64, src_ip: u32) -> bool {
        let leader_pk = match self.slot_to_pubkey.get(&slot) {
            Some(pk) => *pk,
            None => return false,
        };
        // Try DZ overlay IP → client/gossip IP; fall back to direct IP.
        let resolved = self.dz_ip_to_client_ip.get(&src_ip)
            .map(|ip| *ip)
            .unwrap_or(src_ip);
        self.gossip_ip_to_pubkey.get(&resolved)
            .map(|pk| *pk == leader_pk)
            .unwrap_or(false)
    }

    /// Returns true if the leader for `slot` is present in the cache.
    pub fn slot_known(&self, slot: u64) -> bool {
        self.slot_to_pubkey.contains_key(&slot)
    }

    /// Returns the scheduled leader pubkey bytes for `slot`, or `None` if not in cache.
    pub fn leader_for_slot(&self, slot: u64) -> Option<[u8; 32]> {
        self.slot_to_pubkey.get(&slot).map(|pk| *pk)
    }
}

// ---------------------------------------------------------------------------
// Refresh logic
// ---------------------------------------------------------------------------

fn refresh(
    client: &RpcClient,
    dz_client: &RpcClient,
    cache: &LeaderCache,
    absolute_slot: u64,
    slot_index: u64,
) -> anyhow::Result<()> {
    let schedule = client
        .get_leader_schedule(Some(absolute_slot))?
        .ok_or_else(|| anyhow::anyhow!("get_leader_schedule returned None"))?;

    let nodes = client.get_cluster_nodes()?;

    // Build gossip_ip (BE u32) → pubkey bytes, and pubkey string → pubkey bytes.
    let mut gossip_ip_to_pubkey: HashMap<u32, [u8; 32]> = HashMap::with_capacity(nodes.len());
    let mut pubkey_bytes_by_str: HashMap<String, [u8; 32]> = HashMap::with_capacity(nodes.len());

    for n in &nodes {
        let Ok(pk) = Pubkey::from_str(&n.pubkey) else { continue };
        let pk_bytes = pk.to_bytes();
        pubkey_bytes_by_str.insert(n.pubkey.clone(), pk_bytes);

        // Use gossip IP as the canonical network identity for the validator.
        let Some(gossip) = n.gossip else { continue };
        let IpAddr::V4(v4) = gossip.ip() else { continue };
        gossip_ip_to_pubkey.insert(u32::from_be_bytes(v4.octets()), pk_bytes);
    }

    // Build slot → leader pubkey bytes.
    let epoch_start = absolute_slot - slot_index;
    cache.slot_to_pubkey.clear();
    for (pubkey_str, relative_slots) in &schedule {
        let Some(&pk_bytes) = pubkey_bytes_by_str.get(pubkey_str) else { continue };
        for &rel in relative_slots {
            cache.slot_to_pubkey.insert(epoch_start + rel as u64, pk_bytes);
        }
    }

    // Update gossip IP → pubkey map.
    cache.gossip_ip_to_pubkey.clear();
    for (ip, pk_bytes) in gossip_ip_to_pubkey {
        cache.gossip_ip_to_pubkey.insert(ip, pk_bytes);
    }

    // Fetch DZ user accounts to build dz_ip → client_ip map.
    // A failure here is non-fatal: log a warning and keep the existing map.
    match refresh_dz_users(dz_client, cache) {
        Ok(n) => tracing::debug!("DZ user map: {} entries", n),
        Err(e) => tracing::warn!("DZ user map refresh failed (stale data retained): {}", e),
    }

    Ok(())
}

/// Fetches all DZ User accounts and populates `cache.dz_ip_to_client_ip`.
fn refresh_dz_users(dz_client: &RpcClient, cache: &LeaderCache) -> anyhow::Result<usize> {
    let program_id = Pubkey::from_str(DZ_SERVICEABILITY_PROGRAM)?;

    let config = RpcProgramAccountsConfig {
        filters: Some(vec![
            RpcFilterType::Memcmp(Memcmp::new_raw_bytes(0, vec![DZ_USER_DISCRIMINATOR])),
        ]),
        ..Default::default()
    };

    let accounts = dz_client.get_program_accounts_with_config(&program_id, config)?;

    cache.dz_ip_to_client_ip.clear();
    let mut count = 0usize;

    for (_, account) in accounts {
        let data = &account.data;
        if data.len() < DZ_DZ_IP_OFFSET + 4 {
            continue;
        }
        let client_ip = u32::from_be_bytes(
            data[DZ_CLIENT_IP_OFFSET..DZ_CLIENT_IP_OFFSET + 4]
                .try_into()
                .unwrap(),
        );
        let dz_ip = u32::from_be_bytes(
            data[DZ_DZ_IP_OFFSET..DZ_DZ_IP_OFFSET + 4]
                .try_into()
                .unwrap(),
        );

        if dz_ip == 0 || client_ip == 0 {
            continue;
        }

        cache.dz_ip_to_client_ip.insert(dz_ip, client_ip);
        count += 1;
    }

    Ok(count)
}
