//! Leader schedule cache for shred race filtering.
//!
//! Fetches the Solana leader schedule and cluster node list via RPC, then
//! builds a `slot → leader_pubkey` map and a `gossip_ip → pubkey` map.
//!
//! Used by [`crate::shred_race::PublisherTracker`] to filter the race tracker
//! to only count leader-originated shreds.

use dashmap::DashMap;
use solana_account_decoder_client_types::UiAccountEncoding;
use solana_client::rpc_client::RpcClient;
use solana_client::rpc_config::{RpcAccountInfoConfig, RpcProgramAccountsConfig};
use solana_client::rpc_filter::{Memcmp, RpcFilterType};
use solana_pubkey::Pubkey;
use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};

// ---------------------------------------------------------------------------
// DZ serviceability constants
// ---------------------------------------------------------------------------

/// On-chain program ID for the DoubleZero serviceability smart contract (mainnet).
const DZ_SERVICEABILITY_PROGRAM: &str = "ser2VaTMAcYTaauMrTSfSrxBaUDq7BLNs2xfUugTAGv";

/// Byte 0 of a DZ User account (AccountType::User = 7).
const DZ_USER_DISCRIMINATOR: u8 = 7;

/// Byte offset of `ClientIp` ([u8; 4] BE) in a DZ User account.
const DZ_CLIENT_IP_OFFSET: usize = 116;

/// Byte offset of `DzIp` ([u8; 4] BE) in a DZ User account.
const DZ_DZ_IP_OFFSET: usize = 120;

// ---------------------------------------------------------------------------
// LeaderCache
// ---------------------------------------------------------------------------

pub struct LeaderCache {
    /// Maps absolute slot → leader identity pubkey bytes.
    slot_to_pubkey: DashMap<u64, [u8; 32]>,
    /// Maps gossip IPv4 (big-endian u32) → validator identity pubkey bytes.
    gossip_ip_to_pubkey: DashMap<u32, [u8; 32]>,
    /// Set to `true` after the first successful refresh completes.
    ready: AtomicBool,
}

impl LeaderCache {
    /// Spawns a background thread that populates and refreshes the cache.
    pub fn new(rpc_url: &str) -> Arc<Self> {
        let cache = Arc::new(Self {
            slot_to_pubkey: DashMap::new(),
            gossip_ip_to_pubkey: DashMap::new(),
            ready: AtomicBool::new(false),
        });
        let cache_bg = cache.clone();
        let url = rpc_url.to_string();

        std::thread::Builder::new()
            .name("leader-cache".into())
            .spawn(move || {
                let client = RpcClient::new(url);
                let mut last_epoch = u64::MAX;

                loop {
                    match client.get_epoch_info() {
                        Ok(ei) => {
                            if ei.epoch != last_epoch {
                                match refresh(&client, &cache_bg, ei.absolute_slot, ei.slot_index) {
                                    Ok(()) => {
                                        last_epoch = ei.epoch;
                                        cache_bg.ready.store(true, Relaxed);
                                        tracing::info!(
                                            epoch = ei.epoch,
                                            slots = cache_bg.slot_to_pubkey.len(),
                                            gossip_nodes = cache_bg.gossip_ip_to_pubkey.len(),
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
    pub fn is_leader(&self, slot: u64, src_ip: u32) -> bool {
        let leader_pk = match self.slot_to_pubkey.get(&slot) {
            Some(pk) => *pk,
            None => return false,
        };
        self.gossip_ip_to_pubkey.get(&src_ip)
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

    /// Number of slot→pubkey entries currently in the cache.
    pub fn slot_count(&self) -> usize {
        self.slot_to_pubkey.len()
    }

    /// Number of gossip IP → pubkey mappings loaded from cluster nodes.
    pub fn gossip_ip_count(&self) -> usize {
        self.gossip_ip_to_pubkey.len()
    }

    /// Blocks until the cache has completed its first refresh, or `timeout` elapses.
    pub fn wait_ready(&self, timeout: std::time::Duration) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        while !self.ready.load(Relaxed) {
            if std::time::Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        true
    }
}

// ---------------------------------------------------------------------------
// Refresh logic
// ---------------------------------------------------------------------------

fn refresh(
    client: &RpcClient,
    cache: &LeaderCache,
    absolute_slot: u64,
    slot_index: u64,
) -> anyhow::Result<()> {
    let schedule = client
        .get_leader_schedule(Some(absolute_slot))?
        .ok_or_else(|| anyhow::anyhow!("get_leader_schedule returned None"))?;

    let nodes = client.get_cluster_nodes()?;

    let mut gossip_ip_to_pubkey: HashMap<u32, [u8; 32]> = HashMap::with_capacity(nodes.len());
    let mut pubkey_bytes_by_str: HashMap<String, [u8; 32]> = HashMap::with_capacity(nodes.len());

    for n in &nodes {
        let Ok(pk) = Pubkey::from_str(&n.pubkey) else { continue };
        let pk_bytes = pk.to_bytes();
        pubkey_bytes_by_str.insert(n.pubkey.clone(), pk_bytes);

        let Some(gossip) = n.gossip else { continue };
        let IpAddr::V4(v4) = gossip.ip() else { continue };
        gossip_ip_to_pubkey.insert(u32::from_be_bytes(v4.octets()), pk_bytes);
    }

    let epoch_start = absolute_slot - slot_index;
    cache.slot_to_pubkey.clear();
    for (pubkey_str, relative_slots) in &schedule {
        let Some(&pk_bytes) = pubkey_bytes_by_str.get(pubkey_str) else { continue };
        for &rel in relative_slots {
            cache.slot_to_pubkey.insert(epoch_start + rel as u64, pk_bytes);
        }
    }

    cache.gossip_ip_to_pubkey.clear();
    for (ip, pk_bytes) in gossip_ip_to_pubkey {
        cache.gossip_ip_to_pubkey.insert(ip, pk_bytes);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// DZ tunnel IP resolution
// ---------------------------------------------------------------------------

/// Resolves a validator's DoubleZero tunnel (wire) IP from their client (public) IP.
///
/// On DZ multicast groups, packets arrive with `src_ip = dz_ip` — the IP assigned
/// by the DoubleZero network — not the validator's public IP. This function queries
/// DZ User accounts to find the `dz_ip` for the given `client_ip`.
///
/// Returns `Some(dz_ip)` for a multicast publisher account (dz_ip ≠ client_ip).
/// Returns `None` if no matching account is found or only IBRL accounts exist.
///
/// The returned `Ipv4Addr` can be converted to the `u32` format used by `s_addr`
/// (and thus `ShredArrival::src_ip`) via `u32::from_ne_bytes(addr.octets())`.
pub fn resolve_dz_tunnel_ip(
    dz_rpc_url: &str,
    client_ip: std::net::Ipv4Addr,
) -> anyhow::Result<Option<std::net::Ipv4Addr>> {
    let client = RpcClient::new(dz_rpc_url.to_string());
    let program_id = Pubkey::from_str(DZ_SERVICEABILITY_PROGRAM)?;

    let config = RpcProgramAccountsConfig {
        filters: Some(vec![
            RpcFilterType::Memcmp(Memcmp::new_raw_bytes(0, vec![DZ_USER_DISCRIMINATOR])),
            // Match client_ip bytes at offset 116 (network byte order = same as octets).
            RpcFilterType::Memcmp(Memcmp::new_raw_bytes(
                DZ_CLIENT_IP_OFFSET,
                client_ip.octets().to_vec(),
            )),
        ]),
        account_config: RpcAccountInfoConfig {
            encoding: Some(UiAccountEncoding::Base64),
            ..Default::default()
        },
        ..Default::default()
    };

    let accounts = client.get_program_accounts_with_config(&program_id, config)?;

    for (_, account) in accounts {
        if account.data.len() < DZ_DZ_IP_OFFSET + 4 {
            continue;
        }
        let dz_octets: [u8; 4] = account.data[DZ_DZ_IP_OFFSET..DZ_DZ_IP_OFFSET + 4]
            .try_into()
            .unwrap();
        let dz_ip = std::net::Ipv4Addr::from(dz_octets);
        // Return the multicast publisher account (dz_ip ≠ client_ip).
        // Skip IBRL accounts where the tunnel IP equals the public IP.
        if dz_ip != client_ip {
            return Ok(Some(dz_ip));
        }
    }

    Ok(None)
}
