//! Leader schedule cache for shred race filtering.
//!
//! Fetches the Solana leader schedule and cluster node list via RPC, then
//! builds a `slot → leader_pubkey` map and a `gossip_ip → pubkey` map.
//!
//! Also fetches DZ access-pass accounts from the DoubleZero RPC to build a
//! `public_ip → validator_pubkey` map. On DZ multicast groups, `src_ip` is the
//! validator's public IPv4 address (confirmed via `doublezero access-pass list`).
//!
//! Resolution: `src_ip → [ip_to_pubkey] → validator_pubkey` (primary)
//!             `src_ip → [gossip_ip_to_pubkey] → validator_pubkey` (fallback)
//!
//! Used by [`crate::shred_race::PublisherTracker`] to attribute shred arrivals
//! to a specific validator for per-source health monitoring.

use dashmap::DashMap;
use solana_client::rpc_client::RpcClient;
use solana_client::rpc_config::RpcProgramAccountsConfig;
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

/// Anchor discriminator for DZ access-pass accounts.
const DZ_ACCESS_PASS_DISCRIMINATOR: [u8; 8] = [0x0b, 0xf6, 0x8d, 0x09, 0x2b, 0x42, 0xa1, 0x40];

/// Byte offset of the validator identity pubkey (32 bytes) in a DZ access-pass account.
const DZ_ACCESS_PASS_PUBKEY_OFFSET: usize = 35;

/// Byte offset of the public IPv4 address (4 bytes, big-endian) in a DZ access-pass account.
const DZ_ACCESS_PASS_IP_OFFSET: usize = 67;

// ---------------------------------------------------------------------------
// LeaderCache
// ---------------------------------------------------------------------------

pub struct LeaderCache {
    /// Maps absolute slot → leader identity pubkey bytes.
    slot_to_pubkey: DashMap<u64, [u8; 32]>,
    /// Maps gossip IPv4 (big-endian u32) → validator identity pubkey bytes.
    gossip_ip_to_pubkey: DashMap<u32, [u8; 32]>,
    /// Maps public IPv4 (big-endian u32) → validator identity pubkey bytes.
    /// Populated from DZ access-pass accounts via the DoubleZero RPC.
    ip_to_pubkey: DashMap<u32, [u8; 32]>,
    /// Set to `true` after the first successful refresh completes.
    ready: AtomicBool,
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
            ip_to_pubkey: DashMap::new(),
            ready: AtomicBool::new(false),
        });
        let cache_bg = cache.clone();
        let url = rpc_url.to_string();
        let dz_url = dz_rpc_url.map(|s| s.to_string());

        std::thread::Builder::new()
            .name("leader-cache".into())
            .spawn(move || {
                let client = RpcClient::new(url);
                let dz_client = dz_url.as_deref().map(RpcClient::new);
                let mut last_epoch = u64::MAX;

                loop {
                    match client.get_epoch_info() {
                        Ok(ei) => {
                            if ei.epoch != last_epoch {
                                match refresh(&client, dz_client.as_ref(), &cache_bg, ei.absolute_slot, ei.slot_index) {
                                    Ok(()) => {
                                        last_epoch = ei.epoch;
                                        cache_bg.ready.store(true, Relaxed);
                                        tracing::info!(
                                            epoch = ei.epoch,
                                            slots = cache_bg.slot_to_pubkey.len(),
                                            gossip_nodes = cache_bg.gossip_ip_to_pubkey.len(),
                                            dz_publishers = cache_bg.ip_to_pubkey.len(),
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
    /// Checks `ip_to_pubkey` (DZ access-pass) first, then `gossip_ip_to_pubkey` as fallback.
    /// Returns false if the slot is not in the cache or the IP cannot be resolved.
    pub fn is_leader(&self, slot: u64, src_ip: u32) -> bool {
        let leader_pk = match self.slot_to_pubkey.get(&slot) {
            Some(pk) => *pk,
            None => return false,
        };
        // Try direct DZ access-pass map first; fall back to gossip IP lookup.
        if let Some(pk) = self.ip_to_pubkey.get(&src_ip) {
            return *pk == leader_pk;
        }
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

    /// Resolves `src_ip` (big-endian u32) to a validator identity pubkey, or `None`.
    ///
    /// Checks `ip_to_pubkey` (DZ access-pass) first, then `gossip_ip_to_pubkey` as fallback.
    /// Useful for attributing shreds from retransmit groups to a specific validator.
    pub fn pubkey_for_ip(&self, src_ip: u32) -> Option<[u8; 32]> {
        // Try direct DZ access-pass map first; fall back to gossip IP lookup.
        if let Some(pk) = self.ip_to_pubkey.get(&src_ip) {
            return Some(*pk);
        }
        self.gossip_ip_to_pubkey.get(&src_ip).map(|pk| *pk)
    }

    /// Returns `true` if this validator has any scheduled leader slots in the current epoch.
    pub fn has_leader_slots(&self, pk: &[u8; 32]) -> bool {
        self.slot_to_pubkey.iter().any(|e| e.value() == pk)
    }

    /// Number of slot→pubkey entries currently in the cache.
    pub fn slot_count(&self) -> usize {
        self.slot_to_pubkey.len()
    }

    /// Number of public IP → validator pubkey mappings loaded from DZ access-pass accounts.
    pub fn dz_ip_count(&self) -> usize {
        self.ip_to_pubkey.len()
    }

    /// Number of gossip IP → pubkey mappings loaded from cluster nodes.
    pub fn gossip_ip_count(&self) -> usize {
        self.gossip_ip_to_pubkey.len()
    }

    /// Blocks until the cache has completed its first refresh, or `timeout` elapses.
    /// Returns `true` if ready, `false` on timeout.
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
    dz_client: Option<&RpcClient>,
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

    // Fetch DZ access-pass accounts to build public_ip → validator_pubkey map.
    // A failure here is non-fatal: log a warning and keep the existing map.
    if let Some(dz) = dz_client {
        match refresh_access_pass(dz, cache) {
            Ok(n) => tracing::debug!("DZ access-pass map: {} entries", n),
            Err(e) => tracing::warn!("DZ access-pass map refresh failed (stale data retained): {}", e),
        }
    }

    Ok(())
}

/// Fetches all DZ access-pass accounts and populates `cache.ip_to_pubkey`.
///
/// Each access-pass account encodes `(public_ipv4, validator_identity_pubkey)`.
/// Layout (verified against live accounts):
///   - bytes  0– 7: Anchor discriminator `[0x0b, 0xf6, 0x8d, 0x09, 0x2b, 0x42, 0xa1, 0x40]`
///   - bytes 35–66: validator identity pubkey (32 bytes)
///   - bytes 67–70: public IPv4 address (4 bytes, big-endian)
fn refresh_access_pass(dz_client: &RpcClient, cache: &LeaderCache) -> anyhow::Result<usize> {
    let program_id = Pubkey::from_str(DZ_SERVICEABILITY_PROGRAM)?;

    let config = RpcProgramAccountsConfig {
        filters: Some(vec![
            RpcFilterType::Memcmp(Memcmp::new_raw_bytes(
                0,
                DZ_ACCESS_PASS_DISCRIMINATOR.to_vec(),
            )),
        ]),
        ..Default::default()
    };

    let accounts = dz_client.get_program_accounts_with_config(&program_id, config)?;

    cache.ip_to_pubkey.clear();
    let mut count = 0usize;

    for (_, account) in accounts {
        let data = &account.data;
        if data.len() < DZ_ACCESS_PASS_IP_OFFSET + 4 {
            continue;
        }
        let mut pk_bytes = [0u8; 32];
        pk_bytes.copy_from_slice(&data[DZ_ACCESS_PASS_PUBKEY_OFFSET..DZ_ACCESS_PASS_PUBKEY_OFFSET + 32]);
        let ip = u32::from_be_bytes(
            data[DZ_ACCESS_PASS_IP_OFFSET..DZ_ACCESS_PASS_IP_OFFSET + 4]
                .try_into()
                .unwrap(),
        );

        if ip == 0 {
            continue;
        }

        cache.ip_to_pubkey.insert(ip, pk_bytes);
        count += 1;
    }

    Ok(count)
}
