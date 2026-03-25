//! Leader schedule cache for per-IP publisher filtering.
//!
//! Fetches the Solana leader schedule and cluster node list via RPC, then
//! builds a `slot → leader_ipv4` map. A background thread refreshes the map
//! once per epoch so the cache stays current across epoch boundaries.
//!
//! Used by [`crate::shred_race::PublisherTracker`] to skip shred arrivals
//! whose source IP is not the scheduled slot leader.

use dashmap::DashMap;
use solana_client::rpc_client::RpcClient;
use std::net::IpAddr;
use std::sync::Arc;

pub struct LeaderCache {
    /// Maps absolute slot number → leader IPv4 in network byte order (big-endian u32).
    slot_to_ip: DashMap<u64, u32>,
}

impl LeaderCache {
    /// Spawns a background thread that populates and refreshes the cache.
    /// Returns immediately; the cache may be empty until the first fetch completes
    /// (typically within a few seconds). `is_leader` returns `false` for unknown slots.
    pub fn new(rpc_url: &str) -> Arc<Self> {
        let cache = Arc::new(Self { slot_to_ip: DashMap::new() });
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
                                if let Err(e) = refresh(&client, &cache_bg, ei.epoch, ei.absolute_slot, ei.slot_index) {
                                    tracing::warn!("leader cache refresh failed: {}", e);
                                } else {
                                    last_epoch = ei.epoch;
                                    tracing::info!(
                                        epoch = ei.epoch,
                                        slots = cache_bg.slot_to_ip.len(),
                                        "leader cache refreshed"
                                    );
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

    /// Returns true if `src_ip` (network byte order u32) is the scheduled leader for `slot`.
    /// Returns false if the slot is not yet in the cache or if src_ip doesn't match.
    pub fn is_leader(&self, slot: u64, src_ip: u32) -> bool {
        self.slot_to_ip.get(&slot).map(|ip| *ip == src_ip).unwrap_or(false)
    }

    /// Returns true if the leader for `slot` is present in the cache.
    /// Returns false if the slot is not yet known (cache still warming, or the slot
    /// falls outside the current epoch window).
    pub fn slot_known(&self, slot: u64) -> bool {
        self.slot_to_ip.contains_key(&slot)
    }
}

fn refresh(
    client: &RpcClient,
    cache: &LeaderCache,
    _epoch: u64,
    absolute_slot: u64,
    slot_index: u64,
) -> anyhow::Result<()> {
    let schedule = client
        .get_leader_schedule(Some(absolute_slot))?
        .ok_or_else(|| anyhow::anyhow!("get_leader_schedule returned None"))?;

    let nodes = client.get_cluster_nodes()?;

    // Build pubkey → IPv4 (u32, network byte order) from cluster node TPU addresses.
    // Fall back to gossip IP if TPU is absent.
    let ip_map: std::collections::HashMap<String, u32> = nodes
        .iter()
        .filter_map(|n| {
            let addr = n.tpu.or(n.gossip)?;
            if let IpAddr::V4(v4) = addr.ip() {
                Some((n.pubkey.clone(), u32::from_be_bytes(v4.octets())))
            } else {
                None
            }
        })
        .collect();

    // epoch_start_slot = absolute_slot - slot_index_within_epoch
    let epoch_start = absolute_slot - slot_index;

    cache.slot_to_ip.clear();
    for (pubkey, relative_slots) in &schedule {
        if let Some(&ip) = ip_map.get(pubkey) {
            for &rel in relative_slots {
                cache.slot_to_ip.insert(epoch_start + rel as u64, ip);
            }
        }
    }

    Ok(())
}
