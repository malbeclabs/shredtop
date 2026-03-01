//! Multi-source fan-in with deduplication and lead-time measurement.
//!
//! [`FanInSource`] accepts any number of [`TxSource`] implementations, starts each on
//! its own thread(s), and merges their output into a single `Sender<DecodedTx>`.
//!
//! Deduplication is keyed on `signatures[0]` of each transaction. The first source to
//! deliver a given transaction wins and forwards it downstream; later arrivals of the
//! same transaction are counted as duplicates. When a shred source and an RPC source
//! both deliver the same transaction, their receive timestamps are compared to compute
//! the shred lead time (positive = shred arrived before RPC).

use crossbeam_channel::Sender;
use crate::receiver::CaptureEvent;
use dashmap::DashMap;
use solana_pubkey::Pubkey;
use std::collections::HashSet;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::thread::JoinHandle;

use crate::decoder::DecodedTx;
use crate::metrics;
use crate::shred_race::ShredRaceTracker;
use crate::source_metrics::SourceMetrics;

// ---------------------------------------------------------------------------
// TxSource trait
// ---------------------------------------------------------------------------

/// A pluggable transaction source that can be wired into [`FanInSource`].
pub trait TxSource: Send + 'static {
    fn name(&self) -> &'static str;
    /// Returns true if this source is an RPC source (used for lead-time direction).
    fn is_rpc(&self) -> bool {
        false
    }
    /// Start all threads for this source. The source writes decoded transactions to
    /// `tx` and increments `metrics` counters as it operates.
    /// `race` is `Some` only for shred-tier sources; other sources should accept and
    /// ignore it (parameter named `_race`).
    fn start(
        self: Box<Self>,
        tx: Sender<DecodedTx>,
        metrics: Arc<SourceMetrics>,
        race: Option<Arc<ShredRaceTracker>>,
    ) -> Vec<JoinHandle<()>>;
}

// ---------------------------------------------------------------------------
// ShredTxSource
// ---------------------------------------------------------------------------

/// Wraps [`ShredReceiver`] + [`ShredDecoder`] into a single [`TxSource`].
pub struct ShredTxSource {
    /// Display name for this source (e.g. "bebop", "jito-shredstream")
    pub name: &'static str,
    pub multicast_addr: String,
    pub port: u16,
    pub interface: String,
    pub pin_recv_core: Option<usize>,
    pub pin_decode_core: Option<usize>,
    pub shred_version: Option<u16>,
    /// Optional capture channel; forwarded to ShredReceiver for the hot-path tap.
    pub capture_tx: Option<crossbeam_channel::Sender<CaptureEvent>>,
}

impl TxSource for ShredTxSource {
    fn name(&self) -> &'static str {
        self.name
    }

    fn is_rpc(&self) -> bool {
        false
    }

    fn start(
        self: Box<Self>,
        tx: Sender<DecodedTx>,
        metrics: Arc<SourceMetrics>,
        race: Option<Arc<ShredRaceTracker>>,
    ) -> Vec<JoinHandle<()>> {
        let (shred_tx, shred_rx) = crossbeam_channel::bounded(4096);

        let multicast_addr = self.multicast_addr.clone();
        let port = self.port;
        let interface = self.interface.clone();
        let shred_version = self.shred_version;
        let recv_metrics = metrics.clone();
        let pin_recv = self.pin_recv_core;
        let name = self.name;
        let race_tx = race.as_ref().map(|r| r.sender());
        let capture_tx = self.capture_tx.clone();

        let recv_handle = std::thread::Builder::new()
            .name(format!("{}-recv", name))
            .spawn(move || {
                if let Some(core) = pin_recv {
                    pin_to_core(core);
                }
                let mut receiver = crate::receiver::ShredReceiver::new(
                    &multicast_addr,
                    port,
                    &interface,
                    shred_tx,
                    recv_metrics,
                    shred_version,
                    race_tx,
                    capture_tx,
                )
                .expect("failed to create shred receiver");
                receiver.run().expect("shred receiver crashed");
            })
            .expect("failed to spawn recv thread");

        let pin_decode = self.pin_decode_core;
        let decode_handle = std::thread::Builder::new()
            .name(format!("{}-decode", name))
            .spawn(move || {
                if let Some(core) = pin_decode {
                    pin_to_core(core);
                }
                let decoder = crate::decoder::ShredDecoder::new(shred_rx, tx, metrics);
                decoder.run().expect("shred decoder crashed");
            })
            .expect("failed to spawn decode thread");

        vec![recv_handle, decode_handle]
    }
}

// ---------------------------------------------------------------------------
// TurbineTxSource
// ---------------------------------------------------------------------------

/// Receives shreds from the Solana turbine retransmit tree via SO_REUSEPORT.
///
/// Binds `0.0.0.0:tvu_port` with `SO_REUSEPORT` so shredtop can coexist with
/// a running validator on the same port. Turbine shreds come from many retransmit
/// nodes, so the kernel distributes traffic across both sockets by per-flow hash.
///
/// Use this as a baseline to measure how many milliseconds faster a premium shred
/// feed (bebop, jito-shredstream) delivers each shred vs standard turbine propagation.
pub struct TurbineTxSource {
    /// Display name (e.g. "turbine")
    pub name: &'static str,
    /// TVU port the validator listens on (default 8002)
    pub port: u16,
    pub pin_recv_core: Option<usize>,
    pub pin_decode_core: Option<usize>,
    pub shred_version: Option<u16>,
    pub capture_tx: Option<crossbeam_channel::Sender<CaptureEvent>>,
}

impl TxSource for TurbineTxSource {
    fn name(&self) -> &'static str {
        self.name
    }

    fn is_rpc(&self) -> bool {
        false
    }

    fn start(
        self: Box<Self>,
        tx: Sender<DecodedTx>,
        metrics: Arc<SourceMetrics>,
        race: Option<Arc<ShredRaceTracker>>,
    ) -> Vec<JoinHandle<()>> {
        let (shred_tx, shred_rx) = crossbeam_channel::bounded(4096);

        let port = self.port;
        let shred_version = self.shred_version;
        let recv_metrics = metrics.clone();
        let pin_recv = self.pin_recv_core;
        let name = self.name;
        let race_tx = race.as_ref().map(|r| r.sender());
        let capture_tx = self.capture_tx.clone();

        let recv_handle = std::thread::Builder::new()
            .name(format!("{}-recv", name))
            .spawn(move || {
                if let Some(core) = pin_recv {
                    pin_to_core(core);
                }
                let mut receiver = crate::receiver::ShredReceiver::new_unicast(
                    port,
                    shred_tx,
                    recv_metrics,
                    shred_version,
                    race_tx,
                    capture_tx,
                )
                .expect("failed to create turbine receiver");
                receiver.run().expect("turbine receiver crashed");
            })
            .expect("failed to spawn turbine recv thread");

        let pin_decode = self.pin_decode_core;
        let decode_handle = std::thread::Builder::new()
            .name(format!("{}-decode", name))
            .spawn(move || {
                if let Some(core) = pin_decode {
                    pin_to_core(core);
                }
                let decoder = crate::decoder::ShredDecoder::new(shred_rx, tx, metrics);
                decoder.run().expect("turbine decoder crashed");
            })
            .expect("failed to spawn turbine decode thread");

        vec![recv_handle, decode_handle]
    }
}

// ---------------------------------------------------------------------------
// RpcTxSource
// ---------------------------------------------------------------------------

/// Wraps [`RpcSource`] into a single [`TxSource`].
pub struct RpcTxSource {
    pub url: String,
    pub pin_core: Option<usize>,
}

impl TxSource for RpcTxSource {
    fn name(&self) -> &'static str {
        "rpc"
    }

    fn is_rpc(&self) -> bool {
        true
    }

    fn start(
        self: Box<Self>,
        tx: Sender<DecodedTx>,
        metrics: Arc<SourceMetrics>,
        _race: Option<Arc<ShredRaceTracker>>,
    ) -> Vec<JoinHandle<()>> {
        let url = self.url.clone();
        let pin_core = self.pin_core;
        let handle = std::thread::Builder::new()
            .name("rpc-source".into())
            .spawn(move || {
                if let Some(core) = pin_core {
                    pin_to_core(core);
                }
                let mut source = crate::rpc_source::RpcSource::new(&url, tx, metrics)
                    .expect("failed to create RPC source");
                source.run().expect("RPC source crashed");
            })
            .expect("failed to spawn rpc-source");
        vec![handle]
    }
}

// ---------------------------------------------------------------------------
// FanInSource
// ---------------------------------------------------------------------------

/// Tracks the first arrival of a transaction signature in the dedup map.
struct FirstArrival {
    /// Receive timestamp from the winning source (nanoseconds)
    recv_ns: u64,
    /// Whether the winning source is an RPC source
    is_rpc: bool,
    /// Metrics handle for the winning source, used to record lead time
    metrics: Arc<SourceMetrics>,
}

/// Multi-source fan-in with deduplication.
///
/// Add sources with [`add_source`], then call [`start`] to start all threads.
/// The returned `Vec<Arc<SourceMetrics>>` has one entry per source in insertion order.
pub struct FanInSource {
    sources: Vec<(Box<dyn TxSource>, Arc<SourceMetrics>)>,
    /// Optional program/account filter. When non-empty, only transactions whose static
    /// account keys include at least one of these pubkeys are counted for lead-time.
    /// Applies to shred-tier sources only; RPC-tier sources (is_rpc=true) are exempt.
    pub filter_programs: Vec<String>,
}

impl FanInSource {
    pub fn new() -> Self {
        Self { sources: Vec::new(), filter_programs: Vec::new() }
    }

    pub fn add_source(&mut self, source: Box<dyn TxSource>, metrics: Arc<SourceMetrics>) {
        self.sources.push((source, metrics));
    }

    /// Start all sources and return their metrics handles, the shred race tracker,
    /// and all thread handles.
    pub fn start(
        self,
        out_tx: Sender<DecodedTx>,
    ) -> (Vec<Arc<SourceMetrics>>, Arc<ShredRaceTracker>, Vec<JoinHandle<()>>) {
        let dedup: Arc<DashMap<[u8; 64], FirstArrival>> = Arc::new(DashMap::new());
        let mut all_handles: Vec<JoinHandle<()>> = Vec::new();
        let mut all_metrics: Vec<Arc<SourceMetrics>> = Vec::new();

        let race_tracker = ShredRaceTracker::new();

        // Parse filter programs once at start time; shared across relay threads.
        let filter_set: Arc<HashSet<Pubkey>> = Arc::new(
            self.filter_programs
                .iter()
                .filter_map(|s| s.parse::<Pubkey>().ok())
                .collect(),
        );

        for (source, source_metrics) in self.sources {
            let source_name = source.name();
            let source_is_rpc = source.is_rpc();
            let (inner_tx, inner_rx) = crossbeam_channel::bounded::<DecodedTx>(4096);

            // Pass the race tracker to shred-tier sources; None for RPC-tier.
            let race_arg = if !source_is_rpc { Some(race_tracker.clone()) } else { None };
            let source_handles = source.start(inner_tx, source_metrics.clone(), race_arg);
            all_handles.extend(source_handles);
            all_metrics.push(source_metrics.clone());

            let dedup_clone = dedup.clone();
            let out_tx_clone = out_tx.clone();
            let filter_clone = filter_set.clone();

            let relay_handle = std::thread::Builder::new()
                .name(format!("fan-in-{}", source_name))
                .spawn(move || {
                    for decoded in &inner_rx {
                        // Apply program/account filter for shred-tier sources.
                        // RPC-tier sources are exempt so they always provide timestamps.
                        if !filter_clone.is_empty() && !source_is_rpc {
                            let keys = decoded.transaction.message.static_account_keys();
                            if !keys.iter().any(|k| filter_clone.contains(k)) {
                                continue;
                            }
                        }

                        let sig_bytes: [u8; 64] = match decoded.transaction.signatures.first() {
                            Some(sig) => match sig.as_ref().try_into() {
                                Ok(b) => b,
                                Err(_) => continue,
                            },
                            None => continue,
                        };

                        use dashmap::mapref::entry::Entry;
                        match dedup_clone.entry(sig_bytes) {
                            Entry::Vacant(e) => {
                                // First arrival — forward downstream
                                source_metrics.txs_first.fetch_add(1, Relaxed);
                                e.insert(FirstArrival {
                                    recv_ns: decoded.shred_recv_ns,
                                    is_rpc: source_is_rpc,
                                    metrics: source_metrics.clone(),
                                });
                                let _ = out_tx_clone.try_send(decoded);
                            }
                            Entry::Occupied(e) => {
                                // Duplicate — record lead time
                                source_metrics.txs_duplicate.fetch_add(1, Relaxed);
                                let first = e.get();

                                // Lead time: positive = shred arrived before RPC.
                                // If the first arrival was shred and the duplicate is RPC,
                                // the lead is (rpc_recv - shred_recv).
                                // If the first arrival was RPC and the duplicate is shred,
                                // the lead is negative (shred arrived late).
                                let (shred_ns, rpc_ns) = if !first.is_rpc && source_is_rpc {
                                    // First=shred, current=rpc
                                    (first.recv_ns, decoded.shred_recv_ns)
                                } else if first.is_rpc && !source_is_rpc {
                                    // First=rpc, current=shred
                                    (decoded.shred_recv_ns, first.recv_ns)
                                } else {
                                    // Both same type — compare timestamps directly
                                    // (shred vs shred: measures relative lead between feeds)
                                    if !source_is_rpc {
                                        (decoded.shred_recv_ns, first.recv_ns)
                                    } else {
                                        continue; // rpc vs rpc: skip
                                    }
                                };

                                let lead_us = (rpc_ns as i64 - shred_ns as i64) / 1000;

                                if !first.is_rpc {
                                    // Record on the shred source that arrived first
                                    first.metrics.record_lead_time_us(lead_us);
                                } else {
                                    // Current source (shred) arrived after RPC — record negative lead
                                    source_metrics.record_lead_time_us(lead_us);
                                }
                            }
                        }
                    }
                })
                .expect("failed to spawn relay thread");

            all_handles.push(relay_handle);
        }

        // Eviction thread: every 60s, drop dedup entries older than 15 minutes
        let dedup_evict = dedup;
        let evict_handle = std::thread::Builder::new()
            .name("fan-in-evict".into())
            .spawn(move || loop {
                std::thread::sleep(std::time::Duration::from_secs(60));
                let cutoff_ns = metrics::now_ns().saturating_sub(900_000_000_000);
                dedup_evict.retain(|_, v| v.recv_ns > cutoff_ns);
            })
            .expect("failed to spawn evict thread");
        all_handles.push(evict_handle);

        (all_metrics, race_tracker, all_handles)
    }
}

impl Default for FanInSource {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn pin_to_core(core_id: usize) {
    #[cfg(target_os = "linux")]
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_SET(core_id, &mut set);
        libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
    }
    #[cfg(not(target_os = "linux"))]
    let _ = core_id;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use dashmap::mapref::entry::Entry;
    use std::sync::atomic::Ordering::Relaxed;

    #[test]
    fn test_first_arrival_wins() {
        let dedup: DashMap<[u8; 64], FirstArrival> = DashMap::new();
        let metrics = SourceMetrics::new("test", false);
        let sig: [u8; 64] = [0xAB; 64];

        match dedup.entry(sig) {
            Entry::Vacant(e) => {
                metrics.txs_first.fetch_add(1, Relaxed);
                e.insert(FirstArrival {
                    recv_ns: 100_000,
                    is_rpc: false,
                    metrics: metrics.clone(),
                });
            }
            Entry::Occupied(_) => {
                metrics.txs_duplicate.fetch_add(1, Relaxed);
            }
        }

        assert_eq!(metrics.txs_first.load(Relaxed), 1);
        assert_eq!(metrics.txs_duplicate.load(Relaxed), 0);

        match dedup.entry(sig) {
            Entry::Vacant(e) => {
                metrics.txs_first.fetch_add(1, Relaxed);
                e.insert(FirstArrival {
                    recv_ns: 200_000,
                    is_rpc: false,
                    metrics: metrics.clone(),
                });
            }
            Entry::Occupied(_) => {
                metrics.txs_duplicate.fetch_add(1, Relaxed);
            }
        }

        assert_eq!(metrics.txs_first.load(Relaxed), 1);
        assert_eq!(metrics.txs_duplicate.load(Relaxed), 1);
    }

    #[test]
    fn test_lead_time_shred_first() {
        let shred_recv_ns: u64 = 100_000;
        let rpc_recv_ns: u64 = 200_000;

        let lead_us = (rpc_recv_ns as i64 - shred_recv_ns as i64) / 1000;
        assert!(lead_us > 0);
        assert_eq!(lead_us, 100);

        let shred_metrics = SourceMetrics::new("shred", false);
        shred_metrics.record_lead_time_us(lead_us);
        assert_eq!(shred_metrics.lead_time_count.load(Relaxed), 1);
        assert_eq!(shred_metrics.lead_time_sum_us.load(Relaxed), 100);
    }

    #[test]
    fn test_lead_time_rpc_first() {
        let rpc_recv_ns: u64 = 100_000;
        let shred_recv_ns: u64 = 200_000;

        let lead_us = (rpc_recv_ns as i64 - shred_recv_ns as i64) / 1000;
        assert!(lead_us < 0);
        assert_eq!(lead_us, -100);

        let shred_metrics = SourceMetrics::new("shred", false);
        shred_metrics.record_lead_time_us(lead_us);
        assert_eq!(shred_metrics.lead_time_count.load(Relaxed), 1);
        assert_eq!(shred_metrics.lead_time_sum_us.load(Relaxed), -100);
    }
}
