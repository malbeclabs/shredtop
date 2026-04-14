//! Shred-to-shred race tracker.
//!
//! Measures which shred feed delivers each `(slot, shred_index)` first and
//! by how much — purely at the shred level, before FEC reassembly.
//!
//! ## Architecture
//! `ShredReceiver` hot loops call `try_send(ShredArrival)` (~20 ns, non-blocking)
//! into a bounded channel. A background thread drains the channel, maintains a
//! `(slot, idx) → first_arrival` map, and records per-pair win counts/latencies.
//! A second thread evicts stale entries every 5 s. Drops on a full channel are
//! acceptable — this is a sampling metric, not a correctness path.

use crossbeam_channel::{bounded, Sender};
use dashmap::DashMap;
use serde::Serialize;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};

use crate::leader_cache::LeaderCache;
use crate::metrics;

// ---------------------------------------------------------------------------
// Wire type sent from ShredReceiver hot loop
// ---------------------------------------------------------------------------

/// Sent from a [`crate::receiver::ShredReceiver`] hot loop to the race tracker.
pub struct ShredArrival {
    pub source: &'static str,
    pub slot: u64,
    pub idx: u32,
    pub recv_ns: u64,
    /// Source IPv4 in network byte order (big-endian u32). Zero if unavailable.
    pub src_ip: u32,
}

struct ShredFirstArrival {
    /// (source_name, recv_ns, src_ip) for each feed that has delivered this shred.
    arrivals: Vec<(&'static str, u64, u32)>,
    inserted_ns: u64,
    /// How many shred-tier sources must deliver before the race is recorded.
    expected: usize,
}

// ---------------------------------------------------------------------------
// Per-pair metrics
// ---------------------------------------------------------------------------

const RESERVOIR_CAP: usize = 4096;

struct RaceReservoir {
    buf: [i64; RESERVOIR_CAP],
    len: usize,
    pos: usize,
}

impl RaceReservoir {
    fn new() -> Self {
        Self { buf: [0; RESERVOIR_CAP], len: 0, pos: 0 }
    }

    fn push(&mut self, v: i64) {
        self.buf[self.pos] = v;
        self.pos = (self.pos + 1) % RESERVOIR_CAP;
        if self.len < RESERVOIR_CAP {
            self.len += 1;
        }
    }

    /// Returns `(p50, p95, p99)` in µs, or `None` if empty.
    fn percentiles(&self) -> Option<(i64, i64, i64)> {
        if self.len == 0 {
            return None;
        }
        let mut sorted = self.buf[..self.len].to_vec();
        sorted.sort_unstable();
        let n = sorted.len();
        Some((
            sorted[(n * 50 / 100).min(n - 1)],
            sorted[(n * 95 / 100).min(n - 1)],
            sorted[(n * 99 / 100).min(n - 1)],
        ))
    }
}

struct ShredPairMetrics {
    source_a: &'static str,
    source_b: &'static str,
    a_wins: AtomicU64,
    b_wins: AtomicU64,
    /// Sum of winner's lead time in µs (always ≥ 0).
    lead_sum_us: AtomicI64,
    lead_count: AtomicU64,
    reservoir: Mutex<RaceReservoir>,
}

impl ShredPairMetrics {
    fn new(source_a: &'static str, source_b: &'static str) -> Arc<Self> {
        Arc::new(Self {
            source_a,
            source_b,
            a_wins: AtomicU64::new(0),
            b_wins: AtomicU64::new(0),
            lead_sum_us: AtomicI64::new(0),
            lead_count: AtomicU64::new(0),
            reservoir: Mutex::new(RaceReservoir::new()),
        })
    }

    fn record(&self, winner: &'static str, lead_us: i64) {
        if winner == self.source_a {
            self.a_wins.fetch_add(1, Relaxed);
        } else {
            self.b_wins.fetch_add(1, Relaxed);
        }
        self.lead_sum_us.fetch_add(lead_us, Relaxed);
        self.lead_count.fetch_add(1, Relaxed);
        self.reservoir.lock().unwrap().push(lead_us);
    }

    fn snapshot(&self) -> ShredPairSnapshot {
        let a_wins = self.a_wins.load(Relaxed);
        let b_wins = self.b_wins.load(Relaxed);
        let total_matched = a_wins + b_wins;
        let lead_count = self.lead_count.load(Relaxed);
        let lead_sum = self.lead_sum_us.load(Relaxed);

        let a_win_pct = if total_matched > 0 {
            a_wins as f64 / total_matched as f64 * 100.0
        } else {
            0.0
        };
        let lead_mean_us = if lead_count > 0 {
            Some(lead_sum as f64 / lead_count as f64)
        } else {
            None
        };

        let (lead_p50_us, lead_p95_us, lead_p99_us) = {
            let res = self.reservoir.lock().unwrap();
            res.percentiles()
                .map_or((None, None, None), |(p50, p95, p99)| (Some(p50), Some(p95), Some(p99)))
        };

        ShredPairSnapshot {
            source_a: self.source_a,
            source_b: self.source_b,
            a_wins,
            b_wins,
            total_matched,
            a_win_pct,
            lead_mean_us,
            lead_p50_us,
            lead_p95_us,
            lead_p99_us,
        }
    }
}

// ---------------------------------------------------------------------------
// IP-based per-source shred counting
// ---------------------------------------------------------------------------

struct IpFilter {
    /// Wire-level source IP (dz_ip) to count shreds from.
    target_ip: u32,
    /// Per-source shred counts keyed by source name.
    per_source: DashMap<&'static str, AtomicU64>,
}

impl IpFilter {
    fn new(target_ip: u32) -> Arc<Self> {
        Arc::new(Self { target_ip, per_source: DashMap::new() })
    }
}

// ---------------------------------------------------------------------------
// Per-IP publisher tracking
// ---------------------------------------------------------------------------

struct IpStats {
    total: AtomicU64,
    wins: AtomicU64,
    last_seen_ns: AtomicU64,
}

impl IpStats {
    fn new(now_ns: u64) -> Arc<Self> {
        Arc::new(Self {
            total: AtomicU64::new(0),
            wins: AtomicU64::new(0),
            last_seen_ns: AtomicU64::new(now_ns),
        })
    }
}

/// Per-source-IP snapshot, serialized to JSONL.
#[derive(Serialize, Clone, Debug)]
pub struct IpSnapshot {
    /// Dotted-decimal IPv4 address (e.g. "1.2.3.4").
    pub src_ip: String,
    pub total_shreds: u64,
    pub wins: u64,
    pub win_pct: f64,
    pub last_seen_ns: u64,
}

pub struct PublisherTracker {
    ips: DashMap<u32, Arc<IpStats>>,
    /// When set, only count arrivals where src_ip is the scheduled slot leader.
    leader_cache: Option<Arc<LeaderCache>>,
}

impl PublisherTracker {
    fn new(leader_cache: Option<Arc<LeaderCache>>) -> Arc<Self> {
        Arc::new(Self { ips: DashMap::new(), leader_cache })
    }

    fn record_arrival(&self, src_ip: u32, now_ns: u64) {
        if src_ip == 0 {
            return;
        }
        let stats = self.ips.entry(src_ip).or_insert_with(|| IpStats::new(now_ns)).clone();
        stats.total.fetch_add(1, Relaxed);
        stats.last_seen_ns.store(now_ns, Relaxed);
    }

    /// Returns true if `src_ip` is the scheduled leader for `slot`.
    /// Always true when no leader cache is configured (no filtering).
    pub fn is_leader(&self, slot: u64, src_ip: u32) -> bool {
        match &self.leader_cache {
            None => true,
            Some(cache) => cache.is_leader(slot, src_ip),
        }
    }

    /// Returns true when race pair recording should proceed for this slot.
    /// If no leader cache is configured, always true. If configured, true only when
    /// the slot's leader is already in the cache — ensuring races are only counted
    /// for verified leader slots. For relay sources (DZ, Jito), this is the correct
    /// gate since src_ip is the relay node, not the validator.
    pub fn slot_known(&self, slot: u64) -> bool {
        match &self.leader_cache {
            None => true,
            Some(cache) => cache.slot_known(slot),
        }
    }

    fn record_win(&self, src_ip: u32, slot: u64) {
        if src_ip == 0 {
            return;
        }
        if let Some(ref cache) = self.leader_cache {
            if !cache.is_leader(slot, src_ip) {
                return;
            }
        }
        if let Some(stats) = self.ips.get(&src_ip) {
            stats.wins.fetch_add(1, Relaxed);
        }
    }

    pub fn snapshots(&self) -> Vec<IpSnapshot> {
        let mut snaps: Vec<IpSnapshot> = self
            .ips
            .iter()
            .map(|e| {
                let ip = Ipv4Addr::from(e.key().to_be_bytes());
                let total = e.value().total.load(Relaxed);
                let wins = e.value().wins.load(Relaxed);
                IpSnapshot {
                    src_ip: ip.to_string(),
                    total_shreds: total,
                    wins,
                    win_pct: if total > 0 { wins as f64 / total as f64 * 100.0 } else { 0.0 },
                    last_seen_ns: e.value().last_seen_ns.load(Relaxed),
                }
            })
            .collect();
        snaps.sort_by(|a, b| b.wins.cmp(&a.wins));
        snaps
    }
}

// ---------------------------------------------------------------------------
// Public snapshot (serialized into JSONL)
// ---------------------------------------------------------------------------

#[derive(Serialize, Clone, Debug)]
pub struct ShredPairSnapshot {
    pub source_a: &'static str,
    pub source_b: &'static str,
    pub a_wins: u64,
    pub b_wins: u64,
    pub total_matched: u64,
    /// Win rate of source_a (0–100).
    pub a_win_pct: f64,
    /// Mean winner lead time in µs (always positive).
    pub lead_mean_us: Option<f64>,
    pub lead_p50_us: Option<i64>,
    pub lead_p95_us: Option<i64>,
    pub lead_p99_us: Option<i64>,
}

// ---------------------------------------------------------------------------
// ShredRaceTracker
// ---------------------------------------------------------------------------

pub struct ShredRaceTracker {
    tx: Sender<ShredArrival>,
    pairs: Arc<DashMap<(&'static str, &'static str), Arc<ShredPairMetrics>>>,
    publisher_tracker: Arc<PublisherTracker>,
    ip_filter: Option<Arc<IpFilter>>,
}

impl ShredRaceTracker {
    /// `expected`: number of shred-tier sources that must all deliver a shred
    /// before a race result is recorded. A race is only meaningful when every
    /// configured shred feed carried the shred — partial deliveries are evicted
    /// without producing a result.
    ///
    /// `leader_cache`: when `Some`, publisher IP stats are only recorded for
    /// shreds whose source IP matches the scheduled slot leader.
    pub fn new(
        expected: usize,
        leader_cache: Option<Arc<LeaderCache>>,
        ip_filter: Option<u32>,
    ) -> Arc<Self> {
        let (tx, rx) = bounded::<ShredArrival>(4096);
        let arrivals: Arc<DashMap<(u64, u32), ShredFirstArrival>> = Arc::new(DashMap::new());
        let pairs: Arc<DashMap<(&'static str, &'static str), Arc<ShredPairMetrics>>> =
            Arc::new(DashMap::new());
        let publisher_tracker = PublisherTracker::new(leader_cache);
        let ip_filter_arc = ip_filter.map(IpFilter::new);

        // Processing thread: drain channel, match arrivals, record wins.
        let arrivals_proc = arrivals.clone();
        let pairs_proc = pairs.clone();
        let pub_proc = publisher_tracker.clone();
        let filter_proc = ip_filter_arc.clone();
        std::thread::Builder::new()
            .name("shred-race-proc".into())
            .spawn(move || {
                for arrival in &rx {
                    process_arrival(&arrivals_proc, &pairs_proc, &pub_proc, filter_proc.as_deref(), arrival, expected);
                }
            })
            .expect("failed to spawn shred-race-proc");

        // Eviction thread: every 5s remove arrivals older than 10s.
        let arrivals_evict = arrivals;
        std::thread::Builder::new()
            .name("shred-race-evict".into())
            .spawn(move || loop {
                std::thread::sleep(std::time::Duration::from_secs(5));
                let cutoff_ns = metrics::now_ns().saturating_sub(10_000_000_000);
                arrivals_evict.retain(|_, v| v.inserted_ns > cutoff_ns);
            })
            .expect("failed to spawn shred-race-evict");

        Arc::new(Self { tx, pairs, publisher_tracker, ip_filter: ip_filter_arc })
    }

    /// Get a channel sender for use in a `ShredReceiver`.
    pub fn sender(&self) -> Sender<ShredArrival> {
        self.tx.clone()
    }

    /// Snapshot all pair metrics; returns them sorted by source name for stable display.
    pub fn snapshots(&self) -> Vec<ShredPairSnapshot> {
        let mut snaps: Vec<ShredPairSnapshot> =
            self.pairs.iter().map(|e| e.value().snapshot()).collect();
        snaps.sort_by(|a, b| a.source_a.cmp(b.source_a).then(a.source_b.cmp(b.source_b)));
        snaps
    }

    /// Snapshot per-source-IP publisher stats; sorted by wins descending.
    pub fn ip_snapshots(&self) -> Vec<IpSnapshot> {
        self.publisher_tracker.snapshots()
    }

    /// Returns `(source_name, shred_count)` for each source that received shreds
    /// from the configured target IP. Empty when no IP filter is set.
    pub fn validator_source_counts(&self) -> Vec<(String, u64)> {
        self.ip_filter.as_ref().map(|f| {
            f.per_source.iter()
                .map(|e| (e.key().to_string(), e.value().load(Relaxed)))
                .collect()
        }).unwrap_or_default()
    }

    /// Record a transaction-level (signature-matched) cross-tier race result.
    ///
    /// Called from the fan-in relay thread when a transaction arrives on both a
    /// shred feed and RPC, allowing RPC to appear as a contender in the race table.
    ///
    /// `shred_source` — `&'static str` name of the shred-tier source (e.g. `"edge-solana-shreds"`).
    /// `lead_us`      — signed µs: positive when shred wins, negative when RPC wins.
    pub fn record_tx_race(&self, shred_source: &'static str, lead_us: i64) {
        const RPC: &str = "rpc";
        let (key_a, key_b) = if shred_source <= RPC {
            (shred_source, RPC)
        } else {
            (RPC, shred_source)
        };
        let pair = self.pairs
            .entry((key_a, key_b))
            .or_insert_with(|| ShredPairMetrics::new(key_a, key_b))
            .clone();
        let winner = if lead_us >= 0 { shred_source } else { RPC };
        pair.record(winner, lead_us.abs());
    }
}

// ---------------------------------------------------------------------------
// Processing logic (off hot path)
// ---------------------------------------------------------------------------

fn process_arrival(
    arrivals: &DashMap<(u64, u32), ShredFirstArrival>,
    pairs: &DashMap<(&'static str, &'static str), Arc<ShredPairMetrics>>,
    pub_tracker: &PublisherTracker,
    ip_filter: Option<&IpFilter>,
    arrival: ShredArrival,
    expected: usize,
) {
    let ShredArrival { source, slot, idx, recv_ns, src_ip } = arrival;
    let now = metrics::now_ns();

    // Record every arrival for per-IP totals (including retransmitters).
    pub_tracker.record_arrival(src_ip, recv_ns);

    // IP filter: count shreds from the target wire-level src_ip.
    if let Some(filter) = ip_filter {
        if src_ip == filter.target_ip {
            filter.per_source
                .entry(source)
                .or_insert_with(|| AtomicU64::new(0))
                .fetch_add(1, Relaxed);
        }
    }

    // Only count leader-originated shreds for the race.
    if !pub_tracker.is_leader(slot, src_ip) {
        return;
    }

    use dashmap::mapref::entry::Entry;
    match arrivals.entry((slot, idx)) {
        Entry::Occupied(mut e) => {
            // All expected sources already delivered — retransmission guard.
            if e.get().arrivals.len() >= e.get().expected {
                return;
            }
            // Duplicate from the same feed — ignore.
            if e.get().arrivals.iter().any(|&(s, _, _)| s == source) {
                return;
            }
            // Stale entry not yet evicted — remove and discard.
            if now.saturating_sub(e.get().inserted_ns) >= 10_000_000_000 {
                e.remove();
                return;
            }

            e.get_mut().arrivals.push((source, recv_ns, src_ip));

            if e.get().arrivals.len() >= e.get().expected {
                // All sources delivered — record all pairwise results.
                let mut sorted = e.get().arrivals.clone();
                sorted.sort_unstable_by_key(|&(_, ns, _)| ns);

                // Winner is the fastest arrival; record per-IP win.
                let (_, _, winner_ip) = sorted[0];
                pub_tracker.record_win(winner_ip, slot);

                for i in 0..sorted.len() {
                    for j in (i + 1)..sorted.len() {
                        let (winner_src, winner_ns, _) = sorted[i];
                        let (loser_src, loser_ns, _) = sorted[j];
                        let lead_us = (loser_ns as i64 - winner_ns as i64) / 1000;
                        // Canonical key: alphabetically sorted so (a,b) == (b,a).
                        let (key_a, key_b) =
                            if winner_src <= loser_src { (winner_src, loser_src) }
                            else { (loser_src, winner_src) };
                        let pair = pairs
                            .entry((key_a, key_b))
                            .or_insert_with(|| ShredPairMetrics::new(key_a, key_b))
                            .clone();
                        pair.record(winner_src, lead_us);
                    }
                }
            }
        }
        Entry::Vacant(e) => {
            e.insert(ShredFirstArrival {
                arrivals: vec![(source, recv_ns, src_ip)],
                inserted_ns: now,
                expected,
            });
        }
    }
}
