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
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};

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
}

struct ShredFirstArrival {
    recv_ns: u64,
    source: &'static str,
    inserted_ns: u64,
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
}

impl ShredRaceTracker {
    pub fn new() -> Arc<Self> {
        let (tx, rx) = bounded::<ShredArrival>(4096);
        let arrivals: Arc<DashMap<(u64, u32), ShredFirstArrival>> = Arc::new(DashMap::new());
        let pairs: Arc<DashMap<(&'static str, &'static str), Arc<ShredPairMetrics>>> =
            Arc::new(DashMap::new());

        // Processing thread: drain channel, match arrivals, record wins.
        let arrivals_proc = arrivals.clone();
        let pairs_proc = pairs.clone();
        std::thread::Builder::new()
            .name("shred-race-proc".into())
            .spawn(move || {
                for arrival in &rx {
                    process_arrival(&arrivals_proc, &pairs_proc, arrival);
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

        Arc::new(Self { tx, pairs })
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
}

// ---------------------------------------------------------------------------
// Processing logic (off hot path)
// ---------------------------------------------------------------------------

fn process_arrival(
    arrivals: &DashMap<(u64, u32), ShredFirstArrival>,
    pairs: &DashMap<(&'static str, &'static str), Arc<ShredPairMetrics>>,
    arrival: ShredArrival,
) {
    let ShredArrival { source, slot, idx, recv_ns } = arrival;
    let now = metrics::now_ns();

    use dashmap::mapref::entry::Entry;
    match arrivals.entry((slot, idx)) {
        Entry::Occupied(e) => {
            let first_source = e.get().source;
            if first_source == source {
                // Duplicate from the same feed — ignore.
                return;
            }
            let first_recv_ns = e.get().recv_ns;
            e.remove();

            // Discard if delta looks like an eviction artifact (>10s).
            let lead_us = ((first_recv_ns as i64) - (recv_ns as i64)).abs() / 1000;
            if lead_us >= 10_000_000 {
                return;
            }

            let winner = if first_recv_ns <= recv_ns { first_source } else { source };

            // Canonical key: alphabetically sorted so (a,b) == (b,a).
            let (key_a, key_b) = if first_source <= source {
                (first_source, source)
            } else {
                (source, first_source)
            };

            let pair = pairs
                .entry((key_a, key_b))
                .or_insert_with(|| ShredPairMetrics::new(key_a, key_b))
                .clone();
            pair.record(winner, lead_us);
        }
        Entry::Vacant(e) => {
            e.insert(ShredFirstArrival { recv_ns, source, inserted_ns: now });
        }
    }
}
