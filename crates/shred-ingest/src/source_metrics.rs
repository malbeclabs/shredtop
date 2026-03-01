use serde::Serialize;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------------------
// Per-slot stats emitted by the decoder when a slot is finalised
// ---------------------------------------------------------------------------

/// Maximum number of per-slot records kept in the rolling log.
/// At ~400ms per slot this covers roughly 3 minutes of history.
const SLOT_LOG_CAP: usize = 500;

/// Outcome of a single slot's decode attempt.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SlotOutcome {
    /// All data shreds arrived and the slot was fully decoded.
    Complete,
    /// Some shreds arrived and were decoded; coverage was incomplete.
    Partial,
    /// The slot expired with no decoded transactions.
    Dropped,
}

/// Per-slot decode statistics collected by [`ShredDecoder`].
#[derive(Debug, Clone, Serialize)]
pub struct SlotStats {
    pub slot: u64,
    /// Number of unique data shreds received (includes FEC-recovered shreds).
    pub shreds_seen: u32,
    /// Number of data shreds reconstructed via Reed-Solomon FEC recovery.
    pub fec_recovered: u32,
    /// Transactions decoded from this slot.
    pub txs_decoded: u32,
    pub outcome: SlotOutcome,
}

// ---------------------------------------------------------------------------
// Lead-time reservoir — circular buffer, sorted at snapshot time
// ---------------------------------------------------------------------------

const RESERVOIR_CAP: usize = 4096;

struct LeadTimeReservoir {
    buf: [i64; RESERVOIR_CAP],
    /// Number of valid entries: 0..=RESERVOIR_CAP
    len: usize,
    /// Next write index (wraps around once full)
    pos: usize,
}

impl LeadTimeReservoir {
    fn new() -> Self {
        Self {
            buf: [0; RESERVOIR_CAP],
            len: 0,
            pos: 0,
        }
    }

    fn push(&mut self, v: i64) {
        self.buf[self.pos] = v;
        self.pos = (self.pos + 1) % RESERVOIR_CAP;
        if self.len < RESERVOIR_CAP {
            self.len += 1;
        }
    }

    /// Returns (p50, p95, p99) in µs, or None if empty.
    /// Sorts a clone of the buffer — called at most once every snapshot interval.
    fn percentiles(&self) -> Option<(i64, i64, i64)> {
        if self.len == 0 {
            return None;
        }
        let mut sorted = self.buf[..self.len].to_vec();
        sorted.sort_unstable();
        let n = sorted.len();
        let p50 = sorted[(n * 50 / 100).min(n - 1)];
        let p95 = sorted[(n * 95 / 100).min(n - 1)];
        let p99 = sorted[(n * 99 / 100).min(n - 1)];
        Some((p50, p95, p99))
    }
}

// ---------------------------------------------------------------------------
// SourceMetrics
// ---------------------------------------------------------------------------

/// Atomic per-source quality counters.
/// All atomic writes use Relaxed ordering — these are sampling metrics, not synchronisation.
pub struct SourceMetrics {
    pub name: &'static str,
    /// True for RPC-tier sources (rpc, geyser); false for shred-tier feeds.
    /// Used by the dashboard to show `—` instead of 0 for shred-only columns.
    pub is_rpc: bool,

    // Ingestion
    pub shreds_received: AtomicU64,
    pub bytes_received: AtomicU64,
    /// Shreds silently dropped because the receiver→decoder channel was full
    /// (backpressure from the decoder falling behind).
    pub shreds_dropped: AtomicU64,

    // Slot outcomes
    pub slots_attempted: AtomicU64,
    pub slots_complete: AtomicU64,
    pub slots_partial: AtomicU64,
    pub slots_dropped: AtomicU64,

    // Coverage (data shreds)
    pub coverage_shreds_seen: AtomicU64,
    pub coverage_shreds_expected: AtomicU64,

    // FEC recovery
    pub fec_recovered_shreds: AtomicU64,

    // Tx flow
    pub txs_decoded: AtomicU64,
    pub txs_emitted: AtomicU64,
    /// Won the fan-in dedup race (first arrival)
    pub txs_first: AtomicU64,
    /// Lost the fan-in dedup race (duplicate)
    pub txs_duplicate: AtomicU64,

    // Lead time relative to RPC (µs, positive = shred arrived before RPC)
    pub lead_time_count: AtomicU64,
    /// Number of lead-time samples where this source beat RPC (lead_time > 0)
    pub lead_wins: AtomicU64,
    pub lead_time_sum_us: AtomicI64,
    /// Rolling reservoir of recent samples; sorted at snapshot time to compute percentiles.
    lead_time_reservoir: Mutex<LeadTimeReservoir>,

    /// Rolling log of per-slot decode outcomes emitted by the decoder.
    /// Capped at SLOT_LOG_CAP; oldest entries are evicted when full.
    /// Only populated for shred-type sources (never for RPC/Geyser).
    slot_log: Mutex<VecDeque<SlotStats>>,
}

/// Plain-struct snapshot of SourceMetrics for display (no atomics).
#[derive(Debug, Clone)]
pub struct SourceMetricsSnapshot {
    pub name: &'static str,
    pub is_rpc: bool,
    pub shreds_received: u64,
    pub bytes_received: u64,
    pub shreds_dropped: u64,
    pub slots_attempted: u64,
    pub slots_complete: u64,
    pub slots_partial: u64,
    pub slots_dropped: u64,
    pub coverage_shreds_seen: u64,
    pub coverage_shreds_expected: u64,
    pub fec_recovered_shreds: u64,
    pub txs_decoded: u64,
    pub txs_emitted: u64,
    pub txs_first: u64,
    pub txs_duplicate: u64,
    pub lead_time_count: u64,
    pub lead_wins: u64,
    pub lead_time_sum_us: i64,
    pub lead_time_p50_us: Option<i64>,
    pub lead_time_p95_us: Option<i64>,
    pub lead_time_p99_us: Option<i64>,
    /// Per-slot decode outcomes from the rolling log (up to SLOT_LOG_CAP entries).
    pub slot_log: Vec<SlotStats>,
}

impl SourceMetrics {
    pub fn new(name: &'static str, is_rpc: bool) -> Arc<Self> {
        Arc::new(Self {
            name,
            is_rpc,
            shreds_received: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            shreds_dropped: AtomicU64::new(0),
            slots_attempted: AtomicU64::new(0),
            slots_complete: AtomicU64::new(0),
            slots_partial: AtomicU64::new(0),
            slots_dropped: AtomicU64::new(0),
            coverage_shreds_seen: AtomicU64::new(0),
            coverage_shreds_expected: AtomicU64::new(0),
            fec_recovered_shreds: AtomicU64::new(0),
            txs_decoded: AtomicU64::new(0),
            txs_emitted: AtomicU64::new(0),
            txs_first: AtomicU64::new(0),
            txs_duplicate: AtomicU64::new(0),
            lead_time_count: AtomicU64::new(0),
            lead_wins: AtomicU64::new(0),
            lead_time_sum_us: AtomicI64::new(0),
            lead_time_reservoir: Mutex::new(LeadTimeReservoir::new()),
            slot_log: Mutex::new(VecDeque::with_capacity(SLOT_LOG_CAP)),
        })
    }

    /// Record a per-slot decode outcome from the shred decoder.
    /// The log is bounded to SLOT_LOG_CAP entries; the oldest entry is dropped when full.
    pub fn push_slot_stats(&self, stats: SlotStats) {
        let mut log = self.slot_log.lock().unwrap();
        if log.len() >= SLOT_LOG_CAP {
            log.pop_front();
        }
        log.push_back(stats);
    }

    /// Outlier bounds for lead-time samples (µs).
    /// Samples outside this range are silently discarded — they indicate measurement
    /// artifacts (e.g. RPC block-fetch retry) rather than real network latency.
    pub const LEAD_TIME_MAX_US: i64 = 2_000_000; // 2 000 ms
    pub const LEAD_TIME_MIN_US: i64 = -500_000; //  -500 ms

    /// Record a single lead-time sample in microseconds.
    /// Positive values mean this source arrived before its counterpart.
    /// Samples outside [LEAD_TIME_MIN_US, LEAD_TIME_MAX_US] are discarded.
    pub fn record_lead_time_us(&self, us: i64) {
        if us > Self::LEAD_TIME_MAX_US || us < Self::LEAD_TIME_MIN_US {
            return;
        }
        self.lead_time_count.fetch_add(1, Relaxed);
        if us > 0 {
            self.lead_wins.fetch_add(1, Relaxed);
        }
        self.lead_time_sum_us.fetch_add(us, Relaxed);
        self.lead_time_reservoir.lock().unwrap().push(us);
    }

    /// Mean lead time in µs, or None if no samples yet.
    pub fn mean_lead_time_us(&self) -> Option<f64> {
        let count = self.lead_time_count.load(Relaxed);
        if count == 0 {
            return None;
        }
        Some(self.lead_time_sum_us.load(Relaxed) as f64 / count as f64)
    }

    /// Shred coverage as a percentage, or None if no expected count recorded.
    pub fn coverage_pct(&self) -> Option<f64> {
        let expected = self.coverage_shreds_expected.load(Relaxed);
        if expected == 0 {
            return None;
        }
        Some(self.coverage_shreds_seen.load(Relaxed) as f64 / expected as f64 * 100.0)
    }

    /// Fraction of decoded txs that won the fan-in race, or None if no data.
    pub fn win_rate(&self) -> Option<f64> {
        let first = self.txs_first.load(Relaxed);
        let dup = self.txs_duplicate.load(Relaxed);
        if first + dup == 0 {
            return None;
        }
        Some(first as f64 / (first + dup) as f64 * 100.0)
    }

    /// Capture a consistent point-in-time snapshot (slight skew possible on atomics;
    /// reservoir lock is held only for the percentile sort).
    pub fn snapshot(&self) -> SourceMetricsSnapshot {
        let (lead_p50, lead_p95, lead_p99) = {
            let res = self.lead_time_reservoir.lock().unwrap();
            res.percentiles()
                .map_or((None, None, None), |(p50, p95, p99)| {
                    (Some(p50), Some(p95), Some(p99))
                })
        };

        let slot_log = {
            let log = self.slot_log.lock().unwrap();
            log.iter().cloned().collect()
        };

        SourceMetricsSnapshot {
            name: self.name,
            is_rpc: self.is_rpc,
            shreds_received: self.shreds_received.load(Relaxed),
            bytes_received: self.bytes_received.load(Relaxed),
            shreds_dropped: self.shreds_dropped.load(Relaxed),
            slots_attempted: self.slots_attempted.load(Relaxed),
            slots_complete: self.slots_complete.load(Relaxed),
            slots_partial: self.slots_partial.load(Relaxed),
            slots_dropped: self.slots_dropped.load(Relaxed),
            coverage_shreds_seen: self.coverage_shreds_seen.load(Relaxed),
            coverage_shreds_expected: self.coverage_shreds_expected.load(Relaxed),
            fec_recovered_shreds: self.fec_recovered_shreds.load(Relaxed),
            txs_decoded: self.txs_decoded.load(Relaxed),
            txs_emitted: self.txs_emitted.load(Relaxed),
            txs_first: self.txs_first.load(Relaxed),
            txs_duplicate: self.txs_duplicate.load(Relaxed),
            lead_time_count: self.lead_time_count.load(Relaxed),
            lead_wins: self.lead_wins.load(Relaxed),
            lead_time_sum_us: self.lead_time_sum_us.load(Relaxed),
            lead_time_p50_us: lead_p50,
            lead_time_p95_us: lead_p95,
            lead_time_p99_us: lead_p99,
            slot_log,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lead_time_percentiles() {
        let m = SourceMetrics::new("test", false);
        // Insert 100 values 1µs..=100µs
        for i in 1i64..=100 {
            m.record_lead_time_us(i);
        }
        assert_eq!(m.lead_time_count.load(Relaxed), 100);
        let snap = m.snapshot();
        // sorted[0..100] = [1, 2, ..., 100]
        // p50: idx = (100*50/100).min(99) = 50 → sorted[50] = 51
        // p95: idx = (100*95/100).min(99) = 95 → sorted[95] = 96
        // p99: idx = (100*99/100).min(99) = 99 → sorted[99] = 100
        assert_eq!(snap.lead_time_p50_us, Some(51));
        assert_eq!(snap.lead_time_p95_us, Some(96));
        assert_eq!(snap.lead_time_p99_us, Some(100));
        let mean = m.mean_lead_time_us().unwrap();
        assert!((mean - 50.5).abs() < 0.1);
    }

    #[test]
    fn test_lead_time_outlier_cap() {
        let m = SourceMetrics::new("test", false);
        m.record_lead_time_us(1_000_000);
        m.record_lead_time_us(-400_000);
        m.record_lead_time_us(2_000_001); // outlier, discarded
        m.record_lead_time_us(6_724_000); // outlier, discarded
        m.record_lead_time_us(4_994_000); // outlier, discarded
        m.record_lead_time_us(-500_001);  // outlier, discarded
        assert_eq!(m.lead_time_count.load(Relaxed), 2);
        let snap = m.snapshot();
        assert!(snap.lead_time_p50_us.is_some());
        assert!(snap.lead_time_p99_us.is_some());
    }

    #[test]
    fn test_win_rate() {
        let m = SourceMetrics::new("test", false);
        assert!(m.win_rate().is_none());
        m.txs_first.fetch_add(7, Relaxed);
        m.txs_duplicate.fetch_add(3, Relaxed);
        let wr = m.win_rate().unwrap();
        assert!((wr - 70.0).abs() < 0.01);
    }

    #[test]
    fn test_coverage_pct() {
        let m = SourceMetrics::new("test", false);
        assert!(m.coverage_pct().is_none());
        m.coverage_shreds_seen.store(67, Relaxed);
        m.coverage_shreds_expected.store(100, Relaxed);
        let cov = m.coverage_pct().unwrap();
        assert!((cov - 67.0).abs() < 0.01);
    }

    #[test]
    fn test_snapshot() {
        let m = SourceMetrics::new("snap", false);
        m.shreds_received.store(100, Relaxed);
        m.txs_decoded.store(42, Relaxed);
        let s = m.snapshot();
        assert_eq!(s.name, "snap");
        assert_eq!(s.shreds_received, 100);
        assert_eq!(s.txs_decoded, 42);
        assert!(s.lead_time_p50_us.is_none());
    }

    #[test]
    fn test_reservoir_wraps() {
        let m = SourceMetrics::new("wrap", false);
        // Fill past capacity; all values are the same constant
        for _ in 0..RESERVOIR_CAP + 100 {
            m.record_lead_time_us(500_000);
        }
        let snap = m.snapshot();
        assert_eq!(snap.lead_time_p50_us, Some(500_000));
        assert_eq!(snap.lead_time_p99_us, Some(500_000));
    }
}
