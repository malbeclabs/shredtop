//! Pipeline latency instrumentation.
//!
//! Provides nanosecond-resolution timestamps and per-stage duration accumulators.
//! On Linux, timestamps use `CLOCK_MONOTONIC_RAW` (immune to NTP slew).
//! On other platforms, an `Instant`-based fallback is used.
//!
//! Kernel `SO_TIMESTAMPNS` timestamps arrive in `CLOCK_REALTIME`. The receiver
//! converts them to `CLOCK_MONOTONIC_RAW` using a one-time offset sampled at startup
//! so all timestamps throughout the pipeline share the same reference frame.

use std::sync::atomic::{AtomicU64, Ordering};

/// Nanosecond timestamp via `CLOCK_MONOTONIC_RAW` (Linux) or `Instant` (other platforms).
#[inline(always)]
pub fn now_ns() -> u64 {
    #[cfg(target_os = "linux")]
    {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        unsafe {
            libc::clock_gettime(libc::CLOCK_MONOTONIC_RAW, &mut ts);
        }
        (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
    }
    #[cfg(not(target_os = "linux"))]
    {
        use std::time::Instant;
        static EPOCH: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
        let epoch = EPOCH.get_or_init(Instant::now);
        epoch.elapsed().as_nanos() as u64
    }
}

/// Accumulates total duration and call count for each pipeline stage.
///
/// All fields use `Relaxed` ordering — these are sampling metrics, not synchronisation.
/// Call `avg_ns(field)` to compute the mean duration for a given stage.
pub struct StageMetrics {
    pub shred_receive_ns: AtomicU64,
    pub decode_ns: AtomicU64,
    pub signal_ns: AtomicU64,
    pub execute_ns: AtomicU64,
    pub total_ns: AtomicU64,
    pub count: AtomicU64,
}

impl StageMetrics {
    pub const fn new() -> Self {
        Self {
            shred_receive_ns: AtomicU64::new(0),
            decode_ns: AtomicU64::new(0),
            signal_ns: AtomicU64::new(0),
            execute_ns: AtomicU64::new(0),
            total_ns: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    pub fn record_stage(&self, field: &AtomicU64, duration_ns: u64) {
        field.fetch_add(duration_ns, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn avg_ns(&self, field: &AtomicU64) -> u64 {
        let count = self.count.load(Ordering::Relaxed);
        if count == 0 {
            return 0;
        }
        field.load(Ordering::Relaxed) / count
    }
}

pub static METRICS: StageMetrics = StageMetrics::new();
