//! `shredtop run` — background data collection daemon.
//!
//! Runs the full shred pipeline with no TUI and writes per-source metrics
//! snapshots to a JSONL log file every N seconds. Designed to run under
//! systemd or in a tmux session. Use `shredtop status` to query the log,
//! or `shredtop service install` to manage via systemd.

use anyhow::Result;
use serde::Serialize;
use shred_ingest::{CaptureEvent, DecodedTx, FanInSource, ShredPairSnapshot, SourceMetricsSnapshot};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::capture;
use crate::config::ProbeConfig;
use crate::monitor::build_source;

pub const DEFAULT_LOG: &str = "/var/log/shredtop.jsonl";

#[derive(Serialize)]
struct LogEntry<'a> {
    ts: u64,
    started_at: u64,
    sources: Vec<SourceSnap<'a>>,
    shred_race: Vec<ShredPairSnapshot>,
}

#[derive(Serialize)]
struct SourceSnap<'a> {
    name: &'a str,
    /// True for RPC-tier sources (rpc, geyser); false for shred-tier feeds.
    is_rpc: bool,
    shreds_per_sec: f64,
    coverage_pct: Option<f64>,
    /// % of matched transactions where this feed beat RPC (lead_time > 0)
    beat_rpc_pct: Option<f64>,
    lead_time_mean_us: Option<f64>,
    lead_time_p50_us: Option<i64>,
    lead_time_p95_us: Option<i64>,
    lead_time_p99_us: Option<i64>,
    lead_time_samples: u64,
    txs_per_sec: f64,
    /// Total transactions this source won the dedup race (first arrival, cumulative)
    txs_first: u64,
    /// Total transactions this source arrived as a duplicate (matched another source, cumulative)
    txs_duplicate: u64,
}

pub fn run(config: &ProbeConfig, interval_secs: u64, log_path: PathBuf) -> Result<()> {
    if config.sources.is_empty() {
        anyhow::bail!("no sources configured — run `shredtop discover` first");
    }

    eprintln!(
        "shredtop run — {} source(s), logging to {} every {}s",
        config.sources.len(),
        log_path.display(),
        interval_secs
    );
    eprintln!("Run `shredtop status` to check current metrics.");

    // Spin up the capture thread if [capture] is configured and enabled.
    let cap_tx: Option<crossbeam_channel::Sender<CaptureEvent>> =
        if let Some(cap_cfg) = config.capture.as_ref().filter(|c| c.enabled) {
            let (tx, rx) = crossbeam_channel::bounded::<CaptureEvent>(4096);
            capture::spawn_capture_thread(cap_cfg, rx);
            let sizes: Vec<String> = cap_cfg
                .formats
                .iter()
                .enumerate()
                .map(|(i, fmt)| {
                    let max = cap_cfg.max_size_mb.get(i).copied().unwrap_or(10_000);
                    format!("{fmt}≤{max}MB")
                })
                .collect();
            eprintln!(
                "shredtop capture — {} → {}  ({} MB rotate)",
                sizes.join(", "),
                cap_cfg.output_dir,
                cap_cfg.rotate_mb,
            );
            Some(tx)
        } else {
            None
        };

    let mut fan_in = FanInSource::new();
    fan_in.filter_programs = config.filter_programs.clone();
    for entry in &config.sources {
        let (source, metrics) = build_source(entry, cap_tx.clone())?;
        fan_in.add_source(source, metrics);
    }

    let (out_tx, out_rx) = crossbeam_channel::bounded::<DecodedTx>(4096);
    let (all_metrics, race_tracker, _handles) = fan_in.start(out_tx);

    std::thread::spawn(move || {
        for _ in out_rx {}
    });

    let started_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Truncate the log at startup so the monitor immediately reflects this run.
    if let Ok(f) = std::fs::File::create(&log_path) {
        drop(f);
    }

    let interval = Duration::from_secs(interval_secs);
    let mut prev: Vec<SourceMetricsSnapshot> = all_metrics.iter().map(|m| m.snapshot()).collect();
    let mut prev_time = Instant::now();

    loop {
        std::thread::sleep(interval);

        let now = Instant::now();
        let elapsed = now.duration_since(prev_time).as_secs_f64();
        prev_time = now;

        let curr: Vec<SourceMetricsSnapshot> = all_metrics.iter().map(|m| m.snapshot()).collect();
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let entry = LogEntry {
            ts,
            started_at,
            sources: curr
                .iter()
                .zip(prev.iter())
                .map(|(c, p)| make_snap(c, p, elapsed))
                .collect(),
            shred_race: race_tracker.snapshots(),
        };

        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&log_path) {
            if let Ok(line) = serde_json::to_string(&entry) {
                let _ = writeln!(file, "{}", line);
            }
        }

        prev = curr;
    }
}

fn make_snap<'a>(
    c: &'a SourceMetricsSnapshot,
    p: &SourceMetricsSnapshot,
    elapsed: f64,
) -> SourceSnap<'a> {
    let shreds_delta = c.shreds_received.saturating_sub(p.shreds_received);
    let txs_delta = c.txs_decoded.saturating_sub(p.txs_decoded);

    let coverage_pct = if c.coverage_shreds_expected > 0 {
        Some((c.coverage_shreds_seen as f64 / c.coverage_shreds_expected as f64 * 100.0).min(100.0))
    } else {
        None
    };

    let beat_rpc_pct = if c.lead_time_count > 0 {
        Some(c.lead_wins as f64 / c.lead_time_count as f64 * 100.0)
    } else {
        None
    };

    let lead_mean = if c.lead_time_count > 0 {
        Some(c.lead_time_sum_us as f64 / c.lead_time_count as f64)
    } else {
        None
    };

    SourceSnap {
        name: c.name,
        is_rpc: c.is_rpc,
        shreds_per_sec: shreds_delta as f64 / elapsed,
        coverage_pct,
        beat_rpc_pct,
        lead_time_mean_us: lead_mean,
        lead_time_p50_us: c.lead_time_p50_us,
        lead_time_p95_us: c.lead_time_p95_us,
        lead_time_p99_us: c.lead_time_p99_us,
        lead_time_samples: c.lead_time_count,
        txs_per_sec: txs_delta as f64 / elapsed,
        txs_first: c.txs_first,
        txs_duplicate: c.txs_duplicate,
    }
}
