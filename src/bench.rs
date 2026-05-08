//! `shredtop bench` — timed benchmark with structured JSON output.
//!
//! Runs all configured sources for a fixed duration, then emits a JSON report
//! with per-source statistics including lead-time histogram, win rate, FEC recovery,
//! and coverage percentage.

use anyhow::Result;
use chrono::Utc;
use serde::Serialize;
use shred_ingest::source_metrics::SlotStats;
use shred_ingest::{
    DecodedTx, FanInSource, IpSnapshot, LeaderCache, ShredPairSnapshot, SourceMetricsSnapshot,
};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::color;
use crate::config::ProbeConfig;
use crate::monitor::build_source;

#[derive(Debug, Serialize)]
pub struct BenchReport {
    pub duration_secs: u64,
    pub sources: Vec<SourceReport>,
    pub shred_race: Vec<ShredPairSnapshot>,
    pub publisher_ips: Vec<IpSnapshot>,
}

#[derive(Debug, Serialize)]
pub struct SourceReport {
    pub name: String,
    pub shreds_received: u64,
    pub shreds_per_sec: f64,
    pub bytes_received_mb: f64,
    pub shreds_dropped: u64,
    pub slots_attempted: u64,
    pub slots_complete: u64,
    pub slots_partial: u64,
    pub slots_dropped: u64,
    pub coverage_pct: Option<f64>,
    pub fec_recovered_shreds: u64,
    pub txs_decoded: u64,
    pub txs_per_sec: f64,
    pub win_rate_pct: Option<f64>,
    pub lead_time_mean_us: Option<f64>,
    pub lead_time_p50_us: Option<i64>,
    pub lead_time_p95_us: Option<i64>,
    pub lead_time_p99_us: Option<i64>,
    pub lead_time_samples: u64,
    /// Per-slot decode outcomes (shred sources only; up to 500 most recent slots).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub slot_breakdown: Vec<SlotStats>,
}

pub fn run(config: &ProbeConfig, duration_secs: u64, output: Option<PathBuf>) -> Result<()> {
    if config.sources.is_empty() {
        anyhow::bail!(
            "no sources configured — run `shredtop init > probe.toml` to create a config"
        );
    }

    eprintln!(
        "shredtop bench — running for {}s with {} source(s)...",
        duration_secs,
        config.sources.len()
    );

    let mut fan_in = FanInSource::new();
    fan_in.filter_programs = config.filter_programs.clone();
    fan_in.leader_cache = config
        .leader_filter
        .as_ref()
        .filter(|lf| lf.enabled)
        .map(|lf| LeaderCache::new(&lf.rpc_url, lf.dz_rpc_url.as_deref()));

    for entry in &config.sources {
        let (source, metrics) = build_source(entry, None)?;
        fan_in.add_source(source, metrics);
    }

    let (out_tx, out_rx) = crossbeam_channel::bounded::<DecodedTx>(4096);
    let (all_metrics, race_tracker, _handles) = fan_in.start(out_tx);

    // Drain thread
    std::thread::spawn(move || for _ in out_rx {});

    let start = Instant::now();
    let target = Duration::from_secs(duration_secs);

    // Progress indicator every 10s
    let mut next_tick = 10u64;
    while start.elapsed() < target {
        std::thread::sleep(Duration::from_secs(1));
        let elapsed = start.elapsed().as_secs();
        if elapsed >= next_tick {
            eprintln!("  ...{}s / {}s", elapsed, duration_secs);
            next_tick += 10;
        }
    }

    let elapsed_secs = start.elapsed().as_secs_f64();
    let snapshots: Vec<SourceMetricsSnapshot> = all_metrics.iter().map(|m| m.snapshot()).collect();

    let race_snaps = race_tracker.snapshots();

    let report = BenchReport {
        duration_secs,
        sources: snapshots
            .iter()
            .map(|s| source_report(s, elapsed_secs))
            .collect(),
        shred_race: race_snaps,
        publisher_ips: race_tracker.ip_snapshots(),
    };

    let json = serde_json::to_string_pretty(&report)?;

    // Formatted human-readable report — stderr if --output, stdout otherwise
    let time_str = Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();
    let header_title = format!(" SHREDTOP BENCH REPORT  {}s  {} ", duration_secs, time_str);
    let width = 100;
    let report_lines = format_report(&report, &header_title, width);

    match &output {
        Some(path) => {
            std::fs::write(path, &json)?;
            for line in &report_lines {
                eprintln!("{}", line);
            }
            eprintln!(
                "{}",
                color::dim(&format!("Report written to {}", path.display()))
            );
        }
        None => {
            for line in &report_lines {
                println!("{}", line);
            }
            println!("{}", json);
        }
    }

    Ok(())
}

fn format_report(report: &BenchReport, header_title: &str, width: usize) -> Vec<String> {
    let sep = "=".repeat(width);
    let thin = "-".repeat(width);
    let mut lines: Vec<String> = Vec::new();

    lines.push(color::bold(&sep));
    lines.push(color::bold_cyan(&format!("{:^width$}", header_title)));
    lines.push(color::bold(&sep));
    lines.push(String::new());

    // SHRED RACE section
    lines.push(color::bold("SHRED RACE  validator \u{2192} this machine:"));
    lines.push(String::new());

    let has_race = !report.shred_race.is_empty();
    if !has_race {
        lines.push(color::dim(
            "  No races yet — waiting for same slot to appear on multiple shred feeds.",
        ));
    } else {
        lines.push(color::bold(&format!(
            "  {:<22}  {:>7}  {:>9}  {:>10}  {:>9}  {:>9}",
            "CONTENDER", "WIN%", "RACES", "FASTER BY", "LEAD p50", "LEAD p95",
        )));
        lines.push(color::dim(&format!("  {}", "-".repeat(width - 2))));

        let mut pairs: Vec<&ShredPairSnapshot> = report.shred_race.iter().collect();
        pairs.sort_by(|a, b| b.total_matched.cmp(&a.total_matched));

        for p in &pairs {
            let a_pct = p.a_win_pct;
            let b_pct = 100.0 - a_pct;
            let (faster, f_pct, slower, s_pct) = if a_pct >= b_pct {
                (p.source_a, a_pct, p.source_b, b_pct)
            } else {
                (p.source_b, b_pct, p.source_a, a_pct)
            };
            let avg_str = p
                .lead_mean_us
                .map(|v| format!("+{:.2}ms", v / 1000.0))
                .unwrap_or_else(|| "\u{2014}".into());
            let p50_str = p
                .lead_p50_us
                .map(|v| format!("+{:.1}ms", v as f64 / 1000.0))
                .unwrap_or_else(|| "\u{2014}".into());
            let p95_str = p
                .lead_p95_us
                .map(|v| format!("+{:.1}ms", v as f64 / 1000.0))
                .unwrap_or_else(|| "\u{2014}".into());

            lines.push(color::green(&format!(
                "  {:<22}  {:>6.1}%  {:>9}  {:>10}  {:>9}  {:>9}",
                faster,
                f_pct,
                format_num(p.total_matched),
                avg_str,
                p50_str,
                p95_str,
            )));
            lines.push(color::dim(&format!(
                "  {:<22}  {:>6.1}%  {:>9}  {:>10}  {:>9}  {:>9}",
                slower, s_pct, "\u{2014}", "\u{2014}", "\u{2014}", "\u{2014}",
            )));
        }
    }
    lines.push(String::new());

    // SOURCE table
    lines.push(color::bold(&format!(
        "{:<20}  {:>9}  {:>5}  {:>7}",
        "SOURCE", "SHREDS/s", "COV%", "TXS/s",
    )));
    lines.push(color::dim(&thin));
    for s in &report.sources {
        let shreds = format!("{:.0}", s.shreds_per_sec);
        let cov = s
            .coverage_pct
            .map(|p| format!("{:.0}%", p.min(100.0)))
            .unwrap_or_else(|| "\u{2014}".into());
        let txs = format!("{:.0}", s.txs_per_sec);
        lines.push(format!(
            "{:<20}  {:>9}  {:>5}  {:>7}",
            s.name, shreds, cov, txs,
        ));
    }
    lines.push(color::dim(&thin));
    lines.push(color::dim(
        "LEAD = kernel SO_TIMESTAMPNS delta between feeds  p50/p95 = percentiles  RACES = matched (slot,idx) pairs",
    ));
    lines.push(String::new());

    // PUBLISHER IPs section
    if !report.publisher_ips.is_empty() {
        lines.push(color::bold(
            "PUBLISHER IPs  (source IP → shreds delivered):",
        ));
        lines.push(String::new());
        lines.push(color::bold(&format!(
            "  {:<17}  {:>9}  {:>7}  {:>6}",
            "SOURCE IP", "SHREDS", "WINS", "WIN%",
        )));
        lines.push(color::dim(&format!("  {}", "-".repeat(width - 2))));
        for ip in &report.publisher_ips {
            lines.push(format!(
                "  {:<17}  {:>9}  {:>7}  {:>5.1}%",
                ip.src_ip,
                format_num(ip.total_shreds),
                format_num(ip.wins),
                ip.win_pct,
            ));
        }
        lines.push(String::new());
    }

    lines
}

fn format_num(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out.chars().rev().collect()
}

fn source_report(s: &SourceMetricsSnapshot, elapsed_secs: f64) -> SourceReport {
    let coverage_pct = if s.coverage_shreds_expected > 0 {
        Some(s.coverage_shreds_seen as f64 / s.coverage_shreds_expected as f64 * 100.0)
    } else {
        None
    };

    let win_rate_pct = {
        let total = s.txs_first + s.txs_duplicate;
        if total > 0 {
            Some(s.txs_first as f64 / total as f64 * 100.0)
        } else {
            None
        }
    };

    let lead_mean = if s.lead_time_count > 0 {
        Some(s.lead_time_sum_us as f64 / s.lead_time_count as f64)
    } else {
        None
    };

    SourceReport {
        name: s.name.to_string(),
        shreds_received: s.shreds_received,
        shreds_per_sec: s.shreds_received as f64 / elapsed_secs,
        bytes_received_mb: s.bytes_received as f64 / 1_048_576.0,
        shreds_dropped: s.shreds_dropped,
        slots_attempted: s.slots_attempted,
        slots_complete: s.slots_complete,
        slots_partial: s.slots_partial,
        slots_dropped: s.slots_dropped,
        coverage_pct,
        fec_recovered_shreds: s.fec_recovered_shreds,
        txs_decoded: s.txs_decoded,
        txs_per_sec: s.txs_decoded as f64 / elapsed_secs,
        win_rate_pct,
        lead_time_mean_us: lead_mean,
        lead_time_p50_us: s.lead_time_p50_us,
        lead_time_p95_us: s.lead_time_p95_us,
        lead_time_p99_us: s.lead_time_p99_us,
        lead_time_samples: s.lead_time_count,
        slot_breakdown: s.slot_log.clone(),
    }
}
