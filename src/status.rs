//! `shredtop status` — show the most recent snapshot from the metrics log.
//!
//! Reads the last line from /var/log/shredtop.jsonl and prints a static
//! one-shot table. Use this to check on the running service without
//! opening the live dashboard.

use anyhow::Result;
use chrono::{TimeZone, Utc};

use crate::color;
use crate::run::DEFAULT_LOG;

pub fn run() -> Result<()> {
    let content = match std::fs::read_to_string(DEFAULT_LOG) {
        Ok(c) => c,
        Err(_) => {
            eprintln!("No metrics log found at {}.", DEFAULT_LOG);
            eprintln!("Start the service first:  shredtop service start");
            return Ok(());
        }
    };

    let line = match content.lines().filter(|l| !l.is_empty()).last() {
        Some(l) => l,
        None => {
            eprintln!("Metrics log is empty — service may just be starting.");
            return Ok(());
        }
    };

    let entry: serde_json::Value = serde_json::from_str(line)?;
    let ts = entry["ts"].as_u64().unwrap_or(0) as i64;
    let dt = Utc.timestamp_opt(ts, 0).single();
    let time_str = dt
        .map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| "unknown".into());

    let started_at = entry["started_at"].as_u64().unwrap_or(0) as i64;
    let (started_str, uptime_str) = if started_at > 0 {
        let s = Utc
            .timestamp_opt(started_at, 0)
            .single()
            .map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| "—".into());
        let secs = (ts - started_at).max(0) as u64;
        let h = secs / 3600;
        let m = (secs % 3600) / 60;
        let s2 = secs % 60;
        let u = if h > 0 { format!("{}h {}m {}s", h, m, s2) }
                 else if m > 0 { format!("{}m {}s", m, s2) }
                 else { format!("{}s", s2) };
        (s, u)
    } else {
        ("—".into(), "—".into())
    };

    // Determine whether any baseline (rpc/geyser) source is present before
    // printing headers so column layout can be decided upfront.
    let has_rpc = entry["sources"]
        .as_array()
        .map(|sources| sources.iter().any(|s| s["is_rpc"].as_bool().unwrap_or(false)))
        .unwrap_or(false);

    let width = 100;
    println!("{}", color::bold(&"=".repeat(width)));
    println!(
        "{}",
        color::bold_cyan(&format!("{:^width$}", format!(" SHREDTOP STATUS  {} ", time_str)))
    );
    println!("{}", color::bold(&"=".repeat(width)));
    println!("{}", color::dim(&format!("  Started: {}   Uptime: {}", started_str, uptime_str)));
    println!();

    if has_rpc {
        println!(
            "{}",
            color::bold(&format!(
                "{:<20}  {:>9}  {:>5}  {:>6}  {:>6}  {:>9}  {:>9}  {:>9}  {:>9}",
                "SOURCE", "SHREDS/s", "COV%", "TXS/s", "BEAT%", "LEAD avg", "LEAD p50", "LEAD p95", "LEAD p99",
            ))
        );
    } else {
        println!(
            "{}",
            color::bold(&format!(
                "{:<20}  {:>9}  {:>5}  {:>6}",
                "SOURCE", "SHREDS/s", "COV%", "TXS/s",
            ))
        );
    }
    println!("{}", color::dim(&"-".repeat(width)));

    if let Some(sources) = entry["sources"].as_array() {
        for s in sources {
            let name = s["name"].as_str().unwrap_or("?");
            let is_rpc = s["is_rpc"].as_bool().unwrap_or(false);

            let shreds_str = if is_rpc {
                "—".into()
            } else {
                format!("{:.0}", s["shreds_per_sec"].as_f64().unwrap_or(0.0))
            };
            let cov = if is_rpc {
                "—".into()
            } else {
                s["coverage_pct"]
                    .as_f64()
                    .map(|p| format!("{:.0}%", p.min(100.0)))
                    .unwrap_or_else(|| "—".into())
            };
            let txs = s["txs_per_sec"].as_f64().unwrap_or(0.0);

            let row = if has_rpc {
                let beat = if is_rpc {
                    "—".into()
                } else {
                    s["beat_rpc_pct"]
                        .as_f64()
                        .map(|p| format!("{:.0}%", p))
                        .unwrap_or_else(|| "—".into())
                };
                let (avg_str, p50_str, p95_str, p99_str) = if is_rpc {
                    ("baseline".into(), "—".into(), "—".into(), "—".into())
                } else if let Some(mean_us) = s["lead_time_mean_us"].as_f64() {
                    let avg = format!("{:+.1}ms", mean_us / 1000.0);
                    let p50 = s["lead_time_p50_us"].as_f64()
                        .map(|v| format!("{:+.1}ms", v / 1000.0))
                        .unwrap_or_else(|| "—".into());
                    let p95 = s["lead_time_p95_us"].as_f64()
                        .map(|v| format!("{:+.1}ms", v / 1000.0))
                        .unwrap_or_else(|| "—".into());
                    let p99 = s["lead_time_p99_us"].as_f64()
                        .map(|v| format!("{:+.1}ms", v / 1000.0))
                        .unwrap_or_else(|| "—".into());
                    (avg, p50, p95, p99)
                } else {
                    ("—".into(), "—".into(), "—".into(), "—".into())
                };
                format!(
                    "{:<20}  {:>9}  {:>5}  {:>6.0}  {:>6}  {:>9}  {:>9}  {:>9}  {:>9}",
                    name, shreds_str, cov, txs, beat, avg_str, p50_str, p95_str, p99_str,
                )
            } else {
                format!(
                    "{:<20}  {:>9}  {:>5}  {:>6.0}",
                    name, shreds_str, cov, txs,
                )
            };

            let row = if is_rpc {
                color::dim(&row)
            } else if let Some(beat) = s["beat_rpc_pct"].as_f64() {
                if beat >= 60.0 { color::green(&row) }
                else if beat >= 40.0 { color::yellow(&row) }
                else { color::red(&row) }
            } else {
                row
            };
            println!("{}", row);
        }
    }

    println!("{}", color::dim(&"-".repeat(width)));
    println!();

    // Dedup diagnostics
    println!("{}", color::bold("DEDUP (cumulative since start):"));
    println!(
        "{}",
        color::bold(&format!(
            "  {:<20}  {:>10}  {:>12}",
            "SOURCE", "TXS_FIRST", "TXS_DUPLICATE"
        ))
    );
    if let Some(sources) = entry["sources"].as_array() {
        for s in sources {
            let name = s["name"].as_str().unwrap_or("?");
            let first = s["txs_first"].as_u64().unwrap_or(0);
            let dup = s["txs_duplicate"].as_u64().unwrap_or(0);
            println!("  {:<20}  {:>10}  {:>12}", name, first, dup);
        }
    }
    println!();

    // Shred-level race section
    println!("{}", color::bold(&format!(
        "SHRED RACE  validator \u{2192} this machine  (since start):"
    )));
    let race_pairs = entry["shred_race"].as_array();
    let has_race = race_pairs.map(|p| !p.is_empty()).unwrap_or(false);
    if !has_race {
        println!(
            "{}",
            color::dim("  No races yet — waiting for same slot to appear on multiple shred feeds.")
        );
    } else {
        println!(
            "{}",
            color::bold(&format!(
                "  {:<22}  {:>7}  {:>9}  {:>10}  {:>9}  {:>9}",
                "CONTENDER", "WIN%", "RACES", "FASTER BY", "LEAD p50", "LEAD p95",
            ))
        );
        let mut pairs: Vec<&serde_json::Value> = race_pairs.unwrap().iter().collect();
        pairs.sort_by(|a, b| {
            let ma = a["total_matched"].as_u64().unwrap_or(0);
            let mb = b["total_matched"].as_u64().unwrap_or(0);
            mb.cmp(&ma)
        });
        for (i, p) in pairs.iter().enumerate() {
            if i > 0 {
                println!("  \u{00b7}\u{00b7}\u{00b7}\u{00b7}\u{00b7}");
            }
            let sa = p["source_a"].as_str().unwrap_or("?");
            let sb = p["source_b"].as_str().unwrap_or("?");
            let matched = p["total_matched"].as_u64().unwrap_or(0);
            let a_pct = p["a_win_pct"].as_f64().unwrap_or(0.0);
            let b_pct = 100.0 - a_pct;
            let (faster, f_pct, slower, s_pct) = if a_pct >= b_pct {
                (sa, a_pct, sb, b_pct)
            } else {
                (sb, b_pct, sa, a_pct)
            };
            let avg_str = p["lead_mean_us"]
                .as_f64()
                .map(|v| format!("+{:.2}ms", v / 1000.0))
                .unwrap_or_else(|| "—".into());
            let p50_str = p["lead_p50_us"]
                .as_f64()
                .map(|v| format!("+{:.1}ms", v / 1000.0))
                .unwrap_or_else(|| "—".into());
            let p95_str = p["lead_p95_us"]
                .as_f64()
                .map(|v| format!("+{:.1}ms", v / 1000.0))
                .unwrap_or_else(|| "—".into());
            println!(
                "{}",
                color::green(&format!(
                    "  {:<22}  {:>6.1}%  {:>9}  {:>10}  {:>9}  {:>9}",
                    faster, f_pct, format_num(matched), avg_str, p50_str, p95_str,
                ))
            );
            println!(
                "{}",
                color::dim(&format!(
                    "  {:<22}  {:>6.1}%  {:>9}  {:>10}  {:>9}  {:>9}",
                    slower, s_pct, "—", "—", "—", "—",
                ))
            );
        }
    }
    println!();
    println!("{}", color::dim(
        "  Matched on (slot, shred_index) \u{2014} when the same shred arrives on both feeds, records"
    ));
    println!("{}", color::dim(
        "  which relay delivered it first and by how much. Timing uses the kernel UDP receive"
    ));
    println!("{}", color::dim(
        "  timestamp (SO_TIMESTAMPNS), before any userspace processing."
    ));
    println!();
    if !has_rpc {
        println!(
            "{}",
            color::yellow(
                "  Shred-race-only mode — BEAT%/LEAD require a baseline source. Run `shredtop discover` to add one."
            )
        );
        println!();
    }
    println!(
        "{}",
        color::dim(&format!("Log: {}  (shredtop service status for service health)", DEFAULT_LOG))
    );

    Ok(())
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
