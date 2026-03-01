//! `shredtop monitor` — live dashboard reading from the service metrics log.
//!
//! This command is a read-only view. It reads `/var/log/shredtop.jsonl` written
//! by `shredtop run` / `shredtop service start` and redraws the dashboard every
//! N seconds. Ctrl-C closes the view; the background service keeps running.

use anyhow::Result;
use chrono::{TimeZone, Utc};
use libc;
use shred_ingest::{GeyserTxSource, JitoShredstreamSource, RpcTxSource, ShredTxSource, TurbineTxSource, SourceMetrics};
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::color;
use crate::config::SourceEntry;
use crate::run::DEFAULT_LOG;

static RUNNING: AtomicBool = AtomicBool::new(true);

extern "C" fn handle_sigint(_: libc::c_int) {
    RUNNING.store(false, Ordering::SeqCst);
}

fn log_has_data() -> bool {
    std::fs::metadata(DEFAULT_LOG)
        .map(|m| m.len() > 0)
        .unwrap_or(false)
}

pub fn run(interval_secs: u64) -> Result<()> {
    // If the log file doesn't exist at all, the service isn't installed.
    if std::fs::metadata(DEFAULT_LOG).is_err() {
        eprintln!("No metrics log found at {}.", DEFAULT_LOG);
        eprintln!();
        eprintln!("Start the background service first:");
        eprintln!("  shredtop service start");
        eprintln!();
        eprintln!("Then run `shredtop monitor` again.");
        return Ok(());
    }

    // Log exists but is empty — service just started. Poll up to 30s.
    if !log_has_data() {
        println!(
            "{}",
            color::yellow("Service recently started — monitor will appear in under 30s...")
        );
        let mut waited = 0u32;
        loop {
            std::thread::sleep(std::time::Duration::from_secs(5));
            waited += 5;
            if log_has_data() {
                // Clear the waiting message before launching dashboard
                print!("\x1b[1A\x1b[2K");
                break;
            }
            if waited >= 30 {
                println!(
                    "{}",
                    color::yellow("Service is taking longer than expected. Check: shredtop service status")
                );
                return Ok(());
            }
        }
    }

    RUNNING.store(true, Ordering::SeqCst);
    unsafe { libc::signal(libc::SIGINT, handle_sigint as *const () as libc::sighandler_t) };

    println!(
        "{}",
        color::bold("SHREDTOP MONITOR  —  Ctrl-C to close  (service keeps running)")
    );
    println!();

    let mut lines_drawn = 0usize;

    while RUNNING.load(Ordering::SeqCst) {
        let snapshot = read_last_entry(DEFAULT_LOG);

        // Overwrite previous dashboard draw
        if lines_drawn > 0 {
            print!("\x1b[{}A\x1b[0J", lines_drawn);
        }

        lines_drawn = match snapshot {
            Some(entry) => draw_dashboard(&entry),
            None => {
                let line = "Waiting for first snapshot...";
                println!("{}", line);
                1
            }
        };
        std::io::stdout().flush().ok();

        // Sleep in small increments so Ctrl-C is responsive
        let mut waited = 0u64;
        while waited < interval_secs && RUNNING.load(Ordering::SeqCst) {
            std::thread::sleep(std::time::Duration::from_secs(1));
            waited += 1;
        }
    }

    println!();
    println!("View closed.  Service is still running in the background.");
    println!("  shredtop status  — check metrics any time");

    Ok(())
}

fn read_last_entry(path: &str) -> Option<serde_json::Value> {
    let content = std::fs::read_to_string(path).ok()?;
    let line = content.lines().filter(|l| !l.is_empty()).last()?;
    serde_json::from_str(line).ok()
}

fn draw_dashboard(entry: &serde_json::Value) -> usize {
    const W: usize = 100;
    let mut out: Vec<String> = Vec::new();

    // Timestamp from log entry
    let ts = entry["ts"].as_u64().unwrap_or(0) as i64;
    let time_str = Utc
        .timestamp_opt(ts, 0)
        .single()
        .map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| "—".into());

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

    // Header
    out.push(color::bold(&"=".repeat(W)));
    out.push(color::bold_cyan(&format!("{:^W$}", format!("  SHREDTOP FEED QUALITY  {}  ", time_str))));
    out.push(color::bold(&"=".repeat(W)));
    out.push(color::dim(&format!("  Started: {}   Uptime: {}", started_str, uptime_str)));
    out.push(String::new());

    // Determine whether any baseline (rpc/geyser) source is present — must
    // scan first so column headers can be decided before row rendering.
    let mut has_rpc = false;
    if let Some(sources) = entry["sources"].as_array() {
        for s in sources {
            if s["is_rpc"].as_bool().unwrap_or(false) {
                has_rpc = true;
                break;
            }
        }
    }

    // Column headers — BEAT%/LEAD columns only shown when a baseline exists
    if has_rpc {
        out.push(color::bold(&format!(
            "{:<20}  {:>9}  {:>5}  {:>6}  {:>6}  {:>9}  {:>9}  {:>9}  {:>9}",
            "SOURCE", "SHREDS/s", "COV%", "TXS/s", "BEAT%", "LEAD avg", "LEAD p50", "LEAD p95", "LEAD p99",
        )));
    } else {
        out.push(color::bold(&format!(
            "{:<20}  {:>9}  {:>5}  {:>6}",
            "SOURCE", "SHREDS/s", "COV%", "TXS/s",
        )));
    }
    out.push(color::dim(&"-".repeat(W)));

    let mut edge_lines: Vec<String> = Vec::new();

    if let Some(sources) = entry["sources"].as_array() {
        for s in sources {
            let name = s["name"].as_str().unwrap_or("?");
            let is_rpc = s["is_rpc"].as_bool().unwrap_or(false);

            let shreds_str = if is_rpc {
                "—".into()
            } else {
                format!("{:.0}", s["shreds_per_sec"].as_f64().unwrap_or(0.0))
            };

            let cov_str = s["coverage_pct"]
                .as_f64()
                .map(|p| format!("{:.0}%", p.min(100.0)))
                .unwrap_or_else(|| "—".into());

            let txs_str = format!("{:.0}", s["txs_per_sec"].as_f64().unwrap_or(0.0));

            let row = if has_rpc {
                let beat_str = if is_rpc {
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
                    "{:<20}  {:>9}  {:>5}  {:>6}  {:>6}  {:>9}  {:>9}  {:>9}  {:>9}",
                    name, shreds_str, cov_str, txs_str, beat_str, avg_str, p50_str, p95_str, p99_str,
                )
            } else {
                format!(
                    "{:<20}  {:>9}  {:>5}  {:>6}",
                    name, shreds_str, cov_str, txs_str,
                )
            };

            // Colorize entire row based on source type and edge health
            let row = if is_rpc {
                color::dim(&row)
            } else if let Some(beat) = s["beat_rpc_pct"].as_f64() {
                if beat >= 60.0 {
                    color::green(&row)
                } else if beat >= 40.0 {
                    color::yellow(&row)
                } else {
                    color::red(&row)
                }
            } else {
                row
            };
            out.push(row);

            // Edge assessment for shred sources (only meaningful with a baseline)
            if !is_rpc && has_rpc {
                if let Some(mean_us) = s["lead_time_mean_us"].as_f64() {
                    let mean_ms = mean_us / 1000.0;
                    let samples = s["lead_time_samples"].as_u64().unwrap_or(0);
                    let (label, symbol) = if mean_us > 1_000.0 {
                        ("AHEAD of RPC", color::bold_green("✓"))
                    } else if mean_us > 0.0 {
                        ("marginally ahead", color::yellow("~"))
                    } else if mean_us > -5_000.0 {
                        ("BEHIND RPC", color::yellow("⚠"))
                    } else {
                        ("BADLY BEHIND RPC", color::red("✗"))
                    };
                    edge_lines.push(format!(
                        "  {}  {:<20} {}  by {:.2}ms avg  ({} samples)",
                        symbol, name, label, mean_ms.abs(), samples,
                    ));
                }
            }
        }
    }

    out.push(color::dim(&"-".repeat(W)));

    // Shred race section — directly under the feed table, before edge assessment
    out.push(String::new());
    out.push(color::bold(&format!(
        "SHRED RACE  validator \u{2192} this machine  (since start):"
    )));
    let race_pairs = entry["shred_race"].as_array();
    let has_race = race_pairs.map(|p| !p.is_empty()).unwrap_or(false);
    if !has_race {
        out.push(color::dim(
            "  No races yet — waiting for same slot to appear on multiple shred feeds.",
        ));
    } else {
        out.push(color::bold(&format!(
            "  {:<22}  {:>7}  {:>9}  {:>10}  {:>9}  {:>9}",
            "CONTENDER", "WIN%", "RACES", "FASTER BY", "LEAD p50", "LEAD p95",
        )));
        let mut pairs: Vec<&serde_json::Value> = race_pairs.unwrap().iter().collect();
        pairs.sort_by(|a, b| {
            let ma = a["total_matched"].as_u64().unwrap_or(0);
            let mb = b["total_matched"].as_u64().unwrap_or(0);
            mb.cmp(&ma)
        });
        for (i, p) in pairs.iter().enumerate() {
            if i > 0 {
                out.push("  \u{00b7}\u{00b7}\u{00b7}\u{00b7}\u{00b7}".into());
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
            out.push(color::green(&format!(
                "  {:<22}  {:>6.1}%  {:>9}  {:>10}  {:>9}  {:>9}",
                faster, f_pct, format_num(matched), avg_str, p50_str, p95_str,
            )));
            out.push(color::dim(&format!(
                "  {:<22}  {:>6.1}%  {:>9}  {:>10}  {:>9}  {:>9}",
                slower, s_pct, "—", "—", "—", "—",
            )));
        }
    }
    out.push(String::new());
    out.push(color::dim(
        "  Matched on (slot, shred_index) \u{2014} when the same shred arrives on both feeds, records",
    ));
    out.push(color::dim(
        "  which relay delivered it first and by how much. Timing uses the kernel UDP receive",
    ));
    out.push(color::dim(
        "  timestamp (SO_TIMESTAMPNS), before any userspace processing.",
    ));

    out.push(String::new());

    // Edge assessment
    out.push(color::bold("EDGE ASSESSMENT:"));
    if edge_lines.is_empty() {
        if !has_rpc {
            out.push(color::yellow(
                "  Shred-race-only mode — BEAT%/LEAD require a baseline source. Run `shredtop discover` to add one.",
            ));
        } else {
            out.push(color::dim(
                "  Warming up — lead times appear once transactions match across feeds.",
            ));
        }
    } else {
        for line in &edge_lines {
            out.push(line.clone());
        }
    }

    out.push(String::new());
    out.push(color::dim(&"-".repeat(W)));
    if has_rpc {
        out.push(color::dim(
            "COV% = block shreds received  BEAT% = % of matched txs where feed beat RPC  \
             LEAD = ms before RPC confirms  p50/p95/p99 = percentiles",
        ));
    } else {
        out.push(color::dim(
            "COV% = block shreds received  (add a baseline to unlock BEAT%/LEAD columns)",
        ));
    }

    let count = out.len();
    for line in out {
        println!("{}", line);
    }
    count
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

// ---------------------------------------------------------------------------
// Source construction — used by run.rs
// ---------------------------------------------------------------------------

pub fn build_source(
    entry: &SourceEntry,
    capture_tx: Option<crossbeam_channel::Sender<shred_ingest::CaptureEvent>>,
) -> Result<(Box<dyn shred_ingest::TxSource>, Arc<SourceMetrics>)> {
    let name: &'static str = Box::leak(entry.name.clone().into_boxed_str());
    // rpc and geyser are baseline sources; shred and jito-grpc are shred-tier feeds.
    let is_rpc = matches!(entry.source_type.as_str(), "rpc" | "geyser");
    let metrics = SourceMetrics::new(name, is_rpc);

    let source: Box<dyn shred_ingest::TxSource> = match entry.source_type.as_str() {
        "shred" => {
            let multicast_addr = entry
                .multicast_addr
                .clone()
                .ok_or_else(|| anyhow::anyhow!("source '{}': missing multicast_addr", name))?;
            let port = entry.port.unwrap_or(20001);
            let interface = entry
                .interface
                .clone()
                .unwrap_or_else(|| "doublezero1".into());
            Box::new(ShredTxSource {
                name,
                multicast_addr,
                port,
                interface,
                pin_recv_core: entry.pin_recv_core,
                pin_decode_core: entry.pin_decode_core,
                shred_version: entry.shred_version,
                capture_tx,
            })
        }
        "rpc" => {
            let url = entry
                .url
                .clone()
                .unwrap_or_else(|| "http://127.0.0.1:8899".into());
            Box::new(RpcTxSource { url, pin_core: entry.pin_recv_core })
        }
        "geyser" => {
            let url = entry
                .url
                .clone()
                .ok_or_else(|| anyhow::anyhow!("source '{}': missing url for geyser source", name))?;
            Box::new(GeyserTxSource { name, url, x_token: entry.x_token.clone() })
        }
        "jito-grpc" => {
            let url = entry
                .url
                .clone()
                .ok_or_else(|| anyhow::anyhow!("source '{}': missing url for jito-grpc source", name))?;
            Box::new(JitoShredstreamSource { name, url })
        }
        "turbine" => {
            let port = entry.port.unwrap_or(8002);
            Box::new(TurbineTxSource {
                name,
                port,
                pin_recv_core: entry.pin_recv_core,
                pin_decode_core: entry.pin_decode_core,
                shred_version: entry.shred_version,
                capture_tx,
            })
        }
        other => {
            anyhow::bail!("unknown source_type '{}' for source '{}'", other, name);
        }
    };

    Ok((source, metrics))
}
