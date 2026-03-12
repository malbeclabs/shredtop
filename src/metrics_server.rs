//! Prometheus metrics HTTP endpoint.
//!
//! Serves a minimal Prometheus text-format `/metrics` response over a plain
//! HTTP/1.0 `TcpListener`. No async runtime required.
//!
//! The server runs on its own thread and reads the latest snapshot via a
//! `crossbeam_channel::Receiver<MetricsSnapshot>`. The sender drops old
//! values — only the most recent snapshot is served.

use std::io::Write;
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use shred_ingest::SourceMetricsSnapshot;

/// Snapshot of all source metrics at a point in time.
#[derive(Clone)]
pub struct MetricsSnapshot {
    pub sources: Vec<SourceMetricsSnapshot>,
}

/// Spawn the metrics server thread.
///
/// Returns a `MetricsUpdater` that `run.rs` calls every snapshot interval to
/// push new data. The server thread runs indefinitely in the background.
pub fn spawn(port: u16) -> MetricsUpdater {
    let state: Arc<Mutex<Option<MetricsSnapshot>>> = Arc::new(Mutex::new(None));
    let state_server = state.clone();

    std::thread::Builder::new()
        .name("metrics-server".into())
        .spawn(move || {
            let listener = match TcpListener::bind(("0.0.0.0", port)) {
                Ok(l) => {
                    eprintln!("shredtop metrics — http://0.0.0.0:{}/metrics", port);
                    l
                }
                Err(e) => {
                    eprintln!("metrics server failed to bind port {}: {}", port, e);
                    return;
                }
            };
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let body = {
                    let snap = state_server.lock().unwrap();
                    match snap.as_ref() {
                        Some(s) => render(s),
                        None => "# no data yet\n".into(),
                    }
                };
                let response = format!(
                    "HTTP/1.0 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body,
                );
                let _ = stream.write_all(response.as_bytes());
            }
        })
        .expect("failed to spawn metrics-server thread");

    MetricsUpdater { state }
}

pub struct MetricsUpdater {
    state: Arc<Mutex<Option<MetricsSnapshot>>>,
}

impl MetricsUpdater {
    pub fn update(&self, snapshot: MetricsSnapshot) {
        *self.state.lock().unwrap() = Some(snapshot);
    }
}

/// Render a `MetricsSnapshot` as Prometheus text format.
fn render(snap: &MetricsSnapshot) -> String {
    let mut out = String::with_capacity(2048);

    for s in &snap.sources {
        let name = s.name;

        gauge(&mut out, "shredtop_shreds_received_total",
            &[("source", name)], s.shreds_received as f64,
            "Total shreds received");
        gauge(&mut out, "shredtop_shreds_dropped_total",
            &[("source", name)], s.shreds_dropped as f64,
            "Shreds dropped (channel full)");
        gauge(&mut out, "shredtop_shreds_invalid_total",
            &[("source", name)], s.shreds_invalid as f64,
            "Malformed/unknown packets rejected before decoder");

        if !s.is_rpc {
            if let Some(cov) = coverage_pct(s) {
                gauge(&mut out, "shredtop_coverage_pct",
                    &[("source", name)], cov,
                    "Block shred coverage percent");
            }

            if s.lead_time_count > 0 {
                let beat_pct = s.lead_wins as f64 / s.lead_time_count as f64 * 100.0;
                gauge(&mut out, "shredtop_beat_rpc_pct",
                    &[("source", name)], beat_pct,
                    "Percent of matched transactions where feed beat RPC");

                let mean_ms = s.lead_time_sum_us as f64 / s.lead_time_count as f64 / 1000.0;
                gauge(&mut out, "shredtop_lead_time_mean_ms",
                    &[("source", name)], mean_ms,
                    "Mean lead time over RPC in milliseconds (positive = ahead)");

                if let Some(p50) = s.lead_time_p50_us {
                    gauge(&mut out, "shredtop_lead_time_ms",
                        &[("source", name), ("quantile", "0.5")], p50 as f64 / 1000.0,
                        "Lead time quantile in milliseconds");
                }
                if let Some(p95) = s.lead_time_p95_us {
                    gauge(&mut out, "shredtop_lead_time_ms",
                        &[("source", name), ("quantile", "0.95")], p95 as f64 / 1000.0,
                        "Lead time quantile in milliseconds");
                }
                if let Some(p99) = s.lead_time_p99_us {
                    gauge(&mut out, "shredtop_lead_time_ms",
                        &[("source", name), ("quantile", "0.99")], p99 as f64 / 1000.0,
                        "Lead time quantile in milliseconds");
                }
            }

            if let Some(secs) = s.secs_since_heartbeat {
                gauge(&mut out, "shredtop_heartbeat_age_secs",
                    &[("source", name)], secs as f64,
                    "Seconds since last DoubleZero heartbeat (0 if just received)");
            }
        }
    }

    out
}

fn coverage_pct(s: &SourceMetricsSnapshot) -> Option<f64> {
    if s.coverage_shreds_expected == 0 { return None; }
    Some((s.coverage_shreds_seen as f64 / s.coverage_shreds_expected as f64 * 100.0).min(100.0))
}

fn gauge(out: &mut String, name: &str, labels: &[(&str, &str)], value: f64, help: &str) {
    use std::fmt::Write;
    let _ = writeln!(out, "# HELP {} {}", name, help);
    let _ = writeln!(out, "# TYPE {} gauge", name);
    if labels.is_empty() {
        let _ = writeln!(out, "{} {}", name, value);
    } else {
        let lstr: Vec<String> = labels.iter().map(|(k, v)| format!("{}=\"{}\"", k, v)).collect();
        let _ = writeln!(out, "{}{{{}}} {}", name, lstr.join(","), value);
    }
}
