//! `shredtop capture list` — display the on-disk capture ring.

use anyhow::Result;
use chrono::{TimeZone, Utc};
use pcap_file::pcap::PcapReader;
use std::fs::File;
use std::path::{Path, PathBuf};

use crate::color;
use crate::config::ProbeConfig;

pub fn run(config_path: &Path) -> Result<()> {
    let config = ProbeConfig::load(config_path)?;
    let cap = config.capture.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "no [capture] section in probe.toml — run `shredtop discover` to configure capture"
        )
    })?;

    if !cap.enabled {
        println!("Capture is disabled in probe.toml ([capture] enabled = false).");
        return Ok(());
    }

    let output_dir = Path::new(&cap.output_dir);
    if !output_dir.exists() {
        println!("Capture directory {} does not exist yet.", output_dir.display());
        println!("Start the service to begin capture: shredtop service start");
        return Ok(());
    }

    // Collect all capture files.
    let mut files: Vec<PathBuf> = std::fs::read_dir(output_dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with("shreds."))
                .unwrap_or(false)
        })
        .collect();

    if files.is_empty() {
        println!("No capture files in {}.", output_dir.display());
        println!("Start the service and wait a moment: shredtop service start");
        return Ok(());
    }

    // Sort: generation 0 (active, no numeric suffix) first; higher numbers are
    // more recent archives. Display oldest → newest → current.
    files.sort_by_key(|p| archive_generation(p));

    let mut total_bytes: u64 = 0;
    println!("{}", color::bold_cyan(&format!("CAPTURE RING  {}", output_dir.display())));

    for path in &files {
        let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        total_bytes += size;

        let is_active = archive_generation(path) == 0;
        let (first_ts, last_ts) = read_timestamps(path, is_active);

        let name = path.file_name().unwrap_or_default().to_string_lossy();
        let size_str = human_size(size);
        let ts_str = match (first_ts, last_ts) {
            (Some(f), Some(_l)) if is_active => {
                format!("{} → (current)", fmt_ts(f))
            }
            (Some(f), Some(l)) => format!("{} → {}", fmt_ts(f), fmt_ts(l)),
            (Some(f), None) => format!("{} → (current)", fmt_ts(f)),
            _ => "—".into(),
        };

        let row = format!("  {:<30}  {:>8}  {}", name, size_str, ts_str);
        if is_active {
            println!("{}", color::bold(&row));
        } else {
            println!("{}", color::dim(&row));
        }
    }

    let ring_cap_mb: u64 = cap
        .formats
        .iter()
        .enumerate()
        .map(|(i, _)| cap.ring_files_for(i) as u64 * cap.rotate_mb)
        .sum();
    println!(
        "{}",
        color::bold(&format!(
            "  Total: {}   ({} file(s), ring capacity {} MB across {} format(s))",
            human_size(total_bytes),
            files.len(),
            ring_cap_mb,
            cap.formats.len(),
        ))
    );

    Ok(())
}

/// Extract the archive generation number from the file name.
/// `shreds.pcap` → 0 (active), `shreds.pcap.7` → 7.
fn archive_generation(path: &Path) -> u32 {
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    // Try to parse trailing ".N"
    if let Some(dot) = name.rfind('.') {
        let suffix = &name[dot + 1..];
        if let Ok(n) = suffix.parse::<u32>() {
            return n;
        }
    }
    0 // active file has no numeric suffix
}

/// Read first-packet and last-packet timestamps from a pcap file.
/// For the active (still-writing) file we skip the last-timestamp scan.
fn read_timestamps(path: &Path, is_active: bool) -> (Option<u64>, Option<u64>) {
    let Ok(file) = File::open(path) else {
        return (None, None);
    };
    let Ok(mut reader) = PcapReader::new(file) else {
        return (None, None);
    };

    let first = reader
        .next_packet()
        .and_then(|r: Result<_, _>| r.ok())
        .map(|p| p.timestamp.as_nanos() as u64);

    if is_active {
        return (first, None);
    }

    // For archived files, scan to find the last packet timestamp.
    // We iterate rather than seeking because pcap has variable-length records.
    let mut last = first;
    while let Some(pkt_result) = reader.next_packet() {
        if let Ok(pkt) = pkt_result {
            last = Some(pkt.timestamp.as_nanos() as u64);
        }
    }

    (first, last)
}

fn fmt_ts(ns: u64) -> String {
    let secs = (ns / 1_000_000_000) as i64;
    Utc.timestamp_opt(secs, 0)
        .single()
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_else(|| "?".into())
}

fn human_size(bytes: u64) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if bytes >= 1024 * 1024 {
        format!("{:.0} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.0} KB", bytes as f64 / 1024.0)
    }
}
