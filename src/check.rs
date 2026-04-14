//! `shredtop check` — confirm a specific validator is publishing into a feed.
//!
//! Takes the validator's client (public) IPv4, resolves the DoubleZero tunnel IP
//! via the DZ serviceability program, then counts shreds arriving from that IP
//! across all configured shred sources.

use anyhow::{Context, Result};
use shred_ingest::FanInSource;
use std::time::Duration;

use crate::config::ProbeConfig;
use crate::monitor::build_source;

pub fn run(
    config: &ProbeConfig,
    client_ip_str: &str,
    source_filter: Option<&str>,
    duration: u64,
) -> Result<()> {
    // Parse client IP.
    let client_ip: std::net::Ipv4Addr = client_ip_str
        .parse()
        .with_context(|| format!("--ip: invalid IPv4 address '{}'", client_ip_str))?;
    // Resolve DZ tunnel IP (the wire-level src_ip on DZ multicast packets).
    let dz_rpc = read_dz_rpc_url().ok_or_else(|| {
        anyhow::anyhow!(
            "~/.config/doublezero/cli/config.yml not found or has no json_rpc_url. \
             Cannot resolve DZ tunnel IP."
        )
    })?;

    print!("Resolving DZ tunnel IP for {}...", client_ip_str);
    std::io::Write::flush(&mut std::io::stdout()).ok();

    let wire_ip = shred_ingest::resolve_dz_tunnel_ip(&dz_rpc, client_ip)?
        .unwrap_or(client_ip);
    let wire_ip_str = wire_ip.to_string();

    if wire_ip == client_ip {
        println!(" no tunnel found, using {} directly", wire_ip_str);
    } else {
        println!(" {} (dz_ip)", wire_ip_str);
    }

    // Select shred sources.
    let selected: Vec<_> = config
        .sources
        .iter()
        .filter(|s| {
            let is_shred = !matches!(
                s.source_type.as_str(),
                "rpc" | "geyser" | "shreder" | "arpc" | "thor" | "jetstream"
            );
            if !is_shred {
                return false;
            }
            if let Some(name) = source_filter {
                return s.name == name;
            }
            true
        })
        .collect();

    if selected.is_empty() {
        if let Some(name) = source_filter {
            anyhow::bail!("source '{}' not found in probe.toml", name);
        } else {
            anyhow::bail!("no shred sources configured in probe.toml");
        }
    }

    println!(
        "Sources: {}",
        selected.iter().map(|s| s.name.as_str()).collect::<Vec<_>>().join(", ")
    );

    // Build FanInSource with IP filter.
    let mut fan_in = FanInSource::new();
    // Use from_ne_bytes: s_addr on Linux x86_64 stores NBO bytes read as native LE u32.
    fan_in.ip_filter = Some(u32::from_ne_bytes(wire_ip.octets()));

    for entry in &selected {
        let (source, metrics) = build_source(entry, None)?;
        fan_in.add_source(source, metrics);
    }

    let (out_tx, out_rx) = crossbeam_channel::bounded::<shred_ingest::DecodedTx>(256);
    let (_, race_tracker, _handles) = fan_in.start(out_tx);

    std::thread::spawn(move || {
        for _ in out_rx {}
    });

    println!("Observing for {}s...\n", duration);
    std::thread::sleep(Duration::from_secs(duration));

    // Collect results.
    let mut counts = race_tracker.validator_source_counts();
    for entry in &selected {
        if !counts.iter().any(|(name, _)| name == &entry.name) {
            counts.push((entry.name.clone(), 0));
        }
    }
    counts.sort_by(|a, b| a.0.cmp(&b.0));

    // Print table.
    println!("{:<26} {:>8}   {}", "SOURCE", "SHREDS", "STATUS");
    println!("{}", "-".repeat(50));

    let mut any_publishing = false;
    for (source, shreds) in &counts {
        let status = if *shreds > 0 {
            any_publishing = true;
            "PUBLISHING"
        } else {
            "NO SHREDS"
        };
        println!("{:<26} {:>8}   {}", source, shreds, status);
    }

    println!();
    if any_publishing {
        println!("{} ({}) is publishing into at least one source.", client_ip_str, wire_ip_str);
    } else {
        println!(
            "No shreds from {} ({}) in {}s window.",
            client_ip_str, wire_ip_str, duration
        );
    }

    Ok(())
}

/// Reads the DoubleZero RPC URL from `~/.config/doublezero/cli/config.yml`.
fn read_dz_rpc_url() -> Option<String> {
    let home = std::env::var("HOME").ok()?;
    let path = std::path::PathBuf::from(home).join(".config/doublezero/cli/config.yml");
    let text = std::fs::read_to_string(path).ok()?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("json_rpc_url:") {
            let url = rest.trim().trim_matches('"').trim_matches('\'').to_string();
            if !url.is_empty() {
                return Some(url);
            }
        }
    }
    None
}
