//! `shredtop check` — confirm a specific validator is publishing into a feed.
//!
//! Subscribes to the configured shred sources, observes live traffic for a
//! fixed window, and reports per-source shred counts for slots where the
//! given validator is the scheduled leader.

use anyhow::{Context, Result};
use shred_ingest::{FanInSource, LeaderCache};
use std::time::Duration;

use crate::config::ProbeConfig;
use crate::monitor::build_source;

pub fn run(
    config: &ProbeConfig,
    validator: &str,
    source_filter: Option<&str>,
    duration: u64,
) -> Result<()> {
    // Parse validator pubkey.
    let validator_bytes = shred_ingest::parse_pubkey(validator)
        .with_context(|| format!("--validator: invalid pubkey '{}'", validator))?;

    // Find the RPC URL for leader schedule fetching.
    let rpc_url = config
        .leader_filter
        .as_ref()
        .filter(|lf| lf.enabled)
        .map(|lf| lf.rpc_url.clone())
        .or_else(|| {
            config
                .sources
                .iter()
                .find(|s| s.source_type == "rpc")
                .and_then(|s| s.url.clone())
        })
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No RPC URL found. Add a [leader_filter] section to probe.toml or \
                 ensure an rpc source is configured with a url."
            )
        })?;

    // Start the leader cache (background thread).
    let leader_cache = LeaderCache::new(&rpc_url, None);

    // Select shred sources.
    let selected: Vec<_> = config
        .sources
        .iter()
        .filter(|s| {
            // Skip RPC-tier sources — they don't emit ShredArrival events.
            let is_shred = !matches!(
                s.source_type.as_str(),
                "rpc" | "geyser" | "shreder" | "arpc" | "thor" | "jetstream"
            );
            if !is_shred {
                return false;
            }
            // Apply --source filter if specified.
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
        "Checking validator {}",
        &validator[..validator.len().min(16)]
    );
    println!(
        "Sources: {}",
        selected.iter().map(|s| s.name.as_str()).collect::<Vec<_>>().join(", ")
    );
    print!("Waiting for leader schedule");
    std::io::Write::flush(&mut std::io::stdout()).ok();

    // Give the leader cache time to populate (it fetches on first epoch detection).
    std::thread::sleep(Duration::from_secs(10));
    println!(" done");

    // Build FanInSource with only the selected shred sources.
    let mut fan_in = FanInSource::new();
    fan_in.validator_filter = Some((validator_bytes, leader_cache.clone()));

    for entry in &selected {
        let (source, metrics) = build_source(entry, None)?;
        fan_in.add_source(source, metrics);
    }

    let (out_tx, out_rx) = crossbeam_channel::bounded::<shred_ingest::DecodedTx>(256);
    let (_, race_tracker, _handles) = fan_in.start(out_tx);

    // Drain decoded transactions — we only care about the ShredArrival stats.
    std::thread::spawn(move || {
        for _ in out_rx {}
    });

    // Observe.
    println!("Observing for {}s...\n", duration);
    std::thread::sleep(Duration::from_secs(duration));

    // Collect results.
    let mut counts = race_tracker.validator_source_counts();
    // Add sources that saw zero shreds so they appear in the table.
    for entry in &selected {
        if !counts.iter().any(|(name, _, _)| name == &entry.name) {
            counts.push((entry.name.clone(), 0, 0));
        }
    }
    counts.sort_by(|a, b| a.0.cmp(&b.0));

    // Print table.
    println!(
        "{:<26} {:>8}   {:>13}   {}",
        "SOURCE", "SHREDS", "LEADER_SLOTS", "STATUS"
    );
    println!("{}", "-".repeat(70));

    let mut any_publishing = false;
    for (source, shreds, slots) in &counts {
        let status = if *shreds > 0 {
            any_publishing = true;
            "PUBLISHING"
        } else {
            "NO SHREDS"
        };
        println!(
            "{:<26} {:>8}   {:>13}   {}",
            source,
            shreds,
            slots,
            status
        );
    }

    println!();
    if any_publishing {
        println!(
            "Validator {} is publishing into at least one source.",
            &validator[..validator.len().min(16)]
        );
    } else {
        println!(
            "No shreds found for validator {} in {}s window.",
            &validator[..validator.len().min(16)],
            duration
        );
        println!("Possible causes: validator not currently leading, or not publishing to these groups.");
    }

    Ok(())
}
