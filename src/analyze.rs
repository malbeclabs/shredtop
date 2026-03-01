//! `shredtop analyze` — per-feed shred timing analysis from a pcap file.
//!
//! Reads any pcap written by `shredtop capture` (or any third-party capture
//! of the same UDP multicast traffic), pairs shreds that arrived on multiple
//! feeds, and prints a timing table identical in format to the live SHRED RACE
//! output shown by `shredtop monitor`.

use anyhow::Result;
use pcap_file::pcap::PcapReader;
use std::collections::HashMap;
use std::fs::File;
use std::net::Ipv4Addr;
use std::path::Path;
use tracing::warn;

// ─── Shred header constants (mirrors decoder.rs) ──────────────────────────────

const VARIANT_OFF: usize = 64;
const SLOT_OFF: usize = 65;
const INDEX_OFF: usize = 73;
const MIN_SHRED_LEN: usize = 77; // slot(8) + index(4) + variant(1) + sig(64) = 77

/// Returns `true` for data shreds, `false` for coding shreds or malformed buffers.
fn is_data_shred(bytes: &[u8]) -> bool {
    if bytes.len() < MIN_SHRED_LEN {
        return false;
    }
    let variant = bytes[VARIANT_OFF];
    let high = variant & 0xF0;
    // Coding: 0x5a (LegacyCode) or high nibble 0x4x–0x7x (Merkle coding variants).
    // Data: 0xa5 (LegacyData), high nibble 0x8x, 0x9x, 0xax, 0xbx.
    !(variant == 0x5a || matches!(high, 0x40 | 0x50 | 0x60 | 0x70))
}

/// Parse (slot, index) from a raw shred buffer. Returns `None` if too short.
fn parse_slot_index(bytes: &[u8]) -> Option<(u64, u32)> {
    if bytes.len() < MIN_SHRED_LEN {
        return None;
    }
    let slot = u64::from_le_bytes(bytes[SLOT_OFF..SLOT_OFF + 8].try_into().ok()?);
    let index = u32::from_le_bytes(bytes[INDEX_OFF..INDEX_OFF + 4].try_into().ok()?);
    Some((slot, index))
}

// ─── Internal types ───────────────────────────────────────────────────────────

struct ShredEvent {
    feed: String,
    timestamp_ns: u64,
}

/// First two arrivals for a (slot, shred_index) pair.
type RaceMap = HashMap<(u64, u32), (ShredEvent, Option<ShredEvent>)>;

// ─── Entry point ─────────────────────────────────────────────────────────────

pub fn run(pcap: &Path, feed_args: &[(Ipv4Addr, String)], min_matched: u64) -> Result<()> {
    let file = File::open(pcap)?;
    let mut reader = PcapReader::new(file)?;

    // Build IP-octets → feed-name lookup.
    let feed_map: HashMap<[u8; 4], &str> =
        feed_args.iter().map(|(ip, name)| (ip.octets(), name.as_str())).collect();

    let mut race: RaceMap = HashMap::new();
    let mut packets_read: u64 = 0;
    let mut shreds_parsed: u64 = 0;

    while let Some(pkt_result) = reader.next_packet() {
        let pkt = match pkt_result {
            Ok(p) => p,
            Err(e) => {
                warn!("pcap read error: {}", e);
                continue;
            }
        };
        packets_read += 1;

        let data = &pkt.data;
        // Minimum frame: Ethernet(14) + IPv4(20) + UDP(8) + shred header(77) = 119
        if data.len() < 119 {
            continue;
        }
        // EtherType must be IPv4 (0x0800).
        if data[12] != 0x08 || data[13] != 0x00 {
            continue;
        }
        // IP protocol must be UDP (0x11).
        if data[23] != 0x11 {
            continue;
        }

        // dst IP is at IPv4 header bytes 16-19 → frame bytes 30-33.
        let dst_ip = [data[30], data[31], data[32], data[33]];
        let feed = feed_map
            .get(&dst_ip)
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("{}.{}.{}.{}", dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3]));

        // UDP payload starts at byte 42 (14 + 20 + 8).
        let udp_payload = &data[42..];

        if !is_data_shred(udp_payload) {
            continue;
        }
        let (slot, index) = match parse_slot_index(udp_payload) {
            Some(v) => v,
            None => continue,
        };

        shreds_parsed += 1;
        let ts_ns = pkt.timestamp.as_nanos() as u64;
        let key = (slot, index);

        match race.entry(key) {
            std::collections::hash_map::Entry::Vacant(e) => {
                e.insert((ShredEvent { feed, timestamp_ns: ts_ns }, None));
            }
            std::collections::hash_map::Entry::Occupied(mut e) => {
                let val = e.get_mut();
                // Only record the second distinct-feed arrival; ignore 3rd+.
                if val.1.is_none() && val.0.feed != feed {
                    val.1 = Some(ShredEvent { feed, timestamp_ns: ts_ns });
                }
            }
        }
    }

    // ─── Aggregate ───────────────────────────────────────────────────────────

    let mut wins: HashMap<String, u64> = HashMap::new();
    let mut lead_ns: HashMap<String, Vec<u64>> = HashMap::new();
    let mut pairs_matched: u64 = 0;

    for (_, (first, second)) in &race {
        let Some(second) = second else { continue };
        pairs_matched += 1;

        let lead = second.timestamp_ns.saturating_sub(first.timestamp_ns);
        *wins.entry(first.feed.clone()).or_insert(0) += 1;
        lead_ns.entry(first.feed.clone()).or_default().push(lead);
        wins.entry(second.feed.clone()).or_insert(0);
    }

    // ─── Output ──────────────────────────────────────────────────────────────

    println!();
    println!("SHRED TIMING ANALYSIS  —  {}", pcap.display());
    println!(
        "Packets read: {:>12}   Shreds parsed: {:>12}   Pairs matched: {:>12}",
        fmt_num(packets_read),
        fmt_num(shreds_parsed),
        fmt_num(pairs_matched),
    );
    println!();

    if pairs_matched < min_matched {
        warn!(
            "only {} matched pairs (--min-matched {}); check --feed mappings or pcap content",
            pairs_matched, min_matched
        );
    }

    // Sort feeds: winner (most first-arrivals) first.
    let mut feeds: Vec<String> = wins.keys().cloned().collect();
    feeds.sort_by(|a, b| wins[b].cmp(&wins[a]));

    println!(
        "  {:<24}  {:>6}  {:>10}  {:>10}  {:>10}  {:>10}",
        "FEED", "WIN%", "MATCHED", "AVG LEAD", "LEAD p50", "LEAD p95",
    );
    println!("  {}", "-".repeat(78));

    for feed in &feeds {
        let feed_wins = wins[feed];
        let win_pct = if pairs_matched > 0 {
            100.0 * feed_wins as f64 / pairs_matched as f64
        } else {
            0.0
        };

        if let Some(times) = lead_ns.get_mut(feed) {
            times.sort_unstable();
            let avg_us = times.iter().sum::<u64>() as f64 / times.len() as f64 / 1000.0;
            let p50 = percentile(times, 50) as f64 / 1000.0;
            let p95 = percentile(times, 95) as f64 / 1000.0;
            println!(
                "  {:<24}  {:>5.1}%  {:>10}  {:>10}  {:>10}  {:>10}",
                feed,
                win_pct,
                fmt_num(feed_wins),
                format!("{:+.0}µs", avg_us),
                format!("{:+.0}µs", p50),
                format!("{:+.0}µs", p95),
            );
        } else {
            println!(
                "  {:<24}  {:>5.1}%  {:>10}  {:>10}  {:>10}  {:>10}",
                feed, win_pct, "—", "—", "—", "—",
            );
        }

        if feed_wins == 0 {
            warn!("feed '{}': no first-arrivals — check --feed IP mapping", feed);
        }
    }

    println!();
    Ok(())
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn percentile(sorted: &[u64], pct: usize) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = (sorted.len() * pct / 100).min(sorted.len() - 1);
    sorted[idx]
}

fn fmt_num(n: u64) -> String {
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
