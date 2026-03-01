//! `shredtop discover` — show multicast memberships and configured sources.
//!
//! Queries the kernel for active multicast group memberships, lists configured
//! sources from probe.toml, and shows DoubleZero group metadata if the CLI is
//! installed. On completion, offers to write detected sources back to probe.toml.

use anyhow::Result;
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use crate::color;
use crate::config::{CaptureConfig, ProbeConfig, SourceEntry};

pub fn run(config: &ProbeConfig, config_path: &Path) -> Result<()> {
    // -----------------------------------------------------------------------
    // Configured sources
    // -----------------------------------------------------------------------
    println!("{}", color::bold_cyan("=== Configured sources (probe.toml) ==="));
    show_configured_sources(config);

    // -----------------------------------------------------------------------
    // Active multicast memberships (ip maddr show)
    // -----------------------------------------------------------------------
    println!();
    println!("{}", color::bold_cyan("=== Active multicast memberships ==="));
    let memberships = collect_and_show_memberships();

    // -----------------------------------------------------------------------
    // DoubleZero group selection
    // -----------------------------------------------------------------------
    println!();
    println!("{}", color::bold_cyan("=== DoubleZero multicast groups ==="));
    let mut dz_sources: Vec<SourceEntry> = Vec::new();

    match fetch_dz_groups() {
        None => {
            println!("  doublezero CLI not found.");
            println!("  Install the doublezero CLI to auto-detect groups.");
            println!("  (DoubleZero feeds can be added manually in the next step)");
        }
        Some(groups) if groups.is_empty() => {
            println!("  No groups returned by doublezero CLI.");
        }
        Some(groups) => {
            // Print table with [subscribed] marker
            println!(
                "  {:<4} {:<22} {:<16} {:>4} {:>4}  {:<12}  {}",
                "#", "CODE", "MULTICAST IP", "PUB", "SUB", "STATUS", ""
            );
            println!("  {}", "-".repeat(76));
            let subscribed_indices: Vec<usize> = groups
                .iter()
                .enumerate()
                .filter(|(_, g)| memberships.contains_key(&g.multicast_ip))
                .map(|(i, _)| i)
                .collect();
            for (i, g) in groups.iter().enumerate() {
                let marker = if memberships.contains_key(&g.multicast_ip) {
                    color::green("[subscribed]")
                } else {
                    String::new()
                };
                let status_colored = if g.status == "activated" {
                    color::green(&g.status)
                } else {
                    color::yellow(&g.status)
                };
                println!(
                    "  {:<4} {:<22} {:<16} {:>4} {:>4}  {}  {}",
                    i + 1,
                    g.code,
                    g.multicast_ip,
                    g.publishers,
                    g.subscribers,
                    color::rpad(&status_colored, 12),
                    marker,
                );
            }
            println!();

            // Default = subscribed groups
            let default_str = if subscribed_indices.is_empty() {
                "none".to_string()
            } else {
                subscribed_indices
                    .iter()
                    .map(|i| (i + 1).to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            };

            print!(
                "{}",
                color::yellow(&format!(
                    "Select groups to include [{}] (comma-separated numbers, or Enter for default): ",
                    default_str
                ))
            );
            io::stdout().flush().ok();
            let mut input = String::new();
            io::stdin().read_line(&mut input).ok();
            let input = input.trim().to_string();

            let selected_indices: Vec<usize> = if input.is_empty() {
                subscribed_indices.clone()
            } else {
                input
                    .split(',')
                    .filter_map(|s| s.trim().parse::<usize>().ok())
                    .filter(|&i| i >= 1 && i <= groups.len())
                    .map(|i| i - 1)
                    .collect()
            };

            if !selected_indices.is_empty() {
                // Sniff ports from live traffic for selected groups that are subscribed
                let needs_sniff: Vec<(String, String)> = selected_indices
                    .iter()
                    .filter_map(|&i| {
                        let g = &groups[i];
                        memberships
                            .get(&g.multicast_ip)
                            .map(|iface| (g.multicast_ip.clone(), iface.clone()))
                    })
                    .collect();

                let traffic_ports: HashMap<String, u16> = if !needs_sniff.is_empty() {
                    print!("  Sniffing shred ports from live traffic (3s)...");
                    io::stdout().flush().ok();
                    let ports = detect_shred_ports_from_traffic(&needs_sniff);
                    println!(" done.");
                    for (ip, port) in &ports {
                        println!("    {} → port {}", ip, port);
                    }
                    ports
                } else {
                    HashMap::new()
                };

                // Build a SourceEntry for each selected group
                for &i in &selected_indices {
                    let g = &groups[i];
                    let iface = memberships
                        .get(&g.multicast_ip)
                        .cloned()
                        .unwrap_or_else(|| "doublezero1".to_string());

                    // Port priority: traffic sniff → known defaults → user prompt
                    let port: Option<u16> = traffic_ports
                        .get(&g.multicast_ip)
                        .copied()
                        .or_else(|| known_port_for_group(&g.code));

                    let port = if let Some(p) = port {
                        if traffic_ports.contains_key(&g.multicast_ip) {
                            // detected from traffic — already printed above
                        } else {
                            println!(
                                "  {} — no traffic detected; using known port {}",
                                g.code, p
                            );
                        }
                        Some(p)
                    } else {
                        // Unknown group with no traffic — ask the user
                        println!(
                            "  {} — could not detect port (no traffic in 3s).",
                            g.code
                        );
                        let port_str = prompt_required(
                            &format!("  Port for {}", g.code),
                            "e.g. 7733",
                        );
                        port_str.parse::<u16>().ok()
                    };

                    dz_sources.push(SourceEntry {
                        name: g.code.clone(),
                        source_type: "shred".into(),
                        multicast_addr: Some(g.multicast_ip.clone()),
                        port,
                        interface: Some(iface),
                        url: None,
                        x_token: None,
                        pin_recv_core: None,
                        pin_decode_core: None,
                        shred_version: None,
                    });
                }

                // Show active UDP sockets only when there's a conflict
                let known_ports: Vec<u16> = traffic_ports.values().copied().collect();
                show_udp_sockets(&known_ports);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Build the final source list
    // -----------------------------------------------------------------------
    let mut sources_to_write: Vec<SourceEntry> = Vec::new();

    // Include auto-detected DZ feeds
    if !dz_sources.is_empty() {
        println!();
        println!("DoubleZero feeds selected:");
        for s in &dz_sources {
            println!(
                "  {} — {} port {} on {}",
                s.name,
                s.multicast_addr.as_deref().unwrap_or("?"),
                s.port
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "?".into()),
                s.interface.as_deref().unwrap_or("?"),
            );
        }
        println!();
        if prompt_yn(&format!(
            "Include these DoubleZero feeds in {}?",
            config_path.display()
        )) {
            sources_to_write.extend(dz_sources);
        }
    }

    // -----------------------------------------------------------------------
    // Manual sources (non-DZ: geyser, jito-grpc, rpc, custom shred feeds)
    // -----------------------------------------------------------------------
    println!();
    if prompt_yn("Are there any additional feed sources to add?") {
        let manual = collect_manual_sources();
        sources_to_write.extend(manual);
    }

    // -----------------------------------------------------------------------
    // RPC baseline
    // -----------------------------------------------------------------------
    // Check if an rpc/geyser baseline already exists (either in what we're
    // writing or in the existing config).
    let has_baseline_already = sources_to_write
        .iter()
        .any(|s| matches!(s.source_type.as_str(), "rpc" | "geyser" | "jito-grpc"))
        || config
            .sources
            .iter()
            .any(|s| matches!(s.source_type.as_str(), "rpc" | "geyser" | "jito-grpc"));

    if !has_baseline_already {
        println!();
        println!("{}", color::bold_cyan("=== No baseline source configured ==="));
        println!("A baseline (rpc/geyser) enables BEAT%/LEAD metrics — comparison of shred feeds");
        println!("vs block confirmation. Without one, SHRED RACE (inter-feed comparison) is still");
        println!("fully active.");
        println!();
        println!("{}", color::bold_cyan("=== Add a baseline? ==="));
        println!("  1) Auto-detect local RPC  (tries ports 8899, 58000, 8900, 9000, 8080)");
        println!("  2) Enter URL manually");
        println!("  3) Skip — shred race only");
        print!("{}", color::yellow("Choice [1-3]: "));
        io::stdout().flush().ok();

        let mut input = String::new();
        io::stdin().read_line(&mut input).ok();
        let choice = input.trim().to_string();

        match choice.as_str() {
            "1" | "" => {
                print!("  Probing local RPC ports...");
                io::stdout().flush().ok();
                match detect_rpc_url() {
                    Some(url) => {
                        println!(" found: {}", url);
                        if prompt_yn(&format!("  Add {} as baseline?", url)) {
                            sources_to_write.push(SourceEntry {
                                name: "rpc".into(),
                                source_type: "rpc".into(),
                                multicast_addr: None,
                                port: None,
                                interface: None,
                                url: Some(url),
                                x_token: None,
                                pin_recv_core: None,
                                pin_decode_core: None,
                                shred_version: None,
                            });
                        }
                    }
                    None => {
                        println!(" none found.");
                        println!("  No local RPC detected. Try option 2 to enter a remote URL.");
                    }
                }
            }
            "2" => {
                let url = prompt_required("  RPC URL", "e.g. http://127.0.0.1:8899");
                sources_to_write.push(SourceEntry {
                    name: "rpc".into(),
                    source_type: "rpc".into(),
                    multicast_addr: None,
                    port: None,
                    interface: None,
                    url: Some(url),
                    x_token: None,
                    pin_recv_core: None,
                    pin_decode_core: None,
                    shred_version: None,
                });
            }
            _ => {
                println!("  {}", color::yellow("Running in shred-race-only mode."));
                println!("  Add a baseline later via `shredtop discover`.");
            }
        }
    }

    // -----------------------------------------------------------------------
    // Capture configuration
    // -----------------------------------------------------------------------
    let capture_cfg = configure_capture();

    // -----------------------------------------------------------------------
    // Write probe.toml
    // -----------------------------------------------------------------------
    if !sources_to_write.is_empty() {
        let cfg = ProbeConfig {
            sources: sources_to_write,
            filter_programs: Vec::new(),
            capture: capture_cfg,
        };
        let toml_str = toml::to_string_pretty(&cfg)?;
        std::fs::write(config_path, toml_str)?;
        println!();
        println!("Written to {}.", config_path.display());
        println!();
        println!("  Sources configured:");
        for src in &cfg.sources {
            println!("    {}", src.name);
        }
        if let Some(ref cap) = cfg.capture {
            for (i, fmt) in cap.formats.iter().enumerate() {
                let max_mb = cap.max_size_mb.get(i).copied().unwrap_or(10_000);
                println!("  Capture ({}): {} → {}  (≤{} MB)", fmt, fmt, cap.output_dir, max_mb);
            }
            println!("  Recording starts when the service starts (not yet).");
        } else {
            println!("  Capture: disabled");
        }

        // Restart the background service so the new config takes effect.
        let svc_restarted = std::process::Command::new("systemctl")
            .args(["restart", "shredtop"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if svc_restarted {
            println!();
            println!("  {}", color::bold_green("✓ Service restarted. Run `shredtop monitor` to watch live metrics."));
        } else {
            println!();
            println!("  {}", color::yellow("⚠ Service not running. Start it with: shredtop service start"));
        }
    } else {
        println!();
        println!("No sources selected — probe.toml not modified.");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// DoubleZero group metadata
// ---------------------------------------------------------------------------

struct DzGroup {
    code: String,
    multicast_ip: String,
    publishers: u32,
    subscribers: u32,
    status: String,
}

/// Known shred data ports for well-known DoubleZero groups (from DoubleZero docs).
/// Used as a fallback when traffic sniffing finds no packets within the timeout.
fn known_port_for_group(code: &str) -> Option<u16> {
    match code {
        "bebop" => Some(7733),
        "jito-shredstream" => Some(20001),
        _ => None,
    }
}

/// Run `doublezero multicast group list` (pipe-delimited table, no flags) and
/// parse the result into a list of groups.
///
/// Returns `None` if the `doublezero` CLI is not found on PATH.
/// Returns `Some([])` if the CLI ran but returned no groups.
fn fetch_dz_groups() -> Option<Vec<DzGroup>> {
    let output = Command::new("doublezero")
        .args(["multicast", "group", "list"])
        .output()
        .ok()?;

    if !output.status.success() && output.stdout.is_empty() {
        return None;
    }

    let text = String::from_utf8_lossy(&output.stdout);
    let mut groups = Vec::new();

    for line in text.lines() {
        // Table format:  account | code | multicast_ip | max_bandwidth | publishers | subscribers | status | owner
        let fields: Vec<&str> = line.split('|').map(|f| f.trim()).collect();
        if fields.len() < 7 {
            continue;
        }
        // Skip the header row
        if fields[1] == "code" || fields[0] == "account" {
            continue;
        }
        let code = fields[1].to_string();
        let multicast_ip = fields[2].to_string();
        if code.is_empty() || multicast_ip.is_empty() {
            continue;
        }
        let publishers: u32 = fields[4].parse().unwrap_or(0);
        let subscribers: u32 = fields[5].parse().unwrap_or(0);
        let status = fields[6].to_string();

        groups.push(DzGroup {
            code,
            multicast_ip,
            publishers,
            subscribers,
            status,
        });
    }

    Some(groups)
}

// ---------------------------------------------------------------------------
// Multicast memberships
// ---------------------------------------------------------------------------

/// Parse `ip maddr show`, print active multicast memberships, and return a map
/// of multicast_ip → interface_name.
fn collect_and_show_memberships() -> HashMap<String, String> {
    #[cfg(target_os = "linux")]
    {
        let mut map = HashMap::new();
        if let Ok(output) = Command::new("ip").args(["maddr", "show"]).output() {
            let text = String::from_utf8_lossy(&output.stdout);
            let mut current_iface = String::new();
            for line in text.lines() {
                if line.starts_with(|c: char| c.is_ascii_digit()) {
                    if let Some(name) = line.split_whitespace().nth(1) {
                        current_iface = name.trim_end_matches(':').to_string();
                    }
                } else if line.trim().starts_with("inet ") {
                    let addr = line.trim().split_whitespace().nth(1).unwrap_or("");
                    let first_octet: u8 =
                        addr.split('.').next().unwrap_or("0").parse().unwrap_or(0);
                    if (224..=239).contains(&first_octet) {
                        println!("  {}  {}", current_iface, addr);
                        map.insert(addr.to_string(), current_iface.clone());
                    }
                }
            }
            if map.is_empty() {
                println!("  (no multicast memberships found)");
            }
        } else {
            println!("  (ip command not available)");
        }
        map
    }

    #[cfg(not(target_os = "linux"))]
    {
        println!("  (multicast membership query requires Linux — ip maddr show)");
        HashMap::new()
    }
}

// ---------------------------------------------------------------------------
// Traffic-based port detection
// ---------------------------------------------------------------------------

/// Sniff live UDP traffic to determine which port each subscribed multicast
/// group is using for shred data.
///
/// Runs a brief `tcpdump` capture (up to 3 seconds) on each interface and
/// parses the destination port from the first packet seen for each group.
/// Requires `tcpdump` to be installed and sufficient privileges (root).
fn detect_shred_ports_from_traffic(
    groups: &[(String, String)], // (multicast_ip, interface)
) -> HashMap<String, u16> {
    // Group by interface so we run one tcpdump per interface.
    let mut by_iface: HashMap<String, Vec<String>> = HashMap::new();
    for (ip, iface) in groups {
        by_iface.entry(iface.clone()).or_default().push(ip.clone());
    }

    let mut result: HashMap<String, u16> = HashMap::new();

    for (iface, ips) in &by_iface {
        // Build a pcap filter matching only packets destined for these IPs.
        let filter = ips
            .iter()
            .map(|ip| format!("dst {}", ip))
            .collect::<Vec<_>>()
            .join(" or ");

        // Use `timeout` to enforce a wall-clock limit; `-c 30` caps packet count.
        let output = Command::new("timeout")
            .args(["3", "tcpdump", "-c", "30", "-ni", iface, "-q", &filter])
            .output();

        let Ok(output) = output else { continue };

        // tcpdump writes packet lines to stdout; combine with stderr for safety.
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        for line in stdout.lines().chain(stderr.lines()) {
            if let Some((ip, port)) = parse_dst_from_tcpdump_line(line) {
                if ips.contains(&ip) {
                    result.entry(ip).or_insert(port);
                }
            }
            // Stop early if we have ports for all groups on this interface.
            if ips.iter().all(|ip| result.contains_key(ip)) {
                break;
            }
        }
    }

    result
}

/// Parse a tcpdump `-q` output line and return the destination (multicast IP, port).
///
/// Expected format: `HH:MM:SS.usec IP src.sport > dst.dport: UDP, length N`
/// The dst token is `A.B.C.D.PORT:` — we rsplit on `.` to separate IP from port.
///
/// Port 5765 is the DoubleZero heartbeat (fires every ~10s, ~4-byte payload).
/// It is filtered out here so it cannot shadow the real shred data port (7733).
fn parse_dst_from_tcpdump_line(line: &str) -> Option<(String, u16)> {
    let gt = line.find(" > ")?;
    let after = &line[gt + 3..];
    let token = after.split_whitespace().next()?.trim_end_matches(':');
    let dot = token.rfind('.')?;
    let ip = &token[..dot];
    let port: u16 = token[dot + 1..].parse().ok()?;
    // Filter out the DoubleZero heartbeat port — not a shred data port.
    if port == 5765 {
        return None;
    }
    // Sanity-check: destination should be a multicast address (224–239).
    let first_octet: u8 = ip.split('.').next()?.parse().ok()?;
    if !(224..=239).contains(&first_octet) {
        return None;
    }
    Some((ip.to_string(), port))
}

// ---------------------------------------------------------------------------
// Display helpers
// ---------------------------------------------------------------------------

fn show_configured_sources(config: &ProbeConfig) {
    if config.sources.is_empty() {
        println!("  (none)");
    } else {
        println!(
            "  {}",
            color::bold(&format!(
                "{:<20} {:<10} {:<20} {:<8} {:<14}",
                "NAME", "TYPE", "MULTICAST/URL", "PORT", "INTERFACE"
            ))
        );
        println!("  {}", color::dim(&"-".repeat(72)));
        for s in &config.sources {
            match s.source_type.as_str() {
                "shred" => {
                    println!(
                        "  {:<20} {:<10} {:<20} {:<8} {:<14}",
                        s.name,
                        "shred",
                        s.multicast_addr.as_deref().unwrap_or("(default)"),
                        s.port.map(|p| p.to_string()).unwrap_or_else(|| "?".into()),
                        s.interface.as_deref().unwrap_or("doublezero1"),
                    );
                }
                "rpc" | "geyser" | "jito-grpc" => {
                    println!(
                        "  {:<20} {:<10} {:<20} {:<8} {:<14}",
                        s.name,
                        s.source_type,
                        s.url.as_deref().unwrap_or("-"),
                        "-",
                        "-",
                    );
                }
                other => {
                    println!("  {:<20} {:<10} (unknown type: {})", s.name, other, other);
                }
            }
        }
    }
}

/// Print UDP sockets listening on known shred ports from `ss -ulnp`.
///
/// Multicast receivers bind to 0.0.0.0:<port> (not the multicast IP), so we
/// look for sockets on the detected/known ports rather than filtering by IP.
fn show_udp_sockets(ports: &[u16]) {
    #[cfg(target_os = "linux")]
    {
        let port_strs: Vec<String> = if ports.is_empty() {
            // Fall back to well-known DoubleZero ports if none detected yet.
            vec!["7733".into(), "20001".into()]
        } else {
            // Deduplicate.
            let mut seen = std::collections::HashSet::new();
            ports
                .iter()
                .filter(|p| seen.insert(*p))
                .map(|p| p.to_string())
                .collect()
        };

        if let Ok(output) = Command::new("ss").args(["-ulnp"]).output() {
            let text = String::from_utf8_lossy(&output.stdout);
            let mut found_lines: Vec<String> = Vec::new();
            for line in text.lines().skip(1) {
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() >= 5 {
                    let local = fields[4];
                    let port = local.rsplit(':').next().unwrap_or("");
                    if port_strs.iter().any(|p| p == port) {
                        let process = fields.get(6).copied().unwrap_or("");
                        found_lines.push(format!("  UDP {}  {}", local, process));
                    }
                }
            }
            // Only show this section when there IS a conflict — a receiver
            // already bound to the port. If nothing is running, skip silently.
            if !found_lines.is_empty() {
                println!("{}", color::bold_cyan("=== Active UDP sockets on shred ports ==="));
                for line in &found_lines {
                    println!("{}", color::yellow(line));
                }
                println!("{}", color::yellow("  ⚠ Another process is already listening on these ports."));
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = ports;
        println!("  (UDP socket query requires Linux — ss -ulnp)");
    }
}

// ---------------------------------------------------------------------------
// RPC detection
// ---------------------------------------------------------------------------

/// Probe candidate localhost RPC ports and return the URL of the first one
/// that responds to a Solana `getHealth` JSON-RPC call. Returns `None` if no
/// local RPC is found on any candidate port.
fn detect_rpc_url() -> Option<String> {
    const CANDIDATES: &[u16] = &[8899, 58000, 8900, 9000, 8080];
    const BODY: &str = r#"{"jsonrpc":"2.0","id":1,"method":"getHealth"}"#;

    for &port in CANDIDATES {
        let addr = format!("127.0.0.1:{}", port);
        let Ok(mut stream) =
            TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_millis(300))
        else {
            continue;
        };
        let req = format!(
            "POST / HTTP/1.0\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            port,
            BODY.len(),
            BODY
        );
        if stream.write_all(req.as_bytes()).is_err() {
            continue;
        }
        let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
        let mut response = String::new();
        let _ = stream.read_to_string(&mut response);
        if response.contains("\"result\"") {
            return Some(format!("http://127.0.0.1:{}", port));
        }
    }

    None
}

// ---------------------------------------------------------------------------
// Interactive source builder (non-DZ / manual sources)
// ---------------------------------------------------------------------------

/// Ask the user to describe one or more sources that weren't auto-detected.
/// Handles all source types: shred (custom), rpc, geyser, jito-grpc.
fn collect_manual_sources() -> Vec<SourceEntry> {
    let mut sources = Vec::new();
    loop {
        println!();
        println!("Source type:");
        println!("  1) shred     — UDP multicast shred feed (custom / non-DoubleZero)");
        println!("  2) rpc       — Solana JSON-RPC (local or remote)");
        println!("  3) geyser    — Yellowstone gRPC (Helius, Triton, QuickNode, …)");
        println!("  4) jito-grpc — Jito ShredStream gRPC proxy (local)");
        print!("{}", color::yellow("Type [1-4]: "));
        io::stdout().flush().ok();

        let mut input = String::new();
        io::stdin().read_line(&mut input).ok();
        let choice = input.trim().to_string();

        let entry = match choice.as_str() {
            "1" | "shred" => {
                let name = prompt_required("  Name", "e.g. my-feed");
                let multicast_addr = prompt_required("  Multicast IP", "e.g. 233.84.178.1");
                let port_str =
                    prompt_required("  Port", "e.g. 7733 for bebop, 20001 for jito");
                let port: u16 = match port_str.parse() {
                    Ok(p) => p,
                    Err(_) => {
                        println!("  Invalid port — skipping source.");
                        continue;
                    }
                };
                let interface =
                    prompt_with_default("  Interface", "doublezero1", "network interface");
                SourceEntry {
                    name,
                    source_type: "shred".into(),
                    multicast_addr: Some(multicast_addr),
                    port: Some(port),
                    interface: Some(interface),
                    url: None,
                    x_token: None,
                    pin_recv_core: None,
                    pin_decode_core: None,
                    shred_version: None,
                }
            }
            "2" | "rpc" => {
                let name = prompt_with_default("  Name", "rpc", "display name");
                let url = prompt_required("  URL", "e.g. http://127.0.0.1:8899");
                SourceEntry {
                    name,
                    source_type: "rpc".into(),
                    multicast_addr: None,
                    port: None,
                    interface: None,
                    url: Some(url),
                    x_token: None,
                    pin_recv_core: None,
                    pin_decode_core: None,
                    shred_version: None,
                }
            }
            "3" | "geyser" => {
                let name = prompt_required("  Name", "e.g. helius");
                let url =
                    prompt_required("  URL", "e.g. https://mainnet.helius-rpc.com:443");
                let x_token = prompt_optional("  x-token", "auth token — press Enter to skip");
                SourceEntry {
                    name,
                    source_type: "geyser".into(),
                    multicast_addr: None,
                    port: None,
                    interface: None,
                    url: Some(url),
                    x_token,
                    pin_recv_core: None,
                    pin_decode_core: None,
                    shred_version: None,
                }
            }
            "4" | "jito-grpc" => {
                let name = prompt_with_default("  Name", "jito-grpc", "display name");
                let url =
                    prompt_with_default("  URL", "http://127.0.0.1:9999", "proxy address");
                SourceEntry {
                    name,
                    source_type: "jito-grpc".into(),
                    multicast_addr: None,
                    port: None,
                    interface: None,
                    url: Some(url),
                    x_token: None,
                    pin_recv_core: None,
                    pin_decode_core: None,
                    shred_version: None,
                }
            }
            _ => {
                println!("  Unknown type — enter 1, 2, 3, or 4.");
                continue;
            }
        };

        println!("  Added: {}", entry.name);
        sources.push(entry);

        println!();
        if !prompt_yn("Add another source?") {
            break;
        }
    }
    sources
}

// ---------------------------------------------------------------------------
// Prompt helpers
// ---------------------------------------------------------------------------

fn prompt_yn(question: &str) -> bool {
    print!("{}", color::yellow(&format!("{} [y/N] ", question)));
    io::stdout().flush().ok();
    let mut input = String::new();
    io::stdin().read_line(&mut input).ok();
    input.trim().eq_ignore_ascii_case("y")
}

/// Prompt for a required field — re-asks until the user enters something.
fn prompt_required(label: &str, hint: &str) -> String {
    loop {
        print!("{}", color::yellow(&format!("{} ({}): ", label, hint)));
        io::stdout().flush().ok();
        let mut input = String::new();
        io::stdin().read_line(&mut input).ok();
        let val = input.trim().to_string();
        if !val.is_empty() {
            return val;
        }
        println!("  Required — please enter a value.");
    }
}

/// Prompt for a field with a default value shown in brackets.
fn prompt_with_default(label: &str, default: &str, hint: &str) -> String {
    print!("{}", color::yellow(&format!("{} [{}] ({}): ", label, default, hint)));
    io::stdout().flush().ok();
    let mut input = String::new();
    io::stdin().read_line(&mut input).ok();
    let val = input.trim().to_string();
    if val.is_empty() {
        default.to_string()
    } else {
        val
    }
}

/// Prompt for an optional field — returns None if the user presses Enter.
fn prompt_optional(label: &str, hint: &str) -> Option<String> {
    print!("{}", color::yellow(&format!("{} ({}): ", label, hint)));
    io::stdout().flush().ok();
    let mut input = String::new();
    io::stdin().read_line(&mut input).ok();
    let val = input.trim().to_string();
    if val.is_empty() {
        None
    } else {
        Some(val)
    }
}

// ---------------------------------------------------------------------------
// Capture configuration wizard
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Disk discovery helper
// ---------------------------------------------------------------------------

struct DiskEntry {
    mount: String,
    size: String,
    avail: String,
    use_pct: String,
}

/// Run `df -hT`, filter pseudo-filesystems, return real mounts with free space.
fn list_disks() -> Vec<DiskEntry> {
    // Try Linux `df -hT` (shows filesystem type for filtering).
    // Falls back to `df -h` if -T is unsupported (macOS).
    let out = Command::new("df")
        .args(["-hT"])
        .output()
        .or_else(|_| Command::new("df").args(["-h"]).output());

    let output = match out {
        Ok(o) if o.status.success() => o.stdout,
        _ => return Vec::new(),
    };

    let text = String::from_utf8_lossy(&output);
    let pseudo = [
        "tmpfs", "devtmpfs", "devpts", "sysfs", "proc", "cgroup", "cgroup2",
        "overlay", "squashfs", "udev", "hugetlbfs", "mqueue", "nsfs",
        "securityfs", "fusectl", "tracefs", "debugfs", "configfs", "bpf",
        "efivarfs", "autofs", "pstore",
    ];

    let mut entries = Vec::new();
    for line in text.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        // `df -hT`: Filesystem Type Size Used Avail Use% Mounted
        // `df -h`:  Filesystem      Size Used Avail Use% Mounted
        // We detect by checking if col[1] looks like a type (no '/' or '%').
        let (fstype, size, avail, use_pct, mount) = if cols.len() >= 7 {
            // Likely -hT format
            (cols[1], cols[2], cols[4], cols[5], cols[6])
        } else if cols.len() >= 6 {
            // Plain -h format (no type column)
            ("", cols[1], cols[3], cols[4], cols[5])
        } else {
            continue;
        };

        // Skip pseudo filesystems by type.
        if pseudo.iter().any(|&p| p == fstype) {
            continue;
        }
        // Skip pseudo mount points.
        if mount.starts_with("/proc")
            || mount.starts_with("/sys")
            || mount.starts_with("/dev/pts")
            || mount.starts_with("/run/user")
        {
            continue;
        }
        // Skip if size is effectively zero or the "0" placeholder.
        if size == "0" || size.starts_with('0') {
            continue;
        }

        entries.push(DiskEntry {
            mount: mount.to_string(),
            size: size.to_string(),
            avail: avail.to_string(),
            use_pct: use_pct.to_string(),
        });
    }
    entries
}

/// Parse a human-readable size like "10G", "500M", "2T", or bare "50000" (MB).
/// Returns megabytes.
fn parse_size_mb(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (num_part, suffix) = if s.ends_with(|c: char| c.is_alphabetic()) {
        s.split_at(s.len() - 1)
    } else {
        (s, "")
    };
    let n: f64 = num_part.parse().ok()?;
    let mb = match suffix.to_uppercase().as_str() {
        "T" => (n * 1024.0 * 1024.0) as u64,
        "G" => (n * 1024.0) as u64,
        "M" | "" => n as u64,
        _ => return None,
    };
    if mb == 0 { None } else { Some(mb) }
}

// ---------------------------------------------------------------------------
// Capture configuration wizard
// ---------------------------------------------------------------------------

/// Ask the user whether to enable raw shred capture, and if so, collect
/// formats, disk, and per-format max sizes.
/// Returns `None` if the user skips capture.
fn configure_capture() -> Option<CaptureConfig> {
    println!();
    println!("{}", color::bold_cyan("=== Raw shred capture (optional) ==="));
    println!("  Stores raw packets to disk for offline analysis and replay.");
    println!();
    println!("  1) pcap   — Wireshark-compatible, industry standard");
    println!("  2) csv    — spreadsheet / pandas-friendly");
    println!("  3) jsonl  — structured JSON lines");
    println!("  4) Skip   — no capture");
    print!("{}", color::yellow("Select the formats you want to record [4] (comma-separated numbers, or Enter for default): "));
    io::stdout().flush().ok();

    let mut input = String::new();
    io::stdin().read_line(&mut input).ok();
    let choice = input.trim().to_string();

    let mut formats: Vec<String> = Vec::new();
    for token in choice.split(',').map(str::trim) {
        match token {
            "1" => { if !formats.contains(&"pcap".to_string())  { formats.push("pcap".into());  } }
            "2" => { if !formats.contains(&"csv".to_string())   { formats.push("csv".into());   } }
            "3" => { if !formats.contains(&"jsonl".to_string()) { formats.push("jsonl".into()); } }
            "4" | "" => {}
            other => { println!("  Ignoring unrecognised token {:?}.", other); }
        }
    }

    if formats.is_empty() {
        println!("  Capture disabled.");
        return None;
    }

    // ── Step 2: choose a disk ────────────────────────────────────────────────
    println!();
    println!("{}", color::bold_cyan("=== Choose a disk for capture files ==="));
    println!();

    let disks = list_disks();
    if disks.is_empty() {
        println!("  (could not detect disks — enter path manually)");
    } else {
        println!("  {}", color::bold(&format!("{:<4}  {:<30}  {:>6}  {:>6}  {}", "#", "MOUNT POINT", "SIZE", "AVAIL", "USE%")));
        println!("  {}", color::dim(&"-".repeat(60)));
        for (i, d) in disks.iter().enumerate() {
            println!("  {:<4}  {:<30}  {:>6}  {:>6}  {}", i + 1, d.mount, d.size, d.avail, d.use_pct);
        }
        println!();
    }

    let output_dir = if disks.is_empty() {
        prompt_with_default("Output directory", "/var/log/shredtop-capture", "full path")
    } else {
        print!("{}", color::yellow(&format!("Disk [1-{}, or enter path]: ", disks.len())));
        io::stdout().flush().ok();
        let mut sel = String::new();
        io::stdin().read_line(&mut sel).ok();
        let sel = sel.trim();

        let mount = if let Ok(n) = sel.parse::<usize>() {
            disks
                .get(n.saturating_sub(1))
                .map(|d| d.mount.trim_end_matches('/').to_string())
                .unwrap_or_else(|| "/var/log".to_string())
        } else if !sel.is_empty() {
            sel.trim_end_matches('/').to_string()
        } else {
            // default to first disk
            disks[0].mount.trim_end_matches('/').to_string()
        };

        format!("{}/shredtop-capture", mount)
    };

    // ── Step 3: max size per format ──────────────────────────────────────────
    println!();
    println!("{}", color::bold_cyan("=== Max disk space per format ==="));
    println!("  Use G for gigabytes, M for megabytes (e.g. 10G, 500M).");
    println!();

    let rotate_mb: u64 = 500; // fixed rotation interval
    let mut max_size_mb: Vec<u64> = Vec::new();

    for fmt in &formats {
        let (default_size, approx_time) = match fmt.as_str() {
            "pcap"  => ("50G",  "~2.5hrs of recording"),
            "csv"   => ("5G",   "~2.5hrs of recording"),
            "jsonl" => ("10G",  "~2.5hrs of recording"),
            _       => ("10G",  "~2.5hrs of recording"),
        };
        loop {
            print!("{}", color::yellow(&format!(
                "  Set max size for {} collection [suggested {} for {}]: ",
                fmt, default_size, approx_time
            )));
            io::stdout().flush().ok();
            let mut s = String::new();
            io::stdin().read_line(&mut s).ok();
            let s = s.trim();
            let raw = if s.is_empty() { default_size } else { s };
            match parse_size_mb(raw) {
                Some(mb) => {
                    max_size_mb.push(mb);
                    break;
                }
                None => println!("  Unrecognised size {:?} — try e.g. 10G or 500M.", raw),
            }
        }
    }

    // Summary
    println!();
    for (fmt, &max_mb) in formats.iter().zip(max_size_mb.iter()) {
        let ring = (max_mb / rotate_mb).max(2);
        println!("  {} → {}  (≤{} MB, {} × {} MB files)", fmt, output_dir, max_mb, ring, rotate_mb);
    }

    Some(CaptureConfig {
        enabled: true,
        formats,
        max_size_mb,
        output_dir,
        rotate_mb,
    })
}
