//! CLI definitions for shredtop.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[clap(
    name = "shredtop",
    version,
    about = "Solana shred feed latency benchmark\n\nMeasures how many milliseconds ahead of confirmed RPC your DoubleZero or Jito ShredStream feed delivers transactions.\n\nQuick start:\n  shredtop discover          # detect feeds, write probe.toml\n  shredtop service start     # start background collection\n  shredtop monitor           # open live dashboard",
    long_about = None
)]
pub struct Cli {
    /// Path to probe.toml config file
    #[clap(long, short, default_value = "probe.toml")]
    pub config: PathBuf,

    #[clap(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Detect active shred feeds and write probe.toml
    Discover,

    /// Start background data collection as a systemd service
    ///
    /// Run this once after install. Installs the unit file, enables it on
    /// boot, and starts the service immediately. If the service is already
    /// running, shows current status instead.
    Service {
        #[clap(subcommand)]
        action: ServiceAction,
    },

    /// Live dashboard showing feed quality (Ctrl-C closes view, service keeps running)
    ///
    /// Read-only view of the metrics written by `shredtop service start`.
    /// Requires the service to be running first.
    Monitor {
        /// Dashboard refresh interval in seconds
        #[clap(long, default_value = "15")]
        interval: u64,
    },

    /// Latest metrics snapshot from the service log (non-interactive)
    Status,

    /// Run a timed benchmark and write a structured JSON report
    Bench {
        /// How many seconds to run the benchmark
        #[clap(long, default_value = "60")]
        duration: u64,

        /// Write JSON report to this file (default: stdout)
        #[clap(long)]
        output: Option<PathBuf>,
    },

    /// Print an example probe.toml to stdout
    Init,

    /// Remove all shredtop files from the system (service, binary, logs, capture files, config)
    Uninstall,

    /// Upgrade shredtop to the latest release binary
    Upgrade {
        /// Pull main branch and rebuild from source instead of downloading a release
        #[clap(long)]
        source: bool,
    },

    /// Manage and inspect the on-disk capture ring
    Capture {
        #[clap(subcommand)]
        action: CaptureAction,
    },

    /// Analyze a pcap capture file for per-feed shred timing
    ///
    /// Reads any pcap written by `shredtop capture` (or any third-party capture
    /// of the same UDP multicast traffic), pairs shreds that arrived on multiple
    /// feeds, and prints a timing table showing win rates and lead times.
    ///
    /// Example:
    ///   shredtop analyze capture.pcap \
    ///     --feed 233.84.178.1=bebop \
    ///     --feed 233.84.178.2=jito-shredstream
    Analyze {
        /// pcap file to analyze
        pcap: std::path::PathBuf,

        /// Feed IP=name mappings (repeatable), e.g. --feed 233.84.178.1=bebop
        #[clap(long, value_parser = parse_feed_mapping)]
        feed: Vec<(std::net::Ipv4Addr, String)>,

        /// Minimum matched pairs required to display results
        #[clap(long, default_value_t = 10)]
        min_matched: u64,
    },

    /// Background data collection daemon (used by the systemd service)
    #[clap(hide = true)]
    Run {
        /// Snapshot interval in seconds
        #[clap(long, default_value = "15")]
        interval: u64,

        /// Path to write metrics log (JSONL)
        #[clap(long, default_value = crate::run::DEFAULT_LOG)]
        log: std::path::PathBuf,
    },
}

fn parse_feed_mapping(s: &str) -> std::result::Result<(std::net::Ipv4Addr, String), String> {
    let (ip_str, name) = s
        .split_once('=')
        .ok_or_else(|| format!("expected IP=name, got '{}'", s))?;
    let ip = ip_str
        .parse::<std::net::Ipv4Addr>()
        .map_err(|e| format!("invalid IP '{}': {}", ip_str, e))?;
    Ok((ip, name.to_string()))
}

#[derive(Subcommand)]
pub enum CaptureAction {
    /// List capture ring files with sizes and timestamp coverage
    List,
}

#[derive(Subcommand)]
pub enum ServiceAction {
    /// Install the unit file, enable on boot, and start (run this once to set up)
    Start,
    /// Stop the service
    Stop,
    /// Restart the service
    Restart,
    /// Show systemd service status
    Status,
    /// Enable the service to start on boot
    Enable,
    /// Disable the service from starting on boot
    Disable,
    /// Stop, disable, and remove the unit file
    Uninstall,
}
