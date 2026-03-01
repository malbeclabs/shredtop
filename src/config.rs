//! `probe.toml` configuration for shredtop.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Top-level probe configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProbeConfig {
    #[serde(default)]
    pub sources: Vec<SourceEntry>,
    /// Optional list of program or account pubkeys (base58). When non-empty, only
    /// transactions whose static account keys include at least one of these pubkeys
    /// are included in lead-time statistics. Applies to shred-tier sources only;
    /// RPC-tier sources (rpc, geyser, jito-grpc) are always exempt.
    #[serde(default)]
    pub filter_programs: Vec<String>,
    /// Raw shred capture configuration. Omit to disable capture.
    #[serde(default)]
    pub capture: Option<CaptureConfig>,
}

/// Configuration for the always-on ring-buffer capture subsystem.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CaptureConfig {
    /// Enable capture.
    #[serde(default = "CaptureConfig::default_enabled")]
    pub enabled: bool,
    /// Output formats: one or more of "pcap", "csv", "jsonl".
    /// Each format writes its own ring of files under `output_dir`.
    #[serde(default = "CaptureConfig::default_formats")]
    pub formats: Vec<String>,
    /// Maximum total disk space (MB) each format's ring may consume.
    /// Parallel to `formats`; index N applies to `formats[N]`.
    /// Missing entries fall back to 10 000 MB (10 GB).
    #[serde(default)]
    pub max_size_mb: Vec<u64>,
    /// Directory to write capture files into.
    #[serde(default = "CaptureConfig::default_output_dir")]
    pub output_dir: String,
    /// Rotate to a new file after this many megabytes.
    #[serde(default = "CaptureConfig::default_rotate_mb")]
    pub rotate_mb: u64,
}

impl CaptureConfig {
    fn default_enabled() -> bool { true }
    fn default_formats() -> Vec<String> { vec!["pcap".into()] }
    fn default_output_dir() -> String { "/var/log/shredtop-capture".into() }
    fn default_rotate_mb() -> u64 { 500 }

    /// Number of ring files to keep for format at `idx`.
    /// Derived from `max_size_mb[idx] / rotate_mb`, minimum 2.
    pub fn ring_files_for(&self, idx: usize) -> usize {
        let max = self.max_size_mb.get(idx).copied().unwrap_or(10_000);
        ((max / self.rotate_mb) as usize).max(2)
    }
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            enabled: Self::default_enabled(),
            formats: Self::default_formats(),
            max_size_mb: vec![10_000],
            output_dir: Self::default_output_dir(),
            rotate_mb: Self::default_rotate_mb(),
        }
    }
}

/// One data source (shred feed or RPC endpoint).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SourceEntry {
    /// Human-readable name shown in the dashboard (e.g. "bebop", "jito-shredstream", "rpc")
    pub name: String,
    /// Source type: "shred" or "rpc"
    #[serde(rename = "type")]
    pub source_type: String,
    /// Multicast group IP (shred only)
    pub multicast_addr: Option<String>,
    /// UDP port (shred only; bebop=7733, jito-shredstream=20001)
    pub port: Option<u16>,
    /// Network interface for multicast (shred only, e.g. "doublezero1")
    pub interface: Option<String>,
    /// RPC endpoint URL (rpc or geyser)
    pub url: Option<String>,
    /// Authentication token sent as `x-token` header (geyser only)
    pub x_token: Option<String>,
    /// CPU core to pin receiver thread to (optional)
    pub pin_recv_core: Option<usize>,
    /// CPU core to pin decoder thread to (optional)
    pub pin_decode_core: Option<usize>,
    /// Only accept shreds with this version (bytes 77-78). Silently drops mismatches.
    /// Useful during forks or network upgrades. Omit to accept all versions.
    #[serde(default)]
    pub shred_version: Option<u16>,
}

impl ProbeConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config file: {}", path.display()))?;
        let cfg: Self = toml::from_str(&text)
            .with_context(|| format!("failed to parse config file: {}", path.display()))?;
        Ok(cfg)
    }

    /// Returns a default config that matches the standard DoubleZero + RPC setup.
    pub fn default_example() -> Self {
        Self {
            filter_programs: Vec::new(),
            capture: None,
            sources: vec![
                SourceEntry {
                    name: "bebop".into(),
                    source_type: "shred".into(),
                    multicast_addr: Some("233.84.178.1".into()),
                    port: Some(7733),
                    interface: Some("doublezero1".into()),
                    url: None,
                    x_token: None,
                    pin_recv_core: None,
                    pin_decode_core: None,
                    shred_version: None,
                },
                SourceEntry {
                    name: "jito-shredstream".into(),
                    source_type: "shred".into(),
                    multicast_addr: Some("233.84.178.2".into()),
                    port: Some(20001),
                    interface: Some("doublezero1".into()),
                    url: None,
                    x_token: None,
                    pin_recv_core: None,
                    pin_decode_core: None,
                    shred_version: None,
                },
                SourceEntry {
                    name: "rpc".into(),
                    source_type: "rpc".into(),
                    multicast_addr: None,
                    port: None,
                    interface: None,
                    url: Some("http://127.0.0.1:8899".into()),
                    x_token: None,
                    pin_recv_core: None,
                    pin_decode_core: None,
                    shred_version: None,
                },
            ],
        }
    }
}
