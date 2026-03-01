//! `shredtop service` — systemd integration.
//!
//! Installs and manages a systemd unit that runs `shredtop run` in the
//! background, logging metrics to /var/log/shredtop.jsonl.

use anyhow::Result;
use std::process::Command;

use crate::color;

const UNIT_PATH: &str = "/etc/systemd/system/shredtop.service";

pub fn install(config_path: &std::path::Path) -> Result<()> {
    let already_active = Command::new("systemctl")
        .args(["is-active", "--quiet", "shredtop"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if already_active {
        println!("{}", color::green("Service is already running."));
        println!();
        println!("  shredtop service stop     — stop the service");
        println!("  shredtop service restart  — restart the service");
        println!("  shredtop monitor          — open live dashboard");
        return Ok(());
    }

    let binary = std::env::current_exe()?;
    let config_abs = config_path
        .canonicalize()
        .unwrap_or_else(|_| config_path.to_path_buf());

    let unit = format!(
        r#"[Unit]
Description=Shredtop — Solana shred feed latency monitor
After=network.target

[Service]
Type=simple
User=root
ExecStart={binary} -c {config} run
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"#,
        binary = binary.display(),
        config = config_abs.display(),
    );

    std::fs::write(UNIT_PATH, unit)?;

    let _ = Command::new("systemctl").arg("daemon-reload").status();
    let _ = Command::new("systemctl").args(["enable", "shredtop"]).status();
    let _ = Command::new("systemctl").args(["start", "shredtop"]).status();

    println!("{}", color::bold_green("✓ Service installed, enabled, and started."));
    println!();
    println!("  shredtop monitor  — open live dashboard");
    println!("  shredtop status   — view latest metrics");

    Ok(())
}

pub fn uninstall() -> Result<()> {
    let _ = Command::new("systemctl").args(["stop", "shredtop"]).status();
    let _ = Command::new("systemctl")
        .args(["disable", "shredtop"])
        .status();
    std::fs::remove_file(UNIT_PATH)?;
    let _ = Command::new("systemctl").arg("daemon-reload").status();
    println!("Removed {}.", UNIT_PATH);
    Ok(())
}

pub fn control(action: &str) -> Result<()> {
    let ok = Command::new("systemctl")
        .args([action, "shredtop"])
        .status()?
        .success();
    anyhow::ensure!(ok, "systemctl {} shredtop failed", action);
    Ok(())
}
