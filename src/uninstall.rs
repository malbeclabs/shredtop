//! `shredtop uninstall` — remove all shredtop files from the system.

use anyhow::Result;
use std::io::{self, Write};
use std::path::Path;
use std::process::Command;

use crate::color;
use crate::config::ProbeConfig;
use crate::run::DEFAULT_LOG;

pub fn run(config_path: &Path) -> Result<()> {
    // Collect the capture dir before we potentially remove probe.toml
    let capture_dir = ProbeConfig::load(config_path)
        .ok()
        .and_then(|c| c.capture)
        .map(|cap| cap.output_dir);

    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    let source_dir = format!("{}/shredtop", home);
    let binary = which_shredtop();

    println!("The following will be removed:");
    println!("  systemd service         shredtop.service");
    if let Some(ref bin) = binary {
        println!("  binary                  {}", bin);
    }
    println!("  metrics log             {}", DEFAULT_LOG);
    if let Some(ref cap) = capture_dir {
        println!("  capture files           {}", cap);
    }
    println!("  config                  {}", config_path.display());
    if Path::new(&source_dir).exists() {
        println!("  source directory        {}", source_dir);
    }
    println!();
    print!("{}", color::yellow("Proceed? [y/N]: "));
    io::stdout().flush().ok();

    let mut input = String::new();
    io::stdin().read_line(&mut input).ok();
    if input.trim().to_lowercase() != "y" {
        println!("Aborted.");
        return Ok(());
    }

    println!();

    // 1. Stop and remove systemd service
    step("Stopping service", || {
        let _ = Command::new("systemctl").args(["stop", "shredtop"]).status();
        let _ = Command::new("systemctl").args(["disable", "shredtop"]).status();
        let unit = "/etc/systemd/system/shredtop.service";
        if Path::new(unit).exists() {
            std::fs::remove_file(unit)?;
            let _ = Command::new("systemctl").arg("daemon-reload").status();
        }
        Ok(())
    });

    // 2. Remove binary
    if let Some(ref bin) = binary {
        step(&format!("Removing binary ({})", bin), || {
            std::fs::remove_file(bin).map_err(anyhow::Error::from)
        });
    } else {
        // Try cargo uninstall as fallback
        step("Removing binary (cargo uninstall)", || {
            Command::new("cargo")
                .args(["uninstall", "shredtop"])
                .status()?;
            Ok(())
        });
    }

    // 3. Remove metrics log
    step(&format!("Removing metrics log ({})", DEFAULT_LOG), || {
        if Path::new(DEFAULT_LOG).exists() {
            std::fs::remove_file(DEFAULT_LOG).map_err(anyhow::Error::from)
        } else {
            Ok(())
        }
    });

    // 4. Remove capture files
    if let Some(ref cap) = capture_dir {
        step(&format!("Removing capture files ({})", cap), || {
            if Path::new(cap).exists() {
                std::fs::remove_dir_all(cap).map_err(anyhow::Error::from)
            } else {
                Ok(())
            }
        });
    }

    // 5. Remove probe.toml
    step(&format!("Removing config ({})", config_path.display()), || {
        if config_path.exists() {
            std::fs::remove_file(config_path).map_err(anyhow::Error::from)
        } else {
            Ok(())
        }
    });

    // 6. Remove source directory
    if Path::new(&source_dir).exists() {
        step(&format!("Removing source directory ({})", source_dir), || {
            std::fs::remove_dir_all(&source_dir).map_err(anyhow::Error::from)
        });
    }

    println!();
    println!("{}", color::bold_green("✓ shredtop uninstalled."));
    Ok(())
}

fn step(label: &str, f: impl FnOnce() -> Result<()>) {
    print!("  {}...", label);
    io::stdout().flush().ok();
    match f() {
        Ok(_) => println!(" {}", color::green("done")),
        Err(e) => println!(" {} ({})", color::yellow("skipped"), e),
    }
}

fn which_shredtop() -> Option<String> {
    let out = Command::new("which").arg("shredtop").output().ok()?;
    let path = std::str::from_utf8(&out.stdout).ok()?.trim().to_string();
    if path.is_empty() { None } else { Some(path) }
}
