//! `shredtop upgrade` — download the latest release binary from GitHub.

use anyhow::Result;
use std::io::{self, Write};
use std::process::Command;

use crate::color;

const RELEASES_API: &str =
    "https://api.github.com/repos/malbeclabs/shredtop/releases/latest";
const DOWNLOAD_URL: &str =
    "https://github.com/malbeclabs/shredtop/releases/download/{tag}/shredtop";

pub fn run() -> Result<()> {
    let current = env!("CARGO_PKG_VERSION");
    println!("Current:  v{}", current);
    print!("Latest:   ");
    io::stdout().flush()?;

    let latest = fetch_latest_release();
    match &latest {
        Some(tag) => println!("{}", tag),
        None => {
            println!("(could not reach GitHub)");
            return Ok(());
        }
    }

    let tag = latest.unwrap();
    if tag == format!("v{}", current) {
        println!("{}", color::green("Already up to date."));
        return Ok(());
    }

    println!("{}", color::cyan(&format!("Upgrading to {}...", tag)));

    let url = DOWNLOAD_URL.replace("{tag}", &tag);
    let dest = which_shredtop()?;
    let tmp = dest.with_extension("tmp");

    let ok = Command::new("curl")
        .args(["-fsSL", "--max-time", "120", "-o"])
        .arg(&tmp)
        .arg(&url)
        .status()?
        .success();
    anyhow::ensure!(ok, "download failed — check your internet connection");

    // chmod before replacing so there's no window where the binary is non-executable
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&tmp)?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&tmp, perms)?;
    }

    // Atomic rename — works even while the old binary is running
    std::fs::rename(&tmp, &dest)?;

    println!("{}", color::bold_green(&format!("✓ Done. {} installed to {}.", tag, dest.display())));
    Ok(())
}

/// Fetch latest main and rebuild from source.
/// Builds whatever is on main regardless of whether CI has published a release yet.
pub fn run_from_source() -> Result<()> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    let repo = std::path::PathBuf::from(&home).join("shredtop");
    let repo_str = repo.to_str().unwrap();

    if repo.exists() {
        println!("Fetching latest main...");
        let ok = Command::new("git")
            .args(["-C", repo_str, "fetch", "origin"])
            .status()?
            .success();
        anyhow::ensure!(ok, "git fetch failed");
        // Show what changed before resetting
        Command::new("git")
            .args(["-C", repo_str, "diff", "--stat", "HEAD", "origin/main"])
            .status()
            .ok();
        // Hard-reset to origin/main — clean tree, no local drift.
        let ok = Command::new("git")
            .args(["-C", repo_str, "reset", "--hard", "origin/main"])
            .status()?
            .success();
        anyhow::ensure!(ok, "git reset failed");
    } else {
        println!("Cloning to {}...", repo_str);
        let ok = Command::new("git")
            .args(["clone", "https://github.com/malbeclabs/shredtop.git", repo_str])
            .status()?
            .success();
        anyhow::ensure!(ok, "git clone failed");
    }

    println!("Building...");
    let ok = Command::new("cargo")
        .args(["build", "--release"])
        .current_dir(&repo)
        .status()?
        .success();
    anyhow::ensure!(ok, "cargo build failed");

    // Copy to a temp file then rename — avoids ETXTBSY on the running binary
    let built = repo.join("target/release/shredtop");
    let dest = which_shredtop()?;
    let tmp = dest.with_extension("tmp");
    std::fs::copy(&built, &tmp)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&tmp)?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&tmp, perms)?;
    }

    std::fs::rename(&tmp, &dest)?;

    println!("{}", color::bold_green(&format!("✓ Done. Built from source (main) installed to {}.", dest.display())));
    Ok(())
}

/// Locate the installed shredtop binary via `which`.
fn which_shredtop() -> Result<std::path::PathBuf> {
    let out = Command::new("which").arg("shredtop").output()?;
    let path = std::str::from_utf8(&out.stdout)?.trim().to_string();
    anyhow::ensure!(!path.is_empty(), "could not locate installed shredtop binary");
    Ok(std::path::PathBuf::from(path))
}

/// Query the GitHub releases API and return the tag name of the latest release.
fn fetch_latest_release() -> Option<String> {
    let output = Command::new("curl")
        .args(["-sf", "--max-time", "10", "-H", "User-Agent: shredtop", RELEASES_API])
        .output()
        .ok()?;

    if !output.status.success() || output.stdout.is_empty() {
        return None;
    }

    let json: serde_json::Value = serde_json::from_slice(&output.stdout).ok()?;
    json.get("tag_name")?.as_str().map(str::to_string)
}
