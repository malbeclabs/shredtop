//! `shredtop upgrade` — download the latest release binary from GitHub.

use anyhow::Result;
use std::io::{self, Write};
use std::process::Command;

use crate::color;

const RELEASES_API: &str = "https://api.github.com/repos/malbeclabs/shredtop/releases/latest";
const DOWNLOAD_URL: &str =
    "https://github.com/malbeclabs/shredtop/releases/download/{tag}/shredtop";

pub fn run() -> Result<()> {
    let current = env!("CARGO_PKG_VERSION");
    println!("Current:  v{}", current);
    print!("Latest:   ");
    io::stdout().flush()?;

    let latest = fetch_latest_release();
    match &latest {
        Ok(tag) => println!("{}", tag),
        Err(e) => {
            println!("({})", e);
            return Ok(());
        }
    }

    let tag = latest.unwrap(); // safe: matched Ok above
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

    println!(
        "{}",
        color::bold_green(&format!("✓ Done. {} installed to {}.", tag, dest.display()))
    );
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
            .args([
                "clone",
                "https://github.com/malbeclabs/shredtop.git",
                repo_str,
            ])
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

    println!(
        "{}",
        color::bold_green(&format!(
            "✓ Done. Built from source (main) installed to {}.",
            dest.display()
        ))
    );
    Ok(())
}

/// Locate the installed shredtop binary via `which`.
fn which_shredtop() -> Result<std::path::PathBuf> {
    let out = Command::new("which").arg("shredtop").output()?;
    let path = std::str::from_utf8(&out.stdout)?.trim().to_string();
    anyhow::ensure!(
        !path.is_empty(),
        "could not locate installed shredtop binary"
    );
    Ok(std::path::PathBuf::from(path))
}

/// Query the GitHub releases API and return the tag name of the latest release.
/// Falls back to `git ls-remote --tags` if api.github.com is unreachable.
fn fetch_latest_release() -> Result<String, String> {
    fetch_via_api().or_else(|_| fetch_via_git_ls_remote())
}

fn fetch_via_api() -> Result<String, String> {
    let output = Command::new("curl")
        .args([
            "-sf",
            "--max-time",
            "10",
            "-H",
            "User-Agent: shredtop",
            RELEASES_API,
        ])
        .output()
        .map_err(|_| "curl not found".to_string())?;

    if output.stdout.is_empty() || !output.status.success() {
        // HTTP 404 = no releases published yet; other failures = network error
        let status = output.status.code().unwrap_or(0);
        if status == 22 {
            // curl exit 22 = HTTP 4xx/5xx (with -f flag)
            return Err("no release published yet".to_string());
        }
        return Err("could not reach GitHub".to_string());
    }

    let json: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| "unexpected response from GitHub API".to_string())?;
    json.get("tag_name")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| "no tag_name in GitHub API response".to_string())
}

fn fetch_via_git_ls_remote() -> Result<String, String> {
    let output = Command::new("git")
        .args([
            "ls-remote",
            "--tags",
            "--sort=-version:refname",
            "https://github.com/malbeclabs/shredtop.git",
            "v*",
        ])
        .output()
        .map_err(|_| "git not found".to_string())?;

    if !output.status.success() {
        return Err("could not reach GitHub".to_string());
    }

    // Output lines: "<sha>\trefs/tags/<tag>"  (or "<sha>\trefs/tags/<tag>^{}")
    // Pick the first non-peeled tag (no "^{}" suffix)
    let text = std::str::from_utf8(&output.stdout)
        .map_err(|_| "invalid utf8 from git ls-remote".to_string())?;
    for line in text.lines() {
        if line.ends_with("^{}") {
            continue;
        }
        if let Some(tag) = line
            .split('\t')
            .nth(1)
            .and_then(|r| r.strip_prefix("refs/tags/"))
        {
            return Ok(tag.to_string());
        }
    }
    Err("no releases published yet".to_string())
}
