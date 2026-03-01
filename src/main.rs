//! shredtop — Solana shred feed latency benchmark.
//!
//! Measures the latency advantage of DoubleZero / Jito ShredStream raw shred
//! feeds over confirmed-block RPC polling. Run `shredtop --help` for usage.

use anyhow::Result;
use clap::Parser;
use tracing_subscriber::EnvFilter;

mod analyze;
mod bench;
mod capture;
mod color;
mod capture_status;
mod cli;
mod config;
mod discover;
mod monitor;
mod run;
mod service;
mod status;
mod uninstall;
mod upgrade;

use cli::{CaptureAction, Cli, Commands, ServiceAction};

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("warn".parse()?))
        .init();

    let cli = Cli::parse();

    // Load config (except for commands that don't need it)
    let config = match &cli.command {
        Commands::Init | Commands::Upgrade { .. } | Commands::Status | Commands::Service { .. } | Commands::Monitor { .. } | Commands::Capture { .. } | Commands::Analyze { .. } | Commands::Uninstall => None,
        _ => {
            if !cli.config.exists() {
                std::fs::write(&cli.config, b"")?;
                eprintln!(
                    "Created '{}' — run `shredtop discover` to populate it.",
                    cli.config.display()
                );
            }
            Some(config::ProbeConfig::load(&cli.config)?)
        }
    };

    match cli.command {
        Commands::Init => {
            let example = config::ProbeConfig::default_example();
            print!("{}", toml::to_string_pretty(&example)?);
        }
        Commands::Upgrade { source } => {
            if source {
                upgrade::run_from_source()?;
            } else {
                upgrade::run()?;
            }
        }
        Commands::Discover => {
            discover::run(config.as_ref().unwrap(), &cli.config)?;
        }
        Commands::Monitor { interval } => {
            monitor::run(interval)?;
        }
        Commands::Bench { duration, output } => {
            bench::run(config.as_ref().unwrap(), duration, output)?;
        }
        Commands::Run { interval, log } => {
            run::run(config.as_ref().unwrap(), interval, log)?;
        }
        Commands::Status => {
            status::run()?;
        }
        Commands::Service { action } => match action {
            ServiceAction::Start => service::install(&cli.config)?,
            ServiceAction::Stop => service::control("stop")?,
            ServiceAction::Uninstall => service::uninstall()?,
            ServiceAction::Restart => service::control("restart")?,
            ServiceAction::Status => service::control("status")?,
            ServiceAction::Enable => service::control("enable")?,
            ServiceAction::Disable => service::control("disable")?,
        },
        Commands::Capture { action } => match action {
            CaptureAction::List => capture_status::run(&cli.config)?,
        },
        Commands::Analyze { pcap, feed, min_matched } => {
            analyze::run(&pcap, &feed, min_matched)?;
        }
        Commands::Uninstall => {
            uninstall::run(&cli.config)?;
        }
    }

    Ok(())
}
