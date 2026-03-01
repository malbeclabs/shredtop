//! Pluggable transaction source abstraction.
//! Allows swapping between shred feed, RPC polling, etc.

use anyhow::Result;
use crossbeam_channel::Sender;
use std::sync::Arc;

use crate::decoder::DecodedTx;
use crate::source_metrics::SourceMetrics;

/// Transaction source configuration
#[derive(Debug, Clone)]
pub enum SourceConfig {
    /// UDP multicast shred feed (lowest latency, requires DoubleZero or Jito ShredStream)
    Shred {
        multicast_addr: String,
        port: u16,
        interface: String,
        shred_version: Option<u16>,
    },
    /// RPC block polling (highest latency, always available)
    Rpc { url: String },
}

/// Start the configured transaction source on a new thread.
pub fn start_source(
    config: SourceConfig,
    tx: Sender<DecodedTx>,
    pin_core: Option<usize>,
    metrics: Arc<SourceMetrics>,
) -> Result<std::thread::JoinHandle<()>> {
    match config {
        SourceConfig::Shred { multicast_addr, port, interface, shred_version } => {
            let (shred_tx, shred_rx) = crossbeam_channel::bounded(4096);

            let recv_metrics = metrics.clone();
            let handle = std::thread::Builder::new()
                .name("shred-recv".into())
                .spawn(move || {
                    if let Some(core) = pin_core {
                        pin_to_core(core);
                    }
                    let mut receiver = crate::receiver::ShredReceiver::new(
                        &multicast_addr,
                        port,
                        &interface,
                        shred_tx,
                        recv_metrics,
                        shred_version,
                        None,
                        None,
                    )
                    .expect("failed to create shred receiver");
                    receiver.run().expect("shred receiver crashed");
                })?;

            std::thread::Builder::new()
                .name("shred-decode".into())
                .spawn(move || {
                    let decoder = crate::decoder::ShredDecoder::new(shred_rx, tx, metrics);
                    decoder.run().expect("shred decoder crashed");
                })?;

            Ok(handle)
        }
        SourceConfig::Rpc { url } => {
            let handle = std::thread::Builder::new()
                .name("rpc-source".into())
                .spawn(move || {
                    if let Some(core) = pin_core {
                        pin_to_core(core);
                    }
                    let mut source = crate::rpc_source::RpcSource::new(&url, tx, metrics)
                        .expect("failed to create RPC source");
                    source.run().expect("RPC source crashed");
                })?;
            Ok(handle)
        }
    }
}

fn pin_to_core(core_id: usize) {
    #[cfg(target_os = "linux")]
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_SET(core_id, &mut set);
        libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
    }
    #[cfg(not(target_os = "linux"))]
    let _ = core_id;
}
