//! RPC WebSocket subscription-based transaction source.
//!
//! Subscribes to confirmed transaction logs via `logsSubscribe` WebSocket RPC.
//! Works without --enable-rpc-transaction-history — uses live push notifications
//! instead of historical getBlock polling.
//!
//! If no WebSocket endpoint is reachable (no local validator, or pure relay
//! machine), the source reconnects silently in the background. Other sources
//! are unaffected and LEAD metrics stay null until a connection is established.

use anyhow::Result;
use crossbeam_channel::Sender;
use futures_util::StreamExt;
use solana_client::nonblocking::pubsub_client::PubsubClient;
use solana_client::rpc_config::{RpcTransactionLogsConfig, RpcTransactionLogsFilter};
use solana_commitment_config::CommitmentConfig;
use solana_message::{Message as LegacyMessage, VersionedMessage};
use solana_signature::Signature;
use solana_transaction::versioned::VersionedTransaction;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;

use crate::decoder::DecodedTx;
use crate::metrics;
use crate::source_metrics::SourceMetrics;

pub struct RpcSource {
    ws_url: String,
    tx: Sender<DecodedTx>,
    metrics: Arc<SourceMetrics>,
}

impl RpcSource {
    pub fn new(rpc_url: &str, tx: Sender<DecodedTx>, metrics: Arc<SourceMetrics>) -> Result<Self> {
        // Convert http(s):// → ws(s)://, then probe to find the actual WS port.
        // Agave validators sometimes bind WebSocket on rpc-port+1 (--rpc-pubsub-port).
        let raw_ws = rpc_url
            .replacen("https://", "wss://", 1)
            .replacen("http://", "ws://", 1);
        let ws_url = probe_ws_url(&raw_ws);
        tracing::info!("RPC source: will subscribe via {}", ws_url);
        Ok(Self {
            ws_url,
            tx,
            metrics,
        })
    }

    pub fn run(&mut self) -> Result<()> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;

        rt.block_on(async {
            loop {
                match run_logs_subscribe(&self.ws_url, self.tx.clone(), self.metrics.clone()).await
                {
                    Ok(()) => {}
                    Err(e) => {
                        tracing::warn!(
                            "RPC logs subscription '{}' disconnected: {}  reconnecting in 5s",
                            self.ws_url,
                            e
                        );
                    }
                }
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        });

        Ok(())
    }
}

async fn run_logs_subscribe(
    ws_url: &str,
    tx: Sender<DecodedTx>,
    metrics: Arc<SourceMetrics>,
) -> Result<()> {
    let pubsub = PubsubClient::new(ws_url).await?;

    let (mut stream, _unsub) = pubsub
        .logs_subscribe(
            RpcTransactionLogsFilter::All,
            RpcTransactionLogsConfig {
                commitment: Some(CommitmentConfig::confirmed()),
            },
        )
        .await?;

    tracing::info!("RPC logs subscription active on {}", ws_url);

    while let Some(response) = stream.next().await {
        // Skip failed transactions — shred feeds also decode them but we want
        // the comparison to be meaningful (confirmed successful txs only).
        if response.value.err.is_some() {
            continue;
        }

        let recv_ns = metrics::now_realtime_ns();
        let slot = response.context.slot;

        if let Some(decoded) = make_decoded_tx(&response.value.signature, slot, recv_ns) {
            metrics.txs_decoded.fetch_add(1, Relaxed);
            metrics.txs_emitted.fetch_add(1, Relaxed);
            let _ = tx.try_send(decoded);
        }
    }

    anyhow::bail!("logs subscription stream ended")
}

/// Probe `ws_url` with a real WebSocket handshake. If the primary port refuses
/// the upgrade, try `port+1` — the Agave `--rpc-pubsub-port` convention.
/// Returns the working URL, or the original if neither can be verified (the
/// existing 5s retry loop will surface the error normally).
fn probe_ws_url(ws_url: &str) -> String {
    let without_scheme = ws_url
        .strip_prefix("wss://")
        .or_else(|| ws_url.strip_prefix("ws://"))
        .unwrap_or(ws_url);
    let (host_port, _) = without_scheme
        .split_once('/')
        .unwrap_or((without_scheme, ""));
    let (host, port_str) = host_port.rsplit_once(':').unwrap_or((host_port, ""));
    let port: u16 = match port_str.parse() {
        Ok(p) => p,
        Err(_) => return ws_url.to_string(),
    };

    if try_ws_handshake(host, port) {
        return ws_url.to_string();
    }

    let alt = port + 1;
    if try_ws_handshake(host, alt) {
        let alt_url = ws_url.replacen(&format!(":{}", port), &format!(":{}", alt), 1);
        tracing::info!(
            "rpc_source: WebSocket not on :{}, using :{} (rpc-pubsub-port)",
            port,
            alt
        );
        return alt_url;
    }

    ws_url.to_string()
}

/// Attempt a WebSocket upgrade handshake. Returns true if the server responds
/// with HTTP 101 Switching Protocols.
fn try_ws_handshake(host: &str, port: u16) -> bool {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;

    let addr = format!("{}:{}", host, port);
    let Ok(addr) = addr.parse() else { return false };
    let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(300)) else {
        return false;
    };
    let req = format!(
        "GET / HTTP/1.1\r\nHost: {}:{}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
        host, port
    );
    if stream.write_all(req.as_bytes()).is_err() {
        return false;
    }
    let _ = stream.set_read_timeout(Some(Duration::from_millis(400)));
    let mut buf = [0u8; 32];
    let n = stream.read(&mut buf).unwrap_or(0);
    std::str::from_utf8(&buf[..n]).unwrap_or("").contains("101")
}

fn make_decoded_tx(sig_str: &str, slot: u64, recv_ns: u64) -> Option<DecodedTx> {
    let sig: Signature = sig_str.parse().ok()?;
    let sig_arr: [u8; 64] = sig.as_ref().try_into().ok()?;
    let transaction = VersionedTransaction {
        signatures: vec![Signature::from(sig_arr)],
        message: VersionedMessage::Legacy(LegacyMessage::default()),
    };
    Some(DecodedTx {
        transaction,
        slot,
        shred_recv_ns: recv_ns,
        decode_done_ns: recv_ns,
    })
}
