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
        // Convert http(s):// → ws(s):// — same host and port, WebSocket path
        let ws_url = rpc_url
            .replacen("https://", "wss://", 1)
            .replacen("http://", "ws://", 1);
        tracing::info!("RPC source: will subscribe via {}", ws_url);
        Ok(Self { ws_url, tx, metrics })
    }

    pub fn run(&mut self) -> Result<()> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;

        rt.block_on(async {
            loop {
                match run_logs_subscribe(&self.ws_url, self.tx.clone(), self.metrics.clone()).await {
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
