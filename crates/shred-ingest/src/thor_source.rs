//! ThorStreamer gRPC transaction source.
//!
//! Connects to a ThorStreamer endpoint and subscribes to confirmed transaction
//! events for lead-time comparison against raw shred feeds.
//!
//! Proto definitions below are inline (no protoc needed) using prost derives.
//! Verify field tags against ThorStreamer's published proto before deploying.
//!
//! The source reconnects automatically on disconnect (5s delay).

use anyhow::Result;
use crossbeam_channel::Sender;
use futures_util::StreamExt;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::thread::JoinHandle;

use solana_message::{Message as LegacyMessage, VersionedMessage};
use solana_signature::Signature;
use solana_transaction::versioned::VersionedTransaction;

use crate::decoder::DecodedTx;
use crate::fan_in::TxSource;
use crate::metrics;
use crate::source_metrics::SourceMetrics;

// ---------------------------------------------------------------------------
// Inline protobuf definitions for ThorStreamer
//
// Wire format (verify against ThorStreamer proto):
//   message SubscribeTransactionsRequest {}
//   message TransactionNotification {
//     uint64 slot       = 1;
//     bytes  signature  = 2;  // 64-byte Ed25519 signature
//   }
//   service ThorStreamer {
//     rpc SubscribeTransactions(SubscribeTransactionsRequest)
//         returns (stream TransactionNotification);
//   }
// ---------------------------------------------------------------------------

#[derive(Clone, PartialEq, prost::Message)]
struct SubscribeTransactionsRequest {}

#[derive(Clone, PartialEq, prost::Message)]
struct ThorTransactionNotification {
    #[prost(uint64, tag = "1")]
    pub slot: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub signature: Vec<u8>,
}

// ---------------------------------------------------------------------------
// ThorTxSource
// ---------------------------------------------------------------------------

/// ThorStreamer gRPC transaction source.
///
/// Delivers confirmed transactions from a ThorStreamer endpoint. Use as a
/// baseline to compare against raw shred feeds — lead time will show how many
/// ms earlier shreds arrive vs. the ThorStreamer stream.
pub struct ThorTxSource {
    /// Display name for this source in the dashboard
    pub name: &'static str,
    /// gRPC endpoint URL (e.g. "http://grpc.example.com:10000")
    pub url: String,
    /// Optional authentication token sent as `x-token` metadata header
    pub x_token: Option<String>,
}

impl TxSource for ThorTxSource {
    fn name(&self) -> &'static str {
        self.name
    }

    fn is_rpc(&self) -> bool {
        true
    }

    fn start(
        self: Box<Self>,
        tx: Sender<DecodedTx>,
        metrics: Arc<SourceMetrics>,
        _race: Option<Arc<crate::shred_race::ShredRaceTracker>>,
    ) -> Vec<JoinHandle<()>> {
        let name = self.name;
        let url = self.url.clone();
        let x_token = self.x_token.clone();

        let handle = std::thread::Builder::new()
            .name(format!("{}-thor", name))
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("thor: failed to build tokio runtime");

                rt.block_on(async move {
                    loop {
                        if let Err(e) =
                            run_thor(&url, &x_token, tx.clone(), metrics.clone()).await
                        {
                            tracing::warn!(
                                "thor source '{}' disconnected: {}  reconnecting in 5s",
                                name,
                                e
                            );
                        }
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    }
                });
            })
            .expect("thor: failed to spawn thread");

        vec![handle]
    }
}

// ---------------------------------------------------------------------------
// Async connection loop
// ---------------------------------------------------------------------------

async fn run_thor(
    url: &str,
    x_token: &Option<String>,
    tx: Sender<DecodedTx>,
    metrics: Arc<SourceMetrics>,
) -> Result<()> {
    let channel = tonic::transport::Channel::from_shared(url.to_owned())?
        .connect()
        .await?;

    let mut grpc: tonic::client::Grpc<tonic::transport::Channel> =
        tonic::client::Grpc::new(channel);

    let path = tonic::codegen::http::uri::PathAndQuery::from_static(
        "/thorstreamer.ThorStreamer/SubscribeTransactions",
    );

    grpc.ready()
        .await
        .map_err(|e| anyhow::anyhow!("thor: service not ready: {}", e))?;

    let codec = tonic_prost::ProstCodec::<
        SubscribeTransactionsRequest,
        ThorTransactionNotification,
    >::default();

    let mut req = tonic::Request::new(SubscribeTransactionsRequest {});
    if let Some(ref t) = x_token {
        if let Ok(val) = t.parse::<tonic::metadata::MetadataValue<tonic::metadata::Ascii>>() {
            req.metadata_mut().insert("x-token", val);
        }
    }
    let mut stream: tonic::codec::Streaming<ThorTransactionNotification> = grpc
        .server_streaming(req, path, codec)
        .await?
        .into_inner();

    while let Some(msg) = stream.next().await {
        let msg = msg?;
        let recv_ns = metrics::now_ns();

        metrics.txs_decoded.fetch_add(1, Relaxed);

        if let Some(decoded) = make_decoded_tx(&msg.signature, msg.slot, recv_ns) {
            metrics.txs_emitted.fetch_add(1, Relaxed);
            let _ = tx.try_send(decoded);
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_decoded_tx(sig_bytes: &[u8], slot: u64, recv_ns: u64) -> Option<DecodedTx> {
    let sig_arr: [u8; 64] = sig_bytes.try_into().ok()?;
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
