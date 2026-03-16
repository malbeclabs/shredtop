//! JetStream (OrbitFlare) gRPC transaction source.
//!
//! Connects to a JetStream endpoint and subscribes to confirmed transaction
//! events for lead-time comparison against raw shred feeds.
//!
//! Proto definitions below are inline (no protoc needed) using prost derives.
//! JetStream's SubscribeUpdate includes a `timestamp` field (Unix ms) and a
//! `filter_id` that identifies which subscription filter matched.
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
// Inline protobuf definitions for JetStream (OrbitFlare)
//
// Wire format (verify against OrbitFlare JetStream proto):
//   message SubscribeRequest {
//     map<string, TransactionFilter> transactions = 1;
//   }
//   message TransactionFilter {}
//   message SubscribeUpdate {
//     string filter_id  = 1;
//     uint64 timestamp  = 2;  // Unix milliseconds when tx was confirmed
//     bytes  signature  = 3;  // 64-byte Ed25519 signature
//     uint64 slot       = 4;
//   }
//   service Jetstream {
//     rpc Subscribe(stream SubscribeRequest) returns (stream SubscribeUpdate);
//   }
// ---------------------------------------------------------------------------

#[derive(Clone, PartialEq, prost::Message)]
struct JetstreamSubscribeRequest {}

#[derive(Clone, PartialEq, prost::Message)]
struct JetstreamSubscribeUpdate {
    #[prost(string, tag = "1")]
    pub filter_id: String,
    /// Unix timestamp in milliseconds when the transaction was confirmed.
    #[prost(uint64, tag = "2")]
    pub timestamp: u64,
    #[prost(bytes = "vec", tag = "3")]
    pub signature: Vec<u8>,
    #[prost(uint64, tag = "4")]
    pub slot: u64,
}

// ---------------------------------------------------------------------------
// JetstreamTxSource
// ---------------------------------------------------------------------------

/// JetStream (OrbitFlare) gRPC transaction source.
///
/// Delivers confirmed transactions from a JetStream endpoint. Use as a
/// baseline to compare against raw shred feeds — lead time will show how many
/// ms earlier shreds arrive vs. the JetStream feed.
pub struct JetstreamTxSource {
    /// Display name for this source in the dashboard
    pub name: &'static str,
    /// gRPC endpoint URL (e.g. "http://grpc.example.com:10000")
    pub url: String,
    /// Optional authentication token sent as `x-token` metadata header
    pub x_token: Option<String>,
}

impl TxSource for JetstreamTxSource {
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
            .name(format!("{}-jetstream", name))
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("jetstream: failed to build tokio runtime");

                rt.block_on(async move {
                    loop {
                        if let Err(e) =
                            run_jetstream(&url, &x_token, tx.clone(), metrics.clone()).await
                        {
                            tracing::warn!(
                                "jetstream source '{}' disconnected: {}  reconnecting in 5s",
                                name,
                                e
                            );
                        }
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    }
                });
            })
            .expect("jetstream: failed to spawn thread");

        vec![handle]
    }
}

// ---------------------------------------------------------------------------
// Async connection loop
// ---------------------------------------------------------------------------

async fn run_jetstream(
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
        "/jetstream.Jetstream/Subscribe",
    );

    grpc.ready()
        .await
        .map_err(|e| anyhow::anyhow!("jetstream: service not ready: {}", e))?;

    let codec = tonic_prost::ProstCodec::<
        JetstreamSubscribeRequest,
        JetstreamSubscribeUpdate,
    >::default();

    // JetStream uses bidirectional streaming; send a single subscribe request.
    let mut req = tonic::Request::new(futures_util::stream::once(async {
        JetstreamSubscribeRequest {}
    }));
    if let Some(ref t) = x_token {
        if let Ok(val) = t.parse::<tonic::metadata::MetadataValue<tonic::metadata::Ascii>>() {
            req.metadata_mut().insert("x-token", val);
        }
    }
    let mut stream: tonic::codec::Streaming<JetstreamSubscribeUpdate> = grpc
        .streaming(req, path, codec)
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
