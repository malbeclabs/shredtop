//! Jito ShredStream gRPC transaction source.
//!
//! Connects to a locally-running Jito ShredStream proxy (typically at
//! `http://127.0.0.1:9999`). The proxy receives raw shreds from Jito's
//! network and exposes them as decoded `Entry` messages via gRPC. Our
//! client subscribes to that stream and extracts transactions for
//! lead-time comparison against an RPC baseline.
//!
//! The proxy handles Jito auth (keypair challenge-response); this client
//! needs no credentials — just the local proxy URL.
//!
//! The source reconnects automatically on disconnect (5s delay).

use anyhow::Result;
use crossbeam_channel::Sender;
use futures_util::StreamExt;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::thread::JoinHandle;

#[allow(deprecated)]
use solana_entry::entry::Entry;

use crate::decoder::DecodedTx;
use crate::fan_in::TxSource;
use crate::metrics;
use crate::source_metrics::SourceMetrics;

// ---------------------------------------------------------------------------
// Minimal protobuf message types for the ShredStream proxy protocol
//
// Defined manually using prost derives — no proto files or protoc needed.
// Wire format matches shredstream.proto from jito-labs/mev-protos:
//   message SubscribeEntriesRequest {}
//   message Entry { uint64 slot = 1; bytes entries = 2; }
//   service ShredstreamProxy {
//     rpc SubscribeEntries(SubscribeEntriesRequest) returns (stream Entry);
//   }
// ---------------------------------------------------------------------------

#[derive(Clone, PartialEq, prost::Message)]
struct SubscribeEntriesRequest {}

#[derive(Clone, PartialEq, prost::Message)]
struct JitoEntry {
    #[prost(uint64, tag = "1")]
    pub slot: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub entries: Vec<u8>,
}

// ---------------------------------------------------------------------------
// JitoShredstreamSource
// ---------------------------------------------------------------------------

/// Jito ShredStream gRPC transaction source.
///
/// Receives decoded entries from a local ShredStream proxy, extracts
/// transactions, and feeds them into the fan-in pipeline for lead-time
/// comparison against an RPC baseline. Transactions arrive before block
/// confirmation, giving similar lead times to raw UDP shred feeds.
pub struct JitoShredstreamSource {
    /// Display name for this source in the dashboard
    pub name: &'static str,
    /// gRPC endpoint of the local ShredStream proxy (e.g. "http://127.0.0.1:9999")
    pub url: String,
}

impl TxSource for JitoShredstreamSource {
    fn name(&self) -> &'static str {
        self.name
    }

    /// Jito ShredStream entries arrive before block confirmation, so this
    /// source is a shred-tier feed, not an RPC baseline.
    fn is_rpc(&self) -> bool {
        false
    }

    fn start(
        self: Box<Self>,
        tx: Sender<DecodedTx>,
        metrics: Arc<SourceMetrics>,
        _race: Option<Arc<crate::shred_race::ShredRaceTracker>>,
    ) -> Vec<JoinHandle<()>> {
        let name = self.name;
        let url = self.url.clone();

        let handle = std::thread::Builder::new()
            .name(format!("{}-jito-grpc", name))
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("jito-grpc: failed to build tokio runtime");

                rt.block_on(async move {
                    loop {
                        if let Err(e) =
                            run_jito_shredstream(&url, tx.clone(), metrics.clone()).await
                        {
                            tracing::warn!(
                                "jito-shredstream source '{}' disconnected: {}  reconnecting in 5s",
                                name,
                                e
                            );
                        }
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    }
                });
            })
            .expect("jito-grpc: failed to spawn thread");

        vec![handle]
    }
}

// ---------------------------------------------------------------------------
// Async connection loop
// ---------------------------------------------------------------------------

async fn run_jito_shredstream(
    url: &str,
    tx: Sender<DecodedTx>,
    metrics: Arc<SourceMetrics>,
) -> Result<()> {
    let channel = tonic::transport::Channel::from_shared(url.to_owned())?
        .connect()
        .await?;

    let mut grpc: tonic::client::Grpc<tonic::transport::Channel> =
        tonic::client::Grpc::new(channel);

    let path = tonic::codegen::http::uri::PathAndQuery::from_static(
        "/shredstream.ShredstreamProxy/SubscribeEntries",
    );

    grpc.ready()
        .await
        .map_err(|e| anyhow::anyhow!("jito-grpc: service not ready: {}", e))?;

    let codec = tonic_prost::ProstCodec::<SubscribeEntriesRequest, JitoEntry>::default();

    let req = tonic::Request::new(SubscribeEntriesRequest {});
    let mut stream: tonic::codec::Streaming<JitoEntry> = grpc
        .server_streaming(req, path, codec)
        .await?
        .into_inner();

    while let Some(msg) = stream.next().await {
        let msg = msg?;
        let recv_ns = metrics::now_ns();
        let slot = msg.slot;

        // The proxy sends bincode-serialized Vec<solana_entry::entry::Entry>
        #[allow(deprecated)]
        let entries: Vec<Entry> = match bincode::deserialize(&msg.entries) {
            Ok(e) => e,
            Err(_) => continue,
        };

        #[allow(deprecated)]
        for entry in entries {
            for transaction in entry.transactions {
                metrics.txs_decoded.fetch_add(1, Relaxed);
                let decoded = DecodedTx {
                    transaction,
                    slot,
                    shred_recv_ns: recv_ns,
                    decode_done_ns: recv_ns,
                };
                metrics.txs_emitted.fetch_add(1, Relaxed);
                let _ = tx.try_send(decoded);
            }
        }
    }

    Ok(())
}
