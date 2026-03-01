//! Yellowstone gRPC Geyser transaction source.
//!
//! Connects to any Yellowstone-compatible endpoint (Triton, Helius, QuickNode, etc.),
//! subscribes to all non-vote confirmed transactions, and feeds them into the fan-in
//! pipeline for lead-time comparison against raw shred feeds.
//!
//! The source reconnects automatically on disconnect (5s delay between attempts).

use anyhow::Result;
use crossbeam_channel::Sender;
use futures_util::StreamExt;
use std::collections::HashMap;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::thread::JoinHandle;

use solana_message::{Message as LegacyMessage, VersionedMessage};
use solana_signature::Signature;
use solana_transaction::versioned::VersionedTransaction;

use yellowstone_grpc_proto::geyser::{
    geyser_client::GeyserClient, subscribe_update::UpdateOneof, CommitmentLevel, SubscribeRequest,
    SubscribeRequestFilterTransactions,
};

use crate::decoder::DecodedTx;
use crate::fan_in::TxSource;
use crate::metrics;
use crate::source_metrics::SourceMetrics;

// ---------------------------------------------------------------------------
// GeyserTxSource
// ---------------------------------------------------------------------------

/// Yellowstone gRPC Geyser transaction source.
///
/// Delivers confirmed transactions from a Geyser-compatible endpoint. Use as a
/// baseline to compare against raw shred feeds — lead time will show how many ms
/// earlier shreds arrive vs. the Geyser stream.
pub struct GeyserTxSource {
    /// Display name for this source in the dashboard
    pub name: &'static str,
    /// gRPC endpoint URL (e.g. "http://grpc.example.com:10000" or "https://...")
    pub url: String,
    /// Optional authentication token sent as `x-token` metadata header
    pub x_token: Option<String>,
}

impl TxSource for GeyserTxSource {
    fn name(&self) -> &'static str {
        self.name
    }

    /// Geyser delivers confirmed transactions — same semantics as RPC, so we
    /// treat it as the baseline for shred lead-time computation.
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
            .name(format!("{}-geyser", name))
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("geyser: failed to build tokio runtime");

                rt.block_on(async move {
                    loop {
                        if let Err(e) =
                            run_geyser(&url, &x_token, tx.clone(), metrics.clone()).await
                        {
                            tracing::warn!(
                                "geyser source '{}' disconnected: {}  reconnecting in 5s",
                                name,
                                e
                            );
                        }
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    }
                });
            })
            .expect("geyser: failed to spawn thread");

        vec![handle]
    }
}

// ---------------------------------------------------------------------------
// Async connection loop
// ---------------------------------------------------------------------------

async fn run_geyser(
    url: &str,
    x_token: &Option<String>,
    tx: Sender<DecodedTx>,
    metrics: Arc<SourceMetrics>,
) -> Result<()> {
    let channel = tonic::transport::Channel::from_shared(url.to_owned())?
        .connect()
        .await?;

    let token = x_token.clone();
    let mut client = GeyserClient::with_interceptor(channel, move |mut req: tonic::Request<()>| {
        if let Some(ref t) = token {
            if let Ok(val) =
                t.parse::<tonic::metadata::MetadataValue<tonic::metadata::Ascii>>()
            {
                req.metadata_mut().insert("x-token", val);
            }
        }
        Ok(req)
    });

    // Subscribe to all non-vote, non-failed confirmed transactions.
    let request = SubscribeRequest {
        transactions: HashMap::from([(
            "all".to_string(),
            SubscribeRequestFilterTransactions {
                vote: Some(false),
                failed: Some(false),
                ..Default::default()
            },
        )]),
        commitment: Some(CommitmentLevel::Confirmed as i32),
        ..Default::default()
    };

    // Send one subscribe request; the server streams updates until disconnect.
    let mut stream = client
        .subscribe(futures_util::stream::once(async { request }))
        .await?
        .into_inner();

    while let Some(msg) = stream.next().await {
        let msg = msg?;
        if let Some(UpdateOneof::Transaction(tx_update)) = msg.update_oneof {
            if let Some(tx_info) = tx_update.transaction {
                let recv_ns = metrics::now_ns();
                let slot = tx_update.slot;

                metrics.txs_decoded.fetch_add(1, Relaxed);

                if let Some(decoded) = make_decoded_tx(&tx_info.signature, slot, recv_ns) {
                    metrics.txs_emitted.fetch_add(1, Relaxed);
                    let _ = tx.try_send(decoded);
                }
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a minimal `DecodedTx` from the 64-byte Geyser signature.
///
/// The fan-in pipeline only needs `signatures[0]` for deduplication and
/// `shred_recv_ns` for timing — the rest of the transaction is not used.
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
