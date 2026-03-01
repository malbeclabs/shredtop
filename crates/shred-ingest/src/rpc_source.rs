//! RPC block-polling transaction source.
//!
//! Polls confirmed blocks via the Solana JSON-RPC API every 100ms.
//! Slower than shred ingestion (~400ms+ behind), but works without a multicast feed.
//! Used as the baseline comparison source for lead-time measurement.

use anyhow::Result;
use crossbeam_channel::Sender;
use solana_client::rpc_client::RpcClient;
use solana_commitment_config::CommitmentConfig;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::Duration;

use crate::decoder::DecodedTx;
use crate::metrics;
use crate::source_metrics::SourceMetrics;

/// Polls confirmed blocks via RPC and emits transactions.
pub struct RpcSource {
    rpc: RpcClient,
    tx: Sender<DecodedTx>,
    last_slot: u64,
    metrics: Arc<SourceMetrics>,
}

impl RpcSource {
    pub fn new(rpc_url: &str, tx: Sender<DecodedTx>, metrics: Arc<SourceMetrics>) -> Result<Self> {
        let rpc = RpcClient::new_with_commitment(
            rpc_url.to_string(),
            CommitmentConfig::confirmed(),
        );
        let last_slot = rpc.get_slot()?;
        tracing::info!("RPC source starting at slot {}", last_slot);
        Ok(Self { rpc, tx, last_slot, metrics })
    }

    /// Main polling loop — runs on its own thread
    pub fn run(&mut self) -> Result<()> {
        tracing::info!("RPC transaction source started (polling mode)");
        loop {
            match self.poll_new_slots() {
                Ok(count) => {
                    if count > 0 {
                        tracing::debug!("processed {} transactions from RPC", count);
                    }
                }
                Err(e) => {
                    tracing::warn!("RPC poll error: {}, retrying...", e);
                    std::thread::sleep(Duration::from_millis(500));
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn poll_new_slots(&mut self) -> Result<usize> {
        let current_slot = self.rpc.get_slot()?;
        if current_slot <= self.last_slot {
            return Ok(0);
        }

        let mut total_txs = 0;

        for slot in (self.last_slot + 1)..=current_slot {
            match self.process_slot(slot) {
                Ok(count) => total_txs += count,
                Err(e) => {
                    tracing::trace!("slot {} not available: {}", slot, e);
                }
            }
        }

        self.last_slot = current_slot;
        Ok(total_txs)
    }

    fn process_slot(&self, slot: u64) -> Result<usize> {
        self.metrics.slots_attempted.fetch_add(1, Relaxed);

        let block = self.rpc.get_block_with_config(
            slot,
            solana_client::rpc_config::RpcBlockConfig {
                encoding: Some(solana_transaction_status::UiTransactionEncoding::Base64),
                transaction_details: Some(solana_transaction_status::TransactionDetails::Full),
                rewards: Some(false),
                commitment: Some(CommitmentConfig::confirmed()),
                max_supported_transaction_version: Some(0),
            },
        )?;
        let recv_ts = metrics::now_ns();

        let mut count = 0;

        if let Some(transactions) = block.transactions {
            for tx_with_meta in transactions {
                if let Some(decoded) = self.decode_ui_transaction(tx_with_meta, slot, recv_ts) {
                    let _ = self.tx.try_send(decoded);
                    count += 1;
                }
            }
        }

        self.metrics.slots_complete.fetch_add(1, Relaxed);
        self.metrics.txs_decoded.fetch_add(count as u64, Relaxed);

        Ok(count)
    }

    fn decode_ui_transaction(
        &self,
        tx_with_meta: solana_transaction_status::EncodedTransactionWithStatusMeta,
        slot: u64,
        recv_ts: u64,
    ) -> Option<DecodedTx> {
        let decode_start = metrics::now_ns();
        let tx = tx_with_meta.transaction;
        match tx.decode() {
            Some(versioned_tx) => {
                let decode_done = metrics::now_ns();
                metrics::METRICS.record_stage(
                    &metrics::METRICS.decode_ns,
                    decode_done - decode_start,
                );
                Some(DecodedTx {
                    transaction: versioned_tx,
                    slot,
                    shred_recv_ns: recv_ts,
                    decode_done_ns: decode_done,
                })
            }
            None => None,
        }
    }
}
