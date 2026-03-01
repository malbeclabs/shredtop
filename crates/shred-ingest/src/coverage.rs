//! Slot-level coverage event types for `SourceMetrics` tracking.

/// Slot-level outcome events emitted by the decoder when a slot is finalised.
/// Used to update `SourceMetrics` slot counters.
pub enum SlotCoverageEvent {
    /// All data shreds arrived contiguously and were fully decoded.
    Complete { slot: u64, shreds_seen: u32, txs_decoded: u32 },
    /// Slot expired with some shreds decoded but coverage was incomplete.
    Partial { slot: u64, shreds_seen: u32, txs_decoded: u32 },
    /// Slot expired with zero decoded transactions.
    Dropped { slot: u64 },
}
