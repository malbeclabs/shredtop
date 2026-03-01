//! Shred reassembly and transaction decoding.
//!
//! Accepts raw shreds from `ShredReceiver`, accumulates data shred payloads per slot,
//! flushes contiguous runs into an entry buffer, and deserializes `Entry` structs via
//! bincode to extract `VersionedTransaction`s.
//!
//! FEC (Reed-Solomon erasure) recovery is implemented for Merkle coding shreds.
//! When a FEC set accumulates enough shards (data + coding >= num_data), missing
//! data shreds are reconstructed and inserted into the slot's data_payloads map.

use anyhow::Result;
use crossbeam_channel::{Receiver, Sender};
use reed_solomon_erasure::galois_8::ReedSolomon;
use solana_transaction::versioned::VersionedTransaction;
use std::collections::HashMap;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;

use crate::metrics;
use crate::source_metrics::{SlotOutcome, SlotStats, SourceMetrics};

// ---------------------------------------------------------------------------
// Raw shred header parsing
//
// solana_ledger::shred is pub(crate) in Agave 3.x — not accessible externally.
// We parse the binary layout directly using the stable Agave shred wire format.
//
// Common header layout (all shred types):
//   Bytes   0 ..  63 = signature (64 bytes, not used here)
//   Byte   64        = ShredVariant
//   Bytes  65 ..  72 = slot (u64 LE)
//   Bytes  73 ..  76 = index (u32 LE)
//   Bytes  77 ..  78 = version (u16 LE, not used)
//   Bytes  79 ..  82 = fec_set_index (u32 LE, not used)
//
// Data shred header (appended after common header at offset 83):
//   Bytes  83 ..  84 = parent_offset (u16 LE, not used)
//   Byte   85        = flags  (bit 0x01 = LAST_SHRED_IN_SLOT)
//   Bytes  86 ..  87 = size   (u16 LE) — absolute end offset of entry data from byte 0
//                              i.e. data = bytes[88..size]
//
// Entry data location (identical for all data shred types — Legacy and all Merkle variants):
//   Bytes 88 .. size = entry data
//
// Shred variant byte (byte 64):
//   0xa5             = LegacyData
//   0x5a             = LegacyCode  (skipped)
//   high nibble 0x8  = MerkleData unchained, unsigned    (0x80–0x8F)
//   high nibble 0x9  = MerkleData chained,   unsigned    (0x90–0x9F) ← current mainnet
//   high nibble 0xa  = MerkleData unchained,  resigned   (0xa0–0xaF, but 0xa5 is LegacyData)
//   high nibble 0xb  = MerkleData chained,    resigned   (0xb0–0xbF)
//   high nibble 0x4–0x7 = MerkleCode (skipped)
//
// Proof entries, chained merkle root, resigned signature are all appended AFTER `size` and
// are therefore invisible to our parser — we just stop at `size`.
// ---------------------------------------------------------------------------

const VARIANT_OFF: usize = 64;
const SLOT_OFF: usize = 65;
const INDEX_OFF: usize = 73;
const FEC_SET_INDEX_OFF: usize = 79; // u32 LE
const FLAGS_OFF: usize = 85;
const SIZE_OFF: usize = 86; // u16 LE: absolute end of entry data (bytes[88..size])
const DATA_OFF: usize = 88; // entry data starts here (same for all data shred types)
const LAST_IN_SLOT_FLAG: u8 = 0x01;
const LEGACY_DATA_VARIANT: u8 = 0xa5;

// Coding shred header fields (after common header at offset 83)
const CODE_NUM_DATA_OFF: usize = 83; // u16 LE: number of data shreds in FEC set
const CODE_NUM_CODE_OFF: usize = 85; // u16 LE: number of coding shreds in FEC set
const CODE_POSITION_OFF: usize = 87; // u16 LE: this coding shred's position (0-based)
const CODE_HDR_END: usize = 89; // minimum length for a coding shred

// Agave Merkle shred fixed buffer size used as the RS symbol width.
// Both data and coding shreds are padded / truncated to this size for RS.
const SHRED_RS_SIZE: usize = 1228;

/// Parse slot, index and fec_set_index from any shred type (code or data).
/// Returns None only if the buffer is shorter than the common header.
fn shred_slot_index(bytes: &[u8]) -> Option<(u64, u32, u32)> {
    if bytes.len() < FEC_SET_INDEX_OFF + 4 {
        return None;
    }
    let slot = u64::from_le_bytes(bytes[SLOT_OFF..SLOT_OFF + 8].try_into().unwrap());
    let index = u32::from_le_bytes(bytes[INDEX_OFF..INDEX_OFF + 4].try_into().unwrap());
    let fec_set_index = u32::from_le_bytes(
        bytes[FEC_SET_INDEX_OFF..FEC_SET_INDEX_OFF + 4].try_into().unwrap(),
    );
    Some((slot, index, fec_set_index))
}

/// Parsed fields from a coding shred header.
struct CodingShredInfo {
    num_data: u16,
    num_coding: u16,
    /// This coding shred's 0-based position within the coding shreds of the FEC set.
    position: u16,
}

/// Parse the coding-shred-specific header fields.
/// Returns None for non-coding shreds, malformed buffers, or zero num_data/num_coding.
fn parse_coding_header(bytes: &[u8]) -> Option<CodingShredInfo> {
    if bytes.len() < CODE_HDR_END {
        return None;
    }
    let variant = bytes[VARIANT_OFF];
    // Coding shreds: high nibble 0x4–0x7 (Merkle variants).
    // 0x5a is LegacyCode — skip; we only handle Merkle coding shreds.
    let high = variant & 0xF0;
    if high != 0x40 && high != 0x50 && high != 0x60 && high != 0x70 {
        return None;
    }
    if variant == 0x5a {
        // LegacyCode — RS layout differs; skip.
        return None;
    }

    let num_data = u16::from_le_bytes([bytes[CODE_NUM_DATA_OFF], bytes[CODE_NUM_DATA_OFF + 1]]);
    let num_coding = u16::from_le_bytes([bytes[CODE_NUM_CODE_OFF], bytes[CODE_NUM_CODE_OFF + 1]]);
    let position = u16::from_le_bytes([bytes[CODE_POSITION_OFF], bytes[CODE_POSITION_OFF + 1]]);

    if num_data == 0 || num_coding == 0 {
        return None;
    }

    Some(CodingShredInfo { num_data, num_coding, position })
}

/// Parse a data shred's entry payload.
/// Returns `(last_in_slot, data_bytes)` for data shreds, `None` for code
/// shreds or malformed payloads.
fn parse_data_payload(bytes: &[u8]) -> Option<(bool, Vec<u8>)> {
    if bytes.len() < DATA_OFF {
        return None;
    }
    let variant = bytes[VARIANT_OFF];

    let is_data = variant == LEGACY_DATA_VARIANT
        || matches!(variant & 0xF0, 0x80 | 0x90 | 0xa0 | 0xb0);
    if !is_data {
        return None;
    }

    let last_in_slot = (bytes[FLAGS_OFF] & LAST_IN_SLOT_FLAG) != 0;

    let size = u16::from_le_bytes([bytes[SIZE_OFF], bytes[SIZE_OFF + 1]]) as usize;
    if size < DATA_OFF || size > bytes.len() {
        return None;
    }

    Some((last_in_slot, bytes[DATA_OFF..size].to_vec()))
}

use crate::receiver::RawShred;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Decoded transaction with timing metadata for the latency pipeline.
pub struct DecodedTx {
    pub transaction: VersionedTransaction,
    pub slot: u64,
    pub shred_recv_ns: u64,
    pub decode_done_ns: u64,
}

// ---------------------------------------------------------------------------
// Per-slot state: accumulate data shred payloads
// ---------------------------------------------------------------------------

struct SlotState {
    /// Data shred payloads keyed by shred index
    data_payloads: HashMap<u32, Vec<u8>>,
    /// Next contiguous index we expect (for streaming deserialization).
    /// Initialised to u32::MAX; set to the first received shred index on
    /// the first call to `set_first_index` so that shred relays starting
    /// mid-block (e.g. DoubleZero, which only sends the tail FEC sets) can
    /// still accumulate a contiguous run without waiting for idx=0.
    next_contiguous: u32,
    /// Accumulated entry bytes from contiguous data shreds
    entry_buf: Vec<u8>,
    /// Bytes already consumed from entry_buf
    consumed: usize,
    /// Highest data shred index seen
    max_index: u32,
    /// Whether we've seen the last shred in slot
    last_seen: bool,
    last_touch_ns: u64,
    /// Number of transactions decoded from this slot
    txs_decoded: u32,
    /// Unique data shreds received (direct + FEC-recovered)
    shreds_seen: u32,
    /// Data shreds reconstructed via Reed-Solomon FEC for this slot
    fec_recovered_count: u32,
    /// Whether this slot has already been counted in slot outcome metrics
    counted: bool,
    /// Whether the first Entry boundary has been located within entry_buf.
    /// When starting mid-stream (shred index > 0), the beginning of entry_buf
    /// may contain the tail of an incomplete Entry from earlier shreds.
    /// We scan forward once to skip past it before normal deserialization.
    boundary_scanned: bool,
}

impl SlotState {
    fn new(now: u64) -> Self {
        Self {
            data_payloads: HashMap::with_capacity(64),
            next_contiguous: u32::MAX, // set on first shred receipt
            entry_buf: Vec::with_capacity(64 * 1024),
            consumed: 0,
            max_index: 0,
            last_seen: false,
            last_touch_ns: now,
            txs_decoded: 0,
            shreds_seen: 0,
            fec_recovered_count: 0,
            counted: false,
            boundary_scanned: false,
        }
    }

    /// Called with the first shred index received for this slot.
    /// Anchors `next_contiguous` so that relay streams starting mid-block
    /// (shred indices > 0) are flushed immediately rather than waiting for
    /// a shred at index 0 that will never arrive.
    fn set_first_index(&mut self, idx: u32) {
        if self.next_contiguous == u32::MAX {
            self.next_contiguous = idx;
            if idx > 0 {
                self.boundary_scanned = false;
            } else {
                self.boundary_scanned = true;
            }
        }
    }

    /// Try to flush contiguous data shred payloads into entry_buf
    fn flush_contiguous(&mut self) {
        while let Some(payload) = self.data_payloads.remove(&self.next_contiguous) {
            self.entry_buf.extend_from_slice(&payload);
            self.next_contiguous += 1;
        }
    }

    /// Try to deserialize entries from accumulated data and extract transactions.
    #[allow(deprecated)]
    fn try_deserialize(&mut self) -> Vec<VersionedTransaction> {
        let mut txs = Vec::new();

        // ── Phase 1: locate the first Entry boundary ────────────────────────
        if !self.boundary_scanned {
            let buf = &self.entry_buf[self.consumed..];
            if buf.len() < 48 {
                return txs;
            }

            let mut found_at: Option<usize> = None;
            for off in 0..buf.len().saturating_sub(47) {
                let tx_count = u64::from_le_bytes(buf[off + 40..off + 48].try_into().unwrap());
                if tx_count > 512 {
                    continue;
                }
                let mut cur = std::io::Cursor::new(&buf[off..]);
                if bincode::deserialize_from::<_, solana_entry::entry::Entry>(&mut cur).is_ok() {
                    found_at = Some(off);
                    break;
                }
            }

            match found_at {
                Some(off) => {
                    self.consumed += off;
                    self.boundary_scanned = true;
                }
                None => {
                    return txs;
                }
            }
        }

        // ── Phase 2: stream-deserialize complete Entries ─────────────────────
        let buf = &self.entry_buf[self.consumed..];
        if buf.is_empty() {
            return txs;
        }
        let mut cursor = std::io::Cursor::new(buf);
        loop {
            let pos_before = cursor.position();
            match bincode::deserialize_from::<_, solana_entry::entry::Entry>(&mut cursor) {
                Ok(entry) => {
                    txs.extend(entry.transactions);
                }
                Err(_) => {
                    cursor.set_position(pos_before);
                    break;
                }
            }
        }
        self.consumed += cursor.position() as usize;
        txs
    }
}

// ---------------------------------------------------------------------------
// FEC set state: buffer shards for Reed-Solomon recovery
// ---------------------------------------------------------------------------

struct FecSet {
    num_data: usize,
    num_coding: usize,
    shards: HashMap<usize, Vec<u8>>,
    recovered: bool,
}

impl FecSet {
    fn new(num_data: usize, num_coding: usize) -> Self {
        Self {
            num_data,
            num_coding,
            shards: HashMap::with_capacity(num_data + num_coding),
            recovered: false,
        }
    }

    fn ready_to_recover(&self) -> bool {
        !self.recovered && self.shards.len() >= self.num_data
    }

    fn reconstruct(&mut self) -> Vec<(usize, Vec<u8>)> {
        self.recovered = true;

        let total = self.num_data + self.num_coding;
        if total == 0 || self.num_data == 0 || self.num_coding == 0 {
            return Vec::new();
        }

        let mut shard_opts: Vec<Option<Vec<u8>>> =
            (0..total).map(|i| self.shards.get(&i).cloned()).collect();

        let missing_data: Vec<usize> =
            (0..self.num_data).filter(|i| !self.shards.contains_key(i)).collect();

        if missing_data.is_empty() {
            return Vec::new();
        }

        let rs = match ReedSolomon::new(self.num_data, self.num_coding) {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!(
                    num_data = self.num_data,
                    num_coding = self.num_coding,
                    err = %e,
                    "FEC: failed to create ReedSolomon instance"
                );
                return Vec::new();
            }
        };

        if let Err(e) = rs.reconstruct(&mut shard_opts) {
            tracing::debug!(
                num_data = self.num_data,
                num_coding = self.num_coding,
                present = self.shards.len(),
                err = %e,
                "FEC: RS reconstruction failed"
            );
            return Vec::new();
        }

        let mut result = Vec::with_capacity(missing_data.len());
        for idx in missing_data {
            if let Some(Some(shard)) = shard_opts.get(idx) {
                result.push((idx, shard.clone()));
            }
        }
        result
    }
}

// ---------------------------------------------------------------------------
// ShredDecoder
// ---------------------------------------------------------------------------

const MAX_ACTIVE_SLOTS: usize = 64;
const SLOT_EXPIRY_DISTANCE: u64 = 32;

pub struct ShredDecoder {
    rx: Receiver<RawShred>,
    tx: Sender<DecodedTx>,
    metrics: Arc<SourceMetrics>,
}

impl ShredDecoder {
    pub fn new(rx: Receiver<RawShred>, tx: Sender<DecodedTx>, metrics: Arc<SourceMetrics>) -> Self {
        Self { rx, tx, metrics }
    }

    pub fn run(&self) -> Result<()> {
        tracing::info!("shred decoder started");

        let mut slots: HashMap<u64, SlotState> = HashMap::with_capacity(MAX_ACTIVE_SLOTS);
        let mut fec_sets: HashMap<u64, HashMap<u32, FecSet>> =
            HashMap::with_capacity(MAX_ACTIVE_SLOTS);
        let mut highest_slot: u64 = 0;

        for raw_shred in &self.rx {
            let decode_start = metrics::now_ns();

            let (slot, shred_index, fec_set_index) = match shred_slot_index(&raw_shred.data) {
                Some(si) => si,
                None => continue,
            };

            if slot > highest_slot {
                highest_slot = slot;
                slots.retain(|&s, state| {
                    if s + SLOT_EXPIRY_DISTANCE >= highest_slot {
                        return true;
                    }
                    if !state.counted {
                        if state.txs_decoded > 0 {
                            self.metrics.slots_partial.fetch_add(1, Relaxed);
                            self.metrics.push_slot_stats(SlotStats {
                                slot: s,
                                shreds_seen: state.shreds_seen,
                                fec_recovered: state.fec_recovered_count,
                                txs_decoded: state.txs_decoded,
                                outcome: SlotOutcome::Partial,
                            });
                        } else {
                            self.metrics.slots_dropped.fetch_add(1, Relaxed);
                            self.metrics.push_slot_stats(SlotStats {
                                slot: s,
                                shreds_seen: state.shreds_seen,
                                fec_recovered: state.fec_recovered_count,
                                txs_decoded: 0,
                                outcome: SlotOutcome::Dropped,
                            });
                        }
                    }
                    false
                });
                fec_sets.retain(|&s, _| s + SLOT_EXPIRY_DISTANCE >= highest_slot);
            }

            if highest_slot.saturating_sub(slot) > SLOT_EXPIRY_DISTANCE {
                continue;
            }

            let now = metrics::now_ns();

            // ── Coding shred path ────────────────────────────────────────────
            if let Some(code_info) = parse_coding_header(&raw_shred.data) {
                let num_data = code_info.num_data as usize;
                let num_coding = code_info.num_coding as usize;
                let code_position = code_info.position as usize;
                let shard_pos = num_data + code_position;

                if code_position >= num_coding {
                    continue;
                }

                let slot_fec = fec_sets.entry(slot).or_default();
                let fec = slot_fec
                    .entry(fec_set_index)
                    .or_insert_with(|| {
                        // Count expected data shreds per FEC set as we discover them.
                        // This is the correct denominator for coverage on tail-only feeds
                        // where the last-in-slot marker rarely arrives.
                        self.metrics
                            .coverage_shreds_expected
                            .fetch_add(num_data as u64, Relaxed);
                        FecSet::new(num_data, num_coding)
                    });

                if fec.num_data != num_data || fec.num_coding != num_coding {
                    continue;
                }

                fec.shards.entry(shard_pos).or_insert_with(|| {
                    let mut buf = raw_shred.data.clone();
                    buf.resize(SHRED_RS_SIZE, 0);
                    buf
                });

                if fec.ready_to_recover() {
                    let recovered = fec.reconstruct();
                    if !recovered.is_empty() {
                        let slot_state = slots.entry(slot).or_insert_with(|| {
                            self.metrics.slots_attempted.fetch_add(1, Relaxed);
                            SlotState::new(now)
                        });
                        slot_state.last_touch_ns = now;

                        let mut recovered_count = 0u64;
                        for (data_shard_idx, shard_bytes) in recovered {
                            let global_idx =
                                fec_set_index.saturating_add(data_shard_idx as u32);
                            if slot_state.data_payloads.contains_key(&global_idx) {
                                continue;
                            }
                            if let Some((last_in_slot, payload)) =
                                parse_data_payload(&shard_bytes)
                            {
                                slot_state.set_first_index(global_idx);
                                if global_idx > slot_state.max_index {
                                    slot_state.max_index = global_idx;
                                }
                                if last_in_slot {
                                    slot_state.last_seen = true;
                                }
                                slot_state.data_payloads.insert(global_idx, payload);
                                recovered_count += 1;
                            }
                        }

                        if recovered_count > 0 {
                            self.metrics
                                .fec_recovered_shreds
                                .fetch_add(recovered_count, Relaxed);
                            self.metrics
                                .coverage_shreds_seen
                                .fetch_add(recovered_count, Relaxed);
                            slot_state.shreds_seen += recovered_count as u32;
                            slot_state.fec_recovered_count += recovered_count as u32;

                            slot_state.flush_contiguous();

                            if slot_state.last_seen
                                && slot_state.next_contiguous > slot_state.max_index
                                && !slot_state.counted
                            {
                                self.metrics.slots_complete.fetch_add(1, Relaxed);
                                slot_state.counted = true;
                                self.metrics.push_slot_stats(SlotStats {
                                    slot,
                                    shreds_seen: slot_state.shreds_seen,
                                    fec_recovered: slot_state.fec_recovered_count,
                                    txs_decoded: slot_state.txs_decoded,
                                    outcome: SlotOutcome::Complete,
                                });
                            }

                            let txs = slot_state.try_deserialize();
                            if !txs.is_empty() {
                                let decode_done = metrics::now_ns();
                                metrics::METRICS.record_stage(
                                    &metrics::METRICS.decode_ns,
                                    decode_done - decode_start,
                                );

                                let tx_count = txs.len() as u32;
                                slot_state.txs_decoded += tx_count;
                                self.metrics.txs_decoded.fetch_add(tx_count as u64, Relaxed);

                                for tx in txs {
                                    let decoded = DecodedTx {
                                        transaction: tx,
                                        slot,
                                        shred_recv_ns: raw_shred.recv_timestamp_ns,
                                        decode_done_ns: decode_done,
                                    };
                                    let _ = self.tx.try_send(decoded);
                                }
                            }
                        }
                    }
                }

                continue;
            }

            // ── Data shred path ──────────────────────────────────────────────
            let (last_in_slot, payload) = match parse_data_payload(&raw_shred.data) {
                Some(d) => d,
                None => continue,
            };

            self.metrics.coverage_shreds_seen.fetch_add(1, Relaxed);

            let state = slots.entry(slot).or_insert_with(|| {
                self.metrics.slots_attempted.fetch_add(1, Relaxed);
                SlotState::new(now)
            });
            state.last_touch_ns = now;

            let data_shard_idx = shred_index.checked_sub(fec_set_index).map(|i| i as usize);
            if let Some(shard_pos) = data_shard_idx {
                let slot_fec = fec_sets.entry(slot).or_default();
                if let Some(fec) = slot_fec.get_mut(&fec_set_index) {
                    fec.shards.entry(shard_pos).or_insert_with(|| {
                        let mut buf = raw_shred.data.clone();
                        buf.resize(SHRED_RS_SIZE, 0);
                        buf
                    });
                }
            }

            state.set_first_index(shred_index);

            if shred_index > state.max_index {
                state.max_index = shred_index;
            }
            if last_in_slot {
                state.last_seen = true;
            }

            if state.data_payloads.insert(shred_index, payload).is_none() {
                state.shreds_seen += 1;
            }
            state.flush_contiguous();

            if state.last_seen && state.next_contiguous > state.max_index && !state.counted {
                self.metrics.slots_complete.fetch_add(1, Relaxed);
                state.counted = true;
                self.metrics.push_slot_stats(SlotStats {
                    slot,
                    shreds_seen: state.shreds_seen,
                    fec_recovered: state.fec_recovered_count,
                    txs_decoded: state.txs_decoded,
                    outcome: SlotOutcome::Complete,
                });
            }

            let txs = state.try_deserialize();
            if !txs.is_empty() {
                let decode_done = metrics::now_ns();
                metrics::METRICS
                    .record_stage(&metrics::METRICS.decode_ns, decode_done - decode_start);

                let tx_count = txs.len() as u32;
                state.txs_decoded += tx_count;
                self.metrics.txs_decoded.fetch_add(tx_count as u64, Relaxed);

                for tx in txs {
                    let decoded = DecodedTx {
                        transaction: tx,
                        slot,
                        shred_recv_ns: raw_shred.recv_timestamp_ns,
                        decode_done_ns: decode_done,
                    };
                    let _ = self.tx.try_send(decoded);
                }
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flush_contiguous_in_order() {
        let mut state = SlotState::new(0);
        state.set_first_index(0);

        state.data_payloads.insert(0, vec![1, 2, 3]);
        state.data_payloads.insert(1, vec![4, 5, 6]);
        state.data_payloads.insert(2, vec![7, 8, 9]);
        state.flush_contiguous();

        assert_eq!(state.entry_buf, vec![1, 2, 3, 4, 5, 6, 7, 8, 9]);
        assert_eq!(state.next_contiguous, 3);
        assert!(state.data_payloads.is_empty());
    }

    #[test]
    fn test_flush_contiguous_out_of_order() {
        let mut state = SlotState::new(0);
        state.set_first_index(0);

        state.data_payloads.insert(2, vec![7, 8, 9]);
        state.flush_contiguous();
        assert!(state.entry_buf.is_empty());
        assert_eq!(state.next_contiguous, 0);

        state.data_payloads.insert(0, vec![1, 2, 3]);
        state.flush_contiguous();
        assert_eq!(state.entry_buf, vec![1, 2, 3]);
        assert_eq!(state.next_contiguous, 1);

        state.data_payloads.insert(1, vec![4, 5, 6]);
        state.flush_contiguous();
        assert_eq!(state.entry_buf, vec![1, 2, 3, 4, 5, 6, 7, 8, 9]);
        assert_eq!(state.next_contiguous, 3);
        assert!(state.data_payloads.is_empty());
    }

    fn make_shred(variant: u8, data: &[u8], last_in_slot: bool) -> Vec<u8> {
        let total = 1228;
        let mut buf = vec![0u8; total];
        buf[VARIANT_OFF] = variant;
        let size_abs = (DATA_OFF + data.len()) as u16;
        buf[SIZE_OFF] = size_abs as u8;
        buf[SIZE_OFF + 1] = (size_abs >> 8) as u8;
        if last_in_slot {
            buf[FLAGS_OFF] = LAST_IN_SLOT_FLAG;
        }
        buf[DATA_OFF..DATA_OFF + data.len()].copy_from_slice(data);
        buf
    }

    #[test]
    fn test_parse_legacy_data() {
        let payload = b"hello world";
        let shred = make_shred(LEGACY_DATA_VARIANT, payload, false);
        let (last, data) = parse_data_payload(&shred).expect("should parse");
        assert!(!last);
        assert_eq!(data, payload);
    }

    #[test]
    fn test_parse_chained_merkle_data() {
        let payload = b"solana entry bytes";
        let shred = make_shred(0x92, payload, true);
        let (last, data) = parse_data_payload(&shred).expect("should parse");
        assert!(last);
        assert_eq!(data, payload);
    }

    #[test]
    fn test_parse_legacy_code_rejected() {
        let shred = make_shred(0x5a, b"", false);
        assert!(parse_data_payload(&shred).is_none());
    }

    #[test]
    fn test_parse_merkle_code_rejected() {
        let shred = make_shred(0x44, b"", false);
        assert!(parse_data_payload(&shred).is_none());
    }

    #[test]
    fn test_parse_too_short() {
        assert!(parse_data_payload(&[0u8; 10]).is_none());
        assert!(parse_data_payload(&[0u8; 87]).is_none());
    }

    #[test]
    fn test_parse_size_beyond_buf() {
        let mut shred = make_shred(0x90, b"data", false);
        shred[SIZE_OFF] = 0x0F;
        shred[SIZE_OFF + 1] = 0x27;
        assert!(parse_data_payload(&shred).is_none());
    }

    #[test]
    fn test_flush_contiguous_mid_stream() {
        let mut state = SlotState::new(0);

        state.set_first_index(1001);
        state.data_payloads.insert(1001, vec![10, 11]);
        state.flush_contiguous();
        assert_eq!(state.entry_buf, vec![10, 11]);
        assert_eq!(state.next_contiguous, 1002);

        state.data_payloads.insert(1000, vec![99]);
        state.flush_contiguous();
        assert_eq!(state.entry_buf, vec![10, 11], "1000 is stale, not flushed");
        assert_eq!(state.next_contiguous, 1002);

        state.data_payloads.insert(1002, vec![20, 21]);
        state.flush_contiguous();
        assert_eq!(state.entry_buf, vec![10, 11, 20, 21]);
        assert_eq!(state.next_contiguous, 1003);
    }

    #[test]
    fn test_complete_detection() {
        let mut state = SlotState::new(0);
        state.set_first_index(0);

        state.max_index = 2;
        state.last_seen = true;

        state.data_payloads.insert(0, vec![1]);
        state.data_payloads.insert(1, vec![2]);
        state.data_payloads.insert(2, vec![3]);
        state.flush_contiguous();

        assert!(state.last_seen);
        assert!(state.next_contiguous > state.max_index);
        assert!(!state.counted);

        if state.last_seen && state.next_contiguous > state.max_index && !state.counted {
            state.counted = true;
        }
        assert!(state.counted);
    }

    fn make_coding_shred(variant: u8, num_data: u16, num_coding: u16, position: u16) -> Vec<u8> {
        let mut buf = vec![0u8; SHRED_RS_SIZE];
        buf[VARIANT_OFF] = variant;
        buf[CODE_NUM_DATA_OFF] = num_data as u8;
        buf[CODE_NUM_DATA_OFF + 1] = (num_data >> 8) as u8;
        buf[CODE_NUM_CODE_OFF] = num_coding as u8;
        buf[CODE_NUM_CODE_OFF + 1] = (num_coding >> 8) as u8;
        buf[CODE_POSITION_OFF] = position as u8;
        buf[CODE_POSITION_OFF + 1] = (position >> 8) as u8;
        buf
    }

    #[test]
    fn test_parse_coding_header_valid() {
        let shred = make_coding_shred(0x64, 32, 32, 5);
        let info = parse_coding_header(&shred).expect("should parse coding header");
        assert_eq!(info.num_data, 32);
        assert_eq!(info.num_coding, 32);
        assert_eq!(info.position, 5);
    }

    #[test]
    fn test_parse_coding_header_rejects_data() {
        let shred = make_shred(0x90, b"hello", false);
        assert!(parse_coding_header(&shred).is_none());
    }

    #[test]
    fn test_parse_coding_header_rejects_legacy_code() {
        let shred = make_coding_shred(0x5a, 16, 16, 0);
        assert!(parse_coding_header(&shred).is_none());
    }

    #[test]
    fn test_parse_coding_header_rejects_zero_counts() {
        let zero_data = make_coding_shred(0x64, 0, 16, 0);
        assert!(parse_coding_header(&zero_data).is_none());
        let zero_coding = make_coding_shred(0x64, 16, 0, 0);
        assert!(parse_coding_header(&zero_coding).is_none());
    }

    #[test]
    fn test_parse_coding_header_too_short() {
        assert!(parse_coding_header(&[0u8; CODE_HDR_END - 1]).is_none());
    }

    #[test]
    fn test_fec_set_reconstruct_recovers_missing_data() {
        use reed_solomon_erasure::galois_8::ReedSolomon;

        const N: usize = 2;
        const M: usize = 2;
        const SZ: usize = 64;

        let mut original: Vec<Vec<u8>> = vec![vec![1u8; SZ], vec![2u8; SZ]];
        let rs = ReedSolomon::new(N, M).unwrap();
        let mut all_shards: Vec<Vec<u8>> = original.clone();
        all_shards.push(vec![0u8; SZ]);
        all_shards.push(vec![0u8; SZ]);
        rs.encode(&mut all_shards).unwrap();

        let mut fec = FecSet::new(N, M);
        fec.shards.insert(0, all_shards[0].clone());
        fec.shards.insert(2, all_shards[2].clone());
        fec.shards.insert(3, all_shards[3].clone());

        assert!(fec.ready_to_recover());

        let recovered = fec.reconstruct();
        assert_eq!(recovered.len(), 1);
        let (idx, bytes) = &recovered[0];
        assert_eq!(*idx, 1);
        assert_eq!(bytes, &original[1]);
    }

    #[test]
    fn test_fec_set_not_ready_when_insufficient_shards() {
        let mut fec = FecSet::new(4, 4);
        fec.shards.insert(4, vec![0u8; SHRED_RS_SIZE]);
        assert!(!fec.ready_to_recover());
    }

    #[test]
    fn test_fec_set_reconstruct_no_missing_data() {
        use reed_solomon_erasure::galois_8::ReedSolomon;

        const N: usize = 2;
        const M: usize = 2;
        const SZ: usize = 64;

        let rs = ReedSolomon::new(N, M).unwrap();
        let mut all_shards: Vec<Vec<u8>> =
            vec![vec![3u8; SZ], vec![4u8; SZ], vec![0u8; SZ], vec![0u8; SZ]];
        rs.encode(&mut all_shards).unwrap();

        let mut fec = FecSet::new(N, M);
        for (i, s) in all_shards.iter().enumerate() {
            fec.shards.insert(i, s.clone());
        }
        let recovered = fec.reconstruct();
        assert!(recovered.is_empty());
    }
}
