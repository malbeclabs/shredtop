//! Shred reassembly and transaction decoding.
//!
//! Accepts raw shreds from `ShredReceiver`, accumulates data shred payloads per slot,
//! flushes contiguous runs into an entry buffer, and deserializes `Entry` structs via
//! wincode to extract `VersionedTransaction`s.
//!
//! FEC (Reed-Solomon erasure) recovery is implemented for Merkle coding shreds.
//! When a FEC set accumulates enough shards (data + coding >= num_data), missing
//! data shreds are reconstructed and inserted into the slot's data_payloads map.

use anyhow::Result;
use crossbeam_channel::{Receiver, Sender};
use reed_solomon_erasure::galois_8::ReedSolomon;
use solana_transaction::versioned::VersionedTransaction;
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;

use crate::metrics;
use crate::source_metrics::{SlotOutcome, SlotStats, SourceMetrics};

/// Upper bound on transactions in one Entry. A larger count means we are not
/// looking at an Entry header.
const MAX_ENTRY_TXS: u64 = 512;

/// Why an Entry could not be read from the front of a buffer.
#[derive(Debug, PartialEq)]
pub(crate) enum EntryError {
    /// The Entry continues past the end of the buffer.
    Truncated,
    /// The bytes are not a readable Entry.
    Malformed,
}

/// Read one `solana_entry::entry::Entry` (num_hashes u64, hash [u8; 32],
/// transaction count u64, transactions) from the front of `buf`.
///
/// Transactions are read with wincode: v1 transactions (SIMD-0385) put the
/// message first and the signatures after it with no length prefix, and only
/// wincode understands that layout. bincode reads legacy and v0 only.
///
/// Returns the transactions and the number of bytes the Entry took.
pub(crate) fn read_entry(buf: &[u8]) -> Result<(Vec<VersionedTransaction>, usize), EntryError> {
    if buf.len() < 48 {
        return Err(EntryError::Truncated);
    }
    let count = u64::from_le_bytes(buf[40..48].try_into().unwrap());
    if count > MAX_ENTRY_TXS {
        return Err(EntryError::Malformed);
    }
    let mut rest = &buf[48..];
    let mut txs = Vec::with_capacity(count as usize);
    for _ in 0..count {
        match wincode::deserialize_from::<VersionedTransaction>(&mut rest) {
            Ok(t) => txs.push(t),
            Err(wincode::ReadError::Io(wincode::io::ReadError::ReadSizeLimit(_))) => {
                return Err(EntryError::Truncated)
            }
            Err(_) => return Err(EntryError::Malformed),
        }
    }
    Ok((txs, buf.len() - rest.len()))
}

/// Read a `Vec<Entry>` as the Jito proxy sends it (u64 count, then Entries).
/// An unreadable Entry is skipped; the Entries after it are still read.
///
/// Returns the transactions and the number of skips.
pub(crate) fn read_entry_batch(buf: &[u8]) -> (Vec<VersionedTransaction>, u64) {
    if buf.is_empty() {
        return (Vec::new(), 0);
    }
    let mut consumed = 0;
    let mut boundary_scanned = true;
    // The whole batch is here, so its end is known up front.
    let mut batch_starts = VecDeque::from([0, buf.len()]);
    let mut skipped = 0;
    let txs = decode_entries(
        buf,
        &mut consumed,
        &mut boundary_scanned,
        &mut batch_starts,
        &mut skipped,
    );
    (txs, skipped)
}

/// Decode the complete Entries in `buf[*consumed..]` and advance `consumed`
/// past them. An Entry cut off at the end of `buf` is left for the next call.
///
/// `buf` is a run of entry batches. Each batch is a u64 Entry count followed
/// by the Entries (a count of 0 marks a block marker instead, which we skip).
/// `batch_starts` holds the known batch offsets in `buf`, in order.
///
/// When `boundary_scanned` is false, `buf[*consumed..]` may start mid-Entry:
/// we joined the slot mid-block, or the Entry there could not be read. Then we
/// wait until the end of the current batch is known and look for the first
/// place from which Entries run back to back to exactly that end (see
/// `find_entry_run`). Each unreadable Entry adds one to `skipped`.
fn decode_entries(
    buf: &[u8],
    consumed: &mut usize,
    boundary_scanned: &mut bool,
    batch_starts: &mut VecDeque<usize>,
    skipped: &mut u64,
) -> Vec<VersionedTransaction> {
    let mut txs = Vec::new();

    loop {
        while batch_starts.front().is_some_and(|&s| s < *consumed) {
            batch_starts.pop_front();
        }

        // ── Phase 1: locate the first Entry boundary ────────────────────────
        if !*boundary_scanned {
            // Scan only a batch we hold in full. With part of it missing, an
            // Entry that has only half arrived looks unreadable, and we would
            // step past it.
            let Some(&batch_end) = batch_starts.front() else {
                return txs;
            };
            // Nothing found: the rest of this batch is lost, but the next
            // batch start is always a boundary.
            *consumed = find_entry_run(buf, *consumed, batch_end).unwrap_or(batch_end);
            *boundary_scanned = true;
        }

        // ── Phase 2: decode complete Entries ────────────────────────────────
        loop {
            if batch_starts.front() == Some(&*consumed) {
                let next = batch_starts.get(1).copied();
                if let Some(next) = next.filter(|&n| n < *consumed + 8) {
                    // Too short to hold its own Entry count: not a real batch.
                    *skipped += 1;
                    *consumed = next;
                    batch_starts.pop_front();
                    continue;
                }
                let Some(count) = buf.get(*consumed..*consumed + 8) else {
                    return txs;
                };
                if u64::from_le_bytes(count.try_into().unwrap()) == 0 {
                    // Block marker, not Entries: skip to the next batch once
                    // we know where it starts.
                    match next {
                        Some(next) => *consumed = next,
                        None => return txs,
                    }
                } else {
                    *consumed += 8;
                }
                batch_starts.pop_front();
                continue;
            }
            let batch_end = batch_starts.front().copied();

            match read_entry(&buf[*consumed..]) {
                Ok((entry_txs, used)) if batch_end.is_none_or(|end| *consumed + used <= end) => {
                    txs.extend(entry_txs);
                    *consumed += used;
                }
                // Entry continues in data we have not received yet.
                Err(EntryError::Truncated) if batch_end.is_none() => return txs,
                // Unreadable, or runs past the end of its batch.
                _ => {
                    *skipped += 1;
                    *boundary_scanned = false;
                    break;
                }
            }
        }
    }
}

/// Find the first offset in `buf[from..end]` from which Entries follow each
/// other back to back and stop exactly at `end`, the end of their batch.
/// Every transaction in them must pass `sanitize`, and the first Entry must
/// carry at least one, since zero-filled bytes read as empty Entries.
///
/// Bytes that merely parse as an Entry, such as one spelled out in some
/// transaction's instruction data, almost never chain to the batch end, so
/// they are not mistaken for real Entries.
fn find_entry_run(buf: &[u8], from: usize, end: usize) -> Option<usize> {
    let region = &buf[from..end];
    // reaches_end[i]: whether a valid Entry run from i stops exactly at the end.
    let mut reaches_end: Vec<Option<bool>> = vec![None; region.len() + 1];
    reaches_end[region.len()] = Some(true);

    (0..region.len())
        .find(|&off| {
            runs_to_end(region, off, &mut reaches_end)
                && read_entry(&region[off..]).is_ok_and(|(txs, _)| !txs.is_empty())
        })
        .map(|off| from + off)
}

/// Follow Entries from `start` and report whether they stop exactly at the
/// end of `region`. Results are cached in `reaches_end`.
fn runs_to_end(region: &[u8], start: usize, reaches_end: &mut [Option<bool>]) -> bool {
    let mut path = Vec::new();
    let mut off = start;
    let result = loop {
        if let Some(known) = reaches_end[off] {
            break known;
        }
        path.push(off);
        match read_entry(&region[off..]) {
            Ok((txs, used)) if txs.iter().all(|t| t.sanitize().is_ok()) => off += used,
            _ => break false,
        }
    };
    for p in path {
        reaches_end[p] = Some(result);
    }
    result
}

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
//   Byte   85        = flags  (bits 0x3F = reference tick,
//                              bit  0x40 = DATA_COMPLETE: last shred of an entry batch,
//                              bits 0xC0 = LAST_SHRED_IN_SLOT, both bits set)
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
                            // Matches Agave `ShredFlags::LAST_SHRED_IN_SLOT`. It includes the DATA_COMPLETE
                            // bit, so both bits must be set; the low 6 bits are the reference tick.
const LAST_IN_SLOT_FLAG: u8 = 0xC0;
const DATA_COMPLETE_FLAG: u8 = 0x40;
const LEGACY_DATA_VARIANT: u8 = 0xa5;

// Coding shred header fields (after common header at offset 83)
const CODE_NUM_DATA_OFF: usize = 83; // u16 LE: number of data shreds in FEC set
const CODE_NUM_CODE_OFF: usize = 85; // u16 LE: number of coding shreds in FEC set
const CODE_POSITION_OFF: usize = 87; // u16 LE: this coding shred's position (0-based)
const CODE_HDR_END: usize = 89; // minimum length for a coding shred

// Merkle shred sizes, as in Agave `shred::merkle`, for finding the erasure
// coded part of a shred (see `erasure_shard`).
const SIGNATURE_SIZE: usize = 64;
const DATA_SHRED_PAYLOAD: usize = 1203;
const CODE_SHRED_PAYLOAD: usize = 1228;
const MERKLE_ROOT_SIZE: usize = 32;
const MERKLE_PROOF_ENTRY_SIZE: usize = 20;

/// Parse slot, index and fec_set_index from any shred type (code or data).
/// Returns None only if the buffer is shorter than the common header.
fn shred_slot_index(bytes: &[u8]) -> Option<(u64, u32, u32)> {
    if bytes.len() < FEC_SET_INDEX_OFF + 4 {
        return None;
    }
    let slot = u64::from_le_bytes(bytes[SLOT_OFF..SLOT_OFF + 8].try_into().unwrap());
    let index = u32::from_le_bytes(bytes[INDEX_OFF..INDEX_OFF + 4].try_into().unwrap());
    let fec_set_index = u32::from_le_bytes(
        bytes[FEC_SET_INDEX_OFF..FEC_SET_INDEX_OFF + 4]
            .try_into()
            .unwrap(),
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

    Some(CodingShredInfo {
        num_data,
        num_coding,
        position,
    })
}

/// Parse a data shred's entry payload.
/// Returns `(last_in_slot, data_bytes)` for data shreds, `None` for code
/// shreds or malformed payloads.
fn parse_data_payload(bytes: &[u8]) -> Option<(bool, Vec<u8>)> {
    if bytes.len() < DATA_OFF {
        return None;
    }
    let variant = bytes[VARIANT_OFF];

    let is_data =
        variant == LEGACY_DATA_VARIANT || matches!(variant & 0xF0, 0x80 | 0x90 | 0xa0 | 0xb0);
    if !is_data {
        return None;
    }

    let last_in_slot = (bytes[FLAGS_OFF] & LAST_IN_SLOT_FLAG) == LAST_IN_SLOT_FLAG;

    let size = u16::from_le_bytes([bytes[SIZE_OFF], bytes[SIZE_OFF + 1]]) as usize;
    if size < DATA_OFF || size > bytes.len() {
        return None;
    }

    Some((last_in_slot, bytes[DATA_OFF..size].to_vec()))
}

/// True when this data shred is the last one of an entry batch, so the next
/// shred starts a new batch.
fn ends_entry_batch(bytes: &[u8]) -> bool {
    bytes.len() > FLAGS_OFF && bytes[FLAGS_OFF] & DATA_COMPLETE_FLAG != 0
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
    /// Index of the shred at the start of entry_buf (u32::MAX until the
    /// first shred arrives).
    first_index: u32,
    /// Accumulated entry bytes from contiguous data shreds
    entry_buf: Vec<u8>,
    /// Bytes already consumed from entry_buf
    consumed: usize,
    /// Highest data shred index seen
    max_index: u32,
    /// Whether we've seen the last shred in slot
    last_seen: bool,
    last_touch_ns: u64,
    /// Earliest kernel receive timestamp (ns) across all shreds in this slot.
    /// Used as the shred-side timestamp for lead-time computation so the
    /// measurement reflects when the first shred data arrived, not when
    /// enough shreds accumulated to trigger deserialization.
    earliest_recv_ns: u64,
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
    /// Indices of received data shreds that end an entry batch.
    batch_ends: HashSet<u32>,
    /// Offsets in entry_buf where an entry batch starts, in order.
    batch_starts: VecDeque<usize>,
    /// Entries skipped since the decoder last reported them to metrics.
    skipped: u64,
    /// The FEC set our first received shred sits in, when that shred is not
    /// the first of its set. Shreds before it may still be rebuilt, so
    /// reading waits until the set is rebuilt or given up.
    hold_for_set: Option<u32>,
    /// Shreds put in front of entry_buf so far (capped).
    prepended: u32,
    /// Shreds rebuilt by FEC whose original has not arrived (yet).
    rebuilt: HashSet<u32>,
}

impl SlotState {
    fn new(now: u64) -> Self {
        Self {
            data_payloads: HashMap::with_capacity(64),
            next_contiguous: u32::MAX, // set on first shred receipt
            first_index: u32::MAX,
            entry_buf: Vec::with_capacity(64 * 1024),
            consumed: 0,
            max_index: 0,
            last_seen: false,
            last_touch_ns: now,
            earliest_recv_ns: u64::MAX,
            txs_decoded: 0,
            shreds_seen: 0,
            fec_recovered_count: 0,
            counted: false,
            boundary_scanned: false,
            batch_ends: HashSet::new(),
            batch_starts: VecDeque::new(),
            skipped: 0,
            hold_for_set: None,
            prepended: 0,
            rebuilt: HashSet::new(),
        }
    }

    /// Called with the first shred index received for this slot.
    /// Anchors `next_contiguous` so that relay streams starting mid-block
    /// (shred indices > 0) are flushed immediately rather than waiting for
    /// a shred at index 0 that will never arrive.
    fn set_first_index(&mut self, idx: u32) {
        if self.next_contiguous == u32::MAX {
            self.next_contiguous = idx;
            self.first_index = idx;
            self.boundary_scanned = idx == 0;
            if idx == 0 {
                self.batch_starts.push_back(0);
            }
        }
    }

    /// Whether data shred `index` is already in this slot: waiting in
    /// data_payloads, or already copied into entry_buf.
    fn has_shred(&self, index: u32) -> bool {
        self.data_payloads.contains_key(&index)
            || (self.first_index..self.next_contiguous).contains(&index)
    }

    /// Add a received or rebuilt data shred. Returns false if the slot
    /// already had it.
    fn add_data_shred(
        &mut self,
        index: u32,
        shred: &[u8],
        last_in_slot: bool,
        payload: Vec<u8>,
    ) -> bool {
        self.set_first_index(index);
        if self.has_shred(index) {
            return false;
        }
        if index < self.first_index && !self.can_prepend() {
            // Too late to put in front of entry_buf: it would never be read.
            return false;
        }
        if index > self.max_index {
            self.max_index = index;
        }
        if last_in_slot {
            self.last_seen = true;
        }
        if ends_entry_batch(shred) {
            self.batch_ends.insert(index);
        }
        self.data_payloads.insert(index, payload);
        self.shreds_seen += 1;
        true
    }

    /// Try to flush contiguous data shred payloads into entry_buf
    fn flush_contiguous(&mut self) {
        self.prepend_earlier();
        while let Some(payload) = self.data_payloads.remove(&self.next_contiguous) {
            self.entry_buf.extend_from_slice(&payload);
            if self.batch_ends.remove(&self.next_contiguous) {
                self.batch_starts.push_back(self.entry_buf.len());
            }
            self.next_contiguous += 1;
        }
    }

    /// Put shreds that come just before the start of entry_buf in front of
    /// it. They show up when the slot's first shreds arrive out of order, or
    /// when FEC rebuilds a shred lost before the first one we received.
    /// Only done while nothing has been read from entry_buf yet.
    fn prepend_earlier(&mut self) {
        while self.can_prepend() && self.first_index > 0 {
            let idx = self.first_index - 1;
            let Some(payload) = self.data_payloads.remove(&idx) else {
                return;
            };
            let n = payload.len();
            self.entry_buf.splice(0..0, payload);
            for start in self.batch_starts.iter_mut() {
                *start += n;
            }
            if self.batch_ends.remove(&idx) {
                // The old front of entry_buf starts a batch.
                self.batch_starts.push_front(n);
            }
            self.first_index = idx;
            self.prepended += 1;
            if self.hold_for_set.is_some_and(|held| idx <= held) {
                // The gap up to the start of the held set is filled: nothing
                // is left for FEC to bring back.
                self.hold_for_set = None;
            }
            if idx == 0 {
                // The slot starts with a batch.
                self.batch_starts.push_front(0);
                self.boundary_scanned = true;
            }
        }
    }

    /// Whether shreds can still go in front of entry_buf: nothing has been
    /// read from it yet, and the cap is not reached. Each prepend moves the
    /// whole buffer, so the cap keeps a hostile sender from making that slow.
    fn can_prepend(&self) -> bool {
        self.consumed == 0
            && !self.boundary_scanned
            && self.prepended < MAX_PREPEND_SHREDS
            && self.entry_buf.len() <= MAX_PREPEND_BYTES
    }

    /// Stop waiting for the FEC set in `hold_for_set` once it is rebuilt or
    /// complete (`set_done`), or once a later set shows up: by then its
    /// coding shreds have had their chance. Returns true if released.
    fn release_hold(&mut self, fec_set_index: u32, set_done: bool) -> bool {
        match self.hold_for_set {
            Some(held) if fec_set_index > held || (fec_set_index == held && set_done) => {
                self.hold_for_set = None;
                true
            }
            _ => false,
        }
    }

    /// Try to deserialize entries from accumulated data and extract transactions.
    fn try_deserialize(&mut self) -> Vec<VersionedTransaction> {
        if self.hold_for_set.is_some() {
            return Vec::new();
        }
        decode_entries(
            &self.entry_buf,
            &mut self.consumed,
            &mut self.boundary_scanned,
            &mut self.batch_starts,
            &mut self.skipped,
        )
    }
}

// ---------------------------------------------------------------------------
// FEC set state: buffer shards for Reed-Solomon recovery
// ---------------------------------------------------------------------------

/// The erasure coded part of a Merkle shred, as Agave codes it: data shreds
/// from just after the signature, coding shreds from just after their
/// headers, both up to the end of the data buffer. The chained Merkle root,
/// the Merkle proof and the retransmitter signature that follow are not
/// coded. Both kinds give the same length within an FEC set.
///
/// Returns None for legacy shreds and for packets too short for their variant.
fn erasure_shard(bytes: &[u8]) -> Option<&[u8]> {
    let variant = *bytes.get(VARIANT_OFF)?;
    let proof_size = usize::from(variant & 0x0F);
    let (start, payload_size, chained, resigned) = match variant & 0xF0 {
        0x40 => (CODE_HDR_END, CODE_SHRED_PAYLOAD, false, false),
        0x60 => (CODE_HDR_END, CODE_SHRED_PAYLOAD, true, false),
        0x70 => (CODE_HDR_END, CODE_SHRED_PAYLOAD, true, true),
        0x80 => (SIGNATURE_SIZE, DATA_SHRED_PAYLOAD, false, false),
        0x90 => (SIGNATURE_SIZE, DATA_SHRED_PAYLOAD, true, false),
        0xb0 => (SIGNATURE_SIZE, DATA_SHRED_PAYLOAD, true, true),
        _ => return None,
    };
    let end = payload_size.checked_sub(
        proof_size * MERKLE_PROOF_ENTRY_SIZE
            + if chained { MERKLE_ROOT_SIZE } else { 0 }
            + if resigned { SIGNATURE_SIZE } else { 0 },
    )?;
    bytes.get(start..end)
}

#[derive(Default)]
struct FecSet {
    /// (num_data, num_coding), from the first coding shred of the set.
    layout: Option<(usize, usize)>,
    /// Erasure shards of data shreds, keyed by (index within the set,
    /// length). A corrupted shred can give a shard of the wrong length, so
    /// copies of different lengths are kept apart, and the rebuild uses the
    /// length most shards agree on.
    data: HashMap<(usize, usize), Vec<u8>>,
    /// Erasure shards of coding shreds, keyed by (position, length).
    coding: HashMap<(usize, usize), Vec<u8>>,
    /// Recovery ran, or every data shred arrived: nothing left to do.
    done: bool,
    /// Per shard length: (data shards inside the set, coding shards). Kept
    /// up to date as shards arrive, so checking a set costs the same however
    /// many shards it holds.
    counts: HashMap<usize, (usize, usize)>,
}

impl FecSet {
    /// Set the layout from the first coding shred, and count data shards
    /// that arrived before it against it.
    fn set_layout(&mut self, num_data: usize, num_coding: usize) {
        self.layout = Some((num_data, num_coding));
        for count in self.counts.values_mut() {
            count.0 = 0;
        }
        for &(i, len) in self.data.keys() {
            if i < num_data {
                self.counts.entry(len).or_default().0 += 1;
            }
        }
    }

    /// Whether the set may keep one more shard. A real set holds at most
    /// MAX_SET_SHARDS; room for a few times that leaves space for corrupted
    /// copies without letting a hostile sender grow it without end.
    fn has_room(&self) -> bool {
        self.data.len() + self.coding.len() < 4 * MAX_SET_SHARDS
    }

    /// Keep the erasure shard of the data shred at `i` within the set.
    /// Indices past what one set can hold are not kept.
    fn add_data(&mut self, i: usize, shard: &[u8]) {
        if self.done || i >= MAX_SET_SHARDS || !self.has_room() {
            return;
        }
        let key = (i, shard.len());
        if self.data.contains_key(&key) {
            return;
        }
        self.data.insert(key, shard.to_vec());
        if self.layout.is_none_or(|(num_data, _)| i < num_data) {
            self.counts.entry(shard.len()).or_default().0 += 1;
        }
    }

    /// Keep the erasure shard of the coding shred at `position`.
    fn add_coding(&mut self, position: usize, shard: &[u8]) {
        if self.done || !self.has_room() {
            return;
        }
        let key = (position, shard.len());
        if self.coding.contains_key(&key) {
            return;
        }
        self.coding.insert(key, shard.to_vec());
        self.counts.entry(shard.len()).or_default().1 += 1;
    }

    /// The shard length most shards agree on, with how many data shreds
    /// (inside the set) and coding shreds have it.
    fn best_length(&self) -> Option<(usize, usize, usize)> {
        self.counts
            .iter()
            .max_by_key(|&(&len, &(d, c))| (d + c, len))
            .map(|(&len, &(d, c))| (len, d, c))
    }

    /// A data shred is missing and enough shards arrived to rebuild it.
    fn ready_to_recover(&mut self) -> bool {
        let Some((num_data, _)) = self.layout else {
            return false;
        };
        if self.done {
            return false;
        }
        let Some((_, have_data, have_coding)) = self.best_length() else {
            return false;
        };
        if have_data >= num_data {
            // Nothing to recover: free the shards.
            self.finish();
            return false;
        }
        have_data + have_coding >= num_data
    }

    fn finish(&mut self) {
        self.done = true;
        self.data = HashMap::new();
        self.coding = HashMap::new();
        self.counts = HashMap::new();
    }

    /// Rebuild the missing data shreds. Returns (index within the set, shred
    /// bytes) for each, with the signature zeroed: the rest of the shred
    /// parses like a received one.
    fn reconstruct(&mut self) -> Vec<(usize, Vec<u8>)> {
        let Some((num_data, num_coding)) = self.layout else {
            return Vec::new();
        };
        let Some((len, _, _)) = self.best_length() else {
            return Vec::new();
        };
        let mut shards: Vec<Option<Vec<u8>>> = (0..num_data)
            .map(|i| self.data.remove(&(i, len)))
            .chain((0..num_coding).map(|i| self.coding.remove(&(i, len))))
            .collect();
        self.finish();

        let missing: Vec<usize> = (0..num_data).filter(|&i| shards[i].is_none()).collect();
        if missing.is_empty() {
            return Vec::new();
        }

        let rs = match ReedSolomon::new(num_data, num_coding) {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!(num_data, num_coding, err = %e, "FEC: bad set layout");
                return Vec::new();
            }
        };
        if let Err(e) = rs.reconstruct_data(&mut shards) {
            tracing::debug!(num_data, num_coding, err = %e, "FEC: RS reconstruction failed");
            return Vec::new();
        }

        missing
            .into_iter()
            .filter_map(|i| {
                let shard = shards[i].take()?;
                let mut shred = vec![0u8; SIGNATURE_SIZE];
                shred.extend_from_slice(&shard);
                Some((i, shred))
            })
            .collect()
    }
}

/// Drop FEC sets of expired slots, and sets that got no coding shred within
/// FEC_WAIT_SLOTS: a feed that sends none would otherwise fill memory with
/// data shards.
fn prune_fec_sets(fec_sets: &mut HashMap<u64, HashMap<u32, FecSet>>, highest_slot: u64) {
    fec_sets.retain(|&s, sets| {
        if s + FEC_WAIT_SLOTS < highest_slot {
            sets.retain(|_, fec| fec.layout.is_some());
        }
        s + SLOT_EXPIRY_DISTANCE >= highest_slot
    });
}

// ---------------------------------------------------------------------------
// ShredDecoder
// ---------------------------------------------------------------------------

const MAX_ACTIVE_SLOTS: usize = 64;
const SLOT_EXPIRY_DISTANCE: u64 = 32;
/// Slots an FEC set's data shards wait for its first coding shred.
const FEC_WAIT_SLOTS: u64 = 2;
/// Reed-Solomon over GF(2^8) handles at most 256 shards per FEC set.
const MAX_SET_SHARDS: usize = 256;
/// Most shreds a slot may put in front of its buffer (see `can_prepend`).
const MAX_PREPEND_SHREDS: u32 = 256;
/// No prepends once a slot's buffer is this big (see `can_prepend`).
const MAX_PREPEND_BYTES: usize = 1 << 20;

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
        // Whether this feed sends coding shreds at all.
        let mut seen_coding = false;
        // Slots waiting for FEC (see `SlotState::hold_for_set`), lowest first.
        let mut held_slots: BTreeSet<u64> = BTreeSet::new();

        for raw_shred in &self.rx {
            let decode_start = metrics::now_ns();

            let (slot, shred_index, fec_set_index) = match shred_slot_index(&raw_shred.data) {
                Some(si) => si,
                None => continue,
            };

            // Guard against corrupted shreds with garbage slot values.
            // A jump larger than MAX_SLOT_JUMP would poison highest_slot and
            // cause all subsequent real shreds to fail the expiry check below,
            // silently dropping all output until restart.
            //
            // Exception: highest_slot == 0 means we haven't seen any valid shred yet.
            // The first real shred sets the baseline regardless of slot distance
            // (mainnet slots are ~350_000_000, which exceeds MAX_SLOT_JUMP from 0).
            const MAX_SLOT_JUMP: u64 = 1000;
            if slot > highest_slot
                && (highest_slot == 0 || slot.saturating_sub(highest_slot) <= MAX_SLOT_JUMP)
            {
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
                prune_fec_sets(&mut fec_sets, highest_slot);
            }

            if highest_slot.saturating_sub(slot) > SLOT_EXPIRY_DISTANCE {
                continue;
            }

            let now = metrics::now_ns();
            let recv_ns = raw_shred.recv_timestamp_ns;

            // A shred from a newer slot: older slots stop waiting for FEC.
            while let Some(s) = held_slots.first().copied().filter(|&s| s < slot) {
                held_slots.remove(&s);
                if let Some(state) = slots.get_mut(&s) {
                    if state.hold_for_set.take().is_some() {
                        state.flush_contiguous();
                        self.decode_slot(state, s, decode_start);
                    }
                }
            }

            // ── Coding shred path ────────────────────────────────────────────
            if let Some(code_info) = parse_coding_header(&raw_shred.data) {
                let num_data = code_info.num_data as usize;
                let num_coding = code_info.num_coding as usize;
                let position = code_info.position as usize;
                if position >= num_coding || num_data + num_coding > MAX_SET_SHARDS {
                    continue;
                }
                let Some(shard) = erasure_shard(&raw_shred.data) else {
                    continue;
                };
                seen_coding = true;

                let fec = fec_sets
                    .entry(slot)
                    .or_default()
                    .entry(fec_set_index)
                    .or_default();
                match fec.layout {
                    None => {
                        // Count expected data shreds per FEC set as we discover
                        // them. This is the correct denominator for coverage on
                        // tail-only feeds where the last-in-slot marker rarely
                        // arrives.
                        self.metrics
                            .coverage_shreds_expected
                            .fetch_add(num_data as u64, Relaxed);
                        fec.set_layout(num_data, num_coding);
                    }
                    Some(layout) if layout != (num_data, num_coding) => continue,
                    Some(_) => {}
                }
                fec.add_coding(position, shard);
                let recovered = if fec.ready_to_recover() {
                    fec.reconstruct()
                } else {
                    Vec::new()
                };
                let set_done = fec.done;
                let state = if recovered.is_empty() {
                    slots.get_mut(&slot)
                } else {
                    Some(self.slot_state(&mut slots, slot, now, recv_ns))
                };
                if let Some(state) = state {
                    let added = self.insert_recovered(state, slot, fec_set_index, recovered);
                    let released = state.release_hold(fec_set_index, set_done);
                    if added || released {
                        state.flush_contiguous();
                        self.decode_slot(state, slot, decode_start);
                    }
                }
                continue;
            }

            // ── Data shred path ──────────────────────────────────────────────
            let (last_in_slot, payload) = match parse_data_payload(&raw_shred.data) {
                Some(d) => d,
                None => continue,
            };

            // Keep the erasure shard: with the coding shreds it can rebuild
            // a data shred lost on the way.
            let shard = erasure_shard(&raw_shred.data);
            let fec = fec_sets
                .entry(slot)
                .or_default()
                .entry(fec_set_index)
                .or_default();
            if let (Some(i), Some(shard)) = (shred_index.checked_sub(fec_set_index), shard) {
                fec.add_data(i as usize, shard);
            }
            let recovered = if fec.ready_to_recover() {
                fec.reconstruct()
            } else {
                Vec::new()
            };
            let set_done = fec.done;

            let state = self.slot_state(&mut slots, slot, now, recv_ns);
            let first_in_slot = state.next_contiguous == u32::MAX;
            let mut changed = false;
            if state.add_data_shred(shred_index, &raw_shred.data, last_in_slot, payload) {
                self.metrics.coverage_shreds_seen.fetch_add(1, Relaxed);
                changed = true;
            } else if state.rebuilt.remove(&shred_index) {
                // The original came after all: it was late, not lost.
                state.fec_recovered_count -= 1;
                self.metrics.fec_recovered_shreds.fetch_sub(1, Relaxed);
                if state.counted {
                    self.metrics.unrecover_logged(slot);
                }
            }
            if seen_coding
                && first_in_slot
                && shred_index > fec_set_index
                && shard.is_some()
                && !set_done
            {
                // We start inside an FEC set: FEC may still rebuild the
                // shreds before this one, so wait before reading. Only on a
                // feed that sends coding shreds: without them, waiting only
                // delays the slot.
                state.hold_for_set = Some(fec_set_index);
                held_slots.insert(slot);
            }
            // Add the received shred and the rebuilt ones before reading, so
            // the first read already sees them all.
            changed |= self.insert_recovered(state, slot, fec_set_index, recovered);
            changed |= state.release_hold(fec_set_index, set_done);
            if changed {
                state.flush_contiguous();
                self.decode_slot(state, slot, decode_start);
            }
        }

        Ok(())
    }

    /// The slot's state, created on its first shred.
    fn slot_state<'a>(
        &self,
        slots: &'a mut HashMap<u64, SlotState>,
        slot: u64,
        now: u64,
        recv_ns: u64,
    ) -> &'a mut SlotState {
        let state = slots.entry(slot).or_insert_with(|| {
            self.metrics.slots_attempted.fetch_add(1, Relaxed);
            SlotState::new(now)
        });
        state.last_touch_ns = now;
        if recv_ns < state.earliest_recv_ns {
            state.earliest_recv_ns = recv_ns;
        }
        state
    }

    /// Add data shreds rebuilt by FEC to their slot. Returns true if any
    /// was added; the caller flushes and decodes.
    fn insert_recovered(
        &self,
        state: &mut SlotState,
        slot: u64,
        fec_set_index: u32,
        recovered: Vec<(usize, Vec<u8>)>,
    ) -> bool {
        let mut recovered_count = 0u32;
        for (i, shred) in recovered {
            let index = fec_set_index.saturating_add(i as u32);
            // Rebuilt shreds are not checked against the Merkle root. A
            // corrupted shard makes RS output garbage, so at least require
            // the header to say what the shred must be.
            if shred_slot_index(&shred) != Some((slot, index, fec_set_index)) {
                continue;
            }
            let Some((last_in_slot, payload)) = parse_data_payload(&shred) else {
                continue;
            };
            if state.add_data_shred(index, &shred, last_in_slot, payload) {
                state.rebuilt.insert(index);
                recovered_count += 1;
            }
        }
        if recovered_count == 0 {
            return false;
        }

        self.metrics
            .fec_recovered_shreds
            .fetch_add(u64::from(recovered_count), Relaxed);
        self.metrics
            .coverage_shreds_seen
            .fetch_add(u64::from(recovered_count), Relaxed);
        state.fec_recovered_count += recovered_count;
        true
    }

    /// After new data reached a slot: count it as complete once every shred
    /// is in, then decode what can be decoded and send it on.
    fn decode_slot(&self, state: &mut SlotState, slot: u64, decode_start: u64) {
        let txs = state.try_deserialize();
        self.metrics
            .entries_skipped
            .fetch_add(std::mem::take(&mut state.skipped), Relaxed);
        if !txs.is_empty() {
            let decode_done = metrics::now_ns();
            metrics::METRICS.record_stage(&metrics::METRICS.decode_ns, decode_done - decode_start);

            let tx_count = txs.len() as u32;
            state.txs_decoded += tx_count;
            self.metrics.txs_decoded.fetch_add(tx_count as u64, Relaxed);

            for tx in txs {
                let decoded = DecodedTx {
                    transaction: tx,
                    slot,
                    shred_recv_ns: state.earliest_recv_ns,
                    decode_done_ns: decode_done,
                };
                if self.tx.try_send(decoded).is_err() {
                    self.metrics.txs_dropped.fetch_add(1, Relaxed);
                }
            }
        }

        // Count the slot complete after reading, so its stats include the
        // transactions of its last shreds. A held slot has read nothing yet.
        if state.hold_for_set.is_none()
            && state.last_seen
            && state.next_contiguous > state.max_index
            && !state.counted
        {
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
        // Odd reference tick in the low bits, like real shreds carry.
        buf[FLAGS_OFF] = 0x05;
        if last_in_slot {
            buf[FLAGS_OFF] |= LAST_IN_SLOT_FLAG;
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
    fn test_parse_odd_reference_tick_not_last() {
        let mut shred = make_shred(0x92, b"entry", false);
        // Reference tick 1: bit 0x01 set, but not the last shred in the slot.
        shred[FLAGS_OFF] = 0x01;
        let (last, _) = parse_data_payload(&shred).expect("should parse");
        assert!(!last);
        // DATA_COMPLETE alone (end of an entry batch) is not last either.
        shred[FLAGS_OFF] = DATA_COMPLETE_FLAG | 0x3F;
        let (last, _) = parse_data_payload(&shred).expect("should parse");
        assert!(!last);
        shred[FLAGS_OFF] = LAST_IN_SLOT_FLAG | 0x01;
        let (last, _) = parse_data_payload(&shred).expect("should parse");
        assert!(last);
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

        // Nothing read yet, so an earlier shred goes in front.
        state.data_payloads.insert(1000, vec![99]);
        state.flush_contiguous();
        assert_eq!(state.entry_buf, vec![99, 10, 11]);
        assert_eq!(state.next_contiguous, 1002);

        state.data_payloads.insert(1002, vec![20, 21]);
        state.flush_contiguous();
        assert_eq!(state.entry_buf, vec![99, 10, 11, 20, 21]);
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
        let mut buf = vec![0u8; CODE_SHRED_PAYLOAD];
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

    /// A set with `n` data and `m` coding shards of `sz` bytes, encoded.
    fn encoded_shards(n: usize, m: usize, sz: usize) -> Vec<Vec<u8>> {
        let mut shards: Vec<Vec<u8>> = (0..n + m).map(|i| vec![i as u8 + 1; sz]).collect();
        ReedSolomon::new(n, m).unwrap().encode(&mut shards).unwrap();
        shards
    }

    #[test]
    fn test_fec_set_reconstruct_recovers_missing_data() {
        let all = encoded_shards(2, 2, 64);
        let mut fec = FecSet::default();
        fec.set_layout(2, 2);
        fec.add_data(0, &all[0]);
        fec.add_coding(1, &all[3]);
        assert!(fec.ready_to_recover());

        let recovered = fec.reconstruct();
        assert_eq!(recovered.len(), 1);
        let (idx, shred) = &recovered[0];
        assert_eq!(*idx, 1);
        // Zeroed signature, then the rebuilt shard.
        assert_eq!(&shred[..SIGNATURE_SIZE], &[0u8; SIGNATURE_SIZE]);
        assert_eq!(&shred[SIGNATURE_SIZE..], all[1].as_slice());
        assert!(fec.done);
        assert!(!fec.ready_to_recover());
    }

    #[test]
    fn test_fec_set_not_ready_when_insufficient_shards() {
        let mut fec = FecSet::default();
        fec.add_data(0, &[0u8; 8]);
        fec.add_data(1, &[0u8; 8]);
        // No coding shred yet, so the layout is unknown.
        assert!(!fec.ready_to_recover());
        fec.set_layout(4, 4);
        fec.add_coding(0, &[0u8; 8]);
        assert!(!fec.ready_to_recover());
        fec.add_coding(1, &[0u8; 8]);
        assert!(fec.ready_to_recover());
    }

    #[test]
    fn test_fec_set_with_all_data_frees_shards() {
        let all = encoded_shards(2, 2, 64);
        let mut fec = FecSet::default();
        fec.set_layout(2, 2);
        fec.add_data(0, &all[0]);
        fec.add_data(1, &all[1]);
        fec.add_coding(0, &all[2]);
        assert!(!fec.ready_to_recover());
        assert!(fec.done);
        assert!(fec.data.is_empty() && fec.coding.is_empty());
    }

    #[test]
    fn test_fec_set_rebuilds_with_the_length_most_shards_agree_on() {
        // A wrong-length coding shard arrives first, and a wrong-length
        // copy of data shard 0 before its good copy. The rebuild uses the
        // length the other shards share.
        let all = encoded_shards(3, 3, 64);
        let mut fec = FecSet::default();
        fec.set_layout(3, 3);
        fec.add_coding(0, &[9u8; 40]);
        fec.add_data(0, &[9u8; 40]);
        fec.add_data(0, &all[0]);
        fec.add_coding(1, &all[4]);
        assert!(!fec.ready_to_recover());
        fec.add_coding(2, &all[5]);
        assert!(fec.ready_to_recover());
        let mut got = fec.reconstruct();
        got.sort();
        assert_eq!(got.len(), 2);
        assert_eq!(&got[0].1[SIGNATURE_SIZE..], all[1].as_slice());
        assert_eq!(&got[1].1[SIGNATURE_SIZE..], all[2].as_slice());
    }

    #[test]
    fn test_erasure_shard_ranges_match_agave() {
        // Chained data (0x9_) and coding (0x6_) shreds in one set give shards
        // of the same length: data from byte 64, coding from byte 89, up to
        // the chained root.
        for (data_variant, code_variant, resigned) in [(0x96, 0x66, false), (0xb6, 0x76, true)] {
            let data = vec![0u8; DATA_SHRED_PAYLOAD];
            let mut d = data.clone();
            d[VARIANT_OFF] = data_variant;
            let mut c = vec![0u8; CODE_SHRED_PAYLOAD];
            c[VARIANT_OFF] = code_variant;
            let ds = erasure_shard(&d).unwrap();
            let cs = erasure_shard(&c).unwrap();
            let tail =
                MERKLE_ROOT_SIZE + 6 * MERKLE_PROOF_ENTRY_SIZE + if resigned { 64 } else { 0 };
            assert_eq!(ds.len(), DATA_SHRED_PAYLOAD - SIGNATURE_SIZE - tail);
            assert_eq!(cs.len(), CODE_SHRED_PAYLOAD - CODE_HDR_END - tail);
            assert_eq!(ds.len(), cs.len());
            // The data shard starts at the variant byte.
            assert_eq!(ds[0], data_variant);
        }
        let mut legacy = vec![0u8; CODE_SHRED_PAYLOAD];
        legacy[VARIANT_OFF] = LEGACY_DATA_VARIANT;
        assert!(erasure_shard(&legacy).is_none());
        let mut short = vec![0u8; 500];
        short[VARIANT_OFF] = 0x96;
        assert!(erasure_shard(&short).is_none());
    }

    #[test]
    fn test_highest_slot_not_poisoned_by_garbage() {
        // Reproduces the production bug: a single shred with slot=u64::MAX would
        // set highest_slot to u64::MAX, causing every subsequent real shred to
        // fail the expiry check and be silently dropped forever.
        const MAX_SLOT_JUMP: u64 = 1000;

        let mut highest_slot: u64 = 100;

        // Simulate a corrupted shred with a garbage slot value.
        let garbage_slot = u64::MAX;
        if garbage_slot > highest_slot && garbage_slot.saturating_sub(highest_slot) <= MAX_SLOT_JUMP
        {
            highest_slot = garbage_slot;
        }
        assert_eq!(
            highest_slot, 100,
            "garbage slot must not poison highest_slot"
        );

        // Normal slot progression must still work after the bad shred.
        let next_slot = 102u64;
        if next_slot > highest_slot && next_slot.saturating_sub(highest_slot) <= MAX_SLOT_JUMP {
            highest_slot = next_slot;
        }
        assert_eq!(highest_slot, 102);
    }

    use solana_message::compiled_instruction::CompiledInstruction;
    use solana_message::{v0, v1, Address, Hash, Message, MessageHeader, VersionedMessage};
    use solana_signature::Signature;

    fn tx(seed: u8, message: VersionedMessage) -> VersionedTransaction {
        VersionedTransaction {
            signatures: vec![Signature::from([seed; 64])],
            message,
        }
    }

    /// Wire bytes of one Entry holding `txs`, written field by field.
    fn entry_bytes(txs: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&1u64.to_le_bytes()); // num_hashes
        out.extend_from_slice(&[0u8; 32]); // hash
        out.extend_from_slice(&(txs.len() as u64).to_le_bytes());
        for t in txs {
            out.extend_from_slice(t);
        }
        out
    }

    /// Wire bytes of one entry batch: the Entry count, then the Entries.
    fn batch(entries: &[Vec<u8>]) -> Vec<u8> {
        let mut out = (entries.len() as u64).to_le_bytes().to_vec();
        for e in entries {
            out.extend_from_slice(e);
        }
        out
    }

    /// One signer that pays the fee, plus a program account.
    fn one_signer() -> MessageHeader {
        MessageHeader {
            num_required_signatures: 1,
            num_readonly_signed_accounts: 0,
            num_readonly_unsigned_accounts: 1,
        }
    }

    /// A legacy message that passes `sanitize`, with one instruction carrying `data`.
    fn legacy_message(seed: u8, data: Vec<u8>) -> Message {
        Message {
            header: one_signer(),
            account_keys: vec![
                Address::new_from_array([seed; 32]),
                Address::new_from_array([seed ^ 0xff; 32]),
            ],
            recent_blockhash: Hash::new_from_array([seed; 32]),
            instructions: vec![CompiledInstruction {
                program_id_index: 1,
                accounts: vec![0],
                data,
            }],
        }
    }

    fn legacy_tx_bytes(seed: u8) -> Vec<u8> {
        let message = VersionedMessage::Legacy(legacy_message(seed, vec![seed]));
        wincode::serialize(&tx(seed, message)).unwrap()
    }

    fn v0_tx_bytes(seed: u8) -> Vec<u8> {
        let message = VersionedMessage::V0(v0::Message {
            header: one_signer(),
            account_keys: vec![
                Address::new_from_array([seed; 32]),
                Address::new_from_array([seed ^ 0xff; 32]),
            ],
            recent_blockhash: Hash::new_from_array([seed; 32]),
            ..v0::Message::default()
        });
        wincode::serialize(&tx(seed, message)).unwrap()
    }

    /// A transaction with an unknown message version (prefix 0xff). It cannot
    /// be read no matter how many more shreds arrive.
    fn bad_tx_bytes() -> Vec<u8> {
        let mut out = vec![1u8]; // one signature (short_vec)
        out.extend_from_slice(&[0xaa; 64]);
        out.push(0xff);
        out.extend_from_slice(&[0x11; 40]);
        out
    }

    /// A slot that starts at shred 0 with `buf` already flushed.
    fn slot_with(buf: Vec<u8>) -> SlotState {
        let mut s = SlotState::new(0);
        s.set_first_index(0);
        s.entry_buf = buf;
        s
    }

    fn sigs(txs: &[VersionedTransaction]) -> Vec<u8> {
        txs.iter()
            .map(|t| <[u8; 64]>::from(t.signatures[0])[0])
            .collect()
    }

    /// A v1 message with one signer, as the network sends it.
    fn v1_message(seed: u8) -> v1::Message {
        v1::Message {
            header: MessageHeader {
                num_required_signatures: 1,
                num_readonly_signed_accounts: 0,
                num_readonly_unsigned_accounts: 0,
            },
            config: v1::TransactionConfig::default(),
            lifetime_specifier: Hash::new_from_array([seed; 32]),
            account_keys: vec![Address::new_from_array([seed; 32])],
            instructions: vec![],
        }
    }

    /// SIMD-0385 wire layout of a v1 transaction: the message (starting with
    /// the 0x81 version byte), then the signatures with no length prefix.
    fn v1_tx_bytes(seed: u8) -> Vec<u8> {
        let mut out = v1_message(seed).serialize();
        out.extend_from_slice(&[seed; 64]);
        out
    }

    #[test]
    fn test_test_transactions_pass_sanitize() {
        for bytes in [legacy_tx_bytes(1), v0_tx_bytes(2), v1_tx_bytes(3)] {
            let t: VersionedTransaction = wincode::deserialize(&bytes).unwrap();
            assert_eq!(t.sanitize(), Ok(()));
        }
    }

    #[test]
    fn test_v1_wire_layout_matches_wincode() {
        let bytes = v1_tx_bytes(9);
        assert_eq!(bytes[0], 0x81);
        let t = tx(9, VersionedMessage::V1(v1_message(9)));
        assert_eq!(wincode::serialize(&t).unwrap(), bytes);
    }

    #[test]
    fn test_v1_transaction_decodes_between_legacy_entries() {
        let mut s = slot_with(batch(&[
            entry_bytes(&[legacy_tx_bytes(1)]),
            entry_bytes(&[v1_tx_bytes(9)]),
            entry_bytes(&[legacy_tx_bytes(2)]),
        ]));
        let txs = s.try_deserialize();
        assert_eq!(s.consumed, s.entry_buf.len());
        assert_eq!(sigs(&txs), vec![1, 9, 2]);
        assert!(matches!(txs[1].message, VersionedMessage::V1(_)));
    }

    #[test]
    fn test_every_cut_reads_as_truncated() {
        for tx_bytes in [legacy_tx_bytes(1), v0_tx_bytes(2), v1_tx_bytes(3)] {
            let entry = entry_bytes(&[tx_bytes]);
            for cut in 0..entry.len() {
                assert_eq!(read_entry(&entry[..cut]), Err(EntryError::Truncated));
            }
            let (txs, used) = read_entry(&entry).unwrap();
            assert_eq!(txs.len(), 1);
            assert_eq!(used, entry.len());
        }
    }

    #[test]
    fn test_cut_off_v1_transaction_waits_for_more_shreds() {
        let first = entry_bytes(&[legacy_tx_bytes(1)]);
        let full = batch(&[first.clone(), entry_bytes(&[v1_tx_bytes(9)])]);
        let first_end = 8 + first.len();

        for cut in first_end + 1..full.len() {
            let mut s = slot_with(full[..cut].to_vec());
            assert_eq!(sigs(&s.try_deserialize()), vec![1]);
            assert_eq!(s.consumed, first_end);

            s.entry_buf.extend_from_slice(&full[cut..]);
            assert_eq!(sigs(&s.try_deserialize()), vec![9]);
            assert_eq!(s.consumed, full.len());
        }
    }

    #[test]
    fn test_batches_split_across_shreds() {
        // Real shred layout: each entry batch starts with its Entry count, a
        // batch can span shreds, and the shred ending a batch says so. A count
        // of 0 marks a block marker, which carries no Entries.
        let batch1 = batch(&[
            entry_bytes(&[legacy_tx_bytes(1), v0_tx_bytes(2)]),
            entry_bytes(&[v1_tx_bytes(3)]),
        ]);
        let mut marker = 0u64.to_le_bytes().to_vec();
        marker.extend_from_slice(&[0x5a; 50]);
        let batch2 = batch(&[entry_bytes(&[v1_tx_bytes(4)])]);

        let cut = 30; // inside the first Entry of batch 1
        let shreds: Vec<(Vec<u8>, bool)> = vec![
            (batch1[..cut].to_vec(), false),
            (batch1[cut..].to_vec(), true),
            (marker, true),
            (batch2, true),
        ];

        let mut s = SlotState::new(0);
        s.set_first_index(0);
        let mut got = Vec::new();
        for (idx, (payload, ends_batch)) in shreds.into_iter().enumerate() {
            s.data_payloads.insert(idx as u32, payload);
            if ends_batch {
                s.batch_ends.insert(idx as u32);
            }
            s.flush_contiguous();
            got.extend(s.try_deserialize());
        }
        assert_eq!(sigs(&got), vec![1, 2, 3, 4]);
        assert_eq!(s.consumed, s.entry_buf.len());
    }

    #[test]
    fn test_mid_slot_start_with_v1() {
        // Relays may start mid-block: the buffer opens with the tail of an
        // Entry whose start we never saw.
        let lost = entry_bytes(&[legacy_tx_bytes(7)]);
        let mut buf = lost[lost.len() / 2..].to_vec();
        buf.extend(entry_bytes(&[legacy_tx_bytes(1)]));
        buf.extend(entry_bytes(&[v1_tx_bytes(9)]));

        let mut s = SlotState::new(0);
        s.set_first_index(5);
        s.entry_buf = buf;
        // The batch end is not known yet, so nothing is scanned.
        assert!(s.try_deserialize().is_empty());
        s.batch_starts.push_back(s.entry_buf.len());
        assert_eq!(sigs(&s.try_deserialize()), vec![1, 9]);
        assert_eq!(s.skipped, 0);
    }

    #[test]
    fn test_unreadable_entry_does_not_drop_rest_of_slot() {
        let mut s = slot_with(batch(&[
            entry_bytes(&[legacy_tx_bytes(1)]),
            entry_bytes(&[bad_tx_bytes()]),
            entry_bytes(&[legacy_tx_bytes(2)]),
        ]));
        // The scan past the bad Entry waits for the end of its batch.
        assert_eq!(sigs(&s.try_deserialize()), vec![1]);
        s.batch_starts.push_back(s.entry_buf.len());
        assert_eq!(sigs(&s.try_deserialize()), vec![2]);
        assert_eq!(s.consumed, s.entry_buf.len());
        assert_eq!(s.skipped, 1);
    }

    #[test]
    fn test_fake_entry_in_instruction_data_is_not_decoded() {
        // A real transaction whose instruction data spells out a whole Entry
        // (with a valid transaction) followed by a few more bytes.
        let fake = entry_bytes(&[legacy_tx_bytes(0xee)]);
        let mut data = fake.clone();
        data.extend_from_slice(&[7; 5]);
        let host = VersionedMessage::Legacy(legacy_message(1, data));
        let host_entry = entry_bytes(&[wincode::serialize(&tx(1, host)).unwrap()]);
        let fake_at = host_entry
            .windows(fake.len())
            .position(|w| w == fake.as_slice())
            .unwrap();

        // Join the slot mid-Entry at every point before the fake Entry.
        for cut in 1..=fake_at {
            let mut buf = host_entry[cut..].to_vec();
            buf.extend(entry_bytes(&[legacy_tx_bytes(2)]));
            buf.extend(entry_bytes(&[v1_tx_bytes(3)]));
            let mut s = SlotState::new(0);
            s.set_first_index(5);
            s.entry_buf = buf;
            s.batch_starts.push_back(s.entry_buf.len());
            assert_eq!(sigs(&s.try_deserialize()), vec![2, 3], "cut {cut}");
        }
    }

    #[test]
    fn test_half_received_entry_is_not_skipped_mid_slot() {
        // Join mid-block, then receive the rest a few bytes at a time. The
        // Entry that is still arriving must not be stepped over.
        let lost = entry_bytes(&[legacy_tx_bytes(7)]);
        let mut full = lost[lost.len() / 2..].to_vec();
        full.extend(entry_bytes(&[legacy_tx_bytes(1)]));
        full.extend(entry_bytes(&[v1_tx_bytes(9)]));
        full.extend(entry_bytes(&[v0_tx_bytes(2)]));

        let mut s = SlotState::new(0);
        s.set_first_index(5);
        let mut got = Vec::new();
        for chunk in full.chunks(37) {
            s.entry_buf.extend_from_slice(chunk);
            got.extend(s.try_deserialize());
        }
        s.batch_starts.push_back(s.entry_buf.len());
        got.extend(s.try_deserialize());
        assert_eq!(sigs(&got), vec![1, 9, 2]);
        assert_eq!(s.skipped, 0);
    }

    #[test]
    fn test_short_batches_do_not_overrun_buffer() {
        // A 3-byte batch and an empty one, then a normal batch.
        let good = batch(&[entry_bytes(&[legacy_tx_bytes(1)])]);
        let mut s = SlotState::new(0);
        s.set_first_index(0);
        s.entry_buf = vec![9, 9, 9];
        s.batch_starts.extend([3, 3]);
        s.entry_buf.extend_from_slice(&good);
        s.batch_starts.push_back(s.entry_buf.len());
        assert_eq!(sigs(&s.try_deserialize()), vec![1]);
        assert_eq!(s.consumed, s.entry_buf.len());
        assert_eq!(s.skipped, 2);
    }

    #[test]
    fn test_incomplete_entry_waits_for_more_shreds() {
        let first = entry_bytes(&[legacy_tx_bytes(1)]);
        let second = entry_bytes(&[legacy_tx_bytes(2)]);
        let full = batch(&[first.clone(), second.clone()]);
        let split = 8 + first.len() + second.len() / 2;

        let mut s = slot_with(full[..split].to_vec());
        assert_eq!(sigs(&s.try_deserialize()), vec![1]);
        assert_eq!(s.consumed, 8 + first.len());

        s.entry_buf.extend_from_slice(&full[split..]);
        assert_eq!(sigs(&s.try_deserialize()), vec![2]);
    }

    #[test]
    fn test_jito_batch_keeps_entries_after_unreadable_one() {
        let b = batch(&[
            entry_bytes(&[legacy_tx_bytes(1)]),
            entry_bytes(&[bad_tx_bytes()]),
            entry_bytes(&[v1_tx_bytes(9)]),
        ]);
        let (txs, skipped) = read_entry_batch(&b);
        assert_eq!(sigs(&txs), vec![1, 9]);
        assert_eq!(skipped, 1);
    }

    #[test]
    fn test_jito_batch_with_unreadable_first_entry() {
        let b = batch(&[
            entry_bytes(&[bad_tx_bytes()]),
            entry_bytes(&[legacy_tx_bytes(1)]),
            entry_bytes(&[v1_tx_bytes(9)]),
        ]);
        let (txs, skipped) = read_entry_batch(&b);
        assert_eq!(sigs(&txs), vec![1, 9]);
        assert_eq!(skipped, 1);
    }

    #[test]
    fn test_jito_short_or_empty_message() {
        assert_eq!(read_entry_batch(&[]).1, 0);
        let (txs, skipped) = read_entry_batch(&[1, 2, 3]);
        assert!(txs.is_empty());
        assert_eq!(skipped, 1);
    }

    // ── Full decoder: shreds carrying real batch flags ────────────────────────

    const TEST_SLOT: u64 = 1_000;

    /// Data shreds for one slot, starting at index 0. Each batch is cut into
    /// pieces of `chunk` bytes; the last piece of a batch has DATA_COMPLETE
    /// set and the last shred of the slot has LAST_SHRED_IN_SLOT.
    fn slot_shreds(batches: &[Vec<u8>], chunk: usize) -> Vec<RawShred> {
        let mut pieces = Vec::new();
        for b in batches {
            let parts: Vec<&[u8]> = if b.is_empty() {
                vec![&[]]
            } else {
                b.chunks(chunk).collect()
            };
            let n = parts.len();
            for (i, p) in parts.into_iter().enumerate() {
                pieces.push((p.to_vec(), i + 1 == n));
            }
        }
        let total = pieces.len();
        pieces
            .into_iter()
            .enumerate()
            .map(|(idx, (payload, ends_batch))| {
                let mut data = make_shred(0x92, &payload, false);
                data[SLOT_OFF..SLOT_OFF + 8].copy_from_slice(&TEST_SLOT.to_le_bytes());
                data[INDEX_OFF..INDEX_OFF + 4].copy_from_slice(&(idx as u32).to_le_bytes());
                if ends_batch {
                    data[FLAGS_OFF] |= DATA_COMPLETE_FLAG;
                }
                if idx + 1 == total {
                    data[FLAGS_OFF] |= LAST_IN_SLOT_FLAG;
                }
                RawShred {
                    data,
                    recv_timestamp_ns: 1,
                }
            })
            .collect()
    }

    /// Feed `shreds` through `ShredDecoder::run` and collect what it emits.
    fn run_decoder(shreds: Vec<RawShred>) -> (Vec<u8>, Arc<SourceMetrics>) {
        let (in_tx, in_rx) = crossbeam_channel::unbounded();
        let (out_tx, out_rx) = crossbeam_channel::unbounded();
        let metrics = SourceMetrics::new("test", false);
        for s in shreds {
            in_tx.send(s).unwrap();
        }
        drop(in_tx);
        ShredDecoder::new(in_rx, out_tx, metrics.clone())
            .run()
            .unwrap();
        let txs: Vec<_> = out_rx.try_iter().map(|d| d.transaction).collect();
        (sigs(&txs), metrics)
    }

    fn block_marker() -> Vec<u8> {
        let mut marker = 0u64.to_le_bytes().to_vec();
        marker.extend_from_slice(&[0x5a; 50]);
        marker
    }

    fn test_batches() -> Vec<Vec<u8>> {
        vec![
            batch(&[
                entry_bytes(&[legacy_tx_bytes(1), v0_tx_bytes(2)]),
                entry_bytes(&[v1_tx_bytes(3)]),
            ]),
            block_marker(),
            batch(&[entry_bytes(&[v1_tx_bytes(4)]), entry_bytes(&[])]),
            batch(&[entry_bytes(&[legacy_tx_bytes(5), v1_tx_bytes(6)])]),
        ]
    }

    #[test]
    fn test_run_reads_flagged_batches_without_skips() {
        for chunk in [40, 97, 1000] {
            let mut shreds = slot_shreds(&test_batches(), chunk);
            // Shreds arrive out of order too.
            shreds.swap(1, 2);
            let n = shreds.len();
            shreds.swap(n - 1, n - 3);

            let (got, m) = run_decoder(shreds);
            assert_eq!(got, vec![1, 2, 3, 4, 5, 6], "chunk {chunk}");
            assert_eq!(m.entries_skipped.load(Relaxed), 0, "chunk {chunk}");
            assert_eq!(m.slots_complete.load(Relaxed), 1, "chunk {chunk}");
        }
    }

    #[test]
    fn test_run_mid_block_join_without_skips() {
        // Join after the first shred: the first Entry of batch 1 is lost,
        // everything from its second Entry on is read.
        let shreds = slot_shreds(&test_batches(), 97);
        let first_entry_end = 8 + entry_bytes(&[legacy_tx_bytes(1), v0_tx_bytes(2)]).len();
        assert!(97 < first_entry_end);
        let (got, m) = run_decoder(shreds.into_iter().skip(1).collect());
        assert_eq!(got, vec![3, 4, 5, 6]);
        assert_eq!(m.entries_skipped.load(Relaxed), 0);
    }

    #[test]
    fn test_run_survives_short_and_empty_batches() {
        let good = batch(&[entry_bytes(&[legacy_tx_bytes(1)])]);
        let after = batch(&[entry_bytes(&[v1_tx_bytes(2)])]);
        let shreds = slot_shreds(&[good, vec![9, 9, 9], vec![], after], 1000);
        let (got, m) = run_decoder(shreds);
        assert_eq!(got, vec![1, 2]);
        assert_eq!(m.entries_skipped.load(Relaxed), 2);
    }

    // ── Real Agave shreds: FEC recovery under loss ─────────────────────────────

    /// One slot of Merkle shreds (data and coding) made by Agave's own
    /// `Shredder` 4.2.2: a small first entry batch that fits in one FEC set,
    /// one spanning two FEC sets, and the last one.
    /// Each record is a u16 LE length, then the shred. Transaction `n` has
    /// `n` as u16 LE in the first two bytes of its signature.
    const AGAVE_SLOT: &[u8] = include_bytes!("../testdata/agave_slot_1000.bin");

    fn agave_shreds() -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut rest = AGAVE_SLOT;
        while rest.len() >= 2 {
            let len = u16::from_le_bytes([rest[0], rest[1]]) as usize;
            out.push(rest[2..2 + len].to_vec());
            rest = &rest[2 + len..];
        }
        out
    }

    /// Feed raw shreds through the decoder; return the transaction ids it
    /// emitted, sorted, and the metrics.
    fn decode_ids(shreds: &[Vec<u8>]) -> (Vec<u16>, Arc<SourceMetrics>) {
        let (in_tx, in_rx) = crossbeam_channel::unbounded();
        let (out_tx, out_rx) = crossbeam_channel::unbounded();
        let metrics = SourceMetrics::new("test", false);
        // A running feed has sent coding shreds before this slot: start with
        // one from the slot before.
        let mut warm_up = agave_shreds()
            .into_iter()
            .find(|s| parse_coding_header(s).is_some())
            .unwrap();
        warm_up[SLOT_OFF..SLOT_OFF + 8].copy_from_slice(&(TEST_SLOT - 1).to_le_bytes());
        for data in std::iter::once(&warm_up).chain(shreds) {
            in_tx
                .send(RawShred {
                    data: data.clone(),
                    recv_timestamp_ns: 1,
                })
                .unwrap();
        }
        drop(in_tx);
        ShredDecoder::new(in_rx, out_tx, metrics.clone())
            .run()
            .unwrap();
        let mut ids: Vec<u16> = out_rx
            .try_iter()
            .map(|d| {
                let sig = <[u8; 64]>::from(d.transaction.signatures[0]);
                u16::from_le_bytes([sig[0], sig[1]])
            })
            .collect();
        ids.sort_unstable();
        (ids, metrics)
    }

    struct TestRng(u64);
    impl TestRng {
        fn below(&mut self, n: u64) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (self.0 >> 33) % n
        }
    }

    fn is_data(shred: &[u8]) -> bool {
        parse_data_payload(shred).is_some()
    }

    #[test]
    fn test_agave_slot_decodes_in_full() {
        let shreds = agave_shreds();
        assert!(shreds.iter().any(|s| is_data(s)));
        assert!(shreds.iter().any(|s| parse_coding_header(s).is_some()));
        let (ids, m) = decode_ids(&shreds);
        let total = ids.len() as u16;
        assert!(total > 100);
        assert_eq!(ids, (1..=total).collect::<Vec<_>>());
        assert_eq!(m.entries_skipped.load(Relaxed), 0);
        assert_eq!(m.slots_complete.load(Relaxed), 1);
    }

    #[test]
    fn test_agave_slot_lost_data_shreds_are_rebuilt() {
        let shreds = agave_shreds();
        let (all, _) = decode_ids(&shreds);
        // Drop every data shred in turn: FEC must bring each one back.
        for drop in (0..shreds.len()).filter(|&i| is_data(&shreds[i])) {
            let mut lossy = shreds.clone();
            lossy.remove(drop);
            let (ids, m) = decode_ids(&lossy);
            assert_eq!(ids, all, "dropped shred {drop}");
            assert_eq!(m.fec_recovered_shreds.load(Relaxed), 1, "dropped {drop}");
            assert_eq!(m.entries_skipped.load(Relaxed), 0, "dropped {drop}");
        }
    }

    #[test]
    fn test_agave_slot_coding_first_recovers_on_data_shred() {
        // Each FEC set arrives coding shreds first, with one coding and one
        // data shred lost. Recovery then becomes possible only when a data
        // shred arrives, so the data path must start it.
        let shreds = agave_shreds();
        let (all, _) = decode_ids(&shreds);
        let mut sets: Vec<u32> = shreds
            .iter()
            .map(|s| shred_slot_index(s).unwrap().2)
            .collect();
        sets.dedup();
        let mut stream = Vec::new();
        for fec in sets {
            let in_set = |s: &&Vec<u8>| shred_slot_index(s).unwrap().2 == fec;
            stream.extend(
                shreds
                    .iter()
                    .filter(in_set)
                    .filter(|s| !is_data(s))
                    .skip(1)
                    .cloned(),
            );
            stream.extend(
                shreds
                    .iter()
                    .filter(in_set)
                    .filter(|s| is_data(s))
                    .enumerate()
                    .filter(|(i, _)| *i != 5)
                    .map(|(_, s)| s.clone()),
            );
        }
        let (ids, m) = decode_ids(&stream);
        assert_eq!(ids, all);
        assert!(m.fec_recovered_shreds.load(Relaxed) >= 4);
    }

    #[test]
    fn test_agave_slot_late_shred_after_recovery_counts_once() {
        // Data shred 5 is late: FEC rebuilds it first, then the original
        // arrives. It counts once as seen, and not as recovered: it was
        // late, not lost.
        let shreds = agave_shreds();
        let (all, _) = decode_ids(&shreds);
        let late = shreds
            .iter()
            .position(|s| is_data(s) && shred_slot_index(s).unwrap().1 == 5)
            .unwrap();
        let mut stream = shreds.clone();
        let shred = stream.remove(late);
        stream.push(shred);
        let (ids, m) = decode_ids(&stream);
        assert_eq!(ids, all);
        assert_eq!(m.fec_recovered_shreds.load(Relaxed), 0);
        assert_eq!(m.coverage_shreds_seen.load(Relaxed), 128);
    }

    #[test]
    fn test_agave_slot_corrupt_coding_shards_are_not_trusted() {
        // Data shred 5 is lost and every coding shred of its set has a
        // corrupted byte in the column that rebuilds the slot field. The
        // rebuilt shred then names the wrong slot and must be dropped.
        let mut stream = agave_shreds();
        stream.retain(|s| !(is_data(s) && shred_slot_index(s).unwrap().1 == 5));
        for s in stream.iter_mut() {
            if parse_coding_header(s).is_some() && shred_slot_index(s).unwrap().2 == 0 {
                // Shard byte 1 is the first slot byte (offset 65) of a data shred.
                s[CODE_HDR_END + SLOT_OFF - SIGNATURE_SIZE] ^= 0xff;
            }
        }
        let (_, m) = decode_ids(&stream);
        assert_eq!(m.fec_recovered_shreds.load(Relaxed), 0);
    }

    /// Shreds of FEC set `fec`, data or coding.
    fn set_shreds(shreds: &[Vec<u8>], fec: u32, data: bool) -> Vec<Vec<u8>> {
        shreds
            .iter()
            .filter(|s| shred_slot_index(s).unwrap().2 == fec && is_data(s) == data)
            .cloned()
            .collect()
    }

    #[test]
    fn test_agave_slot_first_shred_lost_and_rebuilt() {
        // The slot's first batch fits in FEC set 0. Shred 0 is lost and comes
        // back only after the rest of the set (data, then coding). Reading
        // must wait for it, or the start of the batch is lost.
        let shreds = agave_shreds();
        let (all, _) = decode_ids(&shreds);
        let stream: Vec<Vec<u8>> = shreds
            .iter()
            .filter(|s| !(is_data(s) && shred_slot_index(s).unwrap().1 == 0))
            .cloned()
            .collect();
        let (ids, m) = decode_ids(&stream);
        assert_eq!(ids, all);
        assert_eq!(m.fec_recovered_shreds.load(Relaxed), 1);
        assert_eq!(m.coverage_shreds_seen.load(Relaxed), 128);
    }

    #[test]
    fn test_agave_slot_first_shred_lost_for_good() {
        // Shred 0 and every coding shred of its set are lost, so it can't be
        // rebuilt. Reading goes on once the next set shows up, and the
        // missing shred is not counted as seen or rebuilt.
        let shreds = agave_shreds();
        let (all, _) = decode_ids(&shreds);
        let stream: Vec<Vec<u8>> = shreds
            .iter()
            .filter(|s| {
                let (_, index, fec) = shred_slot_index(s).unwrap();
                !(fec == 0 && (!is_data(s) || index == 0))
            })
            .cloned()
            .collect();
        let (ids, m) = decode_ids(&stream);
        assert!(!ids.is_empty());
        assert!(ids.iter().all(|i| all.contains(i)));
        assert_eq!(m.fec_recovered_shreds.load(Relaxed), 0);
        assert_eq!(m.coverage_shreds_seen.load(Relaxed), 127);
    }

    #[test]
    fn test_agave_slot_batch_end_shred_completes_rebuild() {
        // Set 0 holds the whole first batch. 31 of its coding shreds arrive,
        // then only its last data shred, which both ends the batch and makes
        // the rebuild possible. The rebuilt shreds must be read with it.
        let shreds = agave_shreds();
        let (all, _) = decode_ids(&shreds);
        let data0 = set_shreds(&shreds, 0, true);
        assert!(ends_entry_batch(data0.last().unwrap()));
        let mut stream: Vec<Vec<u8>> = set_shreds(&shreds, 0, false).into_iter().skip(1).collect();
        stream.push(data0.last().unwrap().clone());
        stream.extend(
            shreds
                .iter()
                .filter(|s| shred_slot_index(s).unwrap().2 > 0)
                .cloned(),
        );
        let (ids, m) = decode_ids(&stream);
        assert_eq!(ids, all);
        assert_eq!(m.fec_recovered_shreds.load(Relaxed), 31);
        assert_eq!(m.entries_skipped.load(Relaxed), 0);
    }

    #[test]
    fn test_agave_slot_no_loss_counts_nothing_as_rebuilt() {
        // Coding shreds first, no loss: FEC rebuilds every data shred before
        // its original arrives. Those were late, not lost, so the rebuilt
        // count ends at 0.
        let shreds = agave_shreds();
        let (all, _) = decode_ids(&shreds);
        let mut stream = Vec::new();
        for fec in [0, 32, 64, 96] {
            stream.extend(set_shreds(&shreds, fec, false));
            stream.extend(set_shreds(&shreds, fec, true));
        }
        let (ids, m) = decode_ids(&stream);
        assert_eq!(ids, all);
        assert_eq!(m.fec_recovered_shreds.load(Relaxed), 0);
        assert_eq!(m.coverage_shreds_seen.load(Relaxed), 128);
    }

    #[test]
    fn test_prepends_are_capped() {
        // Shreds arriving in falling index order with no batch end would
        // each move the whole buffer. Only MAX_PREPEND_SHREDS may.
        let mut s = SlotState::new(0);
        let top = 5_000u32;
        for idx in (0..=top).rev() {
            let shred = make_shred(0x92, &[1; 100], false);
            s.add_data_shred(idx, &shred, false, vec![1; 100]);
            s.flush_contiguous();
        }
        assert_eq!(s.prepended, MAX_PREPEND_SHREDS);
        assert_eq!(s.first_index, top - MAX_PREPEND_SHREDS);
        assert_eq!(s.entry_buf.len(), 100 * (MAX_PREPEND_SHREDS as usize + 1));
    }

    #[test]
    fn test_fec_set_keeps_only_in_range_data_shards() {
        let mut fec = FecSet::default();
        fec.add_data(5, &[1; 8]);
        fec.add_data(MAX_SET_SHARDS - 1, &[1; 8]);
        fec.add_data(MAX_SET_SHARDS, &[1; 8]);
        fec.add_data(100_000, &[1; 8]);
        assert_eq!(fec.data.len(), 2);
    }

    #[test]
    fn test_fec_set_accepts_256_shards() {
        let mut ok = make_coding_shred(0x66, 128, 128, 0);
        ok[SLOT_OFF..SLOT_OFF + 8].copy_from_slice(&TEST_SLOT.to_le_bytes());
        let (_, m) = decode_ids(&[ok]);
        assert_eq!(m.coverage_shreds_expected.load(Relaxed), 32 + 128);
    }

    #[test]
    fn test_fec_set_ignores_out_of_range_shards() {
        // A coding header claiming more than 256 shards is not a real set,
        // and data shards past index 255 are not kept.
        let mut big = make_coding_shred(0x66, 200, 100, 0);
        big[SLOT_OFF..SLOT_OFF + 8].copy_from_slice(&TEST_SLOT.to_le_bytes());
        let mut far = make_shred(0x96, b"x", false);
        far[SLOT_OFF..SLOT_OFF + 8].copy_from_slice(&TEST_SLOT.to_le_bytes());
        far[INDEX_OFF..INDEX_OFF + 4].copy_from_slice(&300u32.to_le_bytes());
        let (ids, m) = decode_ids(&[big, far]);
        assert!(ids.is_empty());
        // Only the warm-up shred's set (32 data shreds) counts.
        assert_eq!(m.coverage_shreds_expected.load(Relaxed), 32);
    }

    #[test]
    fn test_held_slot_is_not_logged_complete_before_reading() {
        // Join inside the slot's last FEC set with its coding shreds lost.
        // The slot waits for FEC; it must not count as complete with 0 txs
        // meanwhile. A shred from the next slot ends the wait.
        let shreds = agave_shreds();
        let mut stream: Vec<Vec<u8>> = set_shreds(&shreds, 96, true).into_iter().skip(1).collect();
        let (ids, m) = decode_ids(&stream);
        assert!(ids.is_empty());
        assert_eq!(m.slots_complete.load(Relaxed), 0);

        let mut next = set_shreds(&shreds, 0, false).remove(0);
        next[SLOT_OFF..SLOT_OFF + 8].copy_from_slice(&(TEST_SLOT + 1).to_le_bytes());
        stream.push(next);
        let (ids, m) = decode_ids(&stream);
        assert!(!ids.is_empty());
        assert_eq!(m.slots_complete.load(Relaxed), 1);
        let logged = m.snapshot().slot_log;
        assert!(logged
            .iter()
            .any(|s| s.slot == TEST_SLOT && s.txs_decoded == ids.len() as u32));
    }

    /// Decode `shreds` and also return the per-transaction receive times.
    fn decode_recv_times(shreds: &[(Vec<u8>, u64)]) -> Vec<u64> {
        let (in_tx, in_rx) = crossbeam_channel::unbounded();
        let (out_tx, out_rx) = crossbeam_channel::unbounded();
        for (data, at) in shreds {
            in_tx
                .send(RawShred {
                    data: data.clone(),
                    recv_timestamp_ns: *at,
                })
                .unwrap();
        }
        drop(in_tx);
        ShredDecoder::new(in_rx, out_tx, SourceMetrics::new("test", false))
            .run()
            .unwrap();
        out_rx.try_iter().map(|d| d.shred_recv_ns).collect()
    }

    #[test]
    fn test_agave_slot_reordered_first_shreds_do_not_hold() {
        // Shreds 0 and 1 swap places and nothing is lost. Once shred 0 is
        // put in front, nothing is left for FEC: reading must not wait for
        // the set's coding shreds (here they never come).
        let shreds = agave_shreds();
        let mut stream = set_shreds(&shreds, 0, true);
        stream.swap(0, 1);
        let (ids, _) = decode_ids(&stream);
        assert!(!ids.is_empty());
    }

    #[test]
    fn test_agave_slot_join_at_set_start_does_not_hold() {
        // Starting exactly at a set start leaves nothing earlier in that set
        // to rebuild, so reading starts at once (set 96's coding is lost).
        let shreds = agave_shreds();
        let (ids, m) = decode_ids(&set_shreds(&shreds, 96, true));
        assert!(!ids.is_empty());
        assert_eq!(m.slots_complete.load(Relaxed), 1);
    }

    #[test]
    fn test_agave_slot_logged_recovered_count_matches_metric() {
        // Coding first, no loss: the slot's log entry must not count rebuilt
        // shreds whose originals arrived.
        let shreds = agave_shreds();
        let mut stream = Vec::new();
        for fec in [0, 32, 64, 96] {
            stream.extend(set_shreds(&shreds, fec, false));
            stream.extend(set_shreds(&shreds, fec, true));
        }
        let (_, m) = decode_ids(&stream);
        let log = m.snapshot().slot_log;
        let entry = log.iter().find(|s| s.slot == TEST_SLOT).unwrap();
        assert_eq!(entry.fec_recovered, 0);
        assert_eq!(entry.shreds_seen, 128);
    }

    #[test]
    fn test_agave_slot_bad_length_copy_does_not_block_rebuild() {
        // Shred 5 is lost. Shred 7 first arrives with a wrong proof size
        // (so a shard of the wrong length), then its good copy. The bad
        // shard must not make the rebuild of shred 5 fail.
        let shreds = agave_shreds();
        let (all, _) = decode_ids(&shreds);
        let mut stream = Vec::new();
        for s in &shreds {
            let index = shred_slot_index(s).unwrap().1;
            if is_data(s) && index == 5 {
                continue;
            }
            if is_data(s) && index == 7 {
                let mut bad = s.clone();
                bad[VARIANT_OFF] += 1;
                stream.push(bad);
            }
            stream.push(s.clone());
        }
        let (ids, m) = decode_ids(&stream);
        assert_eq!(ids, all);
        assert_eq!(m.fec_recovered_shreds.load(Relaxed), 1);
    }

    #[test]
    fn test_agave_slot_bad_length_coding_shred_first_does_not_block_rebuild() {
        // Shred 5 is lost, and the first coding shred of its set arrives
        // with a wrong proof size before its good copy. The rebuild must
        // still use the length the other shards agree on.
        let shreds = agave_shreds();
        let (all, _) = decode_ids(&shreds);
        for coding_first in [false, true] {
            let mut stream = Vec::new();
            let mut bad = set_shreds(&shreds, 0, false).remove(0);
            bad[VARIANT_OFF] += 1;
            stream.push(bad);
            for fec in [0, 32, 64, 96] {
                let data: Vec<Vec<u8>> = set_shreds(&shreds, fec, true)
                    .into_iter()
                    .filter(|s| shred_slot_index(s).unwrap().1 != 5)
                    .collect();
                let coding = set_shreds(&shreds, fec, false);
                if coding_first {
                    stream.extend(coding);
                    stream.extend(data);
                } else {
                    stream.extend(data);
                    stream.extend(coding);
                }
            }
            let (ids, m) = decode_ids(&stream);
            assert_eq!(ids, all, "coding first: {coding_first}");
            assert_eq!(m.fec_recovered_shreds.load(Relaxed), 1);
        }
    }

    #[test]
    fn test_agave_slot_mismatched_layout_is_ignored() {
        // A coding shred claiming a different layout for a known set is
        // ignored, so it can't spoil the rebuild.
        let shreds = agave_shreds();
        let (all, _) = decode_ids(&shreds);
        let mut odd = set_shreds(&shreds, 0, false).remove(0);
        odd[CODE_NUM_DATA_OFF] = 31;
        let mut stream: Vec<Vec<u8>> = Vec::new();
        for s in &shreds {
            if is_data(s) && shred_slot_index(s).unwrap().1 == 3 {
                continue;
            }
            stream.push(s.clone());
            if !is_data(s) && shred_slot_index(s).unwrap().1 == 0 {
                stream.push(odd.clone());
            }
        }
        let (ids, _) = decode_ids(&stream);
        assert_eq!(ids, all);
    }

    #[test]
    fn test_slot_receive_time_is_earliest_shred() {
        // Every transaction carries the slot's earliest shred receive time
        // (here the first shred's), not that of a later shred.
        let shreds = agave_shreds();
        let timed: Vec<(Vec<u8>, u64)> = shreds
            .iter()
            .enumerate()
            .map(|(i, s)| (s.clone(), 1_000 + i as u64))
            .collect();
        let earliest = timed.iter().map(|(_, t)| *t).min().unwrap();
        let times = decode_recv_times(&timed);
        assert!(!times.is_empty());
        assert!(times.iter().all(|&t| t == earliest));
    }

    #[test]
    fn test_slot_with_missing_last_shred_is_not_complete() {
        // The last data shred and all coding of its set are lost: the slot
        // can't count as complete.
        let shreds = agave_shreds();
        let stream: Vec<Vec<u8>> = shreds
            .iter()
            .filter(|s| {
                let (_, index, fec) = shred_slot_index(s).unwrap();
                !(fec == 96 && (!is_data(s) || index == 126))
            })
            .cloned()
            .collect();
        let (_, m) = decode_ids(&stream);
        assert_eq!(m.slots_complete.load(Relaxed), 0);
    }

    #[test]
    fn test_prepend_stops_past_byte_cap() {
        let mut s = SlotState::new(0);
        s.add_data_shred(
            10,
            &make_shred(0x92, b"", false),
            false,
            vec![0; MAX_PREPEND_BYTES + 1],
        );
        s.flush_contiguous();
        s.add_data_shred(9, &make_shred(0x92, b"", false), false, vec![1; 10]);
        s.flush_contiguous();
        assert_eq!(s.first_index, 10);
        assert_eq!(s.prepended, 0);
    }

    #[test]
    fn test_fec_set_counts_only_data_inside_the_set() {
        let mut fec = FecSet::default();
        for i in 0..5 {
            fec.add_data(i, &[1; 10]);
        }
        fec.add_coding(0, &[2; 10]);
        fec.set_layout(4, 4);
        assert_eq!(fec.best_length(), Some((10, 4, 1)));
        fec.set_layout(5, 4);
        assert_eq!(fec.best_length(), Some((10, 5, 1)));
        // Shards past the set's data count don't count once the layout is known.
        fec.set_layout(4, 4);
        fec.add_data(7, &[1; 10]);
        assert_eq!(fec.best_length(), Some((10, 4, 1)));

        // The same once the layout came first: index 4 is outside a 4-shred set.
        let mut fec = FecSet::default();
        fec.set_layout(4, 4);
        fec.add_data(4, &[1; 10]);
        assert_eq!(fec.best_length(), None);
        fec.add_data(3, &[1; 10]);
        assert_eq!(fec.best_length(), Some((10, 1, 0)));
    }

    #[test]
    fn test_fec_set_is_capped() {
        let mut fec = FecSet::default();
        for len in 1..100 {
            for i in 0..MAX_SET_SHARDS {
                fec.add_data(i, &vec![0u8; len]);
            }
        }
        assert_eq!(fec.data.len(), 4 * MAX_SET_SHARDS);
        fec.add_coding(0, &[0u8; 5]);
        assert!(fec.coding.is_empty());
    }

    #[test]
    fn test_prune_fec_sets() {
        let mut sets: HashMap<u64, HashMap<u32, FecSet>> = HashMap::new();
        let with_coding = || FecSet {
            layout: Some((32, 32)),
            ..FecSet::default()
        };
        for slot in [100, 197, 198] {
            let m = sets.entry(slot).or_default();
            m.insert(0, with_coding());
            m.insert(32, FecSet::default());
        }
        prune_fec_sets(&mut sets, 200);
        // Slot 100 is expired; 197 is past FEC_WAIT_SLOTS, so its set
        // without coding goes; 198 keeps both.
        assert!(!sets.contains_key(&100));
        assert_eq!(sets[&197].len(), 1);
        assert!(sets[&197].contains_key(&0));
        assert_eq!(sets[&198].len(), 2);
        prune_fec_sets(&mut sets, 197 + SLOT_EXPIRY_DISTANCE);
        assert!(sets.contains_key(&197));
        prune_fec_sets(&mut sets, 198 + SLOT_EXPIRY_DISTANCE);
        assert!(!sets.contains_key(&197));
    }

    #[test]
    fn test_erasure_shard_unchained_variants() {
        // Older unchained Merkle shreds (0x8_ data, 0x4_ coding) have no
        // chained root.
        let mut d = vec![0u8; DATA_SHRED_PAYLOAD];
        d[VARIANT_OFF] = 0x86;
        let mut c = vec![0u8; CODE_SHRED_PAYLOAD];
        c[VARIANT_OFF] = 0x46;
        let tail = 6 * MERKLE_PROOF_ENTRY_SIZE;
        assert_eq!(
            erasure_shard(&d).unwrap().len(),
            DATA_SHRED_PAYLOAD - SIGNATURE_SIZE - tail
        );
        assert_eq!(
            erasure_shard(&c).unwrap().len(),
            CODE_SHRED_PAYLOAD - CODE_HDR_END - tail
        );
    }

    #[test]
    fn test_agave_slot_hold_ends_when_its_set_is_rebuilt() {
        // Join inside the slot's last set, shred 96 lost: the set's coding
        // shreds rebuild it and end the wait, with no newer slot needed.
        let shreds = agave_shreds();
        let mut stream: Vec<Vec<u8>> = set_shreds(&shreds, 96, true).into_iter().skip(1).collect();
        stream.extend(set_shreds(&shreds, 96, false));
        let (ids, m) = decode_ids(&stream);
        assert!(!ids.is_empty());
        assert_eq!(m.fec_recovered_shreds.load(Relaxed), 1);
        assert_eq!(m.slots_complete.load(Relaxed), 1);
    }

    #[test]
    fn test_agave_slot_random_loss_and_reordering() {
        let shreds = agave_shreds();
        let (all, _) = decode_ids(&shreds);
        let mut rng = TestRng(7);
        for trial in 0..60 {
            // 1-5% loss, and shreds swap places with near neighbours, so
            // coding shreds can arrive before the data shreds of their set.
            let loss = 1 + rng.below(5);
            let mut lossy: Vec<Vec<u8>> = shreds
                .iter()
                .filter(|_| rng.below(100) >= loss)
                .cloned()
                .collect();
            for _ in 0..lossy.len() / 4 {
                let a = rng.below(lossy.len() as u64 - 8) as usize;
                lossy.swap(a, a + 1 + rng.below(7) as usize);
            }
            let (ids, m) = decode_ids(&lossy);
            assert_eq!(ids, all, "trial {trial}");
            assert_eq!(m.entries_skipped.load(Relaxed), 0, "trial {trial}");
        }
    }

    /// Every FEC set in `shreds` holds enough shards to rebuild its data.
    fn every_set_recoverable(shreds: &[Vec<u8>], all: &[Vec<u8>]) -> bool {
        let mut num_data: HashMap<u32, usize> = HashMap::new();
        for s in all {
            if let (Some(c), Some((_, _, fec))) = (parse_coding_header(s), shred_slot_index(s)) {
                num_data.insert(fec, c.num_data as usize);
            }
        }
        let mut have: HashMap<u32, usize> = HashMap::new();
        for s in shreds {
            *have.entry(shred_slot_index(s).unwrap().2).or_default() += 1;
        }
        have.iter().all(|(fec, n)| *n >= num_data[fec])
    }

    #[test]
    fn test_agave_slot_mid_block_join_with_loss() {
        // Join the stream part-way through, then lose a few shreds. While
        // every FEC set can still be rebuilt, every entry batch that starts
        // after the first data shred we receive must be read in full.
        // Before FEC worked, one lost shred before the first batch end cost
        // the whole slot.
        let shreds = agave_shreds();
        let (all, _) = decode_ids(&shreds);
        let data: Vec<&Vec<u8>> = shreds.iter().filter(|s| is_data(s)).collect();
        let index_of = |s: &[u8]| shred_slot_index(s).unwrap().1;
        let batch_starts: Vec<u32> = std::iter::once(0)
            .chain(
                data.iter()
                    .filter(|s| ends_entry_batch(s))
                    .map(|s| index_of(s) + 1),
            )
            .collect();

        let mut rng = TestRng(11);
        let mut checked = 0;
        for join in (1..shreds.len() - 40).step_by(5) {
            let joined = &shreds[join..];
            for trial in 0..3 {
                let lossy: Vec<Vec<u8>> = joined
                    .iter()
                    .filter(|_| rng.below(100) >= 3)
                    .cloned()
                    .collect();
                let (ids, _) = decode_ids(&lossy);
                assert!(ids.iter().all(|i| all.contains(i)), "join {join}");
                if !every_set_recoverable(&lossy, &shreds) {
                    continue;
                }
                // The first batch may have started before the first data
                // shred we received; every batch after that must be whole.
                let Some(earliest) = lossy
                    .iter()
                    .filter(|s| is_data(s))
                    .map(|s| index_of(s))
                    .min()
                else {
                    continue;
                };
                let Some(&from) = batch_starts.iter().find(|&&b| b >= earliest) else {
                    continue;
                };
                let tail: Vec<Vec<u8>> = data
                    .iter()
                    .filter(|s| index_of(s) >= from)
                    .map(|s| s.to_vec())
                    .collect();
                let (must_have, _) = decode_ids(&tail);
                assert!(
                    must_have.iter().all(|i| ids.contains(i)),
                    "join {join} trial {trial}: missing {:?}",
                    must_have
                        .iter()
                        .filter(|i| !ids.contains(i))
                        .collect::<Vec<_>>()
                );
                checked += 1;
            }
        }
        assert!(checked > 60, "only {checked} trials could be checked");
    }

    #[test]
    fn test_agave_slot_corrupted_shreds_do_not_panic() {
        // Corrupt random bytes of real shreds, mostly in the headers, and
        // feed them through with loss and reordering.
        let shreds = agave_shreds();
        let mut rng = TestRng(23);
        for _ in 0..40 {
            let mut stream: Vec<Vec<u8>> = shreds
                .iter()
                .filter(|_| rng.below(100) >= 5)
                .cloned()
                .collect();
            for _ in 0..1 + rng.below(20) {
                let i = rng.below(stream.len() as u64) as usize;
                let s = &mut stream[i];
                let at = if rng.below(4) == 0 {
                    rng.below(s.len() as u64) as usize
                } else {
                    64 + rng.below(32) as usize
                };
                s[at] = rng.below(256) as u8;
                if rng.below(10) == 0 {
                    let keep = rng.below(s.len() as u64) as usize;
                    s.truncate(keep);
                }
            }
            for _ in 0..stream.len() / 8 {
                let a = rng.below(stream.len() as u64) as usize;
                let b = rng.below(stream.len() as u64) as usize;
                stream.swap(a, b);
            }
            decode_ids(&stream);
        }
    }
}
