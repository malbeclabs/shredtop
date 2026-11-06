# Test data

`agave_slot_1000.bin` is one slot of real Merkle shreds (128 data, 128 coding,
168 transactions, three entry batches) made by Agave's own `Shredder` from
`solana-ledger` 4.2.2. The decoder tests use it to check FEC recovery against
the real shred layout.

Each record is a u16 LE length followed by the shred bytes. Transaction `n`
has `n` as u16 LE in the first two bytes of its signature.

## Regenerate

`solana-ledger` is a heavy dependency (it builds RocksDB), so the generator is
kept out of the workspace. Copy the two files below into a new folder and run:

```sh
cargo run --release -- agave_slot_1000.bin
```

`Cargo.toml`:

```toml
[package]
name = "shredgen"
version = "0.1.0"
edition = "2021"
publish = false

[dependencies]
solana-ledger = { version = "=4.2.2", features = ["agave-unstable-api"] }
solana-entry = { version = "=4.2.2", features = ["agave-unstable-api"] }
solana-hash = ">=4.4.0,<4.6.0"
solana-keypair = "3.1.2"
solana-message = ">=4.2.3,<4.5.0"
solana-signature = ">=3.4.1,<3.5.0"
solana-transaction = ">=4.1.4,<4.2.0"
solana-address = "*"
```

`src/main.rs`:

```rust
//! Writes one real slot of Agave Merkle shreds (data + coding) to a file.
//! Record format: u16 LE length, then the shred bytes.
use solana_entry::entry::Entry;
use solana_hash::Hash;
use solana_keypair::Keypair;
use solana_ledger::shred::{ProcessShredsStats, ReedSolomonCache, Shredder};
use solana_message::{compiled_instruction::CompiledInstruction, Message, MessageHeader, VersionedMessage, v0};
use solana_signature::Signature;
use solana_transaction::versioned::VersionedTransaction;
use std::io::Write;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0 >> 33
    }
}

fn tx(id: u16, rng: &mut Rng) -> VersionedTransaction {
    let mut sig = [0u8; 64];
    sig[..2].copy_from_slice(&id.to_le_bytes());
    for b in sig[2..].iter_mut() { *b = rng.next() as u8; }
    let len = 20 + (rng.next() % 260) as usize;
    let data: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
    let keys = vec![
        solana_address::Address::new_from_array([id as u8; 32]),
        solana_address::Address::new_from_array([(id >> 8) as u8 ^ 0x55; 32]),
    ];
    let header = MessageHeader { num_required_signatures: 1, num_readonly_signed_accounts: 0, num_readonly_unsigned_accounts: 1 };
    let ix = CompiledInstruction { program_id_index: 1, accounts: vec![0], data };
    let message = if id % 3 == 0 {
        VersionedMessage::V0(v0::Message { header, account_keys: keys, recent_blockhash: Hash::new_from_array([7; 32]), instructions: vec![ix], address_table_lookups: vec![] })
    } else {
        VersionedMessage::Legacy(Message { header, account_keys: keys, recent_blockhash: Hash::new_from_array([7; 32]), instructions: vec![ix] })
    };
    VersionedTransaction { signatures: vec![Signature::from(sig)], message }
}

fn main() {
    let out = std::env::args().nth(1).expect("output path");
    let mut rng = Rng(42);
    let keypair = Keypair::new();
    let shredder = Shredder::new(1_000, 999, 5, 0).unwrap();
    let cache = ReedSolomonCache::default();
    let mut stats = ProcessShredsStats::default();
    let mut id = 0u16;
    let mut entries_for = |n_entries: usize, txs_per: usize, rng: &mut Rng| -> Vec<Entry> {
        (0..n_entries).map(|i| {
            let transactions = if i % 7 == 6 { vec![] } else {
                (0..txs_per).map(|_| { id += 1; tx(id, rng) }).collect()
            };
            Entry { num_hashes: 1 + i as u64, hash: Hash::new_from_array([i as u8; 32]), transactions }
        }).collect()
    };
    // Batch sizes: one spanning two FEC sets, one small, one last in slot.
    let batches = [(28, 5, false), (2, 2, false), (12, 4, true)];
    let (mut next_data, mut next_code) = (0u32, 0u32);
    let mut root = Hash::new_from_array([1; 32]);
    let mut file = std::fs::File::create(out).unwrap();
    let mut n = 0;
    for (n_entries, txs_per, last) in batches {
        let entries = entries_for(n_entries, txs_per, &mut rng);
        let shreds: Vec<_> = shredder.make_merkle_shreds_from_entries(&keypair, &entries, last, root, next_data, next_code, &cache, &mut stats).collect();
        for s in &shreds {
            if s.is_data() { next_data = next_data.max(s.index() + 1); } else { next_code = next_code.max(s.index() + 1); }
            let p: &[u8] = s.payload().as_ref();
            file.write_all(&(p.len() as u16).to_le_bytes()).unwrap();
            file.write_all(p).unwrap();
            n += 1;
        }
        root = shreds.last().unwrap().merkle_root().unwrap();
    }
    eprintln!("wrote {n} shreds, {next_data} data, {next_code} coding, {id} txs");
}
```
