# Shredtop Backlog

Deferred features and improvements not yet implemented.

---

## Option 2 — Tx send time as baseline

**Summary:** Use local transaction submissions as the baseline instead of an RPC node.

**How it works:** The user submits transactions from this machine. Record the send timestamp
(via a log file or local socket), match by signature when the shred feed delivers it back.
This measures the full round-trip: submit → validator → shred relay → this machine.

**Advantage:** No RPC node required. Baseline latency is zero (it's the submission
timestamp itself), so any positive lead time is a true measurement of how early the shred
feed delivers relative to when the tx was sent.

**Limitation:** Requires integration with the user's tx submission pipeline. Shredtop
would need to tail a log file or accept UDP/Unix socket events from the submission process.
Out of scope until there's a concrete use case.

---

## Option 3 — Public/remote RPC as baseline

**Summary:** Use any public RPC endpoint (mainnet-beta, Helius, QuickNode, Triton) as the
confirmation baseline, eliminating the need for a local node.

**How it works:** Same as the current RPC baseline, but the node is remote. `shredtop
discover` would offer a curated list of well-known public endpoints.

**Tradeoff:** A public RPC introduces 50–500 ms of additional baseline latency depending
on provider and network path. This inflates all LEAD measurements by the same offset,
making the absolute numbers misleading. BEAT% and relative comparisons between shred feeds
remain valid.

**Implementation:** Minimal code change — just allow a non-localhost URL in the rpc source.
The main work is UX: `shredtop discover` should warn the user about inflated LEAD values
when a remote RPC is detected, and suggest interpreting BEAT% instead of raw LEAD ms.

**Candidate public endpoints to offer in discover:**
- `https://api.mainnet-beta.solana.com` (official, rate-limited)
- Helius, QuickNode, Triton (require API keys)
