# shredtop

Measures which Solana shred feed delivers each shred to your machine first, and by how much.

```
====================================================================================================
                      SHREDTOP  2026-03-25 11:42:07 UTC
====================================================================================================
  Started: 2026-03-25 11:30:00 UTC   Uptime: 12m 7s

SHRED RACE  validator → this machine  (since start):

  CONTENDER              WIN%   RACES/s   FASTER BY    LEAD p50   LEAD p95
  ----------------------------------------------------------------------------------------------------
  edge-solana-shreds                 63.1%       412   +0.19ms       +0.1ms     +0.7ms
  jito-shredstream      36.9%         —         —            —          —

SOURCE               LINK    SHREDS/s   COV%  TXS/s   BEAT%   LEAD avg   LEAD p50   LEAD p95   LEAD p99
----------------------------------------------------------------------------------------------------
edge-solana-shreds                  OK        4200   98%     420    64.2%    +48.2ms    +46.1ms    +71.3ms    +91.0ms
jito-shredstream       OK        3900   97%     380    55.1%    +31.4ms    +29.9ms    +55.8ms    +74.2ms
rpc                     —           —    —      390  baseline          —          —          —          —
----------------------------------------------------------------------------------------------------

  EDGE ASSESSMENT
  ✓ edge-solana-shreds              ahead of RPC by +48ms avg
  ✓ jito-shredstream   ahead of RPC by +31ms avg
```

---

## Contents

- [Install](#install)
- [Discover](#discover)
  - [probe.toml — full reference](#probetoml--full-reference)
  - [Source types](#source-types)
  - [Optional per-source fields](#optional-per-source-fields)
- [Status](#status)
- [Monitor](#monitor)
- [Uninstall](#uninstall)
- [Program Architecture](#program-architecture)
- [Shred Race Architecture](#shred-race-architecture)
  - [What is a shred race?](#what-is-a-shred-race)
  - [Kernel timestamping](#kernel-timestamping)
  - [Why CLOCK_REALTIME on both sides](#why-clock_realtime-on-both-sides)
  - [The race processing pipeline](#the-race-processing-pipeline)
  - [Pairwise win recording](#pairwise-win-recording)
  - [Publisher IP tracking](#publisher-ip-tracking)
  - [Leader slot filter](#leader-slot-filter)
- [DoubleZero multicast groups](#doublezero-multicast-groups)
- [License](#license)

---

## Install

**Build from source (requires Rust 1.81+):**

```bash
git clone https://github.com/malbeclabs/shredtop.git ~/shredtop
cargo install --path ~/shredtop
```

**Pre-built binary:**

```bash
curl -fsSL https://github.com/malbeclabs/shredtop/releases/latest/download/shredtop -o /usr/local/bin/shredtop && chmod +x /usr/local/bin/shredtop
```

**Upgrade:**

```bash
shredtop upgrade           # download and install the latest release binary
shredtop upgrade --source  # pull latest from GitHub and rebuild from source
```

---

## Discover

`shredtop discover` sniffs live multicast traffic on your network interfaces, identifies active shred feeds, detects DoubleZero multicast groups, and optionally writes a ready-to-use `probe.toml`.

```bash
shredtop discover
```

It will show which multicast groups are active and on which ports, then offer to write `probe.toml`. After writing the config, you can edit it manually to add baseline sources, recording options, or filters.

After discovery, start the background service:

```bash
shredtop service start
```

The service installs a systemd unit, enables it on boot, and starts collection immediately. Ctrl-C from `monitor` or `status` does not stop the service — it runs in the background until you explicitly stop it.

```bash
shredtop service stop
shredtop service restart
shredtop service status
shredtop service uninstall   # stop, disable, and remove the unit file
```

### probe.toml — full reference

`probe.toml` is the single configuration file for all sources, recording, and filters. `shredtop discover` writes a starter version; all optional sections are off by default.

```toml
# ── Shred feeds ──────────────────────────────────────────────────────────────

[[sources]]
name = "edge-solana-shreds"
type = "shred"
multicast_addr = "233.84.178.1"
port = 7733
interface = "doublezero1"

[[sources]]
name = "jito-shredstream"
type = "shred"
multicast_addr = "233.84.178.2"
port = 20001
interface = "doublezero1"

# ── Baseline source (required for BEAT%/LEAD columns) ────────────────────────

[[sources]]
name = "rpc"
type = "rpc"
url = "http://127.0.0.1:8899"

# Yellowstone gRPC (alternative to RPC — lower latency baseline)
# [[sources]]
# name = "geyser"
# type = "geyser"
# url = "https://grpc.example.com:10000"
# x_token = "your-auth-token"   # optional

# Jito ShredStream gRPC proxy (alternative baseline)
# [[sources]]
# name = "jito-grpc"
# type = "jito-grpc"
# url = "http://127.0.0.1:9999"

# Turbine — validator node only. Receives shreds from the standard turbine
# retransmit tree via SO_REUSEPORT, coexisting with a running validator.
# Use this to measure how much faster a dedicated shred feed is vs standard turbine propagation.
# [[sources]]
# name = "turbine"
# type = "turbine"
# port = 8002

# ── Optional: transaction filter ─────────────────────────────────────────────
# Restrict BEAT%/LEAD measurement to transactions touching these programs or accounts.
# Applies to shred-tier sources only. RPC-tier sources are always exempt.
# filter_programs = [
#   "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4",   # Jupiter v6
#   "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8",  # Raydium AMM
# ]

# ── Optional: ring-buffer raw shred capture ───────────────────────────────────
# Records every raw shred packet to a rotating file ring on disk.
# Use `shredtop capture list` to inspect the ring and `shredtop analyze` to
# post-process pcap files for offline timing analysis.
#
# [capture]
# enabled = true
# formats = ["pcap"]           # one or more of: "pcap", "csv", "jsonl"
#                              # each format gets its own independent ring of files
# max_size_mb = [10000]        # maximum disk space per format in MB
#                              # index N applies to formats[N]; missing entries default to 10 000 MB
# rotate_mb = 500              # start a new file after this many megabytes
# output_dir = "/var/log/shredtop-capture"

# ── Optional: Prometheus metrics endpoint ────────────────────────────────────
# Serves Prometheus text-format metrics at http://0.0.0.0:<port>/metrics
#
# [metrics]
# enabled = true
# port = 9090

# ── Optional: leader schedule filter for publisher IP stats ──────────────────
# When enabled, publisher IP statistics only count shreds whose source IP
# matches the scheduled slot leader for that slot.
# See "Shred Race Architecture" below for when this is and isn't useful.
#
# [leader_filter]
# enabled = true
# rpc_url = "http://127.0.0.1:8899"
```

### Source types

| `type` | Description |
|--------|-------------|
| `shred` | Raw UDP multicast shred feed (DZ or Jito ShredStream relay). Requires `multicast_addr`, `port`, `interface`. |
| `turbine` | Solana turbine retransmit tree via `SO_REUSEPORT`. Coexists with a running validator on the TVU port. Requires `port` (default `8002`). |
| `unicast` | Unicast UDP forwarder — exclusive bind to `addr:port`. For relays that push shreds to you directly. |
| `rpc` | Confirmed-transaction WebSocket subscription (`logsSubscribe`). Requires `url`. |
| `geyser` | Yellowstone gRPC (Triton, Helius, QuickNode, etc.). Requires `url`; `x_token` optional. Acts as RPC baseline. |
| `jito-grpc` | Jito ShredStream proxy gRPC. Requires `url` (e.g. `http://127.0.0.1:9999`). Acts as RPC baseline. |
| `shreder` | Shreder relay. |
| `arpc` | Atlas RPC. |
| `thor` | Thor. |
| `jetstream` | Jetstream. |

### Optional per-source fields

| Field | Default | Description |
|-------|---------|-------------|
| `pin_recv_core` | — | CPU core to pin the receiver thread to |
| `pin_decode_core` | — | CPU core to pin the decoder thread to |
| `shred_version` | — | Only accept shreds with this version (bytes 77–78). Drop mismatches silently. |
| `heartbeat_port` | `5765` | DZ heartbeat port override (`shred` only) |
| `x_token` | — | Auth token sent as `x-token` gRPC header (`geyser` only) |

---

## Status

```bash
shredtop status
```

Reads the last line from `/var/log/shredtop.jsonl` and prints a static one-shot table. Works from any terminal or script without opening the live dashboard.

**Output sections:**

**SHRED RACE** — cumulative since service start. One pair of rows per feed combination. The faster feed is green; the slower feed is dimmed.

| Column | Meaning |
|--------|---------|
| `WIN%` | Fraction of matched shreds where this feed delivered first |
| `RACES/s` | Matched `(slot, shred_index)` pairs per second (total ÷ uptime) |
| `FASTER BY` | Mean lead time of the winner over the loser |
| `LEAD p50` | Median per-shred advantage |
| `LEAD p95` | 95th-percentile advantage |

**Per-source feed table** — with a baseline source:

| Column | Meaning |
|--------|---------|
| `SHREDS/s` | Raw UDP packets per second (`—` for RPC-tier) |
| `COV%` | Fraction of each block's data shreds that arrived |
| `TXS/s` | Decoded transactions per second |
| `BEAT%` | % of matched transactions where this feed arrived before RPC |
| `LEAD avg` | Mean arrival advantage over RPC baseline |
| `LEAD p50/p95/p99` | Percentiles of arrival advantage |

**DEDUP** — cumulative totals showing how many transactions were first vs duplicate arrivals per source. Useful for verifying that dedup is working and that all sources are active.

---

## Monitor

```bash
shredtop monitor
shredtop monitor --interval 3   # refresh every 3 seconds (default: 5)
```

Live dashboard reading from the service metrics log. Ctrl-C closes the view — the background service keeps running.

Requires `shredtop service start` to be running first.

**SHRED RACE section** — feed-vs-feed, always shown when two or more shred-tier sources are configured. Each matched pair produces two rows: the faster feed (green) and the slower feed (dimmed).

| Column | Meaning |
|--------|---------|
| `WIN%` | Fraction of races this feed won |
| `RACES/s` | Races per second (matched shreds ÷ uptime) |
| `FASTER BY` | Mean lead time of the winning feed in ms |
| `LEAD p50` | Median lead — typical per-shred advantage |
| `LEAD p95` | 95th-percentile lead — good worst-case |

**Per-source feed table** — shown below the race section. Column set depends on whether a baseline source (RPC-tier) is configured.

Without baseline:

| Column | Meaning |
|--------|---------|
| `LINK` | DZ heartbeat freshness: `OK` ≤10s · `STALE` ≤60s · `DEAD` >60s · `—` for RPC-tier |
| `SHREDS/s` | Raw UDP packets per second |
| `COV%` | Block shred coverage |
| `TXS/s` | Decoded transactions per second |

With baseline (adds):

| Column | Meaning |
|--------|---------|
| `BEAT%` | % of matched transactions where this feed beat RPC |
| `LEAD avg` | Mean arrival advantage over RPC in ms |
| `LEAD p50/p95/p99` | Percentiles of lead time |

**EDGE ASSESSMENT** — shown when a baseline source is present. One line per shred-tier source:

| Symbol | Meaning |
|--------|---------|
| `✓` green | Consistently ahead of RPC (mean > +1ms) |
| `~` yellow | Marginally ahead (0 to +1ms) |
| `⚠` yellow | Behind RPC (−5ms to 0ms) |
| `✗` red | Badly behind RPC (< −5ms) |

---

## Uninstall

**One command:**

```bash
shredtop uninstall
```

Stops and removes the systemd service, binary, metrics log, capture files, config, and source directory. Prompts for confirmation before proceeding.

**Manual:**

```bash
shredtop service uninstall                  # stop, disable, and remove systemd unit
rm /usr/local/bin/shredtop                  # binary (curl install)
# or: cargo uninstall shredtop              # binary (cargo install)
rm -f /var/log/shredtop.jsonl               # metrics log
rm -rf /var/log/shredtop-capture            # capture ring (check output_dir in probe.toml)
rm -rf ~/shredtop probe.toml               # source and config
```

---

## Program Architecture

shredtop runs as a background service writing structured metrics to `/var/log/shredtop.jsonl`. The CLI commands (`monitor`, `status`, `bench`) are readers — they parse that log and display it. The service and the display are completely decoupled.

```
┌─────────────────────────────────────────────────────────────────┐
│  Background Service  (shredtop run / systemd)                    │
│                                                                   │
│  ┌──────────────┐    ┌──────────────┐                            │
│  │ ShredReceiver│    │ ShredReceiver│  ...one per shred feed      │
│  │ recvmmsg     │    │ recvmmsg     │                            │
│  │ SO_TIMESTAMPNS│   │ SO_TIMESTAMPNS│                           │
│  └──────┬───────┘    └──────┬───────┘                            │
│         │ RawShred           │ RawShred                           │
│         │ (recv_timestamp_ns)│                                    │
│         ▼                   ▼                                     │
│  ┌──────────────┐    ┌──────────────┐                            │
│  │ ShredDecoder │    │ ShredDecoder │  FEC recovery + bincode     │
│  └──────┬───────┘    └──────┬───────┘                            │
│         │ DecodedTx          │ DecodedTx                          │
│         └──────────┬─────────┘                                    │
│                    ▼                                               │
│             ┌─────────────┐   ◄── RpcSource / GeyserSource        │
│             │  FanInSource │        (baseline, RPC-tier)           │
│             │  sig dedup   │                                       │
│             │  lead time   │                                       │
│             └──────┬───────┘                                      │
│                    │ SourceMetrics                                 │
│                    ▼                                               │
│           /var/log/shredtop.jsonl  (JSONL, one line per interval) │
│                                                                   │
│  ┌─────────────────────┐   ShredArrival (slot, idx, recv_ns)      │
│  │  ShredRaceTracker   │ ◄── tapped from every ShredReceiver       │
│  │  (slot,idx) pairs   │                                          │
│  │  pairwise wins      │                                          │
│  │  PublisherTracker   │                                          │
│  └─────────────────────┘                                          │
│                                                                   │
│  ┌─────────────────────┐                                          │
│  │  Capture Thread     │ ◄── CaptureEvent tap (try_send, no-block) │
│  │  pcap / csv / jsonl │                                          │
│  │  rotating ring      │                                          │
│  └─────────────────────┘                                          │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│  CLI (reads log / ring, does not talk to service directly)       │
│                                                                   │
│  shredtop monitor   — live dashboard from /var/log/shredtop.jsonl│
│  shredtop status    — latest snapshot from /var/log/shredtop.jsonl│
│  shredtop bench     — timed run, structured JSON report           │
│  shredtop capture list — inspect capture ring on disk            │
│  shredtop analyze   — post-process pcap for timing table         │
└─────────────────────────────────────────────────────────────────┘
```

**Hot-path design** — each `ShredReceiver` runs on a dedicated thread (optionally pinned to a CPU core) and uses:
- `SO_BUSY_POLL 50µs` — spin-waits for packets, eliminating scheduler wakeup latency
- `SO_TIMESTAMPNS` — kernel records receive timestamp at NIC driver level before any userspace scheduling
- `recvmmsg(MSG_WAITFORONE, batch=64)` — returns as soon as ≥1 packet is available, amortizes syscall overhead
- `SO_RCVBUFFORCE 32MB` — bypasses `net.core.rmem_max`

The decoder runs on a second thread. FanIn relay threads are a third layer. The race tracker and capture tap receive data via bounded `crossbeam_channel` with non-blocking `try_send` — the hot path is never stalled by downstream consumers.

---

## Shred Race Architecture

### What is a shred race?

Solana leaders distribute blocks as shreds — 1228-byte UDP packets carrying Reed-Solomon coded fragments of the block data. Each shred has a fixed-layout header containing `slot` (8 bytes, LE u64 at offset 65) and `shred_index` (4 bytes, LE u32 at offset 73).

A shred race is the answer to: **which feed delivered the same `(slot, shred_index)` to this machine first, and by how many microseconds?**

This is measured at the kernel socket layer — before FEC reconstruction, before bincode deserialization, before any userspace processing whatsoever.

### Kernel timestamping

Each `ShredReceiver` enables `SO_TIMESTAMPNS` on its UDP socket at construction time. When the NIC driver delivers a packet, the kernel records `CLOCK_REALTIME` in a `SCM_TIMESTAMPNS` control message (cmsg). shredtop reads this via `recvmmsg` and extracts it from the cmsg chain on every packet. This timestamp reflects when the kernel first touched the packet — not when userspace read it.

The raw `CLOCK_REALTIME` nanosecond value is stored directly. No clock conversion is applied.

### Why CLOCK_REALTIME on both sides

`SO_TIMESTAMPNS` delivers `CLOCK_REALTIME`. The RPC baseline source (`logsSubscribe` WebSocket callback) also records `clock_gettime(CLOCK_REALTIME)` at notification time.

Using the same clock for both measurements is critical. The alternative — converting shred timestamps to `CLOCK_MONOTONIC_RAW` using a fixed startup offset — fails when NTP makes a step correction to `CLOCK_REALTIME` after startup (common in the first 30–60 seconds of boot while ntpd synchronizes). A 50ms NTP step would make every shred appear 50ms later than it really was, producing systematically negative lead times. With `CLOCK_REALTIME` on both sides, any NTP corrections affect both measurements equally and cancel out in the formula `lead_us = (rpc_ns − shred_ns) / 1000`.

### The race processing pipeline

```
ShredReceiver hot loop (per feed)
  │
  │  recvmmsg → parse slot+idx from bytes [65:77]
  │
  ├─► try_send(ShredArrival { source, slot, idx, recv_ns, src_ip })
  │         │                                          ↑
  │         │                              CLOCK_REALTIME from SO_TIMESTAMPNS
  │         │
  │       bounded channel(4096)    ← drops silently on full; this is a
  │         │                          sampling metric, not a correctness path
  │         ▼
  │   shred-race-proc thread
  │     DashMap<(slot, idx), ShredFirstArrival>
  │
  │     On first arrival for (slot, idx):
  │       insert { arrivals: [(source, recv_ns, src_ip)], expected: N }
  │
  │     On subsequent arrivals:
  │       push (source, recv_ns, src_ip) to arrivals[]
  │       if arrivals.len() == expected (all feeds delivered):
  │         sort by recv_ns
  │         record pairwise wins (see below)
  │         record publisher IP win
  │
  └─► stale entries evicted every 5s (cutoff: 10s old)
```

`expected` equals the number of shred-tier sources configured. A race result is only recorded when **all** configured shred feeds have delivered the same shred — partial deliveries produce no result and are evicted.

### Pairwise win recording

When all N sources have delivered `(slot, idx)`, shredtop sorts the arrivals by `recv_ns` ascending (fastest first) and records every ordered pair:

```
for i in 0..N:
    for j in (i+1)..N:
        winner = arrivals[i]   ← earlier recv_ns
        loser  = arrivals[j]
        lead_us = (loser.recv_ns − winner.recv_ns) / 1000
        key = alphabetically sorted (winner.source, loser.source)
        pair.record(winner.source, lead_us)
```

Pair keys are sorted alphabetically so `(edge-solana-shreds, jito-shredstream)` and `(jito-shredstream, edge-solana-shreds)` map to the same entry. `a_wins` counts wins by the alphabetically-first source; `b_wins` counts wins by the other.

A `RaceReservoir` (fixed 4096-slot ring buffer, overwriting oldest on full) stores recent `lead_us` values per pair. `percentiles()` sorts the buffer and returns p50/p95/p99 at snapshot time.

### Publisher IP tracking

Every shred arrival records the sender's IPv4 address (`src_ip` extracted from `recvmmsg msg_name`). The `PublisherTracker` maintains a `DashMap<u32, IpStats>` tracking per-IP:

- `total_shreds` — all arrivals from this IP
- `wins` — times this IP's shred won a race (i.e., was the fastest arrival)
- `last_seen_ns` — most recent arrival timestamp

Results appear in the `publisher_ips` array in the JSONL log and in `shredtop bench` output, sorted by wins descending.

### Leader slot filter

The `[leader_filter]` config section enables `LeaderCache`, a background component that:

1. Calls `getEpochInfo` to get the current epoch and absolute slot
2. Calls `getLeaderSchedule(absolute_slot)` to get the full epoch schedule: `pubkey → [relative_slot, ...]`
3. Calls `getClusterNodes` to get the TPU/gossip IP for each validator pubkey
4. Builds a `DashMap<slot, IPv4_u32>` mapping every absolute slot in the epoch to the leader's IPv4
5. Refreshes once per epoch boundary, polling every 60 seconds

With the filter enabled, `PublisherTracker` only records arrivals where `src_ip == leader_ip_for_slot`. Similarly, race results are only recorded for slots whose leader is already in the cache.

**When this is useful:** turbine and unicast sources, where `src_ip` is the validator sending shreds directly. Filtering to confirmed leaders eliminates noise from retransmit nodes.

**When this produces no results:** relay sources (DZ multicast, Jito ShredStream). The `src_ip` on every packet is the relay node's IP — it will never appear in the leader schedule. With `leader_filter` enabled, `publisher_ips` will be empty for these sources. Omit `[leader_filter]` if you are only running relay sources.

---

## DoubleZero multicast groups

| Feed | Multicast IP | Port |
|------|-------------|------|
| edge-solana-shreds | `233.84.178.1` | `7733` |
| jito-shredstream | `233.84.178.2` | `20001` |

To subscribe, refer to the DoubleZero documentation for joining multicast groups over the DZ network fabric.

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
