# shredtop

Measures the latency advantage of raw Solana shred feeds over confirmed-block RPC.

If your business depends on seeing transactions before your competitors, shredtop gives you an estimate of how many milliseconds ahead you are, and whether that edge is holding.

```
====================================================================================================
                      SHREDTOP FEED QUALITY  2026-02-25 23:27:33 UTC
====================================================================================================

SOURCE               SHREDS/s   COV%  TXS/s   BEAT%   LEAD avg   LEAD p50   LEAD p95   LEAD p99
----------------------------------------------------------------------------------------------------
bebop                       0      —      0       —          —          —          —          —
jito-shredstream        52585   100%     22    100%   +629.8ms   +598.3ms   +890.1ms  +1124.5ms
rpc                         —      —   4065       —   baseline          —          —          —
----------------------------------------------------------------------------------------------------

EDGE ASSESSMENT:
  ✓  jito-shredstream    AHEAD of RPC  by 629.82ms avg  (10219 samples)

----------------------------------------------------------------------------------------------------
COV% = block shreds received  BEAT% = % of matched txs where feed beat RPC  LEAD = ms before RPC confirms  p50/p95/p99 = percentiles
```

---

## How it works

Solana leaders distribute blocks as shreds over UDP. Feed providers relay those shreds to your machine before the block is confirmed.

shredtop:

1. Binds a UDP socket on your multicast interface and receives raw shreds
2. Parses the Agave wire format, runs Reed-Solomon FEC recovery on partial FEC sets
3. Deserializes `Entry` structs via bincode to extract transactions
4. Polls a baseline source (RPC, Yellowstone Geyser, or Jito gRPC proxy) for confirmed transactions in parallel
5. Matches transactions across sources by `signatures[0]`, computes arrival time deltas

Lead time = `T_rpc_confirmed − T_shred_received`. Positive means you were ahead.

All timestamps use `CLOCK_MONOTONIC_RAW` (Linux) — immune to NTP slew.

```mermaid
flowchart LR
    subgraph Feeds["Shred Feeds"]
        DZ["DoubleZero UDP\nMulticast"]
        JITO_UDP["Jito ShredStream\nUDP Multicast"]
    end

    subgraph Baseline["Baseline Sources"]
        RPC["Solana RPC\nJSON-RPC polling"]
        GEY["Yellowstone Geyser\ngRPC"]
        JGRPC["Jito gRPC Proxy"]
    end

    subgraph HotPath["Hot Path (per shred feed)"]
        RECV["ShredReceiver\nrecvmmsg · SO_TIMESTAMPNS"]
        DEC["ShredDecoder\nFEC recovery · bincode"]
    end

    subgraph CaptureSide["Capture Side-Channel"]
        CAP["Capture Thread\ntry_send · never blocks"]
        RING["Ring Buffer\npcap / csv / jsonl"]
    end

    subgraph Agg["Matching & Aggregation"]
        RACE["ShredRaceTracker\nslot + idx pairs\nfeed-vs-feed lead time"]
        FANIN["FanInSource\nsignatures[0] dedup\nshred-vs-baseline lead time"]
        METRICS["SourceMetrics\nper-source counters"]
    end

    LOG["/var/log/shredtop.jsonl\nMetrics Log"]

    subgraph CLI["CLI"]
        MON["shredtop monitor\nlive dashboard"]
        STAT["shredtop status\nsnapshot"]
        BENCH["shredtop bench\nJSON report"]
        CLIST["shredtop capture list\nring inventory"]
        ANA["shredtop analyze\ntiming table"]
    end

    DZ & JITO_UDP --> RECV
    RECV -->|raw shreds| DEC
    RECV -->|"ShredArrival\n(slot, idx, recv_ns)"| RACE
    RECV -->|"CaptureEvent\ntry_send"| CAP
    CAP --> RING

    DEC -->|DecodedTx| FANIN
    DEC --> METRICS
    RPC & GEY & JGRPC -->|DecodedTx| FANIN
    FANIN --> METRICS

    RACE -->|ShredPairSnapshot| LOG
    METRICS -->|snapshots| LOG

    LOG --> MON & STAT & BENCH
    RING --> CLIST & ANA
```

---

## Requirements

- Linux x86_64
- A shred feed (DoubleZero, Jito ShredStream UDP, or Jito gRPC proxy)
- A baseline source: local Solana RPC node, Yellowstone Geyser endpoint, or Jito ShredStream gRPC proxy
- Rust 1.81+ _(build from source only)_

---

## Install

**RECOMENDED Build from source (requires Rust 1.81+):**

```bash
git clone https://github.com/Haruko-Haruhara-GSPB/shredtop.git ~/shredtop
cargo install --path ~/shredtop
```

# to upgrade from source
```
shredtop upgrade --source
```

**Pre-built binary (recommended):**

```bash
curl -fsSL https://github.com/Haruko-Haruhara-GSPB/shredtop/releases/latest/download/shredtop -o /usr/local/bin/shredtop && chmod +x /usr/local/bin/shredtop
```



---

## Quick start

```bash
# 1. Detect active feeds and write probe.toml
shredtop discover

# 2. Start background collection (installs systemd service, persists across reboots)
shredtop service start

# 3. Open the live dashboard — Ctrl-C closes the view, collection keeps running
shredtop monitor

# Check metrics any time without opening the dashboard
shredtop status

# Upgrade to the latest version
shredtop upgrade --source
```

---

## Configuration

`probe.toml` defines one or more sources. Mix shred feeds and an RPC baseline:

```toml
# DoubleZero bebop feed
[[sources]]
name = "bebop"
type = "shred"
multicast_addr = "233.84.178.1"
port = 7733
interface = "doublezero1"

# Jito ShredStream feed
[[sources]]
name = "jito-shredstream"
type = "shred"
multicast_addr = "233.84.178.2"
port = 20001
interface = "doublezero1"

# RPC baseline
[[sources]]
name = "rpc"
type = "rpc"
url = "http://127.0.0.1:8899"

# Turbine baseline — validator node only
# Receives shreds from the standard turbine retransmit tree via SO_REUSEPORT.
# Coexists with a running validator on the same TVU port.
# Use this to measure premium feed lead time vs standard network propagation.
# [[sources]]
# name = "turbine"
# type = "turbine"
# port = 8002   # match your validator's --tvu-port (default 8002)

# Yellowstone gRPC Geyser baseline (alternative to RPC polling)
# [[sources]]
# name = "geyser"
# type = "geyser"
# url = "https://grpc.example.com:10000"
# x_token = "your-auth-token"   # optional

# Jito ShredStream gRPC (requires local shredstream-proxy at 127.0.0.1:9999)
# [[sources]]
# name = "jito-shredstream"
# type = "jito-grpc"
# url = "http://127.0.0.1:9999"
```

### Source types

| `type` | Description |
|--------|-------------|
| `shred` | Raw UDP multicast shred feed (DoubleZero or Jito ShredStream relay). Requires `multicast_addr`, `port`, `interface`. |
| `turbine` | Solana turbine retransmit tree. Binds the validator's TVU port with `SO_REUSEPORT` to coexist with a running validator. No multicast join required. Use this on a validator node to measure how many milliseconds faster a premium feed delivers each shred vs standard network propagation. Requires `port` (default `8002`). The lead time observed depends on which validator client is running — stock Agave delivers shreds via standard gossip, while accelerated validator forks deliver shreds via a faster path. shredtop captures whatever arrives at the TVU port; the number reflects the fork. |
| `rpc` | Confirmed-block polling via standard Solana JSON-RPC. Requires `url`. |
| `geyser` | Confirmed transactions via Yellowstone gRPC (Triton, Helius, QuickNode, etc.). Requires `url`; `x_token` is optional. Acts as RPC baseline. |
| `jito-grpc` | Decoded entries from a local [Jito ShredStream proxy](https://github.com/jito-labs/shredstream-proxy). Requires `url` (e.g. `http://127.0.0.1:9999`). The proxy handles Jito auth; this client needs no credentials. Arrives before block confirmation — shows lead time vs. RPC baseline. |

Optional per-source fields:

| Field | Default | Description |
|-------|---------|-------------|
| `port` | — | UDP multicast port (`shred` only). bebop=`7733`, jito-shredstream=`20001` — always set explicitly |
| `interface` | `doublezero1` | Network interface for multicast (`shred` only) |
| `x_token` | — | Auth token sent as `x-token` gRPC header (`geyser` only) |
| `pin_recv_core` | — | CPU core to pin the receiver thread |
| `pin_decode_core` | — | CPU core to pin the decoder thread |

### Program filter

To restrict lead-time measurement to specific programs or accounts, add a top-level `filter_programs` list:

```toml
# Only measure lead time for transactions that touch these programs/accounts.
# Applies to shred-tier sources only; RPC sources are always exempt (provide baseline).
filter_programs = [
  "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4",   # Jupiter v6
  "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8",  # Raydium AMM
]
```

When `filter_programs` is empty (the default), all transactions are measured.

---

## Commands

### `shredtop service start`

Installs the systemd unit file, enables it on boot, and starts the service. If the service is already running, shows current status instead. Run once after install.

```bash
shredtop service start    # start (installs and enables automatically)
shredtop service stop     # stop
shredtop service restart  # restart
shredtop service status   # show systemd status
shredtop service uninstall  # remove unit file and disable
```

### `shredtop monitor [--interval N]`

Live dashboard reading from the service metrics log. Refreshes every `N` seconds (default 5). Ctrl-C closes the view — the background service keeps running.

Requires `shredtop service start` to be running first.

| Column | Meaning |
|--------|---------|
| `SHREDS/s` | Raw UDP packets received per second |
| `COV%` | Fraction of each block's data shreds that arrived |
| `TXS/s` | Decoded transactions per second |
| `BEAT%` | Of transactions seen by both this feed and RPC, % where this feed arrived first |
| `LEAD avg` | Mean arrival advantage over RPC in milliseconds |
| `LEAD p50` | Median lead time — typical transaction advantage |
| `LEAD p95` | 95th percentile — good worst-case lead time |
| `LEAD p99` | 99th percentile — true worst-case lead time |

### `shredtop status`

One-shot snapshot from the metrics log. Non-interactive — works from any terminal or script.

### `shredtop discover`

Auto-detects DoubleZero multicast feeds and local RPC nodes. Shows group availability, active multicast memberships, and configured sources from `probe.toml`. Sniffs live traffic to identify the correct UDP port for each feed automatically. Offers to write detected sources to `probe.toml`.

Internet-based sources (Helius, Triton, QuickNode Geyser, Jito gRPC proxy) cannot be auto-detected and must be configured manually in `probe.toml` — see the source type table above.

### `shredtop bench --duration N [--output FILE]`

Runs a timed benchmark for `N` seconds and writes a JSON report. If `--output` is omitted, prints to stdout.

```json
{
  "duration_secs": 300,
  "sources": [
    {
      "name": "bebop",
      "shreds_received": 1260000,
      "shreds_per_sec": 4200.0,
      "bytes_received_mb": 1764.0,
      "shreds_dropped": 120,
      "slots_attempted": 1250,
      "slots_complete": 980,
      "slots_partial": 245,
      "slots_dropped": 25,
      "coverage_pct": 82.3,
      "fec_recovered_shreds": 15600,
      "txs_decoded": 126000,
      "txs_per_sec": 420.0,
      "win_rate_pct": 61.4,
      "lead_time_mean_us": 321.4,
      "lead_time_p50_us": 298,
      "lead_time_p95_us": 612,
      "lead_time_p99_us": 890,
      "lead_time_samples": 74800,
      "slot_breakdown": [
        { "slot": 320481234, "shreds_seen": 42, "fec_recovered": 3, "txs_decoded": 18, "outcome": "complete" },
        { "slot": 320481235, "shreds_seen": 38, "fec_recovered": 0, "txs_decoded": 14, "outcome": "partial" }
      ]
    }
  ]
}
```

`slot_breakdown` is included for shred-type sources only (omitted for rpc/geyser/jito-grpc). Up to the 500 most recently finalized slots are included. Each entry shows:

| Field | Description |
|-------|-------------|
| `slot` | Solana slot number |
| `shreds_seen` | Unique data shreds received (including FEC-recovered) |
| `fec_recovered` | Shreds reconstructed via Reed-Solomon FEC |
| `txs_decoded` | Transactions decoded from this slot |
| `outcome` | `complete` / `partial` / `dropped` |

### `shredtop init`

Prints a default `probe.toml` to stdout.

### `shredtop upgrade`

Downloads and installs the latest release binary.

```bash
shredtop upgrade           # download latest release
shredtop upgrade --source  # pull main and rebuild from source
```

---

## Understanding the numbers

**Coverage %** — Some feed providers relay only the tail FEC sets of each block, not the full block. 80–90% coverage is normal and expected. shredtop handles mid-stream joins correctly (no waiting for shred index 0).

**Win rate %** — how often this source delivers a transaction before all other sources. With two shred feeds and one RPC, a healthy setup shows the faster shred source winning 55–65% of transactions.

**Lead time** — samples outside `[−500ms, +2000ms]` are discarded as measurement artifacts (e.g. RPC retry delays). The displayed avg/p50/p95/p99 reflect real network latency only. p50 is the median (typical transaction), p99 is the worst-case you'll see in practice.

**FEC recovery** — when data shreds are dropped in transit, Reed-Solomon coding shreds allow reconstruction. A non-zero FEC-REC count is normal; a high count relative to SHREDS/s may indicate packet loss on the multicast path.

---

## DoubleZero multicast groups

| Code | Multicast IP | Port | Description |
|------|-------------|------|-------------|
| `bebop` | `233.84.178.1` | `7733` | multicast relay |
| `jito-shredstream` | `233.84.178.2` | `20001` | Jito relay |

To subscribe to a multicast group over DoubleZero refer to the DoubleZero documentation.

---

## Uninstall

```bash
shredtop uninstall
```

Stops and removes the systemd service, binary, metrics log, capture files, config, and source directory. Prompts for confirmation before proceeding.

### Manual uninstall

```bash
shredtop service uninstall                                           # stop, disable, remove unit file
cargo uninstall shredtop                                             # remove binary (if installed via cargo)
rm /usr/local/bin/shredtop                                           # remove binary (if installed via curl)
rm -f /var/log/shredtop.jsonl                                        # remove metrics log
rm -rf "$(grep output_dir probe.toml | head -1 | cut -d'"' -f2)"    # remove capture files (check probe.toml for path)
rm -rf ~/shredtop probe.toml                                         # remove source and config
```

---

## License

MIT
