# Agent Instructions — shredtop

## What this is
Standalone Solana shred feed latency benchmark. Measures the millisecond advantage of raw shred feeds (DoubleZero, Jito ShredStream) over confirmed-block RPC polling.

## Agent context — read these files at session start
| File | Contents |
|---|---|
| `agents/` | TBD |

## Critical rules

### Commit style
- Push directly to main — no PRs
- No `Co-Authored-By` trailers in commit messages
- No auto-commits without explicit instruction

### Build & local validation
- `cargo build` requires Linux (x86_64). On macOS, use `make check` (or `cargo check`) for syntax validation.
- `make ci` runs the same gate CI runs: `fmt-check`, `clippy -D warnings`, `cargo test --locked`. Run it before pushing.
- Toolchain is pinned in `rust-toolchain.toml` (currently 1.95.0 + rustfmt + clippy). `cargo`/`rustup` auto-install it on first invocation; no manual `rustup update` needed.
- `RUSTFLAGS=-D warnings` is exported by the Makefile, mirroring the CI workflow env.
- **Platform parity gotcha:** clippy on macOS skips `#[cfg(target_os = "linux")]` blocks, so Linux-only code paths can pass `make ci` locally and still fail in CI. When touching code under such a `cfg`, expect CI to be the authoritative lint check.
