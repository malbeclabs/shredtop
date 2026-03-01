# Agent Instructions — shredtop

## What this is
Standalone Solana shred feed latency benchmark. Measures the millisecond advantage of raw shred feeds (DoubleZero, Jito ShredStream) over confirmed-block RPC polling.

## Agent context — read these files at session start
| File | Contents |
|---|---|
| `agents/` | TBD |

## Critical rules

### Git identity
Always verify git identity before committing:
```bash
git config user.name
git config user.email
```

### Commit style
- Push directly to main — no PRs
- No `Co-Authored-By` trailers in commit messages
- No auto-commits without explicit instruction

### Build
- `cargo build` requires Linux (x86_64)
- `cargo check` works locally on macOS for syntax validation
