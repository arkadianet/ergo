# Ergo Rust Node

A from-scratch Rust implementation of an [Ergo Platform](https://ergoplatform.org)
full node. The goal is strict consensus compatibility with the
[Scala reference client](https://github.com/ergoplatform/ergo) without
inheriting its architecture: every component is built in idiomatic Rust,
checked against externally-produced test vectors, and laid out so the boundary
between consensus-critical and non-consensus code is visible.

Repository: <https://github.com/arkadianet/ergo>

## Documentation

- [`ARCHITECTURE.md`](./ARCHITECTURE.md) — the big picture: crate layering, the
  single-writer runtime model, data-flow paths, and the consensus / persistence
  / reorg contracts.
- [`docs/codemap.md`](./docs/codemap.md) — per-crate **codebase map**: a layered
  index, the dependency graph, and a landmark page for each of the 22 crates
  (purpose, modules, key types, invariants, "start here").
- [`docs/overview.md`](./docs/overview.md) — the handbook: repository layout and
  the full build / test / run / configure surface.
- [`docs/configuration.md`](./docs/configuration.md) — every config field, by type
  (`ergo-node.toml` and the daemon's `ergo-walletd.toml`).
- [`docs/codemap/ergo-walletd.md`](./docs/codemap/ergo-walletd.md) — the standalone
  watch-only wallet daemon: descriptor format, no-secret boundary, read-only
  API, socket permissions, and confirmed-only balances.
- [`docs/operating.md`](./docs/operating.md) — running, modes, observability.
- [`docs/compatibility.md`](./docs/compatibility.md) — consensus-compatibility and versioning policy.
- [`CONTRIBUTING.md`](./CONTRIBUTING.md) · [`SECURITY.md`](./SECURITY.md) · [`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md)

## Status

Pre-1.0, alpha. Consensus-critical paths are exercised by oracle-backed tests
against Scala-produced fixtures and against mainnet, but the node has not had
broad real-world deployment exposure and **must not be relied on for production
infrastructure or funds custody**. See [`SECURITY.md`](./SECURITY.md).

What ships today, against the Scala reference node's mode taxonomy:

| Capability | Scala | This node |
|---|---|---|
| Mode 1 — Full archive | yes | yes |
| Mode 2 — UTXO snapshot bootstrap (consume + serve) | yes | yes |
| Mode 3 — Pruned (suffix window) | yes | yes (functional; end-to-end activation-parity tests are the remaining `done` gate) |
| Mode 4 — Pruned + UTXO bootstrap | yes | yes for the composed lifecycle: a real UTXO-snapshot install and a NiPoPoW proof compose max-style on the prune sentinel and reboot cleanly (proof-first composition succeeds; snapshot-first rejects the later proof and preserves the installed state; `ergo-node/tests/it/mode4_acceptance.rs`). End-to-end deferred snapshot installation through real header catch-up and a live multi-peer soak remain outstanding |
| Mode 5 — Digest verifier (AD-proof tx validation) | yes | yes (boots and syncs headers from peers; external ADProof-corpus parity beyond the pinned mainnet window and reorg-abort re-anchor remain) |
| Mode 6 — Headers-only | yes | yes |
| NiPoPoW bootstrap (consume + serve) | yes | yes |
| Extra-index (`/blockchain/*`) | yes | yes (requires Mode 1) |
| Mining — external-miner protocol | yes | yes; requires `state_type = "utxo"` (Modes 1–4), rejected on `digest` (Modes 5–6) |
| HD wallet | yes | yes (single-prover + multi-sig primitives; cooperative distributed multi-sig deferred) |
| Standalone watch-only wallet daemon | n/a | yes — `ergo-walletd`: separate process, own database, node-fed sync, read-only local API, no secrets ([docs](./docs/codemap/ergo-walletd.md)) |

Specifics operators should read before deploying:

- **Mainnet sync to tip** was reached on 2026-04-26 at height 1,771,976;
  continued live-mainnet sync has been part of the development loop since.
- **Mode 2 + NiPoPoW combined boot** is ~20 minutes from an empty `data_dir` to
  "bootstrap complete" on mainnet. The Mode 2 trust anchor is provisional —
  cross-check the installed UTXO root against a known-good reference manifest
  before treating it as authoritative.
- **REST API authentication** applies only to `/wallet/*` and `/node/shutdown`
  (Blake2b-256 of the `api_key` header vs `[api.security].api_key_hash`).
  Read/submit routes stay unauthenticated by design — front the public surface
  with a reverse proxy if exposing off loopback.

Configuration enforces four of Scala's five `consistentSettings` rules at load
time (R1, R2, R3, R5); R4 has no analogue because the node exposes no
`check_reemission_rules` opt-out.

## Goals

- A from-scratch Rust implementation — not a wrapper, port, or transcription.
- Strict protocol compatibility: accept every block Scala accepts, reject every
  block it rejects; mainnet-observed behaviour is the authoritative tie-breaker.
- Explicit consensus boundaries — consensus-critical paths sit in dedicated
  crates with narrow APIs (see [`docs/codemap.md`](./docs/codemap.md)).
- Test-vector-driven correctness — boundary tests pin against Scala-produced
  fixtures, not against the implementation under test.
- Proven cryptographic primitives (`k256`, `blake2`, `pbkdf2`, `aes-gcm`,
  `num-bigint`, `gf2_192`); no hand-rolled crypto.
- An AST-walking ErgoTree interpreter — no bytecode VM unless profiling proves
  one necessary.

## Non-goals

- Not a wrapper around, or a line-by-line port of, the Scala node.
- Not a light client (the NiPoPoW bootstrap covers the fast-start case).
- Not an internal-CPU miner — the external-miner REST protocol is supported; an
  in-node mining loop is out of scope.
- Not production-ready. See Status and [`SECURITY.md`](./SECURITY.md).

## Quickstart

The workspace pins Rust 1.95.0 via [`rust-toolchain.toml`](./rust-toolchain.toml)
(`rustup` installs it on first build).

```bash
# Build the node, the wallet CLI, and the standalone wallet daemon.
cargo build --release -p ergo-node -p ergo-wallet -p ergo-walletd

# Run against the bundled default config (mainnet full archival; REST + operator
# web UI on 127.0.0.1:9099).
./target/release/ergo-node --config ergo-node/ergo-node.toml

# CLI help.
./target/release/ergo-node --help
```

The wallet also ships as a standalone **watch-only daemon**
(`ergo-walletd`). It runs beside a node, keeps its own wallet database, syncs
from the node's `/api/v1/chain/*` API, and serves a read-only local API on an
owner-only Unix socket (or loopback TCP) — confirmed balances, boxes,
transactions, and addresses for the public keys in its descriptor file. It
holds no signing key and has no send, sign, or unlock route:

```bash
# Start the daemon against a local node (see the bundled reference config).
./target/release/ergo-walletd --config ergo-walletd/ergo-walletd.toml

# Read it back over the socket. Every route is a GET; nothing can mutate state.
curl --unix-socket ergo-walletd.sock http://local/api/v1/wallet/status
curl --unix-socket ergo-walletd.sock http://local/api/v1/wallet/balances
```

The first run performs a full Initial Block Download from genesis; subsequent
runs resume from the persisted tip. Sync is bounded on both axes: `sync_batch`
is how many blocks a pass may *apply*, `blocks_page` (default 1) how many it may
*request* per `blocks-since` call, because the wire form hex-encodes every
output box and a single response is capped at 8 MiB. The descriptor file is the
daemon's only input: it lists public keys, so the `/scan/*` registry the backing
store also implements is always empty here and `/api/v1/scans` returns `[]` —
scan registration stays a node capability. The node also serves a
dependency-free
operator web dashboard at the REST bind address (`http://127.0.0.1:9099/` by
default) — a single-page app with Overview (live charts + event feed),
Explorer, Peers, Mempool, Mining, Voting, and Wallet sections — plus Scala API
docs at `/swagger` and RUST API docs at `/swagger/native`; wallet actions
require the API key. For a ~20-minute clean-DB boot, enable Mode 2 + NiPoPoW.

Two deviations the daemon does not paper over, both written up in
[`docs/codemap/ergo-walletd.md`](./docs/codemap/ergo-walletd.md#known-deviations):

- the chain protocol carries no raw header bytes, so a block's protocol id is
  checked for *consistency* (parent linkage, height, tip agreement, uniqueness)
  but **not recomputed** from header bytes; ErgoBox bytes *are* parsed and
  fully re-derived;
- `/balance` and `/status` are values the daemon computes from blocks it has
  applied — confirmed-only, with `available == confirmed`, literal-zero
  `reserved`/`immature`, and `null` `unconfirmed`/`reemission` — so they are
  **not** byte-identical to an embedded wallet's embedded values.
The full build / test / run / configuration surface — profiles, feature-gated
tests, the config reference, observability — is in
[`docs/overview.md`](./docs/overview.md).

## Correctness

Correctness discipline is the largest investment in the project. Consensus-
boundary tests pin against **externally-produced fixtures** (a running Scala
node + real mainnet bytes), never self-oracles; `sigma-rust` is used only as a
dev/test oracle and is never linked into the consensus path. CI runs `cargo fmt
--check`, `cargo check`, `cargo clippy --all-targets --all-features -- -D
warnings`, and `cargo test --all` on Linux / macOS / Windows, plus
`cargo-audit` / `cargo-deny` / `cargo-machete`. Detail in
[`docs/overview.md`](./docs/overview.md); subsystem-by-subsystem parity status
in [`docs/compatibility.md`](./docs/compatibility.md).

## Contributing

[`CONTRIBUTING.md`](./CONTRIBUTING.md) has the full guide. Safe starting points:
test-vector extraction, operator ergonomics (config/CLI/logging), documentation,
and non-consensus tooling. Anything in the consensus crates (`ergo-primitives`,
`ergo-ser`, `ergo-crypto`, `ergo-sigma`, `ergo-validation`, `ergo-state`,
`ergo-mining`) — serialization, ID computation, PoW, the AVL+ digest, reorg
semantics, the NiPoPoW verifier — requires an oracle-backed test; PRs touching
it without fixtures will be sent back.

## Security

Pre-1.0. **Do not use this node for production infrastructure or funds
custody.** Consensus, state-integrity, remote-input crash, and cryptographic-
verdict regressions are in scope. Report privately via a GitHub Security
Advisory draft — not a public issue or PR. Findings against `sigma-rust` go
upstream (this node uses it only as a dev oracle). Full scope and process in
[`SECURITY.md`](./SECURITY.md).

## License

Every workspace crate is dual-licensed under
[MIT](https://opensource.org/license/mit) **or**
[Apache 2.0](https://opensource.org/license/apache-2-0), at your option. See
[`LICENSE-MIT`](./LICENSE-MIT) and [`LICENSE-APACHE`](./LICENSE-APACHE).
