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
  index, the dependency graph, and a landmark page for each of the 17 crates
  (purpose, modules, key types, invariants, "start here").
- [`docs/overview.md`](./docs/overview.md) — the handbook: repository layout and
  the full build / test / run / configure surface.
- [`docs/configuration.md`](./docs/configuration.md) — every config field, by type.
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
| Mode 4 — Pruned + UTXO bootstrap | yes | partial (Mode 2 + Mode 3 pieces compose; composed-lifecycle plumbing open) |
| Mode 5 — Digest verifier (AD-proof tx validation) | yes | yes (boots end-to-end; external ADProof-corpus parity + reorg-abort hardening remain) |
| Mode 6 — Headers-only | yes | yes |
| NiPoPoW bootstrap (consume + serve) | yes | yes |
| Extra-index (`/blockchain/*`) | yes | yes (requires Mode 1) |
| Mining — external-miner protocol | yes | yes; requires `state_type = "utxo"` (Modes 1–4), rejected on `digest` (Modes 5–6) |
| HD wallet | yes | yes (single-prover + multi-sig primitives; cooperative distributed multi-sig deferred) |

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
# Build the node + wallet binaries.
cargo build --release -p ergo-node -p ergo-wallet

# Run against the bundled developer config (mainnet; REST on 127.0.0.1:9099).
./target/release/ergo-node --config ergo-node/ergo-node.toml

# CLI help.
./target/release/ergo-node --help
```

The first run performs a full Initial Block Download from genesis; subsequent
runs resume from the persisted tip. For a ~20-minute clean-DB boot, enable Mode
2 + NiPoPoW. The full build / test / run / configuration surface — profiles,
feature-gated tests, the config reference, observability — is in
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
