# Overview — building, running, and the repository in depth

This is the full companion to the [README](../README.md). The README is the
front door (what the node is, what ships, a quickstart); this document is the
handbook: repository layout, the build/test/run surface in full, the
configuration reference, and the correctness discipline.

See also: [`../ARCHITECTURE.md`](../ARCHITECTURE.md) (cross-crate design),
[`codemap.md`](./codemap.md) (per-crate map), [`configuration.md`](./configuration.md)
(every config field), [`operating.md`](./operating.md) (modes + observability),
[`compatibility.md`](./compatibility.md) (consensus + versioning policy).

## Repository layout

```text
.
├── Cargo.toml                         workspace manifest (17 members, resolver v2)
├── rust-toolchain.toml                pinned toolchain (1.95.0, rustfmt + clippy)
├── deny.toml                          cargo-deny policy
├── ARCHITECTURE.md                    cross-crate architecture spec
├── CHANGELOG.md                       per-release notes (Keep a Changelog format)
├── CONTRIBUTING.md                    contribution guide, test conventions, audit tooling
├── SECURITY.md                        scope + disclosure process
├── CODE_OF_CONDUCT.md                 community expectations
├── ergo-{primitives,ser,…}/           17 workspace crates (see docs/codemap.md)
├── ergo-node/ergo-node.toml           bundled developer config
├── ergo-node/ergo-node.toml.example   operator template
├── docs/
│   ├── overview.md                    this handbook
│   ├── codemap.md + codemap/          per-crate codebase map (index + 17 pages)
│   ├── configuration.md               every config field, by type
│   ├── operating.md                   running, modes, observability
│   ├── compatibility.md               consensus-compatibility + versioning policy
│   └── architecture.md                redirect to ../ARCHITECTURE.md
├── test-vectors/
│   ├── mainnet/                       real mainnet bytes (headers, blocks, proofs)
│   ├── testnet/                       testnet equivalents
│   ├── ergo-crypto/                   Merkle, batch-multiproof, PoW vectors
│   ├── ergo-p2p/                      wire-frame fixtures (Scala-anchored)
│   ├── ergo-sigma/                    cost-table + interpreter vectors
│   ├── extra-index/                   indexer parity fixtures
│   ├── mining/                        candidate generation + reemission vectors
│   ├── primitives/                    VLQ, Digest, GroupElement edge cases
│   ├── scala/                         raw extracts to be processed by scripts/
│   └── scripts/                       per-corpus extraction helpers
├── scripts/                           Scala-oracle vector-extraction helper
└── .github/workflows/                 CI (fmt, clippy, test, audit, deny, machete)
```

## Crates and architecture

The workspace is 17 crates in a strict, acyclic dependency DAG. Rather than
duplicate per-crate descriptions here (which drift), see:

- [`codemap.md`](./codemap.md) — the layered crate table, the dependency graph,
  a "where do I find X" index, and a landmark page per crate (purpose, modules,
  key types, owned invariants, "start here").
- [`../ARCHITECTURE.md`](../ARCHITECTURE.md) — the cross-crate big picture: the
  single-writer action-loop runtime model, the data-flow paths, and the
  consensus/persistence/reorg contracts.

Two layering decisions diverge from the Scala reference and are worth knowing up
front: **`ergo-state` depends on `ergo-validation`** (state asks validation "is
this legal?", not the reverse), and **`ergo-p2p` knows nothing about chain
logic** (`ergo-sync` drives it as a passive transport).

## Correctness and compatibility

Correctness discipline is the single largest piece of investment in this
project:

- **Oracle-backed test vectors.** Consensus-boundary tests pin against
  externally-produced fixtures, not against the implementation under test.
  Vectors live under [`../test-vectors/`](../test-vectors/). The repository's
  rule: a self-oracle (`let expected = my_fn(input)`) proves only internal
  consistency; where the boundary matters (header IDs, `transactionsRoot`,
  `extensionRoot`, ErgoScript `bytes_to_sign`, `proofFor` JSON, Autolykos
  solution acceptance, AVL+ digest equality) the fixture must come from outside.
- **Mainnet bytes.** [`../test-vectors/mainnet/`](../test-vectors/mainnet/)
  holds real headers, blocks, and a captured Scala-served NiPoPoW proof. Mainnet
  observed behaviour is the tie-breaker for any parity dispute.
- **CI matrix.** [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) runs
  `cargo fmt --check`, `cargo check`, `cargo clippy --all-targets --all-features
  -- -D warnings`, and `cargo test --all` on Linux, macOS, and Windows. A
  `cost-trace` feature-gated run exercises the `ergo-sigma` instrumentation
  surface; a `diagnostics`-feature compile-only run keeps the gated triage
  harness valid.
- **Generated API spec, snapshot-tested.** The Rust-native `/api/v1/*` surface
  is OpenAPI-documented from the handler annotations (served at
  `/api-docs/openapi-native.yaml`, browsable at `/swagger/native`); a snapshot
  test pins the generated YAML against a golden file, so an un-mirrored
  handler/DTO change fails CI.
- **Supply-chain auditors.** CI runs `cargo-audit` (RustSec advisories),
  `cargo-deny` (licenses/duplicates/advisories per
  [`../deny.toml`](../deny.toml)), and `cargo-machete` (unused deps).
  `cargo-udeps` and `cargo-geiger` are operator-discretion (see
  [`../CONTRIBUTING.md`](../CONTRIBUTING.md)).
- **Vector re-extraction.** Per-corpus scripts under
  [`../test-vectors/scripts/`](../test-vectors/scripts/) regenerate the fixtures
  from a running Scala node, so drift introduced by a Scala upgrade is detectable
  by re-running them and diffing. (This requires a self-hosted, fully synced
  Scala node, so it is a manual/local step rather than hosted CI.)
- **`sigma-rust` as dev oracle, never as runtime logic.** The reference Rust
  sigma implementation cross-checks our interpreter in tests; it is never linked
  into the consensus path.

## Building

The workspace pins Rust 1.95.0 via
[`../rust-toolchain.toml`](../rust-toolchain.toml); `rustup` installs it
automatically on first build.

```bash
# Compile-check the whole workspace.
cargo check --workspace --tests

# Release builds of the two binaries.
cargo build --release -p ergo-node
cargo build --release -p ergo-wallet
```

Optional build profiles:

```bash
# Long-running oracle / CI runs (opt-level 2).
cargo test --profile oracle --workspace

# Release-equivalent + frame pointers + line-table debuginfo for
# perf / flamegraph attribution.
RUSTFLAGS="-C target-cpu=native -C force-frame-pointers=yes" \
  cargo build --profile release-prof -p ergo-node
```

## Testing

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
```

`[profile.test]` sets `opt-level = 1` to keep crypto-heavy oracle tests around
the 30 s mark (vs ~4 min at `opt-level = 0`) while preserving backtraces. CI
runs the workspace suite on Linux, macOS, and Windows on every push and PR.

Per-crate scoped tests are the fastest inner loop:

```bash
cargo test -p ergo-ser
cargo test -p ergo-validation
cargo test -p ergo-state
```

Some feature-gated surfaces require explicit invocation:

```bash
# Cost-trace recording in ergo-sigma (compile + run; CI does the same).
cargo test -p ergo-sigma --features cost-trace --test cost_trace_smoke
cargo test -p ergo-sigma --features cost-trace --test traced_untraced_parity

# Diagnostics-feature triage tests are compile-only in CI (need external state).
cargo test --no-run -p ergo-validation --features diagnostics
```

Test conventions (full detail in [`../CONTRIBUTING.md`](../CONTRIBUTING.md)):
`#[cfg(test)] mod tests` blocks use a fixed section ordering (helpers, happy
path, round-trips, error paths, oracle parity); test names follow
`<subject>_<scenario>_<expected>` so a CI failure line conveys what broke
without opening the file.

## Running

```bash
# Run against the bundled developer config.
./target/release/ergo-node --config ergo-node/ergo-node.toml

# Or as a one-shot dev run via cargo.
cargo run --release -p ergo-node -- --config ergo-node/ergo-node.toml

# CLI help.
ergo-node --help
```

With the bundled developer config the node:

- Connects on **mainnet** (P2P port 9030).
- Persists state under `./ergo-data/` by default.
- Serves the REST API on `127.0.0.1:9099`. `/wallet/*` and `/node/shutdown`
  require an `api_key` request header that Blake2b-256-hashes to the configured
  `[api.security].api_key_hash` (mandatory at config-load whenever the API
  server is enabled).
- Serves browser UIs at `/` (operator dashboard) and `/wallet/ui` (wallet), plus
  Swagger UIs at `/swagger` (Scala-compatible surface) and `/swagger/native`
  (operator `/api/v1/*` surface).
- Uses the bundled mainnet seed list plus any `[peers].known`.

The first run performs an Initial Block Download (IBD) from genesis; subsequent
runs resume from the persisted tip. For a fast clean-DB boot, combine Mode 2 +
NiPoPoW (see Configuration). CLI flags override TOML keys override defaults.

The wallet binary ships separately for HD key derivation and operator mnemonic
flows:

```bash
./target/release/ergo-wallet --help
```

### Observability

The node uses `tracing` with a stderr layer plus an optional non-lossy rolling
file appender (`[logging]` / `[logging.file]`). Setting `ERGO_MEM_CSV=<path>`
enables a memory sampler that appends one row per tick to a CSV (useful for IBD
memory profiling), with a sidecar marker CSV recording lifecycle events.

## Configuration

The bundled developer config is
[`../ergo-node/ergo-node.toml`](../ergo-node/ergo-node.toml); an operator
template lives next to it as `ergo-node.toml.example`. Every field is documented
by type in [`configuration.md`](./configuration.md). The high-level shape:

```toml
network  = "mainnet"            # or "testnet"
# data_dir = "./ergo-data"      # default; node DB + logs

[node]
agent_name = "opus"
node_name  = "your-node"

# Mode-selection knobs (defaults shown; omit to keep Mode 1 full archive):
# state_type           = "utxo"  # "utxo" | "digest" (Mode 5 / 6)
# verify_transactions  = true    # false ⇒ Mode 6 (headers-only, requires digest)
# blocks_to_keep       = -1      # -1 archive | N>0 pruned (Mode 3)

[node.utxo]
utxo_bootstrap = false          # true ⇒ Mode 2: jump to UTXO snapshot at boot

[node.nipopow]
nipopow_bootstrap = false       # true ⇒ NiPoPoW: jump to proof tip at boot
p2p_nipopows      = 2           # quorum threshold (matches Scala mainnet)

[chain]
# genesis_id = "b0244dfc…"      # 32-byte hex; defaults to mainnet's genesis

[peers]
known           = ["213.239.193.208:9030", "159.65.11.55:9030"]
target_outbound = 60
max_connections = 80

[mining]
enabled = false                 # external-miner candidate API (GET /mining/candidate,
                                # POST /mining/solution). Requires state_type = "utxo"
                                # (Modes 1–4); rejected at config-load on "digest"
                                # (Modes 5–6), which keep no UTXO box store. Serves
                                # candidates only once synced to tip.
# miner_public_key_hex = "02…"  # 33-byte compressed hex reward key; omit ⇒ use the
                                # wallet's first EIP-3 key (read from the persisted tracked-
                                # pubkey store — a LOCKED but initialized wallet still mines)
# claim_storage_rent = true     # auto-collect storage rent into the candidate; requires
                                # [indexer] enabled (Mode 1) and a chain past one storage
                                # period (mainnet only — testnet is too young)

[indexer]
enabled = true                  # /blockchain/* extra-index parity surface
                                # (requires Mode 1; rejected on pruned/bootstrap/digest)

[logging]
default_level = "info"

[logging.file]
dir       = "."
prefix    = "ergo-node"
rotation  = "never"
max_files = 1
```

For a fast clean-DB boot, combine Mode 2 with the NiPoPoW bootstrap:

```toml
[node.utxo]
utxo_bootstrap = true

[node.nipopow]
nipopow_bootstrap = true
```

End-to-end this has been measured at roughly 20 minutes on mainnet versus a
multi-hour full IBD. Operators should still cross-check the installed UTXO root
against a known-good manifest before treating the state as authoritative — the
Mode 2 trust anchor is provisional pending a Scala-oracle vector.

Configuration is unstable until 1.0: keys and shapes may change between minor
versions. See [`compatibility.md`](./compatibility.md) for the versioning
policy.

## Development workflow

Contributor invariants are documented in
[`../CONTRIBUTING.md`](../CONTRIBUTING.md). The short version:

- Consensus compatibility is non-negotiable; cleverness is not a reason to
  diverge from Scala-observed behaviour.
- Prefer correctness and clarity over abstraction; explicit Rust ownership beats
  framework indirection.
- Keep changes focused; split changes that touch multiple subsystems.
- Add tests alongside behaviour changes. Consensus-critical
  encoding/hashing/validation changes need an externally-produced fixture, not a
  self-oracle.
- Run `cargo fmt`, `cargo clippy --all-targets --all-features -- -D warnings`,
  and `cargo test --workspace` before submitting.
- Source comments describe present invariants; changelog/roadmap framing belongs
  in `CHANGELOG.md`, not in `.rs` files.

## Roadmap

Subsystem-by-subsystem parity status lives in
[`compatibility.md`](./compatibility.md). Near-term work identified but not yet
finished:

- **Mode 4 (pruned + UTXO bootstrap)** — the combo config is accepted and
  `install_snapshot_state` seeds the prune sentinel (Mode 2 + Mode 3 compose);
  the composed both-bootstrap lifecycle (`ergo-node/tests/mode4_acceptance.rs`
  Rows A/C) needs the remaining cross-crate boot plumbing.
- **Mode 5 (digest verifier) hardening** — boots end-to-end through the digest
  apply path; remaining: external Scala ADProof-corpus parity, genesis-block
  body validation, intermediate voted-params epoch continuity, bounded history
  retention, reorg-abort rebuild coverage.
- **Cooperative distributed multi-sig** — primitives + hint-replay ship; the
  `DistributedSigSpecification` round protocol is deferred.
- **HTTPS for peer REST URLs** — currently only `http://` peer-advertised REST
  endpoints are accepted; TLS pulls in `rustls` and is deferred.

The roadmap is conservative on purpose.
