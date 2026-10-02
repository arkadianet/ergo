# Contributing

Thanks for your interest in contributing. This is an independent, from-scratch
Rust reimplementation of an Ergo full node. It targets strict consensus
compatibility with the Scala reference node — but it is **not** the reference
node, and it is pre-1.0 alpha software. The guidance below is everything you
need to build, test, and submit changes; it is self-contained.

## Project goals

- Consensus compatibility with the Scala reference node is non-negotiable.
- Prefer conservative correctness and clarity over cleverness. When a fix feels
  hacky, reach for the clean solution.
- Use proven crypto crates (`k256`, `blake2`, `sha2`, `pbkdf2`, `aes-gcm`,
  `num-bigint`, `gf2_192`). Do not roll your own primitives.
- For consensus-boundary changes, tests must be oracle-backed (Scala-produced
  fixtures or mainnet bytes), never self-oracles.

See [`docs/architecture.md`](./docs/architecture.md) for the crate layering and
data flow, and [`docs/compatibility.md`](./docs/compatibility.md) for what
"consensus-compatible" means here and where the known gaps are.

## Prerequisites

The toolchain is pinned to **Rust 1.95.0** via
[`rust-toolchain.toml`](./rust-toolchain.toml) at the repo root. `rustup`
installs it (with `rustfmt` and `clippy`) automatically on first build, so you
do not need to select a toolchain by hand. The workspace is edition 2021.

CI reads the stable compiler directly from `rust-toolchain.toml`. Every member
inherits the workspace's `rust-version` requirement (currently 1.95.0) and lint
policy. When raising the compiler requirement, update the toolchain channel and
workspace `rust-version` together; `scripts/ci-policy.py` rejects drift. The
compiler pin selects the development toolchain; `rust-version` tells downstream
users the minimum supported compiler.

## Build

```bash
# Compile-check the whole workspace, tests included.
cargo check --locked --workspace --tests

# Release builds of the two shipped binaries.
cargo build --locked --release -p ergo-node
cargo build --locked --release -p ergo-wallet
```

## Test workflow

Run the full local gate before submitting — it mirrors CI:

```bash
cargo fmt --all -- --check
python3 scripts/check-rust-fragments.py
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace
RUSTDOCFLAGS="-D warnings" cargo doc --locked --workspace --all-features --no-deps
python3 scripts/ci-policy.py
python3 -m unittest discover -s scripts -p 'test_release*.py'
```

`clippy` runs with `-D warnings`: a warning is a failure. If a lint trips after
your change, fix the root cause — do not `#[allow(...)]` it away. The workspace
forbids unsafe code and warns on
`dbg!`. It intentionally permits test unwraps and avoids blanket pedantic lint
sets. Public Rustdoc links and HTML must resolve, and strict docs build with all
features. Private helper references in public docs should be code text, not links
to pages downstream users cannot open.

### Per-crate inner loop

Scoped tests are the fastest iteration loop while you work on one crate:

```bash
cargo test --locked -p ergo-ser
cargo test --locked -p ergo-validation
cargo test --locked -p ergo-state
```

### Feature-gated tests

Two surfaces need explicit feature flags to compile and run; the default
`cargo test --locked --workspace` does not build them:

```bash
# Cost-trace recording in ergo-sigma (CI runs exactly these two tests).
cargo test --locked -p ergo-sigma --features cost-trace --test it cost_trace_smoke
cargo test --locked -p ergo-sigma --features cost-trace --test it traced_untraced_parity

# Diagnostics-feature triage tests. CI compiles these only (--no-run) because
# they need external state (mainnet captures, captured block JSON, a running
# Scala node). Run them locally only if you have that state.
cargo test --locked --no-run -p ergo-validation --features diagnostics
cargo test --locked --no-run -p ergo-mempool    --features diagnostics
cargo test --locked --no-run -p ergo-ser        --features diagnostics
```

### Differential testing

CI runs the `ergo-difftest` structured campaign on every push and pull request:

```bash
cargo run --locked --release -p ergo-difftest -- --structured --iters 50000 --min-coverage 0.80
```

This checks wire-decoder invariants across all `ergo-ser` surfaces (no panics,
encode–decode fixed point) and enforces that every generator produces adversarial
inputs at the expected rate (≥ 80 % of the declared vocabulary). An invariant
violation or a generator falling below the coverage threshold fails CI. The
harness unit tests (`tests/it/smoke.rs`, `tests/it/selftest.rs`) are exercised by
the standard `cargo test --locked --workspace` run above and do not need a
Scala oracle.

### Test profiles

Defined in the workspace [`Cargo.toml`](./Cargo.toml):

| Profile | Inherits | `opt-level` | Use |
|---|---|---|---|
| `test` | — | `1` | Default for `cargo test --locked`. Keeps crypto-heavy oracle tests near ~30 s instead of ~4 min at `opt-level = 0`, while preserving backtraces. |
| `oracle` | `test` | `2` | Long-running oracle / CI runs: `cargo test --locked --profile oracle --workspace`. |
| `release-prof` | `release` | — | Release-equivalent plus frame pointers and line-table debuginfo so `perf`/flamegraph can attribute samples. |

The profiling build:

```bash
RUSTFLAGS="-C target-cpu=native -C force-frame-pointers=yes" \
  cargo build --locked --profile release-prof -p ergo-node
```

## Audit tooling

Three auditors run in CI on every push and pull request. Treat a local failure
the same as a `clippy -D warnings` failure: stop, diagnose, fix the dependency
tree — do not silence the tool.

Install the exact auditor releases from [`.github/ci-tools.toml`](.github/ci-tools.toml).
`--version` pins the tool release; `--locked` uses that release's dependency
lockfile. CI uses both, and the shared action exposes these same versions:

```bash
python3 - <<'PYTOOLS'
import subprocess, tomllib
with open(".github/ci-tools.toml", "rb") as source:
    versions = tomllib.load(source)["tools"]
for name in ("deny", "audit", "machete"):
    subprocess.run(["cargo", "install", f"cargo-{name}", "--version",
                    versions[name], "--locked"], check=True)
PYTOOLS
```

| Tool | Command | Checks | When |
|---|---|---|---|
| `cargo-deny` | `cargo deny check` | Licenses, duplicate deps, RustSec advisories, source gating. Config in [`deny.toml`](./deny.toml). | CI (every push/PR); locally before submitting dependency changes. |
| `cargo-audit` | `cargo audit --deny warnings --ignore RUSTSEC-2025-0141` | RustSec advisory database against `Cargo.lock`. | CI (every push/PR). |
| `cargo-machete` | `cargo machete` | Unused dependencies (stable Rust). | CI (every push/PR). |
| `cargo-udeps` | `cargo +nightly udeps --workspace` | Unused dependencies (nightly; stricter — catches feature-gated deps machete misses). | Not in CI. Run before a release-train cut. |
| `cargo-geiger` | `cargo geiger` | `unsafe`-code surface report. Informational, no pass/fail. | Not in CI. Diff against the previous run before merging any PR that adds `unsafe`. |

## Test conventions

These conventions keep tests scannable and keep consensus claims honest.

**Where tests live.**

- Unit tests go in a `#[cfg(test)] mod tests` block inside the same `.rs` file —
  they need access to private items.
- Integration tests live in the per-crate `tests/it/` binary (`tests/it/main.rs`
  plus modules, declared as `[[test]] name = "it"`) — public API only, written
  from the perspective of a downstream user. Standalone `tests/<name>.rs`
  binaries are reserved for feature-gated diagnostics/triage targets that need
  their own harness.

**Section dividers.** Inside any `mod tests` block, use these dividers in this
fixed order so a reader can scan top-to-bottom:

```rust
// ----- helpers -----
// ----- happy path -----
// ----- round-trips -----
// ----- error paths -----
// ----- oracle parity -----
```

**Naming.** `<subject>_<scenario>_<expected>`, e.g. `vlq_u32_max_roundtrips`,
`get_u8_truncated_input_errors`,
`apply_block_at_activation_advances_validation_settings`. The test name alone,
in a CI failure line, must convey what broke without opening the file.

**Self-containment.** Each test is independent: no order dependence (cargo runs
in parallel, non-deterministically), no shared mutable state, no leftover files
outside `tempfile::tempdir()`.

**Oracle-parity rule.** For codecs, hashes, IDs, and any byte-format that must
agree with the Scala reference node or sigma-state, the expected value MUST come
from an external oracle (Scala node REST, mainnet block bytes, sigma-state
vector) — never from `let expected = my_fn(input)`. A self-oracle proves
internal consistency, not correctness. Oracle vectors live under
`test-vectors/` so they stay re-extractable from a Scala node rather than buried
as inline literals without provenance. The boundaries where an oracle-backed
test is mandatory include header IDs, `transactionsRoot`, `extensionRoot`,
ErgoScript `bytes_to_sign`, `proofFor` JSON, Autolykos solution acceptance, and
AVL+ digest equality. PRs that touch consensus-critical code without an
oracle-backed test will be sent back for fixtures.

## Consensus-compatibility non-negotiables

This node aims to **accept every block the Scala reference node accepts and
reject every block it rejects**. Compatibility is a property of observable
inputs and outputs, enforced by tests — not of internal code structure, which is
deliberately independent. Three rules follow from that:

- **Conservative correctness over cleverness.** Mainnet-observed behavior is the
  authoritative tie-breaker for any parity dispute. When in doubt, match what the
  reference node does on mainnet.
- **Test oracles are ranked, and only external oracles count for consensus.**
  Mainnet bytes are the strongest signal; the Scala reference node is the
  practical accept/reject oracle (fixtures under `test-vectors/` are
  re-extractable from a running Scala node). `sigma-rust` is a **dev/test oracle
  only** — it is used in tests to cross-check the interpreter and is **never**
  linked into the consensus path. Findings against `sigma-rust` belong upstream,
  not here.
- **Proven crypto only.** Consensus and wire crypto go through audited crates;
  no hand-rolled primitives.

If you are touching consensus-critical surfaces — serialization/IDs, PoW, the
interpreter, AVL+ state, validation rules, reorg/storage, or the test oracles —
read [`docs/compatibility.md`](./docs/compatibility.md) first. It documents the
verified surfaces, how parity is checked against the Scala reference node and
mainnet, and the areas where parity is still incomplete.

Release packaging and exact-tag validation are documented in
[`docs/releasing.md`](docs/releasing.md). Python tooling requires Python 3.11+. CI also runs the browser model and voting
regressions with the Node.js release pinned in `.github/ci-tools.toml`:

```sh
node --experimental-default-type=module --test ergo-api/web/tests/*.test.mjs
node scripts/test-voting-ui.cjs
```

## Pull requests

- Keep PRs focused. If a change touches multiple subsystems, split it. A single
  PR should touch a small, reviewable set of files.
- Include a short test plan in the description: which commands you ran and what
  passed.
- Before submitting, run the full local gate (`fmt --check`,
  `clippy -D warnings`, `cargo test --locked --workspace`, strict Rustdoc) and
  confirm it is green.
- If you change any consensus-critical encoding, hashing, or validation logic,
  add or update an oracle-backed test vector — see the oracle-parity rule above.
- Commit messages should explain the *why*, not restate the diff. Code comments
  describe present invariants, not rename or refactor history (that belongs in
  the git log).

## Reporting bugs

- Include the exact commit hash and your OS.
- Include the raw logs and panic backtrace, if any. Work from the raw output —
  it finds the real problem faster than a paraphrase.
- For a consensus or parity issue, include the smallest reproducible input
  (bytes or a fixture) and what the Scala reference node does with it.

For security-sensitive reports (consensus, state-integrity, remote-input
crash/DoS, or cryptographic-verdict issues), do **not** open a public issue —
follow [`SECURITY.md`](./SECURITY.md).
