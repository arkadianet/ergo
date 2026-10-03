# ergo-difftest fuzz targets

> **NIGHTLY ONLY.** These targets require `cargo-fuzz` and a nightly Rust
> toolchain. PR CI checks their separate lockfile with the pinned nightly;
> the targets' longer build/run campaigns remain scheduled.

## Quick start

```bash
# Install a nightly toolchain (do NOT touch rust-toolchain.toml — it stays
# pinned to stable 1.95.0 for the rest of the workspace) and cargo-fuzz.
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz --locked

# From ergo-difftest/fuzz/ (or ergo-difftest/, cargo-fuzz finds the sibling
# fuzz/ dir either way):
cd ergo-difftest/fuzz

# Resolve this separate workspace against its committed dependency lock.
cargo +nightly metadata --locked --format-version 1 > /dev/null

# Build every target (ASan-instrumented, release).
cargo +nightly fuzz build

# Run one target with the committed seed corpus for a bounded time budget
# (seconds) or a bounded run count — either works, pick one:
cargo +nightly fuzz run ergo_tree -- -max_total_time=60
cargo +nightly fuzz run constant -- -runs=20000

# cargo-fuzz has no --locked flag; check that its build preserved the lock.
# CI performs this check even when a fuzz target reports a crash.
git diff --exit-code -- Cargo.lock

# All surface/target names
cargo +nightly fuzz list

# If a run finds a crash, minimize the failing input before filing an issue:
cargo +nightly fuzz tmin <target> fuzz/artifacts/<target>/crash-<hash>
# (run from ergo-difftest/, so the artifact path above is
#  ergo-difftest/fuzz/artifacts/<target>/crash-<hash>)
```

`fuzz/artifacts/` and `fuzz/target/` are gitignored — crash inputs never get
committed by accident. When a crash reproduces, do not fix the underlying
code in the same change that wires up fuzzing: minimize it, file an issue
with the minimized hex and the reproduction command, and let the fix land
separately. Two such bugs were found bringing this suite up for the first
time — see [CI](#ci-cargo-fuzz-nightly) below.

## Why nightly?

`cargo-fuzz` wraps `libFuzzer`, which ships as part of the LLVM distribution
bundled with the Rust nightly compiler. The stable toolchain (pinned 1.95.0)
does not include `libFuzzer`. See [cargo-fuzz docs](https://rust-fuzz.github.io/book/).

## Architecture

The real invariant logic is in **`ergo-difftest/src/fuzz.rs`**, compiled on
stable and unit-tested in `cargo test -p ergo-difftest`. Each target file
(`fuzz_targets/*.rs`) is a 3-line nightly shim:

```rust
fuzz_target!(|data: &[u8]| {
    ergo_difftest::fuzz::fuzz_one("<surface>", data);
});
```

A panic in `fuzz_one` (which means `Outcome::Bug`) is treated as a crash by
libFuzzer and the input is saved to `artifacts/<target>/`. The `fuzz.rs`
module is covered by the stable CI gate via unit tests, so coverage-guided
mutation adds real signal on top of an already-validated invariant.

The P2P targets use `ergo-difftest/src/network_fuzz.rs`, also compiled and tested
on stable, against the production `ergo-p2p` codecs:

- `p2p_frame` checks both network magics, signed lengths, checksums, consumed
  boundaries and selected fragmented prefixes. It also wraps arbitrary payloads
  in a valid checksum to reach message decoders.
- `p2p_handshake` exercises strings, declared addresses, signed feature counts,
  unknown features and the production handshake size limit.
- `p2p_message` interprets the first input byte as a message code and checks the
  canonical fixed point of accepted inventory, modifiers, peers, sync, snapshot
  and NiPoPoW payloads. Unknown codes and malformed payloads are clean outcomes.
- `p2p_delivery` drives the production modifier delivery tracker through
  requests, saturated batches, arrivals, duplicates, timeout checks, early
  reassignments, disconnects, forgetting and hedged requests. An independent
  ownership ledger checks per-peer capacity, request timestamps/types, timeout
  boundaries and cancellation after each operation.

Frame/message inputs are bounded to 1 MiB of supplied bytes, while declared
lengths are unrestricted. Handshake inputs retain one byte beyond the production
cap to exercise oversized admission. These are codec and framing checks, not TCP
timing, consensus acceptance or Scala verdict claims. They do not change the
consensus structured campaign's vocabulary or coverage denominator.

The delivery target uses five-byte instructions: operation, peer, little-endian
modifier index, argument. Operations are selected modulo ten; four peers and
4096 modifier ids keep memory bounded, and at most 128 instructions execute.
The clock advances only through encoded offsets (including the timeout and late
allowance boundaries). The received set fits inside the production dedupe
window. A history of requested senders checks never-solicited arrivals without
reimplementing the late allowance expiry or retry policy. This is a state-machine
robustness check; it does not simulate TCP scheduling or assert Scala parity.

## Corpus

`corpus/<surface>/` contains small curated seed files:

| Surface             | Seeds                                            |
|---------------------|--------------------------------------------------|
| `ergo_tree`         | Decoded `failing_tree_*.hex` + `fee_proposition` |
| `sigma_expr`        | Same trees (shares the `ergo_tree` decoder)      |
| `constant`          | SBoolean true/false, SInt 42                     |
| `header`            | One real mainnet v1 header (height 1)            |
| `transaction`       | First genesis-era transaction                    |
| `ergo_box_candidate`| One mainnet box candidate                        |
| `p2p_frame`         | Scala framing vectors, negative/maximal declared lengths |
| `p2p_handshake`     | Minimal synthetic handshake and negative feature count |
| `p2p_message`       | Scala payload vectors and synthetic seeds for every registered code |
| `p2p_delivery`      | Synthetic saturation, hedge/late delivery, disconnect/retry and timeout-boundary sequences |

P2P files named `scala-*` are decoded from the existing external vectors under
`test-vectors/ergo-p2p/`; their provenance is retained in that directory's
`PROVISIONING.md`. Files named `synthetic-*` and the minimal handshake are mutation
seeds, not independent consensus oracles.

The nightly scheduled CI job (`fuzz.yml`) runs a long campaign and may grow
this corpus. Growing/pruning the corpus is manual; commit curated inputs that
help libFuzzer find interesting coverage quickly.

### Growing the corpus

```bash
# Seed from a larger set of real vectors (mutation basis, not committed)
cargo +nightly fuzz run ergo_tree -- \
  -seed_inputs=corpus/ergo_tree            \
  -corpus=corpus/ergo_tree                 \
  -jobs=4
```

## Pinned CI setup and lock maintenance

Use the versions in [`.github/ci-tools.toml`](../../../.github/ci-tools.toml)
to reproduce CI. From the repository root:

```bash
FUZZ_TOOLCHAIN=$(python3 -c 'import tomllib; print(tomllib.load(open(".github/ci-tools.toml", "rb"))["toolchains"]["fuzz"])')
FUZZ_VERSION=$(python3 -c 'import tomllib; print(tomllib.load(open(".github/ci-tools.toml", "rb"))["tools"]["fuzz"])')
rustup toolchain install "$FUZZ_TOOLCHAIN" --profile minimal
cargo install cargo-fuzz --version "$FUZZ_VERSION" --locked
cargo +"$FUZZ_TOOLCHAIN" metadata --manifest-path ergo-difftest/fuzz/Cargo.toml \
  --locked --format-version 1 > /dev/null
```

When a workspace dependency changes, update the detached lock with Cargo,
then rerun the locked precheck and affected targets. For example:

```bash
cargo +"$FUZZ_TOOLCHAIN" update --manifest-path ergo-difftest/fuzz/Cargo.toml \
  -p num-bigint --precise 0.5.1
cargo +"$FUZZ_TOOLCHAIN" metadata --manifest-path ergo-difftest/fuzz/Cargo.toml \
  --locked --format-version 1 > /dev/null
```

Use the changed dependency's package and version in the update command. Commit
both workspace lockfiles together; do not edit lockfile package entries by hand.

## PR CI gates

The stable, hermetic campaign runs on every PR/push via the `difftest` job
in `.github/workflows/ci.yml`:

```bash
cargo run --locked --release -p ergo-difftest -- --structured --iters 50000 --min-coverage 0.80
```

The separate `fuzz-dependencies` job resolves `fuzz/Cargo.toml` with the pinned
nightly and `cargo metadata --locked`, so a dependency update cannot leave the
detached fuzz lock stale. It does not build or run libFuzzer. The scheduled job
in `fuzz.yml` runs a longer campaign (2 000 000 iters + corpus mutation) and is
not a PR gate.

## CI: cargo-fuzz (nightly)

The `cargo-fuzz-nightly` job in `.github/workflows/fuzz.yml` builds and runs
all consensus and P2P targets on a real nightly toolchain — a `fail-fast: false` matrix, one
job per target, each capped at `-max_total_time=600` (10 minutes) seeded
from the committed `corpus/<target>/`. This build/run job runs only on the
nightly cron (02:00 UTC) and `workflow_dispatch`, and does not block PRs. PR CI
separately validates the detached dependency lock with the same nightly.

A crash (`-error_exitcode=1`) fails that matrix leg. On failure the job
uploads `fuzz/artifacts/<target>/` as a workflow artifact
(`fuzz-crash-<target>`) for triage; the (possibly coverage-grown) corpus
directory is uploaded unconditionally as `fuzz-corpus-<target>` so an
operator can review new inputs and fold curated ones back into the committed
seed corpus by hand.

### First-run results (local, nightly toolchain, `-max_total_time=60` per target)

| Target                | Runs (in 60s)   | Result                                    |
|------------------------|-----------------|--------------------------------------------|
| `ergo_tree`            | 1,031,310       | clean                                       |
| `constant`              | crashed @ ~1,656,098 | **bug found** — see arkadianet/ergo#304 |
| `ergo_box_candidate`    | crashed @ ~70,309    | **bug found** — see arkadianet/ergo#305 |
| `transaction`          | 1,363,878       | clean                                       |
| `header`               | 5,454,733       | clean                                       |
| `sigma_expr`            | 489,380         | clean                                       |

All 6 targets built cleanly on the first try (no shim breakage). The two
crashes are real, hermetic `ergo-difftest` invariant violations (round-trip
and fixed-point checks — see `ergo-difftest/src/fuzz.rs`), minimized with
`cargo fuzz tmin`, and tracked as issues rather than fixed alongside this CI
wiring (see arkadianet/ergo#304 and arkadianet/ergo#305 for the minimized
reproducers and full details).

## JVM oracle differential

The nightly workflow schedules a JVM consensus differential campaign with a
recorded seed, reference version and oracle transcripts. Its separate archival
state-root replay job requires `REPLAY_NODE_URL` and explicitly reports when
that endpoint is unset. Neither workflow wiring nor a skipped replay is a
successful external campaign receipt. Local oracle setup is documented in
`ergo-difftest/docs/interface-contracts.md`.
