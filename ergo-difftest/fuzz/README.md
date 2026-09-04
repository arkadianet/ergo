# ergo-difftest fuzz targets

> **NIGHTLY ONLY.** These targets require `cargo-fuzz` and a nightly Rust
> toolchain. They are NOT part of the stable CI gate (see D1 in
> `ergo-difftest/docs/interface-contracts.md §6`).

## Quick start

```bash
# Install a nightly toolchain (do NOT touch rust-toolchain.toml — it stays
# pinned to stable 1.95.0 for the rest of the workspace) and cargo-fuzz.
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz --locked

# From ergo-difftest/fuzz/ (or ergo-difftest/, cargo-fuzz finds the sibling
# fuzz/ dir either way):
cd ergo-difftest/fuzz

# Build every target (ASan-instrumented, release).
cargo +nightly fuzz build

# Run one target with the committed seed corpus for a bounded time budget
# (seconds) or a bounded run count — either works, pick one:
cargo +nightly fuzz run ergo_tree -- -max_total_time=60
cargo +nightly fuzz run constant -- -runs=20000

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

## Stable CI gate

The stable, hermetic campaign runs on every PR/push via the `difftest` job
in `.github/workflows/ci.yml`:

```bash
cargo run --release -p ergo-difftest -- --structured --iters 50000 --min-coverage 0.80
```

This is the gating check. The nightly scheduled job in `fuzz.yml` runs a
longer campaign (2 000 000 iters + corpus mutation) and is NOT gating — it
finds new bugs over time without blocking PRs.

## CI: cargo-fuzz (nightly)

The `cargo-fuzz-nightly` job in `.github/workflows/fuzz.yml` builds and runs
all 6 targets on a real nightly toolchain — a `fail-fast: false` matrix, one
job per target, each capped at `-max_total_time=600` (10 minutes) seeded
from the committed `corpus/<target>/`. `ci.yml` (the PR gate) is untouched
and stays stable-only; this job runs only on the nightly cron (02:00 UTC)
and `workflow_dispatch`, and does not block PRs.

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

The JVM-oracle differential (`difftest --oracle`) and the replay driver
(`difftest --replay`) are NOT in CI — they require `scala-cli` + a live Scala
node (`localhost:9053`). Run them manually as documented in
`ergo-difftest/docs/interface-contracts.md`.
