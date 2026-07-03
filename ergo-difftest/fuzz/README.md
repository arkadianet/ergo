# ergo-difftest fuzz targets

> **NIGHTLY ONLY.** These targets require `cargo-fuzz` and a nightly Rust
> toolchain. They are NOT part of the stable CI gate (see D1 in
> `ergo-difftest/docs/interface-contracts.md §6`).

## Quick start

```bash
# Install cargo-fuzz (requires nightly toolchain installed via rustup)
rustup toolchain install nightly
cargo install cargo-fuzz

# Run a surface with the committed seed corpus
cargo +nightly fuzz run fuzz_ergo_tree -- -seed_inputs=corpus/ergo_tree
cargo +nightly fuzz run fuzz_constant  -- -seed_inputs=corpus/constant

# All surface names
cargo +nightly fuzz list
```

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
cargo +nightly fuzz run fuzz_ergo_tree -- \
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

## JVM oracle differential

The JVM-oracle differential (`difftest --oracle`) and the replay driver
(`difftest --replay`) are NOT in CI — they require `scala-cli` + a live Scala
node (`localhost:9053`). Run them manually as documented in
`ergo-difftest/docs/interface-contracts.md`.
