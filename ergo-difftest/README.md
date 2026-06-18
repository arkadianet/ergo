# ergo-difftest

A fuzzing harness for the Ergo consensus **wire-format decoders** (`ergo-ser`).
It exists to find the class of node-vs-Scala divergences that a SANTA grade or a
state-root soak *won't* surface — rare/adversarial inputs where the Rust node and
the Scala reference disagree (e.g. the STypeVar UTF-8 and off-curve-GroupElement
findings).

Two layers:

## Phase 1 — oracle-free invariants (hermetic, runs in CI)

Generates and mutates bytes, runs them through the decoders, and checks:

* **no decode panics** (`catch_unwind`) — the panic class, e.g. a write-overflow,
* **parse → serialize fixed point** — decode, re-encode, re-decode must reach a
  byte-stable fixed point (catches non-canonical / echo-trap re-encoding).

```
cargo run -p ergo-difftest -- --iters 1000000 --seed 7
cargo run -p ergo-difftest -- --surface ergo_tree --corpus test-vectors/mainnet
cargo run -p ergo-difftest -- --repro 1b1501040a…     # triage one input
cargo run -p ergo-difftest -- --selftest              # prove the detector has teeth
```

Determinism: a `(seed, iter)` pair reproduces an identical input; every finding
prints a `--repro <hex>`. `tests/smoke.rs` and `tests/selftest.rs` are the CI
regression guards (no `scala-cli` needed).

## Phase 2 — differential vs the JVM reference (`--oracle`)

Spawns the Scala serde oracle once and streams inputs over a pipe, diffing the
node's verdict against the JVM's:

* **accept/reject mismatch** — one side parses, the other refuses. The
  stall (reject-valid) / fork (accept-invalid) class.
* **canonical mismatch** — both accept but re-serialize differently (soft-fork
  "unparsed" trees are filtered; box/tx canonical is not compared because the
  node retains the original ergoTree slice).

```
cargo run -p ergo-difftest -- --oracle --iters 2000 --corpus test-vectors/mainnet
```

Differential surfaces (context-complete consensus units):
`ergo_tree`, `ergo_box_candidate`, `transaction`, `header`. Bare `sigma_type` /
`constant` are intentionally **not** differential surfaces — the node's type/value
codec is version-gated *inside a tree*, so testing it context-free over-reports;
those codecs are exercised in-context via `ergo_tree`/`ergo_box_candidate`.

### Oracle setup (one-time)

`scripts/jvm_serde_oracle/ErgoSerdeOracle.scala` runs the real `sigma-state` +
`ergo-core` the node mirrors (version 6.0.2). `sigma-state` is on Maven;
`ergo-core` (transaction/header) is not, so publish it locally first:

```
cd <ergo reference checkout>
sbt "avldb/publishLocal" "ergoWallet/publishLocal" "ergoCore/publishLocal"
```

(`avldb` pulls `leveldbjni-all` from the GitLab repo declared in the `.scala`
`using repository` directive.) Needs `scala-cli` on `PATH`; the first `--oracle`
run resolves deps and compiles (~1 min), then queries are fast.

## Corpus

`--corpus <dir>` loads seeds for mutation: `.hex` files (one hex string),
`.json` files (every quoted hex value — covers the test-vector `bytes`/`ergoTree`
fields), or raw bytes otherwise. Pointing at `test-vectors/mainnet` mutates real
mainnet trees/boxes/txs/headers — the high-yield mode (bugs cluster near the
valid manifold).

## Promote findings to regression tests

A confirmed divergence becomes a committed oracle-parity test in `ergo-ser`
(seed + hex + the JVM-blessed expected), the same convention as
`scripts/scala_hamt_oracle`. The fuzzer is the searchlight; committed vectors are
the ratchet.
