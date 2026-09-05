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

Phase 1 covers **every standalone** `ergo-ser` wire decoder: the block/header
sections (`header`, `block_transactions`, `extension`, `popow_header`,
`nipopow_proof`), the transaction tree (`transaction`, `unsigned_transaction`,
`ergo_box`, `ergo_box_candidate`, `ergo_tree`, `sigma_type`, `constant`), the
input/proof/register sub-structures (`input`, `unsigned_input`,
`context_extension`, `spending_proof`, `register`), and the leaf codecs
(`ad_proofs`, `token`, `nbits_difficulty`, `autolykos_v1`, `autolykos_v2`,
`batch_merkle_proof`). Version-parameterised readers (Autolykos) get one surface
per version; `()`-returning writers are wrapped to fit the fixed-point check.
Codecs that only ever appear *nested* inside another (`data_input`,
`token_indexed`, `read_value`) are exercised in-context via their containing
surface, not standalone.

```bash
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

```bash
cargo run -p ergo-difftest -- --oracle --iters 2000 --corpus test-vectors/mainnet
```

Differential surfaces (context-complete consensus units):
`ergo_tree`, `ergo_box_candidate`, `transaction`, `header`, `reduce`,
`reduce_ctx`, `validate`, `verify_avl`. Bare `sigma_type` /
`constant` are intentionally **not** differential surfaces — the node's type/value
codec is version-gated *inside a tree*, so testing it context-free over-reports;
those codecs are exercised in-context via `ergo_tree`/`ergo_box_candidate`.

### Oracle setup (one-time)

`scripts/jvm_serde_oracle/ErgoSerdeOracle.scala` runs the real `sigma-state` +
`ergo-core` the node mirrors (version 6.0.2). `sigma-state` is on Maven;
`ergo-core` (transaction/header) is not, so publish it locally first:

```bash
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

## Phase 3 — the standing consensus guard

Phase 2 is a tool you point at a question. Phase 3 is the same machinery wired to
run unattended over the surfaces where the recent reject-valid bugs actually
lived, with a pass/fail contract.

```bash
scripts/difftest-guard.sh                       # seed 991, 2000 iters/surface
scripts/difftest-guard.sh --iters 20000 --seed 7
scripts/difftest-guard.sh --surfaces "reduce_ctx transaction"
```

It runs the structure-aware generators against the live oracle on `reduce`,
`reduce_ctx`, `transaction`, `ergo_box_candidate` and `validate`, minimizes and
classifies every unique divergence, and prints a per-surface table. Records land
under `ergo-difftest/regressions/` (gitignored); `QUEUE.md` lists the pending
ones.

| exit | meaning |
|---|---|
| 0 | every planned check ran; no unbaselined pending divergence |
| 1 | an **unbaselined** pending divergence — a candidate for human triage |
| 2 | usage / environment error (no `scala-cli`, no binary, malformed baseline) |
| 3 | **harness error** — the oracle died, or a surface checked fewer inputs than it planned |

Exit 3 exists because the failure mode that matters most is a guard that passes
having checked almost nothing. Three independent assertions guard against it: the
campaign's own exit code (`difftest` returns 3 on a spawn or pipe failure, never
folding one into a clean summary), an `oracle: HARNESS ERROR:` marker grep over
the log, and a `checks == iters` count per surface. To see it work, set
`DIFFTEST_ORACLE_DIE_AFTER=<n>` — a fault-injection knob in the oracle script that
answers `n` queries and exits.

### The accepted baseline

A guard that is red on day one teaches nobody anything: a new finding is
indistinguishable from the ones already known, and the red becomes wallpaper.
`known_bugs/baseline.toml` lists the divergences that are present on `main`
right now, each keyed by its content-addressed record identity
(`<surface>/sha256(input_hex)[..16]`, the same key `auto_file` writes to) and
each carrying a **required** `ref` matching `(PR|issue) #<number>`. An entry
without a tracking reference is refused — that is a muted divergence, not an
accepted one.

The guard fails only on pendings that are *not* listed; baselined ones print in
their own table, and a baseline entry the run did not reproduce is called out
too (either the fix landed and the entry should be deleted, or coverage was
lost). When a referenced fix merges, delete the entry: the guard going red on
the next run is the signal that the fix did not close the class.

`KnownArtifact` records are reported and never fail the run.

### The `EvaluatedValue` vocabulary (`src/gen/evaluated_value.rs`)

Scala parses **two** wire positions with the full `ValueSerializer` followed by a
cast to `EvaluatedValue` — a box's **registers** and an input's **context
extension** — not with the constant reader. That cast admits four node kinds:

| node | opcode | reference verdict |
|---|---|---|
| `Constant` | its own type code (`<= 0x70`) | accept |
| `ConcreteCollection` | `0x83`, or `0x85` bool-packed | accept |
| `Tuple` | `0x86` | accept |
| `GroupGenerator` | `0x82` | accept |
| anything else (`Height` `0xA3`, `Inputs` `0xA4`, …) | — | reject (`ClassCastException`) |

The `transaction` and `ergo_box_candidate` generators place all five classes at
their respective positions, each behind its own feature bit
(`ctx_ext_*` / `register_*`), so a campaign that never reaches one is a provable
gap rather than a silent one. The `Constant` arm draws the full constant
vocabulary, including the nested `Coll[Coll[Byte]]` and tuple shapes that only
appear un-nested at these two positions.

### `ctx_expr` / `reduce_ctx` — reading the values, not just parsing them

Seeding the vocabulary at parse is half the job: a value nobody reads can only
ever produce a *deserializer* divergence. The `reduce` surface can't close that
gap — it pins an empty extension and a register-less SELF.

So there is a frame surface:

```text
ctx_expr frame := contextExtension · ergoBoxCandidate
```

Both halves are self-delimiting, so one reader consumes them in sequence on
either side. The box's `ergoTree` is the script, the box is SELF (registers
included), and the extension is the input's — **all three from the wire**. The
`reduce_ctx` oracle surface reduces that frame on both implementations and
compares `P:<prop>|<cost>`, so the vocabulary is exercised through evaluation and
cost accounting, not just parse.

`src/gen/sigma_expr.rs` supplies the readers (`CtxRead`): `getVar[T](i)`,
`SELF.R4[T]`, `.get`, `.isDefined`, `._1`, and `(i)` indexing, each paired with
exactly the value it reads so the tree reduces to a concrete proposition instead
of a lockstep type-mismatch reject.

### Triage: which divergences fail the guard

A parse-surface divergence is reconciled against the surface that actually
*evaluates* the same bytes:

| parse surface | reduction channel |
|---|---|
| `ergo_tree` | `reduce` (the bytes are a script) |
| `ergo_box_candidate` | `reduce_ctx`, prefixed with an empty extension (`00`) |
| `transaction`, `header` | none — the bytes are not a script |

If the reduction agrees, the finding is a `KnownArtifact` (the node retains
original wire bytes / defers the curve check). If it persists, or the surface has
no channel, the record is `PENDING` and a human decides. The harness never sets a
which-side-is-right verdict.

### Known coverage gap — `CONTEXT.headers`

Both reduce surfaces run with an **empty** last-headers window: the node side
leaves `ReductionContext::last_headers` empty and the JVM side passes
`headers = Colls.emptyColl[Header]`. A script reading `CONTEXT.headers` sees a
zero-length collection on both sides and agrees trivially, so the window-size
divergence family (#238: 10 headers in Rust vs 9 in Scala) **cannot** surface
here. Closing it needs a header window on both sides — a fixed agreed set of
serialized headers, or a third `ctx_expr` frame field carrying them on the wire.
That is an oracle-contract change, deliberately not folded into the guard; the
replay driver reaches the class in the meantime.

### Debugging the pipe

`DIFFTEST_ORACLE_LOG=<path>` writes the full request/response transcript. A
standing guard is only as trustworthy as its pipe: when a campaign reports a
verdict a manual re-query cannot reproduce, this is the evidence that says
whether the harness and the oracle were in step. The log is opened in APPEND
mode with a per-process header, and `difftest-guard.sh` gives each surface its
own `<path>.<surface>` file, so one surface's oracle cannot overwrite another's
evidence.

### CI

The nightly `consensus-guard` job in `.github/workflows/fuzz.yml` runs the same
set, uploads `regressions/` plus the per-surface oracle transcripts as an artifact,
fails on any unbaselined `PENDING`, and fails louder (exit 3) if the run did not
check what it planned to. It is `workflow_dispatch`-only rather than scheduled, because
`ergo-core 6.0.2` is not on Maven Central: a cold GitHub-hosted runner has to
clone the Scala node and `sbt avldb/publishLocal ergoWallet/publishLocal
ergoCore/publishLocal`, which does not fit the ~20 min budget. The job caches
`~/.ivy2/local` + `~/.cache/coursier` keyed on the oracle script hash, so a warm
runner skips that entirely — point the `runner` input at a self-hosted label (or
an operator cron) for the green path. The hermetic PR-time `difftest` job in
`ci.yml` needs none of this and is unchanged.
