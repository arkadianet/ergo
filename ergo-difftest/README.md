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

The structural comparison checks each serialization step against two Scala
behaviours, without normalizing either serialized byte sequence:

* In trees with version **< 3**, an opcode `0x7e` with `NumericCast` payload and
  an immediate `Expr::Const` input is stripped by Scala's serializer. A chain
  ending in a constant converges one level per round trip; comparison predicts
  exactly one pass and compares it with the next decoded structure. Remaining
  cast targets and premature removal of multiple levels stay observable. Extra rounds run
  only while the decoded tree still has a pending direct Upcast(Const) strip,
  checking normalized structure each round, with a 110-round bound matching
  Scala's MaxTreeDepth. Otherwise `b1 == b2` stays mandatory. Other casts/nodes,
  Unparsed bodies and all v3+ casts remain compared as-is
  (`ValueSerializer.scala:154-166,359-370`).
* Every `SigmaValue::Header` first has its ID independently checked against
  Blake2b256 of a consumed header slice observed by the header parser. Missing,
  mismatched or ambiguous wire provenance is a Bug. Verified IDs are then zeroed for comparison, including
  constants nested in collections, tuples, options, trees, registers and context
  extensions. All header fields remain compared. Scala hashes the retained input
  slice (`ErgoHeader.scala:132-140,167-180`), so canonicalizing an identity-point
  encoding can change this derived id without changing the header.

Known-bug-catalog **#19** retains the existing `WriteRejected` classification
when re-decoding a value containing an opaque tree fails. A successful
opaque-to-structural transition gets no exemption. Opaque trees compare their
bytes exactly, excluding only validation-error provenance; unrelated fields in
the containing value remain compared. Byte fixed point `b1 == b2` remains
mandatory except for the bounded pending-Upcast convergence described above.
The existing type-depth guard exclusion is unchanged. Structural comparison applies through
every containing surface, including boxes,
transactions, block transactions and `ctx_expr`; cached bytes remain compared.
Only ErgoTree AST codecs (`ergo_tree` and `sigma_expr`) follow extra strip rounds;
boxes, transactions and blocks re-emit retained tree bytes verbatim.
The `parity_*` corpus seeds and the embedded `surfaces.rs` regressions cover
the nightly failures. JVM captures reject the invalid block-item and unknown-method
seeds; their expectations are Rejected, not normalized acceptance. The candidate
seed still yields WriteRejected because its re-decode fails the SelectField check.

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
cargo run --locked -p ergo-difftest -- --iters 1000000 --seed 7
cargo run --locked -p ergo-difftest -- --surface ergo_tree --corpus test-vectors/mainnet
cargo run --locked -p ergo-difftest -- --repro 1b1501040a…     # triage one input
cargo run --locked -p ergo-difftest -- --selftest              # prove the detector has teeth
```

Determinism: a `(seed, iter)` pair reproduces an identical input when the mode,
surface and corpus contents match. Corpus files load in lexical path order; every finding
prints a `--repro <hex>`. `tests/it/smoke.rs` and `tests/it/selftest.rs` are the CI
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
cargo run --locked -p ergo-difftest -- --oracle --iters 2000 --corpus test-vectors/mainnet
```

Differential surfaces (each has its own parse, dummy-context reduction or verifier contract):
`ergo_tree`, `ergo_box_candidate`, `transaction`, `header`, `reduce`,
`reduce_ctx`, `verify`, `validate`, `verify_avl`. Bare `sigma_type` /
`constant` are intentionally **not** differential surfaces — the node's type/value
codec is version-gated *inside a tree*, so testing it context-free over-reports;
those codecs are exercised in-context via `ergo_tree`/`ergo_box_candidate`.

### Oracle setup (one-time)

`scripts/jvm_serde_oracle/ErgoSerdeOracle.scala` runs the real `sigma-state` +
`ergo-core` the node mirrors (version 6.0.6). `sigma-state` is on Maven;
`ergo-core` (transaction/header) is not, so publish it locally first:

```bash
cd <ergo reference checkout, tag v6.0.6>
sbt "avldb/publishLocal" "ergoWallet/publishLocal" "ergoCore/publishLocal"
```

(`avldb` pulls `leveldbjni-all` from the GitLab repo declared in the `.scala`
`using repository` directive.) Needs `scala-cli` on `PATH`; the first `--oracle`
run resolves deps and compiles (~1 min), then queries are fast.

The oracle executes a private copy of the selected standalone Scala source.
Relative project files and resources from its original checkout are not copied.
`Oracle::provenance()` records the exact source text and SHA-256, command arguments,
and actual executing JVM properties and resolved classpath JAR hashes after a
query. A declared dependency directive alone is not execution evidence.

The first response has a 180-second deadline, including compilation and dependency
resolution. Later responses have a 10-second deadline. Override these with
`DIFFTEST_ORACLE_STARTUP_TIMEOUT_MS` and `DIFFTEST_ORACLE_QUERY_TIMEOUT_MS`; each
must be an integer in `1..=1800000`. The deadline includes request writes and
response reads. Request and response lines are limited to 16 MiB. Retained stderr
is limited to its first 64 KiB and last 8 KiB, with the total byte count recorded.
Timeouts, incomplete responses and transport errors terminate that oracle; it
cannot be reused for later requests. Cleanup kills the owned Unix process group
and attempts to reap the direct child within two seconds. Windows cleanup covers
the direct child; descendant termination is not certified. Descendants that
escape the owned Unix group are also outside this cleanup contract.

## Corpus

`--corpus <dir>` loads regular files in lexical path order: `.hex` files
(one UTF-8 hex string), `.json` files (decoded string values of at least eight
hex characters, recursively through arrays and objects), or raw bytes otherwise.
JSON object keys are excluded. Missing or unreadable directories/files, malformed
JSON/hex and a corpus with no usable seeds fail with harness exit 3. Markdown and
text files are skipped; directories and symlinks are not followed. Decompress
JSON archives into a separate corpus directory first; `.json.gz` is otherwise
raw seed data. Mutation reproducibility requires identical ordered seed contents.

`--structured` uses its grammar generators and refuses `--corpus`, which would
otherwise be ignored. `--min-coverage` requires a hermetic structured campaign,
a finite threshold in 0..=1 and positive iterations. It measures constructor
labels, not semantic branch coverage or known-bug rediscovery.

`--structured --oracle` requires a supported `--surface`: `ergo_tree`,
`ergo_box_candidate`, `transaction`, `header`, `reduce`, `reduce_ctx` or
`validate`. `reduce` maps to `sigma_expr`, `reduce_ctx` to the context/box frame,
and `validate` to transaction bytes. The framed `verify` and `verify_avl`
protocols have no matching structured generator and are refused before a JVM
starts; use existing explicit requests with `--repro` for those surfaces.

`--check-canonical` requires a completely parsed ErgoTree and valid expected
hex. A rejection or trailing input returns harness exit 3 because no complete
tree was compared. A byte mismatch returns 1, and so does a writer error after
a complete decode, which re-encodes nothing that could match. `catch_unwind`
reports unwind panics as `Bug` while preserving the caller's process-wide panic
hook. It does not catch aborts, allocation failure or stack overflow.

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
files every observed divergence class as pending, and prints a per-surface
table. Classes retain their first concrete generating iteration and actual
structured/mutation mode. The guard uses a fresh, gitignored
`ergo-difftest/regressions-run.*` directory by default. An explicit
`--regressions-dir` must be new, or kept deliberately with `--keep-regressions`;
existing output is never cleared. Each invocation preserves separate logs.
`QUEUE.md` is a derived view of immutable pending records. If shrinking fails, the original
input/verdicts are saved with `minimized: false` and `processing_error`; that
failure still returns harness exit3. A failed file write also returns3.

| exit | meaning |
|---|---|
| 0 | every planned check ran; no unbaselined pending divergence |
| 1 | an **unbaselined** pending divergence — a candidate for human triage |
| 2 | usage / environment error (no `scala-cli`, no binary, malformed baseline) |
| 3 | **harness error** — the oracle died, or a surface checked fewer inputs than it planned |

Exit 3 exists because the failure mode that matters most is a guard that passes
having checked almost nothing. Independent assertions guard against it: the
campaign's own exit code (`difftest` returns 3 on a spawn or pipe failure, never
folding one into a clean summary), an `oracle: HARNESS ERROR:` marker grep over
the log, a `checks == iters` count per surface, and complete pending-record
accounting for every observed divergence class, plus validated execution
journals and record identities. Runtime identity that could not be captured
makes the run incomplete, including a run with no findings. To inspect the
existing failure-path mechanism, see
`DIFFTEST_ORACLE_DIE_AFTER=<n>` — a fault-injection knob in the oracle script that
answers `n` queries and exits.

### The accepted baseline

`known_bugs/baseline.toml` retains historical tracked divergences. New baseline
keys are `<surface>/<64-character semantic SHA-256>` and require a `ref`
matching `(PR|issue) #<number>`. The semantic digest includes surface, kind,
input, both verdicts, compiled-source/compiler configuration, archived oracle
sources, executing JVM/JAR identities, and the surface/context policy. Seed,
iteration and temporary paths remain in the evidence without changing this
comparison key. Compiled source is the workspace manifest, lockfile and
toolchain pin plus each crate's manifest, build script and `src/` tree. Editing
this baseline, records, docs, scripts or test vectors keeps every key; any
compiled-source change gives new keys. The journal still records the whole
source snapshot. Historical 16-character input keys remain visible as stale
entries and cannot mute a comparison under unbound authority.

The separate record filename hashes the complete canonical JSON, so different
processing or execution evidence is preserved. Records are published atomically
under a filing lock; identical records are idempotent. `runs/` holds immutable
execution journals and exact primary/verify Scala source archives. Every
`--oracle` campaign writes one, with or without `--minimize`, under
`--regressions-dir` (default `ergo-difftest/regressions`, relative to the
current directory). Repro commands
select those archives, including `DIFFTEST_VERIFY_ORACLE_SCRIPT` for the sidecar.
The build-script source inventory and running executable hash are diagnostic
provenance, not a signed build attestation. File synchronization and atomic
publication do not establish power-loss durability.

The guard fails only on pendings that are *not* listed; baselined ones print in
their own table, and a baseline entry the run did not reproduce is called out
too (either the fix landed and the entry should be deleted, or coverage was
lost). When a referenced fix merges, delete the entry: the guard going red on
the next run is the signal that the fix did not close the class.

An explicit reviewed `KnownArtifact` disposition is stored separately. Refile
reviewed records through the filing API; editing immutable JSON in place breaks
its identity. Dummy-context agreement never assigns that disposition automatically.

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

Every new divergence stays `PENDING`. Agreement under one fixed dummy context,
including rejection by both reductions, does not explain a parse difference or
prove it benign in other contexts. `KnownArtifact` is reserved for explicit
human review backed by a specific source/fixture explanation. The harness
never assigns which side is right or automatically certifies no consensus impact.

### Known coverage gap — `CONTEXT.headers`

Both reduce surfaces run with an **empty** last-headers window: the node side
leaves `ReductionContext::last_headers` empty and the JVM side passes
`headers = Colls.emptyColl[Header]`. A script reading `CONTEXT.headers` sees a
zero-length collection on both sides and agrees trivially, so the window-size
divergence family (#238: 10 headers in Rust vs 9 in Scala) **cannot** surface
here. Closing it needs a header window on both sides — a fixed agreed set of
serialized headers, or a third `ctx_expr` frame field carrying them on the wire.
That is an oracle-contract change, deliberately not folded into the guard; the
early replay supplies Rust parent headers, but has no independent scripted
reference reduction with a matched nonempty window. It does not close that
comparison by itself.

### Debugging the pipe

`DIFFTEST_ORACLE_LOG=<path>` writes the full request/response transcript. A
standing guard is only as trustworthy as its pipe: when a campaign reports a
verdict a manual re-query cannot reproduce, this is the evidence that says
whether the harness and the oracle were in step. The log is opened in APPEND
mode with a per-process header, and `difftest-guard.sh` gives each surface its
own `<path>.<surface>` file, so one surface's oracle cannot overwrite another's
evidence.

### CI

The `consensus-guard` job in `.github/workflows/fuzz.yml` runs the same set every
night at 02:00 UTC and on `workflow_dispatch`. It fails on any unbaselined
`PENDING`, and fails louder (exit 3) if the run did not check what it planned to.
Scheduled campaigns use the workflow run ID as their seed, so successive runs
exercise different inputs. Reproduce a recorded campaign by supplying its
`guard_seed` and `guard_iters` through manual dispatch or the local command.

The artifact preserves the source SHA, seed, iteration count, reference version,
full guard output, oracle warm-up output, minimized `regressions/`, and per-surface
oracle transcripts. Bootstrap or oracle failures remain failed steps; an empty
or incomplete campaign cannot pass. Runs on the same ref are serialized without
cancelling an active campaign.

`ergo-core 6.0.6` is not on Maven Central: a cold hosted runner publishes
`avldb`, `ergoWallet`, and `ergoCore` from the pinned reference tag locally. The
120-minute job budget allows this cold path. The job caches `~/.ivy2/local` and
`~/.cache/coursier`, keyed on the oracle script hash and reference version, so
subsequent runs reuse those dependencies. Set the repository Actions variable
`CONSENSUS_GUARD_RUNNER` to a warm runner label to use an existing local cache;
otherwise runs use `ubuntu-latest`. A manual `runner` input overrides that
variable. This job runs scheduled or manually selected repository code, never
untrusted pull-request code. The hermetic PR-time `difftest` job remains separate.
