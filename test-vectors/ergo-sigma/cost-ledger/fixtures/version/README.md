# VERSION cost fixtures

Oracle: `scripts/jvm_evaluated_value_oracle/EvaluatedValueOracle.scala`,
sigma-state / ergo-core / ergo-wallet **6.0.2**. Every expected record comes
from `scripts/gen-cost-fixture.sh`. There are 17 JSON files and 177 Rust/JVM cases, plus one JVM-only case.

`ergo-difftest/src/gen/version_cost.py` writes the tree bytes directly and
reuses the EVAL generator's ten boundary prefixes. No ErgoScript compiler is
involved. Prefixes expose costs that would otherwise disappear when converting
JIT units to block units.

| Fixtures | Evidence |
| --- | --- |
| `upcast-v{2,3}{,-wide}` | Identical mixed Byte/Long Plus body; v2 inserts an Upcast, v3 throws ClassCastException after charging. Matched Long/Long controls accept. The v2 mixed body costs one extra block unit at every prefix. V3 failure costs and budget sweeps come from the JVM accumulator observation. |
| `bool-root` | V3 Boolean root rejected by parser rule 1001. `parse_only` forces the ValidationException retained inside Scala's size-delimited UnparsedErgoTree, without invoking verify. All costs remain `unavailable`, rather than inventing a zero charge. Rust confirms the retained body's Boolean type. |
| `method-activation`, `method-activated` | Identical v3 Global.serialize body: activation 2 rejects at the tree-version gate with retained baseline 17; activation 3 accepts at total 20. The method is never reached in the rejected case. |
| `self-index-a{1,2}` | Actual SELF index is zero. The contract checks -1 at activation 1 and zero at activation 2. Both accept at every prefix with equal costs. |
| `gate-supported` | Tree 3, activation 2: RejectScript / InterpreterException, total 17. |
| `gate-future` | Tree 4, activation 4: Accept, eval 0, crypto 0, total 17. Both versions exceed the supported maximum 3. |
| `gate-validation` | DeserializeContext[SigmaProp] receives serialized Boolean. Rule 1000 throws through reductionWithDeserialize's trySoftForkable; default enabled settings rethrow it. RejectScript / ValidationException, retained total 31, plus budgets 17 through 32. This covers the rejection arm, not soft-fork acceptance under changed validation settings. |
| `lazy-default-v{2,3}-{cheap,expensive}` | ByIndex selects an existing item. V3 ignores either default and has identical costs at every prefix. V2 evaluates the default; the expensive expression adds two block units. |

The JVM observer retains the input context cost when checkSoftForkCondition
throws and the returned context cost after deserializeMeasured succeeds.
`observe_deserialization_failure` uses the latter only for the validation
failure immediately following deserialization. Successful future-version
bypass explicitly reports zero eval and crypto because fullReduction did not
run. Existing full verify and evaluator-failure fields keep their meanings.

## Regenerate

Run from the worktree root, with Cargo commands serially:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 ergo-difftest/src/gen/version_cost.py
for f in test-vectors/ergo-sigma/cost-ledger/fixtures/version/*.json.gz; do
  scripts/gen-cost-fixture.sh "$f"
done
PYTHONDONTWRITEBYTECODE=1 python3 ergo-difftest/src/gen/version_cost.py --failure-limits
for f in gate-validation upcast-v3; do
  scripts/gen-cost-fixture.sh "test-vectors/ergo-sigma/cost-ledger/fixtures/version/$f.json.gz"
done
cargo test -p ergo-sigma --features cost-trace --test it cost_ledger_fixtures_jvm_verify_fields_match -- --nocapture
python3 scripts/cost-ledger.py render
python3 scripts/cost-ledger.py check
```

The failure-budget generator reads the JVM's existing observations to select
budgets, removes expected records from new requests, and requires another JVM
run. It never derives expected costs or verdicts from Rust.

## Pre-v3 method exclusion and recognized soft forks

`method-pre-v3.json.gz` hand-serializes the same Global.serialize (type 106,
method 3) as the activation controls, with tree version 2 and activation 3.
The pre-v3 method table excludes it (methods.scala:79/101). The size-delimited
parser retains its ValidationException; `propositionFromErgoTree` rejects it.
The oracle observes the context baseline at this failure point before reduction.

`gate-soft-fork.jvm` is JSON with a `.jvm` suffix: JVM-only evidence, deliberately
outside the Rust runner's `.json` / `.json.gz` selection. It does not close a ledger row.
Its request supplies `validation_settings_replaced_rules: {"1000": 1001}`;
the oracle applies `SigmaValidationSettings.updated(1000, ReplacedRule(1001))`
to the context. The identical `gate-validation.json.gz` body and context extension
throw rule 1000. Default settings reject at 31; replaced settings recognize a
soft fork and accept at total 27 (eval 10, crypto 0). The caught failure's
context is discarded in favor of context1; the successful total is therefore
lower than the rejected case's observed total.

Authority (sigmastate v6.0.2):

- `core/shared/src/main/scala/sigma/validation/ValidationRules.scala:248`
- `interpreter/shared/src/main/scala/sigmastate/interpreter/Interpreter.scala:249`

Rust preserves cumulative status updates in voting/validation_settings.rs and
activation updates in active_params, but ReductionContext and full verify have
no SigmaValidationSettings/isSoftFork input. The activated-version gate uses
only activated_script_version. VERSION-tree-version-gate remains OPEN for L4
replay or L5 block evidence after cumulative rule statuses reach verification.
The Rust fixture adapter rejects an override rather than silently ignoring it.

Regenerate the two requests (preserving existing activation controls):

```sh
python3 ergo-difftest/src/gen/version_cost.py --fix-probes
scripts/gen-cost-fixture.sh test-vectors/ergo-sigma/cost-ledger/fixtures/version/method-pre-v3.json.gz
scripts/gen-cost-fixture.sh test-vectors/ergo-sigma/cost-ledger/fixtures/version/gate-soft-fork.jvm
```

Every expected value is generated by the pinned JVM verify command; both files
carry request/response hashes and separate selected/executed counts.
