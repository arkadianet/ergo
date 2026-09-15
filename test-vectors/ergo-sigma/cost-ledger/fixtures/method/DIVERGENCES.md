# METHOD fixture divergence tracking

## METHOD-coll-startsEndsWith — cost-only, unresolved

Task 3.4d independently confirms that Rust charges the wrong collection length
for both methods. The ledger remains DIVERGENT. Design section 7 requires the
production fix to land separately; this fixture commit contains no evaluator fix.
No remote issue or PR was created.

Source authority is sigmastate v6.0.2, commit
`23dd29f612249c169d09fae9bca76d7cc02e144c`,
`data/shared/src/main/scala/sigma/ast/methods.scala`, `startsWith_eval` and
`endsWith_eval`. Both call `addSeqCost` with **xs.length**, the receiver length,
using `Zip_CostKind = PerItemCost(10,1,10)`.
Rust's `ergo-sigma/src/evaluator/opcodes/method_call/coll.rs::starts_ends_with`
computes `pn` from the argument and charges that length instead.

`coll-startsEndsWith.json.gz` exercises receiver lengths `0, 1, 9, 10, 11, 21`,
argument lengths `0, 1, receiver + 11`, both methods, and ten cost prefixes.
Of 360 cases, 26 have observable block-cost differences (13 per method).
The other cases match at block granularity; that does not prove their internal
JIT costs agree. Every case executes and is checked.

Examples below apply independently to methods 31 (startsWith) and 32 (endsWith).
The fixture names encode the receiver, argument and prefix values.

| Receiver length | Argument length | Prefix | Rust eval/total BC | JVM eval/total BC |
|---:|---:|---:|---:|---:|
| 0 | 11 | 1 | 4 | 3 |
| 10 | 21 | 8 | 6 | 5 |
| 11 | 0 | 1 | 3 | 4 |
| 21 | 0 | 8 | 5 | 6 |

Both sides accept these high-limit guards, and crypto cost is zero. This is a
**cost-only** finding. The overcharge and undercharge directions can affect
acceptance near a cost limit; limit-boundary verdicts are not claimed here.

`expected` remains the verbatim JVM response from `scripts/gen-cost-fixture.sh`.
The separate `known_divergence.differences` objects contain the exact observed
Rust/JVM comparison fields reported by the failing fixture runner. Those
observations are diagnostic evidence and cannot close a row. The runner requires
the attached row to remain DIVERGENT, pins this tracking path to this row,
compares the entire recorded difference object, and rejects changed or stale
annotations. Its summary counts these as known divergences, never as skips.

Reproduce by running:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 ergo-difftest/src/gen/method_rest_cost.py
scripts/gen-cost-fixture.sh test-vectors/ergo-sigma/cost-ledger/fixtures/method/coll-startsEndsWith.json.gz
cargo test -p ergo-sigma --test it cost_ledger_fixtures_jvm_verify_fields_match -- --nocapture
```

A separate fix should charge the receiver length, remove the 26 annotations,
regenerate JVM evidence, run the full gate, and close the row with the fix
reference. A stale annotation deliberately fails once parity is restored.
