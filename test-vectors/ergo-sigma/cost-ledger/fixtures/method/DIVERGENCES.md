# METHOD fixture divergence tracking

## METHOD-coll-startsEndsWith — resolved by Task 0.7

Both methods charge the receiver length with
`Zip_CostKind = PerItemCost(10,1,10)`, matching sigmastate v6.0.2 commit
`23dd29f612249c169d09fae9bca76d7cc02e144c`,
`data/shared/src/main/scala/sigma/ast/methods.scala`, `startsWith_eval` and
`endsWith_eval`. Each calls `addSeqCost` with **xs.length**.
The fix is `fix(sigma): charge Coll.startsWith/endsWith over the receiver length like Scala`.

`coll-startsEndsWith.json.gz` exercises receiver lengths `0, 1, 9, 10, 11, 21`,
argument lengths `0, 1, receiver + 11`, both methods, and ten cost prefixes.
All 360 cases match the JVM, including the 26 cases (13 per method) that
exposed observable block-cost differences when Rust charged argument length.
The fixture runner checks every case without known-divergence annotations.

Examples apply independently to methods 31 (startsWith) and 32 (endsWith).
Costs below are eval/total block cost; crypto cost is zero.

| Receiver length | Argument length | Prefix | Rust before | JVM (unchanged) | Rust after |
|---:|---:|---:|---:|---:|---:|
| 0 | 11 | 1 | 4 | 3 | 3 |
| 10 | 21 | 8 | 6 | 5 | 5 |
| 11 | 0 | 1 | 3 | 4 | 4 |
| 21 | 0 | 8 | 5 | 6 | 6 |

Both sides accept these high-limit guards. The prior cost-only divergence
included overcharges and undercharges. Limit-boundary verdicts are not claimed
by these fixtures.

`expected` contains the verbatim JVM response from `scripts/gen-cost-fixture.sh`;
refreshing the evidence for this fix leaves every expected record unchanged.
The ledger row is CLOSED with the fixture runner as independent-oracle evidence.

Reproduce by running:

```sh
scripts/gen-cost-fixture.sh test-vectors/ergo-sigma/cost-ledger/fixtures/method/coll-startsEndsWith.json.gz
cargo test -p ergo-sigma --test it cost_ledger_fixtures_jvm_verify_fields_match -- --nocapture
```
