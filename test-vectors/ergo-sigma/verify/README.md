# Full verification fixtures

Oracle: `scripts/jvm_evaluated_value_oracle/EvaluatedValueOracle.scala`,
commit `2210c764` (sigma-state, ergo-core and ergo-wallet 6.0.2;
Scala 2.12, scala-cli 1.12). `cases.json` stores the exact requests and JVM
response objects; `requests.jsonl` is the same request sequence for regeneration:

```sh
scala-cli run scripts/jvm_evaluated_value_oracle/EvaluatedValueOracle.scala --server=false -- verify < test-vectors/ergo-sigma/verify/requests.jsonl
```

Requests are UTF-8 JSON bytes on the difftest `verify` surface. `--repro`
hex-encodes the entire JSON document. Embedded boxes, candidates, trees,
extensions and headers use consensus bytes. Pre-header is the oracle's
89-byte big-endian frame. No compiler constructs the dead-branch script:
`00d1959385030101d40100` is `sigmaProp(if (true == true) true else
DeserializeContext[Boolean](0))` and independently measures 26 block units.
`deserialize-subst-request.json` is the pinned re-injection request.

The differential compares verdict, eval/crypto/rent/total block costs and
rent_path, including costs on rejected proofs. Runtime-specific diagnostics
and the supplementary legacy evaluator record are retained but not compared.

`known_divergence` records the original finding for the two rent fixtures.
All cases now participate in parity assertions: the production rent shortcut
charges 50 BC (500 JIT), including a total of 67 BC with init cost 17.
The transaction script regressions in `ergo-validation/tests/it/cost_storage_rent.rs`
cover shortcut success and fallback for TX-storage-rent.

## Reproducibility manifest

[`manifest.json`](manifest.json) records the script revision and SHA-256,
exact sigma-state/ergo-core/ergo-wallet dependency versions (all 6.0.2),
Scala CLI and JVM versions, source anchors, Rust toolchain/features, synthetic
context, run counts, timestamp, and hashes of every input and output artifact.
The standalone artifact fallback is explicit: these are not 6.0.5 node results.

`fix-cases.json` adds eight independently captured JVM cases. The fractional
rent fallback uses serialized `sigmaProp(if (true == true) true else false)`
(`00d19593850301010100`): the JVM reports 43 JIT against limit 40, `RejectCost`,
and charged-to-failure total 4 BC. Seven probes exercise storage-fee field
validation with rent enabled or disabled. No expected cost comes from Rust.

Regenerate the raw JVM responses from the checked-in requests:

```sh
scala-cli run scripts/jvm_evaluated_value_oracle/EvaluatedValueOracle.scala --server=false -- verify < test-vectors/ergo-sigma/verify/requests.jsonl > test-vectors/ergo-sigma/verify/responses.jsonl
scala-cli run scripts/jvm_evaluated_value_oracle/EvaluatedValueOracle.scala --server=false -- verify < test-vectors/ergo-sigma/verify/fix-requests.jsonl > test-vectors/ergo-sigma/verify/fix-responses.jsonl
cargo test -p ergo-difftest --lib oracle::verify::tests
```

Responses correspond by line to the requests and case objects. Compare each
parsed response to its case's `expected` object before updating any fixture;
refresh the manifest hashes and run metadata after regeneration. The pinned
re-injection request equals the first original case's request.
