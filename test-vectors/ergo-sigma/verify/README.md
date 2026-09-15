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
