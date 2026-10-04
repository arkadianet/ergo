# Direct cost probe source snapshot

The directory `b16454cc77645aac499d9c06d8dbfd26a93dc99369368a9a96c9d8daf6770c93`
contains the exact `EvaluatedValueOracle.scala` bytes named by the historical
`jitcost_bounds.json` and `accumulator_initial_scope.json` captures. Its name is
the source SHA-256. Do not edit an archived source in place.

Both captures recorded checkout base `d3c7de477ddd56044aa5044774156c17be1760c4`,
whose source differs. Matching source bytes are recoverable at
`5d62fd5851e74fcb965b4aba50e1b423127f46f1`. This establishes source recovery;
the original execution revision and clean or dirty checkout state are unknown.
The fixture manifests preserve the original outcomes, timestamps and recorded
base, and state this uncertainty explicitly.

[The recapture receipt](../direct-cost-recapture.json) records two fresh,
standalone sigma-state 6.0.6 executions of this snapshot. All four JIT-bound
and six accumulator cases match the historical outcomes, including the exact
response hashes. The response files beside the source preserve those bytes.
This is finite arithmetic and accumulator evidence. It does not establish live
voted limits, complete transaction acceptance or operational node behavior.

The content-addressed `DirectProbeRuntime.scala` wrapper delegates to the
unchanged oracle and reports actual JVM properties on stderr. The receipt
hashes all 46 JARs on the executing JVM classpath. Circe resolved to 0.14.15,
despite the oracle's 0.14.5 directive; declared versions alone are insufficient
runtime provenance. Absolute cache paths record the original execution
location; artifact names and hashes identify the dependencies for reproduction.

With the pinned artifacts available, reproduce from the repository root:

```sh
snapshot=test-vectors/scala/source-snapshots/b16454cc77645aac499d9c06d8dbfd26a93dc99369368a9a96c9d8daf6770c93
wrapper=$snapshot/9095c3d3dd84e34695b18bfaa704d9cf983514cf52581094dc8d79fcfcfc323f/DirectProbeRuntime.scala
scala-cli --skip-cli-updates run "$snapshot/EvaluatedValueOracle.scala" "$wrapper" \
  --server=false --main-class DirectProbeRuntime \
  --suppress-outdated-dependency-warning -- jitcost_probe
scala-cli --skip-cli-updates run "$snapshot/EvaluatedValueOracle.scala" "$wrapper" \
  --server=false --main-class DirectProbeRuntime \
  --suppress-outdated-dependency-warning -- accumulator_probe
```

Future captures through `scripts/gen-evaluated-probe.py` archive the source
before execution, distinguish checkout base from exact source state, verify the
snapshot after execution and record the actual resolved JARs. Unrelated rent or
verify run metadata is excluded. The producer captures reported cases; a
separate comparison must establish equality with expected results.
