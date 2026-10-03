# Collection carrier fixtures

These seven ordinary contracts were compiled, serialized, reduced and verified
by the published sigma-state / ergo-core 6.0.6 implementations on 2026-10-03.
The compiler/evaluator source, complete output and artifact hashes are retained
here. Expected propositions and costs come from Scala, never from Rust.
The scripts use HEIGHT and collections; the group equality is a control.
All trees use version 3, activated version 3 and height 0.

Reproduce with Java 17 and Scala CLI, from this directory:

```sh
scala-cli run Capture.scala ErgoSerdeOracle.scala --server=false --jvm system --main-class AuditCollectionProbe
```

`cases.json` pins all seven emitted wire trees and Scala reduction/verification
outputs. The reduction cost starts at zero JIT units. Verification uses the
oracle's ordinary dummy SELF/input context and empty proof/message; its total
also includes interpreter initialization and crypto verification rules.
The test separates exact public reduction costs from spending verification.
These fixtures establish these contracts' behavior, not chain occurrence,
full-transaction validity, arbitrary proof topology or network-wide readiness.

The sigma-state 6.0.6 JAR SHA256 is
`91423ee0dc5857ee53568e655fcc77abdc36f67f735897eefee576a4e37f1898`.
The pinned oracle dependencies and exact compiler/evaluator/transcript hashes
are recorded in `cases.json`; reproduction should compare all seven lines and
keep setup failures distinct from reference verdicts.
