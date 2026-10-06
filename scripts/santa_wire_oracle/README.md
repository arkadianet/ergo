These independent wire verdicts use sigma-state **6.0.7** and ergo-core **6.0.7**.
The transaction oracle in `../santa_tx_oracle` uses the same setup.

Use a Java 21 `JAVA_HOME` and Scala CLI. ergo-core is not on Maven Central:
from a separate Scala node checkout at tag `v6.0.7`, publish its dependencies
and core with `sbt 'avldb/publishLocal' 'ergoWallet/publishLocal' 'ergoCore/publishLocal'`.
Do not modify a running node or its checkout for this step. The GitLab repository
directive resolves leveldbjni-all; `ivy2Local` resolves the locally published core.

From this repository:

```bash
export COURSIER_REPOSITORIES='ivy2Local|https://repo.maven.apache.org/maven2'
export JAVA_TOOL_OPTIONS='-XX:ActiveProcessorCount=8'
python3 scripts/regenerate-santa-oracles.py --scala-cli scala-cli
```

The helper compiles each oracle once into a temporary workspace, checks complete
entry coverage, and regenerates every `.jvm.tsv` companion. It reports individual
verdict changes. For this upgrade, exactly six old wire accepts become
`REJECT DeserializeCallDepthExceeded`; transaction verdicts and costs do not change.
`SUPERSEDED_BY_607` in `ergo-ser/tests/it/santa_wire.rs` records those six upstream
6.0.6 expectations and fails if upstream begins agreeing.

To inspect a single fixture without changing its companion:

```bash
scala-cli run scripts/santa_wire_oracle/SantaWireOracle.scala \
  --server=false --jvm system --workspace /tmp/santa-wire-607 -- \
  test-vectors/santa/wire/v6/authored/Box.zero_width_collections_607.json
```

The actual type-call limit is **8**. In sigma-state's
[SizeConstant(8, 16, ...)](https://github.com/ergoplatform/sigmastate-interpreter/blob/v6.0.7/core/shared/src/main/scala/sigma/data/SigmaConstants.scala),
8 is the value and 16 is the constant identifier. Compact embedded type codes
can construct multiple layers without another recursive deserialization call.
