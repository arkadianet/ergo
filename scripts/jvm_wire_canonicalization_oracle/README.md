This probe independently forces transaction wire bytes, the signing message,
transaction and output box IDs, received proposition bytes, and persisted UTXO
bytes on sigma-state / ergo-core 6.0.7. Rejected parse controls retain their JVM
exception names. It reads no expected results.

With ergo-core 6.0.7 published locally and Scala CLI installed, run from the
repository root:

```bash
export COURSIER_REPOSITORIES='ivy2Local|https://repo.maven.apache.org/maven2'
export JAVA_TOOL_OPTIONS='-XX:ActiveProcessorCount=8'
scala-cli run --server=false scripts/jvm_wire_canonicalization_oracle/CanonicalizationOracle.scala -- \
  test-vectors/scala/wire_canonicalization_607.json > /tmp/canonicalization.jsonl
python3 - <<'PY'
import json
from pathlib import Path
entries = [json.loads(line) for line in Path('/tmp/canonicalization.jsonl').read_text().splitlines()]
Path('test-vectors/scala/wire_canonicalization_607.json').write_text(json.dumps({'entries': entries}, indent=2) + '\n')
PY
```

The GitLab repository supplies the
leveldbjni transitive dependency; sigma-state resolves from Maven Central.
The SANTA wire and transaction companions also cover nested box constants,
register and extension carriers, and direct / embedded method-call spend costs.
