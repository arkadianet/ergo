The oracles pin sigma-state 6.0.7 and record actual JVM results rather than
assuming the Rust limit or error classification. `DeserializationOracle.scala`
records descriptor boundaries, exact direct-reader positions, validation rule
identities, canonical constants and size-delimited tree wrapping.
`SoftForkOracle.scala` exercises Interpreter.verify with enabled, disabled,
changed and replaced rule 1020 at activated versions 2 and 3.

```bash
export COURSIER_REPOSITORIES='https://repo.maven.apache.org/maven2'
export JAVA_TOOL_OPTIONS='-XX:ActiveProcessorCount=8'
scala-cli run scripts/jvm_deserialization_607_oracle/DeserializationOracle.scala \
  --server=false --jvm system --workspace /tmp/deserialization-607 -- \
  test-vectors/scala/deserialization_607.json
scala-cli run scripts/jvm_deserialization_607_oracle/SoftForkOracle.scala \
  --server=false --jvm system --workspace /tmp/softfork-607 -- \
  test-vectors/scala/softfork_607.json
```

Each emits JSON lines. Wrap them in `{"entries": [...]}` to regenerate the fixture.
The input fields remain valid when the output fields are present.
Type recursion starts at 0 and rejects depth 9: `MaxTypeDepth.value` is **8**,
while its `SizeConstant` identifier is 16. The write side has no corresponding
type-depth consensus check. Zero-width collection data rejects even at length 0.
An unparsed sized tree retains rule 1020; an unsized tree throws a hard serializer
error. The core rule is soft-forkable when replaced, but the node's currentSettings
omits rule 1020. Its isSoftFork consequently returns false at spend time for
both retained trees and failed substitutions. Match that omission deliberately.
Evaluation through Global.deserializeTo is outside Interpreter's soft-fork catch.
