# Compiled output versus reader acceptance

The seven existing ordinary UnsignedBigInt type examples compile under the
sigma-state6.0.6 frontend3 and its header0 API assembly. The same pinned parser
rejects every emitted header0 tree at activated versions1,2,3. All seven
header3 controls parse successfully at activated3 with complete consumption.
`cases.json` retains both compile acceptance and parser rejection explicitly.
This is not evidence that the Scala compiler rejects these sources.

TypeSerializer selects the validation-rule identity using activated version,
while `embeddableIdToType` selects table membership using ErgoTree version.
An activated3 override of header0's table therefore cannot certify usable
compiler output. Rust refuses these outputs before deriving addresses, an
explicit local compiler validation policy rather than a change to incoming
consensus gates or emitted headers. Supported folded v0 outputs remain valid.

The full source/transcript/JAR hashes are in `cases.json`. Reproduce from this
directory with Java17 and Scala CLI:

```sh
COURSIER_REPOSITORIES='ivy2Local|https://repo.maven.apache.org/maven2' \
scala-cli run Capture.scala ../../ergo-sigma/collection-types/ErgoSerdeOracle.scala \
  --server=false --jvm system --main-class CompilerReaderCapture
```

The existing oracle source supplies the locally published ergo-core dependency;
this capture directly invokes the real compiler and serializer, with no Rust
oracle. It does not execute a spend, full transaction or deployed node.
