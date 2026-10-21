# Compiled output versus reader acceptance

The seven existing ordinary UnsignedBigInt type examples compile under the
sigma-state 6.0.6 frontend 3 and its header 0 API assembly. The same pinned parser
rejects every emitted header 0 tree at activated versions 1, 2, 3. All seven
header 3 controls parse successfully at activated 3 with complete consumption.
`cases.json` retains both compile acceptance and parser rejection explicitly.
This is not evidence that the Scala compiler rejects these sources.

TypeSerializer selects the validation-rule identity using activated version,
while `embeddableIdToType` selects table membership using ErgoTree version.
An activated 3 override of header 0's table therefore cannot certify usable
compiler output.

The header 0 assembly in `Capture.scala` is not what the node's compile route
does. `ScriptApiRoute.compileSource` builds
`ErgoTree.defaultHeaderWithVersion(treeVersion)` (`ScriptApiRoute.scala:58`,
ergo 6.0.5/6.0.7; `ScriptApiRouteSpec` asserts header `0x10` at v0 and `0x19`
at v1), so at tree version 3 the route emits the header 3 bytes. Rust's
`compile(.., 3, ..)` writes that same header and emits exactly each case's
`header3_control_hex` (pinned by
`compiled_v6_type_outputs_carry_scala_header3_bytes` in
`ergo-compiler/src/tree/mod.rs`). The post-write self-check still re-reads the
emitted bytes before deriving addresses, so a v6 type code under a pre-v3
header would still be refused.

The full source/transcript/JAR hashes are in `cases.json`. Reproduce from this
directory with Java 17 and Scala CLI:

```sh
COURSIER_REPOSITORIES='ivy2Local|https://repo.maven.apache.org/maven2' \
scala-cli run Capture.scala ../../ergo-sigma/collection-types/ErgoSerdeOracle.scala \
  --server=false --jvm system --main-class CompilerReaderCapture
```

The existing oracle source supplies the locally published ergo-core dependency;
this capture directly invokes the real compiler and serializer, with no Rust
oracle. It does not execute a spend, full transaction or deployed node.

`CapturePositive.scala` restores the val-bound empty unsigned collection control.
Its type-bearing collection folds away before wire assembly; the real compiler,
assembled under header 0, emits `10010400d1937e730005c1a7`, and the real reader
accepts all three activated versions with complete consumption. Rust at tree
version 3 emits the same body under the route's header 3
(`1b0b010400d1937e730005c1a7`). `scala-folded.stdout`, stderr and
`receipt-folded.json` retain that independent result and source/JAR hashes.
Reproduce with `scala-cli run CapturePositive.scala --server=false --jvm system
--main-class CompilerFoldedControl` under the same Java/repository setup.
