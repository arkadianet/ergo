# Pinned Scala V1 status and ordering observations

`observations.tsv` was captured on 2026-10-04 by compiling the exact selected
`compareV1` and `syncInfoV1` methods from the shipped unchanged Scala v6.0.5
`ErgoHistoryReader.scala` (revision 5528ef569a41ebccbc8658212e6ee3c97d990b96).
`CaptureCompareV1.scala` supplies a minimal ordinary metadata adapter: canonical
64-digit hex IDs, optional local tip, known-ID set and ascending height lookup.
It does not compile the entire history trait or execute an Ergo node.

Seven comparison rows pin last-position equality, a local tip at the oldest
endpoint/interior, known fork, unknown peer, empty peer and pregenesis overlap.
Four producer rows pin empty history, ascending IDs with a zero pregenesis
prefix at heights 3/1000, and the latest 1000 IDs without that prefix at 1001.
The zero ID follows `Header.GenesisParentId`/`PreGenesisHeader.serializedId` in
the included source. Both selected methods occur verbatim in the wrapper;
source/helper/output and Scala compiler/library/reflect 2.12.21 hashes are in
`provenance.json`. All selected-method compilation/execution exited 0.

To repeat using those three verified jars, set `SCALA_CP` to their classpath
and run from this directory with a disposable classes directory:

```bash
mkdir -p /tmp/ergo-sync-v1-classes
java -cp "$SCALA_CP" scala.tools.nsc.Main -classpath "$SCALA_CP" \
  -d /tmp/ergo-sync-v1-classes CaptureCompareV1.scala
java -cp "/tmp/ergo-sync-v1-classes:$SCALA_CP" CaptureCompareV1
```

Rust P2P consumes all seven status rows; SYNC consumes all four producer rows
and separately checks inbound common-point normalization and pregenesis/empty
continuations. V1 is oldest-first on the wire and tip-last; V2 remains
newest-first. These are finite metadata/method observations and ordinary Rust
codec regressions, not a full legacy peer exchange or consensus acceptance
proof. The current default admission floor negotiates V2.
