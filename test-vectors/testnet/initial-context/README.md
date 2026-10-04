# Public testnet launch and early epochs

Captured on 2026-10-04 from the public Scala 6.0.3 testnet REST node
`http://213.239.193.208:9052`. The independently hosted testnet explorer agrees
on height-1 ID `5b1827ca092b599eafbaf339d2acf2445bc5216ec2e022d9c001a6fff660cad9`.
`provenance.json` records exact response, source, helper and dependency hashes.
The REST JSON files are verbatim captures; `headers.json` contains separately
computed JVM bytes and IDs, not a raw-wire HTTP response.

The authority for launch behavior is the included unchanged Scala v6.0.5
`LaunchParameters.scala` at revision
`5528ef569a41ebccbc8658212e6ee3c97d990b96`. `Parameters.scala` and
`ErgoStateContext.scala` pin its parameter/default and first-epoch context.
The testnet launch row has block version 4 and proposed disabled rules 215
and 409. Those proposals are not active cumulative settings. The captured
height-1 genesis header is version 1; height 2 is version 4. The first epoch
starts at height 128, not 1024. Both captured epoch extensions (128 and 1024)
contain the proposal and no cumulative `0x02` settings, with subblocks=30.

The Rust consumer checks all four full header byte round trips/IDs, PoW
solutions, extension roots against header commitments, genesis identity and
box JSON, and the height-0 first-epoch bootstrap at 128. Its empty prior tally
exercises the reference bootstrap branch, which accepts parsed parameters and
settings when `currentParameters.height == 0`; it does not derive the actual
previous tally from four sparse headers. The genesis box capture is
semantically equal to the existing embedded `../genesis_boxes.json`.

## Reproducing the finite header serialization

`PrintHeaderBytes.scala` is the exact helper compiled in this capture. Its
Scala CLI directive comments were removed so the actual command used pinned
Sigma 6.0.6, rather than the general extraction script's wallet dependency.
Compile using Java 17, Scala compiler/library/reflect 2.12.21 and the exact
jars listed in `provenance.json` (including Sigma 6.0.6, scrypto 3.1.1,
scorex-util 0.2.2, Circe 0.14.15 and Bouncy Castle 1.85.1). Set `SCALA_CP` to
that verified classpath; use a disposable output directory:

```bash
mkdir -p /tmp/ergo-testnet-header-classes
java -cp "$SCALA_CP" scala.tools.nsc.Main -classpath "$SCALA_CP" \
  -d /tmp/ergo-testnet-header-classes PrintHeaderBytes.scala
for height in 1 2 128 1024; do
  java -cp "/tmp/ergo-testnet-header-classes:$SCALA_CP" PrintHeaderBytes \
    < "header-$height.json"
done
```

Each line contains `headerWithoutPow`, full header bytes, and computed ID.
The capture compiled and ran this helper for all four inputs with exit 0,
and every computed ID matched the REST ID. General bulk extraction scripts
may use a different helper dependency; do not label their outputs as this
pinned run without checking its dependency graph and hashes.

These observations do not authenticate a continuous chain, execute complete
reference-node blocks, prove a full Rust testnet sync or migrate old databases.
Fresh Rust testnet stores seed the corrected row. UTXO reconcile preserves
an existing height-0 row rather than rewriting historical parameters; such
stores need a separately reviewed migration/replay decision. Fresh digest
stores already reject a preexisting launch row that disagrees with their
configured launch. No historical row rewrite is performed by this change.
