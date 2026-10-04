# Scala voting threshold capture

`VotingSettings.scala` is the unchanged v6.0.5 reference source pinned in
`provenance.json`. `CaptureVotingThresholds.scala` calls its `softForkApproved`
method at zero and immediately around each threshold. `thresholds.tsv` is the
captured JVM stdout, consumed by the Rust regression. The custom row exercises
signed overflow; it does not assert that this configuration occurs on a network.

Reproduce with the Scala 2.12.21 compiler, library and reflect jars whose hashes
are recorded in `provenance.json`. Set `SCALA_CP` to their colon-separated paths
and `SCALA_LIBRARY` to the library jar path, then run from this directory:

```bash
mkdir -p classes
java -cp "$SCALA_CP" scala.tools.nsc.Main -classpath "$SCALA_CP" -d classes VotingSettings.scala CaptureVotingThresholds.scala
java -cp "classes:$SCALA_LIBRARY" CaptureVotingThresholds > thresholds.tsv
```

The small wrapper computes the printed threshold using the same Scala `Int`
expression, while each Boolean observation calls the upstream method itself.
These are arithmetic observations, not an independently authenticated chain.
