# Whole-box cached identity

The saved sigma-state 6.0.6 run compares an existing benign TrueLeaf fixture
parsed as a whole box against a newly constructed box with the same parsed
fields. The parsed box retains its exact received bytes and ID. Explicit box
serialization and the new-box constructor use canonical bytes and a different
ID. The three activated-version records agree on this distinction.

`Capture.scala`, stdout/stderr and `cases.json` retain the executed source,
complete output, artifact hashes and pinned source metadata. Reproduce with:

```sh
scala-cli run Capture.scala --server=false
```

These are finite standalone identity/serialization witnesses. They establish
no canonical-chain occurrence or full transaction/proof validity. Rust mutation
checks separately enforce cache coherence; they are not additional Scala runs.
