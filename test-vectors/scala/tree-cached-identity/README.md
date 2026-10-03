# Received tree identity

The retained sigma-state 6.0.6 capture accepts the existing benign TrueLeaf
encoding at activated versions 1, 2 and 3. Its cached tree and template bytes
preserve the input, while explicit AST serialization normalizes it.

`Capture.scala` is the exact executed source; `scala.log` retains the complete
command, diagnostics and results. `cases.json` records source/transcript and
pinned reference-source hashes. The first captured input separately records
an activation/header rejection and is not an accepted hash fixture.

Reproduce the original reader comparison with Scala CLI and Java:

```sh
scala-cli run Capture.scala --server=false
```

Expected cached bytes are independently captured; hashes use the existing
Blake2b256 primitive. These are finite reader/identity cases, not transaction
or chain-validity proofs. Raw-input hashing helpers retain their existing EOF
and unparsed-template policies.
