# SANTA vectors

Conformance vectors vendored from SANTA, the cross-implementation Ergo
conformance suite: <https://github.com/mwaddip/santa>. SANTA is MIT-licensed,
Copyright (c) 2026 The SANTA Authors; its license is reproduced in
[`LICENSE`](LICENSE).

| Path | SANTA source | Test |
|---|---|---|
| `AvlVerify.ergots_corpus.json` | `vectors/authds/any/vendored/` | `ergo-sigma/tests/it/santa_avl_verify_corpus.rs` |
| `NipopowProve.jvm-chain-32.json` | `vectors/nipopow/any/authored/` | `ergo-validation/tests/it/santa_nipopow_chain.rs` |
| `wire/v6/authored/<op>.json` | `vectors/wire/v6/authored/<op>.json` at commit `599fbcd` | `ergo-ser/tests/it/santa_wire.rs` |

Wire vector files are copied byte-for-byte. Each one has a companion
`<op>.jvm.tsv` holding our own JVM verdict for every entry, written by
`scripts/santa_wire_oracle/SantaWireOracle.scala` on sigma-state / ergo-core
6.0.6 (the version the Scala node v6.0.6 and v6.1.6 ship). The test requires
SANTA's expectation, that JVM verdict and the node to agree on every entry.

To add a family: copy its `<op>.json` from SANTA, then write its verdicts:

```bash
f=test-vectors/santa/wire/v6/authored/<op>.json
scala-cli run -q scripts/santa_wire_oracle/SantaWireOracle.scala -- "$f" > "${f%.json}.jvm.tsv"
```
