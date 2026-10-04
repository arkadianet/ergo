# Requested mining transaction oracle

`MiningRequestOracle.scala` uses the external Ergo core/wallet 6.0.6 and
sigma-state 6.0.6 JVM implementations to produce
`test-vectors/mining/requested_transactions_scala_6_0_6.json`.

```bash
scala-cli run scripts/jvm_mining_request_oracle/MiningRequestOracle.scala \
  --server=false -- \
  /path/to/ergo/src/main/resources \
  test-vectors/mining/requested_transactions_scala_6_0_6.json
```

Published/local Ivy artifacts must resolve at the pinned versions. The capture
records their SHA-256 hashes and the JVM version. Signatures are freshly generated,
so a recapture changes signature-dependent header and Merkle bytes together.

The fixture contains a signed, zero-fee transaction whose input script requires
both a scalar-one Schnorr signature and a scalar-one `preHeader.minerPk`, a signed
child spending its output, a competing spend, and an independent signed
transaction. The JVM records accept/reject and transaction costs, including the
wrong miner key and a corrupted signature. Original Scala transaction JSON is
included for HTTP tests alongside serialized transaction and input-box bytes.
The input and output creation heights are 15; the policy itself has no height
condition. Its version-zero tree also works with version-two candidate headers.

The upcoming-header proof capture uses the nonconflicting parent, child and
independent transaction. Three transactions produce six v2 witness-tree leaves,
including an odd-width intermediate level. It pins the full header preimage and
Scala's mining proof `{leaf, levels}` encoding, where each level starts with a
side byte. The companion mining integration test also reuses the existing Scala
mainnet block-one capture to pin v1 empty-sibling padding.

These synthetic transactions establish signature/context validation, cost and
membership encoding. Their unmined header does not establish full-block or
proof-of-work acceptance; node integration tests exercise the live submit path.
