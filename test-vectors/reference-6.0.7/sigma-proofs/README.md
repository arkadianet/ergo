Sigma-state 6.0.7 `verifySignature` verdicts are in `cases.jvm.tsv`;
`cases.tsv` has name, proposition, proof and message as hexadecimal bytes.
The corpus covers response reduction, DLog and DH-tuple leaves, OR/AND
composition, shortened/omitted responses, short challenges and trailing bytes.
The direct verifier entry point does not return transaction cost.

`transactions.json` was built with the node's `prove_sigma` using secret 7,
public keys 7*G and 11*G, a simulated response of 5, and deterministic seed 42.
The second entry changes that response to group-order + 5. Both transaction
verdicts and costs were produced by ergo-core 6.0.7 `validateStateful`.

Regenerate from the repository root, with the JVM toolchain available:

```sh
scala-cli run scripts/reference_607_oracle/SigmaProofOracle.scala --server=false -- cases test-vectors/reference-6.0.7/sigma-proofs/cases.tsv > test-vectors/reference-6.0.7/sigma-proofs/cases.jvm.tsv
cargo run --locked -p ergo-wallet --features test-utils --example reference_sigma_responses -- test-vectors/reference-6.0.7/sigma-proofs/transactions.json
scala-cli run scripts/santa_tx_oracle/SantaTxOracle.scala --server=false -- test-vectors/reference-6.0.7/sigma-proofs/transactions.json > test-vectors/reference-6.0.7/sigma-proofs/transactions.jvm.tsv
```

`transactions.jvm-ids.tsv` records name, transaction id, 248-bit witness id,
and comma-separated output box ids. The transaction and output ids are equal
between the proofs; the witness ids differ because their proof bytes differ.

```sh
scala-cli run scripts/reference_607_oracle/TransactionIdsOracle.scala --server=false -- test-vectors/reference-6.0.7/sigma-proofs/transactions.json > test-vectors/reference-6.0.7/sigma-proofs/transactions.jvm-ids.tsv
```
