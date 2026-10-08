Header.checkPow transaction verdicts and successful costs were produced by
ergo-core 6.0.7 validateStateful. The vectors cover zero decoded difficulty,
negative compact difficulty, genuine headers, huge/tiny difficulty, and the
Autolykos version gate. The method charge stays unchanged.

Regenerate from the repository root:

```sh
scala-cli run scripts/santa_tx_oracle/SantaTxOracle.scala --server=false -- test-vectors/reference-6.0.7/check-pow/transactions.json > test-vectors/reference-6.0.7/check-pow/transactions.jvm.tsv
```
