Ergo-core / sigma-state 6.0.7 parsing and transaction validation results.
Box candidates use getUIntExact for creationHeight: the wire is VLQ u32,
with a reader bound of Int.MaxValue. Fixtures exercise input/output heights,
block versions 1/2/4, rent eligibility, the exact sign boundary and controls.
Successful transaction costs come from validateStateful. Int overflow while
parsing is a rejection, and no validation cost is returned.

```sh
scala-cli run scripts/reference_607_oracle/ReferenceTxOracle.scala --server=false -- test-vectors/reference-6.0.7/creation-height/transactions.json > test-vectors/reference-6.0.7/creation-height/transactions.jvm.tsv
```
