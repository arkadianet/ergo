Each cases.tsv row contains name, required nBits, and actual nBits.
The JVM records the signed decoded value and whether it equals the required
value, as HeadersProcessor compares requiredDifficulty. These checks do not
verify the PoW equation and have no script cost. The adjacent genuine header
bytes supply the Rust production difficulty validator's chain context.

```sh
scala-cli run scripts/reference_607_oracle/DifficultyOracle.scala --server=false -- test-vectors/reference-6.0.7/difficulty/cases.tsv > test-vectors/reference-6.0.7/difficulty/cases.jvm.tsv
```
