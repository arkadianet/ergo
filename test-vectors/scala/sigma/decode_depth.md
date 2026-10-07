# Decode depth reference fixtures

`decode_depth.tsv` records actual sigma-state **6.0.6** JVM results captured
2026-09-30 with Scala 2.12.20, activated version 3 and tree version 3.
The oracle is `scripts/jvm_serde_oracle/ReviewRegressionOracle.scala` and uses
the published `org.scorexfoundation:sigma-state_2.12:6.0.6` artifact.

To replay, convert each non-comment TSV row to `name surface hex` (columns
1, 2, 5), then run:

```sh
scala-cli run scripts/jvm_serde_oracle/ReviewRegressionOracle.scala -- inputs.tsv
```

The ACCEPT detail is the reference reader's consumed byte count; REJECT records
the exception class. Every accepted fixture consumes the entire input.

`script_N` is a constant box whose sized proposition wraps N further inline
boxes, ending in `sigmaProp(true)`. `register_N` contains N boxes linked through
R4, each with a shallow `sigmaProp(true)` script, ending in Int(1). `sigma_N`
contains N unary Cand nodes and a True leaf. Output indices use one-byte VLQ zero.

The expression serializer and data serializer each consume a reader level.
An inline SBox therefore consumes two levels per link. Register constants also
pass through both serializers. A standalone constant passes directly through
ConstantSerializer into DataSerializer, without the initial expression level.
