# Arithmetic operand type-read fixtures

Captured **2026-10-11** by `scripts/jvm_deserialize_oracle/ArithUpcastOracle.scala`
using the published sigma-state **6.0.7** artifact and Scala **2.12.20**. These
are JVM deserialization results, not predictions from the Rust implementation.

Each operation (`Minus`, `Plus`, `Multiply`, `Division`, `Modulo`, `Min`, `Max`,
and the `BitOr`/`BitAnd` checks) is combined with operands whose type read
fails (`Filter` over a Long, Int or Byte constant, an out-of-range
`SelectField`), on either side, both sides, beside a Boolean, and with valid
numeric controls (`Plus(1, 2L)` and similar).

- `body` rows: `ValueSerializer.deserialize` at tree version 0–3, then `.tpe`,
  the path runtime-deserialized code takes. Phases are `TYPE`, `TYPE_FAIL` or
  `DECODE_FAIL`, with the exception class.
- `tree` rows: `deserializeErgoTree` of `sigmaProp(op(l, r) == 0L)` with header
  `00` (sizeless v0) and sized `08`, `09`, `0a`, `0b`, activated version 3.
  A failed type read is a hard rejection at every version, sized or not; no
  row wraps into `UnparsedErgoTree`.

Regenerate:

```sh
python3 -I scripts/jvm_deserialize_oracle/gen_arith_upcast_inputs.py > inputs.tsv
scala-cli run scripts/jvm_deserialize_oracle/ArithUpcastOracle.scala --server=false \
  --jvm system -- < inputs.tsv
```

Prefix the output with the two comment lines of the TSV.
