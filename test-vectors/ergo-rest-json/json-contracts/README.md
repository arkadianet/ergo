# SDK JSON numeric and field-decoding contracts

`Capture.scala` executes the published sigma-state 6.0.6 SDK `JsonCodecs` with
Scala 2.12.20 and Circe 0.14.5. `scala.stdout` retains all 49 observations:
33 numeric spellings,5 numeric digit/scale boundaries and11 evaluated-value fields.
`cases.json` groups those exact observations for Rust tests. `provenance.json`
records the actual runtime JAR hashes, source pins, command, Java version and
artifact hashes. Source pins cover SDK `JsonCodecs` and Circe's `JsonNumber` and
`BiggerDecimal`; the latter limits nonzero integer conversion to 2^18 decimal
digits, while zero requires no scale expansion.

Reproduce from the repository root with Java and scala-cli installed:

```bash
scala-cli run test-vectors/ergo-rest-json/json-contracts/Capture.scala --server=false --jvm system
```

Review the new observations before changing expectations. Compiler dependency
upgrade hints do not change these pins. These are finite library decoder
observations, not full transaction validation or independently authenticated
chain captures.

The SDK accepts integral exponent/fraction notation in numbers and numeric
strings. REST magnitude fields separately enforce a nonnegative policy; Scala
Long amount/value fields additionally require representability through
Long.MAX_VALUE. These checks do not establish monetary consensus validity.

Each evaluated-value input is decoded independently. The SDK tolerates unused
suffix bytes, and its writer serializes the decoded value. A field cannot borrow bytes from a neighbor in the SDK. The value rows pin
canonical writes separately from raw field prefixes and numeric observations.
