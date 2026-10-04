# Indexed token register text

These observations execute the `new String(bytes, "UTF-8")` and Scala `.toInt`
expressions used by `IndexedToken.fromBox` at Ergo v6.0.5, revision
`5528ef569a41ebccbc8658212e6ee3c97d990b96`. The exact source and its license are
included. `Capture.scala` is a finite expression adapter; it does not compile
or execute the complete IndexedToken class or a node.

The 26 text/integer rows include malformed UTF-8, BMP and supplementary digits,
signs, whitespace and signed integer limits. The complete 65,536-code-unit BMP
scan records the 370 `Character.digit(char, 10)` pairs from Corretto 17.0.17.
The Rust parser's digit ranges are tied to this runtime observation, not to a
claim that arbitrary later JDK Unicode tables are unchanged. Supplementary
characters are rejected because Scala's parser checks UTF-16 code units.

`provenance.json` binds source/output hashes and the actual executing Scala
2.12.20 library and JVM. Captured absolute cache paths describe the execution
location; JAR names and hashes identify its dependency. Reproduce with the
pinned Scala CLI/JVM and artifacts:

```sh
scala-cli --skip-cli-updates run test-vectors/ergo-indexer/token-text/Capture.scala \
  --server=false --jvm system --main-class Capture --suppress-outdated-dependency-warning
```

Rust tests compare all 26 rows through public `IndexedToken::from_box` and the
single-character parser against all BMP digit observations. These are local
index projection checks. No canonical chain occurrence or complete transaction
acceptance is established.
