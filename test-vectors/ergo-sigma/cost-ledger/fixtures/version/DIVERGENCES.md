# Version parser parity

Oracle: pinned sigma-state 6.0.2, `scripts/jvm_evaluated_value_oracle/EvaluatedValueOracle.scala`.

The 14 marked cases for VERSION-G008, VERSION-G016 and VERSION-G018 now match the JVM.
`parser-data-gates.json.gz` and `subst-bytes.json.gz` retain the original JVM expectations,
including the cost-limit boundary cases; no `known_divergence` markers remain.

VERSION-G018 validation-settings replacement behavior remains JVM-only evidence in
`validation-settings.jvm`; Rust has no settings-aware verification harness.
