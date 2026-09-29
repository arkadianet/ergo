# Numeric cast and tuple projection reference fixtures

Captured **2026-09-30** by `scripts/jvm_serde_oracle/ReviewRegressionOracle.scala`
using the published sigma-state **6.0.6** artifact and Scala **2.12.20**. These
are JVM deserialization results, not predictions from the Rust implementation.
The activated version is 3; each tree supplies its own version. ACCEPT details
are consumed-byte counts, and REJECT details name the thrown exception.

To replay, convert each non-comment TSV row to `name surface hex` (columns
1, 2, 5) and run:

```sh
scala-cli run scripts/jvm_serde_oracle/ReviewRegressionOracle.scala -- inputs.tsv
```

Coverage includes both casts, all six numeric types (unsigned only under v3),
method results, tuple/option projections, placeholders, nested boxes and their
registers, sized/sizeless rejection, and precedence of an earlier soft-fork wrap.

The `polluted_placeholder` and `polluted_dead_branch` cases begin with outer
constants `[Boolean(true)]`. An inline box has the sized inner tree
`18050104027300`, whose numeric root wraps rule 1001 after installing `[Int(1)]`.
Scala leaves that constant store installed. Subsequent casts of placeholder 0
therefore accept, including in an unselected branch. The tuple variant installs
a tuple constant and then projects a field from placeholder 0.

The `opaque_binding` cases obtain a numeric ValUse type from a nested box's
script, which Rust conservatively treats as unknown. `legacy_trace_fixture`
retains a former trace-only test input: its SelectField over a Long is rejected
by the JVM with ClassCastException, so the old parse-success expectation was
incorrect. No valid mainnet fixture was rewritten to make the check pass.
