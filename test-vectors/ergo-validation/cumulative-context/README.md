# Cumulative validation context oracle

Captured with pinned Ergo v6.0.5 source methods and the actual Sigma6.0.6 jar.
`CaptureValidationContext.scala` embeds unchanged `updated`, `updateRules` and
update `++` methods from the shipped full source snapshots. Its small outer
`RuleStatus(isActive)` adapter models only rule activation. Sigma statuses use
`org.ergoplatform.validation.ValidationRules.currentSettings` from the real jar;
every captured cumulative status is checked against runtime `getStatus`.

The shipped `ErgoStateContext.scala` also records the source order: append the
target extension/update before executing its transactions. The separate
`cost_block_fixtures` suite consumes an independently captured target-epoch
transaction-pricing transition; this helper does not execute that suite.

The first update disables outer215 and sets Sigma1007 disabled/1008 changed.
An empty second update retains these statuses. The replacement update disables
outer409, replaces1007 with1017 and adds disabled1011. `observations.tsv`
contains all3 exact settings rows and4 checked cost conversions, including two
adjacent example voted limits and the `Int` multiplication-overflow boundary.
They are finite parameter examples, not a permanent mainnet cost ceiling.

`context.rs` consumes all7 observations. The selected source semantics establish
cumulative context construction; this capture does not validate a whole script,
block, or historical activation chain, nor show current chain rejection from
status-map loss. In particular A6 replacement rules have additional runtime
qualification in Sigma; retaining a status does not prove it affects a verdict.

`provenance.json` records full source URLs/hashes, jar hashes, exact local
compile/capture commands and successful exits. To repeat, build the recorded
classpath from pinned jar versions, compile the unchanged helper with
`scala.tools.nsc.Main -classpath <classpath> -d <disposable-classes>
CaptureValidationContext.scala`, then run
`java -cp <disposable-classes>:<classpath> CaptureValidationContext` and compare
stdout exactly with `observations.tsv`. No repository fixture is modified by the
Rust consumer.
