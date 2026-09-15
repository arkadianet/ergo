# Reconciliation: source ledger (sigmastate v6.0.2 / ergo v6.0.2) vs oracle (ergo v6.0.5 / sigmastate v6.0.6)

Produced 2026-09-15 by a read-only source audit (codex) over the cost-affecting paths; verdicts are per commit. Result: **no tariff (costKind / SMethod cost / interpreter constant) changed between sigmastate v6.0.2 and v6.0.6**; two ergo changes affect cost *inputs* only (CONTEXT.headers window 9 vs 10 — already mirrored by PR #238 — and testnet default block version 1→4). Oracle scripts must pin ergo artifacts 6.0.5 and verify the resolved sigma-state is 6.0.6 (`SIGMASTATE_VERSION` can override). Plan Task 1.4.

# JIT-cost reconciliation

**Result:** No JIT tariff changes or new cost declarations were found. Two Ergo changes can affect oracle results through context construction or version selection.

Scope: sigmastate `v6.0.2 → v6.0.6`; Ergo `v6.0.2 → v6.0.5`, restricted to the requested paths. **COST-AFFECTING** includes changes to inputs or version branches that can change measured costs without changing tariffs.

**History caveat:** The initial Ergo log returned `4c43f0e36`, `681a1842d`, and shallow-boundary commit `4a7dba059`. Its parent objects are present locally. Repeating the read-only commands with `GIT_SHALLOW_FILE=/dev/null` recovered five additional relevant commits, included below. No repository files were changed.

## Reconciliation table

Files are identified by basename within the requested paths. Sigma merge rows include first-parent comparisons because ordinary `git show` produced no combined hunks.

| repo | sha | subject | files | verdict | detail/ledger obligation |
|---|---|---|---|---|---|---|
| sigmastate-interpreter | `0ce1a20c2` | Merge branch 'master' into drift-check-tests | `VersionContext.scala`, `CGroupElement.scala`, `SigmaBuilder.scala`, `values.scala`, `TaggedVariableSerializerSpecification.scala`, `GroupLawsSpecification.scala` | no-cost-effect | Incorporates the deprecation, documentation, and test changes detailed below; no additional runtime charging changes. |
| sigmastate-interpreter | `e27555752` | Merge pull request #1157 from jozanek/remove-tagged-variable | `VersionContext.scala`, `SigmaBuilder.scala`, `values.scala`, `TaggedVariableSerializerSpecification.scala` | no-cost-effect | Incorporates `dd4c1f293`; `TaggedVariable` remains registered and its declared cost remains `FixedCost(JitCost(1))`. |
| sigmastate-interpreter | `eefd92980` | Merge branch 'master' into drift-check-tests | `SigmaPredef.scala` | no-cost-effect | Incorporates `9f1d66066`; default-node identity and diagnostic changes introduce no charging obligation. |
| sigmastate-interpreter | `bd7a5f214` | Add drift-check golden tests for spec generators | `Operations.scala` | no-cost-effect | Adds six `InfoObject` wrappers referencing existing context methods through `SMethod.fromIds`; adds no method registrations or tariffs. |
| sigmastate-interpreter | `7bf59d0e6` | audit Exponentiate, lock-in cross-platform equivalence | `CGroupElement.scala`, `GroupLawsSpecification.scala` | no-cost-effect | Adds an explanatory comment and equivalence property test. `CGroupElement.exp` still delegates to `CryptoFacade.exponentiatePoint`. `Exponentiate.eval` still evaluates both operands, charges `FixedCost(JitCost(900))`, then calls `leftV.exp(rightV)`. No scalar-dependent surcharge or new normalization branch. |
| sigmastate-interpreter | `dd4c1f293` | TaggedVariable: pin wire format and deprecate Scala types | `VersionContext.scala`, `SigmaBuilder.scala`, `values.scala`, `TaggedVariableSerializerSpecification.scala` | no-cost-effect | Deprecation annotations, comments, and serialization tests only. Opcode `0x71` and declared `JitCost(1)` remain; `MaxSupportedScriptVersion` remains `3`. Future v7 rejection is documentation, not an implemented branch. |
| sigmastate-interpreter | `9f1d66066` | audit executeFromSelfReg, fix doc generator | `SigmaPredef.scala` | no-cost-effect | In `executeFromSelfRegWithDefault`, the invalid-register branch changes `default.v` to `default`. `syntax.ValueOps(val v: Value[SType])` shows `.v` returns the same AST node. The `executeFromSelfReg` exception changes interpolation from `$id` to `$idx`. `DeserializeRegister` charging is unchanged. |
| sigmastate-interpreter | `1ade73481` | Merge pull request #1061 from jozanek/match-declared-and-actual-type | `SType.scala` | no-cost-effect | Incorporates `3d74bc8ef`; compiler type helpers introduce no evaluator or cost-table change. |
| sigmastate-interpreter | `3d74bc8ef` | Compare declared and actual type for blocks. | `SType.scala` | no-cost-effect | Adds `isAssignableTo`: true for Boolean, Byte, Short, Int, Long, BigInt, String; false otherwise. Adds `getResultType`: function range for `SFunc`, otherwise the original type. Call sites are in `SigmaTyper`; no change to charges for an existing serialized tree. |
| ergo-scala | `4c43f0e36` | deprecation messages fix | `SnapshotsInfo.scala` | no-cost-effect | Snapshot manifest count and height parsing change from `getUInt().toInt` to `getUIntExact()`. Snapshot metadata parsing has no JIT or transaction-cost charge. |
| ergo-scala | `681a1842d` | lastHeaders fix | `ErgoStateContext.scala` | **COST-AFFECTING** | `upcoming` and `simplifiedUpcoming` now pass `lastHeaders.take(Constants.LastHeadersInContext - 1)`. The constant is `10`, so exposed upcoming headers become at most **9**, previously potentially 10. `UpcomingStateContext.sigmaLastHeaders` exposes that sequence directly. Obligation: `CONTEXT.headers` fixtures, collection iteration counts, indexing, and script branches. No tariff changes; resulting cost difference depends on the script. The added oversized-context check only logs. |
| ergo-scala | `4a7dba059` | Merge pull request #2415 from ergoplatform/v2heighttestnet | No actual scoped first-parent changes | no-cost-effect | The apparent whole-tree addition is a shallow-history artifact. Comparing its actual first parent yields an empty scoped diff; restored-history `git show` also has no scoped hunks. Earlier changes hidden behind this boundary are listed separately below. |
| ergo-scala | `d3e93a13e` | addressing review comments #5 | `Settings.scala` | no-cost-effect | Adds backward-compatible configuration fallback from `network.localOnly` to `network.allowLocal`; no script, transaction, or block-cost accounting changes. |
| ergo-scala | `0fa287784` | localOnly => allowLocal | `Settings.scala` | no-cost-effect | Renames the network configuration field; no ledger-cost obligation. |
| ergo-scala | `db04159ab` | fix for bounds must be positive , missed parent header auto downloading | `ValidationRules.scala` | no-cost-effect | `hdrParent` now constructs `ParentHeaderNotFoundError` through `invalid(...)` instead of a generic recoverable error. Changes missing-parent error handling, not cost limits or charges. |
| ergo-scala | `4cfe14e73` | persistentProver.synchronized in proofsForTransactions | `UtxoStateReader.scala` | no-cost-effect | Changes the synchronization monitor from the reader to `persistentProver`; proof-generation locking introduces no JIT charge or transaction-cost formula change. |
| ergo-scala | `91aa8056a` | testnet60 settings | `LaunchParameters.scala` | **COST-AFFECTING** | `TestnetLaunchParameters` changes default `BlockVersion` **1 → 4** (`Header.Interpreter60Version`). `ErgoContext` computes `activatedScriptVersion = blockVersion - 1`, hence **0 → 3** for this initialization path. This selects existing version-gated interpreter behavior. Also changes the proposed update from empty to `rulesToDisable = Seq(215,409)`: `hdrVotesUnknown` and `exMatchParameters`. Obligation: testnet initialization/version fixtures and validation-rule configuration; no numeric tariff change. |

The endpoint comparisons also establish:

- `DataValueComparer.scala` and interpreter production sources are unchanged.
- `ErgoTransaction.scala` and the requested wallet-interpreter directory are unchanged.
- `Parameters.scala` has no endpoint changes to numeric cost parameters.
- The six changed Ergo files are fully accounted for above; existing transaction/block accumulation formulas need no numeric reconciliation adjustment.

## New-declaration list

Counts use `git grep -n -F` against each tag, equivalent to recursive literal matching over tracked tag contents. These are **matching-line counts**, including references and comments, rather than counts of unique declarations.

| Search scope | Pattern | sigmastate v6.0.2 | sigmastate v6.0.6 | Added/removed matching lines |
|---|---|---:|---:|---|
| Whole tracked repository | `costKind` | 355 | 355 | 0 / 0 |
| Requested sigmastate paths | `costKind` | 338 | 338 | 0 / 0 |
| Whole tracked repository | `SMethod(` | 99 | 99 | 0 / 0 |
| Requested sigmastate paths | `SMethod(` | 99 | 99 | 0 / 0 |

Comparison preserved file paths and line contents while ignoring shifted line numbers. Thus unchanged counts do not conceal replacement matches.

**New `costKind` declarations: none. New `SMethod` declarations: none.**

The additions in `Operations.scala` are metadata wrappers for existing methods:

| New wrapper | Existing method reference |
|---|---|
| `HeightInfo` | `SMethod.fromIds(101, 6)` |
| `InputsInfo` | `SMethod.fromIds(101, 4)` |
| `LastBlockUtxoRootHashInfo` | `SMethod.fromIds(101, 9)` |
| `MinerPubkeyInfo` | `SMethod.fromIds(101, 10)` |
| `OutputsInfo` | `SMethod.fromIds(101, 5)` |
| `SelfInfo` | `SMethod.fromIds(101, 7)` |

## Artifact recommendation

Pin **Ergo artifacts to `6.0.5`**, which declares `sigmaStateVersion = "6.0.6"` in its root `build.sbt`. Ergo `v6.0.2` instead declares `"6.0.2"`.

For the default Scala 2.12 build:

```scala
libraryDependencies ++= Seq(
  "org.ergoplatform" %% "ergo-wallet" % "6.0.5",
  "org.ergoplatform" %% "ergo-core"   % "6.0.5"
)
```

The corresponding coordinates are:

- `org.ergoplatform:ergo-wallet_2.12:6.0.5`
- `org.ergoplatform:ergo-core_2.12:6.0.5`
- Expected Sigma dependency: `org.scorexfoundation:sigma-state_2.12:6.0.6`

`ergo-core` depends on `ergo-wallet`; a core-based oracle can declare just core. Use wallet directly for wallet-interpreter-only access. Match Scala binary suffixes throughout; the build also configures 2.11 and 2.13 cross builds.

**Maven Central status from repository evidence:** Both modules are configured for Maven publication, and `.github/workflows/release.yml` runs `+ergoWallet/publishSigned sonatypeBundleRelease` and the corresponding core command. Release `publishTo` uses `localStaging`; snapshots use the Central snapshot endpoint. This establishes an intended Central release workflow. **Repository files alone cannot establish that the `6.0.5` uploads succeeded or are currently available.**

For source builds, `SIGMASTATE_VERSION` overrides the declared default. The oracle’s resolved dependency must therefore be checked for `6.0.6`; the Ergo artifact version alone cannot rule out an override or dependency conflict.

## Least sure

- **Actual Central availability:** Publication is configured, but successful publication is not proved by build files or workflow definitions.
- **Oracle-specific cost differences:** Header truncation and testnet version initialization matter only if the oracle uses those construction paths. No oracle script was supplied, so a numeric cost delta cannot be assigned.
- **Compiler versus evaluator scope:** The `SType` helpers participate in compiler checks outside the requested paths. The no-cost-effect verdict applies to charging an existing serialized tree; it does not assert identical acceptance of all source programs.
- **Runtime validation:** This was a read-only source audit. No JVM/JS equivalence tests or oracle executions were run; the Exponentiate verdict establishes unchanged implementation and tariff, not fresh cross-platform test results.
