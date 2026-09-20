# JIT-cost conformance closure report

Status: DONE_WITH_CONCERNS. Task 8.1 completes the exit audit under the controller ruling permitting residual OPEN obligations. This is not a claim of complete JIT-cost conformance under design §10.1: 57 obligations remain OPEN. No row is closed by a Rust-derived expectation.

## Coverage

Authoritative inventory: 297 rows, 216 CLOSED / 57 OPEN / 24 N-A / 0 DIVERGENT. All N-A rows have notes. `cost-ledger.py check` passes; `check --strict` exits 1 because of the 57 OPEN rows. Inventory diff is empty; its 18 self-tests pass. Source anchor/formula changes remain detectable, while evidence-note changes do not invalidate the audit snapshot. The snapshot includes the 16 follow-up obligations added during the program; existing BitOp anchors retain the same declarations after removal of obsolete action instructions.

| Category | CLOSED | OPEN | N-A | DIVERGENT |
|---|---:|---:|---:|---:|
| BLOCK | 7 | 5 | 3 | 0 |
| EVAL | 25 | 0 | 2 | 0 |
| INTERP | 11 | 4 | 1 | 0 |
| LIMIT | 3 | 0 | 0 | 0 |
| METHOD | 66 | 4 | 2 | 0 |
| OP | 76 | 21 | 13 | 0 |
| ORDER | 12 | 5 | 0 | 0 |
| ROUND | 3 | 0 | 0 | 0 |
| TX | 7 | 1 | 2 | 0 |
| VERSION | 6 | 17 | 1 | 0 |

Version coverage is deliberately incomplete: mainnet historical versions are replayed; v6 has JVM and mixed-devnet evidence. The VERSION rows below retain unproven version branches, including validation-settings soft-fork handling. Source pins are sigmastate v6.0.2 (`23dd29f612249c169d09fae9bca76d7cc02e144c`) and ergo v6.0.2 (`2cdbb8cf09d7ccbc060e1022e3c15bcf6a9991b1`); replay oracle pins are ergo 6.0.5 / sigma-state 6.0.6.

## Campaign evidence

[L4 manifest](results/l4-2026-09-16.json): candidate `cea3b0fa72ec85b4aca6563052f4d2c846e1f812`, 388/388 required ranges, selected=101,187, executed=101,187, failed=0, skipped=0, missing_required_ranges=[]. The required selection test passed in 84.13s, enforcing all ten stratified ranges, every activation transition ±1 epoch, and voted-parameter change ranges. Counts are range/transaction pairs; overlapping ranges contain 94,500 unique transactions. The previous checked-in manifest had two failures on `36b3aa96` despite the supplied zero-failure summary; this full rerun establishes the fixed candidate's result. Input/source hashes are refreshed from the actual replay inputs; capture-time oracle metadata is retained. The subsequent closure commit changes only this report and the manifest.

The required gate passed: fmt and warning-as-error clippy; nextest was unavailable, so the authorized workspace-test fallback ran 7,021 passing tests, zero failures, 97 ignored. Ignored tests are not included as passes. L4 was run separately with diagnostics enabled.

[L6 manifest](results/l6-2026-09-16.json) contains final PASS campaigns for Scala-mines and Rust-mines, each selected=7, executed=7, failed=0, skipped=0. The intermediate Rust-mines failure is explicitly retained as RESOLVED_DIVERGENCE, not counted as a successful campaign. Both directions include cost-boundary verdicts and state commitments; the v6 fixture exercises a v6-only operation. The passing Scala-mines binary source is `9fd384a6`; the final Rust-mines revision is `07a4f410`. Cost-path diffs from these revisions through the candidate are empty for `ergo-sigma/src`, `ergo-validation/src`, and `ergo-primitives/src/cost.rs`. The recorded older Scala-mines binary does not exercise the later emission-recovery fixes; this remains a limitation of that direction's evidence.

The L5 fixture consumers recompute the SHA-256 of compact JSON excluding the manifest, preserving the JVM producer's object order. They validate nested source pins, tools, revision/hash encodings, run fields, features, and context against the fixture payload. Historical producer script and input hashes describe capture-time bytes; they are not incorrectly compared with the current producer. All five block fixture tests pass, including both validators, boundaries, token exhaustion, v6 and invalid-signature controls.

## Divergences found and fixed during the program

The ledger and linked test names contain the independent JVM/mainnet evidence for each fix. These are distinct from the unresolved coverage obligations listed below.

| Finding | Resulting behavior / evidence | Fix commits | PR |
|---|---|---|---|
| Per-input crypto truncation | Truncate each crypto estimate to block units before accumulation; prevents remainder carry and reject-valid exact-limit failures (`INTERP-crypto-trunc`, `ROUND-crypto-per-input`). | [`bc32d5f9`](https://github.com/arkadianet/ergo/commit/bc32d5f9af95e759f3cba66775e87b8be7403a59) | [#337](https://github.com/arkadianet/ergo/pull/337) |
| Storage-rent unit | Charge StorageContractCost as 50 block units (`TX-storage-rent`). | [`69337be6`](https://github.com/arkadianet/ergo/commit/69337be616c46df214f9ac7144e37aa79a6fa689) | [#339](https://github.com/arkadianet/ergo/pull/339) |
| Empty SigmaAnd / SigmaOr | Reject empty children as JVM CAND/COR normalization does (`OP-0xEA`, `OP-0xEB`). | [`37737585`](https://github.com/arkadianet/ergo/commit/377375851b58611ecbc09d40679cc9b60678247e) | [#339](https://github.com/arkadianet/ergo/pull/339) |
| BitOp charge before rejection | Inherited evaluator rejects without charging its declared Fixed(1); independent evaluator failure observations pin this (`ORDER-bitop-charge-then-reject`). | [`7dd8489a`](https://github.com/arkadianet/ergo/commit/7dd8489a51021f935422d5f89a589b0fb8c72d13) | [#339](https://github.com/arkadianet/ergo/pull/339) |
| Collection equality counting | Charge the elements actually compared; unknown-length charges remain deferred (`EVAL-eq-coll-descriptor`). | [`77ea069f`](https://github.com/arkadianet/ergo/commit/77ea069f959d291191304ccb7630b5bc4c692b47) | [#340](https://github.com/arkadianet/ergo/pull/340) |
| Unit equality | Charge zero for Unit equality (`EVAL-eq-mismatch-and-unit-E032`); element-type mismatch remains unproven in that row's note. | [`77ea069f`](https://github.com/arkadianet/ergo/commit/77ea069f959d291191304ccb7630b5bc4c692b47) | [#340](https://github.com/arkadianet/ergo/pull/340) |
| String equality / rejection | Reproduce shallow SString rejection and descriptor-carrier guards in JVM order (`EVAL-sstring-rejected`). | [`77ea069f`](https://github.com/arkadianet/ergo/commit/77ea069f959d291191304ccb7630b5bc4c692b47), [`9d000fc9`](https://github.com/arkadianet/ergo/commit/9d000fc9c78affead303c3b0a6fefe1b3868cec9), [`92cbd181`](https://github.com/arkadianet/ergo/commit/92cbd1815ac9438df2cf3abe7856192f4e7555c1) | [#340](https://github.com/arkadianet/ergo/pull/340) |
| Option charge order | Evaluate receiver/arguments before method tariffs; Some paths include AddToEnvironment, including Option.filter. | [`fff09ea0`](https://github.com/arkadianet/ergo/commit/fff09ea038b254ec910e627b99c8b1badd10a0c6) | [#341](https://github.com/arkadianet/ergo/pull/341) |
| Method failure-path order | Align receiver, argument, fixed-method, AVL, serialization and branch charge order with JVM per-limit observations (`ORDER-*` CLOSED rows). | [`44af3d08`](https://github.com/arkadianet/ergo/commit/44af3d08a5fe13095bf675d78557dcc10aba8c83) | [#341](https://github.com/arkadianet/ergo/pull/341) |
| startsWith / endsWith length | Charge using receiver length, not the compared prefix/suffix length (`METHOD-coll-startsEndsWith`). | [`21dd178b`](https://github.com/arkadianet/ergo/commit/21dd178b6c59ad2b2be063b00767f6937077b160) | [#341](https://github.com/arkadianet/ergo/pull/341) |
| Embedded-script bytes | Charge deserializeMeasured bytes for embedded scripts (`INTERP-embedded-script-deser`). | [`9dc67079`](https://github.com/arkadianet/ergo/commit/9dc67079fb7aa95d8505f56a1a4ea86efaef9843) | [#342](https://github.com/arkadianet/ergo/pull/342) |
| Threshold clamp | Use n-k without a minimum-one clamp: 3-of-3 has 1197 crypto BC and total 1219 (`INTERP-crypto-threshold`). | [`8fe0a271`](https://github.com/arkadianet/ergo/commit/8fe0a27162c4982f1a65e22bd303bfbf59eff1e2) | [#342](https://github.com/arkadianet/ergo/pull/342) |
| Deserialize substitution typing | Reject incompatible registers and untyped substitutions; preserve the independent rule-1001 root gate (commits `23130988`, `5b65b4f9`, `1d8ddde3`). | [`23130988`](https://github.com/arkadianet/ergo/commit/2313098812e3db8ca94005c8c49a7176615d2fca), [`5b65b4f9`](https://github.com/arkadianet/ergo/commit/5b65b4f9d7ef79077cd87b799034262dbacc851a), [`1d8ddde3`](https://github.com/arkadianet/ergo/commit/1d8ddde3eb41e0ae950c147fef60a41fae00c9e3) | [#342](https://github.com/arkadianet/ergo/pull/342) |
| Historical voted parameters | Replay/extractor uses historical epoch parameters rather than present defaults (`TX-l4-range-voted-params`). | [`8c1ed474`](https://github.com/arkadianet/ergo/commit/8c1ed4744e652e0b6ed3ada83be5ea0c7e3d3730) | [#344](https://github.com/arkadianet/ergo/pull/344) |
| Empty token-map typing | Preserve empty map element types to accept valid mainnet spends (`TX-l4-v6-activation-reject-valid`, `3e249d88`). | [`3e249d88`](https://github.com/arkadianet/ergo/commit/3e249d8836d35bb86cbbfd1b960469de793d7dfc), [`e2748cc6`](https://github.com/arkadianet/ergo/commit/e2748cc64d7badb29142a884731abdc179bb0e77) | [#344](https://github.com/arkadianet/ergo/pull/344); cherry-picked to [#340](https://github.com/arkadianet/ergo/pull/340) as `e2748cc6` |
| Emission-box discovery | Track lineage, retain unspent emission boxes, handle exhaustion and restart recovery (`BLOCK-L6-emission-box-discovery`). | [`9fd384a6`](https://github.com/arkadianet/ergo/commit/9fd384a6793f4800ac0ec4334bafbd8e7741ae4f), [`3dc44087`](https://github.com/arkadianet/ergo/commit/3dc44087f261b728da0d38f541b14764200d74a5) | PR-E2 (pending) |
| Mining safety gap | Use Scala tiers rather than the fixed subtraction (`BLOCK-L6-mining-safety-gap`). | [`07a4f410`](https://github.com/arkadianet/ergo/commit/07a4f410723f2912f1d6fb959c60a782b4e9170f) | PR-E2 (pending) |
| POST /blocks gate | Restrict direct full-block submission and SubmitBridge to explicitly opted-in devnets; direct bridge refusal regression evidence. | `c29f9f0a`, `cea3b0fa` | PR-E2 (pending) |

PR mappings follow the controller ruling; fix SHAs are verified against current local history. PR-E2 (pending) will use branch `jit-cost/e2-campaign-closure` for emission discovery, the tiered safety reserve and the POST /blocks gate. No PR is opened or pushed by this task.

## Security and upgrade notes

Every release up to and including v0.7.0 exposed unauthenticated `POST /blocks` full-block submission on mainnet/testnet (`ergo-api/src/server/scala_api.rs`). The surface now requires an explicitly opted-in devnet, with refusal also enforced in SubmitBridge. The former access still required valid PoW and full validation: submission access only, no consensus bypass. Direct bridge regression tests submit a captured mainnet block and verify refusal and no transaction/event dispatch on public networks and unconfigured devnets. See [CHANGELOG](../../../CHANGELOG.md).

Mining emission discovery now tracks lineage instead of `transactions[0].outputs[0]`. First start after upgrade performs bounded synchronous recovery (4096 blocks / 32 MiB). Mainnet post-EIP-27 tips resolve from one block. Insufficient history leaves mining unavailable until an emission-NFT-bearing block is applied. Scala's tiered candidate safety gap reserves 150,000 block-cost units at the current mainnet maximum. The user-transaction budget is `max(0, voted maximum block cost - safety reserve - emission cost - rent cost)`, using saturating subtraction; 150,000 is the reserve, not that budget.

## Residual risks (design §10.6)

- Mainnet replay cannot cover scripts mainnet never contained. OPEN operation, order, and version rows below identify missing source pins, serialized JVM cases, failure sweeps or state-level evidence.
- Pinning establishes behavior only for the reconciled 6.0.5/6.0.6 oracle and 6.0.2 source ledger. Later interpreter, dependency, or protocol drift requires a fresh reconciliation and campaign.
- Scala bug-compatible behavior is intentional, including shallow SString rejection and version-dependent selfBoxIndex. Passing fixtures do not authorize correcting the JVM's behavior independently.
- Strict closure remains unmet. In particular, cumulative SigmaValidationSettings/isSoftFork input is not threaded through the verification interface; the recognized soft-fork condition needs implementation and L4/L5 evidence. Escaping AVL constructor exceptions lack a deterministic serialized probe. Coverage on successful paths does not prove the remaining competing-failure order obligations.
- Bulk L4 vectors are gitignored, so reproduction requires the local captured corpus and pinned oracle tooling. Recorded historical L6 binaries are identified explicitly rather than relabeled as current binaries.

## OPEN rows, exact notes and closing layers

Notes below are copied verbatim from authoritative ledger.toml. An empty note remains empty. “Closing evidence” refines the ledger layer where a static L1 check alone cannot establish runtime rejection or dynamic behavior; no row state is changed by this report.

| Row | Ledger layer | Closing evidence | Exact ledger note |
|---|---|---|---|
| OP-0x7D | L1,L2 | L2 serialized JVM cost/rejection; L1 descriptor where listed | dynamic; table Fixed(10) is not the whole rule |
| OP-0x7E | L1,L2 | L2 serialized JVM cost/rejection; L1 descriptor where listed | dynamic |
| OP-0x8F | L1,L2 | L2 serialized JVM cost/rejection; L1 descriptor where listed |  |
| OP-0x90 | L1,L2 | L2 serialized JVM cost/rejection; L1 descriptor where listed |  |
| OP-0x91 | L1,L2 | L2 serialized JVM cost/rejection; L1 descriptor where listed |  |
| OP-0x92 | L1,L2 | L2 serialized JVM cost/rejection; L1 descriptor where listed |  |
| OP-0x93 | L2 | L2 serialized JVM cost/rejection; L1 descriptor where listed | no static row; see EVAL-eq-* |
| OP-0x94 | L2 | L2 serialized JVM cost/rejection; L1 descriptor where listed |  |
| OP-0x99 | L1,L2 | L2 serialized JVM cost/rejection; L1 descriptor where listed | arith_cost dynamic |
| OP-0x9A | L1,L2 | L2 serialized JVM cost/rejection; L1 descriptor where listed |  |
| OP-0x9C | L1,L2 | L2 serialized JVM cost/rejection; L1 descriptor where listed |  |
| OP-0x9D | L1,L2 | L2 serialized JVM cost/rejection; L1 descriptor where listed |  |
| OP-0x9E | L1,L2 | L2 serialized JVM cost/rejection; L1 descriptor where listed |  |
| OP-0xA1 | L1,L2 | L2 serialized JVM cost/rejection; L1 descriptor where listed |  |
| OP-0xA2 | L1,L2 | L2 serialized JVM cost/rejection; L1 descriptor where listed |  |
| OP-0xB6 | L1,L2 | L2 serialized JVM cost/rejection; L1 descriptor where listed | zero-cost reject; prove no charge before the error |
| OP-0xB7 | L1,L2 | L2 serialized JVM cost/rejection; L1 descriptor where listed | zero-cost reject |
| OP-0xCF | L1 | L2 serialized JVM cost/rejection; L1 descriptor where listed | zero-cost reject |
| OP-0xD6 | L1,L2 | L2 serialized JVM cost/rejection; L1 descriptor where listed | charged AFTER rhs eval (ORDER-blockvalue-valdef) |
| OP-0xD7 | L1 | L2 serialized JVM cost/rejection; L1 descriptor where listed | zero-cost reject |
| OP-0xF1 | L1 | L2 serialized JVM cost/rejection; L1 descriptor where listed | zero-cost reject |
| METHOD-groupelement-exp | L1,L2 | L1,L2 |  |
| METHOD-unclaimed-inventory | L1 | L1 complete JVM/source method dispatch inventory | L1 extractor must list every method Scala can dispatch; each either maps to a row or is proven unreachable/unsupported identically on both sides |
| INTERP-jitcost-bounds | L1 | L1 JVM/source pin and L3 boundary evidence | Rust returns typed Overflow instead of throwing; unreachable from honest input (pin test exists, Rust-oracled) |
| INTERP-toblockcost | L1,L3 | L1 JVM/source pin and L3 boundary evidence |  |
| ORDER-blockvalue-valdef | L2,L3 | L2 throwing JVM probes and L3 competing-limit sweeps | Keep OPEN: requires serialized BlockValue/ValDef fixtures with throwing RHS and tight limits around RHS and environment insertion charges, comparing JVM/Rust verdicts and available totals across every affected limit. Generic binding success sweeps do not distinguish RHS evaluation from the later AddToEnvironment charge; dedicated competing-failure sweeps have not been captured. |
| ORDER-constplaceholder | L2 | L2 throwing JVM probes and L3 competing-limit sweeps | Keep OPEN: requires an out-of-bounds constant-pool lookup that reaches evaluation, with JVM charged-to-failure observations and tight limits distinguishing lookup-before-charge from charge-before-lookup. A malformed serialized placeholder may fail during deserialization before evaluation; an independently observed reachable fixture and its boundary sweep have not been established. |
| ORDER-hof-charge | L2,L3 | L2 throwing JVM probes and L3 competing-limit sweeps | Keep OPEN: requires Map and Exists fixtures whose mapper/condition construction or closure body throws, with limits spanning collection evaluation, function evaluation, known-length overhead and closure environment insertion. Generic successful collection representatives do not isolate those competing failures; dedicated JVM per-limit observations remain uncaptured. |
| ORDER-comparison-charge | L2,L3 | L2 throwing JVM probes and L3 competing-limit sweeps | Keep OPEN: requires LT/LE/GT/GE fixtures with throwing left/right operands and limits spanning both operand costs and the comparison charge, comparing JVM/Rust verdicts and available totals. Successful comparisons do not prove operand-before-charge equivalence under competing failures; dedicated serialized failure-order sweeps remain uncaptured. |
| VERSION-tree-version-gate | L4 | L4 or L5 after validation-settings integration | Supported-version rejection (17), future bypass (17), and default rule-1000 validation rejection (31) remain Rust/JVM controls. JVM-only fixtures/version/gate-soft-fork.jvm replaces rule 1000 with ReplacedRule(1001): recognized trySoftForkable acceptance, eval 10, crypto 0, total 27. Authority: core/shared/src/main/scala/sigma/validation/ValidationRules.scala:248 and interpreter/shared/src/main/scala/sigmastate/interpreter/Interpreter.scala:249. Rust active_params.activated_update and voting/validation_settings.rs preserve statuses, but ReductionContext and verify_spending_proof_with_context_and_cost have no SigmaValidationSettings/isSoftFork input; PR #331 gate consumes only activated_script_version. Close in L4 replay or L5 block fixtures after threading cumulative rule statuses into script verification and matching this recognized condition and cost. |
| VERSION-subst-retention | L2 | L2 version-paired JVM fixtures (and L1 pin where listed) |  |
| BLOCK-param-voting | L4,L5 | L4,L5 | cost parameters reach the accounting through this path; L4 boundary ranges exercise it |
| METHOD-box-registers-R0-R3 | L1,L2 | L1,L2 | M066: generated mandatory-register accessors R0 through R3 each reuse ExtractRegisterAs FixedCost(50). Method IDs are idOfs + register index + 1. Separate accessor identities from explicit getReg IDs 7 and 19; direct-call reachability remains to be tested. |
| METHOD-box-registers-R4-R9 | L1,L2 | L1,L2 | M067: generated optional-register accessors R4 through R9, IDs 13 through 18, each reuse ExtractRegisterAs FixedCost(50). Separate accessor identities from explicit getReg IDs 7 and 19; direct-call reachability remains to be tested. |
| INTERP-accumulator-initial-scope-I020 | L1,L3 | L1 JVM/source pin and L3 boundary evidence | I020: constructor stores initialCost in the initial scope; totalCost at CostAccumulator.scala:78 reads currentScope.currentCost. Neither constructor nor read independently checks the limit; add performs the comparison. |
| INTERP-profiling-cost-isolation-I023 | L1,L2 | L1,L2 | I023: timing-enabled verification supplies a separate profiling evaluator; ordinary verification supplies null. Profiling accumulator creation and optional proof-helper charging are at CErgoTreeEvaluator.scala:465,490,519. These helper measurements are not added again to the returned block cost. |
| TX-verifier-failure-sentinel-T009 | L3,L5 | L3,L5 | T009: verifier Failure yields false and maxCost+1 as a rejection sentinel. Subsequent script and accumulated-cost checks reject; this sentinel is not an accepted execution cost. |
| BLOCK-stop-after-invalid-B002 | L3,L5 | L3,L5 | B002: transaction loop continues only while transactions remain and costResult.isValid. Later transactions are not validated or charged after the first invalid result. |
| BLOCK-digest-state-accounting-B005 | L1,L5 | L1,L5 | B005: DigestState delegates to ErgoState.execTransactions and converts the validation result to Try. It shares cumulative transaction/block accounting with the UTXO-state path. |
| BLOCK-updated-context-before-validation-B006 | L4,L5 | L4,L5 | B006: appendFullBlock produces newStateContext before applyTransactions. Transaction validation receives that updated context, including applicable epoch parameters and block version. |
| BLOCK-cost-parameter-defaults-B008 | L1,L4 | L1,L4 | B008: default BC values are tokenAccessCost=100, inputCost=2000, dataInputCost=100, outputCost=100 and maxBlockCost=1000000; see Parameters.scala:306,308,310,312,318. Current voted parameters replace defaults during validation. |
| VERSION-header-checkPow-G023 | L1,L2 | L2 version-paired JVM fixtures (and L1 pin where listed) | G023: tree-version-3 checkPow method charges FixedCost(700) before invocation; inspected header.version==1 then throws. Other header versions use Autolykos2 verification. Method descriptor is methods.scala:1815 and fixed-method charge order is values.scala:1348. |
| VERSION-G007 | L1,L2 | L2 version-paired JVM fixtures (and L1 pin where listed) | G007: failed AVL insert throws for tree version <3; tree version >=3 uses the failed operation result. Per-entry cost has already been charged. Later digest/result work can differ. Matching branch also exists at interpreter/shared/src/main/scala/sigmastate/eval/Extensions.scala:99. |
| VERSION-G008 | L1,L2 | L2 version-paired JVM fixtures (and L1 pin where listed) | G008: JIT activation selects SubstConstants serialization implementation; tree version >=3 additionally preserves the original size field when the header has the size bit at ErgoTreeSerializer.scala:369. Base substitution descriptor is unchanged; produced bytes and later costs can differ. |
| VERSION-G009 | L1,L2 | L2 version-paired JVM fixtures (and L1 pin where listed) | G009: BoolToSigmaProp charges FixedCost(15) before activation-dependent conversion. Before JIT activation a SigmaProp-valued input is permitted; after activation Boolean casting is required. Test result, exception and subsequent crypto proposition. |
| VERSION-G010 | L1,L2 | L2 version-paired JVM fixtures (and L1 pin where listed) | G010: selfBoxIndex returns -1 before activatedScriptVersion 2 and the actual self index afterward. Accessor cost remains 20. Same obligation as existing VERSION-selfboxindex-bug; no additional charge. |
| VERSION-G011 | L1,L2 | L2 version-paired JVM fixtures (and L1 pin where listed) | G011: xorOf uses old distinct-value semantics before JIT activation and XOR semantics afterward. No independent tariff here; changed Boolean result can change later charged execution. |
| VERSION-G012 | L1,L2 | L2 version-paired JVM fixtures (and L1 pin where listed) | G012: JIT activation fixes array concatenation; pairColl at CollsOverArrays.scala:184 truncates sides to matching lengths under JIT. Append and Zip prices remain unchanged, but representation, lengths, exceptions and later costs can differ. |
| VERSION-G013 | L1,L2 | L2 version-paired JVM fixtures (and L1 pin where listed) | G013: tree version >=3 permits PairColl versus CollOverArray equality in both representation directions; second branch is CollsOverArrays.scala:282. No new descriptor; changed equality can change short-circuiting and later execution. |
| VERSION-G014 | L1,L2 | L2 version-paired JVM fixtures (and L1 pin where listed) | G014: tree version >=3 changes BigInt/UnsignedBigInt conversion cases at SType.scala:412,435,460,487,512,524 and enforces signed BigInt bitLength <=255 at core/shared/src/main/scala/sigma/data/CBigInt.scala:18. Cast tariff remains target-based 10 or 30; results and exceptions affect continuation. |
| VERSION-G015 | L1,L2 | L2 version-paired JVM fixtures (and L1 pin where listed) | G015: pre-v3 serialization strips a leading Upcast; tree version >=3 preserves it. A preserved cast may later incur its 10/30 cost when executed. Distinct from DeserializationSigmaBuilder automatic operand-upcast insertion. |
| VERSION-G016 | L1,L2 | L2 version-paired JVM fixtures (and L1 pin where listed) | G016: versioned method parsing/type-argument handling and ByIndex parsing determine the reconstructed charged expression. ByIndex tree-version branch is data/shared/src/main/scala/sigma/serialization/transformers/ByIndexSerializer.scala:29. No separate parser tariff is introduced by these branches. |
| VERSION-G017 | L1,L2 | L2 version-paired JVM fixtures (and L1 pin where listed) | G017: tree version >=3 enables unsigned and Option data branches at CoreDataSerializer.scala:39,78,118,140 and Header branches at data/shared/src/main/scala/sigma/serialization/DataSerializer.scala:19,39. Global serialization callback totals and deserializeTo success depend on represented data. |
| VERSION-G018 | L1,L2 | L2 version-paired JVM fixtures (and L1 pin where listed) | G018: A6 selects primitive/type validation rules at TypeSerializer.scala:19,228; T3 selects function serialization/deserialization and embedded type tables at :111,211,258. Related predefined-type and unsigned checks are core/shared/src/main/scala/sigma/ast/SType.scala:117,167,194. Preserve each local activation versus tree-version condition; no independent type-validation tariff. |
| VERSION-G019 | L1,L2 | L2 version-paired JVM fixtures (and L1 pin where listed) | G019: A6 selects CheckAndGetMethodV6. Replaced rules 1011,1007,1008 cease being tolerated as soft forks under A6 at core/shared/src/main/scala/sigma/validation/SigmaValidationSettings.scala:60. This can turn baseline-cost soft-fork acceptance into rejection. |
| VERSION-G020 | L1,L2 | L2 version-paired JVM fixtures (and L1 pin where listed) | G020: A6 selects v6 validation-rule sets; core selection is core/shared/src/main/scala/sigma/validation/ValidationRules.scala:229. trySoftForkable at :248 handles recognized ValidationExceptions according to settings; it does not generally forgive ArithmeticException or CostLimitException. |
| ORDER-avl-escaping-constructor | L2,L3 | L2 throwing JVM probes and L3 competing-limit sweeps | An escaping verifier-constructor exception must prevent lookup charging. Invalid metadata and bad proofs are caught by pinned scrypto 3.0.0 reconstructedTree; no deterministic escaping serialized probe established yet. |
