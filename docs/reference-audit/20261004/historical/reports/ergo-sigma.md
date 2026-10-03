# ergo-sigma audit

**NOT_READY. The full authored review is complete. Three reproduced collection evaluation defects affect ordinary independently compiled and parsed scripts; the required strict documentation gate also fails.** This report and its evidence are local ignored artifacts, not a published certification.

## Scope and baseline

Revision `5d62fd5851e74fcb965b4aba50e1b423127f46f1`; review only, Linux x86_64/glibc 2.39, Rust/Cargo 1.95.0, `CARGO_BUILD_JOBS=6`. See [assignment baseline](ergo-sigma-evidence/assignment-baseline.json), the session baseline and shared command receipts. The pre-existing tracked README modification and historical local documents were not changed. No repository implementation, expectations, fixtures, user data or toolchain configuration changed.

All **71 primary authored files, 39,470 lines / 1,774,416 bytes**, were fully read including comments/helpers/tests: 66 crate files, mandatory prompt/codemap, and `ledger.toml`, `scala-enumeration.md`, `inventory-audit.md`. [JSON ledger](ergo-sigma-coverage.json), [TSV](ergo-sigma-coverage.tsv), [read history](ergo-sigma-evidence/read-history.json) retain exact SHA-256 hashes and complete inclusive range unions. Full shared document/generator reads from the earlier workspace phase are reused at exact hash and explicitly labelled; they do not replace the 71 current reads. Generated/captured fixture provenance and broader source ownership remain in workspace/serializer/difftest ledgers. Selected external parser source ranges and generated signature indexing are not claimed as new full authored reads.

The runtime refused fresh reviewer threads. Root explicitly reassigned this separate Sigma prompt to existing reviewer `/root/audit_workspace`; reviewer reuse is not a newly spawned independent second reader. Workspace phase artifacts remain preserved. No subdelegation, live remote nodes/services, publication, operational reinjection, destructive work or unbounded resource demonstration occurred. The completed small collection comparison predates the instruction to create no further custom demonstrations; later assessment uses preserved source and existing receipts.

Current collection authority is the real published pinned **sigma-state 6.0.6** compiler/serializer/evaluator, with the existing ergo-core 6.0.6 dummy spending context. Historical cost authorities include Scala node 6.0.2 declarations and 6.0.5/6.0.6 fixtures. Current Rust fixture-consumer success is distinct from a fresh JVM execution. No whole transaction/block or deployed-chain split is demonstrated by the new comparison.

## Contract map

- `reduce.rs` separates trivial reduction, context-aware public spending verification and recording-only convenience verification. The context-free API promises only trivial reduction. The context verifier applies tree/activation soft-fork checks, extension/group prechecks, deserialize surcharge and retained error/status rules before reduction. Evaluator and crypto JIT subtotals are truncated separately at the per-input block-cost boundary.
- `dispatch/eval.rs` routes runtime evaluation with depth110. The wire parser also limits depth110; caller-built ASTs are a separate accepted surface. Whole-tree prechecks, placeholder walks and deserialize rewriting precede ordinary opcode execution. An evaluator depth counter alone does not bound those preceding recursive walks or dependency allocations.
- Parser static type, runtime `Value` carrier and Scala data descriptor are different invariants. Primitive arrays, SigmaProp/box/header carriers, generic/legacy pairs, token adapters and context-backed box collections must preserve data and semantic element type under transformations, including empty results. SIG001–SIG003 concern this seam.
- Numeric widths, checked/wrapping arithmetic, narrowing, division/remainder, shifts and v3 BigInt/UnsignedBigInt bounds are operation/version specific. Metered descriptor/generic equality is distinct from plain startsWith/endsWith equality; recursively compared SigmaBoolean constructor mismatch may throw.
- Fixed/known-length charges usually precede work. Unknown-length flatMap/comparator charges can be deferred until a body returns, so a throw retains nested charges while skipping the deferred outer charge. Writer callbacks determine serialization costs; descriptor declarations and executed formulas must not be summed twice.
- Schnorr/DHT and AND/OR/threshold verification bind proposition/message through the reference transcript with 24-byte challenges, response consumption, XOR and GF(2^192) polynomials. Reference-permissive proof padding/trailing bytes are compatibility sensitive. Leaf extraction supports wallet hints, not a separate validity oracle. Local prover round trips are not independent authority.
- AVL guards dependency unwind paths, restores the thread-local expected-panic sentinel and poisons after a caught panic. Ordinary failed operations and digest availability are separately reference-sensitive. Panic-abort is prohibited for the wrapper contract; catch_unwind does not contain allocator abort or arbitrary stack exhaustion. Key-length/operation resource questions remain unproven.
- Traces are thread-local diagnostics with explicit enable/take lifecycle and rewritten-node identity constraints. Production features are opt-in, while the default package test graph enables cost-trace through the validation dev dependency. Actual OFF runtime was checked separately.

The [complete static contract index](ergo-sigma-evidence/contract-matrix.md) and [machine matrix](ergo-sigma-evidence/contract-matrix.json) contain **256 opcode-byte rows**, including constants/reserved/internal/deprecated forms, and **199 concrete receiver/method rows** with parser support, signatures, runtime arms, version gates, source formulas, failure behavior and independent evidence limits. There are 143 direct runtime methods and 56 registered methods without a direct arm or normally compiler-lowered. Registry presence is not executability; those 56 are not automatically defects. Handler excerpts and the fully read cost authority preserve dynamic item counts and failure order; absent independent per-opcode evidence is explicit.

| Axis | Contract owner/behavior | Evidence limit |
| --- | --- | --- |
| Tree v0/v1/v2 vs v3 | Header chooses parser v5/v6 registry; dead branches parse eagerly | Committed version/registry consumers pass; unusual direct MethodCalls lack exhaustive independent runtime coverage |
| Activated version below/at3 | Caller supplies activated version; method execution gates and historical behavior differ from header selection | Existing fixtures separate axes; epoch/network construction belongs to validation/node integration |
| Future versions | Activation and tree both beyond supported maximum can accept without verification at baseline cost | Source and committed tests; no live future governance claim |
| Opaque retained error | Unparsed tree is not universally True; current settings must recognize rule/args | Committed wrapped-error fixtures; Q011 replacement-rule reachability unresolved |
| Deserialize | Whole-tree surcharge uses retained SELF script bytes; embedded bytes charged separately; activation controls retained surcharge | Existing cost/error fixtures; no-SELF caller fallback reserializes |
| JIT/block units/cap | Checked i32-compatible arithmetic, block→JIT conversion, per-input evaluator and crypto truncation | Existing cost/ledger consumers; static cap literal is not a proof of dynamic voted bounds |

## Findings

### SIG001 — valid flatMap pairs are silently discarded by a token adapter

**P1 · evaluation correctness · REPRODUCED.** Expected: well-typed flatMap preserves every produced element; authority is pinned Scala6.0.6 compiler/evaluator, with ordinary dummy-context verification. At `ergo-sigma/src/evaluator/opcodes/method_call/coll.rs:384–413`, normalization recognizes generic/legacy pairs by arity2 and a first CollBytes field only. It drains them through filter_map and discards a pair whose second field is not Int/Long or whose first byte collection is not32bytes. The static element type is ignored. Legal `(Coll[Byte],Boolean)` and short-byte `(Coll[Byte],Long/Int)` pairs are not necessarily tokens.

The [completed receipt](ergo-sigma-evidence/collection-probe/receipt.json) preserves exact source, independently compiled v3 bytes, hashes and outputs. At HEIGHT0/activated3, all three trees parse to EOF in Rust. `sigmaProp(Coll(HEIGHT).flatMap{(x: Int) => Coll((Coll[Byte](x.toByte), true))}.size == 1)` and the Long/Int variants return Rust False at234JIT, versus Scala True at234JIT and Scala verification `true|23`. HEIGHT prevents a solely folded constant-only witness. Rust public reduction was executed; Rust proof/full-transaction validation was not. Source `reduce.rs:331` connects this reducer to ordinary nontrivial spending verification, establishing the critical evaluator compatibility impact without a chain-split/prevalence claim.

Trigger: a valid serialized contract flatMaps such pairs. The comparison used production trace-OFF; code is shared across feature variants. Existing tests emphasize32byte/Long token-shaped pairs or separate primitives and miss this composition. Smallest fix: preserve declared pair type and every value; select Tokens only for the exact token type through a lossless conversion. A malformed token must fail explicitly, not disappear. Regression: exact three serialized Scala cases,32byte/Long control and nested pairs, asserting proposition, cost/error and production spending/transaction context. Preserve historical carrier behavior and unrelated token-ID semantics.

### SIG002 — reverse loses the SigmaProp collection carrier required by consumers

**P1 · evaluation correctness · REPRODUCED.** Expected: reverse retains element type and leaves valid subsequent operations executable. At `property_call.rs:951–983`, reverse preserves only five primitive carriers; other collections become CollGeneric. `opcodes/sigma.rs:452–464` accepts only CollSigmaProp for AtLeast, and `evaluator/cost.rs:490` rejects the transformed carrier in descriptor equality.

The ordinary compiled v3 script `atLeast(1, Coll(sigmaProp(HEIGHT >= 0), sigmaProp(HEIGHT >= 1)).reverse)` parses to EOF, then Rust returns TypeError at171partialJIT. Scala reduces True at194JIT and verifies `true|19`. A reversed one-element SigmaProp equality throws `Unexpected descriptor collection carrier` at126partialJIT; Scala reduces True at155JIT and verifies `true|15`. A group-element reverse equality control agrees at1074JIT. [Exact outputs](ergo-sigma-evidence/collection-probe/rust.jsonl) retain successful versus error outcomes and partial costs separately.

Trigger: a legal v3 reverse feeds threshold or equality. Primitive reverse and standalone threshold/equality tests miss composition. Fix: preserve all supported typed carriers, or consistently accept semantically equivalent generic carriers in consumers with the reference's charge/error order. Regression: both exact serialized cases, nontrivial propositions and other descriptor collections, then production spending context. No storage change is required; preserve historical PairColl rules. Rust proof/full transaction execution for these cases remains unrun.

### SIG003 — empty flatMap returning a bound collection is incorrectly typed Byte

**P1 · evaluation correctness · REPRODUCED.** Expected: retain mapper result element type B even without a mapper invocation. `coll.rs:285–302` recognizes only constant/concrete/Boolean collections and If bodies. At `coll.rs:440–441`, an empty receiver and ValUse mapper body fall back to empty CollBytes, ignoring captured bindings.

For `{ val ys = Coll[Long](); sigmaProp(Coll[Int]().flatMap{(x: Int) => ys} == ys) }`, the exact independently compiled v3 bytes parse to EOF. Rust reduces False versus Scala True/verification `true|16`; both reductions charge164JIT. The serialized mapper retains ValUse. Source connects reduction to ordinary spending; Rust proof/full transaction execution is not demonstrated.

Existing empty flatMap tests cover direct constant/concrete bodies, and comments explicitly preserve a fallback residual. A documented residual still breaks this valid contract. Fix: resolve full static Coll[B] with captured/parameter bindings, or thread verified result type through Func. Do not execute the mapper to infer an empty type. Regression: this bound-Long case, empty runtime receiver with nonempty captured body and typed method/GetVar/If result forms under matched contexts. Preserve zero mapper calls and charges for an empty receiver.

### SIG004 — strict public Rustdoc fails on six links

**P2 · documentation/build contract · REPRODUCED.** COMMON requires strict Rustdoc. `RUSTDOCFLAGS='-D warnings' cargo doc --locked -p ergo-sigma --no-deps --all-features` exits101. [Log](ergo-sigma-evidence/strict-doc.log): public docs link to private `AvlVerifier::guarded` at `avl.rs:30,71`; unresolved links occur at `types.rs:370,458,467,706` (`minimal`, bracketed Coll element names, SoftForkNotActivated). Passing zero doctests does not validate public documentation compilation.

Fix qualified visible links and render explanatory types as code; do not disable warnings globally. Acceptance: exact scoped strict command and the coordinated workspace strict gate pass. No runtime verdict/security consequence is claimed.

## Coverage and verification

[Command receipts](ergo-sigma-evidence/results.json) contain cwd, exact command, revision, feature-graph caveat, elapsed time, exit/result and complete logs. Collection receipt explicitly records uncaptured timing and preserves the initial audit-harness compile failure plus corrected successful execution; setup errors are not product defects.

| Check | Result | Executed scope |
| --- | --- | --- |
| locked baseline tests | PASS |514unit+66integration;1ignoredauction;0doctests |
| cost-trace smoke | PASS |2selected/65filtered |
| traced/untraced API test | PASS |1selected/66filtered; same compiled test feature graph |
| value-trace tests | PASS |515unit+66integration;1ignored;0doctests |
| scoped clippy alltargets/allfeatures, warnings denied | PASS | actual enabled graph |
| no-default library check | COMPILE_ONLY | production minimal compile |
| normal and normal+dev feature trees | GRAPH_CAPTURED | default tests unify cost-trace via dev validation |
| doctests | PASS |0tests |
| strict Rustdoc | FAIL101 |six links |
|895existing emission cases ×4independent feature builds | PASS |OFF/cost/value/both; public reduction+EOF, diagnostic lifecycle where compiled |
|7completed serialized pinned-Scala collection cases |6mismatches,1matchingcontrol |Rust public reduction; Scala reduction and dummy-context verification |

[Feature parity](ergo-sigma-evidence/feature-runtime-parity.json) retains identical proposition/error display/partial-JIT output hash `e7b3f9e78e4a5517d4664b7dd443dc5c921d0575bef3a63b2fb4f8b9ecac787a` across895cases×4builds,0errors. The audit-owned independent workspace has no validation dev dependency; verbose rustc commands prove actual OFF. [Lock receipt](ergo-sigma-evidence/feature-harness-lock.json) records root lock provenance and zero changed existing dependency versions/checksums. This closes narrow feature-OFF runtime evidence, not every error/nested trace/script/proof/transaction/timing/resource path.

The ignored auction diagnostic needs absent gitignored headers_700000_700500; not fetched/run. Current committed cost/mainnet/emission/AVL/SANTA consumers pass. Mainnet proof fixtures, synthetic DHT/topologies and local-prover tests have distinct authority strength; a local proof round trip is not independent reference evidence. Unsigned on-chain constant tests stop at parser/carrier assertions, not full spends. Passing suites missed the six composed collection cases.

Shared root fmt/clippy/locked nextest(7629pass98skip)/doctests/deny/documented advisory exception/machete/cost-ledger/UI gates were reused unchanged; shared strict docs fail. Native release/boot proof belongs to workspace/node. No repeated shared gates or fresh external replay were run here.

All cost authorities were fully read. Historical inventory RESOLVED means363declarations/paths reconciled, not every behavior independently executed. Ledger274CLOSED/25N-A includes historical evidence and explicit carrier/context limitations. Wrong/incomplete source-state linkage and strict evidence absence are workspace WS004, not a duplicate Sigma finding. Price extraction, accepted single-tx parallel fixtures and historical L4 output cannot establish every cumulative production cost/error/version branch.

## Unresolved risks and unrun scenarios

The following are hypotheses or validation gaps, excluded from the four confirmed findings:

1. **Q011 rule metadata:** measured deserialize maps1007/1008→1017/1018 atactivation3. Pinned current JVM settings do not register those latter IDs. Reconcile retained serializer metadata, validation settings and a reachable governance/context path before any accept/reject claim. No further custom comparison after steering.
2. **Context Box substitution:** `subst_constants.rs:137` uses `value_to_typed_sigma(new_value,None)` and collection unpacking omits context box carriers. Source confirms an API restriction for SelfBox/BoxRef. No matched valid serialized Box template / independent spending comparison was executed; not counted as a consensus defect.
3. **Materialized v6 context values:** serialize helper comments describe unconditional Scala Value.checkV6Type restrictions, while GetVar/register/generic conversion routes differ. Actual extension/register wire reachability and matched contexts remain unverified; no verdict assertion.
4. **Caller-built/dependency resources:** recursive prewalks precede eval depth guard, large AVL key lengths/operation counts rely on dependency bounds, and extreme crypto saturation can differ from Scala checked error representation. Wire and dynamic cost bounds constrain reachability but are not complete proofs. No stack/allocator crash, giant allocation or high-cost campaign attempted.
5. **EP001/Q003 dynamic cap:** primitives already owns the confirmed P2 static4769136literal false assurance; historical voted limits exceed it. Sigma checked conversion/charges were reviewed, but arithmetic checks precede cap rejection and a small cap cannot bound an arbitrary pending charge. Voted parameters/error handling/block totals await validation owner. No new Sigma runtime overflow claim.
6. **Independent breadth:** unusual direct registered methods normally lowered by compiler, every nested carrier, independently generated mixed valid/invalid proof topology, all transcript mutations, every AVL panic followup, nested trace lifecycle and real tx context permutations are not exhaustively independently executed. Matrix records exact static paths and missing oracle evidence.
7. **Portability/performance:** Linux checks only; other platforms/32bit hosts, sanitizers, throughput/latency distributions and live Scala replay campaigns NOT_RUN. Panic-abort compile guard was inspected; no forbidden runtime test. Emission feature checks are not a benchmark/current-mainnet certification.

## Remediation and readiness

Repair flatMap's lossless pair handling and empty type recovery, then reverse/descriptor compatibility. Pin all six exact serialized mismatches; assert proposition, error/partial/final cost and full production spending/transaction context separately while preserving old-version/JIT and permissive reference proof contracts. Repair six public doc links. Reconcile Q011, voted parameter bounds, materialized context substitution and missing independent proof/AVL/feature compositions with their owners.

Authored inventory/review is complete: no unread primary paths and no source changes. **NOT_READY** follows from reproduced critical evaluator compatibility defects and strict docs, not from hypotheses being treated as failures. No chain split, deployed prevalence, fund compromise or whole-node certification is claimed.
