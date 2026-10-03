# ergo-compiler review

**Readiness: NOT_READY. Authored source review complete; four material API, compatibility or validation findings remain.** Seven confirmed findings: four P2 and three P3. No P0/P1 or whole-transaction failure is claimed. EC002 shares the serializer root cause with **ergo-ser ES010** and must be deduplicated in the workspace aggregate.

## Scope and baseline

Review-only audit of revision `5d62fd5851e74fcb965b4aba50e1b423127f46f1`. These are ignored local artifacts. No repository source, configuration, fixture, example, test or user file was changed. Pre-existing changes were README.md, the audit-prompt directory and two historical audit documents; baseline hashes/state are in `baseline.json`.

All **197 primary authored files** were independently fully read, including comments and inline/integration tests:67 crate files, mandatory prompt/codemap,128 authored ErgoScript sources. Exact coverage is **60,279 lines,2,511,089 bytes,zero hash mismatches**. The `.es` files total **11,767 lines** under the recorded split-line convention; the original ownership estimate was11,720, not a different read scope. Full reads have inclusive ranges covering every line. Search, discovery, generated-data validation and truncated outputs are not counted as full reads. See `ergo-compiler-coverage.json`, `.tsv`, `.md` and `ergo-compiler-evidence/read-history.json`.

Shared manifests, architecture/compatibility/security/contribution documents, JVM generators, fixture manifests and generated capture integrity are reused at matching hashes from the completed workspace/difftest review. The compiler source-map design was fully read for this assignment. The external ledger has22 honest full-read or data-validation records; generated JSON/lockfile validation is not authored-source reading. Every `.es` example is independently read primary source. Negative syntax, incomplete parameterized contracts and editor examples are present; corpus acceptance is not deployment certification.

Platform: Linux x86_64/glibc2.39; Rust `1.95.0 (59807616e 2026-04-14)`; Cargo `1.95.0 (f2d3ce0bd 2026-03-21)`; locked dependencies; build jobs6. This separate prompt/report reused `/root/audit_workspace` after runtime refused new threads; it is not a claimed new independent reviewer identity. FULL COMMON and compiler prompt/assignment were read. No subdelegation occurred.

The package declares no features. The saved production graph excludes Sigma; the test graph uses `ergo-sigma` as a dev dependency. `--no-default-features` is compile-only, not another proven runtime feature matrix. Shared unchanged gates were reused:fmt, workspace all-target/all-feature clippy, nextest, doctests, dependency/license/advisory checks and UI passed; shared strict Rustdoc failed. Those gates do not supersede the scoped strict-doc result.

Authority is the public compiler/API contract, current wire consumers, pinned reference source and capture provenance. Current Parser/Typer scripts pin `sigma-state6.0.6`; historical charter/seed sections cite6.0.2. Captures retain their actual frontend version/network/origin. A changed pin does not silently validate older expectations. No fresh full live compiler/parser/typer/contract recapture ran; saved independent serializer evidence is explicitly identified below.

## Contract map

Parse/bind/typecheck/compile and contract-template entry points accept source, frontend version and supported lifted environment/network values. Parsing must consume intended grammar/EOF and give honest offsets. Binding must preserve scope/order/shadowing. Type assignment must produce a consistent supported tree or structured error across numeric coercion, generics, method/predef visibility and compile-time evaluation. Local parser limits are API resource contracts, not consensus rules.

Emission maps each typed node/payload to compatible wire IR or explicit rejection. Ordered graph rewrites must preserve spending meaning and independently anchored bytes where claimed. Root coercion, segregation and assembly determine full tree bytes. P2S hashes the full tree; P2SH uses the correctly inlined proposition. Templates add named placeholders/defaults/types, declaration-versus-HAMT ordering and separately requested application-header versions. Source maps provide best-effort attribution and must leave unknown origins absent.

Compilation is not block validation. A rejected compiled byte sequence matters to address callers, but this review does not demonstrate a spend, proof, full transaction or canonical-chain failure. Transport/authentication/service limits belong to API/node owners; no remote service was invoked.

## Findings

### EC001 — BigInt constants reach an unreachable argument guard

**P2 · API correctness · SOURCE_CONFIRMED.** `src/typer/assign/apply.rs:740-761` describes an optional Byte/Short/Int/Long conversion but calls `numeric_constant_parts`, which also returns BigInt, then sends it to `unreachable!`. Guards at `:612-623` and `getVarFromInput` adaptation at `:91-98` run this helper before checked narrowing can return `TyperError`.

This is a supported-value boundary: `EnvValue::BigInt` lifts to Constant/BigInt at `src/env.rs:171-174`; binder substitution preserves it. The `bigInt` predef also builds a numeric constant. Generic apply typechecks arguments before adaptation at `apply.rs:350`. Such an argument reaching a `getVar`/`executeFromVar` or applicable input-variable guard can panic through public Result-based typing/compile instead of checked conversion or structured rejection. This is source proof only: no new custom execution, Scala verdict, remote availability or transaction claim.

Restrict the helper domain or explicitly range-check BigInt before narrowing. Preserve supported range behavior and documented class deviations. Add ordinary public API coverage for all numeric payloads in these guards, asserting supported output or structured error. Existing Int-range and BigInt-lift/arithmetic tests do not cover their combination.

### EC002 — The compiler self-check certifies bytes the pinned reader rejects

**P2 · compiled-output compatibility/validation · REPRODUCED using existing tests and saved reference evidence.** `src/lib.rs:894-917` promises a “GENUINE ACCEPT” family. `src/tree/mod.rs:402-435` substitutes the frontend argument as an activated reader override before deriving addresses. Its existing unit at `:1604-1660` passed here, calls public `compile` on `sigmaProp(SELF.R4[UnsignedBigInt].isDefined)` at frontend3, asserts **`1000d1e6c6a70409`**, and checks the same override reader.

Those are the exact existing serializer fixture bytes in `ergo-ser-evidence/probe/probe-input-provenance.json`. Saved pinned `sigma-state6.0.6` standalone reader evidence rejects them at activated1/2/3; the normal Rust reader at3 rejects because type9 requires tree-version3 while header0 is emitted. The override accepts. Local self-consistency therefore does not establish advertised independent acceptance. `compiled-output-reference.json` records source/receipt hashes and the existing executed unit. Independent rejection here covers this exact shared byte sequence; the other six unit shapes have Rust assertions, not six new independent comparisons.

The parser override root cause is **SER ES010**. EC002 records the compiler caller, actual output and certification consequence; aggregate that root cause once. No fresh Scala compiler-source re-derivation, proof, spend, full transaction, stranded funds or chain occurrence was demonstrated. Older6.0.2 comments are not fresh6.0.6 authority.

Resolve the reader/version contract first, then align header/serialization/self-check with the intended independent reference. Preserve frontend visibility, emitted header, activation and template-apply distinctions; preserve v0 data gates, bare-SigmaProp route and addresses. Acceptance needs the existing emitted fixtures checked by the pinned independent reader, then appropriate independent runtime authority before spendability promises. The same override round trip cannot close this gap.

### EC003 — The counter does not prove the documented whole-pipeline depth bound

**P2 · resource contract/important validation gap · SOURCE_CONFIRMED.** `src/parse/mod.rs:46-72` says one128 expr/type counter bounds all downstream recursive structures, needs no other guard and remains below any real stack-overflow threshold. Extractor/pattern recursion (`parse/block/definitions.rs:59-110`) and nested type-argument declarations (`:338-376`) have routes outside those wrappers. Iterative infix construction (`parse/operators.rs:197`) and stable-id/suffix chaining (`parse/block/lambda.rs:155`) can create deeply linked ASTs without measuring resulting depth. Binder and other recursive passes precede the wire-reader self-check.

Passing depth tests cover nested parentheses and Coll annotations, not every grammar family/produced AST/equality/printing/drop or pass. This is a guard/claim gap only. No crash, threshold, attack, measured amplification or denial of service is inferred from call shape. Caller size bounds and later serialization limits qualify exposure without proving the internal claim.

Either state the limited guarantee accurately and remove unmeasured stack assurance, or bound produced AST/type/pattern depth before recursive consumers and cover remaining families. Preserve corpus support and structured TooDeep errors. Acceptance should cover ordinary grammar families/boundaries on supported platforms; performance certification requires separate evidence. No new demonstration was created.

### EC004 — Manual live parity mixes v2 expectations with a forced v3 oracle

**P2 · oracle-test correctness · SOURCE_CONFIRMED.** `tests/it/typer_oracle_parity.rs:122-126` identifies accepted v2 sources `1.toBits`, `1L.toBits`, `1L.toBytes` whose method owners differ at3. The normal sweep excludes them, and `:522-545` tests both versions. Ignored `seed_live_oracle_parity` at `:637-661` gathers all accepts except SWEEP_SKIP, includes these v2 expectations, then forces `ORACLE_TREE_VERSION=3` for the entire child.

Committed seed records at `test-vectors/ergoscript/typer/golden_seed.txt:393-395` expect `%SNumericType`; supported v3 behavior has concrete Int/Long owners. Thus the manual validation path is internally inconsistent about its authority. It was ignored/not executed; no fresh JVM failure is claimed. Record hashes/source proof are in `fixture-test-reconciliation.json`.

Batch by recorded version, or filter v2 owners from the v3 batch and validate them separately at2. Preserve artifact/network pin and do not silently overwrite expectations. Acceptance should execute the corrected existing manual test with cached pinned prerequisites. Normal tests miss this because they correctly special-case versions while the live path is ignored.

### EC005 — Public IR/template values omit validation preconditions

**P3 · API documentation · SOURCE_CONFIRMED.** Public ConstPayload/TypedExpr construction (`src/typed.rs:74,160`) bypasses environment point validation, while `print_typed` uses decompression expects (`typed_print.rs:224-240`). Public ContractTemplate fields (`contract_template.rs:68`) allow manual values, while `expression_tree_bytes`/`serialize` trust writer invariants at `:391-425`. Application inputs are checked but stored types/defaults/expression remain trusted.

These infallible APIs rely on valid compiler-produced data without a clear validation/Panics contract. Normal source/env compilation validates points; no arbitrary-source panic or executed malformed-value demonstration is claimed. Document exact preconditions and offer checked constructors/validation or a Result boundary where appropriate. Preserve deliberate trusted low-level construction. Compiler-produced-only tests do not establish behavior of manually built public values.

### EC006 — Strict public documentation fails

**P3 · documentation build · REPRODUCED.** `RUSTDOCFLAGS="-D warnings" cargo doc --locked -p ergo-compiler --no-deps --all-features` exited101 with **75 diagnostics** excluding the final failure summary. These include private-item links, unresolved type/prose links and function/module ambiguity. Exact messages/locations are in `strict-doc-diagnostics.json`, log in `strict-doc.log`. Three doctests and clippy passed.

Use code formatting for private/prose concepts, qualify public links and disambiguate function/module references. Exposing internals solely to silence links is unnecessary. Acceptance is the same strict command passing; non-strict docs/ordinary tests do not enforce it.

### EC007 — Current comments and manual test instructions have drifted

**P3 · documentation accuracy · SOURCE_CONFIRMED.** `Cargo.toml:3` describes M1+M2/future byte emission though end-to-end compilation is implemented. `src/fold.rs:30` says nonconstant `a==a` is handled by CSE; the full-read CSE shares/materializes rather than rewriting equality. No fresh independent equality mismatch is claimed. `cse/key.rs:58` says constants never hoist despite explicit hoistable constant categories. Instructions at `tests/it/compile_semantic_parity.rs:65,546` use `--test compile_semantic_parity`; the manifest's integration target is **it**. Corpus/typer comments have similar module-as-target instructions.

Update current claims and target commands, retaining expressly historical milestone accounts as history. An existing runnable test is `cargo test --locked -p ergo-compiler --test it compile_semantic_parity::compile_seed_semantic_parity`. Manual recapture needs it/exact filters and can rewrite captures; it was not authorized/run. Validate prose against current pass behavior/manifest targets and keep oracle provenance beside capture instructions.

## Coverage matrix

Every row has complete owned source/comment/test reads. Existing passing witnesses are finite fixture evidence, not unexecuted external comparisons.

| Boundary | Reviewed contract/existing witness | Limit |
| --- | --- | --- |
| Tokens/grammar | Comments/strings/escapes, literals/minima/suffixes, identifiers, whitespace/cuts/EOF, precedence/associativity, blocks/lambdas/contract syntax; full parser tests PASS. | No new grammar campaign or fresh live parser recapture. |
| Positions | UTF-8 offsets, line/column, Unicode and absent/synthesized positions; parser/seed tests PASS. | No exhaustive independent Unicode/surrogate recapture; map offset0 may remain absent. |
| Binding/env | Order/scope/shadowing/free vars/substitution, scalar/coll/curve/BigInt/ProveDlog carriers, address-network decoding and explicit opaque emission rejection; tests PASS. | Unsupported EnvValue carriers and EC005 manual-value preconditions. |
| Types/nodes | Every SType/TypedExpr/ConstPayload arm, unification/occurs/generics, options/tuples/functions/colls and numeric casts reviewed. | EC001 helper-domain fault; documented large BigInt/i128 capability limit. |
| Methods/predefs | Owner/ID/type args, versions, coercions, compile-time validation/error phases; v2/v3 units PASS. | EC004 live version batching; fresh complete live oracle NOT_RUN. |
| Emission | All typed dispatch cases map to explicit wire IR or supported error; scopes/IDs/captures/select/property/type/origin paths read. | Supported rejection is not arbitrary-contract completeness. |
| Graph/walkers | Lambda/cast/overflow/dead-code/v0-data/Sigma/tupling/CSE/thunk scopes and every child arm read; captured assertions PASS. | Local runtime reduction is not independent Scala execution. |
| Assembly/addresses | Bare-root header, append-order/no-dedup constants, placeholders, compact writer/EOF, P2S fulltree/P2SH inlined proposition/network reviewed. | EC002 reader mismatch; no spendability proof. |
| Templates | Names/defaults/type/extra/missing values, four/five+ HAMT ordering/hash/Unicode and apply-version distinctions;20 serialize/16 apply captures consumed PASS. | EC005 manual invariants; fresh JVM recapture NOT_RUN. |
| Source maps | Byte/address parity, origins across folds/CSE/segregation, bounds and best-effort alignment reviewed; existing tests PASS. | No independent runtime attribution for every transformed shape. |
| Resource/determinism/platform | Observable map order versus lookup-only hash maps, copies/recursive passes/dependency boundaries inspected. | EC003; independent-process/order-varied determinism, stack thresholds, performance/other hosts NOT_RUN. |

### Ordered graph invariants

Actual `tree/mod.rs:50-245` order:lambda/application rejection; direct-constant casts; isProven fusion; generic fold; dead-val pruning; v0-data gate; lowering; fold; isProven cleanup; lambda tupling; CSE/materialization; final fold. Assembly follows. Current order takes precedence over historical milestone counts.

| Pass | Invariant and evidence |
| --- | --- |
| Lambda gate/casts | Reject unsupported applications before rewrites; checked casts expose direct constant arithmetic before overflow, preserving documented cast-chain behavior. Existing cases PASS. |
| First fusion/fold | Preserve Bool/Sigma meaning; child compile-time failures survive parent/dead-branch erasure. Overflow/fusion/dead-RHS cases PASS. |
| Prune/data gate | Prune after compile-time checks, before CSE counts; reject surviving v3-only constant data under0. Folded/dead UBI cases PASS. |
| Lower/refold/cleanup | Constant DLog/DHT and singleton lowering exposes constant equality/Sigma adjacency for later cleanup. Byte/address fixtures PASS. |
| Tuple/CSE | Preserve captures/arity via projections; first-build scopes/thunks/siblings govern identity; keys/child walks/use counts/dense IDs reviewed and finite captured assertions PASS. |
| Final fold/assembly | Handle inlined constant adjacency without disturbing hoisted IDs; append constants without dedup and preserve bare-root route. Existing parity PASS, independent usability EC002. |

### Version axes and known deviations

| Axis | Role/evidence |
| --- | --- |
| Frontend tree_version | Parser/binder/type/method visibility; finite v2/v3 fixtures PASS. |
| compile wire header | Fixed0, separate bare-SigmaProp/segregation paths; bytes/address assertions PASS, embedded v6 family EC002. |
| Activated reader/evaluator | Runtime/governance context does not replace header authority. Exact saved6.0.6 rejection atA1/A2/A3; no governance/proof/fulltx claim. |
| Contract apply version | Requested output header/size version distinct from template frontend; existing16 capture consumers PASS. |
| Oracle artifact | Historical6.0.2 sections/current6.0.6 scripts, retained source/network/frontend metadata; full cross-version recapture NOT_RUN. |

Current SEMANTIC_SKIP, P2SH/P2S mismatch, verdict/position deviation and corpus accept-invalid sets are empty, enforced for the finite captured corpus. Typer SWEEP_SKIP remains `tcs g2` rendering-only; three v2-owner sources are graded separately; two class exceptions are `PK(1)`/`unsignedBigInt("-5")`. Rendering exceptions do not justify skipped byte/address/verdict checks. Exact sets/hashes are in `fixture-test-reconciliation.json`.

Separate capability limits: mirrored ignored tuple advanced/modular operations, unrepresentable env collections, opaque SigmaProp emission, documented i128 BigInt downcast extraction, finite practical tuple selectors and reverse-parsing subset. Historical/local val-bound register optimization commentary lacks a new independent witness. Source-map alignment is best effort, with honest absence. None establishes arbitrary-contract fidelity or a new independently confirmed wrong byte result.

## Commands and evidence

All commands ran at repository root/revision/toolchain above. Full argv/environment/time/exit/log paths are in `ergo-compiler-evidence/results.json`.

| Command | Result |
| --- | --- |
| cargo test --locked -p ergo-compiler | **PASS**825 unit+219 integration+3 doctests,0 failed,7 ignored;10.456s. |
| cargo clippy --locked -p ergo-compiler --all-targets --all-features -- -D warnings | **PASS**,5.972s. |
| cargo test --locked -p ergo-compiler --doc | **PASS**3. |
| RUSTDOCFLAGS="-D warnings" cargo doc --locked -p ergo-compiler --no-deps --all-features | **FAIL101**,75 diagnostics. |
| cargo check --locked -p ergo-compiler --lib --no-default-features | **COMPILE_ONLY**,exit0; no package feature axes declared. |
| cargo tree --locked -p ergo-compiler -e normal,features / normal,dev,features | **GRAPH_CAPTURED**,exit0, production/test distinction retained. |

Fixture inventories:317 compile,20 template serialize,16 apply,79 parser-corpus and79 typer-corpus records. Shared integrity/provenance review and existing compiler consumers passed. The compile suite reduces both byte streams using **Rust Sigma**; stored independent bytes/addresses/verdicts are useful anchored historical data, not a fresh Scala runtime proof.

Seven ignored cases are exactly:compile live recapture, parser-corpus live parity, typer-corpus live parity, typer seed live parity, modular arithmetic, subst_const unrepresentable env, tuple advanced operations. Four are manual oracle work; three are documented unsupported/reference-ignored scenarios. Full names/reasons are in `fixture-test-reconciliation.json`; no recapture occurred.

NOT_RUN/unavailable evidence:full live parser/typer/compiler/contract recapture, proofs/spends/full transactions/governance, independent-process/order-varied determinism, complete runtime source attribution, performance/stack threshold/sanitizers/non-native hosts. This absence is not a passing comparison or demonstrated defect. Existing manual parity can use `--test it` with exact filters/pinned Scala/JVM prerequisites after EC004; fixture-writing recapture requires a separately authorized change. No new custom demonstrations/mutations/adversarial inputs were made.

## Remediation and readiness

1. Correct EC001 and verify structured outcomes for every supported numeric carrier.
2. Resolve SER ES010, align compiler version/self-check promises, then independently validate existing emitted fixtures and any spendability claim.
3. Correct or prove EC003 with actual produced structures/grammar families, preserving ordinary corpus support.
4. Repair EC004 version batching before capture certification; retain authority metadata rather than silently replacing expectations.
5. Document/check public construction invariants, repair strict Rustdoc and current pass/target instructions.

The authored inventory and ordinary quality review are complete; tests/clippy passed and evidence is durable. **NOT_READY** reflects remaining material API/compatibility/validation issues for the reference-quality compiler scope, not an operational exploit or canonical transaction failure. Next separate assignment is Mining; workspace integration awaits all20 crate reports.
