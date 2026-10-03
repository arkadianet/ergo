# Audit prompt: ergo-compiler

Audit all of `ergo-compiler` as the ErgoScript-to-ErgoTree compiler of a
prospective reference-quality Rust Ergo node, including its developer tooling.

First read `docs/audit-prompts/COMMON.md` and follow its full methodology,
review-only default, evidence standards, reporting format, and coverage ledger.
Then read `CONTRIBUTING.md`, `docs/compatibility.md`, the manifest/root,
`docs/codemap/ergo-compiler.md` and
`docs/ergoscript-compiler-source-map-design.md`. Commands and repository-prefixed
paths are relative to the repository root; abbreviated source paths are relative
to this crate. Verify documentation against current code. Inventory every file,
inline/integration test, comment, fixture, source include and linked generator.

## Mission and trust boundaries

Compilation is not a block acceptance surface, but wrong bytes or addresses can
strand funds or compile a different spending condition. Audit parser/typer
verdicts, failure classes/positions, typed trees, emitted bytes, addresses and
runtime meaning independently. A local interpreter agreeing with the compiler
does not prove either matches the independent Scala compiler.

User source and environment values reach API-facing compilation. Trace source
size/depth/resource limits and supported environment representations. Review
documented deviations and claimed closures against current externally anchored
tests, rather than taking a historical ledger status as fact.

## Source landmarks

- `ergo-compiler/src/lib.rs`: charter, public API and detailed deviation ledger.
- `token.rs`, `parse/`, `ast.rs`, `error.rs`, `span.rs`: syntax and positions.
- `binder.rs`, `env.rs`, `stype.rs`, `typecheck.rs`, `typed.rs`, `typed_print.rs`.
- `typer/assign/`, `typer/unify.rs`, `methods.rs`, `predef_ir.rs`.
- `emit/`: typed AST-to-wire IR, scopes, method/select lowering and type mapping.
- `tree/`: graph pipeline, assembly, cast/lambda/version gates and child walking.
- `fold.rs`, `inline.rs`, `isproven.rs`, `lower.rs`, `tuple.rs`, `cse/`.
- `contract_parse.rs`, `contract_template.rs`, `param_order.rs`, `source_map.rs`.
- All `ergo-compiler/tests/it/` tests and referenced
  `test-vectors/ergoscript/{corpus,typer,compile,contract}/` fixtures.
- `scripts/jvm_parser_oracle/` and `scripts/jvm_typer_oracle/`, including pinned
  artifacts, batch protocol, environment values and network/version settings.

## Syntax and type audit

1. Check tokenization and scannerless grammar together: comments, nested comment
   behavior, identifiers/backticks, strings/escapes, numeric suffixes, negative
   minima, large literals, reserved words, whitespace/newlines and EOF.
2. Verify precedence, associativity, unary/postfix/application/select chaining,
   lambdas, blocks, val/def grammar, annotations and contract signatures. Test
   ambiguous prefixes, malformed/truncated input and leftover source explicitly.
3. Verify UTF-8 byte offsets versus JVM source positions, Unicode/surrogate
   cases, 1-based line/column and absent/synthesized positions. Check recovery
   paths cannot manufacture a misleading location or consume arbitrary suffixes.
4. Inspect parser depth limits through expressions and type grammar, then follow
   recursive passes/equality/printing/drop after parsing. Bounded parser descent
   alone is not a bound on wide input or later pass recursion/work.
5. Trace binding order, lexical scopes, shadowing, free variables, substitutions,
   recursive definitions and environment/predef name collisions. Verify the
   claimed single-pass/fixpoint binder behavior with independent examples.
6. Audit every type and typed-node case: numeric widening/narrowing, generics,
   unification/occurs checks, options, collection/tuple/function carriers, method
   lookup, specialization and polymorphic result types. NoType/error placeholders
   must not reach successful emission unnoticed.
7. Verify method/predef visibility across versions, method owner/ID/type args,
   implicit coercions, argument evaluation and error class/position. Compare
   parser, binder, typer and emit reject responsibilities with the actual oracle.
8. Check environment lifting, Base58/Base64/address handling and network choice,
   group-element compile-time validation/formatting, ProveDlog values and opaque
   SigmaProp handling. Verify documented reject-side deviations by exact examples.
9. Inspect constant folding during binding/typing separately from later graph
   folding: overflow, division by zero, BigInt bounds, booleans, strings, decoded
   constants and reflection/string conversion can fail at different phases.

## Emission and graph audit

Map every `TypedExpr`/`ConstPayload` to wire IR or an explicit supported rejection.
Check opcode/payload/type agreement, bound IDs, scope push/pop, lambda captures,
receiver lowering, property/method selection and source-origin recording.
Unsupported shapes must not accidentally emit plausible incorrect bytes.

Audit the actual ordered graph passes and their interactions; reconcile comments
calling them a particular pass count with what runs. For each fold/lowering/gate,
establish a transformation invariant and an independent byte/semantic witness:

- Cast folding and arithmetic overflow, including dead branches/dead val RHS,
  direct constants versus cast chains and rejection before pruning.
- isProven/BoolToSigmaProp cancellation, HasSigmas reconstruction, Sigma logic
  simplification, DLog/DHT folding and singleton all/any unwrapping.
- Dead-value reachability, binding substitution, multi-argument lambda tupling
  and field projection; no capture, evaluation-order or arity drift.
- CSE keys, equality, interning, first-build scopes, thunk/sibling isolation,
  pair-projection memo exceptions, free variables, hoist predicates, use counts,
  materialization order and deterministic val IDs.
- Every IR child walker/decompose/recompose arm across all payloads. An omitted
  child can bypass a gate, cost work in a dead branch or corrupt a source map.
- Version-zero serialization gates and GraphBuilding rejection gates: validate
  both verdict and failure class against the pinned compiler, including shapes
  accepted by the typer but rejected by graph building.

Determine which maps affect observable ordering and which are membership-only.
Use repeated independent process runs and order-varied inputs to establish byte
determinism; banning every HashMap would be an unjustified implementation rule.

## Assembly, contracts and tooling

Verify constant segregation's append order, no-dedup semantics, compact writer
interaction, placeholders and reread. Bare SigmaProp roots use a distinct header
and segregation path. Check the full tree bytes and their independent expected
addresses rather than only the result's locally parsed form.

Keep frontend `tree_version`, emitted header version, activated deserialization
context and contract-apply version distinct. `compile` uses a v0 wire header;
contract application can use a size-delimited requested version. Audit the
post-write self-check, trailing-byte handling and any opaque/degraded reread
success; parsing alone does not establish spendable runtime semantics.

Verify P2S over full tree bytes and P2SH over the correct inlined proposition
preimage, address-network prefix and the compile API's explicit P2S routing.
Compare parser/compile failures through API callers without re-auditing unrelated
transport code.

Audit contract metadata/defaults/const types, duplicate parameter names,
declaration-ordered records versus placeholder order, the four/five-parameter
Scala HAMT transition, hash collisions and Unicode names. Check apply inputs,
missing/default/extra/wrong-type arguments, version constraints and output bytes.

For source maps, verify byte/address parity with ordinary compilation, preorder
node/tag agreement, offset bounds and handling of synthesized/ambiguous nodes
after folding, CSE, tupling and segregation. Trace the consumer with Sigma value
tracing; absent mappings must remain honest rather than inventing source origins.

## Required test and evidence review

- Grade parser verdict/position, typer s-expression, rejection class, compile
  bytes/address, contract serialize/apply and runtime semantics separately.
- Inventory exact skip/mismatch sets and fixture counts; rendering deviations
  cannot justify skipped byte/address/verdict comparisons. Verify provenance,
  corpus licenses and generator environment/version pins.
- Include direct constant/P2PK, nontrivial/segregated, env, all version axes,
  nested lambda/CSE/thunk, overflow/dead code, Unicode/position and resource cases.
- Resolve oracle version drift: several current scripts pin sigma-state 6.0.6
  while crate docs still cite 6.0.2. A changed dependency needs a stated authority
  and fixture contract, not a silently substituted expected output.

```bash
cargo test --locked -p ergo-compiler
cargo clippy --locked -p ergo-compiler --all-targets --all-features -- -D warnings
cargo doc --locked -p ergo-compiler --no-deps
```

Check prerequisites before live oracle tests under COMMON and record exactly
which pinned comparisons executed. Local post-write round trips are consistency
evidence; independent expected bytes remain required for correctness claims.

## Exit criteria

Deliver the COMMON report and coverage ledger plus the syntax/type/emission
coverage matrix, pass invariants, version axes and known-deviation evidence.
Separate proven wrong bytes/address/semantics, unsupported capability, oracle
coverage gaps and inaccurate documentation. An empty mismatch set over one seed
corpus does not establish a perfect compiler for arbitrary contracts.
