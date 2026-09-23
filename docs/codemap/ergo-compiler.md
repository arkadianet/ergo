# ergo-compiler

**Purpose:** ErgoScript source → ErgoTree compiler, production-faithful to
Scala's `sigmastate.lang.SigmaCompiler` (sigma-state 6.0.2). Full pipeline:
parse → bind → typecheck → root-coerce (`BoolToSigmaProp`) → emit to
`ergo_ser` opcode IR → nine-pass graph build → constant segregation → wire
write → P2S/P2SH addresses, plus `@contract` template compilation
(`SigmaTemplateCompiler` parity). Explicitly **not a consensus surface**
(`src/lib.rs:9-11`): a compiler bug yields a wrong tree or address, never a
fork — but a wrong address strands funds, so correctness is held to the
oracle-parity bar anyway.

**Depends on (workspace):** ergo-primitives, ergo-ser, ergo-crypto
(dev-only: ergo-sigma as a semantic-smoke oracle)
**Depended on by:** `ergo-api` (the only workspace dependent — `/script/*` and
the native `/api/v1/script/*` surface)
**Approx LOC:** ~24,700 production (~40,400 src incl. in-file tests;
+7,400 integration tests)

## Start here
- `src/lib.rs:1` — the crate charter + module map (`:1259`) + public
  re-exports (`:1300`); the deviation ledger (`D-T*` typer, `D-E*` emit,
  `D-C*` tree/compile) inside the doc comment is the single source of truth for
  every known parity gap and its Scala citation.
- `src/tree/mod.rs:60` — `graph_build`, the oracle-pinned nine-pass ordering
  (cast fold → isProven fusion → fold → dead-val prune → v0 gate → lower →
  re-fold → isProven strip → tuple → CSE → re-fold); `compile` at `:318`.
- `src/parse/mod.rs:83` — `parse` / `parse_type` (`:130`); hand-written
  scannerless parser mirroring Scala's `SigmaParser`, `MAX_PARSE_DEPTH = 128`
  (`:74`, deliberately above the wire bound of 110).
- `src/typed.rs:160` — `TypedExpr`, the typed vocabulary every later phase
  walks; `ConstPayload` at `:74`.
- `src/emit/mod.rs:153` — `emit` / `emit_with_version` (`:160`), typed AST →
  opcode IR; `EmitError` at `:96` (with `GraphBuildingReject` as the
  user-reachable verdict-parity gate).
- `src/cse/mod.rs:1` — the CSE identity model (first-build scope, thunk
  isolation, pair-projection memo); `cse` at `:217`.

## Modules
- `src/ast.rs` — untyped parser AST; `Expr` (`:42`) with one variant per Scala
  parser node.
- `src/binder.rs` — `SigmaBinder` port: env constant substitution + shallow
  rewrites (Coll/min/max/PK/serialize/isEmpty), single bottom-up pass
  documented as fixpoint-equivalent; `bind` (`:115`), `BindError` (`:66`).
- `src/stype.rs` — parser-domain `SType` (includes `NoType`/`STypeApply`);
  `is_predef_available` (`:111`) version-gates `SUnsignedBigInt` below v3.
- `src/parse/` — `mod.rs` (entry points), `cursor.rs` (token cursor),
  `types.rs` (type grammar), `expr_atoms.rs` (atoms + postfix suffixes),
  `operators.rs` (precedence), `block/` (block/val/def/lambda grammar).
- `src/typer/` — `unify.rs` (unification + numeric ladder), `methods.rs`
  (`SMethod` tables, `SMethodDesc` `:52`), `predef_ir.rs` (`SigmaPredef`
  env + irBuilder lowering), `assign/` (`assignType` dispatch across all 25
  arms: `assign_type` `assign/mod.rs:243`, `TyperError` `:101`; submodules
  `simple_arms`/`apply`/`method_call_like`/`lower_method`/`arith_bitop`/
  `harness`).
- `src/typed.rs` — typed AST twin of the 6.0.2 typed vocabulary; every node
  carries a source `pos`.
- `src/emit/` — `mod.rs` (`emit`, version gate
  `V6_ERGO_TREE_VERSION = 3`, unlowered-predef reject helper),
  `dispatch.rs` (the big `TypedExpr` match), `scope.rs` (binding-frame stack +
  id allocator), `select.rs` (residual `Select` lowering catalog),
  `method_call.rs` (`MethodCall`/`PropertyCall` wire dispatch +
  GraphBuilding reject gates), `types.rs` (`map_type`/`map_const`).
- `src/fold.rs` — GraphBuilding-exact constant-folding engine over opcode IR
  (incl. overflow reject arm); `fold` (`:110`).
- `src/inline.rs` — dead-`val` pruning + reachability query.
- `src/isproven.rs` — `SigmaPropIsProven`/`BoolToSigmaProp` cancellation
  (D-C3) + `HasSigmas` reconstruction.
- `src/lower.rs` — `CreateProveDlog`/`DHTuple(Const)` fold + single-element
  `AllOf`/`AnyOf` unwrap.
- `src/tuple.rs` — multi-arg lambda tupling to 1-arg `FuncValue` +
  `SelectField` (D-C4).
- `src/cse/` — hash-cons CSE: `interner.rs` (`Interner` scope stack,
  `:8`), `intern.rs` (interning), `key.rs` (`SymId`/`KeyTag`/`ExprKey`),
  `gate.rs` (usage + 4-predicate hoist gate), `materialize.rs` (Phase C
  rebuild, `:39`), `codec.rs` (child decompose/recompose).
- `src/tree/` — `mod.rs` (`graph_build` + public `compile`, post-write
  self-check), `assemble.rs` (`CompileResult` `:12`, constant segregation
  `:63`, `build_tree` `:108` — header fixed at version 0 / `has_size: false`),
  `cast_fold.rs`, `lambda_gate.rs` (D-C5 verdict-parity reject gate `:46`),
  `v0_gate.rs` (v0-header-unserializable constant DATA walker), `walk.rs`.
- `src/contract_parse.rs` / `src/contract_template.rs` — `@contract` doc-block
  + signature parser (`parse_contract` `:479`) and the
  `SigmaTemplateCompiler` mirror (`compile_contract` `:133`,
  `ContractTemplate` `:68`, `ApplyError` `:100`).
- `src/param_order.rs` — Scala 2.12 `HashTrieMap` iteration order for ≥5
  template params (`iteration_order_2_12` `:71`), matching the JVM's
  placeholder numbering.
- `src/env.rs` — deterministic compile-time `ScriptEnv`/`EnvValue`
  (`BTreeMap`); `EnvValue::ProveDlog` is the wallet-key entry point.
- `src/typecheck.rs` — public front-end (`typecheck` `:190`,
  `typecheck_with_network` `:202`, `CompileError` `:68`).
- `src/typed_print.rs` — canonical oracle s-expression printer
  (`print_typed` `:103`).
- `src/source_map.rs` — emit-time IR-node → source-offset map (`:80`), per
  [`docs/ergoscript-compiler-source-map-design.md`](../ergoscript-compiler-source-map-design.md).
- `src/error.rs` / `src/span.rs` / `src/token.rs` — parse errors, source
  positions, scannerless-lexer reconstruction.

## Key types, traits & functions
- `compile` / `compile_with_source_map` (fns) — end-to-end entry:
  typecheck → root-coerce → emit → graph build → assemble → addresses —
  `src/tree/mod.rs:318` / `:331`
- `CompileResult` (struct) — `tree_bytes`, `ergo_tree`, `p2s_address`,
  `p2sh_address` — `src/tree/assemble.rs:12`
- `CompileError` (enum) — phase-tagged reject surface
  (`Parse`/`Bind`/`Type`/`Root`/`Emit`/`Serializer`/`Write`); `class()` maps
  to the Scala exception class — `src/typecheck.rs:68`
- `typecheck` / `typecheck_with_network` (fns) — parse → bind → `assign_type` —
  `src/typecheck.rs:190` / `:202`
- `parse` / `parse_type` (fns) — ErgoScript expression and type entry points —
  `src/parse/mod.rs:83` / `:130`
- `bind` (fn) / `BindError` (enum) — binder port + reject surface —
  `src/binder.rs:115` / `:66`
- `Expr` (enum) — untyped AST — `src/ast.rs:42`
- `TypedExpr` (enum) / `ConstPayload` (enum) — typed AST + constant payloads —
  `src/typed.rs:160` / `:74`
- `SType` (enum) — parser-domain type; `is_predef_available` version gate —
  `src/stype.rs:14` / `:111`
- `ScriptEnv` (struct) / `EnvValue` (enum) / `lift` (fn) — compile-time env —
  `src/env.rs:82` / `:31` / `:138`
- `assign_type` (fn) / `TyperError` (enum) — the typer dispatch + reject
  surface — `src/typer/assign/mod.rs:243` / `:101`
- `emit` / `emit_with_version` (fns) / `EmitError` (enum) — typed AST → opcode
  IR; `GraphBuildingReject { class, what, pos }` is the user-reachable parity
  gate — `src/emit/mod.rs:153` / `:160` / `:96`
- `cse` (fn, crate-internal) / `Interner` (struct) — the sole
  subexpression-sharing pass — `src/cse/mod.rs:217` / `src/cse/interner.rs:8`
- `compile_contract` (fn) / `ContractTemplate` (struct) /
  `ContractError` / `ApplyError` (enums) — template compile + `apply` /
  `serialize` — `src/contract_template.rs:133` / `:68` / `:82` / `:100`
- `print_typed` / `to_term_string` (fns) — canonical s-expression rendering —
  `src/typed_print.rs:103` / `:37`
- `SourceMap` (struct) — IR-node → source-offset map — `src/source_map.rs:80`

## Invariants & contracts
- **Oracle-pinned to sigma-state 6.0.2.** Every phase mirrors a cited Scala
  source (`sigmastate.lang.SigmaCompiler`); live JVM oracles grade parser
  verdicts + positions (`scripts/jvm_parser_oracle/`), typed s-expressions,
  compiled bytes, and contract templates (`scripts/jvm_typer_oracle/`).
- **Compile byte parity is the gate.** `compile_seed_semantic_parity`
  (`tests/it/compile_semantic_parity.rs:881`) sweeps
  `test-vectors/ergoscript/compile/compile_seed.json` — 318 vectors
  (117 accept / 201 reject) — requiring oracle byte equality for accepts, the
  same reduction for both sides, and empty mismatch sets
  (`DC7_P2SH_MISMATCH_SET: &[]` `:354`, `P2S_DC1_MISMATCH_SET: &[]` `:407`,
  `SEMANTIC_SKIP: &[]` `:116`). A bare `SigmaPropConstant` root must be
  byte- and address-exact.
- **Typer / parser parity.** Golden-seed s-expressions are byte-compared
  (`tests/it/typer_oracle_parity.rs`, 254 records), rejects are graded by
  verdict + class, `SWEEP_SKIP` is exactly one rendering-only entry, and the
  79-contract corpus is checked for parser verdict + exact 1-based
  `line:col` (`tests/it/corpus_smoke.rs:111`).
- **Contract-template parity.** `contract_template_seed_byte_parity` requires
  byte-identical `serialize()` (20 vectors) and `apply` parity (16 vectors);
  placeholder indices follow the JVM's immutable-map iteration order —
  declaration order for ≤4 params (`MAX_DECLARATION_ORDER_PARAMS = 4`,
  `src/contract_template.rs:51`), Scala 2.12 `HashTrieMap` order above that.
- **Reject, never emit wrong bytes, for unknown shapes.** `CreateAvlTree`
  (D-E1), `ZKProofBlock` (D-E2) and opaque-env `SigmaProp` (D-E3) reject with
  `EmitError::UnsupportedNode`; constructs the typer accepts but Scala's
  GraphBuilding rejects surface as `EmitError::GraphBuildingReject` with the
  oracle's exception class (`src/tree/lambda_gate.rs:46`,
  `src/emit/method_call.rs`). Unlowered predefs reject with the oracle's
  `StagingException`/`GraphBuildingException` class (D-C8).
- **Three version axes.** (1) frontend `tree_version` gates the v5/v6 method
  tables and predef visibility (`>= 3` ⇔ `isV3OrLaterErgoTreeVersion`);
  (2) the wire header is fixed at version 0 for `compile()` (contract
  templates carry `tree_version` and `has_size = tree_version > 0`);
  (3) the activated script version is the evaluator's, not the compiler's
  (`src/tree/mod.rs:245-257`, `src/tree/assemble.rs:100-107`).
- **Post-write self-check.** After writing `tree_bytes`, `compile` re-reads
  them under the activated version and rejects with `CompileError::Serializer`
  if they fail to parse or leave trailing bytes — a P2S address must be
  spendable by a real deserializer.
- **Determinism.** `ScriptEnv`, CSE tables, and type substitutions use
  `BTreeMap`/sorted `Vec`, never randomized `HashMap`; CSE identity is decided
  solely by first-build scope, sibling thunks never share, and the
  pair-projection memo is the sole documented bypass of thunk isolation
  (`src/cse/mod.rs:16-100`).
- **Depth bound.** Parser recursion is capped at `MAX_PARSE_DEPTH = 128`,
  deliberately above the consensus wire bound of 110.
