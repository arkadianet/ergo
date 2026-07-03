# M2 Task 6 — Typer core II (Apply arms + predef lowering) — Report

## Status: COMPLETE. Gate green (fmt / clippy --workspace --all-targets / test --workspace).

## What was built

### `ergo-compiler/src/typer/predef_ir.rs` (new)
- `predefined_env(tree_version) -> TypeEnv` — the `predefinedEnv` seed
  (SigmaTyper.scala:33-36): the 34 `globalFuncs` declaration types (`name -> SFunc`,
  type params as `STypeVar`). Infix/unary operator funcs are elided (they never
  appear as `Ident`s — behaviour-preserving; documented).
- `predef_ir_builder(name, func, args) -> Option<Result<TypedExpr, TyperError>>` —
  the `PredefinedFuncApply.unapply` post-wrapper (SigmaPredef.scala:745-753).
  `None` = no builder / `isDefinedAt` false (fall-through, the TYPER-vs-BINDER
  distinction from the Task-4 finding); `Some(Ok)` = lowered node; `Some(Err)` =
  builder body threw.
- **Implemented lowerings** (each citing SigmaPredef.scala): sigmaProp→BoolToSigmaProp,
  allOf→AND, anyOf→OR, xorOf→XorOf, atLeast→AtLeast, ZKProof→ZKProofBlock,
  blake2b256/sha256→CalcBlake2b256/CalcSha256, byteArrayToBigInt/byteArrayToLong/
  longToByteArray/decodePoint→their nodes, proveDlog→CreateProveDlog,
  proveDHTuple→CreateProveDHTuple, avlTree→CreateAvlTree, substConstants→SubstConstants,
  getVar→GetVar (rtpe from callee SFunc range), executeFromVar→DeserializeContext,
  executeFromSelfReg[WithDefault]→DeserializeRegister (+ register-index reject/default),
  getVarFromInput→MethodCall(Context,…,{T→rtpe}), deserializeTo/fromBigEndianBytes→
  MethodCall(Global,…,{T→resType}), **bigInt** (decimal→BigIntConstant) and
  **fromBase16** (hex→ByteArrayConstant, signed i8) — both oracle-verified.
- **Deferred (documented deviations, no M2 oracle coverage; kept in env so calls
  still accept)**: fromBase58/fromBase64 (no vendored decoder), unsignedBigInt (no
  UBI constant payload), deserialize (needs M3 ValueSerializer).

### `ergo-compiler/src/typer/assign.rs` (extended)
- §1.7 `Apply(ApplyTypes(Select…, [T]), args)` — explicit type-arg method calls
  (getReg/some/none/deserializeTo/fromBigEndianBytes/getVarFromInput → MethodCall
  with `{T→rangeTpe}`); getVarFromInput arg-narrow hack (Short/Byte).
- §1.8 `Apply(Select…, args)` — exp→expUnsigned hack; re-run §1.5 Select; SFunc
  branch (unifyTypeLists → getMethod → irBuilder lowering via `lower_method` vs
  `mkApply` fallback); non-SFunc → mkApply.
- §1.9 `Apply(Ident, args)` when the name is a SGlobal method → `process_global_method`
  (groupGenerator→GroupGenerator, xor→Xor, else MethodCall(Global,…)) (E3).
- §1.10 generic Apply — arity, typedArgs, arg adaptations (adaptSigmaPropToBoolean
  §8.3 incl. nested ConcreteCollection recursion + re-finalize; getVar/executeFromVar
  Byte-narrow; getVarFromInput Short/Byte-narrow), unifyTypeLists gate, PredefinedFuncApply
  post-wrapper; SColl indexing → ByIndex + const-fold/upcast-to-Int; STuple const index
  → 1-based SelectField / non-const → ByIndex-over-SAny.
- §1.12 standalone ApplyTypes — free-type-var recovery (SType::SFunc has no tpeParams
  slot), subst → Select-retpe / Ident-retpe, partial-application error.
- §1.4 Ident-global-property → `process_global_method` (groupGenerator, single-dom).
- `lower_method` — shared receiver-keyed catalog (SOption.get/isDefined/getOrElse →
  OptionGet/OptionIsDefined/OptionGetOrElse; SColl map/filter/exists/forall/fold/slice/
  append/getOrElse → dedicated nodes; SGroupElement exp/multiply → Exponentiate/
  MultiplyGroup; else MethodCall). §1.5 property path now routes through it (SOption.get
  → OptionGet enables seed §7).
- Printer fix: `DeserializeRegister.reg` renders `@R{n}` (oracle `@R4`).

## Arms + builders implemented
Apply arms §1.7/§1.8/§1.9/§1.10, §1.12 ApplyTypes, §1.4 global-property; predef
irBuilder table (24 lowerings + 2 constant decoders; 4 deferred); shared method/
property lowering catalog `lower_method`; processGlobalMethod. Only §1.11
MethodCallLike remains NotYetImplemented (Task 7).

## Seed records added
§12 (41 records, ORACLE_TREE_VERSION=3, live JVM oracle): predef lowerings
(sigmaProp/allOf/anyOf/xorOf/atLeast/blake2b256/sha256/proveDlog/proveDHTuple/
byteArrayTo*/longToByteArray/decodePoint/substConstants/ZKProof/getVar/executeFromVar/
executeFromSelfReg/getVarFromInput/deserializeTo/bigInt/fromBase16), §1.7 getReg,
§1.8 exp→Exponentiate + map/slice/getOrElse + MethodCall survivors, §1.9 groupGenerator/
xor, §1.10 collection/tuple indexing (const + non-const + Upcast), §1.12 standalone,
adaptSigmaPropToBoolean nested, BitOp `1 | 2L`.

## Parity sweep result
File-driven byte-parity sweep over the whole golden seed: ~60 in-scope ACCEPT records
match the JVM oracle byte-for-byte (all previously-NYI-blocked §1/§4/§7/§9/§12 records
now enabled, plus the Task-5 structural records). §6 v2-gate records reject with
MethodNotFound. Excluded from byte-sweep (documented, verified structurally instead):
MethodCallLike operators (`* ++ || && + ^`, Task 7), PK, and demo-env GroupElement-
constant records (env.rs `lift` hex-placeholder deviation, M3). 444 lib tests + 142
integration tests pass.

## Deviations (M2)
- GroupElement constant rendering (env.rs) and PK — hex placeholder ≠ oracle Ecp form
  (pre-existing; M3).
- fromBase58/fromBase64/unsignedBigInt/deserialize irBuilders deferred (fall-through =
  accept + correct type, non-canonical node); M3.
- bigInt stores the decimal string verbatim (no BigInteger canonicalization; M3).

## Fix round 1

Commit: f16501b  Gate: fmt clean / clippy -D warnings clean / 448 tests ok (0 failed)

### Probe transcripts (ORACLE_TREE_VERSION=3, batch mode)

| Source | Verb | Oracle result |
|--------|------|---------------|
| `getVar[Int](200)` | tc | `REJECT 0:0 ArithmeticException` |
| `executeFromVar[Int](300)` | tc | `REJECT 0:0 ArithmeticException` |
| `getVarFromInput[Int](70000, 1)` | tc | `REJECT 0:0 ArithmeticException` |
| `unsignedBigInt("-5")` | tc | `REJECT 0:0 InvalidArguments` |
| `unsignedBigInt("5")` | tc | `OK (ConstantNode:UnsignedBigInt (CUnsignedBigInt @5))` — M3 deferred |
| `avlTree(1.toByte, a, 32, Global.none[Int]())` | tce | `OK (CreateAvlTree:AvlTree (Select:Byte ...) ...)` — parity sweep added |
| `executeFromSelfReg[Int](4)` | tc | `OK (DeserializeRegister:Int @R4 None)` — already in seed |
| `executeFromSelfRegWithDefault[Int](4, 0)` | tc | `OK (DeserializeRegister:Int @R4 (ConstantNode:Int @0))` — seed §13 added |

### Fixes applied

**Fix 1 (accept-invalid → reject):** Four `as i8`/`as i16` truncating casts in
`assign_apply_explicit_method` (§1.7 getVarFromInput, 2 sites) and `adapt_apply_args`
(§1.10 getVar/executeFromVar + getVarFromInput, 2 sites) replaced with
`narrow_numeric_const_to` → `const_downcast`. Added `ctx: &TyperCtx` to
`adapt_apply_args`. Removed now-dead `byte_const`/`short_const` in `assign.rs`.
Verdict parity exact; class-tag note D-T1 in lib.rs. 3 new reject tests.

**Fix 2 (unsignedBigInt + honest ledger):** `"unsignedBigInt"` arm split from the
`None` fallthrough: negative literal → `Some(Err(...))` (D-T2 resolved for this arm);
non-negative stays `None` (deferred, M3). `fromBase58`/`fromBase64`/`deserialize`
module docs rewritten as ACCEPT-INVALID deviations (D-T2). lib.rs gains
"Known M2 deviations" consolidated ledger (D-T1..D-T6). 2 new unit tests in
`predef_ir.rs` + 1 reject test in `assign.rs`.

**Fix 3 (seed records):** Golden seed §13 added with 4 reject records
(ArithmeticException/InvalidArguments) + 2 accept records (avlTree 4-arg, WithDefault).
Parity sweep guard bumped >=47. Both new accept records wire into the file-driven sweep
automatically (no SWEEP_SKIP entries needed).
