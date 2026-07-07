# M7 — ContractParser / ContractTemplate foundation — report

**Status:** DONE
**Branch:** `feat/ergoscript-m7-contractparser` (off compiler HEAD `1ddfaeb`)
**Scala reference:** pinned `/home/rkadias/coding/reference/ergo-core/sigmastate-interpreter-v6.0.2`
**Oracle:** `scripts/jvm_typer_oracle` `ct` verb, scala-cli sigma-state 6.0.2 (Scala 2.12.21, JVM 17),
`ORACLE_TREE_VERSION=3`, `ORACLE_NETWORK=testnet`.

## What was built

### 1. `ergo-compiler/src/contract_parse.rs` (new)
A thin wrapper ABOVE the expression grammar, mirroring Scala's `ContractParser` being a sibling of
`SigmaParser` (ContractParser.scala:118-197). New AST: `ParameterDoc`, `ContractDoc`, `ContractParam`,
`ContractSignature`, `ParsedContractTemplate`. Entry point `parse_contract(source, tree_version)`:
- `Docs` sub-parser: `/* ... */` block, `*`-prefixed lines, `@param`/`@returns` vs description vs
  unsupported `@tag`, then `ContractDoc.apply` post-processing (drop leading empties, leading
  description run = top-level description, `@param` + continuation lines → `ParameterDoc`).
- `Signature` sub-parser: literal `@contract`, `def`, an `Id`, `( param-list )`, each param
  `Id ":" Type ("=" Literal)?`. **Reuses `parse_type()` verbatim** for `Type` and a restricted
  literal-only default parse (reuses `parse()` then asserts a literal node, mirroring
  Scala's `ExprLiteral`).
- Body: everything after the top-level `=` is handed to the **existing `parse()`** — no grammar
  duplication.
- Faithful reject surfaces verified against the oracle: `@returns <text>` (returnTag consumes only
  the bare literal) → reject; a non-blank non-`*` doc line → reject; non-literal default → reject.
- Deviation (documented, M1 doctrine): a malformed body surfaces as a positioned `ParseError`, not
  Scala's uncategorised `.get` throw.

### 2. Named-param TYPE env → typer (reuse)
`typecheck.rs::typecheck_contract_body` — binds an already-parsed body against an EMPTY `ScriptEnv`
and layers the param `name -> SType` map onto the existing `predefined_env` type env, then runs the
existing `assign_type`. No new typer logic (SigmaCompiler.scala:74-78 parity).

### 3. Placeholder emit + shared pipeline
- `emit.rs`: `Scope` gained a `placeholders: HashMap<String,u32>` field + `emit_with_placeholders`;
  a body identifier that is neither a val/lambda binding nor a known predef gap and IS a param
  emits `ConstantPlaceholder(index)` (opcode 0x73). Empty map on the normal path — pure superset.
- `tree.rs`: extracted the graph-building pipeline (`compile`'s middle: gates, folds, lowering,
  isProven fusion, tupling, CSE) into `pub(crate) fn graph_build(root)`, called by BOTH `compile`
  and the contract assembler so they stay byte-identical.

### 4. `ergo-compiler/src/contract_template.rs` (new)
`ContractTemplate { name, description, const_types, const_values, parameters, expression_tree }` +
`compile_contract(source, tree_version, network)` mirroring `SigmaTemplateCompiler.compile`/`assemble`.
Placeholder index = **declaration order** (≤4 params; Scala `Map1..Map4` insertion order).
`ContractTemplate::serialize()` reproduces the canonical `ContractTemplate.serializer` wire form
(treeVersion option, serializeString name/description, constTypes via `write_type`, constValues
option via `write_value`, Parameters, length-prefixed `expressionTree` value bytes).

### 5. Oracle + corpus + parity test
- `scripts/jvm_typer_oracle/TyperOracle.scala`: new `ct` verb running
  `SigmaTemplateCompiler(NET).compile(source)` → `ContractTemplate.serializer.toBytes` as hex.
- `test-vectors/ergoscript/contract/sources/*.es` (12 hand-authored) + committed
  `contract_seed.json` (verbatim oracle captures, never hand-edited).
- `ergo-compiler/tests/contract_template_parity.rs`: byte-exact gate.

## Byte-exact result (vs Scala 6.0.2 oracle)

All **≤4-param ACCEPT** vectors are **byte-identical** on the full `ContractTemplate.serializer`
output (which includes the segregated-placeholder `expressionTree` bytes, constTypes, constValues,
and parameters):

- `bare_no_params`, `one_param_no_default`, `one_param_with_default`, `two_params`,
  `two_params_bool`, `two_params_with_defaults`, `four_params`, `mixed_default` (Long default `5L`),
  `empty_doc`, `unsupported_tag` — **10 byte-exact**.
- `returns_with_text` — oracle REJECT (ParserException), Rust rejects → verdict parity.
- `five_params` — oracle ACCEPT, Rust intentionally REJECTS (see below).

## 5+ param HashMap-order port — cleanly DEFERRED (flagged, not mis-emitted)

For ≥5 params Scala's `.toMap` upgrades to a JVM `HashMap`; placeholder index = hash-bucket
iteration order, not declaration order, and leaks into `expressionTree` bytes. Per the captured M5
verdict this needs an `improve(String.hashCode)` bucket-order port (target Scala 2.12). That is
**not implemented**. `compile_contract` returns `ContractError::TooManyParamsForOrdering { count, max: 4 }`
for any ≥5-param template — a distinct, honest error, never a silently-wrong tree. Marked
`TODO(M7-hashmap-order)` in `contract_template.rs`. `constTypes`/`parameters` metadata is
declaration-order-stable regardless; only the body's placeholder indices are at risk, which is
exactly what the reject guards. Test `five_params_deferred_not_mis_emitted` + the parity vector
assert this.

## Gate
`cargo fmt --all -- --check` clean; `cargo clippy --workspace --all-targets --all-features -- -D warnings`
clean (no `#[allow]`); `cargo test --workspace` = **5666 passed / 0 failed**. New tests: 16 in
`contract_parse`, 6 in `contract_template`, 1 parity integration test.

## Descoped (per brief)
The open-ended "stdlib method-surface tail" bullet (recon §4) is intentionally NOT part of this task.
