//! Typed ErgoScript AST → `ergo-ser` opcode IR (backend emission).
//!
//! Provides the type map ([`map_type`]), the constant map ([`map_const`]),
//! and [`emit`]'s coverage: fixed-arity opcode arms (context singletons,
//! relations, arithmetic/boolean operators, collection transformers, sigma
//! combinators, crypto primitives, option/context access), binding forms
//! (`Block`/`ValNode`/`Ident`/`Lambda` → `BlockValue`/`ValDef`/`ValUse`/
//! `FuncValue`), `MethodCall`/`PropertyCall` wire dispatch, the residual
//! `Apply`/`Select` lowering catalog (numeric casts, box/sigma-prop/tuple
//! properties, `FuncApply`), and defensive mixed-width `Upcast`
//! normalization inside the binary arith/relation and `ByIndex` arms. Bit
//! operators are GraphBuilding-parity rejects (see
//! [`EmitError::GraphBuildingReject`], lib.rs D-C5) — Scala's full compiler
//! cannot lower them.
//!
//! This module keeps `EmitError`, the entry points ([`emit`]/
//! [`emit_with_version`]/[`emit_with_placeholders`]), and the small shared
//! helpers (`node`/`bit_op_symbol`/`known_predef_gap`/`upcast_ir`); the walk
//! itself is split across submodules:
//! - [`scope`] — the `Scope` binding-frame stack, id allocator, and
//!   fixed-positional payload builders (`one`/`two`/`three`/`four`/
//!   `items_of`/`two_upcast`/`emit_index`).
//! - [`dispatch`] — the big `emit()` match over every `TypedExpr` variant,
//!   plus `emit_block`/`emit_lambda`/`emit_apply`.
//! - [`select`] — the residual `Select` lowering catalog (numeric casts,
//!   box/sigma-prop/tuple properties).
//! - [`method_call`] — `MethodCall`/`PropertyCall` wire dispatch, including
//!   the GraphBuilding-parity reject gates and the v6-numeric-constant fold.
//! - [`types`] — [`map_type`]/[`map_const`].
//!
//! Opcode bytes come from the `opcode_pattern` dispatch table
//! (`ergo-ser/src/opcode/types.rs:276-436`), which is the crate's consensus
//! contract with Scala `ValueSerializer`/`OpCodes.scala` (sigma-state 6.0.2).
//! Payload shapes follow `dev-docs/ergoscript-compiler-m3-recon/recon-ergoser-ir.md`.
//!
//! # Boolean constant wire shape
//!
//! TyperOracle captures (sigma-state 6.0.2, `cc` verb):
//!
//! ```text
//! sigmaProp(true)        → 10 01 0101   d1 7300
//! sigmaProp(false)       → 10 01 0100   d1 7300
//! sigmaProp(HEIGHT>100)  → 10 01 04c801 d1 91 a3 7300
//! ```
//!
//! The Scala compile path emits Boolean constants via the CONSTANT path — a
//! segregated `SBoolean` table entry (`0101`/`0100`) referenced by a
//! `ConstPlaceholder` (`7300`) — NOT the dedicated `0x7F` True / `0x80` False
//! opcodes. `emit` therefore builds `Expr::Const { SBoolean, Boolean(_) }`
//! with no True/False special-casing; a later segregation transform (the
//! D-C1 flip point — this module deliberately emits non-segregated trees)
//! turns inline constants into table entries. The captures also pin the
//! default P2S tree header `0x10` (version 0 + constant-segregation bit).
//!
//! # Nodes `ergo-ser` cannot represent (deviation-ledger entries in lib.rs)
//!
//! - `CreateAvlTree` — Scala 6.0.2 registers `CreateAvlTreeSerializer` at
//!   opcode `0xB6` with four value args (`ValueSerializer.scala:54`,
//!   `trees.scala:88` `opCode = OpCodes.AvlTreeCode`), but ergo-ser's
//!   `opcode_pattern` parses `0xB6` as `Zero` ("AvlTreeCode (deprecated)"),
//!   so an emitted `Four @ 0xB6` node would not re-parse. Resolved toward
//!   ergo-ser per the M3 ground rule: [`EmitError::UnsupportedNode`].
//! - `ZKProofBlock` — no serializer registration in Scala 6.0.2's
//!   `ValueSerializer` and no byte in `opcode_pattern`: the Scala compiler
//!   itself cannot serialize a `ZKProofBlock` (it is erased by `ZKProving`
//!   before serialization, a prover-side transform out of compiler scope).
//! - `ConstPayload::SigmaProp(String)` — an opaque env-injected sigma
//!   proposition label carries no curve bytes to serialize.
//!
//! `None: Option[T]` never becomes a `Payload::NoneValue` op node: dispatch
//! byte `0xDF` is not parser-accepted (recon §1); a `None` literal must flow
//! through the constant path (`SOption` type + `0x00` discriminant). No
//! `ConstPayload` variant produces one; `Global.none[T]()` lowers to a
//! `PropertyCall` (106, 10) with an explicit type arg.

use ergo_ser::opcode::{Expr, IrNode, Payload};
use ergo_ser::sigma_type::SigmaType;

use crate::typed::TypedExpr;

mod dispatch;
mod method_call;
mod scope;
mod select;
mod types;
pub(crate) use scope::Scope;
pub(crate) use types::{map_const, map_type};

/// Emission failure. `UnresolvedType`/`UnsupportedNode`/`InvalidShape` are
/// COMPILER bug surfaces, not user errors: the typer guarantees the
/// invariants those errors report (no `NoType` in output, no pre-typed
/// nodes, payloads matching node types), so the variants are typed and
/// spanless. `GraphBuildingReject` is the exception — a USER-reachable
/// verdict-parity gate (see its docs).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EmitError {
    /// A compiler-internal type (`NoType`, `STypeApply`) reached `map_type`.
    /// The typer must eliminate both before emit (recon-ergoser-ir OQ2).
    #[error("unresolved compiler-internal type reached emit: {0}")]
    UnresolvedType(String),
    /// A typed node with no opcode-IR lowering: a node `ergo-ser` cannot
    /// represent (see the module docs), or a residual `Select`/`Apply`/
    /// `MethodCall` outside the lowering catalog — the message names the
    /// offending method/field/owner.
    #[error("node not supported by emit: {0}")]
    UnsupportedNode(String),
    /// A structurally invalid shape that must never reach emit (pre-typed
    /// nodes, payload/type mismatches, wire-arity violations, unbound
    /// identifiers).
    #[error("invalid shape reached emit: {0}")]
    InvalidShape(&'static str),
    /// A construct the typer accepts but the FULL Scala compiler REJECTS at
    /// its GraphBuilding/IR stage — no
    /// lowering exists for the node, or compile-time constant evaluation
    /// throws. Mirroring the verdict keeps `compile()` from handing out tree
    /// bytes + addresses the reference compiler can never produce (several
    /// such trees are unspendable — the funds-stranding surface the
    /// oracle-parity bar exists for). `class` is the ORACLE's exception
    /// class, verbatim, for reject-class parity grading (lib.rs D-C5).
    #[error("rejected for Scala GraphBuilding parity ({class}): {what}")]
    GraphBuildingReject {
        /// The Scala exception class the oracle reports for this reject.
        class: &'static str,
        /// What was rejected (names the operator/method/constant family).
        what: String,
    },
}

/// ErgoTree version at/above which the V6 (EIP-50) method surface is active —
/// `VersionContext.isV3OrLaterErgoTreeVersion` (tree/activated version >= 3).
/// Below it the emit-time GraphBuilding-parity gates reject the V6-only
/// `SGlobal` methods that reach emit through the bare predef aliases.
const V6_ERGO_TREE_VERSION: u8 = 3;

/// Lower a typed expression to the `ergo-ser` opcode IR.
///
/// Fixed-arity forms map 1:1 onto `Payload::Zero/One/Two/Three/Four` and the
/// named-field payloads per the `opcode_pattern` table; constants map through
/// [`map_const`]; binding forms allocate ids through a fresh [`Scope`].
///
/// Version-agnostic entry: emits under [`V6_ERGO_TREE_VERSION`] (V6 active), so
/// the emit-time V6-method gates never fire. Use [`emit_with_version`] from the
/// compile route to feed the requested `tree_version` and reject V6-only
/// `SGlobal` predefs under a v5 target.
pub fn emit(expr: &TypedExpr) -> Result<Expr, EmitError> {
    emit_with_version(expr, V6_ERGO_TREE_VERSION)
}

/// Like [`emit`] but carries the requested `tree_version` so the emit-time
/// GraphBuilding-parity gates can reject V6-only constructs under a v5 target
/// (`tree_version < 3`). The compile route threads its `tree_version` here.
pub fn emit_with_version(expr: &TypedExpr, tree_version: u8) -> Result<Expr, EmitError> {
    Scope::new(tree_version).emit(expr)
}

/// Emit a typed contract body, resolving each named parameter to its
/// `ConstantPlaceholder(index)` node (M7). `placeholders` maps a param name to
/// its constant-table index (declaration order for ≤4 params). Any body
/// identifier that is neither a `val`/lambda binding nor a known predef gap and
/// IS in `placeholders` becomes a placeholder; everything else behaves exactly
/// as [`emit`]. Mirrors `SigmaCompiler.compileTyped` seeding `env ++
/// placeholdersEnv` before `buildGraph` (SigmaCompiler.scala:88-93).
pub fn emit_with_placeholders(
    expr: &TypedExpr,
    placeholders: std::collections::HashMap<String, u32>,
) -> Result<Expr, EmitError> {
    Scope::with_placeholders(placeholders).emit(expr)
}

/// `Ok(Expr::Op { .. })` shorthand shared by every opcode arm.
fn node(opcode: u8, payload: Payload) -> Result<Expr, EmitError> {
    Ok(Expr::Op(IrNode { opcode, payload }))
}

/// Surface symbol of a `TypedExpr::BitOp` opcode byte (typed.rs `BIT_*`
/// constants) — for the GraphBuilding-reject message only.
fn bit_op_symbol(opcode: i8) -> &'static str {
    use crate::typed::{
        BIT_AND, BIT_OR, BIT_SHIFT_LEFT, BIT_SHIFT_RIGHT, BIT_SHIFT_RIGHT_ZEROED, BIT_XOR,
    };
    match opcode {
        BIT_OR => "|",
        BIT_AND => "&",
        BIT_XOR => "^",
        BIT_SHIFT_LEFT => "<<",
        BIT_SHIFT_RIGHT => ">>",
        BIT_SHIFT_RIGHT_ZEROED => ">>>",
        _ => "?",
    }
}

/// Predef function names the TYPER accepts (present in `predefined_env`,
/// `typer/predef_ir.rs`) but whose Scala `irBuilder` is the literal
/// `PredefFuncInfo(undefined)` sentinel (`SigmaPredef.scala:79-92` for
/// `allZK`/`anyZK`, `:108-123` for `outerJoin`) — genuinely unimplemented in
/// the REFERENCE compiler itself, not merely unported. `predef_ir_builder`
/// (`typer/predef_ir.rs`, comment at its match's tail) falls through with
/// `None` for exactly these three names, so their typed tree keeps the raw
/// `Apply(Ident, args)` shape all the way to here — see the `T::Ident` arm's
/// doc comment (D-C8) for the full oracle-probe citation. Returns the bare
/// function name for the `GraphBuildingReject` message when `name` is one of
/// these; `None` for every other identifier (which means "genuine pipeline
/// bug" at the call site, not "known predef gap").
fn known_predef_gap(name: &str) -> Option<&str> {
    match name {
        "allZK" | "anyZK" | "outerJoin" => Some(name),
        _ => None,
    }
}

/// Wrap an already-emitted IR expression in `Upcast` (0x7E) to `tpe`.
fn upcast_ir(input: Expr, tpe: SigmaType) -> Expr {
    Expr::Op(IrNode {
        opcode: 0x7E,
        payload: Payload::NumericCast {
            input: Box::new(input),
            tpe,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::{EnvValue, ScriptEnv};
    use crate::stype::SType;
    use crate::typecheck::typecheck;
    use crate::typed::ConstPayload;
    use ergo_primitives::group_element::GroupElement;
    use ergo_primitives::reader::VlqReader;
    use ergo_primitives::writer::VlqWriter;
    use ergo_ser::opcode::{parse_expr, write_expr};
    use ergo_ser::sigma_value::{CollValue, SigmaBoolean, SigmaValue};

    // ----- helpers -----

    /// The secp256k1 generator point, SEC1-compressed (same fixture as
    /// `tests/typer_oracle_parity.rs::generator_ge`).
    fn generator_ge() -> GroupElement {
        let mut bytes = [0u8; 33];
        bytes[0] = 0x02;
        let x = hex::decode("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
            .expect("valid hex");
        bytes[1..].copy_from_slice(&x);
        GroupElement::from_bytes(bytes)
    }

    /// Subset of the oracle demo env (`TyperOracle.scala:demoEnv`) used by the
    /// golden-seed sources in this module: `a`,`b: Coll[Byte]`,
    /// `col1: Coll[Long]`, `g1`,`g2: GroupElement`, `n1: BigInt`.
    fn demo_env() -> ScriptEnv {
        let ge = generator_ge();
        let mut env = ScriptEnv::new();
        env.insert("a", EnvValue::ByteArray(vec![1, 2]));
        env.insert("b", EnvValue::ByteArray(vec![3, 4]));
        env.insert("col1", EnvValue::LongArray(vec![1, 2]));
        env.insert("g1", EnvValue::GroupElement(ge));
        env.insert("g2", EnvValue::GroupElement(ge));
        env.insert("n1", EnvValue::BigInt("5".to_string()));
        env
    }

    /// Real-frontend typecheck at tree_version 3 against the demo env.
    fn tc(src: &str) -> TypedExpr {
        typecheck(&demo_env(), src, 3).unwrap_or_else(|e| panic!("typecheck({src:?}): {e}"))
    }

    fn emit_tc(src: &str) -> Expr {
        emit(&tc(src)).unwrap_or_else(|e| panic!("emit({src:?}): {e}"))
    }

    /// write_expr → parse_expr → structural equality → re-write → byte
    /// equality (the `ergo-ser/src/opcode/tests.rs::roundtrip_v` pattern via
    /// the PUBLIC API). cseg=false: `emit` produces inline constants only;
    /// segregation is a separate transform.
    fn wire_roundtrip(ir: &Expr) -> Vec<u8> {
        let mut w = VlqWriter::new();
        write_expr(&mut w, ir, false).expect("write_expr");
        let data = w.result();
        let mut r = VlqReader::new(&data);
        let decoded = parse_expr(&mut r, 0, 3).expect("parse_expr");
        assert!(r.is_empty(), "leftover bytes after roundtrip");
        assert_eq!(&decoded, ir, "parsed IR differs from emitted IR");
        let mut w2 = VlqWriter::new();
        write_expr(&mut w2, &decoded, false).expect("re-write_expr");
        assert_eq!(data, w2.result(), "reserialized bytes differ");
        data
    }

    fn root_opcode(e: &Expr) -> u8 {
        match e {
            Expr::Op(node) => node.opcode,
            other => panic!("expected an Op node, got {other:?}"),
        }
    }

    /// Frontend source → emit → assert root opcode → wire round-trip.
    fn rt_op(src: &str, opcode: u8) {
        let ir = emit_tc(src);
        assert_eq!(
            root_opcode(&ir),
            opcode,
            "{src:?}: expected opcode {opcode:#04x}"
        );
        wire_roundtrip(&ir);
    }

    fn int_c(v: i32) -> TypedExpr {
        TypedExpr::Constant {
            value: ConstPayload::Int(v),
            tpe: SType::SInt,
        }
    }

    fn long_c(v: i64) -> TypedExpr {
        TypedExpr::Constant {
            value: ConstPayload::Long(v),
            tpe: SType::SLong,
        }
    }

    fn bool_c(v: bool) -> TypedExpr {
        TypedExpr::Constant {
            value: ConstPayload::Bool(v),
            tpe: SType::SBoolean,
        }
    }

    fn byte_coll_c(v: Vec<i8>) -> TypedExpr {
        TypedExpr::Constant {
            value: ConstPayload::ByteColl(v),
            tpe: scoll(SType::SByte),
        }
    }

    fn scoll(t: SType) -> SType {
        SType::SColl(Box::new(t))
    }

    /// Hand-built node → emit → assert opcode → round-trip. For arms the
    /// frontend cannot reach without dedicated binding-form syntax (documented
    /// per test).
    fn rt_node(node: &TypedExpr, opcode: u8) -> Expr {
        let ir = emit(node).unwrap_or_else(|e| panic!("emit({node:?}): {e}"));
        assert_eq!(root_opcode(&ir), opcode, "expected opcode {opcode:#04x}");
        wire_roundtrip(&ir);
        ir
    }

    // ----- happy path -----

    #[test]
    fn map_type_primitives_map_one_to_one() {
        for (s, g) in [
            (SType::SBoolean, SigmaType::SBoolean),
            (SType::SByte, SigmaType::SByte),
            (SType::SShort, SigmaType::SShort),
            (SType::SInt, SigmaType::SInt),
            (SType::SLong, SigmaType::SLong),
            (SType::SBigInt, SigmaType::SBigInt),
            (SType::SUnsignedBigInt, SigmaType::SUnsignedBigInt),
            (SType::SGroupElement, SigmaType::SGroupElement),
            (SType::SSigmaProp, SigmaType::SSigmaProp),
            (SType::SAvlTree, SigmaType::SAvlTree),
            (SType::SContext, SigmaType::SContext),
            (SType::SGlobal, SigmaType::SGlobal),
            (SType::SHeader, SigmaType::SHeader),
            (SType::SPreHeader, SigmaType::SPreHeader),
            (SType::SString, SigmaType::SString),
            (SType::SBox, SigmaType::SBox),
            (SType::SUnit, SigmaType::SUnit),
            (SType::SAny, SigmaType::SAny),
            (
                SType::STypeVar("T".to_string()),
                SigmaType::STypeVar("T".to_string()),
            ),
        ] {
            assert_eq!(map_type(&s).unwrap(), g, "{s:?}");
        }
    }

    #[test]
    fn map_type_compound_shapes_map_recursively() {
        assert_eq!(
            map_type(&scoll(scoll(SType::SByte))).unwrap(),
            SigmaType::SColl(Box::new(SigmaType::SColl(Box::new(SigmaType::SByte))))
        );
        assert_eq!(
            map_type(&SType::SOption(Box::new(SType::SInt))).unwrap(),
            SigmaType::SOption(Box::new(SigmaType::SInt))
        );
        assert_eq!(
            map_type(&SType::STuple(vec![
                SType::SInt,
                SType::SLong,
                SType::SBoolean
            ]))
            .unwrap(),
            SigmaType::STuple(vec![SigmaType::SInt, SigmaType::SLong, SigmaType::SBoolean])
        );
    }

    #[test]
    fn map_type_sfunc_maps_fields_and_tpe_params() {
        // Field renames dom→t_dom / range→t_range, and String idents →
        // SigmaType::STypeVar (recon §2 obligation; the ergo-ser writer
        // rejects any non-STypeVar tpe_param).
        let f = SType::SFunc {
            dom: vec![SType::SInt, SType::STypeVar("T".to_string())],
            range: Box::new(SType::SBoolean),
            tpe_params: vec!["T".to_string()],
        };
        assert_eq!(
            map_type(&f).unwrap(),
            SigmaType::SFunc {
                t_dom: vec![SigmaType::SInt, SigmaType::STypeVar("T".to_string())],
                t_range: Box::new(SigmaType::SBoolean),
                tpe_params: vec![SigmaType::STypeVar("T".to_string())],
            }
        );
    }

    #[test]
    fn map_const_scalar_payloads_produce_expected_pairs() {
        use num_bigint::BigInt;
        for (p, t, exp_t, exp_v) in [
            (
                ConstPayload::Bool(true),
                SType::SBoolean,
                SigmaType::SBoolean,
                SigmaValue::Boolean(true),
            ),
            (
                ConstPayload::Byte(-3),
                SType::SByte,
                SigmaType::SByte,
                SigmaValue::Byte(-3),
            ),
            (
                ConstPayload::Short(300),
                SType::SShort,
                SigmaType::SShort,
                SigmaValue::Short(300),
            ),
            (
                ConstPayload::Int(42),
                SType::SInt,
                SigmaType::SInt,
                SigmaValue::Int(42),
            ),
            (
                ConstPayload::Long(-7),
                SType::SLong,
                SigmaType::SLong,
                SigmaValue::Long(-7),
            ),
            (
                ConstPayload::BigInt("5".to_string()),
                SType::SBigInt,
                SigmaType::SBigInt,
                SigmaValue::BigInt(BigInt::from(5)),
            ),
            // SUnsignedBigInt reuses SigmaValue::BigInt on the wire
            // (write_unsigned_bigint_value takes the BigInt payload).
            (
                ConstPayload::UnsignedBigInt("5".to_string()),
                SType::SUnsignedBigInt,
                SigmaType::SUnsignedBigInt,
                SigmaValue::BigInt(BigInt::from(5)),
            ),
            (
                ConstPayload::String("abc".to_string()),
                SType::SString,
                SigmaType::SString,
                SigmaValue::Str("abc".to_string()),
            ),
            (
                ConstPayload::Unit,
                SType::SUnit,
                SigmaType::SUnit,
                SigmaValue::Unit,
            ),
        ] {
            assert_eq!(map_const(&p, &t).unwrap(), (exp_t, exp_v), "{p:?}");
        }
    }

    #[test]
    fn map_const_collection_and_crypto_payloads_produce_expected_pairs() {
        // ByteColl: signed i8 elements reinterpreted as raw u8 bytes.
        assert_eq!(
            map_const(&ConstPayload::ByteColl(vec![-1, 2]), &scoll(SType::SByte)).unwrap(),
            (
                SigmaType::SColl(Box::new(SigmaType::SByte)),
                SigmaValue::Coll(CollValue::Bytes(vec![0xFF, 0x02])),
            )
        );
        assert_eq!(
            map_const(&ConstPayload::LongColl(vec![1, -2]), &scoll(SType::SLong)).unwrap(),
            (
                SigmaType::SColl(Box::new(SigmaType::SLong)),
                SigmaValue::Coll(CollValue::Values(vec![
                    SigmaValue::Long(1),
                    SigmaValue::Long(-2)
                ])),
            )
        );
        let ge_bytes = *generator_ge().as_bytes();
        assert_eq!(
            map_const(&ConstPayload::GroupElement(ge_bytes), &SType::SGroupElement).unwrap(),
            (
                SigmaType::SGroupElement,
                SigmaValue::GroupElement(GroupElement::from_bytes(ge_bytes)),
            )
        );
        assert_eq!(
            map_const(&ConstPayload::ProveDlog(ge_bytes), &SType::SSigmaProp).unwrap(),
            (
                SigmaType::SSigmaProp,
                SigmaValue::SigmaProp(SigmaBoolean::ProveDlog(GroupElement::from_bytes(ge_bytes))),
            )
        );
    }

    // Semantic smoke (Step 4): the emitted IR is not just parseable — it
    // EVALUATES correctly under the in-repo interpreter (first ergo-sigma
    // dev-dep use in this crate; recon confirmed no dependency cycle).

    #[test]
    fn emitted_sigma_prop_height_gt_100_reduces_true_at_height_200() {
        use ergo_sigma::evaluator::{reduce_expr, ReductionContext};
        let ir = emit_tc("sigmaProp(HEIGHT > 100)");
        let ctx = ReductionContext::minimal(200, 0);
        let sb = reduce_expr(&ir, &ctx, &[]).expect("reduce");
        assert_eq!(sb, SigmaBoolean::TrivialProp(true));
    }

    #[test]
    fn emitted_sigma_prop_height_gt_100_reduces_false_at_height_50() {
        use ergo_sigma::evaluator::{reduce_expr, ReductionContext};
        let ir = emit_tc("sigmaProp(HEIGHT > 100)");
        let ctx = ReductionContext::minimal(50, 0);
        let sb = reduce_expr(&ir, &ctx, &[]).expect("reduce");
        assert_eq!(sb, SigmaBoolean::TrivialProp(false));
    }

    #[test]
    fn emitted_block_val_binding_reduces_across_100() {
        // BlockValue/ValDef/ValUse evaluate correctly under the in-repo
        // interpreter — the binding actually carries HEIGHT to the guard.
        use ergo_sigma::evaluator::{reduce_expr, ReductionContext};
        let ir = emit_tc("sigmaProp({ val x = HEIGHT; x > 100 })");
        for (height, expected) in [(200u32, true), (50, false)] {
            let ctx = ReductionContext::minimal(height, 0);
            let sb = reduce_expr(&ir, &ctx, &[]).expect("reduce");
            assert_eq!(sb, SigmaBoolean::TrivialProp(expected), "height {height}");
        }
    }

    #[test]
    fn emitted_val_bound_lambda_funcapply_reduces_true() {
        // FuncValue + FuncApply semantics: f(2) == 3 for f = x + 1.
        use ergo_sigma::evaluator::{reduce_expr, ReductionContext};
        let ir = emit_tc("sigmaProp({ val f = {(x: Int) => x + 1}; f(2) == 3 })");
        let ctx = ReductionContext::minimal(1, 0);
        let sb = reduce_expr(&ir, &ctx, &[]).expect("reduce");
        assert_eq!(sb, SigmaBoolean::TrivialProp(true));
    }

    #[test]
    fn emitted_coll_map_lambda_reduces_true() {
        // MapCollection over an emitted FuncValue: Coll(1,2).map(+1)(0) == 2.
        use ergo_sigma::evaluator::{reduce_expr, ReductionContext};
        let ir = emit_tc("sigmaProp(Coll(1, 2).map({(x: Int) => x + 1})(0) == 2)");
        let ctx = ReductionContext::minimal(1, 0);
        let sb = reduce_expr(&ir, &ctx, &[]).expect("reduce");
        assert_eq!(sb, SigmaBoolean::TrivialProp(true));
    }

    #[test]
    fn emitted_get_var_composite_reduces_with_extension() {
        // `getVar[Int](1).get > 0`: GetVar inner-type wire + OptionGet +
        // relation, end-to-end against a context extension.
        use ergo_sigma::evaluator::{reduce_expr, ReductionContext};
        let ir = emit_tc("sigmaProp(getVar[Int](1).get > 0)");
        let mut ctx = ReductionContext::minimal(1, 0);
        ctx.extension
            .insert(1, (SigmaType::SInt, SigmaValue::Int(5)));
        let sb = reduce_expr(&ir, &ctx, &[]).expect("reduce");
        assert_eq!(sb, SigmaBoolean::TrivialProp(true));
        // Var absent → OptionGet on None → the script FAILS, like Scala.
        let empty_ctx = ReductionContext::minimal(1, 0);
        assert!(reduce_expr(&ir, &empty_ctx, &[]).is_err());
    }

    #[test]
    fn emitted_mixed_width_arith_reduces_true() {
        // The typer-inserted Upcast (mirrored by emit's normalization)
        // evaluates: (1 + 2L) == 3L.
        use ergo_sigma::evaluator::{reduce_expr, ReductionContext};
        let ir = emit_tc("sigmaProp((1 + 2L) == 3L)");
        let ctx = ReductionContext::minimal(1, 0);
        let sb = reduce_expr(&ir, &ctx, &[]).expect("reduce");
        assert_eq!(sb, SigmaBoolean::TrivialProp(true));
    }

    // ----- round-trips -----

    #[test]
    fn context_singletons_emit_zero_payload_and_roundtrip() {
        for (src, opcode) in [
            ("HEIGHT", 0xA3),
            ("INPUTS", 0xA4),
            ("OUTPUTS", 0xA5),
            ("SELF", 0xA7),
            ("MinerPubkey", 0xAC),
            ("CONTEXT", 0xFE),
            ("Global", 0xDD),
        ] {
            let ir = emit_tc(src);
            assert_eq!(root_opcode(&ir), opcode, "{src}");
            match &ir {
                Expr::Op(IrNode { payload, .. }) => {
                    assert_eq!(payload, &Payload::Zero, "{src}: singleton payload")
                }
                other => panic!("{src}: expected Op, got {other:?}"),
            }
            wire_roundtrip(&ir);
        }
    }

    #[test]
    fn lowered_singletons_emit_property_call_and_roundtrip() {
        // (recon-transforms.md §9, D-C7): bare `LastBlockUtxoRootHash`
        // and bare/dotted `groupGenerator` are NOT `IsContextProperty`
        // primitives on the Scala side — both lower to a `PropertyCall`
        // (opcode 0xDB), not the dedicated 0xA6/0x82 leaf. Oracle-confirmed
        // (`ORACLE_TREE_VERSION=3`): both
        // `LastBlockUtxoRootHash.digest.size` and
        // `CONTEXT.LastBlockUtxoRootHash.digest.size` reply the SAME
        // `PropertyCall(101, 9)` receiver bytes (`…db6509fe…`); both
        // `groupGenerator.getEncoded.size` and
        // `Global.groupGenerator.getEncoded.size` reply the SAME
        // `PropertyCall(106, 1)` receiver bytes (`…db6a01dd…`).
        for (src, (type_id, method_id), receiver_opcode) in [
            ("LastBlockUtxoRootHash", (101u8, 9u8), 0xFEu8),
            ("groupGenerator", (106, 1), 0xDD),
            ("Global.groupGenerator", (106, 1), 0xDD),
        ] {
            let ir = emit_tc(src);
            assert_eq!(root_opcode(&ir), 0xDB, "{src}: PropertyCall opcode");
            match &ir {
                Expr::Op(IrNode {
                    payload:
                        Payload::MethodCall {
                            type_id: tid,
                            method_id: mid,
                            obj,
                            args,
                            type_args,
                        },
                    ..
                }) => {
                    assert_eq!((*tid, *mid), (type_id, method_id), "{src}: wire ids");
                    assert!(args.is_empty(), "{src}: PropertyCall has no args");
                    assert!(type_args.is_empty(), "{src}: no explicit type args");
                    assert_eq!(root_opcode(obj), receiver_opcode, "{src}: receiver");
                    match obj.as_ref() {
                        Expr::Op(IrNode { payload, .. }) => {
                            assert_eq!(payload, &Payload::Zero, "{src}: receiver is a bare leaf")
                        }
                        other => panic!("{src}: expected Op receiver, got {other:?}"),
                    }
                }
                other => panic!("{src}: expected MethodCall payload, got {other:?}"),
            }
            wire_roundtrip(&ir);
        }
    }

    #[test]
    fn constants_emit_via_constant_path_and_roundtrip() {
        for src in [
            "42",
            "1L",
            "true",
            "\"abc\"",
            "()",
            "bigInt(\"5\")",
            "unsignedBigInt(\"5\")",
            "fromBase64(\"YWJj\")",
            "col1",
            "g1",
        ] {
            let ir = emit_tc(src);
            assert!(matches!(ir, Expr::Const { .. }), "{src}: expected Const");
            wire_roundtrip(&ir);
        }
        // Spot-check the UBI wire pair: SUnsignedBigInt type + BigInt value.
        match emit_tc("unsignedBigInt(\"5\")") {
            Expr::Const { tpe, val } => {
                assert_eq!(tpe, SigmaType::SUnsignedBigInt);
                assert_eq!(val, SigmaValue::BigInt(num_bigint::BigInt::from(5)));
            }
            other => panic!("expected Const, got {other:?}"),
        }
    }

    #[test]
    fn relations_emit_relation2_opcodes_and_roundtrip() {
        rt_op("HEIGHT > 100", 0x91);
        rt_op("HEIGHT >= 100", 0x92);
        rt_op("HEIGHT < 100", 0x8F);
        rt_op("HEIGHT <= 100", 0x90);
        rt_op("HEIGHT == 100", 0x93);
        rt_op("HEIGHT != 100", 0x94);
    }

    #[test]
    fn relation_over_two_bool_constants_roundtrips_via_compact_wire_form() {
        // The writer compacts a Relation2 over two Boolean constants into the
        // 0x85 packed form (write.rs:relation2_bool_pair); emit does NOT
        // special-case it — the round-trip must still be structural+byte
        // exact. Hand-built EQ to sidestep any frontend folding.
        let node = TypedExpr::EQ {
            left: Box::new(bool_c(true)),
            right: Box::new(bool_c(false)),
            tpe: SType::SBoolean,
        };
        let ir = rt_node(&node, 0x93);
        let bytes = wire_roundtrip(&ir);
        assert_eq!(bytes, vec![0x93, 0x85, 0x01], "compact Relation2 form");
    }

    #[test]
    fn arith_ops_emit_scala_opcode_bytes_and_roundtrip() {
        rt_op("1 + 2", 0x9A);
        rt_op("5 - 1", 0x99);
        rt_op("2 * 3", 0x9C);
        rt_op("6 / 2", 0x9D);
        rt_op("5 % 2", 0x9E);
        rt_op("min(1, 2)", 0xA1);
        rt_op("max(1, 2)", 0xA2);
    }

    #[test]
    fn bit_ops_reject_graph_building_parity() {
        // Scala 6.0.2 GraphBuilding has NO BitOp lowering — the full
        // compiler rejects every bit operator at every width, shifts
        // included (surface `5 << 1` parses and typechecks fine on both
        // sides; oracle `cc sigmaProp((5 << 1) == 10)` → `REJECT 1:12
        // GraphBuildingException`, compile_seed.json). Opcodes 0xF2-0xF8
        // are unreachable from emit.
        for src in ["1 | 2", "1 & 2", "1 ^ 2", "5 << 1", "5 >> 1", "5 >>> 1"] {
            let err = emit(&tc(src)).expect_err(src);
            assert!(
                matches!(
                    &err,
                    EmitError::GraphBuildingReject { class, .. }
                        if *class == "GraphBuildingException"
                ),
                "{src}: {err:?}"
            );
        }
        // Hand-built BitOp (any opcode byte) rejects the same way.
        let node = TypedExpr::BitOp {
            left: Box::new(int_c(1)),
            right: Box::new(int_c(2)),
            opcode: crate::typed::BIT_SHIFT_LEFT,
            tpe: SType::SInt,
        };
        assert!(matches!(
            emit(&node),
            Err(EmitError::GraphBuildingReject { .. })
        ));
    }

    #[test]
    fn bool_xor_still_emits_binxor_nearest_accept_boundary() {
        // `^` over BOOLEANS is a different node (BinXor, 0xF4) with a real
        // GraphBuilding lowering — the bit-op gate must not touch it.
        rt_op("(HEIGHT > 1) ^ (HEIGHT < 5)", 0xF4);
    }

    #[test]
    fn bool_binops_emit_lazy_opcodes_and_roundtrip() {
        rt_op("HEIGHT > 1 && HEIGHT < 5", 0xED);
        rt_op("HEIGHT > 1 || HEIGHT < 5", 0xEC);
        rt_op("(HEIGHT > 1) ^ (HEIGHT < 5)", 0xF4);
    }

    #[test]
    fn unary_ops_emit_one_payload_and_roundtrip() {
        rt_op("!(HEIGHT > 1)", 0xEF);
        rt_op("-HEIGHT", 0xF0);
    }

    #[test]
    fn bit_inversion_rejects_graph_building_parity() {
        // Same GraphBuilding gap as BitOp (oracle: `cc sigmaProp((~1) ==
        // -2)` → `REJECT 1:13 GraphBuildingException`); 0xF1 never emits.
        let err = emit(&tc("~HEIGHT")).expect_err("~ must reject");
        assert!(
            matches!(
                &err,
                EmitError::GraphBuildingReject { class, .. }
                    if *class == "GraphBuildingException"
            ),
            "{err:?}"
        );
    }

    #[test]
    fn if_emits_three_payload_and_roundtrips() {
        rt_op("if (HEIGHT > 1) 1 else 2", 0x95);
    }

    #[test]
    fn tuple_and_select_field_emit_and_roundtrip() {
        rt_op("(1, 2L)", 0x86);
        // `(1, 2L)._2` survives as `Select '_2'` in the typed AST; the
        // Select arm lowers it to SelectField (GraphBuilding.scala:551-553).
        let ir = emit_tc("(1, 2L)._2");
        assert_eq!(root_opcode(&ir), 0x8C);
        match &ir {
            Expr::Op(IrNode {
                payload: Payload::SelectField { field_idx, .. },
                ..
            }) => assert_eq!(*field_idx, 2, "1-based field index"),
            other => panic!("expected SelectField, got {other:?}"),
        }
        wire_roundtrip(&ir);
        // Hand-built SelectField node (typer static tuple-index arm shape,
        // golden_seed §23(b) static record) still round-trips.
        let node = TypedExpr::SelectField {
            input: Box::new(tc("(1, 2L)")),
            field_index: 2,
            tpe: SType::SLong,
        };
        rt_node(&node, 0x8C);
    }

    #[test]
    fn tuple_select_field_first_component_emits_index_one() {
        let ir = emit_tc("(1, 2L)._1");
        assert_eq!(root_opcode(&ir), 0x8C);
        match &ir {
            Expr::Op(IrNode {
                payload: Payload::SelectField { field_idx, .. },
                ..
            }) => assert_eq!(*field_idx, 1),
            other => panic!("expected SelectField, got {other:?}"),
        }
        wire_roundtrip(&ir);
    }

    #[test]
    fn concrete_collection_emits_elem_type_and_roundtrips() {
        let ir = emit_tc("Coll(1, 2)");
        assert_eq!(root_opcode(&ir), 0x83);
        match &ir {
            Expr::Op(IrNode {
                payload: Payload::ConcreteCollection { elem_type, items },
                ..
            }) => {
                assert_eq!(elem_type, &SigmaType::SInt);
                assert_eq!(items.len(), 2);
            }
            other => panic!("expected ConcreteCollection, got {other:?}"),
        }
        wire_roundtrip(&ir);
    }

    #[test]
    fn upcast_from_mixed_arith_emits_numeric_cast() {
        // `1 + 1L` — the typer wraps the Int side in Upcast(SLong)
        // (unify.rs:478); emit lowers it to NumericCast @ 0x7E.
        let ir = emit_tc("1 + 1L");
        assert_eq!(root_opcode(&ir), 0x9A);
        match &ir {
            Expr::Op(IrNode {
                payload: Payload::Two(left, _),
                ..
            }) => match left.as_ref() {
                Expr::Op(IrNode {
                    opcode: 0x7E,
                    payload: Payload::NumericCast { tpe, .. },
                }) => assert_eq!(tpe, &SigmaType::SLong),
                other => panic!("expected Upcast on the left, got {other:?}"),
            },
            other => panic!("expected Two payload, got {other:?}"),
        }
        wire_roundtrip(&ir);
    }

    #[test]
    fn downcast_hand_built_emits_numeric_cast_and_roundtrips() {
        // Direct Downcast node (the frontend route is the `Select` cast arm,
        // covered by `select_numeric_casts_*` below).
        let node = TypedExpr::Downcast {
            input: Box::new(long_c(1)),
            tpe: SType::SInt,
        };
        let ir = rt_node(&node, 0x7D);
        match &ir {
            Expr::Op(IrNode {
                payload: Payload::NumericCast { tpe, .. },
                ..
            }) => assert_eq!(tpe, &SigmaType::SInt),
            other => panic!("expected NumericCast, got {other:?}"),
        }
    }

    #[test]
    fn select_numeric_casts_emit_numeric_cast_by_ladder_order() {
        // GraphBuilding.scala:555-563: narrower target → Downcast, wider →
        // Upcast, chained casts compose.
        let ir = emit_tc("1.toByte");
        assert_eq!(root_opcode(&ir), 0x7D, "Int→Byte is a Downcast");
        match &ir {
            Expr::Op(IrNode {
                payload: Payload::NumericCast { tpe, .. },
                ..
            }) => assert_eq!(tpe, &SigmaType::SByte),
            other => panic!("expected NumericCast, got {other:?}"),
        }
        wire_roundtrip(&ir);
        rt_op("1.toLong", 0x7E);
        rt_op("1.toBigInt", 0x7E);
        rt_op("1.toByte.toShort", 0x7E); // Upcast over the inner Downcast
    }

    #[test]
    fn select_numeric_cast_same_type_unwraps_to_input() {
        // GraphBuilding.scala:558-559 `if (numValue.tpe == tRes)
        // eval(numValue)` — a same-type cast disappears from the tree.
        let ir = emit_tc("1.toInt");
        assert!(
            matches!(
                &ir,
                Expr::Const {
                    tpe: SigmaType::SInt,
                    val: SigmaValue::Int(1),
                }
            ),
            "same-type cast must unwrap to the bare input, got {ir:?}"
        );
        wire_roundtrip(&ir);
    }

    #[test]
    fn collection_ops_emit_and_roundtrip() {
        rt_op("a.slice(0, 1)", 0xB4);
        rt_op("a ++ b", 0xB3);
        rt_op("Coll(1, 2)(0)", 0xB2);
        // getOrElse on a collection → ByIndex WITH a default child.
        let ir = emit_tc("Coll(1, 2).getOrElse(0, 5)");
        assert_eq!(root_opcode(&ir), 0xB2);
        match &ir {
            Expr::Op(IrNode {
                payload: Payload::ByIndex { default, .. },
                ..
            }) => assert!(default.is_some(), "getOrElse default present"),
            other => panic!("expected ByIndex, got {other:?}"),
        }
        wire_roundtrip(&ir);
    }

    #[test]
    fn size_of_hand_built_emits_one_payload() {
        // Direct SizeOf node; the frontend `Select 'size'` route is covered
        // by `select_size_emits_size_of` below.
        let node = TypedExpr::SizeOf {
            input: Box::new(TypedExpr::Inputs {
                tpe: scoll(SType::SBox),
            }),
            tpe: SType::SInt,
        };
        rt_node(&node, 0xB1);
    }

    #[test]
    fn select_size_emits_size_of() {
        // `col1.size` survives as `Select 'size'` (golden_seed §23(a) dot
        // form); the Select arm lowers it to SizeOf
        // (GraphBuilding.scala:520-525). Also holds for INPUTS and tuples
        // (STuple is collection-like, SType.scala:822-825).
        rt_op("col1.size", 0xB1);
        rt_op("(1, 2L).size", 0xB1);
        let ir = emit_tc("INPUTS.size > 1");
        assert_eq!(root_opcode(&ir), 0x91);
        match &ir {
            Expr::Op(IrNode {
                payload: Payload::Two(left, _),
                ..
            }) => assert_eq!(root_opcode(left), 0xB1, "SizeOf child"),
            other => panic!("expected Two payload, got {other:?}"),
        }
        wire_roundtrip(&ir);
    }

    #[test]
    fn postfix_size_residual_method_call_rejects_graph_building_parity() {
        // `col1 size` (no dot, the grammar's PostFix rule) desugars to a
        // zero-arg MethodCall `%SCollection.size [] {}` (golden_seed §23(a))
        // on BOTH typers, but Scala's GraphBuilding has no arm for the wire
        // pair (12,1) — only the Select path lowers `size` (SizeOf) — and
        // rejects (oracle: `ccs sigmaProp((arr1 size) > 0)` → `REJECT 1:12
        // GraphBuildingException`, compile_seed.json). Emit mirrors the
        // verdict.
        let err = emit(&tc("col1 size")).expect_err("postfix size must reject");
        assert!(
            matches!(
                &err,
                EmitError::GraphBuildingReject { class, .. }
                    if *class == "GraphBuildingException"
            ),
            "{err:?}"
        );
        // Nearest-accept boundary: the DOT form lowers via the Select path
        // to SizeOf (0xB1) — untouched by the gate.
        rt_op("col1.size", 0xB1);
    }

    #[test]
    fn snumeric_container_method_call_rejects_graph_building_parity() {
        // tree_version < 3 resolves `1.toBytes` to the shared SNumericType
        // container (D-T10); Scala's GraphBuilding rejects the v6-only
        // method under v5 activation (oracle, ORACLE_TREE_VERSION=2:
        // `cc sigmaProp(1.toBytes.size == 1)` → `REJECT 1:11
        // GraphBuildingException`, compile_seed.json). The TYPER stays
        // permissive on both sides (M2 parity, golden_seed §21) — the gate
        // is emit's.
        let typed = typecheck(&demo_env(), "1.toBytes", 2).expect("v2 typer accepts (M2 parity)");
        let err = emit(&typed).expect_err("SNumericType residual must reject");
        assert!(
            matches!(
                &err,
                EmitError::GraphBuildingReject { class, .. }
                    if *class == "GraphBuildingException"
            ),
            "{err:?}"
        );
        // Nearest-accept boundary: at v3 the owner resolves per-type (Int).
        // A NON-constant receiver keeps the residual MethodCall with wire
        // pair (4, 6) (oracle: `ccs sigmaProp(HEIGHT.toBytes.size == 4)`
        // keeps the pair too — Err/Err reduce parity, compile_seed.json); a
        // CONSTANT receiver folds at v3 — see
        // `numeric_const_receiver_methods_fold_to_oracle_bytes`.
        let ir = emit_tc("HEIGHT.toBytes");
        assert_eq!(root_opcode(&ir), 0xDB);
        match &ir {
            Expr::Op(IrNode {
                payload:
                    Payload::MethodCall {
                        type_id, method_id, ..
                    },
                ..
            }) => assert_eq!((*type_id, *method_id), (4, 6)),
            other => panic!("expected MethodCall payload, got {other:?}"),
        }
    }

    #[test]
    fn get_reg_out_of_range_literal_rejects_graph_building_parity() {
        // Scala bounds-checks a CONST-index getReg at compile time while
        // lowering it to ExtractRegisterAs (oracle: `cc sigmaProp(
        // SELF.getReg[Int](-1).isDefined)` → `REJECT 0:0
        // ArrayIndexOutOfBoundsException`; same for 10 and 100,
        // compile_seed.json).
        for src in [
            "SELF.getReg[Int](-1)",
            "SELF.getReg[Int](10)",
            "SELF.getReg[Int](100)",
        ] {
            let err = emit(&tc(src)).expect_err(src);
            assert!(
                matches!(
                    &err,
                    EmitError::GraphBuildingReject { class, .. }
                        if *class == "ArrayIndexOutOfBoundsException"
                ),
                "{src}: {err:?}"
            );
        }
        // Nearest-accept boundaries: in-range literals (0..=9) lower to
        // ExtractRegisterAs (byte pins in
        // `get_reg_in_range_literal_lowers_to_extract_register_as`), and a
        // DYNAMIC index is untouched (Scala keeps the MethodCall there too —
        // Err/Err reduce parity).
        for src in ["SELF.getReg[Int](0)", "SELF.getReg[Int](9)"] {
            let ir = emit(&tc(src)).unwrap_or_else(|e| panic!("{src}: {e:?}"));
            assert_eq!(root_opcode(&ir), 0xC6, "{src}");
        }
        let ir = emit(&tc("SELF.getReg[Int](HEIGHT)")).expect("dynamic index");
        assert_eq!(root_opcode(&ir), 0xDC);
    }

    #[test]
    fn numeric_const_receiver_methods_fold_to_oracle_bytes() {
        // (adversarial-findings-methodcalls.md F6): Scala's GraphBuilding
        // partially evaluates v6 numeric methods over CONSTANT receivers at
        // v3; emit folds the same probed set. Every expected hex below is
        // the CONSTANT segment of an oracle capture:
        //   ccs `x.toBytes` (x=10)        → `0e04 0000000a` (big-endian)
        //   ccs `x.toBits`                → `0d20 00000050` (Coll[Boolean],
        //       index 0 = the most significant bit; bit-packed on the wire)
        //   cc `7.toByte.toBytes`         → `0e01 07` (cast-of-literal folds)
        //   cc `7.toByte.toBits`          → `0d08 e0`
        //   cc `5.toShort.toBytes`        → `0e02 0005`
        //   ccs `height1.toBytes` (=100L) → `0e08 0000000000000064`
        //   ccs `b1.toBytes` (=1)         → `0e01 01`
        // bitwiseAnd/Or/Xor over two constants fold too (the x/y probes each
        // reply the FULLY-folded `10010101d17300`; the folded values are
        // pinned here at the constant level).
        for (src, expect_hex) in [
            ("10.toBytes", "0e040000000a"),
            ("10.toBits", "0d2000000050"),
            ("7.toByte.toBytes", "0e0107"),
            ("7.toByte.toBits", "0d08e0"),
            ("5.toShort.toBytes", "0e020005"),
            ("100L.toBytes", "0e080000000000000064"),
            ("1.toByte.toBytes", "0e0101"),
            ("10.bitwiseAnd(11)", "0414"), // Int 10 & 11 = 10 (zigzag 0x14)
            ("10.bitwiseOr(11)", "0416"),  // Int 10 | 11 = 11 (zigzag 0x16)
            ("10.bitwiseXor(11)", "0402"), // Int 10 ^ 11 = 1 (zigzag 0x02)
            ("1.toByte.bitwiseAnd(2.toByte)", "0200"), // Byte 1 & 2 = 0
        ] {
            let ir = emit_tc(src);
            assert!(
                matches!(&ir, Expr::Const { .. }),
                "{src}: expected a folded constant, got {ir:?}"
            );
            assert_eq!(hex::encode(wire_roundtrip(&ir)), expect_hex, "{src}");
        }
        // Probed NON-folds stay residual MethodCalls: BigInt receiver
        // (oracle keeps wire pair (6, 6)) and shiftLeft (keeps (4, 12)).
        rt_op("n1.toBytes", 0xDB);
        rt_op("10.shiftLeft(1)", 0xDC);
    }

    #[test]
    fn get_reg_in_range_literal_lowers_to_extract_register_as() {
        // (adversarial-findings-methodcalls.md F4): Scala lowers a
        // CONST-index `getReg[T]` to ExtractRegisterAs at GraphBuilding —
        // `cc sigmaProp(SELF.getReg[Int](5).isDefined)` and `cc sigmaProp(
        // SELF.R5[Int].isDefined)` reply IDENTICALLY (`1000d1e6c6a70504`;
        // body `…c6 a7 05 04` = ExtractRegisterAs(SELF, reg 5, Int) — the
        // wire carries the INNER elem type).
        let get_reg = emit_tc("SELF.getReg[Int](5)");
        let r5 = emit_tc("SELF.R5[Int]");
        assert_eq!(get_reg, r5, "getReg literal must lower like the R5 path");
        assert_eq!(hex::encode(wire_roundtrip(&get_reg)), "c6a70504");
        // Long variant over another register, with the getOrElse chain the
        // oracle probed (`…e5c6a70405…`).
        let ir = emit_tc("SELF.getReg[Long](4).getOrElse(7L)");
        assert_eq!(hex::encode(wire_roundtrip(&ir)), "e5c6a70405050e");
    }

    #[test]
    fn higher_order_ops_emit_fixed_arity_payloads() {
        // Fixed-arity opcode mapping pinned with constant stand-ins in the
        // function position (the wire pattern is child-shape-agnostic); the
        // real-lambda frontend route is `higher_order_ops_with_frontend_
        // lambdas_emit_func_values` below.
        let input = byte_coll_c(vec![1, 2]);
        let f = long_c(7);
        let mk = |node: TypedExpr, byte: u8| {
            rt_node(&node, byte);
        };
        mk(
            TypedExpr::MapCollection {
                input: Box::new(input.clone()),
                mapper: Box::new(f.clone()),
                tpe: scoll(SType::SLong),
            },
            0xAD,
        );
        mk(
            TypedExpr::Exists {
                input: Box::new(input.clone()),
                condition: Box::new(f.clone()),
                tpe: SType::SBoolean,
            },
            0xAE,
        );
        mk(
            TypedExpr::ForAll {
                input: Box::new(input.clone()),
                condition: Box::new(f.clone()),
                tpe: SType::SBoolean,
            },
            0xAF,
        );
        mk(
            TypedExpr::Filter {
                input: Box::new(input.clone()),
                condition: Box::new(f.clone()),
                tpe: scoll(SType::SByte),
            },
            0xB5,
        );
        mk(
            TypedExpr::Fold {
                input: Box::new(input),
                zero: Box::new(long_c(0)),
                fold_op: Box::new(f),
                tpe: SType::SLong,
            },
            0xB0,
        );
    }

    #[test]
    fn logical_fold_predefs_emit_one_collection_arg() {
        rt_op("allOf(Coll(HEIGHT > 1, HEIGHT > 2))", 0x96);
        rt_op("anyOf(Coll(HEIGHT > 1, HEIGHT > 2))", 0x97);
        rt_op("xorOf(Coll(HEIGHT > 1, HEIGHT > 2))", 0xFF);
    }

    #[test]
    fn at_least_emits_bound_then_input() {
        let ir = emit_tc("atLeast(1, Coll(proveDlog(g1), proveDlog(g2)))");
        assert_eq!(root_opcode(&ir), 0x98);
        match &ir {
            Expr::Op(IrNode {
                payload: Payload::Two(bound, _input),
                ..
            }) => assert!(
                matches!(
                    bound.as_ref(),
                    Expr::Const {
                        val: SigmaValue::Int(1),
                        ..
                    }
                ),
                "bound child first (AtLeast wire order)"
            ),
            other => panic!("expected Two payload, got {other:?}"),
        }
        wire_roundtrip(&ir);
    }

    #[test]
    fn sigma_combinators_emit_sigma_collection() {
        for (src, opcode) in [
            ("proveDlog(g1) && proveDlog(g2)", 0xEA),
            ("proveDlog(g1) || proveDlog(g2)", 0xEB),
        ] {
            let ir = emit_tc(src);
            assert_eq!(root_opcode(&ir), opcode, "{src}");
            match &ir {
                Expr::Op(IrNode {
                    payload: Payload::SigmaCollection { items },
                    ..
                }) => assert_eq!(items.len(), 2, "{src}"),
                other => panic!("{src}: expected SigmaCollection, got {other:?}"),
            }
            wire_roundtrip(&ir);
        }
    }

    #[test]
    fn sigma_coercions_emit_and_roundtrip() {
        rt_op("sigmaProp(HEIGHT > 100)", 0xD1);
        // `.propBytes` / `.isProven` survive as `Select` and the Select arm
        // lowers them (GraphBuilding.scala:527-533).
        rt_op("proveDlog(g1).propBytes", 0xD0);
        rt_op("proveDlog(g1).isProven", 0xCF);
        // Hand-built dedicated nodes still round-trip.
        rt_node(
            &TypedExpr::SigmaPropBytes {
                input: Box::new(tc("proveDlog(g1)")),
                tpe: scoll(SType::SByte),
            },
            0xD0,
        );
        rt_node(
            &TypedExpr::SigmaPropIsProven {
                input: Box::new(tc("proveDlog(g1)")),
                tpe: SType::SBoolean,
            },
            0xCF,
        );
    }

    #[test]
    fn crypto_ops_emit_and_roundtrip() {
        rt_op("proveDlog(g1)", 0xCD);
        rt_op("proveDHTuple(g1, g2, g1, g2)", 0xCE);
        rt_op("blake2b256(a)", 0xCB);
        rt_op("sha256(a)", 0xCC);
    }

    #[test]
    fn byte_conversions_emit_and_roundtrip() {
        rt_op("byteArrayToBigInt(a)", 0x7B);
        rt_op("byteArrayToLong(a)", 0x7C);
        rt_op("longToByteArray(1L)", 0x7A);
    }

    #[test]
    fn group_ops_emit_and_roundtrip() {
        rt_op("decodePoint(a)", 0xEE);
        rt_op("g1.multiply(g2)", 0xA0);
        rt_op("g1.exp(n1)", 0x9F);
        rt_op("Global.xor(a, b)", 0x9B);
    }

    #[test]
    fn option_ops_emit_and_roundtrip() {
        rt_op("getVar[Int](1)", 0xE3);
        rt_op("getVar[Int](1).get", 0xE4);
        rt_op("getVar[Int](1).isDefined", 0xE6);
        rt_op("getVar[Int](1).getOrElse(2)", 0xE5);
    }

    #[test]
    fn get_var_emits_inner_type_on_the_wire() {
        // GetVar's node type is SOption(V); the wire carries V (Scala
        // GetVarSerializer writes `tpe.elemType`; ergo-ser's parse arm reads
        // one bare type and our GetVar payload docs call it the read type).
        let ir = emit_tc("getVar[Int](1)");
        match &ir {
            Expr::Op(IrNode {
                payload: Payload::GetVar { var_id, tpe },
                ..
            }) => {
                assert_eq!(*var_id, 1);
                assert_eq!(tpe, &SigmaType::SInt, "inner type, not SOption");
            }
            other => panic!("expected GetVar, got {other:?}"),
        }
    }

    #[test]
    fn deserialize_ops_emit_and_roundtrip() {
        rt_op("executeFromVar[Boolean](1)", 0xD4);
        let ir = emit_tc("executeFromSelfReg[Boolean](4)");
        assert_eq!(root_opcode(&ir), 0xD5);
        match &ir {
            Expr::Op(IrNode {
                payload:
                    Payload::DeserializeRegister {
                        reg_id,
                        tpe,
                        default,
                    },
                ..
            }) => {
                assert_eq!(*reg_id, 4);
                assert_eq!(tpe, &SigmaType::SBoolean);
                assert!(default.is_none());
            }
            other => panic!("expected DeserializeRegister, got {other:?}"),
        }
        wire_roundtrip(&ir);
        let ir = emit_tc("executeFromSelfRegWithDefault[Int](4, 7)");
        assert_eq!(root_opcode(&ir), 0xD5);
        match &ir {
            Expr::Op(IrNode {
                payload: Payload::DeserializeRegister { default, .. },
                ..
            }) => assert!(default.is_some(), "default child present"),
            other => panic!("expected DeserializeRegister, got {other:?}"),
        }
        wire_roundtrip(&ir);
    }

    #[test]
    fn subst_constants_emits_three_and_roundtrips() {
        rt_op("substConstants(a, Coll(0), Coll(1L))", 0x74);
    }

    #[test]
    fn tree_lookup_hand_built_roundtrips() {
        // No frontend surface constructs TreeLookup at M3 (`avlTree`/AvlTree
        // methods lower elsewhere); 0xB7 parses with wire arity 3 and the
        // evaluator rejects at execution, matching Scala (types.rs:346-353).
        let node = TypedExpr::TreeLookup {
            tree: Box::new(TypedExpr::LastBlockUtxoRootHash {
                tpe: SType::SAvlTree,
            }),
            key: Box::new(byte_coll_c(vec![1])),
            proof: Box::new(byte_coll_c(vec![2])),
            tpe: SType::SOption(Box::new(scoll(SType::SByte))),
        };
        rt_node(&node, 0xB7);
    }

    #[test]
    fn block_val_emits_blockvalue_valdef_valuse_and_roundtrips() {
        // `{ val x = HEIGHT; x > 100 }` → BlockValue(ValDef(1, Height),
        // GT(ValUse(1), 100)); ValDef ids start at 1 in source order and the
        // wire ValDef carries NO type (ergo-ser parse pins tpe: None).
        let ir = emit_tc("{ val x = HEIGHT; x > 100 }");
        assert_eq!(root_opcode(&ir), 0xD8);
        let Expr::Op(IrNode {
            payload: Payload::BlockValue { items, result },
            ..
        }) = &ir
        else {
            panic!("expected BlockValue, got {ir:?}");
        };
        assert_eq!(items.len(), 1);
        match &items[0] {
            Expr::Op(IrNode {
                opcode: 0xD6,
                payload: Payload::ValDef { id, tpe, rhs },
            }) => {
                assert_eq!(*id, 1);
                assert_eq!(*tpe, None, "ValDef type never on the wire");
                assert_eq!(root_opcode(rhs), 0xA3, "rhs is Height");
            }
            other => panic!("expected ValDef, got {other:?}"),
        }
        match result.as_ref() {
            Expr::Op(IrNode {
                opcode: 0x91,
                payload: Payload::Two(left, _),
            }) => assert_eq!(
                left.as_ref(),
                &Expr::Op(IrNode {
                    opcode: 0x72,
                    payload: Payload::ValUse { id: 1 },
                }),
                "block result references the val through ValUse(1)"
            ),
            other => panic!("expected GT result, got {other:?}"),
        }
        wire_roundtrip(&ir);
    }

    #[test]
    fn lambda_emits_funcvalue_with_typed_arg_and_roundtrips() {
        // `OUTPUTS.map({ (o: Box) => o.value })` → MapCollection(Outputs,
        // FuncValue([(1, SBox)], ExtractAmount(ValUse(1)))). FuncValue args
        // MUST carry types — the ergo-ser writer panics otherwise
        // (write.rs FuncValue arm).
        let ir = emit_tc("OUTPUTS.map({ (o: Box) => o.value })");
        assert_eq!(root_opcode(&ir), 0xAD);
        let Expr::Op(IrNode {
            payload: Payload::Two(_, mapper),
            ..
        }) = &ir
        else {
            panic!("expected Two payload, got {ir:?}");
        };
        let Expr::Op(IrNode {
            opcode: 0xD9,
            payload: Payload::FuncValue { args, body },
        }) = mapper.as_ref()
        else {
            panic!("expected FuncValue mapper, got {mapper:?}");
        };
        assert_eq!(args, &vec![(1u32, Some(SigmaType::SBox))]);
        assert_eq!(
            body.as_ref(),
            &Expr::Op(IrNode {
                opcode: 0xC1, // ExtractAmount — Select 'value' lowering
                payload: Payload::One(Box::new(Expr::Op(IrNode {
                    opcode: 0x72,
                    payload: Payload::ValUse { id: 1 },
                }))),
            })
        );
        wire_roundtrip(&ir);
    }

    #[test]
    fn higher_order_ops_with_frontend_lambdas_emit_func_values() {
        for (src, opcode) in [
            ("col1.map({(x: Long) => x})", 0xAD),
            ("col1.exists({(x: Long) => x > 1L})", 0xAE),
            ("col1.forall({(x: Long) => x > 1L})", 0xAF),
            ("col1.filter({(x: Long) => x > 1L})", 0xB5),
        ] {
            let ir = emit_tc(src);
            assert_eq!(root_opcode(&ir), opcode, "{src}");
            match &ir {
                Expr::Op(IrNode {
                    payload: Payload::Two(_, f),
                    ..
                }) => assert_eq!(root_opcode(f), 0xD9, "{src}: FuncValue lambda"),
                other => panic!("{src}: expected Two payload, got {other:?}"),
            }
            wire_roundtrip(&ir);
        }
        // fold's op is a TWO-arg lambda → FuncValue with two typed arg slots.
        let ir = emit_tc("col1.fold(0L, {(acc: Long, x: Long) => acc + x})");
        assert_eq!(root_opcode(&ir), 0xB0);
        match &ir {
            Expr::Op(IrNode {
                payload: Payload::Three(_, _, op),
                ..
            }) => match op.as_ref() {
                Expr::Op(IrNode {
                    opcode: 0xD9,
                    payload: Payload::FuncValue { args, .. },
                }) => assert_eq!(
                    args,
                    &vec![
                        (1u32, Some(SigmaType::SLong)),
                        (2u32, Some(SigmaType::SLong))
                    ]
                ),
                other => panic!("expected two-arg FuncValue, got {other:?}"),
            },
            other => panic!("expected Three payload, got {other:?}"),
        }
        wire_roundtrip(&ir);
    }

    #[test]
    fn nested_scopes_allocate_collision_free_ids() {
        // Outer val takes id 1; the lambda arg continues from the same
        // monotonic counter (id 2) — never-reuse relaxation of the Scala
        // scheme (TreeBuilding.scala:186-191, see the Scope docs).
        let ir = emit_tc("{ val w = 1L; col1.map({(x: Long) => x + w}) }");
        assert_eq!(root_opcode(&ir), 0xD8);
        let Expr::Op(IrNode {
            payload: Payload::BlockValue { items, result },
            ..
        }) = &ir
        else {
            panic!("expected BlockValue, got {ir:?}");
        };
        match &items[0] {
            Expr::Op(IrNode {
                payload: Payload::ValDef { id, .. },
                ..
            }) => assert_eq!(*id, 1),
            other => panic!("expected ValDef, got {other:?}"),
        }
        let Expr::Op(IrNode {
            payload: Payload::Two(_, f),
            ..
        }) = result.as_ref()
        else {
            panic!("expected MapCollection result, got {result:?}");
        };
        let Expr::Op(IrNode {
            payload: Payload::FuncValue { args, body },
            ..
        }) = f.as_ref()
        else {
            panic!("expected FuncValue, got {f:?}");
        };
        assert_eq!(args, &vec![(2u32, Some(SigmaType::SLong))]);
        // Lambda body `x + a`: ValUse(2) for the arg, ValUse(1) for the
        // enclosing val — the arg SHADOWS nothing here, both resolve.
        assert_eq!(
            body.as_ref(),
            &Expr::Op(IrNode {
                opcode: 0x9A,
                payload: Payload::Two(
                    Box::new(Expr::Op(IrNode {
                        opcode: 0x72,
                        payload: Payload::ValUse { id: 2 },
                    })),
                    Box::new(Expr::Op(IrNode {
                        opcode: 0x72,
                        payload: Payload::ValUse { id: 1 },
                    })),
                ),
            })
        );
        wire_roundtrip(&ir);
    }

    #[test]
    fn lambda_arg_shadows_enclosing_val() {
        // The inner `x` must resolve to the lambda arg (id 2), not the
        // enclosing val (id 1) — innermost-frame-first lookup, mirroring the
        // typer's `lambdaEnv = env ++ args` overwrite (SigmaTyper.scala:128).
        let ir = emit_tc("{ val x = 5L; col1.map({(x: Long) => x}) }");
        let Expr::Op(IrNode {
            payload: Payload::BlockValue { result, .. },
            ..
        }) = &ir
        else {
            panic!("expected BlockValue, got {ir:?}");
        };
        let Expr::Op(IrNode {
            payload: Payload::Two(_, f),
            ..
        }) = result.as_ref()
        else {
            panic!("expected MapCollection result, got {result:?}");
        };
        let Expr::Op(IrNode {
            payload: Payload::FuncValue { body, .. },
            ..
        }) = f.as_ref()
        else {
            panic!("expected FuncValue, got {f:?}");
        };
        assert_eq!(
            body.as_ref(),
            &Expr::Op(IrNode {
                opcode: 0x72,
                payload: Payload::ValUse { id: 2 },
            }),
            "inner x resolves to the lambda arg"
        );
        wire_roundtrip(&ir);
    }

    #[test]
    fn apply_of_val_bound_lambda_emits_funcapply_and_roundtrips() {
        // `f(2)` where f is a val-bound lambda → FuncApply(ValUse, [2]).
        let ir = emit_tc("{ val f = {(x: Int) => x + 1}; f(2) }");
        assert_eq!(root_opcode(&ir), 0xD8);
        let Expr::Op(IrNode {
            payload: Payload::BlockValue { result, .. },
            ..
        }) = &ir
        else {
            panic!("expected BlockValue, got {ir:?}");
        };
        match result.as_ref() {
            Expr::Op(IrNode {
                opcode: 0xDA,
                payload: Payload::FuncApply { func, args },
            }) => {
                assert_eq!(
                    func.as_ref(),
                    &Expr::Op(IrNode {
                        opcode: 0x72,
                        payload: Payload::ValUse { id: 2 },
                    }),
                    "callee is the val's ValUse (lambda arg took id 1 — \
                     rhs is emitted before the ValDef id is taken, \
                     TreeBuilding.scala:511-513 ordering)"
                );
                assert_eq!(args.len(), 1);
            }
            other => panic!("expected FuncApply result, got {other:?}"),
        }
        wire_roundtrip(&ir);
    }

    #[test]
    fn outputs_and_coll_index_emit_byindex_and_roundtrip() {
        // Apply-on-Coll is lowered to ByIndex at typer time
        // (SigmaTyper.scala:261-277 port); emit passes it through 0xB2.
        rt_op("OUTPUTS(0)", 0xB2);
        rt_op("col1(0)", 0xB2);
    }

    #[test]
    fn byte_index_from_frontend_carries_single_typer_upcast() {
        // golden_seed §"{ val i = 1.toByte; Coll(1, 2, 3)(i) }": the TYPER
        // already wraps the Byte index in Upcast(SInt); emit_index must not
        // double-wrap (the emitted index node's type is already SInt).
        let ir = emit_tc("{ val i = 1.toByte; Coll(1, 2, 3)(i) }");
        let Expr::Op(IrNode {
            payload: Payload::BlockValue { result, .. },
            ..
        }) = &ir
        else {
            panic!("expected BlockValue, got {ir:?}");
        };
        match result.as_ref() {
            Expr::Op(IrNode {
                opcode: 0xB2,
                payload: Payload::ByIndex { index, .. },
            }) => match index.as_ref() {
                Expr::Op(IrNode {
                    opcode: 0x7E,
                    payload: Payload::NumericCast { input, tpe },
                }) => {
                    assert_eq!(tpe, &SigmaType::SInt);
                    assert_eq!(
                        root_opcode(input),
                        0x72,
                        "exactly ONE Upcast layer over the ValUse"
                    );
                }
                other => panic!("expected a single Upcast, got {other:?}"),
            },
            other => panic!("expected ByIndex result, got {other:?}"),
        }
        wire_roundtrip(&ir);
    }

    #[test]
    fn tuple_dynamic_index_emits_byindex_per_committed_record() {
        // golden_seed §23(b): a non-constant tuple index typechecks to
        // ByIndex:Any over the Tuple value (STuple extends SCollection[SAny]).
        let ir = emit_tc("{ val i = HEIGHT; (1, 2)(i) }");
        assert_eq!(root_opcode(&ir), 0xD8);
        let Expr::Op(IrNode {
            payload: Payload::BlockValue { result, .. },
            ..
        }) = &ir
        else {
            panic!("expected BlockValue, got {ir:?}");
        };
        match result.as_ref() {
            Expr::Op(IrNode {
                opcode: 0xB2,
                payload: Payload::ByIndex { input, index, .. },
            }) => {
                assert_eq!(root_opcode(input), 0x86, "Tuple input");
                assert_eq!(root_opcode(index), 0x72, "ValUse index (Int, no cast)");
            }
            other => panic!("expected ByIndex result, got {other:?}"),
        }
        wire_roundtrip(&ir);
    }

    #[test]
    fn select_box_properties_emit_extract_opcodes() {
        // GraphBuilding.scala:541-549 property → Extract* mapping.
        for (src, opcode) in [
            ("SELF.value", 0xC1),
            ("SELF.propositionBytes", 0xC2),
            ("SELF.bytes", 0xC3),
            ("SELF.bytesWithoutRef", 0xC4),
            ("SELF.id", 0xC5),
            ("SELF.creationInfo", 0xC7),
        ] {
            rt_op(src, opcode);
        }
    }

    #[test]
    fn select_register_emits_extract_register_as_with_inner_type() {
        // `SELF.R4[Long]` → ExtractRegisterAs(reg 4) with the INNER type on
        // the wire (Scala serializer writes `obj.tpe.elemType`,
        // ExtractRegisterAsSerializer.scala serialize).
        let ir = emit_tc("SELF.R4[Long]");
        assert_eq!(root_opcode(&ir), 0xC6);
        match &ir {
            Expr::Op(IrNode {
                payload: Payload::ExtractRegisterAs { reg_id, tpe, .. },
                ..
            }) => {
                assert_eq!(*reg_id, 4);
                assert_eq!(tpe, &SigmaType::SLong, "inner type, not SOption");
            }
            other => panic!("expected ExtractRegisterAs, got {other:?}"),
        }
        wire_roundtrip(&ir);
        // Composite: `.get` over the register read → OptionGet root.
        rt_op("SELF.R4[Long].get", 0xE4);
        // R0 and R9 bound registers.
        for (src, reg) in [("SELF.R0[Long]", 0u8), ("SELF.R9[Int]", 9u8)] {
            let ir = emit_tc(src);
            match &ir {
                Expr::Op(IrNode {
                    payload: Payload::ExtractRegisterAs { reg_id, .. },
                    ..
                }) => assert_eq!(*reg_id, reg, "{src}"),
                other => panic!("{src}: expected ExtractRegisterAs, got {other:?}"),
            }
            wire_roundtrip(&ir);
        }
    }

    #[test]
    fn method_call_get_reg_emits_explicit_type_arg() {
        // `SELF.getReg[Int](HEIGHT)` (DYNAMIC index — a literal index lowers
        // to ExtractRegisterAs instead) → MethodCall 0xDC (99, 19) with
        // one value arg and the explicit `[T]` type block (ergo-ser
        // method_explicit_type_args_count(99, 19) == 1). Oracle keeps the
        // MethodCall for the dynamic form too (`cc sigmaProp(SELF.getReg[
        // Int](HEIGHT).isDefined)` → body `…dc6313a701a304`).
        let ir = emit_tc("SELF.getReg[Int](HEIGHT)");
        assert_eq!(root_opcode(&ir), 0xDC);
        match &ir {
            Expr::Op(IrNode {
                payload:
                    Payload::MethodCall {
                        type_id,
                        method_id,
                        args,
                        type_args,
                        ..
                    },
                ..
            }) => {
                assert_eq!((*type_id, *method_id), (99, 19));
                assert_eq!(args.len(), 1);
                assert_eq!(type_args, &vec![SigmaType::SInt]);
            }
            other => panic!("expected MethodCall payload, got {other:?}"),
        }
        assert_eq!(hex::encode(wire_roundtrip(&ir)), "dc6313a701a304");
        // Composite: OptionGet over the MethodCall.
        rt_op("SELF.getReg[Int](HEIGHT).get", 0xE4);
    }

    #[test]
    fn property_call_none_emits_type_arg_without_args() {
        // `Global.none[Int]()` → PropertyCall 0xDB (106, 10): zero value
        // args but STILL one explicit type arg on the wire (the ergo-ser
        // PropertyCall arm reads the same type block).
        let ir = emit_tc("Global.none[Int]()");
        assert_eq!(root_opcode(&ir), 0xDB);
        match &ir {
            Expr::Op(IrNode {
                payload:
                    Payload::MethodCall {
                        type_id,
                        method_id,
                        args,
                        type_args,
                        ..
                    },
                ..
            }) => {
                assert_eq!((*type_id, *method_id), (106, 10));
                assert!(args.is_empty());
                assert_eq!(type_args, &vec![SigmaType::SInt]);
            }
            other => panic!("expected MethodCall payload, got {other:?}"),
        }
        wire_roundtrip(&ir);
    }

    #[test]
    fn residual_method_calls_emit_wire_ids_and_roundtrip() {
        // Property/method calls the M2 lowering leaves as MethodCall:
        // context/avltree/group-element properties and Global v6 methods.
        for (src, opcode, ids) in [
            ("CONTEXT.dataInputs", 0xDB, (101u8, 1u8)),
            ("CONTEXT.preHeader", 0xDB, (101, 3)),
            ("LastBlockUtxoRootHash.digest", 0xDB, (100, 1)),
            ("g1.getEncoded", 0xDB, (7, 2)),
            // v3 concrete %Int.toBytes — NON-constant receiver (a constant
            // receiver folds instead — gate (d) in emit_method_call).
            ("HEIGHT.toBytes", 0xDB, (4, 6)),
            ("Global.serialize(HEIGHT)", 0xDC, (106, 3)),
        ] {
            let ir = emit_tc(src);
            assert_eq!(root_opcode(&ir), opcode, "{src}");
            match &ir {
                Expr::Op(IrNode {
                    payload:
                        Payload::MethodCall {
                            type_id, method_id, ..
                        },
                    ..
                }) => assert_eq!((*type_id, *method_id), ids, "{src}"),
                other => panic!("{src}: expected MethodCall payload, got {other:?}"),
            }
            wire_roundtrip(&ir);
        }
        // Chained: PreHeader property over a Context property.
        rt_op("CONTEXT.preHeader.height", 0xDB);
    }

    #[test]
    fn hand_built_mixed_relation_gets_upcast_inserted() {
        // Frontend trees carry typer-inserted Upcasts already; a hand-built
        // mixed GT exercises emit's own normalization
        // (comparisonOp → applyUpcast, SigmaBuilder.scala:688-697).
        let node = TypedExpr::GT {
            left: Box::new(int_c(1)),
            right: Box::new(long_c(2)),
            tpe: SType::SBoolean,
        };
        let ir = rt_node(&node, 0x91);
        match &ir {
            Expr::Op(IrNode {
                payload: Payload::Two(left, right),
                ..
            }) => {
                assert_eq!(root_opcode(left), 0x7E, "narrower Int side upcast");
                assert!(matches!(right.as_ref(), Expr::Const { .. }));
            }
            other => panic!("expected Two payload, got {other:?}"),
        }
        // Mirror case: narrower side on the right.
        let node = TypedExpr::ArithOp {
            left: Box::new(long_c(2)),
            right: Box::new(int_c(1)),
            opcode: crate::typed::ARITH_PLUS,
            tpe: SType::SLong,
        };
        let ir = rt_node(&node, 0x9A);
        match &ir {
            Expr::Op(IrNode {
                payload: Payload::Two(left, right),
                ..
            }) => {
                assert!(matches!(left.as_ref(), Expr::Const { .. }));
                assert_eq!(root_opcode(right), 0x7E, "narrower Int side upcast");
            }
            other => panic!("expected Two payload, got {other:?}"),
        }
    }

    #[test]
    fn hand_built_mixed_bit_op_rejects_like_frontend_ones() {
        // Mixed-width bit ops reject the same as same-width ones — Scala's
        // GraphBuilding has no BitOp arm at ANY width (oracle: `cc
        // sigmaProp((1 | 2L) == 3L)` → `REJECT 1:12 GraphBuildingException`,
        // compile_seed.json).
        use crate::typed::BIT_OR;
        let node = TypedExpr::BitOp {
            left: Box::new(int_c(1)),
            right: Box::new(long_c(2)),
            opcode: BIT_OR,
            tpe: SType::SLong,
        };
        assert!(matches!(
            emit(&node),
            Err(EmitError::GraphBuildingReject { .. })
        ));
    }

    #[test]
    fn hand_built_byte_index_gets_upcast_to_int() {
        // Defensive emit_index normalization (SigmaTyper.scala:265-288
        // `typedIndex.upcastTo(SInt)`) for a hand-built narrow index.
        let node = TypedExpr::ByIndex {
            input: Box::new(byte_coll_c(vec![1, 2])),
            index: Box::new(TypedExpr::Constant {
                value: ConstPayload::Byte(1),
                tpe: SType::SByte,
            }),
            default: None,
            tpe: SType::SByte,
        };
        let ir = rt_node(&node, 0xB2);
        match &ir {
            Expr::Op(IrNode {
                payload: Payload::ByIndex { index, .. },
                ..
            }) => match index.as_ref() {
                Expr::Op(IrNode {
                    opcode: 0x7E,
                    payload: Payload::NumericCast { tpe, .. },
                }) => assert_eq!(tpe, &SigmaType::SInt),
                other => panic!("expected Upcast index, got {other:?}"),
            },
            other => panic!("expected ByIndex, got {other:?}"),
        }
    }

    #[test]
    fn mixed_width_arith_relation_frontend_roundtrips() {
        // `(1 + 2L) == 3L`: the typer inserts the Upcast; emit's
        // normalization is a no-op on the already-normalized tree.
        let ir = emit_tc("(1 + 2L) == 3L");
        assert_eq!(root_opcode(&ir), 0x93);
        wire_roundtrip(&ir);
    }

    // ----- error paths -----

    #[test]
    fn create_avl_tree_returns_unsupported_node() {
        // ergo-ser parses 0xB6 as Zero (deprecated AvlTreeCode) while Scala
        // 6.0.2 registers CreateAvlTreeSerializer (Four) on the same byte —
        // resolved toward ergo-ser (module docs + lib.rs ledger).
        let node = TypedExpr::CreateAvlTree {
            operation_flags: Box::new(TypedExpr::Constant {
                value: ConstPayload::Byte(0),
                tpe: SType::SByte,
            }),
            digest: Box::new(byte_coll_c(vec![0; 33])),
            key_length: Box::new(int_c(1)),
            value_length_opt: Box::new(int_c(1)),
            tpe: SType::SAvlTree,
        };
        assert_eq!(
            emit(&node).unwrap_err(),
            EmitError::UnsupportedNode("CreateAvlTree".to_string())
        );
    }

    #[test]
    fn zk_proof_block_returns_unsupported_node() {
        let node = TypedExpr::ZKProofBlock {
            body: Box::new(tc("proveDlog(g1)")),
            tpe: SType::SBoolean,
        };
        assert_eq!(
            emit(&node).unwrap_err(),
            EmitError::UnsupportedNode("ZKProofBlock".to_string())
        );
    }

    #[test]
    fn opaque_sigma_prop_constant_returns_unsupported_node() {
        // An env-injected opaque SigmaProp label has no curve bytes to
        // serialize (lib.rs ledger; only reachable from a hand-built env).
        let err = map_const(
            &ConstPayload::SigmaProp("p1".to_string()),
            &SType::SSigmaProp,
        )
        .unwrap_err();
        assert!(matches!(err, EmitError::UnsupportedNode(_)));
    }

    #[test]
    fn apply_types_and_method_call_like_return_invalid_shape() {
        // Pre-typed-only nodes: the typer eliminates both before returning
        // (typed.rs docs) — reaching emit is a pipeline bug, not a scope gap.
        let at = TypedExpr::ApplyTypes {
            input: Box::new(int_c(1)),
            type_args: vec![SType::SInt],
            tpe: SType::SInt,
        };
        assert!(matches!(emit(&at).unwrap_err(), EmitError::InvalidShape(_)));
        let mcl = TypedExpr::MethodCallLike {
            obj: Box::new(int_c(1)),
            name: "+".to_string(),
            args: vec![int_c(2)],
            tpe: SType::NoType,
        };
        assert!(matches!(
            emit(&mcl).unwrap_err(),
            EmitError::InvalidShape(_)
        ));
    }

    #[test]
    fn map_type_notype_and_stypeapply_return_unresolved_type() {
        assert!(matches!(
            map_type(&SType::NoType).unwrap_err(),
            EmitError::UnresolvedType(_)
        ));
        assert!(matches!(
            map_type(&SType::STypeApply {
                name: "Coll".to_string(),
                args: vec![SType::SInt],
            })
            .unwrap_err(),
            EmitError::UnresolvedType(_)
        ));
    }

    #[test]
    fn tuple_arity_out_of_bounds_returns_invalid_shape() {
        // The ergo-ser writer asserts (panics) past 255 items and a 1-tuple
        // is not a Scala STuple; emit guards both as recoverable errors.
        let one = TypedExpr::Tuple {
            items: vec![int_c(1)],
            tpe: SType::STuple(vec![SType::SInt]),
        };
        assert!(matches!(
            emit(&one).unwrap_err(),
            EmitError::InvalidShape(_)
        ));
        let many = TypedExpr::Tuple {
            items: (0..256).map(int_c).collect(),
            tpe: SType::STuple(vec![SType::SInt; 256]),
        };
        assert!(matches!(
            emit(&many).unwrap_err(),
            EmitError::InvalidShape(_)
        ));
    }

    #[test]
    fn get_var_with_non_option_type_returns_invalid_shape() {
        // GetVar's node type must be SOption(V) (transformers.scala:576);
        // anything else means the typer broke its own invariant.
        let node = TypedExpr::GetVar {
            var_id: 1,
            tpe: SType::SInt,
        };
        assert!(matches!(
            emit(&node).unwrap_err(),
            EmitError::InvalidShape(_)
        ));
    }

    #[test]
    fn lambda_without_body_returns_invalid_shape() {
        // `body: None` only occurs in pre-typed trees (binder invariant); a
        // FuncValue cannot be serialized without a body.
        let node = TypedExpr::Lambda {
            tpe_params: vec![],
            args: vec![("x".to_string(), SType::SInt)],
            given_res_type: SType::SInt,
            body: None,
            tpe: SType::SFunc {
                dom: vec![SType::SInt],
                range: Box::new(SType::SInt),
                tpe_params: vec![],
            },
        };
        assert!(matches!(
            emit(&node).unwrap_err(),
            EmitError::InvalidShape(_)
        ));
    }

    #[test]
    fn lambda_with_type_params_returns_invalid_shape() {
        // The wire FuncValue has no type-param block; the binder enforces
        // `!(tpeParams.nonEmpty && body.nonEmpty)` upstream.
        let node = TypedExpr::Lambda {
            tpe_params: vec![crate::typed::STypeParam {
                ident: "T".to_string(),
            }],
            args: vec![("x".to_string(), SType::SInt)],
            given_res_type: SType::SInt,
            body: Some(Box::new(int_c(1))),
            tpe: SType::SFunc {
                dom: vec![SType::SInt],
                range: Box::new(SType::SInt),
                tpe_params: vec![],
            },
        };
        assert!(matches!(
            emit(&node).unwrap_err(),
            EmitError::InvalidShape(_)
        ));
    }

    #[test]
    fn unbound_ident_returns_invalid_shape() {
        let node = TypedExpr::Ident {
            name: "ghost".to_string(),
            tpe: SType::SInt,
        };
        assert!(matches!(
            emit(&node).unwrap_err(),
            EmitError::InvalidShape(_)
        ));
    }

    /// D-C8: `allZK`/`anyZK`/`outerJoin` are KNOWN predefs (present in
    /// `predefined_env`) with no Scala irBuilder — reaching them here as a
    /// bare unbound `Apply(Ident, args)` is a real, oracle-confirmed user
    /// REJECT (`StagingException`; literal single-/multi-element `Coll` AND
    /// val-bound forms all reject), not a pipeline bug. Must classify as
    /// `GraphBuildingReject`, never
    /// `InvalidShape` — the two are user-facing-vs-internal, not
    /// interchangeable (`unbound_ident_returns_invalid_shape` above pins the
    /// genuine-bug case stays `InvalidShape`).
    #[test]
    fn known_predef_gap_ident_returns_graph_building_reject_not_invalid_shape() {
        for name in ["allZK", "anyZK", "outerJoin"] {
            let node = TypedExpr::Apply {
                func: Box::new(TypedExpr::Ident {
                    name: name.to_string(),
                    tpe: SType::SFunc {
                        dom: vec![SType::SColl(Box::new(SType::SSigmaProp))],
                        range: Box::new(SType::SSigmaProp),
                        tpe_params: vec![],
                    },
                }),
                args: vec![TypedExpr::Constant {
                    value: ConstPayload::ByteColl(vec![]),
                    tpe: SType::SColl(Box::new(SType::SSigmaProp)),
                }],
                tpe: SType::SSigmaProp,
            };
            match emit(&node).unwrap_err() {
                EmitError::GraphBuildingReject { class, what } => {
                    assert_eq!(class, "StagingException", "{name}");
                    assert!(what.contains(name), "{name}: {what}");
                }
                other => panic!("{name}: expected GraphBuildingReject, got {other:?}"),
            }
        }
    }

    #[test]
    fn val_node_outside_block_returns_invalid_shape() {
        // A bare top-level `val` is a PARSE reject (golden_seed §25), so a
        // root ValNode can only be hand-built — a pipeline bug surface.
        let node = TypedExpr::ValNode {
            name: "x".to_string(),
            given_type: SType::SInt,
            body: Box::new(int_c(1)),
            tpe: SType::SInt,
        };
        assert!(matches!(
            emit(&node).unwrap_err(),
            EmitError::InvalidShape(_)
        ));
    }

    #[test]
    fn block_with_non_val_binding_returns_invalid_shape() {
        let node = TypedExpr::Block {
            bindings: vec![int_c(1)],
            result: Box::new(int_c(2)),
            tpe: SType::SInt,
        };
        assert!(matches!(
            emit(&node).unwrap_err(),
            EmitError::InvalidShape(_)
        ));
    }

    #[test]
    fn residual_select_returns_unsupported_node_naming_the_field() {
        // Outside the lowering catalog → UnsupportedNode carrying the field
        // name.
        let node = TypedExpr::Select {
            obj: Box::new(tc("SELF")),
            field: "getRegV5".to_string(),
            res_type: None,
            tpe: SType::SInt,
        };
        match emit(&node).unwrap_err() {
            EmitError::UnsupportedNode(msg) => {
                assert!(msg.contains("getRegV5"), "message names the field: {msg}")
            }
            other => panic!("expected UnsupportedNode, got {other:?}"),
        }
        // Bare `SELF.R4` (function-typed, no `[T]`) is also residual: the
        // register arm requires a resolved Option res_type.
        let bare_reg = tc("SELF.R4");
        match emit(&bare_reg).unwrap_err() {
            EmitError::UnsupportedNode(msg) => {
                assert!(msg.contains("R4"), "message names the field: {msg}")
            }
            other => panic!("expected UnsupportedNode, got {other:?}"),
        }
    }

    #[test]
    fn method_call_with_unknown_owner_returns_unsupported_node() {
        use crate::typed::MethodRef;
        let node = TypedExpr::MethodCall {
            obj: Box::new(int_c(1)),
            method: MethodRef {
                owner: "?".to_string(),
                name: "mystery".to_string(),
            },
            args: vec![],
            type_subst: vec![],
            tpe: SType::SInt,
        };
        match emit(&node).unwrap_err() {
            EmitError::UnsupportedNode(msg) => assert!(
                msg.contains("?.mystery"),
                "message names owner.method: {msg}"
            ),
            other => panic!("expected UnsupportedNode, got {other:?}"),
        }
    }

    #[test]
    fn method_call_missing_explicit_type_binding_returns_invalid_shape() {
        // getReg (99,19) requires a `{T -> _}` binding for its wire type arg.
        use crate::typed::MethodRef;
        let node = TypedExpr::MethodCall {
            obj: Box::new(tc("SELF")),
            method: MethodRef {
                owner: "Box".to_string(),
                name: "getReg".to_string(),
            },
            args: vec![int_c(4)],
            type_subst: vec![],
            tpe: SType::SOption(Box::new(SType::SInt)),
        };
        assert!(matches!(
            emit(&node).unwrap_err(),
            EmitError::InvalidShape(_)
        ));
    }

    #[test]
    fn zero_arg_method_call_of_args_method_returns_invalid_shape() {
        // %SCollection.slice with an empty arg list would serialize as a
        // PropertyCall that deserializes to a different invocation.
        use crate::typed::MethodRef;
        let node = TypedExpr::MethodCall {
            obj: Box::new(tc("col1")),
            method: MethodRef {
                owner: "SCollection".to_string(),
                name: "slice".to_string(),
            },
            args: vec![],
            type_subst: vec![],
            tpe: scoll(SType::SLong),
        };
        assert!(matches!(
            emit(&node).unwrap_err(),
            EmitError::InvalidShape(_)
        ));
    }

    #[test]
    fn apply_on_non_callable_returns_unsupported_node() {
        let node = TypedExpr::Apply {
            func: Box::new(int_c(1)),
            args: vec![int_c(2)],
            tpe: SType::SInt,
        };
        assert!(matches!(
            emit(&node).unwrap_err(),
            EmitError::UnsupportedNode(_)
        ));
    }

    // ----- oracle parity -----

    #[test]
    fn standalone_top_level_val_rejects_matching_oracle() {
        // golden_seed §25: `tc val x = 1` →
        // `REJECT 1:1 ParserException`. Emit never sees a ValNode root from
        // the frontend because the parse already rejects.
        let err = typecheck(&demo_env(), "val x = 1", 3).unwrap_err();
        assert_eq!(err.class(), "ParserException");
    }

    #[test]
    fn sigma_prop_true_emits_boolean_via_constant_path() {
        // Oracle capture (module docs): `cc sigmaProp(true)` →
        // `10 01 0101 d1 7300` — the Boolean rides the CONSTANT path
        // (segregated 0101 table entry + placeholder), not opcode 0x7F.
        // Pre-segregation the same constant is inline: d1 01 01.
        let ir = emit_tc("sigmaProp(true)");
        assert_eq!(
            ir,
            Expr::Op(IrNode {
                opcode: 0xD1,
                payload: Payload::One(Box::new(Expr::Const {
                    tpe: SigmaType::SBoolean,
                    val: SigmaValue::Boolean(true),
                })),
            })
        );
        let bytes = wire_roundtrip(&ir);
        assert_eq!(bytes, vec![0xD1, 0x01, 0x01]);
    }

    #[test]
    fn sigma_prop_height_gt_100_inline_bytes_match_oracle_constant_bytes() {
        // Oracle capture: `cc sigmaProp(HEIGHT > 100)` →
        // `10 01 04c801 d191a37300` (segregated). The inline pre-segregation body is
        // the same opcode spine with the constant bytes `04 c8 01` in place
        // of the placeholder: d1 91 a3 04c801.
        let bytes = wire_roundtrip(&emit_tc("sigmaProp(HEIGHT > 100)"));
        assert_eq!(bytes, vec![0xD1, 0x91, 0xA3, 0x04, 0xC8, 0x01]);
    }
}
