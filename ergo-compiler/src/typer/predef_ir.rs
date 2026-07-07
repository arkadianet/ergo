//! Predefined-function environment + irBuilder lowering table.
//!
//! Ports the `globalFuncs` registry from `SigmaPredef.scala` (pinned v6.0.2
//! `/home/rkadias/coding/reference/ergo-core/sigmastate-interpreter-v6.0.2/
//!   data/shared/src/main/scala/sigma/ast/SigmaPredef.scala`):
//!
//! - [`predefined_env`] — the declaration-type map (`name -> SFunc`) that
//!   `SigmaTyper` seeds as the initial `env` (`predefinedEnv`, SigmaTyper.scala:33-36,
//!   `predefFuncRegistry.funcs.map { k -> f.declaration.tpe }`).  The `globalFuncs`
//!   plus the two *word-named* `infixFuncs` `min`/`max` are reproduced.  The
//!   *operator-symbol* `infixFuncs`/`unaryFuncs` (`"+"`, `"=="`, `"||"`, …) carry
//!   names the parser lowers to dedicated nodes and therefore never appear as
//!   `Ident`s in a bound tree — their env entries are inert, so omitting *those* is
//!   behaviour-preserving.  `min`/`max` are the exception: they ARE valid
//!   identifiers (bare `min`, `val x = min`, and the block duplicate-name check
//!   `{ val min = 1; min }`), so they must be present (adversarial finding A2).
//!
//! - [`predef_ir_builder`] — the `PredefinedFuncApply.unapply` post-wrapper
//!   (SigmaPredef.scala:745-753): given a typed callee `Ident(name, …)` and its
//!   already-typed args, run the corresponding `irBuilder` PartialFunction.  The
//!   `Option<Result<…>>` return encodes the three Scala outcomes:
//!   - `None` — no irBuilder for `name`, or `isDefinedAt` was false (the arg
//!     pattern didn't match) → the caller keeps the `mkApply` node (fall-through).
//!     This is the TYPER path's crucial difference from the BINDER path (Task-4
//!     finding): a non-matching arg pattern falls through here rather than throwing.
//!   - `Some(Ok(n))` — `isDefinedAt` true, the builder produced IR node `n`.
//!   - `Some(Err(e))` — `isDefinedAt` true, the builder body threw (e.g.
//!     `executeFromSelfReg` bad index) → propagated by the caller.
//!
//! # Deferred irBuilders (documented deviations)
//!
//! `unsignedBigInt` parses FIRST, then validates the SIGN of the parsed value
//! (negative → reject, matching Scala `InvalidArguments` — class deviation,
//! see `CLASS_DEVIATION_SOURCES`; `"-0"`/`"-0000"` have `signum() == 0` and
//! ACCEPT as `@0`, golden_seed.txt §24(g)); a valid non-negative literal
//! builds the canonical `ConstPayload::UnsignedBigInt`
//! constant (D-T3 CLOSED, M3 Task-6; oracle: `unsignedBigInt("5")` →
//! `OK (ConstantNode:UnsignedBigInt (CUnsignedBigInt @5))`, golden_seed.txt
//! §13/§24). Canonicalizes leading zeros (`"0005"` → `"5"`, oracle-verified) and
//! caps at 256 bits (`bitLength() > 256` → reject, `CUnsignedBigInt.scala:20-22`)
//! — UNCONDITIONALLY, unlike `bigInt`'s `tree_version >= 3`-gated 255-bit cap.
//!
//! `fromBase58` validates that every character is in the Bitcoin / Scorex Base58
//! alphabet (`123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`).  An
//! invalid character causes Scorex `Base58.decode(s).get` to throw `AssertionError`
//! ("Wrong char in Base58 string") via `Predef.ensuring`; we map this to a
//! `TyperError` (D-T2: verdict parity; error class differs, as documented in
//! lib.rs).  A valid (or empty) literal decodes canonically to a
//! `ByteArrayConstant` (`bs58::decode`, Bitcoin alphabet — byte-identical to
//! Scorex's decoder; M3 Task-5 closes the deferred shape).
//!
//! `fromBase64` validates that every character is in the Java standard Base64
//! alphabet (`A-Za-z0-9+/=`).  An invalid character causes
//! `java.util.Base64.getDecoder().decode(s)` to throw `IllegalArgumentException`;
//! we map to `TyperError` (D-T2: verdict parity; error class differs, as
//! documented in lib.rs).  A valid literal decodes canonically to a
//! `ByteArrayConstant` via the `JAVA_BASE64` engine (standard alphabet,
//! optional padding, trailing bits in the last quantum silently dropped —
//! matching `java.util.Base64.getDecoder()` exactly; M3 Task-5 closes the
//! deferred shape).
//!
//! `deserialize[T](s)` — CLOSED (M4 Task 8, D-T2).  `SigmaPredef.scala:169-188`
//! Base58-decodes `s`, runs `ValueSerializer.deserialize` (the SAME general
//! `Value` grammar `ergo_ser::opcode::parse_expr` reads ErgoTree bodies with)
//! over the bytes, and embeds the resulting expression IN PLACE at typecheck
//! time — a genuine opcode-IR→`TypedExpr` reverse mapping (gap F6). Oracle
//! 2026-07-07 (×2 confirms, `ORACLE_TREE_VERSION=3`): `deserialize[Int]("Jq")`
//! (bytes `04 0a`, a bare `IntConstant(5)`) embeds `ConstantNode:Int @5`;
//! `deserialize[Int]("3p")` (byte `a3`, bare `Height`) embeds `Height:Int` — a
//! non-constant, genuinely RUNTIME node. A bare `deserialize(...)` with no
//! explicit `[T]` REJECTs `InvalidArguments` (oracle-confirmed), mirroring
//! `deserializeTo`/`fromBigEndianBytes`'s existing `global_deserialize` gate.
//!
//! **Scope (probe-bounded):** [`unlower_expr`] covers every `Const` shape
//! [`crate::emit::map_const`] can produce in reverse (the `unmap_const`
//! lockstep — M4 Task 8 review closed the `ConstPayload::ProveDlog` gap,
//! D-C8: `unmap_const` had no arm for `SigmaValue::SigmaProp(SigmaBoolean::
//! ProveDlog(_))`, silently falling through to reject instead of
//! reconstructing a shape `map_const` can re-emit byte-identically; a
//! `map_const ∘ unmap_const = identity` test now sweeps every `ConstPayload`
//! variant to guard the pair against future drift), plus the nine
//! zero-payload context/global singleton primitives (`Height`/`Inputs`/
//! `Outputs`/`Self_`/`MinerPubkey`/`LastBlockUtxoRootHash`/`Context`/`Global`/
//! `GroupGenerator`) — both oracle-confirmed. `ConstPayload::SigmaProp`
//! (the opaque env-injected proposition label) is the one variant that
//! genuinely CANNOT round-trip: `map_const` itself refuses to emit it
//! (`EmitError::UnsupportedNode`, "opaque SigmaProp constant payload" — no
//! curve bytes to serialize), so no wire bytes carrying that shape ever
//! exist for `unmap_const` to invert — this is not a gap, there is nothing
//! to reverse. Anything else a crafted byte string could decode to (a
//! `BinOp`, a `MethodCall`, a materialized `Coll[Int]`/`Coll[Boolean]`
//! constant — `ConstPayload` has no variant for those, only `Coll[Byte]`/
//! `Coll[Long]`, mirroring `map_const`'s own coverage) is REJECTED with a
//! descriptive `TyperError` rather than silently mismapped — an honest,
//! bounded residual: no source in the 79-contract corpus calls `deserialize`
//! at all (grep-confirmed), so this is not a corpus blocker, and closing the
//! general case would mean porting a second full opcode-IR↔TypedExpr
//! symmetric mapping for a predef nothing exercises. See lib.rs § "Known M2
//! deviations" (D-T2) for the full ledger.
//!
//! `fromBase16`/`bigInt` ARE fully implemented (oracle-verified against the JVM
//! typer).

use base64::Engine as _;

use ergo_primitives::group_element::GroupElement;
use ergo_primitives::reader::VlqReader;
use ergo_ser::opcode::{parse_expr, Expr as OpExpr, IrNode, Payload as OpPayload};
use ergo_ser::sigma_type::SigmaType as WireType;
use ergo_ser::sigma_value::{CollValue, SigmaBoolean, SigmaValue as WireValue};

use crate::stype::SType;
use crate::typed::{ConstPayload, MethodRef, TypedExpr};
use crate::typer::assign::{stype_has_free_type_var, TyperError};
use crate::typer::methods::owner_name_for_type;
use crate::typer::TypeEnv;

// ─────────────────────────────────────────────────────────────────────────────
// SType shorthands
// ─────────────────────────────────────────────────────────────────────────────

#[inline]
fn coll(t: SType) -> SType {
    SType::SColl(Box::new(t))
}
#[inline]
fn coll_byte() -> SType {
    coll(SType::SByte)
}
#[inline]
fn opt(t: SType) -> SType {
    SType::SOption(Box::new(t))
}
#[inline]
fn tv(s: &str) -> SType {
    SType::STypeVar(s.to_string())
}
#[inline]
fn func(dom: Vec<SType>, range: SType) -> SType {
    SType::SFunc {
        dom,
        range: Box::new(range),
        tpe_params: vec![],
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// predefined_env — the initial typer env (SigmaTyper.scala:33-36)
// ─────────────────────────────────────────────────────────────────────────────

/// The predefined-function declaration-type environment.
///
/// Mirrors `predefFuncRegistry.funcs.map { k -> f.declaration.tpe }` restricted to
/// `globalFuncs` (see module docs for why infix/unary are elided).  Type
/// parameters appear positionally as [`SType::STypeVar`] inside the `SFunc` (so
/// [`crate::typer::assign`] can recover them for `ApplyTypes` by scanning free type
/// vars) AND are recorded on `SType::SFunc.tpe_params` for the polymorphic predefs
/// (patch loop below) so a bare/unapplied Ident value prints its `[T]` binder.
///
/// The registry is version-independent in Scala (all funcs registered regardless
/// of `tree_version`); version gating happens later at method resolution.  The
/// `tree_version` parameter is accepted for signature stability and future use.
pub fn predefined_env(_tree_version: u8) -> TypeEnv {
    let t = || tv("T");
    let ge = || SType::SGroupElement;
    let sp = || SType::SSigmaProp;
    let mut env = TypeEnv::new();
    let mut put = |name: &str, dom: Vec<SType>, range: SType| {
        env.insert(name.to_string(), func(dom, range));
    };

    // word-named infixFuncs (SigmaPredef.scala:620-623): `min`/`max` carry
    // declaration type `[T](T,T) => T`.  The 2-arg *application* form `min(a,b)` is
    // desugared to `ArithOp` Min/Max at bind time (binder.rs), but the bare/value/
    // shadow forms resolve through this env entry, and the block duplicate-name
    // check reads it (adversarial finding A2).  The `[T]` binder is attached by the
    // tpe_params patch below, so bare `min` prints `[T](T,T) => T` (wave-B shape fix).
    put("min", vec![t(), t()], t());
    put("max", vec![t(), t()], t());

    // logical / threshold
    put("allOf", vec![coll(SType::SBoolean)], SType::SBoolean);
    put("anyOf", vec![coll(SType::SBoolean)], SType::SBoolean);
    put("xorOf", vec![coll(SType::SBoolean)], SType::SBoolean);
    put("allZK", vec![coll(sp())], sp());
    put("anyZK", vec![coll(sp())], sp());
    put("atLeast", vec![SType::SInt, coll(sp())], sp());
    put("ZKProof", vec![sp()], SType::SBoolean);
    put("sigmaProp", vec![SType::SBoolean], sp());

    // context vars (type-parameterised)
    put("getVar", vec![SType::SByte], opt(t()));
    put(
        "getVarFromInput",
        vec![SType::SShort, SType::SByte],
        opt(t()),
    );
    put("executeFromVar", vec![SType::SByte], t());
    put("executeFromSelfReg", vec![SType::SInt], t());
    put("executeFromSelfRegWithDefault", vec![SType::SInt, t()], t());

    // compile-time constants
    put("deserialize", vec![SType::SString], t());
    put("bigInt", vec![SType::SString], SType::SBigInt);
    put(
        "unsignedBigInt",
        vec![SType::SString],
        SType::SUnsignedBigInt,
    );
    put("fromBase16", vec![SType::SString], coll_byte());
    put("fromBase58", vec![SType::SString], coll_byte());
    put("fromBase64", vec![SType::SString], coll_byte());

    // hashes / conversions
    put("blake2b256", vec![coll_byte()], coll_byte());
    put("sha256", vec![coll_byte()], coll_byte());
    put("byteArrayToBigInt", vec![coll_byte()], SType::SBigInt);
    put("byteArrayToLong", vec![coll_byte()], SType::SLong);
    put("decodePoint", vec![coll_byte()], ge());
    put("longToByteArray", vec![SType::SLong], coll_byte());

    // sigma constructors
    put("proveDlog", vec![ge()], sp());
    put("proveDHTuple", vec![ge(), ge(), ge(), ge()], sp());

    // structures
    put(
        "avlTree",
        vec![SType::SByte, coll_byte(), SType::SInt, opt(SType::SInt)],
        SType::SAvlTree,
    );
    put(
        "substConstants",
        vec![coll_byte(), coll(SType::SInt), coll(t())],
        coll_byte(),
    );
    // outerJoin[K, L, R, O] (SigmaPredef.scala:108-123).  No irBuilder
    // (`PredefFuncInfo(undefined)`) → survives as `Apply` at type time, so the env
    // entry alone is a complete port.  Type params are recovered in first-appearance
    // order (K, L, R, O), matching `outerJoin[K, L, R, O](...)`.
    {
        let tup = |a: SType, b: SType| SType::STuple(vec![a, b]);
        put(
            "outerJoin",
            vec![
                coll(tup(tv("K"), tv("L"))),
                coll(tup(tv("K"), tv("R"))),
                func(vec![tv("K"), tv("L")], tv("O")),
                func(vec![tv("K"), tv("R")], tv("O")),
                func(vec![tv("K"), tv("L"), tv("R")], tv("O")),
            ],
            coll(tup(tv("K"), tv("O"))),
        );
    }

    // Global-method predef aliases (also SGlobal methods; the bare-Ident form is
    // reached here, the `Global.<m>` form via the §1.7/§1.8 Select arms).
    put("serialize", vec![t()], coll_byte());
    put("deserializeTo", vec![coll_byte()], t());
    put("fromBigEndianBytes", vec![coll_byte()], t());
    // NB: `PK` is deliberately NOT in the env.  It is a standalone `PKFunc`
    // (SigmaPredef.scala:156), NOT a member of `funcs`, consumed only by the
    // binder's `PK("addr")` rewrite (binder.rs `bind_pk`).  A spurious env entry
    // both fabricates a bare-`PK` value (`PK` accepts, oracle rejects) and wrongly
    // fires the block duplicate-name check (`{ val PK = 1; PK }` rejects, oracle
    // accepts) — adversarial finding A2.

    // Attach declared type parameters to the polymorphic predefs (`STypeParam.ident`,
    // SType.scala:78-89) so a bare/unapplied Ident value prints its `[T]`/`[K,L,R,O]`
    // binder (oracle: `serialize` → `[T](T) => Coll[Byte]`, `min` → `[T](T,T) => T`,
    // `outerJoin` → `[K,L,R,O](...) => ...`).  Monomorphic predefs keep empty params.
    // Applied forms substitute these away, so the printed result type stays ground.
    for (name, params) in [
        ("min", &["T"][..]),
        ("max", &["T"]),
        ("getVar", &["T"]),
        ("getVarFromInput", &["T"]),
        ("executeFromVar", &["T"]),
        ("executeFromSelfReg", &["T"]),
        ("executeFromSelfRegWithDefault", &["T"]),
        ("deserialize", &["T"]),
        ("serialize", &["T"]),
        ("deserializeTo", &["T"]),
        ("fromBigEndianBytes", &["T"]),
        ("substConstants", &["T"]),
        ("outerJoin", &["K", "L", "R", "O"]),
    ] {
        if let Some(SType::SFunc { tpe_params, .. }) = env.get_mut(name) {
            *tpe_params = params.iter().map(|s| (*s).to_string()).collect();
        }
    }

    env
}

// ─────────────────────────────────────────────────────────────────────────────
// small accessors over typed nodes
// ─────────────────────────────────────────────────────────────────────────────

/// The `SFunc` range of a typed callee, if it is a function type.
fn func_range(f: &TypedExpr) -> Option<&SType> {
    match crate::typed::node_tpe(f) {
        SType::SFunc { range, .. } => Some(range),
        _ => None,
    }
}

/// The `SOption` element type, if `t` is `SOption`.
fn option_inner(t: &SType) -> Option<&SType> {
    match t {
        SType::SOption(inner) => Some(inner),
        _ => None,
    }
}

/// The integer value of a numeric `Constant` (`Byte`/`Short`/`Int`/`Long`), else
/// `None`.  Mirrors the `Constant[SNumericType]` guards in the irBuilders.
fn numeric_const_i64(e: &TypedExpr) -> Option<i64> {
    match e {
        TypedExpr::Constant { value, .. } => match value {
            ConstPayload::Byte(v) => Some(*v as i64),
            ConstPayload::Short(v) => Some(*v as i64),
            ConstPayload::Int(v) => Some(*v as i64),
            ConstPayload::Long(v) => Some(*v),
            _ => None,
        },
        _ => None,
    }
}

/// The string value of a `String` `Constant`, else `None`.  Mirrors the
/// `EvaluatedValue[SString.type]` guards in the decode irBuilders.
fn string_const(e: &TypedExpr) -> Option<&str> {
    match e {
        TypedExpr::Constant {
            value: ConstPayload::String(s),
            ..
        } => Some(s),
        _ => None,
    }
}

#[inline]
fn typer_err(msg: impl Into<String>) -> TyperError {
    TyperError::TyperException {
        pos: 0,
        msg: msg.into(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// predef_ir_builder — the PredefinedFuncApply post-wrapper (SigmaPredef.scala:745)
// ─────────────────────────────────────────────────────────────────────────────

/// Try to lower `Apply(Ident(name, _), args)` to the predefined func's IR node.
///
/// Returns `None` when there is no matching irBuilder / the arg pattern
/// (`isDefinedAt`) does not match (fall-through to the surviving `mkApply`);
/// `Some(Ok(node))` on a successful lowering; `Some(Err(_))` when the builder body
/// throws (propagated by the caller).  `func`/`args` are already fully typed.
pub fn predef_ir_builder(
    name: &str,
    func: &TypedExpr,
    args: &[TypedExpr],
    tree_version: u8,
) -> Option<Result<TypedExpr, TyperError>> {
    match name {
        // ── logical / threshold ──────────────────────────────────────────────
        // sigmaProp's Scala irBuilder is `case Seq(b: BoolValue @unchecked) =>
        // mkBoolToSigmaProp(b)` (SigmaPredef.scala): the `@unchecked` erases the
        // element type, so ANY single arg that reached here is wrapped directly in
        // BoolToSigmaProp.  The Apply-time unify gate admits only a Boolean (rule-10)
        // or a SigmaProp (rule-9 SBoolean→SSigmaProp), and a SigmaProp arg is placed
        // unmodified as the value — no SigmaPropIsProven (oracle:
        // `sigmaProp(sigmaProp(true))` → `BoolToSigmaProp(BoolToSigmaProp(true))`).
        "sigmaProp" => {
            if args.len() != 1 {
                return None;
            }
            Some(Ok(TypedExpr::BoolToSigmaProp {
                value: Box::new(args[0].clone()),
                tpe: SType::SSigmaProp,
            }))
        }
        "allOf" => unary(args, coll(SType::SBoolean), |v| TypedExpr::AND {
            input: Box::new(v),
            tpe: SType::SBoolean,
        }),
        "anyOf" => unary(args, coll(SType::SBoolean), |v| TypedExpr::OR {
            input: Box::new(v),
            tpe: SType::SBoolean,
        }),
        // xorOf's Scala irBuilder is `case Seq(col: Coll[SBoolean] @unchecked) =>
        // mkXorOf(col)` (SigmaPredef.scala:72-77): `@unchecked` erases the element
        // type, so ANY single `Coll[_]` fires XorOf.  A `Coll[SigmaProp]` reaches here
        // (it unifies against the declared `Coll[Boolean]` param via rule-9) and lowers
        // directly — xorOf is NOT in adaptSigmaPropToBoolean, so no isProven wrap.
        // Boundary: `xorOf(Coll(1,2,3))` (Coll[Int]) fails the arg-type unify in
        // assign_apply_generic before this builder runs → both REJECT.
        "xorOf" => {
            if args.len() != 1 || !matches!(crate::typed::node_tpe(&args[0]), SType::SColl(_)) {
                return None;
            }
            Some(Ok(TypedExpr::XorOf {
                input: Box::new(args[0].clone()),
                tpe: SType::SBoolean,
            }))
        }
        "ZKProof" => unary(args, SType::SSigmaProp, |v| TypedExpr::ZKProofBlock {
            body: Box::new(v),
            tpe: SType::SBoolean,
        }),
        "atLeast" => {
            // (_, Seq(bound: IntValue, arr: Coll[SigmaProp]))
            if args.len() != 2
                || *crate::typed::node_tpe(&args[0]) != SType::SInt
                || *crate::typed::node_tpe(&args[1]) != coll(SType::SSigmaProp)
            {
                return None;
            }
            Some(Ok(TypedExpr::AtLeast {
                bound: Box::new(args[0].clone()),
                input: Box::new(args[1].clone()),
                tpe: SType::SSigmaProp,
            }))
        }

        // ── hashes / conversions (arg: Coll[Byte] / Long) ────────────────────
        "blake2b256" => unary(args, coll_byte(), |v| TypedExpr::CalcBlake2b256 {
            input: Box::new(v),
            tpe: coll_byte(),
        }),
        "sha256" => unary(args, coll_byte(), |v| TypedExpr::CalcSha256 {
            input: Box::new(v),
            tpe: coll_byte(),
        }),
        "byteArrayToBigInt" => unary(args, coll_byte(), |v| TypedExpr::ByteArrayToBigInt {
            input: Box::new(v),
            tpe: SType::SBigInt,
        }),
        "byteArrayToLong" => unary(args, coll_byte(), |v| TypedExpr::ByteArrayToLong {
            input: Box::new(v),
            tpe: SType::SLong,
        }),
        "decodePoint" => unary(args, coll_byte(), |v| TypedExpr::DecodePoint {
            input: Box::new(v),
            tpe: SType::SGroupElement,
        }),
        "longToByteArray" => unary(args, SType::SLong, |v| TypedExpr::LongToByteArray {
            input: Box::new(v),
            tpe: coll_byte(),
        }),
        "proveDlog" => unary(args, SType::SGroupElement, |v| TypedExpr::CreateProveDlog {
            value: Box::new(v),
            tpe: SType::SSigmaProp,
        }),

        // ── multi-arg sigma / structures ─────────────────────────────────────
        "proveDHTuple" => {
            if args.len() != 4 {
                return None;
            }
            Some(Ok(TypedExpr::CreateProveDHTuple {
                gv: Box::new(args[0].clone()),
                hv: Box::new(args[1].clone()),
                uv: Box::new(args[2].clone()),
                vv: Box::new(args[3].clone()),
                tpe: SType::SSigmaProp,
            }))
        }
        "avlTree" => {
            if args.len() != 4 {
                return None;
            }
            Some(Ok(TypedExpr::CreateAvlTree {
                operation_flags: Box::new(args[0].clone()),
                digest: Box::new(args[1].clone()),
                key_length: Box::new(args[2].clone()),
                value_length_opt: Box::new(args[3].clone()),
                tpe: SType::SAvlTree,
            }))
        }
        "substConstants" => {
            if args.len() != 3 {
                return None;
            }
            Some(Ok(TypedExpr::SubstConstants {
                script_bytes: Box::new(args[0].clone()),
                positions: Box::new(args[1].clone()),
                new_values: Box::new(args[2].clone()),
                tpe: coll_byte(),
            }))
        }

        // ── context-var families (extract rtpe from the callee's SFunc range) ─
        "getVar" => {
            // (Ident(_, SFunc(_, SOption(rtpe), _)), Seq(id: Constant[Numeric]))
            let rtpe = func_range(func).and_then(option_inner)?;
            if args.len() != 1 {
                return None;
            }
            let id = numeric_const_i64(&args[0])?;
            Some(Ok(TypedExpr::GetVar {
                var_id: id as i8,
                tpe: opt(rtpe.clone()),
            }))
        }
        "executeFromVar" => {
            // (Ident(_, SFunc(_, rtpe, _)), Seq(id: Constant[Numeric]))
            let rtpe = func_range(func)?.clone();
            if args.len() != 1 {
                return None;
            }
            let id = numeric_const_i64(&args[0])?;
            Some(Ok(TypedExpr::DeserializeContext {
                id: id as i8,
                tpe: rtpe,
            }))
        }
        "executeFromSelfReg" => execute_from_self_reg(func, args, None),
        "executeFromSelfRegWithDefault" => {
            if args.len() != 2 {
                return None;
            }
            let default = args[1].clone();
            execute_from_self_reg(func, &args[..1], Some(default))
        }
        "getVarFromInput" => {
            // (Ident(_, SFunc(_, SOption(rtpe), _)), Seq(inputId, varId) numeric)
            let rtpe = func_range(func).and_then(option_inner)?.clone();
            if args.len() != 2
                || numeric_const_i64(&args[0]).is_none()
                || numeric_const_i64(&args[1]).is_none()
            {
                return None;
            }
            Some(Ok(method_call(
                context_node(),
                &SType::SContext,
                "getVarFromInput",
                args.to_vec(),
                vec![("T".to_string(), rtpe.clone())],
                opt(rtpe),
            )))
        }

        // ── Global-method predef aliases → MethodCall(Global, …) ─────────────
        "deserializeTo" => global_deserialize(func, args, "deserializeTo"),
        "fromBigEndianBytes" => global_deserialize(func, args, "fromBigEndianBytes"),

        // ── compile-time constant decoders (oracle-verified) ─────────────────
        "bigInt" => {
            let s = string_const(args.first()?)?;
            Some(parse_big_int(s, tree_version))
        }
        "fromBase16" => {
            let s = string_const(args.first()?)?;
            Some(decode_base16(s))
        }

        // unsignedBigInt(s): reject negative literals (Scala InvalidArguments,
        // class deviation — see `tests/typer_oracle_parity.rs`
        // `CLASS_DEVIATION_SOURCES`); a valid non-negative literal builds the
        // canonical `UnsignedBigInt` constant (D-T3 CLOSED, M3 Task-6). The
        // sign check lives INSIDE `parse_unsigned_big_int` — Scala parses
        // FIRST and rejects only `signum() < 0`, so `"-0"` ACCEPTs (§24(g)).
        "unsignedBigInt" => {
            let s = string_const(args.first()?)?;
            Some(parse_unsigned_big_int(s))
        }
        // fromBase58: reject if any char is outside the Bitcoin/Scorex Base58
        // alphabet (Scorex `Base58.decode(s).get` → AssertionError on bad char via
        // `Predef.ensuring`; we emit TyperError — D-T2, verdict parity). A valid
        // (or empty) literal decodes canonically (D-T2 CLOSED, M3 Task-5).
        "fromBase58" => {
            let s = string_const(args.first()?)?;
            match s.chars().find(|&c| !is_base58_char(c)) {
                Some(bad) => Some(Err(typer_err(format!(
                    "Wrong char in Base58 string: '{bad}'"
                )))),
                None => Some(decode_base58(s)),
            }
        }
        // fromBase64: reject if any char is outside the Java standard Base64
        // alphabet (`java.util.Base64.getDecoder().decode(s)` → IllegalArgumentException;
        // we emit TyperError — D-T2, verdict parity). A valid literal decodes
        // canonically (D-T2 CLOSED, M3 Task-5).
        "fromBase64" => {
            let s = string_const(args.first()?)?;
            match validate_base64(s) {
                Err(msg) => Some(Err(typer_err(msg))),
                Ok(()) => Some(decode_base64(s)),
            }
        }
        // deserialize[T](s): CLOSED (M4 Task 8, D-T2) — see module docs.
        "deserialize" => {
            let s = string_const(args.first()?)?;
            let target_tpe = func_range(func)?.clone();
            if stype_has_free_type_var(&target_tpe) {
                return Some(Err(typer_err(
                    "'deserialize' is type-parametric and requires an explicit type argument [T]"
                        .to_string(),
                )));
            }
            Some(deserialize_predef(s, &target_tpe, tree_version))
        }
        // allZK/anyZK/outerJoin/serialize(binder-handled)/PK(binder-handled):
        // no typer-time irBuilder → fall through.
        _ => None,
    }
}

// ----- shared irBuilder helpers -----

/// Single-arg irBuilder with a value-type guard (`isDefinedAt`).
fn unary(
    args: &[TypedExpr],
    expected: SType,
    build: impl FnOnce(TypedExpr) -> TypedExpr,
) -> Option<Result<TypedExpr, TyperError>> {
    if args.len() != 1 || *crate::typed::node_tpe(&args[0]) != expected {
        return None;
    }
    Some(Ok(build(args[0].clone())))
}

/// The `Global` context node (receiver of the deserialize/serialize aliases).
fn global_node() -> TypedExpr {
    TypedExpr::Global {
        tpe: SType::SGlobal,
    }
}

/// The `Context` context node (receiver of `getVarFromInput`).
fn context_node() -> TypedExpr {
    TypedExpr::Context {
        tpe: SType::SContext,
    }
}

/// Build a `MethodCall` whose owner is derived from the receiver `SType`.
fn method_call(
    obj: TypedExpr,
    recv: &SType,
    name: &str,
    args: Vec<TypedExpr>,
    type_subst: Vec<(String, SType)>,
    tpe: SType,
) -> TypedExpr {
    let owner = owner_name_for_type(recv).unwrap_or("?");
    TypedExpr::MethodCall {
        obj: Box::new(obj),
        method: MethodRef {
            owner: owner.to_string(),
            name: name.to_string(),
        },
        args,
        type_subst,
        tpe,
    }
}

/// `deserializeTo`/`fromBigEndianBytes` → `MethodCall(Global, <m>, args, {T->resType})`.
/// `resType = u.opType.tRange.asInstanceOf[SFunc].tRange` reduces to the callee's
/// `SFunc` range (SigmaPredef.scala:470-477, 489-496).  `isDefinedAt` is `(u, args)`
/// — matches any callee, so only the `SFunc`-range extraction can fail here.
fn global_deserialize(
    func: &TypedExpr,
    args: &[TypedExpr],
    name: &str,
) -> Option<Result<TypedExpr, TyperError>> {
    let res_type = func_range(func)?.clone();
    // A1 (accept-invalid fix): the bare `fromBigEndianBytes(a)` / `deserializeTo(a)`
    // form (no explicit `[T]`) leaves the callee's range as an unresolved `STypeVar`.
    // The reference typer REJECTS with IllegalArgumentException (the SMethod still
    // carries unresolved tpeParams); we require a concrete result type.  The
    // explicit-`[T]` control (`fromBigEndianBytes[Int](a)`) resolves `res_type` to
    // a concrete type via §1.7/ApplyTypes and is unaffected.  Oracle-pinned.
    if stype_has_free_type_var(&res_type) {
        return Some(Err(typer_err(format!(
            "'{name}' is type-parametric and requires an explicit type argument [T]"
        ))));
    }
    Some(Ok(method_call(
        global_node(),
        &SType::SGlobal,
        name,
        args.to_vec(),
        vec![("T".to_string(), res_type.clone())],
        res_type,
    )))
}

/// `executeFromSelfReg[T](id)` / `…WithDefault[T](id, default)` → `DeserializeRegister`.
/// Register index must be in `0..ErgoBox.allRegisters.length` (= 10, R0..R9);
/// out of range → `InvalidArguments` (bare form) or returns `default` (default form).
/// SigmaPredef.scala:425-435 (WithDefault), 511-520 (bare).
fn execute_from_self_reg(
    func: &TypedExpr,
    args: &[TypedExpr],
    default: Option<TypedExpr>,
) -> Option<Result<TypedExpr, TyperError>> {
    // (Ident(_, SFunc(_, rtpe, _)), Seq(id: Constant[Numeric]))
    let rtpe = func_range(func)?.clone();
    if args.len() != 1 {
        return None;
    }
    let idx = numeric_const_i64(&args[0])?;
    // ErgoBox.allRegisters.length == 10 (R0..R9).
    const NUM_REGISTERS: i64 = 10;
    if !(0..NUM_REGISTERS).contains(&idx) {
        return match default {
            // WithDefault: out-of-range returns the default value verbatim.
            Some(d) => Some(Ok(d)),
            // bare: out-of-range throws InvalidArguments (mapped to TyperException).
            None => Some(Err(typer_err(format!("Invalid register specified {idx}")))),
        };
    }
    Some(Ok(TypedExpr::DeserializeRegister {
        reg: idx as i8,
        tpe: rtpe,
        default: default.map(Box::new),
    }))
}

/// `bigInt(s)` → `BigIntConstant(new BigInteger(s))` (SigmaPredef.scala:190-199).
/// Parses with `num_bigint::BigInt` — rejects malformed input (mirrors Java
/// `NumberFormatException`) — and stores the CANONICAL decimal string (leading
/// zeros stripped: `bigInt("0005")` → `OK (ConstantNode:BigInt (CBigInt @5))`,
/// oracle-verified, golden_seed.txt §24, D-T3 M3 Task-6).
///
/// Cap (`CBigInt.scala:14-20`): `wrappedValue.bitLength() > 255` throws
/// `ArithmeticException`, but ONLY at `tree_version >= 3`
/// (`VersionContext.current.isV3OrLaterErgoTreeVersion`) — pre-v3 `bigInt(...)`
/// has NO size cap (oracle: `bigInt("<2^1000>")` → `OK` at v2, `REJECT
/// ArithmeticException` at v3, golden_seed.txt §24).  255-bit signed range is
/// `[-2^255, 2^255-1]` (two's-complement `bitLength`; oracle-verified at both
/// boundaries, golden_seed.txt §24).
fn parse_big_int(s: &str, tree_version: u8) -> Result<TypedExpr, TyperError> {
    if !is_decimal_integer(s) {
        return Err(typer_err(format!("For input string: \"{s}\"")));
    }
    let v: num_bigint::BigInt = s
        .parse()
        .map_err(|_| typer_err(format!("For input string: \"{s}\"")))?;
    if tree_version >= 3 && signed_bit_length(&v) > 255 {
        return Err(typer_err(format!("Too big bigint value {v}")));
    }
    Ok(TypedExpr::Constant {
        value: ConstPayload::BigInt(v.to_string()),
        tpe: SType::SBigInt,
    })
}

/// `unsignedBigInt(s)` → `UnsignedBigIntConstant(new BigInteger(s))`
/// (SigmaPredef.scala:201-215).  Parses FIRST with `num_bigint::BigInt`,
/// then rejects on the SIGN — Scala's `UnsignedBigIntFunc` constructs
/// `new BigInteger(s)` and rejects only `signum() < 0`, and
/// `BigInteger("-0").signum() == 0`, so `"-0"`/`"-0000"` ACCEPT as `@0`
/// (oracle: `tc unsignedBigInt("-0")` → `OK (ConstantNode:UnsignedBigInt
/// (CUnsignedBigInt @0))`, golden_seed.txt §24(g), captured 2026-07-07 ×3
/// runs; num-bigint normalizes `-0` to `Sign::NoSign`, so `Sign::Minus`
/// reproduces `signum() < 0` exactly).  Stores the CANONICAL decimal string
/// (leading zeros / `-0` sign stripped: `unsignedBigInt("0005")` →
/// `OK (ConstantNode:UnsignedBigInt (CUnsignedBigInt @5))`, oracle-verified,
/// golden_seed.txt §24, D-T3 M3 Task-6).
///
/// Cap (`CUnsignedBigInt.scala:14-22`): `wrappedValue.bitLength() > 256` throws
/// `ArithmeticException` — UNCONDITIONALLY, no `tree_version` gate (unlike
/// `bigInt`'s cap; oracle-verified at v2, golden_seed.txt §24).  256-bit
/// unsigned range is `[0, 2^256-1]` (oracle-verified at both boundaries,
/// golden_seed.txt §24).
fn parse_unsigned_big_int(s: &str) -> Result<TypedExpr, TyperError> {
    if !is_decimal_integer(s) {
        return Err(typer_err(format!("For input string: \"{s}\"")));
    }
    let v: num_bigint::BigInt = s
        .parse()
        .map_err(|_| typer_err(format!("For input string: \"{s}\"")))?;
    if v.sign() == num_bigint::Sign::Minus {
        return Err(typer_err(format!("Negative unsigned big integer: \"{s}\"")));
    }
    let v = v.magnitude();
    if v.bits() > 256 {
        return Err(typer_err(format!("Too big unsigned big int value {v}")));
    }
    Ok(TypedExpr::Constant {
        value: ConstPayload::UnsignedBigInt(v.to_string()),
        tpe: SType::SUnsignedBigInt,
    })
}

/// Java `BigInteger.bitLength()` semantics for a signed value: the number of
/// bits in the minimal two's-complement representation, excluding the sign bit.
/// For `v >= 0` this is the magnitude's bit length. For `v < 0` it is the
/// magnitude's bit length, UNLESS the magnitude is itself a power of two (i.e.
/// `v` is exactly `-2^k`), in which case the two's-complement encoding of `v`
/// needs one fewer bit (`-1` → bit length 0; `-2^255` → bit length 255,
/// oracle-verified golden_seed.txt §24, matching `Long.MIN_VALUE ==
/// -2^63`'s well-known `bitLength() == 63`).
fn signed_bit_length(v: &num_bigint::BigInt) -> u64 {
    use num_bigint::Sign;
    let mag = v.magnitude();
    let bits = mag.bits();
    if v.sign() == Sign::Minus && bits > 0 && mag.trailing_zeros() == Some(bits - 1) {
        bits - 1
    } else {
        bits
    }
}

/// A non-empty decimal integer literal (optional leading `+`/`-`, then digits).
fn is_decimal_integer(s: &str) -> bool {
    let body = s.strip_prefix(['+', '-']).unwrap_or(s);
    !body.is_empty() && body.bytes().all(|b| b.is_ascii_digit())
}

/// `fromBase16(s)` → `ByteArrayConstant(Base16.decode(s).get)`.  Even-length hex,
/// case-insensitive; bytes stored as signed `i8` (matching `ByteColl`).
fn decode_base16(s: &str) -> Result<TypedExpr, TyperError> {
    if !s.len().is_multiple_of(2) {
        return Err(typer_err(format!("invalid base16 length: {}", s.len())));
    }
    let mut bytes = Vec::with_capacity(s.len() / 2);
    let raw = s.as_bytes();
    let mut i = 0;
    while i < raw.len() {
        let hi = hex_nibble(raw[i]).ok_or_else(|| typer_err("invalid base16 digit"))?;
        let lo = hex_nibble(raw[i + 1]).ok_or_else(|| typer_err("invalid base16 digit"))?;
        bytes.push(((hi << 4) | lo) as i8);
        i += 2;
    }
    Ok(TypedExpr::Constant {
        value: ConstPayload::ByteColl(bytes),
        tpe: coll_byte(),
    })
}

/// `fromBase58(s)` → `ByteArrayConstant(Base58.decode(s).get)`.  Bitcoin/Scorex
/// alphabet — `bs58::decode`'s default alphabet is byte-identical.  Bytes are
/// re-cast as signed `i8` (matching `ByteColl`).  Caller (the `"fromBase58"`
/// match arm) has already rejected any out-of-alphabet character via
/// [`is_base58_char`], so decode failure here would indicate a `bs58` internal
/// bug, not a user input error — mapped to `TyperError` defensively rather than
/// via `expect`, to avoid a panic on any unforeseen edge case.
fn decode_base58(s: &str) -> Result<TypedExpr, TyperError> {
    let bytes = bs58::decode(s)
        .into_vec()
        .map_err(|e| typer_err(format!("invalid base58 string: {e}")))?;
    Ok(TypedExpr::Constant {
        value: ConstPayload::ByteColl(bytes.into_iter().map(|b| b as i8).collect()),
        tpe: coll_byte(),
    })
}

/// `deserialize[T](s)` (SigmaPredef.scala:169-188, D-T2 CLOSED): Base58-decode
/// `s` (same alphabet/decoder as `fromBase58` — `Base58.decode(str).get`,
/// verdict-parity class deviation retained, same as `fromBase58`'s own
/// `AssertionError`↔`TyperError` mismatch), `ergo_ser::opcode::parse_expr` the
/// bytes as ONE general `Value` node (Scala doesn't check the byte count is
/// fully consumed either — `ValueSerializer.deserialize(bytes, pos=0)` just
/// stops after one node), [`unlower_expr`] it back to a `TypedExpr`, and
/// reject if the result's type disagrees with the declared `T`
/// (`res.tpe != tpe` → `InvalidArguments`, oracle-mirrored).
fn deserialize_predef(
    s: &str,
    target_tpe: &SType,
    tree_version: u8,
) -> Result<TypedExpr, TyperError> {
    let bytes = bs58::decode(s)
        .into_vec()
        .map_err(|e| typer_err(format!("deserialize: invalid Base58 string: {e}")))?;
    let mut r = VlqReader::new(&bytes);
    let op = parse_expr(&mut r, 0, tree_version)
        .map_err(|e| typer_err(format!("deserialize: malformed serialized value: {e:?}")))?;
    let typed = unlower_expr(&op).ok_or_else(|| {
        typer_err(
            "deserialize: the decoded value is a shape this compiler's opcode-IR reverse \
             mapping does not (yet) cover — supported: constants and the bare context/global \
             singleton primitives; composite expressions (BinOps, MethodCalls, …) are not"
                .to_string(),
        )
    })?;
    if crate::typed::node_tpe(&typed) != target_tpe {
        return Err(typer_err(format!(
            "deserialize: wrong type after deserialization, expected {target_tpe:?}, got {:?}",
            crate::typed::node_tpe(&typed)
        )));
    }
    Ok(typed)
}

/// Reverse of [`crate::emit::map_const`] plus the nine zero-payload
/// singleton primitives — the opcode-IR→`TypedExpr` mapping `deserialize`
/// needs (gap F6). `None` for anything else (composite expressions, or a
/// `Const` shape `ConstPayload` has no variant for).
fn unlower_expr(op: &OpExpr) -> Option<TypedExpr> {
    match op {
        OpExpr::Const { tpe, val } => {
            let (stype, payload) = unmap_const(tpe, val)?;
            Some(TypedExpr::Constant {
                value: payload,
                tpe: stype,
            })
        }
        OpExpr::Op(IrNode {
            opcode,
            payload: OpPayload::Zero,
        }) => match *opcode {
            0xA3 => Some(TypedExpr::Height { tpe: SType::SInt }),
            0xA4 => Some(TypedExpr::Inputs {
                tpe: SType::SColl(Box::new(SType::SBox)),
            }),
            0xA5 => Some(TypedExpr::Outputs {
                tpe: SType::SColl(Box::new(SType::SBox)),
            }),
            0xA7 => Some(TypedExpr::Self_ { tpe: SType::SBox }),
            0xAC => Some(TypedExpr::MinerPubkey {
                tpe: SType::SColl(Box::new(SType::SByte)),
            }),
            0xA6 => Some(TypedExpr::LastBlockUtxoRootHash {
                tpe: SType::SAvlTree,
            }),
            0xFE => Some(TypedExpr::Context {
                tpe: SType::SContext,
            }),
            0xDD => Some(TypedExpr::Global {
                tpe: SType::SGlobal,
            }),
            0x82 => Some(TypedExpr::GroupGenerator {
                tpe: SType::SGroupElement,
            }),
            _ => None,
        },
        _ => None,
    }
}

/// Reverse of [`crate::emit::map_const`]: an ergo-ser `(SigmaType, SigmaValue)`
/// pair back to a typed `(SType, ConstPayload)` pair. `None` for shapes
/// `ConstPayload` cannot represent — e.g. a materialized `Coll[Int]` or
/// `Coll[Boolean]` constant (only `Coll[Byte]`/`Coll[Long]` have dedicated
/// variants, mirroring `map_const`'s own coverage exactly) — the caller turns
/// that into a `TyperError` rather than silently mismapping it.
fn unmap_const(tpe: &WireType, val: &WireValue) -> Option<(SType, ConstPayload)> {
    match (tpe, val) {
        (WireType::SBoolean, WireValue::Boolean(b)) => {
            Some((SType::SBoolean, ConstPayload::Bool(*b)))
        }
        (WireType::SByte, WireValue::Byte(v)) => Some((SType::SByte, ConstPayload::Byte(*v))),
        (WireType::SShort, WireValue::Short(v)) => Some((SType::SShort, ConstPayload::Short(*v))),
        (WireType::SInt, WireValue::Int(v)) => Some((SType::SInt, ConstPayload::Int(*v))),
        (WireType::SLong, WireValue::Long(v)) => Some((SType::SLong, ConstPayload::Long(*v))),
        (WireType::SBigInt, WireValue::BigInt(v)) => {
            Some((SType::SBigInt, ConstPayload::BigInt(v.to_string())))
        }
        (WireType::SUnsignedBigInt, WireValue::BigInt(v)) => Some((
            SType::SUnsignedBigInt,
            ConstPayload::UnsignedBigInt(v.to_string()),
        )),
        (WireType::SString, WireValue::Str(s)) => {
            Some((SType::SString, ConstPayload::String(s.clone())))
        }
        (WireType::SUnit, WireValue::Unit) => Some((SType::SUnit, ConstPayload::Unit)),
        (WireType::SGroupElement, WireValue::GroupElement(ge)) => Some((
            SType::SGroupElement,
            ConstPayload::GroupElement(*group_element_bytes(ge)),
        )),
        // Mirrors `emit::map_const`'s `ConstPayload::ProveDlog` arm (the
        // binder PK-rule / P2PK-address shape) — closes the M4 Task 8 review
        // gap (D-C8 lockstep): `unmap_const` previously had no arm for
        // `SigmaValue::SigmaProp(SigmaBoolean::ProveDlog(_))`, so a
        // `deserialize[SigmaProp](...)` decoding a `ProveDlog` constant would
        // silently fall through to the `_ => None` reject instead of
        // reconstructing the payload `map_const` can re-emit byte-identically.
        // `SigmaBoolean::{Cand,Cor,Cthreshold,ProveDHTuple,TrivialProp}` have
        // no `ConstPayload` variant at all (mirrors `map_const`'s own
        // coverage — those shapes never appear as bare Constants on the wire
        // in this port) and correctly stay unmapped below.
        (WireType::SSigmaProp, WireValue::SigmaProp(SigmaBoolean::ProveDlog(ge))) => Some((
            SType::SSigmaProp,
            ConstPayload::ProveDlog(*group_element_bytes(ge)),
        )),
        (WireType::SColl(elem), WireValue::Coll(CollValue::Bytes(bytes)))
            if matches!(**elem, WireType::SByte) =>
        {
            Some((
                SType::SColl(Box::new(SType::SByte)),
                ConstPayload::ByteColl(bytes.iter().map(|b| *b as i8).collect()),
            ))
        }
        (WireType::SColl(elem), WireValue::Coll(CollValue::Values(items)))
            if matches!(**elem, WireType::SLong) =>
        {
            let mut longs = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    WireValue::Long(v) => longs.push(*v),
                    _ => return None,
                }
            }
            Some((
                SType::SColl(Box::new(SType::SLong)),
                ConstPayload::LongColl(longs),
            ))
        }
        _ => None,
    }
}

fn group_element_bytes(ge: &GroupElement) -> &[u8; 33] {
    ge.as_bytes()
}

/// `fromBase64(s)` → `ByteArrayConstant(Base64.getDecoder().decode(s))` via the
/// [`JAVA_BASE64`] engine (Java `getDecoder()` equivalence).  Bytes are re-cast
/// as signed `i8` (matching `ByteColl`).  Caller (the `"fromBase64"` match arm)
/// has already run [`validate_base64`], so decode failure here would indicate
/// an engine-config mismatch, not a user input error — mapped to `TyperError`
/// defensively rather than via `expect`.
fn decode_base64(s: &str) -> Result<TypedExpr, TyperError> {
    let bytes = JAVA_BASE64
        .decode(s)
        .map_err(|e| typer_err(format!("invalid base64 string: {e}")))?;
    Ok(TypedExpr::Constant {
        value: ConstPayload::ByteColl(bytes.into_iter().map(|b| b as i8).collect()),
        tpe: coll_byte(),
    })
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Returns `true` iff `c` is in the Scorex / Bitcoin Base58 alphabet:
/// `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`.
/// Excluded: `0`, `O`, `I`, `l` (visually ambiguous characters).
/// (SigmaPredef.scala:235 / scorex-util Base58$.Alphabet)
fn is_base58_char(c: char) -> bool {
    matches!(c,
        '1'..='9'
        | 'A'..='H' | 'J'..='N' | 'P'..='Z'   // skip 'I' and 'O'
        | 'a'..='k' | 'm'..='z'                // skip 'l'
    )
}

/// Java `Base64.getDecoder()`-equivalent decode engine: standard alphabet,
/// decode-time padding is optional (`DecodePaddingMode::Indifferent` — the
/// caller runs [`validate_base64`] first, which independently pins Java's
/// stricter *structural* padding rule: a padded string's total length must be
/// a multiple of 4), and non-zero trailing bits in the final quantum are
/// silently dropped rather than rejected (`with_decode_allow_trailing_bits`;
/// Java does NOT validate the low unused bits of the last symbol — e.g.
/// `"ab"` → `0x69`, discarding the dangling `0b1011`, oracle-confirmed
/// golden_seed.txt §17). Chosen empirically: `base64`'s default `STANDARD`
/// engine (`DecodePaddingMode::RequireCanonical`) rejects unpadded input
/// outright, which would wrongly reject `"ab"`/`"YWJj"`.
static JAVA_BASE64: base64::engine::GeneralPurpose = base64::engine::GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    base64::engine::GeneralPurposeConfig::new()
        .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(true),
);

/// Validates a string against the Java standard Base64 alphabet
/// (`java.util.Base64.getDecoder()` — `A-Za-z0-9+/` plus `=` padding).
///
/// Returns `Ok(())` if the string is a structurally valid base64 input
/// (all chars in alphabet; at most 2 trailing `=` signs; no interior `=`;
/// length % 4 ≠ 1; when padding is present, length must be a multiple of 4).
/// Returns `Err(msg)` otherwise, mirroring the `IllegalArgumentException`
/// that the Java decoder throws.
///
/// Oracle-confirmed (2026-07-04, ORACLE_TREE_VERSION=3):
///   `fromBase64("a=")` → REJECT (pad present, len 2, 2 % 4 ≠ 0)
///   `fromBase64("abcde=")` → REJECT (pad present, len 6, 6 % 4 ≠ 0)
///   `fromBase64("ab")` → OK (no padding, len 2, no structural check)
///
/// (SigmaPredef.scala:249 / `java.util.Base64.getDecoder().decode(s)`)
fn validate_base64(s: &str) -> Result<(), String> {
    for c in s.chars() {
        match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '+' | '/' | '=' => {}
            _ => return Err(format!("Illegal base64 character 0x{:02x}", c as u32)),
        }
    }
    // Validate padding: `=` only at the end, at most 2, no interior `=`.
    let trimmed = s.trim_end_matches('=');
    let pad_count = s.len() - trimmed.len();
    if pad_count > 2 {
        return Err("Too many padding chars in base64 string".to_string());
    }
    if trimmed.contains('=') {
        return Err("Interior '=' in base64 string".to_string());
    }
    // A single trailing character after all complete 4-char groups is undecodable.
    if s.len() % 4 == 1 {
        return Err(format!(
            "Invalid base64 string length: {} (remainder 1 is undecodable)",
            s.len()
        ));
    }
    // Java's decoder rejects padded strings whose total length is not a multiple of 4.
    // e.g. "a=" (len 2) and "abcde=" (len 6) → IllegalArgumentException.
    // Unpadded strings (pad_count == 0) are not subject to this check ("ab" ACCEPTS).
    if pad_count > 0 && !s.len().is_multiple_of(4) {
        return Err(format!(
            "Invalid base64 string length: {} (padding present but length is not a multiple of 4)",
            s.len()
        ));
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::typed_print::print_typed;

    // ----- helpers -----

    fn ident(name: &str, dom: Vec<SType>, range: SType) -> TypedExpr {
        TypedExpr::Ident {
            name: name.to_string(),
            tpe: func(dom, range),
        }
    }
    fn byte_const(v: i8) -> TypedExpr {
        TypedExpr::Constant {
            value: ConstPayload::Byte(v),
            tpe: SType::SByte,
        }
    }
    fn str_const(s: &str) -> TypedExpr {
        TypedExpr::Constant {
            value: ConstPayload::String(s.to_string()),
            tpe: SType::SString,
        }
    }
    fn bytecoll(v: Vec<i8>) -> TypedExpr {
        TypedExpr::Constant {
            value: ConstPayload::ByteColl(v),
            tpe: coll_byte(),
        }
    }

    // ----- happy path — env -----

    #[test]
    fn predefined_env_has_core_global_funcs() {
        let env = predefined_env(3);
        for n in [
            "sigmaProp",
            "allOf",
            "atLeast",
            "getVar",
            "proveDlog",
            "blake2b256",
            "substConstants",
            "deserializeTo",
        ] {
            assert!(env.contains_key(n), "missing predef func {n}");
        }
        // Operator symbols are elided (never appear as Idents).
        assert!(!env.contains_key("+"));
        assert!(!env.contains_key("=="));
    }

    #[test]
    fn predefined_env_getvar_declaration_is_byte_to_option_t() {
        let env = predefined_env(3);
        // getVar is polymorphic: its SFunc carries the `[T]` binder (wave-B shape fix)
        // so a bare `getVar` prints `[T](Byte) => Option[T]`.
        assert_eq!(
            env.get("getVar"),
            Some(&SType::SFunc {
                dom: vec![SType::SByte],
                range: Box::new(opt(tv("T"))),
                tpe_params: vec!["T".to_string()],
            })
        );
    }

    // ----- happy path — irBuilder lowerings (SigmaPredef.scala cites inline) -----

    /// sigmaProp → BoolToSigmaProp (SigmaPredef.scala:134).
    #[test]
    fn sigma_prop_lowers_to_bool_to_sigma_prop() {
        let f = ident("sigmaProp", vec![SType::SBoolean], SType::SSigmaProp);
        let b = TypedExpr::Constant {
            value: ConstPayload::Bool(true),
            tpe: SType::SBoolean,
        };
        let out = predef_ir_builder("sigmaProp", &f, &[b], 3)
            .unwrap()
            .unwrap();
        assert!(matches!(out, TypedExpr::BoolToSigmaProp { .. }));
        assert_eq!(crate::typed::node_tpe(&out), &SType::SSigmaProp);
    }

    /// B3: `sigmaProp(<SigmaProp arg>)` wraps the arg directly in BoolToSigmaProp
    /// (the `@unchecked` irBuilder), producing the oracle's nested double-wrap — NOT a
    /// SigmaPropIsProven coercion.
    #[test]
    fn sigma_prop_of_sigma_prop_arg_double_wraps() {
        let f = ident("sigmaProp", vec![SType::SBoolean], SType::SSigmaProp);
        let inner = TypedExpr::BoolToSigmaProp {
            value: Box::new(TypedExpr::Constant {
                value: ConstPayload::Bool(true),
                tpe: SType::SBoolean,
            }),
            tpe: SType::SSigmaProp,
        };
        let out = predef_ir_builder("sigmaProp", &f, &[inner], 3)
            .unwrap()
            .unwrap();
        assert_eq!(
            print_typed(&out),
            "(BoolToSigmaProp:SigmaProp (BoolToSigmaProp:SigmaProp (ConstantNode:Boolean @true)))"
        );
    }

    /// B2: xorOf's `@unchecked` irBuilder fires for ANY single `Coll[_]` arg — a
    /// `Coll[SigmaProp]` lowers to XorOf directly (no isProven wrap).  A non-Coll arg
    /// falls through (None) so the enclosing arg-type check rejects.
    #[test]
    fn xor_of_lowers_any_coll_elem_type() {
        let f = ident("xorOf", vec![coll(SType::SBoolean)], SType::SBoolean);
        // Coll[SigmaProp] → XorOf (the un-adapted SigmaProp collection is the input).
        let sp_coll = TypedExpr::ConcreteCollection {
            items: vec![TypedExpr::BoolToSigmaProp {
                value: Box::new(TypedExpr::Constant {
                    value: ConstPayload::Bool(true),
                    tpe: SType::SBoolean,
                }),
                tpe: SType::SSigmaProp,
            }],
            elem_type: SType::SSigmaProp,
            tpe: coll(SType::SSigmaProp),
        };
        let out = predef_ir_builder("xorOf", &f, &[sp_coll], 3)
            .unwrap()
            .unwrap();
        assert_eq!(
            print_typed(&out),
            "(XorOf:Boolean (ConcreteCollection:Coll[SigmaProp] [(BoolToSigmaProp:SigmaProp (ConstantNode:Boolean @true))] #SigmaProp))"
        );
        // Non-Coll arg → None (falls through; the assign layer surfaces the type error).
        let non_coll = TypedExpr::Constant {
            value: ConstPayload::Bool(true),
            tpe: SType::SBoolean,
        };
        assert!(predef_ir_builder("xorOf", &f, &[non_coll], 3).is_none());
    }

    /// blake2b256 → CalcBlake2b256 (SigmaPredef.scala:263).
    #[test]
    fn blake2b256_lowers_to_calc_blake() {
        let f = ident("blake2b256", vec![coll_byte()], coll_byte());
        let out = predef_ir_builder("blake2b256", &f, &[bytecoll(vec![1, 2])], 3)
            .unwrap()
            .unwrap();
        assert_eq!(
            print_typed(&out),
            "(CalcBlake2b256:Coll[Byte] (ConstantNode:Coll[Byte] <@1 @2>))"
        );
    }

    /// getVar → GetVar carrying the type arg from the callee's SFunc range
    /// (SigmaPredef.scala:394-395).
    #[test]
    fn get_var_lowers_to_getvar_with_type_arg() {
        let f = ident("getVar", vec![SType::SByte], opt(SType::SInt));
        let out = predef_ir_builder("getVar", &f, &[byte_const(1)], 3)
            .unwrap()
            .unwrap();
        assert_eq!(print_typed(&out), "(GetVar:Option[Int] @1)");
    }

    /// getVar isDefinedAt is false for a non-constant id → fall-through (None).
    #[test]
    fn get_var_non_constant_id_falls_through() {
        let f = ident("getVar", vec![SType::SByte], opt(SType::SInt));
        let non_const = TypedExpr::Ident {
            name: "x".to_string(),
            tpe: SType::SByte,
        };
        assert!(predef_ir_builder("getVar", &f, &[non_const], 3).is_none());
    }

    /// executeFromVar → DeserializeContext (SigmaPredef.scala:405-406).
    #[test]
    fn execute_from_var_lowers_to_deserialize_context() {
        let f = ident("executeFromVar", vec![SType::SByte], SType::SInt);
        let out = predef_ir_builder("executeFromVar", &f, &[byte_const(1)], 3)
            .unwrap()
            .unwrap();
        assert_eq!(print_typed(&out), "(DeserializeContext:Int @1)");
    }

    /// executeFromSelfReg out-of-range index → Err (InvalidArguments/TyperException).
    #[test]
    fn execute_from_self_reg_out_of_range_errors() {
        let f = ident("executeFromSelfReg", vec![SType::SInt], SType::SInt);
        let id = TypedExpr::Constant {
            value: ConstPayload::Int(99),
            tpe: SType::SInt,
        };
        let res = predef_ir_builder("executeFromSelfReg", &f, &[id], 3).unwrap();
        assert!(res.is_err());
    }

    /// deserializeTo → MethodCall(Global, …, {T->resType}) (SigmaPredef.scala:470-477).
    #[test]
    fn deserialize_to_lowers_to_global_method_call() {
        let f = ident("deserializeTo", vec![coll_byte()], SType::SLong);
        let out = predef_ir_builder("deserializeTo", &f, &[bytecoll(vec![1, 2])], 3)
            .unwrap()
            .unwrap();
        assert_eq!(
            print_typed(&out),
            "(MethodCall:Long (Global:SigmaDslBuilder) %SigmaDslBuilder.deserializeTo [(ConstantNode:Coll[Byte] <@1 @2>)] {#T->#Long})"
        );
    }

    /// bigInt → BigIntConstant (SigmaPredef.scala:193-194).
    #[test]
    fn big_int_parses_decimal_literal() {
        let f = ident("bigInt", vec![SType::SString], SType::SBigInt);
        let out = predef_ir_builder("bigInt", &f, &[str_const("12345678901234567890")], 3)
            .unwrap()
            .unwrap();
        assert_eq!(
            print_typed(&out),
            "(ConstantNode:BigInt (CBigInt @12345678901234567890))"
        );
    }

    /// bigInt on a non-numeric string throws (SigmaPredef.scala:194 NumberFormatException).
    #[test]
    fn big_int_non_numeric_errors() {
        let f = ident("bigInt", vec![SType::SString], SType::SBigInt);
        let res = predef_ir_builder("bigInt", &f, &[str_const("notanumber")], 3).unwrap();
        assert!(res.is_err());
    }

    /// fromBase16 → ByteArrayConstant, bytes as signed i8 (SigmaPredef.scala:221).
    #[test]
    fn from_base16_decodes_hex_to_signed_bytes() {
        let f = ident("fromBase16", vec![SType::SString], coll_byte());
        let out = predef_ir_builder("fromBase16", &f, &[str_const("deadbeef")], 3)
            .unwrap()
            .unwrap();
        assert_eq!(
            print_typed(&out),
            "(ConstantNode:Coll[Byte] <@-34 @-83 @-66 @-17>)"
        );
    }

    // ----- error paths / fall-through -----

    /// `deserialize` without an explicit `[T]` REJECTs `InvalidArguments`
    /// (oracle-confirmed 2026-07-07: `deserialize("Jq") == 5` → `REJECT 0:0
    /// InvalidArguments`) — the range stays an unresolved type var, same gate
    /// as `deserializeTo`/`fromBigEndianBytes`'s `global_deserialize`.
    #[test]
    fn deserialize_without_explicit_type_arg_errors() {
        let f = ident("deserialize", vec![SType::SString], tv("T"));
        assert!(predef_ir_builder("deserialize", &f, &[str_const("Jq")], 3)
            .unwrap()
            .is_err());
    }

    /// `deserialize[Int]("Jq")` → `ConstantNode:Int @5` (oracle-confirmed
    /// 2026-07-07 ×2: bytes `04 0a` = `IntConstant(5)`; `"Jq"` is that pair's
    /// Base58 encoding).
    #[test]
    fn deserialize_constant_folds_to_typed_constant() {
        let f = ident("deserialize", vec![SType::SString], SType::SInt);
        let out = predef_ir_builder("deserialize", &f, &[str_const("Jq")], 3)
            .unwrap()
            .unwrap();
        assert_eq!(
            out,
            TypedExpr::Constant {
                value: ConstPayload::Int(5),
                tpe: SType::SInt,
            }
        );
    }

    /// `deserialize[Int]("3p")` → bare `Height` (oracle-confirmed 2026-07-07:
    /// byte `a3` is the bare `Height` opcode) — a genuinely NON-constant,
    /// runtime node, not just a constant-folding shortcut.
    #[test]
    fn deserialize_non_constant_singleton_embeds_the_node() {
        let f = ident("deserialize", vec![SType::SString], SType::SInt);
        let out = predef_ir_builder("deserialize", &f, &[str_const("3p")], 3)
            .unwrap()
            .unwrap();
        assert_eq!(out, TypedExpr::Height { tpe: SType::SInt });
    }

    /// Invalid Base58 char → `TyperError` (Scala: `Base58.decode(str).get` →
    /// `AssertionError`; verdict-parity class deviation, same discipline as
    /// `fromBase58`'s own reject).
    #[test]
    fn deserialize_invalid_base58_char_errors() {
        let f = ident("deserialize", vec![SType::SString], SType::SInt);
        assert!(
            predef_ir_builder("deserialize", &f, &[str_const("not-base58!!!")], 3)
                .unwrap()
                .is_err()
        );
    }

    /// Malformed (truncated) ValueSerializer bytes → `TyperError` (Scala:
    /// `BufferUnderflowException`, oracle-confirmed 2026-07-07).
    #[test]
    fn deserialize_malformed_bytes_errors() {
        // Base58 of a single 0x04 byte: a lone SInt type tag with no value
        // data to follow — `parse_expr` must run out of input mid-value.
        let s = bs58::encode([0x04u8]).into_string();
        let f = ident("deserialize", vec![SType::SString], SType::SInt);
        assert!(predef_ir_builder("deserialize", &f, &[str_const(&s)], 3)
            .unwrap()
            .is_err());
    }

    /// A declared type disagreeing with the decoded value's type REJECTs
    /// (Scala: `res.tpe != tpe` → `InvalidArguments`).
    #[test]
    fn deserialize_type_mismatch_errors() {
        // "Jq" decodes to an Int constant; declaring [Boolean] must reject.
        let f = ident("deserialize", vec![SType::SString], SType::SBoolean);
        assert!(predef_ir_builder("deserialize", &f, &[str_const("Jq")], 3)
            .unwrap()
            .is_err());
    }

    /// A shape `unlower_expr` does not cover (a composite expression — here a
    /// `GT` relation over two Height/Const nodes) rejects with a descriptive
    /// error rather than silently mismapping (probe-bounded scope: gap F6
    /// covers constants + the nine singleton primitives only).
    #[test]
    fn deserialize_composite_expression_rejects_honestly() {
        // Base58 of `HEIGHT > 0`: `d1 91 a3 04 00` — Height(0xa3) is covered,
        // but the enclosing GT(0x91)/BoolToSigmaProp(0xd1) wrapper is not.
        let bytes = [0xd1u8, 0x91, 0xa3, 0x04, 0x00];
        let s = bs58::encode(bytes).into_string();
        let f = ident("deserialize", vec![SType::SString], SType::SSigmaProp);
        assert!(predef_ir_builder("deserialize", &f, &[str_const(&s)], 3)
            .unwrap()
            .is_err());
    }

    // ----- fromBase58 / fromBase64 canonical decode (oracle §17, D-T2 closed) -----

    /// `fromBase58("")` → empty `ByteArrayConstant` (Scorex empty = BigInt(0) =
    /// emptyByteArray). Oracle §17: `OK (ConstantNode:Coll[Byte] <>)`.
    #[test]
    fn from_base58_empty_decodes_to_empty_byte_coll() {
        let f = ident("fromBase58", vec![SType::SString], coll_byte());
        let out = predef_ir_builder("fromBase58", &f, &[str_const("")], 3)
            .expect("isDefinedAt true for valid Base58 (empty)")
            .expect("valid Base58 literal must decode");
        assert_eq!(print_typed(&out), "(ConstantNode:Coll[Byte] <>)");
    }

    /// `fromBase64("")` → empty `ByteArrayConstant` (Java decoder: empty input
    /// = empty output). Oracle §17: `OK (ConstantNode:Coll[Byte] <>)`.
    #[test]
    fn from_base64_empty_decodes_to_empty_byte_coll() {
        let f = ident("fromBase64", vec![SType::SString], coll_byte());
        let out = predef_ir_builder("fromBase64", &f, &[str_const("")], 3)
            .expect("isDefinedAt true for valid Base64 (empty)")
            .expect("valid Base64 literal must decode");
        assert_eq!(print_typed(&out), "(ConstantNode:Coll[Byte] <>)");
    }

    /// `fromBase64("YWJj")` → decodes `"abc"`. Oracle §17:
    /// `OK (ConstantNode:Coll[Byte] <@97 @98 @99>)`.
    #[test]
    fn from_base64_ywjj_decodes_abc() {
        let f = ident("fromBase64", vec![SType::SString], coll_byte());
        let out = predef_ir_builder("fromBase64", &f, &[str_const("YWJj")], 3)
            .expect("isDefinedAt true for valid Base64")
            .expect("valid Base64 literal must decode");
        assert_eq!(print_typed(&out), "(ConstantNode:Coll[Byte] <@97 @98 @99>)");
    }

    // ----- fromBase58 / fromBase64 validation (oracle §17) -----

    /// `fromBase58("$reserveContractHash")` → Err (Scorex: AssertionError "Wrong char
    /// in Base58 string"; oracle §17 class = AssertionError, non-reproducible per D-T2).
    #[test]
    fn from_base58_dollar_char_rejects() {
        let f = ident("fromBase58", vec![SType::SString], coll_byte());
        let res = predef_ir_builder("fromBase58", &f, &[str_const("$reserveContractHash")], 3)
            .expect("isDefinedAt true for invalid Base58 char");
        assert!(res.is_err(), "invalid Base58 char must error");
    }

    /// `fromBase58("0")` → Err (Scorex: '0' not in Base58 alphabet, same path).
    #[test]
    fn from_base58_zero_digit_rejects() {
        let f = ident("fromBase58", vec![SType::SString], coll_byte());
        let res = predef_ir_builder("fromBase58", &f, &[str_const("0")], 3)
            .expect("isDefinedAt true for '0'");
        assert!(res.is_err(), "'0' not in Base58 alphabet");
    }

    /// `fromBase64("$bankNFT")` → Err (Java: IllegalArgumentException; oracle §17
    /// class = IllegalArgumentException, non-reproducible per D-T2).
    #[test]
    fn from_base64_dollar_char_rejects() {
        let f = ident("fromBase64", vec![SType::SString], coll_byte());
        let res = predef_ir_builder("fromBase64", &f, &[str_const("$bankNFT")], 3)
            .expect("isDefinedAt true for invalid Base64 char");
        assert!(res.is_err(), "invalid Base64 char must error");
    }

    /// `fromBase64("abc!")` → Err ('!' not in standard Base64 alphabet; oracle §17).
    #[test]
    fn from_base64_bang_char_rejects() {
        let f = ident("fromBase64", vec![SType::SString], coll_byte());
        let res = predef_ir_builder("fromBase64", &f, &[str_const("abc!")], 3)
            .expect("isDefinedAt true for '!'");
        assert!(res.is_err(), "'!' not in Base64 alphabet");
    }

    /// `fromBase64("RWT_REPO_NFT")` → Err ('_' not in STANDARD base64; oracle §17).
    /// URL-safe base64 uses '_', but `java.util.Base64.getDecoder()` is STANDARD.
    #[test]
    fn from_base64_underscore_rejects() {
        let f = ident("fromBase64", vec![SType::SString], coll_byte());
        let res = predef_ir_builder("fromBase64", &f, &[str_const("RWT_REPO_NFT")], 3)
            .expect("isDefinedAt true for '_'");
        assert!(res.is_err(), "'_' not in standard Base64 alphabet");
    }

    // ----- fromBase64 structural padding validation (oracle §17) -----

    /// `fromBase64("a=")` → Err: padding present but len 2, not a multiple of 4.
    /// Oracle (2026-07-04, ORACLE_TREE_VERSION=3, fresh-JVM):
    ///   `fromBase64("a=")` → REJECT 0:0 IllegalArgumentException
    /// Java's `Base64.getDecoder().decode("a=")` throws because length 2 ≢ 0 (mod 4).
    #[test]
    fn from_base64_padded_wrong_length_rejects() {
        let f = ident("fromBase64", vec![SType::SString], coll_byte());
        let res = predef_ir_builder("fromBase64", &f, &[str_const("a=")], 3)
            .expect("isDefinedAt true for padded input");
        assert!(
            res.is_err(),
            "\"a=\" has padding but len 2, not a multiple of 4"
        );
    }

    /// `fromBase64("abcde=")` → Err: padding present but len 6, not a multiple of 4.
    /// Oracle (2026-07-04, ORACLE_TREE_VERSION=3, fresh-JVM):
    ///   `fromBase64("abcde=")` → REJECT 0:0 IllegalArgumentException
    #[test]
    fn from_base64_padded_length_six_rejects() {
        let f = ident("fromBase64", vec![SType::SString], coll_byte());
        let res = predef_ir_builder("fromBase64", &f, &[str_const("abcde=")], 3)
            .expect("isDefinedAt true for padded input");
        assert!(
            res.is_err(),
            "\"abcde=\" has padding but len 6, not a multiple of 4"
        );
    }

    /// `fromBase64("ab")` → decodes to a single byte (unpadded, no length-mod-4
    /// check; 2 data chars decode to 1 byte, Java drops the 4 dangling low bits
    /// of the last quantum). Oracle (2026-07-04, ORACLE_TREE_VERSION=3, fresh-JVM):
    ///   `fromBase64("ab")` → OK (ConstantNode:Coll[Byte] <@105>)
    #[test]
    fn from_base64_unpadded_short_decodes_dropping_trailing_bits() {
        let f = ident("fromBase64", vec![SType::SString], coll_byte());
        let out = predef_ir_builder("fromBase64", &f, &[str_const("ab")], 3)
            .expect("isDefinedAt true for valid Base64 (unpadded, len 2)")
            .expect("\"ab\" is structurally valid base64; must decode");
        assert_eq!(print_typed(&out), "(ConstantNode:Coll[Byte] <@105>)");
    }

    /// An unknown name has no irBuilder → None.
    #[test]
    fn unknown_name_returns_none() {
        let f = ident("nope", vec![SType::SInt], SType::SInt);
        assert!(predef_ir_builder("nope", &f, &[byte_const(1)], 3).is_none());
    }

    // ----- unsignedBigInt validation (oracle §13) -----

    /// `unsignedBigInt("-5")` → Err (Scala: InvalidArguments; oracle §13).
    #[test]
    fn unsigned_big_int_negative_rejects() {
        let f = ident(
            "unsignedBigInt",
            vec![SType::SString],
            SType::SUnsignedBigInt,
        );
        let res = predef_ir_builder("unsignedBigInt", &f, &[str_const("-5")], 3)
            .expect("isDefinedAt true for negative literal");
        assert!(res.is_err(), "negative unsignedBigInt must error");
    }

    /// `unsignedBigInt("5")` → `ConstantNode:UnsignedBigInt (CUnsignedBigInt @5)`
    /// (D-T3 CLOSED, M3 Task-6; oracle §13/§24).
    #[test]
    fn unsigned_big_int_non_negative_builds_constant() {
        let f = ident(
            "unsignedBigInt",
            vec![SType::SString],
            SType::SUnsignedBigInt,
        );
        let out = predef_ir_builder("unsignedBigInt", &f, &[str_const("5")], 3)
            .expect("isDefinedAt true for non-negative literal")
            .expect("valid unsignedBigInt literal must build a constant");
        assert_eq!(
            print_typed(&out),
            "(ConstantNode:UnsignedBigInt (CUnsignedBigInt @5))"
        );
    }

    /// `unsignedBigInt("-0")` / `("-0000")` ACCEPT as `@0` — Scala parses
    /// FIRST and rejects only `signum() < 0`, and `BigInteger("-0").signum()
    /// == 0` (oracle: `tc unsignedBigInt("-0")` → `OK
    /// (ConstantNode:UnsignedBigInt (CUnsignedBigInt @0))`, golden_seed.txt
    /// §24(g), captured 2026-07-07 ×3 runs).
    #[test]
    fn unsigned_big_int_negative_zero_accepts_as_zero() {
        let f = ident(
            "unsignedBigInt",
            vec![SType::SString],
            SType::SUnsignedBigInt,
        );
        for lit in ["-0", "-0000"] {
            let out = predef_ir_builder("unsignedBigInt", &f, &[str_const(lit)], 3)
                .expect("isDefinedAt true")
                .unwrap_or_else(|e| panic!("{lit}: signum-0 literal must accept: {e:?}"));
            assert_eq!(
                print_typed(&out),
                "(ConstantNode:UnsignedBigInt (CUnsignedBigInt @0))",
                "{lit}"
            );
        }
    }

    /// `unsignedBigInt("0005")` canonicalizes leading zeros → `@5` (oracle-verified,
    /// golden_seed.txt §24, D-T3).
    #[test]
    fn unsigned_big_int_canonicalizes_leading_zeros() {
        let f = ident(
            "unsignedBigInt",
            vec![SType::SString],
            SType::SUnsignedBigInt,
        );
        let out = predef_ir_builder("unsignedBigInt", &f, &[str_const("0005")], 3)
            .expect("isDefinedAt true")
            .expect("valid literal must build a constant");
        assert_eq!(
            print_typed(&out),
            "(ConstantNode:UnsignedBigInt (CUnsignedBigInt @5))"
        );
    }

    /// `unsignedBigInt` caps at 256 bits UNCONDITIONALLY (no `tree_version` gate,
    /// unlike `bigInt`'s 255-bit cap) — oracle §24: `2^256-1` accepts, `2^256`
    /// rejects, at BOTH v2 and v3.
    #[test]
    fn unsigned_big_int_caps_at_256_bits_unconditionally() {
        let f = ident(
            "unsignedBigInt",
            vec![SType::SString],
            SType::SUnsignedBigInt,
        );
        let max_256 =
            "115792089237316195423570985008687907853269984665640564039457584007913129639935";
        let over_256 =
            "115792089237316195423570985008687907853269984665640564039457584007913129639936";
        for tree_version in [2u8, 3u8] {
            let out = predef_ir_builder("unsignedBigInt", &f, &[str_const(max_256)], tree_version)
                .expect("isDefinedAt true")
                .expect("2^256-1 must fit");
            assert_eq!(
                print_typed(&out),
                format!("(ConstantNode:UnsignedBigInt (CUnsignedBigInt @{max_256}))")
            );
            let res = predef_ir_builder("unsignedBigInt", &f, &[str_const(over_256)], tree_version)
                .expect("isDefinedAt true");
            assert!(res.is_err(), "2^256 must be rejected (256-bit cap)");
        }
    }

    /// `bigInt` caps at 255 bits ONLY at `tree_version >= 3` — oracle §24:
    /// `bigInt(2^1000)` accepts at v2, rejects (ArithmeticException) at v3.
    #[test]
    fn big_int_cap_is_version_gated() {
        let f = ident("bigInt", vec![SType::SString], SType::SBigInt);
        let huge_2_pow_1000 = num_bigint::BigUint::from(2u32).pow(1000).to_string();
        let v2 = predef_ir_builder("bigInt", &f, &[str_const(&huge_2_pow_1000)], 2)
            .expect("isDefinedAt true")
            .expect("2^1000 must accept at tree_version 2 (no cap pre-v3)");
        // Oracle-pinned: the verbatim ORACLE_TREE_VERSION=2 reply captured in
        // golden_seed.txt §24(f) (comment block — the accepts-at-v2/rejects-at-v3
        // direction has no swept-record convention, so the byte assertion lives
        // here instead of the sweep).
        let oracle_v2_reply = "(ConstantNode:BigInt (CBigInt @10715086071862673209484250490600018105614048117055336074437503883703510511249361224931983788156958581275946729175531468251871452856923140435984577574698574803934567774824230985421074605062371141877954182153046474983581941267398767559165543946077062914571196477686542167660429831652624386837205668069376))";
        assert_eq!(
            crate::typed_print::print_typed(&v2),
            oracle_v2_reply,
            "v2 typed output must byte-match the §24(f) oracle capture"
        );
        let res = predef_ir_builder("bigInt", &f, &[str_const(&huge_2_pow_1000)], 3)
            .expect("isDefinedAt true");
        assert!(res.is_err(), "2^1000 must be rejected at v3 (255-bit cap)");
    }

    /// `bigInt("0005")` canonicalizes leading zeros → `@5` (oracle-verified,
    /// golden_seed.txt §24, D-T3).
    #[test]
    fn big_int_canonicalizes_leading_zeros() {
        let f = ident("bigInt", vec![SType::SString], SType::SBigInt);
        let out = predef_ir_builder("bigInt", &f, &[str_const("0005")], 3)
            .expect("isDefinedAt true")
            .expect("valid literal must build a constant");
        assert_eq!(print_typed(&out), "(ConstantNode:BigInt (CBigInt @5))");
    }

    /// `bigInt` at the 255-bit boundary: `2^255-1` accepts, `2^255` rejects,
    /// `-2^255` accepts (two's-complement `bitLength` == 255, since 2^255 is a
    /// power of two), `-(2^255+1)` rejects — oracle-verified, golden_seed.txt §24.
    #[test]
    fn big_int_255_bit_boundary() {
        let f = ident("bigInt", vec![SType::SString], SType::SBigInt);
        const MAX_POS: &str =
            "57896044618658097711785492504343953926634992332820282019728792003956564819967"; // 2^255-1
        const OVER_POS: &str =
            "57896044618658097711785492504343953926634992332820282019728792003956564819968"; // 2^255
        const OVER_POS_PLUS_ONE: &str =
            "57896044618658097711785492504343953926634992332820282019728792003956564819969"; // 2^255+1

        let out = predef_ir_builder("bigInt", &f, &[str_const(MAX_POS)], 3)
            .expect("isDefinedAt true")
            .expect("2^255-1 must fit");
        assert_eq!(
            print_typed(&out),
            format!("(ConstantNode:BigInt (CBigInt @{MAX_POS}))")
        );
        let res =
            predef_ir_builder("bigInt", &f, &[str_const(OVER_POS)], 3).expect("isDefinedAt true");
        assert!(res.is_err(), "2^255 must be rejected");

        let min_neg = format!("-{OVER_POS}"); // -2^255
        let out = predef_ir_builder("bigInt", &f, &[str_const(&min_neg)], 3)
            .expect("isDefinedAt true")
            .expect("-2^255 must fit (bitLength 255, power-of-two special case)");
        assert_eq!(
            print_typed(&out),
            format!("(ConstantNode:BigInt (CBigInt @-{OVER_POS}))")
        );
        let over_neg = format!("-{OVER_POS_PLUS_ONE}"); // -(2^255+1)
        let res =
            predef_ir_builder("bigInt", &f, &[str_const(&over_neg)], 3).expect("isDefinedAt true");
        assert!(res.is_err(), "-(2^255+1) must be rejected");
    }

    // ----- round-trips -----

    /// A valid on-curve secp256k1 point (the standard generator) for the
    /// `GroupElement`/`ProveDlog` round-trip cases below — reuses the same
    /// x-coordinate `emit.rs`'s `generator_ge()` test helper does.
    fn generator_ge_bytes() -> [u8; 33] {
        let mut bytes = [0u8; 33];
        bytes[0] = 0x02;
        let x = hex::decode("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
            .expect("valid hex");
        bytes[1..].copy_from_slice(&x);
        bytes
    }

    /// D-C8 drift guard (M4 Task 8 review): `emit::map_const` and this
    /// module's `unmap_const` must stay exact inverses over every
    /// `ConstPayload` variant `map_const` can actually emit. The review found
    /// `unmap_const` silently missing the `ProveDlog` arm (now fixed above) —
    /// this test sweeps every OTHER variant too so a future `ConstPayload`
    /// addition can't reintroduce the same silent one-sided gap.
    /// `ConstPayload::SigmaProp` is deliberately excluded — see
    /// `map_const_rejects_opaque_sigma_prop_no_roundtrip_possible` below for
    /// why it is not a gap.
    #[test]
    fn map_const_unmap_const_roundtrips_every_variant() {
        let ge_bytes = generator_ge_bytes();
        let cases: Vec<(ConstPayload, SType)> = vec![
            (ConstPayload::Bool(true), SType::SBoolean),
            (ConstPayload::Byte(-3), SType::SByte),
            (ConstPayload::Short(300), SType::SShort),
            (ConstPayload::Int(42), SType::SInt),
            (ConstPayload::Long(-7), SType::SLong),
            (ConstPayload::BigInt("12345".to_string()), SType::SBigInt),
            (
                ConstPayload::UnsignedBigInt("12345".to_string()),
                SType::SUnsignedBigInt,
            ),
            (ConstPayload::String("abc".to_string()), SType::SString),
            (ConstPayload::Unit, SType::SUnit),
            (
                ConstPayload::ByteColl(vec![-1, 2]),
                SType::SColl(Box::new(SType::SByte)),
            ),
            (
                ConstPayload::LongColl(vec![1, -2]),
                SType::SColl(Box::new(SType::SLong)),
            ),
            (ConstPayload::GroupElement(ge_bytes), SType::SGroupElement),
            (ConstPayload::ProveDlog(ge_bytes), SType::SSigmaProp),
        ];

        for (payload, tpe) in cases {
            let (wire_tpe, wire_val) = crate::emit::map_const(&payload, &tpe)
                .unwrap_or_else(|e| panic!("map_const({payload:?}) failed: {e:?}"));
            let (round_tpe, round_payload) = unmap_const(&wire_tpe, &wire_val)
                .unwrap_or_else(|| panic!("unmap_const has no inverse arm for {payload:?}"));
            assert_eq!(round_tpe, tpe, "type mismatch round-tripping {payload:?}");
            assert_eq!(
                round_payload, payload,
                "payload mismatch round-tripping {payload:?}"
            );
        }
    }

    /// `ConstPayload::SigmaProp` is the one variant EXCLUDED from the sweep
    /// above: it is an opaque env-injected proposition label with no curve
    /// bytes, and `map_const` itself refuses to emit it
    /// (`EmitError::UnsupportedNode`) — no wire bytes carrying this shape
    /// ever exist for `unmap_const` to invert. Pinned here so this stays a
    /// documented, verified non-round-trip rather than a silent gap.
    #[test]
    fn map_const_rejects_opaque_sigma_prop_no_roundtrip_possible() {
        let err = crate::emit::map_const(
            &ConstPayload::SigmaProp("p1".to_string()),
            &SType::SSigmaProp,
        )
        .expect_err("opaque SigmaProp must not be emittable");
        assert!(matches!(err, crate::emit::EmitError::UnsupportedNode(_)));
    }
}
