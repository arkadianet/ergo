//! Typed ErgoScript AST → `ergo-ser` opcode IR (backend emission, part I).
//!
//! M3 Task 7 scope: the type map ([`map_type`]), the constant map
//! ([`map_const`]), and every FIXED-ARITY opcode arm of [`emit`] — context
//! singletons, relations, arithmetic/bit/boolean operators, collection
//! transformers, sigma combinators, crypto primitives, option/context access.
//! Binding forms (`Block`/`ValNode`/`Ident`/`Lambda`/`Apply`/`Select`/
//! `MethodCall`) are M3 Task 8 and return [`EmitError::UnsupportedNode`] here.
//!
//! Opcode bytes come from the `opcode_pattern` dispatch table
//! (`ergo-ser/src/opcode/types.rs:276-436`), which is the crate's consensus
//! contract with Scala `ValueSerializer`/`OpCodes.scala` (sigma-state 6.0.2).
//! Payload shapes follow `dev-docs/ergoscript-compiler-m3-recon/recon-ergoser-ir.md`.
//!
//! # Boolean constants — byte-shape intel for Task 9/10 (oracle-captured)
//!
//! Live TyperOracle captures (sigma-state 6.0.2, 2026-07-05, `cc` verb):
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
//! with no True/False special-casing; the Task 9/10 segregation transform
//! turns inline constants into table entries. The captures also pin the
//! default P2S tree header `0x10` (version 0 + constant-segregation bit).
//! (Note: the Task-1 review notes mislabeled the `sigmaProp(HEIGHT > 100)`
//! bytes as the `sigmaProp(true)` reply; the three-way capture above
//! disambiguates.)
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
//! `ConstPayload` variant produces one at Task 7 (`Global.none[T]()` lowers
//! to a MethodCall — Task 8).

use ergo_primitives::group_element::GroupElement;
use ergo_ser::opcode::{Expr, IrNode, Payload};
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::{CollValue, SigmaBoolean, SigmaValue};

use crate::stype::SType;
use crate::typed::{ConstPayload, TypedExpr};

/// Emission failure. Every variant is a COMPILER bug surface, not a user
/// error: the typer guarantees the invariants these errors report (no
/// `NoType` in output, no pre-typed nodes, payloads matching node types), so
/// the variants are typed and spanless.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EmitError {
    /// A compiler-internal type (`NoType`, `STypeApply`) reached `map_type`.
    /// The typer must eliminate both before emit (recon-ergoser-ir OQ2).
    #[error("unresolved compiler-internal type reached emit: {0}")]
    UnresolvedType(String),
    /// A typed node with no Task-7 lowering: the Task-8 binding forms, or a
    /// node `ergo-ser` cannot represent (see the module docs).
    #[error("node not supported by emit at M3 Task 7: {0}")]
    UnsupportedNode(&'static str),
    /// A structurally invalid shape that must never reach emit (pre-typed
    /// nodes, payload/type mismatches, wire-arity violations).
    #[error("invalid shape reached emit: {0}")]
    InvalidShape(&'static str),
}

/// Lower a typed expression to the `ergo-ser` opcode IR.
///
/// Fixed-arity forms map 1:1 onto `Payload::Zero/One/Two/Three/Four` and the
/// named-field payloads per the `opcode_pattern` table; constants map through
/// [`map_const`]. Binding forms return [`EmitError::UnsupportedNode`] until
/// Task 8.
pub fn emit(expr: &TypedExpr) -> Result<Expr, EmitError> {
    use TypedExpr as T;

    // Fixed-positional payload builders (recurse through `emit`).
    let one =
        |a: &TypedExpr| -> Result<Payload, EmitError> { Ok(Payload::One(Box::new(emit(a)?))) };
    let two = |a: &TypedExpr, b: &TypedExpr| -> Result<Payload, EmitError> {
        Ok(Payload::Two(Box::new(emit(a)?), Box::new(emit(b)?)))
    };
    let three = |a: &TypedExpr, b: &TypedExpr, c: &TypedExpr| -> Result<Payload, EmitError> {
        Ok(Payload::Three(
            Box::new(emit(a)?),
            Box::new(emit(b)?),
            Box::new(emit(c)?),
        ))
    };
    let four = |a: &TypedExpr,
                b: &TypedExpr,
                c: &TypedExpr,
                d: &TypedExpr|
     -> Result<Payload, EmitError> {
        Ok(Payload::Four(
            Box::new(emit(a)?),
            Box::new(emit(b)?),
            Box::new(emit(c)?),
            Box::new(emit(d)?),
        ))
    };
    let items_of =
        |items: &[TypedExpr]| -> Result<Vec<Expr>, EmitError> { items.iter().map(emit).collect() };
    let node = |opcode: u8, payload: Payload| Ok(Expr::Op(IrNode { opcode, payload }));

    match expr {
        // ── context singletons: leaf opcodes, Zero payload ────────────────
        T::Height { .. } => node(0xA3, Payload::Zero),
        T::Inputs { .. } => node(0xA4, Payload::Zero),
        T::Outputs { .. } => node(0xA5, Payload::Zero),
        T::Self_ { .. } => node(0xA7, Payload::Zero),
        T::MinerPubkey { .. } => node(0xAC, Payload::Zero),
        T::LastBlockUtxoRootHash { .. } => node(0xA6, Payload::Zero),
        T::Context { .. } => node(0xFE, Payload::Zero),
        T::Global { .. } => node(0xDD, Payload::Zero),
        T::GroupGenerator { .. } => node(0x82, Payload::Zero),

        // ── constants: always the constant path (incl. Booleans — see the
        //    module docs; never the 0x7F/0x80 True/False opcodes) ──────────
        T::Constant { value, tpe } => {
            let (tpe, val) = map_const(value, tpe)?;
            Ok(Expr::Const { tpe, val })
        }

        // ── relations (Relation2 pattern; the writer auto-compacts a
        //    bool-constant pair to the 0x85 form) ───────────────────────────
        T::GT { left, right, .. } => node(0x91, two(left, right)?),
        T::GE { left, right, .. } => node(0x92, two(left, right)?),
        T::LT { left, right, .. } => node(0x8F, two(left, right)?),
        T::LE { left, right, .. } => node(0x90, two(left, right)?),
        T::EQ { left, right, .. } => node(0x93, two(left, right)?),
        T::NEQ { left, right, .. } => node(0x94, two(left, right)?),

        // ── arithmetic / bitwise: the typer stores Scala's opcode byte
        //    (typed.rs ARITH_*/BIT_* constants); passthrough as u8 ─────────
        T::ArithOp {
            left,
            right,
            opcode,
            ..
        }
        | T::BitOp {
            left,
            right,
            opcode,
            ..
        } => node(*opcode as u8, two(left, right)?),

        // ── boolean binary (lazy) + unary ─────────────────────────────────
        T::BinAnd { left, right, .. } => node(0xED, two(left, right)?),
        T::BinOr { left, right, .. } => node(0xEC, two(left, right)?),
        T::BinXor { left, right, .. } => node(0xF4, two(left, right)?),
        T::LogicalNot { input, .. } => node(0xEF, one(input)?),
        T::Negation { input, .. } => node(0xF0, one(input)?),
        T::BitInversion { input, .. } => node(0xF1, one(input)?),

        // ── control / structure ───────────────────────────────────────────
        T::If {
            condition,
            true_branch,
            false_branch,
            ..
        } => node(0x95, three(condition, true_branch, false_branch)?),
        T::Tuple { items, .. } => {
            // Scala STuple is 2..=255 items; the ergo-ser writer asserts
            // (panics) past 255 (write.rs Tuple arm), so guard recoverably.
            if !(2..=255).contains(&items.len()) {
                return Err(EmitError::InvalidShape(
                    "Tuple arity outside the Scala wire range 2..=255",
                ));
            }
            node(
                0x86,
                Payload::Tuple {
                    items: items_of(items)?,
                },
            )
        }
        T::SelectField {
            input, field_index, ..
        } => node(
            0x8C,
            Payload::SelectField {
                input: Box::new(emit(input)?),
                // 1-based already (transformers.scala:291 fieldIndex).
                field_idx: *field_index as u8,
            },
        ),
        T::ConcreteCollection {
            items, elem_type, ..
        } => node(
            0x83,
            Payload::ConcreteCollection {
                elem_type: map_type(elem_type)?,
                items: items_of(items)?,
            },
        ),

        // ── numeric casts ─────────────────────────────────────────────────
        T::Upcast { input, tpe } => node(
            0x7E,
            Payload::NumericCast {
                input: Box::new(emit(input)?),
                tpe: map_type(tpe)?,
            },
        ),
        T::Downcast { input, tpe } => node(
            0x7D,
            Payload::NumericCast {
                input: Box::new(emit(input)?),
                tpe: map_type(tpe)?,
            },
        ),

        // ── collection transformers ───────────────────────────────────────
        T::MapCollection { input, mapper, .. } => node(0xAD, two(input, mapper)?),
        T::Exists {
            input, condition, ..
        } => node(0xAE, two(input, condition)?),
        T::ForAll {
            input, condition, ..
        } => node(0xAF, two(input, condition)?),
        T::Fold {
            input,
            zero,
            fold_op,
            ..
        } => node(0xB0, three(input, zero, fold_op)?),
        T::Filter {
            input, condition, ..
        } => node(0xB5, two(input, condition)?),
        T::Slice {
            input, from, until, ..
        } => node(0xB4, three(input, from, until)?),
        T::Append { input, col2, .. } => node(0xB3, two(input, col2)?),
        T::SizeOf { input, .. } => node(0xB1, one(input)?),
        T::ByIndex {
            input,
            index,
            default,
            ..
        } => node(
            0xB2,
            Payload::ByIndex {
                input: Box::new(emit(input)?),
                index: Box::new(emit(index)?),
                default: default
                    .as_deref()
                    .map(|d| emit(d).map(Box::new))
                    .transpose()?,
            },
        ),

        // ── collection-boolean gates: ONE arg (the collection expr) ───────
        T::AND { input, .. } => node(0x96, one(input)?),
        T::OR { input, .. } => node(0x97, one(input)?),
        T::XorOf { input, .. } => node(0xFF, one(input)?),

        // ── sigma combinators ─────────────────────────────────────────────
        T::AtLeast { bound, input, .. } => node(0x98, two(bound, input)?),
        T::SigmaAnd { items, .. } => node(
            0xEA,
            Payload::SigmaCollection {
                items: items_of(items)?,
            },
        ),
        T::SigmaOr { items, .. } => node(
            0xEB,
            Payload::SigmaCollection {
                items: items_of(items)?,
            },
        ),

        // ── sigma / boolean coercions ─────────────────────────────────────
        T::BoolToSigmaProp { value, .. } => node(0xD1, one(value)?),
        T::SigmaPropIsProven { input, .. } => node(0xCF, one(input)?),
        T::SigmaPropBytes { input, .. } => node(0xD0, one(input)?),

        // ── crypto primitives ─────────────────────────────────────────────
        T::CreateProveDlog { value, .. } => node(0xCD, one(value)?),
        T::CreateProveDHTuple { gv, hv, uv, vv, .. } => node(0xCE, four(gv, hv, uv, vv)?),
        T::CalcBlake2b256 { input, .. } => node(0xCB, one(input)?),
        T::CalcSha256 { input, .. } => node(0xCC, one(input)?),

        // ── byte conversions ──────────────────────────────────────────────
        T::ByteArrayToBigInt { input, .. } => node(0x7B, one(input)?),
        T::ByteArrayToLong { input, .. } => node(0x7C, one(input)?),
        T::LongToByteArray { input, .. } => node(0x7A, one(input)?),

        // ── group ops ─────────────────────────────────────────────────────
        T::DecodePoint { input, .. } => node(0xEE, one(input)?),
        T::MultiplyGroup { left, right, .. } => node(0xA0, two(left, right)?),
        T::Exponentiate { left, right, .. } => node(0x9F, two(left, right)?),
        T::Xor { left, right, .. } => node(0x9B, two(left, right)?),

        // ── option ops ────────────────────────────────────────────────────
        T::OptionGet { input, .. } => node(0xE4, one(input)?),
        T::OptionGetOrElse { input, default, .. } => node(0xE5, two(input, default)?),
        T::OptionIsDefined { input, .. } => node(0xE6, one(input)?),

        // ── context access ────────────────────────────────────────────────
        T::GetVar { var_id, tpe } => {
            // Node type is SOption(V) (transformers.scala:576); the wire
            // carries the INNER V (Scala GetVarSerializer writes
            // `tpe.elemType`; ergo-ser's parse arm reads one bare type).
            let SType::SOption(inner) = tpe else {
                return Err(EmitError::InvalidShape("GetVar node type must be SOption"));
            };
            node(
                0xE3,
                Payload::GetVar {
                    var_id: *var_id as u8,
                    tpe: map_type(inner)?,
                },
            )
        }
        T::DeserializeContext { id, tpe } => node(
            0xD4,
            Payload::DeserializeContext {
                id: *id as u8,
                tpe: map_type(tpe)?,
            },
        ),
        T::DeserializeRegister { reg, tpe, default } => node(
            0xD5,
            Payload::DeserializeRegister {
                reg_id: *reg as u8,
                tpe: map_type(tpe)?,
                default: default
                    .as_deref()
                    .map(|d| emit(d).map(Box::new))
                    .transpose()?,
            },
        ),

        // ── misc fixed-arity ──────────────────────────────────────────────
        T::SubstConstants {
            script_bytes,
            positions,
            new_values,
            ..
        } => node(0x74, three(script_bytes, positions, new_values)?),
        T::TreeLookup {
            tree, key, proof, ..
        } => node(0xB7, three(tree, key, proof)?),

        // ── nodes ergo-ser cannot represent (module docs + lib.rs ledger) ─
        T::CreateAvlTree { .. } => Err(EmitError::UnsupportedNode("CreateAvlTree")),
        T::ZKProofBlock { .. } => Err(EmitError::UnsupportedNode("ZKProofBlock")),

        // ── binding forms: M3 Task 8 ──────────────────────────────────────
        T::Block { .. } => Err(EmitError::UnsupportedNode("Block")),
        T::ValNode { .. } => Err(EmitError::UnsupportedNode("ValNode")),
        T::Ident { .. } => Err(EmitError::UnsupportedNode("Ident")),
        T::Lambda { .. } => Err(EmitError::UnsupportedNode("Lambda")),
        T::Apply { .. } => Err(EmitError::UnsupportedNode("Apply")),
        T::Select { .. } => Err(EmitError::UnsupportedNode("Select")),
        T::MethodCall { .. } => Err(EmitError::UnsupportedNode("MethodCall")),

        // ── pre-typed nodes: must never reach emit ────────────────────────
        T::ApplyTypes { .. } => Err(EmitError::InvalidShape(
            "ApplyTypes is pre-typed-only and must not reach emit",
        )),
        T::MethodCallLike { .. } => Err(EmitError::InvalidShape(
            "MethodCallLike is pre-typed-only and must not reach emit",
        )),
    }
}

/// Map a compiler-domain [`SType`] to the wire-domain [`SigmaType`].
///
/// Mechanical 1:1 for every serializable variant; `SFunc` renames
/// `dom`/`range` → `t_dom`/`t_range` and lifts each `tpe_params` ident into
/// a `SigmaType::STypeVar` (the ergo-ser writer requires exactly that shape,
/// `sigma_type.rs:235-244`). `NoType`/`STypeApply` are compiler-internal and
/// error as [`EmitError::UnresolvedType`].
pub(crate) fn map_type(t: &SType) -> Result<SigmaType, EmitError> {
    Ok(match t {
        // Compiler-internal shapes the typer must eliminate (OQ2 defense).
        SType::NoType => return Err(EmitError::UnresolvedType("NoType".to_string())),
        SType::STypeApply { name, .. } => {
            return Err(EmitError::UnresolvedType(format!("STypeApply({name})")))
        }

        // 1:1 renames (stype.rs:14-56 ↔ sigma_type.rs:70-135).
        SType::SBoolean => SigmaType::SBoolean,
        SType::SByte => SigmaType::SByte,
        SType::SShort => SigmaType::SShort,
        SType::SInt => SigmaType::SInt,
        SType::SLong => SigmaType::SLong,
        SType::SBigInt => SigmaType::SBigInt,
        SType::SUnsignedBigInt => SigmaType::SUnsignedBigInt,
        SType::SGroupElement => SigmaType::SGroupElement,
        SType::SSigmaProp => SigmaType::SSigmaProp,
        SType::SAvlTree => SigmaType::SAvlTree,
        SType::SContext => SigmaType::SContext,
        SType::SGlobal => SigmaType::SGlobal,
        SType::SHeader => SigmaType::SHeader,
        SType::SPreHeader => SigmaType::SPreHeader,
        SType::SString => SigmaType::SString,
        SType::SBox => SigmaType::SBox,
        SType::SUnit => SigmaType::SUnit,
        SType::SAny => SigmaType::SAny,
        SType::STypeVar(name) => SigmaType::STypeVar(name.clone()),

        // Compound shapes recurse.
        SType::SColl(elem) => SigmaType::SColl(Box::new(map_type(elem)?)),
        SType::SOption(elem) => SigmaType::SOption(Box::new(map_type(elem)?)),
        SType::STuple(elems) => {
            SigmaType::STuple(elems.iter().map(map_type).collect::<Result<Vec<_>, _>>()?)
        }

        // SFunc: dom→t_dom, range→t_range, String idents → STypeVar
        // (the ergo-ser writer requires STypeVar tpe_params,
        // sigma_type.rs:235-244).
        SType::SFunc {
            dom,
            range,
            tpe_params,
        } => SigmaType::SFunc {
            t_dom: dom.iter().map(map_type).collect::<Result<Vec<_>, _>>()?,
            t_range: Box::new(map_type(range)?),
            tpe_params: tpe_params
                .iter()
                .map(|ident| SigmaType::STypeVar(ident.clone()))
                .collect(),
        },
    })
}

/// Map a constant payload (+ its node type) to the wire `(type, value)` pair.
///
/// The pair is derived from the payload (the byte-of-record); the node type
/// is cross-checked against it — a mismatch is a typer bug surfaced as
/// [`EmitError::InvalidShape`]. `SUnsignedBigInt` values reuse
/// `SigmaValue::BigInt` on the wire (`write_unsigned_bigint_value` takes the
/// BigInt payload, `sigma_value.rs:225-227`).
pub(crate) fn map_const(p: &ConstPayload, t: &SType) -> Result<(SigmaType, SigmaValue), EmitError> {
    // The typer stores BigInt/UnsignedBigInt canonically via
    // `num_bigint::{BigInt,BigUint}::to_string` (D-T3), so a parse failure
    // here means a hand-built payload bypassed the frontend.
    fn parse_bigint(s: &str) -> Result<num_bigint::BigInt, EmitError> {
        s.parse::<num_bigint::BigInt>().map_err(|_| {
            EmitError::InvalidShape("BigInt constant payload is not a decimal integer")
        })
    }

    let (tpe, val) = match p {
        ConstPayload::Bool(b) => (SigmaType::SBoolean, SigmaValue::Boolean(*b)),
        ConstPayload::Byte(v) => (SigmaType::SByte, SigmaValue::Byte(*v)),
        ConstPayload::Short(v) => (SigmaType::SShort, SigmaValue::Short(*v)),
        ConstPayload::Int(v) => (SigmaType::SInt, SigmaValue::Int(*v)),
        ConstPayload::Long(v) => (SigmaType::SLong, SigmaValue::Long(*v)),
        ConstPayload::BigInt(s) => (SigmaType::SBigInt, SigmaValue::BigInt(parse_bigint(s)?)),
        // SUnsignedBigInt reuses the BigInt value on the wire
        // (write_unsigned_bigint_value, sigma_value.rs:225-227).
        ConstPayload::UnsignedBigInt(s) => (
            SigmaType::SUnsignedBigInt,
            SigmaValue::BigInt(parse_bigint(s)?),
        ),
        ConstPayload::String(s) => (SigmaType::SString, SigmaValue::Str(s.clone())),
        ConstPayload::Unit => (SigmaType::SUnit, SigmaValue::Unit),
        // Signed i8 elements reinterpreted as raw wire bytes.
        ConstPayload::ByteColl(bytes) => (
            SigmaType::SColl(Box::new(SigmaType::SByte)),
            SigmaValue::Coll(CollValue::Bytes(bytes.iter().map(|b| *b as u8).collect())),
        ),
        ConstPayload::LongColl(longs) => (
            SigmaType::SColl(Box::new(SigmaType::SLong)),
            SigmaValue::Coll(CollValue::Values(
                longs.iter().map(|v| SigmaValue::Long(*v)).collect(),
            )),
        ),
        // 33-byte SEC1-compressed point, on-curve-checked upstream (D-T5).
        ConstPayload::GroupElement(bytes) => (
            SigmaType::SGroupElement,
            SigmaValue::GroupElement(GroupElement::from_bytes(*bytes)),
        ),
        // Binder PK-rule output — same shape as ergo-ser's own P2PK
        // construction (address.rs:365-368).
        ConstPayload::ProveDlog(pubkey) => (
            SigmaType::SSigmaProp,
            SigmaValue::SigmaProp(SigmaBoolean::ProveDlog(GroupElement::from_bytes(*pubkey))),
        ),
        // Opaque env-injected sigma proposition: no curve bytes to
        // serialize (module docs + lib.rs ledger entry).
        ConstPayload::SigmaProp(_) => {
            return Err(EmitError::UnsupportedNode(
                "opaque SigmaProp constant payload",
            ))
        }
    };

    // Cross-check the payload-derived wire type against the node's assigned
    // type: a mismatch is a typer bug, caught here rather than at write time.
    if map_type(t)? != tpe {
        return Err(EmitError::InvalidShape(
            "constant payload does not match the node's assigned type",
        ));
    }
    Ok((tpe, val))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::{EnvValue, ScriptEnv};
    use crate::typecheck::typecheck;
    use ergo_primitives::reader::VlqReader;
    use ergo_primitives::writer::VlqWriter;
    use ergo_ser::opcode::{parse_expr, write_expr};

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
    /// the PUBLIC API). cseg=false: Task 7 emits inline constants only; the
    /// segregation transform is Task 9/10.
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
    /// M3 frontend cannot reach without Task-8 forms (documented per test).
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

    // ----- round-trips -----

    #[test]
    fn context_singletons_emit_zero_payload_and_roundtrip() {
        for (src, opcode) in [
            ("HEIGHT", 0xA3),
            ("INPUTS", 0xA4),
            ("OUTPUTS", 0xA5),
            ("SELF", 0xA7),
            ("MinerPubkey", 0xAC),
            ("LastBlockUtxoRootHash", 0xA6),
            ("CONTEXT", 0xFE),
            ("Global", 0xDD),
            ("Global.groupGenerator", 0x82),
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
    fn bit_ops_emit_scala_opcode_bytes_and_roundtrip() {
        rt_op("1 | 2", 0xF2);
        rt_op("1 & 2", 0xF3);
        rt_op("1 ^ 2", 0xF5);
        // Shift operators have no ErgoScript surface syntax reachable at M3;
        // the opcode passthrough (`opcode as u8`) is pinned hand-built.
        use crate::typed::{BIT_SHIFT_LEFT, BIT_SHIFT_RIGHT, BIT_SHIFT_RIGHT_ZEROED};
        for (op, byte) in [
            (BIT_SHIFT_RIGHT, 0xF6),
            (BIT_SHIFT_LEFT, 0xF7),
            (BIT_SHIFT_RIGHT_ZEROED, 0xF8),
        ] {
            let node = TypedExpr::BitOp {
                left: Box::new(int_c(1)),
                right: Box::new(int_c(2)),
                opcode: op,
                tpe: SType::SInt,
            };
            rt_node(&node, byte);
        }
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
        rt_op("~HEIGHT", 0xF1);
    }

    #[test]
    fn if_emits_three_payload_and_roundtrips() {
        rt_op("if (HEIGHT > 1) 1 else 2", 0x95);
    }

    #[test]
    fn tuple_and_select_field_emit_and_roundtrip() {
        rt_op("(1, 2L)", 0x86);
        // `(1, 2L)._2` survives as `Select` in the M3 typed AST (same Select
        // survival as `.size`); SelectField is reachable only hand-built
        // until Task 8 lowers Selects.
        let node = TypedExpr::SelectField {
            input: Box::new(tc("(1, 2L)")),
            field_index: 2,
            tpe: SType::SLong,
        };
        let ir = rt_node(&node, 0x8C);
        match &ir {
            Expr::Op(IrNode {
                payload: Payload::SelectField { field_idx, .. },
                ..
            }) => assert_eq!(*field_idx, 2, "1-based field index"),
            other => panic!("expected SelectField, got {other:?}"),
        }
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
        // No M3 frontend path constructs Downcast (numeric casts stay
        // `Select` until Task 8 — assign.rs §1.24 note); hand-built.
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
        // `INPUTS.size` survives as `Select` in the typed AST (golden seed
        // §"INPUTS.size Select survival") — SizeOf itself is reachable only
        // hand-built until Task 8 lowers Selects.
        let node = TypedExpr::SizeOf {
            input: Box::new(TypedExpr::Inputs {
                tpe: scoll(SType::SBox),
            }),
            tpe: SType::SInt,
        };
        rt_node(&node, 0xB1);
    }

    #[test]
    fn higher_order_ops_emit_fixed_arity_payloads() {
        // map/exists/forAll/filter/fold take a lambda the M3 frontend types
        // as `Lambda` (Task 8 → FuncValue). The fixed-arity opcode mapping is
        // pinned with constant stand-ins in the function position; the wire
        // pattern (Two/Three positional children) is child-shape-agnostic.
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
        // SigmaPropBytes / SigmaPropIsProven have no non-Select frontend
        // route at M3 (`.propBytes`/`.isProven` stay Select until Task 8).
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

    // ----- error paths -----

    #[test]
    fn task8_block_form_returns_unsupported_node() {
        // Scope discipline: Block/ValNode (and the other binding forms) are
        // Task 8; at Task 7 they must error, not mis-emit.
        let err = emit(&tc("{ val x = 1; x }")).unwrap_err();
        assert!(
            matches!(err, EmitError::UnsupportedNode(_)),
            "expected UnsupportedNode, got {err:?}"
        );
    }

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
            EmitError::UnsupportedNode("CreateAvlTree")
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
            EmitError::UnsupportedNode("ZKProofBlock")
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

    // ----- oracle parity -----

    #[test]
    fn sigma_prop_true_emits_boolean_via_constant_path() {
        // Oracle capture (module docs): `cc sigmaProp(true)` →
        // `10 01 0101 d1 7300` — the Boolean rides the CONSTANT path
        // (segregated 0101 table entry + placeholder), not opcode 0x7F.
        // Pre-segregation (Task 7) the same constant is inline: d1 01 01.
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
        // `10 01 04c801 d191a37300` (segregated). The inline Task-7 body is
        // the same opcode spine with the constant bytes `04 c8 01` in place
        // of the placeholder: d1 91 a3 04c801.
        let bytes = wire_roundtrip(&emit_tc("sigmaProp(HEIGHT > 100)"));
        assert_eq!(bytes, vec![0xD1, 0x91, 0xA3, 0x04, 0xC8, 0x01]);
    }
}
