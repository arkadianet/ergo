use ergo_ser::opcode::{method_explicit_type_args_count, Expr, Payload};
use ergo_ser::sigma_value::{CollValue, SigmaValue};

use crate::stype::SType;
use crate::typed::{ConstPayload, TypedExpr};
use crate::typer::methods::wire_method;

use super::*;

impl Scope {
    /// `MethodCall`/`PropertyCall` wire dispatch.
    ///
    /// `(type_id, method_id)` resolve through the SAME tables the typer used
    /// (`methods::wire_method`, keyed on the version-aware owner name —
    /// D-T10). Opcode selection is Scala's `MethodCall.companion`:
    /// `if (args.isEmpty) PropertyCall else MethodCall` (values.scala:1322) —
    /// 0xDB writes no arg block, 0xDC writes count + args. The v6 explicit
    /// type-args block (both opcodes) carries the `type_subst` bindings in
    /// the method's DECLARED type-param order, cross-checked against
    /// ergo-ser's per-pair count ([`method_explicit_type_args_count`],
    /// opcode/types.rs:573-589).
    pub(crate) fn emit_method_call(
        &mut self,
        obj: &TypedExpr,
        method: &crate::typed::MethodRef,
        args: &[TypedExpr],
        type_subst: &[(String, SType)],
    ) -> Result<Expr, EmitError> {
        // GraphBuilding reject gates (lib.rs D-C5) — residual MethodCalls the
        // typer accepts (M2 parity) but the FULL Scala compiler rejects:
        //
        // (a) Shared-SNumericType-container methods (`toBytes`/`toBits`,
        //     D-T10): the owner name "SNumericType" is only ever produced at
        //     `tree_version < 3` (`owner_name_for_method`), where Scala's
        //     GraphBuilding rejects the v6-only method under v5 activation
        //     (oracle, ORACLE_TREE_VERSION=2: `ccs sigmaProp(x.toBytes.size
        //     == 4)` → `REJECT 1:13 GraphBuildingException`, 2026-07-07 ×3
        //     runs). At v3 the owner resolves per-type (`Int`/…): a CONSTANT
        //     receiver folds at gate (d) below (wave 2, lib.rs D-C6), a
        //     non-constant one keeps the residual MethodCall (Err/Err reduce
        //     parity).
        if method.owner == "SNumericType" {
            return Err(EmitError::GraphBuildingReject {
                class: "GraphBuildingException",
                what: format!(
                    "v6-only numeric method '{}' on the shared SNumericType container \
                     (tree_version < 3): Scala GraphBuilding rejects it under v5 activation",
                    method.name,
                ),
            });
        }
        // (a2) V6-only `SGlobal` methods reached through a BARE predef alias
        //      (`fromBigEndianBytes`/`deserializeTo`/… — `typer/predef_ir.rs`
        //      `global_deserialize`): the bare form builds `MethodCall(Global, m)`
        //      DIRECTLY, bypassing the version-scoped `SGlobal` method table the
        //      dotted `Global.<m>` form resolves against (which the typer already
        //      v6-gates). Scala exposes these methods ONLY at
        //      `isV3OrLaterErgoTreeVersion` — the v5 `SGlobal` method set is just
        //      `{groupGenerator, xor}` (`SGlobalMethods.getMethods`,
        //      methods.scala:2001-2021, pinned v6.0.2) — and GraphBuilding throws
        //      `GraphBuildingException` on the residual `MethodCall` under v5
        //      activation. Mirror that reject for `tree_version < 3` (oracle
        //      ORACLE_TREE_VERSION=0: `cc sigmaProp(fromBigEndianBytes[Int](
        //      Coll[Byte](0.toByte)) > 0)` → `REJECT 0:0 GraphBuildingException`;
        //      at v3 both accept, byte-identical
        //      `100202000400d191dc6a05dd018301027300047301`). `SigmaDslBuilder`
        //      is the `SGlobal` owner name (`owner_name_for_type`).
        if method.owner == "SigmaDslBuilder"
            && self.tree_version < V6_ERGO_TREE_VERSION
            && !matches!(method.name.as_str(), "groupGenerator" | "xor")
        {
            return Err(EmitError::GraphBuildingReject {
                class: "GraphBuildingException",
                what: format!(
                    "v6-only Global method '{}' requires ErgoTree version >= {} \
                     (v5 SGlobal methods are groupGenerator, xor): the bare predef \
                     alias bypasses the version-scoped method table; Scala \
                     GraphBuilding rejects it under v5 activation",
                    method.name, V6_ERGO_TREE_VERSION,
                ),
            });
        }
        // (b) Postfix residual `size`: a space-form nullary call (`arr1
        //     size`) survives BOTH typers as `MethodCall %SCollection.size`,
        //     but Scala's GraphBuilding has no arm for the wire pair (12,1)
        //     — only the Select path lowers `size` to `SizeOf` — and NO
        //     evaluator accepts the pair (oracle: `ccs sigmaProp((arr1 size)
        //     > 0)` → `REJECT 1:12 GraphBuildingException`; `size` is the
        //     sole nullary custom-irBuilder Coll method, the other postfix
        //     families reject in parity upstream —
        //     adversarial-findings-methodcalls.md F1).
        if method.owner == "SCollection" && method.name == "size" {
            return Err(EmitError::GraphBuildingReject {
                class: "GraphBuildingException",
                what: "residual MethodCall %SCollection.size (postfix `size`): Scala \
                       GraphBuilding only lowers the Select path (SizeOf); wire pair \
                       (12,1) is unevaluable on both sides"
                    .into(),
            });
        }
        // (c) `Box.getReg[T](<literal>)`: Scala lowers a CONST-index getReg
        //     to `ExtractRegisterAs` at GraphBuilding, bounds-checking
        //     `ErgoBox.registers(i)` at compile time (oracle: `cc sigmaProp(
        //     SELF.getReg[Int](-1).isDefined)` → `REJECT 0:0
        //     ArrayIndexOutOfBoundsException`; same for 10 and 100). Out of
        //     range → the wave-1 reject gate; IN RANGE → the wave-2 lowering
        //     (adversarial-findings-methodcalls.md F4): `SELF.getReg[Int](5)`
        //     must emit the SAME bytes as `SELF.R5[Int]` (oracle 2026-07-07
        //     ×3: both reply `1000d1e6c6a70504` — body `…c6a70504`,
        //     ExtractRegisterAs). The wire carries the INNER elem type T
        //     (mirrors the Select `R0`..`R9` arm; ExtractRegisterAsSerializer
        //     writes `tpe.elemType`). Only a LITERAL Int argument lowers — a
        //     dynamic index stays a MethodCall in Scala too (oracle:
        //     `getReg[Int](HEIGHT)` keeps wire pair (99,19) on both sides;
        //     Err/Err reduce parity). Residual (lib.rs D-C6): Scala
        //     const-propagates a val-bound index (`{ val i = 4; …getReg[Int]
        //     (i) }` → `ExtractRegisterAs` reg 4, oracle ×3) — our typed AST
        //     keeps the ValUse, so that form stays a both-accept unevaluable
        //     MethodCall here.
        if method.owner == "Box" && method.name == "getReg" {
            if let Some(TypedExpr::Constant {
                value: crate::typed::ConstPayload::Int(i),
                ..
            }) = args.first()
            {
                if !(0..=9).contains(i) {
                    return Err(EmitError::GraphBuildingReject {
                        class: "ArrayIndexOutOfBoundsException",
                        what: format!(
                            "getReg register index {i} outside 0..=9: Scala lowers the \
                             const-index form to ExtractRegisterAs and bounds-checks it \
                             at compile time"
                        ),
                    });
                }
                let Some((_, inner)) = type_subst.first() else {
                    return Err(EmitError::InvalidShape(
                        "getReg MethodCall missing its explicit T type_subst binding",
                    ));
                };
                return node(
                    0xC6,
                    Payload::ExtractRegisterAs {
                        input: Box::new(self.emit(obj)?),
                        reg_id: *i as u8,
                        tpe: map_type(inner)?,
                    },
                );
            }
        }
        // (d) v6 numeric methods over CONSTANT receivers fold at compile time
        //     — Scala's GraphBuilding partially evaluates them, emitting the
        //     folded constant (wave 2, adversarial-findings-methodcalls.md
        //     F6). Oracle-probed fold set ONLY (2026-07-07 ×3 runs each):
        //     `toBytes`/`toBits` on Byte/Short/Int/Long constants (`ccs
        //     sigmaProp(x.toBytes.size == 4)` → const `0e04 0000000a`,
        //     big-endian; `x.toBits` → const `0d20 00000050`, Coll[Boolean]
        //     MSB-first; `7.toByte.toBytes` → `0e01 07` — a single explicit
        //     cast of a literal folds too) and `bitwiseAnd`/`bitwiseOr`/
        //     `bitwiseXor` over two constants (all three fold: the x/y
        //     probes each reply the fully-folded `10010101d17300`). Probed
        //     NON-folds, deliberately left as residual MethodCalls:
        //     `HEIGHT.toBytes` (non-constant receiver — oracle keeps wire
        //     pair (4,6)), `n1.toBytes` (BigInt receiver — keeps (6,6)),
        //     `x.shiftLeft(1)` (keeps (4,12)); all Err/Err reduce parity.
        //     The owner name is per-type ("Byte"/"Short"/"Int"/"Long") only
        //     at `tree_version >= 3` — pre-v3 the SNumericType gate (a)
        //     already rejected. Out-of-range cast receivers
        //     (`300.toByte.toBytes`) do NOT fold here ([`const_numeric_i64`]
        //     returns `None`): the residual Downcast reaches tree.rs's
        //     `fold_direct_const_casts`, which rejects with the
        //     oracle's ArithmeticException. Residual (lib.rs D-C6): deeper
        //     constant receivers Scala's full partial evaluation also folds —
        //     arithmetic results (`(1 + 2).toBytes`) and multi-cast chains —
        //     stay residual MethodCalls here.
        if let Some(width_bytes) = match method.owner.as_str() {
            "Byte" => Some(1usize),
            "Short" => Some(2),
            "Int" => Some(4),
            "Long" => Some(8),
            _ => None,
        } {
            match method.name.as_str() {
                "toBytes" => {
                    if let Some(v) = const_numeric_i64(obj) {
                        let bytes: Vec<u8> = v.to_be_bytes()[8 - width_bytes..].to_vec();
                        return Ok(Expr::Const {
                            tpe: SigmaType::SColl(Box::new(SigmaType::SByte)),
                            val: SigmaValue::Coll(CollValue::Bytes(bytes)),
                        });
                    }
                }
                "toBits" => {
                    if let Some(v) = const_numeric_i64(obj) {
                        let n_bits = width_bytes * 8;
                        // Collection index 0 = the MOST significant bit
                        // (oracle: `7.toByte.toBits` → `0d08 e0` =
                        // [f,f,f,f,f,t,t,t] — bit (n-1-i) of the value at
                        // index i).
                        let bits: Vec<bool> = (0..n_bits)
                            .map(|i| (v >> (n_bits - 1 - i)) & 1 == 1)
                            .collect();
                        return Ok(Expr::Const {
                            tpe: SigmaType::SColl(Box::new(SigmaType::SBoolean)),
                            val: SigmaValue::Coll(CollValue::BoolBits(bits)),
                        });
                    }
                }
                "bitwiseAnd" | "bitwiseOr" | "bitwiseXor" => {
                    if let (Some(a), Some(b)) = (
                        const_numeric_i64(obj),
                        args.first().and_then(const_numeric_i64),
                    ) {
                        // Bitwise ops on two same-width sign-extended values
                        // stay in range — no overflow path exists.
                        let v = match method.name.as_str() {
                            "bitwiseAnd" => a & b,
                            "bitwiseOr" => a | b,
                            _ => a ^ b,
                        };
                        let (tpe, val) = match method.owner.as_str() {
                            "Byte" => (SigmaType::SByte, SigmaValue::Byte(v as i8)),
                            "Short" => (SigmaType::SShort, SigmaValue::Short(v as i16)),
                            "Int" => (SigmaType::SInt, SigmaValue::Int(v as i32)),
                            _ => (SigmaType::SLong, SigmaValue::Long(v)),
                        };
                        return Ok(Expr::Const { tpe, val });
                    }
                }
                _ => {}
            }
        }
        let Some((type_id, desc)) = wire_method(&method.owner, &method.name) else {
            return Err(EmitError::UnsupportedNode(format!(
                "MethodCall %{}.{} has no wire (typeId, methodId)",
                method.owner, method.name
            )));
        };
        // The thin id projection must stay in lockstep with the full lookup
        // (same table; pins the invariant for direct `wire_ids` consumers).
        debug_assert_eq!(
            crate::typer::methods::wire_ids(&method.owner, &method.name),
            Some((type_id, desc.method_id)),
        );
        // PropertyCall discipline: an empty arg list is only valid when the
        // method table declares the method nullary (receiver-only dom) — a
        // zero-arg call of an args-taking method would serialize as a
        // PropertyCall that Scala deserializes to a different (arg-less)
        // invocation.
        if args.is_empty() && desc.stype.dom.len() != 1 {
            return Err(EmitError::InvalidShape(
                "zero-arg MethodCall of a method whose table entry declares value args",
            ));
        }
        let obj = self.emit(obj)?;
        let args = self.items_of(args)?;
        let mut type_args = Vec::new();
        if desc.explicit_type_args {
            for param in &desc.stype.tpe_params {
                let Some((_, bound)) = type_subst.iter().find(|(name, _)| name == param) else {
                    return Err(EmitError::InvalidShape(
                        "MethodCall missing a type_subst binding for an explicit type param",
                    ));
                };
                type_args.push(map_type(bound)?);
            }
        }
        if type_args.len() != method_explicit_type_args_count(type_id, desc.method_id) {
            return Err(EmitError::InvalidShape(
                "MethodCall explicit-type-arg count disagrees with the ergo-ser wire table",
            ));
        }
        let opcode = if args.is_empty() { 0xDB } else { 0xDC };
        node(
            opcode,
            Payload::MethodCall {
                type_id,
                method_id: desc.method_id,
                obj: Box::new(obj),
                args,
                type_args,
            },
        )
    }
}

/// Constant value of a v6-numeric-method receiver/argument for the wave-2
/// compile-time fold (emit_method_call gate (d), lib.rs D-C6): a DIRECT
/// Byte/Short/Int/Long constant, or a single explicit numeric cast of one
/// (`7.toByte` — a typed `Select` the typer leaves unfolded, class-4(a)).
/// The cast case is range-checked: an out-of-range cast (`300.toByte`)
/// returns `None`, so the residual `Downcast` reaches
/// `tree.rs::fold_direct_const_casts`, which rejects with the oracle's
/// `ArithmeticException` (oracle: `cc sigmaProp(300.toByte.toBytes.size ==
/// 1)` → `REJECT 0:0 ArithmeticException`, 2026-07-07 ×3).
pub(crate) fn const_numeric_i64(e: &TypedExpr) -> Option<i64> {
    fn direct(e: &TypedExpr) -> Option<i64> {
        match e {
            TypedExpr::Constant { value, .. } => match value {
                ConstPayload::Byte(v) => Some(i64::from(*v)),
                ConstPayload::Short(v) => Some(i64::from(*v)),
                ConstPayload::Int(v) => Some(i64::from(*v)),
                ConstPayload::Long(v) => Some(*v),
                _ => None,
            },
            _ => None,
        }
    }
    match e {
        TypedExpr::Constant { .. } => direct(e),
        TypedExpr::Select { obj, field, .. } => {
            let v = direct(obj)?;
            let in_range = match field.as_str() {
                "toByte" => i8::try_from(v).is_ok(),
                "toShort" => i16::try_from(v).is_ok(),
                "toInt" => i32::try_from(v).is_ok(),
                "toLong" => true,
                _ => return None,
            };
            in_range.then_some(v)
        }
        _ => None,
    }
}
