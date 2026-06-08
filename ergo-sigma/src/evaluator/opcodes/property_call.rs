//! `0xDB PropertyCall` and the shared no-arg method dispatch table.
//!
//! `PropertyCall` is a wire-level specialization of `MethodCall`: same
//! `Payload::MethodCall { type_id, method_id, obj, args }` shape, except
//! `args` is always empty. The Scala compiler emits `PropertyCall` for
//! no-arg method invocations to save a byte; both opcodes route into the
//! same `MethodSpecialization` table at runtime.
//!
//! `eval_no_arg_method` is the single source of truth for that table on
//! the Rust side. Both `eval_property_call` (this module) and
//! `eval_method_call`'s no-arg fallthrough route through it. Sharing the
//! table prevents drift between the two entry points.
//!
//! Cost discipline is preserved: `eval_property_call` charges
//! `add_cost(0xDB)` (Fixed 4) before evaluating `obj`, then
//! `eval_no_arg_method` charges `add_method_cost(n)` per matched arm.
//! `eval_method_call` mirrors this with `add_cost(0xDC)` (Fixed 4) and
//! falls through to `eval_no_arg_method` only after its args-using arms
//! fail to match. The two opcode dispatch costs are equal so the no-arg
//! flow yields identical total cost regardless of which entry fired.

use ergo_primitives::cost::CostAccumulator;
use ergo_ser::opcode::Expr;

use super::super::cost::{add_cost, add_method_cost, collection_len};
use super::super::eval_ctx::EvalCtx;
use super::super::helpers::resolve_box;
use super::super::types::{BoxSource, EvalError, ReductionContext, Value, SECP256K1_GENERATOR};

/// Entry point for `0xDB PropertyCall`.
pub(in crate::evaluator) fn eval_property_call(
    type_id: u8,
    method_id: u8,
    obj: &Expr,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    add_cost(cx.cost, 0xDB)?;
    // Soft-fork activation gate for EIP-50 / Sigma 6.0 methods reached
    // via PropertyCall (e.g. `SGlobal.none`, a zero-arg v6 method).
    // Mirrors the gate in `eval_method_call` and shares the single v6
    // method table in `is_v6_method`, so the two entry points cannot
    // drift. Without it a pre-EIP50 tree using a v6 property method
    // would be wrongly accepted instead of soft-fork-rejected.
    if super::method_call::is_v6_method(type_id, method_id) {
        cx.ctx.require_method_version(type_id, method_id, 3)?;
    }
    let obj_val = cx.eval_expr(obj)?;
    match eval_no_arg_method(type_id, method_id, &obj_val, cx.ctx, cx.cost)? {
        Some(v) => Ok(v),
        None => Err(EvalError::TypeError {
            expected: "supported PropertyCall",
            got: format!("type_id={type_id}, method_id={method_id}"),
        }),
    }
}

/// Shared no-arg method dispatch table for `0xDB PropertyCall` and the
/// no-arg fallthrough of `0xDC MethodCall`.
///
/// Returns `Ok(None)` if `(type_id, method_id)` is not a no-arg method —
/// no cost is charged in that case, leaving the caller free to surface
/// either an unsupported error (PropertyCall) or to route to args-using
/// arms (MethodCall, which calls this helper from its catch-all branch
/// after its args-using arms fail to match). On a match,
/// `add_method_cost(n)` for the per-method cost has been charged before
/// the result is returned.
pub(super) fn eval_no_arg_method(
    type_id: u8,
    method_id: u8,
    obj_val: &Value,
    ctx: &ReductionContext<'_>,
    cost: &mut CostAccumulator,
) -> Result<Option<Value>, EvalError> {
    match (type_id, method_id) {
        // SContext(101).dataInputs(1) -> Coll[Box]            cost: 15
        (101, 1) => {
            add_method_cost(cost, 15)?;
            Ok(Some(Value::BoxCollection(BoxSource::DataInputs)))
        }
        // SContext(101).headers(2) -> Coll[Header]            cost: 15
        (101, 2) => {
            add_method_cost(cost, 15)?;
            Ok(Some(Value::CollHeader(ctx.last_headers.to_vec())))
        }
        // SContext(101).preHeader(3) -> PreHeader             cost: 15
        (101, 3) => {
            add_method_cost(cost, 15)?;
            Ok(Some(Value::PreHeader))
        }
        // SContext(101).selfBoxIndex(8) -> Int                cost: 20
        // Pre-JIT (activatedVersion < 2) always returns -1
        // (sigmastate-interpreter#603, preserved as consensus).
        (101, 8) => {
            add_method_cost(cost, 20)?;
            if ctx.activated_script_version < 2 {
                Ok(Some(Value::Int(-1)))
            } else {
                let idx = ctx
                    .inputs
                    .iter()
                    .position(|b| ctx.self_box.is_some_and(|sb| b.id == sb.id))
                    .unwrap_or(0);
                Ok(Some(Value::Int(idx as i32)))
            }
        }
        // SContext(101).minerPubKey(10) -> Coll[Byte]         cost: 20
        (101, 10) => {
            add_method_cost(cost, 20)?;
            Ok(Some(Value::CollBytes(ctx.miner_pubkey.to_vec())))
        }
        // SHeader(104) property methods 1-15                  cost: 10
        (104, mid @ 1..=15) => {
            add_method_cost(cost, 10)?;
            let h = match obj_val {
                Value::Header(h) => h,
                other => {
                    return Err(EvalError::TypeError {
                        expected: "Header for SHeader access",
                        got: format!("{other:?}"),
                    });
                }
            };
            Ok(Some(match mid {
                1 => Value::CollBytes(h.id.to_vec()),
                2 => Value::Byte(h.version as i8),
                3 => Value::CollBytes(h.parent_id.to_vec()),
                4 => Value::CollBytes(h.ad_proofs_root.to_vec()),
                5 => {
                    let avl = ergo_ser::sigma_value::AvlTreeData {
                        digest: ergo_primitives::digest::ADDigest::from_bytes(h.state_root),
                        insert_allowed: false,
                        update_allowed: false,
                        remove_allowed: false,
                        key_length: 32,
                        value_length_opt: None,
                    };
                    Value::AvlTree(avl)
                }
                6 => Value::CollBytes(h.transactions_root.to_vec()),
                7 => Value::Long(h.timestamp as i64),
                8 => Value::Long(h.n_bits as i64),
                9 => Value::Int(h.height as i32),
                10 => Value::CollBytes(h.extension_root.to_vec()),
                11 => Value::GroupElement(h.miner_pk),
                12 => Value::GroupElement(h.pow_onetime_pk),
                13 => Value::CollBytes(h.pow_nonce.to_vec()),
                14 => Value::BigInt(h.pow_distance.clone()),
                15 => Value::CollBytes(h.votes.to_vec()),
                _ => unreachable!(),
            }))
        }
        // SPreHeader(105) property methods 1-7                cost: 10
        (105, 1) => {
            add_method_cost(cost, 10)?;
            Ok(Some(Value::Byte(ctx.pre_header_version as i8)))
        }
        (105, 2) => {
            add_method_cost(cost, 10)?;
            Ok(Some(Value::CollBytes(ctx.pre_header_parent_id.to_vec())))
        }
        (105, 3) => {
            add_method_cost(cost, 10)?;
            Ok(Some(Value::Long(ctx.pre_header_timestamp as i64)))
        }
        (105, 4) => {
            add_method_cost(cost, 10)?;
            Ok(Some(Value::Long(ctx.pre_header_n_bits as i64)))
        }
        (105, 5) => {
            add_method_cost(cost, 10)?;
            Ok(Some(Value::Int(ctx.height as i32)))
        }
        (105, 6) => {
            add_method_cost(cost, 10)?;
            Ok(Some(Value::GroupElement(ctx.miner_pubkey)))
        }
        (105, 7) => {
            add_method_cost(cost, 10)?;
            Ok(Some(Value::CollBytes(ctx.pre_header_votes.to_vec())))
        }
        // SGlobal(106).groupGenerator(1) -> GroupElement      cost: 10
        (106, 1) => {
            add_method_cost(cost, 10)?;
            Ok(Some(Value::GroupElement(SECP256K1_GENERATOR)))
        }
        // SGlobal(106).none(10)[T] -> Option[T]               cost: 5
        // EIP-50 v6 empty-Option constructor. Zero value args, so it
        // serializes as a 0xDB PropertyCall (its sibling some(9) has a
        // value arg and lands in method_call.rs). FixedCost(JitCost(5))
        // per v6.0.2 `SGlobalMethods.noneMethod`. The explicit `[T]` is
        // parsed at the wire, but the value layer's Option is
        // type-erased, so it is not needed here. The soft-fork gate is
        // applied in eval_property_call (this is a v6 method).
        (106, 10) => {
            add_method_cost(cost, 5)?;
            Ok(Some(Value::Opt(None)))
        }
        // SBox(99).tokens(8) -> Coll[(Coll[Byte], Long)]      cost: 15
        (99, 8) => {
            add_method_cost(cost, 15)?;
            let b = resolve_box(obj_val, ctx)?;
            Ok(Some(Value::Tokens(b.tokens.clone())))
        }
        // SAvlTree(100) no-arg properties                     cost: 15
        (100, 1) => {
            add_method_cost(cost, 15)?;
            match obj_val {
                Value::AvlTree(avl) => Ok(Some(Value::CollBytes(avl.digest.as_bytes().to_vec()))),
                other => Err(EvalError::TypeError {
                    expected: "AvlTree for digest",
                    got: format!("{other:?}"),
                }),
            }
        }
        (100, 2) => {
            add_method_cost(cost, 15)?;
            match obj_val {
                Value::AvlTree(avl) => {
                    let flags = (if avl.insert_allowed { 1u8 } else { 0 })
                        | (if avl.update_allowed { 2 } else { 0 })
                        | (if avl.remove_allowed { 4 } else { 0 });
                    // Scala SAvlTree.enabledOperations returns Byte.
                    Ok(Some(Value::Byte(flags as i8)))
                }
                other => Err(EvalError::TypeError {
                    expected: "AvlTree for enabledOperations",
                    got: format!("{other:?}"),
                }),
            }
        }
        (100, 3) => {
            add_method_cost(cost, 15)?;
            match obj_val {
                // key_length is i32 (Scala keyLength: Int): a wrapped-negative
                // length surfaces as a negative SInt here, matching the
                // reference (e.g. keyLength-negative -> Int(-2147483648)).
                Value::AvlTree(avl) => Ok(Some(Value::Int(avl.key_length))),
                other => Err(EvalError::TypeError {
                    expected: "AvlTree for keyLength",
                    got: format!("{other:?}"),
                }),
            }
        }
        (100, 4) => {
            add_method_cost(cost, 15)?;
            match obj_val {
                Value::AvlTree(avl) => Ok(Some(Value::Opt(
                    avl.value_length_opt.map(|v| Box::new(Value::Int(v))),
                ))),
                other => Err(EvalError::TypeError {
                    expected: "AvlTree for valueLengthOpt",
                    got: format!("{other:?}"),
                }),
            }
        }
        // SColl(12).indices(14) -> Coll[Int]                   cost: 20
        (12, 14) => {
            add_method_cost(cost, 20)?;
            let len = collection_len(obj_val, ctx) as i32;
            Ok(Some(Value::CollInt((0..len).collect())))
        }
        // SGroupElement(7).getEncoded(2) -> Coll[Byte]
        // Scala SGroupElement.GetEncodedMethod.costKind = FixedCost(JitCost(250)).
        (7, 2) => {
            add_method_cost(cost, 250)?;
            match obj_val {
                Value::GroupElement(bytes) => Ok(Some(Value::CollBytes(bytes.to_vec()))),
                _ => Err(EvalError::TypeError {
                    expected: "GroupElement",
                    got: format!("{obj_val:?}"),
                }),
            }
        }
        // SGroupElement(7).negate(5) -> GroupElement
        // Scala SGroupElement.NegateMethod.costKind = FixedCost(JitCost(45)).
        // Compressed SEC1 negation flips the prefix byte (02↔03).
        (7, 5) => {
            add_method_cost(cost, 45)?;
            match obj_val {
                Value::GroupElement(bytes) => {
                    let mut negated = *bytes;
                    if negated[0] == 0x02 {
                        negated[0] = 0x03;
                    } else if negated[0] == 0x03 {
                        negated[0] = 0x02;
                    }
                    Ok(Some(Value::GroupElement(negated)))
                }
                _ => Err(EvalError::TypeError {
                    expected: "GroupElement",
                    got: format!("{obj_val:?}"),
                }),
            }
        }
        // SNumericTypeMethods.toBytes(6) / toBits(7) for Byte(2) /
        // Short(3) / Int(4) / Long(5) / BigInt(6) and SUnsignedBigInt(9).
        // Zero value args, so the compiler emits a 0xDB PropertyCall.
        // FixedCost(JitCost(5)) each, per v6.0.2 SNumericTypeMethods
        // (ToBytesMethod id 6, ToBitsMethod id 7).
        //
        // toBytes -> Coll[Byte], big-endian fixed-width two's-complement
        // (see `numeric_big_endian_bytes`). toBits -> Coll[Boolean] of
        // length 8*bytes.len, MSB-first per byte: the base-trait
        // `ExactNumeric.toBits` walks the SAME bytes `toBytes` produces,
        // so one byte computation feeds both (see `bits_msb_first`).
        //
        // For the signed numeric types these are V5+ (they sit in
        // `SNumericTypeMethods.v5Methods`), reachable on every ErgoTree
        // version and intentionally NOT gated in `is_v6_method`.
        // SUnsignedBigInt is a v6-only type, so `(9, 6)|(9, 7)` ARE in
        // `is_v6_method`; the soft-fork gate is applied by the callers.
        (2..=6, 6 | 7) | (9, 6 | 7) => {
            add_method_cost(cost, 5)?;
            let bytes = numeric_big_endian_bytes(obj_val)?;
            Ok(Some(if method_id == 6 {
                Value::CollBytes(bytes)
            } else {
                Value::CollBool(bits_msb_first(&bytes))
            }))
        }
        _ => Ok(None),
    }
}

/// Big-endian byte representation of a numeric `Value`, matching v6.0.2
/// `SNumericTypeMethods.ToBytesMethod` (the runtime body each receiver
/// type dispatches to):
///
/// * Byte / Short / Int / Long — fixed-width (1 / 2 / 4 / 8) big-endian
///   two's-complement (`ExactIntegral.toBigEndianBytes`).
/// * BigInt — `CBigInt.toBytes` = `BigInteger.toByteArray` = minimal
///   signed two's-complement big-endian = `num_bigint::to_signed_bytes_be`.
/// * UnsignedBigInt — `CUnsignedBigInt.toBytes` =
///   `BigIntegers.asUnsignedByteArray(value)` = minimal *unsigned*
///   magnitude big-endian (no sign byte), with zero encoded as a single
///   `0x00` byte. Bouncy Castle keeps the lone zero and strips a leading
///   `0x00` only when more bytes follow, which is exactly
///   `to_bytes_be().1` on the always-non-negative carrier.
fn numeric_big_endian_bytes(v: &Value) -> Result<Vec<u8>, EvalError> {
    Ok(match v {
        Value::Byte(x) => vec![*x as u8],
        Value::Short(x) => x.to_be_bytes().to_vec(),
        Value::Int(x) => x.to_be_bytes().to_vec(),
        Value::Long(x) => x.to_be_bytes().to_vec(),
        Value::BigInt(x) => x.to_signed_bytes_be(),
        Value::UnsignedBigInt(x) => x.to_bytes_be().1,
        other => {
            return Err(EvalError::TypeError {
                expected: "numeric value for toBytes/toBits",
                got: format!("{other:?}"),
            })
        }
    })
}

/// MSB-first bit expansion of `bytes`, matching the base-trait
/// `ExactNumeric.toBits` in v6.0.2: for byte `i` it writes
/// `res[i*8 + (7 - bit)] = (byte_i >> bit) & 1`, i.e. the most
/// significant bit of each byte comes first. Output length is
/// `8 * bytes.len()`.
fn bits_msb_first(bytes: &[u8]) -> Vec<bool> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);
    for &b in bytes {
        for shift in (0..8).rev() {
            bits.push((b >> shift) & 1 == 1);
        }
    }
    bits
}
