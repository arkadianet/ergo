//! `SGlobal` (type_id 106) `0xDC MethodCall` arms: encodeNbits(6),
//! decodeNbits(7), some(9), powHit(8), xor(2), serialize(3), deserializeTo(4),
//! fromBigEndianBytes(5). Also home to the nbits compact-difficulty codec and
//! the `SGlobal.serialize` `DynamicCost` put-cost estimation subsystem
//! (`serialize_put_cost` and its recursive helpers) — both used only by these
//! arms.

pub const COST_DESERIALIZE_TO: CostKind = CostKind::PerItem {
    base: JitCost::from_jit(100),
    per_chunk: JitCost::from_jit(32),
    chunk_size: 32,
};
pub const COST_ENCODE_NBITS: u64 = 25;
pub const COST_DECODE_NBITS: u64 = 50;
pub const COST_SOME: u64 = 5;
pub const COST_FROM_BIG_ENDIAN_BYTES: u64 = 10;

use ergo_primitives::cost::{CostKind, JitCost};
use ergo_ser::opcode::Expr;
use ergo_ser::sigma_type::SigmaType;

use super::check_arity;
use crate::evaluator::cost::{add_cost_per_item, add_method_cost};
use crate::evaluator::eval_ctx::EvalCtx;
use crate::evaluator::types::{EvalError, Value};

// SGlobal(106).encodeNbits(6, value: SBigInt) -> SLong
// EIP-50 v6 method. Encodes a BigInt difficulty target into
// Bitcoin-style "compact" nbits (3-byte mantissa + 1-byte
// exponent + sign bit). Cost: `Fixed(25)` per Scala source.
// Algorithm mirrors
// `core/.../sigma/util/NBitsUtils.scala::encodeCompactBits`.
pub(super) fn encode_nbits(args: &[Expr], cx: &mut EvalCtx<'_>) -> Result<Value, EvalError> {
    check_arity(args, 1)?;
    let v_val = cx.eval_expr(&args[0])?;
    add_method_cost(cx.cost, COST_ENCODE_NBITS)?;
    let v = match &v_val {
        Value::BigInt(n) => n,
        other => {
            return Err(EvalError::TypeError {
                expected: "BigInt for SGlobal.encodeNbits",
                got: format!("{other:?}"),
            })
        }
    };
    Ok(Value::Long(encode_compact_bits(v)))
}

// SGlobal(106).decodeNbits(7, value: SLong) -> SBigInt
// EIP-50 v6 method. Inverse of `encodeNbits`. Cost:
// `Fixed(50)` per Scala source. Algorithm mirrors
// `core/.../sigma/util/NBitsUtils.scala::decodeCompactBits`.
pub(super) fn decode_nbits(args: &[Expr], cx: &mut EvalCtx<'_>) -> Result<Value, EvalError> {
    check_arity(args, 1)?;
    let v_val = cx.eval_expr(&args[0])?;
    let compact = match v_val {
        Value::Long(n) => n,
        other => {
            return Err(EvalError::TypeError {
                expected: "Long for SGlobal.decodeNbits",
                got: format!("{other:?}"),
            })
        }
    };
    add_method_cost(cx.cost, COST_DECODE_NBITS)?;
    Ok(Value::BigInt(decode_compact_bits(compact)))
}

// SGlobal(106).some(9, value: T)[T] -> Option[T]
// EIP-50 v6 Option constructor; wraps the value into a
// non-empty Option. Cost FixedCost(JitCost(5)) per v6.0.2
// `SGlobalMethods.someMethod`. It carries an explicit `[T]` on
// the wire (Seq(tT)), but `Value::Opt` is type-erased at the
// value layer so `type_args` is not needed at runtime (the wire
// byte is consumed by the deserializer), mirroring getReg.
// (Its sibling none(10) takes no value args, so it serializes as
// a 0xDB PropertyCall and is dispatched in
// property_call.rs::eval_no_arg_method, not here.)
pub(super) fn some(args: &[Expr], cx: &mut EvalCtx<'_>) -> Result<Value, EvalError> {
    check_arity(args, 1)?;
    let v = cx.eval_expr(&args[0])?;
    add_method_cost(cx.cost, COST_SOME)?;
    Ok(Value::Opt(Some(Box::new(v))))
}

// SGlobal(106).powHit(8, k: Int, msg: Coll[Byte], nonce: Coll[Byte],
//   h: Coll[Byte], N: Int) -> UnsignedBigInt
// EIP-50 v6 method. Computes the Autolykos-2 PoW hit, matching
// v6.0.2 `Autolykos2PowValidation.hitForVersion2ForMessageWithChecks`
// (requires 2 <= k <= 32 and N >= 16). Monomorphic: no explicit
// type arg on the wire. Cost is the v6.0.2 `PowHitCostKind`,
//   500 + (k + 1) * ((|msg| + |nonce| + |h|) / 128 + 1) * 7
// (chunkSize 128 / perChunk 7 are CalcBlake2b256's; 500 is the
// powHit base), charged before the hit work. Charged via
// `try_from_jit` (not `add_method_cost`) because the value is
// script-controlled and `add_method_cost` would panic on the
// Int.MaxValue overflow edge. Delegates to
// `ergo_crypto::autolykos::v2::hit_for_v2_pow`, the same code the
// block validator's PoW check uses via the `hit_for_v2` wrapper.
pub(super) fn pow_hit(args: &[Expr], cx: &mut EvalCtx<'_>) -> Result<Value, EvalError> {
    check_arity(args, 5)?;
    let k = match cx.eval_expr(&args[0])? {
        Value::Int(v) => v,
        other => {
            return Err(EvalError::TypeError {
                expected: "Int k for SGlobal.powHit",
                got: format!("{other:?}"),
            })
        }
    };
    let msg = match cx.eval_expr(&args[1])? {
        Value::CollBytes(b) => b,
        other => {
            return Err(EvalError::TypeError {
                expected: "Coll[Byte] msg for SGlobal.powHit",
                got: format!("{other:?}"),
            })
        }
    };
    let nonce = match cx.eval_expr(&args[2])? {
        Value::CollBytes(b) => b,
        other => {
            return Err(EvalError::TypeError {
                expected: "Coll[Byte] nonce for SGlobal.powHit",
                got: format!("{other:?}"),
            })
        }
    };
    let h = match cx.eval_expr(&args[3])? {
        Value::CollBytes(b) => b,
        other => {
            return Err(EvalError::TypeError {
                expected: "Coll[Byte] h for SGlobal.powHit",
                got: format!("{other:?}"),
            })
        }
    };
    let n_param = match cx.eval_expr(&args[4])? {
        Value::Int(v) => v,
        other => {
            return Err(EvalError::TypeError {
                expected: "Int N for SGlobal.powHit",
                got: format!("{other:?}"),
            })
        }
    };
    // PowHitCostKind, charged before the (heavy) hit computation.
    let total_len = msg.len() + nonce.len() + h.len();
    let pow_cost = 500i32.wrapping_add(
        k.wrapping_add(1)
            .wrapping_mul((total_len / 128 + 1) as i32)
            .wrapping_mul(7),
    );
    // Scala keeps the wrapped Int in a signed `JitCost`; a negative value only
    // arises for a `k` far outside [2, 32], which the `require` below then
    // rejects. Rust's JitCost is unsigned, so the negative wrap is not charged
    // (the input is rejected either way); it must not surface as a cost
    // overflow, which routes to a different failure class than Scala's.
    if pow_cost >= 0 {
        cx.cost.add(JitCost::try_from_jit(pow_cost as u64)?)?;
    }
    // Scala `hitForVersion2ForMessageWithChecks` bounds: reject
    // (RuntimeException, matching Scala's `require`) rather than
    // compute on out-of-range parameters.
    if pow_cost < 0 || !(2..=32).contains(&k) {
        return Err(EvalError::RuntimeException(
            "SGlobal.powHit: k must be in [2, 32]",
        ));
    }
    if n_param < 16 {
        return Err(EvalError::RuntimeException(
            "SGlobal.powHit: N must be >= 16",
        ));
    }
    let hit =
        ergo_crypto::autolykos::v2::hit_for_v2_pow(k as usize, &msg, &nonce, &h, n_param as u32);
    Ok(Value::UnsignedBigInt(num_bigint::BigInt::from(hit)))
}

// SGlobal(106).deserializeTo(4, bytes: Coll[Byte])[T] -> T
// EIP-50 v6 method, soft-fork-gated, carrying an explicit type
// argument [T] (hasExplicitTypeArgs = Seq(tT)). Decodes `bytes`
// with the *data* serializer (raw typed value bytes) against [T]
// and returns the decoded value -- see the inline note below.
// Cost per sigmastate-interpreter v6.0.2 deserializeCostKind =
// PerItemCost(100, 32, 32).
pub(super) fn deserialize_to(
    args: &[Expr],
    type_args: &[SigmaType],
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    check_arity(args, 1)?;
    let bytes_val = cx.eval_expr(&args[0])?;
    let bytes = match bytes_val {
        Value::CollBytes(b) => b,
        other => {
            return Err(EvalError::TypeError {
                expected: "Coll[Byte] for SGlobal.deserializeTo",
                got: format!("{other:?}"),
            })
        }
    };
    // Scala v6.0.2 `SGlobalMethods.deserializeCostKind`:
    // PerItemCost(baseCost = JitCost(100), perChunkCost = JitCost(32),
    // chunkSize = 32). The node previously carried (30, 20, 32) from
    // the pre-release 6.0-deserialize draft, under-charging deserialize.
    let cost_kind = COST_DESERIALIZE_TO;
    cx.cost.add(cost_kind.compute(bytes.len() as u32)?)?;
    // Scala parity: `SGlobalMethods.deserializeTo_eval` calls
    // `DataSerializer.deserialize(typeArg, reader)`. That is the
    // *data* serializer (raw typed value bytes), not the
    // expression-body serializer used by DeserializeContext.
    // The two formats differ — DataSerializer for SBoolean is
    // a single byte (`!= 0` â‡’ true); for collections it's
    // VLQ-encoded length followed by per-element data. The
    // type to decode against comes from the explicit type
    // argument carried on the MethodCall.
    let target_type = type_args.first().ok_or_else(|| EvalError::TypeError {
        expected: "explicit type argument for SGlobal.deserializeTo",
        got: "no type_args provided".into(),
    })?;
    // SHeader uses the full block-header data format (Scala
    // DataSerializer.deserialize(SHeader) -> ErgoHeader.sigmaSerializer
    // .parse), gated on isV3OrLaterErgoTreeVersion. `read_value` /
    // `sigma_to_value_versioned` handle SHeader and enforce that gate
    // (GHSA-hfj8-hjph-7r78); a pre-v3 ErgoTree calling
    // deserializeTo[SHeader] is rejected here, matching the reference.
    let mut r = ergo_primitives::reader::VlqReader::new(&bytes);
    let parsed = ergo_ser::sigma_value::read_value(&mut r, target_type).map_err(|e| {
        EvalError::TypeError {
            expected: "valid data-serialized value for SGlobal.deserializeTo",
            got: format!("deserialization error: {e}"),
        }
    })?;
    if !r.is_empty() {
        return Err(EvalError::TypeError {
            expected: "fully consumed SGlobal.deserializeTo bytes",
            got: format!("{} trailing bytes", r.remaining()),
        });
    }
    crate::evaluator::helpers::sigma_to_value_versioned(target_type, &parsed, cx.ctx)
}

// SGlobal(106).fromBigEndianBytes(5, bytes: Coll[Byte])[T] -> T
// EIP-50 v6 method, soft-fork-gated. Decodes big-endian
// signed bytes into the requested numeric type `T`. Cost:
// `Fixed(10)` per source. Rejects lengths that don't match
// the target's byte width (1/2/4/8 for Byte/Short/Int/Long;
// 32 for BigInt, matching Scala's signed-256-bit cap).
pub(super) fn from_big_endian_bytes(
    args: &[Expr],
    type_args: &[SigmaType],
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    check_arity(args, 1)?;
    let bytes_val = cx.eval_expr(&args[0])?;
    let bytes = match bytes_val {
        Value::CollBytes(b) => b,
        other => {
            return Err(EvalError::TypeError {
                expected: "Coll[Byte] for SGlobal.fromBigEndianBytes",
                got: format!("{other:?}"),
            })
        }
    };
    let tpe = type_args
        .first()
        .cloned()
        .unwrap_or(ergo_ser::sigma_type::SigmaType::SAny);
    add_method_cost(cx.cost, COST_FROM_BIG_ENDIAN_BYTES)?;
    use ergo_ser::sigma_type::SigmaType as S;
    match tpe {
        S::SByte if bytes.len() == 1 => Ok(Value::Byte(bytes[0] as i8)),
        S::SShort if bytes.len() == 2 => {
            let mut a = [0u8; 2];
            a.copy_from_slice(&bytes);
            Ok(Value::Short(i16::from_be_bytes(a)))
        }
        S::SInt if bytes.len() == 4 => {
            let mut a = [0u8; 4];
            a.copy_from_slice(&bytes);
            Ok(Value::Int(i32::from_be_bytes(a)))
        }
        S::SLong if bytes.len() == 8 => {
            let mut a = [0u8; 8];
            a.copy_from_slice(&bytes);
            Ok(Value::Long(i64::from_be_bytes(a)))
        }
        S::SBigInt if bytes.len() <= 32 => Ok(Value::BigInt(
            num_bigint::BigInt::from_signed_bytes_be(&bytes),
        )),
        // SUnsignedBigInt: UNSIGNED big-endian parse (Scala
        // BigIntegers.fromUnsignedByteArray == new BigInteger(1, bytes),
        // always non-negative). Same <=32-byte cap as SBigInt
        // (SUnsignedBigInt.MaxSizeInBytes = 32). Must NOT use the
        // two's-complement from_signed_bytes_be path.
        S::SUnsignedBigInt if bytes.len() <= 32 => Ok(Value::UnsignedBigInt(
            num_bigint::BigInt::from_bytes_be(num_bigint::Sign::Plus, &bytes),
        )),
        _ => Err(EvalError::TypeError {
            expected: "Coll[Byte] of the target numeric type's exact width",
            got: format!("type={tpe:?}, bytes.len={}", bytes.len()),
        }),
    }
}

// SGlobal(106).xor(2, left: Coll[Byte], right: Coll[Byte]) -> Coll[Byte]
// V5+ method (predates EIP-50). Element-wise XOR, truncates to
// `min(left.len, right.len)` per Scala
// `CollsOverArrays.scala:261`. Functionally identical to the
// inline `0x9B Xor` opcode — same algorithm, different call
// surface. Cost mirrors the inline op (per-item on the
// shorter collection); we charge through the `0x9B` row to
// keep JIT cost parity tests green.
pub(super) fn xor(args: &[Expr], cx: &mut EvalCtx<'_>) -> Result<Value, EvalError> {
    check_arity(args, 2)?;
    let left = cx.eval_expr(&args[0])?;
    let right = cx.eval_expr(&args[1])?;
    let (a, b) = match (left, right) {
        (Value::CollBytes(a), Value::CollBytes(b)) => (a, b),
        (l, r) => {
            return Err(EvalError::TypeError {
                expected: "(Coll[Byte], Coll[Byte]) for SGlobal.xor",
                got: format!("{l:?}, {r:?}"),
            })
        }
    };
    let n = a.len().min(b.len());
    add_cost_per_item(cx.cost, 0x9B, n as u32)?;
    let out: Vec<u8> = a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect();
    Ok(Value::CollBytes(out))
}

// SGlobal(106).serialize(3, value: T) -> Coll[Byte]
// EIP-50 v6 method. v6.0.2 `serializeMethod` is
// `SMethod(.., SFunc(Array(SGlobal, tT), SByteArray, Array(paramT)),
// 3, DynamicCost)`: the `Array(paramT)` is an SFunc type PARAMETER,
// NOT `hasExplicitTypeArgs`, so serialize carries NO wire type byte
// (`type_args` is always empty on real trees). The serialization
// type is the argument's static type (Scala `mc.args(0).tpe`),
// recovered here from the evaluated value via `value_to_typed_sigma`
// — the runtime carriers preserve their static type (`Value::Str`
// keeps SString distinct from `Coll[Byte]`, so SString's cheaper
// length cost is charged correctly), and the only erasures
// (`Value::Opt(None)` -> `SOption(SAny)`, empty `Coll`) are both
// byte- and cost-harmless. Cost is v6.0.2 `DynamicCost` =
// `StartWriterCost` (JitCost 10) once + the sum of `SigmaByteWriter`
// per-put costs `DataSerializer.serialize` emits (`serialize_put_cost`),
// NOT a flat per-item over the output length.
pub(super) fn serialize(args: &[Expr], cx: &mut EvalCtx<'_>) -> Result<Value, EvalError> {
    check_arity(args, 1)?;
    let v = cx.eval_expr(&args[0])?;
    add_method_cost(cx.cost, 10)?;
    let mut w = ergo_primitives::writer::VlqWriter::new();
    serialize_runtime_value(&v, &mut w, cx)?;
    Ok(Value::CollBytes(w.result()))
}

/// Walk runtime containers in write order. Converting a whole tuple first would
/// reject a later unsupported element before charging writes for earlier ones.
fn serialize_runtime_value(
    value: &Value,
    writer: &mut ergo_primitives::writer::VlqWriter,
    cx: &mut EvalCtx<'_>,
) -> Result<(), EvalError> {
    match value {
        Value::Tuple(items) => {
            for item in items {
                serialize_runtime_value(item, writer, cx)?;
            }
        }
        Value::CollGeneric(items, elem_type) | Value::CollLegacyPair(items, elem_type, _) => {
            add_method_cost(cx.cost, 3)?;
            let len = u16::try_from(items.len()).map_err(|_| EvalError::TypeError {
                expected: "collection length <= 65535 for SGlobal.serialize",
                got: items.len().to_string(),
            })?;
            writer.put_u16(len);
            for item in items {
                if let Some(tpe) = crate::evaluator::helpers::value_to_sigma_type(item) {
                    if !crate::evaluator::helpers::sigma_type_compatible(elem_type, &tpe) {
                        return Err(EvalError::TypeError {
                            expected: "element matches CollGeneric elem_type",
                            got: format!("declared {elem_type:?}, found {tpe:?}"),
                        });
                    }
                }
                serialize_runtime_value(item, writer, cx)?;
            }
        }
        Value::Opt(value) => {
            require_serialization_version(
                &SigmaType::SOption(Box::new(SigmaType::SAny)),
                cx.ctx.ergo_tree_version,
            )?;
            add_method_cost(cx.cost, 1)?;
            writer.put_u8(u8::from(value.is_some()));
            if let Some(value) = value {
                serialize_runtime_value(value, writer, cx)?;
            }
        }
        _ => {
            let (tpe, sv) = crate::evaluator::helpers::value_to_typed_sigma(value, Some(cx.ctx))?;
            visit_serialization_puts(&tpe, &sv, cx.ctx.ergo_tree_version, &mut |delta| {
                add_method_cost(cx.cost, delta)
            })?;
            ergo_ser::sigma_value::write_value(writer, &tpe, &sv).map_err(|e| {
                EvalError::TypeError {
                    expected: "serializable value for SGlobal.serialize",
                    got: format!("{e:?}"),
                }
            })?;
        }
    }
    Ok(())
}

fn require_serialization_version(tpe: &SigmaType, version: u8) -> Result<(), EvalError> {
    let expected = match tpe {
        SigmaType::SHeader if version < 3 => "ErgoTree version >= 3 for SHeader serialization",
        SigmaType::SOption(_) if version < 3 => "ErgoTree version >= 3 for SOption serialization",
        SigmaType::SUnsignedBigInt if version < 3 => {
            "ErgoTree version >= 3 for SUnsignedBigInt serialization"
        }
        _ => return Ok(()),
    };
    Err(EvalError::TypeError {
        expected,
        got: format!("ergo_tree_version {version}"),
    })
}

/// Sum the JVM writer callbacks for direct cost-model tests.
#[cfg(test)]
pub(in crate::evaluator) fn serialize_put_cost(
    tpe: &SigmaType,
    sv: &ergo_ser::sigma_value::SigmaValue,
) -> Result<u64, EvalError> {
    let mut total = 0;
    visit_serialization_puts(tpe, sv, 3, &mut |delta| {
        total += delta;
        Ok(())
    })?;
    Ok(total)
}

/// Visit each SigmaByteWriter callback in serialization order. Returning at the
/// first failed charge preserves the charged-to-failure cost at a tight limit.
fn visit_serialization_puts(
    tpe: &SigmaType,
    sv: &ergo_ser::sigma_value::SigmaValue,
    version: u8,
    charge: &mut impl FnMut(u64) -> Result<(), EvalError>,
) -> Result<(), EvalError> {
    use ergo_ser::sigma_type::SigmaType as T;
    use ergo_ser::sigma_value::{CollValue, SigmaValue as Sv};
    require_serialization_version(tpe, version)?;
    match (tpe, sv) {
        (T::SUnit, _) => {}
        (T::SBoolean | T::SByte, _) => charge(1)?,
        (T::SShort | T::SInt | T::SLong, _) => charge(3)?,
        (T::SBigInt, Sv::BigInt(v)) => {
            charge(3)?;
            charge(3 + v.to_signed_bytes_be().len() as u64)?;
        }
        (T::SUnsignedBigInt, Sv::BigInt(v)) => {
            let len = if v.sign() == num_bigint::Sign::NoSign {
                0
            } else {
                v.to_bytes_be().1.len()
            };
            charge(3)?;
            charge(3 + len as u64)?;
        }
        (T::SGroupElement, _) => charge(36)?,
        (T::SString, Sv::Str(s)) => charge(3 + s.len() as u64)?,
        (T::SSigmaProp, Sv::SigmaProp(sb)) => visit_sigma_boolean_puts(sb, charge)?,
        (T::SColl(elem), Sv::Coll(coll)) => {
            charge(3)?;
            match coll {
                CollValue::Bytes(b) => charge(3 + b.len() as u64)?,
                CollValue::BoolBits(bits) => charge(3 + bits.len() as u64)?,
                CollValue::Values(vals) => {
                    for value in vals {
                        visit_serialization_puts(elem, value, version, charge)?;
                    }
                }
            }
        }
        (T::SOption(elem), Sv::Opt(opt)) => {
            charge(1)?;
            if let Some(value) = opt {
                visit_serialization_puts(elem, value, version, charge)?;
            }
        }
        (T::STuple(types), Sv::Tuple(vals)) => {
            for (tpe, value) in types.iter().zip(vals) {
                visit_serialization_puts(tpe, value, version, charge)?;
            }
        }
        (T::SAvlTree, Sv::AvlTree(avl)) => {
            charge(3 + avl.digest.len() as u64)?;
            charge(1)?; // flags; keyLength uses uncharged putUInt
            charge(1)?; // valueLength option tag; its body uses putUInt
        }
        (T::SHeader, Sv::Header(h, _)) => {
            charge(1)?;
            for n in [
                h.parent_id.as_bytes().len(),
                h.ad_proofs_root.as_bytes().len(),
                h.transactions_root.as_bytes().len(),
                h.state_root.as_bytes().len(),
            ] {
                charge(3 + n as u64)?;
            }
            charge(3)?; // timestamp
            charge(3 + h.extension_root.as_bytes().len() as u64)?;
            charge(7)?; // nBits; height uses uncharged putUInt
            charge(3 + h.votes.len() as u64)?;
            if (h.version as i8) > ergo_ser::header::INITIAL_VERSION as i8 {
                charge(1)?;
                charge(3 + h.unparsed_bytes.len() as u64)?;
            }
            match &h.solution {
                ergo_ser::autolykos::AutolykosSolution::V2 { pk, nonce } => {
                    charge(3 + pk.as_bytes().len() as u64)?;
                    charge(3 + nonce.len() as u64)?;
                }
                ergo_ser::autolykos::AutolykosSolution::V1 { pk, w, nonce, d } => {
                    charge(3 + pk.as_bytes().len() as u64)?;
                    charge(3 + w.as_bytes().len() as u64)?;
                    charge(3 + nonce.len() as u64)?;
                    charge(1)?;
                    charge(3 + d.len() as u64)?;
                }
            }
        }
        (T::SBox, Sv::OpaqueBoxBytes(bytes)) => {
            let mut r = ergo_primitives::reader::VlqReader::new(bytes);
            let candidate = ergo_ser::ergo_box::read_ergo_box_candidate(&mut r).map_err(|e| {
                EvalError::TypeError {
                    expected: "parseable SBox bytes for SGlobal.serialize cost",
                    got: format!("box parse error: {e}"),
                }
            })?;
            charge(3)?;
            charge(3 + candidate.ergo_tree_bytes().len() as u64)?;
            charge(1)?;
            for _ in &candidate.tokens {
                charge(35)?;
                charge(3)?;
            }
            charge(1)?;
            let registers = ergo_ser::register::split_register_bytes(candidate.register_bytes())
                .map_err(|e| EvalError::TypeError {
                    expected: "parseable SBox register bytes for SGlobal.serialize cost",
                    got: format!("register split error: {e}"),
                })?;
            for bytes in registers {
                let mut r = ergo_primitives::reader::VlqReader::new(&bytes);
                let expr = ergo_ser::opcode::parse_expr(&mut r, 0, 0).map_err(|e| {
                    EvalError::TypeError {
                        expected: "parseable register value for SGlobal.serialize cost",
                        got: format!("register parse error: {e}"),
                    }
                })?;
                visit_expr_puts(&expr, version, charge)?;
            }
            charge(35)?;
            charge(3)?;
        }
        _ => {
            return Err(EvalError::TypeError {
                expected: "DataSerializer-serializable value for SGlobal.serialize",
                got: format!("{tpe:?}"),
            })
        }
    }
    Ok(())
}

/// TypeSerializer emits one byte callback per encoded type byte.
fn visit_type_puts(
    tpe: &SigmaType,
    charge: &mut impl FnMut(u64) -> Result<(), EvalError>,
) -> Result<(), EvalError> {
    let mut w = ergo_primitives::writer::VlqWriter::new();
    ergo_ser::sigma_type::write_type(&mut w, tpe).map_err(|_| {
        EvalError::RuntimeException("TypeSerializer.serialize: type too large for wire format")
    })?;
    for _ in w.result() {
        charge(1)?;
    }
    Ok(())
}

/// Original register expressions preserve Constant versus CreateTuple encoding.
fn visit_expr_puts(
    expr: &Expr,
    version: u8,
    charge: &mut impl FnMut(u64) -> Result<(), EvalError>,
) -> Result<(), EvalError> {
    use ergo_ser::opcode::{IrNode, Payload};
    match expr {
        Expr::Const { tpe, val } => {
            visit_type_puts(tpe, charge)?;
            visit_serialization_puts(tpe, val, version, charge)?;
        }
        Expr::Op(IrNode {
            opcode: 0x86,
            payload: Payload::Tuple { items },
        }) => {
            charge(1)?;
            charge(1)?;
            for item in items {
                visit_expr_puts(item, version, charge)?;
            }
        }
        Expr::Op(IrNode {
            opcode: 0x83,
            payload: Payload::ConcreteCollection { elem_type, items },
        }) => {
            charge(1)?;
            charge(3)?;
            visit_type_puts(elem_type, charge)?;
            for item in items {
                visit_expr_puts(item, version, charge)?;
            }
        }
        _ => return Err(EvalError::TypeError {
            expected:
                "Constant, CreateTuple, or ConcreteCollection register value for SGlobal.serialize",
            got: format!("{expr:?}"),
        }),
    }
    Ok(())
}

fn visit_sigma_boolean_puts(
    sb: &ergo_ser::sigma_value::SigmaBoolean,
    charge: &mut impl FnMut(u64) -> Result<(), EvalError>,
) -> Result<(), EvalError> {
    use ergo_ser::sigma_value::SigmaBoolean as Sb;
    charge(1)?;
    match sb {
        Sb::TrivialProp(_) => {}
        Sb::ProveDlog(_) => charge(36)?,
        Sb::ProveDHTuple { .. } => {
            for _ in 0..4 {
                charge(36)?;
            }
        }
        Sb::Cand(children) | Sb::Cor(children) => {
            charge(3)?;
            for child in children {
                visit_sigma_boolean_puts(child, charge)?;
            }
        }
        Sb::Cthreshold { children, .. } => {
            charge(3)?;
            charge(3)?;
            for child in children {
                visit_sigma_boolean_puts(child, charge)?;
            }
        }
    }
    Ok(())
}

/// Bitcoin-style "compact" difficulty encoding used by Ergo's
/// `SGlobal.encodeNbits`. Mirrors Scala
/// `sigma/util/NBitsUtils.scala::encodeCompactBits`:
///
/// 1. Take the two's-complement big-endian byte representation.
/// 2. Take the top 3 bytes (left-shift if shorter); these become
///    the 24-bit mantissa.
/// 3. If the mantissa's high bit collides with the sign bit
///    (`& 0x00800000`), shift right by 8 and bump the exponent —
///    keeps the sign bit reserved for the negative-difficulty
///    encoding.
/// 4. Combine: `result = (size << 24) | mantissa | sign_bit`.
fn encode_compact_bits(value: &num_bigint::BigInt) -> i64 {
    let signed = value.to_signed_bytes_be();
    let mut size = signed.len() as i64;
    let mut result: i64 = if size <= 3 {
        // value.longValue << 8 * (3 - size)
        bigint_low_i64(value) << (8 * (3 - size))
    } else {
        // value.shiftRight(8 * (size - 3)).longValue
        let shifted = value >> ((8 * (size - 3)) as usize);
        bigint_low_i64(&shifted)
    };
    if (result & 0x00_80_00_00) != 0 {
        result >>= 8;
        size += 1;
    }
    result |= size << 24;
    if value.sign() == num_bigint::Sign::Minus {
        result |= 0x00_80_00_00;
    }
    result
}

/// Inverse of [`encode_compact_bits`]. Mirrors Scala
/// `sigma/util/NBitsUtils.scala::decodeCompactBits`. Reads the
/// 8-bit `size` exponent from the top byte, takes up to 3 bytes of
/// mantissa from the lower 24 bits, sign-extends, and zero-pads
/// out to `size` bytes. The MSB of the first mantissa byte is the
/// MPI-style sign bit: when set, negate the resulting magnitude.
fn decode_compact_bits(compact: i64) -> num_bigint::BigInt {
    let size = ((compact >> 24) & 0xFF) as usize;
    if size == 0 {
        return num_bigint::BigInt::from(0);
    }
    let mut mantissa = Vec::with_capacity(size);
    if size >= 1 {
        mantissa.push(((compact >> 16) & 0xFF) as u8);
    }
    if size >= 2 {
        mantissa.push(((compact >> 8) & 0xFF) as u8);
    }
    if size >= 3 {
        mantissa.push((compact & 0xFF) as u8);
    }
    // Zero-pad on the right out to `size` total bytes — Scala's
    // `decodeMPI` reads the full length, treating the unread tail
    // as zero (this is the difference between "23 bits of
    // mantissa" and "the mantissa scaled to size bytes").
    while mantissa.len() < size {
        mantissa.push(0);
    }
    let negative = !mantissa.is_empty() && (mantissa[0] & 0x80) != 0;
    if !mantissa.is_empty() {
        mantissa[0] &= 0x7F;
    }
    let mag = num_bigint::BigInt::from_bytes_be(num_bigint::Sign::Plus, &mantissa);
    if negative {
        -mag
    } else {
        mag
    }
}

/// Truncate a `BigInt` to the low 64 bits, matching Java's
/// `BigInteger.longValue()` semantics — wraps around modulo 2^64
/// without panicking on out-of-range values.
fn bigint_low_i64(v: &num_bigint::BigInt) -> i64 {
    use num_traits::ToPrimitive;
    if let Some(x) = v.to_i64() {
        return x;
    }
    // Out-of-range — wrap modulo 2^64 like Java BigInteger.longValue.
    let bytes = v.to_signed_bytes_be();
    let mut buf = [0u8; 8];
    let take = bytes.len().min(8);
    buf[8 - take..].copy_from_slice(&bytes[bytes.len() - take..]);
    i64::from_be_bytes(buf)
}
