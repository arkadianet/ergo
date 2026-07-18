//! `SGlobal` (type_id 106) `0xDC MethodCall` arms: encodeNbits(6),
//! decodeNbits(7), some(9), powHit(8), xor(2), serialize(3), deserializeTo(4),
//! fromBigEndianBytes(5). Also home to the nbits compact-difficulty codec and
//! the `SGlobal.serialize` `DynamicCost` put-cost estimation subsystem
//! (`serialize_put_cost` and its recursive helpers) — both used only by these
//! arms.

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
    let v = match &v_val {
        Value::BigInt(n) => n,
        other => {
            return Err(EvalError::TypeError {
                expected: "BigInt for SGlobal.encodeNbits",
                got: format!("{other:?}"),
            })
        }
    };
    add_method_cost(cx.cost, 25)?;
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
    add_method_cost(cx.cost, 50)?;
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
    add_method_cost(cx.cost, 5)?;
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
    // Scala `hitForVersion2ForMessageWithChecks` bounds: reject
    // (RuntimeException, matching Scala's `require`) rather than
    // compute on out-of-range parameters.
    if !(2..=32).contains(&k) {
        return Err(EvalError::RuntimeException(
            "SGlobal.powHit: k must be in [2, 32]",
        ));
    }
    if n_param < 16 {
        return Err(EvalError::RuntimeException(
            "SGlobal.powHit: N must be >= 16",
        ));
    }
    // PowHitCostKind, charged before the (heavy) hit computation.
    let total_len = msg.len() + nonce.len() + h.len();
    let pow_cost = 500u64 + (k as u64 + 1) * (total_len as u64 / 128 + 1) * 7;
    cx.cost.add(JitCost::try_from_jit(pow_cost)?)?;
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
    let cost_kind = CostKind::PerItem {
        base: JitCost::from_jit(100),
        per_chunk: JitCost::from_jit(32),
        chunk_size: 32,
    };
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
    add_method_cost(cx.cost, 10)?;
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
    let (target_type, sv) = crate::evaluator::helpers::value_to_typed_sigma(&v)?;
    // Scala `DataSerializer.serialize(SHeader)` is gated on
    // `isV3OrLaterErgoTreeVersion` PER materialized header — and the
    // v6 method gate only checks `activatedScriptVersion`, so a tree
    // with `ergo_tree_version < 3` spent post-activation must still
    // reject any header-carrying value here (mirrors the
    // deserializeTo[SHeader] gate, GHSA-hfj8-hjph-7r78). An empty
    // Coll[Header] (no materialized header) is accepted. SAvlTree and
    // the primitives are NOT ergo-tree-version gated.
    if sv.contains_header() && !cx.ctx.is_v3_ergo_tree() {
        return Err(EvalError::TypeError {
            expected: "ErgoTree version >= 3 for SHeader serialization",
            got: format!("ergo_tree_version {}", cx.ctx.ergo_tree_version),
        });
    }
    // `DataSerializer.serialize(SOption)` is gated identically (matches
    // SOption only at isV3OrLaterErgoTreeVersion, else throws). A pre-v3
    // tree building an Option via some/none and serializing it must be
    // rejected. Value-based: an empty Coll[Option] is accepted.
    if sv.contains_option() && !cx.ctx.is_v3_ergo_tree() {
        return Err(EvalError::TypeError {
            expected: "ErgoTree version >= 3 for SOption serialization",
            got: format!("ergo_tree_version {}", cx.ctx.ergo_tree_version),
        });
    }
    // Charged before producing the bytes (Scala charges
    // StartWriterCost up front, then per-put during the write; the
    // total on success is identical). `try_from_jit` is panic-safe.
    let total_cost = 10u64 + serialize_put_cost(&target_type, &sv)?;
    cx.cost.add(JitCost::try_from_jit(total_cost)?)?;
    let mut w = ergo_primitives::writer::VlqWriter::new();
    ergo_ser::sigma_value::write_value(&mut w, &target_type, &sv).map_err(|e| {
        EvalError::TypeError {
            expected: "serializable value for SGlobal.serialize",
            got: format!("{e:?}"),
        }
    })?;
    Ok(Value::CollBytes(w.result()))
}

/// Dynamic-cost (`DynamicCost`) part of `SGlobal.serialize`: the sum of
/// `SigmaByteWriter` per-put JitCost that v6.0.2
/// `DataSerializer.serialize(value, tpe, w)` emits. The caller adds
/// `StartWriterCost` (= 10) on top. Per-put cost model (v6.0.2
/// `SigmaByteWriter`): put(Byte)/putBoolean/putOption-tag = 1;
/// putShort/putInt/putLong = 3; putUShort/putULong = 3; putUInt = 0;
/// putBytes(n)/putBits(n) = `PerItemCost(3,1,1).cost(n)` = 3 + n (for every
/// n, since chunks(0) = 0). SAvlTree and SHeader are modelled here (their
/// `value_to_typed_sigma` arms produce the carriers); SBox serialize is a
/// separate follow-up. `value_to_typed_sigma` still rejects any value with no
/// Scala-anchored serialize bytes, so unsupported carriers never reach here.
pub(in crate::evaluator) fn serialize_put_cost(
    tpe: &ergo_ser::sigma_type::SigmaType,
    sv: &ergo_ser::sigma_value::SigmaValue,
) -> Result<u64, EvalError> {
    use ergo_ser::sigma_type::SigmaType as T;
    use ergo_ser::sigma_value::{CollValue, SigmaValue as Sv};
    let cost = match (tpe, sv) {
        (T::SUnit, _) => 0,
        (T::SBoolean, _) => 1,
        (T::SByte, _) => 1,
        (T::SShort, _) | (T::SInt, _) | (T::SLong, _) => 3,
        // putUShort(len) = 3, then putBytes(byteLen) = 3 + byteLen.
        (T::SBigInt, Sv::BigInt(v)) => 6 + v.to_signed_bytes_be().len() as u64,
        (T::SUnsignedBigInt, Sv::BigInt(v)) => {
            // Unsigned magnitude bytes; zero is encoded as length 0.
            let byte_len = if v.sign() == num_bigint::Sign::NoSign {
                0
            } else {
                v.to_bytes_be().1.len()
            };
            6 + byte_len as u64
        }
        // GroupElementSerializer: putBytes(33).
        (T::SGroupElement, _) => 3 + 33,
        // SString: Scala writes putUInt-NO-INFO(len) (0 cost) + putBytes(n)
        // = 3 + n, strictly cheaper than Coll[Byte]'s putUShort = 6 + n. The
        // distinct `Value::Str` carrier keeps SString from aliasing to
        // Coll[Byte] at the value layer, so this arm (not the Coll one) is
        // taken. Bytes are byte-identical to Coll[Byte] (VLQ length + bytes).
        (T::SString, Sv::Str(s)) => 3 + s.len() as u64,
        (T::SSigmaProp, Sv::SigmaProp(sb)) => sigma_boolean_put_cost(sb),
        // putUShort(len) = 3, then the element body.
        (T::SColl(elem), Sv::Coll(coll)) => {
            3 + match coll {
                CollValue::Bytes(b) => 3 + b.len() as u64,
                CollValue::BoolBits(bits) => 3 + bits.len() as u64,
                CollValue::Values(vals) => {
                    let mut s = 0u64;
                    for x in vals {
                        s += serialize_put_cost(elem, x)?;
                    }
                    s
                }
            }
        }
        // putOption tag (1), then the body iff Some.
        (T::SOption(elem), Sv::Opt(opt)) => {
            1 + match opt {
                Some(inner) => serialize_put_cost(elem, inner)?,
                None => 0,
            }
        }
        // No length prefix; just the concatenated item costs.
        (T::STuple(types), Sv::Tuple(vals)) => {
            let mut s = 0u64;
            for (t, x) in types.iter().zip(vals.iter()) {
                s += serialize_put_cost(t, x)?;
            }
            s
        }
        // AvlTreeData.serializer (mirrors ergo_ser::write_avl_tree):
        //   putBytes(digest 33) = chunk(33)=36 + putUByte(flags)=1
        //   + putUInt(keyLength)=0 + putOption(valueLengthOpt) tag=1
        //   (+ if Some: inner putUInt=0).
        // Constant 38 regardless of flags / keyLength / Some-vs-None, because
        // putUInt costs 0 and the option tag byte is always written.
        (T::SAvlTree, Sv::AvlTree(avl)) => (3 + avl.digest.len() as u64) + 1 + 1,
        // ErgoHeader.sigmaSerializer = HeaderWithoutPowSerializer +
        // AutolykosSolution.sigmaSerializer (mirrors ergo_ser::write_header +
        // write_solution). chunk(n) = 3 + n. put_u8 = 1; put_u64(timestamp) =
        // putULong = 3; put_u32(height) = putUInt = 0 (NOT 3); write_nbits =
        // putBytes(4) = chunk(4). The version>1 block adds putUByte(len)=1 +
        // chunk(unparsedLen). V2 PoW = chunk(pk 33) + chunk(nonce 8); V1 PoW =
        // chunk(pk 33) + chunk(w 33) + chunk(nonce 8) + putUByte(dLen)=1 +
        // chunk(dLen). Charges exactly what write_header/write_solution emit,
        // so cost == bytes for every header version.
        (T::SHeader, Sv::Header(h)) => {
            let chunk = |n: usize| 3 + n as u64;
            let mut c = 1; // put_u8(version)
            c += chunk(h.parent_id.as_bytes().len());
            c += chunk(h.ad_proofs_root.as_bytes().len());
            c += chunk(h.transactions_root.as_bytes().len());
            c += chunk(h.state_root.as_bytes().len());
            c += 3; // put_u64(timestamp) = putULong
            c += chunk(h.extension_root.as_bytes().len());
            c += chunk(4); // write_nbits — 4-byte compact difficulty
                           // put_u32(height) = putUInt = 0 (no charge)
            c += chunk(h.votes.len());
            // Signed-Byte version comparison, matching the header writer
            // (`ergo_ser::header::write_header_without_pow`) so this serialize
            // cost agrees with the bytes actually emitted: a version > 127 is
            // signed-negative, so no unparsed-bytes section is written or
            // charged. (Unreachable: a script can only serialize real context
            // headers, versions 1-4.)
            if (h.version as i8) > ergo_ser::header::INITIAL_VERSION as i8 {
                c += 1; // put_u8(unparsed_bytes.len())
                c += chunk(h.unparsed_bytes.len());
            }
            c += match &h.solution {
                ergo_ser::autolykos::AutolykosSolution::V2 { pk, nonce } => {
                    chunk(pk.as_bytes().len()) + chunk(nonce.len())
                }
                ergo_ser::autolykos::AutolykosSolution::V1 { pk, w, nonce, d } => {
                    chunk(pk.as_bytes().len())
                        + chunk(w.as_bytes().len())
                        + chunk(nonce.len())
                        + 1 // put_u8(d.len())
                        + chunk(d.len())
                }
            };
            c
        }
        // ErgoBox.sigmaSerializer (= ErgoBoxCandidate.
        // serializeBodyWithIndexedDigests + the 32-byte txId and
        // putUShort(index) tail). Mirrors the SigmaByteWriter put-cost
        // sequence exactly (chunk(n) = 3 + n; putULong/putUShort = 3;
        // putUInt = 0; putUByte = 1):
        //   putULong(value)=3 + putBytes(ergoTree)=chunk(treeLen)
        //   + putUInt(height)=0 + putUByte(nTokens)=1
        //   + Σ_tokens [putBytes(id 32)=35 + putULong(amount)=3]
        //   + putUByte(nRegs)=1 + Σ_regs putValue
        //   + putBytes(txId 32)=35 + putUShort(index)=3.
        // The box bytes carried by `OpaqueBoxBytes` are byte-identical to
        // Scala serialize(box) (the InlineBox carrier preserves the verbatim
        // tree and register bytes), so re-parsing recovers the exact structure
        // Scala costs. `read_ergo_box_candidate` leaves txId+index trailing,
        // which the formula charges explicitly.
        (T::SBox, Sv::OpaqueBoxBytes(bytes)) => {
            let chunk = |n: usize| 3 + n as u64;
            let mut r = ergo_primitives::reader::VlqReader::new(bytes);
            let candidate = ergo_ser::ergo_box::read_ergo_box_candidate(&mut r).map_err(|e| {
                EvalError::TypeError {
                    expected: "parseable SBox bytes for SGlobal.serialize cost",
                    got: format!("box parse error: {e}"),
                }
            })?;
            let mut c = 3; // putULong(value)
            c += chunk(candidate.ergo_tree_bytes().len()); // putBytes(ergoTree)
                                                           // putUInt(height) = 0
            c += 1; // putUByte(nTokens)
            c += candidate.tokens.len() as u64 * (chunk(32) + 3); // per token
            c += 1; // putUByte(nRegs)
            let reg_slices = ergo_ser::register::split_register_bytes(candidate.register_bytes())
                .map_err(|e| EvalError::TypeError {
                expected: "parseable SBox register bytes for SGlobal.serialize cost",
                got: format!("register split error: {e}"),
            })?;
            for slice in &reg_slices {
                c += register_put_value_cost(slice)?;
            }
            c += chunk(32); // putBytes(txId)
            c += 3; // putUShort(index)
            c
        }
        _ => {
            return Err(EvalError::TypeError {
                expected: "DataSerializer-serializable value for SGlobal.serialize",
                got: format!("{tpe:?}"),
            })
        }
    };
    Ok(cost)
}

/// JitCost of `TypeSerializer.serialize(tpe)`. Scala writes a serialized type
/// only via `w.put`/`w.putUByte` (each `PutByteCost` = 1), so the cost equals
/// the serialized type's byte length. `ergo_ser::sigma_type::write_type` IS the
/// TypeSerializer encoder, so serialize-and-count is exact for every type
/// (including the pair/triple/quad/tuple-n encodings).
fn type_enc_bytes(tpe: &ergo_ser::sigma_type::SigmaType) -> Result<u64, EvalError> {
    let mut w = ergo_primitives::writer::VlqWriter::new();
    // A type whose length/count overflows Scala's single-byte wire form (e.g. a
    // lossy-decoded STypeVar name > 255 bytes) makes Scala's `putUByte` throw a
    // SerializerException mid-cost; mirror that as a runtime eval failure rather
    // than a panic.
    ergo_ser::sigma_type::write_type(&mut w, tpe).map_err(|_| {
        EvalError::RuntimeException("TypeSerializer.serialize: type too large for wire format")
    })?;
    Ok(w.result().len() as u64)
}

/// JitCost of `SigmaByteWriter.putValue(v)` for a box register value, mirroring
/// `ValueSerializer.serialize`. The register's ORIGINAL bytes decide the
/// encoding — a tuple value can be stored EITHER as a Constant (leading type
/// code <= 0x70) OR as a CreateTuple expression (0x86), and the normalized
/// parsed value loses that distinction — so cost is derived structurally from
/// the parsed expression (`parse_expr` round-trips both forms).
fn register_put_value_cost(bytes: &[u8]) -> Result<u64, EvalError> {
    let mut r = ergo_primitives::reader::VlqReader::new(bytes);
    // Box registers parse with tree_version 0 (`read_register_value`), so a box
    // that already materialized as a value carries registers this parser
    // accepts; re-parsing here cannot spuriously reject.
    let expr = ergo_ser::opcode::parse_expr(&mut r, 0, 0).map_err(|e| EvalError::TypeError {
        expected: "parseable register value for SGlobal.serialize cost",
        got: format!("register parse error: {e}"),
    })?;
    expr_put_value_cost(&expr)
}

/// Recursive `putValue` cost over a parsed register expression. The valid
/// register `EvaluatedValue` forms (Scala: `Constant`, `Tuple`,
/// `ConcreteCollection`) each cost their `ValueSerializer.serialize` puts:
///   - Constant: `ValueSerializer` takes the constant path (no opCode byte) ->
///     `ConstantSerializer` = `putType` + `DataSerializer` =
///     `type_enc_bytes(tpe)` + `serialize_put_cost(tpe, value)`.
///   - CreateTuple (0x86): `put(opCode)` = 1, then `TupleSerializer` writes
///     `putUByte(count)` = 1 and `putValue` per item.
///   - ConcreteCollection (0x83): `put(opCode)` = 1, then
///     `ConcreteCollectionSerializer` writes `putUShort(size)` = 3,
///     `putType(elemType)`, and `putValue` per item.
///
/// All recurse, so nested constants / tuples / collections are costed exactly.
fn expr_put_value_cost(expr: &Expr) -> Result<u64, EvalError> {
    use ergo_ser::opcode::{IrNode, Payload};
    match expr {
        Expr::Const { tpe, val } => Ok(type_enc_bytes(tpe)? + serialize_put_cost(tpe, val)?),
        Expr::Op(IrNode {
            opcode: 0x86,
            payload: Payload::Tuple { items },
        }) => {
            let mut c = 1 + 1; // put(opCode) + putUByte(count)
            for item in items {
                c += expr_put_value_cost(item)?;
            }
            Ok(c)
        }
        // ConcreteCollection is a valid register `EvaluatedValue`
        // (`ConcreteCollection extends EvaluatedCollection extends
        // EvaluatedValue`), so a collection-valued register must be costed, not
        // rejected. `read_register_value` admits only the 0x83 form here (the
        // 0x85 boolean-packed variant is rejected upstream during box parse, so
        // it never reaches this cost path).
        Expr::Op(IrNode {
            opcode: 0x83,
            payload: Payload::ConcreteCollection { elem_type, items },
        }) => {
            // put(opCode)=1 + putUShort(size)=3 + putType(elemType)
            let mut c = 1 + 3 + type_enc_bytes(elem_type)?;
            for item in items {
                c += expr_put_value_cost(item)?;
            }
            Ok(c)
        }
        Expr::Op(IrNode { opcode, .. }) => Err(EvalError::TypeError {
            expected:
                "Constant, CreateTuple, or ConcreteCollection register value for SGlobal.serialize",
            got: format!("register opcode 0x{opcode:02X}"),
        }),
        Expr::Unparsed(_) => Err(EvalError::TypeError {
            expected:
                "Constant, CreateTuple, or ConcreteCollection register value for SGlobal.serialize",
            got: "unparsed-tree body".to_string(),
        }),
    }
}

/// Per-put JitCost for serializing a `SigmaBoolean` via Scala's
/// `SigmaBoolean.serializer`: a 1-byte opCode tag per node, plus
/// `putBytes(33)` = 36 per GroupElement and `putUShort` = 3 per child
/// count (CTHRESHOLD writes both `k` and the count).
fn sigma_boolean_put_cost(sb: &ergo_ser::sigma_value::SigmaBoolean) -> u64 {
    use ergo_ser::sigma_value::SigmaBoolean as Sb;
    match sb {
        Sb::TrivialProp(_) => 1,
        Sb::ProveDlog(_) => 1 + (3 + 33),
        Sb::ProveDHTuple { .. } => 1 + 4 * (3 + 33),
        Sb::Cand(children) | Sb::Cor(children) => {
            1 + 3 + children.iter().map(sigma_boolean_put_cost).sum::<u64>()
        }
        Sb::Cthreshold { children, .. } => {
            1 + 3 + 3 + children.iter().map(sigma_boolean_put_cost).sum::<u64>()
        }
    }
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
