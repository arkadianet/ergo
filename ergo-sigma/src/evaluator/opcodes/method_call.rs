//! `0xDC MethodCall` â€” dispatch on `(type_id, method_id)` to the
//! corresponding type-method handler. Scala charges `MethodCall`
//! overhead (4) at entry plus per-method cost; this module is the
//! single largest opcode in the evaluator.
//!
//! Cost discipline is per-method: each arm calls `add_method_cost(cx.cost, n)`
//! after the dispatcher's `add_cost(cx.cost, 0xDC)`. The two are kept distinct â€”
//! a shared "method overhead" wrapper would silently collapse the per-method
//! cost into the dispatcher cost.

use ergo_primitives::cost::{CostKind, JitCost};
use ergo_ser::opcode::Expr;
use ergo_ser::sigma_type::SigmaType;
use num_integer::Integer;
use num_traits::One;

use super::super::cost::{
    add_cost, add_cost_per_item, add_method_cost, avl_cost_height, collection_len, eq_with_cost,
    try_make_avl_verifier,
};
use super::super::dispatch::eval_expr;
use super::super::eval_ctx::EvalCtx;
use super::super::helpers::{
    coll_elem_type, collection_to_values, sigma_type_compatible, value_to_sigma_type, values_equal,
    values_to_collection, CollKind,
};
use super::super::types::{EvalError, Value};

pub(in crate::evaluator) fn eval_method_call(
    type_id: u8,
    method_id: u8,
    obj: &Expr,
    args: &[Expr],
    type_args: &[ergo_ser::sigma_type::SigmaType],
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    add_cost(cx.cost, 0xDC)?;
    // Soft-fork activation gate for EIP-50 / Sigma 6.0 methods.
    // Scala parity: `MethodCall.evaluate` cross-checks
    // `method.methodVersion` (declared in `_v6Methods`) against
    // `context.activatedScriptVersion`. The table below mirrors the
    // Scala v6 method registry â€” any method-id appearing in `_v6Methods`
    // for a given type-id requires `activatedScriptVersion >= 3` (block
    // header version 4). The (12, 31 | 32) range is fused with
    // 30..=33 since 31 and 32 are the startsWith/endsWith arm. (101, 8)
    // selfBoxIndex stays v5 with its own pre-JIT bug-preservation logic
    // in property_call.rs. (106, 2) Global.xor is V5+ (predates EIP-50).
    if is_v6_method(type_id, method_id) {
        cx.ctx.require_method_version(type_id, method_id, 3)?;
    }
    let obj_val = cx.eval_expr(obj)?;
    match (type_id, method_id) {
        // SCollection(12).indexOf(26) -> Int
        // Cost: PerItemCost(20, 10, 2) charged on actual iterations.
        //
        // Negative `from` clamps to 0 â€” Scala parity. `methods.scala`
        // `indexOf_eval` computes `val start = math.max(from, 0)` and
        // loops from `start`. It does NOT throw. Mirror with
        // `v.max(0) as usize` below.
        (12, 26) => {
            if args.len() != 2 {
                return Err(EvalError::ArityMismatch {
                    expected: 2,
                    got: args.len(),
                });
            }
            let elem = cx.eval_expr(&args[0])?;
            let from = match cx.eval_expr(&args[1])? {
                Value::Int(v) => v.max(0) as usize,
                other => {
                    return Err(EvalError::TypeError {
                        expected: "Int for indexOf from",
                        got: format!("{other:?}"),
                    })
                }
            };
            let (_kind, items) = collection_to_values(obj_val, cx.ctx)?;
            let mut result: i32 = -1;
            let mut iters = 0u32;
            for (i, item) in items.into_iter().enumerate().skip(from) {
                iters += 1;
                // Scala `indexOf_eval` calls `DataValueComparer.equalDataValues`
                // per iteration, charging its cost (e.g. EQ_Prim(3) for a
                // primitive element) inside the addSeqCost loop body.
                if eq_with_cost(&item, &elem, cx.ctx, cx.cost)? {
                    result = i as i32;
                    break;
                }
            }
            let index_of_cost = CostKind::PerItem {
                base: JitCost::from_jit(20),
                per_chunk: JitCost::from_jit(10),
                chunk_size: 2,
            };
            let index_of_delta = index_of_cost.compute(iters)?;
            cx.cost.add(index_of_delta)?;
            #[cfg(feature = "cost-trace")]
            crate::cost_trace::record(
                format!("Method:indexOf(n={})", iters),
                index_of_delta.value(),
                cx.cost.total().value(),
            );
            Ok(Value::Int(result))
        }
        // SCollection(12).zip(29) -> Coll[(A, B)]
        // Cost: PerItemCost(10, 1, 10) charged on xs.length (first collection).
        (12, 29) => {
            if args.len() != 1 {
                return Err(EvalError::ArityMismatch {
                    expected: 1,
                    got: args.len(),
                });
            }
            let ys_val = cx.eval_expr(&args[0])?;
            let n = collection_len(&obj_val, cx.ctx) as u32;
            let zip_cost = CostKind::PerItem {
                base: JitCost::from_jit(10),
                per_chunk: JitCost::from_jit(1),
                chunk_size: 10,
            };
            cx.cost.add(zip_cost.compute(n)?)?;
            // Capture each operand's element type before
            // `collection_to_values` consumes the carrier; the
            // result is `Coll[(A, B)]`, so the carrier is tagged
            // with `STuple(A, B)`.
            let elem_a = coll_elem_type(&obj_val).unwrap_or(SigmaType::SAny);
            let elem_b = coll_elem_type(&ys_val).unwrap_or(SigmaType::SAny);
            let (_kind_a, items_a) = collection_to_values(obj_val, cx.ctx)?;
            let (_kind_b, items_b) = collection_to_values(ys_val, cx.ctx)?;
            let zipped: Vec<Value> = items_a
                .into_iter()
                .zip(items_b)
                .map(|(a, b)| Value::Tuple(vec![a, b]))
                .collect();
            // Outer is Coll[(A, B)] â€” boxed-element coll carrier;
            // each inner element is a real 2-tuple pair (kept as
            // `Value::Tuple`).
            Ok(Value::CollGeneric(
                zipped,
                Box::new(SigmaType::STuple(vec![elem_a, elem_b])),
            ))
        }
        // SColl(12).reverse(30) is a zero-arg method handled by the shared
        // `eval_no_arg_method` table (reachable via 0xDB PropertyCall — the
        // form the compiler emits — and the 0xDC no-arg fallthrough).
        // SColl(12).startsWith(31) / endsWith(32) -> Boolean
        // EIP-50 v6 methods. Scala cost is `Zip_CostKind`
        // (`PerItemCost(10, 1, 10)`) over the prefix/suffix length.
        // Element comparison uses `values_equal` to match the
        // generic-comparison semantics seen elsewhere.
        (12, 31) | (12, 32) => {
            check_arity(args, 1)?;
            let prefix_val = cx.eval_expr(&args[0])?;
            let pn = collection_len(&prefix_val, cx.ctx) as u32;
            let cmp_cost = CostKind::PerItem {
                base: JitCost::from_jit(10),
                per_chunk: JitCost::from_jit(1),
                chunk_size: 10,
            };
            cx.cost.add(cmp_cost.compute(pn)?)?;
            let (_ka, a) = collection_to_values(obj_val, cx.ctx)?;
            let (_kb, b) = collection_to_values(prefix_val, cx.ctx)?;
            if b.len() > a.len() {
                return Ok(Value::Bool(false));
            }
            let offset = if method_id == 31 {
                0
            } else {
                a.len() - b.len()
            };
            for (i, item) in b.iter().enumerate() {
                if !values_equal(&a[offset + i], item, cx.ctx)? {
                    return Ok(Value::Bool(false));
                }
            }
            Ok(Value::Bool(true))
        }
        // SColl(12).get(33) -> SOption[T]
        // EIP-50 v6 method. Bounds-checked indexed access; returns
        // `Some(coll[i])` if in range, else `None`. Scala cost is
        // `ByIndex.costKind` = `Fixed(30)`.
        (12, 33) => {
            check_arity(args, 1)?;
            let idx_val = cx.eval_expr(&args[0])?;
            let idx = match idx_val {
                Value::Int(n) => n,
                other => {
                    return Err(EvalError::TypeError {
                        expected: "Int for SColl.get index",
                        got: format!("{other:?}"),
                    })
                }
            };
            add_method_cost(cx.cost, 30)?;
            let (_kind, items) = collection_to_values(obj_val, cx.ctx)?;
            if idx < 0 || (idx as usize) >= items.len() {
                Ok(Value::Opt(None))
            } else {
                Ok(Value::Opt(Some(Box::new(items[idx as usize].clone()))))
            }
        }
        // SGlobal(106).encodeNbits(6, value: SBigInt) -> SLong
        // EIP-50 v6 method. Encodes a BigInt difficulty target into
        // Bitcoin-style "compact" nbits (3-byte mantissa + 1-byte
        // exponent + sign bit). Cost: `Fixed(25)` per Scala source.
        // Algorithm mirrors
        // `core/.../sigma/util/NBitsUtils.scala::encodeCompactBits`.
        (106, 6) => {
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
        (106, 7) => {
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
        (106, 9) => {
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
        (106, 8) => {
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
            let hit = ergo_crypto::autolykos::v2::hit_for_v2_pow(
                k as usize,
                &msg,
                &nonce,
                &h,
                n_param as u32,
            );
            Ok(Value::UnsignedBigInt(num_bigint::BigInt::from(hit)))
        }
        // SNumericType (Byte=2, Short=3, Int=4, Long=5, BigInt=6) v6
        // bitwise + shift methods. All cost FixedCost(JitCost(5)).
        // Source: `ScorexFoundation/sigmastate-interpreter@6.0-deserialize`
        // `data/.../sigma/ast/methods.scala::SNumericTypeMethods`.
        //
        //   8  bitwiseInverse       (this)              -> tNum
        //   9  bitwiseOr            (this, that: tNum)  -> tNum
        //  10  bitwiseAnd           (this, that: tNum)  -> tNum
        //  11  bitwiseXor           (this, that: tNum)  -> tNum
        //  12  shiftLeft            (this, n: SInt)     -> tNum
        //  13  shiftRight           (this, n: SInt)     -> tNum
        //
        // Semantics mirror Java: Byte/Short are promoted to Int before
        // the shift then narrowed back, mod-32 shift count; Int uses
        // mod-32; Long uses mod-64; BigInt accepts any non-negative
        // shift count and rejects negatives as `RuntimeException` (mirrors
        // Scala's `IllegalArgumentException` from `BigInteger.shiftLeft`).
        // bitwiseInverse (2..=6, 8) is a zero-arg method handled by the shared
        // `eval_no_arg_method` table (reachable via 0xDB PropertyCall — the
        // form the compiler emits — and the 0xDC no-arg fallthrough), so it is
        // intentionally not duplicated here.
        (2..=6, 9) | (2..=6, 10) | (2..=6, 11) => {
            check_arity(args, 1)?;
            let rhs_val = cx.eval_expr(&args[0])?;
            add_method_cost(cx.cost, 5)?;
            let op = method_id; // 9=or, 10=and, 11=xor
            let bin_byte = |a: i8, b: i8| -> i8 {
                match op {
                    9 => a | b,
                    10 => a & b,
                    _ => a ^ b,
                }
            };
            let bin_short = |a: i16, b: i16| -> i16 {
                match op {
                    9 => a | b,
                    10 => a & b,
                    _ => a ^ b,
                }
            };
            let bin_int = |a: i32, b: i32| -> i32 {
                match op {
                    9 => a | b,
                    10 => a & b,
                    _ => a ^ b,
                }
            };
            let bin_long = |a: i64, b: i64| -> i64 {
                match op {
                    9 => a | b,
                    10 => a & b,
                    _ => a ^ b,
                }
            };
            let bin_big = |a: num_bigint::BigInt, b: &num_bigint::BigInt| -> num_bigint::BigInt {
                match op {
                    9 => a | b,
                    10 => a & b,
                    _ => a ^ b,
                }
            };
            match (obj_val, rhs_val) {
                (Value::Byte(a), Value::Byte(b)) => Ok(Value::Byte(bin_byte(a, b))),
                (Value::Short(a), Value::Short(b)) => Ok(Value::Short(bin_short(a, b))),
                (Value::Int(a), Value::Int(b)) => Ok(Value::Int(bin_int(a, b))),
                (Value::Long(a), Value::Long(b)) => Ok(Value::Long(bin_long(a, b))),
                (Value::BigInt(a), Value::BigInt(b)) => Ok(Value::BigInt(bin_big(a, &b))),
                (l, r) => Err(EvalError::TypeError {
                    expected: "matching numeric types for bitwise op",
                    got: format!("{l:?}, {r:?}"),
                }),
            }
        }
        (2..=6, 12) | (2..=6, 13) => {
            check_arity(args, 1)?;
            let n_val = cx.eval_expr(&args[0])?;
            let n = match n_val {
                Value::Int(x) => x,
                other => {
                    return Err(EvalError::TypeError {
                        expected: "Int shift count for shift method",
                        got: format!("{other:?}"),
                    })
                }
            };
            add_method_cost(cx.cost, 5)?;
            let is_left = method_id == 12;
            // Scala ExactIntegral.shiftLeft/shiftRight REJECT an
            // out-of-range count: they throw IllegalArgumentException
            // when `bits < 0 || bits >= width` (Byte 8, Short 16, Int 32,
            // Long 64; BigIntegerOps uses 256 for BigInt). We previously
            // masked the count (n & 31 / n & 63) and so silently accepted
            // out-of-range shifts the reference rejects. With the count
            // validated in range, the shift then matches Java: Byte/Short
            // promote through i32 and truncate; right shift is arithmetic
            // (sign-preserving).
            let width: i32 = match &obj_val {
                Value::Byte(_) => 8,
                Value::Short(_) => 16,
                Value::Int(_) => 32,
                Value::Long(_) => 64,
                Value::BigInt(_) => 256,
                other => {
                    return Err(EvalError::TypeError {
                        expected: "numeric type for shift",
                        got: format!("{other:?}"),
                    })
                }
            };
            if n < 0 || n >= width {
                return Err(EvalError::RuntimeException(
                    "shift count out of range (0 <= bits < bit width)",
                ));
            }
            let shift = n as u32;
            match obj_val {
                Value::Byte(v) => {
                    let promoted = v as i32;
                    let r = if is_left {
                        promoted.wrapping_shl(shift)
                    } else {
                        promoted.wrapping_shr(shift)
                    };
                    Ok(Value::Byte(r as i8))
                }
                Value::Short(v) => {
                    let promoted = v as i32;
                    let r = if is_left {
                        promoted.wrapping_shl(shift)
                    } else {
                        promoted.wrapping_shr(shift)
                    };
                    Ok(Value::Short(r as i16))
                }
                Value::Int(v) => {
                    let r = if is_left {
                        v.wrapping_shl(shift)
                    } else {
                        v.wrapping_shr(shift)
                    };
                    Ok(Value::Int(r))
                }
                Value::Long(v) => {
                    let r = if is_left {
                        v.wrapping_shl(shift)
                    } else {
                        v.wrapping_shr(shift)
                    };
                    Ok(Value::Long(r))
                }
                Value::BigInt(v) => {
                    let amt = shift as usize;
                    let r = if is_left { v << amt } else { v >> amt };
                    Ok(Value::BigInt(r))
                }
                // The `width` match above already rejected non-numeric types.
                other => Err(EvalError::TypeError {
                    expected: "numeric type for shift",
                    got: format!("{other:?}"),
                }),
            }
        }
        // SBox(99).getReg (v5 id 7, v6 id 19; regId: Byte) -> Option[T]
        // Scala v6.0.2 keeps both: getRegMethodV5(7) with no explicit
        // type arg, and getRegMethodV6(19) with hasExplicitTypeArgs.
        // Both share this eval (the explicit `[T]` is parsed at the wire
        // for id 19 but ignored at runtime — see below). v6 id 19 is the
        // soft-fork-gated slot; id 7 is V5+ and ungated.
        // EIP-50 v6 variant of the inline `0xC6 ExtractRegisterAs`.
        // Scala's `SBoxMethods.getRegMethodV6` carries
        // `hasExplicitTypeArgs = Seq(tT)` â€” the type byte parsed at
        // the wire layer is in `type_args[0]` but the
        // evaluator follows the register's actual stored type via
        // `sigma_to_value`, matching Scala's runtime behaviour
        // (the explicit `[T]` is a compile-time hint, not a runtime
        // coercion). Same `Option[T]` shape: R0-R3 mandatory
        // (always Some); R4-R9 additional (may be None).
        (99, 7) | (99, 19) => {
            check_arity(args, 1)?;
            let reg_val = cx.eval_expr(&args[0])?;
            let reg_id = match reg_val {
                Value::Byte(b) => {
                    if b < 0 {
                        return Err(EvalError::TypeError {
                            expected: "Byte in [0, 9] for SBox.getReg register id",
                            got: format!("{b}"),
                        });
                    }
                    b as u8
                }
                other => {
                    return Err(EvalError::TypeError {
                        expected: "Byte register id for SBox.getReg",
                        got: format!("{other:?}"),
                    })
                }
            };
            // Cost mirrors the inline `0xC6 ExtractRegisterAs`
            // dispatch (`add_cost(cx.cost, 0xC6)`) â€” the v6 method
            // variant is the same evaluator work behind a different
            // call site, so charging through the same row keeps the
            // JIT cost parity tests green.
            add_cost(cx.cost, 0xC6)?;
            let b = super::super::helpers::resolve_box(&obj_val, cx.ctx)?;
            super::box_context::read_register_option(b, reg_id, 0xDC, cx.ctx)
        }
        // SContext.getVar (101, 11) is intentionally NOT handled here:
        // it falls through to the catch-all "unsupported MethodCall"
        // reject, matching v6.0.2. `getVarV5Method` (id 11) is V5+
        // (commonMethods) but has NO `.withIRInfo`, so the Scala compiler
        // never lowers `CONTEXT.getVar[T](id)` to a MethodCall; it always
        // emits the inline `0xE3 GetVar` node, which carries T on the
        // wire. A hand-crafted (101, 11) MethodCall has no way to recover
        // T (no explicit type-arg byte; `tT` stays abstract after
        // `specializeFor`), and Scala throws on both eval paths
        // (NoSuchMethodException in the AST interpreter, `throwError` in
        // GraphBuilding) rather than returning None. So rejecting it is
        // the consensus-correct behaviour. (getVarFromInput (101, 12) IS
        // a real v6 MethodCall and is handled just below.)
        // SContext(101).getVarFromInput(12, inputIndex: Short, varId: Byte)[T] -> Option[T]
        // EIP-50 v6 method, new in 6.0 (no v5 inline twin). Reads
        // `tx.inputs(inputIndex).extension.getVar[T](varId)` â€”
        // same exact-type-match rule as `0xE3 GetVar`, just on a
        // different input than SELF. `hasExplicitTypeArgs =
        // Seq(tT)` per Scala source. Returns `None` when the
        // input index is out of range, the var id is missing, or
        // the stored type doesn't match `[T]`.
        (101, 12) => {
            check_arity(args, 2)?;
            let idx_val = cx.eval_expr(&args[0])?;
            let input_idx = match idx_val {
                Value::Short(n) => n,
                other => {
                    return Err(EvalError::TypeError {
                        expected: "Short for SContext.getVarFromInput input index",
                        got: format!("{other:?}"),
                    })
                }
            };
            let var_val = cx.eval_expr(&args[1])?;
            let var_id = match var_val {
                Value::Byte(b) => b as u8,
                other => {
                    return Err(EvalError::TypeError {
                        expected: "Byte for SContext.getVarFromInput var id",
                        got: format!("{other:?}"),
                    })
                }
            };
            let tpe = type_args
                .first()
                .cloned()
                .unwrap_or(ergo_ser::sigma_type::SigmaType::SAny);
            // Cost: identical evaluator work to `0xE3 GetVar`,
            // charge through the same row.
            super::super::cost::add_cost(cx.cost, 0xE3)?;
            // Out-of-range input index â†’ None (Scala silently
            // returns None rather than throwing).
            if input_idx < 0 {
                return Ok(Value::Opt(None));
            }
            let idx = input_idx as usize;
            let Some(ext) = cx.ctx.input_extensions.get(idx) else {
                return Ok(Value::Opt(None));
            };
            match ext.get(&var_id) {
                Some((ext_tpe, ext_val)) if *ext_tpe == tpe => {
                    let val =
                        super::super::helpers::sigma_to_value_versioned(ext_tpe, ext_val, cx.ctx)?;
                    Ok(Value::Opt(Some(Box::new(val))))
                }
                _ => Ok(Value::Opt(None)),
            }
        }
        // SGlobal(106).deserializeTo(4, bytes: Coll[Byte])[T] -> T
        // EIP-50 v6 method, soft-fork-gated, carrying an explicit type
        // argument [T] (hasExplicitTypeArgs = Seq(tT)). Decodes `bytes`
        // with the *data* serializer (raw typed value bytes) against [T]
        // and returns the decoded value -- see the inline note below.
        // Cost per sigmastate-interpreter v6.0.2 deserializeCostKind =
        // PerItemCost(100, 32, 32).
        (106, 4) => {
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
            // The two formats differ â€” DataSerializer for SBoolean is
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
            super::super::helpers::sigma_to_value_versioned(target_type, &parsed, cx.ctx)
        }
        // SGlobal(106).fromBigEndianBytes(5, bytes: Coll[Byte])[T] -> T
        // EIP-50 v6 method, soft-fork-gated. Decodes big-endian
        // signed bytes into the requested numeric type `T`. Cost:
        // `Fixed(10)` per source. Rejects lengths that don't match
        // the target's byte width (1/2/4/8 for Byte/Short/Int/Long;
        // 32 for BigInt, matching Scala's signed-256-bit cap).
        (106, 5) => {
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
                _ => Err(EvalError::TypeError {
                    expected: "Coll[Byte] of the target numeric type's exact width",
                    got: format!("type={tpe:?}, bytes.len={}", bytes.len()),
                }),
            }
        }
        // SHeader(104).checkPow(16) -> Boolean
        // EIP-50 v6 method, soft-fork-gated. Re-verifies Autolykos
        // PoW on the receiver header: Boolean true iff the
        // header's solution satisfies the difficulty target encoded
        // in its `nBits`. Reconstructs an
        // `ergo_ser::header::Header` from the carried `EvalHeader`
        // and delegates to `ergo_crypto::pow::verify_pow_solution`,
        // which is the same code path the validator uses at
        // block-apply time. Cost: `Fixed(700)` per Scala source
        // â€” by far the heaviest method-call cost in the registry,
        // reflecting the hash-and-curve work.
        (104, 16) => {
            check_arity(args, 0)?;
            add_method_cost(cx.cost, 700)?;
            let eh = match &obj_val {
                Value::Header(h) => h.clone(),
                other => {
                    return Err(EvalError::TypeError {
                        expected: "Header for SHeader.checkPow",
                        got: format!("{other:?}"),
                    })
                }
            };
            // Rebuild a serialization-layer `Header` from the evaluator
            // carrier (inverse of `EvalHeader::from_header`) so
            // `verify_pow_solution` sees the same bytes the validator hashed.
            let header = eh.to_header();
            Ok(Value::Bool(
                ergo_crypto::pow::verify_pow_solution(&header).is_ok(),
            ))
        }
        // SGlobal(106).xor(2, left: Coll[Byte], right: Coll[Byte]) -> Coll[Byte]
        // V5+ method (predates EIP-50). Element-wise XOR, truncates to
        // `min(left.len, right.len)` per Scala
        // `CollsOverArrays.scala:261`. Functionally identical to the
        // inline `0x9B Xor` opcode â€” same algorithm, different call
        // surface. Cost mirrors the inline op (per-item on the
        // shorter collection); we charge through the `0x9B` row to
        // keep JIT cost parity tests green.
        (106, 2) => {
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
        (106, 3) => {
            check_arity(args, 1)?;
            let v = cx.eval_expr(&args[0])?;
            let (target_type, sv) = super::super::helpers::value_to_typed_sigma(&v)?;
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
        // SAvlTree(100).contains(9) -> Boolean
        // Args: key (Coll[Byte]), proof (Coll[Byte])
        // Scala `SAvlTreeMethods.containsMethod` â€” same prover/verifier
        // workflow as `get` (cost-shape matches) but returns the
        // presence bit instead of the value. Without this arm any
        // script using `tree.contains(key, proof)` stalls block apply
        // with "expected supported MethodCall, got type_id=100,
        // method_id=9" (testnet h=262,028 tx[2] input 0).
        (100, 9) => {
            if args.len() != 2 {
                return Err(EvalError::ArityMismatch {
                    expected: 2,
                    got: args.len(),
                });
            }
            let avl = match &obj_val {
                Value::AvlTree(a) => a,
                other => {
                    return Err(EvalError::TypeError {
                        expected: "AvlTree for contains",
                        got: format!("{other:?}"),
                    })
                }
            };
            let key = match cx.eval_expr(&args[0])? {
                Value::CollBytes(k) => k,
                other => {
                    return Err(EvalError::TypeError {
                        expected: "Coll[Byte] for AVL key",
                        got: format!("{other:?}"),
                    })
                }
            };
            let proof = match cx.eval_expr(&args[1])? {
                Value::CollBytes(p) => p,
                other => {
                    return Err(EvalError::TypeError {
                        expected: "Coll[Byte] for AVL proof",
                        got: format!("{other:?}"),
                    })
                }
            };
            let create_cost = CostKind::PerItem {
                base: JitCost::from_jit(110),
                per_chunk: JitCost::from_jit(20),
                chunk_size: 64,
            };
            cx.cost.add(create_cost.compute(proof.len() as u32)?)?;
            let lookup_cost = CostKind::PerItem {
                base: JitCost::from_jit(40),
                per_chunk: JitCost::from_jit(10),
                chunk_size: 1,
            };
            // Scala contains_eval (CErgoTreeEvaluator.scala:78-93): a bad
            // proof yields reconstructedTree=None and performLookup ->
            // Failure -> `case Failure(_) => false`. It NEVER throws —
            // construction OR lookup failure both return false, as does a
            // witnessed-absent key (Success(None)). The LookupAvlTree cost is
            // charged over bv.treeHeight, which equals the digest's height
            // byte (rootNodeHeight = startingDigest.last, set BEFORE the proof
            // parse) even on a failed construction — so the lookup cost is the
            // same on both paths.
            cx.cost.add(lookup_cost.compute(avl_cost_height(avl))?)?;
            match try_make_avl_verifier(avl, &proof) {
                Some(mut bv) => match bv.lookup(&key) {
                    Ok(Some(_)) => Ok(Value::Bool(true)),
                    Ok(None) | Err(_) => Ok(Value::Bool(false)),
                },
                None => Ok(Value::Bool(false)),
            }
        }
        // SAvlTree(100).get(10) -> Option[Coll[Byte]]
        // Args: key (Coll[Byte]), proof (Coll[Byte])
        (100, 10) => {
            if args.len() != 2 {
                return Err(EvalError::ArityMismatch {
                    expected: 2,
                    got: args.len(),
                });
            }
            let avl = match &obj_val {
                Value::AvlTree(a) => a,
                other => {
                    return Err(EvalError::TypeError {
                        expected: "AvlTree for get",
                        got: format!("{other:?}"),
                    })
                }
            };
            let key = match cx.eval_expr(&args[0])? {
                Value::CollBytes(k) => k,
                other => {
                    return Err(EvalError::TypeError {
                        expected: "Coll[Byte] for AVL key",
                        got: format!("{other:?}"),
                    })
                }
            };
            let proof = match cx.eval_expr(&args[1])? {
                Value::CollBytes(p) => p,
                other => {
                    return Err(EvalError::TypeError {
                        expected: "Coll[Byte] for AVL proof",
                        got: format!("{other:?}"),
                    })
                }
            };
            // Cost: CreateAvlVerifier(proof.len) + LookupAvlTree(treeHeight)
            let create_cost = CostKind::PerItem {
                base: JitCost::from_jit(110),
                per_chunk: JitCost::from_jit(20),
                chunk_size: 64,
            };
            cx.cost.add(create_cost.compute(proof.len() as u32)?)?;
            let lookup_cost = CostKind::PerItem {
                base: JitCost::from_jit(40),
                per_chunk: JitCost::from_jit(10),
                chunk_size: 1,
            };
            // Scala get_eval (CErgoTreeEvaluator.scala:95-109): charges
            // LookupAvlTree(treeHeight) then performs the lookup; a Failure
            // (bad-proof construction OR a lookup that throws) calls
            // syntax.error -> errored (NOT version-gated). Only a witnessed-
            // absent key (Success(None)) returns None. The LookupAvlTree cost
            // is charged BEFORE the lookup runs (Scala's addSeqCost adds the
            // cost before the block), so it is charged on the construction-
            // failure path too; height = avl_cost_height (digest height on
            // valid metadata/bad proof, 0 for invalid metadata e.g.
            // keyLength==0). (The cost is consensus-inert here since a get
            // failure errors and the tx is rejected, but matching Scala's
            // charge order keeps the accumulator faithful.)
            cx.cost.add(lookup_cost.compute(avl_cost_height(avl))?)?;
            match try_make_avl_verifier(avl, &proof) {
                Some(mut bv) => match bv.lookup(&key) {
                    Ok(Some(v)) => Ok(Value::Opt(Some(Box::new(Value::CollBytes(v))))),
                    Ok(None) => Ok(Value::Opt(None)),
                    Err(_) => Err(EvalError::TypeError {
                        expected: "valid AVL proof for get",
                        got: "proof verification failed".into(),
                    }),
                },
                None => Err(EvalError::TypeError {
                    expected: "valid AVL proof for get",
                    got: "verifier construction failed".into(),
                }),
            }
        }
        // SAvlTree(100).getMany(11) -> Coll[Option[Coll[Byte]]]
        // Args: keys (Coll[Coll[Byte]]), proof (Coll[Byte])
        (100, 11) => {
            if args.len() != 2 {
                return Err(EvalError::ArityMismatch {
                    expected: 2,
                    got: args.len(),
                });
            }
            let avl = match &obj_val {
                Value::AvlTree(a) => a,
                other => {
                    return Err(EvalError::TypeError {
                        expected: "AvlTree for getMany",
                        got: format!("{other:?}"),
                    })
                }
            };
            let keys_val = cx.eval_expr(&args[0])?;
            let keys: Vec<Vec<u8>> = match keys_val {
                // Outer `Coll[Coll[Byte]]` is the boxed-element coll
                // carrier; each inner element is a typed `CollBytes`.
                Value::CollGeneric(items, _) => items
                    .into_iter()
                    .map(|item| match item {
                        Value::CollBytes(k) => Ok(k),
                        other => Err(EvalError::TypeError {
                            expected: "Coll[Byte] in keys",
                            got: format!("{other:?}"),
                        }),
                    })
                    .collect::<Result<_, _>>()?,
                other => {
                    return Err(EvalError::TypeError {
                        expected: "Coll[Coll[Byte]] for AVL keys",
                        got: format!("{other:?}"),
                    })
                }
            };
            let proof = match cx.eval_expr(&args[1])? {
                Value::CollBytes(p) => p,
                other => {
                    return Err(EvalError::TypeError {
                        expected: "Coll[Byte] for AVL proof",
                        got: format!("{other:?}"),
                    })
                }
            };
            // Cost: CreateAvlVerifier(proof.len) + N * LookupAvlTree(treeHeight)
            let create_cost = CostKind::PerItem {
                base: JitCost::from_jit(110),
                per_chunk: JitCost::from_jit(20),
                chunk_size: 64,
            };
            cx.cost.add(create_cost.compute(proof.len() as u32)?)?;
            let lookup_cost = CostKind::PerItem {
                base: JitCost::from_jit(40),
                per_chunk: JitCost::from_jit(10),
                chunk_size: 1,
            };
            // Scala getMany_eval (CErgoTreeEvaluator.scala:111-130): the
            // proof failure is only observed INSIDE the per-key lookup
            // (`keys.map { ... case Failure(_) => syntax.error }`), so a
            // construction failure must NOT abort before the loop — with an
            // empty key list NO lookup runs and the method returns an empty
            // Coll, which Scala accepts. Carry the verifier as an Option and
            // treat a construction failure as a per-key lookup Failure; a
            // Failure (construction OR lookup) errors when a key is processed
            // (NOT version-gated). A witnessed-absent key yields a None
            // element.
            let mut bv_opt = try_make_avl_verifier(avl, &proof);
            let tree_height = avl_cost_height(avl);
            let mut results = Vec::with_capacity(keys.len());
            for key in keys {
                cx.cost.add(lookup_cost.compute(tree_height)?)?;
                let looked = match bv_opt.as_mut() {
                    Some(bv) => bv.lookup(&key),
                    None => Err(()),
                };
                match looked {
                    Ok(Some(v)) => results.push(Value::Opt(Some(Box::new(Value::CollBytes(v))))),
                    Ok(None) => results.push(Value::Opt(None)),
                    Err(_) => {
                        return Err(EvalError::TypeError {
                            expected: "valid AVL proof for getMany",
                            got: "proof verification failed".into(),
                        })
                    }
                }
            }
            // AVL `getMany` returns `Coll[Option[Coll[Byte]]]`; tag
            // the carrier with that exact element type so empty
            // results and serialize-back preserve the right shape.
            Ok(Value::CollGeneric(
                results,
                Box::new(SigmaType::SOption(Box::new(SigmaType::SColl(Box::new(
                    SigmaType::SByte,
                ))))),
            ))
        }
        // SAvlTree(100).update(13) -> Option[AvlTree]
        // Args: entries (Coll[(Coll[Byte], Coll[Byte])]), proof (Coll[Byte])
        (100, 13) => {
            if args.len() != 2 {
                return Err(EvalError::ArityMismatch {
                    expected: 2,
                    got: args.len(),
                });
            }
            let avl = match &obj_val {
                Value::AvlTree(a) => a.clone(),
                other => {
                    return Err(EvalError::TypeError {
                        expected: "AvlTree for update",
                        got: format!("{other:?}"),
                    })
                }
            };
            // Args evaluated before the body (Scala evaluates a MethodCall's
            // args before the method runs), so the flag-deny path still pays
            // the entries+proof eval cost. Outcome/cost in eval_avl_mutate.
            let entries = extract_avl_entries(cx.eval_expr(&args[0])?)?;
            let proof = match cx.eval_expr(&args[1])? {
                Value::CollBytes(p) => p,
                other => {
                    return Err(EvalError::TypeError {
                        expected: "Coll[Byte] for AVL proof",
                        got: format!("{other:?}"),
                    })
                }
            };
            eval_avl_mutate(&avl, entries, &proof, AvlMutOp::Update, cx)
        }
        // SAvlTree(100).insert(12) -> Option[AvlTree]
        (100, 12) => {
            if args.len() != 2 {
                return Err(EvalError::ArityMismatch {
                    expected: 2,
                    got: args.len(),
                });
            }
            let avl = match &obj_val {
                Value::AvlTree(a) => a.clone(),
                other => {
                    return Err(EvalError::TypeError {
                        expected: "AvlTree for insert",
                        got: format!("{other:?}"),
                    })
                }
            };
            // Args evaluated before the body (Scala order) so the flag-deny
            // path still pays the entries+proof eval cost. Outcome (incl. the
            // pre-v3 insert-failure throw) and cost in eval_avl_mutate.
            let entries = extract_avl_entries(cx.eval_expr(&args[0])?)?;
            let proof = match cx.eval_expr(&args[1])? {
                Value::CollBytes(p) => p,
                other => {
                    return Err(EvalError::TypeError {
                        expected: "Coll[Byte] for AVL proof",
                        got: format!("{other:?}"),
                    })
                }
            };
            eval_avl_mutate(&avl, entries, &proof, AvlMutOp::Insert, cx)
        }
        // SAvlTree(100).insertOrUpdate(16) -> Option[AvlTree].
        // EIP-50 v6 method. Mirrors `SAvlTreeMethods.insertOrUpdateMethod`
        // at `methods.scala:1671-1686` â€” inserts new entries OR
        // overwrites existing ones for the same key in a single
        // proof-verified batch. Same args/result shape as
        // `insert` (100,12): `(entries: Coll[(Coll[Byte], Coll[Byte])],
        // proof: Coll[Byte]) -> Option[AvlTree]`.
        //
        // Gating: BOTH `insert_allowed` AND `update_allowed` must be
        // set on the tree, since at evaluation time we don't know
        // whether each key is present (update) or absent (insert).
        // A tree that disables either op can't safely accept an
        // `InsertOrUpdate` batch.
        //
        // Cost model matches `insert`: per-proof create_cost + per-entry
        // insert_cost, computed against the proof bytes and tree height.
        (100, 16) => {
            if args.len() != 2 {
                return Err(EvalError::ArityMismatch {
                    expected: 2,
                    got: args.len(),
                });
            }
            let avl = match &obj_val {
                Value::AvlTree(a) => a.clone(),
                other => {
                    return Err(EvalError::TypeError {
                        expected: "AvlTree for insertOrUpdate",
                        got: format!("{other:?}"),
                    })
                }
            };
            // Args evaluated before the body (Scala order) so the flag-deny
            // path still pays the entries+proof eval cost. insertOrUpdate
            // charges BOTH flag costs and uses the Update cost kind for both
            // paths — handled in eval_avl_mutate.
            let entries = extract_avl_entries(cx.eval_expr(&args[0])?)?;
            let proof = match cx.eval_expr(&args[1])? {
                Value::CollBytes(p) => p,
                other => {
                    return Err(EvalError::TypeError {
                        expected: "Coll[Byte] for AVL proof",
                        got: format!("{other:?}"),
                    })
                }
            };
            eval_avl_mutate(&avl, entries, &proof, AvlMutOp::InsertOrUpdate, cx)
        }
        // SAvlTree(100).remove(14) -> Option[AvlTree]
        (100, 14) => {
            if args.len() != 2 {
                return Err(EvalError::ArityMismatch {
                    expected: 2,
                    got: args.len(),
                });
            }
            let avl = match &obj_val {
                Value::AvlTree(a) => a.clone(),
                other => {
                    return Err(EvalError::TypeError {
                        expected: "AvlTree for remove",
                        got: format!("{other:?}"),
                    })
                }
            };
            // Args evaluated before the body (Scala order) so the flag-deny
            // path still pays the keys+proof eval cost.
            let keys = extract_avl_keys(cx.eval_expr(&args[0])?)?;
            let proof = match cx.eval_expr(&args[1])? {
                Value::CollBytes(p) => p,
                other => {
                    return Err(EvalError::TypeError {
                        expected: "Coll[Byte] for AVL proof",
                        got: format!("{other:?}"),
                    })
                }
            };
            cx.cost.add(JitCost::from_jit(15))?; // isRemoveAllowed
            if !avl.remove_allowed {
                return Ok(Value::Opt(None));
            }
            let create_cost = CostKind::PerItem {
                base: JitCost::from_jit(110),
                per_chunk: JitCost::from_jit(20),
                chunk_size: 64,
            };
            cx.cost.add(create_cost.compute(proof.len() as u32)?)?;
            let remove_cost = CostKind::PerItem {
                base: JitCost::from_jit(100),
                per_chunk: JitCost::from_jit(15),
                chunk_size: 1,
            };
            let mut bv_opt = try_make_avl_verifier(&avl, &proof);
            // treeHeight == digest height byte even on a failed construction.
            let nitems = avl_cost_height(&avl).max(1);
            // Scala remove_eval uses cfor (NOT forall): every key is charged
            // and attempted; per-op results are IGNORED — the outcome is
            // decided solely by the final bv.digest. Never throws.
            for key in &keys {
                cx.cost.add(remove_cost.compute(nitems)?)?;
                if let Some(bv) = bv_opt.as_mut() {
                    let _ = bv.remove(key);
                }
            }
            // remove uniquely charges digest_Info(15) UNCONDITIONALLY after
            // the loop (insert/update/insertOrUpdate do not).
            cx.cost.add(JitCost::from_jit(15))?;
            match bv_opt.as_ref().and_then(|bv| bv.digest()) {
                Some(d) if d.len() == 33 => {
                    cx.cost.add(JitCost::from_jit(40))?; // updateDigest_Info
                    let mut digest_arr = [0u8; 33];
                    digest_arr.copy_from_slice(&d);
                    let mut updated = avl.clone();
                    updated.digest = ergo_primitives::digest::ADDigest::from_bytes(digest_arr);
                    Ok(Value::Opt(Some(Box::new(Value::AvlTree(updated)))))
                }
                _ => Ok(Value::Opt(None)),
            }
        }
        // SColl(12).flatMap(15) -> Coll[B]
        // Scala: xs.flatMap(f) â€” map each element to a collection, flatten results.
        (12, 15) => {
            if args.len() != 1 {
                return Err(EvalError::ArityMismatch {
                    expected: 1,
                    got: args.len(),
                });
            }
            let n = collection_len(&obj_val, cx.ctx);
            add_cost_per_item(cx.cost, 0xDC, n as u32)?;
            let func_val = cx.eval_expr(&args[0])?;
            let (_kind, items) = collection_to_values(obj_val, cx.ctx)?;
            match func_val {
                Value::Func {
                    captured_env,
                    params,
                    param_types: _,
                    body,
                } => {
                    // Collect all inner collections, preserving the raw Value form
                    // so we can reassemble the correct output type.
                    let mut inner_colls: Vec<Value> = Vec::new();
                    for item in items {
                        cx.cost.add(JitCost::from_jit(10))?;
                        let mut call_env = (*captured_env).clone();
                        if let Some(param_id) = params.first() {
                            call_env.insert(*param_id, item);
                        }
                        let inner = eval_expr(
                            &body,
                            cx.ctx,
                            cx.constants,
                            &mut call_env,
                            cx.depth,
                            cx.cost,
                            cx.trace,
                        )?;
                        inner_colls.push(inner);
                    }

                    // Flatten by type: merge all inner collections into one.
                    // The boxed-element coll carrier (`CollGeneric`)
                    // from conditional expressions represents a Coll:
                    // - CollGeneric([])                 â†’ empty Coll (skip)
                    // - CollGeneric([Tuple([CollBytes, Long]), ...]) â†’ Tokens
                    // - CollGeneric([Int, Int, ...])    â†’ CollInt
                    // Normalize these before flattening. The inner
                    // `Tuple(inner)` patterns are real 2-tuple pairs,
                    // intentionally unchanged.
                    for c in inner_colls.iter_mut() {
                        if let Value::CollGeneric(elems, _) = c {
                            if elems.is_empty() {
                                        // Will be removed below
                                    } else if elems.iter().all(|e| matches!(e, Value::Tuple(inner) if inner.len() == 2 && matches!(&inner[0], Value::CollBytes(_)))) {
                                        // CollGeneric of (CollBytes, Long) pairs â†’ Tokens
                                        let tokens: Vec<([u8; 32], u64)> = elems.drain(..).filter_map(|e| {
                                            if let Value::Tuple(mut inner) = e {
                                                if inner.len() == 2 {
                                                    let amount = match inner.pop().unwrap() {
                                                        Value::Long(n) => n as u64,
                                                        Value::Int(n) => n as u64,
                                                        _ => return None,
                                                    };
                                                    if let Value::CollBytes(b) = inner.pop().unwrap() {
                                                        if b.len() == 32 {
                                                            let mut arr = [0u8; 32];
                                                            arr.copy_from_slice(&b);
                                                            return Some((arr, amount));
                                                        }
                                                    }
                                                }
                                            }
                                            None
                                        }).collect();
                                        *c = Value::Tokens(tokens);
                                    }
                        }
                    }
                    // Capture the pre-filter shape so an all-empty
                    // flatMap result preserves the original element
                    // type instead of collapsing to `Coll[Byte]`.
                    let first_shape: Option<Value> = inner_colls.first().map(|v| match v {
                        Value::CollBytes(_) => Value::CollBytes(vec![]),
                        Value::CollShort(_) => Value::CollShort(vec![]),
                        Value::CollInt(_) => Value::CollInt(vec![]),
                        Value::CollLong(_) => Value::CollLong(vec![]),
                        Value::CollBool(_) => Value::CollBool(vec![]),
                        Value::CollSigmaProp(_) => Value::CollSigmaProp(vec![]),
                        Value::CollBox(_) => Value::CollBox(vec![]),
                        Value::CollHeader(_) => Value::CollHeader(vec![]),
                        Value::Tokens(_) => Value::Tokens(vec![]),
                        Value::CollGeneric(_, elem) => Value::CollGeneric(vec![], elem.clone()),
                        _ => Value::CollBytes(vec![]),
                    });
                    inner_colls.retain(|v| !matches!(v, Value::CollGeneric(t, _) if t.is_empty()));
                    if inner_colls.is_empty() {
                        return Ok(first_shape.unwrap_or(Value::CollBytes(vec![])));
                    }
                    match &inner_colls[0] {
                        Value::CollBytes(_) => {
                            let mut out = Vec::new();
                            for c in inner_colls {
                                if let Value::CollBytes(b) = c {
                                    out.extend(b);
                                }
                            }
                            Ok(Value::CollBytes(out))
                        }
                        Value::CollInt(_) => {
                            let mut out = Vec::new();
                            for c in inner_colls {
                                if let Value::CollInt(v) = c {
                                    out.extend(v);
                                }
                            }
                            Ok(Value::CollInt(out))
                        }
                        Value::CollLong(_) => {
                            let mut out = Vec::new();
                            for c in inner_colls {
                                if let Value::CollLong(v) = c {
                                    out.extend(v);
                                }
                            }
                            Ok(Value::CollLong(out))
                        }
                        Value::CollBool(_) => {
                            let mut out = Vec::new();
                            for c in inner_colls {
                                if let Value::CollBool(v) = c {
                                    out.extend(v);
                                }
                            }
                            Ok(Value::CollBool(out))
                        }
                        Value::Tokens(_) => {
                            let mut out = Vec::new();
                            for c in inner_colls {
                                if let Value::Tokens(v) = c {
                                    out.extend(v);
                                }
                            }
                            Ok(Value::Tokens(out))
                        }
                        Value::CollBox(_) => {
                            let mut out = Vec::new();
                            for c in inner_colls {
                                if let Value::CollBox(v) = c {
                                    out.extend(v);
                                }
                            }
                            Ok(Value::CollBox(out))
                        }
                        // Boxed-element coll fallback — flatten all
                        // elements into one `CollGeneric`. Handles
                        // Coll[Coll[Byte]] and any other nested
                        // boxed-element coll. The first inner's
                        // elem_type drives the output tag (all
                        // inners share the same element type under
                        // the IR's static-type system).
                        Value::CollGeneric(_, elem_type) => {
                            let elem_type = elem_type.clone();
                            let mut out = Vec::new();
                            for c in inner_colls {
                                match c {
                                    Value::CollGeneric(elems, _) => out.extend(elems),
                                    other => out.push(other),
                                }
                            }
                            Ok(Value::CollGeneric(out, elem_type))
                        }
                        other => Err(EvalError::TypeError {
                            expected: "collection result from flatMap body",
                            got: format!("{other:?}"),
                        }),
                    }
                }
                _ => Err(EvalError::TypeError {
                    expected: "Func for flatMap",
                    got: format!("{func_val:?}"),
                }),
            }
        }
        // SColl(12).patch(19) -> Coll[T]
        //
        // Scala-parity oracle: sigma-state CollsOverArrays.scala:94-98
        // delegates to `Array[A].patch(from, patch.toArray, replaced)`,
        // which is Scala 2.13's `mutable.ArrayOps.patch$extension`. The
        // bytecode-decoded algorithm (verified against scala-library
        // 2.13.16) is:
        //
        //     chunk1           = if (from > 0) min(from, xs.length) else 0
        //     clampedReplaced  = if (replaced < 0) 0 else replaced
        //     chunk2           = xs.length - chunk1 - clampedReplaced
        //     if (chunk2 > 0):
        //         suffix = xs[xs.length - chunk2 .. xs.length]
        //     else:
        //         suffix = []
        //     result = xs[0..chunk1] ++ patch ++ suffix
        //
        // Negative `from` and negative `replaced` both clamp to 0
        // silently; neither throws. The same shape holds for
        // `immutable.Vector.patch` (default impl in
        // `immutable.StrictOptimizedSeqOps`), which Vector inherits.
        //
        // The Rust form below is equivalent. With `from_u = max(0, from)`
        // and `replaced_u = max(0, replaced)`, the splice region
        // `from_u.min(n) .. (from_u + replaced_u).min(n)` removes exactly
        // `coll[start..end]` where start = chunk1 and end = chunk1 +
        // clampedReplaced (capped at n). The resulting buffer
        // `coll[0..start] ++ patch ++ coll[end..n]` is byte-identical to
        // Scala's `xs[0..chunk1] ++ patch ++ xs[xs.length - chunk2 ..]`
        // for every i32 input pair (oracle-verified, 12 cases incl. i32
        // boundaries). `Coll.updated` is the only method in the Coll
        // family whose Scala backing throws on out-of-range indices â€”
        // see the updated arm below.
        (12, 19) => {
            if args.len() != 3 {
                return Err(EvalError::ArityMismatch {
                    expected: 3,
                    got: args.len(),
                });
            }
            let from_val = cx.eval_expr(&args[0])?;
            let patch_val = cx.eval_expr(&args[1])?;
            let replaced_val = cx.eval_expr(&args[2])?;
            // n.max(0) mirrors Scala's `if (from > 0) ... else 0` /
            // `if (replaced < 0) 0 else replaced` clamp.
            let from = match from_val {
                Value::Int(n) => n.max(0) as usize,
                _ => {
                    return Err(EvalError::TypeError {
                        expected: "Int for patch from",
                        got: format!("{from_val:?}"),
                    })
                }
            };
            let replaced = match replaced_val {
                Value::Int(n) => n.max(0) as usize,
                _ => {
                    return Err(EvalError::TypeError {
                        expected: "Int for patch replaced",
                        got: format!("{replaced_val:?}"),
                    })
                }
            };
            // Scala-anchored cost: sigma-state `methods.scala::PatchMethod`
            // declares `PerItemCost(baseCost = JitCost(30), perChunkCost
            // = JitCost(2), chunkSize = 10)` charged over
            // `xs.length + patch.length`. The prior fallback through
            // `add_cost_per_item(cx.cost, 0xDC, n)` resolved to
            // `Fixed(4)` â€” under-charging vs. Scala (consensus-loosening).
            let xs_len = collection_len(&obj_val, cx.ctx);
            let patch_len = collection_len(&patch_val, cx.ctx);
            let cost_n = (xs_len + patch_len) as u32;
            let patch_cost = CostKind::PerItem {
                base: JitCost::from_jit(30),
                per_chunk: JitCost::from_jit(2),
                chunk_size: 10,
            };
            let patch_delta = patch_cost.compute(cost_n)?;
            cx.cost.add(patch_delta)?;
            #[cfg(feature = "cost-trace")]
            crate::cost_trace::record(
                format!("Method:patch(n={})", cost_n),
                patch_delta.value(),
                cx.cost.total().value(),
            );
            // splice(start..end, patch) yields xs[0..start] ++ patch
            //   ++ xs[end..n], equivalent to Scala chunk1/chunk2 model
            //   above. `from + replaced` cannot overflow usize on
            //   supported targets: both args are clamped to [0,
            //   i32::MAX], so the worst-case sum is 2 * i32::MAX =
            //   4_294_967_294, which fits in u32 (and trivially in
            //   u64).
            match (obj_val, patch_val) {
                (Value::CollBytes(mut coll), Value::CollBytes(patch)) => {
                    let end = (from + replaced).min(coll.len());
                    coll.splice(from.min(coll.len())..end, patch);
                    Ok(Value::CollBytes(coll))
                }
                (Value::CollInt(mut coll), Value::CollInt(patch)) => {
                    let end = (from + replaced).min(coll.len());
                    coll.splice(from.min(coll.len())..end, patch);
                    Ok(Value::CollInt(coll))
                }
                (Value::CollLong(mut coll), Value::CollLong(patch)) => {
                    let end = (from + replaced).min(coll.len());
                    coll.splice(from.min(coll.len())..end, patch);
                    Ok(Value::CollLong(coll))
                }
                (c, p) => Err(EvalError::TypeError {
                    expected: "matching collection types for patch",
                    got: format!("{c:?}, {p:?}"),
                }),
            }
        }
        // SColl(12).updated(20) -> Coll[T]
        // Scala: coll.updated(index, elem) â€” replace element at index.
        // sigma-state's `CollsOverArrays.scala:100-104` delegates to
        // `Array[A].updated(index, elem)`, which throws
        // `IndexOutOfBoundsException` for any `index < 0 || index >= length`.
        // The previous Rust implementation silently no-op'd both cases
        // (negative wrapped to `usize::MAX` via `as usize`, then the
        // implicit `if idx < coll.len()` check skipped the write and
        // returned the original collection).
        //
        // Order of checks below keeps the error class for non-collection
        // receivers as `TypeError`:
        //   1. Eval args, type-check index is `Int`.
        //   2. Charge cost â€” matches Scala's `addSeqCost(costKind,
        //      coll.length, opDesc) { coll.updated(...) }` ordering at
        //      `methods.scala::updated_eval`.
        //   3. Type-check receiver is a `Coll` â€” `TypeError` on miss.
        //   4. Bounds-check index â€” `RuntimeException` on out-of-range.
        //   5. Dispatch by carrier â€” `TypeError` on elem mismatch.
        // The Scala-source citation above is the rejection-parity oracle
        // (sigma-state delegates to Scala stdlib whose Scaladoc pins the
        // throw semantics).
        (12, 20) => {
            if args.len() != 2 {
                return Err(EvalError::ArityMismatch {
                    expected: 2,
                    got: args.len(),
                });
            }
            let idx_val = cx.eval_expr(&args[0])?;
            let elem_val = cx.eval_expr(&args[1])?;
            let idx_i32 = match idx_val {
                Value::Int(n) => n,
                _ => {
                    return Err(EvalError::TypeError {
                        expected: "Int for updated index",
                        got: format!("{idx_val:?}"),
                    })
                }
            };
            // Scala-anchored cost: sigma-state `methods.scala::UpdatedMethod`
            // declares `PerItemCost(baseCost = JitCost(20), perChunkCost
            // = JitCost(1), chunkSize = 10)` charged over `coll.length`.
            // Prior fallback through `add_cost_per_item(cx.cost, 0xDC, n)`
            // resolved to `Fixed(4)` â€” under-charging vs. Scala.
            let n = collection_len(&obj_val, cx.ctx);
            let updated_cost = CostKind::PerItem {
                base: JitCost::from_jit(20),
                per_chunk: JitCost::from_jit(1),
                chunk_size: 10,
            };
            let updated_delta = updated_cost.compute(n as u32)?;
            cx.cost.add(updated_delta)?;
            #[cfg(feature = "cost-trace")]
            crate::cost_trace::record(
                format!("Method:updated(n={})", n),
                updated_delta.value(),
                cx.cost.total().value(),
            );
            // Receiver type-gate. `collection_len` returns 0 for
            // non-collections, which would make the bounds-check below
            // fire RuntimeException for any idx â€” wrong error class.
            // Filter here so the dispatch below only sees real Colls.
            //
            // Scala-sigma's `Coll[T].updated` accepts any element-typed
            // collection (`CollsOverArrays.scala:100-104` delegates to
            // `Array[A].updated` for any `A`). The allow-list covers
            // every Coll carrier the Value enum can represent with a
            // strict element-type check: primitives
            // (CollBytes/Short/Int/Long/Bool), strictly-typed boxed
            // carriers (CollSigmaProp, CollHeader), special-shape
            // carriers (CollBox, Tokens), and the source-ref box
            // carrier (BoxCollection â€” produced by INPUTS, OUTPUTS,
            // dataInputs).
            //
            // `Value::Tuple` (real fixed-arity STuple) is permanently
            // excluded â€” tuples are not collections in Scala-sigma,
            // and STuple field replacement is not an EIP-50 method.
            // `Value::CollGeneric` is the boxed-element coll carrier
            // (Coll[Tuple], Coll[Header], nested colls); accepted
            // here because Scala's `Coll[A].updated` is generic over
            // any `A`. The element-type compatibility is trusted to
            // the script-load type-check â€” runtime simply replaces
            // the box at the index.
            if !matches!(
                obj_val,
                Value::CollBytes(_)
                    | Value::CollShort(_)
                    | Value::CollInt(_)
                    | Value::CollLong(_)
                    | Value::CollBool(_)
                    | Value::CollSigmaProp(_)
                    | Value::CollHeader(_)
                    | Value::CollBox(_)
                    | Value::Tokens(_)
                    | Value::BoxCollection(_)
                    | Value::CollGeneric(_, _)
            ) {
                return Err(EvalError::TypeError {
                    expected: "Coll for updated receiver",
                    got: format!("{obj_val:?}"),
                });
            }
            if idx_i32 < 0 || (idx_i32 as usize) >= n {
                return Err(EvalError::RuntimeException(
                    "Coll.updated: index out of bounds",
                ));
            }
            let idx = idx_i32 as usize;
            match (obj_val, elem_val) {
                // CollBytes accepts a Byte element â€” the natural carrier
                // produced by `eval_by_index` on a Coll[Byte] (see
                // collection.rs:118). Scala-sigma's typed dispatch
                // accepts `Coll[Byte].updated(i, e: Byte)` and the
                // Rust evaluator must match: a natural ErgoScript like
                // `bytes.updated(0, otherBytes(0))` cannot otherwise
                // round-trip a single byte without a manual
                // `toInt`/`toByte` dance the script author never wrote.
                //
                // Strict Byte-only: no `(CollBytes, Int)` arm. Scala's
                // typed dispatch on `Coll[Byte].updated` pins the
                // element to `SByte`, so a hand-built ErgoTree
                // presenting an `Int` element falls through to the
                // mismatch arm below and TypeErrors â€” matching Scala
                // rejection semantics.
                (Value::CollBytes(mut coll), Value::Byte(v)) => {
                    coll[idx] = v as u8;
                    Ok(Value::CollBytes(coll))
                }
                (Value::CollShort(mut coll), Value::Short(v)) => {
                    coll[idx] = v;
                    Ok(Value::CollShort(coll))
                }
                (Value::CollInt(mut coll), Value::Int(v)) => {
                    coll[idx] = v;
                    Ok(Value::CollInt(coll))
                }
                (Value::CollLong(mut coll), Value::Long(v)) => {
                    coll[idx] = v;
                    Ok(Value::CollLong(coll))
                }
                (Value::CollBool(mut coll), Value::Bool(v)) => {
                    coll[idx] = v;
                    Ok(Value::CollBool(coll))
                }
                (Value::CollSigmaProp(mut coll), Value::SigmaProp(v)) => {
                    coll[idx] = v;
                    Ok(Value::CollSigmaProp(coll))
                }
                (Value::CollHeader(mut coll), Value::Header(v)) => {
                    coll[idx] = *v;
                    Ok(Value::CollHeader(coll))
                }
                // CollBox accepts any box-typed value: BoxRef (from
                // INPUTS/OUTPUTS-derived collections), SelfBox (the
                // current input), or InlineBox (from OpaqueBoxBytes
                // constants). Other variants fall through to the
                // TypeError arm below.
                (
                    Value::CollBox(mut coll),
                    elem @ (Value::BoxRef { .. } | Value::SelfBox | Value::InlineBox(_)),
                ) => {
                    coll[idx] = elem;
                    Ok(Value::CollBox(coll))
                }
                // BoxCollection (INPUTS / OUTPUTS / dataInputs source-
                // ref carrier) materializes through collection_to_values
                // into a `Vec<Value::BoxRef>`, then rebuilds as
                // CollBox. Scala-sigma treats these as first-class
                // Coll[Box], so `INPUTS.updated(0, SELF)` must work
                // here.
                (
                    obj @ Value::BoxCollection(_),
                    elem @ (Value::BoxRef { .. } | Value::SelfBox | Value::InlineBox(_)),
                ) => {
                    let (_kind, mut items) = collection_to_values(obj, cx.ctx)?;
                    items[idx] = elem;
                    Ok(Value::CollBox(items))
                }
                // Tokens stores canonical (TokenId, Long) pairs. The
                // typical update path is `tokens.updated(i,
                // (idBytes, amt))` where the element matches the
                // canonical 32-byte+Long shape â€” preserve as Tokens.
                //
                // For mismatched shapes (non-32-byte id, non-Long
                // amount, or wrong arity), `values_to_collection`'s
                // Token-fallback at helpers.rs degrades to
                // `Value::CollGeneric` (the boxed-element coll
                // carrier). Scala-sigma's generic
                // `Coll[(Coll[Byte], Long)].updated` accepts any
                // compatible element-typed tuple; rejecting on
                // non-canonical shape would be stricter than Scala.
                (Value::Tokens(coll), Value::Tuple(parts)) => {
                    // Re-materialize via collection_to_values so the
                    // existing Tuple<->Tokens reconciliation logic
                    // in values_to_collection drives the shape
                    // decision uniformly.
                    let mut items: Vec<Value> = coll
                        .into_iter()
                        .map(|(id, amt)| {
                            Value::Tuple(vec![
                                Value::CollBytes(id.to_vec()),
                                Value::Long(amt as i64),
                            ])
                        })
                        .collect();
                    items[idx] = Value::Tuple(parts);
                    let token_elem_type = SigmaType::STuple(vec![
                        SigmaType::SColl(Box::new(SigmaType::SByte)),
                        SigmaType::SLong,
                    ]);
                    values_to_collection(CollKind::Token, items, token_elem_type)
                }
                // `CollGeneric` is the boxed-element coll carrier:
                // `Coll[Tuple]`, `Coll[Header]`, `Coll[Option[_]]`,
                // nested colls, AVL batch result. Scala's
                // `Coll[A].updated` is generic over `A`. The carrier-
                // tagged `elem_type` is the IR-pinned `A`; the
                // runtime defends against malformed ErgoTree bytes
                // by recovering the replacement's `SigmaType` via
                // `value_to_sigma_type` (exhaustive over runtime
                // variants — handles `Opt`, `Header`, real `Tuple`,
                // nested `CollGeneric`) and requiring equality
                // against the carrier's `elem_type`.
                (Value::CollGeneric(mut coll, elem_type), elem) => {
                    let elem_ty = value_to_sigma_type(&elem).ok_or(EvalError::TypeError {
                        expected: "element with recoverable SigmaType for Coll.updated",
                        got: format!("{elem:?}"),
                    })?;
                    // `sigma_type_compatible` treats `SAny` as a
                    // wildcard so `Value::Opt(None)` (which can only
                    // surface its inner as `SAny`) flows through a
                    // carrier tagged `SOption(concreteT)` — matching
                    // Scala's `Coll[Option[T]].updated(i, None)`.
                    if !sigma_type_compatible(&elem_type, &elem_ty) {
                        return Err(EvalError::TypeError {
                            expected: "matching element type for Coll.updated",
                            got: format!("{elem_type:?} vs {elem_ty:?}"),
                        });
                    }
                    coll[idx] = elem;
                    Ok(Value::CollGeneric(coll, elem_type))
                }
                (c, e) => Err(EvalError::TypeError {
                    expected: "matching collection/element types for updated",
                    got: format!("{c:?}, {e:?}"),
                }),
            }
        }
        // SCollection(12).updateMany(21) -> Coll[T]
        // Scala `CollOverArray.updateMany(indexes, values)`
        // (CollsOverArrays.scala): `requireSameLength(indexes, values)`
        // (throws on length mismatch), clone the receiver, then for each i
        // set `resArr[indexes[i]] = values[i]` — an index `< 0 || >= len`
        // throws IndexOutOfBoundsException; duplicate indexes are allowed
        // (processed in order, last write wins). Cost is
        // `PerItemCost(baseCost=20, perChunkCost=2, chunkSize=10)` charged
        // over the RECEIVER length (methods.scala UpdateManyMethod /
        // updateMany_eval `addSeqCost(costKind, coll.length)`).
        (12, 21) => {
            if args.len() != 2 {
                return Err(EvalError::ArityMismatch {
                    expected: 2,
                    got: args.len(),
                });
            }
            // Capture the receiver's element type and length before
            // `collection_to_values` consumes the carrier. A non-collection
            // receiver has no element type -> reject (matches the
            // type-checked surface; `collection_len` would otherwise return
            // 0 and mis-class the error).
            let elem_type = coll_elem_type(&obj_val).ok_or(EvalError::TypeError {
                expected: "Coll for updateMany receiver",
                got: format!("{obj_val:?}"),
            })?;
            let n = collection_len(&obj_val, cx.ctx);
            let indexes_val = cx.eval_expr(&args[0])?;
            let values_val = cx.eval_expr(&args[1])?;
            // PerItemCost(20,2,10) over the receiver length, charged before
            // the operation (matches Scala addSeqCost wrapping the block).
            let delta = CostKind::PerItem {
                base: JitCost::from_jit(20),
                per_chunk: JitCost::from_jit(2),
                chunk_size: 10,
            }
            .compute(n as u32)?;
            cx.cost.add(delta)?;
            #[cfg(feature = "cost-trace")]
            crate::cost_trace::record(
                format!("Method:updateMany(n={n})"),
                delta.value(),
                cx.cost.total().value(),
            );
            // Decompose `indexes` as a generic collection rather than
            // requiring the `CollInt` carrier up front. Scala's JIT erases
            // the static `Coll[Int]` type, so a malformed-but-deserializable
            // tree whose indexes carrier is empty with a non-Int element type
            // (e.g. `Coll[Long]()`) still passes `requireSameLength` and the
            // zero-iteration loop, returning the receiver clone. Each index
            // is cast to Int only when READ (Scala `indexes(i)` -> Int, a
            // ClassCastException on a non-Int element).
            let (_ikind, index_vals) = collection_to_values(indexes_val, cx.ctx)?;
            let (kind, mut items) = collection_to_values(obj_val, cx.ctx)?;
            let (_vkind, values) = collection_to_values(values_val, cx.ctx)?;
            // requireSameLength(indexes, values) — IllegalArgumentException.
            if index_vals.len() != values.len() {
                return Err(EvalError::RuntimeException(
                    "Coll.updateMany: indexes and values length mismatch",
                ));
            }
            for (idx_val, val) in index_vals.into_iter().zip(values) {
                let pos = match idx_val {
                    Value::Int(n) => n,
                    other => {
                        return Err(EvalError::TypeError {
                            expected: "Int index for updateMany",
                            got: format!("{other:?}"),
                        })
                    }
                };
                if pos < 0 || pos as usize >= items.len() {
                    return Err(EvalError::RuntimeException(
                        "Coll.updateMany: index out of bounds",
                    ));
                }
                // Each WRITTEN value must be assignable to the receiver's
                // element type. Scala's `Coll[A]` is backed by `Array[A]`, so
                // storing a value of a different type throws ArrayStoreException
                // (the values:Coll[A] signature is otherwise enforced at type-
                // check time). We mirror that per write — using the SAny-aware
                // `sigma_type_compatible` so `Coll[Option[T]].updateMany(_,
                // [None])` (None erases to SOption(SAny)) still passes. An
                // empty values collection writes nothing, so it is accepted
                // regardless of its declared element type — matching Scala.
                let val_ty = value_to_sigma_type(&val).ok_or(EvalError::TypeError {
                    expected: "element with recoverable SigmaType for updateMany",
                    got: format!("{val:?}"),
                })?;
                if !sigma_type_compatible(&elem_type, &val_ty) {
                    return Err(EvalError::TypeError {
                        expected: "matching element type for updateMany",
                        got: format!("{elem_type:?} vs {val_ty:?}"),
                    });
                }
                items[pos as usize] = val;
            }
            // `values_to_collection` rebuilds the receiver's carrier (the
            // written elements are already type-checked above).
            values_to_collection(kind, items, elem_type)
        }
        // SOption(36).map(7) -> Option[B]
        // Scala: opt.map(f) â€” apply f to value if Some, return None if None.
        // `SOption.MapMethod.costKind = FixedCost(JitCost(20))`; applying the
        // lambda to a Some value additionally charges AddToEnv(5) when the
        // argument is bound (same per-application overhead as every other HOF
        // lambda invocation, e.g. MapCollection). None applies no lambda.
        (36, 7) => {
            if args.len() != 1 {
                return Err(EvalError::ArityMismatch {
                    expected: 1,
                    got: args.len(),
                });
            }
            add_method_cost(cx.cost, 20)?;
            let func_val = cx.eval_expr(&args[0])?;
            match obj_val {
                Value::Opt(None) => Ok(Value::Opt(None)),
                Value::Opt(Some(inner)) => match func_val {
                    Value::Func {
                        captured_env,
                        params,
                        param_types: _,
                        body,
                    } => {
                        cx.cost.add(JitCost::from_jit(5))?;
                        #[cfg(feature = "cost-trace")]
                        crate::cost_trace::record("AddToEnv", 5, cx.cost.total().value());
                        let mut call_env = (*captured_env).clone();
                        if let Some(param_id) = params.first() {
                            call_env.insert(*param_id, *inner);
                        }
                        let result = eval_expr(
                            &body,
                            cx.ctx,
                            cx.constants,
                            &mut call_env,
                            cx.depth,
                            cx.cost,
                            cx.trace,
                        )?;
                        Ok(Value::Opt(Some(Box::new(result))))
                    }
                    _ => Err(EvalError::TypeError {
                        expected: "Func for Option.map",
                        got: format!("{func_val:?}"),
                    }),
                },
                _ => Err(EvalError::TypeError {
                    expected: "Option for map",
                    got: format!("{obj_val:?}"),
                }),
            }
        }
        // SOption(36).filter(8) -> Option[T]
        (36, 8) => {
            if args.len() != 1 {
                return Err(EvalError::ArityMismatch {
                    expected: 1,
                    got: args.len(),
                });
            }
            add_method_cost(cx.cost, 10)?;
            let func_val = cx.eval_expr(&args[0])?;
            match obj_val {
                Value::Opt(None) => Ok(Value::Opt(None)),
                Value::Opt(Some(inner)) => match func_val {
                    Value::Func {
                        captured_env,
                        params,
                        param_types: _,
                        body,
                    } => {
                        let mut call_env = (*captured_env).clone();
                        if let Some(param_id) = params.first() {
                            call_env.insert(*param_id, *inner.clone());
                        }
                        let result = eval_expr(
                            &body,
                            cx.ctx,
                            cx.constants,
                            &mut call_env,
                            cx.depth,
                            cx.cost,
                            cx.trace,
                        )?;
                        match result {
                            Value::Bool(true) => Ok(Value::Opt(Some(inner))),
                            Value::Bool(false) => Ok(Value::Opt(None)),
                            _ => Err(EvalError::TypeError {
                                expected: "Bool from Option.filter predicate",
                                got: format!("{result:?}"),
                            }),
                        }
                    }
                    _ => Err(EvalError::TypeError {
                        expected: "Func for Option.filter",
                        got: format!("{func_val:?}"),
                    }),
                },
                _ => Err(EvalError::TypeError {
                    expected: "Option for filter",
                    got: format!("{obj_val:?}"),
                }),
            }
        }
        // SBigInt(6).toUnsigned(14) -> UnsignedBigInt
        // SBigInt(6).toUnsignedMod(15, m: UnsignedBigInt) -> UnsignedBigInt
        // Sigma 6.0 conversions from signed â†’ unsigned. Scala costs:
        //   ToUnsigned     FixedCost(JitCost(5)) â€” methods.scala:545-546
        //   ToUnsignedMod  FixedCost(JitCost(15)) â€” methods.scala:552-553
        // toUnsigned: errors if `this` is negative (caller bug; the
        // unsigned type can't represent it). toUnsignedMod: reduces
        // any signed value modulo `m`, always producing a value in
        // [0, m). `m` must be non-zero.
        // SBigInt.toUnsigned (6, 14) is a zero-arg method handled by the shared
        // `eval_no_arg_method` table (reachable via 0xDB PropertyCall).
        (6, 15) => {
            check_arity(args, 1)?;
            let signed = expect_bigint(&obj_val, "SBigInt.toUnsignedMod receiver")?;
            let m_val = cx.eval_expr(&args[0])?;
            let m = expect_unsigned_bigint(&m_val, "SBigInt.toUnsignedMod modulus")?;
            add_method_cost(cx.cost, 15)?;
            if m.sign() == num_bigint::Sign::NoSign {
                return Err(EvalError::RuntimeException(
                    "SBigInt.toUnsignedMod: modulus is zero",
                ));
            }
            // Mathematical mod: result is always in [0, m). Rust's `%`
            // returns a value with sign matching the dividend, so for
            // negative `signed` we add `m` to bring it into range.
            let r = signed % m;
            let result = if r.sign() == num_bigint::Sign::Minus {
                r + m
            } else {
                r
            };
            Ok(Value::UnsignedBigInt(result))
        }
        // SUnsignedBigInt(9) v6 bitwise/shift methods, INHERITED from
        // SNumericTypeMethods.v6Methods (SUnsignedBigIntMethods extends
        // SNumericTypeMethods). All FixedCost(JitCost(5)), no type args.
        //   8 bitwiseInverse  9 bitwiseOr  10 bitwiseAnd  11 bitwiseXor
        //   12 shiftLeft       13 shiftRight
        // Unlike SBigInt (signed two's-complement), these operate on the
        // UNSIGNED 256-bit domain: bitwiseInverse is the masked complement
        // (2^256-1) XOR n (Scala `CUnsignedBigInt.bitwiseInverse` flips a
        // fixed 32-byte array), and shiftLeft/shiftRight hard-reject a
        // count outside [0, 256) and reject a shiftLeft result exceeding
        // 256 bits (CUnsignedBigInt's ctor throws), rather than masking
        // the count the way the fixed-width (2..=6, 12|13) arms do.
        // SUnsignedBigInt.bitwiseInverse (9, 8) is a zero-arg method handled by
        // the shared `eval_no_arg_method` table (reachable via 0xDB
        // PropertyCall), so it is intentionally not duplicated here.
        (9, 9) | (9, 10) | (9, 11) => {
            check_arity(args, 1)?;
            let a = expect_unsigned_bigint(&obj_val, "SUnsignedBigInt bitwise receiver")?.clone();
            let b_val = cx.eval_expr(&args[0])?;
            let b = expect_unsigned_bigint(&b_val, "SUnsignedBigInt bitwise operand")?;
            add_method_cost(cx.cost, 5)?;
            // Inputs are in [0, 2^256); or/and/xor stay in range (no mask).
            let r = match method_id {
                9 => a | b,
                10 => a & b,
                _ => a ^ b,
            };
            Ok(Value::UnsignedBigInt(r))
        }
        (9, 12) => {
            check_arity(args, 1)?;
            let a = expect_unsigned_bigint(&obj_val, "SUnsignedBigInt.shiftLeft receiver")?.clone();
            let bits = match cx.eval_expr(&args[0])? {
                Value::Int(x) => x,
                other => {
                    return Err(EvalError::TypeError {
                        expected: "Int shift count for SUnsignedBigInt.shiftLeft",
                        got: format!("{other:?}"),
                    })
                }
            };
            add_method_cost(cx.cost, 5)?;
            if !(0..256).contains(&bits) {
                return Err(EvalError::RuntimeException(
                    "SUnsignedBigInt.shiftLeft: shift count out of range [0, 256)",
                ));
            }
            let r = a << bits as usize;
            if r.bits() > 256 {
                return Err(EvalError::RuntimeException(
                    "SUnsignedBigInt.shiftLeft: result exceeds 256 bits",
                ));
            }
            Ok(Value::UnsignedBigInt(r))
        }
        (9, 13) => {
            check_arity(args, 1)?;
            let a =
                expect_unsigned_bigint(&obj_val, "SUnsignedBigInt.shiftRight receiver")?.clone();
            let bits = match cx.eval_expr(&args[0])? {
                Value::Int(x) => x,
                other => {
                    return Err(EvalError::TypeError {
                        expected: "Int shift count for SUnsignedBigInt.shiftRight",
                        got: format!("{other:?}"),
                    })
                }
            };
            add_method_cost(cx.cost, 5)?;
            if !(0..256).contains(&bits) {
                return Err(EvalError::RuntimeException(
                    "SUnsignedBigInt.shiftRight: shift count out of range [0, 256)",
                ));
            }
            // Logical shift (receiver >= 0, no sign extension).
            Ok(Value::UnsignedBigInt(a >> bits as usize))
        }
        // SUnsignedBigInt(9) v6 modular-arithmetic methods. Costs
        // per methods.scala:574-609 â€” fixed costs (no per-bit scaling
        // in Scala for these operations either).
        //   14 modInverse   FixedCost(JitCost(150))  (this, m)
        //   15 plusMod      FixedCost(JitCost(30))   (this, that, m)
        //   16 subtractMod  FixedCost(JitCost(30))   (this, that, m)
        //   17 multiplyMod  FixedCost(JitCost(40))   (this, that, m)
        //   18 mod          FixedCost(JitCost(20))   (this, m)
        //   19 toSigned     FixedCost(JitCost(10))   (this)
        (9, 14) => {
            check_arity(args, 1)?;
            let a = expect_unsigned_bigint(&obj_val, "SUnsignedBigInt.modInverse receiver")?;
            let m_val = cx.eval_expr(&args[0])?;
            let m = expect_unsigned_bigint(&m_val, "SUnsignedBigInt.modInverse modulus")?;
            add_method_cost(cx.cost, 150)?;
            // Java's BigInteger.modInverse throws on a non-positive modulus;
            // guard m == 0 here so a crafted `modInverse(1, 0)` rejects the
            // transaction instead of panicking on `1 % 0` below.
            if m.sign() == num_bigint::Sign::NoSign {
                return Err(EvalError::RuntimeException(
                    "SUnsignedBigInt.modInverse: modulus is zero",
                ));
            }
            // num-bigint provides modpow but not modinverse directly.
            // Use the extended Euclidean algorithm: if gcd(a, m) = 1,
            // the Bezout coefficient for `a` is the inverse mod m.
            let egcd = a.extended_gcd(m);
            if !egcd.gcd.is_one() {
                return Err(EvalError::RuntimeException(
                    "SUnsignedBigInt.modInverse: receiver not coprime with modulus",
                ));
            }
            let r = egcd.x % m;
            let inv = if r.sign() == num_bigint::Sign::Minus {
                r + m
            } else {
                r
            };
            Ok(Value::UnsignedBigInt(inv))
        }
        (9, 15) => {
            check_arity(args, 2)?;
            let a = expect_unsigned_bigint(&obj_val, "SUnsignedBigInt.plusMod receiver")?;
            let b_val = cx.eval_expr(&args[0])?;
            let b = expect_unsigned_bigint(&b_val, "SUnsignedBigInt.plusMod addend")?;
            let m_val = cx.eval_expr(&args[1])?;
            let m = expect_unsigned_bigint(&m_val, "SUnsignedBigInt.plusMod modulus")?;
            add_method_cost(cx.cost, 30)?;
            if m.sign() == num_bigint::Sign::NoSign {
                return Err(EvalError::RuntimeException(
                    "SUnsignedBigInt.plusMod: modulus is zero",
                ));
            }
            Ok(Value::UnsignedBigInt((a + b) % m))
        }
        (9, 16) => {
            check_arity(args, 2)?;
            let a = expect_unsigned_bigint(&obj_val, "SUnsignedBigInt.subtractMod receiver")?;
            let b_val = cx.eval_expr(&args[0])?;
            let b = expect_unsigned_bigint(&b_val, "SUnsignedBigInt.subtractMod subtrahend")?;
            let m_val = cx.eval_expr(&args[1])?;
            let m = expect_unsigned_bigint(&m_val, "SUnsignedBigInt.subtractMod modulus")?;
            add_method_cost(cx.cost, 30)?;
            if m.sign() == num_bigint::Sign::NoSign {
                return Err(EvalError::RuntimeException(
                    "SUnsignedBigInt.subtractMod: modulus is zero",
                ));
            }
            // (a - b) mod m â€” unsigned semantics: if a < b, the
            // difference is negative; add m to wrap into [0, m).
            let diff = a - b;
            let r = diff % m;
            let result = if r.sign() == num_bigint::Sign::Minus {
                r + m
            } else {
                r
            };
            Ok(Value::UnsignedBigInt(result))
        }
        (9, 17) => {
            check_arity(args, 2)?;
            let a = expect_unsigned_bigint(&obj_val, "SUnsignedBigInt.multiplyMod receiver")?;
            let b_val = cx.eval_expr(&args[0])?;
            let b = expect_unsigned_bigint(&b_val, "SUnsignedBigInt.multiplyMod multiplier")?;
            let m_val = cx.eval_expr(&args[1])?;
            let m = expect_unsigned_bigint(&m_val, "SUnsignedBigInt.multiplyMod modulus")?;
            add_method_cost(cx.cost, 40)?;
            if m.sign() == num_bigint::Sign::NoSign {
                return Err(EvalError::RuntimeException(
                    "SUnsignedBigInt.multiplyMod: modulus is zero",
                ));
            }
            Ok(Value::UnsignedBigInt((a * b) % m))
        }
        (9, 18) => {
            check_arity(args, 1)?;
            let a = expect_unsigned_bigint(&obj_val, "SUnsignedBigInt.mod receiver")?;
            let m_val = cx.eval_expr(&args[0])?;
            let m = expect_unsigned_bigint(&m_val, "SUnsignedBigInt.mod modulus")?;
            add_method_cost(cx.cost, 20)?;
            if m.sign() == num_bigint::Sign::NoSign {
                return Err(EvalError::RuntimeException(
                    "SUnsignedBigInt.mod: modulus is zero",
                ));
            }
            Ok(Value::UnsignedBigInt(a % m))
        }
        // SUnsignedBigInt.toSigned (9, 19) is a zero-arg method handled by the
        // shared `eval_no_arg_method` table (reachable via 0xDB PropertyCall).
        // SGroupElement(7).exp(6, e: UnsignedBigInt) -> GroupElement
        // Scala `SGroupElementMethods.ExponentiateUnsignedMethod`
        // (EIP-50 / v6Methods, confirmed by disassembly of
        // `sigma/ast/SGroupElementMethods$.class` â€” method id 6).
        // Semantics: same EC scalar multiplication as the inline
        // 0x9F `Exponentiate` opcode, but the exponent carrier is
        // `SUnsignedBigInt` rather than `SBigInt`. Because the
        // unsigned value is already in [0, 2^256), the signed
        // Euclidean correction needed in 0x9F is unnecessary â€”
        // `Scalar::reduce` over the 256-bit big-endian magnitude
        // is the canonical reduction mod the secp256k1 group order.
        // Cost matches `Exponentiate.costKind` = `FixedCost(900)`.
        (7, 6) => {
            check_arity(args, 1)?;
            let ge_bytes = match &obj_val {
                Value::GroupElement(b) => *b,
                other => {
                    return Err(EvalError::TypeError {
                        expected: "GroupElement for SGroupElement.exp(unsigned)",
                        got: format!("{other:?}"),
                    })
                }
            };
            let exp_val = cx.eval_expr(&args[0])?;
            let exp = match exp_val {
                Value::UnsignedBigInt(n) => n,
                other => {
                    return Err(EvalError::TypeError {
                        expected: "UnsignedBigInt for SGroupElement.exp(unsigned) exponent",
                        got: format!("{other:?}"),
                    })
                }
            };
            add_method_cost(cx.cost, 900)?;

            use k256::elliptic_curve::group::GroupEncoding;
            use k256::elliptic_curve::ops::Reduce;
            use k256::Scalar;

            let point = super::sigma::decode_group_element(&ge_bytes)?;
            let (_, exp_bytes) = exp.to_bytes_be();
            let mut scalar_bytes = [0u8; 32];
            let take = exp_bytes.len().min(32);
            scalar_bytes[32 - take..].copy_from_slice(&exp_bytes[exp_bytes.len() - take..]);
            let wide = k256::U256::from_be_slice(&scalar_bytes);
            let scalar = Scalar::reduce(wide);
            let result = point * scalar;
            let result_bytes = result.to_bytes();
            let mut out = [0u8; 33];
            out.copy_from_slice(&result_bytes);
            Ok(Value::GroupElement(out))
        }
        // Fall through to the shared no-arg method table for any
        // (type_id, method_id) the args-using arms above did not
        // claim. This dedupes the header / preheader / global / AVL
        // property logic that otherwise lives in two places. The table
        // is NO-arg only, so enforce arity here: a no-arg method invoked
        // with arguments is malformed and must error (preserving the
        // `check_arity(args, 0)` the moved bitwiseInverse / toUnsigned /
        // toSigned / reverse arms used to enforce — a 0xDC MethodCall
        // carrying extra args must not silently ignore them).
        _ => match super::property_call::eval_no_arg_method(
            type_id, method_id, &obj_val, cx.ctx, cx.cost,
        )? {
            // The shared table is NO-arg only: if it claims this method but the
            // 0xDC MethodCall carried arguments, the tree is malformed — error
            // on arity (preserving the `check_arity(args, 0)` the moved
            // bitwiseInverse / toUnsigned / toSigned / reverse arms enforced, so
            // extra args are never silently ignored). Methods the table does NOT
            // claim (e.g. SContext.getVar, which legitimately takes args) fall
            // through to the unsupported-MethodCall error regardless of arity.
            Some(_) if !args.is_empty() => Err(EvalError::ArityMismatch {
                expected: 0,
                got: args.len(),
            }),
            Some(v) => Ok(v),
            None => Err(EvalError::TypeError {
                expected: "supported MethodCall",
                got: format!("type_id={}, method_id={}", type_id, method_id),
            }),
        },
    }
}

// ----- EIP-50 v6 method registry -----

/// Returns `true` if `(type_id, method_id)` is a Sigma 6.0 / EIP-50
/// method requiring `activatedScriptVersion >= 3`. Mirrors the Scala
/// `_v6Methods` declarations across `sigma/ast/methods.scala` â€”
/// specifically:
///
/// * `SNumericTypeMethods._v6Methods` (Byte=2, Short=3, Int=4, Long=5,
///   BigInt=6): bitwiseInverse(8), bitwiseOr(9), bitwiseAnd(10),
///   bitwiseXor(11), shiftLeft(12), shiftRight(13).
/// * `SBigIntMethods._v6Methods`: toUnsigned(14), toUnsignedMod(15).
/// * `SGroupElementMethods._v6Methods`: exp(6) with `UnsignedBigInt`
///   exponent (existing exp(5) with `BigInt` exponent stays v5).
/// * `SUnsignedBigIntMethods` (entire type, 9): inherited numeric
///   bitwiseInverse(8) through shiftRight(13), plus its own modular
///   modInverse(14) through toSigned(19).
/// * `SCollectionMethods._v6Methods`: reverse(30), startsWith(31),
///   endsWith(32), get(33). (No `distinct` exists in Scala v6.0.2.)
/// * `SBoxMethods._v6Methods`: getReg(19) (getRegMethodV5 id 7 is V5+).
/// * `SContextMethods._v6Methods`: getVarFromInput(12) only. getVar
///   (id 11) is V5+ (commonMethods), NOT v6-gated.
/// * `SHeaderMethods._v6Methods`: checkPow(16).
/// * `SGlobalMethods._v6Methods`: serialize(3), deserializeTo(4),
///   fromBigEndianBytes(5), encodeNbits(6), decodeNbits(7), powHit(8),
///   some(9), none(10).
///   (Global.xor(2) predates EIP-50 â€” V5+, not gated here.)
///
/// (12, 26)/(12, 29) `indexOf`/`updateMany`, (36, *) Option methods,
/// the V5+ SAvlTree methods (`contains` / `get` / `getMany` /
/// `insert` / `update` / `remove` / `updateDigest` etc.),
/// (101, 8) `selfBoxIndex`, and (106, 2) `Global.xor` are V5+ and
/// intentionally not listed. The only v6 addition to SAvlTree â€”
/// `insertOrUpdate` (100, 16) â€” IS listed below.
pub(super) fn is_v6_method(type_id: u8, method_id: u8) -> bool {
    match (type_id, method_id) {
        // SNumericType bitwise + shifts
        (2..=6, 8..=13) => true,
        // SBigInt â†’ unsigned conversions
        (6, 14) | (6, 15) => true,
        // SGroupElement.exp with UnsignedBigInt exponent
        (7, 6) => true,
        // SUnsignedBigInt: inherited numeric bitwise/shift (8..=13) +
        // its own modular arithmetic (14..=19). All v6 / EIP-50.
        (9, 8..=19) => true,
        // SCollection reverse/startsWith/endsWith/get
        (12, 30..=33) => true,
        // SBox.getReg v6 slot (getRegMethodV5 id 7 is V5+, ungated)
        (99, 19) => true,
        // SAvlTree.insertOrUpdate (v6 â€” methods.scala:1671-1686).
        // Pre-v6 SAvlTree methods stay non-gated (caller already
        // pre-v6 callable).
        (100, 16) => true,
        // SContext.getVarFromInput (v6-only). getVar (id 11) is V5+
        // (commonMethods), so it is NOT gated here.
        (101, 12) => true,
        // SHeader.checkPow
        (104, 16) => true,
        // SGlobal: serialize, deserializeTo, fromBigEndianBytes,
        // encodeNbits, decodeNbits, powHit(8), some(9), none(10).
        (106, 3..=10) => true,
        _ => false,
    }
}

// ----- helpers for the SBigInt/SUnsignedBigInt v6 methods -----

fn check_arity(args: &[Expr], expected: usize) -> Result<(), EvalError> {
    if args.len() != expected {
        return Err(EvalError::ArityMismatch {
            expected,
            got: args.len(),
        });
    }
    Ok(())
}

/// Decoded `Coll[(Coll[Byte], Coll[Byte])]` AVL insert/update entries.
type AvlEntries = Vec<(Vec<u8>, Vec<u8>)>;

/// The three batch-mutating SAvlTree operations that take a
/// `Coll[(Coll[Byte], Coll[Byte])]` of key/value entries.
#[derive(Clone, Copy)]
enum AvlMutOp {
    Insert,
    Update,
    InsertOrUpdate,
}

/// Extract `Coll[(Coll[Byte], Coll[Byte])]` entries from an evaluated value
/// (the outer collection is the boxed-element `CollGeneric` carrier; each
/// inner element is a real 2-tuple `Value::Tuple`).
fn extract_avl_entries(v: Value) -> Result<AvlEntries, EvalError> {
    match v {
        Value::CollGeneric(items, _) => items
            .into_iter()
            .map(|item| match item {
                Value::Tuple(pair) if pair.len() == 2 => {
                    let mut it = pair.into_iter();
                    let k = match it.next().unwrap() {
                        Value::CollBytes(k) => k,
                        other => {
                            return Err(EvalError::TypeError {
                                expected: "Coll[Byte] for AVL entry key",
                                got: format!("{other:?}"),
                            })
                        }
                    };
                    let v = match it.next().unwrap() {
                        Value::CollBytes(v) => v,
                        other => {
                            return Err(EvalError::TypeError {
                                expected: "Coll[Byte] for AVL entry value",
                                got: format!("{other:?}"),
                            })
                        }
                    };
                    Ok((k, v))
                }
                other => Err(EvalError::TypeError {
                    expected: "(Coll[Byte], Coll[Byte]) AVL entry",
                    got: format!("{other:?}"),
                }),
            })
            .collect(),
        other => Err(EvalError::TypeError {
            expected: "Coll[(Coll[Byte], Coll[Byte])] AVL entries",
            got: format!("{other:?}"),
        }),
    }
}

/// Extract `Coll[Coll[Byte]]` keys from an evaluated value.
fn extract_avl_keys(v: Value) -> Result<Vec<Vec<u8>>, EvalError> {
    match v {
        Value::CollGeneric(items, _) => items
            .into_iter()
            .map(|item| match item {
                Value::CollBytes(k) => Ok(k),
                other => Err(EvalError::TypeError {
                    expected: "Coll[Byte] in AVL keys",
                    got: format!("{other:?}"),
                }),
            })
            .collect(),
        other => Err(EvalError::TypeError {
            expected: "Coll[Coll[Byte]] AVL keys",
            got: format!("{other:?}"),
        }),
    }
}

/// Shared insert/update/insertOrUpdate evaluation, mirroring Scala
/// `CErgoTreeEvaluator.{insert,update,insertOrUpdate}_eval`. The caller must
/// have already evaluated (and thereby charged) the `entries`/`proof` args
/// — Scala evaluates a MethodCall's args before the body, so the flag-deny
/// path still pays the arg-eval cost.
///
/// Cost (all JitCost): flag check(s) FixedCost(15) each (insertOrUpdate
/// charges BOTH isUpdate + isInsert = 30) BEFORE the boolean guard;
/// CreateAvlVerifier PerItemCost(110,20,64) over `proof.len`; per-entry op
/// cost (InsertIntoAvlTree(40,10,1) for insert, UpdateAvlTree(120,20,1) for
/// update AND insertOrUpdate) over `max(treeHeight,1)`, charged BEFORE the
/// per-entry validity check (so a failed entry is charged); updateDigest_Info
/// FixedCost(40) only on success.
///
/// Outcome: a flag-disabled tree returns None. Construction failure (bad
/// proof) and any op failure (bad key, wrong value-length) make the verifier
/// degrade — insert is the ONLY version-gated op (pre-v3 failure → errored;
/// v3+ → None); update/insertOrUpdate always return None on failure. Success
/// returns Some(tree.updateDigest(...)). Entries are processed with a
/// forall-style short-circuit after the first failing entry.
fn eval_avl_mutate(
    avl: &ergo_ser::sigma_value::AvlTreeData,
    entries: AvlEntries,
    proof: &[u8],
    op: AvlMutOp,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    // Flag *_Info cost(s) charged before the guard (insertOrUpdate needs both).
    match op {
        AvlMutOp::Insert => {
            cx.cost.add(JitCost::from_jit(15))?;
            if !avl.insert_allowed {
                return Ok(Value::Opt(None));
            }
        }
        AvlMutOp::Update => {
            cx.cost.add(JitCost::from_jit(15))?;
            if !avl.update_allowed {
                return Ok(Value::Opt(None));
            }
        }
        AvlMutOp::InsertOrUpdate => {
            cx.cost.add(JitCost::from_jit(15))?; // isUpdateAllowed
            cx.cost.add(JitCost::from_jit(15))?; // isInsertAllowed
            if !avl.update_allowed || !avl.insert_allowed {
                return Ok(Value::Opt(None));
            }
        }
    }
    let create_cost = CostKind::PerItem {
        base: JitCost::from_jit(110),
        per_chunk: JitCost::from_jit(20),
        chunk_size: 64,
    };
    cx.cost.add(create_cost.compute(proof.len() as u32)?)?;
    let op_cost = match op {
        AvlMutOp::Insert => CostKind::PerItem {
            base: JitCost::from_jit(40),
            per_chunk: JitCost::from_jit(10),
            chunk_size: 1,
        },
        AvlMutOp::Update | AvlMutOp::InsertOrUpdate => CostKind::PerItem {
            base: JitCost::from_jit(120),
            per_chunk: JitCost::from_jit(20),
            chunk_size: 1,
        },
    };
    let mut bv_opt = try_make_avl_verifier(avl, proof);
    // nItems = max(treeHeight,1); treeHeight == the digest's height byte even
    // on a failed construction (rootNodeHeight is set before the proof parse).
    let nitems = avl_cost_height(avl).max(1);
    let mut all_ok = true;
    for (key, value) in entries {
        // Per-entry op cost charged before the validity check.
        cx.cost.add(op_cost.compute(nitems)?)?;
        let ok = match bv_opt.as_mut() {
            Some(bv) => {
                // Pre-validate the value length to avoid the crate's op-time
                // assert! panic; a mismatch is the same op failure scrypto's
                // require() raises.
                if avl
                    .value_length_opt
                    .is_some_and(|vl| value.len() != vl as usize)
                {
                    false
                } else {
                    match op {
                        AvlMutOp::Insert => bv.insert(&key, &value).is_ok(),
                        AvlMutOp::Update => bv.update(&key, &value).is_ok(),
                        AvlMutOp::InsertOrUpdate => bv.insert_or_update(&key, &value).is_ok(),
                    }
                }
            }
            None => false, // construction failed
        };
        if !ok {
            all_ok = false;
            break; // forall short-circuit
        }
    }
    // Any op OR construction failure makes scrypto's topNode None -> digest
    // None -> the method returns None. Do NOT consult bv.digest() on failure:
    // a value-length failure is caught by the pre-check WITHOUT running the
    // op, so the verifier's topNode/digest is still the pre-failure value —
    // but Scala's failed performInsert/Update would have nulled it. And
    // updateDigest_Info(40) is charged only on success, so it's skipped here.
    if !all_ok {
        // insert is the ONLY version-gated op: a failed insert on a pre-v3
        // ErgoTree throws (syntax.error). `activated_script_version < 3`
        // implies the ErgoTree version is < 3 (a v3 tree cannot be spent
        // before v3 activation), so the throw is correct for that case.
        // PRE-EXISTING GAP (tracked): a legacy ErgoTree-v<3 box spent in a
        // post-activation (activated>=3) block — Scala throws but we return
        // None — needs the ErgoTree header version threaded into the eval
        // context (the same version-threading gap as getReg / SOption-pre-v3
        // / SHeader); the old no-gate code had this gap too.
        if matches!(op, AvlMutOp::Insert) && cx.ctx.activated_script_version < 3 {
            return Err(EvalError::RuntimeException(
                "AvlTree.insert failed on a pre-v3 ErgoTree",
            ));
        }
        return Ok(Value::Opt(None));
    }
    match bv_opt.as_ref().and_then(|bv| bv.digest()) {
        Some(d) if d.len() == 33 => {
            cx.cost.add(JitCost::from_jit(40))?; // updateDigest_Info (success only)
            let mut digest_arr = [0u8; 33];
            digest_arr.copy_from_slice(&d);
            let mut updated = avl.clone();
            updated.digest = ergo_primitives::digest::ADDigest::from_bytes(digest_arr);
            Ok(Value::Opt(Some(Box::new(Value::AvlTree(updated)))))
        }
        _ => Ok(Value::Opt(None)),
    }
}

fn expect_bigint<'a>(
    v: &'a Value,
    where_used: &'static str,
) -> Result<&'a num_bigint::BigInt, EvalError> {
    match v {
        Value::BigInt(n) => Ok(n),
        other => Err(EvalError::TypeError {
            expected: where_used,
            got: format!("{other:?}"),
        }),
    }
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
        (T::SAvlTree, Sv::AvlTree(avl)) => (3 + avl.digest.as_bytes().len() as u64) + 1 + 1,
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
            if h.version > ergo_ser::header::INITIAL_VERSION {
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
fn type_enc_bytes(tpe: &ergo_ser::sigma_type::SigmaType) -> u64 {
    let mut w = ergo_primitives::writer::VlqWriter::new();
    ergo_ser::sigma_type::write_type(&mut w, tpe);
    w.result().len() as u64
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
        Expr::Const { tpe, val } => Ok(type_enc_bytes(tpe) + serialize_put_cost(tpe, val)?),
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
            let mut c = 1 + 3 + type_enc_bytes(elem_type);
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

fn expect_unsigned_bigint<'a>(
    v: &'a Value,
    where_used: &'static str,
) -> Result<&'a num_bigint::BigInt, EvalError> {
    match v {
        Value::UnsignedBigInt(n) => Ok(n),
        other => Err(EvalError::TypeError {
            expected: where_used,
            got: format!("{other:?}"),
        }),
    }
}

// ----- helpers for SGlobal nbits (Bitcoin-style compact encoding) -----

/// Bitcoin-style "compact" difficulty encoding used by Ergo's
/// `SGlobal.encodeNbits`. Mirrors Scala
/// `sigma/util/NBitsUtils.scala::encodeCompactBits`:
///
/// 1. Take the two's-complement big-endian byte representation.
/// 2. Take the top 3 bytes (left-shift if shorter); these become
///    the 24-bit mantissa.
/// 3. If the mantissa's high bit collides with the sign bit
///    (`& 0x00800000`), shift right by 8 and bump the exponent â€”
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
    // Zero-pad on the right out to `size` total bytes â€” Scala's
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
/// `BigInteger.longValue()` semantics â€” wraps around modulo 2^64
/// without panicking on out-of-range values.
fn bigint_low_i64(v: &num_bigint::BigInt) -> i64 {
    use num_traits::ToPrimitive;
    if let Some(x) = v.to_i64() {
        return x;
    }
    // Out-of-range â€” wrap modulo 2^64 like Java BigInteger.longValue.
    let bytes = v.to_signed_bytes_be();
    let mut buf = [0u8; 8];
    let take = bytes.len().min(8);
    buf[8 - take..].copy_from_slice(&bytes[bytes.len() - take..]);
    i64::from_be_bytes(buf)
}
