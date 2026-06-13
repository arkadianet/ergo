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

use ergo_primitives::cost::{CostAccumulator, CostKind, JitCost};
use ergo_ser::opcode::Expr;
use ergo_ser::sigma_type::SigmaType;

use super::super::cost::{add_cost, add_method_cost, collection_len};
use super::super::eval_ctx::EvalCtx;
use super::super::helpers::{coll_elem_type, collection_to_values, resolve_box};
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
        // SContext(101).LastBlockUtxoRootHash(9) -> AvlTree    cost: 15
        // Scala LastBlockUtxoRootHash.costKind = FixedCost(JitCost(15))
        // (values.scala:1495). Emitted as a 0xDB PropertyCall, so it belongs in
        // the no-arg table; mirrors the inline 0xA6 LastBlockUtxoRootHash arm.
        (101, 9) => {
            add_method_cost(cost, 15)?;
            let avl = ctx
                .last_block_utxo_root
                .clone()
                .ok_or(EvalError::EmptyHeaderWindow)?;
            Ok(Some(Value::AvlTree(avl)))
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
                    // Scala CHeader.stateRoot =
                    // CAvlTree(AvlTreeData.avlTreeFromDigest(digest)):
                    // ALL operations enabled (insert/update/remove →
                    // serialized treeFlags 0x07), keyLength 32, no
                    // value length.
                    let avl = ergo_ser::sigma_value::AvlTreeData {
                        digest: h.state_root.to_vec(),
                        insert_allowed: true,
                        update_allowed: true,
                        remove_allowed: true,
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
                // header.minerPk — canonicalize+validate the materialized GE
                // (Scala returns a decoded EcPoint; a 0x00-lead encoding is the
                // identity, an off-curve encoding errors), matching the GE
                // value basis the rest of the evaluator now uses.
                11 => Value::GroupElement(super::sigma::canonicalize_group_element(h.miner_pk)?),
                // header.powOnetimePk — same GE value basis (v2 sets it to the
                // generator, v1 to the solution's `w`; both on-curve for real
                // headers, so canonicalization only affects crafted SHeader
                // values, matching Scala GroupElementSerializer.parse).
                12 => {
                    Value::GroupElement(super::sigma::canonicalize_group_element(h.pow_onetime_pk)?)
                }
                13 => Value::CollBytes(h.pow_nonce.to_vec()),
                14 => Value::BigInt(h.pow_distance.clone()),
                15 => Value::CollBytes(h.votes.to_vec()),
                _ => unreachable!(),
            }))
        }
        // SHeader(104).checkPow(16) -> Boolean. EIP-50 v6 method.
        // FixedCost(JitCost(700)) (methods.scala). Re-verifies Autolykos PoW on
        // the carried header. Emitted as a zero-arg 0xDB PropertyCall, so it
        // belongs in this shared no-arg table (16 is outside the 1..=15 arm
        // above, so no match-order hazard). The v6 soft-fork gate is applied by
        // the dispatcher before this point.
        (104, 16) => {
            add_method_cost(cost, 700)?;
            let eh = match obj_val {
                Value::Header(h) => h,
                other => {
                    return Err(EvalError::TypeError {
                        expected: "Header for SHeader.checkPow",
                        got: format!("{other:?}"),
                    })
                }
            };
            let header = eh.to_header();
            Ok(Some(Value::Bool(
                ergo_crypto::pow::verify_pow_solution(&header).is_ok(),
            )))
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
        // SBox(99) accessor method-forms 1..6 — the PropertyCall twins of the
        // dedicated extract opcodes, dispatched to the same logic. The per-method
        // cost equals the opcode's cost (the 0xDB envelope (4) and the receiver
        // visit are charged by the caller). Extract bodies are inlined here
        // rather than delegating to the box_context opcodes, which would
        // re-evaluate the receiver and double-charge it.
        // SBox(99).value(1) -> Long                            cost: 8 (ExtractAmount)
        (99, 1) => {
            add_method_cost(cost, 8)?;
            let b = resolve_box(obj_val, ctx)?;
            Ok(Some(Value::Long(b.value)))
        }
        // SBox(99).propositionBytes(2) -> Coll[Byte]           cost: 10 (ExtractScriptBytes)
        (99, 2) => {
            add_method_cost(cost, 10)?;
            let b = resolve_box(obj_val, ctx)?;
            Ok(Some(Value::CollBytes(b.script_bytes.clone())))
        }
        // SBox(99).bytes(3) -> Coll[Byte] (retained)           cost: 12 (ExtractBytes)
        (99, 3) => {
            add_method_cost(cost, 12)?;
            let b = resolve_box(obj_val, ctx)?;
            Ok(Some(Value::CollBytes(b.raw_bytes.clone())))
        }
        // SBox(99).bytesWithoutRef(4) -> Coll[Byte] (canonical) cost: 12 (ExtractBytesWithNoRef)
        (99, 4) => {
            add_method_cost(cost, 12)?;
            let b = resolve_box(obj_val, ctx)?;
            Ok(Some(Value::CollBytes(
                super::box_context::box_candidate_bytes_canonical(b)?,
            )))
        }
        // SBox(99).id(5) -> Coll[Byte]                         cost: 12 (ExtractId)
        (99, 5) => {
            add_method_cost(cost, 12)?;
            let b = resolve_box(obj_val, ctx)?;
            Ok(Some(Value::CollBytes(b.id.to_vec())))
        }
        // SBox(99).creationInfo(6) -> (Int, Coll[Byte])        cost: 16 (ExtractCreationInfo)
        // 34-byte ref = 32-byte txId ++ 2-byte big-endian output index.
        (99, 6) => {
            add_method_cost(cost, 16)?;
            let b = resolve_box(obj_val, ctx)?;
            let mut ref_bytes = Vec::with_capacity(34);
            ref_bytes.extend_from_slice(&b.transaction_id);
            ref_bytes.extend_from_slice(&b.output_index.to_be_bytes());
            Ok(Some(Value::Tuple(vec![
                Value::Int(b.creation_height as i32),
                Value::CollBytes(ref_bytes),
            ])))
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
                Value::AvlTree(avl) => Ok(Some(Value::CollBytes(avl.digest.clone()))),
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
        // SAvlTree.isInsertAllowed(5) / isUpdateAllowed(6) / isRemoveAllowed(7)
        // -> Boolean, FixedCost(JitCost(15)). Zero-arg flag accessors over the
        // enabledOperations bits (Scala SAvlTreeMethods, V5+/ungated).
        (100, 5) => {
            add_method_cost(cost, 15)?;
            match obj_val {
                Value::AvlTree(avl) => Ok(Some(Value::Bool(avl.insert_allowed))),
                other => Err(EvalError::TypeError {
                    expected: "AvlTree for isInsertAllowed",
                    got: format!("{other:?}"),
                }),
            }
        }
        (100, 6) => {
            add_method_cost(cost, 15)?;
            match obj_val {
                Value::AvlTree(avl) => Ok(Some(Value::Bool(avl.update_allowed))),
                other => Err(EvalError::TypeError {
                    expected: "AvlTree for isUpdateAllowed",
                    got: format!("{other:?}"),
                }),
            }
        }
        (100, 7) => {
            add_method_cost(cost, 15)?;
            match obj_val {
                Value::AvlTree(avl) => Ok(Some(Value::Bool(avl.remove_allowed))),
                other => Err(EvalError::TypeError {
                    expected: "AvlTree for isRemoveAllowed",
                    got: format!("{other:?}"),
                }),
            }
        }
        // SColl(12).indices(14) -> Coll[Int]
        // Scala `SCollection.IndicesMethod_CostKind = PerItemCost(baseCost=20,
        // perChunkCost=2, chunkSize=16)` over the collection length (NOT a
        // flat 20): chunks(n) = (n-1)/16+1, so cost(n<=16)=22, (17..=32)=24, …
        (12, 14) => {
            let len = collection_len(obj_val, ctx);
            let delta = CostKind::PerItem {
                base: JitCost::from_jit(20),
                per_chunk: JitCost::from_jit(2),
                chunk_size: 16,
            }
            .compute(len as u32)?;
            cost.add(delta)?;
            #[cfg(feature = "cost-trace")]
            crate::cost_trace::record(
                format!("Method:indices(n={len})"),
                delta.value(),
                cost.total().value(),
            );
            Ok(Some(Value::CollInt((0..len as i32).collect())))
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
        // SUnsignedBigInt's `(9, 6)|(9, 7)` are not listed in
        // `is_v6_method` either (it gates only `(9, 8..=19)`): the
        // receiver type is itself v6-only, so these arms are not
        // reachable pre-v6 through any constructible value.
        (2..=6, 6 | 7) | (9, 6 | 7) => {
            add_method_cost(cost, 5)?;
            let bytes = numeric_big_endian_bytes(obj_val)?;
            Ok(Some(if method_id == 6 {
                Value::CollBytes(bytes)
            } else {
                Value::CollBool(bits_msb_first(&bytes))
            }))
        }
        // SNumericTypeMethods.bitwiseInverse(8) for Byte(2)/Short(3)/Int(4)/
        // Long(5)/BigInt(6) -> ~x. Zero-arg, FixedCost(JitCost(5)). The
        // compiler emits this as 0xDB PropertyCall, so it must live in the
        // shared no-arg table (it was previously only in eval_method_call's
        // args-arms and thus unreachable via PropertyCall).
        (2..=6, 8) => {
            add_method_cost(cost, 5)?;
            match obj_val {
                Value::Byte(n) => Ok(Some(Value::Byte(!n))),
                Value::Short(n) => Ok(Some(Value::Short(!n))),
                Value::Int(n) => Ok(Some(Value::Int(!n))),
                Value::Long(n) => Ok(Some(Value::Long(!n))),
                Value::BigInt(n) => Ok(Some(Value::BigInt(!n))),
                other => Err(EvalError::TypeError {
                    expected: "numeric type for bitwiseInverse",
                    got: format!("{other:?}"),
                }),
            }
        }
        // SUnsignedBigInt.bitwiseInverse(8) -> (2^256 - 1) XOR n (masked
        // complement in the unsigned 256-bit domain). Zero-arg, FixedCost(5).
        (9, 8) => {
            add_method_cost(cost, 5)?;
            match obj_val {
                Value::UnsignedBigInt(n) => {
                    let mask =
                        (num_bigint::BigInt::from(1) << 256u32) - num_bigint::BigInt::from(1);
                    Ok(Some(Value::UnsignedBigInt(&mask ^ n)))
                }
                other => Err(EvalError::TypeError {
                    expected: "UnsignedBigInt for bitwiseInverse",
                    got: format!("{other:?}"),
                }),
            }
        }
        // SBigInt.toUnsigned(14) -> UnsignedBigInt. Zero-arg, FixedCost(5).
        // Errors if the receiver is negative (the unsigned type can't represent
        // it). The compiler emits this as 0xDB PropertyCall.
        (6, 14) => {
            add_method_cost(cost, 5)?;
            match obj_val {
                Value::BigInt(n) => {
                    if n.sign() == num_bigint::Sign::Minus {
                        return Err(EvalError::TypeError {
                            expected: "non-negative SBigInt for toUnsigned",
                            got: format!("{n:?}"),
                        });
                    }
                    Ok(Some(Value::UnsignedBigInt(n.clone())))
                }
                other => Err(EvalError::TypeError {
                    expected: "SBigInt for toUnsigned",
                    got: format!("{other:?}"),
                }),
            }
        }
        // SUnsignedBigInt.toSigned(19) -> BigInt. Zero-arg, FixedCost(10).
        // Errors if the value would not fit signed 256-bit (>= 2^255).
        (9, 19) => {
            add_method_cost(cost, 10)?;
            match obj_val {
                Value::UnsignedBigInt(a) => {
                    let two_pow_255 = num_bigint::BigInt::from(1) << 255;
                    if a >= &two_pow_255 {
                        return Err(EvalError::RuntimeException(
                            "SUnsignedBigInt.toSigned: value exceeds signed 256-bit range",
                        ));
                    }
                    Ok(Some(Value::BigInt(a.clone())))
                }
                other => Err(EvalError::TypeError {
                    expected: "UnsignedBigInt for toSigned",
                    got: format!("{other:?}"),
                }),
            }
        }
        // SColl.reverse(30) -> Coll[T]. Zero-arg; cost PerItemCost(20,2,100)
        // over the collection length. The compiler emits it as 0xDB
        // PropertyCall, so it lives in the shared no-arg table.
        (12, 30) => {
            let n = collection_len(obj_val, ctx) as u32;
            let reverse_cost = CostKind::PerItem {
                base: JitCost::from_jit(20),
                per_chunk: JitCost::from_jit(2),
                chunk_size: 100,
            };
            cost.add(reverse_cost.compute(n)?)?;
            let reversed = match obj_val.clone() {
                Value::CollBytes(mut v) => {
                    v.reverse();
                    Value::CollBytes(v)
                }
                Value::CollInt(mut v) => {
                    v.reverse();
                    Value::CollInt(v)
                }
                Value::CollLong(mut v) => {
                    v.reverse();
                    Value::CollLong(v)
                }
                Value::CollShort(mut v) => {
                    v.reverse();
                    Value::CollShort(v)
                }
                Value::CollBool(mut v) => {
                    v.reverse();
                    Value::CollBool(v)
                }
                other => {
                    let elem_type = coll_elem_type(&other).unwrap_or(SigmaType::SAny);
                    let (_kind, mut items) = collection_to_values(other, ctx)?;
                    items.reverse();
                    Value::CollGeneric(items, Box::new(elem_type))
                }
            };
            Ok(Some(reversed))
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
