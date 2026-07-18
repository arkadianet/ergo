//! `SCollection` (type_id 12) `0xDC MethodCall` arms: indexOf(26), zip(29),
//! startsWith(31)/endsWith(32), get(33), flatMap(15), patch(19), updated(20),
//! updateMany(21). Each was one arm of the `eval_method_call` match; the
//! router in `mod.rs` delegates by `(type_id, method_id)`.

use ergo_primitives::cost::{CostKind, JitCost};
use ergo_ser::opcode::Expr;
use ergo_ser::sigma_type::SigmaType;

use super::check_arity;
use crate::evaluator::cost::{add_method_cost, collection_len, eq_with_cost};
use crate::evaluator::dispatch::eval_expr;
use crate::evaluator::eval_ctx::EvalCtx;
use crate::evaluator::helpers::{
    coll_elem_type, collection_to_values, sigma_type_compatible, value_to_sigma_type, values_equal,
    values_to_collection, CollKind,
};
use crate::evaluator::opcodes::binding::check_closure_param_types;
use crate::evaluator::types::{EvalError, Value};

// SCollection(12).indexOf(26) -> Int
// Cost: PerItemCost(20, 10, 2) charged on actual iterations.
//
// Negative `from` clamps to 0 — Scala parity. `methods.scala`
// `indexOf_eval` computes `val start = math.max(from, 0)` and
// loops from `start`. It does NOT throw. Mirror with
// `v.max(0) as usize` below.
pub(super) fn index_of(
    obj_val: Value,
    args: &[Expr],
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
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
pub(super) fn zip(obj_val: Value, args: &[Expr], cx: &mut EvalCtx<'_>) -> Result<Value, EvalError> {
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
    // Outer is Coll[(A, B)] — boxed-element coll carrier;
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
pub(super) fn starts_ends_with(
    method_id: u8,
    obj_val: Value,
    args: &[Expr],
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
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
pub(super) fn get(obj_val: Value, args: &[Expr], cx: &mut EvalCtx<'_>) -> Result<Value, EvalError> {
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

// SColl(12).flatMap(15) -> Coll[B]
// Scala: xs.flatMap(f) — map each element to a collection, flatten results.
pub(super) fn flat_map(
    obj_val: Value,
    args: &[Expr],
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    if args.len() != 1 {
        return Err(EvalError::ArityMismatch {
            expected: 1,
            got: args.len(),
        });
    }
    // MethodCall.costKind = FixedCost(4) is charged ONCE at the
    // eval_method_call entry (opcode 0xDC); the FuncValue arg eval
    // charges FixedCost(5). The flatMap method's own cost is
    // FlatMapMethod_CostKind = PerItemCost(60,10,8) over the OUTPUT
    // (flattened) length, charged below — Scala flatMap_eval
    // (methods.scala) wraps `xs.flatMap(f); res.length` in addSeqCost.
    let func_val = cx.eval_expr(&args[0])?;
    let (_kind, items) = collection_to_values(obj_val, cx.ctx)?;
    match func_val {
        Value::Func {
            captured_env,
            params,
            param_types,
            body,
        } => {
            // Collect all inner collections, preserving the raw Value form
            // so we can reassemble the correct output type.
            let mut inner_colls: Vec<Value> = Vec::new();
            for item in items {
                // Scala closure invocation: Value.checkType runs
                // before the AddToEnvironment charge.
                check_closure_param_types(&param_types)?;
                let mut call_env = (*captured_env).clone();
                if let Some(param_id) = params.first() {
                    // Scala FuncValue closure binds its argument on each
                    // application: addFixedCost(AddToEnvironment = 5).
                    cx.cost.add(JitCost::from_jit(5))?;
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
            let result = if inner_colls.is_empty() {
                first_shape.unwrap_or(Value::CollBytes(vec![]))
            } else {
                match &inner_colls[0] {
                    Value::CollBytes(_) => {
                        let mut out = Vec::new();
                        for c in inner_colls {
                            if let Value::CollBytes(b) = c {
                                out.extend(b);
                            }
                        }
                        Value::CollBytes(out)
                    }
                    Value::CollInt(_) => {
                        let mut out = Vec::new();
                        for c in inner_colls {
                            if let Value::CollInt(v) = c {
                                out.extend(v);
                            }
                        }
                        Value::CollInt(out)
                    }
                    Value::CollLong(_) => {
                        let mut out = Vec::new();
                        for c in inner_colls {
                            if let Value::CollLong(v) = c {
                                out.extend(v);
                            }
                        }
                        Value::CollLong(out)
                    }
                    Value::CollBool(_) => {
                        let mut out = Vec::new();
                        for c in inner_colls {
                            if let Value::CollBool(v) = c {
                                out.extend(v);
                            }
                        }
                        Value::CollBool(out)
                    }
                    Value::CollShort(_) => {
                        let mut out = Vec::new();
                        for c in inner_colls {
                            if let Value::CollShort(v) = c {
                                out.extend(v);
                            }
                        }
                        Value::CollShort(out)
                    }
                    Value::CollSigmaProp(_) => {
                        let mut out = Vec::new();
                        for c in inner_colls {
                            if let Value::CollSigmaProp(v) = c {
                                out.extend(v);
                            }
                        }
                        Value::CollSigmaProp(out)
                    }
                    Value::CollHeader(_) => {
                        let mut out = Vec::new();
                        for c in inner_colls {
                            if let Value::CollHeader(v) = c {
                                out.extend(v);
                            }
                        }
                        Value::CollHeader(out)
                    }
                    Value::Tokens(_) => {
                        let mut out = Vec::new();
                        for c in inner_colls {
                            if let Value::Tokens(v) = c {
                                out.extend(v);
                            }
                        }
                        Value::Tokens(out)
                    }
                    Value::CollBox(_) => {
                        let mut out = Vec::new();
                        for c in inner_colls {
                            if let Value::CollBox(v) = c {
                                out.extend(v);
                            }
                        }
                        Value::CollBox(out)
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
                        Value::CollGeneric(out, elem_type)
                    }
                    other => {
                        return Err(EvalError::TypeError {
                            expected: "collection result from flatMap body",
                            got: format!("{other:?}"),
                        })
                    }
                }
            };
            // FlatMapMethod_CostKind = PerItemCost(60, 10, 8) charged
            // over the OUTPUT (flattened) length — Scala flatMap_eval
            // (methods.scala) does `addSeqCost(costKind){ res.length }`.
            // compute(0) = 70 (chunks truncate to 1), matching the
            // empty-result case.
            let out_len = collection_len(&result, cx.ctx) as u32;
            cx.cost.add(
                CostKind::PerItem {
                    base: JitCost::from_jit(60),
                    per_chunk: JitCost::from_jit(10),
                    chunk_size: 8,
                }
                .compute(out_len)?,
            )?;
            Ok(result)
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
// family whose Scala backing throws on out-of-range indices —
// see the updated arm below.
pub(super) fn patch(
    obj_val: Value,
    args: &[Expr],
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
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
    // `Fixed(4)` — under-charging vs. Scala (consensus-loosening).
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
    // Generic carrier: Scala `Coll[A].patch` accepts every element type
    // (CollsOverArrays), so decompose both receiver and patch to a `Vec<Value>`
    // and splice — rather than enumerating a few carriers (which reject-valid'd
    // `Coll[Short]` / `Coll[Boolean]` / tuple / box / header receivers). Mirrors
    // the generic path `updateMany` already uses.
    let elem_type = coll_elem_type(&obj_val).ok_or_else(|| EvalError::TypeError {
        expected: "Coll for patch receiver",
        got: format!("{obj_val:?}"),
    })?;
    let (kind, mut items) = collection_to_values(obj_val, cx.ctx)?;
    let (_patch_kind, patch_items) = collection_to_values(patch_val, cx.ctx)?;
    // Each patched-in element must be assignable to the receiver's element
    // type: Scala's `patch(_, patch: Coll[A], _)` is backed by `Array[A]`, so a
    // foreign element throws ArrayStoreException. An empty patch writes nothing
    // and is accepted regardless of its declared element type — matching Scala
    // and the `updateMany` empty-values rule.
    for p in &patch_items {
        let p_ty = value_to_sigma_type(p).ok_or_else(|| EvalError::TypeError {
            expected: "patch element with recoverable SigmaType",
            got: format!("{p:?}"),
        })?;
        if !sigma_type_compatible(&elem_type, &p_ty) {
            return Err(EvalError::TypeError {
                expected: "matching element type for patch",
                got: format!("{elem_type:?} vs {p_ty:?}"),
            });
        }
    }
    // splice(start..end, patch) yields xs[0..start] ++ patch ++ xs[end..n],
    // equivalent to Scala's chunk1/chunk2 model above. `from + replaced` cannot
    // overflow usize on supported targets: both args are clamped to
    // [0, i32::MAX], so the worst-case sum 2 * i32::MAX fits in u32.
    let end = (from + replaced).min(items.len());
    items.splice(from.min(items.len())..end, patch_items);
    values_to_collection(kind, items, elem_type)
}

// SColl(12).updated(20) -> Coll[T]
// Scala: coll.updated(index, elem) — replace element at index.
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
//   2. Charge cost — matches Scala's `addSeqCost(costKind,
//      coll.length, opDesc) { coll.updated(...) }` ordering at
//      `methods.scala::updated_eval`.
//   3. Type-check receiver is a `Coll` — `TypeError` on miss.
//   4. Bounds-check index — `RuntimeException` on out-of-range.
//   5. Dispatch by carrier — `TypeError` on elem mismatch.
// The Scala-source citation above is the rejection-parity oracle
// (sigma-state delegates to Scala stdlib whose Scaladoc pins the
// throw semantics).
pub(super) fn updated(
    obj_val: Value,
    args: &[Expr],
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
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
    // resolved to `Fixed(4)` — under-charging vs. Scala.
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
    // fire RuntimeException for any idx — wrong error class.
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
    // carrier (BoxCollection — produced by INPUTS, OUTPUTS,
    // dataInputs).
    //
    // `Value::Tuple` (real fixed-arity STuple) is permanently
    // excluded — tuples are not collections in Scala-sigma,
    // and STuple field replacement is not an EIP-50 method.
    // `Value::CollGeneric` is the boxed-element coll carrier
    // (Coll[Tuple], Coll[Header], nested colls); accepted
    // here because Scala's `Coll[A].updated` is generic over
    // any `A`. The element-type compatibility is trusted to
    // the script-load type-check — runtime simply replaces
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
        // CollBytes accepts a Byte element — the natural carrier
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
        // mismatch arm below and TypeErrors — matching Scala
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
        // canonical 32-byte+Long shape — preserve as Tokens.
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
                    Value::Tuple(vec![Value::CollBytes(id.to_vec()), Value::Long(amt as i64)])
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
pub(super) fn update_many(
    obj_val: Value,
    args: &[Expr],
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
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
