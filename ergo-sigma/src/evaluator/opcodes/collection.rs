//! Collection / higher-order opcodes:
//!
//! - 0xB1 SizeOf
//! - 0xB2 ByIndex
//! - 0xAF ForAll, 0xB5 Filter, 0xB0 Fold, 0xAD MapCollection,
//!   0xAE Exists, 0xB3 Append, 0xB4 Slice
//!
//! The higher-order arms (ForAll / Filter / Fold / Map / Exists)
//! recurse into `eval_expr` per element and charge an `AddToEnv`
//! (5 jit) per closure invocation. Cost-charge sequencing is preserved
//! exactly: collection and function construction precede the known-length
//! overhead charge; per-element AddToEnv charges precede each closure body.
//! Scala transformers.scala:40-45,123-127,160-164,187-191,224-230
//! uses addSeqCostNoOp for these operations.

use crate::evaluator::helpers::reject_sstring;
use ergo_primitives::cost::JitCost;
use ergo_ser::opcode::Expr;
use ergo_ser::sigma_type::SigmaType;

use super::super::cost::{add_cost, add_cost_per_item, collection_len};
use super::super::dispatch::eval_expr;
use super::super::eval_ctx::EvalCtx;
use super::super::helpers::{
    coll_elem_type, collection_to_values, infer_collection, value_to_sigma_type,
    values_to_collection,
};
use super::super::types::{BoxSource, EvalError, Value};
use super::binding::check_closure_param_types;

// 0xB1 SizeOf
pub(in crate::evaluator) fn eval_size_of(
    inner: &Expr,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    add_cost(cx.cost, 0xB1)?;
    let val = cx.eval_expr(inner)?;
    match val {
        Value::BoxCollection(src) => {
            let len = match src {
                BoxSource::Outputs => cx.ctx.outputs.len(),
                BoxSource::Inputs => cx.ctx.inputs.len(),
                BoxSource::DataInputs => cx.ctx.data_inputs.len(),
            };
            Ok(Value::Int(len as i32))
        }
        Value::CollBool(v) => Ok(Value::Int(v.len() as i32)),
        Value::CollBytes(v) => Ok(Value::Int(v.len() as i32)),
        Value::CollShort(v) => Ok(Value::Int(v.len() as i32)),
        Value::CollInt(v) => Ok(Value::Int(v.len() as i32)),
        Value::CollLong(v) => Ok(Value::Int(v.len() as i32)),
        Value::CollSigmaProp(v) => Ok(Value::Int(v.len() as i32)),
        Value::CollBox(v) => Ok(Value::Int(v.len() as i32)),
        // `CONTEXT.headers.size` — Scala answers 10 on mainnet; without
        // this arm the Rust node raised a type error (consensus divergence
        // for any script that reads it).
        Value::CollHeader(v) => Ok(Value::Int(v.len() as i32)),
        Value::Tokens(v) => Ok(Value::Int(v.len() as i32)),
        // Boxed-element coll carrier (Coll[Tuple], Coll[Header]
        // fallback, etc.). A real `Value::Tuple` is not a collection
        // and falls through to the type-error arm.
        Value::CollGeneric(v, _) | Value::CollLegacyPair(v, _, _) => Ok(Value::Int(v.len() as i32)),
        _ => Err(EvalError::TypeError {
            expected: "Collection",
            got: format!("{val:?}"),
        }),
    }
}

// 0xB2 ByIndex(collection, index, default?)
pub(in crate::evaluator) fn eval_by_index(
    input: &Expr,
    index: &Expr,
    default: Option<&Expr>,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    let coll = cx.eval_expr(input)?;
    let idx = cx.eval_expr(index)?;
    let idx = match idx {
        Value::Int(i) => i as usize,
        _ => {
            return Err(EvalError::TypeError {
                expected: "Int index",
                got: format!("{idx:?}"),
            })
        }
    };
    // Scala ByIndex.eval (transformers.scala): pre-v3 trees evaluate the
    // default eagerly after the index — its cost (and any error) lands even
    // when the index is in bounds. V3+ trees (isV3OrLaterErgoTreeVersion)
    // evaluate it lazily, only on an out-of-bounds index.
    let mut eager_default = match default {
        Some(d) if !cx.ctx.is_v3_ergo_tree() => Some(cx.eval_expr(d).and_then(reject_sstring)?),
        _ => None,
    };
    // Charge sequencing per Scala ByIndex.eval: input, index, and the
    // pre-v3 eager default all evaluate BEFORE the ByIndex fixed charge;
    // the element access / lazy default come after it.
    add_cost(cx.cost, 0xB2)?;
    match coll {
        Value::BoxCollection(src) => {
            let len = match src {
                BoxSource::Outputs => cx.ctx.outputs.len(),
                BoxSource::Inputs => cx.ctx.inputs.len(),
                BoxSource::DataInputs => cx.ctx.data_inputs.len(),
            };
            if idx < len {
                Ok(Value::BoxRef {
                    source: src,
                    index: idx,
                })
            } else if let Some(d) = default {
                take_default(d, &mut eager_default, cx)
            } else {
                Err(EvalError::TypeError {
                    expected: "valid box index",
                    got: format!("{src:?}[{idx}] (len={len})"),
                })
            }
        }
        Value::Tokens(ref tokens) => {
            if idx < tokens.len() {
                let (token_id, amount) = &tokens[idx];
                Ok(Value::Tuple(vec![
                    Value::CollBytes(token_id.to_vec()),
                    Value::Long(*amount as i64),
                ]))
            } else if let Some(d) = default {
                take_default(d, &mut eager_default, cx)
            } else {
                Err(EvalError::TypeError {
                    expected: "valid token index",
                    got: format!("index {idx} in {} tokens", tokens.len()),
                })
            }
        }
        Value::CollBytes(ref bytes) => {
            if idx < bytes.len() {
                // Element boundary produces Value::Byte, not erased Int —
                // typed-carrier invariant pinned by the parity tests.
                Ok(Value::Byte(bytes[idx] as i8))
            } else if let Some(d) = default {
                take_default(d, &mut eager_default, cx)
            } else {
                Err(EvalError::TypeError {
                    expected: "valid byte index",
                    got: format!("index {idx} in {} bytes", bytes.len()),
                })
            }
        }
        Value::CollInt(ref ints) => {
            if idx < ints.len() {
                Ok(Value::Int(ints[idx]))
            } else if let Some(d) = default {
                take_default(d, &mut eager_default, cx)
            } else {
                Err(EvalError::TypeError {
                    expected: "valid int index",
                    got: format!("index {idx} in {} ints", ints.len()),
                })
            }
        }
        Value::CollLong(ref longs) => {
            if idx < longs.len() {
                Ok(Value::Long(longs[idx]))
            } else if let Some(d) = default {
                take_default(d, &mut eager_default, cx)
            } else {
                Err(EvalError::TypeError {
                    expected: "valid long index",
                    got: format!("index {idx} in {} longs", longs.len()),
                })
            }
        }
        Value::CollShort(ref shorts) => {
            if idx < shorts.len() {
                Ok(Value::Short(shorts[idx]))
            } else if let Some(d) = default {
                take_default(d, &mut eager_default, cx)
            } else {
                Err(EvalError::TypeError {
                    expected: "valid short index",
                    got: format!("index {idx} in {} shorts", shorts.len()),
                })
            }
        }
        Value::CollSigmaProp(ref props) => {
            if idx < props.len() {
                Ok(Value::SigmaProp(props[idx].clone()))
            } else if let Some(d) = default {
                take_default(d, &mut eager_default, cx)
            } else {
                Err(EvalError::TypeError {
                    expected: "valid sigmaprop index",
                    got: format!("index {idx} in {} props", props.len()),
                })
            }
        }
        Value::CollBool(ref bools) => {
            if idx < bools.len() {
                Ok(Value::Bool(bools[idx]))
            } else if let Some(d) = default {
                take_default(d, &mut eager_default, cx)
            } else {
                Err(EvalError::TypeError {
                    expected: "valid bool index",
                    got: format!("index {idx} in {} bools", bools.len()),
                })
            }
        }
        Value::CollBox(ref items) => {
            if idx < items.len() {
                Ok(items[idx].clone())
            } else if let Some(d) = default {
                take_default(d, &mut eager_default, cx)
            } else {
                Err(EvalError::TypeError {
                    expected: "valid box index",
                    got: format!("index {idx} in {} boxes", items.len()),
                })
            }
        }
        Value::CollHeader(ref headers) => {
            if idx < headers.len() {
                Ok(Value::Header(Box::new(headers[idx].clone())))
            } else if let Some(d) = default {
                take_default(d, &mut eager_default, cx)
            } else {
                Err(EvalError::TypeError {
                    expected: "valid header index",
                    got: format!("index {idx} in {} headers", headers.len()),
                })
            }
        }
        // Boxed-element coll carrier. ByIndex is a Coll operation, so
        // a real `Value::Tuple` (fixed-arity STuple) falls through to
        // the type-error arm — STuple field access goes through
        // `SelectField` (0x8C), not `ByIndex` (0xB2).
        Value::CollGeneric(ref items, _) | Value::CollLegacyPair(ref items, _, _) => {
            if idx < items.len() {
                Ok(items[idx].clone())
            } else if let Some(d) = default {
                take_default(d, &mut eager_default, cx)
            } else {
                Err(EvalError::TypeError {
                    expected: "valid collection index",
                    got: format!("index {idx} in {} items", items.len()),
                })
            }
        }
        _ => Err(EvalError::TypeError {
            expected: "indexed collection",
            got: format!("{coll:?}"),
        }),
    }
}

// Out-of-bounds ByIndex default: hand back the pre-v3 eagerly evaluated
// value, or evaluate lazily (v3+ trees only evaluate the default on a miss).
fn take_default(
    d: &Expr,
    eager: &mut Option<Value>,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    match eager.take() {
        Some(v) => Ok(v),
        None => cx.eval_expr(d).and_then(reject_sstring),
    }
}

// 0xAF ForAll(collection, predicate)
pub(in crate::evaluator) fn eval_forall(
    coll_expr: &Expr,
    pred_expr: &Expr,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    let coll = cx.eval_expr(coll_expr)?;
    let n = collection_len(&coll, cx.ctx);
    let pred = cx.eval_expr(pred_expr)?;
    add_cost_per_item(cx.cost, 0xAF, n as u32)?;
    let (_coll_kind, items) = collection_to_values(coll, cx.ctx)?;
    match pred {
        Value::Func {
            captured_env,
            params,
            param_types,
            body,
        } => {
            for item in items {
                // Scala closure invocation: Value.checkType runs before
                // the AddToEnvironment charge (see check_closure_param_types).
                check_closure_param_types(&param_types)?;
                cx.cost.add(JitCost::from_jit(5))?;
                #[cfg(feature = "cost-trace")]
                crate::cost_trace::record("AddToEnv", 5, cx.cost.total().value());
                let mut call_env = (*captured_env).clone();
                if let Some(param_id) = params.first() {
                    call_env.insert(*param_id, item);
                }
                let result = eval_expr(
                    &body,
                    cx.ctx,
                    cx.constants,
                    &mut call_env,
                    cx.depth,
                    cx.cost,
                    cx.trace,
                )
                .and_then(reject_sstring)?;
                match result {
                    Value::Bool(false) => return Ok(Value::Bool(false)),
                    Value::Bool(true) => {}
                    _ => {
                        return Err(EvalError::TypeError {
                            expected: "Bool from ForAll predicate",
                            got: format!("{result:?}"),
                        })
                    }
                }
            }
            Ok(Value::Bool(true))
        }
        _ => Err(EvalError::TypeError {
            expected: "Func for ForAll",
            got: format!("{pred:?}"),
        }),
    }
}

// 0xB5 Filter(collection, predicate)
pub(in crate::evaluator) fn eval_filter(
    coll_expr: &Expr,
    pred_expr: &Expr,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    let coll = cx.eval_expr(coll_expr)?;
    let n = collection_len(&coll, cx.ctx);
    let pred = cx.eval_expr(pred_expr)?;
    add_cost_per_item(cx.cost, 0xB5, n as u32)?;
    // Filter preserves the input's element type; capture before
    // `collection_to_values` consumes the carrier so the rebuild
    // step can re-tag the `CollGeneric` fallback with the right T.
    let elem_type = coll_elem_type(&coll).unwrap_or(SigmaType::SAny);
    let (coll_kind, items) = collection_to_values(coll, cx.ctx)?;
    match pred {
        Value::Func {
            captured_env,
            params,
            param_types,
            body,
        } => {
            let mut result = Vec::new();
            for item in items {
                // Scala closure invocation: Value.checkType runs before
                // the AddToEnvironment charge (see check_closure_param_types).
                check_closure_param_types(&param_types)?;
                cx.cost.add(JitCost::from_jit(5))?;
                #[cfg(feature = "cost-trace")]
                crate::cost_trace::record("AddToEnv", 5, cx.cost.total().value());
                let mut call_env = (*captured_env).clone();
                if let Some(param_id) = params.first() {
                    call_env.insert(*param_id, item.clone());
                }
                let keep = eval_expr(
                    &body,
                    cx.ctx,
                    cx.constants,
                    &mut call_env,
                    cx.depth,
                    cx.cost,
                    cx.trace,
                )
                .and_then(reject_sstring)?;
                if matches!(keep, Value::Bool(true)) {
                    result.push(item);
                }
            }
            values_to_collection(coll_kind, result, elem_type)
        }
        _ => Err(EvalError::TypeError {
            expected: "Func for Filter",
            got: format!("{pred:?}"),
        }),
    }
}

// 0xB0 Fold(collection, zero, op) — left fold
pub(in crate::evaluator) fn eval_fold(
    coll_expr: &Expr,
    zero_expr: &Expr,
    op_expr: &Expr,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    let coll = cx.eval_expr(coll_expr)?;
    let n = collection_len(&coll, cx.ctx);
    let mut acc = cx.eval_expr(zero_expr).and_then(reject_sstring)?;
    let op = cx.eval_expr(op_expr)?;
    add_cost_per_item(cx.cost, 0xB0, n as u32)?;
    let (_coll_kind, items) = collection_to_values(coll, cx.ctx)?;
    match op {
        Value::Func {
            captured_env,
            params,
            param_types,
            body,
        } => {
            for item in items {
                // Scala closure invocation: Value.checkType runs before
                // the AddToEnvironment charge (see check_closure_param_types).
                check_closure_param_types(&param_types)?;
                cx.cost.add(JitCost::from_jit(5))?;
                #[cfg(feature = "cost-trace")]
                crate::cost_trace::record("AddToEnv", 5, cx.cost.total().value());
                let mut call_env = (*captured_env).clone();
                // Fold function takes (acc, item) as a tuple via params
                if params.len() >= 2 {
                    call_env.insert(params[0], acc);
                    call_env.insert(params[1], item);
                } else if params.len() == 1 {
                    // Single param: receives (acc, item) as tuple
                    call_env.insert(params[0], Value::Tuple(vec![acc, item]));
                }
                acc = eval_expr(
                    &body,
                    cx.ctx,
                    cx.constants,
                    &mut call_env,
                    cx.depth,
                    cx.cost,
                    cx.trace,
                )
                .and_then(reject_sstring)?;
            }
            Ok(acc)
        }
        _ => Err(EvalError::TypeError {
            expected: "Func for Fold",
            got: format!("{op:?}"),
        }),
    }
}

// 0xAD MapCollection(collection, mapper)
// Output type is inferred from mapper results, not the input collection.
pub(in crate::evaluator) fn eval_map_collection(
    coll_expr: &Expr,
    mapper_expr: &Expr,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    let coll = cx.eval_expr(coll_expr)?;
    let n = collection_len(&coll, cx.ctx);
    let mapper = cx.eval_expr(mapper_expr)?;
    add_cost_per_item(cx.cost, 0xAD, n as u32)?;
    map_values(coll, mapper, cx)
}

/// Map an evaluated collection and closure after the caller's scheduled charge.
pub(in crate::evaluator) fn map_values(
    coll: Value,
    mapper: Value,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    // PairOfCols.map (CollsOverArrays.scala:317) returns CollOverArray,
    // whereas CollOverArray.map uses builder.fromArray, which unzips pairs.
    let maps_pair_columns = matches!(coll_elem_type(&coll),
        Some(SigmaType::STuple(ref types)) if types.len() == 2)
        && !matches!(&coll, Value::CollLegacyPair(_, _, None));
    let (_input_kind, items) = collection_to_values(coll, cx.ctx)?;
    match mapper {
        Value::Func {
            captured_env,
            params,
            param_types,
            body,
        } => {
            let mut result = Vec::new();
            for item in items {
                // Scala closure invocation: Value.checkType runs before
                // the AddToEnvironment charge (see check_closure_param_types).
                check_closure_param_types(&param_types)?;
                cx.cost.add(JitCost::from_jit(5))?;
                #[cfg(feature = "cost-trace")]
                crate::cost_trace::record("AddToEnv", 5, cx.cost.total().value());
                let mut call_env = (*captured_env).clone();
                if let Some(param_id) = params.first() {
                    call_env.insert(*param_id, item);
                }
                result.push(
                    eval_expr(
                        &body,
                        cx.ctx,
                        cx.constants,
                        &mut call_env,
                        cx.depth,
                        cx.cost,
                        cx.trace,
                    )
                    .and_then(reject_sstring)?,
                );
            }
            // Build type bindings for type inference: captured env + param types
            let mut param_bindings = std::collections::HashMap::new();
            // Captured closure values → derive types from runtime values
            for (id, val) in captured_env.iter() {
                if let Some(t) = value_to_sigma_type(val) {
                    param_bindings.insert(*id, t);
                }
            }
            // Explicit parameter types override captured bindings
            for (id, tpe) in &param_types {
                if let Some(t) = tpe {
                    param_bindings.insert(*id, t.clone());
                }
            }
            let result = infer_collection(result, &body, &param_bindings, cx.constants)?;
            // Only PairOfCols.map leaves a Tuple2 array for pre-JIT append.
            if cx.ctx.activated_script_version < 2 && maps_pair_columns {
                if let Value::CollGeneric(items, elem_type) = result {
                    if matches!(elem_type.as_ref(), SigmaType::STuple(ts) if ts.len() == 2) {
                        return Ok(Value::CollLegacyPair(items, elem_type, None));
                    }
                    return Ok(Value::CollGeneric(items, elem_type));
                }
            }
            Ok(result)
        }
        _ => Err(EvalError::TypeError {
            expected: "Func for MapCollection",
            got: format!("{mapper:?}"),
        }),
    }
}

// 0xAE Exists(collection, predicate)
pub(in crate::evaluator) fn eval_exists(
    coll_expr: &Expr,
    pred_expr: &Expr,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    let coll = cx.eval_expr(coll_expr)?;
    let n = collection_len(&coll, cx.ctx);
    let pred = cx.eval_expr(pred_expr)?;
    add_cost_per_item(cx.cost, 0xAE, n as u32)?;
    let (_coll_kind, items) = collection_to_values(coll, cx.ctx)?;
    match pred {
        Value::Func {
            captured_env,
            params,
            param_types,
            body,
        } => {
            for item in items {
                // Scala closure invocation: Value.checkType runs before
                // the AddToEnvironment charge (see check_closure_param_types).
                check_closure_param_types(&param_types)?;
                cx.cost.add(JitCost::from_jit(5))?;
                #[cfg(feature = "cost-trace")]
                crate::cost_trace::record("AddToEnv", 5, cx.cost.total().value());
                let mut call_env = (*captured_env).clone();
                if let Some(param_id) = params.first() {
                    call_env.insert(*param_id, item);
                }
                let result = eval_expr(
                    &body,
                    cx.ctx,
                    cx.constants,
                    &mut call_env,
                    cx.depth,
                    cx.cost,
                    cx.trace,
                )
                .and_then(reject_sstring)?;
                if matches!(result, Value::Bool(true)) {
                    return Ok(Value::Bool(true));
                }
            }
            Ok(Value::Bool(false))
        }
        _ => Err(EvalError::TypeError {
            expected: "Func for Exists",
            got: format!("{pred:?}"),
        }),
    }
}

// 0xB3 Append(left, right) — concatenate two collections
pub(in crate::evaluator) fn eval_append(
    left_expr: &Expr,
    right_expr: &Expr,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    let left = cx.eval_expr(left_expr)?;
    let right = cx.eval_expr(right_expr)?;
    let total = collection_len(&left, cx.ctx) + collection_len(&right, cx.ctx);
    add_cost_per_item(cx.cost, 0xB3, total as u32)?;
    append_values(left, right, cx)
}

/// Append's single charge covers the recursive PairOfCols column appends.
fn append_values(left: Value, right: Value, cx: &EvalCtx<'_>) -> Result<Value, EvalError> {
    let elem_type = coll_elem_type(&left).unwrap_or(SigmaType::SAny);
    // CollsOverArrays.scala:50,184: VersionContext.current.isJitActivated
    // (activation >= 2) fixes Tuple2 array concatenation and truncates zip sides.
    if cx.ctx.activated_script_version < 2 {
        if let Value::CollLegacyPair(items, _, None) = &left {
            if !items.is_empty() {
                return Err(EvalError::TypeError {
                    expected: "Tuple2 array for pre-JIT append",
                    got: "Object array".into(),
                });
            }
            return Ok(right);
        }
        if matches!(&elem_type, SigmaType::STuple(ts) if ts.len() == 2) {
            let (left_a, left_b) = pair_columns(left, cx)?;
            let (right_a, right_b) = pair_columns(right, cx)?;
            let a = append_values(left_a, right_a, cx)?;
            let b = append_values(left_b, right_b, cx)?;
            return super::super::helpers::legacy_pair(a, b, cx.ctx);
        }
    }
    let (kind, mut items) = collection_to_values(left, cx.ctx)?;
    let (_, tail) = collection_to_values(right, cx.ctx)?;
    items.extend(tail);
    values_to_collection(kind, items, elem_type)
}

fn pair_columns(value: Value, cx: &EvalCtx<'_>) -> Result<(Value, Value), EvalError> {
    if let Value::CollLegacyPair(_, _, Some(columns)) = value {
        return Ok(*columns);
    }
    let Some(SigmaType::STuple(types)) = coll_elem_type(&value) else {
        return Err(EvalError::TypeError {
            expected: "pair collection for append",
            got: format!("{value:?}"),
        });
    };
    let (_, items) = collection_to_values(value, cx.ctx)?;
    let mut a = Vec::with_capacity(items.len());
    let mut b = Vec::with_capacity(items.len());
    for item in items {
        match item {
            Value::Tuple(mut pair) if pair.len() == 2 => {
                b.push(pair.pop().expect("pair has two elements"));
                a.push(pair.pop().expect("pair has two elements"));
            }
            other => {
                return Err(EvalError::TypeError {
                    expected: "pair for append",
                    got: format!("{other:?}"),
                })
            }
        }
    }
    let kind_a = super::super::helpers::sigma_type_to_coll_kind(&types[0])
        .unwrap_or(super::super::helpers::CollKind::Tuple);
    let kind_b = super::super::helpers::sigma_type_to_coll_kind(&types[1])
        .unwrap_or(super::super::helpers::CollKind::Tuple);
    Ok((
        values_to_collection(kind_a, a, types[0].clone())?,
        values_to_collection(kind_b, b, types[1].clone())?,
    ))
}

// 0xB4 Slice(collection, from, until)
//
// Negative bounds clamp to 0 — Scala parity. `transformers.scala::Slice.eval`
// delegates to `inputV.slice(fromV, untilV)`, which Scala's `Array.slice`
// implements as `lo = math.max(from, 0); hi = math.min(math.max(until, 0),
// xs.length); if (hi > lo) copyOfRange(xs, lo, hi) else new Array[A](0)`.
// No throw on negative; `until < from` returns empty. Mirror with
// `v.max(0) as usize` below plus the `if from <= until` branch.
pub(in crate::evaluator) fn eval_slice(
    coll_expr: &Expr,
    from_expr: &Expr,
    until_expr: &Expr,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    let coll = cx.eval_expr(coll_expr)?;
    let from = match cx.eval_expr(from_expr)? {
        Value::Int(v) => v.max(0) as usize,
        other => {
            return Err(EvalError::TypeError {
                expected: "Int for Slice from",
                got: format!("{other:?}"),
            })
        }
    };
    let until = match cx.eval_expr(until_expr)? {
        Value::Int(v) => v.max(0) as usize,
        other => {
            return Err(EvalError::TypeError {
                expected: "Int for Slice until",
                got: format!("{other:?}"),
            })
        }
    };
    let elem_type = coll_elem_type(&coll).unwrap_or(SigmaType::SAny);
    let (kind, items) = collection_to_values(coll, cx.ctx)?;
    let len = items.len();
    // Cost is charged on the **pre-len-clamp** range size to match
    // Scala's `transformers.scala::Slice.eval`, which charges
    // `Math.max(0, until - from)` over the user-supplied bounds
    // (after the per-arg `max(0)` clamp). Charging only over the
    // post-clamp `sliced.len()` under-charges when `until > len` —
    // a consensus-loosening direction.
    let cost_n = until.saturating_sub(from) as u32;
    add_cost_per_item(cx.cost, 0xB4, cost_n)?;
    let from_clamped = from.min(len);
    let until_clamped = until.min(len);
    let sliced: Vec<Value> = if from_clamped <= until_clamped {
        items
            .into_iter()
            .skip(from_clamped)
            .take(until_clamped - from_clamped)
            .collect()
    } else {
        Vec::new()
    };
    values_to_collection(kind, sliced, elem_type)
}
