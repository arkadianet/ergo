//! Binding and control-flow opcodes:
//!
//! - 0x73 ConstPlaceholder — index into the segregated constant pool
//! - 0x72 ValUse           — reference a bound variable
//! - 0xD8 BlockValue       — sequence of ValDefs then a result expression
//! - 0xD6 ValDef           — bind a value to an id in the environment
//! - 0x95 If               — three-arm conditional with trace push for the condition
//! - 0x86 Tuple            — eager n-ary tuple construction
//! - 0x8C SelectField      — 1-indexed tuple field access
//! - 0xD9 FuncValue        — closure capturing the current environment
//! - 0xDA FuncApply        — closure invocation (charges AddToEnv per call)
//!
//! These arms drive the recursion contract: every arm calls back into
//! `eval_expr` (the same depth-aware router from `dispatch::eval_expr`)
//! so depth accounting stays in one place.

use ergo_primitives::cost::{CostAccumulator, JitCost};
use ergo_ser::opcode::{Expr, Payload};
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::SigmaValue;

use super::super::cost::{add_cost, add_cost_per_item};
use super::super::dispatch::{eval_expr, TraceEntry};
use super::super::eval_ctx::EvalCtx;
use super::super::helpers::{infer_expr_type, sigma_to_value, trace_val};
use super::super::types::{Env, EvalError, Value};

// 0x73 ConstPlaceholder(index)
pub(in crate::evaluator) fn eval_const_placeholder(
    index: u32,
    constants: &[(SigmaType, SigmaValue)],
    cost: &mut CostAccumulator,
) -> Result<Value, EvalError> {
    add_cost(cost, 0x73)?;
    let idx = index as usize;
    if idx >= constants.len() {
        return Err(EvalError::ConstantOutOfBounds(index));
    }
    sigma_to_value(&constants[idx].0, &constants[idx].1)
}

// 0x72 ValUse — reference a bound variable
pub(in crate::evaluator) fn eval_val_use(
    id: u32,
    env: &Env,
    cost: &mut CostAccumulator,
) -> Result<Value, EvalError> {
    add_cost(cost, 0x72)?;
    env.get(&id).cloned().ok_or(EvalError::TypeError {
        expected: "bound variable",
        got: format!("unbound ValUse(id={id})"),
    })
}

// 0xD8 BlockValue — bind ValDef/FunDef items then return result.
//
// Scala `BlockValue.eval` casts every item `asInstanceOf[ValDef]`
// (FunDef IS a ValDef with non-empty tpeArgs) and binds it inline —
// the ValDef/FunDef NODES are never dispatched (they have no eval
// override; see the standalone reject arms in dispatch). A non-ValDef
// item fails the cast (ClassCastException → script error).
//
// SCOPING: Scala threads a LOCAL `curEnv` (immutable map) — item
// bindings are visible to later items and to `result`, but the
// caller's env is untouched once the block returns. Bindings must not
// leak past the block, and a shadowed outer id must reappear
// afterwards (an expression evaluated after the block sees the
// PRE-block env). Mirrored with a block-local clone; closures created
// inside the block capture the block env, exactly like Scala's
// FuncValue capturing `curEnv`.
/// Scala `Value.checkType(vd, v)` (values.scala:251/998) narrowed to the single
/// mismatch our runtime value model can exhibit. `SType.isValueOfType` requires
/// a 2-item `STuple` value to be a `Tuple2`; a register holding a `Tuple`
/// (0x86 `CreateTuple`) node evaluates to a `Coll` (see
/// `box_context::read_register_option`), so binding it at a pair type must fail
/// — bug-for-bug with Scala's InterpreterException "Invalid type returned by
/// evaluator". The ValDef type is derived from `rhs` (Scala never serializes
/// it); inference over the immediate `rhs` (empty binding env — the poison's
/// producing `rhs` is a self-contained register read) is enough to catch it at
/// its own binding, and any earlier re-binding was already checked. When the
/// type cannot be inferred, or it is not an `STuple`, the value is accepted
/// unchanged.
fn check_valdef_pair_type(
    rhs: &Expr,
    constants: &[(SigmaType, SigmaValue)],
    val: &Value,
) -> Result<(), EvalError> {
    // Scala runs `Value.checkType(vd, v)` on every ValDef binding
    // (values.scala:998) and `SType.isValueOfType` handles ONLY the
    // pair case for tuples: `STuple(2)` requires a `Tuple2` runtime
    // value, and any other tuple arity hits
    // `sys.error("Unsupported tuple type …")` — which inside
    // `verifyInput` is also a rejection, unconditionally, whatever
    // the runtime value class (SType.scala:200-202). Mirror both:
    //
    //   - a two-element `Value::Tuple` satisfies `STuple(2)` — the
    //     only tuple shape Scala accepts — so it short-circuits
    //     before the inference walk;
    //   - inferred `STuple(2)` with any other value class rejects
    //     (the poisoned 0x86-register Coll);
    //   - inferred `STuple(n != 2)` rejects regardless of the value,
    //     matching the `sys.error` (a 0x86 register of arity 3+ read
    //     at its tuple type lands here — CodeRabbit PR #161 finding).
    if matches!(val, Value::Tuple(items) if items.len() == 2) {
        return Ok(());
    }
    if let Some(SigmaType::STuple(elems)) =
        infer_expr_type(rhs, &std::collections::HashMap::new(), constants)
    {
        if elems.len() == 2 {
            return Err(EvalError::TypeError {
                expected:
                    "Tuple2 for an (_, _) binding (Scala Value.checkType / SType.isValueOfType)",
                got: "non-pair value — a 0x86 CreateTuple register read as (_, _) yields a Coll"
                    .to_string(),
            });
        }
        return Err(EvalError::TypeError {
            expected: "pair — Scala SType.isValueOfType supports only 2-tuples and \
                       sys.errors on any other STuple arity (SType.scala:200-202)",
            got: format!("STuple arity {} binding", elems.len()),
        });
    }
    Ok(())
}

pub(in crate::evaluator) fn eval_block_value(
    items: &[Expr],
    result: &Expr,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    add_cost_per_item(cx.cost, 0xD8, items.len() as u32)?;
    let mut block_env = cx.env.clone();
    for item in items {
        match item {
            Expr::Op(node) => match &node.payload {
                Payload::ValDef { id, rhs, .. } | Payload::FunDef { id, rhs, .. } => {
                    let val = eval_expr(
                        rhs,
                        cx.ctx,
                        cx.constants,
                        &mut block_env,
                        cx.depth,
                        cx.cost,
                        cx.trace,
                    )?;
                    // AddToEnvironment — Scala charges it AFTER the rhs
                    // eval (addFixedCost wraps only the env update).
                    add_cost(cx.cost, 0xD6)?;
                    // Scala `BlockValue.eval` runs `Value.checkType(vd, v)`
                    // (values.scala:998) with `vd.tpe = rhs.tpe`. The only
                    // mismatch our value model can produce is a register holding
                    // a `Tuple` (0x86 `CreateTuple`) node, which evaluates to a
                    // `Coll` (box_context::read_register_option); binding it where
                    // a pair `(_, _)` is expected fails `SType.isValueOfType`
                    // (`isInstanceOf[Tuple2]`), matching Scala's
                    // InterpreterException "Invalid type returned by evaluator"
                    // that fails `verifyInput`. Every legitimate `STuple` value
                    // here is a `Value::Tuple`, so this rejects ONLY the poisoned
                    // register-Coll — never a valid binding. The `rhs` type is
                    // derived (Scala never serializes the ValDef type); when it
                    // cannot be inferred the check is skipped (conservative:
                    // no new reject-valid).
                    check_valdef_pair_type(rhs, cx.constants, &val)?;
                    if let Some(t) = cx.trace.as_mut() {
                        t.push(TraceEntry {
                            label: format!("ValDef({id})"),
                            value: trace_val(&val),
                        });
                    }
                    block_env.insert(*id, val);
                }
                _ => {
                    return Err(EvalError::TypeError {
                        expected: "ValDef/FunDef as BlockValue item (Scala asInstanceOf[ValDef])",
                        got: format!("opcode 0x{:02X}", node.opcode),
                    })
                }
            },
            Expr::Const { .. } => {
                return Err(EvalError::TypeError {
                    expected: "ValDef/FunDef as BlockValue item (Scala asInstanceOf[ValDef])",
                    got: "inline constant".to_string(),
                })
            }
            Expr::Unparsed(_) => {
                return Err(EvalError::TypeError {
                    expected: "ValDef/FunDef as BlockValue item (Scala asInstanceOf[ValDef])",
                    got: "unparsed-tree body".to_string(),
                })
            }
        }
    }
    let result_val = eval_expr(
        result,
        cx.ctx,
        cx.constants,
        &mut block_env,
        cx.depth,
        cx.cost,
        cx.trace,
    )?;
    if let Some(t) = cx.trace.as_mut() {
        t.push(TraceEntry {
            label: "BlockValue result".into(),
            value: trace_val(&result_val),
        });
    }
    Ok(result_val)
}

// 0x95 If(condition, then_branch, else_branch)
pub(in crate::evaluator) fn eval_if(
    cond: &Expr,
    then_br: &Expr,
    else_br: &Expr,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    add_cost(cx.cost, 0x95)?;
    let c = cx.eval_expr(cond)?;
    if let Some(t) = cx.trace.as_mut() {
        t.push(TraceEntry {
            label: "If condition".into(),
            value: trace_val(&c),
        });
    }
    match c {
        Value::Bool(true) => cx.eval_expr(then_br),
        Value::Bool(false) => cx.eval_expr(else_br),
        _ => Err(EvalError::TypeError {
            expected: "Bool for If condition",
            got: format!("{c:?}"),
        }),
    }
}

// 0x86 Tuple — eager construction. Scala `Tuple.eval` (values.scala) rejects
// any arity other than 2 (`if (items.length != 2) syntax.error("Invalid
// tuple ...")`) — only pairs are valid in v4/v5/v6. (ExtractCreationInfo is a
// separate node producing an arity-2 result and is unaffected.)
//
// The arity check is intentionally BEFORE `add_cost`, mirroring Scala
// exactly: Tuple.eval runs the `items.length != 2` check first and calls
// `addCost(Tuple.costKind)` only at the very end (after evaluating the two
// items). So a non-pair tuple errors with the arity error WITHOUT charging
// the Tuple cost — even under a cost budget below 0x86's fixed cost, the
// arity error must win over a cost-limit error (matching Scala's
// `syntax.error` firing before `addCost`). Do NOT move `add_cost` above this
// guard: that would surface CostExceeded where Scala surfaces "Invalid
// tuple" — a consensus divergence on the error class.
pub(in crate::evaluator) fn eval_tuple(
    items: &[Expr],
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    if items.len() != 2 {
        return Err(EvalError::ArityMismatch {
            expected: 2,
            got: items.len(),
        });
    }
    add_cost(cx.cost, 0x86)?;
    let mut values = Vec::with_capacity(items.len());
    for item in items {
        let v = cx.eval_expr(item)?;
        // Scala `Tuple.eval` runs `Value.checkType(item, itemV)` per item;
        // `SType.isValueOfType` then `sys.error("Unsupported tuple type")` for
        // any item whose type is a tuple of arity != 2 — only pairs are a valid
        // runtime tuple representation. A nested *pair* item is fine. The check
        // is shallow (the item's own arity), mirroring the per-item checkType.
        if let Value::Tuple(inner) = &v {
            if inner.len() != 2 {
                return Err(EvalError::TypeError {
                    expected: "pair (arity-2) tuple item",
                    got: format!("tuple item of arity {}", inner.len()),
                });
            }
        }
        values.push(v);
    }
    Ok(Value::Tuple(values))
}

// 0x8C SelectField(input, field_idx) — 1-indexed tuple field access
pub(in crate::evaluator) fn eval_select_field(
    input: &Expr,
    field_idx: u8,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    add_cost(cx.cost, 0x8C)?;
    let tuple = cx.eval_expr(input)?;
    match tuple {
        Value::Tuple(items) => {
            let idx = (field_idx as usize).saturating_sub(1);
            items.get(idx).cloned().ok_or(EvalError::TypeError {
                expected: "valid tuple index",
                got: format!("index {field_idx} in tuple of len {}", items.len()),
            })
        }
        _ => Err(EvalError::TypeError {
            expected: "Tuple",
            got: format!("{tuple:?}"),
        }),
    }
}

// 0xD9 FuncValue — closure capturing the current environment
pub(in crate::evaluator) fn eval_func_value(
    args: &[(u32, Option<SigmaType>)],
    body: &Expr,
    env: &Env,
    cost: &mut CostAccumulator,
) -> Result<Value, EvalError> {
    add_cost(cost, 0xD9)?;
    // Scala `FuncValue.eval` (values.scala:1040-1056): after charging the
    // fixed cost, `if (args.length == 1) <closure> else syntax.error(...)`.
    // A 0- or multi-arg lambda errors when the node is EVALUATED (created),
    // before any application — multi-arg functions are not representable in
    // the evaluator (closures are unary; tuples carry multiple values). A
    // FuncValue on a dead branch is never evaluated, so it never errors.
    if args.len() != 1 {
        return Err(EvalError::RuntimeException(
            "FuncValue must have exactly 1 argument",
        ));
    }
    let params: Vec<u32> = args.iter().map(|(id, _)| *id).collect();
    Ok(Value::Func {
        captured_env: std::rc::Rc::new(env.clone()),
        params,
        param_types: args.to_vec(),
        body: Box::new(body.clone()),
    })
}

/// Scala `FuncValue.eval` closures run `Value.checkType(argTpe, vArg)`
/// on EVERY invocation. `SType.isValueOfType` is SHALLOW — a `Coll[T]`
/// parameter accepts any `Coll` value (`case _: SCollectionType[_] =>
/// x.isInstanceOf[Coll[_]]`, no element recursion) — but it has NO
/// case for a top-level `STypeVar` and falls through to
/// `sys.error("Unknown type")`. So a polymorphic lambda
/// `(x: T) => ...` CREATES fine but ALWAYS errors when invoked, from
/// any call path: direct `FuncApply` and every HOF loop
/// (map/filter/forall/exists/fold/flatMap). Called per invocation so
/// a HOF over an EMPTY collection never errors (Scala never enters
/// the closure). Vector: HOF_FunDef_type_var_body
/// identity-applied-reject.
pub(in crate::evaluator) fn check_closure_param_types(
    param_types: &[(u32, Option<SigmaType>)],
) -> Result<(), EvalError> {
    for (_, tpe) in param_types {
        if let Some(SigmaType::STypeVar(name)) = tpe {
            return Err(EvalError::TypeError {
                expected:
                    "concrete lambda parameter type (Scala isValueOfType has no STypeVar case)",
                got: format!("STypeVar({name})"),
            });
        }
    }
    Ok(())
}

// 0xDA FuncApply — closure invocation. Charges AddToEnv (5 jit) per call.
pub(in crate::evaluator) fn eval_func_apply(
    func: &Expr,
    arg_exprs: &[Expr],
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    add_cost(cx.cost, 0xDA)?;
    let func_val = cx.eval_expr(func)?;
    match func_val {
        Value::Func {
            captured_env,
            params,
            param_types,
            body,
        } => {
            if params.len() != arg_exprs.len() {
                return Err(EvalError::ArityMismatch {
                    expected: params.len(),
                    got: arg_exprs.len(),
                });
            }
            let mut call_env = (*captured_env).clone();
            for (param_id, arg_expr) in params.iter().zip(arg_exprs.iter()) {
                let arg_val = cx.eval_expr(arg_expr)?;
                check_closure_param_types(&param_types)?;
                call_env.insert(*param_id, arg_val);
            }
            // AddToEnvironment — charged once per invocation, AFTER
            // arg evaluation and checkType: Scala's closure runs
            // checkType first and only then addFixedCost(AddToEnv)
            // around the env update, so a polymorphic reject must not
            // pay this charge. (Scala closures are always 1-arg —
            // multi-param creation errors there — so the single
            // post-loop charge is exact for every Scala-reachable
            // shape and keeps the per-invocation convention for the
            // multi-arg extension.)
            cx.cost.add(JitCost::from_jit(5))?;
            #[cfg(feature = "cost-trace")]
            crate::cost_trace::record("AddToEnv", 5, cx.cost.total().value());
            // Body evaluates with a fresh `call_env`, not the caller's env.
            // Direct call to the free function so we can swap envs without
            // disturbing `cx.env`.
            eval_expr(
                &body,
                cx.ctx,
                cx.constants,
                &mut call_env,
                cx.depth,
                cx.cost,
                cx.trace,
            )
        }
        _ => Err(EvalError::TypeError {
            expected: "Func for FuncApply",
            got: format!("{func_val:?}"),
        }),
    }
}
