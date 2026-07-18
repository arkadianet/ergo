//! `SOption` (type_id 36) `0xDC MethodCall` arms: map(7), filter(8).

use ergo_primitives::cost::JitCost;
use ergo_ser::opcode::Expr;

use crate::evaluator::cost::add_method_cost;
use crate::evaluator::dispatch::eval_expr;
use crate::evaluator::eval_ctx::EvalCtx;
use crate::evaluator::opcodes::binding::check_closure_param_types;
use crate::evaluator::types::{EvalError, Value};

// SOption(36).map(7) -> Option[B]
// Scala: opt.map(f) — apply f to value if Some, return None if None.
// `SOption.MapMethod.costKind = FixedCost(JitCost(20))`; applying the
// lambda to a Some value additionally charges AddToEnv(5) when the
// argument is bound (same per-application overhead as every other HOF
// lambda invocation, e.g. MapCollection). None applies no lambda.
pub(super) fn map(obj_val: Value, args: &[Expr], cx: &mut EvalCtx<'_>) -> Result<Value, EvalError> {
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
                param_types,
                body,
            } => {
                // Scala closure invocation: Value.checkType runs
                // before the AddToEnvironment charge.
                check_closure_param_types(&param_types)?;
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
pub(super) fn filter(
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
    // Scala `FilterMethod` is `FixedCost(JitCost(20))` (methods.scala
    // SOptionMethods) — same as `map`; charging 10 diverges on consensus cost.
    add_method_cost(cx.cost, 20)?;
    let func_val = cx.eval_expr(&args[0])?;
    match obj_val {
        Value::Opt(None) => Ok(Value::Opt(None)),
        Value::Opt(Some(inner)) => match func_val {
            Value::Func {
                captured_env,
                params,
                param_types,
                body,
            } => {
                // Scala closure invocation runs Value.checkType.
                check_closure_param_types(&param_types)?;
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
