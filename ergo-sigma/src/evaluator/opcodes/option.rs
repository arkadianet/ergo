//! Option opcodes: OptionGet (0xE4), OptionGetOrElse (0xE5),
//! OptionIsDefined (0xE6). NoneValue (0xDF) has no dispatch arm —
//! `None: Option[T]` flows through the type-prefixed SOption constant
//! encoding and lowers to `Value::Opt(None)` via `sigma_to_value`.

use ergo_ser::opcode::Expr;

use super::super::cost::add_cost;
use super::super::eval_ctx::EvalCtx;
use super::super::types::{EvalError, Value};

// 0xE4 OptionGet — unwrap Option, error if None or non-Option
pub(in crate::evaluator) fn eval_option_get(
    inner: &Expr,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    add_cost(cx.cost, 0xE4)?;
    let val = cx.eval_expr(inner)?;
    match val {
        Value::Opt(Some(v)) => Ok(*v),
        Value::Opt(None) => Err(EvalError::TypeError {
            expected: "Some value",
            got: "None".into(),
        }),
        _ => Err(EvalError::TypeError {
            expected: "Option for OptionGet",
            got: format!("{val:?}"),
        }),
    }
}

// 0xE5 OptionGetOrElse — unwrap Option with default
pub(in crate::evaluator) fn eval_option_get_or_else(
    opt_expr: &Expr,
    default_expr: &Expr,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    add_cost(cx.cost, 0xE5)?;
    let val = cx.eval_expr(opt_expr)?;
    match val {
        Value::Opt(Some(v)) => Ok(*v),
        Value::Opt(None) => cx.eval_expr(default_expr),
        _ => Err(EvalError::TypeError {
            expected: "Option for OptionGetOrElse",
            got: format!("{val:?}"),
        }),
    }
}

// 0xE6 OptionIsDefined — check if Option is Some
pub(in crate::evaluator) fn eval_option_is_defined(
    inner: &Expr,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    add_cost(cx.cost, 0xE6)?;
    let val = cx.eval_expr(inner)?;
    match val {
        Value::Opt(Some(_)) => Ok(Value::Bool(true)),
        Value::Opt(None) => Ok(Value::Bool(false)),
        _ => Err(EvalError::TypeError {
            expected: "Option for OptionIsDefined",
            got: format!("{val:?}"),
        }),
    }
}
