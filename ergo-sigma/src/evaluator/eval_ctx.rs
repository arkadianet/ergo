//! Per-evaluation borrow bundle.
//!
//! `EvalCtx` packages the six borrows every recursive opcode helper
//! threads end-to-end: the immutable `ReductionContext`, the immutable
//! `constants` table, plus four mutable accumulators — `env`, `depth`,
//! `cost`, and `trace`. Helpers that need all six take a single
//! `&mut EvalCtx<'_>` rather than a six-parameter signature, which lets
//! `evaluator/opcodes/*` drop their module-level
//! `#![allow(clippy::too_many_arguments)]`.
//!
//! Single lifetime is sufficient: `ReductionContext<'a>` is covariant
//! in its lifetime (only borrows `&[T]` slices), so unifying its
//! lifetime with the EvalCtx lifetime does not constrain callers.
//!
//! Visibility is `pub(in crate::evaluator)` — the bundle is an
//! evaluator-internal convenience and must not appear on any public
//! surface (`reduce_expr*` keep their original signatures).
//!
//! Helpers that genuinely take only a subset of the six fields stay
//! narrow on purpose: forcing them to take `&mut EvalCtx` would
//! over-borrow and create needless lifetime pressure for no readability
//! gain. Keep narrow: `eval_const_placeholder`, `eval_val_use`,
//! `eval_func_value`, `eval_get_var`, simple constant emitters,
//! `eval_no_arg_method`, `decode_group_element`.

use ergo_primitives::cost::CostAccumulator;
use ergo_ser::opcode::Expr;
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::SigmaValue;

use super::dispatch::{eval_expr, TraceEntry};
use super::types::{Env, EvalError, ReductionContext, Value};

pub(in crate::evaluator) struct EvalCtx<'a> {
    pub ctx: &'a ReductionContext<'a>,
    pub constants: &'a [(SigmaType, SigmaValue)],
    pub env: &'a mut Env,
    pub depth: &'a mut usize,
    pub cost: &'a mut CostAccumulator,
    pub trace: &'a mut Option<Vec<TraceEntry>>,
}

impl EvalCtx<'_> {
    /// Recurse into the depth-aware router from `dispatch::eval_expr`.
    /// Splits the bundle's borrows back into the underlying six refs;
    /// the reborrows expire at the end of the call so the caller's
    /// `&mut EvalCtx` is usable again afterwards.
    #[inline]
    pub(in crate::evaluator) fn eval_expr(&mut self, expr: &Expr) -> Result<Value, EvalError> {
        eval_expr(
            expr,
            self.ctx,
            self.constants,
            self.env,
            self.depth,
            self.cost,
            self.trace,
        )
    }
}
