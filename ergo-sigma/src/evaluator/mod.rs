mod cost;
mod dispatch;
mod eval_ctx;
mod helpers;
mod opcodes;
mod types;

pub use dispatch::*;
pub use helpers::sigma_to_value;

/// A short, human-readable rendering of a runtime value (the form the
/// evaluator's own trace uses; long values are truncated).
pub fn render_value(v: &Value) -> String {
    helpers::serialize::trace_val(v)
}
pub use types::*;

#[cfg(test)]
mod tests;

pub use opcodes::method_call::method_cost_rows;
pub use opcodes::property_call::no_arg_cost_rows;
