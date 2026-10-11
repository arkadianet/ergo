//! Optional per-thread budget on the collection bytes an evaluation
//! materialises.
//!
//! Cost accounting bounds evaluation *work*, but some operations (for
//! example `Append` inside `map`) build large collections for a small cost
//! per item. Callers that evaluate untrusted trees outside validation (the
//! API script playground) install an [`EvalMemoryBudget`] for the duration
//! of one reduction. While it is installed, every collection value the
//! evaluator produces is charged by its shallow size (element count times
//! element size); the cumulative total is an upper bound on what the
//! evaluation allocated for collection results. Exceeding the limit ends
//! the evaluation with [`EvalError::MemoryBudgetExceeded`].
//!
//! No budget is installed on block, mempool or mining validation, so their
//! verdicts are unchanged; the only cost there is one thread-local read per
//! evaluated node.

use std::cell::Cell;

use super::types::{EvalError, Value};

thread_local! {
    /// `(used, limit)` while a budget is installed on this thread.
    static BUDGET: Cell<Option<(u64, u64)>> = const { Cell::new(None) };
}

/// RAII guard: installs a collection-bytes budget for the current thread
/// and removes it (restoring any outer budget) on drop.
#[must_use = "the budget is removed when the guard is dropped"]
pub struct EvalMemoryBudget {
    previous: Option<(u64, u64)>,
}

impl EvalMemoryBudget {
    /// Install a budget of `limit_bytes` on the current thread.
    pub fn install(limit_bytes: u64) -> Self {
        let previous = BUDGET.with(|b| b.replace(Some((0, limit_bytes))));
        Self { previous }
    }

    /// Bytes charged so far on this thread's active budget.
    pub fn used(&self) -> u64 {
        BUDGET.with(|b| b.get().map(|(used, _)| used).unwrap_or(0))
    }
}

impl Drop for EvalMemoryBudget {
    fn drop(&mut self) {
        BUDGET.with(|b| b.set(self.previous));
    }
}

/// Charge `value` against the active budget, if any.
#[inline]
pub(crate) fn charge(value: &Value) -> Result<(), EvalError> {
    BUDGET.with(|b| match b.get() {
        None => Ok(()),
        Some((used, limit)) => {
            let used = used.saturating_add(shallow_bytes(value));
            b.set(Some((used, limit)));
            if used > limit {
                Err(EvalError::MemoryBudgetExceeded { used, limit })
            } else {
                Ok(())
            }
        }
    })
}

/// Shallow heap size of a collection value: element count times the size of
/// one element. Nested collections are charged when they are produced, so
/// they are not walked again here (that keeps the charge O(1)).
fn shallow_bytes(value: &Value) -> u64 {
    use std::mem::size_of;
    let bytes = match value {
        Value::CollBytes(v) => v.len(),
        Value::CollBool(v) => v.len(),
        Value::CollShort(v) => v.len() * size_of::<i16>(),
        Value::CollInt(v) => v.len() * size_of::<i32>(),
        Value::CollLong(v) => v.len() * size_of::<i64>(),
        Value::Tokens(v) => v.len() * size_of::<([u8; 32], u64)>(),
        Value::CollSigmaProp(v) => v.len() * size_of::<ergo_ser::sigma_value::SigmaBoolean>(),
        Value::CollHeader(v) => v.len() * size_of::<super::types::EvalHeader>(),
        Value::CollGeneric(v, _) | Value::CollLegacyPair(v, _, _) | Value::CollBox(v) => {
            v.len() * size_of::<Value>()
        }
        Value::Tuple(v) => v.len() * size_of::<Value>(),
        Value::Str(s) => s.len(),
        _ => 0,
    };
    bytes as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_budget_never_charges() {
        assert!(charge(&Value::CollBytes(vec![0; 1 << 20])).is_ok());
    }

    #[test]
    fn budget_rejects_once_cumulative_bytes_exceed_limit_and_restores_on_drop() {
        {
            let guard = EvalMemoryBudget::install(1000);
            assert!(charge(&Value::CollBytes(vec![0; 600])).is_ok());
            assert_eq!(guard.used(), 600);
            let err = charge(&Value::CollBytes(vec![0; 600])).unwrap_err();
            assert!(matches!(
                err,
                EvalError::MemoryBudgetExceeded {
                    used: 1200,
                    limit: 1000
                }
            ));
        }
        // Dropped: no budget left on this thread.
        assert!(charge(&Value::CollBytes(vec![0; 1 << 20])).is_ok());
    }
}
