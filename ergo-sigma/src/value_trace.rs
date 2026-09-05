//! Debug-only value trace (feature `value-trace`): every evaluated node's
//! value, keyed by the node's preorder id in the tree being reduced — what
//! a workbench needs to show "this expression was `false`" over the
//! source, through the compiler's source map. Never a consensus path:
//! recording is a thread-local the caller arms per reduction, and the
//! evaluator only looks at it when the feature is compiled in.
//!
//! Ids come from `ergo_ser::opcode::preorder` over the root passed to
//! [`enable`]; nodes are matched by address, so an inlined copy the
//! evaluator makes (a tree with `deserialize`) records nothing — which is
//! the honest answer for a rewritten tree.

use std::cell::RefCell;
use std::collections::HashMap;

use ergo_ser::opcode::{preorder, Expr};

use crate::evaluator::Value;

/// One recorded value: the node's preorder id and a rendering of its value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueEntry {
    pub id: u64,
    pub value: String,
}

#[derive(Default)]
struct Recorder {
    ids: HashMap<usize, u64>,
    entries: Vec<ValueEntry>,
}

thread_local! {
    static TRACE: RefCell<Option<Recorder>> = const { RefCell::new(None) };
}

/// Begin recording on this thread for a reduction of `root`. Replaces
/// any active recording.
pub fn enable(root: &Expr) {
    let ids = preorder(root)
        .map(|(id, e)| (e as *const Expr as usize, id))
        .collect();
    TRACE.with(|t| {
        *t.borrow_mut() = Some(Recorder {
            ids,
            entries: Vec::new(),
        })
    });
}

/// Stop recording and take the entries, in evaluation order (a node
/// evaluated several times — a lambda body — appears several times).
pub fn take() -> Option<Vec<ValueEntry>> {
    TRACE.with(|t| t.borrow_mut().take().map(|r| r.entries))
}

/// Record `value` for `expr` if a recording is active and the node is
/// one of the armed root's. No-op otherwise.
pub fn record(expr: &Expr, value: &Value) {
    TRACE.with(|t| {
        let mut b = t.borrow_mut();
        let Some(r) = b.as_mut() else { return };
        let Some(&id) = r.ids.get(&(expr as *const Expr as usize)) else {
            return;
        };
        let rendered = crate::evaluator::render_value(value);
        r.entries.push(ValueEntry {
            id,
            value: rendered,
        });
    });
}
