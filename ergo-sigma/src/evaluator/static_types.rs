//! Static node types for the reference's runtime `Value.checkType` calls.
//!
//! Scala keeps a `tpe` on every ErgoTree node and, at fixed evaluation sites
//! (ValUse, BlockValue items and result, lambda argument and body, Tuple and
//! ConcreteCollection items, Fold zero, ByIndex and OptionGetOrElse defaults,
//! `==`/`!=` operands, If branches, `Coll.getOrElse`'s default), compares the
//! evaluated value's class with that type, failing the script on a mismatch.
//! Our IR carries no per-node type, so the types are computed once per
//! evaluated tree by the parse-order typer
//! ([`ergo_ser::ergo_tree::record_node_types`]) and looked up by node address.
//!
//! The table lives for one script evaluation (a [`Scope`] at the evaluation
//! root). Every tree it describes stays alive and unmoved for that time: the
//! evaluated tree is borrowed by the root call, and lambda bodies are cloned
//! once per evaluation into reference-counted copies the table owns, with the
//! original nodes' types copied onto them, so closures never evaluate a node
//! whose address could be reused while the table refers to it.
//! <https://github.com/ergoplatform/sigmastate-interpreter/blob/v6.0.7/data/shared/src/main/scala/sigma/ast/values.scala#L251-L260>

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use ergo_ser::opcode::{Expr, IrNode};
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::SigmaValue;

use super::helpers::check_value_type;
use super::types::{EvalError, Value};

#[derive(Default)]
struct Table {
    /// Node address -> static type, for every node the typer determines.
    types: HashMap<usize, SigmaType>,
    /// Original lambda body address -> its stable per-evaluation copy.
    bodies: HashMap<usize, Rc<Expr>>,
    /// Addresses of substituted runtime-deserialized expressions.
    fresh_roots: HashSet<usize>,
    /// Nesting count of open scopes.
    depth: usize,
}

fn addr(expr: &Expr) -> usize {
    expr as *const Expr as usize
}

/// Record that `expr` is a substituted runtime-deserialized expression.
pub(crate) fn mark_fresh_root(expr: &Expr) {
    TABLE.with(|t| {
        if let Some(table) = t.borrow_mut().as_mut() {
            table.fresh_roots.insert(addr(expr));
        }
    });
}

/// Whether `expr` was recorded by [`mark_fresh_root`]; the record is removed.
pub(crate) fn take_fresh_root(expr: &Expr) -> bool {
    TABLE.with(|t| {
        t.borrow_mut()
            .as_mut()
            .is_some_and(|table| table.fresh_roots.remove(&addr(expr)))
    })
}

/// Move the fresh-root records of `original`'s descendants to the
/// same nodes of its structural `copy` (the roots themselves are the
/// caller's: a copy is usually moved into place afterwards).
pub(crate) fn copy_fresh_roots(original: &Expr, copy: &Expr) {
    TABLE.with(|t| {
        if let Some(table) = t.borrow_mut().as_mut() {
            for ((_, o), (_, c)) in ergo_ser::opcode::preorder(original)
                .zip(ergo_ser::opcode::preorder(copy))
                .skip(1)
            {
                if table.fresh_roots.remove(&addr(o)) {
                    table.fresh_roots.insert(addr(c));
                }
            }
        }
    });
}

thread_local! {
    static TABLE: RefCell<Option<Table>> = const { RefCell::new(None) };
}

/// Keeps the type table alive for one evaluation. Nested scopes share it; the
/// outermost drop clears it.
pub(crate) struct Scope(());

impl Scope {
    pub(crate) fn enter() -> Self {
        TABLE.with(|t| {
            let mut t = t.borrow_mut();
            t.get_or_insert_with(Table::default).depth += 1;
        });
        Scope(())
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        // The table owns lambda body copies; drop them outside the borrow.
        let finished = TABLE.with(|t| {
            let mut t = t.borrow_mut();
            let done = match t.as_mut() {
                Some(table) => {
                    table.depth = table.depth.saturating_sub(1);
                    table.depth == 0
                }
                None => false,
            };
            if done {
                t.take()
            } else {
                None
            }
        });
        drop(finished);
    }
}

/// Type every node of an evaluated tree. The recorded fresh roots (substituted
/// runtime-deserialized expressions) are typed as Scala typed them, each on
/// its own reader.
pub(crate) fn annotate(expr: &Expr, constants: &[(SigmaType, SigmaValue)]) {
    TABLE.with(|t| {
        if let Some(table) = t.borrow_mut().as_mut() {
            let fresh = std::mem::take(&mut table.fresh_roots);
            ergo_ser::ergo_tree::record_node_types(expr, constants, &fresh, &mut table.types);
        }
    });
}

/// The static type of `expr`, when the typer determined it.
pub(crate) fn node_type(expr: &Expr) -> Option<SigmaType> {
    lookup(ergo_ser::ergo_tree::node_key(expr))
}

/// The static type of an operation node.
pub(crate) fn op_type(node: &IrNode) -> Option<SigmaType> {
    lookup(node as *const IrNode as usize)
}

fn lookup(key: usize) -> Option<SigmaType> {
    TABLE.with(|t| {
        t.borrow()
            .as_ref()
            .and_then(|table| table.types.get(&key).cloned())
    })
}

/// A lambda body for a closure: one copy per evaluation, carrying the
/// original nodes' static types.
pub(crate) fn func_body(body: &Expr) -> Rc<Expr> {
    let key = addr(body);
    TABLE.with(|t| {
        let mut t = t.borrow_mut();
        let Some(table) = t.as_mut() else {
            return Rc::new(body.clone());
        };
        if let Some(copy) = table.bodies.get(&key) {
            return Rc::clone(copy);
        }
        let copy = Rc::new(body.clone());
        for ((_, original), (_, copied)) in
            ergo_ser::opcode::preorder(body).zip(ergo_ser::opcode::preorder(&copy))
        {
            let key = ergo_ser::ergo_tree::node_key(original);
            if let Some(tpe) = table.types.get(&key).cloned() {
                table
                    .types
                    .insert(ergo_ser::ergo_tree::node_key(copied), tpe);
            }
        }
        table.bodies.insert(key, Rc::clone(&copy));
        copy
    })
}

/// Scala `Value.checkType(node, value)`. A node whose type is unknown, or only
/// known as the typer's `SAny` placeholder, is not checked.
pub(crate) fn check_node(expr: &Expr, value: &Value, v3_tree: bool) -> Result<(), EvalError> {
    check_typed(node_type(expr), value, v3_tree)
}

/// [`check_node`] for an operation node.
pub(crate) fn check_op(node: &IrNode, value: &Value, v3_tree: bool) -> Result<(), EvalError> {
    check_typed(op_type(node), value, v3_tree)
}

fn check_typed(tpe: Option<SigmaType>, value: &Value, v3_tree: bool) -> Result<(), EvalError> {
    match tpe {
        Some(SigmaType::SAny) | None => Ok(()),
        Some(tpe) => check_value_type(&tpe, value, v3_tree),
    }
}
