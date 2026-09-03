//! The canonical preorder walk over an [`Expr`] tree — the ONE node-identity
//! contract shared by the compiler's source map and any consumer that wants
//! to cite a node (`docs/ergoscript-compiler-source-map-design.md` §2).
//!
//! Ids are assigned by depth-first traversal in payload field order
//! (`0` = root). Both producer and consumer MUST take ids from this walk
//! rather than derive their own: an independently maintained counter drifts
//! silently the first time one side skips a subtree.

use super::types::{Expr, Payload};

/// Direct children of `e`, in the order the walk visits them (payload field
/// order, which is also serialization order).
pub fn children(e: &Expr) -> Vec<&Expr> {
    let node = match e {
        Expr::Op(n) => n,
        Expr::Const { .. } | Expr::Unparsed(_) => return Vec::new(),
    };
    match &node.payload {
        Payload::Zero
        | Payload::ValUse { .. }
        | Payload::ConstPlaceholder { .. }
        | Payload::TaggedVar { .. }
        | Payload::BoolCollection { .. }
        | Payload::GetVar { .. }
        | Payload::DeserializeContext { .. }
        | Payload::NoneValue { .. } => Vec::new(),
        Payload::One(a) => vec![&**a],
        Payload::Two(a, b) => vec![&**a, &**b],
        Payload::Three(a, b, c) => vec![&**a, &**b, &**c],
        Payload::Four(a, b, c, d) => vec![&**a, &**b, &**c, &**d],
        Payload::ValDef { rhs, .. } | Payload::FunDef { rhs, .. } => vec![&**rhs],
        Payload::BlockValue { items, result } => {
            let mut v: Vec<&Expr> = items.iter().collect();
            v.push(result);
            v
        }
        Payload::FuncValue { body, .. } => vec![&**body],
        Payload::MethodCall { obj, args, .. } => {
            let mut v = vec![&**obj];
            v.extend(args.iter());
            v
        }
        Payload::ConcreteCollection { items, .. }
        | Payload::Tuple { items }
        | Payload::SigmaCollection { items } => items.iter().collect(),
        Payload::SelectField { input, .. }
        | Payload::ExtractRegisterAs { input, .. }
        | Payload::NumericCast { input, .. } => vec![&**input],
        Payload::DeserializeRegister { default, .. } => default.as_deref().into_iter().collect(),
        Payload::ByIndex {
            input,
            index,
            default,
        } => {
            let mut v = vec![&**input, &**index];
            v.extend(default.as_deref());
            v
        }
        Payload::FuncApply { func, args } => {
            let mut v = vec![&**func];
            v.extend(args.iter());
            v
        }
    }
}

/// Depth-first preorder over `root`: `(id, node)` with ids `0..n` in visit
/// order.
pub fn preorder(root: &Expr) -> impl Iterator<Item = (u64, &Expr)> {
    let mut stack: Vec<&Expr> = vec![root];
    let mut next: u64 = 0;
    std::iter::from_fn(move || {
        let e = stack.pop()?;
        // Push children reversed so the first child is visited next.
        for c in children(e).into_iter().rev() {
            stack.push(c);
        }
        let id = next;
        next += 1;
        Some((id, e))
    })
}

/// The opcode tag a walk reports for `e`: the opcode byte for an op node,
/// `0x00` for an inline constant, `0xFF` for an unparsed body.
pub fn node_opcode(e: &Expr) -> u8 {
    match e {
        Expr::Op(n) => n.opcode,
        Expr::Const { .. } => 0x00,
        Expr::Unparsed(_) => 0xFF,
    }
}
