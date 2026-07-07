//! M4 Task 6 — D-C3: `SigmaPropIsProven` elimination + Boolean↔SigmaProp
//! coercion fusion (`dev-docs/ergoscript-compiler-m4-recon/recon-transforms.md`
//! §3).
//!
//! A typed AST that mixes `SigmaProp` and `Boolean` in a logical context
//! carries the round-trip coercions `SigmaPropIsProven` (`.isProven`, wire
//! opcode `0xCF`) and `BoolToSigmaProp` (`sigmaProp(..)`, `0xD1`). Neither
//! evaluator accepts a residual `0xCF` (`SigmaPropIsProven` has `costKind =
//! notSupportedError` and no `eval`, transformers.scala:321-329), so a compile
//! output carrying one is unevaluable (lib.rs D-C3). Scala's GraphBuilding
//! CANCELS the coercions via two `rewriteDef` fusion rules:
//!
//! - **isProven→isValid fusion** (`GraphBuilding.scala:188`,
//!   `(sigmaProp(bool)).isValid → bool`): `SigmaPropIsProven(BoolToSigmaProp(x))
//!   → x`. Fires inside the `toExp`/`rewriteDef` fixpoint, so it must run
//!   BEFORE the generic constant fold ([`crate::fold`]): the Boolean it exposes
//!   then feeds the fold — e.g. `sigmaProp(true) ^ (1 == 1)` becomes
//!   `BinXor(true, true)` which the fold reduces to `false`.
//! - **`sigmaProp(p.isValid) → p`** (`GraphBuilding.scala:189`, plus the
//!   top-level `removeIsProven` at `:245-252` applied at `:418`):
//!   `BoolToSigmaProp(SigmaPropIsProven(p)) → p`. The top-level strip runs
//!   AFTER buildGraph, so this must also run AFTER the lowering block
//!   ([`crate::lower`]) — the D-C2 `proveDlog(const)` fold and the
//!   single-element `AllOf`/`AnyOf` unwrap are what make the
//!   `BoolToSigmaProp`/`SigmaPropIsProven` adjacency appear (e.g.
//!   `allOf(Coll(proveDlog(g1)))` → `BoolToSigmaProp(SigmaPropIsProven(Const
//!   {SigmaProp}))` → bare `SigmaPropConstant`). Because our root coercion
//!   always wraps a Boolean-typed root in `BoolToSigmaProp`, a bare
//!   `SigmaPropIsProven` root never occurs, so the top-level strip and the
//!   `:189` fusion collapse into this single `0xD1(0xCF(p))` rule.
//!
//! **Pass position** (plan locked decision 1): run [`eliminate_isproven`] at
//! TWO points, mirroring the two Scala positions — once BEFORE
//! [`crate::fold`] (the fixpoint fusion) and once AFTER [`crate::lower`] (the
//! post-buildGraph top-level strip, over the adjacency the unwrap/D-C2 fold
//! expose). Both are pure AST→AST rewrites; the fold that reduces a
//! fusion-exposed operand is the existing [`crate::fold`] pass, not this one.
//!
//! **Residual (NOT closed here):** a SigmaProp operand that SURVIVES fusion
//! inside a binary Boolean op (`proveDlog(g1).isProven && HEIGHT > 5`, where
//! the sigma is not itself `sigmaProp(<bool>)`) still needs Scala's `HasSigmas`
//! `SigmaAnd`/`SigmaOr` reconstruction (recon-transforms.md §3/§4,
//! `GraphBuilding.scala:167-203`). No current byte target exercises it (the
//! five graduated SEMANTIC_SKIP sources all carry `sigmaProp(<const bool>)`
//! operands that fuse to plain Booleans; the corpus mixed-logic vectors are
//! MULTI-blocked on val-inlining/CSE, Tasks 8/9). See the emit-arm audit in
//! the lib.rs D-C3 ledger.

use ergo_ser::opcode::{Expr, IrNode, Payload};

// Opcode constants (ergo-ser/src/opcode/types.rs).
const SIGMA_PROP_IS_PROVEN: u8 = 0xCF;
const BOOL_TO_SIGMA_PROP: u8 = 0xD1;

/// Eliminate `SigmaPropIsProven`/`BoolToSigmaProp` round-trip coercions,
/// bottom-up. A single post-order pass suffices: a node's children are fully
/// reduced before its own rule runs, and each rule's result is an
/// already-reduced sub-expression (never a freshly-reducible coercion node),
/// so no fixpoint loop is needed.
pub(crate) fn eliminate_isproven(expr: Expr) -> Expr {
    // 1. Reduce children first (post-order).
    let expr = match expr {
        Expr::Op(IrNode { opcode, payload }) => Expr::Op(IrNode {
            opcode,
            payload: map_children(payload),
        }),
        other => other,
    };
    // 2. Apply the two fusion rules to THIS node (children already reduced).
    match expr {
        // isProven→isValid: `SigmaPropIsProven(BoolToSigmaProp(x)) → x`.
        Expr::Op(IrNode {
            opcode: SIGMA_PROP_IS_PROVEN,
            payload: Payload::One(inner),
        }) => match *inner {
            Expr::Op(IrNode {
                opcode: BOOL_TO_SIGMA_PROP,
                payload: Payload::One(x),
            }) => *x,
            other => Expr::Op(IrNode {
                opcode: SIGMA_PROP_IS_PROVEN,
                payload: Payload::One(Box::new(other)),
            }),
        },
        // sigmaProp(p.isValid)/removeIsProven: `BoolToSigmaProp(SigmaPropIsProven(p)) → p`.
        Expr::Op(IrNode {
            opcode: BOOL_TO_SIGMA_PROP,
            payload: Payload::One(inner),
        }) => match *inner {
            Expr::Op(IrNode {
                opcode: SIGMA_PROP_IS_PROVEN,
                payload: Payload::One(p),
            }) => *p,
            other => Expr::Op(IrNode {
                opcode: BOOL_TO_SIGMA_PROP,
                payload: Payload::One(Box::new(other)),
            }),
        },
        other => other,
    }
}

/// By-value child map — the D-C3 twin of `crate::lower::map_children` /
/// `crate::fold`'s `fold_children` (a new child-carrying `Payload` variant
/// fails to compile here until it is mapped, keeping the traversal exhaustive).
fn map_children(payload: Payload) -> Payload {
    let f = |b: Box<Expr>| Box::new(eliminate_isproven(*b));
    let fv =
        |items: Vec<Expr>| -> Vec<Expr> { items.into_iter().map(eliminate_isproven).collect() };
    match payload {
        Payload::Zero
        | Payload::ValUse { .. }
        | Payload::ConstPlaceholder { .. }
        | Payload::TaggedVar { .. }
        | Payload::BoolCollection { .. }
        | Payload::GetVar { .. }
        | Payload::DeserializeContext { .. }
        | Payload::NoneValue { .. } => payload,
        Payload::One(a) => Payload::One(f(a)),
        Payload::NumericCast { input, tpe } => Payload::NumericCast {
            input: f(input),
            tpe,
        },
        Payload::Two(a, b) => Payload::Two(f(a), f(b)),
        Payload::Three(a, b, c) => Payload::Three(f(a), f(b), f(c)),
        Payload::Four(a, b, c, d) => Payload::Four(f(a), f(b), f(c), f(d)),
        Payload::ValDef { id, tpe, rhs } => Payload::ValDef {
            id,
            tpe,
            rhs: f(rhs),
        },
        Payload::FunDef {
            id,
            tpe,
            tpe_args,
            rhs,
        } => Payload::FunDef {
            id,
            tpe,
            tpe_args,
            rhs: f(rhs),
        },
        Payload::BlockValue { items, result } => Payload::BlockValue {
            items: fv(items),
            result: f(result),
        },
        Payload::FuncValue { args, body } => Payload::FuncValue {
            args,
            body: f(body),
        },
        Payload::MethodCall {
            type_id,
            method_id,
            obj,
            args,
            type_args,
        } => Payload::MethodCall {
            type_id,
            method_id,
            obj: f(obj),
            args: fv(args),
            type_args,
        },
        Payload::ConcreteCollection { elem_type, items } => Payload::ConcreteCollection {
            elem_type,
            items: fv(items),
        },
        Payload::Tuple { items } => Payload::Tuple { items: fv(items) },
        Payload::SigmaCollection { items } => Payload::SigmaCollection { items: fv(items) },
        Payload::SelectField { input, field_idx } => Payload::SelectField {
            input: f(input),
            field_idx,
        },
        Payload::ExtractRegisterAs { input, reg_id, tpe } => Payload::ExtractRegisterAs {
            input: f(input),
            reg_id,
            tpe,
        },
        Payload::DeserializeRegister {
            reg_id,
            tpe,
            default,
        } => Payload::DeserializeRegister {
            reg_id,
            tpe,
            default: default.map(f),
        },
        Payload::ByIndex {
            input,
            index,
            default,
        } => Payload::ByIndex {
            input: f(input),
            index: f(index),
            default: default.map(f),
        },
        Payload::FuncApply { func, args } => Payload::FuncApply {
            func: f(func),
            args: fv(args),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::group_element::GroupElement;
    use ergo_ser::sigma_type::SigmaType;
    use ergo_ser::sigma_value::{SigmaBoolean, SigmaValue};

    // ----- helpers -----

    fn op1(opcode: u8, inner: Expr) -> Expr {
        Expr::Op(IrNode {
            opcode,
            payload: Payload::One(Box::new(inner)),
        })
    }

    fn op2(opcode: u8, l: Expr, r: Expr) -> Expr {
        Expr::Op(IrNode {
            opcode,
            payload: Payload::Two(Box::new(l), Box::new(r)),
        })
    }

    fn bool_const(b: bool) -> Expr {
        Expr::Const {
            tpe: SigmaType::SBoolean,
            val: SigmaValue::Boolean(b),
        }
    }

    fn height() -> Expr {
        Expr::Op(IrNode {
            opcode: 0xA3,
            payload: Payload::Zero,
        })
    }

    fn sigma_const(byte: u8) -> Expr {
        let mut bytes = [0u8; 33];
        bytes[0] = 0x02;
        bytes[1] = byte;
        Expr::Const {
            tpe: SigmaType::SSigmaProp,
            val: SigmaValue::SigmaProp(SigmaBoolean::ProveDlog(GroupElement::from_bytes(bytes))),
        }
    }

    // ----- happy path -----

    #[test]
    fn eliminate_isproven_of_sigmaprop_bool_fuses_to_the_bool() {
        // SigmaPropIsProven(BoolToSigmaProp(true)) → true (rule 1).
        let e = op1(
            SIGMA_PROP_IS_PROVEN,
            op1(BOOL_TO_SIGMA_PROP, bool_const(true)),
        );
        assert_eq!(eliminate_isproven(e), bool_const(true));
    }

    #[test]
    fn eliminate_sigmaprop_of_isproven_fuses_to_the_sigma() {
        // BoolToSigmaProp(SigmaPropIsProven(p)) → p (rule 2 / removeIsProven).
        let p = sigma_const(0xAA);
        let e = op1(BOOL_TO_SIGMA_PROP, op1(SIGMA_PROP_IS_PROVEN, p.clone()));
        assert_eq!(eliminate_isproven(e), p);
    }

    #[test]
    fn eliminate_isproven_fires_on_nested_operand() {
        // BinAnd(SigmaPropIsProven(BoolToSigmaProp(true)), height) →
        // BinAnd(true, height): rule 1 fires on the left operand, the node
        // itself is untouched (the fold that keeps/reduces BinAnd is a later
        // pass).
        let e = op2(
            0xED,
            op1(
                SIGMA_PROP_IS_PROVEN,
                op1(BOOL_TO_SIGMA_PROP, bool_const(true)),
            ),
            height(),
        );
        assert_eq!(eliminate_isproven(e), op2(0xED, bool_const(true), height()));
    }

    #[test]
    fn eliminate_isproven_double_coercion_chain_fully_cancels() {
        // BoolToSigmaProp(SigmaPropIsProven(BoolToSigmaProp(SigmaPropIsProven(p))))
        // → p (post-order cancels both round trips in one pass).
        let p = sigma_const(0xBB);
        let e = op1(
            BOOL_TO_SIGMA_PROP,
            op1(
                SIGMA_PROP_IS_PROVEN,
                op1(BOOL_TO_SIGMA_PROP, op1(SIGMA_PROP_IS_PROVEN, p.clone())),
            ),
        );
        assert_eq!(eliminate_isproven(e), p);
    }

    // ----- error paths / non-firing -----

    #[test]
    fn eliminate_isproven_leaves_non_coercion_isproven_alone() {
        // SigmaPropIsProven whose child is NOT a BoolToSigmaProp (a surviving
        // sigma, e.g. a bare SigmaProp const) is left as-is — the HasSigmas
        // reconstruction residual, not this pass's job.
        let e = op1(SIGMA_PROP_IS_PROVEN, sigma_const(0xCC));
        assert_eq!(eliminate_isproven(e.clone()), e);
    }

    #[test]
    fn eliminate_isproven_leaves_ordinary_sigmaprop_wrap_alone() {
        // BoolToSigmaProp(GT(..)) — the ordinary `sigmaProp(HEIGHT > 5)` shape
        // — must NOT fire (child is not SigmaPropIsProven).
        let e = op1(BOOL_TO_SIGMA_PROP, op2(0x8F, height(), bool_const(true)));
        assert_eq!(eliminate_isproven(e.clone()), e);
    }

    #[test]
    fn eliminate_isproven_is_idempotent() {
        let p = sigma_const(0xDD);
        let e = op1(BOOL_TO_SIGMA_PROP, op1(SIGMA_PROP_IS_PROVEN, p.clone()));
        let once = eliminate_isproven(e);
        assert_eq!(eliminate_isproven(once.clone()), once);
        assert_eq!(once, p);
    }
}
