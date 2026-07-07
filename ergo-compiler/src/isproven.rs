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
//! **`HasSigmas` reconstruction (M5 Task 5b, D-C3 residual now CLOSED):** a
//! SigmaProp operand that SURVIVES fusion inside a logical op
//! (`proveDlog(receiver).isProven && HEIGHT > 5`, or an `allOf(Coll(.., sigma))`,
//! where the sigma is not itself `sigmaProp(<bool>)`) is now reconstructed into
//! Scala's `SigmaAnd`/`SigmaOr` shape (recon-transforms.md §3/§4,
//! `GraphBuilding.scala:167-203`) by [`reconstruct_binop`] / [`reconstruct_collop`],
//! run in this same post-order pass (see [`eliminate_isproven`] rule family 2).
//! Byte-pinned against three corpus vectors whose CSE schedule is otherwise
//! oracle-exact: `chaincash-basis/basis-tracker-basis.es` and
//! `chaincash/offchain/basis.es` (the `&&`-chain `BinAnd` form,
//! `ea02d1…cd7208`) and `rosen-bridge/GuardSign.es` (the `allOf(Coll(..))`
//! form, `ea02d196 8303…`). The `0xCF` emit arm is thereby no longer
//! frontend-reachable for these sources.

use ergo_ser::opcode::{Expr, IrNode, Payload};

// Opcode constants (ergo-ser/src/opcode/types.rs).
const SIGMA_PROP_IS_PROVEN: u8 = 0xCF;
const BOOL_TO_SIGMA_PROP: u8 = 0xD1;
const AND: u8 = 0x96; // logical `allOf(Coll[Boolean])`
const OR: u8 = 0x97; // logical `anyOf(Coll[Boolean])`
const CONCRETE_COLLECTION: u8 = 0x83;
const BIN_AND: u8 = 0xED; // lazy `&&`
const BIN_OR: u8 = 0xEC; // lazy `||`
const SIGMA_AND: u8 = 0xEA;
const SIGMA_OR: u8 = 0xEB;

/// Eliminate `SigmaPropIsProven`/`BoolToSigmaProp` round-trip coercions AND
/// reconstruct the `HasSigmas` `SigmaAnd`/`SigmaOr` shape, bottom-up. A single
/// post-order pass suffices: a node's children are fully reduced before its own
/// rule runs, and each rule's result is an already-reduced sub-expression, so no
/// fixpoint loop is needed.
///
/// Two rule families fire on each (child-reduced) node:
///
/// 1. **Coercion cancellation** (`GraphBuilding.scala:188-189`):
///    `SigmaPropIsProven(BoolToSigmaProp(x)) → x` and
///    `BoolToSigmaProp(SigmaPropIsProven(p)) → p`. The second rule is also what
///    strips the outer `sigmaProp(..)` a reconstruction produces (its result is
///    a `SigmaPropIsProven(<sigma>)` — Scala's `res.isValid` — so a parent
///    `sigmaProp(reconstructed)` cancels back to the bare sigma tree).
///
/// 2. **`HasSigmas` reconstruction** (`GraphBuilding.scala:167-203`): a logical
///    op (`BinAnd`/`BinOr` — the lazy `&&`/`||` — or `And`/`Or` over a
///    `Coll[Boolean]`) that mixes plain `Boolean` operands with `SigmaProp`
///    operands (each carried as a `SigmaPropIsProven(s)` coercion, Scala's
///    `SigmaM.isValid(s)`) is rebuilt into a `SigmaAnd`/`SigmaOr` over sigma
///    operands: every plain `Boolean` operand is coerced UP via
///    `BoolToSigmaProp`, every `SigmaPropIsProven(s)` operand contributes its
///    bare `s`, and the whole node is wrapped in `SigmaPropIsProven` (Scala's
///    `res.isValid`) so a parent `sigmaProp(..)` / the outer bool op cancels it.
///    Fires ONLY when a sigma operand is present (a pure-Boolean logical op is
///    left untouched). `BinXor` is NOT reconstructed: it is a strict op, not one
///    of Scala's lazy `ApplyBinOpLazy` cases, and SigmaProp has no XOR (the D-C3
///    `^` forms fold to a constant earlier).
pub(crate) fn eliminate_isproven(expr: Expr) -> Expr {
    // 1. Reduce children first (post-order).
    let expr = match expr {
        Expr::Op(IrNode { opcode, payload }) => Expr::Op(IrNode {
            opcode,
            payload: map_children(payload),
        }),
        other => other,
    };
    // 2. Apply the rules to THIS node (children already reduced).
    match expr {
        // ----- HasSigmas reconstruction (mixed Bool/Sigma logical ops) -----
        // `l && r` / `l || r` where an operand is a surviving sigma.
        Expr::Op(IrNode {
            opcode: BIN_AND,
            payload: Payload::Two(l, r),
        }) => reconstruct_binop(SIGMA_AND, *l, *r),
        Expr::Op(IrNode {
            opcode: BIN_OR,
            payload: Payload::Two(l, r),
        }) => reconstruct_binop(SIGMA_OR, *l, *r),
        // `allOf(Coll(..))` / `anyOf(Coll(..))` with a sigma among the items.
        Expr::Op(IrNode {
            opcode: AND,
            payload: Payload::One(coll),
        }) => reconstruct_collop(AND, SIGMA_AND, *coll),
        Expr::Op(IrNode {
            opcode: OR,
            payload: Payload::One(coll),
        }) => reconstruct_collop(OR, SIGMA_OR, *coll),

        // ----- coercion cancellation -----
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

/// Coerce a `Boolean`-typed expression UP to `SigmaProp` (Scala
/// `sigmaDslBuilder.sigmaProp(bool)` with the `sigmaProp(p.isValid) → p` fusion
/// folded in): a `SigmaPropIsProven(p)` operand unwraps to its bare sigma `p`;
/// anything else is wrapped in `BoolToSigmaProp`.
fn coerce_to_sigma(e: Expr) -> Expr {
    match e {
        Expr::Op(IrNode {
            opcode: SIGMA_PROP_IS_PROVEN,
            payload: Payload::One(p),
        }) => *p,
        other => Expr::Op(IrNode {
            opcode: BOOL_TO_SIGMA_PROP,
            payload: Payload::One(Box::new(other)),
        }),
    }
}

/// True iff `e` is a `SigmaPropIsProven(_)` coercion — i.e. a `SigmaProp`
/// operand in a `Boolean` logical context (Scala `SigmaM.isValid(_)`).
fn is_sigma_operand(e: &Expr) -> bool {
    matches!(
        e,
        Expr::Op(IrNode {
            opcode: SIGMA_PROP_IS_PROVEN,
            ..
        })
    )
}

/// `l op r` (`op` = lazy `&&`/`||`, `sigma_op` = its `SigmaAnd`/`SigmaOr` twin).
/// If neither operand is a sigma, the node is a pure-Boolean logical op — left
/// unchanged. Otherwise (`GraphBuilding.scala:167-185`): both operands are
/// coerced UP to `SigmaProp`, combined under `sigma_op`, and wrapped in
/// `SigmaPropIsProven` (Scala's `res.isValid`) so the enclosing `sigmaProp(..)`
/// (or outer logical op) cancels it.
fn reconstruct_binop(sigma_op: u8, l: Expr, r: Expr) -> Expr {
    let op = if sigma_op == SIGMA_AND {
        BIN_AND
    } else {
        BIN_OR
    };
    if !is_sigma_operand(&l) && !is_sigma_operand(&r) {
        return Expr::Op(IrNode {
            opcode: op,
            payload: Payload::Two(Box::new(l), Box::new(r)),
        });
    }
    let combined = Expr::Op(IrNode {
        opcode: sigma_op,
        payload: Payload::SigmaCollection {
            items: vec![coerce_to_sigma(l), coerce_to_sigma(r)],
        },
    });
    Expr::Op(IrNode {
        opcode: SIGMA_PROP_IS_PROVEN,
        payload: Payload::One(Box::new(combined)),
    })
}

/// `allOf(coll)` / `anyOf(coll)` (`bool_op` = `And`/`Or`, `sigma_op` =
/// `SigmaAnd`/`SigmaOr`). Implements the `AllOf`/`AnyOf` `HasSigmas` rules
/// (`GraphBuilding.scala:191-203`) over an emitted `And`/`Or` node whose sole
/// child is a `ConcreteCollection[Boolean]`. If no item is a sigma the node is
/// left unchanged; otherwise the items are split into Booleans `bs` and sigmas
/// `ss` (each `SigmaPropIsProven(s)` contributing its bare `s`):
///
/// - `zk` = the sigma side: a lone sigma stays bare (the single-element `allZK`/
///   `anyZK` unwrap, `:207-208`), else `sigma_op` over all of `ss`.
/// - `bs` empty → `SigmaPropIsProven(zk)` (Scala `zk.isValid`).
/// - else → `SigmaPropIsProven(sigma_op(Coll(sigmaProp(allOf/anyOf(bs)), zk)))`,
///   where `allOf(bs)` is a lone Boolean bare (single-element unwrap, `:205-206`)
///   else the rebuilt `bool_op` over `bs`.
fn reconstruct_collop(bool_op: u8, sigma_op: u8, coll: Expr) -> Expr {
    let (elem_type, items) = match coll {
        Expr::Op(IrNode {
            opcode: CONCRETE_COLLECTION,
            payload: Payload::ConcreteCollection { elem_type, items },
        }) => (elem_type, items),
        // Non-literal collection (e.g. a `ValUse`): cannot inspect items — the
        // op stays a plain Boolean `And`/`Or`.
        other => {
            return Expr::Op(IrNode {
                opcode: bool_op,
                payload: Payload::One(Box::new(other)),
            });
        }
    };

    let mut bs: Vec<Expr> = Vec::new();
    let mut ss: Vec<Expr> = Vec::new();
    for item in items {
        match item {
            Expr::Op(IrNode {
                opcode: SIGMA_PROP_IS_PROVEN,
                payload: Payload::One(s),
            }) => ss.push(*s),
            b => bs.push(b),
        }
    }

    if ss.is_empty() {
        // No sigma operand — reassemble the untouched Boolean op.
        return Expr::Op(IrNode {
            opcode: bool_op,
            payload: Payload::One(Box::new(Expr::Op(IrNode {
                opcode: CONCRETE_COLLECTION,
                payload: Payload::ConcreteCollection {
                    elem_type,
                    items: bs,
                },
            }))),
        });
    }

    // Sigma side: single-element `allZK`/`anyZK` unwrap.
    let zk = if ss.len() == 1 {
        ss.pop().expect("len == 1")
    } else {
        Expr::Op(IrNode {
            opcode: sigma_op,
            payload: Payload::SigmaCollection { items: ss },
        })
    };

    let combined = if bs.is_empty() {
        zk
    } else {
        // Boolean side: single-element `allOf`/`anyOf` unwrap, else the rebuilt
        // `bool_op(ConcreteCollection(bs))`, coerced UP to `SigmaProp`.
        let bool_agg = if bs.len() == 1 {
            bs.pop().expect("len == 1")
        } else {
            Expr::Op(IrNode {
                opcode: bool_op,
                payload: Payload::One(Box::new(Expr::Op(IrNode {
                    opcode: CONCRETE_COLLECTION,
                    payload: Payload::ConcreteCollection {
                        elem_type,
                        items: bs,
                    },
                }))),
            })
        };
        Expr::Op(IrNode {
            opcode: sigma_op,
            payload: Payload::SigmaCollection {
                items: vec![coerce_to_sigma(bool_agg), zk],
            },
        })
    };

    Expr::Op(IrNode {
        opcode: SIGMA_PROP_IS_PROVEN,
        payload: Payload::One(Box::new(combined)),
    })
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

    // ----- HasSigmas reconstruction -----

    fn concrete_coll(items: Vec<Expr>) -> Expr {
        Expr::Op(IrNode {
            opcode: CONCRETE_COLLECTION,
            payload: Payload::ConcreteCollection {
                elem_type: SigmaType::SBoolean,
                items,
            },
        })
    }

    fn sigma_coll(opcode: u8, items: Vec<Expr>) -> Expr {
        Expr::Op(IrNode {
            opcode,
            payload: Payload::SigmaCollection { items },
        })
    }

    #[test]
    fn reconstruct_mixed_binand_becomes_sigma_and_wrapped_in_isproven() {
        // `bool && sigma.isProven` (surviving sigma, not `sigmaProp(<bool>)`) →
        // `SigmaAnd(Coll(BoolToSigmaProp(bool), sigma)).isProven` — the Scala
        // `res.isValid` shape (`GraphBuilding.scala:178-185`). Oracle byte
        // target: `basis-tracker-basis.es` `ea02d1...cd7208` (SigmaAnd of the
        // bool AND and the `proveDlog`).
        let bool_op = op2(0x8F, height(), bool_const(true)); // some Boolean node
        let sigma = sigma_const(0xAA);
        let e = op2(
            BIN_AND,
            bool_op.clone(),
            op1(SIGMA_PROP_IS_PROVEN, sigma.clone()),
        );
        let want = op1(
            SIGMA_PROP_IS_PROVEN,
            sigma_coll(SIGMA_AND, vec![op1(BOOL_TO_SIGMA_PROP, bool_op), sigma]),
        );
        assert_eq!(eliminate_isproven(e), want);
    }

    #[test]
    fn reconstruct_wrapped_mixed_binand_cancels_outer_sigmaprop() {
        // The enclosing `sigmaProp(bool && sigma.isProven)` → bare `SigmaAnd`
        // (the reconstruction's `res.isValid` cancels against the outer
        // `BoolToSigmaProp`). This is the full basis/GuardSign root shape.
        let bool_op = op2(0x8F, height(), bool_const(true));
        let sigma = sigma_const(0xBB);
        let e = op1(
            BOOL_TO_SIGMA_PROP,
            op2(
                BIN_AND,
                bool_op.clone(),
                op1(SIGMA_PROP_IS_PROVEN, sigma.clone()),
            ),
        );
        let want = sigma_coll(SIGMA_AND, vec![op1(BOOL_TO_SIGMA_PROP, bool_op), sigma]);
        assert_eq!(eliminate_isproven(e), want);
    }

    #[test]
    fn reconstruct_mixed_binor_becomes_sigma_or() {
        let bool_op = op2(0x8F, height(), bool_const(true));
        let sigma = sigma_const(0xCC);
        let e = op2(
            BIN_OR,
            op1(SIGMA_PROP_IS_PROVEN, sigma.clone()),
            bool_op.clone(),
        );
        // Sigma on the LEFT: `sigma.isProven || bool` →
        // `SigmaOr(Coll(sigma, BoolToSigmaProp(bool))).isProven`.
        let want = op1(
            SIGMA_PROP_IS_PROVEN,
            sigma_coll(SIGMA_OR, vec![sigma, op1(BOOL_TO_SIGMA_PROP, bool_op)]),
        );
        assert_eq!(eliminate_isproven(e), want);
    }

    #[test]
    fn reconstruct_allof_hassigmas_splits_bools_from_sigma() {
        // `allOf(Coll(b1, b2, sigma.isProven))` → the GuardSign shape:
        // `SigmaAnd(Coll(BoolToSigmaProp(allOf(Coll(b1, b2))), sigma)).isProven`.
        // Oracle: `GuardSign.es` `ea02 d1 96 8303 ... <atLeast>`.
        let b1 = op2(0x8F, height(), bool_const(true));
        let b2 = op2(0x8F, height(), bool_const(false));
        let sigma = sigma_const(0xDD);
        let e = op1(
            AND,
            concrete_coll(vec![
                b1.clone(),
                b2.clone(),
                op1(SIGMA_PROP_IS_PROVEN, sigma.clone()),
            ]),
        );
        let want = op1(
            SIGMA_PROP_IS_PROVEN,
            sigma_coll(
                SIGMA_AND,
                vec![
                    op1(BOOL_TO_SIGMA_PROP, op1(AND, concrete_coll(vec![b1, b2]))),
                    sigma,
                ],
            ),
        );
        assert_eq!(eliminate_isproven(e), want);
    }

    #[test]
    fn reconstruct_allof_single_bool_unwraps_before_coercion() {
        // One Boolean + one sigma: `allOf(Coll(b, sigma.isProven))`. The
        // single-element `allOf` unwrap (`GraphBuilding.scala:205`) means the
        // bool side is bare `b`, coerced to `BoolToSigmaProp(b)` — no `And` node.
        let b = op2(0x8F, height(), bool_const(true));
        let sigma = sigma_const(0xEE);
        let e = op1(
            AND,
            concrete_coll(vec![b.clone(), op1(SIGMA_PROP_IS_PROVEN, sigma.clone())]),
        );
        let want = op1(
            SIGMA_PROP_IS_PROVEN,
            sigma_coll(SIGMA_AND, vec![op1(BOOL_TO_SIGMA_PROP, b), sigma]),
        );
        assert_eq!(eliminate_isproven(e), want);
    }

    #[test]
    fn reconstruct_allof_all_sigmas_collapses_to_bare_zk() {
        // No Boolean operand: `allOf(Coll(s1.isProven, s2.isProven))` →
        // `SigmaAnd(Coll(s1, s2)).isProven` (bs empty branch, `:193-194`).
        let s1 = sigma_const(0x11);
        let s2 = sigma_const(0x22);
        let e = op1(
            AND,
            concrete_coll(vec![
                op1(SIGMA_PROP_IS_PROVEN, s1.clone()),
                op1(SIGMA_PROP_IS_PROVEN, s2.clone()),
            ]),
        );
        let want = op1(SIGMA_PROP_IS_PROVEN, sigma_coll(SIGMA_AND, vec![s1, s2]));
        assert_eq!(eliminate_isproven(e), want);
    }

    // ----- error paths / non-firing -----

    #[test]
    fn reconstruct_pure_boolean_binand_left_untouched() {
        // No sigma operand — a pure-Boolean `&&` is NOT reconstructed.
        let e = op2(
            BIN_AND,
            op2(0x8F, height(), bool_const(true)),
            bool_const(false),
        );
        assert_eq!(eliminate_isproven(e.clone()), e);
    }

    #[test]
    fn reconstruct_pure_boolean_allof_left_untouched() {
        // No sigma among the items — `allOf` stays a Boolean `And`.
        let e = op1(
            AND,
            concrete_coll(vec![
                op2(0x8F, height(), bool_const(true)),
                op2(0x8F, height(), bool_const(false)),
            ]),
        );
        assert_eq!(eliminate_isproven(e.clone()), e);
    }

    #[test]
    fn eliminate_isproven_leaves_bare_isproven_alone() {
        // SigmaPropIsProven whose child is NOT a BoolToSigmaProp and which is
        // NOT inside a logical op (a surviving sigma, e.g. a bare SigmaProp
        // const) is left as-is — the reconstruction only fires on an enclosing
        // BinAnd/BinOr/And/Or; a lone coercion waits for its parent.
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
