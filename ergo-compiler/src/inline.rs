//! Dead-`val` pruning + dead-code reachability over the emitted opcode IR
//! (`ergo_ser::opcode::Expr`), reproducing the OBSERVABLE effect of Scala's
//! `buildGraph`/`buildTree` schedule pruning
//! (`dev-docs/ergoscript-compiler-m4-recon/recon-transforms.md` §8).
//!
//! ## Scope (post-M5-Task-4)
//!
//! This module was originally the M4 `val`-inlining + id-renumbering surface.
//! Those responsibilities RETIRED into `crate::cse` (M5 Task 4, locked decision
//! 4): the scope-chain hash-cons is now the SOLE subexpression-sharing pass —
//! single-use `val`s inline for free (a use-count-1 symbol is not hoisted),
//! multi-use non-constant `val`s hoist to `ValDef`s in their first-build scope,
//! and dense ids are assigned assign-once with no renumber pass. What remains
//! here are the two pieces that are NOT sharing decisions:
//!
//! - **[`prune_dead_vals`]** — dead-code elimination. A `val` never referenced
//!   from its block result is unreachable from Scala's DFS `schedule`
//!   (`ProgramGraphs.scala:35-64`) → never emitted. Kept as a distinct pass
//!   because it must run at a SPECIFIC pipeline slot (see below), and CSE relies
//!   on it: a dead `val`'s rhs must not be interned, else its `ValUse` refs
//!   would inflate CSE's flat usage count and wrongly hoist a
//!   used-only-in-dead-code subexpression.
//! - **[`live_def_ids`]** — the reachability query
//!   `crate::tree::graph_building_lambda_reject` consumes (NF-2): which
//!   higher-order (`SFunc`-param) lambdas sit in dead code Scala's schedule
//!   prunes before the lowering that would `MatchError`. Sharing the exact same
//!   reachability the pruner uses keeps the reject gate and the prune transform
//!   in lockstep.
//!
//! ## Pipeline slot (pinned by oracle probes — see `crate::tree::compile`)
//!
//! [`prune_dead_vals`] runs AFTER `crate::fold::fold` and BEFORE CSE / the
//! v0-data gate. AFTER fold: an overflow in a DEAD `val`'s rhs must still reject
//! (Scala's eager `buildNode` runs over every bind before the schedule prunes),
//! so the fold traverses dead `val` rhs first — `{ val unused = 2147483647 + 1;
//! sigmaProp(true) }` → `REJECT ArithmeticException`. Reachability is recomputed
//! from scratch, so a `val` a fold turned dead (sole use erased by `x * 0 -> 0`)
//! is dropped too. BEFORE the v0-data gate: a dead `val` holding v3-only data
//! (`{ val unused = Coll[BigInt](); sigmaProp(true) }` → OK) must be gone before
//! the gate scans, matching the oracle's accept.

use ergo_ser::opcode::{Expr, IrNode, Payload};
use std::collections::{HashMap, HashSet};

const BLOCK_VALUE: u8 = 0xD8;

/// Remove `val`s that are unreachable from the block result and flatten a block
/// whose `ValDef` list empties out. Runs AFTER the fold passes (so a dead
/// `val`'s overflowing rhs has already rejected) and recomputes reachability
/// from scratch, so it also drops a `val` that a fold turned dead (e.g. the sole
/// use erased by `x * 0 -> 0`). Only ever DROPS unreachable defs — reachable
/// multi-use `val`s are untouched.
pub(crate) fn prune_dead_vals(expr: Expr) -> Expr {
    match expr {
        Expr::Op(IrNode {
            opcode: BLOCK_VALUE,
            payload: Payload::BlockValue { items, result },
        }) => {
            let items: Vec<Expr> = items.into_iter().map(prune_dead_vals).collect();
            let result = prune_dead_vals(*result);
            let live = block_reachable(&items, &result);
            let out: Vec<Expr> = items
                .into_iter()
                .filter(|item| match def_id(item) {
                    Some(id) => live.contains(&id),
                    None => true,
                })
                .collect();
            if out.is_empty() {
                result
            } else {
                Expr::Op(IrNode {
                    opcode: BLOCK_VALUE,
                    payload: Payload::BlockValue {
                        items: out,
                        result: Box::new(result),
                    },
                })
            }
        }
        Expr::Op(IrNode { opcode, payload }) => Expr::Op(IrNode {
            opcode,
            payload: map_children(payload, prune_dead_vals),
        }),
        other => other,
    }
}

/// The set of `ValDef`/`FunDef` ids that survive pruning, across the WHOLE tree
/// — a def id is "live" iff it is reachable from its own block's result. Used by
/// [`crate::tree::graph_building_lambda_reject`] to know which higher-order
/// (`SFunc`-param) lambdas sit in dead code that Scala's schedule prunes before
/// the lowering that would `MatchError` (recon-transforms.md §8; NF-2). The
/// reject walk combines this with a transitively-inherited dead flag, so a def
/// that is "live within its own block" but nested inside an outer DEAD def is
/// still treated as dead there.
pub(crate) fn live_def_ids(root: &Expr) -> HashSet<u32> {
    let mut live = HashSet::new();
    collect_live(root, &mut live);
    live
}

fn collect_live(expr: &Expr, out: &mut HashSet<u32>) {
    if let Expr::Op(IrNode {
        opcode: BLOCK_VALUE,
        payload: Payload::BlockValue { items, result },
    }) = expr
    {
        out.extend(block_reachable(items, result));
    }
    for_each_child(expr, &mut |c| collect_live(c, out));
}

/// Reachable-from-result set of a block's own def ids: a fixpoint following
/// `ValUse` edges from the result and through each reachable def's rhs,
/// restricted to ids DEFINED in this block (outer/inner-scope ids are decided by
/// their own blocks; ids are globally unique so there is no shadowing).
fn block_reachable(items: &[Expr], result: &Expr) -> HashSet<u32> {
    let defined: HashSet<u32> = items.iter().filter_map(def_id).collect();
    let rhs_of: HashMap<u32, &Expr> = items
        .iter()
        .filter_map(|it| Some((def_id(it)?, def_rhs(it)?)))
        .collect();

    let mut live: HashSet<u32> = HashSet::new();
    let mut work: Vec<u32> = valuse_ids(result, &defined).into_iter().collect();
    while let Some(id) = work.pop() {
        if live.insert(id) {
            if let Some(rhs) = rhs_of.get(&id) {
                work.extend(valuse_ids(rhs, &defined));
            }
        }
    }
    live
}

/// The distinct `ValUse` ids (restricted to `defined`) occurring in `expr`.
fn valuse_ids(expr: &Expr, defined: &HashSet<u32>) -> HashSet<u32> {
    let mut count = HashMap::new();
    count_valuses(expr, defined, &mut count);
    count.into_keys().collect()
}

/// Count `ValUse` occurrences (restricted to `defined` ids) into `count`.
fn count_valuses(expr: &Expr, defined: &HashSet<u32>, count: &mut HashMap<u32, usize>) {
    if let Expr::Op(IrNode {
        payload: Payload::ValUse { id },
        ..
    }) = expr
    {
        if defined.contains(id) {
            *count.entry(*id).or_insert(0) += 1;
        }
    }
    for_each_child(expr, &mut |c| count_valuses(c, defined, count));
}

/// `ValDef`/`FunDef` id of a block item, if it is one.
fn def_id(item: &Expr) -> Option<u32> {
    match item {
        Expr::Op(IrNode {
            payload: Payload::ValDef { id, .. } | Payload::FunDef { id, .. },
            ..
        }) => Some(*id),
        _ => None,
    }
}

fn def_rhs(item: &Expr) -> Option<&Expr> {
    match item {
        Expr::Op(IrNode {
            payload: Payload::ValDef { rhs, .. } | Payload::FunDef { rhs, .. },
            ..
        }) => Some(rhs),
        _ => None,
    }
}

/// Visit each direct child `Expr` of `expr` (immutable) — the read-only twin of
/// [`map_children`]. A new child-carrying `Payload` variant fails to compile in
/// [`map_children`] (below), which keeps this walker's coverage honest via that
/// exhaustive match.
fn for_each_child(expr: &Expr, f: &mut dyn FnMut(&Expr)) {
    let Expr::Op(IrNode { payload, .. }) = expr else {
        return;
    };
    match payload {
        Payload::Zero
        | Payload::ValUse { .. }
        | Payload::ConstPlaceholder { .. }
        | Payload::TaggedVar { .. }
        | Payload::BoolCollection { .. }
        | Payload::GetVar { .. }
        | Payload::DeserializeContext { .. }
        | Payload::NoneValue { .. } => {}
        Payload::One(a) | Payload::NumericCast { input: a, .. } => f(a),
        Payload::Two(a, b) => {
            f(a);
            f(b);
        }
        Payload::Three(a, b, c) => {
            f(a);
            f(b);
            f(c);
        }
        Payload::Four(a, b, c, d) => {
            f(a);
            f(b);
            f(c);
            f(d);
        }
        Payload::Five(a, b, c, d, e) => {
            f(a);
            f(b);
            f(c);
            f(d);
            f(e);
        }
        Payload::ValDef { rhs, .. } | Payload::FunDef { rhs, .. } => f(rhs),
        Payload::BlockValue { items, result } => {
            items.iter().for_each(&mut *f);
            f(result);
        }
        Payload::FuncValue { body, .. } => f(body),
        Payload::MethodCall { obj, args, .. } => {
            f(obj);
            args.iter().for_each(&mut *f);
        }
        Payload::ConcreteCollection { items, .. }
        | Payload::Tuple { items }
        | Payload::SigmaCollection { items } => items.iter().for_each(&mut *f),
        Payload::SelectField { input, .. } | Payload::ExtractRegisterAs { input, .. } => f(input),
        Payload::DeserializeRegister { default, .. } => {
            if let Some(d) = default {
                f(d);
            }
        }
        Payload::ByIndex {
            input,
            index,
            default,
        } => {
            f(input);
            f(index);
            if let Some(d) = default {
                f(d);
            }
        }
        Payload::FuncApply { func, args } => {
            f(func);
            args.iter().for_each(&mut *f);
        }
    }
}

/// By-value child map applying `g` to each child `Expr` — the inline-pass twin
/// of `crate::lower::map_children`. A new child-carrying `Payload` variant fails
/// to compile here until it is mapped.
fn map_children(payload: Payload, g: impl Fn(Expr) -> Expr + Copy) -> Payload {
    let f = |b: Box<Expr>| Box::new(g(*b));
    let fv = |items: Vec<Expr>| -> Vec<Expr> { items.into_iter().map(g).collect() };
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
        Payload::Five(a, b, c, d, e) => Payload::Five(f(a), f(b), f(c), f(d), f(e)),
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
    use ergo_ser::sigma_type::SigmaType;
    use ergo_ser::sigma_value::SigmaValue;

    // ----- helpers -----

    fn int_const(v: i64) -> Expr {
        Expr::Const {
            tpe: SigmaType::SInt,
            val: SigmaValue::Int(v as i32),
        }
    }

    fn height() -> Expr {
        Expr::Op(IrNode {
            opcode: 0xA3,
            payload: Payload::Zero,
        })
    }

    fn valuse(id: u32) -> Expr {
        Expr::Op(IrNode {
            opcode: 0x72,
            payload: Payload::ValUse { id },
        })
    }

    fn valdef(id: u32, rhs: Expr) -> Expr {
        Expr::Op(IrNode {
            opcode: 0xD6, // ValDef
            payload: Payload::ValDef {
                id,
                tpe: None,
                rhs: Box::new(rhs),
            },
        })
    }

    fn block(items: Vec<Expr>, result: Expr) -> Expr {
        Expr::Op(IrNode {
            opcode: BLOCK_VALUE,
            payload: Payload::BlockValue {
                items,
                result: Box::new(result),
            },
        })
    }

    fn gt(a: Expr, b: Expr) -> Expr {
        Expr::Op(IrNode {
            opcode: 0x91,
            payload: Payload::Two(Box::new(a), Box::new(b)),
        })
    }

    // ----- happy path (dead-`val` pruning; inlining/id-density is now CSE) -----

    #[test]
    fn zero_use_val_is_pruned() {
        // `{ val unused = HEIGHT; sigmaProp(true) }`-shape: dead val dropped and
        // the emptied block flattens to its bare result.
        let e = block(vec![valdef(1, height())], int_const(0));
        assert_eq!(prune_dead_vals(e), int_const(0));
    }

    #[test]
    fn val_used_only_by_dead_val_both_prune() {
        // `{ val a = HEIGHT; val dead = a; sigmaProp(true) }`: `dead` is
        // unreachable from the result and `a` is used only by `dead` → both gone.
        let e = block(
            vec![valdef(1, height()), valdef(2, valuse(1))],
            int_const(0),
        );
        assert_eq!(prune_dead_vals(e), int_const(0));
    }

    #[test]
    fn live_single_use_val_is_kept_not_inlined() {
        // `prune_dead_vals` is DCE only — it never inlines. A live single-use
        // `val` keeps its `ValDef`; the actual inlining is CSE's job now
        // (use-count-1 → not hoisted → inlined at materialization).
        let e = block(vec![valdef(1, height())], gt(valuse(1), int_const(5)));
        assert_eq!(prune_dead_vals(e.clone()), e);
    }

    #[test]
    fn live_multi_use_val_is_kept() {
        // A live multi-use non-constant `val` KEEPS its `ValDef` (the CSE
        // sharing surface). Id is untouched.
        let e = block(
            vec![valdef(7, height())],
            gt(valuse(7), gt(valuse(7), int_const(1))),
        );
        assert_eq!(prune_dead_vals(e.clone()), e);
    }

    #[test]
    fn prune_recurses_into_nested_block() {
        // A dead `val` inside a nested block is pruned; the live outer `val` and
        // the surviving structure are kept verbatim.
        let inner = block(
            vec![valdef(3, height())], // dead: result does not use id 3
            gt(valuse(1), int_const(5)),
        );
        let e = block(vec![valdef(1, height())], inner);
        let expected = block(vec![valdef(1, height())], gt(valuse(1), int_const(5)));
        assert_eq!(prune_dead_vals(e), expected);
    }

    // ----- round-trips -----

    #[test]
    fn no_block_no_change() {
        let e = gt(height(), int_const(5));
        assert_eq!(prune_dead_vals(e.clone()), e);
    }

    // ----- live_def_ids -----

    #[test]
    fn live_def_ids_excludes_dead_and_dead_only_referenced() {
        // id 3 live (used in result); id 1 dead; id 2 used only by dead id 1.
        let e = block(
            vec![
                valdef(1, valuse(2)), // dead (nothing uses id 1)
                valdef(2, height()),  // used only by dead id 1
                valdef(3, height()),  // live
            ],
            valuse(3),
        );
        let live = live_def_ids(&e);
        assert!(live.contains(&3));
        assert!(!live.contains(&1));
        assert!(!live.contains(&2));
    }
}
