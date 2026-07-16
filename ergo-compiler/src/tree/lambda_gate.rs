use ergo_ser::opcode::{Expr, IrNode};

use crate::emit::EmitError;

use super::*;

/// GraphBuilding verdict-parity gate over the emitted body — lambda and
/// application shapes the FULL Scala compiler rejects (lib.rs D-C5).
///
/// Oracle-pinned rules:
/// - **Zero-arg `FuncValue` rejects ANYWHERE** — even as the rhs of an
///   unused val (`cc { val unused = {() => 1}; sigmaProp(true) }` → `REJECT
///   1:17 GraphBuildingException`): the definition itself crashes Scala's
///   graph construction, before any dead-code elimination.
/// - **`FuncApply` with arg count != 1 rejects** (`f(1, 2)` → `REJECT 1:50`,
///   `f()`, aliased `g(1, 2)`, inline `{(x, y) => x + y}(1, 2)` — all
///   `GraphBuildingException`): Scala lowers only 1-arg applications. The
///   multi-arg lambda DEFINITION is fine (the IR tuples it), so an unused
///   val-bound multi-arg lambda (`{ val unused = {(x: Int, y: Int) => x +
///   y}; sigmaProp(true) }` → OK), an un-applied alias (`val g = f` with no
///   call → OK) and every HOF-callback use — direct `fold(0L, {(a, b) =>
///   ...})` AND val-bound `fold(0L, f)` (`cc { val f = {(a:
///   Long, b: Long) => a + b}; sigmaProp(Coll(1L, 2L).fold(0L, f) == 3L) }`
///   → OK, the D-C4 both-accept class, e.g. corpus
///   `crystalpool/swap-tokens.es`) — stay ACCEPTED: the gate keys on the
///   APPLICATION node, not on the `FuncValue`. Those accepted multi-arg
///   DEFINITIONS are lowered to the tupled 1-arg form downstream by
///   [`crate::tuple`] (D-C4), which is why they are evaluable and
///   byte-matchable — this gate itself is unchanged.
/// - **A lambda with a FUNCTION-typed parameter rejects** (`{(f: Int => Int)
///   => f(10)}` and the param-unused body variant → `REJECT 0:0
///   MatchError`) UNLESS the lambda sits in DEAD code that Scala's schedule
///   prunes before the lowering that dies. The exemption is
///   REACHABILITY-based and transitive: a
///   `FuncValue` with an `SFunc` param anywhere inside an unreachable `val`'s
///   rhs — direct rhs (`cc { val unused = {(f: Int => Int) => 1};
///   sigmaProp(true) }` → OK) OR nested (`cc { val unused = Coll({(f: Int =>
///   Int) => 1}); sigmaProp(true) }` → OK) — is exempt, matching the oracle.
///   A val used only by other dead vals is itself dead, so its nested
///   higher-order lambdas are exempt too. This uses the same
///   [`crate::inline::live_def_ids`] reachability that [`crate::inline::
///   prune_dead_vals`] prunes on, keeping the gate and the pruning transform
///   in lockstep. The zero-arg rule is deliberately NOT dead-exempted (see
///   above) — it is an eager construction failure, not a schedule-pruned
///   lowering.
pub(crate) fn graph_building_lambda_reject(root: &Expr) -> Option<EmitError> {
    // The set of `val` ids that survive dead-`val` pruning (reachable from
    // their block result). A higher-order (`SFunc`-param) lambda is exempt from
    // the `MatchError` reject exactly when it sits in DEAD code — Scala's
    // schedule prunes it before the lowering that would `MatchError`
    // (`{ val unused = Coll({(f: Int => Int) => 1});
    // sigmaProp(true) }` → oracle OK). The zero-arg-lambda and multi-arg-apply
    // rejects are EAGER `buildNode`-over-every-bind failures that fire in dead
    // code too (`{ val unused = Coll({() => 1}); ... }` → reject; `{ val f =
    // {(x, y) => ...}; val unused = f(1, 2); ... }` → reject), so they are NOT
    // dead-exempt.
    let live = crate::inline::live_def_ids(root);

    // Walk with a transitively-inherited `dead` flag: once inside a dead
    // `ValDef`'s rhs, every descendant is dead (so a NESTED `SFunc`-param lambda
    // — not just a direct rhs — is exempt too). A def is dead here iff
    // it is already in a dead region OR its id did not survive pruning.
    let mut stack: Vec<(&Expr, bool)> = vec![(root, false)];
    while let Some((e, dead)) = stack.pop() {
        let Expr::Op(IrNode { payload, .. }) = e else {
            continue;
        };
        match payload {
            Payload::FuncValue { args, body } => {
                if args.is_empty() {
                    return Some(EmitError::GraphBuildingReject {
                        class: "GraphBuildingException",
                        what: "zero-arg lambda: Scala's graph construction rejects a \
                               FuncValue definition with no arguments (even unused)"
                            .into(),
                    });
                }
                if !dead
                    && args
                        .iter()
                        .any(|(_, t)| matches!(t, Some(SigmaType::SFunc { .. })))
                {
                    return Some(EmitError::GraphBuildingReject {
                        class: "MatchError",
                        what: "lambda with a function-typed parameter: Scala's \
                               GraphBuilding cannot lower a higher-order user lambda"
                            .into(),
                    });
                }
                stack.push((body, dead));
            }
            Payload::FuncApply { func, args } => {
                if args.len() != 1 {
                    return Some(EmitError::GraphBuildingReject {
                        class: "GraphBuildingException",
                        what: format!(
                            "{}-arg lambda application: Scala's GraphBuilding lowers \
                             only 1-arg applications",
                            args.len(),
                        ),
                    });
                }
                stack.push((func.as_ref(), dead));
                stack.push((&args[0], dead));
            }
            Payload::ValDef { id, rhs, .. } | Payload::FunDef { id, rhs, .. } => {
                stack.push((rhs.as_ref(), dead || !live.contains(id)));
            }
            other => {
                let mut children = Vec::new();
                push_children(other, &mut children);
                stack.extend(children.into_iter().map(|c| (c, dead)));
            }
        }
    }
    None
}
