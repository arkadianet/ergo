use ergo_primitives::cost::{CostAccumulator, CostError, JitCost};
use ergo_ser::ergo_tree::ErgoTree;
use ergo_ser::opcode::{Expr, IrNode, Payload};
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::{SigmaBoolean, SigmaValue};
use thiserror::Error;

/// Cost of evaluating a SigmaProp constant (trivial reduction path).
/// Source: sigmastate-interpreter Interpreter.scala:533
const EVAL_SIGMA_PROP_CONSTANT: JitCost = JitCost::from_jit(50);

/// Scala `Interpreter.CostPerTreeByte` (`Interpreter.scala:88`) — the
/// per-ergo-tree-byte cost of the deserialize-substitution pass.
const COST_PER_TREE_BYTE: u64 = 2;

/// Scala `VersionContext.V6SoftForkVersion` (`VersionContext.scala:56`): the
/// activated-script version at/after which `isV6Activated` is true. Our
/// `ReductionContext::activated_script_version` is the same quantity
/// (`Block.headerVersion - 1`), so the deserialize-substitution cost is
/// charged when `activated_script_version >= V6_SOFT_FORK_VERSION`.
const V6_SOFT_FORK_VERSION: u8 = 3;

/// Length of the canonical serialized ErgoTree — Scala's
/// `ergoTree.bytes.length`, used for the deserialize-substitution cost. We
/// re-serialize the parsed tree (byte-identical for every wire-conformant
/// tree, which the wire-tier corpus pins); only invoked on the rare
/// `hasDeserialize` path so the re-serialization is not on the hot path.
fn serialized_ergo_tree_len(tree: &ErgoTree) -> Result<usize, VerifySpendingError> {
    let mut w = ergo_primitives::writer::VlqWriter::new();
    ergo_ser::ergo_tree::write_ergo_tree(&mut w, tree).map_err(|_| {
        VerifySpendingError::Eval(super::evaluator::EvalError::RuntimeException(
            "ergo tree re-serialization failed while costing deserialize substitution",
        ))
    })?;
    Ok(w.result().len())
}

/// Failures raised by the trivial-reduction fast path.
///
/// Mirrors Scala's `Interpreter.fullReduction` (`Interpreter.scala:203-228`)
/// which only takes the fast path on the exact pattern
/// `SigmaPropConstant(p)` and falls through to
/// `CErgoTreeEvaluator.evalToCrypto` for everything else, including
/// scripts whose body is a top-level `SBoolean` constant (legal under
/// 6.0 / v3 ErgoTrees — the evaluator owns the implicit
/// `Bool → SigmaProp` coercion and its cost accounting).
///
/// Two of these variants are caller-must-fall-through (the trivial
/// path didn't match Scala's `SigmaPropConstant(p)` pattern); two
/// are hard rejects (the tree is structurally malformed).
#[derive(Debug, Error)]
pub enum ReductionError {
    /// Body is not a single constant — caller must fall back to the
    /// full evaluator. Caller MUST fall through.
    #[error("ErgoTree does not trivially reduce to a sigma proposition")]
    NotTriviallyReducible,
    /// Body IS a single constant, but not of type `SSigmaProp`
    /// (e.g. a top-level `SBoolean` root, common in v3 ErgoTrees
    /// under 6.0 semantics). The full evaluator handles the implicit
    /// `Bool → SigmaProp` coercion and charges the correct cost.
    /// Caller MUST fall through.
    #[error("body constant type is {0:?}, not SSigmaProp — full evaluator needed")]
    BodyConstantNotSigmaProp(SigmaType),
    /// A `ConstPlaceholder` referenced an index past the constants
    /// table. Hard reject — the tree is malformed.
    #[error("constant index {0} out of bounds")]
    ConstantIndexOutOfBounds(u32),
    /// Constant was tagged `SSigmaProp` but the value isn't a
    /// `SigmaProp(_)` — a deserializer / structural bug. Hard reject;
    /// the full evaluator wouldn't be able to recover this either.
    #[error("malformed constant: tagged SSigmaProp but value is not SigmaProp")]
    MalformedSigmaPropConstant,
}

/// Attempt trivial reduction of an ErgoTree to a SigmaBoolean.
///
/// Handles:
/// - Non-segregated P2PK: body is `Const { tpe: SSigmaProp, val: SigmaProp(...) }`
/// - Segregated P2PK: body is `Op(ConstPlaceholder { index: 0 })` referencing a SigmaProp constant
///
/// Returns `Err(NotTriviallyReducible)` for complex scripts.
pub fn trivial_reduce(tree: &ErgoTree) -> Result<SigmaBoolean, ReductionError> {
    match &tree.body {
        // Inline constant (non-segregated)
        Expr::Const { tpe, val } => sigma_value_to_sigma_boolean(tpe, val),

        // Opcode node — check for ConstPlaceholder
        Expr::Op(IrNode {
            opcode: 0x73,
            payload: Payload::ConstPlaceholder { index },
        }) => {
            if !tree.constant_segregation {
                return Err(ReductionError::NotTriviallyReducible);
            }
            let idx = *index as usize;
            if idx >= tree.constants.len() {
                return Err(ReductionError::ConstantIndexOutOfBounds(*index));
            }
            let (tpe, val) = &tree.constants[idx];
            sigma_value_to_sigma_boolean(tpe, val)
        }

        _ => Err(ReductionError::NotTriviallyReducible),
    }
}

fn sigma_value_to_sigma_boolean(
    tpe: &SigmaType,
    val: &SigmaValue,
) -> Result<SigmaBoolean, ReductionError> {
    match (tpe, val) {
        (SigmaType::SSigmaProp, SigmaValue::SigmaProp(sb)) => Ok(sb.clone()),
        // tpe says SSigmaProp but val isn't — structural malformed.
        // Hard reject; the full evaluator can't recover this either.
        (SigmaType::SSigmaProp, _) => Err(ReductionError::MalformedSigmaPropConstant),
        // tpe is anything else (e.g. SBoolean root in a v3 tree).
        // Scala's fast path only matches SigmaPropConstant(p); every
        // other constant type is the evaluator's job, including the
        // implicit Bool → SigmaProp coercion under 6.0. Caller must
        // fall through.
        (other, _) => Err(ReductionError::BodyConstantNotSigmaProp(other.clone())),
    }
}

/// Verify a spending proof for a transaction input (trivial reduction only).
pub fn verify_spending_proof(
    ergo_tree: &ErgoTree,
    proof_bytes: &[u8],
    bytes_to_sign: &[u8],
) -> Result<bool, VerifySpendingError> {
    let proposition = trivial_reduce(ergo_tree).map_err(VerifySpendingError::Reduction)?;
    super::verify::verify_sigma_proof(&proposition, proof_bytes, bytes_to_sign)
        .map_err(VerifySpendingError::Verification)
}

/// Verify a spending proof using the expression evaluator with context.
/// Falls back from trivial reduction to expression evaluation for supported scripts.
///
/// Uses a recording-only cost accumulator (no limit enforcement).
pub fn verify_spending_proof_with_context(
    ergo_tree: &ErgoTree,
    proof_bytes: &[u8],
    bytes_to_sign: &[u8],
    ctx: &super::evaluator::ReductionContext<'_>,
) -> Result<bool, VerifySpendingError> {
    let mut cost = CostAccumulator::recording_only();
    verify_spending_proof_with_context_and_cost(
        ergo_tree,
        proof_bytes,
        bytes_to_sign,
        ctx,
        &mut cost,
    )
}

/// Verify a spending proof using the expression evaluator with context,
/// accumulating cost into the provided accumulator.
pub fn verify_spending_proof_with_context_and_cost(
    ergo_tree: &ErgoTree,
    proof_bytes: &[u8],
    bytes_to_sign: &[u8],
    ctx: &super::evaluator::ReductionContext<'_>,
    cost: &mut CostAccumulator,
) -> Result<bool, VerifySpendingError> {
    // Whole-tree, pre-reduction parity checks Scala performs at context build /
    // deserialize (ContextExtension key domain via `toSigmaContext`; every
    // GroupElement constant on-curve via `GroupElementSerializer.parse`). These
    // fire BEFORE the trivial-reduction fast path below — which never enters the
    // evaluator's `eval_expr` (where the same checks also live) — so a bare P2PK
    // spend with a high-bit extension key or an off-curve GE constant is rejected
    // exactly as the reference node does, not silently accepted. Run before any
    // cost is charged, mirroring the throw happening ahead of reduction.
    super::evaluator::pre_reduction_checks(ctx, &ergo_tree.constants)
        .map_err(VerifySpendingError::Eval)?;

    // Deserialize-substitution cost (Scala `Interpreter.reductionWithDeserialize`,
    // Interpreter.scala:240-260): a tree that CONTAINS a DeserializeContext /
    // DeserializeRegister node adds `ergoTree.bytes.length * CostPerTreeByte(2)`
    // to `initCost`. It is UNCONDITIONAL on `hasDeserialize` — charged even
    // when the deserialize node is on a dead branch or its context var is
    // absent (so it is NOT the per-substitution `deserializeMeasured` cost,
    // which only fires when a node is actually substituted). Gated on V6
    // activation (`isV6Activated == activatedVersion >= V6SoftForkVersion(3)`):
    // pre-V6 the charge was not added (Interpreter.scala:250-259). Block-cost
    // domain (added to initCost, not JIT-scaled), so charged via
    // `from_block_cost`. Added before the eval baseline to mirror Scala adding
    // it to `initCost` ahead of reduction.
    if ctx.activated_script_version >= V6_SOFT_FORK_VERSION
        && super::evaluator::expr_has_deserialize(&ergo_tree.body)
    {
        let tree_len = serialized_ergo_tree_len(ergo_tree)?;
        let subst_block_cost = (tree_len as u64).saturating_mul(COST_PER_TREE_BYTE);
        let subst = JitCost::from_block_cost(subst_block_cost)
            .map_err(|e| VerifySpendingError::Eval(CostError::from(e).into()))?;
        cost.add(subst)
            .map_err(|e| VerifySpendingError::Eval(e.into()))?;
    }

    // Record baseline so we can snap eval cost to block boundary later.
    // Scala's verify() truncates eval_jit via toBlockCost before adding
    // crypto cost (which is also independently truncated to block cost).
    let pre_eval = cost.total();

    // Try trivial reduction first. Mirrors Scala
    // `Interpreter.fullReduction:210-225`: the fast path only handles
    // the `SigmaPropConstant(p)` pattern; every other body shape
    // (including v3 / 6.0 top-level `SBoolean` roots) goes through
    // the full evaluator, which owns the implicit `Bool → SigmaProp`
    // coercion and its cost accounting.
    let proposition = match trivial_reduce(ergo_tree) {
        Ok(prop) => {
            // Scala charges Eval_SigmaPropConstant(50) for trivially-reducible scripts
            // (Interpreter.scala:211). Without this, P2PK inputs are underpriced.
            cost.add(EVAL_SIGMA_PROP_CONSTANT)
                .map_err(|e| VerifySpendingError::Eval(e.into()))?;
            prop
        }
        Err(ReductionError::NotTriviallyReducible)
        | Err(ReductionError::BodyConstantNotSigmaProp(_)) => {
            // Fall through to evaluator — cost owned by evaluator path.
            super::evaluator::reduce_expr_with_cost(
                &ergo_tree.body,
                ctx,
                &ergo_tree.constants,
                cost,
            )
            .map_err(VerifySpendingError::Eval)?
        }
        Err(e) => return Err(VerifySpendingError::Reduction(e)),
    };

    // Match Scala's per-input toBlockCost truncation: drop the JitCost
    // remainder from evaluation before adding crypto cost.
    #[cfg(feature = "cost-trace")]
    let before_snap = cost.total().value();
    cost.snap_to_block_boundary(pre_eval);
    #[cfg(feature = "cost-trace")]
    super::cost_trace::record_snap(before_snap, cost.total().value());

    // AOT: charge crypto verification cost based on the reduced sigma proposition.
    let crypto_cost = super::crypto_cost::estimate_crypto_cost(&proposition);
    #[cfg(feature = "cost-trace")]
    super::cost_trace::record(
        format!("Crypto:{}", crypto_cost.value()),
        crypto_cost.value(),
        cost.total().value() + crypto_cost.value(),
    );
    cost.add(crypto_cost)
        .map_err(|e| VerifySpendingError::Eval(e.into()))?;

    super::verify::verify_sigma_proof(&proposition, proof_bytes, bytes_to_sign)
        .map_err(VerifySpendingError::Verification)
}

/// Errors produced by the spending-proof entry points. Variants
/// distinguish the failure phase so callers can map each to the
/// appropriate consensus / mempool error envelope.
#[derive(Debug, Error)]
pub enum VerifySpendingError {
    /// Trivial reduction surfaced an unrecoverable error (typed
    /// constant mismatch, out-of-bounds placeholder index).
    #[error("reduction error: {0}")]
    Reduction(ReductionError),
    /// The fallback evaluator raised — opcode not implemented, type
    /// mismatch at runtime, cost limit exceeded, etc.
    #[error("evaluation error: {0}")]
    Eval(super::evaluator::EvalError),
    /// Reduced cleanly but the actual sigma-proof verification failed.
    #[error("verification error: {0}")]
    Verification(super::verify::SigmaVerifyError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_ser::ergo_tree::ErgoTree;
    use ergo_ser::opcode::{Expr, IrNode, Payload};

    // ----- helpers -----

    fn p2pk_constant() -> SigmaValue {
        SigmaValue::SigmaProp(SigmaBoolean::TrivialProp(true))
    }

    fn inline_const_tree(tpe: SigmaType, val: SigmaValue) -> ErgoTree {
        ErgoTree {
            version: 0,
            has_size: false,
            constant_segregation: false,
            constants: Vec::new(),
            body: Expr::Const { tpe, val },
        }
    }

    fn segregated_const_tree(index: u32, constants: Vec<(SigmaType, SigmaValue)>) -> ErgoTree {
        ErgoTree {
            version: 0,
            has_size: false,
            constant_segregation: true,
            constants,
            body: Expr::Op(IrNode {
                opcode: 0x73,
                payload: Payload::ConstPlaceholder { index },
            }),
        }
    }

    // ----- happy path: SigmaProp constant (Scala SigmaPropConstant(p)) -----

    #[test]
    fn trivial_reduce_inline_sigmaprop_constant_ok() {
        let t = inline_const_tree(SigmaType::SSigmaProp, p2pk_constant());
        let sb = trivial_reduce(&t).expect("inline SigmaProp constant is the canonical fast path");
        assert!(matches!(sb, SigmaBoolean::TrivialProp(true)));
    }

    #[test]
    fn trivial_reduce_segregated_sigmaprop_constant_ok() {
        let t = segregated_const_tree(0, vec![(SigmaType::SSigmaProp, p2pk_constant())]);
        let sb =
            trivial_reduce(&t).expect("segregated SigmaProp constant is the canonical fast path");
        assert!(matches!(sb, SigmaBoolean::TrivialProp(true)));
    }

    // ----- fall-through cases (caller must invoke full evaluator) -----

    #[test]
    fn trivial_reduce_inline_sboolean_root_falls_through() {
        // v3 / 6.0 ErgoTrees can have a top-level SBoolean root; Scala's
        // Interpreter.fullReduction routes these to evalToCrypto, which
        // applies the implicit Bool → SigmaProp coercion. Our trivial
        // path must SIGNAL fall-through, not hard-reject.
        let t = inline_const_tree(SigmaType::SBoolean, SigmaValue::Boolean(true));
        let err = trivial_reduce(&t).expect_err("SBoolean root is not the fast path");
        assert!(
            matches!(
                err,
                ReductionError::BodyConstantNotSigmaProp(SigmaType::SBoolean)
            ),
            "expected BodyConstantNotSigmaProp(SBoolean), got {err:?}",
        );
    }

    #[test]
    fn trivial_reduce_segregated_sboolean_constant_falls_through() {
        // The actual shape that surfaced on testnet h=28474: a v3 tree
        // whose body is `ConstPlaceholder(0)` pointing to a Boolean
        // constant. Must classify as fall-through, not hard-reject.
        let t = segregated_const_tree(0, vec![(SigmaType::SBoolean, SigmaValue::Boolean(false))]);
        let err = trivial_reduce(&t).expect_err("SBoolean constant is not the fast path");
        assert!(
            matches!(
                err,
                ReductionError::BodyConstantNotSigmaProp(SigmaType::SBoolean)
            ),
            "expected BodyConstantNotSigmaProp(SBoolean), got {err:?}",
        );
    }

    #[test]
    fn trivial_reduce_complex_body_falls_through() {
        // Anything that isn't an inline Const or a single ConstPlaceholder
        // is just "not trivially reducible" — the original fast-path miss.
        let t = ErgoTree {
            version: 0,
            has_size: false,
            constant_segregation: false,
            constants: Vec::new(),
            body: Expr::Op(IrNode {
                opcode: 0xFF, // arbitrary non-placeholder opcode
                payload: Payload::Zero,
            }),
        };
        let err = trivial_reduce(&t).expect_err("complex body is not the fast path");
        assert!(matches!(err, ReductionError::NotTriviallyReducible));
    }

    // ----- hard-reject cases (malformed tree, evaluator can't recover) -----

    #[test]
    fn trivial_reduce_placeholder_out_of_bounds_hard_rejects() {
        let t = segregated_const_tree(5, vec![(SigmaType::SSigmaProp, p2pk_constant())]);
        let err = trivial_reduce(&t).expect_err("OOB placeholder is structural corruption");
        assert!(matches!(err, ReductionError::ConstantIndexOutOfBounds(5)));
    }

    #[test]
    fn trivial_reduce_malformed_sigmaprop_constant_hard_rejects() {
        // tpe tagged SSigmaProp but val isn't a SigmaProp — deserializer
        // bug or tampering. The full evaluator can't recover this either
        // (the type/value pair is internally inconsistent), so we hard
        // reject in the fast path with a distinct error class.
        let t = segregated_const_tree(0, vec![(SigmaType::SSigmaProp, SigmaValue::Boolean(true))]);
        let err = trivial_reduce(&t).expect_err("malformed SigmaProp constant must hard reject");
        assert!(
            matches!(err, ReductionError::MalformedSigmaPropConstant),
            "expected MalformedSigmaPropConstant, got {err:?}",
        );
    }

    // ----- caller-side classification (the actual bug fix) -----

    #[test]
    fn caller_falls_through_on_body_constant_not_sigmaprop() {
        // The fix: BodyConstantNotSigmaProp must be classified the same
        // as NotTriviallyReducible at the call site. This test checks
        // the discriminant matches, leaving the full-evaluator path
        // exercised by validation-level integration tests.
        let fall_through = |e: &ReductionError| {
            matches!(
                e,
                ReductionError::NotTriviallyReducible | ReductionError::BodyConstantNotSigmaProp(_)
            )
        };
        let hard_reject = |e: &ReductionError| {
            matches!(
                e,
                ReductionError::ConstantIndexOutOfBounds(_)
                    | ReductionError::MalformedSigmaPropConstant
            )
        };
        assert!(fall_through(&ReductionError::NotTriviallyReducible));
        assert!(fall_through(&ReductionError::BodyConstantNotSigmaProp(
            SigmaType::SBoolean
        )));
        assert!(hard_reject(&ReductionError::ConstantIndexOutOfBounds(7)));
        assert!(hard_reject(&ReductionError::MalformedSigmaPropConstant));
    }

    // ----- deserialize-substitution cost (Scala reductionWithDeserialize) -----

    /// `if(ph0:Bool, ph1:Bool, deserialize[Bool](id 0))` over two segregated
    /// `Boolean(true)` constants: body type SBoolean reduces to `Bool(true)`
    /// (the `else` deserialize branch is dead, never evaluated), which the
    /// evaluator coerces to `TrivialProp(true)`. `hasDeserialize` is true
    /// (the 0xD4 node is present syntactically), so the V6 substitution cost
    /// applies even though the node never runs — exactly the block-111927
    /// dead-branch shape.
    fn deser_dead_branch_tree() -> ErgoTree {
        let body = Expr::Op(IrNode {
            opcode: 0x95, // If
            payload: Payload::Three(
                Box::new(Expr::Op(IrNode {
                    opcode: 0x73,
                    payload: Payload::ConstPlaceholder { index: 0 },
                })),
                Box::new(Expr::Op(IrNode {
                    opcode: 0x73,
                    payload: Payload::ConstPlaceholder { index: 1 },
                })),
                Box::new(Expr::Op(IrNode {
                    opcode: 0xD4, // DeserializeContext
                    payload: Payload::DeserializeContext {
                        id: 0,
                        tpe: SigmaType::SBoolean,
                    },
                })),
            ),
        });
        ErgoTree {
            version: 0,
            has_size: false,
            constant_segregation: true,
            constants: vec![
                (SigmaType::SBoolean, SigmaValue::Boolean(true)),
                (SigmaType::SBoolean, SigmaValue::Boolean(true)),
            ],
            body,
        }
    }

    fn verify_block_cost(tree: &ErgoTree, activated: u8) -> u64 {
        let mut ctx = crate::evaluator::ReductionContext::minimal(500_000, 0);
        ctx.activated_script_version = activated;
        ctx.ergo_tree_version = tree.version; // 0; keep <= activated
        let mut cost = CostAccumulator::recording_only();
        let ok = verify_spending_proof_with_context_and_cost(tree, &[], &[], &ctx, &mut cost)
            .expect("dead-branch deserialize tree reduces to TrueProp and verifies");
        assert!(ok, "TrivialProp(true) must verify with an empty proof");
        cost.total_block_cost()
    }

    #[test]
    fn deserialize_substitution_cost_charged_only_at_v6() {
        // Scala reductionWithDeserialize adds treeBytes * CostPerTreeByte to
        // initCost, gated on isV6Activated (activatedVersion >= 3). The ONLY
        // difference between activated 2 and 3 for this tree is that charge,
        // so the block-cost delta must equal treeBytes * 2 (non-circular).
        let tree = deser_dead_branch_tree();
        let len = serialized_ergo_tree_len(&tree).expect("re-serialize") as u64;
        assert!(len > 0);
        let cost_v6 = verify_block_cost(&tree, 3);
        let cost_pre = verify_block_cost(&tree, 2);
        assert_eq!(
            cost_v6,
            cost_pre + len * COST_PER_TREE_BYTE,
            "V6 must add deserializeSubstitutionCost = treeBytes({len}) * {COST_PER_TREE_BYTE} block units",
        );
    }
}

#[cfg(test)]
mod pre_reduction_check_tests {
    use super::*;

    fn p2pk_trivial() -> SigmaValue {
        SigmaValue::SigmaProp(SigmaBoolean::TrivialProp(true))
    }

    fn inline_sigmaprop_tree() -> ErgoTree {
        ErgoTree {
            version: 0,
            has_size: false,
            constant_segregation: false,
            constants: Vec::new(),
            body: Expr::Const {
                tpe: SigmaType::SSigmaProp,
                val: p2pk_trivial(),
            },
        }
    }

    /// A trivially-reducible (P2PK-shaped) tree still verifies cleanly under a
    /// well-formed context — the new pre-reduction checks must not break the
    /// fast path.
    #[test]
    fn trivial_p2pk_clean_ctx_verifies() {
        let tree = inline_sigmaprop_tree();
        let ctx = crate::evaluator::ReductionContext::minimal(500_000, 0);
        let mut cost = CostAccumulator::recording_only();
        let ok = verify_spending_proof_with_context_and_cost(&tree, &[], b"msg", &ctx, &mut cost)
            .expect("trivial P2PK verifies under a clean context");
        assert!(ok);
    }

    /// A ContextExtension key with the high bit set (>= 0x80) must reject the
    /// spend BEFORE the trivial-reduction fast path — Scala `toSigmaContext`
    /// throws at context build, so even a bare P2PK input fails. (Regression
    /// guard: the depth-0 eval_expr check is bypassed by trivial_reduce.)
    #[test]
    fn trivial_p2pk_extension_key_high_bit_rejects() {
        let tree = inline_sigmaprop_tree();
        let mut ctx = crate::evaluator::ReductionContext::minimal(500_000, 0);
        ctx.extension
            .insert(128, (SigmaType::SInt, SigmaValue::Int(42)));
        let mut cost = CostAccumulator::recording_only();
        let res = verify_spending_proof_with_context_and_cost(&tree, &[], b"msg", &ctx, &mut cost);
        assert!(
            res.is_err(),
            "extension key 0x80 must reject even a trivial P2PK spend, got {res:?}"
        );
    }

    /// An off-curve GroupElement constant in the segregated table must reject a
    /// trivially-reducible spend, even though the live (trivial) path never
    /// reads it — Scala curve-validates every GE constant at deserialize.
    #[test]
    fn trivial_p2pk_offcurve_ge_constant_rejects() {
        let mut ge = [0xffu8; 33];
        ge[0] = 0x02; // off-curve x
        let tree = ErgoTree {
            version: 0,
            has_size: false,
            constant_segregation: true,
            constants: vec![
                (SigmaType::SSigmaProp, p2pk_trivial()),
                (
                    SigmaType::SGroupElement,
                    SigmaValue::GroupElement(
                        ergo_primitives::group_element::GroupElement::from_bytes(ge),
                    ),
                ),
            ],
            body: Expr::Op(IrNode {
                opcode: 0x73,
                payload: Payload::ConstPlaceholder { index: 0 },
            }),
        };
        let ctx = crate::evaluator::ReductionContext::minimal(500_000, 0);
        let mut cost = CostAccumulator::recording_only();
        let res = verify_spending_proof_with_context_and_cost(&tree, &[], b"msg", &ctx, &mut cost);
        assert!(
            res.is_err(),
            "off-curve GE constant must reject even a trivial spend, got {res:?}"
        );
    }
}
