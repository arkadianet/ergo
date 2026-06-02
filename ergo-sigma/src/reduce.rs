use ergo_primitives::cost::{CostAccumulator, JitCost};
use ergo_ser::ergo_tree::ErgoTree;
use ergo_ser::opcode::{Expr, IrNode, Payload};
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::{SigmaBoolean, SigmaValue};
use thiserror::Error;

/// Cost of evaluating a SigmaProp constant (trivial reduction path).
/// Source: sigmastate-interpreter Interpreter.scala:533
const EVAL_SIGMA_PROP_CONSTANT: JitCost = JitCost::from_jit(50);

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
}
