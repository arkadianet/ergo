//! Per-output height-constraint checks.
//!
//! Scala references (`ergo-core/.../mempool/ErgoTransaction.scala`):
//! - line 172: `txFuture` (rule 112) — `creationHeight <= currentHeight`
//! - line 174: `txMonotonicHeight` (rule 124) — `creationHeight >=
//!   maxCreationHeightInInputs`. Soft-fork-gated on
//!   `Header.HardeningVersion = 2`: v1/v2 blocks treat the max as
//!   `0` (no-op since `creation_height: u32 >= 0` is trivial).
//!
//! Rule 122 (`txNegHeight`) is type-level in Rust: `creation_height`
//! is `u32`, so a negative value is unrepresentable at the box
//! candidate boundary. No runtime check needed.

use ergo_ser::ergo_box::ErgoBox;
use ergo_ser::transaction::Transaction;

use crate::context::TransactionContext;
use crate::error::ValidationError;

/// Scala `Header.HardeningVersion = 2`. Rule 124 (`txMonotonicHeight`)
/// activates strictly after this version — i.e. blocks with
/// `version >= 3` enforce the monotonic-height invariant on outputs.
pub const HARDENING_VERSION: u8 = 2;

/// Reject any output whose declared `creation_height` is greater
/// than the block we're validating. Scala rule 112 (`txFuture`).
///
/// Equality is allowed — coinbase outputs at block H have
/// `creation_height == H` legitimately. Only strict-greater fails.
pub fn validate_output_heights(
    tx: &Transaction,
    ctx: &TransactionContext,
) -> Result<(), ValidationError> {
    for (i, out) in tx.output_candidates.iter().enumerate() {
        if out.creation_height > ctx.height {
            return Err(ValidationError::OutputFromFuture {
                index: i,
                creation_height: out.creation_height,
                block_height: ctx.height,
            });
        }
    }
    Ok(())
}

/// Reject when any output's `creation_height` is below the maximum
/// `creation_height` across the spending inputs. Scala rule 124
/// (`txMonotonicHeight`).
///
/// Soft-fork-gated on `Header.HardeningVersion = 2`:
/// `block_version <= 2` returns immediately (Scala `maxCreationHeightInInputs = 0`,
/// trivially satisfied by `u32`). `block_version >= 3` computes
/// `max(input.creation_height)` and enforces
/// `out.creation_height >= that max`.
pub fn validate_monotonic_heights(
    tx: &Transaction,
    resolved_inputs: &[ErgoBox],
    block_version: u8,
) -> Result<(), ValidationError> {
    // Signed-Byte version comparison (Scala `Header.Version = Byte`): the
    // HardeningVersion gate is signed. Agrees for real versions (1-4); a
    // malformed version > 127 is signed-negative, so the rule is skipped —
    // matching the reference. (Unreachable: PoW-firewalled.)
    if (block_version as i8) <= HARDENING_VERSION as i8 {
        return Ok(());
    }
    let max_input_height = resolved_inputs
        .iter()
        .map(|b| b.candidate.creation_height)
        .max()
        .unwrap_or(0);
    for (i, out) in tx.output_candidates.iter().enumerate() {
        if out.creation_height < max_input_height {
            return Err(ValidationError::OutputCreationHeightBelowInputs {
                index: i,
                creation_height: out.creation_height,
                max_input_height,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::digest::Digest32;
    use ergo_ser::ergo_box::ErgoBoxCandidate;
    use ergo_ser::ergo_tree::ErgoTree;
    use ergo_ser::input::{ContextExtension, Input, SpendingProof};
    use ergo_ser::opcode::Expr;
    use ergo_ser::register::AdditionalRegisters;
    use ergo_ser::sigma_type::SigmaType;
    use ergo_ser::sigma_value::SigmaValue;

    fn simple_tree() -> ErgoTree {
        ErgoTree {
            version: 0,
            has_size: true,
            constant_segregation: true,
            constants: vec![(SigmaType::SBoolean, SigmaValue::Boolean(true))],
            body: Expr::Const {
                tpe: SigmaType::SBoolean,
                val: SigmaValue::Boolean(true),
            },
        }
    }

    fn candidate_at_height(creation_height: u32) -> ErgoBoxCandidate {
        ErgoBoxCandidate::new(
            1_000_000_000_000,
            simple_tree(),
            creation_height,
            vec![],
            AdditionalRegisters::empty(),
        )
        .unwrap()
    }

    fn make_input() -> Input {
        Input {
            box_id: Digest32::from_bytes([1; 32]),
            spending_proof: SpendingProof::new(vec![], ContextExtension::empty()).unwrap(),
        }
    }

    fn make_tx_with_outputs(outputs: Vec<ErgoBoxCandidate>) -> Transaction {
        Transaction {
            inputs: vec![make_input()],
            data_inputs: vec![],
            output_candidates: outputs,
        }
    }

    fn ctx_at_height(height: u32) -> TransactionContext {
        TransactionContext {
            height,
            miner_pubkey: [0u8; 33],
            pre_header_timestamp: 0,
            activated_script_version: 2,
            pre_header_version: 0,
            pre_header_parent_id: [0u8; 32],
            pre_header_n_bits: 0,
            pre_header_votes: [0u8; 3],
        }
    }

    #[test]
    fn output_at_block_height_accepted() {
        // Equality case — a coinbase-style output created at the
        // block's own height must pass.
        let tx = make_tx_with_outputs(vec![candidate_at_height(100)]);
        let ctx = ctx_at_height(100);
        validate_output_heights(&tx, &ctx).unwrap();
    }

    #[test]
    fn output_below_block_height_accepted() {
        // Historical creation_height (e.g. spending an old box's
        // re-emission) is fine.
        let tx = make_tx_with_outputs(vec![candidate_at_height(50)]);
        let ctx = ctx_at_height(100);
        validate_output_heights(&tx, &ctx).unwrap();
    }

    #[test]
    fn output_one_over_block_height_rejected() {
        // Strict-greater fails. This is the boundary that Scala
        // rule 112 enforces.
        let tx = make_tx_with_outputs(vec![candidate_at_height(101)]);
        let ctx = ctx_at_height(100);
        let err = validate_output_heights(&tx, &ctx).unwrap_err();
        match err {
            ValidationError::OutputFromFuture {
                index,
                creation_height,
                block_height,
            } => {
                assert_eq!(index, 0);
                assert_eq!(creation_height, 101);
                assert_eq!(block_height, 100);
            }
            other => panic!("expected OutputFromFuture, got {other:?}"),
        }
    }

    #[test]
    fn second_output_from_future_rejected_with_correct_index() {
        // Index reported must match the first offending output.
        let tx = make_tx_with_outputs(vec![candidate_at_height(100), candidate_at_height(105)]);
        let ctx = ctx_at_height(100);
        let err = validate_output_heights(&tx, &ctx).unwrap_err();
        match err {
            ValidationError::OutputFromFuture { index, .. } => assert_eq!(index, 1),
            other => panic!("expected OutputFromFuture at index 1, got {other:?}"),
        }
    }

    #[test]
    fn genesis_block_outputs_at_height_zero_accepted() {
        // Genesis edge: block height 0, outputs at creation_height 0
        // must pass (0 <= 0).
        let tx = make_tx_with_outputs(vec![candidate_at_height(0)]);
        let ctx = ctx_at_height(0);
        validate_output_heights(&tx, &ctx).unwrap();
    }

    #[test]
    fn far_future_creation_height_rejected() {
        // Adversarial value: max u32 creation_height, modest block
        // height. Must reject cleanly without arithmetic surprise.
        let tx = make_tx_with_outputs(vec![candidate_at_height(u32::MAX)]);
        let ctx = ctx_at_height(1_000_000);
        let err = validate_output_heights(&tx, &ctx).unwrap_err();
        assert!(matches!(
            err,
            ValidationError::OutputFromFuture {
                creation_height: u32::MAX,
                block_height: 1_000_000,
                ..
            }
        ));
    }

    // ----- validate_monotonic_heights (rule 124) -----

    use ergo_primitives::digest::ModifierId;
    use ergo_ser::ergo_box::ErgoBox;

    fn boxed(candidate: ErgoBoxCandidate, fill: u8) -> ErgoBox {
        ErgoBox {
            candidate,
            transaction_id: ModifierId::from_bytes([fill; 32]),
            index: 0,
        }
    }

    fn input_at_height(creation_height: u32, fill: u8) -> ErgoBox {
        boxed(candidate_at_height(creation_height), fill)
    }

    #[test]
    fn monotonic_v1_block_is_noop() {
        // block_version <= HARDENING_VERSION → rule is a no-op even
        // when output creation_height is below input max.
        let tx = make_tx_with_outputs(vec![candidate_at_height(50)]);
        let inputs = vec![input_at_height(100, 1)];
        validate_monotonic_heights(&tx, &inputs, 1).unwrap();
    }

    #[test]
    fn monotonic_v2_block_is_noop() {
        // v2 == HARDENING_VERSION. Boundary is `<=`, so v2 is still
        // a no-op; rule activates at v3.
        let tx = make_tx_with_outputs(vec![candidate_at_height(50)]);
        let inputs = vec![input_at_height(100, 1)];
        validate_monotonic_heights(&tx, &inputs, 2).unwrap();
    }

    #[test]
    fn monotonic_v3_block_enforces_invariant() {
        // Output creation_height 100 == max input creation_height
        // 100. Equality passes.
        let tx = make_tx_with_outputs(vec![candidate_at_height(100)]);
        let inputs = vec![input_at_height(100, 1), input_at_height(80, 2)];
        validate_monotonic_heights(&tx, &inputs, 3).unwrap();
    }

    #[test]
    fn monotonic_v127_signed_positive_enforces() {
        // 127 as i8 is +127 (> HardeningVersion 2), so the rule is enforced:
        // an output below the max input height is rejected.
        let tx = make_tx_with_outputs(vec![candidate_at_height(50)]);
        let inputs = vec![input_at_height(100, 1)];
        assert!(validate_monotonic_heights(&tx, &inputs, 127).is_err());
    }

    #[test]
    fn monotonic_v128_signed_negative_is_noop() {
        // 128 as i8 is -128 (<= HardeningVersion 2 under signed semantics), so
        // the rule is a no-op — same output that v127 rejects now passes.
        // (Unreachable in practice; pins the 127/128 signed boundary.)
        let tx = make_tx_with_outputs(vec![candidate_at_height(50)]);
        let inputs = vec![input_at_height(100, 1)];
        validate_monotonic_heights(&tx, &inputs, 128).unwrap();
    }

    #[test]
    fn monotonic_v3_rejects_output_below_max_input_height() {
        let tx = make_tx_with_outputs(vec![candidate_at_height(50)]);
        let inputs = vec![input_at_height(100, 1), input_at_height(80, 2)];
        let err = validate_monotonic_heights(&tx, &inputs, 3).unwrap_err();
        match err {
            ValidationError::OutputCreationHeightBelowInputs {
                index,
                creation_height,
                max_input_height,
            } => {
                assert_eq!(index, 0);
                assert_eq!(creation_height, 50);
                assert_eq!(max_input_height, 100);
            }
            other => panic!("expected OutputCreationHeightBelowInputs, got {other:?}"),
        }
    }

    #[test]
    fn monotonic_v3_empty_inputs_treated_as_zero_max() {
        // Validator typically rejects zero-input txs at structural
        // pass (rule 100), but the helper is independently safe:
        // empty inputs → max=0 → any u32 output height passes.
        let tx = make_tx_with_outputs(vec![candidate_at_height(0)]);
        validate_monotonic_heights(&tx, &[], 3).unwrap();
    }

    #[test]
    fn monotonic_v3_reports_first_offending_output() {
        // Two outputs both below max; report the lower-index one.
        let tx = make_tx_with_outputs(vec![
            candidate_at_height(100), // passes
            candidate_at_height(50),  // first offender
            candidate_at_height(40),  // also offending
        ]);
        let inputs = vec![input_at_height(100, 1)];
        let err = validate_monotonic_heights(&tx, &inputs, 3).unwrap_err();
        match err {
            ValidationError::OutputCreationHeightBelowInputs { index, .. } => {
                assert_eq!(index, 1);
            }
            other => panic!("expected offender index=1, got {other:?}"),
        }
    }
}
