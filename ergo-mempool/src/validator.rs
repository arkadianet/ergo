//! Production [`Validator`] bridging `ergo_validation::validate_transaction_parsed`.
//!
//! Owns nothing — purely a stateless adapter. Handed to
//! [`crate::admission::process`] alongside the tip context. Errors from
//! `ergo_validation::ValidationError` are mapped to our coarser
//! [`ValidationErr`] so the admission pipeline can route penalties
//! and observability uniformly.

use ergo_primitives::digest::{blake2b256, Digest32, ModifierId};
use ergo_primitives::reader::VlqReader;
use ergo_ser::ergo_box::ErgoBox;
use ergo_ser::transaction::{bytes_to_sign, read_transaction, Transaction};
use ergo_validation::{validate_transaction_parsed, UtxoView, ValidationError};

use crate::admission::{PeekedTx, Validated, ValidationErr, Validator};

/// Canonical miner-fee ErgoTree serialization on Ergo mainnet. Any
/// output whose `ergo_tree_bytes()` equals this tree is counted as
/// paying a miner fee. Derived empirically from the mainnet
/// `transactions_1761000_1762000` corpus: the fee proposition appears
/// exactly as one output on ~83% of txs, consistent across all blocks
/// surveyed. Mirrors Scala's `MonetarySettings.feePropositionBytes`.
///
/// The tree is `proveDlog(minerPk) ∧ HEIGHT >= SelfCreationHeight + 720`,
/// constant-segregated with a fixed emission delay (`delta = 720` on
/// mainnet). Const bytes are stable across versions.
/// Test-only re-export for the harness at `tests/m7_mainnet_corpus.rs`.
#[doc(hidden)]
pub const MAINNET_FEE_PROPOSITION_BYTES_FOR_TEST: &[u8] = MAINNET_FEE_PROPOSITION_BYTES;

/// Canonical mainnet miner-fee ErgoTree bytes. Outputs whose
/// `ergo_tree_bytes()` exactly equals this slice are the
/// fee-bearing outputs of a transaction; their value sum IS the
/// fee under Ergo's `inputs == outputs` ERG conservation rule.
/// Used by the mempool admission gate AND by the §10.4 fee-stats
/// routes (`poolHistogram` / `getFee` / `waitTime`) to compute
/// per-tx fee without resolving inputs.
pub const MAINNET_FEE_PROPOSITION_BYTES: &[u8] = &[
    0x10, 0x05, 0x04, 0x00, 0x04, 0x00, 0x0e, 0x36, 0x10, 0x02, 0x04, 0xa0, 0x0b, 0x08, 0xcd, 0x02,
    0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
    0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
    0xea, 0x02, 0xd1, 0x92, 0xa3, 0x9a, 0x8c, 0xc7, 0xa7, 0x01, 0x73, 0x00, 0x73, 0x01, 0x10, 0x01,
    0x02, 0x04, 0x02, 0xd1, 0x96, 0x83, 0x03, 0x01, 0x93, 0xa3, 0x8c, 0xc7, 0xb2, 0xa5, 0x73, 0x00,
    0x00, 0x01, 0x93, 0xc2, 0xb2, 0xa5, 0x73, 0x01, 0x00, 0x74, 0x73, 0x02, 0x73, 0x03, 0x83, 0x01,
    0x08, 0xcd, 0xee, 0xac, 0x93, 0xb1, 0xa5, 0x73, 0x04,
];

/// Default production validator. Resolves regular inputs against
/// `input_view` (the pool overlay), data inputs against `data_input_view`
/// (committed-only), then delegates to `validate_transaction_parsed`.
#[derive(Debug, Default, Clone, Copy)]
pub struct ErgoValidator;

impl Validator for ErgoValidator {
    fn peek_fee(&self, tx_bytes: &[u8]) -> Result<PeekedTx, ValidationErr> {
        // Deserialize only. No structural check, no input resolution,
        // no cost counter — just enough to read output values and
        // compute tx_id. Short-circuits below-min-fee txs before any
        // expensive validation.
        let mut r = VlqReader::new(tx_bytes);
        let tx = read_transaction(&mut r).map_err(|_| ValidationErr::Deserialize)?;
        if !r.is_empty() {
            return Err(ValidationErr::Deserialize);
        }

        // Fee sum uses saturating arithmetic. A parseable malicious
        // tx with multiple huge canonical fee outputs cannot panic
        // (debug) or wrap (release). On saturation the cheap gate
        // lets the tx through — full validation then rejects via
        // monetary/structural rules (ERG conservation over u64 is
        // impossible if a single output is u64::MAX). The gate's job
        // is only "reject clearly below-fee"; "weird values" belong
        // to real validation.
        let fee = tx
            .output_candidates
            .iter()
            .filter(|c| c.ergo_tree_bytes() == MAINNET_FEE_PROPOSITION_BYTES)
            .map(|c| c.value)
            .fold(0u64, |acc, v| acc.saturating_add(v));

        // tx_id = blake2b256(bytes_to_sign(tx)). Matches what
        // `validate_transaction_parsed` computes internally, so
        // the admission layer's debug_assert fires if they ever
        // disagree for the same bytes.
        let message = bytes_to_sign(&tx).map_err(|_| ValidationErr::Deserialize)?;
        let tx_id = Digest32::from_bytes(*blake2b256(&message).as_bytes());
        Ok(PeekedTx { tx_id, fee })
    }

    fn validate(
        &self,
        tx_bytes: &[u8],
        input_view: &dyn UtxoView,
        data_input_view: &dyn UtxoView,
        cx: &mut ergo_validation::TxValidationCtx<'_>,
    ) -> Result<Validated, ValidationErr> {
        // Deserialize. Trailing-byte check mirrors ergo-validation.
        let tx = {
            let mut r = VlqReader::new(tx_bytes);
            let parsed = read_transaction(&mut r).map_err(|_| ValidationErr::Deserialize)?;
            if !r.is_empty() {
                return Err(ValidationErr::Deserialize);
            }
            parsed
        };

        // Resolve inputs against the pool overlay.
        let resolved_inputs = resolve_inputs(&tx, input_view)?;
        // Resolve data inputs against committed UTXO only — never the
        // pool overlay; data inputs cannot reference pending state.
        let resolved_data_inputs = resolve_data_inputs(&tx, data_input_view)?;

        // Delegate to the validation crate. Script evaluation runs here.
        let checked = validate_transaction_parsed(
            tx.clone(),
            tx_bytes,
            resolved_inputs.clone(),
            resolved_data_inputs,
            false, // scripts on
            cx,
        )
        .map_err(map_validation_error)?;

        // Fee: sum of output values whose proposition matches the
        // mainnet miner-fee ErgoTree. In Ergo, fees are paid AS an
        // output to the fee tree; total inputs == total outputs (ERG
        // conservation), so `inputs - outputs` is zero. Matches
        // Scala `ErgoMemPool`: filter outputs by ergoTree equality
        // against `feePropositionBytes`, sum values.
        let fee: u64 = tx
            .output_candidates
            .iter()
            .filter(|c| c.ergo_tree_bytes() == MAINNET_FEE_PROPOSITION_BYTES)
            .map(|c| c.value)
            .sum();

        // Materialize output boxes (tx_id + index). Collect box ids in
        // parallel. On any serialization error we treat it as a
        // structural failure — it shouldn't happen for a validated tx.
        let tx_id_bytes = *checked.tx_id();
        let tx_id_digest = Digest32::from_bytes(tx_id_bytes);
        // ErgoBox.transaction_id is a ModifierId newtype (post-2026-05-06);
        // Validated.tx_id is still Digest32 for cross-crate API stability.
        let tx_id_modifier: ModifierId = tx_id_digest.into();
        let mut output_boxes = Vec::with_capacity(tx.output_candidates.len());
        let mut output_ids = Vec::with_capacity(tx.output_candidates.len());
        for (idx, candidate) in tx.output_candidates.iter().enumerate() {
            let ergo_box = ErgoBox {
                candidate: candidate.clone(),
                transaction_id: tx_id_modifier,
                index: idx as u16,
            };
            let id = ergo_box.box_id().map_err(|_| ValidationErr::Structural)?;
            output_ids.push(id);
            output_boxes.push(ergo_box);
        }

        // Cross-check: tx_id we store must match blake2b256(bytes_to_sign)
        // so downstream box_id derivation is consistent. CheckedTransaction
        // already computed this; redo the hash as an assertion.
        let message = bytes_to_sign(&tx).map_err(|_| ValidationErr::Structural)?;
        debug_assert_eq!(*blake2b256(&message).as_bytes(), tx_id_bytes);

        let input_box_ids: Vec<Digest32> = tx.inputs.iter().map(|i| i.box_id).collect();

        Ok(Validated {
            tx_id: tx_id_digest,
            input_box_ids,
            output_box_ids: output_ids,
            outputs: output_boxes,
            fee,
            size_bytes: tx_bytes.len() as u32,
            consumed_cost: cx.cost.consumed(),
        })
    }
}

fn resolve_inputs(tx: &Transaction, view: &dyn UtxoView) -> Result<Vec<ErgoBox>, ValidationErr> {
    tx.inputs
        .iter()
        .map(|input| {
            view.get_box(&input.box_id)
                .ok_or(ValidationErr::UnresolvedInput)
        })
        .collect()
}

fn resolve_data_inputs(
    tx: &Transaction,
    view: &dyn UtxoView,
) -> Result<Vec<ErgoBox>, ValidationErr> {
    tx.data_inputs
        .iter()
        .map(|di| {
            view.get_box(&di.box_id)
                .ok_or(ValidationErr::UnresolvedDataInput)
        })
        .collect()
}

fn map_validation_error(err: ValidationError) -> ValidationErr {
    use ValidationError as E;
    match err {
        E::Deserialization(_) => ValidationErr::Deserialize,
        E::NonCanonical => ValidationErr::NonCanonical,
        // Admission-fast-fail bucket. Mempool uses this to route
        // rejections that can be decided without script eval or UTXO
        // re-resolution. Includes per-output verifier failures
        // (dust 111, future 112, boxSize 120, propSize 121) that
        // Scala surfaces from `verifyOutput` — `scala_rejection_parity`
        // categorizes those as MONETARY because that bucket follows
        // Scala's verifier-path provenance, but for admission routing
        // they're all fast-fails alongside collection-level rules.
        E::NoInputs
        | E::DuplicateInput { .. }
        | E::TooManyInputs { .. }
        | E::TooManyDataInputs { .. }
        | E::TooManyOutputs { .. }
        | E::OutputValueTooLow { .. }
        | E::TooManyTokens { .. }
        | E::BoxTooLarge { .. }
        | E::PropositionTooLarge { .. }
        | E::OutputFromFuture { .. }
        | E::OutputCreationHeightBelowInputs { .. } => ValidationErr::Structural,
        E::InputBoxNotFound { .. } => ValidationErr::UnresolvedInput,
        E::DataInputBoxNotFound { .. } => ValidationErr::UnresolvedDataInput,
        E::ResolvedInputsMismatch { .. }
        | E::ResolvedInputIdMismatch { .. }
        | E::ResolvedDataInputsMismatch { .. }
        | E::ResolvedDataInputIdMismatch { .. } => {
            ValidationErr::Other("resolved-inputs contract violation".into())
        }
        E::InternalInvariantViolated(_) => {
            ValidationErr::Other("internal validator invariant violated".into())
        }
        E::ErgNotConserved { .. } | E::TokenNotConserved { .. } | E::InvalidMinting { .. } => {
            ValidationErr::MonetaryFailed
        }
        E::ScriptError { .. } | E::ProofFailed { .. } => ValidationErr::ScriptFailed,
        E::CostExceeded { .. } => ValidationErr::CostExceeded,
        // JitCost arithmetic overflow is structurally distinct from a
        // limit hit (see ValidationError::JitCostOverflow doc), but the
        // mempool's failure surface treats both as cost-class rejections.
        E::JitCostOverflow(_) => ValidationErr::CostExceeded,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::cost::{CostAccumulator, JitCost};
    use ergo_validation::{ProtocolParams, TransactionContext, TxValidationCtx};

    struct EmptyUtxo;
    impl UtxoView for EmptyUtxo {
        fn get_box(&self, _: &Digest32) -> Option<ErgoBox> {
            None
        }
    }

    fn dummy_ctx() -> TransactionContext {
        TransactionContext {
            height: 1000,
            miner_pubkey: [0u8; 33],
            pre_header_timestamp: 0,
            activated_script_version: 2,
            pre_header_version: 3,
            pre_header_parent_id: [0u8; 32],
            pre_header_n_bits: 0,
            pre_header_votes: [0u8; 3],
        }
    }

    /// Drift guard for the mainnet miner-fee proposition bytes. The
    /// hardcoded constant must equal the Scala-derived fixture at
    /// `test-vectors/mainnet/fee_proposition.hex`, which is
    /// regenerated from `ErgoTreePredef.feeProposition(720)` via
    /// `test-vectors/scripts/scala/PrintFeePropositionBytes.scala`.
    /// If Scala's serialization ever changes, regenerate the fixture
    /// — this test will then fail, forcing an explicit constant
    /// update in lockstep.
    // ----- happy path -----

    #[test]
    fn fee_proposition_matches_scala_derived_fixture() {
        let fixture = std::fs::read_to_string("../test-vectors/mainnet/fee_proposition.hex")
            .expect(
                "test-vectors/mainnet/fee_proposition.hex not found — \
             regenerate with test-vectors/scripts/scala/PrintFeePropositionBytes.scala",
            );
        let fixture_bytes =
            hex::decode(fixture.trim()).expect("fee_proposition.hex is not valid hex");
        assert_eq!(
            MAINNET_FEE_PROPOSITION_BYTES,
            fixture_bytes.as_slice(),
            "hardcoded MAINNET_FEE_PROPOSITION_BYTES drifted from Scala-derived fixture. \
             Either regenerate fixture and update constant in lockstep, or investigate why \
             they diverge."
        );
    }

    #[test]
    fn peek_fee_saturates_on_multi_output_overflow() {
        // Construct a tx with two canonical-fee outputs whose values
        // sum to overflow. `peek_fee` must saturate (not panic, not
        // wrap) so the cheap gate cannot be the termination point
        // for a malicious parseable tx. Full validation's monetary
        // check then rejects via ERG-conservation over finite input
        // sums.
        use ergo_primitives::writer::VlqWriter;
        use ergo_ser::ergo_box::ErgoBoxCandidate;
        use ergo_ser::ergo_tree::read_ergo_tree;
        use ergo_ser::input::{ContextExtension, Input, SpendingProof};
        use ergo_ser::register::AdditionalRegisters;
        use ergo_ser::transaction::{write_transaction, Transaction};

        let tree_bytes = MAINNET_FEE_PROPOSITION_BYTES.to_vec();
        let mut r = VlqReader::new(&tree_bytes);
        let tree = read_ergo_tree(&mut r).unwrap();
        let mk_fee_out = |value: u64| {
            ErgoBoxCandidate::from_trusted_raw_parts(
                value,
                tree.clone(),
                tree_bytes.clone(),
                0,
                vec![],
                AdditionalRegisters::empty(),
                vec![0u8],
            )
        };
        let tx = Transaction {
            inputs: vec![Input {
                box_id: Digest32::from_bytes([1u8; 32]),
                spending_proof: SpendingProof::new(Vec::new(), ContextExtension::empty()).unwrap(),
            }],
            data_inputs: vec![],
            output_candidates: vec![mk_fee_out(u64::MAX), mk_fee_out(u64::MAX)],
        };
        let mut w = VlqWriter::new();
        write_transaction(&mut w, &tx).unwrap();
        let bytes = w.result();

        let v = ErgoValidator;
        let peeked = v
            .peek_fee(&bytes)
            .expect("peek_fee must not panic on overflow");
        assert_eq!(
            peeked.fee,
            u64::MAX,
            "fee saturates on overflow — gate passes the tx through, full validation rejects later"
        );
    }

    #[test]
    fn peek_fee_returns_real_tx_id() {
        use ergo_primitives::writer::VlqWriter;
        use ergo_ser::ergo_box::ErgoBoxCandidate;
        use ergo_ser::ergo_tree::read_ergo_tree;
        use ergo_ser::input::{ContextExtension, Input, SpendingProof};
        use ergo_ser::register::AdditionalRegisters;
        use ergo_ser::transaction::{bytes_to_sign, write_transaction, Transaction};

        let tree_bytes = vec![0x00u8, 0x01, 0x01];
        let mut r = VlqReader::new(&tree_bytes);
        let tree = read_ergo_tree(&mut r).unwrap();
        let tx = Transaction {
            inputs: vec![Input {
                box_id: Digest32::from_bytes([7u8; 32]),
                spending_proof: SpendingProof::new(Vec::new(), ContextExtension::empty()).unwrap(),
            }],
            data_inputs: vec![],
            output_candidates: vec![ErgoBoxCandidate::new(
                1_000,
                tree,
                0,
                vec![],
                AdditionalRegisters::empty(),
            )
            .unwrap()],
        };
        let mut w = VlqWriter::new();
        write_transaction(&mut w, &tx).unwrap();
        let bytes = w.result();

        let peeked = ErgoValidator.peek_fee(&bytes).unwrap();
        let expected_id =
            Digest32::from_bytes(*blake2b256(&bytes_to_sign(&tx).unwrap()).as_bytes());
        assert_eq!(
            peeked.tx_id, expected_id,
            "peek_fee returns real tx_id, not a placeholder"
        );
    }

    #[test]
    fn deserialize_failure_maps_to_deserialize_err() {
        let v = ErgoValidator;
        let u = EmptyUtxo;
        let ctx = dummy_ctx();
        let params = ProtocolParams::mainnet_default();
        let mut cost = CostAccumulator::new(JitCost::from_block_cost(1_000_000).unwrap());
        let mut tx_cx = TxValidationCtx {
            ctx: &ctx,
            params: &params,
            cost: &mut cost,
            last_headers: &[],
        };
        let err = v.validate(b"\xff\xff\xff", &u, &u, &mut tx_cx).unwrap_err();
        assert!(matches!(err, ValidationErr::Deserialize));
    }

    #[test]
    fn error_mapping_is_exhaustive() {
        // Every ValidationError variant the validation crate can throw
        // must map to one of our ValidationErr variants. Sampling all
        // branches keeps the admission penalty table honest.
        assert!(matches!(
            map_validation_error(ValidationError::Deserialization("x".into())),
            ValidationErr::Deserialize
        ));
        assert!(matches!(
            map_validation_error(ValidationError::NonCanonical),
            ValidationErr::NonCanonical
        ));
        assert!(matches!(
            map_validation_error(ValidationError::NoInputs),
            ValidationErr::Structural
        ));
        assert!(matches!(
            map_validation_error(ValidationError::DuplicateInput { index: 0 }),
            ValidationErr::Structural
        ));
        assert!(matches!(
            map_validation_error(ValidationError::InputBoxNotFound { box_id: "x".into() }),
            ValidationErr::UnresolvedInput
        ));
        assert!(matches!(
            map_validation_error(ValidationError::DataInputBoxNotFound { box_id: "x".into() }),
            ValidationErr::UnresolvedDataInput
        ));
        assert!(matches!(
            map_validation_error(ValidationError::ErgNotConserved {
                inputs: 1,
                outputs: 2
            }),
            ValidationErr::MonetaryFailed
        ));
        assert!(matches!(
            map_validation_error(ValidationError::TokenNotConserved {
                token_id: "x".into(),
                input: 0,
                output: 1
            }),
            ValidationErr::MonetaryFailed
        ));
        assert!(matches!(
            map_validation_error(ValidationError::InvalidMinting {
                token_id: "x".into()
            }),
            ValidationErr::MonetaryFailed
        ));
        assert!(matches!(
            map_validation_error(ValidationError::ScriptError {
                index: 0,
                reason: "x".into()
            }),
            ValidationErr::ScriptFailed
        ));
        assert!(matches!(
            map_validation_error(ValidationError::ProofFailed { index: 0 }),
            ValidationErr::ScriptFailed
        ));
        assert!(matches!(
            map_validation_error(ValidationError::CostExceeded {
                current: 0,
                limit: 0
            }),
            ValidationErr::CostExceeded
        ));
        assert!(matches!(
            map_validation_error(ValidationError::OutputValueTooLow {
                index: 0,
                value: 1,
                min: 2
            }),
            ValidationErr::Structural
        ));
        assert!(matches!(
            map_validation_error(ValidationError::TooManyTokens {
                index: 0,
                count: 100,
                max: 10
            }),
            ValidationErr::Structural
        ));
        assert!(matches!(
            map_validation_error(ValidationError::BoxTooLarge {
                index: 0,
                size: 1,
                max: 0
            }),
            ValidationErr::Structural
        ));
        assert!(matches!(
            map_validation_error(ValidationError::ResolvedInputsMismatch {
                expected: 1,
                got: 0
            }),
            ValidationErr::Other(_)
        ));
        assert!(matches!(
            map_validation_error(ValidationError::ResolvedInputIdMismatch {
                index: 0,
                expected: "x".into()
            }),
            ValidationErr::Other(_)
        ));
    }
}
