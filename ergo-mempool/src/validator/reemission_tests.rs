use super::*;
use crate::admission::{AdmissionOutcome, RejectReason, TipContext};
use crate::types::{MempoolAction, MempoolConfig, TipPointer, TxSource};
use ergo_primitives::cost::{CostAccumulator, JitCost};
use ergo_primitives::writer::VlqWriter;
use ergo_ser::ergo_box::ErgoBoxCandidate;
use ergo_ser::ergo_tree::read_ergo_tree;
use ergo_ser::input::{ContextExtension, Input, SpendingProof};
use ergo_ser::register::AdditionalRegisters;
use ergo_ser::token::Token;
use ergo_ser::transaction::write_transaction;
use ergo_validation::{ProtocolParams, ReemissionRuleInputs, TxValidationCtx, TxValidationRules};
use std::time::Instant;

const TOKEN: [u8; 32] = [42; 32];
const TRUE: &[u8] = &[0, 8, 0xd3];
const FALSE: &[u8] = &[0, 8, 0xd2];

struct Boxes(ErgoBox);
impl UtxoView for Boxes {
    fn get_box(&self, id: &Digest32) -> Option<ErgoBox> {
        (self.0.box_id().unwrap() == *id).then(|| self.0.clone())
    }
}

fn candidate(value: u64, tree: &[u8], tokens: Vec<Token>) -> ErgoBoxCandidate {
    ErgoBoxCandidate::new(
        value,
        read_ergo_tree(&mut VlqReader::new(tree)).unwrap(),
        0,
        tokens,
        AdditionalRegisters::empty(),
    )
    .unwrap()
}

fn fixture(preserve_token: bool) -> (Boxes, Vec<u8>, ReemissionRuleInputs) {
    let token = Token {
        token_id: Digest32::from_bytes(TOKEN),
        amount: 1_000_000,
    };
    let input = ErgoBox {
        candidate: candidate(10_000_000, TRUE, vec![token.clone()]),
        transaction_id: Digest32::from_bytes([1; 32]).into(),
        index: 0,
    };
    let tx = Transaction {
        inputs: vec![Input {
            box_id: input.box_id().unwrap(),
            spending_proof: SpendingProof::new(Vec::new(), ContextExtension::empty()).unwrap(),
        }],
        data_inputs: vec![],
        output_candidates: vec![
            candidate(
                8_000_000,
                TRUE,
                if preserve_token { vec![token] } else { vec![] },
            ),
            candidate(1_000_000, FALSE, vec![]),
            candidate(1_000_000, MAINNET_FEE_PROPOSITION_BYTES, vec![]),
        ],
    };
    let mut w = VlqWriter::new();
    write_transaction(&mut w, &tx).unwrap();
    (
        Boxes(input),
        w.result(),
        ReemissionRuleInputs {
            activation_height: 0,
            reemission_token_id: TOKEN,
            pay_to_reemission_tree: FALSE.to_vec(),
        },
    )
}

#[test]
fn output_token_declines_before_scripts_without_peer_penalty_and_caches_fetch_id() {
    let (boxes, bytes, rules) = fixture(true);
    let ctx = super::tests::dummy_ctx();
    let params = ProtocolParams::mainnet_default();
    let mut cost = CostAccumulator::new(JitCost::from_block_cost(1_000_000).unwrap());
    let err = ErgoValidator
        .validate(
            &bytes,
            &boxes,
            &boxes,
            &mut TxValidationCtx {
                ctx: &ctx,
                params: &params,
                cost: &mut cost,
                last_headers: &[],
                rules: TxValidationRules {
                    reemission: Some(&rules),
                    soft_fields_allowed: true,
                },
            },
        )
        .unwrap_err();
    assert_eq!(err, ValidationErr::ReemissionPolicy);
    assert_eq!(cost.consumed(), 0);

    let mut pool = crate::Mempool::new(MempoolConfig::default(), Box::new(crate::weight::ByCost));
    let tip = TipContext {
        tip: TipPointer {
            height: 1000,
            header_id: Digest32::from_bytes([0; 32]),
        },
        best_header_height: 1000,
        best_full_block_height: 1000,
        utxo: &boxes,
        tx_context: &ctx,
        params: &params,
        last_headers: &[],
        reemission: Some(&rules),
        input_block_txs: &[],
    };
    let id = ErgoValidator.peek_fee(&bytes).unwrap().tx_id;
    for _ in 0..2 {
        let (outcome, actions) = pool.process(
            &bytes,
            TxSource::Peer("127.0.0.1:1234".parse().unwrap()),
            Instant::now(),
            &tip,
            &ErgoValidator,
        );
        assert!(matches!(
            outcome,
            AdmissionOutcome::Rejected {
                reason: RejectReason::ValidationFailed {
                    kind: ValidationErr::ReemissionPolicy
                }
            }
        ));
        assert!(!actions.iter().any(|a| matches!(
            a,
            MempoolAction::Penalize { .. } | MempoolAction::BroadcastInv { .. }
        )));
        assert_eq!(pool.size(), 0);
        assert!(pool.is_invalidated(&id));
    }
}

#[test]
fn reward_burn_is_admitted_and_network_without_reemission_can_preserve_tokens() {
    for (preserve, enabled) in [(false, true), (true, false)] {
        let (boxes, bytes, rules) = fixture(preserve);
        let ctx = super::tests::dummy_ctx();
        let params = ProtocolParams::mainnet_default();
        let mut cost = CostAccumulator::new(JitCost::from_block_cost(1_000_000).unwrap());
        ErgoValidator
            .validate(
                &bytes,
                &boxes,
                &boxes,
                &mut TxValidationCtx {
                    ctx: &ctx,
                    params: &params,
                    cost: &mut cost,
                    last_headers: &[],
                    rules: TxValidationRules {
                        reemission: enabled.then_some(&rules),
                        soft_fields_allowed: true,
                    },
                },
            )
            .unwrap();
        assert!(cost.consumed() > 0);
    }
}
