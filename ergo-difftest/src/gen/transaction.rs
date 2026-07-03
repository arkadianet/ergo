//! Structure-aware generator for the `transaction` SER surface.
//!
//! Wire shape: `inputs · dataInputs · tokenTable · outputs`. The outputs are
//! serialized in indexed-token mode against the per-tx table. The adversarial
//! knobs here are tx-level shape violations (empty outputs, a 0-amount token)
//! that the codec accepts but validation rejects — the accept/reject boundary
//! the differential is built to catch.

use ergo_primitives::digest::Digest32;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::ergo_box::ErgoBoxCandidate;
use ergo_ser::ergo_tree::ErgoTree;
use ergo_ser::input::{ContextExtension, Input, SpendingProof};
use ergo_ser::opcode::Expr;
use ergo_ser::register::AdditionalRegisters;
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::{SigmaBoolean, SigmaValue};
use ergo_ser::transaction::{write_transaction, Transaction};

use crate::gen::asm;
use crate::gen::{Feature, FeatureSet, GenMode, GenOutput};
use crate::rng::Rng;

const SURFACE: &str = "transaction";

/// Generate one transaction input: ~40% on-manifold, ~60% adversarial.
pub fn gen(rng: &mut Rng) -> GenOutput {
    if rng.below(100) < 40 {
        gen_valid(rng)
    } else {
        gen_adversarial(rng)
    }
}

fn valid_sigmaprop_tree() -> ErgoTree {
    ErgoTree {
        version: 0,
        has_size: false,
        constant_segregation: false,
        constants: vec![],
        body: Expr::Const {
            tpe: SigmaType::SSigmaProp,
            val: SigmaValue::SigmaProp(SigmaBoolean::TrivialProp(true)),
        },
    }
}

/// On-manifold: a valid 1-input / 1-output transaction, via the real writer.
pub fn gen_valid(rng: &mut Rng) -> GenOutput {
    let mut box_id = [0u8; 32];
    for b in box_id.iter_mut() {
        *b = rng.byte();
    }
    let input = Input {
        box_id: Digest32::from_bytes(box_id),
        spending_proof: SpendingProof::new(vec![], ContextExtension::empty())
            .expect("empty extension serializes"),
    };
    let output = ErgoBoxCandidate::new(
        1_000_000 + (rng.next_u64() >> 12),
        valid_sigmaprop_tree(),
        (rng.next_u64() & 0xffff) as u32,
        vec![],
        AdditionalRegisters::empty(),
    )
    .expect("valid output serializes");
    let tx = Transaction {
        inputs: vec![input],
        data_inputs: vec![],
        output_candidates: vec![output],
    };
    let mut w = VlqWriter::new();
    write_transaction(&mut w, &tx).expect("valid tx writes");
    GenOutput {
        surface: SURFACE,
        bytes: w.result(),
        intended_valid: true,
        mode: GenMode::OnManifold,
        features: FeatureSet::from_iter([Feature::OnManifoldValid]),
    }
}

/// One signed input: 32-byte box id, empty proof (`u16` 0), empty extension.
fn valid_input_bytes(rng: &mut Rng) -> Vec<u8> {
    let mut b = Vec::with_capacity(34);
    for _ in 0..32 {
        b.push(rng.byte());
    }
    asm::put_vlq(&mut b, 0); // proof length u16 = 0
    b.push(0x00); // context-extension count = 0
    b
}

/// One indexed output box: value · tree · height · tokens(indexed) · registers.
fn indexed_output_bytes(
    value: u64,
    tree: &[u8],
    height: u32,
    token_amounts: &[(u32, u64)],
) -> Vec<u8> {
    let mut b = Vec::new();
    asm::put_vlq(&mut b, value);
    b.extend_from_slice(tree);
    asm::put_vlq(&mut b, height as u64);
    b.push(token_amounts.len() as u8);
    for (idx, amount) in token_amounts {
        asm::put_vlq(&mut b, *idx as u64);
        asm::put_vlq(&mut b, *amount);
    }
    b.push(0x00); // empty register block
    b
}

/// Assemble a full transaction from field byte-blocks.
fn assemble_tx(inputs: &[Vec<u8>], token_ids: &[[u8; 32]], outputs: &[Vec<u8>]) -> Vec<u8> {
    let mut b = Vec::new();
    asm::put_vlq(&mut b, inputs.len() as u64); // input count u16
    for inp in inputs {
        b.extend_from_slice(inp);
    }
    asm::put_vlq(&mut b, 0); // data-input count u16 = 0
    asm::put_vlq(&mut b, token_ids.len() as u64); // token-table count u32
    for id in token_ids {
        b.extend_from_slice(id);
    }
    asm::put_vlq(&mut b, outputs.len() as u64); // output count u16
    for o in outputs {
        b.extend_from_slice(o);
    }
    b
}

fn gen_adversarial(rng: &mut Rng) -> GenOutput {
    if rng.coin() {
        empty_outputs(rng)
    } else {
        zero_amount_token(rng)
    }
}

/// A transaction with a valid input but ZERO outputs. Bug #23: the codec
/// accepts it (the ≥1-output rule is a validation rule), so it round-trips.
fn empty_outputs(rng: &mut Rng) -> GenOutput {
    let bytes = assemble_tx(&[valid_input_bytes(rng)], &[], &[]);
    GenOutput {
        surface: SURFACE,
        bytes,
        intended_valid: true,
        mode: GenMode::Adversarial,
        features: FeatureSet::from_iter([Feature::TxEmptyOutputs]),
    }
}

/// A transaction whose single output holds a token with amount 0. Bug #23: the
/// codec accepts; the positive-amount rule lives in validation.
fn zero_amount_token(rng: &mut Rng) -> GenOutput {
    let mut token_id = [0u8; 32];
    for b in token_id.iter_mut() {
        *b = rng.byte();
    }
    let output = indexed_output_bytes(1_000_000, &asm::TREE_TRUE_PROP, 1, &[(0, 0)]);
    let bytes = assemble_tx(&[valid_input_bytes(rng)], &[token_id], &[output]);
    GenOutput {
        surface: SURFACE,
        bytes,
        intended_valid: true,
        mode: GenMode::Adversarial,
        features: FeatureSet::from_iter([Feature::TxZeroAmountToken]),
    }
}
