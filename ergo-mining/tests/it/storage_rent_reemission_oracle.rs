//! Oracle-parity: the storage-rent / EIP-27 deadlock, pinned against a
//! live Scala mainnet node.
//!
//! Vector `test-vectors/mainnet/storage_rent_reemission_deadlock.json`
//! captures a REAL rent-eligible mainnet miner-reward box
//! (`fbf119cb…f82cfb`, 63 ERG, created at 777,693 — 476 blocks after
//! EIP-27 activation) still carrying 12 ERG of re-emission tokens, plus
//! the two only-possible claim shapes and the Scala node's verdict on
//! each (POST /transactions/check at height 1,831,842):
//!
//! 1. **Token-preserving claim** (what `checkExpiredBox`'s recreate
//!    branch demands) → Scala: "Transaction should conform EIP-27 rules".
//! 2. **Burn-compliant claim** (token dropped, 1 nanoErg/token paid to
//!    pay-to-reemission — what `verifyReemissionSpending` demands) →
//!    Scala: script verification failure (`checkExpiredBox` false: tokens
//!    and value not preserved).
//!
//! Together the verdicts prove the box is consensus-unclaimable via
//! storage rent on the reference node — the basis for the builder's
//! re-emission-token exclusion (`build_rent_claim`). This test pins the
//! Rust validator to the same two rejections (reject-invalid parity) and
//! the fixed builder to skipping the box entirely.

use ergo_mining::storage_rent_claim::build_rent_claim;
use ergo_primitives::digest::{Digest32, ModifierId};
use ergo_primitives::reader::VlqReader;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::read_ergo_tree;
use ergo_ser::input::{ContextExtension, Input, SpendingProof};
use ergo_ser::register::AdditionalRegisters;
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::SigmaValue;
use ergo_ser::token::Token;
use ergo_ser::transaction::{write_transaction, Transaction};
use ergo_validation::{
    validate_transaction_parsed, CostAccumulator, JitCost, ProtocolParams, ReemissionRuleInputs,
    TransactionContext, TxValidationCtx, TxValidationRules, ValidationError,
};

// ----- helpers -----

/// secp256k1 generator point, compressed — the miner pk the captured
/// claim txs pay rent to.
const MINER_PK: [u8; 33] = [
    0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B,
    0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17,
    0x98,
];

fn vector() -> serde_json::Value {
    let path = format!(
        "{}/../test-vectors/mainnet/storage_rent_reemission_deadlock.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_slice(&std::fs::read(&path).expect("read vector")).expect("parse vector")
}

fn mainnet_rules() -> ReemissionRuleInputs {
    let spec = ergo_chain_spec::ChainSpec::mainnet();
    let reem = spec.reemission.as_ref().expect("mainnet has EIP-27");
    let trees = spec
        .emission_script_trees()
        .expect("mainnet has emission trees");
    ReemissionRuleInputs {
        activation_height: reem.activation_height,
        reemission_token_id: *reem.reemission_token_id.as_bytes(),
        pay_to_reemission_tree: trees.pay_to_reemission,
    }
}

fn hex32(s: &str) -> [u8; 32] {
    let mut a = [0u8; 32];
    hex::decode_to_slice(s, &mut a).expect("32-byte hex");
    a
}

fn candidate_from_json(o: &serde_json::Value) -> ErgoBoxCandidate {
    let tree_bytes = hex::decode(o["ergoTree"].as_str().unwrap()).expect("tree hex");
    let tree = read_ergo_tree(&mut VlqReader::new(&tree_bytes)).expect("parse tree");
    let tokens: Vec<Token> = o["assets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| Token {
            token_id: Digest32::from_bytes(hex32(a["tokenId"].as_str().unwrap())),
            amount: a["amount"].as_u64().unwrap(),
        })
        .collect();
    ErgoBoxCandidate::from_trusted_raw_parts(
        o["value"].as_u64().unwrap(),
        tree,
        tree_bytes,
        o["creationHeight"].as_u64().unwrap() as u32,
        tokens,
        AdditionalRegisters::empty(),
        vec![0x00],
    )
}

fn input_box(v: &serde_json::Value) -> ErgoBox {
    let b = &v["input_box"];
    ErgoBox {
        candidate: candidate_from_json(b),
        transaction_id: ModifierId::from_bytes(hex32(b["transactionId"].as_str().unwrap())),
        index: b["index"].as_u64().unwrap() as u16,
    }
}

/// Rebuild a captured claim tx: every input is a storage-rent input
/// (empty proof, var-127 = Short(0) naming the recreated output).
fn claim_tx_from_json(tx: &serde_json::Value) -> Transaction {
    let inputs: Vec<Input> = tx["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| {
            let mut ext = ContextExtension::empty();
            ext.values
                .insert(127, (SigmaType::SShort, SigmaValue::Short(0)));
            Input {
                box_id: Digest32::from_bytes(hex32(i["boxId"].as_str().unwrap())),
                spending_proof: SpendingProof::new(Vec::new(), ext).expect("proof"),
            }
        })
        .collect();
    let output_candidates = tx["outputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(candidate_from_json)
        .collect();
    Transaction {
        inputs,
        data_inputs: Vec::new(),
        output_candidates,
    }
}

fn validate(
    tx: &Transaction,
    resolved: Vec<ErgoBox>,
    height: u32,
    params: &ProtocolParams,
    rules: &ReemissionRuleInputs,
) -> Result<(), ValidationError> {
    let mut w = VlqWriter::new();
    write_transaction(&mut w, tx).unwrap();
    let bytes = w.result();
    let ctx = TransactionContext {
        height,
        miner_pubkey: MINER_PK,
        pre_header_timestamp: 0,
        activated_script_version: 2,
        pre_header_version: 3,
        pre_header_parent_id: [0u8; 32],
        pre_header_n_bits: 0,
        pre_header_votes: [0u8; 3],
    };
    let mut cost = CostAccumulator::new(JitCost::from_block_cost(params.max_block_cost).unwrap());
    let mut cx = TxValidationCtx {
        ctx: &ctx,
        params,
        cost: &mut cost,
        last_headers: &[],
        rules: TxValidationRules {
            reemission: Some(rules),
        },
    };
    validate_transaction_parsed(tx.clone(), &bytes, resolved, Vec::new(), false, &mut cx)
        .map(|_| ())
}

// ----- oracle parity -----

#[test]
fn token_preserving_claim_rejected_like_scala() {
    // Scala: "Transaction should conform EIP-27 rules". Rust must reject
    // the identical tx via the ported rule (stage 7), not accept a tx the
    // reference node rejects.
    let v = vector();
    let height = v["captured"]["spending_height"].as_u64().unwrap() as u32;
    let bx = input_box(&v);
    let tx = claim_tx_from_json(&v["token_preserving_claim"]["tx"]);
    let params = ProtocolParams::mainnet_default();

    let err = validate(&tx, vec![bx], height, &params, &mainnet_rules())
        .expect_err("Scala rejects this tx; Rust must too");
    assert!(
        matches!(err, ValidationError::ReemissionRulesViolated(_)),
        "expected ReemissionRulesViolated, got {err:?}"
    );
}

#[test]
fn burn_compliant_claim_rejected_like_scala() {
    // Scala: input script verification fails (`checkExpiredBox` false —
    // the recreated output dropped the tokens and 12 ERG of value). Rust
    // must fail the same stage (script, stage 6), proving the deadlock's
    // second jaw: EIP-27 compliance breaks the storage-rent contract.
    let v = vector();
    let height = v["captured"]["spending_height"].as_u64().unwrap() as u32;
    let bx = input_box(&v);
    let tx = claim_tx_from_json(&v["burn_compliant_claim"]["tx"]);
    let params = ProtocolParams::mainnet_default();

    let err = validate(&tx, vec![bx], height, &params, &mainnet_rules())
        .expect_err("Scala rejects this tx; Rust must too");
    // Scala reports this as `Success((false, cost))` — the input verified
    // to FALSE. The Rust pipeline surfaces the same outcome as
    // `ProofFailed` (empty proof + storage-rent conditions not met).
    assert!(
        matches!(err, ValidationError::ProofFailed { index: 0 }),
        "expected ProofFailed (storage-rent contract violated), got {err:?}"
    );
}

#[test]
fn fixed_builder_skips_the_oracle_box() {
    // The builder must refuse to claim the real mainnet box both claim
    // shapes were rejected for — the fix under test.
    let v = vector();
    let height = v["captured"]["spending_height"].as_u64().unwrap() as u32;
    let bx = input_box(&v);
    let params = ProtocolParams::mainnet_default();
    let rules = mainnet_rules();

    let claim = build_rent_claim(&[bx], height, &params, 64, &MINER_PK, Some(&rules))
        .expect("builder must not error");
    assert!(
        claim.is_none(),
        "the oracle box is consensus-unclaimable and must be skipped"
    );
}
