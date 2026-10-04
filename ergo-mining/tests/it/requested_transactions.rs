//! External Scala fixtures pin signed miner-key-sensitive, zero-fee package
//! validation and the exact upcoming-header/proof wire bytes. These fixtures
//! establish transaction validity and membership encoding, not proof-of-work.

use ergo_mining::candidate_proof::upcoming_transactions_proof;
use ergo_mining::candidate_selection::{
    select_prioritized_txs_cancellable, CandidateOverlay, Selected,
};
use ergo_primitives::digest::Digest32;
use ergo_primitives::reader::VlqReader;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::ergo_box::{read_ergo_box, ErgoBox};
use ergo_ser::header::{read_header, Header};
use ergo_ser::transaction::{read_transaction, transaction_id, write_transaction, Transaction};
use ergo_validation::{ProtocolParams, TransactionContext, UtxoView};
use serde_json::Value;

// ----- helpers -----

struct Fixture {
    raw: Value,
    boxes: Vec<ErgoBox>,
    transactions: Vec<Transaction>,
    header: Header,
}

impl Fixture {
    fn load() -> Self {
        let raw: Value = serde_json::from_str(include_str!(
            "../../../test-vectors/mining/requested_transactions_scala_6_0_6.json"
        ))
        .unwrap();
        let decode = |field: &str| hex::decode(raw[field].as_str().unwrap()).unwrap();
        let boxes = ["input_box", "independent_input_box"]
            .iter()
            .map(|field| read_ergo_box(&mut VlqReader::new(&decode(field))).unwrap())
            .collect();
        let header = read_header(&mut VlqReader::new(&decode("header"))).unwrap();
        let transactions = raw["transactions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| {
                read_transaction(&mut VlqReader::new(
                    &hex::decode(value.as_str().unwrap()).unwrap(),
                ))
                .unwrap()
            })
            .collect();
        Self {
            raw,
            boxes,
            transactions,
            header,
        }
    }

    fn context(&self, wrong_key: bool) -> TransactionContext {
        TransactionContext {
            height: self.raw["height"].as_u64().unwrap() as u32,
            miner_pubkey: hex::decode(
                self.raw[if wrong_key {
                    "wrong_miner_pk"
                } else {
                    "miner_pk"
                }]
                .as_str()
                .unwrap(),
            )
            .unwrap()
            .try_into()
            .unwrap(),
            pre_header_timestamp: 0,
            activated_script_version: 2,
            pre_header_version: 3,
            pre_header_parent_id: [0; 32],
            pre_header_n_bits: 0,
            pre_header_votes: [0; 3],
        }
    }

    fn select(&self, txs: &[Transaction], wrong_key: bool, cost: u64, size: u64) -> Selected {
        let ctx = self.context(wrong_key);
        select_prioritized_txs_cancellable(
            &mut CandidateOverlay::new(self),
            txs,
            &ctx,
            &ProtocolParams::mainnet_default(),
            &[],
            cost,
            size,
            None,
            &|| false,
        )
        .unwrap()
    }
}

impl UtxoView for Fixture {
    fn get_box(&self, id: &Digest32) -> Option<ErgoBox> {
        self.boxes
            .iter()
            .find(|b| b.box_id().unwrap() == *id)
            .cloned()
    }
}

fn serialized_size(tx: &Transaction) -> u64 {
    let mut writer = VlqWriter::new();
    write_transaction(&mut writer, tx).unwrap();
    writer.result().len() as u64
}

fn selected_ids(selected: &Selected) -> Vec<[u8; 32]> {
    selected
        .checked
        .iter()
        .map(|(checked, _)| *checked.tx_id())
        .collect()
}

// ----- happy path -----

#[test]
fn requested_signed_zero_fee_chain_preserves_order_and_skips_conflict() {
    let fixture = Fixture::load();
    let selected = fixture.select(&fixture.transactions, false, u64::MAX, u64::MAX);
    let expected: Vec<_> = [0, 1, 3]
        .map(|index| {
            *transaction_id(&fixture.transactions[index])
                .unwrap()
                .as_bytes()
        })
        .to_vec();
    assert_eq!(selected_ids(&selected), expected);
    assert_eq!(selected.total_fee, 0);
    assert!(selected.suspects.is_empty());
    assert_eq!(
        selected.checked[0].1,
        fixture.raw["parent_matching_key"]["cost"].as_u64().unwrap()
    );
    assert_eq!(
        selected.checked[1].1,
        fixture.raw["child"]["cost"].as_u64().unwrap()
    );
}

// ----- error paths -----

#[test]
fn requested_wrong_miner_key_rejects_genesis_and_descendant() {
    let fixture = Fixture::load();
    assert_eq!(fixture.raw["parent_wrong_key"]["accept"], false);
    let selected = fixture.select(&fixture.transactions, true, u64::MAX, u64::MAX);
    assert_eq!(
        selected_ids(&selected),
        vec![*transaction_id(&fixture.transactions[3]).unwrap().as_bytes()]
    );
}

#[test]
fn requested_bad_signature_rejects_genesis_and_descendant() {
    let fixture = Fixture::load();
    assert_eq!(fixture.raw["parent_bad_signature"]["accept"], false);
    let mut txs = fixture.transactions[..2].to_vec();
    txs[0] = read_transaction(&mut VlqReader::new(
        &hex::decode(fixture.raw["bad_signature_transaction"].as_str().unwrap()).unwrap(),
    ))
    .unwrap();
    assert!(fixture
        .select(&txs, false, u64::MAX, u64::MAX)
        .checked
        .is_empty());
}

#[test]
fn requested_missing_input_rejects_genesis_and_descendant() {
    let fixture = Fixture::load();
    let mut txs = fixture.transactions[..2].to_vec();
    txs[0].inputs[0].box_id = Digest32::from_bytes([0xff; 32]);
    assert!(fixture
        .select(&txs, false, u64::MAX, u64::MAX)
        .checked
        .is_empty());
}

#[test]
fn requested_oversized_parent_excludes_its_child() {
    let fixture = Fixture::load();
    assert!(fixture
        .select(
            &fixture.transactions[..2],
            false,
            u64::MAX,
            serialized_size(&fixture.transactions[0]) - 1
        )
        .checked
        .is_empty());
}

#[test]
fn requested_cost_budget_keeps_parent_and_excludes_child() {
    let fixture = Fixture::load();
    let cost = fixture.raw["parent_matching_key"]["cost"].as_u64().unwrap();
    let selected = fixture.select(&fixture.transactions[..2], false, cost, u64::MAX);
    assert_eq!(selected.checked.len(), 1);
    assert_eq!(selected.total_cost, cost);
}

#[test]
fn requested_child_before_parent_is_skipped_without_reordering() {
    let fixture = Fixture::load();
    let selected = fixture.select(
        &[
            fixture.transactions[1].clone(),
            fixture.transactions[0].clone(),
        ],
        false,
        u64::MAX,
        u64::MAX,
    );
    assert_eq!(
        selected_ids(&selected),
        vec![*transaction_id(&fixture.transactions[0]).unwrap().as_bytes()]
    );
}

// ----- oracle parity -----

#[test]
fn upcoming_proof_scala_v2_witness_tree_and_preimage_match() {
    let fixture = Fixture::load();
    let txs = [0, 1, 3].map(|i| fixture.transactions[i].clone());
    let proof = upcoming_transactions_proof(&fixture.header, &txs, &txs)
        .unwrap()
        .unwrap();
    assert_eq!(
        hex::encode(proof.msg_preimage),
        fixture.raw["proof"]["msgPreimage"].as_str().unwrap()
    );
    let actual: Vec<_> = proof
        .tx_proofs
        .iter()
        .map(|tx| {
            serde_json::json!({
                "leaf": hex::encode(tx.leaf),
                "levels": tx.levels.iter().map(hex::encode).collect::<Vec<_>>()
            })
        })
        .collect();
    assert_eq!(
        actual,
        *fixture.raw["proof"]["txProofs"].as_array().unwrap()
    );
}

#[test]
fn upcoming_proof_only_included_requested_transactions_are_proven() {
    let fixture = Fixture::load();
    let txs = [0, 1, 3].map(|i| fixture.transactions[i].clone());
    let proof = upcoming_transactions_proof(
        &fixture.header,
        &txs,
        &[
            fixture.transactions[2].clone(),
            fixture.transactions[0].clone(),
        ],
    )
    .unwrap()
    .unwrap();
    assert_eq!(proof.tx_proofs.len(), 1);
    assert_eq!(
        hex::encode(proof.tx_proofs[0].leaf),
        fixture.raw["proof"]["txProofs"][0]["leaf"]
            .as_str()
            .unwrap()
    );
    assert!(upcoming_transactions_proof(&fixture.header, &txs, &[])
        .unwrap()
        .is_none());
}

#[test]
fn upcoming_proof_mainnet_v1_single_leaf_padding_matches_scala_capture() {
    let headers: Value = serde_json::from_str(include_str!(
        "../../../test-vectors/mainnet/headers_1_2000.json"
    ))
    .unwrap();
    let blocks: Value = serde_json::from_str(include_str!(
        "../../../test-vectors/mainnet/blocks_1_5.json"
    ))
    .unwrap();
    let header = &headers.as_array().unwrap()[0];
    let block = &blocks.as_array().unwrap()[0];
    let parsed_header = read_header(&mut VlqReader::new(
        &hex::decode(header["bytes"].as_str().unwrap()).unwrap(),
    ))
    .unwrap();
    let tx = read_transaction(&mut VlqReader::new(
        &hex::decode(block["transactions"][0]["bytes"].as_str().unwrap()).unwrap(),
    ))
    .unwrap();
    let proof = upcoming_transactions_proof(
        &parsed_header,
        std::slice::from_ref(&tx),
        std::slice::from_ref(&tx),
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        hex::encode(proof.msg_preimage),
        header["headerWithoutPow"].as_str().unwrap()
    );
    let captured: Value = serde_json::from_str(include_str!("../../../test-vectors/mainnet/proof_for_tx/h1_4c6282be413c6e300a530618b37790be5f286ded758accc2aebd41554a1be308.json")).unwrap();
    assert_eq!(
        hex::encode(proof.tx_proofs[0].leaf),
        captured["leafData"].as_str().unwrap()
    );
    let encoded: Vec<_> = captured["levels"]
        .as_array()
        .unwrap()
        .iter()
        .map(|level| {
            let mut bytes = vec![level[1].as_u64().unwrap() as u8];
            bytes.extend(hex::decode(level[0].as_str().unwrap()).unwrap());
            bytes
        })
        .collect();
    assert_eq!(proof.tx_proofs[0].levels, encoded);
}
