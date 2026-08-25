//! CONTEXT.headers window parity — mainnet incident 1,853,462–1,853,480
//! (2026-08-17/18).
//!
//! Scala exposes **9** headers to `CONTEXT.headers` while validating a
//! block (`ErgoStateContext.process` → `sigmaLastHeaders =
//! lastHeaders.drop(1)`), and 10 on the candidate/mempool surface
//! (`UpcomingStateContext`, whole `lastHeaders`). This node used to feed
//! all 10 into block-validation script eval, so scripts indexing
//! `CONTEXT.headers(9)` reduced here but threw
//! `ArrayIndexOutOfBoundsException` on the JVM: 15 poisoned blocks were
//! applied and later reorged away.
//!
//! Oracle vectors: `test-vectors/mainnet/context_headers_1853478/`
//! (see its README for provenance). Per the README's ADProofs caveat the
//! reject vectors are driven through the tx/script layer against the
//! supplied spent boxes — sufficient because the divergence is in script
//! evaluation, before any AVL digest check.

use std::collections::HashMap;

use ergo_primitives::digest::{Digest32, ModifierId};
use ergo_primitives::reader::VlqReader;
use ergo_rest_json::{
    decode_header_json, decode_scala_transaction, ScalaOutputInput, ScalaTransactionInput,
};
use ergo_ser::ergo_box::ErgoBox;
use ergo_ser::header::Header;
use ergo_ser::transaction::{read_transaction, transaction_id};
use ergo_validation::context::{LocalPolicy, ProtocolParams, TransactionContext};
use ergo_validation::cost::CostAccumulator;
use ergo_validation::error::ValidationError;
use ergo_validation::tx::validate_transaction;
use ergo_validation::UtxoView;

const VECTOR_DIR: &str = "../test-vectors/mainnet/context_headers_1853478";

struct TestUtxo(HashMap<Digest32, ErgoBox>);

impl UtxoView for TestUtxo {
    fn get_box(&self, box_id: &Digest32) -> Option<ErgoBox> {
        self.0.get(box_id).cloned()
    }
}

fn read_vector(name: &str) -> serde_json::Value {
    let path = format!("{VECTOR_DIR}/{name}");
    let data = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("missing oracle vector {path}: {e}"));
    serde_json::from_str(&data).unwrap()
}

fn load_ancestor_headers() -> Vec<Header> {
    let raw = read_vector("ancestor_headers_tip_first.json");
    let arr = raw.as_array().expect("ancestors array");
    arr.iter()
        .map(|h| decode_header_json(&h.to_string()).expect("ancestor header decodes"))
        .collect()
}

fn load_spent_boxes() -> HashMap<Digest32, ErgoBox> {
    let raw = read_vector("spent_input_boxes.json");
    let arr = raw.as_array().expect("spent boxes array");
    let mut map = HashMap::new();
    for b in arr {
        let output = ScalaOutputInput {
            value: b["value"].as_u64().unwrap(),
            ergo_tree: b["ergoTree"].as_str().unwrap().to_string(),
            assets: serde_json::from_value(b["assets"].clone()).unwrap(),
            creation_height: b["creationHeight"].as_u64().unwrap() as u32,
            additional_registers: serde_json::from_value(b["additionalRegisters"].clone())
                .unwrap_or_default(),
        };
        let candidate = ergo_rest_json::decode::decode_output(&output).expect("box decodes");
        let tx_id_bytes: [u8; 32] = hex::decode(b["transactionId"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let box_id_bytes: [u8; 32] = hex::decode(b["boxId"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        map.insert(
            Digest32::from_bytes(box_id_bytes),
            ErgoBox {
                candidate,
                transaction_id: ModifierId::from_bytes(tx_id_bytes),
                index: b["index"].as_u64().unwrap() as u16,
            },
        );
    }
    map
}

/// Load the poison transaction as canonical wire bytes plus its claimed id.
fn load_poison_tx() -> (Vec<u8>, String) {
    let raw = read_vector("tx_b44970ed.json");
    let id = raw["id"].as_str().unwrap().to_lowercase();
    let input: ScalaTransactionInput = serde_json::from_value(raw).expect("Scala tx JSON");
    let bytes = decode_scala_transaction(&input).expect("poison tx canonicalizes");
    (bytes, id)
}

/// The Scala node's own context dump while rejecting `3a011457…` at
/// 1,853,462 pins the rule directly: 9 headers, tip-first H-1 … H-9.
#[test]
fn scala_verification_context_exposes_nine_headers() {
    let ctx = read_vector("scala_verification_context.json");
    let headers = ctx["headers"].as_array().expect("headers array");
    assert_eq!(
        headers.len(),
        9,
        "Scala block-validation context must hold 9 headers"
    );

    let pre_height = ctx["preHeader"]["height"].as_u64().unwrap();
    let heights: Vec<u64> = headers
        .iter()
        .map(|h| h["height"].as_u64().unwrap())
        .collect();
    let expected: Vec<u64> = (1..=9).map(|i| pre_height - i).collect();
    assert_eq!(heights, expected, "tip-first H-1..H-9 expected");
}

/// The live poison transaction: with the spurious 10th header visible the
/// script reduces and the proof verifies (the historical accept path);
/// with the correct 9-header window `CONTEXT.headers(9)` fails reduction
/// and the tx is rejected — matching the JVM verdict on every block that
/// carried it.
#[test]
fn poison_tx_rejected_with_nine_window_accepted_with_ten() {
    let ancestors = load_ancestor_headers();
    assert_eq!(
        ancestors.len(),
        10,
        "fixture holds 10 ancestors of cb0df53b…"
    );
    // Sanity: tip-first from 1,853,477 down to 1,853,468 (README).
    for (i, h) in ancestors.iter().enumerate() {
        assert_eq!(h.height, 1853477 - i as u32, "ancestor[{i}] height");
    }

    let utxo_view = TestUtxo(load_spent_boxes());

    // Pre-header fields from the reject block cb0df53b… itself (its header
    // is what Scala's preHeader carried while rejecting it).
    let block = read_vector("block_reject_cb0df53b.json");
    let block_header = decode_header_json(&block["header"].to_string()).expect("block header");
    let height = block_header.height;
    assert_eq!(height, 1_853_478);

    let tx_ctx = TransactionContext {
        height,
        miner_pubkey: *block_header.solution.pk().as_bytes(),
        pre_header_timestamp: block_header.timestamp,
        activated_script_version: block_header.version.saturating_sub(1),
        pre_header_version: block_header.version,
        pre_header_parent_id: *block_header.parent_id.as_bytes(),
        pre_header_n_bits: block_header.n_bits as u64,
        pre_header_votes: block_header.votes,
    };

    let (tx_bytes, tx_id_hex) = load_poison_tx();

    // Wire bytes must round-trip to the claimed poison id.
    let mut r = VlqReader::new(&tx_bytes);
    let parsed = read_transaction(&mut r).expect("poison tx parses");
    let parsed_id = transaction_id(&parsed).expect("bytes_to_sign");
    assert_eq!(
        hex::encode(parsed_id.as_bytes()),
        tx_id_hex,
        "canonicalized poison tx id mismatch"
    );
    // Input #0 spends a18124cb… (creationHeight 1,853,457 per README).
    let spend_box_hex = hex::encode(parsed.inputs[0].box_id.as_bytes());
    assert!(utxo_view.0.contains_key(&parsed.inputs[0].box_id));
    assert_eq!(&spend_box_hex[..12], "a18124cba8e7");

    let params = ProtocolParams::mainnet_default();
    let policy = LocalPolicy::default_policy();

    // Historical (buggy) behavior: full 10-entry window → script reduces,
    // proof verifies, tx validates. This documents exactly why the node
    // accepted 15 poisoned blocks; do not "fix" this assertion away.
    {
        let mut cost = CostAccumulator::recording_only();
        let mut cx10 = ergo_validation::TxValidationCtx {
            ctx: &tx_ctx,
            params: &params,
            cost: &mut cost,
            last_headers: &ancestors,
            rules: ergo_validation::TxValidationRules::default(),
        };
        let result = validate_transaction(&tx_bytes, &utxo_view, &policy, &mut cx10);
        assert!(
            result.is_ok(),
            "poison tx must verify under the legacy 10-entry window (documents the bug), got {:?}",
            result.err()
        );
    }

    // Correct Scala-parity window: first 9 only → `headers(9)` cannot
    // resolve, reduction fails, tx rejected.
    {
        let mut cost = CostAccumulator::recording_only();
        let mut cx9 = ergo_validation::TxValidationCtx {
            ctx: &tx_ctx,
            params: &params,
            cost: &mut cost,
            last_headers: &ancestors[..9],
            rules: ergo_validation::TxValidationRules::default(),
        };
        let result = validate_transaction(&tx_bytes, &utxo_view, &policy, &mut cx9);
        let err = result.expect_err("poison tx MUST be rejected under the 9-entry window");
        assert!(
            matches!(
                &err,
                ValidationError::ScriptError { index: 0, .. }
                    | ValidationError::ProofFailed { index: 0 }
            ),
            "expected script-layer failure on input #0 under 9-window, got {err:?}"
        );
    }
}
