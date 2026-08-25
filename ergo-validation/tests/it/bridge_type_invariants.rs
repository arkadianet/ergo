//! Tests that EvalBox and EvalHeader conversions preserve all fields
//! from their source types. Catches representation drift between the
//! serialization layer (ergo-ser) and the evaluator bridge types (ergo-sigma).

use ergo_primitives::reader::VlqReader;
use ergo_ser::header::{read_header, serialize_header};
use ergo_sigma::evaluator::EvalHeader;
use serde::Deserialize;

#[derive(Deserialize)]
struct HeaderVector {
    height: u32,
    #[allow(dead_code)]
    id: String,
    bytes: String,
}

fn load_header_vectors(path: &str) -> Vec<HeaderVector> {
    let data =
        std::fs::read_to_string(path).unwrap_or_else(|e| panic!("failed to read {path}: {e}"));
    serde_json::from_str(&data).unwrap_or_else(|e| panic!("failed to parse {path}: {e}"))
}

// --- EvalHeader field preservation ---

#[test]
fn eval_header_preserves_all_v1_fields() {
    let vecs = load_header_vectors("../test-vectors/mainnet/headers_1_500.json");
    assert!(!vecs.is_empty());

    let v = &vecs[0]; // height 1, v1
    let bytes = hex::decode(&v.bytes).unwrap();
    let mut r = VlqReader::new(&bytes);
    let header = read_header(&mut r).unwrap();
    let (_, hid) = serialize_header(&header).expect("real mainnet header serializes");
    let header_id = *hid.as_bytes();

    assert_eq!(header.version, 1, "expected v1 header");
    let eval = EvalHeader::from_header(&header, header_id);

    // Identity fields
    assert_eq!(eval.id, header_id);
    assert_eq!(eval.version, header.version);
    assert_eq!(eval.height, header.height);
    assert_eq!(eval.timestamp, header.timestamp);
    assert_eq!(eval.n_bits, header.n_bits);
    assert_eq!(eval.votes, header.votes);

    // Digest fields
    assert_eq!(eval.parent_id, *header.parent_id.as_bytes());
    assert_eq!(eval.ad_proofs_root, *header.ad_proofs_root.as_bytes());
    assert_eq!(eval.state_root, *header.state_root.as_bytes());
    assert_eq!(eval.transactions_root, *header.transactions_root.as_bytes());
    assert_eq!(eval.extension_root, *header.extension_root.as_bytes());

    // Miner PK
    assert_eq!(eval.miner_pk, *header.solution.pk().as_bytes());

    // V1-specific: pow_onetime_pk = w, pow_distance = d
    match &header.solution {
        ergo_ser::autolykos::AutolykosSolution::V1 { w, d, .. } => {
            assert_eq!(&eval.pow_onetime_pk, w.as_bytes());
            // Compare via signed big-endian bytes (avoids num_bigint dep)
            assert_eq!(eval.pow_distance.to_signed_bytes_be(), *d);
        }
        _ => panic!("expected V1 solution"),
    }

    // Nonce
    assert_eq!(eval.pow_nonce, *header.solution.nonce());
}

#[test]
#[ignore = "needs gitignored headers_417792_419000.json — extract via test-vectors/scripts then run with --ignored"]
fn eval_header_preserves_all_v2_fields() {
    let vecs = load_header_vectors("../test-vectors/mainnet/headers_417792_419000.json");
    assert!(!vecs.is_empty());

    let v = &vecs[0]; // first v2 header
    let bytes = hex::decode(&v.bytes).unwrap();
    let mut r = VlqReader::new(&bytes);
    let header = read_header(&mut r).unwrap();
    let (_, hid) = serialize_header(&header).expect("real mainnet header serializes");
    let header_id = *hid.as_bytes();

    assert!(header.version >= 2, "expected v2+ header");
    let eval = EvalHeader::from_header(&header, header_id);

    // All standard fields
    assert_eq!(eval.id, header_id);
    assert_eq!(eval.version, header.version);
    assert_eq!(eval.height, header.height);
    assert_eq!(eval.parent_id, *header.parent_id.as_bytes());
    assert_eq!(eval.transactions_root, *header.transactions_root.as_bytes());
    assert_eq!(eval.miner_pk, *header.solution.pk().as_bytes());
    assert_eq!(eval.pow_nonce, *header.solution.nonce());

    // V2-specific: pow_onetime_pk = secp256k1 generator, pow_distance = 0
    let expected_generator: [u8; 33] = [
        0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87,
        0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16,
        0xF8, 0x17, 0x98,
    ];
    assert_eq!(eval.pow_onetime_pk, expected_generator);
    // V2 pow_distance is zero — verify via byte representation
    assert_eq!(
        eval.pow_distance.to_signed_bytes_be(),
        vec![0],
        "expected zero pow_distance for v2"
    );
}

#[test]
#[ignore = "needs gitignored headers_417792_419000.json (v2 source) — extract via test-vectors/scripts then run with --ignored"]
fn eval_header_batch_v1_v2_field_coverage() {
    // Verify field preservation across a batch of headers spanning v1 and v2.
    let v1_vecs = load_header_vectors("../test-vectors/mainnet/headers_1_500.json");
    let v2_vecs = load_header_vectors("../test-vectors/mainnet/headers_417792_419000.json");

    let mut checked = 0;
    for v in v1_vecs.iter().take(10).chain(v2_vecs.iter().take(10)) {
        let bytes = hex::decode(&v.bytes).unwrap();
        let mut r = VlqReader::new(&bytes);
        let header = read_header(&mut r).unwrap();
        let (_, hid) = serialize_header(&header).expect("real mainnet header serializes");
        let eval = EvalHeader::from_header(&header, *hid.as_bytes());

        // Core invariants that must hold for all headers
        assert_eq!(eval.id, *hid.as_bytes(), "id mismatch at h={}", v.height);
        assert_eq!(eval.height, header.height);
        assert_eq!(eval.version, header.version);
        assert_eq!(eval.miner_pk.len(), 33);
        assert_eq!(eval.pow_onetime_pk.len(), 33);
        assert_eq!(eval.pow_nonce.len(), 8);
        checked += 1;
    }
    eprintln!("bridge_type_invariants: {checked} headers verified");
    assert!(checked >= 20);
}

// --- EvalBox field preservation ---

use ergo_validation::test_helpers::{candidate_to_eval_box, ergo_box_to_eval_box};

#[test]
fn eval_box_preserves_fields_from_ergo_box() {
    // Load real mainnet boxes with raw serialized bytes
    let data = std::fs::read_to_string("../test-vectors/mainnet/boxes_recent.json").unwrap();
    let vectors: Vec<serde_json::Value> = serde_json::from_str(&data).unwrap();
    assert!(!vectors.is_empty(), "need at least one box vector");

    let mut checked = 0;
    for (i, v) in vectors.iter().enumerate() {
        let box_hex = v["bytes"].as_str().unwrap();
        let box_bytes = hex::decode(box_hex).unwrap();
        let mut r = VlqReader::new(&box_bytes);
        let ergo_box = ergo_ser::ergo_box::read_ergo_box(&mut r).unwrap();

        let eval_box = ergo_box_to_eval_box(&ergo_box, i).unwrap();

        // Value preservation
        assert_eq!(
            eval_box.value, ergo_box.candidate.value as i64,
            "value mismatch for box {i}"
        );

        // Creation height
        assert_eq!(
            eval_box.creation_height, ergo_box.candidate.creation_height,
            "creation_height mismatch for box {i}"
        );

        // Script bytes
        assert_eq!(
            eval_box.script_bytes,
            ergo_box.candidate.ergo_tree_bytes(),
            "script_bytes mismatch for box {i}"
        );

        // Token count
        assert_eq!(
            eval_box.tokens.len(),
            ergo_box.candidate.tokens.len(),
            "token count mismatch for box {i}"
        );

        // Token IDs and amounts
        for (j, token) in ergo_box.candidate.tokens.iter().enumerate() {
            assert_eq!(
                eval_box.tokens[j].0,
                *token.token_id.as_bytes(),
                "token {j} ID mismatch for box {i}"
            );
            assert_eq!(
                eval_box.tokens[j].1, token.amount,
                "token {j} amount mismatch for box {i}"
            );
        }

        // Register count (R4-R9)
        let src_reg_count = ergo_box.candidate.additional_registers.registers.len();
        let eval_reg_count = eval_box.registers.iter().filter(|r| r.is_some()).count();
        assert_eq!(
            eval_reg_count,
            src_reg_count.min(6),
            "register count mismatch for box {i}"
        );

        // Box ID (must be computable and match)
        let expected_id = ergo_box.box_id().unwrap();
        assert_eq!(
            eval_box.id,
            *expected_id.as_bytes(),
            "box ID mismatch for box {i}"
        );

        // Raw bytes (non-empty for real boxes)
        assert!(
            !eval_box.raw_bytes.is_empty(),
            "raw_bytes should be non-empty for box {i}"
        );

        checked += 1;
    }
    eprintln!("eval_box_field_preservation: {checked} boxes verified");
    assert!(checked >= 3);
}

#[test]
fn eval_box_candidate_conversion_preserves_fields() {
    // Verify candidate_to_eval_box for output candidates using real block data.
    let data = std::fs::read_to_string("../test-vectors/mainnet/blocks_1_5.json").unwrap();
    let blocks: Vec<serde_json::Value> = serde_json::from_str(&data).unwrap();

    let mut checked = 0;
    for block in blocks.iter().take(3) {
        let txs = block["transactions"].as_array().unwrap();
        for tx_val in txs {
            let tx_hex = tx_val["bytes"].as_str().unwrap();
            let tx_bytes = hex::decode(tx_hex).unwrap();
            let mut r = VlqReader::new(&tx_bytes);
            let tx = ergo_ser::transaction::read_transaction(&mut r).unwrap();
            let tx_id = ergo_ser::transaction::transaction_id(&tx).unwrap();

            for (i, candidate) in tx.output_candidates.iter().enumerate() {
                let eval_box = candidate_to_eval_box(candidate, &tx_id, i as u16).unwrap();

                assert_eq!(eval_box.value, candidate.value as i64);
                assert_eq!(eval_box.creation_height, candidate.creation_height);
                assert_eq!(eval_box.script_bytes, candidate.ergo_tree_bytes());
                assert_eq!(eval_box.tokens.len(), candidate.tokens.len());
                assert!(!eval_box.raw_bytes.is_empty());
                assert_ne!(eval_box.id, [0u8; 32], "box ID should be non-zero");
                checked += 1;
            }
        }
    }
    eprintln!("eval_box_candidate_conversion: {checked} output boxes verified");
    assert!(checked >= 3);
}
