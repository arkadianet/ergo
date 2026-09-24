//! Scala-anchored vectors for the input-block message codecs (codes
//! 100/102/104/105/106), sourced from `test-vectors/weak-blocks/`.
//! Expected bytes/ids come from `scripts/jvm_weak_blocks_oracle` (never
//! computed by this crate — see CLAUDE.md's oracle-parity rule).

use std::path::{Path, PathBuf};

use ergo_p2p::message::{
    deserialize_input_block, deserialize_input_block_tx_ids, deserialize_input_block_txs,
    deserialize_input_block_txs_request, deserialize_ordering_block_announcement_msg,
    serialize_input_block_tx_ids, serialize_input_block_txs, serialize_input_block_txs_request,
    MessageError, CODE_INPUT_BLOCK_TXS, CODE_INPUT_BLOCK_TXS_REQUEST, CODE_INPUT_BLOCK_TX_IDS,
    INPUT_BLOCK_MESSAGE_MAX_SIZE,
};
use serde::Deserialize;

// ----- helpers -----

fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("test-vectors")
        .join("weak-blocks")
}

fn load<T: for<'de> Deserialize<'de>>(name: &str) -> T {
    let path = vectors_dir().join(format!("{name}.json"));
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

fn hex(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap_or_else(|e| panic!("hex-decode {s}: {e}"))
}

fn id32(s: &str) -> [u8; 32] {
    let bytes = hex(s);
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

#[derive(Deserialize)]
struct MessagesDoc {
    cases: Vec<MessageCase>,
    reject_cases: Vec<RejectCase>,
}

#[derive(Deserialize)]
struct MessageCase {
    name: String,
    code: u8,
    bytes_hex: String,
    input_block_id: String,
    #[serde(default)]
    weak_ids: Option<Vec<String>>,
    #[serde(default)]
    tx_hex: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct RejectCase {
    name: String,
    code: u8,
    bytes_hex: String,
    jvm: String,
}

#[derive(Deserialize)]
struct AnnouncementDoc {
    cases: Vec<AnnouncementCase>,
}

#[derive(Deserialize)]
struct AnnouncementCase {
    name: String,
    bytes_hex: String,
}

#[derive(Deserialize)]
struct OrderingDoc {
    cases: Vec<OrderingCase>,
}

#[derive(Deserialize)]
struct OrderingCase {
    name: String,
    bytes_hex: String,
}

// ----- oracle parity -----

#[test]
fn input_block_tx_ids_txs_and_txs_request_vectors_roundtrip_byte_exact() {
    let doc: MessagesDoc = load("messages");
    for case in &doc.cases {
        let bytes = hex(&case.bytes_hex);
        let expected_id = id32(&case.input_block_id);
        match case.code {
            CODE_INPUT_BLOCK_TX_IDS => {
                let d = deserialize_input_block_tx_ids(&bytes)
                    .unwrap_or_else(|e| panic!("{}: {e}", case.name));
                assert_eq!(d.input_block_id, expected_id, "{}", case.name);
                let expected_weak = case.weak_ids.as_ref().expect("weak_ids");
                assert_eq!(
                    d.weak_ids.iter().map(hex::encode).collect::<Vec<_>>(),
                    *expected_weak,
                    "{}",
                    case.name
                );
                assert_eq!(
                    serialize_input_block_tx_ids(&d),
                    bytes,
                    "{} re-serialize",
                    case.name
                );
            }
            CODE_INPUT_BLOCK_TXS_REQUEST => {
                let d = deserialize_input_block_txs_request(&bytes)
                    .unwrap_or_else(|e| panic!("{}: {e}", case.name));
                assert_eq!(d.input_block_id, expected_id, "{}", case.name);
                let expected_weak = case.weak_ids.as_ref().expect("weak_ids");
                assert_eq!(
                    d.weak_ids.iter().map(hex::encode).collect::<Vec<_>>(),
                    *expected_weak,
                    "{}",
                    case.name
                );
                assert_eq!(
                    serialize_input_block_txs_request(&d),
                    bytes,
                    "{} re-serialize",
                    case.name
                );
            }
            CODE_INPUT_BLOCK_TXS => {
                let d = deserialize_input_block_txs(&bytes)
                    .unwrap_or_else(|e| panic!("{}: {e}", case.name));
                assert_eq!(d.input_block_id, expected_id, "{}", case.name);
                let expected_tx = case.tx_hex.as_ref().expect("tx_hex");
                assert_eq!(d.transactions.len(), expected_tx.len(), "{}", case.name);
                for (tx, expected) in d.transactions.iter().zip(expected_tx) {
                    let reserialized = {
                        let mut w = ergo_primitives::writer::VlqWriter::new();
                        ergo_ser::transaction::write_transaction(&mut w, tx).unwrap();
                        w.result()
                    };
                    assert_eq!(hex::encode(reserialized), *expected, "{}", case.name);
                }
                assert_eq!(
                    serialize_input_block_txs(&d).unwrap(),
                    bytes,
                    "{} re-serialize",
                    case.name
                );
            }
            other => panic!("{}: unexpected code {other}", case.name),
        }
    }

    for r in &doc.reject_cases {
        assert_eq!(r.jvm, "Reject", "{}", r.name);
        let bytes = hex(&r.bytes_hex);
        let result: Result<(), MessageError> = match r.code {
            CODE_INPUT_BLOCK_TX_IDS => deserialize_input_block_tx_ids(&bytes).map(|_| ()),
            CODE_INPUT_BLOCK_TXS_REQUEST => deserialize_input_block_txs_request(&bytes).map(|_| ()),
            CODE_INPUT_BLOCK_TXS => deserialize_input_block_txs(&bytes).map(|_| ()),
            other => panic!("{}: unexpected code {other}", r.name),
        };
        assert!(result.is_err(), "{}", r.name);
    }
}

#[test]
fn deserialize_input_block_accepts_every_announcement_vector() {
    let doc: AnnouncementDoc = load("announcement");
    for case in &doc.cases {
        let bytes = hex(&case.bytes_hex);
        deserialize_input_block(&bytes).unwrap_or_else(|e| panic!("{}: {e}", case.name));
    }
}

#[test]
fn deserialize_ordering_block_announcement_msg_accepts_every_ordering_vector() {
    let doc: OrderingDoc = load("ordering_announcement");
    for case in &doc.cases {
        let bytes = hex(&case.bytes_hex);
        deserialize_ordering_block_announcement_msg(&bytes)
            .unwrap_or_else(|e| panic!("{}: {e}", case.name));
    }
}

// ----- error paths -----

#[test]
fn input_block_payload_at_max_size_rejected_before_parsing() {
    // A zero-filled buffer is not itself a valid announcement, but the
    // size gate must reject it before the parser ever runs — assert the
    // specific `PayloadTooLarge` variant, not just "any error", so this
    // doesn't silently degrade into testing the parser's own rejection.
    let payload = vec![0u8; INPUT_BLOCK_MESSAGE_MAX_SIZE];
    let err = deserialize_input_block(&payload).unwrap_err();
    assert!(matches!(
        err,
        MessageError::PayloadTooLarge(INPUT_BLOCK_MESSAGE_MAX_SIZE)
    ));
}
