//! Scala-anchored vectors for the input-block wire objects.
//! Expected bytes/ids come from `scripts/jvm_weak_blocks_oracle` (never from this crate).
use ergo_primitives::reader::VlqReader;
use ergo_ser::input_block::*;
use ergo_ser::transaction::{read_transaction, transaction_id};
use ergo_ser::weak_id::{weak_id_of, witness_id};
use serde::Deserialize;

fn load<T: for<'de> Deserialize<'de>>(name: &str) -> T {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../test-vectors/weak-blocks/");
    let text = std::fs::read_to_string(format!("{path}{name}.json")).expect("vector file");
    serde_json::from_str(&text).expect("vector json")
}
fn hex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("hex")
}

#[derive(Deserialize)]
struct AnnouncementDoc {
    cases: Vec<AnnouncementCase>,
    reject_cases: Vec<RejectCase>,
}
#[derive(Deserialize)]
struct AnnouncementCase {
    name: String,
    bytes_hex: String,
    id: String,
    header_hex: String,
    prev_input_block_id: Option<String>,
    transactions_digest: String,
    prev_transactions_digest: String,
    weak_tx_ids: Option<Vec<String>>,
}
#[derive(Deserialize)]
struct RejectCase {
    name: String,
    bytes_hex: String,
    jvm: String,
}

#[test]
fn input_block_announcement_vectors_roundtrip_byte_exact() {
    let doc: AnnouncementDoc = load("announcement");
    for case in &doc.cases {
        let bytes = hex(&case.bytes_hex);
        let ann =
            parse_input_block_announcement(&bytes).unwrap_or_else(|e| panic!("{}: {e}", case.name));
        assert_eq!(
            hex::encode(ann.id().unwrap().as_bytes()),
            case.id,
            "{}",
            case.name
        );
        assert_eq!(
            ann.fields.prev_input_block_id.map(hex::encode),
            case.prev_input_block_id,
            "{}",
            case.name
        );
        assert_eq!(
            hex::encode(ann.fields.transactions_digest),
            case.transactions_digest,
            "{}",
            case.name
        );
        assert_eq!(
            hex::encode(ann.fields.prev_transactions_digest),
            case.prev_transactions_digest,
            "{}",
            case.name
        );
        assert_eq!(
            ann.weak_tx_ids
                .as_ref()
                .map(|v| v.iter().map(hex::encode).collect::<Vec<_>>()),
            case.weak_tx_ids,
            "{}",
            case.name
        );
        assert_eq!(
            serialize_input_block_announcement(&ann).unwrap(),
            bytes,
            "{} re-serialize",
            case.name
        );
        let _ = hex(&case.header_hex);
    }
    for r in &doc.reject_cases {
        assert_eq!(r.jvm, "Reject", "{}", r.name);
        assert!(
            parse_input_block_announcement(&hex(&r.bytes_hex)).is_err(),
            "{}",
            r.name
        );
    }
}

#[derive(Deserialize)]
struct OrderingDoc {
    cases: Vec<OrderingCase>,
    reject_cases: Vec<RejectCase>,
}
#[derive(Deserialize)]
struct OrderingCase {
    name: String,
    bytes_hex: String,
    header_id: String,
    non_broadcasted_tx_hex: Vec<String>,
    broadcasted_ids: Vec<String>,
    unparsed_hex: String,
}

#[test]
fn ordering_block_announcement_vectors_roundtrip_byte_exact() {
    let doc: OrderingDoc = load("ordering_announcement");
    for case in &doc.cases {
        let bytes = hex(&case.bytes_hex);
        let ann = parse_ordering_block_announcement(&bytes)
            .unwrap_or_else(|e| panic!("{}: {e}", case.name));
        let (_, hid) = ergo_ser::header::serialize_header(&ann.header).unwrap();
        assert_eq!(hex::encode(hid.as_bytes()), case.header_id, "{}", case.name);
        assert_eq!(
            ann.non_broadcasted_transactions.len(),
            case.non_broadcasted_tx_hex.len(),
            "{}",
            case.name
        );
        assert_eq!(
            ann.broadcasted_transaction_ids
                .iter()
                .map(hex::encode)
                .collect::<Vec<_>>(),
            case.broadcasted_ids,
            "{}",
            case.name
        );
        assert_eq!(
            hex::encode(&ann.unparsed_bytes),
            case.unparsed_hex,
            "{}",
            case.name
        );
        assert_eq!(
            serialize_ordering_block_announcement(&ann).unwrap(),
            bytes,
            "{} re-serialize",
            case.name
        );
    }
    for r in &doc.reject_cases {
        assert_eq!(r.jvm, "Reject", "{}", r.name);
        assert!(
            parse_ordering_block_announcement(&hex(&r.bytes_hex)).is_err(),
            "{}",
            r.name
        );
    }
}

#[derive(Deserialize)]
struct WeakDoc {
    cases: Vec<WeakCase>,
}
#[derive(Deserialize)]
struct WeakCase {
    name: String,
    tx_hex: String,
    tx_id: String,
    witness_id: String,
    weak_id: String,
}

#[test]
fn weak_ids_match_scala_for_witness_variants() {
    let doc: WeakDoc = load("weak_ids");
    for case in &doc.cases {
        let tx_bytes = hex(&case.tx_hex);
        let mut r = VlqReader::new(&tx_bytes);
        let tx = read_transaction(&mut r).unwrap();
        assert_eq!(
            hex::encode(transaction_id(&tx).unwrap().as_bytes()),
            case.tx_id,
            "{}",
            case.name
        );
        assert_eq!(
            hex::encode(witness_id(&tx)),
            case.witness_id,
            "{}",
            case.name
        );
        assert_eq!(
            hex::encode(weak_id_of(&tx).unwrap()),
            case.weak_id,
            "{}",
            case.name
        );
    }
    let tx1 = doc.cases.iter().find(|c| c.name == "tx1").unwrap();
    let other = doc
        .cases
        .iter()
        .find(|c| c.name == "tx1_other_witness")
        .unwrap();
    assert_eq!(tx1.tx_id, other.tx_id);
    assert_ne!(tx1.weak_id, other.weak_id);
}
