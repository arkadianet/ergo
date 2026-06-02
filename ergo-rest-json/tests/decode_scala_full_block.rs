//! Coverage for `decode_scala_full_block` — the §12 step (a)
//! composition that drives `POST /blocks` body decoding.
//!
//! Focused on the boundary-consistency check: every block section
//! carries the header_id it claims to belong to. A mismatched
//! section in one body is a sign of a malformed (or adversarial)
//! submission; reject at the JSON boundary.

use ergo_rest_json::decode_scala_full_block;
use ergo_rest_json::types::{
    ScalaAdProofs, ScalaBlockTransactions, ScalaExtension, ScalaFullBlock, ScalaHeader,
    ScalaPowSolutions,
};
use serde_json::Value as JsonValue;

fn make_minimal_header() -> ScalaHeader {
    ScalaHeader {
        extension_id: String::new(),
        difficulty: "1".to_string(),
        votes: "000000".to_string(),
        timestamp: 1_550_000_000_000,
        size: 0,
        unparsed_bytes: String::new(),
        // 33 bytes
        state_root: "00".repeat(33),
        height: 1,
        n_bits: 0x011765,
        version: 2,
        id: String::new(),
        ad_proofs_root: "00".repeat(32),
        transactions_root: "00".repeat(32),
        extension_hash: "00".repeat(32),
        pow_solutions: ScalaPowSolutions {
            pk: "02".to_string() + &"00".repeat(32),
            w: "00".repeat(33),
            n: "00".repeat(8),
            d: JsonValue::Number(0u32.into()),
        },
        ad_proofs_id: String::new(),
        transactions_id: String::new(),
        parent_id: "00".repeat(32),
    }
}

fn make_full_block_with_section_ids(
    header: ScalaHeader,
    bt_header_id: String,
    ext_header_id: String,
    ad_header_id: Option<String>,
) -> ScalaFullBlock {
    ScalaFullBlock {
        header,
        block_transactions: ScalaBlockTransactions {
            header_id: bt_header_id,
            transactions: vec![],
            block_version: 2,
            size: 0,
        },
        extension: ScalaExtension {
            header_id: ext_header_id,
            digest: "00".repeat(32),
            fields: vec![],
        },
        ad_proofs: ad_header_id.map(|hid| ScalaAdProofs {
            header_id: hid,
            proof_bytes: String::new(),
            digest: "00".repeat(32),
            size: 0,
        }),
        size: 0,
    }
}

/// Happy path: section header_ids match the decoded header id.
#[test]
fn decode_scala_full_block_accepts_matching_section_ids() {
    let h = make_minimal_header();
    let (_h_bytes, h_id) = ergo_rest_json::decode_scala_header(&h).unwrap();
    let id_hex = hex::encode(h_id.as_bytes());

    let body = make_full_block_with_section_ids(h, id_hex.clone(), id_hex.clone(), Some(id_hex));
    decode_scala_full_block(&body).expect("matching section ids must decode");
}

#[test]
fn decode_scala_full_block_rejects_mismatched_block_transactions_header_id() {
    let h = make_minimal_header();
    let (_h_bytes, h_id) = ergo_rest_json::decode_scala_header(&h).unwrap();
    let id_hex = hex::encode(h_id.as_bytes());
    let bogus = "ff".repeat(32);

    let body = make_full_block_with_section_ids(h, bogus, id_hex.clone(), Some(id_hex));
    let err = decode_scala_full_block(&body).unwrap_err();
    assert_eq!(err.0, "deserialize");
    assert!(
        err.1.contains("blockTransactions.headerId"),
        "unexpected detail: {}",
        err.1
    );
}

#[test]
fn decode_scala_full_block_rejects_mismatched_extension_header_id() {
    let h = make_minimal_header();
    let (_h_bytes, h_id) = ergo_rest_json::decode_scala_header(&h).unwrap();
    let id_hex = hex::encode(h_id.as_bytes());
    let bogus = "ee".repeat(32);

    let body = make_full_block_with_section_ids(h, id_hex.clone(), bogus, Some(id_hex));
    let err = decode_scala_full_block(&body).unwrap_err();
    assert!(
        err.1.contains("extension.headerId"),
        "unexpected detail: {}",
        err.1
    );
}

#[test]
fn decode_scala_full_block_rejects_mismatched_ad_proofs_header_id() {
    let h = make_minimal_header();
    let (_h_bytes, h_id) = ergo_rest_json::decode_scala_header(&h).unwrap();
    let id_hex = hex::encode(h_id.as_bytes());
    let bogus = "dd".repeat(32);

    let body = make_full_block_with_section_ids(h, id_hex.clone(), id_hex, Some(bogus));
    let err = decode_scala_full_block(&body).unwrap_err();
    assert!(
        err.1.contains("adProofs.headerId"),
        "unexpected detail: {}",
        err.1
    );
}

#[test]
fn decode_scala_full_block_accepts_case_insensitive_hex() {
    // Scala's lowercase emission is a convention; the JSON
    // shape itself accepts either case. The boundary check
    // should compare case-insensitively (matches Scala's
    // `Base16.decode` which is case-insensitive).
    let h = make_minimal_header();
    let (_h_bytes, h_id) = ergo_rest_json::decode_scala_header(&h).unwrap();
    let id_lower = hex::encode(h_id.as_bytes());
    let id_upper = id_lower.to_uppercase();

    let body = make_full_block_with_section_ids(h, id_upper, id_lower.clone(), Some(id_lower));
    decode_scala_full_block(&body).expect("case-insensitive id match must decode");
}

#[test]
fn decode_scala_full_block_ad_proofs_absent_decodes_ok() {
    // Mode 5 / digest-mode blocks may not carry ad_proofs at all
    // (the Option<ScalaAdProofs> is None). Boundary check should
    // skip the ad-proofs branch entirely.
    let h = make_minimal_header();
    let (_h_bytes, h_id) = ergo_rest_json::decode_scala_header(&h).unwrap();
    let id_hex = hex::encode(h_id.as_bytes());

    let body = make_full_block_with_section_ids(h, id_hex.clone(), id_hex, None);
    let decoded = decode_scala_full_block(&body).expect("ad_proofs absent must decode");
    assert!(decoded.ad_proofs_bytes.is_none());
}
