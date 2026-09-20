//! Regression: header receive must enforce end-of-input, like the reload path
//! and the sibling receive sinks. A header delivered as `canonical ++ trailing`
//! must be rejected, not accepted under a raw-bytes id.

use ergo_sync::header_proc::pre_validate_header;

fn mainnet_header(height: u64) -> Vec<u8> {
    let raw = std::fs::read_to_string("../test-vectors/mainnet/headers_1_10.json")
        .expect("read headers_1_10.json");
    let v: Vec<serde_json::Value> = serde_json::from_str(&raw).expect("parse headers");
    let e = v
        .iter()
        .find(|e| e["height"].as_u64() == Some(height))
        .expect("height present");
    hex::decode(e["bytes"].as_str().expect("bytes hex")).expect("decode header bytes")
}

#[test]
fn header_receive_accepts_canonical_rejects_trailing() {
    let clean = mainnet_header(2);
    // A canonical mainnet header (with valid PoW) is accepted.
    assert!(
        pre_validate_header(&clean).is_ok(),
        "canonical header must be accepted"
    );

    // The same header with trailing bytes appended is rejected at parse.
    let mut trailing = clean.clone();
    trailing.extend_from_slice(&[0xAA, 0xBB]);
    let err = match pre_validate_header(&trailing) {
        Ok(_) => panic!("trailing-byte header must be rejected"),
        Err(e) => e,
    };
    assert!(
        format!("{err:?}").contains("trailing bytes"),
        "expected a trailing-bytes error, got: {err:?}"
    );
}
