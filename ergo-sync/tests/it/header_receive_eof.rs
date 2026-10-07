//! Standalone header receive uses the parsed header's canonical ID.
//! Received suffix bytes do not become a separate header identity.

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
fn header_receive_normalizes_trailing_bytes() {
    let clean = mainnet_header(2);
    // A canonical mainnet header (with valid PoW) is accepted.
    assert!(
        pre_validate_header(&clean).is_ok(),
        "canonical header must be accepted"
    );

    // Scala HeaderSerializer.parseBytes accepts the parsed prefix. The ID
    // remains bound to canonical fields; storage uses the canonical bytes.
    let mut trailing = clean.clone();
    trailing.extend_from_slice(&[0xAA, 0xBB]);
    let parsed = pre_validate_header(&trailing).expect("reference accepts suffix bytes");
    let canonical = pre_validate_header(&clean).unwrap();
    assert_eq!(parsed.header_id(), canonical.header_id());
    assert_eq!(parsed.header(), canonical.header());
}
