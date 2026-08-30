//! Header solution-pk curve-check (Scala `GroupElementSerializer.parse`
//! parity at header ingestion).
//!
//! Scala rejects a header whose Autolykos solution `pk` is an off-curve
//! point or an invalid SEC1 prefix at deserialize time. The v2+ PoW hit
//! depends only on `(msg, nonce, height)`, so without an explicit curve
//! check such headers parse cleanly and pass PoW here — an accept-invalid
//! chain split (audit finding H-1). `pre_validate_header` now drains the
//! reader's group-element sideband and runs the JVM-matching accept rule
//! *before* PoW, so the poisoned pk gets its own specific verdict.

use ergo_primitives::digest::{ADDigest, Digest32, ModifierId};
use ergo_primitives::group_element::GroupElement;
use ergo_ser::autolykos::AutolykosSolution;
use ergo_ser::header::{serialize_header, Header};
use ergo_sync::header_proc::{pre_validate_header, HeaderProcessError};
use ergo_validation::header::HeaderValidationError;

/// Generator point, SEC1-compressed (on-curve).
const G: [u8; 33] = [
    0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
    0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17,
    0x98,
];

/// Build serialized v2-header bytes with the supplied solution `pk`. The
/// rest of the header is inert zeros — sufficient because the GE check
/// fires right after parse, before any PoW or chain context.
fn v2_header_bytes_with_pk(pk: [u8; 33]) -> Vec<u8> {
    let header = Header {
        version: 2,
        parent_id: ModifierId::from_bytes([1u8; 32]),
        ad_proofs_root: Digest32::from_bytes([2u8; 32]),
        transactions_root: Digest32::from_bytes([3u8; 32]),
        state_root: ADDigest::from_bytes([4u8; 33]),
        timestamp: 1_700_000_000_000,
        extension_root: Digest32::from_bytes([5u8; 32]),
        n_bits: 0x1d00_ffff,
        height: 600_000,
        votes: [0; 3],
        unparsed_bytes: Vec::new(),
        solution: AutolykosSolution::V2 {
            pk: GroupElement::from_bytes(pk),
            nonce: [7u8; 8],
        },
    };
    serialize_header(&header)
        .map(|(bytes, _)| bytes)
        .expect("crafted header serializes")
}

/// Off-curve pk (0x02-lead, x = 0 — no y exists on SecP256K1) must be
/// rejected with the dedicated verdict BEFORE PoW gets a say.
#[test]
fn off_curve_pk_rejected_before_pow() {
    let mut bad = [0u8; 33];
    bad[0] = 0x02;
    let bytes = v2_header_bytes_with_pk(bad);
    match pre_validate_header(&bytes) {
        Err(HeaderProcessError::Validation(HeaderValidationError::InvalidGroupElement {
            encoding,
        })) => assert_eq!(encoding, bad, "rejected encoding must be echoed"),
        Err(other) => panic!("expected InvalidGroupElement, got {other}"),
        Ok(_) => panic!("off-curve pk must not pass ingestion"),
    }
}

/// Invalid SEC1 prefix (uncompressed 0x04 where only compressed encodings
/// are accepted) must be rejected the same way.
///
/// NOTE: since the wire prefix rule landed in `read_group_element`
/// (0x00/0x02/0x03 only — JVM `GroupElementSerializer.parse` parity), the
/// rejection now fires EARLIER, at header deserialize
/// (`HeaderProcessError::Deserialize`), before the curve-check stage. The
/// old `InvalidGroupElement` verdict remains reachable for on-prefix
/// off-curve points (see `off_curve_pk_rejected_before_pow`).
#[test]
fn bad_prefix_pk_rejected_before_pow() {
    let mut bad = [0u8; 33];
    bad[0] = 0x04;
    let bytes = v2_header_bytes_with_pk(bad);
    match pre_validate_header(&bytes) {
        // Wire-layer rejection (parse-time prefix rule) — the expected path now.
        Err(HeaderProcessError::Deserialize(msg)) => {
            assert!(
                msg.contains("invalid SEC1 point prefix"),
                "deserialize error must name the prefix rule: {msg}"
            );
        }
        // Belt-and-suspenders: the curve-check stage still rejects bad encodings.
        Err(HeaderProcessError::Validation(HeaderValidationError::InvalidGroupElement {
            ..
        })) => {}
        Err(other) => panic!("expected deserialize/validation reject, got {other}"),
        Ok(_) => panic!("bad-prefix pk must not pass ingestion"),
    }
}

/// Positive control for check ordering: the same crafted header with an
/// ON-curve pk must sail past the GE gate and fail later at PoW (the
/// nonce doesn't satisfy difficulty) — proving the gate neither rejects
/// valid points nor masks the next stage.
#[test]
fn on_curve_pk_passes_gate_and_fails_pow() {
    let bytes = v2_header_bytes_with_pk(G);
    match pre_validate_header(&bytes) {
        Err(HeaderProcessError::Validation(HeaderValidationError::Pow(_))) => {}
        Err(other) => panic!("expected Pow failure after passing the GE gate, got {other}"),
        Ok(_) => panic!("header with unsatisfying PoW must not pass ingestion"),
    }
}

/// Real mainnet v2+ headers must still pass ingestion end to end.
#[test]
fn curated_mainnet_v2_headers_still_validate() {
    let data = std::fs::read_to_string("../test-vectors/mainnet/headers_v2_curated.json")
        .expect("fixture");
    let entries: serde_json::Value = serde_json::from_str(&data).unwrap();
    let arr = entries.as_array().expect("header array");
    assert!(!arr.is_empty());
    for e in arr {
        let height = e["height"].as_u64().unwrap();
        let bytes = hex::decode(e["bytes"].as_str().unwrap()).unwrap();
        if let Err(err) = pre_validate_header(&bytes) {
            panic!("curated mainnet header at h={height} must pass ingestion: {err}");
        }
    }
}
