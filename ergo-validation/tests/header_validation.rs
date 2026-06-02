use ergo_crypto::difficulty::{is_recalculation_height, DifficultyParams};
use ergo_crypto::pow::verify_pow_solution;
use ergo_primitives::reader::VlqReader;
use ergo_ser::header::{read_header, serialize_header, Header};
use ergo_validation::header::{
    check_parent_id, check_timestamp, validate_header, HeaderValidationError,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct HeaderVector {
    height: u32,
    #[allow(dead_code)]
    id: String,
    bytes: String,
}

fn load_vectors(path: &str) -> Vec<HeaderVector> {
    let data =
        std::fs::read_to_string(path).unwrap_or_else(|e| panic!("failed to read {path}: {e}"));
    serde_json::from_str(&data).unwrap_or_else(|e| panic!("failed to parse {path}: {e}"))
}

fn decode_header(v: &HeaderVector) -> Header {
    let bytes = hex::decode(&v.bytes).unwrap();
    let mut r = VlqReader::new(&bytes);
    read_header(&mut r).unwrap()
}

fn decode_with_id(v: &HeaderVector) -> (Header, [u8; 32]) {
    let h = decode_header(v);
    let (_, id) = serialize_header(&h).expect("real header vector serializes");
    (h, *id.as_bytes())
}

/// Load headers sorted by height, returning (header, computed_id) pairs.
fn load_sorted(path: &str) -> Vec<(Header, [u8; 32])> {
    let mut vecs = load_vectors(path);
    vecs.sort_by_key(|v| v.height);
    vecs.iter().map(decode_with_id).collect()
}

// ---------------------------------------------------------------------------
// Positive tests
// ---------------------------------------------------------------------------

#[test]
fn contiguous_validation_1_500() {
    let headers = load_sorted("../test-vectors/mainnet/headers_1_500.json");
    assert!(
        headers.len() >= 500,
        "expected 500+ headers, got {}",
        headers.len()
    );

    let mut validated = 0;
    for i in 1..headers.len() {
        let (ref child, _) = headers[i];
        let (ref parent, ref parent_id) = headers[i - 1];

        check_parent_id(child, parent_id).unwrap_or_else(|e| {
            panic!("parent ID check failed at height {}: {e}", child.height);
        });
        check_timestamp(child, parent).unwrap_or_else(|e| {
            panic!("timestamp check failed at height {}: {e}", child.height);
        });
        validated += 1;
    }
    eprintln!("contiguous_validation_1_500: {validated} headers validated");
    assert!(validated >= 499);
}

#[test]
#[ignore = "needs gitignored headers_415000_417791.json + headers_417792_419000.json — extract via test-vectors/scripts then run with --ignored"]
fn v1_to_v2_pow_transition() {
    let pre = load_sorted("../test-vectors/mainnet/headers_415000_417791.json");
    let post = load_sorted("../test-vectors/mainnet/headers_417792_419000.json");
    let cfg = DifficultyParams::mainnet();

    // Verify the last v1 header and first v2 header link correctly
    let (ref last_v1, ref last_v1_id) = pre.last().unwrap();
    let (ref first_v2, ref first_v2_id) = post[0];

    assert_eq!(last_v1.version, 1);
    assert!(first_v2.version >= 2);
    assert_eq!(first_v2.height, last_v1.height + 1);

    // Full validate_header across the v1→v2 boundary
    validate_header(
        first_v2.clone(),
        *first_v2_id,
        last_v1_id,
        last_v1,
        std::slice::from_ref(last_v1),
        &cfg,
    )
    .unwrap_or_else(|e| panic!("v1→v2 boundary validation failed: {e}"));

    // Validate contiguous chain within v2 range.
    // At epoch boundaries we lack lookback headers for difficulty recalc,
    // so fall back to parent+timestamp+PoW for those blocks.
    let mut full = 0;
    let mut partial = 0;
    for i in 1..post.len() {
        let (ref child, ref child_id) = post[i];
        let (ref parent, ref parent_id) = post[i - 1];
        if is_recalculation_height(child.height, &cfg) {
            check_parent_id(child, parent_id).unwrap();
            check_timestamp(child, parent).unwrap();
            verify_pow_solution(child).unwrap();
            partial += 1;
        } else {
            validate_header(
                child.clone(),
                *child_id,
                parent_id,
                parent,
                std::slice::from_ref(parent),
                &cfg,
            )
            .unwrap_or_else(|e| {
                panic!("full validation failed at height {}: {e}", child.height);
            });
            full += 1;
        }
    }
    eprintln!("v1_to_v2_transition: {full} full + {partial} partial (epoch boundary, no lookback)");
}

#[test]
#[ignore = "needs gitignored headers_843000_844672.json + headers_844673_846000.json — extract via test-vectors/scripts then run with --ignored"]
fn eip37_epoch_boundary() {
    let pre = load_sorted("../test-vectors/mainnet/headers_843000_844672.json");
    let post = load_sorted("../test-vectors/mainnet/headers_844673_846000.json");
    let cfg = DifficultyParams::mainnet();

    let (ref last_pre, ref last_pre_id) = pre.last().unwrap();
    let (ref first_post, _) = post[0];

    // Full validate_header across the EIP-37 boundary (first post-EIP37 is itself
    // an epoch boundary, so use parent+timestamp+PoW — no lookback available)
    check_parent_id(first_post, last_pre_id).unwrap();
    check_timestamp(first_post, last_pre).unwrap();
    verify_pow_solution(first_post).unwrap();

    // Validate a stretch after EIP-37 activation.
    // Epoch boundaries lack lookback → parent+timestamp+PoW only.
    let mut full = 0;
    let mut partial = 0;
    for i in 1..post.len().min(200) {
        let (ref child, ref child_id) = post[i];
        let (ref parent, ref parent_id) = post[i - 1];
        if is_recalculation_height(child.height, &cfg) {
            check_parent_id(child, parent_id).unwrap();
            check_timestamp(child, parent).unwrap();
            verify_pow_solution(child).unwrap();
            partial += 1;
        } else {
            validate_header(
                child.clone(),
                *child_id,
                parent_id,
                parent,
                std::slice::from_ref(parent),
                &cfg,
            )
            .unwrap_or_else(|e| {
                panic!("full validation failed at height {}: {e}", child.height);
            });
            full += 1;
        }
    }
    eprintln!(
        "eip37_epoch_boundary: {full} full + {partial} partial (epoch boundary, no lookback)"
    );
}

#[test]
fn full_validate_header_with_pow_and_difficulty() {
    // Use headers_1_500 — for non-boundary blocks, epoch_headers = [parent]
    let headers = load_sorted("../test-vectors/mainnet/headers_1_500.json");
    let cfg = DifficultyParams::mainnet();

    let mut validated = 0;
    for i in 1..headers.len().min(100) {
        let (ref child, ref child_id) = headers[i];
        let (ref parent, ref parent_id) = headers[i - 1];

        // For non-epoch-boundary blocks, epoch_headers = [parent]
        validate_header(
            child.clone(),
            *child_id,
            parent_id,
            parent,
            std::slice::from_ref(parent),
            &cfg,
        )
        .unwrap_or_else(|e| {
            panic!("full validation failed at height {}: {e}", child.height);
        });
        validated += 1;
    }
    eprintln!("full_validate_header: {validated} headers fully validated");
    assert!(validated >= 99);
}

// ---------------------------------------------------------------------------
// Negative tests
// ---------------------------------------------------------------------------

#[test]
fn reject_wrong_parent_id() {
    let headers = load_sorted("../test-vectors/mainnet/headers_1_10.json");
    let (ref child, _) = headers[1];
    let fake_parent_id = [0xAA; 32];

    match check_parent_id(child, &fake_parent_id) {
        Err(HeaderValidationError::ParentMismatch { .. }) => {}
        other => panic!("expected ParentMismatch, got {other:?}"),
    }
}

#[test]
fn reject_timestamp_not_monotonic() {
    let headers = load_sorted("../test-vectors/mainnet/headers_1_10.json");
    let (ref child, _) = headers[1];
    // Create a parent with a future timestamp
    let mut fake_parent = headers[0].0.clone();
    fake_parent.timestamp = child.timestamp + 1;

    match check_timestamp(child, &fake_parent) {
        Err(HeaderValidationError::TimestampNotMonotonic { .. }) => {}
        other => panic!("expected TimestampNotMonotonic, got {other:?}"),
    }
}

#[test]
fn reject_equal_timestamp() {
    let headers = load_sorted("../test-vectors/mainnet/headers_1_10.json");
    let (ref child, _) = headers[1];
    let mut fake_parent = headers[0].0.clone();
    fake_parent.timestamp = child.timestamp; // equal, not strictly less

    match check_timestamp(child, &fake_parent) {
        Err(HeaderValidationError::TimestampNotMonotonic { .. }) => {}
        other => panic!("expected TimestampNotMonotonic, got {other:?}"),
    }
}

#[test]
fn reject_pow_via_validate_header() {
    let headers = load_sorted("../test-vectors/mainnet/headers_1_10.json");
    let (ref parent, ref parent_id) = headers[0];
    let mut bad_child = headers[1].0.clone();
    // Corrupt the nonce to break PoW
    match &mut bad_child.solution {
        ergo_ser::autolykos::AutolykosSolution::V1 { nonce, .. } => {
            nonce[0] ^= 0xFF;
        }
        ergo_ser::autolykos::AutolykosSolution::V2 { nonce, .. } => {
            nonce[0] ^= 0xFF;
        }
    }

    let cfg = DifficultyParams::mainnet();
    match validate_header(
        bad_child.clone(),
        [0u8; 32],
        parent_id,
        parent,
        std::slice::from_ref(parent),
        &cfg,
    ) {
        Err(HeaderValidationError::Pow(_)) => {}
        other => panic!("expected Pow error, got {other:?}"),
    }
}

#[test]
fn reject_difficulty_mismatch() {
    // Test the Difficulty error path directly, bypassing PoW which runs first
    // in validate_header() and would mask the nBits mismatch.
    use ergo_crypto::pow::verify_header_difficulty;
    let headers = load_sorted("../test-vectors/mainnet/headers_1_10.json");
    let (ref parent, _) = headers[0];
    let mut bad_child = headers[1].0.clone();
    bad_child.n_bits ^= 0x0000_FF00;
    let cfg = DifficultyParams::mainnet();

    let err = verify_header_difficulty(&bad_child, std::slice::from_ref(parent), &cfg).unwrap_err();
    assert!(
        format!("{err}").contains("nBits mismatch"),
        "expected nBits mismatch, got: {err}",
    );

    // Also verify it surfaces through validate_header as Difficulty variant
    let (_, ref parent_id) = headers[0];
    match validate_header(
        bad_child.clone(),
        [0u8; 32],
        parent_id,
        parent,
        std::slice::from_ref(parent),
        &cfg,
    ) {
        Err(HeaderValidationError::Pow(_)) | Err(HeaderValidationError::Difficulty(_)) => {}
        other => panic!("expected Pow or Difficulty error, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// from_persisted_parts tests
// ---------------------------------------------------------------------------

use ergo_validation::header::CheckedHeader;

/// Pull `(header, scala_id, raw_bytes)` for one fixture entry — anchored
/// on the Scala-emitted bytes and id from the JSON, NOT on our own
/// `serialize_header` round-trip. This keeps the constructor's hash check
/// honest against an external oracle: any drift between our codec and
/// Scala's wire form would surface as a `HeaderIdMismatch` here, where a
/// re-serialized variant would silently mask it.
fn load_persisted_fixture(path: &str, idx: usize) -> (Header, [u8; 32], Vec<u8>) {
    let mut vecs = load_vectors(path);
    vecs.sort_by_key(|v| v.height);
    let v = &vecs[idx];
    let bytes = hex::decode(&v.bytes).expect("fixture bytes hex");
    let mut id_bytes = [0u8; 32];
    let id_decoded = hex::decode(&v.id).expect("fixture id hex");
    assert_eq!(id_decoded.len(), 32, "fixture id must be 32 bytes");
    id_bytes.copy_from_slice(&id_decoded);
    let header = decode_header(v);
    (header, id_bytes, bytes)
}

#[test]
fn from_persisted_parts_accepts_valid_metadata() {
    let (header, header_id, bytes) =
        load_persisted_fixture("../test-vectors/mainnet/headers_1_10.json", 1);
    let checked = CheckedHeader::from_persisted_parts(
        &bytes,
        header_id,
        1, // pow_validity = valid
        header.height,
        *header.parent_id.as_bytes(),
        header.timestamp,
    );
    assert!(checked.is_ok());
    let checked = checked.unwrap();
    assert_eq!(checked.height(), header.height);
    assert_eq!(*checked.header_id(), header_id);
}

#[test]
fn from_persisted_parts_rejects_pow_not_validated() {
    let (header, header_id, bytes) =
        load_persisted_fixture("../test-vectors/mainnet/headers_1_10.json", 1);
    match CheckedHeader::from_persisted_parts(
        &bytes,
        header_id,
        0, // pow_validity = unknown
        header.height,
        *header.parent_id.as_bytes(),
        header.timestamp,
    ) {
        Err(HeaderValidationError::PowNotValidated { pow_validity: 0 }) => {}
        other => panic!("expected PowNotValidated, got {other:?}"),
    }
}

#[test]
fn from_persisted_parts_rejects_height_mismatch() {
    let (header, header_id, bytes) =
        load_persisted_fixture("../test-vectors/mainnet/headers_1_10.json", 1);
    match CheckedHeader::from_persisted_parts(
        &bytes,
        header_id,
        1,
        header.height + 999, // wrong height
        *header.parent_id.as_bytes(),
        header.timestamp,
    ) {
        Err(HeaderValidationError::MetaHeightMismatch { .. }) => {}
        other => panic!("expected MetaHeightMismatch, got {other:?}"),
    }
}

#[test]
fn from_persisted_parts_rejects_parent_mismatch() {
    let (header, header_id, bytes) =
        load_persisted_fixture("../test-vectors/mainnet/headers_1_10.json", 1);
    match CheckedHeader::from_persisted_parts(
        &bytes,
        header_id,
        1,
        header.height,
        [0xAA; 32], // wrong parent
        header.timestamp,
    ) {
        Err(HeaderValidationError::MetaParentMismatch { .. }) => {}
        other => panic!("expected MetaParentMismatch, got {other:?}"),
    }
}

#[test]
fn from_persisted_parts_rejects_timestamp_mismatch() {
    let (header, header_id, bytes) =
        load_persisted_fixture("../test-vectors/mainnet/headers_1_10.json", 1);
    match CheckedHeader::from_persisted_parts(
        &bytes,
        header_id,
        1,
        header.height,
        *header.parent_id.as_bytes(),
        header.timestamp + 1, // wrong timestamp
    ) {
        Err(HeaderValidationError::MetaTimestampMismatch { .. }) => {}
        other => panic!("expected MetaTimestampMismatch, got {other:?}"),
    }
}

#[test]
fn from_persisted_parts_rejects_id_mismatch() {
    // Caller-supplied expected_id ≠ blake2b256(bytes): the new constructor
    // is the trust boundary at the persisted-storage hydration path.
    let (header, header_id, bytes) =
        load_persisted_fixture("../test-vectors/mainnet/headers_1_10.json", 1);
    let mut wrong_id = header_id;
    wrong_id[0] ^= 0xFF;
    match CheckedHeader::from_persisted_parts(
        &bytes,
        wrong_id,
        1,
        header.height,
        *header.parent_id.as_bytes(),
        header.timestamp,
    ) {
        Err(HeaderValidationError::HeaderIdMismatch { expected, computed }) => {
            assert_eq!(expected, wrong_id);
            assert_eq!(computed, header_id);
        }
        other => panic!("expected HeaderIdMismatch, got {other:?}"),
    }
}

#[test]
fn from_persisted_parts_rejects_unparseable_bytes() {
    // Bytes that don't parse cleanly: the constructor surfaces a typed
    // parse error rather than panicking or silently constructing junk.
    let (_, _, bytes) = load_persisted_fixture("../test-vectors/mainnet/headers_1_10.json", 1);
    let truncated = &bytes[..bytes.len() / 2];
    let truncated_id = *ergo_primitives::digest::blake2b256(truncated).as_bytes();
    match CheckedHeader::from_persisted_parts(
        truncated,
        truncated_id, // matches the truncated hash, so the parse fails first
        1,
        0,
        [0u8; 32],
        0,
    ) {
        Err(HeaderValidationError::HeaderParseFailed(_)) => {}
        other => panic!("expected HeaderParseFailed, got {other:?}"),
    }
}

#[test]
fn from_persisted_parts_rejects_trailing_bytes() {
    // A row of the form `valid_header_bytes ++ junk` would hash to a
    // different id than the canonical bytes alone. We synthesize that
    // case by appending bytes AND using the appended-bytes' hash as the
    // expected_id, so the hash check passes — leaving the EOF guard as
    // the only thing standing between noncanonical bytes and a happy
    // CheckedHeader.
    let (header, _, bytes) = load_persisted_fixture("../test-vectors/mainnet/headers_1_10.json", 1);
    let mut tampered = bytes.clone();
    tampered.extend_from_slice(&[0xAA; 4]);
    let tampered_id = *ergo_primitives::digest::blake2b256(&tampered).as_bytes();
    match CheckedHeader::from_persisted_parts(
        &tampered,
        tampered_id,
        1,
        header.height,
        *header.parent_id.as_bytes(),
        header.timestamp,
    ) {
        Err(HeaderValidationError::HeaderParseFailed(msg)) => {
            assert!(
                msg.contains("trailing"),
                "expected trailing-bytes message, got: {msg}"
            );
        }
        other => panic!("expected HeaderParseFailed (trailing), got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Phase 2: validator-contract pin for the new MissingEpochHeaders surface
// ---------------------------------------------------------------------------

/// Pins the ergo-crypto/ergo-validation contract that an undersized
/// EIP-37 epoch window surfaces as
/// `HeaderValidationError::Difficulty(DifficultyError::MissingEpochHeaders)`.
/// The sync executor's classification (orphan-buffer + retry, no peer
/// penalty) is layered on top of this contract; this test is what
/// guarantees the executor's match arm is reachable for the right
/// reason and not swallowing a different error category.
#[test]
fn validate_header_after_pow_eip37_undersized_window_returns_difficulty_missing() {
    use ergo_crypto::pow::DifficultyError;
    use ergo_validation::header::{validate_header_after_pow, PowCheckedHeader};

    // Real mainnet headers: parent at 1_761_792 (= 13_764 * 128, a
    // post-EIP-37 recalculation boundary) and child at 1_761_793.
    let headers = load_sorted("../test-vectors/mainnet/headers_1761000_1762000.json");
    let parent = headers
        .iter()
        .find(|(h, _)| h.height == 1_761_792)
        .expect("corpus must contain height 1_761_792");
    let child = headers
        .iter()
        .find(|(h, _)| h.height == 1_761_793)
        .expect("corpus must contain height 1_761_793");

    // Build the PoW proof against mainnet config (these are real mainnet
    // headers, so PoW is genuinely valid).
    let cfg = DifficultyParams::mainnet();
    let pow_checked = PowCheckedHeader::verify_pow(child.0.clone(), child.1).unwrap_or_else(|e| {
        panic!("real mainnet header at 1_761_793 must pass PoW: {e}");
    });

    // Supply only the parent. EIP-37 needs len >= 2 for the predictive
    // ∪ classic average; the ergo-crypto checked helper detects that
    // and surfaces MissingEpochHeaders.
    let parent_id = parent.1;
    let epoch_headers = std::slice::from_ref(&parent.0);
    let result = validate_header_after_pow(pow_checked, &parent_id, &parent.0, epoch_headers, &cfg);

    match result {
        Err(HeaderValidationError::Difficulty(DifficultyError::MissingEpochHeaders)) => {}
        other => panic!(
            "expected Difficulty(MissingEpochHeaders) at EIP-37 boundary with len-1 window, got {other:?}"
        ),
    }
}
