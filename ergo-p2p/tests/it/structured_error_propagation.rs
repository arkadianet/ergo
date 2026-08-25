//! Integration tests pinning that p2p parse failures preserve their
//! structured underlying `ReadError` / `HandshakeError` across the
//! public API.
//!
//! These tests live in the integration layer (no `#[cfg(test)]`
//! access) precisely so they exercise what downstream code sees when
//! a peer sends a malformed payload. Substring matches on Display
//! would silently regress if a message wording changed; variant
//! matches catch a taxonomy regression at compile or assertion time.

use ergo_p2p::handshake::{deserialize_handshake, deserialize_peer_spec_from, HandshakeError};
use ergo_p2p::message::{
    deserialize_get_nipopow_proof, deserialize_get_snapshots_info, deserialize_inv,
    deserialize_peers, deserialize_sync_info, MessageError,
};
use ergo_primitives::reader::{ReadError, VlqReader};
use ergo_primitives::vlq::VlqError;
use ergo_primitives::writer::VlqWriter;

// ----- helpers -----

/// Build the wire prefix of an `Inv` payload up to but not including
/// the modifier-id bytes. Used to craft truncated payloads where the
/// `get_bytes(32)` call hits EOF mid-id.
fn inv_prefix_with_count(type_id: u8, count: u32) -> Vec<u8> {
    let mut w = VlqWriter::new();
    w.put_u8(type_id);
    w.put_u32(count);
    w.result()
}

// ----- error paths -----

#[test]
fn inv_truncated_in_id_surfaces_typed_unexpected_end() {
    // Claim 1 modifier but emit zero id bytes. `get_bytes(32)`
    // reports the raw EOF as ReadError::UnexpectedEnd { needed: 32 }.
    let payload = inv_prefix_with_count(101, 1);

    let err = deserialize_inv(&payload).expect_err("truncated inv must error");

    let MessageError::Read(read_err) = err else {
        panic!("expected MessageError::Read, got {err:?}");
    };
    let ReadError::UnexpectedEnd { needed, .. } = read_err else {
        panic!("expected ReadError::UnexpectedEnd, got {read_err:?}");
    };
    assert_eq!(
        needed, 32,
        "needed-byte count must reflect the modifier-id read width",
    );
}

#[test]
fn inv_truncated_in_count_vlq_surfaces_typed_vlq_unexpected_end() {
    // type_id present, but the VLQ-encoded count is cut after a
    // continuation byte — get_u32_exact() bottoms out in
    // VlqReader::get_vlq which returns VlqError::UnexpectedEnd.
    // Migration value: the nested Vlq variant distinguishes
    // "VLQ truncated" from "raw byte read short" without parsing
    // the Display string.
    let payload = vec![101u8, 0x80]; // type_id, then VLQ continuation byte with no follow-up

    let err = deserialize_inv(&payload).expect_err("truncated VLQ count must error");

    assert!(
        matches!(
            err,
            MessageError::Read(ReadError::Vlq(VlqError::UnexpectedEnd))
        ),
        "expected MessageError::Read(Vlq(UnexpectedEnd)), got {err:?}",
    );
}

#[test]
fn sync_info_v2_truncated_in_header_surfaces_typed_unexpected_end() {
    // V2 marker (length=0 sentinel + mode marker + header count) but
    // the very first header's length field is cut: get_u16 hits EOF
    // mid-VLQ → ReadError::Vlq(VlqError::UnexpectedEnd).
    let mut w = VlqWriter::new();
    w.put_u16(0); // V2 sentinel
    w.put_u8(0xFF); // SYNC_V2_MARKER (-1 as u8)
    w.put_u8(1); // 1 header to follow
                 // omit header_len + header bytes
    let payload = w.result();

    let err = deserialize_sync_info(&payload).expect_err("V2 truncated must error");

    assert!(
        matches!(
            err,
            MessageError::Read(ReadError::Vlq(VlqError::UnexpectedEnd))
        ),
        "expected typed Vlq(UnexpectedEnd) on header_len read, got {err:?}",
    );
}

#[test]
fn get_snapshots_info_non_empty_payload_surfaces_typed_variant() {
    // Phase 3 added NonEmptyGetSnapshotsInfo for the case previously
    // stringified as MessageError::Read("...got N bytes"). The
    // payload-size byte count is the carried value, available for
    // structured peer-policy decisions.
    let payload = vec![0xAA, 0xBB, 0xCC];

    let err = deserialize_get_snapshots_info(&payload).expect_err("non-empty payload rejected");

    assert!(
        matches!(err, MessageError::NonEmptyGetSnapshotsInfo(3)),
        "expected NonEmptyGetSnapshotsInfo(3), got {err:?}",
    );
}

#[test]
fn get_nipopow_proof_pad_length_truncated_surfaces_typed_unexpected_end() {
    // pad_length claims 7 bytes but only 1 follows. get_bytes(7) is
    // a raw fixed-width read so the structured error is the
    // top-level ReadError::UnexpectedEnd { needed: 7, .. }, not a
    // Vlq-wrapped one. Pinning the distinction protects against a
    // regression that collapses both paths.
    let mut w = VlqWriter::new();
    w.put_i32(6); // m
    w.put_i32(10); // k
    w.put_u8(0); // header_id absent
    w.put_u16(7); // pad_length = 7
    w.put_bytes(&[0xAA]); // only 1 byte present
    let payload = w.result();

    let err = deserialize_get_nipopow_proof(&payload).expect_err("pad truncated must error");

    let MessageError::Read(ReadError::UnexpectedEnd { needed, .. }) = err else {
        panic!("expected Read(UnexpectedEnd), got {err:?}");
    };
    assert_eq!(needed, 7, "needed must equal claimed pad_length");
}

#[test]
fn handshake_truncated_in_time_surfaces_typed_vlq_unexpected_end() {
    // Empty payload — get_u64 reads a VLQ-encoded u64 and fails at
    // the very first byte with VlqError::UnexpectedEnd. Pins that
    // HandshakeError::Read now wraps the typed ReadError instead of
    // a stringified Display.
    let err = deserialize_handshake(&[]).expect_err("empty handshake must error");

    assert!(
        matches!(
            err,
            HandshakeError::Read(ReadError::Vlq(VlqError::UnexpectedEnd))
        ),
        "expected HandshakeError::Read(Vlq(UnexpectedEnd)), got {err:?}",
    );
}

#[test]
fn peer_spec_negative_feature_count_surfaces_typed_variant() {
    // After agent_name + version + node_name + addr-absent, a u8
    // feature_count whose i8 cast is negative is now a typed
    // NegativeFeatureCount rather than HandshakeError::Read("...").
    // Drive deserialize_peer_spec_from directly so we don't need to
    // construct a full Handshake wrapper.
    let mut w = VlqWriter::new();
    w.put_u8(1); // agent_name length = 1
    w.put_u8(b'X'); // agent_name byte
    w.put_u8(0); // major
    w.put_u8(0); // minor
    w.put_u8(1); // patch
    w.put_u8(1); // node_name length = 1
    w.put_u8(b'Y'); // node_name byte
    w.put_u8(0); // addr_present = 0 (absent)
    w.put_u8(0xFF); // feature_count byte → -1 as i8
    let bytes = w.result();
    let mut r = VlqReader::new(&bytes);

    let err = deserialize_peer_spec_from(&mut r).expect_err("negative count must error");

    assert!(
        matches!(err, HandshakeError::NegativeFeatureCount(-1)),
        "expected NegativeFeatureCount(-1), got {err:?}",
    );
}

#[test]
fn peers_payload_with_corrupt_peer_spec_wraps_typed_handshake_error() {
    // A Peers payload claims 1 peer but the PeerSpec body is
    // truncated at the agent_name read. After Phase 3 this surfaces
    // as MessageError::PeerSpec(HandshakeError::Read(ReadError::*))
    // — the entire chain is structurally inspectable, not a
    // stringified peer-spec failure.
    let mut w = VlqWriter::new();
    w.put_u32(1); // 1 peer
    w.put_u8(8); // agent_name claims 8 bytes
                 // ... none follow
    let payload = w.result();

    let err = deserialize_peers(&payload, 100).expect_err("truncated peer spec must error");

    let MessageError::PeerSpec(HandshakeError::Read(read_err)) = err else {
        panic!("expected MessageError::PeerSpec(HandshakeError::Read(_)), got {err:?}");
    };
    let ReadError::UnexpectedEnd { needed, .. } = read_err else {
        panic!("expected ReadError::UnexpectedEnd, got {read_err:?}");
    };
    assert_eq!(needed, 8, "needed must equal claimed agent_name length");
}
