//! Scala-anchored wire-vector oracle for ergo-p2p framing + payload
//! codecs. Each test loads a Scala-test-derived `.hex` from
//! `test-vectors/ergo-p2p/`, decodes the full frame through
//! `ergo_p2p::framing`, hands the payload to the per-message
//! deserializer, asserts semantic content, then re-serializes +
//! re-frames and asserts byte-identical roundtrip.
//!
//! Per-vector provenance is documented in
//! `test-vectors/ergo-p2p/PROVISIONING.md`. The upstream Scala
//! tests mark these hex strings as "test vector for external
//! implementations" — they are the contract third-party
//! (re-)implementations are expected to match.

use std::path::{Path, PathBuf};

use ergo_p2p::framing::{deserialize_frame, serialize_frame, MessageFrame, MAINNET_MAGIC};
use ergo_p2p::message::{
    deserialize_inv, deserialize_modifiers, deserialize_sync_info, serialize_inv,
    serialize_modifiers, serialize_sync_info, SyncInfo, CODE_INV, CODE_MODIFIER,
    CODE_REQUEST_MODIFIER, CODE_SYNC_INFO,
};

// ----- helpers -----

fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("test-vectors")
        .join("ergo-p2p")
}

fn load_hex(rel: &str) -> Vec<u8> {
    let path = vectors_dir().join(rel);
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    hex::decode(text.trim()).unwrap_or_else(|e| panic!("hex-decode {}: {e}", path.display()))
}

/// `[1x16, 2x16]` — the synthetic header id used by the Scala
/// `Inv`, `RequestModifier`, and `SyncInfo` test fixtures.
fn synthetic_header_id() -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..16].fill(1);
    out[16..].fill(2);
    out
}

fn decode_one_frame(bytes: &[u8]) -> (MessageFrame, usize) {
    deserialize_frame(&MAINNET_MAGIC, bytes)
        .expect("frame decode")
        .expect("frame complete")
}

// ----- oracle parity -----

/// `Inv` (code 55) carrying one `Header`-modifier id. Anchored by
/// `network/InvSpecification.scala:37`. The vector is the full
/// mainnet frame; the test verifies framing + payload + checksum +
/// byte-identical reserialize.
#[test]
fn inv_header_single_mainnet_roundtrips_scala_vector() {
    let captured = load_hex("inv/header_single_mainnet.hex");

    let (frame, consumed) = decode_one_frame(&captured);
    assert_eq!(consumed, captured.len(), "frame consumes the whole vector");
    assert_eq!(frame.code, CODE_INV, "code 55 = Inv");

    let inv = deserialize_inv(&frame.payload).expect("payload decode");
    assert_eq!(inv.type_id, 101, "modifierTypeId for Header");
    assert_eq!(inv.ids.len(), 1, "one advertised id");
    assert_eq!(inv.ids[0], synthetic_header_id());

    // Roundtrip: same payload → same frame bytes (checksum included).
    let re_payload = serialize_inv(&inv).expect("payload reserialize");
    assert_eq!(re_payload, frame.payload, "payload byte-identical");
    let re_framed = serialize_frame(
        &MAINNET_MAGIC,
        &MessageFrame {
            code: frame.code,
            payload: re_payload,
        },
    );
    assert_eq!(re_framed, captured, "full-frame byte-identical");
}

/// `RequestModifier` (code 22). Same logical `InvData` payload as
/// the `Inv` vector — the codec is shared; only the frame code
/// changes. Anchored by `network/RequestModifiersSpecification.scala:38`.
#[test]
fn request_modifier_header_single_mainnet_roundtrips_scala_vector() {
    let captured = load_hex("request_modifier/header_single_mainnet.hex");

    let (frame, _) = decode_one_frame(&captured);
    assert_eq!(
        frame.code, CODE_REQUEST_MODIFIER,
        "code 22 = RequestModifier"
    );

    let inv = deserialize_inv(&frame.payload).expect("payload decode");
    assert_eq!(inv.type_id, 101);
    assert_eq!(inv.ids.len(), 1);
    assert_eq!(inv.ids[0], synthetic_header_id());

    // The shared-codec invariant: same payload as the Inv vector.
    let inv_payload = load_hex("inv/header_single_mainnet.hex");
    let (inv_frame, _) = decode_one_frame(&inv_payload);
    assert_eq!(
        frame.payload, inv_frame.payload,
        "Inv and RequestModifier payloads must be byte-identical for the same InvData",
    );

    let re_framed = serialize_frame(
        &MAINNET_MAGIC,
        &MessageFrame {
            code: frame.code,
            payload: serialize_inv(&inv).unwrap(),
        },
    );
    assert_eq!(re_framed, captured);
}

/// `SyncInfo` V1 (code 65) with one header id. Anchored by
/// `network/ErgoSyncInfoSpecification.scala:38`. Confirms the count
/// field is VLQ-encoded (the V1 single-header payload is 33 bytes:
/// `VLQ(1) || 32-byte-id`, not `u16 BE(1) || 32-byte-id` which
/// would be 34).
#[test]
fn sync_info_v1_single_header_mainnet_roundtrips_scala_vector() {
    let captured = load_hex("sync_info/v1_single_header_mainnet.hex");

    let (frame, _) = decode_one_frame(&captured);
    assert_eq!(frame.code, CODE_SYNC_INFO);
    assert_eq!(
        frame.payload.len(),
        33,
        "Scala-vector V1 payload size pin (VLQ count = 1 byte)"
    );

    let info = deserialize_sync_info(&frame.payload).expect("payload decode");
    let header_ids = match info {
        SyncInfo::V1 { header_ids } => header_ids,
        other => panic!("expected V1, got {other:?}"),
    };
    assert_eq!(header_ids.len(), 1);
    assert_eq!(header_ids[0], synthetic_header_id());

    let re_framed = serialize_frame(
        &MAINNET_MAGIC,
        &MessageFrame {
            code: frame.code,
            payload: serialize_sync_info(&SyncInfo::V1 { header_ids }),
        },
    );
    assert_eq!(re_framed, captured);
}

/// `Modifiers` (code 33) wrapping one `Header` modifier. Anchored
/// by `network/ModifiersSpecification.scala:34`. Exercises the
/// `(type, count, [(id, len, bytes)])` payload shape end-to-end —
/// the only test in this suite whose payload includes a
/// VLQ-encoded length (`0xe1 0x01` = 225) and a 225-byte body.
#[test]
fn modifiers_header_single_mainnet_roundtrips_scala_vector() {
    let captured = load_hex("modifiers/header_single_mainnet.hex");

    let (frame, _) = decode_one_frame(&captured);
    assert_eq!(frame.code, CODE_MODIFIER);
    assert_eq!(
        frame.payload.len(),
        261,
        "Scala fixture payload size: 1 + 1 + 32 + 2 + 225 = 261"
    );

    let modifiers = deserialize_modifiers(&frame.payload).expect("payload decode");
    assert_eq!(modifiers.type_id, 101);
    assert_eq!(modifiers.modifiers.len(), 1);
    let (id, bytes) = &modifiers.modifiers[0];
    assert_eq!(bytes.len(), 225, "header body length");
    // Cross-crate oracle: recompute the modifier id from the header
    // body bytes through ergo-primitives' blake2b — this is the same
    // derivation `HeaderSerializer.parseBytes` + `header.id` does on
    // the Scala side. Catches drift where ergo-p2p framing still
    // roundtrips but the id-derivation in ergo-primitives diverges from
    // Scala.
    let recomputed_id = ergo_primitives::digest::blake2b256(bytes);
    assert_eq!(
        id,
        recomputed_id.as_bytes(),
        "modifier id must equal blake2b256(header_bytes)",
    );
    // Also exercise ergo-ser's `read_header` to confirm the body
    // parses as a real mainnet-shape header — a finer drift signal
    // than the leading-byte check, since a corrupted body would
    // pass that but fail the full parse.
    let mut r = ergo_primitives::reader::VlqReader::new(bytes);
    let header = ergo_ser::header::read_header(&mut r).expect("header parses via ergo-ser");
    assert_eq!(
        header.version, 0x42,
        "block version preserved through full parse",
    );

    let re_framed = serialize_frame(
        &MAINNET_MAGIC,
        &MessageFrame {
            code: frame.code,
            payload: serialize_modifiers(&modifiers).expect("payload reserialize"),
        },
    );
    assert_eq!(re_framed, captured);
}

/// `SyncInfo` V2 payload-only fixture. The Scala
/// `ErgoSyncInfoSpecification` doesn't have an upstream byte
/// fixture for V2, so this vector is manually transcribed from
/// `ergo-core/.../network/history/ErgoSyncInfo.scala:60-74`
/// (`ErgoSyncInfoSerializer.serialize`'s V2 case). Provenance is
/// weaker than the Scala-test-anchored V1/Inv/etc. vectors, but
/// stronger than the inline self-derivation in
/// `message.rs::sync_info_v2_roundtrip` — see PROVISIONING.md
/// § "Vectors not in this tree" for the upstream-PR follow-up.
#[test]
fn sync_info_v2_single_header_payload_roundtrips_scala_source_derivation() {
    let captured_payload = load_hex("sync_info/v2_single_header_payload.hex");

    let info = deserialize_sync_info(&captured_payload).expect("payload decode");
    let headers = match info {
        SyncInfo::V2 { headers } => headers,
        other => panic!("expected V2, got {other:?}"),
    };
    assert_eq!(headers.len(), 1, "one announced header");
    assert_eq!(headers[0].len(), 225, "header body length");

    // Same cross-crate oracle as Modifiers: the V2 payload carries
    // the raw header bytes (no id wrapping), so we just parse them
    // to confirm they're a real header in the ergo-ser shape.
    let mut r = ergo_primitives::reader::VlqReader::new(&headers[0]);
    let header = ergo_ser::header::read_header(&mut r).expect("V2-wrapped header parses");
    assert_eq!(header.version, 0x42, "block version through V2 envelope");

    // Roundtrip 1: payload-only.
    let re_payload = serialize_sync_info(&SyncInfo::V2 {
        headers: headers.clone(),
    });
    assert_eq!(
        re_payload, captured_payload,
        "V2 payload byte-identical roundtrip",
    );

    // Roundtrip 2: exercise the V2 path through the framing layer so
    // the wire-compat gap on code 65 V2 isn't limited to payload-only.
    // We wrap the captured payload in a frame, decode it back through
    // `deserialize_frame`, verify the frame header (magic/code/length/
    // checksum), then re-frame from the parsed `SyncInfo` and assert
    // byte-identity. The V2 full-frame hex itself remains a follow-up
    // (upstream Scala-side byte fixture), but the framing layer is now
    // exercised on V2 inputs.
    let framed = serialize_frame(
        &MAINNET_MAGIC,
        &MessageFrame {
            code: CODE_SYNC_INFO,
            payload: captured_payload.clone(),
        },
    );
    let (decoded_frame, consumed) = decode_one_frame(&framed);
    assert_eq!(
        consumed,
        framed.len(),
        "frame consumes whole synthetic V2 wrap"
    );
    assert_eq!(decoded_frame.code, CODE_SYNC_INFO);
    assert_eq!(
        decoded_frame.payload, captured_payload,
        "frame payload round-trips"
    );

    let re_framed = serialize_frame(
        &MAINNET_MAGIC,
        &MessageFrame {
            code: CODE_SYNC_INFO,
            payload: serialize_sync_info(&SyncInfo::V2 { headers }),
        },
    );
    assert_eq!(re_framed, framed, "V2 full-frame self-roundtrip identical");
}
