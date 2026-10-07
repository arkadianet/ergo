//! Bounded, stable entry points for coverage-guided P2P fuzzing.
//!
//! These exercise the production codecs, independently of the consensus
//! generator registry. Rejections are expected; panics and violations of frame
//! boundaries or canonical fixed points are libFuzzer findings. No socket,
//! clock, database, panic-hook mutation or JVM process is needed per input.

use ergo_p2p::framing::{self, MessageFrame, MAINNET_MAGIC, TESTNET_MAGIC};
use ergo_p2p::handshake::{self, MAX_HANDSHAKE_SIZE};
use ergo_p2p::message;

/// Bound work by actual input length, never by an untrusted declared length.
pub const MAX_NETWORK_FUZZ_INPUT: usize = 1_048_576;
const MAX_PEERS: usize = 32;

/// Exercise raw framing, selected incomplete prefixes and payload dispatch.
///
/// Both network magics are checked. A valid frame must consume exactly its
/// declared bytes and reproduce them verbatim, including its checksum; bytes
/// after it belong to the next frame. The header decoder never allocates a
/// declared body, even when the length is near `i32::MAX`.
pub fn fuzz_frame(data: &[u8]) {
    let data = &data[..data.len().min(MAX_NETWORK_FUZZ_INPUT)];
    for magic in [MAINNET_MAGIC, TESTNET_MAGIC] {
        check_frame(&magic, data);
        // Split around all framing boundaries plus a mutation-selected body
        // position. A fixed number of prefixes avoids quadratic work.
        for len in [0, 4, 5, 8, 9, 12, 13, data.len() / 2] {
            check_frame(&magic, &data[..len.min(data.len())]);
        }
    }
    if let Some((&code, payload)) = data.split_first() {
        // Wrapping the input in a correct checksum gets arbitrary payloads to
        // their decoders instead of spending every mutation on checksum errors.
        let frame = MessageFrame {
            code,
            payload: payload.to_vec(),
        };
        let bytes = framing::serialize_frame(&MAINNET_MAGIC, &frame);
        check_frame(&MAINNET_MAGIC, &bytes);
    }
}

fn check_frame(magic: &[u8; 4], data: &[u8]) {
    let header = framing::parse_frame_header(magic, data);
    if let Ok(Some((frame, consumed))) = framing::deserialize_frame(magic, data) {
        let header = header.expect("accepted frame has a valid header").unwrap();
        assert_eq!(header.code, frame.code);
        assert_eq!(header.payload_len, frame.payload.len());
        assert_eq!(consumed, framing::wire_len(frame.payload.len()));
        assert!(consumed <= data.len());
        assert_eq!(framing::serialize_frame(magic, &frame), data[..consumed]);
        check_payload(frame.code, &frame.payload);
    }
}

/// Exercise raw handshakes and their consumed-byte boundary.
pub fn fuzz_handshake(data: &[u8]) {
    // Include the oversize rejection rather than truncating it into a legal
    // handshake. This also keeps the parser's own production size cap covered.
    let data = &data[..data.len().min(MAX_HANDSHAKE_SIZE + 1)];
    if let Ok((handshake, consumed)) = handshake::deserialize_handshake_with_consumed(data) {
        assert!(consumed <= data.len());
        let canonical = handshake::serialize_handshake(&handshake);
        // Lossy UTF-8 decoding can expand short strings before serialization.
        // Re-encoding can therefore exceed the handshake admission cap. That
        // is a size rejection, not evidence of a framing or decoder crash.
        if canonical.len() <= MAX_HANDSHAKE_SIZE {
            let (reparsed, consumed) = handshake::deserialize_handshake_with_consumed(&canonical)
                .expect("canonical admitted handshake decodes");
            assert_eq!(consumed, canonical.len());
            assert_eq!(handshake::serialize_handshake(&reparsed), canonical);
        }
    }
}

/// First byte is a wire message code; the remainder is its raw payload.
pub fn fuzz_message(data: &[u8]) {
    let data = &data[..data.len().min(MAX_NETWORK_FUZZ_INPUT)];
    if let Some((&code, payload)) = data.split_first() {
        check_payload(code, payload);
    }
}

fn check_payload(code: u8, payload: &[u8]) {
    if code == message::CODE_HANDSHAKE {
        fuzz_handshake(payload);
        return;
    }
    if let Some(canonical) = canonical_payload(code, payload) {
        let second = canonical_payload(code, &canonical)
            .expect("serialized P2P payload must decode and serialize again");
        assert_eq!(canonical, second, "P2P payload canonical fixed point");
    }
}

fn canonical_payload(code: u8, payload: &[u8]) -> Option<Vec<u8>> {
    use message::*;
    match code {
        CODE_GET_PEERS => deserialize_get_peers(payload)
            .ok()
            .map(|()| serialize_get_peers()),
        CODE_PEERS => deserialize_peers(payload, MAX_PEERS)
            .ok()
            .map(|v| serialize_peers(&v)),
        CODE_INV | CODE_REQUEST_MODIFIER => deserialize_inv(payload)
            .ok()
            .and_then(|v| serialize_inv(&v).ok()),
        CODE_MODIFIER => deserialize_modifiers(payload)
            .ok()
            .and_then(|v| serialize_modifiers(&v).ok()),
        CODE_SYNC_INFO => deserialize_sync_info(payload)
            .ok()
            .and_then(|v| serialize_sync_info(&v).ok()),
        CODE_GET_SNAPSHOTS_INFO => deserialize_get_snapshots_info(payload)
            .ok()
            .map(|()| serialize_get_snapshots_info()),
        CODE_SNAPSHOTS_INFO => deserialize_snapshots_info(payload)
            .ok()
            .and_then(|v| serialize_snapshots_info(&v).ok()),
        CODE_GET_MANIFEST => deserialize_get_manifest(payload)
            .ok()
            .map(|v| serialize_get_manifest(&v)),
        CODE_MANIFEST => deserialize_manifest(payload)
            .ok()
            .and_then(|v| serialize_manifest(&v).ok()),
        CODE_GET_UTXO_CHUNK => deserialize_get_utxo_chunk(payload)
            .ok()
            .map(|v| serialize_get_utxo_chunk(&v)),
        CODE_UTXO_CHUNK => deserialize_utxo_chunk(payload)
            .ok()
            .and_then(|v| serialize_utxo_chunk(&v).ok()),
        CODE_GET_NIPOPOW_PROOF => deserialize_get_nipopow_proof(payload)
            .ok()
            .map(|v| serialize_get_nipopow_proof(&v)),
        CODE_NIPOPOW_PROOF => deserialize_nipopow_proof(payload)
            .ok()
            .and_then(|v| serialize_nipopow_proof(&v).ok()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    fn vector(path: &str) -> Vec<u8> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../test-vectors/ergo-p2p")
            .join(path);
        hex::decode(std::fs::read_to_string(path).unwrap().trim()).unwrap()
    }

    // ----- happy path -----

    #[test]
    fn all_message_codes_and_arbitrary_payloads_complete() {
        // A bounded deterministic mutation smoke campaign covers every code,
        // including unknown codes. libFuzzer supplies deeper coverage nightly.
        for code in 0..=u8::MAX {
            for len in [0, 1, 2, 8, 32, 127, 255] {
                let mut input = vec![code];
                input.extend((0..len).map(|i| code.wrapping_add(i as u8)));
                fuzz_message(&input);
                fuzz_frame(&input);
                fuzz_handshake(&input);
            }
        }
    }

    // ----- error paths -----

    #[test]
    fn declared_frame_lengths_and_truncated_checksums_complete() {
        for length in [i32::MIN, -1, 0, 1, 8_194_304, i32::MAX] {
            let mut input = MAINNET_MAGIC.to_vec();
            input.push(message::CODE_MODIFIER);
            input.extend_from_slice(&length.to_be_bytes());
            for suffix in 0..=4 {
                let mut bytes = input.clone();
                bytes.extend(std::iter::repeat_n(0, suffix));
                fuzz_frame(&bytes);
            }
        }
    }

    #[test]
    fn handshake_size_cap_and_signed_feature_count_complete() {
        fuzz_handshake(&vec![0xff; MAX_HANDSHAKE_SIZE + 1]);
        // timestamp, nonempty agent, version, empty node, absent address,
        // negative signed feature count.
        fuzz_handshake(&[0, 1, b'a', 6, 0, 6, 0, 0, 0xff]);
    }

    // ----- oracle parity -----

    #[test]
    fn scala_wire_vectors_and_every_truncation_complete() {
        for path in [
            "inv/header_single_mainnet.hex",
            "request_modifier/header_single_mainnet.hex",
            "modifiers/header_single_mainnet.hex",
            "sync_info/v1_single_header_mainnet.hex",
        ] {
            let bytes = vector(path);
            let (frame, consumed) = framing::deserialize_frame(&MAINNET_MAGIC, &bytes)
                .unwrap()
                .unwrap();
            assert_eq!(consumed, bytes.len());
            for end in 0..=bytes.len() {
                fuzz_frame(&bytes[..end]);
            }
            let mut payload = vec![frame.code];
            payload.extend_from_slice(&frame.payload);
            fuzz_message(&payload);
        }
    }
}
