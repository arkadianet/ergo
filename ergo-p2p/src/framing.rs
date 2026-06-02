//! P2P message framing codec.
//!
//! Wire format [protocol, verified: MessageSerializer.scala]:
//!
//! Empty payload:  magic[4] || code[1] || length[4 BE i32 = 0]  (9 bytes)
//! With payload:   magic[4] || code[1] || length[4 BE i32] || checksum[4] || payload[length]
//!                 (13 + length bytes)
//!
//! Checksum = first 4 bytes of blake2b256(payload).
//! The framing layer uses raw big-endian encoding, NOT VLQ.

use ergo_primitives::digest::blake2b256;
use thiserror::Error;

pub const MAGIC_LENGTH: usize = 4;
pub const CHECKSUM_LENGTH: usize = 4;
pub const HEADER_LENGTH: usize = MAGIC_LENGTH + 1 + 4; // 9

pub const MAINNET_MAGIC: [u8; 4] = [1, 0, 2, 4];
pub const TESTNET_MAGIC: [u8; 4] = [2, 0, 2, 3];

/// Failures produced by [`serialize_frame`] / [`deserialize_frame`].
#[derive(Debug, Error)]
pub enum FrameError {
    /// The frame's leading magic bytes did not match the configured network.
    #[error("wrong magic bytes: expected {expected:?}, got {got:?}")]
    WrongMagic {
        /// Magic the decoder was configured for.
        expected: [u8; 4],
        /// Magic the frame actually carried.
        got: [u8; 4],
    },
    /// Frame declared a negative payload length — protocol violation.
    #[error("negative payload length: {0}")]
    NegativeLength(i32),
    /// Recomputed payload checksum did not match the frame's bytes 9..13.
    #[error("checksum mismatch")]
    ChecksumMismatch,
    /// Frame's `code` byte is not a registered message id.
    #[error("unknown message code: {0}")]
    UnknownCode(u8),
}

/// A parsed message frame (code + payload bytes).
#[derive(Debug, Clone)]
pub struct MessageFrame {
    /// Message code identifying the payload type.
    pub code: u8,
    /// Raw payload bytes; empty for codes that carry no body.
    pub payload: Vec<u8>,
}

/// Exact on-wire byte length of a frame carrying `payload_len` payload
/// bytes — the count [`serialize_frame`] produces and [`deserialize_frame`]
/// consumes. 9 bytes for an empty payload, `13 + payload_len` otherwise
/// (header + checksum + payload). Defined beside the (de)serializer from
/// the same constants and pinned to it by `wire_len_matches_serialize_frame`
/// so the two cannot drift. Used for per-peer byte accounting at the
/// transport boundary (post-handshake framed-message bytes).
pub fn wire_len(payload_len: usize) -> usize {
    if payload_len > 0 {
        HEADER_LENGTH + CHECKSUM_LENGTH + payload_len
    } else {
        HEADER_LENGTH
    }
}

/// Serialize a message frame to wire bytes.
pub fn serialize_frame(magic: &[u8; 4], frame: &MessageFrame) -> Vec<u8> {
    let data_len = frame.payload.len() as i32;
    let total = if data_len > 0 {
        HEADER_LENGTH + CHECKSUM_LENGTH + frame.payload.len()
    } else {
        HEADER_LENGTH
    };

    let mut buf = Vec::with_capacity(total);
    buf.extend_from_slice(magic);
    buf.push(frame.code);
    buf.extend_from_slice(&data_len.to_be_bytes());

    if data_len > 0 {
        let hash = blake2b256(&frame.payload);
        buf.extend_from_slice(&hash.as_bytes()[..CHECKSUM_LENGTH]);
        buf.extend_from_slice(&frame.payload);
    }

    buf
}

/// Attempt to deserialize one message frame from a byte buffer.
///
/// Returns `Ok(Some((frame, consumed)))` on success, where `consumed` is
/// the number of bytes used from the buffer.
/// Returns `Ok(None)` if the buffer doesn't contain a complete frame yet.
/// Returns `Err` for protocol violations (wrong magic, bad checksum, etc.).
pub fn deserialize_frame(
    magic: &[u8; 4],
    data: &[u8],
) -> Result<Option<(MessageFrame, usize)>, FrameError> {
    if data.len() < HEADER_LENGTH {
        return Ok(None); // incomplete
    }

    // Parse header
    let mut got_magic = [0u8; 4];
    got_magic.copy_from_slice(&data[..4]);
    let code = data[4];
    let length = i32::from_be_bytes(data[5..9].try_into().unwrap());

    // Negative length = malicious
    if length < 0 {
        return Err(FrameError::NegativeLength(length));
    }

    // Wrong magic
    if got_magic != *magic {
        return Err(FrameError::WrongMagic {
            expected: *magic,
            got: got_magic,
        });
    }

    if length == 0 {
        // Empty payload — frame is just the 9-byte header.
        return Ok(Some((
            MessageFrame {
                code,
                payload: Vec::new(),
            },
            HEADER_LENGTH,
        )));
    }

    // Non-empty payload: need header + checksum + payload
    let total_needed = HEADER_LENGTH + CHECKSUM_LENGTH + length as usize;
    if data.len() < total_needed {
        return Ok(None); // incomplete
    }

    let checksum = &data[9..13];
    let payload = &data[13..13 + length as usize];

    // Verify checksum
    let hash = blake2b256(payload);
    if &hash.as_bytes()[..CHECKSUM_LENGTH] != checksum {
        return Err(FrameError::ChecksumMismatch);
    }

    Ok(Some((
        MessageFrame {
            code,
            payload: payload.to_vec(),
        },
        total_needed,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_payload_roundtrip() {
        let frame = MessageFrame {
            code: 1,
            payload: Vec::new(),
        };
        let bytes = serialize_frame(&MAINNET_MAGIC, &frame);
        assert_eq!(bytes.len(), HEADER_LENGTH); // 9 bytes

        let (parsed, consumed) = deserialize_frame(&MAINNET_MAGIC, &bytes).unwrap().unwrap();
        assert_eq!(consumed, HEADER_LENGTH);
        assert_eq!(parsed.code, 1);
        assert!(parsed.payload.is_empty());
    }

    #[test]
    fn non_empty_payload_roundtrip() {
        let payload = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let frame = MessageFrame { code: 55, payload };
        let bytes = serialize_frame(&MAINNET_MAGIC, &frame);
        assert_eq!(bytes.len(), HEADER_LENGTH + CHECKSUM_LENGTH + 4);

        let (parsed, consumed) = deserialize_frame(&MAINNET_MAGIC, &bytes).unwrap().unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(parsed.code, 55);
        assert_eq!(parsed.payload, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn wire_len_matches_serialize_frame() {
        // wire_len must equal the bytes serialize_frame emits (and
        // deserialize_frame consumes) for both the empty and non-empty
        // framing branches — pins the per-peer byte accounting to the real
        // wire format so the helper can't drift from the codec.
        for payload in [Vec::new(), vec![0u8; 1], vec![0xABu8; 250]] {
            let frame = MessageFrame {
                code: 7,
                payload: payload.clone(),
            };
            let bytes = serialize_frame(&MAINNET_MAGIC, &frame);
            assert_eq!(
                wire_len(payload.len()),
                bytes.len(),
                "len {}",
                payload.len()
            );
            let (_, consumed) = deserialize_frame(&MAINNET_MAGIC, &bytes).unwrap().unwrap();
            assert_eq!(
                wire_len(payload.len()),
                consumed,
                "consumed len {}",
                payload.len()
            );
        }
    }

    #[test]
    fn incomplete_header_returns_none() {
        let result = deserialize_frame(&MAINNET_MAGIC, &[1, 0, 2, 4, 55]);
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn incomplete_payload_returns_none() {
        // Valid header saying 100 bytes of payload, but we only have header
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&MAINNET_MAGIC);
        bytes.push(55);
        bytes.extend_from_slice(&100i32.to_be_bytes());
        // Missing checksum and payload
        let result = deserialize_frame(&MAINNET_MAGIC, &bytes);
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn wrong_magic_returns_error() {
        let frame = MessageFrame {
            code: 1,
            payload: Vec::new(),
        };
        let bytes = serialize_frame(&TESTNET_MAGIC, &frame);
        let result = deserialize_frame(&MAINNET_MAGIC, &bytes);
        assert!(matches!(result, Err(FrameError::WrongMagic { .. })));
    }

    #[test]
    fn negative_length_returns_error() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&MAINNET_MAGIC);
        bytes.push(55);
        bytes.extend_from_slice(&(-1i32).to_be_bytes());
        let result = deserialize_frame(&MAINNET_MAGIC, &bytes);
        assert!(matches!(result, Err(FrameError::NegativeLength(-1))));
    }

    #[test]
    fn bad_checksum_returns_error() {
        let payload = vec![1, 2, 3, 4];
        let frame = MessageFrame { code: 55, payload };
        let mut bytes = serialize_frame(&MAINNET_MAGIC, &frame);
        // Corrupt the checksum (bytes 9-12)
        bytes[9] ^= 0xFF;
        let result = deserialize_frame(&MAINNET_MAGIC, &bytes);
        assert!(matches!(result, Err(FrameError::ChecksumMismatch)));
    }

    #[test]
    fn testnet_magic_roundtrip() {
        let frame = MessageFrame {
            code: 75,
            payload: vec![42],
        };
        let bytes = serialize_frame(&TESTNET_MAGIC, &frame);
        let (parsed, _) = deserialize_frame(&TESTNET_MAGIC, &bytes).unwrap().unwrap();
        assert_eq!(parsed.code, 75);
        assert_eq!(parsed.payload, vec![42]);
    }

    #[test]
    fn multiple_frames_in_buffer() {
        let f1 = MessageFrame {
            code: 1,
            payload: Vec::new(),
        };
        let f2 = MessageFrame {
            code: 55,
            payload: vec![10, 20],
        };
        let mut buf = serialize_frame(&MAINNET_MAGIC, &f1);
        buf.extend_from_slice(&serialize_frame(&MAINNET_MAGIC, &f2));

        let (parsed1, consumed1) = deserialize_frame(&MAINNET_MAGIC, &buf).unwrap().unwrap();
        assert_eq!(parsed1.code, 1);

        let (parsed2, _consumed2) = deserialize_frame(&MAINNET_MAGIC, &buf[consumed1..])
            .unwrap()
            .unwrap();
        assert_eq!(parsed2.code, 55);
        assert_eq!(parsed2.payload, vec![10, 20]);
    }
}
