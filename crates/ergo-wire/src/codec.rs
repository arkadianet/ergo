use blake2::{digest::consts::U32, Blake2b, Digest};
use ergo_settings::constants::{CHECKSUM_LENGTH, MAGIC_LENGTH, MESSAGE_HEADER_LENGTH};
use thiserror::Error;

/// Maximum message body size (2 MB). Rejects messages with a declared length
/// exceeding this limit to prevent memory exhaustion from malicious peers.
pub const MAX_MESSAGE_BODY_SIZE: i32 = 2_097_152;

#[derive(Debug, Error)]
pub enum FrameError {
    #[error("wrong magic bytes")]
    WrongMagic,
    #[error("negative data length")]
    NegativeLength,
    #[error("message too large ({0} bytes, max {MAX_MESSAGE_BODY_SIZE})")]
    MessageTooLarge(i32),
    #[error("checksum mismatch")]
    ChecksumMismatch,
    #[error("unknown message code: {0}")]
    UnknownCode(u8),
}

#[derive(Debug, Clone)]
pub struct RawMessage {
    pub code: u8,
    pub body: Vec<u8>,
}

/// Encode a P2P message frame:
/// magic(4) + code(1) + length(4 BE) [+ checksum(4) + body if body non-empty]
pub fn encode_message(magic: &[u8; 4], code: u8, body: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(MESSAGE_HEADER_LENGTH + CHECKSUM_LENGTH + body.len());
    buf.extend_from_slice(magic);
    buf.push(code);
    buf.extend_from_slice(&(body.len() as i32).to_be_bytes());

    if !body.is_empty() {
        let checksum = blake2b_checksum(body);
        buf.extend_from_slice(&checksum);
        buf.extend_from_slice(body);
    }

    buf
}

/// Decode a P2P message frame. Returns:
/// - Ok(None) if not enough data yet
/// - Ok(Some(RawMessage)) on success
/// - Err on protocol violation
pub fn decode_message(
    expected_magic: &[u8; 4],
    data: &[u8],
) -> Result<Option<RawMessage>, FrameError> {
    if data.len() < MESSAGE_HEADER_LENGTH {
        return Ok(None);
    }

    let magic = &data[0..MAGIC_LENGTH];
    if magic != expected_magic {
        return Err(FrameError::WrongMagic);
    }

    let code = data[MAGIC_LENGTH];
    let length = i32::from_be_bytes([
        data[MAGIC_LENGTH + 1],
        data[MAGIC_LENGTH + 2],
        data[MAGIC_LENGTH + 3],
        data[MAGIC_LENGTH + 4],
    ]);

    if length < 0 {
        return Err(FrameError::NegativeLength);
    }

    if length > MAX_MESSAGE_BODY_SIZE {
        return Err(FrameError::MessageTooLarge(length));
    }

    let length = length as usize;

    if length == 0 {
        return Ok(Some(RawMessage {
            code,
            body: Vec::new(),
        }));
    }

    let total_needed = MESSAGE_HEADER_LENGTH + CHECKSUM_LENGTH + length;
    if data.len() < total_needed {
        return Ok(None);
    }

    let checksum_start = MESSAGE_HEADER_LENGTH;
    let body_start = checksum_start + CHECKSUM_LENGTH;
    let received_checksum = &data[checksum_start..body_start];
    let body = &data[body_start..body_start + length];

    let expected_checksum = blake2b_checksum(body);
    if received_checksum != expected_checksum {
        return Err(FrameError::ChecksumMismatch);
    }

    Ok(Some(RawMessage {
        code,
        body: body.to_vec(),
    }))
}

fn blake2b_checksum(data: &[u8]) -> [u8; CHECKSUM_LENGTH] {
    let hash = Blake2b::<U32>::digest(data);
    let mut checksum = [0u8; CHECKSUM_LENGTH];
    checksum.copy_from_slice(&hash[..CHECKSUM_LENGTH]);
    checksum
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_empty_body_message() {
        let magic = [2u8, 0, 0, 1];
        let frame = encode_message(&magic, 1, &[]);
        assert_eq!(frame.len(), 9);
        assert_eq!(&frame[0..4], &magic);
        assert_eq!(frame[4], 1);
        assert_eq!(&frame[5..9], &0i32.to_be_bytes());
    }

    #[test]
    fn serialize_message_with_body() {
        let magic = [1u8, 0, 2, 4];
        let body = b"hello";
        let frame = encode_message(&magic, 55, body);
        assert_eq!(frame.len(), 18);
        assert_eq!(frame[4], 55);
        let length = i32::from_be_bytes([frame[5], frame[6], frame[7], frame[8]]);
        assert_eq!(length, 5);
    }

    #[test]
    fn deserialize_roundtrip() {
        let magic = [2u8, 0, 0, 1];
        let body = vec![1u8, 2, 3, 4, 5];
        let frame = encode_message(&magic, 33, &body);
        let parsed = decode_message(&magic, &frame).unwrap().unwrap();
        assert_eq!(parsed.code, 33);
        assert_eq!(parsed.body, body);
    }

    #[test]
    fn deserialize_wrong_magic_fails() {
        let magic = [2u8, 0, 0, 1];
        let wrong_magic = [1u8, 0, 2, 4];
        let frame = encode_message(&wrong_magic, 1, &[]);
        let result = decode_message(&magic, &frame);
        assert!(result.is_err());
    }

    #[test]
    fn deserialize_empty_body_message() {
        let magic = [2u8, 0, 0, 1];
        let frame = encode_message(&magic, 1, &[]);
        let parsed = decode_message(&magic, &frame).unwrap().unwrap();
        assert_eq!(parsed.code, 1);
        assert!(parsed.body.is_empty());
    }

    #[test]
    fn incomplete_data_returns_none() {
        let magic = [2u8, 0, 0, 1];
        let result = decode_message(&magic, &[2, 0, 0]).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn reject_message_exceeding_max_body_size() {
        let magic = [1u8, 0, 2, 4];
        // Craft a frame header with length = 3 MB (exceeds MAX_MESSAGE_BODY_SIZE of 2 MB).
        let oversized_length: i32 = 3 * 1024 * 1024;
        let mut frame = Vec::new();
        frame.extend_from_slice(&magic);
        frame.push(1); // code
        frame.extend_from_slice(&oversized_length.to_be_bytes());
        // We don't need checksum/body since the error triggers before reading them.
        let result = decode_message(&magic, &frame);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, FrameError::MessageTooLarge(len) if len == oversized_length),
            "expected MessageTooLarge, got: {err:?}"
        );
    }

    #[test]
    fn accept_message_at_max_body_size() {
        let magic = [1u8, 0, 2, 4];
        // A message exactly at MAX_MESSAGE_BODY_SIZE should be accepted (if enough
        // data is present). With insufficient data it returns None, not an error.
        let mut frame = Vec::new();
        frame.extend_from_slice(&magic);
        frame.push(1); // code
        frame.extend_from_slice(&MAX_MESSAGE_BODY_SIZE.to_be_bytes());
        // Not enough data for the full message — should return None (not error).
        let result = decode_message(&magic, &frame);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn reject_message_just_over_max_body_size() {
        let magic = [1u8, 0, 2, 4];
        let over_limit = MAX_MESSAGE_BODY_SIZE + 1;
        let mut frame = Vec::new();
        frame.extend_from_slice(&magic);
        frame.push(1);
        frame.extend_from_slice(&over_limit.to_be_bytes());
        let result = decode_message(&magic, &frame);
        assert!(matches!(
            result,
            Err(FrameError::MessageTooLarge(len)) if len == over_limit
        ));
    }
}
