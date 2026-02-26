//! Binary serialization of Ergo AD proofs, matching `ADProofsSerializer.scala`.

use ergo_types::ad_proofs::ADProofs;
use ergo_types::modifier_id::ModifierId;

use crate::vlq::{get_uint, put_uint, CodecError};

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

/// Serialize `ADProofs` into its wire format.
///
/// Wire layout:
/// ```text
/// [32 bytes: header_id]
/// [VLQ UInt: proof_length]
/// [proof_length bytes: proof_bytes]
/// ```
pub fn serialize_ad_proofs(proofs: &ADProofs) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32 + 5 + proofs.proof_bytes.len());

    // header_id: 32 bytes
    buf.extend_from_slice(&proofs.header_id.0);

    // proof_length: VLQ UInt
    put_uint(&mut buf, proofs.proof_bytes.len() as u32);

    // proof_bytes: variable
    buf.extend_from_slice(&proofs.proof_bytes);

    buf
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Parse `ADProofs` from its serialized wire bytes.
pub fn parse_ad_proofs(data: &[u8]) -> Result<ADProofs, CodecError> {
    let reader = &mut &data[..];

    // header_id: 32 bytes
    let header_id = ModifierId(read_array::<32>(reader)?);

    // proof_length: VLQ UInt
    let proof_length = get_uint(reader)? as usize;

    // proof_bytes: proof_length bytes
    let proof_bytes = read_bytes(reader, proof_length)?;

    Ok(ADProofs {
        header_id,
        proof_bytes,
    })
}

// ---------------------------------------------------------------------------
// Low-level reader helpers
// ---------------------------------------------------------------------------

fn read_array<const N: usize>(reader: &mut &[u8]) -> Result<[u8; N], CodecError> {
    if reader.len() < N {
        return Err(CodecError::UnexpectedEof);
    }
    let mut arr = [0u8; N];
    arr.copy_from_slice(&reader[..N]);
    *reader = &reader[N..];
    Ok(arr)
}

fn read_bytes(reader: &mut &[u8], len: usize) -> Result<Vec<u8>, CodecError> {
    if reader.len() < len {
        return Err(CodecError::UnexpectedEof);
    }
    let data = reader[..len].to_vec();
    *reader = &reader[len..];
    Ok(data)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ad_proofs_roundtrip() {
        let proofs = ADProofs {
            header_id: ModifierId([0xAA; 32]),
            proof_bytes: vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03],
        };
        let bytes = serialize_ad_proofs(&proofs);
        let parsed = parse_ad_proofs(&bytes).unwrap();
        assert_eq!(parsed, proofs);
    }

    #[test]
    fn ad_proofs_empty_proof() {
        let proofs = ADProofs {
            header_id: ModifierId([0xBB; 32]),
            proof_bytes: Vec::new(),
        };
        let bytes = serialize_ad_proofs(&proofs);
        let parsed = parse_ad_proofs(&bytes).unwrap();
        assert_eq!(parsed, proofs);
        assert!(parsed.proof_bytes.is_empty());
    }

    #[test]
    fn ad_proofs_large_proof() {
        let proofs = ADProofs {
            header_id: ModifierId([0xCC; 32]),
            proof_bytes: vec![0x42; 10_000],
        };
        let bytes = serialize_ad_proofs(&proofs);
        let parsed = parse_ad_proofs(&bytes).unwrap();
        assert_eq!(parsed, proofs);
        assert_eq!(parsed.proof_bytes.len(), 10_000);
    }

    #[test]
    fn ad_proofs_format_header_id_first() {
        let header_id = ModifierId([0xEE; 32]);
        let proofs = ADProofs {
            header_id,
            proof_bytes: vec![0x01, 0x02, 0x03],
        };
        let bytes = serialize_ad_proofs(&proofs);
        // First 32 bytes must be the header_id
        assert_eq!(&bytes[..32], &[0xEE; 32]);
    }

    #[test]
    fn ad_proofs_parse_truncated_returns_error() {
        let proofs = ADProofs {
            header_id: ModifierId([0xDD; 32]),
            proof_bytes: vec![0x01, 0x02, 0x03, 0x04, 0x05],
        };
        let bytes = serialize_ad_proofs(&proofs);
        // Truncate: only keep header_id + part of VLQ length
        let result = parse_ad_proofs(&bytes[..20]);
        assert!(result.is_err());
    }
}
