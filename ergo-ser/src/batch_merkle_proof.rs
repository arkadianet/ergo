//! Batch Merkle proof codec — the wire format used by scorex-utils
//! `BatchMerkleProofSerializer` for compact multi-leaf proofs. The
//! NiPoPoW interlinks proof (one per `PoPowHeader`) is encoded with
//! this format.
//!
//! Wire layout (mirrors `scrypto BatchMerkleProofSerializer.scala`,
//! `digest_size = 32`, `index_size = 4`, `side_size = 1`):
//!
//! ```text
//! i32 num_indices  (big-endian, raw 4 bytes)
//! i32 num_proofs   (big-endian, raw 4 bytes)
//! [num_indices x { i32 index_be, [u8; 32] digest }]
//! [num_proofs  x { [u8; 32] digest, u8 side }]
//! ```
//!
//! A `digest` of all 32 zero bytes in the **proofs** section maps
//! to `EmptyByteArray` — the odd-trailing sibling case during the
//! merkle reduction. Matching Scala's encoding ambiguates a real
//! all-zero digest with the empty marker; we mirror that for
//! parity (probability of a genuine all-zero Blake2b256 output is
//! negligible).

use ergo_primitives::reader::{ReadError, VlqReader};

use crate::error::WriteError;

/// Side of the sibling that a proof entry hashes against during the
/// merkle reduction. Mirrors scrypto `scorex.crypto.authds.Side`
/// where `LeftSide = 0`, `RightSide = 1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// The proof's `digest` is on the LEFT of the current node when
    /// hashing the next level. Hash order: `proof.digest ++ leaf`.
    Left,
    /// Hash order: `leaf ++ proof.digest`.
    Right,
}

impl Side {
    /// Convert to the byte representation used on the wire.
    pub fn as_byte(self) -> u8 {
        match self {
            Self::Left => 0,
            Self::Right => 1,
        }
    }

    /// Decode from the wire byte. Any value other than 0 maps to
    /// `Right` — matches Scala's `asInstanceOf[Side]` cast which is
    /// permissive for non-zero bytes.
    pub fn from_byte(b: u8) -> Self {
        if b == 0 {
            Self::Left
        } else {
            Self::Right
        }
    }
}

/// A single proof step: a sibling digest and which side it pairs on.
/// `None` digest means "empty sibling" (odd-trailing case during the
/// merkle reduction — the parent is computed as
/// `Blake2b256(0x01 ++ left)` with no right child).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofEntry {
    /// Sibling digest. `None` represents the odd-trailing empty
    /// sibling (Scala's `EmptyByteArray`).
    pub digest: Option<[u8; 32]>,
    /// Which side the sibling is on when hashing the next level.
    pub side: Side,
}

/// Compact multi-leaf merkle proof. Verifies up to N leaves against
/// a single root digest by combining a per-leaf branch with shared
/// internal-node hashes.
///
/// Construction: Scala's `BatchMerkleProof.indices` is a sequence of
/// `(leaf_index, leaf_digest)` pairs (the leaves being proved);
/// `proofs` is the bottom-up sequence of sibling digests used during
/// the reduction.
///
/// Verification: see `ergo-validation::popow::merkle::verify_batch_merkle_proof`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchMerkleProof {
    /// Leaves under proof, each as `(leaf_index, leaf_digest)`.
    pub indices: Vec<(u32, [u8; 32])>,
    /// Sibling-digest path bottom-up.
    pub proofs: Vec<ProofEntry>,
}

/// Serialize a `BatchMerkleProof` to the wire byte format. Mirrors
/// scrypto `BatchMerkleProofSerializer.serialize`.
pub fn serialize_batch_merkle_proof(bmp: &BatchMerkleProof) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + bmp.indices.len() * 36 + bmp.proofs.len() * 33);
    out.extend_from_slice(&(bmp.indices.len() as u32).to_be_bytes());
    out.extend_from_slice(&(bmp.proofs.len() as u32).to_be_bytes());
    for (idx, digest) in &bmp.indices {
        out.extend_from_slice(&idx.to_be_bytes());
        out.extend_from_slice(digest);
    }
    for entry in &bmp.proofs {
        match entry.digest {
            Some(d) => out.extend_from_slice(&d),
            // EmptyByteArray serializes as 32 zero bytes.
            None => out.extend_from_slice(&[0u8; 32]),
        }
        out.push(entry.side.as_byte());
    }
    out
}

/// Deserialize a `BatchMerkleProof` from the wire byte format.
/// Mirrors scrypto `BatchMerkleProofSerializer.deserialize`. Returns
/// `WriteError::InvalidData` on truncated input or size mismatch.
pub fn deserialize_batch_merkle_proof(bytes: &[u8]) -> Result<BatchMerkleProof, WriteError> {
    if bytes.len() < 8 {
        return Err(WriteError::InvalidData(format!(
            "BatchMerkleProof: input too short ({} bytes, need ≥ 8)",
            bytes.len()
        )));
    }
    let num_indices = u32::from_be_bytes(bytes[0..4].try_into().expect("4 bytes")) as usize;
    let num_proofs = u32::from_be_bytes(bytes[4..8].try_into().expect("4 bytes")) as usize;

    let indices_size = num_indices * 36; // 4-byte index + 32-byte digest
    let proofs_size = num_proofs * 33; // 32-byte digest + 1-byte side
    let expected_total = 8 + indices_size + proofs_size;
    if bytes.len() != expected_total {
        return Err(WriteError::InvalidData(format!(
            "BatchMerkleProof: invalid size — expected {expected_total} bytes for \
             {num_indices} indices + {num_proofs} proofs, got {}",
            bytes.len()
        )));
    }

    let mut indices = Vec::with_capacity(num_indices);
    let mut pos = 8;
    for _ in 0..num_indices {
        let idx = u32::from_be_bytes(bytes[pos..pos + 4].try_into().expect("4 bytes"));
        pos += 4;
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&bytes[pos..pos + 32]);
        pos += 32;
        indices.push((idx, digest));
    }

    let mut proofs = Vec::with_capacity(num_proofs);
    for _ in 0..num_proofs {
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&bytes[pos..pos + 32]);
        pos += 32;
        let side = Side::from_byte(bytes[pos]);
        pos += 1;
        // Scala parity: all-zero 32-byte digest decodes as
        // `EmptyByteArray` (the odd-trailing empty sibling case).
        let digest_opt = if digest.iter().all(|&b| b == 0) {
            None
        } else {
            Some(digest)
        };
        proofs.push(ProofEntry {
            digest: digest_opt,
            side,
        });
    }

    Ok(BatchMerkleProof { indices, proofs })
}

/// Deserialize via a [`VlqReader`] consuming exactly the expected
/// number of bytes. Convenience for nested codecs that hold the
/// proof as a length-prefixed blob.
pub fn read_batch_merkle_proof(
    r: &mut VlqReader,
    expected_bytes: usize,
) -> Result<BatchMerkleProof, ReadError> {
    let bytes = r.get_bytes(expected_bytes)?.to_vec();
    deserialize_batch_merkle_proof(&bytes)
        .map_err(|e| ReadError::InvalidData(format!("BatchMerkleProof: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    fn proof_entry(d: [u8; 32], side: Side) -> ProofEntry {
        ProofEntry {
            digest: Some(d),
            side,
        }
    }

    // ----- round-trips -----

    #[test]
    fn empty_proof_roundtrips() {
        let bmp = BatchMerkleProof {
            indices: vec![],
            proofs: vec![],
        };
        let bytes = serialize_batch_merkle_proof(&bmp);
        assert_eq!(bytes.len(), 8); // just the two u32 counts
        let parsed = deserialize_batch_merkle_proof(&bytes).unwrap();
        assert_eq!(parsed, bmp);
    }

    #[test]
    fn single_index_single_proof_roundtrips() {
        let bmp = BatchMerkleProof {
            indices: vec![(0u32, [0xAA; 32])],
            proofs: vec![proof_entry([0xBB; 32], Side::Right)],
        };
        let bytes = serialize_batch_merkle_proof(&bmp);
        let parsed = deserialize_batch_merkle_proof(&bytes).unwrap();
        assert_eq!(parsed, bmp);
    }

    #[test]
    fn empty_sibling_digest_decodes_as_none() {
        // Empty-sibling case: a 32-zero digest in a proof entry
        // round-trips as Some(None) (the digest field is None).
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0u32.to_be_bytes()); // 0 indices
        bytes.extend_from_slice(&1u32.to_be_bytes()); // 1 proof entry
        bytes.extend_from_slice(&[0u8; 32]); // empty sibling
        bytes.push(0); // Side::Left
        let parsed = deserialize_batch_merkle_proof(&bytes).unwrap();
        assert_eq!(parsed.proofs.len(), 1);
        assert!(parsed.proofs[0].digest.is_none());
        assert_eq!(parsed.proofs[0].side, Side::Left);
        // Re-serialize: empty digest serializes back to 32 zeros.
        let re_bytes = serialize_batch_merkle_proof(&parsed);
        assert_eq!(re_bytes, bytes);
    }

    // ----- error paths -----

    #[test]
    fn truncated_input_below_header_size_errors() {
        let bytes = vec![0u8; 7]; // less than 8-byte header
        assert!(deserialize_batch_merkle_proof(&bytes).is_err());
    }

    #[test]
    fn size_mismatch_errors() {
        // Claim 2 indices but supply bytes for only 1.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&2u32.to_be_bytes()); // 2 indices
        bytes.extend_from_slice(&0u32.to_be_bytes()); // 0 proofs
        bytes.extend_from_slice(&0u32.to_be_bytes()); // 1 index, 4 bytes
        bytes.extend_from_slice(&[0u8; 32]); // 1 digest, 32 bytes
                                             // Only 1 of 2 indices supplied; total = 8 + 36 = 44, but claim wants 8 + 72 = 80.
        assert!(deserialize_batch_merkle_proof(&bytes).is_err());
    }

    #[test]
    fn side_byte_nonzero_maps_to_right() {
        assert_eq!(Side::from_byte(0), Side::Left);
        assert_eq!(Side::from_byte(1), Side::Right);
        assert_eq!(Side::from_byte(255), Side::Right); // permissive Scala parity
    }
}
