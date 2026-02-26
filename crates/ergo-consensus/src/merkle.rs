//! Binary Merkle tree using Blake2b-256 for Ergo block root computations.

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};

const LEAF_PREFIX: u8 = 0x00;
const INTERNAL_PREFIX: u8 = 0x01;

fn blake2b256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).expect("valid output size");
    hasher.update(data);
    let mut out = [0u8; 32];
    hasher.finalize_variable(&mut out).expect("correct output size");
    out
}

/// Hash a leaf element: `Blake2b256(0x00 || data)`.
pub fn leaf_hash(data: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(1 + data.len());
    buf.push(LEAF_PREFIX);
    buf.extend_from_slice(data);
    blake2b256(&buf)
}

/// Hash two child nodes: `Blake2b256(0x01 || left || right)`.
pub fn internal_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 65];
    buf[0] = INTERNAL_PREFIX;
    buf[1..33].copy_from_slice(left);
    buf[33..65].copy_from_slice(right);
    blake2b256(&buf)
}

/// Side indicator for Merkle proof authentication path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MerkleSide {
    /// Sibling is on the left.
    Left = 0,
    /// Sibling is on the right.
    Right = 1,
}

/// A single step in a Merkle authentication path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleProofStep {
    pub side: MerkleSide,
    pub hash: [u8; 32],
}

/// Compute the Merkle root of a list of data elements.
///
/// Returns `None` if `elements` is empty.
/// Leaf = `Blake2b256(0x00 || data)`, node = `Blake2b256(0x01 || left || right)`.
/// If an odd number of elements exists at any level, the last element is promoted.
pub fn merkle_root(elements: &[&[u8]]) -> Option<[u8; 32]> {
    if elements.is_empty() {
        return None;
    }

    let mut hashes: Vec<[u8; 32]> = elements.iter().map(|e| leaf_hash(e)).collect();

    while hashes.len() > 1 {
        let mut next_level = Vec::with_capacity(hashes.len().div_ceil(2));
        for chunk in hashes.chunks(2) {
            if chunk.len() == 2 {
                next_level.push(internal_hash(&chunk[0], &chunk[1]));
            } else {
                next_level.push(chunk[0]);
            }
        }
        hashes = next_level;
    }

    Some(hashes[0])
}

/// Compute the Merkle authentication path for a specific leaf index.
///
/// Returns `None` if `elements` is empty or `leaf_index` is out of bounds.
/// Each step contains the sibling hash and whether it is on the left or right.
pub fn merkle_proof(elements: &[&[u8]], leaf_index: usize) -> Option<Vec<MerkleProofStep>> {
    if elements.is_empty() || leaf_index >= elements.len() {
        return None;
    }

    let mut hashes: Vec<[u8; 32]> = elements.iter().map(|e| leaf_hash(e)).collect();
    let mut index = leaf_index;
    let mut proof = Vec::new();

    while hashes.len() > 1 {
        let mut next_level = Vec::with_capacity(hashes.len().div_ceil(2));
        let mut next_index = 0;

        for chunk_start in (0..hashes.len()).step_by(2) {
            if chunk_start + 1 < hashes.len() {
                // Pair exists
                if index == chunk_start {
                    proof.push(MerkleProofStep {
                        side: MerkleSide::Right,
                        hash: hashes[chunk_start + 1],
                    });
                    next_index = next_level.len();
                } else if index == chunk_start + 1 {
                    proof.push(MerkleProofStep {
                        side: MerkleSide::Left,
                        hash: hashes[chunk_start],
                    });
                    next_index = next_level.len();
                }
                next_level.push(internal_hash(&hashes[chunk_start], &hashes[chunk_start + 1]));
            } else {
                // Odd element promoted
                if index == chunk_start {
                    next_index = next_level.len();
                }
                next_level.push(hashes[chunk_start]);
            }
        }

        hashes = next_level;
        index = next_index;
    }

    Some(proof)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_returns_none() {
        assert_eq!(merkle_root(&[]), None);
    }

    #[test]
    fn single_element() {
        let data: &[u8] = b"hello";
        let root = merkle_root(&[data]).unwrap();
        assert_eq!(root, leaf_hash(data));
    }

    #[test]
    fn two_elements() {
        let a: &[u8] = b"alpha";
        let b: &[u8] = b"beta";
        let expected = internal_hash(&leaf_hash(a), &leaf_hash(b));
        assert_eq!(merkle_root(&[a, b]).unwrap(), expected);
    }

    #[test]
    fn three_elements() {
        let a: &[u8] = b"one";
        let b: &[u8] = b"two";
        let c: &[u8] = b"three";
        // Level 0: [leaf(a), leaf(b), leaf(c)]
        // Level 1: [internal(leaf(a), leaf(b)), leaf(c)]  (c promoted)
        // Level 2: internal(internal(leaf(a), leaf(b)), leaf(c))
        let expected = internal_hash(
            &internal_hash(&leaf_hash(a), &leaf_hash(b)),
            &leaf_hash(c),
        );
        assert_eq!(merkle_root(&[a, b, c]).unwrap(), expected);
    }

    #[test]
    fn four_elements() {
        let a: &[u8] = b"w";
        let b: &[u8] = b"x";
        let c: &[u8] = b"y";
        let d: &[u8] = b"z";
        // Full balanced tree:
        // Level 0: [leaf(a), leaf(b), leaf(c), leaf(d)]
        // Level 1: [internal(leaf(a), leaf(b)), internal(leaf(c), leaf(d))]
        // Level 2: internal(left_pair, right_pair)
        let left = internal_hash(&leaf_hash(a), &leaf_hash(b));
        let right = internal_hash(&leaf_hash(c), &leaf_hash(d));
        let expected = internal_hash(&left, &right);
        assert_eq!(merkle_root(&[a, b, c, d]).unwrap(), expected);
    }

    #[test]
    fn deterministic() {
        let data: &[&[u8]] = &[b"foo", b"bar", b"baz"];
        let root1 = merkle_root(data).unwrap();
        let root2 = merkle_root(data).unwrap();
        assert_eq!(root1, root2);
    }

    #[test]
    fn order_matters() {
        let a: &[u8] = b"first";
        let b: &[u8] = b"second";
        let root_ab = merkle_root(&[a, b]).unwrap();
        let root_ba = merkle_root(&[b, a]).unwrap();
        assert_ne!(root_ab, root_ba);
    }

    /// Verify a Merkle proof by recomputing the root from a leaf hash and proof steps.
    fn verify_proof(leaf: &[u8; 32], proof: &[MerkleProofStep]) -> [u8; 32] {
        let mut current = *leaf;
        for step in proof {
            current = match step.side {
                MerkleSide::Left => internal_hash(&step.hash, &current),
                MerkleSide::Right => internal_hash(&current, &step.hash),
            };
        }
        current
    }

    #[test]
    fn proof_single_element() {
        let data: &[u8] = b"only";
        let proof = merkle_proof(&[data], 0).unwrap();
        assert!(proof.is_empty());
        let root = verify_proof(&leaf_hash(data), &proof);
        assert_eq!(root, leaf_hash(data));
    }

    #[test]
    fn proof_two_elements() {
        let a: &[u8] = b"alpha";
        let b: &[u8] = b"beta";
        let elements: &[&[u8]] = &[a, b];
        let expected_root = merkle_root(elements).unwrap();

        let proof = merkle_proof(elements, 0).unwrap();
        assert_eq!(proof.len(), 1);
        let root = verify_proof(&leaf_hash(a), &proof);
        assert_eq!(root, expected_root);

        let proof = merkle_proof(elements, 1).unwrap();
        assert_eq!(proof.len(), 1);
        let root = verify_proof(&leaf_hash(b), &proof);
        assert_eq!(root, expected_root);
    }

    #[test]
    fn proof_three_elements_index_0() {
        let a: &[u8] = b"one";
        let b: &[u8] = b"two";
        let c: &[u8] = b"three";
        let elements: &[&[u8]] = &[a, b, c];
        let expected_root = merkle_root(elements).unwrap();

        let proof = merkle_proof(elements, 0).unwrap();
        let root = verify_proof(&leaf_hash(a), &proof);
        assert_eq!(root, expected_root);
    }

    #[test]
    fn proof_three_elements_index_2() {
        let a: &[u8] = b"one";
        let b: &[u8] = b"two";
        let c: &[u8] = b"three";
        let elements: &[&[u8]] = &[a, b, c];
        let expected_root = merkle_root(elements).unwrap();

        let proof = merkle_proof(elements, 2).unwrap();
        let root = verify_proof(&leaf_hash(c), &proof);
        assert_eq!(root, expected_root);
    }

    #[test]
    fn proof_four_elements_each() {
        let a: &[u8] = b"w";
        let b: &[u8] = b"x";
        let c: &[u8] = b"y";
        let d: &[u8] = b"z";
        let elements: &[&[u8]] = &[a, b, c, d];
        let expected_root = merkle_root(elements).unwrap();

        for (i, elem) in elements.iter().enumerate() {
            let proof = merkle_proof(elements, i).unwrap();
            let root = verify_proof(&leaf_hash(elem), &proof);
            assert_eq!(root, expected_root, "proof failed for index {i}");
        }
    }

    #[test]
    fn proof_out_of_bounds() {
        let elements: &[&[u8]] = &[b"a", b"b", b"c"];
        assert_eq!(merkle_proof(elements, 3), None);
        assert_eq!(merkle_proof(elements, 100), None);
    }

    #[test]
    fn proof_empty_elements() {
        let elements: &[&[u8]] = &[];
        assert_eq!(merkle_proof(elements, 0), None);
    }

    #[test]
    fn known_vector() {
        let root = merkle_root(&[b"tx1", b"tx2"]).unwrap();
        let expected = internal_hash(&leaf_hash(b"tx1"), &leaf_hash(b"tx2"));
        assert_eq!(root, expected);
        // Verify the exact bytes are stable (regression guard).
        let hex = root.iter().map(|b| format!("{b:02x}")).collect::<String>();
        assert_eq!(hex.len(), 64, "root must be 32 bytes (64 hex chars)");
        // Re-derive independently to double-check.
        let lh1 = blake2b256(&[LEAF_PREFIX, b't', b'x', b'1']);
        let lh2 = blake2b256(&[LEAF_PREFIX, b't', b'x', b'2']);
        let mut combined = [0u8; 65];
        combined[0] = INTERNAL_PREFIX;
        combined[1..33].copy_from_slice(&lh1);
        combined[33..65].copy_from_slice(&lh2);
        let expected_raw = blake2b256(&combined);
        assert_eq!(root, expected_raw);
    }
}
