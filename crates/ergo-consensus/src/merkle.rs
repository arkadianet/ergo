//! Binary Merkle tree for Ergo block root computations.
//!
//! Root computation delegates to `ergo-merkle-tree` (sigma-rust ecosystem) for
//! protocol-correct handling of odd-count levels (pairs with EmptyNode rather
//! than promoting the odd element).

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use ergo_merkle_tree::{MerkleNode, MerkleTree};

const LEAF_PREFIX: u8 = 0x00;
const INTERNAL_PREFIX: u8 = 0x01;

fn blake2b256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).expect("valid output size");
    hasher.update(data);
    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("correct output size");
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

/// Hash a single child paired with an empty node: `Blake2b256(0x01 || hash)`.
///
/// In the ergo-merkle-tree, when one child is an EmptyNode, the parent is
/// computed as a 33-byte hash (prefix + single child) rather than a 65-byte
/// hash (prefix + both children).
pub fn empty_child_hash(hash: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 33];
    buf[0] = INTERNAL_PREFIX;
    buf[1..33].copy_from_slice(hash);
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
    /// Sibling hash. `None` when the sibling is an empty node.
    pub hash: Option<[u8; 32]>,
}

/// The Merkle root for an empty sequence of elements.
///
/// Matches Scala's `Algos.emptyMerkleTreeRoot = Algos.hash(Array[Byte]())`.
pub fn empty_merkle_root() -> [u8; 32] {
    blake2b256(&[])
}

/// Compute the Merkle root of a list of data elements.
///
/// Returns `None` if `elements` is empty.
/// Delegates to `ergo-merkle-tree` for protocol-correct root computation.
pub fn merkle_root(elements: &[&[u8]]) -> Option<[u8; 32]> {
    if elements.is_empty() {
        return None;
    }
    let nodes: Vec<MerkleNode> = elements
        .iter()
        .map(|e| MerkleNode::from_bytes(e.to_vec()))
        .collect();
    let tree = MerkleTree::new(nodes);
    Some(tree.root_hash_special().0)
}

/// Compute the Merkle authentication path for a specific leaf index.
///
/// Returns `None` if `elements` is empty or `leaf_index` is out of bounds.
/// Each step contains the sibling hash (or `None` for empty nodes) and
/// whether the sibling is on the left or right.
///
/// The tree structure matches `ergo-merkle-tree`: odd-count levels are padded
/// with empty nodes rather than promoting the last element.
pub fn merkle_proof(elements: &[&[u8]], leaf_index: usize) -> Option<Vec<MerkleProofStep>> {
    if elements.is_empty() || leaf_index >= elements.len() {
        return None;
    }

    // Build leaf hashes, pad to even with empty node (None).
    let mut level: Vec<Option<[u8; 32]>> = elements.iter().map(|e| Some(leaf_hash(e))).collect();
    if level.len() % 2 == 1 {
        level.push(None);
    }

    let mut index = leaf_index;
    let mut proof = Vec::new();

    while level.len() > 1 {
        // Pad to even if needed (can happen at higher levels).
        if level.len() % 2 == 1 {
            level.push(None);
        }

        let mut next_level = Vec::with_capacity(level.len() / 2);
        let mut next_index = 0;

        for chunk_start in (0..level.len()).step_by(2) {
            let left = level[chunk_start];
            let right = level[chunk_start + 1];

            if index == chunk_start {
                // We're on the left, sibling is on the right.
                proof.push(MerkleProofStep {
                    side: MerkleSide::Right,
                    hash: right,
                });
                next_index = next_level.len();
            } else if index == chunk_start + 1 {
                // We're on the right, sibling is on the left.
                proof.push(MerkleProofStep {
                    side: MerkleSide::Left,
                    hash: left,
                });
                next_index = next_level.len();
            }

            // Compute parent hash.
            let parent = match (left, right) {
                (Some(l), Some(r)) => Some(internal_hash(&l, &r)),
                (Some(h), None) => Some(empty_child_hash(&h)),
                (None, Some(h)) => Some(empty_child_hash(&h)),
                (None, None) => None,
            };
            next_level.push(parent);
        }

        level = next_level;
        index = next_index;
    }

    Some(proof)
}

/// Verify a Merkle proof by recomputing the root from a leaf hash and proof steps.
pub fn verify_proof(leaf: &[u8; 32], proof: &[MerkleProofStep]) -> [u8; 32] {
    let mut current = *leaf;
    for step in proof {
        current = match (step.side, step.hash) {
            (_, None) => empty_child_hash(&current),
            (MerkleSide::Left, Some(h)) => internal_hash(&h, &current),
            (MerkleSide::Right, Some(h)) => internal_hash(&current, &h),
        };
    }
    current
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
        // Single element: paired with empty node → blake2b256(0x01 || leaf_hash)
        assert_eq!(root, empty_child_hash(&leaf_hash(data)));
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
        // Level 0: [leaf(a), leaf(b), leaf(c), Empty]
        // Level 1: [internal(leaf(a), leaf(b)), empty_child(leaf(c))]
        // Level 2: internal(level1[0], level1[1])
        let expected = internal_hash(
            &internal_hash(&leaf_hash(a), &leaf_hash(b)),
            &empty_child_hash(&leaf_hash(c)),
        );
        assert_eq!(merkle_root(&[a, b, c]).unwrap(), expected);
    }

    #[test]
    fn four_elements() {
        let a: &[u8] = b"w";
        let b: &[u8] = b"x";
        let c: &[u8] = b"y";
        let d: &[u8] = b"z";
        let left = internal_hash(&leaf_hash(a), &leaf_hash(b));
        let right = internal_hash(&leaf_hash(c), &leaf_hash(d));
        let expected = internal_hash(&left, &right);
        assert_eq!(merkle_root(&[a, b, c, d]).unwrap(), expected);
    }

    #[test]
    fn five_elements() {
        let bytes: &[u8] = &[1u8; 32];
        let h0x = leaf_hash(bytes);
        let h10 = internal_hash(&h0x, &h0x);
        let h12 = empty_child_hash(&h0x);
        let h20 = internal_hash(&h10, &h10);
        let h21 = empty_child_hash(&h12);
        let expected = internal_hash(&h20, &h21);
        // All 5 elements are the same byte pattern.
        let elems: Vec<&[u8]> = vec![bytes; 5];
        assert_eq!(merkle_root(&elems).unwrap(), expected);
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

    #[test]
    fn proof_single_element() {
        let data: &[u8] = b"only";
        let proof = merkle_proof(&[data], 0).unwrap();
        // Single element gets paired with empty node → 1 proof step.
        assert_eq!(proof.len(), 1);
        assert_eq!(proof[0].side, MerkleSide::Right);
        assert_eq!(proof[0].hash, None); // empty node sibling
        let root = verify_proof(&leaf_hash(data), &proof);
        assert_eq!(root, merkle_root(&[data]).unwrap());
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
    fn proof_five_elements_each() {
        let elements: Vec<Vec<u8>> = (0u8..5)
            .map(|i| {
                let mut d = vec![0u8; 32];
                d[0] = i;
                d
            })
            .collect();
        let refs: Vec<&[u8]> = elements.iter().map(|e| e.as_slice()).collect();
        let expected_root = merkle_root(&refs).unwrap();

        for (i, elem) in refs.iter().enumerate() {
            let proof = merkle_proof(&refs, i).unwrap();
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
        let hex = root.iter().map(|b| format!("{b:02x}")).collect::<String>();
        assert_eq!(hex.len(), 64, "root must be 32 bytes (64 hex chars)");
    }

    /// Cross-check: our merkle_root must agree with ergo-merkle-tree for various sizes.
    #[test]
    fn cross_check_with_ergo_merkle_tree() {
        for count in 1..=20 {
            let elements: Vec<Vec<u8>> = (0..count)
                .map(|i| {
                    let mut d = vec![0u8; 32];
                    d[0] = i as u8;
                    d
                })
                .collect();
            let refs: Vec<&[u8]> = elements.iter().map(|e| e.as_slice()).collect();

            let our_root = merkle_root(&refs).unwrap();

            // Build via ergo-merkle-tree directly.
            let nodes: Vec<MerkleNode> = elements
                .iter()
                .map(|e| MerkleNode::from_bytes(e.clone()))
                .collect();
            let tree = MerkleTree::new(nodes);
            let lib_root = tree.root_hash_special().0;

            assert_eq!(our_root, lib_root, "mismatch for {count} elements");
        }
    }
}
