//! AVL+ tree node digest (label) computation.
//!
//! Consensus-critical: these hash inputs must exactly match the scorex-util
//! AVL+ implementation used by the Ergo reference node. The authoritative
//! Rust oracle is `ergo_avltree_rust` crate (batch_node.rs lines 83-111).
//!
//! Leaf label  = blake2b256(0x00 || key[32] || value[var] || next_leaf_key[32])
//! Internal label = blake2b256(0x01 || balance_as_u8[1] || left_label[32] || right_label[32])
//! ADDigest = root_label[32] || tree_height[1]

use ergo_primitives::digest::{ADDigest, Digest32};

/// Prefix byte for leaf nodes in the label hash.
/// Note: the *serialization* format uses the opposite convention (leaf=1, internal=0)
/// but the label hash uses leaf=0, internal=1. See ergo_avltree_rust batch_node.rs.
pub const LEAF_LABEL_PREFIX: u8 = 0x00;

/// Prefix byte for internal nodes in the label hash.
pub const INTERNAL_LABEL_PREFIX: u8 = 0x01;

/// Sentinel key for the leftmost boundary (all zeros).
pub const NEGATIVE_INFINITY_KEY: [u8; 32] = [0x00; 32];

/// Sentinel key for the rightmost boundary (all 0xFF).
pub const POSITIVE_INFINITY_KEY: [u8; 32] = [0xFF; 32];

/// Compute the label (hash) of a leaf node.
///
/// `key`: 32-byte box_id (or sentinel key)
/// `value`: serialized box bytes (variable length, may be empty for sentinel)
/// `next_leaf_key`: key of the next leaf in sorted order, or POSITIVE_INFINITY_KEY
pub fn leaf_label(key: &[u8; 32], value: &[u8], next_leaf_key: &[u8; 32]) -> Digest32 {
    use blake2::digest::consts::U32;
    use blake2::{Blake2b, Digest as _};

    let mut hasher = Blake2b::<U32>::new();
    hasher.update([LEAF_LABEL_PREFIX]);
    hasher.update(key);
    hasher.update(value);
    hasher.update(next_leaf_key);
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    Digest32::from_bytes(bytes)
}

/// Compute the label (hash) of an internal node.
///
/// `balance`: AVL balance factor (-1, 0, or 1), stored as i8.
/// `left_label`: 32-byte label of the left child.
/// `right_label`: 32-byte label of the right child.
pub fn internal_label(balance: i8, left_label: &Digest32, right_label: &Digest32) -> Digest32 {
    use blake2::digest::consts::U32;
    use blake2::{Blake2b, Digest as _};

    let mut hasher = Blake2b::<U32>::new();
    hasher.update([INTERNAL_LABEL_PREFIX]);
    hasher.update([balance as u8]);
    hasher.update(left_label.as_bytes());
    hasher.update(right_label.as_bytes());
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    Digest32::from_bytes(bytes)
}

/// Construct the 33-byte ADDigest from a root node's label and the tree height.
pub fn root_digest(root_label: &Digest32, tree_height: u8) -> ADDigest {
    let mut bytes = [0u8; 33];
    bytes[..32].copy_from_slice(root_label.as_bytes());
    bytes[32] = tree_height;
    ADDigest::from_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- happy path -----

    #[test]
    fn empty_sentinel_leaf_label_is_deterministic() {
        // A sentinel leaf with NegativeInfinity key, empty value, pointing to PositiveInfinity
        let label = leaf_label(&NEGATIVE_INFINITY_KEY, &[], &POSITIVE_INFINITY_KEY);
        // Verify it's non-zero and deterministic
        assert_ne!(label, Digest32::ZERO);
        let label2 = leaf_label(&NEGATIVE_INFINITY_KEY, &[], &POSITIVE_INFINITY_KEY);
        assert_eq!(label, label2);
    }

    #[test]
    fn leaf_label_changes_with_value() {
        let key = [0x01; 32];
        let next = POSITIVE_INFINITY_KEY;
        let l1 = leaf_label(&key, &[0xAA, 0xBB], &next);
        let l2 = leaf_label(&key, &[0xCC, 0xDD], &next);
        assert_ne!(l1, l2);
    }

    #[test]
    fn internal_label_changes_with_balance() {
        let left = Digest32::from_bytes([0x11; 32]);
        let right = Digest32::from_bytes([0x22; 32]);
        let l_neg = internal_label(-1, &left, &right);
        let l_zero = internal_label(0, &left, &right);
        let l_pos = internal_label(1, &left, &right);
        assert_ne!(l_neg, l_zero);
        assert_ne!(l_zero, l_pos);
        assert_ne!(l_neg, l_pos);
    }

    #[test]
    fn balance_negative_one_is_0xff() {
        // Verify that -1i8 as u8 == 0xFF (two's complement)
        assert_eq!((-1i8) as u8, 0xFF);
    }

    #[test]
    fn root_digest_format() {
        let label = Digest32::from_bytes([0xAB; 32]);
        let ad = root_digest(&label, 3);
        let bytes = ad.as_bytes();
        assert_eq!(&bytes[..32], &[0xAB; 32]);
        assert_eq!(bytes[32], 3);
    }

    /// Cross-validate leaf and internal label computation against the
    /// ergo_avltree_rust crate (the authoritative Rust oracle).
    #[test]
    fn cross_validate_labels_against_ergo_avltree_rust() {
        use bytes::Bytes;
        use ergo_avltree_rust::batch_node::{AVLTree, InternalNode, LeafNode, Node, NodeHeader};

        let key_len = 32;
        let tree = AVLTree::new(
            |digest| Node::LabelOnly(NodeHeader::new(Some(*digest), None)),
            key_len,
            None,
        );

        // Create a leaf via the oracle
        let key = Bytes::from(vec![0x42u8; 32]);
        let value = Bytes::from(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let next_key = Bytes::from(vec![0xFF; 32]);
        let oracle_leaf = LeafNode::new(&key, &value, &next_key);
        let oracle_leaf_label = tree.label(&oracle_leaf);

        // Compute with our function
        let our_key = [0x42u8; 32];
        let our_label = leaf_label(&our_key, &[0xDE, 0xAD, 0xBE, 0xEF], &POSITIVE_INFINITY_KEY);
        assert_eq!(
            our_label.as_bytes(),
            &oracle_leaf_label,
            "leaf label mismatch with oracle"
        );

        // Create two leaves, then an internal node
        let key_a = Bytes::from(vec![0x10; 32]);
        let key_b = Bytes::from(vec![0x20; 32]);
        let val_a = Bytes::from(vec![0x01]);
        let val_b = Bytes::from(vec![0x02]);

        let leaf_a = LeafNode::new(&key_a, &val_a, &key_b);
        let leaf_b = LeafNode::new(&key_b, &val_b, &Bytes::from(vec![0xFF; 32]));
        let label_a = tree.label(&leaf_a);
        let label_b = tree.label(&leaf_b);

        let internal = InternalNode::new(Some(key_b.clone()), &leaf_a, &leaf_b, 0);
        let oracle_internal_label = tree.label(&internal);

        // Compute with our functions
        let our_la = leaf_label(&[0x10; 32], &[0x01], &[0x20; 32]);
        let our_lb = leaf_label(&[0x20; 32], &[0x02], &POSITIVE_INFINITY_KEY);
        assert_eq!(our_la.as_bytes(), &label_a, "leaf A label mismatch");
        assert_eq!(our_lb.as_bytes(), &label_b, "leaf B label mismatch");

        let our_internal = internal_label(0, &our_la, &our_lb);
        assert_eq!(
            our_internal.as_bytes(),
            &oracle_internal_label,
            "internal label mismatch with oracle"
        );
    }
}
