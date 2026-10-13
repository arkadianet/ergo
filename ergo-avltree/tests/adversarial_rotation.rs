#![allow(clippy::style, clippy::complexity, clippy::perf)]
//! Regression tests: crafted proofs that route a non-`Internal` node into a
//! double rotation's promoted-grandchild slot must be rejected (`Err`) rather
//! than panicking.
//!
//! The rotation helpers guard the CHILD's kind (the caller pattern-matches it)
//! but not the GRANDCHILD's, and the grandchild is whatever the proof packed
//! there. A well-formed AVL tree can never hold the routing shape that reaches
//! these sites, but the verifier materialises its tree from attacker-chosen
//! proof bytes and reads each internal node's balance byte straight off the
//! proof, so a crafted proof reaches them trivially.
//!
//! The reference (scrypto) `BatchAVLVerifier` casts to `InternalNode` at the
//! same point — `AuthenticatedTreeOps.doubleLeftRotate` starts
//! `aload_3; InternalNode.left(); checkcast InternalNode` — and lets the
//! resulting `ClassCastException` be caught by the `Try` wrapping
//! `returnResultOfOneOperation`. Returning `Err` matches that accept/reject
//! set without aborting the process.
//!
//! The four vectors below are ported from the `@ergots/avltree` port's
//! `verifier-adversarial-rotation.test.ts`, which found them.

use bytes::Bytes;
use ergo_avltree::batch_avl_verifier::BatchAVLVerifier;
use ergo_avltree::operation::*;

mod common;
use common::generate_tree;

fn hex_to_bytes(h: &str) -> Bytes {
    let raw: Vec<u8> = (0..h.len() / 2)
        .map(|i| u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap())
        .collect();
    Bytes::from(raw)
}

/// 32-byte key with `b` in the first and last position.
fn key_byte(b: u8) -> ADKey {
    let mut k = [0u8; 32];
    k[0] = b;
    k[31] = b;
    Bytes::copy_from_slice(&k)
}

/// A crafted proof must be rejected, not panic.
fn expect_rejected(
    starting_digest: Bytes,
    proof: Bytes,
    key_length: usize,
    value_length: Option<usize>,
    op: Operation,
) {
    let verifier = BatchAVLVerifier::new(
        &starting_digest,
        &proof,
        generate_tree(key_length, value_length),
        None,
        None,
    );
    // Some vectors decode cleanly and only fail during replay; others may be
    // rejected at reconstruction. Either is a rejection — neither may panic.
    if let Ok(mut v) = verifier {
        assert!(
            v.perform_one_operation(&op).is_err(),
            "verifier accepted a malformed proof"
        );
    }
}

// ---------------------------------------------------------------------------
// Delete path: the promoted sub-root is packed as a bare LABEL.
// keyLength 32, no fixed value length.
// ---------------------------------------------------------------------------

#[test]
fn remove_double_left_rotation_onto_label_is_err_not_panic() {
    // Insertion order 2,4,1,3 then Remove(0x01); the promoted sub-root
    // (root.right.left) is packed as a label instead of an internal node.
    expect_rejected(
        hex_to_bytes("8200dc987d3a29bf34d43305c53cd5ce3582c58966753a1c468c5ba349804ea503"),
        hex_to_bytes("02000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000010000000002020000000000000000000000000000000000000000000000000000000000000200000001010003e447f71b494b687a4b47541e9282d0906bcbd9b61dda41e3ec3964f0776d1cb103dca3ace8ebca185a103f2aecd620e54416864c730b223da2577d7c75b0d417fbff010401"),
        32,
        None,
        Operation::Remove(key_byte(0x01)),
    );
}

#[test]
fn remove_double_right_rotation_onto_label_is_err_not_panic() {
    // Key-mirror of the above: insertion order 3,1,4,2 then Remove(0x04);
    // the promoted sub-root (root.left.right) is packed as a label.
    expect_rejected(
        hex_to_bytes("5e6c913f4a1f763792e34bf758b7d45687c0b77ba0671398ad304ece53e382f803"),
        hex_to_bytes("03c28daac8506f3840d68bf6b10a1ef14642b4fdae5997157209bbb13d6c7c0d500377c07458e3d9b764ef2e6c8db3294f5bf5298e71aadc0888fad8046b38b19a51010203000000000000000000000000000000000000000000000000000000000000030400000000000000000000000000000000000000000000000000000000000004000000010302ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff000000010400ff0400"),
        32,
        None,
        Operation::Remove(key_byte(0x04)),
    );
}

// ---------------------------------------------------------------------------
// Insert path: the promoted sub-root is a freshly split LEAF.
// keyLength 1, fixed value length 1. Three-token proofs.
// ---------------------------------------------------------------------------

#[test]
fn insert_double_right_rotation_onto_leaf_is_err_not_panic() {
    // Crafted tree — Internal(balance = -1, left = Leaf, right = Label):
    //   02 10 20 aa   LEAF key=0x10 nextLeafKey=0x20 value=0xaa
    //   03 11*32      LABEL
    //   ff            INTERNAL, balance byte 0xff = -1
    //   04            END_OF_TREE
    //   01            directions bit 0 set -> descend LEFT
    // The digest is computed over exactly this tree, so decoding and the
    // digest check both pass and the failure is a genuine replay failure.
    //
    // Insert(0x18) splits the leaf's gap into Internal(balance 0, Leaf, Leaf)
    // with heightIncreased; the root's crafted -1 balance enters the rotation
    // branch, the split node's 0 balance selects the *double* rotation, and
    // the promoted sub-root (node.left.right) is a fresh Leaf.
    expect_rejected(
        hex_to_bytes("96ccb020196496f331ad999eb9e07c65f31c4c8b2b9722266492a6b3614a9a1602"),
        hex_to_bytes(&("021020aa03".to_owned() + &"11".repeat(32) + "ff0401")),
        1,
        Some(1),
        Operation::Insert(KeyValue {
            key: Bytes::from(vec![0x18u8]),
            value: Bytes::from(vec![0xbbu8]),
        }),
    );
}

#[test]
fn insert_double_left_rotation_onto_leaf_is_err_not_panic() {
    // Sign-mirror of the above — Internal(balance = +1, left = Label, right = Leaf),
    // directions bit clear so the descent goes right.
    expect_rejected(
        hex_to_bytes("f0422bf0225488ef15b0c098fd6725d9cdb3b9ee0491c1ec6279f162ae549a2a02"),
        hex_to_bytes(&("03".to_owned() + &"22".repeat(32) + "021020aa" + "01" + "04" + "00")),
        1,
        Some(1),
        Operation::Insert(KeyValue {
            key: Bytes::from(vec![0x18u8]),
            value: Bytes::from(vec![0xbbu8]),
        }),
    );
}
