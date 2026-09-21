//! AVL node serialization format compatibility tests.
//!
//! Post-Task-1.6 invariants:
//! - v1 tag `0x01` still deserializes with `None` child labels (read-only legacy).
//! - v2 tag `0x02` roundtrips child labels.
//! - `node_to_bytes` writes `0x02` for internals and panics if child labels
//!   are missing (every mutation path must populate them).
//! - Leaf serialization is unchanged.

use ergo_primitives::digest::Digest32;
use ergo_state::avl::node::AvlNode;
use ergo_state::store::{node_from_bytes, node_to_bytes};

// ----- happy path -----

#[test]
fn v1_internal_bytes_read_with_no_child_labels() {
    let mut buf = vec![0x01];
    buf.extend_from_slice(&[0x42; 32]);
    buf.extend_from_slice(&100u64.to_be_bytes());
    buf.extend_from_slice(&200u64.to_be_bytes());
    buf.push(0);
    match node_from_bytes(&buf).expect("self-built bytes parse") {
        AvlNode::Internal {
            left,
            right,
            balance,
            left_label,
            right_label,
            ..
        } => {
            assert_eq!(left, 100);
            assert_eq!(right, 200);
            assert_eq!(balance, 0);
            assert!(left_label.is_none());
            assert!(right_label.is_none());
        }
        _ => panic!("expected Internal"),
    }
}

#[test]
fn v2_internal_bytes_read_preserves_child_labels() {
    let ll = [0xAA; 32];
    let rl = [0xBB; 32];
    let mut buf = vec![0x02];
    buf.extend_from_slice(&[0x42; 32]);
    buf.extend_from_slice(&100u64.to_be_bytes());
    buf.extend_from_slice(&200u64.to_be_bytes());
    buf.push(0);
    buf.extend_from_slice(&ll);
    buf.extend_from_slice(&rl);
    match node_from_bytes(&buf).expect("self-built bytes parse") {
        AvlNode::Internal {
            left_label,
            right_label,
            ..
        } => {
            assert_eq!(left_label, Some(Digest32::from_bytes(ll)));
            assert_eq!(right_label, Some(Digest32::from_bytes(rl)));
        }
        _ => panic!("expected Internal"),
    }
}

#[test]
fn v2_internal_roundtrip_preserves_child_labels() {
    let ll = Digest32::from_bytes([0xAA; 32]);
    let rl = Digest32::from_bytes([0xBB; 32]);
    let node = AvlNode::Internal {
        key: [0x42; 32],
        left: 100,
        right: 200,
        balance: 0,
        left_label: Some(ll),
        right_label: Some(rl),
        label: None,
    };
    let bytes = node_to_bytes(&node);
    assert_eq!(bytes[0], 0x02);
    match node_from_bytes(&bytes).expect("v2 round-trip parse") {
        AvlNode::Internal {
            left,
            right,
            balance,
            left_label,
            right_label,
            ..
        } => {
            assert_eq!(left, 100);
            assert_eq!(right, 200);
            assert_eq!(balance, 0);
            assert_eq!(left_label, Some(ll));
            assert_eq!(right_label, Some(rl));
        }
        _ => panic!("expected Internal"),
    }
}

#[test]
#[should_panic(expected = "left_label must be Some")]
fn writing_v2_internal_without_labels_panics() {
    let node = AvlNode::Internal {
        key: [0; 32],
        left: 1,
        right: 2,
        balance: 0,
        left_label: None,
        right_label: None,
        label: None,
    };
    let _ = node_to_bytes(&node);
}

/// Regression test for Task 1.10: simulate an in-place v1->v2 DB upgrade.
///
/// Builds a tree, commits it, then rewrites every internal node into a v1
/// shape (left_label = None, right_label = None) via `load_node`.
/// Triggers a mutation that must pass through `modify_node` on the root
/// (and likely other internals), then serializes each Modified before-image
/// via `node_to_bytes`.
///
/// Without the Task 1.10 fix, `modify_node` captures the loaded v1 internal
/// verbatim and `node_to_bytes` panics on the None child labels. With the
/// fix, `modify_node` normalizes the before-image so every captured
/// Internal has Some child labels.
///
/// To ensure the test isn't vacuous, it asserts at least one captured
/// Internal before-image corresponds to a node_id that was rewritten to v1.
#[test]
fn v1_internal_before_image_does_not_panic_during_undo_serialize() {
    use ergo_state::avl::changelog::NodeChange;
    use ergo_state::avl::tree::AvlTree;

    let mut tree = AvlTree::new();
    for i in 0u8..16 {
        let mut key = [0u8; 32];
        key[0] = i.wrapping_mul(17).wrapping_add(1);
        key[1] = i;
        tree.insert(key, vec![i, i, i, i]);
    }
    tree.clear_dirty();

    // Rewrite every Internal in the committed tree as v1-shaped (no child
    // labels). This maximizes the chance that any mutation captures at
    // least one v1 before-image.
    let v1_internal_ids: Vec<u64> = tree
        .all_nodes()
        .into_iter()
        .filter_map(|(id, node)| match node {
            AvlNode::Internal {
                key,
                left,
                right,
                balance,
                ..
            } => {
                let rewritten = AvlNode::Internal {
                    key,
                    left,
                    right,
                    balance,
                    left_label: None,
                    right_label: None,
                    label: None,
                };
                Some((id, rewritten))
            }
            AvlNode::Leaf { .. } => None,
        })
        .map(|(id, rewritten)| {
            tree.load_node(id, rewritten);
            id
        })
        .collect();
    assert!(
        !v1_internal_ids.is_empty(),
        "test tree must contain at least one internal node"
    );

    // Trigger a mutation. Removing + reinserting a key walks from root
    // through several internals, all of which are now v1-shaped.
    let mut target_key = [0u8; 32];
    target_key[0] = 3u8.wrapping_mul(17).wrapping_add(1);
    target_key[1] = 3;
    tree.remove(&target_key);
    tree.insert(target_key, vec![9, 9, 9, 9]);

    let log = tree.take_change_log();

    // Each Modified before-image must serialize cleanly. Without the fix
    // this panics on the first v1 Internal captured.
    let mut saw_rewritten_internal = false;
    for change in log.changes() {
        if let NodeChange::Modified(id, node) = change {
            if matches!(node, AvlNode::Internal { .. }) && v1_internal_ids.contains(id) {
                saw_rewritten_internal = true;
            }
            let _bytes = node_to_bytes(node);
        }
    }
    assert!(
        saw_rewritten_internal,
        "regression coverage is vacuous — mutation did not capture any v1-rewritten \
         Internal before-image; tighten the test or pick a mutation that touches one"
    );
}

// ----- error paths -----
//
// AVL+ invariant: internal-node `balance` is structurally restricted
// to `{-1, 0, 1}`. The on-disk byte is `i8` so any value in
// `[-128, 127]` parses without a checked cast. Without the codec
// guard, an out-of-range value flows into `avl::tree::double_left_rotate`
// / `double_right_rotate` where a match arm panics. The decoder
// rejects out-of-range bytes with a `Serialization` error.

/// Build a synthetic v1 internal-node byte sequence with caller-chosen
/// `balance` byte. Used by the rejection tests below to feed
/// `node_from_bytes` an adversarial value without depending on the
/// writer (which would refuse to emit an out-of-range value).
fn v1_internal_bytes_with_balance(balance_byte: u8) -> Vec<u8> {
    let mut buf = vec![0x01];
    buf.extend_from_slice(&[0x42; 32]); // key
    buf.extend_from_slice(&100u64.to_be_bytes()); // left
    buf.extend_from_slice(&200u64.to_be_bytes()); // right
    buf.push(balance_byte);
    buf
}

/// Same shape as the v1 helper above but with the v2 tag and the
/// trailing child-label suffix the codec requires.
fn v2_internal_bytes_with_balance(balance_byte: u8) -> Vec<u8> {
    let mut buf = vec![0x02];
    buf.extend_from_slice(&[0x42; 32]); // key
    buf.extend_from_slice(&100u64.to_be_bytes()); // left
    buf.extend_from_slice(&200u64.to_be_bytes()); // right
    buf.push(balance_byte);
    buf.extend_from_slice(&[0xAA; 32]); // left_label
    buf.extend_from_slice(&[0xBB; 32]); // right_label
    buf
}

#[test]
fn v1_internal_with_balance_2_rejected() {
    let bytes = v1_internal_bytes_with_balance(0x02);
    let err = node_from_bytes(&bytes).expect_err("balance 0x02 must reject");
    let msg = format!("{err:?}");
    assert!(msg.contains("balance 2"), "wrong message: {msg}");
    assert!(msg.contains("v1"), "must cite v1 arm: {msg}");
}

#[test]
fn v2_internal_with_balance_2_rejected() {
    let bytes = v2_internal_bytes_with_balance(0x02);
    let err = node_from_bytes(&bytes).expect_err("balance 0x02 must reject");
    let msg = format!("{err:?}");
    assert!(msg.contains("balance 2"), "wrong message: {msg}");
    assert!(msg.contains("v2"), "must cite v2 arm: {msg}");
}

#[test]
fn v1_internal_with_balance_i8_max_rejected() {
    // 0x7F → i8 (+127), the largest unsigned-byte value before the sign
    // bit flips. Pins that the gate doesn't accidentally short-circuit
    // for positive-only values near the i8 ceiling.
    let bytes = v1_internal_bytes_with_balance(0x7F);
    let err = node_from_bytes(&bytes).expect_err("balance 0x7F must reject");
    assert!(format!("{err:?}").contains("balance 127"));
}

#[test]
fn v2_internal_with_balance_i8_min_rejected() {
    // 0x80 → i8 (-128), the most negative value. Pins the sign-bit
    // path — `data[49] as i8` performs a sign-extending cast, so this
    // arrives as `-128` not `+128`. The gate must catch it.
    let bytes = v2_internal_bytes_with_balance(0x80);
    let err = node_from_bytes(&bytes).expect_err("balance 0x80 must reject");
    assert!(format!("{err:?}").contains("balance -128"));
}

#[test]
fn v1_internal_accepts_all_three_valid_balance_values() {
    // 0x00 → 0, 0x01 → 1, 0xFF → -1. The negative case is the one most
    // likely to regress if someone replaces the i8 cast with a u8 check.
    for (byte, expected) in [(0x00u8, 0i8), (0x01, 1), (0xFF, -1)] {
        let bytes = v1_internal_bytes_with_balance(byte);
        let node = node_from_bytes(&bytes).expect("valid balance must parse");
        match node {
            AvlNode::Internal { balance, .. } => assert_eq!(
                balance, expected,
                "byte 0x{byte:02X} should decode as {expected}"
            ),
            _ => panic!("expected Internal"),
        }
    }
}

#[test]
fn v2_internal_accepts_all_three_valid_balance_values() {
    for (byte, expected) in [(0x00u8, 0i8), (0x01, 1), (0xFF, -1)] {
        let bytes = v2_internal_bytes_with_balance(byte);
        let node = node_from_bytes(&bytes).expect("valid balance must parse");
        match node {
            AvlNode::Internal { balance, .. } => assert_eq!(
                balance, expected,
                "byte 0x{byte:02X} should decode as {expected}"
            ),
            _ => panic!("expected Internal"),
        }
    }
}

#[test]
fn leaf_roundtrip_unchanged() {
    let node = AvlNode::Leaf {
        key: [0x11; 32],
        value: vec![1, 2, 3, 4],
        next_key: [0xFF; 32],
        label: None,
    };
    let bytes = node_to_bytes(&node);
    assert_eq!(bytes[0], 0x00);
    let rt = node_from_bytes(&bytes).expect("leaf round-trip parse");
    match rt {
        AvlNode::Leaf {
            key,
            value,
            next_key,
            ..
        } => {
            assert_eq!(key, [0x11; 32]);
            assert_eq!(value, vec![1, 2, 3, 4]);
            assert_eq!(next_key, [0xFF; 32]);
        }
        _ => panic!("expected Leaf"),
    }
}
