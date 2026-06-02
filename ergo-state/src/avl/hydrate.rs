//! Hydrate a `BatchAVLProver` from the current `AvlTree` state.
//!
//! Walks the arena-backed tree from the root and builds the equivalent
//! `Rc<RefCell<Node>>` graph that `ergo_avltree_rust`'s prover operates
//! on. The constructed prover can then run a batch of operations
//! (insert / remove / update) to produce a new root digest and the
//! AD-proof bytes that mainnet validators expect.
//!
//! This is a read-only seam. It never mutates the source tree, never
//! touches persistent storage, and is intended for mining-side
//! candidate dry-runs (Phase 1c). It always operates on the **current
//! committed tip** as held by the supplied `AvlTree` reference.
//!
//! Cost is O(tree size) reads against the arena and O(tree size) heap
//! for the hydrated node graph. Caching across calls is a deliberate
//! follow-up; v1 hydrates per dry-run.

use bytes::Bytes;
use ergo_avltree_rust::batch_avl_prover::BatchAVLProver;
use ergo_avltree_rust::batch_node::{
    AVLTree as OracleTree, InternalNode, LeafNode, Node, NodeHeader, NodeId as OracleNodeId,
};
use ergo_avltree_rust::operation::Digest32 as OracleDigest32;

use super::node::{AvlNode, NodeId};
use super::tree::AvlTree;
use crate::store::StateError;

/// Length of UTXO box keys in bytes. Box IDs are Blake2b256 digests.
const UTXO_KEY_LENGTH: usize = 32;

/// Hydrate a fresh `BatchAVLProver` from the current state of `tree`.
///
/// Walks `tree` from the root, builds a parallel `Rc<RefCell<Node>>`
/// graph in the upstream prover's representation, and wraps it in a
/// `BatchAVLProver`. Nodes are marked `is_new = false` so the prover
/// treats them as existing tree state, not freshly inserted material.
///
/// The returned prover collects changed nodes (`collect_changed_nodes
/// = true`) so the caller can extract the AD-proof bytes after running
/// a batch.
pub fn hydrate_batch_avl_prover(tree: &AvlTree) -> Result<BatchAVLProver, StateError> {
    hydrate_batch_avl_prover_from_fetch(tree.root_id(), tree.tree_height(), &|id| {
        tree.get_node(id).ok_or(StateError::InternalInvariant {
            what: "hydrate: node id missing from arena",
        })
    })
}

/// Hydrate a `BatchAVLProver` from an arbitrary node source.
///
/// `fetch(id)` must return the AVL node stored at `id`, or an `Err` if
/// it is missing or corrupt. Both hydration paths funnel through here:
/// - the live-arena path ([`hydrate_batch_avl_prover`]) reads nodes from
///   an in-memory `AvlTree`;
/// - the off-loop committed-snapshot path
///   ([`crate::store::snapshot::CommittedSnapshot`]) reads nodes from a
///   single redb read transaction so the entire walk — and every other
///   build input it pairs with — is one snapshot-consistent view.
///
/// `root_id` is the committed root node id and `tree_height` its height
/// (for the live path, `tree.root_id()` / `tree.tree_height()`; for the
/// snapshot path, the `StateMeta` `root_node_id` / `tree_height`).
pub(crate) fn hydrate_batch_avl_prover_from_fetch(
    root_id: NodeId,
    tree_height: u8,
    fetch: &dyn Fn(NodeId) -> Result<AvlNode, StateError>,
) -> Result<BatchAVLProver, StateError> {
    let root = hydrate_subtree(root_id, fetch)?;
    let mut oracle = OracleTree::new(default_resolver, UTXO_KEY_LENGTH, None);
    oracle.root = Some(root);
    oracle.height = tree_height as usize;
    Ok(BatchAVLProver::new(
        oracle, /* collect_changed_nodes = */ true,
    ))
}

/// Default resolver for label-only stubs. Hydration produces a fully
/// expanded tree, so this resolver should never actually fire during
/// dry-run; it's wired up because [`OracleTree::new`] requires one.
fn default_resolver(digest: &OracleDigest32) -> Node {
    Node::LabelOnly(NodeHeader::new(Some(*digest), None))
}

fn hydrate_subtree(
    id: NodeId,
    fetch: &dyn Fn(NodeId) -> Result<AvlNode, StateError>,
) -> Result<OracleNodeId, StateError> {
    let node = fetch(id)?;
    let oracle_node = match node {
        AvlNode::Leaf {
            key,
            value,
            next_key,
            ..
        } => {
            let leaf = LeafNode::new(
                &Bytes::from(key.to_vec()),
                &Bytes::from(value),
                &Bytes::from(next_key.to_vec()),
            );
            mark_loaded(&leaf);
            leaf
        }
        AvlNode::Internal {
            key,
            left,
            right,
            balance,
            ..
        } => {
            let left_node = hydrate_subtree(left, fetch)?;
            let right_node = hydrate_subtree(right, fetch)?;
            let internal = InternalNode::new(
                Some(Bytes::from(key.to_vec())),
                &left_node,
                &right_node,
                balance,
            );
            mark_loaded(&internal);
            internal
        }
    };
    Ok(oracle_node)
}

/// Mark a freshly-hydrated node as existing tree state, not a new node.
///
/// Upstream constructors default to `is_new = true` because they're
/// designed for apply-time mutations. Hydration loads existing nodes;
/// `is_new = false` is required so the prover's bookkeeping doesn't
/// treat the hydrated graph as a fresh batch.
fn mark_loaded(node: &OracleNodeId) {
    let mut borrow = node.borrow_mut();
    let hdr = match &mut *borrow {
        Node::LabelOnly(h) => h,
        Node::Internal(n) => &mut n.hdr,
        Node::Leaf(n) => &mut n.hdr,
    };
    hdr.is_new = false;
    hdr.visited = false;
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_avltree_rust::authenticated_tree_ops::AuthenticatedTreeOps;
    use ergo_primitives::digest::Digest32;

    // ----- helpers -----

    fn make_key(seed: u8) -> [u8; 32] {
        let mut k = [0u8; 32];
        k[0] = seed.wrapping_mul(17).wrapping_add(5);
        k[31] = seed;
        k
    }

    fn prover_root_digest(prover: &mut BatchAVLProver) -> [u8; 33] {
        let d = prover.digest().expect("digest");
        let mut out = [0u8; 33];
        out.copy_from_slice(&d);
        out
    }

    // ----- happy path -----

    #[test]
    fn hydrate_round_trip_zero_ops_preserves_root_empty_tree() {
        let tree = AvlTree::new();
        let expected = *tree.root_digest().as_bytes();
        let mut prover = hydrate_batch_avl_prover(&tree).expect("hydrate empty");
        let hydrated = prover_root_digest(&mut prover);
        assert_eq!(
            expected, hydrated,
            "hydrating an empty (sentinel-only) tree must preserve the root digest"
        );
    }

    #[test]
    fn hydrate_round_trip_zero_ops_preserves_root_one_leaf() {
        let mut tree = AvlTree::new();
        tree.insert(make_key(1), vec![0x01]);
        let expected = *tree.root_digest().as_bytes();
        let mut prover = hydrate_batch_avl_prover(&tree).expect("hydrate one-leaf");
        let hydrated = prover_root_digest(&mut prover);
        assert_eq!(
            expected, hydrated,
            "hydrating a one-leaf tree must preserve the root digest"
        );
    }

    #[test]
    fn hydrate_round_trip_zero_ops_preserves_root_ten_leaves() {
        let mut tree = AvlTree::new();
        for i in 0u8..10 {
            tree.insert(make_key(i), vec![i, i + 1, i + 2]);
        }
        let expected = *tree.root_digest().as_bytes();
        let mut prover = hydrate_batch_avl_prover(&tree).expect("hydrate ten-leaf");
        let hydrated = prover_root_digest(&mut prover);
        assert_eq!(
            expected, hydrated,
            "hydrating a 10-leaf tree must preserve the root digest"
        );
    }

    #[test]
    fn hydrate_round_trip_zero_ops_preserves_root_after_remove() {
        let mut tree = AvlTree::new();
        for i in 0u8..10 {
            tree.insert(make_key(i), vec![i, i + 1]);
        }
        tree.remove(&make_key(3));
        tree.remove(&make_key(7));
        let expected = *tree.root_digest().as_bytes();
        let mut prover = hydrate_batch_avl_prover(&tree).expect("hydrate post-remove");
        let hydrated = prover_root_digest(&mut prover);
        assert_eq!(
            expected, hydrated,
            "hydrating a tree with deletions must preserve the root digest"
        );
    }

    #[test]
    fn hydrate_round_trip_zero_ops_preserves_root_large_tree() {
        // ~depth-7 tree, enough to exercise multiple internal-node levels.
        let mut tree = AvlTree::new();
        for i in 0u8..128 {
            tree.insert(make_key(i), vec![i]);
        }
        let expected = *tree.root_digest().as_bytes();
        let mut prover = hydrate_batch_avl_prover(&tree).expect("hydrate 128-leaf");
        let hydrated = prover_root_digest(&mut prover);
        assert_eq!(
            expected, hydrated,
            "hydrating a 128-leaf tree must preserve the root digest"
        );
    }

    // ----- round-trips -----

    // ----- error paths -----

    #[test]
    fn hydrate_missing_arena_root_returns_internal_invariant() {
        let tree = AvlTree::new_empty_with_label(42, 0, Digest32::from_bytes([0u8; 32]));
        let err = match hydrate_batch_avl_prover(&tree) {
            Err(err) => err,
            Ok(_) => panic!("missing root must fail"),
        };
        match err {
            StateError::InternalInvariant { what } => {
                assert_eq!(what, "hydrate: node id missing from arena");
            }
            other => panic!("expected InternalInvariant, got {other:?}"),
        }
    }

    // ----- oracle parity -----

    // ----- internal-node format coverage -----
    //
    // Hydration reads only the structural fields of `AvlNode::Internal`
    // (`key`, `left`, `right`, `balance`) and ignores `left_label` /
    // `right_label` / `label` (the v2-only cached digests). So the v1
    // vs v2 distinction is invisible at the hydrate boundary — both
    // formats produce identical upstream nodes. The 5 zero-op
    // round-trip tests above already exercise v2 internals (created
    // via mutation in this process) and the digest-equality assertion
    // would fail just as loudly if the v1 path diverged from v2 here.
}
