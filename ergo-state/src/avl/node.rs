//! AVL+ tree node types and arena-based storage.
//!
//! Nodes are identified by u64 IDs and stored in an arena (HashMap now, redb
//! table later). This avoids Rc<RefCell> and maps cleanly to persistent storage.

use ergo_primitives::digest::Digest32;

/// Node identifier — indexes into the arena.
pub type NodeId = u64;

/// A sentinel value meaning "no node".
pub const NULL_NODE: NodeId = 0;

/// AVL+ tree node. Either a leaf carrying a key/value pair or an
/// internal node holding two child IDs and the incremental balance
/// factor used by the AVL rotations.
#[derive(Debug, Clone)]
pub enum AvlNode {
    /// Key-value leaf. `next_key` is the AVL+ successor pointer used
    /// for proof generation.
    Leaf {
        /// Leaf key.
        key: [u8; 32],
        /// Leaf value.
        value: Vec<u8>,
        /// Successor key in sorted order. Sentinel-terminated.
        next_key: [u8; 32],
        /// Cached leaf label. `None` when the label has not been
        /// computed (or was invalidated by a mutation).
        label: Option<Digest32>,
    },
    /// Internal node with two child IDs and the AVL balance factor.
    Internal {
        /// Separator key: equals the key of the leftmost leaf in the right subtree.
        key: [u8; 32],
        /// Left child arena id.
        left: NodeId,
        /// Right child arena id.
        right: NodeId,
        /// AVL balance factor: `right.height - left.height`, in `{-1, 0, 1}` after rebalance.
        balance: i8,
        /// Cached label of the left child. Persisted in v2 format; `None` for
        /// v1-loaded nodes and for nodes built before incremental labels
        /// were wired into every mutation path.
        left_label: Option<Digest32>,
        /// Cached label of the right child. Same v1/v2 semantics as `left_label`.
        right_label: Option<Digest32>,
        /// In-memory only label of this node. Never persisted.
        label: Option<Digest32>,
    },
}

impl AvlNode {
    /// Borrow the leaf key (for `Leaf`) or separator key (for `Internal`).
    pub fn key(&self) -> &[u8; 32] {
        match self {
            AvlNode::Leaf { key, .. } => key,
            AvlNode::Internal { key, .. } => key,
        }
    }

    /// Borrow the cached label, if any.
    pub fn label(&self) -> Option<&Digest32> {
        match self {
            AvlNode::Leaf { label, .. } => label.as_ref(),
            AvlNode::Internal { label, .. } => label.as_ref(),
        }
    }

    /// Invalidate the cached label so the next read recomputes it from
    /// the (possibly mutated) children.
    pub fn invalidate_label(&mut self) {
        match self {
            AvlNode::Leaf { label, .. } => *label = None,
            AvlNode::Internal { label, .. } => *label = None,
        }
    }

    /// `true` iff this node is a leaf.
    pub fn is_leaf(&self) -> bool {
        matches!(self, AvlNode::Leaf { .. })
    }
}
