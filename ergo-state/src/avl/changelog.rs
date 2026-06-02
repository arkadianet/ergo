//! Before-image change log for AVL+ tree mutations.
//!
//! Every tree mutation (insert, remove, rotation) records the before-image of
//! each modified node and the ID of each newly allocated node. On rollback,
//! modified nodes are restored to their before-images and created nodes are
//! deleted. This provides exact structural undo with bounded storage.

use super::node::{AvlNode, NodeId};

/// A recorded change to a single node.
#[derive(Debug, Clone)]
pub enum NodeChange {
    /// An existing node was overwritten. Stores (node_id, old_value).
    /// On rollback: restore nodes[id] = old_value.
    Modified(NodeId, AvlNode),
    /// A new node was allocated. Stores the node_id.
    /// On rollback: delete nodes[id].
    Created(NodeId),
}

/// Change log for one block's worth of tree mutations.
///
/// Records are appended in mutation order. Rollback replays them in reverse.
/// If a node is modified multiple times in one block, only the FIRST
/// before-image is recorded — that's the pre-block state we need to restore.
#[derive(Debug, Clone, Default)]
pub struct ChangeLog {
    changes: Vec<NodeChange>,
    /// Track which node IDs have already been recorded as Modified in this
    /// block. Ensures we capture the original pre-image, not an intermediate.
    modified_ids: std::collections::HashSet<NodeId>,
}

impl ChangeLog {
    /// Empty change log. Equivalent to `Default::default()`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that an existing node is about to be overwritten.
    /// Only the first call per node_id records the before-image;
    /// subsequent calls are no-ops (the original pre-image is already saved).
    pub fn record_modify(&mut self, id: NodeId, old_value: AvlNode) {
        if self.modified_ids.insert(id) {
            self.changes.push(NodeChange::Modified(id, old_value));
        }
    }

    /// Record that a new node was allocated.
    pub fn record_create(&mut self, id: NodeId) {
        self.changes.push(NodeChange::Created(id));
    }

    /// Take the change log, leaving an empty one in its place.
    pub fn take(&mut self) -> ChangeLog {
        std::mem::take(self)
    }

    /// Borrow the recorded changes for serialization into the undo entry.
    pub fn changes(&self) -> &[NodeChange] {
        &self.changes
    }

    /// `true` if no changes were recorded.
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }

    /// Append a raw change entry. Used during deserialization where
    /// the caller has already deduplicated `Modified` entries; bypasses
    /// the [`Self::record_modify`] dedup check.
    pub fn push_raw(&mut self, change: NodeChange) {
        self.changes.push(change);
    }
}
