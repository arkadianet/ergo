//! AVL+ tree with authenticated digests.
//!
//! Node storage is abstracted via `NodeArena` (crate-private trait).
//! `AvlTree::new()` uses `MemoryArena` (HashMap-backed) for tests.
//! Production code will use `CachedDiskArena` (LRU+redb) via
//! `AvlTree::new_disk_backed()`.
//!
//! The tree starts with a single sentinel leaf (NegativeInfinity key, empty value,
//! next_key = PositiveInfinity). All real keys are inserted between these sentinels.

use ergo_primitives::digest::{ADDigest, Digest32};

use super::arena::{MemoryArena, NodeArena};
use super::changelog::{ChangeLog, NodeChange};
use super::digest::{
    internal_label, leaf_label, root_digest, NEGATIVE_INFINITY_KEY, POSITIVE_INFINITY_KEY,
};
use super::node::{AvlNode, NodeId, NULL_NODE};

/// Info about a deleted leaf, returned by delete_at when delete_max = true.
struct DeletedLeaf {
    key: [u8; 32],
    value: Vec<u8>,
}

/// Which child of a parent we're referring to when fetching a sibling label.
enum Side {
    Left,
    Right,
}

struct LeftShrink {
    id: NodeId,
    sep_key: [u8; 32],
    new_left: NodeId,
    new_left_label: Digest32,
    right: NodeId,
    parent_right_label: Option<Digest32>,
    balance: i8,
    child_decreased: bool,
}

struct RightShrink {
    id: NodeId,
    sep_key: [u8; 32],
    left: NodeId,
    parent_left_label: Option<Digest32>,
    new_right: NodeId,
    new_right_label: Digest32,
    balance: i8,
    child_decreased: bool,
}

/// AVL+ tree backed by a pluggable [`NodeArena`].
///
/// The tree maintains the root's authenticated label incrementally on
/// every insert / remove / rotate so `root_digest()` is O(1) even on a
/// disk-backed arena. Mutations emit before-image entries into
/// [`ChangeLog`]; the store's commit path drains the log into the undo
/// table and the arena's dirty set into redb in the same transaction.
pub struct AvlTree {
    arena: Box<dyn NodeArena + Send>,
    root: NodeId,
    /// Label of the current root node. Hydrated from state_meta at open time
    /// and maintained on every mutation so `root_digest()` is O(1).
    root_label: Digest32,
    height: u8,
    next_id: u64,
    /// Before-image change log for rollback support.
    change_log: ChangeLog,
}

impl Default for AvlTree {
    fn default() -> Self {
        Self::new()
    }
}

// ---- Arena accessor methods ----
//
// Thin wrappers that delegate to the arena trait object.
// Keeps tree logic clean and avoids `self.arena.` noise everywhere.

impl AvlTree {
    fn node_clone(&self, id: NodeId) -> AvlNode {
        self.arena.get(id).expect("node not found in arena")
    }

    fn node_get(&self, id: NodeId) -> Option<AvlNode> {
        self.arena.get(id)
    }

    fn store_node(&mut self, id: NodeId, node: AvlNode) {
        self.arena.put(id, node);
    }

    fn remove_node(&mut self, id: NodeId) {
        self.arena.remove(id);
    }

    fn has_node(&self, id: NodeId) -> bool {
        self.arena.contains(id)
    }

    fn set_label(&self, id: NodeId, label: Digest32) {
        self.arena.set_label(id, label);
    }

    // invariant: label-agnostic — cache-statistics accessor; no consensus path.
    /// Total arena reads since last reset. Scaffolding for K v2 read-count
    /// tests — see `ergo-state/tests/avl_root_digest_reads.rs`.
    pub fn arena_read_count(&self) -> u64 {
        self.arena.read_count()
    }

    // invariant: label-agnostic — cache-statistics accessor; no consensus path.
    /// Reset the arena read counter to zero.
    pub fn arena_reset_read_count(&self) {
        self.arena.reset_read_count();
    }

    // invariant: label-agnostic — cache-statistics accessor; no consensus path.
    /// Bytes currently held in the clean LRU cache (0 for arenas without one).
    pub fn arena_cache_clean_bytes(&self) -> usize {
        self.arena.cache_clean_bytes()
    }

    // invariant: label-agnostic — cache-statistics accessor; no consensus path.
    /// Configured byte budget for the clean cache (0 if unbudgeted).
    pub fn arena_cache_capacity_bytes(&self) -> usize {
        self.arena.cache_capacity_bytes()
    }

    // invariant: label-agnostic — cache-statistics accessor; no consensus path.
    /// Number of nodes in the clean cache.
    pub fn arena_cache_clean_len(&self) -> usize {
        self.arena.cache_clean_len()
    }

    // invariant: label-agnostic — cache-statistics accessor; no consensus path.
    /// Number of structurally modified (dirty) nodes pending commit.
    pub fn arena_cache_dirty_len(&self) -> usize {
        self.arena.cache_dirty_len()
    }
}

impl AvlTree {
    // invariant: label-mutator (init) — constructs `root_label =
    // leaf_label(NEG_INF, &[], POS_INF)` (the canonical empty-AVL+
    // sentinel) at construction time. Never used for restored state.
    /// Create a new tree with just the sentinel leaf (MemoryArena).
    pub fn new() -> Self {
        let sentinel_label = leaf_label(&NEGATIVE_INFINITY_KEY, &[], &POSITIVE_INFINITY_KEY);
        let mut tree = AvlTree {
            arena: Box::new(MemoryArena::new()),
            root: NULL_NODE,
            root_label: sentinel_label,
            height: 0,
            next_id: 1,
            change_log: ChangeLog::new(),
        };
        let sentinel = AvlNode::Leaf {
            key: NEGATIVE_INFINITY_KEY,
            value: Vec::new(),
            next_key: POSITIVE_INFINITY_KEY,
            label: None,
        };
        tree.root = tree.alloc(sentinel);
        tree
    }

    /// Create a tree shell for loading from redb (MemoryArena) with an explicit
    /// root_label. Nodes are loaded via `load_node()` and the caller must have
    /// the correct root label already in hand (typically from `state_meta`).
    // invariant: trust-input-label — caller-supplied `root_label` becomes
    // the new cached root. Used by snapshot bootstrap; caller is responsible
    // for verifying the label against an external oracle (Mode 2
    // `manifest_id` verification).
    pub fn new_empty_with_label(root_id: NodeId, height: u8, root_label: Digest32) -> Self {
        AvlTree {
            arena: Box::new(MemoryArena::new()),
            root: root_id,
            root_label,
            height,
            next_id: root_id + 1,
            change_log: ChangeLog::new(),
        }
    }

    // invariant: trust-input-label — crate-internal constructor for restored
    // state. `root_label` MUST come from `state_meta.root_digest[..32]` per
    // the doc comment; trust flows from durable storage, not from in-memory
    // recomputation.
    /// Create a tree with a custom arena and restored state (existing DB).
    /// `root_label` must come from the persisted `state_meta.root_digest[..32]`.
    pub(crate) fn new_with_arena(
        arena: Box<dyn NodeArena + Send>,
        root_id: NodeId,
        height: u8,
        next_id: u64,
        root_label: Digest32,
    ) -> Self {
        AvlTree {
            arena,
            root: root_id,
            root_label,
            height,
            next_id,
            change_log: ChangeLog::new(),
        }
    }

    // invariant: label-mutator (init) — disk-backed analogue of `new()`.
    // Computes the same NEG_INF/POS_INF sentinel leaf and the same
    // `root_label = leaf_label(NEG_INF, &[], POS_INF)`. Used by
    // `StateStore::open` for a fresh disk-backed tree before any genesis
    // state has been loaded.
    /// Create a new sentinel-initialized tree with a custom arena (new DB).
    pub(crate) fn new_disk_backed(arena: Box<dyn NodeArena + Send>) -> Self {
        let sentinel_label = leaf_label(&NEGATIVE_INFINITY_KEY, &[], &POSITIVE_INFINITY_KEY);
        let mut tree = AvlTree {
            arena,
            root: NULL_NODE,
            root_label: sentinel_label,
            height: 0,
            next_id: 1,
            change_log: ChangeLog::new(),
        };
        let sentinel = AvlNode::Leaf {
            key: NEGATIVE_INFINITY_KEY,
            value: Vec::new(),
            next_key: POSITIVE_INFINITY_KEY,
            label: None,
        };
        tree.root = tree.alloc(sentinel);
        tree
    }

    // invariant: label-passthrough — inserts a raw `AvlNode` (with its
    // cached label, if any) into the arena and bumps `next_id`. Used by
    // snapshot bootstrap / cold restart; caller is responsible for the
    // load-bearing trust of the passed labels (typically Scala-verified
    // or oracle-checked at the snapshot manifest boundary).
    /// Load a node from persistent storage into the arena.
    pub fn load_node(&mut self, id: NodeId, node: AvlNode) {
        self.store_node(id, node);
        if id >= self.next_id {
            self.next_id = id + 1;
        }
    }

    // invariant: label-agnostic — metadata accessor; not consensus-load-bearing.
    /// Get the root node ID.
    pub fn root_id(&self) -> NodeId {
        self.root
    }

    // invariant: label-agnostic — metadata accessor; not consensus-load-bearing.
    /// Get the AVL tree height (not block height).
    pub fn tree_height(&self) -> u8 {
        self.height
    }

    // invariant: label-agnostic — metadata accessor; not consensus-load-bearing.
    /// Get the next_id allocator counter.
    pub fn next_id(&self) -> u64 {
        self.next_id
    }

    // invariant: label-agnostic — returns the mutation log without touching labels.
    /// Take the change log (resets it). Called after successful block apply.
    pub fn take_change_log(&mut self) -> ChangeLog {
        self.change_log.take()
    }

    // invariant: label-mutator (recover) — restores before-image NODES from
    // the change log (the labels carried inside those nodes are restored
    // alongside), then assigns `self.root_label = self.label_of(root_id)`.
    // `label_of` returns the cached own-label when present and only falls
    // back to structural recomputation when the own-label is missing — it
    // does NOT unconditionally recompute. Net effect after return:
    // `self.root_label` is consistent with the restored arena state.
    /// Rollback changes from a change log. Replays in reverse:
    /// - Created nodes are deleted from the arena.
    /// - Modified nodes are restored to their before-images.
    ///
    /// Then restores root and height, and recomputes `root_label` from
    /// the restored root via a full recompute. This is the safe
    /// correctness guarantee; a future refinement may use before-image
    /// labels once labels are threaded through the mutation path.
    pub fn rollback(&mut self, log: &ChangeLog, root_id: NodeId, tree_height: u8) {
        for change in log.changes().iter().rev() {
            match change {
                NodeChange::Created(id) => {
                    self.remove_node(*id);
                }
                NodeChange::Modified(id, old_node) => {
                    self.store_node(*id, old_node.clone());
                }
            }
        }
        self.root = root_id;
        self.height = tree_height;
        // Task 1.7: label_of reads parent-held child labels (v2) in O(1);
        // compute_label_fallback still fires for v1 legacy as a bounded
        // one-time cost until v2 has rewritten the affected nodes.
        self.root_label = self.label_of(root_id);
    }

    // invariant: label-passthrough — returns `(node_id, AvlNode)` pairs
    // INCLUDING the stored labels on each node. Used by the persist
    // pipeline to write changed nodes to redb. Persistence is byte-exact
    // passthrough; labels stored to disk are the labels the in-memory
    // tree just produced via `insert`/`remove` maintenance. Do NOT use
    // this method as a label trust source for consensus paths.
    /// Iterate over dirty (modified + created) nodes for flushing to persistent storage.
    pub fn dirty_nodes(&self) -> Vec<(u64, AvlNode)> {
        let mut seen = std::collections::HashSet::new();
        let mut result = Vec::new();
        for change in self.change_log.changes() {
            let id = match change {
                NodeChange::Created(id) => *id,
                NodeChange::Modified(id, _) => *id,
            };
            if seen.insert(id) {
                if let Some(node) = self.node_get(id) {
                    result.push((id, node));
                }
            }
        }
        result
    }

    // invariant: label-agnostic — returns node-id metadata about pending
    // writes; does not depend on label correctness.
    /// Node IDs that were touched by this block's mutations but no longer exist
    /// in the arena (removed during tree rebalancing). These should be deleted
    /// from persistent storage.
    pub fn deleted_node_ids(&self) -> Vec<u64> {
        let mut seen = std::collections::HashSet::new();
        let mut result = Vec::new();
        for change in self.change_log.changes() {
            let id = match change {
                NodeChange::Created(id) | NodeChange::Modified(id, _) => *id,
            };
            if seen.insert(id) && !self.has_node(id) {
                result.push(id);
            }
        }
        result
    }

    // invariant: label-passthrough — returns the raw `AvlNode` including
    // its stored label. Caller MUST NOT trust the returned label without
    // an external verification — this method is for persistence-layer
    // writes and maintenance, not for consensus-path reads.
    /// Get a node by ID (owned). Used by the store to write individual dirty
    /// nodes to persistent storage.
    pub fn get_node(&self, id: NodeId) -> Option<AvlNode> {
        self.node_get(id)
    }

    // invariant: label-agnostic — drops the change log after a successful
    // commit; does not read or write labels.
    /// Clear the change log after a successful commit.
    pub fn clear_dirty(&mut self) {
        self.change_log = ChangeLog::new();
    }

    // invariant: label-agnostic — arena lifecycle; does not read labels.
    /// Notify the arena of a successful commit (moves dirty → clean in
    /// CachedDiskArena; no-op for MemoryArena).
    pub fn arena_commit(&mut self) {
        self.arena.commit();
    }

    // invariant: label-agnostic — arena lifecycle; does not read labels.
    /// Notify the arena of an abort (discards dirty + clean cache in
    /// CachedDiskArena; no-op for MemoryArena).
    pub fn arena_abort(&mut self) {
        self.arena.abort();
    }

    // invariant: label-agnostic — returns node-id metadata about which
    // labels are dirty; does not depend on label correctness.
    /// Take the set of node IDs whose labels were computed since last commit.
    /// Used by persist_apply to write labels to redb in the same transaction.
    pub fn take_label_dirty(&mut self) -> std::collections::HashSet<u64> {
        self.arena.take_label_dirty()
    }

    // invariant: label-passthrough — same caveat as `get_node`: returned
    // nodes carry their cached labels; do NOT trust them on the consensus
    // read path without external verification.
    /// Iterate over all nodes in the arena.
    /// Escape hatch for rare maintenance (genesis init, snapshot export).
    pub fn all_nodes(&self) -> Vec<(u64, AvlNode)> {
        self.arena.iter_all()
    }

    // invariant: label-agnostic — structural count only; ignores labels.
    /// Count reachable nodes from the root (for debugging).
    pub fn reachable_node_count(&self) -> usize {
        self.count_reachable(self.root)
    }

    fn count_reachable(&self, id: NodeId) -> usize {
        match self.node_get(id) {
            Some(AvlNode::Leaf { .. }) => 1,
            Some(AvlNode::Internal { left, right, .. }) => {
                1 + self.count_reachable(left) + self.count_reachable(right)
            }
            None => 0,
        }
    }

    // invariant: label-agnostic — structural count only; ignores labels.
    /// Total nodes in arena.
    pub fn arena_size(&self) -> usize {
        self.arena.len()
    }

    // invariant: trust-input-label — caller-supplied `root_label` becomes
    // the new cached root. Used by `rebuild_from_committed` after a reorg
    // abort; caller reads it from committed `state_meta`, so trust flows
    // from durable storage. Code path that calls this MUST have read from
    // committed redb tables.
    /// Reset tree pointers (used by rebuild_from_committed). Caller supplies
    /// the committed root_label from state_meta; no tree walk needed.
    pub fn reset(&mut self, root_id: NodeId, height: u8, next_id: u64, root_label: Digest32) {
        self.root = root_id;
        self.height = height;
        self.next_id = next_id;
        self.root_label = root_label;
        self.change_log = ChangeLog::new();
    }

    fn alloc(&mut self, node: AvlNode) -> NodeId {
        let id = self.next_id;
        self.next_id += 1;
        self.store_node(id, node);
        self.change_log.record_create(id);
        id
    }

    /// Overwrite an existing node in place, recording the before-image.
    fn modify_node(&mut self, id: NodeId, new_node: AvlNode) {
        let old = self.node_clone(id);
        // Normalize legacy v1 Internal before-images so UndoEntry::serialize
        // never panics in node_to_bytes. Bounded one-time cost per v1 internal
        // encountered on a mutation path; fresh DBs never hit this.
        let old = self.normalize_internal_labels(old);
        self.change_log.record_modify(id, old);
        self.store_node(id, new_node);
    }

    /// If `node` is a v1 legacy Internal (missing child labels), compute them
    /// and return a v2-equivalent node. Other node shapes (Leaf, or Internal
    /// already fully labeled) are returned unchanged.
    ///
    /// Used only on before-images captured in ChangeLog. Structural fields
    /// (key, left, right, balance) are preserved exactly; only the label
    /// fields are promoted from None to Some. The arena entry is NOT updated —
    /// callers overwrite it with the new node next.
    ///
    /// Mid-block, a child referenced by `left`/`right` may have already been
    /// removed from the arena by earlier rebalancing. In that case the child's
    /// block-start state is captured in the ChangeLog as a `Modified` entry;
    /// we resolve the label from there.
    fn normalize_internal_labels(&self, node: AvlNode) -> AvlNode {
        match node {
            AvlNode::Internal {
                key,
                left,
                right,
                balance,
                left_label,
                right_label,
                label,
            } => {
                let ll = left_label.unwrap_or_else(|| self.block_start_label(left));
                let rl = right_label.unwrap_or_else(|| self.block_start_label(right));
                AvlNode::Internal {
                    key,
                    left,
                    right,
                    balance,
                    left_label: Some(ll),
                    right_label: Some(rl),
                    label,
                }
            }
            other => other,
        }
    }

    /// Resolve a child's block-start label for before-image normalization.
    ///
    /// If the child was modified or removed earlier in this block, its
    /// block-start state is captured in the ChangeLog as a `Modified`
    /// before-image — use that. Otherwise read from the arena, which still
    /// holds the child's block-start state.
    fn block_start_label(&self, id: NodeId) -> Digest32 {
        // Scan ChangeLog first: a captured Modified before-image is the
        // authoritative block-start state for that node_id, regardless of
        // whether the arena still holds it.
        for change in self.change_log.changes() {
            if let NodeChange::Modified(change_id, before) = change {
                if *change_id == id {
                    return Self::label_from_node_standalone(before);
                }
            }
        }
        // Not modified this block — arena still holds the block-start state.
        if self.has_node(id) {
            return self.compute_label_fallback(id);
        }
        panic!(
            "normalize_internal_labels: child {id} not in arena and not in ChangeLog — \
             consensus bug or corrupted change_log"
        );
    }

    /// Compute a node's own label from its structural content, without
    /// touching the arena. Used for before-image labels captured in the
    /// ChangeLog, which may reference detached subtrees.
    fn label_from_node_standalone(node: &AvlNode) -> Digest32 {
        if let Some(l) = node.label() {
            return *l;
        }
        match node {
            AvlNode::Leaf {
                key,
                value,
                next_key,
                ..
            } => leaf_label(key, value, next_key),
            AvlNode::Internal {
                balance,
                left_label,
                right_label,
                ..
            } => {
                // Every v2 internal has Some child labels. A None here means
                // a v1 before-image captured without normalization — that
                // must never happen (modify_node normalizes on capture).
                let ll = left_label.expect(
                    "label_from_node_standalone: v1 before-image captured without normalization",
                );
                let rl = right_label.expect(
                    "label_from_node_standalone: v1 before-image captured without normalization",
                );
                internal_label(*balance, &ll, &rl)
            }
        }
    }

    // invariant: trusts-cached-label — returns the cached root label
    // maintained by every mutation path (`insert`, `remove`, `rollback`).
    // Trust contract: the per-operation oracle in
    // `tests/avl_labels_oracle.rs` proves this cache matches
    // `ergo_avltree_rust` at every step; production trusts it.
    /// The root's label. Cached in `self.root_label`, maintained by mutations.
    pub fn root_label(&self) -> Digest32 {
        self.root_label
    }

    /// Read a node's label. Uses the cached own-label if present; otherwise
    /// uses stored child labels (v2 internal nodes) and falls back to
    /// recursive compute (v1 legacy) only when a child label is missing.
    /// Leaves always recompute their label from content.
    fn label_of(&self, id: NodeId) -> Digest32 {
        let node = self.node_clone(id);
        if let Some(l) = node.label().cloned() {
            return l;
        }
        match &node {
            AvlNode::Leaf {
                key,
                value,
                next_key,
                ..
            } => {
                let lbl = leaf_label(key, value, next_key);
                self.set_label(id, lbl);
                lbl
            }
            AvlNode::Internal {
                balance,
                left,
                right,
                left_label,
                right_label,
                ..
            } => {
                let ll = match left_label {
                    Some(l) => *l,
                    None => self.compute_label_fallback(*left),
                };
                let rl = match right_label {
                    Some(l) => *l,
                    None => self.compute_label_fallback(*right),
                };
                let lbl = internal_label(*balance, &ll, &rl);
                self.set_label(id, lbl);
                lbl
            }
        }
    }

    /// Cold fallback: recursively computes the full subtree label, ignoring
    /// any stored child labels. Used when a v1 legacy node lacks child labels
    /// and by the transitional recompute in `insert` / `remove` until Tasks
    /// 1.4 + 1.5 thread labels through every mutation path.
    fn compute_label_fallback(&self, id: NodeId) -> Digest32 {
        let node = self.node_clone(id);
        if let Some(l) = node.label().cloned() {
            return l;
        }
        match &node {
            AvlNode::Leaf {
                key,
                value,
                next_key,
                ..
            } => {
                let lbl = leaf_label(key, value, next_key);
                self.set_label(id, lbl);
                lbl
            }
            AvlNode::Internal {
                balance,
                left,
                right,
                ..
            } => {
                let ll = self.compute_label_fallback(*left);
                let rl = self.compute_label_fallback(*right);
                let lbl = internal_label(*balance, &ll, &rl);
                self.set_label(id, lbl);
                lbl
            }
        }
    }

    // invariant: trusts-cached-label — O(1) wrapper over `root_label()`;
    // same trust contract. Returns the 33-byte `ADDigest` form that flows
    // into the block header's `state_root`.
    /// Get the 33-byte authenticated root digest. O(1): reads the cached
    /// `root_label` field — no arena traversal.
    pub fn root_digest(&self) -> ADDigest {
        root_digest(&self.root_label, self.height)
    }

    // invariant: force-recompute-only — test-only oracle that walks the
    // subtree and recomputes every label from structure, ignoring cached
    // labels. Returns what the cache *should* equal. Disagreement with
    // `root_digest()` indicates stored-label corruption.
    /// TEST-ONLY oracle: recompute the root digest by walking the entire
    /// subtree and recomputing every label from structure, **ignoring** any
    /// stored `left_label`/`right_label`/`label` fields. Used to prove that
    /// the stored labels aren't stale after incremental updates.
    #[cfg(any(test, feature = "recompute-oracle"))]
    pub fn forced_full_recompute_digest(&self) -> ADDigest {
        let label = self.recompute_subtree_label(self.root);
        root_digest(&label, self.height)
    }

    /// TEST-ONLY helper: recompute a subtree's label from scratch. Crucially
    /// does NOT read `left_label`/`right_label` from internal nodes and does
    /// NOT call `set_label` (which would populate the cache and defeat the
    /// oracle's purpose). Only reads `key`/`value`/`next_key` on leaves and
    /// `balance`/`left`/`right` on internals.
    #[cfg(any(test, feature = "recompute-oracle"))]
    fn recompute_subtree_label(&self, id: NodeId) -> Digest32 {
        let node = self.node_clone(id);
        match &node {
            AvlNode::Leaf {
                key,
                value,
                next_key,
                ..
            } => leaf_label(key, value, next_key),
            AvlNode::Internal {
                balance,
                left,
                right,
                ..
            } => {
                let ll = self.recompute_subtree_label(*left);
                let rl = self.recompute_subtree_label(*right);
                internal_label(*balance, &ll, &rl)
            }
        }
    }

    // invariant: label-agnostic — returns the value for a key. Does not
    // consult labels; the result depends only on the BST structure, not
    // on hash cache correctness.
    /// Lookup a value by key. Returns None if not found.
    pub fn lookup(&self, key: &[u8; 32]) -> Option<Vec<u8>> {
        self.lookup_at(self.root, key)
    }

    fn lookup_at(&self, id: NodeId, key: &[u8; 32]) -> Option<Vec<u8>> {
        let node = self.node_get(id)?;
        match node {
            AvlNode::Leaf {
                key: leaf_key,
                value,
                ..
            } => {
                if &leaf_key == key {
                    Some(value)
                } else {
                    None
                }
            }
            AvlNode::Internal {
                key: sep_key,
                left,
                right,
                ..
            } => {
                if key < &sep_key {
                    self.lookup_at(left, key)
                } else {
                    self.lookup_at(right, key)
                }
            }
        }
    }

    /// Fetch a child's label from the parent's stored fields. Falls back to
    /// `compute_label_fallback` only when the parent is v1 legacy (the stored
    /// field is `None`). On the hot path callers MUST have the parent's
    /// `left_label`/`right_label` already destructured — never load the
    /// sibling node just to compute its label.
    fn sibling_label_from_parent(
        &self,
        left_id: NodeId,
        right_id: NodeId,
        left_label: &Option<Digest32>,
        right_label: &Option<Digest32>,
        which: Side,
    ) -> Digest32 {
        match which {
            Side::Left => match left_label {
                Some(l) => *l,
                None => self.compute_label_fallback(left_id),
            },
            Side::Right => match right_label {
                Some(l) => *l,
                None => self.compute_label_fallback(right_id),
            },
        }
    }

    // invariant: label-mutator (writer) — mutates the tree and updates
    // labels along the dirtied path. Maintains the per-operation oracle
    // invariant: after return, every label on the affected ancestor
    // chain matches what `forced_full_recompute_digest()` would produce.
    /// Insert a key-value pair. Returns the old value if the key already existed.
    pub fn insert(&mut self, key: [u8; 32], value: Vec<u8>) -> Option<Vec<u8>> {
        assert!(key > NEGATIVE_INFINITY_KEY && key < POSITIVE_INFINITY_KEY);
        let (new_root, new_root_label, _changed, height_increased, old_value) =
            self.insert_at(self.root, &key, value);
        if height_increased {
            self.height += 1;
        }
        self.root = new_root;
        self.root_label = new_root_label;
        old_value
    }

    /// Recursive insert. Returns
    /// `(new_subtree_root, new_subtree_label, changed, height_increased, old_value)`.
    ///
    /// Labels are threaded bottom-up: every `modify_node`/`alloc` that writes
    /// an `AvlNode::Internal` on this path populates `left_label`, `right_label`,
    /// and `label`. Sibling labels come from the parent's destructured
    /// `left_label`/`right_label` fields — never from a fresh arena load.
    fn insert_at(
        &mut self,
        id: NodeId,
        key: &[u8; 32],
        value: Vec<u8>,
    ) -> (NodeId, Digest32, bool, bool, Option<Vec<u8>>) {
        let node = self.node_clone(id);
        match node {
            AvlNode::Leaf {
                key: leaf_key,
                value: leaf_value,
                next_key,
                ..
            } => {
                match key.cmp(&leaf_key) {
                    std::cmp::Ordering::Equal => {
                        let old = leaf_value;
                        let new_label = leaf_label(&leaf_key, &value, &next_key);
                        self.modify_node(
                            id,
                            AvlNode::Leaf {
                                key: leaf_key,
                                value,
                                next_key,
                                label: None,
                            },
                        );
                        (id, new_label, true, false, Some(old))
                    }
                    std::cmp::Ordering::Greater => {
                        // Modified left leaf: key=leaf_key, value=leaf_value, next_key=*key.
                        let left_label_val = leaf_label(&leaf_key, &leaf_value, key);
                        self.modify_node(
                            id,
                            AvlNode::Leaf {
                                key: leaf_key,
                                value: leaf_value,
                                next_key: *key,
                                label: None,
                            },
                        );
                        // New right leaf: key=*key, value, next_key=next_key.
                        let right_label_val = leaf_label(key, &value, &next_key);
                        let right = self.alloc(AvlNode::Leaf {
                            key: *key,
                            value,
                            next_key,
                            label: None,
                        });
                        let own_label = internal_label(0, &left_label_val, &right_label_val);
                        let internal = self.alloc(AvlNode::Internal {
                            key: *key,
                            left: id,
                            right,
                            balance: 0,
                            left_label: Some(left_label_val),
                            right_label: Some(right_label_val),
                            label: Some(own_label),
                        });
                        (internal, own_label, true, true, None)
                    }
                    std::cmp::Ordering::Less => {
                        // New left leaf: key=*key, value, next_key=leaf_key.
                        let left_label_val = leaf_label(key, &value, &leaf_key);
                        let left = self.alloc(AvlNode::Leaf {
                            key: *key,
                            value,
                            next_key: leaf_key,
                            label: None,
                        });
                        // Modified right leaf: same key/value/next_key as before.
                        let right_label_val = leaf_label(&leaf_key, &leaf_value, &next_key);
                        self.modify_node(
                            id,
                            AvlNode::Leaf {
                                key: leaf_key,
                                value: leaf_value,
                                next_key,
                                label: None,
                            },
                        );
                        let own_label = internal_label(0, &left_label_val, &right_label_val);
                        let internal = self.alloc(AvlNode::Internal {
                            key: leaf_key,
                            left,
                            right: id,
                            balance: 0,
                            left_label: Some(left_label_val),
                            right_label: Some(right_label_val),
                            label: Some(own_label),
                        });
                        (internal, own_label, true, true, None)
                    }
                }
            }
            AvlNode::Internal {
                key: sep_key,
                left,
                right,
                balance,
                left_label,
                right_label,
                ..
            } => {
                if key < &sep_key {
                    let (new_left, new_left_label, changed, child_height_increased, old_value) =
                        self.insert_at(left, key, value);
                    if !changed {
                        // Parent unchanged — recompute our own label from the
                        // parent-held child labels (v1 fallback on miss).
                        let ll = self.sibling_label_from_parent(
                            left,
                            right,
                            &left_label,
                            &right_label,
                            Side::Left,
                        );
                        let rl = self.sibling_label_from_parent(
                            left,
                            right,
                            &left_label,
                            &right_label,
                            Side::Right,
                        );
                        let own_label = internal_label(balance, &ll, &rl);
                        return (id, own_label, false, false, old_value);
                    }
                    if child_height_increased && balance < 0 {
                        let new_left_balance = self.get_balance(new_left);
                        let right_sibling_label = self.sibling_label_from_parent(
                            left,
                            right,
                            &left_label,
                            &right_label,
                            Side::Right,
                        );
                        let (result, result_label) = if new_left_balance < 0 {
                            self.single_right_rotate(
                                id,
                                new_left,
                                new_left_label,
                                right,
                                right_sibling_label,
                                &sep_key,
                            )
                        } else {
                            self.double_right_rotate(
                                id,
                                new_left,
                                new_left_label,
                                right,
                                right_sibling_label,
                                &sep_key,
                            )
                        };
                        return (result, result_label, true, false, old_value);
                    }
                    let my_height_increased = child_height_increased && balance == 0;
                    let new_balance = if child_height_increased {
                        balance - 1
                    } else {
                        balance
                    };
                    let right_sibling_label = self.sibling_label_from_parent(
                        left,
                        right,
                        &left_label,
                        &right_label,
                        Side::Right,
                    );
                    let new_own_label =
                        internal_label(new_balance, &new_left_label, &right_sibling_label);
                    self.modify_node(
                        id,
                        AvlNode::Internal {
                            key: sep_key,
                            left: new_left,
                            right,
                            balance: new_balance,
                            left_label: Some(new_left_label),
                            right_label: Some(right_sibling_label),
                            label: Some(new_own_label),
                        },
                    );
                    (id, new_own_label, true, my_height_increased, old_value)
                } else {
                    let (new_right, new_right_label, changed, child_height_increased, old_value) =
                        self.insert_at(right, key, value);
                    if !changed {
                        let ll = self.sibling_label_from_parent(
                            left,
                            right,
                            &left_label,
                            &right_label,
                            Side::Left,
                        );
                        let rl = self.sibling_label_from_parent(
                            left,
                            right,
                            &left_label,
                            &right_label,
                            Side::Right,
                        );
                        let own_label = internal_label(balance, &ll, &rl);
                        return (id, own_label, false, false, old_value);
                    }
                    if child_height_increased && balance > 0 {
                        let new_right_balance = self.get_balance(new_right);
                        let left_sibling_label = self.sibling_label_from_parent(
                            left,
                            right,
                            &left_label,
                            &right_label,
                            Side::Left,
                        );
                        let (result, result_label) = if new_right_balance > 0 {
                            self.single_left_rotate(
                                id,
                                left,
                                left_sibling_label,
                                new_right,
                                new_right_label,
                                &sep_key,
                            )
                        } else {
                            self.double_left_rotate(
                                id,
                                left,
                                left_sibling_label,
                                new_right,
                                new_right_label,
                                &sep_key,
                            )
                        };
                        return (result, result_label, true, false, old_value);
                    }
                    let my_height_increased = child_height_increased && balance == 0;
                    let new_balance = if child_height_increased {
                        balance + 1
                    } else {
                        balance
                    };
                    let left_sibling_label = self.sibling_label_from_parent(
                        left,
                        right,
                        &left_label,
                        &right_label,
                        Side::Left,
                    );
                    let new_own_label =
                        internal_label(new_balance, &left_sibling_label, &new_right_label);
                    self.modify_node(
                        id,
                        AvlNode::Internal {
                            key: sep_key,
                            left,
                            right: new_right,
                            balance: new_balance,
                            left_label: Some(left_sibling_label),
                            right_label: Some(new_right_label),
                            label: Some(new_own_label),
                        },
                    );
                    (id, new_own_label, true, my_height_increased, old_value)
                }
            }
        }
    }

    // invariant: label-mutator (writer) — same trust contract as `insert`:
    // updates labels along the dirtied path so the per-operation oracle
    // invariant holds after return.
    /// Remove a key. Returns the old value if found.
    pub fn remove(&mut self, key: &[u8; 32]) -> Option<Vec<u8>> {
        assert!(*key > NEGATIVE_INFINITY_KEY && *key < POSITIVE_INFINITY_KEY);
        let found = self.find_leaf(self.root, key);
        if !found {
            return None;
        }
        let (new_root, new_root_label, height_decreased, old_value, _) =
            self.delete_at(self.root, key, false);
        if height_decreased {
            self.height -= 1;
        }
        self.root = new_root;
        self.root_label = new_root_label;
        Some(old_value)
    }

    fn find_leaf(&self, id: NodeId, key: &[u8; 32]) -> bool {
        let node = self.node_clone(id);
        match node {
            AvlNode::Leaf { key: leaf_key, .. } => &leaf_key == key,
            AvlNode::Internal {
                key: sep_key,
                left,
                right,
                ..
            } => {
                if key < &sep_key {
                    self.find_leaf(left, key)
                } else {
                    self.find_leaf(right, key)
                }
            }
        }
    }

    /// Recursive delete. Returns
    /// `(new_subtree_root, new_subtree_label, height_decreased, old_value, saved_deleted_leaf)`.
    ///
    /// Labels thread bottom-up. At internal nodes, sibling labels come from
    /// the parent's destructured `left_label`/`right_label` — never from a
    /// sibling-node load.
    fn delete_at(
        &mut self,
        id: NodeId,
        key: &[u8; 32],
        delete_max: bool,
    ) -> (NodeId, Digest32, bool, Vec<u8>, Option<DeletedLeaf>) {
        let node = self.node_clone(id);
        match node {
            AvlNode::Internal {
                key: sep_key,
                left,
                right,
                balance,
                left_label,
                right_label,
                ..
            } => {
                let direction: i32 = if delete_max {
                    1
                } else {
                    match key.cmp(&sep_key) {
                        std::cmp::Ordering::Less => -1,
                        std::cmp::Ordering::Equal => 0,
                        std::cmp::Ordering::Greater => 1,
                    }
                };

                if direction >= 0 {
                    let right_node = self.node_clone(right);
                    if let AvlNode::Leaf {
                        key: right_key,
                        value: right_value,
                        next_key: right_next_key,
                        ..
                    } = right_node
                    {
                        if delete_max || right_key == *key {
                            let old_value = right_value.clone();
                            let saved = if delete_max {
                                Some(DeletedLeaf {
                                    key: right_key,
                                    value: right_value,
                                })
                            } else {
                                None
                            };
                            let (new_left, new_left_label) = if delete_max {
                                // Left subtree is structurally unchanged. Its
                                // label comes from the parent-held left_label
                                // (v1 fallback on miss).
                                let ll = self.sibling_label_from_parent(
                                    left,
                                    right,
                                    &left_label,
                                    &right_label,
                                    Side::Left,
                                );
                                (left, ll)
                            } else {
                                self.change_max_next_key(left, &right_next_key)
                            };
                            // `id` is the internal being spliced out; normalize
                            // any v1 before-image so UndoEntry::serialize can't
                            // panic. `right` is a Leaf — no normalization needed.
                            let id_old = self.normalize_internal_labels(self.node_clone(id));
                            self.change_log.record_modify(id, id_old);
                            self.change_log.record_modify(right, self.node_clone(right));
                            self.remove_node(id);
                            self.remove_node(right);
                            return (new_left, new_left_label, true, old_value, saved);
                        }
                    }
                }

                if direction == 0 {
                    let left_node = self.node_clone(left);
                    if let AvlNode::Leaf {
                        key: left_key,
                        value: left_value,
                        ..
                    } = left_node
                    {
                        let old_value = left_value.clone();
                        let (new_right, new_right_label) =
                            self.change_min_key_value(right, &left_key, &left_value);
                        // Same rationale: `id` is the internal being spliced
                        // out; normalize v1 before-image. `left` is a Leaf.
                        let id_old = self.normalize_internal_labels(self.node_clone(id));
                        self.change_log.record_modify(id, id_old);
                        self.change_log.record_modify(left, self.node_clone(left));
                        self.remove_node(id);
                        self.remove_node(left);
                        return (new_right, new_right_label, true, old_value, None);
                    }
                }

                if direction <= 0 {
                    if direction == 0 {
                        let old_value = self.find_min_value(right);
                        let (new_left, new_left_label, child_decreased, _discarded, saved) =
                            self.delete_at(left, key, true);
                        let saved = saved.unwrap();
                        let (new_right, new_right_label) =
                            self.change_min_key_value(right, &saved.key, &saved.value);
                        let (result, result_label, total_decreased) = self
                            .rebalance_after_left_shrink(LeftShrink {
                                id,
                                sep_key: saved.key,
                                new_left,
                                new_left_label,
                                right: new_right,
                                parent_right_label: Some(new_right_label),
                                balance,
                                child_decreased,
                            });
                        (result, result_label, total_decreased, old_value, None)
                    } else {
                        let (new_left, new_left_label, child_decreased, old_value, saved) =
                            self.delete_at(left, key, delete_max);
                        let (result, result_label, total_decreased) = self
                            .rebalance_after_left_shrink(LeftShrink {
                                id,
                                sep_key,
                                new_left,
                                new_left_label,
                                right,
                                parent_right_label: right_label,
                                balance,
                                child_decreased,
                            });
                        (result, result_label, total_decreased, old_value, saved)
                    }
                } else {
                    let (new_right, new_right_label, child_decreased, old_value, saved) =
                        self.delete_at(right, key, delete_max);
                    let (result, result_label, total_decreased) = self
                        .rebalance_after_right_shrink(RightShrink {
                            id,
                            sep_key,
                            left,
                            parent_left_label: left_label,
                            new_right,
                            new_right_label,
                            balance,
                            child_decreased,
                        });
                    (result, result_label, total_decreased, old_value, saved)
                }
            }
            _ => panic!("delete_at reached a leaf directly"),
        }
    }

    // ---- Rotation helpers ----

    /// Single right rotation (LL imbalance). Returns the new subtree root and
    /// its label. Caller passes both children's labels so we never re-read
    /// them via `label_of`; the left-child's own `left_label`/`right_label`
    /// fields are read from the destructured internal node (with v1 fallback).
    fn single_right_rotate(
        &mut self,
        current: NodeId,
        left_child: NodeId,
        _left_child_label: Digest32,
        right_child: NodeId,
        right_child_label: Digest32,
        sep_key: &[u8; 32],
    ) -> (NodeId, Digest32) {
        let lc_node = self.node_clone(left_child);
        let (lc_key, lc_left, lc_right, lc_left_label, lc_right_label) = match lc_node {
            AvlNode::Internal {
                key,
                left,
                right,
                left_label,
                right_label,
                ..
            } => (key, left, right, left_label, right_label),
            _ => panic!("single_right_rotate: left_child is not internal"),
        };
        let lc_right_label_val = match lc_right_label {
            Some(l) => l,
            None => self.compute_label_fallback(lc_right),
        };
        let lc_left_label_val = match lc_left_label {
            Some(l) => l,
            None => self.compute_label_fallback(lc_left),
        };
        let new_current_label = internal_label(0, &lc_right_label_val, &right_child_label);
        self.modify_node(
            current,
            AvlNode::Internal {
                key: *sep_key,
                left: lc_right,
                right: right_child,
                balance: 0,
                left_label: Some(lc_right_label_val),
                right_label: Some(right_child_label),
                label: Some(new_current_label),
            },
        );
        let new_root_label = internal_label(0, &lc_left_label_val, &new_current_label);
        self.modify_node(
            left_child,
            AvlNode::Internal {
                key: lc_key,
                left: lc_left,
                right: current,
                balance: 0,
                left_label: Some(lc_left_label_val),
                right_label: Some(new_current_label),
                label: Some(new_root_label),
            },
        );
        (left_child, new_root_label)
    }

    /// Single left rotation (RR imbalance). Mirror of single_right_rotate.
    fn single_left_rotate(
        &mut self,
        current: NodeId,
        left_child: NodeId,
        left_child_label: Digest32,
        right_child: NodeId,
        _right_child_label: Digest32,
        sep_key: &[u8; 32],
    ) -> (NodeId, Digest32) {
        let rc_node = self.node_clone(right_child);
        let (rc_key, rc_left, rc_right, rc_left_label, rc_right_label) = match rc_node {
            AvlNode::Internal {
                key,
                left,
                right,
                left_label,
                right_label,
                ..
            } => (key, left, right, left_label, right_label),
            _ => panic!("single_left_rotate: right_child is not internal"),
        };
        let rc_left_label_val = match rc_left_label {
            Some(l) => l,
            None => self.compute_label_fallback(rc_left),
        };
        let rc_right_label_val = match rc_right_label {
            Some(l) => l,
            None => self.compute_label_fallback(rc_right),
        };
        let new_current_label = internal_label(0, &left_child_label, &rc_left_label_val);
        self.modify_node(
            current,
            AvlNode::Internal {
                key: *sep_key,
                left: left_child,
                right: rc_left,
                balance: 0,
                left_label: Some(left_child_label),
                right_label: Some(rc_left_label_val),
                label: Some(new_current_label),
            },
        );
        let new_root_label = internal_label(0, &new_current_label, &rc_right_label_val);
        self.modify_node(
            right_child,
            AvlNode::Internal {
                key: rc_key,
                left: current,
                right: rc_right,
                balance: 0,
                left_label: Some(new_current_label),
                right_label: Some(rc_right_label_val),
                label: Some(new_root_label),
            },
        );
        (right_child, new_root_label)
    }

    /// Double right rotation (LR imbalance). Promotes left_child.right to root.
    fn double_right_rotate(
        &mut self,
        current: NodeId,
        left_child: NodeId,
        _left_child_label: Digest32,
        right_child: NodeId,
        right_child_label: Digest32,
        sep_key: &[u8; 32],
    ) -> (NodeId, Digest32) {
        let lc_node = self.node_clone(left_child);
        let (lc_key, lc_left, lc_right, lc_left_label, lc_right_label) = match lc_node {
            AvlNode::Internal {
                key,
                left,
                right,
                left_label,
                right_label,
                ..
            } => (key, left, right, left_label, right_label),
            _ => panic!("double_right_rotate: left_child is not internal"),
        };
        let lr_node = self.node_clone(lc_right);
        let (lr_key, lr_left, lr_right, lr_left_label, lr_right_label, lr_balance) = match lr_node {
            AvlNode::Internal {
                key,
                left,
                right,
                left_label,
                right_label,
                balance,
                ..
            } => (key, left, right, left_label, right_label, balance),
            _ => panic!("double_right_rotate: lc_right is not internal"),
        };
        let (nlb, nrb) = match lr_balance {
            0 => (0i8, 0i8),
            -1 => (0i8, 1i8),
            1 => (-1i8, 0i8),
            _ => panic!("invalid balance {lr_balance}"),
        };
        // Destructured labels for grandchildren, with v1 fallback.
        let lc_left_label_val = match lc_left_label {
            Some(l) => l,
            None => self.compute_label_fallback(lc_left),
        };
        // lc_right_label (present on the parent) is no longer needed — it
        // described lc_right's OLD subtree; lc_right gets a new balance below
        // and becomes the new root. Its fresh label is computed from its new
        // children (left_child and current).
        let _ = lc_right_label;
        let lr_left_label_val = match lr_left_label {
            Some(l) => l,
            None => self.compute_label_fallback(lr_left),
        };
        let lr_right_label_val = match lr_right_label {
            Some(l) => l,
            None => self.compute_label_fallback(lr_right),
        };

        // New left_child: key=lc_key, left=lc_left, right=lr_left, balance=nlb
        let new_left_child_label = internal_label(nlb, &lc_left_label_val, &lr_left_label_val);
        self.modify_node(
            left_child,
            AvlNode::Internal {
                key: lc_key,
                left: lc_left,
                right: lr_left,
                balance: nlb,
                left_label: Some(lc_left_label_val),
                right_label: Some(lr_left_label_val),
                label: Some(new_left_child_label),
            },
        );
        // New current: key=sep_key, left=lr_right, right=right_child, balance=nrb
        let new_current_label = internal_label(nrb, &lr_right_label_val, &right_child_label);
        self.modify_node(
            current,
            AvlNode::Internal {
                key: *sep_key,
                left: lr_right,
                right: right_child,
                balance: nrb,
                left_label: Some(lr_right_label_val),
                right_label: Some(right_child_label),
                label: Some(new_current_label),
            },
        );
        // New root (was lc_right): key=lr_key, left=left_child, right=current, balance=0
        let new_root_label = internal_label(0, &new_left_child_label, &new_current_label);
        self.modify_node(
            lc_right,
            AvlNode::Internal {
                key: lr_key,
                left: left_child,
                right: current,
                balance: 0,
                left_label: Some(new_left_child_label),
                right_label: Some(new_current_label),
                label: Some(new_root_label),
            },
        );
        (lc_right, new_root_label)
    }

    /// Double left rotation (RL imbalance). Mirror of double_right_rotate.
    fn double_left_rotate(
        &mut self,
        current: NodeId,
        left_child: NodeId,
        left_child_label: Digest32,
        right_child: NodeId,
        _right_child_label: Digest32,
        sep_key: &[u8; 32],
    ) -> (NodeId, Digest32) {
        let rc_node = self.node_clone(right_child);
        let (rc_key, rc_left, rc_right, rc_left_label, rc_right_label) = match rc_node {
            AvlNode::Internal {
                key,
                left,
                right,
                left_label,
                right_label,
                ..
            } => (key, left, right, left_label, right_label),
            _ => panic!("double_left_rotate: right_child is not internal"),
        };
        let rl_node = self.node_clone(rc_left);
        let (rl_key, rl_left, rl_right, rl_left_label, rl_right_label, rl_balance) = match rl_node {
            AvlNode::Internal {
                key,
                left,
                right,
                left_label,
                right_label,
                balance,
                ..
            } => (key, left, right, left_label, right_label, balance),
            _ => panic!("double_left_rotate: rc_left is not internal"),
        };
        let (nlb, nrb) = match rl_balance {
            0 => (0i8, 0i8),
            -1 => (0i8, 1i8),
            1 => (-1i8, 0i8),
            _ => panic!("invalid balance {rl_balance}"),
        };
        let _ = rc_left_label;
        let rc_right_label_val = match rc_right_label {
            Some(l) => l,
            None => self.compute_label_fallback(rc_right),
        };
        let rl_left_label_val = match rl_left_label {
            Some(l) => l,
            None => self.compute_label_fallback(rl_left),
        };
        let rl_right_label_val = match rl_right_label {
            Some(l) => l,
            None => self.compute_label_fallback(rl_right),
        };

        // New current: key=sep_key, left=left_child, right=rl_left, balance=nlb
        let new_current_label = internal_label(nlb, &left_child_label, &rl_left_label_val);
        self.modify_node(
            current,
            AvlNode::Internal {
                key: *sep_key,
                left: left_child,
                right: rl_left,
                balance: nlb,
                left_label: Some(left_child_label),
                right_label: Some(rl_left_label_val),
                label: Some(new_current_label),
            },
        );
        // New right_child: key=rc_key, left=rl_right, right=rc_right, balance=nrb
        let new_right_child_label = internal_label(nrb, &rl_right_label_val, &rc_right_label_val);
        self.modify_node(
            right_child,
            AvlNode::Internal {
                key: rc_key,
                left: rl_right,
                right: rc_right,
                balance: nrb,
                left_label: Some(rl_right_label_val),
                right_label: Some(rc_right_label_val),
                label: Some(new_right_child_label),
            },
        );
        // New root (was rc_left): key=rl_key, left=current, right=right_child, balance=0
        let new_root_label = internal_label(0, &new_current_label, &new_right_child_label);
        self.modify_node(
            rc_left,
            AvlNode::Internal {
                key: rl_key,
                left: current,
                right: right_child,
                balance: 0,
                left_label: Some(new_current_label),
                right_label: Some(new_right_child_label),
                label: Some(new_root_label),
            },
        );
        (rc_left, new_root_label)
    }

    // ---- Deletion helpers ----

    /// Update the `next_key` of the rightmost leaf in the subtree rooted at
    /// `id`. Returns `(subtree_root, subtree_label)`. Labels thread up using
    /// parent-held sibling fields (v1 fallback only when a stored label is
    /// None).
    fn change_max_next_key(&mut self, id: NodeId, new_next_key: &[u8; 32]) -> (NodeId, Digest32) {
        let node = self.node_clone(id);
        match node {
            AvlNode::Leaf { key, value, .. } => {
                let new_label = leaf_label(&key, &value, new_next_key);
                self.modify_node(
                    id,
                    AvlNode::Leaf {
                        key,
                        value,
                        next_key: *new_next_key,
                        label: Some(new_label),
                    },
                );
                (id, new_label)
            }
            AvlNode::Internal {
                key: sep_key,
                left,
                right,
                balance,
                left_label,
                right_label,
                ..
            } => {
                let (new_right, new_right_label) = self.change_max_next_key(right, new_next_key);
                let ll = self.sibling_label_from_parent(
                    left,
                    right,
                    &left_label,
                    &right_label,
                    Side::Left,
                );
                let new_own_label = internal_label(balance, &ll, &new_right_label);
                self.modify_node(
                    id,
                    AvlNode::Internal {
                        key: sep_key,
                        left,
                        right: new_right,
                        balance,
                        left_label: Some(ll),
                        right_label: Some(new_right_label),
                        label: Some(new_own_label),
                    },
                );
                (id, new_own_label)
            }
        }
    }

    /// Update the key+value of the leftmost leaf in the subtree rooted at
    /// `id`. Returns `(subtree_root, subtree_label)`. Same label-threading
    /// discipline as `change_max_next_key`.
    fn change_min_key_value(
        &mut self,
        id: NodeId,
        new_key: &[u8; 32],
        new_value: &[u8],
    ) -> (NodeId, Digest32) {
        let node = self.node_clone(id);
        match node {
            AvlNode::Leaf { next_key, .. } => {
                let new_label = leaf_label(new_key, new_value, &next_key);
                self.modify_node(
                    id,
                    AvlNode::Leaf {
                        key: *new_key,
                        value: new_value.to_vec(),
                        next_key,
                        label: Some(new_label),
                    },
                );
                (id, new_label)
            }
            AvlNode::Internal {
                key: sep_key,
                left,
                right,
                balance,
                left_label,
                right_label,
                ..
            } => {
                let (new_left, new_left_label) =
                    self.change_min_key_value(left, new_key, new_value);
                let rl = self.sibling_label_from_parent(
                    left,
                    right,
                    &left_label,
                    &right_label,
                    Side::Right,
                );
                let new_own_label = internal_label(balance, &new_left_label, &rl);
                self.modify_node(
                    id,
                    AvlNode::Internal {
                        key: sep_key,
                        left: new_left,
                        right,
                        balance,
                        left_label: Some(new_left_label),
                        right_label: Some(rl),
                        label: Some(new_own_label),
                    },
                );
                (id, new_own_label)
            }
        }
    }

    fn find_min_value(&self, id: NodeId) -> Vec<u8> {
        let node = self.node_clone(id);
        match node {
            AvlNode::Leaf { value, .. } => value,
            AvlNode::Internal { left, .. } => self.find_min_value(left),
        }
    }

    /// Rebalance after the left subtree of `id` shrank. The caller passes the
    /// new left subtree root + label, the right subtree id + its label from
    /// the pre-mutation parent's stored `right_label` field (v1 fallback on
    /// miss). Returns `(new_subtree_root, new_subtree_label, height_decreased)`.
    fn rebalance_after_left_shrink(&mut self, shrink: LeftShrink) -> (NodeId, Digest32, bool) {
        let LeftShrink {
            id,
            sep_key,
            new_left,
            new_left_label,
            right,
            parent_right_label,
            balance,
            child_decreased,
        } = shrink;

        let right_label_val =
            parent_right_label.unwrap_or_else(|| self.compute_label_fallback(right));
        if child_decreased && balance > 0 {
            let right_balance = self.get_balance(right);
            if right_balance < 0 {
                let (result, result_label) = self.double_left_rotate(
                    id,
                    new_left,
                    new_left_label,
                    right,
                    right_label_val,
                    &sep_key,
                );
                (result, result_label, true)
            } else {
                // Single left rotation inlined (so we can set the post-rotate
                // balances to `1 - right_balance` / `right_balance - 1` —
                // `single_left_rotate` hard-codes 0/0 which is only correct on
                // the insert path).
                let right_node = self.node_clone(right);
                let (rc_key, rc_left, rc_right, rc_left_label, rc_right_label) = match right_node {
                    AvlNode::Internal {
                        key,
                        left,
                        right,
                        left_label,
                        right_label,
                        ..
                    } => (key, left, right, left_label, right_label),
                    _ => panic!("rebalance_after_left_shrink: right is not internal"),
                };
                let rc_left_label_val =
                    rc_left_label.unwrap_or_else(|| self.compute_label_fallback(rc_left));
                let rc_right_label_val =
                    rc_right_label.unwrap_or_else(|| self.compute_label_fallback(rc_right));
                let new_left_balance = 1 - right_balance;
                let new_r_balance = right_balance - 1;
                let new_id_label =
                    internal_label(new_left_balance, &new_left_label, &rc_left_label_val);
                self.modify_node(
                    id,
                    AvlNode::Internal {
                        key: sep_key,
                        left: new_left,
                        right: rc_left,
                        balance: new_left_balance,
                        left_label: Some(new_left_label),
                        right_label: Some(rc_left_label_val),
                        label: Some(new_id_label),
                    },
                );
                let new_right_label =
                    internal_label(new_r_balance, &new_id_label, &rc_right_label_val);
                self.modify_node(
                    right,
                    AvlNode::Internal {
                        key: rc_key,
                        left: id,
                        right: rc_right,
                        balance: new_r_balance,
                        left_label: Some(new_id_label),
                        right_label: Some(rc_right_label_val),
                        label: Some(new_right_label),
                    },
                );
                (right, new_right_label, new_r_balance == 0)
            }
        } else {
            let new_balance = if child_decreased {
                balance + 1
            } else {
                balance
            };
            let new_own_label = internal_label(new_balance, &new_left_label, &right_label_val);
            self.modify_node(
                id,
                AvlNode::Internal {
                    key: sep_key,
                    left: new_left,
                    right,
                    balance: new_balance,
                    left_label: Some(new_left_label),
                    right_label: Some(right_label_val),
                    label: Some(new_own_label),
                },
            );
            (id, new_own_label, child_decreased && new_balance == 0)
        }
    }

    /// Mirror of `rebalance_after_left_shrink` for right-shrink.
    fn rebalance_after_right_shrink(&mut self, shrink: RightShrink) -> (NodeId, Digest32, bool) {
        let RightShrink {
            id,
            sep_key,
            left,
            parent_left_label,
            new_right,
            new_right_label,
            balance,
            child_decreased,
        } = shrink;

        let left_label_val = parent_left_label.unwrap_or_else(|| self.compute_label_fallback(left));
        if child_decreased && balance < 0 {
            let left_balance = self.get_balance(left);
            if left_balance > 0 {
                let (result, result_label) = self.double_right_rotate(
                    id,
                    left,
                    left_label_val,
                    new_right,
                    new_right_label,
                    &sep_key,
                );
                (result, result_label, true)
            } else {
                // Single right rotation inlined (balances here are
                // `left_balance + 1` / `-1 - left_balance`, not 0/0).
                let left_node = self.node_clone(left);
                let (lc_key, lc_left, lc_right, lc_left_label, lc_right_label) = match left_node {
                    AvlNode::Internal {
                        key,
                        left,
                        right,
                        left_label,
                        right_label,
                        ..
                    } => (key, left, right, left_label, right_label),
                    _ => panic!("rebalance_after_right_shrink: left is not internal"),
                };
                let lc_left_label_val =
                    lc_left_label.unwrap_or_else(|| self.compute_label_fallback(lc_left));
                let lc_right_label_val =
                    lc_right_label.unwrap_or_else(|| self.compute_label_fallback(lc_right));
                let new_right_balance = -1 - left_balance;
                let new_l_balance = left_balance + 1;
                let new_id_label =
                    internal_label(new_right_balance, &lc_right_label_val, &new_right_label);
                self.modify_node(
                    id,
                    AvlNode::Internal {
                        key: sep_key,
                        left: lc_right,
                        right: new_right,
                        balance: new_right_balance,
                        left_label: Some(lc_right_label_val),
                        right_label: Some(new_right_label),
                        label: Some(new_id_label),
                    },
                );
                let new_left_label =
                    internal_label(new_l_balance, &lc_left_label_val, &new_id_label);
                self.modify_node(
                    left,
                    AvlNode::Internal {
                        key: lc_key,
                        left: lc_left,
                        right: id,
                        balance: new_l_balance,
                        left_label: Some(lc_left_label_val),
                        right_label: Some(new_id_label),
                        label: Some(new_left_label),
                    },
                );
                (left, new_left_label, new_l_balance == 0)
            }
        } else {
            let new_balance = if child_decreased {
                balance - 1
            } else {
                balance
            };
            let new_own_label = internal_label(new_balance, &left_label_val, &new_right_label);
            self.modify_node(
                id,
                AvlNode::Internal {
                    key: sep_key,
                    left,
                    right: new_right,
                    balance: new_balance,
                    left_label: Some(left_label_val),
                    right_label: Some(new_right_label),
                    label: Some(new_own_label),
                },
            );
            (id, new_own_label, child_decreased && new_balance == 0)
        }
    }

    // ---- Node access helpers ----

    fn get_balance(&self, id: NodeId) -> i8 {
        match self.node_clone(id) {
            AvlNode::Internal { balance, .. } => balance,
            _ => 0,
        }
    }

    // ----- test-only label-corruption hooks (M-5) -----
    //
    // These three accessors exist for the proptests in
    // `tests/avl_labels_oracle.rs` that pin the M-5 trust invariant:
    // the `recompute-oracle` (`forced_full_recompute_digest`) is
    // genuinely independent of every cached label surface (arena
    // per-node labels AND `self.root_label`), and corruption of those
    // caches is observable through the normal reader paths. Gated
    // behind `#[cfg(any(test, feature = "test-helpers"))]` — never
    // reachable from production.

    // invariant: trusts-cached-label (test-only) — thin wrapper over
    // the private `label_of`, gated `#[cfg(any(test, feature =
    // "test-helpers"))]`. Same trust contract as `root_label()` /
    // `root_digest()`: returns the cached arena label; the M-5
    // proptests use this to observe what the read path would return
    // after corruption.
    /// TEST-ONLY: Read the cached label for `id`. Wraps the private
    /// `label_of` so integration tests in `tests/` can observe what the
    /// arena returns for a specific node.
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn label_of_for_test(&self, id: NodeId) -> Digest32 {
        self.label_of(id)
    }

    // invariant: label-mutator (test-only) — bypasses normal label
    // maintenance to write directly to the arena's per-node label.
    // Gated `#[cfg(any(test, feature = "test-helpers"))]`. Used by
    // the M-5 proptests to assert the arena cache is independent of
    // `forced_full_recompute_digest()`. Never reachable from
    // production.
    /// TEST-ONLY: XOR a single byte of the arena-stored label for `id`.
    /// Bypasses normal label maintenance to simulate stored-label
    /// corruption. Pairs with `forced_full_recompute_digest()` to prove
    /// the oracle is cache-independent.
    ///
    /// Note: this corrupts the arena's stored label for the given node
    /// id. It does NOT affect `self.root_label`. To corrupt the cached
    /// root, use `corrupt_root_label_byte_for_test`.
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn corrupt_arena_label_byte_for_test(&self, id: NodeId, byte_idx: usize, mask: u8) {
        let current = self.label_of(id); // resolves/caches the label first
        let mut bytes = *current.as_bytes();
        bytes[byte_idx] ^= mask;
        self.arena.set_label(id, Digest32::from_bytes(bytes));
    }

    // invariant: label-mutator (test-only) — mutates the cached
    // `self.root_label` field directly, bypassing every normal
    // mutation path. Gated `#[cfg(any(test, feature =
    // "test-helpers"))]`. Pairs with `forced_full_recompute_digest()`
    // to prove the oracle does NOT consult `self.root_label`. Never
    // reachable from production.
    /// TEST-ONLY: XOR a single byte of the cached `self.root_label`.
    /// Pairs with `forced_full_recompute_digest()` to prove the oracle
    /// recomputes from structure and does not consult the cached root.
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn corrupt_root_label_byte_for_test(&mut self, byte_idx: usize, mask: u8) {
        let mut bytes = *self.root_label.as_bytes();
        bytes[byte_idx] ^= mask;
        self.root_label = Digest32::from_bytes(bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use ergo_avltree_rust::authenticated_tree_ops::AuthenticatedTreeOps;
    use ergo_avltree_rust::batch_avl_prover::BatchAVLProver;
    use ergo_avltree_rust::batch_node::{AVLTree as OracleTree, Node, NodeHeader};
    use ergo_avltree_rust::operation::{KeyValue, Operation};

    fn oracle_tree() -> BatchAVLProver {
        BatchAVLProver::new(
            OracleTree::new(
                |digest| Node::LabelOnly(NodeHeader::new(Some(*digest), None)),
                32,
                None,
            ),
            true,
        )
    }

    fn oracle_insert(prover: &mut BatchAVLProver, key: &[u8; 32], value: &[u8]) {
        prover
            .perform_one_operation(&Operation::Insert(KeyValue {
                key: Bytes::from(key.to_vec()),
                value: Bytes::from(value.to_vec()),
            }))
            .unwrap();
    }

    fn oracle_remove(prover: &mut BatchAVLProver, key: &[u8; 32]) {
        prover
            .perform_one_operation(&Operation::Remove(Bytes::from(key.to_vec())))
            .unwrap();
    }

    fn oracle_digest(prover: &BatchAVLProver) -> [u8; 33] {
        let d = prover.digest().unwrap();
        let mut out = [0u8; 33];
        out.copy_from_slice(&d);
        out
    }

    fn our_digest(tree: &mut AvlTree) -> [u8; 33] {
        *tree.root_digest().as_bytes()
    }

    // ----- happy path -----

    #[test]
    fn empty_tree_digest_matches_oracle() {
        let oracle = oracle_tree();
        let mut ours = AvlTree::new();
        assert_eq!(our_digest(&mut ours), oracle_digest(&oracle));
    }

    #[test]
    fn single_insert_digest_matches_oracle() {
        let mut oracle = oracle_tree();
        let mut ours = AvlTree::new();
        let key = [0x42u8; 32];
        let value = vec![0xDE, 0xAD, 0xBE, 0xEF];
        oracle_insert(&mut oracle, &key, &value);
        ours.insert(key, value.clone());
        assert_eq!(our_digest(&mut ours), oracle_digest(&oracle));
    }

    #[test]
    fn three_inserts_digest_matches_oracle() {
        let mut oracle = oracle_tree();
        let mut ours = AvlTree::new();
        let entries = [
            ([0x10u8; 32], vec![0x01]),
            ([0x30u8; 32], vec![0x03]),
            ([0x20u8; 32], vec![0x02]),
        ];
        for (key, value) in &entries {
            oracle_insert(&mut oracle, key, value);
            ours.insert(*key, value.clone());
        }
        assert_eq!(our_digest(&mut ours), oracle_digest(&oracle));
    }

    #[test]
    fn ten_inserts_digest_matches_oracle() {
        let mut oracle = oracle_tree();
        let mut ours = AvlTree::new();
        for i in 0u8..10 {
            let mut key = [0u8; 32];
            key[0] = i * 17 + 5;
            key[31] = i;
            let value = vec![i, i + 1, i + 2];
            oracle_insert(&mut oracle, &key, &value);
            ours.insert(key, value);
        }
        assert_eq!(our_digest(&mut ours), oracle_digest(&oracle));
    }

    #[test]
    fn lookup_returns_correct_values() {
        let mut tree = AvlTree::new();
        let key1 = [0x10; 32];
        let key2 = [0x20; 32];
        let key3 = [0x30; 32];
        tree.insert(key1, vec![1]);
        tree.insert(key2, vec![2]);
        tree.insert(key3, vec![3]);
        assert_eq!(tree.lookup(&key1), Some(vec![1u8]));
        assert_eq!(tree.lookup(&key2), Some(vec![2u8]));
        assert_eq!(tree.lookup(&key3), Some(vec![3u8]));
        assert_eq!(tree.lookup(&[0x40; 32]), None);
    }

    #[test]
    fn insert_then_remove_digest_matches_oracle() {
        let mut oracle = oracle_tree();
        let mut ours = AvlTree::new();
        let keys: Vec<[u8; 32]> = (1u8..=5)
            .map(|i| {
                let mut k = [0u8; 32];
                k[0] = i * 20;
                k
            })
            .collect();
        for (i, key) in keys.iter().enumerate() {
            oracle_insert(&mut oracle, key, &[i as u8]);
            ours.insert(*key, vec![i as u8]);
        }
        oracle_remove(&mut oracle, &keys[2]);
        ours.remove(&keys[2]);
        assert_eq!(
            our_digest(&mut ours),
            oracle_digest(&oracle),
            "after removing key[2]"
        );
        oracle_remove(&mut oracle, &keys[0]);
        ours.remove(&keys[0]);
        assert_eq!(
            our_digest(&mut ours),
            oracle_digest(&oracle),
            "after removing key[0]"
        );
    }

    #[test]
    fn twenty_inserts_then_remove_all_digest_matches_oracle() {
        let mut oracle = oracle_tree();
        let mut ours = AvlTree::new();
        let mut keys: Vec<[u8; 32]> = Vec::new();
        for i in 0u8..20 {
            let mut k = [0u8; 32];
            k[0] = (i.wrapping_mul(37).wrapping_add(13)) % 250 + 1;
            k[1] = i;
            keys.push(k);
        }
        for (i, key) in keys.iter().enumerate() {
            let value = vec![i as u8; 4];
            oracle_insert(&mut oracle, key, &value);
            ours.insert(*key, value);
        }
        assert_eq!(
            our_digest(&mut ours),
            oracle_digest(&oracle),
            "after 20 inserts"
        );
        for key in keys.iter().rev() {
            oracle_remove(&mut oracle, key);
            ours.remove(key);
            assert_eq!(
                our_digest(&mut ours),
                oracle_digest(&oracle),
                "digest mismatch after removing key {:?}",
                &key[..2]
            );
        }
    }

    #[test]
    fn three_inserts_remove_middle() {
        let mut oracle = oracle_tree();
        let mut ours = AvlTree::new();
        let k0 = {
            let mut k = [0u8; 32];
            k[0] = 1;
            k
        };
        let k1 = {
            let mut k = [0u8; 32];
            k[0] = 26;
            k[1] = 1;
            k
        };
        let k2 = {
            let mut k = [0u8; 32];
            k[0] = 51;
            k[1] = 2;
            k
        };
        for (key, val) in [(k0, vec![0u8; 4]), (k1, vec![1u8; 4]), (k2, vec![2u8; 4])] {
            oracle_insert(&mut oracle, &key, &val);
            ours.insert(key, val);
        }
        assert_eq!(
            our_digest(&mut ours),
            oracle_digest(&oracle),
            "after 3 inserts"
        );
        assert!(ours.lookup(&k1).is_some(), "k1 should exist before removal");
        oracle_remove(&mut oracle, &k1);
        ours.remove(&k1);
        assert!(ours.lookup(&k0).is_some(), "k0 should survive removal");
        assert!(ours.lookup(&k2).is_some(), "k2 should survive removal");
        assert!(ours.lookup(&k1).is_none(), "k1 should be gone");
        assert_eq!(
            our_digest(&mut ours),
            oracle_digest(&oracle),
            "after removing k1"
        );
    }

    #[test]
    fn interleaved_insert_remove_matches_oracle() {
        let mut oracle = oracle_tree();
        let mut ours = AvlTree::new();
        let mut keys: Vec<[u8; 32]> = Vec::new();
        for i in 0u8..10 {
            let mut k = [0u8; 32];
            k[0] = i * 25 + 1;
            k[1] = i;
            keys.push(k);
            let value = vec![i; 8];
            oracle_insert(&mut oracle, &k, &value);
            ours.insert(k, value);
        }
        for &idx in &[3usize, 7, 1] {
            oracle_remove(&mut oracle, &keys[idx]);
            ours.remove(&keys[idx]);
            assert_eq!(
                our_digest(&mut ours),
                oracle_digest(&oracle),
                "diverged after removing keys[{idx}]"
            );
        }
        for i in 10u8..12 {
            let mut k = [0u8; 32];
            k[0] = i.wrapping_mul(7).wrapping_add(3);
            k[1] = i;
            keys.push(k);
            let value = vec![i; 8];
            oracle_insert(&mut oracle, &k, &value);
            ours.insert(k, value);
        }
        assert_eq!(our_digest(&mut ours), oracle_digest(&oracle));
        for &idx in &[0usize, 5] {
            oracle_remove(&mut oracle, &keys[idx]);
            ours.remove(&keys[idx]);
        }
        assert_eq!(our_digest(&mut ours), oracle_digest(&oracle));
        for i in 12u8..17 {
            let mut k = [0u8; 32];
            k[0] = i.wrapping_mul(7).wrapping_add(3);
            k[1] = i;
            keys.push(k);
            let value = vec![i; 8];
            oracle_insert(&mut oracle, &k, &value);
            ours.insert(k, value);
        }
        assert_eq!(
            our_digest(&mut ours),
            oracle_digest(&oracle),
            "digest mismatch after interleaved ops"
        );
    }
}
