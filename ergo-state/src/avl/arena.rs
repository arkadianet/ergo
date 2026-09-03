//! Node arena abstraction for the AVL+ tree.
//!
//! Crate-private trait that decouples tree logic from storage backend.
//! Two implementations:
//! - `MemoryArena`: HashMap-backed, used by tests and genesis init.
//! - `CachedDiskArena`: Three-tier (dirty + LRU + redb), used in production.

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use ergo_primitives::digest::Digest32;
use lru::LruCache;
use redb::{Database, ReadOnlyTable, ReadableTable};

use super::node::{AvlNode, NodeId};
use crate::store::AVL_NODES;

/// Minimal crate-private abstraction over node storage.
///
/// All reads return owned `AvlNode` (no references) to support
/// interior mutability in the disk-backed arena.
/// Internal trait — not part of public API. Exposed for integration tests only.
pub trait NodeArena {
    /// Get a node by ID. Returns None if not found.
    fn get(&self, id: NodeId) -> Option<AvlNode>;

    /// Store a node (insert or overwrite).
    fn put(&mut self, id: NodeId, node: AvlNode);

    /// Remove a node from the arena.
    fn remove(&mut self, id: NodeId);

    /// Check if a node exists.
    fn contains(&self, id: NodeId) -> bool;

    /// Set a node's cached label (derived data, not a structural change).
    /// Uses interior mutability — takes &self, not &mut self.
    fn set_label(&self, id: NodeId, label: Digest32);

    /// Number of nodes currently in the arena.
    fn len(&self) -> usize;

    /// True when the arena has no known nodes.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Iterate all nodes. Escape hatch for rare maintenance operations
    /// (genesis init, snapshot export). Materializes all nodes — violates
    /// the bounded-memory story while running.
    fn iter_all(&self) -> Vec<(NodeId, AvlNode)>;

    /// Flush dirty state after a successful redb commit.
    /// For MemoryArena: no-op. For CachedDiskArena: moves dirty → clean.
    fn commit(&mut self);

    /// Discard uncommitted state after a failed operation.
    /// For MemoryArena: no-op. For CachedDiskArena: clears dirty + clean.
    fn abort(&mut self);

    /// Take the set of node IDs whose labels were computed since last commit.
    /// Labels are derived cache data — they are written to redb in the same
    /// transaction as the block commit but are NOT part of the undo log.
    /// Safe to lose on abort (deterministically recomputable).
    fn take_label_dirty(&mut self) -> HashSet<NodeId>;

    /// Total arena reads since last reset. Used by the K v2 read-count
    /// regression tests to prove `root_digest()` is O(1) and mutations read
    /// only the mutation path.
    fn read_count(&self) -> u64;

    /// Reset the read counter to zero.
    fn reset_read_count(&self);

    /// Bytes currently held in the clean LRU cache. Default 0 for arenas
    /// without a byte-budgeted cache (e.g. `MemoryArena`).
    fn cache_clean_bytes(&self) -> usize {
        0
    }

    /// Configured byte budget for the clean cache. Default 0 means
    /// unbudgeted / not applicable.
    fn cache_capacity_bytes(&self) -> usize {
        0
    }

    /// Number of nodes currently in the clean cache.
    fn cache_clean_len(&self) -> usize {
        0
    }

    /// Number of structurally modified (dirty) nodes pending commit.
    fn cache_dirty_len(&self) -> usize {
        0
    }

    /// Open a snapshot read session for a bulk cold-read walk.
    ///
    /// While the returned guard is alive, every cache miss reads through
    /// one already-open redb read transaction and one already-open table
    /// handle instead of opening its own. Closing is by `Drop`.
    ///
    /// Arenas with no disk tier (e.g. [`MemoryArena`]) return an inert
    /// guard.
    fn begin_read_session(&self) -> ReadSession {
        ReadSession::inert()
    }
}

// ============================================================================
// Read sessions
// ============================================================================

/// The redb handles a read session keeps open.
///
/// Only the table is stored: `ReadOnlyTable` owns a clone of the
/// transaction's `Arc<TransactionGuard>`, so holding it pins the same
/// snapshot the originating `ReadTransaction` did.
type SessionTable = ReadOnlyTable<u64, &'static [u8]>;

/// Session state shared between an arena and its live [`ReadSession`].
///
/// Shared ownership (rather than a borrow of the arena) is what lets the
/// state-apply walk hold a session open across `&mut AvlTree` mutations:
/// the guard closes the session on drop without borrowing the tree.
type SessionSlot = Arc<Mutex<Option<SessionTable>>>;

/// Lock a session slot, tolerating poisoning.
///
/// The slot holds a redb read handle and nothing else — a panic elsewhere
/// cannot leave it half-updated, so there is no invariant for poisoning to
/// protect.
fn lock_session(slot: &SessionSlot) -> MutexGuard<'_, Option<SessionTable>> {
    slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// RAII handle for an open snapshot read session.
///
/// INVARIANT: a session must never span a change to the committed redb
/// contents, or cold reads would serve a stale snapshot while the cache
/// serves the new one. Two things enforce it:
///
/// * callers scope the guard to a single read-only walk (hydration) or to
///   the pre-persist mutation walk of one block, dropping it before the
///   write transaction commits;
/// * [`NodeArena::commit`] and [`NodeArena::abort`] close any session still
///   open, so a guard leaked by a panicking walk cannot outlive the block
///   boundary it was opened in.
///
/// A session pins a redb snapshot for as long as it is held, which defers
/// page reuse — another reason to keep it bounded by one block.
#[must_use = "the read session closes as soon as the guard is dropped"]
pub struct ReadSession {
    slot: Option<SessionSlot>,
}

impl ReadSession {
    /// A guard that owns no session. Returned by arenas without a disk
    /// tier, and by a nested `begin_read_session` whose outer guard already
    /// owns the session.
    fn inert() -> Self {
        Self { slot: None }
    }
}

impl Drop for ReadSession {
    fn drop(&mut self) {
        if let Some(slot) = &self.slot {
            *lock_session(slot) = None;
        }
    }
}

// ============================================================================
// MemoryArena
// ============================================================================

/// HashMap-backed arena. Used by tests and genesis initialization.
pub struct MemoryArena {
    nodes: HashMap<NodeId, AvlNode>,
    /// Interior mutability for set_label (which takes &self).
    label_updates: RefCell<Vec<(NodeId, Digest32)>>,
    read_count: AtomicU64,
}

impl Default for MemoryArena {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryArena {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            label_updates: RefCell::new(Vec::new()),
            read_count: AtomicU64::new(0),
        }
    }

    fn flush_labels(&mut self) {
        let updates = self.label_updates.get_mut();
        for (id, label) in updates.drain(..) {
            if let Some(node) = self.nodes.get_mut(&id) {
                match node {
                    AvlNode::Leaf { label: l, .. } => *l = Some(label),
                    AvlNode::Internal { label: l, .. } => *l = Some(label),
                }
            }
        }
    }
}

impl NodeArena for MemoryArena {
    fn get(&self, id: NodeId) -> Option<AvlNode> {
        self.read_count.fetch_add(1, Ordering::Relaxed);
        let node = self.nodes.get(&id)?.clone();
        let updates = self.label_updates.borrow();
        if updates.is_empty() {
            return Some(node);
        }
        for (uid, label) in updates.iter() {
            if *uid == id {
                let mut patched = node;
                match &mut patched {
                    AvlNode::Leaf { label: l, .. } => *l = Some(*label),
                    AvlNode::Internal { label: l, .. } => *l = Some(*label),
                }
                return Some(patched);
            }
        }
        Some(node)
    }

    fn put(&mut self, id: NodeId, node: AvlNode) {
        self.flush_labels();
        self.nodes.insert(id, node);
    }

    fn remove(&mut self, id: NodeId) {
        self.flush_labels();
        self.nodes.remove(&id);
    }

    fn contains(&self, id: NodeId) -> bool {
        self.nodes.contains_key(&id)
    }

    fn set_label(&self, id: NodeId, label: Digest32) {
        self.label_updates.borrow_mut().push((id, label));
    }

    fn len(&self) -> usize {
        self.nodes.len()
    }

    fn iter_all(&self) -> Vec<(NodeId, AvlNode)> {
        self.nodes.iter().map(|(&id, n)| (id, n.clone())).collect()
    }

    fn commit(&mut self) {
        self.flush_labels();
    }

    fn abort(&mut self) {
        self.label_updates.get_mut().clear();
    }

    fn take_label_dirty(&mut self) -> HashSet<NodeId> {
        HashSet::new() // MemoryArena applies labels inline, nothing to persist
    }

    fn read_count(&self) -> u64 {
        self.read_count.load(Ordering::Relaxed)
    }

    fn reset_read_count(&self) {
        self.read_count.store(0, Ordering::Relaxed);
    }
}

// ============================================================================
// CachedDiskArena
// ============================================================================

/// Approximate in-memory byte size of an AvlNode.
fn node_byte_size(node: &AvlNode) -> usize {
    match node {
        AvlNode::Leaf { value, .. } => {
            // key(32) + value.len() + next_key(32) + label(33) + overhead(~40)
            137 + value.len()
        }
        AvlNode::Internal { .. } => {
            // key(32) + left(8) + right(8) + balance(1) + label(33) + overhead(~40)
            122
        }
    }
}

/// Apply a label to a node in-place.
fn apply_label(node: &mut AvlNode, label: Digest32) {
    match node {
        AvlNode::Leaf { label: l, .. } => *l = Some(label),
        AvlNode::Internal { label: l, .. } => *l = Some(label),
    }
}

/// Disk-backed node arena with byte-budgeted LRU cache and non-evictable dirty map.
///
/// Three-tier storage:
/// 1. `dirty` (HashMap) — structurally modified nodes, non-evictable until commit/abort.
/// 2. `clean_cache` (LruCache) — recently read committed nodes, byte-budgeted LRU eviction.
/// 3. redb `AVL_NODES` table — all committed nodes, authoritative on cache miss.
///
/// Lookup order: dirty → clean_cache → redb.
///
/// CONCURRENCY: Owned exclusively by StateStore on the state-application
/// thread. Must NOT be shared with concurrent validation or mempool workers.
/// Use a separate SnapshotReader for concurrent UTXO reads.
pub struct CachedDiskArena {
    /// Structurally modified nodes — non-evictable until commit/abort.
    dirty: RefCell<HashMap<NodeId, AvlNode>>,
    /// IDs of nodes removed from the tree this block (in dirty or was in clean).
    /// Tracked so that `contains()` returns false for removed nodes even though
    /// they still exist in redb.
    removed: RefCell<HashSet<NodeId>>,
    /// Clean committed nodes — byte-budgeted LRU eviction to redb.
    clean_cache: RefCell<LruCache<NodeId, AvlNode>>,
    /// Redb handle for cold reads.
    db: Arc<Database>,
    /// Open read session, if a `ReadSession` guard is currently alive.
    session: SessionSlot,
    /// Byte budget for the clean cache only.
    byte_budget: usize,
    clean_bytes: Cell<usize>,
    /// Nodes with newly-computed labels (derived cache, not in undo log).
    label_dirty: RefCell<HashSet<NodeId>>,
    read_count: AtomicU64,
}

// Send: yes, Sync: no.
// CachedDiskArena uses `RefCell` for interior mutation, which forbids
// shared (`&self`) cross-thread access. Owning the arena IS safe to
// move between threads (e.g. spawning the node action loop with
// `tokio::spawn`); all interior types (HashMap, LruCache, redb's
// Database/ReadTransaction, AtomicU64, Cell) are themselves `Send`.
// The `+ Send` bound on `Box<dyn NodeArena + Send>` in `AvlTree`
// surfaces this.

impl CachedDiskArena {
    /// Create a new disk-backed arena.
    ///
    /// `byte_budget`: max bytes for the clean LRU cache (dirty map is unbounded
    /// but small — bounded by per-block mutation count).
    pub fn new(db: Arc<Database>, byte_budget: usize) -> Self {
        // LruCache needs a NonZeroUsize item cap. We derive it from the byte
        // budget (min node ~100 bytes) and enforce the actual byte budget
        // ourselves via clean_bytes tracking.
        let item_cap = (byte_budget / 100).max(1024);
        let cap = std::num::NonZeroUsize::new(item_cap).unwrap();
        Self {
            dirty: RefCell::new(HashMap::new()),
            removed: RefCell::new(HashSet::new()),
            clean_cache: RefCell::new(LruCache::new(cap)),
            db,
            session: SessionSlot::default(),
            byte_budget,
            clean_bytes: Cell::new(0),
            label_dirty: RefCell::new(HashSet::new()),
            read_count: AtomicU64::new(0),
        }
    }

    /// Close any open read session. Called at the commit/abort boundary,
    /// past which a session's snapshot would be stale.
    fn clear_session(&self) {
        *lock_session(&self.session) = None;
    }

    /// Access the set of nodes whose labels were computed (for persist_apply).
    pub fn take_label_dirty(&self) -> HashSet<NodeId> {
        std::mem::take(&mut *self.label_dirty.borrow_mut())
    }

    /// Load a node from redb. Uses the open session's table if there is one.
    fn load_from_redb(&self, id: NodeId) -> Option<AvlNode> {
        let session = lock_session(&self.session);
        if let Some(table) = session.as_ref() {
            return Self::read_node_from_table(table, id);
        }
        drop(session);
        // No session — open a one-shot read transaction and table.
        let txn = self.db.begin_read().ok()?;
        let table = txn.open_table(AVL_NODES).ok()?;
        Self::read_node_from_table(&table, id)
    }

    fn read_node_from_table(table: &SessionTable, id: NodeId) -> Option<AvlNode> {
        let guard = table.get(id).ok()??;
        // Corrupt persisted bytes are unrecoverable here. The
        // `NodeArena::get` contract returns `Option<AvlNode>` (None =
        // missing), so we fail loud rather than silently masking
        // corruption as a cache miss — the digest invariant would
        // diverge if we returned None for a present-but-corrupt row.
        Some(
            crate::store::node_from_bytes(guard.value())
                .expect("avl arena: node_from_bytes failed on persisted bytes"),
        )
    }

    /// Evict LRU entries from clean_cache until clean_bytes <= byte_budget.
    fn enforce_budget(&self) {
        let mut cache = self.clean_cache.borrow_mut();
        let mut bytes = self.clean_bytes.get();
        while bytes > self.byte_budget {
            if let Some((_id, evicted)) = cache.pop_lru() {
                bytes -= node_byte_size(&evicted);
            } else {
                break;
            }
        }
        self.clean_bytes.set(bytes);
    }

    /// Insert a node into the clean cache, enforcing the byte budget.
    fn insert_clean(&self, id: NodeId, node: AvlNode) {
        let size = node_byte_size(&node);
        let mut cache = self.clean_cache.borrow_mut();
        // If already present, subtract old size first.
        if let Some(old) = cache.pop(&id) {
            self.clean_bytes
                .set(self.clean_bytes.get() - node_byte_size(&old));
        }
        cache.put(id, node);
        self.clean_bytes.set(self.clean_bytes.get() + size);
        drop(cache);
        self.enforce_budget();
    }
}

impl NodeArena for CachedDiskArena {
    fn get(&self, id: NodeId) -> Option<AvlNode> {
        self.read_count.fetch_add(1, Ordering::Relaxed);
        // Check removed set first.
        if self.removed.borrow().contains(&id) {
            return None;
        }
        // 1. Check dirty map.
        if let Some(node) = self.dirty.borrow().get(&id) {
            return Some(node.clone());
        }
        // 2. Check clean cache.
        {
            let mut cache = self.clean_cache.borrow_mut();
            if let Some(node) = cache.get(&id) {
                return Some(node.clone());
            }
        }
        // 3. Fall through to redb.
        let node = self.load_from_redb(id)?;
        // Insert into clean cache for future reads.
        self.insert_clean(id, node.clone());
        Some(node)
    }

    fn put(&mut self, id: NodeId, node: AvlNode) {
        // Remove from removed set if present (node is being re-inserted).
        self.removed.get_mut().remove(&id);
        // Remove from clean cache — node is now dirty.
        if let Some(old) = self.clean_cache.get_mut().pop(&id) {
            let bytes = self.clean_bytes.get();
            self.clean_bytes
                .set(bytes.saturating_sub(node_byte_size(&old)));
        }
        self.dirty.get_mut().insert(id, node);
    }

    fn remove(&mut self, id: NodeId) {
        self.dirty.get_mut().remove(&id);
        if let Some(old) = self.clean_cache.get_mut().pop(&id) {
            let bytes = self.clean_bytes.get();
            self.clean_bytes
                .set(bytes.saturating_sub(node_byte_size(&old)));
        }
        self.removed.get_mut().insert(id);
    }

    fn contains(&self, id: NodeId) -> bool {
        if self.removed.borrow().contains(&id) {
            return false;
        }
        if self.dirty.borrow().contains_key(&id) {
            return true;
        }
        if self.clean_cache.borrow_mut().contains(&id) {
            return true;
        }
        // Fall through to redb.
        self.load_from_redb(id).is_some()
    }

    fn set_label(&self, id: NodeId, label: Digest32) {
        // Try dirty first.
        {
            let mut dirty = self.dirty.borrow_mut();
            if let Some(node) = dirty.get_mut(&id) {
                apply_label(node, label);
                self.label_dirty.borrow_mut().insert(id);
                return;
            }
        }
        // Try clean cache.
        {
            let mut cache = self.clean_cache.borrow_mut();
            if let Some(node) = cache.get_mut(&id) {
                apply_label(node, label);
                self.label_dirty.borrow_mut().insert(id);
            }
        }
        // Node is not cached — label will be computed again on next access.
        // This is a no-op, which is correct: labels are derived data.
    }

    fn len(&self) -> usize {
        // Approximate: dirty + clean (doesn't count redb-only nodes).
        self.dirty.borrow().len() + self.clean_cache.borrow_mut().len()
    }

    fn iter_all(&self) -> Vec<(NodeId, AvlNode)> {
        // Escape hatch: iterate redb + overlay dirty.
        let mut result = HashMap::new();
        // Load all from redb.
        if let Ok(txn) = self.db.begin_read() {
            if let Ok(table) = txn.open_table(AVL_NODES) {
                if let Ok(iter) = table.iter() {
                    for (k, v) in iter.flatten() {
                        let id = k.value();
                        // Same loud-fail policy as `read_node_from_txn`:
                        // `iter_all` is a diagnostic / genesis-init / snapshot
                        // escape hatch, not a hot path; corrupt rows would
                        // leave the snapshot or genesis seed silently wrong.
                        let node = crate::store::node_from_bytes(v.value()).expect(
                            "avl arena iter_all: node_from_bytes failed on persisted bytes",
                        );
                        result.insert(id, node);
                    }
                }
            }
        }
        // Overlay dirty nodes (current uncommitted state).
        for (id, node) in self.dirty.borrow().iter() {
            result.insert(*id, node.clone());
        }
        // Remove nodes that were deleted this block.
        for id in self.removed.borrow().iter() {
            result.remove(id);
        }
        result.into_iter().collect()
    }

    fn commit(&mut self) {
        // Past this boundary redb holds different bytes, so any session a
        // walk left open would serve a stale snapshot on the next miss.
        self.clear_session();
        // Move dirty → clean. Dirty nodes are now committed in redb.
        let dirty = std::mem::take(self.dirty.get_mut());
        for (id, node) in dirty {
            self.insert_clean(id, node);
        }
        // Clear removed set — these deletions are now committed in redb.
        self.removed.get_mut().clear();
        self.label_dirty.get_mut().clear();
    }

    fn abort(&mut self) {
        self.clear_session();
        self.dirty.get_mut().clear();
        self.removed.get_mut().clear();
        self.clean_cache.get_mut().clear();
        self.clean_bytes.set(0);
        self.label_dirty.get_mut().clear();
    }

    fn take_label_dirty(&mut self) -> HashSet<NodeId> {
        std::mem::take(self.label_dirty.get_mut())
    }

    fn read_count(&self) -> u64 {
        self.read_count.load(Ordering::Relaxed)
    }

    fn reset_read_count(&self) {
        self.read_count.store(0, Ordering::Relaxed);
    }

    fn cache_clean_bytes(&self) -> usize {
        self.clean_bytes.get()
    }

    fn cache_capacity_bytes(&self) -> usize {
        self.byte_budget
    }

    fn cache_clean_len(&self) -> usize {
        self.clean_cache.borrow().len()
    }

    fn cache_dirty_len(&self) -> usize {
        self.dirty.borrow().len()
    }

    fn begin_read_session(&self) -> ReadSession {
        let mut slot = lock_session(&self.session);
        if slot.is_some() {
            // Already inside a session. The outer guard owns it; an inner
            // guard that closed it on drop would silently downgrade the
            // rest of the outer walk back to one-shot transactions.
            return ReadSession::inert();
        }
        // A session is a pure optimization: if redb declines to open the
        // transaction or the table, fall back to per-read transactions
        // rather than failing the walk.
        let Ok(txn) = self.db.begin_read() else {
            return ReadSession::inert();
        };
        let Ok(table) = txn.open_table(AVL_NODES) else {
            return ReadSession::inert();
        };
        *slot = Some(table);
        ReadSession {
            slot: Some(Arc::clone(&self.session)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use redb::Database;
    use tempfile::TempDir;

    // ----- helpers -----

    /// A leaf whose value encodes `tag`, so a read can be attributed to the
    /// snapshot it came from.
    fn leaf(tag: u8) -> AvlNode {
        AvlNode::Leaf {
            key: [tag; 32],
            value: vec![tag; 8],
            next_key: [0xFF; 32],
            label: None,
        }
    }

    fn leaf_tag(node: &AvlNode) -> u8 {
        match node {
            AvlNode::Leaf { value, .. } => value[0],
            AvlNode::Internal { .. } => panic!("expected a leaf"),
        }
    }

    /// Persist `(id, leaf(tag))` for every pair into a committed `AVL_NODES`.
    fn persist(db: &Database, nodes: &[(NodeId, u8)]) {
        let txn = crate::begin_write_qr(db).expect("begin write");
        {
            let mut table = txn.open_table(AVL_NODES).expect("open avl_nodes");
            for (id, tag) in nodes {
                table
                    .insert(*id, crate::store::node_to_bytes(&leaf(*tag)).as_slice())
                    .expect("insert node");
            }
        }
        txn.commit().expect("commit");
    }

    fn fixture(nodes: &[(NodeId, u8)]) -> (TempDir, Arc<Database>) {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = Arc::new(Database::create(dir.path().join("arena.redb")).expect("create redb"));
        persist(&db, nodes);
        (dir, db)
    }

    impl CachedDiskArena {
        fn session_is_open(&self) -> bool {
            lock_session(&self.session).is_some()
        }
    }

    // ----- happy path -----

    #[test]
    fn read_session_cold_reads_match_sessionless_reads() {
        let (_dir, db) = fixture(&[(1, 0xA1), (2, 0xA2), (3, 0xA3)]);

        let sessionless = CachedDiskArena::new(Arc::clone(&db), 0);
        let expected: Vec<u8> = (1..=3)
            .map(|id| leaf_tag(&sessionless.get(id).expect("cold read")))
            .collect();

        let arena = CachedDiskArena::new(Arc::clone(&db), 0);
        let session = arena.begin_read_session();
        let observed: Vec<u8> = (1..=3)
            .map(|id| leaf_tag(&arena.get(id).expect("cold read in session")))
            .collect();
        drop(session);

        assert_eq!(observed, expected);
    }

    #[test]
    fn read_session_missing_node_returns_none() {
        let (_dir, db) = fixture(&[(1, 0xA1)]);
        let arena = CachedDiskArena::new(Arc::clone(&db), 0);
        let _session = arena.begin_read_session();
        assert!(arena.get(99).is_none());
    }

    // ----- session lifecycle -----

    #[test]
    fn read_session_closes_when_guard_drops() {
        let (_dir, db) = fixture(&[(1, 0xA1)]);
        let arena = CachedDiskArena::new(db, 0);
        let session = arena.begin_read_session();
        assert!(arena.session_is_open());
        drop(session);
        assert!(!arena.session_is_open());
    }

    #[test]
    fn read_session_nested_guard_drop_leaves_outer_session_open() {
        let (_dir, db) = fixture(&[(1, 0xA1)]);
        let arena = CachedDiskArena::new(db, 0);
        let outer = arena.begin_read_session();
        let inner = arena.begin_read_session();
        drop(inner);
        assert!(
            arena.session_is_open(),
            "an inner guard must not close the session its outer guard owns"
        );
        drop(outer);
        assert!(!arena.session_is_open());
    }

    #[test]
    fn arena_commit_closes_leaked_read_session() {
        let (_dir, db) = fixture(&[(1, 0xA1)]);
        let mut arena = CachedDiskArena::new(db, 1 << 20);
        std::mem::forget(arena.begin_read_session());
        assert!(arena.session_is_open());
        arena.commit();
        assert!(!arena.session_is_open());
    }

    #[test]
    fn arena_abort_closes_leaked_read_session() {
        let (_dir, db) = fixture(&[(1, 0xA1)]);
        let mut arena = CachedDiskArena::new(db, 1 << 20);
        std::mem::forget(arena.begin_read_session());
        assert!(arena.session_is_open());
        arena.abort();
        assert!(!arena.session_is_open());
    }

    /// The reason `commit`/`abort` close the session: an open session pins
    /// the snapshot it was opened on, so a cold read taken after a redb
    /// commit would still see the pre-commit bytes.
    #[test]
    fn read_session_pins_the_snapshot_it_opened_on() {
        let (_dir, db) = fixture(&[(1, 0xA1)]);
        let arena = CachedDiskArena::new(Arc::clone(&db), 0);

        let session = arena.begin_read_session();
        assert_eq!(leaf_tag(&arena.get(1).expect("cold read")), 0xA1);
        persist(&db, &[(1, 0xB1)]);
        assert_eq!(
            leaf_tag(&arena.get(1).expect("cold read in session")),
            0xA1,
            "a session must keep serving its own snapshot"
        );
        drop(session);

        assert_eq!(
            leaf_tag(&arena.get(1).expect("cold read after session")),
            0xB1,
            "a closed session must not outlive its snapshot"
        );
    }
}
