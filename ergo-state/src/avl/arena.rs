//! Node arena abstraction for the AVL+ tree.
//!
//! Crate-private trait that decouples tree logic from storage backend.
//! Two implementations:
//! - `MemoryArena`: HashMap-backed, used by tests and genesis init.
//! - `CachedDiskArena`: Three-tier (dirty + LRU + redb), used in production.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use ergo_primitives::digest::Digest32;
use lru::LruCache;
use redb::{Database, ReadableTable};

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

    /// Flush dirty state once its bytes are (or will be) in redb.
    /// For MemoryArena: no-op. For CachedDiskArena: moves dirty → clean.
    ///
    /// `durability` says whether the caller has already written those
    /// bytes to redb or merely queued them — see [`CommitDurability`].
    /// Getting it wrong is a correctness bug, not a performance one: a
    /// clean node is evictable, and evicting a node redb does not yet
    /// hold makes the next cold read serve pre-commit bytes.
    fn commit(&mut self, durability: CommitDurability);

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

    /// Bytes held in the clean cache that redb does not hold yet, because
    /// the persist job carrying them has not committed. These are pinned
    /// against eviction, so this is the amount by which the cache may
    /// legitimately exceed its byte budget. Default 0.
    fn cache_unpersisted_bytes(&self) -> usize {
        0
    }

    /// Handle to the durable watermark this arena consults before
    /// releasing pins, for the persist pipeline to advance as jobs
    /// commit. `None` for arenas with no disk tier, which never pin.
    fn durable_seq_handle(&self) -> Option<Arc<AtomicU64>> {
        None
    }
}

// ============================================================================
// Commit durability
// ============================================================================

/// Whether the bytes being moved dirty → clean are already in redb.
///
/// The clean cache is evictable and its backstop is redb, so a clean node
/// is only sound once redb can serve it. The synchronous persist path
/// commits its write transaction before calling [`NodeArena::commit`] and
/// passes [`CommitDurability::Durable`]. The pipeline path only *queues* a
/// `PersistJob`, and the worker commits it later — it passes
/// [`CommitDurability::PendingJob`] so the arena can pin those nodes until
/// the job's commit is acknowledged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitDurability {
    /// Redb already holds these bytes; the nodes are immediately evictable.
    Durable,
    /// The bytes are in persist job `seq`, which has not committed yet.
    /// The nodes stay pinned until the durable watermark reaches `seq`.
    PendingJob(u64),
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

    fn commit(&mut self, _durability: CommitDurability) {
        // No disk tier: nothing is ever read back from redb, so
        // durability of the caller's write is irrelevant here.
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
    /// Reusable read transaction for the current block.
    read_txn: RefCell<Option<redb::ReadTransaction>>,
    /// Byte budget for the clean cache only.
    byte_budget: usize,
    clean_bytes: Cell<usize>,
    /// Clean nodes whose bytes redb does not hold yet: node id → the
    /// persist job sequence carrying them, and their cached byte size.
    /// Pinned against eviction until `durable_seq` reaches that sequence.
    /// Empty on the synchronous persist path.
    unpersisted: RefCell<HashMap<NodeId, (u64, usize)>>,
    /// The same pins indexed by job: sequence → node ids pinned to it.
    /// Releasing job `s` pops exactly the buckets `<= s` instead of
    /// walking every pin. An id rewritten by a later job leaves a stale
    /// entry in its old bucket; the release step ignores it by checking
    /// the id's current sequence in `unpersisted`.
    pins_by_job: RefCell<BTreeMap<u64, Vec<NodeId>>>,
    /// Running sum of the sizes in `unpersisted`, so the hot eviction
    /// path can tell "nothing is evictable" without walking the map.
    unpersisted_bytes: Cell<usize>,
    /// Last value of `durable_seq` the pin set was settled against.
    /// `release_durable_pins` is on the per-insert path, so it returns
    /// without touching the maps unless the watermark actually moved.
    durable_seen: Cell<u64>,
    /// Sequence number of the last persist job whose redb commit
    /// completed. Written by the persist worker, read here. Monotonic;
    /// stays 0 when no pipeline is attached (and then nothing is ever
    /// pinned, because commits pass `Durable`).
    durable_seq: Arc<AtomicU64>,
    /// True while the pin set is holding the cache over budget. Latches
    /// so the warning fires on entering that state, not once per insert.
    overrun_logged: Cell<bool>,
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
            read_txn: RefCell::new(None),
            byte_budget,
            clean_bytes: Cell::new(0),
            unpersisted: RefCell::new(HashMap::new()),
            pins_by_job: RefCell::new(BTreeMap::new()),
            unpersisted_bytes: Cell::new(0),
            durable_seen: Cell::new(0),
            durable_seq: Arc::new(AtomicU64::new(0)),
            overrun_logged: Cell::new(false),
            label_dirty: RefCell::new(HashSet::new()),
            read_count: AtomicU64::new(0),
        }
    }

    /// Open a read transaction for the current block.
    /// All cache misses during this block reuse this transaction.
    pub fn begin_read_session(&self) {
        let txn = self
            .db
            .begin_read()
            .expect("failed to begin read transaction");
        *self.read_txn.borrow_mut() = Some(txn);
    }

    /// Close the read transaction after block processing.
    pub fn end_read_session(&self) {
        *self.read_txn.borrow_mut() = None;
    }

    /// Access the set of nodes whose labels were computed (for persist_apply).
    pub fn take_label_dirty(&self) -> HashSet<NodeId> {
        std::mem::take(&mut *self.label_dirty.borrow_mut())
    }

    /// Drop pins whose persist job has since committed.
    ///
    /// On the per-insert hot path, so it is O(1) unless the durable
    /// watermark moved since the last call: one acquire load compared
    /// against `durable_seen`. When it did move, only the job buckets
    /// that became durable are popped (`BTreeMap::split_off`), so the
    /// cost is proportional to the pins being released, not to the pins
    /// still held.
    fn release_durable_pins(&self) {
        let durable = self.durable_seq.load(Ordering::Acquire);
        if durable == self.durable_seen.get() {
            return;
        }
        self.durable_seen.set(durable);
        let mut by_job = self.pins_by_job.borrow_mut();
        if by_job.is_empty() {
            return;
        }
        // Buckets strictly above the watermark stay; everything else is
        // durable now.
        let still_pending = by_job.split_off(&durable.saturating_add(1));
        let released = std::mem::replace(&mut *by_job, still_pending);
        drop(by_job);

        let mut unpersisted = self.unpersisted.borrow_mut();
        let mut freed = 0usize;
        for (seq, ids) in released {
            for id in ids {
                // A rewrite by a later job re-pinned this id under a newer
                // sequence; that bucket entry is the live one, this one
                // is stale and must not release it.
                if let Some(&(current_seq, size)) = unpersisted.get(&id) {
                    if current_seq == seq {
                        unpersisted.remove(&id);
                        freed += size;
                    }
                }
            }
        }
        self.unpersisted_bytes
            .set(self.unpersisted_bytes.get().saturating_sub(freed));
        if unpersisted.is_empty() {
            self.overrun_logged.set(false);
        }
    }

    /// Drop the pin on `id`, if it had one. Called when a node leaves the
    /// clean cache by mutation or removal rather than by eviction.
    fn unpin(&self, id: NodeId) {
        if let Some((_seq, size)) = self.unpersisted.borrow_mut().remove(&id) {
            self.unpersisted_bytes
                .set(self.unpersisted_bytes.get().saturating_sub(size));
        }
    }

    /// Load a node from redb. Uses the session read transaction if available.
    fn load_from_redb(&self, id: NodeId) -> Option<AvlNode> {
        let txn_borrow = self.read_txn.borrow();
        if let Some(txn) = txn_borrow.as_ref() {
            return Self::read_node_from_txn(txn, id);
        }
        drop(txn_borrow);
        // No session — open a one-shot read transaction.
        let txn = self.db.begin_read().ok()?;
        Self::read_node_from_txn(&txn, id)
    }

    fn read_node_from_txn(txn: &redb::ReadTransaction, id: NodeId) -> Option<AvlNode> {
        let table = txn.open_table(AVL_NODES).ok()?;
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

    /// Evict LRU entries from clean_cache until clean_bytes <= byte_budget,
    /// skipping nodes redb cannot serve yet.
    ///
    /// A pinned node (one whose persist job has not committed) is never
    /// evicted: its only copy outside the in-flight job is right here, so
    /// dropping it would make the next cold read fall through to redb and
    /// return pre-commit bytes — or nothing at all, for a node created in
    /// the window. When the pins alone exceed the budget the cache
    /// deliberately over-runs; that over-run is bounded by the persist
    /// queue (`queue_depth` jobs x one block's structural writes), because
    /// the job channel is bounded and blocks the applier when full.
    fn enforce_budget(&self) {
        self.release_durable_pins();
        let bytes_before = self.clean_bytes.get();
        if bytes_before <= self.byte_budget {
            return;
        }
        // Fast path for the fully-pinned state: nothing here can be
        // evicted, so skip cycling the whole cache through `held`.
        if self.unpersisted_bytes.get() >= bytes_before {
            self.log_pin_overrun(bytes_before);
            return;
        }

        let unpersisted = self.unpersisted.borrow();
        let mut cache = self.clean_cache.borrow_mut();
        let mut bytes = bytes_before;
        // Walk from the LRU end. A pinned victim is promoted to the MRU
        // end in place (no pop/re-put, no allocation) so it is not
        // re-examined until it ages out again; `pinned_seen` bounds the
        // walk at one pass over the cache when everything left is pinned.
        let mut pinned_seen = 0usize;
        while bytes > self.byte_budget {
            let Some((&id, _)) = cache.peek_lru() else {
                break;
            };
            if unpersisted.contains_key(&id) {
                pinned_seen += 1;
                if pinned_seen >= cache.len() {
                    break;
                }
                cache.promote(&id);
                continue;
            }
            let Some((_, node)) = cache.pop_lru() else {
                break;
            };
            bytes -= node_byte_size(&node);
        }
        self.clean_bytes.set(bytes);
        drop(cache);
        drop(unpersisted);
        if bytes > self.byte_budget {
            self.log_pin_overrun(bytes);
        }
    }

    /// Warn once per over-run episode that pins are holding the clean
    /// cache above its byte budget. Latched by `overrun_logged` so a
    /// stalled persist worker produces one line, not one per insert.
    fn log_pin_overrun(&self, bytes: usize) {
        if self.overrun_logged.replace(true) {
            return;
        }
        tracing::warn!(
            clean_bytes = bytes,
            byte_budget = self.byte_budget,
            unpersisted_bytes = self.unpersisted_bytes.get(),
            unpersisted_nodes = self.unpersisted.borrow().len(),
            "avl arena: clean cache over budget — persist jobs have not \
             committed, so their nodes cannot be evicted",
        );
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
        // Leaving the clean cache for the dirty map: the pin (if any) is
        // released here and re-taken by the next `commit`, which knows the
        // job sequence the new bytes will travel in.
        self.unpin(id);
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
        self.unpin(id);
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

    fn commit(&mut self, durability: CommitDurability) {
        // Move dirty → clean. On the synchronous path redb already holds
        // these bytes; on the pipeline path it does not yet, so each node
        // is pinned to the job that carries it and stays unevictable until
        // that job's commit is acknowledged.
        let pin_to_seq = match durability {
            CommitDurability::Durable => None,
            // Already acknowledged between the send and this call — the
            // nodes are durable, so pinning them would be pure overhead.
            CommitDurability::PendingJob(seq)
                if seq <= self.durable_seq.load(Ordering::Acquire) =>
            {
                None
            }
            CommitDurability::PendingJob(seq) => Some(seq),
        };
        let dirty = std::mem::take(self.dirty.get_mut());
        for (id, node) in dirty {
            if let Some(seq) = pin_to_seq {
                let size = node_byte_size(&node);
                // A re-write in a later job supersedes the earlier pin;
                // only the delta in size is added to the running total.
                // The earlier bucket entry goes stale and is skipped at
                // release because the id's sequence no longer matches.
                let prev = self
                    .unpersisted
                    .get_mut()
                    .insert(id, (seq, size))
                    .map_or(0, |(_, old_size)| old_size);
                self.pins_by_job.get_mut().entry(seq).or_default().push(id);
                self.unpersisted_bytes
                    .set(self.unpersisted_bytes.get() + size - prev);
            }
            self.insert_clean(id, node);
        }
        // Clear removed set. Deleted nodes are unreachable from the root
        // and `next_id` never recycles an id (`AvlTree::allocate`), so a
        // deletion still in flight cannot be observed as a resurrected
        // node the way a stale write could.
        self.removed.get_mut().clear();
        self.label_dirty.get_mut().clear();
    }

    fn abort(&mut self) {
        self.dirty.get_mut().clear();
        self.removed.get_mut().clear();
        self.clean_cache.get_mut().clear();
        self.clean_bytes.set(0);
        // The clean cache is gone, so there is nothing left to pin.
        // Callers must flush the persist pipeline before aborting — the
        // rebuild that follows reads redb, which lags any in-flight job.
        self.unpersisted.get_mut().clear();
        self.pins_by_job.get_mut().clear();
        self.unpersisted_bytes.set(0);
        self.overrun_logged.set(false);
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

    fn cache_unpersisted_bytes(&self) -> usize {
        // Pins are released lazily on the eviction path; settle them here
        // so the gauge reports what is pinned NOW, not what was pinned at
        // the last budget enforcement (a flushed pipeline must read 0).
        //
        // Borrow rule: this takes `pins_by_job` and `unpersisted` mutably
        // through the `RefCell`s. It must not be called while `commit`,
        // `put`, `remove` or `abort` hold `get_mut` on those maps — the
        // arena is single-threaded and those never call back into the
        // gauge, so the invariant is structural, but a new caller inside
        // one of them would panic on the `RefCell`.
        self.release_durable_pins();
        self.unpersisted_bytes.get()
    }

    fn durable_seq_handle(&self) -> Option<Arc<AtomicU64>> {
        Some(Arc::clone(&self.durable_seq))
    }
}
