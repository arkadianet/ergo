//! Ordered mempool pool + indexes.
//!
//! Priority order is weight DESC with tx_id tiebreak. All indexes
//! are maintained in lockstep — every mutation preserves the
//! invariants asserted in [`OrderedPool::check_invariants`].

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Instant;

use ergo_primitives::digest::Digest32;
use ergo_ser::ergo_box::ErgoBox;
use thiserror::Error;

use crate::types::{TxId, TxSource};

/// A pool entry. Holds the pool-relevant projection of a validated
/// transaction. The full `CheckedTransaction` is not retained because
/// its validation proof is tip-contextual — revalidation rebuilds it
/// from `bytes` as needed.
#[derive(Debug, Clone)]
pub struct Entry {
    pub tx_id: TxId,
    pub bytes: Arc<[u8]>,
    /// Box ids this tx spends.
    pub inputs: Vec<Digest32>,
    /// Box ids this tx creates (derived from outputs at admission).
    pub outputs: Vec<Digest32>,
    /// Tx ids of pool txs this tx spends outputs of. Empty if all inputs
    /// are committed boxes. Populated at insert time from `by_output`.
    pub parents_in_pool: Vec<TxId>,
    pub fee: u64,
    pub weight: u64,
    pub size_bytes: u32,
    pub cost: u64,
    pub created_at: Instant,
    pub last_checked_at: Instant,
    pub source: TxSource,
    /// Materialized output boxes aligned with `outputs` by index.
    /// Populated by admission so `OrderedPool::output_map` can build
    /// the overlay for pool-chained dependencies. Tests that don't
    /// exercise chaining leave this empty.
    pub output_boxes: Vec<ErgoBox>,
}

impl Entry {
    /// Constructor used by admission and by tests. Fields that depend
    /// on the current pool state (`parents_in_pool`) are set to the
    /// provided values; the pool does NOT recompute them on insert.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tx_id: TxId,
        bytes: Arc<[u8]>,
        inputs: Vec<Digest32>,
        outputs: Vec<Digest32>,
        parents_in_pool: Vec<TxId>,
        fee: u64,
        weight: u64,
        size_bytes: u32,
        cost: u64,
        source: TxSource,
    ) -> Self {
        let now = Instant::now();
        Self {
            tx_id,
            bytes,
            inputs,
            outputs,
            parents_in_pool,
            fee,
            weight,
            size_bytes,
            cost,
            created_at: now,
            last_checked_at: now,
            source,
            output_boxes: Vec::new(),
        }
    }

    /// Attach materialized output boxes. Lengths of `outputs` and
    /// `output_boxes` must match; admission ensures this.
    pub fn with_output_boxes(mut self, boxes: Vec<ErgoBox>) -> Self {
        self.output_boxes = boxes;
        self
    }
}

/// Ordered pool key. Sorts by weight DESC then tx_id ASC so
/// `BTreeMap::iter()` yields entries in priority order directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WeightedKey {
    /// Negated weight. BTreeMap sorts ascending; negation makes heavier
    /// weights sort first. `i128` to avoid overflow on negation of
    /// `u64::MAX`.
    neg_weight: i128,
    tx_id: TxId,
}

impl WeightedKey {
    fn new(weight: u64, tx_id: TxId) -> Self {
        Self {
            neg_weight: -(weight as i128),
            tx_id,
        }
    }

    pub fn weight(&self) -> u64 {
        (-self.neg_weight) as u64
    }

    pub fn tx_id(&self) -> &TxId {
        &self.tx_id
    }
}

impl PartialOrd for WeightedKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for WeightedKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.neg_weight
            .cmp(&other.neg_weight)
            .then_with(|| self.tx_id.as_bytes().cmp(other.tx_id.as_bytes()))
    }
}

#[derive(Debug, Error)]
pub enum PoolError {
    #[error("tx already in pool: {0:?}")]
    Duplicate(TxId),
    #[error("output box_id collision on insert: {0:?}")]
    OutputCollision(Digest32),
}

/// The ordered pool. Single-writer; all mutations through `&mut self`.
#[derive(Debug)]
pub struct OrderedPool {
    ordered: BTreeMap<WeightedKey, Entry>,
    by_tx_id: HashMap<TxId, WeightedKey>,
    by_input: HashMap<Digest32, TxId>,
    by_output: HashMap<Digest32, TxId>,
    /// Parent → children. Populated whenever a child is inserted that
    /// spends an output currently in `by_output`. Edges are removed
    /// when either endpoint leaves the pool.
    children_of: HashMap<TxId, Vec<TxId>>,
    total_bytes: usize,
    /// Monotonic counter bumped on every pool mutation (`insert` / `remove`,
    /// and thus every admission, eviction, reorg demotion, and revalidation
    /// re-admit — all route through these two). An insert/remove changes the
    /// candidate-visible pool's MEMBERSHIP or, for a reweight (remove+insert
    /// of a surviving tx), its priority ORDERING — both feed the candidate's
    /// tx-selection order, so the off-loop engine (via `Mempool::revision`)
    /// treats any advance as "rebuild due". A reorg reweight advances the
    /// counter for a tx that stays in the pool, but reweights happen only
    /// during a tip change, whose rebuild already subsumes the signal — so
    /// this can never produce a spurious *same-tip* rebuild.
    revision: u64,
}

impl OrderedPool {
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            ordered: BTreeMap::new(),
            by_tx_id: HashMap::with_capacity(cap),
            by_input: HashMap::with_capacity(cap * 2),
            by_output: HashMap::with_capacity(cap * 2),
            children_of: HashMap::new(),
            total_bytes: 0,
            revision: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.ordered.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ordered.is_empty()
    }

    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    /// Monotonic membership-revision counter (bumped on every insert /
    /// remove). See the `revision` field.
    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn contains(&self, tx_id: &TxId) -> bool {
        self.by_tx_id.contains_key(tx_id)
    }

    pub fn get(&self, tx_id: &TxId) -> Option<&Entry> {
        let key = self.by_tx_id.get(tx_id)?;
        self.ordered.get(key)
    }

    /// Iterator over entries in priority order (highest weight first).
    pub fn iter_prioritized(&self) -> impl Iterator<Item = &Entry> {
        self.ordered.values()
    }

    /// Weight of the lowest-priority entry, or `None` if empty.
    pub fn lowest_weight(&self) -> Option<u64> {
        self.ordered.keys().next_back().map(|k| k.weight())
    }

    /// Tx id of the lowest-priority entry, or `None` if empty.
    pub fn lowest_tx_id(&self) -> Option<TxId> {
        self.ordered.keys().next_back().map(|k| *k.tx_id())
    }

    /// Given a set of inputs, return the tx ids in the pool that
    /// already spend any of them. Used for double-spend conflict
    /// detection during admission.
    pub fn conflicts_for_inputs(&self, inputs: &[Digest32]) -> Vec<TxId> {
        let mut seen: std::collections::HashSet<TxId> = std::collections::HashSet::new();
        let mut out = Vec::new();
        for b in inputs {
            if let Some(tx_id) = self.by_input.get(b) {
                if seen.insert(*tx_id) {
                    out.push(*tx_id);
                }
            }
        }
        out
    }

    /// Insert an entry. All indexes updated atomically; a duplicate or
    /// output-collision returns an error without partial mutation.
    pub fn insert(&mut self, entry: Entry) -> Result<(), PoolError> {
        if self.by_tx_id.contains_key(&entry.tx_id) {
            return Err(PoolError::Duplicate(entry.tx_id));
        }
        for out in &entry.outputs {
            if self.by_output.contains_key(out) {
                return Err(PoolError::OutputCollision(*out));
            }
        }
        let key = WeightedKey::new(entry.weight, entry.tx_id);
        let tx_id = entry.tx_id;
        // Record parent → child edges from the entry's parents_in_pool.
        for parent in &entry.parents_in_pool {
            self.children_of.entry(*parent).or_default().push(tx_id);
        }
        // Stage indexes before moving `entry`.
        for b in &entry.inputs {
            self.by_input.insert(*b, tx_id);
        }
        for b in &entry.outputs {
            self.by_output.insert(*b, tx_id);
        }
        self.total_bytes = self.total_bytes.saturating_add(entry.bytes.len());
        self.by_tx_id.insert(tx_id, key);
        self.ordered.insert(key, entry);
        self.revision += 1;
        Ok(())
    }

    /// Remove a single entry. Descendants are NOT removed — use
    /// `remove_with_descendants` for cascading eviction. Returns the
    /// removed entry or `None` if absent.
    pub fn remove(&mut self, tx_id: &TxId) -> Option<Entry> {
        let key = self.by_tx_id.remove(tx_id)?;
        let entry = self.ordered.remove(&key)?;
        for b in &entry.inputs {
            self.by_input.remove(b);
        }
        for b in &entry.outputs {
            self.by_output.remove(b);
        }
        // Drop this tx's own `children_of` bucket (its children remain
        // in the pool but their parent reference is now dangling —
        // on_tip_change sweeps those entries; this method only cleans
        // the parent->child map.
        self.children_of.remove(tx_id);
        // Drop incoming edges from this tx's parents.
        for parent in &entry.parents_in_pool {
            if let Some(siblings) = self.children_of.get_mut(parent) {
                siblings.retain(|c| c != tx_id);
                if siblings.is_empty() {
                    self.children_of.remove(parent);
                }
            }
        }
        self.total_bytes = self.total_bytes.saturating_sub(entry.bytes.len());
        self.revision += 1;
        Some(entry)
    }

    /// Remove `tx_id` and all descendants (children, grandchildren, …).
    /// Bounded by `max_depth` nodes visited to avoid pathological
    /// family walks. Returns removed entries in removal order (parent
    /// last — children are removed first so their `parents_in_pool`
    /// backreferences stay consistent during the sweep).
    pub fn remove_with_descendants(&mut self, tx_id: &TxId, max_depth: usize) -> Vec<Entry> {
        if !self.contains(tx_id) {
            return Vec::new();
        }
        // Collect descendants depth-first (explicit stack), capped at
        // `max_depth` nodes visited.
        let mut to_visit: Vec<TxId> = vec![*tx_id];
        let mut ordered_ids: Vec<TxId> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        while let Some(next) = to_visit.pop() {
            if !seen.insert(next) {
                continue;
            }
            if ordered_ids.len() >= max_depth {
                break;
            }
            ordered_ids.push(next);
            if let Some(children) = self.children_of.get(&next) {
                for child in children {
                    if !seen.contains(child) {
                        to_visit.push(*child);
                    }
                }
            }
        }
        // Remove children first, parent last.
        ordered_ids.reverse();
        let mut removed = Vec::with_capacity(ordered_ids.len());
        for id in ordered_ids {
            if let Some(e) = self.remove(&id) {
                removed.push(e);
            }
        }
        removed
    }

    /// Tx id(s) that created the given output box_id. Used by
    /// admission to compute `parents_in_pool` for an incoming tx.
    pub fn parent_for_output(&self, box_id: &Digest32) -> Option<TxId> {
        self.by_output.get(box_id).copied()
    }

    /// Materialize a `BoxId → ErgoBox` map over all pool-created outputs.
    /// Used by admission to build the `PoolUtxoOverlay` for the
    /// incoming candidate. Entries whose `output_boxes` is empty
    /// (e.g. unit tests that seed the pool directly) contribute
    /// nothing.
    pub fn output_map(&self) -> HashMap<Digest32, ErgoBox> {
        let mut map = HashMap::new();
        for entry in self.ordered.values() {
            for (idx, id) in entry.outputs.iter().enumerate() {
                if let Some(b) = entry.output_boxes.get(idx) {
                    map.insert(*id, b.clone());
                }
            }
        }
        map
    }

    /// Snapshot of the `by_input` index: spent committed-box id → pool
    /// tx that spends it. Used by the API mempool overlay (P5) to
    /// support `excludeMempoolSpent` filtering and to surface a
    /// `spending_tx_id` when a confirmed UTXO has a pending pool spend.
    /// O(N) clone over pool entries; the publisher calls this once per
    /// `sync_tick` and stores the result in the snapshot.
    pub fn input_map(&self) -> HashMap<Digest32, TxId> {
        self.by_input.clone()
    }

    /// Test-only: assert all index cross-references are consistent.
    /// Called after mutations in unit tests.
    #[doc(hidden)]
    pub fn check_invariants(&self) {
        assert_eq!(
            self.ordered.len(),
            self.by_tx_id.len(),
            "ordered and by_tx_id sizes diverged"
        );
        let mut computed_bytes = 0usize;
        let mut seen_inputs = std::collections::HashSet::new();
        let mut seen_outputs = std::collections::HashSet::new();
        for (key, entry) in &self.ordered {
            assert_eq!(
                self.by_tx_id.get(&entry.tx_id),
                Some(key),
                "by_tx_id points to wrong key for {:?}",
                entry.tx_id
            );
            for b in &entry.inputs {
                assert!(seen_inputs.insert(*b), "duplicate input across pool: {b:?}");
                assert_eq!(self.by_input.get(b), Some(&entry.tx_id));
            }
            for b in &entry.outputs {
                assert!(
                    seen_outputs.insert(*b),
                    "duplicate output across pool: {b:?}"
                );
                assert_eq!(self.by_output.get(b), Some(&entry.tx_id));
            }
            computed_bytes += entry.bytes.len();
        }
        assert_eq!(
            self.total_bytes, computed_bytes,
            "total_bytes counter out of sync"
        );
        // No dangling children_of edges.
        for (parent, children) in &self.children_of {
            assert!(
                self.by_tx_id.contains_key(parent),
                "children_of has edge from non-pool parent {parent:?}"
            );
            for child in children {
                assert!(
                    self.by_tx_id.contains_key(child),
                    "children_of has edge to non-pool child {child:?}"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    fn digest(b: u8) -> Digest32 {
        Digest32::from_bytes([b; 32])
    }

    fn mk_entry(
        tx_id_byte: u8,
        weight: u64,
        inputs: &[u8],
        outputs: &[u8],
        parents_in_pool: &[u8],
    ) -> Entry {
        let bytes: Arc<[u8]> = Arc::from(vec![0u8; 100].into_boxed_slice());
        Entry::new(
            digest(tx_id_byte),
            bytes,
            inputs.iter().map(|b| digest(*b)).collect(),
            outputs.iter().map(|b| digest(*b)).collect(),
            parents_in_pool.iter().map(|b| digest(*b)).collect(),
            100_000,
            weight,
            100,
            50_000,
            TxSource::Api,
        )
    }

    // ----- happy path -----

    #[test]
    fn insert_then_contains() {
        let mut p = OrderedPool::with_capacity(4);
        p.insert(mk_entry(1, 10, &[10], &[11], &[])).unwrap();
        assert!(p.contains(&digest(1)));
        assert_eq!(p.len(), 1);
        p.check_invariants();
    }

    #[test]
    fn revision_bumps_on_pool_mutation_not_on_no_ops() {
        let mut p = OrderedPool::with_capacity(4);
        assert_eq!(p.revision(), 0, "fresh pool revision starts at 0");
        p.insert(mk_entry(1, 10, &[10], &[11], &[])).unwrap();
        assert_eq!(p.revision(), 1, "insert bumps revision");
        p.insert(mk_entry(2, 20, &[12], &[13], &[])).unwrap();
        assert_eq!(p.revision(), 2, "second insert bumps revision");
        // Rejected insert (duplicate id) must NOT bump — it returns before
        // mutating the pool.
        let _ = p.insert(mk_entry(1, 99, &[14], &[15], &[]));
        assert_eq!(p.revision(), 2, "rejected insert must not bump revision");
        // Remove bumps; an absent remove does not.
        p.remove(&digest(1)).unwrap();
        assert_eq!(p.revision(), 3, "remove bumps revision");
        assert!(p.remove(&digest(99)).is_none());
        assert_eq!(p.revision(), 3, "absent remove must not bump revision");
        p.check_invariants();
    }

    #[test]
    fn duplicate_insert_rejected() {
        let mut p = OrderedPool::with_capacity(4);
        p.insert(mk_entry(1, 10, &[10], &[11], &[])).unwrap();
        let err = p.insert(mk_entry(1, 20, &[12], &[13], &[])).unwrap_err();
        assert!(matches!(err, PoolError::Duplicate(_)));
        p.check_invariants();
    }

    #[test]
    fn output_collision_rejected() {
        let mut p = OrderedPool::with_capacity(4);
        p.insert(mk_entry(1, 10, &[10], &[11], &[])).unwrap();
        let err = p.insert(mk_entry(2, 20, &[12], &[11], &[])).unwrap_err();
        assert!(matches!(err, PoolError::OutputCollision(_)));
        p.check_invariants();
    }

    #[test]
    fn iter_prioritized_weight_desc() {
        let mut p = OrderedPool::with_capacity(4);
        p.insert(mk_entry(1, 10, &[10], &[11], &[])).unwrap();
        p.insert(mk_entry(2, 30, &[20], &[21], &[])).unwrap();
        p.insert(mk_entry(3, 20, &[30], &[31], &[])).unwrap();
        let ids: Vec<u8> = p
            .iter_prioritized()
            .map(|e| e.tx_id.as_bytes()[0])
            .collect();
        assert_eq!(ids, vec![2, 3, 1]);
    }

    #[test]
    fn tie_break_by_tx_id_ascending() {
        let mut p = OrderedPool::with_capacity(4);
        p.insert(mk_entry(3, 10, &[30], &[31], &[])).unwrap();
        p.insert(mk_entry(1, 10, &[10], &[11], &[])).unwrap();
        p.insert(mk_entry(2, 10, &[20], &[21], &[])).unwrap();
        let ids: Vec<u8> = p
            .iter_prioritized()
            .map(|e| e.tx_id.as_bytes()[0])
            .collect();
        assert_eq!(ids, vec![1, 2, 3], "same-weight entries sort by tx_id ASC");
    }

    #[test]
    fn remove_drops_indexes() {
        let mut p = OrderedPool::with_capacity(4);
        p.insert(mk_entry(1, 10, &[10], &[11], &[])).unwrap();
        let removed = p.remove(&digest(1)).unwrap();
        assert_eq!(removed.weight, 10);
        assert!(p.is_empty());
        assert!(p.parent_for_output(&digest(11)).is_none());
        p.check_invariants();
    }

    #[test]
    fn remove_absent_returns_none() {
        let mut p = OrderedPool::with_capacity(4);
        assert!(p.remove(&digest(99)).is_none());
    }

    #[test]
    fn lowest_weight_tracks_min() {
        let mut p = OrderedPool::with_capacity(4);
        assert!(p.lowest_weight().is_none());
        p.insert(mk_entry(1, 50, &[10], &[11], &[])).unwrap();
        p.insert(mk_entry(2, 10, &[20], &[21], &[])).unwrap();
        p.insert(mk_entry(3, 30, &[30], &[31], &[])).unwrap();
        assert_eq!(p.lowest_weight(), Some(10));
        assert_eq!(p.lowest_tx_id(), Some(digest(2)));
    }

    #[test]
    fn conflicts_for_inputs_detects_double_spends() {
        let mut p = OrderedPool::with_capacity(4);
        p.insert(mk_entry(1, 10, &[10, 11], &[50], &[])).unwrap();
        p.insert(mk_entry(2, 20, &[20, 21], &[51], &[])).unwrap();
        let cf = p.conflicts_for_inputs(&[digest(11), digest(99)]);
        assert_eq!(cf, vec![digest(1)]);
        let cf2 = p.conflicts_for_inputs(&[digest(10), digest(20)]);
        assert_eq!(cf2.len(), 2);
    }

    #[test]
    fn conflicts_empty_when_no_overlap() {
        let mut p = OrderedPool::with_capacity(4);
        p.insert(mk_entry(1, 10, &[10], &[11], &[])).unwrap();
        assert!(p.conflicts_for_inputs(&[digest(99)]).is_empty());
    }

    #[test]
    fn total_bytes_tracks_inserts_and_removes() {
        let mut p = OrderedPool::with_capacity(4);
        let bytes1: Arc<[u8]> = Arc::from(vec![0u8; 100].into_boxed_slice());
        let e1 = Entry::new(
            digest(1),
            bytes1,
            vec![digest(10)],
            vec![digest(11)],
            vec![],
            1000,
            10,
            100,
            50,
            TxSource::Api,
        );
        let bytes2: Arc<[u8]> = Arc::from(vec![0u8; 200].into_boxed_slice());
        let e2 = Entry::new(
            digest(2),
            bytes2,
            vec![digest(20)],
            vec![digest(21)],
            vec![],
            2000,
            20,
            200,
            100,
            TxSource::Api,
        );
        p.insert(e1).unwrap();
        p.insert(e2).unwrap();
        assert_eq!(p.total_bytes(), 300);
        p.remove(&digest(1));
        assert_eq!(p.total_bytes(), 200);
    }

    #[test]
    fn parent_for_output_resolves_creator() {
        let mut p = OrderedPool::with_capacity(4);
        p.insert(mk_entry(1, 10, &[10], &[100, 101], &[])).unwrap();
        assert_eq!(p.parent_for_output(&digest(100)), Some(digest(1)));
        assert_eq!(p.parent_for_output(&digest(101)), Some(digest(1)));
        assert_eq!(p.parent_for_output(&digest(250)), None);
    }

    #[test]
    fn children_of_tracks_parent_child_edges() {
        let mut p = OrderedPool::with_capacity(4);
        // parent creates box 100
        p.insert(mk_entry(1, 10, &[10], &[100], &[])).unwrap();
        // child spends box 100 → declared parent = tx 1
        p.insert(mk_entry(2, 20, &[100], &[200], &[1])).unwrap();
        assert_eq!(p.children_of.get(&digest(1)), Some(&vec![digest(2)]));
        p.check_invariants();
    }

    #[test]
    fn remove_with_descendants_cascades_children() {
        let mut p = OrderedPool::with_capacity(4);
        p.insert(mk_entry(1, 10, &[10], &[100], &[])).unwrap();
        p.insert(mk_entry(2, 20, &[100], &[200], &[1])).unwrap();
        p.insert(mk_entry(3, 30, &[200], &[201], &[2])).unwrap();
        let removed = p.remove_with_descendants(&digest(1), 500);
        assert_eq!(removed.len(), 3, "parent + child + grandchild");
        assert!(p.is_empty());
        p.check_invariants();
    }

    #[test]
    fn remove_with_descendants_respects_max_depth() {
        let mut p = OrderedPool::with_capacity(8);
        p.insert(mk_entry(1, 10, &[10], &[100], &[])).unwrap();
        p.insert(mk_entry(2, 20, &[100], &[200], &[1])).unwrap();
        p.insert(mk_entry(3, 30, &[200], &[210], &[2])).unwrap();
        p.insert(mk_entry(4, 40, &[210], &[220], &[3])).unwrap();
        // Cap at 2: only parent + first child evicted.
        let removed = p.remove_with_descendants(&digest(1), 2);
        assert_eq!(removed.len(), 2);
        // tx 3 and tx 4 remain.
        assert!(p.contains(&digest(3)));
        assert!(p.contains(&digest(4)));
        p.check_invariants();
    }

    #[test]
    fn remove_with_descendants_on_missing_tx() {
        let mut p = OrderedPool::with_capacity(4);
        assert!(p.remove_with_descendants(&digest(99), 10).is_empty());
    }

    #[test]
    fn removing_parent_leaves_child_without_dangling_edge() {
        let mut p = OrderedPool::with_capacity(4);
        p.insert(mk_entry(1, 10, &[10], &[100], &[])).unwrap();
        p.insert(mk_entry(2, 20, &[100], &[200], &[1])).unwrap();
        p.remove(&digest(1));
        // children_of[tx1] cleared entirely; tx2 still in pool.
        assert!(!p.children_of.contains_key(&digest(1)));
        assert!(p.contains(&digest(2)));
        p.check_invariants();
    }

    #[test]
    fn weighted_key_ordering_is_total_and_stable() {
        let k1 = WeightedKey::new(100, digest(1));
        let k2 = WeightedKey::new(100, digest(2));
        let k3 = WeightedKey::new(200, digest(3));
        assert!(k3 < k1, "higher weight sorts earlier");
        assert!(k1 < k2, "same weight: tx_id ASC");
    }

    #[test]
    fn weighted_key_handles_max_weight() {
        let k = WeightedKey::new(u64::MAX, digest(1));
        assert_eq!(k.weight(), u64::MAX);
    }

    #[test]
    fn get_returns_entry() {
        let mut p = OrderedPool::with_capacity(4);
        p.insert(mk_entry(1, 10, &[10], &[11], &[])).unwrap();
        let e = p.get(&digest(1)).unwrap();
        assert_eq!(e.weight, 10);
        assert!(p.get(&digest(99)).is_none());
    }

    #[test]
    fn empty_pool_lowest_is_none() {
        let p = OrderedPool::with_capacity(4);
        assert!(p.lowest_weight().is_none());
        assert!(p.lowest_tx_id().is_none());
    }

    #[test]
    fn check_invariants_passes_on_empty() {
        let p = OrderedPool::with_capacity(4);
        p.check_invariants();
    }

    #[test]
    fn input_map_returns_inputs_across_pool() {
        let mut p = OrderedPool::with_capacity(4);
        // tx 1 spends boxes 10, 11
        p.insert(mk_entry(1, 10, &[10, 11], &[100], &[])).unwrap();
        // tx 2 spends boxes 20, 21
        p.insert(mk_entry(2, 30, &[20, 21], &[200], &[])).unwrap();

        let map = p.input_map();
        assert_eq!(map.len(), 4);
        assert_eq!(map.get(&digest(10)), Some(&digest(1)));
        assert_eq!(map.get(&digest(11)), Some(&digest(1)));
        assert_eq!(map.get(&digest(20)), Some(&digest(2)));
        assert_eq!(map.get(&digest(21)), Some(&digest(2)));
        // Outputs are not inputs.
        assert!(!map.contains_key(&digest(100)));
        assert!(!map.contains_key(&digest(200)));
    }

    #[test]
    fn input_map_empty_pool() {
        let p = OrderedPool::with_capacity(4);
        assert!(p.input_map().is_empty());
    }

    #[test]
    fn input_map_drops_entries_after_remove() {
        let mut p = OrderedPool::with_capacity(4);
        p.insert(mk_entry(1, 10, &[10, 11], &[100], &[])).unwrap();
        p.insert(mk_entry(2, 30, &[20], &[200], &[])).unwrap();
        p.remove(&digest(1));
        let map = p.input_map();
        assert_eq!(map.len(), 1);
        assert_eq!(map.get(&digest(20)), Some(&digest(2)));
    }
}
