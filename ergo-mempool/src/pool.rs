//! Ordered mempool pool + indexes.
//!
//! Priority order is weight DESC with tx_id tiebreak. All indexes
//! are maintained in lockstep — every mutation preserves the
//! invariants asserted in [`OrderedPool::check_invariants`].

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};

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

/// Bounds for one family-weight (CPFP) walk. Mirrors Scala
/// `OrderedTxPool`'s `MaxParentScanDepth` (`max_depth`) and
/// `MaxParentScanTime` (`deadline`); `max_ops` is a Rust-only safety cap
/// on total re-keys with no Scala counterpart (Scala bounds only by depth
/// and time). The depth/time guards gate *descent* — a bailed recursion
/// returns but its caller keeps re-keying remaining siblings, matching
/// Scala's `foldLeft`; only `max_ops` is a hard stop of the whole walk.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FamilyBounds {
    max_depth: usize,
    max_ops: usize,
    max_update_ms: u64,
}

impl FamilyBounds {
    pub(crate) fn new(max_depth: usize, max_ops: usize, max_update_ms: u64) -> Self {
        Self {
            max_depth,
            max_ops,
            max_update_ms,
        }
    }
}

/// Apply a signed `delta` to a `u64` weight without overflow or wrap:
/// widen to `i128`, floor at 0, ceil at `u64::MAX`. Scala uses a signed
/// `Long` and lets weights drift negative on bounded partial walks; we
/// clamp to keep the `u64` key well-formed (see the underflow note in the
/// family-weight design — a bounded walk may legitimately under-subtract).
fn saturating_apply(weight: u64, delta: i128) -> u64 {
    let r = i128::from(weight) + delta;
    u64::try_from(r.max(0)).unwrap_or(u64::MAX)
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
    /// Monotonic counter bumped on every candidate-visible pool mutation:
    /// `insert`, `remove`, and the family-weight walk's `rekey_weight` (which
    /// moves a surviving tx's slot in `ordered`). It thus advances on every
    /// admission, eviction, reorg removal, revalidation re-admit, and CPFP
    /// family credit/debit. `insert`/`remove` change the pool's MEMBERSHIP; a
    /// `rekey_weight` changes its priority ORDERING — both feed the
    /// candidate's tx-selection order, so the off-loop engine (via
    /// `Mempool::revision`) treats any advance as "rebuild due". Family-weight
    /// credits reweight ancestors *during* an admission, so their bumps
    /// coalesce into the rebuild that admission already warrants — never a
    /// spurious *extra* one. (`detach_parent` mutates only `parents_in_pool`,
    /// which is not candidate-visible, so it deliberately does not bump.)
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

    /// Deep copy for transactional admission staging: a commit that may evict
    /// the new tx itself is applied to this clone and swapped into the live
    /// pool only if the tx survives, so a rejected admission never mutates the
    /// live pool. Kept `pub(crate)` (rather than a public `Clone` impl) so the
    /// expensive full-pool copy is not part of the crate's external API.
    pub(crate) fn clone_for_staging(&self) -> Self {
        Self {
            ordered: self.ordered.clone(),
            by_tx_id: self.by_tx_id.clone(),
            by_input: self.by_input.clone(),
            by_output: self.by_output.clone(),
            children_of: self.children_of.clone(),
            total_bytes: self.total_bytes,
            revision: self.revision,
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

    /// Monotonic candidate-visible revision counter, bumped on every `insert`,
    /// `remove`, and family-weight `rekey_weight`. See the `revision` field.
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
    pub(crate) fn remove(&mut self, tx_id: &TxId) -> Option<Entry> {
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
    /// Discards the truncation frontier; production callers use the
    /// `_frontier` / `_debiting` variants (only tests want the plain form).
    #[cfg(test)]
    pub(crate) fn remove_with_descendants(&mut self, tx_id: &TxId, max_depth: usize) -> Vec<Entry> {
        self.remove_with_descendants_frontier(tx_id, max_depth).0
    }

    /// Like [`Self::remove_with_descendants`] but also returns the *truncation
    /// frontier*: descendants that were NOT removed because the `max_depth`
    /// node cap was hit — the un-visited direct children of removed nodes,
    /// still pooled. Every frontier id's parent WAS removed, so each is
    /// orphaned; the caller carries them into bounded follow-up removal so a
    /// deep family below a hard-invalid tx is fully evicted over several
    /// passes rather than left dangling (its later revalidation returns
    /// `UnresolvedInput`, which the recheck policy retains, not evicts).
    /// The frontier is empty when the cap was not hit.
    pub(crate) fn remove_with_descendants_frontier(
        &mut self,
        tx_id: &TxId,
        max_depth: usize,
    ) -> (Vec<Entry>, Vec<TxId>) {
        if !self.contains(tx_id) {
            return (Vec::new(), Vec::new());
        }
        // Collect descendants depth-first (explicit stack), capped at
        // `max_depth` nodes visited.
        let mut to_visit: Vec<TxId> = vec![*tx_id];
        let mut ordered_ids: Vec<TxId> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut truncated = false;
        while let Some(next) = to_visit.pop() {
            if !seen.insert(next) {
                continue;
            }
            if ordered_ids.len() >= max_depth {
                // Cap hit BEFORE visiting `next`: it (and everything else
                // still queued) is an un-removed descendant of a removed node.
                to_visit.push(next);
                truncated = true;
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
        let removed_set: std::collections::HashSet<TxId> = ordered_ids.iter().copied().collect();
        let mut removed = Vec::with_capacity(ordered_ids.len());
        for id in ordered_ids {
            if let Some(e) = self.remove(&id) {
                removed.push(e);
            }
        }
        // Frontier = remaining queued ids, deduped and excluding any that were
        // actually removed (a diamond child can be queued twice, one copy
        // popped+removed). Empty unless the cap truncated the walk.
        let frontier: Vec<TxId> = if truncated {
            let mut seen_f = std::collections::HashSet::new();
            to_visit
                .into_iter()
                .filter(|id| !removed_set.contains(id) && seen_f.insert(*id))
                .collect()
        } else {
            Vec::new()
        };
        (removed, frontier)
    }

    /// Re-key a single in-pool tx to `new_weight`, moving only its slot in
    /// `ordered` and its `by_tx_id` mapping. The weight-independent indexes
    /// (`by_input`/`by_output`/`children_of`/`total_bytes`) are untouched —
    /// so, unlike `remove`+`insert`, this preserves a non-leaf node's own
    /// `children_of` edges. No-op if the tx is absent. Used only by the
    /// family-weight walk.
    fn rekey_weight(&mut self, tx_id: &TxId, new_weight: u64) {
        let Some(old_key) = self.by_tx_id.get(tx_id).copied() else {
            return;
        };
        if old_key.weight() == new_weight {
            return; // no ordering change — skip the churn (and revision bump)
        }
        let Some(mut entry) = self.ordered.remove(&old_key) else {
            return;
        };
        entry.weight = new_weight;
        let new_key = WeightedKey::new(new_weight, *tx_id);
        self.by_tx_id.insert(*tx_id, new_key);
        self.ordered.insert(new_key, entry);
        self.revision += 1;
    }

    /// Strip a now-confirmed/removed `parent` from `child`'s
    /// `parents_in_pool`, in place. `parents_in_pool` is not part of the
    /// ordering key, so the slot in `ordered` is unaffected — no re-key and
    /// no `remove`+`insert` (which would drop `child`'s own `children_of`
    /// edges). No-op if `child` is absent.
    pub(crate) fn detach_parent(&mut self, child: &TxId, parent: &TxId) {
        let Some(key) = self.by_tx_id.get(child).copied() else {
            return;
        };
        if let Some(entry) = self.ordered.get_mut(&key) {
            entry.parents_in_pool.retain(|p| p != parent);
        }
    }

    /// Refresh a surviving tx's `last_checked_at` after a tip re-validation
    /// pass, marking it as visited this pass so the oldest-first rotation moves
    /// on. Updates ONLY the rotation clock — NOT `cost`/`weight`: the recheck is
    /// a validity check, not a re-pricing, and writing a fresh consumed cost
    /// here without re-keying would desync `Entry.cost` from the `ByCost`
    /// `WeightedKey` (and feed stale weights to later #139 debits). Priority
    /// stays owned by admission. `last_checked_at` is not part of `WeightedKey`,
    /// so the `ordered` slot is unchanged (no re-key). No-op if absent.
    pub(crate) fn touch_rechecked(&mut self, tx_id: &TxId, now: Instant) {
        let Some(key) = self.by_tx_id.get(tx_id).copied() else {
            return;
        };
        if let Some(entry) = self.ordered.get_mut(&key) {
            entry.last_checked_at = now;
        }
    }

    /// Family-weight (CPFP) walk: add `delta` to every in-pool ancestor of
    /// the tx whose inputs are `seed_inputs`, recursively up the spend graph.
    /// Faithful port of Scala `OrderedTxPool.updateFamily`
    /// (`OrderedTxPool.scala:185-212`): parents are re-derived from the live
    /// `by_output` map at each level, the *same* `delta` propagates to every
    /// ancestor, and there is no global visited-set (a diamond ancestor is
    /// intentionally credited once per path). `delta` is `+own_weight` on
    /// admission (credit) and `-current_weight` on removal (debit). Bounded
    /// by `bounds`.
    pub(crate) fn update_family(
        &mut self,
        seed_inputs: &[Digest32],
        delta: i128,
        bounds: FamilyBounds,
    ) {
        // Stamp the time budget per top-level walk, matching Scala's
        // per-`updateFamily` `startTime` (`OrderedTxPool.scala:189`).
        let deadline = Instant::now() + Duration::from_millis(bounds.max_update_ms);
        let mut ops: usize = 0;
        self.update_family_rec(seed_inputs, delta, bounds, deadline, 0, &mut ops);
    }

    fn update_family_rec(
        &mut self,
        seed_inputs: &[Digest32],
        delta: i128,
        bounds: FamilyBounds,
        deadline: Instant,
        depth: usize,
        ops: &mut usize,
    ) {
        // Depth/time guard gates DESCENT (Scala :191): a bailed call returns,
        // but its caller's loop keeps re-keying remaining sibling parents —
        // matching Scala's `foldLeft`, not a single global stop.
        if depth > bounds.max_depth || Instant::now() > deadline {
            tracing::warn!(
                depth,
                "mempool family-weight walk: depth/time bound hit, stopping descent"
            );
            return;
        }
        // Direct parents at this level, captured (id + weight + inputs) BEFORE
        // re-keying any of them — mirroring Scala materializing `parentTxs`
        // before its `foldLeft`, so each direct parent is boosted from its
        // call-start weight even if an earlier sibling's recursion already
        // touched it. Deduped per call (Scala `.toSet`); deliberately NO global
        // visited-set across branches (a diamond ancestor reached via recursion
        // is still credited once per path).
        let mut seen: std::collections::HashSet<TxId> = std::collections::HashSet::new();
        let parents: Vec<(TxId, u64, Vec<Digest32>)> = seed_inputs
            .iter()
            .filter_map(|box_id| self.by_output.get(box_id).copied())
            .filter(|id| seen.insert(*id))
            .filter_map(|id| self.get(&id).map(|e| (id, e.weight, e.inputs.clone())))
            .collect();
        for (parent, captured_weight, parent_inputs) in parents {
            // Rust-only total-rekey cap — a hard stop for the whole walk.
            if *ops >= bounds.max_ops {
                tracing::warn!(
                    ops = *ops,
                    "mempool family-weight walk: ops cap hit, stopping"
                );
                return;
            }
            self.rekey_weight(&parent, saturating_apply(captured_weight, delta));
            *ops += 1;
            self.update_family_rec(&parent_inputs, delta, bounds, deadline, depth + 1, ops);
        }
    }

    /// Remove a single tx and debit its weight from its surviving ancestors
    /// (the de-propagation half of Scala `remove` → `updateFamily(-weight)`).
    /// No-op if absent.
    pub(crate) fn remove_debiting(&mut self, tx_id: &TxId, bounds: FamilyBounds) -> Option<Entry> {
        let removed = self.remove(tx_id)?;
        // `removed` is owned and already out of the pool; its inputs still
        // point at the surviving parents' outputs in `by_output`, so the debit
        // reaches them.
        self.update_family(&removed.inputs, -i128::from(removed.weight), bounds);
        Some(removed)
    }

    /// Remove a tx and its whole descendant subtree, then debit EACH removed
    /// tx's weight from its surviving ancestors (Scala `remove` →
    /// `updateFamily(-weight)`, applied per tx). Ancestors *inside* the removed
    /// subtree are already gone from `by_output`, so each debit reaches only
    /// still-live parent paths. Per-entry (not just the root) is required for
    /// DAG families: a removed child whose OTHER parent survives must still
    /// debit that parent — debiting only the root's accumulated weight would
    /// leave a phantom boost on the surviving co-parent.
    pub(crate) fn remove_with_descendants_debiting(
        &mut self,
        tx_id: &TxId,
        max_depth: usize,
        bounds: FamilyBounds,
    ) -> Vec<Entry> {
        self.remove_with_descendants_debiting_frontier(tx_id, max_depth, bounds)
            .0
    }

    /// [`Self::remove_with_descendants_debiting`] that also returns the
    /// truncation frontier (see [`Self::remove_with_descendants_frontier`]) so
    /// the recheck cascade can carry orphaned deep descendants into bounded
    /// follow-up eviction.
    pub(crate) fn remove_with_descendants_debiting_frontier(
        &mut self,
        tx_id: &TxId,
        max_depth: usize,
        bounds: FamilyBounds,
    ) -> (Vec<Entry>, Vec<TxId>) {
        let (removed, frontier) = self.remove_with_descendants_frontier(tx_id, max_depth);
        for entry in &removed {
            self.update_family(&entry.inputs, -i128::from(entry.weight), bounds);
        }
        (removed, frontier)
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
mod tests;
