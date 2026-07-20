//! Staging pool: brief holding store for transactions that cannot yet be
//! admitted to the live pool, of two kinds (see the design doc §L / §1):
//!
//! * **Orphan** (child-before-parent): `validate` returned
//!   `UnresolvedInput`, so we hold only the cheap `peek_structure`
//!   projection — no cost, no materialized outputs — indexed by the
//!   still-missing input box-ids so an arriving parent can resolve it.
//! * **Held** (parent-before-child): a tx that FULLY VALIDATED but lost the
//!   fee / capacity / double-spend gate. Retained briefly with its computed
//!   `weight`, `cost`, and materialized `outputs`, indexed by the box-ids it
//!   creates so a later descendant can reconstruct the package.
//!
//! This module is the pure data structure: indices, caps, eviction order,
//! and pruning. It runs NO validation and emits NO actions — wiring lives
//! in `admission` / `reorg`. Every entry is deserialize-only work bounded by
//! the caps here; the "no script eval without charging `CostBudgets`"
//! invariant is upheld by the callers that promote entries out of staging.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ergo_primitives::digest::Digest32;
use ergo_ser::ergo_box::ErgoBox;

use crate::types::{PeerId, TipPointer, TxId, TxSource};
use crate::weight::SCALE;

/// Which of the two staging kinds an entry is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StagedKind {
    /// Child-before-parent: inputs not yet resolvable.
    Orphan,
    /// Parent-before-child: valid but lost an admission gate.
    Held,
}

/// Validated facts retained for a **Held** entry so a package re-score is
/// arithmetic only — no re-validation of the held tx unless the tip moved.
#[derive(Debug, Clone)]
pub struct HeldFacts {
    /// Single-tx weight computed at the failed admission (`WeightFunction`).
    pub weight: u64,
    /// Consumed validation cost.
    pub cost: u64,
    /// Materialized output boxes, aligned with `output_box_ids` by index.
    pub outputs: Vec<ErgoBox>,
}

/// One staged transaction.
#[derive(Debug, Clone)]
pub struct StagedTx {
    pub tx_id: TxId,
    pub bytes: Arc<[u8]>,
    pub kind: StagedKind,
    /// ALL declared regular inputs (from `peek_structure` / `Validated`).
    pub input_box_ids: Vec<Digest32>,
    /// Declared DATA inputs. Tracked so block-advance pruning can drop an
    /// entry whose data-input box was confirmed-and-consumed (it can never be
    /// admitted again). Empty when unknown.
    pub data_input_box_ids: Vec<Digest32>,
    /// ALL created outputs.
    pub output_box_ids: Vec<Digest32>,
    pub fee: u64,
    pub size_bytes: u32,
    /// `Some` for Held (fully validated), `None` for Orphan (cost unknown).
    pub validated: Option<HeldFacts>,
    /// Subset of inputs unresolved at staging; empty for Held.
    pub missing_inputs: Vec<Digest32>,
    pub source: TxSource,
    pub staged_at: Instant,
    /// Tip height when staged → block-count expiry.
    pub staged_height: u32,
    /// Header id of the tip this entry was (re-)validated against. The package
    /// freshness gate keys on tip IDENTITY, not height: a same-height reorg
    /// (Y@H replacing X@H) leaves `staged_height` unchanged but changes this,
    /// forcing re-validation of a context-sensitive held member.
    pub staged_tip_id: Digest32,
    /// Full-revalidation attempts; hard cap (`staging_max_reevals`).
    pub reeval_count: u16,
    /// Monotonic insertion sequence — FIFO tiebreak for eviction/expiry.
    seq: u64,
}

impl StagedTx {
    /// Eviction/ordering priority. Held uses its real weight
    /// (`fee·SCALE/cost`); Orphan uses the declared `fee·SCALE/size` proxy
    /// since its cost is unknown. Higher = keep longer.
    pub fn priority_proxy(&self) -> u64 {
        match &self.validated {
            Some(h) => h.weight,
            None => {
                let size = (self.size_bytes as u128).max(1);
                u64::try_from((self.fee as u128).saturating_mul(SCALE as u128) / size)
                    .unwrap_or(u64::MAX)
            }
        }
    }

    pub fn is_held(&self) -> bool {
        matches!(self.kind, StagedKind::Held)
    }

    pub fn is_orphan(&self) -> bool {
        matches!(self.kind, StagedKind::Orphan)
    }

    pub fn peer(&self) -> Option<PeerId> {
        self.source.peer()
    }
}

/// Hard capacity/fairness bounds for the staging pool. Constructed from
/// `MempoolConfig` once staging is wired (later phase); the defaults are the
/// human-confirmed values so the structure is testable in isolation.
#[derive(Debug, Clone, Copy)]
pub struct StagingCaps {
    pub max_count: usize,
    pub max_bytes: usize,
    pub max_count_per_peer: usize,
    pub max_bytes_per_peer: usize,
    pub max_waiters_per_input: usize,
}

impl Default for StagingCaps {
    fn default() -> Self {
        Self {
            max_count: 2048,
            max_bytes: 8 * 1024 * 1024,
            max_count_per_peer: 128,
            max_bytes_per_peer: 1024 * 1024,
            max_waiters_per_input: 64,
        }
    }
}

/// Why a staging insert was refused. A refusal is never fatal — the tx is
/// simply not staged (it may arrive again); no pool state changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StageReject {
    /// Already staged under this tx_id.
    Duplicate,
    /// Single tx larger than the whole staging byte budget.
    TooLarge,
    /// Source peer already at its per-peer count allotment.
    PerPeerCount,
    /// Source peer already at its per-peer byte allotment.
    PerPeerBytes,
    /// One waited-on input already has `max_waiters_per_input` waiters
    /// (cascade-bomb bound).
    WaitersFull,
    /// Pool full and the newcomer is the least valuable entry — evicting a
    /// higher-priority incumbent to make room for it would be regressive.
    Full,
}

/// Result of a successful staging insert: the entries evicted to make room
/// (lowest package-feerate first). Empty on the common path.
#[derive(Debug, Clone, Default)]
pub struct StageAdmit {
    pub evicted: Vec<StagedTx>,
}

/// The staging pool. Single-writer; owned by `Mempool` alongside `pool`.
#[derive(Debug)]
pub struct StagingPool {
    by_tx_id: HashMap<TxId, StagedTx>,
    /// A box-id a staged tx MUST spend but can't yet resolve → the staged
    /// txs waiting on it. Only orphans register here.
    waiting_on_input: HashMap<Digest32, Vec<TxId>>,
    /// Box-ids a staged tx CREATES → its tx-id. Both kinds register here so
    /// an incoming child can discover a staged ancestor.
    by_output: HashMap<Digest32, TxId>,
    /// Insertion-order id list — cheap iteration + FIFO invariants.
    fifo: VecDeque<TxId>,
    total_bytes: usize,
    per_peer_count: HashMap<PeerId, usize>,
    per_peer_bytes: HashMap<PeerId, usize>,
    caps: StagingCaps,
    seq_counter: u64,
}

impl StagingPool {
    pub fn new(caps: StagingCaps) -> Self {
        Self {
            by_tx_id: HashMap::new(),
            waiting_on_input: HashMap::new(),
            by_output: HashMap::new(),
            fifo: VecDeque::new(),
            total_bytes: 0,
            per_peer_count: HashMap::new(),
            per_peer_bytes: HashMap::new(),
            caps,
            seq_counter: 0,
        }
    }

    pub fn with_default_caps() -> Self {
        Self::new(StagingCaps::default())
    }

    pub fn len(&self) -> usize {
        self.by_tx_id.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_tx_id.is_empty()
    }

    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    pub fn caps(&self) -> &StagingCaps {
        &self.caps
    }

    pub fn contains(&self, tx_id: &TxId) -> bool {
        self.by_tx_id.contains_key(tx_id)
    }

    pub fn get(&self, tx_id: &TxId) -> Option<&StagedTx> {
        self.by_tx_id.get(tx_id)
    }

    pub fn peer_count(&self, peer: &PeerId) -> usize {
        self.per_peer_count.get(peer).copied().unwrap_or(0)
    }

    pub fn peer_bytes(&self, peer: &PeerId) -> usize {
        self.per_peer_bytes.get(peer).copied().unwrap_or(0)
    }

    /// Staged tx ids waiting on `box_id` (orphans whose missing input is
    /// `box_id`). Empty slice if none.
    pub fn waiters_on(&self, box_id: &Digest32) -> &[TxId] {
        self.waiting_on_input
            .get(box_id)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// The staged tx (orphan or held) that CREATES `box_id`, if any. Used to
    /// walk up from an incoming child to a staged ancestor.
    pub fn creator_of(&self, box_id: &Digest32) -> Option<TxId> {
        self.by_output.get(box_id).copied()
    }

    /// Iterate staged entries in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = &StagedTx> {
        self.fifo.iter().filter_map(move |id| self.by_tx_id.get(id))
    }

    /// Stage an **orphan** (unresolved inputs). `missing_inputs` is the
    /// subset of `input_box_ids` that could not be resolved.
    #[allow(clippy::too_many_arguments)]
    pub fn stage_orphan(
        &mut self,
        tx_id: TxId,
        bytes: Arc<[u8]>,
        input_box_ids: Vec<Digest32>,
        data_input_box_ids: Vec<Digest32>,
        output_box_ids: Vec<Digest32>,
        fee: u64,
        size_bytes: u32,
        missing_inputs: Vec<Digest32>,
        source: TxSource,
        now: Instant,
        staged_tip: TipPointer,
    ) -> Result<StageAdmit, StageReject> {
        let entry = StagedTx {
            tx_id,
            bytes,
            kind: StagedKind::Orphan,
            input_box_ids,
            data_input_box_ids,
            output_box_ids,
            fee,
            size_bytes,
            validated: None,
            missing_inputs,
            source,
            staged_at: now,
            staged_height: staged_tip.height,
            staged_tip_id: staged_tip.header_id,
            reeval_count: 0,
            seq: 0, // assigned in `insert`
        };
        self.insert(entry)
    }

    /// Stage a **held** tx (validated, lost an admission gate).
    #[allow(clippy::too_many_arguments)]
    pub fn stage_held(
        &mut self,
        tx_id: TxId,
        bytes: Arc<[u8]>,
        input_box_ids: Vec<Digest32>,
        data_input_box_ids: Vec<Digest32>,
        output_box_ids: Vec<Digest32>,
        fee: u64,
        size_bytes: u32,
        weight: u64,
        cost: u64,
        outputs: Vec<ErgoBox>,
        source: TxSource,
        now: Instant,
        staged_tip: TipPointer,
    ) -> Result<StageAdmit, StageReject> {
        let entry = StagedTx {
            tx_id,
            bytes,
            kind: StagedKind::Held,
            input_box_ids,
            data_input_box_ids,
            output_box_ids,
            fee,
            size_bytes,
            validated: Some(HeldFacts {
                weight,
                cost,
                outputs,
            }),
            missing_inputs: Vec::new(),
            source,
            staged_at: now,
            staged_height: staged_tip.height,
            staged_tip_id: staged_tip.header_id,
            reeval_count: 0,
            seq: 0,
        };
        self.insert(entry)
    }

    /// Core insert: cap enforcement (caller-priority-aware) then indexing.
    fn insert(&mut self, mut entry: StagedTx) -> Result<StageAdmit, StageReject> {
        if self.by_tx_id.contains_key(&entry.tx_id) {
            return Err(StageReject::Duplicate);
        }
        let size = entry.size_bytes as usize;
        // A single tx that can never fit the whole budget is refused outright.
        if size > self.caps.max_bytes {
            return Err(StageReject::TooLarge);
        }

        // Per-peer fairness — refuse (never evict another peer's entries for
        // this one) so one peer cannot grief the shared budget.
        if let Some(p) = entry.peer() {
            if self.peer_count(&p) + 1 > self.caps.max_count_per_peer {
                return Err(StageReject::PerPeerCount);
            }
            if self.peer_bytes(&p) + size > self.caps.max_bytes_per_peer {
                return Err(StageReject::PerPeerBytes);
            }
        }

        // Fan-out (cascade-bomb) bound: no missing input may exceed its
        // waiter cap. Checked across the DISTINCT missing inputs.
        let mut distinct_missing: Vec<Digest32> = Vec::new();
        for m in &entry.missing_inputs {
            if !distinct_missing.contains(m) {
                distinct_missing.push(*m);
            }
        }
        for m in &distinct_missing {
            if self.waiters_on(m).len() >= self.caps.max_waiters_per_input {
                return Err(StageReject::WaitersFull);
            }
        }

        // Global capacity: evict lowest-priority incumbents to make room.
        // Refuse if the newcomer is itself the least valuable entry.
        let newcomer_priority = entry.priority_proxy();
        let mut admit = StageAdmit::default();
        loop {
            let over_count = self.by_tx_id.len() + 1 > self.caps.max_count;
            let over_bytes = self.total_bytes + size > self.caps.max_bytes;
            if !over_count && !over_bytes {
                break;
            }
            let Some(low_id) = self.lowest_priority_id() else {
                // Nothing left to evict; only the newcomer would remain. It
                // fits (size <= max_bytes, count 1 <= max_count).
                break;
            };
            let low_priority = self.by_tx_id.get(&low_id).map(|e| e.priority_proxy());
            if let Some(lp) = low_priority {
                if lp > newcomer_priority {
                    // The least valuable incumbent still outranks the
                    // newcomer — don't regress the pool for it.
                    return Err(StageReject::Full);
                }
            }
            if let Some(removed) = self.remove(&low_id) {
                admit.evicted.push(removed);
            } else {
                break;
            }
        }

        // Commit indexing.
        entry.seq = self.seq_counter;
        self.seq_counter += 1;
        let tx_id = entry.tx_id;
        for m in &distinct_missing {
            self.waiting_on_input.entry(*m).or_default().push(tx_id);
        }
        for out in &entry.output_box_ids {
            self.by_output.insert(*out, tx_id);
        }
        if let Some(p) = entry.peer() {
            *self.per_peer_count.entry(p).or_insert(0) += 1;
            *self.per_peer_bytes.entry(p).or_insert(0) += size;
        }
        self.total_bytes += size;
        self.fifo.push_back(tx_id);
        self.by_tx_id.insert(tx_id, entry);
        Ok(admit)
    }

    /// Overwrite a staged tx's `reeval_count`. Used when an orphan is
    /// re-staged after a failed promotion attempt so the CPU-per-tx cap
    /// (`staging_max_reevals`) accrues across attempts rather than resetting.
    /// No-op if absent.
    pub fn bump_reeval(&mut self, tx_id: &TxId, reeval_count: u16) {
        if let Some(e) = self.by_tx_id.get_mut(tx_id) {
            e.reeval_count = reeval_count;
        }
    }

    /// Remove a staged tx and clean every index. Returns the removed entry.
    pub fn remove(&mut self, tx_id: &TxId) -> Option<StagedTx> {
        let entry = self.by_tx_id.remove(tx_id)?;
        // waiting_on_input: drop this tx from each of its DISTINCT missing
        // inputs' waiter lists.
        let mut seen: HashSet<Digest32> = HashSet::new();
        for m in &entry.missing_inputs {
            if !seen.insert(*m) {
                continue;
            }
            if let Some(waiters) = self.waiting_on_input.get_mut(m) {
                waiters.retain(|w| w != tx_id);
                if waiters.is_empty() {
                    self.waiting_on_input.remove(m);
                }
            }
        }
        // by_output: drop only the mappings that still point at this tx (a
        // later staged tx creating the same output-id — impossible in
        // practice — would have overwritten the mapping).
        for out in &entry.output_box_ids {
            if self.by_output.get(out) == Some(tx_id) {
                self.by_output.remove(out);
            }
        }
        // Per-peer counters.
        if let Some(p) = entry.peer() {
            if let Some(c) = self.per_peer_count.get_mut(&p) {
                *c = c.saturating_sub(1);
                if *c == 0 {
                    self.per_peer_count.remove(&p);
                }
            }
            if let Some(b) = self.per_peer_bytes.get_mut(&p) {
                *b = b.saturating_sub(entry.size_bytes as usize);
                if *b == 0 {
                    self.per_peer_bytes.remove(&p);
                }
            }
        }
        self.total_bytes = self.total_bytes.saturating_sub(entry.size_bytes as usize);
        self.fifo.retain(|id| id != tx_id);
        Some(entry)
    }

    /// The lowest-priority staged tx id (priority ascending, then oldest
    /// `seq`), or `None` if empty.
    fn lowest_priority_id(&self) -> Option<TxId> {
        self.by_tx_id
            .values()
            .min_by(|a, b| {
                a.priority_proxy()
                    .cmp(&b.priority_proxy())
                    .then_with(|| a.seq.cmp(&b.seq))
            })
            .map(|e| e.tx_id)
    }

    /// Drop every staged tx that spends (as a REGULAR input) or reads (as a
    /// DATA input) any box in `spent` — that box has been confirmed-and-
    /// consumed on-chain, so the tx can never be admitted again. Returns
    /// removed entries.
    pub fn prune_spent_inputs(&mut self, spent: &HashSet<Digest32>) -> Vec<StagedTx> {
        if spent.is_empty() || self.by_tx_id.is_empty() {
            return Vec::new();
        }
        let doomed: Vec<TxId> = self
            .by_tx_id
            .values()
            .filter(|e| {
                e.input_box_ids
                    .iter()
                    .chain(e.data_input_box_ids.iter())
                    .any(|b| spent.contains(b))
            })
            .map(|e| e.tx_id)
            .collect();
        doomed.iter().filter_map(|id| self.remove(id)).collect()
    }

    /// Drop staged txs past their wall-clock TTL or block-count horizon.
    /// A tx is expired when `now - staged_at >= ttl` OR
    /// `tip_height - staged_height >= max_blocks`. Returns removed entries.
    pub fn prune_expired(
        &mut self,
        now: Instant,
        tip_height: u32,
        ttl: Duration,
        max_blocks: u32,
    ) -> Vec<StagedTx> {
        if self.by_tx_id.is_empty() {
            return Vec::new();
        }
        let doomed: Vec<TxId> = self
            .by_tx_id
            .values()
            .filter(|e| {
                let aged = now.duration_since(e.staged_at) >= ttl;
                let stale = tip_height.saturating_sub(e.staged_height) >= max_blocks;
                aged || stale
            })
            .map(|e| e.tx_id)
            .collect();
        doomed.iter().filter_map(|id| self.remove(id)).collect()
    }

    /// Test-only: assert the indices are mutually consistent.
    #[doc(hidden)]
    pub fn check_invariants(&self) {
        assert_eq!(
            self.by_tx_id.len(),
            self.fifo.len(),
            "by_tx_id / fifo size mismatch"
        );
        let mut computed_bytes = 0usize;
        let mut peer_count: HashMap<PeerId, usize> = HashMap::new();
        let mut peer_bytes: HashMap<PeerId, usize> = HashMap::new();
        for id in &self.fifo {
            let e = self.by_tx_id.get(id).expect("fifo id must be in by_tx_id");
            computed_bytes += e.size_bytes as usize;
            if let Some(p) = e.peer() {
                *peer_count.entry(p).or_insert(0) += 1;
                *peer_bytes.entry(p).or_insert(0) += e.size_bytes as usize;
            }
            // Every output maps back to this tx.
            for out in &e.output_box_ids {
                assert_eq!(
                    self.by_output.get(out),
                    Some(id),
                    "by_output mapping wrong for {out:?}"
                );
            }
            // Every distinct missing input lists this tx as a waiter.
            let mut seen = HashSet::new();
            for m in &e.missing_inputs {
                if seen.insert(*m) {
                    assert!(
                        self.waiters_on(m).contains(id),
                        "waiting_on_input missing waiter {id:?} for {m:?}"
                    );
                }
            }
        }
        assert_eq!(self.total_bytes, computed_bytes, "total_bytes out of sync");
        assert_eq!(
            self.per_peer_count, peer_count,
            "per_peer_count out of sync"
        );
        assert_eq!(
            self.per_peer_bytes, peer_bytes,
            "per_peer_bytes out of sync"
        );
        // No dangling waiter/creator references.
        for (box_id, waiters) in &self.waiting_on_input {
            assert!(!waiters.is_empty(), "empty waiter list for {box_id:?}");
            for w in waiters {
                assert!(
                    self.by_tx_id.contains_key(w),
                    "dangling waiter {w:?} for {box_id:?}"
                );
            }
        }
        for (box_id, creator) in &self.by_output {
            assert!(
                self.by_tx_id.contains_key(creator),
                "dangling by_output creator {creator:?} for {box_id:?}"
            );
        }
    }
}

#[cfg(test)]
mod tests;
