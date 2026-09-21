//! Provisional input-block chain APIs (Matrix / `weak-blocks` plan 2, task 2;
//! see spec §8 in `dev-docs/superpowers/specs/2026-09-21-input-blocks-port-design.md`).
//!
//! Three surfaces mirror Scala `ErgoMemPool`'s weak-blocks integration:
//!
//! * [`InputBlockOverlay`] — the UTXO view used to admit input-block
//!   transactions: committed + pool outputs + input-block outputs, minus
//!   boxes spent BY input-block transactions. Boxes spent by ordinary pool
//!   transactions stay visible — same rule [`crate::overlay::PoolUtxoOverlay`]
//!   already applies for replace-by-fee.
//! * [`apply_input_block_txs`] — Scala `removeWithDoubleSpends`: evict the
//!   given txs (if pooled) and every pool tx conflicting with them on
//!   inputs. NOT `on_tip_change`: no tip pointer, no revalidation-queue
//!   push, no budget reset.
//! * [`restore_input_block_txs`] — Scala `put` on rolled-back cached
//!   bodies: no validation, `weighted(tx, feeFactor)`, `updateFamily`
//!   family-weight credit, capacity eviction. D1: [`crate::pool::OrderedPool::insert`]
//!   refuses an entry whose inputs conflict with a pooled tx, while Scala's
//!   `put` admits both; such entries are dropped as [`RestoreOutcome::Conflict`].

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;

use ergo_primitives::digest::Digest32;
use ergo_ser::ergo_box::ErgoBox;
use ergo_ser::transaction::{transaction_id, Transaction};
use ergo_ser::weak_id::WeakId;
use ergo_ser::WriteError;
use ergo_validation::UtxoView;

use crate::pool::{Entry, FamilyBounds, OrderedPool, PoolError};
use crate::types::{EvictionReason, MempoolAction, MempoolConfig, ObservedEvent, TxId, TxSource};
use crate::validator::ErgoValidator;
use crate::weight::{WeightFunction, WeightInputs};
use crate::Validator as _;

/// Scala `FakeCost`: the weight input used for a restored tx's cost when the
/// node did not retain its previously-computed validation cost (`ErgoMemPool`
/// `FeePerCycle` default).
pub const FAKE_COST: u64 = 100_000;

/// One cached body for [`restore_input_block_txs`]: `(tx_id, canonical
/// bytes, retained validation cost if the node still has it)`.
pub type RestoreBody = (TxId, Arc<[u8]>, Option<u64>);

/// UTXO view for admitting input-block transactions (spec §8): committed +
/// pool outputs, PLUS outputs created by the given input-block transactions,
/// MINUS boxes those input-block transactions spend. Boxes spent by ordinary
/// pool transactions stay visible — replace-by-fee is unaffected. Data
/// inputs are resolved through the same view (parity with Scala
/// `withMempoolAndInputBlocks`).
pub struct InputBlockOverlay<'a> {
    base: &'a dyn UtxoView,
    pool_outputs: &'a HashMap<Digest32, ErgoBox>,
    ib_outputs: HashMap<Digest32, ErgoBox>,
    ib_spent: HashSet<Digest32>,
}

impl<'a> InputBlockOverlay<'a> {
    /// Builds the overlay's input-block-local index from `input_block_txs`:
    /// every input they declare is spent (hidden), every output they create
    /// is visible (unless also spent within the same batch, in which case it
    /// is fully consumed and stays hidden).
    pub fn new(
        base: &'a dyn UtxoView,
        pool_outputs: &'a HashMap<Digest32, ErgoBox>,
        input_block_txs: &[Transaction],
    ) -> Result<Self, WriteError> {
        let mut ib_outputs = HashMap::new();
        let mut ib_spent = HashSet::new();
        for tx in input_block_txs {
            let tx_id_modifier = transaction_id(tx)?;
            for input in &tx.inputs {
                ib_spent.insert(input.box_id);
            }
            for (idx, candidate) in tx.output_candidates.iter().enumerate() {
                let ergo_box = ErgoBox {
                    candidate: candidate.clone(),
                    transaction_id: tx_id_modifier,
                    index: idx as u16,
                };
                let id = ergo_box.box_id()?;
                ib_outputs.insert(id, ergo_box);
            }
        }
        Ok(Self {
            base,
            pool_outputs,
            ib_outputs,
            ib_spent,
        })
    }
}

impl UtxoView for InputBlockOverlay<'_> {
    fn get_box(&self, box_id: &Digest32) -> Option<ErgoBox> {
        // Boxes spent by an input-block tx are gone from this view, even if
        // an input-block tx also (re-)creates a box under the same id —
        // fully consumed within the batch either way.
        if self.ib_spent.contains(box_id) {
            return None;
        }
        if let Some(b) = self.ib_outputs.get(box_id) {
            return Some(b.clone());
        }
        if let Some(b) = self.pool_outputs.get(box_id) {
            return Some(b.clone());
        }
        self.base.get_box(box_id)
    }
}

/// Retained pool entry for a later [`restore_input_block_txs`] call (Scala
/// keeps the rolled-back block's cached bodies; the Rust port keeps the
/// pool [`Entry`]'s already-computed facts so a restore can reuse them).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovedEntry {
    pub tx_id: TxId,
    pub bytes: Arc<[u8]>,
    pub fee: u64,
    pub size_bytes: u32,
    pub cost: u64,
}

impl From<&Entry> for RemovedEntry {
    fn from(e: &Entry) -> Self {
        Self {
            tx_id: e.tx_id,
            bytes: e.bytes.clone(),
            fee: e.fee,
            size_bytes: e.size_bytes,
            cost: e.cost,
        }
    }
}

/// Scala `removeWithDoubleSpends(txs)`: remove `txs` (where pooled) and
/// every pool tx that spends any of the same inputs. NOT `on_tip_change` —
/// no tip pointer, no revalidation-queue push, no budget reset. Structured
/// like `on_tip_change`'s Step 1/2/3/4 (snapshot children of the applied
/// txs, remove them without cascading so surviving children stay pooled,
/// cascade-evict conflicting txs since their whole subtree double-spent,
/// then detach the stale parent edge from survivors) so the same pool
/// invariants (`children_of` / `parents_in_pool` consistency) hold.
///
/// Fails closed: every `tx`'s id is computed FIRST, in a read-only pass
/// (`transaction_id`, `pool.contains` — no mutation), before any pool
/// removal begins. If ANY tx's id cannot be computed, the whole call
/// returns `Err` with the pool untouched — never a partial removal from
/// the txs enumerated before the failing one.
pub fn apply_input_block_txs(
    pool: &mut OrderedPool,
    config: &MempoolConfig,
    txs: &[Transaction],
) -> Result<(Vec<RemovedEntry>, Vec<MempoolAction>), WriteError> {
    let bounds = FamilyBounds::new(
        config.max_family_depth,
        config.max_family_ops,
        config.max_family_update_ms,
    );

    // Read-only pass: compute every tx's id before touching the pool at
    // all, so a failure here (`?`) aborts with zero mutation.
    let mut all_inputs: Vec<Digest32> = Vec::new();
    let mut tx_ids: Vec<TxId> = Vec::with_capacity(txs.len());
    for tx in txs {
        all_inputs.extend(tx.inputs.iter().map(|i| i.box_id));
        tx_ids.push(*transaction_id(tx)?.as_digest());
    }
    let applied_ids: Vec<TxId> = tx_ids.into_iter().filter(|id| pool.contains(id)).collect();

    // Step 1 — snapshot surviving children of the about-to-be-removed
    // applied txs BEFORE removal (their `parents_in_pool` edge goes stale).
    let applied_set: HashSet<TxId> = applied_ids.iter().copied().collect();
    let mut applied_parent_children: HashMap<TxId, Vec<TxId>> = HashMap::new();
    if !applied_set.is_empty() {
        for e in pool.iter_prioritized() {
            for parent in &e.parents_in_pool {
                if applied_set.contains(parent) {
                    applied_parent_children
                        .entry(*parent)
                        .or_default()
                        .push(e.tx_id);
                }
            }
        }
    }

    // Step 2 — remove the applied txs themselves, no cascade: a surviving
    // child's spent-output-of-parent input is now committed within this
    // provisional chain, so it stays valid.
    let mut removed: Vec<RemovedEntry> = Vec::new();
    for id in &applied_ids {
        if let Some(entry) = pool.remove_debiting(id, bounds) {
            removed.push(RemovedEntry::from(&entry));
        }
    }

    // Step 3 — cascade-evict pool txs that conflict on inputs with the
    // applied txs (Scala `removeWithDoubleSpends`'s double-spend half): the
    // whole subtree is now built on a box that's been spent elsewhere.
    let mut already: HashSet<TxId> = removed.iter().map(|e| e.tx_id).collect();
    for id in pool.conflicts_for_inputs(&all_inputs) {
        if already.contains(&id) {
            continue;
        }
        for e in pool.remove_with_descendants_debiting(&id, config.max_family_depth, bounds) {
            if already.insert(e.tx_id) {
                removed.push(RemovedEntry::from(&e));
            }
        }
    }

    // Step 4 — detach applied parents from surviving children's
    // `parents_in_pool` (edge cleanup only; survivors keep any family-weight
    // boost earned from their own descendants).
    for (parent, children) in &applied_parent_children {
        for child in children {
            pool.detach_parent(child, parent);
        }
    }

    let mut actions = Vec::new();
    if !removed.is_empty() {
        let tx_ids: Vec<TxId> = removed.iter().map(|e| e.tx_id).collect();
        actions.push(MempoolAction::RevokeBroadcast {
            tx_ids: tx_ids.clone(),
        });
        actions.push(MempoolAction::Observe {
            event: ObservedEvent::Evicted {
                tx_ids,
                reason: EvictionReason::InputConflict,
            },
        });
    }

    Ok((removed, actions))
}

/// Outcome of restoring one cached body through [`restore_input_block_txs`].
/// A single call can return MORE entries than `bodies` — a `CapacityEvicted`
/// is pushed for every pool tx (restored-this-call or pre-existing) that the
/// post-insert capacity sweep evicts, including the just-restored body
/// itself if it lands as the pool's own new lowest weight (Scala parity:
/// `put` evicts `orderedTransactions.last` unconditionally after crediting).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoreOutcome {
    Restored(TxId),
    /// D1: refused by [`OrderedPool::insert`] because the body's inputs
    /// conflict with an already-pooled tx (duplicate tx id and output-id
    /// collision also land here — both are forms of "can't seat this entry
    /// as given"). Scala's `put` admits both transactions; see spec §8.
    Conflict(TxId),
    /// The body's bytes did not deserialize (`ErgoValidator::peek_structure`
    /// failed).
    Malformed(TxId),
    CapacityEvicted(TxId),
}

/// Scala `put`: re-insert cached bodies WITHOUT validation — no script
/// check, no double-spend check (beyond the D1 divergence noted on
/// [`RestoreOutcome::Conflict`]). Fee comes from a structural peek
/// (`ErgoValidator::peek_structure`, matching `peek_fee`'s fee derivation),
/// size from the bytes, cost is the retained value from a prior admission or
/// [`FAKE_COST`] when unknown. Inserted through [`OrderedPool::insert`] so
/// family weights ([`OrderedPool::update_family`]) and capacity enforcement
/// behave exactly as for any admitted entry.
pub fn restore_input_block_txs(
    pool: &mut OrderedPool,
    config: &MempoolConfig,
    weight_fn: &dyn WeightFunction,
    bodies: &[RestoreBody],
    now: Instant,
) -> Vec<RestoreOutcome> {
    let bounds = FamilyBounds::new(
        config.max_family_depth,
        config.max_family_ops,
        config.max_family_update_ms,
    );
    let mut outcomes = Vec::with_capacity(bodies.len());

    for (tx_id, bytes, retained_cost) in bodies {
        let peeked = match ErgoValidator.peek_structure(bytes) {
            Ok(p) => p,
            Err(_) => {
                outcomes.push(RestoreOutcome::Malformed(*tx_id));
                continue;
            }
        };
        let size_bytes = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
        let cost = retained_cost.unwrap_or(FAKE_COST);
        let weight = weight_fn.compute(WeightInputs {
            tx_id,
            fee: peeked.fee,
            size_bytes,
            cost,
        });

        let mut seen = HashSet::new();
        let parents_in_pool: Vec<TxId> = peeked
            .input_box_ids
            .iter()
            .filter_map(|inp| pool.parent_for_output(inp))
            .filter(|p| seen.insert(*p))
            .collect();

        let mut entry = Entry::new(
            *tx_id,
            bytes.clone(),
            peeked.input_box_ids.clone(),
            peeked.output_box_ids.clone(),
            parents_in_pool,
            peeked.fee,
            weight,
            size_bytes,
            cost,
            TxSource::DemotedFromBlock,
        );
        entry.created_at = now;
        entry.last_checked_at = now;

        match pool.insert(entry) {
            Ok(()) => {
                pool.update_family(&peeked.input_box_ids, i128::from(weight), bounds);

                // Reconnect already-pooled spenders of this restored tx's
                // outputs (findings-2-r1 #1): a child C that survived this
                // tx's earlier removal (e.g. via `apply_input_block_txs`)
                // had its `parents_in_pool` edge detached, so restoring the
                // parent must re-attach it — otherwise a later cascading
                // eviction of the restored tx (via `children_of`, which
                // `remove_with_descendants_debiting` walks) would miss C
                // entirely and leave it pooled spending a box that no
                // longer exists. Crediting `update_family` through the
                // reconnected edge reproduces exactly the family-weight
                // boost C's presence would have contributed had this tx
                // never left the pool (Scala `put` re-registers outputs so
                // families reconnect — spec §8).
                //
                // findings-2-r2 #1: seed the credit ONLY with the edge(s)
                // that actually point at the just-restored tx — NOT the
                // child's full input set. A child can have a surviving
                // co-parent Q that this restore never touched (Q kept its
                // `parents_in_pool` edge and its credit the whole time);
                // walking `child.inputs` wholesale would re-discover Q via
                // `by_output` and credit it a second time on every
                // apply/restore cycle.
                for child_id in pool.conflicts_for_inputs(&peeked.output_box_ids) {
                    if child_id == *tx_id {
                        continue;
                    }
                    pool.attach_parent(&child_id, tx_id);
                    if let Some(child) = pool.get(&child_id) {
                        let child_weight = child.weight;
                        let reconnected_inputs: Vec<Digest32> = child
                            .inputs
                            .iter()
                            .filter(|inp| peeked.output_box_ids.contains(inp))
                            .copied()
                            .collect();
                        pool.update_family(&reconnected_inputs, i128::from(child_weight), bounds);
                    }
                }

                outcomes.push(RestoreOutcome::Restored(*tx_id));
                while pool.len() > config.max_pool_size
                    || pool.total_bytes() > config.max_pool_bytes
                {
                    let Some(victim) = pool.lowest_tx_id() else {
                        break;
                    };
                    for e in pool.remove_with_descendants_debiting(
                        &victim,
                        config.max_family_depth,
                        bounds,
                    ) {
                        outcomes.push(RestoreOutcome::CapacityEvicted(e.tx_id));
                    }
                }
            }
            Err(PoolError::Duplicate(_))
            | Err(PoolError::OutputCollision(_))
            | Err(PoolError::InputCollision(_)) => {
                outcomes.push(RestoreOutcome::Conflict(*tx_id));
            }
        }
    }

    outcomes
}

/// All pool entries whose weak id (`tx_id[0..3] ++ witness_id[0..3]`,
/// Scala `ErgoTransaction.weakId`) equals `weak`. Never collapses to a
/// single match — a weak id is only 6 bytes, so distinct pooled txs can
/// legitimately collide (spec §7.5); every collision must be resolvable
/// through the full-id transaction request/response.
pub fn find_by_weak_id<'p>(pool: &'p OrderedPool, weak: &WeakId) -> Vec<&'p Entry> {
    // O(1) through the pool's weak-id index. The previous implementation
    // scanned and re-parsed every pooled transaction on every call, and
    // the node called it once per announced weak id — with the miner
    // publishing roughly one input block a second that was the dominant
    // per-frame cost of the whole subsystem.
    //
    // The index is built from each entry's own bytes at insert time, so
    // it answers exactly what the scan answered, including collisions
    // (a weak id is 6 bytes; distinct pooled txs legitimately collide,
    // spec §7.5) and including the skip-on-undecodable contract.
    pool.tx_ids_by_weak_id(weak)
        .iter()
        .filter_map(|id| pool.get(id))
        .collect()
}

#[cfg(test)]
mod tests;
