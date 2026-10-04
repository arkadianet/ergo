//! Private transaction admission and chain lifecycle, owned by the action loop.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use ergo_api::mining::{MiningApiError, PrivateTransactionOptions};
use ergo_mempool::admission::Validator;
use ergo_mempool::pool::Entry;
use ergo_mempool::types::TxSource;
use ergo_mining::handle::MiningHandle;
use ergo_mining::private_queue::{PrivateTransactionState, Reconciled};
use ergo_primitives::cost::{CostAccumulator, JitCost};
use ergo_primitives::digest::Digest32;
use ergo_state::HeaderSectionStore;
use ergo_validation::{TxValidationCtx, TxValidationRules};

use super::{tip_context::build_tip_context, NodeState};

pub(super) fn api_entry(
    entry: ergo_mining::private_queue::PrivateTransactionEntry,
) -> ergo_api::mining::PrivateTransactionEntry {
    let state = match entry.state {
        PrivateTransactionState::Queued => "queued",
        PrivateTransactionState::InCandidate => "in_candidate",
        PrivateTransactionState::Mined => "mined",
        PrivateTransactionState::Conflicted => "conflicted",
        PrivateTransactionState::Cancelled => "cancelled",
        PrivateTransactionState::Expired => "expired",
    };
    ergo_api::mining::PrivateTransactionEntry {
        tx_id: entry.tx_id,
        state: state.into(),
        reason: entry.reason,
        created_at_ms: entry.created_at_ms,
        expires_at_ms: entry.expires_at_ms,
        expires_at_height: entry.expires_at_height,
        priority: entry.priority,
        label: entry.label,
        input_ids: entry.input_ids,
        fee_nano_erg: entry.fee_nano_erg,
        size_bytes: entry.size_bytes,
        validation_cost: entry.validation_cost,
        mined_block_id: entry.mined_block_id,
        mined_height: entry.mined_height,
    }
}

/// Decline the queue's transactions on every public admission path. Called at
/// startup, whether or not mining is enabled. Cancelled and expired entries,
/// and confirmations deeper than the rollback window, are no longer this
/// miner's work, so they stay publicly admissible.
pub(super) fn register_queued(
    mempool: &mut ergo_mempool::Mempool,
    queue: &ergo_mining::private_queue::PrivateTransactionQueue,
) {
    for id in queue.guarded_ids() {
        mempool.register_private_transaction(Digest32::from_bytes(id));
    }
}

/// Let a transaction this node will no longer mine (cancelled, expired, or a
/// settled confirmation) through public admission again; the operator may now
/// broadcast it through this node.
pub(super) fn release_withdrawn(mempool: &mut ergo_mempool::Mempool, tx_ids: &[String]) {
    for id in tx_ids.iter().filter_map(|id| decode_tx_id(id)) {
        mempool.unregister_private_transaction(&id);
    }
}

fn decode_tx_id(tx_id: &str) -> Option<Digest32> {
    let raw = hex::decode(tx_id).ok()?;
    Some(Digest32::from_bytes(<[u8; 32]>::try_from(raw).ok()?))
}

pub(super) fn admit(
    state: &mut NodeState,
    handle: &MiningHandle,
    bytes: &[u8],
    options: PrivateTransactionOptions,
) -> Result<ergo_api::mining::PrivateTransactionEntry, MiningApiError> {
    if bytes.len() > state.mempool.config().max_tx_size_bytes {
        return Err(MiningApiError::BadRequest(
            "private transaction exceeds the configured transaction size limit".into(),
        ));
    }
    let queue = handle.private_queue();
    let validator = ergo_mempool::ErgoValidator;
    let peek = validator.peek_fee(bytes).map_err(|e| {
        MiningApiError::BadRequest(format!("private transaction decode failed: {e:?}"))
    })?;
    let id = hex::encode(peek.tx_id.as_bytes());
    // Resubmitting tracked work is idempotent; a cancelled or expired id is
    // validated again and queued as a fresh item.
    if let Some(existing) = queue.entry(&id) {
        if existing.state.is_pending() || existing.state == PrivateTransactionState::Mined {
            return Ok(api_entry(existing));
        }
    }
    // Staged orphans and held parents came through public admission and can
    // still be promoted and relayed, like a pooled transaction.
    if state.mempool.contains(&peek.tx_id) || state.mempool.is_staged(&peek.tx_id) {
        return Err(MiningApiError::BadRequest("transaction is already in the public mempool; private delivery cannot undo a broadcast".into()));
    }
    let mut owned = build_tip_context(state)
        .ok_or_else(|| MiningApiError::Unavailable("applied chain context is not ready".into()))?;
    if owned
        .best_header_height
        .saturating_sub(owned.best_full_block_height)
        > state.mempool.config().ibd_gate_block_lag
    {
        return Err(MiningApiError::Unavailable(
            "private admission waits for chain synchronization".into(),
        ));
    }
    let store = state
        .store
        .as_utxo()
        .ok_or_else(|| MiningApiError::Unavailable("private mining requires UTXO state".into()))?;
    owned.tx_context.miner_pubkey = match handle.resolve_reward_key(store) {
        ergo_state::wallet::RewardKeyResolution::Ready(pk) => pk,
        _ => {
            return Err(MiningApiError::Unavailable(
                "mining reward key is not ready".into(),
            ))
        }
    };
    let private_entries = queue.selection_entries();
    let reserved = queue.reserved_inputs();
    let structure = validator.peek_structure(bytes).map_err(|e| {
        MiningApiError::BadRequest(format!("private transaction structure failed: {e:?}"))
    })?;
    if structure
        .input_box_ids
        .iter()
        .any(|id| reserved.contains(id.as_bytes()))
    {
        return Err(MiningApiError::BadRequest(
            "an input is reserved by another private transaction".into(),
        ));
    }
    let mut outputs = state.mempool.pool_output_overlay();
    for entry in &private_entries {
        for (id, output) in entry.outputs.iter().zip(&entry.output_boxes) {
            outputs.insert(*id, output.clone());
        }
    }
    let input_view = ergo_mempool::overlay::PoolUtxoOverlay::new(store, &outputs);
    let cap = JitCost::from_block_cost(state.mempool.config().max_tx_cost).map_err(|_| {
        MiningApiError::Internal("configured transaction cost limit is invalid".into())
    })?;
    let mut cost = CostAccumulator::new(cap);
    let mut context = TxValidationCtx {
        ctx: &owned.tx_context,
        params: &owned.params,
        cost: &mut cost,
        last_headers: &owned.last_headers,
        rules: TxValidationRules {
            reemission: owned.reemission.as_ref(),
        },
    };
    // Normal canonical/structural/monetary/script/cost validation. Only the
    // public relay fee gate is omitted; no public pool mutation happens.
    let validated = validator
        .validate(bytes, &input_view, store, &mut context)
        .map_err(|e| {
            MiningApiError::BadRequest(format!("private transaction validation failed: {e:?}"))
        })?;
    let parents: Vec<_> = private_entries
        .iter()
        .filter(|entry| {
            validated
                .input_box_ids
                .iter()
                .any(|id| entry.outputs.contains(id))
        })
        .map(|entry| entry.tx_id)
        .collect();
    let entry = Entry::new(
        validated.tx_id,
        Arc::from(bytes),
        validated.input_box_ids,
        validated.output_box_ids,
        parents,
        validated.fee,
        0,
        validated.size_bytes,
        validated.consumed_cost,
        TxSource::Wallet,
    )
    .with_output_boxes(validated.outputs);
    let result = queue
        .admit_at_tip(
            &entry,
            ergo_mining::private_queue::PrivateTransactionOptions {
                expires_at_ms: options.expires_at_ms,
                expires_at_height: options.expires_at_height,
                priority: options.priority,
                label: options.label,
            },
            crate::snapshot::unix_now_ms(),
            owned.tip.height,
            Some(hex::encode(owned.tip.header_id.as_bytes())),
        )
        .map_err(MiningApiError::BadRequest)?;
    state.mempool.register_private_transaction(entry.tx_id);
    handle.invalidate_operator_generation();
    Ok(api_entry(result))
}

/// Reconcile applied history first, then apply deadlines, so a transaction
/// confirmed in its last eligible block is recorded as mined, not expired.
pub(super) fn run_lifecycle(state: &mut NodeState, handle: &MiningHandle) {
    match reconcile(state, handle) {
        Ok(outcome) => release_withdrawn(&mut state.mempool, &outcome.released),
        Err(error) => {
            tracing::warn!(%error, "private mining queue waits for confirmation history");
        }
    }
    if let Err(error) = expire(state, handle) {
        tracing::error!(%error, "private mining expiry failed; work remains withdrawn");
    }
}

/// Called before every solution request as well as on ordinary loop ticks.
/// Height deadlines are judged against the reconciled height, never the
/// applied tip, so a deadline cannot expire a transaction that a not yet
/// reconciled block confirmed. A time deadline racing such a block is
/// corrected when reconciliation finds the confirmation.
pub(super) fn expire(state: &mut NodeState, handle: &MiningHandle) -> Result<bool, String> {
    let now = crate::snapshot::unix_now_ms();
    let queue = handle.private_queue();
    if queue.list().is_empty() {
        return Ok(false);
    }
    let height = queue.observation_cursor().0;
    if !queue.list().iter().any(|entry| {
        matches!(
            entry.state,
            PrivateTransactionState::Queued
                | PrivateTransactionState::InCandidate
                | PrivateTransactionState::Conflicted
        ) && (entry.expires_at_ms.is_some_and(|d| d <= now)
            || entry.expires_at_height.is_some_and(|d| d <= height))
    }) {
        return Ok(false);
    }
    // Retire offered templates and in-flight build generations before inputs
    // can be released by a durable expiry commit.
    handle.invalidate_operator_generation();
    let expired = queue.expire(now, height)?;
    release_withdrawn(&mut state.mempool, &expired);
    Ok(!expired.is_empty())
}

/// Incrementally inspect applied history, including after an offline interval.
/// At most 32 blocks are decoded on an iteration. Confirmation classification
/// waits until catch-up has reached the applied tip.
pub(super) fn reconcile(state: &NodeState, handle: &MiningHandle) -> Result<Reconciled, String> {
    let queue = handle.private_queue();
    if queue.list().is_empty() {
        return Ok(Reconciled::default());
    }
    let reader = state.store.reader_handle();
    let Some((height, tip)) = reader.committed_tip().map_err(|e| e.to_string())? else {
        return Ok(Reconciled::default());
    };
    let mut rolled_back = BTreeSet::new();
    for entry in queue
        .list()
        .into_iter()
        .filter(|e| e.state == PrivateTransactionState::Mined)
    {
        if let Some((mined_height, mined_id)) =
            entry.mined_height.zip(entry.mined_block_id.as_deref())
        {
            let definitely_orphaned = mined_height > height
                || reader
                    .applied_header_id_at_height(mined_height)
                    .map_err(|e| e.to_string())?
                    .is_some_and(|id| hex::encode(id) != mined_id);
            if definitely_orphaned {
                rolled_back.insert(entry.tx_id);
            }
        }
    }
    if !rolled_back.is_empty() {
        handle.invalidate_operator_generation();
        queue.reopen_rolled_back(&rolled_back)?;
    }
    let (mut cursor, previous_tip) = queue.observation_cursor();
    let mut previous_id = previous_tip
        .and_then(|id| hex::decode(id).ok())
        .and_then(|id| <[u8; 32]>::try_from(id).ok());
    if previous_id.is_some()
        && reader
            .applied_header_id_at_height(cursor)
            .map_err(|e| e.to_string())?
            != previous_id
    {
        // Walk the old branch backwards to the applied common ancestor. Keep
        // bounded work; a deep rollback progresses over subsequent iterations.
        for _ in 0..32 {
            if cursor == 0
                || reader
                    .applied_header_id_at_height(cursor)
                    .map_err(|e| e.to_string())?
                    == previous_id
            {
                break;
            }
            let Some(id) = previous_id else {
                break;
            };
            let Some(bytes) = reader.get_header(&id).map_err(|e| e.to_string())? else {
                break;
            };
            let mut r = ergo_primitives::reader::VlqReader::new(&bytes);
            let header = ergo_ser::header::read_header(&mut r)
                .map_err(|e| format!("private queue ancestry decode: {e:?}"))?;
            previous_id = Some(*header.parent_id.as_bytes());
            cursor = cursor.saturating_sub(1);
        }
        if cursor > 0
            && reader
                .applied_header_id_at_height(cursor)
                .map_err(|e| e.to_string())?
                != previous_id
        {
            queue.set_observation_cursor(cursor, previous_id.map(hex::encode));
            return Ok(Reconciled::default());
        }
    }
    let mut applied = BTreeMap::new();
    let ids: BTreeSet<_> = queue.list().into_iter().map(|entry| entry.tx_id).collect();
    let db = state.store.db_arc();
    let mut scanned = cursor.min(height);
    let end = cursor.saturating_add(32).min(height);
    for h in cursor.saturating_add(1)..=end {
        match ergo_state::store::block_txs_for_wallet_at_height(&db, h).map_err(|e| e.to_string())? {
            Some((block_id, txs)) => {
                for tx in txs {
                    let id = hex::encode(tx.tx_id);
                    if ids.contains(&id) { applied.insert(id, (h, hex::encode(block_id))); }
                }
            }
            None => return Err("private queue confirmation history is unavailable; waiting for retained applied blocks".into()),
        }
        scanned = h;
    }
    let caught_up = scanned == height;
    let private_outputs: HashMap<_, _> = queue
        .selection_entries()
        .into_iter()
        .flat_map(|entry| entry.outputs.into_iter().zip(entry.output_boxes))
        .collect();
    let candidate_ids: BTreeSet<String> = handle
        .inspect_template(None, None)
        .map(|snapshot| {
            snapshot
                .template
                .candidate
                .transactions
                .iter()
                .filter_map(|tx| {
                    ergo_ser::transaction::transaction_id(tx)
                        .ok()
                        .map(|id| hex::encode(id.as_bytes()))
                })
                .collect()
        })
        .unwrap_or_default();
    let before = queue.reserved_inputs();
    let scanned_tip = if caught_up {
        Some(tip)
    } else {
        reader
            .applied_header_id_at_height(scanned)
            .map_err(|e| e.to_string())?
    };
    let outcome = queue.reconcile(
        scanned,
        scanned_tip.map(hex::encode).unwrap_or_default(),
        &applied,
        |h, id| {
            reader
                .applied_header_id_at_height(h)
                .ok()
                .flatten()
                .is_some_and(|raw| hex::encode(raw) == id)
        },
        |id| {
            !caught_up
                || reader.lookup_box(id).ok().flatten().is_some()
                || private_outputs.contains_key(&Digest32::from_bytes(*id))
        },
        &candidate_ids,
        // Mined entries keep their signed bytes while this node could still
        // roll their block back.
        state
            .store
            .max_rollback_depth()
            .unwrap_or(ergo_state::store::ROLLBACK_WINDOW),
    )?;
    if before != queue.reserved_inputs() {
        handle.invalidate_operator_generation();
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests;
