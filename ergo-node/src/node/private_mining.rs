//! Private transaction admission and chain lifecycle, owned by the action loop.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ergo_api::mining::{MiningApiError, PrivateTransactionOptions};
use ergo_mempool::admission::Validator;
use ergo_mempool::pool::Entry;
use ergo_mempool::types::TxSource;
use ergo_mining::handle::MiningHandle;
use ergo_mining::private_queue::{PrivateQueueError, PrivateTransactionState, Reconciled};
use ergo_primitives::cost::{CostAccumulator, JitCost};
use ergo_primitives::digest::Digest32;
use ergo_state::{ChainStateRead, HeaderSectionStore};
use ergo_validation::{TxValidationCtx, TxValidationRules};

use super::{tip_context::build_tip_context, NodeState};

/// Event-driven lifecycle of the private queue, owned by the action loop.
/// Applied history is reconciled when the applied tip changes (or while a
/// bounded catch-up is unfinished) and deadlines are applied when one is due,
/// so an unchanged chain costs the loop nothing. Candidate membership is not
/// tracked here; it is derived from the served template when listing.
#[derive(Debug, Default)]
pub(crate) struct PrivateLifecycle {
    /// Applied tip the queue was last reconciled at.
    reconciled_tip: Option<(u32, [u8; 32])>,
    /// The last pass stopped short of that tip: a bounded batch, or a
    /// committed tip still trailing the applied one.
    catching_up: bool,
    /// Elapsed work whose templates are already withdrawn while its durable
    /// expiry is still pending, so a failing write withdraws nothing twice.
    /// Builds never select it: selection filters elapsed deadlines itself.
    expiry_withdrawn: BTreeSet<String>,
    /// No durable expiry is retried before this instant.
    expiry_retry_at: Option<Instant>,
    last_expiry_error: Option<Instant>,
    last_history_warning: Option<Instant>,
    /// Reconciliation passes run, for tests of the event triggers.
    #[cfg(test)]
    reconcile_passes: usize,
}

/// Pause between attempts to make an elapsed deadline durable.
const EXPIRY_RETRY: Duration = Duration::from_secs(10);
/// A repeating lifecycle error or warning is logged at most this often.
const LOG_INTERVAL: Duration = Duration::from_secs(60);

/// Whether a repeating condition may log now; at most once per `LOG_INTERVAL`.
fn log_allowed(last: &mut Option<Instant>) -> bool {
    let now = Instant::now();
    if last.is_some_and(|at| now.duration_since(at) < LOG_INTERVAL) {
        return false;
    }
    *last = Some(now);
    true
}

pub(super) fn api_entry(
    entry: ergo_mining::private_queue::PrivateTransactionEntry,
    in_candidate: bool,
) -> ergo_api::mining::PrivateTransactionEntry {
    let state = match entry.state {
        PrivateTransactionState::Queued | PrivateTransactionState::InCandidate if in_candidate => {
            "in_candidate"
        }
        PrivateTransactionState::Queued | PrivateTransactionState::InCandidate => "queued",
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

/// What the template currently served for the applied tip says about
/// private work: the ids it includes, and why the build left others out.
#[derive(Default)]
struct ServedTemplate {
    included: HashSet<String>,
    excluded: BTreeMap<String, String>,
}

impl ServedTemplate {
    fn read(handle: &MiningHandle) -> Self {
        let Some(snapshot) = handle.inspect_template(None, None) else {
            return Self::default();
        };
        let template = &snapshot.template;
        Self {
            included: template
                .private_transaction_ids()
                .iter()
                .map(|id| hex::encode(id.as_bytes()))
                .collect(),
            excluded: template
                .candidate
                .observation
                .excluded
                .iter()
                .map(|excluded| {
                    (
                        hex::encode(excluded.tx_id.as_bytes()),
                        excluded.reason.clone(),
                    )
                })
                .collect(),
        }
    }

    /// `entry` with its membership in this template. A queued transaction
    /// the build left out carries the build's reason, e.g. a data input that
    /// changed or a script whose height bound passed: it is never included
    /// until that changes.
    fn view(
        &self,
        mut entry: ergo_mining::private_queue::PrivateTransactionEntry,
    ) -> ergo_api::mining::PrivateTransactionEntry {
        let active = entry.state.is_active();
        let in_candidate = active && self.included.contains(&entry.tx_id);
        if active && !in_candidate {
            if let Some(reason) = self.excluded.get(&entry.tx_id) {
                entry.reason = Some(format!("not includable: {reason}"));
            }
        }
        api_entry(entry, in_candidate)
    }
}

/// The queue as the operator sees it, with candidate membership and build
/// exclusions read from the served template at request time.
pub(super) fn list(handle: &MiningHandle) -> Vec<ergo_api::mining::PrivateTransactionEntry> {
    let served = ServedTemplate::read(handle);
    handle
        .private_queue()
        .list()
        .into_iter()
        .map(|entry| served.view(entry))
        .collect()
}

/// One entry as [`list`] would show it.
pub(super) fn view(
    handle: &MiningHandle,
    entry: ergo_mining::private_queue::PrivateTransactionEntry,
) -> ergo_api::mining::PrivateTransactionEntry {
    ServedTemplate::read(handle).view(entry)
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

/// A rejected request is the caller's error (400); a failed durable write is
/// the node's (500).
fn queue_error(error: PrivateQueueError) -> MiningApiError {
    match error {
        PrivateQueueError::Rejected(reason) => MiningApiError::BadRequest(reason),
        PrivateQueueError::Storage(reason) => MiningApiError::Internal(reason),
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
            return Ok(view(handle, existing));
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
        .map_err(queue_error)?;
    state.mempool.register_private_transaction(entry.tx_id);
    // Nothing served becomes wrong by adding work: current templates keep
    // serving and accepting solutions, and the queue revision change asks the
    // action loop for a refresh that includes it.
    Ok(view(handle, result))
}

/// Run after every action-loop arm. Reconciles applied history first, then
/// applies deadlines, so a transaction confirmed in its last eligible block is
/// recorded as mined, not expired. Work happens only when the applied tip
/// changed, a bounded catch-up is unfinished, or a deadline is due.
pub(super) fn run_lifecycle(state: &mut NodeState, handle: &MiningHandle) {
    let queue = handle.private_queue();
    if queue.is_empty() {
        return;
    }
    let applied = state.store.chain_state_meta();
    let tip = (applied.best_full_block_height, applied.best_full_block_id);
    if state.private_mining.reconciled_tip != Some(tip) || state.private_mining.catching_up {
        state.private_mining.reconciled_tip = Some(tip);
        #[cfg(test)]
        {
            state.private_mining.reconcile_passes += 1;
        }
        match reconcile(state, handle) {
            Ok(outcome) => {
                release_withdrawn(&mut state.mempool, &outcome.released);
                state.private_mining.catching_up =
                    queue.observation_cursor() != (tip.0, Some(hex::encode(tip.1)));
            }
            Err(error) => {
                // Retried when the applied tip next changes.
                state.private_mining.catching_up = false;
                if log_allowed(&mut state.private_mining.last_history_warning) {
                    tracing::warn!(%error, "private mining queue waits for confirmation history");
                }
            }
        }
    }
    expire(state, handle);
}

/// Called before every mining request as well as after loop arms; constant
/// time unless a deadline is due. Height deadlines are judged against the
/// reconciled height, never the applied tip, so a deadline cannot expire a
/// transaction that a not yet reconciled block confirmed. A time deadline
/// racing such a block is corrected when reconciliation finds the
/// confirmation.
///
/// A failing write never stops mining: elapsed work's templates are
/// withdrawn once, its inputs stay reserved, every other template keeps
/// serving and accepting solutions, and the durable expiry is retried every
/// `EXPIRY_RETRY` with a rate-limited error.
pub(super) fn expire(state: &mut NodeState, handle: &MiningHandle) {
    let now = crate::snapshot::unix_now_ms();
    let queue = handle.private_queue();
    let height = queue.observed_height();
    let lifecycle = &mut state.private_mining;
    if !queue.deadline_due(now, height) {
        lifecycle.expiry_withdrawn.clear();
        return;
    }
    // Before a durable expiry can release inputs, withdraw the templates that
    // include newly elapsed work, and retire in-flight builds only when it was
    // selectable; every other template keeps serving and accepting solutions.
    let due = queue.due(now, height);
    lifecycle
        .expiry_withdrawn
        .retain(|id| due.iter().any(|(due_id, _)| due_id == id));
    let fresh: Vec<_> = due
        .iter()
        .filter(|(id, _)| !lifecycle.expiry_withdrawn.contains(id))
        .collect();
    if !fresh.is_empty() {
        withdraw(
            handle,
            fresh.iter().map(|(id, _)| id.as_str()),
            fresh.iter().any(|(_, state)| state.is_active()),
        );
        lifecycle
            .expiry_withdrawn
            .extend(fresh.iter().map(|(id, _)| id.clone()));
    }
    if lifecycle
        .expiry_retry_at
        .is_some_and(|at| Instant::now() < at)
    {
        return;
    }
    match queue.expire(now, height) {
        Ok(expired) => {
            lifecycle.expiry_withdrawn.clear();
            lifecycle.expiry_retry_at = None;
            release_withdrawn(&mut state.mempool, &expired);
        }
        Err(error) => {
            lifecycle.expiry_retry_at = Some(Instant::now() + EXPIRY_RETRY);
            if log_allowed(&mut lifecycle.last_expiry_error) {
                tracing::error!(
                    %error,
                    pending = due.len(),
                    "private mining expiry is not durable yet; elapsed work stays withdrawn and \
                     its inputs reserved, retrying"
                );
            }
        }
    }
}

/// Withdraw pending work. The target is checked before any template is
/// touched; repeating a cancellation is idempotent.
pub(super) fn cancel(
    state: &mut NodeState,
    handle: &MiningHandle,
    tx_id: &str,
) -> Result<ergo_api::mining::PrivateTransactionEntry, MiningApiError> {
    let queue = handle.private_queue();
    let entry = queue
        .entry(tx_id)
        .ok_or_else(|| MiningApiError::BadRequest("private transaction not found".into()))?;
    if entry.state == PrivateTransactionState::Mined {
        return Err(MiningApiError::BadRequest(
            "a confirmed transaction cannot be cancelled".into(),
        ));
    }
    if !entry.state.is_pending() {
        return Ok(view(handle, entry));
    }
    // Only templates that include it stop serving, before its inputs are
    // released; in-flight builds retire only if they could have selected it.
    withdraw(handle, std::iter::once(tx_id), entry.state.is_active());
    let cancelled = queue.cancel(tx_id).map_err(queue_error)?;
    release_withdrawn(&mut state.mempool, std::slice::from_ref(&cancelled.tx_id));
    Ok(view(handle, cancelled))
}

fn withdraw<'a>(handle: &MiningHandle, tx_ids: impl Iterator<Item = &'a str>, retire_builds: bool) {
    let ids: HashSet<Digest32> = tx_ids.filter_map(decode_tx_id).collect();
    if !ids.is_empty() {
        handle.withdraw_private_transactions(&ids, retire_builds);
    }
}

/// Incrementally inspect applied history, including after an offline interval.
/// At most 32 blocks are decoded on a call. Recorded confirmations are checked
/// against the applied chain only when the observed branch left it, and input
/// availability only once catch-up has reached the committed tip.
pub(super) fn reconcile(state: &NodeState, handle: &MiningHandle) -> Result<Reconciled, String> {
    let queue = handle.private_queue();
    let reader = state.store.reader_handle();
    let Some((height, tip)) = reader.committed_tip().map_err(|e| e.to_string())? else {
        return Ok(Reconciled::default());
    };
    let (mut cursor, previous_tip) = queue.observation_cursor();
    let mut previous_id = previous_tip.as_deref().and_then(decode_hash);
    if cursor == height && previous_id == Some(tip) {
        return Ok(Reconciled::default());
    }
    if previous_id.is_some()
        && reader
            .applied_header_id_at_height(cursor)
            .map_err(|e| e.to_string())?
            != previous_id
    {
        // The observed branch left the applied chain. Reopen confirmations in
        // blocks that are no longer applied before bounded ancestry work.
        let mut orphaned = BTreeSet::new();
        for (tx_id, mined_height, mined_id) in queue.confirmations() {
            let definitely_orphaned = mined_height > height
                || reader
                    .applied_header_id_at_height(mined_height)
                    .map_err(|e| e.to_string())?
                    .is_some_and(|id| hex::encode(id) != mined_id);
            if definitely_orphaned {
                orphaned.insert(tx_id);
            }
        }
        queue.reopen_rolled_back(&orphaned)?;
        // Walk the old branch backwards to the applied common ancestor. Keep
        // bounded work; a deep rollback progresses over subsequent passes.
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
    let ids = queue.record_ids();
    let db = state.store.db_arc();
    let mut scanned = cursor.min(height);
    let end = cursor.saturating_add(32).min(height);
    for h in cursor.saturating_add(1)..=end {
        match ergo_state::store::block_txs_for_wallet_at_height(&db, h).map_err(|e| e.to_string())? {
            Some((block_id, txs)) => {
                for tx in txs.iter().filter(|tx| ids.contains(&tx.tx_id)) {
                    applied.insert(hex::encode(tx.tx_id), (h, hex::encode(block_id)));
                }
            }
            None => return Err("private queue confirmation history is unavailable; waiting for retained applied blocks".into()),
        }
        scanned = h;
    }
    let caught_up = scanned == height;
    let scanned_tip = if caught_up {
        Some(tip)
    } else {
        reader
            .applied_header_id_at_height(scanned)
            .map_err(|e| e.to_string())?
    };
    queue.reconcile(
        scanned,
        scanned_tip.map(hex::encode).unwrap_or_default(),
        &applied,
        caught_up,
        // A parent still in the public mempool is spendable: candidate
        // assembly selects it ahead of the private child.
        |id| {
            reader.lookup_box(id).ok().flatten().is_some()
                || state.mempool.creates_output(&Digest32::from_bytes(*id))
        },
        // Mined entries keep their signed bytes while this node could still
        // roll their block back.
        state
            .store
            .max_rollback_depth()
            .unwrap_or(ergo_state::store::ROLLBACK_WINDOW),
    )
}

fn decode_hash(hex_id: &str) -> Option<[u8; 32]> {
    <[u8; 32]>::try_from(hex::decode(hex_id).ok()?).ok()
}

#[cfg(test)]
mod tests;
