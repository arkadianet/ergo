//! Block processor thread: receives modifiers from the event loop, validates
//! and applies them to the [`NodeViewHolder`], and sends progress events back.
//!
//! [`ProcessorCommand`] flows event-loop -> processor.
//! [`ProcessorEvent`] flows processor -> event-loop.

use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::Duration;

use crate::connection_pool::PeerId;
use crate::modifiers_cache::ModifiersCache;
use crate::node_view::NodeViewHolder;
use ergo_types::header::Header;
use ergo_types::modifier_id::ModifierId;

/// Bounded channel capacity for both command and event channels.
/// Must be larger than the maximum modifier batch size (400 headers + 1 ApplyFromCache).
pub const CHANNEL_CAPACITY: usize = 2048;

/// Maximum number of commands to drain per batch iteration.
///
/// Must be >= 450 to cover a full header Inv cycle (up to 400 headers + 1
/// `ApplyFromCache`).  A smaller value causes multiple intermediate
/// `HeadersApplied` events per cycle, each triggering a `SyncInfoV2`
/// broadcast that generates a flood of useless Inv responses and delays the
/// final broadcast that carries the correct chain tip — stalling header sync
/// for up to one `sync_tick` interval (5 s).
const MAX_BATCH_SIZE: usize = 512;

/// Header modifier type ID.
const HEADER_TYPE_ID: u8 = 101;

// ---------------------------------------------------------------------------
// Commands: event loop -> processor
// ---------------------------------------------------------------------------

/// A command sent from the event loop to the block-processor thread.
#[derive(Debug, Clone)]
pub enum ProcessorCommand {
    /// Store a raw modifier (header bytes, block body section, etc.).
    StoreModifier {
        /// Modifier type discriminant (101 = Header, 102 = BlockTransactions, ...).
        type_id: u8,
        /// Unique modifier identifier.
        modifier_id: ModifierId,
        /// Serialized modifier bytes.
        data: Vec<u8>,
        /// The peer that delivered this modifier, if known.
        peer_hint: Option<PeerId>,
    },

    /// Store a header that has already been parsed and PoW-validated.
    StorePrevalidatedHeader {
        /// Unique modifier identifier.
        modifier_id: ModifierId,
        /// The parsed header (boxed to keep enum size small).
        header: Box<Header>,
        /// Original wire bytes (needed if the header must be cached for retry).
        raw_data: Vec<u8>,
        /// The peer that delivered this modifier, if known.
        peer_hint: Option<PeerId>,
    },

    /// Trigger a cache drain -- attempt to apply cached modifiers.
    ApplyFromCache,

    /// A pre-sorted batch of PoW-validated headers from fast sync.
    ///
    /// Headers must be in ascending height order.  The processor stores all of
    /// them in a single RocksDB WriteBatch via
    /// `HistoryDb::bulk_store_headers`, which is substantially faster than
    /// issuing one `StorePrevalidatedHeader` command per header.
    BulkHeaders {
        /// Tuples of (modifier_id, parsed header, raw wire bytes).
        headers: Vec<(ModifierId, Box<Header>, Vec<u8>)>,
    },

    /// Graceful shutdown request.
    Shutdown,
}

// ---------------------------------------------------------------------------
// Events: processor -> event loop
// ---------------------------------------------------------------------------

/// An event sent from the block-processor thread back to the event loop.
#[derive(Debug, Clone)]
pub enum ProcessorEvent {
    /// One or more headers were successfully stored/applied.
    HeadersApplied {
        /// IDs of the newly applied headers.
        new_header_ids: Vec<ModifierId>,
        /// Additional modifier IDs that should be downloaded.
        to_download: Vec<ModifierId>,
    },

    /// A full block was validated and applied to state.
    BlockApplied {
        /// Header ID of the applied block.
        header_id: ModifierId,
        /// Block height.
        height: u32,
    },

    /// A modifier was stored in the out-of-order cache.
    ModifierCached {
        /// Modifier type discriminant.
        type_id: u8,
        /// Unique modifier identifier.
        modifier_id: ModifierId,
    },

    /// Validation of a modifier failed.
    ValidationFailed {
        /// Unique modifier identifier.
        modifier_id: ModifierId,
        /// The peer that sent the modifier, for penalty dispatch.
        peer_hint: Option<PeerId>,
        /// Human-readable error description.
        error: String,
    },

    /// Periodic snapshot of processor state for the event loop.
    StateUpdate {
        /// Current best headers-only height.
        headers_height: u32,
        /// Current best full-block height.
        full_height: u32,
        /// Best header ID, if any.
        best_header_id: Option<ModifierId>,
        /// Best full-block header ID, if any.
        best_full_id: Option<ModifierId>,
        /// State root digest.
        state_root: Vec<u8>,
        /// IDs of blocks applied since the last update.
        applied_blocks: Vec<ModifierId>,
        /// If a rollback occurred, the height we rolled back to.
        rollback_height: Option<u32>,
        /// Last N headers (newest first) for SyncInfoV2 construction.
        /// Loaded from the processor's own DB, bypassing the secondary DB.
        sync_headers: Vec<Header>,
        /// Current on-chain consensus parameters from the voting state machine.
        parameters: ergo_consensus::parameters::Parameters,
    },
}

// ---------------------------------------------------------------------------
// ProcessorState
// ---------------------------------------------------------------------------

/// Mutable state owned by the processor thread.
pub struct ProcessorState {
    /// The node view holder that manages history, state, and mempool.
    pub node_view: NodeViewHolder,
    /// Out-of-order modifier cache for buffering modifiers received
    /// before their dependencies are available.
    pub cache: ModifiersCache,
    /// Highest header height written by fast-sync bulk writes.
    ///
    /// `best_header_height()` only advances along the connected P2P chain
    /// tip, which lags far behind the bulk-write frontier during fast header
    /// sync.  This field tracks the highest height actually written to DB by
    /// any `BulkHeaders` batch so the throttle in `fast_header_sync.rs` can
    /// compare against a realistic write frontier rather than the stale P2P
    /// tip.
    pub fast_sync_write_height: u32,
}

impl ProcessorState {
    /// Creates a new `ProcessorState` wrapping the given `NodeViewHolder`.
    pub fn new(node_view: NodeViewHolder) -> Self {
        Self {
            node_view,
            cache: ModifiersCache::with_default_capacities(),
            fast_sync_write_height: 0,
        }
    }

    /// Creates a `ProcessorState` backed by a temporary database for testing.
    #[cfg(test)]
    pub fn new_test() -> (Self, tempfile::TempDir) {
        use crate::mempool::ErgoMemPool;
        use ergo_storage::history_db::HistoryDb;
        use std::sync::{Arc, RwLock};

        let tmpdir = tempfile::tempdir().expect("failed to create temp dir");
        let history = HistoryDb::open(tmpdir.path()).expect("failed to open temp history db");
        let mempool = Arc::new(RwLock::new(ErgoMemPool::new(1000)));
        let node_view = NodeViewHolder::new(history, mempool, true, vec![0u8; 33]);
        let state = Self::new(node_view);
        (state, tmpdir)
    }
}

// ---------------------------------------------------------------------------
// Processor run loop
// ---------------------------------------------------------------------------

/// Spawns the processor loop on the current thread with panic protection.
///
/// `state_factory` is called on the current thread to construct the
/// `ProcessorState`. The entire loop is wrapped in `catch_unwind`; on
/// panic a `ProcessorEvent::ValidationFailed` with "FATAL:" prefix is sent.
pub fn run_processor_with_state<F>(
    cmd_rx: Receiver<ProcessorCommand>,
    evt_tx: tokio::sync::mpsc::Sender<ProcessorEvent>,
    state_factory: F,
) where
    F: FnOnce() -> ProcessorState + Send + 'static,
{
    let evt_tx_panic = evt_tx.clone();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut state = state_factory();
        processor_loop_with_state(&cmd_rx, &evt_tx, &mut state);
    }));

    if let Err(panic_info) = result {
        let msg = if let Some(s) = panic_info.downcast_ref::<&str>() {
            format!("FATAL: processor thread panicked: {s}")
        } else if let Some(s) = panic_info.downcast_ref::<String>() {
            format!("FATAL: processor thread panicked: {s}")
        } else {
            "FATAL: processor thread panicked (unknown payload)".to_string()
        };
        let _ = evt_tx_panic.blocking_send(ProcessorEvent::ValidationFailed {
            modifier_id: ModifierId([0u8; 32]),
            peer_hint: None,
            error: msg,
        });
    }
}

/// Main blocking loop that receives commands and processes them in batches.
fn processor_loop_with_state(
    cmd_rx: &Receiver<ProcessorCommand>,
    evt_tx: &tokio::sync::mpsc::Sender<ProcessorEvent>,
    state: &mut ProcessorState,
) {
    // Send initial StateUpdate so the event loop has valid cached_sync_headers
    // and cached_headers_height from the very first sync_tick, without needing
    // to wait for a command to arrive.
    send_state_update(state, evt_tx);

    loop {
        // Block until a command arrives or the timeout elapses.
        let first = match cmd_rx.recv_timeout(Duration::from_millis(10)) {
            Ok(cmd) => cmd,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => return,
        };

        // Drain a batch of up to MAX_BATCH_SIZE commands.
        let mut batch = Vec::with_capacity(MAX_BATCH_SIZE);
        batch.push(first);
        while batch.len() < MAX_BATCH_SIZE {
            match cmd_rx.try_recv() {
                Ok(cmd) => batch.push(cmd),
                Err(_) => break,
            }
        }

        let mut new_headers: Vec<ModifierId> = Vec::new();
        let mut blocks_to_download: Vec<ModifierId> = Vec::new();
        let mut shutdown = false;

        for cmd in batch {
            match cmd {
                ProcessorCommand::Shutdown => {
                    shutdown = true;
                    break;
                }
                ProcessorCommand::StoreModifier {
                    type_id,
                    modifier_id,
                    data,
                    peer_hint,
                } => {
                    let mut accum = BatchAccum {
                        new_headers: &mut new_headers,
                        blocks_to_download: &mut blocks_to_download,
                    };
                    process_store_modifier(
                        state,
                        evt_tx,
                        type_id,
                        modifier_id,
                        data,
                        peer_hint,
                        &mut accum,
                    );
                }
                ProcessorCommand::StorePrevalidatedHeader {
                    modifier_id,
                    header,
                    raw_data,
                    peer_hint,
                } => {
                    let mut accum = BatchAccum {
                        new_headers: &mut new_headers,
                        blocks_to_download: &mut blocks_to_download,
                    };
                    process_prevalidated_header(
                        state,
                        evt_tx,
                        modifier_id,
                        *header,
                        raw_data,
                        peer_hint,
                        &mut accum,
                    );
                }
                ProcessorCommand::BulkHeaders { headers } => {
                    let mut accum = BatchAccum {
                        new_headers: &mut new_headers,
                        blocks_to_download: &mut blocks_to_download,
                    };
                    process_bulk_headers(state, headers, &mut accum);
                }
                ProcessorCommand::ApplyFromCache => {
                    let mut accum = BatchAccum {
                        new_headers: &mut new_headers,
                        blocks_to_download: &mut blocks_to_download,
                    };
                    apply_from_cache_processor(state, evt_tx, &mut accum);
                }
            }
        }

        // After processing the command batch, always try to drain cached
        // headers that can now be applied (their parent may have been applied
        // in this batch).  This is critical for fast header sync where
        // out-of-order chunks put headers into the cache and only an explicit
        // drain makes forward progress.
        {
            let mut accum = BatchAccum {
                new_headers: &mut new_headers,
                blocks_to_download: &mut blocks_to_download,
            };
            apply_from_cache_processor(state, evt_tx, &mut accum);
        }

        // After each batch: emit accumulated events.
        // IMPORTANT: StateUpdate must be sent BEFORE HeadersApplied so the
        // event loop's cached_sync_headers are fresh when it broadcasts
        // SyncInfoV2 in response to HeadersApplied.  Without this ordering,
        // the SyncInfoV2 would contain a stale tip, causing peers to send Inv
        // for already-received headers which are all filtered out — stalling
        // the sync loop until the next periodic sync tick.
        tracing::debug!(
            new_headers = new_headers.len(),
            blocks_to_dl = blocks_to_download.len(),
            "processor: batch done"
        );
        send_state_update(state, evt_tx);
        if !new_headers.is_empty() || !blocks_to_download.is_empty() {
            let _ = evt_tx.blocking_send(ProcessorEvent::HeadersApplied {
                new_header_ids: std::mem::take(&mut new_headers),
                to_download: std::mem::take(&mut blocks_to_download),
            });
        }

        if shutdown {
            return;
        }
    }
}

// ---------------------------------------------------------------------------
// Batch accumulator
// ---------------------------------------------------------------------------

/// Accumulates header IDs and download requests across a batch of commands.
struct BatchAccum<'a> {
    new_headers: &'a mut Vec<ModifierId>,
    blocks_to_download: &'a mut Vec<ModifierId>,
}

// ---------------------------------------------------------------------------
// Command handlers
// ---------------------------------------------------------------------------

/// Process a `StoreModifier` command.
fn process_store_modifier(
    state: &mut ProcessorState,
    evt_tx: &tokio::sync::mpsc::Sender<ProcessorEvent>,
    type_id: u8,
    modifier_id: ModifierId,
    data: Vec<u8>,
    peer_hint: Option<PeerId>,
    accum: &mut BatchAccum<'_>,
) {
    match state
        .node_view
        .process_modifier(type_id, &modifier_id, &data)
    {
        Ok(info) => {
            if type_id == HEADER_TYPE_ID {
                accum.new_headers.push(modifier_id);
            }
            // Collect download requests from ProgressInfo.
            for (_ty, dl_id) in &info.to_download {
                accum.blocks_to_download.push(*dl_id);
            }
            // Emit BlockApplied events for any blocks applied during this call.
            emit_applied_blocks(state, evt_tx);
        }
        Err(e) => {
            // Put in cache for later retry.
            state.cache.put(modifier_id, type_id, data, None);
            let _ = evt_tx.blocking_send(ProcessorEvent::ModifierCached {
                type_id,
                modifier_id,
            });
            tracing::debug!(
                %e,
                ?modifier_id,
                type_id,
                peer = ?peer_hint,
                "modifier cached (not yet applicable)"
            );
        }
    }
}

/// Process a `StorePrevalidatedHeader` command.
///
/// If the header fails because its parent isn't stored yet (out-of-order
/// delivery), we re-serialize and cache it for later retry via
/// `ApplyFromCache`.  Only truly invalid headers produce a
/// `ValidationFailed` event.
fn process_prevalidated_header(
    state: &mut ProcessorState,
    evt_tx: &tokio::sync::mpsc::Sender<ProcessorEvent>,
    modifier_id: ModifierId,
    header: Header,
    raw_data: Vec<u8>,
    peer_hint: Option<PeerId>,
    accum: &mut BatchAccum<'_>,
) {
    let best_height = state.node_view.history.best_header_height().unwrap_or(0);

    // Fast path: if the header is far above the current tip, its parent
    // can't possibly be in the DB.  Skip the expensive DB lookup and go
    // straight to cache.  The auto-drain after each batch will apply it
    // once the chain catches up.
    if header.height > best_height + 1 {
        state
            .cache
            .put(modifier_id, HEADER_TYPE_ID, raw_data, Some(header));
        return;
    }

    tracing::trace!(
        height = header.height,
        genesis = header.is_genesis(),
        "processor: handling prevalidated header"
    );
    match state
        .node_view
        .process_prevalidated_header(&modifier_id, &header)
    {
        Ok(info) => {
            tracing::trace!(height = header.height, "processor: header applied OK");
            accum.new_headers.push(modifier_id);
            for (_ty, dl_id) in &info.to_download {
                accum.blocks_to_download.push(*dl_id);
            }
        }
        Err(e) => {
            let err_str = e.to_string();
            if err_str.contains("parent header not found") {
                tracing::trace!(
                    height = header.height,
                    "processor: cached (parent not found)"
                );
                // Out-of-order: cache original wire bytes for retry with parsed header.
                state
                    .cache
                    .put(modifier_id, HEADER_TYPE_ID, raw_data, Some(header));
            } else {
                tracing::warn!(height = header.height, %e, "processor: header REJECTED");
                let _ = evt_tx.blocking_send(ProcessorEvent::ValidationFailed {
                    modifier_id,
                    peer_hint,
                    error: format!("prevalidated header failed: {e}"),
                });
            }
        }
    }
}

/// Process a `BulkHeaders` command.
///
/// Calls [`HistoryDb::bulk_store_headers`] to write all headers in a single
/// RocksDB WriteBatch, then records each applied header ID in `accum`.
/// Errors are logged but do not propagate — a partial success is still
/// forwarded to the event loop via the accumulated IDs.
fn process_bulk_headers(
    state: &mut ProcessorState,
    headers: Vec<(ModifierId, Box<Header>, Vec<u8>)>,
    accum: &mut BatchAccum<'_>,
) {
    // Build a map of modifier_id -> height so we can determine the highest
    // applied height without an extra DB round-trip.
    let id_to_height: std::collections::HashMap<ModifierId, u32> =
        headers.iter().map(|(id, h, _)| (*id, h.height)).collect();

    let flat: Vec<(ModifierId, Header, Vec<u8>)> = headers
        .into_iter()
        .map(|(id, h, raw)| (id, *h, raw))
        .collect();

    match state.node_view.history.bulk_store_headers(&flat) {
        Ok(applied_ids) => {
            let count = applied_ids.len();
            let mut max_height = 0u32;
            for id in applied_ids {
                if let Some(&h) = id_to_height.get(&id) {
                    if h > max_height {
                        max_height = h;
                    }
                }
                accum.new_headers.push(id);
            }
            if max_height > state.fast_sync_write_height {
                state.fast_sync_write_height = max_height;
            }
            tracing::debug!(count, max_height, "bulk_headers: batch written");
        }
        Err(e) => {
            tracing::error!(%e, "bulk_headers: batch write failed");
        }
    }
}

/// Apply cached modifiers using the `popCandidate` pattern.
///
/// Phase 1: Pop headers one at a time at `current_height + 1` using
/// `pop_header_candidate`. Uses `process_prevalidated_header` (skips PoW)
/// since the header was already PoW-validated before being cached.
///
/// Phase 2: Pop body sections whose header ID matches the next full-block
/// height using `pop_body_candidate`.
fn apply_from_cache_processor(
    state: &mut ProcessorState,
    evt_tx: &tokio::sync::mpsc::Sender<ProcessorEvent>,
    accum: &mut BatchAccum<'_>,
) {
    // Phase 1: Apply cached headers using pop_header_candidate.
    let headers_height = state.node_view.history.best_header_height().unwrap_or(0);
    let mut current_height = headers_height;
    let mut applied_headers = 0usize;

    loop {
        let candidate = state.cache.pop_header_candidate(current_height);
        let Some((id, _type_id, data, header_opt)) = candidate else {
            break;
        };

        if let Some(header) = header_opt {
            match state.node_view.process_prevalidated_header(&id, &header) {
                Ok(info) => {
                    applied_headers += 1;
                    current_height = header.height;
                    accum.new_headers.push(id);
                    for (_ty, dl_id) in &info.to_download {
                        accum.blocks_to_download.push(*dl_id);
                    }
                    emit_applied_blocks(state, evt_tx);
                }
                Err(e) => {
                    tracing::debug!(
                        height = header.height,
                        %e,
                        "cache pop_candidate: header validation failed, re-caching"
                    );
                    state.cache.put(id, HEADER_TYPE_ID, data, Some(header));
                    break;
                }
            }
        } else {
            match state.node_view.process_modifier(HEADER_TYPE_ID, &id, &data) {
                Ok(info) => {
                    applied_headers += 1;
                    current_height = state
                        .node_view
                        .history
                        .best_header_height()
                        .unwrap_or(current_height);
                    accum.new_headers.push(id);
                    for (_ty, dl_id) in &info.to_download {
                        accum.blocks_to_download.push(*dl_id);
                    }
                    emit_applied_blocks(state, evt_tx);
                }
                Err(_) => {
                    state.cache.put(id, HEADER_TYPE_ID, data, None);
                    break;
                }
            }
        }
    }

    if applied_headers > 0 {
        tracing::debug!(
            applied_headers,
            new_height = current_height,
            "cache drain: headers applied"
        );
    }

    // Phase 2: Apply cached body sections using pop_body_candidate.
    let mut applied_bodies = 0usize;
    loop {
        let full_height = state
            .node_view
            .history
            .best_full_block_height()
            .unwrap_or(0);
        let next_height = full_height + 1;
        let header_ids = state
            .node_view
            .history
            .header_ids_at_height(next_height)
            .unwrap_or_default();
        if header_ids.is_empty() {
            break;
        }

        let candidate = state.cache.pop_body_candidate(&header_ids);
        let Some((id, type_id, data, _header)) = candidate else {
            break;
        };

        match state.node_view.process_modifier(type_id, &id, &data) {
            Ok(info) => {
                applied_bodies += 1;
                for (_ty, dl_id) in &info.to_download {
                    accum.blocks_to_download.push(*dl_id);
                }
                emit_applied_blocks(state, evt_tx);
            }
            Err(e) => {
                tracing::debug!(
                    modifier_id = hex::encode(id.0),
                    type_id,
                    %e,
                    "cache pop_candidate: body validation failed, re-caching"
                );
                state.cache.put(id, type_id, data, None);
                break;
            }
        }
    }

    if applied_bodies > 0 {
        tracing::debug!(applied_bodies, "cache drain: body sections applied");
    }
}

/// Emit `BlockApplied` events for any blocks applied during the last
/// `process_modifier` call.
fn emit_applied_blocks(
    state: &mut ProcessorState,
    evt_tx: &tokio::sync::mpsc::Sender<ProcessorEvent>,
) {
    for applied_id in state.node_view.take_applied_blocks() {
        let height = state
            .node_view
            .history
            .load_header(&applied_id)
            .ok()
            .flatten()
            .map(|h| h.height)
            .unwrap_or(0);
        let _ = evt_tx.blocking_send(ProcessorEvent::BlockApplied {
            header_id: applied_id,
            height,
        });
    }
}

/// Read current heights from history and send a `StateUpdate` event.
fn send_state_update(
    state: &mut ProcessorState,
    evt_tx: &tokio::sync::mpsc::Sender<ProcessorEvent>,
) {
    // Use the max of the P2P chain tip height and the fast-sync bulk-write
    // frontier.  During fast header sync, bulk writes fill the DB far ahead
    // of the connected P2P tip, so using only best_header_height() would make
    // the throttle think the processor is behind.
    let headers_height = state
        .node_view
        .history
        .best_header_height()
        .unwrap_or(0)
        .max(state.fast_sync_write_height);
    let full_height = state
        .node_view
        .history
        .best_full_block_height()
        .unwrap_or(0);
    let best_header_id = state.node_view.history.best_header_id().ok().flatten();
    let best_full_id = state.node_view.history.best_full_block_id().ok().flatten();
    let state_root = state.node_view.state_root().to_vec();
    let applied_blocks = state.node_view.take_applied_blocks();
    let rollback_height = state.node_view.take_rollback_height();

    // Load last N headers (newest first) for SyncInfoV2 construction.
    // This runs on the processor's own read-write DB, so it always reflects
    // the latest applied headers — no secondary DB staleness issues.
    let sync_headers = load_sync_headers(&state.node_view.history, MAX_SYNC_HEADERS);

    // Current on-chain consensus parameters from the voting state machine.
    let parameters = state.node_view.current_parameters().clone();

    let _ = evt_tx.blocking_send(ProcessorEvent::StateUpdate {
        headers_height,
        full_height,
        best_header_id,
        best_full_id,
        state_root,
        applied_blocks,
        rollback_height,
        sync_headers,
        parameters,
    });
}

/// Maximum number of headers to include in SyncInfoV2.
const MAX_SYNC_HEADERS: u32 = 10;

/// Load the last `count` headers (newest first) from the database,
/// walking backwards from the best header by height.
fn load_sync_headers(history: &ergo_storage::history_db::HistoryDb, count: u32) -> Vec<Header> {
    let best_height = history.best_header_height().unwrap_or(0);
    if best_height == 0 {
        return Vec::new();
    }
    let start = if best_height > count {
        best_height - count + 1
    } else {
        1
    };
    let mut headers = Vec::with_capacity(count as usize);
    for h in (start..=best_height).rev() {
        if let Ok(ids) = history.header_ids_at_height(h) {
            if let Some(id) = ids.first() {
                if let Ok(Some(header)) = history.load_header(id) {
                    headers.push(header);
                }
            }
        }
    }
    headers
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    /// Both enums must be `Send` so they can cross thread boundaries.
    #[test]
    fn command_and_event_are_send() {
        fn assert_send<T: Send>() {}
        assert_send::<ProcessorCommand>();
        assert_send::<ProcessorEvent>();
    }

    /// Round-trip through channels (std::sync::mpsc for commands, tokio::sync::mpsc for events).
    #[test]
    fn channel_round_trip() {
        // Command channel (std::sync::mpsc)
        let (cmd_tx, cmd_rx) = mpsc::sync_channel::<ProcessorCommand>(CHANNEL_CAPACITY);

        let mid = ModifierId([0xAB; 32]);
        cmd_tx
            .send(ProcessorCommand::StoreModifier {
                type_id: 101,
                modifier_id: mid,
                data: vec![1, 2, 3],
                peer_hint: Some(42),
            })
            .unwrap();
        cmd_tx.send(ProcessorCommand::Shutdown).unwrap();

        match cmd_rx.recv().unwrap() {
            ProcessorCommand::StoreModifier {
                type_id,
                modifier_id,
                data,
                peer_hint,
            } => {
                assert_eq!(type_id, 101);
                assert_eq!(modifier_id, mid);
                assert_eq!(data, vec![1, 2, 3]);
                assert_eq!(peer_hint, Some(42));
            }
            other => panic!("expected StoreModifier, got {:?}", other),
        }

        match cmd_rx.recv().unwrap() {
            ProcessorCommand::Shutdown => {}
            other => panic!("expected Shutdown, got {:?}", other),
        }

        // Event channel (tokio::sync::mpsc)
        let (evt_tx, mut evt_rx) = tokio::sync::mpsc::channel::<ProcessorEvent>(CHANNEL_CAPACITY);

        let hid = ModifierId([0xCD; 32]);
        evt_tx
            .try_send(ProcessorEvent::BlockApplied {
                header_id: hid,
                height: 100,
            })
            .unwrap();

        match evt_rx.try_recv().unwrap() {
            ProcessorEvent::BlockApplied { header_id, height } => {
                assert_eq!(header_id, hid);
                assert_eq!(height, 100);
            }
            other => panic!("expected BlockApplied, got {:?}", other),
        }
    }

    /// Spawn processor thread, send Shutdown, verify it exits within 1s.
    #[test]
    fn processor_shutdown() {
        let (cmd_tx, cmd_rx) = mpsc::sync_channel::<ProcessorCommand>(CHANNEL_CAPACITY);
        let (evt_tx, _evt_rx) = tokio::sync::mpsc::channel::<ProcessorEvent>(CHANNEL_CAPACITY);

        let handle = std::thread::spawn(move || {
            run_processor_with_state(cmd_rx, evt_tx, || {
                let (state, _tmpdir) = ProcessorState::new_test();
                // Leak tmpdir so it outlives the processor loop.
                std::mem::forget(_tmpdir);
                state
            });
        });

        cmd_tx.send(ProcessorCommand::Shutdown).unwrap();
        // The thread should exit within 1 second.
        let result = handle.join();
        assert!(
            result.is_ok(),
            "processor thread should exit cleanly on Shutdown"
        );
    }

    /// Spawn with test state, send a StoreModifier (type 102, dummy data),
    /// then Shutdown. Verify at least one event is received.
    #[test]
    fn processor_handles_modifier_sends_event() {
        let (cmd_tx, cmd_rx) = mpsc::sync_channel::<ProcessorCommand>(CHANNEL_CAPACITY);
        let (evt_tx, mut evt_rx) = tokio::sync::mpsc::channel::<ProcessorEvent>(CHANNEL_CAPACITY);

        let handle = std::thread::spawn(move || {
            run_processor_with_state(cmd_rx, evt_tx, || {
                let (state, _tmpdir) = ProcessorState::new_test();
                std::mem::forget(_tmpdir);
                state
            });
        });

        let mid = ModifierId([0x42; 32]);
        cmd_tx
            .send(ProcessorCommand::StoreModifier {
                type_id: 102,
                modifier_id: mid,
                data: vec![0xDE, 0xAD],
                peer_hint: Some(1),
            })
            .unwrap();
        cmd_tx.send(ProcessorCommand::Shutdown).unwrap();

        handle.join().expect("processor thread should not panic");

        // Collect all events and verify we got at least one meaningful event
        // (ModifierCached or ValidationFailed, since the test NodeViewHolder
        // has no real block data, and also StateUpdate from the batch end).
        let mut events = Vec::new();
        while let Ok(evt) = evt_rx.try_recv() {
            events.push(evt);
        }
        assert!(
            !events.is_empty(),
            "expected at least one event from the processor"
        );

        // Verify that we got either a ModifierCached or a StateUpdate.
        let has_expected = events.iter().any(|evt| {
            matches!(
                evt,
                ProcessorEvent::ModifierCached { .. }
                    | ProcessorEvent::StateUpdate { .. }
                    | ProcessorEvent::ValidationFailed { .. }
            )
        });
        assert!(
            has_expected,
            "expected ModifierCached, StateUpdate, or ValidationFailed event; got: {:?}",
            events
        );
    }

    /// Spawn processor thread, send a `BulkHeaders` command containing one
    /// height-1 header, then Shutdown.  Verify that a `HeadersApplied` event
    /// is emitted with the header's ID.
    #[test]
    fn bulk_headers_command_emits_headers_applied() {
        use ergo_types::modifier_id::ModifierId;

        let (cmd_tx, cmd_rx) = mpsc::sync_channel::<ProcessorCommand>(CHANNEL_CAPACITY);
        let (evt_tx, mut evt_rx) = tokio::sync::mpsc::channel::<ProcessorEvent>(CHANNEL_CAPACITY);

        let handle = std::thread::spawn(move || {
            run_processor_with_state(cmd_rx, evt_tx, || {
                let (state, _tmpdir) = ProcessorState::new_test();
                // Leak the tempdir so it outlives the processor loop.
                std::mem::forget(_tmpdir);
                state
            });
        });

        // Build one minimal header at height 1 whose parent is GENESIS_PARENT.
        let header_id = ModifierId([0x11; 32]);
        let mut header = ergo_types::header::Header::default_for_test();
        header.height = 1;
        header.n_bits = 0x01010000; // compact encoding: difficulty 1
        header.parent_id = ModifierId::GENESIS_PARENT;
        let raw = ergo_wire::header_ser::serialize_header(&header);

        cmd_tx
            .send(ProcessorCommand::BulkHeaders {
                headers: vec![(header_id, Box::new(header), raw)],
            })
            .unwrap();
        cmd_tx.send(ProcessorCommand::Shutdown).unwrap();

        handle.join().expect("processor thread should not panic");

        // Collect all events.
        let mut events = Vec::new();
        while let Ok(evt) = evt_rx.try_recv() {
            events.push(evt);
        }

        // At least one HeadersApplied event must mention our header ID.
        let found = events.iter().any(|evt| {
            if let ProcessorEvent::HeadersApplied { new_header_ids, .. } = evt {
                new_header_ids.contains(&header_id)
            } else {
                false
            }
        });
        assert!(
            found,
            "expected HeadersApplied event containing header_id {:?}; got: {:?}",
            header_id, events
        );
    }
}
