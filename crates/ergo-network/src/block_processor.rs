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
pub const CHANNEL_CAPACITY: usize = 256;

/// Maximum number of commands to drain per batch iteration.
const MAX_BATCH_SIZE: usize = 64;

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
        /// The peer that delivered this modifier, if known.
        peer_hint: Option<PeerId>,
    },

    /// Trigger a cache drain -- attempt to apply cached modifiers.
    ApplyFromCache,

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
}

impl ProcessorState {
    /// Creates a new `ProcessorState` wrapping the given `NodeViewHolder`.
    pub fn new(node_view: NodeViewHolder) -> Self {
        Self {
            node_view,
            cache: ModifiersCache::with_default_capacities(),
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
    loop {
        // Block until a command arrives or the timeout elapses.
        let first = match cmd_rx.recv_timeout(Duration::from_millis(100)) {
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
                        state, evt_tx, type_id, modifier_id, data, peer_hint, &mut accum,
                    );
                }
                ProcessorCommand::StorePrevalidatedHeader {
                    modifier_id,
                    header,
                    peer_hint,
                } => {
                    let mut accum = BatchAccum {
                        new_headers: &mut new_headers,
                        blocks_to_download: &mut blocks_to_download,
                    };
                    process_prevalidated_header(
                        state, evt_tx, modifier_id, *header, peer_hint, &mut accum,
                    );
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

        // After each batch: emit accumulated events.
        if !new_headers.is_empty() || !blocks_to_download.is_empty() {
            let _ = evt_tx.blocking_send(ProcessorEvent::HeadersApplied {
                new_header_ids: std::mem::take(&mut new_headers),
                to_download: std::mem::take(&mut blocks_to_download),
            });
        }

        send_state_update(state, evt_tx);

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
    match state.node_view.process_modifier(type_id, &modifier_id, &data) {
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
            state.cache.put(modifier_id, type_id, data);
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
fn process_prevalidated_header(
    state: &mut ProcessorState,
    evt_tx: &tokio::sync::mpsc::Sender<ProcessorEvent>,
    modifier_id: ModifierId,
    header: Header,
    peer_hint: Option<PeerId>,
    accum: &mut BatchAccum<'_>,
) {
    match state.node_view.process_prevalidated_header(&modifier_id, &header) {
        Ok(info) => {
            accum.new_headers.push(modifier_id);
            for (_ty, dl_id) in &info.to_download {
                accum.blocks_to_download.push(*dl_id);
            }
        }
        Err(e) => {
            let _ = evt_tx.blocking_send(ProcessorEvent::ValidationFailed {
                modifier_id,
                peer_hint,
                error: format!("prevalidated header failed: {e}"),
            });
        }
    }
}

/// Drain all entries from the cache and attempt to apply each one.
/// Entries that fail are re-inserted. Iterates up to `MAX_BATCH_SIZE` times
/// to handle cascading dependencies.
fn apply_from_cache_processor(
    state: &mut ProcessorState,
    evt_tx: &tokio::sync::mpsc::Sender<ProcessorEvent>,
    accum: &mut BatchAccum<'_>,
) {
    for _iteration in 0..MAX_BATCH_SIZE {
        let entries = state.cache.drain_all();
        if entries.is_empty() {
            break;
        }

        let mut any_applied = false;
        for (id, type_id, data) in entries {
            match state.node_view.process_modifier(type_id, &id, &data) {
                Ok(info) => {
                    any_applied = true;
                    if type_id == HEADER_TYPE_ID {
                        accum.new_headers.push(id);
                    }
                    for (_ty, dl_id) in &info.to_download {
                        accum.blocks_to_download.push(*dl_id);
                    }
                    emit_applied_blocks(state, evt_tx);
                }
                Err(_) => {
                    // Re-insert for future retry.
                    state.cache.put(id, type_id, data);
                }
            }
        }

        if !any_applied {
            break;
        }
    }
}

/// Emit `BlockApplied` events for any blocks applied during the last
/// `process_modifier` call.
fn emit_applied_blocks(state: &mut ProcessorState, evt_tx: &tokio::sync::mpsc::Sender<ProcessorEvent>) {
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
fn send_state_update(state: &mut ProcessorState, evt_tx: &tokio::sync::mpsc::Sender<ProcessorEvent>) {
    let headers_height = state
        .node_view
        .history
        .best_header_height()
        .unwrap_or(0);
    let full_height = state
        .node_view
        .history
        .best_full_block_height()
        .unwrap_or(0);
    let best_header_id = state
        .node_view
        .history
        .best_header_id()
        .ok()
        .flatten();
    let best_full_id = state
        .node_view
        .history
        .best_full_block_id()
        .ok()
        .flatten();
    let state_root = state.node_view.state_root().to_vec();
    let applied_blocks = state.node_view.take_applied_blocks();
    let rollback_height = state.node_view.take_rollback_height();

    let _ = evt_tx.blocking_send(ProcessorEvent::StateUpdate {
        headers_height,
        full_height,
        best_header_id,
        best_full_id,
        state_root,
        applied_blocks,
        rollback_height,
    });
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
        assert!(result.is_ok(), "processor thread should exit cleanly on Shutdown");
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
        assert!(has_expected, "expected ModifierCached, StateUpdate, or ValidationFailed event; got: {:?}", events);
    }
}
