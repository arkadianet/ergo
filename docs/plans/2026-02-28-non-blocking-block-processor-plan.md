# Non-Blocking Block Processor Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Move NodeViewHolder and block validation off the event loop onto a dedicated processor thread, communicating via bounded channels, so the event loop stays responsive during sync.

**Architecture:** Dedicated OS thread owns NodeViewHolder + ModifiersCache. Event loop forwards modifiers via `std::sync::mpsc::sync_channel`. Processor sends results back. HistoryDb dual handles: read-write on processor, read-only on event loop. Rayon parallel tx validation deferred to a follow-up — this plan focuses on the thread split.

**Tech Stack:** std::thread, std::sync::mpsc, std::panic::catch_unwind, existing rayon (already in workspace)

---

### Task 1: Define ProcessorCommand and ProcessorEvent enums

**Files:**
- Create: `crates/ergo-network/src/block_processor.rs`
- Modify: `crates/ergo-network/src/lib.rs` (add `pub mod block_processor;`)

**Context:** These are the message types flowing between the event loop and the processor thread. ProcessorCommand goes event-loop→processor, ProcessorEvent goes processor→event-loop. They must be `Send + 'static` because they cross thread boundaries. `Header` is from `ergo_types::header::Header`. `ModifierId` is `ergo_types::modifier_id::ModifierId`. `PeerId` is `u64` (from `crate::connection_pool::PeerId`).

**Step 1: Write the failing test**

In `crates/ergo-network/src/block_processor.rs`, add a test module at the bottom:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use ergo_types::modifier_id::ModifierId;

    #[test]
    fn command_and_event_are_send() {
        fn assert_send<T: Send>() {}
        assert_send::<ProcessorCommand>();
        assert_send::<ProcessorEvent>();
    }

    #[test]
    fn channel_round_trip() {
        let (cmd_tx, cmd_rx) = std::sync::mpsc::sync_channel::<ProcessorCommand>(8);
        let (evt_tx, evt_rx) = std::sync::mpsc::sync_channel::<ProcessorEvent>(8);

        let id = ModifierId([1u8; 32]);
        cmd_tx
            .try_send(ProcessorCommand::StoreModifier {
                type_id: 102,
                modifier_id: id,
                data: vec![0xAB],
                peer_hint: None,
            })
            .unwrap();
        cmd_tx.try_send(ProcessorCommand::Shutdown).unwrap();

        let msg = cmd_rx.recv().unwrap();
        assert!(matches!(msg, ProcessorCommand::StoreModifier { type_id: 102, .. }));
        let msg = cmd_rx.recv().unwrap();
        assert!(matches!(msg, ProcessorCommand::Shutdown));

        evt_tx
            .try_send(ProcessorEvent::BlockApplied {
                header_id: id,
                height: 42,
            })
            .unwrap();
        let evt = evt_rx.recv().unwrap();
        assert!(matches!(evt, ProcessorEvent::BlockApplied { height: 42, .. }));
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p ergo-network block_processor -- --nocapture`
Expected: Compile error — module doesn't exist yet.

**Step 3: Write minimal implementation**

Create `crates/ergo-network/src/block_processor.rs`:

```rust
//! Dedicated block processor thread: receives modifiers from the event loop,
//! validates and applies them on its own thread, and sends results back.

use ergo_types::header::Header;
use ergo_types::modifier_id::ModifierId;

use crate::connection_pool::PeerId;

/// Commands sent from the event loop to the processor thread.
pub enum ProcessorCommand {
    /// Store and process a raw block section (type 102/104/108) or header (101).
    StoreModifier {
        type_id: u8,
        modifier_id: ModifierId,
        data: Vec<u8>,
        /// The peer that sent this modifier (for penalty attribution).
        peer_hint: Option<PeerId>,
    },
    /// Store a header that has already been parsed and PoW-validated.
    StorePrevalidatedHeader {
        modifier_id: ModifierId,
        header: Header,
        peer_hint: Option<PeerId>,
    },
    /// Trigger a cache drain attempt (after storing modifiers).
    ApplyFromCache,
    /// Graceful shutdown: finish current work, then exit.
    Shutdown,
}

/// Events sent from the processor thread back to the event loop.
pub enum ProcessorEvent {
    /// Header(s) stored — event loop should update sync state.
    HeadersApplied {
        new_header_ids: Vec<ModifierId>,
        /// Block section IDs that need downloading.
        to_download: Vec<ModifierId>,
    },
    /// Full block validated and state applied.
    BlockApplied {
        header_id: ModifierId,
        height: u32,
    },
    /// Modifier stored in cache (missing dependencies — not applied yet).
    ModifierCached {
        type_id: u8,
        modifier_id: ModifierId,
    },
    /// Validation or storage failed for a modifier.
    ValidationFailed {
        modifier_id: ModifierId,
        peer_hint: Option<PeerId>,
        error: String,
    },
    /// Periodic state snapshot for SharedState / API.
    StateUpdate {
        headers_height: u32,
        full_height: u32,
        best_header_id: Option<ModifierId>,
        best_full_id: Option<ModifierId>,
        state_root: Vec<u8>,
        applied_blocks: Vec<ModifierId>,
        rollback_height: Option<u32>,
    },
}

/// Channel capacity for both command and event channels.
pub const CHANNEL_CAPACITY: usize = 256;
```

Add to `crates/ergo-network/src/lib.rs`:
```rust
pub mod block_processor;
```

**Step 4: Run tests to verify they pass**

Run: `cargo test -p ergo-network block_processor -- --nocapture`
Expected: 2 tests pass.

**Step 5: Commit**

```bash
git add crates/ergo-network/src/block_processor.rs crates/ergo-network/src/lib.rs
git commit -m "feat(network): add ProcessorCommand and ProcessorEvent channel types"
```

---

### Task 2: Implement the processor thread run loop

**Files:**
- Modify: `crates/ergo-network/src/block_processor.rs`

**Context:** The processor thread owns `NodeViewHolder` + `ModifiersCache`. It blocks on `recv_timeout(100ms)`, drains batches up to 64, processes each command by delegating to the existing `NodeViewHolder` methods (`process_modifier`, `process_prevalidated_header`), and calls `apply_from_cache`. It sends `ProcessorEvent`s back for each processed item. Wrap the entire loop in `catch_unwind` so a panic doesn't silently kill the thread.

The `apply_from_cache` logic currently lives in `message_handler.rs` (lines 730-794). For this task, we move its logic into the processor. The processor calls a local copy of the same algorithm.

**Step 1: Write the failing test**

Add to the test module in `block_processor.rs`:

```rust
#[test]
fn processor_shutdown() {
    use std::sync::mpsc;
    use std::time::Duration;

    let (cmd_tx, cmd_rx) = mpsc::sync_channel::<ProcessorCommand>(CHANNEL_CAPACITY);
    let (evt_tx, _evt_rx) = mpsc::sync_channel::<ProcessorEvent>(CHANNEL_CAPACITY);

    let handle = std::thread::spawn(move || {
        run_processor(cmd_rx, evt_tx);
    });

    cmd_tx.send(ProcessorCommand::Shutdown).unwrap();
    // Should exit within 1 second.
    handle.join().unwrap();
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p ergo-network block_processor::tests::processor_shutdown -- --nocapture`
Expected: Compile error — `run_processor` doesn't exist.

**Step 3: Write minimal implementation**

Add to `block_processor.rs`, below the enum definitions:

```rust
use std::sync::mpsc::{Receiver, SyncSender, RecvTimeoutError};
use std::time::Duration;

use crate::modifiers_cache::ModifiersCache;
use crate::node_view::NodeViewHolder;

/// Maximum commands to drain per batch iteration.
const MAX_BATCH_SIZE: usize = 64;

/// Run the processor loop. Call this from `std::thread::spawn`.
///
/// The processor owns `NodeViewHolder` and `ModifiersCache`, processing
/// commands from the event loop and sending results back.
///
/// This function returns when it receives `Shutdown` or the command
/// channel disconnects. Panics inside the loop are caught and reported
/// via a `ProcessorEvent::ValidationFailed` with a descriptive message.
pub fn run_processor(
    cmd_rx: Receiver<ProcessorCommand>,
    evt_tx: SyncSender<ProcessorEvent>,
) {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        processor_loop(&cmd_rx, &evt_tx);
    }));

    if let Err(panic_info) = result {
        let msg = if let Some(s) = panic_info.downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = panic_info.downcast_ref::<String>() {
            s.clone()
        } else {
            "unknown panic".to_string()
        };
        tracing::error!(error = %msg, "processor thread panicked");
        // Send a fatal event so the event loop knows to shut down.
        let _ = evt_tx.try_send(ProcessorEvent::ValidationFailed {
            modifier_id: ModifierId([0u8; 32]),
            peer_hint: None,
            error: format!("FATAL: processor thread panicked: {msg}"),
        });
    }
}

fn processor_loop(
    cmd_rx: &Receiver<ProcessorCommand>,
    evt_tx: &SyncSender<ProcessorEvent>,
) {
    let mut batch: Vec<ProcessorCommand> = Vec::with_capacity(MAX_BATCH_SIZE);

    loop {
        // Block waiting for first command.
        match cmd_rx.recv_timeout(Duration::from_millis(100)) {
            Ok(cmd) => batch.push(cmd),
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => {
                tracing::info!("processor: command channel disconnected, exiting");
                return;
            }
        }

        // Drain up to MAX_BATCH_SIZE - 1 more without blocking.
        while batch.len() < MAX_BATCH_SIZE {
            match cmd_rx.try_recv() {
                Ok(cmd) => batch.push(cmd),
                Err(_) => break,
            }
        }

        for cmd in batch.drain(..) {
            match cmd {
                ProcessorCommand::Shutdown => {
                    tracing::info!("processor: shutdown requested");
                    return;
                }
                ProcessorCommand::StoreModifier { .. }
                | ProcessorCommand::StorePrevalidatedHeader { .. }
                | ProcessorCommand::ApplyFromCache => {
                    // Modifier processing will be wired in Task 3.
                }
            }
        }
    }
}
```

**Step 4: Run tests to verify they pass**

Run: `cargo test -p ergo-network block_processor -- --nocapture`
Expected: 3 tests pass (command_and_event_are_send, channel_round_trip, processor_shutdown).

**Step 5: Commit**

```bash
git add crates/ergo-network/src/block_processor.rs
git commit -m "feat(network): add processor thread run loop with shutdown and panic safety"
```

---

### Task 3: Wire modifier processing into the processor loop

**Files:**
- Modify: `crates/ergo-network/src/block_processor.rs`

**Context:** The processor needs to own a `NodeViewHolder` and `ModifiersCache`. We add a `ProcessorState` struct that holds these plus helper methods. The `run_processor` function signature changes to accept a closure/factory that builds the state on the processor thread (since `NodeViewHolder` is not `Send`).

Actually, looking at NodeViewHolder's fields: `HistoryDb` contains `Arc<DB>` (RocksDB), `Arc<RwLock<ErgoMemPool>>`, DigestState, UtxoState — these all need to be checked for Send. Instead of fighting Send bounds, we'll use a builder pattern: `run_processor` accepts a `FnOnce` that constructs `ProcessorState` on the processor thread.

**Step 1: Write the failing test**

```rust
#[test]
fn processor_handles_store_modifier_unknown_type() {
    use std::sync::mpsc;

    let (cmd_tx, cmd_rx) = mpsc::sync_channel::<ProcessorCommand>(CHANNEL_CAPACITY);
    let (evt_tx, evt_rx) = mpsc::sync_channel::<ProcessorEvent>(CHANNEL_CAPACITY);

    let handle = std::thread::spawn(move || {
        run_processor_with_state(cmd_rx, evt_tx, || {
            ProcessorState::new_test()
        });
    });

    // Send a modifier, then shutdown.
    let id = ModifierId([2u8; 32]);
    cmd_tx
        .send(ProcessorCommand::StoreModifier {
            type_id: 102,
            modifier_id: id,
            data: vec![0x01, 0x02],
            peer_hint: Some(99),
        })
        .unwrap();
    cmd_tx.send(ProcessorCommand::Shutdown).unwrap();

    handle.join().unwrap();

    // Should get either a ModifierCached or ValidationFailed event
    // (depends on whether NodeViewHolder can process it — in test mode
    // with no real DB, we expect a failure or cache event).
    let evt = evt_rx.try_recv();
    assert!(evt.is_ok(), "expected at least one event from processor");
}
```

**Step 2: Run test to verify it fails**

Expected: Compile error — `run_processor_with_state` and `ProcessorState` don't exist.

**Step 3: Implement ProcessorState and run_processor_with_state**

Add to `block_processor.rs`:

```rust
use crate::message_handler; // for apply_from_cache logic
use crate::sync_manager::SyncManager;
use crate::delivery_tracker::DeliveryTracker;

/// State owned by the processor thread.
pub struct ProcessorState {
    pub node_view: NodeViewHolder,
    pub cache: ModifiersCache,
}

impl ProcessorState {
    /// Create a ProcessorState from an existing NodeViewHolder.
    pub fn new(node_view: NodeViewHolder) -> Self {
        Self {
            node_view,
            cache: ModifiersCache::with_default_capacities(),
        }
    }

    #[cfg(test)]
    pub fn new_test() -> Self {
        use std::sync::{Arc, RwLock};
        use ergo_storage::history_db::HistoryDb;
        use crate::mempool::ErgoMemPool;

        let dir = tempfile::tempdir().unwrap();
        let history = HistoryDb::open(dir.path()).unwrap();
        let mempool = Arc::new(RwLock::new(ErgoMemPool::new(1000)));
        let genesis = vec![0u8; 33];
        let nv = NodeViewHolder::new(history, mempool, true, genesis);
        Self {
            node_view: nv,
            cache: ModifiersCache::with_default_capacities(),
        }
    }
}

/// Run the processor loop, constructing state on the processor thread.
///
/// `state_factory` is called on the processor thread to create the
/// ProcessorState — this avoids Send requirements on NodeViewHolder.
pub fn run_processor_with_state<F>(
    cmd_rx: Receiver<ProcessorCommand>,
    evt_tx: SyncSender<ProcessorEvent>,
    state_factory: F,
) where
    F: FnOnce() -> ProcessorState + Send + 'static,
{
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut state = state_factory();
        processor_loop_with_state(&cmd_rx, &evt_tx, &mut state);
    }));

    if let Err(panic_info) = result {
        let msg = if let Some(s) = panic_info.downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = panic_info.downcast_ref::<String>() {
            s.clone()
        } else {
            "unknown panic".to_string()
        };
        tracing::error!(error = %msg, "processor thread panicked");
        let _ = evt_tx.try_send(ProcessorEvent::ValidationFailed {
            modifier_id: ModifierId([0u8; 32]),
            peer_hint: None,
            error: format!("FATAL: processor thread panicked: {msg}"),
        });
    }
}

fn processor_loop_with_state(
    cmd_rx: &Receiver<ProcessorCommand>,
    evt_tx: &SyncSender<ProcessorEvent>,
    state: &mut ProcessorState,
) {
    let mut batch: Vec<ProcessorCommand> = Vec::with_capacity(MAX_BATCH_SIZE);
    let mut new_headers: Vec<ModifierId> = Vec::new();
    let mut blocks_to_download: Vec<ModifierId> = Vec::new();

    loop {
        match cmd_rx.recv_timeout(Duration::from_millis(100)) {
            Ok(cmd) => batch.push(cmd),
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => {
                tracing::info!("processor: command channel disconnected, exiting");
                return;
            }
        }

        while batch.len() < MAX_BATCH_SIZE {
            match cmd_rx.try_recv() {
                Ok(cmd) => batch.push(cmd),
                Err(_) => break,
            }
        }

        new_headers.clear();
        blocks_to_download.clear();

        for cmd in batch.drain(..) {
            match cmd {
                ProcessorCommand::Shutdown => {
                    tracing::info!("processor: shutdown requested");
                    return;
                }
                ProcessorCommand::StoreModifier {
                    type_id,
                    modifier_id,
                    data,
                    peer_hint,
                } => {
                    match state.node_view.process_modifier(type_id, &modifier_id, &data) {
                        Ok(info) => {
                            if type_id == 101 {
                                new_headers.push(modifier_id);
                            }
                            for (_section_type, hdr_id) in &info.to_download {
                                if !blocks_to_download.contains(hdr_id) {
                                    blocks_to_download.push(*hdr_id);
                                }
                            }
                            // Check for applied blocks.
                            let applied = state.node_view.take_applied_blocks();
                            if !applied.is_empty() {
                                let height = state.node_view.history
                                    .best_full_block_height().unwrap_or(0);
                                for block_id in &applied {
                                    let _ = evt_tx.try_send(ProcessorEvent::BlockApplied {
                                        header_id: *block_id,
                                        height,
                                    });
                                }
                            }
                        }
                        Err(e) => {
                            // Cache the modifier for retry.
                            state.cache.put(modifier_id, type_id, data);
                            let _ = evt_tx.try_send(ProcessorEvent::ModifierCached {
                                type_id,
                                modifier_id,
                            });
                            tracing::debug!(
                                modifier_id = ?modifier_id,
                                error = %e,
                                "processor: caching modifier for retry"
                            );
                        }
                    }
                }
                ProcessorCommand::StorePrevalidatedHeader {
                    modifier_id,
                    header,
                    peer_hint,
                } => {
                    match state.node_view.process_prevalidated_header(&modifier_id, &header) {
                        Ok(info) => {
                            new_headers.push(modifier_id);
                            for (_section_type, hdr_id) in &info.to_download {
                                if !blocks_to_download.contains(hdr_id) {
                                    blocks_to_download.push(*hdr_id);
                                }
                            }
                        }
                        Err(e) => {
                            let _ = evt_tx.try_send(ProcessorEvent::ValidationFailed {
                                modifier_id,
                                peer_hint,
                                error: format!("{e}"),
                            });
                        }
                    }
                }
                ProcessorCommand::ApplyFromCache => {
                    apply_from_cache_processor(
                        &mut state.cache,
                        &mut state.node_view,
                        &mut new_headers,
                        &mut blocks_to_download,
                        evt_tx,
                    );
                }
            }
        }

        // After batch: send aggregated header/download events.
        if !new_headers.is_empty() || !blocks_to_download.is_empty() {
            let _ = evt_tx.try_send(ProcessorEvent::HeadersApplied {
                new_header_ids: std::mem::take(&mut new_headers),
                to_download: std::mem::take(&mut blocks_to_download),
            });
        }

        // Periodic state update (every batch).
        send_state_update(&state.node_view, evt_tx);
    }
}

/// Cache drain: same algorithm as message_handler::apply_from_cache but
/// operates on ProcessorState and sends events directly.
fn apply_from_cache_processor(
    cache: &mut ModifiersCache,
    node_view: &mut NodeViewHolder,
    new_headers: &mut Vec<ModifierId>,
    blocks_to_download: &mut Vec<ModifierId>,
    evt_tx: &SyncSender<ProcessorEvent>,
) {
    let max_iterations = 64;
    let mut applied_any = true;
    let mut iterations = 0;

    while applied_any && iterations < max_iterations {
        if cache.is_empty() {
            break;
        }
        applied_any = false;
        iterations += 1;

        let entries: Vec<(ModifierId, u8, Vec<u8>)> = cache.drain_all();
        for (id, type_id, data) in entries {
            match node_view.process_modifier(type_id, &id, &data) {
                Ok(info) => {
                    applied_any = true;
                    if type_id == 101 {
                        new_headers.push(id);
                    }
                    for (_section_type, hdr_id) in &info.to_download {
                        if !blocks_to_download.contains(hdr_id) {
                            blocks_to_download.push(*hdr_id);
                        }
                    }
                    let applied = node_view.take_applied_blocks();
                    for block_id in &applied {
                        let height = node_view.history
                            .best_full_block_height().unwrap_or(0);
                        let _ = evt_tx.try_send(ProcessorEvent::BlockApplied {
                            header_id: *block_id,
                            height,
                        });
                    }
                }
                Err(_) => {
                    cache.put(id, type_id, data);
                }
            }
        }
    }
}

fn send_state_update(node_view: &NodeViewHolder, evt_tx: &SyncSender<ProcessorEvent>) {
    let headers_height = node_view.history.best_header_id().ok().flatten()
        .and_then(|id| node_view.history.load_header(&id).ok().flatten())
        .map(|h| h.height)
        .unwrap_or(0);
    let full_height = node_view.history.best_full_block_height().unwrap_or(0);
    let best_header_id = node_view.history.best_header_id().ok().flatten();
    let best_full_id = node_view.history.best_full_block_id().ok().flatten();

    let _ = evt_tx.try_send(ProcessorEvent::StateUpdate {
        headers_height,
        full_height,
        best_header_id,
        best_full_id,
        state_root: node_view.state_root().to_vec(),
        applied_blocks: Vec::new(),
        rollback_height: None,
    });
}
```

Note: `ModifiersCache::drain_all` and `ModifiersCache::with_default_capacities` must exist. Check if they do; if not, add them.

**Step 4: Run tests**

Run: `cargo test -p ergo-network block_processor -- --nocapture`
Expected: All tests pass.

**Step 5: Commit**

```bash
git add crates/ergo-network/src/block_processor.rs
git commit -m "feat(network): wire modifier processing into processor thread loop"
```

---

### Task 4: Add ModifiersCache::drain_all method

**Files:**
- Modify: `crates/ergo-network/src/modifiers_cache.rs`

**Context:** The processor's `apply_from_cache_processor` needs to drain all entries from the cache, try to apply them, and re-insert any that fail. The existing cache has `drain_headers` and `drain_body` but no `drain_all`. We also need `with_default_capacities` if it doesn't exist.

**Step 1: Check what methods exist**

Read `modifiers_cache.rs` to find existing drain/iteration methods.

**Step 2: Write the failing test**

```rust
#[test]
fn drain_all_returns_all_entries() {
    let mut cache = ModifiersCache::with_default_capacities();
    let id1 = ModifierId([1u8; 32]);
    let id2 = ModifierId([2u8; 32]);
    cache.put(id1, 101, vec![0xAA]);
    cache.put(id2, 102, vec![0xBB]);
    assert_eq!(cache.len(), 2);

    let drained = cache.drain_all();
    assert_eq!(drained.len(), 2);
    assert!(cache.is_empty());
}
```

**Step 3: Implement**

Add to `ModifiersCache`:

```rust
/// Drain all entries from both tiers, returning (id, type_id, data) tuples.
pub fn drain_all(&mut self) -> Vec<(ModifierId, u8, Vec<u8>)> {
    let mut result = Vec::with_capacity(self.len());

    // Drain headers tier.
    while let Some((id, cached)) = self.headers.pop_lru() {
        result.push((id, cached.type_id, cached.data));
    }

    // Drain body tier.
    while let Some((id, cached)) = self.body_sections.pop_lru() {
        result.push((id, cached.type_id, cached.data));
    }

    result
}
```

Also add `with_default_capacities` if it doesn't exist:

```rust
/// Create a cache with default capacities (8192 headers, 384 body).
pub fn with_default_capacities() -> Self {
    Self::new(DEFAULT_HEADERS_CAPACITY, DEFAULT_BODY_CAPACITY)
}
```

And `len`:

```rust
/// Total number of cached entries across both tiers.
pub fn len(&self) -> usize {
    self.headers.len() + self.body_sections.len()
}
```

**Step 4: Run tests**

Run: `cargo test -p ergo-network modifiers_cache -- --nocapture`
Expected: All pass.

**Step 5: Commit**

```bash
git add crates/ergo-network/src/modifiers_cache.rs
git commit -m "feat(network): add ModifiersCache::drain_all and helper methods"
```

---

### Task 5: Add read-only HistoryDb handle for the event loop

**Files:**
- Modify: `crates/ergo-node/src/event_loop.rs`
- Modify: `crates/ergo-node/src/main.rs`

**Context:** Currently the event loop accesses `node_view.history` for sync protocol lookups (SyncInfo, continuation IDs, height queries). When NodeViewHolder moves to the processor thread, the event loop needs its own read-only HistoryDb. The `HistoryDb::open_read_only` already exists and is already used for the API server.

This task adds a second read-only handle and threads it through to wherever the event loop currently touches `node_view.history` for read-only sync operations. The main consumer is `handle_sync_tick`, `handle_check_modifiers`, `handle_message` (for SyncInfo handling), and `update_shared_state`.

For this task, we:
1. Open an additional read-only HistoryDb in `main.rs` (alongside the existing API one).
2. Pass it as `sync_history: &HistoryDb` into the event loop `run()` function.
3. Thread it to `handle_sync_tick`, `handle_check_modifiers`, `update_shared_state`.
4. For `handle_message`, thread it to `handle_sync_info` calls (which currently take `&node_view.history`).

This is a preparatory step — the event loop still owns `node_view` for now, but these functions now use the separate read-only handle.

**Step 1: Modify `main.rs`**

After the existing API history handle (line ~95):
```rust
let sync_history = HistoryDb::open_read_only(&db_path)
    .unwrap_or_else(|e| panic!("cannot open sync history db: {e}"));
```

Pass `&sync_history` to the `run()` call.

**Step 2: Update `run()` signature**

Add `sync_history: &HistoryDb` parameter.

**Step 3: Thread `sync_history` through**

Replace `&node_view.history` with `sync_history` in:
- `handle_sync_tick` (pass as parameter, use for `sync_mgr.on_tick`)
- `handle_check_modifiers` (pass as parameter)
- `update_shared_state` (pass as parameter for height queries)
- `is_synced_for_txs` computation (use `sync_history` for height queries)

Keep `node_view.history` usage in `handle_message` for now (it mutates through `process_modifier`), and in the `applied_blocks` block (which loads headers for broadcasting).

**Step 4: Run all tests**

Run: `cargo test --workspace`
Expected: All pass — behavior is identical, just reading from a different RocksDB handle that sees the same data.

**Step 5: Commit**

```bash
git add crates/ergo-node/src/main.rs crates/ergo-node/src/event_loop.rs
git commit -m "refactor(node): add sync_history read-only handle for event loop"
```

---

### Task 6: Spawn processor thread and wire channels in main.rs

**Files:**
- Modify: `crates/ergo-node/src/main.rs`
- Modify: `crates/ergo-node/src/event_loop.rs`

**Context:** This is the core integration task. Instead of passing `node_view` directly to `run()`, we:

1. Create the `sync_channel` pair for commands and events.
2. Spawn the processor thread with `std::thread::spawn`, passing `node_view` into the closure (it's constructed on main thread but moved into the processor thread's closure — this works because `std::thread::spawn` requires `Send` for the closure return, but the closure itself just needs `Send` for the captured values; we use `run_processor_with_state` with a factory that constructs NodeViewHolder on the new thread).

Wait — `NodeViewHolder` needs to be constructed on the processor thread. Currently `main.rs` constructs it, configures it (set_blocks_to_keep, set_checkpoint_height, etc.), and passes it to `run()`. We need to move all that construction into the factory closure.

Actually, the simplest approach: construct `NodeViewHolder` on the main thread as before, but since `std::thread::spawn` requires `Send`, we need to make `NodeViewHolder` sendable. Let's check: `HistoryDb` wraps `Arc<DB>` which is `Send`. `Arc<RwLock<ErgoMemPool>>` is `Send`. `UtxoState` and `DigestState` need checking.

Alternative: use `std::thread::Builder::new().spawn(|| { ... })` with an `unsafe impl Send` or restructure. Simplest: move the entire construction into the spawned thread.

For this task, we'll restructure `main.rs` to move NodeViewHolder construction into the processor thread factory closure. The event loop's `run()` function changes to accept `cmd_tx: SyncSender<ProcessorCommand>` and `evt_rx: Receiver<ProcessorEvent>` instead of `node_view: NodeViewHolder`.

**Step 1: Restructure main.rs**

Move all NodeViewHolder construction (lines 85-163) into a factory closure. The factory receives settings by value (clone) and returns `ProcessorState`.

```rust
// In main.rs, replace node_view construction + event loop call:

let (cmd_tx, cmd_rx) = std::sync::mpsc::sync_channel(
    ergo_network::block_processor::CHANNEL_CAPACITY,
);
let (evt_tx, evt_rx) = std::sync::mpsc::sync_channel(
    ergo_network::block_processor::CHANNEL_CAPACITY,
);

// Clone settings for processor thread.
let proc_settings = settings.clone();
let proc_mempool = mempool.clone();
let proc_db_path = db_path.clone();

let processor_handle = std::thread::Builder::new()
    .name("block-processor".to_string())
    .spawn(move || {
        ergo_network::block_processor::run_processor_with_state(
            cmd_rx,
            evt_tx,
            move || {
                let history = HistoryDb::open(&proc_db_path)
                    .unwrap_or_else(|e| panic!("processor: cannot open database: {e}"));
                let genesis_digest = proc_settings.ergo.chain.genesis_state_digest();
                let is_utxo_mode = proc_settings.ergo.node.state_type == "utxo";
                let mut nv = NodeViewHolder::with_recovery(
                    history,
                    proc_mempool,
                    !is_utxo_mode,
                    genesis_digest,
                );
                // Configure...
                nv.set_blocks_to_keep(proc_settings.ergo.node.blocks_to_keep);
                nv.set_checkpoint_height(proc_settings.ergo.node.checkpoint_height);
                nv.set_v2_activation_config(
                    proc_settings.ergo.chain.version2_activation_height,
                    proc_settings.ergo.chain.version2_activation_difficulty_hex.clone(),
                );
                // UTXO persistence setup...
                if is_utxo_mode {
                    let utxo_path = Path::new(&proc_settings.ergo.directory).join("utxo");
                    // (same utxo setup code as current main.rs)
                }
                if let Err(e) = nv.restore_consistency() {
                    tracing::error!(error = %e, "consistency restore failed");
                }
                ergo_network::block_processor::ProcessorState::new(nv)
            },
        );
    })
    .expect("failed to spawn processor thread");
```

**Step 2: Update event loop `run()` signature**

Replace `node_view: NodeViewHolder` with:
```rust
cmd_tx: std::sync::mpsc::SyncSender<ergo_network::block_processor::ProcessorCommand>,
evt_rx: std::sync::mpsc::Receiver<ergo_network::block_processor::ProcessorEvent>,
sync_history: &HistoryDb,
```

**Step 3: Update message handling**

In the `msg = pool.recv()` branch, instead of calling `message_handler::handle_message` which takes `&mut node_view`, split the handling:

- **SyncInfo (code 65), GetPeers (1), Peers (2), Inv (55), RequestModifier (22)**: These don't need NodeViewHolder. Extract them into a new `handle_message_thin` that takes `sync_history` instead of `node_view`.

- **Modifiers (code 33)**: Forward to processor via `cmd_tx.try_send()`.

This is a significant refactoring of the message_handler. To keep the changeset manageable, this task restructures the event loop to forward Modifiers messages to the processor and handle ProcessorEvent responses. Other message types continue to use the read-only history handle.

**Step 4: Add ProcessorEvent handler to select! loop**

```rust
// New select! branch:
evt = async { evt_rx.recv() } => {
    match evt {
        Ok(ProcessorEvent::HeadersApplied { new_header_ids, to_download }) => {
            sync_mgr.on_headers_received(&new_header_ids, sync_history);
            if !to_download.is_empty() {
                sync_mgr.enqueue_block_downloads(to_download);
            }
        }
        Ok(ProcessorEvent::BlockApplied { header_id, height }) => {
            // Update shared state, notify indexer, etc.
        }
        Ok(ProcessorEvent::ValidationFailed { modifier_id, peer_hint, error }) => {
            if error.starts_with("FATAL:") {
                tracing::error!(error, "processor thread died, shutting down");
                break;
            }
            // Apply penalty
        }
        Ok(ProcessorEvent::StateUpdate { .. }) => {
            // Update shared state cache
        }
        Ok(ProcessorEvent::ModifierCached { .. }) => {
            // No action needed
        }
        Err(_) => {
            tracing::error!("processor event channel disconnected");
            break;
        }
    }
}
```

Note: `std::sync::mpsc::Receiver` is not async. Wrap with `tokio::task::spawn_blocking` or use a `tokio::sync::mpsc` instead. Since we want to integrate into `select!`, it's cleaner to use `tokio::sync::mpsc` for the event channel (processor→event loop) and `std::sync::mpsc` for commands (event loop→processor, since the processor thread uses blocking recv).

**Revised channel types:**
- `cmd_tx/cmd_rx`: `std::sync::mpsc::sync_channel` (processor blocks on recv)
- `evt_tx/evt_rx`: `tokio::sync::mpsc::channel` (event loop polls in select!)

Update `ProcessorEvent` channel in `block_processor.rs` to use `tokio::sync::mpsc::Sender` and the event loop uses `tokio::sync::mpsc::Receiver`.

**Step 5: Add graceful shutdown**

On Ctrl-C or API shutdown:
```rust
let _ = cmd_tx.try_send(ProcessorCommand::Shutdown);
// Wait for processor thread to exit.
let _ = processor_handle.join();
```

**Step 6: Run all tests**

Run: `cargo test --workspace`
Expected: All pass.

**Step 7: Commit**

```bash
git add crates/ergo-node/src/main.rs crates/ergo-node/src/event_loop.rs crates/ergo-network/src/block_processor.rs
git commit -m "feat(node): spawn processor thread, forward modifiers via channels"
```

---

### Task 7: Refactor message_handler to separate thin (sync) and thick (modifier) paths

**Files:**
- Modify: `crates/ergo-network/src/message_handler.rs`

**Context:** The event loop no longer owns `NodeViewHolder`, so `handle_message` cannot take `&mut NodeViewHolder`. We need to split it:

1. `handle_sync_message` — handles codes 1 (GetPeers), 2 (Peers), 55 (Inv), 22 (RequestModifier), 65 (SyncInfo). Takes `&HistoryDb` (read-only). Does NOT take NodeViewHolder.

2. Raw modifier data (code 33) is forwarded to the processor by the event loop directly (not through message_handler).

The existing `handle_modifiers` function (which calls `node_view.process_modifier`) is removed from the event loop path — its logic now lives in the processor thread.

**Step 1: Create `handle_sync_message`**

Extract the non-modifier branches from `handle_message` into a new function:

```rust
pub fn handle_sync_message(
    peer_id: PeerId,
    msg: &RawMessage,
    history: &HistoryDb,
    sync_tracker: &mut SyncTracker,
    tracker: &mut DeliveryTracker,
    connected_peers: &[std::net::SocketAddr],
    last_sync_from: &mut HashMap<PeerId, Instant>,
    last_sync_header_applied: &mut Option<u32>,
) -> HandleResult {
    match msg.code {
        1 => handle_get_peers(peer_id, connected_peers),
        2 => handle_peers(&msg.body),
        65 => { /* SyncInfo handling — uses history read-only */ }
        55 => { /* Inv — uses tracker only */ }
        22 => { /* RequestModifier — uses history read-only */ }
        _ => HandleResult::empty(),
    }
}
```

Keep the old `handle_message` for backward compatibility (tests use it), but mark it `#[deprecated]` or leave it as-is.

**Step 2: Update event loop**

In the `msg = pool.recv()` branch:
- For code 33 (Modifiers): parse ModifiersData, forward each modifier to processor via `cmd_tx`.
- For all other codes: call `handle_sync_message`.

**Step 3: Handle code 33 forwarding**

```rust
33 => {
    // Modifiers: forward to processor thread.
    let mods = match ModifiersData::parse(&incoming.message.body) {
        Ok(m) => m,
        Err(_) => continue,
    };
    let type_id = mods.type_id as u8;

    // Transaction modifiers handled locally (mempool, no state needed).
    if type_id == 2 {
        // Keep tx handling in event loop (mempool is Arc<RwLock>).
        // ... existing handle_tx_modifiers logic
        continue;
    }

    // Header parallel PoW validation stays in event loop.
    if type_id == HEADER_TYPE_ID {
        // Existing rayon parallel PoW code...
        for validated_header in &validated {
            let _ = cmd_tx.try_send(ProcessorCommand::StorePrevalidatedHeader { ... });
        }
    } else {
        // Body sections: forward raw to processor.
        for (id, data) in &mods.modifiers {
            let _ = cmd_tx.try_send(ProcessorCommand::StoreModifier { ... });
        }
    }
    let _ = cmd_tx.try_send(ProcessorCommand::ApplyFromCache);
}
```

**Step 4: Run all tests**

Run: `cargo test --workspace`
Expected: All pass.

**Step 5: Commit**

```bash
git add crates/ergo-network/src/message_handler.rs crates/ergo-node/src/event_loop.rs
git commit -m "refactor(network): split message_handler into sync and modifier paths"
```

---

### Task 8: Wire ProcessorEvent handling for applied blocks

**Files:**
- Modify: `crates/ergo-node/src/event_loop.rs`

**Context:** When the processor applies a block (sends `ProcessorEvent::BlockApplied`), the event loop needs to:
1. Update SharedState (height, best block ID).
2. Notify the indexer (`indexer_tx`).
3. Handle wallet rollback/scan (if wallet feature enabled).
4. Create UTXO snapshots.
5. Broadcast Inv for recent blocks.
6. Reset tx cost tracker.

Most of this code currently lives in the `!result.applied_blocks.is_empty()` block (lines 442-620). Move it into the `ProcessorEvent::BlockApplied` handler.

For wallet and snapshot operations that need `node_view` access: the processor sends the necessary data in `ProcessorEvent::StateUpdate` (which includes `applied_blocks` and `rollback_height`). The event loop uses the sync_history handle for header lookups.

**Step 1: Move applied_blocks handling to ProcessorEvent::BlockApplied handler**

The `ProcessorEvent::StateUpdate` variant already carries `applied_blocks` and `rollback_height`. When receiving a StateUpdate with non-empty applied_blocks, do:

```rust
Ok(ProcessorEvent::StateUpdate {
    headers_height,
    full_height,
    best_header_id,
    best_full_id,
    state_root,
    applied_blocks,
    rollback_height,
}) => {
    // Update cached heights.
    cached_headers_height = headers_height;
    cached_full_height = full_height;
    cached_state_root = state_root;

    if !applied_blocks.is_empty() {
        tx_cost_tracker.reset();

        // Notify indexer.
        if let Some(ref idx_tx) = indexer_tx {
            for block_id in &applied_blocks {
                if let Ok(Some(header)) = sync_history.load_header(block_id) {
                    let _ = idx_tx.try_send(IndexerEvent::BlockApplied {
                        header_id: block_id.0,
                        height: header.height,
                    });
                }
            }
        }

        // Broadcast Inv for recent blocks.
        // ... (same logic using sync_history.load_header)

        // Update SharedState.
        if let Ok(mut s) = shared.try_write() {
            s.headers_height = headers_height as u64;
            s.full_height = full_height as u64;
            // etc.
        }
    }
}
```

**Step 2: Handle wallet operations**

For wallet, the processor needs to send block transaction data. Add to StateUpdate:
```rust
/// Raw block transactions for wallet scanning (only populated when wallet feature is active).
wallet_blocks: Vec<(ModifierId, u32, Vec<Vec<u8>>)>, // (block_id, height, tx_bytes)
```

Or: have the event loop read block transactions from `sync_history` using the block_id (it's read-only but block_transactions are stored in the shared RocksDB).

**Step 3: Run all tests**

Run: `cargo test --workspace`
Expected: All pass.

**Step 4: Commit**

```bash
git add crates/ergo-node/src/event_loop.rs crates/ergo-network/src/block_processor.rs
git commit -m "feat(node): wire ProcessorEvent::BlockApplied handling in event loop"
```

---

### Task 9: Handle mempool, mining, and UTXO proof access

**Files:**
- Modify: `crates/ergo-node/src/event_loop.rs`
- Modify: `crates/ergo-network/src/block_processor.rs`

**Context:** Several event loop branches access `node_view` for non-modifier purposes:

1. **Mempool**: `node_view.mempool` — already `Arc<RwLock<ErgoMemPool>>`, shared. Event loop keeps a direct reference. No change needed.

2. **Mining**: `candidate_gen.generate_candidate(&node_view.history, &node_view.mempool, node_view.current_parameters(), utxo_ref)` — needs history (use sync_history), mempool (shared), parameters (cache from StateUpdate), UTXO ref (not available from event loop).

   For mining: either (a) send a `GenerateCandidate` command to the processor and get back the candidate, or (b) have the mining candidate generator use the read-only history + cached parameters. Option (b) is simpler — mining only needs read access.

   The UTXO reference is needed for fee calculation. Send the UTXO state root in StateUpdate and cache it. If mining needs actual UTXO lookups, add a ProcessorCommand::GenerateCandidate.

3. **UTXO proof**: `node_view.utxo_state()` — needs UTXO tree access. Add `ProcessorCommand::UtxoProof` and have the processor handle it.

4. **Block submission (POST /blocks)**: `node_view.process_modifier` — forward to processor via cmd_tx.

5. **Mempool audit**: `node_view.box_exists_in_utxo` — needs UTXO access. Either send a command or skip audit when UTXO is on processor.

This task handles each of these. For UTXO-dependent operations, add new ProcessorCommand variants with oneshot response channels.

**Step 1: Add new command variants**

```rust
pub enum ProcessorCommand {
    // ... existing variants ...

    /// Generate a mining candidate (from event loop mining tick).
    GenerateCandidate {
        response: tokio::sync::oneshot::Sender<Result<(), String>>,
    },

    /// UTXO batch proof request.
    UtxoProof {
        box_ids: Vec<[u8; 32]>,
        response: tokio::sync::oneshot::Sender<Result<Vec<u8>, String>>,
    },
}
```

**Step 2: Handle in processor loop**

Add match arms in `processor_loop_with_state`.

**Step 3: Update event loop callers**

Replace direct `node_view` calls with channel-based requests.

**Step 4: Run all tests**

Run: `cargo test --workspace`
Expected: All pass.

**Step 5: Commit**

```bash
git add crates/ergo-network/src/block_processor.rs crates/ergo-node/src/event_loop.rs
git commit -m "feat(node): route mining, UTXO proof, and block submit through processor"
```

---

### Task 10: Remove node_view from event loop run() and clean up

**Files:**
- Modify: `crates/ergo-node/src/event_loop.rs`
- Modify: `crates/ergo-node/src/main.rs`

**Context:** By this point, all `node_view` access in the event loop should be replaced by either (a) sync_history read-only queries, (b) mempool Arc, (c) processor commands/events, or (d) cached state from ProcessorEvent::StateUpdate.

This task:
1. Removes `node_view` parameter from `run()`.
2. Removes `mod_cache` from event loop (moved to processor).
3. Removes `apply_from_cache` calls from event loop.
4. Ensures `handle_sync_tick` uses `sync_history` not `node_view.history`.
5. Ensures `update_shared_state` uses cached values from ProcessorEvent.
6. Cleans up dead code.

**Step 1: Audit remaining node_view references**

Search for `node_view.` in event_loop.rs. Each must be replaced:
- `node_view.history.*` → `sync_history.*`
- `node_view.mempool` → `mempool` (direct Arc reference)
- `node_view.is_digest_mode()` → cached boolean from startup
- `node_view.utxo_db()` → via ProcessorCommand
- `node_view.utxo_state()` → via ProcessorCommand
- `node_view.state_root()` → cached from ProcessorEvent::StateUpdate
- `node_view.current_parameters()` → cached from ProcessorEvent::StateUpdate
- `node_view.state_version_id()` → cached from ProcessorEvent::StateUpdate
- `node_view.take_rollback_height()` → from ProcessorEvent::StateUpdate
- `node_view.take_applied_blocks()` → from ProcessorEvent
- `node_view.box_exists_in_utxo()` → skip or add ProcessorCommand
- `node_view.set_utxo_state()` → happens on processor thread only

**Step 2: Replace all references**

Each replaced with the appropriate mechanism.

**Step 3: Run all tests**

Run: `cargo test --workspace`
Expected: All pass.

**Step 4: Run clippy**

Run: `cargo clippy --workspace -- -D warnings`
Expected: 0 warnings.

**Step 5: Commit**

```bash
git add crates/ergo-node/src/event_loop.rs crates/ergo-node/src/main.rs
git commit -m "refactor(node): remove NodeViewHolder from event loop, fully channel-based"
```

---

### Task 11: Integration test — sync with processor thread

**Files:**
- Modify: `crates/ergo-testkit/src/lib.rs` (or existing integration test file)

**Context:** Verify the processor thread works end-to-end: store a header via ProcessorCommand, get HeadersApplied event back, store block sections, get BlockApplied back. This tests the full channel round-trip without a live network.

**Step 1: Write integration test**

```rust
#[test]
fn processor_thread_stores_header_and_applies_block() {
    // 1. Create temp dir, open HistoryDb.
    // 2. Spawn processor thread with real NodeViewHolder.
    // 3. Send StorePrevalidatedHeader for a genesis header.
    // 4. Expect HeadersApplied event with to_download.
    // 5. Send StoreModifier for each block section.
    // 6. Send ApplyFromCache.
    // 7. Expect BlockApplied event.
    // 8. Send Shutdown, join thread.
}
```

**Step 2: Run test**

Run: `cargo test -p ergo-testkit processor_thread -- --nocapture`
Expected: Pass.

**Step 3: Commit**

```bash
git add crates/ergo-testkit/src/lib.rs
git commit -m "test(testkit): add integration test for processor thread channel flow"
```

---

### Task 12: Final verification and cleanup

**Files:**
- All modified files

**Step 1: Run full test suite**

Run: `cargo test --workspace`
Expected: All tests pass.

**Step 2: Run clippy**

Run: `cargo clippy --workspace -- -D warnings`
Expected: 0 warnings.

**Step 3: Verify binary compiles and starts**

Run: `cargo build --release -p ergo-node`
Expected: Compiles.

**Step 4: Smoke test**

Start the node, verify:
- Headers sync proceeds without blocking
- Status tick fires every 10s (not 2+ minutes)
- Block download starts after headers catch up
- Graceful shutdown works

**Step 5: Final commit if any cleanup needed**

```bash
git commit -m "chore: final cleanup for non-blocking block processor"
```
