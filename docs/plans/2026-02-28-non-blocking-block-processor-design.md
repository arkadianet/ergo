# Non-Blocking Block Processor Design

## Problem

The Ergo Rust node's event loop runs on a single tokio task with 13+ `select!` branches. Block validation (`validate_and_apply_block`) runs synchronously inline, blocking the entire event loop for up to 2 minutes during heavy sync. This starves header sync, peer management, SyncInfo exchange, and status ticks.

Profiling during v1 header sync (heights 1303-27858) showed:
- 47.5% CPU: blake2b hashing (PoW + header IDs)
- 21.2% CPU: EC point arithmetic (v1 PoW verification)
- 9.3% CPU: RocksDB reads

## Design: Dedicated Processor Thread + Rayon Parallel Validation

### Architecture Overview

Split the event loop into two halves:

1. **Event loop (tokio task)**: Thin message router. Handles network I/O, peer management, sync protocol, parallel header PoW (rayon, already implemented). Sends block sections to processor via bounded channel.

2. **Processor thread (std::thread)**: Owns `NodeViewHolder`, `ModifiersCache`, and a `rayon::ThreadPool`. Receives commands, validates blocks, applies state changes. Sends results back via channel.

This matches the Scala node's approach (NodeViewHolder on a dedicated `critical-dispatcher` with 2 threads, separate from the network dispatcher) while being simpler than a full actor system.

### Section 1: Channel Architecture

```
Event Loop                          Processor Thread
    |                                      |
    |--- ProcessorCommand (bounded) ------>|
    |                                      |
    |<--- ProcessorEvent (bounded) --------|
    |                                      |
```

**ProcessorCommand** (event loop -> processor):
- `StoreModifier { type_id, modifier_id, data }` — raw modifier bytes from network
- `StorePrevalidatedHeader { modifier_id, header }` — already parsed + PoW-validated header
- `ApplyFromCache` — trigger cache drain after storing modifiers
- `Shutdown` — graceful stop

**ProcessorEvent** (processor -> event loop):
- `HeadersApplied { new_best: Option<ModifierId>, to_download: Vec<(u8, ModifierId)> }` — header stored, may need block sections
- `BlockApplied { header_id: ModifierId, height: u32 }` — full block validated and applied
- `ModifierCached { type_id, modifier_id }` — stored in cache (missing dependencies)
- `ValidationFailed { modifier_id, peer_hint: Option<PeerId>, error: String }` — for penalty dispatch
- `StateUpdate { headers_height, full_height, best_header_id, best_full_id }` — periodic state snapshot for /info API

Channel sizing: 256 commands, 256 events. `try_send()` from event loop — if full, log warning and drop (back-pressure signal).

### Section 2: Processor Thread Lifecycle

```rust
let (cmd_tx, cmd_rx) = std::sync::mpsc::sync_channel::<ProcessorCommand>(256);
let (evt_tx, evt_rx) = std::sync::mpsc::sync_channel::<ProcessorEvent>(256);

std::thread::spawn(move || {
    let mut node_view = NodeViewHolder::new(...);
    let mut cache = ModifiersCache::new(8192, 384);
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(num_cpus::get().min(4))
        .build()
        .unwrap();
    let mut batch = Vec::with_capacity(64);

    loop {
        // Block waiting for first command (no busy-spin)
        match cmd_rx.recv_timeout(Duration::from_millis(100)) {
            Ok(cmd) => batch.push(cmd),
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => break,
        }

        // Drain up to 63 more without blocking
        while batch.len() < 64 {
            match cmd_rx.try_recv() {
                Ok(cmd) => batch.push(cmd),
                Err(_) => break,
            }
        }

        for cmd in batch.drain(..) {
            match cmd {
                ProcessorCommand::Shutdown => return,
                ProcessorCommand::StoreModifier { .. } => { /* process */ },
                ProcessorCommand::StorePrevalidatedHeader { .. } => { /* process */ },
                ProcessorCommand::ApplyFromCache => { /* drain cache */ },
            }
        }
    }
});
```

The processor thread:
- Owns `NodeViewHolder` (not Send — constructed on the processor thread itself)
- Blocks on `recv_timeout(100ms)` to avoid busy-spinning
- Drains batches of up to 64 commands per iteration
- Sends `ProcessorEvent`s back for each processed item

### Section 3: Parallel Validation via Rayon

Block validation has 8 stages. Some are embarrassingly parallel, others require sequential state access:

| Stage | Description | Parallel? | Where |
|-------|------------|-----------|-------|
| 1 | Assemble full block | No | Processor |
| 2 | Structural validation | No | Processor |
| 3 | Difficulty check | No | Processor |
| 4 | Parse transactions | **Yes** | Rayon pool |
| 5a | Stateless tx validation | **Yes** | Rayon pool |
| 5b | Stateful UTXO lookups | No | Processor |
| 5c | Sigma proof verification | **Yes** | Rayon pool |
| 6 | Apply state changes | No | Processor |
| 7 | Mark valid, update best | No | Processor |
| 8 | Mempool eviction | No | Processor |

Stages 4, 5a, and 5c are pure functions of the transaction data and can run on the rayon pool. The processor thread orchestrates: run parallel stages, collect results, proceed with sequential stages.

```rust
// Parallel: parse + stateless validate all txs
let results: Vec<Result<ParsedTx, Error>> = pool.install(|| {
    block.transactions.par_iter()
        .map(|tx_bytes| {
            let tx = parse_transaction(tx_bytes)?;
            validate_tx_stateless(&tx)?;
            Ok(tx)
        })
        .collect()
});

// Sequential: stateful validation + state apply
for tx in &parsed_txs {
    validate_tx_stateful(tx, &utxo_state)?;
}
apply_state_changes(&mut utxo_state, &parsed_txs)?;
```

### Section 4: Event Loop Changes

The event loop becomes a thin router:

```rust
// In select! loop:
msg = peer_rx.recv() => {
    match msg {
        Modifiers(mods) => {
            // Header path: parallel PoW (rayon, stays here), then send to processor
            if type_id == HEADER_TYPE_ID {
                let validated = rayon_validate_headers(&mods); // existing code
                for (id, header) in validated {
                    let _ = cmd_tx.try_send(ProcessorCommand::StorePrevalidatedHeader { id, header });
                }
            } else {
                // Block sections: forward to processor
                for (id, data) in mods {
                    let _ = cmd_tx.try_send(ProcessorCommand::StoreModifier { type_id, id, data });
                }
            }
            let _ = cmd_tx.try_send(ProcessorCommand::ApplyFromCache);
        }
        // ... other message types handled locally
    }
}

evt = processor_event_rx.recv() => {
    match evt {
        ProcessorEvent::HeadersApplied { to_download, .. } => {
            sync_mgr.on_headers_received(&to_download, &history_ro);
        }
        ProcessorEvent::BlockApplied { header_id, height } => {
            delivery_tracker.set_received(...);
            // Update local height tracking
        }
        ProcessorEvent::ValidationFailed { modifier_id, error, .. } => {
            penalty_mgr.penalize(peer, PenaltyType::InvalidBlock);
        }
        ProcessorEvent::StateUpdate { .. } => {
            // Cache for /info endpoint
        }
    }
}
```

Key: `try_send()` everywhere. If the processor is backed up, modifiers are dropped with a warning — the delivery tracker will re-request them.

### Section 5: What Stays vs What Moves

**Stays in event loop:**
- SyncInfo exchange and peer sync status
- Inv/RequestModifier protocol
- Peer management (connect, disconnect, penalty)
- SyncManager state machine
- DeliveryTracker (request/receive tracking)
- Parallel header PoW validation (rayon, already implemented)
- ModifierTracker (requested/received/invalid status)
- API request handling (via read-only HistoryDb)

**Moves to processor thread:**
- `NodeViewHolder` (HistoryDb write handle, UtxoState, DigestState, VotingState)
- `ModifiersCache` (out-of-order modifier storage)
- `validate_and_apply_block` (full 8-stage pipeline)
- `apply_from_cache` (iterative cache drain)
- `process_modifier` / `process_prevalidated_header`
- Mempool mutations (eviction on block apply)
- Block pruning

### Section 6: HistoryDb Dual Handles

Already proven pattern — the API server uses `HistoryDb::open_read_only` for concurrent access:

```rust
// Processor thread: read-write
let history_rw = HistoryDb::open(&history_path)?;

// Event loop: read-only (for sync protocol lookups)
let history_ro = HistoryDb::open_read_only(&history_path)?;
```

The event loop needs read-only access for:
- `has_all_sections()` — check if block is complete
- `load_header()` — for SyncInfo continuation IDs
- `best_header_id()` / `best_full_block_id()` — for sync state
- Height index lookups

RocksDB handles concurrent readers + single writer natively.

### Section 7: Error Handling and Shutdown

**Processor panics**: Wrap the processor loop in `std::panic::catch_unwind`. If it panics, send a fatal event to the event loop, which triggers graceful shutdown.

**Channel full (try_send fails)**: Log warning, drop the command. DeliveryTracker will time out and re-request the modifier from a peer. This provides natural back-pressure.

**Graceful shutdown**:
1. Event loop sends `ProcessorCommand::Shutdown`
2. Processor drains remaining commands, finishes current block
3. Processor drops `NodeViewHolder` (flushes RocksDB)
4. Processor thread exits
5. Event loop detects channel disconnect, completes shutdown

## Migration Path

The processor thread is an internal refactor — no protocol changes, no API changes, no config changes. The network sees the same behavior, just faster.

## References

- Scala Ergo: `NodeViewHolder` on `critical-dispatcher` (2 dedicated threads via Akka)
- ergo-rust-node: Three-layer channel pipeline with `try_send()` and 50k buffers
