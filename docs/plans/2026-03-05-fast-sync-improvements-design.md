# Fast Sync Improvements Design

**Goal:** Eliminate slow-peer pipeline stalls, increase the lookahead buffer, and replace per-header RocksDB writes with per-chunk bulk writes — raising fast header sync throughput from ~1,280 h/s to an estimated 4,000–8,000 h/s.

**Architecture:** Three independent improvements delivered as separate commits. A (work-stealing queue + per-peer timeout) fixes slow-peer stalls. B (MAX_LOOKAHEAD + cache resize) gives the pipeline more headroom. C (BulkHeaders processor command) removes the write-per-header bottleneck.

**Tech stack:** `fast_header_sync.rs`, `block_processor.rs`, `modifiers_cache.rs`, `node_view.rs`, `history_db.rs`. No new crates required.

---

## Background: why the processor is the bottleneck

Fast sync has two concurrent stages:

```
Network fetch (HTTP)                    Processor thread (RocksDB writes)
────────────────────                    ──────────────────────────────────
peer1 ──┐                               recv header → validate → write RocksDB
peer2 ──┼─ cmd_tx channel (capacity 2048) → apply to chain state → update index
peer3 ──┘
```

From the sync log (335,872 headers, 207s run):
- Network fetch rate: ~1,620 h/s
- Processor drain rate: ~1,279 h/s
- Throttle events: 491 (MAX_LOOKAHEAD=80,000 fills in ~50s and stays full)
- Slow peer dips: 5 peers took 75–88s per chunk, dropping throughput to 341 h/s

The processor writes one header at a time (one RocksDB put per header). Bulk batching amortizes WAL flushes across a whole chunk (2,047 headers → 1 write).

---

## Improvement A: Work-Stealing Queue + Per-Peer Timeout

**File:** `crates/ergo-node/src/fast_header_sync.rs`

### Current problem

The current dispatcher pre-builds all chunks into a `Vec`, dispatches them sequentially to idle peers, collects all results, then does a serial retry pass for failed chunks. A peer taking 88s holds its chunk slot for 88s before the chunk enters the retry queue.

### Design

Replace the Vec + retry-pass with a shared `VecDeque` work-stealing queue:

```rust
const PEER_FETCH_TIMEOUT_SECS: u64 = 20;

let pending: Arc<Mutex<VecDeque<(u32, u32)>>> =
    Arc::new(Mutex::new(chunks.into_iter().collect()));
```

Dispatcher loop (replaces the current `for (from, to) in &chunks` loop):
1. Pop the next `(from, to)` from the front of `pending`. If empty, done.
2. Apply the lookahead throttle (unchanged logic).
3. Wait for an idle healthy peer.
4. Spawn a task with `tokio::time::timeout(Duration::from_secs(PEER_FETCH_TIMEOUT_SECS), fetch_and_validate_chunk(...))`.
5. On success: mark peer idle, notify dispatcher.
6. On timeout or error: increment peer failure count; push `(from, to)` back to the **front** of `pending`; mark peer idle.

No retry pass needed — failed chunks re-enter the queue immediately and are picked up by the next idle peer.

The outer `reqwest::Client` timeout stays at 30s (acts as a hard ceiling). `PEER_MAX_FAILURES = 3` (blacklist after 3 consecutive failures) is unchanged.

### Expected outcome

Slow peers that exceed 20s are immediately reassigned. The 75–88s trough windows (341 h/s) are eliminated. Peak throughput during slow-peer periods goes from 341 h/s back to 2,800+ h/s.

---

## Improvement B: MAX_LOOKAHEAD + ModifiersCache Resize

**Files:** `crates/ergo-node/src/fast_header_sync.rs`, `crates/ergo-network/src/modifiers_cache.rs`

### Design

Two constant changes:

```rust
// fast_header_sync.rs
const MAX_LOOKAHEAD: u32 = 200_000;  // was 80_000

// modifiers_cache.rs (with_default_capacities)
const DEFAULT_HEADER_CAPACITY: usize = 32_768;  // was 8_192
```

**Memory cost:** Each cached header holds raw bytes (~300 bytes) + parsed `Header` struct (~200 bytes) ≈ 500 bytes. 32,768 × 500 = ~16 MB added ceiling. Acceptable.

**Why both must change together:** The `process_prevalidated_header` fast-path caches any header where `height > best_height + 1`. With MAX_LOOKAHEAD=200,000 and 13 concurrent peers × 2,047 h/chunk = ~26,000 headers potentially in-flight, the cache must hold at least that many without evicting headers the processor needs next. 32,768 covers this comfortably.

### Expected outcome

Fast sync can keep all peers busy for longer before hitting the throttle (~123s at 1,620 h/s vs ~49s previously). Combined with A, this keeps the pipeline full even when some peers are slow.

---

## Improvement C: BulkHeaders Processor Command

**Files:** `crates/ergo-network/src/block_processor.rs`, `crates/ergo-network/src/node_view.rs`, `crates/ergo-storage/src/history_db.rs`, `crates/ergo-node/src/fast_header_sync.rs`

### New command variant

```rust
// block_processor.rs
pub enum ProcessorCommand {
    // ... existing variants ...

    /// A pre-sorted batch of PoW-validated headers from fast sync.
    /// Headers are in ascending height order within the batch.
    BulkHeaders {
        headers: Vec<(ModifierId, Box<Header>, Vec<u8>)>, // (id, header, raw_bytes)
    },
}
```

### Processor handler: `process_bulk_headers`

```rust
fn process_bulk_headers(
    state: &mut ProcessorState,
    evt_tx: &tokio::sync::mpsc::Sender<ProcessorEvent>,
    headers: Vec<(ModifierId, Box<Header>, Vec<u8>)>,
    accum: &mut BatchAccum<'_>,
) {
    // In-memory map for parent lookups within this bulk call.
    let mut in_flight: HashMap<ModifierId, Header> = HashMap::new();
    let mut batch = WriteBatch::default();

    for (id, header, raw) in headers {
        // Find parent: check in_flight first (headers applied earlier in this
        // bulk call), then fall back to the DB.
        let parent_opt = in_flight.get(&header.parent_id)
            .cloned()
            .or_else(|| state.node_view.history.load_header(&header.parent_id).ok().flatten());

        let Some(parent) = parent_opt else {
            // Parent not yet available — put into cache for later.
            state.cache.put(id, HEADER_TYPE_ID, raw, Some(*header));
            continue;
        };

        // Validate against parent (height, timestamp, version, difficulty).
        if let Err(e) = validate_child_header_skip_pow(&header, &parent, now_ms(), None, MAX_DRIFT) {
            tracing::warn!(height = header.height, %e, "bulk: header rejected");
            continue;
        }

        // Accumulate writes into batch (objects CF + indexes CF).
        history_db_batch_put_header(&mut batch, &id, &header, &raw);

        in_flight.insert(id, *header);
        accum.new_headers.push(id);
    }

    // Single WAL flush for all headers in this chunk.
    if let Err(e) = state.node_view.history.write_batch(batch) {
        tracing::error!(%e, "bulk: batch write failed");
    }

    // Update best_header_id to reflect the highest applied header.
    state.node_view.history.update_best_header_from_in_flight(&in_flight);
}
```

### HistoryDb additions

- `pub fn write_batch(&self, batch: WriteBatch) -> Result<(), StorageError>` — thin wrapper over `self.db.raw().write(batch)`.
- `pub fn batch_put_header(batch: &mut WriteBatch, db: &NodeDb, id: &ModifierId, raw: &[u8])` — writes to `cf_objects` and `cf_indexes` (height→id) without committing.
- `pub fn update_best_header(&self, id: &ModifierId, header: &Header) -> Result<(), StorageError>` — updates the best header key in `cf_indexes`.

### fast_header_sync change

In `fetch_and_validate_chunk`: instead of the per-header `cmd_tx.try_send(StorePrevalidatedHeader {...})` loop, accumulate all validated headers into a `Vec` and send one command:

```rust
cmd_tx.try_send(ProcessorCommand::BulkHeaders { headers: validated })?;
```

The `ApplyFromCache` send at the end of the chunk is unchanged.

### Edge cases

- **Parent not in DB or in_flight:** header is cached via `state.cache.put(...)` and will be applied by the next `apply_from_cache` drain.
- **Invalid header mid-batch:** log and skip. Does not abort the batch — remaining valid headers continue.
- **WriteBatch failure:** log error. The headers in `accum.new_headers` will not actually be in the DB, which may cause downstream parent-not-found errors for dependent headers. These will self-heal when the next P2P or fast_sync delivers the missing chunk.

### Expected outcome

One WAL flush per chunk (2,047 headers) vs one per header. Processor throughput target: 4,000–8,000 h/s (3–6× improvement), eliminating the processor as the bottleneck entirely.

---

## Testing

- All existing `cargo test --workspace` tests must pass after each commit.
- Unit test for `process_bulk_headers`: send 10 sequential headers in one bulk command, verify all are stored and `new_headers` has 10 entries.
- Unit test for timeout reassign: mock a slow peer (returns after 25s), verify chunk is reassigned to a second peer within 25s.
- Integration: run `ergo-testkit` pipeline tests unchanged.
