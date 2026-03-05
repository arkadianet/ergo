# Fast Sync Improvements Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Raise fast header sync throughput from ~1,280 h/s to 4,000–8,000 h/s via three improvements: work-stealing peer queue (A), lookahead increase (B), and bulk RocksDB writes (C).

**Architecture:** Three independent commits. A refactors `run_fast_sync` to use a `VecDeque` work-stealing queue with a 20s per-peer timeout. B bumps one constant. C adds a `bulk_store_headers` helper in `header_store.rs`, a `BulkHeaders` command in `block_processor.rs`, and wires it from `fetch_and_validate_chunk`.

**Tech Stack:** `tokio::time::timeout`, `std::collections::VecDeque`, `rocksdb::WriteBatch`, existing `HistoryBatch`, `add_scores`/`difficulty_from_nbits` from `chain_scoring.rs`.

---

## Key file map

```
crates/ergo-node/src/fast_header_sync.rs   — run_fast_sync, fetch_and_validate_chunk
crates/ergo-network/src/block_processor.rs — ProcessorCommand enum, processor loop
crates/ergo-storage/src/header_store.rs    — store_header_with_score, new bulk_store_headers
crates/ergo-storage/src/chain_scoring.rs   — add_scores(), difficulty_from_nbits()
crates/ergo-storage/src/history_db.rs      — HistoryBatch (put_modifier, put_index, write)
```

Important constants / types you need to know:
- `HEADER_TYPE_ID = 101u8` (in header_store.rs and block_processor.rs)
- `height_ids_key(height: u32) -> [u8;32]` — key for "list of header IDs at this height" (history_db.rs)
- `header_height_key(id)`, `best_header_key()`, `header_score_key(id)` — index key helpers (history_db.rs)
- `HistoryBatch::put_modifier(type_id, id, data)` / `put_index(key, value)` / `write(self)` — batch API (history_db.rs)
- `add_scores(a: &[u8], b: &[u8]) -> Vec<u8>` — adds two big-endian score byte arrays (chain_scoring.rs)
- `difficulty_from_nbits(n_bits: u64) -> Vec<u8>` — converts nBits to difficulty bytes (chain_scoring.rs)
- `HistoryDb::is_score_greater(a: &[u8], b: &[u8]) -> bool` — score comparator (chain_scoring.rs)

---

## Task 1: B — Bump MAX_LOOKAHEAD

**Files:**
- Modify: `crates/ergo-node/src/fast_header_sync.rs:339`

The ModifiersCache header capacity is already 100,000 (checked in `modifiers_cache.rs:21`). Only the lookahead constant needs changing.

**Step 1: Edit the constant**

In `fast_header_sync.rs`, find line 339:
```rust
const MAX_LOOKAHEAD: u32 = 80_000;
```
Change to:
```rust
const MAX_LOOKAHEAD: u32 = 200_000;
```

**Step 2: Verify tests pass**

```bash
cargo test --workspace
```
Expected: all tests pass (this is a pure constant change).

**Step 3: Commit**

```bash
git add crates/ergo-node/src/fast_header_sync.rs
git commit -m "perf(fast-sync): increase MAX_LOOKAHEAD from 80k to 200k"
```

---

## Task 2: A — Work-stealing queue + per-peer timeout

**Files:**
- Modify: `crates/ergo-node/src/fast_header_sync.rs` — `run_fast_sync` function (lines ~242–513)

**Context:** The current code pre-builds all chunks into a `Vec`, dispatches them in a `for` loop, collects all `JoinHandle`s, and then runs a serial retry pass. A slow peer (88s) blocks its chunk slot for 88s before retrying. The fix replaces the Vec with a shared `VecDeque`; failed chunks are pushed back to the front immediately for any idle peer to pick up. A 20s `tokio::time::timeout` per fetch replaces the 120s client timeout as the reassignment trigger.

**Step 1: Write a failing test**

At the bottom of `fast_header_sync.rs`, in the `#[cfg(test)]` block, add:

```rust
#[test]
fn timeout_constant_is_reasonable() {
    // PEER_FETCH_TIMEOUT_SECS must exist and be between 10 and 60.
    assert!(PEER_FETCH_TIMEOUT_SECS >= 10);
    assert!(PEER_FETCH_TIMEOUT_SECS <= 60);
}
```

**Step 2: Run to verify it fails**

```bash
cargo test -p ergo-node fast_header_sync::tests::timeout_constant_is_reasonable
```
Expected: compile error — `PEER_FETCH_TIMEOUT_SECS` is not defined yet.

**Step 3: Implement the work-stealing refactor**

Replace the entire `run_fast_sync` function body (from `use std::collections...` on line ~252 to the closing `}` of the function on line ~513) with the implementation below.

**Add the constant** near the top of the file, after `PEER_MAX_FAILURES`:
```rust
/// If a peer does not return a chunk within this many seconds, cancel the
/// request, increment its failure count, and push the chunk back to the
/// front of the work queue for immediate reassignment to another peer.
const PEER_FETCH_TIMEOUT_SECS: u64 = 20;
```

**Replace `run_fast_sync` body:**

```rust
pub async fn run_fast_sync(
    api_urls: ApiPeerUrls,
    our_height: u32,
    chunk_size: u32,
    max_concurrent: u32,
    cmd_tx: std::sync::mpsc::SyncSender<ergo_network::block_processor::ProcessorCommand>,
    shutdown: tokio::sync::watch::Receiver<bool>,
    current_headers_height: SharedHeadersHeight,
    fast_sync_active: SharedFastSyncActive,
) {
    use std::collections::{HashMap, HashSet, VecDeque};
    use std::sync::Arc;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30)) // hard ceiling; 20s timeout fires first
        .build()
        .unwrap();

    // Wait for at least one peer to advertise a REST API URL (up to 60s).
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        if *shutdown.borrow() {
            return;
        }
        let urls: Vec<String> = api_urls.read().unwrap().values().cloned().collect();
        if !urls.is_empty() {
            tracing::info!(peers = urls.len(), "fast_header_sync: found API peers");
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            tracing::info!("fast_header_sync: no peers with REST API URLs after 60s, giving up");
            return;
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }

    // Discover best height from available peers.
    let mut best_height = 0u32;
    {
        let urls: Vec<String> = api_urls.read().unwrap().values().cloned().collect();
        for url in &urls {
            match fetch_peer_height(&client, url).await {
                Ok(h) => {
                    best_height = h;
                    tracing::info!(height = h, url, "fast_header_sync: discovered chain height");
                    break;
                }
                Err(e) => {
                    tracing::warn!(url, error = %e, "fast_header_sync: failed to query /info");
                }
            }
        }
    }

    if best_height <= our_height {
        tracing::info!(our_height, best_height, "fast_header_sync: already synced");
        return;
    }

    const HANDOFF_DISTANCE: u32 = 1000;
    let target = best_height.saturating_sub(HANDOFF_DISTANCE);
    if target <= our_height {
        tracing::info!("fast_header_sync: within handoff distance, P2P will handle");
        return;
    }

    let chunks = compute_chunks(our_height, target, chunk_size);
    tracing::info!(
        chunks = chunks.len(),
        from = our_height + 1,
        to = target,
        chunk_size,
        max_concurrent,
        "fast_header_sync: starting parallel fetch"
    );

    fast_sync_active.store(true, std::sync::atomic::Ordering::Relaxed);

    // Work-stealing queue: failed chunks are pushed back to the front for
    // immediate reassignment to the next idle peer.
    let pending: Arc<std::sync::Mutex<VecDeque<(u32, u32)>>> =
        Arc::new(std::sync::Mutex::new(chunks.into_iter().collect()));

    let peer_failures: Arc<std::sync::RwLock<HashMap<String, u32>>> =
        Arc::new(std::sync::RwLock::new(HashMap::new()));
    let busy_peers: Arc<std::sync::Mutex<HashSet<String>>> =
        Arc::new(std::sync::Mutex::new(HashSet::new()));
    let peer_idle = Arc::new(tokio::sync::Notify::new());

    let client = Arc::new(client);
    let cmd_tx = Arc::new(cmd_tx);

    let mut handles = Vec::new();
    let mut total = 0usize;

    loop {
        if *shutdown.borrow() {
            break;
        }

        // Pop the next chunk from the front of the work queue.
        let chunk = pending.lock().unwrap().pop_front();
        let Some((from, to)) = chunk else {
            break; // all chunks dispatched (or pushed back and retried)
        };

        // Skip chunks that P2P sync has already covered.
        let p2p_height = current_headers_height.load(std::sync::atomic::Ordering::Relaxed);
        if p2p_height >= to {
            tracing::debug!(from, to, p2p_height, "fast_header_sync: skipping (P2P ahead)");
            continue;
        }

        // Throttle: don't dispatch a chunk more than MAX_LOOKAHEAD headers
        // ahead of the processor. Spin until the processor catches up.
        loop {
            if *shutdown.borrow() {
                break;
            }
            let processor_height =
                current_headers_height.load(std::sync::atomic::Ordering::Relaxed);
            if from <= processor_height + MAX_LOOKAHEAD {
                break;
            }
            tracing::debug!(
                from,
                processor_height,
                gap = from - processor_height,
                "fast_header_sync: throttling (too far ahead)"
            );
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }

        // Wait for an idle, healthy peer under the concurrency cap.
        let url = loop {
            if *shutdown.borrow() {
                break None;
            }
            let candidate = {
                let all_urls: Vec<String> =
                    api_urls.read().unwrap().values().cloned().collect();
                let busy = busy_peers.lock().unwrap();
                let failures = peer_failures.read().unwrap();
                all_urls
                    .into_iter()
                    .filter(|u| !busy.contains(u))
                    .find(|u| failures.get(u).copied().unwrap_or(0) < PEER_MAX_FAILURES)
            };
            if let Some(url) = candidate {
                let busy_count = busy_peers.lock().unwrap().len() as u32;
                if busy_count < max_concurrent {
                    break Some(url);
                }
            }
            tokio::select! {
                _ = peer_idle.notified() => {}
                _ = tokio::time::sleep(std::time::Duration::from_secs(2)) => {}
            }
        };

        let Some(url) = url else {
            break; // shutdown
        };

        busy_peers.lock().unwrap().insert(url.clone());

        let client = client.clone();
        let cmd_tx = cmd_tx.clone();
        let peer_failures = peer_failures.clone();
        let busy_peers = busy_peers.clone();
        let peer_idle = peer_idle.clone();
        let pending = pending.clone();

        handles.push(tokio::spawn(async move {
            // Race the fetch against the per-peer timeout.  A timeout counts
            // as a failure: the chunk is pushed back for reassignment.
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(PEER_FETCH_TIMEOUT_SECS),
                fetch_and_validate_chunk(client.as_ref(), &url, from, to, cmd_tx.as_ref()),
            )
            .await;

            let result: Result<usize, FastSyncError> = match result {
                Ok(r) => r,
                Err(_elapsed) => Err(FastSyncError::Http(format!(
                    "peer {url} timed out after {PEER_FETCH_TIMEOUT_SECS}s"
                ))),
            };

            match &result {
                Ok(count) => {
                    tracing::debug!(from, to, count, peer = url, "fast_header_sync: chunk done");
                    peer_failures.write().unwrap().remove(&url);
                }
                Err(e) => {
                    tracing::debug!(from, to, peer = url, error = %e, "fast_header_sync: chunk failed, requeueing");
                    // Push the chunk back to the FRONT so the next idle peer
                    // picks it up immediately.
                    pending.lock().unwrap().push_front((from, to));
                    let mut failures = peer_failures.write().unwrap();
                    let count = failures.entry(url.clone()).or_insert(0);
                    *count += 1;
                    if *count >= PEER_MAX_FAILURES {
                        tracing::warn!(peer = url, "fast_header_sync: peer blacklisted");
                    }
                }
            }

            busy_peers.lock().unwrap().remove(&url);
            peer_idle.notify_one();

            result
        }));
    }

    // Wait for all in-flight tasks.
    let mut errors = 0usize;
    for handle in handles {
        match handle.await {
            Ok(Ok(count)) => total += count,
            Ok(Err(_)) => errors += 1,
            Err(_) => errors += 1,
        }
    }

    fast_sync_active.store(false, std::sync::atomic::Ordering::Relaxed);

    tracing::info!(
        total_headers = total,
        errors,
        "fast_header_sync: parallel fetch complete"
    );
}
```

Note: the `fetch_and_validate_chunk` function signature and body are **unchanged**.

**Step 4: Run the test to verify it passes**

```bash
cargo test -p ergo-node fast_header_sync::tests::timeout_constant_is_reasonable
```
Expected: PASS.

**Step 5: Run full tests**

```bash
cargo test --workspace
```
Expected: all tests pass.

**Step 6: Commit**

```bash
git add crates/ergo-node/src/fast_header_sync.rs
git commit -m "perf(fast-sync): work-stealing queue with 20s per-peer timeout"
```

---

## Task 3: C1 — `HistoryDb::bulk_store_headers`

**Files:**
- Modify: `crates/ergo-storage/src/header_store.rs`

**Context:** `store_header_with_score` (already in `header_store.rs`) creates one `HistoryBatch` per header and commits it immediately. The bulk version creates ONE batch for all N headers in a chunk. Parent score lookups first check an in-memory map (for parents applied earlier in the same bulk call), then fall back to the DB. Height-ID lists are read once per height and updated in-memory. One `batch.write()` at the end.

**Step 1: Write a failing test**

At the bottom of `header_store.rs` in the `#[cfg(test)]` block (look at existing tests like `store_header_sequential` for the pattern — tests use `HistoryDb::open(tmpdir.path())`), add:

```rust
#[test]
fn bulk_store_headers_applies_five_sequential() {
    use ergo_types::header::Header;
    use ergo_types::modifier_id::ModifierId;

    let tmp = tempfile::tempdir().unwrap();
    let db = crate::history_db::HistoryDb::open(tmp.path()).unwrap();

    // Build 5 sequential headers (genesis + 4 children).
    // Use Header::default_for_test() and override height/parent_id.
    // Header::default_for_test() is defined in ergo-types and creates a
    // valid header with zeroed fields. For test purposes the scores and
    // parent links don't need to reflect real chain difficulty.
    let ids: Vec<ModifierId> = (0u8..5).map(|i| ModifierId([i + 1; 32])).collect();
    let raws: Vec<Vec<u8>> = ids.iter().map(|_| vec![0xAAu8; 10]).collect();

    let headers: Vec<(ModifierId, ergo_types::header::Header, Vec<u8>)> = ids
        .iter()
        .zip(raws.iter())
        .enumerate()
        .map(|(i, (id, raw))| {
            let mut h = Header::default_for_test();
            h.height = (i + 1) as u32;
            h.parent_id = if i == 0 {
                ModifierId::GENESIS_PARENT
            } else {
                ids[i - 1]
            };
            (*id, h, raw.clone())
        })
        .collect();

    let applied = db.bulk_store_headers(&headers).unwrap();
    assert_eq!(applied.len(), 5);

    // Every header should now be retrievable.
    for (id, header, _) in &headers {
        let loaded = db.load_header(id).unwrap();
        assert!(loaded.is_some(), "header at height {} not found", header.height);
    }

    // Best header should be the last one (height 5).
    let best_id = db.best_header_id().unwrap().unwrap();
    assert_eq!(best_id, ids[4]);
}
```

**Step 2: Run to verify it fails**

```bash
cargo test -p ergo-storage header_store::tests::bulk_store_headers_applies_five_sequential
```
Expected: compile error — `bulk_store_headers` does not exist.

**Step 3: Implement `bulk_store_headers`**

Add the following method to the `impl HistoryDb` block in `header_store.rs` (after `store_header_with_score`).

You will need these imports at the top of the file (add them alongside the existing imports if not already present):
```rust
use std::collections::HashMap;
use ergo_wire::header_ser::serialize_header;
use crate::chain_scoring::{add_scores, difficulty_from_nbits};
use crate::history_db::{
    best_header_key, header_height_key, header_score_key, height_ids_key,
    HistoryDb, StorageError,
};
```

Method implementation:

```rust
/// Store a batch of pre-validated, height-sorted headers in a single
/// `WriteBatch`, amortizing WAL flushes across the whole chunk.
///
/// `headers` must be sorted by height ascending.  If `raw` is `None` for
/// an entry the header is re-serialized on-the-fly via `serialize_header`.
///
/// Parent score lookups first check `in_flight_scores` (built up during
/// this call) before falling back to the DB, so headers within the same
/// batch can reference each other as parents.
///
/// Returns the IDs of headers that were successfully stored (skips
/// duplicates that are already in the DB).
pub fn bulk_store_headers(
    &self,
    headers: &[(ModifierId, ergo_types::header::Header, Vec<u8>)],
) -> Result<Vec<ModifierId>, StorageError> {
    if headers.is_empty() {
        return Ok(Vec::new());
    }

    // In-memory maps to avoid DB reads for items set within this batch.
    // Keys are ModifierId; values are big-endian cumulative score bytes.
    let mut in_flight_scores: HashMap<ModifierId, Vec<u8>> = HashMap::new();
    // height -> list of IDs at that height (read-on-first-use from DB).
    let mut height_ids_cache: HashMap<u32, Vec<ModifierId>> = HashMap::new();

    // Load current best score (to check whether any bulk header beats it).
    let mut best_score: Vec<u8> = self
        .best_header_id()?
        .and_then(|id| self.get_header_score(&id).ok()?)
        .unwrap_or_else(|| vec![0u8]);
    let mut best_id_candidate: Option<ModifierId> = None;

    let mut batch = self.new_batch();
    let mut applied: Vec<ModifierId> = Vec::with_capacity(headers.len());

    for (id, header, raw) in headers {
        // Skip duplicates.
        if self.contains_modifier(HEADER_TYPE_ID, id)? {
            continue;
        }

        // Compute cumulative score.
        let parent_score: Vec<u8> = in_flight_scores
            .get(&header.parent_id)
            .cloned()
            .or_else(|| self.get_header_score(&header.parent_id).ok()?)
            .unwrap_or_else(|| vec![0u8]);
        let our_score = add_scores(&parent_score, &difficulty_from_nbits(header.n_bits));

        // 1. Store the raw header bytes (type_id = 101).
        //    Use provided raw bytes; they were already serialized by
        //    fast_sync's json_header_to_wire, so no re-serialization needed.
        batch.put_modifier(HEADER_TYPE_ID, id, raw);

        // 2. Height -> IDs index.
        //    Read the existing list once per height, cache in memory.
        let height_key = height_ids_key(header.height);
        let ids_at_height = height_ids_cache
            .entry(header.height)
            .or_insert_with(|| self.header_ids_at_height(header.height).unwrap_or_default());
        if !ids_at_height.contains(id) {
            ids_at_height.push(*id);
        }
        batch.put_index(&height_key, &serialize_id_list(ids_at_height));

        // 3. Header -> height index.
        let h_key = header_height_key(id);
        batch.put_index(&h_key, &header.height.to_be_bytes());

        // 4. Cumulative score.
        let s_key = header_score_key(id);
        batch.put_index(&s_key, &our_score);

        // Track best header by score.
        if Self::is_score_greater(&our_score, &best_score) {
            best_score = our_score.clone();
            best_id_candidate = Some(*id);
        }

        in_flight_scores.insert(*id, our_score);
        applied.push(*id);
    }

    // Update best header pointer if any header in this batch beats the
    // current best.
    if let Some(best_id) = best_id_candidate {
        batch.put_index(&best_header_key(), &best_id.0);
    }

    batch.write()?;
    Ok(applied)
}
```

Note: `serialize_id_list` is a private free function already in `header_store.rs`. Use it directly (it's in the same file).

**Step 4: Run the test to verify it passes**

```bash
cargo test -p ergo-storage header_store::tests::bulk_store_headers_applies_five_sequential
```
Expected: PASS.

**Step 5: Run full tests**

```bash
cargo test --workspace
```
Expected: all tests pass.

**Step 6: Commit**

```bash
git add crates/ergo-storage/src/header_store.rs
git commit -m "feat(storage): add HistoryDb::bulk_store_headers for single-batch writes"
```

---

## Task 4: C2 — `BulkHeaders` command + processor handler

**Files:**
- Modify: `crates/ergo-network/src/block_processor.rs`

**Context:** Add a new `ProcessorCommand::BulkHeaders` variant carrying a pre-sorted `Vec` of headers, and a handler `process_bulk_headers` that calls `history.bulk_store_headers`, then emits `HeadersApplied`.

**Step 1: Write a failing test**

In the `#[cfg(test)]` block of `block_processor.rs`, add after the existing tests:

```rust
#[test]
fn bulk_headers_command_applies_headers() {
    use ergo_types::header::Header;
    use ergo_types::modifier_id::ModifierId;
    use std::sync::mpsc;

    let (cmd_tx, cmd_rx) = mpsc::sync_channel::<ProcessorCommand>(CHANNEL_CAPACITY);
    let (evt_tx, mut evt_rx) = tokio::sync::mpsc::channel::<ProcessorEvent>(CHANNEL_CAPACITY);

    let handle = std::thread::spawn(move || {
        run_processor_with_state(cmd_rx, evt_tx, || {
            let (state, _tmpdir) = ProcessorState::new_test();
            std::mem::forget(_tmpdir);
            state
        });
    });

    // Build a genesis header (height=1, parent=GENESIS_PARENT).
    let raw_genesis = ergo_wire::header_ser::serialize_header(&Header {
        height: 1,
        parent_id: ModifierId::GENESIS_PARENT,
        ..Header::default_for_test()
    });
    let genesis_id = ModifierId({
        use blake2::digest::{Update, VariableOutput};
        let mut h = blake2::Blake2bVar::new(32).unwrap();
        h.update(&raw_genesis);
        let mut out = [0u8; 32];
        h.finalize_variable(&mut out).unwrap();
        out
    });

    cmd_tx
        .send(ProcessorCommand::BulkHeaders {
            headers: vec![(
                genesis_id,
                Box::new(Header {
                    height: 1,
                    parent_id: ModifierId::GENESIS_PARENT,
                    ..Header::default_for_test()
                }),
                raw_genesis,
            )],
        })
        .unwrap();
    cmd_tx.send(ProcessorCommand::Shutdown).unwrap();

    handle.join().expect("processor should not panic");

    // Collect all events.
    let mut events = Vec::new();
    while let Ok(e) = evt_rx.try_recv() {
        events.push(e);
    }

    // Must have at least one HeadersApplied event.
    let has_applied = events.iter().any(|e| matches!(e, ProcessorEvent::HeadersApplied { .. }));
    assert!(has_applied, "expected HeadersApplied event from BulkHeaders command; got: {:?}", events);
}
```

**Step 2: Run to verify it fails**

```bash
cargo test -p ergo-network block_processor::tests::bulk_headers_command_applies_headers
```
Expected: compile error — `ProcessorCommand::BulkHeaders` does not exist.

**Step 3: Add the `BulkHeaders` variant**

In `block_processor.rs`, add the new variant to `ProcessorCommand` after `StorePrevalidatedHeader`:

```rust
/// A pre-sorted batch of PoW-validated headers from fast sync.
/// Headers are in ascending height order. The processor stores all of them
/// in a single RocksDB WriteBatch via `HistoryDb::bulk_store_headers`.
BulkHeaders {
    headers: Vec<(ModifierId, Box<ergo_types::header::Header>, Vec<u8>)>,
},
```

**Step 4: Handle `BulkHeaders` in the processor batch loop**

In `processor_loop_with_state`, inside the `for cmd in batch` match block, add a new arm after `StorePrevalidatedHeader`:

```rust
ProcessorCommand::BulkHeaders { headers } => {
    let mut accum = BatchAccum {
        new_headers: &mut new_headers,
        blocks_to_download: &mut blocks_to_download,
    };
    process_bulk_headers(state, evt_tx, headers, &mut accum);
}
```

**Step 5: Add the `process_bulk_headers` function**

Add after `process_prevalidated_header` (around line 462):

```rust
/// Process a `BulkHeaders` command.
///
/// Calls `HistoryDb::bulk_store_headers` to write all headers in a single
/// RocksDB WriteBatch, then records each applied header in `accum`.
fn process_bulk_headers(
    state: &mut ProcessorState,
    _evt_tx: &tokio::sync::mpsc::Sender<ProcessorEvent>,
    headers: Vec<(ModifierId, Box<ergo_types::header::Header>, Vec<u8>)>,
    accum: &mut BatchAccum<'_>,
) {
    // Unwrap Box<Header> into (ModifierId, Header, Vec<u8>) for bulk_store_headers.
    let flat: Vec<(ModifierId, ergo_types::header::Header, Vec<u8>)> = headers
        .into_iter()
        .map(|(id, h, raw)| (id, *h, raw))
        .collect();

    match state.node_view.history.bulk_store_headers(&flat) {
        Ok(applied_ids) => {
            for id in applied_ids {
                accum.new_headers.push(id);
            }
        }
        Err(e) => {
            tracing::error!(%e, "bulk_headers: batch write failed");
        }
    }
}
```

**Step 6: Run the test to verify it passes**

```bash
cargo test -p ergo-network block_processor::tests::bulk_headers_command_applies_headers
```
Expected: PASS.

**Step 7: Run full tests**

```bash
cargo test --workspace
```
Expected: all tests pass.

**Step 8: Commit**

```bash
git add crates/ergo-network/src/block_processor.rs
git commit -m "feat(processor): add BulkHeaders command for single-batch header writes"
```

---

## Task 5: C3 — Wire fast_sync to send `BulkHeaders`

**Files:**
- Modify: `crates/ergo-node/src/fast_header_sync.rs` — `fetch_and_validate_chunk` function (lines ~516–594)

**Context:** Currently `fetch_and_validate_chunk` sends one `StorePrevalidatedHeader` per header in a retry loop, then one `ApplyFromCache`. Replace the per-header sends with a single `BulkHeaders` send.

**Step 1: Write a failing test**

The existing test `json_header_to_wire_produces_valid_header` still passes. We don't need a new unit test here — the change is a behavior swap in an async fn. Verify by running the full suite in Step 3.

**Step 2: Replace the send loop in `fetch_and_validate_chunk`**

Find this block (around lines 562–591):

```rust
    for (mid, header, raw) in validated {
        let mut cmd = ProcessorCommand::StorePrevalidatedHeader {
            modifier_id: mid,
            header: Box::new(header),
            raw_data: raw,
            peer_hint: None,
        };
        // Retry loop: if the channel is full, yield briefly and retry.
        loop {
            match cmd_tx.try_send(cmd) {
                Ok(()) => break,
                Err(std::sync::mpsc::TrySendError::Full(returned)) => {
                    tokio::task::yield_now().await;
                    cmd = returned;
                }
                Err(std::sync::mpsc::TrySendError::Disconnected(_)) => return Ok(count),
            }
        }
    }
    loop {
        match cmd_tx.try_send(ProcessorCommand::ApplyFromCache) {
            Ok(()) => break,
            Err(std::sync::mpsc::TrySendError::Full(_)) => {
                tokio::task::yield_now().await;
            }
            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => break,
        }
    }
```

Replace with:

```rust
    // Send the whole chunk as a single BulkHeaders command.
    let bulk_headers = validated
        .into_iter()
        .map(|(mid, header, raw)| (mid, Box::new(header), raw))
        .collect();

    let mut cmd = ProcessorCommand::BulkHeaders { headers: bulk_headers };
    loop {
        match cmd_tx.try_send(cmd) {
            Ok(()) => break,
            Err(std::sync::mpsc::TrySendError::Full(returned)) => {
                tokio::task::yield_now().await;
                cmd = returned;
            }
            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => return Ok(count),
        }
    }

    // Still trigger a cache drain so any headers buffered from previous
    // out-of-order chunks can be applied now that their parents exist.
    loop {
        match cmd_tx.try_send(ProcessorCommand::ApplyFromCache) {
            Ok(()) => break,
            Err(std::sync::mpsc::TrySendError::Full(_)) => {
                tokio::task::yield_now().await;
            }
            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => break,
        }
    }
```

Also add the import at the top of `fetch_and_validate_chunk`:
`ProcessorCommand` is already imported via `use ergo_network::block_processor::ProcessorCommand;` inside the function. No new imports needed.

**Step 3: Run full tests**

```bash
cargo test --workspace
```
Expected: all tests pass.

**Step 4: Lint**

```bash
cargo clippy --workspace -- -D warnings
```
Expected: no warnings.

**Step 5: Commit**

```bash
git add crates/ergo-node/src/fast_header_sync.rs
git commit -m "perf(fast-sync): send BulkHeaders per chunk instead of one command per header"
```

---

## Final verification

```bash
cargo test --workspace && cargo clippy --workspace -- -D warnings && cargo fmt --check
```

All three must pass before declaring complete.
