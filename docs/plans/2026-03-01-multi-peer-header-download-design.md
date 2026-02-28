# Multi-Peer Parallel Header Download Design

**Date:** 2026-03-01
**Status:** Approved

## Problem

The Rust node requests all headers from a single peer per Inv cycle (up to 400).
Scala partitions header requests across multiple ahead peers for parallel download.
This limits header sync throughput to one peer's bandwidth.

## Scope

Implement Scala-style partitioning of a received `Inv(header_ids)` from an Older
peer across multiple eligible Older peers for `RequestModifier`. Strict
single-owner tracking per modifier ID with retry reassignment on timeout.

**Not in scope:** proactive multi-peer solicitation, new REST endpoints, SyncManager
restructuring.

## Architecture Decision

**Approach A + helper function/module.** Partitioning logic in `handle_inv` with a
pure `partition_header_ids` function extracted into `header_partitioner.rs`.
`SyncMetrics` struct for rolling counters. Reuse existing `DeliveryTracker` and
stale/timeout reassignment mechanisms.

Rationale: lowest risk, fewest moving parts, no duplicate state vs DeliveryTracker.

## Component Design

### 1. Header Partitioner (`ergo-network/src/header_partitioner.rs`)

#### `partition_header_ids`

```
fn partition_header_ids(
    ids: &[ModifierId],      // height-ordered ascending (preserved from Inv)
    peers: &[PeerId],        // eligible peers, inv_sender at [0]
    min_per_peer: usize,     // default 50 (Scala behavior)
) -> Vec<(PeerId, Vec<ModifierId>)>
```

Algorithm:
1. If `ids.is_empty()` or `peers.is_empty()` → return empty.
2. Cap `ids` at 400 (take first 400).
3. `max_peers_by_size = max(1, capped_len / min_per_peer)`.
4. `usable_peers = min(peers.len(), max_peers_by_size)`.
5. Assert: no chunk < `min_per_peer` unless `usable_peers == 1`.
6. `chunk_size = capped_len / usable_peers`.
   Remainder `r = capped_len % usable_peers` distributed to first `r` peers
   (1 extra each).
7. Return contiguous slices assigned to `peers[0..usable_peers]`.

Strategy enum for future extensibility:

```
enum PartitionStrategy { Contiguous }
// Room for RoundRobin later
```

#### `select_eligible_peers`

```
enum EligiblePeers {
    Partition(Vec<PeerId>),
    SinglePeerFallback(PeerId, &'static str),
}

fn select_eligible_peers(
    inv_sender: PeerId,
    sync_tracker: &SyncTracker,
    connected_peers: &[PeerId],
) -> EligiblePeers
```

Rules:
- Filter `connected_peers` to those with `sync_tracker.status(peer) == Older`.
- If `inv_sender` is Older, ensure it's at position 0.
- If `inv_sender` is not Older → return `SinglePeerFallback(inv_sender,
  "inv_sender not classified Older")` with warning log.
- Exclude Younger, Unknown, Fork (deliberate v1 choice, documented for future
  revisit; Fork peers may become eligible later if needed).

### 2. Integration into `handle_inv`

Refactored `handle_inv` for type_id == HEADER_TYPE_ID (101):

```
1. Filter IDs preserving original Inv iteration order (stable filter)
   → to_request: Vec<ModifierId>
2. DO NOT call set_requested yet
3. Check global outstanding cap (2400):
   - If exceeded: emit NO new RequestModifiers. Log `cap_backpressure` with
     global_outstanding count and to_request_len. Return empty actions.
     (Existing stale/timeout ticks will drain outstanding and unblock next cycle.)
4. eligible = select_eligible_peers(peer_id, sync_tracker, connected_peers)
5. Match eligible:
   - Partition(peers):
     a. Filter out peers at per-peer cap (800)
     b. If all filtered out: same as global cap — emit nothing, log
        `cap_backpressure_all_peers`, return empty
     c. assignments = partition_header_ids(&to_request, &remaining_peers, 50)
     d. For each (assigned_peer, chunk):
        - tracker.set_requested(type_id, id, assigned_peer) for each id
        - Push SyncAction::RequestModifiers { peer_id: assigned_peer, .. }
     e. metrics.record_partition(batch_id, ...)
   - SinglePeerFallback(peer, reason):
     a. Check per-peer cap for inv_sender. If at cap: emit nothing, log
        `cap_backpressure_single_peer`, return empty
     b. Log warning with reason and peer classification state
     c. tracker.set_requested for each id with inv_sender
     d. Single SyncAction::RequestModifiers to inv_sender
6. Non-header type_ids: unchanged (single peer request to inv_sender)
```

New `handle_inv` parameters:
- `sync_tracker: &SyncTracker`
- `connected_peers: Vec<PeerId>` (owned snapshot, avoids borrow conflicts)
- `metrics: &mut SyncMetrics`

Functions extracted from `handle_inv` to keep it tidy:
- `select_eligible_peers(inv_sender, sync_tracker, connected_peers)`
- `partition_header_ids(ids, peers, min_per_peer)`
- `send_partitioned_requests(assignments, tracker, metrics)` (returns Vec<SyncAction>)

### 3. Outstanding Request Caps

Per-peer max outstanding header requests: **800**
Global max outstanding header requests: **2400**

Enforcement:
- Before partitioning, query DeliveryTracker for per-peer and global outstanding
  counts (new methods: `outstanding_header_count(peer_id)`,
  `total_outstanding_headers()`).
- If global cap exceeded: emit NO new `RequestModifiers` this cycle. Log
  `cap_backpressure`. Existing stale/timeout ticks drain outstanding requests
  and unblock future cycles. This is a real cap, not a suggestion.
- If per-peer cap exceeded for a candidate: exclude that peer from eligible set.
- If all candidates excluded by per-peer cap: emit nothing, log
  `cap_backpressure_all_peers`.
- During reassignment: check target peer cap before reassigning. If all at cap,
  defer (leave request in tracker, it will retry next tick).

### 4. SyncMetrics (`ergo-network/src/sync_metrics.rs`)

```
struct SyncMetrics {
    next_batch_id: u64,
    window_start: Instant,
    window_secs: u64,               // default 10

    // Window counters
    headers_applied: u64,
    batches_started: u64,
    timeouts: u64,
    reassignments: u64,
    dup_requests_prevented: u64,
    validate_ms_total: u64,
    db_ms_total: u64,

    // Per-peer window counters
    requests_sent_by_peer: HashMap<PeerId, u64>,
    mods_received_by_peer: HashMap<PeerId, u64>,
    timeouts_by_peer: HashMap<PeerId, u64>,

    // Active batch tracking
    active_batches: HashMap<u64, BatchInfo>,
}

struct BatchInfo {
    started: Instant,
    inv_len: usize,
    to_request_len: usize,
    peer_count: usize,
    chunks: Vec<(PeerId, usize)>,
    delivered: usize,               // applied + invalid + dup_blocked
}
```

Batch lifecycle:
- Created at `record_partition` (inv receipt).
- Updated at `record_headers_applied` (increment `delivered`).
- Completed when `delivered >= to_request_len`.
- Evicted if `now - started > 60s` (stale TTL). Warning: `batch_evicted_stale`.
- Max 128 active batches (oldest evicted first if exceeded).

Normalization:
- `validate_ms_per_400 = (validate_ms_total / headers_applied) * 400`
  (guard divide-by-zero).
- Same for `db_ms_per_400`.

`dup_requests_prevented`: incremented when we would request an ID but skip because
tracker shows Requested/Received/Invalid. Not incremented for unsolicited
duplicates received.

Ownership: single-threaded, owned by event loop. No atomics.

#### Required Log Events

Per-batch (one line each, `tracing::info!`):

| Event | Fields |
|---|---|
| `inv_received` | peer, inv_len, our_height, peer_height, batch_id |
| `partition_decided` | batch_id, inv_len, to_request_len, peer_count, chunks, min_chunk, reason_single_peer |
| `requests_sent` | batch_id, peer, n_ids, chunk_start_idx, chunk_end_idx |
| `modifier_received` | peer, n_mods, bytes, batch_id, elapsed_ms |
| `headers_applied` | batch_id, applied, invalid, dup_blocked, pow_ms, db_ms, total_ms, headers_per_sec, batch_age_ms |

Retry logs:

| Event | Fields |
|---|---|
| `delivery_timeout` | n_missing, from_peer, to_peer, attempt, age_ms |
| `reassigned` | header_id, from_peer, to_peer, attempt |

Periodic rollup (`tracing::info!`, every 10s via `maybe_emit_rollup`):

| Field | Computation |
|---|---|
| window_s | elapsed since last rollup |
| headers_applied | sum |
| headers_per_sec | headers_applied / window_s |
| avg_peers_used_per_batch | sum(peer_counts) / batches_started |
| timeouts | sum |
| reassignments | sum |
| dup_requests_prevented | sum |
| validate_ms_per_400 | normalized |
| db_ms_per_400 | normalized |

### 5. SyncInfo V2 Configurable Header Count

Move `MAX_SYNC_HEADERS` to a config value:

- Setting: `sync_info_max_headers: u32` in ergo-settings (default 10).
- Validation: clamp to `1..=50`.
- Pass to `build_sync_info_persistent(db, max_headers)`.

V1/V2 compatibility note: Since `check_peer_version` rejects peers below
`EIP37_FORK (4.0.100)` and `SYNC_V2_MIN = 4.0.16`, every connected peer supports
V2 by definition. No format gating needed. Add a compile-time or test-time
assertion: `EIP37_FORK >= SYNC_V2_MIN`.

### 6. Timeout and Retry

No change to timeout values (delivery_timeout = 30s, max_checks = 2).

Reassignment enhancements:
- On chunk timeout: reassign to different eligible Older peer (not the one that
  failed, preferably not one already holding chunks from the same batch).
- Before reassigning: check target peer outstanding cap. If at cap, try next
  eligible peer. If none under cap, defer to next tick.
- Stale header tick (1s, 2s threshold) works unchanged with multi-peer — it
  operates per-ID via DeliveryTracker.

## Correctness Invariants

1. Every header ID in an Inv is requested exactly once initially (single owner
   via DeliveryTracker), unless timed out and reassigned.
2. `set_requested` called only for IDs included in emitted `RequestModifiers`
   actions. Never for IDs filtered out or not assigned.
3. Processor thread remains the single-writer for DB. No change to processor
   command/event flow.
4. Cache pop/drain behavior unchanged. Out-of-order headers from later chunks
   buffer in cache and drain when the prefix chunk arrives.
5. Inv order preserved: `to_request` maintains original Inv iteration order
   (stable filter). Partitioner receives height-ordered IDs.

## Protocol Behavior Parity

- 400 IDs per cycle cap preserved.
- Continuation ID computation unchanged.
- Peer classification transitions unchanged.
- Pipelining preserved: after headers applied, SyncInfo sent to trigger next
  cycle (existing fast-path in `handle_modifiers`).

## Testing Strategy

### Unit Tests (header_partitioner.rs)

Partitioner:
1. N=400, K=4, min=50 → 4 chunks of 100
2. N=150, K=4, min=50 → 3 peers, 50 each
3. N=30, K=3, min=50 → 1 peer gets all 30
4. N=0 → empty
5. K=0 → empty
6. K=1 → all to single peer
7. N=100, K=2, min=50 → 2×50
8. N=107, K=2, min=50 → 54+53
9. Coverage: union(chunks) == original, all disjoint
10. No chunk < min_per_peer unless usable_peers == 1

Peer selection:
1. inv_sender Older + 2 other Older → Partition([inv_sender, p2, p3])
2. inv_sender not Older → SinglePeerFallback + reason
3. No Older peers → SinglePeerFallback
4. Mix Older/Younger/Fork → only Older included
5. inv_sender Older but only Older → Partition([inv_sender])

Config clamping:
1. 0 → 1, 1 → 1, 10 → 10, 50 → 50, 51 → 50, u32::MAX → 50

### Property Tests

Random N (1..400), random K (1..10):
- union(chunks) == original IDs
- chunks pairwise disjoint
- each chunk.len() >= min_per_peer OR usable_peers == 1
- sum(chunk.len()) == min(N, 400)

### Integration Tests (ergo-testkit)

1. **Single peer ahead:** behavior identical to pre-change (single RequestModifiers)
2. **3 peers ahead:** RequestModifiers sent to 3 peers, all headers applied
3. **Timeout from 1 peer:** reassignment to alt peer, headers complete
4. **Outstanding cap:** slow peers trigger cap, fallback to fewer peers
5. **Cap hit during reassignment:** walks eligible peers, defers if all at cap
6. **Out-of-order flood:** peers B/C deliver later chunks first, A slow:
   - Cache grows but doesn't explode
   - Nothing applied past the gap
   - Prefix arrival drains cache, progress resumes
   - No cache drain deadlock regression
7. **Prefix peer failure:** earliest-chunk peer fails:
   - Reassignment picks different peer
   - Earliest IDs reassigned first
   - Batch completes or evicts with warning after TTL

### Negative/Abuse Tests

1. Peer sends unsolicited modifier → ignored, no state poisoning
2. Peer sends duplicate modifier → skip + counter, no tracker churn
3. inv_sender classified non-Older → SinglePeerFallback + warning, no partition

### SyncInfo V1/V2 Tests

1. Round-trip V1 serialize/parse
2. Round-trip V2 serialize/parse
3. Assert `EIP37_FORK >= SYNC_V2_MIN` (all connected peers support V2)
4. V2 with 1, 10, 50 headers: correct encoding/decoding

## Files Changed

### New Files
- `crates/ergo-network/src/header_partitioner.rs` — partition algorithm + peer selection
- `crates/ergo-network/src/sync_metrics.rs` — rolling window counters + batch tracking

### Modified Files
- `crates/ergo-network/src/message_handler.rs` — `handle_inv` refactored for multi-peer
- `crates/ergo-network/src/delivery_tracker.rs` — add `outstanding_header_count(peer_id)`, `total_outstanding_headers()`
- `crates/ergo-network/src/persistent_sync.rs` — configurable `max_headers` parameter
- `crates/ergo-network/src/lib.rs` — register new modules
- `crates/ergo-settings/src/lib.rs` — add `sync_info_max_headers` setting
- `crates/ergo-node/src/event_loop.rs` — pass new params to `handle_inv`, periodic `maybe_emit_rollup`, snapshot connected peers
- `crates/ergo-testkit/tests/` — new integration tests

## Acceptance Criteria

1. With >= 3 ahead peers, header download throughput increases roughly proportional
   to peer count (until CPU/DB bottleneck).
2. No increase in invalid header acceptance or chain divergence.
3. No duplicate requests or stuck pending deliveries under simulated
   timeout/failure.
4. Configurable SyncInfo header count works (1..50) without breaking peers.
5. All existing tests pass. No clippy warnings.
6. Structured log events emitted for all specified events.
7. Periodic rollup log shows accurate throughput and retry statistics.
