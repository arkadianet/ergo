# Fast Block Sync Design

**Goal:** Bulk-download block body sections (BlockTransactions + Extension) via peer REST APIs, bypassing the slow P2P request/response cycle. Same pattern as fast header sync but for block bodies.

**Architecture:** After fast header sync completes and all headers are stored, walk the height index to collect header IDs, batch them into chunks of 16, and POST to `/blocks/headerIds` on peer REST APIs in parallel. Parse JSON responses, convert to wire-format bytes, and bulk-store to DB via a new `BulkBlockSections` processor command. The existing processor `apply_progress` mechanism applies blocks sequentially afterward — no changes to validation or application logic.

**Tech Stack:** Rust, tokio, reqwest, serde_json, RocksDB WriteBatch

---

## Context

### Current Problem
P2P block sync downloads body sections one-at-a-time via Inv/RequestModifier/Modifier exchanges. With backpressure, the node syncs ~160 blocks/sec. For 1.7M blocks this takes ~3 hours. Fast header sync already proved that HTTP bulk download is 10-100x faster than P2P for the download phase.

### Fast Header Sync Pattern (established)
- `GET /blocks/chainSlice?fromHeight=X&toHeight=Y` → JSON headers
- Validate PoW, convert to wire bytes
- `BulkHeaders` processor command → single WriteBatch
- Parallel chunk fetch with work-stealing, per-peer caps, timeout/blacklist
- Throttle: don't get too far ahead of processor

### Key Constraint
Downloaded data must be **consensus-equivalent** to what P2P delivers. The wire-format bytes stored in DB must be identical to what the P2P modifier handler would produce. Validation and application use the same code path regardless of how data arrived.

---

## Data Flow

```
Height index → header IDs → chunk into batches of 16
  → POST /blocks/headerIds to peer REST APIs (parallel, work-stealing)
  → Parse JSON full blocks
  → Extract BlockTransactions (type 102) + Extension (type 108)
  → Convert to wire-format bytes (same as P2P)
  → BulkBlockSections processor command (single WriteBatch per chunk)
  → Processor stores to DB via put_modifier
  → apply_progress picks them up when all sections present
  → validate_and_apply_block runs full validation pipeline
```

ADProofs (type 104) are skipped — UTXO mode doesn't need them.

---

## Components

### 1. JSON-to-Wire Conversion

Parse the JSON full block response. Each block contains:

**BlockTransactions (type 102):**
- JSON: `blockTransactions.transactions` array with inputs, outputs, etc.
- Wire: header_id (32 bytes) + VLQ(tx_count) + concatenated serialized transactions
- Reuse existing `ergo_wire` transaction serialization

**Extension (type 108):**
- JSON: `extension.fields` array of key-value pairs
- Wire: header_id (32 bytes) + VLQ(field_count) + (key_len + key + VLQ(value_len) + value) per field
- Reuse existing `ergo_wire` extension serialization

The header ID from JSON maps to the modifier_id used as the DB key.

### 2. BulkBlockSections Processor Command

```rust
ProcessorCommand::BulkBlockSections {
    sections: Vec<(u8, ModifierId, Vec<u8>)>,  // (type_id, modifier_id, wire_bytes)
}
```

Processor handler:
1. Store all sections in a single RocksDB WriteBatch (fast I/O)
2. For each unique header_id in the batch, check `has_all_sections`
3. If all sections present, trigger `apply_progress`

Same pattern as `BulkHeaders` but for body sections.

### 3. run_fast_block_sync Pipeline

Structure mirrors `run_fast_sync` for headers:

- **Startup:** Wait for API peers (up to 60s)
- **Range:** `full_height + 1` to `headers_height - 1000` (handoff distance)
- **Chunking:** Walk height index, collect header IDs, batch into groups of 16
- **Parallel fetch:** One request per peer at a time, work-stealing queue
- **Failure handling:** 20s timeout, push failed chunks to front of queue, blacklist after 3 failures
- **Throttle:** Don't get more than 50,000 blocks ahead of `SharedFullHeight` (applied height)
- **Shutdown:** Watch channel, graceful stop

### 4. Event Loop Integration

- Spawn `run_fast_block_sync` as tokio task after fast header sync completes
- Share: `ApiPeerUrls`, shutdown watch channel, processor `cmd_tx`
- Add `SharedFullHeight: Arc<AtomicU32>` — updated on each `BlockApplied` event
- Reuse `fast_header_sync` config setting (no new config)

---

## Sequencing & Lifecycle

1. Open DB, spawn processor thread
2. Connect to peers, discover API URLs
3. **Fast header sync** → bulk-store headers to `best_height - 1000`
4. P2P finishes last ~1000 headers
5. **Fast block sync** → bulk-store body sections from `full_height + 1` to `headers_height - 1000`
6. P2P block download covers last ~1000 blocks
7. Processor applies blocks sequentially from height 1 forward (continuous background)

Fast block sync and P2P may overlap near handoff. Idempotent storage (`put_modifier` overwrites) and `has_all_sections` deduplication make this safe.

---

## Error Handling

| Scenario | Behavior |
|----------|----------|
| Bad JSON / parse failure | Skip block, log warning, next peer re-requests |
| Peer timeout (20s) | Push chunk to front of queue, increment failure count |
| Peer blacklist (3 failures) | Stop using peer, continue with others |
| No healthy peers (60s) | Fall back to P2P-only sync |
| Wire serialization mismatch | Block fails validation at apply time (existing pipeline catches it) |
| Shutdown signal | Drain in-flight requests, stop cleanly |

---

## Key Files

| File | Changes |
|------|---------|
| `crates/ergo-node/src/fast_block_sync.rs` | NEW: JSON parsing, wire conversion, parallel fetch pipeline |
| `crates/ergo-network/src/block_processor.rs` | ADD: `BulkBlockSections` command variant + handler |
| `crates/ergo-node/src/event_loop.rs` | ADD: spawn fast block sync task, `SharedFullHeight` atomic |
| `crates/ergo-node/src/main.rs` | ADD: create `SharedFullHeight`, pass to event loop |
| `crates/ergo-wire/src/` | MAYBE: add/expose serializers for BlockTransactions and Extension if not already public |

---

## Constants

| Name | Value | Rationale |
|------|-------|-----------|
| Chunk size (blocks per request) | 16 | Balance between HTTP overhead and response size |
| Max concurrent requests | Same as header sync | Reuse existing peer concurrency |
| Handoff distance | 1000 blocks | Match header sync handoff |
| Throttle lookahead | 50,000 blocks | Generous but bounded disk usage |
| Peer timeout | 20s | Match header sync timeout |
| Max peer failures | 3 | Match header sync blacklist threshold |
