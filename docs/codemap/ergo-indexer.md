# ergo-indexer

**Purpose:** Opt-in extra-index parity with the Scala node's `extraIndex` feature. This is the *writer half*: a private redb store, per-block apply/rollback, segmented address/template/token indexes, address balance bookkeeping, EIP-4 mint tracking, a storage-rent eligibility index, and a polling task that follows the committed chain tip. The reader-side trait + DTOs live in `ergo-indexer-types`.

**Depends on (workspace):** ergo-primitives, ergo-ser, ergo-state, ergo-indexer-types
**Depended on by:** (see codemap index)

## Start here
- `apply::apply_block_with_scratch` — the heart: how one block becomes box/tx/address/template/token rows in a single atomic redb txn. Read its module doc first.
- `task::IndexerTask::step` — the poll loop: self-repair gate → reorg-check → caught-up-check → load+verify+apply. Defines forward progress, reorg detection, and secondary-index rebuild dispatch via the `IndexerChainSource` trait.
- `segment.rs` module doc + `segment_buffer.rs` module doc — the head-buffer/spill model (512-entry spills, sign-bit = spent flag) shared by all three keyed indexes. This is the trickiest invariant in the crate.
- `store::IndexerStore` — owns the redb file, the wipe/resume open table, and every read accessor the handle drives.
- `lib.rs` — the module map, written as a guided tour.

## Modules
- `src/lib.rs` — crate root: module tree, re-exports, and a re-export of the reader-side surface from `ergo-indexer-types`.
- `src/apply.rs` — per-block forward apply: outputs → box rows + balance/segment append; inputs → spend-stamp + balance/segment sign-flip; tx rows; storage-rent insert/remove; mint detection; meta+undo+prune commit. Owns `write_then_insert`, `load_address_into_map`, `flush_addresses`.
- `src/rollback.rs` — exact inverse of apply, walking the block's txs in reverse. Restores meta from the `UndoEntry` snapshot; pops/unflips segment entries; deletes token records whose creating mint was in the rolled-back block.
- `src/rebuild.rs` — chain-free rebuild of the derived secondary (template/token) box-segment indexes from the intact primary tables (`NUMERIC_BOX` + `INDEXED_BOX`). Triggered when a tolerated `SegmentEntryMissing` drift stamps a sticky repair marker in `INDEXER_META`. Phase 0 wipes template/token box-segment heads and their spill rows; Phase 1 replays box history in `gi` order via `append_box_entry`/`flip_box_segment_entry`, reusing the exact apply machinery so rebuilt segments are byte-identical to a fresh linear index. Both phases commit per-chunk and checkpoint in `INDEXER_META` for crash-safety and resumability. Consensus is untouched. Exports `rebuild_secondary_indexes`.
- `src/task.rs` — `IndexerTask` polling loop + the `IndexerChainSource` read trait + `IndexerPoll` step outcomes; self-repair gate (checks the sticky marker and drives `rebuild_secondary_indexes` before any forward-apply or rollback); bounded section-missing retry; reorg detection via header-id re-read.
- `src/handle.rs` — `IndexerHandle`: the read-side `IndexerQuery` impl wired into `ergo-api`. Holds in-memory status + cached indexed-height mirror; paging/dereference helpers (`slice_paged`, `try_dereference_box`, `try_dereference_tx`).
- `src/segment.rs` — `Segment` body type + wire codec (Scala `Segment.scala` parity); `SEGMENT_THRESHOLD = 512`.
- `src/segment_buffer.rs` — head-buffer + spill mechanics: `append_box_entry`/`append_tx_entry`, `flip`/`unflip_box_segment_entry`, `pop_box_entry`/`pop_tx_entry`, `flush_staged_spills`. Drives both address and template/token segments.
- `src/segment_id.rs` — pure derivations: `box_segment_id`/`tx_segment_id`, `tree_hash`/`tree_hash_from_bytes`, `token_unique_id`. All `[inherited]` byte-exact formulas — part of the public API surface.
- `src/address.rs` — `IndexedAddress` parent record + `BalanceInfo` (order-preserving token bundle, clamp-at-zero ergs) + wire codecs.
- `src/template.rs` — `IndexedTemplate` parent record (box-segment only, no balance) + `template_hash_for_box_bytes` (Scala `hashTreeTemplate`, soft-fork-wrapped trees included).
- `src/token.rs` — `IndexedToken` parent record + EIP-4 `is_mint` predicate + `from_box` (R4/R5/R6 metadata decode) + `add_emission_amount`.
- `src/scratch.rs` — `BlockApplyScratch`: reusable per-block/per-tx allocation arenas; entry-clear (never exit-clear) safety contract.
- `src/config.rs` — `IndexerConfig` (`enabled`, `poll_idle_ms`, `db_filename`); disabled by default.
- `src/error.rs` — `IndexerError` (typed redb/decode/divergence/schema variants) + `halt_reason()` mapping to `IndexerHaltReason`.
- `src/ser/` — wire codecs for persisted rows (`boxes`, `txs`) + shared `write_opt`/`read_opt`; mirrors Scala `ExtraIndexSerializer`.
- `src/store/` — redb layer. `mod.rs` (`IndexerStore` + all read accessors), `tables.rs` (10 table defs + `create_all`), `meta.rs` (`IndexerMeta`, `INDEXER_SCHEMA_VERSION = 3`), `undo.rs` (`UndoEntry`, `ROLLBACK_WINDOW = 200`, prune), `storage_rent.rs` (`unspent_by_creation_height` index), plus `boxes`/`txs`/`numeric`/`address`/`template`/`token`/`segment` row helpers.

## Key types, traits & functions
- `IndexerStore` (struct) — owns the `Arc<redb::Database>`; wipe/resume `open`; every read accessor.
- `IndexerHandle` (struct) — read-side handle, implements `IndexerQuery`; `boot` returns `None` only when disabled, else `Some(syncing|halted)`.
- `IndexerTask<C>` (struct) — poll driver over `IndexerChainSource` — `src/task.rs`.
- `IndexerChainSource` (trait) — `committed_tip` / `header_id_at` / `best_header_id_at` / `full_block` read surface; production wires `ChainStoreReader` with fully applied `CHAIN_INDEX` IDs. The best-header `HEADER_CHAIN_INDEX` ID is only reorg evidence: an indexed height missing from the applied chain (State restarted from its last durable IBD commit) unwinds only once the best-header chain selects another block there.
- `IndexerPoll` (enum) — `Idle`/`Applied`/`RolledBack`/`SectionRetry`/`Race`/`AppliedGap`/`Halted` step outcomes.
- `apply_block` / `apply_block_with_scratch` (fn) — forward apply; scratch variant reuses arenas — `src/apply.rs`.
- `rollback_one_block` (fn) — inverse apply, undo-snapshot meta restore.
- `IndexerBlock<'a>` (struct) — caller-provided apply/rollback input (`height`, `header_id`, `&[Transaction]`).
- `IndexerMeta` (struct) — persisted meta mirror (`indexed_height`, `indexed_header_id`, `global_tx_index`, `global_box_index`).
- `UndoEntry` (struct) — `[height-1]` snapshot for rollback meta restore; own framing (not ergo-ser).
- `Segment` (struct) — shared body for all parent + spill records; signed-i64 box entries (sign = spent).
- `IndexedAddress` + `BalanceInfo` (struct) — address parent + running balance — `src/address.rs`.
- `IndexedTemplate` (struct) — template parent (box-segment only).
- `IndexedToken` (struct) — token parent + mint metadata — `src/token.rs`; `is_mint` (EIP-4 predicate) + `from_box`.
- `box_segment_id` / `tx_segment_id` / `token_unique_id` / `tree_hash_from_bytes` (fn) — `[inherited]` byte-exact derivations — `src/segment_id.rs`.
- `IndexerError` (enum) + `halt_reason()` — typed errors; never crosses the API boundary.
- `IndexerConfig` (struct) — `[indexer]` TOML section.
- `BlockApplyScratch` (struct) — run-loop arenas.
- `OpenOutcome` (enum) — `CreatedFresh`/`Resumed`/`WipedAndRecreated`.
- `StoreHealthSnapshot` (struct) — mutually-consistent repair-marker + meta snapshot captured under one redb read txn; driven by `IndexerStore::health_snapshot` and surfaced via `IndexerHandle::health` as `IndexerHealthDto`.

## Invariants & contracts
- **Per-block atomicity.** All of a block's mutations — box/tx/numeric rows, address/template/token parents, spill segments, storage-rent rows, meta, undo write, undo prune — commit in a single redb `WriteTransaction`. Any `?` drops the txn (no commit), so on-disk state is exactly pre-call (`src/apply.rs`, `src/rollback.rs`).
- **Durable checkpoints.** Apply and batched catch-up use `Immediate` durability. The complete batch commits atomically; observers and the cached height are published only after commit. An error abandons the entire uncommitted batch, including undo and numeric rows.
- **Checkpoint ownership.** An initialized schema-v3 store requires all four checkpoint fields. Empty height has no header or counters; nonempty height has a header. Writer-representable counters are checked. Apply and rollback compare the caller's complete checkpoint under the redb writer lock, so a stale caller receives `StaleCheckpoint` before changing any rows.
- **Sequential height contract.** Apply requires `block.height == meta.indexed_height + 1` (`HeightMismatch` otherwise); rollback requires `block.height == meta.indexed_height` AND `Some(block.header_id) == meta.indexed_header_id` (`HeightMismatch`/`HeaderMismatch`) — guards indexer/chain divergence and reorg races (`src/apply.rs`, `src/rollback.rs`).
- **Persisted-codec bounds.** Stored parent heads and spill rows reject arrays exceeding 512 entries and negative spill counters before allocating. Claimed entry counts must fit the remaining bytes. The generic segment codec can still represent transient buffers larger than a stored head. Balance token counts must fit their minimum encoded entry size; initial reservations are bounded. These checks protect local storage decoding and preserve valid row bytes.
- **Segment spill topology.** Head buffers spill when length is *strictly* > 512; each spill row holds exactly 512 entries; spill count counters are monotonic; rollback pops must merge-back and match the expected global index or fail `SegmentTopologyError` (`src/segment.rs`, `src/segment_buffer.rs`, `src/rollback.rs`).
- **Box-segment sign encoding.** Box entries are signed-i64: `+global_index` while unspent, `-global_index` after spend; the box *record's* `global_index` stays positive (the spent state lives on the spending-* fields). Tx entries are always positive. Dereference via `abs(entry)` (`src/segment.rs`, `src/handle.rs`).
- **`[inherited]` byte-exact derivations.** Segment-id strings (`" box segment "`, `" tx segment "`), token unique-id suffix (`"token"`, no spaces), tree-hash = `blake2b256(canonical tree bytes)`, and template-hash are Scala-parity formulas; a single wrong byte produces records Scala-compatible clients cannot look up.
- **Wire-format parity.** All persisted row codecs mirror Scala `ExtraIndexSerializer`/`Segment.scala`/`BalanceInfo.scala`/`IndexedToken.scala`: VLQ-zigzag i32/i64, unsigned VLQ for u16 and token `emissionAmount` (u64), raw 32-byte ids, `Opt[X]` = 1 marker byte + body. `emissionAmount` u64-vs-i32 and `Some("")` ≠ `None` are load-bearing (`src/ser/mod.rs`, `src/token.rs`). `BalanceInfo.tokens` is order-preserving (first-touch append) — byte output depends on token-touch order.
- **Schema wipe/resume.** `INDEXER_SCHEMA_VERSION = 3`. File absent → create fresh; version matches → resume; version mismatches → delete + recreate (full resync); version key missing → halt `SchemaCorruption`; meta table missing → halt `DbCorruption`. No in-place migration (`src/store/mod.rs`, `src/store/meta.rs`).
- **Rollback window.** `INDEXER_UNDO` retains entries for `ROLLBACK_WINDOW = 200` (mirrors `ergo-state`); pruned strictly-less-than `current_height - 200` so the deepest target survives. Undo decode enforces strict-EOF (rollback removes the row after consuming it, so a corrupt-then-rewritten row would otherwise hide).
- **Protocol-genesis box absorption.** The 3 protocol-seeded box IDs (foundation / no-premine / emission) are never in `INDEXED_BOX`; their first spend pushes `0` to `input_nums` and continues instead of `InputMissing`, mirroring Scala `ExtraIndexer.scala:331`. Genesis (height 1) skips the input-spend pass entirely (`src/apply.rs`, `src/rollback.rs`).
- **Storage-rent index coherence.** `unspent_by_creation_height` is keyed by the box's own `creationHeight` (R3 metadata, *not* inclusion height) + immutable `global_box_index`; symmetric insert-on-output / remove-on-input with apply, fully re-derived from unchanged `IndexedErgoBox` rows on rollback (no undo-payload extension) (`src/store/storage_rent.rs`, `src/apply.rs`, `src/rollback.rs`).
- **Required mint metadata.** Spending, transferring, rolling back or rebuilding a token requires its existing parent record. A missing parent returns `TokenMetadataMissing`; these operations never invent mint metadata from a transfer box. A failed repair retains its durable pending marker and cursor, including across reopening.
- **Repair ownership.** A process-local guard is shared by store clones. Durable pending markers and writer-side checks also exclude ordinary apply, rollback and metadata-only commits while repair is incomplete. Repair chunks commit independently; cancellation or failure preserves already committed chunks and resume state.
- **Secondary-index degrade-not-halt.** A `SegmentEntryMissing` on a DERIVED secondary index (template/token box-segment) is tolerated — the indexer marks a sticky `repair_pending` marker in `INDEXER_META` and continues applying blocks rather than halting. The PRIMARY address segments still halt on any topology error. On the next poll, `IndexerTask::step` detects the marker and runs `rebuild_secondary_indexes` (chain-free, from the intact primary box table) before resuming normal forward-apply. A process-lifetime counter `secondary_index_drift_skips()` and the durable repair markers drive the health surface (`src/segment_buffer.rs`, `src/task.rs`, `src/rebuild.rs`).
- **Halted-handle read isolation.** A boot-time-halted handle has no store; database reads return `Err(IndexerReadError)` for the unavailable store and the polling task is not spawned. The cached `indexed_height`/`status` reads recover from a poisoned lock rather than propagating panic, keeping the API surface up after an indexer fault.
- **Indexer DB isolation.** The redb file is separate from the chain store, so an indexer wipe never touches consensus data.

## Chain reads, polling and parity evidence

`IndexerChainSource` returns `Result` for every read. `Ok(None)` means absent
header or section data; an error means a failed storage read or decode. The
production adapter retains the underlying cause in `IndexerError::ChainRead`.
A failure during batching or rollback halts the task, preserves the last
committed checkpoint and prevents a previous `CaughtUp` status from surviving
as healthy. Custom source implementations must preserve this distinction.
Each call can observe a separate chain snapshot; canonicality is rechecked
before forward commit. This adapter consumes already accepted chain data and
does not perform independent block authentication.

The dedicated worker continues after committed apply/rollback progress.
Persistent `Race` results wait 50 ms; `Idle` waits for the configured interval
with a 50 ms minimum even when `poll_idle_ms` is zero. These waits observe
cancellation. Missing sections, and applied heights missing below a tip that
stays anchored (`AppliedGap`), retain the bounded five-attempt, one-second
retry policy before halting `section-missing`. Public single-step methods
publish halt status but do not sleep.

Token names, descriptions and persisted optional strings use JVM-compatible
UTF-8 replacement. Decimal parsing follows Scala 2.12 signed `Int` behavior,
including Java 17 BMP decimal digits, ASCII signs, checked range and rejection
of non-BMP digits. `test-vectors/ergo-indexer/token-text` retains actual finite
JVM captures, the complete BMP digit observation, pinned source and runtime
provenance. It compares selected `IndexedToken` expressions rather than a
complete Scala node execution or evidence of those values occurring on-chain.

Read errors propagate to API consumers. Page and global-range references are
resolved in one redb snapshot; a missing referenced row fails the entire
response. Global ranges are clipped to the snapshot's indexed counters.
`IndexerHandle` retains the last observed read failure until reopened, and
`health()` returns it rather than reporting healthy zero counters after an
unrelated successful query. `/api/v1/indexer/status` returns HTTP 500 for
failed snapshots or observed read corruption; cached indexed-height/status
remain queryable. Storeless syncing/halted handles still reject database
queries with an unavailable-store error. Only `health()` may return `Ok` with
zero store-backed counters for their explicit offline status, provided no
read error is latched; `drift_skips` remains the live process counter
(`src/handle.rs`).
