# ergo-indexer

**Purpose:** Opt-in extra-index parity with the Scala node's `extraIndex` feature. This is the *writer half*: a private redb store, per-block apply/rollback, segmented address/template/token indexes, address balance bookkeeping, EIP-4 mint tracking, a storage-rent eligibility index, and a polling task that follows the committed chain tip. The reader-side trait + DTOs live in `ergo-indexer-types`.

**Depends on (workspace):** ergo-primitives, ergo-ser, ergo-state, ergo-indexer-types
**Depended on by:** (see codemap index)
**Approx LOC:** ~7,250 non-test (~11,500 with tests)

## Start here
- `apply::apply_block_with_scratch` (`src/apply.rs:117`) — the heart: how one block becomes box/tx/address/template/token rows in a single atomic redb txn. Read its module doc (`src/apply.rs:1-22`) first.
- `task::IndexerTask::step` (`src/task.rs:124`) — the poll loop: self-repair gate → reorg-check → caught-up-check → load+verify+apply. Defines forward progress, reorg detection, and secondary-index rebuild dispatch via the `IndexerChainSource` trait.
- `segment.rs` module doc + `segment_buffer.rs` module doc — the head-buffer/spill model (512-entry spills, sign-bit = spent flag) shared by all three keyed indexes. This is the trickiest invariant in the crate.
- `store::IndexerStore` (`src/store/mod.rs:57`) — owns the redb file, the wipe/resume open table, and every read accessor the handle drives.
- `lib.rs` (`src/lib.rs:15-27`) — the module map, written as a guided tour.

## Modules
- `src/lib.rs` — crate root: module tree, re-exports, and a re-export of the reader-side surface from `ergo-indexer-types`.
- `src/apply.rs` — per-block forward apply: outputs → box rows + balance/segment append; inputs → spend-stamp + balance/segment sign-flip; tx rows; storage-rent insert/remove; mint detection; meta+undo+prune commit. Owns `write_then_insert`, `load_address_into_map`, `flush_addresses`.
- `src/rollback.rs` — exact inverse of apply, walking the block's txs in reverse. Restores meta from the `UndoEntry` snapshot; pops/unflips segment entries; deletes token records whose creating mint was in the rolled-back block.
- `src/rebuild.rs` — chain-free rebuild of the derived secondary (template/token) box-segment indexes from the intact primary tables (`NUMERIC_BOX` + `INDEXED_BOX`). Triggered when a tolerated `SegmentEntryMissing` drift stamps a sticky repair marker in `INDEXER_META`. Phase 0 wipes template/token box-segment heads and their spill rows; Phase 1 replays box history in `gi` order via `append_box_entry`/`flip_box_segment_entry`, reusing the exact apply machinery so rebuilt segments are byte-identical to a fresh linear index. Both phases commit per-chunk and checkpoint in `INDEXER_META` for crash-safety and resumability. Consensus is untouched. Exports `rebuild_secondary_indexes`.
- `src/task.rs` — `IndexerTask` polling loop + the `IndexerChainSource` read trait + `IndexerPoll` step outcomes; self-repair gate (checks the sticky marker and drives `rebuild_secondary_indexes` before any forward-apply or rollback); bounded section-missing retry; reorg detection via header-id re-read.
- `src/handle.rs` — `IndexerHandle`: the read-side `IndexerQuery` impl wired into `ergo-api`. Holds in-memory status + cached indexed-height mirror; paging/dereference helpers (`slice_paged`, `dereference_box`, `dereference_tx`).
- `src/segment.rs` — `Segment` body type + wire codec (Scala `Segment.scala` parity); `SEGMENT_THRESHOLD = 512`.
- `src/segment_buffer.rs` — head-buffer + spill mechanics: `append_box_entry`/`append_tx_entry`, `flip`/`unflip_box_segment_entry`, `pop_box_entry`/`pop_tx_entry`, `flush_staged_spills`. Drives both address and template/token segments.
- `src/segment_id.rs` — pure derivations: `box_segment_id`/`tx_segment_id`, `tree_hash`/`tree_hash_from_bytes`, `token_unique_id`. All `[inherited]` byte-exact formulas — part of the public API surface.
- `src/address.rs` — `IndexedAddress` parent record + `BalanceInfo` (order-preserving token bundle, clamp-at-zero ergs) + wire codecs.
- `src/template.rs` — `IndexedTemplate` parent record (box-segment only, no balance) + `template_hash_for_box_bytes` (soft-fork-unparseable → skip).
- `src/token.rs` — `IndexedToken` parent record + EIP-4 `is_mint` predicate + `from_box` (R4/R5/R6 metadata decode) + `add_emission_amount`.
- `src/scratch.rs` — `BlockApplyScratch`: reusable per-block/per-tx allocation arenas; entry-clear (never exit-clear) safety contract.
- `src/config.rs` — `IndexerConfig` (`enabled`, `poll_idle_ms`, `db_filename`); disabled by default.
- `src/error.rs` — `IndexerError` (typed redb/decode/divergence/schema variants) + `halt_reason()` mapping to `IndexerHaltReason`.
- `src/ser/` — wire codecs for persisted rows (`boxes`, `txs`) + shared `write_opt`/`read_opt`; mirrors Scala `ExtraIndexSerializer`.
- `src/store/` — redb layer. `mod.rs` (`IndexerStore` + all read accessors), `tables.rs` (10 table defs + `create_all`), `meta.rs` (`IndexerMeta`, `INDEXER_SCHEMA_VERSION = 2`), `undo.rs` (`UndoEntry`, `ROLLBACK_WINDOW = 200`, prune), `storage_rent.rs` (`unspent_by_creation_height` index), plus `boxes`/`txs`/`numeric`/`address`/`template`/`token`/`segment` row helpers.

## Key types, traits & functions
- `IndexerStore` (struct) — owns the `Arc<redb::Database>`; wipe/resume `open`; every read accessor — `src/store/mod.rs:57`, `open` at `:85`.
- `IndexerHandle` (struct) — read-side handle, implements `IndexerQuery`; `boot` returns `None` only when disabled, else `Some(syncing|halted)` — `src/handle.rs:28`, `boot` at `:56`.
- `IndexerTask<C>` (struct) — poll driver over `IndexerChainSource` — `src/task.rs:98`; `step` at `:124`, `run` at `:287`.
- `IndexerChainSource` (trait) — `committed_tip` / `header_id_at` / `full_block` read surface; production wires `ChainStoreReader` — `src/task.rs:56`.
- `IndexerPoll` (enum) — `Idle`/`Applied`/`RolledBack`/`SectionRetry`/`Race`/`Halted` step outcomes — `src/task.rs:76`.
- `apply_block` / `apply_block_with_scratch` (fn) — forward apply; scratch variant reuses arenas — `src/apply.rs:104` / `:117`.
- `rollback_one_block` (fn) — inverse apply, undo-snapshot meta restore — `src/rollback.rs:76`.
- `IndexerBlock<'a>` (struct) — caller-provided apply/rollback input (`height`, `header_id`, `&[Transaction]`) — `src/apply.rs:64`.
- `IndexerMeta` (struct) — persisted meta mirror (`indexed_height`, `indexed_header_id`, `global_tx_index`, `global_box_index`) — `src/store/meta.rs:153`.
- `UndoEntry` (struct) — `[height-1]` snapshot for rollback meta restore; own framing (not ergo-ser) — `src/store/undo.rs:23`.
- `Segment` (struct) — shared body for all parent + spill records; signed-i64 box entries (sign = spent) — `src/segment.rs:48`.
- `IndexedAddress` + `BalanceInfo` (struct) — address parent + running balance — `src/address.rs:131` / `:46`.
- `IndexedTemplate` (struct) — template parent (box-segment only) — `src/template.rs:41`.
- `IndexedToken` (struct) — token parent + mint metadata — `src/token.rs:60`; `is_mint` (EIP-4 predicate) + `from_box`.
- `box_segment_id` / `tx_segment_id` / `token_unique_id` / `tree_hash_from_bytes` (fn) — `[inherited]` byte-exact derivations — `src/segment_id.rs:43`/`:48`/`:95`/`:84`.
- `IndexerError` (enum) + `halt_reason()` — typed errors; never crosses the API boundary — `src/error.rs:104`, mapping at `:355`.
- `IndexerConfig` (struct) — `[indexer]` TOML section — `src/config.rs:6`.
- `BlockApplyScratch` (struct) — run-loop arenas — `src/scratch.rs:36`.
- `OpenOutcome` (enum) — `CreatedFresh`/`Resumed`/`WipedAndRecreated` — `src/store/mod.rs:39`.
- `StoreHealthSnapshot` (struct) — mutually-consistent repair-marker + meta snapshot captured under one redb read txn; driven by `IndexerStore::health_snapshot` and surfaced via `IndexerHandle::health` as `IndexerHealthDto` — `src/store/mod.rs:67`.

## Invariants & contracts
- **Per-block atomicity.** All of a block's mutations — box/tx/numeric rows, address/template/token parents, spill segments, storage-rent rows, meta, undo write, undo prune — commit in a single redb `WriteTransaction`. Any `?` drops the txn (no commit), so on-disk state is exactly pre-call (`src/apply.rs:150-578`, `src/rollback.rs:156-635`).
- **Durability is `Eventual` on apply** (`src/apply.rs:162`): the per-block txn stays atomic but defers fsync; the crash-recovery model is "replay from chain tip" because every indexer row is derived state reproducible from the durable consensus store.
- **Sequential height contract.** Apply requires `block.height == meta.indexed_height + 1` (`HeightMismatch` otherwise); rollback requires `block.height == meta.indexed_height` AND `Some(block.header_id) == meta.indexed_header_id` (`HeightMismatch`/`HeaderMismatch`) — guards indexer/chain divergence and reorg races (`src/apply.rs:123`, `src/rollback.rs:87-102`).
- **Segment spill topology.** Head buffers spill when length is *strictly* > 512; each spill row holds exactly 512 entries; spill count counters are monotonic; rollback pops must merge-back and match the expected global index or fail `SegmentTopologyError` (`src/segment.rs:38,63`, `src/segment_buffer.rs:135`, `src/rollback.rs:321`).
- **Box-segment sign encoding.** Box entries are signed-i64: `+global_index` while unspent, `-global_index` after spend; the box *record's* `global_index` stays positive (the spent state lives on the spending-* fields). Tx entries are always positive. Dereference via `abs(entry)` (`src/segment.rs:11-13`, `src/handle.rs:733`).
- **`[inherited]` byte-exact derivations.** Segment-id strings (`" box segment "`, `" tx segment "`), token unique-id suffix (`"token"`, no spaces), tree-hash = `blake2b256(canonical tree bytes)`, and template-hash are Scala-parity formulas; a single wrong byte produces records Scala-compatible clients cannot look up (`src/segment_id.rs:20-101`).
- **Wire-format parity.** All persisted row codecs mirror Scala `ExtraIndexSerializer`/`Segment.scala`/`BalanceInfo.scala`/`IndexedToken.scala`: VLQ-zigzag i32/i64, unsigned VLQ for u16 and token `emissionAmount` (u64), raw 32-byte ids, `Opt[X]` = 1 marker byte + body. `emissionAmount` u64-vs-i32 and `Some("")` ≠ `None` are load-bearing (`src/ser/mod.rs:1-58`, `src/token.rs:9-23`). `BalanceInfo.tokens` is order-preserving (first-touch append) — byte output depends on token-touch order.
- **Schema wipe/resume.** `INDEXER_SCHEMA_VERSION = 2`. File absent → create fresh; version matches → resume; version mismatches → delete + recreate (full resync); version key missing → halt `SchemaCorruption`; meta table missing → halt `DbCorruption`. No in-place migration (`src/store/mod.rs:85-144`, `src/store/meta.rs:25`).
- **Rollback window.** `INDEXER_UNDO` retains entries for `ROLLBACK_WINDOW = 200` (mirrors `ergo-state`); pruned strictly-less-than `current_height - 200` so the deepest target survives. Undo decode enforces strict-EOF (rollback removes the row after consuming it, so a corrupt-then-rewritten row would otherwise hide) (`src/store/undo.rs:128-146,84-95`).
- **Protocol-genesis box absorption.** The 3 protocol-seeded box IDs (foundation / no-premine / emission) are never in `INDEXED_BOX`; their first spend pushes `0` to `input_nums` and continues instead of `InputMissing`, mirroring Scala `ExtraIndexer.scala:331`. Genesis (height 1) skips the input-spend pass entirely (`src/apply.rs:191-222,318`, `src/rollback.rs:241-243,414`).
- **Storage-rent index coherence.** `unspent_by_creation_height` is keyed by the box's own `creationHeight` (R3 metadata, *not* inclusion height) + immutable `global_box_index`; symmetric insert-on-output / remove-on-input with apply, fully re-derived from unchanged `IndexedErgoBox` rows on rollback (no undo-payload extension) (`src/store/storage_rent.rs:1-24`, `src/apply.rs:251,381`, `src/rollback.rs:295,472`).
- **Secondary-index degrade-not-halt.** A `SegmentEntryMissing` on a DERIVED secondary index (template/token box-segment) is tolerated — the indexer marks a sticky `repair_pending` marker in `INDEXER_META` and continues applying blocks rather than halting. The PRIMARY address segments still halt on any topology error. On the next poll, `IndexerTask::step` detects the marker and runs `rebuild_secondary_indexes` (chain-free, from the intact primary box table) before resuming normal forward-apply. A process-lifetime counter `secondary_index_drift_skips()` and the durable repair markers drive the health surface (`src/segment_buffer.rs:76,101`, `src/task.rs:139-170`, `src/rebuild.rs`).
- **Halted-handle read isolation.** A boot-time-halted handle has no store; reads return `None`/empty/0 and the polling task is not spawned. The cached `indexed_height`/`status` reads recover from a poisoned lock rather than propagating panic, keeping the API surface up after an indexer fault (`src/handle.rs:32-39,158-184`).
- **Indexer DB isolation.** The redb file is separate from the chain store, so an indexer wipe never touches consensus data (`src/store/mod.rs:1-3`).

## Notes for the architecture doc
Two stale *source comments* in `src/store/mod.rs` (not README/docs claims): the `IndexerStore` doc at `:53-55` says apply/rollback are "layered on top via the `commit_apply_meta_only` / `commit_rollback_meta_only` helpers" — but `apply.rs`/`rollback.rs` inline their meta+undo+prune writes in their own write txn; those helpers are only used by integration tests. `begin_write`'s doc at `:591` references a `commit_block_txn` method that does not exist. Worth a cleanup pass, but outside the README/docs accuracy scope.
