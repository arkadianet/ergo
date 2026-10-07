# ergo-indexer-types

**Purpose:** The reader-side surface of the optional `/blockchain/*` extra-index: the `IndexerQuery` trait, the per-type DTOs/record types it returns, the in-memory `IndexerStatus`/`IndexerHaltReason` enums, the mainnet protocol-genesis box-ID whitelist, and the `Digest32` ID aliases. Split out from `ergo-indexer` so `ergo-api` can consume the read surface without depending on `redb` or `ergo-state`.

**Depends on (workspace):** ergo-primitives, ergo-ser
**Depended on by:** (see codemap index) — ergo-api, ergo-indexer

## Start here
- `IndexerQuery` (trait) — `src/query.rs:53` — the confirmed-only reader contract the API mounts routes against. Read this first.
- `src/lib.rs` — module tree, re-exports, and the `Digest32` ID aliases (`BoxId`, `TxId`, `TokenId`, `HeaderId`, `TreeHash`, `TemplateHash`).
- `IndexedErgoBox` / `IndexedErgoTransaction` (structs) — `src/types.rs:33,66` — the two persisted in-memory record types every box/tx DTO aliases to.
- `IndexerStatus` (enum) — `src/status.rs:7` — the `Syncing`/`CaughtUp`/`Halted` gate the router middleware checks before gated `/blockchain/*` reads.

## Modules
- `src/lib.rs` — crate root: declares the 4 modules, re-exports the public surface, defines the six `pub type X = Digest32` ID aliases.
- `src/query.rs` — the `IndexerQuery` trait, `IndexerReadError`, paging primitives (`Page`, `SortDir`), and the DTO surface (`IndexerHealthDto`, `IndexedBoxDto`/`IndexedTxDto` aliases plus `BalanceDto`, `IndexedTokenDto`, `StorageRentEligibleDto`, `IndexedBlockDto`).
- `src/types.rs` — the parsed/structured in-memory record types (`IndexedErgoBox`, `IndexedErgoTransaction`) held while applying and surfaced to readers. The wire format lives in `ergo-indexer::ser`, not here.
- `src/status.rs` — `IndexerStatus` (never persisted) and `IndexerHaltReason` (kebab-case serde enum) with its `as_kebab_case()` / `detail()` formatters for the `503` envelopes.
- `src/protocol_genesis.rs` — `const`-evaluated mainnet protocol-genesis box-ID whitelist + `is_protocol_genesis_box`; lets the apply path absorb the first spend of the 3 pre-block-1 boxes instead of halting `InputMissing`.

## Key types, traits & functions
- `IndexerQuery` (trait) — confirmed-only reader; `Send + Sync + 'static`; database reads return `Result<_, IndexerReadError>` independently of the status gate — `src/query.rs:43-55`
- `IndexerReadError` (struct) — database unavailability or inconsistent/corrupt storage, distinct from successfully queried missing data — `src/query.rs:23`
- `IndexerQuery::indexed_height` / `status` / `is_caught_up` — cached height + gate primitives, available without storage; `is_caught_up` is a default-impl convenience over `status()` — `src/query.rs:54,55,75`
- `IndexerQuery::health` (defaulted) — returns `Result<IndexerHealthDto, IndexerReadError>`; its operator HTTP route is never status-gated but returns 500 on read failure. Production `IndexerHandle` reads the real snapshot and preserves observed failures; stubs inherit `Ok(IndexerHealthDto::default())` — `src/query.rs:66`, `ergo-indexer/src/handle.rs:280-308`, `ergo-api/src/blockchain.rs:187-219`
- Storage-rent trait methods (`storage_rent_eligible_paged`, `storage_rent_eligible_total`, `storage_rent_in_creation_range`, `storage_rent_total_in_creation_range`) — default to `Ok(Vec::new())`/`Ok(0)` for fixtures/stubs; production `IndexerHandle` overrides with fallible store reads — `src/query.rs:177,192,208,223`
- `Page` (struct) / `SortDir` (enum) — `(offset, limit)` paging + sort direction; `MaxItems` is enforced at the API layer, not validated here — `src/query.rs:9,17`
- `IndexedErgoBox` (struct) + `is_spent()` — one redb row per `BoxId`; valid persisted records use non-negative `global_index` (spent-flag is segment-side sign) and a complete spend triple; public fields do not enforce these rules — `src/types.rs:33,49`
- `IndexedErgoTransaction` (struct) — one redb row per `TxId`; `input_nums`/`output_nums` are global indices for `byIndex`; `numConfirmations` deliberately omitted (rebuilt on read) — `src/types.rs:66`
- `IndexerHealthDto` (struct) — live health snapshot returned inside `Ok` by `health()`; fields expose the durable `INDEXER_META` repair markers (`repair_pending`, `repair_next_gi`, `repair_skipped`), process-lifetime `drift_skips` and running totals (`global_boxes`, `global_txs`); `Default` holds empty repair markers and zero counters — `src/query.rs:246-268`
- `BalanceDto` (struct) — ERG nanos + order-preserving `tokens` vec; mirrors Scala `BalanceInfo` first-touch insertion order — `src/query.rs:225`
- `IndexedTokenDto` (struct) — mint metadata; `emission_amount` is `i64` to match Scala signed `Long` JSON (persisted as `u64`) — `src/query.rs:245`
- `StorageRentEligibleDto` (struct) — one `unspent_by_creation_height` row carrying rent-computation fields — `src/query.rs:210`
- `IndexedBlockDto` (struct) — unit-struct placeholder; block reassembly not yet wired — `src/query.rs:256`
- `IndexerStatus` (enum) — `Syncing` / `CaughtUp` / `Halted(IndexerHaltReason)`; never persisted — `src/status.rs:7`
- `IndexerHaltReason` (enum) + `as_kebab_case()` / `detail()` — 5 fatal classifications feeding the `503 indexer-halted` envelope — `src/status.rs:20,41,54`
- `PROTOCOL_GENESIS_BOX_IDS_MAINNET` (const) + `is_protocol_genesis_box(&[u8;32]) -> bool` — emission/no-premine/foundation box-ID whitelist for apply-path absorption — `src/protocol_genesis.rs:24,36`
- ID aliases: `BoxId`, `TxId`, `TokenId`, `HeaderId`, `TreeHash`, `TemplateHash` = `Digest32` — `src/lib.rs:23-28`

## Invariants & contracts
- `IndexerQuery` database methods return `Result` even when `status() == CaughtUp`. The gated `/blockchain/*` routes reject `Syncing`/`Halted` with 503 before querying, but caught-up status does not establish storage health (`src/query.rs:43-55`, `ergo-api/src/blockchain.rs:261-277`). Cached height/status remain infallible; the operator health route is ungated and can return 500.
- Valid persisted `IndexedErgoBox.global_index` values are non-negative on the box record (assigned at output time, never sign-flipped). The spent-flag is carried by the segment-side sign, not the box record (`src/types.rs:39-43`).
- `[inherited]` segment-filter quirk: segment-based unspent queries filter `_ > 0`, so the genesis output (`global_index = 0`) is invisible to those routes on both Scala and Rust — must not be "fixed" to include 0 (`src/types.rs:21-26`).
- Valid persisted box spend triples (`spending_tx_id`, `spending_height`, `spending_proof`) are set or unset together, mirroring Scala `IndexedErgoBox.asSpent` (`src/types.rs:28-31,35-37`).
- Mempool-overlay discriminator is `inclusion_height == 0` (block heights start at 1), NOT `global_index == 0` (`src/types.rs:14-19`).
- `numConfirmations` is transient (rebuilt on read as `bestFullBlockHeight - height`) and deliberately not modeled — the API formatter computes it from the indexer's `indexed_height()` (`src/types.rs:61-64`).
- `IndexerStatus` is never persisted: persisting `CaughtUp` could let a stale positive open routes before the indexer confirms the canonical tip (`src/status.rs:3-5`).
- `IndexerHaltReason::as_kebab_case()` is a pinned wire string: the literal `<reason>` in the `503 indexer-halted` envelope `detail`; it tracks the serde `rename_all = "kebab-case"` derivation but is surfaced as `&'static str` so middleware skips `serde_json` quote-stripping (`src/status.rs:33-49`).
- `BalanceDto.tokens` ordering is consensus-observable parity: order-preserving first-touch insertion to diff byte-for-byte against Scala `BalanceInfo.tokens` (`src/query.rs:225-228`).
- `IndexedTokenDto.emission_amount` is `i64` to match Scala's signed `Long` JSON shape even though the persisted record is `u64`; the projection casts via `as i64` (loss-free for realistic emissions) (`src/query.rs:245-248`).
- `PROTOCOL_GENESIS_BOX_IDS_MAINNET` is a closed 3-ID whitelist matching `test-vectors/mainnet/genesis_boxes.json`; only these IDs' first spends are absorbed silently, every other unknown input keeps `InputMissing` terminal (`src/protocol_genesis.rs:9-20`).

Database query methods in `IndexerQuery` return `Result`: successful missing
point reads use `Ok(None)`, missing owners use empty pages or zero totals,
and unavailable/corrupt storage uses `Err(IndexerReadError)`. The `try_*`
aliases forward the same result contract.
Cached `status()` and `indexed_height()` remain available without storage.

Public record fields are unconstrained in-memory values, not checked constructors.
Persistence codecs and apply helpers enforce the valid-record contracts described
above; raw construction alone does not establish them.

`boxes_by_global_range` and `txs_by_global_range` use ascending half-open
`[lo, hi)` global-index ranges. `boxes_latest_paged` and `txs_latest_paged`
translate an offset into the latest indexed window using the counter and rows
from one read snapshot. Their default implementations return
`Err(IndexerReadError)` for an unsupported reader; an empty successful page
therefore means a supported query found no rows. The HTTP boundary rejects
values outside its signed paging domain before narrowing them.
