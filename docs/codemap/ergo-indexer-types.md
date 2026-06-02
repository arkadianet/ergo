# ergo-indexer-types

**Purpose:** The reader-side surface of the optional `/blockchain/*` extra-index: the `IndexerQuery` trait, the per-type DTOs/record types it returns, the in-memory `IndexerStatus`/`IndexerHaltReason` enums, the mainnet protocol-genesis box-ID whitelist, and the `Digest32` ID aliases. Split out from `ergo-indexer` so `ergo-api` can consume the read surface without depending on `redb` or `ergo-state`.

**Depends on (workspace):** ergo-primitives, ergo-ser
**Depended on by:** (see codemap index) — ergo-api, ergo-indexer
**Approx LOC:** ~468 (src, incl. tests)

## Start here
- `IndexerQuery` (trait) — `src/query.rs:31` — the entire confirmed-only reader contract; the 25-method surface the API mounts routes against. Read this first.
- `src/lib.rs` — module tree, re-exports, and the `Digest32` ID aliases (`BoxId`, `TxId`, `TokenId`, `HeaderId`, `TreeHash`, `TemplateHash`).
- `IndexedErgoBox` / `IndexedErgoTransaction` (structs) — `src/types.rs:33,66` — the two persisted in-memory record types every box/tx DTO aliases to.
- `IndexerStatus` (enum) — `src/status.rs:7` — the `Syncing`/`CaughtUp`/`Halted` gate the router middleware checks before any read.

## Modules
- `src/lib.rs` — crate root: declares the 4 modules, re-exports the public surface, defines the six `pub type X = Digest32` ID aliases.
- `src/query.rs` — the `IndexerQuery` trait, paging primitives (`Page`, `SortDir`), and the DTO surface (`IndexedBoxDto`/`IndexedTxDto` aliases plus `BalanceDto`, `IndexedTokenDto`, `StorageRentEligibleDto`, `IndexedBlockDto`).
- `src/types.rs` — the parsed/structured in-memory record types (`IndexedErgoBox`, `IndexedErgoTransaction`) held while applying and surfaced to readers. The wire format lives in `ergo-indexer::ser`, not here.
- `src/status.rs` — `IndexerStatus` (never persisted) and `IndexerHaltReason` (kebab-case serde enum) with its `as_kebab_case()` / `detail()` formatters for the `503` envelopes.
- `src/protocol_genesis.rs` — `const`-evaluated mainnet protocol-genesis box-ID whitelist + `is_protocol_genesis_box`; lets the apply path absorb the first spend of the 3 pre-block-1 boxes instead of halting `InputMissing`.

## Key types, traits & functions
- `IndexerQuery` (trait) — confirmed-only reader; `Send + Sync + 'static`, infallible (router gates on `status() == CaughtUp`) — `src/query.rs:31`
- `IndexerQuery::indexed_height` / `status` / `is_caught_up` — height + gate primitives; `is_caught_up` is a default-impl convenience over `status()` — `src/query.rs:32,33,40`
- Storage-rent trait methods (`storage_rent_eligible_paged`, `storage_rent_eligible_total`, `storage_rent_in_creation_range`, `storage_rent_total_in_creation_range`) — have default impls returning empty/0 so fixtures/stubs inherit them; production `IndexerHandle` overrides — `src/query.rs:96,111,127,142`
- `Page` (struct) / `SortDir` (enum) — `(offset, limit)` paging + sort direction; `MaxItems` is enforced at the API layer, not validated here — `src/query.rs:9,17`
- `IndexedErgoBox` (struct) + `is_spent()` — one redb row per `BoxId`; `global_index` always non-negative on the box record (spent-flag is segment-side sign); spend triple set/unset together — `src/types.rs:33,49`
- `IndexedErgoTransaction` (struct) — one redb row per `TxId`; `input_nums`/`output_nums` are global indices for `byIndex`; `numConfirmations` deliberately omitted (rebuilt on read) — `src/types.rs:66`
- `BalanceDto` (struct) — ERG nanos + order-preserving `tokens` vec; mirrors Scala `BalanceInfo` first-touch insertion order — `src/query.rs:187`
- `IndexedTokenDto` (struct) — mint metadata; `emission_amount` is `i64` to match Scala signed `Long` JSON (persisted as `u64`) — `src/query.rs:207`
- `StorageRentEligibleDto` (struct) — one `unspent_by_creation_height` row carrying rent-computation fields — `src/query.rs:172`
- `IndexedBlockDto` (struct) — unit-struct placeholder; block reassembly not yet wired — `src/query.rs:218`
- `IndexerStatus` (enum) — `Syncing` / `CaughtUp` / `Halted(IndexerHaltReason)`; never persisted — `src/status.rs:7`
- `IndexerHaltReason` (enum) + `as_kebab_case()` / `detail()` — 5 fatal classifications feeding the `503 indexer-halted` envelope — `src/status.rs:20,41,54`
- `PROTOCOL_GENESIS_BOX_IDS_MAINNET` (const) + `is_protocol_genesis_box(&[u8;32]) -> bool` — emission/no-premine/foundation box-ID whitelist for apply-path absorption — `src/protocol_genesis.rs:24,36`
- ID aliases: `BoxId`, `TxId`, `TokenId`, `HeaderId`, `TreeHash`, `TemplateHash` = `Digest32` — `src/lib.rs:23-28`

## Invariants & contracts
- `IndexerQuery` is infallible by contract: the router middleware gates every read on `status() == CaughtUp` before invoking any method, so methods return bare values, not `Result` (`src/query.rs:22-31`).
- `IndexedErgoBox.global_index` is always non-negative on the box record (assigned at output time, never sign-flipped). The spent-flag is carried by the segment-side sign, not the box record (`src/types.rs:39-43`).
- `[inherited]` segment-filter quirk: segment-based unspent queries filter `_ > 0`, so the genesis output (`global_index = 0`) is invisible to those routes on both Scala and Rust — must not be "fixed" to include 0 (`src/types.rs:21-26`).
- Box spend triple (`spending_tx_id`, `spending_height`, `spending_proof`) is always set or unset together, mirroring Scala `IndexedErgoBox.asSpent` (`src/types.rs:28-31,35-37`).
- Mempool-overlay discriminator is `inclusion_height == 0` (block heights start at 1), NOT `global_index == 0` (`src/types.rs:14-19`).
- `numConfirmations` is transient (rebuilt on read as `bestFullBlockHeight - height`) and deliberately not modeled — the API formatter computes it from the indexer's `indexed_height()` (`src/types.rs:61-64`).
- `IndexerStatus` is never persisted: persisting `CaughtUp` could let a stale positive open routes before the indexer confirms the canonical tip (`src/status.rs:3-5`).
- `IndexerHaltReason::as_kebab_case()` is a pinned wire string: the literal `<reason>` in the `503 indexer-halted` envelope `detail`; it tracks the serde `rename_all = "kebab-case"` derivation but is surfaced as `&'static str` so middleware skips `serde_json` quote-stripping (`src/status.rs:33-49`).
- `BalanceDto.tokens` ordering is consensus-observable parity: order-preserving first-touch insertion to diff byte-for-byte against Scala `BalanceInfo.tokens` (`src/query.rs:182-189`).
- `IndexedTokenDto.emission_amount` is `i64` to match Scala's signed `Long` JSON shape even though the persisted record is `u64`; the projection casts via `as i64` (loss-free for realistic emissions) (`src/query.rs:200-205`).
- `PROTOCOL_GENESIS_BOX_IDS_MAINNET` is a closed 3-ID whitelist matching `test-vectors/mainnet/genesis_boxes.json`; only these IDs' first spends are absorbed silently, every other unknown input keeps `InputMissing` terminal (`src/protocol_genesis.rs:9-20`).
