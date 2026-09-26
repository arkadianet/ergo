# ergo-wallet-service

**Purpose:** Transport-neutral wallet orchestration, persistence, and runtime
core. Owns wallet state, the redb wallet store, apply/rollback/rescan logic,
chain-client boundaries, box selection, and unsigned transaction construction.
It is the service-owned runtime core, but it does not own HTTP, node lifecycle,
or secret-file policy.

**Depends on (workspace):** `ergo-wallet`, `ergo-wallet-protocol`,
`ergo-primitives`, `ergo-ser`, `ergo-validation`
**Normal dependency boundary:** the allowed normal direct dependencies are the
five workspace crates above plus `serde`, `serde_json`, `hex`, `thiserror`,
`redb`, and `bincode`. There is intentionally no direct `ergo-sigma`
dependency: the service consumes sigma-facing types through `ergo-wallet` and
`ergo-validation`, so an extra edge would be unused. The normal tree must not
contain `ergo-state`, `ergo-api`, `ergo-node`, `ergo-mempool`, `ergo-mining`,
`ergo-sync`, `tokio`, or `axum`; `tests/dependency_boundary.rs` enforces this.
**Depended on by:** `ergo-node`; `ergo-state` during the transitional
`ergo-state -> ergo-wallet-service` integration
**Approx LOC:** ~9.2K (`src/**/*.rs`)

## Start here
- `src/lib.rs` — module map and the service's public re-exports.
- `src/state.rs` — in-memory `WalletState`, tracked-key caches, hydration, and
  lock-state projection.
- `src/runtime.rs:71` — `WalletService`/`WalletRuntime`, status and balance
  reads, bounded sync, and rescan orchestration.
- `src/chain.rs:193` — object-safe `ChainClient` plus neutral tip, snapshot,
  block-range, UTXO, and submit shapes used by the runtime.
- `src/wallet/store.rs:52` — `WalletStore`/`WalletRead`/`WalletWrite` and the
  `RedbWalletStore` implementation.
- `src/wallet/apply/` — chain-apply classification, scan tracking, maturity,
  and rollback hooks; these run inside the state's existing redb transaction.
- `src/tx_builder.rs` and `src/box_selector/` — pure box selection and
  unsigned transaction construction, including EIP-27 re-emission handling.

## Modules
- `src/runtime.rs` — synchronous service orchestration over a wallet store and
  chain client; `WalletRuntime` is an alias for `WalletService`.
- `src/chain.rs` — runtime-facing chain port and owned response types.
- `src/state.rs` — cached wallet state and hydration boundary.
- `src/wallet/` — redb tables, value types, reader/writer traits, apply and
  maturity logic, scan tracking, schema migration, and rescan service.
- `src/tx_builder.rs`, `src/box_selector/` — transaction/UTXO construction
  logic independent of a transport.
- `src/scan/` — scan predicates, registry, and scan request types.

## Key types, traits & functions
- `WalletService` / `WalletRuntime` — service-owned runtime facade.
- `WalletStatus`, `RescanRequest`, `RescanReport` — status and bounded
  synchronization results.
- `ChainClient`, `CommittedTip`, `BlocksSinceResponse` — transport-neutral
  chain port used by rescan and runtime reads.
- `WalletState`, `HydrationSource` — in-memory wallet projection and its
  persistence input.
- `WalletStore`, `WalletRead`, `WalletWrite`, `RedbWalletStore` — persistence
  port and redb implementation.
- `WalletApplyHook`, `WalletApplyPayload`, `WalletWiring`, `RescanGuard` —
  chain-state integration contracts.
- `WalletScanService`, `WalletScanCursor`, `RescanState` — recovery and cursor
  state.
- `UnsignedTxBuilder`, `SelectionPlan`, `BoxSelector` — transaction
  construction and input selection.
- `Balance`, `WalletBox`, `WalletTransaction`, `TrackedPubkeyMeta` — owned
  persistence/read value types.

## Invariants & contracts
- **Service-owned persistence.** Wallet tables, schema migration, wallet
  reads/writes, apply/rollback, maturity, and rescan logic live here. The
  tables are opened against the same `state.redb` database as chain state so
  chain and wallet mutations can share one commit, but the service does not
  depend on the `ergo-state` crate.
- **Transactional chain integration.** `WalletApplyPayload` carries owned
  block data across the chain/persist boundary. `ergo-state` calls the
  service-backed `WalletWrite` implementation inside its existing write
  transaction; the transitional `ergo-state -> ergo-wallet-service` edge is
  the compatibility seam, not a second database.
- **Fail-closed recovery.** Apply generations, fences, rescan state, and the
  durable `scan_invalidated` flag prevent a partial or reorg-conflicted
  replay from silently advancing wallet state.
- **Transport neutrality.** The service exposes synchronous ports and owned
  values. It does not open sockets, spawn a tokio runtime, depend on axum, or
  know the node's command loop.
- **Relocation is transitional.** The service is the runtime and persistence
  core, while the current node still supplies embedded secret storage, the
  `WalletStateHook`, the wallet writer command loop, and the API adapter.
  Full runtime relocation is therefore not complete in this phase.
