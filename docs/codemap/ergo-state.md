# ergo-state

**Purpose:** Authenticated UTXO state for the Ergo node. Owns the
redb-backed `StateStore` that validated blocks apply to: an in-memory AVL+
tree with arena-backed node storage and incremental root-label maintenance,
an atomic `apply_block` / `rollback_to` (delta-based reorg) commit path, the
header/section chain index, voted protocol parameters, Mode 2 UTXO-snapshot
install, Mode 3 suffix pruning, and a sibling Mode 5 digest-verifier backend
(`DigestStateStore`).

Wallet tables and wallet apply/rescan code are now owned by
`ergo-wallet-service`. `ergo-state` keeps a compatibility wallet facade and
coordinates service-backed wallet writes inside the same `state.redb` write
transaction, because moving that transaction boundary is transitional phase-2
work.

**Depends on (workspace):** `ergo-primitives`, `ergo-ser`, `ergo-chain-spec`,
`ergo-crypto`, `ergo-validation`, `ergo-sigma`, `ergo-wallet`,
`ergo-wallet-service`
**Depended on by:** (see codemap index)
**Approx LOC:** ~35K (source and substantial inline tests)

## Start here
- `src/lib.rs` — module map and the public state/apply surface.
- `src/store/mod.rs` — `StateStore` plus the chain-state data model and the
  service-backed wallet re-exports used by the state integration.
- `src/store/apply.rs` — the apply pipeline: builds the service-owned
  `WalletApplyPayload`, applies UTXO changes, and commits chain plus wallet
  state atomically.
- `src/avl/tree.rs` — the authenticated AVL+ tree and its O(1) root digest.
- `src/backend.rs` — `StateBackend`, `ChainStateRead`, `HeaderSectionStore`,
  and `BlockApply` dispatch for UTXO and digest backends.
- `src/reader.rs` — lock-free `ChainStoreReader` and committed block/wallet
  read helpers.
- `src/wallet/mod.rs` — the transitional facade: most `wallet` submodules are
  re-exports from `ergo-wallet-service`, not a second implementation.
- `src/store/wallet_tx_bridge.rs` — the chain-side adapter that builds owned
  wallet block data and maps state errors into the service rescan error model.

## Modules
- `src/store/` — `StateStore`: open / genesis / apply / rollback / reorg /
  snapshot install / pruning, plus redb table definitions. Important children
  are `apply.rs` (block-apply and service wallet payload), `reorg.rs`,
  `undo.rs`, `snapshot.rs`, `dry_run.rs`, `lazy_prover.rs`, `votes.rs`,
  `popow_cache.rs`, `meta.rs`, `open.rs`, `rebuild.rs`, `backfill.rs`, and
  `error.rs`.
- `src/avl/` — AVL+ nodes, arena, digest, changelog, serialization, hydration,
  and Scala-compatible snapshot codecs.
- `src/backend.rs` — backend traits and `StateBackendKind` dispatch.
- `src/chain.rs` — `HeaderMeta`, `ChainStateMeta`, `ChainState`, and
  header-availability types.
- `src/reader.rs` — `ChainStoreReader`, committed snapshots, chain-index reads,
  and block data for wallet rescans.
- `src/persist.rs` — background persistence pipeline. A queued job carries
  the service-owned wallet payload and applies it in the batch write
  transaction.
- `src/diff.rs` — block-apply transaction diffs consumed by the mempool and
  indexer.
- `src/active_params.rs` — voted-parameter redb table helpers.
- `src/header_store.rs` — header/section tables and buffered-write overlay.
- `src/digest_store.rs`, `src/digest_apply.rs`, `src/digest_utxo_view.rs` —
  Mode 5 digest persistence and ADProof-driven verification.
- `src/wallet/` — compatibility facade over `ergo-wallet-service`: apply and
  scan hooks, reader/store/table/value types, maturity, schema migration, and
  rescan exports. The service owns the implementation; state still calls it
  through the facade.
- `src/redb_util.rs` — `begin_write_qr` and repair-logging write helper.

## Key types, traits & functions
- `StateStore` — Mode 1/2/3/6 UTXO state store.
- `StateStore::apply_block` — apply a `CheckedBlock` and advance the tip.
- `StateStore::rollback_to` — delta-based reorg rollback.
- `StateStore::persist_apply` — atomic chain-plus-wallet commit unit.
- `StateStore::install_snapshot_state` — Mode 2 UTXO snapshot install.
- `AvlTree`, `AvlNode`, `NodeArena` — authenticated tree and node storage.
- `ChainStoreReader` — lock-free committed-state read handle.
- `StateBackend`, `ChainStateRead`, `HeaderSectionStore`, `BlockApply` —
  generic backend dispatch traits.
- `DigestStateStore`, `DigestProofVerifier` — Mode 5 digest backend.
- `PersistPipeline`, `PersistResult` — background commit batching.
- `WalletApplyHook`, `WalletApplyPayload`, `WalletWiring`, `RescanGuard` —
  service-owned integration contracts re-exported through the state facade.
- `WalletStore`, `WalletRead`, `WalletWrite`, `RedbWalletStore` — service
  persistence ports used by the state transaction.
- `WalletScanService`, `WalletScanCursor`, `RescanState` — service rescan
  surface exposed to the state/node integration.
- `StateError` — state/store error taxonomy, including conversion from
  service wallet-store errors.
- `begin_write_qr` — mandatory quick-repair write-transaction helper.

## Invariants & contracts
- **Atomic commit per applied block.** `persist_apply` writes undo-log, AVL+
  mutations, chain index, state metadata, epoch-boundary voted parameters,
  and service-owned wallet rows in one redb write transaction. Wallet writes
  use the service-backed `WalletWrite` implementation on that same transaction;
  the service does not open a second state database.
- **Delta-based reorg.** Reorg is `rollback_to(common_ancestor)` followed by
  re-application. Rollback replays each block's before-image through the
  service wallet rollback path and restores the in-memory chain from committed
  disk state after an AVL mutation failure.
- **Cursor continuity and recovery.** Wallet cursor height, header identity,
  chain-index identity, scan invalidation, and rescan state are checked across
  apply, rollback, restart, and migration paths. A partial or stale rescan
  cannot silently advance the wallet cursor.
- **Undo-log keys are `(height, header_id)`.** The composite key lets fork
  branches at the same height coexist.
- **best_header and best_full_block are separate.** They are tracked
  independently so header-first sync and headers-only digest mode remain
  possible.
- **Invalidity policy.** `pow_validity` is the only persisted validity flag;
  other failures are session-scoped and cleared on restart.
- **AVL+ label hashing matches the reference.** Leaf and internal label
  prefixes, the `ADDigest` layout, and snapshot codecs are consensus-facing
  byte contracts.
- **Single-writer state; generic backend dispatch.** The node action loop is
  the sole chain-state writer. The backend is monomorphized through
  `B: StateBackend`; it is not a `dyn` dispatch boundary.
- **Crash-repair contract.** Every production write transaction routes through
  `begin_write_qr` with quick repair enabled.
- **Dependency boundary.** `ergo-state` may depend on
  `ergo-wallet-service` for the transitional facade, but the service must
  not depend on `ergo-state`. This direction preserves the shared-database
  transaction seam without creating a cycle.
- **Validation direction.** `ergo-state` depends on `ergo-validation`, not the
  reverse: state asks validation whether a block is legal before applying it.

## Transitional wallet facade

`ergo-state/src/wallet/` and selected `ergo-state/src/store` exports preserve
the historical `ergo_state::wallet` paths while delegating implementation to
`ergo-wallet-service`. The state crate remains the owner of the chain apply
and rollback orchestration; the service owns wallet tables, reader/writer
semantics, apply classification, maturity, scan tracking, and rescan logic.
The edge is deliberately one-way and transitional: full runtime relocation
from the node/state integration is not complete in this phase.
