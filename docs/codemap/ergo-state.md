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
transaction, as the supported Phase 2 embedded compatibility boundary.

**Depends on (workspace):** `ergo-primitives`, `ergo-ser`, `ergo-chain-spec`,
`ergo-crypto`, `ergo-validation`, `ergo-sigma`, `ergo-wallet`,
`ergo-wallet-service`
**Depended on by:** (see codemap index)

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
  snapshot install / pruning, plus all redb table definitions. Submodules:
  `apply.rs` (block-apply core + `compute_minimal_full_block_height`),
  `reorg.rs` (`rollback_to` three-phase delta replay), `undo.rs` (`UndoEntry`
  reverse-delta codec), `snapshot/` (`CommittedSnapshot` single-txn off-loop
  view + mining-candidate dry-run), `dry_run.rs` (`apply_change_set_via_prover`),
  `lazy_prover.rs` (scoped-worker AVL proof generation with on-demand node
  expansion, backing `StateStore::regenerate_ad_proofs`),
  `votes.rs`, `popow_cache.rs` (NiPoPoW prover/interlinks), `meta.rs`
  (`StateMeta` row), `open.rs`, `rebuild.rs` (rebuild-from-committed recovery),
  `backfill.rs` (legacy index back-fill), `error.rs` (`StateError`).
- `src/avl/` — AVL+ primitives: `node.rs` (`AvlNode` enum, `NodeId`),
  `tree.rs` (`AvlTree`), `arena.rs` (`NodeArena` trait + memory/cached-disk
  arenas), `digest.rs` (leaf/internal label + root-digest math),
  `changelog.rs` (`ChangeLog` before-image undo), `serialization.rs` (node
  byte codec), `hydrate.rs` (rebuild tree from `AVL_NODES`), `snapshot_codec/`
  (Scala-byte-exact `ProverNodeSerializer` codec for Mode 2 snapshot chunks).
- `src/backend.rs` — `StateBackend`/`ChainStateRead`/`HeaderSectionStore`/
  `BlockApply` traits + `StateBackendKind` enum dispatch.
- `src/chain.rs` — `HeaderMeta`, `ChainStateMeta`, `ChainState`,
  `HeaderAvailability`, `HeightLookup`: serialization-focused chain-index types.
- `src/reader.rs` — `ChainStoreReader`: lock-free `Clone` read handle (own redb
  read txn per call) used by the API layer and indexer.
- `src/persist.rs` — background persist pipeline (`PersistPipeline`,
  `PersistResult`, `PersistProgress`) batching AVL writes into one redb commit
  off the action loop, with a shared first-failure latch and commit barrier.
- `src/diff.rs` — block-apply tx diff (`TipPointer`, `AppliedTx`, `TxDiff`)
  consumed by the indexer/mempool.
- `src/active_params.rs` — `voted_params` redb table read/write helpers
  (`VOTED_PARAMS`); the `ActiveProtocolParameters` type itself lives in
  `ergo-validation`.
- `src/header_store.rs` — `HeaderSectionTables`: the header/section tables +
  buffered-write overlay shared by both backends.
- `src/digest_store/mod.rs` — `DigestStateStore`: Mode 5 persistence sibling to
  `StateStore` (digest + chain-state history ledgers, no arena).
- `src/digest_apply.rs` — `DigestProofVerifier`, `DigestApplyError`,
  `ResolvedBoxes`: verifies a block's ADProofs and derives the post-apply digest.
- `src/digest_utxo_view.rs` — `DigestUtxoView`: resolves a block's input boxes
  from its ADProofs so the digest backend can run full tx validation.
- `src/wallet/` — compatibility facade over `ergo-wallet-service`, which owns
  wallet tables, reader/writer types, apply/maturity/scan logic and schema migration.
  Embedded writes still share the chain's `state.redb` transaction; the daemon
  uses its own `wallet.redb`.
- `src/redb_util.rs` — `begin_write_qr` (quick-repair write txn) +
  `open_with_repair_logging`; every production write txn must route through here.

## Key types, traits & functions
- `StateStore` (struct) — Mode 1/2/3/6 UTXO state store — `src/store/mod.rs:641`
- `StateStore::apply_block` (fn) — apply a `CheckedBlock`, advancing the tip — `src/store/apply.rs:139`
- `StateStore::rollback_to` (fn) — delta-based reorg rollback to a target height — `src/store/reorg.rs:41`
- `StateStore::persist_apply` (fn) — the atomic one-txn commit unit — `src/store/mod.rs:4271`
- `StateStore::install_snapshot_state` (fn) — Mode 2 UTXO-snapshot install — `src/store/mod.rs:1091`
- `StateStore::regenerate_ad_proofs` (fn) — regenerate a block's ADProofs from
  the parent tree via on-demand AVL reads (Scala `UtxoState` proof generation);
  self-checks the proof and never mutates the tree — `src/store/mod.rs:2822`
- `AdProofsApplyPolicy` (enum) — `Regenerate` (default for UTXO stores) vs
  `VerifyShipped` (digest/opt-in tests) — `src/store/mod.rs:752`
- `compute_minimal_full_block_height` (fn) — Mode 3 prune low-water mark (Scala parity) — `src/store/apply.rs:53`
- `AvlTree` (struct) — incremental authenticated AVL+ tree — `src/avl/tree.rs:61`
- `AvlNode` (enum) — Leaf / Internal node, with cached labels — `src/avl/node.rs:18`
- `leaf_label` / `internal_label` (fn) — consensus-critical label hashes — `src/avl/digest.rs:32`, `:52`
- `NodeArena` (trait) — pluggable node storage (memory / cached-disk) — `src/avl/arena.rs:25`
- `UndoEntry` (struct) — per-block reverse delta (changelog + box-level) — `src/store/undo.rs:18`
- `ChainState` / `ChainStateMeta` (struct) — in-memory vs persisted chain pointers — `src/chain.rs:358`, `:209`
- `HeaderMeta` (struct) — persisted header row; `pow_validity` is the only persisted validity flag — `src/chain.rs:22`
- `HeaderAvailability` (enum) — Dense vs PoPowSparse history mode — `src/chain.rs:135`
- `ChainStoreReader` (struct) — lock-free read handle — `src/reader.rs:31`
- `CommittedSnapshot` (struct) — single-txn committed view for off-loop builds — `src/store/snapshot/mod.rs`
- `StateBackend` / `ChainStateRead` / `HeaderSectionStore` / `BlockApply` (traits) — backend dispatch surface — `src/backend.rs:42`–`:158`
- `StateBackendKind` (enum) — `Utxo` / `Digest` runtime dispatch — `src/backend.rs:299`
- `DigestStateStore` (struct) — Mode 5 digest-verifier backend — `src/digest_store/mod.rs:140`
- `DigestProofVerifier` (struct) — ADProof-driven digest derivation — `src/digest_apply.rs:156`
- `PersistPipeline` / `PersistResult` (struct/enum) — background commit batching — `src/persist.rs:284`, `:261`
- `StateError` (enum) — crate-wide error; re-exported as `ergo_state::store::StateError` — `src/store/error.rs`
- `begin_write_qr` (fn) — quick-repair write-txn helper (mandatory for all writes) — `src/redb_util.rs:33`

## Invariants & contracts
- **Atomic commit per applied block.** `persist_apply` writes undo_log +
  AVL+ node mutations + chain_index + state_meta + (epoch-boundary) voted_params
  + (when hooked) wallet rows in a single redb write transaction. Either all
  land or none do.
- **Chain metadata ownership.** Header writes merge only their header pointer,
  score and availability with the full-block pointer already committed in the
  same transaction. Persist batches merge their full-block pointer with the
  latest committed header selection. A stale batch cannot replace a newer
  header or a same-height selected fork; a foreground header write cannot
  publish queued AVL progress. Open rejects full-block height differing from
  AVL metadata height instead of trusting an inconsistent snapshot baseline.
- **Persistence failure is terminal.** The first failed batch stops the worker.
  No dependent delta may commit after it. The shared failure latch is
  authoritative even when result notifications are full; sends, drains,
  barriers and explicit shutdown return the original error. Shutdown still
  joins the worker and attempts the final synchronous commit, and reports
  failure rather than claiming success. Joined pipelines retain their failure
  and cannot be replaced in the same store; recovery requires reopening from
  committed state. Repeated shutdown cannot erase an earlier failure.
- **Commit and durability are separate.** `flush_persist_pipeline` waits for
  transaction commit, not device synchronization. Normal and periodic durable
  batches use `Durability::Immediate`; relaxed IBD batches use `None`. Leaving
  IBD drains queued jobs and forces an Immediate barrier before changing mode.
  `persistence_progress` reports admitted, committed and synchronously durable
  cumulative job counts across worker rebinding, not heights. The configured IBD
  interval alone does not bound replay loss: queued jobs add volatile work to
  committed jobs since the last fsync. A process crash and a machine power
  failure have different survival guarantees, and durable writes depend on
  the operating system/device honoring fsync.
- **Delta-based reorg.** There is no single "reorg" method; reorg is
  `rollback_to(common_ancestor)` then re-apply. Rollback replays each block's
  `ChangeLog` before-image in reverse via `apply_rollback_mutations`. Any
  failure after AVL mutation routes through `rebuild_from_committed` to restore
  in-memory state from committed disk state.
- **undo_log keys are (height, header_id).** Composite 36-byte key so
  competing fork branches at the same height coexist (`store/undo.rs`,
  `UNDO_LOG` def in `store/mod.rs:74`).
- **best_header and best_full_block are separate.** Tracked independently in
  `ChainState` / `ChainStateMeta`; the gap drives IBD block download.
- **Invalidity policy.** `pow_validity` persists definitive PoW invalidity
  (`2`) and full-block consensus-rule invalidity (`3`), including descendants.
  IO, missing context, local consistency errors and ambiguous digest failures
  use session marks instead. The sync executor owns verdict classification.
- **AVL+ label hashing matches scorex-util / `ergo_avltree_rust`.** Leaf =
  `blake2b256(0x00 ‖ key ‖ value ‖ next_key)`, Internal =
  `blake2b256(0x01 ‖ balance ‖ left_label ‖ right_label)`, ADDigest =
  `root_label[32] ‖ tree_height[1]`. Note the label prefixes (leaf=0,
  internal=1) are the OPPOSITE of the node serialization prefixes (leaf=1,
  internal=0) — `avl/digest.rs`, `avl/snapshot_codec/mod.rs`.
- **Snapshot node codec is Scala-byte-exact.** `value_length` is fixed-width
  4-byte big-endian (`Ints.toByteArray`), NOT VLQ (`avl/snapshot_codec/mod.rs`).
- **Snapshot installation and trust are separate.** Codec reconstruction
  verifies manifest/chunk labels; the caller must supply the authenticated
  header root. Install drains any worker, replaces AVL rows, co-commits root
  and allocator metadata, then publishes the height/tree and rebinds the
  worker without resetting progress. Runtime node IDs start at 1, reserving
  0 for NULL; legacy imported root-0 stores fail explicitly on reopen.
- **Single-writer state; generic (not `dyn`) backend dispatch.** The action
  loop is the sole writer, so the executor binds `B: StateBackend` and
  monomorphizes; the differing `apply_full_block` internals (box arena vs
  ADProof verifier) are not object-safe behind `dyn` (`backend.rs:13`).
- **Backend schema separation enforced by `data_dir_state_type`.** `"utxo"`,
  `"digest"` (headers-only Mode 6, same schema), and `"digest-verifier"` (Mode 5,
  incompatible schema). A dir carrying both AVL arena rows and digest-verifier
  markers with no sentinel is a hard `DbCorruption` — never inferred
  (`store/mod.rs:425`).
- **Mode 3 prune monotonicity / rollback-window safety.** The prune
  low-water mark never walks backward (`compute_minimal_full_block_height`),
  and `blocks_to_keep >= ROLLBACK_WINDOW + SAFETY_MARGIN` is enforced at config
  load so the active rollback window can never fall into pruned territory
  (`store/mod.rs:173`, `:608`).
- **Crash-repair contract.** Every write txn goes through `begin_write_qr`
  (quick_repair on); a single non-quick-repair commit defeats it for all prior
  commits, so the rule is mechanical: zero `db.begin_write()` outside this
  helper (`redb_util.rs:10`).
- **`ergo-state` depends on `ergo-validation`, not vice versa.** State asks
  validation "is this block legal?" before applying; it never defines
  acceptance rules.

## Transitional wallet facade

`ergo-state/src/wallet/` and selected `ergo-state/src/store` exports preserve
the historical `ergo_state::wallet` paths while delegating implementation to
`ergo-wallet-service`. The state crate remains the owner of the chain apply
and rollback orchestration; the service owns wallet tables, reader/writer
semantics, apply classification, maturity, scan tracking, and rescan logic.
The edge is deliberately one-way. Phase 2 retains this compatibility facade
and embedded co-commit boundary; hosting the spending engine in the daemon and
cutting over embedded storage are follow-on deployment work.
## Doc accuracy notes
- The crate's read-only handle is `reader::ChainStoreReader`
  (`src/reader.rs:31`), reached via `StateStore::reader_handle()`. There is no
  type named `StateReader`. See [the architecture](../../ARCHITECTURE.md)
  for the cross-crate read boundary.
