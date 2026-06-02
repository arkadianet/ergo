# ergo-state

**Purpose:** Authenticated UTXO state for the Ergo node. Owns the
redb-backed `StateStore` that validated blocks apply to: an in-memory AVL+
tree with arena-backed node storage and incremental root-label maintenance,
an atomic `apply_block` / `rollback_to` (delta-based reorg) commit path, the
header/section chain index (best-header vs best-full-block), per-epoch voted
protocol parameters, Mode 2 UTXO-snapshot install, Mode 3 suffix pruning, and
a sibling Mode 5 digest-verifier backend (`DigestStateStore`) that derives the
same state root from a block's ADProofs instead of a box arena.

**Depends on (workspace):** ergo-primitives, ergo-ser, ergo-chain-spec, ergo-crypto, ergo-validation, ergo-sigma
**Depended on by:** (see codemap index)
**Approx LOC:** ~28,900 (src incl. substantial inline tests; ~25 of 43 files carry `#[cfg(test)]` blocks)

## Start here
- `lib.rs` (`src/lib.rs:1`) — module map + re-export surface. Names the
  three-trait backend dispatch (`StateBackend` = `ChainStateRead` +
  `HeaderSectionStore` + `BlockApply`) and the two concrete backends.
- `StateStore` (`src/store/mod.rs:557`) — the Mode 1/2/3/6 store. Its
  inherent methods (`open`, `initialize_genesis`/`apply_genesis`,
  `apply_block`, `rollback_to`, `install_snapshot_state`, `reader_handle`)
  are the whole forward contract. The largest module in the crate.
- `apply_block` → `apply_checked_transactions` → `apply_utxo_changes` →
  `persist_apply` (`src/store/apply.rs:139`, `:197`, `:417`; `src/store/mod.rs:4206`)
  — the apply pipeline. `persist_apply` is the atomic-commit unit (one redb
  write txn for undo + AVL + chain_index + state_meta + voted_params + wallet).
- `AvlTree` (`src/avl/tree.rs:61`) — the authenticated AVL+ tree; maintains the
  root label incrementally so `root_digest()` is O(1). Read alongside
  `avl/digest.rs` for the consensus-critical label hash inputs.
- `backend.rs` (`src/backend.rs:40`) — the `StateBackend` trait family and the
  `StateBackendKind` enum (`Utxo(StateStore)` / `Digest(DigestStateStore)`) the
  node binds against generically.

## Modules
- `src/store/` — `StateStore`: open / genesis / apply / rollback / reorg /
  snapshot install / pruning, plus all redb table definitions. Submodules:
  `apply.rs` (block-apply core + `compute_minimal_full_block_height`),
  `reorg.rs` (`rollback_to` three-phase delta replay), `undo.rs` (`UndoEntry`
  reverse-delta codec), `snapshot.rs` (`CommittedSnapshot` single-txn off-loop
  view + mining-candidate dry-run), `dry_run.rs` (`apply_change_set_via_prover`),
  `votes.rs`, `popow_cache.rs` (NiPoPoW prover/interlinks), `meta.rs`
  (`StateMeta` row), `open.rs`, `rebuild.rs` (rebuild-from-committed recovery),
  `backfill.rs` (legacy index back-fill), `error.rs` (`StateError`).
- `src/avl/` — AVL+ primitives: `node.rs` (`AvlNode` enum, `NodeId`),
  `tree.rs` (`AvlTree`), `arena.rs` (`NodeArena` trait + memory/cached-disk
  arenas), `digest.rs` (leaf/internal label + root-digest math),
  `changelog.rs` (`ChangeLog` before-image undo), `serialization.rs` (node
  byte codec), `hydrate.rs` (rebuild tree from `AVL_NODES`), `snapshot_codec.rs`
  (Scala-byte-exact `ProverNodeSerializer` codec for Mode 2 snapshot chunks).
- `src/backend.rs` — `StateBackend`/`ChainStateRead`/`HeaderSectionStore`/
  `BlockApply` traits + `StateBackendKind` enum dispatch.
- `src/chain.rs` — `HeaderMeta`, `ChainStateMeta`, `ChainState`,
  `HeaderAvailability`, `HeightLookup`: serialization-focused chain-index types.
- `src/reader.rs` — `ChainStoreReader`: lock-free `Clone` read handle (own redb
  read txn per call) used by the API layer and indexer.
- `src/persist.rs` — background persist pipeline (`PersistPipeline`,
  `PersistResult`) batching AVL writes into one redb commit off the action loop.
- `src/diff.rs` — block-apply tx diff (`TipPointer`, `AppliedTx`, `TxDiff`)
  consumed by the indexer/mempool.
- `src/active_params.rs` — `voted_params` redb table read/write helpers
  (`VOTED_PARAMS`); the `ActiveProtocolParameters` type itself lives in
  `ergo-validation`.
- `src/header_store.rs` — `HeaderSectionTables`: the header/section tables +
  buffered-write overlay shared by both backends.
- `src/digest_store.rs` — `DigestStateStore`: Mode 5 persistence sibling to
  `StateStore` (digest + chain-state history ledgers, no arena).
- `src/digest_apply.rs` — `DigestProofVerifier`, `DigestApplyError`,
  `ResolvedBoxes`: verifies a block's ADProofs and derives the post-apply digest.
- `src/digest_utxo_view.rs` — `DigestUtxoView`: resolves a block's input boxes
  from its ADProofs so the digest backend can run full tx validation.
- `src/wallet/` — wallet persistence in the same `state.redb`: `WalletApplyHook`
  / `RescanGuard` hooks, `WalletReader`, value types, apply/maturity/scan logic.
- `src/redb_util.rs` — `begin_write_qr` (quick-repair write txn) +
  `open_with_repair_logging`; every production write txn must route through here.

## Key types, traits & functions
- `StateStore` (struct) — Mode 1/2/3/6 UTXO state store — `src/store/mod.rs:557`
- `StateStore::apply_block` (fn) — apply a `CheckedBlock`, advancing the tip — `src/store/apply.rs:139`
- `StateStore::rollback_to` (fn) — delta-based reorg rollback to a target height — `src/store/reorg.rs:41`
- `StateStore::persist_apply` (fn) — the atomic one-txn commit unit — `src/store/mod.rs:4206`
- `StateStore::install_snapshot_state` (fn) — Mode 2 UTXO-snapshot install — `src/store/mod.rs:1039`
- `compute_minimal_full_block_height` (fn) — Mode 3 prune low-water mark (Scala parity) — `src/store/apply.rs:53`
- `AvlTree` (struct) — incremental authenticated AVL+ tree — `src/avl/tree.rs:61`
- `AvlNode` (enum) — Leaf / Internal node, with cached labels — `src/avl/node.rs:18`
- `leaf_label` / `internal_label` (fn) — consensus-critical label hashes — `src/avl/digest.rs:32`, `:52`
- `NodeArena` (trait) — pluggable node storage (memory / cached-disk) — `src/avl/arena.rs:27`
- `UndoEntry` (struct) — per-block reverse delta (changelog + box-level) — `src/store/undo.rs:18`
- `ChainState` / `ChainStateMeta` (struct) — in-memory vs persisted chain pointers — `src/chain.rs:358`, `:209`
- `HeaderMeta` (struct) — persisted header row; `pow_validity` is the only persisted validity flag — `src/chain.rs:22`
- `HeaderAvailability` (enum) — Dense vs PoPowSparse history mode — `src/chain.rs:135`
- `ChainStoreReader` (struct) — lock-free read handle — `src/reader.rs:31`
- `CommittedSnapshot` (struct) — single-txn committed view for off-loop builds — `src/store/snapshot.rs`
- `StateBackend` / `ChainStateRead` / `HeaderSectionStore` / `BlockApply` (traits) — backend dispatch surface — `src/backend.rs:40`–`:120`
- `StateBackendKind` (enum) — `Utxo` / `Digest` runtime dispatch — `src/backend.rs:246`
- `DigestStateStore` (struct) — Mode 5 digest-verifier backend — `src/digest_store.rs:140`
- `DigestProofVerifier` (struct) — ADProof-driven digest derivation — `src/digest_apply.rs:156`
- `PersistPipeline` / `PersistResult` (struct/enum) — background commit batching — `src/persist.rs:288`, `:265`
- `StateError` (enum) — crate-wide error; re-exported as `ergo_state::store::StateError` — `src/store/error.rs`
- `begin_write_qr` (fn) — quick-repair write-txn helper (mandatory for all writes) — `src/redb_util.rs:33`

## Invariants & contracts
- **Atomic commit per applied block.** `persist_apply` writes undo_log +
  AVL+ node mutations + chain_index + state_meta + (epoch-boundary) voted_params
  + (when hooked) wallet rows in a single redb write transaction. Either all
  land or none do.
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
- **Invalidity policy.** `pow_validity` is the ONLY persisted validity flag,
  reserved for cryptographically definitive PoW failure. All other failures use
  session-scoped `ChainState::session_invalids`, cleared on restart
  (`chain.rs:21`, `:372`).
- **AVL+ label hashing matches scorex-util / `ergo_avltree_rust`.** Leaf =
  `blake2b256(0x00 ‖ key ‖ value ‖ next_key)`, Internal =
  `blake2b256(0x01 ‖ balance ‖ left_label ‖ right_label)`, ADDigest =
  `root_label[32] ‖ tree_height[1]`. Note the label prefixes (leaf=0,
  internal=1) are the OPPOSITE of the node serialization prefixes (leaf=1,
  internal=0) — `avl/digest.rs:15`, `avl/snapshot_codec.rs:8`.
- **Snapshot node codec is Scala-byte-exact.** `value_length` is fixed-width
  4-byte big-endian (`Ints.toByteArray`), NOT VLQ (`avl/snapshot_codec.rs:20`).
- **Single-writer state; generic (not `dyn`) backend dispatch.** The action
  loop is the sole writer, so the executor binds `B: StateBackend` and
  monomorphizes; the differing `apply_full_block` internals (box arena vs
  ADProof verifier) are not object-safe behind `dyn` (`backend.rs:13`).
- **Backend schema separation enforced by `data_dir_state_type`.** `"utxo"`,
  `"digest"` (headers-only Mode 6, same schema), and `"digest-verifier"` (Mode 5,
  incompatible schema). A dir carrying both AVL arena rows and digest-verifier
  markers with no sentinel is a hard `DbCorruption` — never inferred
  (`store/mod.rs:362`).
- **Mode 3 prune monotonicity / rollback-window safety.** The prune
  low-water mark never walks backward (`compute_minimal_full_block_height`),
  and `blocks_to_keep >= ROLLBACK_WINDOW + SAFETY_MARGIN` is enforced at config
  load so the active rollback window can never fall into pruned territory
  (`store/mod.rs:173`, `:555`).
- **Crash-repair contract.** Every write txn goes through `begin_write_qr`
  (quick_repair on); a single non-quick-repair commit defeats it for all prior
  commits, so the rule is mechanical: zero `db.begin_write()` outside this
  helper (`redb_util.rs:10`).
- **`ergo-state` depends on `ergo-validation`, not vice versa.** State asks
  validation "is this block legal?" before applying; it never defines
  acceptance rules.

## Doc accuracy notes
- The crate's read-only handle is `reader::ChainStoreReader`
  (`src/reader.rs:31`), reached via `StateStore::reader_handle()`. There is no
  type named `StateReader`. The stale `src/lib.rs` crate-doc reference is now
  corrected to `ChainStoreReader`; `docs/architecture.md:30` still names a
  nonexistent `StateReader` and should be fixed there too.
