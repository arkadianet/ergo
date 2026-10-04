# ergo-sync

**Purpose:** The sync layer that drives header-first chain sync, parallel block
validation, and peer-aware modifier delivery. A decision engine
(`SyncCoordinator`) turns peer events (`SyncInfo` / `Inv` / `Modifier` /
disconnect / timeout) into `Action`s; a stateful runtime (`SyncExecutor`)
consumes those actions — validating + persisting headers and blocks against
`ergo-state` and feeding results back — and the two bootstrap reducers
(UTXO-snapshot and NiPoPoW) seed a fresh node before normal IBD takes over.

**Depends on (workspace):** ergo-primitives, ergo-ser, ergo-crypto, ergo-validation, ergo-state, ergo-p2p
**Depended on by:** (see codemap index) — only `ergo-node`

## Start here
- `src/lib.rs` — the module map docstring; orients the four core modules (coordinator / executor / header_proc / block_proc).
- `coordinator::SyncCoordinator` (`src/coordinator/mod.rs`) — the heart: event→action engine. Read its event handlers `on_sync_info`, `on_inv`, `on_modifier_received`, `on_header_validated`, `on_block_applied`.
- `coordinator::Action` (`src/coordinator/mod.rs`) — the six-variant action surface (`ValidateHeader`, `PersistSection`, `AssembleBlock`, plus `SendToPeer` / `Penalize` / `NoteDeliveryOutcome`) that wires the coordinator to the executor and network.
- `coordinator::ChainView` (`src/coordinator/mod.rs`) — the read-only chain interface the coordinator queries; implemented for `StateStore` (and the digest/backend-enum variants) in `src/coordinator/chain_view.rs`, mocked in tests.
- `executor::SyncExecutor` (`src/executor/mod.rs`) — the runtime glue. `execute_all` is the per-tick entry; `try_apply_next_blocks` is the sequential block-apply + reorg drain.

## Modules
- `src/coordinator/mod.rs` — event→action decision engine. Owns `DeliveryTracker` / `AssemblyTracker` / `SyncState` bookkeeping, request scheduling (per-peer caps, bucketed multi-peer distribution, HOL hedging, timeout/disconnect re-requests), fork-choice classification, and the `ChainView` trait. Production chain queries are in `chain_view.rs`; events and scheduling are in their corresponding modules. `section_verify.rs` hosts the standalone `verify_section_modifier_id` parity check used by the ergo-node messaging layer.
- `src/executor/mod.rs` — stateful action consumer + pipeline driver. Owns `ProtocolParams`, the rolling header caches (`last_headers`, `block_context_headers`, in-memory `header_index`), the orphan-header buffer, and startup hydration/recovery. Runs the single-header and rayon-batched header paths, the sequential block-apply drain, and full-chain reorg/rollback.
- `src/header_proc.rs` — two-phase header processing: parallel parse + PoW (`pre_validate_header` → `PreValidatedHeader`) then sequential chain-linkage + difficulty + persist (`finalize_header`). `process_header_cfg` is the combined single-shot path.
- `src/block_proc/mod.rs` — full-block pipeline: load header+sections, deserialize, build `BlockValidationContext`, run `validate_full_block_parallel`, apply to state. `process_block` dispatches to UTXO (`process_block_utxo`, `block_proc/utxo.rs`) and digest (`process_block_digest`) backends; also runs the epoch-boundary voting recompute on extension blocks. UTXO blocks regenerate ADProofs locally and insert generated sections only inside the 114,688-block suffix window measured from the best known header (this adds no eviction of previously stored proofs); digest blocks require the shipped section.
- `src/popow_bootstrap.rs` — NiPoPoW bootstrap consume-side reducer (`PopowBootstrap`): tracks per-peer proof requests, feeds inbound proofs to `NipopowVerifier`, reports quorum + best proof, terminal after `mark_applied`. Active only on a fresh store with `nipopow_bootstrap = true`.
- `src/snapshot_bootstrap/mod.rs` — Mode 2 (UTXO-snapshot) discovery + chunk-assembly reducers. `SnapshotBootstrap` applies Scala's quorum manifest selection; `ChunkAssembly` tracks per-subtree chunk requests/timeouts; `verify_manifest_against_state_root` is the trust check against the header's committed `state_root`.
- `src/perf.rs` — per-tick header/block pipeline counters (`HeaderPerfCounters`, `BlockPerfCounters`) drained by the node heartbeat. Telemetry only.

## Key types, traits & functions
- `SyncCoordinator` (struct) — event→action engine; owns delivery/assembly/sync trackers — `src/coordinator/mod.rs`
- `Action` (enum) — `ValidateHeader` / `PersistSection` / `AssembleBlock` / `SendToPeer` / `Penalize` / `NoteDeliveryOutcome` — `src/coordinator/mod.rs`
- `ChainView` (trait) — read-only chain queries (best header/full-block, on-best-chain, height lookups with sparse-mode awareness); impls in `src/coordinator/chain_view.rs`
- `SyncCoordinator::on_sync_info` (fn) — classify peer chain status (V1 id-overlap / V2 commonPoint) and emit continuation Inv / reciprocal SyncInfo / header-validate — `src/coordinator/events.rs`
- `SyncCoordinator::on_inv` (fn) — filter advertised ids (have / in-flight / received / prune-sentinel), register + emit `RequestModifier` — `src/coordinator/events.rs`
- `SyncCoordinator::on_header_validated` (fn) — post-validate hook: gate on headers-synced + mode + prune sentinel, register pending block + request sections within the download window — `src/coordinator/events.rs`
- `SyncCoordinator::request_missing_sections_bucketed` (fn) — multi-peer capacity-balanced section distribution (ports Scala `requestDownload` + `ElementPartitioner`) — `src/coordinator/scheduling.rs`
- `SyncCoordinator::check_hol_hedges` (fn) — head-of-line hedge: early-reassign the next sequential block's stuck sections before the full delivery timeout — `src/coordinator/scheduling.rs`
- `build_sync_info_payload` (fn) — version-aware SyncInfo payload (V2 = 50 recent headers, V1 = 1000 recent ids) — `src/coordinator/events.rs`
- `verify_section_modifier_id` (fn) — standalone receive-time section-id recomputation (dual-root merkle parity); called by ergo-node messaging, not the coordinator path — `src/coordinator/section_verify.rs`
- `SyncExecutor` (struct) — stateful pipeline driver; owns params + header caches + orphan buffer + header_index + perf counters — `src/executor/mod.rs`
- `SyncExecutor::execute_all` / `execute` (fn) — per-tick action dispatcher; partitions `ValidateHeader` into the rayon batch path, forwards `SendToPeer`/`Penalize` to the network loop — `src/executor/mod.rs`
- `SyncExecutor::try_apply_next_blocks` (fn) — sequential block-apply drain + full-chain reorg rollback loop; suppressed under headers-only / mid-bootstrap — `src/executor/block_apply.rs`
- `SyncExecutor::process_local_header` (fn) — single-header pipeline for locally-mined blocks (no peer), returns drain actions the caller MUST flush — `src/executor/header_pipeline.rs`
- `SyncExecutor::hydrate_from_store` / `hydrate_block_context` / `load_header_index` / `recover_coordinator` (fn) — startup cache rebuild + pending-block reseed; fail-fast on persisted-row integrity gaps — `src/executor/startup.rs`
- `StartupError` / `HydrationError` (enum) — fatal startup/hydration faults (e.g. `HEADER_CHAIN_INDEX` coverage gap, persisted-row missing) — `src/executor/startup.rs`
- `PreValidatedHeader` (struct) — immutable PoW-checked-but-not-linked header; metadata is derived from its inner header and finalize checks retained-byte identity; genesis separately rechecks PoW — `src/header_proc.rs`
- `ProcessedHeader` (struct) — finalize result: id/height/parent, `is_new_best`, section roots, parsed header + `CheckedHeader` proof — `src/header_proc.rs`
- `finalize_header` / `pre_validate_header` / `process_header_cfg` (fn) — the two-phase header pipeline + combined single-shot path — `src/header_proc.rs`
- `process_block` (fn) + `ProcessedBlock` (struct) — full-block validate+apply dispatcher (UTXO/digest backends) — `src/block_proc/mod.rs`
- `HeaderProcessError` / `BlockProcessError` (enum) — pipeline errors; note retryable `ParentNotFound` / `EpochContextIncomplete` (orphan-buffer, no penalty) vs definitive `Invalid` — `src/header_proc.rs` / `src/block_proc/mod.rs`
- `PopowBootstrap` (struct) + `PopowBootstrapState` (enum) — NiPoPoW bootstrap reducer — `src/popow_bootstrap.rs`
- `SnapshotBootstrap` / `ChunkAssembly` (struct) + `verify_manifest_against_state_root` (fn) — Mode 2 UTXO-snapshot discovery, chunk assembly, manifest trust check — `src/snapshot_bootstrap/mod.rs`

## Invariants & contracts
- **Coordinator effects:** mutations and sends are emitted as `Action`s; diagnostics use `tracing` directly. Read-only `ChainView` queries may access storage. Tests use mock queries; production decisions depend on their backing store.
- **PoW result reuse:** prevalidation parses to EOF, drains group elements, hashes the exact bytes, and verifies PoW. Finalization checks the retained bytes against that ID before storage access and derives parent/height from the immutable inner header. Non-genesis finalization and retries reuse PoW; the special genesis path verifies PoW again with initial difficulty.
- **Selected-branch caches:** losing fork headers still unlock their children but never enter the best-header SyncInfo window. A winning reorg rebuilds its recent ancestry and rewrites affected height-index entries. Applied-block context remains separately aligned to the full-block tip.
- **Header-first / best_header ≠ best_full_block:** sections are requested only after `headers_chain_synced()` (Scala `isHeadersChainSynced` parity); block apply is strictly sequential from `best_full_block_height + 1`. The header tip can be far ahead of the full-block tip (`src/coordinator/mod.rs`, `src/executor/mod.rs`).
- **Fork choice by cumulative score, applied sequentially:** header fork-choice swaps happen in `finalize_header` via cumulative-difficulty comparison (`is_new_best`); full-chain reorg rolls back to the common ancestor and re-applies via `try_apply_next_blocks` / `rollback_full_chain_to_best_header` (`src/executor/mod.rs`). Note the module-doc caveat that V1 SyncInfo *classification* still uses height-based heuristics (`src/coordinator/mod.rs`).
- **Failure ownership:** missing immediate parents and incomplete epoch context remain buffered without acceptance or a peer penalty. Immediate-parent arrivals retry their children; any new header progress retries context-blocked buckets once so an older retarget ancestor can unblock them. Local stored-header integrity, storage, retained-byte contract, and invalid arithmetic-context errors stop processing with diagnostics rather than penalizing peers. Batch failure follows the existing fail-stop contract because memory may already be ahead of its atomic persisted state.
- **Durable block invalidity:** consensus block/transaction, epoch-extension and regenerated-proof-hash verdicts may durably invalidate a branch. `HeaderMeta` is a persisted consistency error and stays session-scoped, as do data/IO failures and digest-apply ambiguity.
- **Wire-sized registration:** missing-parent lists are chunked at `MAX_INV_OBJECTS` before delivery registration. Every registered chunk has an emitted encodable request; tests decode the exact IDs, order, type and peer.
- **Section-id receive-time parity:** `verify_section_modifier_id` recomputes the section id (dual-root merkle) so a peer cannot substitute payload under a requested id (`src/coordinator/mod.rs`).
- **ADProofs: regenerated for UTXO, shipped for digest.** A UTXO block never
  waits for a downloaded ADProofs section: `process_block_utxo` regenerates the
  proof from the parent tree, verifies its hash against `adProofsRoot`, and
  retains a type-104 section only when the height is inside the 114,688-block
  suffix window measured from the best known header (Scala
  `adProofsSuffixLength`). This is an insertion gate, not eviction of
  previously stored proofs, so near-tip full-block
  responses carry proofs. Digest nodes keep `requires_proofs` set and verify
  the shipped section instead (`src/block_proc/utxo.rs`;
  `src/coordinator/mod.rs`; see
  [`../utxo-proof-validation.md`](../utxo-proof-validation.md)).
- **Mode gating (headers-only / mid-bootstrap):** `should_skip_block_sections()` (Mode 6 permanent + Mode 2 transient) suppresses section Inv handling, section persistence, pending-block registration, and block apply at every layer — perimeter (`on_inv`), receive (`on_modifier_received`), schedule (`on_header_validated`), dispatch (`execute` rechecks queued `PersistSection`/`AssembleBlock` actions), and apply (`try_apply_next_blocks`) — defense-in-depth (`src/coordinator/mod.rs`, `src/executor/mod.rs`).
- **Prune-sentinel request gate (Mode 3):** when `prune_sentinel() > 0`, sub-sentinel sections are fail-CLOSED — never requested (would be evicted on apply / refused on serve); inert for archive / Mode 6 / pre-eviction stores (`src/coordinator/mod.rs`).
- **Snapshot manifest trust:** a peer-advertised `manifest_id` is accepted only if it equals the first 32 bytes of the canonical header's committed `state_root` at the snapshot height; quorum = highest height where `>= MIN_MANIFEST_VOTES (3)` peers agree (`src/snapshot_bootstrap/mod.rs`).
- **Startup integrity is fail-fast:** hydration treats a missing/corrupt persisted header row or a `HEADER_CHAIN_INDEX` coverage gap as fatal (`HydrationError` / `StartupError::IndexGap`) rather than silently truncating caches — the persisted header table is the source of truth after restart (`src/executor/mod.rs`). The one exception is a `PoPowSparse` store, where the recent-header window ends at the first ancestor absent below the NiPoPoW proof's contiguous suffix (`src/executor/startup.rs`).

The Mode5 ordinary replay requires exactly 55 data-input blocks in its 183-block
range and compares every resulting root with captured mainnet headers. Its
header-sync companion seeds only the one-parent difficulty context, so the
executor must start its cache at a tip without stored ancestry. These are
fixed-corpus checks; ignored startup benchmarks and historical script/oracle
prerequisites remain explicit.
