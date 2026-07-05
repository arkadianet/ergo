# ergo-sync

**Purpose:** The sync layer that drives header-first chain sync, parallel block
validation, and peer-aware modifier delivery. A pure decision engine
(`SyncCoordinator`) turns peer events (`SyncInfo` / `Inv` / `Modifier` /
disconnect / timeout) into `Action`s; a stateful runtime (`SyncExecutor`)
consumes those actions — validating + persisting headers and blocks against
`ergo-state` and feeding results back — and the two bootstrap reducers
(UTXO-snapshot and NiPoPoW) seed a fresh node before normal IBD takes over.

**Depends on (workspace):** ergo-primitives, ergo-ser, ergo-crypto, ergo-validation, ergo-state, ergo-p2p
**Depended on by:** (see codemap index) — only `ergo-node`
**Approx LOC:** ~8,550 (production `.rs`, excluding `tests.rs` integration files)

## Start here
- `src/lib.rs` — the module map docstring; orients the four core modules (coordinator / executor / header_proc / block_proc).
- `coordinator::SyncCoordinator` (`src/coordinator/mod.rs:198`) — the heart: pure event→action engine. Read its event handlers `on_sync_info`, `on_inv`, `on_modifier_received`, `on_header_validated`, `on_block_applied`.
- `coordinator::Action` (`src/coordinator/mod.rs:44`) — the four-variant action surface (`ValidateHeader`, `PersistSection`, `AssembleBlock`, plus `SendToPeer` / `Penalize`) that wires the coordinator to the executor and network.
- `coordinator::ChainView` (`src/coordinator/mod.rs:81`) — the read-only chain interface the coordinator queries; implemented for `StateStore` (and the digest/backend-enum variants) in the same file, mocked in tests.
- `executor::SyncExecutor` (`src/executor/mod.rs:173`) — the runtime glue. `execute_all` is the per-tick entry; `try_apply_next_blocks` is the sequential block-apply + reorg drain.

## Modules
- `src/coordinator/mod.rs` — pure, I/O-free decision engine. Owns `DeliveryTracker` / `AssemblyTracker` / `SyncState` bookkeeping, request scheduling (per-peer caps, bucketed multi-peer distribution, HOL hedging, timeout/disconnect re-requests), fork-choice classification, and the `ChainView` trait + its production impls. Also hosts the standalone `verify_section_modifier_id` parity check used by the ergo-node messaging layer.
- `src/executor/mod.rs` — stateful action consumer + pipeline driver. Owns `ProtocolParams`, the rolling header caches (`last_headers`, `block_context_headers`, in-memory `header_index`), the orphan-header buffer, and startup hydration/recovery. Runs the single-header and rayon-batched header paths, the sequential block-apply drain, and full-chain reorg/rollback.
- `src/header_proc.rs` — two-phase header processing: parallel parse + PoW (`pre_validate_header` → `PreValidatedHeader`) then sequential chain-linkage + difficulty + persist (`finalize_header`). `process_header_cfg` is the combined single-shot path.
- `src/block_proc.rs` — full-block pipeline: load header+sections, deserialize, build `BlockValidationContext`, run `validate_full_block_parallel`, apply to state. `process_block` dispatches to UTXO (`process_block_utxo`) and digest (`process_block_digest`) backends; also runs the epoch-boundary voting recompute on extension blocks.
- `src/popow_bootstrap.rs` — NiPoPoW bootstrap consume-side reducer (`PopowBootstrap`): tracks per-peer proof requests, feeds inbound proofs to `NipopowVerifier`, reports quorum + best proof, terminal after `mark_applied`. Active only on a fresh store with `nipopow_bootstrap = true`.
- `src/snapshot_bootstrap.rs` — Mode 2 (UTXO-snapshot) discovery + chunk-assembly reducers. `SnapshotBootstrap` applies Scala's quorum manifest selection; `ChunkAssembly` tracks per-subtree chunk requests/timeouts; `verify_manifest_against_state_root` is the trust check against the header's committed `state_root`.
- `src/perf.rs` — per-tick header/block pipeline counters (`HeaderPerfCounters`, `BlockPerfCounters`) drained by the node heartbeat. Telemetry only.

## Key types, traits & functions
- `SyncCoordinator` (struct) — pure event→action engine; owns delivery/assembly/sync trackers — `src/coordinator/mod.rs:198`
- `Action` (enum) — `ValidateHeader` / `PersistSection` / `AssembleBlock` / `SendToPeer` / `Penalize` — `src/coordinator/mod.rs:44`
- `ChainView` (trait) — read-only chain queries (best header/full-block, on-best-chain, height lookups with sparse-mode awareness); impl'd for `StateStore` at `src/coordinator/mod.rs:1872` — `src/coordinator/mod.rs:81`
- `SyncCoordinator::on_sync_info` (fn) — classify peer chain status (V1 id-overlap / V2 commonPoint) and emit continuation Inv / reciprocal SyncInfo / header-validate — `src/coordinator/mod.rs:567`
- `SyncCoordinator::on_inv` (fn) — filter advertised ids (have / in-flight / received / prune-sentinel), register + emit `RequestModifier` — `src/coordinator/mod.rs:750`
- `SyncCoordinator::on_header_validated` (fn) — post-validate hook: gate on headers-synced + mode + prune sentinel, register pending block + request sections within the download window — `src/coordinator/mod.rs:999`
- `SyncCoordinator::request_missing_sections_bucketed` (fn) — multi-peer capacity-balanced section distribution (ports Scala `requestDownload` + `ElementPartitioner`) — `src/coordinator/mod.rs:1379`
- `SyncCoordinator::check_hol_hedges` (fn) — head-of-line hedge: early-reassign the next sequential block's stuck sections before the full delivery timeout — `src/coordinator/mod.rs:1562`
- `build_sync_info_payload` (fn) — version-aware SyncInfo payload (V2 = 50 recent headers, V1 = 1000 recent ids) — `src/coordinator/mod.rs:1853`
- `verify_section_modifier_id` (fn) — standalone receive-time section-id recomputation (dual-root merkle parity); called by ergo-node messaging, not the coordinator path — `src/coordinator/mod.rs:2187`
- `SyncExecutor` (struct) — stateful pipeline driver; owns params + header caches + orphan buffer + header_index + perf counters — `src/executor/mod.rs:173`
- `SyncExecutor::execute_all` / `execute` (fn) — per-tick action dispatcher; partitions `ValidateHeader` into the rayon batch path, forwards `SendToPeer`/`Penalize` to the network loop — `src/executor/mod.rs:914` / `:872`
- `SyncExecutor::try_apply_next_blocks` (fn) — sequential block-apply drain + full-chain reorg rollback loop; suppressed under headers-only / mid-bootstrap — `src/executor/mod.rs:1297`
- `SyncExecutor::process_local_header` (fn) — single-header pipeline for locally-mined blocks (no peer), returns drain actions the caller MUST flush — `src/executor/mod.rs:288`
- `SyncExecutor::hydrate_from_store` / `hydrate_block_context` / `load_header_index` / `recover_coordinator` (fn) — startup cache rebuild + pending-block reseed; fail-fast on persisted-row integrity gaps — `src/executor/mod.rs:440` / `:491` / `:594` / `:720`
- `StartupError` / `HydrationError` (enum) — fatal startup/hydration faults (e.g. `HEADER_CHAIN_INDEX` coverage gap, persisted-row missing) — `src/executor/mod.rs:56` / `:96`
- `PreValidatedHeader` (struct) — PoW-checked-but-not-linked header carrying an unforgeable `PowCheckedHeader` proof so finalize never re-pays PoW — `src/header_proc.rs:97`
- `ProcessedHeader` (struct) — finalize result: id/height/parent, `is_new_best`, section roots, parsed header + `CheckedHeader` proof — `src/header_proc.rs:60`
- `finalize_header` / `pre_validate_header` / `process_header_cfg` (fn) — the two-phase header pipeline + combined single-shot path — `src/header_proc.rs:173` / `:151` / `:214`
- `process_block` (fn) + `ProcessedBlock` (struct) — full-block validate+apply dispatcher (UTXO/digest backends) — `src/block_proc.rs:294` / `:182`
- `HeaderProcessError` / `BlockProcessError` (enum) — pipeline errors; note retryable `ParentNotFound` / `EpochContextIncomplete` (orphan-buffer, no penalty) vs definitive `Invalid` — `src/header_proc.rs:26` / `src/block_proc.rs:110`
- `PopowBootstrap` (struct) + `PopowBootstrapState` (enum) — NiPoPoW bootstrap reducer — `src/popow_bootstrap.rs:52` / `:35`
- `SnapshotBootstrap` / `ChunkAssembly` (struct) + `verify_manifest_against_state_root` (fn) — Mode 2 UTXO-snapshot discovery, chunk assembly, manifest trust check — `src/snapshot_bootstrap.rs:165` / `:242` / `:101`

## Invariants & contracts
- **Coordinator purity:** `SyncCoordinator` performs no I/O and no async — every effect is an emitted `Action`. This is the testability + determinism contract the whole crate rests on (`src/coordinator/mod.rs:1-5`).
- **One PoW per header:** PoW is verified exactly once. `pre_validate_header` produces an unforgeable `PowCheckedHeader`; `finalize_header` consumes it without re-checking, and orphan retries reuse the cached proof (`src/header_proc.rs:86-101`).
- **Header-first / best_header ≠ best_full_block:** sections are requested only after `headers_chain_synced()` (Scala `isHeadersChainSynced` parity); block apply is strictly sequential from `best_full_block_height + 1`. The header tip can be far ahead of the full-block tip (`src/coordinator/mod.rs:999-1017`, `src/executor/mod.rs:1297`).
- **Fork choice by cumulative score, applied sequentially:** header fork-choice swaps happen in `finalize_header` via cumulative-difficulty comparison (`is_new_best`); full-chain reorg rolls back to the common ancestor and re-applies via `try_apply_next_blocks` / `rollback_full_chain_to_best_header` (`src/executor/mod.rs:1497`). Note the module-doc caveat that V1 SyncInfo *classification* still uses height-based heuristics (`src/coordinator/mod.rs:9-12`).
- **Retryable vs definitive validation failure:** `ParentNotFound` and `EpochContextIncomplete` are local context gaps → orphan-buffer + retry, never a peer penalty and never persisted as accepted; only cryptographically definitive failures mark a header `Invalid` (`src/header_proc.rs:39-51`).
- **Section-id receive-time parity:** `verify_section_modifier_id` recomputes the section id (dual-root merkle) so a peer cannot substitute payload under a requested id (`src/coordinator/mod.rs:2187`).
- **Mode gating (headers-only / mid-bootstrap):** `should_skip_block_sections()` (Mode 6 permanent + Mode 2 transient) suppresses section Inv handling, section persistence, pending-block registration, and block apply at every layer — perimeter (`on_inv`), receive (`on_modifier_received`), schedule (`on_header_validated`), and apply (`try_apply_next_blocks`) — defense-in-depth (`src/coordinator/mod.rs:347`, `:771`, `:974`, `src/executor/mod.rs:1309`).
- **Prune-sentinel request gate (Mode 3):** when `prune_sentinel() > 0`, sub-sentinel sections are fail-CLOSED — never requested (would be evicted on apply / refused on serve); inert for archive / Mode 6 / pre-eviction stores (`src/coordinator/mod.rs:1050`, `:1431`).
- **Snapshot manifest trust:** a peer-advertised `manifest_id` is accepted only if it equals the first 32 bytes of the canonical header's committed `state_root` at the snapshot height; quorum = highest height where `>= MIN_MANIFEST_VOTES (3)` peers agree (`src/snapshot_bootstrap.rs:80-121`).
- **Startup integrity is fail-fast:** hydration treats a missing/corrupt persisted header row or a `HEADER_CHAIN_INDEX` coverage gap as fatal (`HydrationError` / `StartupError::IndexGap`) rather than silently truncating caches — the persisted header table is the source of truth after restart (`src/executor/mod.rs:55-116`, `:440`).
