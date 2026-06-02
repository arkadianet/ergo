# ergo-node

**Purpose:** The L7 binary + runtime crate. Wires every workspace component
crate (state, p2p, sync, mempool, indexer, mining, wallet, api) into a single
supervised `tokio` runtime, owns process-level lifecycle (config load, data-dir
layout, genesis, graceful shutdown), runs the single-writer action loop, and
exposes the node's behaviour to `ergo-api` through `Arc<dyn …>` trait bridges
backed by a lock-free snapshot.

**Depends on (workspace):** ergo-primitives, ergo-ser, ergo-chain-spec,
ergo-crypto, ergo-validation, ergo-wallet, ergo-state, ergo-p2p, ergo-sync,
ergo-mempool, ergo-mining, ergo-indexer, ergo-api, ergo-rest-json, ergo-sigma
**Depended on by:** (see codemap index — top of the stack; nothing depends on it)
**Approx LOC:** ~28,100 (src only, excluding tests)

## Start here
- `node::boot::run_inner` (`src/node/boot.rs:153`) — the whole bring-up
  sequence: store/genesis/AVL, handshake + peer manager, sync executor +
  coordinator, indexer, wallet boot, API bind, mining wire-up, action-loop
  spawn. Returns the live `RunHandle`. `run` (`:65`) wraps it with signals.
- `node::action_loop::action_loop` (`src/node/action_loop.rs:37`) — the
  single-writer event loop: four timers (dial/sync/mempool/memory) + inbound
  event coalescing + API submit drain + mining dispatch + clean shutdown.
- `node::state::NodeState` (`src/node/state.rs:73`) — the runtime god-struct
  every loop handler mutates; reading its fields is the fastest map of what the
  node owns at runtime.
- `snapshot::NodeSnapshot` (`src/snapshot.rs:44`) + `api_bridge` — the read
  boundary: per-tick projection of node state into API DTOs, parked in an
  `ArcSwap`, served lock-free to the axum task.

## Modules
- `src/main.rs` — thin binary: parse `Cli`, load `NodeConfig`, init tracing
  (stderr always + optional non-lossy rolling file appender), install the
  panic-to-tracing hook, call `run`.
- `src/lib.rs` — library facade; re-exports `run`, `run_inner`, `RunHandle`.
- `src/config/` — TOML + CLI → resolved `NodeConfig`. `cli.rs` (clap parser),
  `toml_sections.rs` (raw TOML shapes), `load.rs` (precedence + all validation
  + Mode-3/5/6 activation gates), `resolved.rs` (`NodeConfig`/`StateType`/
  logging), `mod.rs` (canonical-mode predicates + `validate_supported`).
- `src/node/boot.rs` — boot orchestration (start here).
- `src/node/action_loop.rs` — the action loop body + `handle_mempool_tick`.
- `src/node/state.rs` — `NodeState` + `PeerRegistry`/`PeerRuntime`.
- `src/node/handle.rs` — `RunHandle`: shutdown ordering + task-leak-safe `Drop`.
- `src/node/sync_tick.rs` — the 1 s sync cycle: delivery timeouts, peer
  eviction, block-apply advance, missing-section re-request, SyncInfo dispatch,
  heartbeat, snapshot publish; drives popow/utxo bootstrap state machines.
- `src/node/events.rs` — peer-event dispatcher; coalesces header-modifier
  batches; handles `LocalFullBlock` (mined-block apply pipeline).
- `src/node/messaging.rs` — inbound per-frame `message::CODE_*` dispatcher
  (throttle → deserialize → coordinator/executor/mempool routing).
- `src/node/admission.rs` — peer + API tx admission through `Mempool::process`;
  maps `MempoolAction`s to outer-loop `Action`s and shapes `SubmitError`.
- `src/node/peer_actions.rs` — outbound plumbing: dial scheduler, action flush,
  penalty application, disconnect cleanup, channel sends.
- `src/node/identity.rs` — mode-label / `NodeMode` classification, `/identity`
  payload build, NiPoPoW resume classification, runtime activation gate.
- `src/node/mining_dispatch.rs` / `mining_engine.rs` — bridge dispatch (serve
  cached candidate, apply submitted solution) + the off-loop candidate engine
  task fed `BuildIntent`s over a `watch` channel.
- `src/node/wallet_bridge.rs` (+ `commands/`) — single-writer wallet task
  (`run_wallet_writer`), `WalletCommand` enum, `NodeWalletAdmin` (`WalletAdmin`
  impl), `ChainStateAccessor`, and the `WalletStateHook` chain-apply hook.
- `src/node/heartbeat.rs` — per-tick operator stderr heartbeat (diagnostics).
- `src/node/snapshot_emit.rs` / `snapshot_state.rs` — assemble `SnapshotParts`
  from `NodeState`; Mode-2 snapshot-server cache state.
- `src/node/tip_context.rs` / `sync_helpers.rs` / `util.rs` / `memory_sampler.rs`
  — admission tip context, anchor sync-info helpers, misc, mem sampling.
- `src/api_bridge.rs` (+ `scala_compat.rs`, `block_reassembly.rs`, `compat.rs`,
  `error.rs`) — implements `ergo-api`'s `NodeReadState`/`NodeSubmit`/
  `MempoolView`/`NodeAdmin` against the snapshot + submission channels; hosts
  the load-bearing Scala-vs-Rust JSON byte-parity oracle tests.
- `src/mining_bridge.rs` — `NodeMining` impl: `MiningRequest` channel bridge,
  work-message JSON projection, candidate longpoll.
- `src/snapshot.rs` — `NodeSnapshot` DTO bundle, `SnapshotPublisher`,
  `SnapshotHandle` (`Arc<ArcSwap<NodeSnapshot>>`), recent-blocks tip cache.
- `src/peer_loop.rs` — per-peer dial/accept + read/write tasks; `PeerEvent` enum.
- `src/notifier.rs` — `MempoolNotifier`: polls committed tip identity
  `(height, header_id)`, emits `TxDiff` so the mempool reconciles off the
  consensus path; generic over `DiffSource`.
- `src/indexer_chain.rs` — `IndexerChainSource` adapter over `ChainStoreReader`.
- `src/genesis.rs` — genesis-box JSON loading for state init.
- `src/anchor_map.rs` / `anchor_scheduler.rs` — REST-sourced header-anchor map
  (Step B observation) + per-peer SyncInfo crafting (Step C).
- `src/wallet_boot.rs` — wallet unlock+hydrate+persist boot path; rescan flag.
- `src/mem_*.rs` — optional memory-observability sampler (`ERGO_MEM_CSV`).

## Key types, traits & functions
- `RunHandle` (struct) — live owned interface to a running node; `shutdown`/
  `Drop` enforce bounded graceful drain then durable close — `src/node/handle.rs:39`
- `NodeState` (struct) — action-loop god-struct (store, sync, peers, mempool,
  snapshot, wallet hook, bootstrap state machines) — `src/node/state.rs:73`
- `run` / `run_inner` (async fn) — production entry / handle-returning entry —
  `src/node/boot.rs:65` / `:153`
- `action_loop` (async fn) — the single-writer select loop — `src/node/action_loop.rs:37`
- `NodeSnapshot` (struct) + `SnapshotPublisher` (struct) + `SnapshotHandle`
  (type alias) — per-tick read projection — `src/snapshot.rs:44` / `:252` / `:248`
- `SnapshotReadState` / `SnapshotMempoolView` / `ShutdownAdmin` / `SubmitBridge`
  — the `ergo-api` trait impls + submission channel — `src/api_bridge.rs:55/301/116/390`
- `MiningRequest` (enum) + `MINING_TIMEOUT`/`LONGPOLL_TIMEOUT` — mining bridge —
  `src/mining_bridge.rs:62`
- `PeerEvent` (enum) — peer-task → action-loop messages incl. `LocalFullBlock` —
  `src/peer_loop.rs:20`
- `MempoolNotifier` (struct) + `DiffSource` (trait) + `PollOutcome` (enum) —
  `src/notifier.rs:60/24/39`
- `WalletCommand` (enum) + `NodeWalletAdmin` (struct) + `run_wallet_writer`
  (async fn) + `WalletStateHook` (struct) — wallet single-writer — `src/node/wallet_bridge.rs:62/190/778/740`
- `NodeConfig` / `StateType` (struct/enum) + `NodeConfig::load` — `src/config/resolved.rs` / `src/config/load.rs`
- `NodeMode` (enum) + `classify_node_mode` / `validate_runtime_mode_support` —
  mode taxonomy + activation gate — `src/node/identity.rs:98/238/582`
- `is_canonical_mode_5_combo` / `is_canonical_mode_6_combo` /
  `mempool_force_off_for_mode` — single-source mode predicates — `src/config/mod.rs:79/51/108`

## Invariants & contracts
- **Single-writer state.** All `StateStore` mutation and mempool mutation
  happen on the one action-loop task; the mempool needs no locking because it
  is owned there. Cross-task work (API submit, mining, wallet) crosses bounded
  mpsc channels with per-request oneshot replies.
- **Atomic durable shutdown.** Clean shutdown is bounded (5 s API drain cap)
  precisely so the action loop's terminal `StateStore::shutdown_cleanly()` runs
  the undo_log + AVL + chain_index + state_meta atomic commit; `RunHandle::Drop`
  is best-effort only and does NOT guarantee durable close — embedders must
  `shutdown().await` before reopening a `data_dir` (`src/node/handle.rs`,
  `src/node/action_loop.rs:294`).
- **Reorg-detecting mempool reconcile.** `MempoolNotifier` tracks
  `(height, header_id)` not just height, so equal-height reorgs are detected;
  consensus commit touches no channels (`src/notifier.rs`).
- **Epoch-boundary revalidation.** On a tip change whose active voted params or
  validation settings differ from last-seen, every active mempool tx is demoted
  into the revalidation queue and re-admitted under the new rules
  (`src/node/action_loop.rs:334`).
- **Anti-DoS recording survives a dropped reply.** A submission's mempool
  admission outcome is recorded even if the API handler already timed out and
  dropped its oneshot (`src/node/action_loop.rs:180`).
- **Mode-support gating is enforced twice.** `NodeConfig::load` (TOML path) and
  `validate_runtime_mode_support` (programmatic-construction backstop) share the
  `is_canonical_mode_*` predicates so the two gates cannot drift; the mining /
  indexer / mempool subsystems force-off on `state_type == Digest`
  (`src/config/load.rs`, `src/node/identity.rs:582`, `src/config/mod.rs`).
- **PoW verified at the API boundary.** `submit_full_block` verifies the
  Autolykos solution in the axum task so an invalid-PoW block never wakes the
  action loop (`src/api_bridge.rs:438`).
- **Lock-free reads.** The API never blocks the action loop: reads load an
  `Arc<ArcSwap<NodeSnapshot>>` rebuilt once per sync tick; snapshot construction
  is bounded and the recent-blocks tail is cached by full-block tip id
  (`src/snapshot.rs`, `src/node/snapshot_emit.rs`).
- **Background-task leak safety.** `RunHandle::Drop` signals + aborts every
  task it owns (action loop, API, inbound listener, indexer, anchor builder,
  mining engine) and fires latched-watch cancels so a forgotten `shutdown()`
  cannot leak tasks or bound ports (`src/node/handle.rs`).
