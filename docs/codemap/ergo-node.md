# ergo-node

**Purpose:** The binary and embedded/API-adapter runtime crate. Wires chain
state, P2P, sync, mempool, mining, indexer, API, wallet cryptography, and
`ergo-wallet-service` into one supervised tokio process. It owns process
lifecycle, the single-writer chain action loop, and the embedded wallet writer
that adapts the service's wallet engine to the API and chain runtime.

The node is not being replaced by the service: it remains the embedded host
and API adapter. All wallet orchestration — command logic, transaction build,
signing, sweep, multi-sig, key derivation, rescan orchestration, the
chain-apply hook and the rescan fences — lives in
`ergo_wallet_service::engine::WalletEngine`. The node keeps a thin adapter:
configuration, the command channel and writer task, the in-process chain
seams over `ergo-state`, the submission and mempool adapters, the `ergo_api`
`WalletAdmin` impl, and the wallet session/task lifecycle.

**Depends on (workspace):** `ergo-primitives`, `ergo-ser`, `ergo-chain-spec`,
`ergo-crypto`, `ergo-validation`, `ergo-wallet`, `ergo-wallet-service`,
`ergo-state`, `ergo-p2p`, `ergo-sync`, `ergo-mempool`, `ergo-mining`,
`ergo-indexer`, `ergo-api`, `ergo-rest-json`, `ergo-sigma`
**Depended on by:** (see codemap index — top of the stack)
**Approx LOC:** ~44K (`src/**/*.rs`)

## Start here
- `src/node/boot/` — production bring-up and `RunHandle` lifecycle.
- `src/node/boot/api_wiring.rs` — constructs the shared wallet store, the
  in-process `ChainClient`, `ergo_wallet_service::runtime::WalletService`, the
  wallet's `RescanCoordinator` (boot recovery runs on it), the
  `EmbeddedWallet` (admin, writer task owning the `WalletEngine`, chain-apply
  `WalletStateHook`), and the API adapters.
- `src/node/action_loop.rs` — the chain-state single-writer event loop.
- `src/node/state.rs` — `NodeState`, the runtime god-struct mutated by loop
  handlers.
- `src/node/wallet_bridge.rs` — the wallet adapter: `EmbeddedWallet`,
  `WalletCommand`, `NodeWalletAdmin`, the `WalletWriter` loop that dispatches
  each command to the `WalletEngine`, and the node-side seam implementations
  (`ChainStateAccessorImpl`, `NodeSubmitAdapter`, `MempoolViewOverlay`).
- `src/node/wallet_bridge/chain_client.rs` — `InProcessChainClient`, adapting
  committed `ChainStoreReader` and node submission into the service's
  `ChainClient` port.
- `src/snapshot.rs` — lock-free `NodeSnapshot` projection served to the API.

## Modules
- `src/main.rs`, `src/lib.rs` — CLI/bin and library facade.
- `src/config/` — TOML/CLI parsing, precedence, resolved configuration, mode
  selection, and validation.
- `src/node/boot.rs`, `src/node/boot/api_wiring.rs` — process startup and API
  plus wallet wiring.
- `src/node/action_loop.rs`, `sync_tick.rs`, `events.rs`, `messaging.rs` — the
  single-writer chain loop and event ingestion.
- `src/node/state.rs`, `handle.rs`, `admission.rs`, `peer_actions.rs` — runtime
  state, shutdown, transaction admission, and peer command plumbing.
- `src/node/sync_tick.rs`, `src/node/boot/sync_setup.rs` — applied-tip advancement and
  snapshot/NiPoPoW bootstrap state machines.
- `src/node/wallet_bridge.rs` — the embedded wallet adapter: command channel,
  rescan fences and control policy, engine dispatch, rescan-job spawning, the
  `/scan/addBox` box-JSON decode, and the seam implementations over
  `ergo-state` / `NodeSubmit` / the API mempool view.
- `src/node/wallet_bridge/chain_client.rs` — the node's concrete
  `ChainClient` implementation over committed state and `NodeSubmit`.
- `src/node/wallet_bridge/chain_snapshot.rs` — `ChainSnapshot`, the committed
  `SigningView` over an `ergo-state` `CommittedSnapshot`.
- `src/wallet_boot.rs` — wallet session ids, per-session task tracking, and
  routing a node shutdown, by session id, to that session's
  `RescanCoordinator`.
- `src/api_bridge.rs` (+ siblings) — API trait implementations backed by the
  node snapshot and submission channels.
- `src/mining_bridge.rs`, `src/node/mining_dispatch.rs`,
  `src/node/mining_engine.rs` — external-miner adapter and off-loop candidate
  engine.
- `src/snapshot.rs`, `src/node/snapshot_emit.rs`, `snapshot_state.rs` — API
  snapshot construction and publication.
- `src/peer_loop.rs` — peer connection tasks and `PeerEvent` production.
- `src/indexer_chain.rs` — indexer reader adapter over `ChainStoreReader`.
- `src/notifier.rs` — committed-tip notifier for mempool reconciliation.
- `src/genesis.rs`, `anchor_map.rs`, `anchor_scheduler.rs` — genesis loading
  and header-anchor support.
- `src/node/event_feed.rs`, `first_deliverer.rs`, `heartbeat.rs`,
  `memory_sampler.rs` — operator feed, attribution, and diagnostics.

## Key types, traits & functions
- `RunHandle`, `run`, `run_inner` — live process lifecycle and graceful
  shutdown.
- `NodeState`, `action_loop` — chain runtime ownership and serialized mutation.
- `NodeSnapshot`, `SnapshotPublisher`, `SnapshotHandle` — per-tick API read
  projection.
- `NodeWalletAdmin` — API-to-wallet-command adapter (with the pre-enqueue
  rescan fence).
- `ChainStateAccessorImpl`, `ChainSnapshot` — the node's `WalletChainAccess` /
  `SigningView` over committed `ergo-state`.
- `NodeSubmitAdapter`, `MempoolViewOverlay` — the engine's `TxSubmitter` and
  `MempoolOverlay` over `NodeSubmit` and the API mempool view.
- `WalletStateHook` — the service's `WalletApplyHook`, re-exported; built from
  the engine by `EmbeddedWallet` and wired into block apply / rollback (its
  `wiring()` supplies the rollback guard).
- `InProcessChainClient` / `NodeChainClient` — committed-state and submission
  adapter for the service `ChainClient`.
- `WalletService` — service-owned runtime core embedded at boot and handed
  to the engine, which uses it for selected reads and for rescans.
- `EmbeddedWallet`, `WalletWriter`, `WalletCommand` — the embedded wallet.
  `EmbeddedWallet::new(parts)` builds the engine, begins the wallet session and
  returns the admin, the writer task (one engine per writer, commands executed
  in arrival order) and the chain-apply hook, all on the engine's
  `RescanCoordinator`.
- `PeerEvent`, `MempoolNotifier`, `DiffSource` — peer ingestion and mempool
  reconciliation contracts.
- `NodeConfig`, `StateType`, `NodeMode` — resolved configuration and operating
  mode taxonomy.
- `is_canonical_mode_5_combo`, `is_canonical_mode_6_combo` — shared runtime
  capability gates.

## Invariants & contracts
- **One chain-state writer.** All `StateStore` and mempool mutation happens on
  the action-loop task. Service-owned wallet persistence is invoked through a
  wallet apply payload in the same state redb transaction on both synchronous
  and background-persist paths.
- **Thin wallet adapter.** The wallet's behavior lives in the service's
  `WalletEngine`; the node moves commands and replies, enforces the rescan
  fences (before enqueue in `NodeWalletAdmin`, at execution in the writer),
  runs a rescan's `RescanJob` with `spawn_blocking` tracked by the wallet
  session, and implements the chain / submit / mempool seams. One
  `RescanCoordinator` per wallet session is shared by the engine, the admin
  fence and the chain-apply hook by construction — `EmbeddedWallet::new`
  derives all three from the one engine, and none takes a coordinator of its
  own; there are no process-global rescan flags.
- **Derived keys track forward.** Deriving a key persists it (tracked key,
  visible addresses and — for `deriveNextKey` — the derivation head in one
  write) and tracks it from the next applied block; it does not rescan
  history.
- **In-process chain adapter.** `InProcessChainClient` returns owned,
  identity-checked block data from the committed state reader and routes
  submission through `NodeSubmit`; the service itself has no node/API
  dependency.
- **Atomic durable shutdown.** Clean shutdown drains the API before the action
  loop performs the final durable state commit. `RunHandle::Drop` is
  best-effort and embedders must await `shutdown()` before reopening a data
  directory.
- **Reorg-detecting mempool reconcile.** `MempoolNotifier` keys on
  `(height, header_id)`, so equal-height reorgs are detected without putting
  channels on the consensus commit path.
- **Epoch-boundary revalidation.** A tip change with different active params
  or validation settings demotes active mempool transactions and re-admits
  them under the new rules.
- **IP bans evict every connection.** A banned peer tears down all registered
  runtime entries for that IP, including other ports and pending handshakes.
- **Change-address updates are unlocked-only and ownership-checked.** The
  recorded path is re-derived with the active master key before persistence.
- **Mode gates are enforced twice.** Config loading and the programmatic
  runtime backstop share the canonical mode predicates; mining and the
  extra-index force off in incompatible state modes.
- **PoW is verified at the API boundary.** Submitted full blocks receive an
  Autolykos precheck before waking the action loop.
- **Lock-free API reads.** The API loads the `ArcSwap` snapshot and never
  blocks the chain writer on ordinary reads.
- **Task ownership is explicit.** Shutdown signals and aborts every task
  registered by `RunHandle`; wallet writer/rescan tasks are tracked by
  `wallet_boot` so they cannot outlive the embedded wallet session silently.
  A node's shutdown is routed by its wallet session id to that session's
  `RescanCoordinator`, so it cancels its own running rescan even when another
  session has begun in the same process since, and never reaches another
  session's wallet.
