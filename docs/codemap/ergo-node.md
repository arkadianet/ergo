# ergo-node

**Purpose:** The binary and embedded/API-adapter runtime crate. Wires chain
state, P2P, sync, mempool, mining, indexer, API, wallet cryptography, and
`ergo-wallet-service` into one supervised tokio process. It owns process
lifecycle, the single-writer chain action loop, and the embedded wallet writer
that adapts the service core to the API and chain runtime.

The node is not being replaced by the service: it remains the embedded host
and API adapter. The service owns wallet persistence/runtime-core behavior,
while the node still owns secret storage, the command loop, the state hook,
and the in-process chain client. Full runtime relocation is transitional.

**Depends on (workspace):** `ergo-primitives`, `ergo-ser`, `ergo-chain-spec`,
`ergo-crypto`, `ergo-validation`, `ergo-wallet`, `ergo-wallet-service`,
`ergo-state`, `ergo-p2p`, `ergo-sync`, `ergo-mempool`, `ergo-mining`,
`ergo-indexer`, `ergo-api`, `ergo-rest-json`, `ergo-sigma`
**Depended on by:** (see codemap index — top of the stack)
**Approx LOC:** ~53K (`src/**/*.rs`)

## Start here
- `src/node/boot/` — production bring-up and `RunHandle` lifecycle.
- `src/node/boot/api_wiring.rs` — constructs the shared wallet store, the
  in-process `ChainClient`, `ergo_wallet_service::runtime::WalletService`, the
  embedded wallet writer, and the API adapters.
- `src/node/action_loop.rs` — the chain-state single-writer event loop.
- `src/node/state.rs` — `NodeState`, the runtime god-struct mutated by loop
  handlers.
- `src/node/wallet_bridge.rs` — wallet command loop, `NodeWalletAdmin`,
  `WalletStateHook`, and the embedded/API adaptation around the service.
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
- `src/node/wallet_bridge.rs` (+ `commands/`, `support/`) — the embedded wallet
  command loop and API/admin adaptation.
- `src/node/wallet_bridge/chain_client.rs` — the node's concrete
  `ChainClient` implementation over committed state and `NodeSubmit`.
- `src/wallet_boot.rs` — unlock/hydration, rescan lifecycle flags, task
  tracking, and shutdown. This remains node-owned during runtime relocation.
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
- `NodeWalletAdmin` — API-to-wallet-command adapter.
- `WalletStateHook` — node implementation of the service's `WalletApplyHook`.
- `InProcessChainClient` / `NodeChainClient` — committed-state and submission
  adapter for the service `ChainClient`.
- `WalletService` — service-owned runtime core embedded at boot; the node
  passes it into selected read paths while retaining fallback/compatibility
  paths during relocation.
- `WalletCommand`, `run_wallet_writer_with_service`, `WriterContext` — the
  transitional embedded wallet runtime.
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
- **Two current wallet layers, one service core.** The service owns
  persistence and runtime-core behavior. The node still owns the embedded
  `SecretStorage`, `WalletState` lock, command dispatch, signing/admin
  adaptation, rescan task flags, and API trait implementation. Do not describe
  full runtime relocation as complete.
- **Derived-key recovery.** Key derivation checks that history can be read
  before changing the tracked keys, then starts a supervised full rescan.
  Wallet operations remain fenced until the rebuild succeeds; unsupported
  or pruned backends reject derivation before persisting a new key.
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
