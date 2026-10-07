# ergo-wallet-service

**Purpose:** Transport-neutral wallet orchestration, persistence, and runtime
core. Owns wallet state, the redb wallet store, apply/rollback/rescan logic,
chain-client boundaries, box selection, unsigned transaction construction, and
— in `engine` — the complete wallet command logic: lifecycle, reads,
build/sign/self-verify/send, the reward sweep, multi-sig, key derivation,
`/scan/*`, rescan orchestration, and the chain-apply hook. It does not own
HTTP, a tokio runtime, node lifecycle, or secret-file policy; embedders supply
those through the engine's seams.

**Depends on (workspace):** `ergo-wallet`, `ergo-wallet-protocol`,
`ergo-primitives`, `ergo-ser`, `ergo-validation`, `ergo-sigma`
**Normal dependency boundary:** the allowed normal direct dependencies are the
six workspace crates above plus `serde`, `serde_json`, `hex`, `thiserror`,
`redb`, `bincode`, `tracing`, `async-trait` (a proc macro: runtime-agnostic
`async fn` in the submit seam, no executor), `parking_lot` (the shared
`SecretStorage` / `WalletState` locks), `k256` and `zeroize` (external-secret
scalars and private-key export). `ergo-sigma` is a direct edge because the
engine's signed-transaction self-verify calls the sigma verifier. The normal
tree must not contain `ergo-state`, `ergo-api`, `ergo-node`, `ergo-mempool`,
`ergo-mining`, `ergo-sync`, `tokio`, or `axum`;
`tests/dependency_boundary.rs` enforces this. `ergo-rest-json` is a
**dev-dependency** only (the `/scan/addBox` tests decode their box JSON with
the node's production decoder).
**Depended on by:** `ergo-node`, `ergo-walletd`; `ergo-state` during the
transitional `ergo-state -> ergo-wallet-service` integration
**Approx LOC:** ~22K (`src/**/*.rs`, including tests)

## Start here
- `src/lib.rs` — module map and the service's public re-exports.
- `src/engine/mod.rs` — `WalletEngine`, the wallet orchestration core: one
  method per wallet command, built from `WalletEngineParts`.
- `src/engine/chain.rs`, `mempool.rs`, `submit.rs`, `rescan.rs` — the seams
  the engine runs on (see below).
- `src/state.rs` — in-memory `WalletState`, tracked-key caches, hydration, and
  lock-state projection.
- `src/runtime.rs:74` — `WalletService`/`WalletRuntime`, status and balance
  reads, bounded sync, and rescan orchestration over a `ChainClient`.
- `src/chain.rs:312` — object-safe `ChainClient` plus neutral tip, snapshot,
  block-range, UTXO, and submit shapes used by the runtime.
- `src/wallet/store.rs:170` — `WalletStore`/`WalletRead`/`WalletWrite` and the
  `RedbWalletStore` implementation.
- `src/wallet/apply/` — chain-apply classification, scan tracking, maturity,
  and rollback hooks; these run inside the state's existing redb transaction.
- `src/tx_builder.rs` and `src/box_selector/` — pure box selection and
  unsigned transaction construction, including EIP-27 re-emission handling.

## Modules
- `src/engine/` — the wallet engine:
  - `mod.rs` — `WalletEngine` / `WalletEngineParts`.
  - `chain.rs` — `WalletChainAccess` (signing/rescan chain contract),
    `SigningView` (one committed view for sign + self-verify),
    `ChainAccessError`, `map_chain_error`.
  - `mempool.rs` — `MempoolOverlay` (+ `NoopMempoolOverlay`).
  - `submit.rs` — async `TxSubmitter`, `TxSubmitError`, `map_submit_error`.
  - `rescan.rs` — `RescanCoordinator`, `WalletRescanGuard`,
    `WalletEngine::prepare_rescan` → `RescanJob`, and
    `recover_interrupted_rescan` (boot-time recovery).
  - `config.rs` — `WalletEngineConfig`.
  - `admin.rs` — status, init/restore, unlock/lock, seed check, change
    address, and the failed-attempt budget (`AttemptLimiter`).
  - `reads.rs` — compat and native balance/address/box/transaction reads.
  - `scan_guard.rs` — durable scan-invalidation gate for reads and spending;
    direct engine callers receive the same refusals as node API callers.
  - `build.rs` — the shared burn-aware unsigned-tx builder + native
    `boxes/select` / `transactions/build`.
  - `sign.rs` — native `transactions/sign` / `transactions/send` and the
    shared sign / self-verify / serialize building blocks.
  - `send.rs` — compat `PaymentSend` / `TransactionGenerate*` /
    `TransactionSign` / `TransactionSend` / `BoxesCollect` and the native send
    commands.
  - `sweep.rs` — the "retrieve matured mining rewards" sweep.
  - `multisig.rs`, `hints_codec.rs` — `generateCommitments` / `extractHints`
    and the hints-bag JSON codec.
  - `keys.rs` — `deriveKey` / `deriveNextKey` / `getPrivateKey` and
    `WalletBootService` (unlock + hydrate + unlock-time key derivation +
    change-address backfill).
  - `scan.rs` — the `/scan/*` registry, tracked-box reads/writes, and the
    rescan scan matcher.
  - `hook.rs` — `WalletStateHook`, the chain-apply `WalletApplyHook`.
  - `dto.rs` — wallet-row → wire-entry projections and pagination.
- `src/runtime.rs` — synchronous service orchestration over a wallet store and
  chain client; `WalletRuntime` is an alias for `WalletService`.
- `src/chain.rs` — runtime-facing chain port and owned response types, plus
  `authenticate_header` / `HeaderAuthError`: decode raw header bytes as exactly
  one header, recompute the id over the received bytes, and check the claimed
  height and parent (`ChainBlock::authenticate_header`,
  `ChainHeader::authenticate`).
- `src/state.rs` — cached wallet state and hydration boundary.
- `src/wallet/` — redb tables, value types, reader/writer traits, apply and
  maturity logic, scan tracking, schema migration, and rescan service.
- `src/tx_builder.rs`, `src/box_selector/` — transaction/UTXO construction
  logic independent of a transport.
- `src/scan/` — scan predicates, registry, and scan request types.

## Key types, traits & functions
- `WalletEngine`, `WalletEngineParts`, `WalletEngineConfig` — the wallet
  orchestration core and its construction. Methods return
  `Result<_, WalletAdminError>`; they are synchronous except the three that
  await submission (`payment_send` / `transaction_send`,
  `native_send_transaction`, `retrieve_rewards`). Commands that change wallet
  state take `&mut self`; read-only ones take `&self`.
- `WalletChainAccess`, `SigningView`, `ChainAccessError` — the engine's chain
  seam. Deliberately separate from `ChainClient` (the daemon's HTTP chain
  contract); the embedded node implements it over committed `ergo-state`.
- `MempoolOverlay`, `TxSubmitter`, `TxSubmitError` — pool and submission
  seams.
- `RescanCoordinator`, `WalletRescanGuard`, `RescanJob`,
  `recover_interrupted_rescan` — per-wallet rescan fences and orchestration.
- `WalletStateHook`, `WalletBootService` — chain-apply hook (from
  `WalletEngine::state_hook`; `WalletStateHook::standalone` for engine-less
  harnesses) and the unlock path.
- `WalletService` / `WalletRuntime` — service-owned runtime facade.
- `WalletStatus`, `RescanRequest`, `RescanReport` — status and bounded
  synchronization results.
- `ChainClient`, `CommittedTip`, `BlocksSinceResponse` — transport-neutral
  chain port used by rescan and runtime reads. `ChainClient::committed_tip_within`
  is the bounded variant for read paths that must not block on a transport's
  default deadline; the default implementation is the unbounded call, so a
  transport opts in rather than being silently truncated.
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
- **The engine is the wallet.** Every wallet command's logic lives in
  `WalletEngine`; an embedder only moves commands and replies.
- **Single writer, compiler-enforced.** Every command that writes the secret
  storage, the in-memory state or the wallet store, claims a rescan, or
  updates a failed-attempt budget (`init`, `restore`, `unlock`, `lock`,
  `check`, `update_change_address`, `derive_key`, `derive_next_key`, the
  `/scan/*` mutations, `prepare_rescan`) takes `&mut self`, so it never runs
  alongside another command on the same engine; read-only commands take
  `&self`. The engine relies on that ordering for read-then-write sequences
  (scan registry, derivation head) and takes its locks at each command's
  historical granularity. The node's writer task owns its engine by value.
- **No process-global wallet state.** Rescan fences, cancellation, the
  shutdown request, and the transition lock live in one `RescanCoordinator`
  per wallet, shared by `Arc` between the engine, the `WalletStateHook` and
  its `WalletRescanGuard`. The crate has no `static` atomics or mutexes for
  wallet or rescan state.
- **A hook shares its engine's coordinator by construction.** The hook for a
  wallet an engine runs comes only from `WalletEngine::state_hook`, and the
  rollback guard only from that hook; neither can be handed another
  coordinator (their constructors are crate-private).
  `WalletStateHook::standalone`, with a coordinator of its own, is the
  explicitly engine-less path for test harnesses.
- **Rescan runs off the command path.** `WalletEngine::prepare_rescan`
  performs every check and transition that can refuse a rescan and returns a
  `RescanJob`; the embedder runs `RescanJob::run` on a blocking thread. The
  job's guard is armed, failed closed, when the job is built, and releases the
  fences (or keeps them failed closed) when the job finishes or unwinds; a job
  dropped without running releases the task slot and leaves the wallet failed
  closed, so a full rescan can recover it.
- **Signing reads one committed view.** Sign and self-verify read a single
  `SigningView`; the paths that submit re-check it against the committed tip
  (`WalletChainAccess::ensure_view_current`) first, so a tip that moved
  between signing and submission is a typed `409 stale_chain_tip` rather than
  a submission built against a superseded tip.
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
- **Two-direction applied-header index.** The standalone store's applied-header
  history is written in both directions in the same transaction —
  `height -> block id` (`WALLET_APPLIED_HEADERS`) and `block id -> height`
  (`WALLET_APPLIED_HEADER_IDS`) — so duplicate detection ("this block id is
  already applied at another height") is a point lookup instead of a full scan
  per applied block, and rollback/rescan truncation drops both. The reverse
  table is derived state and is rebuilt at open if it is missing or out of
  step, so a store written by an older build keeps duplicate detection.
- **Transport neutrality.** The service exposes synchronous ports, one async
  submission trait, and owned values. It does not open sockets, spawn a tokio
  runtime, depend on axum, or know the node's command channel. The embedded
  node is a thin adapter (`ergo-node/src/node/wallet_bridge.rs`); phase 3
  lets the daemon sign and send through the same engine.
