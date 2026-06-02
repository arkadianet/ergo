# ergo-api

**Purpose:** Operator-facing read-mostly HTTP/JSON server for the node. Hosts the axum router that serves the Scala-compatible surface (`/info`, `/blocks/*`, `/transactions*`, `/utxo/*`, `/peers/*`, `/utils/*`, `/blockchain/*`, `/mining/*`) and the node-native `/api/v1/*` dashboard surface, plus the `/wallet/*` API and the embedded browser UIs. Its contract with the rest of the workspace is a small set of `Arc<dyn …>` traits — the node implements them against a runtime snapshot and hands the trait objects to `serve`; `ergo-api` never reaches into node internals.

**Depends on (workspace):** ergo-indexer-types, ergo-ser, ergo-primitives, ergo-rest-json (plus dev-only: ergo-indexer)
**Depended on by:** (see codemap index)
**Approx LOC:** ~10,300

## Start here
- `src/lib.rs` — the module tree + re-export list; the crate's public face in 40 lines.
- `src/traits.rs` — the load-bearing seam: `NodeReadState`, `NodeSubmit`, `NodeAdmin`, `MempoolView`, `ChainParamsView`. Read this to understand the whole boundary.
- `router_with_mempool_and_wallet_and_security` (`src/server.rs:477`) — the single function that assembles every route; the canonical map of what is mounted and under what condition.
- `src/compat/traits.rs` — `NodeChainQuery`, the live id-keyed read trait the Scala-compat surface needs (block/utxo/tx/peers/pool by id).
- `src/types.rs` (module doc) — the wire DTO contract, especially the id-encoding rules (lowercase hex, 64 hex chars for ids, 66 for `state_root_avl`).

## Modules
- `src/lib.rs` — crate root: module tree + the curated re-export set.
- `src/traits.rs` — node-implemented reader/submit/admin/mempool/chain-params traits + `Noop*` test impls; `PoolTxDetail` type alias.
- `src/server.rs` — axum router assembly, all native `/api/v1/*` handlers, asset serving, the bind/serve entry points, graceful-shutdown contract, conditional route mounting, the `TraceLayer` request-id span, and the submit-error mapping helpers (`map_submit_error`, `submit_via_node`).
- `src/auth.rs` — `api_key`-header middleware (`require_api_key`), `ApiSecurity` (Blake2b-256 hex, constant-time compare), Scala-parity 403 envelope.
- `src/mining.rs` — `/mining/*` sub-router + `NodeMining` trait + `MiningApiError`→HTTP mapping; `mining_router`, `NoopNodeMining`.
- `src/utils.rs` — stateless `/utils/*` helpers (seed, blake2b hash, address ⇄ raw, address validation, ergoTree→address); pure functions of input + `NetworkPrefix`.
- `src/web.rs` — compile-time-embedded static assets (dashboard HTML/CSS/JS, Swagger pages, openapi.yaml, JetBrains Mono font, wallet UI bundle).
- `src/types.rs` — node-native wire DTOs (`Api*`, `SubmitError`/`SubmitMode`, `RawTransactionBytes`, difficulty series) with `utoipa::ToSchema` for the native OpenAPI spec.
- `src/compat/` — Scala-compatible surface mounted at bare paths.
  - `compat/traits.rs` — `NodeChainQuery` live-read trait + `UtxoBoxBytes` envelope.
  - `compat/types.rs` — `ScalaInfo` / `Parameters` + re-exports of the shared `ergo-rest-json` Scala DTOs.
  - `compat/handlers.rs` — `/info`, `/blocks/*`, `/utxo/*`, `/peers/*`, `/transactions/unconfirmed/*` GET handlers.
  - `compat/blocks.rs` — `POST /blocks` (sendMinedBlock) handler.
  - `compat/transactions.rs` — `POST /transactions[/bytes][/check[Bytes]]` submit/check handlers.
- `src/blockchain.rs` + `src/blockchain/*` — the optional `/blockchain/*` extra-index parity surface. `blockchain.rs` holds `BlockchainState`, `enforce_status_gate` middleware, `indexed_height_handler`, the error envelopes, and paging/sort parsing (`resolve_page`, `parse_sort_direction`, `MAX_ITEMS = 16384`). Submodules: `balance`, `blocks`, `boxes`, `byaddress`, `byergotree`, `bytemplate`, `range`, `storage_rent`, `tokens`, `transactions`, `unspent_byaddress`.
- `src/wallet/` — `/wallet/*` API. `mod.rs` defines `WalletAdmin` trait + `router_with_security`; submodules `lifecycle` (status/init/restore/unlock/lock/check), `state_mut` (rescan/updateChangeAddress), `reads`, `sending`, `multi_sig`, `admin_advanced`, `lock_guard`, `types` (camelCase DTOs).

## Key types, traits & functions
- `NodeReadState` (trait) — sync snapshot reads: info/status/tip/sync/peers/mempool/health/identity/host/recent_blocks — `src/traits.rs:21`
- `NodeSubmit` (trait) — async submit boundary: `submit_transaction` (bytes), `submit_transaction_json` (Scala DTO), `submit_full_block`; returns hex modifier id — `src/traits.rs:64`
- `MempoolView` (trait) — sync pool overlay for the extra-index: `is_spent_by_pool`/`pool_spending_tx`/`pool_outputs`/`pool_tx_detail` — `src/traits.rs:168`
- `NodeAdmin` (trait) — single `request_shutdown` backing `POST /node/shutdown` — `src/traits.rs:142`
- `ChainParamsView` (trait) — voted-param arithmetic for storage-rent (`storage_fee_factor_for_validation_at`, `compute_storage_fee`) without a direct `ergo-validation` dep — `src/traits.rs:227`
- `PoolTxDetail` (type) — `(Arc<[u8]>, Arc<HashMap<BoxId, ErgoBox>>)` coherent single-snapshot tx-bytes + outputs pair — `src/traits.rs:204`
- `NodeChainQuery` (trait) — live id-keyed Scala-compat reads (block/header/utxo/tx/peers/pool by id) — `src/compat/traits.rs:15`
- `NodeMining` (trait) — async external-miner surface: `candidate` (longpoll), `submit_solution`, `reward_address`, `reward_pubkey` — `src/mining.rs:35`
- `MiningApiError` (enum) — categorized mining errors with the HTTP-status mapping (`InvalidPow`→400, `Unavailable`→503, `Timeout`→504, …) — `src/mining.rs:68`
- `WalletAdmin` (trait) — async wallet lifecycle/reads/sending boundary — `src/wallet/mod.rs:35`
- `ApiSecurity` (struct) + `require_api_key` (fn) — `api_key`-header auth: `hash_key` (Blake2b-256 hex), constant-time compare, Scala-parity 403 — `src/auth.rs:43`, `src/auth.rs:105`
- `ServerCtx` (struct) — the dependency bundle threaded through every entry point; `Option` fields decide which route families mount — `src/server.rs:105`
- `router_with_mempool_and_wallet_and_security` (fn) — the full router builder (mempool overlay + `WalletAdmin` + explicit `Option<ApiSecurity>` gate) — `src/server.rs:477`
- `bind` / `serve_on` / `serve` / `serve_on_with_mempool_and_wallet_and_security` (fns) — listener + axum lifecycle, graceful-shutdown contract — `src/server.rs:138,163,274,226`
- `mining_router` (fn) — builds the `/mining/*` sub-router merged in when mining is enabled — `src/mining.rs:169`
- `BlockchainState` (struct) + `enforce_status_gate` (fn) — extra-index router state + the `503 indexer-syncing/-halted` gate — `src/blockchain.rs:105`, `src/blockchain.rs:203`
- `ApiInfo` / `ApiIdentity` / `ApiStatus` / `ApiSubmitError` / `ApiNativeSubmitError` / `SubmitMode` (types) — native `/api/v1/*` wire DTOs — `src/types.rs`
- `ScalaInfo` / `Parameters` (types) — Scala `/info` body — `src/compat/types.rs`

## Invariants & contracts
- **Trait-object boundary, no concrete-type leak.** Every dependency on node runtime state enters through `Arc<dyn …>` (`NodeReadState`/`NodeSubmit`/`NodeAdmin`/`MempoolView`/`ChainParamsView`/`NodeChainQuery`/`NodeMining`/`IndexerQuery`/`WalletAdmin`). The production build never depends on `ergo-indexer`/`ergo-state` (`ergo-indexer` is dev-only).
- **Snapshot-read handlers.** Sync reader-trait methods are contractually cheap snapshot reads invokable on every request with no main-loop coordination; the node backs them from an `ArcSwap<NodeSnapshot>` rebuilt per sync tick.
- **Id/hash wire encoding.** All id- and content-hash `String` fields are lowercase Base16, byte-exact with on-disk/on-chain bytes — no `0x`, no upper-case, no base64. 64 hex chars for 32-byte ids; 66 for `state_root_avl` (33-byte AVL+ root). Scala DTO field names match the reference node byte-for-byte (`ergo-rest-json`, pinned by its byte-parity oracle).
- **Auth scope.** The `api_key` middleware gates only `/wallet/*` and both `/node/shutdown` aliases, and only when a `Some(ApiSecurity)` is passed; all read/submit/`/blockchain`/`/peers`/`/utils`/`/mining`(candidate/reward) routes stay unauthenticated. `api_key` header (lowercase, underscore), Blake2b-256 → lowercase hex, constant-time compare, `403 {error,reason:"invalid.api-key",detail:null}` — Scala parity. The full-featured builder takes the gate as a required `Option`, never defaulted, by design (no "did production enable auth?" footgun).
- **Conditional route mounting.** `/blockchain/*` mounts only with an `IndexerQuery`; its byId/byIndex routes are fronted by `enforce_status_gate` (only `CaughtUp` passes; otherwise the pinned `503 indexer-syncing`/`indexer-halted` envelope short-circuits before any trait method). `/blockchain/indexedHeight` is always 200, bypassing the gate. `/utxo/*` mounts either the six live handlers (UTXO backend) or the same six path+method shapes returning `503` (digest backend) per `ServerCtx::utxo_reads_supported`. Tx/block-reassembly routes additionally require the chain reader; storage-rent routes require a `ChainParamsView`.
- **Scala-parity error envelopes & paging caps.** `{error, reason, detail}` field order matches Scala's emission; `MAX_ITEMS = 16384` paging cap, default `offset=0/limit=5`, and the verbatim `sortDirection`/over-limit error strings are pinned for router-walk parity.
- **Submit return contract.** `NodeSubmit` success returns the hex-encoded 32-byte modifier id (tx id for tx methods, header id for `submit_full_block`); `submit_full_block` defaults to `route_disabled` (→503) when block submission is not wired.
- **Graceful-shutdown contract.** `serve_on*` pairs axum's graceful drain with the action loop so in-flight submit/check handlers can surface a structured `503 shutting_down` instead of a TCP RST; the request-id `TraceLayer` span logs path only (never the full query string).
- **Wallet UI security headers.** `/wallet/ui*` carries a scoped CSP + `no-store`/`no-cache` layer (bfcache mitigation for mnemonic-bearing pages); the page is public but the `/wallet/*` JSON API it drives stays `api_key`-gated.

(No consensus, PoW, AVL, persistence, or reorg invariants are owned here — those live in `ergo-validation`/`ergo-state`/`ergo-crypto`. This crate owns only its wire-shape, auth-scope, route-gating, and trait-boundary contracts.)
