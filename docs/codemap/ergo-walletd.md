# ergo-walletd

**Purpose:** The standalone wallet process owns `wallet.redb`, its encrypted
seed store in opt-in seed mode, and a supervised engine writer. Watch-only
mode imports public descriptors and retains confirmed read projections. Seed
mode serves the shared engine's native and Scala APIs, spending, scans, rescans,
private mining jobs, and public wallet UI assets. See
[wallet extraction and cutover](../wallet-extraction.md) for operational policy.

**Normal dependency boundary:** Wallet/service/protocol crates plus pure
consensus and wire dependencies (`ergo-primitives`, `ergo-ser`,
`ergo-chain-spec`, `ergo-validation`, `ergo-sigma`, `ergo-rest-json`). The host
uses redb for explicit copy migration, bounded HTTP/RPC, Axum/Hyper/Tokio for
local serving and supervision, protected file/CLI/config support and zeroizing
credentials. No normal `ergo-node`, `ergo-state`, `ergo-api`, `ergo-mempool` or
`ergo-sync` dependency enters the daemon. Node, state, API, mempool and mining
crates are test-only for real HTTP and private-reservation fixtures.

**Phase 3 hosting:** `host.rs` owns command admission, blocking engine work,
command-scoped spending refresh/release, rescan fencing and secret erasure.
`spending.rs` implements chain/signing, coherent pool and bounded submission
ports over authenticated versioned HTTP. `full_api/` owns complete native and
Scala adapters plus a wallet-only UI; watch read behavior remains in `api.rs`.
`migration.rs` handles stopped-source locking, private-copy export and encrypted
secret publication. Pure wallet dependencies and optional host features are described
in [ergo-wallet](ergo-wallet.md); the shared persistence/engine behavior lives
in [ergo-wallet-service](ergo-wallet-service.md).

The historical read/sync details below describe the watch-only adapter and the
short diagnostic routes. Seed native routes use engine schemas and capabilities
as described above.

## Start here
- `src/main.rs` — process entry. **Blocking first, async second**: load the
  config, call `prepare`, *then* build the runtime and `block_on(run(..))`. The
  split is load-bearing, not stylistic — see "Startup is two phases" below.
- `src/lib.rs` — `prepare` (blocking: claim mode ownership, open the store,
  import watch descriptors or build a locked seed host, construct the blocking
  chain client and wire the syncer/tip) and `run` / `run_until` (async:
  bind the listeners, supervise the blocking sync loop and the join set).
- `src/config.rs` — `WalletMode`, `Network`, `FileConfig`, `Cli`, `Config`, and
  `read_api_key` (the node/local API-key file permission gate).
- `src/host.rs` — `WalletHost`: locked seed startup, typed engine commands,
  bounded admission and the shared sync writer gate.
- `src/lifecycle_api.rs` — seed API authentication and local lifecycle status.
- `src/full_api/` — native/Scala engine adapters and wallet UI assets.
- `src/spending.rs` — bounded coherent node context, mempool and submission ports.
- `src/engine_chain.rs` — `LifecycleChainAccess`: local cursor and bounded
  node-tip reads; no signing or engine rescan replay.
- `src/ownership.rs` — durable `wallet-mode` marker and data-directory policy.
- `src/descriptor.rs:68` — `parse_file` / `parse_text` / `import`: the
  no-secret descriptor boundary.
- `src/sync.rs:106` — `StandaloneSyncer` / `sync_once`: the forward/reorg/pruned
  state machine that drives the wallet cursor. `batch` is the per-pass **apply**
  budget and `page` is the per-request **page** budget; see "Two sync budgets".
- `src/chain_http.rs:55` — `HttpChainClient`: the node HTTP adapter (including the
  `/blockchain/*` address-index reads behind restore and key backfill) and its
  response neutralisation/validation, the 16 MiB body cap, and the
  `new_in_runtime` / `with_timeouts_in_runtime` constructors for async callers.
- `src/api.rs:32` — `ApiContext` and the read-only router.
- `src/tip.rs:32` — `CachedNodeTip`: the last-observed node tip shared between
  the sync loop and `/status`.
- `src/socket.rs:27` — `UnixSocketGuard` / `bind_restricted`: socket ownership
  marker and owner-only permissions.

## Modules
- `src/config.rs` — TOML/CLI schema, mode validation, and credential file
  policy (API-key files must not be group/other readable; keys are redacted
  and held in zeroizing buffers).
- `src/ownership.rs` — claim the data directory's mode before opening redb;
  reject cross-mode reuse and require fresh seed directories.
- `src/host.rs` — seed metadata/public-cache hydration, one engine writer,
  typed lifecycle/key wrappers, sync serialization and shutdown key erasure.
- `src/lifecycle_api.rs` — authentication before body parsing and the local
  lifecycle-status projection; `full_api/` supplies strict native/Scala handlers.
- `src/engine_chain.rs` — capability-limited `WalletChainAccess` adapter.
- `src/descriptor.rs` — descriptor parsing/validation and idempotent import
  into the wallet's tracked-pubkey tables.
- `src/sync.rs` — bounded rescan/forward sync, reorg rewind and rebuild,
  retries, and durable rescan-state failure recording. `SyncConfig::batch` is
  the apply budget and `SyncConfig::page` the per-request page budget; see "Two
  sync budgets".
- `src/chain_http.rs` — blocking `reqwest` client for
  `api/v1/chain/{tip,snapshot,blocks-since,boxes/:id}` with body-size caps,
  timeouts, and status-code → typed-error mapping. It authenticates every
  block and snapshot header against its raw bytes and re-derives every box —
  see "What the daemon verifies".
- `src/api.rs` — axum router, read handlers, DTO projection.
- `src/socket.rs` (unix) — Unix-socket claim/cleanup and `0o600` permissions.
- `src/tip.rs` — node-tip cache with a capped fallback probe.

## Key types, traits & functions
- `config::Config`, `config::FileConfig`, `config::Cli`, `config::WalletMode`, `config::Network`,
  `config::ApiKey` — the operator surface.
- `descriptor::DescriptorEntry`, `descriptor::ImportReport`,
  `descriptor::parse_file`, `descriptor::import` — descriptor boundary.
- `sync::StandaloneSyncer`, `sync::SyncConfig`, `sync::SyncReport`,
  `sync::SyncError` — sync engine. `sync::DEFAULT_BLOCKS_PER_PAGE` is the shipped
  per-request page size; `sync::MAX_SYNC_BLOCKS` bounds both knobs.
- `chain_http::MAX_RESPONSE_BODY_BYTES` — the 16 MiB cap that bounds a page.
- `chain_http::HttpChainClient` — the only place a node URL is used.
- `api::ApiContext`, `api::router`, `api::READ_ROUTE_INVENTORY` — the read-only
  API and its test-pinned route list.
- `host::WalletHost`, `host::HostError` — seed host and startup failures.
- `api::seed_router`, `lifecycle_api::LIFECYCLE_ROUTE_INVENTORY` — authenticated
  seed routes plus the existing read projections.
- `engine_chain::LifecycleChainAccess` — engine cursor/tip capability adapter.
- `tip::CachedNodeTip`, `tip::PROBE_TIMEOUT` — `/status` tip source.

## The local read API

In default watch mode every read route is a `GET`; each is mounted twice, at a short path and under
`/api/v1/wallet/*`. `READ_ROUTE_INVENTORY` is the pinned list and is asserted by
`tests/it/routes.rs`, which also asserts that the default watch router leaves
wallet lifecycle, signing, and private-key routes unmounted. Seed mode retains
short diagnostic reads and projects native wallet routes through the full engine.
`api::watch_router` and the seed router both authenticate every read and write
with the local credential, and the TCP listener additionally checks `Host`
(`host_guard`).

| Route | Response |
|---|---|
| `/status`, `/api/v1/wallet/status` | `WatchOnlyWalletStatusDto`: durable scan cursor (height + header id), node tip, derived `lag`, `scanInvalidated`, rescan state, sync state |
| `/balance`, `/balances`, `/api/v1/wallet/balance[s]` | `WalletBalanceDto` — confirmed only |
| `/boxes`, `/boxes/:id`, `/api/v1/wallet/boxes[/:id]` | `BoxPage` / `WalletBoxSummary` — confirmed only |
| `/transactions`, `/transactions/:id`, `/api/v1/wallet/transactions[/:id]` | `TxPage` / `WalletTransactionSummary` |
| `/addresses`, `/api/v1/wallet/addresses` | `AddressPage` of `WalletAddressDto` |
| `/scans`, `/scan/listAll`, `/api/v1/scans`, `/api/v1/scan/listAll` | `Vec<ScanDto>` — persisted registrations; see "Scan registry reads" |

`offset` (default 0) and `limit` (default 50, max 16384) are the only query
parameters; anything else is a `400`.

## Opt-in seed lifecycle

`mode = "seed"` requires a fresh `data_dir`, no `descriptor_file`, and a
protected `local_api_key_file` containing a different credential from the
node's `api_key_file`. The local credential protects all seed-mode reads and
writes on both listener types. Authentication precedes request-body parsing;
duplicate key headers are refused, secret bodies are capped at 16 KiB, transaction
bodies at 8 MiB, and
every response carries `Cache-Control: no-store`. Native errors keep their
stable reason codes; internal error text and malformed secret bodies are not
echoed to callers.

| Route | Purpose |
|---|---|
| `GET /api/v1/wallet/lifecycle/status` | `LifecycleStatusDto { initialized, locked }`, entirely local |
| `POST /api/v1/wallet/init`, `/restore` | Publish a new encrypted seed through `WalletEngine`; do not overwrite an existing wallet |
| `POST /api/v1/wallet/unlock`, `/lock` | Authenticate or erase the in-memory master key |
| `POST /api/v1/wallet/mnemonic/verify` | Verify the recovery phrase through the engine's attempt budget |
| `POST /api/v1/wallet/addresses` | Derive the next EIP-3 key or a requested path |
| `GET`, `PUT /api/v1/wallet/change-address` | Read or update the persisted owned change address |

The short `/status` route retains `WatchOnlyWalletStatusDto`; lifecycle
state has its own entirely local route. Native `/api/v1/wallet/status` uses the
engine projection and refreshes committed node context for pruning/EIP-27 flags;
an unavailable node returns `503 node_unavailable`. Native balance, address,
transaction, scan, key, signing, sending and private job routes use the shared
engine, while the Scala compatibility routes serve the existing wallet UI.

`WalletHost` opens `data_dir/wallet` with `SecretStorage`, validates metadata,
hydrates public caches from one store snapshot, and always starts locked.
Malformed metadata or hydration errors stop startup; public wallet rows
without an encrypted seed are refused. `ownership::claim` persists the mode
before database creation, protects Unix seed directories with `0700`, rejects
cross-mode reuse, and treats an unmarked Phase 2 database as watch-only. Watch
startup also refuses a `wallet` secret directory. Explicit stopped-source copy
cutover is implemented by `migration.rs`; no startup path adopts embedded data.

Every lifecycle/key command runs on a blocking worker under the same mutex
as an entire sync pass. At most 32 commands are admitted; overload returns
`429 rate_limited`. Engine password and seed checks retain their independent
failed-attempt budgets. Sync waits until persisted tracked keys exist. Seed
stores opt into `RedbWalletStore::rebuild_history_on_key_additions()`, which
commits a new/changed key together with invalidation, a genesis cursor and
cleared history, so initial unlock and later key derivation cannot miss older
funds. Failed unlocks and derivations leave existing history untouched.

`LifecycleChainAccess` remains the capability-limited adapter for local lifecycle
embedders. Production seed mode installs `RemoteSpendingAccess`: each spending
command refreshes coherent committed context and pool/private reservations under
the writer, then releases them after the command. Signing, sending, job creation
and cancellation use this path. Private queue reads and cancellation remain
available when candidate mining is disabled; new private imports require mining.
Rescan runs as a supervised engine job and fences conflicting commands while
local status and lock remain available.

Shutdown closes admission before cancelling sync. Queued commands return
`503 shutting_down`; work already holding the writer finishes before the
engine locks. A command panic closes admission and locks the engine before
releasing that writer. The bounded supervisor wait may expire while a blocking
request finishes, but pending cleanup and the host's final drop still erase
the unlocked key.

## Startup is two phases

`reqwest`'s blocking client owns a private Tokio runtime, created and dropped
inside `ClientBuilder::build`. Tokio aborts when a runtime is dropped on a thread
that is inside an async context, and `reqwest` drops a *shell* runtime while it
is entered in exactly that case, so building the client from an `async fn` (or
under `#[tokio::main]`) **panics before the daemon's first log line** in a
`debug_assertions` build. `main` therefore does all blocking work in
`prepare` — mode claim, store open, descriptor import or seed-host hydration,
`HttpChainClient::new` — and only
then constructs the runtime and enters `run`. Nothing in `run` can construct a
client: it takes a `Daemon`, not a `LoadedConfig`.

For an embedder (or a `#[tokio::test]`) that is already inside a runtime,
`HttpChainClient::new_in_runtime` hands the build to the runtime's blocking
pool, which is not an async context, and moves the finished client back. There
is deliberately **no** runtime check inside `with_timeouts`: `Handle::try_current()`
is `Ok` on a blocking-pool thread (where the build is safe) as well as on an
entered worker (where it panics), so a check built on it would reject the one
context that works. The invariant is documented, enforced structurally by
`main`, and exercised end-to-end by `tests/it/daemon_boot.rs` and
`tests/it/seed_daemon_boot.rs`.

`run_until(daemon, shutdown)` is `run` with the shutdown trigger injected
(`run` passes SIGINT/SIGTERM). Only the tests use it — signalling the harness
would take it down too — and it is the same supervision path, so the test
exercises the production one.

## Two sync budgets

`SyncConfig` has two independent counters and they must not be conflated:

- **`batch` (`sync_batch`)** — the maximum number of blocks *applied* by one
  `sync_once`. It is the pass's work budget and bounds how much the wallet
  database can change before the loop returns.
- **`page` (`blocks_page`, default `DEFAULT_BLOCKS_PER_PAGE` = 128)** — the
  *ceiling* on the number of blocks asked for in a single `blocks-since` call.
  It is the *request* budget, and the page actually requested adapts below it.

Every request is `min(remaining, page_now, batch - processed)`, where `page_now`
is the syncer's adaptive page, never above `page`. A pass with `batch = 256`
reaches the tip through as many requests as its pages take.

The ceiling is sized against `chain_http::MAX_RESPONSE_BODY_BYTES` (16 MiB) by
the adaptation, not by the constant. The chain protocol carries every
transaction and every output box as hex strings, so a page's JSON body costs
roughly four times the serialized bytes of the blocks in it, and consensus
bounds one block's `BlockTransactions` section by the voted `maxBlockSize`
parameter. Against the largest `maxBlockSize` this repo documents an operator
voting for (2 MiB in `docs/configuration.md`) one maxed-out block is already
8 MiB of hex, so a page of `1` is the only page whose worst legal body provably
fits, but real blocks are far smaller and a fixed page of `1` costs about 1.9
million round trips for a full mainnet scan. So the page starts at 16
(`INITIAL_PAGE`), is resized after every served page from its largest block
(`note_page`: toward a quarter of the cap, at most doubling), and is halved and
retried when a response is refused for size (`blocks_since_adaptive`). Sizing the
request from the apply budget, `min(batch, remaining)`, could ask for up to 1024
blocks regardless, which is a permanent sync failure on a real chain.

A response over the cap is `ChainClientError::PageTooLarge { blocks, limit }`
(`chain_http::read_page`). The sync loop answers it by halving; a one-block page
that is still too large cannot be fetched at all, so `map_chain_error` turns it
into one terminal protocol error naming the cap and the page size.
`tests/it/node_api.rs` drives the adaptation against the real node API with
~1.5 MiB blocks, and `tests/it/sync.rs` pins the sizing and the terminal case
against a simulated chain with a response cap.

## Where the wallet starts

How much of the chain the wallet reads depends on what it can prove about its
keys.

- **Nothing tracked, nothing to do.** `StandaloneSyncer::has_tracking` is true
  when a key is tracked or a `/scan/*` rule is registered, which are the
  matcher's only inputs (watch-only descriptor keys are tracked keys too). A
  pass is skipped otherwise, in the host and in the descriptor-mode loop, and no
  cursor is created.
- **`init` starts at the tip.** A mnemonic the engine just generated cannot have
  history. `WalletEngine::init` puts the cursor on the node's committed tip and
  records a fresh-wallet anchor (`WALLET_FRESH_ANCHOR`) in the same transaction;
  the first unlock tracks its first two keys under that anchor without the usual
  history reset, then clears it. Every command, sync passes included, takes the
  host's writer gate first, so no pass is in flight while the cursor moves. If the
  node cannot be reached, `init` still succeeds and the wallet replays as before.
- **`restore` uses the node's address index when it has one.** The first unlock
  of a wallet `init` did not create walks the EIP-3 external addresses in windows
  of 20 through `ChainClient::addresses_used`, stopping 20 addresses past the last
  used one, and tracks every key up to it. The sync pass that then rebuilds from
  genesis asks `ChainClient::address_history` for the blocks that touched those
  keys (both the P2PK script and the mining-reward script) and applies only
  those, through the same classification as a full scan, then follows blocks
  from 16 blocks below the shorter of the index height and the tip. Each named
  block is fetched from the chain and must carry the index's block id and
  transaction, or the index is ignored and the wallet scans. A node without the
  index, an index that is not caught up, registered scans, or any disagreement
  all fall back to the full scan. See `ergo-wallet-service/src/address_index.rs`.
- **A key added later** is not assumed fresh. The engine asks the index: never
  seen, it is added with no rescan; seen, its history is backfilled from the
  named blocks in the same transaction that adds it; otherwise (no index, or the
  index cannot be trusted) the old safe default stands and the scan is
  invalidated. A caller can say `"fresh": true` on `deriveKey` / `deriveNextKey`
  (`?fresh=true`) to add the key with no rescan on its own word.
- **A declared start.** `POST /wallet/rescan` with `fromHeight > 0` and
  `"noActivityBefore": true` restarts an *invalidated* scan at that height: the
  stored history is cleared, the cursor goes to the block before it, and the same
  incomplete-history record offline discovery writes (`history_complete: false`,
  anchor = that block) says history below it was not reconstructed.

## What the daemon verifies

The node is authenticated by its API key, but its answers are still checked.

- **Block and header identity.** Every block on a `blocks-since` page and every
  header in a snapshot carries its raw serialized header (`headerBytes`).
  `chain_http` decodes it as exactly one header with no trailing bytes,
  recomputes the id as `blake2b256(headerBytes)`, and requires the claimed
  `blockId` / `headerId`, `height` and `parentId` (and, for snapshot headers,
  `timestampUnixMs`) to be the ones the header carries
  (`ergo_wallet_service::authenticate_header`). The id is hashed over the bytes
  as received, never over a re-encoding, because the decoder drops the unparsed
  section of v2-v4 headers. Pages are additionally checked for parent linkage
  against the wallet cursor, height contiguity, uniqueness, and agreement with
  the reported tip.
- **Boxes.** Every `ErgoBox` is parsed canonically and re-serialized; `box_id`,
  embedded `transaction_id`, output index, value, assets, and creation height
  are recomputed (`chain_http::neutral_block` / `WalletService::convert_block`).
- **Proof of work.** Every block and snapshot header's Autolykos solution is
  checked against the header's own `nBits` (`chain_http::verify_header_pow`).
- **Transactions inside a block.** Every transaction arrives with its
  serialized bytes. `chain_http::bind_transactions` recomputes each
  transaction id and witness id, checks the structured inputs and output boxes
  against the parsed transaction, and recomputes the block's
  `transactionsRoot` against its header. A node cannot alter, add or drop a
  transaction inside a block it serves; a node that cannot supply the bytes
  (one serving blocks from wallet state rows only) is refused.

What remains trusted:

- **Chain selection and difficulty.** The daemon does not follow difficulty
  adjustment, so it cannot tell whether a header's stated `nBits` was the one
  required at its height, or whether the presented chain is the best chain.
- **Completeness.** A node can withhold whole blocks or stall; it cannot make a
  served block say something its header does not commit to.
- **Mempool, fees, relay parameters and admission** for spending.

## Known deviations

This is a real gap in what this daemon reports. It is not hidden behind a
passing test suite.

### 1. Balance and status values are confirmed-only projections

Every read route is a **projection the daemon computes from blocks it has
applied**, and the shape is visible in the DTOs:

- `WalletBalanceDto.nanoErg.confirmed` and `.available` are the **same** number
  (the confirmed total), not two independently-sourced quantities. `reserved` and
  `immature` are literal `"0"` because the daemon has no reservation or maturity
  concept on the read path; `unconfirmed` and `reemission` are `null`, not empty.
- `height` / `asOf` are the **wallet's durable scan cursor**, not the node tip,
  so a lagging wallet reports an older height than the chain has.
- `lag` and `sync` on `/status` are derived from that cursor and the tip the sync
  loop last observed, which is served from a cache and may be stale by up to two
  sync intervals.
- `BoxStatus` is `confirmed` or `immature{maturesAtHeight}` as computed by the
  wallet store's own maturity rule, and `provenance` is the wallet's tracked-key
  classification — neither is a field the node serves.

Consequence: the diagnostic `/balance` is not comparable byte-for-byte against a
seed wallet's native `/api/v1/wallet/balance`, and a difference is not by itself
evidence of a bug. What *is* exact is the box layer: box ids and box bytes are validated
against canonical ErgoBox serialization on the way in, so a box the daemon
reports is a box it re-derived.

## Scan registry reads

The backing store supports scan registries, and the read API returns persisted
registrations. The descriptor schema accepts public keys, derivation paths and
labels, but no tracking rules. A fresh descriptor-only store therefore has no
registered scans. A watch-only daemon has no registration or mutation route.
A seed daemon serves the Scala-compatible management routes (`/scan/register`,
`/scan/deregister`, `/scan/stopTracking`, `/scan/addBox`, and the box reads),
and its registrations persist in the same store. `sync::scan_records` applies
any registry already persisted in the wallet store.

`tests/it/scan_registry_rewind.rs` registers a scan through the store's own
`put_scan` write API so the rewind path — `rewind_to_ancestor` →
`rewind_scans_from_height`, which would otherwise be reached against an initially empty registry — runs against non-empty `WALLET_SCAN_BOXES`, `WALLET_SCAN_BOX_INDEX`,
and `WALLET_SCAN_TXS`.

## Tests

| File | What it pins |
|---|---|
| `tests/it/http_client.rs` | `HttpChainClient` wire parsing and status→error mapping against a one-shot TCP responder (the `api_key` header, `410` pruning, `404`, canonical box/tip identity). |
| `tests/it/node_api.rs` | The **real** node chain API in-process: a seeded `ergo-state` `StateStore`, the real `ergo-node` `InProcessChainClient` + `WalletChainAdapter`, the real `ergo-api` `/api/v1/chain/*` router with its real `ApiSecurity` gate, driven by the real daemon client and `StandaloneSyncer` over real HTTP. Covers tip, forward/bounded/empty `blocks-since`, the genesis-cursor wire contract, the `api_key` gate (present/wrong/absent), a daemon restart against an existing database, and a real `rollback_to` + re-apply reorg the daemon rewinds and follows. Also the **paging contract on realistic blocks**: ~1.5 MiB blocks of real ErgoBoxes where a three-block page cannot fit the 8 MiB cap, so the adaptive page is refused once for size, halves, and completes the pass, and a ceiling of one block keeps the fixed one-block page. |
| `tests/it/daemon_boot.rs` | The full production startup shape — config + 0600 api-key file + descriptor file, `prepare` on a non-runtime thread, runtime + `run_until` on another — then the read API over the real Unix socket, the sync loop reaching the real node tip, the `0400`/`0600` socket mode, the empty `/scans`, the `404` write routes, and the socket-guard cleanup on shutdown. Plus the api-key permission gate and `Debug` redaction. |
| `tests/it/seed_daemon_boot.rs` | Config → real seed TCP API → authenticated real-node sync; distinct node/local credentials, locked restart with persisted addresses, mode ownership, and refusal of implicit watch/seed migration. |
| `tests/it/lifecycle.rs` | Real hosted engine through seed routes: authentication before parsing, native errors, secret response policy, lifecycle/key persistence, wrong-password budget, and unchanged default watch routes. |
| `tests/it/index_restore.rs` (with `tests/it/sim_chain.rs`) | Where the wallet starts, on a simulated chain with a real address index computed from the same blocks: `init` at the tip and no block request below it, a keyless daemon making no request, restore from the index equal to a plain block scan (balances, boxes, transaction history, tracked keys, change address), an index that lags or disagrees or a registered scan falling back to the scan, a derived key never seen / with history (backfilled, equal to a scan) / with an unusable index (invalidates) / declared fresh (no rescan), and the declared start. |
| `src/host.rs` unit tests | Locked boot/restart, atomic first-key replay reset, no-key sync pause, shared command/sync writer, bounded admission, shutdown queue rejection and panic key erasure. |
| `src/engine_chain.rs`, `src/ownership.rs` unit tests | Local lifecycle during node outage, bounded tip capability, unsupported signing/replay, mode markers and seed directory permissions. |
| `src/supervision_tests.rs` | A seed terminal failure stays parked until a key reset permits replay; idle Unix keep-alive connections close on shutdown and release redb for immediate reopen. The real seed TCP boot test also holds pooled connections across shutdown before restarting. |
| `tests/it/scan_registry_rewind.rs` | `rewind_to_ancestor` → `rewind_scans_from_height` with a **non-empty** registry: seeded `WALLET_SCAN_BOXES` / `_INDEX` / `_TXS`, the post-boundary rows removed, the pre-boundary spend restored to `Unspent`, the reverse index trimmed to the surviving box, the tx rows keyed by height, and the restored box still reachable through the index. |
| `tests/it/sync.rs` | The sync state machine against a scripted node: paging limits, the page budget bounding every request independently of the apply budget, an out-of-range page failing before the node is called, an oversized page failing closed with one request and no loop, ancestor rewind, pruned history, conflict retry, gap/duplicate/parent-mismatch terminal errors, unprogressing-rewind bound, tip publication, and the durable-write count of a caught-up pass (no `running` on an idle tick). |
| `tests/it/routes.rs` | `READ_ROUTE_INVENTORY` is the only default watch surface, and its lifecycle/signing/private-key routes are `404`. |
| `tests/it/store_reopen.rs` | The standalone store reopens with its keys, cursor, and cleared invalidation flag. |

## Invariants & contracts
- **Confirmed only, and a projection rather than a re-serve.** The wallet is fed
  by applied blocks, never by the mempool or unconfirmed headers, so every
  balance, box, and transaction read is confirmed. `/balance` reports
  `confirmed == available` and `reserved == immature == "0"`; `unconfirmed` and
  `reemission` are `null`. Seed key changes reset history for replay; seed spending uses the
  shared engine rather than these diagnostic projections. These
  are values the daemon *computes* from applied blocks — see "Known
  deviations" §1 for the exact shape.
- **Watch descriptor boundary.** The default watch mode reads public wallet data only. The descriptor file
  carries compressed public keys, derivation paths, and labels — anything else
  (a `private_key` field, a non-secp256k1 curve) is a hard parse error. The
  store keeps 33-byte pubkeys and renders base58 addresses at read time, so the
  network prefix is never baked into persistent state. Watch mode loads the
  node API credential but never constructs secret storage. Seed mode owns its
  encrypted secret directory. Both modes require a separate local API
  credential; credentials are permission-checked, redacted, compared as
  SHA-256 digests in constant time and zeroized on drop.
- **Mode ownership.** A durable `wallet-mode` marker prevents reuse between
  watch and seed modes. An unmarked database can only resume as watch-only;
  seed migration is not inferred from persisted public keys.
- **Capability-limited hosting.** Watch routes are read-only. Seed mode adds
  lifecycle/key writes through `WalletEngine`, with one gate shared with
  complete sync passes and atomic history resets on actual key additions.
  Seed routes include signing and submission through authenticated
  command-scoped adapters; watch routes remain read-only.
- **Loopback by construction.** `tcp_fallback` must be a loopback address; the
  Unix socket is created under a `0o077` umask and `chmod 0600`, with a
  `<socket>.owner` marker (`ergo-walletd-socket:<pid>:<nanos>`) so a stale
  socket is reclaimed but a live one is never stolen. Local authentication
  protects both Unix and TCP listeners in both modes; the TCP listener accepts
  only its loopback `Host` names plus `[api] allowed_hosts`.
- **Sealed at rest.** `encrypted_db` stores `wallet.redb` as AES-256-GCM
  sectors; `seal` starts the daemon without its database key and opens the
  database only when a password, passphrase or `unseal_key_file` releases it,
  encrypting a cleartext database on the way. The engine keeps multisig
  nonces in memory under single-use handles bound to their input and public
  commitment (consumed on any attempt; 1 h expiry, 4096 cap) by default;
  `[security] multisig_nonces = "caller"` opts out. It wipes them on every
  lock and, with custody on, refuses a hex nonce for any
  key not supplied in `externalSecrets` (`ergo-wallet-service`
  `engine/hints_codec.rs`).
- **Locked by default, and again.** Seed wallets restart sealed and locked; `host` locks
  them after `[security] idle_lock` without a non-`GET` operation and after
  `max_unlock`. The unlock attempt budget persists in
  `unlock-attempts.json`. `hardening` disables core dumps and ptrace before any
  credential is read.
- **Network identity is configuration.** `network` (`mainnet` | `testnet`,
  default `mainnet`, any other value rejected) is threaded into descriptor
  validation and into every address this API renders. The daemon cannot infer
  the node's network, so a mismatch with `node_url` renders addresses the node's
  network will not decode.
- **Fail-closed sync.** A page that breaks height, parent, or duplicate
  invariants, an ancestor that does not rewind, and a second reorg deeper than
  retained history after a full rebuild are terminal: the durable rescan state
  becomes `failed`; syncing pauses and the authenticated read API stays
  available. The seed worker compares committed tracked-key rows under
  the writer gate while parked; an actual key change permits replay without
  restarting, even if recording the failure metadata had failed.
  The watch worker stops on terminal failure. A sync-worker panic stops the daemon. A reorg that *does* rewind is a warn and
  a continue — the old fixed "8 rebuilds per batch" cap is gone. Terminal and
  retryable failures log at `error`/`warn` with locally generated text only.
- **Bounded reads.** `/status` never blocks on an unbounded node request: it
  serves the tip the sync loop last observed and only probes when that
  observation is older than two sync intervals, with a 2 s probe ceiling.
- **Bounded requests.** One `blocks-since` page is at most `blocks_page` blocks
  (default 1) and at most 16 MiB of body, whichever bites first. The apply budget
  (`sync_batch`) never sizes a request. A page over the byte cap is a single
  terminal error naming the cap and the page — never a smaller-page retry and
  never a loop. See "Two sync budgets".
- **Idle ticks do not write.** A pass publishes `running` only after it knows it
  has work, i.e. below the at-tip check, so a caught-up daemon costs the single
  `idle` write per tick instead of `running` followed by `idle`.

A pass that exhausts its block budget continues immediately. Completed passes,
seed passes with no keys, and retryable errors wait for `sync_interval`;
terminal errors suspend syncing while `/status` remains available. Seed workers
remain parked until committed tracked-key rows change.
`shutdown_timeout_secs` (default 5) bounds shutdown waiting, with cancellation
checked between blocks, retries, and HTTP requests. An in-flight blocking HTTP
request may finish after this deadline, but cancellation prevents subsequent
block application. Seed admission closes before cancellation, queued commands
are rejected, and the hosted engine locks after work holding its writer drains.
Listener shutdown closes idle TCP connections and drains the Unix listener's
owned connection set before releasing the database for restart.
