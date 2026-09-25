# ergo-walletd

**Purpose:** The standalone watch-only Ergo wallet daemon. It is a separate
process from the node: it owns its own redb wallet database, pulls chain data
over the node's `/api/v1/chain/*` HTTP surface, and serves a **read-only** local
HTTP API. It never holds a secret key, never signs, never submits, and has no
route that can spend.

**Depends on (workspace):** `ergo-wallet`, `ergo-wallet-service`,
`ergo-wallet-protocol`, `ergo-primitives`, `ergo-ser`
**Normal dependency boundary:** the five workspace crates above plus `axum`,
`hyper`, `hyper-util`, `tower`, `clap`, `hex`, `libc`, `reqwest`, `serde`,
`serde_json`, `thiserror`, `tokio`, `toml`, `tracing`, and
`tracing-subscriber`. It deliberately does **not** depend on `ergo-node`,
`ergo-api`, `ergo-state`, `ergo-mempool`, `ergo-sync`, or `ergo-chain-spec`: the
daemon talks to a node over HTTP, not through the node's internals. Network
identity is therefore a *config* value (`config::Network`) mapped to
`ergo_ser::address::NetworkPrefix`, not a chain-spec lookup.
**Test-only dependency boundary:** `ergo-node`, `ergo-api`, `ergo-state` (with
`test-helpers`), `ergo-validation` (with `test-helpers`), `parking_lot`,
`redb`, and `bincode` are `[dev-dependencies]` **only**. `ergo-node`,
`ergo-api`, and `ergo-state` exist so `tests/it/node_api.rs` and
`tests/it/daemon_boot.rs` can stand up the *real* node chain API in-process — a
real `StateStore`, the real `InProcessChainClient` + `WalletChainAdapter`, the
real `ergo-api` router with its real `api_key` gate — and drive the real daemon
client and sync loop over real HTTP against it, instead of a hand-rolled stub.
`ergo-validation` and `parking_lot` exist only for `tests/it/shadow.rs`, which
has to build a real `CheckedBlock` for the production `StateStore::apply_block`
and a real `ergo-node` `WalletStateHook` (see "The embedded-vs-daemon shadow
harness"). They never enter the released binary's dependency graph;
`Cargo.toml` carries the same note per dependency.
**Depended on by:** nothing in the workspace (it is a leaf binary)
**Approx LOC:** ~4.8K (`src/**/*.rs`) plus ~6.2K of integration tests

## Start here
- `src/main.rs` — process entry. **Blocking first, async second**: load the
  config, call `prepare`, *then* build the runtime and `block_on(run(..))`. The
  split is load-bearing, not stylistic — see "Startup is two phases" below.
- `src/lib.rs` — `prepare` (blocking: open the store, import descriptors, build
  the blocking chain client, wire the syncer/tip) and `run` / `run_until` (async:
  bind the listeners, supervise the blocking sync loop and the join set).
- `src/config.rs:26` — `Network`, `FileConfig`, `Cli`, `Config`, and
  `read_api_key` (the API-key file permission gate).
- `src/descriptor.rs:68` — `parse_file` / `parse_text` / `import`: the
  no-secret descriptor boundary.
- `src/sync.rs:106` — `StandaloneSyncer` / `sync_once`: the forward/reorg/pruned
  state machine that drives the wallet cursor. `batch` is the per-pass **apply**
  budget and `page` is the per-request **page** budget; see "Two sync budgets".
- `src/chain_http.rs:55` — `HttpChainClient`: the node HTTP adapter and its
  response neutralisation/validation, the 8 MiB body cap, and the
  `new_in_runtime` / `with_timeouts_in_runtime` constructors for async callers.
- `src/api.rs:32` — `ApiContext` and the read-only router.
- `src/tip.rs:32` — `CachedNodeTip`: the last-observed node tip shared between
  the sync loop and `/status`.
- `src/socket.rs:27` — `UnixSocketGuard` / `bind_restricted`: socket ownership
  marker and owner-only permissions.

## Modules
- `src/config.rs` — TOML/CLI schema, validation, and the secret-adjacent file
  policy (API-key file must not be group/other readable; key never logged).
- `src/descriptor.rs` — descriptor parsing/validation and idempotent import
  into the wallet's tracked-pubkey tables.
- `src/sync.rs` — bounded rescan/forward sync, reorg rewind and rebuild,
  retries, and durable rescan-state failure recording. `SyncConfig::batch` is
  the apply budget and `SyncConfig::page` the per-request page budget; see "Two
  sync budgets".
- `src/chain_http.rs` — blocking `reqwest` client for
  `api/v1/chain/{tip,snapshot,blocks-since,boxes/:id}` with body-size caps,
  timeouts, and status-code → typed-error mapping. Its response validation is
  bounded by what the wire can prove — see "Known deviations" §1.
- `src/api.rs` — axum router, read handlers, DTO projection.
- `src/socket.rs` (unix) — Unix-socket claim/cleanup and `0o600` permissions.
- `src/tip.rs` — node-tip cache with a capped fallback probe.

## Key types, traits & functions
- `config::Config`, `config::FileConfig`, `config::Cli`, `config::Network`,
  `config::ApiKey` — the operator surface.
- `descriptor::DescriptorEntry`, `descriptor::ImportReport`,
  `descriptor::parse_file`, `descriptor::import` — descriptor boundary.
- `sync::StandaloneSyncer`, `sync::SyncConfig`, `sync::SyncReport`,
  `sync::SyncError` — sync engine. `sync::DEFAULT_BLOCKS_PER_PAGE` is the shipped
  per-request page size; `sync::MAX_SYNC_BLOCKS` bounds both knobs.
- `chain_http::MAX_RESPONSE_BODY_BYTES` — the 8 MiB cap that bounds a page.
- `chain_http::HttpChainClient` — the only place a node URL is used.
- `api::ApiContext`, `api::router`, `api::READ_ROUTE_INVENTORY` — the read-only
  API and its test-pinned route list.
- `tip::CachedNodeTip`, `tip::PROBE_TIMEOUT` — `/status` tip source.

## The local read API

Every route is a `GET`; each is mounted twice, at a short path and under
`/api/v1/wallet/*`. `READ_ROUTE_INVENTORY` is the pinned list and is asserted by
`tests/it/routes.rs`, which also asserts that wallet lifecycle, signing, and
private-key routes return `404`.

| Route | Response |
|---|---|
| `/status`, `/api/v1/wallet/status` | `WatchOnlyWalletStatusDto`: durable scan cursor (height + header id), node tip, derived `lag`, `scanInvalidated`, rescan state, sync state |
| `/balance`, `/balances`, `/api/v1/wallet/balance[s]` | `WalletBalanceDto` — confirmed only |
| `/boxes`, `/boxes/:id`, `/api/v1/wallet/boxes[/:id]` | `BoxPage` / `WalletBoxSummary` — confirmed only |
| `/transactions`, `/transactions/:id`, `/api/v1/wallet/transactions[/:id]` | `TxPage` / `WalletTransactionSummary` |
| `/addresses`, `/api/v1/wallet/addresses` | `AddressPage` of `WalletAddressDto` |
| `/scans`, `/scan/listAll`, `/api/v1/scans`, `/api/v1/scan/listAll` | `Vec<ScanDto>` — always `[]`; see "No scan registry" |

`offset` (default 0) and `limit` (default 50, max 16384) are the only query
parameters; anything else is a `400`.

## Startup is two phases

`reqwest`'s blocking client owns a private Tokio runtime, created and dropped
inside `ClientBuilder::build`. Tokio aborts when a runtime is dropped on a thread
that is inside an async context, and `reqwest` drops a *shell* runtime while it
is entered in exactly that case, so building the client from an `async fn` (or
under `#[tokio::main]`) **panics before the daemon's first log line** in a
`debug_assertions` build. `main` therefore does all blocking work in
`prepare` — store open, descriptor import, `HttpChainClient::new` — and only
then constructs the runtime and enters `run`. Nothing in `run` can construct a
client: it takes a `Daemon`, not a `LoadedConfig`.

For an embedder (or a `#[tokio::test]`) that is already inside a runtime,
`HttpChainClient::new_in_runtime` hands the build to the runtime's blocking
pool, which is not an async context, and moves the finished client back. There
is deliberately **no** runtime check inside `with_timeouts`: `Handle::try_current()`
is `Ok` on a blocking-pool thread (where the build is safe) as well as on an
entered worker (where it panics), so a check built on it would reject the one
context that works. The invariant is documented, enforced structurally by
`main`, and exercised end-to-end by `tests/it/daemon_boot.rs`.

`run_until(daemon, shutdown)` is `run` with the shutdown trigger injected
(`run` passes SIGINT/SIGTERM). Only the tests use it — signalling the harness
would take it down too — and it is the same supervision path, so the test
exercises the production one.

## Two sync budgets

`SyncConfig` has two independent counters and they must not be conflated:

- **`batch` (`sync_batch`)** — the maximum number of blocks *applied* by one
  `sync_once`. It is the pass's work budget and bounds how much the wallet
  database can change before the loop returns.
- **`page` (`blocks_page`, default `DEFAULT_BLOCKS_PER_PAGE` = 1)** — the maximum
  number of blocks asked for in a single `blocks-since` call. It is the
  *request* budget, and it is what bounds one response body.

Every request is `min(remaining, page, batch - processed)`. A pass with
`batch = 256` and `page = 1` reaches the tip through up to 256 requests.

The default of 1 is sized against `chain_http::MAX_RESPONSE_BODY_BYTES` (8 MiB),
not picked for throughput. The chain protocol carries every output box as a hex
string, so a page's JSON body costs roughly twice the serialized bytes of the
blocks in it, and consensus bounds one block's `BlockTransactions` section by
the voted `maxBlockSize` parameter. Measured against the largest `maxBlockSize`
this repo documents an operator voting for (2 MiB in `docs/configuration.md`),
one maxed-out block is already 4 MiB of hex, so a page of `1` provably fits with
more than half the cap spare while a page of `2` reaches 8 MiB *before* any JSON
envelope. Today's mainnet parameter is smaller, so the default is deliberately
conservative; `blocks_page` remains configurable and raising it is a per-node
decision. The earlier behaviour — sizing the request from the apply budget,
`min(batch, remaining)` — could ask for up to 1024 blocks and hit the cap on any
real chain, which is a permanent sync failure, not a slow one.

A block too large even for a one-block page is not retried smaller: the daemon
never shrinks a page, so `chain_http::read_page` reports it once as a terminal
error naming both the cap and the page size, and `map_chain_error` keeps it out
of the retry path. `tests/it/node_api.rs` drives that against the real node API
with ~1.5 MiB blocks, in both directions: bounded page ⇒ completed pass,
unbounded page ⇒ one request and the named bounded error.
`tests/it/sync.rs` pins the worst-case arithmetic above against the real cap
constant.

## Known deviations

These are real gaps in what this daemon can verify or report. They are not
hidden behind a passing test suite.

### 1. A block's protocol id is not recomputed from raw header bytes

The chain protocol carries structured block, transaction, and box fields but
**no raw header bytes**. A block's `block_id` is therefore taken from the node
and checked for *consistency*, not *recomputed*: parent linkage against the
wallet cursor, height contiguity, uniqueness within a page, and agreement with
the reported tip. `chain_http::neutral_block` never hashes a header, so a node
that reports a wrong `blockId` for a block whose bytes this build never sees is
**not** caught at this layer.

What *is* recomputed: every `ErgoBox` — canonical parse, re-serialization
equality, `box_id`, embedded `transaction_id`, output index, value, assets, and
creation height (`chain_http::neutral_block` / `WalletService::convert_block`).
Transaction ids are cross-checked against the ids embedded in their own output
boxes, but likewise cannot be recomputed from raw transaction bytes.

Closing this needs raw header bytes on the chain protocol (a node-side change),
not a client change. Until then, the block-identity trust boundary is the node's
API key: whoever holds it can serve a chain the daemon will accept, subject to
the continuity and box-level checks above.

### 2. Balance and status values are confirmed-only, not byte-identical to the
### embedded values

Every read route is a **projection the daemon computes from blocks it has
applied**. The values it returns are not the node's embedded values re-served
verbatim, and the differences are visible in the DTOs:

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

Consequence: the daemon's `/balance` is not comparable byte-for-byte against the
embedded wallet's `/wallet/balance`, and a difference is not by itself evidence
of a bug. What *is* exact is the box layer: box ids and box bytes are validated
against canonical ErgoBox serialization on the way in, so a box the daemon
reports is a box it re-derived.

## No scan registry

`WalletService`'s backing store implements the node's `/scan/*` registry, and
`sync::scan_records` feeds it whenever `WalletScanMatcher::registry()` is
non-empty. The daemon's *only* input for that registry is the descriptor file,
whose strict schema admits public keys, derivation paths, and labels — no
tracking rule. So the registry is always empty in production: `/scans` returns
`[]` and `WALLET_SCAN_BOXES` / `_INDEX` / `_TXS` are never written. Scan
registration stays a node capability; a tracking rule is a predicate over
arbitrary box contents, a different trust decision from "watch these public
keys".

`tests/it/scan_registry_rewind.rs` registers a scan through the store's own
`put_scan` write API so the rewind path — `rewind_to_ancestor` →
`rewind_scans_from_height`, which is otherwise only ever reached against empty
tables — runs against non-empty `WALLET_SCAN_BOXES`, `WALLET_SCAN_BOX_INDEX`,
and `WALLET_SCAN_TXS`.

## Tests

| File | What it pins |
|---|---|
| `tests/it/http_client.rs` | `HttpChainClient` wire parsing and status→error mapping against a one-shot TCP responder (the `api_key` header, `410` pruning, `404`, canonical box/tip identity). |
| `tests/it/node_api.rs` | The **real** node chain API in-process: a seeded `ergo-state` `StateStore`, the real `ergo-node` `InProcessChainClient` + `WalletChainAdapter`, the real `ergo-api` `/api/v1/chain/*` router with its real `ApiSecurity` gate, driven by the real daemon client and `StandaloneSyncer` over real HTTP. Covers tip, forward/bounded/empty `blocks-since`, the genesis-cursor wire contract, the `api_key` gate (present/wrong/absent), a daemon restart against an existing database, and a real `rollback_to` + re-apply reorg the daemon rewinds and follows. Also the **paging contract on realistic blocks**: ~1.5 MiB blocks of real ErgoBoxes where a three-block page cannot fit the 8 MiB cap, so the default one-block page completes the pass and an unbounded page fails closed on the first response. |
| `tests/it/daemon_boot.rs` | The full production startup shape — config + 0600 api-key file + descriptor file, `prepare` on a non-runtime thread, runtime + `run_until` on another — then the read API over the real Unix socket, the sync loop reaching the real node tip, the `0400`/`0600` socket mode, the empty `/scans`, the `404` write routes, and the socket-guard cleanup on shutdown. Plus the api-key permission gate and `Debug` redaction. |
| `tests/it/scan_registry_rewind.rs` | `rewind_to_ancestor` → `rewind_scans_from_height` with a **non-empty** registry: seeded `WALLET_SCAN_BOXES` / `_INDEX` / `_TXS`, the post-boundary rows removed, the pre-boundary spend restored to `Unspent`, the reverse index trimmed to the surviving box, the tx rows keyed by height, and the restored box still reachable through the index. |
| `tests/it/sync.rs` | The sync state machine against a scripted node: paging limits, the page budget bounding every request independently of the apply budget, an out-of-range page failing before the node is called, an oversized page failing closed with one request and no loop, ancestor rewind, pruned history, conflict retry, gap/duplicate/parent-mismatch terminal errors, unprogressing-rewind bound, tip publication, and the durable-write count of a caught-up pass (no `running` on an idle tick). |
| `tests/it/routes.rs` | `READ_ROUTE_INVENTORY` is the only mounted surface, and every lifecycle/signing/private-key route is `404`. |
| `tests/it/store_reopen.rs` | The standalone store reopens with its keys, cursor, and cleared invalidation flag. |
| `tests/it/shadow.rs` | The **shadow harness** (see its own section below): embedded vs daemon over the same blocks, plus the cheap negative controls that keep the comparison honest. Its five scenarios are `#[ignore]`d — run with `scripts/shadow-compare.sh` or the `wallet-shadow` CI job. |

## The embedded-vs-daemon shadow harness

Phase 2 moved the wallet core out of the node into `ergo-wallet-service`, so
the node and this daemon now reach the same tables by two different routes:

- **Embedded** — the node's `StateStore` redb *is* the wallet database, and
  the chain-apply seam writes the wallet tables inside the same redb write
  transaction as the UTXO mutation.
- **Daemon** — a separate `RedbWalletStore` fed by blocks pulled from the
  node's `/api/v1/chain/*` over HTTP, applied by `StandaloneSyncer`.

`tests/it/shadow.rs` runs both against the same blocks and compares the
**normalized `WalletRead` state** of the two stores. It does **not** compare
daemon DTOs: `/balance`'s `reserved == "0"` and `/status`'s cached tip are
documented projections ("Known deviations" §2), so comparing them would report
differences that are not divergences. Both sides write their state through the
same service functions, so the persisted result *is* comparable.

**What is compared**, field by field, with a rendered diff that names the field
that moved: cursor identity (height *and* header id), committed tip, balances,
every box (id, creation tx/index/height, value, assets, status incl.
`Immature { matures_at }` and spend attribution, provenance), the unspent
subset separately, wallet transactions, the scan registry (rows, last-used id,
count), scan boxes and scan transactions when a scan is seeded, tracked keys
with full metadata, visible keys, derivation head, change address, the
`scan_invalidated` flag, and the EIP-3 reward-key resolution (including the
`Pending` / `Corrupt` discrimination). Every collection is sorted by a total
order at capture, so a diff can only mean "a value differs".

**Both paths are real.** The embedded side uses the production
`StateStore::apply_block` with the production `ergo-node` `WalletStateHook`
(hydrated from the store's own `WALLET_TRACKED_PUBKEYS`), so the wallet apply
is the atomic in-txn one, and `StateStore::rollback_to` with the real
`ProdRescanGuard` for the reorg. The daemon side uses the real
`StandaloneSyncer` over the real `HttpChainClient` against the real `ergo-api`
router with its real `ApiSecurity` gate and real `Governor`, backed by that
same `StateStore` through ergo-node's real `InProcessChainClient` +
`WalletChainAdapter`. Blocks are applied one at a time and the daemon catches
up after each, which is the deployment shape.

**Scenarios** (all `#[ignore]`d, so the default nextest job never pays for
them):

| Name | What it pins |
|---|---|
| `shadow_sweep_digest_1_1000_agrees_embedded_and_daemon` | The headline: real mainnet blocks 1..=1000 from `test-vectors`, every height's state root asserted against the captured one, and both sides compared at **every** applied height — not only at the tip, because the divergences worth catching are transient (a status the next block promotes, a box only one side re-adds, a flag the next pass reconciles) and a tip-only comparison would report "agree" for a wallet that never agreed. The box floor is carried forward across heights, so a comparison that quietly went empty fails at the height it went empty. Also asserts a real `MinerReward` box and at least one `Immature` box exist, so the maturity comparison is not vacuous. |
| `shadow_synthetic_smoke_agrees_embedded_and_daemon` | A harness-built chain where every classification branch is reachable deterministically: `Owned`/`Confirmed`, `MinerReward`/`Immature`, a spend, a token-bearing box, a box paid to an untracked key (both paths must ignore it), and a seeded scan so `WALLET_SCAN_BOXES`/`_INDEX`/`_TXS` are non-empty on both sides. |
| `shadow_reorg_rewinds_and_reapplies_on_both_sides` | A real fork: the node rolls back with its own `rollback_to` and re-derives the fork with a different solution nonce (so genuinely different block ids); the daemon must take the node's `Ancestor` answer, rewind, and follow. Compared before the reorg and after both sides follow the fork. |
| `shadow_survives_a_node_and_daemon_restart` | Both redb databases are closed and re-opened — the node's `StateStore` and the daemon's `RedbWalletStore` — and the node's served API is torn down and rebuilt. Asserts neither the chain height nor either durable cursor moved, and that a caught-up pass completes having applied **zero** blocks: a restart that silently replayed the chain would be a rescan wearing a restart's clothes. |
| `shadow_daemon_rescan_from_zero_reproduces_the_embedded_state` | The durable `scan_invalidated` flag is set (what a rescan request and every fail-closed fence leave behind) and the next real pass rebuilds the whole wallet from genesis over HTTP, clearing the flag, landing on exactly the state the embedded side reached incrementally. |

**Two harness constraints worth knowing about, both discovered by making the
scenarios fail loudly rather than quietly:**

- *The daemon must not be polled mid-reorg.* `StandaloneSyncer` treats a
  durable cursor **above** the node's reported tip as a terminal
  `SyncError::Protocol` ("wallet cursor N is ahead of node tip M"), not as a
  rewind. A node that has rolled back but not yet re-applied presents exactly
  that state, so the reorg scenario advances the node to the same height before
  the daemon looks again. That is also true in production, where a node's
  rollback and re-apply happen inside one action-loop turn — but it means a
  daemon pointed at a node that is *mid-reorg* stops rather than waits.
- *A restart has to release every handle.* redb takes an exclusive `flock` on
  the file, so a close/re-open only succeeds once the last `Arc<Database>` is
  dropped. The harness's `EmbeddedFiles` and `DaemonSide::store` are both held
  behind an `Option` for exactly this: the node's served API (whose
  `ChainStoreReader` holds the same `Arc<Database>`) has to be torn down before
  the store can be re-opened. Getting this wrong is a
  `DatabaseAlreadyOpen`, not a silent no-op.

**The comparator is itself tested.** Two cheap, non-`#[ignore]`d tests keep the
suite from being self-congratulatory:
`shadow_comparator_detects_an_injected_divergence_in_every_compared_field`
mutates one field at a time and requires the diff to be non-empty *and* to name
that field, and
`shadow_comparator_rejects_a_vacuous_zero_box_comparison` proves the
non-zero-box floor fires. Every scenario also passes a minimum box count, so a
harness that tracked nothing would fail rather than pass for the wrong reason.

The sweep carries a third, in-band regression: at height 100 it injects a real
durable divergence (the daemon-side `scan_invalidated` flag) and requires the
comparison *at that height* to reject it and name the field. The flag is exactly
the transient case a tip-only sweep cannot see — the very next sync pass
rebuilds from genesis and clears it — so a sweep without per-height comparison
would finish green. The scenario then continues to 1000, which also proves the
reconciling rescan lands back on the embedded side's state rather than papering
over the injection.

**Running it:**

```
scripts/shadow-compare.sh            # cheap negative controls only (seconds)
scripts/shadow-compare.sh --all      # controls + all five slow scenarios
scripts/shadow-compare.sh sweep      # one named scenario
scripts/shadow-compare.sh --list     # scenario name -> test name
```

The script redirects `CARGO_TARGET_DIR` and `TMPDIR` into `.shadow-target/`
unless the caller already set `CARGO_TARGET_DIR`: the harness links the
`ergo-node` + `ergo-api` + `ergo-state` test binary, and sharing the normal
target dir would evict (or be evicted by) the developer's build cache. The
directory is removed on success; `SHADOW_KEEP=1` retains it. CI runs the same
command in the separate `wallet-shadow` job, which is deliberately **not** part
of the `check` matrix and does not touch
`scripts/ci-shards.py`'s crate-group ledger — the scenarios live inside the
existing `it` target precisely so shard coverage is unchanged. That job sets
`CARGO_TARGET_DIR` (and `SHADOW_KEEP=1`) at job level, *above* its
`Swatinem/rust-cache` step and to the same path the script would have chosen:
the script only claims the variable when the caller left it unset, and
`rust-cache` keys and restores on the target dir cargo really used, so a
`rust-cache` that warmed the default `./target` would be a cache the run could
never hit. `TMPDIR` is deliberately left to the script — it has no bearing on
what is cached, and a job-level `TMPDIR` would point at a directory that does
not exist until the script creates it.

**One deviation from `tests/it/node_api.rs`, and why.** The shadow harness
serves the router through `into_make_service_with_connect_info::<SocketAddr>()`
(the shape `ergo_api::server` uses) rather than a bare `axum::serve`. Without
`ConnectInfo` the `Governor` cannot read the peer IP, so every caller is
bucketed under one shared "unknown" key; a sweep's thousands of `blocks-since`
calls then get throttled into 429s that have nothing to do with wallet
behaviour. With it, a loopback daemon is exempt on a direct bind — the
production posture. `node_api.rs` makes a handful of requests, so it never
reached the limiter and needs no change.

## Invariants & contracts
- **Confirmed only, and a projection rather than a re-serve.** The wallet is fed
  by applied blocks, never by the mempool or unconfirmed headers, so every
  balance, box, and transaction read is confirmed. `/balance` reports
  `confirmed == available` and `reserved == immature == "0"`; `unconfirmed` and
  `reemission` are `null`. There is no route that can change a balance. These
  are values the daemon *computes* from applied blocks, not the embedded wallet's
  values re-served verbatim — see "Known deviations" §2 for the exact
  differences and what they mean for comparison against an embedded wallet.
- **No-secret boundary.** The daemon reads public data only. The descriptor file
  carries compressed public keys, derivation paths, and labels — anything else
  (a `private_key` field, a non-secp256k1 curve) is a hard parse error. The
  store keeps 33-byte pubkeys and renders base58 addresses at read time, so the
  network prefix is never baked into persistent state. The only secret-adjacent
  file is the *node* API key, which is read from disk with a permission check
  (rejecting group/other-readable files), held in a `Debug`-redacted `ApiKey`,
  sent only as a request header, and never logged.
- **Read-only.** No route mutates wallet state, and `HttpChainClient::submit`
  returns `ChainClientError::Unsupported`. The daemon cannot spend, sign, or
  unlock anything.
- **Loopback by construction.** `tcp_fallback` must be a loopback address; the
  Unix socket is created under a `0o077` umask and `chmod 0600`, with a
  `<socket>.owner` marker (`ergo-walletd-socket:<pid>:<nanos>`) so a stale
  socket is reclaimed but a live one is never stolen.
- **Network identity is configuration.** `network` (`mainnet` | `testnet`,
  default `mainnet`, any other value rejected) is threaded into descriptor
  validation and into every address this API renders. The daemon cannot infer
  the node's network, so a mismatch with `node_url` renders addresses the node's
  network will not decode.
- **Fail-closed sync.** A page that breaks height, parent, or duplicate
  invariants, an ancestor that does not rewind, and a second reorg deeper than
  retained history after a full rebuild are terminal: the durable rescan state
  becomes `failed` and the daemon exits. A reorg that *does* rewind is a warn and
  a continue — the old fixed "8 rebuilds per batch" cap is gone. Terminal and
  retryable failures log at `error`/`warn` with locally generated text only.
- **Bounded reads.** `/status` never blocks on an unbounded node request: it
  serves the tip the sync loop last observed and only probes when that
  observation is older than two sync intervals, with a 2 s probe ceiling.
- **Bounded requests.** One `blocks-since` page is at most `blocks_page` blocks
  (default 1) and at most 8 MiB of body, whichever bites first. The apply budget
  (`sync_batch`) never sizes a request. A page over the byte cap is a single
  terminal error naming the cap and the page — never a smaller-page retry and
  never a loop. See "Two sync budgets".
- **Idle ticks do not write.** A pass publishes `running` only after it knows it
  has work, i.e. below the at-tip check, so a caught-up daemon costs the single
  `idle` write per tick instead of `running` followed by `idle`.
