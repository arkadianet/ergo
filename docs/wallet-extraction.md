# Wallet extraction

Phase 2 extracts the shared wallet implementation and proves a standalone
watch-only daemon against the embedded wallet. Phase 1 landed in main through
[#381](https://github.com/arkadianet/ergo/pull/381). All seven Phase 2 items
landed on `integration/wallet-extraction`; [#574](https://github.com/arkadianet/ergo/pull/574)
completed their refresh and validation. The subsequent main merge carries the
0.12.3 node changes across the extracted boundaries in
[#618](https://github.com/arkadianet/ergo/pull/618). Phase 3 is complete on the
integration branch: [#619](https://github.com/arkadianet/ergo/pull/619) added
the seed lifecycle host and [#620](https://github.com/arkadianet/ergo/pull/620)
completed the daemon engine, migration, packaging and portable library work.
Seed ownership remains opt-in and the embedded node remains the default.
These are the three documented extraction phases; promoting the integration
branch to main and choosing a release/cutover are subsequent delivery work.

## Phase 2 milestones

| Item | Result | Original PR |
|---|---|---|
| 1 | Wallet-store and reward-key boundaries; explicit embedded/external ownership | [#394](https://github.com/arkadianet/ergo/pull/394) |
| 2 | Protocol and service crates; wallet persistence and chain runtime relocation | [#400](https://github.com/arkadianet/ergo/pull/400) |
| 3 | Published committed-chain endpoints for external wallets | [#401](https://github.com/arkadianet/ergo/pull/401) |
| 4 | Standalone watch-only daemon with its own database and local read API | [#403](https://github.com/arkadianet/ergo/pull/403) |
| 5 | Embedded/daemon shadow comparison, reorg, restart and rescan coverage | [#404](https://github.com/arkadianet/ergo/pull/404) |
| 6 | Header identity authentication using the original serialized header bytes | [#415](https://github.com/arkadianet/ergo/pull/415) |
| 7 | Shared `WalletEngine` for lifecycle, reads, construction, signing, sending, keys, scans and rescans | [#416](https://github.com/arkadianet/ergo/pull/416) |

## Ownership and behavior

- `ergo-wallet-protocol` owns transport-neutral DTOs and wallet error mappings.
  Its normal dependency graph has no node, storage or executor dependency.
- `ergo-wallet-service` owns the wallet engine, stores, scan/sync implementation,
  persistence and operation coordination. Pure selection and construction
  live in `ergo-wallet` with service compatibility exports. Chain snapshots, coherent mempool
  overlays and transaction submission enter through capability traits. The
  service's normal graph has no `ergo-node`, `ergo-state`, `ergo-api`,
  `ergo-mempool` or Tokio dependency.
- `ergo-node` embeds the engine through a serialized command adapter, committed
  chain views and supervised wallet/rescan workers. Embedded wallet rows still
  co-commit with chain rows in the same `state.redb` transaction.
- `ergo-walletd` owns a separate `wallet.redb`, resumes from a durable cursor,
  and defaults to an authenticated watch-only local read API. Opt-in seed mode hosts
  `WalletEngine` for lifecycle, selection, construction, signing, sending,
  scans, rescans and finite private mining jobs through an authenticated API. Both modes authenticate header identity and box
  IDs, check every header's proof of work and bind every block's transactions
  to its header, while trusting the node for chain selection and difficulty.
  Watch reads and short diagnostic projections remain confirmed-only. Seed
  routes use the shared engine and coherently captured node/pool state.

`[wallet] mode = "embedded"` remains the default. External mode skips embedded
wallet boot, secrets, writer and apply hooks. Privileged wallet routes require
a configured API key before returning `410 wallet_moved` with the configured
daemon address. Public wallet UI/watch routes retain their public ownership
guidance. The node does not proxy requests. Mining in external mode requires
a pinned reward public key.

The refresh retains main's rescan ownership and cancellation guarantees,
atomic cache hydration, tracked-key/master checks, path visibility and
derivation-counter fixes, native register/mint/burn/eligibility support, and
coherent selection/signing snapshots. The 0.12.3 refresh also retains durable
private mining jobs, scoped API credentials, offline current-UTXO discovery,
and pruned restore invalidation. The service owns job preparation and durable
records; the node supplies private queue access and bounded background RPCs.
Discovery retains its anchor and incomplete-history metadata without inventing
historical inclusion heights. It uses the current workspace toolchain
and dependency lock. Legacy redb files require the existing offline copy
migration; this file-format migration is separate from the explicit
embedded-to-daemon wallet cutover below.

## Completion checks

Phase 2 and Phase 3 completion require the workspace formatting/fragment checks,
all-target/all-feature Clippy, workspace tests and doctests, strict rustdoc,
dependency-boundary checks and CI shard coverage. The dedicated shadow gate is
`scripts/shadow-compare.sh --all`: both negative controls plus the synthetic,
reorg, node/daemon restart, rescan and mainnet 1–1000 scenarios must run.

## Phase 3: daemon engine hosting

`mode = "watch_only"` remains the daemon default. Seed hosting is explicit:
use `mode = "seed"`, a fresh separate data directory, no `descriptor_file`,
and two different protected credentials. `api_key_file` authenticates outbound
node requests; `local_api_key_file` authenticates local wallet operations.
An outbound scoped node credential needs `wallet` and, for private mining jobs,
`operator`. An `admin` credential or the legacy master key also authorizes these
requests.
Seed wallets restart locked. Persisted public keys continue syncing while locked.
The durable `wallet-mode` and `wallet-network` markers prevent incompatible
ownership and network changes.

The seed daemon serves the shared native `/api/v1/wallet/*` operations, Scala
`/wallet/*` and `/scan/*` adapters, native scan/watch-account routes, and wallet
private-queue operations. These include selection, build, sign, signed or
intent send, reward sweeps, key management, scan management, full/partial
rescan, multisig commitments/hints and durable private mining jobs. The separate
`/status` diagnostic projection reports cursor, tip, lag and sync failures;
`/api/v1/wallet/status` uses the shared engine's native status schema and a
refreshed node context for pruning and EIP-27 flags. It returns a typed
`node_unavailable` error when that context cannot be obtained.
`/api/v1/wallet/lifecycle/status` returns local `{initialized, locked}` flags
without requiring a reachable node. Private-key export retains its disabled
operator default.

Every seed API request requires exactly one local `api_key` header, on both
Unix sockets and loopback TCP. Authentication precedes parsing. Secret bodies
are limited to 16 KiB; transaction and scan bodies are bounded separately at
8 MiB. Responses use the appropriate native or Scala error envelope, with
internal details withheld and `Cache-Control: no-store`. The engine retains
password/mnemonic attempt budgets. Public static wallet UI assets use CSP and
no-store; the browser enters a separate daemon credential, never the node key.

Spending commands refresh one versioned authenticated node context under the
wallet writer. It contains committed header bytes and original header IDs,
adopted validation settings, complete protocol and re-emission parameters,
relay limits and pruning/history availability, a coherent immutable mempool
publication, and private-queue reservations with their revision. Responses are
bounded and validated before entering the engine; failures cannot become an
empty pool or default consensus settings. UTXO lookups and admission retain the
committed-tip guard. Node admission remains responsible for current conflicts;
a context does not reserve inputs against concurrent external transactions.
The preheader's provenance is explicit: a deterministic next-block estimate
cannot promise the timestamp/miner fields of a future mined block.

Lifecycle, public-key writes, sync and spending share one engine writer.
Actual key additions reset history atomically. Rescan claims its fence under
that writer, suspends normal public-state mutations and sync, and owns a
supervised cancellable replay. `/status` and local lifecycle status remain
available. An explicit rescan also unparks a terminal sync failure. Mining jobs
recover their durable journal on boot and poll through the same writer; exact
signed bytes are persisted before private admission and retried idempotently.
Shutdown closes admission, cancels replay, stops listeners/workers and erases
unlocked secrets after admitted commands drain.

### Migration and rollback

Stop the embedded node and retain a complete backup. If its database uses an
old redb format, first run the existing `ergo-node migrate-redb` copy migration.
Upgrade the embedded wallet application schema with the current node before
cutover. Before stopping, cancel queued wallet jobs and withdraw their private
transactions through the wallet/node APIs. Mined and conflicted job records
with a transaction ID still belong to the scheduler because they follow that
transaction through chain reorganizations. Default migration refuses these
retained records as well as unfinished jobs.

```sh
ergo-walletd migrate --source-data-dir /path/to/node-data \
  --destination /path/to/new-wallet-data --network mainnet
```

If reviewed job records still retain scheduler ownership, explicitly quarantine
the journal in the private migration copy:

```sh
ergo-walletd migrate --source-data-dir /path/to/node-data \
  --destination /path/to/new-wallet-data --network mainnet \
  --quarantine-mining-jobs
```

This preserves every complete job record and its signed bytes in
`wallet_mining_jobs_quarantined_v1`, retains the next job ID, and leaves the
destination's active journal empty. The report records the quarantine count.
The original database remains byte-for-byte unchanged. The flag does not
withdraw or copy the node's private queue: queued transactions can still run
when mining is enabled, so cancel unwanted entries before stopping the node.
The daemon's builder continues to exclude the node's reserved private inputs.

For a custom secret-store location, add `--source-secret-dir /path/to/secrets`.
The destination must not exist and its parent must exist. The tool exclusively
locks the raw stopped source, opens and recovers only a private temporary copy,
and copies supported wallet tables into a fresh `wallet.redb`. It preserves
keys, derivation head, change address, balances/history, scans, discovery
coverage and applied-header anchors; chain databases are not copied. It copies
the original encrypted secret bytes without decrypting them; the daemon's first
successful unlock rewrites that copy in the version-2 Argon2id keystore format
and leaves the node's file untouched. Typed row
comparison and source/secret byte checks run before publication. Unknown wallet
tables, unfinished discovery work, invalid anchors, scheduler-owned jobs without
explicit quarantine, and existing paths fail closed. `migration.json` records
content hashes and row counts.
An interrupted publication remains unmarked and cannot be adopted as a seed
wallet; inspect and retain that directory before retrying at another path.

Point the seed config at the resulting directory with the recorded network.
Set the node's `[wallet] mode = "external"` and its daemon address, retain the
original node directory, and pin a mining reward public key if mining is used.
Start the node and daemon, inspect authenticated status/balances/addresses,
and unlock only when needed. The node returns ownership guidance and never
proxies secrets or runs a second wallet writer.

For rollback, stop both processes before changing ownership. Stop using the
standalone directory and restore the node's embedded config and original
wallet directory. Its retained cursor catches up against retained chain
history; transactions sent since cutover still exist on chain and must be
rescanned before trusting the old balance. Do not run both owners concurrently.
The original job journal and node private queue also remain available; review
their approvals before restoring embedded ownership, because retained work may
resume after a rollback.
Current-UTXO discovery retains its incomplete-history metadata rather than
inventing historical inclusion heights. See [standalone offline discovery](wallet-extraction-offline-discovery.md)
for the stopped-node traversal command and its ownership/network checks.

### Distribution and deployment

Release archives include `ergo-walletd`, both daemon config templates, the
wallet documentation and [the systemd unit](../deploy/ergo-walletd.service).
All extracted binaries are version/help checked. Wallet smoke checks exercise
independent API authentication, seed initialization/unlock, graceful stop and
locked reopen, without a remote node. Windows templates use loopback TCP;
Unix deployments may use the owner-only socket.

For systemd, install the binary and sample unit, create
`/etc/ergo-walletd/walletd.toml` from the seed template, and provision distinct
owner-only `/etc/ergo-walletd/node-api-key` and `wallet-api-key` files.
The unit uses `LoadCredential` to present private credential copies to its
dynamic account, with state under `/var/lib/ergo-walletd` and the socket under
`/run/ergo-walletd`. Its default Unix socket is suitable for local clients;
configure loopback TCP for a browser. Adjust `shutdown_timeout_secs` for the
node's bounded RPC deadline and set `TimeoutStopSec` above it. The unit keeps
daemon memory out of swap and core files, filters system calls, drops all
capabilities and allows only loopback networking; add a remote `https` node's
address with `IPAddressAllow`. Installing these examples does not change the
embedded-node or watch-only-daemon defaults.

The daemon's security controls — the version-2 Argon2id keystore and its
automatic upgrade, idle and maximum-duration locks, the persisted unlock
budget, local authentication in both modes, the `Host` allowlist, node
transport rules and process hardening — are described in the
[daemon configuration reference](configuration.md#ergo-walletdtoml-security).

## Parallel library work

[#612](https://github.com/arkadianet/ergo/issues/612) follows Phase 3 as two
separate reviews. The first adds explicit-context reduction, EIP-43 reduced
transaction bytes for EIP-19 cold signing, offline proofs and commitments.
Its fixtures cross-check AppKit and sigma-rust, including QR and ErgoPay
round trips. The existing `Prover::sign` gate remains unchanged in that review.
The second adds direct signing with an explicit intended candidate and an
optional host capability tied to its committed view. Standard embedded-node
and daemon views retain their synthetic-context script gate until an actual
candidate provider supplies the full context. See the [library guide](wallet-reduced-transactions.md)
and [oracle provenance](../test-vectors/wallet/README.md#reduced-transactions-and-cold-transport).

Implemented in [#620](https://github.com/arkadianet/ergo/pull/620),
[#613](https://github.com/arkadianet/ergo/issues/613) makes the portable
`ergo-wallet` core the default. The `keystore` feature enables encrypted file
storage; `cli` enables the binary and includes keystore. Hosts explicitly opt
into keystore. Portable master keys, selection and construction avoid node,
redb, Tokio, CLI and file-keystore dependencies. CI checks both Android library
targets without an NDK link and guards the normal no-default dependency graph.
