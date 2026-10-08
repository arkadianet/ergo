# Wallet extraction

Phase 2 extracts the shared wallet implementation and proves a standalone
watch-only daemon against the embedded wallet. Phase 1 landed in main through
[#381](https://github.com/arkadianet/ergo/pull/381). All seven Phase 2 items
landed on `integration/wallet-extraction`; [#574](https://github.com/arkadianet/ergo/pull/574)
completed their refresh and validation. The subsequent main merge carries the
0.12.3 node changes across the extracted boundaries. Phase 3 has started with
opt-in daemon seed lifecycle hosting; spending support remains a later increment.

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
  selection and transaction construction. Chain snapshots, coherent mempool
  overlays and transaction submission enter through capability traits. The
  service's normal graph has no `ergo-node`, `ergo-state`, `ergo-api`,
  `ergo-mempool` or Tokio dependency.
- `ergo-node` embeds the engine through a serialized command adapter, committed
  chain views and supervised wallet/rescan workers. Embedded wallet rows still
  co-commit with chain rows in the same `state.redb` transaction.
- `ergo-walletd` owns a separate `wallet.redb`, resumes from a durable cursor,
  and defaults to a watch-only local read API. Opt-in seed mode hosts
  `WalletEngine` for encrypted seed lifecycle and key management through an
  authenticated local API. Both modes authenticate header identity and box
  IDs, while trusting the node for chain validity and transaction membership.
  Balance and sync-status projections remain confirmed-only; neither daemon
  mode can build, sign or submit transactions yet.

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
migration; this format migration is separate from a future embedded-to-daemon
wallet cutover.

## Completion checks

Phase 2 completion requires the workspace formatting/fragment checks,
all-target/all-feature Clippy, workspace tests and doctests, strict rustdoc,
dependency-boundary checks and CI shard coverage. The dedicated shadow gate is
`scripts/shadow-compare.sh --all`: both negative controls plus the synthetic,
reorg, node/daemon restart, rescan and mainnet 1–1000 scenarios must run.

## Phase 3: daemon engine hosting

The first Phase 3 increment implements local seed lifecycle and key management
through the shared `WalletEngine`. `mode = "watch_only"` remains the daemon's
default: it imports public descriptors, opens no secret storage and exposes
the existing read API. `mode = "seed"` requires a separate data directory,
an independent `local_api_key_file` credential and no `descriptor_file`.
On first use, initialize or restore through the API; the daemon does not
automatically import an embedded wallet or turn a descriptor wallet into a
seed wallet. Existing seed wallets restart locked.
The persisted `wallet-mode` marker identifies daemon-owned seed data; an
unmarked directory with `wallet.redb`, `wallet/` or `state.redb` is rejected.

The outbound `api_key_file` authenticates node chain requests. The independent
`local_api_key_file` authenticates every seed-mode API request, including reads,
on both Unix sockets and loopback TCP. The two files must contain different
credentials. Authentication runs before secret-body parsing; requests are
bounded, password-guess budgets remain in the engine, and all seed-mode
responses carry `Cache-Control: no-store`.

The additional native routes are:

| Method | Path | Behavior |
|---|---|---|
| GET | `/api/v1/wallet/lifecycle/status` | Local `initialized` and `locked` flags; no node connection needed |
| POST | `/api/v1/wallet/init` | Create an encrypted seed; return the recovery phrase once |
| POST | `/api/v1/wallet/restore` | Restore a recovery phrase with an explicit derivation mode |
| POST | `/api/v1/wallet/unlock` | Unlock and reconcile derived public keys |
| POST | `/api/v1/wallet/lock` | Drop the unlocked secret |
| POST | `/api/v1/wallet/mnemonic/verify` | Check the recovery phrase through the engine's attempt budget |
| POST | `/api/v1/wallet/addresses` | Derive the next key or an explicit path |
| GET / PUT | `/api/v1/wallet/change-address` | Read or update the tracked, owned change address |

`/status` and `/api/v1/wallet/status` keep the Phase 2 cursor, node-tip, lag and
sync projection. The separate lifecycle status avoids claiming that a local
seed has a complete spending view. Commands and sync passes share one writer
gate. Adding keys resets historical scan state in the transaction that adds
them, and syncing waits until keys are known. Persisted public keys continue
syncing while the secret is locked.
A terminal seed-sync failure remains visible until a new-key history reset
requests replay, which resumes without restarting the process.

This increment deliberately has no construction, signing, sending or private-key
export routes. The node's pruning policy is unknown to the lifecycle adapter,
and engine block replay is unavailable. A restored wallet's historical balance
is established by normal daemon sync against the required retained history;
restore never claims that an unavailable history has been recovered.

The remaining Phase 3 work is to provide a coherent committed node context,
active validation settings and re-emission rules, a coherent mempool overlay,
and submission adapters before exposing construction, signing and sending.
Embedded-to-daemon data/secret migration, daemon release packaging and service
deployment, API/UI parity and the eventual compatibility/default policy also
need explicit completion criteria. The lifecycle increment does not change the
node's default embedded-wallet policy.

## Parallel library work

Two library workstreams support the extraction and Argus integration:

- [#613](https://github.com/arkadianet/ergo/issues/613): make `ergo-wallet`
  embeddable by making CLI and file-keystore dependencies optional and adding
  Android compile checks. This dependency split is a separate workstream from
  daemon lifecycle hosting.
- [#612](https://github.com/arkadianet/ergo/issues/612): reduce transactions
  against real chain context, implement EIP-19 encoding and reduced signing,
  and verify contract-input proofs against Scala fixtures. This enables
  Argus contract signing, offline signing and ErgoPay.

Daemon hosting and EIP-19 can proceed alongside the library dependency split.
Making the synthetic signing context and its validation dependency optional
in #613 follows the real-context API in #612. Neither issue is a prerequisite
for the Phase 2 watch-only acceptance boundary.
