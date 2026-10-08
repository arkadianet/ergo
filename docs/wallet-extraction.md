# Wallet extraction

Phase 2 extracts the shared wallet implementation and proves a standalone
watch-only daemon against the embedded wallet. Phase 1 landed in main through
[#381](https://github.com/arkadianet/ergo/pull/381). All seven Phase 2 items
landed on `integration/wallet-extraction`; [#574](https://github.com/arkadianet/ergo/pull/574)
completed their refresh and validation. The subsequent main merge carries the
0.12.3 node changes across the extracted boundaries.

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
  and exposes a read-only local API. It holds no secrets and cannot sign or
  submit transactions. It authenticates header identity and box IDs, while
  trusting the node for chain validity and transaction membership. Its balance
  and status projections are confirmed-only.

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

## Next stage

Phase 3 hosts `WalletEngine` in the daemon and supplies secret lifecycle,
mutable wallet routes, signing views, mempool overlays and submission adapters.
Embedded-to-daemon data/secret migration, daemon release packaging and service
deployment, API/UI parity and the eventual compatibility/default policy still
need explicit completion criteria. They are not part of the Phase 2 watch-only
acceptance boundary.

Two library workstreams support the extraction and Argus integration:

- [#613](https://github.com/arkadianet/ergo/issues/613): make `ergo-wallet`
  embeddable by making CLI and file-keystore dependencies optional and adding
  Android compile checks. The CLI/keystore split can start before Phase 3.
- [#612](https://github.com/arkadianet/ergo/issues/612): reduce transactions
  against real chain context, implement EIP-19 encoding and reduced signing,
  and verify contract-input proofs against Scala fixtures. This enables
  Argus contract signing, offline signing and ErgoPay.

Daemon hosting and EIP-19 can proceed alongside the library dependency split.
Making the synthetic signing context and its validation dependency optional
in #613 follows the real-context API in #612. Neither issue is a prerequisite
for the Phase 2 watch-only acceptance boundary.
