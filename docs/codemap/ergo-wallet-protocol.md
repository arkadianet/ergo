# ergo-wallet-protocol

**Purpose:** Transport-neutral wallet and node-chain wire contracts. Defines
serialized request/response shapes, ID and byte validation, and the
native/Scala wallet DTO vocabulary shared by an embedded service, an external
daemon, and API adapters. It owns no storage, chain reader, HTTP server,
async runtime, or signing implementation.

**Depends on (workspace):** none
**Normal dependency boundary:** the only allowed normal dependencies are
`serde`, `serde_json`, and `hex`. The crate must not acquire an Ergo workspace
crate, `redb`, `tokio`, `axum`, or `utoipa`; this boundary is checked by
`tests/dependency_boundary.rs`.
**Depended on by:** `ergo-api`, `ergo-wallet-service`, `ergo-node`, `ergo-walletd`
**Approx LOC:** ~3.8K (`src/**/*.rs`)

## Start here
- `src/lib.rs` — module tree, root re-exports, and the compatibility
  `wallet::{chain,native,scala}` namespaces.
- `src/chain.rs:5` — chain version constants, lowercase ID/hex validation,
  chain snapshots, block cursors, and the transport-neutral block/submit
  response shapes.
- `src/error.rs:3` — the shared `WalletAdminError` taxonomy and stable reason
  strings used by adapters.
- `src/native/dto/` — DTOs for the native `/api/v1/wallet/*` surface.
- `src/native/dto/lifecycle.rs` — strict seed/password lifecycle requests,
  mnemonic response types and the daemon's local `LifecycleStatusDto`.
- `src/scala/` — Scala-compatible lifecycle, query, scan, sending, and
  multi-sig wire shapes.

## Modules
- `src/chain.rs` — `Id32`/`HexBytes`, chain tip/cursor/header/snapshot/block
  types, `BlocksSinceResponse`, and submit request/response types.
- `src/error.rs` — transport-neutral wallet error values and reason/detail
  helpers.
- `src/native/dto/` — address, balance, box, lifecycle, reward, status,
  transaction, and transaction-construction DTOs.
- `src/scala/` — Scala-compatible lifecycle, pagination, scan, sending,
  multi-sig, and advanced-admin DTOs.

## Key types, traits & functions
- `Id32`, `HexBytes` — validated lowercase wire representations of 32-byte
  identifiers and raw bytes.
- `ChainTip`, `ChainSnapshot`, `ChainBlock` — neutral chain read shapes.
  Each `ChainBlock` and each snapshot `ChainHeader` carries its raw serialized
  header as `headerBytes`, so a consumer can recompute the id instead of
  trusting it.
- `BlocksSinceResponse` — tagged `Forward`, `Ancestor`, and `Pruned` results.
- `SubmitRequest`, `SubmitResponse` — neutral transaction submission shapes.
- `WalletAdminError` — shared lifecycle, authorization, and transaction error
  vocabulary, including `ShuttingDown` (`503 shutting_down`) for closed
  wallet command admission.
- `LifecycleStatusDto { initialized, locked }` — the daemon's local seed
  status, separate from `WatchOnlyWalletStatusDto`'s confirmed sync projection
  and the embedded `WalletStatusDto`.
- `native::dto::*` and `scala::*` — adapter-facing DTO families; the
  protocol does not implement their routes.

## Invariants & contracts
- **Transport neutrality.** These are data contracts only. A consumer chooses
  the transport and owns networking, persistence, scheduling, and runtime
  policy; the protocol crate does neither.
- **Strict wire identifiers.** IDs are 64 lowercase hex characters, byte
  strings are lowercase hex, and reserved snapshot IDs are rejected during
  deserialization (`src/chain.rs:14-42`).
- **Stable shape tags.** Chain and submit responses retain explicit tagged
  variants, and Scala-facing DTOs preserve their camelCase or explicitly
  documented wire names.
- **Strict lifecycle bodies.** Native seed/password requests reject unknown
  fields. Their `Debug` implementations redact passwords and recovery phrases;
  mnemonic-bearing responses are redacted too. Body-size limits, authentication,
  response caching and key erasure remain adapter/host policy.
- **Dependency isolation.** No consensus acceptance, UTXO lookup, secret
  handling, storage schema, or async/runtime behavior belongs in this crate.
- The normal dependency boundary is intentionally narrower than the
  workspace-wide foundation convention: `ergo-wallet-protocol` does not
  depend on `ergo-primitives` or `ergo-ser` merely to share wire vocabulary.
