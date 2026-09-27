# Architecture

This is an independent, from-scratch Rust reimplementation of an Ergo full
node. It targets **strict consensus compatibility** with the Scala reference
client but deliberately does **not** inherit its internal architecture — it is
not a port. Where the layering or data flow diverges from the reference node,
that is by design and is called out below.

This document is the cross-crate big picture: the layering, the runtime
concurrency model, the data-flow paths, and the consensus/persistence/reorg
contracts every contributor must preserve. For per-crate detail (modules, key
types, "start here") see the [codebase map](docs/codemap.md). For running and
configuring the node see [docs/operating.md](docs/operating.md) and
[docs/configuration.md](docs/configuration.md); for the compatibility contract,
[docs/compatibility.md](docs/compatibility.md).

## Design principles

These are the standing constraints the codebase is built around:

- **Consensus compatibility is non-negotiable.** Mainnet observed behaviour is
  authoritative; the Scala reference node is the practical oracle for
  acceptance/rejection parity; `sigma-rust` is a dev/test oracle only and never
  runs in the consensus path.
- **Conservative correctness over cleverness.** The interpreter is an
  AST-walking evaluator, not a bytecode VM — no VM unless profiling proves it
  matters.
- **Proven crypto crates only.** Primitives (`k256`, `blake2`, AES-GCM) are not
  rolled by hand; this crate stack composes them.
- **Content-addressed integrity end to end.** Every consensus ID (`header_id`,
  `transaction_id`, `box_id`, block-section `modifier_id`) is the hash of
  canonical bytes, so byte-exact serialization is a correctness property, not a
  performance detail.

## Crate layering

The node's runtime is 21 workspace crates forming a strict, acyclic
dependency DAG enforced by `cargo`. A separate 22nd workspace crate,
`ergo-difftest`, is a dev/test-only differential-fuzz harness
(`publish = false`): it depends on the consensus crates but nothing depends
on it, so it sits outside this runtime DAG. The table below is a summary; the
[codebase map](docs/codemap.md) has the full per-crate detail and the
dependency graph.

| Layer | Crates | Role |
|---|---|---|
| **L0** foundation | `ergo-primitives` | byte codecs (VLQ/zigzag), `Digest32`/`ModifierId`/`ADDigest`, `blake2b256`, JIT cost model |
| **L1** wire format | `ergo-ser` | byte-exact round-trippable codecs for every consensus structure |
| **L2** capability | `ergo-chain-spec`, `ergo-crypto`, `ergo-sigma`, `ergo-compiler`, `ergo-p2p`, `ergo-rest-json`, `ergo-indexer-types`, `ergo-wallet-protocol` | network params; PoW + difficulty + Merkle; the ErgoTree interpreter and compiler; P2P transport; JSON DTOs; the indexer read surface; transport-neutral wallet wire contracts |
| **L3** validation | `ergo-validation` | header/block/tx acceptance rules; voted-param epochs; NiPoPoW verify |
| **L4** wallet core | `ergo-wallet`, `ergo-wallet-service` | HD cryptography/secrets/proving; service-owned wallet state, persistence, apply/rescan, selection, and runtime orchestration |
| **L5** state | `ergo-state` | redb-backed authenticated UTXO state, AVL+ tree, atomic apply/rollback, and the transitional wallet facade |
| **L6** subsystems | `ergo-mempool`, `ergo-sync`, `ergo-mining`, `ergo-indexer` | admission/reorg handling; chain sync; block production; extra-index |
| **L7** API | `ergo-api` | HTTP/JSON server; talks to the node only through `Arc<dyn …>` traits and protocol DTOs |
| **L8** runtime | `ergo-node` | the binary: process wiring, lifecycle, the single-writer chain action loop, and the embedded/API wallet adapter |
| **L8** runtime | `ergo-walletd` | the standalone watch-only wallet daemon: its own wallet database, an HTTP chain client, a bounded sync/reorg loop, and a read-only local API. A separate process with its own single-writer sync thread, not a node component |

The wallet split is intentionally transitional at the state boundary.
`ergo-wallet-protocol` is transport-neutral and owns only wire DTOs and
validation. `ergo-wallet-service` owns the wallet persistence/runtime core:
state, redb tables, apply/rescan/sync, selection, and transaction
construction. `ergo-state` retains the `ergo_state::wallet` compatibility
facade and the one-way normal edge `ergo-state -> ergo-wallet-service`, so
service-owned wallet writes can share the chain store's existing redb
transaction. The reverse edge is forbidden. The node remains the embedded
host/API adapter; its secret storage, command loop, state hook, and in-process
chain client are still present, so full runtime relocation is not complete.

`ergo-walletd` is the wallet runtime with the node removed. It runs as its
own process with its own single-writer sync thread over its own redb store,
pulls chain data from a node's `/api/v1/chain/*` HTTP surface, and serves a
read-only local API. It never holds a secret key, never signs, and never
submits, so the local socket is the whole trust boundary: it is created
`0o600` under a `0o077` umask, and the optional TCP listener is restricted to
loopback at config load. Because the daemon cannot ask a node which network it
serves, `network` is a required config identity threaded into descriptor
validation and into every address the API renders.

Startup is two phases rather than one `async fn`. `reqwest`'s blocking client
owns a private Tokio runtime, created and dropped inside
`ClientBuilder::build`, and Tokio aborts when a runtime is dropped on a thread
that is inside an async context — so building it from `run` (or from under
`#[tokio::main]`) panicked before the first log line in a dev build. `prepare`
does every blocking construction step and `main` calls it *before* the runtime
exists; `run` then takes an already-built `Daemon` and cannot construct a
client at all. The daemon's only scan input is the descriptor file, which the
strict schema limits to public keys, so the `/scan/*` registry the backing store
also implements is always empty here and `/scans` always returns `[]`; scan
registration stays a node capability.

Two layering decisions diverge from the Scala reference and are worth
internalizing first:

- **`ergo-state` depends on `ergo-validation`, not the other way around.**
  Validation *defines* the acceptance rules; state *asks* "is this block legal?"
  before applying it. State holds no acceptance logic.
- **`ergo-p2p` knows nothing about chain logic.** It owns framing,
  serialization, and per-peer accounting only. `ergo-sync` drives it as a
  passive transport; the two sit at the same dependency layer.

## The runtime: a single-writer action loop

The node is one `tokio` runtime built around a supervised **action loop**
(`ergo-node/src/node/action_loop.rs`). Chain state has one writer:

1. **The action loop** owns chain-apply (`ergo-state::StateStore`) and the
   `Mempool`, both mutated inline on the loop task. Chain-apply, mempool
   admission, and reorg are serialized by construction—there is no lock around
   UTXO state because there is only one writer.

Wallet work is split at a transitional seam. The service-owned
`WalletService`/`WalletRuntime` owns the wallet persistence/runtime core and
is embedded by the node over a shared wallet store plus an in-process
`ChainClient`. The current node wallet writer task
(`ergo-node/src/node/wallet_bridge.rs`) still owns embedded `SecretStorage`,
`WalletState` locking/hydration, command dispatch, signing/admin adaptation,
and API-facing replies. During block apply, a service-owned
`WalletApplyPayload` runs in the same redb write transaction as the chain
mutation; during API/runtime reads, the service is used where wired while
compatibility paths remain. This is why the node is still the embedded/API
adapter and why full runtime relocation is transitional rather than complete.

Three background workers hang off the loop so slow work never gates it:

- **The persist pipeline** (`ergo-state` persist worker) batches AVL+ writes
  into redb commits off the block-apply hot path. In-memory state may lead
  persisted state by up to the queue depth; on restart the persisted tip is read
  back and replay resumes.
- **The off-loop mining engine** (`ergo-mining` / `ergo-node` mining task)
  builds block candidates from a single committed redb snapshot and CAS-
  publishes them into a served cache, so candidate assembly never blocks the
  writer.
- **The indexer poller** (`ergo-indexer`, optional) follows the committed tip
  and writes only to its own redb file.

`ergo-wallet-service` is transport-neutral and has no node, API, tokio, or
axum dependency. Its `WalletStore` is opened against the same redb handle as
chain state, but its normal dependency direction is the reverse of the
compatibility facade: `ergo-state -> ergo-wallet-service`, never service to
state. The node supplies `InProcessChainClient`, which turns committed
`ChainStoreReader` data and `NodeSubmit` calls into the service's owned chain
port. Service status/rescan methods are synchronous; an external daemon or a
future node runtime may embed them, while the current node retains the
embedded writer and adapter.

Reads never touch the writer. The API task serves owned DTOs from a
`NodeSnapshot` held in an `ArcSwap`, rebuilt once per sync tick — so an HTTP
handler runs on every request without coordinating with the loop and without
holding a lock across an `await`. The snapshot also projects a bounded operator
event-feed ring (a loop-side FIFO diffed each tick as the snapshot is emitted),
served at `/api/v1/events`.

## Data-flow paths

### Inbound: P2P → sync → validation → state

```text
TCP frames ─► ergo-p2p ─► peer_loop ─(mpsc PeerEvent)─► action loop
                                                            │
                                  ergo-sync SyncCoordinator ◄┘   (pure: events → Actions)
                                            │
                              header_proc: parallel parse + PoW, then sequential linkage
                                            │
                              block_proc: load sections ─► ergo-validation (legal?) ─► ergo-state
                                            │
                              StateStore::apply_block: AVL+ mutation + chain index, one redb txn
```

`ergo-p2p` decodes wire frames; the `ergo-node` peer loop forwards `PeerEvent`s
into the action loop over a bounded mpsc channel. Inbound header `Modifier`
messages are coalesced (up to 64 per iteration) so the executor's parallel
pre-validate + sequential finalize + single redb transaction amortizes its
per-batch overhead. The `SyncCoordinator` is a **pure, I/O-free decision
engine** — it turns peer events into `Action`s; the stateful `SyncExecutor`
consumes those actions, validating and persisting against `ergo-state`.
`best_header` and `best_full_block` advance independently, so headers race ahead
of full-block validation (header-first sync).

### Mempool admission

A submitted transaction (`POST /transactions` or `/api/v1/mempool/submit`)
crosses `NodeSubmit::submit_transaction` → a channel `SubmitRequest` into the
action loop → `Mempool::process`. Admission is a 17-step pipeline (parse → fee
→ structural → monetary → script via `ergo-validation` → cost-budget → insert)
split into a decision-only `check` phase (steps 0–14, never mutates the pool)
and a `commit` phase (insert/evict). On a new tip the loop runs the mempool's
reorg handler; demoted transactions go to a bounded revalidation queue and
re-run full admission on the mempool timer — they never re-enter the active pool
directly.

### Block production (mining)

The off-loop engine opens one `CommittedSnapshot` per build, assembles a
candidate against the committed UTXO tip (coinbase + emission/reemission,
greedy mempool selection, optional zero-fee storage-rent self-claim, AVL
dry-run), and CAS-publishes it iff the live tip still matches. `GET
/mining/candidate` serves the published cache only, gated on the one-way
mining-started latch (Scala `ErgoMiner`: a freshly applied block that leaves the
header chain within 6 blocks of the applied chain, checked once and never
re-closed; `[mining].offline_generation` waives the freshness half for peerless
devnet chains). The candidate's parent is always the applied full-block tip, so a
header chain racing ahead of the bodies cannot halt block production.
Submitted solutions are PoW-prechecked off the loop, then re-checked for the
authoritative parent under the loop lock before the block is applied.

### State → REST API

`ergo-api` never reaches into node internals. Its entire contract is a small
set of `Arc<dyn …>` traits; the node implements them against the per-tick
`ArcSwap` snapshot and hands the trait objects to `serve`. Optional route
families (`/blockchain/*`, `/mining/*`, the Scala-compat block surface,
`/wallet/*`) are mounted only when the corresponding trait object is plumbed in.

## Consensus, persistence & reorg contracts

These are the load-bearing invariants. A contributor touching the relevant crate
must preserve them; each is grounded in code and most are pinned by
oracle-parity tests.

### Serialization (`ergo-ser`)

- **Byte-round-trip identity.** Every section re-serializes to the exact bytes
  it parsed, because `header_id`/`transaction_id`/`box_id` all derive from those
  bytes. `ErgoBoxCandidate`/`SpendingProof` carry the original
  `ergo_tree_bytes`/`register_bytes`/`extension` alongside the parsed form so
  non-canonical Scala encodings round-trip without breaking IDs.
- **Lockstep writers.** The three transaction writers (signed / unsigned /
  `bytes_to_sign`) and the header PoW-preimage vs id paths share bounds checks
  and cannot diverge.
- **Scala-quirk fidelity.** The per-tx distinct-token-id table is emitted in
  first-occurrence order (reordering changes the tx id); context-extension maps
  with ≥5 vars re-serialize in Scala 2.12 `HashTrieMap` iteration order (else
  `bytes_to_sign` desyncs and signatures fail); the Autolykos solution carries
  no on-wire variant tag (V1/V2 selected by header version).
- **Soft-fork passthrough.** ErgoTrees above the max supported version are
  accepted size-delimited and round-tripped verbatim without body parsing.
- **Hostile-input bounds.** Recursion/allocation guards (`MAX_TYPE_DEPTH`,
  `MAX_EXPR_DEPTH`, soft-capped `Vec::with_capacity`) mirror Scala.

### Validation (`ergo-validation`)

- **Unforgeable proofs.** `CheckedHeader`/`CheckedTransaction`/`CheckedBlock`
  have private fields; production constructors run full validation. The
  `from_persisted_parts`/`trust_me` escape hatches are explicit and auditable.
- **Canonical-encoding enforcement.** Every tx must re-serialize bit-identically
  to its input bytes (`NonCanonical` otherwise); persisted headers are parsed to
  EOF.
- **Validator caps tighter than wire caps** (counts ≤ `Short.MaxValue`, not
  `u16::MAX`; extension value 64 B vs wire 255; proposition bytes 4096).
- **Sequential/parallel equivalence.** Parallel block validation yields
  identical accept/reject and the same first-failing-tx-by-index ordering as
  sequential; intra-block double-spends are rejected up front.
- **Arithmetic parity.** Storage-fee uses i32 wrapping-multiply (overflow above
  ~1717 bytes preserved to match Scala); JIT-cost overflow is a typed rejection,
  never a panic.
- **DoS-safe rule ordering.** Extension structural/interlink/size checks run
  *after* the Merkle-root recompute so an unbounded payload can't force an
  O(N²) scan.

### State, persistence & reorg (`ergo-state`)

- **Atomic commit per block.** `undo_log` + AVL+ node mutations + `chain_index`
  + `state_meta` (+ epoch-boundary `voted_params`) land in a **single redb write
  transaction**. When a wallet hook is present, service-owned wallet rows are
  applied through the state transaction's borrowed `WalletWrite` as part of
  that same commit. The state crate coordinates this boundary; it does not
  reimplement wallet persistence.
- **Delta-based reorg.** There is no single "reorg" method: `rollback_to(common
  ancestor)` replays each block's changelog before-image in reverse, then
  re-applies the new branch. Any failure after an AVL mutation routes through
  `rebuild_from_committed`, restoring in-memory state from committed disk state
  — no in-memory-only state can outlive a failed commit.
- **`undo_log` keys are `(height, header_id)`** (36-byte composite), so
  competing fork branches at the same height coexist.
- **`best_header` and `best_full_block` are tracked separately**, enabling
  header-first sync and the headers-only digest mode.
- **Tiered invalidity.** `pow_validity` is the *only* persisted validity flag
  (cryptographically definitive PoW failure). All other failures are
  session-scoped (`session_invalids`, cleared on restart) because they might be
  our own bug.
- **AVL+ label hashing** matches `scorex-util`/`ergo_avltree_rust` exactly
  (`leaf = blake2b256(0x00‖key‖value‖next_key)`, `internal =
  blake2b256(0x01‖balance‖left‖right)`, `ADDigest = root_label‖tree_height`).
- **Crash-repair contract.** Every write transaction routes through
  `begin_write_qr` (quick-repair on); no raw `db.begin_write()` exists outside
  the helper.

### Sync (`ergo-sync`)

- **Coordinator purity.** `SyncCoordinator` performs no I/O and no async beyond
  `tracing` diagnostics — every other effect is an emitted `Action`. This is the
  testability/determinism contract.
- **One PoW per header.** `pre_validate_header` produces an unforgeable
  `PowCheckedHeader`; `finalize_header` consumes it without re-checking, and
  orphan retries reuse the cached proof.
- **Fork choice by cumulative score**, applied sequentially: header swaps by
  cumulative difficulty; a full-chain reorg rolls back to the common ancestor
  then re-applies.
- **Retryable vs definitive failure.** `ParentNotFound`/`EpochContextIncomplete`
  are local context gaps → orphan-buffer + retry, never a peer penalty and never
  persisted as accepted; only cryptographically definitive failures mark a
  header `Invalid`.
- **Receive-time id verification.** A requested section's id is recomputed on
  receipt so a peer cannot substitute payload under a requested id.
- **Fail-fast hydration.** A missing/corrupt persisted header row or a
  chain-index coverage gap on restart is fatal, never silently truncated — the
  persisted header table is the source of truth after restart.

### Mempool (`ergo-mempool`)

- **Single writer**; raw pool access is `cfg(test)`/`test-support` only.
- **Staged admission**: `check` is decision-only; only `commit` mutates, so a
  late capacity/budget reject can't drop valid pooled txs.
- **Anti-DoS is metered even on `/check`** (cost charged on failure too,
  saturating) so `/check` can't be a free unmetered-script oracle.
- **Weight-based replacement, not raw RBF**: a conflicting candidate replaces a
  conflict set only if its weight strictly exceeds the set's *average* weight;
  losers are still charged cost.
- **Data inputs resolve committed-only**; a tx cannot see an unconfirmed pool
  output through a data input.

## Node operating modes

A "mode" is a combination of config fields, not a single enum:

| Mode | `state_type` | `verify_transactions` | `blocks_to_keep` | Mines? | Extra-index? |
|---|---|---|---|:--:|:--:|
| 1 — full archive | utxo | true | -1 | ✅ | ✅ |
| 2 — UTXO snapshot bootstrap | utxo | true | -1 (+ `utxo_bootstrap`) | ✅ | ✗ |
| 3 — pruned suffix window | utxo | true | N ≥ floor | ✅ | ✗ |
| 4 — pruned + bootstrap | utxo | true | N (+ bootstrap) | ✅ | ✗ |
| 5 — digest verifier | digest | true | -1 | ✗ | ✗ |
| 6 — headers-only | digest | false | 0 | ✗ | ✗ |

The cross-cutting rules, enforced at config-load **and** a runtime backstop:
**mining requires `state_type = "utxo"`** (any of Modes 1–4 — candidate
generation needs the UTXO box store; digest modes are rejected); **the
extra-index requires Mode 1** (full archive, un-pruned, no bootstrap); **storage-
rent self-claim requires the indexer**. `ergo-state` keeps `utxo` and `digest`
data directories non-interconvertible via a persisted sentinel.

## Trait boundaries

The load-bearing seam is `ergo-api`'s set of `Arc<dyn …>` traits
(`ergo-api/src/traits.rs` + siblings). The node implements them against a
runtime snapshot; **`ergo-api` never reaches into node internals** and the
production build never depends on `ergo-state`/`ergo-indexer`.

| Trait | Shape | Purpose |
|---|---|---|
| `NodeReadState` | sync | snapshot reads (`info`/`status`/`tip`/`peers`/`mempool_*`/`recent_blocks`/…) |
| `NodeSubmit` | async | `submit_transaction[_json]`, `submit_full_block` — cross the loop via channel + oneshot |
| `WalletAdmin` | async | wallet lifecycle/reads/sending; owner is the single-writer wallet task |
| `MempoolView` | sync | pool overlay for the extra-index, composed with `IndexerQuery` at the handler |
| `NodeChainQuery` | sync | Scala-compat block/chain queries |
| `NodeMining` | sync | external-miner candidate/solution surface |
| `ChainParamsView` | sync | voted-param arithmetic without a direct `ergo-validation` dep |
| `NodeAdmin` | sync | `request_shutdown` |
| `IndexerQuery` | sync | confirmed-only indexer reader (router gates every read on `CaughtUp`) |

### Wallet protocol, service, and state boundaries

The wallet split has three different contracts:

- `ergo-wallet-protocol` is transport-neutral data only. Its normal
  dependencies are `serde`, `serde_json`, and `hex`; it owns ID/byte
  validation and native/Scala DTO shapes, not storage or runtime behavior.
- `ergo-wallet-service` is the service-owned persistence/runtime core. Its
  normal direct dependencies are `ergo-wallet`, `ergo-wallet-protocol`,
  `ergo-primitives`, `ergo-ser`, `ergo-validation`, `serde`, `serde_json`,
  `hex`, `thiserror`, `redb`, and `bincode`. It has no direct
  `ergo-sigma` dependency: its sigma-facing types are consumed through the
  wallet and validation crates, so adding one would be an unused edge. It must
  not depend on `ergo-state`, `ergo-api`, `ergo-node`, the other node
  subsystems, `tokio`, or `axum`.
- `ergo-state` is the transitional integration owner for chain apply/rollback.
  It depends on `ergo-wallet-service` and re-exports the service wallet
  facade so the shared redb transaction remains atomic. The service must not
  depend on state; moving the remaining facade/runtime ownership is future
  work.

Two more seams keep the writer model honest: `ergo-state`'s `StateBackend`
trait family is dispatched **generically** (monomorphized `B: StateBackend`,
not `dyn`) so the UTXO box-arena and the Mode-5 ADProof verifier share one apply
pipeline; and `ergo-mining`'s `CandidateStateView` lets the same candidate
builder run on-loop (`StateStore`) or off-loop (`CommittedSnapshot`),
byte-identically.

## Where to start reading

- **Runtime + action loop:** `ergo-node/src/node/` (`boot/`,
  `action_loop.rs`, `sync_tick.rs`, `wallet_bridge.rs`).
- **Wallet wire contracts:** `ergo-wallet-protocol/src/chain.rs` and
  `src/native/dto/` / `src/scala/`.
- **Wallet persistence/runtime core:** `ergo-wallet-service/src/runtime.rs`,
  `src/wallet/store.rs`, and `src/wallet/apply/`; read
  `ergo-state/src/wallet/` for the transitional facade.
- **The API boundary:** `ergo-api/src/lib.rs`, `ergo-api/src/traits.rs`.
- **The store + its invariants:** `ergo-state/src/lib.rs`, then `store`, `avl`,
  `persist`.
- **The sync pipeline:** `ergo-sync/src/lib.rs` (coordinator, header/block
  processing, the two bootstrap reducers).
- **Anything else:** start from the [codebase map](docs/codemap.md) — find the
  crate, open its page.
