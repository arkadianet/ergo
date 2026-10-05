# Consensus compatibility

This node is an independent, from-scratch Rust reimplementation of an
[Ergo Platform](https://ergoplatform.org) full node. It is **not** the
[Scala reference client](https://github.com/ergoplatform/ergo), and it
shares no code with it. The goal is bug-for-bug consensus parity with the
reference node — accept every block the reference node accepts, reject
every block it rejects — but parity is a property we test toward, not a
guarantee we can hand you.

The internal architecture is deliberately its own: idiomatic Rust, a
layered crate workspace, an AST-walking ErgoScript interpreter rather than
a bytecode VM, and an inverted `ergo-state → ergo-validation` dependency.
None of it is ported from Scala. Compatibility is therefore a property of
observable inputs and outputs (which blocks and transactions are accepted
or rejected, what bytes go on the wire), enforced by tests — not a property
of code structure.

> **Read this before relying on the node for funds.** The codebase is
> pre-1.0 alpha. Consensus-critical paths are oracle-tested against
> Scala-produced fixtures and exercised against mainnet to tip, but
> real-world deployment exposure is limited, and parity is incomplete in
> the areas called out under [Known limitations](#known-limitations). Do
> not use this node for funds custody or production infrastructure, and
> verify its verdicts against the Scala reference node before trusting them.
> See [`SECURITY.md`](../SECURITY.md) for the disclosure scope and process,
> and [Versioning and stability](#versioning-and-stability) for the
> pre-1.0 stability policy.

## What "compatible" means here

The contract is behavioral. For any header, block, or transaction, this
node's accept/reject verdict — and, where bytes are observable
(`transactionsRoot`, header IDs, AVL+ state root, the bytes a transaction
is signed over, the P2P wire framing) — is meant to match what the Scala
reference node does on the same input. Mainnet-observed behavior is the
authoritative tie-breaker for any dispute: where this node and the
reference node disagree, the reference node (and the chain mainnet has
actually accepted) is correct by definition, and the divergence is a bug
here.

## What is implemented and parity-tested

### Received block-section bytes

Block sections are stored through typed persistence with their received
payload intact, and P2P `RequestModifier` serves that payload intact, in both
UTXO and digest modes. This is an intentional byte-fidelity difference from
Scala 6.0.7: its history insertion serializes parsed `BlockTransactions`, and
its P2P responder serves those stored canonical bytes. We retain received bytes
to avoid introducing a blanket transform over embedded values with retained
wire identity. No storage migration or canonicalization is introduced. Section identity commits
to its type, header ID and content root, rather than a hash of the entire wire
payload; receive-time verification recomputes that identity from parsed content.

The fresh Scala-backed fixture
`test-vectors/scala/block_section_storage_6_0_7.json` and
`ergo-node/src/node/tests/section_wire_policy.rs` pin 22 accepted sections,
including noncanonical Boolean/context-extension and zero-prefixed identity
GroupElement encodings, across block versions 1 and 4. Eight wire payloads
differ from canonical storage, while transaction IDs, transaction/witness
roots, section IDs and canonical re-serialization agree. This evidence is
scoped to these encodings and section admission; the synthetic input boxes
and unmined headers do not establish full-block validity. Retained box/header
identity (#357) must not be generalized into canonical identity.

`GET /blocks/{id}/transactions` is a parsed JSON surface. Its transaction
values and canonical transaction sizes match Scala in these cases. Rust's
section `size` consistently describes received bytes. Scala initially reports
received section length from its parsed-object cache, then canonical stored
length after reopening; the shorter Boolean leaf encodings differ by one byte
at that point. The oracle records both states separately. Reproduction and
the exact production storage/serving seams are documented in
[the pinned oracle archive](https://github.com/arkadianet/ergo/tree/ba2ac17932c8ca818594f110b5b25e9c07ac6dba/scripts/jvm_section_oracle/README.md).

### Sync and API behavior

Header admission enforces Scala's fatal rule 209 (`hdrTooOld`): a child's
parent must be less than `[node] keep_versions` blocks below the applied
full-block tip, and genesis requires the full tip to be below that window.
The default window is 200. Header-only sync uses the full height, so headers
ahead of block application remain eligible. Digest nodes use the same
admission setting even though their persisted rollback history is unbounded.

Full-chain switching waits for a contiguous, available replacement suffix
whose cumulative work exceeds the applied tip's work. Header-only forks
leave the applied state intact; a shorter, heavier full chain can replace a
longer one. The header and full-block tips can differ while bodies are being
downloaded, including across a digest-store restart. Regression coverage lives
in `ergo-sync/src/executor/relay_tests.rs`, `ergo-sync/tests/it/header_too_old.rs`,
and the node's periodic-driver tests.

Peer gossip, sharing-list rotation, discovery fanout and sync fanout draw
their production seeds from OS randomness. Selection functions keep explicit
seed inputs for deterministic tests. Download reassignment retains its
connected-peer filtering, degradation preference and recency ranking; those
quality rules do not use wall-clock entropy. Wallet mutations `/wallet/lock`
and `/wallet/deriveNextKey` accept POST as well as Scala-compatible GET, with
the same API-key authentication on both methods.

The surfaces below are exercised by oracle-backed tests against
Scala-produced fixtures and/or replayed against real mainnet bytes. The
authoritative live, subsystem-by-subsystem status is the project's parity
tracker; this section is the distilled picture.

| Surface | Coverage |
|---|---|
| Serialization / wire format | Headers, block transactions, boxes, ErgoTree (v0/v1, constant segregation), `SValue`/constants (primitives, `Coll`, `Tuple`, `Option`), PoPoW headers, extension sections, batch-Merkle proofs. Boundary IDs (`transactionsRoot`, `extensionRoot`, header IDs, `bytes_to_sign`) are pinned to external fixtures. P2P framing is checked against captured Scala bytes. |
| Proof-of-Work | Autolykos v2 (N-element table, solution verification, difficulty bits) plus EIP-37 difficulty adjustment, verified across a full mainnet IBD. |
| Sigma interpreter | AST-walking ErgoTree interpreter over the consensus-active opcodes, per-opcode cost accounting, context binding, R4–R9 registers; sigma protocols (Schnorr/DLog, Diffie-Hellman tuple, AND/OR/THRESHOLD, Fiat-Shamir challenge); `ReduceToCrypto`. Cost parity has been checked over the full mainnet transaction set. |
| AVL+ state | Tree-node serialization matching the Scala AVL+ wire format, root-digest computation, insert/update/remove, batch ops, AD-proof generation. State-root digest matched at every height across a full IBD to the mainnet tip. |
| Validation | Header validation (PoW, difficulty, timestamp, parent linkage, genesis, extension digest, voted-parameter epoch transitions), full-block validation (tx root, AD proofs, extension k/v, per-tx structural and semantic checks, cost-budget enforcement, post-apply state-digest match), transaction validation (signatures, cost accounting, token preservation, data inputs, storage rent), and the voted-parameters / soft-fork voting mechanism. Rejection-parity tests confirm rejects, not just accepts. |
| Reorg / storage integrity | Delta-based rollback; undo-log persisted atomically alongside AVL mutations, chain index, and state-meta in a single redb write transaction per applied block; reorg abort rebuilds in-memory state from committed DB state. |
| Crypto primitives | Blake2b-256 (consensus digest), SHA-256 (wire checksum), Merkle membership and batch proofs, secp256k1 group operations — all via established crates (`k256`, `blake2`, `sha2`, `gf2_192`), no rolled-own primitives. |
| REST surface | The Scala API (`/info`, `/blocks/*`, `/transactions*`, `/utxo/*`, `/peers/*`, `/utils/*`, `/script/*`, `/emission/*`, the Scala-compatible extra-index `/blockchain/*` routes (indexer-gated), `/mining/*` (mining-gated, including supplied-transaction/per-request-key candidates with Scala upcoming-transaction proofs), `/wallet/*`) alongside the RUST API under `/api/v1/*` plus Rust-only storage-rent routes under `/blockchain/storageRent/*`. The RUST API surface: unconditionally mounted `info`, `identity`, `host`, `status`, `votes` (GET), `tip`, `sync`, `peers`, `mempool/summary`, `mempool/transactions[/:tx_id]`, `blocks/recent`, `events`, `health`; submit-gated `mempool/submit` and `mempool/check`; chain-reader-gated `difficulty/history`, `votes/history`, `mining/minerStats`; indexer-gated `indexer/status` and `transactions/:tx_id/detail`; admin-gated `node/shutdown` and `votes` (POST); and the api-key-gated RUST API wallet sub-surface (`wallet/status`, `wallet/balance`, `wallet/addresses`, `wallet/boxes[/:box_id]`, `wallet/transactions[/:tx_id]`, `wallet/rewards/retrieve`, and key-lifecycle routes). JSON DTOs and canonicalizing decoders are anchored by a byte-parity oracle against the Scala JSON shapes. |
| NiPoPoW | Prover/verifier, P2P exchange + bootstrap, and the four `/nipopow/*` REST routes. Byte/JSON parity pinned against genuine Scala-serializer fixtures, a live mainnet differential vs the reference node (all endpoints, genesis/epoch-boundary/v1-era heights, anchored proofs, error surfaces), scrypto batch-Merkle shape vectors, and a 132-header `maxLevelOf` oracle sweep. One documented deviation: the Scala node reports stale `header.size` metadata (+1) for some historical headers, contradicting its own served bytes; this build serves the true byte length. |

**Milestone.** Mainnet sync to tip was reached on 2026-04-26 at height
1,771,976, with state-digest parity at every height. Continued sync against
live mainnet has been part of the development loop since.

**Modes that boot today** (against the reference node's mode taxonomy):
Mode 1 (full archive), Mode 2 (UTXO snapshot bootstrap, consume and serve),
Mode 3 (pruned suffix window; activation details under Known limitations),
Mode 4 (pruned + UTXO bootstrap — the composed lifecycle), Mode 5 (digest
verifier — boots, passes the handshake/sync-info/API seams, and syncs headers
from live peers; broader AD-proof block-replay coverage remains), and Mode 6
(headers-only digest). NiPoPoW bootstrap (consume and serve),
the extra-index `/blockchain/*` surface, the external-miner mining protocol,
and an HD wallet (single-prover signing, BIP39 + BIP32, AES-GCM secret
storage) also ship. In operation, a combined Mode 2 + NiPoPoW boot from an
empty `data_dir` has been observed to complete in well under an hour on
mainnet — far faster than a multi-hour full IBD from genesis, though the
exact figure depends on peer and hardware conditions.

## How parity is checked

Wallet-file encryption and the modern/pre-1627 derivation paths are pinned to
fresh fixtures from Scala wallet 6.0.6 at commit
`23aabead88774d27f2c9190ace3c9abbc8f1d5cb`. Every PR regenerates the fixture and
unlocks a newly created Rust wallet with the Scala implementation. See
[wallet fixture provenance](../test-vectors/wallet/README.md). Import accepts
Scala's historical encrypted-stream field split, absent cipher algorithm/mode
fields, and a missing/null legacy flag, as well as the authenticated field
layout written by earlier Rust versions. New files use the Scala field split;
older Rust binaries that only understand the previous split cannot unlock
them. Keep an upgraded binary available before creating/restoring a wallet.

Four independent oracles, ranked by signal strength, with a strict rule
about which one counts for consensus:

- **Mainnet bytes — strongest.** Real headers, blocks, and a captured
  Scala-served NiPoPoW proof live under
  [`test-vectors/mainnet/`](../test-vectors/mainnet/). The reference node's
  mainnet-observed behavior is the authoritative tie-breaker for any parity
  dispute. The single most demanding check is a full IBD to the mainnet
  tip with AVL+ state-root equality at every height.
- **Scala reference node — the practical acceptance/rejection oracle.**
  Fixtures under [`test-vectors/`](../test-vectors/) are re-extractable from
  a running Scala node. Consensus-boundary tests pin against these
  externally-produced vectors, never against the implementation under test:
  a self-oracle (`let expected = my_fn(input)`) proves only internal
  consistency, never correctness. A manual-trigger vector-drift workflow
  (cron commented out until sync stabilizes) regenerates the vectors
  against a self-hosted Scala node and reports byte-level deltas; drift is
  reviewed by hand, never auto-applied.
- **`sigma-rust` — dev/test only, never runtime.** The reference Rust sigma
  implementation is used in tests to cross-check the interpreter. It is
  **never** linked into the consensus path. Findings against `sigma-rust`
  itself should be reported upstream, not against this node (see
  [`SECURITY.md`](../SECURITY.md) scope).
- **`ergo-difftest` — continuous structure-aware differential fuzzing.** A
  dedicated workspace crate drives structure-aware generators over every
  consensus wire-format surface (ErgoTree, box, transaction, header, sigma
  expressions, constants, AVL frames), checking two oracle-free invariants on
  every generated or corpus-mutated input: no decode panics, and
  `decode → encode` reaches a byte-stable fixed point. A JVM-oracle
  differential layer, run locally against `ergo-core` / a live Scala node,
  translates generator outputs into accept/reject fixtures — this is the layer
  that catches real accept-vs-reject divergences. A `cargo-fuzz` / libFuzzer
  layer (nightly Rust, ASan-instrumented) adds coverage-guided byte mutation
  over the same surfaces.

CI runs `cargo fmt --check`, `cargo check`, `cargo clippy --all-targets
--all-features -- -D warnings`, and `cargo test` across Linux, macOS, and
Windows on every push and pull request; a `difftest` job runs the
`ergo-difftest` structured campaign (50,000 iterations, 80 % vocabulary
coverage gate) on Linux on every push; a nightly scheduled workflow runs
longer structured and corpus-mutation campaigns (2,000,000 iterations each)
plus bounded `cargo-fuzz` / libFuzzer / ASan passes on nightly Rust across
six surfaces; a nightly JVM consensus differential campaign with rotating,
reproducible seeds and preserved oracle transcripts; plus the supply-chain auditors `cargo-audit`, `cargo-deny`,
and `cargo-machete`. See
[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) and
[`.github/workflows/fuzz.yml`](../.github/workflows/fuzz.yml).

## Storage compatibility

The redb 2.6 → 4 file-format change is a storage compatibility boundary, not a
consensus or wire-format change. Use the [offline copy-only migration](operating.md#migrating-legacy-redb-databases)
for v2 databases before startup. Table schemas and typed row contents are
verified under both real dependency versions, including the indexer's fixed
width tuple keys and embedded wallet tables; unknown schemas fail closed.
Keep the old data directory and binary for rollback because a database later
written by redb 4 may contain type metadata unreadable by redb 2.6.

## Known limitations

Areas where parity is incomplete, partial, or deliberately out of scope.
Be aware of these before depending on the node.
### Operating-mode status

These statuses describe the implemented modes and the limits of their current
coverage. Fixture tests, process-recovery tests and configured external jobs
have different scopes; a skipped job does not establish parity.

| Mode | Current status and caveats |
| --- | --- |
| **1 — UTXO full archive** | Supported default. Mainnet replay checks authenticated state roots, but limited deployment exposure remains. Bounded early-mainnet process-death tests cover reorg recovery, not every historical fork or interruption inside a database commit. |
| **2 — UTXO snapshot bootstrap** | Supported consume/serve lifecycle. Trust-flag persistence tests do not verify an external trust root. A Scala-produced manifest/chunk set and independently reported header root are still needed to establish installation, tamper rejection with unchanged state, and reopen against an external snapshot. Cross-check the installed root with a known-good reference. |
| **3 — pruned UTXO** | Partial. Scala fixtures cover retention calculations and section eviction; native boot/reopen tests cover genesis-first downloads and guarded legacy-floor repair. They do not establish a complete historical genesis replay, pruning activation and restart lifecycle. |
| **4 — pruned + snapshot bootstrap** | Partial. Install/reopen and proof-first versus snapshot-first composition are tested. A deterministic three-peer test validates mainnet block 10 after a Rust-reconstructed block-9 snapshot and header catch-up, then reopens. This is neither a Scala-produced snapshot trust fixture nor a long-running live multi-peer soak. |
| **5 — digest verifier** | Partial. Full transaction/AD-proof replay covers a mainnet voting boundary and additional mainnet/testnet windows, including data inputs, rollback/replay and corrupted-proof rejection. Seeded windows are neither genesis replay nor cold-open historical reorg coverage; broader eras and complete rollback/index/parameter history remain required. Digest rollback history is currently unbounded; a retention change needs a supported-window contract and storage migration. |
| **6 — headers-only digest** | Supported header validation and sync. It does not download or validate full blocks and provides no UTXO state. |

Current regression entry points include the [Mode 3 lifecycle tests](../ergo-node/tests/it/mode3_lifecycle.rs),
[Mode 4 acceptance](../ergo-node/tests/it/mode4_acceptance.rs) and
[catch-up tests](../ergo-node/tests/it/mode4_catchup.rs),
[Mode 5 executor replay](../ergo-sync/tests/it/mode5_executor_replay.rs) and
[corpus breadth tests](../ergo-sync/tests/it/mode5_corpus_breadth.rs), and
[UTXO/digest interrupted-reorg recovery](../ergo-sync/src/executor/relay_tests.rs).
Early-mainnet recovery uses externally captured replacement blocks with a
synthetic abandoned fork. Synthetic AVL cold-reopen tests check root caching
and read bounds, rather than an external snapshot trust anchor.

Historical private UTXO mixed-node tests do not establish current-revision
Mode 4/5 live-soak coverage. The nightly JVM campaign and archival replay are
separate obligations; archival replay requires `REPLAY_NODE_URL`, and an unset
secret reports that replay was not tested. Workflow wiring alone does not
establish a successful external campaign.

The webhook connector checks every DNS answer, rejects mixed forbidden/public
answers, connects through the checked results and disables redirects/proxies.
Peer admission, handshake slots and dial selection share normalized IPv4 `/16`
or native IPv6 `/48` connection groups, including IPv4-mapped addresses. These
bounded policies and their regression tests do not expand the mode guarantees.

### Partial (landed but incomplete)

- **Mode 3 (pruned / suffix window)** — schema, handshake and
  `block_sections` eviction after apply have landed; a standard pruned
  config boots and replays full blocks from genesis before pruning (see
  below). A normal Mode 3
  (`state_type = utxo`, `verify = true`, `blocks_to_keep` at or above the
  rollback-window floor of `keep_versions + SAFETY_MARGIN`, i.e. 250 at
  the defaults) loads and runs. Only configurations that would undermine
  reorg safety are rejected at startup: sub-floor suffix windows,
  `blocks_to_keep < -1`, and `blocks_to_keep = 0` outside the canonical
  headers-only Mode 6 combo.

  **Fresh startup and retention.** A fresh UTXO store starts downloading
  full blocks at height 1, even when its header chain is already synced.
  Validation requires the applied parent state; a recent header alone cannot
  replace the skipped UTXO history. The node replays from genesis and advances
  `minimalFullBlockHeight` as blocks are applied and old sections are pruned.
  The applied-block retention formula is
  `max(1, applied_height - blocks_to_keep + 1)`, snapped down to the
  containing voting epoch's start when it exceeds `votingLength`.

  Older startup code could persist a header-derived floor before any full
  block was applied. Boot and sync ticks repair that floor to 1 only when
  both live and committed UTXO state remain at height 0, the header chain is
  dense and neither bootstrap marker is present, then rebuild pending
  downloads. A valid fresh floor is unchanged. Applied, snapshot and
  NiPoPoW-bootstrapped stores keep their floor; the ordinary setter remains
  monotonic. Repair failures are logged and retried. Archive
  nodes also download from their applied parent; headers-only Mode 6 does
  not download full blocks. Rollbacks below a retained floor are refused.

  This fresh-download policy is specific to the Rust UTXO backend. The
  committed Scala sentinel vectors cover retention calculations, while
  native boot/reopen tests cover the guarded repair and pending range.
  Complete historical activation and retention coverage remains open.
- **Mode 4 (pruned + UTXO bootstrap)** — builds on Mode 3 (landed) plus
  the Mode 2 snapshot bootstrap. Tests cover a real snapshot install through
  boot and both NiPoPoW/UTXO orderings: proof-first composes; snapshot-first
  rejects the later proof and preserves state
  (`ergo-node/tests/it/mode4_acceptance.rs`). A three-peer acceptance test now drives snapshot discovery parked above
  a NiPoPoW tip through real P2P header catch-up, snapshot installation, full
  validation of the next mainnet block, and restart
  (`ergo-node/tests/it/mode4_catchup.rs`). Long-running live multi-peer soak
  coverage remains outstanding.
- **Mode 5 (digest verifier)** — the storage schema, atomic-commit layer,
  and AD-proof apply seam exist; the node boots, survives the handshake,
  sync-info, and API seams, and syncs headers from live peers (the
  executor's header pipeline is backend-agnostic, so a digest store
  validates and persists headers exactly as a UTXO store does).
  AD-proof block replay is oracle-pinned against the mainnet voting-boundary
  window and additional mainnet/testnet windows in `test-vectors/mode5/`.
  The additional corpus exercises full transaction validation, root-preserving
  rollback/replay, and corrupted-proof rejection with unchanged committed
  state (`ergo-sync/tests/it/mode5_corpus_breadth.rs`). Broader historical-era
  coverage remains open. Bounded subprocess tests kill both digest and UTXO
  executors after rollback/partial apply and recover external early-mainnet
  replacement roots on reopen (`ergo-sync/src/executor/relay_tests.rs`).
  External-window cold-open reorg campaigns still need an owned database with
  complete historical rollback/index/parameter substrate.
- **Mode 2 trust anchor** — the installed UTXO root verification is
  provisional pending a Scala-oracle vector. Operators using Mode 2 should
  cross-check the bootstrapped UTXO root against a known-good reference
  before treating the state as authoritative.
- **`/emission` surface** — `GET /emission/at/{blockHeight}` is implemented
  (EIP-27-aware, differential-tested against live-Scala vectors at
  `test-vectors/api/emission/`); `GET /emission/scripts` is implemented on
  **mainnet** from verified contract-tree constants in `ergo-chain-spec`
  (oracle-pinned byte-for-byte against the live-Scala capture at
  `test-vectors/api/emission/scripts.json`; the emission tree cross-checks
  against the genesis emission box). Divergence: Scala's testnet serves
  three testnet addresses (its conf retains the reemission settings even
  though activation is unreachable); this build returns 404 there pending
  a testnet oracle capture.
### Out of scope by design

These are deliberate non-goals, not gaps.

- Not a wrapper around, or a line-by-line port of, the Scala node.
- Not a light client — the NiPoPoW bootstrap covers the fast-start case.
- Not an internal-CPU miner — the external-miner REST protocol is
  supported; an in-node mining loop is intentionally excluded.
- The cooperative distributed multi-signature round protocol is deferred —
  the signing primitives and hint-replay surface ship, but the multi-party
  interaction is not implemented.
- Scala's `consistentSettings` rule R4 (mainnet mining ⇒
  `checkReemissionRules`) has no analogue, because the node exposes no
  opt-out — the rule's antecedent is unreachable. The other four rules
  (R1, R2, R3, R5) are enforced at config load.

## Versioning and stability

While the version is `0.x.y`, **nothing is stable.** Configuration keys,
REST response shapes, log fields, persisted-state layouts, and crate APIs
may all change between minor versions. Treat every pre-1.0 upgrade as
potentially breaking:

- Back up your `data_dir` before upgrading. If a version bump changes the
  persisted-state layout, the upgrade may require a rebuild from genesis.
- Re-read [`CHANGELOG.md`](../CHANGELOG.md) before each upgrade — each entry
  calls out what moved.
- Pin to a specific tag, not `latest`.

Rust consumers upgrading to the `num-bigint 0.5` dependency must update their
own direct dependency if they exchange `BigInt` or `BigUint` with this workspace
(for example, through `SigmaValue`, evaluator values or difficulty helpers).
Types from `num-bigint 0.4` and `0.5` are distinct. This dependency upgrade does
not change the node's specified integer wire encodings.

## Reporting a consensus divergence

A consensus divergence — this node accepting a block the Scala reference
rejects, or rejecting one the reference accepts, or diverging on UTXO/AVL+
state — is the highest-severity class of bug for this project. Report it
**privately**, before any public disclosure or PR, via a GitHub Security
Advisory draft:
<https://github.com/arkadianet/ergo/security/advisories/new>.

Include the affected version (commit hash), reproduction steps, expected
versus observed behavior, and — for anything that could split the network —
whether you have shared the same finding with the Scala reference team.
Coordinated disclosure across both implementations is the right path for
any bug that could fork consensus. Full scope, required fields, and
response targets are in [`SECURITY.md`](../SECURITY.md).
