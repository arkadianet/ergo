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
| REST surface | A Scala-compatible REST surface (`/info`, `/blocks/*`, `/transactions*`, `/utxo/*`, `/peers/*`, `/utils/*`, the extra-index `/blockchain/*`, `/mining/*`, `/wallet/*`) alongside a node-native `/api/v1/*` operator API. JSON DTOs and canonicalizing decoders are anchored by a byte-parity oracle against the Scala JSON shapes. |

**Milestone.** Mainnet sync to tip was reached on 2026-04-26 at height
1,771,976, with state-digest parity at every height. Continued sync against
live mainnet has been part of the development loop since.

**Modes that boot today** (against the reference node's mode taxonomy):
Mode 1 (full archive), Mode 2 (UTXO snapshot bootstrap, consume and serve),
Mode 5 (digest verifier — boots and passes handshake/sync seams; full sync
stalls at the UTXO-typed executor header pipeline), and Mode 6 (headers-only
digest). NiPoPoW bootstrap (consume and serve),
the extra-index `/blockchain/*` surface, the external-miner mining protocol,
and an HD wallet (single-prover signing, BIP39 + BIP32, AES-GCM secret
storage) also ship. In operation, a combined Mode 2 + NiPoPoW boot from an
empty `data_dir` has been observed to complete in well under an hour on
mainnet — far faster than a multi-hour full IBD from genesis, though the
exact figure depends on peer and hardware conditions.

## How parity is checked

Three independent oracles, ranked by signal strength, with a strict rule
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

CI runs `cargo fmt --check`, `cargo check`, `cargo clippy --all-targets
--all-features -- -D warnings`, and `cargo test` across Linux, macOS, and
Windows on every push and pull request, plus the supply-chain auditors
`cargo-audit`, `cargo-deny`, and `cargo-machete`. See
[`.github/workflows/ci.yml`](../.github/workflows/ci.yml).

## Known limitations

Areas where parity is incomplete, partial, or deliberately out of scope.
Be aware of these before depending on the node.

### Partial (landed but incomplete)

- **Mode 3 (pruned / suffix window)** — schema, handshake, and
  `block_sections` eviction have landed; a standard pruned config boots.
  A normal Mode 3 (`state_type = utxo`, `verify = true`, `blocks_to_keep`
  at or above the rollback-window floor of 232) loads and runs. Only
  configurations that would undermine reorg safety are rejected at startup:
  sub-floor suffix windows (`blocks_to_keep` below 232), `blocks_to_keep <
  -1`, and `blocks_to_keep = 0` outside the canonical headers-only Mode 6
  combo.
- **Mode 4 (pruned + UTXO bootstrap)** — builds on Mode 3 (landed) plus
  the Mode 2 snapshot bootstrap; not yet wired.
- **Mode 5 (digest verifier)** — the storage schema, atomic-commit layer,
  and AD-proof apply seam exist; the node boots and survives the
  handshake, sync-info, and API seams. Full sync stalls at the UTXO-typed
  executor header pipeline (the AD-proof transaction-validation path is
  pending); external ADProof-corpus parity and reorg-abort hardening also
  remain open.
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
- **NiPoPoW** — complete: prover/verifier, P2P exchange + bootstrap, and
  the four `/nipopow/*` REST routes. Byte/JSON parity is pinned against
  genuine Scala-serializer fixtures, a live mainnet differential vs the
  reference node (all endpoints, genesis/epoch-boundary/v1-era heights,
  anchored proofs, error surfaces), scrypto batch-Merkle shape vectors,
  and a 132-header `maxLevelOf` oracle sweep. One documented deviation:
  the Scala node reports stale `header.size` metadata (+1) for some
  historical headers, contradicting its own served bytes; this build
  serves the true byte length.

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
