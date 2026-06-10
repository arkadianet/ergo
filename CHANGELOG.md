# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to follow [Semantic Versioning](https://semver.org/)
once it reaches 1.0. This is pre-1.0 alpha software: configuration keys,
REST shapes, and persisted-state layouts may break between minor versions.

This is an independent Rust reimplementation of an Ergo full node, not the
Scala reference node. It targets strict consensus compatibility (accept
every block Scala accepts, reject every block it rejects), verified against
Scala-produced fixtures and mainnet bytes — but verify its verdicts against
the reference node before relying on it for funds or production
infrastructure.

## [Unreleased]

## [0.4.0] - 2026-06-10

A large consensus-behaviour release. It closes the SANTA conformance effort —
the ErgoTree interpreter and serializer now match the Scala
`sigmastate-interpreter` reference bug-for-bug across the suite (`{value, cost,
error}`) — hardens the mining candidate path, and carries a security fix. As
always for this node: re-verify its verdicts against the Scala reference node
before relying on it for funds.

### Security

- **`SHeader` value support + ErgoTree-version threading
  (GHSA-hfj8-hjph-7r78).** Header values reaching script evaluation are now
  modelled and version-gated correctly (#31).

### Added

- **Scala-compat `GET /emission/at/{blockHeight}`** — per-height emission
  schedule data: `{height, minerReward, totalCoinsIssued, totalRemainCoins,
  reemitted}`, EIP-27-aware (mirrors `EmissionApiRoute.emissionInfoAtHeight`).
  Public route, mounted in every node mode; the cumulative-issuance primitives
  join `ergo-mining::emission_rules`, differential-tested against 17 vectors
  captured from a live Scala mainnet node. `GET /emission/scripts` remains
  unimplemented (its oracle capture ships for whoever picks it up) (#15).
- **Node mode identity on the overview page + real mining flag** (#11).

### Fixed

- **ErgoTree interpreter & serializer — consensus parity with the Scala
  reference (SANTA conformance).** ~40 bug-for-bug `{value, cost, error}`
  fixes across the sigma evaluator and `ergo-ser`, verified against the SANTA
  vector suite and the `sigmastate-interpreter` source. Highlights:
  - Numeric arithmetic — Int/Long overflow + div/mod, Byte/Short wrap, BigInt
    256-bit bounds + modulus, out-of-range v6 shift counts, pre-v3 mixed-kind
    operand auto-upcast, get/encode/negate/cast costs (#17, #19, #20, #21,
    #30, #54).
  - UnsignedBigInt carrier — arithmetic, `fromBigEndianBytes`, upcast,
    ordering (#34, #44).
  - AVL tree — graceful bad-proof outcomes for lookup + mutating ops,
    keyLength/valueLength signed-i32 wrap + allowed-op accessors,
    `updateDigest`/`updateOperations`, Scala cost models (#25, #28, #29, #42).
  - Equality & collection cost models — EQ/NEQ + indexOf, SigmaProp equality,
    SigmaAnd/Or evaluate-all-before-collapse, flatMap / indices / updateMany /
    Option.map (#30, #33, #36, #37, #41, #46).
  - `Global.serialize` for Box / AvlTree / Header, `substConstants`,
    DecodePoint curve validation + identity canonicalization (#38, #39, #40,
    #43).
  - Box / Header / register access — SBox value + real txid/index, register
    reads enforce the requested type, `getReg` dynamic index + getRegV5
    reject, `Header.stateRoot` AvlTree flags, zero-arg v6 method dispatch
    (#23, #32, #45, #49, #50, #51).
  - SOption — requires ErgoTree v≥3, any nonzero discriminant is `Some`
    (#24, #47).
  - Other opcode semantics — ByIndex eager (pre-v3) / lazy (v3+) default,
    CreateTuple arity≠2 reject, HOF function values + `hasDeserialize`
    reduction fork, canonical `0x0c0c` prefix for `Coll[Coll[..]]` (#18, #22,
    #48, #52).
- **`atLeast` with a trivial-prop child no longer panics the verifier** — it
  now folds trivial children per Scala `AtLeast.reduce`. Was a reachable
  consensus-path panic + divergence on a crafted-but-plausible spend (#53).
- **Soft-fork-disabled validation rule 215 (unknown header votes) honored**
  (#16).
- **Unknown paths answer a plain `404`, not `403 invalid.api-key`.** Route
  middleware now mounts via `route_layer` (matched routes only); Scala's
  whole-prefix key gating survives via explicit `/wallet/*` and `/node/*`
  catch-alls.
- **Digest-mode (Mode 5/6) survival** — no longer crashes on the first
  `sync_tick`, handshake, or API seam (#8); P2P delivery-tracker type-shadow
  bound (#6).

### Performance

- **Mining candidate generation — from ~seconds to near-instant on the hot
  path.** A per-tip pristine AVL base cache + single-step incremental advance
  + minimal-first publish collapse the candidate dry-run, and the cold /
  cache-miss rehydrate now streams `AVL_NODES` sequentially (readahead-
  friendly) instead of pointer-chasing. With `[mining] candidate_base_cache =
  true`, same-tip / mempool-driven rebuilds reuse the resident tree — a
  multi-GB full rehydrate (minutes under memory pressure, which starved
  external miners with `/mining/candidate` 503s) becomes a ~16 ms reuse
  (#7, #9, #12, #55).

## [0.3.0] - 2026-06-03

First public release of the independent Rust Ergo full node. Rolls up all
development since 0.2.1: the browser wallet UI, the off-loop mining-candidate
engine and zero-fee storage-rent self-claim, digest/headers-only modes (5/6),
EIP-50 / Sigma 6.0 consensus work, the extra-index parity surface, and the full
documentation set (README, ARCHITECTURE, per-crate codebase map).

### Added

- **Browser Wallet UI at `/wallet/ui`** — a static-asset wallet front end
  served by the node's axum app, mirroring the operator dashboard chassis
  (vanilla HTML + ES2017 JS + CSS, embedded via `include_str!`, no build
  chain). The browser is a thin remote control for the existing `/wallet/*`
  REST API: it never holds the master key, derives, or signs.
  - Routes: `GET /wallet/ui`, `GET /wallet/ui/index.html`,
    `GET /wallet/ui/wallet.js`.
  - The UI mount sits on the public operator router, deliberately **outside**
    the `api_key`-gated `/wallet/*` subtree — the page carries no secrets and
    authenticates each `/wallet/*` call with the key the operator pastes in.
    The `api_key` lives only in `sessionStorage` and is sent via the `api_key`
    header; mnemonics live only in the DOM and are never persisted.
  - A response-header layer applies a strict CSP
    (`default-src 'self'; img-src 'self' data:; style-src 'self'
    'unsafe-inline'; script-src 'self'`) plus `Cache-Control: no-store`,
    `Pragma: no-cache`, and `Referrer-Policy: no-referrer` to the bare mount
    and every sibling asset. These headers cover `/wallet/ui*` only, not the
    dashboard at `/`.
  - Surfaces lifecycle (status / unlock / lock), init / restore with an
    explicit post-unlock step, balances / addresses, payment send (with a
    confirm modal), `deriveNextKey`, and `updateChangeAddress`.
  - Tests pin the auth scope (UI public while `/wallet/*` stays `403`), the
    security headers (and their absence on the dashboard), and the
    init/restore → unlock request contract.

- **Mode 5 (digest verifier) — partial, not yet bootable.** This is an
  independent reimplementation of Scala's `StateType.Digest` backend that
  validates transactions via AD-proofs instead of holding box bytes, keeping
  only a 33-byte authenticated UTXO root plus a per-height history ledger.
  The schema, persistence sibling, proof-verifier, and apply seam have
  landed but are `pub(crate)` and unwired into boot dispatch. The runtime
  mode gate rejects any non-canonical-Mode-6 digest config, so Mode 5 cannot
  be selected today.
  - `DigestProofVerifier` helper with full ADProofs binding.
  - Net-`boxChanges` apply seam plus a Mode 1 parity oracle.
  - `DigestStateStore` persistence sibling to `StateStore`, mirroring the
    same single-redb-write-transaction atomic-commit invariant over its own
    ledgers.
  - `StateBackend` trait family (`ChainStateRead` / `HeaderSectionStore` /
    `BlockApply`) abstracting the UTXO and digest persistence backends so the
    single-writer action loop can later dispatch on `state_type`. `StateStore`
    implements all three by delegating to its existing inherent methods; no
    consumer binds the traits yet (additive, no behavior change).

- **Mode-aware `/utxo/*` route subtree + unsupported-subsystem gates.** Under
  the digest backend (`state_type = "digest"`), the six `/utxo/*` lookup
  routes (`genesis`, `byId`, `byIdBinary`, `withPool/byId`,
  `withPool/byIdBinary`, `POST withPool/byIds`) mount with the same
  path/method shapes but return `503` with reason
  `"Lookup is not supported for stateType=digest"` instead of resolving boxes.
  Config load additionally rejects `[mining] enabled` and `[indexer] enabled`
  when `state_type = "digest"`. (The `503` envelope is locally authored — no
  Scala oracle pin yet.)

- **Mode 4 (pruned + UTXO bootstrap) — partial.** `NodeMode` classifier over
  the full cross-product of `(state_type, verify_transactions, blocks_to_keep,
  utxo_bootstrap, nipopow_bootstrap)`, install-once semantics for the UTXO
  snapshot (`UTXO_BOOTSTRAP_INSTALLED_V1` marker), a NiPoPoW-resume truth
  table, an operator-facing mode label, and a captured NiPoPoW proof test
  fixture. Mode 4 builds on Mode 3 plus this bootstrap path.

- **Mode 3 (pruned / suffix window) — partial.** Pruning activation
  envelope landed across `ergo-state` / `ergo-node` / `ergo-sync`: the prune
  sentinel infrastructure, a `SECTION_HEIGHT_INDEX`, bootstrap-aware sentinel
  seeding on the writer side, and end-to-end activation parity across the
  coordinator / executor / storage path. The prune-window floor formula
  (`blocks_to_keep >= ROLLBACK_WINDOW + SAFETY_MARGIN`) is pinned against a
  Scala-source-derived parity test and a Scala-runtime oracle. `/api/v1/identity`
  refreshes the live mode. The `block_sections` eviction job is still pending,
  so Mode 3 remains gated.

- **HD wallet (`ergo-wallet` crate) with a Scala-compatible `/wallet/*` REST
  surface.** All 27 `WalletApiRoute` endpoints are mounted and respond with
  well-formed Scala-compatible JSON. Single-prover signing, AES-GCM secret
  storage, BIP39 + BIP32 / EIP-3 derivation, and the multi-sig primitive
  surface are in place; the cooperative distributed multi-signing protocol is
  deferred (primitives and hint-replay ship, the multi-party dance does not).
  - **Key derivation.** BIP39 mnemonic generation / import, post-1627 BIP32
    HD derivation for modern / fresh wallets, BIP44 Ergo coin-type 429,
    pubkey → P2PK address rendering, and a `cargo run -p ergo-wallet --bin
    ergo-wallet` CLI with `generate` / `import` / `derive` / `pubkey` /
    `address` subcommands (operators can generate `miner_public_key_hex` for
    `[mining]` config without external tooling). Backed by `k256` +
    `hmac-sha512` + `bip39`; no `sigma-rust` runtime dependency. Also ships
    pre-1627 (`ExtendedSecretKeyLegacy`) derivation for legacy Scala wallet
    import compatibility, matching the Ergo issue #1627 derivation behavior.
  - **Encrypted secret storage + view-only scan.** `encryption.rs`
    (PBKDF2-HMAC-SHA512 128k + AES-256-GCM), `storage.rs` (Scala-compatible
    `<data_dir>/wallet/<uuid>.json` matching `JsonSecretStorage`), and an
    in-memory `WalletState`. Wallet tables live in the same `state.redb` as
    chain state (apply + rollback atomic with chain mutation); output
    classification follows `WalletScanLogic.scala` (Owned / MinerReward +
    maturity / Custom / ignored) with mining-reward maturity gating
    (`REWARD_MATURITY_MAINNET = 720`). The wallet runs as a single-writer
    task (`run_wallet_writer`) behind the channel-backed `NodeWalletAdmin`
    bridge.
  - **Send + proving.** Transaction building, box selection
    (`DefaultBoxSelector` greedy ascending-value with exact change and
    multi-asset support), and a Sigma proving engine: Schnorr (`ProveDlog`)
    and DH-tuple (`ProveDHTuple`) proofs with Fiat-Shamir challenges, AND / OR
    compound composition, and threshold (k-of-n) proofs via Lagrange
    interpolation over GF(2^192). Send routes: `POST /wallet/payment/send`,
    `POST /wallet/transaction/{send,generate,generateUnsigned,sign}`, and
    `POST /wallet/boxes/collect`. Every signed tx passes a mandatory tx-level
    self-verify gate (`verify_spending_proof_with_context_and_cost` per input)
    before submission. A locked wallet can still sign via the external-secret
    lock-matrix path when an `ExternalSecretDto` array covers all input
    propositions.
  - **Multi-sig primitives + advanced HD.** `generate_commitments_for` /
    `bag_for_multisig` (and their tx-level wrappers) mirror Scala
    `ProverUtils.generateCommitmentsFor` / `bagForTransaction`, with a
    `NodePosition` type for hint disambiguation across compound Sigma trees.
    `prove_sigma` consumes `OwnCommitment` / `RealSecretProof` /
    `SimulatedSecretProof` from a supplied `HintsBag`, matching leaves by
    `(image, position)`. REST: `POST /wallet/generateCommitments`,
    `POST /wallet/extractHints`, `POST /wallet/deriveKey`,
    `GET /wallet/deriveNextKey`, and `POST /wallet/getPrivateKey` (returns the
    raw scalar only when `[wallet] expose_private_keys = true`, otherwise
    `403`).
  - **Wallet sync mode.** Ships in rescan-on-demand plus an incremental
    per-block apply / rollback hook wired through production apply and
    rollback atomically with chain mutation. Full multi-party distributed
    signing (2-of-3, dApp commitment exchange) and the
    `ReplaceCompactCollectBoxSelector` compaction algorithm remain deferred.

### Changed

- **Documentation: `ergo-api::types` module gains an id-encoding
  contract section** — pins the lowercase-hex, no-`0x`-prefix convention
  across the operator API surface and groups the load-bearing id- and
  root-shaped String fields by width: 32 bytes / 64 hex chars for every
  id and content hash (`header_id`, `parent_id`, `tx_id`, `box_id`,
  `token_id`, `manifest_id` — all `Digest32` under the hood per the
  shared `ergo-indexer-types` aliases); 33 bytes / 66 hex chars for
  `state_root_avl` (`Digest32 || balance-byte`). No code or wire
  changes — this is a reader-facing contract that was previously
  implicit. Numeric fields on this surface (peer score, heights,
  timestamps, n_bits) wire as JSON numbers, not hex.
- **`/api/v1/mempool/{submit,check}` rejection body drops the `error` field** —
  the Rust-native error envelope is now `ApiNativeSubmitError`
  (`{reason, detail?}`) instead of `ApiSubmitError`
  (`{error, reason, detail?}`). The dropped `error: u16` field
  duplicated the response's HTTP status code (e.g. body `error: 400`
  on a `400 Bad Request` response), which Rust-native clients already
  read from the response status line. Scala-compat
  `POST /transactions`, `/transactions/bytes`, `/transactions/checkBytes`
  still emit the full `ApiSubmitError` shape for Scala-client parity.
  Internally the conversion is a one-line `From<ApiSubmitError>`
  impl, so the existing `map_submit_error` mapping table stays the
  authoritative source of `(StatusCode, reason)` pairs.
- **`/api/v1/mempool/transactions.size` removed** — the envelope's `size`
  field was a literal duplicate of `transactions.len()` (the producer
  emitted `transactions.len() as u32`). Clients read the array length
  directly. Saves a u32 per response and removes the only fail point
  where the count and the array could drift. Scala-compat
  `/transactions/unconfirmed` (which returns a bare array, no envelope)
  is unaffected. The Scala-compat bridge's internal `pool_size()`
  helper now derives the count from `.transactions.len()` instead of
  reading the dropped field.
- **`/api/v1/tip.best_full_block.state_digest` renamed to `state_root_avl`** —
  the old name was ambiguous now that the same struct also carries
  `n_bits` and `difficulty` (added in the dashboard difficulty/hashrate
  work); a reader could reasonably assume `state_digest` was a digest
  *of the header* (cumulative score / header hash) rather than the AVL+
  authenticated UTXO-tree root. The value is unchanged (33-byte
  `Digest32 || balance-byte` payload, hex-encoded, 66 chars) and matches
  the on-chain `Header.stateRoot` field. Clients reading
  `tip.best_full_block.state_digest` must read `state_root_avl`
  instead. Scala-compat `/info` already exposes this value as
  `stateRoot`; that surface is unaffected and the bridge layer reads
  from the renamed field internally.
- **`/api/v1/identity.bootstrap_status` enum tightening + field rename** —
  three `String` fields become typed enums and one field is renamed:
  - `.phase` becomes `ApiBootstrapPhase` (`"discovery"` /
    `"manifest_requested"` / `"manifest_verified"` / `"downloading_chunks"` /
    `"reconstructing"` / `"installing"` / `"post_install_catchup"`).
  - `.popow_phase` becomes `Option<ApiPopowPhase>` (`"requesting"` /
    `"quorum_met"` / `"applied"` / `"catchup"`); the field is omitted from
    the JSON when `None` (which is the only value the producer emits today,
    until the popow_bootstrap reducer is wired in Part 2 §14.6).
  - `.history_mode` is **renamed to `.header_availability`** and becomes
    `Option<ApiHeaderAvailability>`. The variants serialize as
    `"sparse"` (NiPoPoW dense-suffix header section) and `"dense"` (full
    history from genesis), and the field is omitted from the JSON when
    `None` — today the producer only ever emits `Some("sparse")` or
    omits the field for the Dense store reading. The old name collided
    with `/api/v1/identity.history_mode` (`ApiHistoryMode`, a different
    concept: archive / utxo-bootstrapped / headers-only / pruned). The
    new name reflects what the field actually reports — whether the
    on-disk header section is dense from genesis or sparse with a
    NiPoPoW dense-suffix anchor. Wire strings for the values the
    producer can emit today are unchanged from the previous String
    emission; the schema is now exhaustive and the producer in
    `snapshot_emit::build_bootstrap_status` can no longer drift from
    the consumer set by typo. Clients consuming
    `bootstrap_status.history_mode` must read `header_availability`
    instead. Scala-compat `/info` does not expose any of these fields.
- **`/api/v1/identity.state_type` is now a typed enum** — `"utxo"` /
  `"digest"` were already the only documented values, but the wire field
  was a free `String`. The new `ApiStateType` enum encodes those two
  variants directly; clients pattern-matching on the string set lose
  nothing and gain a typed schema entry in the OpenAPI document.
- **`/api/v1/peers[].direction` and `.state` are now typed enums** —
  `direction` becomes `ApiPeerDirection` (`"inbound"` / `"outbound"`);
  `.state` becomes `ApiPeerState` (`"connecting"` / `"handshaking"` /
  `"active"` / `"degraded"` / `"disconnected"`). Wire strings are
  unchanged from the previous String emission, but the schema is now
  exhaustive and the producer match in `snapshot::project_peer` no
  longer can drift from the consumer set by typo. Scala-compat
  `/peers/{all,connected}` is unaffected (its own `connection_type`
  string is mapped from `ApiPeerDirection` at the bridge layer).
- **`/api/v1/host` byte fields are now `Option<u64>`** — `rss_bytes`,
  `state_db_bytes`, `index_db_bytes`, `disk_free_bytes`, and
  `disk_total_bytes` wire as `null` when the underlying measurement fails
  (sysinfo refresh failure, missing file, indexer disabled, mount point not
  in sysinfo's disk list). `Some(0)` now unambiguously means a legitimately
  zero measurement. Previously all five wired as `0` for both "could not
  determine" and "legitimately zero," which broke monitoring scrapers that
  pattern-matched `0` as "disk full" or "process died." Clients reading
  `/api/v1/host` must null-check these fields. Scala-compat `/info` is
  unaffected. The `NodeReadState::host()` trait default body now returns all
  measurable fields as `None` instead of all-zeros, matching the new
  semantics.
- **`/api/v1/mempool/transactions[/{tx_id}]` `.source` field is now a tagged
  union** — wires as `{"kind": "peer", "addr": "..."}` for the peer-relayed
  case, or `{"kind": "<api|wallet|demoted_from_block>"}` for the unit
  variants. Previously a flat string (`"peer:1.2.3.4:9030"` / `"api"` /
  `"wallet"` / `"demoted_from_block"`) that clients had to split on `:`.
  Clients must switch on `source.kind` and read `source.addr` only when
  `kind === "peer"`. Scala-compat `/transactions/unconfirmed[/{id}]` is
  unaffected (Scala does not expose a source field).
- **`/api/v1/mempool/transactions[/{tx_id}]` cost / weight field renames +
  new envelope `weight_function`**:
  - `cost` → `validation_cost_units` on each `ApiMempoolTransaction` —
    sigma-interpreter execution cost in block-budget units (compare against
    the active epoch's `maxBlockCost`).
  - `weight` → `priority_weight` on each `ApiMempoolTransaction` —
    mempool-ordering scalar `(fee × 1024) / denom`, where `denom` depends on
    the configured weight function.
  - New `weight_function` field on the `ApiMempoolTransactions` envelope —
    one of `"cost"` / `"size"` / `"min"`. The boot path converts the
    configured weight function via `TryFrom<&str>`; an unknown name fails the
    boot loudly (no silent fallback). Empty-pool snapshots still emit the
    envelope field. Scala-compat `/transactions/unconfirmed[/{id}]` is
    unaffected.
- **`/api/v1/identity.blocks_to_keep` replaced with structured `history_mode`
  tagged union** — was an `i32` carrying sentinel values (`-1` = full
  archive, `-2` = utxo-bootstrapped, `N >= 0` = pruned suffix length). Now a
  tagged object: `{"kind": "archive"}` / `{"kind": "utxo_bootstrapped"}` /
  `{"kind": "headers_only"}` / `{"kind": "pruned", "suffix_len": N}`.
  Semantics are config-intent only (what `NodeConfig` asked for at boot); to
  observe runtime progress, read `fullHeight` / `bestFullHeaderId` on
  adjacent endpoints. Clients must switch on `history_mode.kind`. Scala-compat
  `/info` is unaffected (Scala emits `blocksToKeep` as a numeric field there).
  The `history_mode` value is projected once at boot from the node's
  configured intent, so it can be reasoned about against a fixture config
  without booting a node.

## [0.2.1] - 2026-05-10

### Added
- Operator dashboard rewrite (`ergo-api/web/`) — multi-pane layout with
  hero status strip, sync pipeline (3 fills: headers / blocks / indexer),
  identity grid, time-series charts (block height / block time / mempool
  depth), recent-blocks list, host-resources strip, mempool fee
  histogram, and peer-composition distribution bars. Live data only —
  no mocks; missing endpoints render `—` with a `mock` pill until they
  ship. Three themes (dark / light / contrast), per-panel toggles.
- `GET /api/v1/identity` — node mode (state_type, verify_transactions,
  blocks_to_keep, utxo_bootstrap, nipopow_bootstrap), mining flag,
  extra-index / submission toggles, declared and bind addresses.
  Captured at boot from `NodeConfig` + the hardcoded `Mode` peer-feature.
- `GET /api/v1/host` — process RSS, on-disk size of `state.redb` and
  `indexer.redb`, free / total bytes on the data-directory volume.
  CPU / network / load fields reserved; sampling cadence to land in a
  follow-up.
- `ApiPeer` extended with optional `bytes_in`, `bytes_out`,
  `peer_height`. Schema-only — populating these requires p2p layer
  cumulative byte counters and SyncInfo height plumbing (deferred).
- Workspace-wide structured logging via `tracing` with rolling-file
  output, JSON format option, and per-handler correlation spans
  (`validate_block`, `apply_block`, `admit`, `admit_check`, `msg`,
  axum HTTP request).
- `[logging]` TOML section with `default_level`, `format`, and
  `[logging.file]` (dir, prefix, rotation cadence, max retention).
- Typed `BridgeError` for the Scala-compat encoder layer; preserves
  upstream `ReadError` / `WriteError` / `StateError` source via
  `#[source]` instead of flattening to a `String`.
- Typed `PeerOrigin::{Seed, Gossip}` replacing the `from_seed: bool`
  parameter / field across `ergo-p2p`. Wire-format flag-bit unchanged.
- `SECURITY.md`, `CHANGELOG.md`, `rust-toolchain.toml`.
- Per-test span-emission tests pinning the `#[instrument]` contract
  on the four hot-path entry points.
- `expectedConsensusBranch` (`wholeBoxTake` / `recreateWithFee` /
  `overflowInverted`) and `practicallyCollectable` boolean on every
  storage-rent eligibility entry. Replaces the `subsidyRequired` /
  `profitableNoSubsidy` pair, which were misleading: the i32-wrap
  case ("subsidy required") forces the recreate branch with a
  required output value at the original owner's ergoTree, so the
  "subsidy" is an unrecoverable gift, not a bridge loan a miner
  recoups. The `overflowInverted` value flags boxes that consensus
  rules nominally accept for collection but no rational party
  collects in practice — the actual data shape needed to filter
  "things a rent collector will work on" vs "consensus dust." Also
  adds `consensusFeeOverflow: bool` and `mathematicalStorageFee: i64`
  for clients that want to see the un-wrapped product.
- **Breaking** (alpha API): the response shape of every
  `/blockchain/storageRent/*` endpoint changed by this rename. No
  v1 client commitments exist yet; consumers tracking master should
  switch to the new fields.
- `unspent_by_creation_height` indexer table (storage-rent eligibility
  slice 1): apply/rollback hooks insert/delete in the same redb txn
  as `INDEXED_BOX`; `INDEXER_SCHEMA_VERSION` bumped 1 → 2 (existing
  v1 DBs are wiped + resynced on first boot).
- `GET /blockchain/storageRent/eligible?height={H}&offset=&limit=&sortDirection=`
  (storage-rent eligibility slice 2): paged list of unspent boxes
  with `creationHeight ≤ H − StoragePeriod`, each carrying
  consensus-correct `storageFeeI32`, `mathematicalStorageFee`,
  `consensusFeeOverflow`, `expectedConsensusBranch`,
  `practicallyCollectable`, `rentOwed`, and `minRecreatedOutputValue`.
  Mounts only when `[indexer] enabled = true`
  AND the bridge supplies a `ChainParamsView`. Rust-node-exclusive;
  no Scala equivalent.
- `ChainParamsView` API trait + `ergo_validation::storage_rent::compute_storage_fee`
  helper. Both consumers — block validation and the API endpoint —
  reach the same i32 wrapping multiplication, so the API never
  diverges from the consensus path on wrap-eligible boxes.
- `ChainStoreReader::active_params_at` pass-through, used by the
  storage-rent endpoint's voted-params lookup.

### Changed
- Mempool notifier `TooFarBehind` / `ReorgTooDeep` errors during IBD
  are logged at `debug` level (down from `warn`) — the mempool is
  IBD-gated anyway, so the diff path is throwaway during catch-up.
  `MissingSections` (a real chain-index inconsistency) stays at warn.
- `PersistPipeline::send` returns `Result<(), StateError>`; previously
  panicked on a closed worker channel, now propagates so the caller
  can shut down cleanly on disk-full / redb fsync failure.
- `ChainStoreReader::header_id_at_height` renamed to
  `get_header_id_at_height` to match the `get_*` convention used by
  every other inherent read on the struct.

### Fixed
- Block validation: `BlockUtxoOverlay::get_box_from_base` now resolves
  data inputs through the union of pre-block UTXO + intra-block
  creates. Previous behavior incorrectly excluded boxes created by
  earlier transactions in the same block; mainnet block 422,179 (tx 2
  data-inputs a box with `settlementHeight = 422,179`) is the proof.
- `ergo-node` startup no longer panics on a duplicate
  `tracing_log::LogTracer::init()` install. `tracing-subscriber`'s
  default features already pull in the bridge.

### Removed
- 8 stale `#[allow(dead_code)]` annotations in `ergo-indexer/src/store/*.rs`.
  Four functions (`write_box`, `write_numeric_box`, `write_numeric_tx`,
  `write_tx`) deleted as truly unused; the other four (`write_address`,
  `delete_address`, `write_spill`, `delete_spill`) gated under
  `#[cfg(test)]` to match their actual call surface.
