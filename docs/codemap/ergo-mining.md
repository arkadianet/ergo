# ergo-mining

**Purpose:** External-miner-side block production for the Ergo Rust node:
assembles consensus-correct block candidates against the committed UTXO tip
(coinbase + emission/reemission, mempool tx selection, optional storage-rent
self-claim, AVL dry-run), serves work messages, and accepts Autolykos v2
solutions back through the block-apply path. No internal CPU miner, no wallet.

**Depends on (workspace):** ergo-primitives, ergo-ser, ergo-chain-spec,
ergo-crypto, ergo-validation, ergo-state, ergo-mempool
**Depended on by:** (see codemap index)
**Approx LOC:** ~7,670 (src only)

## Start here
- `generate_candidate` (`src/candidate.rs:113`) — the orchestrator; read this
  to see the whole assembly flow end to end (pre-header → coinbase → rent →
  mempool selection → fee tx → AVL dry-run → header + work message).
- `MiningHandle` (`src/handle.rs:88`) — the API-task-facing entry point and
  bounded-ring candidate cache; the seam between the off-loop engine and the
  REST handlers.
- `src/engine.rs` — the off-loop build driver (`build_and_publish`, `BestTip`,
  `BuildIntent`, `BuildOutcome`); explains the commit-visibility/CAS-publish
  consensus-safety story.
- `verify_solution` + `apply_mined_block` (`src/solution.rs:83`,
  `src/submit.rs:81`) — the two-stage solution acceptance path (API pre-check,
  then executor-side authoritative apply).
- `CandidateStateView` (`src/state_view.rs:42`) — the read trait that lets the
  same builder run on-loop (`StateStore`) or off-loop (`CommittedSnapshot`).

## Modules
- `src/lib.rs` — module tree + re-exports (`MiningConfig`, `MiningError`,
  emission helpers, `reward_output_script`).
- `src/candidate.rs` — block-candidate orchestrator (`Candidate`,
  `generate_candidate`); composes every other module into a finished candidate.
- `src/engine.rs` — off-loop candidate engine core: one committed snapshot,
  commit-visibility gate, `generate_candidate`, CAS-publish.
- `src/handle.rs` — `MiningHandle`: bounded template-ring cache, tip CAS,
  serve/verify, longpoll notify, reward-key resolution.
- `src/config.rs` — `MiningConfig` (parsed `[mining]` TOML) + `validate`.
- `src/error.rs` — `MiningError` taxonomy.
- `src/state_view.rs` — `CandidateStateView` trait; impls for `StateStore`
  (on-loop) and `CommittedSnapshot` (off-loop).
- `src/coinbase.rs` — pre-EIP-27 emission tx + fee-collecting tx; mainnet
  fee-proposition bytes.
- `src/reemission.rs` — EIP-27 at-activation / post-activation emission txs
  and `reemission_for_height`.
- `src/emission_rules.rs` — per-height emission math (`emission_at_height`,
  `miners_reward_at_height`); re-exports `MonetarySettings` from chain-spec.
- `src/emission_box.rs` — locate the current emission box (tx[0].out[0] of the
  parent block) for the next candidate to consume.
- `src/reward_script.rs` — build the canonical 54-byte reward-output ErgoTree
  (`SigmaAnd(GE(Height, creationHeight+720), proveDlog(pk))`).
- `src/candidate_selection.rs` — `CandidateOverlay` (in-block UTXO overlay) +
  `select_user_txs` (greedy priority-order mempool selection).
- `src/tx_selection.rs` — pure budget-tracking selection half
  (`select_by_budget`, `DEFAULT_COST_SAFETY_GAP`).
- `src/extension_builder.rs` — candidate Extension fields (NIPoPoW interlinks);
  epoch-boundary encoding deferred.
- `src/storage_rent_claim.rs` — miner-side zero-fee storage-rent self-claim
  builder (`build_rent_claim`, `build_budget_bounded_rent_claim`).
- `src/work_message.rs` — typed `WorkMessage` / `MinerSolution` (JSON-free).
- `src/solution.rs` — API-side solution pre-check (`verify_solution`,
  `SolutionOutcome`, `SubmittedBlock`).
- `src/submit.rs` — executor-side block-section persistence + authoritative
  parent recheck (`apply_mined_block`, `MiningSubmitRequest`).

## Key types, traits & functions
- `generate_candidate` (fn) — assemble the next candidate from a
  `CandidateStateView` — `src/candidate.rs:113`
- `Candidate` (struct) — cached candidate (header w/ placeholder solution,
  validation ctx, txs, AVL proof bytes, extension, `msg`, `target`, parent) —
  `src/candidate.rs:63`
- `MiningHandle` (struct) — bounded-ring cache + tip CAS + serve/verify —
  `src/handle.rs:88`
- `RewardKeySource` (enum) — `Pinned([u8;33])` or `Wallet` (lazy EIP-3) —
  `src/handle.rs:53`
- `build_and_publish` (fn) — off-loop build of one intent into the served cache
  — `src/engine.rs:178`
- `BestTip` (struct) — authoritative tip + synced bit (`parent_id`,
  `chain_seq`, `synced`) — `src/engine.rs:51`
- `BuildIntent` (struct) — loop-resolved build request (expected parent,
  mempool snapshot, miner pk, rent boxes) — `src/engine.rs:74`
- `BuildOutcome` / `TemplateIdentity` / `Template` (enum/structs) — engine
  result, template versioning, published template — `src/engine.rs:131,98,122`
- `CandidateStateView` (trait) — committed read surface for the builder —
  `src/state_view.rs:42`
- `MiningConfig` (struct) — parsed `[mining]` section; `validate` —
  `src/config.rs:19`
- `MiningError` (enum) — error taxonomy (InvalidConfig, HexDecode, WrongLength,
  IdComputation, Decode, EmissionInvariant, StateRead, InvalidMinerPublicKey,
  HeaderSerialization) — `src/error.rs:34`
- `WorkMessage` / `MinerSolution` (structs) — typed external-miner I/O;
  `MinerSolution::from_hex` — `src/work_message.rs:15,31`
- `verify_solution` (fn) → `SolutionOutcome` (Accepted/InvalidPow/StaleParent),
  `SubmittedBlock` — `src/solution.rs:83,43,62`
- `apply_mined_block` (fn) — persist sections + authoritative parent recheck;
  `MiningSubmitRequest`, `MiningSubmitError` — `src/submit.rs:81,29,39`
- `reward_output_script` / `reward_output_script_from_hex` (fns) — canonical
  reward ErgoTree bytes; `REWARD_SCRIPT_LEN = 54` — `src/reward_script.rs:82,93`
- `emission_at_height` / `miners_reward_at_height` (fns) — emission curve;
  `COINS_IN_ONE_ERGO` — `src/emission_rules.rs:33,49`
- `build_pre_eip27_emission_tx` / `build_fee_tx` (fns) — coinbase + fee tx —
  `src/coinbase.rs:66,148`
- `build_post_eip27_emission_tx` / `build_activation_emission_tx` /
  `reemission_for_height` (fns) — EIP-27 emission paths — `src/reemission.rs`
- `CandidateOverlay` / `select_user_txs` (struct/fn) — in-block overlay +
  greedy mempool selection — `src/candidate_selection.rs:46,164`
- `build_rent_claim` / `build_budget_bounded_rent_claim` (fns) — zero-fee
  storage-rent self-claim — `src/storage_rent_claim.rs:90,264`

## Invariants & contracts
- **Synced-tip gate.** Candidates are only built and served while `synced(tip)`
  (a committed full block exists and the header tip equals it). There is no
  `offline_generation` bypass — mining at an unsynced tip produces
  script-divergent candidates and is forbidden (`config.rs`,
  `engine.rs::should_publish`, `handle.rs::cached_work_if_synced`).
- **Single committed view per build.** Every consensus-bearing read flows
  through `CandidateStateView`; the off-loop engine sources all reads from one
  `CommittedSnapshot` (a single redb read txn) so the build can't splice inputs
  across a commit boundary. The off-loop build is proven byte-identical to the
  on-loop build for the same committed tip (`state_view.rs`).
- **Wrong-parent never served.** The tip lives inside the cache lock; publish
  CAS-checks the live tip under that lock, and serve scans newest-first for a
  template whose parent equals the current tip. A reorg/advance during a build
  wastes the work rather than serving a wrong-parent candidate
  (`handle.rs::publish_if_current` / `cached_work_if_synced`).
- **Two-stage solution acceptance.** `verify_solution` runs the PoW pre-check
  (`hit_for_v2 <= target`) and a fast-fail parent-id check off the loop;
  `apply_mined_block` re-checks parent-id under the action-loop lock as the
  authoritative TOCTOU close before persisting sections (`solution.rs`,
  `submit.rs`).
- **Block order + budget.** Block tx order is `[emission, (rent), ...user txs,
  fee]`. The pinned coinbase+rent prefix and mempool selection are bounded by
  the voted `max_block_cost`/`max_block_size` (the AVL dry-run checks neither);
  selection stops `DEFAULT_COST_SAFETY_GAP` below the cost ceiling, and the
  assembly trims the lowest-priority tail tx until the `BlockTransactions`
  section fits (`candidate.rs`, `tx_selection.rs`).
- **Storage-rent self-claim.** Pinned ahead of mempool selection so any
  conflicting fee-bearing claim on the same box is excluded; zero fee; mirrors
  `ErgoInterpreter.checkExpiredBox` (empty proof, var-127 output index,
  `box_age >= storage_period`, recreate-vs-seize on `value` vs `storageFee`).
  Boxes whose fee wraps negative are consensus-uncollectable and skipped; the
  builder only returns transactions the validator accepts (`storage_rent_claim.rs`).
- **Emission / reemission parity.** Per-height emission and reward math, the
  reward-output ErgoTree (pk at byte offset 7..40, 54-byte total), and the
  EIP-27 emission-tx shapes are byte-parity-verified against captured mainnet
  fixtures (`emission_rules.rs`, `reward_script.rs`, `reemission.rs`).
- **Coverage gaps (by design).** Epoch/voting boundary candidates
  (`H % 1024 == 0`) are rejected — the proposed-update + validation-settings
  extension encoding is deferred; an internal CPU miner is not implemented
  (`use_external_miner` must be `true`) (`extension_builder.rs`, `config.rs`).
