# ergo-validation

**Purpose:** L3 consensus-acceptance crate. Decides whether a header, block, or transaction is *legal* — structural / monetary / script / cost checks, voted-protocol-parameter epoch recomputation, validation-rule status updates, miner-vote tallies, and NiPoPoW proof verification. Holds no fork-choice, no UTXO storage, no P2P: it answers "is this legal?" and hands back unforgeable `Checked*` proof objects. (`src/lib.rs:1-31`)

**Depends on (workspace):** ergo-primitives, ergo-ser, ergo-chain-spec, ergo-crypto, ergo-sigma
**Depended on by:** (see codemap index) — notably `ergo-state` depends on this (inverted dependency: state asks validation for legality before applying).
**Approx LOC:** ~15000 (incl. tests)

## Start here
- `src/lib.rs` — module tree + re-exports + an explicit "what is NOT here" boundary (lines 27-31). The fastest map of the crate.
- `src/block.rs` (`validate_full_block_parallel`, `validate_full_block`) — the full-block orchestration that ties header → roots → extension rules → per-tx → cost budget together. The production entry point.
- `src/tx/mod.rs` (`validate_transaction`, `validate_transaction_parsed`, `CheckedTransaction`) — the per-tx pipeline (deserialize → curve-check GEs → structural → canonical → resolve → heights → monetary → script → re-emission check).
- `src/header.rs` (`validate_header`, `CheckedHeader`, `PowCheckedHeader`) — header acceptance and the typestate proof objects.
- `src/error.rs` (`ValidationError`) — the consensus-rejection taxonomy with Scala-parity rule numbers; reading the variants is reading the rule set.

## Modules
- `src/block.rs` — full-block validation: section-id linkage, transactions/extension Merkle roots, extension structural rules (400/404/405/406), interlink rules (401/402), fork-vote window (407), block-tx-size (306), intra-block UTXO overlay + topological tx layering for `rayon` parallel validation, block cost budget. Owns `CheckedBlock`, `BlockValidationContext`, `BlockValidationError`, `SoftForkState`.
- `src/header.rs` — header-level rules: PoW (`PowCheckedHeader::verify_pow`), parent linkage, timestamp monotonicity + future-drift (211), difficulty, vote sanity (213/214/215). Produces `CheckedHeader`; `from_persisted_parts` is the trusted re-hydration escape hatch.
- `src/tx/mod.rs` — per-tx orchestration, `CheckedTransaction`, `TxValidationCtx`, `TxValidationRules`, canonical-encoding check, input/data-input resolution + match verification.
- `src/tx/structural.rs` — stateless tx checks: non-empty inputs, collection caps (102/103/104 at `Short.MaxValue`), no duplicate inputs, per-output box-size / token-count / min-value / proposition-size (121) caps.
- `src/tx/monetary.rs` — ERG conservation (inputs ≥ outputs) and per-token conservation + minting rule (mint id must equal `inputs[0].box_id`).
- `src/tx/heights.rs` — per-output `creation_height` rules: future-output (112) and monotonic-height (124, soft-fork-gated on block version ≥ 3).
- `src/tx/script.rs` — ErgoTree reduction + spending-proof verification bridge into `ergo-sigma`; transaction init-cost formula (`calcInitCost` parity); storage-rent collection branch (`check_storage_rent`); the `ErgoBox`/candidate → `EvalBox` adapters.
- `src/tx/ge.rs` — group-element curve-check: validates every `GroupElement` point collected by `ergo-ser` during transaction parse (ProveDlog/ProveDHTuple scripts, SGroupElement constants/registers, SHeader keys, nested SBox values, context-extension). Scalar `ergo-ser` layer stores point bytes unvalidated; this stage rejects off-curve / bad-prefix points at the earliest stateless position, matching the JVM's deserialize-time rejection.
- `src/tx/reemission.rs` — EIP-27 re-emission spending validation: port of Scala `verifyReemissionSpending` (non-emission-box branch). Enforces that re-emission tokens in spent reward boxes are burned (no output carries them) and that exactly one nanoErg per burned token is paid to the pay-to-reemission contract. `reemission_obligation_core` is the shared single-source helper used by both the consensus validator and the wallet balance/builder surfaces so they cannot diverge.
- `src/cost.rs` — thin re-export of `CostAccumulator` / `CostError` / `JitCost` from `ergo-primitives` so callers stay on `ergo_validation` types.
- `src/context.rs` — the input surfaces: `ProtocolParams` (votable params), `LocalPolicy` (non-consensus node limits), `TransactionContext` (per-block script-visible fields), `UtxoView` (box-lookup trait).
- `src/active_params.rs` — `ActiveProtocolParameters`: per-epoch active set parsed from the epoch-start extension; the persistence codec (`serialize`/`deserialize`) and launch defaults (`scala_launch*`).
- `src/voting/recompute.rs` — `compute_next_params`: the soft-fork voting state machine + non-fork param updates (Scala `Parameters.update`).
- `src/voting/votes.rs` — `compute_epoch_votes`: tally `header.votes` across an epoch via the `ChainHeaderReader` trait.
- `src/voting/extension_validation.rs` — `validate_epoch_extension`: epoch-start extension vs recomputed active set (Scala `exMatchParameters`/`exMatchValidationSettings`).
- `src/voting/validation_settings.rs` — `ErgoValidationSettings` / `ErgoValidationSettingsUpdate` types, `RuleStatus`, and their wire codec.
- `src/popow/algos.rs` — pure NiPoPoW algorithms (KMZ17): `max_level_of`, `best_arg`, `lowest_common_ancestor`, `update_interlinks`, interlink pack/unpack.
- `src/popow/verifier.rs` — `NipopowVerifier`: stateful best-proof-keeping `process` reducer over incoming `NipopowProof`s.
- `src/popow/proof.rs` — `NipopowProofExt` trait (proof-level helpers) + popow-header interlink-proof check.
- `src/popow/merkle.rs` — `verify_batch_merkle_proof` against an expected root.
- `src/storage_rent.rs` — `compute_storage_fee`: the consensus-critical i32 wrapping multiply (`storage_fee_factor * box_bytes_len`) shared by the validator and the API storage-rent endpoint.
- `src/pre_header.rs` — `CandidatePreHeader` / `CandidateValidationContext`: the frozen script-visible context used during mining-candidate assembly.

## Key types, traits & functions
- `ValidationError` (enum) — every consensus tx/block/header rejection, grouped by phase, with Scala rule numbers in the docs — `src/error.rs:12`
- `CheckedTransaction` (struct) — unforgeable validated tx (private fields); carries `tx_id` computed once + resolved inputs — `src/tx/mod.rs:78`
- `TxValidationRules` (struct) — network-constant consensus rule bundle threaded through `TxValidationCtx`; carries optional `ReemissionRuleInputs` so EIP-27 enforcement is uniform across block apply, mempool admission, and mining — `src/tx/mod.rs:32`
- `validate_transaction` / `validate_transaction_parsed` (fn) — full pipeline from bytes / from parsed-with-resolved-inputs (block path, supports `skip_scripts` checkpoint) — `src/tx/mod.rs:117` / `:219`
- `TxValidationCtx` (struct) — the per-tx borrow bundle (ctx, params, mutable cost, last_headers, rules) — `src/tx/mod.rs:50`
- `CheckedHeader` (struct) — validated header + computed `header_id`; `from_persisted_parts` re-hydration (does NOT re-verify PoW) — `src/header.rs:20`
- `PowCheckedHeader` (struct) — PoW-verified proof so the batch pipeline parallelizes PoW then finalizes sequentially — `src/header.rs:555`
- `validate_header` / `validate_header_after_pow` (fn) — only ways to mint a `CheckedHeader` from raw inputs — `src/header.rs:632` / `:594`
- `CheckedBlock` (struct) + `validate_full_block_parallel` (fn) — block proof object + production parallel validator; `validate_full_block` is the `#[cfg(any(test, feature = "test-helpers"))]` sequential reference twin — `src/block.rs:888` / `:1569` / `:954`
- `BlockValidationContext` (struct) — parent header, UTXO view, params, voting_length, parent extension, soft-fork state, last headers, optional script-validation checkpoint — `src/block.rs:87`
- `SoftForkState` (struct) — soft-fork prohibited-vote window computation for rule 407 — `src/block.rs:40`
- `validate_interlinks` / `validate_extension_structural` / `validate_fork_vote` / `check_block_transactions_size` (fn) — the standalone block-level rule helpers (401/402, 400/404/405/406, 407, 306) — `src/block.rs:545` / `:611` / `:503` / `:437`
- `build_tx_layers` / `TxLayers` (fn/struct, crate-private) — topological layering of intra-block tx deps + intra-block double-spend rejection — `src/block.rs:799`
- `ProtocolParams` (struct) — votable params; `mainnet_default` fallback + `from_active` derivation — `src/context.rs:7`
- `UtxoView` (trait) — `get_box(box_id) -> Option<ErgoBox>` lookup surface — `src/context.rs:145`
- `ActiveProtocolParameters` (struct) — per-epoch active set; `serialize`/`deserialize` persistence codec, `parse_active_params`, `scala_launch*` defaults — `src/active_params.rs:55`
- `compute_next_params` (fn) — soft-fork + param recompute returning `(next_active, activated_update)` — `src/voting/recompute.rs:78`
- `compute_epoch_votes` (fn) + `ChainHeaderReader` (trait) — epoch vote tally over a header reader — `src/voting/votes.rs:65` / `:10`
- `validate_epoch_extension` (fn) + `ExtensionValidationOutcome` (struct) — epoch-start extension match — `src/voting/extension_validation.rs:152` / `:20`
- `ErgoValidationSettings` / `ErgoValidationSettingsUpdate` (struct) — rule-status set + soft-fork update with codec — `src/voting/validation_settings.rs:141` / `:195`
- `NipopowVerifier` (struct) — best-proof reducer (`process`, `best_chain`, `best_proof`) — `src/popow/verifier.rs:60`
- `update_interlinks` / `max_level_of` / `best_arg` / `lowest_common_ancestor` (fn) — pure NiPoPoW algorithms — `src/popow/algos.rs:472` / `:332` / `:383` / `:425`
- `verify_batch_merkle_proof` (fn) — batch Merkle proof vs root — `src/popow/merkle.rs:33`
- `compute_storage_fee` (fn) — consensus i32 wrapping multiply for storage rent — `src/storage_rent.rs:29`
- `compute_tx_init_cost` / `INTERPRETER_INIT_COST` (fn/const) — Scala `calcInitCost` parity; init cost = 10_000 — `src/tx/script.rs:71` / `:36`
- `verify_reemission_spending` / `reemission_obligation_core` (fn) — EIP-27 re-emission spending validator (Scala `verifyReemissionSpending` non-emission-box branch); `reemission_obligation_core` is the shared single-source burn-obligation helper used by both the validator and the wallet balance/builder — `src/tx/reemission.rs:100` / `:215`
- `ReemissionRuleInputs` / `ReemissionObligation` (struct) — network constants for EIP-27 enforcement (activation height, token id, pay-to-reemission tree bytes); obligation result (triggered flag + tokens to burn) — `src/tx/reemission.rs:55` / `:248`
- `derive_activated_script_version` / `neutral_votes` (const fn) — `script_version = block_version - 1`; zeroed votes — `src/voting/mod.rs:67` / `:50`

## Invariants & contracts
- **`Checked*` types are unforgeable proofs.** `CheckedHeader`, `CheckedTransaction`, `CheckedBlock` have private fields; the only production constructors run full validation. Downstream crates trust them without re-checking. `from_persisted_parts` (header) and `from_parts`/`trust_me` (test-helpers) are the controlled escape hatches.
- **Canonical-encoding enforcement.** Every tx must re-serialize bit-identically to its input bytes (`check_canonical` → `ValidationError::NonCanonical`); `read_header` consumption is checked to EOF in `from_persisted_parts`. Non-canonical-but-parseable input is rejected.
- **Scala-tighter validator caps over wire caps.** Counts are capped at `Short.MaxValue` (32_767) at the validator even though the wire codec allows `u16::MAX`; extension field values capped at 64 B (wire allows 255); proposition bytes capped at 4_096.
- **Sequential/parallel block-validation equivalence.** `validate_full_block_parallel` must produce identical accept/reject (and first-failing-tx-by-index error ordering) as the sequential reference; both run the same per-tx pipeline, same cost summation, same `max_block_cost` inequality. Intra-block double-spend is rejected up front by `build_tx_layers`.
- **Intra-block UTXO semantics.** Inputs resolve through an overlay that surfaces in-block creates and filters in-block spends; data inputs resolve through `get_box_from_base` (union of pre-block + in-block creates, NOT filtering spends) — pinned to mainnet blocks 290684 and 422179.
- **Consensus arithmetic parity.** Storage-fee uses i32 *wrapping* multiply (overflow at >1717 bytes is mainnet-observed and must be preserved). JIT cost arithmetic surfaces overflow as typed `JitCostOverflow` rejection rather than panicking. Vote-byte negation uses `checked_neg` to survive adversarial `i8::MIN`.
- **Defensive rule ordering.** Extension structural / interlink / block-tx-size checks run AFTER the Merkle-root recompute so an unbound adversarial payload cannot force the O(N²) duplicate scan or re-serialize work as a DoS.
- **Epoch-boundary determinism.** `compute_next_params`/`parse_active_params` reject non-epoch-start heights and out-of-range params; `ActiveProtocolParameters` round-trips byte-stably (unknown ids preserved in `extra`), so the persisted active set never drifts from the wire form.
- **No fork-choice, no storage, no P2P.** This crate owns acceptance rules only; chain-graph / reorg / AVL+ mutation live in `ergo-state`, mempool admission in `ergo-mempool`.

