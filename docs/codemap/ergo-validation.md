# ergo-validation

**Purpose:** L3 consensus-acceptance crate. Decides whether a header, block, or transaction is *legal* — structural / monetary / script / cost checks, voted-protocol-parameter epoch recomputation, validation-rule status updates, miner-vote tallies, and NiPoPoW proof verification. Holds no fork-choice, no UTXO storage, no P2P: it checks the supplied inputs and returns private-field `Checked*` artifacts. Their guarantees depend on the entry point, caller context, and any authorized script checkpoint.

**Depends on (workspace):** ergo-primitives, ergo-ser, ergo-chain-spec, ergo-crypto, ergo-sigma
**Depended on by:** (see codemap index) — notably `ergo-state` depends on this (inverted dependency: state asks validation for legality before applying).

## Start here
- `src/lib.rs` — module tree, re-exports, and crate boundaries. The fastest map of the crate.
- `src/block/validate.rs` (`validate_full_block_parallel`, `validate_full_block`) — the full-block orchestration that ties header → roots → extension rules → per-tx → cost budget together. The production entry point.
- `src/tx/mod.rs` (`validate_transaction`, `validate_transaction_parsed`, `CheckedTransaction`) — the per-tx pipeline (deserialize → curve-check GEs → structural → resolve → heights → monetary → script → re-emission check).
- `src/header/mod.rs` (`validate_header`, `CheckedHeader`, `PowCheckedHeader`) — header checks and the private-field checked types.
- `src/error.rs` (`ValidationError`) — the consensus-rejection taxonomy with Scala-parity rule numbers; reading the variants is reading the rule set.

## Modules
- `src/block/mod.rs` — full-block validation: section-id linkage, transactions/extension Merkle roots, extension structural rules (400/404/405/406), interlink rules (401/402), fork-vote window (407), block-tx-size (306), intra-block UTXO overlay + topological tx layering for `rayon` parallel validation, block cost budget. Owns `CheckedBlock`, `BlockValidationContext`, `BlockValidationError`, `SoftForkState`.
- `src/header/mod.rs` — header-level rules: PoW (`PowCheckedHeader::verify_pow`), parent linkage, timestamp monotonicity + future-drift (211), difficulty, non-deactivatable vote sanity (213/214); activated rules 212/215 run with block context. Produces `CheckedHeader`; `from_persisted_parts` is the trusted re-hydration escape hatch.
- `src/tx/mod.rs` — per-tx orchestration, `CheckedTransaction`, `TxValidationCtx`, `TxValidationRules`, input/data-input resolution + match verification.
- `src/tx/structural.rs` — stateless tx checks: non-empty inputs, collection caps (102/103/104 at `Short.MaxValue`), no duplicate inputs, per-output box-size / token-count / min-value / proposition-size (121) caps.
- `src/tx/monetary.rs` — ERG conservation (inputs ≥ outputs) and per-token conservation + minting rule (mint id must equal `inputs[0].box_id`).
- `src/tx/heights.rs` — per-output `creation_height` rules: future-output (112) and monotonic-height (124, soft-fork-gated on block version ≥ 3).
- `src/tx/script/mod.rs` — ErgoTree reduction + spending-proof verification bridge into `ergo-sigma`; transaction init-cost formula (`calcInitCost` parity); storage-rent collection branch (`check_storage_rent`); the `ErgoBox`/candidate → `EvalBox` adapters.
- `src/tx/ge.rs` — group-element curve-check: validates every `GroupElement` point collected by `ergo-ser` during transaction parse (ProveDlog/ProveDHTuple scripts, SGroupElement constants/registers, SHeader keys, nested SBox values, context-extension). Scalar `ergo-ser` layer stores point bytes unvalidated; this stage rejects off-curve / bad-prefix points at the earliest stateless position, matching the JVM's deserialize-time rejection.
- `src/tx/reemission.rs` — EIP-27 re-emission spending validation: port of Scala `verifyReemissionSpending` (non-emission-box branch). Enforces that re-emission tokens in spent reward boxes are burned (no output carries them) and that exactly one nanoErg per burned token is paid to the pay-to-reemission contract. `reemission_obligation_core` is the shared single-source helper used by both the consensus validator and the wallet balance/builder surfaces so they cannot diverge.
- `src/cost.rs` — thin re-export of `CostAccumulator` / `CostError` / `JitCost` from `ergo-primitives` so callers stay on `ergo_validation` types.
- `src/context.rs` — the input surfaces: `ProtocolParams` (votable params), `LocalPolicy` (non-consensus node limits), `TransactionContext` (per-block script-visible fields), `UtxoView` (box-lookup trait).
- `src/active_params/mod.rs` — `ActiveProtocolParameters`: per-epoch active set parsed from the epoch-start extension; the persistence codec (`serialize`/`deserialize`) and launch defaults (`scala_launch*`).
- `src/voting/recompute/mod.rs` — `compute_next_params`: the soft-fork voting state machine + non-fork param updates (Scala `Parameters.update`).
- `src/voting/votes.rs` — `compute_epoch_votes`: tally `header.votes` across an epoch via the `ChainHeaderReader` trait.
- `src/voting/extension_validation/mod.rs` — `validate_epoch_extension`: epoch-start extension vs recomputed active set (Scala `exMatchParameters`/`exMatchValidationSettings`).
- `src/voting/validation_settings.rs` — `ErgoValidationSettings` / `ErgoValidationSettingsUpdate` types, `RuleStatus`, and their wire codec.
- `src/popow/algos/mod.rs` — pure NiPoPoW algorithms (KMZ17): `max_level_of`, `best_arg`, `lowest_common_ancestor`, `update_interlinks`, interlink pack/unpack.
- `src/popow/verifier.rs` — `NipopowVerifier`: stateful best-proof-keeping `process` reducer over incoming `NipopowProof`s.
- `src/popow/proof.rs` — `NipopowProofExt` trait (proof-level helpers) + popow-header interlink-proof check.
- `src/popow/merkle.rs` — `verify_batch_merkle_proof` against an expected root.
- `src/fee.rs` — `MAINNET_FEE_PROPOSITION_BYTES`, the canonical mainnet miner-fee ErgoTree shared by the mempool (re-exported as `ergo_mempool::validator::MAINNET_FEE_PROPOSITION_BYTES`), candidate assembly, and the wallet transaction builder.
- `src/storage_rent.rs` — `compute_storage_fee`: the consensus-critical i32 wrapping multiply (`storage_fee_factor * box_bytes_len`) shared by the validator and the API storage-rent endpoint.
- `src/pre_header.rs` — `CandidatePreHeader` / `CandidateValidationContext`: the frozen script-visible context used during mining-candidate assembly.

## Key types, traits & functions
- `ValidationError` (enum) — every consensus tx/block/header rejection, grouped by phase, with Scala rule numbers in the docs — `src/error.rs`
- `CheckedTransaction` (struct) — private-field accepted tx, with scripts optionally skipped at a checkpoint; carries `tx_id` computed once + resolved inputs — `src/tx/mod.rs`
- `TxValidationRules` (struct) — network-constant consensus rule bundle threaded through `TxValidationCtx`; carries optional `ReemissionRuleInputs` so EIP-27 enforcement is uniform across block apply, mempool admission, and mining — `src/tx/mod.rs`
- `validate_transaction` / `validate_transaction_parsed` (fn) — full pipeline from bytes / from parsed-with-resolved-inputs (block path, supports caller-authorized `skip_scripts`; sideband overload requires the points from that exact parse) — `src/tx/mod.rs`
- `TxValidationCtx` (struct) — the per-tx borrow bundle (ctx, params, mutable cost, last_headers, rules) — `src/tx/mod.rs`
- `CheckedHeader` (struct) — accepted header + caller-supplied ID, or ID checked against persisted bytes; `from_persisted_parts` re-hydration (does NOT re-verify PoW) — `src/header/mod.rs`
- `PowCheckedHeader` (struct) — PoW-verified proof so the batch pipeline parallelizes PoW then finalizes sequentially — `src/header/mod.rs`
- `validate_header` / `validate_header_after_pow` (fn) — fresh header-validation entry points with caller-owned byte/ID and parse-sideband obligations — `src/header/mod.rs`
- `CheckedBlock` (struct) + `validate_full_block_parallel` (fn) — block proof object + production parallel validator; `validate_full_block` is the `#[cfg(any(test, feature = "test-helpers"))]` sequential reference twin — `src/block/mod.rs` / `src/block/validate.rs`
- `BlockValidationContext` (struct) — parent header, UTXO view, params, voting_length, parent extension, soft-fork state, last headers, optional script-validation checkpoint — `src/block/mod.rs`
- `SoftForkState` (struct) — soft-fork prohibited-vote window computation for rule 407 — `src/block/mod.rs`
- `validate_interlinks` / `validate_extension_structural` / `validate_fork_vote` / `check_block_transactions_size` (fn) — the standalone block-level rule helpers (401/402, 400/404/405/406, 407, 306) — `src/block/mod.rs`
- `build_tx_layers` / `TxLayers` (fn/struct, crate-private) — topological layering of intra-block tx deps + intra-block double-spend rejection — `src/block/layering.rs`
- `ProtocolParams` (struct) — votable params; `for_block` selects target-epoch numeric parameters and folds the target delta into cumulative settings; `from_active_with_settings` uses an already accumulated rule table; `from_active` only sees its row delta — `src/context.rs`
- `UtxoView` (trait) — `get_box(box_id) -> Option<ErgoBox>` lookup surface — `src/context.rs`
- `ActiveProtocolParameters` (struct) — per-epoch active set; `serialize`/`deserialize` persistence codec, `parse_active_params`, `scala_launch*` defaults — `src/active_params/mod.rs`
- `compute_next_params` (fn) — soft-fork + param recompute returning `(next_active, activated_update)` — `src/voting/recompute/mod.rs`
- `compute_epoch_votes` (fn) + `ChainHeaderReader` (trait) — epoch vote tally over a header reader — `src/voting/votes.rs`
- `validate_epoch_extension` (fn) + `ExtensionValidationOutcome` (struct) — epoch-start extension match — `src/voting/extension_validation/mod.rs`
- `ErgoValidationSettings` / `ErgoValidationSettingsUpdate` (struct) — rule-status set + soft-fork update with codec — `src/voting/validation_settings.rs`
- `NipopowVerifier` (struct) — best-proof reducer (`process`, `best_chain`, `best_proof`) — `src/popow/verifier.rs`
- `update_interlinks` / `max_level_of` / `best_arg` / `lowest_common_ancestor` (fn) — pure NiPoPoW algorithms — `src/popow/algos/mod.rs`
- `verify_batch_merkle_proof` (fn) — batch Merkle proof vs root — `src/popow/merkle.rs`
- `compute_storage_fee` (fn) — consensus i32 wrapping multiply for storage rent — `src/storage_rent.rs`
- `compute_tx_init_cost` / `INTERPRETER_INIT_COST` (fn/const) — Scala `calcInitCost` parity; init cost = 10_000 — `src/tx/script/mod.rs`
- `verify_reemission_spending` / `reemission_obligation_core` (fn) — EIP-27 re-emission spending validator (Scala `verifyReemissionSpending` non-emission-box branch); `reemission_obligation_core` is the shared single-source burn-obligation helper used by both the validator and the wallet balance/builder — `src/tx/reemission.rs`
- `ReemissionRuleInputs` / `ReemissionObligation` (struct) — network constants for EIP-27 enforcement (activation height, token id, pay-to-reemission tree bytes); obligation result (triggered flag + tokens to burn) — `src/tx/reemission.rs`
- `derive_activated_script_version` / `neutral_votes` (const fn) — `script_version = block_version - 1`; zeroed votes — `src/voting/mod.rs`

## Invariants & contracts
- **Checked artifacts retain path-specific results.** Private fields prevent external replacement of accepted parts. Fresh header checks trust caller IDs, parse sidebands, and ancestry; persisted hydration checks the exact stored bytes, EOF, and metadata but trusts the prior PoW marker. Parsed transaction calls authorize script skipping explicitly. Full-block calls trust their checked header and supplied UTXO/context; checkpointed scripts and their charges do not run. Test-helper constructors bypass checks deliberately.
- **Received encodings and identifiers.** Accepted transactions can normalize on serialization. Transaction IDs hash the reserialized `bytes_to_sign`; block transaction roots use those parsed IDs and witness hashes. The mempool retains received bytes for relay, without an encoding-equality rejection or peer penalty. Persisted headers are stored canonically and checked to EOF by `from_persisted_parts`.
- **Scala-tighter validator caps over wire caps.** Counts are capped at `Short.MaxValue` (32_767) at the validator even though the wire codec allows `u16::MAX`; extension field values capped at 64 B (wire allows 255); proposition bytes capped at 4_096.
- **Parallel failure ordering is per layer.** Backward dependencies determine topological layers. Each layer resolves all inputs before per-transaction validation, then reports the lowest failing index within that layer. This can differ from global transaction-index ordering in the sequential reference. Both paths share transaction checks and cost summation; a global first-error or general Scala equivalence claim needs separate evidence.
- **Intra-block lookup scope.** Spending inputs see the base view plus outputs of transactions already committed to the overlay, and filter overlay spends. Data inputs see the base view plus every output of the block, without filtering spends, as pinned Scala's `UtxoState.applyTransactions` callback resolves through all block outputs and its data-input lookups never fail; the Digest base already exposes all block outputs. A data input may therefore name a later transaction's output, while a forward spend still fails when the block's removals apply. Mainnet captures 290684/422179 cover spent pre-block and earlier-created boxes; `same_block_data_inputs` covers forward reads and spends on both validation paths.
- **Cumulative activated settings.** Persisted active parameter rows contain an epoch delta, not the cumulative rule-status table. Runtime contexts use `for_block` or `from_active_with_settings` with the separately accumulated settings. The shipped `cumulative-context` JVM fixture exercises actual pinned Scala update semantics and JIT conversions; synthetic epoch/reopen tests exercise persistence and context wiring, not historical script verdicts.
- **Consensus arithmetic parity.** Storage-fee uses i32 *wrapping* multiply (overflow at >1717 bytes is mainnet-observed and must be preserved). JIT cost arithmetic surfaces overflow as typed `JitCostOverflow` rejection rather than panicking. Vote-byte negation uses `checked_neg` to survive adversarial `i8::MIN`.
- **Defensive rule ordering.** Extension structural / interlink / block-tx-size checks run AFTER the Merkle-root recompute so an unbound adversarial payload cannot force the O(N²) duplicate scan or re-serialize work as a DoS.
- **Epoch-boundary determinism.** `compute_next_params`/`parse_active_params` reject non-epoch-start heights and out-of-range params; `ActiveProtocolParameters` round-trips byte-stably (unknown ids preserved in `extra`), so the persisted active set never drifts from the wire form.
- **No fork-choice, no storage, no P2P.** This crate owns acceptance rules only; chain-graph / reorg / AVL+ mutation live in `ergo-state`, mempool admission in `ergo-mempool`.


`scala_launch_testnet()` follows the pinned v6.0.5 version-4 launch row with
proposed disables 215/409 and empty activated settings. The finite
`tests/it/testnet_launch_oracle.rs` consumes captured heights 1, 2, 128 and
1024, checking external header IDs/PoW/extension commitments and the first-epoch
bootstrap. It does not execute a continuous chain or migrate historical rows.

The vector-integrity test requires all five advertised files and all 1,548
records, rejects malformed hex, parse failures and trailing bytes, and checks
the transaction ID against its bytes-to-sign. It parses under the explicitly
selected storage-reader activation-1 context. This verifies codec coverage and
ID derivation; it does not execute scripts, resolve UTXOs, or prove canonical
round-trip equivalence under every activation.

`NipopowProofExt::is_better_than` uses a strict score comparison. Valid beats
invalid; ties, two invalid proofs, absent common ancestors, and fallible ancestor
computation return false. The method has no panic-catching boundary.
