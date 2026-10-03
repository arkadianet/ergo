# `ergo-state` reference-node audit prompt

Audit `ergo-state` as the authenticated, durable state boundary of a reference-quality Ergo Rust node.
First read `docs/audit-prompts/COMMON.md` and apply its entire audit contract and report format.
Then read `CONTRIBUTING.md`, `docs/compatibility.md`, and `docs/codemap/ergo-state.md`.
This is a review-only audit unless the invoking user explicitly authorizes remediation.
Use the checked-out implementation to verify documentation; the codemap is an orientation aid, not proof.
Independently inventory every crate file and every reachable shared fixture, script, include fragment, example, and benchmark.
Review all production code, inline/unit/integration tests, comments, rustdoc, manifests, features, and supporting material under COMMON.
Do not inherit a clean bill of health or completion status from earlier audit documents.

## Mission and trust boundaries

Determine whether the UTXO and digest backends preserve exactly the state the accepted chain commits to.
Prove consistency across speculative mutation, asynchronous persistence, atomic redb transactions, crash recovery, rollback, bootstrap, pruning, and wallet hooks.
Treat peer sections, AD proofs, snapshots, persisted rows, legacy databases, and operator network/mode settings as separate input boundaries.
Separate validated acceptance rules supplied by `ergo-validation` from this crate's storage and authenticated-state obligations.
Distinguish in-memory applied state, redb-committed state, and crash-durable state whenever discussing visibility or success.

## Current source landmarks

- `src/lib.rs`, `src/backend.rs`: public facade, trait contracts, UTXO/digest dispatch, unsupported backend operations.
- `src/store/mod.rs`, `open.rs`, `apply.rs`, `reorg.rs`, `rebuild.rs`, `undo.rs`, `meta.rs`: lifecycle and commit/rollback machinery.
- `src/persist.rs`, `src/redb_util.rs`, `src/storage_observability.rs`: worker/barriers, quick repair, durability, error provenance and health.
- `src/avl/{tree,node,arena,digest,changelog,serialization,hydrate}.rs`: AVL structure, labels, arena, codecs, undo and cold reconstruction.
- `src/avl/snapshot_codec/{mod,node_codec,manifest,server,tests}.rs`: Scala node encoding, verified manifests, chunk generation.
- `src/store/{dry_run,lazy_prover,height_index,backfill,popow_cache,emission,votes,wallet_tx_bridge}.rs`: proof work, indexes, compatibility recovery, emission/votes and wallet transactions.
- `src/store/snapshot/{mod,lazy,tests}.rs`: one-transaction committed view and candidate dry runs.
- `src/{chain,header_store,reader,active_params,diff,digest_apply,digest_utxo_view}.rs`: chain indexes, reads, voting, diffs and proof verification.
- `src/digest_store/{mod,open,apply,rollback,voted_params,tests}.rs`: Mode 5 schema and history ledgers.
- `src/wallet/`: tables, store, readers, hydration, scans, maturity and chain hooks; recurse through `apply/`.
- `tests/it/main.rs`, all declared and undeclared test files, `tests/avl_labels_oracle.proptest-regressions`.
- `examples/extract_mode5_corpus.rs`, `extract_mode5_prior_headers.rs`, `src/store/dry_run_bench.rs`, and their fixture-generation instructions.

These landmarks are starting points. Resolve modules/includes and discover any additional files yourself.

## Authenticated tree and proof review

- Verify leaf/internal label inputs, balance encoding, node prefixes versus hash prefixes, next-key links, sentinel leaves, tree-height byte, and genesis digest against independent vectors.
- Check insert/update/remove, all rotations, successor replacement, root replacement, empty/one-node trees, duplicate/missing keys, and operation ordering.
- Trace every label invalidation/recompute path; stale cached labels must never survive an accepted mutation or rollback.
- Review `NodeId` lifetime, reuse/free lists, allocation failures, dirty/clean transitions, before-images, and arena aliases.
- Cached-disk eviction must preserve dirty nodes and nodes whose serialized bytes have not reached the required committed sequence.
- Inspect hydration for missing nodes, cycles, unreachable nodes, duplicate ownership, malformed child references and label/height mismatches.
- Verify decode bounds and fixed-width/VLQ/endian choices separately for persistent nodes, Scala snapshot nodes, manifests, and undo entries.
- Regenerated proofs must use the actual parent state and canonical transaction operation sequence, match `adProofsRoot`, and self-verify without mutating live state.
- Dry-run/lazy-prover failures, worker panic, cancellation, and partial expansion must leave the parent view and arena unchanged.
- Digest proof verification must bind old/new roots, operation counts/types, resolved input boxes, duplicate inputs, data inputs and intra-block outputs.
- Compare UTXO regeneration and shipped-proof digest execution for both acceptance and rejection; agreement between two local implementations is insufficient oracle evidence.

## Commit, persistence and crash safety

- Map every write transaction and its durability setting; verify production writes consistently use the quick-repair helper.
- Audit atomicity of undo, AVL nodes, UTXO rows, applied-chain index, tip metadata, epoch parameters/settings, emission identity and hooked wallet mutations.
- Include header/section overlays, pruning indexes, pending writes and deferred flushes in the map; identify which operations have separate transactions.
- Trace every mutation-before-failure path through successful restoration or `rebuild_from_committed`; a failed rebuild must prevent continued unsafe apply.
- `PersistPipeline` progress must count committed jobs rather than heights so repeated/lower branch heights cannot satisfy a later branch's barrier.
- Bounded completion-channel loss must not affect barrier truth; sticky worker errors, unexpected close, panic and queue-send failure cannot become `Ok(())`.
- Check job batching preserves block order, undo retention, wallet operations and the final metadata/root corresponding to the batch's committed tip.
- Verify arena durability watermarks advance only after commit and release pins with the intended memory ordering.
- Review backpressure memory bounds, worker/thread ownership, sender/receiver drop, flush versus shutdown races, and all database/reader reference lifetimes.
- Establish when `force_durable_flush` is required; `Durability::Eventual` commits alone do not establish fsync-level crash survival.
- On persist failure, inspect every caller: no tip publication, bootstrap success, mined-block success or retry path may imply a durability guarantee that failed.
- Reopen must anchor to committed metadata and cross-check roots, index tips, undo/history coverage, voted parameters, schema markers and genesis/network identity.
- Legacy backfill/migration must validate before stamping or rewriting; a rejected mis-open must not poison directory classification.
- Treat database corruption, missing data and absence as different results; read errors must not become empty state or launch-default parameters.

## Chain lifecycle, modes and rollback

- Preserve separate best-header and best-full pointers through apply, forks, rollback, restart, sparse NiPoPoW history and snapshots.
- Check composite undo identity `(height, header_id)`, competing forks at equal height, rollback-to-genesis and boundary depths.
- Restore parameters, cumulative validation settings, emission identity, wallet/maturity state, indexes and caches to the exact ancestor before replay.
- Trace definitive PoW and full-block rule invalidity versus session invalidity; IO, missing sections and ambiguous local digest failures must not permanently invalidate a valid branch.
- Invalid descendants and best-header re-anchoring must remain consistent across durable flags, height lookups and restart.
- Validate `data_dir_state_type` separation among UTXO, headers-only digest and digest-verifier schemas, including legacy ambiguous directories.
- Check Mode 2 snapshot install re-verifies tree root/height, canonical header, checkpoint and trust sentinels before atomic publication.
- Inspect first-epoch validation-settings trust state, epoch-boundary disarming, restart persistence and mining's refusal while cumulative settings remain provisional.
- NiPoPoW installation must preserve sparse/dense semantics, checkpoint requirements, proof terminals and usable successor context.
- Prune sentinel initialization must match headers-synced/epoch alignment policy and remain monotonic across restarts and bootstrap ordering.
- Ensure archive/headers-only behavior, suffix boundary arithmetic, undo floors and rollback windows match resolved configuration.
- Pruned sections, section-height/type indexes and AD-proof insertion windows must remain consistent for lookup, serve, replay and reorg.
- Digest history/root/tip ledgers must update atomically and reject missing/mismatched rows at open and rollback.
- Compare backend trait and enum behavior, especially absence/errors, genesis, epochs, sparse lookups and rollback capacity.

## Readers, wallet and downstream seams

- A `CommittedSnapshot` must source every consensus read from one held read transaction; no helper may silently open a newer one.
- Review live `ChainStoreReader` consistency claims, lazy reads, cache keys and how consumers handle concurrent commits/reorgs.
- `TxDiff` generation must detect equal-height/different-id reorgs and distinguish horizon/pruned gaps from an empty change set.
- Verify persisted emission identity includes exhausted versus unavailable history and follows the applied chain, including legacy bounded recovery.
- Wallet hooks and shared writer transactions must avoid deadlock, partial scan rows and wallet failure that leaves chain/wallet commit claims inconsistent.
- Check spend/create tracking, reward maturity, rollback, rescan guard, partial scans, scan deletion and hydration of corrupt/incompatible rows.
- Trace callers in `ergo-sync`, `ergo-node`, `ergo-mining`, `ergo-indexer`, `ergo-mempool` and API readers for assumptions the storage API does not guarantee.

## Required evidence and meaningful verification

Use COMMON's verification policy; inspect each test's body and fixture provenance, not only its name.
Start with `cargo test --locked -p ergo-state --lib` and `cargo test --locked -p ergo-state --test it` on isolated temporary databases.
Inventory `test-helpers`, `recompute-oracle`, and `test-utils`; verify no test-only durability or unchecked-apply support reaches production configuration.
Do not use `test-utils` non-durable commits as crash/restart evidence; arrange real durability and process-level interruption where required.
Seek independent root/AD-proof vectors, randomized AVL operation sequences, forced full recomputation and reverse-delta round trips.
Exercise persistence queue saturation, dropped result events, same-height branch replacement, worker failure/close and barriers at distinct job sequences.
Demand fault evidence around commit/flush/rollback/snapshot-install boundaries and reopen invariants after partial corruption.
Review pruning/oracle, voted-parameter/settings, committed-snapshot, digest replay, wallet and cold-arena tests for boundary and negative coverage.
Inspect ignored mainnet tests and corpus extraction examples; report missing captures or external-state prerequisites without claiming those checks passed.
Include shared `test-vectors/mainnet/`, `test-vectors/mode3-pruning/`, `test-vectors/mode5/`, snapshot vectors and referenced scripts in coverage.
Benchmark proof generation, hydration, cache misses, persist backlog and rollback on representative data; distinguish reproducible evidence from guesses.

## Crate-specific completion criteria

Report a reviewed-file ledger and explicit backend/mode/feature/test coverage under COMMON.
Supply a commit/visibility/durability table and a failure-recovery map for each state-changing path.
State the independently established root/proof parity evidence and the exact crash/rollback cases exercised.
Every unresolved issue must identify affected invariant, trigger, caller consequences, reproduction/evidence and a proportionate remediation.
Mark unavailable or unproven durability, Mode 2 trust, Mode 5 corpus and cross-mode lifecycle evidence as gaps, with concrete next verification steps.
Do not certify reference readiness while a reachable failure path can expose inconsistent state, lose promised durable data, or accept an unverified root.
