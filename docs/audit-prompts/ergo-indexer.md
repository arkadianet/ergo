# `ergo-indexer` reference-quality audit prompt

Audit `ergo-indexer` as the optional derived-data writer, reorg follower,
resumable secondary-index repairer, and persistent query implementation. Read
`docs/audit-prompts/COMMON.md` first, then `CONTRIBUTING.md`,
`docs/compatibility.md`, and `docs/codemap/ergo-indexer.md`. Follow the common
review-only workflow, complete file ledger, evidence rules, and report format.
Establish current batching, worker, read-error, and rollback-window behavior from
source; the codemap describes useful landmarks but may predate these contracts.

## Mission and boundaries

Trace committed canonical chain snapshots → loaded parsed blocks → per-block/
batch writes → persisted primary/secondary rows and undo/meta → published handle
height/status/health → API reads. Also trace fork detection → rollback and
secondary drift → durable repair marker → chunked rebuild → resumed service.
The index is rebuildable derived state, yet false balances, incomplete reads,
unbounded repair, corruption concealment, or consensus-store deletion remain
serious failures. Verify isolation and observable errors, not merely atomic DB APIs.

## Source landmarks and associated material

- Read `Cargo.toml`, `src/lib.rs`, `config.rs`, `error.rs`, `handle.rs`,
  `task.rs`, `task_batch_tests.rs`, `apply.rs`, `rollback.rs`, and `rebuild.rs`.
- Read all `src/store/` helpers and table definitions, `src/ser/` codecs,
  `address.rs`, `template.rs`, `token.rs`, `segment.rs`, `segment_id.rs`,
  `segment_buffer.rs`, `scratch.rs`, and `segment_perf.rs` wherever wired by cfg.
- Include all inline tests and every module in `tests/it/main.rs`: store boot,
  queries, apply, rollback, depth/spill/token reorgs, storage rent, rebuild,
  backfill, task/resume, and error taxonomy.
- Resolve byte/JSON fixtures and upstream extra-index serializer/formula
  authorities named by tests. Review `docs/perf/indexer-batches-2026-09-26.md`
  as historical evidence whose assumptions must match the checkout.
- Follow `ergo-indexer-types`, `ergo-state` committed chain reader, production
  node indexer boot/task wiring, API status gates/fallible reads, and rent users.
- Build a table/index inventory: key/value wire format, invariant, write owners,
  read owners, apply/rollback/rebuild participation, and corruption behavior.

## Atomicity, durability, and restart

1. Prove the transaction boundary for standalone apply, rollback, and batched
   catch-up: box/tx/numeric rows, balances/parents, spills, rent rows, tokens,
   metadata, repair markers, undo insertion, and pruning must commit together.
   Check helpers never open an independent writer or publish uncommitted state.
2. Verify public/internal apply preconditions are checked inside the appropriate
   transaction: sequential height, matching parent/previous meta, header identity,
   legal signed heights, counter ranges, block ordering, and writer serialization.
3. Review batch block/time limits, mid-batch missing sections, validation errors,
   fork rechecks, cancellation, and commit errors. Establish whether each outcome
   commits a prefix or aborts all staged work, and what cached height reports.
4. Audit `Durability::Eventual` against the actual restart model: indexer meta and
   rows must recover together, lag must be replayable from retained chain data,
   and an index ahead of the recovered committed tip must be reconciled safely.
5. Review schema version/table/meta corruption, absent versus existing database,
   resume versus recreate, incompatible-schema deletion, and failure midway
   through recreation. Validate configurable filenames/paths and prevent any
   wipe or collision from touching consensus DBs or unrelated files.
6. Draw publication order: committed redb transaction → cached height/status/
   health → API observation. Check concurrent readers, poisoned locks, boot
   failures, degraded repair, and errors cannot advertise healthy complete state.
7. Inspect persisted codecs for strict EOF, option markers, length/count bounds,
   signed VLQ/zigzag, truncation, duplicates, canonical bytes, and damaged rows.
   No read-path `unwrap` or `.ok()` may disguise corruption without an explicit
   compatible fallback whose consequence is documented.

## Apply and exact inverse rollback

8. Verify every input is found or belongs to the exact mainnet protocol-genesis
   exception; genesis behavior and numeric sentinels must match primary authority.
   Check duplicate/missing/spent inputs and intra-block/intra-transaction spends.
9. Verify immutable global indices and canonical IDs, transaction/input/output
   ordering, spend triple updates, data-input semantics, repeated addresses,
   historical script byte retention, and reverse transaction order on rollback.
10. Prove apply followed by rollback restores logical tables, counters, parents,
    token order/metadata, spent flags, and rent rows exactly, allowing only
    documented diagnostics/DB-layout differences. Failure midway must restore
    pre-call state; reapply must equal fresh linear indexing.
11. Check ERG/token balance arithmetic, saturation/clamping compatibility,
    first-touch token ordering, zero-removal/re-addition, duplicate assets,
    signed conversions, overflow bounds, and conservation across touched rows.
12. Check EIP-4 mint identity/amount, multiple outputs holding the minted token,
    existing-token transfer, protocol-genesis input handling, R4/R5/R6 metadata,
    Unicode/invalid register types, empty-versus-absent values, and rollback removal.
13. Verify tree/template/token ID formulas byte-for-byte, raw versus normalized
    tree bytes, constant segregation, soft-fork/unparseable scripts, and the
    distinction between intentional unindexable templates and storage corruption.
14. Check rent index keys use box creation height and immutable global index,
    canonical box lengths/value, insert/remove symmetry, rollback restoration,
    range order/inclusivity, and corrupted/missing primary dereferences.
15. Verify undo framing/snapshot completeness/prune boundary against configured
    rollback retention, including 0, 1, default, and large windows. Node boot must
    mirror state retention; deep forks must halt honestly without partial unwind.

## Segments, repair, and polling lifecycle

16. Prove segment head/spill invariants at 0/1/511/512/513/multiple-spill lengths:
    exact spill sizes, strict threshold, deterministic IDs/counters, staged-write
    lookup, merge-back, expected last entry, and no ghost/missing spill rows.
17. Verify signed spent encoding and `abs`/negation limits, index zero behavior,
    immutable record index, transaction entries, duplicate entries, and inherited
    unspent filtering. Do not repair a deliberate Scala quirk without authority.
18. Review primary address topology errors versus tolerated derived template/token
    drift. Every tolerated skip must mark repair atomically, preserve primary
    truth, record diagnostics, and prevent falsely complete read-side behavior.
19. Prove rebuild arming precedes destructive writes, phase-0 deletion and phase-1
    replay checkpoints are restart-safe, each chunk writes cursor/data atomically,
    numeric index order reproduces fresh secondary bytes, and cancellation keeps
    sufficient durable state for resume. Reorg/apply cannot race rebuild writers.
20. Check corrupted/undecodable/skipped primary rows and missing numeric entries:
    completed-with-skips remains observable, progress denominators/units are
    correct, and repair does not erase sticky evidence of incomplete output.
21. Verify committed-tip/header/full-block snapshots and the final fork recheck,
    including a header-chain flip preceding state reorg, lower/equal-height forks,
    pruned old blocks, transient races, and unknown tip. Follow canonical state
    rather than an uncommitted header-chain preference.
22. Check dedicated worker thread startup, spawn failure, owning handles, stop/
    drop/join, cancellation during idle/retry/apply/rebuild, bounded retry/backoff,
    zero/extreme polling periods, and prompt shutdown without async-runtime blocking.
23. Verify reusable scratch state is cleared before reuse, including an error
    before exit cleanup, failed batches, reorg retries, and canonical byte buffers.

## Reads, meaningful evidence, and completion

24. Map each `IndexerQuery` read and fallible adapter to one or more consistent
    transactions. Check missing versus corrupt/unavailable data, paging before/
    after filtering, both sort directions, global ranges, totals, index-zero,
    token order, rent queries, halted handles, and health snapshot coherence.
25. Review hot-path work and batch/rebuild memory growth against representative
    address/token concentrations, not only ordinary tiny blocks. Confirm performance
    shortcuts preserve codecs, rollback behavior, and diagnostics.

- Required evidence: complete table snapshots before/after injected apply/rollback
  errors; apply→rollback→reapply equivalence; reopen after committed and interrupted
  batch/rebuild checkpoints; corruption taxonomy; 512-boundary and retention-boundary
  cases; canonical-tip races; primary-versus-secondary missing-entry behavior.
- Use independent mainnet/Scala indexing fixtures for IDs, balances, order, token
  metadata, codecs, genesis exceptions, and representative historical scripts.
  Fresh-vs-rebuilt self-consistency complements these; it cannot replace parity.
- Use the common checks plus `cargo test --locked -p ergo-indexer`. Inspect the batch and
  segment performance test wiring before running longer experiments; record
  platform/storage limits and avoid actual operator databases.

Complete when every table mutation/read, worker/rebuild state, codec, cfg module,
test, comment, and fixture has a ledger entry; inverse/restart/race/error contracts
have concrete evidence; and residual compatibility, retention, incomplete-repair,
and durability risks are explicit in the common report.
