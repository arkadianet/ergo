# Audit prompt: ergo-validation

Audit `ergo-validation` as the header, block, transaction, voting and NiPoPoW
acceptance authority of a prospective reference-quality Rust Ergo node.

First read `docs/audit-prompts/COMMON.md` and follow its full methodology,
review-only default, evidence standards, reporting format, and coverage ledger.
Then read `CONTRIBUTING.md`, `docs/compatibility.md`, the crate manifest/root and
`docs/codemap/ergo-validation.md`. Commands and repository-prefixed paths are
relative to the repository root; abbreviated source paths are relative to this
crate. The codemap contains old flat-module landmarks; discover current files.
Inventory every file, test, comment, feature, source include, linked fixture,
generator and applicable workspace configuration. Cover all rules and APIs,
including diagnostic and helper surfaces, rather than only production landmarks.

## Mission and trust boundaries

Trace precisely what `CheckedHeader`, `PowCheckedHeader`, `CheckedTransaction`
and `CheckedBlock` prove. Their private fields do not erase public escape hatches,
trusted persistence, caller-supplied parse sidebands or script checkpoints.
State mutation, authenticated-state proof application/root checking, fork choice
and admission policy have cooperating owners: establish the boundary instead of
claiming this crate alone validates every aspect of a full block.

Audit verdict, error/rule ordering, partial cost, resolved boxes, IDs and active
parameter transition as separate outputs. Local policy, checkpoint trust and
consensus rule statuses must remain distinguishable. Preserve independently
verified Scala arithmetic and acceptance quirks even where they look incorrect.

## Current source landmarks

- `ergo-validation/src/header/{mod,timestamp,votes}.rs`: PoW/final header checks,
  persisted rehydration, trusted/test constructors and vote rules.
- `ergo-validation/src/block/`: validation drivers, roots/linkage, extension,
  interlinks, fork-vote, size, layering, overlay and block error taxonomy.
- `ergo-validation/src/tx/mod.rs`: raw/parsed/with-group-elements entry points,
  canonicality, resolution, checked transaction and context/rule bundles.
- `ergo-validation/src/tx/{structural,monetary,heights,ge,reemission}.rs` and
  `tx/script/`: evaluator bridge, init cost and storage-rent branch.
- `ergo-validation/src/context.rs`, `pre_header.rs`, `storage_rent.rs`, `cost.rs`.
- `ergo-validation/src/active_params/`, `voting/` and their wire/persist codecs,
  epoch recompute, rule settings, vote selection/tallies and extension matching.
- `ergo-validation/src/popow/`: algorithms/proving/scoring/interlinks, proof
  connections, Merkle verification and stateful best-proof selection.
- All inline tests, `ergo-validation/tests/it/`, standalone diagnostics and
  linked mainnet/testnet/Scala/cost-ledger fixture and extraction/oracle tooling.

## Header and checked-object contracts

Verify PoW and context-dependent finalization together: parent ID, height,
genesis, nBits, timestamp equality/future drift, votes, version behavior and ID
derivation. Do not invent version-by-height rules the reference does not enforce.
Trace current time injection and overflow boundaries in timestamp arithmetic.

Audit persisted rehydration: exact bytes, EOF, expected ID, PoW-valid metadata,
height/parent/timestamp agreement and trust provenance. Check all constructors
and feature-gated escape hatches; map which downstream consumers trust them.
Verify documentation says what is proven after checkpoint/script skipping and
before state digest/application validation, including trusted public APIs.

## Transactions and evaluator bridge

Create an entry-point comparison table for raw validation, caller-parsed
validation, supplied-group-element validation, block paths, mempool and mining:

- Original bytes, parsed tx, derived tx ID and resolved box identities/order
  must be consistent. Check EOF, canonical reserialization and any intentionally
  normalizing Scala encoding; avoid extending canonical rejection without an
  external accept/reject witness.
- Verify parse-time group-element sideband completeness/index alignment through
  nested constants, headers, boxes, dead branches and degraded trees. Identify
  whether public APIs can be passed incomplete sidebands, and their actual trust
  precondition/caller boundary rather than assuming the type proves alignment.
- Check count bounds, nonempty collections, duplicates, positive value/assets,
  box/token/proposition size, min-value-per-byte and output-index narrowing.
  Wire caps and Scala validation caps differ; check each rule at its actual cap.
- Verify input/data-input resolution with adversarial or mistaken `UtxoView`
  results, length/order mismatches, output identity errors and duplicate data
  references. State authentication lives at the supplying caller boundary.
- Check ERG sums, token sums, negative/high-bit amounts, overflow, burning and
  minting from the first input ID. Verify rule ordering on multi-violation cases.
- Check future and monotonic creation heights, block-version activation and
  trusted persisted inputs; include boundary heights and u32 extremes.
- Audit all ErgoBox/candidate-to-EvalBox fields: retained script/register bytes,
  identity, transaction ID/index, token ordering, typed registers and SELF index.
- Verify script context selection: block versus upcoming-context header count
  and order, height, miner key, pre-header, extension, activated version,
  validation statuses and parent AVL root. Check coherent candidate snapshots.
- Review transaction init cost, token-access counting/order, per-input Sigma
  evaluation/crypto rounding, partial failure costs and error mapping. Distinct
  JIT overflow, cost limit, parse, reduction and bad proof errors must not merge
  incorrectly at the rule boundary.
- Audit storage rent's eligibility, signed wrapping fee calculation, output
  selection/shape, script/register/token preservation, insufficient value and
  fallback behavior. Independently verify the intentional i32 multiplication
  overflow instead of widening it as cleanup.
- Check EIP-27 activation, emission/non-emission branch, NFT/token identity,
  burning obligation, required nanoERG payment, aggregation and output script
  matching. Trace shared `reemission_obligation_core` use by wallet/builder.
  Rules must remain threaded even when a checkpoint skips scripts.

## Full block orchestration and parallelism

Audit linkage of all sections/header IDs, tx/witness roots, extension roots,
extension structural caps/duplicates, interlinks, fork-vote window and rule 306.
Check expensive payload work occurs at the intended commitment-bound stage;
compare rejection precedence with independent reference inputs.

Verify sequential/parallel acceptance, checked tx ordering, deterministic earliest
failure by original tx index and cost results. Layer order can differ from tx
index order; use multiple independently failing transactions in different layers.
Check forward dependencies, same-layer dependencies, cycles, missing boxes,
duplicate output IDs, intra-block double spends and malformed-output omissions.

Verify spend overlay versus data-input view separately: pre-block boxes spent
earlier remain data-readable; earlier in-block creates are data-readable; future
creates do not become readable merely because another parallel layer completes.
Use mainnet witnesses and adversarial orderings rather than a generic DAG model.

Trace each per-tx cap, block total summation, exact-cap/plus-one behavior, partial
execution after a failed layer and accounting across inputs/transactions.
Distinguish permitted speculation within a dispatched layer from later-layer
execution. Verify block parameter choice at an epoch transition, not only parent
defaults. Check checkpoint height/ID enforcement and retained non-script checks
through both paths and state-application callers.

## Voting, settings and persistence

Build an epoch/state-machine table covering launch rows for mainnet/testnet/
devnet, ordinary epochs, fork proposal/tally/rejection/approval/activation,
hardcoded v2 transition, v4 subblock injection and cumulative settings updates.

Check vote sign handling/i8::MIN, duplicate/opposite/unknown votes, threshold
comparisons, epoch-window linkage and missing ancestors. Verify min/max/step
rounding for each votable ID, including small values and vote-direction ties.
Test missing approved parameter IDs and inconsistent soft-fork keys against JVM
exceptions. Separate proposed update, newly activated update and cumulative rule
statuses; verify disabled-rule application and which rules can be disabled.

Audit extension versus persistence codecs as different formats: duplicate IDs,
unknown `extra` preservation, required fields, numeric widths/signedness,
version auto-detection, truncation/EOF, rule updates and deterministic ordering.
Check public caller-built active params against `ProtocolParams::from_active`
preconditions and its widening casts. Frozen fallback defaults are not the
authoritative per-epoch parameter source. Trace `ProtocolParams::for_block` and
rule-specific parent/target parameter choices through UTXO and digest callers.

## NiPoPoW acceptance

Review level calculation, difficulty context, interlinks packing/unpacking,
batch Merkle proof consumption/indices/markers, valid connections, suffix/prefix
ordering, m/k bounds, continuous mode, genesis binding, LCA/best argument and
score/tie behavior. Include malformed/empty/deep proofs and adversarial indices.
Trace proof generation separately from verification; same-crate proof round trips
cannot establish soundness. Check stateful best-proof replacement, counters,
reset and unchanged state after invalid input against pinned Scala evidence.
Genesis `None` is an explicit trust choice; inspect actual public-network callers.

## Required evidence and checks

Use the rule-by-rule rejection suites, vector integrity/L4 manifests, context
header-window witnesses, epoch-extension/vote corpora, full block/negative cases,
NiPoPoW fixtures and cost-total/ledger block families. Record selected, executed,
checked, ignored, skipped and missing cases. Pin oracle version/context per
fixture; synthetic UTXO block oracles do not automatically cover history rules,
mainnet root replay or every digest-state path.

```bash
cargo test --locked -p ergo-validation
cargo test --locked --no-run -p ergo-validation --features diagnostics
cargo clippy --locked -p ergo-validation --all-targets --all-features -- -D warnings
cargo doc --locked -p ergo-validation --no-deps --all-features
```

Run externally dependent diagnostics/campaigns only after validating their
prerequisites under COMMON. Feature-unified dev dependencies can expose helper
APIs during tests; verify the production build graph separately for a trust claim.

## Exit criteria

Deliver the COMMON report, coverage ledger, rule/entry-point/epoch matrices and
checked-object trust table. Every major verdict/cost claim needs independent
reference evidence with matching active params, state and context. Report proven
bugs, compatibility uncertainty, missing enforcement evidence and quality gaps
separately; enumerate cooperating state/mempool/mining obligations explicitly.
