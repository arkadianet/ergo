# Mining candidate refresh

Pending mempool changes now wake the action loop at their refresh deadline.
They no longer need another inbound event or the 250 ms mempool polling tick.
The default minimum interval between refresh signals is 250 ms, previously
1,000 ms. Explicit configuration overrides still apply. The first mutation
after a quiet interval signals immediately; mutations during the interval
coalesce into one intent containing the latest mempool snapshot.

Applied-parent changes bypass the interval, including equal-height reorgs.
Once mining has started, header-only advances and rejection re-anchors retain
the current applied-parent work without rebuilding it. A failed locally solved
block whose templates were withdrawn still requests an immediate rebuild.

An obsolete build stops between phases, rent rows, and selected transactions
when its applied parent changes. An active script validation or AVL operation
finishes before cancellation; AVL restoration and the worker's one-request,
one-reply protocol remain intact. Same-parent mempool arrivals do not cancel a
publishable build, so continuous arrivals cannot starve publication. A new
parent receives a minimal candidate before full enrichment.

Selection now skips transactions that exceed the remaining size or cost budget
and considers later entries in priority order. A skipped transaction leaves the
overlay untouched; a child whose required output is unavailable also stays out.
Budget skips are not reported as invalid transactions.

## Proof reuse and measurement

The worker retains one successful state root and proof. Reuse requires an exact
match of applied-parent ID, parent state root, checked transaction IDs, and
complete canonical transaction bytes in block order. Transaction validation
still runs under every fresh candidate context, including its timestamp. The
cache works independently of `candidate_base_cache` and retains owned bytes
rather than another AVL graph. Changed transaction sets regenerate the proof;
failed misses clear the previous entry.

Reproduce the full-engine benchmark:

```bash
cargo test -p ergo-mining --test it benchmark_same_parent_full_refresh_proof_reuse -- --ignored --nocapture --test-threads=1
```

October 2, 2026, Linux / Ryzen 7 7800X3D, default test profile (`opt-level = 1`).
The fixture contains 32 independent fee-paying true-script transactions on one
fixed parent. Both paths have separately primed AVL base caches. After one
warm-up, 31 builds per path alternate execution order. Timings include opening
the committed snapshot, current transaction validation, candidate construction,
and publication. Fixture setup and solution inspection are outside the timed
region. Every pass compares published header, transaction, extension, root,
proof, work-message, and metric surfaces.

| Full build on the same parent and transaction set | Median | p95 |
| --- | ---: | ---: |
| Primed AVL base, regenerate proof | 2.807 ms | 2.928 ms |
| Primed AVL base, reuse proof after validation | 2.529 ms | 2.614 ms |

This comparison isolates proof reuse within the updated engine. It does not
measure live mainnet builds, cold storage, changed transaction sets, rent
enumeration, or the total improvement over the previous node. The deadline and
default-interval changes reduce intentional scheduling delay separately from
candidate assembly time. No live node or configuration was changed.

## Verification

The proof-cache tests reconstruct the committed state from the Scala-produced
`test-vectors/ergo-sigma/cost-ledger/blocks/p2pk.json.gz` fixture and compare
both cache misses and hits with its exact proof bytes and state root after full
script validation. Additional regressions cover extension and data-input order
changes, failed misses, cancellation after completed AVL restoration, latest
parent dispatch, retained-template recovery, budget backfilling, and deadline
wakeups without external events. New build log fields report proof reuse,
setup, rent resolution, assembly, publication, and worker overhead alongside
the existing consensus-phase timings.
