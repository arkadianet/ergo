# ADProofs regeneration micro-benchmark — measured baseline

Issue #257, workstream A step 1. Date: 2026-09-02.

## What is measured

`StateStore::regenerate_ad_proofs` (the proofHash check PR #256 ran per
applied block, before PR #265 replaced it for UTXO backends) is split into
its two phases plus the two things it should be compared against:

| column | code under test | expected complexity |
|---|---|---|
| arena setup | `CachedDiskArena::new` | O(cache byte budget) — **once per open**, not per block |
| hydrate | `avl::hydrate::hydrate_batch_avl_prover` | O(tree size) arena reads + heap |
| prove | `store::dry_run::apply_change_set_to_prover` | claimed O(block); measured O(tree size) — see below |
| regen total | hydrate + prove | what `regenerate_ad_proofs` costs per block |
| verify-shipped | `store::dry_run::self_check_candidate_proof` | O(block) — same replay `verify_shipped_ad_proofs` (#265) performs |
| state-apply | `AvlTree::remove` / `insert` for the same change-set | O(block · log tree) — the denominator |

The harness is `ergo-state/src/store/dry_run_bench.rs`, an `#[ignore]`d
crate-internal test (`adproofs_regen_cost_table`). No new dependency was
added — it uses `tempfile` and `redb`, both already present.

## Methodology

- Fixture: `n` synthetic 90-byte boxes with deterministic splitmix64 keys,
  inserted into a real `AvlTree` on a `CachedDiskArena` and committed to a
  real redb `AVL_NODES` table in a `tempfile::tempdir()`. Every measured
  hydration therefore reads through the same disk-arena path production
  uses, not an in-memory shortcut.
- Every run constructs a **fresh** `CachedDiskArena`, so the clean LRU is
  cold. The OS page cache is warm (one untimed warm-up iteration precedes
  the timed ones), which makes these numbers a **floor** for a real node
  whose 70+ GB state does not fit in page cache.
- Block change-sets: `txs` transactions, each with one data input
  (lookup), two spent boxes (removes) and two created boxes (inserts).
  Each transaction claims three consecutive stride slots across the whole
  key space, so the data-input path and the two spent-box paths are
  pairwise disjoint and the proof visits independent root-to-leaf paths.
  The fixture asserts that disjointness — an earlier revision of this
  benchmark strided lookups and removals over overlapping index ranges,
  which made almost every lookup free (the removal already walked that
  path) and understated proof size by 13–16 %. `txs = 0` is an empty block.
- 5 timed runs per cell after 1 warm-up; the table reports the **median**.
- The state-apply column runs on its own cold arena so the hydration walk
  has not already warmed it. Its post-root is asserted equal to the
  prover's root, so the two columns are measuring the same transition.
- Both the shipped default cache budget (`StateStore::DEFAULT_CACHE_BYTES`
  = 1 GiB) and a constrained 16 MiB budget are measured.

Machine: AMD Ryzen 7 7800X3D, 8 cores / 16 threads, 61 GiB RAM, Fedora
(Linux 7.0.11). `cargo test --release` (opt-level 3). Single-threaded test.
Reproduce with:

```bash
cargo test -p ergo-state --release adproofs_regen_cost_table -- --ignored --nocapture
```

(`ERGO_REGEN_BENCH_SIZES` / `ERGO_REGEN_BENCH_RUNS` override the defaults.)

## Numbers

All times in milliseconds, median of 5.

| UTXO boxes | cache | block txs | ops | arena setup ms | nodes read | hydrate ms | prove ms | regen total ms | verify-shipped ms | state-apply ms | proof B |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 10000 | 1024 MiB | 0 | 0 | 4.82 | 20001 | 46.87 | 4.61 | 51.47 | 0.00 | 0.00 | 34 |
| 10000 | 1024 MiB | 10 | 50 | 4.81 | 20001 | 45.44 | 5.30 | 50.73 | 0.34 | 1.37 | 22818 |
| 10000 | 1024 MiB | 100 | 500 | 5.06 | 20001 | 47.28 | 6.30 | 53.58 | 2.04 | 9.13 | 165169 |
| 10000 | 1024 MiB | 500 | 2500 | 4.69 | 20001 | 44.52 | 9.67 | 54.19 | 7.38 | 32.23 | 559741 |
| 10000 | 16 MiB | 0 | 0 | 0.00 | 20001 | 16.09 | 4.48 | 20.57 | 0.00 | 0.00 | 34 |
| 10000 | 16 MiB | 10 | 50 | 0.00 | 20001 | 14.91 | 3.93 | 18.84 | 0.32 | 0.74 | 22818 |
| 10000 | 16 MiB | 100 | 500 | 0.00 | 20001 | 13.75 | 4.68 | 18.43 | 2.01 | 4.13 | 165169 |
| 10000 | 16 MiB | 500 | 2500 | 0.00 | 20001 | 14.43 | 9.18 | 23.61 | 7.41 | 20.11 | 559741 |
| 100000 | 1024 MiB | 0 | 0 | 5.33 | 200001 | 336.24 | 64.10 | 400.34 | 0.00 | 0.00 | 34 |
| 100000 | 1024 MiB | 10 | 50 | 6.05 | 200001 | 333.84 | 52.92 | 386.76 | 1.57 | 2.13 | 28617 |
| 100000 | 1024 MiB | 100 | 500 | 5.66 | 200001 | 321.95 | 56.54 | 378.49 | 5.41 | 15.58 | 226292 |
| 100000 | 1024 MiB | 500 | 2500 | 5.19 | 200001 | 316.00 | 62.12 | 378.12 | 16.51 | 56.30 | 919555 |
| 100000 | 16 MiB | 0 | 0 | 0.02 | 200001 | 200.97 | 55.77 | 256.74 | 0.00 | 0.00 | 34 |
| 100000 | 16 MiB | 10 | 50 | 0.02 | 200001 | 201.94 | 53.19 | 255.13 | 1.53 | 1.17 | 28617 |
| 100000 | 16 MiB | 100 | 500 | 0.02 | 200001 | 201.41 | 55.72 | 257.13 | 5.07 | 7.83 | 226292 |
| 100000 | 16 MiB | 500 | 2500 | 0.02 | 200001 | 211.84 | 63.44 | 275.28 | 18.01 | 33.17 | 919555 |
| 1000000 | 1024 MiB | 0 | 0 | 7.69 | 2000001 | 2698.66 | 554.81 | 3253.47 | 0.00 | 0.00 | 34 |
| 1000000 | 1024 MiB | 10 | 50 | 6.26 | 2000001 | 2661.90 | 546.40 | 3208.30 | 3.38 | 10.58 | 34180 |
| 1000000 | 1024 MiB | 100 | 500 | 6.34 | 2000001 | 2639.33 | 552.50 | 3191.82 | 18.12 | 20.82 | 284760 |
| 1000000 | 1024 MiB | 500 | 2500 | 6.02 | 2000001 | 2566.26 | 532.58 | 3098.84 | 41.79 | 78.92 | 1214620 |
| 1000000 | 16 MiB | 0 | 0 | 1.00 | 2000001 | 2558.00 | 482.91 | 3040.91 | 0.00 | 0.00 | 34 |
| 1000000 | 16 MiB | 10 | 50 | 0.35 | 2000001 | 2486.45 | 479.70 | 2966.15 | 10.75 | 1.39 | 34180 |
| 1000000 | 16 MiB | 100 | 500 | 0.45 | 2000001 | 2569.42 | 485.88 | 3055.30 | 15.49 | 10.68 | 284760 |
| 1000000 | 16 MiB | 500 | 2500 | 0.37 | 2000001 | 2525.46 | 509.37 | 3034.84 | 33.78 | 45.48 | 1214620 |

### Derived

Regeneration cost per block, 16 MiB budget, versus block size:

| UTXO boxes | empty block | 500-tx block | ratio |
|---:|---:|---:|---:|
| 10,000 | 20.6 ms | 23.6 ms | 1.15x |
| 100,000 | 256.7 ms | 275.3 ms | 1.07x |
| 1,000,000 | 3040.9 ms | 3034.8 ms | 1.00x |

Regeneration cost per block versus UTXO-set size (500-tx block, 16 MiB):

| UTXO boxes | regen total | scaling vs previous |
|---:|---:|---:|
| 10,000 | 23.6 ms | — |
| 100,000 | 275.3 ms | 11.7x for 10x boxes |
| 1,000,000 | 3034.8 ms | 11.0x for 10x boxes |

Regeneration versus the O(block) alternatives, 1M boxes, 500-tx block,
16 MiB: regen 3034.8 ms; verify-shipped 33.8 ms (**90x cheaper**);
state-apply core 45.5 ms (regen is **67x** the cost of the state
transition it is checking).

Hydration at the 1 GiB default versus the 16 MiB budget, per cell:

| UTXO boxes | empty | 10 tx | 100 tx | 500 tx |
|---:|---:|---:|---:|---:|
| 10,000 | 2.91x | 3.05x | 3.44x | 3.09x |
| 100,000 | 1.67x | 1.65x | 1.60x | 1.49x |
| 1,000,000 | 1.05x | 1.07x | 1.03x | 1.02x |

## Interpretation

The regeneration cost is **entirely a function of the UTXO-set size and
essentially independent of the block** — at a 1M-box tree an empty block
costs 3.04 s and a 500-tx block 3.03 s (1.00x), while growing the tree 10x
multiplies the cost by ~11x. That is the signature of a per-block
O(tree size) term, and it splits about 83 % hydration / 17 % proving. The
proving column is itself not O(block): at zero operations it still costs
0.48 s on a 1M-box tree, because `BatchAVLProver::digest()` recomputes
labels over the freshly hydrated graph whose nodes carry no cached labels.
So both phases of `regenerate_ad_proofs` scale with the tree, not the
block, and no amount of block-size tuning helps.

Extrapolating the measured ~11x-per-10x trend from 1M boxes to a
mainnet-sized set (~10M boxes) gives roughly 30 s per block on this
machine. That is still inside the 2-minute mainnet block interval, so the
warm-page-cache figure alone does not prove a node falls behind; what does
is the cold-disk measurement in PR #265, where a real 74 GB archival node
ground through 100 blocks in 69 min (~2.4 min/block) — comfortably past
the interval, and therefore unable to keep up. The benchmark's role here
is to identify the *mechanism* (an O(tree size) term paid per block) and
show it is already 30 s at a tree an order of magnitude smaller than
mainnet's with everything in page cache; #265's field measurement is what
establishes that a real node exceeds the block interval. #264 was the
field report of exactly that.

Given that, **the cached-prover reuse idea from issue #257 step 3 is not
worth building for the apply path.** PR #265 already removed the
regeneration from UTXO apply in favour of verifying the shipped proofs,
and the numbers say that was the right shape of fix rather than a
stopgap: verify-shipped is 90x cheaper at 1M boxes and, unlike a cached
prover, it is O(block) with no resident-tree memory at all. A pristine-base
cache (`candidate_dry_run_cached` / `DryRunBase`) would replace a ~3 s
rehydration with an O(ops) advance, but it only helps while blocks arrive
strictly consecutively — any reorg, any tip flip, any gap poisons the base
and pays the full cost again — and it must hold the entire hydrated
`Rc<RefCell<Node>>` graph resident, which for a mainnet-sized tree is the
multi-GB heap that #264's RSS explosion was made of. That trade is worth
making for **mining**, where `candidate_dry_run_cached` already amortizes
hydration across repeated candidate builds at a single tip and the
resident cost buys many rebuilds; it is not worth it on the validation
path, which now has a strictly better option. The remaining regeneration
callers (mining candidate generation, and `AdProofsApplyPolicy::Regenerate`
as the non-production default) are unaffected by this conclusion.

Two secondary findings fell out of the measurement and are worth
recording:

1. **Nothing calls `CachedDiskArena::begin_read_session`.** Grepping the
   crate, `begin_read_session` / `end_read_session` have no callers
   outside `avl/arena.rs`, so every cold node read opens its own redb
   read transaction (`load_from_redb`'s no-session branch). The hydration
   walk at 1M boxes takes 2,000,001 arena reads; each miss is a fresh
   `db.begin_read()` plus `open_table`. This is a live per-read overhead
   on every arena miss in production, not only in this benchmark, and it
   is a cheap independent win worth its own issue (#288).
2. **The 1 GiB default cache budget costs hydration throughput, by an
   amount that shrinks with tree size.** `CachedDiskArena::new` derives
   its LRU item cap as `byte_budget / 100`, so the shipped default
   allocates a ~10.7M-slot table. Hydration at 1 GiB was slower than at
   16 MiB in all twelve cells measured, but the penalty is strongly
   size-dependent: **2.91–3.44x at 10k boxes, 1.49–1.67x at 100k, and
   1.02–1.07x at 1M** (see the ratio table above). In absolute terms the
   overhead is 30–34 ms at 10k, 104–135 ms at 100k and 41–176 ms at 1M —
   i.e. roughly a fixed cost for faulting in the sparse oversized table,
   which is why it dominates a small tree's hydration and disappears into
   a large one's. The 1M row should not be leaned on: at a 16 MiB budget
   a 1M-box tree evicts continuously while the 1 GiB one never does, so
   that comparison spans two different cache regimes, and an earlier run
   of this same benchmark had 1 GiB 2.3 % *faster* than 16 MiB on the
   1M/500-tx cell against 1.6 % slower here — those single-digit
   differences are not separable from run-to-run variation. The claim
   supported by the data is therefore: **at trees of ~100k boxes and
   below, the oversized LRU table costs 1.5–3.4x on hydration**; at
   mainnet scale the effect is within noise and unproven either way.
   Production constructs the arena once per open, so the 5–8 ms of setup
   time is irrelevant; it is the per-insert page-faulting that shows up.
   Right-sizing the item cap from the *observed* node size rather than a
   hardcoded 100 bytes is a candidate for workstream B's `cache_bytes`
   lever (#289).

## Revision note

The table above was regenerated on 2026-09-03 after review found that the
original change-set builder strided data-input lookups and spent-box
removals over overlapping index ranges, so every lookup after the first
reused a path a removal already walked. With disjoint key sets the proof
grows 13–16 % (e.g. 794,536 → 919,555 bytes at 100k boxes / 500 tx) and
verify-shipped rises accordingly. Absolute times in the new table are also
lower than the first run across the board because the machine was quiet;
the first run overlapped a workspace `cargo test`. Every ratio and
conclusion in this document is computed from the new table. None of the
qualitative conclusions changed; the cache-budget claim in finding 2 was
materially corrected.
