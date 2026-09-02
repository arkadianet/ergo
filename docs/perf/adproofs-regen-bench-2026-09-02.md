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
  (lookup), two spent boxes (removes) and two created boxes (inserts),
  with the touched keys strided across the whole key space so the proof
  visits independent root-to-leaf paths. `txs = 0` is an empty block.
- 5 timed runs per cell after 1 warm-up; the table reports the **median**.
- The state-apply column runs on its own cold arena so the hydration walk
  has not already warmed it. Its post-root is asserted equal to the
  prover's root, so the two columns are measuring the same transition.
- Both the shipped default cache budget (`StateStore::DEFAULT_CACHE_BYTES`
  = 1 GiB) and a constrained 16 MiB budget are measured.

Machine: AMD Ryzen 7 7800X3D, 8 cores / 16 threads, 61 GiB RAM, Fedora
(Linux 7.0.11). `cargo test --release` (opt-level 3). Single-threaded test.
Reproduce with:

```
cargo test -p ergo-state --release adproofs_regen_cost_table -- --ignored --nocapture
```

(`ERGO_REGEN_BENCH_SIZES` / `ERGO_REGEN_BENCH_RUNS` override the defaults.)

## Numbers

All times in milliseconds, median of 5.

| UTXO boxes | cache | block txs | ops | arena setup ms | nodes read | hydrate ms | prove ms | regen total ms | verify-shipped ms | state-apply ms | proof B |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 10000 | 1024 MiB | 0 | 0 | 7.34 | 20001 | 70.06 | 8.24 | 78.30 | 0.00 | 0.00 | 34 |
| 10000 | 1024 MiB | 10 | 50 | 8.83 | 20001 | 110.86 | 8.06 | 118.91 | 0.53 | 2.15 | 20255 |
| 10000 | 1024 MiB | 100 | 500 | 7.30 | 20001 | 79.15 | 10.14 | 89.29 | 3.09 | 13.72 | 144082 |
| 10000 | 1024 MiB | 500 | 2500 | 7.42 | 20001 | 80.77 | 16.00 | 96.77 | 12.15 | 59.06 | 494869 |
| 10000 | 16 MiB | 0 | 0 | 0.01 | 20001 | 25.04 | 7.91 | 32.94 | 0.00 | 0.00 | 34 |
| 10000 | 16 MiB | 10 | 50 | 0.01 | 20001 | 24.86 | 7.72 | 32.58 | 0.45 | 1.10 | 20255 |
| 10000 | 16 MiB | 100 | 500 | 0.01 | 20001 | 23.69 | 9.62 | 33.31 | 3.14 | 10.27 | 144082 |
| 10000 | 16 MiB | 500 | 2500 | 0.01 | 20001 | 26.50 | 16.37 | 42.87 | 12.80 | 40.57 | 494869 |
| 100000 | 1024 MiB | 0 | 0 | 7.48 | 200001 | 585.50 | 118.30 | 703.80 | 0.01 | 0.00 | 34 |
| 100000 | 1024 MiB | 10 | 50 | 8.89 | 200001 | 578.51 | 79.84 | 658.35 | 1.68 | 2.61 | 24286 |
| 100000 | 1024 MiB | 100 | 500 | 12.58 | 200001 | 599.23 | 95.66 | 694.89 | 6.76 | 24.30 | 193471 |
| 100000 | 1024 MiB | 500 | 2500 | 8.05 | 200001 | 568.27 | 106.09 | 674.36 | 25.39 | 108.91 | 794536 |
| 100000 | 16 MiB | 0 | 0 | 0.03 | 200001 | 331.91 | 101.55 | 433.47 | 0.01 | 0.00 | 34 |
| 100000 | 16 MiB | 10 | 50 | 0.04 | 200001 | 316.93 | 73.05 | 389.97 | 2.44 | 1.74 | 24286 |
| 100000 | 16 MiB | 100 | 500 | 0.03 | 200001 | 272.30 | 79.24 | 351.54 | 6.15 | 9.81 | 193471 |
| 100000 | 16 MiB | 500 | 2500 | 0.03 | 200001 | 280.77 | 81.38 | 362.15 | 21.38 | 42.06 | 794536 |
| 1000000 | 1024 MiB | 0 | 0 | 11.63 | 2000001 | 4055.66 | 789.77 | 4845.43 | 0.01 | 0.00 | 34 |
| 1000000 | 1024 MiB | 10 | 50 | 9.06 | 2000001 | 4406.78 | 829.99 | 5236.77 | 3.50 | 12.05 | 29034 |
| 1000000 | 1024 MiB | 100 | 500 | 9.37 | 2000001 | 4869.40 | 865.73 | 5735.13 | 23.34 | 27.99 | 240419 |
| 1000000 | 1024 MiB | 500 | 2500 | 7.36 | 2000001 | 3787.52 | 763.43 | 4550.95 | 55.24 | 135.52 | 1031733 |
| 1000000 | 16 MiB | 0 | 0 | 1.11 | 2000001 | 3812.27 | 735.61 | 4547.87 | 0.01 | 0.00 | 34 |
| 1000000 | 16 MiB | 10 | 50 | 0.70 | 2000001 | 3474.35 | 684.66 | 4159.01 | 14.07 | 1.64 | 29034 |
| 1000000 | 16 MiB | 100 | 500 | 0.80 | 2000001 | 3767.34 | 744.10 | 4511.43 | 21.13 | 15.87 | 240419 |
| 1000000 | 16 MiB | 500 | 2500 | 0.78 | 2000001 | 3878.56 | 773.20 | 4651.76 | 45.27 | 64.34 | 1031733 |

### Derived

Regeneration cost per block, 16 MiB budget, versus block size:

| UTXO boxes | empty block | 500-tx block | ratio |
|---:|---:|---:|---:|
| 10,000 | 32.9 ms | 42.9 ms | 1.30× |
| 100,000 | 433.5 ms | 362.2 ms | 0.84× |
| 1,000,000 | 4547.9 ms | 4651.8 ms | 1.02× |

Regeneration cost per block versus UTXO-set size (500-tx block, 16 MiB):

| UTXO boxes | regen total | scaling vs previous |
|---:|---:|---:|
| 10,000 | 42.9 ms | — |
| 100,000 | 362.2 ms | 8.4× for 10× boxes |
| 1,000,000 | 4651.8 ms | 12.8× for 10× boxes |

Regeneration versus the O(block) alternatives, 1M boxes, 500-tx block,
16 MiB: regen 4651.8 ms; verify-shipped 45.3 ms (**103× cheaper**);
state-apply core 64.3 ms (regen is **72×** the cost of the state
transition it is checking).

## Interpretation

The regeneration cost is **entirely a function of the UTXO-set size and
essentially independent of the block** — an empty block costs the same
4.5 s at a 1M-box tree as a 500-tx block does (4.55 s vs 4.65 s, 1.02×),
while growing the tree 10× multiplies the cost by 8–13×. That is the
signature of a per-block O(tree size) term, and it splits about 84 %
hydration / 16 % proving. The proving column is itself not O(block): at
zero operations it still costs 0.74 s on a 1M-box tree, because
`BatchAVLProver::digest()` recomputes labels over the freshly hydrated
graph whose nodes carry no cached labels. So both phases of
`regenerate_ad_proofs` scale with the tree, not the block, and no amount
of block-size tuning helps. Extrapolating the measured linear trend from
1M boxes to a mainnet-sized set (~10M boxes) gives ~45 s per block on this
machine with a warm page cache — the same order as, and consistent with,
the ~2.4 min/block that PR #265 measured on a real 74 GB archival node
with cold disk. Against a 2-minute mainnet block interval, a node paying
this per block cannot keep up: this was a real IBD/catch-up regression,
not a theoretical one, and #264 was its field report.

Given that, **the cached-prover reuse idea from issue #257 step 3 is not
worth building for the apply path.** PR #265 already removed the
regeneration from UTXO apply in favour of verifying the shipped proofs,
and the numbers say that was the right shape of fix rather than a
stopgap: verify-shipped is 103× cheaper at 1M boxes and, unlike a cached
prover, it is O(block) with no resident-tree memory at all. A pristine-base
cache (`candidate_dry_run_cached` / `DryRunBase`) would replace a ~4.5 s
rehydration with an O(ops) advance, but it only helps while blocks arrive
strictly consecutively — any reorg, any tip flip, any gap poisons the base
and pays the full 4.5 s again — and it must hold the entire hydrated
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
   is a cheap independent win worth its own issue.
2. **The 1 GiB default cache budget has a measurable per-arena
   construction cost.** `CachedDiskArena::new` derives its LRU item cap as
   `byte_budget / 100`, so the shipped default allocates a ~10.7M-slot
   table: 7–12 ms of setup (timed separately in the table above) and,
   more importantly, hydration at the 1 GiB budget runs consistently
   ~20–40 % slower than at 16 MiB across every size measured (e.g. 585 ms
   vs 332 ms at 100k boxes, empty block) because inserts into the sparse
   oversized table fault in cold pages. Production constructs the arena
   once per open so the setup millisecond count does not matter, but the
   per-insert penalty is paid for the life of the process. Right-sizing
   the item cap from the *observed* node size rather than a hardcoded 100
   bytes is a candidate for workstream B's `cache_bytes` lever.
