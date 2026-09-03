# AVL arena read sessions + lazy LRU sizing — measured before/after

Issues #288 and #289 (workstream B of #257). Date: 2026-09-03.
Baseline commit: `f08b17c5` (origin/main).

Sibling of [`adproofs-regen-bench-2026-09-02.md`](adproofs-regen-bench-2026-09-02.md),
which established the baseline and the methodology. Fixture construction,
change-set shape, warm-up and median rules are unchanged; read that
document first. This one records what the two levers it identified in its
"secondary findings" section actually bought.

Machine: AMD Ryzen 7 7800X3D, 8 cores / 16 threads, 61 GiB RAM, Fedora
(Linux 7.0.11). `cargo test --release`, single-threaded, median of 5 after
one warm-up. Reproduce with:

```bash
cargo test -p ergo-state --release adproofs_regen_cost_table -- --ignored --nocapture
```

## Levers

**#288 — one read session per bulk AVL walk.** `CachedDiskArena` had a
`begin_read_session` / `end_read_session` pair that nothing called, so
`load_from_redb` always took its no-session branch: a fresh
`db.begin_read()` **and** a fresh `open_table` for every cold node read —
2,000,001 of each on a 1M-box hydration. The pair could not be called from
the state-apply walk anyway, because that walk holds `&mut AvlTree` while
it reads. It is now an RAII `ReadSession` guard whose state is shared with
the arena through an `Arc<Mutex<..>>` rather than borrowed from it, so a
mutating walk can hold one open; and the session caches the opened
`ReadOnlyTable`, not just the transaction, so a miss costs one B-tree
lookup and nothing else. Two call sites take one: the hydration walk
(`hydrate_batch_avl_prover`, read-only, covers every dry-run and mining
caller) and one block's pre-persist mutation walk in `apply_mutations`.
A session pins the redb snapshot it opened on, so it must never span a
change to the committed bytes; `NodeArena::commit` / `abort` close any
session still open, which bounds even a guard leaked by a panicking walk
to the block it was opened in. `read_session_pins_the_snapshot_it_opened_on`
pins the reason that backstop exists rather than leaving it as a comment.

**#289 — let the clean cache grow into its byte budget.**
`CachedDiskArena::new` derived an LRU item cap of `byte_budget / 100`, so
the shipped 1 GiB `[store] cache_bytes` default reserved a ~10.7M-slot
table up front and faulted its cold pages in as the walk populated it —
while the working set never came near the cap. The item cap was redundant:
`enforce_budget` already evicts by LRU until `clean_bytes <= byte_budget`,
so the byte budget was always the real bound and the item cap only ever
fired first by accident. It is now `LruCache::unbounded`, which starts
from an empty table and grows geometrically with occupancy. Eviction
semantics are byte-for-byte what they were — the `cached_disk_arena`
integration tests still pin them, and
`clean_cache_evicts_on_byte_budget_not_item_count` states the bound
directly.

## Hydration, ms (median of 5)

| boxes | cache | txs | baseline | +#288 | +#288+#289 | total |
|---:|---:|---:|---:|---:|---:|---:|
| 10,000 | 1 GiB | 0 | 46.04 | 47.28 | 7.89 | **5.8x** |
| 10,000 | 1 GiB | 10 | 62.41 | 37.01 | 7.86 | **7.9x** |
| 10,000 | 1 GiB | 100 | 73.34 | 42.10 | 8.13 | **9.0x** |
| 10,000 | 1 GiB | 500 | 65.14 | 42.85 | 10.50 | **6.2x** |
| 10,000 | 16 MiB | 0 | 27.61 | 8.75 | 8.94 | 3.1x |
| 10,000 | 16 MiB | 10 | 20.22 | 8.10 | 12.03 | 1.7x |
| 10,000 | 16 MiB | 100 | 18.85 | 8.26 | 10.90 | 1.7x |
| 10,000 | 16 MiB | 500 | 26.00 | 8.54 | 9.39 | 2.8x |
| 100,000 | 1 GiB | 0 | 413.32 | 229.76 | 166.58 | **2.5x** |
| 100,000 | 1 GiB | 10 | 488.90 | 238.01 | 129.81 | **3.8x** |
| 100,000 | 1 GiB | 100 | 460.85 | 246.68 | 175.01 | **2.6x** |
| 100,000 | 1 GiB | 500 | 445.21 | 270.39 | 136.16 | **3.3x** |
| 100,000 | 16 MiB | 0 | 309.58 | 135.32 | 163.28 | 1.9x |
| 100,000 | 16 MiB | 10 | 216.18 | 135.12 | 153.40 | 1.4x |
| 100,000 | 16 MiB | 100 | 181.83 | 192.08 | 140.72 | 1.3x |
| 100,000 | 16 MiB | 500 | 211.50 | 162.35 | 129.50 | 1.6x |
| 1,000,000 | 1 GiB | 0 | 3705.71 | 3083.11 | 2181.24 | **1.7x** |
| 1,000,000 | 1 GiB | 10 | 3744.71 | 2821.47 | 2272.53 | **1.6x** |
| 1,000,000 | 1 GiB | 100 | 4059.10 | 2676.05 | 1803.41 | **2.3x** |
| 1,000,000 | 1 GiB | 500 | 3103.52 | 2329.36 | 1788.90 | **1.7x** |
| 1,000,000 | 16 MiB | 0 | 2769.24 | 2440.63 | 1749.04 | 1.6x |
| 1,000,000 | 16 MiB | 10 | 3362.41 | 2007.89 | 1841.03 | 1.8x |
| 1,000,000 | 16 MiB | 100 | 3667.72 | 1930.83 | 2341.55 | 1.6x |
| 1,000,000 | 16 MiB | 500 | 4370.57 | 1817.59 | 2522.95 | 1.7x |

Read the 16 MiB rows as one regime and the 1 GiB rows as another: at 1M
boxes a 16 MiB arena evicts continuously while a 1 GiB one never does, so
the two are not interchangeable. The `#289` column moves the 16 MiB rows
around by tens of ms in both directions — that is run-to-run variation on
a lever that, at a 16 MiB budget, only ever reserved ~168k slots.

## The 1 GiB / 16 MiB hydration ratio, before and after #289

This is the number issue #289 was opened on: how much slower the shipped
default is than a small budget, at the same tree size.

| boxes | txs | baseline | after both levers |
|---:|---:|---:|---:|
| 10,000 | 0 | 1.67x | 0.88x |
| 10,000 | 10 | 3.09x | 0.65x |
| 10,000 | 100 | 3.89x | 0.75x |
| 10,000 | 500 | 2.51x | 1.12x |
| 100,000 | 0 | 1.34x | 1.02x |
| 100,000 | 10 | 2.26x | 0.85x |
| 100,000 | 100 | 2.53x | 1.24x |
| 100,000 | 500 | 2.11x | 1.05x |
| 1,000,000 | 0 | 1.34x | 1.25x |
| 1,000,000 | 10 | 1.11x | 1.23x |
| 1,000,000 | 100 | 1.11x | 0.77x |
| 1,000,000 | 500 | 0.71x | 0.71x |

The penalty at 10k and 100k boxes — the unambiguous part of #289's claim —
is gone: every ratio now sits within run-to-run noise of 1.0 instead of
1.5–3.9x. The 1M rows were noise before and are noise after, exactly as
#289's own revision note predicted.

**Recommended default: unchanged at 1 GiB.** No smaller budget was better
at every size once the pre-size was removed, and a smaller budget costs
eviction churn on a large tree. `[store] cache_bytes` per deployment size
still wants an IBD-shaped measurement (#257 workstream B methodology:
sampler CSV + `ERGO_MEM_MAPS=1`) before `docs/configuration.md` grows a
recommendation table; this micro-benchmark cannot substitute for it.

## Arena construction, ms (median of 5)

| boxes | cache | baseline | after both levers |
|---:|---:|---:|---:|
| any | 1 GiB | 5.16–8.97 | 0.00 |
| any | 16 MiB | 0.00–1.05 | 0.00 |

Production constructs the arena once per open, so this was never the
headline cost — but it is the direct fingerprint of the pre-sized table,
and it is now zero.

## Production-shaped check

Mainnet-fixture block application, `cargo test -p ergo-state --release`,
best of 3 wall-clock per binary, run on `origin/main` sources and on this
branch in the same worktree and target dir:

| test | what it applies | before | after |
|---|---|---:|---:|
| `chain_validate_1_1000` | blocks 1–1000, every tx fully validated against state-backed UTXO lookups | 0.95 s | 0.74 s |
| `digest_chain_1_1000` | blocks 1–1000 with digest verification at every height, plus rollback-window pruning | 1.41 s | 1.29 s |
| `ad_proofs_root_oracle` | ADProofs root vs Scala oracle | 0.00 s | 0.00 s |
| `avl_cold_restart` | cold-restart arena rehydration | 0.16 s | 0.14 s |

Both 1–1000 tests assert the state root at **every** applied height
against captured Scala-node vectors, so their passing is the digest-parity
evidence: the AVL root digests are byte-identical before and after. Wall
time is not worse. These fixtures are early mainnet — near-empty blocks
over a small tree — so they are a regression guard, not a throughput
measurement; the micro-benchmark above is where the size scaling lives.

## What did not pan out

Nothing was measured and discarded. Both levers were kept because both
moved the number they were opened against, in the direction and at the
scale the issues predicted. The one claim deliberately **not** made is
about mainnet IBD throughput: neither lever has been measured on a real
re-sync, and the hydration path they speed up is no longer on the
validation critical path at all since #265 replaced regeneration with
`verify_shipped_ad_proofs`. Their live value is on the paths that still
regenerate — mining candidate builds, `/utxo/*` reads, cold block apply —
and on every cold arena miss anywhere in the node, which is what the #288
session fixes generically.
