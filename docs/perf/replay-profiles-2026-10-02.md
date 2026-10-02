# Replay profile smoke — 2026-10-02

The maintained replay runner successfully compared four independent AVL/redb
budgets against the same closed first-1,000-block mainnet snapshot. Every one of
the 12 disposable copies replayed heights 851–1,000 (150 transactions), restored
the original root and height, and verified both again after clean reopen. The
locked source and executable hashes stayed unchanged. This validates the
measurement path on a small early workload; it does not establish a later-chain
memory budget or a code speedup.

[Instructions and workload definitions](replay-profiles.md),
[raw summary](data/replay-profiles-2026-10-02/summary.json),
[all per-run records](data/replay-profiles-2026-10-02/records.json), and
[build/host provenance](data/replay-profiles-2026-10-02/provenance.json) accompany
all 12 CSV captures and stdout/stderr files in the same data directory.

## Conditions

- Candidate Rust source: `c1ec894d5eda42be18351adccea27cea2365ee33`;
  runner source: `4c132be3e2a1fd8190517975cb27b846e90e3800`, clean tree.
- Release executable SHA-256:
  `d710d7207322522fdf8f849c390e92adc2890e6a91fe63f225888f8ddf2484a0`.
- Closed seed SHA-256:
  `821af804d3e275968d85b6f646833be1ef04f59dafa853e77af8bc7f2cafb60f`;
  403,714,048 bytes. This is the preserved seed from the archived benchmark
  implementation at `ba2ac17932c8ca818594f110b5b25e9c07ac6dba`, prepared from
  the committed mainnet fixtures. The maintained `prepare` command can produce
  a logically equivalent seed, but file allocation/layout and its hash can differ.
- AMD Ryzen 7 7800X3D, 64,920,620 KiB RAM, ext4, Rust 1.95.0;
  `cargo build --release --locked -p ergo-node --example ibd_replay`.
- Three runs per profile, rotated profile order; proof policy `regenerate`,
  persistence channel capacity 64, IBD flush interval 500, three idle retained
  samples per run. Fresh processes and application caches; OS page cache warm.
- No compilation or workspace tests overlapped the measured runs. The live node,
  desktop and other background services remained running. Per-run load averages
  are retained; this is not an isolated machine experiment.
- Header downloads/PoW, indexer, wallet, mining and API activity are outside the
  replay process. Preparation, rollback, copying and reopen are outside the timer.

## Medians across three runs

| AVL budget (MiB) | State redb budget (MiB) | Committed time (ms) | Durable time (ms) | Sampled peak RSS (KiB) | Retained RSS (KiB) | State redb evictions at end |
|---:|---:|---:|---:|---:|---:|---:|
| 16 | 16 | 84.3 | 613.5 | 29,152 | 28,124 | 4,195 |
| 1,024 | 16 | 81.7 | 611.2 | 29,164 | 28,124 | 4,192 |
| 16 | 1,024 | 94.8 | 632.3 | 49,244 | 49,244 | 0 |
| 1,024 | 1,024 | 94.3 | 626.7 | 49,240 | 49,240 | 0 |

Redb counts are active cumulative counters since opening each copy, so they
include opening and rollback outside the measured replay interval. Retained RSS
is sampled while the store remains allocated after its clean shutdown; it is
not a total-node or long-running RSS bound. Sampling does not capture every
instantaneous peak.

The observed clean AVL occupancy was 227,328 bytes in every profile, well below
both AVL budgets. Median observed pinned unpersisted bytes were 5,129–7,293;
median input-channel occupancy peaks were 0–1 jobs, with a maximum of six in an
individual run. These sampled channel counts exclude the worker's active batch
and results. Phase timings, queue observations and anonymous residency are in
the raw records.

The matched root was:

```text
736dead46883b961dacc8d3386dee59a579cf5abb42f881a37b08ebc2fb947240c
```

## Limits and next measurement

The committed intervals were only 77.5–100.9 ms. The roughly 0.5-second shutdown
monitor wait dominates durable timing; sampling, scheduling, file layout and
other background work matter at this scale. Differences here cannot select an
optimal production budget, demonstrate a regression/improvement, or justify
changing the preserved defaults. The three-second retained window also cannot
prove or disprove a leak.

The next informative input is a separately owned, closed, consistent later-chain
UTXO snapshot retaining full bodies, canonical header/parameter history and a
rollback interval. The maintained runner accepts such a snapshot with its pinned
hash and refuses a database currently owned by a node. No closed later-chain
UTXO snapshot was available for this capture. No running node database was
copied, stopped or reconfigured. Use the same crossed profiles and matched
proof/persistence settings on that input, then a longer combined-load soak for
owners excluded from replay.

## Reproduce

On a machine holding the preserved seed, build the recorded Rust revision and
run the recorded runner revision with a new output path:

```sh
python3 scripts/bench-ibd.py \
  --binary target/release/examples/ibd_replay \
  --source-commit c1ec894d5eda42be18351adccea27cea2365ee33 \
  --snapshot /scratch/closed-seed/state.redb \
  --snapshot-sha256 821af804d3e275968d85b6f646833be1ef04f59dafa853e77af8bc7f2cafb60f \
  --output-dir /scratch/new-replay-results \
  --runs 3 --blocks 150 --retained-seconds 3 \
  --profile constrained:16:16 small_redb:1024:16 small_avl:16:1024 default:1024:1024
```
