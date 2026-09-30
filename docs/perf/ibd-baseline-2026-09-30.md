# Current-path IBD/RSS baseline

This baseline covers two distinct profiles: a read-only observation of the
running archival node, and repeatable offline full-block replay on disposable
copies of a pinned early-mainnet state. They are not interchangeable workloads
and are not a before/after speedup comparison.

## Reproduce the offline cache comparison

Use the repository-pinned Rust toolchain and run from the repository root:

```sh
cargo build --release --locked -p ergo-node --example ibd_baseline
target/release/examples/ibd_baseline prepare /scratch/new-seed 1073741824
python3 scripts/bench-ibd.py \
  --binary target/release/examples/ibd_baseline \
  --snapshot /scratch/new-seed/state.redb \
  --output-dir /scratch/new-results --runs 3 --cache-mib 16 128 1024
```

Both preparation and replay refuse existing destination directories. The
runner removes only its own temporary copies and checks that the source
snapshot's hash remains unchanged. Retain the JSON results, memory CSVs,
mapping markers and stderr with the baseline. The runner records binary and
snapshot SHA-256, source commit/dirty status, CPU, RAM, OS, filesystem,
toolchain, cache conditions and per-run load averages.

Preparation verifies mainnet headers 1..1000 with real PoW and difficulty,
reconstructs transactions/interlink extensions from the committed fixtures,
checks section identities and applies every block with script validation and
state-root checks. It generates the canonical AD proofs outside measurement.
The replay opens a new copy, rolls back to 850, and applies blocks 851..1000
through production `process_block` with **VerifyShipped**, a 64-job persist
channel and IBD flush interval 500. It uses no script checkpoint. Every run
flushes commits, shuts down cleanly and reopens to check the original height
and root. The pinned final root is
`736dead46883b961dacc8d3386dee59a579cf5abb42f881a37b08ebc2fb947240c`.

Header preparation, snapshot copying and rollback are outside the timing.
Downloads, peer/event queues, extra indexing, wallets and mining are outside
this offline profile. Their absence is not evidence of zero memory use in a
network node. Source fixtures and copied snapshot pages are OS-cache warm;
each replay's process and AVL cache are fresh. No global cache drop is made.

## Measurement semantics

`enqueue_seconds` includes validation, apply and per-ten-block memory sampling;
`committed_seconds` also waits for the persist barrier; `durable_seconds` also
includes clean shutdown. Report both committed and durable throughput. The
worker's shutdown progress monitor can add approximately 0.5 seconds, which
dominates this short interval; do not attribute that time to proof validation
or use it to forecast sustained network throughput.

Phase counters separate header/section reads, parent context, transaction
validation and state apply/enqueue. Their sum is not durable wall time: proof
handling and other work are not individually split, and persistence overlaps
the caller. The CSV uses existing `/proc` RSS and `smaps_rollup` samplers.
`ERGO_MEM_MAPS=1` markers reuse the existing mapping buckets at apply start,
commit and the final retained-memory sample. Mapping sizes are virtual address
space; RSS is measured separately. Three plateau samples span 1.5 seconds,
which is a short retained-memory observation, not a long-term leak test.

Persist-channel length and unpersisted pinned AVL bytes are sampled after
every block. The channel count excludes the worker's current batch and result
queue. Observed peaks are lower bounds, not the configured capacity or an
estimate of total queued payload bytes. CSV RSS peaks likewise may miss short
transients between samples. Redb cache-eviction counters are zero when the
dependency's `cache_metrics` feature is disabled and must not be interpreted
as evidence of zero misses.

## Read-only live observation

On Linux, with a known node PID and its public API address:

```sh
python3 scripts/sample-live-ibd.py \
  --url http://127.0.0.1:9063 --pid NODE_PID \
  --output-dir /scratch/new-live-results --duration 120 --interval 1
```

This polls public info/sync/metrics and `/proc/PID/{status,smaps_rollup}`.
It captures mapping residency separately at both ends, verifies the executable
hash stays constant, and reports height delta over monotonic elapsed time.
It sends no signals, reads no credentials and changes no configuration. Keep
deployment build metadata and sanitized mode/cache/indexer/mining settings
with the output. A live run is uncontrolled with respect to peer bandwidth,
block mix, indexing, mining and other host work. Quantized last-apply gauges
are sampled observations, not cumulative phase timings.

## Regression procedure

Keep the exact executable, preparation commit, fixture hashes, immutable
snapshot hash and raw results. Build candidate and baseline before measuring;
do not overlap compilation/tests with comparison runs. Use the same snapshot,
filesystem, host, cache budget, proof policy, script checkpoint and persist
settings. Rotate execution order and report individual runs and medians.
Verify identical roots and successful reopen before comparing time or memory.
Separate cache-budget comparisons from code-change comparisons.

Repeat longer, later-chain intervals before extrapolating to full-mainnet IBD
or choosing a universal budget. For a longer offline interval, provision an
explicitly owned consistent snapshot with enough rollback history and the
appropriate epoch/re-emission configuration. Never copy an actively changing
database and assume it is a consistent snapshot. Synthetic regeneration
benchmarks remain useful for attribution but do not replace full validation.
No CI throughput threshold or speculative cache/queue optimization is added.

## Recorded results, 2026-09-30

Raw [offline results](data/2026-09-30/offline/summary.json), nine individual
JSON/CSV/marker/stderr files in that directory, and
[live results](data/2026-09-30/live/summary.json) with compressed samples and
[sanitized deployment settings](data/2026-09-30/live/deployment.json) accompany
this report. Units below use KiB for resident memory and MiB for cache budgets.

The host was an AMD Ryzen 7 7800X3D (8 cores, 16 logical CPUs),
64,920,620 KiB RAM, Pop!_OS 24.04 LTS, Linux 7.1.5-76070105-generic,
glibc 2.39. Storage was an Intel Optane INTEL SSDPEK1A118GA, 110.3 GiB,
`/dev/nvme0n1p1`, ext4. Rust was 1.95.0 (59807616e, 2026-04-14).
No compilation or tests overlapped the recorded windows. The archival node
remained running throughout the offline comparison, so other host load was
not eliminated; per-run load averages are retained.

Offline provenance:

| Item | Value |
|---|---|
| Source commit (clean) | `07bd01fe5a3cd27633238b7faa570b76b3d236b8` |
| Release example SHA-256 | `55013490c2b8cccde4d43df312ff942fcb699556c00d33f04787db7c9b20ee25` |
| Immutable prepared snapshot SHA-256 | `821af804d3e275968d85b6f646833be1ef04f59dafa853e77af8bc7f2cafb60f` |

The seed was closed after preparation and unchanged after all nine replays.
Regenerating it can change database allocation/layout and its file hash even
with the same logical root. Preserve the exact snapshot for a comparison;
a newly prepared snapshot requires a new matched baseline.

### Offline full-validation replay

Each row reports medians of three fresh-process runs over the same 150 blocks.
All nine runs verified shipped proofs, scripts, final root and successful
shutdown/reopen. Budget order rotated between runs.

| AVL budget MiB | Committed seconds | Committed blocks/s | Durable seconds | Durable blocks/s | Sampled peak RSS KiB | Retained RSS KiB | Retained anon / file KiB |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 16 | 0.06394 | 2345.9 | 0.58473 | 256.5 | 41484 | 41484 | 33980 / 7504 |
| 128 | 0.06030 | 2487.7 | 0.57172 | 262.4 | 41656 | 41656 | 34060 / 7576 |
| 1024 | 0.06320 | 2373.5 | 0.58289 | 257.3 | 42032 | 42032 | 34420 / 7532 |

Shutdown dominates the durable timing for this short workload. Neither column
is a forecast for later-chain network IBD. The small differences among budgets
do not demonstrate an optimal budget or a code speedup.

Median cumulative phase counters, milliseconds across all 150 blocks:

| AVL budget MiB | Header load | Section load | Parent context | Transaction validation | State apply/enqueue | Total instrumented block time |
|---:|---:|---:|---:|---:|---:|---:|
| 16 | 2.641 | 6.312 | 3.534 | 15.378 | 18.636 | 54.651 |
| 128 | 2.102 | 6.190 | 3.403 | 15.050 | 17.670 | 51.990 |
| 1024 | 2.205 | 6.069 | 3.172 | 16.363 | 18.307 | 54.165 |

Validation and apply/enqueue are the largest separately measured caller
categories. Proof handling remains within unclassified time; this evidence
does not establish a particular proof or persistence bottleneck.

| AVL budget MiB | Maximum sampled clean AVL bytes | Maximum observed persist-channel jobs | Maximum observed unpersisted pinned AVL bytes |
|---:|---:|---:|---:|
| 16 | 167952 | 4 | 15592 |
| 128 | 167952 | 8 | 24957 |
| 1024 | 167952 | 4 | 13670 |

These are maxima across each budget's three runs. The clean working set was
approximately 164 KiB and fit every budget; no material cache effect was
shown. The configured channel capacity was 64. Observations do not include the
worker's current batch or measure total queue payload memory. Mapping markers
reported no redb file mapping. Anonymous virtual reservations were much larger
than resident anonymous memory; virtual address space is not an RSS cost.

### Live archival IBD

The public-network node was observed from 12:10:04.792 to 12:12:05.624 UTC,
with 116 samples over 120.832 seconds. It ran release main commit
`5d62fd5851e74fcb965b4aba50e1b423127f46f1`, executable SHA-256
`be94a3309b3896f7370a52be8129bfbe25f506fab3c650402846d910765f0b99`.
This deployment predates the follow-up fixes. It used UTXO archive mode, full
transaction/script validation (checkpoint 0), no bootstrap, a 2 GiB AVL budget,
200 retained versions, download window 384, enabled indexer and mining, with
existing warm process/database/OS caches. No restart or configuration change
was made for this observation.

| Quantity | Observation |
|---|---:|
| Applied height | 697175 → 701050 (3875 blocks) |
| Wall throughput | 32.069 blocks/s |
| RSS first → last KiB | 3652624 → 4102052 |
| Sampled peak RSS KiB | 4102056 |
| Anonymous resident first → last KiB | 3626600 → 4076028 |
| File resident first → last KiB | 26024 → 26024 |
| Pending-block sampled peak | 387 |
| In-flight sections / peers sampled peaks | 768 / 21 |
| Orphan groups / headers sampled peaks | 0 / 0 |
| Apply errors / wedged gauge | 0 / 0 |
| Sampled last-apply duration median / maximum | 11 / 189 ms |

The received-ID set reached 10000 entries; it is deduplication history, not a
count of retained section payloads. Pending-block counts on this deployment
can include fork bodies and must not be equated with the forward download
window. Gauge samples do not provide cumulative phase times or a persist
queue memory breakdown.

At the end, full mapping buckets showed anonymous RSS 4,067,988 KiB,
heap 7,256 KiB, stack 12 KiB, and other file/special mappings 26,796 KiB;
there was no redb file mapping bucket. These separately read `/proc` samples
need not sum exactly to the earlier `status` sample. RSS grew from roughly
3.5 to 3.9 GiB, almost entirely in anonymous memory. This observation does not
identify its owner: allocator-backed redb caches, AVL nodes, indexer/mining
work and queues share that category. The window did not reach an RSS plateau
and does not establish a leak or justify assigning growth to one component.

The live 32 blocks/s and offline figures cover different heights, state sizes,
block mixes and concurrent work. They cannot be treated as a before/after
comparison. Follow the matched regression procedure above before changing a
cache, queue policy or performance threshold.
