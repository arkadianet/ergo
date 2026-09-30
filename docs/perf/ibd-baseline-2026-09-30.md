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
