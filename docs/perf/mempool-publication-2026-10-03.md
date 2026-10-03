# Mempool admission and API publication samples

The repeatable benchmark lives in `ergo-node/benches/mempool_publication.rs`.
It calls the production mempool entry point, realtime observer/bus, snapshot
publisher/ArcSwap, and API DTO JSON serializer. It has no new dependencies,
network calls, database writes, or externally supplied node.

Run from the workspace root:

```sh
CARGO_BUILD_JOBS=4 cargo bench -p ergo-node --bench mempool_publication --profile test > docs/perf/mempool-publication-2026-10-03.csv
```

The checked-in CSV contains one local run on October 3, 2026: Rust 1.95.0
(`59807616e`, LLVM 22.1.2), x86_64 Linux 7.1.5, AMD Ryzen 7 7800X3D, 16 logical
CPUs. It uses the workspace **test profile**, `opt-level = 1`, with debug
assertions enabled. Other audit compilation activity could use the same host;
CPU affinity/frequency, system load and allocator were not controlled. These
are diagnostic samples, not a production throughput or latency guarantee.
For a production optimization comparison, repeat the same command with
`--profile release` on a quiet machine and retain both complete sample files.
Do not compare timings across profiles as if only the source changed.

Each dimension gets one discarded warm-up and five recorded samples. The CSV
reports the sample's total elapsed nanoseconds and its arithmetic mean per
operation. No individual operation timings, percentile estimates, confidence
intervals or allocation counts are collected. Setup, subscriber drains and
summary checks are outside measured intervals. Admission checks each accepted
result inside its interval; the returned actions are consumed with `black_box`.
Assertions stop the run if a sample does not actually admit its transactions,
retain its shared bytes, advance the event cursor, or obey the bounded queue
and lag behavior.

| Case | Dimensions | Timed work | Work outside scope |
| --- | --- | --- | --- |
| `admission` | Initial pool 0/1000/5000, transaction bytes 256/4096, subscribers 0/1/32; 256 admissions per sample | `Mempool::process`, pool indexes/priority/anti-DoS/staging bookkeeping, allocation/copying, production observer and realtime publication | A synthetic validator derives unique independent input/output IDs from the first 8 bytes and charges 1 cost unit. It does **not** deserialize real Ergo transactions, read UTXOs, evaluate scripts, materialize output boxes or resolve CPFP packages. Seeding/payload construction/draining are untimed. The pool grows by 256 without eviction. |
| `realtime_drained` | Subscribers 0/1/32; 16,384 events per sample | `RealtimeMempoolObserver::on_admitted`, event timestamp/hex/JSON, sequence/backfill and bounded filtered fanout | Receivers drain between 128-event batches outside the timer. No websocket encoding, HTTP delivery, task scheduling, network or client processing. |
| `realtime_stalled` | Same fanout matrix and event count | Same publication path with subscriber queues left unread; eventually measures full-queue drop/lag flag path | Includes the first 256 successful queued events before saturation. It does not benchmark the socket worker closing a slow client. Zero subscribers is the same no-fanout baseline. |
| `snapshot_publish` | Prepared pool 0/1000/5000, retained transaction bytes 256/4096; 128 publishes per sample | Clone prepared transaction DTOs, build/publish production `NodeSnapshot`, ArcSwap replacement and one snapshot read | Does not time the node's production mempool projection walk, pool input/output overlay construction, peer projection, recent-block/state reads or complete `sync_tick`. Full transaction bytes are Arc-shared and checked for pointer identity. Other DTO panels are empty. |
| `api_mempool_json` | Same prepared pool/size matrix; 32 responses per sample | Read current ArcSwap snapshot and serialize its `ApiMempoolTransactions` DTO to a fresh JSON byte buffer | Does not include route/authentication, HTTP headers/transmission, Tokio scheduling or full transaction-body JSON. Transaction byte size here changes a metadata field; it does not enlarge the response by 256/4096 bytes per row. |

Selected medians of the five sample means, rounded to microseconds:

| Case | Pool | Bytes | Subscribers | µs/operation |
| --- | ---: | ---: | ---: | ---: |
| admission |0|256|0|2.75|
| admission |1000|256|0|6.88|
| admission |5000|256|0|33.59|
| admission |5000|4096|32|38.31|
| realtime_drained |0|256|0|0.46|
| realtime_drained |0|256|32|1.76|
| realtime_stalled |0|256|32|1.39|
| snapshot_publish |1000|256|0|35.05|
| snapshot_publish |5000|256|0|174.56|
| api_mempool_json |1000|256|0|585.21|
| api_mempool_json |5000|256|0|2904.87|

The complete 180 recorded rows in the [sample CSV](mempool-publication-2026-10-03.csv)
are the source for this table. The admission samples show a pool-size effect
under this synthetic validator and profile. They do not attribute that effect
to a particular function or establish the production algorithm's scaling. The snapshot and serialization cases show the cost of
those prepared DTOs under this harness; they do not measure the action loop's
end-to-end publication delay. Use the same dimensions, fixtures, profile and
measurement boundaries when comparing a future change. Add production
validator/CPFP/overlay cases explicitly before making claims about those paths.

`cargo bench` passes `--bench` to this custom benchmark harness and runs the
full recorded matrix. Direct invocation and `cargo test --all-targets` run a
small admission/publication/snapshot matrix with the same behavior checks. Ordinary tests retain the
original fixture and Scala oracle provenance: the large node test aggregate
includes behavior files under `src/node/tests/` without changing test filters.
