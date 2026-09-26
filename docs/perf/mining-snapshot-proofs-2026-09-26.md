# Committed-snapshot mining proofs

With `candidate_base_cache = false` (the existing default), mining now reads
authenticated AVL paths from its held redb snapshot rather than hydrating the
entire UTXO tree for each proof. It reuses the validator's scoped lazy prover,
keeps the canonical operation order and proof self-check, and retains no prover
graph after the call. The explicitly enabled full-tree base cache is unchanged.

## Reproduction

```powershell
cargo test -p ergo-state --lib benchmark_committed_snapshot_proofs -- --ignored --nocapture --test-threads=1
```

September 26, 2026, Windows / Ryzen 5950X / 128 GiB RAM / NVMe, workspace test
profile (`opt-level = 1`). Fixtures contain deterministic hashed keys and
128-byte values. Each sample performs the stated number of lookups, removals,
and insertions. One warm-up precedes five measured runs; the table reports
median wall times. Fixture construction and the common proof self-check are
outside the timed region. Every sample compares both root and proof bytes.

| UTXOs | Operations of each kind | Lazy node reads | Full tree nodes | Lazy | Full hydration + proof |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 8,192 | 1 | 65 | 16,385 | 0.983 ms | 23.245 ms |
| 8,192 | 64 | 2,637 | 16,385 | 22.238 ms | 23.944 ms |
| 131,072 | 1 | 105 | 262,145 | 1.885 ms | 440.283 ms |
| 131,072 | 64 | 4,659 | 262,145 | 50.121 ms | 435.710 ms |

These are warm, synthetic proof measurements, not full candidate-build times,
cold-storage throughput, live mainnet RSS, or comparisons with a reused cached
base. The cached mode may still benefit repeated large same-tip builds. Legacy
v1 database nodes lack child labels and require subtree reads to derive them;
they remain supported without retaining a full graph, but do not have the same
path-only I/O bound as v2 nodes.

## Correctness checks

- Mixed lookup/remove/insert batches, duplicate lookups, and replacement keys
  produce identical roots and proof bytes to full hydration.
- A held snapshot remains consistent across database writes; new snapshots
  observe missing/corrupt rows and restored rows.
- Failed operations do not poison later proofs. Invalid authenticated labels,
  root metadata, and cyclic legacy pointers fail rather than publishing a proof.
- The full state and mining suites and nine node mining integration tests pass,
  including candidate generation, solving and submission on isolated fixtures.
  Clippy passes for all targets of `ergo-state`, `ergo-mining`, and `ergo-node`.

No live node configuration or deployment was changed for these measurements.
