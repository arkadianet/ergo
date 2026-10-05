# Shipping an indexer schema change

The ordered registry in `ergo-indexer/src/store/migration_registry.rs` applies to
indexes already using redb 4. Boot reports `MigrationPending` when the persisted
version has a complete path to `INDEXER_SCHEMA_VERSION`; the dedicated indexer
worker runs those steps in order. Unsupported versions rebuild from genesis. Synchronous `IndexerStore::open` uses the same registry.

1. Bump `INDEXER_SCHEMA_VERSION` and append one named `MigrationStep` from the
   previous version to the new version. Keep existing steps and their fixed
   destination versions. The registry test requires unique `from` versions,
   adjacent `n → n + 1` steps, a contiguous chain and the current final version.
2. Implement the step with one atomic redb transaction. Check cancellation
   throughout long scans and immediately before commit. Write that step's
   fixed `to` version last, in the same transaction as its rows. A shutdown or
   crash leaves either the old version or the completed step; a subsequent
   boot resumes from the last committed version. A step failure triggers the
   background rebuild. The registry logs each step's name, versions and timing.
3. Add a regression test proving equivalence with a from-scratch index over
   the same blocks: compare rows byte-for-byte in **every table**, including
   metadata and undo, then roll back both indexes and compare again. Include
   relevant historical derivations, boundary cases and an injected failure
   proving atomicity. Show that the regression fails without the fix.
4. Run the real-data harness on a copy of an offline index, updating its
   source-version expectations for the new step. Keep source data untouched.
5. Add an **Upgrading** note to `CHANGELOG.md` describing supported versions,
   preservation, fallback and any space requirements. Run the repository gates.

## 0.11 upgrade policy and reference measurement

A stale 0.11 index (redb 2.6, schema below current) is deleted first through the
upgrade journal by default, freeing space for the state upgrade. With
`--keep-stale-indexer` or `[store] auto_upgrade_keep_stale_indexer = true`, it is
retained as a legacy rollback backup. Either way, after the state upgrade the
index rebuilds from genesis in the background while the node mines. A registered
schema migration path does not cause a stale redb 2.6 index to be converted.

Indexes already using redb 4, including main builds between #491 and #571 and
future schema bumps, migrate in place in the background when the registry has a
complete path. Boot never waits for the schema migration. Unsupported versions
and failed steps rebuild in the background.

The reviewer measured the 2 → 3 harness on a copy of a real 0.11 mainnet schema-2
index at height **1,887,066**, with **57,777,147 boxes**, **11.4 million
transactions**, and **140,557 tokens**:

| Phase | Reference result |
| --- | --- |
| Migration changes | 4 tokens and 14 boxes across 7 templates |
| Undo validation | 201 entries |
| Commit | 0.06 seconds |
| Box scan | 62 minutes across 6 workers on a heavily loaded machine |
| redb 2.6 → 4 file-format conversion | 3 hours 14 minutes under the same load |

File-format conversion hashes every typed row under both readers. Preserving
this index requires that conversion plus the migration and about **46 GB** of
extra disk, costing about as much as rebuilding. Running the conversion during
synchronous startup would add hours of mining downtime. The 0.11 path therefore
rebuilds; the registry remains useful for redb-4 indexes and future schema bumps.
These are reference measurements under load, not runtime estimates for every
machine.

## Real-data copy harness

For the existing 2 → 3 step, use an offline schema-2 index already converted to
redb 4. The ignored benchmark copies the source under the repository's `target/`,
migrates only that copy and reports copy/open, token, parallel box scan/merge,
template, undo and commit timings with final counts. It retains the migrated
copy for inspection. Never point other node commands at the source directory.

```sh
ERGO_INDEXER_MIGRATION_SOURCE=/path/to/offline/indexer-schema2.redb \
  cargo test --locked -p ergo-indexer --lib schema_two_real_data_copy_benchmark -- --ignored --nocapture
```

This benchmark checks checkpoint preservation and measures the existing step;
it does not replace the row-for-row equivalence and rollback tests above. The
non-ignored `schema_two_copy_harness_never_changes_source` test checks
the copy-only contract on a generated fixture.
