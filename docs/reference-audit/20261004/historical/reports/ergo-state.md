# ergo-state review — NOT_READY

Local ignored review artifacts only; no repository source, tests, docs, configuration, fixtures or oracle expectations changed. Authored coverage is complete: **120/120 files, 60,876 lines, 2,440,395 bytes**, read in full including comments, every test/helper, examples, manifests and regression seed. Exact hashes/ranges are in [the ledger](ergo-state-coverage.json); shared fixture/generator ownership and validation are separately recorded in [351 receipts](ergo-state-evidence/shared-fixture-coverage.json).

## Scope and baseline

Reviewed HEAD `5d62fd5851e74fcb965b4aba50e1b423127f46f1`, main, package0.10.0, edition2021, Rust/Cargo1.95.0, native Linux x86_64 kernel7.1.5/glibc2.39, 2026-10-03 UTC. Root manifest/profile/toolchain and CI, COMMON/assignment/state prompt, CONTRIBUTING, SECURITY, compatibility, architecture and codemap read fully. Preexisting README edit and untracked audit documents/prompts preserved. Scope includes both UTXO/digest backends, all authored cfg branches, all declared/undeclared tests and shared corpus consumers. Build outputs/runtime data/private operator databases are excluded. No operator wallet, live node or external service accessed.

Mainnet bytes and pinned reference provenance govern compatibility. Scala v6.0.3 `28ebb184b0c90ee9adebe1111eb6aa3244798ba9` is the recorded snapshot authority; neighboring v6.0.5/HEAD `5528ef569a41ebccbc8658212e6ee3c97d990b96` is separate. Historical audit documents describe another revision and are leads only. Internal Rust producer/verifier agreement is not independent Scala parity. Workspace owner fully read relevant generators/provisioning/docs and validated exact-hash fixture structures; state fully read authored extractors and consumers, separately validated the remaining manifest binary. Recorded provenance unavailable or revision mismatch remains explicit in workspace provenance receipts.

Parent restricted continuation to defensive source review and existing-test receipts. Earlier copied-package disposable logical-failure tests are preserved with their exact limited predicates; no further custom demonstrations were created.

## Contract and trust map

Public StateStore/StateBackendKind dispatch owns state application, rollback, bootstrap, metadata, readers, params and wallet integration. CheckedBlock is validation's capability; unchecked raw apply is restricted to genesis/test helpers. Peer sections, shipped proofs, reconstructed snapshots, local persisted rows, configuration, wallet rows and caches have distinct trust boundaries. UTXO applies sorted net operations, records before-images, recomputes/compares the expected root, and persists nodes/undo/allocator/index/epoch/wallet atomically. Digest verification binds parent/post root, proof hash, section/header identity, exact operations, resolved box IDs and removes before synchronous commit.

CommittedSnapshot holds one read transaction for all consensus reads; this prevents reading different database generations but cannot repair a semantically inconsistent generation. ChainStoreReader live calls may open distinct transactions. Header persistence is a separate foreground writer sharing CHAIN_STATE_META with the async full-block worker. Pipeline progress uses committed job sequences rather than heights and Acquire/Release watermark publication; completion-event loss is intentionally tolerated by the sticky watch barrier. Snapshot installation replaces dense arena IDs and publishes trusted-history/prune markers. Wallet hooks execute in the same chain writer transaction, while standalone wallet operations are separate. Wallet unspent selection filters Confirmed, excluding Immature/Spent; custom scans use separate tables. Canonical chain specs currently all use miner_reward_delay720; stale comments do not prove a current network maturity defect.

| State-changing path | Visibility / publication | Atomic tables and durability | Failure / recovery map |
|---|---|---|---|
| Genesis initialize | live tree before commit; genesis flag after success | AVL/root/ChainState, Immediate; allocator absent | boot aborts on failure; reopen scans allocator if absent |
| Direct UTXO apply | mutate then hard root check; publish after commit | AVL, composite undo, allocator, root, applied/header indexes, params/settings, emission, wallet | ordinary failure rebuilds from committed; failed rebuild must stop caller; Immediate except explicit IBD policy |
| Pipelined apply | queue acceptance advances speculative tree/height/chain/settings | worker up to50jobs per transaction; final root/allocator/ChainState; every block undo/index/wallet | queue pressure blocks producer; None/Eventual are not fsync; sticky flush detects worker failure, shutdown/error policy ST006 |
| Header insert/batch | foreground overlay then transaction | headers/meta/height/section/header index and entire ChainState; Immediate | failed batch clears overlay; independent writer ownership ST011 |
| Snapshot install | stage metadata, commit then replace arena | dense AVL/root/ChainState/anchor/trust/prune sentinel; Immediate | node halts bootstrap on error; allocator/root sentinel/height/watermark omissions ST001–004 |
| UTXO rollback/reorg | flush queued applies first; reverse before-images; publish after commit | AVL/root/allocator/undo/index/params/settings/emission/wallet; Immediate | failed mutation rebuilds committed tree; ancestor/prune/undo floors enforced |
| Digest apply/rollback | verify/preflight; commit then publish | paired digest/history/root/ChainState/index/params ledgers; Immediate | strict tip/genesis/history consistency; missing history rejected; postcommit cache failure is terminal |
| Typed peer section insertion | row visible on return | independent section transaction, usually None; whole-block durable variant Immediate | missing/pruned section can be redownloaded; prune admission and insertion share writer |
| Prune/backfill/NiPoPoW | individual guarded transaction and cache refresh | section/index/sentinel/metadata changes; quick-repair writer | monotonic floors, legacy validation before stamps; sparse history does not establish missing UTXO state |
| Flush / clean shutdown | barrier counts committed jobs; sticky errors survive lossy event channel | empty Immediate transaction forces durability | explicit flush truthful; shutdown ignores earlier nonpoisoning worker failure ST006 |

Authored unsafe/FFI/manual Send/Sync obligations were inventoried; no authored unsafe implementation requires a separate memory-safety finding. Relevant storage dependency unsafe/platform behavior remains pinned redb's boundary, not a certified transitive audit. Local cached redb2.6.3 CheckedBackend and transaction durability/quick-repair contracts were selected-source reviewed. Actual backend I/O poisons later access; quick repair saves allocator state and enables two-phase commit, with recovery-performance implications distinct from fsync guarantees. NODE owns its wallet change-address plain begin_write bypass.

## Confirmed findings

Eleven independently actionable findings: P0=0, P1=3, P2=6, P3=2. Source proof and existing assertions establish the defects/gaps below; no accepted-invalid-root consensus split or physical power-loss consequence is demonstrated.

### ST001 — P1 correctness/recovery — SOURCE_CONFIRMED: snapshot install retains an obsolete allocator across ordinary reopen

Expected: imported node IDs and allocator next_id must be atomically coherent (NodeId lifetime/reopen contract). `ergo-state/src/store/mod.rs:1177–1376` installs IDs0..N-1 and root0 but omits STATE_META allocator. `store/open.rs:105–168` retains a present allocator, scanning/persisting only when absent. `avl/tree.rs:491–497` allocates existing next_id and unconditionally stores there; no occupancy guard protects imported nodes.

Reachable ordinary Mode2/4 sequence: initialize genesis, reopen before bootstrap (migration creates small genesis allocator g), install verified snapshot with N>g, reopen again before first successor persist_apply writes N (`store/mod.rs:3717`), then a valid new-key insert writes over imported reachable node g. Created-node undo can subsequently remove the overwritten original. Fresh uninterrupted bootstrap with allocator absent is distinct. Node pipeline-before-install and verified installer call are at `ergo-node/src/node/boot/sync_setup.rs:325–347` and `node/sync_tick.rs:1165–1242`. Root verification may reject the valid successor; impact is correct-state/recovery availability, not proved acceptance of a wrong root. No custom install/reopen demonstration executed.

Fix atomically persist imported allocator and coherent nonzero ID mapping, then cross-check reopen allocation metadata. Acceptance: initialized genesis → ordinary reopen → verified install → reopen before successor → valid inserts/removes → forced root/lookup/rollback/reopen parity. Existing bootstrap tests inspect metadata/sentinels rather than this lifecycle.

### ST002 — P1 lifecycle availability — SOURCE_CONFIRMED: installed root0 conflicts with NULL_NODE0 readers

Expected: verified imported boxes and proof generation remain available. Installer `store/mod.rs:1299` and replacement tree use root ID0; `avl/node.rs:12` defines NULL_NODE0. `reader.rs:771` returns None immediately for root0; CommittedSnapshot lookup delegates there. `store/snapshot/mod.rs:413` and `snapshot/lazy.rs:20` reject that root for hydration/proof generation.

Ordinary verified installation therefore makes committed box lookups miss and candidate proof paths unavailable until a root-changing operation, potentially surviving root-preserving updates. This affects API/mempool/mining/recovery service, not a demonstrated invalid-chain acceptance. Fix import IDs1..N and relocate every child consistently, or reconcile the sentinel convention throughout all consumers. Acceptance must lookup known imported boxes through held snapshots/live readers, generate mixed/empty proofs, reopen and repeat. Existing tests intentionally treat root0 as empty and bootstrap tests omit those reader/proof assertions.

### ST011 — P1 publication/concurrency — SOURCE_CONFIRMED: header and full-block writers overwrite the whole ChainState row

Expected: committed root, full tip, header tip and indexes describe one coherent generation. Pipelined apply publishes speculative full tip at `store/apply.rs:632–646`. Foreground `store/mod.rs:2700–2720` sends that entire live ChainState to headers; `header_store.rs:644,795` writes the whole row. Worker later writes its previously captured whole ChainState at `persist.rs:928–939`.

Production enables pipeline at node boot. Sync timer `ergo-node/src/node/sync_tick.rs:243` calls `ergo-sync/src/executor/reorg.rs:352–580` and returns without a persistence barrier. Independently queued inbound events at `ergo-node/src/node/action_loop.rs:164–195` reach `node/events.rs:168`, `ergo-sync/src/executor/mod.rs:492–552`, and `executor/header_pipeline.rs:312–483`, which flushes headers without draining the worker. Thus a normal header writer may obtain redb's writer before a pending apply: it commits fullH while AVL/index remainH-1. The worker then can overwrite a newer header pointer with its old captured pointer while HEADER_CHAIN_INDEX reflects the new header. Held read transactions preserve this mixed semantic generation; `store/snapshot/mod.rs:83–144` checks row presence/decoding, not cross-table height/root/index agreement. Reopen likewise does not reconcile all UTXO projections.

This is source-supported ordinary scheduling, conditional on pending jobs and writer order; no controlled race, crash or power cut was run. It does not prove P0 consensus divergence. Fix single ownership or transaction-local merging of independently owned committed header/full projections; a barrier alone must also prevent stale captured header writes. Acceptance: ordinary validated queued apply + valid new header in both writer orders, assert held snapshot/root/full/header/index/params agreement and clean reopen. Existing per-path tests miss the competing writers.

### ST003 — P2 resource/concurrency — SOURCE_CONFIRMED: arena replacement detaches persistence watermark

`store/mod.rs:898–912` captures the current arena's durable_seq handle; install tail `1357–1376` replaces CachedDiskArena without rebinding worker. `avl/arena.rs:461` creates watermark0; pending pins release against that new handle (`485`) while worker commits advance the old one. Production pipeline is enabled before installation. Post-install ordinary successful jobs cannot release their new-arena pins under the intended committed sequence, weakening the clean-cache bound as touched population grows. No exhaustion, performance measurement or remote demonstration is claimed.

Fix drain/rebind or recreate pipeline with coherent monotonic sequence accounting, or preserve shared arena identity. Acceptance: verified install with active pipeline, ordinary bounded successors and flush, assert pin release/cache bound/root parity. Existing cache tests do not replace the arena underneath an active worker.

### ST004 — P2 API correctness — SOURCE_CONFIRMED: install leaves live height behind committed height

`store/mod.rs:1177–1376` persists StateMeta/ChainState heightH but never sets self.height; accessor at950 and rollback starting height retain the earlier value, normally0. Node updates coordinator from ChainState at `node/sync_tick.rs:1202–1205`, so this does not alone prove its download loop stalls. Fix publish live height after successful commit. Acceptance asserts inherent/trait height, rollback boundary and clean reopen after install; current bootstrap assertions cover ChainState only.

### ST005 — P2 API correctness — SOURCE_CONFIRMED: AVL remove returns predecessor bytes

AvlTree::remove promises the removed key's previous value. In `avl/tree.rs:1224–1243`, direction0 with a leaf left child preserves left_value, moves it to the right minimum, deletes left/internal, and returns that predecessor value. Requested key is the old right minimum/separator. Other branch finds the actual right-minimum value. Tree structure/root may remain correct; StateStore separately looks up spent bytes and uses remove's Option only for presence, so chain impact is unproved.

Fix preserve the original requested right-minimum bytes before replacement without altering hash/undo algorithms. Regression: distinct predecessor/requested values including sentinel case; assert returned bytes, survivor lookup, root, reverse-delta and reopen parity. Existing tree tests check root/lookups rather than this returned value.

### ST006 — P2 failure contract — SOURCE_CONFIRMED; limited REPRODUCED generic fixtures

`persist.rs:634–745` records sticky watch error then continues later jobs; completion try_send can lose events. `store/mod.rs:922–934` drains only events. `shutdown_cleanly:1062–1068` drops the pipeline and returns an empty Immediate commit without checking sticky watch/join failure; Drop `persist.rs:1211–1240` is best effort. Explicit flush `store/mod.rs:938–946` correctly checks sticky errors.

Two prior copied-package tests passed in repro-verified.log: invalid reserved parameter-ID job1024 followed by minimal1025 proved continued logical processing; unchecked syntheticheight1024 failed because zero-parent HEADER_META was missing and proved flushErr/shutdownOk/liveheight1024 vs committed0. These predicates are invalid caller fixtures, not validated canonical production parameters/heights. Earlier failed attempts are retained and superseded. Pinned redb CheckedBackend permanently poisons real backend I/O failures (`cached_file.rs:125–179`; dependency test `db.rs:1390–1440`), so those examples do not establish healthy descendant commits or false-success shutdown after actual storage I/O/power loss. A supported nonpoisoning wallet/metadata failure may be possible, but its complete healthy-following-job production sequence is unresolved.

Fix make worker failure terminal for dependent jobs, close admission and require fallible shutdown to check sticky worker/join results. Acceptance separately proves an ordinary supported logical-failure predicate, queue/barrier/error truth and canonical sequence; physical durability needs another model. Existing tests don't close that production predicate.

### ST008 — P2 public library input — SOURCE_CONFIRMED: StateStore NiPoPoW m0 can panic

`store/popow_cache.rs:256–280` rejects k0 and checked k+m overflow but not m0. With a nonempty prefix level, `560–565` indexes level_headers[len-m], hence len when m0. Expected contract is typed invalid-parameter rejection, as `reader.rs:513,537–546` already implements. Public StateStore API can be called directly with m0; current REST routes enforce positive m/k (`ergo-api/src/compat/handlers.rs:161–179`, `v1/routes/light.rs:246–266`), and ordinary internal callers use positive values. No REST panic/reproduction is claimed.

Fix share the positive-m guard before database/proof work. Regression asserts m0/k0/overflow return exact errors and positive fixtures retain parity; existing public-helper tests lack m0.

### ST009 — P2 important validation gap — SOURCE_CONFIRMED: cache advance and voted-cost oracle assertions leave critical cases open

`store/snapshot/tests.rs:1285–1442` names nonempty advanced mutations, but the nonempty spend is blockN; advanced N+1 at1393/1422 is empty. `tests/it/committed_snapshot_parity.rs:65,219–257` helper always starts height1, so apply10 then apply1 tests fallback/replacement rather than valid N+1. `tests/it/cost_parity_oracle_voted_params.rs:309–444` ignored oracle skips missing prerequisites and asserts only mismatches0, allowing zero matches; activation cases452/459 are explicitly ignored STUBs.

Expected tests must reject a broken nonempty cache-delta replay and establish nonvacuous voted/activation parity. Passing baseline does not prove either implementation wrong. Fix valid N+1 remove/insert/data-input transaction with independently captured or forced-fresh proof/root equality; require expected corpus count and >0 exact matches, identify skip reasons, add pinned pre/at/post activation fixtures. No new custom test created.

### ST007 — P3 documentation — SOURCE_CONFIRMED: commit/durability docs are stale; strict Rustdoc fails

Strict all-feature scoped Rustdoc fails32diagnostics (strict-docs.log) including private/unresolved links and unescaped brackets/HTML. Source docs call speculative height/ChainState committed, architecture says advance only after commit, digest modules deny the implemented production bridge, codemap overlooks durable full-validation verdict3, node decoder docs say panic despite Result, snapshot depth/manifest-size description is reversed, and several backfill/sentinel/performance comments describe obsolete behavior. These reduce public contract reviewability.

Fix links and factual statements against current code; distinguish queue acceptance/redb commit/fsync and current backend/mode behavior. Acceptance strict Rustdoc passes and examples/docs link to the actual contract tests; preserve consensus quirks.

### ST010 — P3 test clarity/assertions — SOURCE_CONFIRMED: several diagnostics overstate what they validate

`tests/it/persistent_blocks_1_10.rs:167–214` calls ordinary clean drop a crash; rollback_to_height_3 at440 actually rolls to4; comments claim a lookup without its assertion. `headers_by_height.rs:311` corrupt-row test inserts healthy rows (separate prune_phase3a tests do cover corrupt lengths). `multi_tx_ordering.rs:32,115` prints model diagnostics with no pass/fail parity assertion, and its ModelB collects operations rather than applying sequential tree state. Pipeline pruning queue64 does not guarantee/assert a single spanning batch. Some below-floor tests accept any error rather than the promised sentinel variant. Wallet mid-apply test drops an uncommitted completed apply, establishing abort behavior rather than partial-power-loss survival.

Fix names and comments to actual evidence, or add precise useful assertions with deterministic barriers and typed errors. Preserve substantive existing terminal parity/corruption tests; no demand for redundant test count.

## Verification, fixtures and complete coverage

[results.json](ergo-state-evidence/results.json) records full commands, revision, cwd, toolchain/environment, exits, duration, logs and counts. Baseline databases are temporary. No shared global check rerun.

| Check | Actual result / limits |
|---|---|
| cargo test --locked -p ergo-state --lib | PASS379, ignored2 |
| cargo test --locked -p ergo-state --test it | PASS361, ignored4 |
| no-default; recompute-oracle; test-helpers; test-utils library checks | COMPILE_ONLY, all four passed |
| scoped all-feature strict Rustdoc | FAIL exit101,32diagnostics |
| scoped doctests | PASS0tests |
| standalone normal/build/feature production tree | PASS; reviewed; no unintended test-utils non-durable path |
| shared workspace tests, warning-denying Clippy, fmt, dependency/cost checks | reused exact revision PASS,7629passed98skipped; strict workspace docs FAIL |
| copied-package logical policy fixtures | PASS2, exact invalid/synthetic predicates ST006; no current source edits |
| exact-hash binary semantic consumer | PASS format/all-node hashes/recorded-root; not authenticated installation |
| shared native release Mode1 devnet boot/shutdown/reopen | PASS narrow fresh-genesis scope only |

State dev self-dependency enables test helpers, recompute oracle and test-utils for unit/integration builds. Baseline non-durable test paths cannot certify crash durability; separate production graph/checks distinguish that behavior. Feature bodies were fully read; individual feature checks are compilation, not all runtime permutations. No benches/build scripts are silently omitted; authored extractors and benchmark helper were read, external captures not run. Unsafe dependencies, native other platforms and real filesystem power-failure properties remain outside native Linux ordinary execution.

AVL tests cover fixed roots/labels, random operations, forced recomputation, undo and reopen, cold/eviction/pin paths, rotations and proof self-verification; mainnet/pruning fixture consumers cover independent historical positive bytes. Prune formula/activation, equal-height forks, composite undo, digest history/open/rollback, emission exhaustion, votes/settings and wallet transaction/scan/maturity/abort cases were read and passed their actual assertions. Negative-reference verdict breadth and critical cross-writer/snapshot lifecycle remain gaps above.

Manifest binary `test-vectors/testnet/utxo_snapshot_manifest_522239.bin`:1,605,536B, SHA256 `b1e80786f37507c270273996475f8de6f071acf4472f75ad5bc4d85d7997b971`; metadata JSON SHA256 `dba4aeea6a0650b6c2e41eb42c03645d22e40434acf429a5bbed2e0f0615bdf1`. [Semantic receipt](ergo-state-evidence/manifest-validation.json) parses every byte,16,383 internal nodes, depth14/treeheight23,16,384 unique boundary labels; balances0:8946,-1:3746,1:3691; checks child Blake2b labels and recorded root `7858b36c8c7596da9999a013d91608a341583a0a1f5d4859c5d80e5d296e0fac` with height byte0x17. Existing Rust manifest_root_scala_testnet_fixture_matches_header passed. Recorded Scala6.0.3 capture2026-09-24T07:51:12.228479+00 height522239/header `1b46a9a538defc5615c510b14c180f1caff16de68d8590175a2229751ef4805e`. Historical metadata/root integrity is separate from a trusted canonical checkpoint; chunks are absent, so full reconstruction/install/reopen remains UNAVAILABLE.

Mode5 corpus has193 fixture rows (workspace structured validation); existing digest mainnet replay consumes every row, asserts >=100, consecutive heights, previous computed root→next parent, proof hash/section binding and postroot. Separate resolved-box replay hashes every witnessed old value to its ID and covers removes. These passed in lib baseline. Recorded source/capture authority and unavailable external refresh are explicit in shared provenance. Genesis producer/consumer is internal witness consistency with pinned genesis-root constants, not an independently captured block1 ADProof hash.

Cross-crate serializer ES007/008: state checked/raw output builders compute box ID and stored bytes using the same candidate serializer/cached bytes, so storage key/value hashing is coherent there. Public mutable parsed registers/raw-constructor semantic coherence belongs to serializer owner; no proved ScalaBox ID/consensus split is imported into state findings. NODE owns direct wallet admin quick-repair bypass. Mandatory docs/codemap primary FULL statuses and selected redb/node/sync/serializer ranges are distinguished from their owning audit's whole-file coverage.

## Separate hypotheses and external evidence gaps

- Public ReconstructedTree is not opaque: installer trusts cached root plus caller expected root rather than recomputing every node/fetching header root itself. Production reconstruction/checkpoint/header-root gates were followed; no peer bypass proved. Prefer an opaque validated capability; verify complete trusted snapshot lifecycle when chunks/checkpoint are available.
- Corrupt persisted child graphs/cycles, oversized undo counts, failed hydration's missing/error distinction, cached parameter fallback and UTXO open cross-table coherence need additional bounded corruption/operational proof if stronger robustness is promised. No new resource-exhaustion demonstration run.
- Fresh Mode3 seeded suffix download without a snapshot cannot supply skipped UTXO parent state; state has no shortcut to establish it. NODE owns complete boot/download caller closure; its helper test alone is synthetic headers, not suffix full apply.
- Canonical healthy descendant processing after a supported nonpoisoning worker error remains unproved. ST006's invalid caller predicates are not that evidence. Real redb backend I/O poison and injected logical errors are different models.
- NOT_RUN: process-kill recovery, physical power interruption, native Windows/macOS/32bit, representative full-archive proof/hydration/backlog/rollback benchmarks, independent malformed Scala oracle refresh, voted activation stubs and complete externally authenticated snapshot installation. Required next evidence uses isolated valid fixtures and real durability, pins exact reference/context, reports skips/counts, and separates injected error/process exit/power loss.
- Representative performance lacks profile/repetition/distribution/hardware dataset receipts; source complexity/cache analysis is not a throughput claim.

## Remediation order and readiness

1. Repair snapshot ID0/allocator atomically (ST001/002), publish live height (ST004), and preserve/rebind worker arena sequence ownership (ST003). Storage-format migration and old imported databases require careful reopen validation.
2. Give header/full ChainState one coherent committed publication contract (ST011); assert root/full/header/index/settings agreement across both writer orders, reorg and reopen.
3. Make fallible shutdown and worker admission terminal/error-truthful (ST006), proving the supported failure predicate separately from backend I/O/power loss.
4. Correct remove return bytes and public NiPoPoW parameter guards without changing consensus labels/proofs (ST005/008).
5. Close nonempty-cache/voted-oracle gaps and truthful test assertions (ST009/010); repair strict docs/public visibility contracts (ST007). Preserve independently verified Scala quirks.
6. Obtain listed external platform, trusted-snapshot, activation, process/power and representative performance evidence before expanding readiness claims.

**NOT_READY** for reference UTXO/snapshot lifecycle/publication scope because reachable source-confirmed critical contracts remain broken. Authored inventory is complete; remaining items are explicitly scoped external/operational validation gaps, not hidden unread files. No P0 consensus split, fund compromise, physical durability guarantee or full-node readiness is certified.
