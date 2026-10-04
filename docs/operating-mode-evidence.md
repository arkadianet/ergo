# Operating-mode evidence and remaining closure work

This inventory revalidates audit recommendation R05 on 2026-10-03. It records
the scope of committed evidence, rather than a deployment guarantee. The
[compatibility policy](compatibility.md) remains authoritative. Local fixture
tests, historical mixed-node campaign receipts, and a configured CI job are
different forms of evidence; a skipped job does not establish parity.

## Committed evidence

| Surface | Evidence and actual scope |
|---|---|
| Mode 3 pruning | [Scala runtime vectors](../test-vectors/mode3-pruning/runtime-vectors.json) contain 30 cases from upstream `FullBlockPruningProcessor` at `4a7dba059794054fc4c81f5d990dafdeb4f97a49`, generated 2026-09-03. [Formula](../ergo-state/tests/it/prune_formula_scala_oracle.rs), [eviction](../ergo-state/tests/it/prune_eviction_pipeline_oracle.rs), and [sync eviction](../ergo-state/tests/it/prune_eviction_sync_oracle.rs) tests cover the sentinel and retention seams. These are bounded fixture tests of retention calculations, not certification of the fresh UTXO download policy. Four node policy tests and four [boot/reopen tests](../ergo-node/tests/it/mode3_lifecycle.rs) cover genesis-first downloads and guarded legacy-floor repair, including a preserved NiPoPoW proof floor, using stored fixture headers without historical full-block validation. |
| Mode 4 composition and restart | [Acceptance tests](../ergo-node/tests/it/mode4_acceptance.rs) cover install/reopen, proof-first composition, snapshot-first proof rejection, and sentinel/provenance persistence. Their small reconstructed snapshot is synthetic. The [catch-up test](../ergo-node/tests/it/mode4_catchup.rs) additionally uses three owned P2P suppliers, external mainnet headers/transactions 1–10, a snapshot reconstructed through block 9 whose root must match its mainnet header, deferred discovery above the NiPoPoW tip, real forward header admission, full validation of block 10, and graceful shutdown/reopen. The supplier snapshot is produced by Rust; this does not replace a Scala-produced snapshot trust fixture. |
| Mode 5 epoch-crossing block replay | [Executor replay](../ergo-sync/tests/it/mode5_executor_replay.rs) applies 183 externally captured mainnet blocks, 1795978–1796160, including 55 data-input blocks and voting boundary 1796096, through production digest processing and full transaction validation. Prior epoch headers and active parameters are seeded from captured fixtures. Expected roots come from mainnet headers; this is neither genesis replay nor a fork-choice campaign. |
| Mode 5 additional networks/windows | [Three captures](../test-vectors/mode5/breadth/README.md), acquired 2026-10-02, cover mainnet 1761000–1761007 and 1885600–1885607 from Scala 6.1.2, and testnet 442325–442332 from Scala 6.0.3. [Breadth tests](../ergo-sync/tests/it/mode5_corpus_breadth.rs) check identities, parameter commitments, full validation, root-preserving rollback/replay, and corrupted-proof rejection with unchanged committed state. Each database is seeded at the window; it does not contain the historical rollback substrate needed for cold-open recovery. |
| Interrupted reorg recovery | [Executor subprocess tests](../ergo-sync/src/executor/relay_tests.rs) kill an owned process after committed rollback and after a partial replacement apply, for both UTXO and digest backends. Reopen recovers roots/tips/coordinator state and finishes the replacement suffix. Replacement blocks and expected roots are captured mainnet blocks 1–3; the abandoned fork is synthetic. This establishes bounded process-death recovery, not every historical reorg or interruption inside a database commit. |
| Storage reopen | [Chain-storage tests](../ergo-state/tests/it/chain_storage_reorg.rs) pin rollback and header/full-tip persistence across reopen using early mainnet fixtures. [Cold AVL tests](../ergo-state/tests/it/avl_cold_restart.rs) check cached-root and mutation read bounds over synthetic state. [Mode 2 trust-lifecycle tests](../ergo-state/tests/it/mode2_trust_lifecycle.rs) check persistence/consumption of the first-epoch flag; they do not verify an external trust root. |
| Historical mixed-node campaigns | The [smoke receipt](../scripts/devnet-mixed/smoke-evidence.json) records 100/100 blocks, no skips/failures, at Rust `3cdc04e7` against Scala 6.0.5 / sigma-state 6.0.6 on 2026-09-16. The [direct-submit receipt](../scripts/devnet-mixed/direct-submit-evidence.json) records 2/2 cases and matching full-tip/root commitments. The [L6 receipt](../test-vectors/ergo-sigma/cost-ledger/results/l6-2026-09-16.json) preserves the stopped mining divergence and both later 7/7 passing directions, including exact-cap acceptance and over-cap unchanged-state rejection after `07a4f410`. These private UTXO devnet campaigns do not establish Mode 4/5 live-soak or current-revision deployment results. |
| Continuous external oracles | The [nightly workflow](../.github/workflows/fuzz.yml) schedules a JVM consensus campaign with recorded seed/reference version/transcripts. Its separate archival replay job requires `REPLAY_NODE_URL`; an unset secret explicitly reports that state-root replay was not tested. Workflow wiring alone is not a successful campaign receipt. |

## Remaining work and closure criteria

These responsibilities identify the owning subsystem; they do not assign a
person, a deadline, or an already completed campaign.

| Obligation | Owning subsystem and evidence needed to close it |
|---|---|
| Mode 3 complete activation lifecycle | Pruning/node maintainers: extend the bounded Scala retention and native startup tests into an owned full-node genesis replay/activation/restart run with applied-state commitments, retained reference retention values and section-eviction observations. Document the fresh Rust UTXO download policy separately from Scala header-only floor calculations. The operating guide's end-to-end activation gate remains open. |
| Mode 2 external trust anchor | Bootstrap/state maintainers: preserve a Scala-produced manifest/chunk set, its reference version and hashes, and an independently reported header state root. Exercise accepted installation, altered manifest/chunk/root rejection with unchanged state, and reopen. A Rust-built tree or a trust-flag lifecycle test is insufficient. |
| Mode 4 live soak | Node/sync maintainers: run an owned multi-peer deployment with a recorded duration, versions/configuration, snapshot anchor, header/full-tip/root observations, disconnect/reconnect and restart outcomes, selected/executed/skipped counts, and retained logs. The deterministic three-peer catch-up regression closes that seam, while the long-running live-soak obligation stays open. |
| Broader Mode 5 historical recovery | Digest/sync maintainers: add earlier protocol eras, voting changes and more complex transaction/data-input workloads with independently captured proofs/roots. For external-window cold-open/process-death reorg campaigns, first provision an owned database with complete historical rollback/index/parameter substrate; the eight-block seeded windows intentionally cannot stand in for that snapshot. Retain both branches, interruption points and all post-reopen commitments. |
| Archival replay availability | CI/reference-node maintainers: provision an owned archival reference endpoint, set `REPLAY_NODE_URL`, and retain an executed replay receipt with source/reference revisions, checked range, roots and failure/skip counts. Until then, the job's explicit skip remains an unclosed external coverage gap. |

Digest rollback history is currently unbounded. A retention change needs its
own supported rollback-window contract, compatibility evidence and storage
migration plan; the existing replay receipts do not establish that policy.
Cooperative distributed multisig remains a deferred feature, independently of
the shipped signing primitives and hint replay.

Two adjacent R05 policies have more specific current contracts. The
[webhook connector](../ergo-api/src/v1/webhooks/worker.rs) checks every DNS answer,
rejects mixed forbidden/public answers, connects through those checked results,
and disables redirects/proxies; its unit tests cover the resolver boundary.
[Peer address budgets](../ergo-p2p/src/peer_manager/limits.rs) normalize
IPv4-mapped addresses and apply IPv4 `/16` or native IPv6 `/48` connection groups.
Inbound, outbound, handshake slots and dial selection use that same grouping.
[Regression tests](../ergo-p2p/src/peer_manager/tests.rs) cover mixed directions,
rotation inside an IPv6 prefix, distinct prefixes and mapped-address accounting.
The legacy `Peer::subnet` IPv4 helper is not the manager's admission key.
