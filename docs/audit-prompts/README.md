# Rust node audit prompts

Use these prompts to review the implementation against a reference-node quality
standard. They cover all 19 workspace crates and the detached nightly fuzz
package. They are audit instructions, not completed audits or readiness claims.

## Run one crate review

Give a reviewer or coding agent this launch instruction, replacing the crate:

```text
Perform a comprehensive review-only audit of ergo-state in this checkout.
Read docs/audit-prompts/COMMON.md and docs/audit-prompts/ergo-state.md in full
and follow both. Review every authored file, tests, comments, docs, manifests,
fixtures, tooling, feature path, and relevant caller/dependency boundary.
Produce the required report, per-file coverage ledger, evidence, and prioritized
remediation plan. Preserve existing changes. Do not change node code or oracle
expectations. Continue until the review is complete; if evidence or coverage is
missing, state it explicitly and leave an exact continuation plan.
```

Each crate file is also a launch prompt: ask the agent to read and execute it.
The common contract is intentionally shared; a crate file alone is incomplete
unless the reviewer loads `COMMON.md`. For a tool that cannot access this
repository, supply the full common contract followed by the full crate prompt
and the relevant source; providing the prompt alone cannot establish an audit.

The default is review only. To request subsequent implementation, use a separate
instruction such as:

```text
Remediate the confirmed findings from audit/reports/ergo-state.md in focused
changes, preserving Scala consensus/wire/cost behavior and existing user work.
Add meaningful regressions and independent oracle evidence where required.
Run applicable crate and integration checks, then the shared workspace gates
once for the final revision. Update each finding with the fix, tested revision,
evidence, and unresolved external validation. Do not mark unavailable evidence
complete or publish/merge/deploy anything as part of this instruction.
```

## Prompt index

The suggested order follows invariant dependencies. Crates in the same group
can be reviewed concurrently; cross-crate findings still need an owner and
integration evidence. Read the actual Cargo graph rather than assuming this
ordering is a complete dependency graph.

| Group | Prompt | Main responsibility |
| --- | --- | --- |
| Foundations | [ergo-primitives](ergo-primitives.md) | Digest types, byte readers/writers, arithmetic and cost primitives |
| Foundations | [ergo-ser](ergo-ser.md) | Consensus bytes, types, canonical identity, parsing limits |
| Network and crypto rules | [ergo-chain-spec](ergo-chain-spec.md) | Network identity, genesis, monetary and activation parameters |
| Network and crypto rules | [ergo-crypto](ergo-crypto.md) | Autolykos, difficulty, Merkle trees/proofs |
| Execution and language | [ergo-sigma](ergo-sigma.md) | Interpreter semantics, cost, proofs and resource safety |
| Execution and language | [ergo-compiler](ergo-compiler.md) | Source-to-tree/address parity, phases and diagnostics |
| Consensus validation | [ergo-validation](ergo-validation.md) | Checked capabilities, header/block/transaction and NiPoPoW rules |
| Storage and keys | [ergo-state](ergo-state.md) | Authenticated state, persistence, rollback, snapshots and modes |
| Storage and keys | [ergo-wallet](ergo-wallet.md) | Secrets, derivation, signing, selection, storage and CLI |
| Subsystems | [ergo-p2p](ergo-p2p.md) | Framing, cancellation, accounting, peers and anti-eclipse |
| Subsystems | [ergo-sync](ergo-sync.md) | Download state machine, fork handling and execution |
| Subsystems | [ergo-mempool](ergo-mempool.md) | Admission, overlays, scheduling, budgets and revalidation |
| Subsystems | [ergo-mining](ergo-mining.md) | Candidate/reward/proof construction and solution lifecycle |
| Index and adapters | [ergo-indexer-types](ergo-indexer-types.md) | Shared query contracts, schemas, status and boundary types |
| Index and adapters | [ergo-indexer](ergo-indexer.md) | Atomic indexing, queries, errors, reorgs and recovery |
| Index and adapters | [ergo-rest-json](ergo-rest-json.md) | Scala-compatible JSON, canonical conversions and input validation |
| Serving | [ergo-api](ergo-api.md) | Routes, authorization, services, events, webhooks and embedded UI |
| Runtime integration | [ergo-node](ergo-node.md) | Configuration, boot, supervision, action loop and complete node modes |
| Evidence tooling | [ergo-difftest](ergo-difftest.md) | Generators, oracle independence, campaigns and replay evidence |
| Evidence tooling | [ergo-difftest-fuzz](ergo-difftest-fuzz.md) | Detached libFuzzer targets, corpus, budgets and sanitizer evidence |
| Final closure | [Workspace integration](WORKSPACE.md) | Cross-crate lifecycles, root docs/tooling, CI, packaging and readiness |

Review evidence tooling early enough to validate any tests used as authority;
its placement above does not mean test oracles can be trusted before review.

## Coordinate a complete node audit

1. Read [COMMON.md](COMMON.md), establish one reviewed revision and dirty-state
   baseline, and assign every crate plus the detached fuzz package explicitly.
2. Audit in bounded tasks with a durable file ledger. Keep shared artifacts and
   root-file coverage under one owner; give each report a distinct path.
3. Share contract assumptions and findings at dependency boundaries. Have an
   independent reviewer challenge critical conclusions and oracle independence.
4. Run [WORKSPACE.md](WORKSPACE.md) after the crate reports are available. Close
   shared gaps with actual integration evidence and reconcile root documentation.
5. If remediating, update reports and rerun affected boundary tests on the final
   revision. Execute expensive unchanged workspace gates once per revision.

Reports default to `audit/reports/`, which is ignored by this repository. Keep
the evidence locally or use a user-specified durable destination; do not confuse
an untracked report with a published or independently verified result.

The prompts are grounded in the source layout when written. On later revisions,
rediscover files, features, contracts, and CI commands. A renamed landmark
requires navigation updates, not an automatic defect finding. Historical
audit/remediation documents are leads to verify against the reviewed revision.
