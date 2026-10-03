# `ergo-node` reference-node audit prompt

Audit `ergo-node` as the executable, supervision and cross-crate integration boundary of a reference-quality Ergo Rust node.
First read `docs/audit-prompts/COMMON.md` and apply its entire audit contract and report format.
Then read `CONTRIBUTING.md`, `docs/compatibility.md`, and `docs/codemap/ergo-node.md`.
This is a review-only audit unless the invoking user explicitly authorizes remediation.
Verify current implementation/wiring rather than assuming historical status or codemap paths are still accurate.
Independently inventory every crate file and shared test/helper/include/fixture/script/operator document it references.
Apply COMMON to all Rust code, tests, comments, rustdoc, TOML examples, CLI help, manifest and tooling.

## Mission and trust boundaries

Determine whether components are wired under their actual contracts and fail safely through startup, steady state, attacks, reorgs, partial failure and shutdown.
Track operator configuration, peer bytes, REST requests, wallet secrets, external miner inputs, reference-node HTTP and optional downloaded databases separately.
The single-writer action loop owns chain/mempool mutation; every cross-task command needs bounded ownership and honest acknowledgement.
Inspect all dependent-crate seams; isolated crate correctness cannot establish node correctness.
Distinguish process liveness, API availability, sync health, committed tip and durable shutdown.

## Current source landmarks

- `src/main.rs`, `lib.rs`, `config/{mod,cli,load,resolved,toml_sections,tests}.rs` and both crate TOML configs.
- `src/node/boot/{mod,peers,sync_setup,mining,api_wiring}.rs`, `node/handle.rs`, `action_loop.rs`, `state.rs`: orchestration and ownership.
- `src/peer_loop.rs`, `peer_loop/outbound.rs`, `node/{peer_actions,events,sync_tick,block_relay,section_serving}.rs`.
- `src/node/messaging/{mod,dispatch,manifest,popow,utxo_chunk}.rs`: message perimeter and bootstrap serving/consumption.
- `src/node/{admission,tip_context,sync_helpers,prune_activation,identity,util}.rs`: readiness, active rules and mode gates.
- `src/node/{mining_dispatch,mining_engine}.rs`, `src/mining_bridge.rs`: external miner bridges and actual blocking builder ownership.
- `src/node/wallet_bridge.rs`, recursive `commands/`, `support/`, `chain_snapshot.rs`, `scan_guard.rs`, plus `src/wallet_boot.rs`.
- `src/api_bridge.rs`, recursive helpers/Scala compatibility/tests, `src/snapshot/{mod,build,publisher}.rs`, `node/snapshot_emit/`, `snapshot_state.rs`.
- `src/{notifier,indexer_chain,genesis,anchor_map,anchor_scheduler,decode_stack,realtime_mempool_bridge}.rs`.
- `src/{activity,incidents,metrics_counters,peer_details}.rs`, `peer_details/download.rs`, `mem_*.rs` and node telemetry/health/storage probes.
- `src/node/{event_feed,first_deliverer,reorg_history,heartbeat,memory_sampler,shadow_watch,telemetry,storage_probe}.rs` and `node/tests.rs`.
- `tests/common/mod.rs`, all `tests/it/` modules; `examples/{ge_soak,p2p_adversary,p2p_probe}.rs`.

These landmarks are not a complete-file claim. Resolve all module/include paths and shared materials yourself.

## Configuration, modes and bootstrap trust

- Verify defaults and file/environment/CLI precedence, unknown keys, validation errors, help text and both example configs agree.
- Prove `NodeConfig::load` and programmatic/runtime backstop enforce identical supported-combination predicates.
- Review mainnet/testnet/devnet genesis identity, chain parameters, address encoding, magic and data-dir selection through all subsystem constructors.
- Build a mode matrix for archive, UTXO snapshot, pruning, composed bootstrap/pruning, digest verifier and headers-only digest.
- Verify force-off behavior for mempool, mining, wallet/indexer capabilities and route mounting matches backend semantics rather than only labels.
- Mode identity/resume state must reflect persisted sparse/dense history and actual bootstrap phase; no stale snapshot/config label can misrepresent trust.
- Prune sentinel starts at the correct headers-synced transition, aligns to epoch, remains monotonic and respects undo floor across restart.
- Check NiPoPoW/snapshot ordering, deferred installs, checkpoint materialization, manifest root/height, same-height reorg and first-epoch settings trust.
- Bootstrap success requires successful state installation; mode gates must remain closed after install failure or poisoned persistence.
- Inventory operator escape-hatch environment variables such as forced headers-synced/capture options, their logging and whether they bypass documented safety.

## Startup, supervision and shutdown

- Map each startup phase and every resource/task/thread/channel/DB/listener it creates; failure at the next phase must unwind prior ownership.
- Signal handlers must cover startup on supported Unix/Windows paths; API shutdown notification and signal races must converge on one cleanup path.
- Action-loop panic/early exit must become a fatal process outcome and close API/inbound listeners rather than leave a plausible live facade.
- Classify required workers versus optional diagnostics; supervise failures according to the documented policy and expose halted subsystems honestly.
- Explicit shutdown must close admission, drain/bound API requests, stop peers, stop/join builders/indexer/wallet where required, flush state and propagate final errors.
- Aborting an async coordinator is not cancellation of its blocking/dedicated worker; real worker join and DB references must remain owned until completion.
- Check cancellation of `RunHandle::shutdown` itself, forgotten `Drop`, repeated signals and partial startup failure for leaked tasks/sockets/read transactions.
- Document which shutdown waits are bounded and which are intentionally unbounded for noninterruptible state safety; compare actual behavior to comments.
- `Drop` best effort cannot promise immediate DB reopen or durable close; explicit successful shutdown must establish its actual durable guarantee.
- Optional detached storage probes must hold only intended weak/temporary references, expire stale samples and not delay cleanup of chain DB handles.
- Logging guards, incident writers, lookup/download workers, reference tasks and global process state need lifecycle accounting too.

## Action-loop fairness, peer IO and storage failure

- Inspect every `select!` arm, drain loop, batch/coalescing cap and timer: continuously ready peers/API commands must not starve sync, shutdown or wallet/mining replies.
- Bound inbound channel bytes through actual `ReadBudget` permit transfer until events and extracted payloads are consumed/dropped.
- Outbound message/byte caps must charge allocation capacity plus framing and keep permits until queued/current writes finish.
- Overflow, oversized frames, send failure and stalled writes must close the affected socket, release resources and clean coordinator ownership.
- Enforce first-body/no-progress deadlines and per-IP large-frame slots in actual production connection setup.
- Every requested message dropped by local throttling/queue failure must avoid falsely penalizing the honest peer for non-delivery.
- Verify solicited Modifier over-cap admission and byte charging, hostile unsolicited handling and message count/size gates before decode.
- Message/section ID validation must precede persistence and assembly; bootstrap message handlers need the same trust/resource perimeter.
- Ban one IP and remove every registered/pending socket from that IP, including alternate ports and queued dial/handshake work.
- Track peer registry/manager/transport task counts and disconnect events through reorderings, failed handshake and same-peer replacement.
- Compare local mined/full-block paths and peer apply paths: header-before-sections, durable section write, validated apply, announce and coordinator feedback.
- Terminal persist/DB corruption must stop unsafe apply/admission and reach operator status; logging then returning empty actions is not proof of safe continuation.
- State reads must distinguish absence from failure; section serving/API reassembly cannot fabricate successful empty/missing results from a failed database operation.
- AD-proof suffix insertion, prune serve limits and rollback wedge health must agree across sync, serving and snapshots.

## Transaction admission, miner and notifier integration

- Peer/API/wallet submission and check routes must use the same consensus context and intended source budgets/policies.
- Record anti-DoS outcomes even if a reply receiver times out/drops; accepted work must not be repeated solely because acknowledgement was lost.
- Request bytes, queue entries, oneshots and blocking decode/PoW work need aggregate limits and cancellation-safe permits lasting until actual completion.
- Review `decode_stack` depth/destruction strategy: stack sizing must cover parse AND drop, including errors and deeply nested hostile JSON/script trees.
- Verify API full-block PoW precheck and authoritative action-loop linkage/context checks close TOCTOU without trusting HTTP-side facts blindly.
- Mining readiness latch, committed-snapshot build, persist lag, minimal/full refresh, stale CAS publish and longpoll serve changes must work under real wiring.
- Off-loop candidate worker and optional rent index queries must be bounded and held DB snapshots released before claimed clean shutdown.
- Mempool notifier must key on `(height, header_id)`, handle equal-height reorgs and propagate unavailable/pruned diff errors rather than empty success.
- Epoch parameter/settings changes must demote active/staged validation facts and revoke unsafe relay/mining use before subsequent processing.
- Failed block transaction IDs and mining suspects must invalidate/recheck the correct local pool family without treating local storage faults as consensus rejection.
- Observer/realtime publication must remain cheap, bounded and nonblocking under slow API clients; events describe the actual local pool.

## Wallet, indexer and API bridges

- Wallet writer/chain hooks/rescan guards must share the promised single-writer and transactional ordering without deadlock or partial chain/wallet claims.
- Unlock/hydrate/persist boot must propagate failures and protect seed/password/derived-key lifetime, permissions, zeroization and logging.
- Change-address updates must require unlock and re-derived ownership; signing/submit/reward/sweep/multisig-hint helpers must use network/current-context rules.
- Cancelled wallet requests, partial scans, scan deletion, reorg, maturity and restart must produce consistent persisted and API-visible state.
- Indexer startup/catch-up/reorg/failed-store/shutdown must be honest about eventual consistency and must not hold chain writers hostage.
- API DTOs/Scala JSON shape, arbitrary-precision numbers, byte lengths, error/status mapping and route gates must match implemented compatibility claims.
- `ArcSwap` snapshots must be internally coherent, bounded and refreshed on the right events; recent-block caches must key by full-tip identity.
- Dynamic identity/status/events/miner attribution must update through bootstrap, peer transitions, reorgs and indexer failure without fabricated completeness.
- Read bridges must not block the action loop or leak state secrets through errors; admin/vote/wallet/mining routes must receive the intended authentication/configuration.

## Operator diagnostics, optional services and filesystem behavior

- Review global logging/activity/incident state for multiple node instances, secret redaction, UTF-8 clipping, byte bounds and attacker-controlled cardinality.
- Logging/incident capture must not recursively log, block consensus indefinitely, silently overwrite evidence or create unsafe paths/permissions.
- Verify metrics freshness, storage poisoning/recovery state, deep-fork wedge, apply-age gauges and heartbeat distinguish stale snapshots from live stalled work.
- Shadow reference/anchor services are observations, not consensus authority; bound requests/retries and prevent timeout/bad JSON from corrupting local truth.
- Peer-details reverse DNS/GeoIP work must stay off consensus/API critical paths and honor configured privacy/opt-in behavior.
- Compressed DB downloads need compressed/decompressed caps, cancellation, validation before atomic replacement, safe temp paths and preserved usable old data.
- Memory CSV/maps/markers and storage probes must be optional, platform-correct and bounded; noncritical sampling failures must not become false node-health success.
- Examples/soak/adversary tools must document networks, destinations, effects and reproducible bounded operation; do not run against live operator/third-party nodes by default.

## Required evidence and meaningful verification

Start with `cargo test --locked -p ergo-node --lib` and `cargo test --locked -p ergo-node --test it` on isolated data/loopback services.
Check example compilation with `cargo check --locked -p ergo-node --examples`; external network/download/Scala tests are prerequisite-dependent, not automatically safe to execute.
Inspect integration coverage for submit/mining, mode runtime gates, Mode 3/4/5, indexer lifecycle, wallet send/admin/restart and live identity refresh.
Demand partial-startup failure and worker panic tests, cancellation/permit accounting, shutdown-error propagation and reopening after explicit durable shutdown.
Exercise queue saturation, sustained mixed load, slow peers/API clients, duplicate submission, same-height reorg and persist poisoning under real wiring.
Use pinned external JSON/wire/consensus captures; synthetic success through mocked components cannot establish full-node reference parity.
Include production release-feature graphs and native platform lifecycle evidence; compile-only targets/ignored prerequisites remain explicit gaps.
Measure action-loop service latency, retained payloads, build/scan workers, snapshot cost and diagnostics overhead with representative sustained load.

## Crate-specific completion criteria

Supply configuration/mode/route matrices, task/thread/permit ownership ledger, failure-supervision policy and durable-shutdown evidence under COMMON.
State what is proved by full runtime tests versus isolated mocks, and what still needs long-lived cross-mode/peer/platform evidence.
Do not certify reference readiness if the API can outlive its dead state machine, cancellation detaches DB-owning work, or failed persistence/bootstrap/submit is presented as success.
