# `ergo-p2p` reference-node audit prompt

Audit `ergo-p2p` as the adversarial network boundary of a reference-quality Ergo Rust node.
First read `docs/audit-prompts/COMMON.md` and apply its entire audit contract and report format.
Then read `CONTRIBUTING.md`, `docs/compatibility.md`, and `docs/codemap/ergo-p2p.md`.
This is a review-only audit unless the invoking user explicitly authorizes remediation.
Verify the checked-out implementation rather than inheriting claims from the codemap or prior audits.
Independently inventory every crate file, every test/module/include, and shared fixture/extraction/support files used by it.
Apply COMMON to all code, tests, comments, rustdoc, manifests and features; inspect undeclared or unreachable test files too.

## Mission and trust boundaries

Determine whether hostile peers can cause incorrect wire behavior, unbounded work/memory, resource leaks, deadlock, unfair bans, eclipse amplification or delivery stalls.
This crate is passive transport and bookkeeping; the chain decision engine belongs to `ergo-sync`, runtime task/channel ownership to `ergo-node`.
Audit those seams enough to prove actual behavior, including permits and buffers held outside this crate.
Separate socket address, declared address, gossip address, session/node identity and IP/subnet policy identities.
Persistent peer reputation is advisory state: classify explicit best-effort writes and report their failure semantics accurately.

## Current source landmarks

- `src/lib.rs`, `src/types.rs`: facade, payload types and modifier taxonomy.
- `src/framing.rs`: `parse_frame_header`, frame serialization/deserialization, `wire_len`, magic, lengths and checksum.
- `src/connection.rs`: TCP buffering, `ReadBudget`, byte/slot/IP permits, first-body and progress deadlines.
- `src/message/{mod,tests}.rs`: all payload serializers, counts, limits, SyncInfo versions, snapshot/NiPoPoW messages.
- `src/handshake.rs`, `src/peer.rs`: handshake/features, protocol versions, per-peer lifecycle, penalties and byte counters.
- `src/peer_manager/{mod,known_peer,limits,routability,persistence,tests}.rs`: admission, selection, dial pool, bans and persistence.
- `src/address_book/{mod,codec}.rs`: redb rows, staleness/ban expiry, caps and recovery.
- `src/delivery/{mod,tests}.rs`, `src/assembly.rs`, `src/partition.rs`, `src/sync.rs`, `src/throttle.rs`: request/arrival/timeout state and pure policies.
- `tests/it/main.rs`, `wire_tcp_pair.rs`, `wire_vectors_oracle.rs`, `address_book_persist.rs`, `structured_error_propagation.rs`.
- Shared `test-vectors/ergo-p2p/` and provisioning material; inspect every referenced capture and its generator.
- Runtime callers `ergo-node/src/peer_loop.rs`, `peer_loop/outbound.rs`, `node/messaging/`, `node/peer_actions.rs` and sync coordinator.

Landmarks are not a coverage substitute. Resolve current modules and discover any additional examples, benchmarks or features yourself.

## Wire encoding and hostile decoding

- Independently pin mainnet/testnet magic, registered codes, signed big-endian frame length, empty-frame checksum omission and blake2b checksum bytes.
- `wire_len` must match emitted bytes for empty and nonempty frames and every accounting caller.
- Review integer narrowing in serialization, impossible lengths and public callers outside the production socket cap.
- Check every truncated header/body/checksum boundary, coalesced frames, arbitrary TCP fragmentation and EOF interpretation.
- Partial input must be distinguished from malformed input without spinning, accepting a truncated payload or discarding the next frame.
- Counts and advertised lengths must be bounded before allocation and by remaining bytes; inspect aggregate limits as well as per-entry limits.
- Verify each message schema independently: Inv/RequestModifier, Modifiers, GetPeers/Peers, SyncInfo V1/V2, snapshot codes 76–81, NiPoPoW codes 90–91.
- Preserve externally observed Scala behavior for padding, empty payloads, unknown features, version markers and permitted trailing bytes.
- Inspect duplicate IDs, duplicate entries, inconsistent type IDs, reserved codes, zero counts and maximum count/size combinations.
- Handshake feature lengths, unknown-feature retention/skipping, UTF-8 and version/address encodings must remain bounded and byte compatible.
- Test external-oracle decode/encode and rejection outcomes; local round trips alone do not establish protocol correctness.
- Structured error chains must identify frame versus message versus handshake faults and retain useful cause without dumping sensitive payloads.

## Read budget, cancellation and connection lifecycle

- Reconstruct the total retained-byte bound: payload capacity, frame buffer, read-ahead, checksum, queued events and temporary serialization allocations.
- Verify the byte budget and slot arithmetic permit every slot-holder to finish, including mixed small frames and maximal bodies.
- A large-frame slot must be acquired before byte permits; readers waiting for a slot must hold no budget that creates a cycle.
- Small one-read frames must not become starved behind large-body slot admission.
- The per-IP slot set and notify mechanism must release/wake correctly on normal completion, EOF, timeout, error, cancellation and panic.
- Check cancellation while waiting for bytes, waiting for slot/IP ownership, reading a partial body and handing payload to the node.
- Audit ownership transfer: permits must remain attached to the actual retained payload until action-loop processing/drop, and release exactly once.
- First-body deadline and body no-progress deadline must begin/restart correctly; distinguish legitimate slow progress from header-only reservation attacks.
- Check pre-buffered bodies, partial checksum bytes, budget capacities smaller than a frame, and permit arithmetic conversions.
- Closing budgets/channels must wake waiters with failure; disconnected peers must not strand permits or buffered frames.
- Socket write interruption cannot safely resume a partially written frame without explicit design; inspect node task behavior on cancellation/write timeout.
- Document task join/abort requirements at the caller seam and compare loopback test relaxations with production per-IP enforcement.

## Peer admission, routing and anti-eclipse policies

- Review pending dial, accepted socket, handshaking, ready, disconnect and ban transitions; count pending connections in admission limits where intended.
- Enforce total/outbound/inbound/per-IP/per-subnet limits across both successful and failed handshakes, duplicate connections and simultaneous arrivals.
- Session/node self-connect detection must not confuse legitimate peers or allow spoofed local/declared addresses to evade identity checks.
- Validate capability/version floors before peer selection; classify unknown, obsolete and future-compatible versions with pinned authority.
- Routability must cover IPv4, IPv6, mapped IPv4, unspecified, multicast, reserved, documentation, private, link-local and malformed address forms.
- Explicit operator peers and local/devnet policy must be distinguished from untrusted gossip; prove which exceptions are intentional.
- Prevent third-party advertised addresses or bans from polluting trust/eviction policy as though authenticated by the socket peer.
- Inspect peer-discovery caps, origin retention, duplicate updates, insertion ordering, backoff/jitter and clock changes.
- Peer scoring and throughput-aware selection must not let Sybils monopolize request/gossip partitions or make honest low-bandwidth peers permanently useless.
- Check ban escalation, expiry, permanent bans, maximum ban-table size and all same-IP connections including pending handshakes.
- Audit malicious penalties versus local IO/context faults; node must not punish an honest peer for dropped outbound requests or local resource failure.

## Delivery, assembly, throttling and scheduling

- Model request states, owners, in-flight counts, received history, retries, failures, canceled shadows and late-delivery allowances.
- Every ownership transition must debit/credit exactly once on receive, timeout, hedge, reassignment, retry exhaustion, cancel and disconnect.
- Accept legitimate late responses to previously owned requests without allowing unsolicited floods to reset state or escape penalties.
- Bound histories, failed sets, shadows and per-ID metadata over long runtimes; inspect cleanup when a chain branch or pending block is abandoned.
- Transaction request policy must account for invalidation/unresolved caches and alternate IDs/bytes without starving block traffic.
- Hedging must preserve valid owner sets and remain bounded across repeated retries; completed IDs cannot be repeatedly requested.
- Inspect unsolicited, duplicate and wrong-type responses, expected modifier IDs and mismatch cleanup.
- Assembly reverse indexes must bind transactions/extension/AD-proof section IDs to the correct header and avoid cross-header completion.
- UTXO proof regeneration versus digest shipped-proof requirements must not make a block spuriously complete or permanently incomplete.
- Partitioning must be deterministic where promised, capacity aware and fair across rotation, capability filtering and empty/uneven peer sets.
- Throughput windows must handle exact boundaries, counter overflow and monotonic time; byte accounting must charge actual wire length.
- Review the node seam that admits solicited Modifiers over byte cap and records over-cap traffic; honest deliveries cannot be dropped then blamed as non-delivery.
- Do not infer chain fork choice from preliminary height-based `SyncState` classification; verify the coordinator supplies the authoritative decision.

## Peer database and recovery

- Review key/value codecs for malformed rows, unknown versions, truncated values, oversized names and inconsistent IP encoding.
- Verify write transactions, quick-repair settings, atomic peer/ban updates where promised and bounded database growth.
- Startup load must distinguish stale/expired rows from corrupt data or IO failure and follow documented quarantine/failure policy.
- Ban/peer TTLs and wall-to-monotonic conversions must tolerate future timestamps and clock rollback without infinite bans/backoff.
- Inspect write-through failure policy and logging for `persist_*` helpers; best-effort reputation loss cannot be reported as durable success.
- Failed persistence must neither crash unrelated chain processing nor silently conceal operator-relevant loss of configured bans.
- Reopen tests must cover successful retention, expiry, eviction, corrupt records and interrupted writes without mutating live operator databases.

## Required evidence and meaningful verification

Start with `cargo test --locked -p ergo-p2p --lib` and `cargo test --locked -p ergo-p2p --test it`; inspect `test-helpers` feature exposure.
Check independent captured-wire vectors and negative mutations for every supported message/handshake version and network magic.
Use loopback socket pairs with fragmentation, EOF, slow/no-progress bodies and simultaneous maximal frames under a deliberately small read budget.
Demand permit/counter invariants after cancellation and disconnection and a progress proof/test for the budget's previous hold-and-wait hazard.
Exercise delivery/hedging/timeouts with deterministic time and disconnect reorderings, not flaky wall-clock sleeps.
Test state-machine sequences against simple accounting models where that adds independent evidence.
Inspect node queue capacity/byte budgets, solicited throttle exception, banned-IP cleanup and actual transfer of read permits.
Record missing Scala captures and external provisioning prerequisites as gaps; never treat synthetic fixtures as genuine captures.

## Crate-specific completion criteria

Report coverage of every codec/message/version plus a connection/budget/delivery transition ledger under COMMON.
Supply measured or proven memory bounds, cancellation/permit-release evidence, and anti-eclipse/banning boundary cases.
Separate protocol divergences, intentional policy differences and advisory persistence limitations with evidence for each.
Do not certify reference readiness if hostile input can panic, cause an unbounded allocation, strand permits, deadlock readers or falsely penalize honest requested delivery.
