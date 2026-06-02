# ergo-p2p

**Purpose:** The Ergo P2P protocol stack as a passive transport layer: TCP frame codec, handshake + feature negotiation, the typed message (de)serializers, the per-peer state machine, the peer manager (dial/accept/eviction/anti-eclipse limits), a redb-backed address book, and the modifier inventory / delivery / block-section-assembly bookkeeping. Knows nothing about chain logic — `ergo-sync` drives it.

**Depends on (workspace):** ergo-primitives, ergo-ser
**Depended on by:** (see codemap index)
**Approx LOC:** ~9,500 total across `src` (~5,300 production; the rest is inline `#[cfg(test)]` modules plus the standalone `src/peer_manager/tests.rs`)

## Start here
- The crate doc comment + module list in `src/lib.rs:1-51` — the authoritative module map and the layer's charter (sits on `ergo_primitives` + `ergo_ser`, driven by the sync coordinator).
- `framing.rs` (`serialize_frame`/`deserialize_frame`, `src/framing.rs:69`/`:97`) — the wire-frame contract (`magic||code||len||checksum||payload`); everything else is payloads inside this envelope.
- `message.rs` — the message-code constants (`CODE_*`, `src/message.rs:19-33`) and the per-message payload codecs; the clearest map of what protocol messages exist.
- `handshake.rs` (`Handshake`, `PeerSpec`, `Version`, `PeerFeature`) — the connection-admission gate and the wire types reused by the `Peers` gossip message.
- `peer_manager/mod.rs` (`PeerManager`) — the connection lifecycle + anti-eclipse policy hub; the largest behavioral surface.

## Modules
- `src/framing.rs` — wire-frame codec (big-endian header, blake2b256 4-byte checksum, magic constants); `MessageFrame`, `FrameError`, `wire_len` for byte accounting.
- `src/connection.rs` — async `Connection` over `TcpStream`: buffered framed read/write, `MAX_PAYLOAD_SIZE` (8 MiB) early-reject, `ConnectionError`.
- `src/message.rs` — payload (de)serializers for every message code (Inv, Modifiers, GetPeers/Peers, SyncInfo V1/V2, snapshot codes 76-81, NiPoPoW codes 90-91); `MessageError`, allocation-bound + size-cap guards, Scala-parity pad-length handling.
- `src/handshake.rs` — `Handshake`/`PeerSpec`/`Version`/`PeerFeature` (Mode/SessionId/LocalAddress/RestApiUrl/Unknown) codecs; `MAX_HANDSHAKE_SIZE`; `HandshakeError`. Reused by `message::serialize_peers`.
- `src/peer.rs` — per-peer state machine + penalty/scoring model: `PeerInfo`, `PeerScore`, `ConnectionState`, `Penalty`, `SyncVersion`, version floor, byte counters.
- `src/peer_manager/mod.rs` — `PeerManager`: dial/accept registration, handshake completion + self-connect detection, ban table, peer selection (download/gossip/capability-filtered), `known_addresses` dial pool with backoff, address-book write-through.
- `src/peer_manager/limits.rs` — `PeerLimits` (max/target-outbound/per-IP/per-/16) + `ConnectError`.
- `src/peer_manager/routability.rs` — `is_routable_for_p2p` (RFC1918/loopback/link-local/CGNAT/ULA filter) + `declared_to_socket` IPv4/IPv6 parse.
- `src/peer_manager/tests.rs` — standalone integration-style test module for the manager.
- `src/address_book/mod.rs` — `AddressBook`: `peers.redb` persistence of peer rows + per-IP bans, load-time staleness/expiry pruning, `MAX_PEERS` eviction, quick-repair open.
- `src/address_book/codec.rs` — key/value byte encoders/decoders for the persisted peer / ban / IP-key records.
- `src/partition.rs` — pure `distribute` of pending modifier IDs across peers into per-(peer,type) `Bucket`s; deterministic, rotation-cursored, deliberate Scala divergences documented.
- `src/throttle.rs` — `ThroughputLimiter`: per-peer sliding-window (100 msg/s, 2 MB/s) rate limiter; pure state, `now`-parameterized.
- `src/assembly.rs` — `AssemblyTracker`: per-header section-arrival aggregator (transactions/extension/AD-proofs) with reverse modifier-id index; section-id recipe itself lives in `ergo_ser::modifier_id`.
- `src/delivery.rs` — `DeliveryTracker`: request ownership, per-peer in-flight caps, timeout/retry/reassignment, duplicate + unsolicited-modifier policy, late-delivery acceptance.
- `src/sync.rs` — per-peer `SyncState` download-window tracker + `compare_sync_info`/`PeerChainStatus` height-based preliminary classifier (full fork choice lives in `ergo-sync`).
- `src/types.rs` — shared payload types: `ModifierTypeId`, `InvData`, `ModifiersData`, `SnapshotsInfo`, `NipopowProofData`.

## Key types, traits & functions
- `serialize_frame` / `deserialize_frame` (fn) — the frame codec; deserialize returns `Ok(None)` on a partial buffer, `Err` on protocol violation — `src/framing.rs:69` / `src/framing.rs:97`
- `MessageFrame` (struct) / `FrameError` (enum) — parsed `code`+`payload`; WrongMagic/NegativeLength/ChecksumMismatch/UnknownCode — `src/framing.rs:46` / `:24`
- `Connection` (struct) — async framed TCP wrapper; `read_message`/`write_message`/`send`, `new_with_buffer` for post-handshake leftover bytes — `src/connection.rs:21`
- `CODE_*` (consts) — message id registry (GetPeers 1, Peers 2, RequestModifier 22, Modifier 33, Inv 55, SyncInfo 65, Handshake 75, snapshot 76-81, NiPoPoW 90-91) — `src/message.rs:19`
- `SyncInfo` (enum) — V1 header-id list / V2 serialized-header list with the `-1` marker convention — `src/message.rs:238`
- `Handshake` / `PeerSpec` / `DeclaredAddress` (structs) — handshake wire shape; `serialize_peer_spec_to`/`deserialize_peer_spec_from` shared with `Peers` — `src/handshake.rs:394` / `:276` / `:285`
- `Version` (struct) — 3-byte protocol version with named milestones (`EIP37_FORK`, `NIPOPOW`, `CURRENT` = 6.0.2) and `Ord` — `src/handshake.rs:16`
- `PeerFeature` (enum) — LocalAddress(2)/SessionId(3)/RestApiUrl(4)/Mode(16)/Unknown; unknown features round-trip verbatim — `src/handshake.rs:74`
- `PeerInfo` (struct) — per-peer record: state/score/direction/spec/sync_version + shared atomic byte counters — `src/peer.rs:233`
- `PeerScore` (struct) / `Penalty` (enum) / `PenaltyOutcome` (enum) — time-decaying score, ban escalation, Scala-parity penalty values (NonDelivery 2 / Misbehavior 10 / Spam 25 / Permanent 1e9) — `src/peer.rs:111` / `:76` / `:402`
- `PeerManager` (struct) — connection lifecycle + selection + discovery + ban hub; ~40 public methods — `src/peer_manager/mod.rs:149`
- `PeerLimits` (struct) / `ConnectError` (enum) — anti-eclipse caps (80/60/1/3 defaults) and dial/accept rejection reasons — `src/peer_manager/limits.rs:17` / `:45`
- `is_routable_for_p2p` (fn) / `declared_to_socket` (fn) — dial/gossip routability gate; safe IPv4/IPv6 declared-address parse — `src/peer_manager/routability.rs:26` / `:78`
- `AddressBook` (struct) — redb peer/ban persistence; `open`/`load_all`/`upsert_handshaked`/`record_ban`/… — `src/address_book/mod.rs:200`
- `distribute` (fn) / `Bucket` (type) / `BucketConfig` (struct) — pure per-round modifier-ID partitioner across sorted peers — `src/partition.rs:91` / `:41` / `:59`
- `ThroughputLimiter` (struct) / `LimiterVerdict` (enum) — per-peer rate limiter; `check_and_record` only records on `Ok` — `src/throttle.rs:89` / `:38`
- `AssemblyTracker` (struct) — section-arrival aggregator; `section_received` signals completion exactly once (incomplete→complete transition) — `src/assembly.rs:28`
- `DeliveryTracker` (struct) / `DeliveryAction` (enum) / `ModifierStatus` (enum) — in-flight request bookkeeping; `on_received` → Accept/Ignore/RejectSpam — `src/delivery.rs:96` / `:55` / `:42`
- `SyncState` (struct) / `compare_sync_info` (fn) / `PeerChainStatus` (enum) — download-window + per-peer SyncInfo cadence; height-based status classifier — `src/sync.rs:63` / `:328` / `:21`
- `ModifierTypeId` (enum) / `InvData` / `ModifiersData` / `SnapshotsInfo` / `NipopowProofData` — shared protocol payload types — `src/types.rs:8` / `:52` / `:62` / `:73` / `:81`

## Invariants & contracts
- **Wire-frame format parity.** `magic[4]||code[1]||len[4 BE i32]` is 9 bytes for an empty payload, else `+ checksum[4] || payload`; checksum is the first 4 bytes of `blake2b256(payload)`. Framing is raw big-endian, NOT VLQ. `wire_len` is pinned to the codec by `wire_len_matches_serialize_frame` so byte accounting can't drift (`src/framing.rs`).
- **Payload codec ↔ Scala parity.** Message payloads use VLQ/zigzag (`ergo_primitives` reader/writer). Size caps, count limits (Inv ≤ 400, SyncInfo V1 ≤ 1001, V2 ≤ 50 headers), and mandatory NiPoPoW `pad_length` truncation-errors mirror the Scala `*Spec.scala` sources; the `MAX_MODIFIER_WITH_RESERVE` accounting in deserialize must match the serializer's per-entry `id+4+len` (regression-pinned in `message.rs` tests).
- **DoS-bound allocation.** Decoders never pre-reserve from an attacker-controlled VLQ count: `Vec::with_capacity` is bounded by `remaining / MIN_*_ENTRY_BYTES`, and oversized declared frame lengths are rejected at `Connection::read_message` before buffering the payload (`MAX_PAYLOAD_SIZE` 8 MiB).
- **Peer scoring / ban parity.** Penalty scores and the 500-point ban threshold match Scala `PenaltyType`; `Permanent` bypasses the 2-minute safe interval and routes straight to a (capped 1-year) ban; the peer version floor is EIP-37 (4.0.100) and a below-floor handshake is permanently banned. Score decays 10 points / 10 minutes.
- **Anti-eclipse connection limits.** Defaults: 80 total, 60 target-outbound, 1 per IP, 3 per /16 subnet. Self-connection is detected via the SessionId feature's `session_id`. Gossip-learned addresses pass the routability filter; operator `Seed` addresses bypass it and survive dial-pool eviction.
- **Persistence isolation + atomicity.** The address book is a separate `peers.redb` (no coupling to the consensus state DB) and can be wiped without touching the chain. Every production write goes through `begin_write_qr` (quick-repair on) so a crash never leaves the DB needing full repair; bans and peers are both persisted (a deliberate divergence from Scala, which holds bans in-memory). Best-effort: write failures are logged, in-memory state stays authoritative.
- **Delivery / assembly idempotency.** `AssemblyTracker::section_received` returns the header id only on the first incomplete→complete transition; `DeliveryTracker` accepts a section only from the current owner or a registered late-acceptable peer, treats duplicates as Ignore and truly-unsolicited modifiers as RejectSpam, and bounds the received-set at 10,000 entries (FIFO).
- **Partition determinism.** `distribute` assigns each modifier ID to at most one bucket per call, preserves input ID order within a bucket, emits types in ascending order, rotates the first assignee by `round`, and never panics on empty peers (no modulo-by-zero). Overflow beyond `peers.len() * max_per_bucket` is deferred to the caller's next round, not dropped.
- **Charter boundary.** This crate owns transport, wire codecs, and per-peer accounting only — no chain logic, no fork choice, no validation. `compare_sync_info` is an explicit height-based *preliminary* classifier; real cumulative-difficulty fork choice lives in `ergo-sync`/`ergo-state`. The block-section id recipe lives in `ergo_ser::modifier_id`, not here.

## Notes on doc accuracy
README.md:160 (`ergo-p2p — Wire framing, peer manager, Inv / RequestModifier`), README.md:197-200, docs/architecture.md:26, and docs/architecture.md:45-47 describe this crate accurately versus the current source: the L2 layer placement, the dependency posture (only `ergo-primitives` + `ergo-ser`), the "knows nothing about chain logic / `ergo-sync` drives p2p as a passive transport" charter, and the feature list (framing, handshake, typed messages, per-peer state machine, peer manager, redb address book, block-section assembly, modifier-delivery tracking) all match. No stale or wrong claims found.
