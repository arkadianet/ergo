# Phase 0 survey: legacy P2P stack

Read-only survey of the Rust node's existing P2P implementation, compared
with the Scala reference node. Every protocol claim below cites either a
reference-source path (local checkout, pinned revision) or a shipped
fixture. Claims that could not be confirmed are listed in
[`unverified.md`](unverified.md).

## Reference pin

Phase 0 pins the reference to **`ergoplatform/ergo` v6.0.7**
(`5528ef569a41ebccbc8658212e6ee3c97d990b96` is v6.0.5; v6.0.7 is the tag
level checked out locally at `~/Coding/remote/ergo-scala`).

Version decision (2026-11-10): the network-facing files are **unchanged**
between v6.0.5 and v6.0.7. `git diff --stat v6.0.5 v6.0.7` over
`src/main/scala/org/ergoplatform/network`, `ergo-core/src/main/scala/org/ergoplatform/network`,
the Scala network tests, and `application.conf` reports only:

- `application.conf`: `appVersion` `6.0.5` → `6.0.7`, plus a mempool policy
  flag (`rejectStorageRentTxs`), which is not wire format.
- `ErgoNodeViewSynchronizer.scala`: during UTXO-snapshot bootstrap, ignore
  block-section Invs until the snapshot is applied. This is a sync-policy
  change, not a codec change.
- `ErgoNodeViewSynchronizerSpecification.scala`: test additions.

Therefore v6.0.7 is the pinned reference and v6.0.5 fixture provenance
remains valid for wire bytes. The Rust node already advertises
`Version::CURRENT = 6.0.7` (`ergo-p2p/src/handshake.rs:60-66`).

## What the Rust repo already has

### Workspace

23 crates (`Cargo.toml`). The Phase 0 surface is:

- `ergo-p2p` — transport, wire codecs, peer bookkeeping (~17.3k lines of
  `src` + `tests`).
- `ergo-sync` — coordinator/executor: events → actions, header-first sync.
- `ergo-node` — runtime wiring, peer loop, action loop, dispatch.
- `ergo-difftest` — fuzz harness and differential-test helpers.

`ergo-p2p` depends only on `ergo-primitives`, `ergo-ser`, `redb`, `thiserror`,
`tokio`, and `tracing` (`ergo-p2p/Cargo.toml`). It does not depend on
consensus or node internals, so a new observer crate can reuse it without
extracting or refactoring the codec.

### Framing

`ergo-p2p/src/framing.rs`

- `magic[4] || code[1] || length[4 BE i32] || checksum[4] || payload`.
- Empty payload omits the checksum (9-byte frame); non-empty is 13 + length.
- Checksum = first 4 bytes of `Blake2b256(payload)`.
  Verified by Scala `ErgoSyncInfoSpecification.scala` (`checksum shouldBe
  hash.Blake2b256(...)`).
- Payload lengths are big-endian raw integers in the frame header; payload
  fields use Scorex VLQ (`ergo-primitives`).

### Handshake

`ergo-p2p/src/handshake.rs`

- `Handshake { time: u64, peer_spec }`; `time` is VLQ `putULong`.
- `PeerSpec` layout: shortString agent, three raw version bytes, shortString
  node name, optional declared address (`len byte`, addr, `u32` port), signed
  feature count, then `(feature_id, ushort_len, body)`.
- Feature ids 2 (`LocalAddress`), 3 (`SessionId`), 4 (`RestApiUrl`), 16
  (`Mode`), matching `PeerFeatureDescriptors.scala`.
- Admission cap: parsed prefix ≤ 8096 bytes (`HandshakeSerializer.scala:22`),
  implemented as `MAX_HANDSHAKE_SIZE`; coalesced framed bytes after the
  prefix are preserved.
- Agent/node names are one-byte-prefixed strings; the encoder truncates at
  255 bytes on a UTF-8 boundary.

**Verification state:** codec unit tests and a synthetic code-75 exchange;
no imported golden byte vector in the repo. The reference
`HandshakeSpecification.scala` contains a real-node hex fixture
(`bcd2919c…`) that Phase 0 will import (see `unverified.md`).

### Messages and codes

`ergo-p2p/src/message/mod.rs` registers all 15 codes used by the reference
node:

| Code | Message | Codec entry point |
|---|---|---|
| 1 | GetPeers | `serialize_get_peers`, `deserialize_get_peers` |
| 2 | Peers | `serialize_peers`, `deserialize_peers` |
| 22 | RequestModifier | `serialize_inv`, `deserialize_inv` |
| 33 | Modifiers | `serialize_modifiers`, `deserialize_modifiers` |
| 55 | Inv | `serialize_inv`, `deserialize_inv` |
| 65 | SyncInfo | `serialize_sync_info`, `deserialize_sync_info` |
| 75 | Handshake | `handshake.rs` |
| 76 | GetSnapshotsInfo | `serialize_get_snapshots_info` |
| 77 | SnapshotsInfo | `serialize_snapshots_info` |
| 78 | GetManifest | `serialize_get_manifest` |
| 79 | Manifest | `serialize_manifest` |
| 80 | GetUtxoChunk | `serialize_get_utxo_chunk` |
| 81 | UtxoChunk | `serialize_utxo_chunk` |
| 90 | GetNipopowProof | `serialize_get_nipopow_proof` |
| 91 | NipopowProof | `serialize_nipopow_proof` |

Limits: 400 Inv/RequestModifier ids, 400 modifiers, 2 MiB modifier payload,
400 peers per `Peers` message, 50 headers in SyncInfo V2
(`message/mod.rs:36-56,278-281`; Scala
`BasicMessagesRepo.scala:43-62`, `ErgoSyncInfo.scala:41-46`).

### SyncInfo versions

`ergo-p2p/src/message/mod.rs:273-385`; reference
`ergo-core/.../history/ErgoSyncInfo.scala`.

- V1: `putUShort` count (VLQ on the wire), then 32-byte ids. Oldest-first,
  tip last. Maximum 1000 ids plus a zero pregenesis sentinel. `length == 0`
  with trailing bytes is not V1.
- V2: count `0`, marker byte `-1` (`0xFF`), ubyte header count ≤ 50, then
  `(ushort length, header bytes)` newest-first. Header length must be
  `< 1000`.
- `ErgoSyncInfoSpecification.scala` pins V1 bytes but has no V2 byte
  fixture; the repo's V2 vector is source-derived payload-only
  (`test-vectors/ergo-p2p/PROVISIONING.md`).

### Peer management, address book, delivery

- `peer_manager/limits.rs`: 384 max connections, 96 target outbound, 256
  inbound, 1 per IP, 3 per IPv4 `/16` or IPv6 `/48`.
- `peer_manager/`: self-session detection, eviction, seed handling, gossip,
  selection policy.
- `address_book/`: redb persistence, quick-repair writes, expiry,
  routability pruning, failure/backoff state.
- `delivery/`: one current owner per modifier, 3 s delivery timeout
  (deliberate divergence from Scala's 10 s), retries/hedges, late-arrival
  allowances, bounded received FIFO.
- `throttle.rs`: per-peer message/byte windows. `partition.rs`:
  throughput-aware request buckets.
- `sync.rs`: download-window state and V1/V2 status comparison.

These are local policy and are unit-tested; they are **not** authenticated
peer identity and do not establish a universal eclipse-resistance property
(`docs/codemap/ergo-p2p.md`).

### Node integration

- `ergo-node/src/peer_loop.rs`: raw handshake, then framed read/write loop
  with byte budgets (`EventByteBudget`, 256 MiB) and backpressure.
- `ergo-node/src/node/messaging/dispatch.rs`: per-code dispatch, throttle,
  progress classification, penalties.
- `ergo-node/src/node/peer_actions.rs`: action flush, RequestModifier
  counters, penalty application, first-deliverer ring drain.
- `ergo-sync/src/coordinator/`: `on_inv`, `on_sync_info`,
  `on_modifier_received`, `on_header_validated`, `on_block_applied`.
- Existing observability: `first_deliverer.rs` (bounded
  `header_id → first peer`), `NetStats` (per-peer Inv/Modifier counters),
  `/api/v1/events` (`peerConnected`, `peerDisconnected`, `blockApplied`,
  `reorg`), `/metrics`, `telemetry.rs`.

### Tests, vectors, fuzzing, CI

- Golden vectors (`test-vectors/ergo-p2p/`): full frames for Inv,
  RequestModifier, SyncInfo V1, Modifiers; V2 payload only.
  Consumed by `ergo-p2p/tests/it/wire_vectors_oracle.rs`.
- `test-vectors/ergo-p2p/sync-v1/`: pinned Scala v6.0.5 source, JVM
  comparison/producer observations, provenance hashes.
- Unit/integration tests: `message/tests.rs` (~969 lines),
  `delivery/tests.rs`, `peer_manager/tests.rs`, `wire_tcp_pair.rs`,
  `structured_error_propagation.rs`, `address_book_persist.rs`.
- Fuzz targets: `p2p_frame`, `p2p_handshake`, `p2p_message`,
  `p2p_delivery` (`ergo-difftest/fuzz/`), with corpus directories and
  `scripts/fuzz-step.sh`. CI has a fuzz workflow (`.github/workflows/fuzz.yml`).
- CI gates: `cargo fmt --check`, `cargo clippy --all-targets -D warnings`,
  `cargo nextest run --workspace`, `cargo audit --deny warnings`,
  `cargo deny` (`.github/workflows/ci.yml`).

## Gaps versus Phase 0

1. **No observer mode** and no JSONL schema. No per-block pipeline keyed by
   `(header_id, peer)` covering announce → request → section delivery →
   validation → applied.
2. **No crawler.** `peer_manager` can dial learned peers, but there is no
   controlled discovery walk with persistent rate-limited state.
3. **No per-request RTT output.** `DeliveryTracker` keeps `requested_at`
   internally; it is not surfaced per completed request.
4. **No validation-latency telemetry** keyed to first announce.
5. **No clock-offset field** in any existing output.
6. **Golden bytes incomplete**: Handshake, GetPeers, Peers, full-frame V2
   have no imported external vector. (Per instruction, SnapshotsInfo,
   Manifest, UtxoChunk, and NiPoPoW vectors are deferred.)
7. **No parse-level JVM accept/reject differential harness.** Network-level
   differential is deferred by decision.
8. **No `docs/phase0-report.md`, dataset, or analysis scripts.**
9. **Documentation error fixed in this change:** `docs/compatibility.md`
   described the wire checksum as SHA-256; the framing checksum is
   Blake2b-256 (first 4 bytes). SHA-256 is used for webhook/API hashing, not
   P2P frames.

## Environment (observed 2026-11-10)

- Live Rust mainnet node: `127.0.0.1:9063`
  (`/home/arkadias/nodes/rust-mainnet`), archival UTXO, 64 peers.
- Live Rust testnet node: `127.0.0.1:9052`
  (`/home/arkadias/nodes/testnet-node`).
- `chrony` active; RMS offset ≈ 1 ms, last offset ≈ −0.3 ms.
- `tcpdump` usable; Docker unavailable; `sbt` not on `PATH`; Java 21 and the
  pinned Scala 2.12.21 jars are available.
- Disk: ~226 GB free. Short, rotated captures and derived JSONL are
  feasible; a multi-day raw pcap of 64 peers is not.
