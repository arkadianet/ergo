# Unverified and open protocol questions

Anything here is **UNVERIFIED** until a reference-source citation, an
imported golden vector, or a captured live byte sequence pins it. Phase 0
must not treat these as settled.

Reference pin: `ergoplatform/ergo` **v6.0.7**
(`~/Coding/remote/ergo-scala`). Wire-facing files are unchanged from
v6.0.5; see [`survey.md`](survey.md).

## Wire bytes: verified against source

Pinned by the v6.0.7 reference source (Scala citation), imported test
vectors, or byte vectors independently computed from that source (all in
`ergo-p2p`, committed with the codec/fuzz work):

| Item | Source evidence |
|---|---|
| Handshake full frame | Real-node 52-byte hex fixture imported from `ergo-core/src/test/.../network/HandshakeSpecification.scala:13` (`real_node_handshake_fixture` in `ergo-p2p/src/handshake.rs`): agent `ergoref`, v3.3.6, `LocalAddress` 127.0.0.1:9006. The fixture also pins the `LocalAddress` **port wire encoding as VLQ** — port 9006 is parsed as a 2-byte VLQ from the fixture bytes. |
| GetPeers (code 1) | Full-frame golden vector `010002040100000000` (`get_peers_full_frame_vector`, `ergo-p2p/src/message/tests.rs`), computed independently in Python per `MessageSerializer.scala:22-34` (blake2b256[:4] checksum). |
| Peers (code 2) | Full-frame golden vector with a fixed `PeerSpec` (`peers_full_frame_vector`, same file), computed independently in Python. |
| SyncInfo V2 full frame | Full-frame golden vector `0100020441000000e1437c8549{225 B payload}` (`sync_info_v2_full_frame_vector`, same file); payload prefix `00ff01dc01` = VLQ `putUShort(0)` + marker `0xff` + count 1 + VLQ length. |
| `SessionId` feature body | `putBytes(magic)` + `putLong(sessionId)` (`SessionIdPeerFeature.scala:36-40`) with scorex `putLong`/`getLong` = **VLQ + zigzag**, variable-length 1..=10-byte body (scorex-util 0.2.2 `VLQWriter`/`VLQReader`); six golden body vectors computed independently in Python (`session_id_feature_wire_format_golden_vectors`, `ergo-p2p/src/handshake.rs`). |
| `Mode` feature `verify_tx` byte | Signed-byte boolean per `byteToBoolean` (`ModePeerFeature.scala:109`). |
| Declared address layout | Length byte = address bytes + 4, then port via `getUInt().toIntExact` (`PeerSpec.scala:79-85`); a hint below 4 throws in Scala — mirrored by `HandshakeError::MalformedDeclaredAddress` (the *only* item-4 fix that changed accept/reject behaviour). |
| Feature id registry | 2 `LocalAddress`, 3 `SessionId`, 4 `RestApiUrl`, 16 `Mode` (`PeerFeatureDescriptors.scala`). |
| Feature parse-failure semantics | Unknown id **or** failed body parse drops the single feature and the handshake still succeeds (`PeerSpec.scala:86-99`: `parseTry(...).toOption`, with the comment "we ignore a feature … if we do not know how to parse it or failed to do that"); only a *structural* `PeerSpec` failure (empty agent name, negative feature count, truncated chunk, port > `Int.MaxValue`) fails the whole handshake, which `PeerConnectionHandler` answers with `banPeer()` = permanent penalty + `CloseConnection` (`PeerConnectionHandler.scala:100-115`). This is why our pre-fix malformed `SessionId` bodies were tolerated by Scala peers: dropped, not rejected. |
| SyncInfo V2 header bound | `headerBytesCount < 1000` — reject `>= 1000` (`SyncInfoMessageSpec.scala`). |
| `Peers` count bound | `maxPeerSpecObjects` default 64; over-limit is a parse rejection (scorex network config). |

**Key codec pin (source, corroborated live):** scorex `Writer.putUShort` /
`putUInt` / `putLong` are **VLQ** (plus zigzag for signed), not
fixed-width big-endian — `VLQWriter.scala`, scorex-util 0.2.2.

## Wire bytes: verified against live bytes

Pinned by captured mainnet/testnet traffic (the 48 h dataset streams) or
the 2026-11-10 A/B run, not by the reference source alone:

| Item | Live evidence |
|---|---|
| VLQ encoding on the wire | The Rust VLQ decoder parsed real mainnet 4-header V2 syncs and real peer handshakes without modification (`pop-os-mainnet` stream, from 2026-11-10 14:02). |
| 6.0.8 seed V2 sync form | Live seeds send the 4-header form at offsets 0/16/128/512 behind the tip (observed heights, `pop-os-mainnet` stream) — matches `FullV2SyncOffsets` in the v6.0.7 source, but the 6.0.8 binary itself was not inspected. |
| 400-id catch-up extension | Empty-V2 reply → seed re-sends `Inv` of the first 400 header ids; per-seed re-send gaps 0.9 s, then 60.1–62.4 s (A/B run 2026-11-10, `/home/arkadias/observation/syncinfo-ab-2026-11-10/`); each of the 400 ids re-announced 3 006 times by 20:35. |
| Tip-presentation fix behaviour | Old binary (empty V2): seed sends **6** extensions in ~4.5 min. New binary (tip V2): **1** extension, then a tip reply, seed goes silent (same A/B run). |
| Header sizes on the wire | Mainnet tip headers constant 220 B; early-chain headers (h ≤ 400) 278/279 B — extension content still unidentified (row in the next section). |
| `SessionId` decode against live peers | **Live-verified, 2026-11-11 capture run** (07:25–11:47 AEST; 2 508 mainnet handshakes from 55 unique peers, `--capture-handshake-hex`, replayed offline through the fixed codec via `replay-captures`): 100 % parse-OK, 0 rejections, 0 newly-rejected vs the pre-fix codec. Per unique peer, excluding our own pre-fix node (50 handshakes): 2 408/2 458 strict (98.0 %), 50/2 458 `unknown:3` (2.0 %) — all 50 from one other pre-fix Rust peer (`ergo-rust-mainnet-nbg1`, old 12-byte BE body, preserved verbatim as `Unknown`, handshake accepted). Including our own node: 2 408/2 508 (96.0 %). Independent confirmation (jar oracle, real Scala 6.0.8 `HandshakeSerializer.parse`): the testnet canary's 72-byte handshake decodes `magic=02030203` (testnet, `testnet.conf:94`) + `sessionId=8288960606751204270` and is fully consumed (72/72); our pre-fix node's 12-byte body is accepted by Scala but mis-decoded (`sessionId=-10`) — both directions of the interop explained. |

## Wire bytes without an imported external oracle

| Item | Current evidence | How it will be verified |
|---|---|---|
| SnapshotsInfo / GetSnapshotsInfo | Byte-layout unit tests derived from `BasicMessagesRepo.scala`. | **Deferred by decision** (Phase 0 keeps parse-level parity only). |
| Manifest / GetManifest | Same. | **Deferred by decision.** |
| UtxoChunk / GetUtxoChunk | Same. | **Deferred by decision.** |
| NipopowProof / GetNipopowProof | Same. | **Deferred by decision.** |
| Early-mainnet header extension content | Captured live: mainnet headers at heights 1–400 arrive as 278/279 B (vs 220 B for tip headers) — the extra bytes are the variable-length header extension; content not yet identified (2026-11-10, `pop-os-mainnet` stream). Irrelevant to wire parity (the parser handles the extension generically; both sizes parse and id-match). | Identify by fetching one such block (e.g. id `55ee5b282051993f…`, height 60) from a full-node/explorer block view and reading the extension payload; only needed if the report cites early-header sizes. |

## Behavioural differences observed in code review

These are not wire-format unknowns; they are known local divergences that
must either be fixed, tested as intentional, or listed in the report.

1. **Unknown peer features are preserved, not dropped.**
   `ergo-p2p/src/handshake.rs` deserializes an unrecognized feature id into
   `PeerFeature::Unknown` and re-serializes its body verbatim. Scala
   `PeerSpecSerializer.parse` (`PeerSpec.scala:86-99`) uses `flatMap` over
   the known serializer map and **drops** unknown features. Consequence: a
   `PeerSpec` we relay through `Peers` can carry features Scala would have
   discarded. Harmless for parsing, observable in a byte differential.
   Status: open; decide whether to keep (round-trip fidelity) and document.
   Since the codec/fuzz fix, the preservation also applies to *known*
   feature ids whose body is not the canonical serialization (trailing
   bytes, truncated fields, out-of-range values) — `deserialize_feature`
   requires exact field bounds and full consumption, and preserves
   otherwise. This is a deliberate superset over Scala: Scala's `parseTry`
   (`Serializer.scala`, scorex-util 0.2.2) is a plain `Try(parse(r))` and
   its chunk reader is not checked for exhaustion, so Scala silently
   ignores trailing bytes in a feature chunk. The stricter parse keeps
   `serialize(deserialize(x)) == x` byte-stable for preserved specs, which
   matters because they are re-emitted in `Peers` replies.

2. **SyncInfo V2 header length boundary (fixed in this change).**
   Scala requires `headerBytesCount < 1000`; the Rust decoder previously
   accepted exactly 1000. Both encoder and decoder now reject `>= 1000`.
   Golden boundary test added in `ergo-p2p/src/message/tests.rs`.

3. **Peers count limit (fixed in this change).**
   The node dispatch previously accepted up to 100 `PeerSpec`s per `Peers`
   message, while Scala uses `scorex.network.maxPeerSpecObjects` (default
   64) and rejects larger counts. The dispatch now uses
   `MAX_ACCEPTED_PEER_SPECS` (64). The `ergo-p2p` codec itself takes the
   limit as a parameter, which is correct for testability.

4. **Empty SyncInfo V2 header entries.**
   The Rust decoder stores V2 header bytes without parsing them, so a
   zero-length header entry is accepted at the message layer. Scala calls
   `HeaderSerializer.parseBytes` immediately and would reject it. This is
   deferred to the parse-level differential work; it does not affect
   well-formed peers.

5. **Handshake agent/node-name truncation.**
   The Rust encoder truncates strings to 255 bytes on a UTF-8 boundary;
   Scala `putShortString` behaviour for overlong strings is not yet pinned.
   Honest peers stay far below the limit, so this is a malformed-input
   edge case. Status: UNVERIFIED.

6. **Rust-node SyncInfo V2 content differs from Scala (observed 2026-11-10).**
   Our Rust node presents its 50 most recent *consecutive* headers in a V2
   SyncInfo (`build_sync_info_payload`,
   `ergo-sync/src/coordinator/events.rs:881-892`), while the Scala
   reference presents 4 headers at offsets 0/16/128/512 behind the tip
   (`ErgoHistoryReader.syncInfoV2`, `ErgoHistoryReader.scala:393-409`;
   `FullV2SyncOffsets`, `ErgoHistoryReader.scala:601`). The wire format is
   the same; the extra headers are a strict superset of candidate common
   points for `compareV2`/`commonPoint`. Live data confirms the ergoref
   6.0.8 seeds send the 4-header form (observed heights tip, tip−16,
   tip−128, tip−512, `pop-os-mainnet` stream). Status: open — decide
   whether to match the 4-header form for closer parity or document the
   superset as intentional.

7. **`SessionId` feature wire format (found by the offline fuzz suite,
   fixed in this change).** The Rust codec serialized the 64-bit session id
   as a fixed 8-byte big-endian and parsed it the same way. Scala writes
   `putBytes(magic)` + `putLong(sessionId)`
   (`SessionIdPeerFeature.scala:36-40`), and scorex's `putLong`/`getLong`
   are **VLQ + zigzag** (scorex-util 0.2.2 `VLQWriter.putLong` /
   `VLQReader.getLong`) — a variable-length 1..=10-byte body. The old
   codec therefore misread every Scala peer's session id (and Scala
   misreads ours) in both directions, silently breaking self-connection
   detection (`ergo-node/src/node/events.rs` extracts the id from the
   peer's feature). Fixed to VLQ+zigzag on both sides; six golden body
   vectors pin the format (`session_id_feature_wire_format_golden_vectors`,
   `ergo-p2p/src/handshake.rs`). Cross-generation evidence (pre-fix
   parser on the 20 new/old-format bodies: 0 rejections, 7 of 8
   ≥12-byte bodies silently mis-decoded; fixed codec: 19 exact
   `SessionId` + 1 verbatim `Unknown`): `docs/evidence/old-vs-new-sid/`
   and `ergo-p2p/tests/it/sid_cross_compat.rs`.

8. **Feature/declared-address port bounds and declared-address length
   byte (found by the offline fuzz suite, fixed in this change).**
   (a) `LocalAddress` and declared-address ports were serialized up to
   `u32::MAX` while the parser capped at `i32::MAX`
   (`get_u32_exact` mirrors Scala `getUInt().toIntExact`,
   `LocalAddressPeerFeature.scala:31-35`), so port 2^31 (the fuzz
   regression case) failed the round-trip byte-identity property. The
   serializer now caps at `i32::MAX`; real ports are ≤ 65535 so this never
   fires in production. (b) A declared-address length hint below 4
   previously saturated to a zero-length address; Scala
   `getBytes(fas - 4)` (`PeerSpec.scala:83`) throws instead, failing the
   whole handshake — mirrored with `HandshakeError::MalformedDeclaredAddress`.
   Both pinned by unit tests and by the saved proptest regression cases in
   `ergo-p2p/tests/proptest-regressions/fuzz_offline.txt`.

## Network / measurement assumptions that need data

These are not protocol unknowns; they are measurement-validity questions
that the Phase 0 report must state honestly.

- **Announce ≠ learn.** A peer's `Inv`/`SyncInfo` is stamped when it is
  sent; it may be sent after that peer has already validated the block. Our
  receive timestamp is a lower bound on dissemination, not the peer's own
  first-knowledge time.
- **Per-hop delay is not directly observable** from a single node. We can
  measure per-peer announce delay and first-arrival ordering, but not the
  graph path between the miner and each peer.
- **Vantage bias.** One host on one network sees one slice. The report must
  state the connection count, peer set, and location, and defer network-wide
  claims until a second vantage exists.
- **Clock offset.** `chrony` reports ~1 ms RMS offset on this host today.
  Observer records carry the offset and its source; durations use the
  monotonic clock, not wall time.
- **Crawler reachability is dial-based.** "Reachable" means a completed
  handshake from this vantage within the dial timeout; it does not prove
  the peer is reachable from elsewhere.
- **Seed catch-up re-send cadence (6.0.8 seeds).** The v6.0.7 reference
  explains the mechanism (the 400-id extension is sent inside
  `processSyncV2`, i.e. per processed reply; 60 s `SyncThreshold` at
  `ErgoSyncTracker.scala:21`) and the 60 s cycle was reproduced live in
  the 2026-11-10 A/B run (extension gaps 0.9 s, then 60.1–62.4 s). In
  v6.0.7 the `SendLocalSyncInfo` scheduler ticks at `syncInterval`
  (`application.conf:553`, 5 s) unconditionally
  (`ErgoNodeViewSynchronizer.scala:278-279`); each tick re-includes
  peers per `peersToSyncWith` gating (`ErgoSyncTracker.scala:174-199`).
  Notably, `syncIntervalStable` (`application.conf:556`, 15 s) is
  *defined but unused* in the v6.0.7 sources — the 6.0.8 seeds may
  switch to it once synchronized, which would fit the per-seed p50s
  measured in the 48 h window (5.0 s / 23.6 s / 60.2 s). The exact
  6.0.8 constants/logic are not pinned by the v6.0.7 reference. The
  cadence does not affect the correctness of the tip-presentation fix:
  the comparison result (`Equal` vs `Younger`), not the cadence, controls
  whether an extension is sent.

## Deferred by explicit decision

- Network-level JVM differential (scripted peer against private JVM and
  Rust nodes). Parse-level accept/reject parity is in scope.
- Golden vectors for SnapshotsInfo, Manifest, UtxoChunk, and NiPoPoW.
- A second observation vantage (until one is available).

## Node hook live-test status

The `[observer]` node hook is implemented (see
[`phase0-observer.md`](phase0-observer.md)) and passes unit and config
tests.

- Testnet run: **LIVE** (2026-11-10 13:36 local, `testnet-hook` vantage).
  Verified live: `observer_start`, `announce` (`syncinfo_v2` with heights
  and `inv` tx), `request_sent`, `section_received` (solicited, with
  bytes), `tx_outcome` (`admitted` with fee, size, and `input_ids`),
  `block_applied`, and — once peer blocks started flowing —
  `header_validated` (58 records by 17:12). Note the node is an active
  testnet miner: locally mined blocks fire `block_applied` (340 in 3.6 h)
  but never `header_validated` (the local path bypasses the peer header
  pipeline) and carry no `since_first_announce` — the 58 peer blocks match
  the 58 `header_validated` records 1:1. The executor → observer wiring is
  also unit-tested:
  `ergo-sync` `executor::tests::validation_observer_fires_for_each_installed_header`
  (real mainnet header fixtures, single and batch paths, asserts the
  callback fires exactly once per installed header with the installed id
  and height).
- Mainnet run: **LIVE** (2026-11-10 15:29 local, `mainnet-hook` vantage).
  The mainnet node was restarted on a binary built from its current PR #694
  base (`f70bd07b`, nonP2pk API preserved) plus this branch's change set —
  the only delta is the Phase 0 work (observer hook + codec parity fixes).
  Verified live by 17:12: `observer_start`, `announce` flowing, peer ids
  join with the standalone observer and crawler (shared pseudonym key),
  and all three outcome events flowing — `tx_outcome` (440+, rejection
  mix analysed in the parity section of
  [`phase0-observer.md`](phase0-observer.md)), `block_applied` (49, all
  peer-announced — the node mined none in the window), `header_validated`
  (49). See the partial-data analysis there for the missing-`duration_us`
  finding and fix (commit `cd701a8c`, not yet deployed to the live nodes).
  The standalone observer is running the minimum-48h
  deployment (started 2026-11-10 14:02 local; restarted 15:01 with the
  refactored build after the crawler landed — same behaviour, new
  `run_session` signature).

## Crawler live status

- Mainnet: **LIVE** (2026-11-10 15:01 local, `pop-os-mainnet-crawler`).
  Verified after ~2 min: dials with all four outcomes
  (`handshaken`, `handshake_fail`, `connect_refused`, `connect_timeout`),
  `peer_learned` with `via` pseudonyms, 64 KiB/s per-session ceiling,
  12 new dials/min global cap, per-address backoff, state file persisted
  at mode 0600 and reloaded on restart (backoff survives).
- Testnet: **LIVE** (2026-11-10 15:01 local, `pop-os-testnet-crawler`).
  Walked the small testnet peer set from the local node seed.
- Both crawlers reuse the per-network standalone-observer pseudonym key
  so peer ids join across the observer and crawler JSONL files.
