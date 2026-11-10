# Unverified and open protocol questions

Anything here is **UNVERIFIED** until a reference-source citation, an
imported golden vector, or a captured live byte sequence pins it. Phase 0
must not treat these as settled.

Reference pin: `ergoplatform/ergo` **v6.0.7**
(`~/Coding/remote/ergo-scala`). Wire-facing files are unchanged from
v6.0.5; see [`survey.md`](survey.md).

## Wire bytes without an imported external oracle

| Item | Current evidence | How it will be verified |
|---|---|---|
| Handshake full frame | Codec implemented from `HandshakeSerializer.scala` / `PeerSpec.scala`; only a synthetic code-75 exchange in `wire_tcp_pair.rs`. | Import the real-node hex fixture already present in `ergo-core/src/test/.../HandshakeSpecification.scala` (`bcd2919c…`). |
| GetPeers (code 1) | Empty-payload requirement follows `BasicMessagesRepo.scala:18-29`; round-trip unit test only. | Add a full-frame vector generated from the Scala `MessageSerializer` (empty payload, so deterministic). |
| Peers (code 2) | PeerSpec reuse, count limit, round-trip unit tests. | Add a deterministic Scala-serialized vector with a fixed `PeerSpec`. |
| SyncInfo V2 full frame | Repo vector is **payload only**, transcribed from `ErgoSyncInfo.scala`; not an upstream byte assertion. | Generate a full frame with the Scala serializer using fixed header bytes. |
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
