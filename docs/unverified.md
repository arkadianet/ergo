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

## Deferred by explicit decision

- Network-level JVM differential (scripted peer against private JVM and
  Rust nodes). Parse-level accept/reject parity is in scope.
- Golden vectors for SnapshotsInfo, Manifest, UtxoChunk, and NiPoPoW.
- A second observation vantage (until one is available).

## Node hook live-test status

The `[observer]` node hook is implemented (see
[`phase0-observer.md`](phase0-observer.md)) and passes unit and config
tests.

- Testnet run: **DONE** (2026-11-10, `testnet-hook` vantage). Verified
  live: `observer_start`, `announce` (`syncinfo_v2` with heights and
  `inv` tx), `request_sent`, `section_received` (solicited, with bytes),
  `tx_outcome` (`admitted` with fee, size, and `input_ids`), and
  `block_applied`. `header_validated` did **not** appear live because
  this node is the only active miner on testnet — every applied block is
  locally mined and never transits the peer header pipeline. The
  executor → observer wiring it needs is unit-tested:
  `ergo-sync` `executor::tests::validation_observer_fires_for_each_installed_header`
  (real mainnet header fixtures, single and batch paths, asserts the
  callback fires exactly once per installed header with the installed id
  and height).
- Mainnet run: **LIVE** (2026-11-10 15:29 local, `mainnet-hook` vantage).
  The mainnet node was restarted on a binary built from its current PR #694
  base (`f70bd07b`, nonP2pk API preserved) plus this branch's change set —
  the only delta is the Phase 0 work (observer hook + codec parity fixes).
  Verified: `observer_start`, `announce` flowing, peer ids join with the
  standalone observer and crawler (shared pseudonym key). `tx_outcome`,
  `block_applied`, and `header_validated` are expected to appear as mainnet
  blocks/txs flow. The standalone observer is running the minimum-48h
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
