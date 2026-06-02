# Scala-anchored ergo-p2p wire vectors

`.hex` files in this tree are byte-for-byte fixtures the Rust
`ergo-p2p` framing + payload codecs are asserted against. The
authoritative oracle for each vector is a Scala-side test in
`org.ergoplatform.network.*Specification`, where the same hex string
appears as a literal `bsString shouldBe "..."` assertion against
`MessageSerializer.serialize(...)` output. Those tests are explicitly
marked "test vector for external implementations" — the upstream
project treats them as the contract third-party (re-)implementations
must match.

## Provenance

| File | Scala source | Logical content |
|------|--------------|-----------------|
| `inv/header_single_mainnet.hex` | `network/InvSpecification.scala:37` | `Inv` (code 55) advertising one header id `[1x16, 2x16]`. Mainnet magic `01 00 02 04`. |
| `request_modifier/header_single_mainnet.hex` | `network/RequestModifiersSpecification.scala:38` | `RequestModifier` (code 22). **Same `InvData` payload as the Inv vector** — codec is shared; only the frame `code` differs (0x16 vs 0x37) and the modifier-bytes are identical. Mainnet magic. |
| `sync_info/v1_single_header_mainnet.hex` | `network/ErgoSyncInfoSpecification.scala:38` | `SyncInfo` V1 (code 65) carrying one header id `[1x16, 2x16]`. Mainnet magic. Confirms the count field is VLQ (`0x01`), not raw `u16`. |
| `modifiers/header_single_mainnet.hex` | `network/ModifiersSpecification.scala:34` | `Modifiers` (code 33) wrapping one Block-Header modifier (264-byte fixture from `HeaderSerializer.parseBytes` of `4201ad7f…`). Exercises the `(type, count, [(id, len, bytes)])` payload shape end-to-end. |
| `sync_info/v2_single_header_payload.hex` | `ergo-core/.../network/history/ErgoSyncInfo.scala:60-74` (manual transcription, **not** an upstream byte fixture) | `SyncInfo` V2 **payload only** carrying one 225-byte header (same body as the `modifiers` fixture). Byte layout `00 FF 01 E1 01 || body` derived directly from `ErgoSyncInfoSerializer.serialize`'s V2 case. The upstream `ErgoSyncInfoSpecification` only tests V1; this entry is the strongest V2 oracle available without adding a Scala-side byte fixture. |

The fixtures above are **full frames** (magic + code + length + checksum
+ payload). The Rust oracle test at
[`ergo-p2p/tests/wire_vectors_oracle.rs`](../../ergo-p2p/tests/wire_vectors_oracle.rs)
decodes them through the framing layer first, validates the
checksum, hands the payload to the per-message deserializer, then
re-serializes + re-frames and asserts byte-identical roundtrip.

## How to regenerate / extend

The Scala node has a deterministic per-message serializer test
infrastructure under `src/test/scala/org/ergoplatform/network/`. To
capture additional vectors:

1. Add a property in the relevant `*Specification.scala` that
   constructs the desired `Message[T]` value, runs
   `new MessageSerializer(Seq(spec), magic).serialize(m).toArray`,
   and asserts the hex via `Base16.encode(bs) shouldBe "..."`.
2. Run `sbt "testOnly org.ergoplatform.network.<Spec>Specification"`
   in the Scala repo. The first run will fail and print the actual
   hex; copy it into the `shouldBe`. Re-run to confirm green.
3. Save the hex into a new `.hex` file under
   `test-vectors/ergo-p2p/<message_kind>/<scenario>_<network>.hex`.
4. Add a row above documenting Scala source file + line.
5. Add a test in `wire_vectors_oracle.rs` decoding + roundtripping
   the new vector.

`sbt` is **not** required to consume the vectors — only to add
new ones. The existing oracle test runs on stable Rust + the
files in this tree.

## Vectors not in this tree (follow-ups)

These would round out the Scala-oracle coverage but require
Scala-side test additions in the upstream repo (the existing
`Specification.scala` files don't have hex fixtures for them):

- `sync_info/v2_*` upstream byte fixture — the V2 payload at
  `v2_single_header_payload.hex` is Scala-source-derived rather
  than upstream-test-derived. A real `bsString shouldBe "…"`
  assertion in Scala's `ErgoSyncInfoSpecification` would lift it
  to oracle-grade.
- `handshake/*` — Scala `HandshakeSerializer` has no test-source
  byte fixture. Live capture is brittle (timestamp, session id,
  node name, version are volatile).
- `snapshots_info/*` — `SnapshotsInfoSpecification` covers data
  shape but not wire bytes. Manual derivation from
  `BasicMessagesRepo.scala:93-99` is still the strongest provenance
  available; the inline `mod tests` assertions in
  `ergo-p2p/src/message.rs` mark this explicitly.
- `manifest/*`, `get_manifest/*`, `nipopow/*` — same status:
  serializer is in `BasicMessagesRepo.scala`, no upstream byte
  fixtures.

Adding these requires opening a Scala-side PR to add the byte
assertion (or, for handshake, parameterising the serializer to
take fixed timestamp + session-id constants). Tracked as a
post-Phase-10 follow-up.
