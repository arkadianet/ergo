# Evidence: pre-`85c1b052` parser vs new-format SessionId bodies

Provenance for the "old Rust parser on new-format SessionId bodies" check
(pre-14:02 verification task 2).

- `output-at-06b44bdd.txt` — per-case verdict table from running the
  evidence test against a worktree detached at `06b44bdd` (the commit
  just before the SessionId VLQ+zigzag fix in `85c1b052`). The evidence
  test itself was never committed; it called the *pre-fix*
  `ergo_p2p::handshake::deserialize_handshake` and only compiles against
  that commit. Its logic is reconstructable from the current
  `ergo-p2p/tests/it/sid_cross_compat.rs` (same 20 bodies, same helpers)
  plus the old parser behavior described below (fixed 8-byte big-endian
  read of the first 8 VLQ bytes).

Verdict (20 bodies: 16 synthetic new-format with 1–10-byte VLQ ids, plus
4 captured live bodies — 3 new-format mainnet/testnet peers and 1 old
12-byte big-endian body from our own pre-fix mainnet node):

- **0 rejections.** The old parser never rejects a new-format SessionId
  body.
- Body < 12 bytes (VLQ 1–7 bytes): accepted, but the feature is downgraded
  to `Unknown { feature_id: 3 }` (body preserved, feature dropped) — the
  old code only treated the body as a SessionId when it was at least
  12 bytes.
- Body ≥ 12 bytes: accepted as `SessionId`, and **7 of the 8** carried a
  *silently mis-decoded* id: the old code read the first 8 bytes of the
  VLQ+zigzag stream as a fixed 8-byte big-endian `i64`.

The fixed codec keeps the captured old 12-byte big-endian body verbatim as
`Unknown` (handshake accepted). Other old bodies can decode differently:
an eight-byte id that is also a complete VLQ, such as
`81 81 81 81 81 81 81 01`, parses as a `SessionId` with a different
value — so neither generation rejects the other's handshakes, they just
fail to self-identify each other until both sides run the fixed codec.
The fixed-codec counterpart is `ergo-p2p/tests/it/sid_cross_compat.rs`
(same 20 bodies: 0 rejections, 19 exact `SessionId`, 1 verbatim
`Unknown`).
