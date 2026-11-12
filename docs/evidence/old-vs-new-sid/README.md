# Evidence: pre-`85c1b052` parser vs new-format SessionId bodies

Provenance for the "old Rust parser on new-format SessionId bodies" check
(pre-14:02 verification task 2).

- `old_vs_new_sid.rs` — the evidence test, copied verbatim from the
  temporary worktree that was detached at `06b44bdd` (the commit just
  before the SessionId VLQ+zigzag fix in `85c1b052`). It calls the
  *pre-fix* `ergo_p2p::handshake::deserialize_handshake`, so it only
  compiles against that commit; it is kept here as an artifact, not
  built by the current tree.
- `output-at-06b44bdd.txt` — full `--nocapture` output of that test, run
  in the worktree.

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

This is symmetric with the fixed codec's handling of the old 12-byte
big-endian body (preserved verbatim as `Unknown`, handshake accepted), so
neither generation bans or drops the other's peers — they just fail to
self-identify each other. The fixed-codec counterpart that does compile at
branch head is `ergo-p2p/tests/it/sid_cross_compat.rs` (same 20 bodies:
0 rejections, 19 exact `SessionId`, 1 verbatim `Unknown`).
