# Operator events — the frozen vocabulary

The node pushes typed events on two surfaces backed by ONE producer chain:

- **`GET /api/v1/events`** — the poll/backfill twin: a bounded coarse ring
  (seq-keyed, `?since=` filtering strictly greater).
- **`GET /api/v1/ws`** — the realtime WebSocket bus: subscribe / resume /
  backfill with per-channel filtering.

The REST ring and the WebSocket bus are two views over the same
snapshot-diff producer chain — one differ derives the events, both surfaces
serve them — so a consumer can mix them (poll to catch up, subscribe to
stay current) without seeing contradictory histories. This page freezes the vocabulary: kinds, channels, required
fields, and sequence semantics. Additions are backward-compatible (new kinds
/ new optional fields); renames and removals are breaking and will not
happen casually.

## Coarse feed kinds (`GET /api/v1/events`)

Every entry carries `seq` (monotonic, session-scoped), `unixMs`, `kind`,
plus kind-specific fields. Absent optionals are omitted, never null.

| `kind` | Fields | Meaning |
|---|---|---|
| `blockApplied` | `height`, `headerId`, `txs`, `sizeBytes` | A full block reached the committed tip. |
| `reorg` | `height`, `headerId`, `depth`, `droppedHeaderIds`, `returnedTxIds` (≤128), `returnedTxsTotal`, `deliveredBy?` | Tip replaced. Orphan ids are best-effort from the 32-block committed tail; returned txs and the winning-tip deliverer come from the tip-change diff. |
| `peerConnected` / `peerDisconnected` | `addr` | Handshaked peer set changed. |
| `indexerStatus` | `detail` | Extra-index status transition (incl. halt reason). |
| `syncWedged` | `height`, `headerId` | Terminal deep-fork wedge — the network's chain forks below the rollback window. One event per distinct stuck tip. |
| `shadowDivergence` | `height`, `detail` (`header_mismatch ours=… theirs=…` or `tip_stall`) | Shadow validation confirmed a divergence vs the configured reference node. One event per incident. |

Ring caps: newest-4 block events and 16 peer events per tick; the ring is a
glanceable, not an audit log — durable signals live on `/metrics` and
`/api/v1/node/status` (e.g. a `shadowDivergence` may age out of the ring
under heavy block flow while `ergo_node_shadow_diverged` stays latched).

## WebSocket channels (`GET /api/v1/ws`)

Subscribe with `{"op":"subscribe","channels":[…]}`. Channels:

| Channel | Live | Events |
|---|---|---|
| `blocks` | yes | `block_applied`, `reorg` |
| `mempool` | yes | `tx_accepted`, `tx_dropped` |
| `peers` | yes | `peer_connected`, `peer_disconnected` |
| `tx:<id>` | yes (terminal) | `tx_confirmed` — fires once, then the channel auto-unsubscribes (`reason:"fulfilled"`). |
| `box:<id>` | yes (terminal) | `box_spent` — same terminal semantics. |
| `address:<addr>` / `token:<id>` | **not yet** | Subscribing answers `channel_unavailable` — the fine-grained node-internals taps are the remaining workstream-A item. |

WS event payloads use the same field vocabulary as the coarse feed (the
`reorg` payload is identical field-for-field).

## Sequence + resume semantics

- Every bus event has a global, monotonically increasing `seq`
  (session-scoped; resets on restart — persist nothing across a `welcome`
  with a lower `latest_seq` than you remember).
- `{"op":"resume","since":<seq>,"channels":[…]}` replays retained events
  with `seq > since` that match your channels, oldest-first, capped at
  **1024** per resume. More retained than the cap ⇒ the server answers
  `resync` instead of a partial replay — treat it as "re-read via REST,
  then subscribe fresh".
- The bus retains the last **8192** events. `since` older than the window ⇒
  `resync` with `gap:true`.
- Delivery is exactly-once per socket across the replay/live seam
  (server-side seq watermark).

## Transport limits

- Frames over **64 KiB** are rejected.
- The server emits a `heartbeat` frame every **15 s**. The client must
  produce SOME inbound within the idle window of **2× the interval
  (~30 s)** — a protocol `{"op":"ping"}` frame or a WebSocket-level
  ping/pong both count — or the server closes the socket with
  `idle_timeout`. (`{"op":"ping"}` is the idiomatic keepalive: it also
  returns `pong` with the current `latest_seq`.)
- Per-IP socket caps and a per-socket control-frame rate limit answer
  `rate_limited`.
- Slow consumers are never buffered unboundedly: the per-socket queue drops
  and the socket closes with `slow_consumer` — reconnect and resume.
