# Operator events — the frozen vocabulary

The node publishes coarse operator events and fine-grained changes:

- **`GET /api/v1/events`** — the poll/backfill twin: a bounded coarse ring
  (seq-keyed, `?since=` filtering strictly greater).
- **`GET /api/v1/ws`** — the realtime WebSocket bus: subscribe / resume /
  backfill with per-channel filtering.

Block/reorg/peer events share the snapshot-diff producer across the REST ring
and WebSocket bus. Mempool and committed extra-index changes feed that bus
directly; webhooks consume it too. REST-ring cursors and bus cursors are
independent, so reconcile observations by their block or transaction identity
rather than exchanging sequence numbers between surfaces. This page freezes
kinds, channels, required fields and sequence semantics. New kinds and optional
fields are backward-compatible additions.

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

The dashboard's **Activity & logs** page also provides the separate operator-key
protected structured log history at `GET /api/v1/diagnostics/activity`. Its
session/cursor and retention contract is documented in [Logging](logging.md#dashboard-activity-and-logs).
It does not share coarse-feed or WebSocket sequence numbers. The public coarse
feed remains unchanged.

## WebSocket channels (`GET /api/v1/ws`)

Subscribe with `{"op":"subscribe","channels":[…]}`. Channels:

| Channel | Live | Events |
|---|---|---|
| `blocks` | yes | `block_applied`, `reorg` |
| `mempool` | yes | `tx_accepted`, `tx_dropped`, `tx_confirmed` |
| `peers` | yes | `peer_connected`, `peer_disconnected` |
| `tx:<id>` | yes (terminal) | `tx_confirmed` or `tx_dropped` fulfills the subscription. |
| `box:<id>` | with a live indexer observer | `box_spent` fulfills; `box_unspent` after resubscribing does not. |
| `address:<addr>` | with a live indexer observer | `box_created`, `box_spent`, `box_reverted`, `box_unspent` |
| `token:<id>` | with a live indexer observer | `token_moved`, `token_reverted` |

WS event payloads use the v1 REST field vocabulary (`reorg` is identical to
its coarse counterpart). Indexer-backed classes are enabled only after an
actual writer observer is installed and the API has bound successfully;
disabled indexers and boot failures without a backing store answer
`channel_unavailable`, even when a status/query handle exists. Availability
follows the installed writer: a later indexer halt keeps these classes enabled
but stops new changes; inspect indexer status to distinguish halt from an idle
feed. API-disabled nodes do not capture typed changes.

Box events reuse the canonical v1 box projection, with `header_id` added for
the block creating, spending or reversing the change. `tx_id` remains the
creating transaction; `spent_by` identifies the spending transaction. Creation
and its retraction route to `address:`; spending and restoration route to both
`address:` and `box:`. A retracted creation clears `confirmed`,
`inclusion_height`, `confirmations` and `global_index` on the box DTO. Its
original block height is still in the event envelope. A terminal box client
must resubscribe to observe a later restoration; only the next `box_spent`
fulfills that renewed subscription. Restored box confirmations use the
committed height after the orphan block was removed.

Token events are per asset per box, including mint outputs. They carry
`token_id`, decimal-string `amount`, `direction`, `tx_id` (the creating/spending
transaction for this change), `header_id`, `box_id`, and `address`. Direction
`in` adds this box's assets to the owner's indexed unspent set; `out` removes
them. Transfers normally produce a spent `out` and a created `in`, possibly at
the same address. Reorg inverses use `token_reverted` with the opposite
direction and `confirmed:false`; amount is positive in either direction. Mint
and burn amounts can therefore appear without an opposite pair.

These feeds follow successful indexer commits and may trail the consensus tip
or replay an indexer catch-up interval. The payload height names the indexed
change. They are current-session observations, not an audit log: boot catch-up
before API activation and changes outside retained undo history are not
fabricated. Reorg events include `previous_seq` only when this observer
published the original and retains it in its bounded recent-event ledger.
The ledger holds at most 8192 entries and prunes against the bus cursor;
otherwise `previous_seq` is null. Concurrent publishers can advance bus
retention between lookup and inverse publication, so the link does not
guarantee the original is still backfillable. Match retractions by
box/token/transaction/header identity when rebuilding
from REST. Slow consumers use the same bounded drop/close policy as other
classes; they never hold an indexer commit open. The shared bus is a bounded
best-effort source; durable webhook delivery begins at successful enqueue,
not at every source change.

Protocol genesis boxes are not extra-index rows, so their first spends do not
produce these box/token observations.

## Sequence + resume semantics

- Every bus event has a global, monotonically increasing `seq`
  within one node session. On restart, the bus starts above event cursors
  retained in durable webhook deliveries when that store is available; the
  event backfill itself is not persisted. A cursor can therefore reset or
  skip historical events. Reconcile from REST after a restart or resume gap,
  and discard an old cursor when `welcome.latest_seq` is lower.
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
