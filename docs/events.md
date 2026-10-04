# Operator events — the frozen vocabulary

The node publishes coarse operator events and fine-grained changes:

- **`GET /api/v1/events`** — the poll/backfill twin: a bounded coarse ring
  (seq-keyed, `?since=` filtering strictly greater).
- **`GET /api/v1/ws`** — the realtime WebSocket bus: subscribe / resume /
  backfill with per-channel filtering.
- **`GET /api/v1/events/replay`** — paginated history of that same realtime
  bus, including recovered records, with persistence watermarks and gap flags.

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

Rollback inverses exist only for rollbacks observed while the relevant live
feed is active. Rollbacks during downtime do not generate inverses on restart,
and `tx_confirmed` has no inverse event. Reconcile transaction and chain state
from REST after downtime even if retained replay reports no cursor gap.

These feeds follow successful indexer commits and may trail the consensus tip
or replay an indexer catch-up interval. The payload height names the indexed
change. They are bounded observations, not a chain audit log: boot catch-up
before API activation and changes outside retained undo history are not
fabricated. Reorg events include `previous_seq` only when this observer
published the original and retains it in its bounded recent-event ledger.
The ledger holds at most 8192 entries and prunes against the bus cursor;
otherwise `previous_seq` is null. Concurrent publishers can advance bus
retention between lookup and inverse publication, so the link does not
guarantee the original is still backfillable. Match retractions by
box/token/transaction/header identity when rebuilding
from REST. Slow consumers use the same bounded drop/close policy as other
classes; they never hold an indexer commit open. The shared bus is a bounded source; durable webhook delivery begins at
successful admission. Its worker catches up from retained observations after
subscriber queue overflow or restart. A full pending-delivery ring stops the
admission cursor until space returns. Expired or uncertain source history
first admits the contiguous retained prefix, then pauses affected subscriptions
with `auto_disabled_reason: source_gap`; hooks registered after the missing
interval remain active. Reconcile
from REST before explicitly re-enabling them. Confirmed-only hooks still
receive `box_reverted`, `box_unspent`, and `token_reverted` invalidations,
including `previous_seq` and `height` when available.

Protocol genesis boxes are not extra-index rows, so their first spends do not
produce these box/token observations.

## Sequence + resume semantics

- Every bus event has a global, monotonically increasing `seq`. Production
  restores retained realtime records from `webhooks.redb` before activating
  publishers. Orderly shutdown drains the journal and releases unused cursor
  reservations. A crash preserves the reserved upper cursor boundary, so
  unconfirmed cursors are never reused; the uncertain interval becomes a gap.
  The journal is asynchronous: a live event or its publish cursor alone does
  **not** acknowledge durable persistence. Reconcile after a gap and discard
  an old cursor if it is ahead of this data directory's latest cursor.
- The journal queue holds **8192** observations as shared references. A
  dedicated thread drains everything available, bounded to the queue size plus
  its first observation, per commit. Publishing and indexer commits never wait
  for disk. Overflow or a storage error can lose restart history. A write error
  is logged once and stops persistence until restart; failed batches, pending
  entries and subsequent observations are counted as losses. Live delivery
  continues within the boot epoch reserved before publishers start: **2^40**
  cursors (about 1.1 trillion). That capacity limit is independent of disk health.
  A failed epoch stays reserved across shutdown, exposing a restart gap.
- Durable history retains at most **8192** events and **64 MiB** of encoded
  records, evicting oldest first. A single encoded record over **1 MiB** stops
  journal persistence rather than growing the store without a bound. The live
  resume ring retains at most **8192** events; recovered history may be smaller
  because of the byte limit.
- `{"op":"resume","since":<seq>,"channels":[…]}` replays retained events
  with `seq > since` that match your channels, oldest-first, capped at
  **1024** per resume. More retained than the cap ⇒ the server answers
  `resync` instead of a partial replay — treat it as "re-read via REST,
  then subscribe fresh".
- The bus retains the last **8192** events. `since` older than the window ⇒
  `resync` with `gap:true`.
- Delivery is exactly-once per socket across the replay/live seam
  (server-side seq watermark).

## Polling realtime history

```bash
curl 'http://127.0.0.1:9099/api/v1/events/replay?channels=blocks,mempool&since=0&limit=100'
```

`channels` uses the same selector grammar as WebSocket subscriptions, with
1–64 comma-separated keys. Historical indexed records are readable even when
the current indexer writer is disabled. `limit` is 1–1024, default 100;
`since` is an exclusive bus cursor, default 0. Invalid or future cursors return
400. This public read carries the shared heavy-read governor.

The response contains oldest-first `events`, `oldest_seq`, `latest_seq`,
`next_seq`, `has_more`, `gap`, and `persistence`. Each event preserves its
`routes`, `seq`, `event`, `confirmed`, `height`, `data`, `previous_seq`, and
source timestamp. Continue with `since=next_seq`, including after an empty
page; filtered-out observations still advance the cursor. `has_more` allows
REST clients to page past the WebSocket resume limit without pretending a
partial page is complete. A true `gap` requires reconciliation from current
REST state even if the page contains useful records.

`persistence` is null when no durable store is installed. Otherwise it reports:

- `committed_seq`: largest record cursor confirmed committed. Earlier missing
  observations are still possible; this is not a contiguous acknowledgement.
- `complete_from_seq`: exclusive start of the latest contiguous committed
  segment. A crash interval or legacy webhook cursor starts a new segment.
- `complete_through_seq`: every cursor after `complete_from_seq` through this
  boundary is committed. Equal boundaries describe an empty segment. This
  watermark continues advancing after a gap; inspect `gap` for older missing
  intervals and expired retention.
- `dropped_events`: observations lost by journal admission or failed writes this session.
- `available`: whether journal persistence is currently operating.

Records above the confirmed boundary can be live-only. When notification
cursors cannot be loaded or reserved safely, the boot log reports that API
startup is disabled; the node and wallet continue running. There is no session
fallback that could reuse durable cursors. Webhooks alone are disabled if their
registry cannot be restored but the replay journal initializes successfully. Back up
`webhooks.redb` with the other operator databases, preserving its private
permissions because it also contains signing secrets.

New webhook registrations record the bus boundary inside their serialized
management operation, so replay does not send them observations from before
registration. Previously admitted deliveries retain their IDs, bodies and
retry deadlines across restart; receivers must deduplicate the delivery ID
because an unknown HTTP acknowledgement can still be retried. Admission is
atomic for all hooks matching an event, and a catch-up page commits once.
Unmatched observations advance the admission cursor in memory; active hooks
checkpoint skips after at most 1024 observations or five seconds. No active
hooks means no catch-up checkpoint write.

Before downgrading to a binary predating persistent operator replay, reconcile
REST state and explicitly re-enable every subscription marked `source_gap`
using the current binary. The old snapshot reader cannot decode this new reason;
a downgrade with any such marker disables the webhook subsystem when loading
the registry. Re-enabling clears the marker durably. If reconciliation is not
possible, keep the current binary and retain the paused subscriptions. Back up
`webhooks.redb` before changing versions; do not replace it with a fresh file to
bypass this compatibility check. A pre-replay binary does not preserve the new
journal cursor contract; discard replay cursors and reconcile REST state across
a downgrade.

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
