# Logging — contract & operator guide

The node logs via `tracing` only. There are three distinct jobs, kept
separate by design:

1. **Liveness** — one `heartbeat tick` per minute when idle, at most one
   per 5 s while syncing. Answers "is it alive?"
2. **Forensics** — structured events with canonical fields. Answers
   "what exactly happened at T?"
3. **Attribution** — the minute-cadence `node_gauges` line plus
   Prometheus `/metrics`. Answers "which subsystem owns this?"

Spam is structurally prevented: repeating lines are rate-floored
(heartbeat), deduplicated (peer REST-url rejection warns once per peer+URL),
or moved behind level filters.

## Canonical fields

Never parse ids out of message text; select on fields.

| field | meaning |
|---|---|
| `peer` | remote peer SocketAddr |
| `height` | block height |
| `block` / `section` / `tx` / `box` | full hex ids |
| `section_type` | 102 = transactions, 104 = ADProofs, 108 = extension |
| `code` | stable machine-readable reason (`ad_proofs_mismatch`, …) |

Message text is a short verb phrase; all data lives in fields.

## Level contract

| level | operator meaning | examples |
|---|---|---|
| ERROR | act now | task died, storage failing, checkpoint mismatch |
| WARN | degraded but surviving | peer penalized, retry scheduled, REST url rejected (first sight) |
| INFO | milestone an operator wants in a timeline | tip advanced, config loaded, peer added, candidate accepted |
| DEBUG | mechanics for support | section persisted, request dispatched, parent-walk steps |
| TRACE | firehose | per-input script reduction detail |

## Configuration

```toml
[logging]
default_level = "info"          # used when RUST_LOG is unset

# Per-module overrides (validated at load):
[logging.modules]
"ergo_sync::executor" = "debug"
"ergo_p2p::delivery"  = "trace"
"ergo_node::node::events" = "warn"

[logging.file]
dir       = "<data_dir>/logs"   # default
prefix    = "ergo-node"
rotation  = "daily"
max_files = 14
format    = "json"              # default: machine-queryable archive
```

- `RUST_LOG` **overrides everything** when set.
- Console layer follows `[logging] format` (`text` default); the **file
  sink defaults to `json`** — one object per event, including span
  context. Point Loki/Splunk/`jq` at it.
- The file sink is non-lossy by design: under pressure writers block
  rather than drop events (forensics over throughput).

## Dashboard activity and logs

Open **Activity & logs** from the node workspace. Current conditions are read
from node status and indexer status; they remain visible independently of history
filters. A stale or unreachable status is labelled as unconfirmed. A log error
is an occurrence, not proof of an ongoing failure. A block rejection is shown
as recovered only once applied blocks advance beyond its known nonzero height.

Authorize with the operator `api_key` to inspect structured log history. The
default view shows warnings, errors and explicit recovery events; choose **All
severities** for other INFO milestones. Search messages, codes, peers and block
IDs, filter by subsystem/time, and expand a group for evidence. Opening a group
or changing history pages pauses the list so new arrivals cannot move the item
being inspected. Current conditions continue refreshing. Resume to see new logs.

Matching records within five minutes are grouped conservatively by target,
severity, message and structured fields (including inherited span identity).
Only timing and retry counters are excluded from the key; original values remain
in every retained record. Distinct peers, blocks, reasons, lifecycle transitions,
truncated records and backwards clock changes stay separate. Counts refer to
the retained matching records, never lifetime incident totals. Copy/download
exports newline-delimited JSON with all matching occurrences and their session,
filter, retention and current-status context.

The node keeps at most **2,048 records / 4 MiB** in memory, independently of open
browsers. This history resets on node restart; the existing rotated file logs
and incident snapshots are the durable archive. The page announces restarts,
eviction gaps, capture contention losses and shortened fields. INFO/WARN/ERROR
are captured; DEBUG/TRACE remain in configured log sinks. Messages are capped at
2,048 UTF-8 bytes plus a truncation marker; up to 32 scalar fields shortened at
1,024 bytes each are retained. Named
credential fields are redacted; free-form messages and operational data may
still be sensitive. Logs are never stored in browser local/session storage.
Clearing/changing authorization or leaving the page clears the browser evidence.

`GET /api/v1/diagnostics/activity` is always operator-key gated (including when
no write/admin handle is configured), fails closed without a configured key and
returns `Cache-Control: no-store`. It does not read arbitrary files. Query:

- `limit`: 1–500, default 256; records are oldest first.
- `since`: exclusive decimal sequence cursor, default 0. A nonzero cursor must
  include `session` from the previous response. Sequence values in JSON are
  decimal strings, preserving exact values in JavaScript.
- Continue from **`nextSeq`**, not `latestSeq`, while `hasMore` is true.
- A session mismatch or future cursor sets `reset` and starts from the retained
  beginning. `gap` means records requested by the cursor were evicted.
- `oldestSeq`, `retained`, `capacity`, `byteCapacity` describe retention;
  `droppedTotal` counts capture losses due to contention. An unavailable/busy
  capture buffer returns 503, never a fabricated empty successful history.

The capture path does not wait on readers or perform disk I/O. Successful status
publications also emit `code="node_condition"` transitions for peer connectivity,
sync stalls and block-rejection recovery. These transitions enter ordinary file
logs as well; elapsed time or missing rejection evidence never clears a rejection.

### Development checks

`node --test ergo-api/web/tests/*.test.mjs` includes the history, grouping,
filtering, retention and evidence tests. The optional
`node ergo-api/web/tests/activity.browser.cjs` uses Playwright with isolated
fixture APIs (no live node or external requests). Make Playwright resolvable
through the normal Node module path and install its Chromium browser, or set
`BROWSER_CHANNEL=msedge` to use an installed Edge. Screenshots go to a temporary
directory unless `ACTIVITY_SCREENSHOT_DIR` is set. It checks keyboard inspection,
pause/time-window behavior, auth changes, late responses, restarts, exports,
stale status, safe text rendering and narrow layouts.

## Forensics recipes

```bash
# Full lifecycle of one block (JSON file log):
jq 'select(.fields.block == "7c7587…")' logs/ergo-node.$(date +%F).log

# Everything a misbehaving peer emitted:
jq 'select(.fields.peer == "1.2.3.4:9030")' logs/ergo-node.*.log

# All rejections with reasons:
jq 'select(.level=="WARN" or .level=="ERROR)' | jq -r '.fields.code // .message'
```

## Spans (phase 2)

The block pipeline is instrumented: `pre_validate_header`,
`process_block_utxo`, `handle_assemble_block`, and `on_sync_info` open
spans carrying the canonical fields (`block`, `height`, `peer`). The
JSON file layer embeds current-span + span-list on every event inside
them, so one jq select on `.fields.block` returns a block's whole
story. Wallet lifecycle (`unlocked` / `locked` / unlock failure) and
mining solution verdicts log at INFO; handshake completions and seed
checks at DEBUG.

## Incident snapshots

On the first ERROR with a given code (5-minute dedupe window per code),
the node writes `<data_dir>/incidents/incident-<ts>-<seq>.json`: the
last ~500 structured events, latest subsystem gauges, RSS KiB, and build
version in one attachable file. Newest 10 retained. Attach it verbatim
to bug reports — it is the fastest path to diagnosis.

## Chatter ledger (triage decisions)

| line | disposition |
|---|---|
| `heartbeat tick` | floored: ≥5 s during progress, 60 s idle |
| `peer REST url rejected` | warn once per (peer, URL), repeats at debug |
| `declared address differs from observed` | known-repeat candidate; accepted noise until gauges land (#259 follow-up) |
| `chain progress` during IBD | kept at INFO — primary sync milestone |

New log sites must be reviewed against the level contract above.
