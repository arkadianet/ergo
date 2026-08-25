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
