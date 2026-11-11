# Phase 0 network observer

`ergo-net-observe` is the Phase 0 measurement tool. The `observer` binary is
an honest, read-mostly legacy peer: it performs the same unframed handshake
as the node, speaks only ordinary legacy messages (`GetPeers`, `SyncInfo`,
`Inv`, `RequestModifier`, `Modifiers`), and writes line-delimited JSON
(`ergo-observer/1`) describing what it saw and when. The `crawler` binary
runs the same sessions plus a bounded, rate-limited discovery walk over
learned peer addresses (see [Crawler](#crawler)).

It is **not** a full node and makes no consensus claims. The schema and the
measurement limits below are deliberately explicit so downstream analysis
does not over-read the data. Open protocol questions are tracked in
[`unverified.md`](unverified.md); the code survey is in
[`survey.md`](survey.md).

## Honesty and safety rules

- **Truthful identity.** The handshake advertises the configured agent and
  node name (`ergo-rust-observer` / `ergo-rust-observer-phase0` by default),
  protocol version 6.0.7, no declared address, and no `Mode` feature. It
  never pretends to be a full node or claims chain state it does not have.
- **Bounded outbound.** Every session's sends pass a token bucket capped at
  **64 KiB/s** (`OUTBOUND_BYTES_PER_SEC` in `src/session.rs`), with at most
  4 unanswered requests per peer, at least 2 s between requests to one
  peer, and at most 64 ids per `RequestModifier`. A send that would exceed
  the bucket is dropped and logged, never queued. In practice the request
  pacing bounds a normal session to a few KiB/s, so the process-level
  egress of a multi-session observer or crawler stays modest.
- **No unsolicited traffic.** The observer never sends modifiers it did not
  request, never relays blocks or transactions, never mines, and answers
  `GetPeers` with an empty `Peers` list because it has no verified peers to
  share.
- **Local by default is refused.** Loopback, private, link-local, and
  unspecified peers require `--allow-local`, so a mistyped address cannot
  turn a production run into a scan of the host's own network.
- **Adversarial testing is offline.** No fuzzing or malformed-input probing
  is pointed at public peers. Parse/fuzz work uses `ergo-difftest` and a
  private JVM/Rust reference node.

## Running

Build:

```sh
cargo build -p ergo-net-observe --bin observer
```

Test against a **local testnet node first** (the node's P2P listener is
`:9022`; the observer needs `--allow-local`):

```sh
target/debug/observer \
  --network testnet \
  --peers 127.0.0.1:9022 \
  --allow-local \
  --vantage testnet-local \
  --out /var/lib/ergo-observer/testnet.jsonl \
  --pseudonym-key /var/lib/ergo-observer/testnet.key \
  --clock-source chrony \
  --duration-secs 60
```

Mainnet, using the network's seed peers:

```sh
target/debug/observer \
  --network mainnet \
  --vantage hetzner-1 \
  --out /var/lib/ergo-observer/mainnet.jsonl \
  --pseudonym-key /var/lib/ergo-observer/mainnet.key \
  --clock-source chrony \
  --max-peers 8
```

Stop with Ctrl-C or `--duration-secs`. On shutdown the runner aborts all
sessions, flushes the sink, and writes a final `gap` record if any records
were dropped under backpressure.

### Flags that change what is measured

| Flag | Default | Effect |
|---|---|---|
| `--network` | `mainnet` | Magic bytes and default seed list. |
| `--peers` / `--peers-file` | seed list | Explicit peer set; `host:port`, comma-separated or one per line. |
| `--out` | `observer.jsonl` | Append-only JSONL path. |
| `--vantage` | `local` | Operator label copied into every record. |
| `--clock-offset-ms`, `--clock-source` | `0`, `unset` | Wall-clock offset metadata; `chrony` reads `chronyc tracking`. |
| `--pseudonym-key` | `observer-pseudonym.key` | Keyed address pseudonymisation key (created mode 0600). |
| `--reveal-peer-addresses` | off | Emit raw IPs. Debugging only; do not publish such a file. |
| `--max-peers` | `8` | Concurrent sessions. |
| `--dial-spacing-secs` | `2` | Startup dial spacing. |
| `--request-headers` | on | Fetch announced headers. |
| `--request-bodies` | off | Fetch block transactions / AD proofs / extension sections. |
| `--request-txs` | off | Fetch announced mempool transactions. The standalone observer cannot validate them. |
| `--request-interval-secs`, `--max-outstanding`, `--max-ids-per-request` | `2`, `4`, `64` | Per-peer request pacing. |
| `--allow-local` | off | Permit loopback/private peers. |

## Record schema

Every line is one JSON object:

```json
{"schema":"ergo-observer/1","vantage":"testnet-local","wall_ms":1762742765546,
 "mono_ns":120034567,"clock_offset_ms":1.005,"clock_source":"chrony",
 "peer":{"id":"ed08ad4f...","agent":"ergo-rust","version":"6.0.7",
         "node_name":"arkadias-rust-testnet","direction":"out"},
 "block":{"header_id":"92c127eb...","height":634401},
 "event":"section_received","type_id":101,"id":"92c127eb...","bytes":220,
 "seq":0,"solicited":true,"height":634401,"id_matches":true}
```

- `mono_ns` is monotonic nanoseconds since process start and is the
  authoritative field for durations. `wall_ms` is for cross-host alignment
  only.
- `clock_offset_ms` / `clock_source` record the measured offset between
  local wall time and true time (positive means local is behind). They do
  not affect `mono_ns`.
- `peer.id` is a keyed Blake2b-256 pseudonym (first 16 bytes, hex) unless
  pseudonymisation is explicitly disabled. Raw addresses appear only with
  `--reveal-peer-addresses`.
- Transactions and header ids are public chain identifiers and are emitted
  in full.

Events:

| Event | Meaning |
|---|---|
| `observer_start` | Effective network, identity, peer count, request flags, outbound cap. |
| `conn_open` | TCP connect succeeded, handshake not yet complete. |
| `handshake_ok` / `handshake_fail` | Handshake parse result; `handshake_ok` carries the peer's claimed version, agent, node name, feature labels, and handshake time. Feature **labels only** — feature values are never recorded (see [Dataset notes](#dataset-notes)). Capture runs only: `handshake_ok` may carry `peer_handshake_hex` and `handshake_fail` may carry `received_hex` (raw peer bytes, for offline replay). |
| `announce` | Peer sent `Inv` (`via: inv`) or `SyncInfo` (`syncinfo_v1` / `syncinfo_v2`). `first_global` counts ids never seen by this observer; `first_for_peer` counts ids new from this peer. V2 announces include header bytes, so `heights` is populated. |
| `request_sent` | We sent `RequestModifier` with sequence `seq`. |
| `section_received` | A `Modifiers` entry arrived. For headers, `height`, `computed_id`, and `id_matches` compare `Blake2b256(bytes)` with the claimed id. |
| `rtt` | Request-to-first-matching-section latency, one sample per completed request id. |
| `tx_outcome` | Mempool result. The standalone observer emits `result: unavailable` (it does not validate); the node hook emits `admitted` / `rejected` with a reason. |
| `peer_gossip` | A `Peers` reply, with pseudonymised addresses and claimed identity. |
| `dial_attempt` | Crawler only: one completed dial at a seed or learned address (`peer` is the target). `outcome` is `handshaken`, `handshake_fail`, `connect_refused`, or `connect_timeout`; `retries` is the consecutive-failure count before this attempt; `via` is the pseudonym of the gossiping peer (`seed` for seeds). Emitted when the outcome is known: connect outcomes immediately, handshake outcomes at handshake completion (not at session end). |
| `peer_learned` | Crawler only: an address newly learned from a `Peers` reply and queued for dialing (`peer` is the learned address, `via` the gossiping peer). |
| `get_peers_received` | A peer asked us for peers; we answered honestly with an empty list. |
| `request_received` | A peer asked us for modifiers. We cannot serve them and do not pretend to. |
| `disconnect` | Session ended, with reason and lifetime. |
| `observer_gap` | The bounded sink dropped records; `dropped` is the count since the previous successful line. Renamed from `gap` on 2026-11-11 — no records named `gap` exist in the dataset, so the rename is lossless. This structured event is the **sole gap indicator**; do not infer gaps from log text. |
| `note` | Parse warning or unsupported message. |

The node-only events `header_validated` and `block_applied` are defined in
the same schema and are emitted by the gated node hook, not by the
standalone observer.

## What the data can and cannot show

- **Announce time is a lower bound on the peer's knowledge.** A peer stamps
  an `Inv`/`SyncInfo` when it sends it; it may have validated the block much
  earlier.
- **Per-hop delay is not observable** from one host. We can compare
  per-peer announce delay and first-arrival order, not the path from the
  miner.
- **Reachability is dial-based.** `handshake_ok` means this vantage
  completed a handshake within the timeout; it does not prove reachability
  from elsewhere.
- **One vantage is one slice.** The report must state connection count,
  peer set, and location. Network-wide claims wait for the second vantage.
- **Clock discipline matters.** Use `--clock-source chrony` and keep NTP
  healthy; `mono_ns` protects durations from wall-clock steps, but
  cross-host alignment depends on wall time.

## Crawler

The `crawler` binary runs the same honest sessions as the `observer` plus a
bounded discovery walk: live sessions forward the declared addresses from
their `Peers` replies to a shared frontier, and idle slots dial queued
addresses. It never relays blocks or transactions, never claims a state
mode, and answers `GetPeers` with an empty list, exactly like the observer.

Boundedness rules (all enforced in-process):

- **Global dial cap.** At most `--dial-rate` (default 12) *new* dials per
  minute across all slots.
- **Per-address exponential retry backoff.** A failed dial doubles the
  retry delay from `--backoff-min-secs` (default 60 s) to
  `--backoff-max-secs` (default 6 h); a completed handshake resets it.
- **Frontier cap.** At most 200 000 tracked addresses; the oldest
  non-in-flight entry is evicted at the cap.
- **Local addresses skipped.** Learned loopback / private / link-local
  addresses are dropped unless `--allow-local` (lab use).
- **Session pacing** is the same as the observer: 64 KiB/s per-session
  outbound bucket, 2 s per-peer request interval, 4 outstanding requests,
  64 ids per request, headers only.

The dial outcome is recorded as soon as it is known: connect outcomes
immediately, handshake outcomes at handshake completion — not at session
end — so `dial_attempt` is not delayed by the session idle timeout.

State (`--state` path, default: none) persists the frontier every 60 s via
atomic tmp+rename, mode 0600, and is reloaded on start (surviving backoff
and in-flight state across restarts). **The state file contains raw peer
addresses: it is operator-local and must never be published**, like the
pseudonymisation key. For dataset joinability, the crawler deployment
reuses the same pseudonymisation key as the standalone observer of the
same network.

### Handshake capture (offline analysis only)

`--capture-handshake-hex` additionally records the peer's raw handshake
bytes as hex on the handshake records (`peer_handshake_hex` on
`handshake_ok`, `received_hex` on `handshake_fail` when at least one
byte arrived), closes each session immediately after the handshake
(capture-only mode — otherwise a chatty peer would pin its dial slot
for the whole idle timeout), and, with `--capture-max N`, stops the
crawl after N captured byte sequences (completed handshakes plus
failures that received bytes). The bytes feed the offline
`replay-captures` tool, which re-parses them through the current codec
to quantify strict-parse versus Unknown-preservation rates and
accept/reject deltas. Capture runs must use a separate output file and
state file — these fields are never present in the standing dataset
streams.

```sh
target/debug/crawler \
  --network mainnet \
  --peers-file peers.txt \
  --vantage hetzner-1-crawler \
  --out /var/lib/ergo-observer/mainnet-crawl.jsonl \
  --state /var/lib/ergo-observer/mainnet-crawl-state.json \
  --pseudonym-key /var/lib/ergo-observer/mainnet.key \
  --clock-source chrony \
  --max-peers 8 \
  --dial-rate 12
```

Run log: `ergo-phase0-hs-capture` 2026-11-11 07:25–11:47 AEST — 2 508
captured handshakes from 55 unique mainnet peers (14 seeds,
`--capture-max 2500`, capture-only mode, ~11–12 dials/min dial-rate
bound). Replay verdicts: 100 % parse-OK, 0 rejections, 0 newly-rejected;
96.0 % strict SessionId overall, 98.0 % excluding our own pre-fix node —
the 100 `unknown:3` handshakes are exactly the two pre-fix Rust peers
(ours + `ergo-rust-mainnet-nbg1`). Dial limits held throughout (≤12/min
initiation, 60 s per-address failure-backoff floor, no double-dial of an
in-flight address). Verdict detail: [unverified](unverified.md).

Cross-generation check (same day): the pre-`85c1b052` parser
(commit `06b44bdd`) fed the 20 new/old-format SessionId bodies above
accepts **all 20** (0 rejections) — bodies <12 B are downgraded to
`Unknown {3}`, bodies ≥12 B are accepted as `SessionId`, and 7 of the 8
of those **silently mis-decode** (the old code read the first 8 VLQ
bytes as big-endian i64). Evidence (test + captured output):
[`evidence/old-vs-new-sid`](evidence/old-vs-new-sid/); the
fixed-codec counterpart that compiles at branch head is
`ergo-p2p/tests/it/sid_cross_compat.rs` (same 20 bodies: 19 exact
`SessionId`, 1 verbatim `Unknown`, 0 rejections).

## Node hook

The same crate provides the bounded `ObserverSink` and record model for a
validating node. The hook is **off by default**, writes through a bounded
channel (drop-and-count under pressure, never blocks consensus), and adds
data only a validating node has:

- **Transaction admission outcomes.** `tx_outcome` carries the real
  `admitted` / `rejected` result and, on rejection, the mempool reason —
  including `UnresolvedInput`, which is how a child-before-parent arrival
  shows up. It also records the transaction's input and data-input box ids
  so a rejection can be joined to the parents that arrive later.
- **Header validation timing.** `header_validated` reports the receipt →
  validated duration for each header the executor installs.
- **Full-block apply latency.** `block_applied` reports
  `since_first_announce_us` measured from the first `Inv`/`SyncInfo` seen
  for that header, when the announce is still in the bounded map.

It is passive: enabling it never changes admission, sync, relay, or
consensus behaviour. Every emit is a non-blocking `try_send`; a full queue
drops the record and counts it, and the writer turns the count into a `gap`
line so the dataset says how much was lost.

### Hook overhead (measured 2026-11-10)

No hook work runs *during* header or transaction validation:
`header_received`/`tx_received` fire on the message path before validation
is queued, `on_header_validated` fires after install, and `tx_outcome`
fires after the admission decision. The inline cost of each emit,
micro-benchmarked in release against the real `NodeObserver` + sink
(`ergo-node` `hook_cost_tests::hook_inline_cost_benchmark`, n = 20 000,
sink writer excluded — it runs on its own task):

| Inline path | mean | p50 | p99 |
|---|---|---|---|
| `header_validated` (mutex map lookup + `try_emit`) | 0.87 µs | 0.44 µs | 5.4 µs |
| `tx_outcome` (full tx re-parse for input ids + `try_emit`, 302 B tx) | 18.3 µs | 15.5 µs | 44.9 µs |
| `inv` announce (4 ids) | 2.9 µs | 1.9 µs | 9.9 µs |
| `try_emit` worst case (queue full → drop path) | 0.15 µs | 0.15 µs | 0.18 µs |

Against the live mainnet stream with the hook enabled (2026-11-10 15:29
onwards), `header_validated` durations — which *include* the hook's own
callback, the measurement window being receipt → callback completion —
ran p50 15.5 ms / p99 28.2 ms (n = 22) and `block_applied
since_first_announce` p50 586 ms (n = 26). The hook's p99 (5.4 µs) is
≈ 0.03 % of the median validation duration, and the sink's drop path
(0.18 µs) bounds the cost even when the queue is saturated. With the hook
disabled the only added work is one `Option` check per site.

### `[observer]` configuration

Off by default; enable it in `ergo-node.toml`:

```toml
[observer]
enabled = true
# JSONL path. Relative paths resolve against data_dir.
path = "observer.jsonl"
# Operator label copied into every record.
vantage = "hetzner-1"
# Wall-clock offset metadata (ms) and its source.
clock_offset_ms = 0
clock_source = "chrony"   # "unset" | "operator" | "chrony"
# Bounded queue depth (records); 64..=1000000, default 8192.
queue = 8192
# Keyed pseudonymisation key file, relative to data_dir.
pseudonym_key = "observer-pseudonym.key"
# Emit raw peer addresses. Debugging only; do not publish such a file.
reveal_peer_addresses = false
```

- `path`, `pseudonym_key`, `vantage`, `clock_offset_ms`, `clock_source`,
  `queue`, and `reveal_peer_addresses` are all optional with the defaults
  above.
- A **dormant** (disabled) section resolves its paths but **skips value
  validation**, so a disabled hook cannot brick boot even when junk.
  **Enabling** it requires `clock_source` in `unset|operator|chrony` and
  `queue` in `64..=1000000`.
- The section uses `deny_unknown_fields`, so a typo (e.g. `enabld`) is a
  parse error rather than a silently-off hook — mirroring `[shadow]`.

See [`unverified.md`](unverified.md) for the hook's live-test status.

## Current deployments

| Deployment | Vantage | Started | Notes |
|---|---|---|---|
| Standalone observer, mainnet | `pop-os-mainnet` | 2026-11-10 14:02 local | systemd user service `ergo-phase0-observer`; 14 configured peers (local mainnet node + 13 `mainnet.conf` seeds), max 8 concurrent sessions, headers only, 64 KiB/s per-session outbound ceiling. Output: `/home/arkadias/observation/mainnet-standalone/observer.jsonl`. |
| Crawler, mainnet | `pop-os-mainnet-crawler` | 2026-11-10 15:01 local | systemd user service `ergo-phase0-crawler`; same 14 seeds, max 8 concurrent sessions, 12 new dials/min, 60 s..6 h per-address retry backoff, shared pseudonym key with the standalone observer. Output + state: `/home/arkadias/observation/mainnet-crawler/`. |
| Crawler, testnet | `pop-os-testnet-crawler` | 2026-11-10 15:01 local | systemd user service `ergo-phase0-crawler-testnet`; seed = local testnet node, max 4 concurrent sessions, same dial limits, shared pseudonym key with the testnet node hook. Output + state: `/home/arkadias/observation/testnet-crawler/`. |
| Node hook, testnet | `testnet-hook` | 2026-11-10 13:36 local | `[observer] enabled = true` in the testnet node config; binary = this branch. Output: testnet node `data/observer.jsonl`. |
| Node hook, mainnet | `mainnet-hook` | 2026-11-10 15:29 local | `[observer] enabled = true` in the mainnet node config; binary = the node's current PR #694 base + this branch's change set (nonP2pk API preserved); shares the standalone observer's pseudonym key. Output: mainnet node `data/observer.jsonl`. |

Minimum mainnet observation window is 48 h; the run is extended until the
key interval estimates are tight.

## Dataset notes

- **Gap detection is the structured `observer_gap` event, not log
  text.** The sink-drop event was renamed from `gap` to `observer_gap`
  on 2026-11-11 (no `gap`-named records exist in the dataset, so the
  rename is lossless). Counting gaps is
  `grep -c '"event": *"observer_gap"'` over the JSONL — never a raw
  `grep gap` of the JSONL or of process logs: the mainnet seed's node
  name `mainnet-seed-node-singapore` contains `gap` (thousands of
  substring hits in `mainnet-crawler/crawl.jsonl` alone, 17 026 by
  2026-11-11 07:30), and a raw count would report them as drops.
- **SessionId values are not recorded; pre-fix self-detection was
  inoperative.** Handshake feature *presence* is recorded as labels
  (e.g. `session_id` in `handshake_ok.features`); feature *values* are
  never recorded, in the observer/crawler streams or the node hook
  stream. So there are no recorded SessionId values to invalidate from
  the codec fix `85c1b052` (the body is VLQ+zigzag, not fixed 8-byte
  BE), and the `session_id` presence labels remain valid. Behavioural
  caveat: in every binary prior to that commit the session id was
  misdecoded, so the node's self-connection check (peer session id ==
  our own, `ergo-p2p/src/peer_manager/mod.rs`) never matched: any
  self-connection (the node dialing its own gossiped address) would
  appear in pre-redeploy streams as an ordinary peer. The
  observer/crawler never used session ids, so their measurements are
  unaffected. The fix lands with the window-close redeploy.
- **Capture fields are capture-run only.** `peer_handshake_hex` /
  `received_hex` appear only in runs started with
  `--capture-handshake-hex` (see [Handshake capture](#handshake-capture-offline-analysis-only));
  the standing streams above never contain them.

## Window-close redeploy (staged 2026-11-11)

The 48 h window closes **2026-11-12 14:02 local**. All five running
binaries predate the SyncInfo tip fix (`06b44bdd`) and the SessionId
codec fix (`85c1b052`); both take effect only at this redeploy.

| Step | When | What |
|---|---|---|
| 1. Testnet node (canary) | 2026-11-11, executed | Replace the testnet node binary with the current branch build; restart; observe for several hours: handshake outcomes, disconnect reasons, peer-count stability, and the self-connection check (`handshake not admitted` / `SelfConnection` in the node log). |
| 2. Mainnet node | 2026-11-12 14:02 local | Stop `ergo-rust-archival`, swap in the same build (keeps the `[observer]` hook), start; mark the restart time in this table and in the dataset (the `mono_ns` session boundary). Rollback: `ergo-node.pre-phase0-20261110` + `ergo-node.toml.bak-pre-observer`. |
| 3. Observer + crawlers | 2026-11-12 14:02 local, after step 2 | Restart `ergo-phase0-observer`, `ergo-phase0-crawler`, `ergo-phase0-crawler-testnet` with the new build (capture flags stay off); mark restart times. From this boundary the observer/crawler present the real tip SyncInfo: expect one 400-id catch-up per connection, then tip-region announces only; early-header RTT rows shrink to the first 64 ids/connection and RTT composition becomes tip-dominated. |

### Mainnet rollback triggers (step 2, first 10 minutes)

T0 = restart time of `ergo-rust-archival` at step 2. Baseline facts
(measured, not assumed): the 2026-11-10 15:28 restart recovered to
`peers≈65` within ~2 min (`node_gauges` journal lines); the node's own
`/api/v1/info` reports `target_block_interval_ms=120000` (~5 tip
advances per 10 min, `node_heartbeat` `best_full_block_height`); and the
pre-redeploy baseline is `bans=0` with zero `handshake not admitted`
lines across the whole observation window.

| # | Signal | Threshold (T0-relative) | Action |
|---|---|---|---|
| 1 | Service state | `systemctl --user status ergo-rust-archival` not `active`, or no `node_gauges` line by T0+3 min | **Roll back** |
| 2 | Peer recovery | `peers=` gauge < 20 at T0+5 min (baseline ≈65 by T0+2 min) | **Roll back** |
| 3 | Handshake rejection (codec/parse-related only) | (a) `handshake not admitted` (warn, `ergo-node/src/node/events.rs:401-404`) with `error` = `self-connection detected via session_id` — the only reason code derived from the decoded session id (predicted zero: we are behind NAT); or (b) a burst of handshake *parse* failures, which log at debug level (`handshake failed … parse handshake: …`, `ergo-node/src/peer_loop.rs:317`) and are visible at info level only through stalled peer recovery (trigger 2) | **Roll back** — the codec-change signature; the replay of all 2 508 captured mainnet handshakes predicts zero of these. The other reason codes on that line — `already connected`, `max connections reached`, `no inbound slots available`, `per-IP limit reached`, `per-subnet limit reached`, `peer is banned`, `peer version … below minimum`, `unknown peer` (the 30 s timeout) — are connection-management, not codec failures: **do not roll back for them** |
| 4 | Ban wave | `bans=` gauge ≥ 2 in the first 10 min *and* `peers=` < 40 | **Roll back** |
| 5 | Tip stall | `best_full_block_height` unchanged for 10 min, or persistent `gap > 0` / `storage_health != "healthy"` in heartbeats | **Roll back** if not resolved by T0+10 min |
| 6 | Churn | `peers=` oscillating ±20 % in any 5-min window after initial recovery | Inspect; roll back if it persists to T0+15 min |

Watch: `journalctl --user -u ergo-rust-archival -f` (gauge and heartbeat
lines are the structured signals; `handshake not admitted` is the
signature line, `ergo-node/src/node/events.rs:401-404`). Log **every**
`handshake not admitted` line to the redeploy log with its `error=`
reason code (the full code set is `ConnectError`,
`ergo-p2p/src/peer_manager/limits.rs:81-100`), whether or not it is a
rollback trigger. API health:
`curl -s 127.0.0.1:9063/api/v1/info` (open route — agent/uptime); tip
from `node_heartbeat` (the REST tip route requires the operator
`api_key` header from `ergo-node.toml`).

Rollback procedure (restore the pre-phase-0 state):

1. `systemctl --user stop ergo-rust-archival`
2. `cd /home/arkadias/nodes/rust-mainnet && cp ergo-node.pre-phase0-20261110 ergo-node && cp ergo-node.toml.bak-pre-observer ergo-node.toml`
3. `systemctl --user start ergo-rust-archival`
4. Verify: `/api/v1/info` up, `peers=` past 40 within 3 min, tip
   advancing, `bans=0`, no `handshake not admitted`.
5. Record T0 and the rollback time in the redeploy table; mark the
   `mono_ns` session boundary in the dataset note. Keep the new binary
   build in place for post-hoc debugging (do not delete it).

Step 3 (observer + crawlers) proceeds after a step-2 rollback *unless*
the rollback trigger was #3 (codec/parse-related handshake rejection):
in that case hold step 3 and investigate before restarting any
P2P-facing binary.

Post-redeploy, re-run `scripts/analysis/summarize.py` on the final data
and write the 48 h report (key interval estimates, chosen outbound cap,
the missing-`duration_us` fractions already reported, and the
empty-V2-era artifacts above).

## Tx-outcome rejection parity vs Scala v6.0.7

Every `tx_outcome` rejection reason seen in the mainnet hook stream as of
2026-11-10, checked against the pinned reference
(`/home/arkadias/Coding/reference/ergo-scala-v6.0.7`, tag `v6.0.7`):

| Rust reason (count) | Scala v6.0.7 behaviour | Verdict |
|---|---|---|
| `StorageRentPolicy` (23) | `ErgoMemPool.process` declines before validation: `rejectStorageRentTxs && containsStorageRentClaim(tx)` (`ErgoMemPool.scala:305`); `mainnet.conf:83` sets `rejectStorageRentTxs = true`. Predicate: any input with empty proof carrying extension variable `Constants.StorageIndexVarId` = `Byte.MaxValue` = 127 (`ErgoMemPool.scala:257-261`; `ergo-core/.../settings/Constants.scala:37`). No peer penalty; pool records the id. | **Parity.** Rust mirrors it exactly: same predicate (`ergo-mempool/src/validator.rs:68-71`), same pre-validation position (`admission/mod.rs:339-348`), no penalty, `InvalidationReason::RelayPolicy` record. Reference node also rejects. |
| `UnresolvedInput` (12) | Inputs resolved against `utxo.withUnconfirmedTransactions(getAll)` — committed UTXO plus pooled outputs; unresolved → `Declined("not all utxos in place yet")`, no penalty, pool unchanged (`ErgoMemPool.scala:300-302`). | **Parity on the verdict** (same resolution view: `PoolUtxoOverlay`, `admission/mod.rs:355`). Rust-only *extensions* on top: (a) with `staging_enabled` (true on the mainnet node) the child is held as an orphan and can be admitted when its parent arrives, without re-announcement (`mempool.rs:398-441`); (b) a replacement that would consume an output of a tx it removes is rejected `UnresolvedInput`/`UnresolvedDataInput` (`admission/mod.rs:483-514`) — Scala would accept it and hold an unresolvable pool entry. |
| `DoubleSpendLoser` (14) | `acceptIfNoDoubleSpend` (`ErgoMemPool.scala:196-224`): the new tx replaces its conflicts when its weight beats their **average** weight; weight = `fee × 1024 / feeFactor` (`OrderedTxPool.scala:322-341`). Only direct conflicts are removed; no CPFP credit on stored weights. Loser → `ProcessingOutcome.DoubleSpendingLoser` (`ErgoMemPoolUtils.scala:92`), pool unchanged. | **Same concept, Rust is stricter — Rust-only policy in the edge cases.** Rust replaces only when `weight > max_conflict_weight` (max, not average) **and** `fee > removed_fee` over the conflicts' descendant closure, and conflict weights carry CPFP family credit (step 15c) (`admission/mod.rs:515-545`). A tx with `avg < weight ≤ max`, or `weight > max` but `fee ≤ removed fee`, is **rejected by Rust but accepted by Scala**. Which of the 14 observed cases fall in the edge set is not determinable from the stream (the event carries no weights). Note the mainnet node runs `sort_policy = "cost"` (weight `fee×1024/cost` = Scala `byExecutionCost` formula), while the stock Scala mainnet default is `mempoolSorting = "random"` — a per-startup coin-flip between `bySize` and `byExecutionCost` (`application.conf:88`; `NodeConfigurationSettings.scala:104-109`). |
| `ValidationFailed { kind: ScriptFailed }` (1) | `utxoWithPool.validateWithCost` failure → `ProcessingOutcome.Invalidated` (`ErgoMemPool.scala:331-334`); the node then **penalises the source peer** — `penalizeMisbehavingPeer`, or `penalizeSpammingPeer` for `TooHighCostError` (`ErgoNodeViewSynchronizer.scala:1479-1490`). | **Parity.** `classify` maps `ScriptFailed` → `ValidationFailed` + `Misbehavior` penalty when at tip (`admission/outcome.rs:112-119`). Minor lenient refinement: Rust withholds the penalty while behind tip; Scala penalises regardless. |

### Rust-only admission policies (rejects the reference node would not make)

1. **Stricter RBF gate** — the `DoubleSpendLoser` edge cases above.
2. **`IbdGated`** — peer txs rejected while `block_gap > ibd_gate_block_lag` (default 10, `ergo-mempool/src/types.rs:365`; mainnet config does not override). Scala in digest state (during IBD) *accepts* txs without validation (`ErgoMemPool.scala:339-341`).
3. **Cost budgets** — `PeerBudgetExhausted` / `GlobalBudgetExhausted` (admission step 1); no Scala counterpart.
4. **`RecentlyUnresolved` cache** — fast rejection of recently-seen unresolved bytes (admission step 3); Scala would re-process a re-announced orphan (cheap: parse + resolution).
5. **Private-mining exclusion** — operator-reserved tx ids decline before the fee gate (Rust-only feature).
6. **Replacement self-consumption guard** — see `UnresolvedInput` (b) above.

### Scala-only policy (reject the Rust node would not make)

- **`blacklistedTransactions`** — operator-configured tx-id blacklist → `Invalidated` + peer penalty (`ErgoMemPool.scala:276-280`); no Rust equivalent (empty by default in Scala).

Penalty parity: both stacks penalise the source peer for invalid txs; the
trigger sets match apart from the at-tip refinement. `max_tx_size_bytes`
defaults to 98,304 in both (Scala `maxTransactionSize`,
`application.conf:53`).

## Partial-data analysis (2026-11-10, ~3.1–3.6 h into the window)

Analysis script: `scripts/analysis/summarize.py` (stdlib only). Semantics:
latency joins are computed **per process session** (`mono_ns` resets at
each `observer_start`); announce→request joins use the **latest announce
at or before** the request (peers periodically re-announce tip headers —
joining to first-announce or to any announce produces artifacts); time
units normalised to ms, section sizes in bytes; `--json OUT` writes the
machine-readable report.

### Stream status (snapshot 2026-11-10 ~17:12 local)

| Stream | Span | Records | Peers | Restarts | Gap records |
|---|---|---|---|---|---|
| `pop-os-mainnet` (standalone) | 11 431 s | 14 119 | 4 | 1 | 0 |
| `pop-os-mainnet-crawler` | 7 886 s | 8 490 | 65 | 0 | 0 |
| `pop-os-testnet-crawler` | 7 884 s | 9 683 | 11 | 0 | 0 |
| `mainnet-hook` | 6 203 s | 41 573 | 65 | 0 | 0 |
| `testnet-hook` | 12 975 s | 8 707 | 3 | 0 | 0 |

Anomaly counters are clean: no `gap` records, no duplicate lines, no
wall-clock regressions, no future/stale records, no header-id
mismatches, no schema-shape issues. The only anomaly anywhere is one
`mono_ns` regression in the standalone stream (3.55 s backwards) — the
process restart at 15:01; it is explainable and handled by the
per-session joins. Peer-id joins succeed across all three mainnet
vantages (shared pseudonym key) and the testnet pair.

### Header RTT: sample composition matters

Because the observer and crawler present an **empty V2 SyncInfo** (the
honest "I know no headers" status, `session.rs` `respond_to_sync_info`),
each `ergoref` 6.0.8 seed re-sends a catch-up `Inv` of the first 400
header ids (heights 1–400) whenever one of our sync replies is processed.
The mechanism, derived from the pinned reference: an empty V2 compares as
`Younger` (`ErgoHistoryReader.compareV2`,
`ErgoHistoryReader.scala:164-165`), and
`ErgoNodeViewSynchronizer.processSyncV2` answers every `Younger` with
`hr.continuationIds(syncInfo, size = 400)` sent as `Inv` by
`sendExtension` (`ErgoNodeViewSynchronizer.scala:466-471, 375-381`); for
an empty peer `continuationIdsV2` is heights `1..=min(tip, 400)`
(`ErgoHistoryReader.scala:274-291`, with `GenesisHeight = 1` /
`EmptyHistoryHeight = 0`, `ErgoHistoryUtils.scala:24-25`). The extension
is sent inside `processSyncV2` itself — per processed reply, not on the
seed's own sync timer — and when the reply also triggers
`syncSendNeeded` the seed sends its own 4-header sync in the same burst
(`ErgoNodeViewSynchronizer.scala:490-494`). How often we get another
chance to reply depends on the seed's cadence (5 s `syncInterval` tick,
`ErgoNodeViewSynchronizer.scala:279`, `application.conf:553`; 60 s
`SyncThreshold`, `ErgoSyncTracker.scala:21`); the measured per-seed
re-send p50 in this window is 5.0 s / 23.6 s / 60.2 s (see
`unverified.md` for the 6.0.8-cadence caveat), and each of the 400 ids
had been re-announced 3 006 times by 20:35. The RTT engine requests
announced ids, so ~88 % of the standalone's type-101 RTT samples are
**early-chain headers, not tip headers**:

| Vantage | Tip headers (h > 400) | Early headers (h ≤ 400) |
|---|---|---|
| `pop-os-mainnet` | n=108, p50 235 ms, p99 299 ms | n=784, p50 257 ms, p99 2 386 ms |
| `pop-os-mainnet-crawler` | n=70, p50 275 ms, p99 285 ms | n=400, p50 278 ms, p99 481 ms |
| `pop-os-testnet-crawler` | n=232, p50 41 ms, p99 484 ms | n=400, p50 290 ms, p99 1 756 ms |

(Split at 400, not 1000: the catch-up extension covers exactly heights
1–400 and no receipts exist in 401–1000, so the rows are unchanged.)

The unsplit "p50 257 ms / p99 2 386 ms" figure was dominated by the
early-header tail (2020-era headers served from disk; tip headers are
cached — the testnet split, 41 ms vs 290 ms, shows the gap clearly).
The split was computed offline: `rtt` records carry no modifier id and
`seq` wraps per connection, so samples were joined to their `request_sent`
batch per connection segment (0 unmatched, 0 mixed batches). The tip
rows are the honest header-fetch RTT for the report.

Both sides behave honestly in this exchange (we answer every seed
SyncInfo with our true empty state; the seed re-sends its continuation).
It is a measurement-composition effect, not a protocol divergence.

### SyncInfo fix: present the observed tip (applied at the window-close boundary)

**Artifact in all pre-fix data.** Every record collected before the fix
was gathered while the observer and crawler presented the empty V2
SyncInfo above. By 20:35 the catch-up storm accounted for 3 006
extension messages carrying 1 202 400 ids = **97.2 % of all announced
ids** in the standalone stream; the early-header RTT rows in the table
exist only because of this re-send. Tip-header RTT is unaffected: tip
headers arrive via the seed's periodic 4-header V2 syncs (offsets
0/16/128/512 behind the tip, `ErgoHistoryReader.scala:400-405, 601` —
confirmed live in the A/B below: the seed's sync carried heights tip,
tip−16, tip−128, tip−512), which happen regardless of what we present.

**The fix.** The observer now tracks the highest fully-seen header —
from V2 sync entries and type-101 receipts
(`SharedSeen::observe_header`, `session.rs`) — in a process-wide
`ObservedTip`, and presents it newest-first as a single entry in every
SyncInfo reply (the initial post-handshake reply and the 30 s re-send),
falling back to the honest empty V2 before any header has been seen in
full, or when the header bytes are ≥ 1 000 (the codec's V2 cap). The
peer then compares `Equal` and sends nothing, or — after a tip move —
`Younger` with an extension of only the ids after the common point
(`ErgoHistoryReader.scala:274-291`). The crawler shares the session code
and `SharedSeen`, so the same change covers it.

**Verification (2026-11-10, A/B against a mainnet ergoref 6.0.8 seed).**
Same seed (`159.89.116.15:9030`), same host, 300 s each, minutes apart:

| Binary | 400-id extensions in 300 s | Steady state |
|---|---|---|
| deployed (15:01 build, empty V2) | **6** (gaps 0.9 s, then 62.4 / 60.1 / 60.2 / 60.2 s) | one every ~60 s |
| fixed (20:30 build, tip V2) | **1** (t ≈ 0, answering the honest empty initial reply) | none |

The fixed run's debug log shows the wire content of each reply: first
`V2 empty`, then the tip header `6b81b21c…11d3@Some(1913657)` — the
header the seed itself sent as the first entry of its 4-header sync
(id match verified) — after which the seed stops sending extensions
(`Equal`). The seed's own periodic 4-header syncs continue (6 in 300 s),
as they do for any synced peer. The ~60 s steady-state gap of the old
binary matches the reference `SyncThreshold` (60 s) + 5 s tick derived
above. The local nodes could not host the A/B: the testnet node's
`per_ip_limit = 1` slot on `127.0.0.1` is held by the testnet crawler
(dialing it reset 12/12 handshakes), and the mainnet node is a Rust
node whose sync behaviour is not the side being fixed.

**Consequence for the report.** Post-fix, a connection receives the
400-id catch-up exactly once (answering the initial empty reply) and
then only tip-region announces; with the observer's drop-not-queue
request pacing, the early-header RTT rows shrink to the first 64 ids per
connection and the RTT sample composition becomes tip-dominated — the
honest composition the report wants.

**Boundary.** Per the window-close plan, the running standalone binary
keeps the empty-V2 behaviour until the window closes (2026-11-12 14:02
local); the observer and crawler restart with the fixed binary at that
boundary, and the restart times are marked in the dataset for warm-up
exclusion. All records before that boundary contain the artifact above.

### Section sizes

- Mainnet **tip** headers are a constant **220 B** at every vantage
  (standalone h > 400 receipts, node-hook receipts, crawler receipts).
- Early mainnet headers are **278/279 B** (a variable-length header
  extension; content not identified — see `unverified.md` if it matters
  to the report; it does not for wire parity, which is per-format).
- Testnet headers are **219 B** (max 283).
- Cross-vantage check: the 47 mainnet header ids received by both the
  standalone observer and the node hook **agree on size in all 47 cases**
  (all 220 B) — both vantages measure the modifier content length, so the
  279 vs 220 difference is real on-wire variation, not a measurement
  discrepancy.

### Request and block-flow timing

- announce → first request: p50 ≤ 0.1 ms at all three standalone
  vantages and both node hooks — the request fires immediately on
  announce; pacing (per-peer interval, ≤64 ids/request, bounded
  outstanding) shapes the request *rate*, not the decision latency.
  The standalone issued 105 type-101 requests (91 single-id RTT pings,
  2×16-id, 12×64-id batches → 891 ids) producing 885 receipts.
- Chosen modest outbound cap (for the report): **64 KiB/s (65 536 B/s)
  per session**, token-bucket drop-not-queue at the send path (recorded
  in every `observer_start`); process-level `CPUQuota=10%` on the
  standalone service.
- `mainnet-hook`: `header_validated` p50 **15.2 ms** / p99 29.8 ms
  (n=41 measurable); `block_applied since_first_announce` p50 **583 ms**
  / p99 1 046 ms / max 1 132 ms (n=49). All 49 applied blocks were
  peer-announced first → the node **mined zero blocks** in the window
  (49 blocks ≈ the expected mainnet 2-min cadence for 1.7 h).
- `testnet-hook`: `header_validated` p50 **8.5 ms** / p99 15.2 ms
  (n=48); `block_applied` = 340 in 3.6 h but only 58 carry
  `since_first_announce` → the node **mines the majority of testnet
  blocks** (locally mined blocks fire `block_applied` via
  `block_relay::applied_block_announcements` but are never peer-announced).
  The 58 peer blocks match the 58 `header_validated` records 1:1.
- Tx flow (`mainnet-hook`): announce → body p50 **276 ms** (p99 701 ms,
  one 23 s late delivery); body → outcome p50 **0.8 ms** (p99 11 ms —
  admission is local and fast); announce → outcome p50 277 ms. Every
  `tx_outcome` has a prior announce and body receipt in the stream.
  Outcomes at snapshot: 185 admitted / 255 rejected (reason mix in the
  parity section above).
- Crawler, mainnet: 23 dials → 8 `handshaken`, 4 `handshake_fail`,
  5 `connect_refused`, 6 `connect_timeout` (35 % success — the seed
  list is mostly dead from this vantage); 65 peers learned (51 via
  gossip); connect latency p50 290 ms (10 s timeout cap).
- Clock: configured chrony offset 1.2–1.9 ms at all vantages; seed
  handshake `peer_time_ms` runs 32–176 ms **behind** local wall. All
  durations use the monotonic clock, so the skew does not enter the
  latency figures.

### Missing `header_validated.duration_us` — resolved

7 of the first 40 mainnet records (8/49 and 10/58 testnet at snapshot)
had no `duration_us`. Ruled out with the stream: locally mined headers
(all 7 ids are peer-announced via `syncinfo_v2` before validation), map
eviction (limit 32 768, a few hundred ids in use), and id mismatch
(the redundant type-101 `section_received` for each id has
`id_matches=true`).

Root cause: the header bytes reached the validation pipeline **without a
`Modifiers` message**. The `SyncInfoV2` continuation path
(`coordinator::on_sync_info`, the `PeerChainStatus::Older` arm) emits
`Action::ValidateHeader` for the peer's continuation header straight
from the sync payload (`ergo-sync/src/coordinator/events.rs:205`), while
the dispatch stamps receipt only for `Modifiers` frames
(`dispatch.rs:872`) — so the receipt lookup at validation time missed.
In all 7 cases a redundant `Modifiers` copy of the same header arrived
*after* validation (its `section_received` record postdates the
`header_validated` record), which is how the bytes eventually also
appeared as type-101 receipts.

A second unstamped path existed: the coalesced header-`Modifiers`
processor (`node/events.rs::process_header_modifier_batch`) accumulates
header messages across the tick window without the per-message stamp the
single-event path performs.

Fix (commit `cd701a8c`): stamp at both sites before `execute_all` —
stamp-only (no `section_received` record; the bytes arrived in a SyncInfo
frame, so a receipt record would be schema-false) for the continuation
path, full `header_received` for the coalesced Modifiers path.
`insert_first` is first-sight-wins, so double-stamping across paths is a
no-op. Regression test:
`hook_stamp_tests::stamp_only_makes_duration_measurable_without_section_record`.
Observation-only change — admission, sync, relay and consensus are
untouched. **The live nodes run the pre-fix binary**, so
`duration_us`-missing records continue until the next node redeploy;
the fix lands with the next build.

### Schema / timing anomalies (task 4 report)

1. **`rtt` records carry no modifier id**, and `seq` wraps per
   connection — the old/tip split above required an offline
   per-connection-segment join. Proposed: add `id` to `Event::Rtt`
   (additive schema change); deferred so the running 48 h window is not
   reset for it.
2. **Catch-up `Inv` re-announce storm** — ≈586 k `announce` occurrences
   for ≈400 early-chain ids from three seeds (≈90 % of standalone
   announces at the 17:12 snapshot; 97.2 % of announced ids by 20:35).
   Honest on both sides; it shapes the RTT composition and the request
   mix, nothing else. Being fixed — see the "SyncInfo fix" subsection
   above (artifact, fix, A/B verification, restart boundary).
3. **`mono_ns` resets at process restart** — one occurrence (standalone,
   15:01); handled by per-session joins.
4. **Live-file drift** — the JSONL files grow during analysis; counts
   differ between runs minutes apart (e.g. mainnet `tx_outcome`
   440 → 525 between the two snapshots in this section). Figures above
   are the 17:12 snapshot unless marked otherwise.
5. **Testnet long-tail `block_applied since_first_announce`** (p99
   27.5 s): quiet testnet — a peer-announced header can sit unapplied
   for tens of seconds behind the node's own mining; expected, not an
   anomaly.

The 48 h window for the standalone observer started 2026-11-10 14:02
local (session 2 from 15:01 after the refactored-build restart); the
final report is due after 2026-11-12 14:02, extended until the key
interval estimates are tight.
