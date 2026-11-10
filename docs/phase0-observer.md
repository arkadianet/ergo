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
| `handshake_ok` / `handshake_fail` | Handshake parse result; `handshake_ok` carries the peer's claimed version, agent, node name, feature labels, and handshake time. |
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
| `gap` | The bounded sink dropped records; `dropped` is the count since the previous successful line. |
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
