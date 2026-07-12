# Operating the node

A runbook for node operators: how to build, boot, monitor, back up,
upgrade, and shut down an Ergo Rust node, and what to check when something
goes wrong.

This is an independent, from-scratch Rust reimplementation of an Ergo full
node. It targets strict consensus compatibility with the
[Scala reference client](https://github.com/ergoplatform/ergo) — it accepts
the blocks the reference node accepts and rejects the ones it rejects — but
it is **not** the reference node, and it is pre-1.0 alpha software. Do not
rely on it for funds custody or production infrastructure; see
[`../SECURITY.md`](../SECURITY.md) and the README
[Status](../README.md#status) section.

Contents:

- [Quick start](#quick-start)
- [State modes and how to choose](#state-modes-and-how-to-choose)
- [Fast clean-DB boot (Mode 2 + NiPoPoW)](#fast-clean-db-boot-mode-2--nipopow)
- [First run vs resume](#first-run-vs-resume)
- [Data directory layout and backup](#data-directory-layout-and-backup)
- [Upgrading the node](#upgrading-the-node)
- [Monitoring](#monitoring)
- [API security posture](#api-security-posture)
- [Graceful shutdown](#graceful-shutdown)
- [Troubleshooting](#troubleshooting)

## Quick start

Build the node binary (the workspace pins Rust 1.95.0 via
[`../rust-toolchain.toml`](../rust-toolchain.toml); `rustup` installs it on
first build). See the README [Building](../README.md#building) section for
the full set of build commands.

```bash
cargo build --release -p ergo-node
```

Start from the operator config template
([`../ergo-node/ergo-node.toml.example`](../ergo-node/ergo-node.toml.example)).
Copy it, edit it, and point the node at it:

```bash
cp ergo-node/ergo-node.toml.example ./ergo-node.toml
./target/release/ergo-node --config ./ergo-node.toml
```

The config path is optional. If `--config` is omitted, the node looks for
`ergo-node.toml` inside the data directory; a missing file is not an error —
built-in defaults apply. Precedence is **CLI flags > TOML values > built-in
defaults**.

With the bundled defaults the node connects on mainnet (P2P port 9030),
persists state under `./ergo-data/`, and serves the REST API on
`127.0.0.1:9099`. The first run performs an Initial Block Download (IBD)
from genesis; later runs resume from the persisted tip. See
[Running](../README.md#running) in the README for the cargo one-shot form
and CLI help.

For the authoritative description of every config key, read the source
config module — each field is documented next to its type under
[`../ergo-node/src/config/`](../ergo-node/src/config/). Configuration is
unstable until 1.0; keys and shapes may change between minor versions.

## State modes and how to choose

The backend is selected by a cross-product of three `[node]` fields:
`state_type` (`"utxo"` | `"digest"`), `verify_transactions` (bool), and
`blocks_to_keep` (`-1` archive, `0` headers-only, `N > 0` pruned). The node
classifies each combination into exactly one mode at config-load and refuses
to start on an unsupported combination.

| Mode | Config | Status | Use when |
|---|---|---|---|
| **Mode 1 — UTXO full archive** | `state_type = "utxo"`, `verify_transactions = true`, `blocks_to_keep = -1` | Supported (default) | You want the full UTXO set on disk, can answer box/UTXO queries, and want to run the extra-index (Mode 1 only) or the external miner (any `state_type = "utxo"` mode — see below). |
| **Mode 2 — UTXO snapshot bootstrap** | Mode 1 plus `[node.utxo] utxo_bootstrap = true` | Supported | Clean-DB boot and you want to skip multi-hour genesis replay by installing a UTXO snapshot, then resume normal sync. See the trust caveat below. |
| **Mode 6 — headers-only** | `state_type = "digest"`, `verify_transactions = false`, `blocks_to_keep = 0`, `utxo_bootstrap = false` | Supported | You only need the validated header chain (PoW + difficulty) and never need block bodies, transaction validation, the mempool, or UTXO queries. |
| **Mode 5 — digest verifier** | `state_type = "digest"`, `verify_transactions = true` | Partial | Boots and passes handshake/sync seams; full sync stalls at the UTXO-typed executor header pipeline. AD-proof tx validation, external ADProof-corpus parity, and reorg-abort hardening remain open. |
| **Mode 3 — pruned** | `state_type = "utxo"`, `blocks_to_keep = N > 0` | Partial | A standard pruned config boots — `blocks_to_keep` at or above the 232-block rollback floor — with `block_sections` eviction landed; activation-parity follow-ups remain. |
| **Mode 4 — pruned + bootstrap** | Mode 3 plus `utxo_bootstrap = true` | Partial | Builds on Mode 3 + Mode 2; not yet wired. |

Defaults: `state_type = "utxo"`, `verify_transactions = true`,
`blocks_to_keep = -1` — i.e. omitting all three knobs gives you Mode 1.

Notes on the modes that boot today:

- **Mode 1** keeps the full UTXO set as an on-disk AVL+ tree plus the undo
  log, chain index, headers, and block sections. The `/blockchain/*`
  extra-index requires this full archive (Mode 1 only). Mining and the
  `/utxo/*` box lookups instead require only the UTXO box store, which every
  `state_type = "utxo"` mode keeps — so **mining runs on Modes 1–4** and is
  rejected, at config-load and at the runtime gate, only on the digest modes
  (5–6), which retain no box store to build candidates from.
- **Mode 2** jumps to a UTXO snapshot at a Scala-aligned snapshot height
  instead of replaying from genesis, then resumes block sync from
  `snapshot_height + 1`. Re-install is suppressed on subsequent boots via a
  persistent marker, so leaving `utxo_bootstrap = true` set across restarts
  is safe. **Trust caveat:** snapshot trust verification against the
  header's state root is provisional pending a Scala-oracle vector — before
  treating the bootstrapped UTXO state as authoritative, cross-check the
  installed root against a known-good reference manifest.
- **Mode 6** never requests block sections, force-disables the mempool, and
  does not run the wallet apply hook. `blocks_to_keep` must be exactly `0`
  for this combo.

Config consistency is enforced at load time, mirroring four of the Scala
reference node's five `consistentSettings` rules (R1, R2, R3, R5). The ones
operators trip most often:

- `verify_transactions = false` requires `state_type = "digest"` (R1).
- `[indexer] enabled = true` is incompatible with `blocks_to_keep >= 0` and
  with `utxo_bootstrap = true` — the extra-index requires a full archive
  (R2).
- `[node.nipopow] nipopow_bootstrap = true` requires `utxo_bootstrap = true`
  **or** `blocks_to_keep >= 0`; a plain full archive cannot also
  NiPoPoW-bootstrap (R3).
- `state_type = "digest"` rejects `[mining] enabled = true` and
  `[indexer] enabled = true`.

**Mode-sentinel safety:** UTXO and digest data directories are not
interconvertible in place. A boot-time check refuses a `state_type` that
disagrees with the value recorded in an existing data directory before any
migration runs — to switch backends, use a fresh `data_dir`.

## Fast clean-DB boot (Mode 2 + NiPoPoW)

For a fast first boot on mainnet, combine the UTXO snapshot bootstrap
(Mode 2) with the NiPoPoW header bootstrap. NiPoPoW handles the header phase
(downloading a proof and jumping to the suffix tip instead of replaying the
full header chain); Mode 2 handles the UTXO chunk download and install.

```toml
[node]
state_type = "utxo"
verify_transactions = true
blocks_to_keep = -1

[node.utxo]
utxo_bootstrap = true

[node.nipopow]
nipopow_bootstrap = true
p2p_nipopows = 2          # proof quorum; matches Scala mainnet
```

End-to-end, this has been observed to take on the order of tens of minutes
from an empty `data_dir` to "bootstrap complete" on mainnet — far shorter
than a multi-hour full IBD, though the exact time depends on peer quality
and bandwidth.

Operator notes:

- `p2p_nipopows` is the number of agreeing peer proofs required before the
  best proof is applied. The default of `2` matches the Scala mainnet
  setting. Lower it for a faster but less-corroborated apply; raise it for
  stronger multi-peer confirmation at the cost of a longer wait. It must be
  at least `1`.
- The NiPoPoW bootstrap is only safe to resume from a clean data directory
  or from a store that has already completed bootstrap. If headers were
  downloaded but no full block was applied (a partial header sync), the node
  **refuses to boot** and asks you to clear the data directory or remove the
  bootstrap flag. Start the combined bootstrap from an empty `data_dir`.
- The Mode 2 trust caveat above still applies: cross-check the installed
  UTXO root before trusting the state.

## First run vs resume

**First run (IBD).** On an empty `data_dir`, a Mode 1 node performs an
Initial Block Download from genesis: it downloads and validates headers
first, then downloads block sections and applies blocks, advancing the best
full-block height behind the best header height. The best header tip and the
best full-block tip are tracked independently, so during IBD you will see
headers run ahead while full blocks catch up. Watch progress via the logs or
`GET /api/v1/sync` (see [Monitoring](#monitoring)).

A first run with `utxo_bootstrap` and/or `nipopow_bootstrap` set installs
the snapshot / applies the proof instead of replaying from genesis — see
[Fast clean-DB boot](#fast-clean-db-boot-mode-2--nipopow).

**Resume.** On a populated `data_dir`, the node reads the persisted tip from
the state DB and resumes sync from there. The pending-block queue is
recovered from the store at boot, so an interrupted IBD picks up where it
left off rather than restarting. Because block commits during IBD may use
relaxed durability (see `--ibd-flush-interval` below), a hard crash can
require replaying up to the flush-interval's worth of recent blocks from
peers on the next start — this is automatic.

`--ibd-flush-interval N` (default `500`; `0` = always durable) controls how
often, in blocks, IBD forces a durable flush. A larger interval trades crash
recovery work for IBD throughput. Exiting IBD forces a durable flush of any
pending non-durable commits.

## Data directory layout and backup

`data_dir` defaults to `./ergo-data`. Override it with `--data-dir <path>`
or the top-level `data_dir` key. The node creates the following under it:

| Path | Holds | When present |
|---|---|---|
| `state.redb` | Consensus state: AVL+ UTXO tree, undo log, chain index, state meta, headers, block sections, voted params, wallet tables — the load-bearing DB | Always |
| `peers.redb` | Peer address book (known peers + bans); independent of the consensus DB | Always |
| `wallet/` | Encrypted (AES-GCM) wallet secret storage | When the wallet is initialized |
| `indexer.redb` | Extra-index (address / token / template) DB | Only when `[indexer] enabled = true` |
| `logs/` (or the configured `[logging.file].dir`) | Rotated log files | Only when `[logging.file]` is configured |
| `ergo-node.toml` | Config file, when you keep it in the data dir | Operator-placed |

Each redb file is updated under its own transactions; the consensus state DB
applies every block under a single atomic commit (undo log + AVL mutations +
chain index + state meta land together or not at all).

**Backup.** Back up the redb files together so they stay mutually
consistent. The `peers.redb` address book is not consensus-critical and is
rebuilt if lost; `state.redb` is the one that matters. On a copy-on-write
filesystem (ZFS, btrfs) you can snapshot the directory while the node runs.
Otherwise, stop the node first:

```bash
# stop the node (see Graceful shutdown), then:
cp -rp ./ergo-data /backup/ergo-data.$(date +%Y%m%d)
# restart the node
```

**Restore.** Stop the node, drop the backed-up directory back into place,
and start. Note that the recorded `state_type` is pinned in the data
directory — restore a UTXO backup only into a UTXO-configured node, and a
digest backup only into a digest-configured node.

## Upgrading the node

1. Read the release notes / [`../CHANGELOG.md`](../CHANGELOG.md) for the
   version you are moving to.
2. Stop the node gracefully (see [Graceful shutdown](#graceful-shutdown)) so
   the final state commit and a clean redb close complete.
3. Back up `data_dir` (see above) before any cross-minor upgrade.
4. Swap in the new binary and restart against the same config and
   `data_dir`.

Notes:

- Every tagged release through 1.0 is marked **pre-release** on GitHub;
  treat any pre-1.0 deployment as experimental.
- Configuration is unstable until 1.0 — a minor-version upgrade may rename
  or reshape config keys. The node validates the whole config at load and
  refuses to start with a clear error if a key is wrong, so an upgrade that
  changes the schema will fail fast rather than run with a stale config.
  Re-check your config against the updated
  [`../ergo-node/ergo-node.toml.example`](../ergo-node/ergo-node.toml.example)
  after a minor upgrade.
- Across a consensus change (a soft/hard fork), the upgrade itself is a
  binary swap, but the node's job is to track the same chain the Scala
  reference node tracks. Because this is an independent reimplementation,
  upgrade to a release whose notes state it covers the activated rules
  **before** the activation height, and keep the
  [Status](../README.md#status) and [`../CHANGELOG.md`](../CHANGELOG.md)
  in view. If in doubt around an activation, cross-check the node's tip and
  verdicts against a Scala reference node.

## Monitoring

All monitoring surfaces are on the operator API port (`[api] bind`,
default `127.0.0.1:9099`). There is no separate metrics listener.

**Prometheus `/metrics`.** `GET /metrics` returns Prometheus text
exposition. Every metric is a projection of the same state the JSON API
serves — no extra node state. `/metrics` is **not** authenticated; keep the
API bound to loopback or front it with an authenticated reverse proxy before
scraping over a network.

```yaml
scrape_configs:
  - job_name: ergo-node
    scrape_interval: 15s
    metrics_path: /metrics
    static_configs:
      - targets: ['127.0.0.1:9099']
```

Exposed gauges:

| Metric | Tracks |
|---|---|
| `ergo_node_uptime_seconds` | Seconds since node start |
| `ergo_node_best_header_height` | Best header chain height |
| `ergo_node_best_full_block_height` | Best fully-validated block height |
| `ergo_node_sync_gap` | Headers ahead of full blocks (catch-up gap) |
| `ergo_node_peer_count` | Connected (handshaked) peers |
| `ergo_node_mempool_size` | Pooled transaction count |
| `ergo_node_mempool_bytes` | Pooled-transaction byte total |
| `ergo_node_mempool_capacity_count` | Configured pool capacity (count) |
| `ergo_node_mempool_capacity_bytes` | Configured pool capacity (bytes) |
| `ergo_node_mempool_revalidation_pending` | Demoted txs pending revalidation |
| `ergo_node_snapshot_age_ms` | Age of the read snapshot (how stale the read view is) |

Exposed counters (reset to zero on node restart):

| Metric | Tracks |
|---|---|
| `ergo_node_block_apply_errors_total` | Block-apply rejections since node start |
| `ergo_node_mempool_tx_requested_total` | Unconfirmed-tx ids requested from peers since node start |
| `ergo_node_mempool_peer_tx_admitted_total` | Peer-sourced txs admitted to the mempool since node start |
| `ergo_node_mempool_peer_tx_rejected_total` | Peer-sourced txs rejected by admission since node start |

**Health.** `GET /api/v1/health` returns `200` when the node is healthy
(synced and connected) and `503` when it is stalled or disconnected, with a
JSON body either way. This is the endpoint to poll for liveness/readiness
checks and to confirm a shutdown has completed (the connection refuses once
the process exits).

**Sync progress (JSON).** For ad-hoc inspection, `GET /api/v1/sync`,
`/api/v1/status`, `/api/v1/info`, and `/api/v1/tip` return JSON views of the
same data the metrics project. During IBD, watch `best_header_height` and
`best_full_block_height` climb and the gap between them close.

**Web UIs.** The node serves a single-page operator dashboard at `/` with
seven sections — Overview, Explorer, Peers, Mempool, Mining, Voting, and
Wallet — a Swagger UI for the Scala-compatible REST surface at `/swagger`,
and a native Swagger UI for the operator `/api/v1/*` surface at
`/swagger/native`. These pages are public; the dashboard reads the public
`/api/v1/*` endpoints, and the Wallet section authenticates each `/wallet/*`
call with the operator `api_key` that you enter in the browser. The legacy
`/wallet/ui` path permanently redirects to `/#wallet`. Notable endpoints
the dashboard surfaces and operators can poll directly:
`GET /api/v1/events` (the bounded node event ring, up to 512 buffered
entries), `GET /api/v1/indexer/status` (indexer self-repair progress), and
`GET /api/v1/mining/minerStats` (per-miner block attribution).

**Logs.** The node logs via `tracing` to stderr by default, plus an optional
rolling file appender when `[logging.file]` is configured. `[logging] format`
selects `"text"` (default, human-readable) or `"json"` (for log shippers
like Loki / Elasticsearch / Datadog). The `RUST_LOG` environment variable
overrides `[logging] default_level` at runtime. Useful filters:

```bash
RUST_LOG=ergo_sync=info,warn     # sync progress without the chatter
RUST_LOG=ergo_mempool=debug,info # mempool admission decisions
RUST_LOG=ergo_p2p=debug,info     # P2P handshake / disconnect events
```

## Shadow validation

Opt-in mode that live cross-checks this node's chain against a Scala
reference node and alerts on divergence. The reference implementation cannot
watch itself; this node can watch it — if either implementation ships a
consensus bug, shadow operators know first, with a machine-readable diff.

```toml
[shadow]
enabled = true
reference_url = "http://127.0.0.1:9053"   # a Scala node you trust
# interval_secs = 30        # compare cadence
# lag_tolerance = 3         # compare this many blocks below min(tips)
# stall_gap_threshold = 10  # reference ahead by more than this AND we
                            # are not advancing => tip_stall
# request_timeout_secs = 5
```

Two signals, both cheap (two reference REST reads per tick, never on the
block-apply path):

| Signal | Meaning | Consensus-bug class |
|---|---|---|
| `header_mismatch` | different canonical header id at a depth-floored height | accept-invalid (we kept a branch the reference refused) |
| `tip_stall` | the reference's full-block tip advances while ours does not | reject-valid (we refused a block the network accepted) |

Surfaces: `ApiStatus.shadow` on `GET /api/v1/node/status`, `shadowDivergence` on
`GET /api/v1/events` + the WS bus, and four `/metrics` series
(`ergo_node_shadow_divergence_total`, `_last_compared_height`,
`_reference_unreachable`, `_diverged`) — emitted only when the mode is
enabled, so "absent" and "quiet" stay distinguishable. Alert on
`increase(ergo_node_shadow_divergence_total[10m]) > 0` and on prolonged
`_reference_unreachable == 1`.

False-positive discipline is built in: compares run below a lag floor, a
`header_mismatch` must reproduce on two consecutive ticks, an unreachable
reference is a gauge (never an event), a node **catching up** is not a
stall (the stall signal requires no local progress), and a confirmed
divergence fires one event per incident.

### Divergence fired — who is wrong?

Work the list in order; stop at the first decisive answer.

1. **Is it still active?** `curl :9063/api/v1/node/status | jq .shadow`. If `diverged`
   is null again, it was a transient the latch already cleared (deep
   cross-node reorg race). Note it, don't page.
2. **`tip_stall`: look at OUR apply path first.**
   `curl -s :9063/api/v1/node/status | jq '.last_block_apply_error, .block_apply_errors_total'` and
   `journalctl | grep block_apply`. A rejection loop on one block = WE are
   probably rejecting something valid (reject-valid). Capture the block id
   + rejection reason — that pair is the bug report. Check
   `sync_wedged` too: a wedge is a different failure (see Troubleshooting)
   that also presents as a stall.
3. **`header_mismatch`: ask a third node.** The event names `height`,
   `ours`, `theirs`. Query any independent node (public explorer, a second
   Scala node) for the header id at that height:
   - third party agrees with **them** → our node kept a branch the network
     refused: treat as an accept-invalid bug in THIS node. Preserve the
     data dir; file with `ours`/`theirs`/height.
   - third party agrees with **us** → the *reference* is off-chain: either
     it is stalled/isolated (check its `/info`) or — the headline case —
     the reference implementation rejected a valid block. Verify its logs
     before claiming a Scala consensus bug.
4. **Reorg context.** `GET /api/v1/diagnostics/reorgs` shows recent
   tip replacements with depth, orphaned ids, returned txs, and which peer
   delivered the winning tip — useful to distinguish "wild reorg window"
   from a genuine split.
5. **Reference health.** `_reference_unreachable == 1` for more than a few
   intervals means you are NOT being watched — fix connectivity before
   trusting the quiet.

Safe defaults: divergence changes nothing about node behavior (observe and
alert only). Do not wipe the data dir until the evidence (both header ids,
heights, logs) is preserved — a confirmed divergence data dir is the most
valuable debugging artifact this node can produce.

## API security posture

The default posture is **safe by default for a single-host operator**:

- The API binds to loopback (`127.0.0.1:9099`) by default. A non-loopback
  bind is **rejected at config-load** unless you also set
  `[api] public_bind = true` — the node will not start otherwise.
- `[api.security] api_key_hash` is **mandatory** whenever the API server is
  enabled. It is the lowercase Base16 of `Blake2b256(secret)` and must be
  exactly 64 lowercase hex characters; the node refuses to start with a
  malformed or missing hash. The only way to omit it is `[api] disabled =
  true`. Requests authenticate by sending the secret in the `api_key`
  request header (lowercase, underscore — not `Authorization`, not
  `X-Api-Key`); the node Blake2b-256-hashes it and compares against the
  configured hash in constant time. A missing or wrong key returns `403`.

What the `api_key` actually gates is **narrow, by design** (Scala parity):
only the `/wallet/*` JSON subtree and `POST /node/shutdown` (and its
`/api/v1/node/shutdown` alias) require the key. The gate covers those
whole path prefixes — an unknown subpath under `/wallet/` or `/node/`
still rejects on the key first, mirroring Scala's
`pathPrefix(...) & withAuth`; every other unmatched path is a plain,
ungated `404`. **Everything else is public**
regardless of `public_bind` — including transaction submission
(`POST /transactions*`, `POST /api/v1/mempool/{submit,check}`),
`POST /blocks`, `/mining/solution`, all reads, `/blockchain/*`,
`/emission/*`, `/peers/*`, `/utils/*`, the dashboard, and `/metrics`.

**Before exposing the node beyond localhost:**

- Setting `public_bind = true` removes the only guard against a non-loopback
  bind, and it does so silently — there is no runtime warning. Do not treat
  it as "now the node is secured for the public internet."
- Because submission and read routes stay unauthenticated, put the node
  behind a reverse proxy (or firewall) that adds authentication and rate
  limiting on the public surface. Expose only what you intend to, and keep
  `/metrics` and the submission routes off the open internet unless you have
  fronted them.
- The dashboard at `/` is intentionally public (it carries no secrets; the
  Wallet section authenticates each `/wallet/*` call with the key you enter in
  the browser), but the `/wallet/*` API it drives remains `api_key`-gated.

## Graceful shutdown

The node drains cleanly on SIGINT / SIGTERM / SIGHUP (Unix) or Ctrl+C
(Windows), and on the API shutdown route. A graceful shutdown is what
guarantees the final state commit lands and redb is closed cleanly, so the
next start does not need a recovery pass.

To trigger shutdown over the API:

```bash
curl -s -X POST -H 'api_key: <your-secret>' \
  http://127.0.0.1:9099/api/v1/node/shutdown
```

`POST /node/shutdown` (and `/api/v1/node/shutdown`) is `api_key`-gated. It
returns `202` with the body `shutdown_requested` **immediately**; the actual
drain proceeds asynchronously. Confirm completion by polling
`GET /api/v1/health` until the connection refuses.

The drain fires the action-loop shutdown signal (in-flight write handlers
see a "shutting down" result rather than hanging), cancels the indexer and
anchor-builder tasks with bounded waits, lets in-flight HTTP requests drain
(also bounded), drops the persist pipeline (draining queued writes), and
forces a final durable flush so redb sees a clean close.

Under a process supervisor (systemd, Docker), prefer sending SIGTERM and
allowing a generous stop timeout so the bounded drains and the final flush
complete before the supervisor escalates to SIGKILL.

## Troubleshooting

Work from raw data: the JSON endpoints and the logs are the fastest way to
find the real problem.

**Node refuses to start with a config error.** The whole config is validated
at load. Common causes: a non-loopback `[api] bind` without
`public_bind = true`; a missing or malformed `[api.security] api_key_hash`
(must be 64 lowercase hex chars) while the API is enabled; an unsupported
mode combination (e.g. `verify_transactions = false` without
`state_type = "digest"`, or `[indexer] enabled = true` alongside
`utxo_bootstrap = true` or `blocks_to_keep >= 0`); an empty resolved peer
list. Read the error string — it names the rule that failed.

**Node refuses to boot with a NiPoPoW resume error.** A NiPoPoW bootstrap
cannot resume from a store that downloaded headers but never applied a full
block. Clear the `data_dir` and re-run the bootstrap from empty, or remove
the `nipopow_bootstrap` flag.

**Sync stuck** (`best_header_height` not increasing during IBD):

```bash
curl -s http://127.0.0.1:9099/api/v1/sync | jq .
```

If the connected peer count is `0`, the node is not dialing — check
`[peers] known` and that outbound connections are allowed by your firewall.
The built-in peer ceilings are `target_outbound = 96` (outbound goal),
`max_inbound = 256` (inbound cap), and `max_connections = 384` (hard total);
tune them under `[peers]` if your host cannot sustain that many file
descriptors. If peers are connected but the gap is not shrinking, peers may
be stale or on a fork; inspect `GET /api/v1/peers` to see what heights they
advertise.

**Headers ahead of full blocks.** During IBD the node downloads headers
first, then full blocks; the gap closes naturally as full blocks catch up.
A persistent non-zero `ergo_node_sync_gap` while headers are still syncing is
expected behavior, not a fault.

**Transaction submission rejected.** Submission endpoints return a structured
error envelope whose `reason` field names the failure. Channel-side or
feature-disabled failures (`overloaded`, `shutting_down`, `route_disabled`)
return `503`; a per-submission deadline returns `504`; a local storage
failure returns `500`; bad submitter input (deserialize, non-canonical,
invalid PoW, etc.) returns `400`. A pool at capacity surfaces during
admission — raise `[mempool] max_pool_size` or `[mempool] max_pool_bytes` if
the rejection is capacity-driven. Note that during IBD the mempool gates
admission until the node is close to the tip, so submissions may be deferred
until sync catches up.

**Disk usage growing faster than expected.** Enabling the extra-index
(`[indexer] enabled = true`) adds an `indexer.redb` file and roughly doubles
the on-disk footprint. Disable it if you are not querying the
address/token/template indices. Pruning (positive `[node] blocks_to_keep`)
is not a supported posture today; the supported way to run without keeping
full blocks is Mode 6 (headers-only).

**Reorgs.** The node handles reorgs automatically with delta-based rollback
through the undo log. You will see a brief dip in `best_full_block_height`
followed by a climb on the new chain. A reorg approaching the ~200-block
rollback window is unusual — investigate peer quality before assuming a
node-side fault.

**Memory.** Each redb database falls back to its own ~1 GiB page cache by
default, and that is separate from the AVL arena budget logged at startup.
When budgeting memory, account for `state.redb` plus, when enabled,
`indexer.redb` and `peers.redb`. `[store] cache_bytes` (or `--cache-bytes`)
tunes the AVL arena cache. For IBD memory profiling, setting
`ERGO_MEM_CSV=<path>` makes the node append a per-tick memory sample to a
CSV.
