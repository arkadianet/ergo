# Operator controls

These controls change service availability, request budgets and local peer
administration. They do not change transaction/block validation or chain selection.
The existing `/api/v1/node/health` and Scala-compatible routes retain their behavior.

## Startup, liveness and readiness

All three probes return a JSON report with `ready`, machine-readable `reasons`,
heartbeat/snapshot/tip ages and heights only for required dependencies. Success is HTTP 200;
a failed check is HTTP 503. They are public and exempt from the request governor, so shared proxy budgets
cannot turn supervision probes into HTTP 429 responses.

| Endpoint | Meaning |
| --- | --- |
| `GET /api/v1/node/startup` | The action loop started and has not stopped. |
| `GET /api/v1/node/liveness` | The action loop's monotonic heartbeat remains fresh. Syncing is live. |
| `GET /api/v1/node/readiness` | Heartbeat and runtime snapshot are fresh, headers/blocks are synchronized, state recovery has finished, the chain tip is recent, and no active runtime/storage fault is reported. |

Use startup for startup probes, liveness for process supervision and readiness
for removing a node from a load balancer during sync or stale-state conditions.
Applies and snapshot rebuild/install operations below the 600-second stuck
threshold remain live even with an old heartbeat. Idle stale loops and stuck
applies fail liveness. Readiness tolerates two blocks behind the header tip and
uses a two-hour default tip-age limit to accommodate normal mainnet block gaps. Headers-only nodes check the header tip
without requiring a full-block tip. Readiness requires an actual chain tip, so an
empty devnet is live but unready until it produces blocks.
Storage faults affect readiness for 60 seconds after the latest state-store
failure, or indexer failure when `require_indexer = true`. Repeated failures
renew that window. Best-effort peer-store failures do not affect readiness.
Historical errors remain visible in status and counters after the window expires.

```toml
[api.readiness]
heartbeat_max_age_ms = 600000
snapshot_max_age_ms = 30000
tip_max_age_ms = 7200000
require_indexer = false
require_wallet = false
```

Thresholds accept 1,000 through 86,400,000 milliseconds. The optional dependency
checks should be enabled for services that require indexed queries or wallet
balances. An absent/disabled indexer or uninitialized wallet fails its required
check. Core readiness alone does not guarantee those optional services are ready.
A tip timestamp beyond the consensus future drift (20 minutes) ahead of local wall
time also fails readiness.
Probe failure reasons describe local observations, not proof that the wider
network's best chain has been discovered.

## Effective configuration and runtime changes

`GET /api/v1/node/config` requires operator credentials and returns an explicit
allowlist of resolved boot settings, live `api_limits`/`readiness` settings,
an opaque boot-specific `revision`, reloadable groups and restart-required groups. It contains no API
key hashes, wallet secrets or shadow-node credentials. Values include CLI
overrides and defaults. Checkpoint details are represented by presence flags.

`PATCH /api/v1/node/config` requires admin credentials. Members merge into live
settings. Every member is parsed and validated before applying any change. An
optional `expected_revision` rejects a concurrent edit with HTTP 409
`config_conflict`, including after a restart. Success returns the new configuration view and revision.

```sh
curl -sS -H "api_key: $ERGO_API_KEY" http://127.0.0.1:9099/api/v1/node/config
curl -sS -X PATCH -H "api_key: $ERGO_API_KEY" -H 'Content-Type: application/json' \
  --data '{"expected_revision":"<revision from GET>","api_limits":{"refill_per_sec":30,"burst":60},"readiness":{"require_indexer":true}}' \
  http://127.0.0.1:9099/api/v1/node/config
```

Live changes are process-local. Update TOML to retain them across restarts; the
endpoint never rewrites the operator's configuration file. Network, validation,
bootstrap/checkpoint, proxy trust, authentication configuration, peer connection
limits, mempool capacity, mining, wallet and logging settings require a restart.
Unknown members, including consensus/trust settings, are rejected.

```toml
[api.limits]
refill_per_sec = 20.0
burst = 40.0
cheap_weight = 1.0
heavy_weight = 4.0
compute_weight = 10.0
max_tracked_ips = 65536
idle_prune_after_secs = 600
```

Rates and weights must be finite and positive, and burst must admit one request
of every class. The IP table cap accepts 1..1,000,000; pruning age accepts
1..86,400 seconds. Reconfiguration retains client bucket debt and does not reset
all clients to a full bucket. The same live governor is shared by native route
groups and batch requests. Existing loopback/proxy trust rules remain in effect.

## Named credentials and revocation

The existing `api_key` header and master `api_key_hash` continue to work. Add
named hash credentials to restrict a pool/service's access:

```toml
[api.security]
api_key_hash = "<master Blake2b256 hash: 64 lowercase hex characters>"

[[api.security.keys]]
id = "pool-worker"
hash = "<different Blake2b256 hash: 64 lowercase hex characters>"
scopes = ["mining"]

[[api.security.keys]]
id = "operator-agent"
hash = "<another Blake2b256 hash: 64 lowercase hex characters>"
scopes = ["operator"]
revoked = false # set true to revoke durably in configuration
```

Scopes are `mining`, `wallet`, `operator` and `admin`. Admin permits all gated
groups, including configuration mutation, shutdown, credential administration
and private-key export. Wallet permits wallet/scan/account operations; mining
permits work submission and mining reads. Protocol vote writes, policy updates
and private mining queue access require operator. Wallet mining jobs require
wallet. Unknown authenticated operations deny all scoped keys. Public
routes remain public. Both compatible and native authentication gates enforce
the same scopes. Named keys require a master hash; identifiers are unique
1..64-character ASCII letters/digits/underscore/hyphen strings. At most 128 keys
may be configured, with distinct hashes and nonempty scopes.

Admin callers can inspect `GET /api/v1/node/credentials` (IDs, scopes and revoked
flags only) and revoke a named key with
`DELETE /api/v1/node/credentials/{id}`. HTTP 204 means the revocation ledger was
persisted. Revocation survives restart in `credentials-revoked.json` under the
data directory; include this file in backups. For durable revocation across a
data wipe or an old backup restore, set `revoked = true` on the credential in
TOML (or remove it) and restart. The API cannot rewrite configuration. A missing
ledger with scoped keys logs a warning naming the re-enablement risk. On storage failure the key is
still denied in the current process, but the endpoint returns 503 because
durability was not confirmed. Retry to persist the denial.

Revoked IDs remain revoked even if their configured hash changes. Rotate by
using a new ID. The master key cannot be revoked through this endpoint: rotate
its hash in TOML and restart. A malformed/unreadable ledger refuses API startup when scoped keys exist.
With no scoped keys the ledger is ignored. Config-revoked keys stay denied even
if the ledger is missing or restored from an old backup.

## Manual peer administration

All writes require operator credentials. Ban and unban return HTTP 204
after the action loop acknowledges them. Disconnect and forget return HTTP 200
with `session_closed`, reporting whether there was a session to close. Queue saturation, timeout or unavailable persistence returns 503.
After a timeout, inspect the peer state before retrying.

| Request | Effect |
| --- | --- |
| `POST /api/v1/network/blacklist` with `{"addr":"203.0.113.8","duration_secs":1800}` | Persist an IP-wide timed ban, close all sessions for the IP and reassign pending requests. |
| `DELETE /api/v1/network/blacklist/{addr}` | Remove the IP's durable and live ban; idempotent. |
| `POST /api/v1/network/disconnect` with JSON string `"203.0.113.8:9030"` | Close that session and reassign pending requests. It may be redialed. |
| `DELETE /api/v1/network/peers/{addr}` | Remove saved dial metadata and close that session. |

Bans accept literal IPs or socket addresses, including IPv6; hostnames are
rejected. The default duration is 1,800 seconds, with a range of 1..31,536,000
seconds. Bans apply to every port and IPv4-mapped IPv6 representations of the
same IP. Existing blacklist reads show effective unexpired bans. Writes require
the persistent peer address book and make no live change if persistence fails.
Expiry is checked during admission/dial selection, independently of cleanup.
Configured seeds can reappear after removing saved metadata and restarting;
use a ban if the node must not reconnect to an IP.

Automatic peer bans are process-local and cannot evict or extend manual bans.
The live table reserves 1,024 of its 10,000 entries for operators; manual bans
may also replace automatic entries. Persisted rows include their operator origin.
Legacy rows without an origin marker are discarded at boot because their origin
cannot be established.
