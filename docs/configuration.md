# Configuration reference

This is the complete reference for `ergo-node.toml`, the node's
configuration file. This node is an independent Rust reimplementation
that targets strict consensus compatibility with the Scala reference
node — it is not the reference node, and several config keys exist
specifically to mirror Scala's `consistentSettings` checks. Keys whose
behavior follows Scala are noted as such below.

## New-install setup

`ergo-node init` is the recommended first step for a new installation. With a
TTY it explains and prompts for missing choices; otherwise it requires
`--preset`, `--sync`, `--network`, and a mining `--reward` choice and exits 2
if anything is missing. `--non-interactive` always disables prompts.

```sh
ergo-node init --data-dir ./ergo-data
# Or preview an unattended wallet installation without writing:
ergo-node init --preset wallet --sync genesis --network mainnet \
  --data-dir ./ergo-data --non-interactive --dry-run --json
```

The wizard resolves paths to absolute paths, validates generated TOML using the
node's loader, saves an API secret first and then publishes the new config.
It prints the exact start command with explicit `--config` and `--data-dir`,
the dashboard URL, key-file path, and next steps. `--dry-run` writes nothing
and elides the API hash in its config preview; `--json` returns a plan with
`schema_version = 1`, paths, config contents, disk recommendation, warnings,
reward address (when supplied), and next steps. No mode prints the secret.

| Preset | Indexer | External mining | Storage-rent claims | Sync choices |
|---|---|---|---|---|
| `wallet` | off | off | off | fast, genesis |
| `mining-fast` | off | on | off | fast, genesis |
| `mining-full` | on | on | on | genesis |
| `explorer` | on | off | off | genesis |
| `archival` | off | off | off | genesis |

All presets enable the mempool and write `[node] state_type = "utxo"`,
`verify_transactions = true`, and `blocks_to_keep = -1`. Fast sync writes
`[node.utxo] utxo_bootstrap = true`, `[node.nipopow] nipopow_bootstrap = true`
and `p2p_nipopows = 2`. It avoids historical replay, with download time depending
on peers and bandwidth, and requires `--accept-unanchored-bootstrap` or a
separate interactive consent: snapshot trust is provisional, so **cross-check
the installed UTXO root** against an independently trusted node. Genesis sync
sets both bootstrap flags false and takes hours to days. Explorer and full
mining also need historical index catch-up.

Mining requires `--reward wallet` or `--reward public-key`. Wallet rewards omit
`miner_public_key_hex`; initialize and **unlock** the node wallet in the
dashboard before work is served. Public-key rewards require
`--miner-public-key HEX`, a valid 33-byte compressed secp256k1 point beginning
with `02` or `03`. The wizard displays its P2PK address for the selected
network and requests confirmation in interactive mode. Use
[ergo-solo's Stratum bridge](https://github.com/arkadianet/ergo-stratum-rs) or
[the Lithos guide](lithos.md) to connect external miners.

`--network mainnet|testnet` selects embedded network seeds. `--api-bind ADDR`
defaults to `127.0.0.1:9099`. An explicit non-loopback bind also writes
`[api] public_bind = true` to satisfy the loader and reports that transaction
submission remains publicly callable; privileged routes still require the key.
`--p2p-bind ADDR` and `--declared-addr ADDR` write `[peers] bind_addr` and
`declared_addr` only when supplied; inbound connections need a listener and
port forwarding. The wizard never writes a peer list, voting targets,
private-key exposure, or unauthenticated legacy mining.

`--data-dir PATH` defaults to `./ergo-data`; `--config PATH` defaults to
`<data-dir>/ergo-node.toml` and must end in `.toml`, so it cannot take the
place of a file the node keeps in its data directory. The resolved data
directory is stored in the config.
The secret is `<config-dir>/secrets/api-key`: send its contents in the `api_key`
header or enter them in the dashboard. Unix directory/file modes are
`0700`/`0600`; Windows inherits ACLs, so use a directory only you can read.
Existing secret directories must already have mode `0700` on Unix.

The wizard queries free space on the data filesystem, or its nearest existing
ancestor. Recommended free space (**provisional**) on mainnet is 100 GiB for
wallet or mining-fast with fast sync, 150 GiB for either with genesis sync or
archival, and 250 GiB for explorer or mining-full. On testnet the same tiers
are 20, 30 and 50 GiB. A lower reading requires
`--allow-low-disk` or interactive confirmation; an unknown reading warns and
continues. These budgets are recommendations, not storage limits.

V1 creates new configurations only, installs no service, and edits no existing
files. It refuses existing config/key paths, including symlinks. Fast sync
requires a new or empty data directory to prevent bootstrapping over node data.
Use the printed start command, then press Ctrl-C and wait for graceful shutdown
to stop. For existing installations, edit the configuration deliberately and
use the standalone `api-key` command when a new credential is needed.

## Resolution model

Values are resolved from three sources, highest precedence first:

1. **CLI flags** (e.g. `--network`, `--data-dir`)
2. **TOML file** values
3. **Built-in defaults**

The config file path is `--config <path>`; when that flag is absent the
node looks for `ergo-node.toml` inside the data directory
(`<data_dir>/ergo-node.toml`). If `--config` is omitted and that file does
not exist, built-in defaults apply; a path given with `--config` must exist
and be readable, or the node refuses to start. All validation runs at load
time: any failure returns an error and the node refuses to start rather
than booting into a misconfigured state.

A ready-to-use default config ships at
[`../ergo-node/ergo-node.toml`](../ergo-node/ergo-node.toml) — a mainnet
full-archival node with the `/blockchain/*` extra-index enabled — and a
fully-commented operator template lives next to it at
[`../ergo-node/ergo-node.toml.example`](../ergo-node/ergo-node.toml.example).
Both templates enable the API on loopback with no credential. The dashboard,
swagger and public REST work immediately; privileged routes stay closed until
the operator configures their own key.

### Unknown-key handling is per-section

Typo rejection (`deny_unknown_fields`) is applied per TOML section, not
uniformly. An unknown key inside a strict section is a hard parse error;
an unknown key inside a lenient section is silently ignored. This is
worth knowing when a key seems to have no effect — check that its
section rejects typos:

| Strict (unknown key = error) | Lenient (unknown key ignored) |
|---|---|
| `[node]`, `[node.utxo]`, `[node.nipopow]`, `[mempool]`, `[indexer]`, `[wallet]`, `[voting]`, `[logging]`, `[logging.file]`, `[api]`, `[api.security]`, `[api.script]`, `[api.peer_details]` | top-level, `[peers]`, `[sync]`, `[store]`, `[chain]`, `[mining]` |

**Upgrade:** Formerly ignored unknown keys in `[api]`, `[api.security]` and
`[api.script]` now fail configuration loading and prevent startup. Remove
unsupported keys or rename misspelled keys to their documented names in
existing configs before upgrading.

## Top-level keys

| Key | Type | Default | Description |
|---|---|---|---|
| `network` | string | `"mainnet"` | Selects the chain spec. `"mainnet"`, `"testnet"` or `"devnet"` (the private conformance chain of `scripts/devnet-mixed/`). The network must have an embedded genesis or the node fails fast. CLI: `--network`. |
| `data_dir` | string (path) | `"./ergo-data"` | Root directory for the state database, logs, wallet, and the default config-file location. CLI: `--data-dir`. |

## `[node]`

| Key | Type | Default | Description |
|---|---|---|---|
| `agent_name` | string | `"ergo-rust"` | Agent name advertised in the P2P handshake. |
| `node_name` | string | `"ergo-rust-node"` | Node name advertised in the handshake. |
| `blocks_to_keep` | i32 | `-1` | Pruning suffix length. `-1` = full archive (keep every block). `N > 0` = retain a pruned suffix of `N` blocks. `0` is reserved for the headers-only combo (see below). Values below `-1` are rejected. A positive `N` must be at least the rollback-window floor (`keep_versions + SAFETY_MARGIN`); a smaller value is rejected because a reorg could otherwise need evicted block sections. |
| `keep_versions` | u32 | `200` | Undo-retention window = the deepest chain reorg the node can serve (Scala `keepVersions` parity — same default). Raising it lets the node follow deeper best-chain reorgs at a linear undo-log disk cost; the same value is wired into the extra-index store so the indexer can follow any reorg the state performs. `0` is rejected (a store that can never roll back would wedge on any reorg). Prospective only: undo entries already pruned under a smaller window stay gone, so a raise takes full effect `keep_versions` blocks later. If the best-header chain ever forks deeper than this window, the node cannot reorg onto it and reports a terminal `sync_wedged` state (`/health` = `wedged`, HTTP 503) — the only recovery is a resync. |
| `state_type` | string | `"utxo"` | State backend. `"utxo"` keeps the full UTXO set on disk (wire byte 0); `"digest"` keeps only the authenticated root digest and a header window (wire byte 1). Case-insensitive. `"digest"` supports the digest-verifier and headers-only combinations below. |
| `check_reemission_rules` | bool | `false` | Apply re-emission token allocation and reward-spending validation (rule 123). Enabled automatically when mining is enabled, including `--mining-enabled`. |
| `verify_transactions` | bool | `true` | When `false`, the node syncs headers only and downloads no block sections. Requires `state_type = "digest"` (Scala rule R1) and is accepted only in the headers-only combo below. |

**Digest combinations.** Mode 5 verifies full blocks with AD proofs:
`state_type = "digest"`, `verify_transactions = true`, `blocks_to_keep = -1`,
`utxo_bootstrap = false`, `nipopow_bootstrap = false`. Mode 6 verifies headers
only: `state_type = "digest"`, `verify_transactions = false`,
`blocks_to_keep = 0`, `utxo_bootstrap = false`. Other digest combinations are
rejected. Both modes reject mining and the extra-index because they keep no
UTXO box store. Mode-specific compatibility limits remain in
[`compatibility.md`](compatibility.md).

### `[node.utxo]`

| Key | Type | Default | Description |
|---|---|---|---|
| `utxo_bootstrap` | bool | `false` | When `true`, bootstrap from a UTXO-set snapshot at a fixed-cadence height instead of replaying from genesis, then resume normal sync. Incompatible with `[indexer] enabled = true` (Scala rule R2) and with the headers-only combo. Snapshot trust verification against the header state root is provisional pending a reference-node oracle vector — cross-check the installed UTXO root against a known-good reference before treating the state as authoritative. |

### `[node.nipopow]`

| Key | Type | Default | Description |
|---|---|---|---|
| `nipopow_bootstrap` | bool | `false` | When `true`, jump to a NiPoPoW proof's suffix tip at startup instead of syncing the full header chain. Requires `utxo_bootstrap = true` OR `blocks_to_keep >= 0` (Scala rule R3); a full-archive node cannot also NiPoPoW-bootstrap. Also requires a configured genesis id, so it is incompatible with `[chain] genesis_id = ""` (Scala rule R5). |
| `p2p_nipopows` | u32 | `2` | Number of valid proofs required to reach quorum before applying. Must be at least 1. The default matches the Scala reference (`p2p_nipopows = 2`). |

Combining Mode 2 (`utxo_bootstrap = true`) with NiPoPoW bootstrap gives
the fast clean-database boot path.

## `[peers]`

| Key | Type | Default | Description |
|---|---|---|---|
| `known` | array of strings | `[]` | Known peer socket addresses (`host:port`). The CLI flag `--peers a,b,c` replaces this list entirely (it is not merged). The network's seed peers are then appended as fallbacks and deduplicated. Unparseable entries are dropped silently. If the final peer list is empty, the node refuses to start. |
| `max_connections` | usize | `384` | Hard ceiling on total concurrent connections (inbound + outbound combined). Must be at least 1. |
| `target_outbound` | usize | `96` | Outbound-connection target. Must be at least 1 and no greater than `max_connections`. When omitted, the default is clamped down to `max_connections` if that value is smaller, so a config that pins a low `max_connections` is not broken by a binary upgrade that raises the default. An explicit value above `max_connections` is a hard error. |
| `max_inbound` | usize | `256` | Maximum inbound connections accepted. Decoupled from `target_outbound`: a full outbound set never reduces inbound capacity. `0` = outbound-only. The hard ceiling `max_connections` still applies on top of this budget. |
| `per_ip_limit` | usize | `1` | Maximum connections per peer IP. Must be at least 1. |
| `per_subnet_limit` | usize | `3` | Maximum connections per IPv4 /16 or IPv6 /48 group, across inbound/outbound and pending handshakes. IPv4-mapped IPv6 shares IPv4 limits. Must be at least 1. |
| `bind_addr` | string | none | Inbound TCP listen address. Absent or empty string = outbound-only (no inbound listener). Parsed as a socket address at load; a malformed value is rejected. |
| `declared_addr` | string | none | Address advertised in the handshake and peer gossip so others can dial this node. Independent of `bind_addr` (a NAT'd host binds privately and declares its public address). Absent or empty = the handshake omits it. |
| `allow_local` | bool | `false` | Allow local-network addresses — loopback, RFC1918 / site-local, link-local, IPv6 unique-local, and carrier-grade NAT — to be learned from gossip, dialed, shared with peers, and kept in `peers.redb`. Off by default so a NAT'd peer advertising e.g. `10.0.0.8:9030` does not enter every other node's dial pool. Turn it on for a LAN devnet, where peers must find each other by gossip over private addresses. Mirrors Scala `scorex.network.allowLocal`. Entries in `known` are unaffected: an operator-configured address is always dialable, including `127.0.0.1:9020`. |

## `[sync]`

| Key | Type | Default | Description |
|---|---|---|---|
| `download_window` | usize | `384` | Number of blocks ahead of the validated tip to keep pending for section download. Must be at least 1 and no greater than 100000. |
| `sync_interval_secs` | u64 | `5` | Global SyncInfo broadcast cadence while in IBD (Scala `scorex.network.syncInterval`). Distinct from the per-peer 20 s `MinSyncInterval` floor and from reciprocal SyncInfo replies. |
| `sync_interval_stable_secs` | u64 | `15` | Global SyncInfo broadcast cadence once headers are caught up (Scala mainnet `syncIntervalStable`). |
| `enable_anchor_scheduler` | bool | `false` | Opt-in: dispatch single-anchor `SyncInfo` to REST-capable peers from the anchor map instead of the local recent-header tail. Enable only once the anchor map is observed healthy. |

## `[store]`

| Key | Type | Default | Description |
|---|---|---|---|
| `cache_bytes` | usize | 1 GiB (`1073741824`) | AVL arena clean-node LRU budget, in bytes. CLI flag `--cache-bytes` overrides this. Dirty/pinned nodes and redb's per-database caches are separate; this is not a process RSS limit. |
| `state_redb_cache_bytes` | usize | 1 GiB | redb page-cache budget for `state.redb`, including digest mode. Independent of `cache_bytes`; zero disables this cache. |
| `indexer_redb_cache_bytes` | usize | 1 GiB | redb page-cache budget for the optional indexer database. Used on creation, resume and schema rebuild. |
| `peers_redb_cache_bytes` | usize | 1 GiB | redb page-cache budget for `peers.redb`, including replacement after corruption. |

Defaults preserve the previous per-database budgets. Each redb budget covers
its read/write page caches (approximately 90%/10%); it is neither a resident
memory measurement nor a process-wide hard limit. Startup logs report the
requested budgets. `ERGO_MEM_CSV` samples append the effective per-database
budgets, cumulative active eviction counters, and unpersisted pinned AVL bytes.
An unavailable peer/indexer database reports zero budget; zero evictions can
mean no pressure. Choose a new CSV path when upgrading its column schema.

For a constrained comparison, an AVL/state/indexer/peer cache allocation of
16/16/16/1 MiB is a starting experiment, not an optimal mainnet profile. Replay
the same owned snapshot and interval with identical validation and persistence
settings, verifying final roots and reopen before comparing throughput and RSS.

Start with the 1 GiB default for full-mainnet replay, then compare the same
height interval and validation settings before changing it. The
measured cache comparison found no material
benefit from 16, 128 or 1024 MiB budgets on blocks 851..1000: that small AVL
working set fit all three. This supports a smaller budget for that workload,
but does not establish a full-mainnet minimum or optimal budget.

Reserve memory for redb caches, dirty/pinned AVL nodes, download/persist queues
and enabled indexer, wallet and mining work. A live full-validation archive
node with a 2 GiB AVL budget reached approximately 3.9 GiB RSS during the
recorded window. Increasing the budget does not bound these other allocations.
Use RSS/anonymous/file samples, AVL occupancy and queue observations together;
raise the budget only if a matched replay improves performance and the host
has headroom. The linked baseline includes commands for repeating that check.

## `[chain]`

| Key | Type | Default | Description |
|---|---|---|---|
| `script_validation_checkpoint_height` | u32 | network default | Blocks at or below this height skip per-input ErgoScript evaluation (UTXO mutations and the per-block state-root check still run). `0` disables the checkpoint (full validation everywhere). Precedence: CLI `--checkpoint-height` > TOML > the network's embedded default. |
| `script_validation_checkpoint_block_id` | string (hex) | network default | The 32-byte block id pinned at the checkpoint height; asserted on apply, and a mismatch is a hard error. Must decode to exactly 32 bytes. If a height is set with no id and the network has no default, load fails. CLI: `--checkpoint-block-id`. |
| `checkpoint` | table `{ height, block_id }` | absent | **Header-level trust anchor** (Scala `ergo.node.checkpoint`, enforced in header validation by `HeadersProcessor.checkpointCondition`). The header at exactly `height` must have id `block_id`; a header at that height with any other id is rejected as invalid and the peer that sent it is penalised. Headers at every other height are unaffected — the anchor skips **no** validation. Absent by default, matching Scala's `checkpoint = null`; there is deliberately no network default, so an anchored node is always an operator decision. Distinct from `script_validation_checkpoint_*` above, which governs *skipping* ErgoScript evaluation during full-block validation. `height` must be >= 2 (genesis takes its own validation path and is never checked against the anchor) and `block_id` must decode to exactly 32 bytes (an optional `0x` prefix is allowed). Also gates Mode 2 snapshot installs — see [operating.md](operating.md). |
| `devnet_magic` | array of 4 integers | `[7, 7, 7, 7]` | **Devnet only.** The P2P wire magic of the private chain, so several devnets can run side by side or one can join another private network's magic. Rejected for mainnet and testnet, whose magic is fixed. |
| `genesis_id` | string (hex) | network genesis id | The 32-byte genesis header id used for NiPoPoW R5 enforcement. An optional `0x` prefix is allowed; must decode to 32 bytes. The empty string `""` disables the check (development against synthetic chains only) — mainnet runs must leave this at the default. Combining `genesis_id = ""` with `nipopow_bootstrap = true` is rejected. |

## `[api]`

The operator HTTP API. See the security note below before exposing it
beyond loopback.

| Key | Type | Default | Description |
|---|---|---|---|
| `bind` | string (socket addr) | `"127.0.0.1:9099"` | HTTP API bind address. Parsed at load; a malformed value is rejected. A non-loopback bind is rejected unless `public_bind = true`. |
| `disabled` | bool | `false` | When `true`, the API server is not started. Both shipped templates use `false`. |
| `public_bind` | bool | `false` | Permits binding a non-loopback address. A non-loopback `bind` without `public_bind = true` is rejected at load. See the security note below. |
| `local_reverse_proxy` | bool | `false` | Declares a reverse proxy terminating on loopback in front of the API. When `true`, loopback peers lose the v1 rate-limit exemption, Admin requests use the remote warn-and-allow policy, and API transaction submissions use the public mempool budget. Proxied clients share limits by peer IP; see the security notes below. `X-Forwarded-For` is not trusted. |
| `allowed_hosts` | array of string | `[]` | Extra `Host` header values the DNS-rebinding guard accepts, beyond `localhost` / `127.0.0.1` / `::1` / the literal `bind` address (always accepted on a loopback bind). An entry may include a port (`"example.com:9099"`) to pin it, or omit one to match any port. On a non-loopback bind, the guard only activates when this list is non-empty — see the security note below. |

### Webhook state

Operator webhook registrations, HMAC secrets, bounded delivery history and pending
retry state are stored in `<data_dir>/webhooks.redb`. The file uses owner-only
permissions on Unix. Back up this private database with the node data directory.
A failed open, corrupt snapshot or failed commit disables webhook management and
outbound deliveries until restart; other API routes remain available. If the
notification database cannot open or its cursor cannot initialize safely,
live realtime and durable replay are disabled too. See
[notification storage recovery](events.md#recovering-notification-storage)
for backup, compatibility and corruption recovery steps.
On a commit error, RAM changes are rolled back, but a failed disk flush may leave
either atomic snapshot visible after restart. A failed API request can therefore
have persisted; reconcile registrations and delivery history after reopening.

Webhook storage and response serialization run on one owned blocking thread,
started on first use. Up to eight management operations are admitted, including
the running operation; additional requests receive `503 overloaded` with
`Retry-After: 1`. Accepted work finishes even if its HTTP caller disconnects.
Scheduling has separate admission, and each of the 64 possible in-flight sends
reserves capacity for its outcome. Graceful node shutdown joins these writes
and releases the database before returning.

Delivery attempt reservations and acknowledgements commit before they are
reported. After a crash, an attempt whose outcome is unknown may be retried with
the same delivery ID and body, within the 12-attempt delivery budget. A crash
on the final reserved attempt parks its unknown outcome as failed. Consumers
should deduplicate on `delivery_id`.
The delivery ring retains at most 4,096 entries, evicts terminal entries first,
and rejects new deliveries when every retained entry is pending. Realtime cursors
resume above persisted delivery cursors, but event backfill remains in memory;
WS clients receive backfill gap reports. Webhook consumers receive no marker
for pre-admission fanout drops or a saturated backlog, and should periodically
reconcile their state through REST queries.

### `[api.peer_details]`

The Peers dashboard shows handshake identity and mode, sync relationship,
delivery health, connection setup time, traffic totals/rates, and IP metadata.
Handshake values are peer-reported. Connection setup includes TCP/accept through
handshake completion and is not ping latency. V2 supplies a tip-header height;
V1 heights (and V2 fallback observations) are inferred from shared header IDs,
which can understate the remote tip. The drawer shows the actual height source
and age of the last sync observation.

| Key | Type | Default | Description |
|---|---|---|---|
| `auto_download` | bool | `false` | Opt in to HTTPS downloads of the free DB-IP Lite City and ASN databases when the API is enabled. Checks on startup and every 24 hours; downloads each monthly release once per dataset. Validated updates take effect without restarting. Explicit file overrides are never downloaded or overwritten. |
| `reverse_dns` | bool | `false` | Separately opt in to resolving public peer IPs using the OS DNS resolver when the peer API is read. This discloses peer IPs to the resolver. Four concurrent workers, a five-second response deadline, and a bounded 1,024-IP cache. Successful results expire after 24 hours; failures after 15 minutes. |
| `geoip_db` | path | absent | Local DB-IP or compatible MaxMind City/Country `.mmdb` override. City adds region, city and approximate coordinates; time zone and accuracy radius appear only when supplied by the database. Relative paths use the node data directory. Without an override, uses an existing `geoip/dbip-city-lite.mmdb` cache. |
| `asn_db` | path | absent | Local DB-IP or compatible MaxMind ASN `.mmdb` override for ASN, network organization and network prefix. Relative paths use the node data directory. Without an override, uses an existing `geoip/dbip-asn-lite.mmdb` cache. |

**Default privacy behavior:** native peer details and installed local database
lookups remain available. Neither dataset downloads nor reverse-DNS queries run
unless explicitly enabled. No peer IP is sent to a geolocation service. Turning
downloads off and restarting stops update requests while keeping cached local
data usable. Other normal node networking (P2P, seed discovery, etc.) is unaffected.

To enable free location and ASN data, edit the settings in your existing config
and restart (in the shipped templates these are dotted keys under `[api]`):

```toml
[api.peer_details]
auto_download = true
reverse_dns = false
```

The [DB-IP Lite City](https://db-ip.com/db/download/ip-to-city-lite) and
[DB-IP Lite ASN](https://db-ip.com/db/download/ip-to-asn-lite) datasets require no
account or API key and are distributed under
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). The Peers dashboard
includes the required DB-IP attribution link when showing their data. Applications
reusing this data from the peer API must also retain attribution. The data is
optional and is not bundled with the node binary.

Downloads contact `download.db-ip.com` over HTTPS, revealing the node's outbound
IP to the provider, but never include peer addresses. Redirects are rejected.
Compressed/decompressed size caps are 128/512 MiB for City and 32/128 MiB for ASN;
each request has a three-minute deadline. Gzip integrity, MMDB structure, database
type and build-date regression are checked before atomic replacement. Temporary
files share the cache directory, so allow space for old and new copies during
updates. The `.release` sidecars record the installed month. Failed updates keep
the prior database and retry after 24 hours; the node continues syncing throughout.
If there is no prior data, the WebUI shows downloading or unavailable status.

For offline setup, configure `geoip_db` and `asn_db` to files you install yourself,
leaving both booleans false. Local overrides also support
[MaxMind databases](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/)
obtained under their terms. Overrides load at startup; restart after replacing
them or changing config. An invalid override reports an error and does not fall
back to a network download. Local/special IPs are excluded from DNS and database
lookups. Database type and build date appear in the peer drawer. Country and city
describe an approximate network endpoint, not a verified operator location. An
ASN organization is the network operator and need not be the node operator or
retail ISP. These display-only details never affect peer selection or scoring.

Realtime subscriptions, mempool-depth sampling, and the webhook registry belong
to one node, including when several nodes run in one process. Router construction
starts no background workers; the API listener owns them and stops them at
shutdown. Delivery permits only public
DNS destinations by default, checks every resolved address before connecting,
and disables redirects and environment HTTP proxies so those checks also apply
to retries and cannot be bypassed by alternate routing.

### `[api.security]`

| Key | Type | Default | Description |
|---|---|---|---|
| `api_key_hash` | string (hex) | none | Lowercase Base16 of `Blake2b256(<secret>)`. Optional; privileged routes fail closed when absent. Must be exactly 64 lowercase hex characters (`0-9`, `a-f`); uppercase or mixed case is rejected for canonical-form parity. Supplied hashes are validated even when the API is disabled. |
| `keys` | array of tables | `[]` | Named scoped credentials; use `[[api.security.keys]]` as described below. Requires a master `api_key_hash`. |
| `allow_unauthenticated_legacy_mining` | bool | `false` | Explicit Scala/Lithos compatibility: permits unauthenticated `GET /mining/candidate`, `POST /mining/solution`, and reward address/public-key reads. Requires `api_key_hash` when the API is enabled. Supplied-transaction candidate endpoints and all v1 operator routes remain authenticated. |

`[[api.security.keys]]` defines named credentials with `id`, `hash`, `scopes`
(`mining`, `wallet`, `operator`, `admin`) and `revoked` (default `false`). Scoped
keys require a master hash. Set `revoked = true` for denial that survives a data
wipe or old backup restore; API revocations use a data-directory ledger.
Scoped `mining` keys authorize `POST /mining/candidateWithTxs`,
`POST /mining/candidateWithTxsAndPk` and
`POST /api/v1/mining/candidate-with-txs`. These supplied-transaction routes
require a key even when `allow_unauthenticated_legacy_mining = true`. The flag
is boot-only; runtime `PATCH /api/v1/node/config` changes only `api_limits`
and `readiness`.

### `[api.limits]` and `[api.readiness]`

| Limit key | Default | Meaning |
|---|---|---|
| `refill_per_sec` | `20.0` | Tokens added per second. |
| `burst` | `40.0` | Maximum bucket size; must admit each request class. |
| `cheap_weight` | `1.0` | Tokens per cheap read. |
| `heavy_weight` | `4.0` | Tokens per heavy read. |
| `compute_weight` | `10.0` | Tokens per compute request. |
| `max_tracked_ips` | `65536` | Bucket table bound (`1..1000000`). |
| `idle_prune_after_secs` | `600` | Idle bucket retention (`1..86400`). |

| Readiness key | Default | Meaning |
|---|---|---|
| `heartbeat_max_age_ms` | `600000` | Maximum idle action-loop heartbeat age. Active applies below the 600-second stuck threshold remain live. |
| `snapshot_max_age_ms` | `30000` | Maximum runtime snapshot age. |
| `tip_max_age_ms` | `7200000` | Maximum chain-tip age; two hours accommodates normal block gaps. |
| `require_indexer` | `false` | Require a healthy indexer caught up to the chain. |
| `require_wallet` | `false` | Require a healthy wallet caught up to the chain. |

Rates/weights must be finite and positive. Age thresholds accept
`1000..86400000` milliseconds. Limits and readiness can also be changed for the
current process with `PATCH /api/v1/node/config`. Authentication, proxy trust
and other boot settings require a restart. Probes have their own unthrottled
mount. See [operator controls](operator-controls.md) for scope assignments,
revocation durability and runtime patch examples.

### `[api.script]`

Native script endpoints under `/api/v1/script/*` use this policy. It does not
change authentication on the Scala-compatible `/script/p2sAddress` and
`/script/p2shAddress` routes.

| Key | Type | Default | Description |
|---|---|---|---|
| `require_api_key` | bool | `false` | Require a configured API credential for all seven native script endpoints. When enabled without a configured hash, those endpoints fail closed. |
| `max_cost` | u64 | `8001091` | Maximum native reduction cost; accepts `1..=8001091`. A request can lower the limit, and cannot raise it above this policy. Invalid values reject configuration even when the API is disabled. |

Compilation and reduction use a per-node compute pool with two running jobs,
eight waiting jobs, a two-second queue wait and a thirty-second response
deadline. Scala-compatible P2S/P2SH compilation shares that pool. Queue pressure
returns HTTP 503 with `Retry-After: 1`. A response timeout or disconnected client
does not stop an accepted blocking job: it retains its slot until execution
finishes, and shutdown drains accepted jobs. Point and scan read lanes use
sixteen/four running jobs and sixty-four/sixteen waiting jobs respectively.
These resource limits are code defaults rather than TOML keys.

### Security notes for the API

The API distinguishes public routes from privileged routes:

| Privileged (require a configured hash and valid `api_key`) | Public (no key required) |
|---|---|
| `/wallet/*`, `/scan/*`, `/api/v1/wallet/*` | Dashboard `/`, `/wallet/ui*` redirects, swagger |
| `POST /node/shutdown`, `POST /api/v1/node/shutdown`, `POST /peers/connect`, `POST /api/v1/votes`, `POST /blocks` | Read REST, including `GET /api/v1/votes`, `/info`, `/blocks/*`, `/peers/*`, `/blockchain/*` |
| `/mining/*` (including supplied-transaction candidates; the four legacy routes can be explicitly opened as above) | Transaction submission/checks: `POST /transactions`, `/transactions/bytes`, `/transactions/check`, `/transactions/checkBytes`, `/api/v1/mempool/{submit,check}` |
| v1 Operator/Admin routes (node config, network controls, mining controls, operator votes, scans, account management/PSBT, watch writes, private-key export, webhooks); script compute when configured to require a key | Public v1 queries including watch-only account reads, `/emission/*`, `/utils/*`, `/metrics` |

The whole wallet, scan and node prefixes are gated, including unknown subpaths;
other unmatched paths return `404`. Public means no API-key authentication;
normal validation, subsystem availability and admission policies still apply.

Use `POST /wallet/lock` and `POST /wallet/deriveNextKey` for these wallet
mutations. Their GET forms remain available for Scala-compatible clients;
both methods use the same handlers and require the configured API key.

Transaction submission is public in Scala (`TransactionsApiRoute.scala:174-209`).
Block submission requires an API key, matching Scala (`BlocksApiRoute.scala:127`). This node gates all four mining routes above;
Scala leaves those four open (`MiningApiRoute.scala:45,77,86,98`).

Consequences:

- **Absent hash means privileged routes are closed, including on loopback.**
  Compat/native privileged mounts return `403` with reason
  `api-key-not-configured` and detail
  "API key not configured: set [api.security] api_key_hash (see docs/configuration.md)".
  The v1 tier gate returns its `401 unauthorized` envelope with the same guidance.
  Once configured, the header name is `api_key` (lowercase, underscore), checked
  in constant time; a missing/wrong key retains the existing invalid-key response.
- **`public_bind = true` exposes the submission and read surface to the
  network.** Binding `0.0.0.0` with `public_bind = true` makes
  transaction submission and `/metrics` world-callable.
  For remote operator access, prefer binding loopback and fronting the
  node with an authenticated reverse proxy. On a public bind, transaction
  submissions are automatically charged against the shared
  `global_cost_budget` (not `local_reserved_cost_budget`) so an
  unauthenticated flood on this surface cannot exhaust the reserve the
  operator's own loopback tooling relies on — see `[mempool]`'s
  `local_reserved_cost_budget` below.
- **`/metrics` is not authenticated.** Keep it on loopback or behind a
  proxy.
- **Set `local_reverse_proxy = true` when a reverse proxy connects to a
  loopback API bind.** This flag does not authenticate clients or unlock privileged
  routes; configure client authentication at the proxy separately. Client identity comes only from the real peer socket;
  the node never trusts `X-Forwarded-For`. All clients through the same proxy
  peer IP (usually `127.0.0.1`, or `::1`) share **one v1 governor bucket**:
  default burst 40 tokens, refill 20 tokens/second, Compute requests costing
  10 tokens each. Direct local operator access also loses its loopback
  exemption and shares that bucket when using the same peer IP. Apply
  per-client rate limits at the proxy and size aggregate traffic for this
  budget. Raising governor limits requires changing the server's
  `GovernorConfig`; these limits are not currently exposed in TOML.
- **Realtime connections also share the proxy's peer IP.** The fixed
  `MAX_SOCKETS_PER_IP = 16` cap applies across all proxied clients using that
  IP, including direct local connections from that IP. This socket cap uses
  peer identity regardless of `local_reverse_proxy`; budget concurrent
  WebSocket clients accordingly. Proxy rate limiting does not raise the cap.
- **A declared proxy routes all API transaction submissions through the
  public mempool budget**, including direct local submissions. At boot,
  `api_publicly_bound` becomes true and admission uses `TxSource::PublicApi`
  (shared `global_cost_budget`) rather than `TxSource::Api`
  (`local_reserved_cost_budget`), even though the API binds to loopback.
- **Admin operations remain authenticated and warn-and-allow in production.**
  With `local_reverse_proxy = true`, loopback requests use the remote Admin
  policy and emit a warning after a valid API key is supplied. The setting
  does not enable `admin_hard_deny_nonloopback` or block authenticated Admin
  operations; restrict remote Admin access at the proxy if needed.
- **The `Host` header is checked to close the DNS-rebinding read path.**
  A loopback bind (the default) rejects any request whose `Host` header
  isn't `localhost`, `127.0.0.1`, `[::1]`, the literal `bind` address, or
  an `allowed_hosts` entry, with `421 Misdirected Request` — this stops
  attacker-controlled JavaScript on a rebound domain from reading the
  unauthenticated surface (`/info`, `/blocks/*`, `/peers/*`, …) via a
  victim's browser hitting `127.0.0.1:9099`. A rebinding page can also
  send an `api_key` header under its same-origin hostname: privileged routes
  rely on a secret key, with the Host guard adding defense in depth.
  A request with no `Host` header or HTTP/2 `:authority` is allowed
  (HTTP/1.0 tooling). On a non-loopback bind the guard only activates
  when `allowed_hosts` is non-empty — most public deployments front the
  API with a reverse proxy that already validates `Host`/SNI, and
  enforcing here by default would risk breaking that setup for no
  defensive gain.

Generate a random API secret with the standalone command (no config or data
directory is needed):

```sh
ergo-node api-key generate --secret-file ./api-secret.key
```

The command saves a new 64-character lowercase hex secret in `api-secret.key`
and prints only its configuration hash:

```toml
[api.security]
api_key_hash = "<64 lowercase hex hash>"
```

Paste the printed section into your config (or add the hash to an existing
`[api.security]` section), then restart the node. Send the **secret**, never
the hash, in the `api_key` header or enter it in the dashboard. Keep the secret
file safe: it is created with mode `0600` on Unix. On Windows it inherits the
parent's ACL; choose a directory only you can read. The parent directory must
already exist (it may be reached through a symlink). Generation refuses any
existing destination, including a symlink, and removes the new file if writing
it fails. Use a new file path for each new credential.
The command does not edit your config or initialize node data.

To hash an existing secret without writing any files:

```sh
ergo-node api-key hash --secret-file ./api-secret.key
# Or pipe a secret into: ergo-node api-key hash --stdin
```

Hashing accepts 1–1024 printable non-space ASCII bytes, removes exactly one
trailing LF or CRLF, and rejects other whitespace, controls and non-ASCII
bytes. Both modes support `--json`; output includes `schema_version: 1` and
`api_key_hash`, plus `secret_file` for generation, and never includes the secret.
The shipped templates contain no credential; privileged routes stay locked
until you configure a hash and restart. The API is already enabled.

As in Scala, a running node can also hash a secret: `POST /utils/hash/blake2b`
with the secret as a JSON string returns the same `api_key_hash`. Use it only
over loopback (the secret travels in the request), and generate the secret
randomly rather than choosing a memorable one.

**Upgrade:** operators running the bundled file directly lose the old known
`hello` key. Privileged calls using it now fail until they set their own
`[api.security] api_key_hash`. Existing explicitly configured hashes keep their
behavior.

## `[mempool]`

Only operator-facing knobs are exposed. Internal tuning parameters
(CPFP family limits, revalidation rates, notifier cadence,
unresolved-cache sizing, the staging capacity/fairness caps) are
deliberately not configurable; supplying one of those keys is a parse
error because this section rejects unknown keys. The CPFP family bounds in
particular stay pinned because they mirror Scala `OrderedTxPool` and
changing them changes pool ordering and eviction cascades. The mempool is
force-disabled — regardless of `disabled` — whenever the node has no UTXO
box state, i.e. under `state_type = "digest"` or
`verify_transactions = false`.

The cost budgets below are anti-DoS bounds on how much script-evaluation
work the node will do per block. They are node-local policy: they never
affect which blocks the node accepts, and the Scala reference node has no
equivalent gate on this path at all. `global_cost_budget` is a pool shared
by peers and local submissions; `local_reserved_cost_budget` is an extra
slice only TRUSTED local submissions can reach, and which they spend first.
The per-block total is therefore bounded at the sum of the two.

"Trusted local" here means `TxSource::Wallet` and, for the API path,
`TxSource::Api` — a `POST /transactions*` / `/api/v1/mempool/{submit,check}`
request that arrived while `[api] bind` is loopback. That last qualifier
matters: the `api_key` gate never covers submission routes (see the `[api]`
security note above — they are unauthenticated by design), so the only
signal the node has for "is this really the operator's own tooling" is
whether the listener is reachable from outside the machine at all. Once an
operator sets `[api] public_bind = true` with a non-loopback `bind`, a
submission on that listener is indistinguishable from arbitrary internet
traffic and is classified `TxSource::PublicApi` instead — it contends for
`global_cost_budget` exactly like peer traffic and can never reach
`local_reserved_cost_budget`. Without this distinction, exposing the API
publicly would let any unauthenticated caller flood the reserve the
operator's own wallet submissions depend on.

Two cross-field rules are enforced at load, and only against keys you set
explicitly (lowering `global_cost_budget` alone never fails the boot over a
defaulted key): `per_peer_cost_budget` must not exceed
`global_cost_budget`, and `local_reserved_cost_budget` must not exceed four
times it.

| Key | Type | Default | Description |
|---|---|---|---|
| `disabled` | bool | `false` | When `true`, skip transaction relay (useful for archival or sync-test runs). CLI flag: `--mempool-disabled`. |
| `reject_storage_rent_txs` | bool | `true` on mainnet; `false` on testnet/devnet | Decline transactions with any empty-proof input carrying extension variable 127, including mixed transactions. Set `false` to relay rent claims. Admission policy only: valid claims in blocks and miner self-claims remain allowed. |
| `sort_policy` | string | `"cost"` | Pool priority ordering: `"cost"`, `"size"`, or `"min"`. An unknown value is rejected at load. CLI flag: `--mempool-sort`. |
| `max_pool_size` | usize | `1000` | Maximum transaction count. Must be at least 1. |
| `max_pool_bytes` | usize | `67108864` (64 MiB) | Maximum total pool size in bytes. Must be at least 1. |
| `min_relay_fee_nano_erg` | u64 | `1000000` | Minimum relay fee in nanoERG; also the floor for `/transactions/getFee`. |
| `max_tx_size_bytes` | usize | `98304` (96 KiB) | Maximum single-transaction size. Must be at least 1. |
| `max_tx_cost` | u64 | `4900000` | Maximum single-transaction cost (matches the Scala mainnet override). Must be at least 1. |
| `ibd_gate_block_lag` | u32 | `10` | Block-lag threshold that gates mempool admission while the node is still catching up during initial sync. |
| `rebroadcast_count` | usize | `3` | Number of surviving unconfirmed transactions re-advertised per tip-change recheck (Scala `MempoolAuditor` `rebroadcastCount`). Re-broadcast rotates oldest-`last_checked_at` first. `0` disables re-broadcast. |
| `global_cost_budget` | u64 | `12000000` | The shared per-block validation-cost pool. Peers draw on it, and so does local work once its reserve is gone. Once spent, every peer is refused until the next block. Must be at least 1. |
| `per_peer_cost_budget` | u64 | `10000000` | Per-block validation-cost budget a single peer may spend, within `global_cost_budget`. Must be at least 1, and not more than `global_cost_budget` when set explicitly (a larger value could never bind). |
| `local_reserved_cost_budget` | u64 | `4900000` (one `max_tx_cost`) | Extra per-block validation-cost slice for TRUSTED node-local submissions (wallet, and API submissions on a loopback `[api] bind`), spent **before** the shared pool and reachable by nothing else. A peer flooding the node cannot starve the operator's own transactions — at least one maximum-cost local transaction is always validated per block. Local work beyond the reserve competes with peers for what is left of `global_cost_budget`, so the per-block total never exceeds the sum of the two. `0` restores a single shared pool, i.e. peer traffic can again block local submissions. When set explicitly it may not exceed four times `global_cost_budget`. **Not reachable by API submissions on a `public_bind = true` (non-loopback) bind** — those are unauthenticated by design and are charged against `global_cost_budget` instead, alongside peer traffic. |
| `invalidation_cache_size` | usize | `10000` | Maximum remembered invalidated transaction ids. Matches Scala `invalidModifiersCacheSize`. Must be at least 1. |
| `invalidation_ttl_seconds` | u64 | `14400` (4 h) | How long an invalidated transaction id is remembered and its re-download suppressed. Matches Scala `invalidModifiersCacheExpiration = 4h`. Must be at least 1. Ergo transaction ids do not cover spending proofs, so a peer can invalidate an id by relaying a proof-corrupted variant of a transaction that has not been seen yet; the honest transaction is then refused for this long. The window is identical in the reference node, so shortening it here is a deliberate divergence — it trades that exposure for more re-validation of genuinely invalid transactions. |
| `cleanup_cost_mult` | u64 | `6` | Per-pass cost budget for the tip-revalidation (recheck-and-evict) pass, as a multiplier on the live `max_block_cost`. Transactions not reached in a pass are deferred to later blocks, oldest-checked first. Must be at least 1 (`0` would disable the pass). |
| `staging_enabled` | bool | `false` | Master switch for the staging pool: orphan/held-parent staging, package admission, and package RBF. Off by default; when off, admission behaves exactly as it did before staging existed. The staging capacity/fairness caps are internal tuning and not configurable. |

## `[indexer]`

The opt-in `/blockchain/*` extra-index surface. When disabled (the
default), `/blockchain/*` returns 404 (a deliberate divergence from the
Scala reference, which returns 503). When enabled, the indexer opens its
own database file under the data directory and runs a polling task that
follows the chain tip.

| Key | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `false` | Mounts `/blockchain/*` and spawns the polling task. Requires the full archive: incompatible with `blocks_to_keep >= 0`, with `utxo_bootstrap = true` (Scala rule R2), and with `state_type = "digest"`. |
| `poll_idle_ms` | u64 | `1000` | Idle poll interval (ms) when the tip has not advanced. Must be at least 1. |
| `db_filename` | string | `"indexer.redb"` | Indexer database filename under the data directory. Must be non-empty after trimming. |

## `[mining]`

The external-miner subsystem and its `/mining/*` routes. Disabled by
default. Field-level defaults below apply when the `[mining]` section is
present; if the section is entirely absent the subsystem stays disabled
either way.

| Key | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `false` | Enables the external-miner subsystem and mounts `/mining/*`. Rejected when `state_type = "digest"` (candidate generation needs UTXO state). CLI flag `--mining-enabled` forces it on. |
| `miner_public_key_hex` | string (hex) | none | 33-byte compressed secp256k1 public key (66 hex chars) for the reward output. **Optional in embedded mode**: when set, it is the pinned reward pubkey; when omitted, the wallet's EIP-3 first-address key is resolved at candidate time. It is **required when `[wallet] mode = "external"` and mining is enabled**, because external mode has no wallet tables to resolve. A value that is present must be well-formed (66 hex chars → 33 bytes) or load fails. CLI flag: `--mining-public-key`. |
| `block_candidate_generation_interval_ms` | u64 | `250` | Minimum interval (ms) between same-parent mempool-refresh signals; must be at least 50. The first pool change after a quiet interval signals immediately. Changes within the interval share a deadline and refresh the latest pool snapshot when it expires, independently of the mempool polling tick. Applied-parent changes bypass this interval; header-only changes do not rebuild work once mining has started. Lower values refresh transaction contents sooner but increase build load and churn of the 16 retained templates. |
| `use_external_miner` | bool | `true` | Must be `true` — an internal CPU miner is not supported, so `false` is rejected at load. |
| `candidate_base_cache` | bool | `false` | With the default `false`, candidate proofs load only authenticated AVL operation paths from the committed snapshot and retain no full-tree graph between builds. Legacy v1 nodes without child labels may require subtree reads. Setting `true` enables the alternative cache of the hydrated AVL working set between candidate builds, keyed on the committed tip. Same-tip rebuilds reuse the tree and loaded paths; transaction validation and proof generation for changed transaction sets still run. Independently of this setting, the worker can reuse a prior state root and proof for an identical applied parent and ordered transaction bytes after fresh transaction validation. When the committed tip moves, the engine walks back at most six headers to the cached tip or to one of up to three retained ancestor trees, and replays the stored blocks from there. It checks each block's state root against its header and the final root against the committed state. This covers growth by a few blocks and reorgs up to three deep. Full rehydration remains the fallback beyond that window, and on missing data, decode or prover errors, or digest mismatches. Holds the full UTXO AVL node graph resident — multi-GB on a mainnet archival node, scaling with the UTXO-set size — so enable it only on a mining node with RAM headroom. |
| `claim_storage_rent` | bool | `false` | When `true`, the node sweeps storage-rent-eligible boxes into a self-claim transaction paid to the miner's reward key, inserted ahead of mempool selection so any conflicting fee-bearing claim on the same box is excluded. Opt-in: it changes block contents and seizes rent to the miner. Requires `[indexer] enabled = true` (see cross-section rules). While the index backfills, enumeration may be partial but never claims an invalid box — a lagging index only under-collects. |
| `max_storage_rent_claims` | u32 | `4096` | Safety ceiling on the number of storage-rent boxes swept into one block's self-claim. The block's cost and size budgets are the real binding limit (typically ~3,700 boxes by cost on mainnet); this cap prevents unbounded iteration. Lower it to leave more room for fee-paying user transactions. Only meaningful when `claim_storage_rent = true`. |

The node also accepts authenticated `POST /mining/candidateWithTxs` (a JSON
transaction array) and `POST /mining/candidateWithTxsAndPk` (`{"txs": [...],
"pk": "<compressed public key>"}`). Valid supplied transactions are selected
in request order ahead of automatic rent claims and mempool transactions. They
may have no fee and may spend earlier package outputs; they still undergo full
consensus validation and block cost/size limits. Invalid or nonfitting members
are omitted. The returned `proof.msgPreimage` and `proof.txProofs` prove the
members actually included in the final candidate. The v1 equivalent accepts
either request shape at `POST /api/v1/mining/candidate-with-txs`.

Requests are limited to 1024 transactions and 2 MiB, with at most two packages
queued or building. Builds run on the existing serial worker and cancel when
the caller disconnects or the tip changes. Requested jobs retain their own
bounded history (16 templates) independently of ordinary refreshes; solo reads
always use the operator's reward key. Explicit-key jobs must submit that key.
See [Lithos integration](lithos.md) for client configuration and keystore export.

Storage-rent claims enforce distinct context-extension variable 127 values from height 1,885,000 on every network, matching Scala 6.0.7. This consensus check applies to blocks regardless of `reject_storage_rent_txs`. The self-collector gives each fully consumed input a separate miner output from that height; if proceeds cannot cover the additional outputs' dust floors, the batch is skipped. Earlier blocks retain the historical rules.

## `[voting]`

On-chain protocol-parameter voting. When this node mines, each block it
produces casts up to two votes (`Parameters.ParamVotesCount = 2`) nudging the
configured parameters one step per block toward your target value. The node
only ever casts votes that the consensus header-vote rules accept (at most two
parameter votes, no duplicates or contradictions, and only known increases at
an epoch-start block); a parameter already at its target — or already at its
`min`/`max` bound — casts no vote. Soft-fork voting and `blockVersion` (123)
are **not** operator-settable here.

`GET /api/v1/votes` shows the live votable set with each parameter's current
value, step, and bounds, plus the votes this node is configured to cast.

Non-empty targets require `[mining] enabled = true` — configuring voting with
mining off is a startup error (the votes would never be cast).

### `[voting.targets]`

A map of canonical parameter **name** → desired integer value. An unknown or
non-votable name is a startup error.

| Votable name | Vote id | Meaning |
|---|---|---|
| `storageFeeFactor` | 1 | nanoErg per byte per storage-rent period |
| `minValuePerByte` | 2 | Minimum box value per byte |
| `maxBlockSize` | 3 | Maximum block size (bytes) |
| `maxBlockCost` | 4 | Maximum block cost (JIT cost units) |
| `tokenAccessCost` | 5 | Per-token access cost |
| `inputCost` | 6 | Per-input cost |
| `dataInputCost` | 7 | Per-data-input cost |
| `outputCost` | 8 | Per-output cost |
| `subblocksPerBlock` | 9 | Sub-blocks per block (only active post-EIP-37) |

```toml
[voting.targets]
maxBlockSize = 2097152
storageFeeFactor = 1250000
```

## `[wallet]`

| Key | Type | Default | Description |
|---|---|---|---|
| `mode` | string | `"embedded"` | Wallet ownership mode. `"embedded"` keeps the existing wallet writer, secret storage, hydration, and apply hook. `"external"` does not open wallet secrets, hydrate wallet state, start the writer, or install the wallet apply hook; wallet-owned HTTP routes return `410` with `reason = "wallet_moved"` and the configured daemon address. |
| `daemon_address` | string | `"http://127.0.0.1:9090"` | Address returned by external-mode wallet route responses. It is informational routing guidance; the node does not proxy requests to it. |
| `expose_private_keys` | bool | `false` | When `true`, `POST /wallet/getPrivateKey` returns the derived secret scalar for an address; otherwise that route returns `403 Forbidden`. Setting this `true` lets any authenticated `api_key` request extract per-address private material. |

## `[logging]`

| Key | Type | Default | Description |
|---|---|---|---|
| `default_level` | string | `"info"` | Tracing filter used when the `RUST_LOG` environment variable is unset. Validated as a filter expression; an invalid value is rejected. `RUST_LOG` takes precedence at runtime. |
| `format` | string | `"text"` | Log output format: `"text"` (line-oriented) or `"json"` (one object per line). An unknown value is rejected. |
| `file` | table | none | Presence of a `[logging.file]` table enables rolling-file output. Absent = stderr only. |

### `[logging.file]`

| Key | Type | Default | Description |
|---|---|---|---|
| `dir` | string (path) | `<data_dir>/logs` | Directory for rotated log files. Relative paths resolve against `data_dir`; absolute paths are used as-is. |
| `prefix` | string | `"ergo-node"` | Log filename prefix. Must not contain a path separator (`/` or `\`). |
| `rotation` | string | `"daily"` | Rotation cadence: `"minutely"`, `"hourly"`, `"daily"`, or `"never"`. An unknown value is rejected. |
| `max_files` | usize | `14` | Number of rotated files retained; older files are deleted on rotation. Must be at least 1. |

## CLI-only flags

These flags have no `ergo-node.toml` equivalent:

| Flag | Type | Default | Description |
|---|---|---|---|
| `--config`, `-c <path>` | path | `<data_dir>/ergo-node.toml` | Config file location. |
| `--ibd-flush-interval <N>` | u32 | `500` | Durability-flush cadence (in blocks) during initial sync; `0` = always durable. On a hard crash, up to `N` blocks replay from peers. |

The flags `--network`, `--data-dir`, `--peers`, `--cache-bytes`,
`--checkpoint-height`, `--checkpoint-block-id`, `--mempool-disabled`,
`--mempool-sort`, `--mining-enabled`, and `--mining-public-key` override
their TOML counterparts as described in the tables above.

## Cross-section consistency rules

Several rules mirror the Scala reference node's `consistentSettings`
checks and are enforced at load:

- **R1** — `verify_transactions = false` requires `state_type = "digest"`.
- **R2** — `[indexer] enabled = true` is incompatible with
  `blocks_to_keep >= 0` and with `utxo_bootstrap = true` (the extra-index
  requires a full archive).
- **R3** — `nipopow_bootstrap = true` requires `utxo_bootstrap = true`
  OR `blocks_to_keep >= 0`.
- **R5** — `nipopow_bootstrap = true` requires a configured genesis id
  (cannot use `genesis_id = ""`).
- The digest backend additionally rejects `[mining] enabled = true` and
  `[indexer] enabled = true`, and requires one of the Mode 5 or Mode 6 combinations above.
- `[mining] claim_storage_rent = true` requires `[indexer] enabled = true`
  (the eligible-box scan reads the extra-index).
- `[voting.targets]` set with `[mining] enabled = false` is rejected — the
  votes are only ever cast by blocks this node mines.
- `[wallet] mode = "external"` with `[mining] enabled = true` requires
  `[mining].miner_public_key_hex`; wallet-backed reward-key resolution is
  available only in embedded mode.

## Minimal example

A minimal mainnet full-archive node with public API enabled and privileged routes locked:

```toml
network = "mainnet"
# data_dir defaults to ./ergo-data

[peers]
known = ["213.239.193.208:9030", "159.65.11.55:9030"]

[api]
disabled = false
bind = "127.0.0.1:9099"

# To unlock privileged routes, generate a random secret and hash it as
# described above, then add the generated value here and restart:
# [api.security]
# api_key_hash = "<64 lowercase hex characters>"
```

For the full set of keys, comments, and a fast clean-database boot
configuration (Mode 2 + NiPoPoW), see the bundled config at
[`../ergo-node/ergo-node.toml`](../ergo-node/ergo-node.toml) and the
operator template at
[`../ergo-node/ergo-node.toml.example`](../ergo-node/ergo-node.toml.example).
Configuration is unstable until 1.0; keys and shapes may change between
minor versions — see [`./compatibility.md`](./compatibility.md) for the
versioning policy.

---

# `ergo-walletd.toml`: the standalone wallet daemon

Everything above configures `ergo-node`. This section configures
`ergo-walletd`, the separate wallet daemon documented in
[`codemap/ergo-walletd.md`](./codemap/ergo-walletd.md). A daemon config is read
only by `ergo-walletd --config <path>`, and its schema is strict
(`deny_unknown_fields`), so a node key pasted into a daemon config is a hard
parse error rather than a silently ignored line.

The default watch-only reference config ships at
[`../ergo-walletd/ergo-walletd.toml`](../ergo-walletd/ergo-walletd.toml).
[`../ergo-walletd/ergo-walletd-seed.toml`](../ergo-walletd/ergo-walletd-seed.toml)
shows the opt-in encrypted seed mode. The config schema rejects
unknown fields and combinations that mix descriptor and seed ownership.

`mode = "watch_only"` imports public descriptors and exposes the existing
read API without opening secret storage. `mode = "seed"` hosts the shared
wallet engine for encrypted seed lifecycle, transaction construction, signing,
submission, scans/rescans and durable private mining jobs. In both modes an
independent credential protects all local reads and writes. Seed-mode native balance reads
can include an explicitly requested mempool delta; watch-only reads remain
confirmed-only.

## `ergo-walletd.toml` top-level keys

| Key | Type | Default | Description |
|---|---|---|---|
| `mode` | string | `"watch_only"` | `"watch_only"` requires a public `descriptor_file`. `"seed"` rejects `descriptor_file`. Both require `local_api_key_file`. CLI: `--mode <watch-only\|seed>`. |
| `network` | string | `"mainnet"` | Required network identity: `"mainnet"` or `"testnet"`. Any other value (including `devnet`) is a load error. It selects the base58 address prefix used for descriptor validation and for every address the local API returns, so it **must** match the network the configured `node_url` serves — the daemon cannot infer that from the node. CLI: `--network`. |
| `data_dir` | string (path) | none (required) | Directory holding `wallet.redb`. Seed mode also stores encrypted secret files under `wallet/`. Use a fresh, separate directory when creating a seed wallet; there is no automatic migration from an embedded or descriptor wallet. Created on first start. |
| `node_url` | string (URL) | none (required) | Base URL of the node API. Watch-only mode reads `/api/v1/chain/{tip,snapshot,blocks-since,boxes/:id}`. Seed mode also uses coherent spending context, tip-bound block replay, transaction admission/submission and `/api/v1/mining/private-transactions` queue operations. Must be `http`/`https` with a host and no credentials, query, or fragment. Plain `http` is accepted only for a loopback host (`localhost`, `127.0.0.0/8`, `::1`), because the node credential travels in a header; a remote node needs `https`. CLI: `--node-url`. |
| `node_ca_file` | string (path) | none | PEM bundle of the certificate authorities trusted for an `https` `node_url`. When set, the system roots are not trusted, so only a node certificate chaining to these CAs is accepted. Requires an `https` `node_url`; validated at load. |
| `api_key_file` | string (path) | none (required) | File containing the node's `api_key` request-header value. Scoped credentials need `wallet`; seed private mining jobs additionally need `operator`. An `admin` credential or the legacy master key also authorizes these requests. Must be a regular file that is **not** group- or other-readable (`chmod 600`); anything else aborts startup. The value is held in a `Debug`-redacted type, sent only as a header, and never logged. Size-capped at 4 KiB, and the content must be a single header-safe line. CLI: `--api-key-file`. |
| `descriptor_file` | string (path) | none | Required in `watch_only` mode and rejected in `seed` mode. Public descriptor file (see [Descriptor file](#descriptor-file)); size-capped at 16 MiB and validated at load. CLI: `--descriptor-file`. |
| `local_api_key_file` | string (path) | none (required) | Independent local `api_key` credential protecting every local API request in both modes, on both Unix and TCP listeners. Watch-only balances, addresses and history are as private as a seed wallet's. Uses the same file-permission, size and header-value checks as `api_key_file`; the two files must contain different credentials. Never forwarded to the node. CLI: `--local-api-key-file`. |
| `sync_interval` | u64 or string | `15` | Delay after completed sync passes or retryable errors; incomplete passes continue immediately. Accepts plain seconds (`15`) or a duration string (`"500ms"`, `"30s"`, `"2m"`, `"1h"`). `0` is rejected. CLI: `--sync-interval`. |
| `shutdown_timeout_secs` | u64 | `5` | Maximum seconds to wait for a cancelled sync worker during shutdown. Must be greater than zero. Cancellation prevents subsequent requests and block application; an in-flight blocking HTTP request can finish after the deadline. |
| `sync_batch` | u32 | `256` | **Apply budget**: the maximum number of blocks *applied* (committed to the wallet database) by one sync pass. Must be `1..=1024`. It is not a request size — a pass may reach the node tip through many HTTP calls, and it is not what bounds a single response. Larger values trade memory and pass latency for fewer passes. CLI: `--sync-batch`. |
| `blocks_page` | u32 | `1` | **Request budget**: the maximum number of blocks asked for in a single `blocks-since` call, independent of `sync_batch`. Must be `1..=1024`. The wire form hex-encodes every transaction and output box, so a page of `N` blocks costs roughly four times their serialized bytes and must fit the daemon's hard 16 MiB response cap. The default `1` is the largest page whose *worst legal* body provably fits that cap (see [The two sync budgets](#the-two-sync-budgets)); raising it is an operator decision made against their own node's `maxBlockSize`. A block too large even for a one-block page is a terminal error naming the cap and the page — the daemon never retries with a smaller page. CLI: `--blocks-page`. |
| `unix_socket` | string (path) | none | Path of the owner-only Unix socket serving the local API. Both modes require the local credential on every request. See [Socket permissions](#socket-permissions). CLI: `--unix-socket`. |
| `tcp_fallback` | string (socket addr) | none | Optional loopback TCP listener for the local API. A non-loopback bind is rejected at load. Both modes require the same local credential used on the Unix socket. Alias: `tcp_addr`. CLI: `--tcp-fallback`. |

At least one of `unix_socket` / `tcp_fallback` is required.

### The two sync budgets

`sync_batch` and `blocks_page` bound different things and are deliberately not
the same knob:

- `sync_batch` (apply budget) is how much work one pass may do: at most that
  many blocks committed to the wallet database. It is a *pass* budget.
- `blocks_page` (request budget) is how much one HTTP call may ask for: at most
  that many blocks in a single `blocks-since` page. It is a *request* budget,
  and it is what keeps a response body bounded.

A pass with `sync_batch = 256` and `blocks_page = 1` therefore issues up to 256
requests to apply 256 blocks. The default `1` is chosen against the adapter's
hard 16 MiB response cap: the chain protocol carries each transaction and output
box as a hex string, so a page costs roughly four times the serialized bytes of
the blocks in it,
and consensus bounds one block's `BlockTransactions` section by the voted
`maxBlockSize` parameter. Sizing it against the largest value this document
shows an operator voting for (`maxBlockSize = 2097152`, 2 MiB) makes the default
provably safe for any node the daemon may be pointed at: one maxed-out block is
8 MiB of hex, so a page of `1` fits with about half the cap spare, while a
page of `2` would be 16 MiB *before* the JSON envelope (ids, indices, braces) is
added. Today's mainnet parameter is smaller than that, so the default is
deliberately conservative rather than minimal. Sizing the request from the apply
budget instead (the earlier behaviour, `min(sync_batch, remaining)`) would ask
for up to 1024 blocks and hit the cap on any real chain.

`blocks_page` stays configurable (`1..=1024`) because a node with a much smaller
`maxBlockSize` — or one serving an archive height where a page is known to be
small — can safely serve a wider page. Raising it is an operator decision made
against that node's own parameter, and the byte cap, not the block count, is
what actually bounds a body.

A block that cannot fit even a one-block page is **not** retried smaller — the
daemon never shrinks a page — so the adapter reports it once, as a terminal
error naming both the cap and the page size, and the durable rescan state becomes
`failed`. `tests/it/node_api.rs` pins both halves of this against the real node
API with ~1.5 MiB blocks, and `tests/it/sync.rs` pins the arithmetic above
against the documented 2 MiB `maxBlockSize`.

## `ergo-walletd.toml` `[api]`

| Key | Type | Default | Description |
|---|---|---|---|
| `unix_socket` | string (path) | none | Same as the top-level key. |
| `tcp_fallback` | string (socket addr) | none | Same as the top-level key (alias `tcp_addr`). |
| `allowed_hosts` | array of strings | `[]` | Extra `Host` header values (`host:port`) accepted on `tcp_fallback`, besides the listener's own loopback names (`localhost:<port>` and its IP). Any other `Host` is refused with `403 host_not_allowed` before routing, which stops DNS-rebinding requests from a browser. |

For the listener keys, `[api]` is an *alternative spelling* of the top-level
keys: specifying a listener in both places is a load error, so a half-edited
file cannot leave the daemon listening somewhere unintended.

## `ergo-walletd.toml` `[security]`

| Key | Type | Default | Description |
|---|---|---|---|
| `idle_lock` | u64 or string | `"15m"` | Lock an unlocked seed wallet after this long without a wallet operation: an authenticated non-`GET` request (unlock, sign, send, key or scan changes). Reads do not extend it, so a polling client cannot keep the wallet unlocked. `0` disables it. |
| `max_unlock` | u64 or string | `"12h"` | Lock an unlocked seed wallet this long after unlocking, whatever its activity. `0` disables it. |
| `lock_memory` | bool | `false` | Lock all current and future daemon memory into RAM (Linux). Startup fails unless the memory-lock limit is unlimited (systemd `LimitMEMLOCK=infinity`), because a bounded limit would make later allocations fail. |
| `unseal_key_file` | string (path) | none | Owner-only file holding the wallet database key as 64 hex characters, read at start so the daemon unseals without a password (see [Sealed start](#sealed-start-and-database-encryption)). Intended for a systemd `LoadCredentialEncrypted=` credential bound to the host's TPM. CLI: `--unseal-key-file`. |
| `multisig_nonces` | string | `"daemon"` | Who holds multisig signing nonces between `generateCommitments` and signing. `"daemon"` returns single-use `custody:` handles in place of each own commitment's secret nonce and resolves them when signing; they expire after an hour and are wiped on lock. `"caller"` returns the secret nonce as hex, as the Scala node does: anyone who sees it with the final signature can recover the signing key. |

Durations accept plain seconds or `"500ms"`, `"30s"`, `"15m"`, `"12h"`. Private
mining jobs whose signed bytes are already journaled keep retrying while
locked; unsigned jobs wait for the next unlock without spending retries.

## Sealed start and database encryption

`wallet.redb` is encrypted at rest in both modes: every 4 KiB sector is sealed
with AES-256-GCM under a random wallet database key, with the sector's index
and the file's identifier authenticated, so a copied or recovered database
reveals no addresses, balances or history, and a modified sector fails to
read. The database key is never stored in the clear:

- **Seed wallets** seal it in the keystore under the wallet password.
- **Watch-only wallets** seal it in `data_dir/data-key.json` under an operator
  passphrase of at least 12 characters, set by the first unseal.

A daemon that restarts is **sealed**: it holds no key, does not open the
database and does not sync. Lifecycle status reports
`{initialized, locked, sealed: true}`; other wallet routes answer
`503 wallet_sealed`. To resume:

- `POST /api/v1/wallet/unlock` (or Scala `/wallet/unlock`) with the wallet
  password unseals the database, starts sync and unlocks spending.
- `POST /api/v1/wallet/unseal` with `{pass}` unseals without unlocking:
  sync resumes, spending stays locked. Watch-only wallets use this route with
  their passphrase.

Unseal attempts share the persisted unlock budget. Auto-lock (`idle_lock`,
`max_unlock`) wipes only the spending key, so an unsealed wallet keeps syncing
while locked. `POST /api/v1/wallet/seal` stops the daemon; it starts sealed
again. A fresh seed directory starts unsealed with a new key, which `init` or
`restore` seals into the new keystore.

An existing cleartext `wallet.redb` (a migrated or earlier wallet) is encrypted
on its first unseal through a verified copy and an atomic rename; a wallet
whose keystore has no database key gets one sealed first. Encryption is not
secure erasure: the former cleartext blocks can remain on disk until
overwritten, so use full-disk encryption as well.

For an unattended host, `ergo-walletd export-unseal-key --config <path>`
reads the password (or passphrase) from the first line of standard input and
prints the database key as hex. Pipe it straight into
`systemd-creds encrypt --with-key=tpm2 --name=unseal-key - /etc/ergo-walletd/unseal-key.cred`,
add `LoadCredentialEncrypted=unseal-key:/etc/ergo-walletd/unseal-key.cred` to the
unit and start with `--unseal-key-file ${CREDENTIALS_DIRECTORY}/unseal-key`.
The daemon then unseals at boot without a password; spending still needs the
password. That copy of the key is only as strong as the host that holds it: it
protects a database copied elsewhere, not one read by root on the same host.

## Descriptor file

In `watch_only` mode, `descriptor_file` points at the daemon's public input.
Seed mode rejects this key. JSON or TOML, with
`descriptors` (or `keys`) as an array of entries:

```toml
version = 1

[[keys]]
path        = "m/44'/429'/0'/0/0"                      # derivation path
public_key  = "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2"
label       = "cold storage"                          # optional, <= 256 chars
curve       = "secp256k1"                             # optional, only value
```

| Key | Required | Description |
|---|---|---|
| `path` | yes | `m/…` derivation path; hardened components may use `'`, `h`, or `H`; at most 255 components; leading zeros and values above `0x7fffffff` are rejected. |
| `public_key` | yes | 66 lowercase hex characters: a 33-byte **compressed** secp256k1 point (`02`/`03` prefix). |
| `label` | no | Free-form label returned by `/addresses`; longer than 256 characters is rejected. |
| `curve` | no | Must be `"secp256k1"` if present. |
| `version` (file) | no | Must be `1` if present. |

Validation rules that matter operationally:

- **No secrets.** A `private_key` (or any unknown) field is a parse error, not
  a warning: the schema is strict, so a descriptor file cannot smuggle key
  material into a watch-only daemon. Watch-only mode never opens secret storage.
- **Keys are validated, not trusted.** Each public key must decode as a
  compressed point *and* render as a P2PK address for the configured
  `network`, so a bad key fails at startup instead of on a read route.
- **Import is idempotent and additive.** Re-running with the same file changes
  nothing; a *new* key resets the scan cursor in the same transaction that adds
  the key, so a crash can expose either the old wallet or a clearly invalidated
  rebuild target — never new keys beside a clean cursor.
- **Prefixes are never persisted.** The store keeps 33-byte public keys and the
  API renders base58 at read time, so changing `network` changes the addresses
  the API returns without touching the database. (The chain history itself
  still has to be re-synced from the new network's node.)
- **The descriptor file cannot register a scan.** It admits public keys,
  paths, and labels. The daemon exposes persisted scan registrations through
  `/scans` and `/scan/listAll` and rewinds their tracked boxes and transactions
  on reorgs. A fresh descriptor-only database has an empty registry. Registration
  remains a node capability (`/scan/register`); the daemon has no scan mutation
  routes in either mode.
  `tests/it/scan_registry_rewind.rs` covers the persisted registry's apply and
  rewind behavior, and `tests/it/daemon_boot.rs` covers a fresh database.

## Seed wallet API

Start with `mode = "seed"`, a fresh data directory, `local_api_key_file` and
no `descriptor_file`. The daemon will not automatically migrate embedded
wallet data or turn an existing descriptor wallet into a seed wallet. Initialize
or restore through the local API; encrypted files are stored under
`data_dir/wallet/`. Existing seed wallets always start locked. Unlocking
reconciles the seed's public keys, and later syncing continues while locked.
Seed restarts require the daemon's persisted `wallet-mode` marker; an unmarked
directory containing `wallet.redb`, `wallet/` or `state.redb` is rejected.

Every API request, in either mode, must contain exactly one `api_key` header
matching the local credential, on both Unix and TCP listeners. The node
credential is insufficient. Missing, duplicate or incorrect credentials return
`401` before body parsing; credentials are compared as SHA-256 digests in
constant time. All authenticated responses include `Cache-Control: no-store`.
Lifecycle bodies are capped at 16 KiB, use strict protocol DTOs, and return
generic parse errors without echoing secret fields. Internal error details are
withheld from the local API.

The engine's failed-attempt budget protects password and mnemonic checks: five
failures within a minute lock unlock for five minutes, and each further lockout
before a successful unlock doubles, up to 24 hours. The unlock budget is kept in
the owner-only `data_dir/unlock-attempts.json`, so restarting the daemon neither
resets it nor ends a lockout.

New wallets are written in the version-2 keystore format: Argon2id
(256 MiB, 3 passes) and AES-256-GCM whose associated data authenticates every
parameter and the derivation mode. A version-1 file (the Scala/Appkit PBKDF2
format, including a migrated embedded wallet) is rewritten in place as version 2
by its first successful unlock; the rewrite is an atomic replace, and if it
fails the original file is kept and the unlock still succeeds. Version-2 files
cannot be read by Scala, Appkit or earlier releases; `ergo-wallet
export-keystore` writes a version-1 copy for those tools. Both formats reject
cost parameters large enough to stall unlock. The old file's blocks may remain
on disk until overwritten: replacement is not secure erasure on SSDs or
copy-on-write file systems.

| Method | Route | Request / response |
|---|---|---|
| GET | `/api/v1/wallet/lifecycle/status` | `{initialized, locked}` from local state; `sealed: true` is added while sealed; works while the node is unavailable |
| POST | `/api/v1/wallet/unseal` | `{pass}`; release the database key without unlocking spending (watch-only: the passphrase) |
| POST | `/api/v1/wallet/seal` | Stop the daemon; it starts sealed. `202` |
| POST | `/api/v1/wallet/init` | `{pass, mnemonicPass?, strength?}`; strength is 12, 15, 18, 21 or 24 words, default 24; response `{mnemonic}` |
| POST | `/api/v1/wallet/restore` | `{mnemonic, mnemonicPass?, pass, derivation}`; derivation is `{type:"eip3"}` or `{type:"legacyPre1627"}` |
| POST | `/api/v1/wallet/unlock` | `{pass}`; unlock and reconcile public keys |
| POST | `/api/v1/wallet/lock` | Drop unlocked secret material; idempotent |
| POST | `/api/v1/wallet/mnemonic/verify` | `{mnemonic, mnemonicPass?}`; response `{matched}` |
| POST | `/api/v1/wallet/addresses` | `{type:"next"}` or `{type:"path", derivationPath:"m/..."}`; response `{address, derivationPath, index}` |
| GET | `/api/v1/wallet/change-address` | `{address}`; address may be `null` |
| PUT | `/api/v1/wallet/change-address` | `{address}`; requires an unlocked seed that owns the tracked address |

Seed mode also serves shared engine selection/build/sign/send, reward sweeps,
multisig, scan/rescan and private mining-job routes, including Scala adapters.
Transaction/scan bodies have a separate 8 MiB limit. Private-key export keeps
its disabled operator default. `/api/v1/wallet/status` refreshes a validated
node context for pruning and EIP-27 flags, and returns `node_unavailable` when
the node cannot provide it. `/status` retains cursor, node-tip, lag and sync diagnostics.
The static wallet UI is public so a browser can enter its local credential.
All API reads and writes remain authenticated.

Commands and sync share a writer; actual key additions atomically reset history.
Spending refreshes complete coherent node/pool context and fails before the
engine when required data cannot be validated. Rescans fence mutations and
suspend sync while their cancellable supervised replay runs. Restore marks
unknown/pruned historical coverage incomplete; neither sync nor discovery
invents unavailable historical transactions. See
[daemon engine hosting and cutover](wallet-extraction.md#phase-3-daemon-engine-hosting)
for migration, background jobs, API boundaries and deployment.

## Socket permissions

Both daemon modes restrict their listener addresses and socket permissions:

- The Unix socket is created under a `0o077` umask and then explicitly
  `chmod 0600`; failure to set the mode removes the socket and aborts startup.
- A `<socket>.owner` marker file (`ergo-walletd-socket:<pid>:<nanos>`, mode
  `0600`) records ownership. On start, a socket with a valid marker that refuses
  a connection is treated as stale and removed; a socket that still accepts a
  connection, or one with a missing/invalid marker, is left alone and startup
  fails. A daemon therefore never steals or clobbers a live socket.
- The marker and the socket are removed on clean shutdown.
- Unix connection tasks are tracked and cancelled during listener shutdown;
  TCP listeners drain gracefully within the configured shutdown deadline.
- `tcp_fallback`, when used, must bind a loopback address (rejected otherwise),
  and accepts only its own loopback `Host` names plus `[api] allowed_hosts`.
- Both modes require the independent local `api_key` credential for every read
  and write, in addition to socket permissions or loopback binding. The daemon
  does not provide TLS or bind non-loopback TCP.
- The data directory is owner-only (`0700`) in both modes, as is a socket
  directory the daemon creates.

## Process hardening

Before it reads any credential, the daemon sets its core-file limit to zero and,
on Linux, marks itself non-dumpable, which also blocks same-user debuggers and
`/proc/<pid>/mem` reads. `[security] lock_memory` additionally locks its memory
into RAM. The shipped [systemd unit](../deploy/ergo-walletd.service) adds
`MemorySwapMax=0` and `LimitCORE=0`, an `@system-service` syscall filter,
`MemoryDenyWriteExecute`, no capabilities, private `/proc`, IPC and users, and
loopback-only networking (`IPAddressAllow=localhost`; add a remote `https`
node's address explicitly). Memory protection does not defend against root on
the running host.

## `ergo-walletd` CLI flags

| Flag | Type | Default | Description |
|---|---|---|---|
| `--config`, `-c <path>` | path | `ergo-walletd.toml` | Daemon config file. A missing file is a startup error; required paths and credentials depend on the selected mode. |
| `--mode <watch-only\|seed>` | string | — | Overrides the file's `mode`. TOML spells the default mode `watch_only`. |
| `--network <mainnet\|testnet>` | string | — | Overrides the file's `network`. |
| `--data-dir <path>` | path | — | Overrides `data_dir`. |
| `--node-url <url>` | string | — | Overrides `node_url`. |
| `--api-key-file <path>` | path | — | Overrides `api_key_file`. |
| `--descriptor-file <path>` | path | — | Overrides `descriptor_file`. |
| `--local-api-key-file <path>` | path | — | Overrides `local_api_key_file`. |
| `--sync-interval <secs>` | u64 | — | Overrides `sync_interval`. |
| `--sync-batch <n>` | u32 | — | Overrides `sync_batch` (the per-pass apply budget). |
| `--blocks-page <n>` | u32 | — | Overrides `blocks_page` (the per-request page size). |
| `--unix-socket <path>` | path | — | Overrides `unix_socket`. |
| `--tcp-fallback <addr>` | socket addr | — | Overrides `tcp_fallback`. |
| `--unseal-key-file <path>` | path | — | Overrides `[security] unseal_key_file`. |
| `export-unseal-key` | subcommand | — | Print the wallet database key as hex, reading the password or passphrase from standard input. |

Logging uses `tracing` with the `RUST_LOG` filter (default `info`): reorgs and
retries log at `warn`, protocol violations and other terminal sync failures log
at `error`. Log lines carry locally generated messages and heights only — never
credentials, recovery phrases, passwords or node response bodies.
See [operator controls](operator-controls.md) for configurable API request budgets, readiness policy, named credentials, runtime changes and durable peer administration.
