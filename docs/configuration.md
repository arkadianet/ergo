# Configuration reference

This is the complete reference for `ergo-node.toml`, the node's
configuration file. This node is an independent Rust reimplementation
that targets strict consensus compatibility with the Scala reference
node — it is not the reference node, and several config keys exist
specifically to mirror Scala's `consistentSettings` checks. Keys whose
behavior follows Scala are noted as such below.

## Resolution model

Values are resolved from three sources, highest precedence first:

1. **CLI flags** (e.g. `--network`, `--data-dir`)
2. **TOML file** values
3. **Built-in defaults**

The config file path is `--config <path>`; when that flag is absent the
node looks for `ergo-node.toml` inside the data directory
(`<data_dir>/ergo-node.toml`). A missing config file is not an error —
the node falls back to built-in defaults. All validation runs at load
time: any failure returns an error and the node refuses to start rather
than booting into a misconfigured state.

A ready-to-use default config ships at
[`../ergo-node/ergo-node.toml`](../ergo-node/ergo-node.toml) — a mainnet
full-archival node with the `/blockchain/*` extra-index enabled — and a
fully-commented operator template lives next to it at
[`../ergo-node/ergo-node.toml.example`](../ergo-node/ergo-node.toml.example).

### Unknown-key handling is per-section

Typo rejection (`deny_unknown_fields`) is applied per TOML section, not
uniformly. An unknown key inside a strict section is a hard parse error;
an unknown key inside a lenient section is silently ignored. This is
worth knowing when a key seems to have no effect — check that its
section rejects typos:

| Strict (unknown key = error) | Lenient (unknown key ignored) |
|---|---|
| `[node]`, `[node.utxo]`, `[node.nipopow]`, `[mempool]`, `[indexer]`, `[wallet]`, `[logging]`, `[logging.file]` | top-level, `[peers]`, `[sync]`, `[store]`, `[chain]`, `[api]`, `[api.security]`, `[mining]` |

## Top-level keys

| Key | Type | Default | Description |
|---|---|---|---|
| `network` | string | `"mainnet"` | Selects the chain spec. `"mainnet"` or `"testnet"`. The network must have an embedded genesis or the node fails fast. CLI: `--network`. |
| `data_dir` | string (path) | `"./ergo-data"` | Root directory for the state database, logs, wallet, and the default config-file location. CLI: `--data-dir`. |

## `[node]`

| Key | Type | Default | Description |
|---|---|---|---|
| `agent_name` | string | `"ergo-rust"` | Agent name advertised in the P2P handshake. |
| `node_name` | string | `"ergo-rust-node"` | Node name advertised in the handshake. |
| `blocks_to_keep` | i32 | `-1` | Pruning suffix length. `-1` = full archive (keep every block). `N > 0` = retain a pruned suffix of `N` blocks. `0` is reserved for the headers-only combo (see below). Values below `-1` are rejected. A positive `N` must be at least the rollback-window floor (`ROLLBACK_WINDOW + SAFETY_MARGIN`); a smaller value is rejected because a reorg could otherwise need evicted block sections. |
| `state_type` | string | `"utxo"` | State backend. `"utxo"` keeps the full UTXO set on disk (wire byte 0); `"digest"` keeps only the authenticated root digest and a header window (wire byte 1). Case-insensitive. `"digest"` is accepted only in the headers-only combo below; any other digest configuration is rejected at load. |
| `verify_transactions` | bool | `true` | When `false`, the node syncs headers only and downloads no block sections. Requires `state_type = "digest"` (Scala rule R1) and is accepted only in the headers-only combo below. |

**Headers-only combo.** The only currently-bootable non-UTXO
configuration is `state_type = "digest"` + `verify_transactions = false`
+ `blocks_to_keep = 0` + `utxo_bootstrap = false` (this mirrors Scala
`application.conf`). Other digest or `blocks_to_keep = 0` combinations
are rejected with an explicit error so the conflicting key is obvious.

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
| `max_connections` | usize | `80` | Total connection cap. Must be at least 1. |
| `target_outbound` | usize | `60` | Outbound-connection target. Must be at least 1 and no greater than `max_connections`. The inbound cap is `max_connections - target_outbound` (20 at the defaults). |
| `per_ip_limit` | usize | `1` | Maximum connections per peer IP. Must be at least 1. |
| `per_subnet_limit` | usize | `3` | Maximum connections per /16 subnet. Must be at least 1. |
| `bind_addr` | string | none | Inbound TCP listen address. Absent or empty string = outbound-only (no inbound listener). Parsed as a socket address at load; a malformed value is rejected. |
| `declared_addr` | string | none | Address advertised in the handshake and peer gossip so others can dial this node. Independent of `bind_addr` (a NAT'd host binds privately and declares its public address). Absent or empty = the handshake omits it. |

## `[sync]`

| Key | Type | Default | Description |
|---|---|---|---|
| `download_window` | usize | `384` | Number of blocks ahead of the validated tip to keep pending for section download. Must be at least 1 and no greater than 100000. |
| `enable_anchor_scheduler` | bool | `false` | Opt-in: dispatch single-anchor `SyncInfo` to REST-capable peers from the anchor map instead of the local recent-header tail. Enable only once the anchor map is observed healthy. |

## `[store]`

| Key | Type | Default | Description |
|---|---|---|---|
| `cache_bytes` | usize | 1 GiB (`1073741824`) | redb + AVL arena page-cache budget, in bytes. When omitted, the store uses its built-in default. CLI flag `--cache-bytes` overrides this. Note that redb's own per-database page cache is separate from this AVL-arena budget; account for several gibibytes of resident memory across the state, indexer, peers, and wallet databases. |

## `[chain]`

| Key | Type | Default | Description |
|---|---|---|---|
| `script_validation_checkpoint_height` | u32 | network default | Blocks at or below this height skip per-input ErgoScript evaluation (UTXO mutations and the per-block state-root check still run). `0` disables the checkpoint (full validation everywhere). Precedence: CLI `--checkpoint-height` > TOML > the network's embedded default. |
| `script_validation_checkpoint_block_id` | string (hex) | network default | The 32-byte block id pinned at the checkpoint height; asserted on apply, and a mismatch is a hard error. Must decode to exactly 32 bytes. If a height is set with no id and the network has no default, load fails. CLI: `--checkpoint-block-id`. |
| `genesis_id` | string (hex) | network genesis id | The 32-byte genesis header id used for NiPoPoW R5 enforcement. An optional `0x` prefix is allowed; must decode to 32 bytes. The empty string `""` disables the check (development against synthetic chains only) — mainnet runs must leave this at the default. Combining `genesis_id = ""` with `nipopow_bootstrap = true` is rejected. |

## `[api]`

The operator HTTP API. See the security note below before exposing it
beyond loopback.

| Key | Type | Default | Description |
|---|---|---|---|
| `bind` | string (socket addr) | `"127.0.0.1:9099"` | HTTP API bind address. Parsed at load; a malformed value is rejected. A non-loopback bind is rejected unless `public_bind = true`. |
| `disabled` | bool | `false` | When `true`, the API server is not started and no `api_key_hash` is required. |
| `public_bind` | bool | `false` | Permits binding a non-loopback address. A non-loopback `bind` without `public_bind = true` is rejected at load. See the security note below. |

### `[api.security]`

| Key | Type | Default | Description |
|---|---|---|---|
| `api_key_hash` | string (hex) | none | Lowercase Base16 of `Blake2b256(<secret>)`. **Mandatory whenever the API server is enabled** (mirroring Scala `ErgoApp.scala`). Must be exactly 64 lowercase hex characters (`0-9`, `a-f`); uppercase or mixed case is rejected for canonical-form parity. Not required when `[api] disabled = true`. |

### Security notes for the API

The `api_key` gate is narrow by design, matching the Scala reference
node: it protects only the `/wallet/*` routes and the
`/node/shutdown` route. Every other route is unauthenticated regardless
of bind scope — including transaction submission
(`POST /transactions*`, `POST /api/v1/mempool/{submit,check}`),
`POST /blocks`, `/mining/*`, all read endpoints, and `/metrics`.

Consequences:

- **`api_key_hash` is required even on a loopback bind** whenever the API
  is enabled — it is keyed off whether the API server runs, not off the
  bind address. The header name is `api_key` (lowercase, underscore);
  the value is compared in constant time against the configured hash.
- **`public_bind = true` exposes the submission and read surface to the
  network.** Binding `0.0.0.0` with `public_bind = true` makes
  transaction submission, block submission, and `/metrics` world-callable.
  For remote operator access, prefer binding loopback and fronting the
  node with an authenticated reverse proxy.
- **`/metrics` is not authenticated.** Keep it on loopback or behind a
  proxy.

Generate a hash from a secret with, for example:

```bash
echo -n "<your-secret>" | b2sum -l 256 | cut -d' ' -f1
```

## `[mempool]`

Only operator-facing knobs are exposed. Internal tuning parameters
(CPFP family limits, cost budgets, invalidation and revalidation rates,
notifier cadence, unresolved-cache sizing) are deliberately not
configurable; supplying one of those keys is a parse error because this
section rejects unknown keys. The mempool is force-disabled — regardless
of `disabled` — whenever the node has no UTXO box state, i.e. under
`state_type = "digest"` or `verify_transactions = false`.

| Key | Type | Default | Description |
|---|---|---|---|
| `disabled` | bool | `false` | When `true`, skip transaction relay (useful for archival or sync-test runs). CLI flag: `--mempool-disabled`. |
| `sort_policy` | string | `"cost"` | Pool priority ordering: `"cost"`, `"size"`, or `"min"`. An unknown value is rejected at load. CLI flag: `--mempool-sort`. |
| `max_pool_size` | usize | `1000` | Maximum transaction count. Must be at least 1. |
| `max_pool_bytes` | usize | `67108864` (64 MiB) | Maximum total pool size in bytes. Must be at least 1. |
| `min_relay_fee_nano_erg` | u64 | `1000000` | Minimum relay fee in nanoERG. |
| `max_tx_size_bytes` | usize | `98304` (96 KiB) | Maximum single-transaction size. Must be at least 1. |
| `max_tx_cost` | u64 | `4900000` | Maximum single-transaction cost (matches the Scala mainnet override). Must be at least 1. |
| `ibd_gate_block_lag` | u32 | `10` | Block-lag threshold that gates mempool admission while the node is still catching up during initial sync. |

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
| `miner_public_key_hex` | string (hex) | none | 33-byte compressed secp256k1 public key (66 hex chars) for the reward output. **Optional**: when set, it is the pinned reward pubkey; when omitted, the wallet's EIP-3 first-address key is resolved at candidate time (the node must have a wallet). A value that is present must be well-formed (66 hex chars → 33 bytes) or load fails. CLI flag: `--mining-public-key`. |
| `block_candidate_generation_interval_ms` | u64 | `1000` | Debounce window (ms) for same-parent mempool-refresh rebuilds. When the mempool changes but the tip has not, the node coalesces the burst and regenerates the candidate at most once per window. Lower = fresher candidates but faster churn of the retained template ring. |
| `use_external_miner` | bool | `true` | Must be `true` — an internal CPU miner is not supported, so `false` is rejected at load. |
| `candidate_base_cache` | bool | `false` | Caches the hydrated AVL working set between candidate builds, keyed on the committed tip. The first build per block pays the full hydration; subsequent rebuilds at the same tip (the enriched refresh and every mempool-driven rebuild) are near-instant. Holds the full UTXO AVL node graph resident — multi-GB on a mainnet archival node, scaling with the UTXO-set size — so enable it only on a mining node with RAM headroom. |

## `[wallet]`

| Key | Type | Default | Description |
|---|---|---|---|
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
  `[indexer] enabled = true`, and `state_type = "digest"` boots only in
  the headers-only combo.

## Minimal example

A minimal mainnet full-archive node with the operator API enabled:

```toml
network = "mainnet"
# data_dir defaults to ./ergo-data

[peers]
known = ["213.239.193.208:9030", "159.65.11.55:9030"]

[api]
bind = "127.0.0.1:9099"

[api.security]
# lowercase Base16 of Blake2b256(<your-secret>)
api_key_hash = "324dcf027dd4a30a932c441f365a25e86b173defa4b8e58948253471b81b72cf"
```

For the full set of keys, comments, and a fast clean-database boot
configuration (Mode 2 + NiPoPoW), see the bundled config at
[`../ergo-node/ergo-node.toml`](../ergo-node/ergo-node.toml) and the
operator template at
[`../ergo-node/ergo-node.toml.example`](../ergo-node/ergo-node.toml.example).
Configuration is unstable until 1.0; keys and shapes may change between
minor versions — see [`./compatibility.md`](./compatibility.md) for the
versioning policy.
