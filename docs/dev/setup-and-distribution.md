# Setup wizard and release distribution design

Status: proposal only; no implementation. Evidence baseline: `origin/main` at
`f170dcd58d421c0c1e04079d0065e4c9d44ae745`, reviewed on 2026-10-05. Paths below
refer to that checkout. Implementation effort and proposed disk budgets are
planning estimates, not measurements. The release inventory was also checked
against the GitHub API for `v0.12.0-rc.1` (54 uploaded assets; published
2026-10-05T02:36:13Z). Its tag resolves locally to
`2f678cf4fa1754974f2648fae465cb4aed2766f2`; the packaging workflow, helper,
release docs and config modules have no diff between that tag and this baseline.
Sources: [release](https://github.com/arkadianet/ergo/releases/tag/v0.12.0-rc.1),
[release API](https://api.github.com/repos/arkadianet/ergo/releases/tags/v0.12.0-rc.1),
[workflow](../../.github/workflows/release.yml), [helper](../../scripts/release.py).

Recommend a repository-owned hybrid: `ergo-node api-key` first, then
`ergo-node init`, using the node's own config validation; keep service templates
and updater generation in this repository and version them with the node.
Publish six combined node/wallet archives, `SHA256SUMS`, and one `release.json`:
eight assets in steady state. Keep the known Linux x86-64 bare node and its
checksum for two release tags as a courtesy transition, giving ten assets.
Publish a tested GHCR image in a later release phase. These are proposed choices;
the rationale and remaining maintainer decisions follow.

## 1. Verified setup behavior and friction

The release quickstart requires **copying** `config/ergo-node.toml` into a writable
working directory before `./ergo-node --config ./ergo-node.toml --data-dir
../ergo-data`. The data directory stays outside the extracted archive. Explicit
`--config` pointing to a missing file is an error. Only an absent **implicit**
`<CLI data-dir or ./ergo-data>/ergo-node.toml` permits built-in defaults. CLI
values override TOML values, which override defaults. Sources:
[release quickstart](../release-quickstart.md),
[`NodeConfig::load`](../../ergo-node/src/config/load.rs),
[configuration](../configuration.md).

There are two different defaults, which the brief conflated:

| Setting | No implicit config file | Bundled `ergo-node.toml` |
|---|---|---|
| Network | Mainnet | Mainnet |
| State/verification/retention | UTXO, verify transactions, archive (`-1`) | Same |
| UTXO / NiPoPoW bootstrap | Both false | Both false by omission |
| Indexer | **Disabled** | **Enabled** |
| API/dashboard | `127.0.0.1:9099`, enabled | Same |
| Privileged credential | Absent; routes fail closed | Same |
| Inbound P2P | No listener or declared address | Same by omission |
| Logging | Stderr | Stderr plus rolling files under data dir |

Sources: [loader](../../ergo-node/src/config/load.rs),
[indexer defaults](../../ergo-indexer/src/config.rs),
[bundled config](../../ergo-node/ergo-node.toml),
[dashboard/quickstart](../../README.md#quickstart),
[auth](../../ergo-api/src/auth.rs). `./ergo-node` is a usable public dashboard
and syncing node without a credential; that does not make private wallet or
mining operations ready for use. A release smoke proves temporary devnet
boot/reopen/shutdown, not mainnet synchronization or setup on an arbitrary host
([smoke implementation](../../scripts/release.py#L96)).

Verified friction, in priority order:

1. **Genesis replay is the easy path.** The bundled config additionally builds
   the indexer. [Operating](../operating.md#fast-clean-db-boot-mode-2--nipopow)
   describes multi-hour replay; the [README](../../README.md#status) reports
   approximately 20 minutes to bootstrap completion for Mode 2 + NiPoPoW on
   mainnet. Neither establishes a portable “hours to days” bound or a 20-minute
   guarantee. The fast recipe requires disabling the indexer. It carries a
   provisional snapshot-trust caveat, requires a clean or already-bootstrapped
   store, and cannot combine with `[chain] checkpoint` (local rule R6 in the
   [loader](../../ergo-node/src/config/load.rs)). Fast bootstrap omits historical
   blocks; `blocks_to_keep = -1` does not recover the skipped history.
2. **Credentials require shell work and restart.** Private wallet/scan, mining,
   voting writes and admin routes require an API credential. The documented
   shell recipe computes lowercase `Blake2b256(secret)`; the release smoke does
   the same with Python. Neither the [node command enum](../../ergo-node/src/config/cli.rs)
   nor the [wallet CLI](../../ergo-wallet/src/bin/ergo-wallet.rs) offers an API-key
   generator. Named scoped credentials already exist, so “locked until master
   hash configured” should not be confused with “only one key can be used”
   ([configuration](../configuration.md#apisecurity), [auth](../../ergo-api/src/auth.rs)).
3. **Mining setup is spread across documents.** `[mining] enabled`, a configured
   compressed reward public key or the wallet's first EIP-3 key, and a compatible
   external mining client are necessary. The wallet-derived path needs wallet
   initialization and an unlock before candidate work becomes available.
   There are existing pointers in [configuration](../configuration.md#mining),
   the [example](../../ergo-node/ergo-node.toml.example), and
   [Lithos integration](../lithos.md); “nothing points to it” overstates the gap.
   GPU miners that speak Stratum need a bridge; the node provides an HTTP mining
   protocol, not a Stratum server or CPU miner ([README](../../README.md#non-goals),
   [mining config](../../ergo-mining/src/config.rs),
   [reward resolution](../../ergo-mining/src/handle.rs)). The maintainer's choice
   of `ergo-solo` is supplied context, not a local deployment inspected here.
   Its own [README](https://github.com/arkadianet/ergo-stratum-rs#readme) documents
   this bridge and API-key input.
4. **Container publication is manual.** [Compose](../../deploy/compose.yml)
   builds source and uses `ergo-node:local`; the [Dockerfile](../../Dockerfile)
   builds both binaries. [Deployment](../deployment.md) explicitly says image
   publication is an operator action; the [release workflow](../../.github/workflows/release.yml)
   has no registry publication job. This verifies no first-party publication
   in the audited workflow, rather than asserting no image exists anywhere.
5. **Service installation is manual and Linux-only in the product docs.**
   [Deployment](../deployment.md#linux-systemd) and the
   [systemd unit](../../deploy/ergo-node.service) use a system service, dynamic
   user and five-minute stop timeout. `deploy/` contains no launchd or Windows
   service template. The runtime handles Unix signals and Windows Ctrl+C/REST
   shutdown, but has no Windows SCM service host
   ([boot lifecycle](../../ergo-node/src/node/boot/mod.rs)).

The maintainer's scripts, `OPERATING.txt`, user service and lingering are user
requirements/example output, not repository evidence. No local host scripts,
services, node data or occupied ports were examined.

Some reference comments lag the implementation: the
[example config](../../ergo-node/ergo-node.toml.example) still describes pruning,
digest and bootstrap work as gated, while the
[loader](../../ergo-node/src/config/load.rs) and
[operating guide](../operating.md) admit their documented combinations. The
example also says submission routes are unkeyed while listing `POST /blocks`,
which the [API route inventory](../configuration.md#security-notes-for-the-api)
places behind authentication. The implementation phases must reconcile these
comments; a wizard must not use comments as its validation schema.

## 2. Wizard architecture options

### Existing config boundary

[`ergo-node/src/lib.rs`](../../ergo-node/src/lib.rs) exposes `pub mod config`.
[`config/mod.rs`](../../ergo-node/src/config/mod.rs) re-exports `Cli`, `Command`,
`NodeConfig`, network and resolved config types. `NodeConfig::load(Cli)` is
public. Thus **B can depend on `ergo-node` and validate a generated config today,
without extracting a crate**. `ergo-node` already has a library target and is
`publish = false` ([manifest](../../ergo-node/Cargo.toml)). This works as a path
dependency inside the workspace; it is not a separately published config SDK.

The editable `TomlConfig` and section types are `pub(super)` and derive
`Deserialize`, not `Serialize` ([toml_sections.rs](../../ergo-node/src/config/toml_sections.rs)).
`NodeConfig` is a resolved runtime structure, not a round-trip TOML model
([resolved.rs](../../ergo-node/src/config/resolved.rs)). Neither A nor B can
simply serialize it to preserve comments, omitted defaults and unknown operator
intent. Add an internal preset-to-TOML writer and a `load_from_str`/validate
entry point used by both the loader and wizard. Keep comment-preserving edits
separate, using a focused TOML editor dependency if necessary. Tests must feed
its output back into the authoritative resolver.

A lightweight extracted `ergo-node-config` would require separating CLI,
editable schema, defaults, config resolution and runtime adaptation. The current
resolver imports chain spec, P2P limits, indexer, mempool, mining, API types and
logging filters. Moving it unchanged preserves those dependencies; eliminating
them requires DTOs and conversion code, with duplicated defaults a risk. A
config crate cannot depend on `ergo-node` without a cycle. An extraction must
move validation and consistency rules with their tests, adjust imports/docs,
and avoid changing runtime behavior ([loader](../../ergo-node/src/config/load.rs),
[tests](../../ergo-node/src/config/tests.rs), [node manifest](../../ergo-node/Cargo.toml)).
Estimate 3–5 engineering days for an initial faithful extraction, plus more to
make it genuinely lightweight; this is unnecessary for the proposed first phase.

### Comparison

The following tradeoffs are design judgments based on the boundaries above and
current [CLI dispatch](../../ergo-node/src/main.rs),
[workspace dependencies](../../Cargo.toml) and
[packaging](../../scripts/release.py). Binary-size effects require measurement;
no byte savings are claimed.

| Dimension | A: integrated commands | B: workspace helper binary | C: independent repo/package | D: integrated core + repository templates (recommended) |
|---|---|---|---|---|
| Config-schema drift | Lowest if it calls the same resolver; output still needs tests | Low via `ergo_node::config`; direct editable schema unavailable | Highest for handwritten script/GUI schema; needs a versioned protocol or exact matching node validator | Same as A; OS templates consume validated installation plans |
| Binary size/dependencies | Adds UI/TOML editing and OS adapters to node; CLI, RNG, hash, zeroize already available | Node need not grow much, but helper rebuilds the broad node dependency graph; dead-code elimination may reduce linked code, not guaranteed | Tiny shell script possible, at cost of shell/tool dependencies; GUI adds a runtime/distribution burden | Start with standard stdin prompts and small modules; OS-specific deps gated per target, no GUI |
| Six targets and services | One existing build matrix; service adapters still need development | Add helper build/help/version/smoke on all six; same OS adapter work | Shell is not universal on Windows; GUI/installer support creates its own platform matrix | Core on all six; Linux systemd, macOS launchd, Windows SCM staged explicitly |
| Testability | Pure plan/render tests plus temp-dir command tests; avoid node startup | Same tests; CLI executable boundary useful | Tests span two repos/releases and installed node combinations | Shared planner + injected filesystem/process adapters; existing release smoke covers shipped executable |
| Key handling | Reuse hash/RNG/zeroize; no subprocess secret transport | Equally safe in Rust; extra process unnecessary for core key generation | Script quoting, stdout, argv and GUI storage require separate review | Core writes secret/hash; templates/updaters never receive plaintext in argv |
| Updates/versioning | Commands match installed node schema/version | Lock helper and node to same workspace version; never independently update helper | Compatibility matrix and bootstrap installer trust/update policy required | Node tag versions core/templates; generated receipt records tag/SHA/target and file hashes |
| Release asset count | No extra files | Under today's separate-binary scheme, +4 per target = +24 (78); +0 if bundled only | May leave node assets unchanged, but moves downloads/count to another product | +0 with combined archives; updater/service files live inside archives |
| Maintenance | One repository; modularize to keep runtime focused | One repo but another product entry point, help/docs and packaging path | Two issue trackers, release schedules and compatibility obligations | One repo/release; template and core changes reviewed together |

B is reasonable if a later GUI/installer becomes large enough to justify another
executable, but extracting a config crate only to support today's helper buys
little. C could later wrap `ergo-node init --dry-run --json` with a versioned
plan schema and require a compatible node; it should not own a second config
schema. Do not make an independently versioned GUI a prerequisite for setup.

### Recommendation and repository ownership

Use D: `api-key`, `init`, and eventually `service install/status/uninstall` in
`ergo-node`; keep the planner/writer/OS adapters in dedicated node modules and
service/updater templates in `deploy/`. Node configuration remains owned by the
node repository. All templates and commands ship at the workspace version and
exact release SHA; no independently published setup package. This follows the
existing offline-command pattern while avoiding a third binary
([CLI](../../ergo-node/src/config/cli.rs), [main](../../ergo-node/src/main.rs)).

Move lightweight CLI dispatch ahead of Rayon/Tokio node runtime construction
for `api-key` and plan/render-only commands. Today even offline commands enter
`run_node()` before dispatch. Key generation must not initialize node storage,
networking, the dashboard, logging subscribers, or runtime threads. Existing
maintenance commands can retain their async cancellation dispatcher; do not
fold secret handling into the generic report/error formatter
([main](../../ergo-node/src/main.rs), [maintenance](../../ergo-node/src/maintenance.rs)).

## 3. Proposed UX and scripting contract

All command/flag names below are **proposed**, not available today. Interactive
mode runs only with a terminal; noninteractive invocation fails on missing
required choices rather than waiting for input. `--yes` accepts a fully specified
plan; it does not authorize replacement, trust changes or service installation.
`--dry-run --json` reports a versioned plan containing paths, config changes,
service actions, budgets and next steps, with no generated secret or writes.

Example, once implemented:

```sh
./ergo-node init --preset mining --bootstrap fast --accept-unanchored-bootstrap \
  --network mainnet --install-dir "$HOME/ergo-node" \
  --config "$HOME/ergo-node/config/node.toml" --data-dir "$HOME/ergo-data" \
  --api-bind 127.0.0.1:9099 --api-key-file "$HOME/ergo-node/secrets/api-key" \
  --reward-source wallet --service none --non-interactive --yes
```

`--preset wallet|mining|explorer|archival`,
`--bootstrap fast|anchored|genesis`, `--checkpoint-height/--checkpoint-block-id`,
`--network mainnet|testnet|devnet`, `--install-dir`, `--config`, `--data-dir`,
`--api-bind`, `--peer` (repeatable), `--allow-local`, `--p2p-bind`,
`--declared-addr`, `--api-key-file`,
`--reward-source wallet|public-key`, `--miner-public-key`,
`--service none|user|system`, `--install-service`, `--start`, `--non-interactive`,
`--yes`, `--dry-run`, and `--json` cover the same choices as prompts. There is
no `--api-secret` flag. `--start` is separate from installation and defaults off.

### Step 1: purpose and synchronization

Explain capabilities and duration before choosing. Wallet/mining should offer
fast bootstrap first, **with explicit acceptance of its existing trust caveat**;
no hidden acceptance from choosing a purpose. Offer anchored snapshot/full-header
sync and genesis replay alongside it. Explorer/archival require genesis replay
because users chose historical completeness. Do not change the no-config runtime
default as part of this work. Constraints come from
[load.rs](../../ergo-node/src/config/load.rs),
[operating modes](../operating.md#state-modes-and-how-to-choose),
[fast boot](../operating.md#fast-clean-db-boot-mode-2--nipopow).

Exact preset output on a **new** config (dot notation below denotes TOML tables):

| Preset | Purpose-specific values written | Sync choice | Limits explained |
|---|---|---|---|
| Wallet | `indexer.enabled = false`; `mining.enabled = false`; `mempool.disabled = false` | Fast, anchored or genesis | Fast holdings discovery does not provide full transaction history/custom historical scans |
| Mining (solo HTTP/Stratum bridge) | `indexer.enabled = false`; `mining.enabled = true`; `mining.use_external_miner = true`; `mining.claim_storage_rent = false`; `mempool.disabled = false`; `mining.candidate_base_cache = false` | Fast, anchored or genesis | Reward choice required; no built-in miner; no rent self-claim without indexer |
| Explorer | `indexer.enabled = true`; `mining.enabled = false`; `mempool.disabled = false` | Genesis only | Address/token/template history waits for index catch-up |
| Archival | `indexer.enabled = false`; `mining.enabled = false`; `mempool.disabled = true` | Genesis only | Complete block archive; historical indexed queries need an explicit explorer/indexer choice |

All four explicitly write `node.state_type = "utxo"`,
`node.verify_transactions = true`, `node.blocks_to_keep = -1`,
`node.keep_versions = 200`. The mining public-key choice additionally writes
`mining.miner_public_key_hex`; the wallet choice leaves it absent. No preset
writes `wallet.expose_private_keys = true`, voting targets, or unauthenticated
legacy mining. Existing explicit values require diff review on re-run.
Sources for these keys/defaults and restrictions:
[config reference](../configuration.md), [schema](../../ergo-node/src/config/toml_sections.rs),
[mining config](../../ergo-mining/src/config.rs), [loader](../../ergo-node/src/config/load.rs).

Sync settings layered onto the preset:

| Choice | Exact additional config |
|---|---|
| Fast | `node.utxo.utxo_bootstrap = true`; `node.nipopow.nipopow_bootstrap = true`; `node.nipopow.p2p_nipopows = 2`; **no** `chain.checkpoint` |
| Anchored | `node.utxo.utxo_bootstrap = true`; `node.nipopow.nipopow_bootstrap = false`; `chain.checkpoint = { height = H, block_id = ID }`, supplied by operator; `H >= 2`, 32-byte hex ID |
| Genesis | `node.utxo.utxo_bootstrap = false`; `node.nipopow.nipopow_bootstrap = false`; no new `chain.checkpoint` |

Fast requires `--accept-unanchored-bootstrap` in scripts or a distinct prompt.
Anchored setup explains that an operator-selected future checkpoint does not
anchor a snapshot below that height; the operator must obtain a useful anchor
from a trusted source. It never silently copies the script-validation checkpoint
as a snapshot trust anchor. The wizard preserves embedded script-validation
checkpoint defaults and explains genesis replay still uses that checkpoint;
full script validation from genesis is a separate advanced option
([trust-anchor behavior](../operating.md#mode-2-trust-anchor-chain-checkpoint),
[chain config](../configuration.md#chain)).

No automatic Mode 3/4 pruning preset initially: current docs record remaining
retention/live-soak obligations, and pruning neither shrinks current UTXOs nor
skips genesis reconstruction ([mode evidence](../operating-mode-evidence.md),
[operating](../operating.md)). Mining with storage-rent self-claim or Lithos is
an advanced **genesis + explorer indexer + mining** profile, not the solo-fast
preset ([Lithos](../lithos.md), [consistency checks](../../ergo-node/src/config/load.rs)).

### Step 2: paths and disk estimate

Offer an absolute installation directory for versioned binaries/scripts,
a writable config path and an independent absolute data directory. Put secrets
under `<install-dir>/secrets/`, not in an archive extraction directory. Write
root `network` and `data_dir`; launchers pass explicit `--config` and `--data-dir`
to avoid current-directory-dependent discovery. Resolve user-entered relative
paths once and preview the absolute paths; detect path overlap and existing node
files before committing. Do not initialize databases to find out what mode an
existing directory contains ([loader path precedence](../../ergo-node/src/config/load.rs),
[release quickstart](../release-quickstart.md)).

There is no calibrated per-preset disk sizing dataset in the audited setup docs.
[Operating](../operating.md#migrating-legacy-redb-databases) gives migration
examples of a 41.7 GiB state and 42.2 GiB index; its disk troubleshooting says the
index roughly doubles footprint. These are examples, **not guaranteed current
sizes for every mode**. Do not present them as measured snapshot footprints.
Use these provisional mainnet planning budgets in the prototype:

| Preset | Proposed free-space estimate/reservation on data filesystem | Basis and growth |
|---|---|---|
| Wallet | 100 GiB | UTXO store, overhead, post-snapshot blocks and working headroom; no index |
| Mining | 100 GiB | Same disk plan as wallet; default candidate cache off affects RAM rather than providing a disk cap |
| Explorer | 250 GiB | Full history plus index, rebuild/copy headroom and growth |
| Archival | 150 GiB | Full history without index, copy headroom and growth |

Label the UI values “provisional recommended free space”, not minimum system
requirements or a disk ceiling. All these presets retain subsequent blocks
indefinitely; snapshot bootstrap is not bounded storage. For wallet/mining with
genesis replay, use the 150 GiB archival budget. Anchored bootstrap also needs
all headers. Testnet/devnet say “not calibrated”; allow an explicit
`--disk-budget-gib` override rather than inventing proportional chain sizes.
Query free bytes on the destination filesystem (or nearest existing ancestor),
show existing data separately, and include space for staged release + previous
binaries on the install filesystem. Warn below the planning budget and require
an explicit `--allow-low-disk`; failure to query is reported as unknown. Do not
fill a disk or benchmark to estimate it. Existing `fs4`/`sysinfo` dependencies
may provide the query ([workspace](../../Cargo.toml)).

Before shipping numeric recommendations, calibrate on maintainer-supplied
**offline records** at a documented chain height/version for state, blocks,
indexer, bootstrap peak and growth. Show record age in the wizard. Existing-store
upgrades additionally need the converter's copy-space allowance and rollback
policy, not just fresh-install estimates ([operating](../operating.md#migrating-legacy-redb-databases),
[data upgrade](../../ergo-node/src/data_upgrade.rs)). Unmeasured storage growth
remains an open question in this design.

### Step 3: credential

Call the core `api-key` implementation described below. Write only
`api.security.api_key_hash` into TOML; save the random secret in a file created
with Unix mode `0600`, under a `0700` secrets directory. On Windows use a
protected DACL restricted to the operator (and service identity only if needed),
not a claim that POSIX `0600` secures NTFS. If required access control cannot be
established, fail without publishing a hash/config that enables the key.

Do not print, log, include in JSON/diffs, put into argv/env/service definitions,
or send the secret to an external process. Explain how the user can enter it
from the file into the local dashboard/client; never bake it into `OPERATING.txt`.
Reuse an existing configured credential on re-run. Missing/lost plaintext does
not authorize rotation. An optional later dedicated Stratum key may use
`[[api.security.keys]]` with `id`, `hash`, `scopes = ["mining"]`, `revoked = false`;
the initial quick win handles the master key only. Scoped keys still require a
master hash ([auth configuration](../configuration.md#apisecurity),
[credential validation](../../ergo-api/src/auth/credentials.rs)).

### Step 4: network, API and inbound P2P

Write `network`, `api.disabled = false`, `api.bind` (default loopback
`127.0.0.1:9099`), `api.public_bind = false`,
`api.peer_details.auto_download = false`, `api.peer_details.reverse_dns = false`.
Do not imply that choosing testnet changes the HTTP port; the loader uses 9099
on all networks. Use embedded network seeds rather than copying a hard-coded
mainnet `peers.known` list; custom peers are an explicit advanced input.
Custom `--peer IP:PORT` values write `peers.known`; `--allow-local` writes
`peers.allow_local = true` for learned LAN peer addresses. Devnet has no embedded
seeds, so require at least one explicit peer even for config validation. Its
genesis has no pinned header ID, so the wizard rejects NiPoPoW fast bootstrap
there. Testnet bootstrap is an advanced choice with no mainnet timing estimate;
default testnet/devnet purpose setup to genesis. Mainnet seed ports are mostly
9030 but vary, and testnet seeds have different
ports ([chain spec](../../ergo-chain-spec/src/lib.rs),
[loader](../../ergo-node/src/config/load.rs)).

Inbound defaults off: `peers.bind_addr = ""`, `peers.declared_addr = ""`.
An inbound choice writes both a local listening socket and, if known, the public
reachable socket. Offer 9030 as a **mainnet suggestion**, and require/confirm a
separate port for another coexisting network. `declared_addr` and `bind_addr`
are IP socket addresses (`SocketAddr`), not DNS names; IPv6 uses brackets.
Explain NAT forwarding/firewall work and that advertisement does not configure
either. Reject an advertised endpoint without a listener in the wizard, although
the current loader parses them independently. No UPnP or firewall changes.
Remote HTTP is an advanced choice requiring `api.public_bind = true` and explicit
`api.allowed_hosts`; explain public routes and proxy/TLS setup from
[API security](../configuration.md#security-notes-for-the-api). No secret makes
all routes private.

A future wizard may offer a best-effort bind/conflict check on the user's chosen
ports, close its socket immediately, and warn that success is not a reservation.
**This design task performs no bind, connection or service action on this host.**

### Step 5: mining reward and external bridge

Prompt for either an initialized node wallet's first EIP-3 key (leave
`mining.miner_public_key_hex` absent) or a public key (write it). Explain the
wallet's initialization/unlock next step and candidate availability. Never
collect recovery phrases or wallet passwords in the setup wizard. The shipped
wallet CLI can derive/export public keys, but its `generate` command prints a
mnemonic; the wizard must not invoke it and capture/log the output
([wallet CLI](../../ergo-wallet/src/bin/ergo-wallet.rs),
[wallet boot](../../ergo-node/src/wallet_boot.rs)).

For explicit keys, require a valid compressed secp256k1 curve point (33 bytes,
66 hex characters, `02`/`03` prefix), normalize hex, preview the network-specific
P2PK address and require confirmation of ownership. Current mining config
validation checks hex/length; the wizard should add point validation using the
existing `k256` dependency ([mining config](../../ergo-mining/src/config.rs),
[node manifest](../../ergo-node/Cargo.toml),
[wallet address code](../../ergo-wallet/src/address.rs)). Clarify this is the
public key used to construct the delayed reward script, not an arbitrary payout
address, private scalar or mining seed ([mining CLI](../../ergo-node/src/config/cli.rs)).

Final instructions link to
[`ergo-stratum-rs/README.md`](https://github.com/arkadianet/ergo-stratum-rs#readme)
and [Lithos](../lithos.md). Set its node URL to the selected API address, not its
README's example port 9052. Keep Stratum independent; do not add `ergo-solo` to
this node release, clone/build it automatically, or enable
`allow_unauthenticated_legacy_mining`. Check its supported key-file input before
writing a launcher: its documented `--api-key`/environment inputs are not a
secure key-file integration contract. Any such support is a separate upstream
change; the wizard should give a pointer until it exists.

### Step 6: service and operating bundle

Render, preview and optionally install the service for the selected identity.
Generate OS-native start/stop/status/update launchers and `OPERATING.txt` with
absolute paths, URLs, versions, key-file location (no contents), backup/recovery
commands, bootstrap caveats, graceful-stop timeout, logs and uninstall directions.
Use OS APIs/structured argument arrays for paths with spaces; never interpolate
untrusted values into shell fragments. Default to foreground operation. The
existing [systemd unit](../../deploy/ergo-node.service),
[shutdown lifecycle](../../ergo-node/src/node/boot/mod.rs),
[logging](../logging.md), and [recovery runbook](../operator-recovery.md) are the
source contracts; adapters below are proposed additions.

Service planning verifies that the selected identity can read the executable
and config and write data/log directories. Linux system mode suggests
`/etc/ergo-node/node.toml`, `/var/lib/ergo-node`, and a system-readable versioned
binary installation; the shipped `ProtectHome=yes` unit cannot simply use the
user-mode paths under a home directory. Replan and preview compatible paths or
reject installation, rather than producing a service that cannot start. The
node service needs the hash-bearing config, not the plaintext API-secret file.

| OS / targets | Service design and permissions | Stop/logging behavior |
|---|---|---|
| Linux glibc x86-64, musl x86-64, glibc ARM64 | Prefer user systemd: `~/.config/systemd/user/ergo-node.service`, owner config/data paths, explicit working directory. Install with user manager only if available. Show lingering instructions for start-at-boot without login; never enable it silently. System mode renders the shipped DynamicUser-style unit and privileged install commands; no automatic `sudo` or elevation. Non-systemd Linux gets foreground/scripts with an explicit “service unavailable” result. | SIGTERM, `TimeoutStopSec=300`, restart on failure, journal plus optional rolling files; never stop someone else's node by guessed PID |
| macOS ARM64, x86-64 | User LaunchAgent at `~/Library/LaunchAgents/net.arkadian.ergo-node.plist`; absolute `ProgramArguments`, working dir, controlled log paths, `RunAtLoad` and failure restart. Clearly distinguish login service from boot-time LaunchDaemon; system daemon needs explicit admin installation and dedicated identity. | SIGTERM and a tested five-minute graceful-stop allowance; validate launchd's actual stop timeout behavior on supported macOS versions |
| Windows x86-64 MSVC | Add a Windows SCM host path inside the existing node executable (e.g. internal `service run` mode) with a `windows-service`-style target-gated dependency; register exact binary/config/data arguments and a dedicated identity. Ordinary console `ergo-node.exe` cannot simply be registered as an SCM service. Installation requires an explicitly elevated invocation; emit a reviewable PowerShell plan otherwise. | STOP/SHUTDOWN control calls node shutdown, publishes STOP_PENDING with wait hints up to 300 seconds and then STOPPED. Use rolling files; test service ACLs and uninstall |

Windows is a real implementation phase, not a template-only promise. User-level
Windows startup can optionally use Task Scheduler as a separately labelled login
task; it must not masquerade as an SCM service. Services stop without reading the
API master key. A foreground stop helper can read the key file internally for
`POST /node/shutdown`; it never supplies `api_key` through a `curl -H` argv value.
`status` checks service/process identity plus `/api/v1/node/liveness` and readiness;
a syncing node is alive but may not be ready ([deployment probes](../deployment.md)).

### Step 7: existing installation and final actions

Default on an existing config: parse, validate, show a redacted diff, and write
`node.toml.proposed` without modifying the original. Interactive confirmation or
`--apply-existing --expected-config-sha256 HASH` is required to apply; take a
restricted timestamped backup and abort if the source changed after planning.
Preserve comments, unrelated tables, named credentials and customized paths.
No `--force` that bypasses these guards. Do not silently replace existing secrets,
service files or launchers; compare generated-file hashes in the installation
receipt, and preserve operator-edited files. Idempotent reruns report no changes.

Do not convert a populated archival directory into a snapshot install, clear an
existing directory, or turn a history-incomplete snapshot store into an explorer
by flipping a config key. For those transitions create a separate installation
plan/data directory and explain resync. Enforce the clean-DB bootstrap condition
before writes; if state cannot be safely identified, require a new directory
([bootstrap restrictions](../operating.md#fast-clean-db-boot-mode-2--nipopow),
[indexer restrictions](../../ergo-node/src/config/load.rs)). Existing node config
may contain secrets unrelated to the API hash, so errors must not dump the full
TOML input; report sanitized field/location information only.

Stage outputs in the same destination filesystem; set permissions before writing
secrets, flush, then publish with no-clobber creation or checked replacement.
There is no cross-file atomic rename for config plus key: publish key first,
then config, with an installation journal. A failure may leave an orphan key,
but must not activate a config referencing an unwritten secret. Never delete an
operator file during rollback. Report only paths and repair instructions after
an interrupted operation. Use a setup lock to serialize two wizard invocations.

Finish with exact foreground/service commands, selected API URL, key-file path,
mining reward address, expected bootstrap behavior, where to monitor
`/api/v1/sync`, how to stop, and the appropriate wallet discovery steps. A restored
wallet on a snapshot store needs current-UTXO discovery with a stopped node, and
has incomplete historical/custom-scan coverage
([operator recovery](../operator-recovery.md#wallet-discovery-without-historical-blocks)).
Never claim “synced”, “wallet recovered” or “mining ready” because files were
written. Start only if `--start` was requested; report liveness separately from
readiness and index catch-up. Record node version/SHA/target, preset and generated
file hashes in `<install-dir>/install.json` outside TOML, since the TOML schema
has no installation metadata section ([schema](../../ergo-node/src/config/toml_sections.rs)).

## 4. `ergo-node api-key`: standalone quick win

Implement this independently of the interactive wizard, services and release
layout. Proposed interface:

```text
ergo-node api-key generate --secret-file PATH [--config PATH]
    [--replace-hash EXPECTED_64_HEX] [--json]
ergo-node api-key hash --secret-file PATH|- [--json]
```

`api-key` without a mode shows usage and exits 2. Options belong to the subcommand:
current top-level `--config` conflicts with subcommands, so
`ergo-node --config PATH api-key ...` is not the proposed syntax
([CLI definition](../../ergo-node/src/config/cli.rs)).

Generation contract:

1. Require an explicit secret output path (no stdout destination `-`). Validate
   destination/permissions/config intent before requesting randomness. Reject
   existing files, symlinks/reparse points, unsafe ownership and unsafe secret
   parent directories. Create new secrets directories as 0700 on Unix; do not
   silently tighten permissions on an operator's existing shared directory.
   Use handle-based/no-follow checks where supported to prevent path-swap races;
   on Windows establish the restrictive DACL at creation, before data is written.
2. Obtain 32 random bytes from the OS CSPRNG (fallible `OsRng`); fail on entropy
   error. Encode **64 lowercase ASCII hex characters** as the plaintext secret.
   Hash those 64 ASCII bytes with Blake2b configured for a 32-byte digest. Do not
   hash the decoded random bytes or truncate a Blake2b-512 digest. This matches
   the HTTP middleware, which hashes header bytes, and Python smoke's
   `blake2b(key.encode(), digest_size=32)`
   ([auth](../../ergo-api/src/auth.rs), [release smoke](../../scripts/release.py)).
   Reuse the public [`ApiSecurity::hash_key`](../../ergo-api/src/auth.rs), which
   already implements this operator hash format and has the middleware's
   algorithm and encoding. Keep the change out of consensus hashing code. The
   independently tested
   [primitive hash](../../ergo-primitives/src/digest.rs) provides corroborating
   vectors.
3. Write `SECRET\n` to the output using exclusive creation, Unix 0600 or Windows
   owner-only DACL. Verify protection, flush and sync before reporting success.
   Use zeroizing buffers from allocation for random material, encoded secret
   and any input; no `Debug`, tracing or error dump of their contents. Node
   already depends on RNG/zeroize/hex/primitives
   ([node manifest](../../ergo-node/Cargo.toml)); the
   [wallet CLI](../../ergo-wallet/src/bin/ergo-wallet.rs) demonstrates protected
   secret input and zeroizing allocations. DACL support is additional work.
4. Without `--config`, stdout contains only:

   ```toml
   [api.security]
   api_key_hash = "<64 lowercase hex hash>"
   ```

   Stderr reports the secret-file path and “add this hash and restart”. With
   `--json`, stdout instead has `schema_version: 1`, `api_key_hash`,
   `secret_file`, `config_file` (null if absent), `config_updated`, and
   `restart_required`; no plaintext. Human diagnostics stay on stderr.
5. With `--config`, require an existing readable TOML file. Set only
   `api.security.api_key_hash` using a comment-preserving edit, retaining
   existing security keys/flags. If no hash exists, adding it is allowed by this
   explicit flag. If one exists, refuse unless `--replace-hash` exactly matches
   its current canonical hash; reject that flag without `--config`. Take a
   restricted backup, validate the candidate through the node resolver, check
   unchanged source digest, and publish atomically. Hash replacement does not
   revoke or rotate named credentials: explain this and leave them intact.
   If a candidate fails validation, sanitize parse diagnostics, preserve the
   config, and do not publish a new key. No implicit config search, service
   restart or hot reload. The master hash is boot-time configuration
   ([loader](../../ergo-node/src/config/load.rs),
   [runtime changes](../configuration.md#apisecurity)).
6. Multi-file failure handling follows the wizard's key-first publication rule:
   if config replacement fails after the key was published, retain that new
   protected key, leave original config intact and report its path as an orphan
   needing review. Never success-report a half-completed config update. Rotation
   writes to a **new** secret path; it never overwrites the existing key file.

Hash-only contract: read from a file or stdin without echo/prompt, cap input at
1024 secret bytes plus one line ending, remove exactly one terminal LF and its
optional preceding CR, then reject empty input, embedded CR/LF, controls,
non-ASCII or whitespace. Permit printable non-space ASCII (`0x21..0x7e`). Do
not trim arbitrary whitespace or hex-decode the input. For an existing file,
require the same owner-only protection as a generated file; stdin is the
explicit alternative. Hash mode writes no files and edits no config. Print the
same TOML snippet, or JSON with `schema_version`, `api_key_hash` only. The
newline rule lets a generated file be reused directly and matches actual header
bytes ([authentication contract](../../ergo-api/src/auth.rs)).

Exit status: 0 for completed generation/hash/update; 2 for CLI/input/config
validation or expected-hash mismatch; 1 for entropy, I/O, protection or publication
failure. All diagnostics describe operation/path/field, never the supplied
secret or full config text. An API key is an operator credential, not wallet
entropy. The quick win never creates a wallet, initializes node data or opens a
port. Update [configuration](../configuration.md#apisecurity),
[bundled config comments](../../ergo-node/ergo-node.toml),
[example comments](../../ergo-node/ergo-node.toml.example), and
[release quickstart](../release-quickstart.md) to show this command in its
implementation PR.

## 5. Verification and phased delivery

These are proposed implementation checks; none were run as part of this design.
Build on existing [config tests](../../ergo-node/src/config/tests.rs),
[release helper tests](../../scripts/test_release_policy.py) and
[release smoke](../../scripts/release.py), without using a live mainnet node.

- **Key command:** independent known Blake2b-256 vectors for `hello`, empty hash
  primitive and generated ASCII-vs-decoded-byte distinction; middleware accepts
  the generated file contents after the defined newline removal. Invalid key
  fails auth. Verify OS entropy failures, exclusive creation, Unix permissions,
  Windows DACLs, symlink/reparse refusal, stale source/expected-hash conflicts,
  interrupted key/config publication and preservation of prior config/key.
  Capture stdout/stderr/JSON and injected logs: secret bytes must not appear.
- **Planner/config:** all purpose × valid sync × network combinations pass the
  actual resolver; wrong indexer/bootstrap, R6 and insufficient pruning windows
  fail. Check exact preset output, genesis seed selection, header anchor inputs,
  mining curve points, unknown/custom fields preserved on edits, disk query
  failure, nonempty data refusal, path overlap, spaces/Unicode and shell
  metacharacters. Repeat application yields no diff. Two competing setup plans
  cannot overwrite one another.
- **CLI:** non-TTY without required flags fails promptly; dry run has no files,
  key generation, DB opens or sockets; generated launchers invoke only the
  planned binary/config/data path. Refuse automatic service start unless selected.
- **Services:** unit tests render units/plists/SCM argument plans; disposable CI
  machines exercise installation, permissions, start, restart, graceful stop,
  log locations, timeout and uninstall. Cover user/system distinctions and
  unavailable managers. Do not assume ordinary Windows console smoke proves SCM
  compatibility. Test packaged binaries across all six targets; service behavior
  across all three OS families, including both macOS architectures when possible.
- **Update/package:** verify checksums before extraction; reject traversal,
  absolute entries, duplicates and symlinks/reparse paths; extracted versions
  match the requested release. Failure before activation preserves old binaries;
  config/data/secrets are never archive extraction targets. Test corruption,
  truncated downloads, wrong target/version/SHA, unsupported manifest schemas,
  edited generated scripts, partial restart and explicit rollback caveats.

Efforts are rough engineering days for one developer with review/CI access;
Windows and cross-platform review may dominate elapsed calendar time. Each phase
has a useful endpoint and can ship independently.

| Phase | Scope / completion gate | Estimate |
|---|---|---|
| 0 | Agree on bootstrap/trust presentation, budgets, legacy-asset window and service scope; collect existing sizing records; draft exact UX/output schema | 0.5–1 day, plus maintainer input |
| 1 | `api-key` generation/hash, protected file handling on all OSes, guarded optional config update, docs and focused tests; dispatch before node runtime | 2–4 days; Windows ACL review may extend |
| 2 | Combined archives + release-wide aggregation, source/tag checks retained, migration notes and all six extracted smokes | 2–3 days |
| 3 | `init` planner, interactive/scripted presets, config edit/refusal/dry run, operating bundle, calibrated disk display; no service install required | 4–6 days |
| 4 | Linux user/system and macOS service adapters, install receipt, launchers and archive updater; disposable-host service checks | 3–5 days |
| 5 | Windows SCM host/installer/ACL/shutdown support and Windows updater/service integration | 4–7 days |
| 6 | GHCR native amd64/arm64 image pipeline, smoke/provenance and deployment docs/Compose; optional archive attestations | 2–4 days |

Working total: approximately 17–29 engineering days plus phase 0 and review;
these are scoped estimates, not a commitment. Do not delay the API-key quick win
or asset simplification for service completion. No config-crate extraction,
GUI, independent installer repository or consensus changes are required.

## 6. Release audit: all 54 assets

The six matrix targets each publish **nine** files: two bare executables, two
archives, four checksum sidecars and one manifest. There are 12 executable
payloads, each published twice (bare and archived), rather than 54 different
programs. Windows bare executable names include `.exe`; Windows archive names
do not. GitHub's automatically offered source zip/tar downloads are not among
these 54 uploaded assets. Sources: [live release API](https://api.github.com/repos/arkadianet/ergo/releases/tags/v0.12.0-rc.1),
[`TARGETS`, `package`, `checksum`](../../scripts/release.py),
[matrix/upload/publication](../../.github/workflows/release.yml).

Purpose/consumer codes for the exhaustive inventory below:

| Code | Purpose | Observed producer/consumer and smoke coverage |
|---|---|---|
| N | Bare node executable | `package()` copies the staged node to the release asset; checksum/manifest generator reads it, workflow uploads it. Maintainer reports local Linux glibc x86-64 `update.sh` use; not repository code. No in-repo bare-node downloader found. Bare copy is not separately executed by the smoke. |
| W | Bare wallet executable | Same producer/checksum/upload chain; no in-repo downloader or reported updater consumer. Not separately executed by smoke. |
| NA | Node archive | Operator quickstart/download use; `package()` extracts it, runs extracted node `--help`/`--version`, then fresh devnet boot, `/info`, keyed shutdown, reopen and keyed shutdown. |
| WA | Wallet archive | Operators needing CLI wallet; `package()` extracts it and runs wallet `--help`/`--version`. No wallet creation/signing smoke. |
| NS / WS | Bare executable checksum | Streaming SHA256 sidecar for N/W. NS has the reported Linux glibc updater consumer; no other in-repo consumer found. Helpers generate them; existing smoke does not verify downloaded sidecars. |
| NAS / WAS | Archive checksum | Integrity metadata for downloads; helpers generate and upload. No in-repo archive updater or checksum-verification smoke found. |
| M | Target manifest | JSON `target`, `version`, `sha`, and four asset-name→SHA256 entries. Generated after smoke; uploaded. No in-repo reader found; current publish `verify` does not consume it. |

Evidence for consumer bounds: [quickstart](../release-quickstart.md),
[release docs](../releasing.md), [helper](../../scripts/release.py),
[helper tests](../../scripts/test_release_policy.py). Repository-wide `rg` searches
included hidden workflow files and literal/dynamic executable asset names,
`.sha256`, `release-{target}.json`, `releases/download`, `gh release download`,
`update.sh`, tar/zip names and bare-binary prose. Matches relevant to software
assets were the producer/docs/tests; no first-party updater or public filename
contract was found. The downloader in [scripts/l4_inputs.py](../../scripts/l4_inputs.py)
uses a pinned **fixture** release `l4-inputs-2026-09-20`, not node/wallet assets;
Scala JAR fixture references are also unrelated. Negative search evidence cannot
rule out external users. The maintainer's script remains the one reported bare
consumer, and has not been accessed or modified here.

Every uploaded file, with its code referring to the purpose/consumer table:

| # | Asset | Code |
|---|---|---|
| 1 | `ergo-node-x86_64-unknown-linux-gnu` | N |
| 2 | `ergo-wallet-x86_64-unknown-linux-gnu` | W |
| 3 | `ergo-node-x86_64-unknown-linux-gnu.tar.gz` | NA |
| 4 | `ergo-wallet-x86_64-unknown-linux-gnu.tar.gz` | WA |
| 5 | `ergo-node-x86_64-unknown-linux-gnu.sha256` | NS |
| 6 | `ergo-wallet-x86_64-unknown-linux-gnu.sha256` | WS |
| 7 | `ergo-node-x86_64-unknown-linux-gnu.tar.gz.sha256` | NAS |
| 8 | `ergo-wallet-x86_64-unknown-linux-gnu.tar.gz.sha256` | WAS |
| 9 | `release-x86_64-unknown-linux-gnu.json` | M |
| 10 | `ergo-node-x86_64-unknown-linux-musl` | N |
| 11 | `ergo-wallet-x86_64-unknown-linux-musl` | W |
| 12 | `ergo-node-x86_64-unknown-linux-musl.tar.gz` | NA |
| 13 | `ergo-wallet-x86_64-unknown-linux-musl.tar.gz` | WA |
| 14 | `ergo-node-x86_64-unknown-linux-musl.sha256` | NS |
| 15 | `ergo-wallet-x86_64-unknown-linux-musl.sha256` | WS |
| 16 | `ergo-node-x86_64-unknown-linux-musl.tar.gz.sha256` | NAS |
| 17 | `ergo-wallet-x86_64-unknown-linux-musl.tar.gz.sha256` | WAS |
| 18 | `release-x86_64-unknown-linux-musl.json` | M |
| 19 | `ergo-node-aarch64-unknown-linux-gnu` | N |
| 20 | `ergo-wallet-aarch64-unknown-linux-gnu` | W |
| 21 | `ergo-node-aarch64-unknown-linux-gnu.tar.gz` | NA |
| 22 | `ergo-wallet-aarch64-unknown-linux-gnu.tar.gz` | WA |
| 23 | `ergo-node-aarch64-unknown-linux-gnu.sha256` | NS |
| 24 | `ergo-wallet-aarch64-unknown-linux-gnu.sha256` | WS |
| 25 | `ergo-node-aarch64-unknown-linux-gnu.tar.gz.sha256` | NAS |
| 26 | `ergo-wallet-aarch64-unknown-linux-gnu.tar.gz.sha256` | WAS |
| 27 | `release-aarch64-unknown-linux-gnu.json` | M |
| 28 | `ergo-node-aarch64-apple-darwin` | N |
| 29 | `ergo-wallet-aarch64-apple-darwin` | W |
| 30 | `ergo-node-aarch64-apple-darwin.tar.gz` | NA |
| 31 | `ergo-wallet-aarch64-apple-darwin.tar.gz` | WA |
| 32 | `ergo-node-aarch64-apple-darwin.sha256` | NS |
| 33 | `ergo-wallet-aarch64-apple-darwin.sha256` | WS |
| 34 | `ergo-node-aarch64-apple-darwin.tar.gz.sha256` | NAS |
| 35 | `ergo-wallet-aarch64-apple-darwin.tar.gz.sha256` | WAS |
| 36 | `release-aarch64-apple-darwin.json` | M |
| 37 | `ergo-node-x86_64-apple-darwin` | N |
| 38 | `ergo-wallet-x86_64-apple-darwin` | W |
| 39 | `ergo-node-x86_64-apple-darwin.tar.gz` | NA |
| 40 | `ergo-wallet-x86_64-apple-darwin.tar.gz` | WA |
| 41 | `ergo-node-x86_64-apple-darwin.sha256` | NS |
| 42 | `ergo-wallet-x86_64-apple-darwin.sha256` | WS |
| 43 | `ergo-node-x86_64-apple-darwin.tar.gz.sha256` | NAS |
| 44 | `ergo-wallet-x86_64-apple-darwin.tar.gz.sha256` | WAS |
| 45 | `release-x86_64-apple-darwin.json` | M |
| 46 | `ergo-node-x86_64-pc-windows-msvc.exe` | N |
| 47 | `ergo-wallet-x86_64-pc-windows-msvc.exe` | W |
| 48 | `ergo-node-x86_64-pc-windows-msvc.zip` | NA |
| 49 | `ergo-wallet-x86_64-pc-windows-msvc.zip` | WA |
| 50 | `ergo-node-x86_64-pc-windows-msvc.exe.sha256` | NS |
| 51 | `ergo-wallet-x86_64-pc-windows-msvc.exe.sha256` | WS |
| 52 | `ergo-node-x86_64-pc-windows-msvc.zip.sha256` | NAS |
| 53 | `ergo-wallet-x86_64-pc-windows-msvc.zip.sha256` | WAS |
| 54 | `release-x86_64-pc-windows-msvc.json` | M |

Both archive flavors duplicate the same support payload. `package()` includes
README from `docs/release-quickstart.md`, licenses, changelog, security,
architecture, toolchain file, operating/configuration/compatibility/logging/
operator-controls/deployment docs, two config templates and all of `deploy/`.
Markdown rewriting substitutes extracted-binary commands and pins omitted source
links to the exact source SHA. The copied `deploy/compose.yml` currently builds
from source and its Dockerfile is not in these archives; it is a source-checkout
example, not a release-only container installer. Preserve link adaptation and
clarify that distinction in the combined README
([package/doc adaptation](../../scripts/release.py),
[documentation tests](../../scripts/test_release_policy.py),
[Compose](../../deploy/compose.yml)).

Existing provenance gates resolve tag/version/HEAD before CI and cost-ledger
validation, build both binaries `--locked`, execute platform smoke, and recheck
origin's tag before publication. **`verify` checks source/tag provenance, not the
54 downloaded artifacts or their manifest hashes.** Asset simplification must
preserve these gates and add artifact aggregation validation
([release workflow](../../.github/workflows/release.yml),
[`resolve`, `verify_remote`, `main`](../../scripts/release.py),
[provenance tests](../../scripts/test_release_policy.py)).

## 7. Proposed lean release layout

Publish these target-qualified **combined** archives (target names remain the
current [matrix](../../.github/workflows/release.yml)):

```text
ergo-x86_64-unknown-linux-gnu.tar.gz
ergo-x86_64-unknown-linux-musl.tar.gz
ergo-aarch64-unknown-linux-gnu.tar.gz
ergo-aarch64-apple-darwin.tar.gz
ergo-x86_64-apple-darwin.tar.gz
ergo-x86_64-pc-windows-msvc.zip
SHA256SUMS
release.json
```

Eight uploaded assets, down from 54 (46 fewer, approximately 85%). Archives do
not need a version in the filename because the release URL identifies the tag;
the internal metadata and release-wide manifest verify that tag/version/SHA.
Keep both executables at the archive root, with `.exe` on Windows, so existing
runbook command paths remain valid. Share one copy of licenses/docs/config/deploy
and add `release-info.json` containing schema version, tag, workspace version,
source SHA, target, executable names and service capabilities. Bundle the new
service/updater templates when available. Do not publish a third wizard binary.
This changes packaging, not the two built programs
([current packaging](../../scripts/release.py), [build command](../../.github/workflows/release.yml)).

The tradeoff is a larger download for someone who needs only one executable;
the updater can install only the node but still downloads the shared archive.
Measure compressed bytes before finalizing, rather than claiming a bandwidth
reduction from the asset-count reduction.

`release.json` is recommended, though optional in the minimum layout. Proposed
schema: `schema_version = 1`, `tag`, `version`, `sha`, and a `targets` map whose
six entries contain archive name, archive byte length, archive SHA256,
node/wallet executable names, and internal binary SHA256s. An optional
`compatibility_assets` list identifies the transitional Linux executable and
sidecar. Reserve a future `images` map for OCI digests; reject unsupported major
manifest schemas in the updater. Package-local metadata does not include archive
hashes (that would be self-referential).

Produce `release.json` first from validated per-target build receipts, then
`SHA256SUMS` in lexical filename order, UTF-8 with LF line endings:

```text
<64 lowercase sha256>  ergo-aarch64-apple-darwin.tar.gz
...
<64 lowercase sha256>  release.json
```

There are seven steady-state entries (six archives plus manifest); never include
`SHA256SUMS`' own hash. Use basenames only, exactly two spaces, no paths/newlines,
and reject duplicate names. During transition also checksum the two compatibility
files in `SHA256SUMS`. Manifest archive hashes and checksum rows must agree.
The existing helper's [checksum format](../../scripts/release.py#L162) is already
compatible with this convention, but it writes one sidecar per payload today.

Checksums detect corruption; downloading hashes beside payloads over HTTPS does
not independently authenticate a compromised release. Prefer GitHub artifact
attestations for archives after aggregation checks, retaining `SHA256SUMS` for
ordinary tooling. GitHub provides provenance generation/verification through
[artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations).
Plan narrowly scoped `id-token: write` and `attestations: write` in the attesting
jobs; pin the chosen action by immutable SHA under the repository's
[CI policy](../../scripts/ci-policy.py). Attest archives against the resolved
source commit, not just the checksums file. Verify subject digest, repository,
workflow and commit identity in an attestation-aware updater. Validate generated
provenance on both tag-triggered and manual runs: the dispatch event's commit
can differ from the resolved release commit, so checking out `src/` alone is
not a sufficient provenance contract. Bind the resolved release SHA explicitly
and refuse provenance that does not identify it. Attestations stored
by GitHub add no uploaded release asset; if offline bundles are published,
count those additional files explicitly. A detached signature on `SHA256SUMS`
is an alternative only with a maintainer-approved trusted-key rotation and
verification policy; no managed signing key is assumed in the current workflow.

| Layout | Uploaded release asset count |
|---|---:|
| Six archives + `SHA256SUMS` only | 7 |
| Recommended: above + `release.json` | 8 |
| Recommended + one detached checksum signature | 9 |
| Recommended + GitHub-stored attestations, no uploaded bundles | 8 |
| Recommended + Linux bare executable and existing `.sha256` for transition | 10 |
| Transition plus one detached signature | 11 |

OCI tags/manifests live in a registry and do not inflate these GitHub Release
file counts. Do not retain twelve obsolete archive/binary aliases indefinitely;
that would leave much of the menu clutter intact.

## 8. Migration, updater, workflow and smoke changes

### Compatibility window and operator updates

Keep **only** `ergo-node-x86_64-unknown-linux-gnu` and
`ergo-node-x86_64-unknown-linux-gnu.sha256` for the first two tags using the new
layout. The choice covers the reported maintainer updater without implying a
public bare-name contract. State the exact removal tag/date in the first new
release's changelog/notes after the maintainer picks it. Leave previous releases
and their assets untouched. No need to retrieve or edit the maintainer's private
scripts. Announce wallet/archive filename changes in
[CHANGELOG](../../CHANGELOG.md), [quickstart](../release-quickstart.md),
[releasing](../releasing.md), and [deployment](../deployment.md).

An `update.sh release`-style updater changes from “download bare node + sidecar”
to:

1. Resolve a chosen release tag once (stable channel excludes prereleases by
   default; `--tag`/explicit opt-in can select an RC). Download `release.json`,
   `SHA256SUMS` and the single matching archive from that exact tag.
2. Verify manifest/checksum consistency and archive SHA256 before extracting.
   For `sha256sum`/`shasum`/PowerShell, select the one exact filename rather than
   running verification for every platform file that was not downloaded. If
   attestation verification is enabled, complete it before execution.
3. Extract into a fresh staging/version directory outside config/data/secrets;
   reject unsafe members. Check internal target/tag/version/SHA and executable
   digests; run only `--version` initially. Install both programs or select just
   `ergo-node` from the archive as the existing script does. Preserve executable
   permissions on Unix.
4. Read compatibility/migration notes; explicitly stop the identified service,
   wait for graceful exit, activate the new version and start if the node was
   previously running. Check liveness/readiness separately. Never replace a
   running Windows executable in place. Keep the previous version directory and
   record the activation, config hash and DB compatibility decision.

The first-party wizard should generate `start.sh`, `stop.sh`, `status.sh`,
`update.sh` on Unix and equivalent PowerShell launchers on Windows, plus
`OPERATING.txt`. Prefer a small proposed native `ergo-node update` command for
HTTPS/checksum/safe extraction and OS service coordination, with wrappers calling
it; existing `reqwest`, `sha2`, compression and JSON dependencies reduce the need
for host tools ([node dependencies](../../ergo-node/Cargo.toml)). Tar and zip extraction
and platform-service integration still need review/dependencies. An updater's
implementation belongs to phase 4/5, not the standalone API-key phase. Expose
`update --check`, `update --tag TAG --apply`, `--allow-prerelease`, and a plan-only
mode; require explicit application and no automatic background updates.

Use versioned install directories. Unix can atomically switch a `current`
symlink under an owner-controlled installation root; Windows can update the
recorded launcher pointer and SCM binary path after stopping, without requiring
symlink privileges. Service installations need the corresponding user/admin
rights; no unattended elevation. Source `update.sh main` remains a developer
workflow with its own build resources and exact commit record, not an automatic
fallback when a release download fails. Generated product updaters support
published tags only; the maintainer can keep their separate `main` script.

Rolling back executables is not necessarily rolling back data. Current 0.12
startup can convert redb data automatically; upgrading and then downgrading may
require retained backups and stopped-node recovery rather than swapping binaries.
The updater must surface that compatibility decision and never delete rollback
copies silently ([migration runbook](../operating.md#migrating-legacy-redb-databases),
[compatibility policy](../compatibility.md#versioning-and-stability)).

### Exact planned changes to `scripts/release.py`

Keep `resolve`, `validate_tag` and remote tag verification semantics intact.
Modify these concrete boundaries in the [existing helper](../../scripts/release.py):

- `package`: replace the outer node/wallet archive loop with one shared staging
  tree per target; copy both binaries before documentation adaptation. Preserve
  all current support content, permissions, pinned links and Windows naming.
  Add internal `release-info.json` and the new combined archive basename.
  Extract the **one** archive, inspect both executables, run the existing node
  smoke on that extracted node/config, then issue a build receipt.
- Normalize archive ordering, UID/GID, modes, mtimes and gzip/zip timestamps
  from a declared reproducible timestamp policy (for example commit time, with
  gzip header mtime fixed), rather than staging/check-out wall time. The current
  helper uses `copy2`, Markdown rewrites and ordinary tar/zip writers, so archive
  byte identity across repackaging is not established. Test repeat packaging of
  identical supplied binaries/docs. This does not promise reproducible Rust
  binaries; publication retries should reuse the validated artifacts whenever
  possible rather than rebuild and silently change published checksums.
- `checksum`: separate digest calculation from sidecar writing. Ordinary archives
  and binaries no longer generate sidecars or bare copies. An explicit
  `--legacy-linux-node` packaging option, accepted only for
  `x86_64-unknown-linux-gnu`, writes the transitional bare node plus original
  sidecar. Compare it byte-for-byte/hash-for-hash with the archive's node.
- Output structure: `release-artifacts/public/` contains only the archive (and
  compatibility pair for that one target); `release-artifacts/internal/` contains
  `receipt-<target>.json` with schema/target/tag/version/SHA, public-file hashes
  and byte lengths, internal executable hashes, and completed smoke checks.
  Receipts are CI transport, **not release assets**. Derive tag from the already
  resolved release environment and validate it against workspace version/HEAD.
- Add `aggregate --input DIR --output DIR --tag TAG --sha SHA` for the publishing
  job. Require exactly six distinct expected target receipts, same tag/version/
  SHA, successful recorded smoke, exact allowed filenames and no unexpected
  payloads; recalculate each actual downloaded payload's hash/size. Reject
  duplicate names, missing targets, wrong schema, path traversal and stale files.
  Flatten only validated public payloads into the output, generate `release.json`
  and `SHA256SUMS` as specified above, and check compatibility-pair policy.
- Keep source `verify` separate from aggregation. Extend CLI/tests for the new
  aggregate and compatibility options, and expose an inventory check to enforce
  8 steady-state or 10 transitional public files. Make retries work from a clean
  output stage; do not carry stale `.sha256`/per-target manifests forward.

This also removes public `release-<target>.json`, retaining richer per-target
metadata internally and one public manifest. Existing `packaged_document()`
rewrites README/operating commands and links; preserve it, update its text from
“node archive/other binary archive” to the shared archive, and add
`operator-recovery.md` to `DOCS` because the wizard's wallet/backup next steps
now depend on it. Update [release quickstart](../release-quickstart.md) to mention
both binaries, new commands when shipped, and checksum selection.

### Exact planned changes to `.github/workflows/release.yml`

The six target matrix, locked two-binary build, exact-SHA checkouts, CI and
cost-ledger prerequisites, non-cancelling release concurrency and moved-tag
rejection remain required ([current workflow](../../.github/workflows/release.yml)).

1. Revise workflow header/help to describe one shared archive per target. Pass
   `RELEASE_TAG` from `needs.resolve.outputs.tag` to packaging. Add the legacy
   option only to the glibc x86-64 matrix entry for the declared window; do not
   let a manual dispatch bypass release validation or extend compatibility.
2. Upload `release-artifacts/public/*` and `release-artifacts/internal/*` as the
   single CI artifact `release-<target>`; keep `if-no-files-found: error` and
   extraction smoke before upload. Internal CI artifact count remains six.
3. In `publish`, download those artifacts, check out the resolved SHA, run source
   `verify`, then run `aggregate` with resolved tag/SHA into a clean `public/`
   directory. Add optional attestations only for the validated payload list;
   rerun source `verify` immediately before the publication step as a best-effort
   last moved-tag guard. A tag cannot be made immutable by this workflow alone.
4. Replace `files: artifacts/**/*` with `files: public/*`, populated by the
   exact-allowlist aggregator. Fail missing/extra-file checks before creating or
   updating the release. Keep the current prerelease decision and preservation
   of an existing nonempty release body. Because reruns preserve manual notes,
   put migration notices in the new tag's changelog before first publication.
5. On a rerun, compare existing assets for the same tag: identical digests may be
   reused; differing published bytes require an explicit maintainer recovery
   procedure/new tag rather than silently overwriting an immutable release.
   Do not delete old-release assets or unrelated fixture releases. Cleaning
   local aggregation output is routine; public asset deletion is not migration.

### Smoke and helper-test changes

In [`package()` and `smoke_node()`](../../scripts/release.py), remove duplicate
archive extraction paths and execute both binaries from the combined extracted
directory on each target. Preserve current node boot/reopen/shutdown checks:
temporary devnet, loopback peers/API, dynamic free ports, no public seeds,
peer enrichment disabled, bounded caches, a random test key and no persistent
host data. Preserve both executables' `--help` and exact workspace `--version`.
Do not replace these with a packaging inventory-only check. Current shutdown
also verifies keyed auth; it does not cover wrong-key refusal or wizard behavior.

When `api-key` ships, replace the smoke's manual Python **generation** with the
extracted node command writing a temporary key file/config; independently hash
its ASCII secret with Python's Blake2b-256 to verify it. Assert plaintext is absent
from captured command output, use it only as an in-process HTTP header, and
exercise a wrong/missing key rejection before authorized shutdown. Keep all
secrets/temp state under the smoke temporary directory. Run `init --non-interactive`
into another temp directory with devnet/genesis/no service, an explicit temporary
loopback peer, no start, and inspect
its resulting config. Mainnet fast preset output is validated without fetching
proofs or connecting to mainnet. Real SCM/launchd/systemd tests remain separate.

Extend [scripts/test_release_policy.py](../../scripts/test_release_policy.py):
keep existing provenance and Markdown-link regression tests; update their
quickstart wording expectations; add combined archive inventory/Windows names,
executable permissions, each missing binary/doc/config, hash corruption, six
receipt aggregation, mismatch/duplicates/extra/missing target, newline/path
injection, exact checksum rows, compatibility-window counts, and nonpublic
receipt exclusion. Use fixture files/mocked process execution for fast helper
tests, with the actual extracted-node smoke retaining executable validation in
release CI. No added mainnet integration test is needed for layout changes.

## 9. Container publication

Yes: publishing a release-tagged GHCR image belongs in the node release process,
after exact-commit validation and image smoke. The existing unprivileged
[Dockerfile](../../Dockerfile) and [Compose](../../deploy/compose.yml) already
establish the UID/GID 10001, mounted config, external data volume, loopback host
HTTP mapping, liveness health check and five-minute graceful stop contracts.
Publishing should preserve them. A container is an alternative deployment path,
not the prerequisite for the interactive wizard.

Proposed `ghcr.io/arkadianet/ergo-node:<version>` contains both binaries, supports
`linux/amd64` and `linux/arm64`, and has OCI source/version/revision/license
labels. Publish the immutable version and commit tags; promote `latest` only
for stable tags, never RCs. Record image index/per-architecture digests in release
metadata when this phase is enabled. Packages are separate from release assets.
GitHub supports workflow `GITHUB_TOKEN` publication, repository association,
anonymous pulls for public packages and digest-pinned pulls; first publication
needs a visibility/permission decision
([GHCR documentation](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry)).

Add an image-build/smoke path depending on `resolve`, validation and the Linux
native build artifacts. Initially the Dockerfile's existing source build is the
lowest code-change option, but duplicates compilation. Prefer a release-only
runtime Dockerfile/stage that copies the already smoke-tested glibc amd64/arm64
binaries, using a tested pinned base compatible with the binaries' required glibc.
Do not assume binaries built on `ubuntu-latest` run on Debian bookworm; that
compatibility must pass container execution or require Linux builds on an older
baseline. This is a known validation question from the current
[runner matrix](../../.github/workflows/release.yml) and
[Debian runtime](../../Dockerfile), not a measured failure. Preserve source-build
Dockerfile use for developers.

Use native architecture jobs where possible; QEMU is a fallback with additional
runtime and confidence cost ([deployment guidance](../deployment.md)). Before
pushing/promoting user-facing tags, smoke the image under UID 10001 against a
fresh temporary devnet volume with loopback-only mappings and runtime-mounted
credentials. Check both versions, health endpoint, fresh boot, authenticated
shutdown, restart/reopen, volume ownership, read-only root/capability settings
and graceful stop. Push content-addressed/staging images only after these checks,
then assemble/promote the validated multiarch index. Reject moved tags again
before promotion; use job-local `packages: write`, and OIDC/attestation permissions
only where used. Pin added actions under [CI policy](../../scripts/ci-policy.py).
Do not give every build job registry-write permission.

Change Compose's published deployment path to a version/digest-selected `image:`
with no build requirement, keeping a separate source-build override/example.
Never embed an API key or run first-boot interactive key generation in an image
layer. Document wizard-generated config mounting, UID ownership and probes;
plaintext API secrets stay with operator clients, since the node needs only
the configured hash. Include separate client secret mounts only where needed
in [deployment](../deployment.md). HTTP bind inside a container remains `0.0.0.0`
with `public_bind = true`, while host mapping remains loopback by default.

Costs: two image assemblies, temporary registry storage, image smoke on both
architectures, base-image security updates/scanning, action-pin review,
visibility/retention policy and digest/provenance maintenance. Reusing native
binaries avoids another two Rust builds; using the current source Dockerfile
adds them and emulation may be substantially slower. No monetary or CI-minute
estimate is defensible without this repository's runner/billing measurements.
The phase estimate is 2–4 engineering days, with glibc compatibility potentially
adding work. Version-tagged image rebuilding for base fixes needs a policy
(explicit image revision/digest rather than silently changing a promised immutable
tag). Do not promise a transaction spanning GitHub Release and registry: if one
publication fails, keep validated staging outputs and report/retry the missing
surface; never claim full distribution success until both are available.

## 10. Maintainer decisions and open questions

1. Should wallet/solo-mining setup recommend fast **unanchored** bootstrap with
   explicit consent, or recommend anchored/full-header/genesis sync until the
   snapshot trust caveat is closed? Who supplies maintained sizing/trust records?
2. Is the proposed distinction acceptable: explorer = archive plus index;
   archival = complete blocks without index/mempool; solo mining excludes Lithos
   and storage-rent self-claim unless explicitly selecting the advanced profile?
3. Which OS service modes are supported promises at first release, and who can
   review/test Windows SCM/ACL and macOS launchd behavior? Is Linux user service
   the preferred default over the shipped system service?
4. Approve eight steady-state assets and the two-tag Linux bare-pair transition;
   which exact tag/date removes it, and are there any external consumers beyond
   the reported local updater that repository search cannot find?
5. Are GitHub attestations sufficient for update authenticity, or is an offline
   signature/trusted-key policy required? Should attestation verification be
   mandatory for the first-party updater or an explicit mode?
6. Approve GHCR namespace/public visibility, stable/RC tag policy and base-image
   maintenance ownership; is container publication a required release gate?
   Choose the glibc build baseline after image validation.

Unmeasured points remain explicit: per-preset disk footprint/growth and bootstrap
peak, incremental binary size, CI/image costs, glibc runtime compatibility,
service-stop behavior across supported OS versions, and external asset consumers.
They require maintainer records, implementation measurements or disposable CI
validation; they do not require inspecting or changing the running host.
