# Ergo Rust Node

An independent Rust full node for [Ergo](https://ergoplatform.org), built for
consensus compatibility with the [Scala reference client](https://github.com/ergoplatform/ergo).
It is for node operators, miners, and developers who want to explore a Rust implementation.
**Pre-1.0 alpha: do not use it for funds custody or production infrastructure.**
Read the [security policy](SECURITY.md) and [compatibility limits](docs/compatibility.md).

## Get started

### Download

Download the archive for your platform from [GitHub Releases](https://github.com/arkadianet/ergo/releases).
Each archive holds both programs, `ergo-node` and the `ergo-wallet` CLI, with
config templates and docs. These six platforms are built by the
[release workflow](.github/workflows/release.yml):

| Platform | Archive |
|---|---|
| Linux x86-64, glibc | `ergo-x86_64-unknown-linux-gnu.tar.gz` |
| Linux x86-64, static musl | `ergo-x86_64-unknown-linux-musl.tar.gz` |
| Linux ARM64, glibc | `ergo-aarch64-unknown-linux-gnu.tar.gz` |
| macOS Apple Silicon | `ergo-aarch64-apple-darwin.tar.gz` |
| macOS Intel | `ergo-x86_64-apple-darwin.tar.gz` |
| Windows x86-64, MSVC | `ergo-x86_64-pc-windows-msvc.zip` |

Verify it against the release's `SHA256SUMS`, for example
`sha256sum --ignore-missing -c SHA256SUMS` on Linux.

### Run

Extract the archive into its own directory. From that directory:

```sh
./ergo-node init --data-dir ../ergo-data
```

`init` asks what the node is for (wallet, mining, explorer or archival) and how
to sync, then writes a validated config and a protected API key into the data
directory and prints the command that starts the node. For scripted setups,
pass the choices as flags; see `./ergo-node init --help`. To configure by hand
instead:

```sh
cp config/ergo-node.toml ./ergo-node.toml
./ergo-node --config ./ergo-node.toml --data-dir ../ergo-data
```

On Windows, use `ergo-node.exe`. Open the dashboard at <http://127.0.0.1:9099/>.
Keep the data directory outside the extracted archive so upgrades do not replace it.
See the [release quickstart](docs/release-quickstart.md).

### Choose a setup

Edit the copied `ergo-node.toml` before starting; update its existing sections.

| Preset | Settings | What to expect |
|---|---|---|
| Archival + explorer (default) | `[node] state_type = "utxo"`, `verify_transactions = true`, `blocks_to_keep = -1`; `[indexer] enabled = true` | Full history and address/token queries; long sync from genesis. |
| Fast bootstrap | `[node.utxo] utxo_bootstrap = true`; `[node.nipopow] nipopow_bootstrap = true`; `[indexer] enabled = false` | UTXO snapshot + NiPoPoW; about 20 minutes on mainnet, depending on peers and bandwidth. |
| Mining | `[node] state_type = "utxo"`; `[mining] enabled = true`; reward key as described below | External miner API; starts serving work after sync. |

For fast bootstrap, start with an empty data directory and use these settings:

```toml
[node]
state_type = "utxo"
verify_transactions = true
blocks_to_keep = -1
[node.utxo]
utxo_bootstrap = true
[node.nipopow]
nipopow_bootstrap = true
p2p_nipopows = 2
[indexer]
enabled = false
```

Snapshot trust verification is provisional. Cross-check the installed UTXO root
against a known-good reference before trusting the state. Read the [fast bootstrap guide](docs/operating.md#fast-clean-db-boot-mode-2--nipopow)
and [configuration reference](docs/configuration.md).

Mining needs either `[mining] miner_public_key_hex` (a 33-byte compressed
secp256k1 public key, 66 hex characters; `ergo-wallet pubkey` prints it from a
mnemonic) or an initialized node wallet, whose first EIP-3 key is used.
The node supplies mining work through REST, so GPU rigs need a Stratum server
or pool in between: for example [ergo-solo](https://github.com/arkadianet/ergo-stratum-rs)
for solo mining, or [Lithos](docs/lithos.md). See [mining templates](docs/operator-mining.md).

### Unlock wallet and mining

**Wallet routes, mining controls, and other privileged calls need an API key.**
The dashboard and public reads work without one. `ergo-node init` already
creates one; for a hand-written config, create a key:

```sh
./ergo-node api-key generate --secret-file ./api-key.secret
```

This saves a random secret in a new file only you can read, and prints the
line to add to your config:

```toml
[api.security]
api_key_hash = "<64 lowercase hex characters>"
```

Add it to `ergo-node.toml` and restart the node. Clients send the **secret**
from the file, not the hash, in the `api_key` header; enter it in the dashboard
to authorize privileged calls. Then initialize or unlock your wallet.
`ergo-node api-key hash --secret-file PATH` prints the hash for an existing
secret. See [API authentication](docs/configuration.md#apisecurity).

### Requirements

- Mainnet P2P uses TCP port **9030**. The default config is outbound-only;
  set `[peers] bind_addr` to accept inbound connections.
- The API and dashboard bind to **127.0.0.1:9099** by default. Keep remote
  access behind an authenticated reverse proxy. See [API security](docs/configuration.md#security-notes-for-the-api).
- The explorer index roughly doubles disk usage. For scale, one mainnet archival
  node in October 2026 used about 44 GB for state, 45 GB for the index and about
  3 GB of RAM. Memory includes a default 1 GiB tree cache plus separate 1 GiB
  cache budgets for state, indexer, and peer databases; these do not limit total
  memory use. See [resource planning](docs/operating.md#troubleshooting).

### Run as a service

Linux systemd and Docker Compose packages are included. Systemd uses an unprivileged user and persistent state.
Compose keeps data in a named volume and publishes the API on host loopback. Follow [deployment instructions](docs/deployment.md).

### Upgrading

Stop the old node cleanly and back up its data and config before upgrading.
**0.11 data upgrades automatically** when started with the new binary.
Conversion needs extra free space, and the explorer index rebuilds in the background.
Read the [0.11 upgrade guide](CHANGELOG.md#upgrading-from-011) and [operating instructions](docs/operating.md#upgrading-the-node) first.

## What you get

- **Dashboard:** Overview with charts and events, Explorer, Peers, Mempool,
  Mining, Voting, and Wallet. See [monitoring](docs/operating.md#monitoring).
- **REST APIs:** Scala-compatible routes plus the native `/api/v1/*` API.
  Browse `/swagger` and `/swagger/native` on your node; see [API coverage](docs/compatibility.md).
- **Events and webhooks:** polling, realtime WebSocket subscriptions, replay, and delivery.
  See the [events guide](docs/events.md).
- **Mining:** external-miner candidates and solutions, exact candidate inspection,
  fee estimates, block policies, and private transactions. See [mining](docs/operator-mining.md),
  [block policies](docs/miner-block-policy.md), and [private mining](docs/private-mining.md).
- **Wallet CLI:** mnemonic generation/import, key derivation, addresses, and encrypted keystore export.
  Run `./ergo-wallet --help`; see [wallet usage](docs/overview.md#running) and [keystore export](docs/lithos.md#wallet-files).
- **Offline recovery:** `doctor`, `utxo-stats`, `backup`, `verify-backup`, `restore`, and `wallet-scan-utxo`.
  Stop the node first and follow the [recovery guide](docs/operator-recovery.md).

## Status

Consensus paths have oracle-backed tests and mainnet validation evidence; deployment
exposure is limited. Read [compatibility](docs/compatibility.md) and
[mode evidence](docs/compatibility.md#operating-mode-status) for scope and remaining work.

| Capability | Status | Caveat |
|---|---|---|
| Mode 1 — full archive | Supported | Long initial sync |
| Mode 2 — UTXO snapshot, consume + serve | Supported | Provisional snapshot trust |
| Mode 3 — pruned history | Supported | Fresh stores replay from genesis before pruning; retention campaigns open |
| Mode 4 — pruned + snapshot | Supported | Live multi-peer soak outstanding |
| Mode 5 — digest verifier | Supported | AD-proof parity pinned to one mainnet window; reorg re-anchor open |
| Mode 6 — headers only | Supported | No transaction validation or UTXO queries |
| NiPoPoW, consume + serve | Supported | Bootstrap requires compatible settings |
| Explorer index (`/blockchain/*`) | Supported | Full archive required |
| External-miner protocol | Supported | UTXO state required |
| HD wallet and multisig primitives | Supported | Cooperative distributed multisig deferred |

## For developers

### Build and test

Rust **1.99.0** is pinned in [rust-toolchain.toml](rust-toolchain.toml); `rustup` installs it on first build.
From a source checkout:

```bash
cargo build --locked --release -p ergo-node
cargo build --locked --release -p ergo-wallet
./target/release/ergo-node --config ergo-node/ergo-node.toml
```

The core checks are:

```bash
cargo fmt --all -- --check
python3 scripts/check-rust-fragments.py
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace
RUSTDOCFLAGS="-D warnings" cargo doc --locked --workspace --all-features --no-deps
python3 scripts/ci-policy.py
```

The [contribution guide](CONTRIBUTING.md) gives the full local gate and feature-gated tests.
The [overview](docs/overview.md) covers build profiles and workflows; [ARCHITECTURE.md](ARCHITECTURE.md)
and the [codemap](docs/codemap.md) explain runtime boundaries and crate responsibilities.

### Correctness and contributions

Consensus-boundary tests use external Scala fixtures and real mainnet bytes, never self-oracles.
Expected values computed by the code under test show internal consistency, not compatibility.
Mainnet-observed behavior settles parity disputes.
`sigma-rust` is a dev/test oracle and never part of the consensus path.

Changes to consensus crates (`ergo-primitives`, `ergo-ser`, `ergo-crypto`, `ergo-sigma`,
`ergo-validation`, `ergo-state`, `ergo-mining`) require oracle-backed fixtures. Keep fixtures in `test-vectors/` with reproducible provenance.
Read [contribution rules](CONTRIBUTING.md#test-conventions) and [compatibility policy](docs/compatibility.md).

## Documentation

**Operators**

- [Release quickstart](docs/release-quickstart.md) · [Configuration](docs/configuration.md)
- [Operating and modes](docs/operating.md) · [Deployment](docs/deployment.md)
- [Offline recovery](docs/operator-recovery.md) · [Operator controls](docs/operator-controls.md)
- [Mining](docs/operator-mining.md) · [Lithos](docs/lithos.md) · [Wallet mining jobs](docs/miner-wallet-jobs.md)
- [Events and webhooks](docs/events.md) · [Logging](docs/logging.md) · [Release notes](CHANGELOG.md)

**Developers**

- [Architecture](ARCHITECTURE.md) · [Codemap](docs/codemap.md) · [Overview](docs/overview.md)
- [Compatibility](docs/compatibility.md) · [Operating-mode evidence](docs/compatibility.md#operating-mode-status)
- [Contributing](CONTRIBUTING.md) · [Releasing](docs/releasing.md) · [Code of conduct](CODE_OF_CONDUCT.md)

The wallet extraction integration also provides `ergo-walletd`, a separate
daemon built from source. Watch-only remains its default; Phase 3 adds opt-in
encrypted seed lifecycle and key management through an authenticated local API.
See the [extraction plan](docs/wallet-extraction.md#phase-3-daemon-engine-hosting),
[daemon guide](docs/codemap/ergo-walletd.md) and
[daemon configuration](docs/configuration.md#ergo-walletdtoml-the-standalone-wallet-daemon).
Daemon transaction construction, signing, sending and embedded-wallet migration
remain to be implemented.

## Security

Pre-1.0: **do not use this node for production infrastructure or funds custody.**
Report consensus, state-integrity, remote-input crash, and cryptographic-verdict issues
privately through a GitHub Security Advisory. See [SECURITY.md](SECURITY.md).
Findings against the dev oracle `sigma-rust` belong upstream.

## License

Dual-licensed under MIT or Apache 2.0, at your option.
See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).
