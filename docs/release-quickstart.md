# Ergo binaries

This archive contains either `ergo-node` or `ergo-wallet` (with `.exe` on
Windows), licenses, the changelog, configuration templates and operating docs.
Download the matching archive for the other binary when you need both.

## Status

This independent Rust node is pre-1.0 alpha software. Read
[compatibility and known limitations](docs/compatibility.md) before deploying.
The [security policy](SECURITY.md) describes private disclosure.

## Running

Extract the archive into its own directory. Check `--version` and `--help`.
The following configuration and startup steps require the `ergo-node` archive.
For a new install, run the setup wizard and choose a preset, network and sync
mode. Keep the data directory outside the extracted archive so upgrades do not
replace it:

```sh
./ergo-node init --data-dir ../ergo-data
```

The wizard shows absolute paths, validates the configuration and creates a
protected API credential. Run the exact start command it prints, with explicit
`--config` and `--data-dir`, then open the printed dashboard URL (by default
`http://127.0.0.1:9099/`). Send the contents of the printed key-file path in the
`api_key` header or enter them in the dashboard. Never send the hash.
Press Ctrl-C and wait for graceful shutdown to stop the node.

For unattended setup, supply every choice explicitly. Preview without writing:

```sh
./ergo-node init --preset wallet --sync genesis --network mainnet \
  --data-dir ../ergo-data --non-interactive --dry-run --json
```

Remove `--dry-run` to create the files. Genesis sync takes hours to days.
`wallet` and `mining-fast` also offer `--sync fast`, which requires
`--accept-unanchored-bootstrap`: snapshot trust is provisional, so cross-check
its UTXO root against an independently trusted node. `mining-fast` omits
storage-rent claims; `mining-full` includes them and requires the indexer and
genesis sync. Both mining presets require `--reward wallet` or
`--reward public-key --miner-public-key HEX`. With wallet rewards, initialize
and **unlock** the node wallet before it serves mining work. Connect miners
through [ergo-solo](https://github.com/arkadianet/ergo-stratum-rs) or follow
[the Lithos guide](docs/lithos.md). Explorer and full mining also need time for
historical index catch-up.

Free-space recommendations are provisional: 100 GiB for fast wallet/mining,
150 GiB for genesis wallet/mining-fast or archival, and 250 GiB for explorer or
mining-full. Below the recommendation, the wizard needs `--allow-low-disk` or
interactive confirmation; an unknown free-space reading produces a warning.

The wizard creates new configs only. It refuses an existing config or key,
and fast sync requires a new or empty data directory. For the full option
reference, see [configuration](docs/configuration.md#new-install-setup).
For manual configuration or existing installs, review `config/ergo-node.toml`;
`ergo-node api-key generate --secret-file PATH` and `api-key hash` remain
available without starting the node.

On Windows use `ergo-node.exe`; inherited ACLs must restrict access to the
secrets directory. On Unix the wizard creates `secrets/` with mode `0700` and
its `api-key` file with mode `0600`. The wizard installs no service.

For modes, monitoring, backups and graceful shutdown, read
[operating the node](docs/operating.md). Use `ergo-wallet --help` for wallet
commands. Review [CHANGELOG.md](CHANGELOG.md) before upgrades. Source build
and contributor instructions live in the
[repository](https://github.com/arkadianet/ergo).
