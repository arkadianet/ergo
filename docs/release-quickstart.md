# Ergo binaries

One `ergo-<target>.tar.gz` archive per platform (or `.zip` on Windows) contains
both `ergo-node` and `ergo-wallet` (with `.exe` on Windows), licenses, the
changelog, configuration templates, operating docs and `deploy/` examples.
`release-info.json` records the tag, version, source commit, target and both
executable SHA-256s. Release downloads also include `release.json` and
`SHA256SUMS`; bare binaries and per-file checksum sidecars are no longer published.

Before extracting, download the archive, `release.json` and `SHA256SUMS` from
the same release tag. On Linux, verify just the downloaded platform and manifest:

```sh
awk '$2 == "ergo-x86_64-unknown-linux-gnu.tar.gz" || $2 == "release.json"' SHA256SUMS | sha256sum --check --strict
```

Require two successful checks. Substitute your exact archive basename for other
platforms. On macOS use `shasum -a 256 -c` in place of `sha256sum --check --strict`;
on Windows compare SHA-256s using PowerShell `Get-FileHash -Algorithm SHA256`.
Check that the selected `release.json` target entry agrees with `SHA256SUMS`
on the archive name and hash; it also gives the byte size and executable hashes.
Checksums detect corruption; they do not independently authenticate a release.

## Status

This independent Rust node is pre-1.0 alpha software. Read
[compatibility and known limitations](compatibility.md) before deploying.
The [security policy](../SECURITY.md) describes private disclosure.

## Running

Extract the archive into its own directory. Check `--version` and `--help`.
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
[the Lithos guide](lithos.md). Explorer and full mining also need time for
historical index catch-up.

Free-space recommendations are provisional: 100 GiB for fast wallet/mining,
150 GiB for genesis wallet/mining-fast or archival, and 250 GiB for explorer or
mining-full. Below the recommendation, the wizard needs `--allow-low-disk` or
interactive confirmation; an unknown free-space reading produces a warning.

The wizard creates new configs only. It refuses an existing config or key,
and fast sync requires a new or empty data directory. For the full option
reference, see [configuration](configuration.md#new-install-setup).

To configure by hand instead, or for an existing install, copy the bundled
config, review it, create an API credential and start with an explicit config
and data directory. The bundled config selects mainnet with the extra-index and
serves the API on loopback at `127.0.0.1:9099`:

```sh
cp config/ergo-node.toml ./ergo-node.toml
./ergo-node api-key generate --secret-file ./api-secret.key
# Paste the printed [api.security] section into ./ergo-node.toml before starting.
./ergo-node --config ./ergo-node.toml --data-dir ../ergo-data
```

Keep `api-secret.key` safe and send its secret (never the printed hash) in the
`api_key` header or enter it in the dashboard. Generation requires a new file
in an existing directory; it does not edit the config. To hash an existing
secret, use `./ergo-node api-key hash --secret-file ./api-secret.key`. See
[API authentication](configuration.md#apisecurity).

On Windows use `ergo-node.exe`; inherited ACLs must restrict access to the
secrets directory and key files. On Unix the wizard creates `secrets/` with
mode `0700`, and both the wizard and `api-key generate` create key files with
mode `0600`. The wizard installs no service.

For modes, monitoring, backups and graceful shutdown, read
[operating the node](operating.md). Use `ergo-wallet --help` for wallet
commands. Review [CHANGELOG.md](../CHANGELOG.md) before upgrades. Source build
and contributor instructions live in the
[repository](https://github.com/arkadianet/ergo).
