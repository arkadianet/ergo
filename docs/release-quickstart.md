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
Copy `config/ergo-node.toml` to a writable working directory, review the
settings, generate an API credential, and start with an explicit config and data
directory:

```sh
cp config/ergo-node.toml ./ergo-node.toml
./ergo-node api-key generate --secret-file ./api-secret.key
# Paste the printed [api.security] section into ./ergo-node.toml before starting.
./ergo-node --config ./ergo-node.toml --data-dir ../ergo-data
```

Keep `api-secret.key` safe and send its secret (never the printed hash) in the
`api_key` header or enter it in the dashboard. Generation requires a new file
in an existing directory; it does not edit the config. To hash an existing
secret, use `./ergo-node api-key hash --secret-file ./api-secret.key` (or
`--stdin` for piped input). Both commands support `--json` and run without
starting the node or creating its data directory.

On Windows use `ergo-node.exe` and keep the secret in a directory only you can
read; its ACL is inherited. On Unix the generated file has mode `0600`. The
packaged default selects mainnet with
the extra-index and serves the API on loopback at `127.0.0.1:9099`. Privileged
routes require your own API credential; follow the
[configuration reference](configuration.md#apisecurity). Keep your data
directory outside the extracted archive so upgrades do not replace it.

For modes, monitoring, backups and graceful shutdown, read
[operating the node](operating.md). Use `ergo-wallet --help` for wallet
commands. Review [CHANGELOG.md](../CHANGELOG.md) before upgrades. Source build
and contributor instructions live in the
[repository](https://github.com/arkadianet/ergo).
