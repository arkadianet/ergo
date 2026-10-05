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
[configuration reference](docs/configuration.md#apisecurity). Keep your data
directory outside the extracted archive so upgrades do not replace it.

For modes, monitoring, backups and graceful shutdown, read
[operating the node](docs/operating.md). Use `ergo-wallet --help` for wallet
commands. Review [CHANGELOG.md](CHANGELOG.md) before upgrades. Source build
and contributor instructions live in the
[repository](https://github.com/arkadianet/ergo).
