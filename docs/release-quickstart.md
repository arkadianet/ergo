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
settings, and start the node with an explicit config and data directory:

```sh
cp config/ergo-node.toml ./ergo-node.toml
./ergo-node --config ./ergo-node.toml --data-dir ../ergo-data
```

On Windows use `ergo-node.exe`. The packaged default selects mainnet with
the extra-index and serves the API on loopback at `127.0.0.1:9099`. Privileged
routes require your own API credential; follow the
[configuration reference](docs/configuration.md#apisecurity). Keep your data
directory outside the extracted archive so upgrades do not replace it.

For modes, monitoring, backups and graceful shutdown, read
[operating the node](docs/operating.md). Use `ergo-wallet --help` for wallet
commands. Review [CHANGELOG.md](CHANGELOG.md) before upgrades. Source build
and contributor instructions live in the
[repository](https://github.com/arkadianet/ergo).
