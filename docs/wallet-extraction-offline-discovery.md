# Offline discovery for standalone wallets

Standalone wallets can recover their current holdings from a stopped node’s verified UTXO tree without decrypting their seed or reconstructing historical transactions. Stop both processes, initialize/restore and unlock once beforehand so public keys have been persisted, then run:

```sh
ergo-walletd export-unseal-key --config /path/to/walletd.toml \
  | ergo-node wallet-scan-utxo /path/to/node-data \
      --wallet-data-dir /path/to/wallet-data --wallet-key-stdin
```

The daemon's `wallet.redb` is encrypted; `export-unseal-key` turns the wallet password (read from its standard input) into the database key, which the node reads from its standard input. That key opens the wallet's records but cannot spend, and the node never sees the password. A database that is not encrypted yet (adopted but never unlocked) opens without `--wallet-key-stdin`.

The target must contain a regular `wallet-mode` marker (`seed` or `watch_only`), a matching `wallet-network` marker, and an existing `wallet.redb`. The command locks the node database for read-only traversal and takes the wallet database’s exclusive lock; either running owner prevents discovery. The committed node network must be identifiable from its emission identity or canonical genesis anchor. Unknown or differing networks are rejected before wallet mutation.

Checkpoints and discovered holdings are written only to the standalone wallet. The node’s chain and any wallet tables an earlier release left in its database, both secret directories, and the public API default remain untouched. `--restart` discards an obsolete discovery checkpoint after a tip/key change. Registered custom scans require historical replay. Discovery also refuses scheduler-owned wallet jobs, including mined/conflicted records with a transaction ID that follow chain reorganizations. Cancel pending private work before stopping; retained journal records can be explicitly quarantined during [copy cutover](wallet-extraction.md#migration-and-rollback). The resulting coverage explicitly records incomplete history and unknown historical inclusion heights; resume the daemon to track subsequent committed blocks.
