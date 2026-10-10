# Wallet setup

The wallet runs in its own daemon, `ergo-walletd`, beside the node. The node
validates the chain and builds mining candidates; the daemon holds keys,
tracks balances and signs. Mining needs no wallet at all: the node pays block
rewards to the reward key in its own configuration.

This page covers a new installation and an upgrade from a node that hosted
its wallet itself. The [daemon configuration reference](configuration.md#ergo-walletdtoml-the-standalone-wallet-daemon)
describes every option.

## New installation

### Mining with an existing wallet

Any Ergo wallet's receiving address works as the reward address (Nautilus,
Satergo, a hardware wallet, or an `ergo-walletd` wallet):

```sh
ergo-node init --preset mining-full --sync genesis --network mainnet \
  --reward address --miner-reward-address 9f...
```

or, in an existing `ergo-node.toml`:

```toml
[mining]
enabled = true
miner_reward_address = "9f..."
```

The node decodes the address, checks it belongs to the configured network
and pays rewards to its public key. No daemon is required.

### A wallet in the daemon

1. Create the daemon's configuration and credentials:

   ```sh
   ergo-walletd init --config ~/ergo-walletd/walletd.toml \
     --data-dir ~/ergo-walletd/data --node-url http://127.0.0.1:9053
   ```

   This writes the config and two owner-only credential files beside it, and
   prints a `[[api.security.keys]]` entry for the node (add `--mining-jobs` for
   the scopes private mining jobs need). Add that entry to `ergo-node.toml` and
   restart the node.

2. Start the daemon and create or restore the wallet through its API
   (`POST /api/v1/wallet/init` or `/api/v1/wallet/restore`, with the
   `wallet-api-key` value in the `api_key` header) or its browser UI.

3. To mine to this wallet, print its reward address and add the printed line
   to `ergo-node.toml`:

   ```sh
   ergo-walletd reward-key --config ~/ergo-walletd/walletd.toml
   ```

   The command reads the wallet password from standard input.

The daemon encrypts its database at rest. After a restart it is **sealed**
until the wallet password unlocks it; see
[sealed start](configuration.md#sealed-start-and-database-encryption) for
unattended operation with a TPM-bound credential.

## Upgrading a node that hosted its wallet

A node that no longer hosts its embedded wallet leaves that wallet's rows and
keystore untouched and hands a copy to the daemon:

1. **Upgrade the node.** It keeps syncing and mining. A miner without a
   configured reward key keeps the old wallet's first-address key, and the log
   shows the `miner_reward_address` line to pin it with.

2. **Find the handoff.** On start the node publishes a verified copy of the
   wallet at `<data_dir>/wallet-handoff/`, in the background, and logs the
   exact command for the next step. The copy holds the wallet's tables and its
   encrypted keystore byte for byte; nothing is decrypted.

3. **Adopt it** into a new daemon data directory:

   ```sh
   ergo-walletd adopt --handoff <node data_dir>/wallet-handoff \
     --data-dir ~/ergo-walletd/data
   ```

   Adoption verifies the copy, moves it (or copies and verifies it across file
   systems), and records `wallet-handoff.adopted` in the node's data directory.

4. **Configure and start the daemon** with `ergo-walletd init` using the
   adopted data directory, or an existing seed-mode config pointing at it, and
   unlock it with the old wallet password. The first unlock seals a database
   key into the keystore, upgrades the keystore to the version-2 Argon2id
   format and encrypts the database.

5. **Point wallet clients at the daemon.** The node answers its former wallet
   routes with `wallet_moved` and the daemon's address; the daemon serves the
   same Scala-compatible `/wallet/*` and `/scan/*` routes.

6. **Purge the old rows** from the node once the daemon works:

   ```sh
   ergo-node wallet-legacy-purge <node data_dir>
   ```

   The node must be stopped. The command refuses unless the wallet was
   adopted, then drops the old wallet tables from `state.redb` and compacts it.
   `--remove-keystore` also deletes the old keystore file; keep your mnemonic.

Wallet mining jobs move with the wallet. Between the upgrade and the adoption
nothing follows jobs through reorganizations; transactions already in the
node's private queue still mine. A downgrade after the daemon has upgraded the
keystore, or after a purge, is not supported.
