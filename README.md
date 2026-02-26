# ergo-rust

A Rust implementation of the [Ergo](https://ergoplatform.org) blockchain node, aiming for full protocol compatibility with the [Scala reference implementation](https://github.com/ergoplatform/ergo).

## Status

This is an alternative node implementation. It can sync with the Ergo mainnet and testnet, validate blocks, serve the REST API, and participate in mining.

**Features:**
- Full header and block sync via Ergo P2P protocol (V2)
- Block validation: structural, PoW (Autolykos v2), stateless, and stateful
- Digest and UTXO state modes
- ErgoScript verification via [sigma-rust](https://github.com/ergoplatform/sigma-rust)
- On-chain voting and parameter updates
- EIP-27 re-emission support
- EIP-37 difficulty adjustment
- NiPoPoW proof generation
- Block and UTXO snapshot pruning
- Extra indexer (boxes, transactions, addresses, tokens)
- HD wallet with encrypted keystore (optional `wallet` feature)
- Mining support (internal CPU miner and external miner API)
- REST API (~120 endpoints) with Swagger UI at `/swagger`
- Node admin panel at `/panel`

## Building

Requires Rust 1.75+ and a C/C++ compiler (for RocksDB).

```bash
# Default build (digest mode, no wallet)
cargo build --release

# With wallet support
cargo build --release --features wallet
```

The binary is at `target/release/ergo-node`.

## Running

```bash
# Mainnet (default)
./target/release/ergo-node

# Testnet
./target/release/ergo-node --network testnet

# Custom config
./target/release/ergo-node --config path/to/ergo.toml
```

Default API is at `http://127.0.0.1:9053` (mainnet) or `http://127.0.0.1:9052` (testnet).

## Configuration

See `config/ergo-mainnet.toml` and `config/ergo-testnet.toml` for example configurations. The node looks for config files in this order:

1. `--config` CLI argument
2. `--network` flag (`mainnet` or `testnet`)
3. `ergo.toml` in the current directory
4. `~/.ergo/ergo.toml`
5. Built-in mainnet defaults

## Crate Structure

| Crate | Description |
|-------|-------------|
| `ergo-settings` | Configuration and chain parameters |
| `ergo-wire` | P2P serialization codec |
| `ergo-types` | Core types (headers, blocks, transactions, addresses) |
| `ergo-consensus` | PoW verification and difficulty adjustment |
| `ergo-network` | P2P networking, sync, mempool |
| `ergo-storage` | RocksDB persistence layer |
| `ergo-avldb` | Authenticated AVL+ tree (AD proofs) |
| `ergo-state` | UTXO and digest state management |
| `ergo-indexer` | Extra blockchain indexes |
| `ergo-wallet` | HD wallet and keystore (feature-gated) |
| `ergo-node` | Binary, event loop, REST API |
| `ergo-testkit` | Integration tests |

## Tests

```bash
cargo test --workspace
```

## License

[CC0-1.0](LICENSE)
