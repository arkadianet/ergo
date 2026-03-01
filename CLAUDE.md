# Ergo Rust Node

Rust reimplementation of the Ergo blockchain node, protocol-compatible with the
[Scala reference](../reference_materials/ergo-master/).

## Commands

```bash
# Build
cargo build --release
cargo build --release --features wallet  # with wallet support

# Test
cargo test --workspace

# Lint
cargo clippy --workspace -- -D warnings
cargo fmt --check

# Run
./target/release/ergo-node                    # mainnet
./target/release/ergo-node --network testnet  # testnet
./target/release/ergo-node --config path.toml # custom config
```

## Architecture

Workspace with 12 crates in `crates/`:

| Crate | Purpose |
|-------|---------|
| ergo-settings | Config parsing, network settings |
| ergo-wire | Scorex serialization, P2P message framing |
| ergo-types | Core types, addresses, NiPoPoW, header/block structs |
| ergo-consensus | PoW validation (Autolykos v2), difficulty adjustment |
| ergo-network | P2P protocol, sync manager, peer discovery, mempool |
| ergo-storage | RocksDB persistence, history DB, continuation IDs |
| ergo-avldb | AVL+ tree (authenticated data structure) |
| ergo-state | DigestState, UtxoState, state changes, rollback |
| ergo-indexer | Extra indexer (boxes, txs, addresses, tokens) |
| ergo-wallet | HD wallet, keystore, transaction signing |
| ergo-node | Binary entry point, HTTP API (axum), event loop |
| ergo-testkit | Integration tests, test fixtures |

- Scala reference: `/home/rkadias/coding/reference_materials/ergo-master/`
- Plans: `docs/plans/` (63 design + implementation docs)
- Configs: `config/ergo-mainnet.toml`, `config/ergo-testnet.toml`

## Security

- For any transaction spending multiple UTXOs or boxes, consider security
  implications of input exposure. Never batch spends of script-protected boxes
  where revealing the spending condition in one TX allows front-running of
  remaining boxes.

## Ergo Protocol Gotchas

- **Scorex VLQ**: ALL putUShort/putUInt/putULong use VLQ encoding. putUByte is
  fixed 1 byte. Signed putInt/putLong use ZigZag + VLQ.
- **nBits**: 4-byte big-endian, NOT VLQ.
- **Header ID**: blake2b256(full serialized header WITH pow).
- **Chain scoring**: Must use decode_compact_bits(nBits) for BigUint difficulty,
  NOT raw nBits bytes.
- **Java BigInteger compat**: toByteArray() adds leading 0x00 when MSB set;
  Rust BigUint::to_bytes_be() does not — must manually add in encode_compact_bits.
- **Handshake**: Raw bytes (no message frame). Regular messages use frame:
  magic(4) + code(1) + length(4 BE) + [checksum(4) + body].
- **Box ID**: blake2b256(tx_id ++ vlq(output_index)).
- **MIN_BOX_VALUE**: Dynamic — box.bytes.length * MinValuePerByte (default 360 nanoErg/byte).

## Ergo DeFi Conventions

- When working with token/currency values, always account for decimal precision
  differences between raw chain values and display values. Verify oracle rates,
  token prices, and swap amounts render correctly by checking decimal scaling.
- When filtering or categorizing pools/positions, always test edge cases:
  ERG-denominated vs token-denominated, user's own positions vs others, T2T pools
  vs ERG-based pools. Never assume a filter that works for one denomination works
  for all.

## Ergo Transaction Building

- Miner fees should come from a separate user UTXO, not be deducted from the
  protocol output.
- Change token collection must only include tokens from selected inputs, not all
  wallet UTXOs.

## Pre-Commit Checks

Always run before committing Rust code:
```bash
cargo fmt --check
cargo clippy --workspace -- -D warnings
cargo test --workspace
```
For the mobile app, verify the build compiles for the target platform after changes.

## Post-Implementation Checklist

After implementing any feature, verify that ALL UI elements are properly connected
to backend functionality. Check for hardcoded disabled states, hidden toggles, or
placeholder values that need to be enabled.
