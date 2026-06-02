# Testnet vector extraction

This directory is the testnet counterpart to `test-vectors/mainnet/`. It holds
genesis boxes, header / transaction / box / cost / digest fixtures extracted
from a running Scala testnet node, used as oracle inputs by the Rust node's
testnet-parity tests.

The public testnet was reset in `ergoplatform/ergo` PR #2252 ("New public
testnet parameters", merged 2026-02-26 into v6.0.3). Provision a Scala node
running v6.0.3 or later — the previous PaiNet (`:9022`, magic `[2,0,2,3]`,
checkpoint `h=91320 / fd06abdf…`) has been retired.

## What lives here

Required before testnet startup unlocks (the `validate_supported` gate in
`ergo-node::config` reads `chain_spec.genesis.{header_id, boxes_json}`):

- `genesis_boxes.json` — height-0 boxes, drives `GenesisParams.boxes_json`
- `header_height_1.json` — the first mined header; its id is `GenesisParams.header_id`
- `state_digest_height_1.json` — AVL state root at height 1, for the embedded
  digest round-trip test

Bulk range extractions (`headers_*_NNNNNN*.json` etc.) are gitignored and
regenerable from a running Scala testnet node.

## Provisioning a Scala testnet node

1. Clone `ergoplatform/ergo` at tag `v6.0.3` (or later) — earlier releases
   point at the retired public testnet.
2. Build: `sbt -mem 4096 assembly` from the `ergo` root.
3. Run with the bundled testnet profile:

   ```bash
   java -jar target/scala-2.13/ergo-*.jar --testnet \
        --networkType testnet \
        -c src/main/resources/testnet.conf
   ```

   The v6.0.3 testnet config binds P2P to `:9023` and the REST API to
   `:9052` (default). `extraIndex = true` is required for the
   address/token vector scripts.

4. Wait until the node has imported the early-chain blocks the extraction
   scripts need (height ~10_000 is enough for the Phase 3 vectors above).
   Full tip sync is only required for the eventual cross-network drift
   workflow.

## Extracting vectors

The existing scripts under `test-vectors/scripts/` are network-agnostic: they
read `NODE_URL` from the environment. Point at the testnet REST port:

```bash
export NODE_URL=http://localhost:9052

cd test-vectors/scripts

# Initial set required to unlock --network testnet startup.
./extract_headers.sh 1 1     ../testnet/header_height_1.json
./extract_headers.sh 1 10000 ../testnet/headers_1_10000.json
./extract_utxo_digests.sh 1  ../testnet/state_digest_height_1.json

# Genesis boxes are at height 0; use the boxes script
./extract_boxes.sh 0 ../testnet/genesis_boxes.json
```

After extraction, edit `ergo-chain-spec/src/lib.rs`'s
`GenesisParams::testnet()` to switch `header_id: None` to
`Some(parse_bytes32_hex("<height-1 header id>"))` and
`boxes_json: None` to
`Some(include_str!("../../test-vectors/testnet/genesis_boxes.json"))`.
The runtime gate auto-lifts once both fields are `Some(_)`.

## Provenance

Vectors must come from a Scala testnet node, never from a self-oracle.
Per `CLAUDE.md` §10 (Test conventions): "for codecs, hashes, IDs, and any
byte-format that must agree with Scala/sigma-state, the expected value MUST
come from an external oracle (Scala node REST, mainnet block bytes,
sigma-state vector) — never from `let expected = my_fn(input)`."
