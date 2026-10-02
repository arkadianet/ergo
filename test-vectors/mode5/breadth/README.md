# Additional digest-verifier reference windows

These immutable captures expand the standing mainnet voting-boundary replay
corpus with two more mainnet windows and the current public testnet. Sources
were queried with GET requests on 2026-10-02. No reference configuration or
state was changed.

| Directory | Blocks | Reference | Network voting length |
|---|---|---|---|
| `mainnet-1761000` | 1761000–1761007 | `https://node-p2p.ergoplatform.com`, Scala 6.1.2 | 1024 |
| `mainnet-1885600` | 1885600–1885607 | `https://node-p2p.ergoplatform.com`, Scala 6.1.2 | 1024 |
| `testnet-442325` | 442325–442332 | `http://213.239.193.208:9052`, Scala 6.0.3 | 128 |

Each directory contains eight records with headers, transaction/extension
sections, ADProofs and independently reported parent/post-state roots. Its
`context.json` preserves the reference `/info`, capture timestamp, ten previous
headers, and the epoch-start header/extension/active parameters. Header IDs,
box IDs, transaction IDs, transaction roots, extension roots and proof hashes
are checked against the node's commitments. The replay also checks context
continuity and the epoch extension commitment before adopting parameters.

Reproduce from the repository root:

```bash
NODE_URL=https://node-p2p.ergoplatform.com MODE5_FROM=1761000 MODE5_TO=1761007 \
  MODE5_OUT=test-vectors/mode5/breadth/mainnet-1761000 \
  cargo run -p ergo-state --example extract_mode5_corpus
NODE_URL=https://node-p2p.ergoplatform.com MODE5_FROM=1885600 MODE5_TO=1885607 \
  MODE5_OUT=test-vectors/mode5/breadth/mainnet-1885600 \
  cargo run -p ergo-state --example extract_mode5_corpus
NODE_URL=http://213.239.193.208:9052 MODE5_FROM=442325 MODE5_TO=442332 \
  MODE5_OUT=test-vectors/mode5/breadth/testnet-442325 \
  cargo run -p ergo-state --example extract_mode5_corpus
cargo test -p ergo-sync --test it mode5_corpus_breadth
```

The extractor requires retained, nonempty ADProofs and aborts when any identity
check fails. Public nodes may eventually prune proofs; an archival Scala node
can be substituted with `NODE_URL`. A custom window must stay within one voting
epoch; the existing 193-block corpus separately exercises epoch transitions.

The tests verify full transaction validation through production digest block
processing, same-root rollback/replay, and rejection of corrupted proofs without
changing committed roots/tips/parameters. They seed the window's initial state;
these small captures do not claim genesis-to-window history or cold-open coverage
for an incomplete historical database. Cold-open process-death recovery requires
a separate fixture with complete historical rollback substrate.

`SHA256SUMS` pins all captured JSON bytes. Re-extraction updates capture metadata;
review any changes manually and regenerate checksums only after validating them.
