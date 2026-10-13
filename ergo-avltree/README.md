# ergo-avltree

Authenticated AVL+ tree for the Ergo Rust node: the batch prover that
maintains the UTXO set (`BatchAVLProver`, `PersistentBatchAVLProver`,
`VersionedAVLStorage`) and the batch verifier used for script-level `AvlTree`
methods and block ADProofs (`BatchAVLVerifier`). It is a Rust port of the
`scorex.crypto.authds.avltree.batch` package of
[scrypto](https://github.com/input-output-hk/scrypto), following
<https://eprint.iacr.org/2016/994>.

## Origin and licence

This crate is a copy of
[ergoplatform/ergo_avltree_rust](https://github.com/ergoplatform/ergo_avltree_rust)
at commit `9231458` (master, August 2026), published on crates.io as
`ergo_avltree_rust` up to version 0.1.1. Authors: Konstantin Knizhnik and
Ross Weir, with later fixes by the ergo_avltree_rust contributors. It is
licensed, like upstream, under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT licence ([LICENSE-MIT](LICENSE-MIT))

at your option. Upstream's own README is kept as
[UPSTREAM-README.md](UPSTREAM-README.md).

## Changes from upstream

- Package and library renamed to `ergo-avltree` / `ergo_avltree`; the
  integration tests import the new name.
- Formatted with the workspace's rustfmt settings, and lint allowances added
  at the crate root so the vendored code builds under the workspace's
  `clippy -D warnings` gate. No logic changes.

Behaviour relative to crates.io 0.1.1 (all from upstream master):

- A leaf value longer than 4 MiB in a proof fails reconstruction, as the
  reference verifier (scrypto 3.1.1) does.
- Verifier operations on proofs whose shape a well-formed tree cannot have
  (a leaf or label where a rotation needs an internal node, a balance byte
  outside -1..1, a delete step into a leaf) return an error instead of
  panicking.
- `UpdateLongBy` adds with overflow checking; an overflow fails the
  operation instead of wrapping.
- Node labels are computed iteratively, so labelling a deep tree does not
  recurse once per level.
- Nodes deserialized by `AVLTree::unpack` are marked as persisted.
