# UTXO proof validation during historical sync

UTXO nodes download transactions and extensions, generate ADProofs from their
local parent state, and compare the generated proof hash with the header's
`adProofsRoot`. They also validate transactions and the resulting `stateRoot`.
Downloaded ADProofs are not a prerequisite for UTXO block application.
Digest nodes have no complete UTXO set and still require downloaded proofs.

This follows Scala's [StateType](https://github.com/ergoplatform/ergo/blob/23aabead88774d27f2c9190ace3c9abbc8f1d5cb/ergo-core/src/main/scala/org/ergoplatform/nodeView/state/StateType.scala),
[download selection](https://github.com/ergoplatform/ergo/blob/23aabead88774d27f2c9190ace3c9abbc8f1d5cb/src/main/scala/org/ergoplatform/nodeView/history/storage/modifierprocessors/ToDownloadProcessor.scala),
and [UtxoState proof generation](https://github.com/ergoplatform/ergo/blob/23aabead88774d27f2c9190ace3c9abbc8f1d5cb/src/main/scala/org/ergoplatform/nodeView/state/UtxoState.scala).
Scala's default `adProofsSuffixLength` is 114,688: bootstrapping nodes need not
retain generated proofs for older blocks, even when they retain transactions
and extensions. Requiring those proofs can stall an archival sync at block 2.

`StateStore::regenerate_ad_proofs` uses the existing upstream AVL prover with
on-demand expansion. The arena owner serves node reads to a scoped worker;
the worker owns the upstream `Rc` graph and its function-pointer resolver.
Expanded nodes are checked against their expected labels. Unvisited subtrees
remain hash stubs. The generated proof is independently replayed before its
hash is compared to the header. The authoritative tree is never mutated by
generation, and no prover cache survives a call, restart, or reorg.

Current-format nodes require reads proportional to the touched operation
paths, rather than a whole-tree hydration per block. Legacy v1 nodes missing
child labels may require recursive label reconstruction. Thread creation and
node-request messaging add overhead; full-chain throughput still needs live
measurement. Tests compare exact proof bytes with full hydration, mainnet
commitments, cold disk reads, pending arena writes, and a bounded-read fixture.

The script-validation checkpoint is independent. Keep
`script_validation_checkpoint_height = 0` to execute scripts from genesis.
This change requires no database migration, resync, or checkpoint change.
