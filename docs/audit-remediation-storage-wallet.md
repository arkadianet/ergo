# Storage and wallet remediation

The 2026-10-03 review's storage/wallet group is addressed by these contracts:

| Finding | Change | Regression evidence |
| --- | --- | --- |
| F01 | Transaction-local ownership of header and full-block metadata; startup rejects mismatched full/AVL heights | Newer header and same-height fork survive stale block batch; header publication retains only committed full tip; mismatched reopen fails |
| F02 | Shared first-failure latch and terminal worker failure | Full notification channel cannot hide a failed batch; later valid delta never commits; send/flush/shutdown retain original error |
| F05 | Same-directory temporary secret file, sync, no-replace publication, final sync and Unix directory sync | Faults before publication expose no final file; abandoned temp is ignored; existing target survives; post-publication fault reopens complete file |
| F07 | Fallible joined persistence shutdown plus final durability barrier | Pending worker error survives shutdown and IBD exit; failed IBD exit retains old mode |
| F08 / R04 | Per-node rescan control and node-owned writer/worker joins | Controllers in two nodes are independent; blocked rescan prevents shutdown completion until it releases its database owner; reopen then succeeds; cancelling a join preserves the worker handle for subsequent cleanup |
| F14 | Zeroizing BIP39 entropy/seed/mnemonic, owned commitment nonces and real proof-tree scalars; accurate ownership documentation | Existing key/proving tests and redacted Debug assertions; no claims about all library or register copies |
| F15 | Fresh Scala 6.0.6 AES/storage/derivation vectors, reverse JVM unlock and explicit feature tests in PR CI | Actual external generator regeneration and Scala unlock of new Rust file |
| R02 | Immediate durable batches, fallible drained IBD exit, admitted/committed/durable progress counts and exact periodic cadence | Commit-progress test distinguishes a commit from fsync; existing crash recovery/reorg suites remain enabled |

The external oracle exposed three compatibility defects beyond the original
missing coverage: Scala's `authTag` is the first 16 encrypted-stream bytes,
its cipher JSON omits algorithm/mode, and its legacy flag can be null. New
Rust files follow Scala; authenticated fallback imports earlier Rust files.
Older Rust binaries cannot read newly corrected files. See
[compatibility](compatibility.md) and [fixture provenance](../test-vectors/wallet/README.md).

The native `BoundTransactionHints` workflow consumes secret commitments and
checks the canonical signing message. The low-level Scala-compatible hint
API remains caller-managed: reusing a private nonce for another message can
disclose a signing key. Plain exported phrases and JSON secret-hint DTOs are
also caller-owned. Zeroization covers named owned buffers and cannot promise
erasure of compiler/library temporaries, registers, swap or process dumps.

The durability tests exercise transaction failures, write/publication
checkpoints, restart and cancellation. They do not emulate a physical power
cut or prove that a storage controller honors fsync. Unix secret publication
syncs the directory; Windows' portable API does not provide that operation,
so sudden-power-loss durability of the new filename is limited there.
