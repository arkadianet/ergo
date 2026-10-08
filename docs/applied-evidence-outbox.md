# Applied evidence outbox candidate

This opt-in observer is based on `a203cc02f585bcbe13c743aee008222b208f3c82`.
It changes no validation predicate, checked-type constructor or consensus
codec. It is instrumentation for review, not adoption of a new DEX node pin.
No live node, replay actor or existing store was used to test it.

Enable on a task-owned fully validating UTXO node before persistence startup:

```toml
[node]
applied_evidence_outbox = true

# On a private chain, use its explicit authenticated genesis header ID.
[chain]
genesis_id = "<64 lowercase hex characters>"
```

The default is false. Config refuses digest/header-only mode and a missing
genesis anchor. Existing captured stores keep recording gaps when reopened
without capture enabled; disabling the observer cannot silently preserve a
claim of complete evidence. Enabling after height zero records an incomplete
baseline. Historical raw blocks or an observation file cannot clear this flag.

## Capture and provenance

`ergo-sync::block_proc::utxo` captures after the existing production parallel
validator returns `CheckedBlock`, before the original state apply. It copies
the actual `CheckedTransaction` input/data-input resolutions in declaration
order, the exact stored header bytes and the complete 33-byte parent/result
AVL+ digest (32 hash bytes plus AVL height byte).

Each transaction has `transactionIndex`, `transactionId`, canonical
`signedBytesHex`, `contextExtensions` with regular-input indices and canonical
extension bytes, and ordered `resolvedInputs`/`resolvedDataInputs`. Each box
has its declaration `inputIndex`, exact canonical box encoding and `origin`:
`preBlock` or `earlierOutput`. Origin classification uses only earlier checked
transactions' output IDs; it does not query the state again. Earlier-created
boxes remain in this origin set after they are spent, preserving production's
data-input union semantics.

Signed transaction/box/extension encodings are the pinned `ergo-ser` canonical
encodings, not a claim to preserve every noncanonical encoding that a received
block section may contain. A broadcast archive must retain the original exact
submitted wire independently and must not infer its wire hash from a transaction
ID or a re-encoding.

`provenance.kind` is one of:

- `full`: the existing checked production path above the script checkpoint.
- `checkpointSkipped`: checked structural/monetary/overlay work whose scripts
  were skipped; includes the exact configured checkpoint height and ID.
- `trustedGenesisAnchor`: height-one special handling authenticated against the
  configured genesis header ID, explicitly distinct from full script validation.

Unchecked/generic applies have no capture and produce an explicit gap event.
A skipped, absent or discontinuous capture makes `reconstructionRequired`
sticky. Bootstrap/snapshot state and historical observation archives therefore
cannot become complete live registration evidence through enablement.

## Epoch-effective digest schema

All hashes here are BLAKE2b-256 and lowercase hex. `frame(tag, pieces)` is the
literal tag followed, for each piece, by its eight-byte unsigned big-endian byte
length and the exact piece bytes. Tags below include their final NUL byte.

`parametersDigest` hashes
`frame("ergo/applied-evidence/parameters/v1\0", [activeRow, effectiveParameters])`.
`activeRow` is the existing pinned `ActiveProtocolParameters::serialize()`
encoding of `voted_params_row.unwrap_or(parent_active)`, including the target
epoch/block version. `effectiveParameters` is eleven eight-byte big-endian
values in this order: minValuePerByte, maxBlockCost, maxBlockSize, maxBoxSize,
maxTokensPerBox, inputCost, dataInputCost, outputCost, tokenAccessCost,
storageFeeFactor, storagePeriod. Signed storageFeeFactor uses its two's
complement 64-bit representation. Both component byte strings are exported.

`rulesDigest` hashes
`frame("ergo/applied-evidence/rules/v1\0", [predecessorNodeUpdate, targetSigmaUpdate])`.
The first component is the exact serialized cumulative update used by the
existing predecessor node-rule gates. The second is a serialized settings
update with empty disabled-node rules and the target active row's activated
Sigma status updates. Pending proposed Sigma updates are excluded. The target
epoch row and evidence are committed together; reading the predecessor cache
or a later post-commit cache would produce the wrong digest at an epoch boundary.

These fingerprints bind this pinned node's effective data. They are not a DEX
manifest/activation hash, an independently reviewed ruleset hash, or proof of
Scala/Rust parity. The live service must supply those separate bindings.

## Atomic persistence and reader contract

The synchronous `persist_apply` and background `PersistJob` batching paths
write the event, canonical-height pointer, journal tip and cursor in the same
existing redb transaction as AVL changes, undo, chain metadata, epoch parameters
and wallet state. A state-root mismatch writes no event. An outbox write failure
aborts that entire write transaction. Pending jobs are never exposed as commits.

Rollback flushes pending jobs, then co-commits canonical-pointer truncation,
tip/cursor and branch-generation advancement with the existing chain rollback.
Old apply and rollback records are retained indefinitely. Reapplication on a
replacement branch receives a new journal sequence even at an old height.

`ergo_state::evidence::read_committed(db, after, limit)` reads one committed
redb snapshot, binds its journal tip to canonical `CHAIN_STATE_META`, checks
the supplied cursor identity/hash, and refuses missing records, corrupt data,
rewound cursors and changed archives. Pages contain `meta`, retained `events`
and `nextCursor`; limit is 1 through 1000. The cursor is
`{archiveId, sequence, eventHash}`. Sequence and branchGeneration are exact JSON
integers restricted to 0 through 2^53−1; overflow refuses the atomic mutation.

An event hash is
`frame("ergo/applied-evidence/event/v1\0", [eventJson])` hashed with BLAKE2b-256.
`eventJson` is the pinned serde JSON UTF-8 serialization of `JournalEvent`: no
whitespace, struct fields in declaration order, capture-object keys in lexical
order, with normal JSON escaping. Each event includes its previous event hash.
The archive identity hashes a framed anchor ID, capture-baseline height and
full 33-byte baseline AVL digest. This is a local integrity/cursor mechanism,
not a signature against a database owner.

`reconstructionRequired` never clears through an HTTP request, flag change or
file import. The concrete recovery control for this candidate is replay from
the authenticated genesis into a fresh task-owned fully validated store, then
reconstruct the consuming service. A reader that previously acknowledged data
lost by a crash sees cursor rewind/gap refusal.

Existing redb `Eventual`/`None` durability policy is preserved. Co-commit means
atomic committed visibility, not that every observed page has already been
fsynced. The consumer must keep its durable cursor and recover on rewind.

## Remaining integration

The public in-process reader is implemented. An authenticated node API/stream
handler and service `AppliedEvidenceSource` bridge are not yet implemented.
The bridge must authenticate the native node/transport and chain anchor,
reject reconstruction gaps/skipped provenance, map real registry/order evidence,
bind reviewed manifest/activation/native paired context, and persist its cursor
with its own registry update. JSON exported to a file remains unverified archive
observation; this candidate does not promote such a file to live registration.

No node pin change, deployment, proof of launch parity, market registration or
live trading readiness is implied by these tests.

## Focused validation

```sh
cargo test -p ergo-state --lib evidence::tests
cargo test -p ergo-node --lib applied_evidence_outbox
cargo check -p ergo-state -p ergo-sync -p ergo-node --tests
```

The evidence tests cover synchronous/background co-commit, invisible pending
jobs, state-root and journal-write failure atomicity, rollback and branch
retention, skipped/unchecked/late-start provenance, restart, cursor/gap/corruption
refusals, generation overflow, real production parallel-overlay input/data
resolutions and target epoch parameter/rule co-commit.
