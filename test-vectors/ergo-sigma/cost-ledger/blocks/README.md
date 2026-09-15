# Synthetic block fixture schema (version 1)

Producer: `scripts/jvm_block_oracle/BlockOracle.scala`.
Builder: `scripts/devnet-mixed/build-block.py`.
The Rust consumer is `ergo-validation/tests/it/cost_block_fixtures.rs`.
The tracked smoke fixture is `p2pk.json.gz`; identical bytes are pinned at
`scripts/jvm_block_oracle/p2pk.json.gz`.
All hex fields encode the pinned JVM's canonical serialization; numbers are JSON
integers. Gzip input is accepted by the oracle.

## Build request

| Field | Meaning |
|---|---|
| `schema_version` | Exactly `1`. |
| `ledger` | Row IDs carried into the output; defaults to `["BLOCK-parallel-equiv"]` for the smoke corpus. |
| `parent_boxes_hex` | Serialized target input/data boxes, present before and after parent-chain replay. Duplicate box IDs are forbidden. |
| `parameters` | Complete devnet parameter table, decimal byte IDs mapped to integers. The example uses the exact `DevnetLaunchParameters` table, including block version 3. |
| `transactions_hex` | Nonempty ordered array of signed `ErgoTransaction` bytes for the target. In-block dependencies are allowed. |
| `bootstrap_box_hex` | Optional serialized auxiliary box used to build the parent chain. If omitted, the builder uses its deterministic 1 ERG, true-script, height-zero box. The complete fixture always records it. |

The exact default parameter table is:

```json
{"1":1250000,"2":360,"3":524288,"4":1000000,"5":100,"6":2000,"7":100,"8":100,"123":3}
```

Parameter 4 may be overridden to construct limit-boundary fixtures. Version 3
is covered by the checked-in smoke test; other contexts need their own evidence.
No parameter is silently taken from the live node.

## Complete fixture

The builder adds:

| Field | Meaning |
|---|---|
| `ledger` | Required array of ledger row IDs covered by the fixture. |
| `manifest` | Required design §3 provenance: Scala versions/source SHAs, Rust revision/toolchain/features, tool revision/hash/Scala CLI/JVM, synthetic chain context/versions/voted parameters, command/seeds/timestamp, SHA-256 evidence. |
| `genesis_state_root` | AVL digest of the initial boxes, before applying parent blocks. |
| `initial_box_order_hex` | All initial serialized boxes in the exact JVM AVL insertion order, including the bootstrap box. |
| `parent_headers_hex` | Oldest-first headers, exactly matching `parent_blocks[*].header_hex`. |
| `parent_blocks` | Oldest-first complete synthetic blocks, starting at height 1. Each has one bootstrap transaction. |
| `parent_state_root` | 33-byte AVL digest after applying every parent block. |
| `block` | Complete mined target block, encoded as the section record below. |
| `expected` | Optional separately captured oracle result; never used by the builder or evaluator to decide validity or cost. |
| `oracle_manifest` | Optional provenance, version pins and independent cost basis. |

Each block section record has:

```text
header_hex: canonical HeaderSerializer bytes
transactions_hex: ordered canonical ErgoTransactionSerializer bytes
extension_fields: [[two-byte-key-hex, value-hex], ...], in serialized order
ad_proofs_hex: raw SerializedAdProof bytes (without section/header-ID framing)
```

Header IDs link the reconstructed `BlockTransactions`, `Extension`, and `ADProofs`
sections. The oracle verifies transaction, extension and proof commitments and
checks difficulty-one PoW before calling `applyModifier`.

## Parent-state reconstruction

1. Parse `parent_boxes_hex` and `bootstrap_box_hex`; initialize a fresh disk-backed
   `UtxoState.fromBoxHolder` using the fixture parameters at parameter height 0.
   Both the state and snapshot databases live in a worktree-local temporary directory.
2. The synthetic genesis digest is the AVL root of these initial boxes, using
   the JVM `BoxHolder.sortedBoxes` insertion order. This exact order is recorded
   in `initial_box_order_hex` and checked on replay. A Rust consumer inserts
   those boxes in that order and checks `genesis_state_root`; it need not
   reproduce Scala collection ordering.
3. Replay `parent_blocks` through `applyModifier`, regenerating each parent
   ADProof and requiring exact proof bytes and state-root equality. The bootstrap
   transaction recreates its value at each height; target fixture boxes are
   checked to remain unspent after the chain.
4. A newly built fixture has 128 parent blocks, matching the devnet voting epoch.
   The extensions contain parameters, validation settings and NiPoPoW interlinks.
   Replay must have processed an epoch extension (`currentParameters.height > 0`),
   and its parameter table must equal the fixture table. The retained parent
   header window contains ten headers; target execution exposes the preceding
   nine headers to scripts, following the JVM context rules.
5. Check `parent_state_root`, then reset cost observation and apply the target.
   Failed application must preserve the parent AVL root. No historical mainnet
   root or live-node state is used.

The complete pre-target UTXO set is the original `parent_boxes_hex` plus the last
bootstrap output, **not** the initial bootstrap box. Rust fixture consumers must
replay the same chain/context or construct an equivalent state from these fields.

## Oracle response

```json
{
  "verdict": "Accept",
  "failure_class": null,
  "rejection_detail": null,
  "sum_block_cost": 12503,
  "exec_transactions_calls": 1,
  "state_root_before": "...",
  "state_root_after": "..."
}
```

`verdict` is `Accept` or `Reject`. `failure_class` names the JVM exception for a
rejection. A failed `execTransactions` has no cost payload, so `sum_block_cost`
is null; it is never guessed or replaced with a separately recalculated sum.
If transaction execution succeeds and a subsequent AVL check fails, its
successful observed cost is retained alongside the rejection verdict.
Fixture/setup errors terminate the oracle with a nonzero exit status.

This schema supplies state-application evidence. It does not claim that the
synthetic chain passes a full node's history/difficulty-retargeting rules.

## Reproducibility and Rust consumption

`build`, `smoke`, and `capture` attach `ledger` and `manifest`. `capture` replays
an existing fixture and replaces `expected` with the production JVM observation:

```sh
python3 scripts/jvm_block_oracle/run.py capture scripts/jvm_block_oracle/p2pk.json.gz scripts/jvm_block_oracle/.work/p2pk-captured.json
```

`manifest.evidence.input_sha256` hashes the exact input file bytes (including gzip
framing). `output_payload_sha256` hashes UTF-8 compact JSON in producer field order
with only `manifest` omitted, avoiding a self-referential file hash. Compression
and whitespace do not change this payload. A generated smoke request has no input
file; its frozen bytes are included in the hashed output. `node_app_version` is
null because the offline oracle loads pinned node classes without a running node.
The tool's source hash identifies uncommitted producer changes at capture time.

The Rust runner inserts the recorded initial boxes into `AvlTree`, authenticates
all 128 parent transitions with `DigestProofVerifier`, and replays blocks 2–128
through the sequential validator. The first block has no parent validation context;
its PoW, genesis parent ID, section commitments and authenticated state transition
are checked directly. Epoch parameters are parsed from the extension, and the
last ten checked headers plus parent extension supply target validation context.
Both target validators run with scripts enabled; observed sequential and parallel
per-transaction costs must agree and their sum must equal the JVM total. The
successful target transition must also match the oracle's final root.

The initial corpus contains one accepted P2PK target. Rejected targets deliberately
fail this runner until JVM exception-to-semantic-failure mappings and unavailable
cost handling are added with independent rejection fixtures. This smoke does not
establish multi-transaction layering, cost-cap boundaries, or rejection precedence.
