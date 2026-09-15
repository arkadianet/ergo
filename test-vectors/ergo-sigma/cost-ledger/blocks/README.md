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

The runner maps the pinned JVM `MalformedModifierError` to `RejectCost` only
for rule 307's accumulated-cost message or rule 119's embedded
`sigma.exceptions.CostLimitException`. A rule-119 `Success((false,...))` maps to
`RejectScript`, exercised by the invalid-signature control. Unknown JVM and Rust
errors fail the test; an arbitrary rejection cannot satisfy cost parity. Rejected
execution retains null cost, and the fixture must preserve its parent root.
The Rust validators return validation results without applying rejected blocks.

## Boundary families

Regenerate all families in one JVM invocation so the ordered fixtures share the
same signed transactions (P2PK signatures use JVM prover randomness):

```sh
python3 scripts/jvm_block_oracle/run.py families scripts/jvm_block_oracle/.work
```

Compress each named JSON output with Python `gzip.compress(bytes, mtime=0)` into
this directory. `capture` independently replays any tracked gzip fixture.
Each generated fixture records its JVM baseline in `boundary_basis`; the builder
measures production execution before choosing the boundary cap. The original
signed bytes, state, parameters, source hash and reproduction command are retained.

| Fixture | Cap | JVM result | Evidence |
|---|---:|---|---|
| `a-exact-sum` | 37509 | Accept, 37509 | Three independent P2PK transactions at equality |
| `b-sum-plus-one` | 37508 | RejectCost, unavailable | Identical transactions exceed cap by one |
| `c-single-cap` | 12503 | Accept, 12503 | Single P2PK exactly at cap |
| `d-mid-block`, `d-mid-block-reversed` | 25005 | RejectCost, unavailable | Same three transactions reversed; JVM identifies transaction two as failing |
| `e-token-order` | 24703 | RejectCost, unavailable | Prefix 12503 leaves 12200; structural init 12100 passes, then four token accesses add 400 and fail rule 307 |
| `f-v6-devnet` | 1000000 | Accept, 12104 | Block version 4, activated version 3, ErgoTree version 3 eagerly evaluates Coll.reverse on 201 bytes before True |
| `f-v5-control` | 1000000 | RejectVersion, unavailable | Identical signed transaction and input state, rebuilt under block version 3; JVM rejects tree version 3 above activated 2 |
| `rejection-script-control` | 1000000 | RejectScript, unavailable | Invalid P2PK signature must not count as cost rejection |

These fixtures establish the named boundary obligations, not exhaustive proofs
for arbitrary scripts or full-node history/difficulty validation.

### Requested Long multiplication overflow

`BLOCK-overflow-fixture` remains OPEN. A serialized block cannot provide the
requested overflowing `initialCost` multiplication under the pinned JVM types:

- `ErgoTransaction.validateStateful` lines 370–374 widens collection `.size: Int`
  and `Parameters` cost-table `Int` values to `Long` before multiplying.
- Even `Int.MinValue * Int.MinValue` after widening is `2^62`, below `Long.MaxValue`.
  A collection size is nonnegative, giving an even tighter bound.
- `ErgoLikeTransactionSerializer` in sigma-state's
  `data/shared/src/main/scala/org/ergoplatform/ErgoLikeTransaction.scala`
  lines 148, 155, 172 reads all three counts with `getUShort` (maximum 65535).
  With every positive tariff at `Int.MaxValue`, all three initialization products
  plus the 10000 interpreter constant total at most **422206022428435**, below
  `Long.MaxValue` (9223372036854775807). Adding the running cost bounded by the
  `Int` block cap still cannot overflow `Long`.

A helper called with invented Long counts, a narrower JIT overflow, or a block
rejected for size/cap does not demonstrate the requested production multiplication
overflow. No such substitute is represented as closure evidence.

The version control rebuilds the block envelope and parent chain under parameter
123 = 3 while preserving signed transaction bytes, input boxes and parent UTXO
root. Both Rust validators must report the specific tree-version error. Family
(f) uses cap 1000000 because its observed 12104 cost is below the 12105 needed
by the true-script bootstrap parent transactions. Family (d) additionally pins
the Rust deferred-sum error to `BlockCostExceeded { total: 37509, limit: 25005 }`.
