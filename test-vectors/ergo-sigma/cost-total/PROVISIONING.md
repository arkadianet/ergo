# Scala-anchored ergo-sigma cost-total fixtures

`.json` files in this tree pin Rust transaction-validation cost
against the live Scala `sigmastate-interpreter` running on a
mainnet-synced Ergo node. The fixture is **in-tree**: tx bodies +
per-height header context live in the JSON, so the test runs in
default `cargo test` with no network and no feature flag. Input
boxes are resolved against the existing tracked
`test-vectors/mainnet/input_boxes_*.json` pool; the fixture
deliberately is not self-contained on that surface — see the
follow-up at the bottom.

## Fixture contract

```jsonc
{
  "headers": {
    "<height>": {
      "timestamp":   <u64>,
      "n_bits":      <u64>,
      "version":     <u8>,
      "miner_pk_hex": "<66-hex>"   // 33-byte compressed secp256k1 pk
    }
  },
  "transactions": [
    {
      "tx_id":      "<64-hex>",  // mainnet tx id
      "height":     <u32>,       // block height
      "block_cost": <u64>,       // Scala `totalCost.toBlockCost`
      "tx_bytes":   "<hex>"      // canonical tx serialization
    }
  ]
}
```

**`block_cost` unit**: block-cost units (NOT raw JitCost). The Rust
oracle calls `cost.total_block_cost()` which downcasts JitCost to
block units the same way Scala's `toBlockCost` does — drift in the
scale factor (×10) would fail the test.

**`block_cost` scope**: per-transaction. The Scala extractor sums
`initCost + tokenCost + Σ per-input scriptCost`. The Rust path runs
the same accumulation through `validate_transaction` →
`compute_tx_init_cost` (added up-front) → per-input
`verify_spending_proof_with_context_and_cost` (charged into the same
`CostAccumulator`).

**Context approximations** (must match on Rust + Scala sides):

* `headers = empty` — scripts that read `CONTEXT.headers[i]` may
  diverge. No fixture entry currently hits this. The Rust oracle
  passes `last_headers: &[]` to mirror the Scala extractor's `Colls.emptyColl` argument.
* `LastBlockUtxoRootHash` parity is **partial**: the Scala extractor
  seeds `prevStateRoot` from the previous block's `stateRoot` (see
  `ComputeTransactionCosts.scala:188-205`), but with
  `last_headers: &[]` the Rust validator computes
  `last_block_utxo_root = None` (from `eval_headers.first()`). So
  scripts reading `CONTEXT.LastBlockUtxoRootHash` would diverge
  silently — both harnesses produce different values, and neither
  signals the difference. None of the current fixture txs hit
  opcode `0xA6` (`SContext.LastBlockUtxoRootHash`); a future
  extension that does will need a richer Rust-side context that
  threads `prevStateRoot` through. This is the audit follow-up
  noted at the bottom of this document.
* `ValidationRules = currentSettings` (assumed stable on mainnet).
* `pre_header_parent_id = 0`, `pre_header_votes = 0` — scripts that
  read these would diverge. None of the fixture txs do.
* `activated_script_version = version - 1` per consensus spec.

**Box fidelity invariant**: the Rust oracle asserts
`reconstructed.box_id() == fixture.boxId` for every input box
*before* it enters the in-memory UTXO. The validator does not
re-verify box IDs after resolving inputs from the UTXO map, so a
fabricated body (e.g. a register encoding `read_constant` cannot
parse) would otherwise pass silently. The id check fails loudly
instead — drift on register bytes is non-bypassable.

## Provenance

| File | Heights | Tx count | Notes |
|------|---------|----------|-------|
| `mainnet_700000_700001.json` | 700000-700001 | 5 (of 10) | 5 of the block's txs failed extraction in the Scala harness — see "Drop-rate" below. |

## How to extract (and extend)

### Prerequisites

* A mainnet-synced Ergo node with `/extraIndex` enabled (default
  `http://localhost:9053`). Override the extractor via `NODE_URL`.
* `scala-cli >= 1.0` (the existing harness was built against
  Scala 2.12 + `org.ergoplatform::ergo-wallet:6.1.0`).

### Two-step extraction

1. Run the Scala harness to get `(tx_id, height, block_cost)`:

   ```bash
   scala-cli run test-vectors/scripts/scala/ComputeTransactionCosts.scala \
     -- <start_height> <end_height>
   ```

   Output is JSON to stdout. Capture into a temp file.

2. Augment with `tx_bytes` and per-height header context. The cheap
   way is a small Python helper that pulls the missing pieces from
   the same Scala node:

   ```python
   import json, urllib.request

   COSTS_RAW = "<paste step 1 output here>"
   NODE     = "http://localhost:9053"
   TX_SRCS  = [
       "test-vectors/mainnet/transactions_700000.json",
       "test-vectors/mainnet/transactions_700000_700200.json",
   ]

   costs = json.loads(COSTS_RAW)
   target = {c["tx_id"]: c for c in costs}

   bytes_by_id = {}
   for path in TX_SRCS:
       try:
           with open(path) as f:
               for tx in json.load(f):
                   if tx["id"] in target and tx["id"] not in bytes_by_id:
                       bytes_by_id[tx["id"]] = tx["bytes"]
       except FileNotFoundError:
           continue

   txs = []
   for tid, c in target.items():
       txs.append({**c, "tx_bytes": bytes_by_id[tid]})

   headers = {}
   for h in sorted({c["height"] for c in costs}):
       block_id = json.load(urllib.request.urlopen(
           f"{NODE}/blocks/at/{h}", timeout=10))[0]
       hj = json.load(urllib.request.urlopen(
           f"{NODE}/blocks/{block_id}/header", timeout=10))
       headers[str(h)] = {
           "timestamp":    hj["timestamp"],
           "n_bits":       hj["nBits"],
           "version":      hj["version"],
           "miner_pk_hex": hj["powSolutions"]["pk"],
       }

   with open("mainnet_<start>_<end>.json", "w") as f:
       json.dump({"headers": headers, "transactions": txs}, f, indent=2)
   ```

   The `tx_bytes` lookup walks the existing tracked
   `transactions_*.json` files (which are produced by the same
   audit corpus). Heights covered there: 700000 (tracked) plus
   any locally-extracted ranges. If `tx_bytes` is missing for any
   `tx_id`, the helper fails loudly; capture more breadth before
   re-running.

3. Save under `test-vectors/ergo-sigma/cost-total/mainnet_<start>_<end>.json`
   and add a row to the Provenance table above.

### Drop-rate

Roughly half of mainnet transactions fail the Scala extractor with
`Coll(...) of class CollOverArray` errors — scripts that read
register or data-input contexts the extractor's stub doesn't model.
Dropped transactions are NOT a parity gap, just unextractable through
this harness. To raise the success rate, extend
`ComputeTransactionCosts.scala` to populate per-input
`ContextExtension` (currently `input.spendingProof.extension`) and
optionally `CONTEXT.headers`.

## What this fixture pins

* Each `(tx_id, block_cost)` pair is the live Scala interpreter's
  `totalCost.toBlockCost` on mainnet bytes.
* The Rust oracle (`ergo-validation/tests/cost_total_oracle.rs`)
  drives the production `validate_transaction` path the chain
  validator uses — not a parallel cost path — and asserts
  `cost.total_block_cost() == fixture.block_cost` exactly.
* Two reject-path tests pin the cost-limit gate at the precise
  boundary the chain consensus relies on:
  * Init-cost over budget surfaces `ValidationError::CostExceeded`
    with current/limit in JitCost units.
  * Per-input script eval over budget surfaces
    `ValidationError::ScriptError` whose `reason` carries the
    JitCost-unit numbers.
  Both error envelopes have separate tests so drift in either is
  detected.

A drift in the happy path is chain-fork-class: the cost-limit reject
path is the protocol gate.

## What this fixture does NOT yet cover

* **`LastBlockUtxoRootHash` / opcode `0xA6`**: the Scala extractor
  seeds `prevStateRoot` but the Rust harness's `last_headers: &[]`
  resolves `last_block_utxo_root` to `None`. Scripts reading
  `0xA6` diverge silently. None of the current fixtures hit it.
* **`CONTEXT.headers`**: both harnesses pass `headers = empty`.
* **Non-default active params**: the Rust oracle uses
  `ProtocolParams::mainnet_default()`. Its cost-bearing fields
  (`max_block_cost = 8_001_091`, `input_cost = 2_000`,
  `data_input_cost = 100`, `output_cost = 100`,
  `token_access_cost = 100`) match the voted snapshot at h=700000
  — which is why these fixtures pass under defaults. The
  authoritative path for height-derived params is
  `ProtocolParams::from_active(&ActiveProtocolParameters)`. A
  cross-epoch fixture whose epoch's voted values diverge from
  `mainnet_default()` would need a tracked
  `ActiveProtocolParameters` snapshot threaded through
  `from_active`; until that snapshot ships this oracle cannot
  detect param-snapshot drift for cross-epoch ranges.
* **Cross-epoch voting boundaries**: every fixture entry lives in
  a single epoch.
* **Selection bias**: the extractor drops ~50% of mainnet txs
  (register/data-input dependencies it can't model). The
  retained subset under-represents context-heavy scripts —
  exactly the scripts most likely to expose cost/context bugs.

## Known follow-ups

* **`LastBlockUtxoRootHash` parity**: thread the Scala extractor's
  `prevStateRoot` through to the Rust harness so opcode `0xA6`
  scripts can be measured. Today both harnesses stub this
  surface but with different values (Scala = previous block's
  `stateRoot`; Rust = `None`). A fixture exercising this opcode
  must be added once context plumbing exists.
* **`CONTEXT.headers` parity**: both harnesses currently pass
  `headers = empty`. Add a fixture that reads
  `CONTEXT.headers[i]` to validate that the empty-stub assumption
  doesn't silently mask drift for header-reading scripts.
* **Cross-epoch coverage**: every fixture entry today lives within
  a single voting epoch with mainnet default params. Extend across
  a voting boundary so `cost.total()` is exercised under a
  non-default active params snapshot.
* **Raise Scala-extractor success rate**: the harness drops ~50%
  of mainnet txs (register/data-input dependencies stubbed). Wider
  extraction breadth strengthens both this oracle and
  `cost_parity.rs`.
* **Per-input granularity**: current fixtures expose only the
  aggregate `block_cost`. If a Rust drift bug surfaces, the next
  diagnostic step is per-input cost; modify the Scala extractor to
  emit `script_cost[i]` per input.
* **Decouple from input-box pool**: input-box bytes still come from
  the existing tracked
  `test-vectors/mainnet/input_boxes_700000_700010.json`. Future
  ranges either need a matching `input_boxes_*` capture or to bundle
  input-box bytes directly into the fixture.
