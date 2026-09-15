# JVM transaction cost fixtures

## Reconciled breakdown fixture

`breakdown_700000_700001.json` contains all **10 of 10** mainnet transactions
at heights 700000–700001. It bundles canonical JVM transaction and box bytes,
11 headers (699991–700001), voted parameters, and the runtime artifact manifest.
The default integration test
`ergo-validation::it::cost_parity::transaction_breakdown_mainnet_all_ten_match_jvm`
checks box and transaction IDs, accepts every transaction through Rust's production
validator, and compares every cost field in **block cost units**.

The extractor's stdout contract is:

```jsonc
[
  {
    "tx_id": "<transaction id>",
    "height": 700000,
    "block_cost": 12356,
    "init_block_cost": 12200,
    "token_block_cost": 0,
    "inputs": [
      {"index": 0, "eval_block_cost": 156, "crypto_block_cost": 0, "rent": 0}
    ]
  }
]
```

These example numbers are the JVM result for transaction
`e4cea1c9…` in the fixture. `rent` is **50 BC** when the wallet interpreter's
storage-rent branch succeeds, otherwise 0. It is computational cost, not the
monetary storage fee. Input order is significant.

### Observation and reconciliation

The extractor calls unmodified `ErgoTransaction.validateStateful` with
`accumulatedCost = 0`. Its `RecordingInterpreter` wraps the wallet verifier
that this call actually uses:

- `fullReduction` records the returned reduction cost from that invocation.
- `checkExpiredBox` observes whether the rent predicate returned true. A thrown
  exception still follows the wallet's ordinary `recoverWith` fallback.
- `verify` returns the original result unchanged. Crypto cost is its returned
  total minus the observed reduction and successful rent charge. Thus Scala's
  per-input crypto rounding is preserved.
- Input contexts retain `costLimit = maxCost - currentTxCost` and `initCost = 0`.
  No input is re-run to obtain its breakdown.
- Transaction initialization uses the JVM interpreter constant and active
  parameters; token counting uses `ErgoBoxAssetExtractor`, the node's helper.
- Before emitting a transaction, the extractor requires
  `init + token + Σ(eval + crypto + rent) == block_cost`, where `block_cost`
  is the returned `validateStateful` payload. Missing/reordered observations,
  missing boxes, rejected transactions, and reconciliation failures abort the
  process. No partial stdout fixture is emitted.

Rust records initialization, token, and input boundary observations under its
`cost-trace` feature, alongside the evaluator's existing rounded crypto trace.
The test compares these observations from one `validate_transaction` invocation.
It also independently reconciles the Rust observations to the charged total.
The crate's test-only dependency enables recording in offline tests; normal
production builds do not enable it. Diagnostic range tests additionally require
`--features diagnostics` and now require the breakdown fields in their vectors.
Legacy aggregate-only range JSON must be regenerated before running those tests.

### Context fidelity

The JVM receives the current header and nine preceding headers through
`ErgoStateContext`. Rust receives the same nine ancestors, newest first.
Preheader fields and the previous state digest come from these real headers.
Epoch parameters and validation settings are loaded before the first requested
height and refreshed at epoch boundaries. Chain configuration comes from the
pinned Ergo reference checkout's `mainnet.conf` and `application.conf`.

The bundled Rust test uses the recorded voted parameters. Its default validation
rule settings match this fixture's epoch. Broader fixtures with changed validation
rules need those settings threaded through the Rust harness as well. The legacy
diagnostic range harness still uses default cost parameters and progressive UTXO
resolution, so it is not evidence for cross-epoch parameter parity or full coverage
of an arbitrary range.

### Reproduction

Requirements: scala-cli 1.12, an Ergo node with extraIndex (captured against
6.0.5 at `http://localhost:9053`), and the Ergo v6.0.5 source configuration.
`NODE_URL` and `ERGO_REFERENCE` override these locations.

Artifacts are pinned to **ergo-core/ergo-wallet 6.0.5**, with
**sigma-state 6.0.6**. The extractor asserts the resolved Sigma jar version
at runtime and emits it in both stderr's manifest and the bundled fixture.
See `../cost-ledger/reconciliation.md` for the source-version reconciliation.

The 6.0.5 Ergo artifacts were unavailable in the local cache and Maven Central.
They were built with `publishLocal` from a worktree-local archive of the
reference checkout's `v6.0.5` tag. Because an archive nested in this Rust worktree
inherits the enclosing Git version through sbt-dynver, the successful command was:

```bash
sbt 'set ThisBuild / version := "6.0.5"' \
  avldb/publishLocal ergoWallet/publishLocal ergoCore/publishLocal
```

Run that command in the archived Scala source directory. The extractor enables
`ivy2Local` and the GitLab Maven repository needed for `leveldbjni-all:1.18.3`.
No fallback to 6.0.2 was needed. Do not override `SIGMASTATE_VERSION`.

From the Rust workspace root:

```bash
COST_FIXTURE=test-vectors/ergo-sigma/cost-total/breakdown_700000_700001.json \
scala-cli run test-vectors/scripts/scala/ComputeTransactionCosts.scala \
  --server=false --suppress-outdated-dependency-warning -- 700000 700001

cargo test -p ergo-validation --test it \
  cost_parity::transaction_breakdown_mainnet_all_ten_match_jvm
```

`COST_FIXTURE` is optional. Without it, the script emits only the transaction
array to stdout and the manifest/progress to stderr. The fixture's costs and
canonical bytes come from the same extraction run.

### Drop-rate cause and resolution

Running the original extractor at 700000–700001 reproduced **5 passed, 5 failed**.
The exception stack starts at `scala.collection.mutable.WrappedArray.make`,
called from the extractor's `countTokens` helper. A token ID is a Sigma
`Coll[Byte]` (`sigma.data.CollOverArray`), not a JVM `Array[Byte]`; passing it to
`WrappedArray.make` raises `scala.MatchError`. All five failures occurred while
counting tokens, **before script verification**.

The earlier attribution to stubbed register/data-input context was incorrect.
The production `ErgoBoxAssetExtractor` now performs token counting, eliminating
that conversion. The pinned extractor reports:

```text
h=700000: 3 accepted and reconciled
h=700001: 7 accepted and reconciled
Done: 10 accepted and reconciled, 0 dropped
```

This fixture covers 18 inputs, five token-bearing transactions, and mixed
trivial/script and cryptographic proofs. It does not contain successful rent
spends or nonempty data-input lists. Existing JVM verify fixtures under
`../verify/cases.json` cover rent success and fallback; this mainnet fixture
alone is not a claim of complete rent, rejection, or cost-formula coverage.
No ledger rows are closed by the extractor migration.

## Legacy aggregate fixture

`mainnet_700000_700001.json` retains the original five successfully extracted
transactions and is consumed by `ergo-validation/tests/cost_total_oracle.rs`.
It has aggregate costs only, a partial preheader, empty context headers, and
resolves boxes from `test-vectors/mainnet/input_boxes_700000_700010.json`.
That test checks reconstructed box IDs before validating transactions.

Its five retained totals agree with the new extraction. Its empty Rust header
context does not reconstruct the Scala previous state digest, so it provides no
coverage for scripts reading `CONTEXT.headers` or `LastBlockUtxoRootHash`.
The bundled breakdown fixture supplies the full header context and input bytes
for the new field-by-field test. Neither fixture proves cross-epoch parity.

## Compressed evidence storage

The epoch-extension corpus is stored as deterministic `mainnet-epochs.json.gz`.
`scripts/cost_fixture_io.py` writes gzip without filenames or timestamps.
Evidence SHA-256 hashes cover uncompressed JSON bytes, never gzip archives.
Historical source hashes and revision identifiers retain their original provenance;
changing storage does not regenerate oracle evidence.
