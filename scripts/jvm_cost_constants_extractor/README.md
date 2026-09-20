# JVM cost constants (sigmastate 6.0.2)

`CostConstants.scala` captures the declarations used by the L1 Rust pin consumer.
It does not close ledger rows or read Rust cost implementations.

Run from the repository root:

```bash
revision="$(git rev-parse HEAD)"
timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
scala-cli run scripts/jvm_cost_constants_extractor/CostConstants.scala --server=false --jvm system -- "$revision" "$timestamp"
python3 scripts/jvm_cost_constants_extractor/verify.py
python3 scripts/cost-ledger.py check
```

The output is `test-vectors/ergo-sigma/cost-ledger/scala-constants.json`.
For byte-identical regeneration, use its `manifest.run.command_line`, the same
JVM, Rust toolchain, Scala CLI, and Maven artifacts. The command accepts an
explicit capture timestamp so re-runs can retain it. The manifest records the base revision and exact source SHA-256. `source_state`
is `committed` when that revision contains the extractor, or `working-tree`
when capturing a change before its gated commit. The verifier always checks the
source hash and additionally checks the revision contents for committed captures. No node or blockchain context is
used. Null context fields mean not applicable, and no Rust features are run.

In a worktree with a strict write boundary, set `COURSIER_CACHE` and
`SCALA_CLI_CONFIG` to paths inside the worktree. `--server=false --jvm system`
uses the installed JDK and writes compiler output beside the script.

## Schema and coverage

- `opcodes`: every entry in the JVM's 256-slot `ValueSerializer.serializers`.
  The numeric opcode is unsigned. Unsupported `costKind` getters are retained
  as `NotSupported`, with the precise exception message.
- `containers`: every entry in `MethodsContainer` across ErgoTree versions 0–3,
  including containers without methods. `wireReceiverVersions` comes from
  `SType.types`; it distinguishes registry declarations from wire reachability.
- `methods`: every registered method in each version. Identical descriptors
  across versions are grouped; differing costs remain separate records.
  `minVersion` is the earliest **ErgoTree registry version** for that descriptor,
  not a block version or a claim of wire reachability. Sigmastate 6.0.2 has no
  `SMethod.minVersion` member. The complete `versions` array is retained.
- `tupleMethods`: all inherited `size`/`apply` and generated `_1` through `_255`
  declarations, obtained from `STupleMethods.getTupleMethod` for every arity 2–255
  and version 0–3. Identical declarations are grouped into inclusive `minArity` /
  `maxArity` intervals after asserting the enumerated arities are contiguous.
  Names distinguish accessors from inherited collection methods with colliding IDs.
  This inventory does not imply executability: only pairs have a tuple evaluator;
  serialized verify fixtures pin both pair execution and larger-arity rejection.
- `costKind`: `Fixed`, `PerItem`, `TypeBased`, `Dynamic`, or `NotSupported`.
  `base`, `perChunk`, and `chunkSize` are null when not applicable. Type-based
  functions retain their JVM class; `PowHitCostKind` is a custom dynamic formula
  and retains its class too. Formula execution belongs to the later L2 tests.
  Null method descriptors (e.g. numeric conversions lowered to AST nodes) are
  recorded as `NotSupported` with a reason; they are not extraction exclusions.
- `constants`: reflection discovers all `OperationCostInfo` getters on
  `DataValueComparer`, `Interpreter`, `SigSerializer`, and `FiatShamirTree`.
  The latter two objects own the parsing and serialization crypto costs imported
  by `Interpreter`. Additional scalar JVM values include interpreter costs,
  storage cost, evaluator block size, JitCost representation bounds/scale, and
  the five cost-bearing `Parameters` defaults from pinned ergo-core 6.0.2.
  JitCost has no named bound constants: its bounds are JVM Int bounds, marked
  `jvm-derived` with the Int-backed value-class source citation. Both wallet
  constants are read from the pinned artifact; no manual fallback is used.
- `manifest.excluded`: empty because all requested registry declarations and
  explicit constants were reached. Any future exclusions must name the constant,
  cite source file:line, give a rationale, and be checked against an N-A ledger
  row by the Rust pin consumer. This task does not implement that Rust consumer.

JSON object keys and arrays have stable ordering. The manifest hashes the script
and loaded sigma-state, ergo-wallet, and circe-core artifacts. The embedded output
hash covers the sorted, two-space Circe JSON payload **without the manifest or
final newline**: embedding a whole-file hash in that same file is self-referential.
`verify.py` checks this precise scope. The complete file can additionally be
hashed with `sha256sum test-vectors/ergo-sigma/cost-ledger/scala-constants.json`.

The selected/executed counts count opcode records, version-grouped registry and synthesized tuple method
records, and named constants; container metadata is not a cost obligation.
The verifier checks schema, coverage, provenance, hashes, and a few source-pinned
sentinels. It is an extractor integrity check, not a Rust/JVM parity test.
