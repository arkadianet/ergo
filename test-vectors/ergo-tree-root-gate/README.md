# Rule-1001 root classification regressions

These 28 hand-serialized trees use the existing ErgoSerdeOracle `ergo_tree`
surface with sigma-state and ergo-core 6.0.2. `requests.txt` and `responses.txt`
retain the exact JVM exchange; `cases.json` names the corresponding inputs.
The reproduction command and hashes are in `manifest.json`.

The JVM rejects all 19 sizeless cases: ten unknown-child cases (including
`00d9007201`), six primitive/byte constants, a tuple, a function and a collection.
The nine sized counterparts of the known-type cases include one trailing byte
inside the declared region. Their JVM canonical bytes preserve that entire
region. The Rust regression checks rejection or acceptance and reader position.

The parser root judgment is independent of exact substitution inference. Its
implementation is restored from `5b65b4f9^`, before the round-3 typing change.
Tuple/function unknown children remain definitely non-SigmaProp. Projections,
operand-preserving transforms, method classification, and sized-region behavior
retain that revision's root judgment. Exact tuple/function ranges and collection
projections remain available to substitution. The projection regression also
checks that a sized lenient root stops at the structural expression end.

This is a compatibility restoration, not a claim that all parser residuals are
fixed. In particular, bare unbound ValUse and previously lenient projections
remain outside the root gate's exact knowledge. No cost-ledger row is closed by
these parser tests.

The 2,000-check mainnet mutation campaign selected/executed 2,000 and found
47 divergences in ten classes. The pre-round-3 baseline (`5b65b4f9^`) has the
same classes, multiplicities, outcomes and representative repro bytes, compared
using the same corpus directory (its enumeration order affects generation).
`campaign-baseline.txt` records the unchanged findings. These are explicit
pre-existing parser residuals, not a green whole-parser parity claim.

The campaign also requires the oracle protocol to preserve an empty hex payload:
`ergo_tree ` is a zero-byte parser input, not a malformed protocol frame. The
live `valdef_type_store_shapes_match_jvm_oracle` guard includes that request.
