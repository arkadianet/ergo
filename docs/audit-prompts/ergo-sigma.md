# Audit prompt: ergo-sigma

Audit `ergo-sigma` as the script evaluator, cost meter and spending-proof
verifier of a prospective reference-quality Rust Ergo node.

First read `docs/audit-prompts/COMMON.md` and follow its full methodology,
review-only default, evidence standards, reporting format, and coverage ledger.
Then read `CONTRIBUTING.md`, `docs/compatibility.md`, the manifest/root and
`docs/codemap/ergo-sigma.md`. Commands and repository-prefixed paths are relative
to the repository root; abbreviated source paths are relative to this crate.
Verify map claims and moved modules against the checkout. Inventory all source, tests,
comments, features, source includes, linked fixtures/generators and configuration.
Every handler and feature is in scope, not just scripts observed on mainnet.

## Mission and trust boundaries

Audit verdict, reduced proposition, charged/partial cost and error class as
distinct outputs. This crate accepts both wire-parsed and caller-built trees,
runtime context values, proofs and serialized data reached during evaluation.
Trace parse-time, pre-reduction, reduction, cost and verification checks through
both fast and full paths. An independent Rust evaluator can cross-check semantics
but does not replace the pinned Scala/mainnet authority for consensus claims.

## Source landmarks

- `ergo-sigma/src/reduce.rs`: soft-fork conditions, trivial/full reduction,
  deserialize substitution, input rounding and public spend entry points.
- `ergo-sigma/src/evaluator/dispatch/`: AST walking, pre-checks and eval dispatch.
- `ergo-sigma/src/evaluator/types.rs`, `eval_ctx.rs`, `cost.rs`, `helpers/`.
- `ergo-sigma/src/evaluator/opcodes/`, including every `method_call/` module.
- `ergo-sigma/src/cost_table.rs`, `crypto_cost.rs`, `verify.rs`, `schnorr.rs`, `dht.rs`.
- `ergo-sigma/src/avl.rs`: the authenticated-proof dependency and panic boundary.
- `ergo-sigma/src/cost_trace.rs`, `value_trace.rs` and feature wiring in `lib.rs`.
- All inline tests and `ergo-sigma/tests/it/`, including cost ledger, AVL panic
  differential, SANTA corpus, mainnet spends and v6 unsigned BigInt witnesses.
- `test-vectors/ergo-sigma/`, referenced `test-vectors/scala/` and mainnet/testnet
  data; `scripts/jvm_*oracle/`, cost-ledger tooling and their provenance manifests.

## Coverage matrix and version semantics

Create an opcode and `(receiver type, method ID)` matrix with parser support,
static typing, evaluator implementation, version/activation gate, cost formula,
failure behavior and independent tests. Include unsupported/deprecated/internal
forms and property calls; never equate registry presence with executability.

Trace tree-header version, activated script version, validation settings and
network/block context separately. Check v0–v3, below/at activation, unknown
future versions and opaque/degraded trees. Confirm soft-fork accept-without-
verification conditions, charged cost and status rules against the actual JVM.
Checks in dead branches may be parser/pre-reduction checks rather than executed
method checks; preserve that distinction.

Verify trivial reduction and full reduction agree on admissible constants,
placeholders, error/fallthrough classification and metering. A fast P2PK path
must still enforce required extension/point pre-checks and soft-fork rules.

## Evaluation semantics

For every opcode and method, inspect evaluation order, laziness, types, values,
cost timing, rejection class and depth/resource behavior. In particular:

- Binding, closures, captured environments, shadowing, recursive applications,
  tuple conversion, pair projection and state restored on early errors.
- If/logical/collection short-circuiting, lambda traversal order and empty
  collections. Failed/default operands must run exactly when the JVM runs them.
- Numeric widths, checked/wrapping operations, signed division/remainder, shift
  counts, negative indices, narrowing casts and signed/unsigned BigInt bounds.
- Every collection carrier, nested pairs/options, token-pair adapters and
  conversion into typed Sigma values. Equal runtime data in different carriers
  needs reference-defined comparison, not accidental Rust representation equality.
- Bare versus nested strings, JVM UTF-8/string length and reflective exception
  wrapping. Distinguish byte count, UTF-16 units and Unicode scalar count.
- Box/header/pre-header identity, raw retained bytes versus canonical serialize,
  script/register extraction, creationInfo, IDs and materialized SBox/SHeader.
- HEIGHT, SELF/self index, ordered INPUTS/OUTPUTS/data inputs, extension GetVar,
  header window, miner key, pre-header fields and last-block AVL root. Minimal
  test contexts cannot substantiate real transaction-context parity alone.
- DeserializeContext/DeserializeRegister, constant substitution and rewritten
  tree typing. Include absent/wrong-type values, nested parsing, unread bytes,
  dead branches, rewrite depth and group elements introduced by serialized data.
- Group decoding/encoding, identity prefix normalization, hashes, exponentiation,
  group multiplication, SigmaBoolean construction and simplification; check
  compile-time curve helper policies do not replace runtime semantics.
- AVL/global/header methods, general powHit inputs and activated v6 methods;
  identify caller/dependency preconditions before claiming hostile paths bounded.

## Cost and failure accounting

Trace every charge in both successful and failing execution: fixed/per-item/
type/dynamic cost, comparator walk, serialization, deserialization substitution,
AVL construction/operations, tree rewrite and crypto verification. Verify cost
charged before or after work and before or after an error against the oracle.

Check JIT versus block units, per-input truncation baseline, crypto addition,
nonzero transaction initialization, exact-limit acceptance, one-unit excess and
i32-bound overflow. Recording-only modes still enforce arithmetic invariants.
Check parameter changes and cumulative validation settings supplied by callers.

Compare cost-table declarations with executed formulas; matching constants alone
does not prove complete metering. Inspect ledger scope, divergence sets, hashes,
fixture contexts and claim status. Declaration extraction, reduced expressions,
per-input costs and production block totals are different grades of evidence.

## Proof verifier and AVL boundary

Audit Schnorr/DHT leaf commitment equations, scalar/point range handling,
24-byte challenge interpretation, response padding and proof consumption.
For AND/OR/threshold compositions verify tree topology, child challenges, XOR,
GF(2^192) coefficients, polynomial interpolation/evaluation and transcript byte
layout: tags, order, big-endian lengths, proposition and message binding.
Check trivial propositions, malformed arities/thresholds, deep/wide caller-built
trees, truncation, extra proof bytes and mutation of every transcript component.
Preserve independently confirmed permissive reference behavior rather than
inventing canonical proof constraints.

Review `extract_proof_leaves` and public helpers for agreement with verification
and wallet hint consumers. Validating against the same local prover is not
independent evidence. Establish secret-handling/timing requirements where these
helpers are used by proving code, not only in public verification.

For AVL, inspect construction and every operation, digest retrieval, dependency
preconditions, flags, key/value sizes, operation order and proof consumption.
Verify caught-panic poisoning and ordinary-error behavior separately; a failed
operation need not poison if the reference retains state. Check panic-sentinel
restoration, unwind/destructor containment and the crate's panic-abort compile
guard. Identify memory abort/stack limits that `catch_unwind` cannot contain.
Cross-check mutated proofs with an independent JVM verifier, including a
successful operation followed by a panic and every subsequent access.

## Feature and test evidence

Audit `cost-trace` and `value-trace` for scoped/thread-local lifecycle, nested
recording, error cleanup, pointer/node identity, rewritten trees, parallel workers
and bounded output. Feature-on/off execution must retain consensus verdict/cost;
feature intent in comments is not build-graph enforcement.

```bash
cargo test --locked -p ergo-sigma
cargo test --locked -p ergo-sigma --features cost-trace --test it cost_trace_smoke
cargo test --locked -p ergo-sigma --features cost-trace --test it traced_untraced_parity
cargo test --locked -p ergo-sigma --features value-trace
cargo clippy --locked -p ergo-sigma --all-targets --all-features -- -D warnings
cargo doc --locked -p ergo-sigma --no-deps --all-features
```

Select additional campaigns/diagnostics only after checking prerequisites under
COMMON. Pin artifact and context versions per fixture: older docs cite 6.0.2,
while several current oracles use 6.0.6. Report verified/rejected/skipped cases,
not a blanket mainnet-parity claim inferred from passing smoke tests.

## Exit criteria

Deliver the COMMON report and file ledger with the complete opcode/method/cost
matrix, version/context ownership and proof/dependency threat boundaries.
Highlight untested acceptance/cost branches and unsupported claims separately
from reproduced bugs. Every high-impact conclusion needs a reachable spend or
public-entry witness and correctly matched independent reference context.
