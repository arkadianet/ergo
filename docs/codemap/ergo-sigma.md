# ergo-sigma

**Purpose:** Sigma-protocol verifier and ErgoTree evaluator. Reduces an
ErgoTree body to a `SigmaBoolean` via an AST-walking interpreter with JIT cost
accounting, then verifies the spending proof (Schnorr DLog, ProveDHTuple, and
CAND/COR/Cthreshold composition). Owns the single entry point that mempool
admission and block validation call to check whether an input may be spent.

**Depends on (workspace):** ergo-primitives, ergo-ser, ergo-crypto
**Depended on by:** (see codemap index)
**Approx LOC:** ~15,200 production (~28,000 incl. `evaluator/tests.rs`)

## Start here
- `reduce::verify_spending_proof_with_context` (`src/reduce.rs:149`) — the
  single spending-validation entry point. Read this first: it shows the whole
  flow (trivial reduce → fall back to evaluator → cost snap → crypto cost →
  proof verify).
- `evaluator::dispatch::eval_op` (`src/evaluator/dispatch.rs:449`) — the
  `(opcode, payload)` jump table. The fastest map of *which opcodes exist* and
  which handler each routes to.
- `evaluator::types::Value` and `ReductionContext` (`src/evaluator/types.rs:375`,
  `:201`) — the runtime value enum and the transaction-scoped context every
  opcode reads. Understand these before any opcode handler.
- `verify::verify_sigma_proof` (`src/verify.rs:253`) — Fiat-Shamir proof
  verification over the reduced `SigmaBoolean`.
- `src/lib.rs` — module map + the size/soundness constants
  (`SOUNDNESS_BYTES=24`, `GROUP_SIZE=32`, `SCHNORR_PROOF_SIZE=56`).

## Modules
- `src/reduce.rs` — trivial-reduction fast path + the public
  `verify_spending_proof*` entry points and `VerifySpendingError`. Classifies
  reduction outcomes into fall-through vs. hard-reject.
- `src/evaluator/` — the AST-walking interpreter (see submodules below).
  `mod.rs` re-exports `dispatch::*`, `types::*`, and `sigma_to_value`.
- `src/evaluator/dispatch.rs` — top-level `reduce_expr*` drivers, depth-guarded
  `eval_expr`, and the `eval_op` opcode jump table; also `reduce_expr_traced*`.
- `src/evaluator/types.rs` — `Value`, `ReductionContext`, `EvalBox`,
  `EvalHeader`, `BoxSource`, `EvalError`, the `Env` type alias, `MAX_EVAL_DEPTH`.
- `src/evaluator/eval_ctx.rs` — `EvalCtx`, the six-borrow bundle threaded
  through opcode helpers (evaluator-internal only).
- `src/evaluator/helpers.rs` — wire↔runtime conversion (`sigma_to_value`,
  `value_to_typed_sigma`), `DataValueComparer`-parity equality (`values_equal`),
  collection carrier machinery (`collection_to_values`,
  `values_to_collection`), `SubstConstants` rewrite, box resolution.
- `src/evaluator/cost.rs` — cost-charging shims over `cost_table`
  (`add_cost`, `add_cost_per_item`, `add_method_cost`, `add_arith_cost`,
  dynamic EQ/NEQ cost, AVL verifier construction helper).
- `src/evaluator/opcodes/` — per-category opcode arm bodies; `dispatch.rs` maps
  each `(opcode, payload)` 1:1 here:
  - `method_call.rs` — `0xDC MethodCall` dispatch on `(type_id, method_id)`;
    the largest opcode unit (SColl, SBox, SAvlTree, SGlobal, SNumeric,
    SBigInt/SUnsignedBigInt, SGroupElement, EIP-50/Sigma-6.0 v6 methods).
  - `property_call.rs` — `0xDB PropertyCall` (no-arg method dispatch).
  - `sigma.rs` — ProveDlog/ProveDHTuple construction, AtLeast/SigmaAnd/SigmaOr,
    DecodePoint, Exponentiate, MultiplyGroup, Blake2b256/Sha256, SubstConstants.
  - `collection.rs` — SizeOf, ByIndex, map/filter/fold/forall/exists, append,
    slice.
  - `box_context.rs` — Extract* (amount, id, bytes, script, registers,
    creationInfo), GetVar.
  - `arithmetic.rs`, `comparison.rs`, `boolean.rs`, `cast.rs`, `binding.rs`
    (ValDef/ValUse/BlockValue/If/FuncValue/FuncApply/Tuple/SelectField),
    `constants.rs` (HEIGHT/SELF/INPUTS/OUTPUTS/MinerPubkey/GroupGenerator/…),
    `option.rs`, `errors.rs` (reject-only arms for deprecated/internal/
    non-executable opcodes).
- `src/verify.rs` — `verify_sigma_proof`, the `UncheckedTree` proof parser
  (`parse_and_compute_challenges`), commitment computation, Fiat-Shamir tree
  serialization, and `extract_proof_leaves` (multi-sig hint extraction).
- `src/schnorr.rs` — secp256k1 Schnorr (ProveDlog) leaf primitive:
  `verify_schnorr`, `compute_dlog_commitment`, `build_prove_dlog_ergo_tree`.
- `src/dht.rs` — ProveDHTuple leaf primitive: `verify_dht`,
  `compute_dht_commitment`, `build_prove_dht_ergo_tree`.
- `src/cost_table.rs` — per-opcode `CostKind` rows mirroring
  sigmastate-interpreter (`opcode_cost`, `arith_cost`).
- `src/crypto_cost.rs` — `estimate_crypto_cost`: AOT crypto cost charged once
  per reduced proposition before proof verification.
- `src/avl.rs` — `AvlVerifier`, the sole dependency boundary onto
  `ergo_avltree_rust` (lookup/insert/update/insert_or_update/remove + digest).
  Wraps every operation (including construction) in `catch_unwind` to match
  Scala's fail-closed `Try` behaviour: a malformed proof that would cause
  `ergo_avltree_rust` to panic instead poisons the verifier (`None`) and
  returns an error. Exports `in_expected_avl_panic` so the node's global
  panic hook can suppress the log for a contained AVL panic.
- `src/cost_trace.rs` (feature `cost-trace`) — debug-only per-step cost recorder
  for diagnosing cost divergence against the Scala oracle.

## Key types, traits & functions
- `verify_spending_proof_with_context` (fn) — primary validation entry point;
  trivial-reduce → evaluator fallback → block-cost snap → crypto cost → proof
  verify — `src/reduce.rs:149`
- `verify_spending_proof_with_context_and_cost` (fn) — same, threading an
  external `CostAccumulator` — `src/reduce.rs:167`
- `trivial_reduce` (fn) — P2PK/SigmaProp constant fast path — `src/reduce.rs:91`
- `VerifySpendingError` / `ReductionError` (enums) — phase-tagged failures so
  callers map each to the right consensus/mempool envelope —
  `src/reduce.rs:282`, `:61`
- `reduce_expr_with_cost` (fn) — the evaluator driver behind the fallback path —
  `src/evaluator/dispatch.rs:22`
- `eval_op` (fn) — the opcode jump table — `src/evaluator/dispatch.rs:449`
- `Value` (enum) — runtime evaluation value (typed coll carriers, `BigInt` vs
  distinct `UnsignedBigInt`, box refs, closures) — `src/evaluator/types.rs:375`
- `ReductionContext<'a>` (struct) — transaction-scoped context (HEIGHT, SELF,
  INPUTS/OUTPUTS/dataInputs, extension vars, header window, UTXO root,
  `activated_script_version`); `minimal`/`minimal_v6` constructors,
  `require_method_version` soft-fork gate — `src/evaluator/types.rs:201`
- `EvalBox` / `EvalHeader` (structs) — evaluator box and header projections;
  `EvalHeader::from_header` resolves v1/v2 PoW solution fields —
  `src/evaluator/types.rs:14`, `:80`
- `EvalError` (enum) — typed evaluation failures, incl. `JitCostOverflow`,
  `SoftForkNotActivated`, `NotExecutable`/`DeprecatedOpcode`/`InternalOpcode` —
  `src/evaluator/types.rs:574`
- `verify_sigma_proof` (fn) — top-level Fiat-Shamir proof check over a
  `SigmaBoolean` — `src/verify.rs:253`
- `SigmaVerifyError` / `ProofLeaf` / `extract_proof_leaves` —
  `src/verify.rs:220`, `:17`, `:40`
- `verify_schnorr`, `compute_dlog_commitment`, `build_prove_dlog_ergo_tree` —
  `src/schnorr.rs:43`, `:122`, `:136`
- `verify_dht`, `build_prove_dht_ergo_tree` — `src/dht.rs:49`, `:152`
  (the `compute_dht_commitment` used by `verify::compute_commitments` is
  `pub(crate)`)
- `estimate_crypto_cost` (fn) — `src/crypto_cost.rs:27`
- `opcode_cost` (fn) — `src/cost_table.rs:28`
- `AvlVerifier` (struct) — AVL+ proof boundary — `src/avl.rs:82`
- `in_expected_avl_panic` (fn) — thread-local sentinel read by the global
  panic hook to suppress log noise from contained AVL panics — `src/avl.rs:31`
- `blake2b256` (fn) + `SOUNDNESS_BYTES`/`GROUP_SIZE`/`SCHNORR_PROOF_SIZE`
  (consts) — `src/lib.rs:78`, `:66`

## Invariants & contracts
- **Trivial-reduction parity.** `trivial_reduce` only matches Scala's
  `SigmaPropConstant(p)` fast path; every other body shape (incl. v3/6.0
  top-level `SBoolean` roots) MUST fall through to the full evaluator, which
  owns the implicit `Bool → SigmaProp` coercion and its cost. Structurally
  malformed trees (OOB placeholder index, `SSigmaProp`-tagged non-SigmaProp
  value) hard-reject (`src/reduce.rs:61-114`, `:149-163`).
- **Cost-model parity (consensus).** Per-opcode JitCost mirrors
  sigmastate-interpreter; the trivial path charges `Eval_SigmaPropConstant=50`,
  and eval cost is truncated to the block boundary (`snap_to_block_boundary`)
  before crypto cost is added — matching Scala's per-input `toBlockCost`
  truncation (`src/reduce.rs:167-282`, `src/cost_table.rs`, `src/crypto_cost.rs`).
- **JitCost overflow / limit fidelity.** JitCost arithmetic overflow past the
  Scala `Int.MaxValue` bound is preserved as a distinct typed error
  (`EvalError::JitCostOverflow`) rather than collapsed into a generic script
  error, so the validation boundary can route it correctly
  (`src/evaluator/types.rs:574-680`).
- **Fiat-Shamir / proof-tree byte parity.** Challenge size is 192 bits (24
  bytes); OR distributes challenges with the last child = XOR of the rest;
  Cthreshold uses a `gf2_192` polynomial; the Fiat-Shamir leaf/internal-node
  byte layout (`leaf=1`/`internal=0`, AND=0/OR=1/THRESHOLD=2 tags, big-endian
  i16 lengths) must match Scala `FiatShamirTree.toBytes` exactly
  (`src/verify.rs:289-573`, `src/schnorr.rs:96-117`).
- **Curve / scalar handling.** SEC1 `0x00` prefix decodes to the identity
  point; the 24-byte challenge is interpreted as an unsigned big-endian scalar
  (always `< q` by construction); the response `z` is read with
  zero-left-padding to match Scala's `getBytesUnsafe` (`src/schnorr.rs:163-220`,
  `src/verify.rs:584-594`).
- **Soft-fork activation gate.** EIP-50 / Sigma-6.0 v6 MethodCalls require
  `activated_script_version >= 3` (block-header version 4); a below-threshold
  invocation is rejected with `EvalError::SoftForkNotActivated`, mirroring
  Scala's `MethodCall.evaluate` methodVersion check
  (`src/evaluator/types.rs:340-355`, `src/evaluator/opcodes/method_call.rs:48-50`).
- **Type-strict value equality.** `Value`'s `PartialEq` is type-strict like
  Scala's `DataValueComparer` (notably `UnsignedBigInt` is a distinct carrier
  from `BigInt`, and the only sanctioned cross-representation arm is
  `Tokens ↔ CollGeneric` of `(Coll[Byte], Long)` pairs)
  (`src/evaluator/types.rs:485-572`).
- **Depth bound.** Recursion is capped at `MAX_EVAL_DEPTH = 110`
  (`DepthLimitExceeded`) — `src/evaluator/dispatch.rs:430-432`,
  `src/evaluator/types.rs:693`.
- **AVL dependency containment.** All `ergo_avltree_rust` imports are confined
  to `src/avl.rs`; the rest of the evaluator never touches the underlying crate.
  All operations (construction and per-op) are wrapped in `catch_unwind` so a
  malformed-proof panic from the underlying crate is caught, the verifier is
  poisoned, and subsequent accesses including `digest()` return errors — matching
  Scala's fail-closed `Try` semantics (`src/avl.rs:1-82`).
- **Crypto boundary.** Sigma-proof crypto (Schnorr/DHT/AVL) rides directly on
  `k256`/`sha2`/`gf2_192` for performance; `ergo-crypto` is used only for the
  `SHeader.checkPow` PoW-solution verification, per `src/lib.rs:1-10`.
