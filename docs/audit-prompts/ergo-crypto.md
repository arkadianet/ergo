# Audit prompt: ergo-crypto

Audit `ergo-crypto` as the PoW, difficulty, Merkle and curve-helper layer of a
prospective reference-quality Rust Ergo node.

First read `docs/audit-prompts/COMMON.md` and follow its full methodology,
review-only default, evidence standards, reporting format, and coverage ledger.
Then read `CONTRIBUTING.md`, `docs/compatibility.md`, the crate manifest/root and
`docs/codemap/ergo-crypto.md`. Commands and repository-prefixed paths are relative
to the repository root; abbreviated source paths are relative to this crate.
Verify map claims. Inventory every file, inline/integration test, comment, fixture,
source include, generator and applicable workspace setting; cover modules the
map omits, including `src/group_element.rs`.

## Mission and boundaries

Header solution validity, chain-context difficulty validity and section
commitments are different checks. Trace the full caller contract rather than
calling a passing PoW equation a valid header. This crate also supplies helpers
for mining, interpreter `powHit`/`checkPow`, API inclusion proofs and compiler
point rendering. Invalid caller-built parameters can have different reachability
from wire-decoded inputs; establish the path before assigning impact.

Keep protocol algorithms distinct from vetted cryptographic primitives. Review
composition, byte layout, integer semantics and dependency use with independent
evidence. An intuitive mathematical improvement can change accepted blocks.

## Source landmarks

- `ergo-crypto/src/pow.rs`: `verify_pow_solution`, `verify_header_difficulty`, errors.
- `ergo-crypto/src/autolykos/common.rs`: constants, `calc_n`, index generation,
  hashing and integer/byte conversions.
- `ergo-crypto/src/autolykos/v1.rs`: `hash_mod_q`, group order and v1 EC equation.
- `ergo-crypto/src/autolykos/v2.rs`: general/header-specialized hit and target check.
- `ergo-crypto/src/difficulty.rs`: target conversion, epoch selection, ancestor
  selection, interpolation, EIP-37, required difficulty, mining/verify adapters.
- `ergo-crypto/src/merkle/mod.rs`: roots, leaf digest, reduction, single/batch proofs.
- `ergo-crypto/src/group_element.rs`: compile-time point validation and formatting.
- `ergo-crypto/tests/it/`: PoW, difficulty, root and proofFor oracle suites.
- Mainnet curated header fixtures, `test-vectors/ergo-crypto/batch-merkle/`,
  their provisioning documents and referenced Scala extraction scripts.

## PoW and curve audit

1. Verify header-without-PoW serialization/hashing against captured preimages.
   Inspect zero difficulty/target, invalid compact values and header writer
   rejection. Version, solution variant, height and network schedule are separate
   axes; determine the serializer/caller guarantees before adding a check.
2. Preserve the observed reference behavior where equation checking dispatches
   by encoded variant rather than inventing a version-by-height rejection.
   Confirm programmatic headers cannot violate assumptions unnoticed.
3. Verify all Autolykos constants and M-table byte order/length independently.
   Check N at growth start/each boundary/cap, height extremes and version one.
   The Scala recurrence `n / 100 * 105` differs from `n * 105 / 100`.
4. Check seed layout, overlapping index windows, endianness, modulo N and general
   `k` behavior. Trace caller enforcement for `2 <= k <= 32` and nonzero N;
   public helpers/debug assertions alone do not prove malicious values blocked.
5. For v1, verify rejection-sampling hash, unsigned scalar construction, group
   order, identity/off-curve rules, d range, target inequality and the precise
   EC equation. Confirm malformed point/scalar input returns the intended result.
6. For v2, verify every hash input and slice, dropped first hash byte, summation,
   fixed-width padding, height representation and strict `hit < target`.
   Check the arbitrary-byte general `powHit` API separately from fixed headers.
7. Review point helpers used by the compiler: compile-time identity policy,
   invalid SEC1 prefixes, off-curve input, padded affine coordinates versus JVM
   unpadded rendering and leading-zero coordinates. Do not export that policy
   accidentally into runtime Sigma identity handling.
8. Check dependency scalar/point conversions, field/order distinctions and
   reachable panic/error branches. Timing requirements follow actual secret
   handling; public PoW verification alone is not evidence of a secret leak.

## Difficulty audit

Build a branch table for mainnet, testnet, devnet and caller-built params:
genesis/early heights, ordinary heights, epoch recalculation, v2 transition and
pre/post EIP-37. Trace parent versus child regime and required ancestor ordering.

- Compare `next_n_bits` and verification through their common core, then use
  independent expected values to establish correctness rather than self-parity.
- Verify compact-bits sign/exponent/mantissa normalization with `ergo-ser`, target
  quotient, zero/negative/impossible difficulties and output precision loss.
- Check least-squares signed BigInt arithmetic, precision scaling, division
  toward zero, timestamp deltas, equal/reversed timestamps, regression overflow
  assumptions and conversion to unsigned required difficulty.
- Verify EIP-37 predictive/classic averaging and both clamp stages in exact
  reference order. Check ±50% boundaries and rounding at small difficulties.
- Verify the fixed activation-difficulty special case and its parent-height
  conditions, including networks with no v1-to-v2 transition.
- Verify empty/short/misordered/duplicate/unrelated epoch windows and missing
  context: typed failure versus silently derived difficulty. Inspect callers
  establishing linkage instead of assuming a slice of headers is authenticated.
- Check arithmetic and boundary behavior at height zero/u32::MAX and timestamp
  extremes, zero epoch lengths and mismatched optional EIP-37 fields. Classify
  unreachable invalid config separately from network-input defects.

## Merkle audit

Verify leaf/internal prefixes, empty tree, singleton's internal wrapping, odd
tails paired with an empty byte array, intermediate levels and exact roots.
Empty bytes, a zero digest and a prefixed empty leaf must remain distinct.

Trace transactionsRoot version behavior, tx-ID ordering, witness construction
and 31-byte witness IDs, and extension leaf layout/order. Verify caller-supplied
IDs against their actual source; a correct tree over attacker-selected hashes
does not establish membership of a recomputed transaction.

Audit single-proof construction/verification, side interpretation, leaf preimage,
empty siblings, malformed side values, out-of-range indices and altered root.
Audit batch sort/dedup semantics, duplicate leaf indices, proof order, complete
proof consumption and marker conversion into `ergo-ser`/`ergo-validation`.
Review proofFor wire/JSON parity through the actual REST consumer and oracle.

Trace memory/time growth, repeated hashing and large sibling/path counts. Any
optimization recommendation must preserve the independently verified singleton
and odd-node behavior and identify measured benefit or a demonstrated risk.

## Required test and evidence review

- Distinguish default curated witnesses from ignored bulk-corpus tests and
  gitignored externally provisioned ranges. Record checked/skipped counts and
  coverage around actual retarget boundaries; accepting ten early headers is
  not retarget coverage.
- Require positive and independently judged negative solution/target mutations,
  exact boundary hits, difficult integer rounding cases, both PoW versions and
  all relevant network schedules. Do not call a Rust-mutated negative an oracle
  verdict without checking the pinned reference.
- Verify Scala-derived Merkle roots/proofs for 0/1/2/odd/power-of-two leaves,
  adjacent/sparse/all indices, unsorted duplicates and tampering. Same-library
  root/proof round trips establish consistency only.
- Inventory provenance and artifact versions for every fixture and generator;
  pin SEC/JVM math authority separately from chain acceptance witnesses.

```bash
cargo test --locked -p ergo-crypto
cargo clippy --locked -p ergo-crypto --all-targets --all-features -- -D warnings
cargo doc --locked -p ergo-crypto --no-deps
```

List ignored tests and prerequisites before selecting a corpus replay. Report
exact filters, fixtures and outcomes under COMMON; missing context is not a pass.

## Exit criteria

Deliver the COMMON report and coverage ledger with PoW/difficulty branch tables,
commitment/proof contracts and caller-precondition ownership. Explain the tested
eras/networks and unavailable oracle cases. Separate proven consensus divergence,
API misuse risk, unverified claims and maintainability gaps without changing any
verified arithmetic or commitment convention as an audit-side cleanup.
