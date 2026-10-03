# Audit prompt: ergo-primitives

Audit `ergo-primitives` as the foundational byte, identity, reader-state, and
cost layer of a prospective reference-quality Rust Ergo node.

First read `docs/audit-prompts/COMMON.md` and follow its full methodology,
review-only default, evidence standards, reporting format, and coverage ledger.
Then read `CONTRIBUTING.md`, `docs/compatibility.md`, this crate's `Cargo.toml`,
`ergo-primitives/src/lib.rs`, and `docs/codemap/ergo-primitives.md`. Commands and
repository-prefixed paths are relative to the repository root; abbreviated source
paths are relative to this crate. Treat codemap statements and lines as claims.
Inventory and inspect every crate file and all linked fixtures, source includes,
scripts, tests, comments, documentation, and applicable workspace configuration;
the landmarks below do not limit scope.

## Mission and boundaries

This crate has no workspace dependencies and supplies primitives used throughout
the node. A tiny discrepancy can change transaction/header IDs, parser verdicts,
or the amount of work a block may execute. Its byte wrapper is not a proof of
cryptographic validity. Review public APIs as downstream code actually calls them,
including invalid caller-built values and parsers reading adversarial wire bytes.

Separate canonical encoding, permissive Scala decoding, caller-enforced
canonicality, and trusted stored-data decoding. Preserve externally verified JVM
quirks rather than making an encoding stricter because it looks cleaner.

## Source landmarks

- `ergo-primitives/src/digest.rs`: `Digest32`, `ADDigest`, `ModifierId`, `blake2b256`.
- `ergo-primitives/src/group_element.rs`: `GroupElement`, `IDENTITY_ENCODING`,
  `canonical_encoding`, and `read_group_element`.
- `ergo-primitives/src/vlq.rs` and `zigzag.rs`: unsigned VLQ and signed conversion.
- `ergo-primitives/src/reader.rs`: `VlqReader`, `ReadError`,
  `UnresolvedMethodCheckpoint`, all consuming reads and every parser sideband.
- `ergo-primitives/src/writer.rs`: writer bounds, buffer ownership and reuse.
- `ergo-primitives/src/cost.rs`: `JitCost`, `CostKind`, `CostAccumulator` and errors.
- `test-vectors/primitives/blake2b256_header_oracle.json` and the fixtures under
  `test-vectors/scala/` cited by `cost.rs`; trace their actual provenance.
- `scripts/jvm_serde_oracle/ReviewRegressionOracle.scala` and
  `scripts/jvm_cost_constants_extractor/`: independent boundary evidence.

## Byte and identity audit

1. Verify Blake2b with a 256-bit output parameter, including empty input and
   multi-block input. Distinguish it from truncating a 512-bit hash. Trace all
   delegated hash helpers in callers and compare against independent vectors.
2. Verify exact digest widths, conversions, `AsRef`, equality, hashing, debug
   rendering, and sentinel meaning. `ADDigest` retains its trailing height byte;
   IDs and authenticated roots must not become accidentally interchangeable.
3. Inspect every VLQ termination and failure branch: overlong encodings, trailing
   bytes, 9/10/11-byte inputs, final payload bits and JVM shift truncation. The
   existing decoder permits some nonminimal encodings and drops high tenth-byte
   payload bits; compare actual Scala results before judging these choices.
4. Check unsigned narrowing independently for `get_u32_exact`, `get_u16`, and
   `get_uint_to_i32`. JVM truncation, signed range checks and exact conversions
   are different contracts. Document any intentional read/write asymmetry.
5. Verify zigzag bijections over the full signed ranges and i32-to-i64
   sign-extension before VLQ writing. Include the mainnet signed-register witness
   cited in `zigzag.rs`; canonical Protobuf encodings alone do not prove Scorex
   parity for the i32 sign-extension branch.
6. Check raw big-endian short APIs separately from VLQ shorts. Verify length
   prefix bounds, usize conversions and writer behavior after a failed caller
   precondition; trace whether runtime input can reach documented panic sites.
7. Verify group-element width, legal prefix handling, recording of original
   bytes, identity normalization for every `0x00`-leading encoding, and deferred
   curve validation. Preserve the difference between transport bytes and a
   validated point; inspect callers that construct wrappers directly.

## Reader-state audit

For each read, document success/failure cursor movement, bytes returned, checked
position arithmetic, and side effects. Check `remaining`, `peek_u8`, `set_position`,
`data_slice`, and attempted reads at/past EOF. Verify the documented two-phase
length-prefixed read behavior instead of assuming every failure rewinds.

Audit the complete reader-state lifecycle through nested callers in `ergo-ser`:

- Position limits check the reference's precise before-read boundary, including
  the equality case, a single overrun and a subsequent read.
- Shared nesting depth, `scala_level`, and leaked levels model distinct state.
  Check restoration on ordinary success/error and intentional leaks when an
  ErgoTree degrades; do not replace intentional JVM leaks with a generic reset.
- Group-element collection and unresolved-method checkpoints retain exactly the
  points reached by the reference parser, including failed/degraded inner trees.
- Constant-pool bounds and val-binding stores are scoped or retained according
  to the reference reader contract; inspect cross-tree visibility on one reader.
- Tree-header version, activated version, embeddable-version overrides, strict
  method resolution and `trusted` status cannot leak between unrelated parses.
- Header-span diagnostics cannot alter consumption, acceptance or sidebands.
  Public setters need honest preconditions and actual caller enforcement.

## Cost-model audit

Trace each construction and arithmetic path against the pinned JVM `JitCost`:
the i32 ceiling, multiplication by ten, truncation to block units, overflow
taxonomy, constant constructors, and use of the wider Rust backing type.

Check `CostKind::PerItem` at zero items, chunk sizes one and greater than one,
exact chunk edges and maximal item counts. Verify signed division toward zero,
checked multiplication/addition, and every caller's nonzero chunk-size proof.

Check equality with the limit, one unit over it, current state after a rejected
add, overflow state preservation, recording-only mode, and error propagation.
For `snap_to_block_boundary`, check a nonzero baseline, multiple inputs and
baselines above current cost; explain its precise rounding contract and reconcile
comments describing the accumulator as additive-only with this operation.

Trace downstream sigma/validation metering to show which units and baselines
callers supply. Revalidate numeric safety-margin comments against the active
parameter fixture they cite; old mainnet snapshots are not universal bounds.

## Required test and evidence review

- Account for every inline test and property generator. Identify which tests
  prove arithmetic consistency and which have independent Scala/chain authority.
- Build a boundary matrix for each integer width, malformed VLQ class, cursor
  recovery path, reader sideband scope and cost failure branch.
- Exercise nested/degraded reader state via real `ergo-ser` entry points, not
  only direct setter/getter tests. Include reused readers and early failures.
- Require independent expected hashes, wire bytes and Scala cost/verdicts for
  consensus claims. A writer followed by this reader cannot establish parity.
- Check that property shrinking and regression inputs preserve the observed
  failure class; include debug/release arithmetic when it affects a claim.

Suggested baseline commands, subject to COMMON's resource and reporting rules:

```bash
cargo test --locked -p ergo-primitives
cargo clippy --locked -p ergo-primitives --all-targets --all-features -- -D warnings
cargo doc --locked -p ergo-primitives --no-deps
```

## Exit criteria

Deliver the COMMON report and full file-coverage ledger, plus an explicit table
of primitive contracts, JVM quirks, sideband ownership and cost units. Every
high-impact conclusion must connect to a downstream reachable call and an
independent witness or a stated evidence gap. Report unjustified documentation,
test-oracle or API claims as their own quality findings. Do not declare this
leaf crate correct merely because all local round trips pass.
