# Audit prompt: ergo-ser

Audit every surface of `ergo-ser` as the consensus wire-format and typed-value
boundary of a prospective reference-quality Rust Ergo node.

First read `docs/audit-prompts/COMMON.md` and follow its full methodology,
review-only default, evidence standards, reporting format, and coverage ledger.
Then read `CONTRIBUTING.md`, `docs/compatibility.md`, the crate manifest and root,
and `docs/codemap/ergo-ser.md`. Commands and repository-prefixed paths are relative
to the repository root; abbreviated source paths are relative to this crate. Verify
codemap claims against current code, including modules moved into directories.
Inventory all files, tests, comments, source includes, linked fixtures, generator
scripts, regressions and applicable workspace configuration. The list below is
an entry map, never permission to skip unlisted files or feature-gated code.

## Mission and boundaries

Peer, API and stored bytes become structures used for hashing, signing,
validation, interpretation and indexing. Audit parse verdict, canonical output,
consumption and retained raw bytes as separate observables. Some accepted Scala
encodings normalize on write; some opaque trees retain bytes; some parsed shapes
cannot be written. A blanket input-byte round-trip rule would miss these cases.

The layer avoids curve arithmetic and stateful block rules, yet necessarily
implements serializer acceptance gates. Trace what later validation owns, what
the reader enforces, and what an already-parsed/trusted caller may bypass.

## Source landmarks

- `ergo-ser/src/header.rs`, `autolykos.rs`, `difficulty.rs`, `modifier_id.rs`.
- `ergo-ser/src/block_transactions.rs`, `extension.rs`, `ad_proofs.rs`.
- `ergo-ser/src/transaction.rs`, `input/`, `ergo_box/`, `token.rs`, `register.rs`.
- `ergo-ser/src/ergo_tree/`: header/body reading, gates, root/type inference,
  tree/template hashes, writing and tests.
- `ergo-ser/src/opcode/`: vocabulary, parsing, writing, traversal and tests.
- `ergo-ser/src/sigma_type/` and `sigma_value/`: all type/value carrier codecs.
- `ergo-ser/src/address.rs`, `jvm_utf8.rs`, `scala_hamt.rs`, `decode_stack.rs`.
- `ergo-ser/src/popow_header.rs`, `popow_proof.rs`, `batch_merkle_proof.rs`.
- `ergo-ser/tests/it/`, `proptest-regressions/autolykos.txt`, referenced
  `test-vectors/mainnet/`, `test-vectors/scala/` and `test-vectors/santa/` inputs.
- `scripts/jvm_serde_oracle/`, `scripts/santa_wire_oracle/`,
  `scripts/scala_hamt_oracle/` and `test-vectors/scripts/` extraction paths.

## Sections, transactions and boxes

1. Verify every header-version branch, including v1/v2 PoW layout, header bytes
   without PoW, reserved/unparsed bytes and writer bounds. Identify the identity
   basis after accepted-but-normalizing input; compare raw header ID, serialized
   ID and PoW preimage against pinned oracle captures.
2. Verify block-transactions version discrimination, count fields and per-block
   activated-version scope. Ensure transaction slices, sideband group elements,
   header spans and IDs remain aligned for every parsed transaction.
3. Verify extension key/value lengths, field ordering, AD-proof opacity and
   section modifier IDs. Wire caps and validation caps are separate contracts.
4. Check signed/unsigned/signing-preimage writers together: proof removal,
   context extension handling, collection bounds, output indices, tx IDs and
   distinct-token table first-occurrence order. Inspect unused/duplicate table
   entries, bad indices and normalization against the actual JVM verdict.
5. Trace standalone, accepted and transaction-indexed box readers separately.
   Check tree boundary discovery for sizeless trees, value/height/token fields,
   additional-register spans and full-box transaction ID/index sealing.
6. Audit parsed-versus-raw consistency for `ErgoBoxCandidate` and `SpendingProof`:
   ordinary constructors, checked raw constructors, unchecked trusted raw parts,
   accessors and every writer. Identify deliberate canonicalization and the
   exact raw form used for signing and box IDs; stale comments are in scope.
7. Check R4–R9 density, duplicates, gaps, unsupported value shapes and nested
   SBox/SHeader values. Token amounts use the reference's signed/unsigned
   conversion rules, including zero and values with the high bit set.
8. Verify Scala HAMT ordering transitions at four/five entries, byte-key signed
   hashing and collisions. Do not infer ordering from a deterministic Rust map.

## ErgoTree and typed-value audit

Construct an explicit matrix of header version, activated version, size flag,
segregation, reserved bits, root type, method registry and trusted status.
For each combination trace plain-tree, box-script, transaction, nested-value and
compiler self-check entry points; identify who supplies each version axis.

- Compare declared tree size with actual structural consumption, position-limit
  semantics, signed/wrapped sizes and following box fields. Determine which
  failures propagate and which become `UnparsedErgoTree` under Scala settings.
- Review every soft-fork wrap branch: preserved bytes, body/header gates,
  unresolved-method checkpoint, group-element truncation, levels left open by
  failed frames, and following trees on the same reader.
- Confirm shared depth accounting across expressions, SigmaBoolean, constants,
  registers, context extensions and nested SBox/SHeader trees. Type depth is a
  separate limit; iterative parse/write/traverse/equality/drop paths all matter.
- Check constant-placeholder bounds, val-definition/use visibility, method
  receiver and argument types, explicit type arguments and result-type inference.
  Compare gates and registry data with actual pinned Scala versions.
- Audit all opcode/payload cases for read/write symmetry, compact encodings,
  deprecated/internal forms and exhaustive child walking. Parsed support does
  not imply interpreter execution support.
- Check every type descriptor, embedded code and version gate; empty/one-element
  tuples, large arities, function/type-variable forms, options and nested colls.
- Verify SBigInt and SUnsignedBigInt signedness, 32-byte cap, padding and zero
  representation against independent accept/canonical-output fixtures.
- Check packed booleans, strings, JVM UTF-8 replacement boundaries, arrays,
  tuple/coll carrier distinctions, AVL flags/digest/key/value lengths and sigma
  conjecture arity/count/depth. Invalid SEC1 prefixes and identity normalization
  must preserve hard-reject versus deferred-curve-check behavior.
- Trace tree/template-hash semantics, opaque/degraded trees and constant
  substitution. Indexer hash helpers must not redefine consensus identity.

## Addresses, NiPoPoW and resource boundaries

Verify base58/checksum/network prefixes, P2PK/P2SH/P2S routing and proposition
preimages for short, malformed and wrong-network input. Determine precisely
whether point validation belongs here or to the caller for each public decoder.

Check PoPoW/NiPoPoW and batch-proof field order, fixed-width versus VLQ lengths,
empty-node markers, sides, duplicate/index ordering and EOF contracts. Trace
their conversion into `ergo-crypto` construction and `ergo-validation` verification.

Inspect every input-driven reservation, allocation, recursion and buffer copy.
Soft capacity caps must bound preallocation without changing valid acceptance.
Audit the `DECODE_THREAD_STACK_BYTES` integration in node/runtime/Rayon threads
and distinguish representative regression evidence from a universal stack proof.
Trusted readers must originate only from a justified persisted-data boundary.

## Required test and evidence review

- Build a per-surface matrix of oracle acceptance, rejection class, consumed
  bytes, canonical output and ID/signing preimage. Include truncation at every
  meaningful field boundary, trailing bytes, nonminimal VLQ and hostile counts.
- Use captured canonical-extension/group-element, decode-depth, method-type,
  root-type, SBigInt and SANTA cases as starting evidence; inventory every linked
  input and generator, not merely a few golden examples.
- Verify curated corpus counts, checked versus skipped records, feature gates,
  ignored diagnostics and regression seeds. Missing fixtures are evidence gaps.
- Inspect `ergo-difftest` generators and oracle adapters for these codecs. An
  encode/decode fixed point proves internal consistency, not Scala compatibility.
- Pin oracle artifact versions per fixture; several current JVM scripts use
  sigma-state 6.0.6 while older documentation cites 6.0.2. Explain mismatches
  instead of silently choosing the more convenient version.

```bash
cargo test --locked -p ergo-ser
cargo test --locked --no-run -p ergo-ser --features diagnostics
cargo clippy --locked -p ergo-ser --all-targets --all-features -- -D warnings
cargo doc --locked -p ergo-ser --no-deps
```

Run externally dependent diagnostics or differential campaigns only after
checking their fixture/tool prerequisites under COMMON; report exact scope.

## Exit criteria

Deliver the COMMON report, full coverage ledger, version/entry-point matrix and
an ownership table for raw bytes, canonical bytes, sidebands and identity hashes.
Every codec surface needs explicit test/oracle status. State separately any
proven parser divergence, unverified compatibility claim, resource-risk evidence,
or documentation/test-quality gap; do not silently change accepted wire forms.
