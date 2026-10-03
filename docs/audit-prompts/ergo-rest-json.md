# `ergo-rest-json` reference-quality audit prompt

Audit `ergo-rest-json` as the shared JSON-to-consensus-bytes and Scala REST DTO
boundary. Read `docs/audit-prompts/COMMON.md` first, then `CONTRIBUTING.md`,
`docs/compatibility.md`, and `docs/codemap/ergo-rest-json.md`. Follow the common
review-only workflow, complete file ledger, report format, and evidence rules.
Verify current code and pinned primary reference behavior; names such as
`Preserve` and prose descriptions are not proof of byte fidelity.

## Mission and trust boundaries

Trace untrusted REST JSON → serde DTO → parsed consensus value → retained or
canonicalized byte representation → transaction/header/section IDs → API/node/
indexer/replay consumers. A logically equal AST with different committed bytes
can invalidate signatures, Merkle roots, section IDs, and archival ingestion.
Review encoding and decoding separately, and distinguish parsing success from
consensus acceptance, proof verification, and semantic transaction validation.

This crate supplies wire shapes and byte reconstruction. The transport owns
HTTP body limits; downstream validation owns consensus rules. Identify any
callable entry point whose allocation or numeric limits rely on those external
owners, including non-HTTP callers that bypass the transport.

## Source landmarks and associated material

- Read all of `ergo-rest-json/Cargo.toml`, `src/lib.rs`, `src/types.rs`,
  `src/decode.rs`, `src/mining.rs`, and inline tests.
- Begin the decoder review with `DecodeMode`, all default entry points and all
  `_with_mode` counterparts, `build_transaction_from_input`, and `DecodeError`.
- Trace context extensions, registers, ErgoTree, inputs/outputs, header JSON,
  block transactions, extension sections, AD proofs, and full-block decoders.
- Read every module wired by `tests/it/main.rs`: mode routing, full-block decode,
  header roundtrip, captured header oracle, and NiPoPoW JSON fixtures.
- Resolve fixture paths under `test-vectors/mainnet/`, `test-vectors/testnet/`,
  and NiPoPoW fixtures; verify hashes/provenance and provisioning documents.
- Follow consumers in `ergo-api/src/compat/`, `ergo-node/src/api_bridge.rs`,
  the node wallet bridge, `ergo-difftest/src/bin/replay.rs`, and mining DTO users.
- Compare dependent codecs in `ergo-ser`: transaction/input/context extension,
  register/constant/ErgoTree, header/Autolykos, extension, and block sections.

## Contract review questions

1. Inventory every DTO field, serde rename/default/optional/ignored field, and
   encode/decode type. Check absent versus null versus empty, additional fields,
   duplicate JSON keys, derived IDs/sizes accepted on input, and old/new-version
   tolerance against the intended Scala interface.
2. Verify signedness and range for values, token amounts, heights, indexes,
   header version, `nBits`, timestamps, and arbitrary-precision numbers. Reject
   overflow or unintended float/exponent/string conversion; avoid truncating
   casts or browser-safe-number assumptions for consensus quantities.
3. Draw a mode matrix for each nested field: parse checks, exact bytes retained,
   bytes canonicalized, trailing-byte checks, soft-fork behavior, and rejection
   reason. Follow the mode through standalone and block-section paths without
   accidentally calling a submit-default helper from a mode-aware path.
4. Verify context-extension key parsing, signed-byte key interpretation, duplicate
   aliases, count overflow, insertion order for Scala small maps, and HAMT order
   above the small-map threshold. Test both orders and insertion permutations.
5. Inspect actual context-extension canonicalization in both modes. Reconcile
   `SpendingProof::new` and `try_from_raw_parts` with Scala `bytesToSign`; prove
   which forms intentionally canonicalize and which `EvaluatedValue` forms
   preserve node provenance. Do not copy stale passthrough claims from codemaps.
6. Check dense R4–R9 registers, malformed/gapped/out-of-range names, duplicate
   aliases, serialized constant framing, typed tuple versus CreateTuple forms,
   and strict EOF. Verify each register mode against real chain witnesses.
7. Audit ErgoTree raw-byte retention independently of writer roundtripping.
   Check supported versions, size flags, unparsed/soft-fork wrappers, placeholders,
   constant segregation, noncanonical forms, trailing data, and intentional
   submit-only rejection policies. Justify each restriction externally.
8. Verify that input proofs/extensions, output scripts/registers, and token order
   produce the expected transaction bytes, signing message, transaction ID, and
   output box IDs. A DTO roundtrip alone does not establish these contracts.
9. Check fixed-width hex fields for exact length, case policy, malformed input,
   leading prefixes, and field-specific diagnostic paths. Distinguish syntax
   checks from point-validity, digest, proof, or relationship validation.
10. Review header reconstruction for v1 versus v2+ PoW layouts, signed BigInt
    `d` bytes and leading sign byte, optional/artifact fields, stateRoot length,
    votes width, unparsed fields, height/version boundaries, and real byte length.
11. Check block-transaction order and header-version-dependent framing. Verify
    extension field ordering, key/value lengths, duplicate keys, and section-ID
    derivation; review absent/present AD proofs for full versus digest modes.
12. Verify full-block section `headerId` checks bind to the computed header ID.
    Document which roots/proofs/section IDs remain downstream validation duties;
    do not infer full block validity from this relationship check alone.
13. Verify `deserialize` versus `non_canonical` classification and contextual
    field paths across nested arrays. Ensure diagnostics are bounded and do not
    expose trusted-state internals or mislabel a writer/harness failure as bad JSON.
14. Review maximum counts, recursion, hex expansion, `Vec::with_capacity`, huge
    decimal integers, and byte-vector copies. Establish callable entry-point
    limits and failure behavior rather than relying solely on API body caps.

## Mining and read-side wire evidence

15. Verify Scala names/types for candidate and solution DTOs, especially bare JSON
    integer `b`, accepted inbound decimal strings, signed `d`, omitted optional
    `h`/`proof`, pubkey/nonce encodings, and legacy defaults for pool extensions.
16. Check candidate metrics precision and units: fees as exact nanoERG strings,
    transaction counts, serialized section size, validation cost, and protocol
    maxima. Their values must correspond to the frozen served template; ensure
    a serialization layer does not imply independent validation of observations.
17. Inspect header/full-block/transaction/box/NiPoPoW read DTOs for field order,
    identifier encoding, camelCase spelling, option semantics, and discrepancies
    between captured Scala metadata and authoritative canonical bytes.

## Required adversarial and independent checks

- Use real v1 headers with signed-`d` boundaries and v2+ headers; compare computed
  IDs, exact header bytes, JSON shapes, and independent PoW checks where supplied.
- Use a transaction with tuple registers, nonconstant evaluated extension values,
  and noncanonical boolean encodings. Assert exact signing/ID bytes separately
  from each helper's raw bytes; exercise standalone and full-block mode routing.
- Cover extension map sizes 0, 1, 4, 5, and over-limit; test equivalent key aliases,
  negative/high-bit keys, trailing bytes, malformed hex, and insertion permutations.
- Cover register gaps and R3/R10, oversized/signed numbers, mismatched section
  headers, absent AD proofs, invalid field lengths, and unsupported tree versions.
- Trace existing node `b4_*` byte-parity tests and full-block/root regressions.
  Identify cases pinned only to this implementation's own writer as evidence gaps.
- Check captured fixtures are immutable independent evidence with a clear
  extraction chain. Review tests, test comments, and maps against current mode
  semantics, including misleading historical descriptions.

## Scoped verification and completion

Use the common checks plus `cargo test --locked -p ergo-rest-json`. Select related
`ergo-node`/`ergo-validation` integration tests only after resolving their target
and fixture requirements from manifests. Do not claim a network/oracle run that
was skipped or a semantic validation result from serialization-only tests.

Complete when every encoder/decoder and nested mode path has a contract/evidence
entry, every associated file has a ledger disposition, content-addressed seams
have been checked, and all preservation/canonicalization decisions and external
limits are explicit. Report source/comment/test/fixture defects separately and
leave unresolved parity questions visible in the common report.
