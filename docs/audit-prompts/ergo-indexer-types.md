# `ergo-indexer-types` reference-quality audit prompt

Audit `ergo-indexer-types` as the public read contract joining the optional
extra-index writer, HTTP API, and operator status surfaces. Read
`docs/audit-prompts/COMMON.md` first, then `CONTRIBUTING.md`,
`docs/compatibility.md`, and `docs/codemap/ergo-indexer-types.md`. Follow the
common review-only workflow, complete file ledger, report format, and evidence
rules. This small crate still needs complete review of every item and comment.

## Mission and boundaries

Establish what each trait method and DTO actually promises about confirmed data,
ordering, absence, errors, paging, status, health, and identifier provenance.
The crate deliberately separates read contracts from redb/state implementation;
verify that consumers do not need hidden writer knowledge to use it correctly.
The API adds mempool overlays and derived fields. The writer persists different
wire records. Keep those authorities distinct when evaluating documentation.

Current code includes compatibility reads and fallible `try_*` adapters; review
both. An empty result, unavailable capability, missing row, corrupt storage,
syncing status, and intentionally incomplete repair are different states even
when an older compatibility method collapses them to the same value.

## Source landmarks and associated material

- Read `ergo-indexer-types/Cargo.toml` and all five source files in full:
  `src/lib.rs`, `query.rs`, `types.rs`, `status.rs`, `protocol_genesis.rs`.
- Include inline tests and default stub implementations in the inventory.
  There is no separate declared feature/test matrix to invent; verify metadata.
- Enumerate every re-export, ID alias, trait method, default body, DTO field,
  status variant, error implementation, and genesis constant.
- Follow `IndexerQuery` implementations in `ergo-indexer/src/handle.rs` and API
  test stubs, plus `ergo-api/src/blockchain.rs`, `ergo-api/src/blockchain/`,
  `ergo-api/src/v1/routes/`, `ergo-api/src/v1/pricing/`, and
  `ergo-api/src/v1/decode/` consumers as relevant.
- Compare persisted representations in `ergo-indexer/src/ser/`, `address.rs`,
  `token.rs`, `store/storage_rent.rs`, and `store/meta.rs`.
- Resolve `test-vectors/mainnet/genesis_boxes.json` and its provisioning evidence
  against `PROTOCOL_GENESIS_BOX_IDS_MAINNET`; inspect the state/node genesis seam.

## Trait contract review

1. Build a method-by-method table: key units/type, confirmed-only semantics,
   range inclusivity, sorting/default order, paging stage, return cardinality,
   absence/error behavior, status precondition, implementation, and callers.
2. Verify `Send + Sync + 'static` and object safety match actual lifetime and
   thread usage. Check documentation does not imply cheap coherent snapshots
   when separate calls may see distinct database transactions or reorg states.
3. Trace `indexed_height`, `status`, `is_caught_up`, and `health` independently.
   Confirm `CaughtUp` is a runtime observation, not persisted proof that future
   reads are canonical; identify check/read races that callers must handle.
4. Review each fallible adapter and `IndexerReadError`: no missing row is falsely
   made an error, no storage error becomes success where a caller needs failure,
   and default compatibility delegation is documented honestly.
5. Verify every production implementation overrides defaults where empty/zero or
   healthy-empty would conceal missing support, degraded repair, or real faults.
   Check status-gated API routes and ungated health/height routes separately.
6. Determine whether error messages can carry arbitrary storage detail into
   public responses. Check error chaining, stability expectations, redaction,
   and distinctions between operator diagnostics and pinned wire reason strings.
7. Verify page offset/limit widths, caller-enforced maximums, zero/large pages,
   total-versus-filtered counts, range boundaries, and deterministic ordering.
   Confirm the trait's unenforced limits are visible to non-HTTP consumers.
8. Audit capability placeholders and unused DTOs, including `IndexedBlockDto`:
   comments, route mounting, and implementations must agree about what exists.

## Record and DTO invariants

9. Verify box/global transaction index units and signedness. Box records retain
   nonnegative indexes; segment sign carries spent state elsewhere. Test index
   zero and the inherited segment filter behavior against primary authority.
10. Review the spend-field triple as a joint invariant: transaction ID, height,
    and proof are all absent or all present. Determine whether public construction
    permits invalid combinations and which owner validates them.
11. Verify mempool overlay discrimination uses inclusion-height semantics rather
    than a global-index shortcut; check genesis/index-zero cases explicitly.
12. Check transaction input/output numeric references, protocol-genesis sentinel
    values, inclusion height, block linkage, proofs, and retained canonical bytes
    against writer encoding and API enrichment.
13. Verify transient confirmations, addresses, timestamps, and block IDs are
    derived at the proper consumer with consistent snapshot/height semantics;
    they must not be accidentally represented as persisted facts.
14. Check ERG and token balances for signed range, duplicate token entries,
    negative values, deterministic first-touch token order, and scalar precision
    when mapped into JSON. Preserve externally observable reference quirks.
15. Review token emission `u64` storage → `i64` DTO projection, metadata defaults,
    decimals range, and malformed registers. A realistic-input assertion does
    not substitute for proving reachable range constraints from validated boxes.
16. Verify storage-rent DTO creation height, immutable global index, canonical
    byte length, value units, inclusive creation ranges, and maturity cutoff
    ownership; inclusion height and creation height must not be conflated.
17. Verify health fields distinguish pending repair, cursor phase, skipped rows,
    process-lifetime drift counter, and durable totals. Document reset/restart
    behavior and consistent-snapshot expectations.
18. Match each halt variant's serde spelling, `as_kebab_case`, human detail, error
    taxonomy mapping, API envelope, and metrics labels. The pinned identifiers
    must agree without making human prose an accidental stability contract.
19. Verify the closed protocol-genesis whitelist byte-for-byte and network scope.
    Unknown inputs must not qualify through malformed IDs, sentinel confusion,
    or a fallback that silently extends a mainnet-only exception.
20. Review aliases that share `Digest32`: assess real ID-mixup hazards at call
    sites, conversion boundaries, names, and tests before recommending newtypes.

## Required evidence and scoped verification

- Exercise all default fallible adapters and verify delegation, call counts,
  sorting/page forwarding, missing values, and production failure propagation.
- Compare status/health/height behavior for disabled, syncing, caught-up,
  boot-halted, runtime-halted, pending-repair, and completed-with-skips states.
- Trace index-zero, mempool-height-zero, partial spend triples, token signed
  boundary values, empty metadata, and creation-range inclusivity at real seams.
- Independently verify all three protocol-genesis IDs and every halt wire string;
  in-crate self-consistency tests alone do not establish reference parity.
- Use the common checks plus `cargo test --locked -p ergo-indexer-types`; inspect the
  corresponding writer query and API error tests for consumer contract evidence.

Complete when every public symbol/default/re-export and comment is reviewed,
every trait promise is mapped to implementations and callers, all absence/error/
status distinctions have evidence, and limitations are explicit in the common
report. Do not invent a requirement for an unused placeholder without identifying
its intended contract and consequence.
