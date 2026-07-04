# ergo-rest-json

**Purpose:** The shared JSON ↔ canonical-wire-bytes layer for Scala-compatible Ergo REST. Hosts the JSON DTOs that mirror the Scala node's encoders (`Header.jsonEncoder`, `BlockTransactions.jsonEncoder`, `Extension.jsonEncoder`, `JsonCodecs`, etc.), the `/mining/*` wire DTOs, and the canonicalizing *decoders* that turn parsed JSON back into the exact wire bytes the indexer / validator / persistence layer expect. The decoders are the harder half: they must reproduce Scala's canonical bytes byte-for-byte so content-addressed IDs (tx_id, box_id, section_id) verify.

**Depends on (workspace):** ergo-primitives, ergo-ser
**Depended on by:** (see codemap index) — ergo-api, ergo-node, ergo-difftest, ergo-validation (tests only)
**Approx LOC:** ~1441 (src, incl. tests)

## Start here
- `src/lib.rs` — module tree + the flat re-export surface. Note the re-exports cover `decode::*` and `types::*` only; the `mining` DTOs are reached via the `mining` module path (`ergo_rest_json::mining::WorkMessageJson`).
- `DecodeMode` (enum) — `src/decode.rs:444` — the central contract: `Submit` (wallet→node, strict + canonicalize) vs `Preserve` (on-chain bytes, verbatim). Every decoder branches on this; read it before any decoder.
- `decode_scala_transaction` / `decode_scala_full_block` — `src/decode.rs:49,833` — the two top-level entry points (JSON tx-submit, and `POST /blocks` full-block ingest).
- `ScalaFullBlock` / `ScalaHeader` — `src/types.rs:23,42` — the read-side DTO shapes; field order mirrors Scala emission so captured-fixture diffs read cleanly.
- `WorkMessageJson` — `src/mining.rs:37` — the `/mining/candidate` wire shape; Scala `WorkMessage` fields plus this node's `template_seq`/`clean_jobs` pool extensions.

## Modules
- `src/lib.rs` — crate root: declares the 3 modules and re-exports `decode::*` + `types::*` at the crate top level.
- `src/types.rs` — the Scala-compat JSON DTOs (read-side `ScalaFullBlock`/`ScalaHeader`/`ScalaTransaction`/… and submit-side `ScalaTransactionInput`/`ScalaOutputInput`). Pure serde shapes; no bytes logic.
- `src/decode.rs` — the canonicalizing decoders: JSON DTO → canonical wire `Vec<u8>` via `ergo-ser` readers/writers. Owns `DecodeMode`, `DecodeError`, the per-section decoders, and the soft-fork/non-canonical reject policy.
- `src/mining.rs` — `/mining/*` JSON DTOs (`WorkMessageJson`, `AutolykosSolutionJson`, `RewardAddressResponse`, `RewardPublicKeyResponse`) plus decimal-BigInt serde helpers. Lives here (not `ergo-mining`) so `ergo-api` can mount `/mining/*` without the storage/sync/mempool transitives.

## Key types, traits & functions
- `DecodeMode` (enum: `Submit` | `Preserve`) — strictness/canonicalization switch threaded through every decoder — `src/decode.rs:444`
- `DecodeError` (type = `(&'static str, String)`) — reason+detail tuple; reason is `DESERIALIZE` (`"deserialize"`) or `NON_CANONICAL` (`"non_canonical"`) — `src/decode.rs:35,36,47`
- `decode_scala_transaction(_with_mode)` (fn) — `ScalaTransactionInput` → canonical tx wire bytes — `src/decode.rs:49,56`
- `build_transaction_from_input` (fn, private) — single source of truth for the input/data-input/output loops, shared by the standalone-tx and block-section paths so mode-propagation can't drift — `src/decode.rs:76`
- `decode_input_with_mode` (fn) — `Submit` re-serializes the spending-proof context-extension (canonicalizes); `Preserve` keeps `extension_bytes` verbatim via `SpendingProof::from_trusted_raw_parts` — `src/decode.rs:131`
- `decode_context_extension_with_mode` (fn) — decimal-keyed JSON map → `ContextExtension`; `IndexMap` order preserved for ≤4 entries (Scala `Map1`-`Map4` insertion order), re-sorted by Scala-HAMT key for ≥5 — `src/decode.rs:244`
- `decode_registers_with_mode` (fn) — `additionalRegisters` map → `AdditionalRegisters` + canonical bytes; rejects gaps and out-of-range register names (R4..R9); `Preserve` returns input hex verbatim — `src/decode.rs:359`
- `decode_ergo_tree_canonicalize_with_mode` (fn) — ergoTree hex → `(ErgoTree, bytes)`; ALWAYS returns the input bytes (writer is lossy for some opcodes); `Submit` rejects soft-fork versions + non-roundtripping placeholder patterns — `src/decode.rs:472`
- `decode_scala_header` (fn) — `ScalaHeader` → `(wire bytes, ModifierId)`; maps stateRoot(33B), votes(3B), nBits(u64→u32 with overflow reject), and v1/v2 PoW solution — `src/decode.rs:565`
- `decode_scala_full_block` (fn) → `DecodedFullBlock` — drives `POST /blocks`; cross-checks each section's `headerId` against the computed header id before decoding — `src/decode.rs:833`
- `DecodedFullBlock` (struct) — header bytes + id + per-section canonical bytes (`ad_proofs_bytes` optional for digest-mode blocks) — `src/decode.rs:807`
- `decode_block_transactions_with_mode` / `decode_extension` / `decode_ad_proofs` (fns) — per-section decoders to canonical wire — `src/decode.rs:724,773,899`
- `ScalaFullBlock`, `ScalaHeader`, `ScalaPowSolutions`, `ScalaBlockTransactions`, `ScalaTransaction`, `ScalaInput`, `ScalaSpendingProof`, `ScalaOutput`, `ScalaExtension`, `ScalaAdProofs`, `ScalaBlockSection` (read-side DTOs) — `src/types.rs:23,42,79,89,103,113,121,150,218,227,243`
- `ScalaTransactionInput`, `ScalaOutputInput` (submit-side DTOs) — read only the consensus-bearing fields; derived `id`/`size`/`boxId` are accepted-and-ignored — `src/types.rs:188,204`
- `WorkMessageJson` / `AutolykosSolutionJson` / `RewardAddressResponse` / `RewardPublicKeyResponse` (mining DTOs) — `src/mining.rs:37,91,118,126`

## Invariants & contracts
- **Byte-parity is the contract.** `Submit`-mode JSON must reconstruct canonical wire bytes byte-identical to what an honest wallet/Scala node would produce; `Preserve`-mode (on-chain bytes) must re-emit verbatim so tx_id/box_id/section_id (all `blake2b256` over wire bytes) verify. Anchored by the `b4_*` oracle in `ergo-node/src/api_bridge.rs::tests`.
- **ergoTree bytes are passed through, never re-emitted.** `decode_ergo_tree_canonicalize_*` always returns the input bytes — the `ergo-ser` writer is lossy for some opcode encodings (e.g. `1000d1ed8501` → `1000d1ed01010100` at block 303967, which caused a tx_id divergence / IBD wedge). Re-serialization is used only as a `Submit`-mode roundtrip check.
- **Context-extension wire ordering matches Scala's `Map[Byte,T]`.** ≤4 entries keep JSON/wallet insertion order (`Map1`-`Map4`); ≥5 entries are sorted by `ergo_ser::scala_hamt` depth-first key order. Backed by `IndexMap` (not `BTreeMap`) on `ScalaSpendingProof.extension` so wallet emit-order survives deserialization and the signature still verifies.
- **Register / context-extension `Preserve` passthrough.** Re-serializing would normalize legitimate `Constant[STuple]` forms into the writer's `CreateTuple` form (Scala accepts both; AST-driven, not type-driven), breaking byte fidelity — so `Preserve` keeps original hex verbatim while still running gap/trailing-byte/unknown-register validation.
- **Register density + range.** `additionalRegisters` must be densely packed from R4 upward with no gaps; any key outside R4..R9 is rejected (mirrors Scala `registersDecoder`).
- **Soft-fork reject policy is `Submit`-only.** `version > MAX_SUPPORTED_TREE_VERSION` (3) is rejected on submission with `NON_CANONICAL`; `Preserve` accepts it (already validated on chain).
- **Bounded numeric decodes.** `nBits` (u64 JSON) rejects values `> u32::MAX` rather than truncating; context-extension entry count rejects `> u8::MAX`; fixed-length fields (digest32, stateRoot 33B, votes 3B, PoW pk/w 33B, nonce 8B) length-check before copy.
- **Full-block boundary check.** `decode_scala_full_block` rejects a body whose blockTransactions/extension/adProofs `headerId` does not match the computed header id (case-insensitive hex compare) before any section reaches the apply path.
- **PoW solution layout is version-keyed.** v1 headers decode `AutolykosSolution::V1{pk,w,nonce,d}` with `d` as a signed-two's-complement BigInt (mirrors `BigInt::to_signed_bytes_be`, preserving the leading `0x00` disambiguator); everything else decodes `V2{pk,nonce}` and ignores the Scala `w`/`d` artifacts.
- **Mining DTO Scala parity.** `WorkMessageJson` keeps Scala's `msg`/`b`/`h`/`pk`/`proof` names/types/encoding (`b` is decimal-BigInt string; `proof` omitted when `None`); the node-only `template_seq`/`clean_jobs` are appended and `#[serde(default)]` so legacy/Scala candidates still deserialize.
