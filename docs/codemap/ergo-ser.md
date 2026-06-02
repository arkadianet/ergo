# ergo-ser

**Purpose:** The L1 wire-format layer. Converts Ergo consensus structures to/from their canonical byte form: headers, block-transactions, AD proofs, the miner-voting extension, transactions/inputs/boxes/tokens/registers, ErgoTree (with the opcode AST plus sigma type/value codecs), base58 addresses, Autolykos PoW solutions, `nBits` difficulty, block-section modifier IDs, and NiPoPoW proofs. It owns bytes↔structs only — no validation, no interpreter, no AVL+ state, no JSON.

**Depends on (workspace):** ergo-primitives
**Depended on by:** (see codemap index)
**Approx LOC:** ~10,500 src (excl. opcode tests; ~13,000 incl. all tests)

## Start here
- `src/lib.rs` — the module map and a precise "what is / is NOT here" boundary (lines 8-31).
- `src/header.rs` (`Header`, `read_header`/`write_header`/`serialize_header`) — the consensus header struct; the cleanest example of the read/write/id triad pattern every section follows.
- `src/transaction.rs` (`Transaction`, `bytes_to_sign`, `transaction_id`) — the transaction wire form and the signing-preimage / id derivation that the whole crate exists to get byte-exact.
- `src/ergo_tree.rs` + `src/opcode/` + `src/sigma_type.rs` + `src/sigma_value.rs` — the ErgoTree subsystem: tree header/constants/body, the opcode dispatch tables, and the typed type/value codecs both sides consume.
- `src/error.rs` (`WriteError`) — the only crate-defined error; reads come back as `ergo_primitives::ReadError`.

## Modules
- `src/header.rs` — `Header` struct + read/write/id; `write_header_without_pow` produces the PoW-message preimage. Gates `unparsed_bytes` and PoW-solution layout on `version`.
- `src/block_transactions.rs` — `BlockTransactions` (header_id + ordered txs); v1 vs v2+ wire forms differ by a leading version marker (`MAX_TRANSACTIONS_IN_BLOCK` doubles as the discriminator).
- `src/ad_proofs.rs` — `ADProofs` (header_id + opaque AVL+ proof bytes) for the block's authenticated-state section.
- `src/extension.rs` — `Extension` / `ExtensionField`: the block's 2-byte-keyed key-value bag (miner votes, params, NiPoPoW interlinks). Value length is a single unsigned byte (Scala parity).
- `src/transaction.rs` — `Transaction` / `UnsignedTransaction`; signed/unsigned/`bytes_to_sign` writers kept in lockstep; builds the per-tx distinct-token-id table.
- `src/input.rs` — `Input` / `UnsignedInput` / `DataInput` / `SpendingProof` / `ContextExtension`; `write_input_to_sign` strips the proof for the signing preimage.
- `src/ergo_box.rs` — `ErgoBoxCandidate` / `ErgoBox`; standalone vs token-indexed box codecs; `box_id`; `parse_ergo_box_bytes` for non-size-delimited trees the standalone reader cannot bound.
- `src/token.rs` — `Token` / `TokenId` (= `Digest32`); full-id and table-indexed token codecs.
- `src/register.rs` — `RegisterId` / `RegisterValue` / `AdditionalRegisters` (R4-R9 densely packed); `split_register_bytes` recovers per-register byte spans.
- `src/ergo_tree.rs` — `ErgoTree` struct (header byte decomposed into `version`/`has_size`/`constant_segregation`); size-delimited soft-fork passthrough for unsupported versions.
- `src/opcode/` — the ErgoTree body AST and dispatch. `types.rs` (`Expr`/`IrNode`/`Payload` + the `opcode_pattern`/`opcode_name` tables), `parse.rs` (bytes→AST), `write.rs` (AST→bytes); read and write each consume the shared table independently.
- `src/sigma_type.rs` — `SigmaType` enum + `read_type`/`write_type`; the embeddable-code packing that fits common types into one byte; depth-bounded recursion.
- `src/sigma_value.rs` — `SigmaValue` / `SigmaBoolean` / `AvlTreeData` / `CollValue` + `read_constant`/`write_constant`/`read_value`/`write_value`/`write_sigma_boolean`.
- `src/address.rs` — `NetworkPrefix` + base58 P2PK/P2SH/P2S encode/decode; `build_p2pk_tree_bytes`; checksum + Scala `ErgoAddressEncoder` routing.
- `src/autolykos.rs` — `AutolykosSolution` (V1 = `pk+w+nonce+d`, V2 = `pk+nonce`); the variant tag is implicit and chosen by header version.
- `src/difficulty.rs` — `nBits` compact-bits codec (`read_nbits`/`write_nbits`/`decode_compact_bits`/`encode_compact_bits`/`normalize_difficulty`); same encoding as Bitcoin.
- `src/modifier_id.rs` — block-section modifier IDs: `TYPE_*` constants, `compute_section_id` (blake2b256 over `type||header_id||digest`), `ExpectedSections`.
- `src/popow_header.rs` / `src/popow_proof.rs` — `PoPowHeader` / `NipopowProof` codecs for the NiPoPoW bootstrap path.
- `src/batch_merkle_proof.rs` — `BatchMerkleProof` / `ProofEntry` / `Side`: scorex-utils compact multi-leaf merkle proof wire form (used by the interlinks proof).
- `src/scala_hamt.rs` — Scala 2.12 `HashTrieMap` iteration-order port (`scala_212_improve`, `hamt_sort_key_for_byte_key`) so a re-serialized ≥5-entry context extension matches the order a Scala wallet signed.
- `src/error.rs` — `WriteError::InvalidData` (the only write-side error), with `From<WriteError> for ReadError`.

## Key types, traits & functions
- `Header` (struct) — consensus header; `version` gates `unparsed_bytes` (v2-4 emit-but-discard on read, v5+ preserve) and PoW layout — `src/header.rs:22`
- `read_header` / `write_header` / `serialize_header` / `write_header_without_pow` / `serialize_header_without_pow` (fns) — id = `blake2b256(full_bytes)`; `*_without_pow` is the PoW-message preimage — `src/header.rs:82`-`:178`
- `Transaction` / `UnsignedTransaction` (structs) — inputs · data_inputs · output_candidates — `src/transaction.rs:17` / `:30`
- `bytes_to_sign` / `transaction_id` / `read_transaction` / `write_transaction` / `write_unsigned_transaction` (fns) — tx id = `blake2b256(bytes_to_sign)` — `src/transaction.rs:164`-`:285`
- `ErgoBoxCandidate` (struct) — parsed tree + verbatim `ergo_tree_bytes`/`register_bytes`; `new` (re-serializes), `from_trusted_raw_parts` (unchecked, byte-identity contract), `try_from_raw_parts` (re-parses and verifies) — `src/ergo_box.rs:30`
- `ErgoBox` (struct) — candidate + `transaction_id` + `index`; `box_id` = `blake2b256(serialized box)` — `src/ergo_box.rs:204` / `:218`
- `parse_ergo_box_bytes` (fn) — boundary-aware box parse for non-size-delimited trees that `read_ergo_box_candidate` cannot bound standalone — `src/ergo_box.rs:441`
- `Input` / `UnsignedInput` / `DataInput` / `SpendingProof` / `ContextExtension` (structs) — `write_input_to_sign` strips the proof — `src/input.rs:21`-`:366`
- `AdditionalRegisters` (struct) / `RegisterId` (enum) / `split_register_bytes` (fn) — densely-packed R4-R9 — `src/register.rs:13`-`:158`
- `ErgoTree` (struct) — `version`/`has_size`/`constant_segregation` (header-byte decomposition) + `constants` + `body` — `src/ergo_tree.rs:32`
- `read_ergo_tree` / `write_ergo_tree` (fns) — size-delimited trees over `MAX_SUPPORTED_TREE_VERSION` (=3) pass through unparsed (soft-fork) — `src/ergo_tree.rs:49` / `:92`
- `Expr` / `IrNode` / `Payload` (enums/struct) + `parse_body`/`parse_expr`/`write_body`/`write_expr` + `opcode_name` — `src/opcode/types.rs:19`, `src/opcode/mod.rs:22`
- `SigmaType` (enum) + `read_type`/`write_type`/`decode_type` — embeddable codes 1-11 pack into a constructor byte — `src/sigma_type.rs:57` / `:139`-`:340`
- `SigmaValue` / `SigmaBoolean` / `AvlTreeData` / `CollValue` (enums/struct) + `read_constant`/`write_constant`/`read_value`/`write_value`/`write_sigma_boolean` — `src/sigma_value.rs:24`-`:494`
- `NetworkPrefix` (enum) / `encode_address` / `decode_p2pk_address` / `build_p2pk_tree_bytes` / `encode_address_from_tree_bytes` / `AddressDecodeError` — `src/address.rs:30`-`:360`
- `AutolykosSolution` (enum) + `read_solution`(takes `block_version`) / `write_solution`; `NONCE_LENGTH = 8` — `src/autolykos.rs:14` / `:54` / `:89`
- `compute_section_id` (fn) / `TYPE_HEADER`=101 / `TYPE_BLOCK_TRANSACTIONS`=102 / `TYPE_AD_PROOFS`=104 / `TYPE_EXTENSION`=108 / `ExpectedSections` — `src/modifier_id.rs:26`-`:52`
- `WriteError` (enum, `InvalidData(String)`) — only crate-defined error; `From<WriteError> for ReadError` keeps `Display` text identical — `src/error.rs:25`

## Invariants & contracts
- **Round-trip byte-identity is the crate's core contract.** Every section must re-serialize to the exact bytes it parsed; ids derive from those bytes, so any drift desyncs `header_id`/`transaction_id`/`box_id` from the network — `src/lib.rs:6`.
- **Verbatim-bytes preservation for ids.** `ErgoBoxCandidate` and `SpendingProof` carry the original `ergo_tree_bytes`/`register_bytes`/`extension` bytes alongside the parsed form so non-canonical Scala-emitted encodings round-trip without breaking `box_id`; `from_trusted_raw_parts` is unchecked (caller owns the contract), `try_from_raw_parts` re-parses and verifies — `src/ergo_box.rs:72`/`:110`, `src/input.rs:236`/`:262`.
- **PoW-message and header-id paths cannot diverge.** `write_header_without_pow` (PoW preimage) and `write_header` (id path) run the same `check_header_bounds`; v2-4 reject non-empty `unparsed_bytes` (read side discards them) and v5+ caps them at 255 (length byte is `u8`) — a silent wrap would split the two paths — `src/header.rs:61`/`:91`.
- **Three transaction writers stay in lockstep.** `write_transaction`, `write_unsigned_transaction`, and `bytes_to_sign_into` share `check_transaction_collection_bounds` (inputs/data_inputs/outputs ≤ u16::MAX, token table ≤ i32::MAX) and `write_transaction_tail`, so the signed / unsigned / signing-preimage id paths cannot drift — `src/transaction.rs:50`/`:108`.
- **Token-id table ordering is consensus-relevant.** The per-tx distinct-token table is emitted in first-occurrence order across outputs (indexed token amounts reference it); a different order changes the bytes and the tx id — `src/transaction.rs:86`.
- **ErgoTree soft-fork passthrough.** Trees whose version exceeds `MAX_SUPPORTED_TREE_VERSION` (=3, Scala `MaxSupportedScriptVersion`) are accepted size-delimited without body parsing and round-tripped verbatim, mirroring Scala's `UnparsedErgoTree` branch; the template-hash path skips these — `src/ergo_tree.rs:90`/`:103`.
- **Standalone box parsing needs a tree boundary.** `read_ergo_box_candidate` can only locate the tree/body boundary for size-delimited trees; non-size-delimited mainnet boxes must go through `parse_ergo_box_bytes` (or be parsed in transaction-indexed mode, where the token table provides the boundary) — `src/ergo_box.rs:16`-`:28`.
- **Section modifier-id preimage is fixed 65-byte layout.** `compute_section_id` = `blake2b256(type_id || header_id[32] || section_digest[32])`; any drift makes peers reject our `RequestModifier` answers (Scala `NonHeaderBlockSection.computeIdBytes`) — `src/modifier_id.rs:38`.
- **Context-extension HAMT ordering for ≥5 entries.** A re-serialized `ContextExtension` with ≥5 vars must emit entries in Scala 2.12 `HashTrieMap` iteration order (via `hamt_sort_key_for_byte_key`), not ascending-by-key, or `bytes_to_sign` desyncs and the signature fails to verify; block-ingest stays safe via verbatim preservation — `src/scala_hamt.rs:1`-`:24`, `src/input.rs:63`.
- **Recursion / allocation guards mirror Scala.** Type recursion is capped at `MAX_TYPE_DEPTH`=100 (`CoreSerializer.MaxTreeDepth`), expression depth at `MAX_EXPR_DEPTH`=300, and `Vec::with_capacity` reservations are soft-capped (`CONSTANTS_VEC_SOFT_CAP`=4096, `TRANSACTIONS_VEC_SOFT_CAP`=1024) so a hostile count field cannot force a multi-GiB pre-reservation while still parsing any tree Scala would accept — `src/sigma_type.rs:46`, `src/opcode/types.rs:10`, `src/ergo_tree.rs:23`, `src/block_transactions.rs:31`.
- **Implicit Autolykos variant.** `AutolykosSolution` carries no on-wire tag; `read_solution` selects V1 vs V2 from the header's `block_version`, and V1/V2 wire forms are not interchangeable — `src/autolykos.rs:10`/`:89`.
- **Scala unsigned-byte length fields.** Extension value lengths and per-box token counts are single unsigned bytes (max 255), not VLQ — VLQ would alias for values <128 but desync at 128-255 — `src/extension.rs:39`, `src/ergo_box.rs:226`.
- **`WriteError` Display text matches `ReadError::InvalidData`.** Operator-visible diagnostics stay stable across the read/write error split (`VlqWriter` is infallible; write errors are purely semantic shape constraints) — `src/error.rs:23`-`:38`.
