# ergo-primitives

**Purpose:** The L0 leaf crate of the workspace. Holds the foundational byte-level types and codecs every other crate builds on: Blake2b-256 hashing and the fixed-size hash/ID newtypes, the opaque SEC1 secp256k1 point wrapper, the Scorex-style VLQ + zigzag wire readers/writers, and the JIT-granularity cost model. No curve arithmetic, no consensus-typed serializers, no sigma values — those live one layer up.

**Depends on (workspace):** none (only `blake2`, `hex`, `thiserror`)
**Depended on by:** (see codemap index)
**Approx LOC:** ~2600 (incl. tests)

## Start here
- `src/lib.rs` — the module tree and a precise "what is / is NOT here" boundary statement (lines 18-26).
- `src/reader.rs` (`VlqReader`) and `src/writer.rs` (`VlqWriter`) — the load-bearing wire codecs used by all of `ergo-ser`. Read these to understand the byte format and the cursor-recovery contract.
- `src/digest.rs` — `Digest32` / `ADDigest` / `ModifierId` / `blake2b256`, the identity types threaded through headers, transactions, and state roots.
- `src/cost.rs` (`JitCost`, `CostAccumulator`) — the Scala-parity cost model the interpreter and validator meter against.

## Modules
- `src/digest.rs` — fixed-size hash newtypes (`Digest32` 32-byte, `ADDigest` 33-byte AVL+ root, `ModifierId` newtype over `Digest32`) plus the `blake2b256` hasher.
- `src/group_element.rs` — `GroupElement`, an opaque 33-byte SEC1-compressed secp256k1 point. Bytes are not validated as on-curve here; decompression/arithmetic happens in `ergo-crypto`. Also exports `read_group_element`, which reads 33 bytes from a `VlqReader` and registers the point on the reader's curve-check sideband so a higher layer can validate on-curve after parsing.
- `src/reader.rs` — `VlqReader`, the deserialization cursor over a borrowed `&[u8]`, plus the `ReadError` enum. Beyond the core decode methods the reader carries four sidebands added after the initial release: a `group_elements` accumulator (Scala curve-checks each group element at parse time; this crate is crypto-free so points are collected here and validated later by `ergo-validation`); an `unresolved_method_checkpoint` for method-resolution gating; an `ergo_tree_version` for version-gating embeddable type codes; and a `position_limit` mirroring Scala's `Reader.positionLimit` validation rule 1014. A `trusted` flag (builder: `.trusted()`) skips the consensus acceptance gates when re-reading already-validated stored data (used by the indexer self-repair path).
- `src/writer.rs` — `VlqWriter`, the append-only serialization buffer (with scratch-reuse `clear()`/`as_slice()`).
- `src/vlq.rs` — the underlying unsigned VLQ (== unsigned LEB128 / protobuf varint) encoder/decoder (`encode_vlq`, `encode_vlq_into`, `decode_vlq`) and `VlqError`.
- `src/zigzag.rs` — zigzag mapping for signed ints and the signed VLQ encode/decode helpers used by `VlqReader`/`VlqWriter`. Crate-private `_into` helpers; the only `pub` external surface is the zigzag bijection fns + `decode_signed_*`.
- `src/cost.rs` — `JitCost`, `CostKind`, `CostAccumulator`, `JitCostError`, `CostError`: the JIT-granularity (10× block cost) cost model mirroring sigmastate-interpreter.

## Key types, traits & functions
- `Digest32` (struct) — 32-byte Blake2b-256 hash; `ZERO` sentinel, `from_bytes`/`as_bytes` — `src/digest.rs:6`
- `ADDigest` (struct) — 33-byte authenticated AVL+ state root (32-byte digest + 1-byte tree height); `tree_height_byte()` reads index 32 — `src/digest.rs:42`
- `ModifierId` (struct) — distinct 32-byte identifier newtype over `Digest32` (headers, txs, block sections); explicit `From<Digest32>` conversion only — `src/digest.rs:88`
- `blake2b256` (fn) — `&[u8] -> Digest32` Blake2b-256 hasher — `src/digest.rs:132`
- `GroupElement` (struct) + `GROUP_ELEMENT_LENGTH = 33` (const) — opaque compressed secp256k1 point — `src/group_element.rs:4` / `:8`
- `read_group_element` (fn) — reads a 33-byte `GroupElement` from a `VlqReader` and records it on the reader's `group_elements` sideband for deferred curve-checking; every deserializer that encounters a group element must go through this entry point — `src/group_element.rs:29`
- `VlqReader<'a>` (struct) — borrowing decode cursor: `get_u8`/`get_bytes`/`get_array::<N>`, `get_u32_exact` (Scala `getUIntExact`, i32::MAX bound), `get_u16` (`getUShortExact`), `get_u64`, `get_i32`/`get_i64` (zigzag), `get_short_be` (raw BE, NOT VLQ), `get_length_prefixed_bytes`, `get_uint_to_i32`, `peek_u8`, `set_position`; sideband accessors `record_group_element`/`take_group_elements`, `mark_unresolved_method_checkpoint`, `set_ergo_tree_version`, `set_position_limit`; `.trusted()` builder — `src/reader.rs:5`
- `ReadError` (enum) — `UnexpectedEnd { pos, needed }` / `Vlq(VlqError)` / `ValueTooLarge { type_name, got }` / `InvalidData(String)` — `src/reader.rs:62`
- `VlqWriter` (struct) — append buffer: `put_u8`/`put_bytes`/`put_u32`/`put_u64`/`put_u16`/`put_i32`/`put_i64`, `put_short_be` (raw BE), `put_length_prefixed_bytes` (panics > i32::MAX), `result`/`as_slice`/`clear` — `src/writer.rs:5`
- `encode_vlq` / `encode_vlq_into` / `decode_vlq` (fns) + `VlqError` (`UnexpectedEnd` / `Overflow`) — `src/vlq.rs:5` / `:16` / `:32` / `:53`
- `zigzag_encode_i32`/`zigzag_decode_i32`/`zigzag_encode_i64`/`zigzag_decode_i64` + `decode_signed_i32`/`decode_signed_i64` (fns) — `src/zigzag.rs:3`-`:81`
- `JitCost` (struct) — `u64`-backed, `i32::MAX`-bounded JIT cost; `from_jit` (const, panics on bad literal), `try_from_jit` (fallible), `from_block_cost` (× 10), `checked_add`, `to_block_cost`, `value`, `ZERO` — `src/cost.rs:27`
- `CostKind` (enum) — `Fixed` / `PerItem { base, per_chunk, chunk_size }`; `compute(n_items)` with JVM signed-truncation chunk count — `src/cost.rs:167`
- `CostAccumulator` (struct) — additive-only metering: `new`(enforcing) / `recording_only`, `add`/`add_fixed`/`add_per_item`, `snap_to_block_boundary`, `total`/`total_block_cost`/`consumed` — `src/cost.rs:241`
- `JitCostError` (enum, `Overflow { operation, value }`) / `CostError` (enum, `LimitExceeded` / `Overflow(JitCostError)`) — `src/cost.rs:61` / `:226`

## Invariants & contracts
- **Blake2b-256 = consensus hash.** `blake2b256(header_bytes)` must equal the network header_id; pinned against mainnet header vectors (`test-vectors/primitives/blake2b256_header_oracle.json`), not a self-oracle — `src/digest.rs:244`.
- **`ADDigest` is exactly 33 bytes** (32-byte digest + trailing tree-height byte). A copy/paste truncation to 32 bytes would silently corrupt every `state_root` comparison — `src/digest.rs:42`, pinned at `:194`.
- **`ModifierId` is a real newtype**, not a transparent alias: a fn taking `&ModifierId` will not accept a raw `Digest32` state root by accident; conversion is explicit — `src/digest.rs:88`.
- **VLQ == unsigned LEB128 / protobuf varint** byte-for-byte: 7-bit little-endian payload, MSB continuation bit, valid encodings are 1..=10 bytes for any `u64`. Non-canonical zeros (`[0x80,0x00]`) are accepted to match Scala — `src/vlq.rs`, pinned at `:267`.
- **Reader cursor recovery is all-or-nothing for single-step reads:** a failed typed read does NOT advance `position()`, so upstream framing recovery can rewind (load-bearing for the demoted-to-revalidation path). `get_length_prefixed_bytes` is the one two-phase exception (advances exactly past the length prefix on payload truncation) — `src/reader.rs`, pinned at `:419` and `:691`.
- **`get_u32_exact` enforces the Scala `getUIntExact` bound (`i32::MAX`),** stricter than `u32::MAX`. The writer (`put_u32`) accepts the full `u32` range, so values above `i32::MAX` are intentionally NOT round-trippable through `get_u32_exact` — callers must use `put_u64`/`get_u64`. This asymmetry is deliberate and pinned — `src/reader.rs:323`, `src/writer.rs:41`, asymmetry test `src/reader.rs:778`.
- **Signed-VLQ i32 sign-extends through i64 (JVM `(Long) int`)** before VLQ encoding: an i32 whose post-zigzag bit 31 is set produces a 10-byte VLQ, byte-identical to Scala. Zero-extension would break wire fidelity (witness: mainnet block 555672 tx[2] output[0] R4) — `src/zigzag.rs:45`, pinned at `:230`.
- **`get_short_be`/`put_short_be` are raw big-endian 2-byte, NOT VLQ.** Mixing them with the VLQ `get_u16`/`put_u16` silently corrupts the wire format — `src/reader.rs:408`, `src/writer.rs:69`.
- **`JitCost` mirrors Scala `JitCost` (i32-backed) arithmetic:** every runtime op (`try_from_jit`, `from_block_cost`, `checked_add`) is bounded at `SCALA_INT_MAX` (`i32::MAX`) and returns a structured `JitCostError::Overflow` (Scala `Math.addExact`/`multiplyExact` parity) rather than panicking. JIT = 10× block cost. The overflow path is unreachable from honest mainnet input (max_block_cost JIT cap ≈ 45× under the bound) — `src/cost.rs:27`/`:53`, margin pinned at `:601`.
- **`CostAccumulator` is additive-only** with no decrement; `recording_only` suppresses the limit check but NOT overflow detection — `src/cost.rs:241`.
- **`CostKind::PerItem` chunk count uses JVM signed truncation:** at `n_items = 0` this yields 1 chunk for `chunk_size >= 2` but 0 chunks for `chunk_size == 1`; cost-table sites depend on the `chunk_size == 1` case — `src/cost.rs:195`.
- **`GroupElement` bytes are unvalidated** as on-curve at this layer — it is a transport wrapper only; decompression lives in `ergo-crypto` — `src/group_element.rs:10`.
