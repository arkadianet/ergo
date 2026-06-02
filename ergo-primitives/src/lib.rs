//! Foundational primitives shared by the Ergo Rust node.
//!
//! This is the leaf crate in the workspace — it has no internal dependencies
//! and is consumed by everything else. It deliberately stays minimal:
//!
//! * [`digest`]      — fixed-size hash and authenticated-digest types
//!   (`Digest32`, `ADDigest`, `ModifierId`) and the `blake2b256` hasher.
//! * [`group_element`] — opaque 33-byte SEC1-compressed secp256k1 point
//!   (`GroupElement`). No curve arithmetic lives here.
//! * [`reader`] / [`writer`] — `VlqReader` / `VlqWriter`, the Scorex-style
//!   VLQ + zigzag wire-format codecs used across consensus serialization.
//! * [`vlq`] — the underlying unsigned VLQ encoder/decoder used by the
//!   reader/writer (the only `vlq` item consumed externally is
//!   [`vlq::encode_vlq`]).
//! * [`cost`] — `JitCost`, `CostKind`, and `CostAccumulator`, mirroring the
//!   Scala interpreter's JIT-granularity cost model.
//!
//! What is **not** here:
//!
//! * Any cryptographic primitive beyond Blake2b — secp256k1 arithmetic,
//!   AVL+ trees, Merkle hashing, and PoW live in `ergo-crypto`.
//! * Any consensus-typed serializer (headers, transactions, boxes,
//!   ErgoTree). Those live in `ergo-ser` and build on top of the
//!   `VlqReader`/`VlqWriter` exposed here.
//! * Any sigma-typed value codecs (`SigmaProp`, register payloads,
//!   typed `BigInt` wire form). Those live in `ergo-ser::sigma_value`.

pub mod cost;
pub mod digest;
pub mod group_element;
pub mod reader;
pub mod vlq;
pub mod writer;
pub(crate) mod zigzag;
