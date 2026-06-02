//! AVL+ tree implementation for the authenticated UTXO state.
//!
//! Sub-modules:
//!
//! * [`node`] — [`node::AvlNode`] (leaf / internal) and the
//!   `NodeId` arena-index type.
//! * [`tree`] — [`tree::AvlTree`] insert / remove / lookup with
//!   incremental label maintenance, plus the proof-style verifier
//!   helpers.
//! * [`arena`] — `CachedDiskArena`: the LRU-cached redb-backed node
//!   store that the production tree runs on.
//! * [`digest`] — Blake2b-based leaf / internal label primitives used
//!   by the tree to compute the authenticated root.
//! * [`changelog`] — `ChangeLog`: before-image undo records produced
//!   during apply and consumed during rollback.
//! * [`serialization`] — byte codecs for `AvlNode` and the
//!   crate-internal `AllocMeta`. Wire-format identity matters for
//!   storage compat; touching this is consensus-affecting.

pub mod arena;
pub mod changelog;
pub mod digest;
pub mod hydrate;
pub mod node;
// Storage codecs are crate-internal — the only public path is via
// `crate::store::{node_to_bytes, node_from_bytes}` re-exports so we
// don't double-publish the AVL+ wire format. Keeping this non-public
// avoids committing downstream consumers to the byte layout.
pub(crate) mod serialization;
// Scala-byte-compatible AVL+ node codec for Mode 2 (UTXO snapshot)
// manifests and chunks. Distinct from the internal `serialization`
// module above — that one's our local persistence format, not Scala
// wire-format. Public because Mode 2 part 2c (manifest assembly)
// will live in a separate module that walks the tree using this
// codec.
pub mod snapshot_codec;
pub mod tree;
