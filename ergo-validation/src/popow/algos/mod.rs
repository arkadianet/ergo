//! Pure NiPoPoW algorithms — KMZ17 maxLevelOf, bestArg, LCA, and
//! update_interlinks. Scala reference: `NipopowAlgos.scala` (lines
//! cited inline at each function).
//!
//! - [`interlinks`] — pack/unpack the interlinks vector to/from the
//!   extension's key-value fields, [`interlinks::build_popow_header`],
//!   and the [`interlinks::update_interlinks`] vector-update rule.
//! - [`scoring`] — μ-level ([`scoring::max_level_of`]) and best-argument
//!   score (KMZ17 Algorithm 4).
//! - [`prove`] — NiPoPoW proof construction ([`prove::prove`]).
//! - [`lca`] — [`lca::lowest_common_ancestor`] between two chains.

mod interlinks;
mod lca;
mod prove;
mod scoring;

pub use interlinks::{
    build_popow_header, kv_to_leaf, pack_interlinks, unpack_interlinks, update_interlinks,
    INTERLINKS_VECTOR_PREFIX,
};
pub use lca::lowest_common_ancestor;
pub use prove::{prove, PoPowParams};
pub use scoring::{best_arg, best_arg_from_levels, max_level_of, GENESIS_LEVEL};

use ergo_ser::header::Header;

/// Genesis predicate: parent_id is the zero-bytes 32-byte array.
/// Matches Scala `Header.isGenesis` (`parentId.sameElements(GenesisParentId)`).
pub(crate) fn is_genesis(header: &Header) -> bool {
    *header.parent_id.as_bytes() == [0u8; 32]
}

/// Header id: Blake2b256 of the canonical serialized bytes. We compute
/// from the `bytes-without-pow` || solution path implicitly via
/// `serialize_header` if needed, but for popow we only need an id-by-
/// header lookup; build it via `blake2b256` of the full
/// serialization.
fn header_id(header: &Header) -> Result<[u8; 32], ergo_ser::error::WriteError> {
    // Pre-gates (NipopowProofExt::all_headers_serializable at verifier
    // entry; block validation / mining callers exercise paths where the
    // parent header has already been accepted) keep this Err
    // unreachable in honest control flow. Returning Result rather than
    // panicking lets production callers (block.rs interlinks check,
    // extension_builder.rs candidate construction) degrade to typed
    // errors instead of aborting the node when peer-supplied or
    // mempool-derived headers slip past a future relaxation.
    let (_bytes, id) = ergo_ser::header::serialize_header(header)?;
    Ok(*id.as_bytes())
}
