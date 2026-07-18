//! Wire-shaped DTOs for the operator API.
//!
//! Field types are stable primitives — no internal enum representations
//! or binary blobs leak through.
//!
//! ## Id encoding
//!
//! Every id- or root-shaped `String` field on this module's wire DTOs is
//! lowercase hex, byte-exact with the on-disk and on-chain bytes. No
//! `0x` prefix, no upper-case, no base64. Concretely:
//!
//! - 32 bytes / 64 hex chars — every id- and content-hash field on
//!   this surface (`header_id`, `parent_id`, `tx_id`, `box_id`,
//!   `token_id`, `manifest_id`). All are `Digest32` under the hood —
//!   see the shared aliases in `ergo-indexer-types::{TxId, HeaderId,
//!   BoxId, TokenId}` — the field name carries the semantic, not the
//!   type. `manifest_id` is the AVL chunk-tree root label of a
//!   snapshot bootstrap.
//! - 33 bytes / 66 hex chars — `state_root_avl`, the AVL+
//!   authenticated UTXO-tree root (`Digest32 || balance-byte`);
//!   matches the on-chain `Header.stateRoot`.
//!
//! Numeric fields on this surface (e.g. `ApiPeer.score`, heights,
//! timestamps, n_bits) are JSON numbers, not hex.

mod chain_refs;
mod events;
mod identity;
mod indexer;
mod mempool;
mod peers;
mod status;
mod voting;

pub use chain_refs::*;
pub use events::*;
pub use identity::*;
pub use indexer::*;
pub use mempool::*;
pub use peers::*;
pub use status::*;
pub use voting::*;

/// Hex-encode a 32-byte id without the `0x` prefix.
pub fn hex32(bytes: &[u8; 32]) -> String {
    hex::encode(bytes)
}
