//! Scala-byte-exact codec for AVL+ prover-node bytes used in UTXO
//! snapshot manifests + chunks (Mode 2). Mirrors Scala
//! `ProverNodeSerializer` at
//! `avldb/.../crypto/authds/avltree/batch/ProverNodeSerializer.scala`.
//!
//! Wire format (single node):
//!
//! Internal node — prefix `0x00`:
//! ```text
//! 0x00 || balance (1 byte) || key (32) || left_label (32) || right_label (32)
//! ```
//! Total = 1 + 1 + 32 + 32 + 32 = 98 bytes.
//!
//! Leaf node — prefix `0x01`:
//! ```text
//! 0x01 || key (32) || value_length (4 bytes BE) || value || next_leaf_key (32)
//! ```
//! Total = 1 + 32 + 4 + value.len() + 32 = 69 + value.len() bytes.
//!
//! Scala uses `com.google.common.primitives.Ints.toByteArray` for the
//! value length, which is a fixed-width 4-byte big-endian encoding.
//! Note: this is *not* VLQ — value-length is raw BE for historical
//! AVL+ codec parity.
//!
//! This module is the node-level codec only. Manifest framing
//! (rootHeight + manifestDepth prefix, tree walk to manifest depth)
//! lands alongside the manifest-assembly commit (Mode 2 part 2c).

use crate::avl::node::AvlNode;
use crate::store::StateError;
use ergo_primitives::digest::Digest32;

/// Mainnet manifest depth. Mirrors Scala
/// `ManifestSerializer.MainnetManifestDepth = 14`. The manifest is the
/// top subtree of the AVL+ tree cut at this depth from the root;
/// everything below becomes a separate chunk.
pub const MAINNET_MANIFEST_DEPTH: u8 = 14;

/// Hard ceiling on `parse_chunk_walk` recursion depth, guarding the
/// peer-supplied chunk-decode path against a stack overflow from a
/// degenerate deep-spine chunk (which otherwise recurses once per
/// internal node, bounded only by the multi-MiB frame size). The Ergo
/// AVL+ UTXO tree uses 32-byte keys; an AVL tree of `n` entries has
/// height `<= 1.44 * log2(n + 2)`, so even an absurd `n = 2^48` bounds
/// the height at ~70. 128 leaves comfortable headroom above any
/// realistic UTXO set while capping recursion far below the
/// worker-thread stack limit — a malformed chunk returns a typed error
/// instead of aborting the process.
const MAX_RECONSTRUCT_DEPTH: usize = 128;

/// Prefix byte for an internal node. Scala constant
/// `VersionedLDBAVLStorage.InternalNodePrefix`.
pub const INTERNAL_NODE_PREFIX: u8 = 0x00;

/// Prefix byte for a leaf node. Scala constant
/// `VersionedLDBAVLStorage.LeafPrefix`.
pub const LEAF_PREFIX: u8 = 0x01;

/// AVL+ key size in bytes. Mirrors Scala `StateTreeParameters.keySize`
/// (= `HashLength` = 32).
pub const KEY_SIZE: usize = 32;

/// AVL+ label (digest) size in bytes. Mirrors Scala
/// `StateTreeParameters.labelSize` (= `HashLength` = 32).
pub const LABEL_SIZE: usize = 32;

/// Resolved label closure: given an `AvlNode::Internal` whose
/// `left_label` / `right_label` cache may be unpopulated, this trait
/// hands back the digest for the matching child. The snapshot path
/// invokes it through the tree-walk caller, which has access to the
/// arena and can recompute on demand.
///
/// Decoupling this from `serialize_prover_node` keeps the codec
/// itself arena-free — useful for tests that build nodes by hand and
/// supply the labels directly.
pub trait ChildLabels {
    /// Return the cached or recomputed label for the left child of
    /// the given internal node.
    fn left_label(&self, node: &AvlNode) -> Result<Digest32, StateError>;
    /// Return the cached or recomputed label for the right child of
    /// the given internal node.
    fn right_label(&self, node: &AvlNode) -> Result<Digest32, StateError>;
}

/// Closure-backed `ChildLabels` impl. Threads two callables through;
/// avoids forcing every call site to introduce a struct.
pub struct ClosureChildLabels<L, R>
where
    L: Fn(&AvlNode) -> Result<Digest32, StateError>,
    R: Fn(&AvlNode) -> Result<Digest32, StateError>,
{
    pub left: L,
    pub right: R,
}

impl<L, R> ChildLabels for ClosureChildLabels<L, R>
where
    L: Fn(&AvlNode) -> Result<Digest32, StateError>,
    R: Fn(&AvlNode) -> Result<Digest32, StateError>,
{
    fn left_label(&self, node: &AvlNode) -> Result<Digest32, StateError> {
        (self.left)(node)
    }
    fn right_label(&self, node: &AvlNode) -> Result<Digest32, StateError> {
        (self.right)(node)
    }
}

mod manifest;
mod node_codec;
mod server;

pub use manifest::{
    enumerate_chunk_roots, enumerate_expected_chunk_ids, recompute_chunk_root_label,
    reconstruct_tree, serialize_chunk, serialize_manifest, ReconstructedNode, ReconstructedTree,
};
pub use node_codec::{parse_prover_node, serialize_prover_node, ParsedProverNode};
pub use server::SnapshotServer;

#[cfg(test)]
mod tests;
