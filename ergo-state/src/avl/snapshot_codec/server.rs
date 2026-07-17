//! [`SnapshotServer`] — serve-ready index of one snapshot's manifest
//! and chunk bytes for peer `GetManifest` / `GetUtxoSnapshotChunk`
//! requests.
//!
//! Sibling of `mod.rs`; pure impl relocation.

use crate::avl::tree::AvlTree;
use crate::store::StateError;
use ergo_primitives::digest::Digest32;

use super::manifest::compute_node_label;
use super::{enumerate_chunk_roots, serialize_chunk, serialize_manifest};

// ----- Server-side snapshot index -----

/// Index of a single snapshot ready to serve over the wire.
/// Built once from an [`AvlTree`] at a given height; subsequent
/// peer requests for `GetManifest` / `GetUtxoSnapshotChunk` look
/// up bytes by id without re-walking the tree.
///
/// `manifest_id` and each `subtree_id` are the 32-byte root labels
/// of their respective subtree roots — same convention as Scala
/// `dumpSnapshot` in `VersionedLDBAVLStorage.scala:151-153`, where
/// the manifest is stored under its rootNodeLabel and each subtree
/// is stored under the subtree's rootLabel.
///
/// Manifest depth is fixed at construction. Mainnet uses
/// [`MAINNET_MANIFEST_DEPTH`] (= 14). Shallower depths produce
/// fewer chunks but larger manifest bytes.
pub struct SnapshotServer {
    /// AVL+ root label at the snapshot height. Same value the
    /// reference-node `Manifest` message uses as its on-the-wire
    /// id; same value as the first 32 bytes of the header's
    /// `state_root` field at the snapshot height.
    pub manifest_id: Digest32,
    /// Block height of the snapshot. Reported in `SnapshotsInfo`.
    pub height: u32,
    /// Manifest bytes per Scala `ManifestSerializer.serialize` —
    /// `rootHeight || manifestDepth || DFS-nodes`.
    pub manifest_bytes: Vec<u8>,
    /// Each chunk = (subtree_id, chunk_bytes). The id is the
    /// subtree root's label; the bytes are the full DFS of that
    /// subtree per Scala `SubtreeSerializer.serialize`. Stored in
    /// insertion (manifest DFS) order so a sequential download
    /// can stream them by index.
    pub chunks: Vec<(Digest32, Vec<u8>)>,
}

impl SnapshotServer {
    /// Build a serve-ready snapshot from the current state of `tree`.
    /// Walks the tree once: computes the root label, serializes the
    /// manifest, enumerates the chunk roots, serializes each chunk
    /// alongside its subtree-root label.
    pub fn build(tree: &AvlTree, height: u32, manifest_depth: u8) -> Result<Self, StateError> {
        let manifest_bytes = serialize_manifest(tree, manifest_depth)?;
        let chunk_roots = enumerate_chunk_roots(tree, manifest_depth)?;
        let mut chunks = Vec::with_capacity(chunk_roots.len());
        for root_id in chunk_roots {
            let subtree_id = compute_node_label(tree, root_id)?;
            let chunk_bytes = serialize_chunk(tree, root_id)?;
            chunks.push((subtree_id, chunk_bytes));
        }
        // Manifest id = root_label of the whole tree (matches Scala
        // VersionedLDBAVLStorage.dumpSnapshot return value).
        let manifest_id = compute_node_label(tree, tree.root_id())?;
        Ok(SnapshotServer {
            manifest_id,
            height,
            manifest_bytes,
            chunks,
        })
    }

    /// Find a chunk by its subtree id. Linear scan — chunk counts at
    /// `manifest_depth = 14` are bounded by `2^14 = 16,384` even
    /// for a fully-populated tree, so a Vec scan is fast enough
    /// for the request rate (a single bootstrapping peer fetches
    /// each chunk once).
    pub fn chunk_by_id(&self, subtree_id: &Digest32) -> Option<&[u8]> {
        self.chunks
            .iter()
            .find(|(id, _)| id == subtree_id)
            .map(|(_, bytes)| bytes.as_slice())
    }
}
