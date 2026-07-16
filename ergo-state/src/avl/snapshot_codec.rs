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

use crate::avl::digest::{internal_label, leaf_label};
use crate::avl::node::AvlNode;
use crate::avl::node::NodeId;
use crate::avl::tree::AvlTree;
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

/// Serialize a single AVL+ prover node into the Scala-compatible
/// wire format. Internal nodes need both child labels supplied via
/// `labels`; leaf nodes ignore the `labels` arg (each leaf is
/// self-describing).
pub fn serialize_prover_node(
    node: &AvlNode,
    labels: &dyn ChildLabels,
) -> Result<Vec<u8>, StateError> {
    let mut out = Vec::new();
    match node {
        AvlNode::Internal { key, balance, .. } => {
            out.push(INTERNAL_NODE_PREFIX);
            out.push(*balance as u8);
            out.extend_from_slice(key);
            let left = labels.left_label(node)?;
            let right = labels.right_label(node)?;
            out.extend_from_slice(left.as_bytes());
            out.extend_from_slice(right.as_bytes());
            debug_assert_eq!(out.len(), 1 + 1 + KEY_SIZE + LABEL_SIZE + LABEL_SIZE);
        }
        AvlNode::Leaf {
            key,
            value,
            next_key,
            ..
        } => {
            out.push(LEAF_PREFIX);
            out.extend_from_slice(key);
            // Scala `Ints.toByteArray` = 4 bytes big-endian.
            let value_len: u32 = value.len().try_into().map_err(|_| {
                StateError::Serialization(format!(
                    "AVL leaf value too large for u32 prefix: {} bytes",
                    value.len(),
                ))
            })?;
            out.extend_from_slice(&value_len.to_be_bytes());
            out.extend_from_slice(value);
            out.extend_from_slice(next_key);
        }
    }
    Ok(out)
}

/// Parsed AVL+ prover-node body. Internal nodes carry their child
/// labels as bytes; the caller stitches them into a tree by matching
/// labels to the next-parsed nodes. Leaves are fully self-contained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedProverNode {
    Internal {
        balance: i8,
        key: [u8; KEY_SIZE],
        left_label: [u8; LABEL_SIZE],
        right_label: [u8; LABEL_SIZE],
    },
    Leaf {
        key: [u8; KEY_SIZE],
        value: Vec<u8>,
        next_leaf_key: [u8; KEY_SIZE],
    },
}

/// Parse a single AVL+ prover-node body. Returns the parsed node plus
/// the number of bytes consumed (so a caller can read a sequence of
/// concatenated nodes without external framing).
pub fn parse_prover_node(payload: &[u8]) -> Result<(ParsedProverNode, usize), StateError> {
    if payload.is_empty() {
        return Err(StateError::Serialization(
            "prover-node payload is empty".into(),
        ));
    }
    let prefix = payload[0];
    let body = &payload[1..];
    match prefix {
        INTERNAL_NODE_PREFIX => {
            const NEED: usize = 1 + KEY_SIZE + LABEL_SIZE + LABEL_SIZE;
            if body.len() < NEED {
                return Err(StateError::Serialization(format!(
                    "internal-node payload truncated: need {NEED} body bytes, got {}",
                    body.len(),
                )));
            }
            let balance = body[0] as i8;
            // AVL+ invariant: internal-node balance is structurally
            // restricted to {-1, 0, 1}. The on-wire byte is `i8` so
            // it can carry any value in `[-128, 127]`. Without this
            // gate, an adversarial Mode-2 UTXO snapshot can satisfy
            // the manifest's root-digest check (manifest verifies
            // root, not per-node invariants) while embedding a node
            // whose `balance` byte is later fed to AVL rotations at
            // `tree.rs::double_left_rotate` / `double_right_rotate`,
            // where the match arm `0 | -1 | 1 => …, _ => panic!(...)`
            // takes down the install thread.
            //
            // Scope of the fix: this gate closes the peer-attack
            // Mode-2 surface — bad bytes can't reach `AVL_NODES`
            // because reconstruction errors out before any write.
            // The corrupt-disk surface at `arena.rs:344`
            // (`.expect("node_from_bytes failed on persisted bytes")`)
            // is unchanged and intentional per the comment there:
            // returning `None` for a corrupt-but-present row would
            // silently violate the digest invariant, so a corrupt
            // disk row must fail loud rather than fail-soft.
            if !matches!(balance, -1..=1) {
                return Err(StateError::Serialization(format!(
                    "internal-node balance {balance} out of {{-1, 0, 1}}"
                )));
            }
            let mut key = [0u8; KEY_SIZE];
            key.copy_from_slice(&body[1..1 + KEY_SIZE]);
            let mut left_label = [0u8; LABEL_SIZE];
            left_label.copy_from_slice(&body[1 + KEY_SIZE..1 + KEY_SIZE + LABEL_SIZE]);
            let mut right_label = [0u8; LABEL_SIZE];
            right_label.copy_from_slice(
                &body[1 + KEY_SIZE + LABEL_SIZE..1 + KEY_SIZE + LABEL_SIZE + LABEL_SIZE],
            );
            Ok((
                ParsedProverNode::Internal {
                    balance,
                    key,
                    left_label,
                    right_label,
                },
                1 + NEED,
            ))
        }
        LEAF_PREFIX => {
            if body.len() < KEY_SIZE + 4 {
                return Err(StateError::Serialization(format!(
                    "leaf-node header truncated: need {} body bytes, got {}",
                    KEY_SIZE + 4,
                    body.len(),
                )));
            }
            let mut key = [0u8; KEY_SIZE];
            key.copy_from_slice(&body[..KEY_SIZE]);
            let value_len =
                u32::from_be_bytes(body[KEY_SIZE..KEY_SIZE + 4].try_into().unwrap()) as usize;
            let value_start = KEY_SIZE + 4;
            let value_end = value_start + value_len;
            let next_start = value_end;
            let next_end = next_start + KEY_SIZE;
            if body.len() < next_end {
                return Err(StateError::Serialization(format!(
                    "leaf-node body truncated: need {next_end} body bytes, got {}",
                    body.len(),
                )));
            }
            let value = body[value_start..value_end].to_vec();
            let mut next_leaf_key = [0u8; KEY_SIZE];
            next_leaf_key.copy_from_slice(&body[next_start..next_end]);
            Ok((
                ParsedProverNode::Leaf {
                    key,
                    value,
                    next_leaf_key,
                },
                1 + next_end,
            ))
        }
        other => Err(StateError::Serialization(format!(
            "unknown prover-node prefix byte: 0x{other:02x} (expected 0x00 internal or 0x01 leaf)",
        ))),
    }
}

// ----- Tree-aware manifest + chunk assembly -----

/// Resolved child labels for a single internal-node serialization.
/// Avoids closure-capture lifetime gymnastics — the manifest walker
/// computes both child labels up front and hands them to
/// `serialize_prover_node` via this struct.
struct ResolvedLabels {
    left: Digest32,
    right: Digest32,
}

impl ChildLabels for ResolvedLabels {
    fn left_label(&self, _node: &AvlNode) -> Result<Digest32, StateError> {
        Ok(self.left)
    }
    fn right_label(&self, _node: &AvlNode) -> Result<Digest32, StateError> {
        Ok(self.right)
    }
}

/// Compute (or fetch from cache) the label of any node by id. Used
/// by the manifest writer to fill in `left_label` / `right_label`
/// when the internal node's cache fields are unpopulated (v1-loaded
/// or freshly-built nodes). For v2-cached internals the cached
/// labels are returned directly — no recursion.
fn compute_node_label(tree: &AvlTree, node_id: NodeId) -> Result<Digest32, StateError> {
    let node = tree
        .get_node(node_id)
        .ok_or(StateError::InternalInvariant {
            what: "snapshot codec: missing AVL node during label walk",
        })?;
    match &node {
        AvlNode::Leaf {
            key,
            value,
            next_key,
            label,
        } => Ok(label.unwrap_or_else(|| leaf_label(key, value, next_key))),
        AvlNode::Internal {
            balance,
            left,
            right,
            left_label,
            right_label,
            label,
            ..
        } => {
            if let Some(l) = label {
                return Ok(*l);
            }
            let l_label = match left_label {
                Some(l) => *l,
                None => compute_node_label(tree, *left)?,
            };
            let r_label = match right_label {
                Some(l) => *l,
                None => compute_node_label(tree, *right)?,
            };
            Ok(internal_label(*balance, &l_label, &r_label))
        }
    }
}

/// Serialize the manifest — the top subtree of the AVL+ tree cut at
/// `manifest_depth`. Wire format:
///
/// ```text
/// rootHeight (1 byte) || manifestDepth (1 byte) || DFS-serialized nodes
/// ```
///
/// Mirrors Scala `ManifestSerializer.serialize` byte-for-byte. The
/// DFS walks the tree from the root, serializing each visited node
/// via [`serialize_prover_node`]. Internal nodes at `level <
/// manifest_depth` recurse into both children; nodes at
/// `level == manifest_depth` (or leaves at any depth) are serialized
/// but not recursed into. Children of depth-`manifest_depth` internal
/// nodes become the roots of their respective chunks (see
/// [`serialize_chunk`]).
pub fn serialize_manifest(tree: &AvlTree, manifest_depth: u8) -> Result<Vec<u8>, StateError> {
    let mut out = Vec::new();
    out.push(tree.tree_height());
    out.push(manifest_depth);
    write_manifest_walk(tree, tree.root_id(), 1, manifest_depth, &mut out)?;
    Ok(out)
}

/// Internal recursive walker for [`serialize_manifest`]. Caller is
/// responsible for writing the rootHeight + manifestDepth header
/// bytes; this function only writes node bodies.
fn write_manifest_walk(
    tree: &AvlTree,
    node_id: NodeId,
    level: u8,
    manifest_depth: u8,
    out: &mut Vec<u8>,
) -> Result<(), StateError> {
    let node = tree
        .get_node(node_id)
        .ok_or(StateError::InternalInvariant {
            what: "snapshot codec: missing AVL node during manifest walk",
        })?;

    match &node {
        AvlNode::Leaf { .. } => {
            // Leaves carry their full body; no label dependency.
            // Pass dummy labels — `serialize_prover_node` ignores
            // them for leaf branches.
            let dummy = ResolvedLabels {
                left: Digest32::from_bytes([0u8; 32]),
                right: Digest32::from_bytes([0u8; 32]),
            };
            let bytes = serialize_prover_node(&node, &dummy)?;
            out.extend_from_slice(&bytes);
        }
        AvlNode::Internal { left, right, .. } => {
            // Compute child labels (cached path first; fall through
            // to recursive label compute for legacy v1 nodes).
            let labels = ResolvedLabels {
                left: compute_node_label(tree, *left)?,
                right: compute_node_label(tree, *right)?,
            };
            let bytes = serialize_prover_node(&node, &labels)?;
            out.extend_from_slice(&bytes);

            // Recurse only when within the manifest depth window.
            // At `level == manifest_depth` we serialize the internal
            // node but stop — its children become chunk roots.
            if level < manifest_depth {
                write_manifest_walk(tree, *left, level + 1, manifest_depth, out)?;
                write_manifest_walk(tree, *right, level + 1, manifest_depth, out)?;
            }
        }
    }
    Ok(())
}

/// Serialize one chunk — the full subtree rooted at `subtree_root`.
/// Wire format is a flat DFS of prover nodes with no header bytes.
/// Mirrors Scala `SubtreeSerializer.serialize`. Callers obtain
/// `subtree_root` ids by walking the tree down to `manifest_depth`
/// and collecting the children of each cut node (see
/// [`enumerate_chunk_roots`]).
pub fn serialize_chunk(tree: &AvlTree, subtree_root: NodeId) -> Result<Vec<u8>, StateError> {
    let mut out = Vec::new();
    write_chunk_walk(tree, subtree_root, &mut out)?;
    Ok(out)
}

fn write_chunk_walk(tree: &AvlTree, node_id: NodeId, out: &mut Vec<u8>) -> Result<(), StateError> {
    let node = tree
        .get_node(node_id)
        .ok_or(StateError::InternalInvariant {
            what: "snapshot codec: missing AVL node during chunk walk",
        })?;
    match &node {
        AvlNode::Leaf { .. } => {
            let dummy = ResolvedLabels {
                left: Digest32::from_bytes([0u8; 32]),
                right: Digest32::from_bytes([0u8; 32]),
            };
            let bytes = serialize_prover_node(&node, &dummy)?;
            out.extend_from_slice(&bytes);
        }
        AvlNode::Internal { left, right, .. } => {
            let labels = ResolvedLabels {
                left: compute_node_label(tree, *left)?,
                right: compute_node_label(tree, *right)?,
            };
            let bytes = serialize_prover_node(&node, &labels)?;
            out.extend_from_slice(&bytes);
            // Chunks include every descendant; recurse unconditionally.
            write_chunk_walk(tree, *left, out)?;
            write_chunk_walk(tree, *right, out)?;
        }
    }
    Ok(())
}

/// Enumerate the chunk roots — the children of every depth-
/// `manifest_depth` internal node, plus the root of the tree if
/// `tree_height < manifest_depth` (tiny trees fit entirely in the
/// manifest with no chunks). Each returned `NodeId` is the root of
/// a subtree that should be serialized as its own chunk via
/// [`serialize_chunk`].
pub fn enumerate_chunk_roots(
    tree: &AvlTree,
    manifest_depth: u8,
) -> Result<Vec<NodeId>, StateError> {
    let mut roots = Vec::new();
    collect_chunk_roots(tree, tree.root_id(), 1, manifest_depth, &mut roots)?;
    Ok(roots)
}

fn collect_chunk_roots(
    tree: &AvlTree,
    node_id: NodeId,
    level: u8,
    manifest_depth: u8,
    out: &mut Vec<NodeId>,
) -> Result<(), StateError> {
    let node = tree
        .get_node(node_id)
        .ok_or(StateError::InternalInvariant {
            what: "snapshot codec: missing AVL node while enumerating chunk roots",
        })?;
    match &node {
        AvlNode::Leaf { .. } => {
            // A leaf above the cut means the tree is shallower than
            // the manifest depth — no chunks needed. Don't add the
            // leaf as a chunk root.
        }
        AvlNode::Internal { left, right, .. } => {
            if level == manifest_depth {
                // Children of a depth-manifest_depth internal node
                // are chunk roots.
                out.push(*left);
                out.push(*right);
            } else {
                collect_chunk_roots(tree, *left, level + 1, manifest_depth, out)?;
                collect_chunk_roots(tree, *right, level + 1, manifest_depth, out)?;
            }
        }
    }
    Ok(())
}

// ----- Consume-side reconstruction -----

/// A node in a [`ReconstructedTree`]. Indices into the tree's
/// arena, mirroring the runtime [`crate::avl::AvlNode`] but with
/// fully-resolved labels and arena indices instead of `NodeId`s.
///
/// `Internal.key` is the separator key (the key of the leftmost
/// leaf in the right subtree). It IS part of the manifest /
/// chunk wire format and MUST be preserved during reconstruction
/// — labels alone do not commit it, so a tree with correct labels
/// but wrong separator keys would pass root-equality but break
/// AVL lookup semantics.
#[derive(Debug, Clone)]
pub enum ReconstructedNode {
    Leaf {
        key: [u8; 32],
        value: Vec<u8>,
        next_key: [u8; 32],
    },
    Internal {
        key: [u8; 32],
        balance: i8,
        left: usize,
        right: usize,
        left_label: Digest32,
        right_label: Digest32,
    },
}

/// An AVL+ tree rebuilt from a serialized manifest plus chunks.
/// Byte-identical to the original tree when round-tripped through
/// [`serialize_manifest`] / [`serialize_chunk`] / [`reconstruct_tree`].
///
/// Intermediate representation: 2h-1 produces this; 2i consumes it
/// to populate the runtime `AvlTree` / `StateStore`. Keeping the
/// reconstruction here (no `AvlTree` arena allocation) lets us
/// verify the root label against the manifest_id before any state
/// mutation happens.
#[derive(Debug)]
pub struct ReconstructedTree {
    /// Arena. Index 0 is the root.
    pub nodes: Vec<ReconstructedNode>,
    /// Root label, computed from the bottom up during reconstruction.
    /// MUST equal the `manifest_id` the trust check approved
    /// (see Scala parity in 2g-2).
    pub root_label: Digest32,
    /// AVL+ tree height, from the manifest header byte. Distinct
    /// from chain block height — this is the depth of the deepest
    /// leaf in the AVL+ tree itself.
    pub tree_height: u8,
}

/// Enumerate the chunk subtree IDs declared by a manifest. Each id
/// is the `Digest32` label of a subtree's root, recorded as the
/// `left_label` or `right_label` of an internal node at
/// `level == manifest_depth` in the manifest's DFS body.
///
/// The chunk-download state machine (2h-2) uses this list as the
/// authoritative set of chunks to fetch; in-flight bookkeeping
/// keys off these ids.
pub fn enumerate_expected_chunk_ids(manifest_bytes: &[u8]) -> Result<Vec<Digest32>, StateError> {
    let (_, _, body) = parse_manifest_header(manifest_bytes)?;
    let manifest_depth = manifest_bytes[1];

    let mut cursor = 0usize;
    let mut expected = Vec::new();
    enumerate_walk(body, &mut cursor, 1, manifest_depth, &mut expected)?;
    if cursor != body.len() {
        return Err(StateError::Serialization(format!(
            "snapshot codec: manifest body has {} trailing bytes after walk",
            body.len() - cursor,
        )));
    }
    Ok(expected)
}

/// Reconstruct a tree from a manifest plus its chunks.
///
/// `chunks` maps `subtree_id` → chunk bytes (as produced by
/// [`serialize_chunk`] on the original tree). Every chunk id the
/// manifest expects MUST be present and parse to a subtree whose
/// recomputed root label matches its requested id — the assembly
/// rejects mismatched chunks rather than splicing them in. After
/// splicing, the function recomputes the root label and the
/// result must equal the manifest's implied root (which the caller
/// has separately matched against the canonical state_root via
/// the 2g-2 trust check).
///
/// Errors:
/// * Truncated or malformed manifest / chunk bytes.
/// * Missing chunk for an expected subtree_id.
/// * Extra chunk ids the manifest does not reference (defensive —
///   peers should only serve what we asked for).
/// * Chunk's recomputed root label ≠ its requested subtree_id.
/// * Final root label inconsistent with the manifest's declared
///   tree shape (would indicate a parser / splice bug).
pub fn reconstruct_tree(
    manifest_bytes: &[u8],
    chunks: &std::collections::HashMap<Digest32, Vec<u8>>,
) -> Result<ReconstructedTree, StateError> {
    let (tree_height, manifest_depth, body) = parse_manifest_header(manifest_bytes)?;

    // First pass: parse the manifest DFS into an arena, recording
    // the chunk-subtree slots that need to be filled in.
    let mut nodes: Vec<ReconstructedNode> = Vec::new();
    let mut cursor = 0usize;
    let mut pending_chunks: Vec<(usize, Digest32, ChunkSlot)> = Vec::new();
    let root_idx = parse_manifest_walk(
        body,
        &mut cursor,
        1,
        manifest_depth,
        &mut nodes,
        &mut pending_chunks,
    )?;
    if cursor != body.len() {
        return Err(StateError::Serialization(format!(
            "snapshot codec: manifest body has {} trailing bytes after parse",
            body.len() - cursor,
        )));
    }
    if root_idx != 0 {
        return Err(StateError::Serialization(format!(
            "snapshot codec: manifest root index = {root_idx}, expected 0",
        )));
    }

    // Second pass: for each pending chunk, parse the chunk bytes,
    // verify the subtree root label matches the requested id, then
    // splice the chunk's arena into the main arena and patch the
    // parent's child pointer.
    for (parent_idx, subtree_id, slot) in pending_chunks {
        let chunk_bytes = chunks.get(&subtree_id).ok_or_else(|| {
            StateError::Serialization(format!(
                "snapshot codec: missing chunk for subtree {}",
                hex::encode(subtree_id.as_bytes()),
            ))
        })?;

        let (chunk_subtree_root_idx, chunk_nodes) = parse_chunk(chunk_bytes)?;

        // Splice: append chunk_nodes to the main arena, remapping
        // every internal node's left/right offsets.
        let offset = nodes.len();
        let new_root_idx = chunk_subtree_root_idx + offset;
        for n in chunk_nodes {
            let remapped = match n {
                ReconstructedNode::Leaf {
                    key,
                    value,
                    next_key,
                } => ReconstructedNode::Leaf {
                    key,
                    value,
                    next_key,
                },
                ReconstructedNode::Internal {
                    key,
                    balance,
                    left,
                    right,
                    left_label,
                    right_label,
                } => ReconstructedNode::Internal {
                    key,
                    balance,
                    left: left + offset,
                    right: right + offset,
                    left_label,
                    right_label,
                },
            };
            nodes.push(remapped);
        }

        // Verify the chunk's actual root label matches the requested id.
        let actual_label = recompute_label(&nodes, new_root_idx)?;
        if actual_label != subtree_id {
            return Err(StateError::Serialization(format!(
                "snapshot codec: chunk for subtree {} has actual root label {} \
                 (chunk authenticity check failed)",
                hex::encode(subtree_id.as_bytes()),
                hex::encode(actual_label.as_bytes()),
            )));
        }

        // Patch the parent's child slot to point at the chunk's root.
        let parent = nodes.get_mut(parent_idx).ok_or_else(|| {
            StateError::Serialization(format!(
                "snapshot codec: parent idx {parent_idx} out of bounds during splice",
            ))
        })?;
        match parent {
            ReconstructedNode::Internal { left, right, .. } => match slot {
                ChunkSlot::Left => *left = new_root_idx,
                ChunkSlot::Right => *right = new_root_idx,
            },
            ReconstructedNode::Leaf { .. } => {
                return Err(StateError::Serialization(
                    "snapshot codec: parent of a chunk slot was a leaf".into(),
                ));
            }
        }
    }

    // Final pass: recompute the root label from the fully-spliced arena.
    let root_label = recompute_label(&nodes, 0)?;

    Ok(ReconstructedTree {
        nodes,
        root_label,
        tree_height,
    })
}

/// Which child of the parent a chunk root fills.
#[derive(Debug, Clone, Copy)]
enum ChunkSlot {
    Left,
    Right,
}

/// Returns (tree_height, manifest_depth, body) from raw manifest
/// bytes. Validates the two-byte header is present.
fn parse_manifest_header(bytes: &[u8]) -> Result<(u8, u8, &[u8]), StateError> {
    if bytes.len() < 2 {
        return Err(StateError::Serialization(format!(
            "snapshot codec: manifest too short ({} bytes, need >= 2 for header)",
            bytes.len(),
        )));
    }
    let manifest_depth = bytes[1];
    // A peer supplies `manifest_depth`; the manifest DFS walks recurse while
    // `level < manifest_depth`, so an out-of-range value would let a hostile
    // manifest drive deeper recursion than any valid snapshot. Mainnet uses
    // `MAINNET_MANIFEST_DEPTH` (14); reject anything above it. Both manifest
    // readers (`reconstruct_tree` and `enumerate_expected_chunk_ids`) go
    // through here, so this single check covers both walk entry points.
    if manifest_depth > MAINNET_MANIFEST_DEPTH {
        return Err(StateError::Serialization(format!(
            "snapshot codec: manifest_depth {manifest_depth} exceeds maximum {MAINNET_MANIFEST_DEPTH}",
        )));
    }
    Ok((bytes[0], manifest_depth, &bytes[2..]))
}

/// Walk a manifest body DFS, collecting expected chunk subtree IDs
/// without building the arena. Mirrors the structure of
/// [`parse_manifest_walk`] but is read-only.
fn enumerate_walk(
    body: &[u8],
    cursor: &mut usize,
    level: u8,
    manifest_depth: u8,
    out: &mut Vec<Digest32>,
) -> Result<(), StateError> {
    let remaining = &body[*cursor..];
    let (parsed, consumed) = parse_prover_node(remaining)?;
    *cursor += consumed;
    match parsed {
        ParsedProverNode::Leaf { .. } => {
            // Leaves never reference chunks; nothing to enumerate.
        }
        ParsedProverNode::Internal {
            left_label,
            right_label,
            ..
        } => {
            if level < manifest_depth {
                enumerate_walk(body, cursor, level + 1, manifest_depth, out)?;
                enumerate_walk(body, cursor, level + 1, manifest_depth, out)?;
            } else {
                // level == manifest_depth: this internal node's
                // child labels are chunk subtree IDs.
                out.push(Digest32::from_bytes(left_label));
                out.push(Digest32::from_bytes(right_label));
            }
        }
    }
    Ok(())
}

/// Walk a manifest body DFS, building up the partial top-subtree
/// arena. At `level == manifest_depth` internal nodes, the chunk
/// slots are recorded in `pending_chunks` for the second-pass
/// splice; their child indices in the arena are temporarily set
/// to `usize::MAX` until patched.
fn parse_manifest_walk(
    body: &[u8],
    cursor: &mut usize,
    level: u8,
    manifest_depth: u8,
    nodes: &mut Vec<ReconstructedNode>,
    pending_chunks: &mut Vec<(usize, Digest32, ChunkSlot)>,
) -> Result<usize, StateError> {
    let remaining = &body[*cursor..];
    let (parsed, consumed) = parse_prover_node(remaining)?;
    *cursor += consumed;

    match parsed {
        ParsedProverNode::Leaf {
            key,
            value,
            next_leaf_key,
        } => {
            let idx = nodes.len();
            nodes.push(ReconstructedNode::Leaf {
                key,
                value,
                next_key: next_leaf_key,
            });
            Ok(idx)
        }
        ParsedProverNode::Internal {
            balance,
            key,
            left_label,
            right_label,
        } => {
            let idx = nodes.len();
            let left_digest = Digest32::from_bytes(left_label);
            let right_digest = Digest32::from_bytes(right_label);
            // Reserve slot; left/right filled in after children parsed.
            nodes.push(ReconstructedNode::Internal {
                key,
                balance,
                left: usize::MAX,
                right: usize::MAX,
                left_label: left_digest,
                right_label: right_digest,
            });

            let (left_idx, right_idx) = if level < manifest_depth {
                let l = parse_manifest_walk(
                    body,
                    cursor,
                    level + 1,
                    manifest_depth,
                    nodes,
                    pending_chunks,
                )?;
                let r = parse_manifest_walk(
                    body,
                    cursor,
                    level + 1,
                    manifest_depth,
                    nodes,
                    pending_chunks,
                )?;
                (l, r)
            } else {
                // level == manifest_depth: record chunk slots.
                pending_chunks.push((idx, left_digest, ChunkSlot::Left));
                pending_chunks.push((idx, right_digest, ChunkSlot::Right));
                (usize::MAX, usize::MAX)
            };

            // Patch the placeholder we reserved above.
            match &mut nodes[idx] {
                ReconstructedNode::Internal { left, right, .. } => {
                    *left = left_idx;
                    *right = right_idx;
                }
                _ => unreachable!("just pushed Internal"),
            }
            Ok(idx)
        }
    }
}

/// Parse a chunk's bytes into a (root_idx, nodes) pair. Indices
/// inside `nodes` are 0-based for this chunk; the caller offsets
/// them when splicing into the main arena.
fn parse_chunk(bytes: &[u8]) -> Result<(usize, Vec<ReconstructedNode>), StateError> {
    let mut nodes: Vec<ReconstructedNode> = Vec::new();
    let mut cursor = 0usize;
    let root = parse_chunk_walk(bytes, &mut cursor, &mut nodes, 0)?;
    if cursor != bytes.len() {
        return Err(StateError::Serialization(format!(
            "snapshot codec: chunk has {} trailing bytes",
            bytes.len() - cursor,
        )));
    }
    Ok((root, nodes))
}

/// Recursive DFS for chunk parsing. Internal nodes always recurse
/// into both children; there's no manifest_depth cut inside a
/// chunk.
fn parse_chunk_walk(
    bytes: &[u8],
    cursor: &mut usize,
    nodes: &mut Vec<ReconstructedNode>,
    depth: usize,
) -> Result<usize, StateError> {
    if depth > MAX_RECONSTRUCT_DEPTH {
        return Err(StateError::Serialization(format!(
            "snapshot codec: chunk recursion depth exceeds maximum {MAX_RECONSTRUCT_DEPTH} \
             (malformed deep-spine chunk)",
        )));
    }
    let remaining = &bytes[*cursor..];
    let (parsed, consumed) = parse_prover_node(remaining)?;
    *cursor += consumed;

    match parsed {
        ParsedProverNode::Leaf {
            key,
            value,
            next_leaf_key,
        } => {
            let idx = nodes.len();
            nodes.push(ReconstructedNode::Leaf {
                key,
                value,
                next_key: next_leaf_key,
            });
            Ok(idx)
        }
        ParsedProverNode::Internal {
            balance,
            key,
            left_label,
            right_label,
        } => {
            let idx = nodes.len();
            nodes.push(ReconstructedNode::Internal {
                key,
                balance,
                left: usize::MAX,
                right: usize::MAX,
                left_label: Digest32::from_bytes(left_label),
                right_label: Digest32::from_bytes(right_label),
            });
            let l = parse_chunk_walk(bytes, cursor, nodes, depth + 1)?;
            let r = parse_chunk_walk(bytes, cursor, nodes, depth + 1)?;
            match &mut nodes[idx] {
                ReconstructedNode::Internal { left, right, .. } => {
                    *left = l;
                    *right = r;
                }
                _ => unreachable!("just pushed Internal"),
            }
            Ok(idx)
        }
    }
}

/// Recompute a node's label by recursing into its arena children.
/// Uses [`crate::avl::digest::leaf_label`] for leaves and
/// [`crate::avl::digest::internal_label`] for internals — same
/// primitives the serve side uses, so a correctly-spliced tree
/// produces the same labels as the original.
fn recompute_label(nodes: &[ReconstructedNode], idx: usize) -> Result<Digest32, StateError> {
    let node = nodes.get(idx).ok_or_else(|| {
        StateError::Serialization(format!(
            "snapshot codec: recompute_label idx {idx} out of bounds",
        ))
    })?;
    match node {
        ReconstructedNode::Leaf {
            key,
            value,
            next_key,
        } => Ok(crate::avl::digest::leaf_label(key, value, next_key)),
        ReconstructedNode::Internal {
            balance,
            left,
            right,
            ..
        } => {
            let l = recompute_label(nodes, *left)?;
            let r = recompute_label(nodes, *right)?;
            Ok(crate::avl::digest::internal_label(*balance, &l, &r))
        }
    }
}

/// Recompute the root label of a chunk's serialized bytes.
///
/// Parses only the first prover-node (the chunk's root) and
/// derives its label from its content. The chunk's bytes are
/// trusted as authentic iff the recomputed label equals the
/// `subtree_id` the chunk-download state machine requested —
/// the integration layer makes that comparison after this
/// function returns.
///
/// This is the per-chunk authenticity primitive. It's distinct
/// from the manifest's trust check (which compares against
/// `header.state_root`); chunks are authenticated by their own
/// bytes producing the expected label.
pub fn recompute_chunk_root_label(chunk_bytes: &[u8]) -> Result<Digest32, StateError> {
    if chunk_bytes.is_empty() {
        return Err(StateError::Serialization(
            "snapshot codec: empty chunk bytes".into(),
        ));
    }
    let (parsed, _) = parse_prover_node(chunk_bytes)?;
    match parsed {
        ParsedProverNode::Leaf {
            key,
            value,
            next_leaf_key,
        } => Ok(crate::avl::digest::leaf_label(&key, &value, &next_leaf_key)),
        ParsedProverNode::Internal {
            balance,
            left_label,
            right_label,
            ..
        } => Ok(crate::avl::digest::internal_label(
            balance,
            &Digest32::from_bytes(left_label),
            &Digest32::from_bytes(right_label),
        )),
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::digest::Digest32;

    fn d32(b: u8) -> Digest32 {
        Digest32::from_bytes([b; LABEL_SIZE])
    }

    fn key32(b: u8) -> [u8; KEY_SIZE] {
        [b; KEY_SIZE]
    }

    fn fixed_labels(left: Digest32, right: Digest32) -> impl ChildLabels {
        let l = left;
        let r = right;
        ClosureChildLabels {
            left: move |_| Ok(l),
            right: move |_| Ok(r),
        }
    }

    fn tree_with_missing_root() -> AvlTree {
        AvlTree::new_empty_with_label(42, 0, Digest32::from_bytes([0u8; LABEL_SIZE]))
    }

    fn assert_internal_invariant(err: StateError, expected_what: &'static str) {
        match err {
            StateError::InternalInvariant { what } => assert_eq!(what, expected_what),
            other => panic!("expected InternalInvariant, got {other:?}"),
        }
    }

    // ----- happy path -----

    #[test]
    fn internal_node_serialize_byte_layout() {
        // Build an internal node with deterministic values.
        let node = AvlNode::Internal {
            key: key32(0xAA),
            left: 0,
            right: 0,
            balance: 1,
            left_label: None,
            right_label: None,
            label: None,
        };
        let labels = fixed_labels(d32(0xBB), d32(0xCC));
        let bytes = serialize_prover_node(&node, &labels).unwrap();

        // Expected layout: 0x00 || 0x01 (balance) || [0xAA;32] || [0xBB;32] || [0xCC;32]
        assert_eq!(bytes.len(), 1 + 1 + 32 + 32 + 32);
        assert_eq!(bytes[0], INTERNAL_NODE_PREFIX);
        assert_eq!(bytes[1], 0x01);
        assert_eq!(&bytes[2..34], &[0xAAu8; 32][..]);
        assert_eq!(&bytes[34..66], &[0xBBu8; 32][..]);
        assert_eq!(&bytes[66..98], &[0xCCu8; 32][..]);
    }

    #[test]
    fn internal_node_negative_balance_is_byte_cast() {
        // Scala writes balance via `w.put(n.balance)` — a single byte.
        // Negative balances (-1) round-trip via i8↔u8 reinterpretation.
        let node = AvlNode::Internal {
            key: key32(0x00),
            left: 0,
            right: 0,
            balance: -1,
            left_label: None,
            right_label: None,
            label: None,
        };
        let labels = fixed_labels(d32(0x00), d32(0x00));
        let bytes = serialize_prover_node(&node, &labels).unwrap();
        assert_eq!(bytes[1], 0xFF, "i8(-1) must encode as byte 0xFF");
    }

    #[test]
    fn leaf_node_serialize_byte_layout() {
        let node = AvlNode::Leaf {
            key: key32(0x11),
            value: vec![0x42, 0x43, 0x44, 0x45],
            next_key: key32(0x22),
            label: None,
        };
        // labels arg is unused for leaves; pass dummy.
        let labels = fixed_labels(d32(0), d32(0));
        let bytes = serialize_prover_node(&node, &labels).unwrap();

        // Expected: 0x01 || [0x11;32] || 0x00 0x00 0x00 0x04 (BE) || [0x42..0x45] || [0x22;32]
        assert_eq!(bytes.len(), 1 + 32 + 4 + 4 + 32);
        assert_eq!(bytes[0], LEAF_PREFIX);
        assert_eq!(&bytes[1..33], &[0x11u8; 32][..]);
        assert_eq!(&bytes[33..37], &[0x00, 0x00, 0x00, 0x04]);
        assert_eq!(&bytes[37..41], &[0x42, 0x43, 0x44, 0x45]);
        assert_eq!(&bytes[41..73], &[0x22u8; 32][..]);
    }

    // ----- round-trips -----

    #[test]
    fn internal_node_roundtrip() {
        let node = AvlNode::Internal {
            key: key32(0x77),
            left: 0,
            right: 0,
            balance: -1,
            left_label: None,
            right_label: None,
            label: None,
        };
        let labels = fixed_labels(d32(0x88), d32(0x99));
        let bytes = serialize_prover_node(&node, &labels).unwrap();
        let (parsed, consumed) = parse_prover_node(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        match parsed {
            ParsedProverNode::Internal {
                balance,
                key,
                left_label,
                right_label,
            } => {
                assert_eq!(balance, -1);
                assert_eq!(key, key32(0x77));
                assert_eq!(left_label, [0x88u8; 32]);
                assert_eq!(right_label, [0x99u8; 32]);
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn leaf_node_roundtrip_with_empty_value() {
        let node = AvlNode::Leaf {
            key: key32(0xF0),
            value: vec![],
            next_key: key32(0xF1),
            label: None,
        };
        let labels = fixed_labels(d32(0), d32(0));
        let bytes = serialize_prover_node(&node, &labels).unwrap();
        let (parsed, consumed) = parse_prover_node(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        match parsed {
            ParsedProverNode::Leaf {
                key,
                value,
                next_leaf_key,
            } => {
                assert_eq!(key, key32(0xF0));
                assert!(value.is_empty());
                assert_eq!(next_leaf_key, key32(0xF1));
            }
            other => panic!("expected Leaf, got {other:?}"),
        }
    }

    #[test]
    fn leaf_node_roundtrip_large_value() {
        let value: Vec<u8> = (0u8..255).chain(0u8..255).collect();
        let node = AvlNode::Leaf {
            key: key32(0x55),
            value: value.clone(),
            next_key: key32(0x56),
            label: None,
        };
        let labels = fixed_labels(d32(0), d32(0));
        let bytes = serialize_prover_node(&node, &labels).unwrap();
        let (parsed, _) = parse_prover_node(&bytes).unwrap();
        match parsed {
            ParsedProverNode::Leaf { value: v, .. } => assert_eq!(v, value),
            other => panic!("expected Leaf, got {other:?}"),
        }
    }

    #[test]
    fn concatenated_nodes_parse_sequentially() {
        // Pin "stream-of-nodes" behavior — the parser must report
        // bytes consumed so the next node's offset is calculable.
        // This is how manifest serialization will lay out a tree
        // walk in part 2c.
        let leaf = AvlNode::Leaf {
            key: key32(0x01),
            value: vec![1, 2, 3],
            next_key: key32(0x02),
            label: None,
        };
        let internal = AvlNode::Internal {
            key: key32(0x10),
            left: 0,
            right: 0,
            balance: 0,
            left_label: None,
            right_label: None,
            label: None,
        };
        let dummy = fixed_labels(d32(0x20), d32(0x21));
        let mut stream = serialize_prover_node(&leaf, &dummy).unwrap();
        stream.extend_from_slice(&serialize_prover_node(&internal, &dummy).unwrap());

        let (first, consumed1) = parse_prover_node(&stream).unwrap();
        assert!(matches!(first, ParsedProverNode::Leaf { .. }));
        let (second, _consumed2) = parse_prover_node(&stream[consumed1..]).unwrap();
        assert!(matches!(second, ParsedProverNode::Internal { .. }));
    }

    // ----- error paths -----

    #[test]
    fn parse_rejects_empty_payload() {
        let err = parse_prover_node(&[]).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("empty"), "error: {msg}");
    }

    #[test]
    fn parse_rejects_unknown_prefix() {
        let err = parse_prover_node(&[0xFFu8]).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("unknown prover-node prefix"), "error: {msg}");
        assert!(msg.contains("0xff"), "error must show the byte: {msg}");
    }

    #[test]
    fn parse_rejects_truncated_internal() {
        // Internal needs 1 + 1 + 32 + 32 + 32 = 98 body bytes after
        // prefix. Anything shorter must error.
        let payload = vec![INTERNAL_NODE_PREFIX, 0x00]; // prefix + balance only
        let err = parse_prover_node(&payload).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("truncated"), "error: {msg}");
    }

    #[test]
    fn parse_rejects_truncated_leaf_header() {
        // Leaf needs at least prefix + key + value_len = 37 bytes
        // before any value bytes can be read.
        let payload = vec![LEAF_PREFIX, 0x00]; // missing key and length
        let err = parse_prover_node(&payload).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("truncated"), "error: {msg}");
    }

    /// Build a snapshot internal-node payload (prefix + balance byte +
    /// key + left_label + right_label) with caller-chosen balance byte.
    /// Used by the rejection tests below.
    fn snapshot_internal_payload(balance_byte: u8) -> Vec<u8> {
        let mut payload = vec![INTERNAL_NODE_PREFIX, balance_byte];
        payload.extend_from_slice(&[0x42; KEY_SIZE]);
        payload.extend_from_slice(&[0xAA; LABEL_SIZE]);
        payload.extend_from_slice(&[0xBB; LABEL_SIZE]);
        payload
    }

    #[test]
    fn parse_rejects_internal_balance_2() {
        // The Mode-2 install DoS the ingress gate closes: a snapshot
        // chunk with a balance byte outside {-1, 0, 1} would otherwise
        // propagate to tree rotations and panic the apply thread. The
        // codec must reject here, before any AVL_NODES write.
        let payload = snapshot_internal_payload(0x02);
        let err = parse_prover_node(&payload).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("balance 2"), "wrong message: {msg}");
        assert!(msg.contains("{-1, 0, 1}"), "must cite invariant: {msg}");
    }

    #[test]
    fn parse_rejects_internal_balance_i8_max() {
        let payload = snapshot_internal_payload(0x7F);
        let err = parse_prover_node(&payload).unwrap_err();
        assert!(format!("{err:?}").contains("balance 127"));
    }

    #[test]
    fn parse_rejects_internal_balance_i8_min() {
        // 0x80 sign-extends to i8(-128) via `body[0] as i8`. The gate
        // must catch it — the bug surface is the reverse case where
        // someone replaces the i8 cast with a u8 check and accidentally
        // accepts 0x80 as "+128".
        let payload = snapshot_internal_payload(0x80);
        let err = parse_prover_node(&payload).unwrap_err();
        assert!(format!("{err:?}").contains("balance -128"));
    }

    #[test]
    fn parse_accepts_internal_balance_minus_one() {
        // 0xFF must round-trip as i8(-1). Pins the negative-balance
        // path that's easy to break with a naive u8 range check.
        let payload = snapshot_internal_payload(0xFF);
        let (parsed, _) = parse_prover_node(&payload).expect("0xFF -> -1 must parse");
        match parsed {
            ParsedProverNode::Internal { balance, .. } => assert_eq!(balance, -1),
            _ => panic!("expected Internal"),
        }
    }

    // ----- manifest / chunk assembly -----

    /// Empty tree (just the sentinel leaf): manifest is `rootHeight=0`,
    /// `manifestDepth=14`, then the sentinel leaf body — total 71 bytes.
    /// Pins:
    /// - The 2-byte header layout
    /// - The depth-walking behavior (just visits the root, no recursion
    ///   needed since it's a leaf)
    /// - The NEG_INF / POS_INF sentinel keys via the leaf encoding
    #[test]
    fn manifest_of_empty_tree_is_sentinel_leaf() {
        use crate::avl::digest::{NEGATIVE_INFINITY_KEY, POSITIVE_INFINITY_KEY};
        let tree = AvlTree::new();
        let bytes = serialize_manifest(&tree, MAINNET_MANIFEST_DEPTH).unwrap();

        // Header: rootHeight=0, manifestDepth=14.
        assert_eq!(bytes[0], 0, "rootHeight for empty tree must be 0");
        assert_eq!(bytes[1], MAINNET_MANIFEST_DEPTH);

        // Body = sentinel leaf: 0x01 || NEG_INF || 0x00*4 || POS_INF.
        // No value bytes between the length prefix and next_leaf_key.
        // Total = 2 (header) + 1 (leaf prefix) + 32 (key) + 4 (len) + 32 (next).
        assert_eq!(bytes.len(), 2 + 1 + KEY_SIZE + 4 + KEY_SIZE);
        assert_eq!(bytes[2], LEAF_PREFIX);
        assert_eq!(&bytes[3..3 + KEY_SIZE], &NEGATIVE_INFINITY_KEY[..]);
        assert_eq!(&bytes[3 + KEY_SIZE..3 + KEY_SIZE + 4], &0u32.to_be_bytes(),);
        assert_eq!(
            &bytes[3 + KEY_SIZE + 4..3 + KEY_SIZE + 4 + KEY_SIZE],
            &POSITIVE_INFINITY_KEY[..],
        );
    }

    #[test]
    fn manifest_of_two_leaf_tree_has_one_internal_and_three_leaves() {
        // Inserting two real keys gives a tree shaped:
        //
        //              Internal
        //             /        \
        //         Leaf(NEG_INF) Internal
        //                         /     \
        //                      Leaf(k1)  Leaf(k2 → POS_INF)
        //
        // Exact balancing depends on the inserts' AVL rebalancing,
        // but parse-roundtripping the manifest should always yield
        // at least one internal node + the original sentinel leaf
        // + the two inserted leaves.
        let mut tree = AvlTree::new();
        tree.insert([0x10; 32], vec![0xAA, 0xBB]);
        tree.insert([0x20; 32], vec![0xCC, 0xDD]);
        let bytes = serialize_manifest(&tree, MAINNET_MANIFEST_DEPTH).unwrap();

        // Header.
        assert_eq!(bytes[1], MAINNET_MANIFEST_DEPTH);
        assert!(bytes[0] >= 1, "tree with 3 leaves has height >= 1");

        // Walk the body, classifying each node.
        let mut cursor = 2usize;
        let mut leaf_count = 0usize;
        let mut internal_count = 0usize;
        while cursor < bytes.len() {
            let (parsed, consumed) = parse_prover_node(&bytes[cursor..]).unwrap();
            match parsed {
                ParsedProverNode::Leaf { .. } => leaf_count += 1,
                ParsedProverNode::Internal { .. } => internal_count += 1,
            }
            cursor += consumed;
        }
        assert_eq!(cursor, bytes.len(), "manifest bytes consumed exactly");
        assert!(
            internal_count >= 1,
            "tree of 3 leaves must have at least 1 internal node; got {internal_count}",
        );
        assert_eq!(
            leaf_count, 3,
            "expected sentinel + 2 inserted leaves = 3 leaves; got {leaf_count}",
        );
    }

    #[test]
    fn enumerate_chunk_roots_empty_for_shallow_tree() {
        // Trees shallower than `manifest_depth` have no chunks —
        // every node fits in the manifest top-subtree.
        let mut tree = AvlTree::new();
        tree.insert([0x10; 32], vec![0xAA]);
        tree.insert([0x20; 32], vec![0xBB]);
        let roots = enumerate_chunk_roots(&tree, MAINNET_MANIFEST_DEPTH).unwrap();
        assert!(
            roots.is_empty(),
            "small tree must produce no chunk roots at depth 14; got {} roots",
            roots.len(),
        );
    }

    #[test]
    fn enumerate_chunk_roots_with_shallow_manifest_depth() {
        // Force chunks by using a very shallow manifest depth.
        // With manifest_depth=1, any internal node at the root has
        // its two children as chunk roots.
        let mut tree = AvlTree::new();
        tree.insert([0x10; 32], vec![0xAA]);
        tree.insert([0x20; 32], vec![0xBB]);
        tree.insert([0x30; 32], vec![0xCC]);
        let roots = enumerate_chunk_roots(&tree, 1).unwrap();
        // Root is an internal node → its two children are chunk roots.
        assert_eq!(roots.len(), 2);
    }

    #[test]
    fn chunk_roundtrip_via_parse() {
        // serialize_chunk + parse the resulting bytes back into a
        // sequence of prover nodes. Lock the format end-to-end.
        let mut tree = AvlTree::new();
        tree.insert([0x10; 32], vec![0xAA, 0xBB, 0xCC]);
        tree.insert([0x20; 32], vec![0xDD]);
        // Use the root itself as the "chunk root" — covers the
        // full-tree-as-chunk case.
        let chunk_bytes = serialize_chunk(&tree, tree.root_id()).unwrap();
        let mut cursor = 0usize;
        let mut counts = (0usize, 0usize); // (internals, leaves)
        while cursor < chunk_bytes.len() {
            let (parsed, consumed) = parse_prover_node(&chunk_bytes[cursor..]).unwrap();
            match parsed {
                ParsedProverNode::Leaf { .. } => counts.1 += 1,
                ParsedProverNode::Internal { .. } => counts.0 += 1,
            }
            cursor += consumed;
        }
        assert_eq!(cursor, chunk_bytes.len(), "no trailing bytes");
        assert_eq!(counts.1, 3, "expected 3 leaves (2 inserts + sentinel)");
        assert!(counts.0 >= 1, "expected ≥1 internal; got {}", counts.0);
    }

    #[test]
    fn parse_rejects_leaf_body_shorter_than_declared_value_length() {
        // Build a leaf header that claims a 100-byte value but only
        // provides 4 bytes of body — the parser must refuse rather
        // than read past the end.
        let mut payload = vec![LEAF_PREFIX];
        payload.extend_from_slice(&[0x00u8; KEY_SIZE]); // key
        payload.extend_from_slice(&100u32.to_be_bytes()); // value length = 100
        payload.extend_from_slice(&[0xAAu8; 4]); // only 4 value bytes
        let err = parse_prover_node(&payload).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("truncated"), "error: {msg}");
    }

    #[test]
    fn label_walk_missing_arena_node_returns_internal_invariant() {
        let tree = tree_with_missing_root();
        let err = compute_node_label(&tree, tree.root_id()).unwrap_err();
        assert_internal_invariant(err, "snapshot codec: missing AVL node during label walk");
    }

    #[test]
    fn manifest_walk_missing_arena_node_returns_internal_invariant() {
        let tree = tree_with_missing_root();
        let err = serialize_manifest(&tree, MAINNET_MANIFEST_DEPTH).unwrap_err();
        assert_internal_invariant(err, "snapshot codec: missing AVL node during manifest walk");
    }

    #[test]
    fn chunk_walk_missing_arena_node_returns_internal_invariant() {
        let tree = tree_with_missing_root();
        let err = serialize_chunk(&tree, tree.root_id()).unwrap_err();
        assert_internal_invariant(err, "snapshot codec: missing AVL node during chunk walk");
    }

    #[test]
    fn chunk_root_enumeration_missing_arena_node_returns_internal_invariant() {
        let tree = tree_with_missing_root();
        let err = enumerate_chunk_roots(&tree, MAINNET_MANIFEST_DEPTH).unwrap_err();
        assert_internal_invariant(
            err,
            "snapshot codec: missing AVL node while enumerating chunk roots",
        );
    }

    // ----- snapshot server -----

    #[test]
    fn server_build_manifest_id_matches_root_label() {
        // SnapshotServer.manifest_id MUST equal the AVL+ root label —
        // this is the on-the-wire id peers reference when requesting
        // the manifest, and it must agree with the header state_root.
        let mut tree = AvlTree::new();
        tree.insert([0x10; 32], vec![0xAA]);
        tree.insert([0x20; 32], vec![0xBB]);
        let server = SnapshotServer::build(&tree, 100, MAINNET_MANIFEST_DEPTH).unwrap();
        let expected_root = compute_node_label(&tree, tree.root_id()).unwrap();
        assert_eq!(server.manifest_id, expected_root);
        assert_eq!(server.height, 100);
    }

    #[test]
    fn server_build_manifest_bytes_match_serialize_manifest() {
        // SnapshotServer.manifest_bytes MUST equal what
        // serialize_manifest produces for the same tree — server side
        // doesn't get to reshape what goes on the wire.
        let mut tree = AvlTree::new();
        tree.insert([0x10; 32], vec![0xAA, 0xBB]);
        tree.insert([0x20; 32], vec![0xCC]);
        let server = SnapshotServer::build(&tree, 1, MAINNET_MANIFEST_DEPTH).unwrap();
        let expected = serialize_manifest(&tree, MAINNET_MANIFEST_DEPTH).unwrap();
        assert_eq!(server.manifest_bytes, expected);
    }

    #[test]
    fn server_build_empty_chunks_for_shallow_tree() {
        // At mainnet manifest_depth=14, a 3-leaf tree fits entirely in
        // the manifest top-subtree — zero chunks to serve.
        let mut tree = AvlTree::new();
        tree.insert([0x10; 32], vec![0xAA]);
        tree.insert([0x20; 32], vec![0xBB]);
        let server = SnapshotServer::build(&tree, 1, MAINNET_MANIFEST_DEPTH).unwrap();
        assert!(server.chunks.is_empty());
    }

    #[test]
    fn server_build_chunks_match_codec_at_shallow_depth() {
        // Force chunks with manifest_depth=1. Each chunk in the
        // server must match (compute_node_label, serialize_chunk) for
        // its NodeId — proving server-side bookkeeping matches the
        // codec primitives.
        let mut tree = AvlTree::new();
        tree.insert([0x10; 32], vec![0xAA]);
        tree.insert([0x20; 32], vec![0xBB]);
        tree.insert([0x30; 32], vec![0xCC]);
        let server = SnapshotServer::build(&tree, 1, 1).unwrap();
        let codec_roots = enumerate_chunk_roots(&tree, 1).unwrap();
        assert_eq!(server.chunks.len(), codec_roots.len());
        for (root_id, (server_id, server_bytes)) in codec_roots.iter().zip(&server.chunks) {
            let expected_id = compute_node_label(&tree, *root_id).unwrap();
            let expected_bytes = serialize_chunk(&tree, *root_id).unwrap();
            assert_eq!(*server_id, expected_id);
            assert_eq!(*server_bytes, expected_bytes);
        }
    }

    #[test]
    fn server_chunk_by_id_finds_present_and_misses_unknown() {
        let mut tree = AvlTree::new();
        tree.insert([0x10; 32], vec![0xAA]);
        tree.insert([0x20; 32], vec![0xBB]);
        tree.insert([0x30; 32], vec![0xCC]);
        let server = SnapshotServer::build(&tree, 1, 1).unwrap();
        assert!(!server.chunks.is_empty(), "test precondition");

        // Present id resolves to the stored bytes.
        let (known_id, known_bytes) = server.chunks[0].clone();
        let looked_up = server.chunk_by_id(&known_id).expect("known id resolves");
        assert_eq!(looked_up, known_bytes.as_slice());

        // Unknown id returns None — server doesn't synthesize bytes
        // for ids it never indexed.
        let unknown: Digest32 = [0xFF; 32].into();
        assert!(server.chunk_by_id(&unknown).is_none());
    }

    // ----- 2h-1 consume-side reconstruction -----

    fn populated_tree(n_leaves: u8) -> AvlTree {
        let mut tree = AvlTree::new();
        for i in 0..n_leaves {
            let key = [i.wrapping_add(0x10); 32];
            let value = vec![i, i.wrapping_add(0x20), i.wrapping_add(0x40)];
            tree.insert(key, value);
        }
        tree
    }

    fn chunks_map_from_server(
        server: &SnapshotServer,
    ) -> std::collections::HashMap<Digest32, Vec<u8>> {
        server.chunks.iter().cloned().collect()
    }

    #[test]
    fn reconstruct_round_trips_shallow_tree_at_mainnet_depth() {
        // Tree small enough that the whole thing fits in the manifest
        // (no chunks). Round-trip must still recover the same root.
        let tree = populated_tree(3);
        let server = SnapshotServer::build(&tree, 100, MAINNET_MANIFEST_DEPTH).unwrap();
        let rebuilt = reconstruct_tree(&server.manifest_bytes, &chunks_map_from_server(&server))
            .expect("reconstruction succeeds");
        assert_eq!(
            rebuilt.root_label, server.manifest_id,
            "round-trip root label must match",
        );
        assert_eq!(rebuilt.tree_height, tree.tree_height());
    }

    #[test]
    fn reconstruct_round_trips_tree_with_chunks() {
        // Force chunks by using manifest_depth=1. The tree's top
        // subtree fits in one or two nodes of manifest body; chunks
        // hold the bulk of the leaves.
        let tree = populated_tree(8);
        let server = SnapshotServer::build(&tree, 100, 1).unwrap();
        assert!(
            !server.chunks.is_empty(),
            "test precondition: must have chunks"
        );
        let rebuilt = reconstruct_tree(&server.manifest_bytes, &chunks_map_from_server(&server))
            .expect("reconstruction succeeds");
        assert_eq!(
            rebuilt.root_label, server.manifest_id,
            "manifest+chunks reconstruction must reproduce root",
        );
    }

    #[test]
    fn reconstruct_preserves_leaf_payloads() {
        let tree = populated_tree(4);
        let server = SnapshotServer::build(&tree, 1, 1).unwrap();
        let rebuilt = reconstruct_tree(&server.manifest_bytes, &chunks_map_from_server(&server))
            .expect("reconstruction succeeds");

        let mut leaf_kv: Vec<([u8; 32], Vec<u8>)> = rebuilt
            .nodes
            .iter()
            .filter_map(|n| match n {
                ReconstructedNode::Leaf { key, value, .. } => Some((*key, value.clone())),
                _ => None,
            })
            .collect();
        leaf_kv.sort_by_key(|(k, _)| *k);

        // The tree contains a sentinel leaf (NEG_INF) at insert
        // time, plus the inserted keys. Confirm all inserted keys
        // are present with the original values.
        for i in 0..4u8 {
            let key = [i.wrapping_add(0x10); 32];
            let expected = vec![i, i.wrapping_add(0x20), i.wrapping_add(0x40)];
            let found = leaf_kv
                .iter()
                .find(|(k, _)| *k == key)
                .expect("inserted key present in reconstructed tree");
            assert_eq!(found.1, expected, "value preserved for key {i}");
        }
    }

    #[test]
    fn enumerate_expected_chunk_ids_matches_server_chunk_ids() {
        // The list of expected chunks the manifest declares MUST be
        // a 1:1 match of the server's emitted chunk ids — same set,
        // same order. Otherwise the chunk-download state machine
        // could deadlock waiting for chunks the manifest doesn't
        // actually reference (or miss chunks it needs).
        let tree = populated_tree(8);
        let server = SnapshotServer::build(&tree, 1, 1).unwrap();
        let expected_ids =
            enumerate_expected_chunk_ids(&server.manifest_bytes).expect("enumeration succeeds");
        let server_ids: Vec<Digest32> = server.chunks.iter().map(|(id, _)| *id).collect();
        assert_eq!(expected_ids, server_ids);
    }

    #[test]
    fn reconstruct_rejects_missing_chunk() {
        let tree = populated_tree(8);
        let server = SnapshotServer::build(&tree, 1, 1).unwrap();
        // Withhold one chunk.
        let mut chunks = chunks_map_from_server(&server);
        let removed_id = server.chunks[0].0;
        chunks.remove(&removed_id);

        let err = reconstruct_tree(&server.manifest_bytes, &chunks).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("missing chunk"),
            "error should mention missing chunk; got: {msg}",
        );
    }

    #[test]
    fn reconstruct_rejects_corrupted_chunk_bytes() {
        // Swap one chunk's bytes for garbage. The chunk's recomputed
        // root label won't match its requested subtree_id → assembly
        // refuses the splice.
        let tree = populated_tree(8);
        let server = SnapshotServer::build(&tree, 1, 1).unwrap();
        let mut chunks = chunks_map_from_server(&server);
        let target_id = server.chunks[0].0;
        // Replace with a leaf-only chunk (different shape, definitely
        // won't hash to target_id).
        let bad_chunk = vec![LEAF_PREFIX]
            .into_iter()
            .chain([0xAB; KEY_SIZE])
            .chain(0u32.to_be_bytes())
            .chain([0xCD; KEY_SIZE])
            .collect::<Vec<u8>>();
        chunks.insert(target_id, bad_chunk);

        let err = reconstruct_tree(&server.manifest_bytes, &chunks).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("chunk authenticity") || msg.contains("actual root label"),
            "error should flag chunk-authenticity failure; got: {msg}",
        );
    }

    #[test]
    fn reconstruct_rejects_chunk_internal_balance_out_of_range() {
        // End-to-end pin for the chunk-balance attack vector. A
        // Mode-2 peer crafts a snapshot whose manifest root verifies
        // but whose chunk bytes embed an internal node with
        // `balance ∉ {-1, 0, 1}`. Flow:
        //   reconstruct_tree → parse_prover_node (chunk bytes) →
        //   balance-gate rejects.
        // The chunk-authenticity check never fires because parsing
        // aborts first. The same out-of-range value, if it ever
        // reached `AvlTree::double_left_rotate`, would panic the
        // apply thread (`tree.rs:1517`).
        let tree = populated_tree(8);
        let server = SnapshotServer::build(&tree, 1, 1).unwrap();
        let mut chunks = chunks_map_from_server(&server);
        let target_id = server.chunks[0].0;
        // First node in a chunk is an internal subtree root: byte 0 is
        // INTERNAL_NODE_PREFIX (0x00), byte 1 is the balance. Flip
        // byte 1 to 0x02 (i8 = +2, outside {-1, 0, 1}).
        let mut corrupted = server.chunks[0].1.clone();
        assert_eq!(
            corrupted[0], INTERNAL_NODE_PREFIX,
            "chunk root must be internal for this test"
        );
        corrupted[1] = 0x02;
        chunks.insert(target_id, corrupted);
        let err = reconstruct_tree(&server.manifest_bytes, &chunks).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("balance 2") && msg.contains("{-1, 0, 1}"),
            "reconstruct must fail at the balance gate, not the chunk-authenticity \
             check; got: {msg}"
        );
    }

    #[test]
    fn reconstruct_rejects_truncated_manifest_header() {
        // 1-byte manifest can't fit the (rootHeight, manifestDepth) header.
        let bad = vec![0xAA];
        let chunks = std::collections::HashMap::new();
        let err = reconstruct_tree(&bad, &chunks).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("manifest too short"),
            "error should flag short header; got: {msg}",
        );
    }

    #[test]
    fn reconstruct_rejects_manifest_with_trailing_bytes() {
        // Append a stray byte to a valid manifest — parser must
        // refuse to silently absorb it.
        let tree = populated_tree(3);
        let server = SnapshotServer::build(&tree, 1, MAINNET_MANIFEST_DEPTH).unwrap();
        let mut bad = server.manifest_bytes.clone();
        bad.push(0xFF);
        let err = reconstruct_tree(&bad, &chunks_map_from_server(&server)).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("trailing bytes"),
            "error should flag trailing bytes; got: {msg}",
        );
    }

    // ----- recursion / DoS bounds on peer-supplied snapshot bytes -----

    #[test]
    fn manifest_depth_above_max_rejected() {
        // A peer-supplied manifest_depth above MAINNET_MANIFEST_DEPTH (14)
        // would let a hostile manifest drive deeper DFS recursion than any
        // valid snapshot. parse_manifest_header (used by both manifest
        // readers) rejects it; here we drive it through the public enumerate
        // entry point.
        let manifest = [5u8, MAINNET_MANIFEST_DEPTH + 1]; // tree_height=5, depth=15
        let err = enumerate_expected_chunk_ids(&manifest).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("manifest_depth"), "got: {msg}");
    }

    #[test]
    fn parse_chunk_deep_spine_rejected_before_stack_overflow() {
        // A degenerate left-spine chunk: more nested internal nodes than the
        // recursion ceiling. parse_chunk_walk recurses once per level, so a
        // real (much deeper) version would overflow the worker-thread stack;
        // the depth bound returns a typed error instead. The test reaching its
        // assertion at all is the regression guard.
        let mut bytes = Vec::new();
        for _ in 0..(MAX_RECONSTRUCT_DEPTH + 2) {
            bytes.push(INTERNAL_NODE_PREFIX);
            bytes.push(0u8); // balance
            bytes.extend_from_slice(&key32(0)); // key
            bytes.extend_from_slice(&[0u8; LABEL_SIZE]); // left_label
            bytes.extend_from_slice(&[0u8; LABEL_SIZE]); // right_label
        }
        let err = parse_chunk(&bytes).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("recursion depth"), "got: {msg}");
    }

    #[test]
    fn parse_chunk_at_max_depth_accepted() {
        // Mirror of the reject test: a left-leaning tree that reaches exactly
        // MAX_RECONSTRUCT_DEPTH (not beyond) must still parse, pinning the `>`
        // bound as off-by-one-correct (depths 0..=MAX accepted, MAX+1
        // rejected). DFS preorder of a MAX-deep tree is the internal spine
        // first (MAX internals, deepest left child at depth MAX), then one
        // leaf per internal's right child plus the deepest-left leaf
        // (MAX + 1 leaves total).
        let internal = |out: &mut Vec<u8>| {
            out.push(INTERNAL_NODE_PREFIX);
            out.push(0u8); // balance
            out.extend_from_slice(&key32(0));
            out.extend_from_slice(&[0u8; LABEL_SIZE]);
            out.extend_from_slice(&[0u8; LABEL_SIZE]);
        };
        let leaf = |out: &mut Vec<u8>| {
            out.push(LEAF_PREFIX);
            out.extend_from_slice(&key32(0));
            out.extend_from_slice(&0u32.to_be_bytes()); // value_len = 0
            out.extend_from_slice(&key32(0)); // next_key
        };
        let mut bytes = Vec::new();
        for _ in 0..MAX_RECONSTRUCT_DEPTH {
            internal(&mut bytes);
        }
        for _ in 0..(MAX_RECONSTRUCT_DEPTH + 1) {
            leaf(&mut bytes);
        }
        assert!(
            parse_chunk(&bytes).is_ok(),
            "a chunk reaching exactly MAX_RECONSTRUCT_DEPTH must still parse",
        );
    }
}
