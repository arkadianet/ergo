//! Manifest / chunk framing: produce-side tree walks
//! ([`serialize_manifest`] / [`serialize_chunk`] /
//! [`enumerate_chunk_roots`]) and consume-side reconstruction from
//! peer-supplied bytes ([`reconstruct_tree`] and its
//! depth-guarded parse walks).
//!
//! Sibling of `mod.rs`; pure impl relocation.

use crate::avl::digest::{internal_label, leaf_label};
use crate::avl::node::AvlNode;
use crate::avl::node::NodeId;
use crate::avl::tree::AvlTree;
use crate::store::StateError;
use ergo_primitives::digest::Digest32;

use super::{
    parse_prover_node, serialize_prover_node, ChildLabels, ParsedProverNode,
    MAINNET_MANIFEST_DEPTH, MAX_RECONSTRUCT_DEPTH,
};

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
pub(super) fn compute_node_label(tree: &AvlTree, node_id: NodeId) -> Result<Digest32, StateError> {
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
pub(super) fn parse_chunk(bytes: &[u8]) -> Result<(usize, Vec<ReconstructedNode>), StateError> {
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
