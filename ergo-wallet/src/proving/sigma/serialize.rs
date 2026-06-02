//! Phase 3b — serialize the completed tree into proof bytes matching
//! the verifier's read order. The root challenge is already written
//! by the caller; this writer emits subtree bytes after that.

use super::tree::{Completed, CompletedNode};

// ---------------------------------------------------------------------------
// Phase 3b: serialization (depth-first, matching verifier read order)
// ---------------------------------------------------------------------------

/// Serialize the completed tree into proof bytes (after the root challenge).
///
/// Verifier read order for `parse_and_compute_challenges`:
/// - Root: root_challenge already written by caller (first 24 bytes of proof).
/// - AND node: recurse into each child (no challenge bytes — children share parent's).
/// - OR node: for children 0..n-2, write child_challenge(24B) then recurse;
///   for child n-1, recurse only (verifier recovers challenge via XOR).
/// - Threshold: write (n-k) polynomial coefficients (each 24B), then recurse
///   into each child in order (no per-child challenge bytes).
/// - Schnorr or DHT leaf: write z(32B).
pub(super) fn serialize_tree(tree: &Completed, out: &mut Vec<u8>) {
    match &tree.node {
        CompletedNode::Schnorr { z_bytes } => {
            out.extend_from_slice(z_bytes);
        }
        CompletedNode::Dht { z_bytes } => {
            out.extend_from_slice(z_bytes);
        }
        CompletedNode::And { children } => {
            for child in children {
                serialize_tree(child, out);
            }
        }
        CompletedNode::Or { children } => {
            let n = children.len();
            for (i, child) in children.iter().enumerate() {
                if i < n - 1 {
                    // Write the child's challenge before its subtree.
                    out.extend_from_slice(&child.challenge);
                }
                serialize_tree(child, out);
            }
        }
        CompletedNode::Threshold {
            children,
            poly_more_coeffs,
        } => {
            // Write (n-k) polynomial coefficients first (coeff0 = root challenge, implicit).
            for coeff in poly_more_coeffs {
                out.extend_from_slice(coeff);
            }
            // Then recurse into each child (verifier evaluates Q to recover challenges).
            for child in children {
                serialize_tree(child, out);
            }
        }
    }
}
