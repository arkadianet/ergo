//! Phase 2 — serialize the commitment tree for Fiat-Shamir hashing.
//! Mirrors `fiat_shamir_tree_to_bytes` in the verifier; the prover and
//! verifier MUST produce identical bytes for the root challenge to
//! match.

use ergo_sigma::dht::build_prove_dht_ergo_tree;
use ergo_sigma::schnorr::build_prove_dlog_ergo_tree;

use super::tree::ProverTree;

// ---------------------------------------------------------------------------
// Phase 2: Fiat-Shamir bytes (commitment tree serialization for hashing)
// ---------------------------------------------------------------------------

/// Serialize the full commitment tree for Fiat-Shamir hashing.
/// Mirrors `fiat_shamir_tree_to_bytes` in the verifier.
pub(super) fn fiat_shamir_bytes(tree: &ProverTree) -> Vec<u8> {
    const NODE_PREFIX: u8 = 0;
    const LEAF_PREFIX: u8 = 1;
    const AND_TAG: u8 = 0;
    const OR_TAG: u8 = 1;
    const THRESHOLD_TAG: u8 = 2;

    let mut buf = Vec::new();
    match tree {
        ProverTree::Schnorr { pk, leaf } => {
            let prop_bytes = build_prove_dlog_ergo_tree(pk);
            let cb = leaf.commit_bytes();
            buf.push(LEAF_PREFIX);
            buf.extend_from_slice(&(prop_bytes.len() as i16).to_be_bytes());
            buf.extend_from_slice(&prop_bytes);
            buf.extend_from_slice(&(cb.len() as i16).to_be_bytes());
            buf.extend_from_slice(cb);
        }
        ProverTree::Dht { g, h, u, v, leaf } => {
            let prop_bytes = build_prove_dht_ergo_tree(g, h, u, v);
            let cb = leaf.commit_bytes();
            buf.push(LEAF_PREFIX);
            buf.extend_from_slice(&(prop_bytes.len() as i16).to_be_bytes());
            buf.extend_from_slice(&prop_bytes);
            buf.extend_from_slice(&(cb.len() as i16).to_be_bytes());
            buf.extend_from_slice(cb);
        }
        ProverTree::And { children, .. } => {
            buf.push(NODE_PREFIX);
            buf.push(AND_TAG);
            buf.extend_from_slice(&(children.len() as i16).to_be_bytes());
            for c in children {
                buf.extend_from_slice(&fiat_shamir_bytes(c));
            }
        }
        ProverTree::Or { children, .. } => {
            buf.push(NODE_PREFIX);
            buf.push(OR_TAG);
            buf.extend_from_slice(&(children.len() as i16).to_be_bytes());
            for c in children {
                buf.extend_from_slice(&fiat_shamir_bytes(c));
            }
        }
        ProverTree::Threshold { k, children, .. } => {
            buf.push(NODE_PREFIX);
            buf.push(THRESHOLD_TAG);
            buf.push(*k as u8);
            buf.extend_from_slice(&(children.len() as i16).to_be_bytes());
            for c in children {
                buf.extend_from_slice(&fiat_shamir_bytes(c));
            }
        }
    }
    buf
}
