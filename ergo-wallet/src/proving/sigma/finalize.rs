//! Phase 3a — propagate challenges into the prover tree and finalize
//! per-leaf `z` bytes.
//!
//! - AND children inherit the parent challenge unchanged.
//! - OR's real child challenge is parent ⊕ XOR over simulated siblings'
//!   challenges. The simulated siblings keep their pre-assigned
//!   challenges.
//! - Threshold reconstructs Q (degree n-k) over GF(2^192) with
//!   `Q(0) = root_challenge` plus the simulated children's
//!   `(position, challenge)` constraints; real children read
//!   `Q(position)`. The `(n-k)` non-zero-degree coefficients are
//!   carried into the completed node for serialization.
//! - Real leaves emit `z = r + e * x mod q`.
//! - Simulated and supplied-proof leaves emit their pre-chosen `z`.

use ergo_sigma::SOUNDNESS_BYTES;

use crate::error::WalletError;

use super::crypto::{challenge_to_scalar, xor_bytes};
use super::tree::{Completed, CompletedNode, LeafState, ProverTree};
use super::{COST_PER_LEAF, COST_PER_NODE};

/// Propagate `challenge` into `tree`, finalize real leaves, return completed tree + raw cost.
pub(super) fn complete_tree(
    tree: ProverTree,
    challenge: [u8; SOUNDNESS_BYTES],
) -> Result<(Completed, u64), WalletError> {
    match tree {
        ProverTree::Schnorr { leaf, .. } => {
            let (z_bytes, leaf_cost) = finalize_leaf(leaf, &challenge)?;
            Ok((
                Completed {
                    challenge,
                    node: CompletedNode::Schnorr { z_bytes },
                },
                leaf_cost + COST_PER_LEAF,
            ))
        }

        ProverTree::Dht { leaf, .. } => {
            let (z_bytes, leaf_cost) = finalize_leaf(leaf, &challenge)?;
            Ok((
                Completed {
                    challenge,
                    node: CompletedNode::Dht { z_bytes },
                },
                leaf_cost + COST_PER_LEAF,
            ))
        }

        ProverTree::And { children, .. } => {
            // AND: all children receive the same challenge as the parent.
            let mut completed = Vec::with_capacity(children.len());
            let mut total_cost = COST_PER_NODE;
            for child in children {
                let (c, cost) = complete_tree(child, challenge)?;
                completed.push(c);
                total_cost += cost;
            }
            Ok((
                Completed {
                    challenge,
                    node: CompletedNode::And {
                        children: completed,
                    },
                },
                total_cost,
            ))
        }

        ProverTree::Or { children, .. } => {
            // OR challenge assignment:
            //   real_child_challenge = parent_challenge ⊕ XOR(all simulated siblings)
            //   simulated children: keep their pre-assigned challenge
            //
            // Note: get_sim_challenge returns None for REAL subtrees and Some for fully-simulated.
            // We accumulate XOR of all simulated children into xor_acc starting from parent challenge.
            let mut xor_acc = challenge;
            let sim_challenges: Vec<Option<[u8; SOUNDNESS_BYTES]>> =
                children.iter().map(get_sim_challenge).collect();
            for sc in sim_challenges.iter().flatten() {
                xor_bytes(&mut xor_acc, sc);
            }
            let real_child_ch = xor_acc; // = parent ⊕ XOR(all simulated)

            let mut completed = Vec::with_capacity(children.len());
            let mut total_cost = COST_PER_NODE;
            for (child, sim_ch) in children.into_iter().zip(sim_challenges) {
                let child_ch = sim_ch.unwrap_or(real_child_ch);
                let (c, cost) = complete_tree(child, child_ch)?;
                completed.push(c);
                total_cost += cost;
            }
            Ok((
                Completed {
                    challenge,
                    node: CompletedNode::Or {
                        children: completed,
                    },
                },
                total_cost,
            ))
        }

        ProverTree::Threshold {
            k: _,
            children,
            sim_challenges,
            ..
        } => {
            // Threshold challenge assignment via Lagrange interpolation over GF(2^192).
            //
            // We have (n-k) simulated branches with pre-assigned challenges.
            // Use Gf2_192Poly::interpolate to construct polynomial Q such that:
            //   Q(0) = root_challenge
            //   Q(sim_idx+1) = sim_challenge  for each simulated branch
            //
            // The verifier reads (n-k) coefficient bytes via to_bytes() and evaluates
            // Q at positions 1..=n to recover each child's challenge.
            use gf2_192::gf2_192::Gf2_192;
            use gf2_192::gf2_192poly::Gf2_192Poly;

            let n = children.len();

            // interpolate(points, values, value_at_zero):
            //   points = x-coordinates (non-zero u8 values, distinct)
            //   values = y-values at those points
            //   value_at_zero = Q(0) = root_challenge
            let value_at_zero = Gf2_192::from(challenge);
            let interp_points: Vec<u8> = sim_challenges
                .iter()
                .map(|(idx, _)| (idx + 1) as u8)
                .collect();
            let interp_values: Vec<Gf2_192> = sim_challenges
                .iter()
                .map(|(_, ch)| Gf2_192::from(*ch))
                .collect();

            let poly = Gf2_192Poly::interpolate(&interp_points, &interp_values, value_at_zero)
                .map_err(|_| {
                    WalletError::MissingSecret("threshold Lagrange interpolation failed".into())
                })?;

            // poly.to_bytes() returns the (n-k) non-zero-degree coefficients, each 24 bytes.
            let poly_bytes = poly.to_bytes();
            // Split into per-coefficient arrays.
            let poly_more_coeffs: Vec<[u8; SOUNDNESS_BYTES]> = poly_bytes
                .chunks_exact(SOUNDNESS_BYTES)
                .map(|c| c.try_into().expect("chunk is exactly SOUNDNESS_BYTES"))
                .collect();

            // Build child challenge lookup: simulated → their pre-assigned challenge.
            let sim_map: std::collections::HashMap<usize, [u8; SOUNDNESS_BYTES]> =
                sim_challenges.iter().cloned().collect();

            let mut completed = Vec::with_capacity(n);
            let mut total_cost = COST_PER_NODE;

            for (i, child) in children.into_iter().enumerate() {
                let child_ch: [u8; SOUNDNESS_BYTES] = if let Some(&sc) = sim_map.get(&i) {
                    sc
                } else {
                    // Real branch: evaluate Q at (i+1).
                    let y = poly.evaluate((i + 1) as u8);
                    y.into()
                };
                let (c, cost) = complete_tree(child, child_ch)?;
                completed.push(c);
                total_cost += cost;
            }

            Ok((
                Completed {
                    challenge,
                    node: CompletedNode::Threshold {
                        children: completed,
                        poly_more_coeffs,
                    },
                },
                total_cost,
            ))
        }
    }
}

/// Return the pre-assigned simulated challenge if the entire subtree is simulated;
/// `None` if the subtree contains at least one real branch.
///
/// For compound nodes, the value comes from `sim_root_challenge`, which
/// `build_tree_simulated` populates with the challenge parameter it received
/// (i.e., the challenge the parent assigned to this subtree). Returning the
/// subtree's root challenge — rather than recursing into children[0] — is
/// critical for nested compound simulations: a parent OR's XOR-derive must
/// use each simulated child's *root* challenge, not a leaf challenge buried
/// deep inside the child.
pub(super) fn get_sim_challenge(tree: &ProverTree) -> Option<[u8; SOUNDNESS_BYTES]> {
    match tree {
        ProverTree::Schnorr { leaf, .. } => leaf.simulated_challenge(),
        ProverTree::Dht { leaf, .. } => leaf.simulated_challenge(),
        ProverTree::And {
            sim_root_challenge, ..
        } => *sim_root_challenge,
        ProverTree::Or {
            sim_root_challenge, ..
        } => *sim_root_challenge,
        ProverTree::Threshold {
            sim_root_challenge, ..
        } => *sim_root_challenge,
    }
}

/// Finalize a leaf: real → compute z = r + e*x; simulated → return stored z;
/// supplied proof → return stored z verbatim.
fn finalize_leaf(
    leaf: LeafState,
    challenge: &[u8; SOUNDNESS_BYTES],
) -> Result<([u8; 32], u64), WalletError> {
    match leaf {
        LeafState::Real {
            secret, r_scalar, ..
        } => {
            let e = challenge_to_scalar(challenge);
            let z = r_scalar + e * secret;
            Ok((z.to_bytes().into(), 0))
        }
        LeafState::Simulated { z_bytes, .. } => Ok((z_bytes, 0)),
        LeafState::SuppliedProof { z_bytes, .. } => Ok((z_bytes, 0)),
    }
}
