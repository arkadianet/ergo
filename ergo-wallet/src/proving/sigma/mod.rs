//! Compound sigma proof production — AND/OR/threshold composition over ProveDlog and
//! ProveDHTuple leaves.
//!
//! Mirrors Scala `ErgoProvingInterpreter.signInputs` / `prove` logic.
//! The serialization order matches `ergo_sigma::verify::parse_and_compute_challenges`
//! exactly; a proof produced here must survive `verify_sigma_proof` without
//! modification.
//!
//! # Algorithm
//!
//! 1. **Build** — walk the proposition tree, sampling commitments:
//!    - REAL leaf (registry holds the secret): sample `r`; commit = `g^r`.
//!    - SIMULATED leaf (no secret): sample random `(e, z)`; back-derive
//!      commitment `R = g^z - pk*e` (Schnorr) or `(A,B) = (g^z-u*e, h^z-v*e)` (DHT).
//! 2. **Root challenge** — hash the full commitment tree (all leaves real + simulated)
//!    via Fiat-Shamir; extract root_challenge = blake2b256(fs_bytes || message)[0..24].
//! 3. **Propagate + finalize**:
//!    - AND: all children receive the parent challenge.
//!    - OR: real child's challenge = parent ⊕ XOR(all simulated siblings);
//!      simulated children keep their pre-assigned challenges.
//!    - Threshold: Lagrange interpolation over GF(2^192); real children's
//!      challenges come from evaluating Q at their 1-indexed positions.
//!    - Real leaf: z = r + e*x mod q.
//!    - Simulated leaf: z already chosen in step 1.
//! 4. **Serialize** depth-first matching the verifier's read order:
//!    - Write root_challenge[0..24].
//!    - AND: recurse into each child (no per-child challenge bytes — children share parent).
//!    - OR: for each child except the last, write child_challenge(24B) then recurse.
//!      For the last child, write nothing (verifier reconstructs via XOR).
//!    - Threshold: write (n-k) polynomial coefficients (each 24B, coeff0 implicit from
//!      root challenge), then recurse into each child in order.
//!    - Leaf: write z(32B).

use ergo_primitives::cost::JitCost;
use ergo_ser::sigma_value::SigmaBoolean;
use ergo_sigma::SOUNDNESS_BYTES;

use crate::error::WalletError;
use crate::proving::hints::HintsBag;
use crate::proving::node_position::NodePosition;
use crate::proving::randomness::ProvingRng;
use crate::proving::secrets::SecretRegistry;

mod build;
mod crypto;
mod fiat_shamir;
mod finalize;
mod hints;
mod serialize;
mod tree;

use build::build_tree;
use fiat_shamir::fiat_shamir_bytes;
use finalize::complete_tree;
use serialize::serialize_tree;

// Placeholder costs per the plan. Will be tuned in a later phase.
pub(super) const COST_PER_LEAF: u64 = 50;
pub(super) const COST_PER_NODE: u64 = 1;

/// Produce a proof for an arbitrary `SigmaBoolean` tree.
///
/// Returns `(proof_bytes, accumulated_cost)`.
/// The proof bytes are compatible with `ergo_sigma::verify::verify_sigma_proof`.
///
/// `hints` supports the multi-sig path (empty for single-sig).
pub fn prove_sigma(
    proposition: &SigmaBoolean,
    secrets: &SecretRegistry,
    message: &[u8],
    hints: &HintsBag,
    rng: &mut dyn ProvingRng,
) -> Result<(Vec<u8>, JitCost), WalletError> {
    match proposition {
        SigmaBoolean::TrivialProp(true) => return Ok((Vec::new(), JitCost::ZERO)),
        SigmaBoolean::TrivialProp(false) => {
            return Err(WalletError::MissingSecret(
                "TrivialProp(false) is always unprovable".into(),
            ))
        }
        _ => {}
    }

    // Compound node: three-phase algorithm.
    let tree = build_tree(
        proposition,
        secrets,
        hints,
        NodePosition::crypto_tree_prefix(),
        rng,
    )?;
    let fs_bytes = fiat_shamir_bytes(&tree);
    let mut hash_input = Vec::with_capacity(fs_bytes.len() + message.len());
    hash_input.extend_from_slice(&fs_bytes);
    hash_input.extend_from_slice(message);
    let hash = ergo_sigma::blake2b256(&hash_input);
    let root_ch: [u8; SOUNDNESS_BYTES] = hash[..SOUNDNESS_BYTES].try_into().unwrap();

    let (completed, raw_cost) = complete_tree(tree, root_ch)?;
    let cost = JitCost::try_from_jit(raw_cost)
        .map_err(|_| WalletError::MissingSecret("cost overflow".into()))?;

    let mut proof = Vec::new();
    proof.extend_from_slice(&root_ch);
    serialize_tree(&completed, &mut proof);

    match ergo_sigma::verify::verify_sigma_proof(proposition, &proof, message) {
        Ok(true) => Ok((proof, cost)),
        _ => Err(WalletError::SelfVerifyFailed),
    }
}
