//! Internal data structures threaded through the build / fiat-shamir /
//! finalize / serialize phases.
//!
//! `ProverTree` carries all data needed for both FS hashing and
//! per-leaf finalization. Each leaf is one of:
//! - [`LeafState::Real`] — wallet holds the secret.
//! - [`LeafState::Simulated`] — pre-chosen `(challenge, z, commit)` for
//!   the no-secret branch of an OR/threshold.
//! - [`LeafState::SuppliedProof`] — proof bytes provided by a
//!   cooperating party via a `RealSecretProof` / `SimulatedSecretProof`
//!   hint.
//!
//! `Completed` is the post-propagation shape consumed by the
//! serializer — every node carries its finalized `challenge` and the
//! per-leaf `z` bytes.

use ergo_sigma::SOUNDNESS_BYTES;
use k256::Scalar;

pub(super) enum ProverTree {
    Schnorr {
        pk: [u8; 33],
        leaf: LeafState,
    },
    Dht {
        g: [u8; 33],
        h: [u8; 33],
        u: [u8; 33],
        v: [u8; 33],
        leaf: LeafState,
    },
    And {
        children: Vec<ProverTree>,
        /// Set by `build_tree_simulated` when the entire AND subtree is simulated.
        /// `get_sim_challenge` returns this directly, avoiding a deep recurse into
        /// children[0] that would return the wrong (leaf-level) challenge for nested
        /// compound nodes. `None` when the subtree contains at least one real child.
        sim_root_challenge: Option<[u8; SOUNDNESS_BYTES]>,
    },
    Or {
        children: Vec<ProverTree>,
        /// Set by `build_tree_simulated` when the entire OR subtree is simulated.
        /// The value is the `challenge` argument passed to `build_tree_simulated`
        /// for this node (i.e., the challenge the parent assigned to this OR).
        /// `get_sim_challenge` returns this directly so the parent's XOR-derive
        /// uses the OR's root challenge, not its first leaf's challenge.
        sim_root_challenge: Option<[u8; SOUNDNESS_BYTES]>,
    },
    /// k-of-n threshold. `real_indices` lists which child positions (0-based)
    /// are real; the rest are simulated. `sim_challenges[i]` holds the
    /// pre-assigned challenge for the i-th simulated child in child-index order.
    Threshold {
        k: usize,
        children: Vec<ProverTree>,
        /// One entry per simulated branch, in the order they appear among children.
        sim_challenges: Vec<(usize, [u8; SOUNDNESS_BYTES])>,
        /// Set by `build_tree_simulated` when the entire threshold subtree is simulated.
        sim_root_challenge: Option<[u8; SOUNDNESS_BYTES]>,
    },
}

pub(super) enum LeafState {
    /// Wallet holds the secret. `r_scalar` is the commitment randomness;
    /// `commit_bytes` is the public commitment (33B for Schnorr, 66B for DHT).
    Real {
        secret: Scalar,
        r_scalar: Scalar,
        commit_bytes: Vec<u8>,
    },
    /// Wallet doesn't hold the secret. `challenge`, `z_bytes`, and
    /// `commit_bytes` are all pre-chosen (simulated).
    Simulated {
        challenge: [u8; SOUNDNESS_BYTES],
        z_bytes: [u8; 32],
        commit_bytes: Vec<u8>,
    },
    /// Proof supplied by a cooperating party via `RealSecretProof` or
    /// `SimulatedSecretProof` hint. The commitment bytes are taken from the
    /// matching `RealCommitment`/`SimulatedCommitment` hint (same position),
    /// or back-derived from `(challenge, z)` if no commitment hint is present.
    /// During `complete_tree`, `z_bytes` is emitted verbatim — the challenge
    /// is supplied externally by `complete_tree` propagation (for real leaves)
    /// or by the pre-assigned simulated challenge stored here.
    SuppliedProof {
        /// Pre-assigned challenge from the supplied proof (used only for
        /// simulated leaves so `get_sim_challenge` can report the right value).
        supplied_challenge: Option<[u8; SOUNDNESS_BYTES]>,
        z_bytes: [u8; 32],
        commit_bytes: Vec<u8>,
    },
}

impl LeafState {
    pub(super) fn commit_bytes(&self) -> &[u8] {
        match self {
            LeafState::Real { commit_bytes, .. } => commit_bytes,
            LeafState::Simulated { commit_bytes, .. } => commit_bytes,
            LeafState::SuppliedProof { commit_bytes, .. } => commit_bytes,
        }
    }

    pub(super) fn simulated_challenge(&self) -> Option<[u8; SOUNDNESS_BYTES]> {
        match self {
            LeafState::Simulated { challenge, .. } => Some(*challenge),
            LeafState::Real { .. } => None,
            // SuppliedProof from a RealSecretProof: not simulated (real branch).
            // SuppliedProof from a SimulatedSecretProof: simulated (supplied_challenge set).
            LeafState::SuppliedProof {
                supplied_challenge, ..
            } => *supplied_challenge,
        }
    }
}

pub(super) struct Completed {
    pub(super) challenge: [u8; SOUNDNESS_BYTES],
    pub(super) node: CompletedNode,
}

pub(super) enum CompletedNode {
    Schnorr {
        z_bytes: [u8; 32],
    },
    Dht {
        z_bytes: [u8; 32],
    },
    And {
        children: Vec<Completed>,
    },
    Or {
        children: Vec<Completed>,
    },
    /// Threshold node. `poly_more_coeffs` holds the (n-k) coefficients that
    /// the verifier reads from the proof (coeff0 = root challenge, implicit).
    Threshold {
        children: Vec<Completed>,
        poly_more_coeffs: Vec<[u8; SOUNDNESS_BYTES]>,
    },
}
