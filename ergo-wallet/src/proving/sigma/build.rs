//! Phase 1 — walk the `SigmaBoolean` proposition tree and build the
//! `ProverTree` representation.
//!
//! For each leaf:
//! - If the wallet holds the secret (or a cooperating-party
//!   `RealSecretProof` hint covers it): mark REAL — sample fresh
//!   commitment randomness `r`, compute `R = g^r`.
//! - Otherwise: mark SIMULATED — sample random `(e, z)`, back-derive
//!   commitment `R = g^z - pk*e` (Schnorr) or `(A,B) = (g^z - u*e,
//!   h^z - v*e)` (DHT).
//!
//! For OR / Threshold: the simulated siblings drive the
//! back-derivation; the real child's challenge is reconstructed in
//! `finalize::complete_tree` from the parent challenge ⊕ sim
//! siblings' challenges (OR) or via GF(2^192) interpolation
//! (Threshold).
//!
//! `can_prove` is the fast probe used to decide which leaves go real
//! vs simulated before sampling.

use ergo_ser::sigma_value::SigmaBoolean;
use ergo_sigma::SOUNDNESS_BYTES;
use k256::elliptic_curve::group::GroupEncoding;
use k256::elliptic_curve::ops::MulByGenerator;
use k256::{ProjectivePoint, Scalar};

use crate::error::WalletError;
use crate::proving::hints::HintsBag;
use crate::proving::node_position::NodePosition;
use crate::proving::randomness::ProvingRng;
use crate::proving::secrets::SecretRegistry;

use super::crypto::{pt, sim_dht_commit, sim_schnorr_commit, xor_bytes};
use super::finalize::get_sim_challenge;
use super::hints::{
    find_own_commitment_dht, find_own_commitment_schnorr, find_real_commitment_dht,
    find_real_commitment_schnorr, find_real_secret_proof_compound, find_simulated_commitment_dht,
    find_simulated_commitment_schnorr, find_simulated_secret_proof_compound,
};
use super::tree::{LeafState, ProverTree};

// ---------------------------------------------------------------------------
// Phase 1: build tree
// ---------------------------------------------------------------------------

pub(super) fn build_tree(
    prop: &SigmaBoolean,
    secrets: &SecretRegistry,
    hints: &HintsBag,
    position: NodePosition,
    rng: &mut dyn ProvingRng,
) -> Result<ProverTree, WalletError> {
    match prop {
        SigmaBoolean::TrivialProp(_) => unreachable!("handled in prove_sigma"),

        SigmaBoolean::ProveDlog(ge) => {
            let pk = *ge.as_bytes();
            let leaf = if let Some(&secret) = secrets.dlog_secret(&pk) {
                // Registry-owned secret is authoritative. Hints are coordination
                // artifacts for keys the wallet doesn't own — they must not override.
                // Reuse OwnCommitment from the bag if present (matched by image +
                // position) — multi-sig commitment-generation step pre-populated it.
                let (r, r_pt) =
                    find_own_commitment_schnorr(prop, &position, hints).unwrap_or_else(|| {
                        let r = rng.sample_scalar();
                        let r_bytes: [u8; 33] = ProjectivePoint::mul_by_generator(&r)
                            .to_affine()
                            .to_bytes()
                            .into();
                        (r, r_bytes)
                    });
                LeafState::Real {
                    secret,
                    r_scalar: r,
                    commit_bytes: r_pt.to_vec(),
                }
            } else if let Some(rsp) = find_real_secret_proof_compound(prop, &position, hints) {
                // Cooperating party already proved this leaf. Use their response verbatim.
                // Reached only when the registry has no secret for this key — so this is
                // a foreign-key coordination hint, not a stale hint shadowing a local key.
                // Get commitment from RealCommitment hint (same position) if present;
                // otherwise back-derive R = g^z - pk*e from (challenge, z).
                let z_bytes = rsp.response;
                let commit_bytes =
                    if let Some(r_pt) = find_real_commitment_schnorr(prop, &position, hints) {
                        r_pt.to_vec()
                    } else {
                        sim_schnorr_commit(&pk, &rsp.challenge, &{
                            use k256::elliptic_curve::ops::Reduce;
                            <Scalar as Reduce<k256::U256>>::reduce_bytes(&z_bytes.into())
                        })?
                        .to_vec()
                    };
                LeafState::SuppliedProof {
                    supplied_challenge: None, // real branch
                    z_bytes,
                    commit_bytes,
                }
            } else if let Some(ssp) = find_simulated_secret_proof_compound(prop, &position, hints) {
                // A cooperating party already simulated this leaf (multi-party
                // coordination hint for a branch this prover lacks the secret for).
                // Only reached when neither a registry secret nor a RealSecretProof
                // applies — preserving the exact simulation bytes from the other party.
                let z_bytes = ssp.response;
                let commit_bytes =
                    if let Some(r_pt) = find_simulated_commitment_schnorr(prop, &position, hints) {
                        r_pt.to_vec()
                    } else {
                        sim_schnorr_commit(&pk, &ssp.challenge, &{
                            use k256::elliptic_curve::ops::Reduce;
                            <Scalar as Reduce<k256::U256>>::reduce_bytes(&z_bytes.into())
                        })?
                        .to_vec()
                    };
                LeafState::SuppliedProof {
                    supplied_challenge: Some(ssp.challenge),
                    z_bytes,
                    commit_bytes,
                }
            } else {
                let ch = rng.sample_challenge();
                let z = rng.sample_scalar();
                let r_sim = sim_schnorr_commit(&pk, &ch, &z)?;
                LeafState::Simulated {
                    challenge: ch,
                    z_bytes: z.to_bytes().into(),
                    commit_bytes: r_sim.to_vec(),
                }
            };
            Ok(ProverTree::Schnorr { pk, leaf })
        }

        SigmaBoolean::ProveDHTuple { g, h, u, v } => {
            let (g_b, h_b, u_b, v_b) = (*g.as_bytes(), *h.as_bytes(), *u.as_bytes(), *v.as_bytes());
            use crate::proving::secrets::DhTupleId;
            let leaf = if let Some(&secret) = secrets.dht_secret(&DhTupleId(g_b, h_b, u_b, v_b)) {
                // Registry-owned secret is authoritative. Hints are coordination
                // artifacts for keys the wallet doesn't own — they must not override.
                // Reuse OwnCommitment from the bag if present (matched by image + position).
                let g_pt = pt(&g_b)?;
                let h_pt = pt(&h_b)?;
                let (r, a, b) = find_own_commitment_dht(prop, &position, hints, &g_pt, &h_pt)
                    .unwrap_or_else(|| {
                        let r = rng.sample_scalar();
                        let a: [u8; 33] = (g_pt * r).to_affine().to_bytes().into();
                        let b: [u8; 33] = (h_pt * r).to_affine().to_bytes().into();
                        (r, a, b)
                    });
                let mut cb = Vec::with_capacity(66);
                cb.extend_from_slice(&a);
                cb.extend_from_slice(&b);
                LeafState::Real {
                    secret,
                    r_scalar: r,
                    commit_bytes: cb,
                }
            } else if let Some(rsp) = find_real_secret_proof_compound(prop, &position, hints) {
                // Cooperating party already proved this DHT leaf. Reached only when
                // the registry has no secret for this tuple — foreign-key coordination.
                let z_bytes = rsp.response;
                let commit_bytes = if let Some((a, b)) =
                    find_real_commitment_dht(prop, &position, hints)
                {
                    let mut cb = Vec::with_capacity(66);
                    cb.extend_from_slice(&a);
                    cb.extend_from_slice(&b);
                    cb
                } else {
                    use k256::elliptic_curve::ops::Reduce;
                    let z_scalar = <Scalar as Reduce<k256::U256>>::reduce_bytes(&z_bytes.into());
                    let (a_s, b_s) =
                        sim_dht_commit(&g_b, &h_b, &u_b, &v_b, &rsp.challenge, &z_scalar)?;
                    let mut cb = Vec::with_capacity(66);
                    cb.extend_from_slice(&a_s);
                    cb.extend_from_slice(&b_s);
                    cb
                };
                LeafState::SuppliedProof {
                    supplied_challenge: None,
                    z_bytes,
                    commit_bytes,
                }
            } else if let Some(ssp) = find_simulated_secret_proof_compound(prop, &position, hints) {
                // A cooperating party already simulated this DHT leaf (multi-party
                // coordination hint for a branch this prover lacks the secret for).
                // Only reached when neither a registry secret nor a RealSecretProof
                // applies — preserving the exact simulation bytes from the other party.
                let z_bytes = ssp.response;
                let commit_bytes = if let Some((a, b)) =
                    find_simulated_commitment_dht(prop, &position, hints)
                {
                    let mut cb = Vec::with_capacity(66);
                    cb.extend_from_slice(&a);
                    cb.extend_from_slice(&b);
                    cb
                } else {
                    use k256::elliptic_curve::ops::Reduce;
                    let z_scalar = <Scalar as Reduce<k256::U256>>::reduce_bytes(&z_bytes.into());
                    let (a_s, b_s) =
                        sim_dht_commit(&g_b, &h_b, &u_b, &v_b, &ssp.challenge, &z_scalar)?;
                    let mut cb = Vec::with_capacity(66);
                    cb.extend_from_slice(&a_s);
                    cb.extend_from_slice(&b_s);
                    cb
                };
                LeafState::SuppliedProof {
                    supplied_challenge: Some(ssp.challenge),
                    z_bytes,
                    commit_bytes,
                }
            } else {
                let ch = rng.sample_challenge();
                let z = rng.sample_scalar();
                let (a_s, b_s) = sim_dht_commit(&g_b, &h_b, &u_b, &v_b, &ch, &z)?;
                let mut cb = Vec::with_capacity(66);
                cb.extend_from_slice(&a_s);
                cb.extend_from_slice(&b_s);
                LeafState::Simulated {
                    challenge: ch,
                    z_bytes: z.to_bytes().into(),
                    commit_bytes: cb,
                }
            };
            Ok(ProverTree::Dht {
                g: g_b,
                h: h_b,
                u: u_b,
                v: v_b,
                leaf,
            })
        }

        SigmaBoolean::Cand(children) => {
            if children.is_empty() {
                return Err(WalletError::MissingSecret("AND with empty children".into()));
            }
            let built: Result<Vec<_>, _> = children
                .iter()
                .enumerate()
                .map(|(i, c)| build_tree(c, secrets, hints, position.child(i as u32), rng))
                .collect();
            Ok(ProverTree::And {
                children: built?,
                sim_root_challenge: None,
            })
        }

        SigmaBoolean::Cor(children) => {
            if children.is_empty() {
                return Err(WalletError::MissingSecret("OR with empty children".into()));
            }

            // Probe provability BEFORE building so unprovable compound subtrees
            // (e.g. inner OR(a,b) with no secrets) are routed to
            // build_tree_simulated instead of causing MissingSecret errors.
            // This mirrors the threshold preselection pattern.
            let provable: Vec<bool> = children
                .iter()
                .enumerate()
                .map(|(i, c)| can_prove(c, secrets, hints, &position.child(i as u32)))
                .collect();

            // Scala convention: pick the FIRST provable child as real.
            let real_idx = provable.iter().position(|&p| p).ok_or_else(|| {
                WalletError::MissingSecret("OR proposition: no branch is provable".into())
            })?;

            // Whether the chosen real branch will be assembled entirely from
            // the local registry (no `RealSecretProof` hints in its leaves).
            // A registry-backed real branch recomputes its `z` against
            // whatever final challenge `complete_tree` derives, so a
            // freshly-simulated non-real sibling — even one whose subtree
            // partially overlaps the bag — is safe. A bag-backed real
            // branch carries the original signer's `z` verbatim and must
            // have its derived challenge preserved exactly.
            let real_branch_registry_backed = real_path_registry_backed(
                &children[real_idx],
                secrets,
                hints,
                &position.child(real_idx as u32),
            );

            let mut built = Vec::with_capacity(children.len());
            for (i, child_prop) in children.iter().enumerate() {
                let child_pos = position.child(i as u32);
                if i == real_idx {
                    built.push(build_tree(child_prop, secrets, hints, child_pos, rng)?);
                } else {
                    // Non-real OR sibling MUST yield a simulated subtree: the
                    // verifier recovers the last child's challenge via
                    //   last_ch = root_challenge ⊕ XOR(other-children-challenges)
                    // which requires every non-real child to expose a fully-
                    // determined simulated challenge through get_sim_challenge.
                    //
                    // Three simulation paths, by bag coverage of the subtree's
                    // leaves with SimulatedSecretProof:
                    //  - All: distributed-sig wire reconstruction. Build each
                    //    SuppliedProof leaf directly from the bag and derive
                    //    each compound's sim_root_challenge per the verifier's
                    //    consensus rule, bypassing build_tree's registry-first
                    //    leaf precedence so a registry-held secret cannot
                    //    re-materialize the sibling as Real and break the OR
                    //    XOR-derive.
                    //  - None: ordinary multi-provable OR or unprovable
                    //    compound child. Fresh-simulate with a sampled
                    //    challenge.
                    //  - Partial OR an All subtree containing a Cthreshold
                    //    k=0 (whose sim_root_challenge isn't recoverable
                    //    from leaf hints alone): bag is insufficient for
                    //    byte-identical reconstruction. Safe to
                    //    fresh-simulate when the real OR branch is
                    //    registry-backed (it will recompute z against the
                    //    new challenge); otherwise the bag's real-branch z
                    //    is stale and the proof would fail self-verify, so
                    //    error cleanly.
                    let coverage = subtree_sim_coverage(child_prop, hints, &child_pos);
                    let bag_reconstructable = coverage == SimHintCoverage::All
                        && subtree_hint_reconstructable(child_prop);
                    let child_built = if bag_reconstructable {
                        build_simulated_or_sibling_from_hints(child_prop, hints, &child_pos, rng)?
                    } else if real_branch_registry_backed {
                        let ch = rng.sample_challenge();
                        build_tree_simulated(child_prop, ch, rng)?
                    } else {
                        return Err(WalletError::MissingSecret(
                            "non-real OR sibling cannot be byte-identically \
                             reconstructed from the bag (missing or partial Sim* \
                             coverage, or Cthreshold k=0 nested in subtree) and \
                             the real OR branch is bag-supplied — the bag's \
                             real-branch z would not match the derived challenge"
                                .into(),
                        ));
                    };
                    built.push(child_built);
                }
            }

            // sim_root_challenge stays None for build_tree-built subtrees; OR
            // gets its challenge from complete_tree's XOR derivation.
            // For sub-OR built via build_tree_simulated (fallback path) the
            // child's own sim_root_challenge is set internally.
            Ok(ProverTree::Or {
                children: built,
                sim_root_challenge: None,
            })
        }

        SigmaBoolean::Cthreshold { k, children } => {
            let k = *k as usize;
            if children.is_empty() {
                return Err(WalletError::MissingSecret(
                    "threshold with empty children".into(),
                ));
            }
            let n = children.len();

            // Determine which children will be real (first k provable ones) and
            // which will be simulated. We need to decide this BEFORE building,
            // so simulated children can be built with consistent pre-assigned
            // challenges (their commitments are back-derived from the challenge).
            //
            // Pass 1: probe which propositions the registry can prove.
            let provable: Vec<bool> = children
                .iter()
                .enumerate()
                .map(|(i, c)| can_prove(c, secrets, hints, &position.child(i as u32)))
                .collect();
            let real_count = provable.iter().filter(|&&p| p).count();
            if real_count < k {
                return Err(WalletError::MissingSecret(format!(
                    "threshold k-of-n: need k={k} real branches, have {real_count}"
                )));
            }

            // Mark the first k provable children as truly real; the rest are simulated.
            let mut real_seen = 0usize;
            let mut is_truly_real: Vec<bool> = Vec::with_capacity(n);
            for &p in &provable {
                if p && real_seen < k {
                    is_truly_real.push(true);
                    real_seen += 1;
                } else {
                    is_truly_real.push(false);
                }
            }

            // Pass 2: build children. For simulated positions, pre-sample a challenge
            // and pass it into build_tree_simulated so the commitment is back-derived
            // from the threshold-assigned challenge (not a random independent one).
            let mut built: Vec<ProverTree> = Vec::with_capacity(n);
            let mut sim_challenges: Vec<(usize, [u8; SOUNDNESS_BYTES])> = Vec::new();

            for (i, child_prop) in children.iter().enumerate() {
                let child_pos = position.child(i as u32);
                if is_truly_real[i] {
                    built.push(build_tree(child_prop, secrets, hints, child_pos, rng)?);
                } else {
                    // Pre-sample the threshold-level simulated challenge.
                    let ch = rng.sample_challenge();
                    sim_challenges.push((i, ch));
                    // Build the subtree fully simulated with this challenge.
                    built.push(build_tree_simulated(child_prop, ch, rng)?);
                }
            }

            Ok(ProverTree::Threshold {
                k,
                children: built,
                sim_challenges,
                sim_root_challenge: None,
            })
        }
    }
}

/// Fast probe: can this proposition be proved given the registry + hints bag?
/// Used to decide real/simulated splits before building trees.
///
/// `current_position` must track the position of `prop` in the tree so that
/// hint lookups use `(image, position)` keys — matching what `build_tree`
/// consumes. Without position-awareness, duplicate leaves (same image, different
/// position) would both be counted as provable when only one has a hint.
pub(super) fn can_prove(
    prop: &SigmaBoolean,
    secrets: &SecretRegistry,
    hints: &HintsBag,
    current_position: &NodePosition,
) -> bool {
    match prop {
        SigmaBoolean::TrivialProp(b) => *b,
        SigmaBoolean::ProveDlog(ge) => {
            secrets.dlog_secret(ge.as_bytes()).is_some()
                || hints.hints.iter().any(|h| {
                    matches!(
                        h,
                        crate::proving::hints::Hint::RealSecretProof(rsp)
                            if &rsp.image == prop && &rsp.position == current_position
                    )
                })
        }
        SigmaBoolean::ProveDHTuple { .. } => {
            use crate::proving::secrets::DhTupleId;
            let (g, h, u, v) = match prop {
                SigmaBoolean::ProveDHTuple { g, h, u, v } => (g, h, u, v),
                _ => unreachable!(),
            };
            secrets
                .dht_secret(&DhTupleId(
                    *g.as_bytes(),
                    *h.as_bytes(),
                    *u.as_bytes(),
                    *v.as_bytes(),
                ))
                .is_some()
                || hints.hints.iter().any(|h_hint| {
                    matches!(
                        h_hint,
                        crate::proving::hints::Hint::RealSecretProof(rsp)
                            if &rsp.image == prop && &rsp.position == current_position
                    )
                })
        }
        SigmaBoolean::Cand(children) => children
            .iter()
            .enumerate()
            .all(|(i, c)| can_prove(c, secrets, hints, &current_position.child(i as u32))),
        SigmaBoolean::Cor(children) => children
            .iter()
            .enumerate()
            .any(|(i, c)| can_prove(c, secrets, hints, &current_position.child(i as u32))),
        SigmaBoolean::Cthreshold { k, children } => {
            children
                .iter()
                .enumerate()
                .filter(|(i, c)| can_prove(c, secrets, hints, &current_position.child(*i as u32)))
                .count()
                >= *k as usize
        }
    }
}

/// Coverage of a subtree by `SimulatedSecretProof` hints in the bag, used by
/// the OR-arm of `build_tree` to discriminate distributed-sig reconstruction
/// from ordinary local-simulation paths.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SimHintCoverage {
    /// No leaf in the subtree is covered by a `SimulatedSecretProof`.
    None,
    /// Every leaf in the subtree is covered by a `SimulatedSecretProof`.
    All,
    /// Some leaves are covered, others are not — bag is incomplete for
    /// byte-identical reconstruction; reconstruction would diverge from the
    /// original signer's commitment tree.
    Partial,
}

fn merge_coverage(a: SimHintCoverage, b: SimHintCoverage) -> SimHintCoverage {
    use SimHintCoverage::*;
    match (a, b) {
        (None, None) => None,
        (All, All) => All,
        _ => Partial,
    }
}

fn leaf_sim_coverage(
    prop: &SigmaBoolean,
    hints: &HintsBag,
    current_position: &NodePosition,
) -> SimHintCoverage {
    let has = hints.hints.iter().any(|h| {
        matches!(
            h,
            crate::proving::hints::Hint::SimulatedSecretProof(ssp)
                if &ssp.image == prop && &ssp.position == current_position
        )
    });
    if has {
        SimHintCoverage::All
    } else {
        SimHintCoverage::None
    }
}

fn subtree_sim_coverage(
    prop: &SigmaBoolean,
    hints: &HintsBag,
    current_position: &NodePosition,
) -> SimHintCoverage {
    match prop {
        SigmaBoolean::TrivialProp(_) => SimHintCoverage::None,
        SigmaBoolean::ProveDlog(_) | SigmaBoolean::ProveDHTuple { .. } => {
            leaf_sim_coverage(prop, hints, current_position)
        }
        SigmaBoolean::Cand(children)
        | SigmaBoolean::Cor(children)
        | SigmaBoolean::Cthreshold { children, .. } => children
            .iter()
            .enumerate()
            .map(|(i, c)| subtree_sim_coverage(c, hints, &current_position.child(i as u32)))
            .reduce(merge_coverage)
            .unwrap_or(SimHintCoverage::None),
    }
}

/// Whether a fully Sim*-covered subtree can be byte-identically
/// reconstructed by `build_simulated_or_sibling_from_hints`. False when
/// the subtree contains a `Cthreshold` with `k = 0`, whose
/// `sim_root_challenge` (= Q(0) for a degree-n polynomial fully
/// determined at points 1..=n by the bag's leaf challenges) is one
/// unconstrained degree of freedom not carried by the bag.
fn subtree_hint_reconstructable(prop: &SigmaBoolean) -> bool {
    match prop {
        SigmaBoolean::TrivialProp(_)
        | SigmaBoolean::ProveDlog(_)
        | SigmaBoolean::ProveDHTuple { .. } => true,
        SigmaBoolean::Cand(children) | SigmaBoolean::Cor(children) => {
            children.iter().all(subtree_hint_reconstructable)
        }
        SigmaBoolean::Cthreshold { k, children } => {
            *k > 0 && children.iter().all(subtree_hint_reconstructable)
        }
    }
}

/// Build a non-real OR sibling subtree whose leaves take their
/// `(challenge, z, commit_bytes)` from bag-supplied `SimulatedSecretProof` +
/// matching `SimulatedCommitment` hints — bypassing the registry-first leaf
/// precedence used by `build_tree`.
///
/// Each compound node's `sim_root_challenge` is reverse-derived from its
/// children's bag-supplied challenges per the verifier's consensus rule
/// (matching the patterns `build_tree_simulated` produces at sign time):
///   - Cand: unanimous (every child shares the parent's assigned challenge);
///   - Cor : XOR of children's challenges;
///   - Cthreshold: solve for `sim_root_challenge` (= Q(0)). For
///     0 < k < n, two `interpolate` calls against the first (n-k) bag
///     challenges + one additional bag point give a linear equation in
///     Q(0). For k = n, Q is the constant polynomial Q(x) = the
///     `sim_root_challenge` value, so the root challenge is read
///     directly from any bag child challenge and cross-checked against
///     the rest. For k = 0, `sim_root_challenge` is independent of leaf
///     challenges and the bag does not carry it — errors.
///
/// Precondition: every leaf in `prop` is covered by a `SimulatedSecretProof`
/// in `hints` (the caller gates on `SimHintCoverage::All`). A missing leaf
/// hint inside this function indicates a coverage-discriminator bug and is
/// reported as `MissingSecret` rather than papered over with fresh
/// simulation — mixing bag-supplied and fresh leaves changes the surrounding
/// compound's derived challenge and would invalidate any bag-supplied
/// `RealSecretProof` on the sibling OR branch.
#[allow(clippy::only_used_in_recursion)]
fn build_simulated_or_sibling_from_hints(
    prop: &SigmaBoolean,
    hints: &HintsBag,
    position: &NodePosition,
    rng: &mut dyn ProvingRng,
) -> Result<ProverTree, WalletError> {
    match prop {
        SigmaBoolean::ProveDlog(ge) => {
            let pk = *ge.as_bytes();
            let ssp =
                find_simulated_secret_proof_compound(prop, position, hints).ok_or_else(|| {
                    WalletError::MissingSecret(
                        "build_simulated_or_sibling_from_hints: ProveDlog leaf lacks \
                         SimulatedSecretProof in bag (coverage discriminator bug)"
                            .into(),
                    )
                })?;
            let z_bytes = ssp.response;
            let commit_bytes =
                if let Some(r_pt) = find_simulated_commitment_schnorr(prop, position, hints) {
                    r_pt.to_vec()
                } else {
                    use k256::elliptic_curve::ops::Reduce;
                    let z_scalar = <Scalar as Reduce<k256::U256>>::reduce_bytes(&z_bytes.into());
                    sim_schnorr_commit(&pk, &ssp.challenge, &z_scalar)?.to_vec()
                };
            Ok(ProverTree::Schnorr {
                pk,
                leaf: LeafState::SuppliedProof {
                    supplied_challenge: Some(ssp.challenge),
                    z_bytes,
                    commit_bytes,
                },
            })
        }
        SigmaBoolean::ProveDHTuple { g, h, u, v } => {
            let (g_b, h_b, u_b, v_b) = (*g.as_bytes(), *h.as_bytes(), *u.as_bytes(), *v.as_bytes());
            let ssp =
                find_simulated_secret_proof_compound(prop, position, hints).ok_or_else(|| {
                    WalletError::MissingSecret(
                        "build_simulated_or_sibling_from_hints: ProveDHTuple leaf lacks \
                         SimulatedSecretProof in bag (coverage discriminator bug)"
                            .into(),
                    )
                })?;
            let z_bytes = ssp.response;
            let commit_bytes = if let Some((a, b)) =
                find_simulated_commitment_dht(prop, position, hints)
            {
                let mut cb = Vec::with_capacity(66);
                cb.extend_from_slice(&a);
                cb.extend_from_slice(&b);
                cb
            } else {
                use k256::elliptic_curve::ops::Reduce;
                let z_scalar = <Scalar as Reduce<k256::U256>>::reduce_bytes(&z_bytes.into());
                let (a_s, b_s) = sim_dht_commit(&g_b, &h_b, &u_b, &v_b, &ssp.challenge, &z_scalar)?;
                let mut cb = Vec::with_capacity(66);
                cb.extend_from_slice(&a_s);
                cb.extend_from_slice(&b_s);
                cb
            };
            Ok(ProverTree::Dht {
                g: g_b,
                h: h_b,
                u: u_b,
                v: v_b,
                leaf: LeafState::SuppliedProof {
                    supplied_challenge: Some(ssp.challenge),
                    z_bytes,
                    commit_bytes,
                },
            })
        }
        SigmaBoolean::TrivialProp(_) => Err(WalletError::MissingSecret(
            "cannot simulate TrivialProp in OR sibling reconstruction".into(),
        )),
        SigmaBoolean::Cand(children) => {
            // AND under a simulated OR sibling: every child must share the
            // parent's assigned challenge. The original signer's
            // `build_tree_simulated` propagated the same challenge to every
            // AND child, so the bag's Sim* hints for those leaves must all
            // carry the same challenge. Recurse on each child, then derive
            // sim_root_challenge as that unanimous value.
            let built: Vec<ProverTree> = children
                .iter()
                .enumerate()
                .map(|(i, c)| {
                    build_simulated_or_sibling_from_hints(c, hints, &position.child(i as u32), rng)
                })
                .collect::<Result<_, _>>()?;
            let child_chs: Vec<[u8; SOUNDNESS_BYTES]> = built
                .iter()
                .map(|t| {
                    get_sim_challenge(t).ok_or_else(|| {
                        WalletError::MissingSecret(
                            "AND child under simulated OR sibling produced no sim challenge".into(),
                        )
                    })
                })
                .collect::<Result<_, _>>()?;
            let first = child_chs[0];
            if child_chs.iter().any(|c| c != &first) {
                return Err(WalletError::MissingSecret(
                    "AND under simulated OR sibling: bag-supplied child challenges disagree — \
                     hint bag inconsistent with original AND-propagated challenge"
                        .into(),
                ));
            }
            Ok(ProverTree::And {
                children: built,
                sim_root_challenge: Some(first),
            })
        }
        SigmaBoolean::Cor(children) => {
            // OR under a simulated OR sibling: the sub-OR's root challenge =
            // XOR of all its children's assigned challenges. The original
            // signer built this fully-simulated sub-OR by sampling fresh
            // challenges for children 0..n-2 and deriving child n-1 from the
            // XOR constraint — so the bag's per-leaf challenges already
            // satisfy XOR(all_children) = sub_or_challenge_in_original. Set
            // sim_root_challenge to that XOR so the verifier's recursive
            // XOR-derive recovers child n-1's challenge identically.
            let built: Vec<ProverTree> = children
                .iter()
                .enumerate()
                .map(|(i, c)| {
                    build_simulated_or_sibling_from_hints(c, hints, &position.child(i as u32), rng)
                })
                .collect::<Result<_, _>>()?;
            let mut acc = [0u8; SOUNDNESS_BYTES];
            for child in &built {
                let ch = get_sim_challenge(child).ok_or_else(|| {
                    WalletError::MissingSecret(
                        "OR child under simulated OR sibling produced no sim challenge".into(),
                    )
                })?;
                xor_bytes(&mut acc, &ch);
            }
            Ok(ProverTree::Or {
                children: built,
                sim_root_challenge: Some(acc),
            })
        }
        SigmaBoolean::Cthreshold { k, children } => {
            // Fully-bag Cthreshold subtree as non-real OR sibling. The
            // original signer's `build_tree_simulated` for Cthreshold:
            //   - sampled (n-k) fresh `sim_challenges` for the FIRST n-k
            //     children;
            //   - interpolated Q (degree n-k) through Q(0) = parent
            //     challenge and Q(i+1) = sim_challenges[i];
            //   - assigned the remaining k children Q(i+1).
            //
            // The bag therefore carries each leaf's challenge (the first
            // n-k from random sampling, the remaining k from Q
            // evaluation). To reconstruct byte-identically, take the
            // first n-k bag challenges as sim_challenges, recover the
            // threshold's `sim_root_challenge` (= Q(0)) from any
            // additional bag point on Q, then cross-check that Q
            // matches every remaining k leaves' bag challenges.
            //
            // Q-at-zero recovery via the library's existing
            // `interpolate`: Q_t = interpolate(first n-k points, values,
            // value_at_zero=t) is linear in t over GF(2^192). Two
            // evaluations at t=0 and t=1 of Q_t(p_extra) determine the
            // linear function; solving for the t that produces the
            // (n-k+1)-th bag value at p_extra yields `sim_root_challenge`.
            use gf2_192::gf2_192::Gf2_192;
            use gf2_192::gf2_192poly::Gf2_192Poly;

            let k_usize = *k as usize;
            let n = children.len();
            if k_usize > n {
                return Err(WalletError::MissingSecret(format!(
                    "Cthreshold k={k_usize} exceeds children n={n}"
                )));
            }
            let num_sim = n - k_usize;
            if num_sim == n {
                // k = 0: Q has degree n with n+1 unconstrained coefficients.
                // The n bag-supplied leaf challenges fix Q at points 1..=n
                // but leave Q(0) = sim_root_challenge as a free degree of
                // freedom. The original signer's sim_root_challenge was
                // fresh-sampled and the bag does not carry it, so
                // byte-identical reconstruction is fundamentally not
                // possible from leaf hints alone. (k = 0 thresholds are
                // also semantically degenerate — "at least 0 required" is
                // trivially satisfied.)
                return Err(WalletError::MissingSecret(
                    "Cthreshold k=0 reconstruction not supported: bag does \
                     not carry the sub-threshold's parent challenge, and \
                     it is not recoverable from leaf hints alone"
                        .into(),
                ));
            }

            let built: Vec<ProverTree> = children
                .iter()
                .enumerate()
                .map(|(i, c)| {
                    build_simulated_or_sibling_from_hints(c, hints, &position.child(i as u32), rng)
                })
                .collect::<Result<_, _>>()?;
            let leaf_chs: Vec<[u8; SOUNDNESS_BYTES]> = built
                .iter()
                .map(|t| {
                    get_sim_challenge(t).ok_or_else(|| {
                        WalletError::MissingSecret(
                            "Cthreshold child under simulated OR sibling produced no sim challenge"
                                .into(),
                        )
                    })
                })
                .collect::<Result<_, _>>()?;

            // Recover sim_root_challenge (= Q(0)).
            //
            // num_sim == 0 (k == n): Q is the constant polynomial — sign-time
            // simulation calls interpolate([], [], value_at_zero) → Q(x) =
            // value_at_zero for every x. So every child's bag challenge
            // equals value_at_zero; sim_root_challenge = leaf_chs[0] and we
            // cross-check every other leaf agrees.
            //
            // num_sim > 0: Q has degree n - k ≥ 1. Q_t = interpolate(first
            // n - k points, values, value_at_zero=t) is linear in t over
            // GF(2^192). Two evaluations at t=0 and t=1 at the (n-k+1)-th
            // bag point yield the linear function; solving for the t that
            // matches the (n-k+1)-th bag value recovers Q(0) =
            // sim_root_challenge.
            let sim_root_gf = if num_sim == 0 {
                Gf2_192::from(leaf_chs[0])
            } else {
                let q_points: Vec<u8> = (0..num_sim).map(|i| (i + 1) as u8).collect();
                let q_values: Vec<Gf2_192> =
                    (0..num_sim).map(|i| Gf2_192::from(leaf_chs[i])).collect();
                let p_extra = (num_sim + 1) as u8;
                let v_extra = Gf2_192::from(leaf_chs[num_sim]);

                let q0 = Gf2_192Poly::interpolate(&q_points, &q_values, Gf2_192::from(0i32))
                    .map_err(|_| {
                        WalletError::MissingSecret(
                            "Cthreshold reconstruction: Q_0 interpolation failed".into(),
                        )
                    })?;
                let q1 = Gf2_192Poly::interpolate(&q_points, &q_values, Gf2_192::from(1i32))
                    .map_err(|_| {
                        WalletError::MissingSecret(
                            "Cthreshold reconstruction: Q_1 interpolation failed".into(),
                        )
                    })?;
                let q0_eval = q0.evaluate(p_extra);
                let q1_eval = q1.evaluate(p_extra);
                let denom = q1_eval + q0_eval; // q1 - q0 in char 2
                if denom.is_zero() {
                    return Err(WalletError::MissingSecret(
                        "Cthreshold reconstruction: Q_t(p_extra) is constant in t — \
                         cannot solve for sim_root_challenge"
                            .into(),
                    ));
                }
                let numer = v_extra + q0_eval;
                Gf2_192::multiply(numer, Gf2_192::invert(denom))
            };
            let sim_root: [u8; SOUNDNESS_BYTES] = sim_root_gf.into();

            // Cross-check Q at the remaining (k) bag points (n-k+1..=n for
            // num_sim > 0, or all of 1..=n for num_sim == 0).
            let q = {
                let q_points: Vec<u8> = (0..num_sim).map(|i| (i + 1) as u8).collect();
                let q_values: Vec<Gf2_192> =
                    (0..num_sim).map(|i| Gf2_192::from(leaf_chs[i])).collect();
                Gf2_192Poly::interpolate(&q_points, &q_values, sim_root_gf).map_err(|_| {
                    WalletError::MissingSecret(
                        "Cthreshold reconstruction: Q interpolation failed".into(),
                    )
                })?
            };
            for (i, leaf) in leaf_chs.iter().enumerate().skip(num_sim) {
                let expected: [u8; SOUNDNESS_BYTES] = q.evaluate((i + 1) as u8).into();
                if expected != *leaf {
                    return Err(WalletError::MissingSecret(format!(
                        "Cthreshold reconstruction: bag challenge for child {i} \
                         does not match Q evaluation — bag inconsistent with \
                         original signer's fully-simulated threshold"
                    )));
                }
            }

            let sim_challenges: Vec<(usize, [u8; SOUNDNESS_BYTES])> =
                (0..num_sim).map(|i| (i, leaf_chs[i])).collect();
            Ok(ProverTree::Threshold {
                k: k_usize,
                children: built,
                sim_challenges,
                sim_root_challenge: Some(sim_root),
            })
        }
    }
}

/// Whether `build_tree`'s actual real-branch selection for `prop` will rely
/// only on local registry secrets — i.e., every leaf reached on the path
/// `build_tree` chooses as "real" finds its secret in `secrets` rather than
/// a bag-supplied `RealSecretProof`.
///
/// Used by the OR-arm: a registry-backed real path can recompute `z` against
/// any final challenge `complete_tree` derives, so a freshly-simulated
/// non-real sibling is safe. A real path whose any selected leaf is
/// bag-supplied carries the original signer's `z` verbatim and breaks if
/// the sibling's challenge contribution changes.
///
/// The walk must mirror `build_tree`'s selection rule exactly: `Cand`
/// builds every child as real, `Cor` picks the first `can_prove`-provable
/// child, `Cthreshold` picks the first `k` `can_prove`-provable children.
/// A naive "any descendant is registry-provable" check would classify a
/// path as registry-backed even when `build_tree` would actually pick an
/// earlier sibling that requires a bag `RealSecretProof`.
fn real_path_registry_backed(
    prop: &SigmaBoolean,
    secrets: &SecretRegistry,
    hints: &HintsBag,
    current_position: &NodePosition,
) -> bool {
    match prop {
        SigmaBoolean::TrivialProp(_) => true,
        SigmaBoolean::ProveDlog(ge) => secrets.dlog_secret(ge.as_bytes()).is_some(),
        SigmaBoolean::ProveDHTuple { g, h, u, v } => {
            use crate::proving::secrets::DhTupleId;
            secrets
                .dht_secret(&DhTupleId(
                    *g.as_bytes(),
                    *h.as_bytes(),
                    *u.as_bytes(),
                    *v.as_bytes(),
                ))
                .is_some()
        }
        SigmaBoolean::Cand(children) => children.iter().enumerate().all(|(i, c)| {
            real_path_registry_backed(c, secrets, hints, &current_position.child(i as u32))
        }),
        SigmaBoolean::Cor(children) => {
            let selected = children
                .iter()
                .enumerate()
                .find(|(i, c)| can_prove(c, secrets, hints, &current_position.child(*i as u32)));
            match selected {
                Some((i, c)) => {
                    real_path_registry_backed(c, secrets, hints, &current_position.child(i as u32))
                }
                None => false,
            }
        }
        SigmaBoolean::Cthreshold { k, children } => {
            let mut selected = 0usize;
            for (i, c) in children.iter().enumerate() {
                if selected >= *k as usize {
                    break;
                }
                let child_pos = current_position.child(i as u32);
                if can_prove(c, secrets, hints, &child_pos) {
                    if !real_path_registry_backed(c, secrets, hints, &child_pos) {
                        return false;
                    }
                    selected += 1;
                }
            }
            selected >= *k as usize
        }
    }
}

/// Build a ProverTree for `prop` where the entire subtree is simulated using `challenge`.
///
/// For compound nodes, the challenge propagates down to all leaves, which back-derive
/// their commitments from it. This ensures consistency when the parent threshold node
/// evaluates the polynomial to assign this specific challenge to this subtree.
pub(super) fn build_tree_simulated(
    prop: &SigmaBoolean,
    challenge: [u8; SOUNDNESS_BYTES],
    rng: &mut dyn ProvingRng,
) -> Result<ProverTree, WalletError> {
    match prop {
        SigmaBoolean::TrivialProp(true) => {
            // Can't build a simulated proof for TrivialProp(true) — treat as error.
            Err(WalletError::MissingSecret(
                "cannot simulate TrivialProp(true) in threshold".into(),
            ))
        }
        SigmaBoolean::TrivialProp(false) => Err(WalletError::MissingSecret(
            "TrivialProp(false) is always unprovable".into(),
        )),
        SigmaBoolean::ProveDlog(ge) => {
            let pk = *ge.as_bytes();
            let z = rng.sample_scalar();
            let r_sim = sim_schnorr_commit(&pk, &challenge, &z)?;
            Ok(ProverTree::Schnorr {
                pk,
                leaf: LeafState::Simulated {
                    challenge,
                    z_bytes: z.to_bytes().into(),
                    commit_bytes: r_sim.to_vec(),
                },
            })
        }
        SigmaBoolean::ProveDHTuple { g, h, u, v } => {
            let (g_b, h_b, u_b, v_b) = (*g.as_bytes(), *h.as_bytes(), *u.as_bytes(), *v.as_bytes());
            let z = rng.sample_scalar();
            let (a_s, b_s) = sim_dht_commit(&g_b, &h_b, &u_b, &v_b, &challenge, &z)?;
            let mut cb = Vec::with_capacity(66);
            cb.extend_from_slice(&a_s);
            cb.extend_from_slice(&b_s);
            Ok(ProverTree::Dht {
                g: g_b,
                h: h_b,
                u: u_b,
                v: v_b,
                leaf: LeafState::Simulated {
                    challenge,
                    z_bytes: z.to_bytes().into(),
                    commit_bytes: cb,
                },
            })
        }
        SigmaBoolean::Cand(children) => {
            // AND: all children share the same challenge.
            let built: Result<Vec<_>, _> = children
                .iter()
                .map(|c| build_tree_simulated(c, challenge, rng))
                .collect();
            Ok(ProverTree::And {
                children: built?,
                sim_root_challenge: Some(challenge),
            })
        }
        SigmaBoolean::Cor(children) => {
            // OR fully simulated: verifier reconstructs the last child's challenge as
            //   child[n-1].challenge = parent_challenge XOR child[0].challenge XOR ... XOR child[n-2].challenge
            //
            // So we MUST assign each of the first (n-1) children a fresh independent
            // challenge and derive the last child's challenge from the XOR constraint.
            // Giving all children `parent_challenge` is wrong: the verifier would then
            // reconstruct child[n-1].challenge = parent XOR (n-1)*parent which is not
            // `parent` in general → commitment mismatch → verification failure.
            let n = children.len();
            let mut built = Vec::with_capacity(n);
            let mut xor_acc = challenge; // will accumulate XOR of non-last challenges

            for (i, child) in children.iter().enumerate() {
                let child_challenge = if i < n - 1 {
                    // Sample a fresh challenge for this non-last child.
                    let ch = rng.sample_challenge();
                    xor_bytes(&mut xor_acc, &ch);
                    ch
                } else {
                    // Last child: its challenge must satisfy the verifier's XOR constraint.
                    // parent_challenge = child[0].ch XOR ... XOR child[n-2].ch XOR child[n-1].ch
                    // ⟹ child[n-1].ch = parent_challenge XOR child[0].ch XOR ... XOR child[n-2].ch
                    // xor_acc is already parent XOR child[0].ch XOR ... XOR child[n-2].ch.
                    xor_acc
                };
                built.push(build_tree_simulated(child, child_challenge, rng)?);
            }

            // sim_root_challenge is `challenge` — the value the parent assigned to
            // this OR. get_sim_challenge must return THIS, not children[0]'s challenge,
            // so that any ancestor's XOR-derive uses the correct subtree root challenge.
            Ok(ProverTree::Or {
                children: built,
                sim_root_challenge: Some(challenge),
            })
        }
        SigmaBoolean::Cthreshold { k, children } => {
            // Fully-simulated threshold: pre-sample exactly (n-k) sim
            // challenges (by convention for the FIRST n-k children) and
            // derive the remaining k children's challenges by evaluating Q
            // at their positions, where
            //   Q is the unique degree-(n-k) polynomial over GF(2^192)
            //   with Q(0) = `challenge` and Q(i+1) = sim_challenges[i]
            //
            // The threshold protocol writes (n-k) non-zero-degree
            // coefficients of Q to the proof; the verifier reconstructs Q
            // from those plus the parent challenge (coeff0) and evaluates
            // it at every child position. So both prover and verifier must
            // agree on Q's degree exactly — pre-sampling fewer or more
            // sim_challenges than (n-k) breaks the polynomial degree
            // contract and produces a wrong-length/wrong-degree proof.
            use gf2_192::gf2_192::Gf2_192;
            use gf2_192::gf2_192poly::Gf2_192Poly;

            let k_usize = *k as usize;
            let n = children.len();
            if k_usize > n {
                return Err(WalletError::MissingSecret(format!(
                    "Cthreshold k={k_usize} exceeds children n={n}"
                )));
            }
            let num_sim = n - k_usize;

            let sim_challenges: Vec<(usize, [u8; SOUNDNESS_BYTES])> =
                (0..num_sim).map(|i| (i, rng.sample_challenge())).collect();

            let value_at_zero = Gf2_192::from(challenge);
            let interp_points: Vec<u8> =
                sim_challenges.iter().map(|(i, _)| (i + 1) as u8).collect();
            let interp_values: Vec<Gf2_192> = sim_challenges
                .iter()
                .map(|(_, ch)| Gf2_192::from(*ch))
                .collect();
            let poly = Gf2_192Poly::interpolate(&interp_points, &interp_values, value_at_zero)
                .map_err(|_| {
                    WalletError::MissingSecret(
                        "Cthreshold simulation: polynomial interpolation failed".into(),
                    )
                })?;

            let mut built: Vec<ProverTree> = Vec::with_capacity(n);
            for (i, child) in children.iter().enumerate() {
                let child_ch: [u8; SOUNDNESS_BYTES] = if i < num_sim {
                    sim_challenges[i].1
                } else {
                    poly.evaluate((i + 1) as u8).into()
                };
                built.push(build_tree_simulated(child, child_ch, rng)?);
            }

            Ok(ProverTree::Threshold {
                k: k_usize,
                children: built,
                sim_challenges,
                sim_root_challenge: Some(challenge),
            })
        }
    }
}
