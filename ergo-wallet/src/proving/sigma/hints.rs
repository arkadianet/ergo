//! `HintsBag` + `SecretRegistry` lookup helpers used during build.
//!
//! Cooperating-party flows: a multi-sig leaf may have its proof
//! supplied as a `RealSecretProof` / `SimulatedSecretProof` hint, in
//! which case `build_tree` reuses the (challenge, z) directly instead
//! of sampling fresh randomness. Commitments may be supplied
//! independently via `*Commitment` hints; if absent, back-derive.

use ergo_ser::sigma_value::SigmaBoolean;
use k256::elliptic_curve::group::GroupEncoding;
use k256::{ProjectivePoint, Scalar};

use crate::proving::hints::{FirstProverMessage, Hint, HintsBag};
use crate::proving::node_position::NodePosition;

/// Extract a `RealSecretProof` for a leaf from the hints bag, matched by `(image, position)`.
pub(super) fn find_real_secret_proof_compound<'a>(
    prop: &SigmaBoolean,
    position: &NodePosition,
    hints: &'a HintsBag,
) -> Option<&'a crate::proving::hints::RealSecretProof> {
    for hint in &hints.hints {
        if let crate::proving::hints::Hint::RealSecretProof(rsp) = hint {
            if &rsp.image == prop && &rsp.position == position {
                return Some(rsp);
            }
        }
    }
    None
}

/// Extract a `SimulatedSecretProof` for a leaf from the hints bag, matched by `(image, position)`.
pub(super) fn find_simulated_secret_proof_compound<'a>(
    prop: &SigmaBoolean,
    position: &NodePosition,
    hints: &'a HintsBag,
) -> Option<&'a crate::proving::hints::SimulatedSecretProof> {
    for hint in &hints.hints {
        if let crate::proving::hints::Hint::SimulatedSecretProof(ssp) = hint {
            if &ssp.image == prop && &ssp.position == position {
                return Some(ssp);
            }
        }
    }
    None
}

/// Extract the commitment bytes from a `RealCommitment` hint for a Schnorr leaf.
pub(super) fn find_real_commitment_schnorr(
    prop: &SigmaBoolean,
    position: &NodePosition,
    hints: &HintsBag,
) -> Option<[u8; 33]> {
    for hint in &hints.hints {
        if let crate::proving::hints::Hint::RealCommitment(rc) = hint {
            if &rc.image == prop && &rc.position == position {
                if let FirstProverMessage::Schnorr(r_pt) = &rc.commitment {
                    return Some(*r_pt);
                }
            }
        }
    }
    None
}

/// Extract the commitment bytes from a `SimulatedCommitment` hint for a Schnorr leaf.
pub(super) fn find_simulated_commitment_schnorr(
    prop: &SigmaBoolean,
    position: &NodePosition,
    hints: &HintsBag,
) -> Option<[u8; 33]> {
    for hint in &hints.hints {
        if let crate::proving::hints::Hint::SimulatedCommitment(sc) = hint {
            if &sc.image == prop && &sc.position == position {
                if let FirstProverMessage::Schnorr(r_pt) = &sc.commitment {
                    return Some(*r_pt);
                }
            }
        }
    }
    None
}

/// Extract the commitment bytes from a `RealCommitment` hint for a DHT leaf.
pub(super) fn find_real_commitment_dht(
    prop: &SigmaBoolean,
    position: &NodePosition,
    hints: &HintsBag,
) -> Option<([u8; 33], [u8; 33])> {
    for hint in &hints.hints {
        if let crate::proving::hints::Hint::RealCommitment(rc) = hint {
            if &rc.image == prop && &rc.position == position {
                if let FirstProverMessage::DhTuple { a, b } = &rc.commitment {
                    return Some((*a, *b));
                }
            }
        }
    }
    None
}

/// Extract the commitment bytes from a `SimulatedCommitment` hint for a DHT leaf.
pub(super) fn find_simulated_commitment_dht(
    prop: &SigmaBoolean,
    position: &NodePosition,
    hints: &HintsBag,
) -> Option<([u8; 33], [u8; 33])> {
    for hint in &hints.hints {
        if let crate::proving::hints::Hint::SimulatedCommitment(sc) = hint {
            if &sc.image == prop && &sc.position == position {
                if let FirstProverMessage::DhTuple { a, b } = &sc.commitment {
                    return Some((*a, *b));
                }
            }
        }
    }
    None
}

/// Extract an `OwnCommitment` for a Schnorr leaf from the hints bag.
/// Matches by both image and position. Returns `(r, R_point)` if found.
pub(super) fn find_own_commitment_schnorr(
    prop: &SigmaBoolean,
    position: &NodePosition,
    hints: &HintsBag,
) -> Option<(Scalar, [u8; 33])> {
    for hint in &hints.hints {
        if let Hint::OwnCommitment(oc) = hint {
            if &oc.image == prop && &oc.position == position {
                if let FirstProverMessage::Schnorr(r_pt) = &oc.commitment {
                    let r = scalar_from_bytes_tree(&oc.secret_randomness)?;
                    return Some((r, *r_pt));
                }
            }
        }
    }
    None
}

/// Extract an `OwnCommitment` for a DHT leaf from the hints bag.
/// Matches by both image and position. Returns `(r, a_bytes, b_bytes)` if found.
pub(super) fn find_own_commitment_dht(
    prop: &SigmaBoolean,
    position: &NodePosition,
    hints: &HintsBag,
    g_pt: &ProjectivePoint,
    h_pt: &ProjectivePoint,
) -> Option<(Scalar, [u8; 33], [u8; 33])> {
    for hint in &hints.hints {
        if let Hint::OwnCommitment(oc) = hint {
            if &oc.image == prop && &oc.position == position {
                let r = scalar_from_bytes_tree(&oc.secret_randomness)?;
                let (a, b) = match &oc.commitment {
                    FirstProverMessage::DhTuple { a, b } => (*a, *b),
                    FirstProverMessage::Schnorr(_) => {
                        // Unexpected variant — recompute from r.
                        let a: [u8; 33] = (*g_pt * r).to_affine().to_bytes().into();
                        let b: [u8; 33] = (*h_pt * r).to_affine().to_bytes().into();
                        (a, b)
                    }
                };
                return Some((r, a, b));
            }
        }
    }
    None
}

/// Decode 32 bytes as a secp256k1 scalar (big-endian).
pub(super) fn scalar_from_bytes_tree(bytes: &[u8; 32]) -> Option<Scalar> {
    use k256::elliptic_curve::ops::Reduce;
    use k256::U256;
    let s = <Scalar as Reduce<U256>>::reduce_bytes(&(*bytes).into());
    if s == Scalar::ZERO {
        None
    } else {
        Some(s)
    }
}
