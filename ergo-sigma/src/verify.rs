use thiserror::Error;

use super::dht;
use super::schnorr;
use super::{GROUP_SIZE, SOUNDNESS_BYTES};
use crate::blake2b256;

pub use ergo_ser::sigma_value::SigmaBoolean;

/// Per-leaf data extracted from a fully-parsed sigma proof tree.
///
/// Returned by [`extract_proof_leaves`] for use by multi-sig hint
/// extractors (e.g., `ergo-wallet::proving::extract::bag_for_multisig`).
/// Keeping this flat avoids leaking the crate-private `UncheckedTree`
/// internals (which carry `gf2_192` polynomial state).
#[derive(Debug, Clone)]
pub struct ProofLeaf {
    /// The sigma proposition this leaf proves (e.g., `ProveDlog(pk)`).
    pub proposition: SigmaBoolean,
    /// Commitment bytes recomputed from challenge + response.
    ///
    /// Schnorr (ProveDlog): 33 bytes = compressed `R = g^z - pk*e`.
    /// DHT (ProveDHTuple): 66 bytes = compressed `a(33) || b(33)`.
    pub commitment_bytes: Vec<u8>,
    /// Fiat-Shamir challenge for this leaf (24 bytes, 192-bit soundness).
    pub challenge: [u8; SOUNDNESS_BYTES],
    /// Schnorr response scalar `z` (32 bytes, big-endian).
    pub response: [u8; GROUP_SIZE],
    /// Depth-first position from the crypto-tree root `[0]` (Scala CryptoTreePrefix).
    pub position: Vec<u32>,
}

/// Parse a sigma proof and compute commitments; return all leaf nodes.
///
/// Mirrors the path the verifier takes (Steps 1-4), but instead of
/// performing a Fiat-Shamir check, returns per-leaf data so callers
/// can populate a `HintsBag` for multi-sig protocols.
///
/// Uses `[0]` as the position root, matching Scala `NodePosition.CryptoTreePrefix`.
pub fn extract_proof_leaves(
    proposition: &SigmaBoolean,
    proof_bytes: &[u8],
) -> Result<Vec<ProofLeaf>, SigmaVerifyError> {
    let mut offset = 0;
    let unchecked = parse_and_compute_challenges(proposition, proof_bytes, &mut offset, None)?;
    let with_commits = compute_commitments(unchecked)?;
    let mut leaves = Vec::new();
    collect_leaves(&with_commits, proposition, &[0], &mut leaves);
    Ok(leaves)
}

/// Recursively collect leaf nodes from the parsed+computed tree into `out`.
fn collect_leaves(
    node: &UncheckedTree,
    sigma_node: &SigmaBoolean,
    position: &[u32],
    out: &mut Vec<ProofLeaf>,
) {
    match (node, sigma_node) {
        (
            UncheckedTree::Schnorr {
                challenge,
                z,
                commitment,
                ..
            },
            prop @ SigmaBoolean::ProveDlog(_),
        ) => {
            let commitment_bytes = commitment
                .clone()
                .expect("commitment populated by compute_commitments");
            let mut ch = [0u8; SOUNDNESS_BYTES];
            let src = if challenge.len() >= SOUNDNESS_BYTES {
                &challenge[..SOUNDNESS_BYTES]
            } else {
                challenge
            };
            ch[SOUNDNESS_BYTES - src.len()..].copy_from_slice(src);
            let mut resp = [0u8; GROUP_SIZE];
            let zsrc = if z.len() >= GROUP_SIZE {
                &z[..GROUP_SIZE]
            } else {
                z
            };
            resp[GROUP_SIZE - zsrc.len()..].copy_from_slice(zsrc);
            out.push(ProofLeaf {
                proposition: prop.clone(),
                commitment_bytes,
                challenge: ch,
                response: resp,
                position: position.to_vec(),
            });
        }
        (
            UncheckedTree::DhTuple {
                challenge,
                z,
                commitment,
                ..
            },
            prop @ SigmaBoolean::ProveDHTuple { .. },
        ) => {
            let commitment_bytes = commitment
                .clone()
                .expect("commitment populated by compute_commitments");
            let mut ch = [0u8; SOUNDNESS_BYTES];
            let src = if challenge.len() >= SOUNDNESS_BYTES {
                &challenge[..SOUNDNESS_BYTES]
            } else {
                challenge
            };
            ch[SOUNDNESS_BYTES - src.len()..].copy_from_slice(src);
            let mut resp = [0u8; GROUP_SIZE];
            let zsrc = if z.len() >= GROUP_SIZE {
                &z[..GROUP_SIZE]
            } else {
                z
            };
            resp[GROUP_SIZE - zsrc.len()..].copy_from_slice(zsrc);
            out.push(ProofLeaf {
                proposition: prop.clone(),
                commitment_bytes,
                challenge: ch,
                response: resp,
                position: position.to_vec(),
            });
        }
        (UncheckedTree::And { children, .. }, SigmaBoolean::Cand(sigma_children))
        | (UncheckedTree::Or { children, .. }, SigmaBoolean::Cor(sigma_children)) => {
            for (idx, (child_node, child_sigma)) in
                children.iter().zip(sigma_children.iter()).enumerate()
            {
                let mut child_pos = position.to_vec();
                child_pos.push(idx as u32);
                collect_leaves(child_node, child_sigma, &child_pos, out);
            }
        }
        (
            UncheckedTree::Threshold { children, .. },
            SigmaBoolean::Cthreshold {
                children: sigma_children,
                ..
            },
        ) => {
            for (idx, (child_node, child_sigma)) in
                children.iter().zip(sigma_children.iter()).enumerate()
            {
                let mut child_pos = position.to_vec();
                child_pos.push(idx as u32);
                collect_leaves(child_node, child_sigma, &child_pos, out);
            }
        }
        _ => {
            // Structure mismatch: proposition and proof tree don't align.
            // Silently skip — the verifier's Fiat-Shamir check would have
            // caught a genuine mismatch; here we're extracting hints, so
            // a best-effort walk is appropriate.
        }
    }
}

/// Parsed proof tree with challenges and responses.
#[derive(Debug, Clone)]
enum UncheckedTree {
    Schnorr {
        pk: [u8; 33],
        challenge: Vec<u8>,
        z: Vec<u8>,
        commitment: Option<Vec<u8>>, // filled after compute_commitments
    },
    DhTuple {
        g: [u8; 33],
        h: [u8; 33],
        u: [u8; 33],
        v: [u8; 33],
        challenge: Vec<u8>,
        z: Vec<u8>,
        commitment: Option<Vec<u8>>,
    },
    And {
        challenge: Vec<u8>,
        children: Vec<UncheckedTree>,
    },
    Or {
        challenge: Vec<u8>,
        children: Vec<UncheckedTree>,
    },
    Threshold {
        challenge: Vec<u8>,
        children: Vec<UncheckedTree>,
        k: u8,
        polynomial: Option<gf2_192::gf2_192poly::Gf2_192Poly>,
    },
}

impl UncheckedTree {
    fn challenge(&self) -> &[u8] {
        match self {
            UncheckedTree::Schnorr { challenge, .. } => challenge,
            UncheckedTree::DhTuple { challenge, .. } => challenge,
            UncheckedTree::And { challenge, .. } => challenge,
            UncheckedTree::Or { challenge, .. } => challenge,
            UncheckedTree::Threshold { challenge, .. } => challenge,
        }
    }
}

/// Failure modes for [`verify_sigma_proof`].
#[derive(Debug, Error)]
pub enum SigmaVerifyError {
    /// Proof bytes ran out while parsing — `offset` points at the
    /// position where the next read failed.
    #[error("proof too short at offset {offset}")]
    ProofTooShort {
        /// Byte position the parser had reached when the read failed.
        offset: usize,
    },
    /// Recomputed Fiat-Shamir challenge does not match the root
    /// challenge embedded in the proof.
    #[error("challenge mismatch")]
    ChallengeMismatch,
    /// One of the curve points (commitment recomputation) was invalid.
    /// Carries a short label identifying which point.
    #[error("invalid point in proposition: {0}")]
    InvalidPoint(String),
    /// `Cand` / `Cor` / `Cthreshold` proposition has no children — the
    /// proof is structurally invalid.
    #[error("empty children in conjecture")]
    EmptyChildren,
}

/// Verify a sigma proof against a proposition and message.
///
/// This is the top-level entry point that handles AND/OR composition.
/// For standalone DLog/DHT, delegates to the leaf verifiers.
pub fn verify_sigma_proof(
    proposition: &SigmaBoolean,
    proof_bytes: &[u8],
    message: &[u8],
) -> Result<bool, SigmaVerifyError> {
    // Trivial propositions don't need proof verification
    match proposition {
        SigmaBoolean::TrivialProp(true) => return Ok(true),
        SigmaBoolean::TrivialProp(false) => return Ok(false),
        _ => {}
    }

    if proof_bytes.is_empty() {
        return Ok(false);
    }

    // Step 1-3: Parse proof and compute challenges
    let mut offset = 0;
    let unchecked = parse_and_compute_challenges(proposition, proof_bytes, &mut offset, None)?;

    // Step 4: Compute commitments
    let with_commitments = compute_commitments(unchecked)?;

    // Step 5-6: Fiat-Shamir check
    let fs_bytes = fiat_shamir_tree_to_bytes(&with_commitments);
    let mut hash_input = Vec::with_capacity(fs_bytes.len() + message.len());
    hash_input.extend_from_slice(&fs_bytes);
    hash_input.extend_from_slice(message);
    let hash = blake2b256(&hash_input);
    let expected = &hash[..SOUNDNESS_BYTES];

    Ok(with_commitments.challenge() == expected)
}

/// Parse proof bytes and compute challenges for the tree.
/// Matches Scala `SigSerializer.parseAndComputeChallenges`.
fn parse_and_compute_challenges(
    prop: &SigmaBoolean,
    proof: &[u8],
    offset: &mut usize,
    challenge_opt: Option<&[u8]>,
) -> Result<UncheckedTree, SigmaVerifyError> {
    // Read or use provided challenge
    let challenge = if let Some(c) = challenge_opt {
        c.to_vec()
    } else {
        read_bytes(proof, offset, SOUNDNESS_BYTES)?
    };

    match prop {
        SigmaBoolean::TrivialProp(true) | SigmaBoolean::TrivialProp(false) => {
            // Trivial props should be caught before proof parsing
            unreachable!("trivial propositions should not reach proof parsing")
        }
        SigmaBoolean::ProveDlog(ge) => {
            // Scala reads z with getBytesUnsafe — accepts fewer bytes than GROUP_SIZE
            let z = read_bytes_padded(proof, offset, GROUP_SIZE);
            Ok(UncheckedTree::Schnorr {
                pk: *ge.as_bytes(),
                challenge,
                z,
                commitment: None,
            })
        }
        SigmaBoolean::ProveDHTuple { g, h, u, v } => {
            let z = read_bytes_padded(proof, offset, GROUP_SIZE);
            Ok(UncheckedTree::DhTuple {
                g: *g.as_bytes(),
                h: *h.as_bytes(),
                u: *u.as_bytes(),
                v: *v.as_bytes(),
                challenge,
                z,
                commitment: None,
            })
        }
        SigmaBoolean::Cand(children) => {
            if children.is_empty() {
                return Err(SigmaVerifyError::EmptyChildren);
            }
            // AND: all children get the same challenge as the parent
            let mut parsed_children = Vec::with_capacity(children.len());
            for child in children {
                let parsed = parse_and_compute_challenges(child, proof, offset, Some(&challenge))?;
                parsed_children.push(parsed);
            }
            Ok(UncheckedTree::And {
                challenge,
                children: parsed_children,
            })
        }
        SigmaBoolean::Cor(children) => {
            if children.is_empty() {
                return Err(SigmaVerifyError::EmptyChildren);
            }
            // OR: each child except the last reads its own challenge from proof.
            // Last child's challenge = XOR of parent challenge with all other children's challenges.
            let mut parsed_children = Vec::with_capacity(children.len());
            let mut xor_buf = challenge.clone();

            for (i, child) in children.iter().enumerate() {
                if i < children.len() - 1 {
                    // Non-last children: read challenge from proof
                    let parsed = parse_and_compute_challenges(child, proof, offset, None)?;
                    xor_bytes(&mut xor_buf, parsed.challenge());
                    parsed_children.push(parsed);
                } else {
                    // Last child: challenge = accumulated XOR
                    let parsed =
                        parse_and_compute_challenges(child, proof, offset, Some(&xor_buf))?;
                    parsed_children.push(parsed);
                }
            }

            Ok(UncheckedTree::Or {
                challenge,
                children: parsed_children,
            })
        }
        SigmaBoolean::Cthreshold { k, children } => {
            if children.is_empty() {
                return Err(SigmaVerifyError::EmptyChildren);
            }
            let n = children.len();
            let n_coeffs = n - *k as usize;

            // Read polynomial coefficients (n-k coefficients, each SOUNDNESS_BYTES)
            let coeff_bytes = read_bytes(proof, offset, SOUNDNESS_BYTES * n_coeffs)?;

            // Build polynomial: zero coefficient = challenge, rest from proof
            let challenge_arr: [u8; SOUNDNESS_BYTES] = challenge
                .clone()
                .try_into()
                .map_err(|_| SigmaVerifyError::ProofTooShort { offset: *offset })?;
            let c0 = gf2_192::gf2_192::Gf2_192::from(challenge_arr);
            let coeff0: [u8; 24] = c0.into();
            let cc = gf2_192::gf2_192poly::CoefficientsByteRepr {
                coeff0,
                more_coeffs: &coeff_bytes,
            };
            let polynomial = gf2_192::gf2_192poly::Gf2_192Poly::try_from(cc)
                .map_err(|_| SigmaVerifyError::ProofTooShort { offset: *offset })?;

            // Evaluate polynomial at 1, 2, ..., n to get children's challenges
            let mut parsed_children = Vec::with_capacity(n);
            for (i, child) in children.iter().enumerate() {
                let child_challenge_gf = polynomial.evaluate((i + 1) as u8);
                let child_challenge_bytes: [u8; 24] = child_challenge_gf.into();
                let parsed = parse_and_compute_challenges(
                    child,
                    proof,
                    offset,
                    Some(&child_challenge_bytes),
                )?;
                parsed_children.push(parsed);
            }

            Ok(UncheckedTree::Threshold {
                challenge,
                children: parsed_children,
                k: *k,
                polynomial: Some(polynomial),
            })
        }
    }
}

/// Compute commitments for all leaf nodes.
fn compute_commitments(tree: UncheckedTree) -> Result<UncheckedTree, SigmaVerifyError> {
    match tree {
        UncheckedTree::Schnorr {
            pk, challenge, z, ..
        } => {
            let commitment = schnorr::compute_dlog_commitment(&pk, &challenge, &z)
                .map_err(|_| SigmaVerifyError::InvalidPoint("DLog commitment".into()))?;
            Ok(UncheckedTree::Schnorr {
                pk,
                challenge,
                z,
                commitment: Some(commitment),
            })
        }
        UncheckedTree::DhTuple {
            g,
            h,
            u,
            v,
            challenge,
            z,
            ..
        } => {
            let commitment = dht::compute_dht_commitment(&g, &h, &u, &v, &challenge, &z)
                .map_err(|_| SigmaVerifyError::InvalidPoint("DHT commitment".into()))?;
            Ok(UncheckedTree::DhTuple {
                g,
                h,
                u,
                v,
                challenge,
                z,
                commitment: Some(commitment),
            })
        }
        UncheckedTree::And {
            challenge,
            children,
        } => {
            let new_children: Result<Vec<_>, _> =
                children.into_iter().map(compute_commitments).collect();
            Ok(UncheckedTree::And {
                challenge,
                children: new_children?,
            })
        }
        UncheckedTree::Or {
            challenge,
            children,
        } => {
            let new_children: Result<Vec<_>, _> =
                children.into_iter().map(compute_commitments).collect();
            Ok(UncheckedTree::Or {
                challenge,
                children: new_children?,
            })
        }
        UncheckedTree::Threshold {
            challenge,
            children,
            k,
            polynomial,
        } => {
            let new_children: Result<Vec<_>, _> =
                children.into_iter().map(compute_commitments).collect();
            Ok(UncheckedTree::Threshold {
                challenge,
                children: new_children?,
                k,
                polynomial,
            })
        }
    }
}

/// Serialize the proof tree for Fiat-Shamir hashing.
/// Matches Scala `FiatShamirTree.toBytes`.
fn fiat_shamir_tree_to_bytes(tree: &UncheckedTree) -> Vec<u8> {
    const INTERNAL_NODE_PREFIX: u8 = 0;
    const LEAF_PREFIX: u8 = 1;
    const AND_CONJECTURE: u8 = 0;
    const OR_CONJECTURE: u8 = 1;

    let mut buf = Vec::new();

    match tree {
        UncheckedTree::Schnorr { pk, commitment, .. } => {
            let prop_bytes = schnorr::build_prove_dlog_ergo_tree(pk);
            // Always Some: compute_commitments() ran before this and
            // populated every leaf's commitment field.
            let commit = commitment
                .as_ref()
                .expect("commitment populated by compute_commitments");
            buf.push(LEAF_PREFIX);
            buf.extend_from_slice(&(prop_bytes.len() as i16).to_be_bytes());
            buf.extend_from_slice(&prop_bytes);
            buf.extend_from_slice(&(commit.len() as i16).to_be_bytes());
            buf.extend_from_slice(commit);
        }
        UncheckedTree::DhTuple {
            g,
            h,
            u,
            v,
            commitment,
            ..
        } => {
            let prop_bytes = dht::build_prove_dht_ergo_tree(g, h, u, v);
            // Always Some: compute_commitments() ran before this and
            // populated every leaf's commitment field.
            let commit = commitment
                .as_ref()
                .expect("commitment populated by compute_commitments");
            buf.push(LEAF_PREFIX);
            buf.extend_from_slice(&(prop_bytes.len() as i16).to_be_bytes());
            buf.extend_from_slice(&prop_bytes);
            buf.extend_from_slice(&(commit.len() as i16).to_be_bytes());
            buf.extend_from_slice(commit);
        }
        UncheckedTree::And { children, .. } => {
            buf.push(INTERNAL_NODE_PREFIX);
            buf.push(AND_CONJECTURE);
            buf.extend_from_slice(&(children.len() as i16).to_be_bytes());
            for child in children {
                buf.extend_from_slice(&fiat_shamir_tree_to_bytes(child));
            }
        }
        UncheckedTree::Or { children, .. } => {
            buf.push(INTERNAL_NODE_PREFIX);
            buf.push(OR_CONJECTURE);
            buf.extend_from_slice(&(children.len() as i16).to_be_bytes());
            for child in children {
                buf.extend_from_slice(&fiat_shamir_tree_to_bytes(child));
            }
        }
        UncheckedTree::Threshold { children, k, .. } => {
            const THRESHOLD_CONJECTURE: u8 = 2;
            buf.push(INTERNAL_NODE_PREFIX);
            buf.push(THRESHOLD_CONJECTURE);
            buf.push(*k);
            buf.extend_from_slice(&(children.len() as i16).to_be_bytes());
            for child in children {
                buf.extend_from_slice(&fiat_shamir_tree_to_bytes(child));
            }
        }
    }

    buf
}

fn read_bytes(proof: &[u8], offset: &mut usize, n: usize) -> Result<Vec<u8>, SigmaVerifyError> {
    if *offset + n > proof.len() {
        return Err(SigmaVerifyError::ProofTooShort { offset: *offset });
    }
    let bytes = proof[*offset..*offset + n].to_vec();
    *offset += n;
    Ok(bytes)
}

/// Read up to `n` bytes, left-padding with zeros if fewer are available.
/// Matches Scala's `getBytesUnsafe(n)` which reads `min(n, remaining)`.
/// Used for BigInt response values (z) which may omit leading zero bytes.
fn read_bytes_padded(proof: &[u8], offset: &mut usize, n: usize) -> Vec<u8> {
    let remaining = proof.len().saturating_sub(*offset);
    let to_read = remaining.min(n);
    let pad = n - to_read;
    let mut result = vec![0u8; pad];
    result.extend_from_slice(&proof[*offset..*offset + to_read]);
    *offset += to_read;
    result
}

fn xor_bytes(buf: &mut [u8], other: &[u8]) {
    for (a, b) in buf.iter_mut().zip(other.iter()) {
        *a ^= *b;
    }
}
