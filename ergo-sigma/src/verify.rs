use thiserror::Error;

use super::dht;
use super::schnorr;
use super::{GROUP_SIZE, SOUNDNESS_BYTES};
use crate::blake2b256;

use ergo_ser::sigma_value::is_valid_cthreshold_shape;

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
///
/// This is an unmetered protocol primitive. Callers must bound the logical
/// proposition size or precharge its crypto cost before passing untrusted
/// inputs. Shared storage does not bound the expanded proof/leaf output. Use
/// [`extract_proof_leaves_with_cost`] when an enforcing budget is available.
pub fn extract_proof_leaves(
    proposition: &SigmaBoolean,
    proof_bytes: &[u8],
) -> Result<Vec<ProofLeaf>, SigmaVerifyError> {
    // A trivial ROOT proposition has no cryptographic leaves to extract, so
    // short-circuit before parsing — mirroring verify_sigma_proof's root
    // handling. Only a NESTED trivial child signals the reduction-invariant
    // violation that `parse_and_compute_challenges` rejects. A trivially
    // reduced input (e.g. a script reducing to `sigmaProp(true)`) reaches here
    // via the wallet's `bag_for_transaction`; it must yield an empty bag, not
    // an error that would break hint extraction for the whole transaction.
    if matches!(proposition, SigmaBoolean::TrivialProp(_)) {
        return Ok(Vec::new());
    }
    let mut offset = 0;
    let unchecked = parse_and_compute_challenges(proposition, proof_bytes, &mut offset, None)?;
    let with_commits = compute_commitments(unchecked)?;
    let mut leaves = Vec::new();
    collect_leaves(&with_commits, proposition, &[0], &mut leaves);
    Ok(leaves)
}

/// Collect leaves in depth-first order without recursive traversal or copying
/// every intermediate path. Only a returned leaf owns a position vector.
fn collect_leaves(
    tree: &UncheckedTree,
    proposition: &SigmaBoolean,
    root_position: &[u32],
    out: &mut Vec<ProofLeaf>,
) {
    enum Walk<'a> {
        Enter(usize, &'a SigmaBoolean, Option<u32>),
        Leave(bool),
    }
    let mut position = root_position.to_vec();
    let mut pending = vec![Walk::Enter(0, proposition, None)];
    while let Some(step) = pending.pop() {
        let (index, sigma_node, child_index) = match step {
            Walk::Leave(pushed) => {
                if pushed {
                    position.pop();
                }
                continue;
            }
            Walk::Enter(index, prop, child_index) => (index, prop, child_index),
        };
        if let Some(child_index) = child_index {
            position.push(child_index);
        }
        pending.push(Walk::Leave(child_index.is_some()));
        match (&tree.nodes[index], sigma_node) {
            (
                UncheckedNode::Schnorr {
                    challenge,
                    z,
                    commitment,
                    ..
                },
                prop @ SigmaBoolean::ProveDlog(_),
            )
            | (
                UncheckedNode::DhTuple {
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
                let src = &challenge[..challenge.len().min(SOUNDNESS_BYTES)];
                ch[SOUNDNESS_BYTES - src.len()..].copy_from_slice(src);
                let mut resp = [0u8; GROUP_SIZE];
                let src = &z[..z.len().min(GROUP_SIZE)];
                resp[GROUP_SIZE - src.len()..].copy_from_slice(src);
                out.push(ProofLeaf {
                    proposition: prop.clone(),
                    commitment_bytes,
                    challenge: ch,
                    response: resp,
                    position: position.clone(),
                });
            }
            (UncheckedNode::And { children, .. }, SigmaBoolean::Cand(sigma_children))
            | (UncheckedNode::Or { children, .. }, SigmaBoolean::Cor(sigma_children))
            | (
                UncheckedNode::Threshold { children, .. },
                SigmaBoolean::Cthreshold {
                    children: sigma_children,
                    ..
                },
            ) => {
                for (idx, (&child, prop)) in
                    children.iter().zip(sigma_children.iter()).enumerate().rev()
                {
                    pending.push(Walk::Enter(child, prop, Some(idx as u32)));
                }
            }
            _ => {}
        }
    }
}

/// Proof nodes are stored in depth-first preorder. Child indices keep parsing,
/// commitment computation, serialization and destruction independent of the
/// native call stack, including when parsing fails partway through a deep tree.
#[derive(Debug, Clone)]
struct UncheckedTree {
    nodes: Vec<UncheckedNode>,
}

#[derive(Debug, Clone)]
enum UncheckedNode {
    Schnorr {
        pk: [u8; 33],
        challenge: Vec<u8>,
        z: Vec<u8>,
        commitment: Option<Vec<u8>>,
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
        children: Vec<usize>,
    },
    Or {
        challenge: Vec<u8>,
        children: Vec<usize>,
    },
    Threshold {
        challenge: Vec<u8>,
        children: Vec<usize>,
        k: u16,
    },
}

impl UncheckedNode {
    fn challenge(&self) -> &[u8] {
        match self {
            Self::Schnorr { challenge, .. }
            | Self::DhTuple { challenge, .. }
            | Self::And { challenge, .. }
            | Self::Or { challenge, .. }
            | Self::Threshold { challenge, .. } => challenge,
        }
    }

    fn children_mut(&mut self) -> &mut Vec<usize> {
        match self {
            Self::And { children, .. }
            | Self::Or { children, .. }
            | Self::Threshold { children, .. } => children,
            _ => unreachable!("only conjectures own child frames"),
        }
    }
}

impl UncheckedTree {
    fn challenge(&self) -> &[u8] {
        self.nodes[0].challenge()
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
    /// `Cor` proposition has no last child for challenge computation.
    #[error("empty children in conjecture")]
    EmptyChildren,
    #[error("invalid Cthreshold: k={k}, n={n}")]
    InvalidThreshold { k: u16, n: usize },
    /// A `TrivialProp` appeared as a conjecture child during proof parsing.
    /// Reduction (`AtLeast.reduce`, `SigmaOr` / `SigmaAnd`) must fold these
    /// out before verification; reaching the parser means that invariant was
    /// violated. Rejected rather than panicked because this runs on the
    /// consensus transaction-verification path.
    #[error("unexpected trivial proposition as conjecture child")]
    UnexpectedTrivialChild,
}

/// Failure when metering a proposition before verification or hint extraction.
#[derive(Debug, Error)]
pub enum BudgetedSigmaError {
    /// The proposition's reference crypto charge exceeds the caller's budget.
    #[error(transparent)]
    Cost(#[from] ergo_primitives::cost::CostError),
    /// Metering succeeded, but proof parsing or commitment computation failed.
    #[error(transparent)]
    Verification(#[from] SigmaVerifyError),
}

fn charge_crypto(
    proposition: &SigmaBoolean,
    cost: &mut ergo_primitives::cost::CostAccumulator,
) -> Result<(), ergo_primitives::cost::CostError> {
    cost.add(ergo_primitives::cost::JitCost::from_jit_block_aligned(
        crate::crypto_cost::estimate_crypto_cost(proposition),
    ))
}

/// Charge reference crypto cost before expanding a proof tree, then verify it.
///
/// The caller supplies the enforcing budget. The charge is block-aligned like
/// Scala's per-input crypto charge; it does not include expression reduction.
/// A recording-only accumulator deliberately provides no resource ceiling.
pub fn verify_sigma_proof_with_cost(
    proposition: &SigmaBoolean,
    proof_bytes: &[u8],
    message: &[u8],
    cost: &mut ergo_primitives::cost::CostAccumulator,
) -> Result<bool, BudgetedSigmaError> {
    charge_crypto(proposition, cost)?;
    Ok(verify_sigma_proof(proposition, proof_bytes, message)?)
}

/// Charge reference crypto cost before expanding proof leaves for multisig.
///
/// Use an enforcing accumulator for untrusted propositions. Returned leaf
/// positions and commitments count logical occurrences, including shared ones.
pub fn extract_proof_leaves_with_cost(
    proposition: &SigmaBoolean,
    proof_bytes: &[u8],
    cost: &mut ergo_primitives::cost::CostAccumulator,
) -> Result<Vec<ProofLeaf>, BudgetedSigmaError> {
    charge_crypto(proposition, cost)?;
    Ok(extract_proof_leaves(proposition, proof_bytes)?)
}

fn validate_cthreshold_shape(k: u16, children: &[SigmaBoolean]) -> Result<usize, SigmaVerifyError> {
    let n = children.len();
    if is_valid_cthreshold_shape(k, n) {
        Ok(n)
    } else {
        Err(SigmaVerifyError::InvalidThreshold { k, n })
    }
}

fn validate_cthreshold_tree(proposition: &SigmaBoolean) -> Result<(), SigmaVerifyError> {
    let mut pending = vec![proposition];
    let mut visited = std::collections::HashSet::new();
    while let Some(proposition) = pending.pop() {
        if !visited.insert(proposition as *const SigmaBoolean) {
            continue;
        }
        match proposition {
            SigmaBoolean::Cthreshold { k, children } => {
                validate_cthreshold_shape(*k, children)?;
                pending.extend(children.iter().rev());
            }
            SigmaBoolean::Cand(children) | SigmaBoolean::Cor(children) => {
                pending.extend(children.iter().rev());
            }
            _ => {}
        }
    }
    Ok(())
}

/// Verify a sigma proof against a proposition and message.
///
/// This is the top-level entry point that handles AND/OR composition.
/// For standalone DLog/DHT, delegates to the leaf verifiers.
///
/// This unmetered protocol primitive assumes the caller has bounded the
/// logical proposition size or already charged its crypto cost. Prefer
/// [`verify_sigma_proof_with_cost`] for untrusted reduced propositions, or
/// [`crate::reduce::verify_spending_proof_with_context_and_cost`] for scripts.
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
        validate_cthreshold_tree(proposition)?;
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

/// Parse proof bytes in Scala's depth-first order. OR frames retain the XOR
/// of preceding children; threshold frames retain the reference polynomial.
fn parse_and_compute_challenges(
    prop: &SigmaBoolean,
    proof: &[u8],
    offset: &mut usize,
    challenge_opt: Option<&[u8]>,
) -> Result<UncheckedTree, SigmaVerifyError> {
    enum ChildChallenges {
        And,
        Or(Vec<u8>),
        Threshold(gf2_192::gf2_192poly::Gf2_192Poly),
    }
    struct Frame<'a> {
        node: usize,
        children: &'a [SigmaBoolean],
        next: usize,
        challenges: ChildChallenges,
    }
    let mut nodes: Vec<UncheckedNode> = Vec::new();
    let mut frames: Vec<Frame<'_>> = Vec::new();
    let mut pending = Some((prop, challenge_opt.map(<[u8]>::to_vec)));
    while let Some((prop, provided_challenge)) = pending.take() {
        if let SigmaBoolean::Cthreshold { k, children } = prop {
            validate_cthreshold_shape(*k, children)?;
        }
        let challenge = if let Some(challenge) = provided_challenge {
            challenge
        } else {
            read_bytes(proof, offset, SOUNDNESS_BYTES)?
        };
        let index = nodes.len();
        let mut frame = None;
        let node = match prop {
            SigmaBoolean::TrivialProp(_) => return Err(SigmaVerifyError::UnexpectedTrivialChild),
            SigmaBoolean::ProveDlog(ge) => UncheckedNode::Schnorr {
                pk: *ge.as_bytes(),
                challenge,
                z: read_bytes_padded(proof, offset, GROUP_SIZE),
                commitment: None,
            },
            SigmaBoolean::ProveDHTuple { g, h, u, v } => UncheckedNode::DhTuple {
                g: *g.as_bytes(),
                h: *h.as_bytes(),
                u: *u.as_bytes(),
                v: *v.as_bytes(),
                challenge,
                z: read_bytes_padded(proof, offset, GROUP_SIZE),
                commitment: None,
            },
            SigmaBoolean::Cand(children) | SigmaBoolean::Cor(children) => {
                let is_and = matches!(prop, SigmaBoolean::Cand(_));
                // Deliberately match the JVM consensus quirk: CAND's empty loop
                // builds an unchecked node, while COR indexes its last child
                // and fails. The empty AND still needs its Fiat-Shamir challenge.
                // https://github.com/ergoplatform/sigmastate-interpreter/blob/v6.0.7/interpreter/shared/src/main/scala/sigmastate/SigSerializer.scala#L210-L240
                // The proposition's child count is read as an unsigned short;
                // Fiat-Shamir framing below uses signed-short bits separately.
                // https://github.com/ergoplatform/sigmastate-interpreter/blob/v6.0.7/core/shared/src/main/scala/sigma/data/SigmaBoolean.scala#L80-L86
                if children.is_empty() && !is_and {
                    return Err(SigmaVerifyError::EmptyChildren);
                }
                frame = Some(Frame {
                    node: index,
                    children,
                    next: 0,
                    challenges: if is_and {
                        ChildChallenges::And
                    } else {
                        ChildChallenges::Or(challenge.clone())
                    },
                });
                let children = Vec::with_capacity(children.len());
                if is_and {
                    UncheckedNode::And {
                        challenge,
                        children,
                    }
                } else {
                    UncheckedNode::Or {
                        challenge,
                        children,
                    }
                }
            }
            SigmaBoolean::Cthreshold { k, children } => {
                let n = validate_cthreshold_shape(*k, children)?;
                // Deliberately match the JVM consensus quirk: k=0, n=0 parses
                // a constant polynomial and an unchecked node with no children.
                // Constructor bounds above still reject every invalid shape.
                // https://github.com/ergoplatform/sigmastate-interpreter/blob/v6.0.7/interpreter/shared/src/main/scala/sigmastate/SigSerializer.scala#L242-L263
                // https://github.com/ergoplatform/sigmastate-interpreter/blob/v6.0.7/interpreter/shared/src/main/scala/sigmastate/UncheckedTree.scala#L46-L54
                let n_coeffs = n
                    .checked_sub(usize::from(*k))
                    .ok_or(SigmaVerifyError::InvalidThreshold { k: *k, n })?;
                let coeff_size = SOUNDNESS_BYTES
                    .checked_mul(n_coeffs)
                    .ok_or(SigmaVerifyError::ProofTooShort { offset: *offset })?;
                // Deliberately match the JVM consensus quirk: readBytesChecked
                // consumes whatever remains and only warns on a short read.
                // GF2_192_Poly uses length / 24 complete coefficients, ignoring
                // the consumed partial coefficient. Costs still use n-k.
                // https://github.com/ergoplatform/sigmastate-interpreter/blob/v6.0.7/interpreter/shared/src/main/scala/sigmastate/SigSerializer.scala#L156-L163
                // https://github.com/ergoplatform/sigmastate-interpreter/blob/v6.0.7/interpreter/shared/src/main/scala/sigmastate/SigSerializer.scala#L247-L253
                // https://github.com/ergoplatform/sigmastate-interpreter/blob/v6.0.7/interpreter/shared/src/main/scala/sigmastate/crypto/GF2_192_Poly.scala#L50-L58
                let start = (*offset).min(proof.len());
                let count = coeff_size.min(proof.len() - start);
                *offset = start + count;
                let complete_count = count / SOUNDNESS_BYTES * SOUNDNESS_BYTES;
                let coeff_bytes = &proof[start..start + complete_count];
                let coeff0: [u8; SOUNDNESS_BYTES] = challenge
                    .as_slice()
                    .try_into()
                    .map_err(|_| SigmaVerifyError::ProofTooShort { offset: *offset })?;
                let polynomial = gf2_192::gf2_192poly::Gf2_192Poly::try_from(
                    gf2_192::gf2_192poly::CoefficientsByteRepr {
                        coeff0,
                        more_coeffs: coeff_bytes,
                    },
                )
                .map_err(|_| SigmaVerifyError::ProofTooShort { offset: *offset })?;
                frame = Some(Frame {
                    node: index,
                    children,
                    next: 0,
                    challenges: ChildChallenges::Threshold(polynomial),
                });
                UncheckedNode::Threshold {
                    challenge,
                    children: Vec::with_capacity(n),
                    k: *k,
                }
            }
        };
        nodes.push(node);
        if let Some(parent) = frames.last_mut() {
            if let ChildChallenges::Or(xor) = &mut parent.challenges {
                if parent.next < parent.children.len() {
                    xor_bytes(xor, nodes[index].challenge());
                }
            }
            nodes[parent.node].children_mut().push(index);
        }
        if let Some(frame) = frame {
            frames.push(frame);
        }
        while let Some(frame) = frames.last_mut() {
            if frame.next == frame.children.len() {
                frames.pop();
                continue;
            }
            let child_index = frame.next;
            let challenge = match &frame.challenges {
                ChildChallenges::And => Some(nodes[frame.node].challenge().to_vec()),
                ChildChallenges::Or(xor) if child_index + 1 == frame.children.len() => {
                    Some(xor.clone())
                }
                ChildChallenges::Or(_) => None,
                ChildChallenges::Threshold(poly) => {
                    let bytes: [u8; SOUNDNESS_BYTES] =
                        poly.evaluate((child_index + 1) as u8).into();
                    Some(bytes.to_vec())
                }
            };
            pending = Some((&frame.children[child_index], challenge));
            frame.next += 1;
            break;
        }
    }
    Ok(UncheckedTree { nodes })
}

/// Compute leaf commitments in the same depth-first order as the parser.
fn compute_commitments(mut tree: UncheckedTree) -> Result<UncheckedTree, SigmaVerifyError> {
    for node in &mut tree.nodes {
        match node {
            UncheckedNode::Schnorr {
                pk,
                challenge,
                z,
                commitment,
            } => {
                *commitment = Some(
                    schnorr::compute_dlog_commitment(pk, challenge, z)
                        .map_err(|_| SigmaVerifyError::InvalidPoint("DLog commitment".into()))?,
                );
            }
            UncheckedNode::DhTuple {
                g,
                h,
                u,
                v,
                challenge,
                z,
                commitment,
            } => {
                *commitment = Some(
                    dht::compute_dht_commitment(g, h, u, v, challenge, z)
                        .map_err(|_| SigmaVerifyError::InvalidPoint("DHT commitment".into()))?,
                );
            }
            _ => {}
        }
    }
    Ok(tree)
}

/// Serialize the proof tree for Fiat-Shamir hashing.
/// Matches Scala `FiatShamirTree.toBytes`.
fn fiat_shamir_tree_to_bytes(tree: &UncheckedTree) -> Vec<u8> {
    // Deliberately match the JVM consensus quirk: children.length.toShort
    // wraps counts above 32767 in Fiat-Shamir framing, even though the wire
    // proposition's getUShort keeps its unsigned count (e.g. 40000 children).
    // https://github.com/ergoplatform/sigmastate-interpreter/blob/v6.0.7/interpreter/shared/src/main/scala/sigmastate/UnprovenTree.scala#L267-L289
    const INTERNAL_NODE_PREFIX: u8 = 0;
    const LEAF_PREFIX: u8 = 1;
    const AND_CONJECTURE: u8 = 0;
    const OR_CONJECTURE: u8 = 1;

    let mut buf = Vec::new();

    for node in &tree.nodes {
        match node {
            UncheckedNode::Schnorr { pk, commitment, .. } => {
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
            UncheckedNode::DhTuple {
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
            UncheckedNode::And { children, .. } => {
                buf.push(INTERNAL_NODE_PREFIX);
                buf.push(AND_CONJECTURE);
                buf.extend_from_slice(&(children.len() as i16).to_be_bytes());
            }
            UncheckedNode::Or { children, .. } => {
                buf.push(INTERNAL_NODE_PREFIX);
                buf.push(OR_CONJECTURE);
                buf.extend_from_slice(&(children.len() as i16).to_be_bytes());
            }
            UncheckedNode::Threshold { children, k, .. } => {
                const THRESHOLD_CONJECTURE: u8 = 2;
                buf.push(INTERNAL_NODE_PREFIX);
                buf.push(THRESHOLD_CONJECTURE);
                // Fiat-Shamir tree encodes k as a single byte (Scala UnprovenTree.toBytes:
                // `w.put(unchecked.k.toByte)`), independent of the u16 wire width elsewhere.
                buf.push(*k as u8);
                buf.extend_from_slice(&(children.len() as i16).to_be_bytes());
            }
        }
    }
    buf
}

fn read_bytes(proof: &[u8], offset: &mut usize, n: usize) -> Result<Vec<u8>, SigmaVerifyError> {
    let end = (*offset)
        .checked_add(n)
        .ok_or(SigmaVerifyError::ProofTooShort { offset: *offset })?;
    if end > proof.len() {
        return Err(SigmaVerifyError::ProofTooShort { offset: *offset });
    }
    let bytes = proof[*offset..end].to_vec();
    *offset = end;
    Ok(bytes)
}

/// Read up to `n` bytes, left-padding with zeros if fewer are available.
/// Matches Scala's `getBytesUnsafe(n)` which reads `min(n, remaining)`.
/// Used for BigInt response values (z) which may omit leading zero bytes.
fn read_bytes_padded(proof: &[u8], offset: &mut usize, n: usize) -> Vec<u8> {
    let remaining = proof.len().saturating_sub(*offset);
    let to_read = remaining.min(n);
    let pad = n - to_read;
    let start = (*offset).min(proof.len());
    let end = start.checked_add(to_read).unwrap_or(proof.len());
    let mut result = vec![0u8; pad];
    result.extend_from_slice(&proof[start..end]);
    *offset = end;
    result
}

fn xor_bytes(buf: &mut [u8], other: &[u8]) {
    for (a, b) in buf.iter_mut().zip(other.iter()) {
        *a ^= *b;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::group_element::GroupElement;

    #[test]
    fn deep_proof_paths_and_partial_failure_fit_a_bounded_stack() {
        std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(|| {
                use k256::elliptic_curve::group::GroupEncoding;
                let point = k256::ProjectivePoint::GENERATOR.to_affine().to_bytes();
                let mut prop = SigmaBoolean::ProveDlog(GroupElement::from_bytes(point.into()));
                for depth in 0..10_000 {
                    prop = match depth % 3 {
                        0 => SigmaBoolean::Cand(vec![prop].into()),
                        1 => SigmaBoolean::Cor(vec![prop].into()),
                        _ => SigmaBoolean::Cthreshold {
                            k: 1,
                            children: vec![prop].into(),
                        },
                    };
                }
                // A single-child conjecture forwards its challenge. Parsing,
                // commitments, Fiat-Shamir bytes, leaf positions and cleanup
                // must all tolerate depth independently of the native stack.
                let proof = [0u8; SOUNDNESS_BYTES + GROUP_SIZE];
                assert!(!verify_sigma_proof(&prop, &proof, b"depth regression").unwrap());
                let leaves = extract_proof_leaves(&prop, &proof).unwrap();
                assert_eq!(leaves.len(), 1);
                assert_eq!(leaves[0].position, vec![0; 10_001]);
                assert!(leaves[0].challenge.iter().all(|byte| *byte == 0));

                // OR needs an explicit challenge for its first child. This
                // error occurs below the entire valid prefix; dropping the
                // partially populated proof arena must also stay iterative.
                let mut failing = SigmaBoolean::Cor(vec![prop.clone(), prop.clone()].into());
                for _ in 0..10_000 {
                    failing = SigmaBoolean::Cand(vec![failing].into());
                }
                assert!(matches!(
                    verify_sigma_proof(&failing, &[0; SOUNDNESS_BYTES], b""),
                    Err(SigmaVerifyError::ProofTooShort {
                        offset: SOUNDNESS_BYTES
                    })
                ));
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn empty_proof_threshold_validation_visits_shared_nodes_once() {
        let mut prop = threshold_prop(2, 1);
        for _ in 0..64 {
            prop = SigmaBoolean::Cand(vec![prop.clone(), prop].into());
        }
        assert!(matches!(
            verify_sigma_proof(&prop, &[], b""),
            Err(SigmaVerifyError::InvalidThreshold { k: 2, n: 1 })
        ));
    }

    #[test]
    fn enforcing_budget_rejects_shared_proof_expansion_before_parsing() {
        use ergo_primitives::cost::{CostAccumulator, JitCost};
        let mut prop = SigmaBoolean::ProveDlog(GroupElement::from_bytes([2; 33]));
        for _ in 0..64 {
            prop = SigmaBoolean::Cand(vec![prop.clone(), prop].into());
        }
        let mut budget = CostAccumulator::new(JitCost::from_jit(100_000));
        let proof = [0; SOUNDNESS_BYTES];
        assert!(matches!(
            verify_sigma_proof_with_cost(&prop, &proof, b"", &mut budget),
            Err(BudgetedSigmaError::Cost(_))
        ));
        let mut budget = CostAccumulator::new(JitCost::from_jit(100_000));
        assert!(matches!(
            extract_proof_leaves_with_cost(&prop, &proof, &mut budget),
            Err(BudgetedSigmaError::Cost(_))
        ));
    }

    fn threshold_prop(k: u16, n: usize) -> SigmaBoolean {
        SigmaBoolean::Cthreshold {
            k,
            children: vec![SigmaBoolean::ProveDlog(GroupElement::from_bytes([2u8; 33])); n].into(),
        }
    }

    #[test]
    fn empty_conjectures_require_their_fiat_shamir_challenge() {
        let message = b"empty conjecture consensus regression";
        for (prop, fs_bytes) in [
            (SigmaBoolean::Cand(vec![].into()), vec![0, 0, 0, 0]),
            (threshold_prop(0, 0), vec![0, 2, 0, 0, 0]),
            (
                SigmaBoolean::Cand(vec![threshold_prop(0, 0)].into()),
                vec![0, 0, 0, 1, 0, 2, 0, 0, 0],
            ),
        ] {
            let mut input = fs_bytes;
            input.extend_from_slice(message);
            let mut proof = blake2b256(&input)[..SOUNDNESS_BYTES].to_vec();
            assert!(verify_sigma_proof(&prop, &proof, message).unwrap());
            assert!(extract_proof_leaves(&prop, &proof).unwrap().is_empty());
            assert!(!verify_sigma_proof(&prop, &[], message).unwrap());
            assert!(matches!(
                verify_sigma_proof(&prop, &proof[..SOUNDNESS_BYTES - 1], message),
                Err(SigmaVerifyError::ProofTooShort { .. })
            ));
            proof[0] ^= 1;
            assert!(!verify_sigma_proof(&prop, &proof, message).unwrap());
        }
        assert!(matches!(
            verify_sigma_proof(
                &SigmaBoolean::Cor(vec![].into()),
                &[0; SOUNDNESS_BYTES],
                message
            ),
            Err(SigmaVerifyError::EmptyChildren)
        ));
        assert!(matches!(
            verify_sigma_proof(&threshold_prop(1, 0), &[0; SOUNDNESS_BYTES], message),
            Err(SigmaVerifyError::InvalidThreshold { k: 1, n: 0 })
        ));
    }

    #[test]
    fn cthreshold_invalid_shapes_return_typed_errors() {
        for (k, n) in [(2u16, 1usize), (u16::MAX, 1), (0, 256)] {
            let prop = threshold_prop(k, n);
            let result = verify_sigma_proof(&prop, &[], b"msg");
            assert!(matches!(
                result,
                Err(SigmaVerifyError::InvalidThreshold {
                    k: actual_k,
                    n: actual_n,
                }) if actual_k == k && actual_n == n
            ));
        }
    }

    #[test]
    fn cand_and_cor_reject_nested_invalid_cthreshold_with_empty_proof() {
        let invalid = threshold_prop(2, 1);
        for prop in [
            SigmaBoolean::Cand(vec![SigmaBoolean::Cor(vec![invalid.clone()].into())].into()),
            SigmaBoolean::Cor(vec![SigmaBoolean::Cand(vec![invalid].into())].into()),
        ] {
            assert!(matches!(
                verify_sigma_proof(&prop, &[], b"msg"),
                Err(SigmaVerifyError::InvalidThreshold { k: 2, n: 1 })
            ));
        }
    }

    #[test]
    fn cthreshold_valid_boundaries_are_not_invalid() {
        for n in [1usize, 255] {
            let prop = threshold_prop(n as u16, n);
            let result = verify_sigma_proof(&prop, &[0u8; SOUNDNESS_BYTES + GROUP_SIZE], b"msg");
            assert!(!matches!(
                result,
                Err(SigmaVerifyError::InvalidThreshold { .. })
            ));
        }
    }

    #[test]
    fn threshold_short_coefficients_consume_partials_and_keep_complete_coefficients() {
        let challenge = [0x37; SOUNDNESS_BYTES];
        let coefficients: Vec<u8> = (0..3 * SOUNDNESS_BYTES).map(|i| i as u8 + 1).collect();
        for k in 0..=3 {
            let prop = SigmaBoolean::Cthreshold {
                k,
                children: vec![SigmaBoolean::Cand(vec![].into()); 3].into(),
            };
            let requested = (3 - k as usize) * SOUNDNESS_BYTES;
            for available in 0..=requested {
                let mut proof = challenge.to_vec();
                proof.extend_from_slice(&coefficients[..available]);
                let mut offset = 0;
                let parsed =
                    parse_and_compute_challenges(&prop, &proof, &mut offset, None).unwrap();
                assert_eq!(offset, proof.len(), "k={k}, available={available}");
                let complete = available / SOUNDNESS_BYTES * SOUNDNESS_BYTES;
                let polynomial = gf2_192::gf2_192poly::Gf2_192Poly::try_from(
                    gf2_192::gf2_192poly::CoefficientsByteRepr {
                        coeff0: challenge,
                        more_coeffs: &coefficients[..complete],
                    },
                )
                .unwrap();
                let UncheckedNode::Threshold { children, .. } = &parsed.nodes[0] else {
                    panic!("threshold root expected");
                };
                for (i, child) in children.iter().enumerate() {
                    let expected: [u8; SOUNDNESS_BYTES] = polynomial.evaluate((i + 1) as u8).into();
                    assert_eq!(parsed.nodes[*child].challenge(), expected);
                }
            }
        }
    }

    #[test]
    fn truncated_threshold_proofs_verify_under_and_or_and_threshold_parents() {
        let threshold = SigmaBoolean::Cthreshold {
            k: 1,
            children: vec![SigmaBoolean::Cand(vec![].into()); 3].into(),
        };
        // Independent Fiat-Shamir framing: threshold(1,3), then three AND(0)s.
        let threshold_fs = [0, 2, 1, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        for (prop, prefix) in [
            (threshold.clone(), vec![]),
            (
                SigmaBoolean::Cand(vec![threshold.clone()].into()),
                vec![0, 0, 0, 1],
            ),
            (
                SigmaBoolean::Cor(vec![threshold.clone()].into()),
                vec![0, 1, 0, 1],
            ),
            (
                SigmaBoolean::Cthreshold {
                    k: 1,
                    children: vec![threshold].into(),
                },
                vec![0, 2, 1, 0, 1],
            ),
        ] {
            let message = b"truncated threshold regression";
            let mut hash_input = prefix;
            hash_input.extend_from_slice(&threshold_fs);
            hash_input.extend_from_slice(message);
            let challenge = blake2b256(&hash_input);
            for available in 0..=2 * SOUNDNESS_BYTES {
                let mut proof = challenge[..SOUNDNESS_BYTES].to_vec();
                proof.extend(vec![0xa5; available]);
                assert!(
                    verify_sigma_proof(&prop, &proof, message).unwrap(),
                    "{available}"
                );
            }
        }
    }

    #[test]
    fn read_bytes_rejects_offset_overflow() {
        let mut offset = usize::MAX;
        let result = read_bytes(&[0], &mut offset, 1);
        assert!(matches!(
            result,
            Err(SigmaVerifyError::ProofTooShort { offset: pos })
                if pos == usize::MAX
        ));
        assert_eq!(offset, usize::MAX);
    }

    // A reduced sigma tree must never carry a nested TrivialProp child —
    // `AtLeast.reduce` / `SigmaOr` / `SigmaAnd` fold them out before proof
    // parsing. If one reaches the parser anyway (e.g. a future reduction
    // bug), the verifier must REJECT, not panic: this runs on the consensus
    // transaction-validation path with no `catch_unwind` above it. Regression
    // guard for the AtLeast trivial-fold fix.
    #[test]
    fn cthreshold_with_trivial_child_rejects_not_panics() {
        let prop = SigmaBoolean::Cthreshold {
            k: 2,
            children: vec![
                SigmaBoolean::TrivialProp(true),
                SigmaBoolean::ProveDlog(GroupElement::from_bytes([2u8; 33])),
                SigmaBoolean::ProveDlog(GroupElement::from_bytes([3u8; 33])),
            ]
            .into(),
        };
        // Non-empty proof so we pass the empty-proof early return in
        // verify_sigma_proof and actually reach the parser.
        let proof = vec![0u8; 64];
        let result = verify_sigma_proof(&prop, &proof, b"msg");
        assert!(
            matches!(result, Err(SigmaVerifyError::UnexpectedTrivialChild)),
            "trivial child must be rejected with UnexpectedTrivialChild, not panic; got {result:?}"
        );
    }

    // A TRIVIAL ROOT proposition has no cryptographic leaves to extract —
    // mirror verify_sigma_proof's root short-circuit and return an empty bag,
    // NOT an error. A trivially-reduced input (e.g. a script reducing to
    // `sigmaProp(true)`) reaches extract_proof_leaves through the wallet's
    // bag_for_transaction; erroring there would break hint extraction for the
    // whole transaction.
    #[test]
    fn extract_proof_leaves_trivial_root_returns_empty() {
        for root in [
            SigmaBoolean::TrivialProp(true),
            SigmaBoolean::TrivialProp(false),
        ] {
            let leaves = extract_proof_leaves(&root, &[]);
            assert!(
                matches!(&leaves, Ok(v) if v.is_empty()),
                "trivial root must yield an empty leaf set, got {leaves:?}"
            );
        }
    }

    // The root fast path must NOT mask a NESTED trivial child — that is the
    // reduction-invariant violation the parser rejects (paired with the
    // AtLeast fold). extract_proof_leaves must still surface it as an error.
    #[test]
    fn extract_proof_leaves_nested_trivial_child_rejects() {
        let prop = SigmaBoolean::Cthreshold {
            k: 2,
            children: vec![
                SigmaBoolean::TrivialProp(true),
                SigmaBoolean::ProveDlog(GroupElement::from_bytes([2u8; 33])),
                SigmaBoolean::ProveDlog(GroupElement::from_bytes([3u8; 33])),
            ]
            .into(),
        };
        let proof = vec![0u8; 64];
        let result = extract_proof_leaves(&prop, &proof);
        assert!(
            matches!(result, Err(SigmaVerifyError::UnexpectedTrivialChild)),
            "nested trivial child must still be rejected, got {result:?}"
        );
    }
}
