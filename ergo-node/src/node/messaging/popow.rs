use ergo_p2p::message;
use ergo_p2p::peer::{PeerId, Penalty};
use ergo_sync::coordinator::Action;
use tracing::{info, warn};

use super::super::NodeState;

/// Handle an inbound NiPoPoW proof (message code 91). Decode the
/// wire frame, parse the proof bytes, hand to the
/// `popow_bootstrap` reducer's `on_proof_received`, and penalize on
/// `ValidationError` / `WrongGenesis` (strong signals of malicious
/// or misconfigured peers).
///
/// No-op when `popow_bootstrap` is `None` (either feature disabled
/// or already terminal). Silent drop on decode errors plus a
/// telemetry warn; the wire codec is byte-strict, so a parse
/// failure is either a malicious peer (penalize) or a peer running
/// an incompatible protocol version (degrade).
pub(super) fn handle_inbound_popow_proof(
    state: &mut NodeState,
    peer: PeerId,
    payload: Vec<u8>,
) -> Vec<Action> {
    use ergo_validation::popow::NipopowVerificationResult;

    if state.popow_bootstrap.is_none() {
        // Either NiPoPoW disabled or reducer already terminal —
        // silently drop. A peer responding late after we've already
        // applied a proof is not misbehavior.
        return Vec::new();
    }

    // Step 1: parse the outer wire frame (length-prefixed proof
    // bytes + mandatory pad_length).
    let proof_bytes = match message::deserialize_nipopow_proof(&payload) {
        Ok(b) => b,
        Err(e) => {
            warn!(peer = %peer, error = %e, "bad NipopowProof wire frame");
            return vec![Action::Penalize {
                peer,
                penalty: Penalty::Misbehavior,
            }];
        }
    };

    // Step 2: parse the proof structure.
    let proof = match ergo_ser::popow_proof::deserialize_nipopow_proof(&proof_bytes) {
        Ok(p) => p,
        Err(e) => {
            warn!(peer = %peer, error = %e, "bad NipopowProof body");
            return vec![Action::Penalize {
                peer,
                penalty: Penalty::Misbehavior,
            }];
        }
    };

    // Step 3: hand to reducer + verifier.
    let result = match state.popow_bootstrap.as_mut() {
        Some(popow) => match popow.on_proof_received(peer, proof) {
            Some(r) => r,
            None => {
                // Scala parity (ErgoNodeViewSynchronizer.scala:1066): a
                // duplicate proof from a peer already counted toward quorum
                // is dropped before the verifier with no penalty.
                info!(peer = %peer, "NiPoPoW: duplicate proof from already-counted peer, dropping");
                return Vec::new();
            }
        },
        None => return Vec::new(),
    };

    match result {
        NipopowVerificationResult::BetterChain { total_proofs } => {
            info!(
                peer = %peer,
                total_proofs,
                "NiPoPoW: BetterChain (best-proof replaced)"
            );
            maybe_capture_verified_proof(peer, &proof_bytes);
            Vec::new()
        }
        NipopowVerificationResult::NoBetterChain { total_proofs } => {
            info!(
                peer = %peer,
                total_proofs,
                "NiPoPoW: NoBetterChain (proof valid but not better)"
            );
            maybe_capture_verified_proof(peer, &proof_bytes);
            Vec::new()
        }
        NipopowVerificationResult::WrongGenesis => {
            // Strong signal of malicious peer or wrong-network
            // configuration — penalize.
            warn!(peer = %peer, "NiPoPoW: WrongGenesis");
            vec![Action::Penalize {
                peer,
                penalty: Penalty::Misbehavior,
            }]
        }
        NipopowVerificationResult::ValidationError => {
            warn!(peer = %peer, "NiPoPoW: ValidationError");
            vec![Action::Penalize {
                peer,
                penalty: Penalty::Misbehavior,
            }]
        }
        NipopowVerificationResult::MalformedHeader => {
            // Peer sent a proof containing a header that decodes
            // cleanly via `read_header` but cannot be reserialized
            // via `serialize_header` (e.g., `version ∈ [2, 4]` with
            // non-empty `unparsed_bytes`, or `unparsed_bytes.len() > 255`).
            // Same penalty class as `ValidationError` — both indicate
            // a peer that is either malicious or running broken
            // software. The verifier rejects this input rather than
            // panicking on it.
            warn!(peer = %peer, "NiPoPoW: MalformedHeader (header reserialize bounds)");
            vec![Action::Penalize {
                peer,
                penalty: Penalty::Misbehavior,
            }]
        }
    }
}

/// Scala-oracle capture hook. If env var `ERGO_CAPTURE_NIPOPOW_PROOF` is
/// set, write the raw inbound proof bytes to that path as a one-shot
/// capture. Lets an operator dump a real Scala-served proof for use as a
/// pinned test vector (`test-vectors/mainnet/nipopow_proof_<peer>_<ts>.bin`)
/// without recompiling. Capture once per node lifetime — first proof wins
/// to keep the dump deterministic.
///
/// Called only from the `BetterChain`/`NoBetterChain` result arms — i.e.
/// after the proof has passed wire-frame parse, structure parse, AND the
/// reducer/verifier's genesis + validation checks. A malformed or
/// wrong-genesis proof must never be captured as if it were a clean
/// Scala-oracle fixture.
fn maybe_capture_verified_proof(peer: PeerId, proof_bytes: &[u8]) {
    if let Ok(capture_path) = std::env::var("ERGO_CAPTURE_NIPOPOW_PROOF") {
        if !capture_path.is_empty() && !std::path::Path::new(&capture_path).exists() {
            if let Err(e) = std::fs::write(&capture_path, proof_bytes) {
                warn!(peer = %peer, error = %e, "failed to write NipopowProof capture");
            } else {
                info!(
                    peer = %peer,
                    path = %capture_path,
                    bytes = proof_bytes.len(),
                    "NipopowProof captured for Scala-oracle test fixture",
                );
            }
        }
    }
}
