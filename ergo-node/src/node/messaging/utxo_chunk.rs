use ergo_p2p::peer::PeerId;
use ergo_sync::snapshot_bootstrap::ChunkReceiveOutcome;
use tracing::{debug, warn};

use super::super::NodeState;
use ergo_sync::coordinator::Action;

/// Mode 2 consume-side: process an inbound `UtxoSnapshotChunk`
/// (code 81).
///
/// Chunk authentication is by hash, not by peer ownership: any
/// peer can serve any chunk; we accept whatever recomputes to a
/// subtree_id we expect. The bytes' first prover-node yields the
/// chunk's root structure; `recompute_chunk_root_label` produces
/// the same `Digest32` the producer's `compute_node_label` would
/// have. If that label isn't in the assembly's expected set, drop.
///
/// Strict request ownership is enforced by the assembly's inflight
/// map: `on_chunk_received` returns `WrongPeer` if a different
/// peer than the one we asked tries to fulfill the slot. That
/// case is logged (debug) and silently dropped — no penalty, since
/// races between requests and responses are normal.
/// Malformed replies from request owners re-queue only their slots and exclude
/// that supplier for this epoch; the verified manifest and received chunks survive.
pub(super) fn handle_inbound_utxo_chunk(
    state: &mut NodeState,
    peer: PeerId,
    chunk_bytes: Vec<u8>,
) -> Vec<Action> {
    let Some(assembly) = state.chunk_assembly.as_mut() else {
        // No active chunk-download phase — silent drop. This is
        // the common case for non-Mode-2 nodes (chunk_assembly is
        // always None) and for late-arriving chunks after
        // reconstruction completed.
        return Vec::new();
    };

    // Authenticate via recomputed root label.
    let subtree_id = match ergo_state::avl::snapshot_codec::recompute_chunk_root_label(&chunk_bytes)
    {
        Ok(id) => id,
        Err(e) => {
            warn!(
                peer = %peer,
                error = %e,
                "Mode 2: chunk parse failed during root-label recompute",
            );
            if assembly.has_requests_from(&peer) {
                assembly.drop_peer(&peer);
                state.snapshot_bootstrap.evict_snapshot_supplier(peer);
                return vec![Action::Penalize {
                    peer,
                    penalty: ergo_p2p::peer::Penalty::Misbehavior,
                }];
            }
            return Vec::new();
        }
    };

    match assembly.on_chunk_received(peer, subtree_id, chunk_bytes) {
        ChunkReceiveOutcome::Accepted => {
            debug!(
                peer = %peer,
                subtree_id = %hex::encode(subtree_id.as_bytes()),
                progress = format!("{}/{}", assembly.received_count(), assembly.total_count()),
                "Mode 2: chunk accepted",
            );
        }
        ChunkReceiveOutcome::WrongPeer
        | ChunkReceiveOutcome::Duplicate
        | ChunkReceiveOutcome::UnknownSubtreeId => {
            // All silent-drop cases. No peer penalty — these are
            // benign races (peer races, retransmits, late arrivals
            // after reconstruction).
            debug!(
                peer = %peer,
                subtree_id = %hex::encode(subtree_id.as_bytes()),
                "Mode 2: chunk drop",
            );
        }
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::digest::Digest32;
    use ergo_sync::snapshot_bootstrap::{BootstrapState, ChunkAssembly};
    use std::time::Instant;

    // ----- error paths -----

    #[test]
    fn inbound_chunk_malformed_bytes_penalizes_chunk_server_only() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = crate::node::tests::make_state(&dir.path().join("state.redb"));
        let manifest_server = ([10, 0, 0, 1], 1).into();
        let chunk_server = ([10, 0, 0, 1], 2).into();
        let id = [0xAA; 32];
        for port in 1..=4 {
            state
                .snapshot_bootstrap
                .on_snapshots_info(([10, 0, 0, 1], port).into(), &[(100, id)]);
        }
        state
            .snapshot_bootstrap
            .mark_manifest_requested(manifest_server, 100, id, Instant::now());
        state.snapshot_bootstrap.accept_verified_manifest(vec![]);
        let chunk_id = Digest32::from_bytes([0xBB; 32]);
        let received_id = Digest32::from_bytes([0xCC; 32]);
        let other_id = Digest32::from_bytes([0xDD; 32]);
        let mut assembly = ChunkAssembly::new(vec![chunk_id, received_id, other_id]);
        assembly.mark_requested(received_id, manifest_server, Instant::now());
        assembly.on_chunk_received(manifest_server, received_id, vec![1]);
        assembly.mark_requested(other_id, manifest_server, Instant::now());
        assembly.mark_requested(chunk_id, chunk_server, Instant::now());
        state.chunk_assembly = Some(assembly);
        let actions = handle_inbound_utxo_chunk(&mut state, chunk_server, vec![]);
        assert!(
            matches!(actions.as_slice(), [Action::Penalize { peer, penalty: ergo_p2p::peer::Penalty::Misbehavior }] if *peer == chunk_server)
        );
        assert_eq!(
            state.snapshot_bootstrap.state(),
            BootstrapState::ManifestVerified {
                height: 100,
                manifest_id: id,
            }
        );
        let assembly = state.chunk_assembly.as_ref().unwrap();
        assert_eq!(assembly.received_count(), 1);
        assert_eq!(assembly.next_to_request(), vec![chunk_id]);
        assert!(assembly.has_requests_from(&manifest_server));
        assert!(!assembly.has_requests_from(&chunk_server));
        assert!(state.snapshot_bootstrap.supplier_excluded(&chunk_server));
        // Rediscovery must still be able to select this epoch, excluding its bad supplier.
        state.snapshot_bootstrap.drop_verified_manifest();
        for port in 1..=4 {
            state
                .snapshot_bootstrap
                .on_snapshots_info(([10, 0, 0, 1], port).into(), &[(100, id)]);
        }
        let (peer, height, manifest_id) =
            state.snapshot_bootstrap.should_request_manifest().unwrap();
        assert_ne!(peer, chunk_server);
        assert_eq!((height, manifest_id), (100, id));
        assert!(!state
            .snapshot_bootstrap
            .voters_for_selected_manifest()
            .contains(&chunk_server));
    }
}
