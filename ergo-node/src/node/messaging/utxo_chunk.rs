use ergo_p2p::peer::PeerId;
use ergo_sync::snapshot_bootstrap::ChunkReceiveOutcome;
use tracing::{debug, warn};

use super::super::NodeState;

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
pub(super) fn handle_inbound_utxo_chunk(state: &mut NodeState, peer: PeerId, chunk_bytes: Vec<u8>) {
    let Some(assembly) = state.chunk_assembly.as_mut() else {
        // No active chunk-download phase — silent drop. This is
        // the common case for non-Mode-2 nodes (chunk_assembly is
        // always None) and for late-arriving chunks after
        // reconstruction completed.
        return;
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
            return;
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
}
