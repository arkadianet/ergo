use ergo_p2p::peer::PeerId;
use ergo_primitives::reader::VlqReader;
use ergo_ser::header::read_header;
use ergo_state::HeaderSectionStore;
use ergo_sync::snapshot_bootstrap::verify_manifest_against_state_root;
use tracing::{info, warn};

use super::super::NodeState;

/// Mode 2 consume-side: process an inbound `Manifest` (code 79).
///
/// Three-step funnel:
/// 1. Reducer ownership check — `on_manifest_received` returns
///    `Some((height, manifest_id, bytes))` iff the reply matches
///    our outstanding `GetManifest` request from this peer. A
///    `None` here means stale/unsolicited/wrong-peer; silently
///    drop.
/// 2. Canonical-header lookup — fetch the header at `height` from
///    the best-header chain, deserialize, extract `state_root`.
///    Any failure (chain doesn't have that height, header bytes
///    missing, deserialization error) is treated as "we can't
///    verify this manifest" → evict the voter, recompute selection.
/// 3. Trust check — compare the manifest_id against
///    `state_root[..32]` via `verify_manifest_against_state_root`.
///    On match, latch the bytes via `accept_verified_manifest`.
///    On mismatch, evict the voter — they advertised a manifest
///    inconsistent with our canonical chain.
pub(super) fn handle_inbound_manifest(
    state: &mut NodeState,
    peer: PeerId,
    manifest_bytes: Vec<u8>,
) {
    let Some((height, manifest_id, bytes)) = state
        .snapshot_bootstrap
        .on_manifest_received(peer, manifest_bytes)
    else {
        // Stale, unsolicited, or wrong peer — silent drop.
        return;
    };

    // Canonical header lookup. In Dense mode any `None` is "not on
    // our best chain" → evict the voter. In PoPowSparse mode a
    // `SparseGap` at `snapshot_height` means "we haven't completed
    // bounded forward catchup yet" → silent drop (the voter is
    // still valid; re-poll on the next tick). Distinguishing the
    // two requires the 3-arm `HeightLookup`.
    use ergo_state::chain::HeightLookup;
    let header_id = match state
        .store
        .as_utxo()
        .expect("utxo-only: Mode 2 snapshot-bootstrap manifest verify is gated off in digest mode")
        .lookup_header_at_height(height as u32)
    {
        Ok(HeightLookup::Dense(id)) => id,
        Ok(HeightLookup::SparseGap) => {
            // Catchup hasn't filled the snapshot-height row yet.
            // Per-tick re-poll until the row materializes; do NOT
            // evict — the voter is consistent with the chain, we're
            // just not ready locally.
            tracing::debug!(
                peer = %peer,
                height = height,
                "SparseGap at snapshot height; deferring manifest verify until catchup completes",
            );
            return;
        }
        Ok(HeightLookup::AboveTip) => {
            // Snapshot height exceeds best_header_height — same as
            // Dense's `None` for an above-tip height; the voter has
            // advertised a height we don't have any canonical claim
            // to. Evict, recompute selection.
            warn!(
                peer = %peer,
                height = height,
                "snapshot height above best_header_height; evicting manifest voter",
            );
            state
                .snapshot_bootstrap
                .reject_manifest_and_evict_voter(peer);
            return;
        }
        Err(e) => {
            warn!(
                peer = %peer,
                height = height,
                error = %e,
                "chain index lookup failed during manifest verification; evicting voter",
            );
            state
                .snapshot_bootstrap
                .reject_manifest_and_evict_voter(peer);
            return;
        }
    };

    let header_bytes = match state.store.get_header(&header_id) {
        Ok(Some(b)) => b,
        Ok(None) => {
            warn!(
                peer = %peer,
                header_id = %hex::encode(header_id),
                "header bytes missing for snapshot-height header; evicting voter",
            );
            state
                .snapshot_bootstrap
                .reject_manifest_and_evict_voter(peer);
            return;
        }
        Err(e) => {
            warn!(
                peer = %peer,
                error = %e,
                "header bytes lookup failed; evicting voter",
            );
            state
                .snapshot_bootstrap
                .reject_manifest_and_evict_voter(peer);
            return;
        }
    };

    let header = match read_header(&mut VlqReader::new(&header_bytes)) {
        Ok(h) => h,
        Err(e) => {
            warn!(
                peer = %peer,
                header_id = %hex::encode(header_id),
                error = %e,
                "failed to deserialize canonical header; evicting voter",
            );
            state
                .snapshot_bootstrap
                .reject_manifest_and_evict_voter(peer);
            return;
        }
    };

    // The trust boundary. `state_root.as_bytes()[..32]` must equal
    // `manifest_id` for the peer's snapshot to be canonical.
    match verify_manifest_against_state_root(&manifest_id, &header.state_root) {
        Ok(()) => {
            // Proof-anchor check: if NiPoPoW bootstrap was active,
            // compare the discovered snapshot_height to the proof's
            // anticipated anchor. Scala's serve side picks an anchor
            // at snapshot_height - LastHeadersInContext = -10; a
            // mismatch means the proof was for a different snapshot
            // epoch than the one Mode 2 selected, and bounded
            // forward catchup will need a window larger than
            // LastHeadersInContext. Logged as WARN so an operator
            // tail -f sees it.
            if let Some(popow) = state.popow_bootstrap.as_ref() {
                if let Some(proof) = popow.best_proof() {
                    let proof_suffix_h = proof.suffix_head.header.height;
                    let expected_snapshot_h = proof_suffix_h.saturating_add(10);
                    if expected_snapshot_h != height as u32 {
                        let delta = (height as i64) - (expected_snapshot_h as i64);
                        warn!(
                            proof_suffix_height = proof_suffix_h,
                            expected_snapshot_height = expected_snapshot_h,
                            actual_snapshot_height = height,
                            delta,
                            "NiPoPoW proof anchor does not match discovered snapshot height; \
                             bounded forward catchup window will exceed LastHeadersInContext",
                        );
                    }
                }
            }
            info!(
                peer = %peer,
                height = height,
                manifest_id = %hex::encode(manifest_id),
                "manifest verified against canonical state_root",
            );
            state.snapshot_bootstrap.accept_verified_manifest(bytes);
        }
        Err(e) => {
            warn!(
                peer = %peer,
                height = height,
                error = ?e,
                "manifest failed trust check; evicting voter",
            );
            state
                .snapshot_bootstrap
                .reject_manifest_and_evict_voter(peer);
        }
    }
}
