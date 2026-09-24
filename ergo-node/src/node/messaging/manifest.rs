use ergo_p2p::peer::PeerId;
use ergo_primitives::reader::VlqReader;
use ergo_ser::header::read_header;
use ergo_state::avl::snapshot_codec::{manifest_tree_height, recompute_manifest_root_label};
use ergo_state::HeaderSectionStore;
use ergo_sync::snapshot_bootstrap::verify_manifest_against_state_root;
use tracing::{info, warn};

use super::super::NodeState;
use ergo_p2p::peer::Penalty;
use ergo_sync::coordinator::Action;

/// Mode 2 consume-side: process an inbound `Manifest` (code 79).
///
/// Checks request ownership, authenticates the manifest subtree against the
/// requested ID, then binds its root and height to the canonical header.
/// Bad supplied bytes evict and penalize the sender. Local store/parse errors
/// stop bootstrap without blaming peers; reachable header gaps defer verification.
pub(super) fn handle_inbound_manifest(
    state: &mut NodeState,
    peer: PeerId,
    manifest_bytes: Vec<u8>,
) -> Vec<Action> {
    let Some((height, manifest_id, bytes)) = state
        .snapshot_bootstrap
        .on_manifest_received(peer, manifest_bytes)
    else {
        // Stale, unsolicited, or wrong peer — silent drop.
        return Vec::new();
    };

    // Scala derives manifest.id from parsed bytes before consulting requests:
    // ErgoNodeViewSynchronizer.scala:954-988; BatchAVLProverManifest.scala:18-25.
    match recompute_manifest_root_label(&bytes) {
        Ok(actual) if actual.as_bytes() == &manifest_id => {}
        result => {
            warn!(peer = %peer, height, result = ?result, "invalid or non-asked manifest body");
            state
                .snapshot_bootstrap
                .reject_manifest_and_evict_voter(peer);
            return vec![Action::Penalize {
                peer,
                penalty: Penalty::Misbehavior,
            }];
        }
    }

    let manifest_height = match manifest_tree_height(&bytes) {
        Ok(height) => height,
        Err(e) => {
            warn!(
                peer = %peer,
                height = height,
                error = %e,
                "manifest header parse failed; evicting voter",
            );
            state
                .snapshot_bootstrap
                .reject_manifest_and_evict_voter(peer);
            return Vec::new();
        }
    };

    // Canonical header lookup. In Dense mode any `None` is "not on
    // our best chain" → evict the voter. In PoPowSparse mode a
    // `SparseGap` at `snapshot_height` means "we haven't completed
    // bounded forward catchup yet" → silent drop (the voter is
    // still valid; re-poll on the next tick). Distinguishing the
    // two requires the 3-arm `HeightLookup`.
    use crate::node::sync_tick::{resolve_install_anchor, InstallAnchor};
    let header_id = match resolve_install_anchor(
        state.store.as_utxo().expect(
            "utxo-only: Mode 2 snapshot-bootstrap manifest verify is gated off in digest mode",
        ),
        height as u32,
    ) {
        Ok(InstallAnchor::Ready(id)) => id,
        Ok(InstallAnchor::Defer) => {
            // Catchup hasn't filled the snapshot-height row yet.
            // Per-tick re-poll until the row materializes; do NOT
            // evict — the voter is consistent with the chain, we're
            // just not ready locally.
            tracing::debug!(
                peer = %peer,
                height = height,
                "SparseGap at snapshot height; deferring manifest verify until catchup completes",
            );
            return Vec::new();
        }
        Ok(InstallAnchor::UnreachableGap { dense_from_height }) => {
            // The advertised snapshot sits in the NiPoPoW sparse
            // prefix. Forward catch-up never indexes below
            // `dense_from_height`, so re-polling this voter would
            // spin forever — we can NEVER verify this manifest
            // against a canonical state_root. Evict and recompute
            // selection so a voter advertising a reachable epoch
            // can win instead.
            warn!(
                peer = %peer,
                height = height,
                dense_from_height,
                "snapshot height is below the NiPoPoW proof's dense_from_height and can \
                 never be indexed; evicting manifest voter",
            );
            state
                .snapshot_bootstrap
                .reject_manifest_and_evict_voter(peer);
            return Vec::new();
        }
        Ok(InstallAnchor::AboveTip) => {
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
            return Vec::new();
        }
        Err(e) => {
            crate::node::sync_tick::halt_snapshot_bootstrap(state, &e);
            return Vec::new();
        }
    };

    let header_bytes = match state.store.get_header(&header_id) {
        Ok(Some(b)) => b,
        Ok(None) => {
            crate::node::sync_tick::halt_snapshot_bootstrap(
                state,
                &"canonical snapshot header bytes missing",
            );
            return Vec::new();
        }
        Err(e) => {
            crate::node::sync_tick::halt_snapshot_bootstrap(state, &e);
            return Vec::new();
        }
    };
    let header = match read_header(&mut VlqReader::new(&header_bytes)) {
        Ok(header) => header,
        Err(e) => {
            crate::node::sync_tick::halt_snapshot_bootstrap(state, &e);
            return Vec::new();
        }
    };

    match verify_manifest_against_state_root(&manifest_id, manifest_height, &header.state_root) {
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
            return vec![Action::Penalize {
                peer,
                penalty: Penalty::Misbehavior,
            }];
        }
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::digest::ADDigest;
    use ergo_sync::snapshot_bootstrap::BootstrapState;
    use std::time::Instant;

    // ----- helpers -----

    fn fixture_state(path: &std::path::Path) -> (NodeState, PeerId, [u8; 32], Vec<u8>) {
        let mut state = crate::node::tests::make_state(path);
        let bytes =
            include_bytes!("../../../../test-vectors/testnet/utxo_snapshot_manifest_522239.bin")
                .to_vec();
        let id: [u8; 32] =
            hex::decode("7858b36c8c7596da9999a013d91608a341583a0a1f5d4859c5d80e5d296e0fac")
                .unwrap()
                .try_into()
                .unwrap();
        let root = ADDigest::from_bytes(
            hex::decode("7858b36c8c7596da9999a013d91608a341583a0a1f5d4859c5d80e5d296e0fac17")
                .unwrap()
                .try_into()
                .unwrap(),
        );
        let (header_id, header_bytes) =
            crate::node::tests::synthetic_header_with_state_root(522_239, root);
        let store = state.store.as_utxo_mut().unwrap();
        store.store_header(&header_id, &header_bytes).unwrap();
        store
            .test_force_set_best_header_unsafe(header_id, 522_239, vec![5])
            .unwrap();
        store
            .test_force_put_header_chain_index(522_239, &header_id)
            .unwrap();
        for port in 1..=3 {
            state
                .snapshot_bootstrap
                .on_snapshots_info(([10, 0, 0, 1], port).into(), &[(522_239, id)]);
        }
        let peer = ([10, 0, 0, 1], 1).into();
        state
            .snapshot_bootstrap
            .mark_manifest_requested(peer, 522_239, id, Instant::now());
        (state, peer, id, bytes)
    }

    // ----- error paths -----

    #[test]
    fn inbound_manifest_forged_boundary_label_penalizes_server_without_latching() {
        let dir = tempfile::tempdir().unwrap();
        let (mut state, peer, _, mut bytes) = fixture_state(&dir.path().join("state.redb"));
        // The fixture's left spine reaches the manifest cut. Change only one
        // boundary child label; header, request, height and wire shape stay valid.
        let mut cursor = 2;
        for level in 1..=bytes[1] {
            let (node, consumed) =
                ergo_state::avl::snapshot_codec::parse_prover_node(&bytes[cursor..]).unwrap();
            assert!(matches!(
                node,
                ergo_state::avl::snapshot_codec::ParsedProverNode::Internal { .. }
            ));
            if level == bytes[1] {
                bytes[cursor + 34] ^= 1;
            }
            cursor += consumed;
        }
        let payload = ergo_p2p::message::serialize_manifest(&bytes).unwrap();
        let actions = crate::node::handle_message(
            &mut state,
            peer,
            ergo_p2p::message::CODE_MANIFEST,
            &payload,
            Instant::now(),
        );
        assert!(
            matches!(actions.as_slice(), [Action::Penalize { peer: offender, .. }] if *offender == peer)
        );
        assert!(!matches!(
            state.snapshot_bootstrap.state(),
            BootstrapState::ManifestVerified { .. }
        ));
        assert!(state
            .snapshot_bootstrap
            .take_verified_manifest_bytes()
            .is_none());
    }

    // ----- oracle parity -----

    #[test]
    fn inbound_manifest_scala_testnet_fixture_latches_verified_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let (mut state, peer, id, bytes) = fixture_state(&dir.path().join("state.redb"));
        assert!(handle_inbound_manifest(&mut state, peer, bytes).is_empty());
        assert_eq!(
            state.snapshot_bootstrap.state(),
            BootstrapState::ManifestVerified {
                height: 522_239,
                manifest_id: id
            }
        );
        assert_eq!(
            state.snapshot_bootstrap.verified_manifest_peer(),
            Some(peer)
        );
    }
}
