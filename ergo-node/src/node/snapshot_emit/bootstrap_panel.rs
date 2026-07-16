//! Bootstrap-panel projection: maps the live UTXO-snapshot-bootstrap
//! (Mode 2) reducer state + install-side progress flags to the wire-visible
//! `ApiBootstrapStatus`, or `None` when the panel shouldn't be shown.

use ergo_api::types::ApiBootstrapStatus;
use ergo_state::ChainStateRead;
use ergo_sync::snapshot_bootstrap::BootstrapState;

use super::super::NodeState;

/// Tolerance for hiding the bootstrap panel post-install. Matches
/// `AT_TIP_GAP` in `crate::snapshot` — once full-block tip is within
/// this many blocks of the header tip, catch-up is done and the
/// panel auto-hides.
const BOOTSTRAP_PANEL_HIDE_GAP: u32 = 2;

/// Reducer-independent inputs that drive [`select_bootstrap_phase`].
/// Extracted so the phase cascade can be unit-tested without a full
/// `NodeState`.
struct BootstrapPhaseInputs {
    in_catchup: bool,
    has_reconstructed_tree: bool,
    chunk_assembly_complete: bool,
    has_chunk_assembly: bool,
}

/// Map the live bootstrap reducer state + install-side progress flags
/// to the wire-visible phase. Single source of truth for the phase
/// cascade — keeps the producer and its unit tests in sync.
fn select_bootstrap_phase(
    reducer_state: &BootstrapState,
    inputs: &BootstrapPhaseInputs,
) -> ergo_api::types::ApiBootstrapPhase {
    use ergo_api::types::ApiBootstrapPhase;
    if inputs.in_catchup {
        return ApiBootstrapPhase::PostInstallCatchup;
    }
    match reducer_state {
        BootstrapState::Idle | BootstrapState::Querying | BootstrapState::Selected { .. } => {
            ApiBootstrapPhase::Discovery
        }
        BootstrapState::ManifestRequested { .. } => ApiBootstrapPhase::ManifestRequested,
        BootstrapState::ManifestVerified { .. } => {
            if inputs.has_reconstructed_tree {
                ApiBootstrapPhase::Installing
            } else if inputs.chunk_assembly_complete {
                ApiBootstrapPhase::Reconstructing
            } else if inputs.has_chunk_assembly {
                ApiBootstrapPhase::DownloadingChunks
            } else {
                ApiBootstrapPhase::ManifestVerified
            }
        }
    }
}

/// Project the live bootstrap state into the dashboard DTO, or
/// `None` if the operator shouldn't see a bootstrap panel right now.
///
/// Visibility rules:
/// - Not Mode 2 (utxo_bootstrap not configured): always `None`.
/// - Mode 2, pre-install (`best_full_block_height == 0`): `Some` —
///   show discovery / chunks / reconstruct / install progress.
/// - Mode 2, post-install but still catching up (`gap > 2`): `Some`
///   with phase `post_install_catchup` — show "applying blocks from
///   snapshot height" until tip.
/// - Mode 2, at tip: `None` — panel auto-hides.
pub(super) fn build_bootstrap_status(
    state: &mut NodeState,
    now_unix_ms: u64,
) -> Option<ApiBootstrapStatus> {
    if !state.utxo_bootstrap_enabled {
        return None;
    }
    let cs = state.store.chain_state_meta();
    let best_full = cs.best_full_block_height;
    let best_header = cs.best_header_height;

    let reducer_state = state.snapshot_bootstrap.state();
    if !matches!(reducer_state, BootstrapState::Idle) {
        // Any non-Idle reducer state is evidence the bootstrap flow is
        // genuinely active this session. Latch the flag so a later
        // post-install catch-up window still renders the panel even
        // after the reducer transitions back to a quiet state.
        state.bootstrap_was_active_this_session = true;
    }

    let pre_install = best_full == 0;
    let post_install_catchup = !pre_install
        && state.bootstrap_was_active_this_session
        && best_header.saturating_sub(best_full) > BOOTSTRAP_PANEL_HIDE_GAP;
    if !pre_install && !post_install_catchup {
        return None;
    }
    let in_catchup = post_install_catchup;

    if state.bootstrap_started_unix_ms.is_none() {
        state.bootstrap_started_unix_ms = Some(now_unix_ms);
    }

    let voters = state
        .snapshot_bootstrap
        .voters_for_selected_manifest()
        .len() as u32;
    let (chunks_received, chunks_total) = state
        .chunk_assembly
        .as_ref()
        .map(|ca| (ca.received_count() as u32, ca.total_count() as u32))
        .unwrap_or((0, 0));

    let phase_inputs = BootstrapPhaseInputs {
        in_catchup,
        has_reconstructed_tree: state.reconstructed_tree.is_some(),
        chunk_assembly_complete: state
            .chunk_assembly
            .as_ref()
            .is_some_and(|c| c.is_complete()),
        has_chunk_assembly: state.chunk_assembly.is_some(),
    };
    let phase = select_bootstrap_phase(&reducer_state, &phase_inputs);
    let (snapshot_height, manifest_id, trust_check_passed) = if in_catchup {
        // Post-install: report the height we installed at, derived
        // from chain_state. manifest_id no longer carried in the
        // reducer (it's been cleared post-install); use the
        // best_full_block_id at snapshot_height as a stable proxy.
        (best_full, None, true)
    } else {
        match reducer_state {
            BootstrapState::Idle | BootstrapState::Querying => (0, None, false),
            BootstrapState::Selected {
                height,
                manifest_id,
            } => (height as u32, Some(hex::encode(manifest_id)), false),
            BootstrapState::ManifestRequested {
                height,
                manifest_id,
                ..
            } => (height as u32, Some(hex::encode(manifest_id)), false),
            BootstrapState::ManifestVerified {
                height,
                manifest_id,
            } => (height as u32, Some(hex::encode(manifest_id)), true),
        }
    };

    // NiPoPoW + header-availability dashboard fields.
    // popow_phase / popow_providers will report on the popow_bootstrap
    // reducer once wired to it; until then, these stay None.
    // header_availability + popow_dense_from_height reflect what the
    // store reports — surfaceable today since the persistence layer
    // is already on disk.
    let (header_availability, popow_dense_from_height) =
        match state.store.chain_state_meta().header_availability {
            ergo_state::chain::HeaderAvailability::Dense => (None, None),
            ergo_state::chain::HeaderAvailability::PoPowSparse {
                dense_from_height, ..
            } => (
                Some(ergo_api::types::ApiHeaderAvailability::Sparse),
                Some(dense_from_height),
            ),
        };

    Some(ApiBootstrapStatus {
        phase,
        snapshot_height,
        manifest_id,
        voters,
        chunks_received,
        chunks_total,
        trust_check_passed,
        started_unix_ms: state.bootstrap_started_unix_ms.unwrap_or(now_unix_ms),
        popow_phase: None,
        popow_providers: None,
        header_availability,
        popow_dense_from_height,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_bootstrap_status_returns_none_when_utxo_bootstrap_disabled() {
        // Sanity guard for the producer's gate. `make_state` builds a
        // NodeState with `utxo_bootstrap_enabled = false`, so the
        // producer must short-circuit and skip the panel.
        let tmp = tempfile::tempdir().unwrap();
        let mut state = crate::node::tests::make_state(&tmp.path().join("state.redb"));
        let status = build_bootstrap_status(&mut state, 0);
        assert!(
            status.is_none(),
            "non-Mode-2 nodes must not surface the bootstrap panel"
        );
    }

    #[test]
    fn build_bootstrap_status_emits_discovery_for_idle_reducer_in_mode_2() {
        // End-to-end producer test: Mode 2 enabled, no chain progress yet,
        // reducer state Idle → wire phase = discovery, with the canonical
        // wire literal "discovery" pinned via JSON serialization.
        let tmp = tempfile::tempdir().unwrap();
        let mut state = crate::node::tests::make_state(&tmp.path().join("state.redb"));
        state.utxo_bootstrap_enabled = true;
        let status = build_bootstrap_status(&mut state, 1_000)
            .expect("Mode 2 + pre-install must yield a status");
        assert_eq!(status.phase, ergo_api::types::ApiBootstrapPhase::Discovery);
        let v = serde_json::to_value(&status).unwrap();
        assert_eq!(
            v["phase"],
            serde_json::Value::String("discovery".into()),
            "the producer must wire phase under the `phase` key with the canonical literal"
        );
        assert!(
            v.as_object().unwrap().contains_key("header_availability")
                || !v.as_object().unwrap().contains_key("history_mode"),
            "must use the renamed key (or omit it entirely), never the old name"
        );
    }

    fn phase_inputs(
        in_catchup: bool,
        has_reconstructed_tree: bool,
        chunk_assembly_complete: bool,
        has_chunk_assembly: bool,
    ) -> BootstrapPhaseInputs {
        BootstrapPhaseInputs {
            in_catchup,
            has_reconstructed_tree,
            chunk_assembly_complete,
            has_chunk_assembly,
        }
    }

    #[test]
    fn select_bootstrap_phase_in_catchup_wins_over_reducer_state() {
        // Even with ManifestVerified + all install flags set, in_catchup
        // forces PostInstallCatchup — the post-install branch always
        // outranks the reducer state for wire-phase selection.
        let phase = select_bootstrap_phase(
            &BootstrapState::ManifestVerified {
                height: 100,
                manifest_id: [0u8; 32],
            },
            &phase_inputs(true, true, true, true),
        );
        assert_eq!(
            phase,
            ergo_api::types::ApiBootstrapPhase::PostInstallCatchup
        );
    }

    #[test]
    fn select_bootstrap_phase_idle_querying_selected_all_map_to_discovery() {
        for state in [
            BootstrapState::Idle,
            BootstrapState::Querying,
            BootstrapState::Selected {
                height: 5,
                manifest_id: [1u8; 32],
            },
        ] {
            let phase = select_bootstrap_phase(&state, &phase_inputs(false, false, false, false));
            assert_eq!(
                phase,
                ergo_api::types::ApiBootstrapPhase::Discovery,
                "{state:?} must wire as discovery"
            );
        }
    }

    #[test]
    fn select_bootstrap_phase_manifest_requested_maps_to_manifest_requested() {
        let phase = select_bootstrap_phase(
            &BootstrapState::ManifestRequested {
                peer: "127.0.0.1:9006".parse().unwrap(),
                height: 42,
                manifest_id: [2u8; 32],
            },
            &phase_inputs(false, false, false, false),
        );
        assert_eq!(phase, ergo_api::types::ApiBootstrapPhase::ManifestRequested);
    }

    #[test]
    fn select_bootstrap_phase_manifest_verified_cascade_pins_each_branch() {
        let verified = BootstrapState::ManifestVerified {
            height: 7,
            manifest_id: [3u8; 32],
        };
        // No assembly yet: bare ManifestVerified.
        assert_eq!(
            select_bootstrap_phase(&verified, &phase_inputs(false, false, false, false)),
            ergo_api::types::ApiBootstrapPhase::ManifestVerified
        );
        // Chunk assembly created, still receiving: DownloadingChunks.
        assert_eq!(
            select_bootstrap_phase(&verified, &phase_inputs(false, false, false, true)),
            ergo_api::types::ApiBootstrapPhase::DownloadingChunks
        );
        // Assembly complete, tree not yet reconstructed: Reconstructing.
        // (complete implies has_chunk_assembly is also true at runtime.)
        assert_eq!(
            select_bootstrap_phase(&verified, &phase_inputs(false, false, true, true)),
            ergo_api::types::ApiBootstrapPhase::Reconstructing
        );
        // Reconstructed tree latched in state: Installing — outranks the
        // chunk-assembly flags below it.
        assert_eq!(
            select_bootstrap_phase(&verified, &phase_inputs(false, true, true, true)),
            ergo_api::types::ApiBootstrapPhase::Installing
        );
        // Reconstructed tree latched with no surviving assembly flags:
        // still Installing (the post-reconstruct hand-off path).
        assert_eq!(
            select_bootstrap_phase(&verified, &phase_inputs(false, true, false, false)),
            ergo_api::types::ApiBootstrapPhase::Installing
        );
    }
}
