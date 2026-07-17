//! Boot phase: sync coordinator/executor construction, IBD + background
//! persist pipeline, indexer boot, shadow-validation wiring, store
//! hydration/recovery, and the NiPoPoW bootstrap-resume classification.

use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use ergo_indexer::{IndexerHandle, IndexerQuery, IndexerTask};
use ergo_mempool::weight;
use ergo_state::{ChainStateRead, HeaderSectionStore};
use ergo_sync::coordinator::SyncCoordinator;
use ergo_sync::executor::SyncExecutor;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::config::NodeConfig;
use crate::indexer_chain::ChainReaderAdapter;

use super::super::NodeError;

/// Everything [`setup`] produces, threaded into [`super::run_inner_with_backend`]'s
/// `NodeState` construction and (for `chain_meta`/`bootstrap_kind`) the
/// handshake + identity building that follows.
pub(super) struct SyncSetup {
    pub coordinator: SyncCoordinator,
    pub executor: SyncExecutor,
    pub indexer_handle: Option<IndexerHandle>,
    pub indexer_task_handle: Option<JoinHandle<()>>,
    pub indexer_cancel: Arc<AtomicBool>,
    pub shadow_state: Option<Arc<super::super::shadow_watch::ShadowState>>,
    pub shadow_task_handle: Option<JoinHandle<()>>,
    pub chain_meta: ergo_state::chain::ChainStateMeta,
    pub backend_is_utxo: bool,
    pub bootstrap_kind: crate::node::identity::BootstrapKind,
    pub popow_bootstrap: Option<ergo_sync::popow_bootstrap::PopowBootstrap>,
    pub last_seen_active_params: ergo_validation::ActiveProtocolParameters,
    pub last_seen_validation_settings: ergo_validation::ErgoValidationSettings,
}

/// `weight::from_config` also lives here so `run_inner_with_backend` can
/// build the mempool right after this phase without re-deriving the sort
/// policy validation performed at config load.
///
/// `NodeConfig::load` rejects an invalid `mempool_sort_policy` before this
/// ever runs, so the typical production path always hits `Ok`. Returning a
/// typed error rather than panicking matches the same `api_key_hash`
/// invariant-guard pattern in `api_wiring::bind` — a caller that builds a
/// `NodeConfig` literal bypassing `load()` (tests, embedders) gets a clean
/// boot failure instead of a panic.
pub(super) fn mempool_weight_fn(
    config: &NodeConfig,
) -> Result<Box<dyn ergo_mempool::weight::WeightFunction>, NodeError> {
    weight::from_config(&config.mempool_sort_policy).map_err(|e| -> NodeError {
        format!(
            "config invariant broken: mempool_sort_policy {:?} failed \
             weight::from_config; NodeConfig::load would have rejected this, \
             so the caller built a NodeConfig literal that bypassed validation: {e}",
            config.mempool_sort_policy
        )
        .into()
    })
}

pub(super) fn setup(
    config: &NodeConfig,
    store: &mut ergo_state::StateBackendKind,
    boot_sentinel: u32,
) -> Result<SyncSetup, NodeError> {
    // Mode 6 (headers-only) — when `verify_transactions = false`, the
    // sync coordinator never requests block sections and never tracks
    // pending blocks. Default false keeps Modes 1/2/3/5 on the
    // full-validation path.
    let headers_only = !config.verify_transactions;
    let mut coordinator = SyncCoordinator::new_with_timing(
        store.chain_state_meta().best_full_block_height,
        config.download_window,
        headers_only,
        config
            .chain_spec
            .block_timing
            .header_freshness_threshold_ms(),
    );
    // Operator escape hatch (sibling of ERGO_BAN_HEADERS): force the
    // headers-chain-synced latch at boot so block downloads start even
    // when every header on the target chain is stale. Needed when a
    // halted network is re-driven from a checkpoint: nobody has mined
    // for days, so the freshness edge in `check_headers_synced` can
    // never fire, and the caught-up-to-peers fallback needs peers that
    // agree with our tip — unavailable while peers sit on an abandoned
    // branch (testnet 431,366 recovery). Session-scoped and opt-in;
    // blocks are still fully validated — this only affects WHEN
    // download begins, never WHAT is accepted.
    if std::env::var_os("ERGO_ASSUME_HEADERS_SYNCED").is_some() {
        coordinator.sync_state_mut().mark_headers_chain_synced();
        warn!("ERGO_ASSUME_HEADERS_SYNCED: headers-chain-synced latch forced for this session");
    }
    // Mode 2 / Mode 4 boot gate: when configured for UTXO
    // bootstrap AND the install has never run on this store,
    // suppress the section-download pipeline (same gates as
    // headers_only) until the snapshot install advances
    // `best_full_block_height`.
    //
    // The "install has never run" predicate combines two signals:
    // 1. `best_full_block_height == 0` — no full block has ever
    //    been applied. Necessary because a successful install
    //    bumps best_full to `snapshot_height`, so a restart at
    //    height > 0 must not re-engage the install machinery.
    // 2. `!was_utxo_bootstrapped()` — the persistent provenance
    //    marker. Catches the pathological case where the
    //    marker is armed but best_full_block_height somehow
    //    rolled back to 0 (e.g., wallet replay path bug, manual
    //    state surgery). Without this, re-installing on a store
    //    that already has a snapshot would corrupt state.
    //
    // The install path flips `bootstrap_in_progress` back to
    // false once it succeeds. The contract: an operator
    // can leave `utxo_bootstrap = true` in config across N
    // restarts and the node boots cleanly every time, only
    // doing the install on the first boot.
    // The UTXO snapshot-install provenance marker only exists on the
    // UTXO backend. The digest backend never bootstraps from a UTXO
    // snapshot (config-gated: `utxo_bootstrap` is false for Mode 5), so
    // it reports "never installed" and the install gate stays off.
    let install_already_committed = match store.as_utxo() {
        Some(s) => s.was_utxo_bootstrapped().map_err(|e| {
            Box::new(std::io::Error::other(format!(
                "boot: cannot read utxo_bootstrap_installed marker (state corruption): {e}"
            ))) as NodeError
        })?,
        None => false,
    };
    let best_full_for_install_gate = store.chain_state_meta().best_full_block_height;
    // Persistence-invariant cross-check: the
    // `UTXO_BOOTSTRAP_INSTALLED_V1` marker is written ONLY by
    // `install_snapshot_state`, which atomically bumps
    // `best_full_block_height` to `snapshot_height` in the same
    // write_txn. The combination
    // `(marker = true, best_full_block_height = 0)` is therefore
    // impossible under normal operation. Treat it as
    // state corruption and refuse to boot rather than silently
    // skip the install path and continue against stale snapshot
    // AVL / state metadata.
    if install_already_committed && best_full_for_install_gate == 0 {
        return Err(Box::new(std::io::Error::other(
            "boot: state corruption — UTXO_BOOTSTRAP_INSTALLED_V1 marker is armed \
             but best_full_block_height = 0. The marker is written atomically with \
             the snapshot install which advances best_full to snapshot_height; \
             these two signals must agree. Inspect the data dir before retrying."
                .to_string(),
        )) as NodeError);
    }
    let bootstrap_in_progress = crate::node::identity::should_engage_utxo_install(
        config.utxo_bootstrap,
        best_full_for_install_gate,
        install_already_committed,
    );
    if config.utxo_bootstrap && install_already_committed {
        info!(
            best_full_block_height = best_full_for_install_gate,
            "Mode 2/4: snapshot already installed; skipping install path, resuming sync",
        );
    }
    coordinator.set_bootstrap_in_progress(bootstrap_in_progress);
    // Mirror the boot-time prune sentinel into sync_state so the
    // coordinator's request-side gate skips header-validated
    // sections below it. Only mirror when sentinel > 1 — the
    // default `1` means "no sentinel-active operation has
    // occurred"; leaving sync_state's mirror at its default
    // (`0`) keeps the on_inv prune-aware lookup path off the
    // archive hot path. The coordinator's gate covers Mode 2 /
    // NiPoPoW bootstrap cases via the sync_tick post-apply
    // mirror, which also skips trivial values.
    if boot_sentinel > 1 {
        coordinator
            .sync_state_mut()
            .set_prune_sentinel(boot_sentinel);
    }
    info!(
        download_window = config.download_window,
        headers_only, bootstrap_in_progress, "sync window configured"
    );
    let mut executor = SyncExecutor::new(
        ergo_validation::context::ProtocolParams::mainnet_default(),
        config.chain_spec.difficulty.clone(),
    );
    executor.set_script_validation_checkpoint(config.script_validation_checkpoint);
    if let Some((h, id)) = config.script_validation_checkpoint {
        info!(
            max_height = h,
            checkpoint_id = %hex::encode(id),
            "script-validation checkpoint: skipping ErgoScript eval below max_height",
        );
    } else {
        info!("script-validation checkpoint: disabled (full validation)");
    }
    let reemission_rules = super::build_reemission_rules(&config.chain_spec);
    match &reemission_rules {
        Some(r) => info!(
            activation_height = r.activation_height,
            "EIP-27 re-emission rules: enforced on block validation",
        ),
        None => info!("EIP-27 re-emission rules: disabled (no re-emission on this network)"),
    }
    executor.set_reemission_rules(reemission_rules);

    // 6. IBD durability mode (opt-in via --ibd-flush-interval). The
    // IBD batch-flush window and the background persist pipeline are
    // both AVL+-arena write-path concerns on the UTXO backend; the
    // digest backend commits each block's root inside one redb txn in
    // `apply_block_digest` (no batched AVL replay), so neither applies.
    if let Some(s) = store.as_utxo_mut() {
        if config.ibd_flush_interval > 0 {
            s.set_ibd_mode(true, config.ibd_flush_interval);
            info!(
                flush_interval = config.ibd_flush_interval,
                max_replay_blocks = config.ibd_flush_interval,
                "IBD durability enabled",
            );
        }

        // 6b. Background persist pipeline — decouples redb writes from the
        // block processing hot path. Queue depth 64 lets the persist thread
        // coalesce up to MAX_BATCH_BLOCKS (50) jobs into a single redb txn
        // when the main thread feeds faster than commit; tip-sync naturally
        // degrades to 1 job per batch when the queue stays empty between
        // blocks. In-flight memory is bounded by queue_depth × per-job
        // serialized AVL/undo size (~100-500KB), so 64 ≈ 32MB upper bound.
        s.enable_persist_pipeline(64);
        info!(
            queue_depth = 64,
            "persist pipeline started in background thread"
        );
    }

    // 6c. Indexer boot (opt-in via [indexer] enabled in config).
    // `boot` returns `None` only when disabled — otherwise we get a
    // syncing handle (store wired) or a halted handle (store unavailable
    // due to schema/db corruption at open time). The polling task is only
    // spawned when the handle has a backing store; halted handles answer
    // status reads but never write.
    //
    // The cancel flag is allocated unconditionally so `RunHandle` can
    // signal it on shutdown regardless of whether a task was actually
    // spawned. `indexer_task_handle` is `Some` only when a task is live.
    let indexer_cancel = Arc::new(AtomicBool::new(false));
    let (indexer_handle, indexer_task_handle): (Option<IndexerHandle>, Option<JoinHandle<()>>) =
        match IndexerHandle::boot(&config.indexer_config, &config.data_dir) {
            Some(handle) if handle.store().is_some() => {
                info!(
                    poll_idle_ms = config.indexer_config.poll_idle_ms,
                    db = %config.indexer_config.db_filename,
                    "indexer enabled",
                );
                let chain = ChainReaderAdapter::new(store.reader_handle());
                let task = IndexerTask::new(handle.clone(), chain);
                let cancel_for_task = indexer_cancel.clone();
                let poll_idle = Duration::from_millis(config.indexer_config.poll_idle_ms);
                let task_handle = tokio::spawn(task.run(cancel_for_task, poll_idle));
                (Some(handle), Some(task_handle))
            }
            Some(handle) => {
                warn!(
                    status = ?handle.status(),
                    "indexer enabled but boot halted; store unavailable, status-only",
                );
                (Some(handle), None)
            }
            None => {
                info!("indexer disabled by config");
                (None, None)
            }
        };

    // Shadow validation: live cross-check of this node's chain against a
    // configured Scala reference node, surfacing divergence as an event +
    // metric instead of a day of log archaeology. Opt-in; the task never
    // touches the apply path — it reads through its own `ChainStoreReader`
    // and writes only the shared `ShadowState` the snapshot emitter / event
    // differ project out.
    let (shadow_state, shadow_task_handle): (
        Option<Arc<super::super::shadow_watch::ShadowState>>,
        Option<JoinHandle<()>>,
    ) = if config.shadow_config.enabled {
        match super::super::shadow_watch::HttpShadowReference::new(
            &config.shadow_config.reference_url,
            config.shadow_config.request_timeout_secs,
        ) {
            Ok(reference) => {
                let st = Arc::new(super::super::shadow_watch::ShadowState::default());
                let tip_reader = store.reader_handle();
                let ids_reader = store.reader_handle();
                let local = super::super::shadow_watch::LocalChainView {
                    // Committed full-block tip; 0 (skip-compare floor) on any
                    // read error — the shadow path never propagates store
                    // errors into alerts.
                    tip: move || {
                        tip_reader
                            .committed_tip()
                            .ok()
                            .flatten()
                            .map(|(h, _)| h)
                            .unwrap_or(0)
                    },
                    // Canonical best-chain id only: divergence is about the
                    // chain we FOLLOW, never validated orphans.
                    header_ids_at: move |h| {
                        ids_reader
                            .get_header_id_at_height(h)
                            .ok()
                            .flatten()
                            .map(|id| vec![hex::encode(id)])
                            .unwrap_or_default()
                    },
                };
                info!(
                    reference = %config.shadow_config.reference_url,
                    interval_secs = config.shadow_config.interval_secs,
                    lag_tolerance = config.shadow_config.lag_tolerance,
                    "shadow validation enabled"
                );
                let task = tokio::spawn(super::super::shadow_watch::run(
                    config.shadow_config.clone(),
                    reference,
                    local,
                    st.clone(),
                ));
                (Some(st), Some(task))
            }
            Err(error) => {
                // Fail loudly at boot: an enabled shadow that silently can't
                // watch would be the false comfort this mode exists to kill.
                return Err(format!("[shadow] reference client failed to build: {error}").into());
            }
        }
    } else {
        (None, None)
    };

    // 7. Hydrate + recover + build header index.
    //
    // The executor reads through the `StateBackendKind` enum — it is
    // backend-agnostic for the shared header/section + block-apply
    // paths — so these four calls dispatch to whichever backend `store`
    // holds.
    if let Err(e) = executor.hydrate_from_store(store) {
        error!(error = %e, "fatal: hydrate_from_store failed");
        return Err(Box::new(e));
    }
    if let Err(e) = executor.hydrate_block_context(store) {
        error!(error = %e, "fatal: hydrate_block_context failed");
        return Err(Box::new(e));
    }
    if let Err(e) = executor.load_header_index(store) {
        error!(error = %e, "fatal: load_header_index failed");
        return Err(Box::new(e));
    }
    let recovered = match executor.recover_coordinator(store, &mut coordinator) {
        Ok(n) => n,
        Err(e) => {
            error!(error = %e, "fatal: recover_coordinator failed");
            return Err(Box::new(e));
        }
    };
    if recovered > 0 {
        info!(
            recovered_blocks = recovered,
            "recovered pending blocks from store"
        );
    }

    // Committed chain-state snapshot. Nothing mutates committed state
    // between here and `NodeState` construction, so one owned snapshot
    // feeds the handshake `nipopow` feature, the heartbeat baselines, and
    // the NiPoPoW resume classification — backend-agnostic via the
    // `ChainStateRead` enum forward.
    let chain_meta = store.chain_state_meta();

    // Only the UTXO backend produces box-level apply events the wallet
    // can scan. The headers-only-digest (Mode 6) and digest-verifier
    // (Mode 5) backends have no box arena, so the live wallet apply hook
    // is left empty for both — matching the `NodeState.wallet_hook` doc
    // invariant.
    let backend_is_utxo = store.as_utxo().is_some();

    // Detect bootstrap source from chain_state for the identity label
    // projection. PoPowSparse header_availability is the signature of
    // `apply_popow_proof`; for the Dense + sentinel > 1 case we
    // additionally require the persistent `was_utxo_bootstrapped()`
    // provenance marker to confirm a Mode 2 install ever ran on this
    // store — otherwise the same shape is produced by an archive node
    // that later started pruning, and labelling it `utxo-bootstrapped`
    // would lie. Default to None when no bootstrap shape applies; the
    // label projection then refines to `post-prune archive` in that arm.
    // The bootstrap-kind label reads the UTXO snapshot-install
    // provenance marker, which only the UTXO backend carries. The
    // digest backend never UTXO- or NiPoPoW-bootstraps (Dense-only,
    // archive), so its label is unconditionally `None`.
    let bootstrap_kind = match store.as_utxo() {
        Some(s) => crate::node::identity::detect_bootstrap_kind(s, boot_sentinel).map_err(|e| {
            Box::new(std::io::Error::other(format!(
                "boot: bootstrap-kind detection failed (state corruption): {e}"
            ))) as NodeError
        })?,
        None => crate::node::identity::BootstrapKind::None,
    };

    let last_seen_active_params = store.active_params().clone();
    let last_seen_validation_settings = store.validation_settings().clone();
    // NiPoPoW reducer dispatch over the resume-state truth table. Fresh
    // arms a new reducer; ProofCommitted / NormalStore / Disabled skip
    // it. PartialHeaderSync is classified but refuses to boot — see the
    // `NipopowResumeState` docstring for the underlying machinery gap
    // that makes resume from partial-header state unsafe today.
    let popow_bootstrap = {
        let cs = &chain_meta;
        let resume = crate::node::identity::classify_nipopow_resume(
            config.nipopow_bootstrap,
            &cs.header_availability,
            cs.best_header_height,
            cs.best_full_block_height,
        );
        if config.nipopow_bootstrap {
            info!(
                best_header_height = cs.best_header_height,
                best_full_block_height = cs.best_full_block_height,
                resume_state = ?resume,
                "NiPoPoW bootstrap: resume-state classification",
            );
        }
        match resume {
            crate::node::identity::NipopowResumeState::Fresh => {
                Some(ergo_sync::popow_bootstrap::PopowBootstrap::new(
                    config.p2p_nipopows,
                    config.genesis_id,
                    config.chain_spec.difficulty.clone(),
                ))
            }
            crate::node::identity::NipopowResumeState::PartialHeaderSync => {
                // The reducer's PopowBootstrap::new contract is
                // fresh-only, and `apply_popow_proof` returns
                // `ApplyPopowProofWrongMode` on a non-fresh
                // store. Resuming Mode 4 from partial header
                // progress needs new machinery on the reducer +
                // apply path. Until that lands, refuse to boot
                // rather than arm a reducer whose proof apply
                // would later trigger sync_tick's terminal
                // mark_applied and silently abort bootstrap.
                return Err(Box::new(std::io::Error::other(format!(
                    "boot: NiPoPoW bootstrap cannot resume from partial \
                         header progress (best_header_height = {}, \
                         best_full_block_height = 0, header_availability = \
                         Dense). The reducer + apply path do not yet support \
                         resume; either wait for a future support tranche, \
                         clear the data dir to restart bootstrap from scratch, \
                         or remove nipopow_bootstrap from config.",
                    cs.best_header_height
                ))) as NodeError);
            }
            crate::node::identity::NipopowResumeState::Disabled
            | crate::node::identity::NipopowResumeState::NormalStore
            | crate::node::identity::NipopowResumeState::ProofCommitted => None,
        }
    };

    Ok(SyncSetup {
        coordinator,
        executor,
        indexer_handle,
        indexer_task_handle,
        indexer_cancel,
        shadow_state,
        shadow_task_handle,
        chain_meta,
        backend_is_utxo,
        bootstrap_kind,
        popow_bootstrap,
        last_seen_active_params,
        last_seen_validation_settings,
    })
}
