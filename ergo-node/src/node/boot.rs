//! Node boot sequence: store/genesis/AVL bring-up, handshake +
//! peer-manager build, executor + coordinator instantiation, indexer
//! orchestration, address-book restore, REST API bind, mining bridge
//! wire-up, and the action-loop spawn that produces the live
//! `RunHandle`. Production callers reach this through [`run`]; tests
//! call [`run_inner`] directly so they can drive the handle without
//! signal plumbing.

use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use ergo_indexer::{IndexerHandle, IndexerQuery, IndexerTask};
use ergo_mempool::{weight, Mempool};
use ergo_p2p::address_book::AddressBook;
use ergo_p2p::handshake::{Handshake, PeerFeature, PeerSpec, Version};
use ergo_p2p::peer_manager::{KnownPeer, PeerManager, PeerOrigin};
use ergo_p2p::throttle::ThroughputLimiter;
use ergo_state::store::StateStore;
use ergo_sync::coordinator::SyncCoordinator;
use ergo_sync::executor::SyncExecutor;
use parking_lot::RwLock;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::anchor_map::{self, run_anchor_map_builder, RestPeers};
use crate::anchor_scheduler::AnchorScheduler;
use crate::api_bridge::{
    HostPaths, ScalaCompatBridge, ScalaCompatStatic, SnapshotMempoolView, SnapshotReadState,
    SubmitBridge, SubmitRequest,
};
use crate::config::NodeConfig;
use crate::genesis;
use crate::indexer_chain::ChainReaderAdapter;
use crate::notifier::MempoolNotifier;
use crate::peer_loop::{self, PeerEvent};
use crate::snapshot::{unix_now_ms, SnapshotPublisher};

use super::action_loop::action_loop;
use super::handle::RunHandle;
use super::identity::{build_api_identity, validate_runtime_mode_support};
use super::peer_actions::try_dial_peers;
use super::state::{NodeState, PeerRegistry};
use super::util::{rand_session_id, wall_to_instant};
use super::NodeError;

/// Production entry point: installs signal handlers up front, builds
/// the node via [`run_inner`], supervises the spawned action loop,
/// and shuts down cleanly when SIGINT/SIGTERM/SIGHUP fires.
///
/// Signal handlers are installed BEFORE `run_inner` so a signal during
/// startup (store open, genesis init, AVL load, address-book restore,
/// API bind) is queued by the OS handler and consumed by the supervisor
/// `select!` once startup completes — preserving clean shutdown across
/// the entire process lifetime, not just after the loop is spinning.
///
/// The supervisor also races the spawned loop's join handle: if the
/// action loop panics or returns early without a shutdown signal, we
/// surface that as a fatal `Err` rather than leaving the process alive
/// with the API task still serving against a dead state machine.
///
/// Tests bypass this and call [`run_inner`] directly so they own
/// shutdown through [`RunHandle::shutdown`] instead of sending signals.
pub async fn run(config: NodeConfig) -> Result<(), NodeError> {
    let mut handle = run_inner(config).await?;
    let shutdown_notify = handle.shutdown_notify.clone();

    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sig_int = signal(SignalKind::interrupt())
            .map_err(|e| format!("failed to install SIGINT handler: {e}"))?;
        let mut sig_term = signal(SignalKind::terminate())
            .map_err(|e| format!("failed to install SIGTERM handler: {e}"))?;
        // SIGHUP: sent by the terminal when the controlling process (e.g. the
        // parent cargo process) exits. Without a handler, default action is
        // terminate — catching it here lets us close the DB cleanly.
        let mut sig_hup = signal(SignalKind::hangup())
            .map_err(|e| format!("failed to install SIGHUP handler: {e}"))?;

        tokio::select! {
            biased;
            _ = sig_int.recv() => shutdown_log!("[node] SIGINT received, shutting down..."),
            _ = sig_term.recv() => shutdown_log!("[node] SIGTERM received, shutting down..."),
            _ = sig_hup.recv() => shutdown_log!("[node] SIGHUP received, shutting down..."),
            _ = shutdown_notify.notified() => shutdown_log!("[node] REST shutdown received, shutting down..."),
            loop_result = &mut handle.loop_handle => {
                let cause: NodeError = match loop_result {
                    Ok(Ok(())) => "action loop exited unexpectedly without shutdown signal".into(),
                    Ok(Err(e)) => e,
                    Err(join_err) => Box::new(join_err) as NodeError,
                };
                handle.drain_api_and_inbound().await;
                return Err(cause);
            }
        }
    }

    #[cfg(windows)]
    {
        tokio::select! {
            biased;
            _ = tokio::signal::ctrl_c() => shutdown_log!("[node] Ctrl+C received, shutting down..."),
            _ = shutdown_notify.notified() => shutdown_log!("[node] REST shutdown received, shutting down..."),
            loop_result = &mut handle.loop_handle => {
                let cause: NodeError = match loop_result {
                    Ok(Ok(())) => "action loop exited unexpectedly without shutdown signal".into(),
                    Ok(Err(e)) => e,
                    Err(join_err) => Box::new(join_err) as NodeError,
                };
                handle.drain_api_and_inbound().await;
                return Err(cause);
            }
        }
    }

    handle.shutdown().await
}

/// The `data_dir_state_type` sentinel a given config expects on disk.
///
/// Three backends share the `state_type = "digest"` config string but
/// own incompatible on-disk schemas, so each stamps a distinct
/// sentinel: Mode 5 (Digest + verify) is the digest-verifier backend
/// (`DigestStateStore`, "digest-verifier"); the canonical Mode 6
/// (Digest + !verify, headers-only) reuses the `StateStore` AVL+ arena
/// schema and stamps "digest"; everything else maps to the raw
/// `state_type` string. The peek-gate compares the recorded sentinel
/// against this so a Mode 5 dir is never reopened as Mode 6 (or vice
/// versa) in place.
fn expected_sentinel(config: &NodeConfig) -> &'static str {
    let is_mode_5 = crate::config::is_canonical_mode_5_combo(
        config.state_type,
        config.verify_transactions,
        config.blocks_to_keep,
        config.utxo_bootstrap,
    );
    if is_mode_5 {
        "digest-verifier"
    } else {
        config.state_type.as_str()
    }
}

/// Build EIP-27 re-emission rule inputs from the chain spec. Returns
/// `Some` only on a network that enables re-emission AND carries the
/// verified pay-to-reemission contract tree (mainnet); `None` elsewhere
/// (the public testnet), which disables the consensus check — matching
/// `ChainSpec::reemission` being `None` there. Wired into the block
/// validator so every block transaction is checked against the EIP-27
/// burning condition (Scala `verifyReemissionSpending`).
fn build_reemission_rules(
    spec: &ergo_chain_spec::ChainSpec,
) -> Option<ergo_validation::ReemissionRuleInputs> {
    // `None` means EIP-27 is not enabled on this network (e.g. testnet), so the
    // block validator correctly runs without the re-emission check.
    let reemission = spec.reemission.as_ref()?;
    // EIP-27 IS configured: the verified pay-to-reemission contract tree MUST be
    // available, else we would build rules without a contract to match outputs
    // against. Fail closed — refuse to boot rather than silently disable a
    // consensus check. Unreachable for `ChainSpec::for_network` (mainnet has the
    // trees; testnet returns above), so a failure here means a non-canonical /
    // inconsistent spec, surfaced loudly like the sibling `.expect("const hex")`
    // invariants in `emission_script_trees`.
    let trees = spec.emission_script_trees().expect(
        "chain spec configures EIP-27 re-emission but exposes no verified \
         pay-to-reemission contract tree; refusing to boot with re-emission \
         validation silently disabled",
    );
    Some(ergo_validation::ReemissionRuleInputs {
        activation_height: reemission.activation_height,
        reemission_token_id: *reemission.reemission_token_id.as_bytes(),
        pay_to_reemission_tree: trees.pay_to_reemission,
    })
}

/// Build the node, spawn the action loop on a background task, and
/// return a [`RunHandle`] without blocking on shutdown.
///
/// Production [`run`] calls this then waits on signals; integration
/// tests in `ergo-node/tests/` call this directly so they can drive
/// the in-process `submit` / `read` handles and exit on demand via
/// [`RunHandle::shutdown`].
pub async fn run_inner(config: NodeConfig) -> Result<RunHandle, NodeError> {
    // Mode 3 activation gate (runtime mirror of the config-load gate).
    // `NodeConfig::load` already enforces this for the TOML path, but
    // tests and library embedders construct `NodeConfig` directly,
    // bypassing it. This guard ensures no caller can boot a node that
    // advertises a pruned mode the implementation doesn't yet honor.
    // Lift in the eviction follow-up commit.
    validate_runtime_mode_support(&config)?;
    let db_path = config.data_dir.join("state.redb");
    std::fs::create_dir_all(&config.data_dir)?;

    // 1. Open store
    let cache_bytes = config
        .cache_bytes
        .unwrap_or(StateStore::DEFAULT_CACHE_BYTES);
    // Early mode-sentinel gate — runs BEFORE `open_with_cache` so a
    // mode mismatch fails fast, before any of the open-time
    // migrations (backfill_header_chain_index_if_needed,
    // reconcile_voted_params, codec migrations) can mutate an
    // incompatible data dir. If the sentinel exists and disagrees
    // with the configured `state_type`, refuse here. If the dir is
    // fresh or pre-sentinel, peek returns None and we proceed to
    // open; the stamp gets written by `verify_or_init_state_type`
    // after `open_with_cache` succeeds.
    //
    // The sentinel a fresh dir should carry for THIS config — Mode 5
    // (Digest + verify) is "digest-verifier" (the `DigestStateStore`
    // schema), every other config maps to its `state_type` string.
    // Comparing the recorded stamp against this catches a Mode 5 dir
    // reopened as Mode 6 (both `state_type = "digest"` in config but
    // incompatible on-disk schemas), which the bare `state_type`
    // comparison would have let through.
    let want_sentinel = expected_sentinel(&config);
    if db_path.exists() {
        if let Some(recorded) = StateStore::peek_state_type(&db_path).map_err(|e| {
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("data_dir sentinel peek failed: {e}"),
            )) as NodeError
        })? {
            if recorded != want_sentinel {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "data_dir initialized for state backend {recorded:?}, \
                         but config requests {want_sentinel:?} (state_type = \
                         {:?}); the UTXO, headers-only-digest, and \
                         digest-verifier backends are not interconvertible \
                         in-place — use a fresh data_dir for the new mode.",
                        config.state_type.as_str(),
                    ),
                )) as NodeError);
            }
        }
    }
    // Mode 5 (Digest Verifier) backend selection. The digest store has
    // its own incompatible schema (digest + chain-state history
    // ledgers, no AVL+ box arena), so it cannot reuse the UTXO
    // open/setup path below; instead it seeds the network's genesis
    // root and self-stamps the "digest-verifier" sentinel inside
    // `DigestStateStore::open`. Everything the UTXO arm does between
    // here and the hydration calls — `set_blocks_to_keep`,
    // `verify_or_init_state_type` (which would `StateTypeMismatch`
    // against the self-stamped sentinel), genesis init (no box arena),
    // the index back-fills, the prune-sentinel activation gate, and
    // `enable_persist_pipeline` — is UTXO-specific and is skipped.
    let is_mode_5 = crate::config::is_canonical_mode_5_combo(
        config.state_type,
        config.verify_transactions,
        config.blocks_to_keep,
        config.utxo_bootstrap,
    );
    if is_mode_5 {
        let store = ergo_state::DigestStateStore::open(
            &db_path,
            ergo_validation::scala_launch_for_network(config.chain_spec.network),
            config.chain_spec.voting,
            ergo_chain_spec::GenesisParams::for_network(config.chain_spec.network).state_digest,
        )?;
        info!(
            path = %db_path.display(),
            state_type = config.state_type.as_str(),
            "opened digest-verifier store (Mode 5)",
        );
        info!(
            height = store.height(),
            best_header_height = store.chain_state().best_header_height,
            "current chain state",
        );
        // The digest backend never prunes, so its minimal-full-block
        // height is the inert floor (1) — the same value the UTXO arm's
        // `read_minimal_full_block_height` returns on an archive store.
        let boot_sentinel = ergo_state::ChainStateRead::read_minimal_full_block_height(&store)
            .map_err(|e| {
                Box::new(std::io::Error::other(format!(
                    "boot: cannot read minimal_full_block_height on digest store: {e}"
                ))) as NodeError
            })?;
        return run_inner_with_backend(
            config,
            db_path,
            ergo_state::StateBackendKind::Digest(store),
            boot_sentinel,
        )
        .await;
    }

    let mut store = StateStore::open_with_cache_launch_voting(
        &db_path,
        cache_bytes,
        ergo_validation::scala_launch_for_network(config.chain_spec.network),
        config.chain_spec.voting,
    )?;
    // Mode 3: propagate `[node] blocks_to_keep` into the store so
    // `persist_apply` + `execute_batch` know whether to evict
    // sub-sentinel sections on every forward apply. MUST happen
    // BEFORE `enable_persist_pipeline` below — the pipeline worker
    // captures the value at spawn time.
    store.set_blocks_to_keep(config.blocks_to_keep);
    // Undo-retention window (`[node] keep_versions`, Scala keepVersions
    // parity). Same pre-pipeline ordering requirement as blocks_to_keep.
    store.set_rollback_window(config.keep_versions);
    // NiPoPoW prover reads the network's difficulty schedule (epoch
    // lengths + use_last_epochs) — override the mainnet open-default
    // so a testnet store proves with testnet epochs.
    store.set_difficulty_params(config.chain_spec.difficulty.clone());
    // Post-open stamp: write the sentinel for fresh + legacy dirs.
    // The early gate above already refused any mismatch on existing
    // sentinels; this call is a no-op when one is already present.
    store
        .verify_or_init_state_type(config.state_type.as_str())
        .map_err(|e| {
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("data_dir mode sentinel write failed: {e}"),
            )) as NodeError
        })?;
    info!(
        path = %db_path.display(),
        state_type = config.state_type.as_str(),
        avl_arena_cache_mb = cache_bytes / (1024 * 1024),
        "opened store",
    );
    // Observability note: redb cache config is implicit in 2.6.3 — the
    // `Database::builder()` call in `ergo-state::store` does not invoke
    // `set_cache_size`, so each redb DB falls back to the library default
    // (1 GiB per redb 2.6.3 `Builder::new`, ~90% read / ~10% write split).
    // Log this honestly so operators don't read the AVL arena MB above as
    // the total state-subsystem cache budget.
    info!(
        "redb cache: default/unset (1 GiB per DB, redb 2.6.3); cache_metrics feature disabled (evictions counter inactive)",
    );
    info!(
        height = store.height(),
        best_header_height = store.chain_state().best_header_height,
        "current chain state",
    );

    // Operator escape hatch: `ERGO_BAN_HEADERS` (comma-separated hex-32
    // header ids) pre-marks headers session-invalid so `header_proc`
    // refuses them on arrival. Session-scoped (in-memory, gone on
    // restart without the env) and opt-in — exists for incident
    // recovery where a peer keeps gossiping the tip of a known-invalid
    // branch that this node must not adopt (e.g. testnet 431,367,
    // block `66bfa980…`: header is PoW-valid, body fails script
    // verification, and the serving peer's own best-header pointer
    // never rewound). Malformed entries are rejected at boot so a
    // typo'd ban list fails loudly instead of silently not banning.
    match std::env::var("ERGO_BAN_HEADERS") {
        Ok(list) => {
            for tok in list.split(',').map(str::trim).filter(|t| !t.is_empty()) {
                let bytes = hex::decode(tok).map_err(|e| {
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("ERGO_BAN_HEADERS entry {tok:?} is not hex: {e}"),
                    )) as NodeError
                })?;
                let id: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "ERGO_BAN_HEADERS entry {tok:?} is {} bytes, expected 32",
                            bytes.len()
                        ),
                    )) as NodeError
                })?;
                store.mark_session_invalid(id);
                warn!(
                    header_id = tok,
                    "ERGO_BAN_HEADERS: header banned for this session"
                );
            }
        }
        Err(std::env::VarError::NotPresent) => {}
        // A set-but-non-UTF-8 value must not read as "not set" — that would
        // silently skip every ban, the exact failure this list fails loudly on.
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "ERGO_BAN_HEADERS is set but not valid UTF-8",
            )) as NodeError);
        }
    }

    // 2. Initialize genesis if needed (use genesis_committed flag, not height)
    if !store.genesis_committed() {
        info!("initializing genesis state");
        let boxes = genesis::genesis_boxes_for(config.chain_spec.network);
        store.initialize_genesis(&boxes)?;

        info!(boxes = boxes.len(), "genesis initialized");
    }

    // 2b. Back-fill MODIFIER_TYPE_INDEX for any pre-existing data.
    // No-op on fresh DBs; one-shot pass on first run after upgrade.
    // Idempotent — safe to run every boot. Progress + completion logs
    // come from inside `back_fill_modifier_type_index` (store layer).
    if let Err(e) = store.back_fill_modifier_type_index() {
        warn!(error = %e, "modifier-type-index back-fill failed");
    }

    // 2c. Back-fill HEADERS_BY_HEIGHT for any pre-existing data —
    // groups HEADER_META rows by height so `/blocks/at/{h}` can
    // surface fork orphans alongside the canonical chain header
    // (Scala `headerIdsAtHeight` parity from `HeadersProcessor.scala:264-276`).
    // Sentinel-gated: subsequent boots short-circuit. Idempotent.
    if let Err(e) = store.back_fill_headers_by_height_index() {
        warn!(error = %e, "headers-by-height index back-fill failed");
    }

    // 2d. Mode 3 — back-fill SECTION_HEIGHT_INDEX for any
    // pre-existing data. Powers the serve gate (a peer
    // requesting a section at height below the prune sentinel
    // gets a silent deny). Sentinel-gated like the two above;
    // runs even on archive boots so a future archive→pruned
    // transition has a populated index waiting.
    //
    // When `blocks_to_keep > 0`, back-fill failure is fail-loud
    // (the serve gate cannot operate without the index); when
    // pruning is off, log-and-continue so an archive boot isn't
    // blocked by a transient I/O or corruption issue in the
    // forward-looking index.
    match store.back_fill_section_height_index() {
        Ok(_) => {}
        Err(e) => {
            if config.blocks_to_keep > 0 {
                return Err(format!(
                    "section-height-index back-fill failed and \
                     pruning is enabled (blocks_to_keep={}); cannot \
                     boot safely: {e}",
                    config.blocks_to_keep,
                )
                .into());
            }
            warn!(
                error = %e,
                "section-height-index back-fill failed (archive \
                 boot — non-fatal, will retry next boot)",
            );
        }
    }
    // Mode 3 — prune-sentinel seeding happens at the
    // writer side (`install_snapshot_state` and `apply_popow_proof`
    // co-commit the sentinel inside their existing atomic txns),
    // not here. Reading `chain_state.best_full_block_height + 1`
    // post-open would lie about `snapshot_height` once forward
    // sync has advanced the tip — the writer-side approach pins
    // the boundary at install time, when the value is
    // unambiguously available.
    //
    // Mode 3 / Mode 2 / NiPoPoW activation gate: when any
    // sentinel-bearing operation has occurred (`blocks_to_keep
    // > 0` for live pruning, OR `sentinel > 1` from a prior
    // Mode 2 install / Mode 4 NiPoPoW dense-from), BOTH back-fill
    // sentinels MUST be stamped. Missing SECTION_HEIGHT_INDEX
    // rows would let the serve / receive / storage gates
    // fail-OPEN on Ok(None) lookups, breaking the "once pruned /
    // never resurrected" monotonicity. Missing HEADERS_BY_HEIGHT
    // rows would let eviction silently no-op while still
    // advancing the prune sentinel.
    //
    // Fail-loud on sentinel read errors: masking them with
    // `unwrap_or(1)` would skip the activation gate in the exact
    // corrupt-DB case the gate is meant to catch.
    let boot_sentinel = store.read_minimal_full_block_height().map_err(|e| {
        Box::new(std::io::Error::other(format!(
            "boot: cannot read minimal_full_block_height (state corruption blocks \
             Mode 3 activation check; refuse to boot rather than masking it as archive): {e}"
        ))) as NodeError
    })?;
    let sentinel_active = config.blocks_to_keep > 0 || boot_sentinel > 1;
    // Document a known split-brain state operationally — when the
    // operator's config says archive but the store has a
    // non-default sentinel, the wire/identity follow Scala parity
    // (advertise config.blocks_to_keep) while storage-side gates
    // (receive / serve / storage / rollback) fire on the sentinel.
    // Operator-actionable: either set utxo_bootstrap / nipopow_bootstrap
    // to acknowledge the bootstrap state, or use blocks_to_keep > 0
    // for explicit pruned mode. Logged at warn level so an
    // operator dashboard catches the split.
    if config.blocks_to_keep == -1
        && boot_sentinel > 1
        && !config.utxo_bootstrap
        && !config.nipopow_bootstrap
    {
        warn!(
            boot_sentinel,
            "Mode 3 advisory: store has a non-default prune sentinel but \
             config says archive with no bootstrap flag. Outward identity \
             will advertise archive (Scala parity); storage gates honor the \
             sentinel — set utxo_bootstrap / nipopow_bootstrap to align, or \
             move to blocks_to_keep > 0."
        );
    }
    if sentinel_active {
        if !store.section_height_backfill_complete()? {
            return Err(format!(
                "{}",
                ergo_state::store::StateError::SectionHeightBackfillRequired
            )
            .into());
        }
        store.back_fill_headers_by_height_index().map_err(|e| {
            Box::new(std::io::Error::other(format!(
                "HEADERS_BY_HEIGHT backfill failed (required when a prune \
                 sentinel is in force; eviction + receive/serve/storage gates \
                 depend on the height index being complete): {e}"
            ))) as NodeError
        })?;
        // Verify completeness beyond the sentinel bit. A
        // sentinel-active store whose indexes were partially
        // deleted (data-dir tampering, redb corruption) would
        // otherwise let eviction silently no-op or gates
        // black-hole valid traffic.
        store.verify_height_indexes_completeness().map_err(|e| {
            Box::new(std::io::Error::other(format!(
                "Mode 3 boot index verification failed: {e}"
            ))) as NodeError
        })?;
    }

    // UTXO setup complete — hand the backend (and the prune sentinel
    // the digest arm cannot produce) to the shared, backend-agnostic
    // boot tail.
    run_inner_with_backend(
        config,
        db_path,
        ergo_state::StateBackendKind::Utxo(store),
        boot_sentinel,
    )
    .await
}

/// The backend-agnostic boot tail shared by the UTXO and digest-verifier
/// arms: peer manager, address-book restore, coordinator + executor,
/// hydration, handshake, channels, mempool, REST API, and the action-loop
/// spawn that yields the live [`RunHandle`]. Reads committed chain state
/// through the [`StateBackendKind`] enum; UTXO-only subsystems (the
/// snapshot-install gate, indexer chain adapter, wallet bridge, mining
/// reward wiring) dispatch behind `as_utxo()` so the digest arm skips
/// them cleanly.
///
/// `boot_sentinel` is the Mode-3 prune sentinel the UTXO arm reads at
/// open; the digest backend never prunes, so it passes the inert floor.
async fn run_inner_with_backend(
    config: NodeConfig,
    db_path: std::path::PathBuf,
    mut store: ergo_state::StateBackendKind,
    boot_sentinel: u32,
) -> Result<RunHandle, NodeError> {
    use ergo_state::{ChainStateRead, HeaderSectionStore};
    // 3. Create components
    let session_id: i64 = rand_session_id();
    let mut peer_manager = PeerManager::new_with_limits(session_id, config.peer_limits);

    // 3a. Open + restore from persistent address book (best-effort).
    // Restore happens before configured-peer seeding so:
    // - persisted dial state (last_seen, backoff, from_seed) is preserved
    // - configured seeds re-asserting `from_seed=true` go through the
    //   normal write-through path (book.add_known) only when novel
    match AddressBook::open(&config.data_dir) {
        Ok(book) => {
            let book = Arc::new(book);
            match book.load_all() {
                Ok(state) => {
                    let mono_now = Instant::now();
                    let wall_now = SystemTime::now();
                    for p in &state.peers {
                        peer_manager.restore_known_peer(KnownPeer {
                            addr: p.addr,
                            last_seen: p.last_seen.map(|t| wall_to_instant(t, mono_now, wall_now)),
                            origin: p.origin,
                            last_failure: p
                                .last_failure
                                .map(|t| wall_to_instant(t, mono_now, wall_now)),
                            consecutive_failures: p.consecutive_failures,
                        });
                    }
                    for b in &state.bans {
                        peer_manager.restore_ban(
                            b.ip,
                            wall_to_instant(b.until, mono_now, wall_now),
                            b.count,
                        );
                    }
                    info!(
                        peers = state.peers.len(),
                        bans = state.bans.len(),
                        stale_skipped = state.stale_skipped,
                        corrupt_skipped = state.corrupt_skipped,
                        expired_bans_purged = state.expired_bans_purged,
                        "address_book restored",
                    );
                }
                Err(e) => {
                    warn!(error = %e, "address_book load_all failed; starting with empty in-memory state");
                }
            }
            peer_manager.set_address_book(book);
        }
        Err(e) => {
            warn!(error = %e, "address_book open failed; running without persistence");
        }
    };

    // 4. Seed known peers
    for addr in &config.known_peers {
        peer_manager.add_known_address(*addr, PeerOrigin::Seed);
    }
    info!(
        known_peers = config.known_peers.len(),
        "known peers configured"
    );
    info!(
        max_connections = config.peer_limits.max_connections,
        target_outbound = config.peer_limits.target_outbound,
        max_inbound = config.peer_limits.max_inbound(),
        per_ip = config.peer_limits.per_ip_limit,
        per_subnet = config.peer_limits.per_subnet_limit,
        "peer limits",
    );

    // 5. Create coordinator + executor
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
    let reemission_rules = build_reemission_rules(&config.chain_spec);
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

    // Shadow validation (operator workload §D): live cross-check vs a Scala
    // reference node. Opt-in; the task never touches the apply path — it
    // reads through its own `ChainStoreReader` and writes only the shared
    // `ShadowState` the snapshot emitter / event differ project out.
    let (shadow_state, shadow_task_handle): (
        Option<Arc<super::shadow_watch::ShadowState>>,
        Option<JoinHandle<()>>,
    ) = if config.shadow_config.enabled {
        match super::shadow_watch::HttpShadowReference::new(
            &config.shadow_config.reference_url,
            config.shadow_config.request_timeout_secs,
        ) {
            Ok(reference) => {
                let st = Arc::new(super::shadow_watch::ShadowState::default());
                let tip_reader = store.reader_handle();
                let ids_reader = store.reader_handle();
                let local = super::shadow_watch::LocalChainView {
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
                let task = tokio::spawn(super::shadow_watch::run(
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
    if let Err(e) = executor.hydrate_from_store(&store) {
        error!(error = %e, "fatal: hydrate_from_store failed");
        return Err(Box::new(e));
    }
    if let Err(e) = executor.hydrate_block_context(&store) {
        error!(error = %e, "fatal: hydrate_block_context failed");
        return Err(Box::new(e));
    }
    if let Err(e) = executor.load_header_index(&store) {
        error!(error = %e, "fatal: load_header_index failed");
        return Err(Box::new(e));
    }
    let recovered = match executor.recover_coordinator(&store, &mut coordinator) {
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
    // between here and `NodeState` construction below, so one owned
    // snapshot feeds the handshake `nipopow` feature, the heartbeat
    // baselines, and the NiPoPoW resume classification — backend-
    // agnostic via the `ChainStateRead` enum forward.
    let chain_meta = store.chain_state_meta();

    // Only the UTXO backend produces box-level apply events the wallet
    // can scan. The headers-only-digest (Mode 6) and digest-verifier
    // (Mode 5) backends have no box arena, so the live wallet apply hook
    // is left empty for both — matching the `NodeState.wallet_hook` doc
    // invariant. Read before `store` is moved into `NodeState`.
    let backend_is_utxo = store.as_utxo().is_some();

    // 7. Build handshake
    let declared_address = config.declared_addr.map(|sock| {
        // Encode IPv4 as 4 bytes, IPv6 as 16 bytes — matches Scala's
        // `serializer.toBytes` for `InetSocketAddress` (length-prefixed).
        let addr_bytes: Vec<u8> = match sock.ip() {
            std::net::IpAddr::V4(v4) => v4.octets().to_vec(),
            std::net::IpAddr::V6(v6) => v6.octets().to_vec(),
        };
        ergo_p2p::handshake::DeclaredAddress {
            addr: addr_bytes,
            port: sock.port() as u32,
        }
    });
    let our_handshake = Handshake {
        time: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
        peer_spec: PeerSpec {
            agent_name: config.agent_name.clone(),
            version: Version::CURRENT,
            node_name: config.node_name.clone(),
            declared_address,
            features: vec![
                PeerFeature::SessionId {
                    magic: config.chain_spec.network_params.magic,
                    session_id,
                },
                PeerFeature::Mode {
                    state_type: config.state_type.wire_byte(),
                    verify_tx: config.verify_transactions,
                    // Scala parity (`ModePeerFeature.scala:39`,
                    // `HeadersProcessor.scala:166-169`): a node that
                    // bootstrapped via NiPoPoW advertises
                    // `nipopow = Some(1)` so peers know it does NOT
                    // hold the full header chain (and therefore
                    // shouldn't be asked for one). We mirror that
                    // here by reading the persisted history mode at
                    // boot. A Dense store (no proof ever applied)
                    // advertises `None`; a PoPowSparse store
                    // advertises `Some(1)`.
                    nipopow: match chain_meta.header_availability {
                        ergo_state::chain::HeaderAvailability::Dense => None,
                        ergo_state::chain::HeaderAvailability::PoPowSparse { .. } => Some(1),
                    },
                    // Scala parity (confirmed against
                    // `ModePeerFeature.scala:67-72`):
                    //   if utxoSettings.utxoBootstrap → UTXOSetBootstrapped (-2)
                    //   else → clientCapabilities.blocksToKeep
                    // Scala's `modifiersReq` handler does NOT filter
                    // by the requester's blocks_to_keep; it serves
                    // whatever modifier_id is asked for.
                    blocks_to_keep: if config.utxo_bootstrap {
                        -2
                    } else {
                        config.blocks_to_keep
                    },
                },
            ],
        },
    };

    // 8. Event channel
    // P2P → Header pipeline uses bounded(4096). Headers are small
    // (~200B) and the action loop
    // processes them in big batches (one batch_validate_headers
    // call per Modifier event), so a deep buffer absorbs burst
    // arrivals from 60+ concurrent peers without back-pressuring
    // the per-peer read tasks.
    let (event_tx, event_rx) = mpsc::channel::<PeerEvent>(4096);

    // API submission channel. Bounded so a misbehaving client can't
    // queue-pressure the main loop. Capacity
    // of 256 absorbs a small burst while staying drainable in well
    // under one tick on a healthy node.
    let (submit_tx, submit_rx) = mpsc::channel::<SubmitRequest>(256);
    // Operator /peers/connect -> action-loop dial requests. Small bound:
    // these are manual, rare, and fire-and-forget.
    let (peer_connect_tx, peer_connect_rx) = mpsc::channel::<std::net::SocketAddr>(16);
    // Operator POST /api/v1/votes -> action-loop "rebuild the mining candidate
    // now" signal. Rare, fire-and-forget, coalescing (each rebuild reads the
    // latest targets), so a tiny bound is plenty.
    let (votes_changed_tx, votes_changed_rx) = mpsc::channel::<()>(8);

    // Mining request channel — same shape as submit_rx. Capacity 64 is
    // generous for external-miner polling: typical miners poll the
    // candidate every few seconds and submit solutions only after a
    // successful hash. Drop solutions over capacity rather than queue
    // them since a 5s+ queued solution is almost certainly stale on
    // arrival (block applies at ~2-minute cadence; cached candidates
    // turn over much faster under contention).
    let (mining_submit_tx, mining_submit_rx) =
        mpsc::channel::<crate::mining_bridge::MiningRequest>(64);

    let start_height = chain_meta.best_full_block_height;
    let start_headers = chain_meta.best_header_height;
    let weight_fn = weight::from_config(&config.mempool_sort_policy)
        .expect("sort policy validated at config load");
    let api_weight_function = ergo_api::types::ApiWeightFunction::try_from(weight_fn.name())
        .map_err(|e| {
            NodeError::from(format!(
                "mempool weight function {:?} has no API wire mapping; \
                 add it to ergo_api::types::ApiWeightFunction. {e}",
                weight_fn.name(),
            ))
        })?;
    let mut mempool = Mempool::new(config.mempool_config.clone(), weight_fn);
    let mempool_notifier = MempoolNotifier::new();
    let throttle = ThroughputLimiter::with_defaults();
    info!(
        enabled = config.mempool_config.enabled,
        sort = %config.mempool_sort_policy,
        size_cap = config.mempool_config.max_pool_size,
        min_relay_fee_nano_erg = config.mempool_config.min_relay_fee_nano_erg,
        "mempool configured",
    );
    info!(
        max_msgs_per_window = throttle.limits().max_msgs_per_window,
        max_mb_per_window = throttle.limits().max_bytes_per_window / 1_000_000,
        window_secs = 10,
        "throttle limits",
    );
    // Operator API publisher — created up front so the API server can
    // share the snapshot handle. If `api_bind` is None the server isn't
    // started; the publisher itself stays cheap (one ArcSwap) and is
    // updated unconditionally so disabling/enabling the API never
    // changes the main loop's hot path.
    let started_at = Instant::now();
    let api_info = ergo_api::types::ApiInfo {
        agent_name: config.agent_name.clone(),
        node_name: config.node_name.clone(),
        network: format!("{:?}", config.network).to_lowercase(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        started_at_unix_ms: unix_now_ms(),
        uptime_seconds: 0,
        // Pulled from the live chain spec so the operator dashboard
        // labels the "avg block time" hero against the *actual*
        // network target (mainnet 120s, testnet 45s) — not a
        // hardcoded mainnet value that misreads as broken on
        // testnet.
        target_block_interval_ms: config.chain_spec.difficulty.desired_interval_ms,
    };
    // Detect bootstrap source from chain_state for the identity
    // label projection. PoPowSparse header_availability is the
    // signature of `apply_popow_proof`; for the Dense + sentinel > 1
    // case we additionally require the persistent
    // `was_utxo_bootstrapped()` provenance marker to confirm a Mode 2
    // install ever ran on this store — otherwise the same shape is
    // produced by an archive node that later started pruning, and
    // labelling it `utxo-bootstrapped` would lie. Default to None
    // when no bootstrap shape applies; the label projection then
    // refines to `post-prune archive` in that arm.
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
    let api_identity = build_api_identity(&config, boot_sentinel, bootstrap_kind)?;
    let identity_inputs = crate::node::identity::IdentityInputs::from_config(&config);
    let identity_slot: crate::api_bridge::IdentitySlot =
        Arc::new(arc_swap::ArcSwap::from_pointee(api_identity.clone()));
    let snapshot_publisher =
        SnapshotPublisher::new(api_info.clone(), started_at, api_weight_function);
    // Read state is constructed unconditionally so [`RunHandle`] can
    // expose it for in-process tests even when the HTTP server isn't
    // bound. The submit bridge is always constructed (matching the
    // always-on submission posture); RunHandle exposes it via
    // `Some(_)` so embedders can drive in-process submissions.
    let host_paths = HostPaths {
        state_db: db_path.clone(),
        index_db: config.data_dir.join(&config.indexer_config.db_filename),
        data_dir: config.data_dir.clone(),
    };
    // ONE shared voting-targets slot, seeded from `[voting.targets]`. The SAME
    // `Arc<RwLock<…>>` is handed to the API read state (so `GET /api/v1/votes`
    // reports the live policy), the mining handle (candidate building reads it
    // per build), and — only when mining is enabled — the admin write path (so
    // the auth-gated `POST /api/v1/votes` updates all three at once).
    let voting_targets_slot =
        std::sync::Arc::new(std::sync::RwLock::new(config.voting_targets.clone()));
    let read_state: Arc<dyn ergo_api::NodeReadState> = SnapshotReadState::new(
        snapshot_publisher.handle(),
        identity_slot.clone(),
        host_paths,
        voting_targets_slot.clone(),
        executor.apply_phase_metrics(),
    )
    .into_dyn();
    let submit_bridge: Arc<dyn ergo_api::NodeSubmit> =
        SubmitBridge::new(submit_tx.clone(), event_tx.clone()).into_dyn();

    // Mining subsystem. Activated only when `[mining].enabled = true`;
    // when disabled both the in-process handle and the API bridge are
    // None, the action-loop arm rejects any stray requests with 503,
    // and the `/mining/*` routes are not mounted on the router.
    //
    // `mining_handle` is consumed by the action loop (it owns the
    // candidate cache and dispatches generate/verify against the
    // single-writer state). The API bridge holds only the channel
    // sender plus the pre-computed reward pubkey / address.
    let (mining_handle, mining_bridge): (
        Option<ergo_mining::handle::MiningHandle>,
        Option<Arc<dyn ergo_api::NodeMining>>,
    ) = if config.mining_config.enabled {
        // Reward-key source: an operator-configured pubkey if present, else
        // resolve the wallet's EIP-3 first-address key lazily at candidate
        // time (Scala parity). Malformed configured hex still fails fast here.
        let reward_key = match config.mining_config.miner_public_key_hex.as_ref() {
            Some(pk_hex) => {
                let pk_bytes = hex::decode(pk_hex).map_err(|e| -> NodeError {
                    format!("[mining] miner_public_key_hex hex decode: {e}").into()
                })?;
                let miner_pk: [u8; 33] =
                    pk_bytes.as_slice().try_into().map_err(|_| -> NodeError {
                        format!(
                            "[mining] miner_public_key_hex must be 33 bytes, got {}",
                            pk_bytes.len()
                        )
                        .into()
                    })?;
                ergo_mining::handle::RewardKeySource::Pinned(miner_pk)
            }
            None => ergo_mining::handle::RewardKeySource::Wallet,
        };
        let handle = ergo_mining::handle::MiningHandle::with_reward_key(
            reward_key,
            config.chain_spec.monetary,
            config.chain_spec.reemission.clone(),
            config.chain_spec.difficulty.clone(),
            config.chain_spec.voting,
        )
        .with_rent_config(
            config.mining_config.claim_storage_rent,
            config.mining_config.max_storage_rent_claims,
        )
        // Same EIP-27 rules the block validator and mempool use, so a candidate
        // can never carry an EIP-27-invalid emission / fee / storage-rent /
        // selected tx that block validation would later reject.
        .with_reemission_rules(build_reemission_rules(&config.chain_spec))
        .with_voting_targets(voting_targets_slot.clone());
        let network_prefix = config.chain_spec.network_params.address_prefix;
        // Subscribe to the handle's serve-state-change notifications so the
        // bridge's longpoll wait wakes the instant the served candidate changes
        // (a fresh publish, or a tip transition that moves off the served work).
        let serve_rx = handle.subscribe_serve_changes();
        let bridge = crate::mining_bridge::MiningBridge::new(
            mining_submit_tx.clone(),
            network_prefix,
            serve_rx,
        )
        .into_dyn();
        match reward_key {
            ergo_mining::handle::RewardKeySource::Pinned(pk) => {
                info!(pk = %hex::encode(pk), "mining subsystem enabled (configured reward key); /mining/* routes live");
            }
            ergo_mining::handle::RewardKeySource::Wallet => {
                info!(
                    "mining subsystem enabled (wallet-resolved reward key); /mining/* routes live"
                );
            }
        }
        (Some(handle), Some(bridge))
    } else {
        (None, None)
    };
    // Graceful shutdown channel for the API task. Plumbed through
    // `ergo_api::serve_on` so axum's `with_graceful_shutdown` can
    // drain in-flight HTTP handlers before the task exits — avoiding
    // the TCP-RST mid-request that `JoinHandle::abort()` produces.
    // Held alongside `api_handle` on `RunHandle` so `shutdown()` can
    // signal it before awaiting the loop.
    // Constructed unconditionally; if the bind fails the receiver is
    // simply dropped and never observed.
    let (api_shutdown_tx, api_shutdown_rx) = oneshot::channel::<()>();

    // Shared notify fired by `POST /node/shutdown`. Created before
    // the API server so the admin handle can capture a clone; the
    // outer `run()` waits on this alongside Ctrl+C / SIGTERM.
    let shutdown_notify = Arc::new(tokio::sync::Notify::new());

    let (api_addr, api_handle, api_shutdown_tx, live_wallet_hook) = if let Some(bind_addr) =
        config.api_bind
    {
        // Bind first so `rest_api_url` reflects the actual port (matters
        // for `:0` ephemeral binds in tests and embedders).
        //
        // Bind failure is logged-and-degraded, not fatal: REST is an
        // operator surface, not a prerequisite for sync / validation
        // availability. A test or embedder that needs strict bind
        // detection inspects the returned `RunHandle.api_addr` — `None`
        // after configuring `api_bind = Some(..)` is the failure signal,
        // distinguishable from "API disabled by config" (where
        // `api_bind` itself is `None`).
        match ergo_api::bind(bind_addr).await {
            Ok((actual, listener)) => {
                let scala_static = ScalaCompatStatic {
                    name: format!("ergo-rust-{}-{}", api_info.network, api_info.version),
                    app_version: api_info.version.clone(),
                    network: api_info.network.clone(),
                    launch_time_unix_ms: api_info.started_at_unix_ms,
                    rest_api_url: Some(format!("http://{actual}")),
                };
                let scala_compat_bridge_arc = Arc::new(ScalaCompatBridge::new(
                    snapshot_publisher.handle(),
                    scala_static,
                    store.reader_handle(),
                    config.chain_spec.difficulty.clone(),
                ));
                let scala_compat: Arc<dyn ergo_api::NodeChainQuery> =
                    scala_compat_bridge_arc.clone();
                // Submission HTTP routes are always mounted, matching
                // Scala's TransactionsApiRoute / BlocksApiRoute which
                // register unconditionally. Not-ready signals come
                // from the admission pipeline (TipUnready / IbdGated /
                // Disabled) rather than from a route-level gate.
                info!("api submission enabled; POST /api/v1/mempool/{{submit,check}} and POST /transactions[/bytes][/check[Bytes]], POST /blocks are live");
                let mounted_submit = Some(submit_bridge.clone());
                let network_prefix = config.chain_spec.network_params.address_prefix;
                let indexer_for_api: Option<Arc<dyn IndexerQuery>> = indexer_handle
                    .clone()
                    .map(|h| Arc::new(h) as Arc<dyn IndexerQuery>);
                // P5 mempool overlay: hand the snapshot-backed view to
                // the API so `/blockchain/balance` (and future unspent
                // routes) can render `unconfirmed` from pool state
                // without going through the action loop. Reads are
                // lock-free `arc_swap.load()` per snapshot, so the
                // overlay adds no contention with the main loop.
                let mempool_view = SnapshotMempoolView::new(snapshot_publisher.handle()).into_dyn();
                // Realtime WS bridge (A2): the same process-wide bus the
                // router feeds the `blocks` coarse-ring bridge into. Wiring
                // it as a `MempoolObserver` lets admit/evict publish
                // `tx_accepted`/`tx_dropped` on the `mempool` channel
                // directly from the admission hot path, bypassing the
                // coarse ring (which only carries block/reorg/peer events).
                mempool.set_observer(Some(Arc::new(
                    crate::realtime_mempool_bridge::RealtimeMempoolObserver::new(
                        ergo_api::realtime_handle().bus,
                    ),
                )));
                let mut admin = crate::api_bridge::ShutdownAdmin::new(
                    shutdown_notify.clone(),
                    Some(peer_connect_tx.clone()),
                )
                // Held regardless of mining state to keep the channel open; only
                // fired on a successful vote update (which requires mining).
                .with_votes_changed_signal(votes_changed_tx.clone());
                // Expose the runtime voting write only when mining is enabled —
                // votes have no effect without a candidate builder, so
                // `POST /api/v1/votes` otherwise returns `MiningDisabled`.
                if config.mining_config.enabled {
                    admin = admin.with_voting_targets(voting_targets_slot.clone());
                }
                let admin_handle: Arc<dyn ergo_api::NodeAdmin> = admin.into_dyn();

                // Production wallet admin. Owns the secret storage + wallet
                // state behind RwLocks; the writer task is a dedicated tokio
                // task receiving commands via a channel.
                let db_arc = store.db_arc();
                let is_pruned = config.blocks_to_keep != -1;
                // `ChainStateAccessorImpl::tip_height()` now reads the live committed
                // tip from redb per-call (no captured value), so no boot-time tip is
                // threaded in.
                let chain_accessor: Arc<dyn super::wallet_bridge::ChainStateAccessor> =
                    Arc::new(super::wallet_bridge::ChainStateAccessorImpl::new(
                        db_arc.clone(),
                        is_pruned,
                        // Same EIP-27 rules the validator uses, so the wallet's
                        // burn-aware builder + self-verify gate share consensus.
                        build_reemission_rules(&config.chain_spec),
                    ));
                let wallet_storage = {
                    let secret_dir = config.data_dir.join("wallet");
                    Arc::new(RwLock::new(ergo_wallet::storage::SecretStorage::open(
                        secret_dir,
                    )))
                };
                // Hydrate in-memory caches from redb on restart so that
                // /wallet/addresses and friends serve correct data while the
                // wallet is still locked. The wallet stays locked — operator
                // must /wallet/unlock to load the master key.
                let wallet_state = {
                    let use_pre_1627 = {
                        let mut s = wallet_storage.write();
                        match s.lock_state() {
                            ergo_wallet::storage::LockState::Uninitialized => false,
                            _ => s.load_metadata().unwrap_or_else(|e| {
                                warn!("wallet boot: could not read use_pre_1627 metadata: {e}; defaulting to false");
                                false
                            }),
                        }
                    };
                    let mut state = ergo_wallet::state::WalletState::empty(use_pre_1627);
                    match db_arc.begin_read() {
                        Ok(read_txn) => {
                            let reader = ergo_state::wallet::reader::WalletReader::new(&read_txn);
                            if let Err(e) = state.hydrate_from_reader(&reader, network_prefix) {
                                warn!("wallet boot: hydration from redb failed: {e}; starting with empty caches");
                            }
                        }
                        Err(e) => {
                            warn!("wallet boot: could not open redb read txn for hydration: {e}");
                        }
                    }
                    Arc::new(RwLock::new(state))
                };
                // Clone the Arc before moving into run_wallet_writer so the
                // main loop retains a reference for the live apply hook.
                let wallet_state_for_hook = Arc::clone(&wallet_state);
                let (wallet_tx, wallet_rx) =
                    mpsc::channel::<super::wallet_bridge::WalletCommand>(64);
                let writer_cfg = super::wallet_bridge::WriterConfig {
                    network: network_prefix,
                    expose_private_keys: config.wallet_expose_private_keys,
                    // Same EIP-27 rule inputs the block/mempool validator uses, so
                    // the wallet's re-emission reserve + burn-aware builder cannot
                    // drift from consensus (None off EIP-27 nets, e.g. testnet).
                    reemission: build_reemission_rules(&config.chain_spec),
                    min_relay_fee_nano_erg: config.mempool_config.min_relay_fee_nano_erg,
                    max_tx_size_bytes: config.mempool_config.max_tx_size_bytes,
                };
                let submit_handle: std::sync::Arc<dyn super::wallet_bridge::TxSubmitter> =
                    std::sync::Arc::new(super::wallet_bridge::NodeSubmitAdapter::new(
                        submit_bridge.clone(),
                    ));
                tokio::spawn(super::wallet_bridge::run_wallet_writer(
                    wallet_rx,
                    wallet_storage,
                    wallet_state,
                    db_arc.clone(),
                    chain_accessor,
                    writer_cfg,
                    submit_handle,
                    // Clone the mempool view for the wallet's unconfirmed-balance
                    // overlay; the original moves into ServerCtx below.
                    mempool_view.clone(),
                ));
                let wallet_admin: Arc<dyn ergo_api::wallet::WalletAdmin> =
                    Arc::new(super::wallet_bridge::NodeWalletAdmin::new(wallet_tx));

                let api_ctx = ergo_api::ServerCtx {
                    read: read_state.clone(),
                    compat: Some(scala_compat.clone()),
                    submit: mounted_submit,
                    indexer: indexer_for_api,
                    mempool: mempool_view,
                    network: network_prefix,
                    chain_params: Some(scala_compat_bridge_arc.clone().into_chain_params()),
                    mining: mining_bridge.clone(),
                    // Static per-network schedule math — always wired.
                    // Public route by Scala parity (no withAuth).
                    emission: Some(Arc::new(crate::api_bridge::EmissionScheduleBridge::new(
                        config.chain_spec.monetary,
                        config.chain_spec.reemission.clone(),
                    ))),
                    // Pre-rendered P2S addresses for /emission/scripts;
                    // None off-mainnet (no verified tree constants), in
                    // which case the route stays unmounted (404).
                    emission_scripts: crate::api_bridge::render_emission_scripts(
                        &config.chain_spec,
                    )
                    .map(Arc::new),
                    // `/utxo/*` mount-vs-503 follows the backend: only
                    // the UTXO backend retains box bytes. The digest
                    // backend's boot dispatch (Mode 5) doesn't reach
                    // here yet, but the gate is the right shape now.
                    utxo_reads_supported: config.state_type == crate::config::StateType::Utxo,
                };
                // Mandatory api_key_hash per Scala ErgoApp.scala:40-43.
                // `NodeConfig::load` rejects (api_bind = Some,
                // api_key_hash = None) at config.rs, so the typical
                // production path hits the Ok branches below. We still
                // surface a typed error rather than panic for callers
                // that build `NodeConfig` literals and bypass `load()`
                // (integration tests, future programmatic spawn paths,
                // etc.).
                let Some(hash) = config.api_key_hash.clone() else {
                    return Err("config invariant broken: api_bind = Some(_) requires \
                         api_key_hash = Some(_); NodeConfig::load would have \
                         rejected this, so the caller built a NodeConfig \
                         literal that bypassed validation"
                        .into());
                };
                let security_inner =
                    ergo_api::auth::ApiSecurity::new(hash).map_err(|e| -> NodeError {
                        format!("invalid api_key_hash in NodeConfig: {e}").into()
                    })?;
                let security = Arc::new(security_inner);
                let handle = ergo_api::serve_on_with_mempool_and_wallet_and_security(
                    api_ctx,
                    listener,
                    api_shutdown_rx,
                    Some(admin_handle),
                    wallet_admin,
                    Some(security),
                );
                let hook = Arc::new(super::wallet_bridge::WalletStateHook {
                    wallet: wallet_state_for_hook,
                    db: db_arc.clone(),
                });
                (
                    Some(actual),
                    Some(handle),
                    Some(api_shutdown_tx),
                    Some(hook),
                )
            }
            Err(e) => {
                warn!(addr = %bind_addr, error = %e, "api bind failed; node continuing without API");
                drop(api_shutdown_rx);
                (None, None, None, None)
            }
        }
    } else {
        info!("api disabled by config");
        drop(api_shutdown_rx);
        (None, None, None, None)
    };

    // Inbound P2P listener (opt-in via `[peers] bind_addr`). Without it
    // the node runs outbound-only: peers we dialed feed us blocks/txs
    // fine, but other nodes can't dial us back, so the inbound slots
    // (`max_connections - target_outbound`) sit unused and we don't
    // contribute upload bandwidth to the network.
    let inbound_handle = if let Some(bind) = config.bind_addr {
        Some(tokio::spawn(peer_loop::inbound_listener_task(
            bind,
            event_tx.clone(),
        )))
    } else {
        info!("inbound listener disabled (no [peers] bind_addr); outbound only");
        None
    };

    let last_seen_active_params = store.active_params().clone();
    let last_seen_validation_settings = store.validation_settings().clone();
    // NiPoPoW reducer dispatch over the resume-state truth
    // table. Fresh arms a new reducer; ProofCommitted /
    // NormalStore / Disabled skip it. PartialHeaderSync is
    // classified but refuses to boot — see the
    // `NipopowResumeState` docstring for the underlying machinery
    // gap that makes resume from partial-header state unsafe
    // today.
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
    let mut state = NodeState {
        store,
        coordinator,
        executor,
        shadow: shadow_state,
        last_reorg_enrichment: None,
        peer_manager,
        registry: PeerRegistry::new(),
        event_tx: event_tx.clone(),
        magic: config.chain_spec.network_params.magic,
        our_handshake,
        mempool,
        mempool_notifier,
        throttle,
        last_seen_active_params,
        last_seen_validation_settings,
        snapshot_publisher: Some(snapshot_publisher),
        identity_inputs,
        identity_slot,
        last_beat: Instant::now(),
        // Seeded one idle interval in the past so the first tick emits the
        // operator heartbeat immediately — a node that boots already
        // stalled (gap > 0, no progress) stays visible from tick one
        // rather than going dark for HEARTBEAT_IDLE_INTERVAL. `checked_sub`
        // guards the monotonic-clock underflow when the node starts within
        // one interval of OS boot (same idiom as `last_dial_at` below).
        last_beat_emit: Instant::now()
            .checked_sub(crate::node::heartbeat::HEARTBEAT_IDLE_INTERVAL)
            .unwrap_or_else(Instant::now),
        last_beat_height: start_height,
        last_beat_headers: start_headers,
        req_messages_total: 0,
        req_ids_total: 0,
        sections_received_total: 0,
        mempool_tx_requested_total: 0,
        mempool_peer_tx_admitted_total: 0,
        mempool_peer_tx_rejected_total: 0,
        last_beat_req_messages: 0,
        last_beat_req_ids: 0,
        last_beat_sections_received: 0,
        // Set in the past so the very first `try_dial_peers` call from
        // either the initial-dial below or the first tick fires
        // immediately even in slow mode. `checked_sub` rather than `-`
        // because `Instant - Duration` panics on monotonic-clock
        // underflow — a real surface when the node starts within 60s
        // of OS boot. Falling back to "now" just delays the very first
        // dial by one cooldown window, which is harmless.
        last_dial_at: Instant::now()
            .checked_sub(Duration::from_secs(60))
            .unwrap_or_else(Instant::now),
        // Start in the past so the first gossip-tick after startup
        // fires immediately rather than waiting a full GOSSIP_INTERVAL
        // — useful for tests and accelerates topology discovery on
        // fresh boots. `checked_sub` guards against a too-recent boot
        // (clock at < GOSSIP_INTERVAL from monotonic origin).
        last_gossip_at: Instant::now()
            .checked_sub(ergo_p2p::peer_manager::GOSSIP_INTERVAL)
            .unwrap_or_else(Instant::now),
        indexer_handle: indexer_handle.clone(),
        anchor_map: anchor_map::AnchorMap::new(),
        rest_peer_urls: std::sync::Arc::new(std::sync::RwLock::new(RestPeers::new())),
        anchor_builder_cancel_tx: tokio::sync::watch::channel(false).0,
        anchor_scheduler: AnchorScheduler::new(),
        enable_anchor_scheduler: config.enable_anchor_scheduler,
        anchor_tip_cursor: std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0)),
        snapshot_state: super::snapshot_state::SnapshotState::new(),
        snapshot_bootstrap: ergo_sync::snapshot_bootstrap::SnapshotBootstrap::new(),
        // Pre-resolved above to avoid the partial-move conflict
        // with `store` (the condition needs &store; the field-init
        // sequence would move it first). The reducer's lifetime
        // matches the bootstrap window only — `None` outside it.
        popow_bootstrap,
        utxo_bootstrap_enabled: config.utxo_bootstrap,
        chunk_assembly: None,
        reconstructed_tree: None,
        pending_manifest_bytes: None,
        bootstrap_started_unix_ms: None,
        bootstrap_was_active_this_session: false,
        // The headers-only-digest (Mode 6) and digest-verifier (Mode 5)
        // backends have no UTXO-state apply events to feed the wallet,
        // so leave the hook empty to match the `NodeState.wallet_hook`
        // doc invariant. The wallet bridge itself is still mounted —
        // wallet routes process without erroring (UTXO-dependent reads
        // see an empty set; secret-only ops like init/unlock work).
        // Mode-aware route gating is tracked separately as feature work.
        wallet_hook: if backend_is_utxo {
            live_wallet_hook
        } else {
            None
        },
        // True exactly when the mining engine was spawned (config.mining_config.enabled
        // AND the wiring was built above). `mining_handle.is_some()` is the
        // authoritative gate — it matches the expression that determined whether
        // to enter the `if config.mining_config.enabled` arm.
        mining_enabled: mining_handle.is_some(),
        api_weight_function,
        recent_blocks_cache: None,
        network: config.chain_spec.network_params.address_prefix,
        first_deliverer_ring: crate::node::first_deliverer::FirstDelivererRing::new(),
        event_feed: crate::node::event_feed::EventFeedRing::new(),
        event_feed_prev: crate::node::event_feed::FeedPrev::default(),
        reorg_history: crate::node::reorg_history::ReorgHistory::new(),
        event_feed_projection: None,
        reorg_history_projection: None,
    };

    // Spawn the Step B anchor-map builder. Background task that
    // periodically snapshots `rest_peer_urls` and queries
    // `/blocks/at/{h}`. JoinHandle is stored in `RunHandle` and
    // aborted on shutdown so the task doesn't outlive the action
    // loop. Cancel is latched (`watch<bool>`); RunHandle owns the
    // sender so both `shutdown()` and `Drop` can fire it.
    let anchor_cancel_rx = state.anchor_builder_cancel_tx.subscribe();
    let anchor_cancel_tx_for_handle = state.anchor_builder_cancel_tx.clone();
    let anchor_builder_handle = {
        let map = state.anchor_map.clone();
        let urls = state.rest_peer_urls.clone();
        let tip_cursor = state.anchor_tip_cursor.clone();
        tokio::spawn(async move {
            run_anchor_map_builder(map, urls, tip_cursor, anchor_cancel_rx).await;
        })
    };

    // `node_ready` is the operator-facing "boot complete; serving"
    // signal. Emitted after the store, mempool, optional indexer,
    // optional API server, and optional inbound P2P listener have all
    // been constructed; the next thing the function does is spawn the
    // action loop. The fields are flat-named so dashboards can filter
    // on subsystem-enabled status without parsing nested objects.
    info!(
        event = "node_ready",
        network = ?config.network,
        data_dir = %config.data_dir.display(),
        api_enabled = config.api_bind.is_some(),
        api_addr = ?api_addr,
        p2p_inbound_enabled = inbound_handle.is_some(),
        mempool_enabled = config.mempool_config.enabled,
        indexer_enabled = indexer_handle.is_some(),
        start_height,
        start_header_height = start_headers,
        "node ready",
    );

    info!("starting sync loop");

    // Initial dial — connect immediately, don't wait for first tick.
    // Done here (not inside `action_loop`) so any failure surfaces in
    // the caller's task rather than the spawned loop, matching the
    // pre-refactor behavior.
    try_dial_peers(&mut state);

    // Off-loop mining-candidate engine. Spawned BEFORE the action loop (which
    // consumes `state` + `mining_handle`); it reads committed redb snapshots
    // through its own `ChainStoreReader` and CAS-publishes into the candidate
    // cache shared (via `Arc`) with the action-loop's `MiningHandle` clone.
    // Cancel is a latched `watch<bool>` mirroring the anchor builder; the
    // intent sender is handed to the action loop as the producer side.
    //
    // Boot owns the build-worker thread; the coordinator future owns only the
    // request `Sender`. We create the `std::sync::mpsc` build channel and spawn
    // the worker HERE so the worker `JoinHandle` outlives the coordinator
    // future: `RunHandle::shutdown` aborts the coordinator (usually parked at
    // `reply_rx.await`), which drops the future and its `Sender`, then joins the
    // worker thread via the handle stored on `RunHandle`. If the worker were
    // spawned inside the future its handle would be dropped (detached) on
    // abort, letting a still-running build keep reading/publishing past
    // shutdown — the regression this split closes.
    let mining_engine_cancel_tx = tokio::sync::watch::channel(false).0;
    let (mining_wiring, mining_engine_handle, mining_worker_handle): (
        Option<super::mining_dispatch::MiningWiring>,
        Option<JoinHandle<()>>,
        Option<std::thread::JoinHandle<()>>,
    ) = if let Some(handle) = mining_handle {
        let reader = state.store.reader_handle();
        let indexer = state.indexer_handle.clone();
        // Per-tip dry-run base cache: off by default (a multi-GB resident AVL
        // graph is an operator-facing deployment change). Captured by the
        // worker thread's `move` closure below.
        let use_base_cache = config.mining_config.candidate_base_cache;
        // Discoverability nudge: this branch only runs with mining enabled
        // (which requires `state_type = "utxo"`). With the cache off, every
        // candidate build re-hydrates the full UTXO AVL tree — seconds when the
        // pages are warm, minutes under memory pressure — and a same-tip rebuild
        // on each mempool change re-pays it, which starves an external miner
        // (`GET /mining/candidate` 503s) once a build exceeds the block
        // interval. Left opt-in deliberately (the resident graph is multi-GB),
        // but surfaced loudly so the operator knows the lever exists.
        if !use_base_cache {
            warn!(
                "mining: [mining] candidate_base_cache is off — every candidate build \
                 re-hydrates the full UTXO AVL tree (seconds warm, minutes under memory \
                 pressure), and every same-tip rebuild (each mempool change) re-pays it. \
                 Set `[mining] candidate_base_cache = true` to keep the tree resident \
                 (multi-GB RAM) so rebuilds reuse it and are near-instant."
            );
        }
        let (intent_tx, intent_rx) =
            tokio::sync::watch::channel::<Option<ergo_mining::engine::BuildIntent>>(None);
        let cancel_rx = mining_engine_cancel_tx.subscribe();
        // Build-request channel: the worker owns the receiver, the coordinator
        // future owns the sender. The worker is a plain OS thread (not a tokio
        // task) because it will own the `!Send` per-tip dry-run base cache.
        //
        // `tracing::subscriber::set_default` (the capture tests' mechanism)
        // installs a THREAD-LOCAL default, so a freshly spawned `std::thread`
        // would not inherit it and its build logs would vanish. Snapshot the
        // active dispatcher here on the spawning thread and run the worker loop
        // under it: in production this is the global default (no-op); under test
        // it is the thread-local capture subscriber. The worker's logs then
        // route exactly where the inline build's did.
        let (req_tx, req_rx) = std::sync::mpsc::channel::<super::mining_engine::BuildRequest>();
        let dispatch = tracing::dispatcher::get_default(|d| d.clone());
        // Worker gets its own `MiningHandle` clone (cheap `Arc` share); the
        // coordinator keeps `handle` for the mode probe and refresh predicate.
        let worker = {
            let worker_handle = handle.clone();
            std::thread::Builder::new()
                .name("mining-build-worker".to_string())
                .spawn(move || {
                    tracing::dispatcher::with_default(&dispatch, || {
                        super::mining_engine::run_build_worker(
                            reader,
                            worker_handle,
                            indexer,
                            use_base_cache,
                            req_rx,
                        );
                    });
                })
                .expect("spawn mining build worker thread")
        };
        let engine_handle = handle.clone();
        let task = tokio::spawn(super::mining_engine::run_mining_engine(
            engine_handle,
            req_tx,
            intent_rx,
            cancel_rx,
        ));
        (
            Some(super::mining_dispatch::MiningWiring {
                handle,
                intent_tx,
                refresh_debounce: Duration::from_millis(
                    config.mining_config.block_candidate_generation_interval_ms,
                ),
            }),
            Some(task),
            Some(worker),
        )
    } else {
        (None, None, None)
    };

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let mempool_tick_ms = config.mempool_config.notifier_poll_ms;

    let loop_handle = tokio::spawn(action_loop(
        state,
        event_rx,
        submit_rx,
        mining_submit_rx,
        peer_connect_rx,
        votes_changed_rx,
        mining_wiring,
        shutdown_rx,
        mempool_tick_ms,
    ));

    // Always expose the submit bridge — Scala-parity always-on
    // submission posture. The Option<_> wrapper stays so future
    // read-only modes can null it out without churning embedder
    // callsites.
    let submit = Some(submit_bridge);

    Ok(RunHandle {
        api_addr,
        submit,
        read: read_state,
        shutdown_tx: Some(shutdown_tx),
        api_shutdown_tx,
        loop_handle,
        api_handle,
        inbound_handle,
        shadow_task_handle,
        indexer_cancel,
        indexer_task_handle,
        anchor_builder_handle: Some(anchor_builder_handle),
        anchor_builder_cancel_tx: anchor_cancel_tx_for_handle,
        mining_engine_handle,
        mining_worker_handle,
        mining_engine_cancel_tx,
        shutdown_notify,
    })
}
