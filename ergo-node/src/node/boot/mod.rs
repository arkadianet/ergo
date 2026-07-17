//! Node boot sequence: store/genesis/AVL bring-up, handshake +
//! peer-manager build, executor + coordinator instantiation, indexer
//! orchestration, address-book restore, REST API bind, mining bridge
//! wire-up, and the action-loop spawn that produces the live
//! `RunHandle`. Production callers reach this through [`run`]; tests
//! call [`run_inner`] directly so they can drive the handle without
//! signal plumbing.
//!
//! [`run_inner_with_backend`] is the backend-agnostic boot tail, split
//! into four ordered phases (each in its own submodule) threaded through
//! a plain sequence of `let` bindings — this function's own local
//! variables ARE the "boot context": every phase function takes exactly
//! the prior variables it reads and returns a small struct of the new
//! ones it produces, so [`run_inner_with_backend`] itself stays the one
//! place that assembles them in order:
//!
//! 1. [`peers::setup`] — peer manager, address-book restore, known-peer seeding.
//! 2. [`sync_setup::setup`] — coordinator/executor, IBD + persist pipeline,
//!    indexer boot, shadow-validation wiring, hydrate/recover, NiPoPoW
//!    resume classification.
//! 3. [`mining::build_subsystem`] — the `MiningHandle` + API bridge (gated
//!    on `[mining].enabled`).
//! 4. [`api_wiring::build_scaffold`] then [`api_wiring::bind`] — identity +
//!    read/submit-bridge scaffolding, then the REST API bind itself (split
//!    in two because the mining subsystem above needs the scaffold's
//!    voting-targets slot before `bind` can use the mining bridge).
//!
//! Everything not owned by one of those phases (handshake construction,
//! channel setup, mempool/throttle config, `NodeState` assembly, the
//! anchor-map builder spawn, the off-loop mining-engine spawn, and the
//! action-loop spawn) stays inline here as the orchestrating body.

mod api_wiring;
mod mining;
mod peers;
mod sync_setup;

use std::sync::Arc;
use std::time::{Duration, Instant};

use ergo_mempool::Mempool;
use ergo_p2p::handshake::{Handshake, PeerFeature, PeerSpec, Version};
use ergo_state::store::StateStore;
use tokio::sync::{mpsc, oneshot};
use tracing::{info, warn};

use crate::anchor_map::{self, run_anchor_map_builder, RestPeers};
use crate::anchor_scheduler::AnchorScheduler;
use crate::api_bridge::SubmitRequest;
use crate::config::NodeConfig;
use crate::genesis;
use crate::peer_loop::{self, PeerEvent};

use super::action_loop::action_loop;
use super::handle::RunHandle;
use super::identity::validate_runtime_mode_support;
use super::peer_actions::try_dial_peers;
use super::state::{NodeState, PeerRegistry};
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
    // Install signal handlers BEFORE `run_inner` so a signal during startup
    // (store open, genesis init, AVL load, address-book restore, API bind —
    // which can run for minutes on a large archive database) is captured by
    // the OS-level handler rather than falling through to the default
    // terminate-immediately action. `tokio::signal::unix::signal` installs
    // its handler synchronously at call time (before the returned stream is
    // ever polled), so a signal arriving during `run_inner` is buffered and
    // observed by the `select!` below the moment startup completes.
    #[cfg(unix)]
    let (mut sig_int, mut sig_term, mut sig_hup) = {
        use tokio::signal::unix::{signal, SignalKind};
        (
            signal(SignalKind::interrupt())
                .map_err(|e| format!("failed to install SIGINT handler: {e}"))?,
            signal(SignalKind::terminate())
                .map_err(|e| format!("failed to install SIGTERM handler: {e}"))?,
            // SIGHUP: sent by the terminal when the controlling process
            // (e.g. the parent cargo process) exits. Without a handler,
            // default action is terminate — catching it here lets us close
            // the DB cleanly.
            signal(SignalKind::hangup())
                .map_err(|e| format!("failed to install SIGHUP handler: {e}"))?,
        )
    };
    // Windows has no persistent signal-handle equivalent to Unix's `signal()`
    // — `ctrl_c()` only arms its OS-level hook once its future is first
    // polled. Spawn it immediately (before `run_inner`) so a Ctrl+C during
    // startup is captured; the supervisor `select!` below then awaits this
    // same task instead of calling `ctrl_c()` fresh (which would reopen the
    // startup gap).
    #[cfg(windows)]
    let mut ctrl_c_task = tokio::spawn(tokio::signal::ctrl_c());

    let mut handle = run_inner(config).await?;
    let shutdown_notify = handle.shutdown_notify.clone();

    #[cfg(unix)]
    {
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
            _ = &mut ctrl_c_task => shutdown_log!("[node] Ctrl+C received, shutting down..."),
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
    // Phase 1: peer manager + address book + known-peer seeding.
    let (session_id, peer_manager) = peers::setup(&config);

    // Phase 2: sync coordinator/executor, IBD/persist pipeline, indexer,
    // shadow validation, hydrate/recover, NiPoPoW resume classification.
    let sync = sync_setup::setup(&config, &mut store, boot_sentinel)?;
    let coordinator = sync.coordinator;
    let executor = sync.executor;

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
                    nipopow: match sync.chain_meta.header_availability {
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

    let start_height = sync.chain_meta.best_full_block_height;
    let start_headers = sync.chain_meta.best_header_height;
    let weight_fn = sync_setup::mempool_weight_fn(&config)?;
    let api_weight_function = ergo_api::types::ApiWeightFunction::try_from(weight_fn.name())
        .map_err(|e| {
            NodeError::from(format!(
                "mempool weight function {:?} has no API wire mapping; \
                 add it to ergo_api::types::ApiWeightFunction. {e}",
                weight_fn.name(),
            ))
        })?;
    let mut mempool = Mempool::new(config.mempool_config.clone(), weight_fn);
    let mempool_notifier = crate::notifier::MempoolNotifier::new();
    let throttle = ergo_p2p::throttle::ThroughputLimiter::with_defaults();
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
    let started_at = Instant::now();

    // Phase 3a: API scaffolding (identity, snapshot publisher, read/submit
    // bridges) — built before mining so mining can share voting_targets_slot.
    let scaffold = api_wiring::build_scaffold(
        &config,
        &db_path,
        boot_sentinel,
        sync.bootstrap_kind,
        &executor,
        started_at,
        api_weight_function,
        &submit_tx,
        &event_tx,
    )?;
    let identity_inputs = crate::node::identity::IdentityInputs::from_config(&config);

    // Phase 3b: mining subsystem (the MiningHandle + API bridge).
    let mining_subsystem =
        mining::build_subsystem(&config, &scaffold.voting_targets_slot, &mining_submit_tx)?;

    // Graceful shutdown channel for the API task. Plumbed through
    // `ergo_api::serve_on` so axum's `with_graceful_shutdown` can
    // drain in-flight HTTP handlers before the task exits — avoiding
    // the TCP-RST mid-request that `JoinHandle::abort()` produces.
    // Held alongside `api_handle` on `RunHandle` so `shutdown()` can
    // signal it before awaiting the loop.
    // Constructed unconditionally; if the bind fails the receiver is
    // simply dropped and never observed.

    // Shared notify fired by `POST /node/shutdown`. Created before
    // the API server so the admin handle can capture a clone; the
    // outer `run()` waits on this alongside Ctrl+C / SIGTERM.
    let shutdown_notify = Arc::new(tokio::sync::Notify::new());

    // Phase 4: REST API bind.
    let api_bind = api_wiring::bind(
        &config,
        &store,
        &scaffold.api_info,
        &scaffold.snapshot_publisher,
        scaffold.read_state.clone(),
        scaffold.submit_bridge.clone(),
        sync.indexer_handle.clone(),
        &mut mempool,
        mining_subsystem.bridge.clone(),
        scaffold.voting_targets_slot.clone(),
        &shutdown_notify,
        &peer_connect_tx,
        &votes_changed_tx,
    )
    .await?;
    let api_addr = api_bind.api_addr;
    let api_handle = api_bind.api_handle;
    let api_shutdown_tx = api_bind.api_shutdown_tx;
    let live_wallet_hook = api_bind.live_wallet_hook;

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

    let mut state = NodeState {
        store,
        coordinator,
        executor,
        shadow: sync.shadow_state,
        last_reorg_enrichment: None,
        peer_manager,
        registry: PeerRegistry::new(),
        event_tx: event_tx.clone(),
        magic: config.chain_spec.network_params.magic,
        our_handshake,
        mempool,
        mempool_notifier,
        throttle,
        last_seen_active_params: sync.last_seen_active_params,
        last_seen_validation_settings: sync.last_seen_validation_settings,
        snapshot_publisher: Some(scaffold.snapshot_publisher),
        identity_inputs,
        identity_slot: scaffold.identity_slot,
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
        indexer_handle: sync.indexer_handle.clone(),
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
        popow_bootstrap: sync.popow_bootstrap,
        utxo_bootstrap_enabled: config.utxo_bootstrap,
        chunk_assembly: None,
        reconstructed_tree: None,
        pending_manifest_bytes: None,
        bootstrap_started_unix_ms: None,
        bootstrap_was_active_this_session: false,
        installed_snapshot: None,
        // The headers-only-digest (Mode 6) and digest-verifier (Mode 5)
        // backends have no UTXO-state apply events to feed the wallet,
        // so leave the hook empty to match the `NodeState.wallet_hook`
        // doc invariant. The wallet bridge itself is still mounted —
        // wallet routes process without erroring (UTXO-dependent reads
        // see an empty set; secret-only ops like init/unlock work).
        // Mode-aware route gating is tracked separately as feature work.
        wallet_hook: if sync.backend_is_utxo {
            live_wallet_hook
        } else {
            None
        },
        // True exactly when the mining engine was spawned (config.mining_config.enabled
        // AND the wiring was built above). `mining_handle.is_some()` is the
        // authoritative gate — it matches the expression that determined whether
        // to enter the `if config.mining_config.enabled` arm.
        mining_enabled: mining_subsystem.handle.is_some(),
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
        indexer_enabled = sync.indexer_handle.is_some(),
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
    let mining_engine_cancel_tx = tokio::sync::watch::channel(false).0;
    let mining_engine = mining::spawn_engine(
        &config,
        mining_subsystem.handle,
        &state,
        &mining_engine_cancel_tx,
    );

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let mempool_tick_ms = config.mempool_config.notifier_poll_ms;

    let loop_handle = tokio::spawn(action_loop(
        state,
        event_rx,
        submit_rx,
        mining_submit_rx,
        peer_connect_rx,
        votes_changed_rx,
        mining_engine.wiring,
        shutdown_rx,
        mempool_tick_ms,
    ));

    // Always expose the submit bridge — Scala-parity always-on
    // submission posture. The Option<_> wrapper stays so future
    // read-only modes can null it out without churning embedder
    // callsites.
    let submit = Some(scaffold.submit_bridge);

    Ok(RunHandle {
        api_addr,
        submit,
        read: scaffold.read_state,
        shutdown_tx: Some(shutdown_tx),
        api_shutdown_tx,
        loop_handle,
        api_handle,
        inbound_handle,
        shadow_task_handle: sync.shadow_task_handle,
        indexer_cancel: sync.indexer_cancel,
        indexer_task_handle: sync.indexer_task_handle,
        anchor_builder_handle: Some(anchor_builder_handle),
        anchor_builder_cancel_tx: anchor_cancel_tx_for_handle,
        mining_engine_handle: mining_engine.engine_handle,
        mining_worker_handle: mining_engine.worker_handle,
        mining_engine_cancel_tx,
        shutdown_notify,
    })
}
