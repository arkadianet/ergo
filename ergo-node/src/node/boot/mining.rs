//! Boot phase: mining subsystem construction (the reward-key, `MiningHandle`,
//! and API bridge, gated on `[mining] enabled`) and the off-loop candidate
//! engine spawn (build-worker thread + coordinator task).

use std::time::Duration;

use ergo_state::HeaderSectionStore;
use tokio::task::JoinHandle;
use tracing::info;

use crate::config::NodeConfig;

use super::super::NodeError;

/// What [`build_subsystem`] produces. `handle` is consumed by the action
/// loop (owns the candidate cache); `bridge` holds only the channel sender
/// plus the pre-computed reward pubkey/address and is cloned into the API
/// `ServerCtx`.
pub(super) struct MiningSubsystem {
    pub handle: Option<ergo_mining::handle::MiningHandle>,
    pub bridge: Option<std::sync::Arc<dyn ergo_api::NodeMining>>,
}

/// Build the mining subsystem when `[mining].enabled = true`; both fields
/// are `None` otherwise (the action-loop arm rejects stray requests with
/// 503 and `/mining/*` routes are not mounted).
pub(super) fn build_subsystem(
    config: &NodeConfig,
    voting_targets_slot: &std::sync::Arc<std::sync::RwLock<std::collections::BTreeMap<u8, i64>>>,
    mining_submit_tx: &tokio::sync::mpsc::Sender<crate::mining_bridge::MiningRequest>,
) -> Result<MiningSubsystem, NodeError> {
    if !config.mining_config.enabled {
        return Ok(MiningSubsystem {
            handle: None,
            bridge: None,
        });
    }
    // Reward-key source: an operator-configured pubkey if present, else
    // resolve the wallet's EIP-3 first-address key lazily at candidate
    // time (Scala parity). Malformed configured hex still fails fast here.
    let reward_key = match config.mining_config.miner_public_key_hex.as_ref() {
        Some(pk_hex) => {
            let pk_bytes = hex::decode(pk_hex).map_err(|e| -> NodeError {
                format!("[mining] miner_public_key_hex hex decode: {e}").into()
            })?;
            let miner_pk: [u8; 33] = pk_bytes.as_slice().try_into().map_err(|_| -> NodeError {
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
    .with_reemission_rules(super::build_reemission_rules(&config.chain_spec))
    .with_voting_targets(voting_targets_slot.clone());
    let network_prefix = config.chain_spec.network_params.address_prefix;
    // Subscribe to the handle's serve-state-change notifications so the
    // bridge's longpoll wait wakes the instant the served candidate changes
    // (a fresh publish, or a tip transition that moves off the served work).
    let serve_rx = handle.subscribe_serve_changes();
    let bridge =
        crate::mining_bridge::MiningBridge::new(mining_submit_tx.clone(), network_prefix, serve_rx)
            .into_dyn();
    match reward_key {
        ergo_mining::handle::RewardKeySource::Pinned(pk) => {
            info!(pk = %hex::encode(pk), "mining subsystem enabled (configured reward key); /mining/* routes live");
        }
        ergo_mining::handle::RewardKeySource::Wallet => {
            info!("mining subsystem enabled (wallet-resolved reward key); /mining/* routes live");
        }
    }
    Ok(MiningSubsystem {
        handle: Some(handle),
        bridge: Some(bridge),
    })
}

/// What [`spawn_engine`] produces: the wiring the action loop needs plus
/// the two background handles (`RunHandle` aborts/joins them on shutdown).
pub(super) struct MiningEngineSpawn {
    pub wiring: Option<super::super::mining_dispatch::MiningWiring>,
    pub engine_handle: Option<JoinHandle<()>>,
    pub worker_handle: Option<std::thread::JoinHandle<()>>,
}

/// Spawn the off-loop mining-candidate engine: a `std::thread` build-worker
/// (owns the `!Send` per-tip dry-run base cache) plus a tokio task
/// coordinating build requests against it. Must run AFTER `NodeState` is
/// constructed (needs `state.store.reader_handle()` / `state.indexer_handle`)
/// and BEFORE the action loop is spawned (consumes `state` + `mining_handle`).
///
/// Boot owns the build-worker thread; the coordinator future owns only the
/// request `Sender`. The `std::sync::mpsc` build channel and the worker are
/// created HERE so the worker `JoinHandle` outlives the coordinator future:
/// `RunHandle::shutdown` aborts the coordinator (usually parked at
/// `reply_rx.await`), which drops the future and its `Sender`, then joins the
/// worker thread via the handle stored on `RunHandle`. If the worker were
/// spawned inside the future its handle would be dropped (detached) on
/// abort, letting a still-running build keep reading/publishing past
/// shutdown — the regression this split closes.
pub(super) fn spawn_engine(
    config: &NodeConfig,
    mining_handle: Option<ergo_mining::handle::MiningHandle>,
    state: &super::super::state::NodeState,
    mining_engine_cancel_tx: &tokio::sync::watch::Sender<bool>,
) -> MiningEngineSpawn {
    let Some(handle) = mining_handle else {
        return MiningEngineSpawn {
            wiring: None,
            engine_handle: None,
            worker_handle: None,
        };
    };
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
        tracing::warn!(
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
    let (req_tx, req_rx) = std::sync::mpsc::channel::<super::super::mining_engine::BuildRequest>();
    let dispatch = tracing::dispatcher::get_default(|d| d.clone());
    // Worker gets its own `MiningHandle` clone (cheap `Arc` share); the
    // coordinator keeps `handle` for the mode probe and refresh predicate.
    let worker = {
        let worker_handle = handle.clone();
        std::thread::Builder::new()
            .name("mining-build-worker".to_string())
            .spawn(move || {
                tracing::dispatcher::with_default(&dispatch, || {
                    super::super::mining_engine::run_build_worker(
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
    let task = tokio::spawn(super::super::mining_engine::run_mining_engine(
        engine_handle,
        req_tx,
        intent_rx,
        cancel_rx,
    ));
    MiningEngineSpawn {
        wiring: Some(super::super::mining_dispatch::MiningWiring {
            handle,
            intent_tx,
            refresh_debounce: Duration::from_millis(
                config.mining_config.block_candidate_generation_interval_ms,
            ),
        }),
        engine_handle: Some(task),
        worker_handle: Some(worker),
    }
}
