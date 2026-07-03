//! Implements `ergo_api::NodeReadState` against the snapshot handle
//! the main loop publishes. Lock-free read path: `arc_swap.load()`.
//!
//! The newtype wrapping the handle is what makes the trait impl legal —
//! both the trait and `ArcSwap` are foreign, so a direct impl on
//! `ArcSwap<NodeSnapshot>` would violate the orphan rule.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use tracing::{info, warn};

use ergo_api::compat::types::{
    score_to_u128, Parameters, ScalaBlacklistedPeers, ScalaBlockSection, ScalaBlockTransactions,
    ScalaFullBlock, ScalaHeader, ScalaInfo, ScalaMerkleProof, ScalaOutput, ScalaPeer,
    ScalaTransactionInput,
};
use ergo_api::types::{
    ApiHealth, ApiHost, ApiIdentity, ApiInfo, ApiMempoolSummary, ApiMempoolTransaction,
    ApiMempoolTransactions, ApiPeer, ApiRecentBlock, ApiStatus, ApiSyncStatus, ApiTip,
};
use ergo_api::types::{SubmitError, SubmitMode};
use ergo_api::{MempoolView, NodeAdmin, NodeChainQuery, NodeReadState, NodeSubmit, PoolTxDetail};
use ergo_crypto::pow::verify_pow_solution;
use ergo_primitives::digest::Digest32;
use ergo_primitives::reader::VlqReader;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::ergo_box::{read_ergo_box, ErgoBox};
use ergo_ser::header::read_header;
use ergo_state::reader::ChainStoreReader;
use tokio::sync::Notify;

// Decoder helpers re-exported from the shared `ergo-rest-json` crate.
// Tests below exercise these directly to maintain the b4_* byte-parity
// oracle in this file (the load-bearing Scala-vs-Rust check).

use crate::snapshot::{unix_now_ms, SnapshotHandle};

mod block_reassembly;
mod compat;
mod emission;
mod error;

use block_reassembly::{
    assemble_full_block, build_proof_for_tx, load_and_encode_block_transactions,
    load_and_encode_header, load_and_encode_modifier_by_id, load_headers_in_range,
};
use compat::*;
pub use emission::{render_emission_scripts, EmissionScheduleBridge};
use error::BridgeError;

/// Lock-free identity slot. The action loop swaps a fresh
/// `ApiIdentity` here on each bootstrap transition; the API
/// bridge reads via `load()` per request. Cheap to clone (Arc).
pub type IdentitySlot = Arc<arc_swap::ArcSwap<ApiIdentity>>;

pub struct SnapshotReadState {
    handle: SnapshotHandle,
    /// Lock-free slot the action loop publishes to whenever
    /// boot, `install_snapshot_state`, or `apply_popow_proof`
    /// changes the bootstrap-derived identity fields. Each
    /// `/api/v1/identity` request reads the current value via
    /// `load()`; no allocation on the hot path.
    identity: IdentitySlot,
    /// Paths host metrics need at request time. Captured at boot; never
    /// change. `state_db` and `index_db` are file paths whose `metadata().len()`
    /// is the on-disk size; `data_dir` is the volume the disk-space readout
    /// resolves against.
    host_paths: HostPaths,
    /// Operator voting targets (param id → target value), seeded from
    /// `[voting.targets]` at boot. This is the SAME `Arc<RwLock<…>>` slot the
    /// `MiningHandle` reads and the auth-gated `POST /api/v1/votes` writes, so
    /// `GET /api/v1/votes` always reports the LIVE policy (config + any runtime
    /// edits). Empty ⇒ neutral.
    voting_targets: std::sync::Arc<std::sync::RwLock<std::collections::BTreeMap<u8, i64>>>,
}

/// Filesystem paths the `/api/v1/host` handler needs to compute per-call
/// metrics. Cheap to clone — three `PathBuf`s.
#[derive(Clone, Debug)]
pub struct HostPaths {
    pub state_db: PathBuf,
    pub index_db: PathBuf,
    pub data_dir: PathBuf,
}

/// Drop the Windows `\\?\` extended-length namespace prefix from a
/// canonicalized path so it can be compared against bare drive roots
/// returned by sysinfo (e.g. `C:\`). No-op on non-Windows paths and
/// on paths that don't start with the prefix. Returned as `PathBuf`
/// so the caller can use `Path::starts_with` on it.
fn strip_extended_length_prefix(p: PathBuf) -> PathBuf {
    // The prefix is `\\?\` (four characters). Use `Path::components`
    // first so we don't accidentally rewrite a path that happens to
    // contain `?` literals later in its body.
    use std::path::{Component, Prefix};
    let mut comps = p.components();
    if let Some(Component::Prefix(prefix_comp)) = comps.next() {
        match prefix_comp.kind() {
            Prefix::VerbatimDisk(letter) => {
                // `\\?\C:\Users\...` → `C:\Users\...`
                let mut rebuilt = PathBuf::from(format!("{}:", letter as char));
                for c in comps {
                    rebuilt.push(c.as_os_str());
                }
                return rebuilt;
            }
            Prefix::Verbatim(_) | Prefix::VerbatimUNC(_, _) => {
                // Other extended-length forms (rare): fall through
                // and return the original. Disk-space match will
                // miss, but that's better than guessing wrong.
            }
            _ => {}
        }
    }
    p
}

/// Implements `NodeAdmin` by firing a shared `tokio::sync::Notify` that
/// the action loop's outer wait-for-shutdown `select!` listens for. Any
/// awaiter (Ctrl+C handler or this REST endpoint) racing to fire it is
/// fine — `notify_one` is idempotent, and the action loop only consumes
/// the first signal. Cheap to clone (ref-counted Arc).
pub struct ShutdownAdmin {
    notify: Arc<Notify>,
    /// Operator `/peers/connect` dial requests into the action loop.
    /// `None` for embedders that only expose shutdown.
    peer_connect_tx: Option<tokio::sync::mpsc::Sender<std::net::SocketAddr>>,
    /// Shared voting-targets slot (the SAME `Arc<RwLock<…>>` the `MiningHandle`
    /// reads and the API read state reports). `Some` only when mining is
    /// enabled — `POST /api/v1/votes` returns `MiningDisabled` when `None`,
    /// since votes have no effect without a candidate builder.
    voting_targets: Option<std::sync::Arc<std::sync::RwLock<std::collections::BTreeMap<u8, i64>>>>,
    /// Wakes the action loop to force a same-tip candidate rebuild after a vote
    /// change, so the new header votes apply to the next mined block instead of
    /// waiting for the next tip / mempool change. Held even when mining is off
    /// (keeps the channel open); only fired on a successful vote update, which
    /// requires `voting_targets` to be `Some`.
    votes_changed_tx: Option<tokio::sync::mpsc::Sender<()>>,
}

impl ShutdownAdmin {
    pub fn new(
        notify: Arc<Notify>,
        peer_connect_tx: Option<tokio::sync::mpsc::Sender<std::net::SocketAddr>>,
    ) -> Self {
        Self {
            notify,
            peer_connect_tx,
            voting_targets: None,
            votes_changed_tx: None,
        }
    }

    /// Wire the shared voting-targets slot so `POST /api/v1/votes` can update
    /// it. Call only when mining is enabled; otherwise the write is rejected
    /// with `MiningDisabled`.
    pub fn with_voting_targets(
        mut self,
        slot: std::sync::Arc<std::sync::RwLock<std::collections::BTreeMap<u8, i64>>>,
    ) -> Self {
        self.voting_targets = Some(slot);
        self
    }

    /// Wire the action-loop rebuild signal so a successful vote change forces an
    /// immediate same-tip candidate rebuild. Held regardless of mining state to
    /// keep the channel open; only fired on a successful update.
    pub fn with_votes_changed_signal(mut self, tx: tokio::sync::mpsc::Sender<()>) -> Self {
        self.votes_changed_tx = Some(tx);
        self
    }

    pub fn into_dyn(self) -> Arc<dyn NodeAdmin> {
        Arc::new(self)
    }
}

impl NodeAdmin for ShutdownAdmin {
    fn request_shutdown(&self) {
        info!("/node/shutdown received via REST API");
        self.notify.notify_one();
    }

    fn connect_to_peer(&self, addr: std::net::SocketAddr) {
        let Some(tx) = &self.peer_connect_tx else {
            info!(peer = %addr, "/peers/connect ignored: no dial channel wired");
            return;
        };
        // Fire-and-forget (Scala ConnectTo): a full/closed channel just
        // drops the request — the route has already answered 200.
        if let Err(e) = tx.try_send(addr) {
            info!(peer = %addr, error = %e, "/peers/connect dial request dropped");
        } else {
            info!(peer = %addr, "/peers/connect dial requested");
        }
    }

    fn set_voting_targets(
        &self,
        targets: Vec<(u8, i64)>,
    ) -> Result<(), ergo_api::VotingControlError> {
        let Some(slot) = &self.voting_targets else {
            return Err(ergo_api::VotingControlError::MiningDisabled);
        };
        // Validate every id is operator-votable (1..=8, or 9) BEFORE applying
        // any, so a bad id rejects the whole request without a partial update.
        // `votable_param_name` returns `None` for blockVersion (123), soft-fork
        // (120), and unknown ids.
        for (id, _) in &targets {
            if ergo_validation::voting::votable_param_name(*id).is_none() {
                return Err(ergo_api::VotingControlError::NotVotable { parameter_id: *id });
            }
        }
        // Reject any target outside the parameter's allowable `[min, max]` voting
        // bounds. The recompute only ever steps a parameter toward a bound (and
        // won't step past it), so a target beyond the bound can never be a
        // settling value — it would just pin the parameter at the bound forever
        // while silently misleading the operator. The bounds are constant per id
        // (the same `[min, max]` `GET /api/v1/votes` reports), so no active-param
        // table is needed. Votable-name check above already rejected non-votable
        // ids, so `votable_param_bounds` is `Some` for every id here.
        for (id, target) in &targets {
            if let Some((min, max)) = ergo_validation::voting::votable_param_bounds(*id) {
                let (min, max) = (min as i64, max as i64);
                if *target < min || *target > max {
                    return Err(ergo_api::VotingControlError::OutOfRange {
                        parameter_id: *id,
                        target: *target,
                        min,
                        max,
                    });
                }
            }
        }
        // REPLACE the set (BTreeMap collect dedups by id, last wins).
        let map: std::collections::BTreeMap<u8, i64> = targets.into_iter().collect();
        let count = map.len();
        *slot.write().expect("voting_targets poisoned") = map;
        // Force an immediate candidate rebuild so the new votes apply now, not
        // on the next tip / mempool change. Fire-and-forget: a full channel
        // already has a rebuild queued (each rebuild reads the latest targets),
        // so a dropped signal is harmless.
        if let Some(tx) = &self.votes_changed_tx {
            let _ = tx.try_send(());
        }
        info!(count, "voting targets replaced via POST /api/v1/votes");
        Ok(())
    }
}

impl SnapshotReadState {
    pub fn new(
        handle: SnapshotHandle,
        identity: IdentitySlot,
        host_paths: HostPaths,
        voting_targets: std::sync::Arc<std::sync::RwLock<std::collections::BTreeMap<u8, i64>>>,
    ) -> Self {
        Self {
            handle,
            identity,
            host_paths,
            voting_targets,
        }
    }

    /// Wrap as an `Arc<dyn NodeReadState>` for `ergo_api::serve`.
    pub fn into_dyn(self) -> Arc<dyn NodeReadState> {
        Arc::new(self)
    }

    fn age_ms(&self, produced_at: Instant) -> u64 {
        Instant::now()
            .saturating_duration_since(produced_at)
            .as_millis() as u64
    }
}

impl NodeReadState for SnapshotReadState {
    fn info(&self) -> ApiInfo {
        self.handle.load().info.clone()
    }

    fn votes(&self) -> ergo_api::ApiVotes {
        let snap = self.handle.load();
        let active = &snap.active_params;
        ergo_api::ApiVotes {
            block_height: snap.tip.best_full_block.height,
            block_version: active.block_version,
            epoch_start_height: active.epoch_start_height,
            votable_parameters: ergo_validation::voting::votable_param_descriptors(active)
                .into_iter()
                .map(|d| ergo_api::ApiVotableParam {
                    id: d.id,
                    name: d.name.to_string(),
                    description: d.description.to_string(),
                    current: d.current,
                    step: d.step,
                    min: d.min,
                    max: d.max,
                })
                .collect(),
            // The operator's LIVE voting policy (config + any runtime
            // `POST /api/v1/votes` edits), read under the shared lock, ascending
            // by id (BTreeMap order). Reported as configured, independent of
            // whether a parameter would cast a vote this block (that depends on
            // the live value vs the target). Every id was validated votable when
            // set, so `votable_param_name` resolves; fall back defensively.
            configured_votes: self
                .voting_targets
                .read()
                .expect("voting_targets poisoned")
                .iter()
                .map(|(&id, &target)| ergo_api::ApiConfiguredVote {
                    parameter_id: id,
                    name: ergo_validation::voting::votable_param_name(id)
                        .unwrap_or("unknown")
                        .to_string(),
                    target,
                })
                .collect(),
        }
    }

    fn identity(&self) -> ApiIdentity {
        (**self.identity.load()).clone()
    }

    fn host(&self) -> ApiHost {
        // `state.redb` and `indexer.redb` are plain files; their on-disk
        // size is `metadata().len()`. The indexer file is absent when
        // `[indexer] enabled = false`, which produces `None`.
        let state_db_bytes = std::fs::metadata(&self.host_paths.state_db)
            .map(|m| m.len())
            .ok();
        let index_db_bytes = std::fs::metadata(&self.host_paths.index_db)
            .map(|m| m.len())
            .ok();

        // Process RSS via sysinfo. Refresh only the current process; this
        // avoids enumerating every process on the host on each handler call.
        let mut sys = sysinfo::System::new();
        let rss_bytes = sysinfo::get_current_pid().ok().and_then(|p| {
            sys.refresh_processes_specifics(
                sysinfo::ProcessesToUpdate::Some(&[p]),
                true,
                sysinfo::ProcessRefreshKind::new().with_memory(),
            );
            sys.process(p).map(|proc| proc.memory())
        });

        // Disk space — find the disk whose mount-point is a prefix of
        // data_dir (longest match wins, in case data_dir lives on a
        // sub-mount).
        //
        // On Windows, `std::fs::canonicalize` returns paths prefixed
        // with the `\\?\` extended-length namespace (e.g.
        // `\\?\C:\Users\...\ergo-data`), while sysinfo's mount points
        // come back as bare drive roots (e.g. `C:\`). `Path::starts_with`
        // compares path components, not byte prefixes, so the extended
        // namespace prefix kills the match. Strip it before comparing.
        let disks = sysinfo::Disks::new_with_refreshed_list();
        let canonical_data = std::fs::canonicalize(&self.host_paths.data_dir)
            .map(strip_extended_length_prefix)
            .unwrap_or_else(|_| self.host_paths.data_dir.clone());
        let mut best_match: Option<&sysinfo::Disk> = None;
        let mut best_len = 0usize;
        for disk in &disks {
            let mp = disk.mount_point();
            if canonical_data.starts_with(mp) && mp.as_os_str().len() > best_len {
                best_len = mp.as_os_str().len();
                best_match = Some(disk);
            }
        }
        let (disk_free_bytes, disk_total_bytes) = best_match
            .map(|d| (Some(d.available_space()), Some(d.total_space())))
            .unwrap_or((None, None));

        ApiHost {
            rss_bytes,
            state_db_bytes,
            index_db_bytes,
            disk_free_bytes,
            disk_total_bytes,
            cpu_pct: None,
            net_in_bps: None,
            net_out_bps: None,
            load_1m: None,
        }
    }

    fn status(&self) -> ApiStatus {
        let snap = self.handle.load();
        let mut s = snap.status.clone();
        s.snapshot_age_ms = self.age_ms(snap.produced_at);
        s
    }

    fn tip(&self) -> ApiTip {
        self.handle.load().tip.clone()
    }

    fn sync(&self) -> ApiSyncStatus {
        self.handle.load().sync.clone()
    }

    fn peers(&self) -> Vec<ApiPeer> {
        self.handle.load().peers.clone()
    }

    fn events(&self) -> ergo_api::types::ApiNodeEvents {
        // Pure snapshot clone of the projected event tail.
        (*self.handle.load().events).clone()
    }

    fn recent_blocks(&self, n: u32) -> Vec<ApiRecentBlock> {
        // Pure snapshot clone of the precomputed tail (newest-first),
        // truncated to the caller's bound.
        self.handle
            .load()
            .recent_blocks
            .iter()
            .take(n as usize)
            .cloned()
            .collect()
    }

    fn mempool_summary(&self) -> ApiMempoolSummary {
        self.handle.load().mempool.clone()
    }

    fn mempool_transactions(&self) -> ApiMempoolTransactions {
        self.handle.load().mempool_transactions.clone()
    }

    fn mempool_transaction(&self, tx_id_hex: &str) -> Option<ApiMempoolTransaction> {
        self.handle
            .load()
            .mempool_transactions
            .transactions
            .iter()
            .find(|t| t.tx_id == tx_id_hex)
            .cloned()
    }

    fn health(&self) -> ApiHealth {
        let snap = self.handle.load();
        let mut h = snap.health.clone();
        // The age stored in the snapshot is correct as of `produced_at`;
        // bump it forward so a stale snapshot doesn't report a fresher
        // last-progress than reality.
        h.last_progress_age_ms = h
            .last_progress_age_ms
            .saturating_add(self.age_ms(snap.produced_at));
        h
    }
}

/// Snapshot-backed `MempoolView` for the extra-index P5 overlay.
/// Reads `pool_inputs` / `pool_outputs` from the current snapshot on
/// every call; cheap because the snapshot is `ArcSwap`-shared and
/// rebuilt off the main loop once per `sync_tick`.
///
/// Scala parity: each method maps to the matching read on Scala's
/// in-memory `ErgoMemPoolReader`. The wrapping is what makes the trait
/// impl legal (orphan rule — both `MempoolView` and `ArcSwap` are
/// foreign).
pub struct SnapshotMempoolView {
    handle: SnapshotHandle,
}

impl SnapshotMempoolView {
    pub fn new(handle: SnapshotHandle) -> Self {
        Self { handle }
    }

    /// Wrap as an `Arc<dyn MempoolView>` for handler injection.
    pub fn into_dyn(self) -> Arc<dyn MempoolView> {
        Arc::new(self)
    }
}

impl MempoolView for SnapshotMempoolView {
    fn is_spent_by_pool(&self, box_id: &Digest32) -> bool {
        self.handle.load().pool_inputs.contains_key(box_id)
    }

    fn pool_spending_tx(&self, box_id: &Digest32) -> Option<Digest32> {
        self.handle.load().pool_inputs.get(box_id).copied()
    }

    fn pool_outputs(&self) -> Arc<std::collections::HashMap<Digest32, ErgoBox>> {
        self.handle.load().pool_outputs.clone()
    }

    fn pool_tx_detail(&self, tx_id: &Digest32) -> Option<PoolTxDetail> {
        // Single coherent load: the tx bytes and the pool-output overlay
        // must come from the same snapshot version so pool-parent input
        // resolution can't race a rebuild between two `load()` calls.
        let snap = self.handle.load();
        let bytes = snap
            .pool_full_txs
            .iter()
            .find(|(id, _)| id == tx_id)
            .map(|(_, b)| b.clone())?;
        Some((bytes, snap.pool_outputs.clone()))
    }
}

// Scala-compat read-side bridge — kept in a sibling submodule to
// keep this file navigable. The body uses `use super::*;` to
// inherit api_bridge.rs's import environment, so the split is pure
// relocation. The module itself is private; the `pub use` below
// re-exports the only two public types at api_bridge.rs's level —
// `api_bridge::scala_compat` is NOT a public path.
mod scala_compat;
pub use scala_compat::{ScalaCompatBridge, ScalaCompatStatic};

// Tests in `api_bridge/tests.rs` access this helper via `use super::*;`
// — bring it into api_bridge.rs's namespace so the sibling submodule
// continues to see it without changing the test file.
#[cfg(test)]
use scala_compat::encode_scala_output_from_raw;

// =====================================================================
// Submission bridge
// =====================================================================
//
// `SubmitBridge` is the API-side half of the cross-task channel that
// hands raw bytes to the main loop for admission. The handler `await`s
// a oneshot reply per request — bounded channel, bounded per-request
// timeout.

/// Per-submission deadline. If the main loop hasn't drained and replied
/// within this window, the handler returns `504 reason: "timeout"`.
/// `[proposed]` 5s.
pub const SUBMIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// One submission ferried from the API task to the main loop. The
/// handler holds the `Sender` end of the oneshot; the main loop's
/// `select!` arm sends back when admission completes.
pub struct SubmitRequest {
    pub bytes: Vec<u8>,
    pub mode: SubmitMode,
    pub reply: tokio::sync::oneshot::Sender<Result<String, SubmitError>>,
}

/// Newtype around the channel sender so we can `impl NodeSubmit`. The
/// orphan rule blocks a direct impl on `mpsc::Sender`.
///
/// Carries two channels into the action loop:
/// - `tx` — tx submission (existing `SubmitRequest`).
/// - `event_tx` — `PeerEvent` channel, used for the §12 `POST /blocks`
///   sendMinedBlock path. Wraps the same channel peer-task events
///   ride on, since locally-mined blocks are processed through
///   `PeerEvent::LocalFullBlock`.
pub struct SubmitBridge {
    tx: tokio::sync::mpsc::Sender<SubmitRequest>,
    event_tx: tokio::sync::mpsc::Sender<crate::peer_loop::PeerEvent>,
}

impl SubmitBridge {
    pub fn new(
        tx: tokio::sync::mpsc::Sender<SubmitRequest>,
        event_tx: tokio::sync::mpsc::Sender<crate::peer_loop::PeerEvent>,
    ) -> Self {
        Self { tx, event_tx }
    }

    pub fn into_dyn(self) -> Arc<dyn NodeSubmit> {
        Arc::new(self)
    }
}

#[async_trait::async_trait]
impl NodeSubmit for SubmitBridge {
    async fn submit_transaction_json(
        &self,
        input: ScalaTransactionInput,
        mode: SubmitMode,
    ) -> Result<String, SubmitError> {
        let bytes = decode_scala_transaction(&input).map_err(|(reason, detail)| SubmitError {
            reason: reason.to_string(),
            detail: Some(detail),
        })?;
        self.submit_transaction(bytes, mode).await
    }

    /// §12 `POST /blocks` (sendMinedBlock) production override.
    ///
    /// 1. Decode the Scala-shape JSON into canonical wire bytes for each
    ///    section via `decode_scala_full_block`. Section-id consistency
    ///    is enforced at the JSON boundary.
    /// 2. Re-parse the produced header bytes and verify the Autolykos
    ///    PoW solution. Doing this in the API task means an
    ///    invalid-PoW submission never wakes the action loop.
    /// 3. Send `PeerEvent::LocalFullBlock` with the four section byte
    ///    vectors + a oneshot reply to the action loop's event
    ///    channel. The handler in
    ///    `ergo-node/src/node/events.rs::inject_local_full_block`
    ///    runs the apply pipeline and reports the result through the
    ///    reply oneshot.
    /// 4. Await reply with the same `SUBMIT_TIMEOUT` budget the tx
    ///    path uses.
    async fn submit_full_block(&self, block: ScalaFullBlock) -> Result<String, SubmitError> {
        // (1) JSON → canonical wire bytes.
        let decoded =
            ergo_rest_json::decode_scala_full_block(&block).map_err(|(reason, detail)| {
                SubmitError {
                    reason: reason.to_string(),
                    detail: Some(detail),
                }
            })?;

        // (2) PoW verify on the decoded header bytes. The header was
        //     already parsed inside decode_scala_header, but we
        //     re-parse here so we can call verify_pow_solution against
        //     a typed `Header`. The cost is one VLQ re-walk; the
        //     gain is that bad-PoW submissions never wake the action
        //     loop or touch the apply pipeline.
        let mut reader = VlqReader::new(&decoded.header_bytes);
        let header = read_header(&mut reader).map_err(|e| SubmitError {
            reason: "deserialize".to_string(),
            detail: Some(format!(
                "decoded header bytes did not re-parse cleanly: {e:?}",
            )),
        })?;
        verify_pow_solution(&header).map_err(|e| SubmitError {
            reason: "invalid_pow".to_string(),
            detail: Some(format!("PoW solution rejected: {e}")),
        })?;

        // (3) Ferry the four section byte vectors + reply oneshot to
        //     the action loop. Channel-full is non-blocking (503).
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let event = crate::peer_loop::PeerEvent::LocalFullBlock {
            header_bytes: decoded.header_bytes,
            bt_bytes: decoded.block_transactions_bytes,
            ext_bytes: decoded.extension_bytes,
            ad_proofs_bytes: decoded.ad_proofs_bytes,
            reply: reply_tx,
        };
        match self.event_tx.try_send(event) {
            Ok(()) => {}
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                return Err(SubmitError {
                    reason: "overloaded".to_string(),
                    detail: Some("event channel full; retry with backoff".to_string()),
                });
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                return Err(SubmitError {
                    reason: "shutting_down".to_string(),
                    detail: Some("node main loop has stopped accepting events".to_string()),
                });
            }
        }

        // (4) Await the action loop's reply.
        match tokio::time::timeout(SUBMIT_TIMEOUT, reply_rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_recv_err)) => Err(SubmitError {
                reason: "shutting_down".to_string(),
                detail: Some("main loop closed the reply channel".to_string()),
            }),
            Err(_elapsed) => Err(SubmitError {
                reason: "timeout".to_string(),
                detail: Some(format!(
                    "main loop did not reply within {} ms",
                    SUBMIT_TIMEOUT.as_millis(),
                )),
            }),
        }
    }

    async fn submit_transaction(
        &self,
        bytes: Vec<u8>,
        mode: SubmitMode,
    ) -> Result<String, SubmitError> {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let req = SubmitRequest {
            bytes,
            mode,
            reply: reply_tx,
        };
        // Channel-full is non-blocking: return 503 immediately rather
        // than queueing the axum task indefinitely.
        match self.tx.try_send(req) {
            Ok(()) => {}
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                return Err(SubmitError {
                    reason: "overloaded".to_string(),
                    detail: Some("submission channel full; retry with backoff".to_string()),
                });
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                return Err(SubmitError {
                    reason: "shutting_down".to_string(),
                    detail: Some("node main loop has stopped accepting submissions".to_string()),
                });
            }
        }
        match tokio::time::timeout(SUBMIT_TIMEOUT, reply_rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_recv_err)) => Err(SubmitError {
                // The reply oneshot was dropped without a send. The main
                // loop only does this on shutdown — surface it as
                // shutting_down rather than as a generic 5xx so the
                // client can distinguish from a transient overload.
                reason: "shutting_down".to_string(),
                detail: Some("main loop closed the reply channel".to_string()),
            }),
            Err(_elapsed) => Err(SubmitError {
                reason: "timeout".to_string(),
                detail: Some(format!(
                    "main loop did not reply within {} ms",
                    SUBMIT_TIMEOUT.as_millis()
                )),
            }),
        }
    }
}

// =====================================================================
// JSON inverse encoder
// =====================================================================
//
// Build canonical wire bytes from a Scala-shape `ScalaTransactionInput`.
// The decoder lives in the shared `ergo-rest-json` crate. The b4_*
// byte-parity oracle below remains here as the load-bearing test that
// pins Scala-vs-Rust encoding parity for the JSON submission path
// (covers ignore-vs-reject of synthetic sealing fields, empty-AdProofs
// handling, hex casing, BigInt rejection, and input-cap / depth-cap
// bounds).

pub use ergo_rest_json::decode::{decode_scala_transaction, DESERIALIZE, NON_CANONICAL};

#[cfg(test)]
mod tests;
