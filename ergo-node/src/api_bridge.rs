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
}

impl ShutdownAdmin {
    pub fn new(notify: Arc<Notify>) -> Self {
        Self { notify }
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
}

impl SnapshotReadState {
    pub fn new(handle: SnapshotHandle, identity: IdentitySlot, host_paths: HostPaths) -> Self {
        Self {
            handle,
            identity,
            host_paths,
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
