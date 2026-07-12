//! `NodeState` — the runtime god-struct threaded through every
//! action-loop handler. Owns the store, the sync coordinator +
//! executor, the peer manager + per-peer outbound channels, the
//! mempool, the snapshot publisher, the wallet apply hook, and every
//! other piece of mutable runtime state the loop needs.
//!
//! `PeerRegistry` is the inner map of `PeerId → PeerRuntime` plus the
//! `try_send(peer, code, payload)` accessor used by `send_to_peer`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use ergo_indexer::IndexerHandle;
use ergo_mempool::Mempool;
use ergo_p2p::framing::MessageFrame;
use ergo_p2p::handshake::Handshake;
use ergo_p2p::peer::{PeerId, SyncVersion};
use ergo_p2p::peer_manager::PeerManager;
use ergo_p2p::throttle::ThroughputLimiter;
use ergo_state::StateBackendKind;
use ergo_sync::coordinator::SyncCoordinator;
use ergo_sync::executor::SyncExecutor;
use tokio::sync::mpsc;

use crate::anchor_map::{self, RestPeers};
use crate::anchor_scheduler::AnchorScheduler;
use crate::notifier::MempoolNotifier;
use crate::peer_loop::PeerEvent;
use crate::snapshot::SnapshotPublisher;

use super::snapshot_state;
use super::wallet_bridge;

// ---- Peer registry ----

pub(crate) struct PeerRuntime {
    pub(super) sync_version: SyncVersion,
    pub(super) outbound_tx: mpsc::Sender<MessageFrame>,
}

pub(crate) struct PeerRegistry {
    pub(super) peers: HashMap<PeerId, PeerRuntime>,
}

impl PeerRegistry {
    pub(super) fn new() -> Self {
        Self {
            peers: HashMap::new(),
        }
    }

    /// Send a message to a peer. Returns false if channel was full
    /// (peer will be disconnected by the caller).
    pub(super) fn try_send(&self, peer: &PeerId, code: u8, payload: Vec<u8>) -> bool {
        if let Some(runtime) = self.peers.get(peer) {
            runtime
                .outbound_tx
                .try_send(MessageFrame { code, payload })
                .is_ok()
        } else {
            false
        }
    }

    pub(super) fn remove(&mut self, peer: &PeerId) {
        self.peers.remove(peer);
    }
}

// ---- Node state ----

pub(crate) struct NodeState {
    /// State backend, routed through the `StateBackendKind` enum so a
    /// later phase can hold a digest verifier here. Today it is always
    /// the `Utxo` variant (the Mode 5 boot gate stays closed); access
    /// dispatches through the enum's trait impls, and UTXO-only
    /// subsystems reach the concrete store via `as_utxo()`.
    pub(super) store: StateBackendKind,
    pub(super) coordinator: SyncCoordinator,
    pub(super) executor: SyncExecutor,
    pub(super) peer_manager: PeerManager,
    pub(super) registry: PeerRegistry,
    pub(super) event_tx: mpsc::Sender<PeerEvent>,
    pub(super) magic: [u8; 4],
    pub(super) our_handshake: Handshake,
    // ---- mempool ----
    // Held on the main event-loop task so mutations are single-writer
    // and no locking is needed. The notifier polls committed state on
    // a 250ms tick; on tip change it calls `on_tip_change`. P2P
    // transaction admission goes through `Mempool::process`.
    pub(super) mempool: Mempool,
    /// Shadow-validation outcome state (`Some` only when `[shadow]`
    /// enabled): written by the watch task, projected into the snapshot
    /// (status/metrics) and the operator event differ each publish.
    pub(super) shadow: Option<std::sync::Arc<super::shadow_watch::ShadowState>>,
    pub(super) mempool_notifier: MempoolNotifier,
    // ---- throughput limiter ----
    // Per-peer sliding-window cap (1000 msg/sec, 2 MB/sec over 10s).
    // Consulted on every inbound frame; over-limit frames drop and
    // emit a Misbehavior penalty.
    pub(super) throttle: ThroughputLimiter,
    // Last-observed active voted parameters / validation settings, used
    // to detect epoch-boundary changes that must trigger mempool
    // revalidation. Compared against `store.active_params()` /
    // `store.validation_settings()` after each tip change; if the pair
    // differs, every active mempool tx is demoted into the
    // revalidation queue and re-admitted under the new rules.
    pub(super) last_seen_active_params: ergo_validation::ActiveProtocolParameters,
    pub(super) last_seen_validation_settings: ergo_validation::ErgoValidationSettings,
    // --- operator API snapshot publisher ---
    // Built once per sync_tick; the API task reads via a lock-free
    // ArcSwap. Construction is bounded — see snapshot::build_snapshot.
    pub(super) snapshot_publisher: Option<SnapshotPublisher>,
    // --- `/api/v1/identity` live-refresh slot ---
    // The action loop rebuilds `ApiIdentity` from `identity_inputs`
    // plus current store state whenever a bootstrap transition
    // (install_snapshot_state, apply_popow_proof) changes the
    // sentinel or provenance; the new value is published into
    // `identity_slot`. The API bridge reads via lock-free
    // `ArcSwap::load`.
    pub(super) identity_inputs: crate::node::identity::IdentityInputs,
    pub(super) identity_slot: crate::api_bridge::IdentitySlot,
    // --- heartbeat bookkeeping ---
    pub(super) last_beat: Instant,
    /// When the operator `heartbeat tick` INFO line was last emitted.
    /// The line fires on sync progress; when idle it falls back to one
    /// emission per `HEARTBEAT_IDLE_INTERVAL` so a synced node stays a
    /// liveness pulse, not a per-second flood. Distinct from `last_beat`
    /// (which advances every tick to keep the per-tick perf-timing rates
    /// honest).
    pub(super) last_beat_emit: Instant,
    pub(super) last_beat_height: u32,
    pub(super) last_beat_headers: u32,
    // Sync-S0 rename for truth: req_messages counts RequestModifier messages
    // sent (1 per batch, 1-2 per round under current coordinator behavior).
    // req_ids counts section IDs across all RequestModifier payloads (what
    // we actually asked the peer for). Bucketed-multi-peer (S1) will make
    // the distinction matter — a 3-peer fanout emits 3+ messages for the
    // same ID set.
    pub(super) req_messages_total: u64,
    pub(super) req_ids_total: u64,
    pub(super) sections_received_total: u64,
    /// Observability counters surfaced as Prometheus counters via the
    /// operator-API snapshot (`ApiStatus` → `/metrics`). They make
    /// inbound mempool-tx gossip diagnosable at the default `info` log
    /// level, where the per-tx admit/reject/request traces only fire at
    /// `debug`. Session-scoped (reset on restart; `rate()` handles that).
    ///
    /// Count of unconfirmed-tx ids actually REQUESTED from peers in
    /// response to a tx-typed `Inv` — the POST-dedupe count returned by
    /// `request_transactions` (after it drops already-in-flight/failed ids
    /// and applies the per-peer cap), NOT the raw advertised set, so it
    /// matches one-for-one the `RequestModifier`s actually sent. Bumped in
    /// `messaging::handle_message`'s tx-Inv→request branch; surfaced in
    /// `ApiStatus`/Prometheus.
    pub(super) mempool_tx_requested_total: u64,
    /// Count of peer-sourced (`TxSource::Peer`) txs ADMITTED to the
    /// mempool. Bumped on an `Admitted` outcome in
    /// `admission::admit_transaction` (peer path only — API/Wallet
    /// admissions are not counted).
    pub(super) mempool_peer_tx_admitted_total: u64,
    /// Count of peer-sourced (`TxSource::Peer`) txs REJECTED by admission.
    /// Bumped on a `Rejected` outcome in `admission::admit_transaction`
    /// (peer path only — API/Wallet rejections are not counted).
    pub(super) mempool_peer_tx_rejected_total: u64,
    pub(super) last_beat_req_messages: u64,
    pub(super) last_beat_req_ids: u64,
    pub(super) last_beat_sections_received: u64,
    /// Last time `try_dial_peers` actually fired a dial cycle (vs. an
    /// early-return). Drives the adaptive cadence: while outbound
    /// deficit is large (cold start / IBD) the dial loop runs every
    /// 5s; once we're within `DIAL_FAST_THRESHOLD` of the outbound
    /// target it backs off to one cycle every 30s. Same gentleness
    /// guarantee as the old fixed 30s, with no cold-start penalty.
    pub(super) last_dial_at: Instant,
    /// Timestamp of the most recent periodic-gossip `GetPeers` send.
    /// Gates the gossip path so we ask one random connected peer for
    /// its peer list every `GOSSIP_INTERVAL` — independent of the
    /// dial-tick's deficit gate, so the gossip fires even when our
    /// outbound pool is healthy. Mirrors Scala `PeerSynchronizer`.
    pub(super) last_gossip_at: Instant,
    /// Cheap clone of the indexer handle so the slice-2 memory sampler
    /// can read `indexed_height`, `status`, and redb evictions without
    /// going through the API or owning a separate read txn. `None` when
    /// the indexer is disabled or boot was halted. The handle is `Clone`
    /// (Arc-wrapped), so this duplicate doesn't extend the redb file-lock
    /// lifetime past `shutdown_cleanly()`.
    pub(super) indexer_handle: Option<IndexerHandle>,
    /// Header anchor map (Step B — observation only). Populated by a
    /// background task that polls REST URLs from connected peers and
    /// queries `/blocks/at/{h}`. Heartbeat reads `take_counters()`
    /// each tick. Currently unused by sync — Step C wires it into
    /// per-peer SyncInfo crafting.
    pub(super) anchor_map: anchor_map::AnchorMap,
    /// REST URLs advertised by currently-connected peers, keyed by
    /// `PeerId`. Populated only AFTER `complete_handshake` succeeds
    /// (so a rejected handshake never adds a URL) and removed on
    /// every disconnect path so the map size is bounded by the
    /// connected peer count. `std::sync::RwLock` (sync) because the
    /// action loop holds the lock only briefly and the background
    /// builder snapshots-then-releases — no long-held async borrows.
    pub(super) rest_peer_urls: std::sync::Arc<std::sync::RwLock<RestPeers>>,
    /// Latched cancellation channel for the anchor builder. The
    /// `watch::Sender` is held by `RunHandle` (drop or explicit
    /// shutdown sends `true`); the builder holds a `Receiver` and
    /// checks the latched value at every loop boundary plus selects
    /// on `changed()` between awaits, so cancellation is never
    /// missed. `watch` (vs `Notify`) because the value is durable —
    /// a cancel signaled before the receiver awaits is still
    /// observed when it does.
    pub(super) anchor_builder_cancel_tx: tokio::sync::watch::Sender<bool>,
    /// Step C — per-peer SyncInfo crafting. Active only when
    /// `enable_anchor_scheduler == true` AND the peer advertised
    /// `RestApiUrl`. Holds `(anchor_height, peer, when)` claims so
    /// no two peers race on the same anchor.
    pub(super) anchor_scheduler: AnchorScheduler,
    /// Step C feature flag mirrored from `NodeConfig` so the dispatch
    /// loop can short-circuit without re-reading config.
    pub(super) enable_anchor_scheduler: bool,
    /// Live `best_header_height` cursor handed to the anchor builder
    /// so it can scan frontier-first (start each pass at the current
    /// tip rather than at h=0). Updated by the heartbeat tick. The
    /// builder reads it via `Ordering::Relaxed` — staleness within
    /// one heartbeat is fine; the next pass picks up.
    pub(super) anchor_tip_cursor: std::sync::Arc<std::sync::atomic::AtomicU32>,
    /// Mode 2 snapshot-server cache. Holds at most one
    /// `SnapshotServer` built at a recent Scala-aligned height. Used
    /// by the message dispatcher to answer `GetSnapshotsInfo`,
    /// `GetManifest`, and `GetUtxoSnapshotChunk`. Always empty in
    /// Mode 6 (no UTXO state); populated by the block-apply path at
    /// snapshot heights in part 2f.
    pub(super) snapshot_state: snapshot_state::SnapshotState,
    /// Mode 2 consume-side discovery reducer. Tracks per-peer
    /// `SnapshotsInfo` responses (code 77) and applies Scala's
    /// quorum selection rule. Stays at `BootstrapState::Idle` for
    /// Mode 1/3/5/6 nodes (no consume-side bootstrap in progress).
    /// Manifest download (part 2g) reads this to learn when a
    /// quorum has been reached.
    pub(super) snapshot_bootstrap: ergo_sync::snapshot_bootstrap::SnapshotBootstrap,
    /// NiPoPoW bootstrap state machine (Part 2 sub-phase 14.6).
    /// `None` for nodes that didn't enable `[node] nipopow_bootstrap`
    /// or have already exited the popow window (state == Applied
    /// AND store best_header_height > 0). Stays `Some` for the
    /// active bootstrap window so per-tick polling can drive
    /// request fan-out, proof apply, and the bounded forward catchup
    /// kickoff. Read by `drive_popow_bootstrap` (sync_tick.rs) and
    /// `handle_inbound_popow_proof` (messaging.rs) — both follow-up
    /// commits.
    #[allow(dead_code)]
    pub(super) popow_bootstrap: Option<ergo_sync::popow_bootstrap::PopowBootstrap>,
    /// Mirror of `config.utxo_bootstrap`. The outbound discovery
    /// fan-out (sub-phase 2f-3) checks this flag at each sync_tick
    /// to decide whether to send `GetSnapshotsInfo` (code 76). Will
    /// always be `false` until sub-phase 2j lifts the activation
    /// gate, at which point a Mode 2-configured operator setting
    /// `utxo_bootstrap = true` flips this to `true` at boot.
    pub(super) utxo_bootstrap_enabled: bool,
    /// Mode 2 chunk-download state machine. `Some` only between
    /// `ManifestVerified` (chunks list known) and reconstruction-
    /// complete (bytes handed to the reconstructor). `None`
    /// outside this window — initialization happens lazily on the
    /// first sync_tick after the manifest verifies.
    pub(super) chunk_assembly: Option<ergo_sync::snapshot_bootstrap::ChunkAssembly>,
    /// Output of 2h-1's reconstructor. Held here once chunk
    /// download finishes; consumed by 2i's state-install path.
    /// `Some` only briefly — between `is_complete` on the chunk
    /// assembly and the next sync_tick that runs install.
    pub(super) reconstructed_tree: Option<ergo_state::avl::snapshot_codec::ReconstructedTree>,
    /// Verified manifest bytes stashed during chunk-assembly init
    /// (taken from `SnapshotBootstrap`), held until reconstruction
    /// runs. `take()`'d at reconstruction time so it doesn't
    /// linger past 2h. Kept here (rather than in
    /// `SnapshotBootstrap` or `ChunkAssembly`) because both of
    /// those mark themselves consumed when bytes leave, but the
    /// reconstructor needs the manifest bytes AFTER all chunks
    /// arrive — a separate stash decouples the lifecycles.
    pub(super) pending_manifest_bytes: Option<Vec<u8>>,
    /// Wall-clock Unix-ms timestamp of the first sync_tick that
    /// observed `utxo_bootstrap_enabled && best_full_block_height == 0`.
    /// Used by the operator-API snapshot to render an "elapsed" clock
    /// on the bootstrap dashboard panel. Set once, never reset until
    /// the node restarts (post-install runs still report the original
    /// start so operators see the full lifecycle in catch-up too).
    pub(super) bootstrap_started_unix_ms: Option<u64>,
    /// True if the snapshot-bootstrap reducer has been observed in any
    /// non-`Idle` state during this process lifetime. Gates the
    /// "post-install catch-up" dashboard panel: without this flag, any
    /// Mode 2-configured node that restarts while running behind tip
    /// would render the bootstrap panel even though no bootstrap is
    /// happening. Reset only by restart; once we've genuinely engaged
    /// the bootstrap flow this session, the catch-up panel remains a
    /// valid surface until the node reaches tip.
    pub(super) bootstrap_was_active_this_session: bool,
    /// Production wallet apply hook. `Some` when the node runs with the
    /// REST API enabled (which implies wallet subsystem boot). Called
    /// from `sync_tick` after each block apply to keep wallet tables
    /// up-to-date without coupling the sync layer to the wallet.
    /// `None` in no-API / headers-only mode.
    pub(super) wallet_hook: Option<Arc<wallet_bridge::WalletStateHook>>,
    /// Mirrors "mining wiring exists" for the snapshot emitter (the wiring
    /// itself lives on the action loop, out of the emitter's reach).
    pub(super) mining_enabled: bool,
    /// Active mempool priority-weight function converted at boot to its
    /// wire form. Snapshot ticks read this directly — no per-tick
    /// `&str` → enum conversion. Surfaced on
    /// `/api/v1/mempool/transactions.weight_function`.
    pub(super) api_weight_function: ergo_api::types::ApiWeightFunction,
    /// Per-tip cache for the dashboard's recent-blocks tail. Building it
    /// walks up to 32 full-block headers plus their section reads, which
    /// is too heavy to redo on every snapshot tick; the tail only changes
    /// when the full-block tip advances, so the publisher recomputes only
    /// when `best_full_block_id` differs from the cached tip and otherwise
    /// re-publishes the cached `Arc`. `None` before the first publish.
    pub(super) recent_blocks_cache: Option<crate::snapshot::RecentBlocksCache>,
    /// Address-prefix network byte (mainnet/testnet), used at
    /// snapshot-assembly time to derive `ApiRecentBlock.miner_address`
    /// from the header's Autolykos solution pk.
    pub(super) network: ergo_ser::address::NetworkPrefix,
    /// First-block-deliverer ring: `header_id → (first peer, instant)`.
    /// Records the FIRST peer that delivered each recently-validated
    /// header (its `Modifier` carried the header bytes we accepted), so
    /// an operator can attribute a block → peer → pool. Bounded
    /// (FIFO-evicted at `FirstDelivererRing::CAP`), first-deliverer-only,
    /// pure observability — never feeds sync / consensus / scoring.
    /// Read at snapshot build time to populate `ApiRecentBlock.delivered_by`.
    pub(super) first_deliverer_ring: super::first_deliverer::FirstDelivererRing,
    /// Operator event feed (bounded ring) + the previous-tick observations
    /// its differ compares against. Fed once per snapshot emit; pure
    /// observability — never feeds sync / consensus / scoring.
    pub(super) event_feed: super::event_feed::EventFeedRing,
    pub(super) event_feed_prev: super::event_feed::FeedPrev,
    /// Postmortem reorg ring (64 / 7d) — diagnostics + metrics, not the
    /// coarse glanceable feed.
    pub(super) reorg_history: super::reorg_history::ReorgHistory,
    /// Seq-keyed cache of the projected `ApiNodeEvents` Arc: rebuilt only
    /// when the ring's latest seq advances, so a quiet tick re-publishes
    /// the same allocation (mirrors the recent-blocks per-tip cache).
    pub(super) event_feed_projection: Option<(u64, std::sync::Arc<ergo_api::types::ApiNodeEvents>)>,
    /// `(total, retained_len)`-keyed cache of the diagnostics reorg history
    /// Arc — rebuilt only when push/age-prune changes the ring.
    pub(super) reorg_history_projection: Option<(
        (u64, usize),
        std::sync::Arc<ergo_api::types::ApiReorgHistory>,
    )>,
}
