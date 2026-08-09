//! Per-peer sync state and preliminary chain-status comparison.
//!
//! Provides `PeerChainStatus`, the `SyncState` download-window
//! tracker, and a height-based chain comparison function. The full
//! sync coordinator (continuation header application from
//! `SyncInfoV2`, sync action emission, peer-subset SyncInfo
//! selection, and integration with header validation + `ergo-state`)
//! lives in `ergo-sync`; this module only carries the per-peer state
//! surface the coordinator drives.
//!
//! # SyncInfo send cadence (Scala parity)
//!
//! Scala's proactive SyncInfo fanout is **not** 100 ms. The 100 ms
//! constant `PerPeerSyncLockTime` in `ErgoNodeViewSynchronizer` is a
//! **receive-side** anti-spam filter (`processSync` drops inbound
//! SyncInfo arriving within 100 ms of the previous one). The real
//! send-side knobs are:
//!
//! * [`MIN_SYNC_INTERVAL`] (20 s) — per-peer floor between proactive
//!   SyncInfo sends (`ErgoSyncTracker.MinSyncInterval`)
//! * [`SYNC_THRESHOLD`] (1 min) — peers whose last send is older are
//!   "outdated" and get priority in `peersToSyncWith`
//! * [`CLEAR_THRESHOLD`] (3 min) — stalled peer statuses reset to
//!   `Unknown`
//! * Global tick: [`DEFAULT_SYNC_INTERVAL`] (5 s IBD) /
//!   [`DEFAULT_SYNC_INTERVAL_STABLE`] (15 s) from `application.conf`
//!
//! Reciprocal SyncInfo replies to inbound SyncInfo (and the
//! post-header-progress kick) bypass the 20 s floor — that pull-model
//! response path is what keeps a 1–2 peer IBD pipeline fed.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use tracing::info;

use crate::peer::PeerId;

/// Status of a peer's chain relative to ours.
/// Verified against PeerChainStatus.scala.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerChainStatus {
    /// Peer has the same tip as us.
    Equal,
    /// Peer's best block is on our chain but behind us — we have more.
    Younger,
    /// Peer appears to be ahead of us — they have blocks we don't.
    Older,
    /// Peer is on a fork — we share a common ancestor but diverge.
    Fork,
    /// We don't have enough information to determine status.
    Unknown,
    /// Peer's chain info doesn't make sense (potential misbehavior).
    Nonsense,
}

/// Default download window: the number of blocks ahead of the validated tip
/// we'll keep pending download. Keeps the pipeline fed without unbounded
/// prefetch. TOML-configurable via `[sync] download_window`.
///
/// Raised from 192 (Scala parity default) to 384 to better saturate a
/// single peer when multi-peer discovery is not yet active.
pub const DOWNLOAD_WINDOW: usize = 384;

/// Safety clamp applied inside [`SyncState::new_with_window`] to prevent
/// pathologically large windows from silently truncating during
/// `usize -> u32` height arithmetic downstream.
///
/// Matches `MAX_DOWNLOAD_WINDOW` in `ergo-node/src/config.rs` — changing
/// one without the other creates a config/library ceiling split.
pub const MAX_DOWNLOAD_WINDOW_CLAMP: usize = 100_000;

/// Mainnet-default header-freshness threshold: 120 s/block × 100
/// blocks = 12_000_000 ms (200 minutes). Used by [`SyncState::new`]
/// and [`SyncState::new_with_window`] for callers that don't supply
/// network-aware timing. Production code constructs `SyncState` via
/// [`SyncState::with_timing`] and passes `chain_spec.block_timing`'s
/// computed value instead, so testnet syncs use 45_000 × 800 =
/// 36_000_000 ms.
const DEFAULT_HEADER_FRESHNESS_THRESHOLD_MS: u64 = 12_000_000;

/// Minimum interval between **proactive** SyncInfo sends to the same
/// peer. Scala `ErgoSyncTracker.MinSyncInterval = 20.seconds`.
/// Reciprocal replies to inbound SyncInfo intentionally ignore this
/// floor (see module docs).
pub const MIN_SYNC_INTERVAL: Duration = Duration::from_secs(20);

/// A peer whose last SyncInfo send is older than this is "outdated"
/// and is preferred by `peersToSyncWith`. Scala
/// `ErgoSyncTracker.SyncThreshold = 1.minute`.
pub const SYNC_THRESHOLD: Duration = Duration::from_secs(60);

/// After this much silence since the last SyncInfo **send**, the
/// peer's chain status is cleared back to `Unknown`. Scala
/// `ErgoSyncTracker.ClearThreshold = 3.minutes`.
pub const CLEAR_THRESHOLD: Duration = Duration::from_secs(180);

/// Default global SyncInfo broadcast cadence while in IBD. Scala
/// `application.conf` `scorex.network.syncInterval = 5s`.
pub const DEFAULT_SYNC_INTERVAL: Duration = Duration::from_secs(5);

/// Default global SyncInfo broadcast cadence once synced (stable
/// regime). Scala mainnet `syncIntervalStable = 15s` (testnet uses
/// 30s; we expose the knob under `[sync]` so operators can match).
pub const DEFAULT_SYNC_INTERVAL_STABLE: Duration = Duration::from_secs(15);

/// Sync state for header-first sync.
#[derive(Debug)]
pub struct SyncState {
    /// Headers we know about but haven't downloaded blocks for yet.
    /// Ordered by height (front = lowest).
    pending_blocks: VecDeque<PendingBlock>,
    /// Best header height we're aware of (from any peer).
    best_known_header_height: u32,
    /// Our best validated full block height (from the state store).
    best_full_block_height: u32,
    /// Last time we sent a SyncInfo message to each peer, keyed by
    /// PeerId. Drives the per-peer [`MIN_SYNC_INTERVAL`] floor for
    /// proactive fanout and the [`SYNC_THRESHOLD`] /
    /// [`CLEAR_THRESHOLD`] aging used by subset selection. Reciprocal
    /// SyncInfo replies (inbound SyncInfo / post-header-progress)
    /// also stamp this map. Pruned in `forget_peer_sync` on
    /// disconnect to keep the map bounded by live peers.
    last_sync_sent: HashMap<PeerId, Instant>,
    /// Minimum interval between **proactive** SyncInfo sends to the
    /// same peer. Defaults to [`MIN_SYNC_INTERVAL`] (20 s). Not to be
    /// confused with Scala's receive-side `PerPeerSyncLockTime`
    /// (100 ms anti-spam filter on inbound SyncInfo).
    sync_interval: Duration,
    /// Whether the header chain is synced with the network.
    /// Block section downloads only begin after this flips to true.
    /// Matches Scala's isHeadersChainSynced (FullBlockPruningProcessor.scala).
    headers_chain_synced: bool,
    /// How many blocks ahead of best_full_block to keep pending for
    /// download. Default is [`DOWNLOAD_WINDOW`]; TOML-configurable via
    /// `[sync] download_window`.
    download_window: usize,
    /// Network-derived threshold for "is this header recent enough that
    /// the chain is synced." Computed as `block_interval *
    /// header_chain_diff`. Constant for the lifetime of `SyncState`.
    header_freshness_threshold_ms: u64,
    /// Mode 3 prune sentinel (`STATE_META[minimal_full_block_height]`),
    /// mirrored from the store. `0` = no pruning active (archive,
    /// Mode 6, or fresh store before first eviction). The coordinator
    /// reads this to skip section-request emission for headers whose
    /// height is below the sentinel — the request-side counterpart to
    /// the store's own pruning of sections below this height (Scala
    /// parity: we'd otherwise request sections we'd immediately evict
    /// on apply). Updated by the boot/sync integration after store
    /// apply / open.
    prune_sentinel: u32,
}

/// A block whose header we have but haven't yet downloaded/applied.
#[derive(Debug, Clone)]
pub struct PendingBlock {
    pub height: u32,
    pub header_id: [u8; 32],
}

impl SyncState {
    /// Construct with the default download window ([`DOWNLOAD_WINDOW`])
    /// and the mainnet header-freshness threshold. Production code
    /// running testnet should use [`Self::with_timing`] so the threshold
    /// reflects the network's actual block interval.
    pub fn new(best_full_block_height: u32) -> Self {
        Self::new_with_window(best_full_block_height, DOWNLOAD_WINDOW)
    }

    /// Construct with an explicit download window. Uses the mainnet
    /// header-freshness threshold (see [`Self::new`]).
    ///
    /// The window is clamped to `[1, MAX_DOWNLOAD_WINDOW_CLAMP]` so
    /// that downstream `usize -> u32` conversions in the pending-block
    /// math can't silently truncate. Callers that need a hard limit
    /// check (e.g. `NodeConfig::load`) should reject out-of-bounds
    /// values before reaching this constructor; this clamp is a
    /// belt-and-braces safety net for direct library users.
    pub fn new_with_window(best_full_block_height: u32, download_window: usize) -> Self {
        Self::with_timing(
            best_full_block_height,
            download_window,
            DEFAULT_HEADER_FRESHNESS_THRESHOLD_MS,
        )
    }

    /// Construct with an explicit download window AND
    /// network-derived header-freshness threshold (typically
    /// `chain_spec.block_timing.header_freshness_threshold_ms()`).
    pub fn with_timing(
        best_full_block_height: u32,
        download_window: usize,
        header_freshness_threshold_ms: u64,
    ) -> Self {
        Self {
            pending_blocks: VecDeque::new(),
            best_known_header_height: best_full_block_height,
            best_full_block_height,
            last_sync_sent: HashMap::new(),
            // Proactive per-peer SyncInfo floor (Scala MinSyncInterval).
            // Reciprocal replies bypass this via the coordinator's
            // syncSendNeeded path; do not lower this to "feed the
            // pipeline" — that starves other peers with broadcast spam
            // and misattributes Scala's receive-side 100 ms filter.
            sync_interval: MIN_SYNC_INTERVAL,
            headers_chain_synced: false,
            download_window: download_window.clamp(1, MAX_DOWNLOAD_WINDOW_CLAMP),
            header_freshness_threshold_ms,
            prune_sentinel: 0,
        }
    }

    /// Mirror the Mode 3 prune sentinel from the store. The
    /// coordinator's request-side gate reads this to skip section
    /// requests for headers below the sentinel — we'd just evict
    /// those sections on apply.
    /// Integration layer (`ergo-node::boot.rs` and sync_tick after
    /// each store apply) calls this; archive / Mode 6 callers
    /// leave it at the default `0` so the gate is inert.
    pub fn set_prune_sentinel(&mut self, sentinel: u32) {
        self.prune_sentinel = sentinel;
    }

    /// Current mirrored prune sentinel (`0` = no pruning active).
    pub fn prune_sentinel(&self) -> u32 {
        self.prune_sentinel
    }

    /// The active download window for this state instance.
    pub fn download_window(&self) -> usize {
        self.download_window
    }

    /// Update our best full block height (after applying a block).
    pub fn set_best_full_block(&mut self, height: u32) {
        self.best_full_block_height = height;
        // Prune all pending blocks at or below the new height.
        // Uses retain instead of front-popping to handle any insertion order.
        self.pending_blocks.retain(|b| b.height > height);
    }

    /// Update best known header height (from validated headers).
    pub fn set_best_known_header(&mut self, height: u32) {
        if height > self.best_known_header_height {
            self.best_known_header_height = height;
        }
    }

    /// Add a pending block (header validated, block body needed).
    /// Maintains sorted order by height (front = lowest).
    pub fn add_pending_block(&mut self, height: u32, header_id: [u8; 32]) {
        if height <= self.best_full_block_height {
            return;
        }
        if self.pending_blocks.iter().any(|b| b.header_id == header_id) {
            return;
        }
        // Insert in sorted position by height.
        let pos = self.pending_blocks.partition_point(|b| b.height < height);
        self.pending_blocks
            .insert(pos, PendingBlock { height, header_id });
    }

    /// Retain only pending blocks accepted by `keep`.
    pub fn retain_pending_blocks(&mut self, mut keep: impl FnMut(&PendingBlock) -> bool) {
        self.pending_blocks.retain(|b| keep(b));
    }

    /// Iterate all pending blocks (not filtered by window). Used by the HOL
    /// hedge path to locate the exact next sequential height.
    pub fn pending_blocks_iter(&self) -> impl Iterator<Item = &PendingBlock> {
        self.pending_blocks.iter()
    }

    /// Observability accessor: number of blocks in the sliding
    /// download window.
    pub fn pending_blocks_len(&self) -> usize {
        self.pending_blocks.len()
    }

    /// Get blocks that should be downloaded next (within the download window).
    pub fn blocks_to_download(&self) -> Vec<&PendingBlock> {
        let limit = self
            .best_full_block_height
            .saturating_add(self.download_window as u32);
        self.pending_blocks
            .iter()
            .filter(|b| b.height <= limit)
            .collect()
    }

    /// Whether we're in IBD (header chain is significantly ahead of full blocks).
    pub fn is_ibd(&self) -> bool {
        self.best_known_header_height > self.best_full_block_height + 10
    }

    /// Whether a **proactive** SyncInfo send to `peer` is allowed now
    /// under [`MIN_SYNC_INTERVAL`]. True if we've never asked this peer
    /// or if `sync_interval` has elapsed since the last send.
    ///
    /// Reciprocal replies to inbound SyncInfo must **not** consult this
    /// — Scala's `sendSyncToPeer` stamps `lastSyncSentTime` but does not
    /// gate on `MinSyncInterval` (only `peersToSyncWith` does).
    pub fn should_send_sync(&self, peer: PeerId, now: Instant) -> bool {
        match self.last_sync_sent.get(&peer) {
            Some(t) => now.duration_since(*t) >= self.sync_interval,
            None => true,
        }
    }

    /// True when we have never sent SyncInfo to `peer`, or the last
    /// send is older than [`SYNC_THRESHOLD`]. Scala
    /// `ErgoSyncTracker.notSyncedOrOutdated`.
    pub fn not_synced_or_outdated(&self, peer: PeerId, now: Instant) -> bool {
        match self.last_sync_sent.get(&peer) {
            None => true,
            Some(t) => now.duration_since(*t) > SYNC_THRESHOLD,
        }
    }

    /// True when the last SyncInfo send to `peer` is older than
    /// [`SYNC_THRESHOLD`]. Peers never contacted are **not** outdated
    /// (they are simply unknown) — matches Scala `outdatedPeers`.
    pub fn is_outdated(&self, peer: PeerId, now: Instant) -> bool {
        self.last_sync_sent
            .get(&peer)
            .is_some_and(|t| now.duration_since(*t) > SYNC_THRESHOLD)
    }

    /// True when the last SyncInfo send to `peer` is older than
    /// [`CLEAR_THRESHOLD`]. Used to reset stalled chain-status entries
    /// back to `Unknown` (Scala `clearOldStatuses`).
    pub fn status_clear_due(&self, peer: PeerId, now: Instant) -> bool {
        self.last_sync_sent
            .get(&peer)
            .is_some_and(|t| now.duration_since(*t) > CLEAR_THRESHOLD)
    }

    /// Record that we sent a SyncInfo message to `peer`.
    pub fn mark_sync_sent(&mut self, peer: PeerId, now: Instant) {
        self.last_sync_sent.insert(peer, now);
    }

    /// Drop the per-peer SyncInfo timestamp on disconnect so the map
    /// stays bounded by live peer count. Idempotent.
    pub fn forget_peer_sync(&mut self, peer: &PeerId) {
        self.last_sync_sent.remove(peer);
    }

    /// Check if a header's timestamp indicates the header chain is
    /// synced. Matches Scala: `header.isNew(blockInterval *
    /// headerChainDiff)`. Once synced, stays synced (one-way latch).
    /// Uses the per-network threshold stored on the
    /// [`SyncState`] at construction time.
    pub fn check_headers_synced(&mut self, header_timestamp_ms: u64) {
        if self.headers_chain_synced {
            return;
        }
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        if now_ms.saturating_sub(header_timestamp_ms) < self.header_freshness_threshold_ms {
            self.headers_chain_synced = true;
            info!("headers chain synced — starting block downloads");
        }
    }

    pub fn headers_chain_synced(&self) -> bool {
        self.headers_chain_synced
    }

    /// Flip the one-way headers-chain-synced latch from the
    /// "caught up to peers" fallback path (see
    /// `SyncCoordinator::try_mark_caught_up_to_peers`). Distinct from the
    /// edge-triggered freshness flip in [`Self::check_headers_synced`]:
    /// this lets block download start on an idle/stale tip that the
    /// `header.isNew` freshness test can never recognize. Idempotent;
    /// only ever sets true.
    pub fn mark_headers_chain_synced(&mut self) {
        self.headers_chain_synced = true;
    }

    /// Force headers_chain_synced for tests with old mainnet headers.
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn set_headers_chain_synced(&mut self) {
        self.headers_chain_synced = true;
    }
    pub fn best_full_block_height(&self) -> u32 {
        self.best_full_block_height
    }
    pub fn best_known_header_height(&self) -> u32 {
        self.best_known_header_height
    }
    pub fn pending_count(&self) -> usize {
        self.pending_blocks.len()
    }
}

/// Compare BE `BigUint` score byte slices (no leading-zero padding).
/// Longer length ⇒ larger value, matching `BigUint::to_bytes_be`.
fn score_cmp(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
    match a.len().cmp(&b.len()) {
        std::cmp::Ordering::Equal => a.cmp(b),
        other => other,
    }
}

/// SyncInfo V1 comparison — Scala `ErgoHistoryReader.compareV1`.
///
/// Tip may be at either end of `peer_header_ids`: Scala emits
/// oldest-first (tip = last), Rust outbound is newest-first (tip =
/// first). Equal if our tip matches either end; Older if our tip is
/// elsewhere in their list; Fork if we know any of their ids; else Older
/// (far ahead / unknown).
///
/// `we_contain` is any known header (not only best-chain) — matches
/// Scala `historyStorage.contains`.
pub fn compare_sync_info_v1(
    peer_header_ids: &[[u8; 32]],
    our_best_id: &[u8; 32],
    we_contain: impl Fn(&[u8; 32]) -> bool,
) -> PeerChainStatus {
    if peer_header_ids.is_empty() {
        // They have nothing; we have a tip ⇒ Younger. (Empty/empty is
        // handled by the caller when we also have no tip.)
        return PeerChainStatus::Younger;
    }
    let tip_first = peer_header_ids.first().copied();
    let tip_last = peer_header_ids.last().copied();
    if tip_first == Some(*our_best_id) || tip_last == Some(*our_best_id) {
        return PeerChainStatus::Equal;
    }
    if peer_header_ids.iter().any(|id| id == our_best_id) {
        return PeerChainStatus::Older;
    }
    if peer_header_ids.iter().any(&we_contain) {
        PeerChainStatus::Fork
    } else {
        // No overlap — assume far ahead (Scala compareV1).
        PeerChainStatus::Older
    }
}

/// Inputs for [`compare_sync_info_v2`] (grouped to keep the call site
/// readable and under clippy's argument cap).
pub struct SyncInfoV2Compare<'a> {
    pub peer_tip_id: [u8; 32],
    pub peer_height: u32,
    /// Newest-first peer header ids from the SyncInfo payload.
    pub peer_header_ids: &'a [[u8; 32]],
    pub our_best_id: [u8; 32],
    pub our_best_height: u32,
    /// In-store cumulative score of the peer tip, when known.
    pub peer_tip_score: Option<&'a [u8]>,
    pub our_best_score: &'a [u8],
}

/// SyncInfo V2 comparison — Scala `ErgoHistoryReader.compareV2`, with
/// cumulative-score refinement when `peer_tip_score` is known (in-store
/// tip). Wire SyncInfo carries height + headers but not cumulative
/// score; unknown tips keep the height-based Older branch.
///
/// `we_contain` matches Scala `commonPoint` (`contains`, not
/// best-chain-only).
pub fn compare_sync_info_v2(
    args: SyncInfoV2Compare<'_>,
    we_contain: impl Fn(&[u8; 32]) -> bool,
) -> PeerChainStatus {
    let SyncInfoV2Compare {
        peer_tip_id,
        peer_height,
        peer_header_ids,
        our_best_id,
        our_best_height,
        peer_tip_score,
        our_best_score,
    } = args;
    if peer_header_ids.is_empty() {
        return PeerChainStatus::Younger;
    }
    if peer_height == our_best_height {
        if peer_tip_id == our_best_id {
            return PeerChainStatus::Equal;
        }
        // Equal height, different tip: Fork if we share any ancestor
        // in their list (skip tip — already known off-chain).
        let common = peer_header_ids.iter().skip(1).any(&we_contain);
        return if common {
            PeerChainStatus::Fork
        } else {
            PeerChainStatus::Unknown
        };
    }
    if peer_height > our_best_height {
        // Scala: Older (+ todo check difficulty). When we already hold
        // the tip, refine by cumulative score — a higher height with
        // ≤ our score is not ahead of us.
        if let Some(ps) = peer_tip_score {
            return match score_cmp(ps, our_best_score) {
                std::cmp::Ordering::Greater => PeerChainStatus::Older,
                std::cmp::Ordering::Equal => PeerChainStatus::Equal,
                std::cmp::Ordering::Less => {
                    if peer_header_ids.iter().skip(1).any(&we_contain) {
                        PeerChainStatus::Fork
                    } else {
                        PeerChainStatus::Unknown
                    }
                }
            };
        }
        return PeerChainStatus::Older;
    }
    // peer_height < our_best_height
    PeerChainStatus::Younger
}

/// Legacy height/tip-on-chain helper retained for call sites that still
/// pass an optional peer height without a tip-score context. Prefer
/// [`compare_sync_info_v1`] / [`compare_sync_info_v2`].
pub fn compare_sync_info(
    peer_header_ids: &[[u8; 32]],
    peer_best_height: Option<u32>,
    our_best_height: u32,
    our_chain_contains: impl Fn(&[u8; 32]) -> bool,
) -> PeerChainStatus {
    if peer_header_ids.is_empty() {
        return PeerChainStatus::Unknown;
    }

    let newest_id = &peer_header_ids[0];
    let newest_on_our_chain = our_chain_contains(newest_id);

    if newest_on_our_chain {
        match peer_best_height {
            Some(h) if h == our_best_height => PeerChainStatus::Equal,
            Some(h) if h < our_best_height => PeerChainStatus::Younger,
            Some(_) => PeerChainStatus::Nonsense,
            None => PeerChainStatus::Younger,
        }
    } else {
        let any_on_our_chain = peer_header_ids.iter().skip(1).any(&our_chain_contains);
        if any_on_our_chain {
            match peer_best_height {
                Some(h) if h > our_best_height => PeerChainStatus::Older,
                _ => PeerChainStatus::Fork,
            }
        } else {
            match peer_best_height {
                Some(h) if h > our_best_height => PeerChainStatus::Older,
                _ => PeerChainStatus::Nonsense,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_id(v: u8) -> [u8; 32] {
        [v; 32]
    }

    /// Test helper that produces a unique header ID per u32 seed,
    /// avoiding the u8 collision that [`mk_id`] has above 255.
    fn mk_id32(v: u32) -> [u8; 32] {
        let mut id = [0u8; 32];
        id[..4].copy_from_slice(&v.to_be_bytes());
        id
    }

    #[test]
    fn sync_state_basics() {
        let mut state = SyncState::new(100);
        assert_eq!(state.best_full_block_height(), 100);
        assert!(!state.is_ibd());

        state.set_best_known_header(200);
        assert!(state.is_ibd());

        state.add_pending_block(101, mk_id(1));
        state.add_pending_block(102, mk_id(2));
        assert_eq!(state.pending_count(), 2);

        // Within download window
        let to_download = state.blocks_to_download();
        assert_eq!(to_download.len(), 2);

        // Apply block 101
        state.set_best_full_block(101);
        assert_eq!(state.pending_count(), 1);
    }

    #[test]
    fn download_window_limits_default_384() {
        let mut state = SyncState::new(0);
        assert_eq!(state.download_window(), DOWNLOAD_WINDOW);
        assert_eq!(DOWNLOAD_WINDOW, 384);
        // Add more blocks than the window; blocks_to_download must cap at 384.
        // Use mk_id32 to avoid u8 ID collisions above 255.
        for i in 1..=500 {
            state.add_pending_block(i, mk_id32(i));
        }
        let to_download = state.blocks_to_download();
        assert_eq!(to_download.len(), DOWNLOAD_WINDOW);
    }

    #[test]
    fn download_window_custom_honored() {
        let mut state = SyncState::new_with_window(0, 50);
        assert_eq!(state.download_window(), 50);
        for i in 1..=300 {
            state.add_pending_block(i, mk_id32(i));
        }
        assert_eq!(state.blocks_to_download().len(), 50);
    }

    #[test]
    fn download_window_zero_clamped_to_one() {
        // Avoid a stalled pipeline: window of 0 would never let any block
        // be downloaded. Clamp to 1.
        let mut state = SyncState::new_with_window(0, 0);
        assert_eq!(state.download_window(), 1);
        for i in 1..=5 {
            state.add_pending_block(i, mk_id(i as u8));
        }
        assert_eq!(state.blocks_to_download().len(), 1);
    }

    #[test]
    fn duplicate_pending_blocks_ignored() {
        let mut state = SyncState::new(0);
        state.add_pending_block(1, mk_id(1));
        state.add_pending_block(1, mk_id(1)); // duplicate
        assert_eq!(state.pending_count(), 1);
    }

    #[test]
    fn applied_blocks_not_added() {
        let mut state = SyncState::new(5);
        state.add_pending_block(3, mk_id(3)); // already applied
        assert_eq!(state.pending_count(), 0);
    }

    #[test]
    fn compare_equal() {
        let status = compare_sync_info(&[mk_id(5)], Some(100), 100, |id| *id == mk_id(5));
        assert_eq!(status, PeerChainStatus::Equal);
    }

    #[test]
    fn compare_younger() {
        let status = compare_sync_info(&[mk_id(5)], Some(50), 100, |id| *id == mk_id(5));
        assert_eq!(status, PeerChainStatus::Younger);
    }

    #[test]
    fn compare_older_no_common() {
        let status = compare_sync_info(&[mk_id(99)], Some(200), 100, |_| false);
        assert_eq!(status, PeerChainStatus::Older);
    }

    #[test]
    fn compare_fork() {
        // Peer's newest header not on our chain, but an older one is
        let status = compare_sync_info(
            &[mk_id(99), mk_id(5)],
            Some(100),
            100,
            |id| *id == mk_id(5), // mk_id(5) is on our chain, mk_id(99) is not
        );
        assert_eq!(status, PeerChainStatus::Fork);
    }

    #[test]
    fn compare_older_with_common() {
        let status =
            compare_sync_info(&[mk_id(99), mk_id(5)], Some(200), 100, |id| *id == mk_id(5));
        assert_eq!(status, PeerChainStatus::Older);
    }

    #[test]
    fn compare_empty_is_unknown() {
        let status = compare_sync_info(&[], None, 100, |_| false);
        assert_eq!(status, PeerChainStatus::Unknown);
    }

    #[test]
    fn compare_v1_tip_at_either_end_is_equal() {
        let our = mk_id(5);
        // Scala oldest-first: tip last.
        assert_eq!(
            compare_sync_info_v1(&[mk_id(1), our], &our, |_| false),
            PeerChainStatus::Equal
        );
        // Rust newest-first: tip first.
        assert_eq!(
            compare_sync_info_v1(&[our, mk_id(1)], &our, |_| false),
            PeerChainStatus::Equal
        );
    }

    #[test]
    fn compare_v1_our_tip_in_list_is_older() {
        let our = mk_id(5);
        assert_eq!(
            compare_sync_info_v1(&[mk_id(9), our, mk_id(1)], &our, |_| false),
            PeerChainStatus::Older
        );
    }

    #[test]
    fn compare_v2_equal_height_fork() {
        let status = compare_sync_info_v2(
            SyncInfoV2Compare {
                peer_tip_id: mk_id(99),
                peer_height: 100,
                peer_header_ids: &[mk_id(99), mk_id(5)],
                our_best_id: mk_id(7),
                our_best_height: 100,
                peer_tip_score: None,
                our_best_score: &[1],
            },
            |id| *id == mk_id(5),
        );
        assert_eq!(status, PeerChainStatus::Fork);
    }

    #[test]
    fn compare_v2_score_refines_claimed_older() {
        // Peer claims height ahead, but in-store tip score is not greater.
        let tip = mk_id(99);
        let status = compare_sync_info_v2(
            SyncInfoV2Compare {
                peer_tip_id: tip,
                peer_height: 200,
                peer_header_ids: &[tip, mk_id(5)],
                our_best_id: mk_id(7),
                our_best_height: 100,
                peer_tip_score: Some(&[1]),
                our_best_score: &[2],
            },
            |id| *id == mk_id(5),
        );
        assert_eq!(status, PeerChainStatus::Fork);
        let status_ahead = compare_sync_info_v2(
            SyncInfoV2Compare {
                peer_tip_id: tip,
                peer_height: 200,
                peer_header_ids: &[tip],
                our_best_id: mk_id(7),
                our_best_height: 100,
                peer_tip_score: Some(&[5]),
                our_best_score: &[2],
            },
            |_| false,
        );
        assert_eq!(status_ahead, PeerChainStatus::Older);
    }

    #[test]
    fn sync_interval_respected_per_peer() {
        let mut state = SyncState::new(0);
        let now = Instant::now();
        let p1: PeerId = "127.0.0.1:9030".parse().unwrap();
        let p2: PeerId = "127.0.0.1:9031".parse().unwrap();

        // Both peers eligible initially.
        assert!(state.should_send_sync(p1, now));
        assert!(state.should_send_sync(p2, now));

        // Marking p1 must not affect p2's timer — that's the whole
        // point of the per-peer split.
        state.mark_sync_sent(p1, now);
        assert!(!state.should_send_sync(p1, now + Duration::from_secs(10)));
        assert!(state.should_send_sync(p2, now));

        // Same peer is eligible again after MinSyncInterval (20s).
        assert!(state.should_send_sync(p1, now + MIN_SYNC_INTERVAL));
    }

    #[test]
    fn forget_peer_sync_resets_timer() {
        let mut state = SyncState::new(0);
        let now = Instant::now();
        let p: PeerId = "127.0.0.1:9030".parse().unwrap();

        state.mark_sync_sent(p, now);
        assert!(!state.should_send_sync(p, now + Duration::from_secs(1)));

        state.forget_peer_sync(&p);
        assert!(state.should_send_sync(p, now + Duration::from_secs(1)));
    }

    #[test]
    fn outdated_and_clear_thresholds() {
        let mut state = SyncState::new(0);
        let now = Instant::now();
        let p: PeerId = "127.0.0.1:9030".parse().unwrap();

        // Never contacted: not-synced, but not "outdated" (no send yet).
        assert!(state.not_synced_or_outdated(p, now));
        assert!(!state.is_outdated(p, now));
        assert!(!state.status_clear_due(p, now));

        state.mark_sync_sent(p, now);
        assert!(!state.not_synced_or_outdated(p, now + Duration::from_secs(30)));
        assert!(!state.is_outdated(p, now + Duration::from_secs(30)));

        assert!(state.is_outdated(p, now + SYNC_THRESHOLD + Duration::from_secs(1)));
        assert!(state.not_synced_or_outdated(p, now + SYNC_THRESHOLD + Duration::from_secs(1)));
        assert!(state.status_clear_due(p, now + CLEAR_THRESHOLD + Duration::from_secs(1)));
    }
}
