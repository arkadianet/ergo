//! Per-peer sync state and preliminary chain-status comparison.
//!
//! Provides `PeerChainStatus`, the `SyncState` download-window
//! tracker, and a height-based chain comparison function. The full
//! sync coordinator (cumulative-difficulty fork choice, continuation
//! header application from `SyncInfoV2`, sync action emission, and
//! integration with header validation + `ergo-state`) lives in
//! `ergo-sync`; this module only carries the per-peer state surface
//! the coordinator drives.

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
/// Raised from 192 (Scala parity default) to 384 (Sync-S3) to better
/// saturate a single peer when multi-peer discovery is not yet active.
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
    /// PeerId. Per-peer timer (not global) so the broadcast loop can
    /// keep every peer's Inv pump primed independently — without it,
    /// a single global throttle leaves most peers silent and the
    /// header request fanout collapses to ~1-2 active peers per
    /// sync_interval window. Pruned in `forget_peer_sync` on
    /// disconnect to keep the map bounded by live peers.
    last_sync_sent: HashMap<PeerId, Instant>,
    /// Minimum interval between SyncInfo messages to the same peer.
    /// Set to 100ms to feed Invs from many peers per sync_tick —
    /// equal to Scala's per-peer debounce (`PerPeerSyncLockTime`),
    /// so reference-node peers accept the cadence without penalty.
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
    /// reads this to skip Phase 3a section-request emission for
    /// headers whose height is below the sentinel — Scala parity
    /// for the request-side third of "three drop points" (plan §240).
    /// Updated by the boot/sync integration after store apply / open.
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
            // Lever 1's per-peer SyncInfo cadence. 100ms dispatches at
            // Scala's PerPeerSyncLockTime floor so the peer-side
            // `continuationIdsV1` index lookup is invoked up to 10× per
            // second per peer. Each invocation produces a 400-ID Inv at
            // trivial peer-side cost (~12.8 KB), so 60 peers × 10
            // Invs/sec = 240k discovered IDs/sec — the upper-bound
            // pipeline width before byte download.
            sync_interval: Duration::from_millis(100),
            headers_chain_synced: false,
            download_window: download_window.clamp(1, MAX_DOWNLOAD_WINDOW_CLAMP),
            header_freshness_threshold_ms,
            prune_sentinel: 0,
        }
    }

    /// Mirror the Mode 3 prune sentinel from the store. The
    /// coordinator's request-side gate (Phase 3a, plan §240) reads
    /// this to skip section requests for headers below the
    /// sentinel — we'd just evict those sections on apply.
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

    /// Whether we should send a SyncInfo message to `peer` now
    /// (respects per-peer interval). True if we've never asked this
    /// peer or if `sync_interval` has elapsed since the last send.
    pub fn should_send_sync(&self, peer: PeerId, now: Instant) -> bool {
        match self.last_sync_sent.get(&peer) {
            Some(t) => now.duration_since(*t) >= self.sync_interval,
            None => true,
        }
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

/// Preliminary comparison of a peer's SyncInfo headers against our chain.
///
/// **Limitation**: this uses header height for Older/Fork classification,
/// NOT cumulative difficulty. Ergo's fork choice rule is heaviest chain
/// by cumulative difficulty, not tallest. A proper fork-choice decision
/// requires `cumulative_score` from the store, which the sync
/// coordinator in `ergo-sync` consults; this preliminary classifier is
/// only used for the initial Equal/Younger/Unknown decision.
///
/// This function is sufficient for initial sync status classification
/// (Equal/Younger/Unknown) and for detecting that a peer has headers we
/// don't. The Older vs Fork distinction is approximate until cumulative
/// difficulty is consulted.
///
/// `our_chain_contains` returns true if we have a header ID on our best chain.
/// `our_best_height` is our best header height.
pub fn compare_sync_info(
    peer_header_ids: &[[u8; 32]],
    peer_best_height: Option<u32>,
    our_best_height: u32,
    our_chain_contains: impl Fn(&[u8; 32]) -> bool,
) -> PeerChainStatus {
    if peer_header_ids.is_empty() {
        return PeerChainStatus::Unknown;
    }

    // Check if the peer's most recent header is on our chain
    let newest_id = &peer_header_ids[0]; // headers are newest-first in V2
    let newest_on_our_chain = our_chain_contains(newest_id);

    if newest_on_our_chain {
        // Peer's tip is on our chain
        match peer_best_height {
            Some(h) if h == our_best_height => PeerChainStatus::Equal,
            Some(h) if h < our_best_height => PeerChainStatus::Younger,
            Some(_) => PeerChainStatus::Nonsense, // claims higher but their tip is on our chain at lower height
            None => PeerChainStatus::Younger,     // V1 without height info — assume younger
        }
    } else {
        // Peer's tip is NOT on our chain. Check if any of their headers are.
        let any_on_our_chain = peer_header_ids.iter().skip(1).any(&our_chain_contains);
        if any_on_our_chain {
            // We share a common ancestor but diverge → Fork or Older
            match peer_best_height {
                Some(h) if h > our_best_height => PeerChainStatus::Older,
                _ => PeerChainStatus::Fork,
            }
        } else {
            // No common headers at all
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
        assert!(!state.should_send_sync(p1, now + Duration::from_millis(50)));
        assert!(state.should_send_sync(p2, now));

        // Same peer is eligible again after sync_interval (100ms).
        assert!(state.should_send_sync(p1, now + Duration::from_millis(150)));
    }

    #[test]
    fn forget_peer_sync_resets_timer() {
        let mut state = SyncState::new(0);
        let now = Instant::now();
        let p: PeerId = "127.0.0.1:9030".parse().unwrap();

        state.mark_sync_sent(p, now);
        assert!(!state.should_send_sync(p, now + Duration::from_millis(50)));

        state.forget_peer_sync(&p);
        assert!(state.should_send_sync(p, now + Duration::from_millis(50)));
    }
}
