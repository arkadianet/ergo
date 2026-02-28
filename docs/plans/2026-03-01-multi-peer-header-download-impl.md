# Multi-Peer Parallel Header Download Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Partition header download requests across multiple ahead peers to increase sync throughput proportional to peer count.

**Architecture:** Pure partitioner function in new `header_partitioner.rs` module, called from refactored `handle_inv` in `message_handler.rs`. Rolling-window `SyncMetrics` struct for structured logging. Reuses existing `DeliveryTracker` for single-owner tracking and timeout/reassignment. Configurable SyncInfo header count via settings.

**Tech Stack:** Rust, ergo-network crate, tracing for structured logs, existing DeliveryTracker/SyncTracker

**Design doc:** `docs/plans/2026-03-01-multi-peer-header-download-design.md`

---

### Task 1: DeliveryTracker — Outstanding Count Methods

Add two query methods to DeliveryTracker for enforcing outstanding request caps.

**Files:**
- Modify: `crates/ergo-network/src/delivery_tracker.rs:205` (before closing `}` of `impl`)
- Test: same file, `mod tests` section at line 223

**Step 1: Write the failing tests**

Add at the end of `mod tests` in `crates/ergo-network/src/delivery_tracker.rs` (before the closing `}`):

```rust
#[test]
fn outstanding_header_count_per_peer() {
    let mut tracker = DeliveryTracker::new(60, 3);
    tracker.set_requested(101, make_id(0x40), 1);
    tracker.set_requested(101, make_id(0x41), 1);
    tracker.set_requested(101, make_id(0x42), 2);
    tracker.set_requested(102, make_id(0x43), 1); // body section, not header
    assert_eq!(tracker.outstanding_header_count(1), 2);
    assert_eq!(tracker.outstanding_header_count(2), 1);
    assert_eq!(tracker.outstanding_header_count(99), 0);
}

#[test]
fn total_outstanding_headers() {
    let mut tracker = DeliveryTracker::new(60, 3);
    tracker.set_requested(101, make_id(0x50), 1);
    tracker.set_requested(101, make_id(0x51), 2);
    tracker.set_requested(101, make_id(0x52), 3);
    tracker.set_requested(102, make_id(0x53), 1); // not a header
    assert_eq!(tracker.total_outstanding_headers(), 3);
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test -p ergo-network outstanding_header -- --nocapture`
Expected: FAIL — methods don't exist yet.

**Step 3: Write the implementation**

Add before the closing `}` of `impl DeliveryTracker` (after `snapshot()` at line 204):

```rust
/// Count outstanding header (type_id=101) requests assigned to a specific peer.
pub fn outstanding_header_count(&self, peer_id: PeerId) -> usize {
    self.requested
        .iter()
        .filter(|(&(type_id, _), info)| type_id == 101 && info.peer_id == peer_id)
        .count()
}

/// Count total outstanding header (type_id=101) requests across all peers.
pub fn total_outstanding_headers(&self) -> usize {
    self.requested
        .keys()
        .filter(|(type_id, _)| *type_id == 101)
        .count()
}
```

**Step 4: Run tests to verify they pass**

Run: `cargo test -p ergo-network outstanding_header -- --nocapture`
Expected: PASS (2 new tests)

**Step 5: Commit**

```bash
git add crates/ergo-network/src/delivery_tracker.rs
git commit -m "feat(delivery-tracker): add outstanding header count methods"
```

---

### Task 2: Header Partitioner — Pure Algorithm + Peer Selection

Create the new `header_partitioner.rs` module with the partitioning algorithm and peer selection logic.

**Files:**
- Create: `crates/ergo-network/src/header_partitioner.rs`
- Modify: `crates/ergo-network/src/lib.rs:1` (add module declaration)

**Step 1: Write the failing tests**

Create `crates/ergo-network/src/header_partitioner.rs` with tests first:

```rust
use ergo_types::modifier_id::ModifierId;

use crate::delivery_tracker::PeerId;
use crate::sync_tracker::{PeerChainStatus, SyncTracker};

/// Maximum IDs processed per Inv cycle (Scala: 400).
const MAX_INV_IDS: usize = 400;

/// Default minimum IDs per peer chunk (Scala behavior).
pub const DEFAULT_MIN_PER_PEER: usize = 50;

/// Result of peer eligibility check.
#[derive(Debug)]
pub enum EligiblePeers {
    /// Multiple Older peers available for partitioning.
    Partition(Vec<PeerId>),
    /// Only the inv sender is usable (with reason why partitioning was skipped).
    SinglePeerFallback(PeerId, &'static str),
}

/// Partition `ids` into contiguous chunks assigned to `peers`.
///
/// - `ids` must be in height-ascending order (preserved from Inv iteration).
/// - `peers[0]` should be the inv_sender (gets the lowest-height prefix chunk).
/// - Min chunk size = `min_per_peer`. If not enough IDs, fewer peers are used.
/// - Total capped at 400 IDs.
/// - Returns `Vec<(PeerId, Vec<ModifierId>)>` with non-empty chunks.
pub fn partition_header_ids(
    ids: &[ModifierId],
    peers: &[PeerId],
    min_per_peer: usize,
) -> Vec<(PeerId, Vec<ModifierId>)> {
    if ids.is_empty() || peers.is_empty() {
        return Vec::new();
    }

    let capped = if ids.len() > MAX_INV_IDS {
        &ids[..MAX_INV_IDS]
    } else {
        ids
    };
    let n = capped.len();
    let min = if min_per_peer == 0 { 1 } else { min_per_peer };

    let max_peers_by_size = std::cmp::max(1, n / min);
    let usable_peers = std::cmp::min(peers.len(), max_peers_by_size);

    let chunk_size = n / usable_peers;
    let remainder = n % usable_peers;

    let mut result = Vec::with_capacity(usable_peers);
    let mut offset = 0;

    for i in 0..usable_peers {
        let extra = if i < remainder { 1 } else { 0 };
        let end = offset + chunk_size + extra;
        result.push((peers[i], capped[offset..end].to_vec()));
        offset = end;
    }

    debug_assert_eq!(offset, n, "all IDs must be assigned");
    result
}

/// Select eligible peers for multi-peer header download.
///
/// Rules:
/// - Only peers classified as `Older` are eligible.
/// - `inv_sender` is placed at position 0 if Older.
/// - If `inv_sender` is not Older, returns `SinglePeerFallback`.
/// - Fork/Unknown/Younger peers are excluded (deliberate v1 choice).
pub fn select_eligible_peers(
    inv_sender: PeerId,
    sync_tracker: &SyncTracker,
    connected_peers: &[PeerId],
) -> EligiblePeers {
    let sender_is_older = sync_tracker
        .status(inv_sender)
        .map(|s| s == PeerChainStatus::Older)
        .unwrap_or(false);

    if !sender_is_older {
        let reason = match sync_tracker.status(inv_sender) {
            Some(PeerChainStatus::Younger) => "inv_sender classified Younger",
            Some(PeerChainStatus::Equal) => "inv_sender classified Equal",
            Some(PeerChainStatus::Fork) => "inv_sender classified Fork",
            Some(PeerChainStatus::Unknown) => "inv_sender classified Unknown",
            None => "inv_sender not tracked",
            _ => "inv_sender not Older",
        };
        return EligiblePeers::SinglePeerFallback(inv_sender, reason);
    }

    // Collect all connected Older peers, inv_sender first.
    let mut peers = vec![inv_sender];
    for &pid in connected_peers {
        if pid == inv_sender {
            continue;
        }
        if sync_tracker
            .status(pid)
            .map(|s| s == PeerChainStatus::Older)
            .unwrap_or(false)
        {
            peers.push(pid);
        }
    }

    EligiblePeers::Partition(peers)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_id(byte: u8) -> ModifierId {
        let mut bytes = [0u8; 32];
        bytes[0] = byte;
        ModifierId(bytes)
    }

    fn make_ids(n: usize) -> Vec<ModifierId> {
        (0..n).map(|i| make_id(i as u8)).collect()
    }

    // -- partition_header_ids tests --

    #[test]
    fn partition_empty_ids() {
        let result = partition_header_ids(&[], &[1, 2], 50);
        assert!(result.is_empty());
    }

    #[test]
    fn partition_empty_peers() {
        let result = partition_header_ids(&make_ids(100), &[], 50);
        assert!(result.is_empty());
    }

    #[test]
    fn partition_even_split() {
        let ids = make_ids(400);
        let peers = vec![1, 2, 3, 4];
        let result = partition_header_ids(&ids, &peers, 50);
        assert_eq!(result.len(), 4);
        for (_, chunk) in &result {
            assert_eq!(chunk.len(), 100);
        }
        // Verify coverage and disjointness
        let all: Vec<ModifierId> = result.iter().flat_map(|(_, c)| c.iter().copied()).collect();
        assert_eq!(all, ids);
    }

    #[test]
    fn partition_reduces_peers_for_small_batch() {
        // 150 IDs, 4 peers, min=50 → only 3 peers used
        let ids = make_ids(150);
        let peers = vec![1, 2, 3, 4];
        let result = partition_header_ids(&ids, &peers, 50);
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].1.len(), 50);
        assert_eq!(result[1].1.len(), 50);
        assert_eq!(result[2].1.len(), 50);
    }

    #[test]
    fn partition_below_min_single_peer() {
        // 30 IDs, 3 peers, min=50 → only 1 peer
        let ids = make_ids(30);
        let peers = vec![1, 2, 3];
        let result = partition_header_ids(&ids, &peers, 50);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, 1); // first peer (inv_sender)
        assert_eq!(result[0].1.len(), 30);
    }

    #[test]
    fn partition_single_peer() {
        let ids = make_ids(200);
        let peers = vec![42];
        let result = partition_header_ids(&ids, &peers, 50);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, 42);
        assert_eq!(result[0].1.len(), 200);
    }

    #[test]
    fn partition_exact_min() {
        let ids = make_ids(100);
        let peers = vec![1, 2];
        let result = partition_header_ids(&ids, &peers, 50);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].1.len(), 50);
        assert_eq!(result[1].1.len(), 50);
    }

    #[test]
    fn partition_remainder_distributed() {
        // 107 IDs, 2 peers → 54 + 53
        let ids = make_ids(107);
        let peers = vec![1, 2];
        let result = partition_header_ids(&ids, &peers, 50);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].1.len(), 54); // first peer gets extra
        assert_eq!(result[1].1.len(), 53);
        // Coverage
        let all: Vec<ModifierId> = result.iter().flat_map(|(_, c)| c.iter().copied()).collect();
        assert_eq!(all, ids);
    }

    #[test]
    fn partition_caps_at_400() {
        let ids = make_ids(500);
        let peers = vec![1, 2];
        let result = partition_header_ids(&ids, &peers, 50);
        let total: usize = result.iter().map(|(_, c)| c.len()).sum();
        assert_eq!(total, 400);
    }

    #[test]
    fn partition_contiguous_and_disjoint() {
        let ids = make_ids(200);
        let peers = vec![1, 2, 3];
        let result = partition_header_ids(&ids, &peers, 50);
        // Check contiguous: each chunk's IDs appear consecutively in original
        let mut seen = std::collections::HashSet::new();
        for (_, chunk) in &result {
            for id in chunk {
                assert!(seen.insert(*id), "duplicate ID in partition");
            }
        }
        assert_eq!(seen.len(), 200);
    }

    #[test]
    fn partition_no_chunk_below_min_unless_single() {
        // Test various sizes to ensure min is respected
        for n in 1..=400 {
            let ids = make_ids(n);
            let peers = vec![1, 2, 3, 4, 5, 6, 7, 8];
            let result = partition_header_ids(&ids, &peers, 50);
            for (_, chunk) in &result {
                if result.len() > 1 {
                    assert!(
                        chunk.len() >= 50,
                        "chunk size {} < min 50 with {} peers for n={}",
                        chunk.len(),
                        result.len(),
                        n
                    );
                }
            }
        }
    }

    // -- select_eligible_peers tests --

    #[test]
    fn select_sender_older_with_others() {
        let mut st = SyncTracker::new();
        st.update_status(1, PeerChainStatus::Older, Some(100));
        st.update_status(2, PeerChainStatus::Older, Some(100));
        st.update_status(3, PeerChainStatus::Older, Some(100));
        st.update_status(4, PeerChainStatus::Younger, Some(50));

        let connected = vec![1, 2, 3, 4];
        match select_eligible_peers(1, &st, &connected) {
            EligiblePeers::Partition(peers) => {
                assert_eq!(peers[0], 1); // inv_sender first
                assert_eq!(peers.len(), 3); // only Older peers
                assert!(!peers.contains(&4)); // Younger excluded
            }
            _ => panic!("expected Partition"),
        }
    }

    #[test]
    fn select_sender_not_older() {
        let mut st = SyncTracker::new();
        st.update_status(1, PeerChainStatus::Younger, Some(50));
        st.update_status(2, PeerChainStatus::Older, Some(100));

        let connected = vec![1, 2];
        match select_eligible_peers(1, &st, &connected) {
            EligiblePeers::SinglePeerFallback(peer, reason) => {
                assert_eq!(peer, 1);
                assert!(reason.contains("Younger"));
            }
            _ => panic!("expected SinglePeerFallback"),
        }
    }

    #[test]
    fn select_no_older_peers() {
        let mut st = SyncTracker::new();
        st.update_status(1, PeerChainStatus::Equal, Some(100));
        st.update_status(2, PeerChainStatus::Younger, Some(50));

        let connected = vec![1, 2];
        match select_eligible_peers(1, &st, &connected) {
            EligiblePeers::SinglePeerFallback(_, _) => {}
            _ => panic!("expected SinglePeerFallback"),
        }
    }

    #[test]
    fn select_excludes_fork_and_unknown() {
        let mut st = SyncTracker::new();
        st.update_status(1, PeerChainStatus::Older, Some(100));
        st.update_status(2, PeerChainStatus::Fork, Some(100));
        st.update_status(3, PeerChainStatus::Unknown, None);
        st.update_status(4, PeerChainStatus::Older, Some(100));

        let connected = vec![1, 2, 3, 4];
        match select_eligible_peers(1, &st, &connected) {
            EligiblePeers::Partition(peers) => {
                assert_eq!(peers.len(), 2); // only 1 and 4
                assert!(peers.contains(&1));
                assert!(peers.contains(&4));
            }
            _ => panic!("expected Partition"),
        }
    }

    #[test]
    fn select_sender_only_older() {
        let mut st = SyncTracker::new();
        st.update_status(1, PeerChainStatus::Older, Some(100));

        let connected = vec![1];
        match select_eligible_peers(1, &st, &connected) {
            EligiblePeers::Partition(peers) => {
                assert_eq!(peers, vec![1]);
            }
            _ => panic!("expected Partition with single peer"),
        }
    }
}
```

**Step 2: Register the module**

Add to `crates/ergo-network/src/lib.rs` (alphabetical position, after `header_chain`):

```rust
pub mod header_partitioner;
```

**Step 3: Run tests to verify they pass**

Run: `cargo test -p ergo-network header_partitioner -- --nocapture`
Expected: PASS (all 15 tests)

**Step 4: Run clippy**

Run: `cargo clippy -p ergo-network -- -D warnings`
Expected: no warnings

**Step 5: Commit**

```bash
git add crates/ergo-network/src/header_partitioner.rs crates/ergo-network/src/lib.rs
git commit -m "feat(network): add header partitioner with contiguous chunking and peer selection"
```

---

### Task 3: SyncMetrics — Rolling Window Counters + Batch Tracking

Create the `SyncMetrics` struct with rolling window counters, batch lifecycle tracking, and structured log emission.

**Files:**
- Create: `crates/ergo-network/src/sync_metrics.rs`
- Modify: `crates/ergo-network/src/lib.rs` (add module declaration)

**Step 1: Create the module with implementation + tests**

Create `crates/ergo-network/src/sync_metrics.rs`:

```rust
use std::collections::HashMap;
use std::time::Instant;

use crate::delivery_tracker::PeerId;

/// Maximum active batches before evicting oldest.
const MAX_ACTIVE_BATCHES: usize = 128;

/// TTL for stale batches (seconds).
const BATCH_STALE_TTL_SECS: u64 = 60;

/// Rolling-window sync metrics. Owned by the event loop (single-threaded).
pub struct SyncMetrics {
    next_batch_id: u64,
    window_start: Instant,
    window_secs: u64,

    // Window counters
    headers_applied: u64,
    batches_started: u64,
    timeouts: u64,
    reassignments: u64,
    dup_requests_prevented: u64,
    validate_ms_total: u64,
    db_ms_total: u64,
    peers_used_total: u64,

    // Per-peer window counters
    requests_sent_by_peer: HashMap<PeerId, u64>,
    mods_received_by_peer: HashMap<PeerId, u64>,
    timeouts_by_peer: HashMap<PeerId, u64>,

    // Active batch tracking
    active_batches: HashMap<u64, BatchInfo>,
}

struct BatchInfo {
    started: Instant,
    inv_len: usize,
    to_request_len: usize,
    peer_count: usize,
    chunks: Vec<(PeerId, usize)>,
    delivered: usize,
}

impl SyncMetrics {
    pub fn new(window_secs: u64) -> Self {
        Self {
            next_batch_id: 0,
            window_start: Instant::now(),
            window_secs,
            headers_applied: 0,
            batches_started: 0,
            timeouts: 0,
            reassignments: 0,
            dup_requests_prevented: 0,
            validate_ms_total: 0,
            db_ms_total: 0,
            peers_used_total: 0,
            requests_sent_by_peer: HashMap::new(),
            mods_received_by_peer: HashMap::new(),
            timeouts_by_peer: HashMap::new(),
            active_batches: HashMap::new(),
        }
    }

    /// Generate monotonically increasing batch ID.
    pub fn new_batch_id(&mut self) -> u64 {
        let id = self.next_batch_id;
        self.next_batch_id += 1;
        id
    }

    /// Record a partition decision at Inv receipt time.
    pub fn record_partition(
        &mut self,
        batch_id: u64,
        inv_len: usize,
        to_request_len: usize,
        assignments: &[(PeerId, usize)],
    ) {
        let peer_count = assignments.len();
        self.batches_started += 1;
        self.peers_used_total += peer_count as u64;

        // Evict oldest if at capacity
        while self.active_batches.len() >= MAX_ACTIVE_BATCHES {
            if let Some(&oldest_id) = self
                .active_batches
                .iter()
                .min_by_key(|(_, b)| b.started)
                .map(|(id, _)| id)
            {
                tracing::warn!(batch_id = oldest_id, "batch_evicted_stale: capacity limit");
                self.active_batches.remove(&oldest_id);
            }
        }

        self.active_batches.insert(
            batch_id,
            BatchInfo {
                started: Instant::now(),
                inv_len,
                to_request_len,
                peer_count,
                chunks: assignments.to_vec(),
                delivered: 0,
            },
        );

        tracing::info!(
            batch_id,
            inv_len,
            to_request_len,
            peer_count,
            ?assignments,
            "partition_decided"
        );
    }

    /// Record requests sent to a peer for a batch.
    pub fn record_requests_sent(
        &mut self,
        batch_id: u64,
        peer: PeerId,
        n_ids: usize,
        chunk_start_idx: usize,
        chunk_end_idx: usize,
    ) {
        *self.requests_sent_by_peer.entry(peer).or_insert(0) += n_ids as u64;

        tracing::info!(
            batch_id,
            peer,
            n_ids,
            chunk_start_idx,
            chunk_end_idx,
            "requests_sent"
        );
    }

    /// Record modifiers received from a peer.
    pub fn record_modifier_received(
        &mut self,
        peer: PeerId,
        n_mods: usize,
        bytes: usize,
        batch_id: Option<u64>,
        elapsed_ms: u64,
    ) {
        *self.mods_received_by_peer.entry(peer).or_insert(0) += n_mods as u64;

        tracing::info!(
            peer,
            n_mods,
            bytes,
            batch_id = batch_id.unwrap_or(u64::MAX),
            elapsed_ms,
            "modifier_received"
        );
    }

    /// Record headers applied for a batch.
    pub fn record_headers_applied(
        &mut self,
        batch_id: u64,
        applied: usize,
        invalid: usize,
        dup_blocked: usize,
        pow_ms: u64,
        db_ms: u64,
        total_ms: u64,
    ) {
        self.headers_applied += applied as u64;
        self.validate_ms_total += pow_ms;
        self.db_ms_total += db_ms;

        let batch_age_ms = self
            .active_batches
            .get(&batch_id)
            .map(|b| b.started.elapsed().as_millis() as u64)
            .unwrap_or(0);

        let headers_per_sec = if total_ms > 0 {
            (applied as f64 / total_ms as f64) * 1000.0
        } else {
            0.0
        };

        tracing::info!(
            batch_id,
            applied,
            invalid,
            dup_blocked,
            pow_ms,
            db_ms,
            total_ms,
            headers_per_sec = format!("{:.1}", headers_per_sec),
            batch_age_ms,
            "headers_applied"
        );

        // Update batch completion tracking
        if let Some(batch) = self.active_batches.get_mut(&batch_id) {
            batch.delivered += applied + invalid + dup_blocked;
            if batch.delivered >= batch.to_request_len {
                self.active_batches.remove(&batch_id);
            }
        }
    }

    /// Record a delivery timeout event.
    pub fn record_timeout(
        &mut self,
        n_missing: usize,
        from_peer: PeerId,
        to_peer: Option<PeerId>,
        attempt: u32,
        age_ms: u64,
    ) {
        self.timeouts += 1;
        *self.timeouts_by_peer.entry(from_peer).or_insert(0) += 1;

        tracing::info!(
            n_missing,
            from_peer,
            to_peer = to_peer.unwrap_or(0),
            attempt,
            age_ms,
            "delivery_timeout"
        );
    }

    /// Record a reassignment event.
    pub fn record_reassignment(
        &mut self,
        from_peer: PeerId,
        to_peer: PeerId,
        attempt: u32,
    ) {
        self.reassignments += 1;

        tracing::info!(from_peer, to_peer, attempt, "reassigned");
    }

    /// Record a duplicate request prevented (skipped because already
    /// Requested/Received/Invalid in tracker).
    pub fn record_dup_prevented(&mut self) {
        self.dup_requests_prevented += 1;
    }

    /// Emit periodic rollup log if window has elapsed. Call from event loop tick.
    pub fn maybe_emit_rollup(&mut self) {
        let elapsed = self.window_start.elapsed();
        if elapsed.as_secs() < self.window_secs {
            return;
        }

        // Evict stale batches
        let now = Instant::now();
        let stale_ttl = std::time::Duration::from_secs(BATCH_STALE_TTL_SECS);
        let stale_ids: Vec<u64> = self
            .active_batches
            .iter()
            .filter(|(_, b)| now.duration_since(b.started) > stale_ttl)
            .map(|(id, _)| *id)
            .collect();
        for id in &stale_ids {
            tracing::warn!(batch_id = id, "batch_evicted_stale: TTL exceeded");
            self.active_batches.remove(id);
        }

        let window_s = elapsed.as_secs_f64();
        let headers_per_sec = if window_s > 0.0 {
            self.headers_applied as f64 / window_s
        } else {
            0.0
        };

        let avg_peers = if self.batches_started > 0 {
            self.peers_used_total as f64 / self.batches_started as f64
        } else {
            0.0
        };

        let validate_ms_per_400 = if self.headers_applied > 0 {
            (self.validate_ms_total as f64 / self.headers_applied as f64) * 400.0
        } else {
            0.0
        };

        let db_ms_per_400 = if self.headers_applied > 0 {
            (self.db_ms_total as f64 / self.headers_applied as f64) * 400.0
        } else {
            0.0
        };

        tracing::info!(
            window_s = format!("{:.1}", window_s),
            headers_applied = self.headers_applied,
            headers_per_sec = format!("{:.1}", headers_per_sec),
            avg_peers_used_per_batch = format!("{:.1}", avg_peers),
            timeouts = self.timeouts,
            reassignments = self.reassignments,
            dup_requests_prevented = self.dup_requests_prevented,
            validate_ms_per_400 = format!("{:.1}", validate_ms_per_400),
            db_ms_per_400 = format!("{:.1}", db_ms_per_400),
            stale_batches_evicted = stale_ids.len(),
            "sync_rollup"
        );

        // Reset window
        self.window_start = Instant::now();
        self.headers_applied = 0;
        self.batches_started = 0;
        self.timeouts = 0;
        self.reassignments = 0;
        self.dup_requests_prevented = 0;
        self.validate_ms_total = 0;
        self.db_ms_total = 0;
        self.peers_used_total = 0;
        self.requests_sent_by_peer.clear();
        self.mods_received_by_peer.clear();
        self.timeouts_by_peer.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_batch_id_monotonic() {
        let mut m = SyncMetrics::new(10);
        assert_eq!(m.new_batch_id(), 0);
        assert_eq!(m.new_batch_id(), 1);
        assert_eq!(m.new_batch_id(), 2);
    }

    #[test]
    fn record_partition_tracks_batch() {
        let mut m = SyncMetrics::new(10);
        m.record_partition(0, 400, 350, &[(1, 175), (2, 175)]);
        assert_eq!(m.batches_started, 1);
        assert_eq!(m.peers_used_total, 2);
        assert!(m.active_batches.contains_key(&0));
    }

    #[test]
    fn batch_completes_when_fully_delivered() {
        let mut m = SyncMetrics::new(10);
        m.record_partition(0, 100, 100, &[(1, 50), (2, 50)]);
        assert!(m.active_batches.contains_key(&0));

        m.record_headers_applied(0, 50, 0, 0, 10, 5, 15);
        assert!(m.active_batches.contains_key(&0)); // not yet complete

        m.record_headers_applied(0, 50, 0, 0, 10, 5, 15);
        assert!(!m.active_batches.contains_key(&0)); // complete
    }

    #[test]
    fn batch_eviction_at_capacity() {
        let mut m = SyncMetrics::new(10);
        for i in 0..MAX_ACTIVE_BATCHES + 5 {
            m.record_partition(i as u64, 10, 10, &[(1, 10)]);
        }
        assert!(m.active_batches.len() <= MAX_ACTIVE_BATCHES);
    }

    #[test]
    fn record_dup_prevented_increments() {
        let mut m = SyncMetrics::new(10);
        m.record_dup_prevented();
        m.record_dup_prevented();
        assert_eq!(m.dup_requests_prevented, 2);
    }

    #[test]
    fn per_peer_counters_accumulate() {
        let mut m = SyncMetrics::new(10);
        m.record_requests_sent(0, 1, 50, 0, 49);
        m.record_requests_sent(0, 1, 50, 50, 99);
        m.record_requests_sent(0, 2, 100, 100, 199);
        assert_eq!(m.requests_sent_by_peer[&1], 100);
        assert_eq!(m.requests_sent_by_peer[&2], 100);
    }

    #[test]
    fn rollup_resets_counters() {
        let mut m = SyncMetrics::new(0); // 0s window = always rollup
        m.record_dup_prevented();
        m.headers_applied = 10;
        m.batches_started = 2;
        m.timeouts = 1;

        m.maybe_emit_rollup();

        assert_eq!(m.headers_applied, 0);
        assert_eq!(m.batches_started, 0);
        assert_eq!(m.timeouts, 0);
        assert_eq!(m.dup_requests_prevented, 0);
    }

    #[test]
    fn timeout_tracking() {
        let mut m = SyncMetrics::new(10);
        m.record_timeout(5, 1, Some(2), 1, 30000);
        assert_eq!(m.timeouts, 1);
        assert_eq!(m.timeouts_by_peer[&1], 1);
    }

    #[test]
    fn reassignment_tracking() {
        let mut m = SyncMetrics::new(10);
        m.record_reassignment(1, 2, 1);
        m.record_reassignment(1, 3, 2);
        assert_eq!(m.reassignments, 2);
    }
}
```

**Step 2: Register the module**

Add to `crates/ergo-network/src/lib.rs` (alphabetical, after `sync_manager`):

```rust
pub mod sync_metrics;
```

**Step 3: Run tests**

Run: `cargo test -p ergo-network sync_metrics -- --nocapture`
Expected: PASS (9 tests)

**Step 4: Commit**

```bash
git add crates/ergo-network/src/sync_metrics.rs crates/ergo-network/src/lib.rs
git commit -m "feat(network): add SyncMetrics with rolling window counters and batch tracking"
```

---

### Task 4: Configurable SyncInfo V2 Header Count

Make the SyncInfo V2 header count configurable via settings with clamping to 1..=50.

**Files:**
- Modify: `crates/ergo-settings/src/settings.rs:207` (add field after `sync_interval_stable_secs`)
- Modify: `crates/ergo-network/src/persistent_sync.rs:18,60` (use config value)

**Step 1: Write failing test for config clamping**

Add test in `crates/ergo-settings/src/settings.rs` (if a test module exists) or in `crates/ergo-network/src/persistent_sync.rs`. Since the clamping logic will be a simple function, add it to persistent_sync.rs tests:

In `crates/ergo-network/src/persistent_sync.rs`, add at the bottom:

```rust
/// Clamp sync_info_max_headers to valid range [1, 50].
pub fn clamp_sync_info_max_headers(value: u32) -> u32 {
    value.clamp(1, 50)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamp_sync_info_headers_zero() {
        assert_eq!(clamp_sync_info_max_headers(0), 1);
    }

    #[test]
    fn clamp_sync_info_headers_one() {
        assert_eq!(clamp_sync_info_max_headers(1), 1);
    }

    #[test]
    fn clamp_sync_info_headers_ten() {
        assert_eq!(clamp_sync_info_max_headers(10), 10);
    }

    #[test]
    fn clamp_sync_info_headers_fifty() {
        assert_eq!(clamp_sync_info_max_headers(50), 50);
    }

    #[test]
    fn clamp_sync_info_headers_above_max() {
        assert_eq!(clamp_sync_info_max_headers(51), 50);
    }

    #[test]
    fn clamp_sync_info_headers_large() {
        assert_eq!(clamp_sync_info_max_headers(u32::MAX), 50);
    }
}
```

**Step 2: Add setting field**

In `crates/ergo-settings/src/settings.rs`, add after the `sync_interval_stable_secs` field (around line 207):

```rust
#[serde(default = "default_sync_info_max_headers")]
pub sync_info_max_headers: u32,
```

And add the default function after the other defaults (around line 225):

```rust
fn default_sync_info_max_headers() -> u32 { 10 }
```

**Step 3: Update `build_sync_info_persistent` to accept max_headers**

In `crates/ergo-network/src/persistent_sync.rs`, change the function signature:

```rust
pub fn build_sync_info_persistent(db: &HistoryDb, max_headers: u32) -> Result<ErgoSyncInfo, PersistentSyncError> {
```

Replace `MAX_SYNC_HEADERS` usage with the clamped parameter:

```rust
let max_h = clamp_sync_info_max_headers(max_headers);
let start = if best_height > max_h {
    best_height - max_h + 1
} else {
    1
};
```

Remove or keep `const MAX_SYNC_HEADERS` as a dead-code reference (prefer removing it).

**Step 4: Update all callers**

Search for all callers of `build_sync_info_persistent` and add the `max_headers` parameter. Callers include:
- `crates/ergo-network/src/message_handler.rs` — in `handle_modifiers` (fast-path SyncInfo after headers applied)
- `crates/ergo-node/src/event_loop.rs` — in `handle_sync_tick` and anywhere SyncInfo is built

Each caller needs access to the settings value. Pass it through as a parameter or access from settings.

**Step 5: Add SyncInfo V1/V2 compatibility assertion**

In `crates/ergo-wire/src/handshake.rs` or as a test in persistent_sync.rs:

```rust
#[test]
fn eip37_fork_implies_sync_v2_support() {
    use ergo_wire::handshake::ProtocolVersion;
    // Every connected peer passes EIP37_FORK check (4.0.100),
    // which is >= SYNC_V2_MIN (4.0.16), so all peers support V2.
    assert!(ProtocolVersion::EIP37_FORK >= ProtocolVersion::SYNC_V2_MIN);
}
```

**Step 6: Run tests**

Run: `cargo test -p ergo-network clamp_sync_info -- --nocapture && cargo test -p ergo-network eip37_fork -- --nocapture`
Expected: PASS

Run: `cargo build -p ergo-node`
Expected: compiles (all callers updated)

**Step 7: Commit**

```bash
git add crates/ergo-settings/src/settings.rs crates/ergo-network/src/persistent_sync.rs crates/ergo-network/src/message_handler.rs crates/ergo-node/src/event_loop.rs
git commit -m "feat(settings): configurable SyncInfo V2 header count (1..50, default 10)"
```

---

### Task 5: Refactor `handle_inv` for Multi-Peer Header Partitioning

This is the core integration task. Refactor `handle_inv` to use the partitioner and metrics, with outstanding caps enforcement.

**Files:**
- Modify: `crates/ergo-network/src/message_handler.rs:474-558` (refactor `handle_inv`)
- Modify: `crates/ergo-network/src/message_handler.rs:999-1049` (update `handle_message_without_modifiers`)
- Modify: `crates/ergo-node/src/event_loop.rs:596-614` (pass new args to handler)

**Step 1: Update `handle_inv` signature and imports**

Add imports at the top of `message_handler.rs`:

```rust
use crate::header_partitioner::{self, EligiblePeers, DEFAULT_MIN_PER_PEER};
use crate::sync_metrics::SyncMetrics;
```

Change `handle_inv` signature (line 474):

```rust
fn handle_inv(
    peer_id: PeerId,
    body: &[u8],
    tracker: &mut DeliveryTracker,
    history: &HistoryDb,
    mempool: &crate::mempool::ErgoMemPool,
    is_synced_for_txs: bool,
    sync_tracker: &SyncTracker,
    connected_peers: &[PeerId],
    metrics: &mut SyncMetrics,
) -> HandleResult {
```

**Step 2: Rewrite `handle_inv` body for headers**

Replace the existing body with the multi-peer partitioning logic:

```rust
fn handle_inv(
    peer_id: PeerId,
    body: &[u8],
    tracker: &mut DeliveryTracker,
    history: &HistoryDb,
    mempool: &crate::mempool::ErgoMemPool,
    is_synced_for_txs: bool,
    sync_tracker: &SyncTracker,
    connected_peers: &[PeerId],
    metrics: &mut SyncMetrics,
) -> HandleResult {
    use std::time::Duration;

    let inv = match InvData::parse(body) {
        Ok(inv) => inv,
        Err(_) => return HandleResult::empty(),
    };

    let type_id = inv.type_id as u8;

    if type_id == 2 && !is_synced_for_txs {
        return HandleResult::empty();
    }

    let total_inv_ids = inv.ids.len();
    let stale_threshold = Duration::from_secs(1);

    // Phase 1: Filter IDs, preserving original Inv order. DO NOT call
    // set_requested yet — only mark requested for IDs we actually emit.
    let mut to_request: Vec<ModifierId> = Vec::new();
    let mut stale_count = 0u32;
    let mut dup_count = 0u32;

    for id in &inv.ids {
        let status = tracker.status(type_id, id);
        match status {
            ModifierStatus::Unknown => {
                let already_have = if type_id == 2 {
                    mempool.contains(&ergo_types::transaction::TxId(id.0))
                } else {
                    history.contains_modifier(type_id, id).unwrap_or(true)
                };
                if !already_have {
                    to_request.push(*id);
                }
            }
            ModifierStatus::Requested if type_id == HEADER_TYPE_ID => {
                if let Some(age) = tracker.request_age(type_id, id) {
                    if age >= stale_threshold {
                        to_request.push(*id);
                        stale_count += 1;
                    } else {
                        dup_count += 1;
                        metrics.record_dup_prevented();
                    }
                }
            }
            _ => {
                dup_count += 1;
                metrics.record_dup_prevented();
            }
        }
    }

    if to_request.is_empty() {
        tracing::trace!(type_id, total_inv_ids, "handle_inv: all known");
        return HandleResult::empty();
    }

    // Phase 2: For non-header types, use single-peer request (unchanged).
    if type_id != HEADER_TYPE_ID {
        for id in &to_request {
            tracker.set_requested(type_id, *id, peer_id);
        }
        tracing::info!(type_id, requested = to_request.len(), "handle_inv: requesting from announcing peer");
        return HandleResult {
            actions: vec![SyncAction::RequestModifiers {
                peer_id,
                type_id,
                ids: to_request,
            }],
            new_headers: Vec::new(),
            penalties: Vec::new(),
            applied_blocks: Vec::new(),
        };
    }

    // Phase 3: Header-specific multi-peer partitioning.
    let batch_id = metrics.new_batch_id();

    // Cap check: global outstanding
    const GLOBAL_OUTSTANDING_CAP: usize = 2400;
    const PER_PEER_OUTSTANDING_CAP: usize = 800;

    let global_outstanding = tracker.total_outstanding_headers();
    if global_outstanding >= GLOBAL_OUTSTANDING_CAP {
        tracing::warn!(
            batch_id,
            global_outstanding,
            to_request_len = to_request.len(),
            "cap_backpressure: global outstanding cap exceeded, skipping batch"
        );
        return HandleResult::empty();
    }

    tracing::info!(
        batch_id,
        peer = peer_id,
        inv_len = total_inv_ids,
        to_request_len = to_request.len(),
        stale_reassigned = stale_count,
        dup_prevented = dup_count,
        "inv_received"
    );

    // Peer selection
    let eligible = header_partitioner::select_eligible_peers(
        peer_id,
        sync_tracker,
        connected_peers,
    );

    let actions = match eligible {
        EligiblePeers::Partition(mut peers) => {
            // Filter out peers at per-peer cap
            peers.retain(|&pid| {
                tracker.outstanding_header_count(pid) < PER_PEER_OUTSTANDING_CAP
            });
            if peers.is_empty() {
                tracing::warn!(
                    batch_id,
                    "cap_backpressure_all_peers: all eligible peers at outstanding cap"
                );
                return HandleResult::empty();
            }

            let assignments = header_partitioner::partition_header_ids(
                &to_request,
                &peers,
                DEFAULT_MIN_PER_PEER,
            );

            let summary: Vec<(PeerId, usize)> = assignments
                .iter()
                .map(|(pid, chunk)| (*pid, chunk.len()))
                .collect();
            metrics.record_partition(batch_id, total_inv_ids, to_request.len(), &summary);

            let mut result_actions = Vec::with_capacity(assignments.len());
            let mut offset = 0;
            for (assigned_peer, chunk) in &assignments {
                // Handle stale reassignment for previously-requested IDs
                for id in chunk {
                    let was_stale = tracker.status(type_id, id) == ModifierStatus::Requested;
                    if was_stale {
                        tracker.reassign(type_id, id, *assigned_peer);
                    } else {
                        tracker.set_requested(type_id, *id, *assigned_peer);
                    }
                }

                metrics.record_requests_sent(
                    batch_id,
                    *assigned_peer,
                    chunk.len(),
                    offset,
                    offset + chunk.len() - 1,
                );
                offset += chunk.len();

                result_actions.push(SyncAction::RequestModifiers {
                    peer_id: *assigned_peer,
                    type_id,
                    ids: chunk.clone(),
                });
            }

            result_actions
        }
        EligiblePeers::SinglePeerFallback(fallback_peer, reason) => {
            // Per-peer cap check for single-peer fallback
            if tracker.outstanding_header_count(fallback_peer) >= PER_PEER_OUTSTANDING_CAP {
                tracing::warn!(
                    batch_id,
                    peer = fallback_peer,
                    reason,
                    "cap_backpressure_single_peer: fallback peer at outstanding cap"
                );
                return HandleResult::empty();
            }

            tracing::warn!(
                batch_id,
                peer = fallback_peer,
                reason,
                to_request_len = to_request.len(),
                "single_peer_fallback: partitioning skipped"
            );

            metrics.record_partition(
                batch_id,
                total_inv_ids,
                to_request.len(),
                &[(fallback_peer, to_request.len())],
            );

            for id in &to_request {
                let was_stale = tracker.status(type_id, id) == ModifierStatus::Requested;
                if was_stale {
                    tracker.reassign(type_id, id, fallback_peer);
                } else {
                    tracker.set_requested(type_id, *id, fallback_peer);
                }
            }

            metrics.record_requests_sent(
                batch_id,
                fallback_peer,
                to_request.len(),
                0,
                to_request.len().saturating_sub(1),
            );

            vec![SyncAction::RequestModifiers {
                peer_id: fallback_peer,
                type_id,
                ids: to_request,
            }]
        }
    };

    HandleResult {
        actions,
        new_headers: Vec::new(),
        penalties: Vec::new(),
        applied_blocks: Vec::new(),
    }
}
```

**Step 3: Update `handle_message_without_modifiers` call site (line 1034-1036)**

Change:
```rust
55 => {
    let mp = mempool.read().unwrap();
    handle_inv(peer_id, &msg.body, tracker, history, &mp, is_synced_for_txs)
}
```

To:
```rust
55 => {
    let mp = mempool.read().unwrap();
    handle_inv(
        peer_id,
        &msg.body,
        tracker,
        history,
        &mp,
        is_synced_for_txs,
        sync_tracker,
        connected_peer_ids,
        metrics,
    )
}
```

This means `handle_message_without_modifiers` needs new parameters:
- `connected_peer_ids: &[PeerId]`
- `metrics: &mut SyncMetrics`

Update its signature accordingly.

**Step 4: Update event loop call site (line 596-614)**

In `crates/ergo-node/src/event_loop.rs`, where `handle_message_without_modifiers` is called:

Before the call, snapshot connected peer IDs:

```rust
let connected_peer_ids: Vec<u64> = pool
    .connected_peers()
    .iter()
    .map(|p| p.id)
    .collect();
```

Add `&connected_peer_ids` and `&mut sync_metrics` to the call.

Also add `let mut sync_metrics = SyncMetrics::new(10);` near the top of the event loop where other state is initialized.

**Step 5: Add periodic rollup emission**

In the event loop, add `sync_metrics.maybe_emit_rollup()` to an existing periodic tick (e.g., the `status_tick` which runs every 10s):

```rust
sync_metrics.maybe_emit_rollup();
```

**Step 6: Run compilation**

Run: `cargo build -p ergo-node`
Expected: compiles

**Step 7: Run existing tests**

Run: `cargo test -p ergo-network -- --nocapture`
Expected: all existing tests pass (may need to update test call sites for `handle_inv` with new params)

**Step 8: Update existing `handle_inv` tests**

Any existing tests that call `handle_inv` directly need the three new parameters. Create a dummy `SyncTracker` and `SyncMetrics` for them:

```rust
let mut sync_tracker = SyncTracker::new();
let connected: Vec<u64> = vec![peer_id];
let mut metrics = SyncMetrics::new(10);
```

**Step 9: Commit**

```bash
git add crates/ergo-network/src/message_handler.rs crates/ergo-node/src/event_loop.rs
git commit -m "feat(network): multi-peer header partitioning in handle_inv with outstanding caps"
```

---

### Task 6: Enhanced Stale Header Tick with Cap-Aware Reassignment

Update the stale header tick to check per-peer outstanding caps before reassigning.

**Files:**
- Modify: `crates/ergo-node/src/event_loop.rs:881-916` (stale_header_tick handler)

**Step 1: Update the stale header tick handler**

Replace the current stale_header_tick handler:

```rust
_ = stale_header_tick.tick() => {
    let stale = tracker.collect_stale_headers(Duration::from_secs(2));
    if stale.is_empty() {
        continue;
    }
    let cands = sync_tracker.peers_for_downloading_blocks();
    if cands.is_empty() {
        continue;
    }

    let mut reassigned = 0u32;
    let mut deferred = 0u32;
    let mut per_peer_batch: HashMap<u64, Vec<ergo_types::modifier_id::ModifierId>> = HashMap::new();

    for (id, stale_peer) in &stale {
        // Find an alternative peer that is not the stale peer and under the cap
        if let Some(&alt) = cands.iter().find(|&&p| {
            p != *stale_peer && tracker.outstanding_header_count(p) < 800
        }) {
            tracker.reassign(101, id, alt);
            per_peer_batch.entry(alt).or_default().push(*id);
            reassigned += 1;
            sync_metrics.record_reassignment(*stale_peer, alt, 0);
        } else {
            deferred += 1;
        }
    }

    // Send batched RequestModifiers per target peer
    for (alt, ids) in &per_peer_batch {
        let inv = ergo_wire::inv::InvData {
            type_id: 101,
            ids: ids.clone(),
        };
        let _ = pool.send_to(*alt, MessageCode::RequestModifier as u8, inv.serialize()).await;
    }

    if reassigned > 0 || deferred > 0 {
        tracing::info!(
            stale = stale.len(),
            reassigned,
            deferred,
            target_peers = per_peer_batch.len(),
            "stale header tick"
        );
    }
}
```

**Step 2: Compile and run**

Run: `cargo build -p ergo-node`
Expected: compiles

**Step 3: Commit**

```bash
git add crates/ergo-node/src/event_loop.rs
git commit -m "feat(network): cap-aware stale header reassignment with per-peer batching"
```

---

### Task 7: Unit Tests for Multi-Peer `handle_inv`

Add comprehensive unit tests exercising the refactored `handle_inv`.

**Files:**
- Modify: `crates/ergo-network/src/message_handler.rs` (test module at bottom)

**Step 1: Write tests**

Add these tests to the existing `#[cfg(test)] mod tests` in `message_handler.rs`:

```rust
#[test]
fn handle_inv_header_single_peer_when_sender_not_older() {
    // When inv_sender is not classified Older, should fallback to single-peer
    let mut tracker = DeliveryTracker::new(60, 2);
    let mut sync_tracker = SyncTracker::new();
    sync_tracker.update_status(1, PeerChainStatus::Younger, Some(50));
    let mut metrics = SyncMetrics::new(10);
    let connected = vec![1u64];

    let ids = (0..100u8).map(|i| {
        let mut bytes = [0u8; 32];
        bytes[0] = i;
        ModifierId(bytes)
    }).collect::<Vec<_>>();

    let inv = InvData { type_id: HEADER_TYPE_ID as i8, ids };
    let body = inv.serialize();

    // Need a HistoryDb that says "don't have these"
    let tmp = tempfile::tempdir().unwrap();
    let history = HistoryDb::open(tmp.path()).unwrap();
    let mempool = crate::mempool::ErgoMemPool::new(1000, 100_000);

    let result = handle_inv(
        1, &body, &mut tracker, &history, &mempool,
        false, &sync_tracker, &connected, &mut metrics,
    );

    // Should have exactly 1 RequestModifiers action to peer 1
    assert_eq!(result.actions.len(), 1);
    match &result.actions[0] {
        SyncAction::RequestModifiers { peer_id, type_id, ids } => {
            assert_eq!(*peer_id, 1);
            assert_eq!(*type_id, HEADER_TYPE_ID);
            assert_eq!(ids.len(), 100);
        }
        _ => panic!("expected RequestModifiers"),
    }
}

#[test]
fn handle_inv_header_multi_peer_partitioning() {
    // 3 Older peers: should partition across all 3
    let mut tracker = DeliveryTracker::new(60, 2);
    let mut sync_tracker = SyncTracker::new();
    sync_tracker.update_status(1, PeerChainStatus::Older, Some(1000));
    sync_tracker.update_status(2, PeerChainStatus::Older, Some(1000));
    sync_tracker.update_status(3, PeerChainStatus::Older, Some(1000));
    let mut metrics = SyncMetrics::new(10);
    let connected = vec![1u64, 2, 3];

    let ids = (0..150u8).map(|i| {
        let mut bytes = [0u8; 32];
        bytes[0] = i;
        ModifierId(bytes)
    }).collect::<Vec<_>>();

    let inv = InvData { type_id: HEADER_TYPE_ID as i8, ids };
    let body = inv.serialize();

    let tmp = tempfile::tempdir().unwrap();
    let history = HistoryDb::open(tmp.path()).unwrap();
    let mempool = crate::mempool::ErgoMemPool::new(1000, 100_000);

    let result = handle_inv(
        1, &body, &mut tracker, &history, &mempool,
        false, &sync_tracker, &connected, &mut metrics,
    );

    // Should have 3 RequestModifiers actions
    assert_eq!(result.actions.len(), 3);
    let mut total_ids = 0;
    for action in &result.actions {
        match action {
            SyncAction::RequestModifiers { type_id, ids, .. } => {
                assert_eq!(*type_id, HEADER_TYPE_ID);
                assert_eq!(ids.len(), 50);
                total_ids += ids.len();
            }
            _ => panic!("expected RequestModifiers"),
        }
    }
    assert_eq!(total_ids, 150);
}

#[test]
fn handle_inv_global_cap_backpressure() {
    // Fill tracker to global cap, verify no new requests emitted
    let mut tracker = DeliveryTracker::new(60, 2);
    // Insert 2400 outstanding headers
    for i in 0..2400u32 {
        let mut bytes = [0u8; 32];
        bytes[0..4].copy_from_slice(&i.to_be_bytes());
        tracker.set_requested(101, ModifierId(bytes), 99);
    }

    let mut sync_tracker = SyncTracker::new();
    sync_tracker.update_status(1, PeerChainStatus::Older, Some(1000));
    let mut metrics = SyncMetrics::new(10);
    let connected = vec![1u64];

    let new_id = ModifierId([0xFF; 32]);
    let inv = InvData { type_id: HEADER_TYPE_ID as i8, ids: vec![new_id] };
    let body = inv.serialize();

    let tmp = tempfile::tempdir().unwrap();
    let history = HistoryDb::open(tmp.path()).unwrap();
    let mempool = crate::mempool::ErgoMemPool::new(1000, 100_000);

    let result = handle_inv(
        1, &body, &mut tracker, &history, &mempool,
        false, &sync_tracker, &connected, &mut metrics,
    );

    // Should emit nothing due to global cap
    assert!(result.actions.is_empty());
}

#[test]
fn handle_inv_non_header_unchanged() {
    // Non-header type_id should use single-peer, no partitioning
    let mut tracker = DeliveryTracker::new(60, 2);
    let mut sync_tracker = SyncTracker::new();
    sync_tracker.update_status(1, PeerChainStatus::Older, Some(1000));
    sync_tracker.update_status(2, PeerChainStatus::Older, Some(1000));
    let mut metrics = SyncMetrics::new(10);
    let connected = vec![1u64, 2];

    let id = ModifierId([0xBB; 32]);
    let inv = InvData { type_id: 102, ids: vec![id] }; // block transactions
    let body = inv.serialize();

    let tmp = tempfile::tempdir().unwrap();
    let history = HistoryDb::open(tmp.path()).unwrap();
    let mempool = crate::mempool::ErgoMemPool::new(1000, 100_000);

    let result = handle_inv(
        1, &body, &mut tracker, &history, &mempool,
        false, &sync_tracker, &connected, &mut metrics,
    );

    // Should have exactly 1 action to peer 1 (no partitioning for non-headers)
    assert_eq!(result.actions.len(), 1);
    match &result.actions[0] {
        SyncAction::RequestModifiers { peer_id, .. } => assert_eq!(*peer_id, 1),
        _ => panic!("expected RequestModifiers"),
    }
}
```

**Step 2: Run tests**

Run: `cargo test -p ergo-network handle_inv -- --nocapture`
Expected: PASS

**Step 3: Commit**

```bash
git add crates/ergo-network/src/message_handler.rs
git commit -m "test(network): add multi-peer handle_inv unit tests with cap backpressure"
```

---

### Task 8: Integration Tests in ergo-testkit

Add integration tests for multi-peer header download scenarios.

**Files:**
- Create or modify: `crates/ergo-testkit/tests/multi_peer_sync.rs`

**Step 1: Create integration test file**

This test exercises the partitioner + DeliveryTracker + SyncTracker together in a simulated multi-peer scenario. It cannot do real network I/O but verifies the action dispatch logic end-to-end.

Create `crates/ergo-testkit/tests/multi_peer_sync.rs`:

```rust
//! Integration tests for multi-peer header download partitioning.
//!
//! These tests combine ergo-network components (header_partitioner,
//! DeliveryTracker, SyncTracker, SyncMetrics) to verify end-to-end
//! correctness of the partitioning pipeline without real network I/O.

use ergo_network::delivery_tracker::DeliveryTracker;
use ergo_network::header_partitioner::{
    self, partition_header_ids, select_eligible_peers, EligiblePeers, DEFAULT_MIN_PER_PEER,
};
use ergo_network::sync_metrics::SyncMetrics;
use ergo_network::sync_tracker::{PeerChainStatus, SyncTracker};
use ergo_types::modifier_id::ModifierId;

fn make_id(byte: u8) -> ModifierId {
    let mut bytes = [0u8; 32];
    bytes[0] = byte;
    ModifierId(bytes)
}

fn make_ids(n: usize) -> Vec<ModifierId> {
    (0..n)
        .map(|i| {
            let mut bytes = [0u8; 32];
            bytes[0..2].copy_from_slice(&(i as u16).to_be_bytes());
            ModifierId(bytes)
        })
        .collect()
}

/// Test: single peer ahead behaves identically to pre-change (single RequestModifiers).
#[test]
fn single_peer_ahead_baseline() {
    let ids = make_ids(200);
    let peers = vec![1u64];
    let result = partition_header_ids(&ids, &peers, DEFAULT_MIN_PER_PEER);
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].0, 1);
    assert_eq!(result[0].1.len(), 200);
}

/// Test: 3 peers ahead distributes across all 3.
#[test]
fn three_peers_ahead_distributes() {
    let mut st = SyncTracker::new();
    st.update_status(1, PeerChainStatus::Older, Some(1000));
    st.update_status(2, PeerChainStatus::Older, Some(1000));
    st.update_status(3, PeerChainStatus::Older, Some(1000));

    let connected = vec![1u64, 2, 3];
    let eligible = select_eligible_peers(1, &st, &connected);

    match eligible {
        EligiblePeers::Partition(peers) => {
            assert_eq!(peers.len(), 3);
            let ids = make_ids(300);
            let result = partition_header_ids(&ids, &peers, DEFAULT_MIN_PER_PEER);
            assert_eq!(result.len(), 3);
            for (_, chunk) in &result {
                assert_eq!(chunk.len(), 100);
            }
            // Verify all IDs assigned
            let all: Vec<ModifierId> =
                result.iter().flat_map(|(_, c)| c.iter().copied()).collect();
            assert_eq!(all, ids);
        }
        _ => panic!("expected Partition"),
    }
}

/// Test: timeout simulation — tracker correctly identifies expired requests.
#[test]
fn timeout_enables_reassignment() {
    let mut tracker = DeliveryTracker::new(0, 2); // 0s timeout = immediate
    let id = make_id(0x01);
    tracker.set_requested(101, id, 1);

    let timed_out = tracker.collect_timed_out();
    assert_eq!(timed_out.len(), 1);
    assert_eq!(timed_out[0].2, 1); // original peer

    // Reassign to peer 2
    tracker.reassign(101, &id, 2);

    // Verify reassigned
    let timed_out2 = tracker.collect_timed_out();
    assert_eq!(timed_out2.len(), 1);
    assert_eq!(timed_out2[0].2, 2); // now peer 2
}

/// Test: outstanding cap prevents new requests.
#[test]
fn outstanding_cap_blocks_new_requests() {
    let mut tracker = DeliveryTracker::new(60, 2);

    // Fill peer 1 to cap
    for i in 0..800u32 {
        let mut bytes = [0u8; 32];
        bytes[0..4].copy_from_slice(&i.to_be_bytes());
        tracker.set_requested(101, ModifierId(bytes), 1);
    }

    assert_eq!(tracker.outstanding_header_count(1), 800);
    assert_eq!(tracker.total_outstanding_headers(), 800);

    // Peer 2 still has room
    assert_eq!(tracker.outstanding_header_count(2), 0);
}

/// Test: cap-aware reassignment walks eligible peers.
#[test]
fn cap_aware_reassignment() {
    let mut tracker = DeliveryTracker::new(60, 2);

    // Fill peer 2 to cap
    for i in 0..800u32 {
        let mut bytes = [0u8; 32];
        bytes[0..4].copy_from_slice(&i.to_be_bytes());
        tracker.set_requested(101, ModifierId(bytes), 2);
    }

    // Request from peer 1
    let stale_id = make_id(0xFF);
    tracker.set_requested(101, stale_id, 1);

    // Try to reassign to peer 2 (at cap) — should not reassign
    let alt_peers = vec![2u64, 3u64];
    let target = alt_peers
        .iter()
        .find(|&&p| p != 1 && tracker.outstanding_header_count(p) < 800);

    // Peer 2 at cap, peer 3 has room
    assert_eq!(*target.unwrap(), 3);
}

/// Test: property-style coverage check for various N and K.
#[test]
fn partition_coverage_property() {
    for n in [1, 10, 49, 50, 51, 99, 100, 150, 200, 399, 400, 500] {
        for k in 1..=8 {
            let ids = make_ids(n);
            let peers: Vec<u64> = (1..=k).collect();
            let result = partition_header_ids(&ids, &peers, DEFAULT_MIN_PER_PEER);

            // Union equals original (capped at 400)
            let all: Vec<ModifierId> =
                result.iter().flat_map(|(_, c)| c.iter().copied()).collect();
            let expected_len = n.min(400);
            assert_eq!(
                all.len(),
                expected_len,
                "coverage failed for n={n}, k={k}"
            );
            assert_eq!(all, ids[..expected_len]);

            // Chunks are disjoint (verified by contiguous assignment)
            let mut total = 0;
            for (_, chunk) in &result {
                total += chunk.len();
            }
            assert_eq!(total, expected_len, "total != expected for n={n}, k={k}");

            // Min per peer respected (unless single peer)
            if result.len() > 1 {
                for (_, chunk) in &result {
                    assert!(
                        chunk.len() >= DEFAULT_MIN_PER_PEER,
                        "chunk {} < min {} for n={n}, k={k}",
                        chunk.len(),
                        DEFAULT_MIN_PER_PEER
                    );
                }
            }
        }
    }
}

/// Test: metrics batch lifecycle.
#[test]
fn metrics_batch_lifecycle() {
    let mut metrics = SyncMetrics::new(10);
    let batch_id = metrics.new_batch_id();

    metrics.record_partition(batch_id, 200, 200, &[(1, 100), (2, 100)]);
    // Batch should be active
    metrics.record_headers_applied(batch_id, 100, 0, 0, 50, 20, 70);
    // Still active (100/200)
    metrics.record_headers_applied(batch_id, 100, 0, 0, 50, 20, 70);
    // Now complete (200/200) — internally removed from active_batches
}

/// Test: classification mismatch produces SinglePeerFallback.
#[test]
fn classification_mismatch_single_peer_fallback() {
    let mut st = SyncTracker::new();
    st.update_status(1, PeerChainStatus::Fork, Some(100));
    st.update_status(2, PeerChainStatus::Older, Some(200));

    let connected = vec![1u64, 2];
    match select_eligible_peers(1, &st, &connected) {
        EligiblePeers::SinglePeerFallback(peer, reason) => {
            assert_eq!(peer, 1);
            assert!(reason.contains("Fork"));
        }
        _ => panic!("expected SinglePeerFallback for Fork sender"),
    }
}
```

**Step 2: Update ergo-testkit Cargo.toml**

Ensure `ergo-network` is in `[dev-dependencies]` of `crates/ergo-testkit/Cargo.toml`. Check first — it may already be there.

**Step 3: Run tests**

Run: `cargo test -p ergo-testkit multi_peer_sync -- --nocapture`
Expected: PASS

**Step 4: Commit**

```bash
git add crates/ergo-testkit/tests/multi_peer_sync.rs crates/ergo-testkit/Cargo.toml
git commit -m "test(testkit): add multi-peer header download integration tests"
```

---

### Task 9: SyncInfo V1/V2 Round-Trip Tests

Add round-trip serialization tests and the EIP37 >= SYNC_V2_MIN assertion.

**Files:**
- Modify: `crates/ergo-wire/src/sync_info.rs` (add tests) OR create test in ergo-testkit
- Modify: `crates/ergo-wire/src/handshake.rs` (add assertion test)

**Step 1: Add V1/V2 round-trip tests**

In `crates/ergo-wire/src/sync_info.rs` test module (or create one):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v2_round_trip_single_header() {
        let header = ergo_types::header::Header::default_for_test();
        let v2 = ErgoSyncInfoV2 {
            last_headers: vec![header.clone()],
        };
        let sync = ErgoSyncInfo::V2(v2);
        let bytes = match &sync {
            ErgoSyncInfo::V2(v) => v.serialize(),
            _ => unreachable!(),
        };
        let parsed = ErgoSyncInfo::parse(&bytes).unwrap();
        match parsed {
            ErgoSyncInfo::V2(v) => {
                assert_eq!(v.last_headers.len(), 1);
            }
            _ => panic!("expected V2"),
        }
    }

    #[test]
    fn v2_round_trip_fifty_headers() {
        let headers: Vec<_> = (0..50)
            .map(|i| {
                let mut h = ergo_types::header::Header::default_for_test();
                h.height = i;
                h
            })
            .collect();
        let v2 = ErgoSyncInfoV2 {
            last_headers: headers.clone(),
        };
        let bytes = v2.serialize();
        let parsed = ErgoSyncInfo::parse(&bytes).unwrap();
        match parsed {
            ErgoSyncInfo::V2(v) => {
                assert_eq!(v.last_headers.len(), 50);
            }
            _ => panic!("expected V2"),
        }
    }

    #[test]
    fn v2_empty_round_trip() {
        let v2 = ErgoSyncInfoV2 {
            last_headers: vec![],
        };
        let bytes = v2.serialize();
        let parsed = ErgoSyncInfo::parse(&bytes).unwrap();
        match parsed {
            ErgoSyncInfo::V2(v) => {
                assert!(v.last_headers.is_empty());
            }
            _ => panic!("expected V2"),
        }
    }
}
```

**Step 2: Add EIP37 >= SYNC_V2_MIN assertion**

In `crates/ergo-wire/src/handshake.rs` test module:

```rust
#[test]
fn eip37_fork_implies_sync_v2_support() {
    // All connected peers pass EIP37_FORK (4.0.100) version check,
    // which is >= SYNC_V2_MIN (4.0.16). Therefore all peers support V2.
    assert!(ProtocolVersion::EIP37_FORK >= ProtocolVersion::SYNC_V2_MIN);
}
```

**Step 3: Run tests**

Run: `cargo test -p ergo-wire sync_info -- --nocapture && cargo test -p ergo-wire eip37_fork -- --nocapture`
Expected: PASS

**Step 4: Commit**

```bash
git add crates/ergo-wire/src/sync_info.rs crates/ergo-wire/src/handshake.rs
git commit -m "test(wire): add SyncInfo V1/V2 round-trip tests and EIP37 version assertion"
```

---

### Task 10: Full Test Suite + Clippy Validation

Run the complete test suite and clippy across the entire workspace.

**Files:** None (verification only)

**Step 1: Run all tests**

Run: `cargo test --workspace`
Expected: All tests pass. Verify count is >= 547 (existing) + ~50 new tests.

**Step 2: Run clippy**

Run: `cargo clippy --workspace -- -D warnings`
Expected: 0 warnings

**Step 3: Run build**

Run: `cargo build -p ergo-node --release`
Expected: compiles cleanly

**Step 4: Final commit (if any fixups needed)**

```bash
git add -A
git commit -m "fix: address clippy warnings and test fixups for multi-peer header download"
```

---

### Task 11: Write Short Report

Document what changed, proof points for correctness, and metrics interpretation.

**Files:**
- Create: `docs/plans/2026-03-01-multi-peer-header-download-report.md`

Write a concise report covering:
1. Summary of changes (files, new modules, LOC estimate)
2. Correctness proof points (each invariant from design doc, how tests verify it)
3. Metrics interpretation guide (what each rollup field means, how to read logs)
4. Known limitations (Fork peers excluded, no proactive solicitation, no perf stats for peer ordering)
5. Optional future work (configurable delivery timeout, SyncInfo cooldown)

**Step 1: Write the report**

(Content to be written during implementation based on actual outcomes.)

**Step 2: Commit**

```bash
git add -f docs/plans/2026-03-01-multi-peer-header-download-report.md
git commit -m "docs: add multi-peer header download implementation report"
```
