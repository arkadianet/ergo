//! Chunk-assembly state machine for the Mode 2 UTXO snapshot
//! bootstrap: bounded-inflight `GetUtxoSnapshotChunk` scheduling,
//! strict-ownership receive accounting, and per-chunk timeouts.
//! Fully independent of the manifest-discovery reducer in
//! [`super::manifest`].

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use ergo_p2p::peer::PeerId;
use ergo_primitives::digest::Digest32;

/// Maximum concurrent `GetUtxoSnapshotChunk` requests across all
/// peers. Caps memory + outbound bandwidth during bootstrap.
/// Scala default for snapshot chunk fetch. Sized so a single
/// peer-window TCP buffer doesn't bottleneck the inflight set.
pub const MAX_INFLIGHT_CHUNKS: usize = 16;

/// Per-chunk request timeout. Same intent as
/// [`MANIFEST_REQUEST_TIMEOUT`] but applied to each
/// `GetUtxoSnapshotChunk` independently. A silent peer's chunk
/// slot is freed and re-tried against another quorum voter.
pub const CHUNK_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Chunk-assembly state machine. Owns the bounded-inflight
/// request set for a single bootstrap's chunk-download phase.
///
/// Lifecycle:
///
/// 1. Initialize with the expected chunk subtree IDs from
///    `ergo_state::avl::snapshot_codec::enumerate_expected_chunk_ids`
///    (DFS order from the verified manifest).
/// 2. Each tick: `next_to_request(now)` returns chunks the
///    integration layer should fan out (capped at
///    [`MAX_INFLIGHT_CHUNKS`] - currently-inflight). The caller
///    sends `GetUtxoSnapshotChunk` and pairs each with
///    `mark_requested`.
/// 3. `on_chunk_received(peer, subtree_id, bytes)` validates
///    strict ownership and bookkeeping; bytes are stashed only on
///    accept.
/// 4. `check_timeouts(now)` rolls back stalled chunk slots so
///    they re-enter the request queue (potentially against
///    another voter).
/// 5. When `is_complete()` returns true, `take_chunks()` hands
///    the map off to the reconstructor exactly once.
///
/// **Eligibility filtering is the caller's responsibility.** This
/// reducer accepts any peer the caller pairs with a request; the
/// integration layer must ensure that peer is in the quorum-voter
/// set for the selected `(height, manifest_id)`.
pub struct ChunkAssembly {
    /// All expected chunk subtree IDs. Order is preserved from the
    /// manifest DFS so the integration layer can fan out in the
    /// same order peers expect (irrelevant to consensus, but it
    /// keeps logs grep-friendly).
    expected: Vec<Digest32>,
    /// Set of expected IDs for O(1) authenticity checks on
    /// inbound chunks. Saves a linear scan of `expected` when a
    /// reply arrives.
    expected_set: HashSet<Digest32>,
    /// In-flight requests: subtree_id → (peer, when requested).
    inflight: HashMap<Digest32, ChunkRequestInflight>,
    /// Received bytes, validated by `on_chunk_received`.
    received: HashMap<Digest32, Vec<u8>>,
    /// True after `take_chunks` is called. Subsequent state
    /// transitions are forbidden (the chunk-set was handed off).
    consumed: bool,
}

#[derive(Debug, Clone, Copy)]
struct ChunkRequestInflight {
    peer: PeerId,
    requested_at: Instant,
}

/// Outcome of [`ChunkAssembly::on_chunk_received`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkReceiveOutcome {
    /// Bytes were accepted and stashed. The integration layer can
    /// continue fan-out for remaining chunks.
    Accepted,
    /// We weren't expecting a chunk with this subtree_id. Could
    /// be a peer pushing unsolicited data or a leftover from a
    /// previous bootstrap session. Silently drop.
    UnknownSubtreeId,
    /// We have this chunk in-flight but it's owned by a different
    /// peer. Silently drop — the rightful owner's response is
    /// still expected.
    WrongPeer,
    /// We already received this chunk. Idempotent drop — peers
    /// retransmitting on packet loss / TCP races don't replace
    /// already-stored bytes.
    Duplicate,
}

impl ChunkAssembly {
    /// Initialize the assembly with the expected chunk IDs from
    /// the verified manifest. Empty list = no chunks needed
    /// (entire tree fits in the manifest); `is_complete()`
    /// returns true immediately in that case.
    pub fn new(expected: Vec<Digest32>) -> Self {
        let expected_set = expected.iter().copied().collect();
        Self {
            expected,
            expected_set,
            inflight: HashMap::new(),
            received: HashMap::new(),
            consumed: false,
        }
    }

    /// Return up to `MAX_INFLIGHT_CHUNKS - current_inflight`
    /// chunk IDs that haven't been requested or received yet.
    /// Order matches `expected` (the manifest's DFS order).
    pub fn next_to_request(&self) -> Vec<Digest32> {
        if self.consumed {
            return Vec::new();
        }
        let slots = MAX_INFLIGHT_CHUNKS.saturating_sub(self.inflight.len());
        if slots == 0 {
            return Vec::new();
        }
        self.expected
            .iter()
            .filter(|id| !self.inflight.contains_key(id) && !self.received.contains_key(id))
            .copied()
            .take(slots)
            .collect()
    }

    /// Record that `GetUtxoSnapshotChunk(subtree_id)` was sent to
    /// `peer`. Pair with [`Self::next_to_request`] in the fan-out
    /// loop. Idempotent at the (peer, subtree_id) level — a
    /// repeated call updates `requested_at` so timeout-eviction
    /// uses the most recent send.
    pub fn mark_requested(&mut self, subtree_id: Digest32, peer: PeerId, now: Instant) {
        debug_assert!(
            !self.consumed,
            "mark_requested after take_chunks (consumed)",
        );
        debug_assert!(
            self.expected_set.contains(&subtree_id),
            "mark_requested for an unknown subtree_id — integration bug",
        );
        self.inflight.insert(
            subtree_id,
            ChunkRequestInflight {
                peer,
                requested_at: now,
            },
        );
    }

    /// Inbound `UtxoSnapshotChunk` (code 81) bytes for a peer-
    /// supplied `subtree_id`. Validates strict ownership against
    /// the inflight set. Returns [`ChunkReceiveOutcome`] reflecting
    /// what the caller should do.
    pub fn on_chunk_received(
        &mut self,
        from_peer: PeerId,
        subtree_id: Digest32,
        bytes: Vec<u8>,
    ) -> ChunkReceiveOutcome {
        if self.consumed {
            return ChunkReceiveOutcome::UnknownSubtreeId;
        }
        if !self.expected_set.contains(&subtree_id) {
            return ChunkReceiveOutcome::UnknownSubtreeId;
        }
        if self.received.contains_key(&subtree_id) {
            return ChunkReceiveOutcome::Duplicate;
        }
        let Some(inflight) = self.inflight.get(&subtree_id) else {
            // No request pending for this subtree_id — unsolicited.
            return ChunkReceiveOutcome::UnknownSubtreeId;
        };
        if inflight.peer != from_peer {
            return ChunkReceiveOutcome::WrongPeer;
        }
        self.inflight.remove(&subtree_id);
        self.received.insert(subtree_id, bytes);
        ChunkReceiveOutcome::Accepted
    }

    /// Roll back in-flight chunk slots whose request is older than
    /// [`CHUNK_REQUEST_TIMEOUT`]. Returns the freed subtree IDs so
    /// the caller can log / re-account (the IDs naturally re-enter
    /// the queue via `next_to_request`). Idempotent if no slots
    /// are stale.
    pub fn check_timeouts(&mut self, now: Instant) -> Vec<Digest32> {
        if self.consumed {
            return Vec::new();
        }
        let stale: Vec<Digest32> = self
            .inflight
            .iter()
            .filter_map(|(id, req)| {
                if now.duration_since(req.requested_at) >= CHUNK_REQUEST_TIMEOUT {
                    Some(*id)
                } else {
                    None
                }
            })
            .collect();
        for id in &stale {
            self.inflight.remove(id);
        }
        stale
    }

    /// Drop a specific peer's in-flight chunk requests (e.g. on
    /// peer disconnect). Returns the subtree IDs freed so they
    /// re-enter the request queue.
    pub fn drop_peer(&mut self, peer: &PeerId) -> Vec<Digest32> {
        if self.consumed {
            return Vec::new();
        }
        let dropped: Vec<Digest32> = self
            .inflight
            .iter()
            .filter_map(|(id, req)| if req.peer == *peer { Some(*id) } else { None })
            .collect();
        for id in &dropped {
            self.inflight.remove(id);
        }
        dropped
    }

    /// True when every expected chunk has been received.
    pub fn is_complete(&self) -> bool {
        !self.consumed && self.received.len() == self.expected.len()
    }

    /// Number of expected chunks. Useful for progress reporting.
    pub fn total_count(&self) -> usize {
        self.expected.len()
    }

    /// Number of chunks received so far.
    pub fn received_count(&self) -> usize {
        self.received.len()
    }

    /// Hand the received chunks off to the reconstructor exactly
    /// once. After this call the assembly is marked `consumed`;
    /// further state mutations are debug-asserted away. Returns
    /// `None` if not yet complete or already consumed.
    pub fn take_chunks(&mut self) -> Option<HashMap<Digest32, Vec<u8>>> {
        if self.consumed || !self.is_complete() {
            return None;
        }
        self.consumed = true;
        Some(std::mem::take(&mut self.received))
    }
}
