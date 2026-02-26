//! UTXO snapshot bootstrap — client-side download and reconstruction.
//!
//! [`SnapshotDiscovery`] collects `SnapshotsInfo` responses from peers,
//! decides which snapshot to download, and manages the chunk download plan
//! via [`SnapshotDownloadPlan`].

use std::collections::HashMap;

use crate::snapshots::SnapshotsInfo;

/// Maximum number of chunks downloading concurrently.
const CHUNKS_IN_PARALLEL: usize = 16;

// ---------------------------------------------------------------------------
// SnapshotDownloadPlan
// ---------------------------------------------------------------------------

/// Tracks the progress of downloading a UTXO set snapshot.
pub struct SnapshotDownloadPlan {
    pub snapshot_height: u32,
    pub manifest_id: [u8; 32],
    pub root_digest: [u8; 33],
    pub chunk_ids: Vec<[u8; 32]>,
    downloaded: Vec<bool>,
    in_flight: Vec<bool>,
}

impl SnapshotDownloadPlan {
    /// Returns the number of chunks downloaded so far.
    pub fn downloaded_count(&self) -> usize {
        self.downloaded.iter().filter(|&&d| d).count()
    }

    /// Returns the total number of chunks.
    pub fn total_chunks(&self) -> usize {
        self.chunk_ids.len()
    }

    /// Returns the number of chunks currently in flight.
    fn in_flight_count(&self) -> usize {
        self.in_flight.iter().filter(|&&f| f).count()
    }
}

// ---------------------------------------------------------------------------
// SnapshotDiscovery
// ---------------------------------------------------------------------------

/// Snapshot discovery and download coordinator.
///
/// Collects `SnapshotsInfo` responses from peers, decides which snapshot
/// to download, and manages the chunk download plan.
pub struct SnapshotDiscovery {
    /// manifest_id -> (height, Vec<peer_id>)
    available: HashMap<[u8; 32], (u32, Vec<u64>)>,
    /// Active download plan (if any).
    pub plan: Option<SnapshotDownloadPlan>,
    /// Minimum number of peers that must have the same snapshot before download.
    min_peers: u32,
}

impl SnapshotDiscovery {
    pub fn new(min_peers: u32) -> Self {
        Self {
            available: HashMap::new(),
            plan: None,
            min_peers,
        }
    }

    /// Record a `SnapshotsInfo` response from a peer.
    ///
    /// `header_state_roots` maps a block height to the expected state root
    /// digest from our header chain (for validation).
    pub fn record_info(
        &mut self,
        peer_id: u64,
        info: &SnapshotsInfo,
        header_state_roots: &dyn Fn(u32) -> Option<[u8; 33]>,
    ) {
        for (height, manifest_id) in &info.manifests {
            if header_state_roots(*height).is_none() {
                continue;
            }
            let entry = self
                .available
                .entry(*manifest_id)
                .or_insert((*height, Vec::new()));
            if !entry.1.contains(&peer_id) {
                entry.1.push(peer_id);
            }
        }
    }

    /// Check if we have enough peers for any snapshot and should start downloading.
    ///
    /// Returns `(manifest_id, height, peers)` for the best available snapshot,
    /// or `None` if we don't have enough peers yet.
    pub fn ready_to_download(&self) -> Option<([u8; 32], u32, Vec<u64>)> {
        if self.plan.is_some() {
            return None;
        }
        self.available
            .iter()
            .filter(|(_, (_, peers))| peers.len() as u32 >= self.min_peers)
            .max_by_key(|(_, (height, _))| *height)
            .map(|(id, (height, peers))| (*id, *height, peers.clone()))
    }

    /// Create a download plan from a received manifest.
    pub fn start_download(
        &mut self,
        manifest: &crate::snapshots::SnapshotManifest,
        manifest_id: [u8; 32],
        _peers: Vec<u64>,
    ) {
        let len = manifest.chunk_ids.len();
        self.plan = Some(SnapshotDownloadPlan {
            snapshot_height: manifest.height,
            manifest_id,
            root_digest: manifest.digest,
            chunk_ids: manifest.chunk_ids.clone(),
            downloaded: vec![false; len],
            in_flight: vec![false; len],
        });
        self.available.clear();
    }

    /// Get the next batch of chunk indices and IDs to request.
    ///
    /// Returns up to `CHUNKS_IN_PARALLEL` chunks that haven't been
    /// downloaded or are currently being downloaded.
    pub fn next_chunks_to_download(&mut self) -> Vec<(usize, [u8; 32])> {
        let plan = match self.plan.as_mut() {
            Some(p) => p,
            None => return Vec::new(),
        };

        let available = CHUNKS_IN_PARALLEL.saturating_sub(plan.in_flight_count());
        let mut result = Vec::new();

        for (idx, chunk_id) in plan.chunk_ids.iter().enumerate() {
            if result.len() >= available {
                break;
            }
            if !plan.downloaded[idx] && !plan.in_flight[idx] {
                plan.in_flight[idx] = true;
                result.push((idx, *chunk_id));
            }
        }
        result
    }

    /// Record a downloaded chunk. Returns `true` if the download is now complete.
    pub fn mark_chunk_downloaded(&mut self, chunk_id: &[u8; 32]) -> bool {
        if let Some(ref mut plan) = self.plan {
            if let Some(idx) = plan.chunk_ids.iter().position(|id| id == chunk_id) {
                if !plan.downloaded[idx] {
                    plan.downloaded[idx] = true;
                    plan.in_flight[idx] = false;
                }
            }
            plan.downloaded.iter().all(|&d| d)
        } else {
            false
        }
    }

    /// Check if the download is complete.
    pub fn is_complete(&self) -> bool {
        self.plan
            .as_ref()
            .is_some_and(|p| p.downloaded.iter().all(|&d| d))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshots::{SnapshotManifest, SnapshotsInfo};

    #[test]
    fn record_info_and_ready_to_download() {
        let mut discovery = SnapshotDiscovery::new(2);
        let info = SnapshotsInfo {
            manifests: vec![(52223, [0xAA; 32])],
        };

        discovery.record_info(1, &info, &|_| Some([0; 33]));
        assert!(discovery.ready_to_download().is_none()); // only 1 peer

        discovery.record_info(2, &info, &|_| Some([0; 33]));
        let result = discovery.ready_to_download();
        assert!(result.is_some());
        let (mid, height, peers) = result.unwrap();
        assert_eq!(mid, [0xAA; 32]);
        assert_eq!(height, 52223);
        assert_eq!(peers.len(), 2);
    }

    #[test]
    fn record_info_ignores_unknown_heights() {
        let mut discovery = SnapshotDiscovery::new(1);
        let info = SnapshotsInfo {
            manifests: vec![(52223, [0xAA; 32])],
        };

        // State root unknown for this height.
        discovery.record_info(1, &info, &|_| None);
        assert!(discovery.ready_to_download().is_none());
    }

    #[test]
    fn next_chunks_returns_batch() {
        let mut discovery = SnapshotDiscovery::new(1);
        let manifest = SnapshotManifest {
            height: 100,
            digest: [0; 33],
            chunk_ids: (0u8..20).map(|i| [i; 32]).collect(),
            total_entries: 20,
        };
        discovery.start_download(&manifest, [0xFF; 32], vec![1]);

        let batch = discovery.next_chunks_to_download();
        assert_eq!(batch.len(), 16); // CHUNKS_IN_PARALLEL
        assert_eq!(batch[0].0, 0); // first index
    }

    #[test]
    fn mark_chunk_downloaded_tracks_completion() {
        let mut discovery = SnapshotDiscovery::new(1);
        let chunk_ids: Vec<[u8; 32]> = (0u8..3).map(|i| [i; 32]).collect();
        let manifest = SnapshotManifest {
            height: 100,
            digest: [0; 33],
            chunk_ids: chunk_ids.clone(),
            total_entries: 3,
        };
        discovery.start_download(&manifest, [0xFF; 32], vec![1]);

        assert!(!discovery.is_complete());

        discovery.mark_chunk_downloaded(&chunk_ids[0]);
        assert!(!discovery.is_complete());

        discovery.mark_chunk_downloaded(&chunk_ids[1]);
        assert!(!discovery.is_complete());

        let complete = discovery.mark_chunk_downloaded(&chunk_ids[2]);
        assert!(complete);
        assert!(discovery.is_complete());
    }

    #[test]
    fn ready_to_download_returns_none_when_plan_active() {
        let mut discovery = SnapshotDiscovery::new(1);
        let info = SnapshotsInfo {
            manifests: vec![(100, [0xAA; 32])],
        };
        discovery.record_info(1, &info, &|_| Some([0; 33]));

        let manifest = SnapshotManifest {
            height: 100,
            digest: [0; 33],
            chunk_ids: vec![[0xBB; 32]],
            total_entries: 1,
        };
        discovery.start_download(&manifest, [0xAA; 32], vec![1]);

        // Should return None since a plan is active.
        assert!(discovery.ready_to_download().is_none());
    }

    #[test]
    fn selects_highest_snapshot_when_multiple_available() {
        let mut discovery = SnapshotDiscovery::new(1);

        let info1 = SnapshotsInfo {
            manifests: vec![(100, [0x01; 32])],
        };
        let info2 = SnapshotsInfo {
            manifests: vec![(200, [0x02; 32])],
        };

        discovery.record_info(1, &info1, &|_| Some([0; 33]));
        discovery.record_info(1, &info2, &|_| Some([0; 33]));

        let (_, height, _) = discovery.ready_to_download().unwrap();
        assert_eq!(height, 200); // should pick higher
    }

    #[test]
    fn next_chunks_does_not_re_request_in_flight() {
        let mut discovery = SnapshotDiscovery::new(1);
        let manifest = SnapshotManifest {
            height: 100,
            digest: [0; 33],
            chunk_ids: (0u8..20).map(|i| [i; 32]).collect(),
            total_entries: 20,
        };
        discovery.start_download(&manifest, [0xFF; 32], vec![1]);

        // First call gets indices 0..16 (fills all parallel slots).
        let batch1 = discovery.next_chunks_to_download();
        assert_eq!(batch1.len(), 16);

        // All 16 parallel slots are occupied; no new requests allowed.
        let batch2 = discovery.next_chunks_to_download();
        assert!(batch2.is_empty());

        // Mark 4 chunks as downloaded, freeing 4 parallel slots.
        for i in 0..4 {
            discovery.mark_chunk_downloaded(&[i as u8; 32]);
        }
        let batch3 = discovery.next_chunks_to_download();
        assert_eq!(batch3.len(), 4);
        assert_eq!(batch3[0].0, 16);
        assert_eq!(batch3[3].0, 19);

        // All 16 slots are occupied again (12 original + 4 new).
        let batch4 = discovery.next_chunks_to_download();
        assert!(batch4.is_empty());
    }
}
