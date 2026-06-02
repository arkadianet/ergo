//! Server-side cache for the Mode 2 snapshot wire protocol.
//!
//! Holds at most one [`SnapshotServer`] — the snapshot built at the
//! most recent Scala-aligned height (`Constants.SnapshotEvery =
//! 52_224` blocks). Peers asking for `GetSnapshotsInfo`,
//! `GetManifest`, or `GetUtxoSnapshotChunk` resolve against this
//! single in-memory entry.
//!
//! Empty when:
//! * the node runs in Mode 6 (no UTXO state to snapshot), or
//! * the node hasn't yet reached the first snapshot height.
//!
//! Lookup-by-id is the contract: peers receive the `manifest_id` /
//! `subtree_id` they want via `SnapshotsInfo` and reference it on
//! follow-up requests. A request that doesn't match the cached
//! snapshot is a silent drop — never an error reply — matching the
//! Scala node's `peer.handlerRef !` no-op when `SnapshotsDb` returns
//! nothing for that id.

use ergo_primitives::digest::Digest32;
use ergo_state::avl::snapshot_codec::SnapshotServer;

#[derive(Default)]
pub(crate) struct SnapshotState {
    cached: Option<SnapshotServer>,
}

impl SnapshotState {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Install the next snapshot. Replaces any previously cached
    /// snapshot — only the latest Scala-aligned height is held,
    /// matching Scala's `SnapshotsDb` retention of one entry.
    /// Called by the block-apply trigger in
    /// `sync_tick::maybe_rebuild_serve_snapshot` when the tip
    /// crosses a snapshot height.
    pub(crate) fn set(&mut self, server: SnapshotServer) {
        self.cached = Some(server);
    }

    /// Height of the cached snapshot, if any. Used by the build
    /// trigger to avoid rebuilding at the same height twice.
    pub(crate) fn cached_height(&self) -> Option<u32> {
        self.cached.as_ref().map(|s| s.height)
    }

    /// `(height, manifest_id)` list for the `SnapshotsInfo` reply.
    /// Empty when nothing is cached, which tells the peer "no
    /// snapshots available" so it won't follow up.
    pub(crate) fn available_manifests(&self) -> Vec<(i32, [u8; 32])> {
        match &self.cached {
            Some(server) => vec![(server.height as i32, *server.manifest_id.as_bytes())],
            None => Vec::new(),
        }
    }

    /// Manifest bytes for the requested id, or `None` when the
    /// cached snapshot is empty or its id doesn't match.
    pub(crate) fn manifest_bytes(&self, manifest_id: &[u8; 32]) -> Option<&[u8]> {
        let server = self.cached.as_ref()?;
        (server.manifest_id.as_bytes() == manifest_id).then_some(server.manifest_bytes.as_slice())
    }

    /// Chunk bytes for the requested subtree id, or `None` when the
    /// cached snapshot is empty or no chunk has that label.
    pub(crate) fn chunk_bytes(&self, subtree_id: &[u8; 32]) -> Option<&[u8]> {
        let server = self.cached.as_ref()?;
        let digest = Digest32::from_bytes(*subtree_id);
        server.chunk_by_id(&digest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_state::avl::snapshot_codec::MAINNET_MANIFEST_DEPTH;
    use ergo_state::avl::tree::AvlTree;

    // ----- helpers -----

    fn server_with_two_leaves(height: u32) -> SnapshotServer {
        let mut tree = AvlTree::new();
        tree.insert([0x10; 32], vec![0xAA, 0xBB]);
        tree.insert([0x20; 32], vec![0xCC]);
        SnapshotServer::build(&tree, height, MAINNET_MANIFEST_DEPTH)
            .expect("server build succeeds for non-empty tree")
    }

    // ----- happy path -----

    #[test]
    fn empty_state_advertises_nothing_and_serves_nothing() {
        let state = SnapshotState::new();
        assert!(
            state.available_manifests().is_empty(),
            "no snapshot → empty SnapshotsInfo list",
        );
        assert!(
            state.manifest_bytes(&[0x00; 32]).is_none(),
            "no snapshot → GetManifest finds nothing",
        );
        assert!(
            state.chunk_bytes(&[0x00; 32]).is_none(),
            "no snapshot → GetUtxoSnapshotChunk finds nothing",
        );
    }

    #[test]
    fn set_then_advertise_lists_one_manifest_with_height_and_id() {
        let mut state = SnapshotState::new();
        let server = server_with_two_leaves(52_224);
        let expected_id = *server.manifest_id.as_bytes();
        state.set(server);

        let advertised = state.available_manifests();
        assert_eq!(advertised.len(), 1);
        assert_eq!(advertised[0].0, 52_224i32);
        assert_eq!(advertised[0].1, expected_id);
    }

    #[test]
    fn set_then_manifest_lookup_by_correct_id_returns_bytes() {
        let mut state = SnapshotState::new();
        let server = server_with_two_leaves(100);
        let manifest_id = *server.manifest_id.as_bytes();
        let expected = server.manifest_bytes.clone();
        state.set(server);

        let actual = state
            .manifest_bytes(&manifest_id)
            .expect("known manifest id resolves");
        assert_eq!(actual, expected.as_slice());
    }

    // ----- error paths -----

    #[test]
    fn manifest_lookup_with_wrong_id_returns_none() {
        let mut state = SnapshotState::new();
        state.set(server_with_two_leaves(100));
        assert!(
            state.manifest_bytes(&[0xFF; 32]).is_none(),
            "unknown manifest id must not surface another snapshot's bytes",
        );
    }

    #[test]
    fn chunk_lookup_with_wrong_id_returns_none() {
        let mut state = SnapshotState::new();
        state.set(server_with_two_leaves(100));
        assert!(
            state.chunk_bytes(&[0xFF; 32]).is_none(),
            "unknown subtree id must not surface a chunk it wasn't asked for",
        );
    }

    #[test]
    fn second_set_replaces_first() {
        // SnapshotsDb in Scala keeps a single entry — when a new
        // snapshot is built at a later height, the previous one is
        // evicted. Calling set() twice must reflect this.
        let mut state = SnapshotState::new();
        let first = server_with_two_leaves(52_224);
        let first_id = *first.manifest_id.as_bytes();
        state.set(first);

        // Use a tree with different leaves so manifest_id differs.
        let mut tree2 = AvlTree::new();
        tree2.insert([0x30; 32], vec![0xDD]);
        tree2.insert([0x40; 32], vec![0xEE]);
        let second = SnapshotServer::build(&tree2, 104_448, MAINNET_MANIFEST_DEPTH).unwrap();
        let second_id = *second.manifest_id.as_bytes();
        state.set(second);

        let advertised = state.available_manifests();
        assert_eq!(advertised.len(), 1, "still only one snapshot cached");
        assert_eq!(advertised[0].0, 104_448i32);
        assert_eq!(advertised[0].1, second_id);

        // First snapshot's manifest is no longer reachable.
        assert!(
            state.manifest_bytes(&first_id).is_none(),
            "replaced snapshot must not still resolve",
        );
    }
}
