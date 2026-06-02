//! Read-count assertions for cold-restart + LRU-eviction scenarios.
//! Proves K v2 design holds under memory pressure, not just as an
//! in-memory optimization.

use ergo_state::store::StateStore;

/// After a cold reopen with a tiny 4MB cache, `root_digest()` must be
/// served from the hydrated `root_label` in `state_meta` — zero arena
/// reads even when the cache is empty.
#[test]
fn cold_restart_root_digest_is_zero_reads() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.redb");

    // Synthetic genesis — 1024 boxes is plenty to force a multi-level tree.
    let boxes: Vec<([u8; 32], Vec<u8>)> = (1u32..=1024)
        .map(|i| {
            let mut id = [0u8; 32];
            id[28..].copy_from_slice(&i.to_be_bytes());
            (id, vec![i as u8; 48])
        })
        .collect();

    let pre_shutdown_digest = {
        let mut store = StateStore::open_with_cache(&path, 4 * 1024 * 1024).unwrap();
        store.initialize_genesis(&boxes).unwrap();
        let d = store.root_digest();
        drop(store);
        d
    };

    let mut store = StateStore::open_with_cache(&path, 4 * 1024 * 1024).unwrap();
    store.arena_reset_read_count();
    let post = store.root_digest();

    assert_eq!(post, pre_shutdown_digest);
    assert_eq!(
        store.arena_read_count(),
        0,
        "cold root_digest must do zero arena reads",
    );
}

/// After a cold reopen with a tiny 4MB cache, a single mutation must walk
/// at most O(depth) arena reads. With K v1 (no parent-held labels), a
/// single mutation would recompute sibling labels across whole subtrees
/// — O(subtree_size), thousands of reads. K v2 bounds this to the
/// mutation path.
#[test]
fn cold_restart_single_mutation_bounded_reads() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.redb");

    // ~10k entries: log2(10_000) ≈ 14 levels of internal nodes; tree height
    // ~20 with AVL slack. Enough to see the difference between an O(depth)
    // walk and an O(subtree_size) recomputation.
    let boxes: Vec<([u8; 32], Vec<u8>)> = (1u32..=10_000)
        .map(|i| {
            let mut id = [0u8; 32];
            id[28..].copy_from_slice(&i.to_be_bytes());
            (id, vec![i as u8; 32])
        })
        .collect();

    {
        let mut store = StateStore::open_with_cache(&path, 4 * 1024 * 1024).unwrap();
        store.initialize_genesis(&boxes).unwrap();
        drop(store);
    }

    let mut store = StateStore::open_with_cache(&path, 4 * 1024 * 1024).unwrap();
    store.arena_reset_read_count();

    // Single insert at a fresh key — walks the tree root-to-leaf, reading
    // each node on the path. K v2 sibling labels live inside the parent,
    // so no sibling subtree reads are needed.
    let mut key = [0u8; 32];
    key[24..28].copy_from_slice(&0xDEADBEEFu32.to_be_bytes());
    key[28..].copy_from_slice(&7u32.to_be_bytes());
    store.tree_insert_for_test(key, vec![0xAAu8; 32]);

    let reads = store.arena_read_count();

    // Depth is ~log2(10_000) ≈ 14, plus AVL slack. Generous budget: ~5×
    // depth accounts for rotations touching a few extra nodes. The real
    // guard is against thousands-of-reads regressions (O(subtree_size)).
    let depth: u64 = 20;
    let budget: u64 = 5 * depth;
    assert!(
        reads <= budget,
        "cold-restart single mutation read count too high: {reads} (budget: {budget})",
    );
}
