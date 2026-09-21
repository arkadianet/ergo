//! Read-count regression guards. root_digest() must be O(1) with zero arena
//! reads. The mutation-wrapped counter is what actually proves K v2 design —
//! resetting the counter AFTER mutation hides the real cost.

use ergo_state::avl::tree::AvlTree;

#[test]
fn root_digest_does_zero_arena_reads_after_warmup() {
    let mut tree = AvlTree::new();
    for i in 1u32..=10_000 {
        let mut key = [0u8; 32];
        key[28..].copy_from_slice(&i.to_be_bytes());
        tree.insert(key, vec![i as u8; 32]);
    }
    let _ = tree.root_digest();
    // Apply 15 mutations.
    for i in 0u32..15 {
        let mut key = [0u8; 32];
        key[24..28].copy_from_slice(&0xDEADBEEFu32.to_be_bytes());
        key[28..].copy_from_slice(&i.to_be_bytes());
        tree.insert(key, vec![0xAA; 32]);
    }
    tree.arena_reset_read_count();
    for _ in 0..100 {
        let _ = tree.root_digest();
    }
    assert_eq!(tree.arena_read_count(), 0, "root_digest() must be O(1)");
}

/// The crucial test for K v2: wraps the read counter around the MUTATION
/// itself. Proves that each mutation reads O(depth) nodes — the mutation
/// path — and NOT O(depth × subtree_size) from recomputing sibling labels.
#[test]
fn mutation_read_count_is_bounded_to_mutation_path() {
    let mut tree = AvlTree::new();
    for i in 1u32..=10_000 {
        let mut key = [0u8; 32];
        key[28..].copy_from_slice(&i.to_be_bytes());
        tree.insert(key, vec![i as u8; 32]);
    }
    // Depth is ~log2(10000) ≈ 14. Allow some headroom for rotations/rebalance.
    let max_reads_per_mutation = 64u64;

    tree.arena_reset_read_count();
    let mut key = [0u8; 32];
    key[24..28].copy_from_slice(&0xDEADBEEFu32.to_be_bytes());
    key[28..].copy_from_slice(&1u32.to_be_bytes());
    tree.insert(key, vec![0xAA; 32]);
    let reads = tree.arena_read_count();
    assert!(
        reads <= max_reads_per_mutation,
        "mutation read count must be bounded to mutation path; got {reads}"
    );
}
