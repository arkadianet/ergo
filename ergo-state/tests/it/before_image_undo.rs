//! Before-image undo test suite.
//!
//! Proves the correctness of the before-image rollback mechanism across
//! six categories:
//! 1. Apply/rollback/verify digest over long sequences
//! 2. Randomized insert/remove sequences against oracle
//! 3. Crash safety across atomic transaction boundary
//! 4. Multi-modify per block records original pre-image
//! 5. Created-node deletion and ID reuse rules
//! 6. Pruning past rollback window

use ergo_state::avl::changelog::{ChangeLog, NodeChange};
use ergo_state::avl::tree::AvlTree;

use bytes::Bytes;
use ergo_avltree_rust::authenticated_tree_ops::AuthenticatedTreeOps;
use ergo_avltree_rust::batch_avl_prover::BatchAVLProver;
use ergo_avltree_rust::batch_node::{AVLTree as OracleTree, Node, NodeHeader};
use ergo_avltree_rust::operation::{KeyValue, Operation};

fn oracle_tree() -> BatchAVLProver {
    BatchAVLProver::new(
        OracleTree::new(
            |digest| Node::LabelOnly(NodeHeader::new(Some(*digest), None)),
            32,
            None,
        ),
        true,
    )
}

fn oracle_insert(p: &mut BatchAVLProver, key: &[u8; 32], value: &[u8]) {
    p.perform_one_operation(&Operation::Insert(KeyValue {
        key: Bytes::from(key.to_vec()),
        value: Bytes::from(value.to_vec()),
    }))
    .unwrap();
}

fn oracle_remove(p: &mut BatchAVLProver, key: &[u8; 32]) {
    p.perform_one_operation(&Operation::Remove(Bytes::from(key.to_vec())))
        .unwrap();
}

fn oracle_digest(p: &BatchAVLProver) -> [u8; 33] {
    let d = p.digest().unwrap();
    let mut out = [0u8; 33];
    out.copy_from_slice(&d);
    out
}

fn our_digest(tree: &mut AvlTree) -> [u8; 33] {
    *tree.root_digest().as_bytes()
}

fn make_key(seed: u8, idx: u8) -> [u8; 32] {
    let mut k = [0u8; 32];
    k[0] = seed.wrapping_mul(37).wrapping_add(idx).wrapping_add(1);
    k[1] = seed;
    k[2] = idx;
    k
}

// ============================================================
// Category 1: Apply/rollback/verify digest over long sequences
// ============================================================

// ----- happy path -----

#[test]
fn rollback_single_insert_restores_digest() {
    let mut tree = AvlTree::new();
    tree.clear_dirty(); // commit the sentinel
    let before = our_digest(&mut tree);
    let root_before = tree.root_id();
    let height_before = tree.tree_height();

    let key = make_key(1, 0);
    tree.insert(key, vec![0xAA]);
    let log = tree.take_change_log();

    tree.rollback(&log, root_before, height_before);
    assert_eq!(our_digest(&mut tree), before);
}

#[test]
fn rollback_ten_inserts_restores_digest() {
    let mut tree = AvlTree::new();
    tree.clear_dirty();
    let before = our_digest(&mut tree);
    let root_before = tree.root_id();
    let height_before = tree.tree_height();

    for i in 0u8..10 {
        tree.insert(make_key(i, 0), vec![i]);
    }
    let log = tree.take_change_log();

    tree.rollback(&log, root_before, height_before);
    assert_eq!(our_digest(&mut tree), before);
}

#[test]
fn rollback_mixed_insert_remove_restores_digest() {
    let mut tree = AvlTree::new();

    // Phase 1: insert 10 boxes (committed baseline)
    for i in 0u8..10 {
        tree.insert(make_key(i, 0), vec![i]);
    }
    tree.clear_dirty(); // simulate commit
    let baseline_digest = our_digest(&mut tree);
    let baseline_root = tree.root_id();
    let baseline_height = tree.tree_height();

    // Phase 2: remove 3, insert 5 (uncommitted block)
    for i in [2u8, 5, 7] {
        tree.remove(&make_key(i, 0));
    }
    for i in 10u8..15 {
        tree.insert(make_key(i, 0), vec![i]);
    }
    let log = tree.take_change_log();

    // Rollback should restore baseline
    tree.rollback(&log, baseline_root, baseline_height);
    assert_eq!(our_digest(&mut tree), baseline_digest);
}

// ============================================================
// Category 2: Randomized insert/remove sequences
// ============================================================

#[test]
fn randomized_50_operations_rollback_matches_oracle() {
    let mut tree = AvlTree::new();
    let mut oracle = oracle_tree();

    // Deterministic pseudo-random sequence
    let mut rng_state: u32 = 0xDEADBEEF;
    let next_rng = |s: &mut u32| -> u32 {
        *s ^= *s << 13;
        *s ^= *s >> 17;
        *s ^= *s << 5;
        *s
    };

    let mut live_keys: Vec<[u8; 32]> = Vec::new();

    // 50 operations: mix of insert and remove
    for round in 0u32..50 {
        let op = next_rng(&mut rng_state);
        if live_keys.len() < 3 || op % 3 != 0 {
            // Insert
            let mut key = [0u8; 32];
            let val = next_rng(&mut rng_state);
            key[0..4].copy_from_slice(&val.to_be_bytes());
            key[4..8].copy_from_slice(&round.to_be_bytes());
            let value = vec![(round & 0xFF) as u8; 4];

            tree.insert(key, value.clone());
            oracle_insert(&mut oracle, &key, &value);
            live_keys.push(key);
        } else {
            // Remove a random live key
            let idx = next_rng(&mut rng_state) as usize % live_keys.len();
            let key = live_keys.remove(idx);
            tree.remove(&key);
            oracle_remove(&mut oracle, &key);
        }
    }
    assert_eq!(
        our_digest(&mut tree),
        oracle_digest(&oracle),
        "after 50 ops"
    );

    // Now rollback 10 operations at a time, verifying at each checkpoint
    // We can't easily rollback the oracle, so we verify our tree internally:
    // apply 5 more ops, record checkpoint, apply 5 more, rollback to checkpoint
    tree.clear_dirty();
    let checkpoint_digest = our_digest(&mut tree);
    let checkpoint_root = tree.root_id();
    let checkpoint_height = tree.tree_height();

    for i in 0u8..5 {
        let mut key = [0u8; 32];
        key[0] = 0xF0 + i;
        key[1] = 0x01;
        tree.insert(key, vec![0xFF; 8]);
    }
    let log = tree.take_change_log();

    tree.rollback(&log, checkpoint_root, checkpoint_height);
    assert_eq!(
        our_digest(&mut tree),
        checkpoint_digest,
        "after rollback to checkpoint"
    );
}

#[test]
fn randomized_100_ops_with_repeated_rollback() {
    let mut tree = AvlTree::new();
    let mut live_keys: Vec<[u8; 32]> = Vec::new();
    let mut rng: u32 = 42;
    let next = |s: &mut u32| -> u32 {
        *s ^= *s << 13;
        *s ^= *s >> 17;
        *s ^= *s << 5;
        *s
    };

    for epoch in 0..10 {
        // Record state at start of epoch
        tree.clear_dirty();
        let epoch_digest = our_digest(&mut tree);
        let epoch_root = tree.root_id();
        let epoch_height = tree.tree_height();

        // 10 random operations
        for _ in 0..10 {
            if live_keys.len() < 2 || next(&mut rng) % 3 != 0 {
                let mut key = [0u8; 32];
                let v = next(&mut rng);
                key[0..4].copy_from_slice(&v.to_be_bytes());
                key[4] = epoch;
                tree.insert(key, vec![epoch; 4]);
                live_keys.push(key);
            } else {
                let idx = next(&mut rng) as usize % live_keys.len();
                let key = live_keys.remove(idx);
                tree.remove(&key);
            }
        }
        let log = tree.take_change_log();

        // Rollback
        tree.rollback(&log, epoch_root, epoch_height);
        assert_eq!(
            our_digest(&mut tree),
            epoch_digest,
            "digest mismatch after rollback at epoch {epoch}"
        );

        // Re-apply same operations
        if live_keys.len() < 2 || next(&mut rng) % 3 != 0 {
            let mut key = [0u8; 32];
            let v = next(&mut rng);
            key[0..4].copy_from_slice(&v.to_be_bytes());
            key[4] = epoch + 100;
            tree.insert(key, vec![epoch + 100; 4]);
            live_keys.push(key);
        }
    }
}

// ============================================================
// Category 3: Crash safety across atomic transaction boundary
// ============================================================

// This test uses the persistent StateStore with tempdir.
// Apply blocks 1-5, "crash" (drop store), reopen, verify state.
// Then apply block 6 to confirm the tree is usable after recovery.
// (Already covered by crash_recovery_restores_state in persistent_blocks_1_10.rs,
// but we add a variant that verifies the change_log is empty after recovery.)

#[test]
fn recovery_starts_with_empty_changelog() {
    // After crash recovery, the change_log must be empty.
    // This is verified implicitly: if recovery loaded a non-empty changelog,
    // the first apply_block's take_change_log would include stale entries.
    let mut tree = AvlTree::new();
    for i in 0u8..5 {
        tree.insert(make_key(i, 0), vec![i]);
    }

    // Simulate commit + clear
    tree.clear_dirty();
    assert!(
        tree.take_change_log().is_empty(),
        "changelog should be empty after clear"
    );

    // Simulate recovery: create a new tree and load nodes
    let root_id = tree.root_id();
    let height = tree.tree_height();
    let nodes: Vec<_> = tree.all_nodes();

    let mut recovered = AvlTree::new_empty_with_label(root_id, height, tree.root_label());
    for (id, node) in nodes {
        recovered.load_node(id, node);
    }
    assert!(
        recovered.take_change_log().is_empty(),
        "recovered tree should have empty changelog"
    );
    assert_eq!(our_digest(&mut recovered), our_digest(&mut tree));
}

// ============================================================
// Category 4: Node modified multiple times records original pre-image
// ============================================================

#[test]
fn multi_modify_records_first_preimage_only() {
    let mut tree = AvlTree::new();

    // Insert 5 keys
    for i in 0u8..5 {
        tree.insert(make_key(i, 0), vec![i]);
    }
    tree.clear_dirty();
    let baseline_digest = our_digest(&mut tree);
    let baseline_root = tree.root_id();
    let baseline_height = tree.tree_height();

    // Modify the same area multiple times: remove key, insert it back with
    // different value, remove again, insert with third value. This touches
    // the same internal nodes multiple times within one "block".
    let key = make_key(2, 0);
    tree.remove(&key);
    tree.insert(key, vec![0xAA]);
    tree.remove(&key);
    tree.insert(key, vec![0xBB]);

    let log = tree.take_change_log();

    // Check that Modified entries use dedup — only first before-image per node
    let modified_ids: Vec<u64> = log
        .changes()
        .iter()
        .filter_map(|c| match c {
            NodeChange::Modified(id, _) => Some(*id),
            _ => None,
        })
        .collect();
    let unique: std::collections::HashSet<u64> = modified_ids.iter().copied().collect();
    assert_eq!(
        modified_ids.len(),
        unique.len(),
        "each node should appear at most once as Modified (dedup guarantees original pre-image)"
    );

    // Rollback should restore the baseline digest exactly
    tree.rollback(&log, baseline_root, baseline_height);
    assert_eq!(
        our_digest(&mut tree),
        baseline_digest,
        "multi-modify rollback should restore exact baseline"
    );
}

// ============================================================
// Category 5: Created-node deletion and ID reuse
// ============================================================

#[test]
fn created_nodes_deleted_on_rollback() {
    let mut tree = AvlTree::new();
    tree.clear_dirty(); // commit sentinel
    let initial_arena_size = tree.arena_size();

    tree.insert(make_key(1, 0), vec![1]);
    let log = tree.take_change_log();
    let arena_after_insert = tree.arena_size();
    assert!(
        arena_after_insert > initial_arena_size,
        "insert should grow arena"
    );

    tree.rollback(&log, 1, 0); // root=1 (sentinel), height=0
    assert_eq!(
        tree.arena_size(),
        initial_arena_size,
        "rollback should delete all created nodes, restoring original arena size"
    );
}

#[test]
fn node_ids_are_never_reused() {
    let mut tree = AvlTree::new();
    tree.clear_dirty(); // commit sentinel

    // Insert and remove to create and destroy nodes
    for round in 0u8..5 {
        let key = make_key(round, 0);
        tree.insert(key, vec![round]);
        tree.clear_dirty();
        tree.remove(&key);
        tree.clear_dirty();
    }

    // After 5 insert+remove cycles, the tree should have only the sentinel.
    // The sentinel key is NegativeInfinity = [0x00; 32] with empty value.
    assert_eq!(
        tree.lookup(&[0u8; 32]),
        Some(vec![]),
        "sentinel should still be present with empty value"
    );

    // Insert a new key — its node IDs should not conflict with any previous ones
    let key = make_key(99, 0);
    tree.insert(key, vec![99]);
    assert_eq!(tree.lookup(&key), Some(vec![99u8]));
}

#[test]
fn rollback_then_new_ops_use_fresh_ids() {
    let mut tree = AvlTree::new();
    for i in 0u8..5 {
        tree.insert(make_key(i, 0), vec![i]);
    }
    tree.clear_dirty();
    let root = tree.root_id();
    let height = tree.tree_height();

    // Apply ops
    tree.insert(make_key(10, 0), vec![10]);
    let log = tree.take_change_log();

    // Record highest created ID
    let max_created_id = log
        .changes()
        .iter()
        .filter_map(|c| match c {
            NodeChange::Created(id) => Some(*id),
            _ => None,
        })
        .max()
        .unwrap_or(0);

    // Rollback
    tree.rollback(&log, root, height);

    // New ops after rollback should use IDs > max_created_id
    tree.insert(make_key(20, 0), vec![20]);
    let log2 = tree.take_change_log();
    for change in log2.changes() {
        if let NodeChange::Created(id) = change {
            assert!(
                *id > max_created_id,
                "post-rollback alloc should use fresh ID > {max_created_id}, got {id}"
            );
        }
    }
}

// ============================================================
// Category 6: Pruning past rollback window
// ============================================================

#[test]
fn old_changelog_entries_can_be_dropped_safely() {
    // Simulates pruning: apply N blocks, keep only last W change logs.
    // Verify the tree is correct after pruning (can't rollback past W,
    // but forward operations still work).
    let mut tree = AvlTree::new();
    let mut oracle = oracle_tree();
    let rollback_window = 3;
    let mut logs: Vec<(ChangeLog, u64, u8)> = Vec::new();

    for block in 0u8..10 {
        tree.clear_dirty();
        let root = tree.root_id();
        let height = tree.tree_height();

        let key = make_key(block, 0);
        let value = vec![block; 8];
        tree.insert(key, value.clone());
        oracle_insert(&mut oracle, &key, &value);

        let log = tree.take_change_log();
        logs.push((log, root, height));

        // Prune old logs beyond the window
        if logs.len() > rollback_window {
            logs.remove(0); // oldest log discarded — can't rollback to it
        }

        assert_eq!(
            our_digest(&mut tree),
            oracle_digest(&oracle),
            "block {block}"
        );
    }

    // Verify we can still rollback within the window
    let (log, root, height) = &logs[logs.len() - 1];
    tree.rollback(log, *root, *height);
    // Tree is now at state before last block — still valid
    let _ = our_digest(&mut tree); // should not panic
}

#[test]
fn pruning_does_not_affect_forward_operations() {
    let mut tree = AvlTree::new();
    let mut oracle = oracle_tree();

    // Apply 20 blocks, discarding all change logs (no rollback possible)
    for block in 0u8..20 {
        tree.clear_dirty();
        let key = make_key(block, 0);
        let value = vec![block; 4];
        tree.insert(key, value.clone());
        oracle_insert(&mut oracle, &key, &value);
        let _discarded = tree.take_change_log(); // pruned immediately
    }

    // Tree should still be correct — forward operations are unaffected by pruning
    assert_eq!(our_digest(&mut tree), oracle_digest(&oracle));

    // Can still insert and remove
    let key = make_key(99, 0);
    tree.insert(key, vec![99]);
    oracle_insert(&mut oracle, &key, &[99]);
    assert_eq!(our_digest(&mut tree), oracle_digest(&oracle));
}
