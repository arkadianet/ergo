//! Per-operation parity oracle against ergo_avltree_rust. After every
//! insert/update/remove, our root digest MUST match the reference crate.
//! Guards consensus parity at the operation level, not just per-block.

use bytes::Bytes;
use ergo_avltree_rust::authenticated_tree_ops::AuthenticatedTreeOps;
use ergo_avltree_rust::batch_avl_prover::BatchAVLProver;
use ergo_avltree_rust::batch_node::{AVLTree, Node, NodeHeader};
use ergo_avltree_rust::operation::{KeyValue, Operation};
use ergo_state::avl::tree::AvlTree;

fn oracle_prover() -> BatchAVLProver {
    let tree = AVLTree::new(
        |digest| Node::LabelOnly(NodeHeader::new(Some(*digest), None)),
        32,
        None,
    );
    BatchAVLProver::new(tree, true)
}

fn drive_oracle(op: &Operation, prover: &mut BatchAVLProver) -> Vec<u8> {
    prover.perform_one_operation(op).unwrap();
    prover.digest().unwrap().to_vec()
}

// ----- happy path -----

#[test]
fn insert_sequence_matches_oracle_after_every_op() {
    let mut ours = AvlTree::new();
    let mut oracle = oracle_prover();
    // Start at 1 to avoid the all-zero NEGATIVE_INFINITY sentinel key.
    for i in 1u32..=256 {
        let mut key = [0u8; 32];
        key[28..].copy_from_slice(&i.to_be_bytes());
        let value = vec![i as u8; 64];
        ours.insert(key, value.clone());
        let d = drive_oracle(
            &Operation::Insert(KeyValue {
                key: Bytes::copy_from_slice(&key),
                value: Bytes::copy_from_slice(&value),
            }),
            &mut oracle,
        );
        assert_eq!(
            ours.root_digest().as_bytes(),
            d.as_slice(),
            "divergence at insert i={i}"
        );
    }
}

#[test]
fn rotation_coverage_ll_lr_rl_rr() {
    for keys in [[3u8, 2, 1], [1, 2, 3], [3, 1, 2], [1, 3, 2]] {
        let mut ours = AvlTree::new();
        let mut oracle = oracle_prover();
        for k in keys {
            let mut key = [0u8; 32];
            key[31] = k;
            ours.insert(key, vec![k]);
            drive_oracle(
                &Operation::Insert(KeyValue {
                    key: Bytes::copy_from_slice(&key),
                    value: Bytes::copy_from_slice(&[k]),
                }),
                &mut oracle,
            );
            assert_eq!(
                ours.root_digest().as_bytes(),
                oracle.digest().unwrap().to_vec().as_slice(),
                "divergence during {keys:?} after {k}"
            );
        }
    }
}

#[test]
fn delete_sequence_matches_oracle() {
    let mut ours = AvlTree::new();
    let mut oracle = oracle_prover();
    for i in 1u32..=100 {
        let mut key = [0u8; 32];
        key[28..].copy_from_slice(&i.to_be_bytes());
        let v = vec![i as u8; 16];
        ours.insert(key, v.clone());
        drive_oracle(
            &Operation::Insert(KeyValue {
                key: Bytes::copy_from_slice(&key),
                value: Bytes::copy_from_slice(&v),
            }),
            &mut oracle,
        );
    }
    for i in (1u32..=100).rev() {
        let mut key = [0u8; 32];
        key[28..].copy_from_slice(&i.to_be_bytes());
        ours.remove(&key);
        let d = drive_oracle(
            &Operation::Remove(Bytes::copy_from_slice(&key)),
            &mut oracle,
        );
        assert_eq!(
            ours.root_digest().as_bytes(),
            d.as_slice(),
            "divergence at delete i={i}"
        );
    }
}

#[test]
fn delete_min_max_middle_random() {
    let mut ours = AvlTree::new();
    let mut oracle = oracle_prover();
    for i in 1u32..=20 {
        let mut key = [0u8; 32];
        key[31] = i as u8;
        ours.insert(key, vec![i as u8]);
        drive_oracle(
            &Operation::Insert(KeyValue {
                key: Bytes::copy_from_slice(&key),
                value: Bytes::copy_from_slice(&[i as u8]),
            }),
            &mut oracle,
        );
    }
    for i in [1u32, 20, 10, 5, 15, 7, 13, 3, 17, 8, 12] {
        let mut key = [0u8; 32];
        key[31] = i as u8;
        ours.remove(&key);
        drive_oracle(
            &Operation::Remove(Bytes::copy_from_slice(&key)),
            &mut oracle,
        );
        assert_eq!(
            ours.root_digest().as_bytes(),
            oracle.digest().unwrap().to_vec().as_slice(),
            "divergence after deleting {i}"
        );
    }
}

#[test]
fn absent_key_delete_is_noop() {
    let mut ours = AvlTree::new();
    let prev = ours.root_digest();
    let mut key = [0u8; 32];
    key[31] = 42;
    assert!(ours.remove(&key).is_none());
    assert_eq!(ours.root_digest(), prev);
}

#[test]
fn stored_labels_match_forced_recompute_after_every_op() {
    // Proves the incremental label updates in insert/rotations produce the
    // same digest as a full walk that ignores stored labels. If this ever
    // fails, stored labels are stale and the on-chain digest would diverge.
    let mut ours = AvlTree::new();
    for i in 1u32..=256 {
        let mut key = [0u8; 32];
        key[28..].copy_from_slice(&i.to_be_bytes());
        ours.insert(key, vec![i as u8; 32]);
        assert_eq!(
            ours.root_digest(),
            ours.forced_full_recompute_digest(),
            "stored labels diverged from forced recompute at insert i={i}"
        );
    }
    for i in (1u32..=256).step_by(3) {
        let mut key = [0u8; 32];
        key[28..].copy_from_slice(&i.to_be_bytes());
        ours.remove(&key);
        assert_eq!(
            ours.root_digest(),
            ours.forced_full_recompute_digest(),
            "stored labels diverged from forced recompute after delete i={i}"
        );
    }
}

#[test]
fn random_mixed_insert_delete_matches_oracle_and_forced_recompute() {
    // Seeded deterministic-random sequence of inserts + updates + deletes.
    // After every op: digest matches the reference crate AND matches the
    // forced-full-recompute oracle (stored labels aren't stale).
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    let mut ours = AvlTree::new();
    let mut oracle = oracle_prover();
    let mut rng = StdRng::seed_from_u64(42);
    let mut known_keys: Vec<[u8; 32]> = Vec::new();

    for op_i in 0..500 {
        let choice: u32 = if known_keys.is_empty() {
            0
        } else {
            rng.gen_range(0..3)
        };
        match choice {
            0 => {
                // Insert (or upsert on collision).
                let k = rng.gen_range(1u32..=10_000);
                let mut key = [0u8; 32];
                key[28..].copy_from_slice(&k.to_be_bytes());
                let vlen = rng.gen_range(1..=32);
                let value: Vec<u8> = (0..vlen).map(|_| rng.gen::<u8>()).collect();
                let is_update = known_keys.contains(&key);
                ours.insert(key, value.clone());
                let op = if is_update {
                    Operation::Update(KeyValue {
                        key: Bytes::copy_from_slice(&key),
                        value: Bytes::copy_from_slice(&value),
                    })
                } else {
                    Operation::Insert(KeyValue {
                        key: Bytes::copy_from_slice(&key),
                        value: Bytes::copy_from_slice(&value),
                    })
                };
                drive_oracle(&op, &mut oracle);
                if !is_update {
                    known_keys.push(key);
                }
            }
            1 => {
                // Update an existing key.
                let idx = rng.gen_range(0..known_keys.len());
                let key = known_keys[idx];
                let vlen = rng.gen_range(1..=32);
                let value: Vec<u8> = (0..vlen).map(|_| rng.gen::<u8>()).collect();
                ours.insert(key, value.clone());
                drive_oracle(
                    &Operation::Update(KeyValue {
                        key: Bytes::copy_from_slice(&key),
                        value: Bytes::copy_from_slice(&value),
                    }),
                    &mut oracle,
                );
            }
            2 => {
                // Delete an existing key.
                let idx = rng.gen_range(0..known_keys.len());
                let key = known_keys.swap_remove(idx);
                ours.remove(&key);
                drive_oracle(
                    &Operation::Remove(Bytes::copy_from_slice(&key)),
                    &mut oracle,
                );
            }
            _ => unreachable!(),
        }
        assert_eq!(
            ours.root_digest().as_bytes(),
            oracle.digest().unwrap().to_vec().as_slice(),
            "divergence from ergo_avltree_rust at op {op_i}"
        );
        assert_eq!(
            ours.root_digest(),
            ours.forced_full_recompute_digest(),
            "stored labels diverged from forced recompute at op {op_i}"
        );
    }
}

#[test]
fn update_existing_key_matches_oracle() {
    let mut ours = AvlTree::new();
    let mut oracle = oracle_prover();
    let mut key = [0u8; 32];
    key[31] = 7;
    ours.insert(key, vec![1]);
    drive_oracle(
        &Operation::Insert(KeyValue {
            key: Bytes::copy_from_slice(&key),
            value: Bytes::copy_from_slice(&[1]),
        }),
        &mut oracle,
    );
    ours.insert(key, vec![2]);
    // BatchAVLProver rejects Insert of an existing key — use Update for the
    // second write to match our AvlTree::insert semantics (upsert).
    drive_oracle(
        &Operation::Update(KeyValue {
            key: Bytes::copy_from_slice(&key),
            value: Bytes::copy_from_slice(&[2]),
        }),
        &mut oracle,
    );
    assert_eq!(
        ours.root_digest().as_bytes(),
        oracle.digest().unwrap().to_vec().as_slice(),
    );
}

// ============================================================
// Task 1.7: rollback / restart refresh root_label
// ============================================================

/// Rollback must restore `root_label` so that `root_digest()` equals the
/// pre-mutation digest AND matches the forced-full-recompute oracle.
/// This guards against stale labels after a reorg.
#[test]
fn rollback_restores_root_label_matches_forced_recompute() {
    let mut tree = AvlTree::new();

    // Build a committed baseline with enough entries to exercise rotations.
    for i in 1u32..=50 {
        let mut key = [0u8; 32];
        key[28..].copy_from_slice(&i.to_be_bytes());
        tree.insert(key, vec![i as u8; 16]);
    }
    tree.clear_dirty();
    let baseline_digest = tree.root_digest();
    let baseline_root = tree.root_id();
    let baseline_height = tree.tree_height();
    // The pre-mutation stored labels must already be consistent.
    assert_eq!(baseline_digest, tree.forced_full_recompute_digest());

    // Apply a mix of mutations on top.
    for i in 51u32..=80 {
        let mut key = [0u8; 32];
        key[28..].copy_from_slice(&i.to_be_bytes());
        tree.insert(key, vec![i as u8; 24]);
    }
    for i in [2u32, 10, 25, 40] {
        let mut key = [0u8; 32];
        key[28..].copy_from_slice(&i.to_be_bytes());
        tree.remove(&key);
    }
    let after_digest = tree.root_digest();
    assert_ne!(
        after_digest, baseline_digest,
        "mutations should change digest"
    );

    // Rollback.
    let log = tree.take_change_log();
    tree.rollback(&log, baseline_root, baseline_height);

    // root_digest must equal baseline AND match forced-full-recompute —
    // proving the refreshed root_label is not stale.
    assert_eq!(
        tree.root_digest(),
        baseline_digest,
        "rollback must restore pre-mutation digest",
    );
    assert_eq!(
        tree.root_digest(),
        tree.forced_full_recompute_digest(),
        "post-rollback root_label must match forced recompute",
    );
}

/// After restart (reopening the redb file), `root_digest()` must be served
/// from the hydrated `root_label` with zero arena reads — proving K v2's
/// O(1) cold-read invariant at the StateStore boundary.
#[test]
fn restart_reads_root_label_from_state_meta() {
    use ergo_state::store::StateStore;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.redb");

    // Synthetic genesis: 64 boxes with distinct ids.
    let boxes: Vec<([u8; 32], Vec<u8>)> = (1u32..=64)
        .map(|i| {
            let mut id = [0u8; 32];
            id[28..].copy_from_slice(&i.to_be_bytes());
            (id, vec![i as u8; 48])
        })
        .collect();

    let pre_shutdown_digest = {
        let mut store = StateStore::open(&path).unwrap();
        store.initialize_genesis(&boxes).unwrap();
        let d = store.root_digest();
        drop(store);
        d
    };

    // Reopen from committed state.
    let mut store = StateStore::open(&path).unwrap();
    store.arena_reset_read_count();
    let post_open_digest = store.root_digest();

    assert_eq!(
        post_open_digest, pre_shutdown_digest,
        "post-restart digest must match pre-shutdown",
    );
    assert_eq!(
        store.arena_read_count(),
        0,
        "cold root_digest must do zero arena reads (K v2 invariant)",
    );
}

// ----- properties -----
//
// Audit M-5: prove that the cache (arena per-node labels +
// `self.root_label`) and the recompute oracle
// (`forced_full_recompute_digest`) are independent — corrupting one
// surface must not propagate to the other, and the cached read paths
// must reflect their respective corruption. Together with the
// per-operation oracle tests above, these properties pin the trust
// contract documented as `// invariant:` comments in
// `ergo-state/src/avl/tree.rs`.

use ergo_state::avl::node::{AvlNode, NodeId};

/// In-test DFS from `tree.root_id()` over the AVL+ structure.
/// Returns every reachable node id EXCLUDING the root. Uses the
/// public `get_node` and `root_id` plus destructuring of
/// `AvlNode::Internal`. Equivalent candidate set to what
/// `recompute_subtree_label` walks inside the oracle. Avoids
/// `all_nodes()` because that is raw arena iteration (could include
/// orphan entries unreachable from the root).
fn reachable_non_root_ids(tree: &AvlTree) -> Vec<NodeId> {
    let mut stack = vec![tree.root_id()];
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    while let Some(id) = stack.pop() {
        if !seen.insert(id) {
            continue;
        }
        if id != tree.root_id() {
            out.push(id);
        }
        if let Some(AvlNode::Internal { left, right, .. }) = tree.get_node(id) {
            stack.push(left);
            stack.push(right);
        }
    }
    out
}

proptest::proptest! {
    /// Arena-stored label of a NON-ROOT node. Corruption must:
    /// - Leave `forced_full_recompute_digest()` unchanged (the
    ///   oracle walks the subtree and never reads cached labels).
    /// - Leave `root_digest()` unchanged (the root is cached in
    ///   `self.root_label`, not in the arena; mutating an arena
    ///   label does not propagate up automatically).
    /// - Change `label_of_for_test(id)` to a value distinct from
    ///   the pre-corruption cached label (proves the cache is
    ///   load-bearing for per-node reads).
    #[test]
    fn proptest_arena_label_corruption_is_observable_oracle_unaffected(
        keys in proptest::collection::vec(
            proptest::collection::vec(proptest::prelude::any::<u8>(), 32..=32),
            2..=64,
        ),
        target_idx in 0usize..1024,
        byte_idx in 0usize..32,
        mask in 1u8..=255,
    ) {
        let mut tree = AvlTree::new();
        let mut seen = std::collections::HashSet::new();
        for k in &keys {
            let k_arr: [u8; 32] = k.clone().try_into().unwrap();
            // `AvlTree::insert` panics if `key` equals either sentinel
            // (all-zero or all-FF). Skip those — they're not valid
            // user-insertable keys.
            if k_arr == [0u8; 32] || k_arr == [0xFFu8; 32] {
                continue;
            }
            if seen.insert(k_arr) {
                tree.insert(k_arr, vec![0u8]); // value content irrelevant
            }
        }
        // `MemoryArena::set_label` queues label updates; flush them
        // before sampling so the cached labels populated by
        // `label_of` during the build phase actually land in the
        // node arena (otherwise subsequent `label_of` calls keep
        // recomputing and the corruption write competes with stale
        // queue state).
        tree.arena_commit();

        // Baseline equality. Per-operation oracle tests in this same
        // file prove this for every other test; pin it here too.
        let baseline_root_digest = tree.root_digest();
        let baseline_oracle = tree.forced_full_recompute_digest();
        proptest::prop_assert_eq!(baseline_root_digest, baseline_oracle);

        // Build the proven-reachable node id set via explicit DFS
        // from root_id(). DO NOT use `all_nodes()` — that is raw
        // arena iteration which can include orphans not visited by
        // the oracle's subtree walk, weakening the property to
        // vacuous.
        let candidates = reachable_non_root_ids(&tree);
        proptest::prop_assume!(!candidates.is_empty());
        let id = candidates[target_idx % candidates.len()];

        // Capture the pre-corruption cached label for this node so
        // we can prove the post-corruption read differs. Then flush
        // again — `label_of_for_test` also queues a set_label if it
        // had to compute the label from children, so the cached
        // value needs to land before we corrupt.
        let pre = tree.label_of_for_test(id);
        tree.arena_commit();

        // Corrupt one byte of its arena-stored label, then flush
        // the corruption from the label queue to the node arena.
        tree.corrupt_arena_label_byte_for_test(id, byte_idx, mask);
        tree.arena_commit();

        // Oracle must still match the pre-corruption baseline (it
        // walks the subtree from structure, ignoring cached
        // labels).
        proptest::prop_assert_eq!(
            tree.forced_full_recompute_digest(),
            baseline_oracle,
            "force-recompute oracle must not depend on arena-stored labels",
        );

        // Root digest unchanged: `self.root_label` is the root-cache
        // field, NOT the arena's stored root-node label.
        proptest::prop_assert_eq!(
            tree.root_digest(),
            baseline_root_digest,
            "root_digest reads self.root_label; arena corruption of a non-root \
             must not propagate up automatically",
        );

        // The per-node reader must reflect the corruption.
        let post = tree.label_of_for_test(id);
        proptest::prop_assert_ne!(
            post,
            pre,
            "cached arena label must be observably corrupted after \
             corrupt_arena_label_byte_for_test",
        );
    }

    /// Cached `self.root_label`. Corruption must:
    /// - Change `root_digest()` (cache IS what `root_digest` reads).
    /// - Leave `forced_full_recompute_digest()` unchanged (oracle
    ///   recomputes from the root subtree structure).
    ///
    /// Pins the post-corruption divergence invariant: after
    /// corruption, `root_digest() != forced_full_recompute_digest()`.
    #[test]
    fn proptest_root_label_corruption_diverges_from_oracle(
        keys in proptest::collection::vec(
            proptest::collection::vec(proptest::prelude::any::<u8>(), 32..=32),
            1..=64,
        ),
        byte_idx in 0usize..32,
        mask in 1u8..=255,
    ) {
        let mut tree = AvlTree::new();
        let mut seen = std::collections::HashSet::new();
        for k in &keys {
            let k_arr: [u8; 32] = k.clone().try_into().unwrap();
            // Same sentinel filter as Proptest A: `AvlTree::insert`
            // panics on `key == NEGATIVE_INFINITY_KEY` (all-zero) or
            // `key == POSITIVE_INFINITY_KEY` (all-FF).
            if k_arr == [0u8; 32] || k_arr == [0xFFu8; 32] {
                continue;
            }
            if seen.insert(k_arr) {
                tree.insert(k_arr, vec![0u8]);
            }
        }
        // Flush queued label updates from the build phase so the
        // baseline `forced_full_recompute_digest()` reads from a
        // settled arena. (Same reason as Proptest A.)
        tree.arena_commit();

        let baseline_root_digest = tree.root_digest();
        let baseline_oracle = tree.forced_full_recompute_digest();
        proptest::prop_assert_eq!(baseline_root_digest, baseline_oracle);

        tree.corrupt_root_label_byte_for_test(byte_idx, mask);

        // Cache is load-bearing for root reads: root_digest now
        // differs.
        proptest::prop_assert_ne!(
            tree.root_digest(),
            baseline_root_digest,
            "root_digest must reflect the corruption of self.root_label",
        );

        // Oracle is independent: forced_full_recompute_digest is
        // unchanged.
        proptest::prop_assert_eq!(
            tree.forced_full_recompute_digest(),
            baseline_oracle,
            "force-recompute oracle must not consult self.root_label",
        );

        // Root recomputation diverges from the cache — the M-5
        // headline invariant.
        proptest::prop_assert_ne!(
            tree.root_digest(),
            tree.forced_full_recompute_digest(),
            "after root_label corruption, cache and oracle must disagree",
        );
    }
}
