use std::cell::RefCell;
use std::collections::HashMap;

use bytes::Bytes;
use ergo_avltree_rust::batch_avl_prover::BatchAVLProver;
use ergo_avltree_rust::batch_node::{AVLTree, InternalNode, LeafNode, Node};
use ergo_primitives::digest::ADDigest;

use super::dry_run::{apply_change_set_to_prover, DryRunInsertMap, DryRunRemoveMap};
use super::StateError;
use crate::avl::node::{AvlNode, NodeId};
use crate::avl::tree::AvlTree;

struct Resolver<'a> {
    ids: HashMap<[u8; 32], NodeId>,
    read_node: &'a mut dyn FnMut(NodeId) -> Result<AvlNode, StateError>,
}

// The upstream API accepts a function pointer, so scope a borrowed callback
// to this synchronous proof. The callback owns no tree state and cannot
// escape its scope or move to another thread. The helper restores the prior
// callback on both normal return and unwinding, including nested proofs.
scoped_tls_hkt::scoped_thread_local!(
    static RESOLVER: for<'a> &'a (dyn Fn(&[u8; 32]) -> Result<Node, StateError> + 'a)
);

fn failure(what: &'static str) -> StateError {
    StateError::InternalInvariant { what }
}

impl Resolver<'_> {
    fn load(&mut self, label: &[u8; 32]) -> Result<Node, StateError> {
        let id = *self
            .ids
            .get(label)
            .ok_or_else(|| failure("prover: unknown label"))?;
        let node = (self.read_node)(id)?;
        let loaded = match node {
            AvlNode::Leaf {
                key,
                value,
                next_key,
                ..
            } => LeafNode::new(
                &Bytes::copy_from_slice(&key),
                &Bytes::from(value),
                &Bytes::copy_from_slice(&next_key),
            ),
            AvlNode::Internal {
                key,
                left,
                right,
                balance,
                left_label,
                right_label,
                ..
            } => {
                let left_label = *left_label
                    .ok_or_else(|| failure("prover: missing left label"))?
                    .as_bytes();
                let right_label = *right_label
                    .ok_or_else(|| failure("prover: missing right label"))?
                    .as_bytes();
                self.ids.insert(left_label, left);
                self.ids.insert(right_label, right);
                InternalNode::new(
                    Some(Bytes::copy_from_slice(&key)),
                    &Node::new_label(&left_label),
                    &Node::new_label(&right_label),
                    balance,
                )
            }
        };
        let mut loaded = loaded.borrow_mut();
        if loaded.label() != *label {
            return Err(failure(
                "prover: stored node does not match authenticated label",
            ));
        }
        loaded.reset();
        Ok(loaded.clone())
    }
}

fn resolve(label: &[u8; 32]) -> Node {
    RESOLVER
        .with(|load| load(label).unwrap_or_else(|error| std::panic::resume_unwind(Box::new(error))))
}

/// Generate a proof by expanding only nodes the upstream prover visits.
/// Both the arena and the non-Send prover graph stay on the calling thread,
/// including uncommitted pipeline writes. A scoped callback adapts the
/// upstream function-pointer resolver without per-node channel round trips.
/// Every expanded node is authenticated against its parent label. Untouched
/// subtrees remain hash stubs, bounding work by the operation paths rather
/// than the entire UTXO set. No prover state survives this call.
pub(super) fn prove(
    tree: &AvlTree,
    to_lookup: &[[u8; 32]],
    to_remove: &DryRunRemoveMap,
    to_insert: &DryRunInsertMap,
) -> Result<(ADDigest, Vec<u8>), StateError> {
    let root_id = tree.root_id();
    let root_label = *tree.root_label().as_bytes();
    let height = tree.tree_height();
    let _session = tree.begin_read_session();
    prove_from_reader(
        root_id,
        root_label,
        height,
        to_lookup,
        to_remove,
        to_insert,
        |id| tree.prover_node(id),
    )
}

/// The caller retains ownership of the read view. Both the live arena and a
/// committed database snapshot use the same authenticated, scoped resolver.
pub(super) fn prove_from_reader(
    root_id: NodeId,
    root_label: [u8; 32],
    height: u8,
    to_lookup: &[[u8; 32]],
    to_remove: &DryRunRemoveMap,
    to_insert: &DryRunInsertMap,
    mut read_node: impl FnMut(NodeId) -> Result<AvlNode, StateError>,
) -> Result<(ADDigest, Vec<u8>), StateError> {
    let resolver = RefCell::new(Resolver {
        ids: HashMap::from([(root_label, root_id)]),
        read_node: &mut read_node,
    });
    let load = |label: &[u8; 32]| resolver.borrow_mut().load(label);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        RESOLVER.set(&load, || {
            let mut oracle = AVLTree::new(resolve, 32, None);
            oracle.root = Some(std::rc::Rc::new(RefCell::new(resolve(&root_label))));
            oracle.height = height as usize;
            let mut prover = BatchAVLProver::new(oracle, true);
            apply_change_set_to_prover(&mut prover, to_lookup, to_remove, to_insert)
        })
    }));
    result.unwrap_or_else(|payload| {
        Err(payload
            .downcast::<StateError>()
            .map(|error| *error)
            .unwrap_or_else(|_| failure("prover: upstream prover or node reader panicked")))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::dry_run::{apply_change_set_via_prover, self_check_candidate_proof};
    use ergo_primitives::digest::{blake2b256, Digest32};

    fn key(index: u32) -> [u8; 32] {
        *blake2b256(&index.to_be_bytes()).as_bytes()
    }

    #[test]
    fn lazy_proof_matches_full_hydration_across_mutations() {
        let mut tree = AvlTree::new();
        for index in 0..256 {
            tree.insert(key(index), index.to_be_bytes().to_vec());
        }
        for batch in 0..32 {
            let parent = tree.root_digest();
            let lookup = vec![key(200), key(200), key(1000 + batch)];
            let removed = (batch * 4..batch * 4 + 4)
                .map(|index| (key(index), ()))
                .collect();
            let inserted: DryRunInsertMap = (0..4)
                .map(|offset| (key(1000 + batch * 4 + offset), vec![batch as u8; 24]))
                .collect();
            let expected =
                apply_change_set_via_prover(&tree, &lookup, &removed, &inserted).unwrap();
            let actual = prove(&tree, &lookup, &removed, &inserted).unwrap();
            assert_eq!(actual, expected, "batch {batch}");
            assert_eq!(tree.root_digest(), parent);
            self_check_candidate_proof(&parent, &lookup, &removed, &inserted, &actual.1, &actual.0)
                .unwrap();
            for removed_key in removed.keys() {
                tree.remove(removed_key);
            }
            for (inserted_key, value) in inserted {
                tree.insert(inserted_key, value);
            }
            assert_eq!(tree.root_digest(), actual.0);
        }
    }

    #[test]
    fn lazy_proof_reads_paths_not_the_whole_tree() {
        let mut tree = AvlTree::new();
        for index in 0..8192 {
            tree.insert(key(index), vec![42; 32]);
        }
        let removed = DryRunRemoveMap::from([(key(42), ())]);
        let inserted = DryRunInsertMap::from([(key(9000), vec![7; 32])]);
        tree.arena_reset_read_count();
        let actual = prove(&tree, &[key(64)], &removed, &inserted).unwrap();
        let reads = tree.arena_read_count();
        assert!(reads < 256, "read {reads} arena nodes for three operations");
        let expected = apply_change_set_via_prover(&tree, &[key(64)], &removed, &inserted).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn lazy_proof_matches_full_hydration_for_a_large_mixed_batch() {
        let mut tree = AvlTree::new();
        for index in 0..8192 {
            tree.insert(key(index), vec![42; 32]);
        }
        let parent = tree.root_digest();
        let lookups: Vec<_> = (0..128)
            .flat_map(|index| [key(index * 17), key(index * 17)])
            .collect();
        let removed = (2048..2304).map(|index| (key(index), ())).collect();
        let inserted = (9000..9256)
            .map(|index| (key(index), index.to_be_bytes().to_vec()))
            .collect();
        let actual = prove(&tree, &lookups, &removed, &inserted).unwrap();
        assert_eq!(
            actual,
            apply_change_set_via_prover(&tree, &lookups, &removed, &inserted).unwrap(),
        );
        self_check_candidate_proof(&parent, &lookups, &removed, &inserted, &actual.1, &actual.0)
            .unwrap();
        assert_eq!(tree.root_digest(), parent);
    }

    #[test]
    fn lazy_proof_failure_does_not_poison_later_calls() {
        let mut tree = AvlTree::new();
        tree.insert(key(1), vec![1]);
        let parent = tree.root_digest();
        assert!(prove(
            &tree,
            &[],
            &DryRunRemoveMap::from([(key(2), ())]),
            &DryRunInsertMap::new()
        )
        .is_err());
        assert_eq!(tree.root_digest(), parent);
        let empty = prove(&tree, &[], &DryRunRemoveMap::new(), &DryRunInsertMap::new()).unwrap();
        assert_eq!(
            empty,
            apply_change_set_via_prover(
                &tree,
                &[],
                &DryRunRemoveMap::new(),
                &DryRunInsertMap::new()
            )
            .unwrap()
        );
    }

    #[test]
    fn nested_proof_restores_the_outer_reader_after_success_and_failure() {
        let mut outer = AvlTree::new();
        let mut inner = AvlTree::new();
        for index in 0..128 {
            outer.insert(key(index), vec![index as u8]);
            inner.insert(key(1000 + index), vec![42]);
        }
        let expected = apply_change_set_via_prover(
            &outer,
            &[key(42)],
            &DryRunRemoveMap::new(),
            &DryRunInsertMap::new(),
        )
        .unwrap();
        let mut nested = false;
        assert!(!RESOLVER.is_set());
        let actual = prove_from_reader(
            outer.root_id(),
            *outer.root_label().as_bytes(),
            outer.tree_height(),
            &[key(42)],
            &DryRunRemoveMap::new(),
            &DryRunInsertMap::new(),
            |id| {
                if !nested {
                    nested = true;
                    assert!(prove(
                        &inner,
                        &[key(1042)],
                        &DryRunRemoveMap::new(),
                        &DryRunInsertMap::new(),
                    )
                    .is_ok());
                    assert!(prove_from_reader(
                        inner.root_id(),
                        *inner.root_label().as_bytes(),
                        inner.tree_height(),
                        &[],
                        &DryRunRemoveMap::new(),
                        &DryRunInsertMap::new(),
                        |_| panic!("injected nested node-reader panic"),
                    )
                    .is_err());
                    assert!(RESOLVER.is_set());
                }
                outer.prover_node(id)
            },
        )
        .unwrap();
        assert!(nested);
        assert_eq!(actual, expected);
        assert!(!RESOLVER.is_set());
    }

    #[test]
    fn concurrent_proofs_have_independent_readers() {
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(4));
        let workers: Vec<_> = (0..4)
            .map(|worker| {
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let mut tree = AvlTree::new();
                    for index in 0..256 {
                        tree.insert(key(index), vec![worker; 32]);
                    }
                    barrier.wait();
                    for index in 0..32 {
                        let lookup = [key(index)];
                        let removed = DryRunRemoveMap::from([(key(64 + index), ())]);
                        let inserted = DryRunInsertMap::from([(key(1000 + index), vec![worker])]);
                        assert_eq!(
                            prove(&tree, &lookup, &removed, &inserted).unwrap(),
                            apply_change_set_via_prover(&tree, &lookup, &removed, &inserted)
                                .unwrap(),
                        );
                        assert!(!RESOLVER.is_set());
                    }
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }
    }

    #[test]
    fn lazy_proof_rejects_missing_root() {
        let tree = AvlTree::new_empty_with_label(42, 0, Digest32::from_bytes([0; 32]));
        assert!(prove(&tree, &[], &DryRunRemoveMap::new(), &DryRunInsertMap::new()).is_err());
    }

    #[test]
    fn unvisited_children_are_not_read() {
        let mut tree = AvlTree::new();
        for index in 0..128 {
            tree.insert(key(index), vec![index as u8]);
        }
        let root_id = tree.root_id();
        let root = tree.prover_node(root_id).unwrap();
        let expected = apply_change_set_via_prover(
            &tree,
            &[],
            &DryRunRemoveMap::new(),
            &DryRunInsertMap::new(),
        )
        .unwrap();
        let mut reads = 0;
        let actual = prove_from_reader(
            root_id,
            *tree.root_label().as_bytes(),
            tree.tree_height(),
            &[],
            &DryRunRemoveMap::new(),
            &DryRunInsertMap::new(),
            |id| {
                reads += 1;
                if id == root_id {
                    Ok(root.clone())
                } else {
                    Err(failure("injected unused child read failure"))
                }
            },
        )
        .unwrap();
        assert_eq!(actual, expected);
        assert_eq!(reads, 1, "only the requested root is read");
    }

    #[test]
    fn loaded_leaf_is_authenticated_before_use() {
        let mut tree = AvlTree::new();
        for index in 0..128 {
            tree.insert(key(index), vec![index as u8]);
        }
        let target = key(42);
        let result = prove_from_reader(
            tree.root_id(),
            *tree.root_label().as_bytes(),
            tree.tree_height(),
            &[target],
            &DryRunRemoveMap::new(),
            &DryRunInsertMap::new(),
            |id| {
                let mut node = tree.prover_node(id)?;
                if let AvlNode::Leaf { key, value, .. } = &mut node {
                    if *key == target {
                        value.push(0xff);
                    }
                }
                Ok(node)
            },
        );
        assert!(
            result.is_err(),
            "loaded data must not bypass label verification"
        );
        assert!(prove(
            &tree,
            &[target],
            &DryRunRemoveMap::new(),
            &DryRunInsertMap::new()
        )
        .is_ok());
    }

    #[test]
    fn lazy_proof_supports_legacy_nodes_and_rejects_corruption() {
        let mut tree = AvlTree::new();
        for index in 0..128 {
            tree.insert(key(index), vec![index as u8]);
        }
        let expected = apply_change_set_via_prover(
            &tree,
            &[key(42)],
            &DryRunRemoveMap::new(),
            &DryRunInsertMap::new(),
        )
        .unwrap();
        for (id, mut node) in tree.all_nodes() {
            if let AvlNode::Internal {
                left_label,
                right_label,
                label,
                ..
            } = &mut node
            {
                *left_label = None;
                *right_label = None;
                *label = None;
            }
            tree.load_node(id, node);
        }
        assert_eq!(
            prove(
                &tree,
                &[key(42)],
                &DryRunRemoveMap::new(),
                &DryRunInsertMap::new()
            )
            .unwrap(),
            expected
        );
        let mut root = tree.get_node(tree.root_id()).unwrap();
        if let AvlNode::Internal { left_label, .. } = &mut root {
            *left_label = Some(Digest32::from_bytes([0xAA; 32]));
        }
        tree.load_node(tree.root_id(), root);
        assert!(prove(
            &tree,
            &[key(42)],
            &DryRunRemoveMap::new(),
            &DryRunInsertMap::new()
        )
        .is_err());
    }

    #[test]
    fn lazy_proof_reads_cold_disk_and_uncommitted_nodes() {
        use crate::avl::arena::CachedDiskArena;
        use std::sync::Arc;

        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(redb::Database::create(dir.path().join("proof.redb")).unwrap());
        let mut tree = AvlTree::new();
        for index in 0..4096 {
            tree.insert(key(index), vec![42; 32]);
        }
        let write = db.begin_write().unwrap();
        {
            let mut table = write.open_table(crate::store::AVL_NODES).unwrap();
            for (id, node) in tree.all_nodes() {
                table
                    .insert(id, crate::store::node_to_bytes(&node).as_slice())
                    .unwrap();
            }
        }
        write.commit().unwrap();
        let mut disk_tree = AvlTree::new_with_arena(
            Box::new(CachedDiskArena::new(db, 4096)),
            tree.root_id(),
            tree.tree_height(),
            tree.next_id(),
            tree.root_label(),
        );
        disk_tree.insert(key(5000), vec![99; 32]);
        tree.insert(key(5000), vec![99; 32]);
        disk_tree.arena_reset_read_count();
        let removed = DryRunRemoveMap::from([(key(5000), ()), (key(42), ())]);
        let actual = prove(&disk_tree, &[key(64)], &removed, &DryRunInsertMap::new()).unwrap();
        assert!(disk_tree.arena_read_count() < 256);
        assert_eq!(
            actual,
            apply_change_set_via_prover(&tree, &[key(64)], &removed, &DryRunInsertMap::new())
                .unwrap()
        );
    }
}
