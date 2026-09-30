use std::cell::RefCell;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::mpsc::{channel, Receiver, Sender};

use bytes::Bytes;
use ergo_avltree_rust::batch_avl_prover::BatchAVLProver;
use ergo_avltree_rust::batch_node::{AVLTree, InternalNode, LeafNode, Node};
use ergo_primitives::digest::ADDigest;

use super::dry_run::{apply_change_set_to_prover, DryRunInsertMap, DryRunRemoveMap};
use super::StateError;
use crate::avl::node::{AvlNode, NodeId};
use crate::avl::tree::AvlTree;

// Count-bounded speculative cache, discarded with each proof. The upstream
// prover graph still expands only authenticated nodes actually visited.
const PREFETCH_CACHE_NODES: usize = 128;
const PREFETCH_DEPTH: usize = 2;

struct Resolver {
    ids: HashMap<[u8; 32], NodeId>,
    requests: Sender<NodeId>,
    replies: Receiver<Result<Vec<(NodeId, AvlNode)>, StateError>>,
    prefetched: lru::LruCache<NodeId, AvlNode>,
}

thread_local! {
    static RESOLVER: RefCell<Option<Resolver>> = const { RefCell::new(None) };
}

fn failure(what: &'static str) -> StateError {
    StateError::InternalInvariant { what }
}

impl Resolver {
    fn load(&mut self, label: &[u8; 32]) -> Result<Node, StateError> {
        let id = *self
            .ids
            .get(label)
            .ok_or_else(|| failure("prover: unknown label"))?;
        let node = if let Some(node) = self.prefetched.pop(&id) {
            node
        } else {
            self.requests
                .send(id)
                .map_err(|_| failure("prover: node reader stopped"))?;
            let packet = self
                .replies
                .recv()
                .map_err(|_| failure("prover: node reply missing"))??;
            // Preserve recently prefetched siblings across path changes, but
            // bound speculative copies independently of block/UTXO-set size.
            for (node_id, node) in packet {
                self.prefetched.put(node_id, node);
            }
            self.prefetched
                .pop(&id)
                .ok_or_else(|| failure("prover: requested node missing from packet"))?
        };
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
    RESOLVER.with(|slot| {
        slot.borrow_mut()
            .as_mut()
            .expect("scoped prover resolver")
            .load(label)
            .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(error)))
    })
}

/// Generate a proof by expanding only nodes the upstream prover visits.
/// The arena stays on its owning thread, including uncommitted pipeline
/// writes; the scoped worker adapts the upstream function-pointer resolver
/// without sharing its non-Send node graph or borrowing the arena unsafely.
/// Every expanded node is authenticated against its parent label. Untouched
/// subtrees remain hash stubs, bounding work by the operation paths rather
/// than the entire UTXO set. Small subtree packets amortize the blocking
/// owner/worker handoff. No prover state survives this call.
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
    let (requests, requested) = channel();
    let (replies, reply) = channel();
    std::thread::scope(|scope| {
        let worker = std::thread::Builder::new()
            .name("utxo-proof".into())
            .spawn_scoped(scope, move || {
                RESOLVER.with(|slot| {
                    *slot.borrow_mut() = Some(Resolver {
                        ids: HashMap::from([(root_label, root_id)]),
                        requests,
                        replies: reply,
                        prefetched: lru::LruCache::new(
                            NonZeroUsize::new(PREFETCH_CACHE_NODES).unwrap(),
                        ),
                    });
                });
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let mut oracle = AVLTree::new(resolve, 32, None);
                    oracle.root = Some(std::rc::Rc::new(RefCell::new(resolve(&root_label))));
                    oracle.height = height as usize;
                    let mut prover = BatchAVLProver::new(oracle, true);
                    apply_change_set_to_prover(&mut prover, to_lookup, to_remove, to_insert)
                }));
                RESOLVER.with(|slot| {
                    slot.borrow_mut().take();
                });
                result.unwrap_or_else(|payload| {
                    Err(payload
                        .downcast::<StateError>()
                        .map(|error| *error)
                        .unwrap_or_else(|_| failure("prover: upstream prover panicked")))
                })
            })
            .map_err(|_| failure("prover: failed to start worker"))?;
        while let Ok(id) = requested.recv() {
            let node = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let root = read_node(id)?;
                let mut packet = vec![(id, root)];
                // Two levels beyond the requested node, at most seven nodes.
                // Reads stay on the arena owner; the worker receives owned
                // copies. Child errors are deferred until the child is needed:
                // prefetch must not reject an otherwise valid untouched path.
                let mut level_start = 0;
                for _ in 0..PREFETCH_DEPTH {
                    let level_end = packet.len();
                    for index in level_start..level_end {
                        let AvlNode::Internal { left, right, .. } = &packet[index].1 else {
                            continue;
                        };
                        let children = [*left, *right];
                        for child in children {
                            if let Ok(node) = read_node(child) {
                                packet.push((child, node));
                            }
                        }
                    }
                    level_start = level_end;
                }
                Ok(packet)
            }))
            .unwrap_or_else(|_| Err(failure("prover: node read panicked")));
            if replies.send(node).is_err() {
                break;
            }
        }
        worker
            .join()
            .map_err(|_| failure("prover: worker panicked"))?
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
    fn lazy_proof_rejects_missing_root() {
        let tree = AvlTree::new_empty_with_label(42, 0, Digest32::from_bytes([0; 32]));
        assert!(prove(&tree, &[], &DryRunRemoveMap::new(), &DryRunInsertMap::new()).is_err());
    }

    #[test]
    fn speculative_child_read_errors_do_not_reject_an_unvisited_path() {
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
        assert_eq!(reads, 3, "one requested root and two speculative children");
    }

    #[test]
    fn prefetched_leaf_is_authenticated_before_use() {
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
            "prefetched data must not bypass label verification"
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
