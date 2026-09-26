//! Authenticated, on-demand reads from the snapshot's single held transaction.

use ergo_primitives::digest::{ADDigest, Digest32};
use redb::ReadOnlyTable;

use super::{CommittedSnapshot, StateError, AVL_NODES};
use crate::avl::digest::{internal_label, leaf_label};
use crate::avl::node::{AvlNode, NodeId, NULL_NODE};
use crate::store::dry_run::{DryRunInsertMap, DryRunRemoveMap};

pub(super) fn prove(
    snapshot: &CommittedSnapshot,
    to_lookup: &[[u8; 32]],
    to_remove: &DryRunRemoveMap,
    to_insert: &DryRunInsertMap,
) -> Result<(ADDigest, Vec<u8>, usize), StateError> {
    let meta = &snapshot.state_meta;
    if meta.root_node_id == NULL_NODE || meta.root_digest[32] != meta.tree_height {
        return Err(StateError::InternalInvariant {
            what: "snapshot prover: invalid root metadata",
        });
    }
    let mut nodes = SnapshotNodes {
        table: snapshot.txn.open_table(AVL_NODES)?,
        reads: 0,
    };
    let mut label = [0; 32];
    label.copy_from_slice(&meta.root_digest[..32]);
    let (root, proof) = crate::store::lazy_prover::prove_from_reader(
        meta.root_node_id,
        label,
        meta.tree_height,
        to_lookup,
        to_remove,
        to_insert,
        |id| nodes.normalized(id, 0),
    )?;
    Ok((root, proof, nodes.reads))
}

struct SnapshotNodes {
    table: ReadOnlyTable<u64, &'static [u8]>,
    reads: usize,
}

impl SnapshotNodes {
    fn read(&mut self, id: NodeId) -> Result<AvlNode, StateError> {
        self.reads += 1;
        let bytes = self
            .table
            .get(id)?
            .ok_or_else(|| StateError::DbCorruption {
                table: "avl_nodes",
                key: hex::encode(id.to_be_bytes()),
                reason: "missing node during snapshot proof".into(),
            })?;
        crate::store::node_from_bytes(bytes.value())
    }

    fn normalized(&mut self, id: NodeId, depth: u16) -> Result<AvlNode, StateError> {
        // Legacy rows lack child labels. Recover them without constructing a
        // retained node graph. Bound recursion even if legacy pointers cycle.
        if depth > u8::MAX as u16 {
            return Err(StateError::DbCorruption {
                table: "avl_nodes",
                key: hex::encode(id.to_be_bytes()),
                reason: "legacy subtree exceeds maximum AVL height".into(),
            });
        }
        let mut node = self.read(id)?;
        if let AvlNode::Internal {
            left,
            right,
            left_label,
            right_label,
            ..
        } = &mut node
        {
            if left_label.is_none() {
                *left_label = Some(self.label(*left, depth + 1)?);
            }
            if right_label.is_none() {
                *right_label = Some(self.label(*right, depth + 1)?);
            }
        }
        Ok(node)
    }

    fn label(&mut self, id: NodeId, depth: u16) -> Result<Digest32, StateError> {
        match self.normalized(id, depth)? {
            AvlNode::Leaf {
                key,
                value,
                next_key,
                ..
            } => Ok(leaf_label(&key, &value, &next_key)),
            AvlNode::Internal {
                balance,
                left_label: Some(left),
                right_label: Some(right),
                ..
            } => Ok(internal_label(balance, &left, &right)),
            _ => Err(StateError::InternalInvariant {
                what: "snapshot prover: child labels not normalized",
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::dry_run::{apply_change_set_to_prover, self_check_candidate_proof};
    use crate::store::StateStore;
    use ergo_primitives::digest::blake2b256;
    use redb::ReadableTable;

    fn key(n: u32) -> [u8; 32] {
        *blake2b256(&n.to_be_bytes()).as_bytes()
    }

    fn legacy_bytes(node: &AvlNode) -> Vec<u8> {
        if let AvlNode::Internal {
            key,
            left,
            right,
            balance,
            ..
        } = node
        {
            let mut bytes = vec![1];
            bytes.extend_from_slice(key);
            bytes.extend_from_slice(&left.to_be_bytes());
            bytes.extend_from_slice(&right.to_be_bytes());
            bytes.push(*balance as u8);
            bytes
        } else {
            crate::store::node_to_bytes(node)
        }
    }

    fn fixture(count: u32) -> (tempfile::TempDir, StateStore) {
        let tmp = tempfile::tempdir().unwrap();
        let mut store = StateStore::open(&tmp.path().join("state.redb")).unwrap();
        let boxes: Vec<_> = (0..count).map(|n| (key(n), vec![n as u8; 128])).collect();
        store.initialize_genesis(&boxes).unwrap();
        (tmp, store)
    }

    fn compare(
        snap: &CommittedSnapshot,
        lookup: &[[u8; 32]],
        remove: &DryRunRemoveMap,
        insert: &DryRunInsertMap,
    ) -> usize {
        let mut full = snap.hydrate_prover().unwrap();
        let expected = apply_change_set_to_prover(&mut full, lookup, remove, insert).unwrap();
        let (root, proof, reads) = prove(snap, lookup, remove, insert).unwrap();
        assert_eq!((root, &proof), (expected.0, &expected.1));
        self_check_candidate_proof(&snap.state_root(), lookup, remove, insert, &proof, &root)
            .unwrap();
        reads
    }

    #[test]
    fn snapshot_lazy_proof_matches_full_hydration_for_mixed_operations() {
        let (_tmp, store) = fixture(1024);
        let snap = store.committed_snapshot().unwrap().unwrap();
        compare(&snap, &[], &DryRunRemoveMap::new(), &DryRunInsertMap::new());
        for batch in 0..24 {
            let lookup = [key(batch), key(batch), key(9000)];
            let remove = (batch * 8..batch * 8 + 8).map(|n| (key(n), ())).collect();
            let mut insert: DryRunInsertMap = (2000 + batch * 8..2008 + batch * 8)
                .map(|n| (key(n), vec![n as u8; 200]))
                .collect();
            // Replacement and duplicate lookups exercise both canonical order and rotations.
            insert.insert(key(batch * 8), vec![0xFE; 300]);
            compare(&snap, &lookup, &remove, &insert);
        }
    }

    #[test]
    fn snapshot_lazy_proof_reads_only_paths() {
        let (_tmp, store) = fixture(8192);
        let snap = store.committed_snapshot().unwrap().unwrap();
        let reads = compare(
            &snap,
            &[key(64)],
            &DryRunRemoveMap::from([(key(42), ())]),
            &DryRunInsertMap::from([(key(9000), vec![7; 32])]),
        );
        assert!(reads < 256, "read {reads} nodes for three operation paths");
    }

    #[test]
    fn failed_proof_does_not_poison_the_next_build() {
        let (_tmp, store) = fixture(64);
        let snap = store.committed_snapshot().unwrap().unwrap();
        assert!(prove(
            &snap,
            &[],
            &DryRunRemoveMap::from([(key(9000), ())]),
            &DryRunInsertMap::new()
        )
        .is_err());
        compare(
            &snap,
            &[key(12)],
            &DryRunRemoveMap::new(),
            &DryRunInsertMap::new(),
        );
    }

    #[test]
    fn snapshot_proof_remains_frozen_across_node_removal_and_restoration() {
        let (_tmp, store) = fixture(64);
        let frozen = store.committed_snapshot().unwrap().unwrap();
        let root_id = frozen.state_meta.root_node_id;
        let remove = DryRunRemoveMap::from([(key(42), ())]);
        let insert = DryRunInsertMap::new();
        let expected = prove(&frozen, &[], &remove, &insert).unwrap();
        let original = {
            let write = crate::begin_write_qr(&store.db).unwrap();
            let original = write
                .open_table(AVL_NODES)
                .unwrap()
                .remove(root_id)
                .unwrap()
                .unwrap()
                .value()
                .to_vec();
            write.commit().unwrap();
            original
        };
        assert_eq!(prove(&frozen, &[], &remove, &insert).unwrap(), expected);
        let missing = store.committed_snapshot().unwrap().unwrap();
        assert!(matches!(
            prove(&missing, &[], &remove, &insert),
            Err(StateError::DbCorruption {
                table: "avl_nodes",
                ..
            })
        ));
        let write = crate::begin_write_qr(&store.db).unwrap();
        write
            .open_table(AVL_NODES)
            .unwrap()
            .insert(root_id, original.as_slice())
            .unwrap();
        write.commit().unwrap();
        let restored = store.committed_snapshot().unwrap().unwrap();
        assert_eq!(prove(&restored, &[], &remove, &insert).unwrap(), expected);
        assert!(
            prove(&missing, &[], &remove, &insert).is_err(),
            "failed view remains frozen too"
        );
    }

    #[test]
    fn malformed_child_labels_and_root_metadata_are_rejected() {
        let (_tmp, store) = fixture(64);
        let snap = store.committed_snapshot().unwrap().unwrap();
        let root_id = snap.state_meta.root_node_id;
        let write = crate::begin_write_qr(&store.db).unwrap();
        {
            let mut table = write.open_table(AVL_NODES).unwrap();
            let mut node =
                crate::store::node_from_bytes(table.get(root_id).unwrap().unwrap().value())
                    .unwrap();
            if let AvlNode::Internal { left_label, .. } = &mut node {
                *left_label = Some(Digest32::from_bytes([0xAA; 32]));
            }
            table
                .insert(root_id, crate::store::node_to_bytes(&node).as_slice())
                .unwrap();
        }
        write.commit().unwrap();
        let mut corrupt = store.committed_snapshot().unwrap().unwrap();
        assert!(prove(
            &corrupt,
            &[],
            &DryRunRemoveMap::new(),
            &DryRunInsertMap::new()
        )
        .is_err());
        corrupt.state_meta.root_digest[32] ^= 1;
        assert!(prove(
            &corrupt,
            &[],
            &DryRunRemoveMap::new(),
            &DryRunInsertMap::new()
        )
        .is_err());
        compare(
            &snap,
            &[key(42)],
            &DryRunRemoveMap::new(),
            &DryRunInsertMap::new(),
        );
    }

    #[test]
    fn legacy_nodes_match_the_full_prover_and_cycles_are_bounded() {
        let (_tmp, store) = fixture(128);
        let write = crate::begin_write_qr(&store.db).unwrap();
        {
            let mut table = write.open_table(AVL_NODES).unwrap();
            for (id, node) in store.tree.all_nodes() {
                table.insert(id, legacy_bytes(&node).as_slice()).unwrap();
            }
        }
        write.commit().unwrap();
        let snap = store.committed_snapshot().unwrap().unwrap();
        compare(
            &snap,
            &[key(42)],
            &DryRunRemoveMap::from([(key(10), ())]),
            &DryRunInsertMap::new(),
        );
        let root_id = snap.state_meta.root_node_id;
        let write = crate::begin_write_qr(&store.db).unwrap();
        {
            let mut table = write.open_table(AVL_NODES).unwrap();
            let mut node =
                crate::store::node_from_bytes(table.get(root_id).unwrap().unwrap().value())
                    .unwrap();
            if let AvlNode::Internal {
                left, left_label, ..
            } = &mut node
            {
                *left = root_id;
                *left_label = None;
            }
            table
                .insert(root_id, legacy_bytes(&node).as_slice())
                .unwrap();
        }
        write.commit().unwrap();
        let corrupt = store.committed_snapshot().unwrap().unwrap();
        assert!(matches!(
            prove(
                &corrupt,
                &[],
                &DryRunRemoveMap::new(),
                &DryRunInsertMap::new()
            ),
            Err(StateError::DbCorruption { .. })
        ));
    }

    #[test]
    #[ignore = "manual synthetic snapshot proof benchmark"]
    fn benchmark_committed_snapshot_proofs() {
        for count in [8192, 131072] {
            let (_tmp, store) = fixture(count);
            let snap = store.committed_snapshot().unwrap().unwrap();
            for operations in [1, 64] {
                let lookup: Vec<_> = (128..128 + operations).map(key).collect();
                let remove: DryRunRemoveMap = (0..operations).map(|n| (key(n), ())).collect();
                let insert: DryRunInsertMap = (count..count + operations)
                    .map(|n| (key(n), vec![0xAB; 128]))
                    .collect();
                let mut lazy_ms = Vec::new();
                let mut full_ms = Vec::new();
                let mut reads = 0;
                for iteration in 0..6 {
                    let start = std::time::Instant::now();
                    let actual = prove(&snap, &lookup, &remove, &insert).unwrap();
                    let lazy = start.elapsed().as_secs_f64() * 1000.0;
                    let start = std::time::Instant::now();
                    let mut full = snap.hydrate_prover().unwrap();
                    let expected =
                        apply_change_set_to_prover(&mut full, &lookup, &remove, &insert).unwrap();
                    let hydrated = start.elapsed().as_secs_f64() * 1000.0;
                    assert_eq!((actual.0, &actual.1), (expected.0, &expected.1));
                    reads = actual.2;
                    if iteration > 0 {
                        lazy_ms.push(lazy);
                        full_ms.push(hydrated);
                    }
                }
                lazy_ms.sort_by(f64::total_cmp);
                full_ms.sort_by(f64::total_cmp);
                println!("boxes={count} operations_per_kind={operations} nodes_read={reads} full_nodes={} lazy_ms={:.3} full_ms={:.3}", 2 * count + 1, lazy_ms[2], full_ms[2]);
            }
        }
    }
}
