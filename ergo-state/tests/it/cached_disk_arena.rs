//! Tests for the CachedDiskArena: dirty eviction safety, small-cache oracle
//! parity, abort/rebuild correctness, and label persistence.

use ergo_state::avl::arena::{CachedDiskArena, NodeArena};
use ergo_state::avl::node::AvlNode;
use ergo_state::store::{node_from_bytes, node_to_bytes};
use redb::{Database, TableDefinition};
use std::sync::Arc;
use tempfile::tempdir;

const AVL_NODES: TableDefinition<u64, &[u8]> = TableDefinition::new("avl_nodes");

fn make_arena(cache_bytes: usize) -> (Arc<Database>, CachedDiskArena, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("test.redb");
    let db = Arc::new(Database::create(path).unwrap());
    let arena = CachedDiskArena::new(Arc::clone(&db), cache_bytes);
    (db, arena, dir)
}

fn seed_redb(db: &Database, nodes: &[(u64, AvlNode)]) {
    let txn = ergo_state::begin_write_qr(db).unwrap();
    {
        let mut table = txn.open_table(AVL_NODES).unwrap();
        for (id, node) in nodes {
            table.insert(*id, node_to_bytes(node).as_slice()).unwrap();
        }
    }
    txn.commit().unwrap();
}

fn make_leaf(key_byte: u8, value: &[u8]) -> AvlNode {
    let mut key = [0u8; 32];
    key[0] = key_byte;
    AvlNode::Leaf {
        key,
        value: value.to_vec(),
        next_key: [0xFF; 32],
        label: None,
    }
}

// ============================================================================
// Dirty eviction safety
// ============================================================================

// ----- happy path -----

#[test]
fn dirty_nodes_not_evicted_by_clean_cache_pressure() {
    let (_db, mut arena, _dir) = make_arena(300);

    for i in 1u64..=10 {
        arena.put(i, make_leaf(i as u8, &[i as u8; 100]));
    }

    for i in 1u64..=10 {
        assert!(
            arena.get(i).is_some(),
            "dirty node {i} should be readable despite cache pressure"
        );
    }
}

#[test]
fn commit_moves_dirty_to_clean_with_eviction() {
    let (db, mut arena, _dir) = make_arena(400);

    let nodes: Vec<(u64, AvlNode)> = (1u64..=5)
        .map(|i| (i, make_leaf(i as u8, &[i as u8; 100])))
        .collect();
    for (id, node) in &nodes {
        arena.put(*id, node.clone());
    }
    seed_redb(&db, &nodes);

    arena.commit();

    for i in 1u64..=5 {
        assert!(
            arena.get(i).is_some(),
            "node {i} should be readable after commit"
        );
    }
}

// ============================================================================
// Abort discards uncommitted state
// ============================================================================

#[test]
fn abort_discards_dirty_and_clean() {
    let (db, mut arena, _dir) = make_arena(10_000);

    let committed = vec![
        (1, make_leaf(0x10, &[1])),
        (2, make_leaf(0x20, &[2])),
        (3, make_leaf(0x30, &[3])),
    ];
    seed_redb(&db, &committed);

    for i in 1u64..=3 {
        assert!(arena.get(i).is_some());
    }

    arena.put(1, make_leaf(0x10, &[0xFF]));
    arena.put(4, make_leaf(0x40, &[4]));

    let n1 = arena.get(1).unwrap();
    if let AvlNode::Leaf { value, .. } = &n1 {
        assert_eq!(value, &[0xFF]);
    }
    assert!(arena.get(4).is_some());

    arena.abort();

    let n1 = arena.get(1).unwrap();
    if let AvlNode::Leaf { value, .. } = &n1 {
        assert_eq!(
            value,
            &[1],
            "after abort, node 1 should revert to committed"
        );
    }
    assert!(
        arena.get(4).is_none(),
        "node 4 should not exist after abort"
    );
}

// ============================================================================
// Remove tracking
// ============================================================================

#[test]
fn removed_nodes_not_visible_even_if_in_redb() {
    let (db, mut arena, _dir) = make_arena(10_000);

    seed_redb(&db, &[(1, make_leaf(0x10, &[1]))]);
    assert!(arena.get(1).is_some());

    arena.remove(1);

    assert!(arena.get(1).is_none());
    assert!(!arena.contains(1));
}

// ============================================================================
// Label persistence roundtrip
// ============================================================================

#[test]
fn labels_stripped_on_serialization() {
    use ergo_primitives::digest::Digest32;

    // Labels are derived cache data — never persisted.
    let label = Digest32::from_bytes([0xAB; 32]);
    let leaf = AvlNode::Leaf {
        key: [0x10; 32],
        value: vec![1, 2, 3],
        next_key: [0xFF; 32],
        label: Some(label),
    };
    let bytes = node_to_bytes(&leaf);
    let restored = node_from_bytes(&bytes).expect("self-built bytes parse");
    match restored {
        AvlNode::Leaf { label, .. } => {
            assert!(label.is_none(), "label should be stripped on write");
        }
        _ => panic!("expected leaf"),
    }

    // v2 Internal carries child labels on the wire; the self-label field is
    // still derived cache data and must be stripped on write.
    let ll = Digest32::from_bytes([0xC1; 32]);
    let rl = Digest32::from_bytes([0xC2; 32]);
    let internal = AvlNode::Internal {
        key: [0x20; 32],
        left: 1,
        right: 2,
        balance: -1,
        left_label: Some(ll),
        right_label: Some(rl),
        label: Some(label),
    };
    let bytes = node_to_bytes(&internal);
    let restored = node_from_bytes(&bytes).expect("self-built bytes parse");
    match restored {
        AvlNode::Internal {
            label,
            left_label,
            right_label,
            ..
        } => {
            assert!(label.is_none(), "self-label should be stripped on write");
            assert_eq!(left_label, Some(ll), "child labels survive roundtrip in v2");
            assert_eq!(right_label, Some(rl));
        }
        _ => panic!("expected internal"),
    }
}

#[test]
fn v1_format_parsed_without_label() {
    let mut data = vec![0x00u8];
    data.extend_from_slice(&[0x10; 32]);
    data.extend_from_slice(&3u32.to_be_bytes());
    data.extend_from_slice(&[1, 2, 3]);
    data.extend_from_slice(&[0xFF; 32]);

    let node = node_from_bytes(&data).expect("v1 leaf bytes parse");
    match node {
        AvlNode::Leaf { label, .. } => {
            assert!(label.is_none(), "v1 format should parse with label=None");
        }
        _ => panic!("expected leaf"),
    }
}

// ============================================================================
// iter_all with dirty overlay
// ============================================================================

#[test]
fn iter_all_includes_dirty_and_committed() {
    let (db, mut arena, _dir) = make_arena(10_000);

    seed_redb(
        &db,
        &[(1, make_leaf(0x10, &[1])), (2, make_leaf(0x20, &[2]))],
    );

    arena.put(3, make_leaf(0x30, &[3]));
    arena.put(1, make_leaf(0x10, &[0xFF]));

    let all: std::collections::HashMap<u64, AvlNode> = arena.iter_all().into_iter().collect();

    assert_eq!(all.len(), 3);
    assert!(all.contains_key(&1));
    assert!(all.contains_key(&2));
    assert!(all.contains_key(&3));

    if let AvlNode::Leaf { value, .. } = &all[&1] {
        assert_eq!(value, &[0xFF], "dirty overlay should win");
    }
}

// ============================================================================
// Small-cache StateStore open
// ============================================================================

#[test]
fn small_cache_state_store_opens_and_operates() {
    let dir = tempdir().unwrap();
    let store = ergo_state::store::StateStore::open_with_cache(
        dir.path().join("state.redb").as_path(),
        4096,
    )
    .unwrap();
    assert_eq!(store.height(), 0);
}
