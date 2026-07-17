//! Unit tests for the snapshot codec — node-level byte layout and
//! round-trips, manifest/chunk assembly, the snapshot server, the
//! consume-side reconstruction, and the recursion/DoS bounds on
//! peer-supplied bytes. Moved verbatim from the former inline
//! `mod tests` block of `avl/snapshot_codec.rs`.

use super::manifest::{compute_node_label, parse_chunk};
use crate::avl::tree::AvlTree;

use super::*;
use ergo_primitives::digest::Digest32;

fn d32(b: u8) -> Digest32 {
    Digest32::from_bytes([b; LABEL_SIZE])
}

fn key32(b: u8) -> [u8; KEY_SIZE] {
    [b; KEY_SIZE]
}

fn fixed_labels(left: Digest32, right: Digest32) -> impl ChildLabels {
    let l = left;
    let r = right;
    ClosureChildLabels {
        left: move |_| Ok(l),
        right: move |_| Ok(r),
    }
}

fn tree_with_missing_root() -> AvlTree {
    AvlTree::new_empty_with_label(42, 0, Digest32::from_bytes([0u8; LABEL_SIZE]))
}

fn assert_internal_invariant(err: StateError, expected_what: &'static str) {
    match err {
        StateError::InternalInvariant { what } => assert_eq!(what, expected_what),
        other => panic!("expected InternalInvariant, got {other:?}"),
    }
}

// ----- happy path -----

#[test]
fn internal_node_serialize_byte_layout() {
    // Build an internal node with deterministic values.
    let node = AvlNode::Internal {
        key: key32(0xAA),
        left: 0,
        right: 0,
        balance: 1,
        left_label: None,
        right_label: None,
        label: None,
    };
    let labels = fixed_labels(d32(0xBB), d32(0xCC));
    let bytes = serialize_prover_node(&node, &labels).unwrap();

    // Expected layout: 0x00 || 0x01 (balance) || [0xAA;32] || [0xBB;32] || [0xCC;32]
    assert_eq!(bytes.len(), 1 + 1 + 32 + 32 + 32);
    assert_eq!(bytes[0], INTERNAL_NODE_PREFIX);
    assert_eq!(bytes[1], 0x01);
    assert_eq!(&bytes[2..34], &[0xAAu8; 32][..]);
    assert_eq!(&bytes[34..66], &[0xBBu8; 32][..]);
    assert_eq!(&bytes[66..98], &[0xCCu8; 32][..]);
}

#[test]
fn internal_node_negative_balance_is_byte_cast() {
    // Scala writes balance via `w.put(n.balance)` — a single byte.
    // Negative balances (-1) round-trip via i8↔u8 reinterpretation.
    let node = AvlNode::Internal {
        key: key32(0x00),
        left: 0,
        right: 0,
        balance: -1,
        left_label: None,
        right_label: None,
        label: None,
    };
    let labels = fixed_labels(d32(0x00), d32(0x00));
    let bytes = serialize_prover_node(&node, &labels).unwrap();
    assert_eq!(bytes[1], 0xFF, "i8(-1) must encode as byte 0xFF");
}

#[test]
fn leaf_node_serialize_byte_layout() {
    let node = AvlNode::Leaf {
        key: key32(0x11),
        value: vec![0x42, 0x43, 0x44, 0x45],
        next_key: key32(0x22),
        label: None,
    };
    // labels arg is unused for leaves; pass dummy.
    let labels = fixed_labels(d32(0), d32(0));
    let bytes = serialize_prover_node(&node, &labels).unwrap();

    // Expected: 0x01 || [0x11;32] || 0x00 0x00 0x00 0x04 (BE) || [0x42..0x45] || [0x22;32]
    assert_eq!(bytes.len(), 1 + 32 + 4 + 4 + 32);
    assert_eq!(bytes[0], LEAF_PREFIX);
    assert_eq!(&bytes[1..33], &[0x11u8; 32][..]);
    assert_eq!(&bytes[33..37], &[0x00, 0x00, 0x00, 0x04]);
    assert_eq!(&bytes[37..41], &[0x42, 0x43, 0x44, 0x45]);
    assert_eq!(&bytes[41..73], &[0x22u8; 32][..]);
}

// ----- round-trips -----

#[test]
fn internal_node_roundtrip() {
    let node = AvlNode::Internal {
        key: key32(0x77),
        left: 0,
        right: 0,
        balance: -1,
        left_label: None,
        right_label: None,
        label: None,
    };
    let labels = fixed_labels(d32(0x88), d32(0x99));
    let bytes = serialize_prover_node(&node, &labels).unwrap();
    let (parsed, consumed) = parse_prover_node(&bytes).unwrap();
    assert_eq!(consumed, bytes.len());
    match parsed {
        ParsedProverNode::Internal {
            balance,
            key,
            left_label,
            right_label,
        } => {
            assert_eq!(balance, -1);
            assert_eq!(key, key32(0x77));
            assert_eq!(left_label, [0x88u8; 32]);
            assert_eq!(right_label, [0x99u8; 32]);
        }
        other => panic!("expected Internal, got {other:?}"),
    }
}

#[test]
fn leaf_node_roundtrip_with_empty_value() {
    let node = AvlNode::Leaf {
        key: key32(0xF0),
        value: vec![],
        next_key: key32(0xF1),
        label: None,
    };
    let labels = fixed_labels(d32(0), d32(0));
    let bytes = serialize_prover_node(&node, &labels).unwrap();
    let (parsed, consumed) = parse_prover_node(&bytes).unwrap();
    assert_eq!(consumed, bytes.len());
    match parsed {
        ParsedProverNode::Leaf {
            key,
            value,
            next_leaf_key,
        } => {
            assert_eq!(key, key32(0xF0));
            assert!(value.is_empty());
            assert_eq!(next_leaf_key, key32(0xF1));
        }
        other => panic!("expected Leaf, got {other:?}"),
    }
}

#[test]
fn leaf_node_roundtrip_large_value() {
    let value: Vec<u8> = (0u8..255).chain(0u8..255).collect();
    let node = AvlNode::Leaf {
        key: key32(0x55),
        value: value.clone(),
        next_key: key32(0x56),
        label: None,
    };
    let labels = fixed_labels(d32(0), d32(0));
    let bytes = serialize_prover_node(&node, &labels).unwrap();
    let (parsed, _) = parse_prover_node(&bytes).unwrap();
    match parsed {
        ParsedProverNode::Leaf { value: v, .. } => assert_eq!(v, value),
        other => panic!("expected Leaf, got {other:?}"),
    }
}

#[test]
fn concatenated_nodes_parse_sequentially() {
    // Pin "stream-of-nodes" behavior — the parser must report
    // bytes consumed so the next node's offset is calculable.
    // This is how manifest serialization will lay out a tree
    // walk in part 2c.
    let leaf = AvlNode::Leaf {
        key: key32(0x01),
        value: vec![1, 2, 3],
        next_key: key32(0x02),
        label: None,
    };
    let internal = AvlNode::Internal {
        key: key32(0x10),
        left: 0,
        right: 0,
        balance: 0,
        left_label: None,
        right_label: None,
        label: None,
    };
    let dummy = fixed_labels(d32(0x20), d32(0x21));
    let mut stream = serialize_prover_node(&leaf, &dummy).unwrap();
    stream.extend_from_slice(&serialize_prover_node(&internal, &dummy).unwrap());

    let (first, consumed1) = parse_prover_node(&stream).unwrap();
    assert!(matches!(first, ParsedProverNode::Leaf { .. }));
    let (second, _consumed2) = parse_prover_node(&stream[consumed1..]).unwrap();
    assert!(matches!(second, ParsedProverNode::Internal { .. }));
}

// ----- error paths -----

#[test]
fn parse_rejects_empty_payload() {
    let err = parse_prover_node(&[]).unwrap_err();
    let msg = format!("{err:?}");
    assert!(msg.contains("empty"), "error: {msg}");
}

#[test]
fn parse_rejects_unknown_prefix() {
    let err = parse_prover_node(&[0xFFu8]).unwrap_err();
    let msg = format!("{err:?}");
    assert!(msg.contains("unknown prover-node prefix"), "error: {msg}");
    assert!(msg.contains("0xff"), "error must show the byte: {msg}");
}

#[test]
fn parse_rejects_truncated_internal() {
    // Internal needs 1 + 1 + 32 + 32 + 32 = 98 body bytes after
    // prefix. Anything shorter must error.
    let payload = vec![INTERNAL_NODE_PREFIX, 0x00]; // prefix + balance only
    let err = parse_prover_node(&payload).unwrap_err();
    let msg = format!("{err:?}");
    assert!(msg.contains("truncated"), "error: {msg}");
}

#[test]
fn parse_rejects_truncated_leaf_header() {
    // Leaf needs at least prefix + key + value_len = 37 bytes
    // before any value bytes can be read.
    let payload = vec![LEAF_PREFIX, 0x00]; // missing key and length
    let err = parse_prover_node(&payload).unwrap_err();
    let msg = format!("{err:?}");
    assert!(msg.contains("truncated"), "error: {msg}");
}

/// Build a snapshot internal-node payload (prefix + balance byte +
/// key + left_label + right_label) with caller-chosen balance byte.
/// Used by the rejection tests below.
fn snapshot_internal_payload(balance_byte: u8) -> Vec<u8> {
    let mut payload = vec![INTERNAL_NODE_PREFIX, balance_byte];
    payload.extend_from_slice(&[0x42; KEY_SIZE]);
    payload.extend_from_slice(&[0xAA; LABEL_SIZE]);
    payload.extend_from_slice(&[0xBB; LABEL_SIZE]);
    payload
}

#[test]
fn parse_rejects_internal_balance_2() {
    // The Mode-2 install DoS the ingress gate closes: a snapshot
    // chunk with a balance byte outside {-1, 0, 1} would otherwise
    // propagate to tree rotations and panic the apply thread. The
    // codec must reject here, before any AVL_NODES write.
    let payload = snapshot_internal_payload(0x02);
    let err = parse_prover_node(&payload).unwrap_err();
    let msg = format!("{err:?}");
    assert!(msg.contains("balance 2"), "wrong message: {msg}");
    assert!(msg.contains("{-1, 0, 1}"), "must cite invariant: {msg}");
}

#[test]
fn parse_rejects_internal_balance_i8_max() {
    let payload = snapshot_internal_payload(0x7F);
    let err = parse_prover_node(&payload).unwrap_err();
    assert!(format!("{err:?}").contains("balance 127"));
}

#[test]
fn parse_rejects_internal_balance_i8_min() {
    // 0x80 sign-extends to i8(-128) via `body[0] as i8`. The gate
    // must catch it — the bug surface is the reverse case where
    // someone replaces the i8 cast with a u8 check and accidentally
    // accepts 0x80 as "+128".
    let payload = snapshot_internal_payload(0x80);
    let err = parse_prover_node(&payload).unwrap_err();
    assert!(format!("{err:?}").contains("balance -128"));
}

#[test]
fn parse_accepts_internal_balance_minus_one() {
    // 0xFF must round-trip as i8(-1). Pins the negative-balance
    // path that's easy to break with a naive u8 range check.
    let payload = snapshot_internal_payload(0xFF);
    let (parsed, _) = parse_prover_node(&payload).expect("0xFF -> -1 must parse");
    match parsed {
        ParsedProverNode::Internal { balance, .. } => assert_eq!(balance, -1),
        _ => panic!("expected Internal"),
    }
}

// ----- manifest / chunk assembly -----

/// Empty tree (just the sentinel leaf): manifest is `rootHeight=0`,
/// `manifestDepth=14`, then the sentinel leaf body — total 71 bytes.
/// Pins:
/// - The 2-byte header layout
/// - The depth-walking behavior (just visits the root, no recursion
///   needed since it's a leaf)
/// - The NEG_INF / POS_INF sentinel keys via the leaf encoding
#[test]
fn manifest_of_empty_tree_is_sentinel_leaf() {
    use crate::avl::digest::{NEGATIVE_INFINITY_KEY, POSITIVE_INFINITY_KEY};
    let tree = AvlTree::new();
    let bytes = serialize_manifest(&tree, MAINNET_MANIFEST_DEPTH).unwrap();

    // Header: rootHeight=0, manifestDepth=14.
    assert_eq!(bytes[0], 0, "rootHeight for empty tree must be 0");
    assert_eq!(bytes[1], MAINNET_MANIFEST_DEPTH);

    // Body = sentinel leaf: 0x01 || NEG_INF || 0x00*4 || POS_INF.
    // No value bytes between the length prefix and next_leaf_key.
    // Total = 2 (header) + 1 (leaf prefix) + 32 (key) + 4 (len) + 32 (next).
    assert_eq!(bytes.len(), 2 + 1 + KEY_SIZE + 4 + KEY_SIZE);
    assert_eq!(bytes[2], LEAF_PREFIX);
    assert_eq!(&bytes[3..3 + KEY_SIZE], &NEGATIVE_INFINITY_KEY[..]);
    assert_eq!(&bytes[3 + KEY_SIZE..3 + KEY_SIZE + 4], &0u32.to_be_bytes(),);
    assert_eq!(
        &bytes[3 + KEY_SIZE + 4..3 + KEY_SIZE + 4 + KEY_SIZE],
        &POSITIVE_INFINITY_KEY[..],
    );
}

#[test]
fn manifest_of_two_leaf_tree_has_one_internal_and_three_leaves() {
    // Inserting two real keys gives a tree shaped:
    //
    //              Internal
    //             /        \
    //         Leaf(NEG_INF) Internal
    //                         /     \
    //                      Leaf(k1)  Leaf(k2 → POS_INF)
    //
    // Exact balancing depends on the inserts' AVL rebalancing,
    // but parse-roundtripping the manifest should always yield
    // at least one internal node + the original sentinel leaf
    // + the two inserted leaves.
    let mut tree = AvlTree::new();
    tree.insert([0x10; 32], vec![0xAA, 0xBB]);
    tree.insert([0x20; 32], vec![0xCC, 0xDD]);
    let bytes = serialize_manifest(&tree, MAINNET_MANIFEST_DEPTH).unwrap();

    // Header.
    assert_eq!(bytes[1], MAINNET_MANIFEST_DEPTH);
    assert!(bytes[0] >= 1, "tree with 3 leaves has height >= 1");

    // Walk the body, classifying each node.
    let mut cursor = 2usize;
    let mut leaf_count = 0usize;
    let mut internal_count = 0usize;
    while cursor < bytes.len() {
        let (parsed, consumed) = parse_prover_node(&bytes[cursor..]).unwrap();
        match parsed {
            ParsedProverNode::Leaf { .. } => leaf_count += 1,
            ParsedProverNode::Internal { .. } => internal_count += 1,
        }
        cursor += consumed;
    }
    assert_eq!(cursor, bytes.len(), "manifest bytes consumed exactly");
    assert!(
        internal_count >= 1,
        "tree of 3 leaves must have at least 1 internal node; got {internal_count}",
    );
    assert_eq!(
        leaf_count, 3,
        "expected sentinel + 2 inserted leaves = 3 leaves; got {leaf_count}",
    );
}

#[test]
fn enumerate_chunk_roots_empty_for_shallow_tree() {
    // Trees shallower than `manifest_depth` have no chunks —
    // every node fits in the manifest top-subtree.
    let mut tree = AvlTree::new();
    tree.insert([0x10; 32], vec![0xAA]);
    tree.insert([0x20; 32], vec![0xBB]);
    let roots = enumerate_chunk_roots(&tree, MAINNET_MANIFEST_DEPTH).unwrap();
    assert!(
        roots.is_empty(),
        "small tree must produce no chunk roots at depth 14; got {} roots",
        roots.len(),
    );
}

#[test]
fn enumerate_chunk_roots_with_shallow_manifest_depth() {
    // Force chunks by using a very shallow manifest depth.
    // With manifest_depth=1, any internal node at the root has
    // its two children as chunk roots.
    let mut tree = AvlTree::new();
    tree.insert([0x10; 32], vec![0xAA]);
    tree.insert([0x20; 32], vec![0xBB]);
    tree.insert([0x30; 32], vec![0xCC]);
    let roots = enumerate_chunk_roots(&tree, 1).unwrap();
    // Root is an internal node → its two children are chunk roots.
    assert_eq!(roots.len(), 2);
}

#[test]
fn chunk_roundtrip_via_parse() {
    // serialize_chunk + parse the resulting bytes back into a
    // sequence of prover nodes. Lock the format end-to-end.
    let mut tree = AvlTree::new();
    tree.insert([0x10; 32], vec![0xAA, 0xBB, 0xCC]);
    tree.insert([0x20; 32], vec![0xDD]);
    // Use the root itself as the "chunk root" — covers the
    // full-tree-as-chunk case.
    let chunk_bytes = serialize_chunk(&tree, tree.root_id()).unwrap();
    let mut cursor = 0usize;
    let mut counts = (0usize, 0usize); // (internals, leaves)
    while cursor < chunk_bytes.len() {
        let (parsed, consumed) = parse_prover_node(&chunk_bytes[cursor..]).unwrap();
        match parsed {
            ParsedProverNode::Leaf { .. } => counts.1 += 1,
            ParsedProverNode::Internal { .. } => counts.0 += 1,
        }
        cursor += consumed;
    }
    assert_eq!(cursor, chunk_bytes.len(), "no trailing bytes");
    assert_eq!(counts.1, 3, "expected 3 leaves (2 inserts + sentinel)");
    assert!(counts.0 >= 1, "expected ≥1 internal; got {}", counts.0);
}

#[test]
fn parse_rejects_leaf_body_shorter_than_declared_value_length() {
    // Build a leaf header that claims a 100-byte value but only
    // provides 4 bytes of body — the parser must refuse rather
    // than read past the end.
    let mut payload = vec![LEAF_PREFIX];
    payload.extend_from_slice(&[0x00u8; KEY_SIZE]); // key
    payload.extend_from_slice(&100u32.to_be_bytes()); // value length = 100
    payload.extend_from_slice(&[0xAAu8; 4]); // only 4 value bytes
    let err = parse_prover_node(&payload).unwrap_err();
    let msg = format!("{err:?}");
    assert!(msg.contains("truncated"), "error: {msg}");
}

#[test]
fn label_walk_missing_arena_node_returns_internal_invariant() {
    let tree = tree_with_missing_root();
    let err = compute_node_label(&tree, tree.root_id()).unwrap_err();
    assert_internal_invariant(err, "snapshot codec: missing AVL node during label walk");
}

#[test]
fn manifest_walk_missing_arena_node_returns_internal_invariant() {
    let tree = tree_with_missing_root();
    let err = serialize_manifest(&tree, MAINNET_MANIFEST_DEPTH).unwrap_err();
    assert_internal_invariant(err, "snapshot codec: missing AVL node during manifest walk");
}

#[test]
fn chunk_walk_missing_arena_node_returns_internal_invariant() {
    let tree = tree_with_missing_root();
    let err = serialize_chunk(&tree, tree.root_id()).unwrap_err();
    assert_internal_invariant(err, "snapshot codec: missing AVL node during chunk walk");
}

#[test]
fn chunk_root_enumeration_missing_arena_node_returns_internal_invariant() {
    let tree = tree_with_missing_root();
    let err = enumerate_chunk_roots(&tree, MAINNET_MANIFEST_DEPTH).unwrap_err();
    assert_internal_invariant(
        err,
        "snapshot codec: missing AVL node while enumerating chunk roots",
    );
}

// ----- snapshot server -----

#[test]
fn server_build_manifest_id_matches_root_label() {
    // SnapshotServer.manifest_id MUST equal the AVL+ root label —
    // this is the on-the-wire id peers reference when requesting
    // the manifest, and it must agree with the header state_root.
    let mut tree = AvlTree::new();
    tree.insert([0x10; 32], vec![0xAA]);
    tree.insert([0x20; 32], vec![0xBB]);
    let server = SnapshotServer::build(&tree, 100, MAINNET_MANIFEST_DEPTH).unwrap();
    let expected_root = compute_node_label(&tree, tree.root_id()).unwrap();
    assert_eq!(server.manifest_id, expected_root);
    assert_eq!(server.height, 100);
}

#[test]
fn server_build_manifest_bytes_match_serialize_manifest() {
    // SnapshotServer.manifest_bytes MUST equal what
    // serialize_manifest produces for the same tree — server side
    // doesn't get to reshape what goes on the wire.
    let mut tree = AvlTree::new();
    tree.insert([0x10; 32], vec![0xAA, 0xBB]);
    tree.insert([0x20; 32], vec![0xCC]);
    let server = SnapshotServer::build(&tree, 1, MAINNET_MANIFEST_DEPTH).unwrap();
    let expected = serialize_manifest(&tree, MAINNET_MANIFEST_DEPTH).unwrap();
    assert_eq!(server.manifest_bytes, expected);
}

#[test]
fn server_build_empty_chunks_for_shallow_tree() {
    // At mainnet manifest_depth=14, a 3-leaf tree fits entirely in
    // the manifest top-subtree — zero chunks to serve.
    let mut tree = AvlTree::new();
    tree.insert([0x10; 32], vec![0xAA]);
    tree.insert([0x20; 32], vec![0xBB]);
    let server = SnapshotServer::build(&tree, 1, MAINNET_MANIFEST_DEPTH).unwrap();
    assert!(server.chunks.is_empty());
}

#[test]
fn server_build_chunks_match_codec_at_shallow_depth() {
    // Force chunks with manifest_depth=1. Each chunk in the
    // server must match (compute_node_label, serialize_chunk) for
    // its NodeId — proving server-side bookkeeping matches the
    // codec primitives.
    let mut tree = AvlTree::new();
    tree.insert([0x10; 32], vec![0xAA]);
    tree.insert([0x20; 32], vec![0xBB]);
    tree.insert([0x30; 32], vec![0xCC]);
    let server = SnapshotServer::build(&tree, 1, 1).unwrap();
    let codec_roots = enumerate_chunk_roots(&tree, 1).unwrap();
    assert_eq!(server.chunks.len(), codec_roots.len());
    for (root_id, (server_id, server_bytes)) in codec_roots.iter().zip(&server.chunks) {
        let expected_id = compute_node_label(&tree, *root_id).unwrap();
        let expected_bytes = serialize_chunk(&tree, *root_id).unwrap();
        assert_eq!(*server_id, expected_id);
        assert_eq!(*server_bytes, expected_bytes);
    }
}

#[test]
fn server_chunk_by_id_finds_present_and_misses_unknown() {
    let mut tree = AvlTree::new();
    tree.insert([0x10; 32], vec![0xAA]);
    tree.insert([0x20; 32], vec![0xBB]);
    tree.insert([0x30; 32], vec![0xCC]);
    let server = SnapshotServer::build(&tree, 1, 1).unwrap();
    assert!(!server.chunks.is_empty(), "test precondition");

    // Present id resolves to the stored bytes.
    let (known_id, known_bytes) = server.chunks[0].clone();
    let looked_up = server.chunk_by_id(&known_id).expect("known id resolves");
    assert_eq!(looked_up, known_bytes.as_slice());

    // Unknown id returns None — server doesn't synthesize bytes
    // for ids it never indexed.
    let unknown: Digest32 = [0xFF; 32].into();
    assert!(server.chunk_by_id(&unknown).is_none());
}

// ----- 2h-1 consume-side reconstruction -----

fn populated_tree(n_leaves: u8) -> AvlTree {
    let mut tree = AvlTree::new();
    for i in 0..n_leaves {
        let key = [i.wrapping_add(0x10); 32];
        let value = vec![i, i.wrapping_add(0x20), i.wrapping_add(0x40)];
        tree.insert(key, value);
    }
    tree
}

fn chunks_map_from_server(server: &SnapshotServer) -> std::collections::HashMap<Digest32, Vec<u8>> {
    server.chunks.iter().cloned().collect()
}

#[test]
fn reconstruct_round_trips_shallow_tree_at_mainnet_depth() {
    // Tree small enough that the whole thing fits in the manifest
    // (no chunks). Round-trip must still recover the same root.
    let tree = populated_tree(3);
    let server = SnapshotServer::build(&tree, 100, MAINNET_MANIFEST_DEPTH).unwrap();
    let rebuilt = reconstruct_tree(&server.manifest_bytes, &chunks_map_from_server(&server))
        .expect("reconstruction succeeds");
    assert_eq!(
        rebuilt.root_label, server.manifest_id,
        "round-trip root label must match",
    );
    assert_eq!(rebuilt.tree_height, tree.tree_height());
}

#[test]
fn reconstruct_round_trips_tree_with_chunks() {
    // Force chunks by using manifest_depth=1. The tree's top
    // subtree fits in one or two nodes of manifest body; chunks
    // hold the bulk of the leaves.
    let tree = populated_tree(8);
    let server = SnapshotServer::build(&tree, 100, 1).unwrap();
    assert!(
        !server.chunks.is_empty(),
        "test precondition: must have chunks"
    );
    let rebuilt = reconstruct_tree(&server.manifest_bytes, &chunks_map_from_server(&server))
        .expect("reconstruction succeeds");
    assert_eq!(
        rebuilt.root_label, server.manifest_id,
        "manifest+chunks reconstruction must reproduce root",
    );
}

#[test]
fn reconstruct_preserves_leaf_payloads() {
    let tree = populated_tree(4);
    let server = SnapshotServer::build(&tree, 1, 1).unwrap();
    let rebuilt = reconstruct_tree(&server.manifest_bytes, &chunks_map_from_server(&server))
        .expect("reconstruction succeeds");

    let mut leaf_kv: Vec<([u8; 32], Vec<u8>)> = rebuilt
        .nodes
        .iter()
        .filter_map(|n| match n {
            ReconstructedNode::Leaf { key, value, .. } => Some((*key, value.clone())),
            _ => None,
        })
        .collect();
    leaf_kv.sort_by_key(|(k, _)| *k);

    // The tree contains a sentinel leaf (NEG_INF) at insert
    // time, plus the inserted keys. Confirm all inserted keys
    // are present with the original values.
    for i in 0..4u8 {
        let key = [i.wrapping_add(0x10); 32];
        let expected = vec![i, i.wrapping_add(0x20), i.wrapping_add(0x40)];
        let found = leaf_kv
            .iter()
            .find(|(k, _)| *k == key)
            .expect("inserted key present in reconstructed tree");
        assert_eq!(found.1, expected, "value preserved for key {i}");
    }
}

#[test]
fn enumerate_expected_chunk_ids_matches_server_chunk_ids() {
    // The list of expected chunks the manifest declares MUST be
    // a 1:1 match of the server's emitted chunk ids — same set,
    // same order. Otherwise the chunk-download state machine
    // could deadlock waiting for chunks the manifest doesn't
    // actually reference (or miss chunks it needs).
    let tree = populated_tree(8);
    let server = SnapshotServer::build(&tree, 1, 1).unwrap();
    let expected_ids =
        enumerate_expected_chunk_ids(&server.manifest_bytes).expect("enumeration succeeds");
    let server_ids: Vec<Digest32> = server.chunks.iter().map(|(id, _)| *id).collect();
    assert_eq!(expected_ids, server_ids);
}

#[test]
fn reconstruct_rejects_missing_chunk() {
    let tree = populated_tree(8);
    let server = SnapshotServer::build(&tree, 1, 1).unwrap();
    // Withhold one chunk.
    let mut chunks = chunks_map_from_server(&server);
    let removed_id = server.chunks[0].0;
    chunks.remove(&removed_id);

    let err = reconstruct_tree(&server.manifest_bytes, &chunks).unwrap_err();
    let msg = format!("{err:?}");
    assert!(
        msg.contains("missing chunk"),
        "error should mention missing chunk; got: {msg}",
    );
}

#[test]
fn reconstruct_rejects_corrupted_chunk_bytes() {
    // Swap one chunk's bytes for garbage. The chunk's recomputed
    // root label won't match its requested subtree_id → assembly
    // refuses the splice.
    let tree = populated_tree(8);
    let server = SnapshotServer::build(&tree, 1, 1).unwrap();
    let mut chunks = chunks_map_from_server(&server);
    let target_id = server.chunks[0].0;
    // Replace with a leaf-only chunk (different shape, definitely
    // won't hash to target_id).
    let bad_chunk = vec![LEAF_PREFIX]
        .into_iter()
        .chain([0xAB; KEY_SIZE])
        .chain(0u32.to_be_bytes())
        .chain([0xCD; KEY_SIZE])
        .collect::<Vec<u8>>();
    chunks.insert(target_id, bad_chunk);

    let err = reconstruct_tree(&server.manifest_bytes, &chunks).unwrap_err();
    let msg = format!("{err:?}");
    assert!(
        msg.contains("chunk authenticity") || msg.contains("actual root label"),
        "error should flag chunk-authenticity failure; got: {msg}",
    );
}

#[test]
fn reconstruct_rejects_chunk_internal_balance_out_of_range() {
    // End-to-end pin for the chunk-balance attack vector. A
    // Mode-2 peer crafts a snapshot whose manifest root verifies
    // but whose chunk bytes embed an internal node with
    // `balance ∉ {-1, 0, 1}`. Flow:
    //   reconstruct_tree → parse_prover_node (chunk bytes) →
    //   balance-gate rejects.
    // The chunk-authenticity check never fires because parsing
    // aborts first. The same out-of-range value, if it ever
    // reached `AvlTree::double_left_rotate`, would panic the
    // apply thread (`tree.rs:1517`).
    let tree = populated_tree(8);
    let server = SnapshotServer::build(&tree, 1, 1).unwrap();
    let mut chunks = chunks_map_from_server(&server);
    let target_id = server.chunks[0].0;
    // First node in a chunk is an internal subtree root: byte 0 is
    // INTERNAL_NODE_PREFIX (0x00), byte 1 is the balance. Flip
    // byte 1 to 0x02 (i8 = +2, outside {-1, 0, 1}).
    let mut corrupted = server.chunks[0].1.clone();
    assert_eq!(
        corrupted[0], INTERNAL_NODE_PREFIX,
        "chunk root must be internal for this test"
    );
    corrupted[1] = 0x02;
    chunks.insert(target_id, corrupted);
    let err = reconstruct_tree(&server.manifest_bytes, &chunks).unwrap_err();
    let msg = format!("{err:?}");
    assert!(
        msg.contains("balance 2") && msg.contains("{-1, 0, 1}"),
        "reconstruct must fail at the balance gate, not the chunk-authenticity \
         check; got: {msg}"
    );
}

#[test]
fn reconstruct_rejects_truncated_manifest_header() {
    // 1-byte manifest can't fit the (rootHeight, manifestDepth) header.
    let bad = vec![0xAA];
    let chunks = std::collections::HashMap::new();
    let err = reconstruct_tree(&bad, &chunks).unwrap_err();
    let msg = format!("{err:?}");
    assert!(
        msg.contains("manifest too short"),
        "error should flag short header; got: {msg}",
    );
}

#[test]
fn reconstruct_rejects_manifest_with_trailing_bytes() {
    // Append a stray byte to a valid manifest — parser must
    // refuse to silently absorb it.
    let tree = populated_tree(3);
    let server = SnapshotServer::build(&tree, 1, MAINNET_MANIFEST_DEPTH).unwrap();
    let mut bad = server.manifest_bytes.clone();
    bad.push(0xFF);
    let err = reconstruct_tree(&bad, &chunks_map_from_server(&server)).unwrap_err();
    let msg = format!("{err:?}");
    assert!(
        msg.contains("trailing bytes"),
        "error should flag trailing bytes; got: {msg}",
    );
}

// ----- recursion / DoS bounds on peer-supplied snapshot bytes -----

#[test]
fn manifest_depth_above_max_rejected() {
    // A peer-supplied manifest_depth above MAINNET_MANIFEST_DEPTH (14)
    // would let a hostile manifest drive deeper DFS recursion than any
    // valid snapshot. parse_manifest_header (used by both manifest
    // readers) rejects it; here we drive it through the public enumerate
    // entry point.
    let manifest = [5u8, MAINNET_MANIFEST_DEPTH + 1]; // tree_height=5, depth=15
    let err = enumerate_expected_chunk_ids(&manifest).unwrap_err();
    let msg = format!("{err:?}");
    assert!(msg.contains("manifest_depth"), "got: {msg}");
}

#[test]
fn parse_chunk_deep_spine_rejected_before_stack_overflow() {
    // A degenerate left-spine chunk: more nested internal nodes than the
    // recursion ceiling. parse_chunk_walk recurses once per level, so a
    // real (much deeper) version would overflow the worker-thread stack;
    // the depth bound returns a typed error instead. The test reaching its
    // assertion at all is the regression guard.
    let mut bytes = Vec::new();
    for _ in 0..(MAX_RECONSTRUCT_DEPTH + 2) {
        bytes.push(INTERNAL_NODE_PREFIX);
        bytes.push(0u8); // balance
        bytes.extend_from_slice(&key32(0)); // key
        bytes.extend_from_slice(&[0u8; LABEL_SIZE]); // left_label
        bytes.extend_from_slice(&[0u8; LABEL_SIZE]); // right_label
    }
    let err = parse_chunk(&bytes).unwrap_err();
    let msg = format!("{err:?}");
    assert!(msg.contains("recursion depth"), "got: {msg}");
}

#[test]
fn parse_chunk_at_max_depth_accepted() {
    // Mirror of the reject test: a left-leaning tree that reaches exactly
    // MAX_RECONSTRUCT_DEPTH (not beyond) must still parse, pinning the `>`
    // bound as off-by-one-correct (depths 0..=MAX accepted, MAX+1
    // rejected). DFS preorder of a MAX-deep tree is the internal spine
    // first (MAX internals, deepest left child at depth MAX), then one
    // leaf per internal's right child plus the deepest-left leaf
    // (MAX + 1 leaves total).
    let internal = |out: &mut Vec<u8>| {
        out.push(INTERNAL_NODE_PREFIX);
        out.push(0u8); // balance
        out.extend_from_slice(&key32(0));
        out.extend_from_slice(&[0u8; LABEL_SIZE]);
        out.extend_from_slice(&[0u8; LABEL_SIZE]);
    };
    let leaf = |out: &mut Vec<u8>| {
        out.push(LEAF_PREFIX);
        out.extend_from_slice(&key32(0));
        out.extend_from_slice(&0u32.to_be_bytes()); // value_len = 0
        out.extend_from_slice(&key32(0)); // next_key
    };
    let mut bytes = Vec::new();
    for _ in 0..MAX_RECONSTRUCT_DEPTH {
        internal(&mut bytes);
    }
    for _ in 0..(MAX_RECONSTRUCT_DEPTH + 1) {
        leaf(&mut bytes);
    }
    assert!(
        parse_chunk(&bytes).is_ok(),
        "a chunk reaching exactly MAX_RECONSTRUCT_DEPTH must still parse",
    );
}
