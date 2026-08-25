use ergo_wallet::proving::node_position::NodePosition;

#[test]
fn crypto_tree_prefix_is_singleton_zero() {
    // Matches Scala NodePosition.CryptoTreePrefix = NodePosition(Seq(0)).
    // ErgoTreePrefix is Seq(1) — these are distinct namespaces.
    let pos = NodePosition::crypto_tree_prefix();
    assert_eq!(pos.positions, vec![0]);
}

#[test]
fn child_descent_extends_path() {
    let root = NodePosition::crypto_tree_prefix();
    let child0 = root.child(0);
    let child1 = child0.child(1);
    assert_eq!(child0.positions, vec![0, 0]);
    assert_eq!(child1.positions, vec![0, 0, 1]);
}

#[test]
fn distinct_paths_are_distinct() {
    let root = NodePosition::crypto_tree_prefix();
    assert_ne!(root.child(0), root.child(1));
    assert_ne!(root.child(0).child(0), root.child(0).child(1));
}
