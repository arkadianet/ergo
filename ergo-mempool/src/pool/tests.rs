use super::*;

// ----- helpers -----

fn digest(b: u8) -> Digest32 {
    Digest32::from_bytes([b; 32])
}

fn mk_entry(
    tx_id_byte: u8,
    weight: u64,
    inputs: &[u8],
    outputs: &[u8],
    parents_in_pool: &[u8],
) -> Entry {
    let bytes: Arc<[u8]> = Arc::from(vec![0u8; 100].into_boxed_slice());
    Entry::new(
        digest(tx_id_byte),
        bytes,
        inputs.iter().map(|b| digest(*b)).collect(),
        outputs.iter().map(|b| digest(*b)).collect(),
        parents_in_pool.iter().map(|b| digest(*b)).collect(),
        100_000,
        weight,
        100,
        50_000,
        TxSource::Api,
    )
}

// ----- happy path -----

#[test]
fn insert_then_contains() {
    let mut p = OrderedPool::with_capacity(4);
    p.insert(mk_entry(1, 10, &[10], &[11], &[])).unwrap();
    assert!(p.contains(&digest(1)));
    assert_eq!(p.len(), 1);
    p.check_invariants();
}

#[test]
fn revision_bumps_on_pool_mutation_not_on_no_ops() {
    let mut p = OrderedPool::with_capacity(4);
    assert_eq!(p.revision(), 0, "fresh pool revision starts at 0");
    p.insert(mk_entry(1, 10, &[10], &[11], &[])).unwrap();
    assert_eq!(p.revision(), 1, "insert bumps revision");
    p.insert(mk_entry(2, 20, &[12], &[13], &[])).unwrap();
    assert_eq!(p.revision(), 2, "second insert bumps revision");
    // Rejected insert (duplicate id) must NOT bump — it returns before
    // mutating the pool.
    let _ = p.insert(mk_entry(1, 99, &[14], &[15], &[]));
    assert_eq!(p.revision(), 2, "rejected insert must not bump revision");
    // Remove bumps; an absent remove does not.
    p.remove(&digest(1)).unwrap();
    assert_eq!(p.revision(), 3, "remove bumps revision");
    assert!(p.remove(&digest(99)).is_none());
    assert_eq!(p.revision(), 3, "absent remove must not bump revision");
    p.check_invariants();
}

#[test]
fn duplicate_insert_rejected() {
    let mut p = OrderedPool::with_capacity(4);
    p.insert(mk_entry(1, 10, &[10], &[11], &[])).unwrap();
    let err = p.insert(mk_entry(1, 20, &[12], &[13], &[])).unwrap_err();
    assert!(matches!(err, PoolError::Duplicate(_)));
    p.check_invariants();
}

#[test]
fn output_collision_rejected() {
    let mut p = OrderedPool::with_capacity(4);
    p.insert(mk_entry(1, 10, &[10], &[11], &[])).unwrap();
    let err = p.insert(mk_entry(2, 20, &[12], &[11], &[])).unwrap_err();
    assert!(matches!(err, PoolError::OutputCollision(_)));
    p.check_invariants();
}

#[test]
fn iter_prioritized_weight_desc() {
    let mut p = OrderedPool::with_capacity(4);
    p.insert(mk_entry(1, 10, &[10], &[11], &[])).unwrap();
    p.insert(mk_entry(2, 30, &[20], &[21], &[])).unwrap();
    p.insert(mk_entry(3, 20, &[30], &[31], &[])).unwrap();
    let ids: Vec<u8> = p
        .iter_prioritized()
        .map(|e| e.tx_id.as_bytes()[0])
        .collect();
    assert_eq!(ids, vec![2, 3, 1]);
}

#[test]
fn tie_break_by_tx_id_ascending() {
    let mut p = OrderedPool::with_capacity(4);
    p.insert(mk_entry(3, 10, &[30], &[31], &[])).unwrap();
    p.insert(mk_entry(1, 10, &[10], &[11], &[])).unwrap();
    p.insert(mk_entry(2, 10, &[20], &[21], &[])).unwrap();
    let ids: Vec<u8> = p
        .iter_prioritized()
        .map(|e| e.tx_id.as_bytes()[0])
        .collect();
    assert_eq!(ids, vec![1, 2, 3], "same-weight entries sort by tx_id ASC");
}

#[test]
fn remove_drops_indexes() {
    let mut p = OrderedPool::with_capacity(4);
    p.insert(mk_entry(1, 10, &[10], &[11], &[])).unwrap();
    let removed = p.remove(&digest(1)).unwrap();
    assert_eq!(removed.weight, 10);
    assert!(p.is_empty());
    assert!(p.parent_for_output(&digest(11)).is_none());
    p.check_invariants();
}

#[test]
fn remove_absent_returns_none() {
    let mut p = OrderedPool::with_capacity(4);
    assert!(p.remove(&digest(99)).is_none());
}

#[test]
fn lowest_weight_tracks_min() {
    let mut p = OrderedPool::with_capacity(4);
    assert!(p.lowest_weight().is_none());
    p.insert(mk_entry(1, 50, &[10], &[11], &[])).unwrap();
    p.insert(mk_entry(2, 10, &[20], &[21], &[])).unwrap();
    p.insert(mk_entry(3, 30, &[30], &[31], &[])).unwrap();
    assert_eq!(p.lowest_weight(), Some(10));
    assert_eq!(p.lowest_tx_id(), Some(digest(2)));
}

#[test]
fn conflicts_for_inputs_detects_double_spends() {
    let mut p = OrderedPool::with_capacity(4);
    p.insert(mk_entry(1, 10, &[10, 11], &[50], &[])).unwrap();
    p.insert(mk_entry(2, 20, &[20, 21], &[51], &[])).unwrap();
    let cf = p.conflicts_for_inputs(&[digest(11), digest(99)]);
    assert_eq!(cf, vec![digest(1)]);
    let cf2 = p.conflicts_for_inputs(&[digest(10), digest(20)]);
    assert_eq!(cf2.len(), 2);
}

#[test]
fn conflicts_empty_when_no_overlap() {
    let mut p = OrderedPool::with_capacity(4);
    p.insert(mk_entry(1, 10, &[10], &[11], &[])).unwrap();
    assert!(p.conflicts_for_inputs(&[digest(99)]).is_empty());
}

#[test]
fn total_bytes_tracks_inserts_and_removes() {
    let mut p = OrderedPool::with_capacity(4);
    let bytes1: Arc<[u8]> = Arc::from(vec![0u8; 100].into_boxed_slice());
    let e1 = Entry::new(
        digest(1),
        bytes1,
        vec![digest(10)],
        vec![digest(11)],
        vec![],
        1000,
        10,
        100,
        50,
        TxSource::Api,
    );
    let bytes2: Arc<[u8]> = Arc::from(vec![0u8; 200].into_boxed_slice());
    let e2 = Entry::new(
        digest(2),
        bytes2,
        vec![digest(20)],
        vec![digest(21)],
        vec![],
        2000,
        20,
        200,
        100,
        TxSource::Api,
    );
    p.insert(e1).unwrap();
    p.insert(e2).unwrap();
    assert_eq!(p.total_bytes(), 300);
    p.remove(&digest(1));
    assert_eq!(p.total_bytes(), 200);
}

#[test]
fn parent_for_output_resolves_creator() {
    let mut p = OrderedPool::with_capacity(4);
    p.insert(mk_entry(1, 10, &[10], &[100, 101], &[])).unwrap();
    assert_eq!(p.parent_for_output(&digest(100)), Some(digest(1)));
    assert_eq!(p.parent_for_output(&digest(101)), Some(digest(1)));
    assert_eq!(p.parent_for_output(&digest(250)), None);
}

#[test]
fn children_of_tracks_parent_child_edges() {
    let mut p = OrderedPool::with_capacity(4);
    // parent creates box 100
    p.insert(mk_entry(1, 10, &[10], &[100], &[])).unwrap();
    // child spends box 100 → declared parent = tx 1
    p.insert(mk_entry(2, 20, &[100], &[200], &[1])).unwrap();
    assert_eq!(p.children_of.get(&digest(1)), Some(&vec![digest(2)]));
    p.check_invariants();
}

#[test]
fn remove_with_descendants_cascades_children() {
    let mut p = OrderedPool::with_capacity(4);
    p.insert(mk_entry(1, 10, &[10], &[100], &[])).unwrap();
    p.insert(mk_entry(2, 20, &[100], &[200], &[1])).unwrap();
    p.insert(mk_entry(3, 30, &[200], &[201], &[2])).unwrap();
    let removed = p.remove_with_descendants(&digest(1), 500);
    assert_eq!(removed.len(), 3, "parent + child + grandchild");
    assert!(p.is_empty());
    p.check_invariants();
}

#[test]
fn remove_with_descendants_respects_max_depth() {
    let mut p = OrderedPool::with_capacity(8);
    p.insert(mk_entry(1, 10, &[10], &[100], &[])).unwrap();
    p.insert(mk_entry(2, 20, &[100], &[200], &[1])).unwrap();
    p.insert(mk_entry(3, 30, &[200], &[210], &[2])).unwrap();
    p.insert(mk_entry(4, 40, &[210], &[220], &[3])).unwrap();
    // Cap at 2: only parent + first child evicted.
    let removed = p.remove_with_descendants(&digest(1), 2);
    assert_eq!(removed.len(), 2);
    // tx 3 and tx 4 remain.
    assert!(p.contains(&digest(3)));
    assert!(p.contains(&digest(4)));
    p.check_invariants();
}

#[test]
fn remove_with_descendants_frontier_reports_truncated_orphans() {
    // Chain 1→2→3→4. Cap at 2 removes {1,2}; tx 3 is the un-visited direct
    // child of the removed tx 2 — the truncation frontier the caller carries
    // forward. tx 4 is discovered only once tx 3 is itself processed.
    let mut p = OrderedPool::with_capacity(8);
    p.insert(mk_entry(1, 10, &[10], &[100], &[])).unwrap();
    p.insert(mk_entry(2, 20, &[100], &[200], &[1])).unwrap();
    p.insert(mk_entry(3, 30, &[200], &[210], &[2])).unwrap();
    p.insert(mk_entry(4, 40, &[210], &[220], &[3])).unwrap();

    let (removed, frontier) = p.remove_with_descendants_frontier(&digest(1), 2);
    assert_eq!(removed.len(), 2, "cap removes only parent + first child");
    assert_eq!(frontier, vec![digest(3)], "tx 3 is the orphaned frontier");
    assert!(p.contains(&digest(3)) && p.contains(&digest(4)));
    p.check_invariants();

    // Carrying the frontier forward finishes the job: removing tx 3 (cap 2
    // again) evicts {3,4} with an empty frontier.
    let (removed2, frontier2) = p.remove_with_descendants_frontier(&digest(3), 2);
    assert_eq!(removed2.len(), 2, "tx 3 + tx 4");
    assert!(frontier2.is_empty(), "subtree fully cleared");
    assert!(p.is_empty());
    p.check_invariants();
}

#[test]
fn remove_with_descendants_frontier_empty_when_within_cap() {
    let mut p = OrderedPool::with_capacity(4);
    p.insert(mk_entry(1, 10, &[10], &[100], &[])).unwrap();
    p.insert(mk_entry(2, 20, &[100], &[200], &[1])).unwrap();
    let (removed, frontier) = p.remove_with_descendants_frontier(&digest(1), 500);
    assert_eq!(removed.len(), 2);
    assert!(frontier.is_empty(), "no truncation → no frontier");
}

#[test]
fn remove_with_descendants_on_missing_tx() {
    let mut p = OrderedPool::with_capacity(4);
    assert!(p.remove_with_descendants(&digest(99), 10).is_empty());
}

#[test]
fn removing_parent_leaves_child_without_dangling_edge() {
    let mut p = OrderedPool::with_capacity(4);
    p.insert(mk_entry(1, 10, &[10], &[100], &[])).unwrap();
    p.insert(mk_entry(2, 20, &[100], &[200], &[1])).unwrap();
    p.remove(&digest(1));
    // children_of[tx1] cleared entirely; tx2 still in pool.
    assert!(!p.children_of.contains_key(&digest(1)));
    assert!(p.contains(&digest(2)));
    p.check_invariants();
}

#[test]
fn weighted_key_ordering_is_total_and_stable() {
    let k1 = WeightedKey::new(100, digest(1));
    let k2 = WeightedKey::new(100, digest(2));
    let k3 = WeightedKey::new(200, digest(3));
    assert!(k3 < k1, "higher weight sorts earlier");
    assert!(k1 < k2, "same weight: tx_id ASC");
}

#[test]
fn weighted_key_handles_max_weight() {
    let k = WeightedKey::new(u64::MAX, digest(1));
    assert_eq!(k.weight(), u64::MAX);
}

#[test]
fn get_returns_entry() {
    let mut p = OrderedPool::with_capacity(4);
    p.insert(mk_entry(1, 10, &[10], &[11], &[])).unwrap();
    let e = p.get(&digest(1)).unwrap();
    assert_eq!(e.weight, 10);
    assert!(p.get(&digest(99)).is_none());
}

#[test]
fn empty_pool_lowest_is_none() {
    let p = OrderedPool::with_capacity(4);
    assert!(p.lowest_weight().is_none());
    assert!(p.lowest_tx_id().is_none());
}

#[test]
fn check_invariants_passes_on_empty() {
    let p = OrderedPool::with_capacity(4);
    p.check_invariants();
}

#[test]
fn input_map_returns_inputs_across_pool() {
    let mut p = OrderedPool::with_capacity(4);
    // tx 1 spends boxes 10, 11
    p.insert(mk_entry(1, 10, &[10, 11], &[100], &[])).unwrap();
    // tx 2 spends boxes 20, 21
    p.insert(mk_entry(2, 30, &[20, 21], &[200], &[])).unwrap();

    let map = p.input_map();
    assert_eq!(map.len(), 4);
    assert_eq!(map.get(&digest(10)), Some(&digest(1)));
    assert_eq!(map.get(&digest(11)), Some(&digest(1)));
    assert_eq!(map.get(&digest(20)), Some(&digest(2)));
    assert_eq!(map.get(&digest(21)), Some(&digest(2)));
    // Outputs are not inputs.
    assert!(!map.contains_key(&digest(100)));
    assert!(!map.contains_key(&digest(200)));
}

#[test]
fn input_map_empty_pool() {
    let p = OrderedPool::with_capacity(4);
    assert!(p.input_map().is_empty());
}

#[test]
fn input_map_drops_entries_after_remove() {
    let mut p = OrderedPool::with_capacity(4);
    p.insert(mk_entry(1, 10, &[10, 11], &[100], &[])).unwrap();
    p.insert(mk_entry(2, 30, &[20], &[200], &[])).unwrap();
    p.remove(&digest(1));
    let map = p.input_map();
    assert_eq!(map.len(), 1);
    assert_eq!(map.get(&digest(20)), Some(&digest(2)));
}

// ----- oracle parity (CPFP family weight; Scala OrderedTxPool.updateFamily) -----
//
// Box ids use the 100+ range so they never collide with the small tx-id
// bytes. Expected weights are derived from Scala's arithmetic
// (`newWtx.weight = wtx.weight + weight`, recursive), not from a self-oracle.

/// Bounds wide enough that none of these walks bail — exercises the exact
/// completed-walk arithmetic.
fn wide_bounds() -> FamilyBounds {
    FamilyBounds::new(500, 10_000, 500)
}

#[test]
fn update_family_credit_boosts_in_pool_parent_weight() {
    let mut p = OrderedPool::with_capacity(8);
    // P: own weight 10, creates box 110.
    p.insert(mk_entry(1, 10, &[200], &[110], &[])).unwrap();
    // C: own weight 50, spends P's output (box 110).
    p.insert(mk_entry(2, 50, &[110], &[111], &[1])).unwrap();
    // Admission credit: propagate C's own weight up from C's inputs.
    p.update_family(&[digest(110)], i128::from(50u64), wide_bounds());
    // Scala: parent.weight = own + child = 10 + 50.
    assert_eq!(p.get(&digest(1)).unwrap().weight, 60);
    assert_eq!(p.get(&digest(2)).unwrap().weight, 50, "child unchanged");
    // Parent now outranks child in priority order.
    let order: Vec<_> = p.iter_prioritized().map(|e| e.tx_id).collect();
    assert_eq!(order, vec![digest(1), digest(2)]);
    p.check_invariants();
}

#[test]
fn update_family_debit_returns_parent_to_own_weight() {
    let mut p = OrderedPool::with_capacity(8);
    p.insert(mk_entry(1, 10, &[200], &[110], &[])).unwrap();
    p.insert(mk_entry(2, 50, &[110], &[111], &[1])).unwrap();
    p.update_family(&[digest(110)], i128::from(50u64), wide_bounds());
    assert_eq!(p.get(&digest(1)).unwrap().weight, 60);
    // Remove the child, debiting its current weight back out of P.
    let removed = p.remove_debiting(&digest(2), wide_bounds());
    assert!(removed.is_some());
    assert_eq!(
        p.get(&digest(1)).unwrap().weight,
        10,
        "parent restored to its own weight after child leaves"
    );
    p.check_invariants();
}

#[test]
fn update_family_credit_propagates_through_grandparent_chain() {
    let mut p = OrderedPool::with_capacity(8);
    // P(10) <- C(20) <- GC(40); boxes 110, 111, 112.
    p.insert(mk_entry(1, 10, &[200], &[110], &[])).unwrap();
    p.insert(mk_entry(2, 20, &[110], &[111], &[1])).unwrap();
    p.update_family(&[digest(110)], i128::from(20u64), wide_bounds());
    p.insert(mk_entry(3, 40, &[111], &[112], &[2])).unwrap();
    p.update_family(&[digest(111)], i128::from(40u64), wide_bounds());
    // Scala recursive fold: the grandchild's weight reaches C AND P.
    assert_eq!(p.get(&digest(3)).unwrap().weight, 40, "grandchild own");
    assert_eq!(p.get(&digest(2)).unwrap().weight, 20 + 40, "child own + gc");
    assert_eq!(
        p.get(&digest(1)).unwrap().weight,
        10 + 20 + 40,
        "parent own + child + grandchild"
    );
    p.check_invariants();
}

#[test]
fn update_family_depth_bound_rekeys_siblings_but_stops_descent() {
    // C has two direct parents P1, P2 (a sibling level); P1 has a
    // grandparent GP1. depth bound 0 lets the direct-parent level re-key
    // (both siblings) but stops descent to GP1.
    let mut p = OrderedPool::with_capacity(8);
    p.insert(mk_entry(4, 5, &[201], &[130], &[])).unwrap(); // GP1, creates box 130
    p.insert(mk_entry(1, 10, &[130], &[110], &[4])).unwrap(); // P1, spends 130
    p.insert(mk_entry(2, 20, &[200], &[111], &[])).unwrap(); // P2
    p.insert(mk_entry(3, 50, &[110, 111], &[112], &[1, 2]))
        .unwrap(); // C spends P1+P2
    let bounds = FamilyBounds::new(0, 10_000, 500);
    p.update_family(&[digest(110), digest(111)], i128::from(50u64), bounds);
    assert_eq!(p.get(&digest(1)).unwrap().weight, 60, "sibling P1 re-keyed");
    assert_eq!(p.get(&digest(2)).unwrap().weight, 70, "sibling P2 re-keyed");
    assert_eq!(
        p.get(&digest(4)).unwrap().weight,
        5,
        "grandparent NOT reached: depth bound gates descent"
    );
    p.check_invariants();
}

#[test]
fn update_family_ops_bound_stops_the_whole_walk_including_siblings() {
    // Same sibling shape, but the ops cap (1) is a global stop: only the
    // first sibling is re-keyed; the second is not (contrast the depth test).
    let mut p = OrderedPool::with_capacity(8);
    p.insert(mk_entry(1, 10, &[200], &[110], &[])).unwrap();
    p.insert(mk_entry(2, 20, &[201], &[111], &[])).unwrap();
    p.insert(mk_entry(3, 50, &[110, 111], &[112], &[1, 2]))
        .unwrap();
    let bounds = FamilyBounds::new(500, 1, 500);
    p.update_family(&[digest(110), digest(111)], i128::from(50u64), bounds);
    let p1 = p.get(&digest(1)).unwrap().weight;
    let p2 = p.get(&digest(2)).unwrap().weight;
    // Exactly one sibling was re-keyed (ops cap = 1); the other is untouched.
    assert!(
        (p1 == 60 && p2 == 20) || (p1 == 10 && p2 == 70),
        "ops cap should re-key exactly one sibling, got p1={p1} p2={p2}"
    );
    p.check_invariants();
}

#[test]
fn update_family_diamond_ancestor_credited_once_per_path() {
    // G has two children P1, P2 (spending distinct G outputs); C spends
    // both. No global visited-set, so C's credit reaches G via BOTH paths.
    let mut p = OrderedPool::with_capacity(8);
    p.insert(mk_entry(1, 10, &[200], &[110, 111], &[])).unwrap(); // G, two outputs
    p.insert(mk_entry(2, 20, &[110], &[120], &[1])).unwrap(); // P1
    p.insert(mk_entry(3, 30, &[111], &[121], &[1])).unwrap(); // P2
    p.insert(mk_entry(4, 7, &[120, 121], &[122], &[2, 3]))
        .unwrap(); // C
    p.update_family(&[digest(120), digest(121)], i128::from(7u64), wide_bounds());
    assert_eq!(p.get(&digest(2)).unwrap().weight, 27, "P1 own + C");
    assert_eq!(p.get(&digest(3)).unwrap().weight, 37, "P2 own + C");
    assert_eq!(
        p.get(&digest(1)).unwrap().weight,
        10 + 7 + 7,
        "diamond grandparent credited once per path (2x)"
    );
    p.check_invariants();
}

#[test]
fn remove_with_descendants_debiting_undoes_whole_subtree_boost() {
    // P(10) <- C(20) <- GC(40); fully boosted (P=70, C=60). Removing C's
    // subtree debits P by C's accumulated weight (60), restoring P to 10.
    let mut p = OrderedPool::with_capacity(8);
    p.insert(mk_entry(1, 10, &[200], &[110], &[])).unwrap();
    p.insert(mk_entry(2, 20, &[110], &[111], &[1])).unwrap();
    p.update_family(&[digest(110)], i128::from(20u64), wide_bounds());
    p.insert(mk_entry(3, 40, &[111], &[112], &[2])).unwrap();
    p.update_family(&[digest(111)], i128::from(40u64), wide_bounds());
    assert_eq!(p.get(&digest(1)).unwrap().weight, 70);
    let removed = p.remove_with_descendants_debiting(&digest(2), 500, wide_bounds());
    let removed_ids: Vec<_> = removed.iter().map(|e| e.tx_id).collect();
    assert!(removed_ids.contains(&digest(2)) && removed_ids.contains(&digest(3)));
    assert_eq!(
        p.get(&digest(1)).unwrap().weight,
        10,
        "subtree removal debits the whole subtree's contribution from P"
    );
    p.check_invariants();
}

#[test]
fn rekey_weight_preserves_children_of_for_a_nonleaf_node() {
    // Regression guard: re-keying a node that is itself a parent must NOT
    // drop its children_of edges (the remove+insert bug). Proven via a
    // subsequent cascade removal still reaching the child.
    let mut p = OrderedPool::with_capacity(8);
    p.insert(mk_entry(1, 10, &[200], &[110], &[])).unwrap(); // P
    p.insert(mk_entry(2, 20, &[110], &[111], &[1])).unwrap(); // C, child of P
    p.rekey_weight(&digest(1), 999);
    assert_eq!(p.get(&digest(1)).unwrap().weight, 999);
    let removed = p.remove_with_descendants(&digest(1), 500);
    let ids: Vec<_> = removed.iter().map(|e| e.tx_id).collect();
    assert!(
        ids.contains(&digest(2)),
        "child edge survived the re-key: cascade still removes the child"
    );
    p.check_invariants();
}

#[test]
fn detach_parent_strips_edge_without_changing_weight_or_position() {
    let mut p = OrderedPool::with_capacity(8);
    p.insert(mk_entry(1, 10, &[200], &[110], &[])).unwrap();
    p.insert(mk_entry(2, 20, &[110], &[111], &[1])).unwrap();
    let before = p.get(&digest(2)).unwrap().weight;
    p.detach_parent(&digest(2), &digest(1));
    let child = p.get(&digest(2)).unwrap();
    assert!(
        !child.parents_in_pool.contains(&digest(1)),
        "confirmed parent stripped from parents_in_pool"
    );
    assert_eq!(
        child.weight, before,
        "weight and ordering position unchanged"
    );
    p.check_invariants();
}

#[test]
fn remove_with_descendants_debiting_debits_surviving_co_parent_in_a_diamond() {
    // P1 and P2 each create a box; C spends BOTH (a DAG/diamond child).
    // Removing P1's subtree also removes C (P1's child), and the surviving
    // co-parent P2 must lose C's boost — debiting only the removed root P1
    // would leave a phantom boost on P2.
    let mut p = OrderedPool::with_capacity(8);
    p.insert(mk_entry(1, 10, &[200], &[110], &[])).unwrap(); // P1, box 110
    p.insert(mk_entry(2, 20, &[201], &[111], &[])).unwrap(); // P2, box 111
    p.insert(mk_entry(3, 7, &[110, 111], &[112], &[1, 2]))
        .unwrap(); // C spends both
    p.update_family(&[digest(110), digest(111)], i128::from(7u64), wide_bounds());
    assert_eq!(p.get(&digest(1)).unwrap().weight, 17, "P1 own + C");
    assert_eq!(p.get(&digest(2)).unwrap().weight, 27, "P2 own + C");
    // Remove P1's subtree (P1 + its child C); P2 survives.
    let removed = p.remove_with_descendants_debiting(&digest(1), 500, wide_bounds());
    let ids: Vec<_> = removed.iter().map(|e| e.tx_id).collect();
    assert!(
        ids.contains(&digest(1)) && ids.contains(&digest(3)),
        "P1 and C removed"
    );
    assert!(!p.contains(&digest(3)), "C gone");
    assert_eq!(
        p.get(&digest(2)).unwrap().weight,
        20,
        "surviving co-parent P2 de-boosted back to its own weight"
    );
    p.check_invariants();
}

#[test]
fn saturating_apply_floors_at_zero_and_ceils_at_u64_max() {
    assert_eq!(saturating_apply(10, 5), 15);
    assert_eq!(saturating_apply(10, -100), 0, "under-debit floors at 0");
    assert_eq!(
        saturating_apply(u64::MAX - 5, 100),
        u64::MAX,
        "over-credit ceils at u64::MAX"
    );
    assert_eq!(saturating_apply(u64::MAX, -i128::from(u64::MAX)), 0);
}
