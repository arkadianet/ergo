//! Unit tests for [`StagingPool`] — the pure structure: indexing,
//! per-peer + global caps, eviction order, and pruning. No validation or
//! wiring is exercised here (that arrives in P2+).

use super::*;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

fn d(b: u8) -> Digest32 {
    Digest32::from_bytes([b; 32])
}

fn peer(n: u16) -> PeerId {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9000 + n)
}

fn bytes(b: u8, n: usize) -> Arc<[u8]> {
    Arc::from(vec![b; n].into_boxed_slice())
}

/// Small caps for deterministic eviction tests.
fn small_caps() -> StagingCaps {
    StagingCaps {
        max_count: 3,
        max_bytes: 1000,
        max_count_per_peer: 2,
        max_bytes_per_peer: 500,
        max_waiters_per_input: 2,
    }
}

// A held entry with an explicit weight (so priority is exactly `weight`).
#[allow(clippy::too_many_arguments)]
fn held(
    pool: &mut StagingPool,
    tx: u8,
    inputs: &[u8],
    outputs: &[u8],
    weight: u64,
    size: u32,
    src: TxSource,
    now: Instant,
    height: u32,
) -> Result<StageAdmit, StageReject> {
    pool.stage_held(
        d(tx),
        bytes(tx, size as usize),
        inputs.iter().map(|b| d(*b)).collect(),
        vec![], // data inputs
        outputs.iter().map(|b| d(*b)).collect(),
        1_000_000,
        size,
        weight,
        50_000,
        vec![],
        src,
        now,
        TipPointer {
            height,
            header_id: d(0),
        },
    )
}

#[allow(clippy::too_many_arguments)]
fn orphan(
    pool: &mut StagingPool,
    tx: u8,
    inputs: &[u8],
    outputs: &[u8],
    missing: &[u8],
    fee: u64,
    size: u32,
    src: TxSource,
    now: Instant,
    height: u32,
) -> Result<StageAdmit, StageReject> {
    pool.stage_orphan(
        d(tx),
        bytes(tx, size as usize),
        inputs.iter().map(|b| d(*b)).collect(),
        vec![], // data inputs
        outputs.iter().map(|b| d(*b)).collect(),
        fee,
        size,
        missing.iter().map(|b| d(*b)).collect(),
        src,
        now,
        TipPointer {
            height,
            header_id: d(0),
        },
    )
}

// ----- happy path: indexing -----

#[test]
fn stage_orphan_indexes_missing_input_and_outputs() {
    let mut p = StagingPool::with_default_caps();
    let now = Instant::now();
    orphan(
        &mut p,
        1,
        &[0x10],
        &[0x20],
        &[0x10],
        1_000_000,
        50,
        TxSource::Api,
        now,
        100,
    )
    .unwrap();

    assert!(p.contains(&d(1)));
    assert_eq!(p.len(), 1);
    assert_eq!(p.waiters_on(&d(0x10)), &[d(1)]);
    assert_eq!(p.creator_of(&d(0x20)), Some(d(1)));
    assert!(p.get(&d(1)).unwrap().is_orphan());
    p.check_invariants();
}

#[test]
fn stage_held_indexes_outputs_but_no_waiters() {
    let mut p = StagingPool::with_default_caps();
    let now = Instant::now();
    held(
        &mut p,
        2,
        &[0x11],
        &[0x21],
        500,
        40,
        TxSource::Api,
        now,
        100,
    )
    .unwrap();

    assert!(p.get(&d(2)).unwrap().is_held());
    assert_eq!(p.creator_of(&d(0x21)), Some(d(2)));
    // Held entries never register waiters (they resolved).
    assert!(p.waiters_on(&d(0x11)).is_empty());
    assert_eq!(
        p.get(&d(2)).unwrap().priority_proxy(),
        500,
        "held priority = weight"
    );
    p.check_invariants();
}

#[test]
fn duplicate_is_rejected() {
    let mut p = StagingPool::with_default_caps();
    let now = Instant::now();
    held(&mut p, 3, &[1], &[2], 100, 30, TxSource::Api, now, 1).unwrap();
    assert_eq!(
        held(&mut p, 3, &[1], &[2], 100, 30, TxSource::Api, now, 1).unwrap_err(),
        StageReject::Duplicate
    );
    assert_eq!(p.len(), 1);
}

// ----- removal cleans every index -----

#[test]
fn remove_cleans_all_indices() {
    let mut p = StagingPool::with_default_caps();
    let now = Instant::now();
    orphan(
        &mut p,
        1,
        &[0x10, 0x11],
        &[0x20],
        &[0x10, 0x11],
        1_000_000,
        50,
        TxSource::Peer(peer(1)),
        now,
        5,
    )
    .unwrap();
    assert_eq!(p.peer_count(&peer(1)), 1);
    assert_eq!(p.peer_bytes(&peer(1)), 50);

    let removed = p.remove(&d(1)).unwrap();
    assert_eq!(removed.tx_id, d(1));
    assert!(!p.contains(&d(1)));
    assert!(p.waiters_on(&d(0x10)).is_empty());
    assert!(p.waiters_on(&d(0x11)).is_empty());
    assert!(p.creator_of(&d(0x20)).is_none());
    assert_eq!(p.peer_count(&peer(1)), 0);
    assert_eq!(p.peer_bytes(&peer(1)), 0);
    assert_eq!(p.total_bytes(), 0);
    p.check_invariants();
}

// ----- per-peer caps refuse (do NOT evict other peers) -----

#[test]
fn per_peer_count_cap_refuses_without_evicting_others() {
    let mut p = StagingPool::new(small_caps()); // max_count_per_peer = 2
    let now = Instant::now();
    held(
        &mut p,
        1,
        &[1],
        &[11],
        100,
        30,
        TxSource::Peer(peer(1)),
        now,
        1,
    )
    .unwrap();
    held(
        &mut p,
        2,
        &[2],
        &[12],
        100,
        30,
        TxSource::Peer(peer(1)),
        now,
        1,
    )
    .unwrap();
    // Third from the same peer is refused — its allotment is full.
    assert_eq!(
        held(
            &mut p,
            3,
            &[3],
            &[13],
            100,
            30,
            TxSource::Peer(peer(1)),
            now,
            1
        )
        .unwrap_err(),
        StageReject::PerPeerCount
    );
    // A different peer is unaffected.
    held(
        &mut p,
        4,
        &[4],
        &[14],
        100,
        30,
        TxSource::Peer(peer(2)),
        now,
        1,
    )
    .unwrap();
    assert!(p.contains(&d(1)) && p.contains(&d(2)) && p.contains(&d(4)));
    assert!(!p.contains(&d(3)));
    p.check_invariants();
}

#[test]
fn per_peer_bytes_cap_refuses() {
    let mut p = StagingPool::new(small_caps()); // max_bytes_per_peer = 500
    let now = Instant::now();
    held(
        &mut p,
        1,
        &[1],
        &[11],
        100,
        300,
        TxSource::Peer(peer(1)),
        now,
        1,
    )
    .unwrap();
    assert_eq!(
        held(
            &mut p,
            2,
            &[2],
            &[12],
            100,
            300,
            TxSource::Peer(peer(1)),
            now,
            1
        )
        .unwrap_err(),
        StageReject::PerPeerBytes
    );
    p.check_invariants();
}

// ----- fan-out (waiters-per-input) cap -----

#[test]
fn waiters_per_input_cap_bounds_fanout() {
    let mut p = StagingPool::new(small_caps()); // max_waiters_per_input = 2
    let now = Instant::now();
    // Three orphans all waiting on the SAME box 0x99.
    orphan(
        &mut p,
        1,
        &[0x99],
        &[0x11],
        &[0x99],
        1_000_000,
        30,
        TxSource::Api,
        now,
        1,
    )
    .unwrap();
    orphan(
        &mut p,
        2,
        &[0x99],
        &[0x12],
        &[0x99],
        1_000_000,
        30,
        TxSource::Api,
        now,
        1,
    )
    .unwrap();
    // The third exceeds the fan-out bound for box 0x99.
    assert_eq!(
        orphan(
            &mut p,
            3,
            &[0x99],
            &[0x13],
            &[0x99],
            1_000_000,
            30,
            TxSource::Api,
            now,
            1
        )
        .unwrap_err(),
        StageReject::WaitersFull
    );
    assert_eq!(p.waiters_on(&d(0x99)).len(), 2);
    p.check_invariants();
}

// ----- global capacity eviction: lowest priority first -----

#[test]
fn count_cap_evicts_lowest_priority_first() {
    let mut p = StagingPool::new(small_caps()); // max_count = 3
    let now = Instant::now();
    held(&mut p, 1, &[1], &[11], 900, 30, TxSource::Api, now, 1).unwrap(); // high
    held(&mut p, 2, &[2], &[12], 100, 30, TxSource::Api, now, 1).unwrap(); // LOW
    held(&mut p, 3, &[3], &[13], 800, 30, TxSource::Api, now, 1).unwrap(); // high
                                                                           // Fourth (mid priority) forces eviction of the lowest (tx 2).
    let admit = held(&mut p, 4, &[4], &[14], 500, 30, TxSource::Api, now, 1).unwrap();
    assert_eq!(admit.evicted.len(), 1);
    assert_eq!(
        admit.evicted[0].tx_id,
        d(2),
        "lowest-priority entry evicted"
    );
    assert!(!p.contains(&d(2)));
    assert!(p.contains(&d(1)) && p.contains(&d(3)) && p.contains(&d(4)));
    p.check_invariants();
}

#[test]
fn newcomer_that_is_lowest_priority_is_refused_full() {
    let mut p = StagingPool::new(small_caps()); // max_count = 3
    let now = Instant::now();
    held(&mut p, 1, &[1], &[11], 900, 30, TxSource::Api, now, 1).unwrap();
    held(&mut p, 2, &[2], &[12], 800, 30, TxSource::Api, now, 1).unwrap();
    held(&mut p, 3, &[3], &[13], 700, 30, TxSource::Api, now, 1).unwrap();
    // A newcomer weaker than every incumbent must NOT displace a better one.
    assert_eq!(
        held(&mut p, 4, &[4], &[14], 100, 30, TxSource::Api, now, 1).unwrap_err(),
        StageReject::Full
    );
    assert!(!p.contains(&d(4)));
    assert_eq!(p.len(), 3);
    p.check_invariants();
}

#[test]
fn eviction_ties_break_oldest_first() {
    let mut p = StagingPool::new(small_caps()); // max_count = 3
    let now = Instant::now();
    // Three equal-priority entries; insertion order 1,2,3 (1 oldest).
    held(&mut p, 1, &[1], &[11], 500, 30, TxSource::Api, now, 1).unwrap();
    held(&mut p, 2, &[2], &[12], 500, 30, TxSource::Api, now, 1).unwrap();
    held(&mut p, 3, &[3], &[13], 500, 30, TxSource::Api, now, 1).unwrap();
    // Newcomer with equal priority evicts the OLDEST equal entry (tx 1).
    let admit = held(&mut p, 4, &[4], &[14], 500, 30, TxSource::Api, now, 1).unwrap();
    assert_eq!(
        admit.evicted[0].tx_id,
        d(1),
        "oldest equal-priority evicted"
    );
    p.check_invariants();
}

#[test]
fn byte_cap_evicts_until_it_fits() {
    let mut p = StagingPool::new(StagingCaps {
        max_count: 100,
        max_bytes: 100,
        max_count_per_peer: 100,
        max_bytes_per_peer: 100,
        max_waiters_per_input: 100,
    });
    let now = Instant::now();
    held(&mut p, 1, &[1], &[11], 100, 40, TxSource::Api, now, 1).unwrap(); // low, 40b
    held(&mut p, 2, &[2], &[12], 900, 40, TxSource::Api, now, 1).unwrap(); // high, 40b
                                                                           // total 80; a 40b high-priority newcomer needs 120 > 100 → evict lowest.
    let admit = held(&mut p, 3, &[3], &[13], 800, 40, TxSource::Api, now, 1).unwrap();
    assert_eq!(admit.evicted[0].tx_id, d(1));
    assert!(p.total_bytes() <= 100);
    p.check_invariants();
}

#[test]
fn oversize_single_tx_refused() {
    let mut p = StagingPool::new(small_caps()); // max_bytes = 1000
    let now = Instant::now();
    assert_eq!(
        held(&mut p, 1, &[1], &[11], 100, 2000, TxSource::Api, now, 1).unwrap_err(),
        StageReject::TooLarge
    );
    assert!(p.is_empty());
}

// ----- pruning -----

#[test]
fn prune_spent_inputs_drops_matching_txs() {
    let mut p = StagingPool::with_default_caps();
    let now = Instant::now();
    orphan(
        &mut p,
        1,
        &[0x10],
        &[0x20],
        &[0x10],
        1_000_000,
        30,
        TxSource::Api,
        now,
        1,
    )
    .unwrap();
    held(&mut p, 2, &[0x11], &[0x21], 500, 30, TxSource::Api, now, 1).unwrap();
    held(&mut p, 3, &[0x12], &[0x22], 500, 30, TxSource::Api, now, 1).unwrap();

    let mut spent = HashSet::new();
    spent.insert(d(0x10)); // orphan 1's input
    spent.insert(d(0x11)); // held 2's input
    let removed = p.prune_spent_inputs(&spent);
    let ids: HashSet<TxId> = removed.iter().map(|e| e.tx_id).collect();
    assert_eq!(ids.len(), 2);
    assert!(ids.contains(&d(1)) && ids.contains(&d(2)));
    assert!(p.contains(&d(3)), "unaffected tx retained");
    p.check_invariants();
}

#[test]
fn prune_expired_by_ttl() {
    let mut p = StagingPool::with_default_caps();
    let t0 = Instant::now();
    held(&mut p, 1, &[1], &[11], 100, 30, TxSource::Api, t0, 100).unwrap();
    let later = t0 + Duration::from_secs(400);
    // TTL 300s → tx aged out; block horizon generous so only TTL fires.
    let removed = p.prune_expired(later, 100, Duration::from_secs(300), 4);
    assert_eq!(removed.len(), 1);
    assert!(p.is_empty());
}

#[test]
fn prune_expired_by_block_count() {
    let mut p = StagingPool::with_default_caps();
    let t0 = Instant::now();
    held(&mut p, 1, &[1], &[11], 100, 30, TxSource::Api, t0, 100).unwrap(); // staged at h=100
                                                                            // 4 blocks later (h=104), still well within TTL, block horizon = 4 fires.
    let removed = p.prune_expired(
        t0 + Duration::from_secs(1),
        104,
        Duration::from_secs(300),
        4,
    );
    assert_eq!(removed.len(), 1);
    assert!(p.is_empty());
}

#[test]
fn prune_expired_keeps_fresh_entries() {
    let mut p = StagingPool::with_default_caps();
    let t0 = Instant::now();
    held(&mut p, 1, &[1], &[11], 100, 30, TxSource::Api, t0, 100).unwrap();
    // 2 blocks later, 10s later — under both horizons.
    let removed = p.prune_expired(
        t0 + Duration::from_secs(10),
        102,
        Duration::from_secs(300),
        4,
    );
    assert!(removed.is_empty());
    assert!(p.contains(&d(1)));
    p.check_invariants();
}

// ----- priority proxy -----

#[test]
fn orphan_priority_proxy_is_fee_per_size() {
    let mut p = StagingPool::with_default_caps();
    let now = Instant::now();
    orphan(
        &mut p,
        1,
        &[0x10],
        &[0x20],
        &[0x10],
        1_000_000,
        500,
        TxSource::Api,
        now,
        1,
    )
    .unwrap();
    let expected = 1_000_000u64 * SCALE / 500;
    assert_eq!(p.get(&d(1)).unwrap().priority_proxy(), expected);
}

#[test]
fn iter_yields_insertion_order() {
    let mut p = StagingPool::with_default_caps();
    let now = Instant::now();
    held(&mut p, 5, &[5], &[15], 100, 30, TxSource::Api, now, 1).unwrap();
    held(&mut p, 3, &[3], &[13], 100, 30, TxSource::Api, now, 1).unwrap();
    held(&mut p, 9, &[9], &[19], 100, 30, TxSource::Api, now, 1).unwrap();
    let ids: Vec<TxId> = p.iter().map(|e| e.tx_id).collect();
    assert_eq!(ids, vec![d(5), d(3), d(9)]);
}
