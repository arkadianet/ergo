//! Stateful request/delivery fuzzing against the production P2P tracker.
//!
//! Five-byte instructions select an operation, peer, modifier id and argument.
//! The clock advances only by encoded offsets; no sleeps or sockets are needed.
//! An independent ownership ledger checks counts, capacity, cancellation,
//! timeout boundaries, hedge limits and duplicate handling after every step.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use ergo_p2p::delivery::{
    DeliveryAction, DeliveryTracker, ModifierStatus, DELIVERY_TIMEOUT, MAX_HEDGES,
    MAX_IN_FLIGHT_PER_PEER,
};

const PEERS: usize = 4;
const ID_SPACE: usize = 4096;
const MAX_STEPS: usize = 128;

#[derive(Clone, Copy)]
struct Owner {
    peer: SocketAddr,
    type_id: u8,
    at: Instant,
    hedges: u8,
}

fn modifier_id(index: usize) -> [u8; 32] {
    let mut id = [0; 32];
    id[..2].copy_from_slice(&((index % ID_SPACE) as u16).to_le_bytes());
    id
}

/// Fuzz a bounded sequence of requests, delivery, timeout, hedge and disconnect
/// operations. Panics preserve the whole sequence as a libFuzzer reproducer.
pub fn fuzz_delivery(data: &[u8]) {
    let peers: [SocketAddr; PEERS] = std::array::from_fn(|i| {
        SocketAddr::new(Ipv4Addr::new(127, 0, 0, (i + 1) as u8).into(), 9030)
    });
    let mut tracker = DeliveryTracker::new();
    let mut owners = BTreeMap::<[u8; 32], Owner>::new();
    let mut received = BTreeSet::new();
    // An overapproximation of peers actually asked for each modifier. It lets
    // us reject never-requested senders without duplicating the tracker's late
    // allowance TTL/retry policy in the model.
    let mut asked = BTreeMap::<[u8; 32], BTreeSet<SocketAddr>>::new();
    let mut now = Instant::now();
    let mut last_got = None;

    for instruction in data.as_chunks::<5>().0.iter().take(MAX_STEPS) {
        let peer = peers[instruction[1] as usize % PEERS];
        let index = u16::from_le_bytes([instruction[2], instruction[3]]) as usize;
        let id = modifier_id(index);
        let arg = instruction[4];
        match instruction[0] % 10 {
            0..=2 => {
                let batch = if instruction[0] % 10 == 1 {
                    MAX_IN_FLIGHT_PER_PEER + 4
                } else {
                    usize::from(arg % 17)
                };
                let ids: Vec<_> = (0..batch).map(|i| modifier_id(index + i)).collect();
                let type_id = [101, 102, 104, 108, 2][arg as usize % 5];
                let capacity = MAX_IN_FLIGHT_PER_PEER
                    - owners.values().filter(|owner| owner.peer == peer).count();
                let mut unique = BTreeSet::new();
                let expected: Vec<_> = ids
                    .iter()
                    .filter(|id| {
                        !owners.contains_key(*id)
                            && !received.contains(*id)
                            && (instruction[0] % 10 == 2
                                || tracker.status(id) != ModifierStatus::Failed)
                            && unique.insert(**id)
                    })
                    .take(capacity)
                    .copied()
                    .collect();
                let actual = if instruction[0] % 10 == 2 {
                    tracker.request_allow_failed(peer, type_id, &ids, now)
                } else {
                    tracker.request(peer, type_id, &ids, now)
                };
                assert_eq!(actual, expected, "request respects ownership and capacity");
                for id in actual {
                    owners.insert(
                        id,
                        Owner {
                            peer,
                            type_id,
                            at: now,
                            hedges: 0,
                        },
                    );
                    asked.entry(id).or_default().insert(peer);
                }
            }
            3 => {
                let action = tracker.on_received(&id, &peer);
                if received.contains(&id) {
                    assert_eq!(action, DeliveryAction::Ignore);
                } else if owners.get(&id).is_some_and(|owner| owner.peer == peer) {
                    assert_eq!(action, DeliveryAction::Accept);
                } else if !asked.get(&id).is_some_and(|peers| peers.contains(&peer)) {
                    assert_eq!(action, DeliveryAction::RejectSpam);
                }
                if action == DeliveryAction::Accept {
                    tracker.mark_received(&id);
                    owners.remove(&id);
                    received.insert(id);
                    last_got = Some(now);
                    for sender in peers {
                        assert_eq!(tracker.on_received(&id, &sender), DeliveryAction::Ignore);
                    }
                }
            }
            4 => {
                now += Duration::from_millis([0, 1, 3000, 3001, 59000, 60001][arg as usize % 6]);
                let expired: BTreeSet<_> = owners
                    .iter()
                    .filter(|(_, owner)| now.duration_since(owner.at) > DELIVERY_TIMEOUT)
                    .map(|(id, _)| *id)
                    .collect();
                let connectivity = if arg & 0x80 == 0 { None } else { last_got };
                let result = tracker.check_timeouts_gated(now, connectivity);
                for (peer, ids) in &result.retryable {
                    assert!(!ids.is_empty());
                    for id in ids {
                        assert_eq!(
                            owners.get(id).unwrap().peer,
                            *peer,
                            "timeout keeps peer attribution"
                        );
                    }
                }
                let actual: Vec<_> = result
                    .retryable
                    .iter()
                    .flat_map(|(_, ids)| ids)
                    .copied()
                    .collect();
                assert_eq!(
                    actual.len(),
                    expired.len(),
                    "every expired request is returned once"
                );
                assert_eq!(actual.into_iter().collect::<BTreeSet<_>>(), expired);
                assert!(result.exhausted.iter().all(|id| expired.contains(id)));
                let hard: BTreeSet<_> = expired
                    .iter()
                    .filter(|id| connectivity.is_none_or(|last| owners[*id].at >= last))
                    .copied()
                    .collect();
                assert_eq!(
                    result.penalize.into_iter().collect::<BTreeSet<_>>(),
                    hard,
                    "connectivity gates exactly the hard-timeout penalties"
                );
                for id in expired {
                    owners.remove(&id);
                }
            }
            5 => {
                let expected = owners.get(&id).is_some_and(|owner| {
                    owner.peer != peer
                        && owner.hedges < MAX_HEDGES
                        && owners.values().filter(|owner| owner.peer == peer).count()
                            < MAX_IN_FLIGHT_PER_PEER
                });
                assert_eq!(tracker.reassign(&id, peer, now), expected);
                if expected {
                    let owner = owners.get_mut(&id).unwrap();
                    owner.peer = peer;
                    owner.at = now;
                    owner.hedges += 1;
                    asked.entry(id).or_default().insert(peer);
                }
            }
            6 => {
                let expected: BTreeSet<_> = owners
                    .iter()
                    .filter(|(_, owner)| owner.peer == peer)
                    .map(|(id, _)| *id)
                    .collect();
                let result = tracker.cancel_peer(&peer, now);
                let actual: Vec<_> = result
                    .retryable
                    .into_iter()
                    .chain(result.exhausted)
                    .collect();
                assert_eq!(actual.len(), expected.len());
                assert_eq!(actual.into_iter().collect::<BTreeSet<_>>(), expected);
                owners.retain(|_, owner| owner.peer != peer);
            }
            7 => {
                assert_eq!(tracker.forget_received(&id), received.remove(&id));
            }
            8 => {
                if owners.contains_key(&id) {
                    tracker.register_hedge_peers(&[id], &[peer], now);
                    asked.entry(id).or_default().insert(peer);
                    assert_eq!(tracker.on_received(&id, &peer), DeliveryAction::Accept);
                }
            }
            9 => {
                if !owners.contains_key(&id) {
                    tracker.forget_timed_out(&id);
                }
            }
            _ => unreachable!(),
        }
        assert_eq!(tracker.total_inflight(), owners.len());
        assert_eq!(tracker.received_count(), received.len());
        for peer in peers {
            let count = owners.values().filter(|owner| owner.peer == peer).count();
            assert!(count <= MAX_IN_FLIGHT_PER_PEER);
            assert_eq!(tracker.inflight_count(&peer), count);
            assert_eq!(
                tracker.available_slots(&peer),
                MAX_IN_FLIGHT_PER_PEER - count
            );
            assert_eq!(
                tracker.peer_has_capacity(&peer),
                count < MAX_IN_FLIGHT_PER_PEER
            );
        }
        for (id, owner) in &owners {
            assert_eq!(tracker.status(id), ModifierStatus::Requested);
            assert_eq!(tracker.modifier_type(id), Some(owner.type_id));
            assert_eq!(
                tracker.inflight_age(id, now),
                Some((now.duration_since(owner.at), owner.peer))
            );
            assert_eq!(tracker.on_received(id, &owner.peer), DeliveryAction::Accept);
        }
        let gauges = tracker.gauges();
        assert_eq!(gauges.inflight, owners.len());
        assert_eq!(gauges.received_set, received.len());
        assert!(gauges.late_acceptable <= ID_SPACE);
        assert!(gauges.recently_released <= ID_SPACE);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- happy path -----

    #[test]
    fn mixed_delivery_hedge_timeout_disconnect_and_retry_sequences_complete() {
        let instructions = [
            [0, 0, 0, 0, 2],
            [8, 1, 0, 0, 0],
            [5, 2, 1, 0, 0],
            [3, 1, 0, 0, 0],
            [3, 0, 0, 0, 0],
            [4, 0, 0, 0, 3],
            [0, 3, 1, 0, 1],
            [3, 0, 1, 0, 0],
            [6, 3, 0, 0, 0],
            [7, 0, 0, 0, 0],
            [2, 2, 0, 0, 1],
            [9, 0, 1, 0, 0],
        ];
        fuzz_delivery(&instructions.concat());
    }

    #[test]
    fn capacity_and_hedge_limits_survive_saturated_batches() {
        fuzz_delivery(
            &[
                [1, 0, 0, 0, 0],
                [1, 1, 0, 0, 0],
                [5, 1, 0, 0, 0],
                [5, 2, 0, 0, 0],
                [5, 3, 0, 0, 0],
                [5, 0, 0, 0, 0],
                [6, 2, 0, 0, 0],
                [4, 0, 0, 0, 3],
                [1, 3, 0, 0, 0],
            ]
            .concat(),
        );
    }

    // ----- error paths -----

    #[test]
    fn timeout_buckets_keep_peer_identity_and_soft_and_hard_penalties() {
        fuzz_delivery(
            &[
                [0, 0, 0, 0, 1],
                [0, 1, 10, 0, 1],
                [4, 0, 0, 0, 1],
                [3, 1, 10, 0, 0],
                [0, 2, 20, 0, 1],
                [4, 0, 0, 0, 129],
            ]
            .concat(),
        );
    }

    #[test]
    fn arbitrary_bounded_instruction_streams_complete() {
        for seed in 0..32 {
            let mut rng = crate::rng::Rng::new(seed);
            let bytes: Vec<_> = (0..MAX_STEPS * 5).map(|_| rng.next_u64() as u8).collect();
            fuzz_delivery(&bytes);
        }
        fuzz_delivery(&[]);
        fuzz_delivery(&[255; 4]);
    }
}
