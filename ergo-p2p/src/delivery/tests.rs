use super::*;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

fn peer(port: u16) -> PeerId {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), port)
}

fn id(v: u8) -> [u8; 32] {
    [v; 32]
}

#[test]
fn request_and_receive() {
    let mut tracker = DeliveryTracker::new();
    let now = Instant::now();
    let p = peer(9030);

    let registered = tracker.request(p, 101, &[id(1), id(2)], now);
    assert_eq!(registered.len(), 2);
    assert_eq!(tracker.status(&id(1)), ModifierStatus::Requested);
    assert_eq!(tracker.on_received(&id(1), &p), DeliveryAction::Accept);

    tracker.mark_received(&id(1));
    assert_eq!(tracker.status(&id(1)), ModifierStatus::Received);
    assert_eq!(tracker.on_received(&id(1), &p), DeliveryAction::Ignore);
    assert_eq!(tracker.inflight_count(&p), 1); // id(2) still inflight
}

#[test]
fn unsolicited_modifier_rejected() {
    let tracker = DeliveryTracker::new();
    let p = peer(9030);
    assert_eq!(tracker.status(&id(99)), ModifierStatus::Unknown);
    assert_eq!(tracker.on_received(&id(99), &p), DeliveryAction::RejectSpam);
}

#[test]
fn wrong_peer_delivers_modifier_rejected() {
    let mut tracker = DeliveryTracker::new();
    let now = Instant::now();
    let p1 = peer(9030);
    let p2 = peer(9031);

    tracker.request(p1, 101, &[id(1)], now);
    // p1 is the owner — p2 delivering it is spam
    assert_eq!(tracker.on_received(&id(1), &p2), DeliveryAction::RejectSpam);
    // p1 delivering it is accepted
    assert_eq!(tracker.on_received(&id(1), &p1), DeliveryAction::Accept);
}

#[test]
fn per_peer_limit_enforced() {
    let mut tracker = DeliveryTracker::new();
    let now = Instant::now();
    let p = peer(9030);

    let overflow = MAX_IN_FLIGHT_PER_PEER + 10;
    let ids: Vec<[u8; 32]> = (0..overflow)
        .map(|i| {
            let mut arr = [0u8; 32];
            arr[..2].copy_from_slice(&(i as u16).to_be_bytes());
            arr
        })
        .collect();
    let registered = tracker.request(p, 101, &ids, now);
    assert_eq!(registered.len(), MAX_IN_FLIGHT_PER_PEER);
    assert_eq!(tracker.inflight_count(&p), MAX_IN_FLIGHT_PER_PEER);
    assert!(!tracker.peer_has_capacity(&p));
}

#[test]
fn timeout_detection() {
    let mut tracker = DeliveryTracker::new();
    let now = Instant::now();
    let p = peer(9030);

    tracker.request(p, 101, &[id(1), id(2)], now);
    // Before timeout (relative to the const so it survives retuning).
    let result = tracker.check_timeouts(now + DELIVERY_TIMEOUT / 2);
    assert!(result.retryable.is_empty() && result.exhausted.is_empty());
    // After timeout (first attempt — retryable)
    let result = tracker.check_timeouts(now + DELIVERY_TIMEOUT + Duration::from_secs(1));
    assert_eq!(result.retryable.len(), 1);
    assert_eq!(result.retryable[0].0, p);
    assert_eq!(result.retryable[0].1.len(), 2);
    assert!(result.exhausted.is_empty());
    // Inflight should be cleared
    assert_eq!(tracker.inflight_count(&p), 0);
    // IDs should be retryable (not received, not failed yet)
    assert_eq!(tracker.status(&id(1)), ModifierStatus::Unknown);
}

#[test]
fn mark_received_evicts_recently_released_shadow_after_late_delivery() {
    // Regression: a timed-out modifier is stashed in
    // `recently_released` (the type shadow read by the retry-bucket
    // classifier). If the original peer then answers late and the
    // modifier is accepted + marked received, the shadow must be
    // evicted — receiving is terminal, so the entry is otherwise
    // never re-requested, re-timed-out, or exhausted and would leak
    // one entry per timed-out-then-delivered modifier for the life
    // of the node.
    let mut tracker = DeliveryTracker::new();
    let now = Instant::now();
    let p = peer(9030);

    tracker.request(p, 101, &[id(1)], now);
    // Time it out: inflight -> recently_released, still retryable.
    let result = tracker.check_timeouts(now + DELIVERY_TIMEOUT + Duration::from_secs(1));
    assert_eq!(result.retryable.len(), 1);
    assert!(
        tracker.recently_released.contains_key(&id(1)),
        "timeout should stash the type shadow"
    );

    // Original peer delivers late; the post-timeout window accepts it.
    assert_eq!(tracker.on_received(&id(1), &p), DeliveryAction::Accept);
    tracker.mark_received(&id(1));

    assert_eq!(tracker.status(&id(1)), ModifierStatus::Received);
    assert!(
        tracker.recently_released.is_empty(),
        "mark_received must evict the recently_released shadow, not leak it"
    );
    // Behavioural counterpart: the type lookup no longer resolves.
    assert_eq!(tracker.modifier_type(&id(1)), None);
}

#[test]
fn check_timeouts_sweeps_abandoned_shadow_but_keeps_the_live_set() {
    // An abandoned timed-out id — never re-requested (no eligible
    // peer, or pruned in a reorg) — has no precise eviction point, so
    // the age-based sweep must reclaim it. Critically, the sweep must
    // NOT touch shadows created in the same tick: those are the live
    // working set the coordinator is about to re-request.
    let mut tracker = DeliveryTracker::new();
    let t0 = Instant::now();
    let p = peer(9030);

    // id(1) times out at t0 and is then abandoned (never re-requested).
    tracker.request(p, 102, &[id(1)], t0);
    tracker.check_timeouts(t0 + DELIVERY_TIMEOUT + Duration::from_secs(1));
    assert!(tracker.recently_released.contains_key(&id(1)));

    // A later tick, past the shadow TTL, also times out a fresh id(2).
    let later = t0 + RELEASED_SHADOW_TTL + DELIVERY_TIMEOUT + Duration::from_secs(2);
    tracker.request(p, 102, &[id(2)], later);
    tracker.check_timeouts(later + DELIVERY_TIMEOUT + Duration::from_secs(1));

    // id(1) was abandoned long enough to be swept; id(2) is fresh and
    // must survive (it is still awaiting re-request).
    assert!(
        !tracker.recently_released.contains_key(&id(1)),
        "abandoned shadow must be swept after the TTL"
    );
    assert!(
        tracker.recently_released.contains_key(&id(2)),
        "a just-released shadow must NOT be swept — it is the live set"
    );
    assert_eq!(tracker.modifier_type(&id(2)), Some(102));
}

#[test]
fn cancel_peer_abandoned_shadow_swept_after_ttl() {
    // Disconnect-originated shadows are timestamped by cancel_peer but
    // swept by the periodic check_timeouts tick, so an abandoned one
    // (peer gone, never re-requested) is still reclaimed after the TTL.
    let mut tracker = DeliveryTracker::new();
    let t0 = Instant::now();
    let p = peer(9030);

    tracker.request(p, 104, &[id(7)], t0);
    tracker.cancel_peer(&p, t0);
    assert!(tracker.recently_released.contains_key(&id(7)));

    tracker.check_timeouts(t0 + RELEASED_SHADOW_TTL + Duration::from_secs(1));
    assert!(
        !tracker.recently_released.contains_key(&id(7)),
        "disconnect-originated abandoned shadow must be swept after the TTL"
    );
}

#[test]
fn rerequest_makes_inflight_authoritative_and_drops_shadow() {
    // Re-requesting a timed-out id moves it back into `inflight`; the
    // stale released shadow must be dropped so the live entry wins.
    let mut tracker = DeliveryTracker::new();
    let now = Instant::now();
    let p = peer(9030);

    tracker.request(p, 104, &[id(8)], now);
    tracker.check_timeouts(now + DELIVERY_TIMEOUT + Duration::from_secs(1));
    assert!(tracker.recently_released.contains_key(&id(8)));

    tracker.request(
        peer(9031),
        104,
        &[id(8)],
        now + DELIVERY_TIMEOUT + Duration::from_secs(2),
    );
    assert!(!tracker.recently_released.contains_key(&id(8)));
    assert_eq!(tracker.status(&id(8)), ModifierStatus::Requested);
}

#[test]
fn retry_exhaustion_returns_to_unknown_scala_parity() {
    // Scala parity (CheckDelivery handler at
    // ErgoNodeViewSynchronizer.scala:1287): when a non-header
    // section's checks exceed maxDeliveryChecks, status returns
    // to Unknown. There is NO permanent "Failed" state for
    // sections — they remain eligible for re-request via
    // CheckModifiersToDownload picking a fresh peer.
    let mut tracker = DeliveryTracker::new();
    let p = peer(9030);

    for attempt in 1..=MAX_RETRIES {
        let now = Instant::now();
        tracker.request(p, 101, &[id(1)], now);
        let later = now + DELIVERY_TIMEOUT + Duration::from_secs(1);
        let result = tracker.check_timeouts(later);

        if attempt < MAX_RETRIES {
            assert!(
                !result.retryable.is_empty(),
                "attempt {attempt}: should be retryable",
            );
            assert!(result.exhausted.is_empty());
        } else {
            assert!(
                result.retryable.is_empty(),
                "attempt {attempt}: exhausted means moved out of retry bucket",
            );
            assert_eq!(result.exhausted, vec![id(1)]);
        }
    }

    // After exhaustion, status is Unknown (Scala parity), NOT a
    // permanent "Failed" state. The exhausted return is for
    // caller logging only.
    assert_eq!(tracker.status(&id(1)), ModifierStatus::Unknown);

    // Re-requesting after exhaustion succeeds — id is eligible
    // for a fresh attempt against a different peer next tick.
    let now = Instant::now();
    let registered = tracker.request(p, 101, &[id(1)], now);
    assert_eq!(
        registered,
        vec![id(1)],
        "exhausted modifier must be re-requestable (Scala parity)",
    );
    assert_eq!(tracker.status(&id(1)), ModifierStatus::Requested);
}

#[test]
fn allow_failed_request_revives_modifier() {
    // With the 2Q Scala-parity change, the `failed` set is
    // never populated by ordinary timeout flows — so
    // `request_allow_failed` is now functionally equivalent to
    // `request` in practice. The test verifies the method
    // still works (it's a no-op for already-Unknown ids), so a
    // future caller that DOES set `failed` (e.g., manual
    // intervention or future code) can revive correctly.
    let mut tracker = DeliveryTracker::new();
    let p = peer(9030);

    for attempt in 1..=MAX_RETRIES {
        let now = Instant::now();
        tracker.request(p, 101, &[id(1)], now);
        let later = now + DELIVERY_TIMEOUT + Duration::from_secs(1);
        let result = tracker.check_timeouts(later);
        if attempt < MAX_RETRIES {
            assert!(!result.retryable.is_empty());
        } else {
            assert_eq!(result.exhausted, vec![id(1)]);
        }
    }
    // No permanent Failed under 2Q — id is Unknown after exhaustion.
    assert_eq!(tracker.status(&id(1)), ModifierStatus::Unknown);

    let now = Instant::now();
    let registered = tracker.request_allow_failed(p, 101, &[id(1)], now);
    assert_eq!(registered, vec![id(1)]);
    assert_eq!(tracker.status(&id(1)), ModifierStatus::Requested);
}

#[test]
fn cancel_peer_returns_ids() {
    let mut tracker = DeliveryTracker::new();
    let now = Instant::now();
    let p = peer(9030);

    tracker.request(p, 101, &[id(1), id(2), id(3)], now);
    let result = tracker.cancel_peer(&p, now);
    assert_eq!(result.retryable.len(), 3); // first cancel, all retryable
    assert!(result.exhausted.is_empty());
    assert_eq!(tracker.inflight_count(&p), 0);
    assert_eq!(tracker.total_inflight(), 0);
}

#[test]
fn skip_already_requested_or_received() {
    let mut tracker = DeliveryTracker::new();
    let now = Instant::now();
    let p1 = peer(9030);
    let p2 = peer(9031);

    // p1 requests id(1)
    tracker.request(p1, 101, &[id(1)], now);
    // p2 tries to request id(1) again — should skip
    let registered = tracker.request(p2, 101, &[id(1), id(2)], now);
    assert_eq!(registered, vec![id(2)]);

    // Mark id(1) as received
    tracker.mark_received(&id(1));
    // p2 tries to request id(1) again — should skip (already received)
    let registered = tracker.request(p2, 101, &[id(1)], now);
    assert!(registered.is_empty());
}

#[test]
fn forget_received_allows_future_request() {
    let mut tracker = DeliveryTracker::new();
    let now = Instant::now();
    let p = peer(9030);

    tracker.request(p, 101, &[id(1)], now);
    tracker.mark_received(&id(1));
    assert_eq!(tracker.status(&id(1)), ModifierStatus::Received);

    assert!(tracker.forget_received(&id(1)));
    assert_eq!(tracker.status(&id(1)), ModifierStatus::Unknown);

    let registered = tracker.request(p, 101, &[id(1)], now);
    assert_eq!(registered, vec![id(1)]);
    assert_eq!(tracker.status(&id(1)), ModifierStatus::Requested);
}

#[test]
fn multiple_peers_independent_limits() {
    let mut tracker = DeliveryTracker::new();
    let now = Instant::now();
    let p1 = peer(9030);
    let p2 = peer(9031);

    let ids_p1: Vec<[u8; 32]> = (0..4).map(id).collect();
    let ids_p2: Vec<[u8; 32]> = (10..14).map(id).collect();

    tracker.request(p1, 101, &ids_p1, now);
    tracker.request(p2, 101, &ids_p2, now);

    assert_eq!(tracker.inflight_count(&p1), 4);
    assert_eq!(tracker.inflight_count(&p2), 4);
    assert_eq!(tracker.total_inflight(), 8);
}

#[test]
fn s2_below_drain_watermark_tracks_total_inflight() {
    let mut tracker = DeliveryTracker::new();
    let now = Instant::now();
    let p = peer(9030);

    // Empty pipeline → always below.
    assert!(tracker.below_drain_watermark(1));
    assert!(tracker.below_drain_watermark(64));

    // 10 in flight, watermark 64 → still below.
    let ids: Vec<[u8; 32]> = (0..10).map(id).collect();
    tracker.request(p, 101, &ids, now);
    assert_eq!(tracker.total_inflight(), 10);
    assert!(tracker.below_drain_watermark(64));
    assert!(
        !tracker.below_drain_watermark(10),
        "watermark equal to inflight is NOT below — strict <"
    );
    assert!(tracker.below_drain_watermark(11));
}

#[test]
fn s2_available_slots_matches_inflight_complement() {
    let mut tracker = DeliveryTracker::new();
    let now = Instant::now();
    let p = peer(9030);
    assert_eq!(tracker.available_slots(&p), MAX_IN_FLIGHT_PER_PEER);

    let ids: Vec<[u8; 32]> = (0..50).map(id).collect();
    tracker.request(p, 101, &ids, now);
    assert_eq!(tracker.available_slots(&p), MAX_IN_FLIGHT_PER_PEER - 50);
}

#[test]
fn hol_hedge_reassign_accepts_new_owner_delivery() {
    let mut tracker = DeliveryTracker::new();
    let now = Instant::now();
    let p1 = peer(9030);
    let p2 = peer(9031);

    tracker.request(p1, 101, &[id(1)], now);

    // Reassign to p2 (HOL hedge)
    assert!(tracker.reassign(&id(1), p2, now));
    assert_eq!(tracker.inflight_count(&p1), 0);
    assert_eq!(tracker.inflight_count(&p2), 1);

    // p2 is now the owner — accepts
    assert_eq!(tracker.on_received(&id(1), &p2), DeliveryAction::Accept);
}

#[test]
fn hol_hedge_original_peer_late_delivery_is_accepted() {
    let mut tracker = DeliveryTracker::new();
    let now = Instant::now();
    let p1 = peer(9030);
    let p2 = peer(9031);

    tracker.request(p1, 101, &[id(1)], now);
    tracker.reassign(&id(1), p2, now);

    // p1 delivers late with useful data. Accept it instead of
    // discarding the section and waiting on p2.
    assert_eq!(tracker.on_received(&id(1), &p1), DeliveryAction::Accept);
}

#[test]
fn hol_hedge_inflight_age_returns_age_and_peer() {
    let mut tracker = DeliveryTracker::new();
    let now = Instant::now();
    let p = peer(9030);

    assert!(tracker.inflight_age(&id(1), now).is_none());

    tracker.request(p, 101, &[id(1)], now);
    let later = now + Duration::from_secs(10);
    let (age, owner) = tracker.inflight_age(&id(1), later).unwrap();
    assert!(age >= Duration::from_secs(10));
    assert_eq!(owner, p);
}

#[test]
fn hol_hedge_late_acceptance_cleared_on_mark_received() {
    let mut tracker = DeliveryTracker::new();
    let now = Instant::now();
    let p1 = peer(9030);
    let p2 = peer(9031);

    tracker.request(p1, 101, &[id(1)], now);
    tracker.reassign(&id(1), p2, now);
    // new peer delivers
    tracker.mark_received(&id(1));
    // after mark_received: duplicate ignored, not spam
    assert_eq!(tracker.on_received(&id(1), &p1), DeliveryAction::Ignore);
}

#[test]
fn timeout_late_delivery_from_requested_peer_is_accepted() {
    let mut tracker = DeliveryTracker::new();
    let now = Instant::now();
    let p = peer(9030);

    tracker.request(p, 101, &[id(1)], now);
    let result = tracker.check_timeouts(now + DELIVERY_TIMEOUT + Duration::from_secs(1));
    assert_eq!(result.retryable[0].1, vec![id(1)]);
    assert_eq!(tracker.status(&id(1)), ModifierStatus::Unknown);

    // The request timed out locally, but the peer is still answering a
    // request we actually sent. Accepting this can rescue HOL progress.
    assert_eq!(tracker.on_received(&id(1), &p), DeliveryAction::Accept);
}

#[test]
fn forget_timed_out_keeps_late_acceptance_so_a_late_tx_is_not_penalized() {
    // P1 forgets a timed-out mempool tx without penalty/re-request. But
    // `check_timeouts` records the timed-out peer in `late_acceptable`
    // (allow_late_delivery), so a slow peer that delivers the tx LATE
    // must still be ACCEPTED — if `forget_timed_out` cleared
    // late_acceptable, on_received would return RejectSpam and penalize
    // an honest peer, defeating the "no reason to penalize" goal.
    let mut tracker = DeliveryTracker::new();
    let now = Instant::now();
    let p = peer(9030);

    tracker.request(p, 2 /* Transaction */, &[id(1)], now);
    tracker.check_timeouts(now + DELIVERY_TIMEOUT + Duration::from_secs(1));
    // The coordinator's tx-timeout path forgets it (no penalty, no re-request).
    tracker.forget_timed_out(&id(1));

    // A late delivery from the originally-requested peer is still accepted.
    assert_eq!(tracker.on_received(&id(1), &p), DeliveryAction::Accept);
}

#[test]
fn hol_reassign_respects_new_peer_capacity() {
    let mut tracker = DeliveryTracker::new();
    let now = Instant::now();
    let old = peer(9030);
    let full = peer(9031);

    tracker.request(old, 101, &[id(1)], now);
    let filler: Vec<[u8; 32]> = (0..MAX_IN_FLIGHT_PER_PEER)
        .map(|i| {
            let mut out = [0xAA; 32];
            out[..2].copy_from_slice(&(i as u16).to_be_bytes());
            out
        })
        .collect();
    assert_eq!(
        tracker.request(full, 101, &filler, now).len(),
        MAX_IN_FLIGHT_PER_PEER
    );

    assert!(!tracker.reassign(&id(1), full, now));
    assert_eq!(tracker.inflight_count(&old), 1);
    assert_eq!(tracker.inflight_count(&full), MAX_IN_FLIGHT_PER_PEER);
}

#[test]
fn reassign_capped_at_max_hedges_so_stuck_section_can_time_out() {
    // Liveness guard: a section that no peer answers must not be
    // re-hedged forever (each reassign resets the inflight clock). After
    // MAX_HEDGES reassigns the next is refused, so the section stays put
    // and reaches the normal timeout/retry path.
    let mut tracker = DeliveryTracker::new();
    let now = Instant::now();
    let id0 = id(1);
    tracker.request(peer(9000), 102, &[id0], now);

    // Advance the clock per hedge so the timeout assertion below is taken
    // relative to the LAST successful reassign — this catches a regression
    // where an over-budget (refused) reassign accidentally refreshes
    // `requested_at`.
    let mut last_successful_reassign = now;
    for i in 0..MAX_HEDGES {
        last_successful_reassign += DELIVERY_TIMEOUT / 2;
        assert!(
            tracker.reassign(&id0, peer(9001 + u16::from(i)), last_successful_reassign),
            "reassign #{i} within budget should succeed"
        );
    }
    let refused_at = last_successful_reassign + DELIVERY_TIMEOUT / 2;
    assert!(
        !tracker.reassign(&id0, peer(9099), refused_at),
        "reassign past MAX_HEDGES must be refused so the section can time out"
    );

    let result = tracker
        .check_timeouts(last_successful_reassign + DELIVERY_TIMEOUT + Duration::from_millis(1));
    assert_eq!(
        result.retryable.len(),
        1,
        "a hedge-capped section must fall through to the timeout/retry path"
    );
}
