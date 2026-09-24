//! Operator event-feed projection: the retained [`EventFeedRing`] tail
//! projected to the wire `ApiNodeEvents` DTO.
//!
//! [`EventFeedRing`]: crate::node::event_feed::EventFeedRing

/// Project the ring tail into the API DTO. Called only when the ring's
/// latest seq advanced (see the seq-keyed cache at the call site).
pub(super) fn build_events_projection(
    ring: &crate::node::event_feed::EventFeedRing,
) -> std::sync::Arc<ergo_api::types::ApiNodeEvents> {
    use crate::node::event_feed::FeedEventKind as K;
    // Project the FULL retained tail (ring CAP, 512), not a shorter window:
    // the seq contract promises that a gap between polls means ring
    // EVICTION and nothing else. A narrower projection would open a silent
    // second gap source for any client whose `since` cursor is older than
    // the window but younger than eviction. ~512
    // small events clone only when the seq advances (see the cache at the
    // call site), so the cost stays negligible.
    let events = ring
        .latest(crate::node::event_feed::EventFeedRing::CAP)
        .into_iter()
        .map(|e| {
            let mut ev = ergo_api::types::ApiNodeEvent {
                seq: e.seq,
                unix_ms: e.unix_ms,
                kind: String::new(),
                height: None,
                header_id: None,
                depth: None,
                dropped_header_ids: None,
                returned_tx_ids: None,
                returned_txs_total: None,
                delivered_by: None,
                txs: None,
                size_bytes: None,
                addr: None,
                detail: None,
                reconstructed_order: None,
                reconstruction_key: None,
            };
            match e.kind {
                K::BlockApplied {
                    height,
                    header_id,
                    txs,
                    size_bytes,
                } => {
                    ev.kind = "blockApplied".into();
                    ev.height = Some(height);
                    ev.header_id = Some(header_id);
                    ev.txs = Some(txs);
                    ev.size_bytes = Some(size_bytes);
                }
                K::Reorg {
                    height,
                    header_id,
                    depth,
                    dropped_header_ids,
                    returned_tx_ids,
                    returned_txs_total,
                    delivered_by,
                } => {
                    ev.kind = "reorg".into();
                    ev.height = Some(height);
                    ev.header_id = Some(header_id);
                    ev.depth = Some(depth);
                    ev.dropped_header_ids = Some(dropped_header_ids);
                    ev.returned_tx_ids = Some(returned_tx_ids);
                    ev.returned_txs_total = Some(returned_txs_total);
                    ev.delivered_by = delivered_by;
                }
                K::PeerConnected { addr } => {
                    ev.kind = "peerConnected".into();
                    ev.addr = Some(addr);
                }
                K::PeerDisconnected { addr } => {
                    ev.kind = "peerDisconnected".into();
                    ev.addr = Some(addr);
                }
                K::IndexerStatus { status, detail } => {
                    ev.kind = "indexerStatus".into();
                    ev.detail = Some(match detail {
                        Some(d) => format!("{status} ({d})"),
                        None => status,
                    });
                }
                K::ShadowDivergence {
                    kind,
                    height,
                    ours,
                    theirs,
                } => {
                    ev.kind = "shadowDivergence".into();
                    ev.height = Some(height);
                    ev.detail = Some(if ours.is_empty() {
                        kind
                    } else {
                        format!("{kind} ours={ours} theirs={theirs}")
                    });
                }
                K::SyncWedged { height, header_id } => {
                    ev.kind = "syncWedged".into();
                    ev.height = Some(height);
                    ev.header_id = Some(header_id);
                    ev.detail = Some(
                        "best-header chain forks below the rollback window — resync required"
                            .into(),
                    );
                }
                // Snake-case kinds, deliberately: the M2 devnet smoke and
                // the campaign's reconstruct-rate measurement key off
                // these exact strings (plan 2 tasks 8 and 9).
                K::OrderingReconstructed {
                    height,
                    header_id,
                    txs,
                    order,
                    key,
                } => {
                    ev.kind = "ordering_reconstructed".into();
                    ev.height = Some(height);
                    ev.header_id = Some(header_id);
                    ev.txs = Some(txs);
                    ev.reconstructed_order = Some(order.to_string());
                    ev.reconstruction_key = Some(key.to_string());
                }
                K::OrderingReconstructFallback {
                    height,
                    header_id,
                    reason,
                } => {
                    ev.kind = "ordering_reconstruct_fallback".into();
                    ev.height = Some(height);
                    ev.header_id = Some(header_id);
                    ev.detail = Some(reason);
                }
                K::OrderingReconstructSkipped {
                    height,
                    header_id,
                    reason,
                } => {
                    ev.kind = "ordering_reconstruct_skipped".into();
                    ev.height = Some(height);
                    ev.header_id = Some(header_id);
                    ev.detail = Some(reason);
                }
            }
            ev
        })
        .collect::<Vec<_>>();
    std::sync::Arc::new(ergo_api::types::ApiNodeEvents {
        latest_seq: ring.latest_seq(),
        events,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_events_projection_reorg_includes_depth_and_dropped_header_ids() {
        let mut ring = crate::node::event_feed::EventFeedRing::new();
        ring.push(
            1_700_000_000_000,
            crate::node::event_feed::FeedEventKind::Reorg {
                height: 100,
                header_id: "new-tip".to_string(),
                depth: 2,
                dropped_header_ids: vec!["old-100".to_string(), "old-99".to_string()],
                returned_tx_ids: vec!["aa11".to_string()],
                returned_txs_total: 1,
                delivered_by: Some("1.2.3.4:9030".to_string()),
            },
        );

        let events = build_events_projection(&ring);
        let event = serde_json::to_value(&events.events[0]).unwrap();

        assert_eq!(
            event,
            serde_json::json!({
                "seq": 1,
                "unixMs": 1_700_000_000_000u64,
                "kind": "reorg",
                "height": 100,
                "headerId": "new-tip",
                "depth": 2,
                "droppedHeaderIds": ["old-100", "old-99"],
                "returnedTxIds": ["aa11"],
                "returnedTxsTotal": 1,
                "deliveredBy": "1.2.3.4:9030",
            })
        );
    }

    /// The exact serialized shape `scripts/devnet-matrix/smoke.py` parses
    /// for assertion 4 (task 8b, fix round 3).
    ///
    /// Round 2's "no reconstruction on a root mismatch" guard looked for
    /// an `ordering_reconstructed` event carrying `detail ==
    /// "root_mismatch"` — a shape this projection never produces, so the
    /// guard could never fire. A mismatch reason rides on a FALLBACK
    /// event; a reconstructed event carries no `detail` at all. This
    /// pins that, and the field names the harness reads, so the guard
    /// cannot silently go looking for a shape again.
    /// A block the follower had NO input chain for goes straight to a
    /// full download and used to emit nothing at all, so the fallback
    /// counter undercounted the downloads it was meant to measure — the
    /// devnet `evict` scenario recorded six ordering blocks with zero
    /// reconstructions AND zero fallbacks. This pins the third outcome's
    /// serialized shape, which the campaign parses alongside the others.
    #[test]
    fn a_skipped_reconstruction_reports_its_reason_as_detail() {
        use crate::node::event_feed::{EventFeedRing, FeedEventKind};

        let mut ring = EventFeedRing::new();
        ring.push(
            1_700_000_000_003,
            FeedEventKind::OrderingReconstructSkipped {
                height: 44,
                header_id: "no-chain".to_string(),
                reason: "no_chain".to_string(),
            },
        );

        let events = build_events_projection(&ring);
        let skipped = serde_json::to_value(&events.events[0]).unwrap();

        assert_eq!(
            skipped,
            serde_json::json!({
                "seq": 1,
                "unixMs": 1_700_000_000_003u64,
                "kind": "ordering_reconstruct_skipped",
                "height": 44,
                "headerId": "no-chain",
                "detail": "no_chain",
            })
        );
        // It is NOT a reconstruction: a harness tallying rebuild
        // outcomes must never count this one as one.
        assert!(
            skipped.get("txs").is_none(),
            "a skipped reconstruction assembled nothing: {skipped}"
        );
        assert!(skipped.get("reconstructedOrder").is_none(), "{skipped}");
    }

    #[test]
    fn reconstruction_events_have_the_shape_the_smoke_harness_parses() {
        use crate::node::event_feed::{EventFeedRing, FeedEventKind};

        let mut ring = EventFeedRing::new();
        ring.push(
            1_700_000_000_000,
            FeedEventKind::OrderingReconstructed {
                height: 42,
                header_id: "rebuilt".to_string(),
                txs: 3,
                order: "candidate",
                key: "parent",
            },
        );
        ring.push(
            1_700_000_000_001,
            FeedEventKind::OrderingReconstructFallback {
                height: 43,
                header_id: "downloaded".to_string(),
                reason: "root_mismatch".to_string(),
            },
        );
        ring.push(
            1_700_000_000_002,
            FeedEventKind::BlockApplied {
                height: 43,
                header_id: "downloaded".to_string(),
                txs: 3,
                size_bytes: 1234,
            },
        );

        let events = build_events_projection(&ring);
        let rebuilt = serde_json::to_value(&events.events[0]).unwrap();
        let fallback = serde_json::to_value(&events.events[1]).unwrap();
        let applied = serde_json::to_value(&events.events[2]).unwrap();

        assert_eq!(
            rebuilt,
            serde_json::json!({
                "seq": 1,
                "unixMs": 1_700_000_000_000u64,
                "kind": "ordering_reconstructed",
                "height": 42,
                "headerId": "rebuilt",
                "txs": 3,
                "reconstructedOrder": "candidate",
                "reconstructionKey": "parent",
            })
        );
        // The load-bearing absence: a reconstructed block reports no
        // `detail`, so a mismatch reason can never appear on one.
        assert!(
            rebuilt.get("detail").is_none(),
            "a reconstructed event must carry no detail: {rebuilt}"
        );

        assert_eq!(
            fallback,
            serde_json::json!({
                "seq": 2,
                "unixMs": 1_700_000_000_001u64,
                "kind": "ordering_reconstruct_fallback",
                "height": 43,
                "headerId": "downloaded",
                "detail": "root_mismatch",
            })
        );

        assert_eq!(
            applied,
            serde_json::json!({
                "seq": 3,
                "unixMs": 1_700_000_000_002u64,
                "kind": "blockApplied",
                "height": 43,
                "headerId": "downloaded",
                "txs": 3,
                "sizeBytes": 1234,
            })
        );
    }
}
