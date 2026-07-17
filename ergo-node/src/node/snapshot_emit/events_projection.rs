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
}
