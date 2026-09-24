use ergo_api::types::{ApiNodeEvent, ApiNodeEvents};
use ergo_api_core::observability::{EventFeed, EventRecord, EventSource};

use super::SnapshotReadState;

fn convert_event(event: &ApiNodeEvent) -> EventRecord {
    EventRecord {
        seq: event.seq,
        unix_ms: event.unix_ms,
        kind: event.kind.clone(),
        height: event.height,
        header_id: event.header_id.clone(),
        depth: event.depth,
        dropped_header_ids: event.dropped_header_ids.clone(),
        returned_tx_ids: event.returned_tx_ids.clone(),
        returned_txs_total: event.returned_txs_total,
        delivered_by: event.delivered_by.clone(),
        txs: event.txs,
        size_bytes: event.size_bytes,
        addr: event.addr.clone(),
        detail: event.detail.clone(),
    }
}

fn convert_feed(feed: &ApiNodeEvents) -> EventFeed {
    EventFeed::new(
        feed.latest_seq,
        feed.events.iter().map(convert_event).collect(),
    )
}

impl EventSource for SnapshotReadState {
    fn events(&self) -> EventFeed {
        let snapshot = self.handle.load();
        convert_feed(snapshot.events.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(seq: u64, kind: &str) -> ApiNodeEvent {
        ApiNodeEvent {
            seq,
            unix_ms: 1_700_000_000_000 + seq,
            kind: kind.to_string(),
            height: Some(100 + seq as u32),
            header_id: Some(format!("header-{seq}")),
            depth: None,
            dropped_header_ids: None,
            returned_tx_ids: None,
            returned_txs_total: None,
            delivered_by: None,
            txs: Some(seq as u32),
            size_bytes: Some(seq * 10),
            addr: None,
            detail: None,
        }
    }

    #[test]
    fn converts_the_precomputed_tail_without_reordering_or_losing_fields() {
        let feed = ApiNodeEvents {
            latest_seq: 3,
            events: vec![
                event(1, "blockApplied"),
                event(2, "reorg"),
                event(3, "peerConnected"),
            ],
        };

        let converted = convert_feed(&feed);

        assert_eq!(converted.latest_seq, 3);
        assert_eq!(
            converted
                .events
                .iter()
                .map(|event| event.seq)
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        assert_eq!(converted.events[0].kind, "blockApplied");
        assert_eq!(converted.events[0].header_id.as_deref(), Some("header-1"));
        assert_eq!(converted.events[0].txs, Some(1));
        assert_eq!(converted.events[0].size_bytes, Some(10));
    }

    #[test]
    fn conversion_preserves_reorg_empty_values_as_present() {
        let mut event = event(1, "reorg");
        event.dropped_header_ids = Some(Vec::new());
        event.returned_tx_ids = Some(Vec::new());
        event.returned_txs_total = Some(0);
        let converted = convert_feed(&ApiNodeEvents {
            latest_seq: 1,
            events: vec![event],
        });

        assert_eq!(converted.events[0].dropped_header_ids, Some(Vec::new()));
        assert_eq!(converted.events[0].returned_tx_ids, Some(Vec::new()));
        assert_eq!(converted.events[0].returned_txs_total, Some(0));
    }

    #[test]
    fn conversion_bounds_an_oversized_projection_to_the_newest_tail() {
        let feed = ApiNodeEvents {
            latest_seq: 600,
            events: (1..=600).map(|seq| event(seq, "peerConnected")).collect(),
        };
        let converted = convert_feed(&feed);
        assert_eq!(
            converted.events.len(),
            ergo_api_core::observability::MAX_EVENT_TAIL
        );
        assert_eq!(converted.events.first().unwrap().seq, 89);
        assert_eq!(converted.events.last().unwrap().seq, 600);
    }
}
