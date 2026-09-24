pub const MAX_EVENT_TAIL: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventRecord {
    pub seq: u64,
    pub unix_ms: u64,
    pub kind: String,
    pub height: Option<u32>,
    pub header_id: Option<String>,
    pub depth: Option<u32>,
    pub dropped_header_ids: Option<Vec<String>>,
    pub returned_tx_ids: Option<Vec<String>>,
    pub returned_txs_total: Option<u32>,
    pub delivered_by: Option<String>,
    pub txs: Option<u32>,
    pub size_bytes: Option<u64>,
    pub addr: Option<String>,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EventFeed {
    pub latest_seq: u64,
    pub events: Vec<EventRecord>,
}

impl EventFeed {
    pub fn new(latest_seq: u64, events: Vec<EventRecord>) -> Self {
        let skip = events.len().saturating_sub(MAX_EVENT_TAIL);
        Self {
            latest_seq,
            events: events.into_iter().skip(skip).collect(),
        }
    }

    pub fn since(&self, since: u64) -> Self {
        let mut feed = Self::new(self.latest_seq, self.events.clone());
        if since > 0 {
            feed.events.retain(|event| event.seq > since);
        }
        feed
    }
}

pub trait EventSource: Send + Sync + 'static {
    fn events(&self) -> EventFeed;
}

pub use EventSource as EventFeedSource;

#[cfg(test)]
mod tests {
    use super::*;

    fn event(seq: u64) -> EventRecord {
        EventRecord {
            seq,
            unix_ms: seq,
            kind: "peerConnected".to_string(),
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
        }
    }

    #[test]
    fn feed_constructor_keeps_the_bounded_newest_tail_in_order() {
        let feed = EventFeed::new(600, (1..=600).map(event).collect());
        assert_eq!(feed.events.len(), MAX_EVENT_TAIL);
        assert_eq!(feed.events.first().unwrap().seq, 89);
        assert_eq!(feed.events.last().unwrap().seq, 600);
    }

    #[test]
    fn since_is_strictly_greater_and_keeps_the_watermark() {
        let feed = EventFeed::new(3, vec![event(0), event(1), event(2), event(3)]);
        assert_eq!(feed.since(0).events.len(), 4);
        let filtered = feed.since(2);
        assert_eq!(filtered.latest_seq, 3);
        assert_eq!(
            filtered
                .events
                .iter()
                .map(|event| event.seq)
                .collect::<Vec<_>>(),
            vec![3]
        );
    }
}
