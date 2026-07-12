//! Bounded postmortem ring for operator reorgs.
//!
//! Complements the coarse event feed / WS push: those are live + short
//! resume windows; this ring keeps the last N reorgs (and drops anything
//! older than [`ReorgHistory::MAX_AGE_MS`]) so `GET /api/v1/diagnostics/reorgs`
//! and Prometheus can answer “what reorged?” without a live subscription.
//!
//! Observability only — never consulted by consensus / validation.

use std::collections::VecDeque;

/// One detected tip replacement, as projected for diagnostics / metrics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReorgRecord {
    pub unix_ms: u64,
    pub height: u32,
    pub header_id: String,
    pub depth: u32,
    pub dropped_header_ids: Vec<String>,
    /// True when the dropped list hit the 32-block committed-tail cap —
    /// deeper orphans may exist but are not named.
    pub orphans_truncated: bool,
    /// Rolled-back tx ids returned to the mempool (capped; see total).
    pub returned_tx_ids: Vec<String>,
    /// Uncapped returned-tx count.
    pub returned_txs_total: u32,
    /// First deliverer of the winning tip header, when known.
    pub delivered_by: Option<String>,
}

/// Last-N (+ max-age) reorg history for operator postmortem.
#[derive(Debug, Default)]
pub(crate) struct ReorgHistory {
    entries: VecDeque<ReorgRecord>,
    /// Session counter — never decreases; drives Prometheus counter.
    total: u64,
}

impl ReorgHistory {
    /// Count cap (also bound by [`Self::MAX_AGE_MS`] on push/list).
    pub(crate) const CAP: usize = 64;
    /// Wall-clock retention: 7 days.
    pub(crate) const MAX_AGE_MS: u64 = 7 * 24 * 60 * 60 * 1000;

    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn push(&mut self, record: ReorgRecord) {
        self.total = self.total.saturating_add(1);
        self.entries.push_back(record);
        self.prune(self.entries.back().map(|e| e.unix_ms).unwrap_or(0));
    }

    /// Newest-first retained entries after age/count prune against `now_ms`.
    pub(crate) fn list(&mut self, now_ms: u64) -> Vec<ReorgRecord> {
        self.prune(now_ms);
        self.entries.iter().rev().cloned().collect()
    }

    /// Cache key after age/count prune: `(session_total, retained_len)`.
    /// `total` alone is not enough — age prune can shrink the ring without
    /// changing the counter.
    pub(crate) fn projection_key(&mut self, now_ms: u64) -> (u64, usize) {
        self.prune(now_ms);
        (self.total, self.entries.len())
    }

    pub(crate) fn total(&self) -> u64 {
        self.total
    }

    fn prune(&mut self, now_ms: u64) {
        let cutoff = now_ms.saturating_sub(Self::MAX_AGE_MS);
        while self.entries.front().is_some_and(|e| e.unix_ms < cutoff) {
            self.entries.pop_front();
        }
        while self.entries.len() > Self::CAP {
            self.entries.pop_front();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(unix_ms: u64, height: u32) -> ReorgRecord {
        ReorgRecord {
            unix_ms,
            height,
            header_id: format!("h{height}"),
            depth: 1,
            dropped_header_ids: vec!["old".into()],
            orphans_truncated: false,
            returned_tx_ids: Vec::new(),
            returned_txs_total: 0,
            delivered_by: None,
        }
    }

    // ----- happy path -----

    #[test]
    fn push_and_list_newest_first() {
        let mut h = ReorgHistory::new();
        h.push(rec(1_000, 10));
        h.push(rec(2_000, 11));
        let list = h.list(2_000);
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].height, 11);
        assert_eq!(list[1].height, 10);
        assert_eq!(h.total(), 2);
    }

    // ----- error paths / bounds -----

    #[test]
    fn count_cap_evicts_oldest() {
        let mut h = ReorgHistory::new();
        for i in 0..(ReorgHistory::CAP as u64 + 5) {
            h.push(rec(i, i as u32));
        }
        let list = h.list(ReorgHistory::CAP as u64 + 5);
        assert_eq!(list.len(), ReorgHistory::CAP);
        assert_eq!(list.last().unwrap().height, 5);
        assert_eq!(h.total(), ReorgHistory::CAP as u64 + 5);
    }

    #[test]
    fn max_age_evicts_stale_even_under_cap() {
        let mut h = ReorgHistory::new();
        h.push(rec(1_000, 1));
        h.push(rec(1_000 + ReorgHistory::MAX_AGE_MS + 1, 2));
        let list = h.list(1_000 + ReorgHistory::MAX_AGE_MS + 1);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].height, 2);
        assert_eq!(h.total(), 2, "age prune does not rewind the counter");
    }
}
