//! Operator event feed: a bounded ring of node-lifecycle events for the
//! dashboard's live feed (`GET /api/v1/events`).
//!
//! Pure observability — never feeds sync, consensus, or peer scoring.
//! Events are DERIVED, not instrumented: one call site (`snapshot_emit`)
//! diffs successive per-tick observations (tips, peer set, indexer status)
//! that are already collected on the hot path, so no subsystem grows an
//! event hook. The ring is BOUNDED (FIFO eviction at [`EventFeedRing::CAP`])
//! and each event carries a monotonically increasing `seq` so a polling
//! client can resume with `?since=<seq>` without missing or duplicating
//! entries (gaps mean eviction — the client shows "…" and moves on).

use std::collections::{HashSet, VecDeque};

/// One operator-visible event.
#[derive(Debug, Clone)]
pub(crate) struct FeedEvent {
    /// Monotonic sequence number (starts at 1, never reused).
    pub(crate) seq: u64,
    /// Wall-clock time the event was derived, unix ms.
    pub(crate) unix_ms: u64,
    pub(crate) kind: FeedEventKind,
}

/// Event taxonomy, v1. Deliberately coarse — an operator feed, not a
/// firehose (per-tx mempool churn is intentionally absent). Header ids are
/// hex strings: they exist only to be serialized into the API snapshot.
#[derive(Debug, Clone)]
pub(crate) enum FeedEventKind {
    /// A full block reached the committed tip.
    BlockApplied {
        height: u32,
        header_id: String,
        txs: u32,
        size_bytes: u64,
    },
    /// The best-chain tip changed across a fork. Dropped ids are best-effort
    /// names from the last committed 32-block tail, not a full fork walk.
    Reorg {
        height: u32,
        header_id: String,
        depth: u32,
        dropped_header_ids: Vec<String>,
    },
    PeerConnected {
        addr: String,
    },
    PeerDisconnected {
        addr: String,
    },
    /// The extra-index status label changed (syncing/caughtUp/halted).
    IndexerStatus {
        status: String,
        detail: Option<String>,
    },
}

/// Previous-tick observations the differ compares against. `primed=false`
/// (the boot state) means the first tick only SEEDS this — otherwise boot
/// would flood the feed with a synthetic connect-event per peer and a
/// block-event for the standing tip.
#[derive(Default)]
pub(crate) struct FeedPrev {
    pub(crate) primed: bool,
    pub(crate) tip_height: u32,
    pub(crate) tip_id: String,
    pub(crate) recent: Vec<(u32, String)>,
    pub(crate) peers: std::collections::HashSet<String>,
    pub(crate) indexer_status: Option<String>,
}

/// Per-tick caps so a churn burst (or initial sync) can't monopolize the
/// ring: newest-N blocks, bounded peer-event batches. Excess is dropped —
/// the feed is an operator glanceable, not an audit log.
const MAX_BLOCK_EVENTS_PER_TICK: usize = 4;
const MAX_PEER_EVENTS_PER_TICK: usize = 16;
const RECENT_BLOCKS_CAP: usize = 32;

/// One tick's worth of observations, all already collected on the
/// snapshot-emit hot path — deriving events costs set-diffs only.
pub(crate) struct FeedObservation<'a> {
    pub(crate) unix_ms: u64,
    pub(crate) tip_height: u32,
    /// Hex id of the best FULL block ("" when no tip yet).
    pub(crate) tip_id: String,
    /// Recent committed blocks, newest first: (height, header_id_hex, txs, size).
    pub(crate) recent: &'a [(u32, String, u32, u64)],
    pub(crate) peers: Vec<String>,
    /// Extra-index status label + optional halt detail; `None` = disabled.
    pub(crate) indexer_status: Option<(String, Option<String>)>,
}

fn recent_tail(recent: &[(u32, String, u32, u64)]) -> Vec<(u32, String)> {
    recent
        .iter()
        .take(RECENT_BLOCKS_CAP)
        .map(|(height, id, ..)| (*height, id.clone()))
        .collect()
}

fn dropped_header_ids(prev: &FeedPrev, recent: &[(u32, String, u32, u64)]) -> Vec<String> {
    let now: HashSet<&str> = recent.iter().map(|(_, id, ..)| id.as_str()).collect();
    let mut dropped = Vec::new();

    // Oldest-first gives stable API/WS payloads. This is intentionally capped
    // to the committed tail; deeper orphan names require a real fork walk.
    for (_, id) in prev.recent.iter().rev() {
        if !now.contains(id.as_str()) && !dropped.iter().any(|d| d == id) {
            dropped.push(id.clone());
            if dropped.len() == RECENT_BLOCKS_CAP {
                break;
            }
        }
    }

    if !prev.tip_id.is_empty()
        && !now.contains(prev.tip_id.as_str())
        && !dropped.iter().any(|id| id == &prev.tip_id)
    {
        if dropped.len() == RECENT_BLOCKS_CAP {
            dropped.remove(0);
        }
        dropped.push(prev.tip_id.clone());
    }

    dropped
}

/// Diff `obs` against `prev`, appending derived events to `ring`, then
/// advance `prev`. First call only primes.
///
/// CONSISTENCY CONTRACT: `obs.tip_height`/`obs.tip_id` MUST come from the
/// same source as `obs.recent` (the COMMITTED tail — see the snapshot_emit
/// call site). Feeding the in-memory tip here while `recent` reflects the
/// committed chain would advance the cursor past heights that are not in
/// `recent` yet during the async-persist window, permanently losing their
/// block events.
pub(crate) fn derive_events(
    ring: &mut EventFeedRing,
    prev: &mut FeedPrev,
    obs: FeedObservation,
) -> Vec<super::reorg_history::ReorgRecord> {
    let mut reorgs = Vec::new();
    if prev.primed {
        // Blocks: emit the newest few applied since the previous tick.
        if obs.tip_height > prev.tip_height {
            // Reorg-with-advance: if the committed tail still covers our
            // previous tip height but shows a DIFFERENT id there, the old
            // tip was replaced on the way up — surface the reorg before its
            // replacement blocks. (Deeper reorgs than the 32-block tail
            // can't be distinguished from plain advances and are reported
            // as blockApplied only — documented at the API level.)
            if !prev.tip_id.is_empty() {
                if let Some((_, id, ..)) = obs.recent.iter().find(|(h, ..)| *h == prev.tip_height) {
                    if *id != prev.tip_id {
                        let dropped_header_ids = dropped_header_ids(prev, obs.recent);
                        let depth = dropped_header_ids.len() as u32;
                        let orphans_truncated = dropped_header_ids.len() >= RECENT_BLOCKS_CAP;
                        reorgs.push(super::reorg_history::ReorgRecord {
                            unix_ms: obs.unix_ms,
                            height: prev.tip_height,
                            header_id: id.clone(),
                            depth,
                            dropped_header_ids: dropped_header_ids.clone(),
                            orphans_truncated,
                        });
                        ring.push(
                            obs.unix_ms,
                            FeedEventKind::Reorg {
                                height: prev.tip_height,
                                header_id: id.clone(),
                                depth,
                                dropped_header_ids,
                            },
                        );
                    }
                }
            }
            let advance = (obs.tip_height - prev.tip_height) as usize;
            let mut newly: Vec<_> = obs
                .recent
                .iter()
                .filter(|(h, ..)| *h > prev.tip_height && *h <= obs.tip_height)
                .collect();
            newly.sort_by_key(|(h, ..)| *h); // oldest first for feed order
            let skip = newly
                .len()
                .saturating_sub(MAX_BLOCK_EVENTS_PER_TICK.min(advance));
            for (h, id, txs, size) in newly.into_iter().skip(skip) {
                ring.push(
                    obs.unix_ms,
                    FeedEventKind::BlockApplied {
                        height: *h,
                        header_id: id.clone(),
                        txs: *txs,
                        size_bytes: *size,
                    },
                );
            }
        } else if !obs.tip_id.is_empty() && obs.tip_id != prev.tip_id {
            // Same-or-lower height with a different tip id = reorg.
            let dropped_header_ids = dropped_header_ids(prev, obs.recent);
            let depth = dropped_header_ids.len() as u32;
            let orphans_truncated = dropped_header_ids.len() >= RECENT_BLOCKS_CAP;
            reorgs.push(super::reorg_history::ReorgRecord {
                unix_ms: obs.unix_ms,
                height: obs.tip_height,
                header_id: obs.tip_id.clone(),
                depth,
                dropped_header_ids: dropped_header_ids.clone(),
                orphans_truncated,
            });
            ring.push(
                obs.unix_ms,
                FeedEventKind::Reorg {
                    height: obs.tip_height,
                    header_id: obs.tip_id.clone(),
                    depth,
                    dropped_header_ids,
                },
            );
        }

        // Peer set diff, bounded per tick. Sorted before capping so WHICH
        // events survive a churn burst is deterministic (lowest addresses),
        // not hash-order luck; the overflow is dropped, not deferred — the
        // feed is a glanceable, not an audit log.
        let now: std::collections::HashSet<String> = obs.peers.iter().cloned().collect();
        let mut connected: Vec<&String> = now.difference(&prev.peers).collect();
        connected.sort();
        for addr in connected.into_iter().take(MAX_PEER_EVENTS_PER_TICK) {
            ring.push(
                obs.unix_ms,
                FeedEventKind::PeerConnected { addr: addr.clone() },
            );
        }
        let mut dropped: Vec<&String> = prev.peers.difference(&now).collect();
        dropped.sort();
        for addr in dropped.into_iter().take(MAX_PEER_EVENTS_PER_TICK) {
            ring.push(
                obs.unix_ms,
                FeedEventKind::PeerDisconnected { addr: addr.clone() },
            );
        }
        prev.peers = now;

        // Indexer status transition (skips the disabled=None case entirely).
        if let Some((status, detail)) = &obs.indexer_status {
            if prev.indexer_status.as_deref() != Some(status.as_str()) {
                ring.push(
                    obs.unix_ms,
                    FeedEventKind::IndexerStatus {
                        status: status.clone(),
                        detail: detail.clone(),
                    },
                );
                prev.indexer_status = Some(status.clone());
            }
        }
    } else {
        prev.primed = true;
        prev.peers = obs.peers.iter().cloned().collect();
        prev.indexer_status = obs.indexer_status.as_ref().map(|(s, _)| s.clone());
    }
    prev.tip_height = obs.tip_height;
    prev.recent = recent_tail(obs.recent);
    if !obs.tip_id.is_empty() {
        prev.tip_id = obs.tip_id;
    }
    reorgs
}

/// Bounded FIFO event ring.
pub(crate) struct EventFeedRing {
    events: VecDeque<FeedEvent>,
    next_seq: u64,
}

impl EventFeedRing {
    /// Retention bound. 512 events comfortably covers hours of normal
    /// operation (a block + a little peer churn per two minutes) while
    /// keeping worst-case memory trivial.
    pub(crate) const CAP: usize = 512;

    pub(crate) fn new() -> Self {
        Self {
            events: VecDeque::new(),
            next_seq: 1,
        }
    }

    /// Append an event. At [`Self::CAP`], prefer evicting a non-`reorg`
    /// event so up to [`Self::PIN_REORGS`] recent reorgs survive peer-churn
    /// floods. If the ring is all reorgs (or already over the pin), fall
    /// back to plain FIFO.
    pub(crate) fn push(&mut self, unix_ms: u64, kind: FeedEventKind) {
        if self.events.len() == Self::CAP {
            self.evict_one_for_capacity();
        }
        self.events.push_back(FeedEvent {
            seq: self.next_seq,
            unix_ms,
            kind,
        });
        self.next_seq += 1;
    }

    /// Prefer dropping the oldest non-reorg; otherwise FIFO.
    fn evict_one_for_capacity(&mut self) {
        let reorg_count = self
            .events
            .iter()
            .filter(|e| matches!(e.kind, FeedEventKind::Reorg { .. }))
            .count();
        if reorg_count <= Self::PIN_REORGS {
            if let Some(idx) = self
                .events
                .iter()
                .position(|e| !matches!(e.kind, FeedEventKind::Reorg { .. }))
            {
                self.events.remove(idx);
                return;
            }
        }
        self.events.pop_front();
    }

    /// How many `reorg` events to protect from peer-churn eviction.
    pub(crate) const PIN_REORGS: usize = 16;

    /// Latest `n` events, oldest→newest, for snapshot projection.
    pub(crate) fn latest(&self, n: usize) -> Vec<FeedEvent> {
        let skip = self.events.len().saturating_sub(n);
        self.events.iter().skip(skip).cloned().collect()
    }

    /// Highest sequence number handed out (0 = nothing yet).
    pub(crate) fn latest_seq(&self) -> u64 {
        self.next_seq - 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_n(ring: &mut EventFeedRing, n: usize) {
        for i in 0..n {
            ring.push(
                i as u64,
                FeedEventKind::PeerConnected {
                    addr: format!("10.0.0.{i}:9030"),
                },
            );
        }
    }

    /// Sequences are monotonic from 1 and survive eviction.
    #[test]
    fn seq_is_monotonic_across_eviction() {
        let mut ring = EventFeedRing::new();
        push_n(&mut ring, EventFeedRing::CAP + 10);
        assert_eq!(ring.latest_seq(), (EventFeedRing::CAP + 10) as u64);
        let latest = ring.latest(EventFeedRing::CAP + 100);
        assert_eq!(latest.len(), EventFeedRing::CAP, "bounded at CAP");
        assert_eq!(latest.first().unwrap().seq, 11, "oldest 10 evicted FIFO");
        assert_eq!(latest.last().unwrap().seq, (EventFeedRing::CAP + 10) as u64);
    }

    /// Peer churn must not wipe a pinned reorg from the coarse ring.
    #[test]
    fn peer_flood_preserves_pinned_reorg() {
        let mut ring = EventFeedRing::new();
        ring.push(
            1,
            FeedEventKind::Reorg {
                height: 100,
                header_id: "new".into(),
                depth: 1,
                dropped_header_ids: vec!["old".into()],
            },
        );
        push_n(&mut ring, EventFeedRing::CAP); // fill + force eviction
        let reorgs: Vec<_> = ring
            .latest(EventFeedRing::CAP)
            .into_iter()
            .filter(|e| matches!(e.kind, FeedEventKind::Reorg { .. }))
            .collect();
        assert_eq!(reorgs.len(), 1, "pinned reorg must survive peer flood");
        assert_eq!(reorgs[0].seq, 1);
    }

    /// `latest(n)` returns the newest n, oldest first.
    #[test]
    fn latest_returns_newest_in_order() {
        let mut ring = EventFeedRing::new();
        push_n(&mut ring, 5);
        let l = ring.latest(3);
        assert_eq!(l.iter().map(|e| e.seq).collect::<Vec<_>>(), vec![3, 4, 5]);
    }

    /// Empty ring: latest_seq 0, latest() empty.
    #[test]
    fn empty_ring_is_calm() {
        let ring = EventFeedRing::new();
        assert_eq!(ring.latest_seq(), 0);
        assert!(ring.latest(10).is_empty());
    }

    // ---- derive_events (the differ) ----

    fn obs<'a>(
        tip: (u32, &str),
        recent: &'a [(u32, String, u32, u64)],
        peers: &[&str],
        indexer: Option<(&str, Option<&str>)>,
    ) -> FeedObservation<'a> {
        FeedObservation {
            unix_ms: 1_000,
            tip_height: tip.0,
            tip_id: tip.1.to_string(),
            recent,
            peers: peers.iter().map(|s| s.to_string()).collect(),
            indexer_status: indexer.map(|(s, d)| (s.to_string(), d.map(|x| x.to_string()))),
        }
    }

    fn blk(h: u32, id: &str) -> (u32, String, u32, u64) {
        (h, id.to_string(), 1, 1_000)
    }

    fn kinds(ring: &EventFeedRing) -> Vec<String> {
        ring.latest(usize::MAX)
            .into_iter()
            .map(|e| match e.kind {
                FeedEventKind::BlockApplied { height, .. } => format!("block:{height}"),
                FeedEventKind::Reorg { height, .. } => format!("reorg:{height}"),
                FeedEventKind::PeerConnected { addr } => format!("peer+:{addr}"),
                FeedEventKind::PeerDisconnected { addr } => format!("peer-:{addr}"),
                FeedEventKind::IndexerStatus { status, .. } => format!("index:{status}"),
            })
            .collect()
    }

    /// The first tick primes the differ — a standing tip, a full peer set,
    /// and a live indexer must NOT fabricate events at boot.
    #[test]
    fn first_tick_primes_without_events() {
        let mut ring = EventFeedRing::new();
        let mut prev = FeedPrev::default();
        let recent = [blk(100, "aa")];
        derive_events(
            &mut ring,
            &mut prev,
            obs(
                (100, "aa"),
                &recent,
                &["1.1.1.1:1"],
                Some(("caughtUp", None)),
            ),
        );
        assert!(kinds(&ring).is_empty());
        assert_eq!(prev.tip_height, 100);
        assert!(prev.primed);
    }

    /// A repeated identical observation emits nothing (idempotent tick).
    #[test]
    fn identical_tick_emits_nothing() {
        let mut ring = EventFeedRing::new();
        let mut prev = FeedPrev::default();
        let recent = [blk(100, "aa")];
        for _ in 0..3 {
            derive_events(
                &mut ring,
                &mut prev,
                obs((100, "aa"), &recent, &["1.1.1.1:1"], None),
            );
        }
        assert!(kinds(&ring).is_empty());
    }

    /// Tip advance emits the new blocks oldest-first, capped at the newest
    /// MAX_BLOCK_EVENTS_PER_TICK when the advance is larger.
    #[test]
    fn block_advance_emits_capped_newest() {
        let mut ring = EventFeedRing::new();
        let mut prev = FeedPrev::default();
        let r0 = [blk(100, "aa")];
        derive_events(&mut ring, &mut prev, obs((100, "aa"), &r0, &[], None));
        // advance by 6 — only the newest 4 emit, oldest-first
        let r1: Vec<_> = (101..=106).map(|h| blk(h, &format!("b{h}"))).collect();
        derive_events(&mut ring, &mut prev, obs((106, "b106"), &r1, &[], None));
        assert_eq!(
            kinds(&ring),
            vec!["block:103", "block:104", "block:105", "block:106"]
        );
        assert_eq!(prev.tip_height, 106);
    }

    /// Same-height tip-id change = reorg.
    #[test]
    fn same_height_reorg_emits() {
        let mut ring = EventFeedRing::new();
        let mut prev = FeedPrev::default();
        let r0 = [blk(100, "aa")];
        derive_events(&mut ring, &mut prev, obs((100, "aa"), &r0, &[], None));
        let r1 = [blk(100, "bb")];
        derive_events(&mut ring, &mut prev, obs((100, "bb"), &r1, &[], None));
        assert_eq!(kinds(&ring), vec!["reorg:100"]);
        assert_eq!(prev.tip_id, "bb");
    }

    #[test]
    fn reorg_same_height_lists_replaced_tip_as_dropped() {
        let mut ring = EventFeedRing::new();
        let mut prev = FeedPrev::default();
        let r0 = [blk(10, "A"), blk(9, "X")];
        derive_events(&mut ring, &mut prev, obs((10, "A"), &r0, &[], None));

        let r1 = [blk(10, "B"), blk(9, "X")];
        derive_events(&mut ring, &mut prev, obs((10, "B"), &r1, &[], None));

        let events = ring.latest(usize::MAX);
        assert_eq!(events.len(), 1);
        match &events[0].kind {
            FeedEventKind::Reorg {
                height,
                header_id,
                depth,
                dropped_header_ids,
            } => {
                assert_eq!(*height, 10);
                assert_eq!(header_id, "B");
                assert_eq!(*depth, 1);
                assert_eq!(dropped_header_ids.as_slice(), ["A".to_string()]);
            }
            other => panic!("expected reorg, got {other:?}"),
        }
    }

    /// A reorg that ALSO advances the height surfaces as reorg + the
    /// replacement blocks — detectable because the committed tail shows a
    /// different id at our previous tip height.
    #[test]
    fn reorg_with_advance_emits_reorg_then_blocks() {
        let mut ring = EventFeedRing::new();
        let mut prev = FeedPrev::default();
        let r0 = [blk(100, "aa")];
        derive_events(&mut ring, &mut prev, obs((100, "aa"), &r0, &[], None));
        // chain replaced from 100 up: 100' + 101'
        let r1 = [blk(101, "b101"), blk(100, "a-prime")];
        derive_events(&mut ring, &mut prev, obs((101, "b101"), &r1, &[], None));
        assert_eq!(kinds(&ring), vec!["reorg:100", "block:101"]);
    }

    #[test]
    fn reorg_advance_with_replacement_lists_orphans_from_prev_recent() {
        let mut ring = EventFeedRing::new();
        let mut prev = FeedPrev::default();
        let r0 = [blk(10, "A"), blk(9, "P")];
        derive_events(&mut ring, &mut prev, obs((10, "A"), &r0, &[], None));

        let r1 = [blk(11, "C"), blk(10, "B"), blk(9, "P")];
        derive_events(&mut ring, &mut prev, obs((11, "C"), &r1, &[], None));

        let events = ring.latest(usize::MAX);
        assert_eq!(events.len(), 2);
        match &events[0].kind {
            FeedEventKind::Reorg {
                height,
                header_id,
                depth,
                dropped_header_ids,
            } => {
                assert_eq!(*height, 10);
                assert_eq!(header_id, "B");
                assert_eq!(*depth, 1);
                assert_eq!(dropped_header_ids.as_slice(), ["A".to_string()]);
            }
            other => panic!("expected reorg first, got {other:?}"),
        }
        assert_eq!(kinds(&ring), vec!["reorg:10", "block:11"]);
    }

    /// Peer set diffs emit deterministically (sorted) and honor the cap.
    #[test]
    fn peer_diffs_sorted_and_capped() {
        let mut ring = EventFeedRing::new();
        let mut prev = FeedPrev::default();
        derive_events(
            &mut ring,
            &mut prev,
            obs((0, ""), &[], &["b:1", "a:1"], None),
        );
        assert!(kinds(&ring).is_empty(), "prime tick");
        // b:1 drops; c:1 and d:1 join
        derive_events(
            &mut ring,
            &mut prev,
            obs((0, ""), &[], &["a:1", "d:1", "c:1"], None),
        );
        assert_eq!(kinds(&ring), vec!["peer+:c:1", "peer+:d:1", "peer-:b:1"]);
        // a churn burst beyond the cap emits exactly MAX_PEER_EVENTS_PER_TICK
        let many: Vec<String> = (0..40).map(|i| format!("z{i:02}:1")).collect();
        let many_refs: Vec<&str> = many.iter().map(|s| s.as_str()).collect();
        let before = ring.latest_seq();
        derive_events(&mut ring, &mut prev, obs((0, ""), &[], &many_refs, None));
        let emitted = (ring.latest_seq() - before) as usize;
        // 40 connects capped at 16, plus 3 disconnects (a/c/d)
        assert_eq!(emitted, MAX_PEER_EVENTS_PER_TICK + 3);
    }

    /// Indexer transitions emit once per status change, never repeat.
    #[test]
    fn indexer_transition_emits_once() {
        let mut ring = EventFeedRing::new();
        let mut prev = FeedPrev::default();
        derive_events(
            &mut ring,
            &mut prev,
            obs((0, ""), &[], &[], Some(("syncing", None))),
        );
        derive_events(
            &mut ring,
            &mut prev,
            obs((0, ""), &[], &[], Some(("syncing", None))),
        );
        derive_events(
            &mut ring,
            &mut prev,
            obs((0, ""), &[], &[], Some(("caughtUp", None))),
        );
        derive_events(
            &mut ring,
            &mut prev,
            obs((0, ""), &[], &[], Some(("caughtUp", None))),
        );
        assert_eq!(kinds(&ring), vec!["index:caughtUp"]);
    }

    /// Committed-tail lag safety: with the tip fed from the SAME source as
    /// the tail (the call-site contract), a tail that hasn't advanced yet
    /// cannot advance the cursor — the block event emits on the later tick
    /// instead of being lost.
    #[test]
    fn lagging_tail_defers_rather_than_losing_events() {
        let mut ring = EventFeedRing::new();
        let mut prev = FeedPrev::default();
        let r0 = [blk(100, "aa")];
        derive_events(&mut ring, &mut prev, obs((100, "aa"), &r0, &[], None));
        // persist window: committed tail unchanged → observation unchanged
        derive_events(&mut ring, &mut prev, obs((100, "aa"), &r0, &[], None));
        assert!(kinds(&ring).is_empty());
        // commit lands: tail (and same-source tip) advance together
        let r1 = [blk(101, "bb"), blk(100, "aa")];
        derive_events(&mut ring, &mut prev, obs((101, "bb"), &r1, &[], None));
        assert_eq!(kinds(&ring), vec!["block:101"]);
    }
}
