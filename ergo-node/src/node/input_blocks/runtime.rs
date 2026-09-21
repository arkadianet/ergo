//! `InputBlocksRuntime` — the node's ownership wrapper around the
//! `ergo-inputblocks` processor (spec 7.x, 9.1-9.2).
//!
//! The processor is deliberately clock-free, peer-type-free and I/O-free:
//! it takes a [`Tick`] and an opaque [`PeerTag`] from the caller. This
//! struct is where those become real: a monotonic `Instant` origin, a
//! bijection between `PeerTag` and the node's `PeerId`, the pool entries
//! an applied input block evicted (so a fork switch can put them back),
//! and the per-`DropReason` counters the operator API publishes.
//!
//! One per node, held as `NodeState::input_blocks` and `None` unless
//! `[input_blocks] enabled` (devnet-only, refused elsewhere at config
//! load). Every call site must be a no-op when it is `None`.

use std::collections::{BTreeMap, HashMap};
use std::time::Instant;

use ergo_inputblocks::announcement::AnnouncementPolicy;
use ergo_inputblocks::processor::{DropReason, Processor};
use ergo_inputblocks::types::{InputBlockId, PeerTag, Tick};
use ergo_mempool::input_blocks::RemovedEntry;
use ergo_p2p::peer::PeerId;

use super::profile::{PhaseReport, Profile};
use crate::config::InputBlocksConfig;

/// Bijection between the node's `PeerId` and the processor's opaque
/// [`PeerTag`]. Tags start at 1: [`PeerTag::LOCAL`] (`0`) is reserved for
/// locally mined blocks and must never name a real peer.
#[derive(Debug, Default)]
pub(in crate::node) struct PeerTagMap {
    next: u64,
    by_peer: HashMap<PeerId, PeerTag>,
    by_tag: HashMap<u64, PeerId>,
}

impl PeerTagMap {
    fn new() -> Self {
        Self {
            next: 1,
            by_peer: HashMap::new(),
            by_tag: HashMap::new(),
        }
    }

    /// The tag for `peer`, minting one on first sight. Stable for the
    /// lifetime of the entry.
    fn tag(&mut self, peer: PeerId) -> PeerTag {
        if let Some(t) = self.by_peer.get(&peer) {
            return *t;
        }
        let tag = PeerTag(self.next);
        self.next = self.next.saturating_add(1);
        self.by_peer.insert(peer, tag);
        self.by_tag.insert(tag.0, peer);
        tag
    }

    fn peer(&self, tag: PeerTag) -> Option<PeerId> {
        if tag == PeerTag::LOCAL {
            return None;
        }
        self.by_tag.get(&tag.0).copied()
    }

    /// Drop a disconnected peer's mapping. The processor keeps its own
    /// per-tag bookkeeping (outstanding requests, announcement records);
    /// an effect naming a forgotten tag simply finds no peer and is
    /// discarded by the executor.
    fn forget(&mut self, peer: &PeerId) {
        if let Some(tag) = self.by_peer.remove(peer) {
            self.by_tag.remove(&tag.0);
        }
    }
}

/// What we are waiting for a peer to send us about one input block.
///
/// A block walks announcement -> weak-id list -> bodies, and every phase
/// re-registers the SAME id with the delivery tracker (which is keyed by
/// id alone). Without the phase, a replayed frame from an earlier phase
/// would acknowledge the CURRENT phase's expectation, and the reply that
/// actually answers it would then look unsolicited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::node) enum ExpectedPhase {
    /// `RequestModifier` -123, answered by code 100.
    Announcement,
    /// `RequestModifier` -122, answered by code 102.
    TransactionIds,
    /// Message 105, answered by code 104.
    Bodies,
    /// `RequestModifier` -121, answered by code 106.
    OrderingAnnouncement,
}

/// Per-[`DropReason`] counters. Keyed by the variant NAME (see
/// [`DropReason::name`]) rather than the value, so payload-carrying
/// variants cannot make the map unbounded.
#[derive(Debug, Default)]
pub(in crate::node) struct DropCounters {
    counts: BTreeMap<&'static str, u64>,
    total: u64,
}

impl DropCounters {
    pub(in crate::node) fn bump(&mut self, reason: &DropReason) {
        *self.counts.entry(reason.name()).or_insert(0) += 1;
        self.total = self.total.saturating_add(1);
    }

    /// Every reason that has fired at least once, name-ordered.
    pub(in crate::node) fn iter(&self) -> impl Iterator<Item = (&'static str, u64)> + '_ {
        self.counts.iter().map(|(k, v)| (*k, *v))
    }

    /// Total drops across every reason.
    pub(in crate::node) fn total(&self) -> u64 {
        self.total
    }
}

/// The node's input-block subsystem: processor + the node-side facts the
/// processor deliberately does not own.
pub(in crate::node) struct InputBlocksRuntime {
    processor: Processor,
    peer_tags: PeerTagMap,
    /// Pool entries an applied input block evicted, keyed by the block
    /// that evicted them, so a fork switch can restore them (spec 7.6 /
    /// §8). Released when the block is rolled back or its ordering block
    /// is superseded.
    pub(in crate::node) retained: HashMap<InputBlockId, Vec<RemovedEntry>>,
    started: Instant,
    pub(in crate::node) counters: DropCounters,
    /// `counters.total()` at the last operator report, so the tick can
    /// log a breakdown only when something new was actually dropped
    /// rather than once a second forever.
    last_drop_report: u64,
    /// The phase each outstanding request is waiting on, and who it was
    /// addressed to. Keyed by modifier id ALONE, mirroring the delivery
    /// tracker: `register_expectation` refuses a second request for an
    /// id already in flight, so at most one phase is outstanding per id
    /// at a time. Pruned on the tick against the tracker, and on peer
    /// disconnect.
    expectations: HashMap<[u8; 32], (PeerId, ExpectedPhase)>,
    /// The ordering tip the processor has been told about. Compared
    /// against the store's own `best_full_block_id` on each tick so the
    /// chain events are driven by the committed state itself, not by a
    /// subsystem that may be switched off.
    pub(in crate::node) last_ordering_tip: Option<[u8; 32]>,
    /// `Processor::revision()` as of the last REST read-slot refresh
    /// (fix-round-1, finding 4). Compared against the live value in
    /// `input_blocks::effects::refresh_read_slot` so a `handle()` call
    /// that mutated state WITHOUT emitting any `Effect` — most notably
    /// TTL-driven body-cache expiry inside `Processor::on_tick` — still
    /// triggers a republish instead of leaving the REST snapshot stale.
    pub(in crate::node) read_slot_revision: u64,
    /// Count of input blocks excluded from a REST read-slot refresh
    /// because one of their transaction bodies failed to encode to the
    /// Scala-compat wire shape (fix-round-1, finding 5). Surfaced on
    /// `ApiStatus.input_blocks.drops` under the synthetic reason name
    /// `SnapshotEncodeFailed` — a node-side bookkeeping counter, NOT an
    /// `ergo_inputblocks::processor::DropReason` variant (the processor
    /// itself never produces this; it is purely a symptom of the
    /// node-side Scala-DTO encoder).
    pub(in crate::node) snapshot_encode_failures: u64,
    /// Per-phase timings of the input-block hot path (task 8b). Always
    /// on: the measurement it exists for is a live-node one, and the
    /// cost is one `leading_zeros` plus an increment per observation.
    pub(in crate::node) profile: Profile,
}

impl InputBlocksRuntime {
    /// Build the runtime. The config is CONSUMED here — bounds and the
    /// field-binding policy go into the processor, and `enabled` was
    /// already read by boot to decide whether to build this at all — so
    /// no copy is retained. (`relay_remote` has no effect at this layer:
    /// the processor emits `RelayAnnouncement` only for locally mined
    /// blocks, so honouring it is a processor-side change. See the task
    /// report.)
    pub(in crate::node) fn new(config: &InputBlocksConfig, now: Instant) -> Self {
        Self {
            processor: Processor::new(
                config.bounds,
                AnnouncementPolicy {
                    strict_field_binding: config.strict_field_binding,
                },
            ),
            peer_tags: PeerTagMap::new(),
            retained: HashMap::new(),
            started: now,
            counters: DropCounters::default(),
            last_drop_report: 0,
            expectations: HashMap::new(),
            last_ordering_tip: None,
            read_slot_revision: 0,
            snapshot_encode_failures: 0,
            profile: Profile::new(now),
        }
    }

    /// The phase table for the interval just ended, when the report
    /// interval has elapsed and anything at all was measured.
    pub(in crate::node) fn take_profile_report(
        &mut self,
        now: Instant,
    ) -> Option<Vec<PhaseReport>> {
        self.profile.report(now)
    }

    /// The processor's clock: milliseconds since this runtime was built.
    /// Monotonic by construction (`Instant`), so TTL and request-timeout
    /// sweeps cannot be walked backwards by a wall-clock adjustment.
    pub(in crate::node) fn tick(&self, now: Instant) -> Tick {
        Tick(now.saturating_duration_since(self.started).as_millis() as u64)
    }

    pub(in crate::node) fn tag(&mut self, peer: PeerId) -> PeerTag {
        self.peer_tags.tag(peer)
    }

    pub(in crate::node) fn peer(&self, tag: PeerTag) -> Option<PeerId> {
        self.peer_tags.peer(tag)
    }

    pub(in crate::node) fn forget_peer(&mut self, peer: &PeerId) {
        self.peer_tags.forget(peer);
        self.expectations.retain(|_, (p, _)| p != peer);
    }

    /// Record that `peer` was asked for `phase` of `id`.
    pub(in crate::node) fn expect(&mut self, peer: PeerId, id: [u8; 32], phase: ExpectedPhase) {
        self.expectations.insert(id, (peer, phase));
    }

    /// Consume the expectation `peer`'s `phase` frame for `id` answers,
    /// reporting whether there was one. A frame from a phase we are not
    /// waiting on — a replayed announcement while bodies are
    /// outstanding — answers nothing and leaves the record intact.
    pub(in crate::node) fn take_expectation(
        &mut self,
        peer: &PeerId,
        id: &[u8; 32],
        phase: ExpectedPhase,
    ) -> bool {
        if self.expectations.get(id) == Some(&(*peer, phase)) {
            self.expectations.remove(id);
            true
        } else {
            false
        }
    }

    /// The ids we currently hold a phase record for.
    pub(in crate::node) fn expected_ids(&self) -> impl Iterator<Item = [u8; 32]> + '_ {
        self.expectations.keys().copied()
    }

    /// Drop expectation records for ids `still_outstanding` says the
    /// delivery tracker no longer holds, so the map stays bounded by
    /// genuinely in-flight requests.
    pub(in crate::node) fn prune_expectations(
        &mut self,
        still_outstanding: impl Fn(&[u8; 32]) -> bool,
    ) {
        self.expectations.retain(|id, _| still_outstanding(id));
    }

    /// The per-reason drop breakdown, but only when it has grown since
    /// the last call — so a periodic caller logs on change, not on a
    /// timer. Returns `(new_drops, breakdown)`.
    pub(in crate::node) fn take_drop_report(&mut self) -> Option<(u64, Vec<(&'static str, u64)>)> {
        let total = self.counters.total();
        if total == self.last_drop_report {
            return None;
        }
        let new_drops = total.saturating_sub(self.last_drop_report);
        self.last_drop_report = total;
        Some((new_drops, self.counters.iter().collect()))
    }

    /// The operator-facing status snapshot published on `ApiStatus.input_blocks`
    /// (Task 6). Read at `publish_snapshot` time, once per `sync_tick`, from
    /// the processor's read side plus the runtime's own drop counters — no
    /// live cross-thread reads, mirroring how the peer store's counters are
    /// snapshot-sourced (see `ApiStatus::storage_errors_peers_total`).
    pub(in crate::node) fn api_status(&self) -> ergo_api::types::ApiInputBlocksStatus {
        // `last_ordering_tip` mirrors `processor.best.ordering_id`: every
        // caller that advances the processor's ordering view (`drive` in
        // `hooks.rs`) sets this field in the same step, immediately before
        // handing the event to `processor_mut().handle(..)`, which is what
        // actually updates `best.ordering_id`. There is no public getter
        // for the processor's private field, so this is the node-side
        // mirror the read side uses instead of adding one.
        let forks = self
            .last_ordering_tip
            .map(|oid| self.processor.forks(&oid) as u32)
            .unwrap_or(0);
        ergo_api::types::ApiInputBlocksStatus {
            best_input_block: self.processor.best_input_chain().first().map(hex::encode),
            forks,
            staged_bytes: self.processor.staged_bytes() as u64,
            waitlist: self.processor.waitlist_len() as u32,
            deferred_triggers: self.processor.deferred_triggers() as u32,
            drops: {
                let mut drops: Vec<ergo_api::types::ApiDropCount> = self
                    .counters
                    .iter()
                    .map(|(reason, count)| ergo_api::types::ApiDropCount {
                        reason: reason.to_string(),
                        count,
                    })
                    .collect();
                // Fix-round-1, finding 5: a node-side counter, not a
                // `DropReason` variant (see the field doc), merged into
                // the same name-ordered breakdown so operators see it
                // alongside the processor's own drops rather than on a
                // separate surface.
                if self.snapshot_encode_failures > 0 {
                    drops.push(ergo_api::types::ApiDropCount {
                        reason: "SnapshotEncodeFailed".to_string(),
                        count: self.snapshot_encode_failures,
                    });
                    drops.sort_by(|a, b| a.reason.cmp(&b.reason));
                }
                drops
            },
        }
    }

    pub(in crate::node) fn processor(&self) -> &Processor {
        &self.processor
    }

    pub(in crate::node) fn processor_mut(&mut self) -> &mut Processor {
        &mut self.processor
    }
}
