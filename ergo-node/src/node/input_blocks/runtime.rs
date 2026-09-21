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

    /// Count for one reason name; `0` for a reason that never fired.
    pub(in crate::node) fn get(&self, name: &str) -> u64 {
        self.counts.get(name).copied().unwrap_or(0)
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
    pub(in crate::node) config: InputBlocksConfig,
    started: Instant,
    pub(in crate::node) counters: DropCounters,
}

impl InputBlocksRuntime {
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
            config: config.clone(),
            started: now,
            counters: DropCounters::default(),
        }
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
    }

    pub(in crate::node) fn processor(&self) -> &Processor {
        &self.processor
    }

    pub(in crate::node) fn processor_mut(&mut self) -> &mut Processor {
        &mut self.processor
    }
}
