//! Explicit resource bounds for the input-block processor (spec 7.4).
//!
//! Scala's processor bounds only its Guava transaction cache (1,000,000
//! entries, 2 h expire-after-write) and leaves every other structure —
//! trees, forks, records, the disconnected waitlist, the
//! ordering-announcement map — unbounded. A remote peer decides how many
//! input blocks it announces, so each of those is a memory-growth vector.
//! This port makes every one of them explicit, with a documented
//! overflow behaviour and a test per bound, and reports each overflow as
//! a [`crate::processor::Effect::Dropped`] so the node can alarm on it.
//!
//! The defaults are the spec's; the node overrides them from config.

/// Bounds for every growable structure the processor owns (spec 7.4).
/// Every field is a hard cap: the processor never exceeds it, and the
/// documented overflow action (evict oldest / reject new) is what the
/// corresponding `Dropped` reason reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bounds {
    /// Transaction-cache entries; Scala's Guava `maximumSize(1000000)`.
    /// Overflow evicts the oldest entry
    /// ([`crate::processor::DropReason::CacheEvicted`]).
    pub tx_cache_entries: usize,
    /// Byte cap on the transaction cache — not a Scala bound: Guava's
    /// entry cap alone lets 1M maximal transactions pin an unbounded
    /// number of bytes. Overflow evicts oldest first.
    pub tx_cache_bytes: usize,
    /// Transaction-cache TTL; Scala's `expireAfterWrite(120, MINUTES)`.
    /// Swept on [`crate::processor::Event::Tick`].
    pub tx_cache_ttl_ms: u64,
    /// Disconnected-waitlist announcements (Scala's unbounded
    /// `disconnectedWaitlist`). Overflow drops the oldest.
    pub waitlist_entries: usize,
    /// Competing forks retained per ordering block. Overflow rejects the
    /// new fork — this is the cap the "exponential fork multiplication"
    /// corpus cases assert.
    pub forks_per_ordering: usize,
    /// Announcement records per ordering block: 4 × the maximum
    /// subblocks-per-block multiplier (2048), i.e. four times as many
    /// input blocks as an honest ordering block can carry.
    pub records_per_ordering: usize,
    /// Announcement records across every retained tree.
    pub records_total: usize,
    /// Retained per-ordering trees. Only ordering blocks inside the ±2
    /// height window are reachable, so 8 is generous.
    pub trees_total: usize,
    /// Stored ordering-block announcements. Overflow drops the oldest.
    pub ordering_announcements: usize,
    /// Bytes held across every staging slot (delivered-but-unverified
    /// bodies). Overflow drops the oldest slot.
    pub staging_bytes_total: usize,
    /// Outstanding requests issued to one peer. At the cap the processor
    /// issues no further request to that peer and reports
    /// [`crate::processor::DropReason::RequestsFull`].
    ///
    /// A slot is held only while the request is genuinely outstanding: it
    /// is released by the delivery that answers it, or by
    /// `request_timeout_ms` passing on a [`crate::processor::Event::Tick`].
    pub requests_per_peer: usize,
    /// How long an unanswered request keeps holding its
    /// `requests_per_peer` slot. Not a Scala bound: Scala tracks no
    /// outstanding requests at all. Expiry is swept on
    /// [`crate::processor::Event::Tick`], so a peer that never answers
    /// recovers its budget once — and only once — its requests time out.
    pub request_timeout_ms: u64,
    /// Validation jobs remembered after they were issued, so a result
    /// arriving for an abandoned job can still name the block that job
    /// was validating. Only one job is outstanding at a time; the rest
    /// are retired ids kept for telemetry. Oldest evicted first.
    pub retired_jobs: usize,
    /// Candidate bodies tried per announced weak-id position (spec 7.5
    /// item 4). Beyond this the position is treated as ambiguous and the
    /// bodies are requested from the announcer.
    pub candidates_per_position: usize,
    /// Ordered-digest combinations tried across all positions of one
    /// block before giving up and requesting bodies (spec 7.5). A spent
    /// budget is reported as
    /// [`crate::processor::DropReason::DigestBudgetExhausted`] — never as
    /// a digest mismatch, which would blame the bodies for a local limit.
    pub digest_attempts_per_block: usize,
    /// Scala `InputBlocksProcessor.PruningThreshold`: records more than
    /// this many ordering blocks behind the best height are pruned.
    pub prune_threshold: u32,
    /// Scala `OrderingBlockAnnouncementPruningThreshold = PruningThreshold * 3`.
    pub ordering_announcement_prune_threshold: u32,
    /// Scala `applyInputBlock`'s `HeightThreshold`: an announcement more
    /// than this far above the best ordering height resets (prunes) state.
    pub height_reset_threshold: u32,
    /// Staging-slot lifetime; Scala `LocalInputBlockChunksTTL` (10 min).
    /// Swept on [`crate::processor::Event::Tick`].
    pub staging_ttl_ms: u64,
    /// Validation attempts spent on one input block before it is given
    /// up on. Not a Scala bound (Scala never retries at all): spec 7.5's
    /// witness-variant retry can otherwise walk
    /// `candidates_per_position ^ positions` combinations, each a full
    /// block validation, and the set of rejected combinations it
    /// remembers grows with it. At the cap the block is reported
    /// [`crate::processor::DropReason::ValidationBudgetExhausted`] and no
    /// further combination is offered.
    pub validation_retries_per_block: usize,
    /// Deferred application triggers retained while a validation job is
    /// in flight. Not a spec bound — an implementation queue that must
    /// not grow without limit; overflow drops the oldest trigger.
    pub pending_triggers: usize,
}

impl Default for Bounds {
    fn default() -> Self {
        Self {
            tx_cache_entries: 1_000_000,
            tx_cache_bytes: 256 * 1024 * 1024,
            tx_cache_ttl_ms: 2 * 60 * 60 * 1000,
            waitlist_entries: 256,
            forks_per_ordering: 64,
            records_per_ordering: 8192,
            records_total: 3 * 8192,
            trees_total: 8,
            ordering_announcements: 64,
            staging_bytes_total: 64 * 1024 * 1024,
            requests_per_peer: 32,
            request_timeout_ms: 60 * 1000,
            retired_jobs: 64,
            candidates_per_position: 4,
            digest_attempts_per_block: 16,
            prune_threshold: 2,
            ordering_announcement_prune_threshold: 6,
            height_reset_threshold: 2,
            staging_ttl_ms: 10 * 60 * 1000,
            validation_retries_per_block: 8,
            pending_triggers: 1024,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- oracle parity -----

    #[test]
    fn defaults_match_scala_thresholds() {
        let b = Bounds::default();
        // Scala InputBlocksProcessor.scala: PruningThreshold = 2,
        // OrderingBlockAnnouncementPruningThreshold = PruningThreshold * 3,
        // applyInputBlock's HeightThreshold = 2, Guava cache
        // maximumSize(1000000).expireAfterWrite(120, MINUTES).
        assert_eq!(b.prune_threshold, 2);
        assert_eq!(
            b.ordering_announcement_prune_threshold,
            b.prune_threshold * 3
        );
        assert_eq!(b.height_reset_threshold, 2);
        assert_eq!(b.tx_cache_entries, 1_000_000);
        assert_eq!(b.tx_cache_ttl_ms, 120 * 60 * 1000);
    }
}
