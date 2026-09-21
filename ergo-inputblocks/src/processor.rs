//! The single-writer input-block processor: events in, effects out
//! (spec 7.1–7.6).
//!
//! Skeleton only — every event handler is unimplemented. The tests in
//! this module are the contract the implementation must satisfy.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use ergo_ser::input_block::{InputBlockAnnouncement, OrderingBlockAnnouncement};
use ergo_ser::transaction::Transaction;
use ergo_ser::weak_id::WeakId;

use crate::announcement::AnnouncementPolicy;
use crate::bounds::Bounds;
use crate::ordering::{OrderingStore, ReconstructionPlan};
use crate::tree::InputBlocksTree;
use crate::types::{InputBlockId, OrderingId, PeerTag, Tick, TxRef};

/// Identifier of a validation job the processor handed to the node.
pub type JobId = u64;

/// A transaction body the processor holds: its identity, the weak id it
/// answers, its serialized bytes (for byte accounting) and the parsed
/// transaction the node validates.
#[derive(Debug, Clone)]
pub struct Body {
    /// `(tx_id, witness_id)` — witness variants are distinct bodies.
    pub tx_ref: TxRef,
    /// The 6-byte weak id this body answers.
    pub weak_id: WeakId,
    /// Serialized transaction bytes; the byte caps of spec 7.4 count these.
    pub bytes: Arc<[u8]>,
    /// The parsed transaction.
    pub tx: Transaction,
}

/// Events the node feeds the processor (spec 7.1).
#[derive(Debug, Clone)]
pub enum Event {
    /// An announcement that passed the node's cheap dispatch checks.
    AnnouncementAccepted {
        /// The announcement.
        ann: InputBlockAnnouncement,
        /// Who sent it ([`PeerTag::LOCAL`] for locally mined blocks).
        from: PeerTag,
        /// Node-supplied clock.
        now: Tick,
    },
    /// Bodies delivered by a peer (message 104) or resolved locally.
    TransactionsDelivered {
        /// The block the bodies belong to.
        input_block_id: InputBlockId,
        /// The delivered bodies.
        bodies: Vec<Body>,
        /// The delivering peer, if any.
        from: Option<PeerTag>,
        /// Node-supplied clock.
        now: Tick,
    },
    /// Result of a [`Effect::Validate`].
    ValidationResult {
        /// The job this answers.
        job: JobId,
        /// The generation the job was issued in.
        generation: u64,
        /// Total cost on success, a reason string on failure.
        outcome: Result<u64, String>,
    },
    /// An ordering-block announcement (message 106).
    OrderingAnnouncementAccepted {
        /// The announcement.
        ann: OrderingBlockAnnouncement,
        /// Who sent it.
        from: PeerTag,
        /// Node-supplied clock.
        now: Tick,
    },
    /// A full block was committed at a new best height.
    OrderingBlockApplied {
        /// Its header id.
        header_id: OrderingId,
        /// Its height.
        height: u32,
        /// Node-supplied clock.
        now: Tick,
    },
    /// The node switched best full chain.
    OrderingReorg {
        /// New best full block's header id.
        new_best_header_id: OrderingId,
        /// New best full block's height.
        new_best_height: u32,
        /// Node-supplied clock.
        now: Tick,
    },
    /// Time passed; sweep TTLs and decay request counters.
    Tick {
        /// Node-supplied clock.
        now: Tick,
    },
}

/// Effects the node acts on (spec 7.2).
#[derive(Debug, Clone, PartialEq)]
pub enum Effect {
    /// `RequestModifier` for modifier type −123.
    RequestInputBlock {
        /// The input block to download.
        id: InputBlockId,
        /// Peer to ask.
        from: PeerTag,
    },
    /// `RequestModifier` for modifier type −122.
    RequestTransactionIds {
        /// The input block whose weak-id list is missing.
        input_block_id: InputBlockId,
        /// Peer to ask.
        from: PeerTag,
    },
    /// Message 105.
    RequestTransactions {
        /// The input block the bodies belong to.
        input_block_id: InputBlockId,
        /// The unresolved weak ids.
        weak_ids: Vec<WeakId>,
        /// Peer to ask.
        from: PeerTag,
    },
    /// Download an ordering block's header.
    RequestOrderingHeader {
        /// The header to download.
        header_id: OrderingId,
        /// Peer to ask.
        from: PeerTag,
    },
    /// Download an ordering block's transaction section.
    RequestBlockTransactions {
        /// The ordering block.
        header_id: OrderingId,
        /// Peer to ask.
        from: PeerTag,
    },
    /// Validate one input block's transactions against the committed
    /// snapshot plus the bodies named by `previous`.
    Validate {
        /// Job id; echoed back in [`Event::ValidationResult`].
        job: JobId,
        /// Generation the job belongs to.
        generation: u64,
        /// The block being validated.
        input_block_id: InputBlockId,
        /// The block's own bodies, in announced order.
        txs: Vec<TxRef>,
        /// Bodies of the already-processed chain prefix.
        previous: Vec<TxRef>,
    },
    /// The best input chain changed.
    ChainChanged {
        /// The ordering block whose tree changed.
        ordering_id: OrderingId,
        /// Newly applied input blocks, in application order.
        applied: Vec<InputBlockId>,
        /// Input blocks abandoned by a fork switch.
        rolled_back: Vec<InputBlockId>,
    },
    /// Relay a locally generated input block's announcement.
    RelayAnnouncement {
        /// The block to relay.
        id: InputBlockId,
    },
    /// Relay an `Inv` for a stored ordering-block announcement.
    RelayOrderingInv {
        /// The announced ordering block.
        header_id: OrderingId,
    },
    /// Penalize a peer that sent an invalid announcement.
    Penalize {
        /// The offending peer.
        from: PeerTag,
        /// Static reason string for telemetry.
        reason: &'static str,
    },
    /// Try to rebuild a full block from an ordering announcement.
    OrderingReconstruct {
        /// The plan.
        plan: ReconstructionPlan,
    },
    /// Telemetry: something was dropped, and why.
    Dropped {
        /// The id dropped (an input block, ordering block, or body).
        id: [u8; 32],
        /// Why.
        reason: DropReason,
    },
}

/// Why the processor dropped something (spec 7.4's overflow actions plus
/// the parity drops of 2.7/7.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    /// Already in `records` — Scala `applyInputBlock`'s first guard.
    AlreadyKnown,
    /// Outside the actionable height window (Scala: ±2, and only `+1`
    /// is actually applied; `+2` requests the ordering header instead).
    OutsideHeightWindow,
    /// A `ValidationResult` for a superseded generation or job.
    StaleValidation,
    /// A body needed for validation is no longer cached.
    CacheEvicted,
    /// The disconnected waitlist is full; the oldest entry was dropped.
    WaitlistFull,
    /// The per-ordering fork cap is reached; the new fork was rejected.
    ForksFull,
    /// The record cap (per ordering block or total) is reached.
    RecordsFull,
    /// The staging byte cap is reached; the oldest slot was dropped.
    StagingFull,
    /// The per-peer outstanding-request cap is reached; no request issued.
    RequestsFull,
    /// Every witness variant of a staged position failed validation.
    CandidatesExhausted,
    /// No candidate combination reproduced the announced digest.
    DigestMismatch,
    /// Delivered bodies do not match the announced `transactionsDigest`.
    TxDigestMismatch,
    /// Validation failed and the block had no alternative variants.
    ValidationFailed,
    /// `subblocks_per_block` is unavailable: input blocks are not active,
    /// so the announcement is dropped **without** penalising the peer.
    MultiplierUnavailable,
    /// The ordering-announcement store is full; the oldest was dropped.
    OrderingAnnouncementsFull,
    /// Bodies were delivered for a block the processor has no record of.
    /// Not in the spec's list: Scala logs and ignores this case
    /// (`applyInputBlockTransactions`'s `case None`), and the node needs
    /// to see it to spot a peer spraying bodies.
    UnknownBlock,
    /// The node is running in digest (stateless) mode, where input
    /// blocks cannot be validated at all (Scala `processInputBlock`).
    DigestMode,
}

/// The node's view of the best full block, mirrored into the processor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BestBlocks {
    /// The best full block's header id, if any.
    pub ordering_id: Option<OrderingId>,
    /// Its height (`0` when there is none, matching Scala's
    /// `bestBlocks._1.map(_.height).getOrElse(0)`).
    pub ordering_height: u32,
}

/// Per-event inputs the processor cannot own.
pub struct ProcessorCtx<'a> {
    /// Current `subblocks_per_block`; `None` when input blocks are off.
    pub multiplier: Option<i32>,
    /// Expected `nBits` for an announced block's parent, when known.
    pub expected_n_bits: &'a dyn Fn(&[u8; 32]) -> Option<u32>,
    /// Mempool lookup by weak id (spec 7.5 step 1).
    pub mempool_lookup: &'a dyn Fn(&WeakId) -> Vec<Body>,
    /// Whether the node keeps a UTXO set (input blocks need one).
    pub utxo_mode: bool,
    /// The node's current best full-block height.
    pub full_block_height: u32,
    /// Whether the node already has an ordering block's transaction
    /// section (Scala `historyReader.contains(header.transactionsId)`).
    pub block_transactions_known: &'a dyn Fn(&OrderingId) -> bool,
}

/// One announcement record (Scala `inputBlockRecords`).
#[derive(Debug, Clone)]
struct Record {
    ann: InputBlockAnnouncement,
    from: PeerTag,
    height: u32,
    ordering_id: OrderingId,
    prev: Option<InputBlockId>,
}

/// The validation job currently outstanding (spec 7.4: exactly one).
#[derive(Debug, Clone)]
struct InFlight {
    job: JobId,
    generation: u64,
    id: InputBlockId,
    ordering_id: OrderingId,
}

/// The single-writer state machine (spec 7.1–7.6).
pub struct Processor {
    bounds: Bounds,
    policy: AnnouncementPolicy,
    generation: u64,
    next_job: JobId,
    best: BestBlocks,
    trees: indexmap::IndexMap<OrderingId, InputBlocksTree>,
    tree_heights: HashMap<OrderingId, u32>,
    records: indexmap::IndexMap<InputBlockId, Record>,
    tx_refs: HashMap<InputBlockId, Vec<TxRef>>,
    cache: TxCache,
    staging: indexmap::IndexMap<InputBlockId, Staging>,
    waitlist: VecDeque<(InputBlockId, Option<InputBlockId>)>,
    ordering: OrderingStore,
    outstanding: HashMap<PeerTag, usize>,
    in_flight: Option<InFlight>,
    failed: HashSet<(InputBlockId, TxRef)>,
    pending_triggers: VecDeque<(OrderingId, InputBlockId)>,
}

#[derive(Debug, Default)]
struct TxCache {
    entries: indexmap::IndexMap<TxRef, (Body, Tick)>,
    bytes: usize,
}

#[derive(Debug)]
struct Staging {
    weak_ids: Vec<WeakId>,
    candidates: Vec<Vec<Body>>,
    variants: Option<Vec<Vec<TxRef>>>,
    cursor: Vec<usize>,
    bytes: usize,
    created: Tick,
    from: Option<PeerTag>,
}

impl Processor {
    /// A fresh processor with no state.
    pub fn new(_bounds: Bounds, _policy: AnnouncementPolicy) -> Self {
        unimplemented!("task 11 step 3")
    }

    /// The node tells the processor the best full block on every change.
    pub fn set_best_ordering(&mut self, _id: Option<OrderingId>, _height: u32) {
        unimplemented!("task 11 step 3")
    }

    /// The current generation (spec 7.2).
    pub fn generation(&self) -> u64 {
        unimplemented!("task 11 step 3")
    }

    /// Feed one event; returns the effects the node must act on.
    pub fn handle(&mut self, _event: Event, _ctx: &ProcessorCtx<'_>) -> Vec<Effect> {
        unimplemented!("task 11 step 3")
    }

    /// Scala `bestInputBlock()`.
    pub fn best_input_block(&self) -> Option<&InputBlockAnnouncement> {
        unimplemented!("task 11 step 3")
    }

    /// Scala `bestInputBlocksChain()` — tip first.
    pub fn best_input_chain(&self) -> Vec<InputBlockId> {
        unimplemented!("task 11 step 3")
    }

    /// Scala `getInputBlock`.
    pub fn announcement(&self, _id: &InputBlockId) -> Option<&InputBlockAnnouncement> {
        unimplemented!("task 11 step 3")
    }

    /// Scala `getInputBlockTransactionIds`.
    pub fn transaction_refs(&self, _id: &InputBlockId) -> Option<&[TxRef]> {
        unimplemented!("task 11 step 3")
    }

    /// Scala `getInputBlockTransactionWeakIds`.
    pub fn weak_ids(&self, _id: &InputBlockId) -> Option<Vec<WeakId>> {
        unimplemented!("task 11 step 3")
    }

    /// Scala `getInputBlockTransactions` — skips evicted bodies.
    pub fn bodies(&self, _id: &InputBlockId) -> Option<Vec<&Body>> {
        unimplemented!("task 11 step 3")
    }

    /// Scala `getInputBlockTransactions(id, toFilter)`.
    pub fn bodies_by_weak_ids(&self, _id: &InputBlockId, _filter: &[WeakId]) -> Option<Vec<&Body>> {
        unimplemented!("task 11 step 3")
    }

    /// Scala `getOrderingBlockAnnouncement`.
    pub fn ordering_announcement(
        &self,
        _header_id: &OrderingId,
    ) -> Option<&OrderingBlockAnnouncement> {
        unimplemented!("task 11 step 3")
    }

    /// Scala `getCollectedInputBlocksTransactions`.
    pub fn collected_input_txs(&self, _ordering_id: &OrderingId) -> Vec<TxRef> {
        unimplemented!("task 11 step 3")
    }

    /// Number of competing forks retained for `ordering_id`.
    pub fn forks(&self, _ordering_id: &OrderingId) -> usize {
        unimplemented!("task 11 step 3")
    }

    /// Bytes currently held in staging slots (spec 7.4).
    pub fn staged_bytes(&self) -> usize {
        unimplemented!("task 11 step 3")
    }

    /// Scala `disconnectedWaitlist.size`.
    pub fn waitlist_len(&self) -> usize {
        unimplemented!("task 11 step 3")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support as ts;
    use crate::types::Tick;

    // ----- helpers -----

    /// The ordering block every test builds on, and the height the node
    /// reports as its best full block.
    const ORD: OrderingId = [0xAA; 32];
    const FULL: u32 = 10;

    /// Field binding is off (the strict check of spec 6.3 is exercised in
    /// `announcement.rs`); the proofs the helpers build are still real.
    fn policy() -> AnnouncementPolicy {
        AnnouncementPolicy {
            strict_field_binding: false,
        }
    }

    fn processor() -> Processor {
        processor_with(Bounds::default())
    }

    fn processor_with(bounds: Bounds) -> Processor {
        let mut p = Processor::new(bounds, policy());
        p.set_best_ordering(Some(ORD), FULL);
        p
    }

    fn announce(
        p: &mut Processor,
        ctx: &ts::TestCtx,
        ann: &InputBlockAnnouncement,
        from: PeerTag,
    ) -> Vec<Effect> {
        ctx.handle(
            p,
            Event::AnnouncementAccepted {
                ann: ann.clone(),
                from,
                now: Tick(0),
            },
        )
    }

    fn drops(effects: &[Effect]) -> Vec<DropReason> {
        effects
            .iter()
            .filter_map(|e| match e {
                Effect::Dropped { reason, .. } => Some(*reason),
                _ => None,
            })
            .collect()
    }

    fn has_validate(effects: &[Effect]) -> bool {
        effects.iter().any(|e| matches!(e, Effect::Validate { .. }))
    }

    // ----- happy path -----

    #[test]
    fn announcement_at_height_plus_one_with_all_txs_in_mempool_validates_immediately() {
        let mut p = processor();
        let b1 = ts::body(1, 1);
        let b2 = ts::body(2, 1);
        let mut ctx = ts::TestCtx::at(FULL);
        ctx.mempool.add(&b1);
        ctx.mempool.add(&b2);
        let ann = ts::announcement_for(ORD, FULL + 1, 1, None, &[b1.clone(), b2.clone()]);
        let eff = announce(&mut p, &ctx, &ann, ts::PEER);
        let (_, _, id, txs, previous) = ts::one_validate(&eff);
        assert_eq!(id, ts::ann_id(&ann));
        assert_eq!(txs, vec![b1.tx_ref, b2.tx_ref]);
        assert!(previous.is_empty());
    }

    #[test]
    fn announcement_with_missing_weak_ids_requests_bodies_from_announcer() {
        let mut p = processor();
        let b1 = ts::body(1, 1);
        let b2 = ts::body(2, 1);
        let mut ctx = ts::TestCtx::at(FULL);
        ctx.mempool.add(&b1);
        let ann = ts::announcement_for(ORD, FULL + 1, 1, None, &[b1.clone(), b2.clone()]);
        let eff = announce(&mut p, &ctx, &ann, ts::PEER);
        assert!(
            eff.contains(&Effect::RequestTransactions {
                input_block_id: ts::ann_id(&ann),
                weak_ids: vec![b2.weak_id],
                from: ts::PEER,
            }),
            "{eff:?}"
        );
        assert!(!has_validate(&eff));
    }

    #[test]
    fn announcement_without_weak_ids_requests_ids() {
        let mut p = processor();
        let ctx = ts::TestCtx::at(FULL);
        let ann = ts::announcement(ORD, FULL + 1, 1, None);
        let eff = announce(&mut p, &ctx, &ann, ts::PEER);
        assert!(
            eff.contains(&Effect::RequestTransactionIds {
                input_block_id: ts::ann_id(&ann),
                from: ts::PEER,
            }),
            "{eff:?}"
        );
    }

    #[test]
    fn delivered_bodies_complete_staging_and_validate() {
        let mut p = processor();
        let b1 = ts::body(1, 1);
        let b2 = ts::body(2, 1);
        let mut ctx = ts::TestCtx::at(FULL);
        ctx.mempool.add(&b1);
        let ann = ts::announcement_for(ORD, FULL + 1, 1, None, &[b1.clone(), b2.clone()]);
        let id = ts::ann_id(&ann);
        let eff = announce(&mut p, &ctx, &ann, ts::PEER);
        assert!(!has_validate(&eff));
        assert!(p.staged_bytes() > 0, "b1 must be staged, not cached");
        let eff = ctx.handle(
            &mut p,
            Event::TransactionsDelivered {
                input_block_id: id,
                bodies: vec![b2.clone()],
                from: Some(ts::PEER),
                now: Tick(1),
            },
        );
        let (_, _, vid, txs, _) = ts::one_validate(&eff);
        assert_eq!(vid, id);
        assert_eq!(txs, vec![b1.tx_ref, b2.tx_ref]);
        assert_eq!(p.staged_bytes(), 0, "verified bodies move to the cache");
    }

    #[test]
    fn validation_ok_emits_chain_changed_and_updates_best_input_block() {
        let mut p = processor();
        let b1 = ts::body(1, 1);
        let mut ctx = ts::TestCtx::at(FULL);
        ctx.mempool.add(&b1);
        let ann = ts::announcement_for(ORD, FULL + 1, 1, None, &[b1.clone()]);
        let id = ts::ann_id(&ann);
        let eff = announce(&mut p, &ctx, &ann, ts::PEER);
        let out = ts::validate_ok(&mut p, &ctx, &eff, 42);
        assert!(
            out.contains(&Effect::ChainChanged {
                ordering_id: ORD,
                applied: vec![id],
                rolled_back: vec![],
            }),
            "{out:?}"
        );
        assert_eq!(p.best_input_block().map(ts::ann_id), Some(id));
        assert_eq!(p.best_input_chain(), vec![id]);
    }

    #[test]
    fn local_relay_only_for_locally_generated() {
        let ctx = ts::TestCtx::at(FULL);
        let mut p = processor();
        let remote = ts::announcement(ORD, FULL + 1, 1, None);
        let eff = announce(&mut p, &ctx, &remote, ts::PEER);
        assert!(
            !eff.iter()
                .any(|e| matches!(e, Effect::RelayAnnouncement { .. })),
            "remote relay is off (Scala TODO): {eff:?}"
        );

        let mut p = processor();
        let local = ts::announcement(ORD, FULL + 1, 2, None);
        let eff = announce(&mut p, &ctx, &local, PeerTag::LOCAL);
        assert!(
            eff.contains(&Effect::RelayAnnouncement {
                id: ts::ann_id(&local)
            }),
            "{eff:?}"
        );
    }

    #[test]
    fn child_with_unknown_parent_is_waitlisted_and_parent_requested() {
        let mut p = processor();
        let ctx = ts::TestCtx::at(FULL);
        let parent = ts::announcement(ORD, FULL + 1, 1, None);
        let parent_id = ts::ann_id(&parent);
        let child = ts::announcement(ORD, FULL + 1, 2, Some(parent_id));
        let child_id = ts::ann_id(&child);

        let eff = announce(&mut p, &ctx, &child, ts::PEER);
        assert!(
            eff.contains(&Effect::RequestInputBlock {
                id: parent_id,
                from: ts::PEER
            }),
            "{eff:?}"
        );
        assert_eq!(p.waitlist_len(), 1);

        announce(&mut p, &ctx, &parent, ts::PEER);
        assert_eq!(p.waitlist_len(), 0, "parent arrival reconnects the child");

        // Deliver both bodies (empty transaction sets) and drive the
        // resulting validations: the chain must reach the child.
        let eff = ctx.handle(
            &mut p,
            Event::TransactionsDelivered {
                input_block_id: child_id,
                bodies: Vec::new(),
                from: Some(ts::PEER),
                now: Tick(1),
            },
        );
        assert!(!has_validate(&eff), "child cannot be applied before parent");
        let eff = ctx.handle(
            &mut p,
            Event::TransactionsDelivered {
                input_block_id: parent_id,
                bodies: Vec::new(),
                from: Some(ts::PEER),
                now: Tick(2),
            },
        );
        let (_, _, vid, _, _) = ts::one_validate(&eff);
        assert_eq!(vid, parent_id);
        let out = ts::validate_ok(&mut p, &ctx, &eff, 1);
        let (_, _, vid, _, previous) = ts::one_validate(&out);
        assert_eq!(vid, child_id, "the continuation validates the child");
        assert!(previous.is_empty(), "the parent committed no transactions");
        let out = ts::validate_ok(&mut p, &ctx, &out, 1);
        assert!(!has_validate(&out));
        assert_eq!(p.best_input_chain(), vec![child_id, parent_id]);
    }

    #[test]
    fn announcement_at_height_plus_two_requests_ordering_header() {
        let mut p = processor();
        let ctx = ts::TestCtx::at(FULL);
        let ann = ts::announcement(ORD, FULL + 2, 1, None);
        let eff = announce(&mut p, &ctx, &ann, ts::PEER);
        assert!(
            eff.contains(&Effect::RequestOrderingHeader {
                header_id: ORD,
                from: ts::PEER
            }),
            "{eff:?}"
        );
        assert!(p.announcement(&ts::ann_id(&ann)).is_none());
    }

    #[test]
    fn ordering_applied_bumps_generation_and_clears_best() {
        let mut p = processor();
        let b1 = ts::body(1, 1);
        let mut ctx = ts::TestCtx::at(FULL);
        ctx.mempool.add(&b1);
        let ann = ts::announcement_for(ORD, FULL + 1, 1, None, &[b1.clone()]);
        let eff = announce(&mut p, &ctx, &ann, ts::PEER);
        ts::validate_ok(&mut p, &ctx, &eff, 1);
        assert!(p.best_input_block().is_some());

        let before = p.generation();
        let next: OrderingId = [0xBB; 32];
        let out = ctx.handle(
            &mut p,
            Event::OrderingBlockApplied {
                header_id: next,
                height: FULL + 1,
                now: Tick(5),
            },
        );
        assert!(p.generation() > before);
        assert!(p.best_input_block().is_none());
        assert!(
            out.contains(&Effect::ChainChanged {
                ordering_id: next,
                applied: vec![],
                rolled_back: vec![],
            }),
            "{out:?}"
        );
    }

    #[test]
    fn ordering_announcement_with_stored_prev_input_block_emits_reconstruct() {
        let mut p = processor();
        let b1 = ts::body(1, 1);
        let mut ctx = ts::TestCtx::at(FULL);
        ctx.mempool.add(&b1);
        let ib = ts::announcement_for(ORD, FULL + 1, 1, None, &[b1.clone()]);
        let ib_id = ts::ann_id(&ib);
        let eff = announce(&mut p, &ctx, &ib, ts::PEER);
        ts::validate_ok(&mut p, &ctx, &eff, 1);

        let oa = ts::ordering_announcement(
            ORD,
            FULL + 1,
            9,
            vec![(
                ergo_ser::input_block::PREV_INPUT_BLOCK_ID_KEY,
                ib_id.to_vec(),
            )],
        );
        let oa_id = ts::header_id(&oa.header);
        let out = ctx.handle(
            &mut p,
            Event::OrderingAnnouncementAccepted {
                ann: oa.clone(),
                from: ts::PEER,
                now: Tick(6),
            },
        );
        assert!(
            out.contains(&Effect::RelayOrderingInv { header_id: oa_id }),
            "{out:?}"
        );
        let plan = out
            .iter()
            .find_map(|e| match e {
                Effect::OrderingReconstruct { plan } => Some(plan.clone()),
                _ => None,
            })
            .unwrap_or_else(|| panic!("no OrderingReconstruct in {out:?}"));
        assert_eq!(plan.prev_input_block_id, Some(ib_id));
        // Finding F5, preserved: Scala keys the collected input-chain
        // transactions by the *announced* header's own id, not by the
        // ordering block the input chain actually extends, so the plan
        // carries nothing even though the chain has a transaction.
        assert_eq!(plan.input_chain_txs, p.collected_input_txs(&oa_id));
        assert!(plan.input_chain_txs.is_empty());
        assert_eq!(p.collected_input_txs(&ORD), vec![b1.tx_ref]);
    }

    #[test]
    fn ordering_announcement_without_stored_prev_requests_block_transactions() {
        let mut p = processor();
        let ctx = ts::TestCtx::at(FULL);
        let oa = ts::ordering_announcement(
            ORD,
            FULL + 1,
            9,
            vec![(
                ergo_ser::input_block::PREV_INPUT_BLOCK_ID_KEY,
                [0x5C; 32].to_vec(),
            )],
        );
        let oa_id = ts::header_id(&oa.header);
        let out = ctx.handle(
            &mut p,
            Event::OrderingAnnouncementAccepted {
                ann: oa,
                from: ts::PEER,
                now: Tick(6),
            },
        );
        assert!(
            out.contains(&Effect::RequestBlockTransactions {
                header_id: oa_id,
                from: ts::PEER
            }),
            "{out:?}"
        );
        assert!(p.ordering_announcement(&oa_id).is_some());
    }

    // ----- error paths -----

    #[test]
    fn announcement_outside_height_window_dropped() {
        let ctx = ts::TestCtx::at(FULL);
        for height in [FULL + 3, FULL - 3] {
            let mut p = processor();
            let ann = ts::announcement(ORD, height, 1, None);
            let eff = announce(&mut p, &ctx, &ann, ts::PEER);
            assert_eq!(
                drops(&eff),
                vec![DropReason::OutsideHeightWindow],
                "height {height}: {eff:?}"
            );
            assert!(p.announcement(&ts::ann_id(&ann)).is_none());
        }
    }

    #[test]
    fn announcement_in_digest_mode_dropped() {
        let mut p = processor();
        let mut ctx = ts::TestCtx::at(FULL);
        ctx.utxo_mode = false;
        let ann = ts::announcement(ORD, FULL + 1, 1, None);
        let eff = announce(&mut p, &ctx, &ann, ts::PEER);
        assert_eq!(drops(&eff), vec![DropReason::DigestMode]);
        assert!(p.announcement(&ts::ann_id(&ann)).is_none());
    }

    #[test]
    fn duplicate_announcement_dropped() {
        let mut p = processor();
        let b1 = ts::body(1, 1);
        let mut ctx = ts::TestCtx::at(FULL);
        ctx.mempool.add(&b1);
        let ann = ts::announcement_for(ORD, FULL + 1, 1, None, &[b1.clone()]);
        let first = announce(&mut p, &ctx, &ann, ts::PEER);
        assert!(has_validate(&first));
        let second = announce(&mut p, &ctx, &ann, ts::PEER);
        assert_eq!(drops(&second), vec![DropReason::AlreadyKnown]);
        assert!(!has_validate(&second));
    }

    #[test]
    fn invalid_pow_penalizes_peer() {
        let mut p = processor();
        let mut ctx = ts::TestCtx::at(FULL);
        ctx.multiplier = Some(1);
        let mut ann = ts::announcement(ORD, FULL + 1, 1, None);
        ann.header.n_bits = ts::impossible_n_bits();
        let eff = announce(&mut p, &ctx, &ann, ts::PEER);
        assert!(
            eff.iter().any(|e| matches!(e, Effect::Penalize { .. })),
            "{eff:?}"
        );
        assert!(p.announcement(&ts::ann_id(&ann)).is_none());
    }

    #[test]
    fn multiplier_unavailable_drops_without_penalty() {
        let mut p = processor();
        let mut ctx = ts::TestCtx::at(FULL);
        ctx.multiplier = None;
        let ann = ts::announcement(ORD, FULL + 1, 1, None);
        let eff = announce(&mut p, &ctx, &ann, ts::PEER);
        assert_eq!(drops(&eff), vec![DropReason::MultiplierUnavailable]);
        assert!(!eff.iter().any(|e| matches!(e, Effect::Penalize { .. })));
    }

    #[test]
    fn stale_validation_result_dropped() {
        let mut p = processor();
        let b1 = ts::body(1, 1);
        let mut ctx = ts::TestCtx::at(FULL);
        ctx.mempool.add(&b1);
        let ann = ts::announcement_for(ORD, FULL + 1, 1, None, &[b1.clone()]);
        let eff = announce(&mut p, &ctx, &ann, ts::PEER);
        let (job, generation, _, _, _) = ts::one_validate(&eff);
        ctx.handle(
            &mut p,
            Event::OrderingBlockApplied {
                header_id: [0xBB; 32],
                height: FULL + 1,
                now: Tick(3),
            },
        );
        let out = ctx.handle(
            &mut p,
            Event::ValidationResult {
                job,
                generation,
                outcome: Ok(1),
            },
        );
        assert_eq!(drops(&out), vec![DropReason::StaleValidation]);
        assert!(!out
            .iter()
            .any(|e| matches!(e, Effect::ChainChanged { .. })));
    }

    #[test]
    fn tx_digest_mismatch_keeps_bodies_out_of_cache() {
        let mut p = processor();
        let b1 = ts::body(1, 1);
        let wrong = ts::body(9, 9);
        let mut ctx = ts::TestCtx::at(FULL);
        // The announcement commits to b1 but announces the weak id of a
        // body the mempool answers with something else entirely.
        let ann = ts::announcement_with(
            ORD,
            FULL + 1,
            1,
            None,
            ts::tx_digest(&[b1.tx_ref.tx_id]),
            Some(vec![wrong.weak_id]),
        );
        ctx.mempool.add(&wrong);
        let id = ts::ann_id(&ann);
        let eff = announce(&mut p, &ctx, &ann, ts::PEER);
        assert_eq!(drops(&eff), vec![DropReason::TxDigestMismatch], "{eff:?}");
        assert!(!has_validate(&eff));
        assert!(p.bodies(&id).is_none());
    }

    #[test]
    fn weak_id_collision_prefers_candidate_matching_digest() {
        let mut p = processor();
        let real = ts::body(1, 1);
        let decoy = ts::body(9, 1);
        let mut ctx = ts::TestCtx::at(FULL);
        ctx.mempool.add_under(real.weak_id, &decoy);
        ctx.mempool.add_under(real.weak_id, &real);
        let ann = ts::announcement_for(ORD, FULL + 1, 1, None, &[real.clone()]);
        let eff = announce(&mut p, &ctx, &ann, ts::PEER);
        let (_, _, _, txs, _) = ts::one_validate(&eff);
        assert_eq!(txs, vec![real.tx_ref]);
    }

    #[test]
    fn weak_id_ambiguity_beyond_candidates_requests_bodies() {
        let mut p = processor();
        let real = ts::body(1, 1);
        let mut ctx = ts::TestCtx::at(FULL);
        for seed in 20..25u8 {
            ctx.mempool.add_under(real.weak_id, &ts::body(seed, 1));
        }
        let ann = ts::announcement_for(ORD, FULL + 1, 1, None, &[real.clone()]);
        let eff = announce(&mut p, &ctx, &ann, ts::PEER);
        assert!(
            eff.contains(&Effect::RequestTransactions {
                input_block_id: ts::ann_id(&ann),
                weak_ids: vec![real.weak_id],
                from: ts::PEER,
            }),
            "{eff:?}"
        );
        assert!(!has_validate(&eff));
    }

    #[test]
    fn witness_variant_retry_after_validation_failure() {
        let mut p = processor();
        // Two witness variants of one transaction: same tx_id, different
        // witness_id, so both satisfy the announced digest.
        let v1 = ts::body(1, 1);
        let v2 = ts::body(1, 2);
        assert_eq!(v1.tx_ref.tx_id, v2.tx_ref.tx_id);
        assert_ne!(v1.tx_ref.witness_id, v2.tx_ref.witness_id);
        let mut ctx = ts::TestCtx::at(FULL);
        ctx.mempool.add_under(v1.weak_id, &v1);
        ctx.mempool.add_under(v1.weak_id, &v2);
        let ann = ts::announcement_for(ORD, FULL + 1, 1, None, &[v1.clone()]);
        let eff = announce(&mut p, &ctx, &ann, ts::PEER);
        let (_, _, _, txs, _) = ts::one_validate(&eff);
        assert_eq!(txs, vec![v1.tx_ref]);

        let retry = ts::validate_err(&mut p, &ctx, &eff);
        let (_, _, _, txs, _) = ts::one_validate(&retry);
        assert_eq!(txs, vec![v2.tx_ref], "the other witness variant is tried");

        let done = ts::validate_err(&mut p, &ctx, &retry);
        assert_eq!(drops(&done), vec![DropReason::CandidatesExhausted]);
        assert!(!has_validate(&done));
        assert!(p.best_input_block().is_none());
    }

    #[test]
    fn validation_failure_marks_block_and_chain_does_not_progress() {
        let mut p = processor();
        let b1 = ts::body(1, 1);
        let mut ctx = ts::TestCtx::at(FULL);
        ctx.mempool.add(&b1);
        let ann = ts::announcement_for(ORD, FULL + 1, 1, None, &[b1.clone()]);
        let eff = announce(&mut p, &ctx, &ann, ts::PEER);
        let out = ts::validate_err(&mut p, &ctx, &eff);
        assert_eq!(drops(&out), vec![DropReason::ValidationFailed]);
        assert!(!out
            .iter()
            .any(|e| matches!(e, Effect::ChainChanged { .. })));
        assert!(p.best_input_block().is_none());
        assert!(p.best_input_chain().is_empty());
    }

    #[test]
    fn evicted_previous_body_blocks_progress_with_cache_evicted() {
        let bounds = Bounds {
            tx_cache_entries: 1,
            ..Bounds::default()
        };
        let mut p = processor_with(bounds);
        let b1 = ts::body(1, 1);
        let b2 = ts::body(2, 1);
        let mut ctx = ts::TestCtx::at(FULL);
        ctx.mempool.add(&b1);
        ctx.mempool.add(&b2);
        let a1 = ts::announcement_for(ORD, FULL + 1, 1, None, &[b1.clone()]);
        let id1 = ts::ann_id(&a1);
        let eff = announce(&mut p, &ctx, &a1, ts::PEER);
        ts::validate_ok(&mut p, &ctx, &eff, 1);

        let a2 = ts::announcement_for(ORD, FULL + 1, 2, Some(id1), &[b2.clone()]);
        let eff = announce(&mut p, &ctx, &a2, ts::PEER);
        assert!(!has_validate(&eff), "{eff:?}");
        assert_eq!(drops(&eff), vec![DropReason::CacheEvicted]);
    }

    #[test]
    fn waitlist_full_drops_oldest() {
        let bounds = Bounds {
            waitlist_entries: 1,
            ..Bounds::default()
        };
        let mut p = processor_with(bounds);
        let ctx = ts::TestCtx::at(FULL);
        let orphan1 = ts::announcement(ORD, FULL + 1, 1, Some([0x01; 32]));
        let orphan2 = ts::announcement(ORD, FULL + 1, 2, Some([0x02; 32]));
        announce(&mut p, &ctx, &orphan1, ts::PEER);
        let eff = announce(&mut p, &ctx, &orphan2, ts::PEER);
        assert_eq!(drops(&eff), vec![DropReason::WaitlistFull]);
        assert_eq!(p.waitlist_len(), 1);
    }

    #[test]
    fn forks_full_rejects_new_fork() {
        let bounds = Bounds {
            forks_per_ordering: 1,
            ..Bounds::default()
        };
        let mut p = processor_with(bounds);
        let ctx = ts::TestCtx::at(FULL);
        let a1 = ts::announcement(ORD, FULL + 1, 1, None);
        let id1 = ts::ann_id(&a1);
        announce(&mut p, &ctx, &a1, ts::PEER);
        let a2 = ts::announcement(ORD, FULL + 1, 2, Some(id1));
        announce(&mut p, &ctx, &a2, ts::PEER);
        assert_eq!(p.forks(&ORD), 1, "a linear extension is not a new fork");
        let a3 = ts::announcement(ORD, FULL + 1, 3, Some(id1));
        let eff = announce(&mut p, &ctx, &a3, ts::PEER);
        assert_eq!(drops(&eff), vec![DropReason::ForksFull]);
        assert_eq!(p.forks(&ORD), 1);
        assert!(p.announcement(&ts::ann_id(&a3)).is_none());
    }

    #[test]
    fn records_full_rejects_new_announcement() {
        let bounds = Bounds {
            records_per_ordering: 1,
            ..Bounds::default()
        };
        let mut p = processor_with(bounds);
        let ctx = ts::TestCtx::at(FULL);
        let a1 = ts::announcement(ORD, FULL + 1, 1, None);
        announce(&mut p, &ctx, &a1, ts::PEER);
        let a2 = ts::announcement(ORD, FULL + 1, 2, Some(ts::ann_id(&a1)));
        let eff = announce(&mut p, &ctx, &a2, ts::PEER);
        assert_eq!(drops(&eff), vec![DropReason::RecordsFull]);
        assert!(p.announcement(&ts::ann_id(&a2)).is_none());
    }

    #[test]
    fn staging_full_drops_oldest_slot() {
        let bounds = Bounds {
            staging_bytes_total: 8,
            ..Bounds::default()
        };
        let mut p = processor_with(bounds);
        let present1 = ts::body(1, 1);
        let present2 = ts::body(2, 1);
        let absent1 = ts::body(3, 1);
        let absent2 = ts::body(4, 1);
        let mut ctx = ts::TestCtx::at(FULL);
        ctx.mempool.add(&present1);
        ctx.mempool.add(&present2);

        let a1 = ts::announcement_for(
            ORD,
            FULL + 1,
            1,
            None,
            &[present1.clone(), absent1.clone()],
        );
        let id1 = ts::ann_id(&a1);
        announce(&mut p, &ctx, &a1, ts::PEER);
        assert!(p.staged_bytes() > 0);

        let a2 = ts::announcement_for(
            ORD,
            FULL + 1,
            2,
            Some(id1),
            &[present2.clone(), absent2.clone()],
        );
        let eff = announce(&mut p, &ctx, &a2, ts::PEER);
        assert!(
            drops(&eff).contains(&DropReason::StagingFull),
            "{eff:?}"
        );
    }

    #[test]
    fn requests_per_peer_bound_suppresses_requests() {
        let bounds = Bounds {
            requests_per_peer: 1,
            ..Bounds::default()
        };
        let mut p = processor_with(bounds);
        let ctx = ts::TestCtx::at(FULL);
        let a1 = ts::announcement(ORD, FULL + 1, 1, None);
        let eff = announce(&mut p, &ctx, &a1, ts::PEER);
        assert!(eff
            .iter()
            .any(|e| matches!(e, Effect::RequestTransactionIds { .. })));
        let a2 = ts::announcement(ORD, FULL + 1, 2, Some(ts::ann_id(&a1)));
        let eff = announce(&mut p, &ctx, &a2, ts::PEER);
        assert!(!eff
            .iter()
            .any(|e| matches!(e, Effect::RequestTransactionIds { .. })));
        assert!(drops(&eff).contains(&DropReason::RequestsFull), "{eff:?}");
    }

    #[test]
    fn ordering_announcements_full_drops_oldest() {
        let bounds = Bounds {
            ordering_announcements: 1,
            ..Bounds::default()
        };
        let mut p = processor_with(bounds);
        let ctx = ts::TestCtx::at(FULL);
        let oa1 = ts::ordering_announcement(ORD, FULL + 1, 1, Vec::new());
        let id1 = ts::header_id(&oa1.header);
        ctx.handle(
            &mut p,
            Event::OrderingAnnouncementAccepted {
                ann: oa1,
                from: ts::PEER,
                now: Tick(0),
            },
        );
        let oa2 = ts::ordering_announcement(ORD, FULL + 1, 2, Vec::new());
        let id2 = ts::header_id(&oa2.header);
        let eff = ctx.handle(
            &mut p,
            Event::OrderingAnnouncementAccepted {
                ann: oa2,
                from: ts::PEER,
                now: Tick(1),
            },
        );
        assert!(eff.contains(&Effect::Dropped {
            id: id1,
            reason: DropReason::OrderingAnnouncementsFull
        }));
        assert!(p.ordering_announcement(&id1).is_none());
        assert!(p.ordering_announcement(&id2).is_some());
    }

    // ----- oracle parity -----

    #[test]
    fn prune_after_ordering_matches_scala_thresholds() {
        // Scala prune(): records with `bestHeight - header.height >
        // PruningThreshold(2)` go; ordering announcements with
        // `bestHeight - header.height > 6` go.
        let mut p = processor();
        let ctx = ts::TestCtx::at(FULL);
        let record = ts::announcement(ORD, FULL + 1, 1, None); // height 11
        let record_id = ts::ann_id(&record);
        announce(&mut p, &ctx, &record, ts::PEER);
        let oa = ts::ordering_announcement(ORD, FULL + 1, 2, Vec::new()); // height 11
        let oa_id = ts::header_id(&oa.header);
        ctx.handle(
            &mut p,
            Event::OrderingAnnouncementAccepted {
                ann: oa,
                from: ts::PEER,
                now: Tick(0),
            },
        );

        // best = 13: 13 - 11 == 2, not > 2 -> record kept; 13 - 11 == 2,
        // not > 6 -> announcement kept.
        ctx.handle(
            &mut p,
            Event::OrderingBlockApplied {
                header_id: [0xB1; 32],
                height: 13,
                now: Tick(1),
            },
        );
        assert!(p.announcement(&record_id).is_some());
        assert!(p.ordering_announcement(&oa_id).is_some());

        // best = 14: 14 - 11 == 3 > 2 -> record removed.
        ctx.handle(
            &mut p,
            Event::OrderingBlockApplied {
                header_id: [0xB2; 32],
                height: 14,
                now: Tick(2),
            },
        );
        assert!(p.announcement(&record_id).is_none());
        assert!(p.ordering_announcement(&oa_id).is_some());

        // best = 18: 18 - 11 == 7 > 6 -> announcement removed.
        ctx.handle(
            &mut p,
            Event::OrderingBlockApplied {
                header_id: [0xB3; 32],
                height: 18,
                now: Tick(3),
            },
        );
        assert!(p.ordering_announcement(&oa_id).is_none());
    }

    #[test]
    fn height_jump_reset_at_plus_two_prunes_like_scala() {
        // Scala applyInputBlock: `ib.header.height > bestOrderingHeight +
        // HeightThreshold(2)` resets (prunes) before recording. The node's
        // reported full-block height (the ±2 window) and the processor's
        // mirrored best-ordering height are separate inputs, so a jump is
        // reachable without tripping the window check.
        let mut p = processor();
        p.set_best_ordering(Some(ORD), FULL - 3); // best ordering height 7
        let ctx = ts::TestCtx::at(FULL);
        let old = ts::announcement(ORD, FULL - 1, 1, None); // height 9
        let old_id = ts::ann_id(&old);
        announce(&mut p, &ctx, &old, ts::PEER);
        assert!(p.announcement(&old_id).is_some());

        // height 11 > 7 + 2 -> reset. prune() then runs with bestHeight 7,
        // which keeps the height-9 record (7 - 9 saturates to 0).
        let jump = ts::announcement(ORD, FULL + 1, 2, None);
        announce(&mut p, &ctx, &jump, ts::PEER);
        assert!(p.announcement(&ts::ann_id(&jump)).is_some());

        // With best ordering height 13, the same jump prunes the height-9
        // record (13 - 9 == 4 > 2).
        let mut p = processor();
        p.set_best_ordering(Some(ORD), 13);
        let ctx = ts::TestCtx::at(14);
        let old = ts::announcement(ORD, 15, 3, None);
        let old_id = ts::ann_id(&old);
        announce(&mut p, &ctx, &old, ts::PEER);
        assert!(p.announcement(&old_id).is_some());
        p.set_best_ordering(Some(ORD), 18);
        let ctx = ts::TestCtx::at(19);
        let jump = ts::announcement(ORD, 20, 4, None);
        announce(&mut p, &ctx, &jump, ts::PEER);
        assert!(
            p.announcement(&old_id).is_none(),
            "the height jump's resetState() prunes the stale record"
        );
    }
}
