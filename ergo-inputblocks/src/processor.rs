//! The single-writer input-block processor: events in, effects out
//! (spec 7.1–7.6).
//!
//! One [`Processor`] owns everything Scala's `InputBlocksProcessor` trait
//! holds — per-ordering trees, announcement records, transaction-id
//! lists, the shared transaction cache, the disconnected waitlist and the
//! ordering-announcement store — but reads no chain state and touches no
//! clock: the node supplies the best full block via
//! [`Processor::set_best_ordering`], and every other per-event input via
//! [`ProcessorCtx`].
//!
//! Validation is an *effect*, not a call: the processor emits
//! [`Effect::Validate`] and waits for [`Event::ValidationResult`]. Exactly
//! one job is outstanding at a time, and every `ChainChanged`, applied
//! ordering block and reorg bumps `generation`, so a result that arrives
//! for a superseded view is dropped rather than applied. Where Scala's
//! `InputBlocksTree.processInputBlockTransactions` would walk several
//! blocks inside one call, this port walks them one `Validate` at a time
//! (see [`Processor::pump`]).

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use ergo_ser::input_block::{InputBlockAnnouncement, OrderingBlockAnnouncement};
use ergo_ser::transaction::Transaction;
use ergo_ser::weak_id::WeakId;

/// One announcement held for an ordering block we have not applied yet
/// (see [`Processor::ahead`]).
#[derive(Debug, Clone)]
struct AheadAnnouncement {
    ann: InputBlockAnnouncement,
    from: PeerTag,
    /// The ordering block it sits under — the replay key.
    ordering_id: OrderingId,
    /// Its header height, so an entry that can never be `+1` again is
    /// discarded rather than held forever.
    height: u32,
}

/// Hex view of a 32-byte id for `tracing` fields.
///
/// The crate deliberately takes no `hex` dependency — its public types
/// are byte arrays and the node does the encoding — so the diagnostic
/// logs here carry their own two-line formatter rather than pulling a
/// crate in for them.
struct HexId<'a>(&'a InputBlockId);

impl std::fmt::Display for HexId<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

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

/// What a node's [`Effect::Validate`] run concluded.
///
/// The third arm is the reason this is not a `Result`: "this block is
/// invalid" and "this node cannot check it right now" have opposite
/// consequences. A verdict retires the combination and charges the
/// block's retry budget; a node-local condition must do neither, or one
/// transient miss permanently blacklists the block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationOutcome {
    /// The transactions validated; carries their summed cost.
    Valid(u64),
    /// A consensus verdict on this combination of bodies.
    Invalid(String),
    /// The node could not run the job at all. Transient and node-local.
    Unavailable(String),
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
    /// The weak-id list of an input block, delivered by a peer
    /// (message 102). Only meaningful for a block whose announcement
    /// omitted the list — the node asks for it with
    /// [`Effect::RequestTransactionIds`] and answers with this.
    TransactionIdsDelivered {
        /// The block the ids belong to.
        input_block_id: InputBlockId,
        /// The announced transaction order, as 6-byte weak ids.
        weak_ids: Vec<WeakId>,
        /// The delivering peer.
        from: PeerTag,
        /// Node-supplied clock.
        now: Tick,
    },
    /// Result of a [`Effect::Validate`].
    ValidationResult {
        /// The job this answers.
        job: JobId,
        /// The generation the job was issued in.
        generation: u64,
        /// What the node's validator concluded.
        outcome: ValidationOutcome,
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
        /// The peer that announced the ordering block — the one to ask
        /// for the full `BlockTransactions` section when the plan does
        /// not reproduce the header's transactions root.
        from: PeerTag,
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
    /// A `ValidationResult` for a superseded generation or job, or a job
    /// abandoned because the bodies it froze changed underneath it. The
    /// `Dropped` id is the block the **stale** job was validating and
    /// `generation` the generation that job was issued in — never the
    /// current job's (residual fix round, D).
    StaleValidation {
        /// The generation the stale job belonged to.
        generation: u64,
    },
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
    /// Validation rejected every witness combination the announced
    /// digest allows: the block's own bodies are the problem.
    WitnessCombinationsExhausted,
    /// A delivery offered more witnesses for one announced position than
    /// [`crate::bounds::Bounds::candidates_per_position`] allows. The
    /// extra witnesses are discarded; the block is unaffected.
    VariantCapExceeded {
        /// The announced position the extra witnesses were offered for.
        position: usize,
    },
    /// The block spent [`crate::bounds::Bounds::digest_attempts_per_block`]
    /// ordered-digest attempts without reproducing the announcement's
    /// `transactionsDigest`. A local budget, not evidence against a peer.
    DigestBudgetExhausted,
    /// The block spent
    /// [`crate::bounds::Bounds::validation_retries_per_block`] validation
    /// dispatches; no further combination is offered. A local budget, not
    /// evidence against a peer.
    ValidationBudgetExhausted,
    /// No candidate combination reproduced the announced digest.
    DigestMismatch,
    /// Delivered bodies do not match the announced `transactionsDigest`.
    TxDigestMismatch,
    /// Validation failed and the block had no alternative variants.
    ValidationFailed,
    /// The announcement's extension proof reduces to the header's root
    /// (so it is valid to the Scala reference) but its leaves do not
    /// match the announced fields, and `strict_field_binding` is on.
    /// A policy drop, never a peer penalty — see
    /// [`AnnouncementError::is_policy_only`](crate::announcement::AnnouncementError::is_policy_only).
    FieldsUnbound,
    /// The node could not run the validation job at all — no applied full
    /// block to build a context from, or no UTXO set. Node-local and
    /// transient, NOT a verdict on the block: the combination is left
    /// untried and the attempt is refunded, so a later event re-offers it.
    ValidationUnavailable,
    /// `subblocks_per_block` is unavailable: input blocks are not active,
    /// so the announcement is dropped **without** penalising the peer.
    MultiplierUnavailable,
    /// The ordering-announcement store is full; the oldest was dropped.
    OrderingAnnouncementsFull,
    /// An ordering announcement for a header the node already holds
    /// (spec 9.3 / Scala `processOrderingBlockAnnouncement`). Discarded
    /// before PoW, storage and relay: a peer replaying known
    /// announcements would otherwise buy repeated PoW verification, an
    /// `Inv` broadcast and an eviction from the announcement store.
    OrderingHeaderKnown,
    /// Bodies were delivered for a block the processor has no record of.
    /// Not in the spec's list: Scala logs and ignores this case
    /// (`applyInputBlockTransactions`'s `case None`), and the node needs
    /// to see it to spot a peer spraying bodies.
    UnknownBlock,
    /// A delivered witness cannot replace the block's transaction
    /// selection: that selection is not in a rejected state — it is
    /// either outstanding or already applied — so swapping it would put
    /// an unvalidated body into a processed block.
    SelectionSettled {
        /// Which settled state refused the swap.
        state: SelectionState,
    },
    /// The node is running in digest (stateless) mode, where input
    /// blocks cannot be validated at all (Scala `processInputBlock`).
    DigestMode,
}

impl DropReason {
    /// The variant's name, stable across payload changes, for keying
    /// telemetry counters. Payload-carrying variants (`StaleValidation`,
    /// `VariantCapExceeded`, `SelectionSettled`) collapse to the variant
    /// name: a counter keyed by generation or position would be unbounded.
    pub fn name(&self) -> &'static str {
        match self {
            Self::AlreadyKnown => "AlreadyKnown",
            Self::OutsideHeightWindow => "OutsideHeightWindow",
            Self::StaleValidation { .. } => "StaleValidation",
            Self::CacheEvicted => "CacheEvicted",
            Self::WaitlistFull => "WaitlistFull",
            Self::ForksFull => "ForksFull",
            Self::RecordsFull => "RecordsFull",
            Self::StagingFull => "StagingFull",
            Self::RequestsFull => "RequestsFull",
            Self::WitnessCombinationsExhausted => "WitnessCombinationsExhausted",
            Self::VariantCapExceeded { .. } => "VariantCapExceeded",
            Self::DigestBudgetExhausted => "DigestBudgetExhausted",
            Self::ValidationBudgetExhausted => "ValidationBudgetExhausted",
            Self::DigestMismatch => "DigestMismatch",
            Self::TxDigestMismatch => "TxDigestMismatch",
            Self::ValidationFailed => "ValidationFailed",
            Self::FieldsUnbound => "FieldsUnbound",
            Self::ValidationUnavailable => "ValidationUnavailable",
            Self::MultiplierUnavailable => "MultiplierUnavailable",
            Self::OrderingAnnouncementsFull => "OrderingAnnouncementsFull",
            Self::OrderingHeaderKnown => "OrderingHeaderKnown",
            Self::UnknownBlock => "UnknownBlock",
            Self::SelectionSettled { .. } => "SelectionSettled",
            Self::DigestMode => "DigestMode",
        }
    }

    /// Every variant name [`Self::name`] can return, so a telemetry
    /// surface can publish a zero for reasons that have not fired.
    pub const ALL_NAMES: &'static [&'static str] = &[
        "AlreadyKnown",
        "OutsideHeightWindow",
        "StaleValidation",
        "CacheEvicted",
        "WaitlistFull",
        "ForksFull",
        "RecordsFull",
        "StagingFull",
        "RequestsFull",
        "WitnessCombinationsExhausted",
        "VariantCapExceeded",
        "DigestBudgetExhausted",
        "ValidationBudgetExhausted",
        "DigestMismatch",
        "TxDigestMismatch",
        "ValidationFailed",
        "FieldsUnbound",
        "ValidationUnavailable",
        "MultiplierUnavailable",
        "OrderingAnnouncementsFull",
        "OrderingHeaderKnown",
        "UnknownBlock",
        "SelectionSettled",
        "DigestMode",
    ];
}

/// The state a block's transaction selection is in when a delivery tries
/// to replace it (residual fix round, A).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionState {
    /// Selected — queued for dispatch or with a job outstanding — but not
    /// yet applied. The selection is frozen until that job fails.
    Pending,
    /// The block is applied: its transactions are part of an input chain
    /// and its references are frozen for good.
    Applied,
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
    /// Whether the node already holds an ordering block's HEADER (Scala
    /// `processOrderingBlockAnnouncement`'s "skip if the header is
    /// known", spec 9.3). Distinct from `block_transactions_known`: the
    /// header can be stored long before its transactions are.
    pub header_known: &'a dyn Fn(&OrderingId) -> bool,
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
    /// The block being validated (what the tree asked for).
    id: InputBlockId,
    /// The block whose arrival drove the selection. `tree.process` picks
    /// its fork-switch-or-linear branch from this id, so the real
    /// application must be driven with the *same* trigger the probe used,
    /// not with `id` — otherwise a switch selected on a deep trigger
    /// collapses to the linear branch and no progress is made.
    trigger: InputBlockId,
    ordering_id: OrderingId,
    /// The transaction list the job was handed, frozen at issue time. A
    /// result is only applied while the block's selection still equals
    /// this (fix round 1, finding 4).
    txs: Vec<TxRef>,
    /// The already-processed chain prefix whose bodies were handed to the
    /// job as `previous`; a change to any of those also invalidates it.
    prev_chain: Vec<InputBlockId>,
}

/// What an outstanding request asked for. A delivery only releases the
/// peer's slot when it answers the request that was actually made
/// (residual fix round, D).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestKey {
    /// `RequestModifier` −123: an announcement.
    InputBlock(InputBlockId),
    /// `RequestModifier` −122: a weak-id list.
    TransactionIds(InputBlockId),
    /// Message 105: transaction bodies. The second field identifies
    /// *which* bodies were asked for — two requests for different weak-id
    /// sets are different requests, and each one costs a slot, while a
    /// repeat of the same set is a duplicate and is suppressed (residual
    /// fix round 2, D).
    Transactions(InputBlockId, u64),
    /// An ordering block's header.
    OrderingHeader(OrderingId),
    /// An ordering block's transaction section.
    BlockTransactions(OrderingId),
}

/// Order-independent digest of a requested weak-id set, so the same set
/// asked for twice is recognised as the same request however the
/// positions were ordered. FNV-1a over the sorted ids: this identifies a
/// request, it defends nothing.
fn weak_set_hash(weak_ids: &[WeakId]) -> u64 {
    let mut sorted: Vec<WeakId> = weak_ids.to_vec();
    sorted.sort_unstable();
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for id in sorted {
        for b in id {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    h
}

impl RequestKey {
    /// The request an effect represents, if it is one.
    fn of(effect: &Effect) -> Option<Self> {
        match effect {
            Effect::RequestInputBlock { id, .. } => Some(Self::InputBlock(*id)),
            Effect::RequestTransactionIds { input_block_id, .. } => {
                Some(Self::TransactionIds(*input_block_id))
            }
            Effect::RequestTransactions {
                input_block_id,
                weak_ids,
                ..
            } => Some(Self::Transactions(*input_block_id, weak_set_hash(weak_ids))),
            Effect::RequestOrderingHeader { header_id, .. } => {
                Some(Self::OrderingHeader(*header_id))
            }
            Effect::RequestBlockTransactions { header_id, .. } => {
                Some(Self::BlockTransactions(*header_id))
            }
            _ => None,
        }
    }
}

/// One outstanding request: what was asked, when the answer is due, the
/// effect that would ask again, and how many times it has been issued.
///
/// The effect is kept so the deadline sweep can REISSUE it (spec 9.2's
/// retry contract). Before that, a lost reply was terminal: the sweep
/// only freed the slot, the coordinator deliberately forgets
/// input-block timeouts without re-requesting, and every later
/// announcement of the same block hits `AlreadyKnown` — so a block whose
/// parent announcement or transaction-id reply went missing never
/// progressed again.
#[derive(Debug, Clone)]
struct Pending {
    key: RequestKey,
    /// When the answer stops being expected and the sweep acts.
    deadline: Tick,
    /// The request to reissue, addressed to the same peer.
    effect: Effect,
    /// Issues so far; `1` for a request that has never been retried.
    attempts: u32,
}

/// Ceiling on the exponential backoff between reissues, in doublings of
/// `Bounds::request_timeout_ms`. Keeps the retry deadline bounded while
/// still backing off from a peer that is merely slow.
const REQUEST_BACKOFF_SHIFT_CAP: u32 = 3;

/// A transaction selection a delivery proposed while the block's own
/// selection was still outstanding (residual fix round 2, items B and
/// C/D). Refusing the swap is what keeps the outstanding job valid;
/// discarding the proposal is what used to make the block need *another*
/// delivery to move again. It is verified and its bodies are cached when
/// it is held, so taking it after the failure costs nothing but the
/// dispatch.
#[derive(Debug, Clone)]
struct HeldSelection {
    refs: Vec<TxRef>,
    /// Whether taking it must spend the announcer's recovery allowance:
    /// the block's validation budget was already gone when it arrived.
    recovery: bool,
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
    /// Announcements for the ordering block ONE AHEAD of our best full
    /// block, held until that ordering block is applied (task 8b).
    ///
    /// Spec 2.7 step 4 says an announcement at `best_full_height + 2`
    /// makes the node download the ordering block instead of recording
    /// the input block; the Scala reference does exactly that and marks
    /// the gap with its own `// todo: save input block?`. The
    /// consequence, measured on the mixed devnet, is that the FIRST
    /// input block under every ordering block — the only one whose
    /// `prev_input_block_id` is `None`, and therefore the only one that
    /// can root the new tree — is thrown away, because it is always
    /// published before the follower has applied the ordering block it
    /// sits under. Every later announcement then has an unknown parent,
    /// goes to `waitlist`, and the chain is rebuilt backwards one
    /// request round trip at a time while the miner publishes roughly
    /// one input block a second. The follower never catches up: the
    /// measured lag was p95 234 input blocks with the tree at zero
    /// forks.
    ///
    /// Holding the announcement costs nothing the node was not already
    /// willing to hold — it is the same announcement it will be sent
    /// again — and replaying it the moment the ordering block lands
    /// hands the tree its root in arrival order, so the chain connects
    /// linearly instead of backwards. Keyed by id, insertion-ordered,
    /// capped by `bounds.waitlist_entries` (the same operator meaning:
    /// announcements held because they cannot be placed yet) with
    /// overflow reported as [`DropReason::WaitlistFull`].
    ahead: indexmap::IndexMap<InputBlockId, AheadAnnouncement>,
    ordering: OrderingStore,
    /// Requests issued to a peer and not yet answered, each with the tick
    /// it expires at. Replaces a tick-halving counter: the cap now bounds
    /// *genuinely outstanding* requests, released by the matching
    /// delivery or by their deadline (residual fix round, D).
    outstanding: HashMap<PeerTag, Vec<Pending>>,
    /// Requests reissued by the deadline sweep since start, for the
    /// operator surface (`RequestRetried`). A rising count with no
    /// deliveries is what distinguishes a peer that is dropping replies
    /// from one that was never asked.
    requests_retried: u64,
    /// The clock of the event being handled, so [`Self::request`] can
    /// stamp a deadline without every call site threading it.
    now: Tick,
    /// The block each recently issued job was validating, so a result
    /// that arrives after the job was abandoned names its own subject
    /// instead of whatever is outstanding now. Bounded by
    /// [`crate::bounds::Bounds::retired_jobs`], oldest evicted first.
    issued: indexmap::IndexMap<JobId, InputBlockId>,
    in_flight: Option<InFlight>,
    failed: HashMap<InputBlockId, Vec<Vec<TxRef>>>,
    pending_triggers: VecDeque<(OrderingId, InputBlockId)>,
    /// Blocks whose unavailable bodies have already been reported. Spec
    /// 7.6's re-selection reaches a stalled block again on every event, so
    /// without this the same `CacheEvicted` is emitted over and over;
    /// the entry is cleared the moment the bodies are back.
    reported_evicted: std::collections::HashSet<InputBlockId>,
    /// Blocks whose spent digest / validation budgets have already been
    /// reported, for the same reason as `reported_evicted`. Cleared when
    /// the record is pruned.
    reported_digest_exhausted: std::collections::HashSet<InputBlockId>,
    reported_validation_exhausted: std::collections::HashSet<InputBlockId>,
    /// Ordered-digest attempts spent per input block. Deliberately keyed
    /// by block rather than held in the staging slot, which is deleted on
    /// a digest mismatch — the budget must not be refundable by making
    /// the slot unresolvable and then recreating it (fix round 2,
    /// finding r2-1). Released when the record is pruned.
    digest_attempts: HashMap<InputBlockId, usize>,
    /// Per block, the selections proposed while its current selection was
    /// outstanding, newest last, taken one at a time by the failures that
    /// follow. A single slot lost every alternative but the last: with A
    /// outstanding and B then C delivered, A's failure reached C and B
    /// was unreachable without another delivery (residual fix round 3).
    /// Bounded by [`crate::bounds::Bounds::candidates_per_position`] per
    /// record — the same bound that caps witness variants — and released
    /// on use, on application and at prune.
    held: HashMap<InputBlockId, Vec<HeldSelection>>,
    /// Blocks whose announcer has been invited to rescue them — and the
    /// invitation was *emitted*. The invitation is the body request a
    /// spent budget issues: without one outstanding, no later delivery
    /// can be solicited, and "solicited" is what the recovery allowance
    /// requires (residual fix round 2, ruling B). One per record.
    invited: std::collections::HashSet<InputBlockId>,
    /// Blocks whose invitation the per-peer request cap refused. Marking
    /// them invited anyway disabled recovery for good — the slots that
    /// were full at that moment free up later, but nothing ever asked
    /// again (residual fix round 3). Retried when a slot frees and on
    /// every [`Event::Tick`]; released at prune.
    pending_invitations: std::collections::HashSet<InputBlockId>,
    /// Recovery allowances already granted to a record, as
    /// `(digest, validation)`. Bounded by
    /// [`crate::bounds::Bounds::digest_recovery_per_block`] and
    /// [`crate::bounds::Bounds::validation_recovery_per_block`], never
    /// refunded, and released with the record at prune time.
    recovery_granted: HashMap<InputBlockId, (usize, usize)>,
    /// Validation attempts spent per input block. Spec 7.5's
    /// witness-variant retry is otherwise bounded only by the number of
    /// digest-consistent combinations, which is
    /// `candidates_per_position ^ positions` — a remotely chosen amount
    /// of full block validations, and a rejected-combination list that
    /// grows with it. Released when the record is pruned.
    validation_attempts: HashMap<InputBlockId, usize>,
    /// The selection a block's last failed job came from. A retry has to
    /// re-run the same *selection*, not the block's own id, or a deep
    /// fork-switch trigger collapses into the linear branch; when the
    /// reviving body arrives long after the failure, the failed job is
    /// gone and this is the only place the trigger survives.
    failed_trigger: HashMap<InputBlockId, (OrderingId, InputBlockId)>,
    /// The fork switch currently being walked, and the blocks it has
    /// already reported as rolled back.
    ///
    /// Scala applies a switch in one `processInputBlockTransactions`
    /// call: the rollback list is computed once and `applicationStep`
    /// then walks the rest of the new fork. This port validates one
    /// block per job and re-drives the same trigger to continue, and
    /// `tree.process` recomputes the rollback from the (still tied)
    /// processed depths every time. Reporting it again would make the
    /// node restore the abandoned block's transactions *after* the new
    /// fork's block removed them — a transaction in both blocks would
    /// come back from the dead. The continuation is keyed by
    /// `(ordering_id, trigger)`, so a different selection starts a fresh
    /// one.
    continuation: Option<(
        (OrderingId, InputBlockId),
        std::collections::HashSet<InputBlockId>,
    )>,
    /// Monotonic counter, bumped once per [`Self::handle`] call — i.e.
    /// once per processor event, regardless of whether it produced any
    /// [`Effect`]s (fix-round-1, finding 4). A superset of "every state
    /// mutation": some events genuinely change nothing (e.g. a `Tick`
    /// with nothing to expire), but the read side this exists for (the
    /// node's REST snapshot refresh) needs to catch mutations that
    /// produce NO effect at all — most notably TTL-driven body-cache
    /// expiry inside [`Self::on_tick`], which silently drops cached
    /// bodies without emitting anything. Comparing this across calls is
    /// cheap and never under-reports a change; it can over-report (a
    /// quiet tick still bumps it), which the caller accepts as the safe
    /// direction to be wrong in.
    revision: u64,
}

#[derive(Debug, Default)]
struct TxCache {
    entries: indexmap::IndexMap<TxRef, (Body, Tick)>,
    bytes: usize,
}

/// One candidate body for an announced weak-id position, carrying the
/// provenance spec 7.5 item 4 turns on: a body the announcing peer
/// delivered for *this block* outranks anything guessed from the local
/// mempool, so an over-cap pile of local guesses is settled the moment
/// the peer answers.
#[derive(Debug, Clone)]
struct Candidate {
    body: Body,
    /// The peer that delivered this body for *this* block
    /// ([`PeerTag::LOCAL`] for a locally resolved delivery), or `None`
    /// when it is a local mempool guess. Provenance, not just a flag: a
    /// cap hit names the peer that caused it in the structured log
    /// (residual fix round, A).
    delivered_by: Option<PeerTag>,
}

impl Candidate {
    /// Whether a peer answered with this body for this block, rather
    /// than it being guessed from the local mempool.
    fn delivered(&self) -> bool {
        self.delivered_by.is_some()
    }
}

#[derive(Debug)]
struct Staging {
    weak_ids: Vec<WeakId>,
    /// Unverified candidates per position. Cleared once `variants` is
    /// set: from then on the block's bodies live in the shared cache and
    /// only their `TxRef`s are tracked here.
    candidates: Vec<Vec<Candidate>>,
    /// Per-position variants, set once a combination reproduced the
    /// announced digest. Every entry at position `i` shares that
    /// position's committed `tx_id`, so every combination reachable from
    /// here also satisfies the digest — that invariant is what makes the
    /// witness-variant retry safe.
    variants: Option<Vec<Vec<TxRef>>>,
    cursor: Vec<usize>,
    /// Ordered-digest combinations tried so far, accumulated across every
    /// delivery for this block (spec 7.5's per-block limit). Never reset.
    attempts: usize,
    /// The effective candidate set changed since the last search, so the
    /// cursor restarts — the attempt budget does not.
    dirty: bool,
    /// A delivery widened the resolved variant lists, so the next retry
    /// has to re-enumerate from the start of the expanded space rather
    /// than step forward from the cursor.
    ///
    /// The expansion cannot always be acted on when it happens: while a
    /// job is outstanding the current selection is settled and must not
    /// be swapped under it, so the restart is *recorded* and consumed by
    /// whichever retry runs next — the delivery's own, or the outstanding
    /// job's failure.
    pending_restart: bool,
    bytes: usize,
    created: Tick,
    from: Option<PeerTag>,
}

impl TxCache {
    /// Insert `body`, evicting oldest-first until both the entry and byte
    /// caps hold. Re-inserting an existing `TxRef` keeps its original
    /// position: Scala's Guava cache is `expireAfterWrite`, not LRU, so
    /// re-delivery must not extend a body's life.
    fn insert(&mut self, body: Body, now: Tick, bounds: &Bounds) {
        let added = body.bytes.len();
        if let Some((old, _)) = self.entries.insert(body.tx_ref, (body, now)) {
            self.bytes = self.bytes.saturating_sub(old.bytes.len());
        }
        self.bytes += added;
        while self.entries.len() > bounds.tx_cache_entries || self.bytes > bounds.tx_cache_bytes {
            match self.entries.shift_remove_index(0) {
                Some((_, (b, _))) => self.bytes = self.bytes.saturating_sub(b.bytes.len()),
                None => break,
            }
        }
    }

    fn contains(&self, r: &TxRef) -> bool {
        self.entries.contains_key(r)
    }

    fn get(&self, r: &TxRef) -> Option<&Body> {
        self.entries.get(r).map(|(b, _)| b)
    }

    /// Scala's `expireAfterWrite(120, MINUTES)`, swept explicitly because
    /// this crate has no clock.
    fn expire(&mut self, now: Tick, ttl_ms: u64) {
        let stale: Vec<TxRef> = self
            .entries
            .iter()
            .filter(|(_, (_, at))| now.0.saturating_sub(at.0) > ttl_ms)
            .map(|(r, _)| *r)
            .collect();
        for r in stale {
            if let Some((b, _)) = self.entries.shift_remove(&r) {
                self.bytes = self.bytes.saturating_sub(b.bytes.len());
            }
        }
    }
}

impl Staging {
    fn new(weak_ids: Vec<WeakId>, created: Tick, from: Option<PeerTag>) -> Self {
        let n = weak_ids.len();
        Self {
            weak_ids,
            candidates: vec![Vec::new(); n],
            variants: None,
            cursor: vec![0; n],
            attempts: 0,
            dirty: false,
            pending_restart: false,
            bytes: 0,
            created,
            from,
        }
    }

    /// Add `body` as a candidate for position `i`. Returns whether it was
    /// stored. Duplicates are ignored, except that a re-delivery of a body
    /// already guessed locally upgrades it to peer-delivered.
    ///
    /// Each provenance is capped independently: at most `cap`
    /// peer-delivered bodies (a peer answering with more than that for one
    /// weak id is misbehaving, and the extras would only re-trigger the
    /// ambiguity request), and `cap + 1` local guesses — one more than the
    /// cap, which is exactly enough to detect that the position is over it.
    fn add(&mut self, i: usize, body: Body, delivered_by: Option<PeerTag>, cap: usize) -> bool {
        if self.variants.is_some() || i >= self.candidates.len() {
            return false;
        }
        let delivered = delivered_by.is_some();
        if let Some(existing) = self.candidates[i]
            .iter_mut()
            .find(|c| c.body.tx_ref == body.tx_ref)
        {
            if delivered && !existing.delivered() {
                existing.delivered_by = delivered_by;
                self.dirty = true;
            }
            return false;
        }
        let limit = if delivered { cap } else { cap + 1 };
        if self.candidates[i]
            .iter()
            .filter(|c| c.delivered() == delivered)
            .count()
            >= limit
        {
            return false;
        }
        self.bytes += body.bytes.len();
        self.candidates[i].push(Candidate { body, delivered_by });
        self.dirty = true;
        true
    }

    /// The candidates that actually count at position `i`: the peer's own
    /// answers when it has given any, else the local guesses (spec 7.5
    /// item 4, "the peer's own body wins over local guesses").
    fn effective(&self, i: usize) -> Vec<&Candidate> {
        let slot = &self.candidates[i];
        if slot.iter().any(|c| c.delivered()) {
            slot.iter().filter(|c| c.delivered()).collect()
        } else {
            slot.iter().collect()
        }
    }

    fn effective_refs(&self, i: usize) -> Vec<TxRef> {
        self.effective(i).iter().map(|c| c.body.tx_ref).collect()
    }

    /// The `TxRef`s the current cursor selects, once resolved.
    fn selected(&self) -> Option<Vec<TxRef>> {
        let vars = self.variants.as_ref()?;
        vars.iter()
            .zip(self.cursor.iter())
            .map(|(v, c)| v.get(*c).copied())
            .collect()
    }

    /// Odometer step over the resolved per-position variants (spec 7.5's
    /// witness-variant retry). Returns `false` once every combination
    /// reachable from the current cursor has been tried.
    fn advance(&mut self) -> bool {
        let Some(vars) = self.variants.clone() else {
            return false;
        };
        if self.cursor.len() != vars.len() {
            self.cursor = vec![0; vars.len()];
        }
        for (i, v) in vars.iter().enumerate() {
            if self.cursor[i] + 1 < v.len() {
                self.cursor[i] += 1;
                for c in self.cursor.iter_mut().take(i) {
                    *c = 0;
                }
                return true;
            }
        }
        false
    }

    fn had_alternatives(&self) -> bool {
        self.variants
            .as_ref()
            .is_some_and(|v| v.iter().any(|c| c.len() > 1))
    }
}

/// What [`Processor::search`] concluded about one block's staged bodies.
enum Resolution {
    /// Every position resolved and the ordered digest matched.
    Complete(Vec<TxRef>),
    /// These announced weak ids still need bodies from the announcer.
    Request(Vec<WeakId>),
    /// Exactly one candidate per position, and the digest disagreed.
    DigestMismatch,
    /// The per-block ordered-digest budget is spent, so the search
    /// stopped without a verdict. Resolved *before* the mismatch
    /// classification: a spent budget is a local limit, and reporting it
    /// as `TxDigestMismatch` would blame the bodies for it (residual fix
    /// round, A). `ambiguous` names the positions the announcer could
    /// still settle.
    DigestBudgetExhausted {
        /// Announced weak ids whose position is still ambiguous.
        ambiguous: Vec<WeakId>,
    },
}

/// The digest search itself, over one staging slot. Split out of
/// [`Processor::search`] so the per-block attempt counter can be seeded
/// from — and written back to — [`Processor::digest_attempts`] around it
/// on every exit path.
fn search_staging(
    st: &mut Staging,
    bypass: bool,
    announced: Option<[u8; 32]>,
    cap: usize,
    budget: usize,
) -> Resolution {
    if let Some(sel) = st.selected() {
        return Resolution::Complete(sel);
    }

    let n = st.weak_ids.len();
    let effective: Vec<Vec<TxRef>> = (0..n).map(|i| st.effective_refs(i)).collect();
    let needed: Vec<WeakId> = (0..n)
        .filter(|i| effective[*i].is_empty() || effective[*i].len() > cap)
        .map(|i| st.weak_ids[i])
        .collect();
    if !needed.is_empty() {
        return Resolution::Request(needed);
    }

    if bypass {
        // Finding F4b: an announcement with an empty proof commits to no
        // digest at all, so there is nothing to search — take the first
        // effective candidate at each position, as Scala does.
        return Resolution::Complete(effective.iter().map(|e| e[0]).collect());
    }
    let Some(expected) = announced else {
        return Resolution::Request(Vec::new());
    };

    if st.dirty || st.cursor.len() != n {
        st.cursor = vec![0; n];
        st.dirty = false;
    }
    while st.attempts < budget {
        if st
            .cursor
            .iter()
            .zip(effective.iter())
            .any(|(c, e)| *c >= e.len())
        {
            break;
        }
        let ids: Vec<[u8; 32]> = effective
            .iter()
            .zip(st.cursor.iter())
            .map(|(e, c)| e[*c].tx_id)
            .collect();
        let refs: Vec<&[u8]> = ids.iter().map(|i| &i[..]).collect();
        st.attempts += 1;
        if ergo_crypto::merkle::merkle_tree_root(&refs) == expected {
            return Resolution::Complete(
                effective
                    .iter()
                    .zip(st.cursor.iter())
                    .map(|(e, c)| e[*c])
                    .collect(),
            );
        }
        let mut stepped = false;
        for (i, e) in effective.iter().enumerate() {
            if st.cursor[i] + 1 < e.len() {
                st.cursor[i] += 1;
                for c in st.cursor.iter_mut().take(i) {
                    *c = 0;
                }
                stepped = true;
                break;
            }
        }
        if !stepped {
            break;
        }
    }

    // No combination matched, or the budget is spent. If some position is
    // still ambiguous the announcer's own body settles it (spec 7.5 item
    // 4); otherwise the bodies simply disagree with the announcement.
    let ambiguous: Vec<WeakId> = (0..n)
        .filter(|i| effective[*i].len() > 1)
        .map(|i| st.weak_ids[i])
        .collect();
    if st.attempts >= budget {
        return Resolution::DigestBudgetExhausted { ambiguous };
    }
    if ambiguous.is_empty() {
        Resolution::DigestMismatch
    } else {
        Resolution::Request(ambiguous)
    }
}

impl Processor {
    /// A fresh processor with no state.
    ///
    /// Every bound that is used as a *capacity* — one the processor
    /// divides, indexes or evicts against — is clamped to at least one
    /// here. The node reads its bounds from config, and a zero there is
    /// a misconfiguration the processor must survive rather than a
    /// request to disable the structure: a zero-capacity list has no
    /// room for a new entry and no entry to evict to make room, which is
    /// how a held alternative panicked (residual fix round 4). Clamping
    /// is deliberate in preference to a `debug_assert!`: the regression
    /// for that panic runs in debug, so an assertion would trade a
    /// production panic for a test-time one rather than remove it.
    ///
    /// Bounds that are genuinely meaningful at zero are left alone: a
    /// zero digest or validation budget means "no attempts", and a zero
    /// recovery allowance means "no recovery" — both are honoured.
    pub fn new(bounds: Bounds, policy: AnnouncementPolicy) -> Self {
        let bounds = Bounds {
            candidates_per_position: bounds.candidates_per_position.max(1),
            forks_per_ordering: bounds.forks_per_ordering.max(1),
            records_per_ordering: bounds.records_per_ordering.max(1),
            waitlist_entries: bounds.waitlist_entries.max(1),
            pending_triggers: bounds.pending_triggers.max(1),
            retired_jobs: bounds.retired_jobs.max(1),
            ordering_announcements: bounds.ordering_announcements.max(1),
            ..bounds
        };
        Self {
            bounds,
            policy,
            generation: 0,
            next_job: 1,
            best: BestBlocks::default(),
            trees: indexmap::IndexMap::new(),
            tree_heights: HashMap::new(),
            records: indexmap::IndexMap::new(),
            tx_refs: HashMap::new(),
            cache: TxCache::default(),
            staging: indexmap::IndexMap::new(),
            waitlist: VecDeque::new(),
            ahead: indexmap::IndexMap::new(),
            ordering: OrderingStore::default(),
            outstanding: HashMap::new(),
            requests_retried: 0,
            now: Tick(0),
            issued: indexmap::IndexMap::new(),
            in_flight: None,
            failed: HashMap::new(),
            pending_triggers: VecDeque::new(),
            reported_evicted: std::collections::HashSet::new(),
            reported_digest_exhausted: std::collections::HashSet::new(),
            reported_validation_exhausted: std::collections::HashSet::new(),
            digest_attempts: HashMap::new(),
            held: HashMap::new(),
            invited: std::collections::HashSet::new(),
            pending_invitations: std::collections::HashSet::new(),
            recovery_granted: HashMap::new(),
            validation_attempts: HashMap::new(),
            failed_trigger: HashMap::new(),
            continuation: None,
            revision: 0,
        }
    }

    /// The node tells the processor the best full block on every change;
    /// the processor never reads chain state itself.
    pub fn set_best_ordering(&mut self, id: Option<OrderingId>, height: u32) {
        self.best = BestBlocks {
            ordering_id: id,
            ordering_height: height,
        };
    }

    /// The current generation (spec 7.2): every `ChainChanged`, applied
    /// ordering block and reorg bumps it, invalidating in-flight jobs.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Feed one event; returns the effects the node must act on.
    pub fn handle(&mut self, event: Event, ctx: &ProcessorCtx<'_>) -> Vec<Effect> {
        self.revision = self.revision.wrapping_add(1);
        let mut out = Vec::new();
        // The processor owns no clock: every event but a validation
        // result carries the node's, and request deadlines are stamped
        // from it.
        match &event {
            Event::AnnouncementAccepted { now, .. }
            | Event::TransactionsDelivered { now, .. }
            | Event::TransactionIdsDelivered { now, .. }
            | Event::OrderingAnnouncementAccepted { now, .. }
            | Event::OrderingBlockApplied { now, .. }
            | Event::OrderingReorg { now, .. }
            | Event::Tick { now } => self.now = *now,
            Event::ValidationResult { .. } => {}
        }
        match event {
            Event::AnnouncementAccepted { ann, from, now } => {
                self.on_announcement(ann, from, now, ctx, &mut out)
            }
            Event::TransactionsDelivered {
                input_block_id,
                bodies,
                from,
                now,
            } => self.on_bodies(input_block_id, bodies, from, now, ctx, &mut out),
            Event::TransactionIdsDelivered {
                input_block_id,
                weak_ids,
                from,
                now,
            } => self.on_tx_ids(input_block_id, weak_ids, from, now, ctx, &mut out),
            Event::ValidationResult {
                job,
                generation,
                outcome,
            } => self.on_validation(job, generation, outcome, &mut out),
            Event::OrderingAnnouncementAccepted { ann, from, now: _ } => {
                self.on_ordering_announcement(ann, from, ctx, &mut out)
            }
            Event::OrderingBlockApplied {
                header_id, height, ..
            } => self.on_ordering(header_id, height, false, ctx, &mut out),
            Event::OrderingReorg {
                new_best_header_id,
                new_best_height,
                ..
            } => self.on_ordering(new_best_header_id, new_best_height, true, ctx, &mut out),
            Event::Tick { now } => self.on_tick(now, &mut out),
        }
        out
    }

    // ----- announcements (spec 9.2, Scala `processInputBlock` + `applyInputBlock`) -----

    fn on_announcement(
        &mut self,
        ann: InputBlockAnnouncement,
        from: PeerTag,
        now: Tick,
        ctx: &ProcessorCtx<'_>,
        out: &mut Vec<Effect>,
    ) {
        let Ok(mid) = ann.id() else {
            // A header we cannot serialize has no id to key anything by;
            // the wire layer already rejected it, so this is unreachable
            // from p2p and only guards a locally constructed announcement.
            tracing::debug!("input-block announcement header does not serialize");
            return;
        };
        let id: InputBlockId = *mid.as_bytes();
        let height = ann.header.height;
        let full = ctx.full_block_height;
        let ordering_id: OrderingId = *ann.header.parent_id.as_bytes();

        // Scala `processInputBlock` step 1: the ±2 height window.
        if height > full.saturating_add(2) || height.saturating_add(2) < full {
            out.push(Effect::Dropped {
                id,
                reason: DropReason::OutsideHeightWindow,
            });
            return;
        }
        // Step 2: input blocks need a UTXO set.
        if !ctx.utxo_mode {
            out.push(Effect::Dropped {
                id,
                reason: DropReason::DigestMode,
            });
            return;
        }
        // Whatever else happens to it, the announcement answers the
        // `−123` request that asked for it.
        self.request_answered(from, RequestKey::InputBlock(id));
        // Step 3: already known (Scala `applyInputBlock`'s first guard).
        if self.records.contains_key(&id) {
            out.push(Effect::Dropped {
                id,
                reason: DropReason::AlreadyKnown,
            });
            return;
        }
        // Step 4 of 2.7: `+2` downloads the ordering header. It also
        // HOLDS the announcement (see the `ahead` field): discarding it
        // costs the follower the root of the next ordering block's tree
        // and, with it, the whole ordering-block interval.
        if height == full.saturating_add(2) {
            tracing::debug!(
                block = %HexId(&id),
                ordering = %HexId(&ordering_id),
                height,
                full,
                prev = ?ann.fields.prev_input_block_id.as_ref().map(HexId).map(|h| h.to_string()),
                "input_blocks: announcement one ordering block ahead, held"
            );
            self.request(
                out,
                Effect::RequestOrderingHeader {
                    header_id: ordering_id,
                    from,
                },
                from,
                id,
            );
            self.hold_ahead(id, ordering_id, height, ann, from, out);
            return;
        }
        // Only `+1` is applied; the rest of the window is ignored (parity).
        if height != full.saturating_add(1) {
            out.push(Effect::Dropped {
                id,
                reason: DropReason::OutsideHeightWindow,
            });
            return;
        }

        let expected = (ctx.expected_n_bits)(ann.header.parent_id.as_bytes());
        match crate::announcement::validate_announcement(
            &ann,
            ctx.multiplier,
            expected,
            self.policy,
        ) {
            Ok(()) => {}
            Err(crate::announcement::AnnouncementError::MultiplierUnavailable) => {
                // Input blocks are not active: not the peer's fault.
                out.push(Effect::Dropped {
                    id,
                    reason: DropReason::MultiplierUnavailable,
                });
                return;
            }
            Err(e) if e.is_policy_only() => {
                // Valid by the Scala reference's own check; rejected only
                // because this node runs `strict_field_binding`. Dropping
                // it is the operator's choice; banning the peer for it is
                // not — the pinned Scala miner produces these itself.
                tracing::debug!(
                    error = %e,
                    "input-block announcement rejected by strict field binding"
                );
                out.push(Effect::Dropped {
                    id,
                    reason: DropReason::FieldsUnbound,
                });
                return;
            }
            Err(e) => {
                tracing::debug!(error = %e, "invalid input-block announcement");
                out.push(Effect::Penalize {
                    from,
                    reason: "invalid input-block announcement",
                });
                return;
            }
        }

        // Scala `applyInputBlock`'s height-jump reset.
        if height > self.best.ordering_height + self.bounds.height_reset_threshold {
            self.prune(ctx);
        }

        // Record caps (spec 7.4; Scala has none).
        let per_ordering = self
            .records
            .values()
            .filter(|r| r.ordering_id == ordering_id)
            .count();
        if per_ordering >= self.bounds.records_per_ordering
            || self.records.len() >= self.bounds.records_total
        {
            out.push(Effect::Dropped {
                id,
                reason: DropReason::RecordsFull,
            });
            return;
        }

        if !self.trees.contains_key(&ordering_id) {
            if self.trees.len() >= self.bounds.trees_total {
                if let Some((old, _)) = self.trees.shift_remove_index(0) {
                    self.tree_heights.remove(&old);
                }
            }
            self.trees.insert(ordering_id, InputBlocksTree::default());
            self.tree_heights
                .insert(ordering_id, height.saturating_sub(1));
        }

        let prev = ann.fields.prev_input_block_id;
        let tree = self.trees[&ordering_id].clone();
        let waitlist: Vec<(InputBlockId, Option<InputBlockId>)> =
            self.waitlist.iter().copied().collect();
        match tree.insert(
            crate::tree::AnnouncementRef {
                id,
                prev: prev.as_ref(),
            },
            &waitlist,
        ) {
            Some(updated) => {
                if updated.forks.len() > self.bounds.forks_per_ordering {
                    out.push(Effect::Dropped {
                        id,
                        reason: DropReason::ForksFull,
                    });
                    return;
                }
                // Whatever the tree reconnected is no longer disconnected.
                self.waitlist.retain(|(wid, _)| !updated.known(wid));
                self.trees.insert(ordering_id, updated);
            }
            None => {
                // Scala's `disconnectedWaitlist` branch: remember the
                // block and ask the announcer for its parent.
                if self.waitlist.len() >= self.bounds.waitlist_entries {
                    if let Some((old, _)) = self.waitlist.pop_front() {
                        out.push(Effect::Dropped {
                            id: old,
                            reason: DropReason::WaitlistFull,
                        });
                    }
                }
                tracing::debug!(
                    block = %HexId(&id),
                    ordering = %HexId(&ordering_id),
                    prev = ?prev.as_ref().map(HexId).map(|h| h.to_string()),
                    forks = tree.forks.len(),
                    waitlist = self.waitlist.len(),
                    "input_blocks: announcement disconnected, waitlisted"
                );
                self.waitlist.push_back((id, prev));
                if let Some(p) = prev {
                    self.request(out, Effect::RequestInputBlock { id: p, from }, from, id);
                }
            }
        }

        self.records.insert(
            id,
            Record {
                ann,
                from,
                height,
                ordering_id,
                prev,
            },
        );

        // Parity: Scala relays only its own input blocks (spec 9.2 item 7).
        if from == PeerTag::LOCAL {
            out.push(Effect::RelayAnnouncement { id });
        }

        self.resolve_block(id, now, ctx, out);
    }

    // ----- transaction resolution and staging (spec 7.5) -----

    fn resolve_block(
        &mut self,
        id: InputBlockId,
        now: Tick,
        ctx: &ProcessorCtx<'_>,
        out: &mut Vec<Effect>,
    ) {
        let Some(rec) = self.records.get(&id) else {
            return;
        };
        let from = rec.from;
        let Some(weak) = rec.ann.weak_tx_ids.clone() else {
            // No weak-id list announced: ask for it (`RequestModifier` −122).
            self.request(
                out,
                Effect::RequestTransactionIds {
                    input_block_id: id,
                    from,
                },
                from,
                id,
            );
            return;
        };
        self.staging
            .entry(id)
            .or_insert_with(|| Staging::new(weak, now, Some(from)));
        self.refresh_from_mempool(id, ctx);
        self.enforce_staging_bytes(id, out);
        self.complete_or_request(id, out);
    }

    fn refresh_from_mempool(&mut self, id: InputBlockId, ctx: &ProcessorCtx<'_>) {
        let Some(st) = self.staging.get(&id) else {
            return;
        };
        if st.variants.is_some() {
            return;
        }
        let weak = st.weak_ids.clone();
        let found: Vec<(usize, Vec<Body>)> = weak
            .iter()
            .enumerate()
            .map(|(i, w)| (i, (ctx.mempool_lookup)(w)))
            .collect();
        let cap = self.bounds.candidates_per_position;
        if let Some(st) = self.staging.get_mut(&id) {
            for (i, bodies) in found {
                for b in bodies {
                    // Local guesses, not peer answers: `Staging::effective`
                    // ignores them entirely once the announcer has replied
                    // for that position.
                    st.add(i, b, None, cap);
                }
            }
        }
    }

    /// Spec 7.4's aggregate staging cap. The slot currently being filled
    /// is never the one evicted unless it alone exceeds the cap — evicting
    /// it would make progress impossible while a delivery is in flight.
    fn enforce_staging_bytes(&mut self, current: InputBlockId, out: &mut Vec<Effect>) {
        loop {
            let total: usize = self.staging.values().map(|s| s.bytes).sum();
            if total <= self.bounds.staging_bytes_total {
                return;
            }
            let victim = self
                .staging
                .iter()
                .find(|(id, s)| **id != current && s.bytes > 0)
                .map(|(id, _)| *id)
                .unwrap_or(current);
            self.staging.shift_remove(&victim);
            out.push(Effect::Dropped {
                id: victim,
                reason: DropReason::StagingFull,
            });
            if victim == current {
                return;
            }
        }
    }

    /// Whether the record's announcement carries a proof at all. Scala's
    /// `transactionBodiesMatchAnnouncement` short-circuits to `true` when
    /// the proof has no indices — finding F4b, preserved.
    fn digest_bypassed(&self, id: &InputBlockId) -> bool {
        self.records
            .get(id)
            .is_some_and(|r| r.ann.fields.proof.indices.is_empty())
    }

    fn announced_digest(&self, id: &InputBlockId) -> Option<[u8; 32]> {
        self.records
            .get(id)
            .map(|r| r.ann.fields.transactions_digest)
    }

    /// Spec 7.5 steps 1–4: drive the ordered-digest search for one block.
    ///
    /// The search budget is per **input block**, not per staging slot: it
    /// lives in [`Processor::digest_attempts`] and outlives the slot,
    /// which `complete_or_request` deletes on a digest mismatch. Without
    /// that, a peer could spend the sixteen attempts, send bodies that
    /// make the slot unresolvable, and have the next delivery recreate it
    /// with a fresh allowance (fix round 2, finding r2-1). The entry is
    /// released only when the record is pruned.
    fn search(&mut self, id: InputBlockId) -> Resolution {
        let bypass = self.digest_bypassed(&id);
        let announced = self.announced_digest(&id);
        let cap = self.bounds.candidates_per_position;
        let budget = self.bounds.digest_attempts_per_block + self.granted(&id).0;
        let carried = self.digest_attempts.get(&id).copied().unwrap_or(0);
        let Some(st) = self.staging.get_mut(&id) else {
            return Resolution::Request(Vec::new());
        };
        st.attempts = st.attempts.max(carried);
        let resolution = search_staging(st, bypass, announced, cap, budget);
        let spent = st.attempts;
        self.digest_attempts.insert(id, spent);
        resolution
    }

    fn complete_or_request(&mut self, id: InputBlockId, out: &mut Vec<Effect>) {
        let from = self
            .staging
            .get(&id)
            .and_then(|s| s.from)
            .or_else(|| self.records.get(&id).map(|r| r.from));
        match self.search(id) {
            Resolution::Complete(refs) => self.commit_resolution(id, refs, out),
            Resolution::Request(weak_ids) => {
                if weak_ids.is_empty() {
                    return;
                }
                if let Some(peer) = from {
                    self.request(
                        out,
                        Effect::RequestTransactions {
                            input_block_id: id,
                            weak_ids,
                            from: peer,
                        },
                        peer,
                        id,
                    );
                }
            }
            Resolution::DigestMismatch => {
                // Spec 7.4's last row: unverified bodies never reach the
                // shared cache, so dropping the slot is the whole cleanup.
                self.staging.shift_remove(&id);
                out.push(Effect::Dropped {
                    id,
                    reason: DropReason::TxDigestMismatch,
                });
            }
            Resolution::DigestBudgetExhausted { ambiguous } => {
                // The budget, not the bodies, ended the search. Drop the
                // unverified candidates — nothing here is provable any
                // more — and report it once. The announcer is still asked
                // for the positions it could settle: that request is the
                // only route left to the block, and it is what a recovery
                // delivery (residual fix round, B) answers.
                self.report_digest_exhausted(id, out);
                if ambiguous.is_empty() {
                    // Nothing to disambiguate, so the ordinary request
                    // below would ask for nothing: invite the announcer
                    // to re-send the block instead.
                    self.invite_recovery(id, out);
                }
                self.staging.shift_remove(&id);
                if !ambiguous.is_empty() {
                    if let Some(peer) = from {
                        self.request(
                            out,
                            Effect::RequestTransactions {
                                input_block_id: id,
                                weak_ids: ambiguous,
                                from: peer,
                            },
                            peer,
                            id,
                        );
                    }
                }
            }
        }
    }

    /// The digest matched: keep only the bodies that can legitimately
    /// satisfy it, move those into the shared cache, and record the
    /// per-position variants for spec 7.5's retry.
    fn commit_resolution(&mut self, id: InputBlockId, refs: Vec<TxRef>, out: &mut Vec<Effect>) {
        let now = self.staging.get(&id).map(|s| s.created).unwrap_or(Tick(0));
        let cap = self.bounds.candidates_per_position;
        let mut to_cache: Vec<Body> = Vec::new();
        let mut over_cap: Vec<(usize, Option<PeerTag>)> = Vec::new();
        if let Some(st) = self.staging.get_mut(&id) {
            if st.variants.is_none() {
                let empty: Vec<Candidate> = Vec::new();
                let mut variants: Vec<Vec<TxRef>> = Vec::with_capacity(refs.len());
                for (i, selected) in refs.iter().enumerate() {
                    // The announced digest commits an *ordered list of
                    // transaction ids*, so the moment one combination
                    // reproduces it the id at every position is fixed.
                    // Only the selected body and its witness siblings —
                    // same `tx_id`, different `witness_id` — can also
                    // satisfy it. Every other candidate at this position
                    // is provably not what the announcement committed to,
                    // so it is discarded here and never reaches the shared
                    // cache, and never becomes a retry (fix round 1,
                    // finding 1).
                    //
                    // Spec 7.4's `candidates_per_position` applies here
                    // too. Staging caps the two provenances separately —
                    // `cap` peer answers and `cap + 1` local guesses —
                    // so without this a single position could be
                    // promoted into `2 * cap + 1` retry variants, each
                    // one a body admitted to the shared cache and a
                    // combination the retry loop would validate.
                    let mut variant = vec![*selected];
                    for c in st.candidates.get(i).unwrap_or(&empty) {
                        if c.body.tx_ref.tx_id != selected.tx_id {
                            continue;
                        }
                        if c.body.tx_ref == *selected {
                            to_cache.push(c.body.clone());
                        } else if variant.len() < cap {
                            variant.push(c.body.tx_ref);
                            to_cache.push(c.body.clone());
                        } else {
                            over_cap.push((i, c.delivered_by));
                        }
                    }
                    variants.push(variant);
                }
                st.candidates = vec![Vec::new(); refs.len()];
                st.bytes = 0;
                st.cursor = vec![0; refs.len()];
                st.dirty = false;
                st.variants = Some(variants);
            }
        }
        for b in to_cache {
            self.cache.insert(b, now, &self.bounds);
        }
        self.report_cap_hits(id, &over_cap, out);
        self.set_tx_refs(id, refs, out);
        let Some(ordering_id) = self.records.get(&id).map(|r| r.ordering_id) else {
            return;
        };
        self.pump(ordering_id, id, out);
        if self.in_flight.is_none() {
            self.resume(ordering_id, out);
        }
    }

    /// A block whose digest already passed can have its bodies refilled
    /// from a later delivery: the announcement fixed the transaction id at
    /// every position, so a delivered body carrying one of those ids is
    /// digest-verified by construction and may go straight into the cache
    /// (fix round 1, finding 6). Without this, a body lost to TTL expiry
    /// or eviction would strand the chain on `CacheEvicted` forever,
    /// because a resolved staging slot ignores every further candidate.
    ///
    /// Returns whether a genuinely new witness joined the variant list —
    /// the caller uses that to restart a selection the previous
    /// combination's failure left stalled.
    fn refill_verified(
        &mut self,
        id: InputBlockId,
        bodies: &[Body],
        from: Option<PeerTag>,
        now: Tick,
        out: &mut Vec<Effect>,
    ) -> bool {
        let cap = self.bounds.candidates_per_position;
        let mut to_cache: Vec<Body> = Vec::new();
        let mut over_cap: Vec<(usize, Option<PeerTag>)> = Vec::new();
        let mut admitted = false;
        let mut expanded = false;
        if let Some(st) = self.staging.get_mut(&id) {
            let Some(variants) = st.variants.as_mut() else {
                return false;
            };
            for b in bodies {
                for (position, variant) in variants.iter_mut().enumerate() {
                    let Some(committed) = variant.first().map(|r| r.tx_id) else {
                        continue;
                    };
                    if committed != b.tx_ref.tx_id {
                        continue;
                    }
                    if variant.contains(&b.tx_ref) {
                        // A reference we already track: this is the refill
                        // case, and it is always allowed.
                        to_cache.push(b.clone());
                    } else if variant.len() < cap {
                        variant.push(b.tx_ref);
                        to_cache.push(b.clone());
                        admitted = true;
                        expanded = true;
                    } else {
                        // Spec 7.4's per-position bound applies after
                        // resolution too: a peer must not be able to grow
                        // a block's witness list — and, through it, the
                        // shared cache — by spraying witnesses of a
                        // committed transaction (fix round 2, finding
                        // r2-3).
                        over_cap.push((position, from));
                    }
                }
            }
            if expanded {
                st.pending_restart = true;
            }
        }
        for b in to_cache {
            self.cache.insert(b, now, &self.bounds);
        }
        self.report_cap_hits(id, &over_cap, out);
        admitted
    }

    /// Report the per-position witness cap being hit, once per position.
    /// The reason is telemetry only: a cap hit says nothing about who is
    /// at fault — the pile can be local mempool guesses — so no peer is
    /// penalized for it. The peer that offered the extra witness, when
    /// there is one, is named in the structured log rather than in the
    /// bounded effect (residual fix round, A).
    fn report_cap_hits(
        &mut self,
        id: InputBlockId,
        hits: &[(usize, Option<PeerTag>)],
        out: &mut Vec<Effect>,
    ) {
        let mut reported: Vec<usize> = Vec::new();
        for (position, by) in hits {
            if reported.contains(position) {
                continue;
            }
            reported.push(*position);
            tracing::debug!(
                block = ?id,
                position,
                delivered_by = ?by,
                "witness variants for an announced position are at the cap"
            );
            out.push(Effect::Dropped {
                id,
                reason: DropReason::VariantCapExceeded {
                    position: *position,
                },
            });
        }
    }

    /// Consume `id`'s pending enumeration restart, if it has one.
    fn take_pending_restart(&mut self, id: &InputBlockId) -> bool {
        self.staging
            .get_mut(id)
            .is_some_and(|st| std::mem::take(&mut st.pending_restart))
    }

    /// A witness delivered after the block's current selection was
    /// rejected has to move the cursor: the odometer still points at the
    /// rejected combination, which [`Self::pump`] refuses to re-offer, so
    /// appending the body to the variant list alone restarts nothing
    /// (spec 7.5's retry, driven by a delivery rather than by a failure).
    ///
    /// The selection is re-driven with the trigger the failed job carried,
    /// for the same reason the failure-path retry is: a fork switch has to
    /// stay a fork switch.
    ///
    /// Only a selection validation has *currently* rejected may be
    /// swapped. Asking whether the block ever failed is not the same
    /// question: after witness A fails and witness B is validated and
    /// applied, the failure entry for A is still there, so a witness C
    /// arriving later would replace the applied block's references with a
    /// body nothing validated — and, because the block is already
    /// processed, `pump` would never issue a job for it. An applied or
    /// outstanding selection is settled; the late witness is reported and
    /// the references stay put.
    fn retry_after_delivery(&mut self, id: InputBlockId, out: &mut Vec<Effect>) {
        if let Some(state) = self.settled_state(&id) {
            out.push(Effect::Dropped {
                id,
                reason: DropReason::SelectionSettled { state },
            });
            return;
        }
        if self.validation_exhausted(&id) {
            return;
        }
        // This retry *is* the restart the delivery asked for.
        self.take_pending_restart(&id);
        let Some(refs) = self.next_untried_combination(id, true) else {
            return;
        };
        let Some((ordering_id, trigger)) = self
            .failed_trigger
            .get(&id)
            .copied()
            .or_else(|| self.records.get(&id).map(|r| (r.ordering_id, id)))
        else {
            return;
        };
        self.set_tx_refs(id, refs, out);
        self.pump(ordering_id, trigger, out);
        if self.in_flight.is_none() {
            self.resume(ordering_id, out);
        }
    }

    /// The next combination that satisfies the announced digest and has
    /// not already been rejected by validation. Retries are tracked per
    /// *combination*, not per body: a block whose first witness choice
    /// failed must still be able to retry with a different witness for the
    /// offending position without its innocent block-mates being treated
    /// as failed too (fix round 1, finding 2).
    ///
    /// `restart` re-enumerates from the beginning of the odometer space
    /// instead of stepping forward from the current cursor. A delivery
    /// that adds a variant *widens* the space, and combinations behind
    /// the cursor become reachable for the first time: with counts
    /// `[1, 2]` exhausted the cursor sits at `[0, 1]`, and a new variant
    /// at position 0 makes both `[1, 0]` and `[1, 1]` legal — but
    /// stepping forward only ever reaches `[1, 1]`, stranding the block
    /// if `[1, 0]` is the combination that validates. Nothing is
    /// re-offered twice, because every combination validation actually
    /// rejected is in `rejected`; a combination that was dispatched but
    /// never answered is not a rejection and may legitimately come back.
    fn next_untried_combination(&mut self, id: InputBlockId, restart: bool) -> Option<Vec<TxRef>> {
        let rejected = self.failed.get(&id).cloned().unwrap_or_default();
        let bypass = self.digest_bypassed(&id);
        let announced = self.announced_digest(&id);
        // The digest invariant is checked on *every* retry, not only on
        // the first match (fix round 1, finding 1). By construction every
        // variant at a position shares that position's committed tx id,
        // so this never rejects a legitimate witness sibling — it is an
        // enforced invariant, not an assumed one.
        let acceptable = |selection: &Vec<TxRef>| -> bool {
            if rejected.contains(selection) {
                return false;
            }
            if bypass {
                return true;
            }
            let Some(expected) = announced else {
                return true;
            };
            let ids: Vec<[u8; 32]> = selection.iter().map(|r| r.tx_id).collect();
            let refs: Vec<&[u8]> = ids.iter().map(|i| &i[..]).collect();
            ergo_crypto::merkle::merkle_tree_root(&refs) == expected
        };
        let st = self.staging.get_mut(&id)?;
        let positions = st.variants.as_ref()?.len();
        if restart {
            st.cursor = vec![0; positions];
            if let Some(selection) = st.selected() {
                if acceptable(&selection) {
                    return Some(selection);
                }
            }
        }
        loop {
            if !st.advance() {
                return None;
            }
            let selection = st.selected()?;
            if acceptable(&selection) {
                return Some(selection);
            }
        }
    }

    /// Whether `id` is applied: some fork's processed prefix contains it,
    /// so its transactions are already part of an input chain.
    fn is_applied(&self, id: &InputBlockId) -> bool {
        self.records
            .get(id)
            .and_then(|r| self.trees.get(&r.ordering_id))
            .is_some_and(|t| t.is_processed(id))
    }

    /// The gate every delivery-driven selection change goes through
    /// (residual fix round, D): `Some(state)` when the block's current
    /// transaction selection is settled and must not be swapped, `None`
    /// when it is in a rejected state (or there is no selection yet) and
    /// a delivery may legitimately replace it.
    ///
    /// Applied references are frozen for good: the tree already counts
    /// the block as processed, so no job would ever run for a swapped-in
    /// body. A selection that is merely queued or outstanding is frozen
    /// *until that job fails* — a different witness is not demonstrably
    /// better before validation (residual fix round, C).
    fn settled_state(&self, id: &InputBlockId) -> Option<SelectionState> {
        if self.is_applied(id) {
            return Some(SelectionState::Applied);
        }
        let current = self.tx_refs.get(id)?;
        if self.has_failed_combination(id, current) {
            return None;
        }
        Some(SelectionState::Pending)
    }

    /// Record a block's selected transaction list, invalidating any
    /// outstanding job that was handed the previous one.
    ///
    /// Fix round 1, finding 4: a `Validate` freezes the exact bodies it
    /// was asked about. If the block it is validating — or any block whose
    /// bodies it was given as `previous` — changes underneath it (a peer
    /// delivering another witness of the same transaction keeps the digest
    /// intact but swaps the body), the outstanding result can no longer be
    /// trusted. The job is invalidated here and reissued by the caller's
    /// `pump`.
    fn set_tx_refs(&mut self, id: InputBlockId, refs: Vec<TxRef>, out: &mut Vec<Effect>) {
        let changed = self.tx_refs.get(&id).map(|v| v.as_slice()) != Some(refs.as_slice());
        self.tx_refs.insert(id, refs);
        if !changed {
            return;
        }
        let stale = self
            .in_flight
            .as_ref()
            .is_some_and(|inf| inf.id == id || inf.prev_chain.contains(&id));
        if stale {
            if let Some(inf) = self.in_flight.take() {
                tracing::debug!("input-block validation job invalidated: bodies changed");
                out.push(Effect::Dropped {
                    id: inf.id,
                    reason: DropReason::StaleValidation {
                        generation: inf.generation,
                    },
                });
                // The invalidated job's *selection* must be re-run, not
                // just its block: a fork switch chosen on a deep trigger
                // collapses into the linear branch if it is re-driven
                // with the block's own id. Queue the original trigger at
                // the front so `resume` picks it up first (fix round 2,
                // finding r2-2).
                self.defer_trigger(inf.ordering_id, inf.trigger, true);
            }
        }
    }

    // ----- delivered bodies (message 104) -----

    /// Message 102: the weak-id list the announcement omitted.
    ///
    /// Scala has no separate step here — its `InputBlockAnnouncement`
    /// always carries the list in the cases the reference node produces,
    /// and the wire message exists for the announcement that does not.
    /// The list is *not* covered by the announcement's extension proof,
    /// so it is trusted only as an ordering hint: the ordered Merkle
    /// digest over the bodies it resolves still has to reproduce
    /// `transactionsDigest` before anything is cached or validated. The
    /// per-block digest budget is deliberately not refunded when a
    /// second, different list arrives (fix round 2, finding r2-1).
    fn on_tx_ids(
        &mut self,
        id: InputBlockId,
        weak_ids: Vec<WeakId>,
        from: PeerTag,
        now: Tick,
        ctx: &ProcessorCtx<'_>,
        out: &mut Vec<Effect>,
    ) {
        if self.request_answered(from, RequestKey::TransactionIds(id)) {
            self.retry_invitations(Some(from), out);
        }
        let Some(rec) = self.records.get(&id) else {
            out.push(Effect::Dropped {
                id,
                reason: DropReason::UnknownBlock,
            });
            return;
        };
        // The announcement's own list is authoritative, and a block whose
        // digest already passed has a fixed transaction order: in both
        // cases an id list adds nothing.
        if rec.ann.weak_tx_ids.is_some()
            || self.tx_refs.contains_key(&id)
            || self.staging.get(&id).is_some_and(|s| s.variants.is_some())
        {
            out.push(Effect::Dropped {
                id,
                reason: DropReason::AlreadyKnown,
            });
            return;
        }
        let same = self
            .staging
            .get(&id)
            .is_some_and(|s| s.weak_ids == weak_ids);
        if !same {
            // A different list replaces the slot's unverified candidates;
            // nothing verified is lost, because `variants` is `None` here.
            self.staging.shift_remove(&id);
            self.staging
                .insert(id, Staging::new(weak_ids, now, Some(from)));
        }
        self.refresh_from_mempool(id, ctx);
        self.enforce_staging_bytes(id, out);
        self.complete_or_request(id, out);
    }

    // ----- the announcer's recovery allowance (residual fix round, B) -----

    /// The complete selection a delivery proposes, when it is the kind of
    /// delivery a recovery allowance may be spent on: sent by the peer
    /// that announced the block, answering a body request this processor
    /// actually issued to it, covering every announced position exactly
    /// once.
    ///
    /// "Complete" is a claim about shape, not about validity: the digest
    /// check and the validation still have to pass, and they are what the
    /// allowance buys. An applied block is never a candidate — its
    /// references are frozen for good.
    fn proposed_recovery(
        &self,
        id: InputBlockId,
        weak: &[WeakId],
        bodies: &[Body],
        from: Option<PeerTag>,
        solicited: bool,
    ) -> Option<Vec<TxRef>> {
        if weak.is_empty() || bodies.len() != weak.len() {
            return None;
        }
        let announcer = self.records.get(&id)?.from;
        if from != Some(announcer) {
            return None;
        }
        // Solicited: this delivery answered an outstanding body request to
        // the announcer, or one is outstanding to it right now. A request
        // answered long ago does not make a later unprompted delivery
        // solicited (residual fix round 2, ruling B).
        if !solicited && !self.bodies_requested(announcer, id) {
            return None;
        }
        if self.is_applied(&id) {
            return None;
        }
        // Unambiguous position mapping: one announced weak id per
        // position, one delivered body per announced weak id. Anything
        // else leaves a choice to make, and a recovery must not be spent
        // on a guess.
        let mut selection = Vec::with_capacity(weak.len());
        for (i, w) in weak.iter().enumerate() {
            if weak.iter().skip(i + 1).any(|other| other == w) {
                return None;
            }
            let mut matching = bodies.iter().filter(|b| b.weak_id == *w);
            let body = matching.next()?;
            if matching.next().is_some() {
                return None;
            }
            selection.push(body.tx_ref);
        }
        Some(selection)
    }

    /// Ask the announcer, once, for the block's bodies at the moment the
    /// node gives up on it. Nothing else can make a later delivery
    /// solicited, and an unsolicited delivery may not spend the recovery
    /// allowance — so without this invitation the allowance could never
    /// be used by the peer it belongs to.
    fn invite_recovery(&mut self, id: InputBlockId, out: &mut Vec<Effect>) {
        if self.invited.contains(&id) {
            return;
        }
        let Some(rec) = self.records.get(&id) else {
            return;
        };
        let peer = rec.from;
        let weak_ids = match rec
            .ann
            .weak_tx_ids
            .clone()
            .or_else(|| self.staging.get(&id).map(|s| s.weak_ids.clone()))
        {
            // A block whose transaction order was never announced by weak
            // id has nothing to ask for position by position.
            Some(w) if !w.is_empty() => w,
            _ => return,
        };
        let emitted = self.request(
            out,
            Effect::RequestTransactions {
                input_block_id: id,
                weak_ids,
                from: peer,
            },
            peer,
            id,
        );
        if emitted {
            self.invited.insert(id);
            self.pending_invitations.remove(&id);
        } else {
            // The peer is at its request cap right now. Recovery is not
            // lost: the invitation is retried the moment a slot frees.
            self.pending_invitations.insert(id);
        }
    }

    /// Re-issue invitations the request cap refused. `peer` limits the
    /// retry to the announcer whose slot just freed; `None` retries every
    /// deferred invitation (the deadline sweep, where any slot may have
    /// expired).
    ///
    /// An invitation that still has no capacity stays deferred silently:
    /// it was reported once, when it was first refused.
    fn retry_invitations(&mut self, peer: Option<PeerTag>, out: &mut Vec<Effect>) {
        if self.pending_invitations.is_empty() {
            return;
        }
        let due: Vec<InputBlockId> = self
            .pending_invitations
            .iter()
            .copied()
            .filter(|id| {
                self.records.get(id).is_some_and(|r| {
                    peer.is_none_or(|p| r.from == p) && self.has_request_capacity(r.from)
                })
            })
            .collect();
        for id in due {
            self.invite_recovery(id, out);
        }
    }

    /// Whether `peer` has room for another request right now.
    ///
    /// In-flight slots only, matching [`Self::request`]'s own gate: a
    /// retry-pending slot is a question waiting to be re-asked, not one
    /// occupying the wire.
    fn has_request_capacity(&self, peer: PeerTag) -> bool {
        let now = self.now;
        let held = self.outstanding.get(&peer).map_or(0, |slots| {
            slots.iter().filter(|p| p.deadline.0 > now.0).count()
        });
        held < self.bounds.requests_per_peer
    }

    /// Consume one digest-recovery allowance for `id`. Consumed *before*
    /// the check it pays for, so a failed recovery is not refundable.
    fn grant_digest_recovery(&mut self, id: InputBlockId) -> bool {
        let entry = self.recovery_granted.entry(id).or_insert((0, 0));
        if entry.0 >= self.bounds.digest_recovery_per_block {
            return false;
        }
        entry.0 += 1;
        // The block is no longer given up on, so a later give-up is worth
        // reporting again.
        self.reported_digest_exhausted.remove(&id);
        true
    }

    /// Consume one validation-recovery allowance for `id`.
    fn grant_validation_recovery(&mut self, id: InputBlockId) -> bool {
        let entry = self.recovery_granted.entry(id).or_insert((0, 0));
        if entry.1 >= self.bounds.validation_recovery_per_block {
            return false;
        }
        entry.1 += 1;
        self.reported_validation_exhausted.remove(&id);
        true
    }

    /// Make `proposed` reachable in the block's variant lists and cache
    /// its bodies. A position already at the cap may give up one
    /// *unselected, speculative* variant — otherwise a peer could poison
    /// every position with witnesses and make recovery impossible — but
    /// never the reference the block is currently carrying, and never a
    /// transaction id the announced digest did not commit to.
    fn admit_recovery_selection(
        &mut self,
        id: InputBlockId,
        proposed: &[TxRef],
        bodies: &[Body],
        now: Tick,
    ) -> bool {
        let cap = self.bounds.candidates_per_position;
        let current = self.tx_refs.get(&id).cloned().unwrap_or_default();
        let Some(st) = self.staging.get_mut(&id) else {
            return false;
        };
        let Some(variants) = st.variants.as_mut() else {
            return false;
        };
        if variants.len() != proposed.len() {
            return false;
        }
        for (i, want) in proposed.iter().enumerate() {
            let committed = match variants[i].first() {
                Some(r) => r.tx_id,
                None => return false,
            };
            // The announced digest fixed the transaction id at every
            // position; only a witness of *that* transaction can be
            // swapped in.
            if committed != want.tx_id {
                return false;
            }
            if variants[i].contains(want) {
                continue;
            }
            if variants[i].len() >= cap {
                let victim = variants[i]
                    .iter()
                    .rposition(|r| Some(r) != current.get(i) && *r != variants[i][0]);
                match victim {
                    Some(v) => {
                        variants[i].remove(v);
                    }
                    None => return false,
                }
            }
            variants[i].push(*want);
        }
        // Point the odometer at the recovered selection. The staging
        // cursor *is* the block's selection: every later
        // `complete_or_request` re-derives the transaction list from it,
        // so leaving it behind would silently swap the pinned selection
        // back out on the next delivery.
        if st.cursor.len() != variants.len() {
            st.cursor = vec![0; variants.len()];
        }
        for (i, want) in proposed.iter().enumerate() {
            match variants[i].iter().position(|r| r == want) {
                Some(at) => st.cursor[i] = at,
                None => return false,
            }
        }
        for b in bodies {
            if proposed.contains(&b.tx_ref) {
                self.cache.insert(b.clone(), now, &self.bounds);
            }
        }
        true
    }

    /// Spend the digest-recovery allowance on the announcer's proposal —
    /// checking *that* selection, not whatever the ordinary search
    /// reaches first (residual fix round 2, B). Returns whether the
    /// recovery was taken.
    ///
    /// The ordinary search enumerates every effective candidate, so a
    /// stranger that dropped one wrong body into the block could spend
    /// the sole extra attempt on a combination nobody proposed — and a
    /// position already full of speculative candidates could reject the
    /// proposed body outright. The proposal is therefore checked
    /// directly and, if it holds, installed as the block's only
    /// candidate set, which pins it.
    fn recover_digest(
        &mut self,
        id: InputBlockId,
        weak: &[WeakId],
        proposed: &[TxRef],
        bodies: &[Body],
        now: Tick,
        out: &mut Vec<Effect>,
    ) -> bool {
        // Consumed before the check it pays for.
        if !self.grant_digest_recovery(id) {
            return false;
        }
        *self.digest_attempts.entry(id).or_insert(0) += 1;
        let matches = if self.digest_bypassed(&id) {
            // Finding F4b: an empty proof commits to no digest at all.
            true
        } else {
            let ids: Vec<[u8; 32]> = proposed.iter().map(|r| r.tx_id).collect();
            let refs: Vec<&[u8]> = ids.iter().map(|i| &i[..]).collect();
            Some(ergo_crypto::merkle::merkle_tree_root(&refs)) == self.announced_digest(&id)
        };
        if !matches {
            self.staging.shift_remove(&id);
            out.push(Effect::Dropped {
                id,
                reason: DropReason::TxDigestMismatch,
            });
            return true;
        }
        let Some(announcer) = self.records.get(&id).map(|r| r.from) else {
            return true;
        };
        // A slot holding nothing but the proposal: every position has
        // exactly one candidate, so the variant lists `commit_resolution`
        // builds are the proposal itself.
        let cap = self.bounds.candidates_per_position;
        let mut slot = Staging::new(weak.to_vec(), now, Some(announcer));
        for (i, w) in weak.iter().enumerate() {
            if let Some(b) = bodies.iter().find(|b| b.weak_id == *w) {
                slot.add(i, b.clone(), Some(announcer), cap);
            }
        }
        self.staging.insert(id, slot);
        self.commit_resolution(id, proposed.to_vec(), out);
        true
    }

    /// Whether `proposed` is a witness-for-witness swap of what the
    /// announced digest already committed to at every position — the
    /// only kind of proposal a resolved block may hold.
    fn proposal_matches_commitments(&self, id: &InputBlockId, proposed: &[TxRef]) -> bool {
        self.staging
            .get(id)
            .and_then(|st| st.variants.as_ref())
            .is_some_and(|variants| {
                variants.len() == proposed.len()
                    && variants
                        .iter()
                        .zip(proposed.iter())
                        .all(|(v, want)| v.first().is_some_and(|c| c.tx_id == want.tx_id))
            })
    }

    /// Keep `refs` until the outstanding job fails, caching the bodies it
    /// names so taking it later costs only the dispatch.
    ///
    /// Alternatives accumulate up to `candidates_per_position`: a peer
    /// that keeps offering witnesses while a job runs cannot grow this
    /// list without bound, and — the point of the list — an alternative
    /// is not lost because a later one arrived. At the cap the oldest
    /// goes, and a selection already held is refreshed rather than
    /// duplicated.
    fn hold_selection(
        &mut self,
        id: InputBlockId,
        refs: Vec<TxRef>,
        recovery: bool,
        bodies: &[Body],
        now: Tick,
        out: &mut Vec<Effect>,
    ) {
        let cap = self.bounds.candidates_per_position;
        if cap == 0 {
            // A capacity of zero means "retain nothing": there is no
            // room to hold this alternative, and nothing to evict to
            // make room. `Processor::new` clamps the bound so this is
            // unreachable through the public constructor, but the list
            // operations below are only sound for a non-zero capacity,
            // so the guard states that rather than assuming it. The
            // position is nominal — a zero cap denies every position.
            out.push(Effect::Dropped {
                id,
                reason: DropReason::VariantCapExceeded { position: 0 },
            });
            return;
        }
        for b in bodies {
            if refs.contains(&b.tx_ref) {
                self.cache.insert(b.clone(), now, &self.bounds);
            }
        }
        let slot = self.held.entry(id).or_default();
        slot.retain(|h| h.refs != refs);
        if slot.len() >= cap {
            slot.remove(0);
        }
        slot.push(HeldSelection { refs, recovery });
        // A staged block enumerates its own variants on the next retry;
        // the expansion this delivery represents has to restart that
        // enumeration rather than step forward from the cursor (spec
        // 7.5's retry, ruling C/D).
        if let Some(st) = self.staging.get_mut(&id) {
            if st.variants.is_some() {
                st.pending_restart = true;
            }
        }
    }

    /// Take the selection held for `id` now that its job has failed.
    /// Returns whether it started something.
    fn take_held(
        &mut self,
        id: InputBlockId,
        held: HeldSelection,
        ordering_id: OrderingId,
        trigger: InputBlockId,
        out: &mut Vec<Effect>,
    ) -> bool {
        if self.is_applied(&id) || self.has_failed_combination(&id, &held.refs) {
            return false;
        }
        if held.recovery {
            return self.recover_validation(id, held.refs, &[], Tick(0), out);
        }
        if self.validation_exhausted(&id) {
            return false;
        }
        self.set_tx_refs(id, held.refs, out);
        self.pump(ordering_id, trigger, out);
        true
    }

    /// Spend the validation-recovery allowance on `proposed`: pin that
    /// selection and dispatch one more job for it. Returns whether the
    /// recovery was taken.
    fn recover_validation(
        &mut self,
        id: InputBlockId,
        proposed: Vec<TxRef>,
        bodies: &[Body],
        now: Tick,
        out: &mut Vec<Effect>,
    ) -> bool {
        // A combination validation already rejected would buy nothing.
        if self.has_failed_combination(&id, &proposed) {
            return false;
        }
        if !self.grant_validation_recovery(id) {
            return false;
        }
        if !self.admit_recovery_selection(id, &proposed, bodies, now) {
            return true;
        }
        let Some(ordering_id) = self.records.get(&id).map(|r| r.ordering_id) else {
            return true;
        };
        let (oid, trigger) = self
            .failed_trigger
            .get(&id)
            .copied()
            .unwrap_or((ordering_id, id));
        self.set_tx_refs(id, proposed, out);
        self.pump(oid, trigger, out);
        if self.in_flight.is_none() {
            self.resume(ordering_id, out);
        }
        true
    }

    fn on_bodies(
        &mut self,
        id: InputBlockId,
        bodies: Vec<Body>,
        from: Option<PeerTag>,
        now: Tick,
        ctx: &ProcessorCtx<'_>,
        out: &mut Vec<Effect>,
    ) {
        let solicited = from.is_some_and(|p| self.bodies_answered(p, id, &bodies));
        if solicited {
            // That slot is free now: an invitation the cap refused gets
            // its chance (residual fix round 3).
            self.retry_invitations(from, out);
        }
        let Some(rec) = self.records.get(&id) else {
            out.push(Effect::Dropped {
                id,
                reason: DropReason::UnknownBlock,
            });
            return;
        };
        let announcer = rec.from;
        // The list may have come from the announcement or from a
        // message-102 delivery; either way it fixes the block's
        // transaction order, so bodies are resolved through staging
        // rather than taken in delivery order.
        let known_weak_ids = rec
            .ann
            .weak_tx_ids
            .clone()
            .or_else(|| self.staging.get(&id).map(|s| s.weak_ids.clone()));
        match known_weak_ids {
            Some(weak) => {
                let recovery = self.proposed_recovery(id, &weak, &bodies, from, solicited);
                let mut refilled = false;
                if self.staging.get(&id).is_some_and(|s| s.variants.is_some()) {
                    // The block's digest already passed; a delivery now
                    // can only refill bodies the cache lost — or offer a
                    // witness the rejected selection did not have.
                    refilled = self.refill_verified(id, &bodies, from, now, out);
                    // The announcer may rescue a block whose validation
                    // budget is spent, once (residual fix round, B).
                    if self.validation_exhausted(&id) {
                        if let Some(proposed) = recovery {
                            match self.settled_state(&id) {
                                // Applied references are frozen, allowance
                                // or not.
                                Some(SelectionState::Applied) => {}
                                // A job is outstanding, and the budget was
                                // already spent when it was dispatched:
                                // replacing its references now would
                                // invalidate a job that might still
                                // succeed, and spend the recovery dispatch
                                // on top. Hold the proposal for its
                                // failure instead (residual fix round 2).
                                Some(SelectionState::Pending) => {
                                    if self.proposal_matches_commitments(&id, &proposed) {
                                        self.hold_selection(id, proposed, true, &bodies, now, out);
                                    }
                                    out.push(Effect::Dropped {
                                        id,
                                        reason: DropReason::SelectionSettled {
                                            state: SelectionState::Pending,
                                        },
                                    });
                                    return;
                                }
                                None => {
                                    if self.recover_validation(id, proposed, &bodies, now, out) {
                                        return;
                                    }
                                }
                            }
                        }
                    }
                } else {
                    // ... and a block whose ordered-digest budget is
                    // spent, for one more check of the exact selection it
                    // proposes — checked directly, never through the
                    // ordinary search (residual fix round 2, B).
                    if self.digest_exhausted(&id) {
                        if let Some(proposed) = recovery.clone() {
                            if self.recover_digest(id, &weak, &proposed, &bodies, now, out) {
                                return;
                            }
                        }
                    }
                    self.staging.entry(id).or_insert_with(|| {
                        Staging::new(weak.clone(), now, from.or(Some(announcer)))
                    });
                    let cap = self.bounds.candidates_per_position;
                    if let Some(st) = self.staging.get_mut(&id) {
                        for b in bodies {
                            let positions: Vec<usize> = st
                                .weak_ids
                                .iter()
                                .enumerate()
                                .filter(|(_, w)| **w == b.weak_id)
                                .map(|(i, _)| i)
                                .collect();
                            for i in positions {
                                // A locally resolved delivery is still a
                                // delivery, not a guess.
                                st.add(i, b.clone(), Some(from.unwrap_or(PeerTag::LOCAL)), cap);
                            }
                        }
                    }
                    self.refresh_from_mempool(id, ctx);
                    self.enforce_staging_bytes(id, out);
                }
                self.complete_or_request(id, out);
                if refilled {
                    self.retry_after_delivery(id, out);
                }
            }
            None => {
                // Scala `applyInputBlockTransactions(id, txs, state)`: with
                // no announced weak-id list, the delivered order *is* the
                // block's transaction order.
                //
                // This path goes through the same bounded selection state
                // machine as the staged one (residual fix round, D).
                // Without that, a second delivery naming the same
                // transaction ids with different witnesses passed the
                // ordered digest and replaced an *applied* block's
                // references with bodies nothing ever validated — the
                // tree already counts the block as processed, so no job
                // would run for them.
                let refs: Vec<TxRef> = bodies.iter().map(|b| b.tx_ref).collect();
                let unchanged = self.tx_refs.get(&id).map(|v| v.as_slice()) == Some(&refs[..]);
                let settled = if unchanged {
                    None
                } else {
                    self.settled_state(&id)
                };
                if !unchanged {
                    if settled == Some(SelectionState::Applied) {
                        out.push(Effect::Dropped {
                            id,
                            reason: DropReason::SelectionSettled {
                                state: SelectionState::Applied,
                            },
                        });
                        return;
                    }
                    // The per-block budgets bound this path too: the
                    // ordered-digest check below is real hashing work, and
                    // a swapped selection buys another block validation.
                    if self.digest_exhausted(&id) {
                        self.report_digest_exhausted(id, out);
                        return;
                    }
                    if self.validation_exhausted(&id) {
                        self.report_validation_exhausted(id, out);
                        return;
                    }
                }
                let ids: Vec<[u8; 32]> = bodies.iter().map(|b| b.tx_ref.tx_id).collect();
                if !self.digest_bypassed(&id) {
                    if !unchanged {
                        *self.digest_attempts.entry(id).or_insert(0) += 1;
                    }
                    let mref: Vec<&[u8]> = ids.iter().map(|i| &i[..]).collect();
                    let expected = self.announced_digest(&id).unwrap_or_default();
                    if ergo_crypto::merkle::merkle_tree_root(&mref) != expected {
                        out.push(Effect::Dropped {
                            id,
                            reason: DropReason::TxDigestMismatch,
                        });
                        return;
                    }
                }
                if settled == Some(SelectionState::Pending) {
                    // The outstanding job keeps its references, but this
                    // alternative is digest-verified and its bodies are
                    // cached, so the failure of that job can reach it
                    // without another delivery (residual fix round 2,
                    // C/D). Without the hold, a witness offered
                    // mid-validation was simply lost.
                    self.hold_selection(id, refs, false, &bodies, now, out);
                    out.push(Effect::Dropped {
                        id,
                        reason: DropReason::SelectionSettled {
                            state: SelectionState::Pending,
                        },
                    });
                    return;
                }
                for b in bodies {
                    self.cache.insert(b, now, &self.bounds);
                }
                self.set_tx_refs(id, refs, out);
                let Some(ordering_id) = self.records.get(&id).map(|r| r.ordering_id) else {
                    return;
                };
                // A delivery that replaces a *rejected* selection re-runs
                // the trigger that selection was made on, for the reason
                // the staged retry does: a fork switch chosen on a deep
                // trigger collapses into the linear branch if it is
                // re-driven with the block's own id.
                let trigger = self
                    .failed_trigger
                    .get(&id)
                    .copied()
                    .unwrap_or((ordering_id, id));
                self.pump(trigger.0, trigger.1, out);
                if self.in_flight.is_none() {
                    self.resume(ordering_id, out);
                }
            }
        }
    }

    // ----- validation jobs (spec 7.6) -----

    /// Ask the tree which block it would apply next for `trigger`, then —
    /// if every body that job needs is cached — emit the `Validate` for it.
    ///
    /// The tree's own `applicationStep` would walk several blocks in one
    /// call; the processor runs exactly one validation per job, so the
    /// probe below drives `process` with an `apply` that always fails,
    /// which leaves the tree untouched and only reports *which* block was
    /// asked about. The real application happens in [`Self::on_validation`].
    fn pump(&mut self, ordering_id: OrderingId, trigger: InputBlockId, out: &mut Vec<Effect>) {
        if self.in_flight.is_some() {
            self.defer_trigger(ordering_id, trigger, false);
            return;
        }
        // Scala `applyInputBlockTransactions`: nothing is processed for an
        // ordering block that is not the best full block.
        if self.best.ordering_id != Some(ordering_id) {
            return;
        }
        let Some(tree) = self.trees.get(&ordering_id).cloned() else {
            return;
        };
        let requested = {
            let tx_refs = &self.tx_refs;
            let has_txs = |x: &InputBlockId| tx_refs.contains_key(x);
            let mut req: Option<(InputBlockId, Vec<InputBlockId>)> = None;
            let mut probe = |x: &InputBlockId, prev: &[InputBlockId]| -> Result<u64, ()> {
                if req.is_none() {
                    req = Some((*x, prev.to_vec()));
                }
                Err(())
            };
            tree.process(&trigger, &has_txs, &mut probe);
            req
        };
        let Some((target, prev_chain)) = requested else {
            return;
        };
        let Some(txs) = self.tx_refs.get(&target).cloned() else {
            return;
        };
        // Spec 7.5: a combination that already failed validation for this
        // block is not offered again. Without this a peer could re-deliver
        // the same rejected bodies to make the node re-run the job
        // forever; the witness-variant retry swaps in an untried
        // combination instead, so a legitimate retry is unaffected. No
        // effect is emitted — the rejection was already reported once,
        // when the job actually failed, and re-selection reaches this
        // point on every subsequent event.
        if self.has_failed_combination(&target, &txs) {
            tracing::debug!("skipping a transaction combination that already failed");
            return;
        }
        // The block has spent its validation budget; no combination of
        // its bodies is offered again. Reported here — at the dispatch
        // guard — and not only after a failure, so the give-up is visible
        // however the block reaches it; `report_validation_exhausted`
        // keeps it to once per block, because re-selection reaches this
        // point on every later event.
        if self.validation_exhausted(&target) {
            tracing::debug!("skipping a block that has spent its validation budget");
            self.report_validation_exhausted(target, out);
            return;
        }
        let mut previous: Vec<TxRef> = Vec::new();
        for pid in &prev_chain {
            match self.tx_refs.get(pid) {
                Some(v) => previous.extend(v.iter().copied()),
                None => {
                    if self.reported_evicted.insert(*pid) {
                        out.push(Effect::Dropped {
                            id: *pid,
                            reason: DropReason::CacheEvicted,
                        });
                    }
                    return;
                }
            }
        }
        // Spec 7.4: a job whose bodies are no longer cached cannot run,
        // and the chain cannot progress past that block.
        if txs
            .iter()
            .chain(previous.iter())
            .any(|r| !self.cache.contains(r))
        {
            if self.reported_evicted.insert(target) {
                out.push(Effect::Dropped {
                    id: target,
                    reason: DropReason::CacheEvicted,
                });
            }
            return;
        }
        self.reported_evicted.remove(&target);
        for pid in &prev_chain {
            self.reported_evicted.remove(pid);
        }
        let job = self.next_job;
        self.next_job += 1;
        if self.issued.len() >= self.bounds.retired_jobs {
            self.issued.shift_remove_index(0);
        }
        self.issued.insert(job, target);
        // The budget buys *dispatched* work. A job that a later delivery
        // invalidates through `set_tx_refs` still cost the node a full
        // block validation, so charging only accepted failure results
        // would let a peer spray witnesses and keep reissuing jobs with
        // the counter stuck at one.
        *self.validation_attempts.entry(target).or_insert(0) += 1;
        // This dispatch spent the block's last validation: invite the
        // announcer now, while the job runs, so its answer can be held
        // and used the moment the job fails (residual fix round 2, B).
        if self.validation_exhausted(&target) {
            self.invite_recovery(target, out);
        }
        self.in_flight = Some(InFlight {
            job,
            generation: self.generation,
            id: target,
            trigger,
            ordering_id,
            txs: txs.clone(),
            prev_chain,
        });
        out.push(Effect::Validate {
            job,
            generation: self.generation,
            input_block_id: target,
            txs,
            previous,
        });
    }

    /// Whether `id` has spent its per-block validation budget (spec 7.4's
    /// `validation_retries_per_block`).
    fn validation_exhausted(&self, id: &InputBlockId) -> bool {
        let budget = self.bounds.validation_retries_per_block + self.granted(id).1;
        self.validation_attempts
            .get(id)
            .is_some_and(|n| *n >= budget)
    }

    /// Recovery allowances already granted to `id`, as
    /// `(digest, validation)`.
    fn granted(&self, id: &InputBlockId) -> (usize, usize) {
        self.recovery_granted.get(id).copied().unwrap_or((0, 0))
    }

    /// Whether `id` has spent its per-block ordered-digest budget
    /// (spec 7.5's `digest_attempts_per_block`).
    fn digest_exhausted(&self, id: &InputBlockId) -> bool {
        let budget = self.bounds.digest_attempts_per_block + self.granted(id).0;
        self.digest_attempts.get(id).is_some_and(|n| *n >= budget)
    }

    /// Report a spent digest budget once per block. Spec 7.6's
    /// re-selection reaches an exhausted block on every later event, so
    /// an unguarded report would repeat forever.
    fn report_digest_exhausted(&mut self, id: InputBlockId, out: &mut Vec<Effect>) {
        if self.reported_digest_exhausted.insert(id) {
            out.push(Effect::Dropped {
                id,
                reason: DropReason::DigestBudgetExhausted,
            });
        }
    }

    /// Report a spent validation budget once per block, for the same
    /// reason as [`Self::report_digest_exhausted`].
    fn report_validation_exhausted(&mut self, id: InputBlockId, out: &mut Vec<Effect>) {
        if self.reported_validation_exhausted.insert(id) {
            out.push(Effect::Dropped {
                id,
                reason: DropReason::ValidationBudgetExhausted,
            });
        }
    }

    /// Queue an application trigger for `resume` to pick up. `front`
    /// places it ahead of the queue — used for a job that was
    /// invalidated mid-flight, whose selection should be the first thing
    /// retried.
    fn defer_trigger(&mut self, ordering_id: OrderingId, trigger: InputBlockId, front: bool) {
        if self.pending_triggers.contains(&(ordering_id, trigger)) {
            return;
        }
        if self.pending_triggers.len() >= self.bounds.pending_triggers {
            self.pending_triggers.pop_front();
        }
        if front {
            self.pending_triggers.push_front((ordering_id, trigger));
        } else {
            self.pending_triggers.push_back((ordering_id, trigger));
        }
    }

    fn on_validation(
        &mut self,
        job: JobId,
        generation: u64,
        outcome: ValidationOutcome,
        out: &mut Vec<Effect>,
    ) {
        let Some(inf) = self.in_flight.clone() else {
            // The job was invalidated by a generation bump, which clears
            // `in_flight`. The block it was validating is still named by
            // the retired-job index, so the drop carries the *stale*
            // job's subject rather than a zero id (residual fix round, D).
            out.push(Effect::Dropped {
                id: self.issued.get(&job).copied().unwrap_or([0u8; 32]),
                reason: DropReason::StaleValidation { generation },
            });
            return;
        };
        if inf.job != job || inf.generation != generation {
            // Never attribute a stale result to the job that happens to
            // be outstanding now: report the block and generation the
            // *stale* job was issued for (residual fix round, D).
            out.push(Effect::Dropped {
                id: self.issued.get(&job).copied().unwrap_or([0u8; 32]),
                reason: DropReason::StaleValidation { generation },
            });
            return;
        }
        self.in_flight = None;
        match outcome {
            ValidationOutcome::Valid(cost) => self.on_validation_ok(inf, cost, out),
            ValidationOutcome::Invalid(reason) => {
                tracing::debug!(%reason, "input block validation failed");
                self.on_validation_failed(inf, out)
            }
            ValidationOutcome::Unavailable(reason) => {
                tracing::debug!(%reason, "input block validation unavailable");
                self.on_validation_unavailable(inf, out)
            }
        }
    }

    /// The node could not run the job. The block is untouched: the
    /// combination stays untried (recording it would blacklist a
    /// perfectly valid chain head for good — a node that receives input
    /// blocks before it has applied its first full block would never
    /// validate that ordering block's chain again), and the attempt the
    /// dispatch charged is refunded. No retry is armed here: re-selection
    /// reaches this block on the next event, by which time the node may
    /// be able to run the job. Arming one would spin inside a single
    /// effect batch while the condition holds.
    fn on_validation_unavailable(&mut self, inf: InFlight, out: &mut Vec<Effect>) {
        if let Some(n) = self.validation_attempts.get_mut(&inf.id) {
            *n = n.saturating_sub(1);
        }
        out.push(Effect::Dropped {
            id: inf.id,
            reason: DropReason::ValidationUnavailable,
        });
    }

    fn on_validation_ok(&mut self, inf: InFlight, cost: u64, out: &mut Vec<Effect>) {
        // Fix round 1, finding 4: the job froze the bodies it was handed.
        // `set_tx_refs` normally invalidates a job the moment they change,
        // so this is the belt to that braces — it also covers a selection
        // that moved through any path that did not go through `pump`.
        if self.tx_refs.get(&inf.id).map(|v| v.as_slice()) != Some(inf.txs.as_slice()) {
            out.push(Effect::Dropped {
                id: inf.id,
                reason: DropReason::StaleValidation {
                    generation: inf.generation,
                },
            });
            self.pump(inf.ordering_id, inf.trigger, out);
            if self.in_flight.is_none() {
                self.resume(inf.ordering_id, out);
            }
            return;
        }
        let Some(tree) = self.trees.get(&inf.ordering_id).cloned() else {
            return;
        };
        let target = inf.id;
        let outcome = {
            let tx_refs = &self.tx_refs;
            let has_txs = |x: &InputBlockId| tx_refs.contains_key(x);
            // One step only: every other id the tree offers fails, which
            // stops `applicationStep`'s internal walk after this block.
            let mut apply = |x: &InputBlockId, _prev: &[InputBlockId]| -> Result<u64, ()> {
                if *x == target {
                    Ok(cost)
                } else {
                    Err(())
                }
            };
            tree.process(&inf.trigger, &has_txs, &mut apply)
        };
        self.trees.insert(inf.ordering_id, outcome.tree);
        // Applied: its references are frozen for good, so nothing held
        // for it can ever be taken.
        self.held.remove(&inf.id);
        let key = (inf.ordering_id, inf.trigger);
        if self.continuation.as_ref().map(|(k, _)| *k) != Some(key) {
            self.continuation = Some((key, std::collections::HashSet::new()));
        }
        let mut rolled_back = outcome.rolled_back;
        if let Some((_, reported)) = self.continuation.as_mut() {
            rolled_back.retain(|id| reported.insert(*id));
        }
        if !outcome.applied.is_empty() || !rolled_back.is_empty() {
            out.push(Effect::ChainChanged {
                ordering_id: inf.ordering_id,
                applied: outcome.applied,
                rolled_back,
            });
            self.generation += 1;
        }
        // Scala's `applicationStep` keeps walking the fork it just
        // advanced; here each step is its own job, so the walk continues
        // by re-driving the same trigger. When that yields nothing — the
        // ordinary linear case, where the trigger has just been consumed
        // — fall back to spec 7.6's re-selection.
        self.pump(inf.ordering_id, inf.trigger, out);
        if self.in_flight.is_none() {
            self.resume(inf.ordering_id, out);
        }
    }

    /// Spec 7.5's witness-variant retry: swap in the next digest-consistent
    /// combination that has not already failed and re-run it; when the
    /// combinations are exhausted the fork simply stops progressing
    /// (Scala: application failure).
    fn on_validation_failed(&mut self, inf: InFlight, out: &mut Vec<Effect>) {
        let id = inf.id;
        let budget = self.bounds.validation_retries_per_block;
        self.failed_trigger
            .insert(id, (inf.ordering_id, inf.trigger));
        // The attempt itself was charged when the job was dispatched.
        let exhausted = self.validation_exhausted(&id);
        // Bounded by the budget: once no further combination will be
        // offered there is nothing left to compare against.
        let rejected = self.failed.entry(id).or_default();
        if rejected.len() < budget {
            rejected.push(inf.txs.clone());
        }
        // Selections proposed while this job was outstanding were held
        // rather than swapped under it; the failure is what they were
        // waiting for (residual fix round 2, items B and C/D). The
        // newest is tried first, and one that no longer works — already
        // rejected, or an allowance that is gone — leaves the rest in
        // place for the failures after this one (residual fix round 3).
        while let Some(held) = self.held.get_mut(&id).and_then(|h| h.pop()) {
            if self.held.get(&id).is_some_and(|h| h.is_empty()) {
                self.held.remove(&id);
            }
            if self.take_held(id, held, inf.ordering_id, inf.trigger, out) {
                if self.in_flight.is_none() {
                    self.resume(inf.ordering_id, out);
                }
                return;
            }
        }
        if exhausted {
            self.report_validation_exhausted(id, out);
            if self.in_flight.is_none() {
                self.resume(inf.ordering_id, out);
            }
            return;
        }
        // A delivery that widened the variant lists while this job was
        // outstanding could not act on the expansion — the selection was
        // settled. Its restart is consumed here instead, so combinations
        // that became reachable behind the cursor are not stepped past.
        let restart = self.take_pending_restart(&id);
        match self.next_untried_combination(id, restart) {
            Some(refs) => {
                self.set_tx_refs(id, refs, out);
                // Fix round 1, finding 5c: the retry re-runs the same
                // *selection* the failed job came from, so a fork switch
                // stays a fork switch. Driving it with the block's own id
                // would collapse a deep-trigger switch into the linear
                // branch and stall the fork.
                self.pump(inf.ordering_id, inf.trigger, out);
            }
            None => {
                let reason = if self
                    .staging
                    .get(&id)
                    .is_some_and(|st| st.had_alternatives())
                {
                    DropReason::WitnessCombinationsExhausted
                } else {
                    DropReason::ValidationFailed
                };
                out.push(Effect::Dropped { id, reason });
            }
        }
        // Fix round 1, finding 5b: a terminal failure still has to service
        // whatever was deferred while this job held the single slot.
        if self.in_flight.is_none() {
            self.resume(inf.ordering_id, out);
        }
    }

    /// Spec 7.6's re-selection: on the active tree, take the selected
    /// fork's `first_to_complete()` and validate it when its bodies are
    /// available; otherwise work through the triggers deferred while a job
    /// was in flight.
    ///
    /// Triggers are consumed one at a time and the loop stops the moment a
    /// job starts, so everything behind it stays queued (fix round 1,
    /// finding 5a).
    fn resume(&mut self, ordering_id: OrderingId, out: &mut Vec<Effect>) {
        if self.in_flight.is_some() {
            return;
        }
        let next = self.trees.get(&ordering_id).and_then(|tree| {
            tree.best_index()
                .or_else(|| tree.longest_index())
                .and_then(|i| tree.forks[i].first_to_complete())
        });
        if let Some(n) = next {
            if self.tx_refs.contains_key(&n) {
                self.pump(ordering_id, n, out);
                if self.in_flight.is_some() {
                    return;
                }
            }
        }
        while let Some((oid, trigger)) = self.pending_triggers.pop_front() {
            self.pump(oid, trigger, out);
            if self.in_flight.is_some() {
                return;
            }
        }
    }

    // ----- ordering blocks (spec 7.6, 9.3) -----

    fn on_ordering_announcement(
        &mut self,
        ann: OrderingBlockAnnouncement,
        from: PeerTag,
        ctx: &ProcessorCtx<'_>,
        out: &mut Vec<Effect>,
    ) {
        let Ok((_, mid)) = ergo_ser::header::serialize_header(&ann.header) else {
            tracing::debug!("ordering-block announcement header does not serialize");
            return;
        };
        let header_id: OrderingId = *mid.as_bytes();
        // Spec 9.3 / Scala `processOrderingBlockAnnouncement`: the ±2
        // height window and the known-header skip come FIRST, before any
        // PoW verification, before the store and before the relay.
        // Without them a peer can replay valid historical announcements
        // and buy, per frame, a PoW verification, an `Inv` broadcast to
        // every eligible peer, and the eviction of a useful entry from
        // the bounded announcement store.
        let height = ann.header.height;
        let full = ctx.full_block_height;
        if height > full.saturating_add(2) || height.saturating_add(2) < full {
            out.push(Effect::Dropped {
                id: header_id,
                reason: DropReason::OutsideHeightWindow,
            });
            return;
        }
        if (ctx.header_known)(&header_id) || self.ordering.get(&header_id).is_some() {
            out.push(Effect::Dropped {
                id: header_id,
                reason: DropReason::OrderingHeaderKnown,
            });
            return;
        }
        let expected = (ctx.expected_n_bits)(ann.header.parent_id.as_bytes());
        if let Err(e) = crate::announcement::validate_ordering_announcement(&ann, expected) {
            tracing::debug!(error = %e, "invalid ordering-block announcement");
            out.push(Effect::Penalize {
                from,
                reason: "invalid ordering-block announcement",
            });
            return;
        }

        let prev = ann
            .extension_fields
            .iter()
            .find(|(k, _)| *k == ergo_ser::input_block::PREV_INPUT_BLOCK_ID_KEY)
            .and_then(|(_, v)| <[u8; 32]>::try_from(v.as_slice()).ok());
        let non_broadcasted = ann.non_broadcasted_transactions.clone();
        let broadcasted_ids = ann.broadcasted_transaction_ids.clone();
        let parent_id: OrderingId = *ann.header.parent_id.as_bytes();

        if let Some(evicted) =
            self.ordering
                .insert(header_id, ann, self.bounds.ordering_announcements)
        {
            out.push(Effect::Dropped {
                id: evicted,
                reason: DropReason::OrderingAnnouncementsFull,
            });
        }
        out.push(Effect::RelayOrderingInv { header_id });

        let (chain_txs, chain_key) = self.collected_input_txs_for_announced(&header_id, &parent_id);
        match prev {
            Some(p) if self.tx_refs.contains_key(&p) => {
                out.push(Effect::OrderingReconstruct {
                    from,
                    plan: ReconstructionPlan {
                        header_id,
                        non_broadcasted,
                        broadcasted_ids,
                        // Divergence D5, upstream finding F5. Scala's
                        // follower keys the collected input-chain
                        // transactions by the *announced* header's own id
                        // (`getCollectedInputBlocksTransactions(headerId)`)
                        // while its miner seats the chain collected under
                        // the PARENT
                        // (`getBestOrderingCollectedInputBlocksTransactions`,
                        // which reads `bestOrderingBlock().id`). The trees
                        // are keyed by the block the input chain sits ON,
                        // so the follower's key names a block that has no
                        // tree yet and the lookup returns nothing — which
                        // is what the devnet smoke measured: every
                        // reconstruction ran with an EMPTY input chain and
                        // could not reproduce the root of any block whose
                        // transactions came from input blocks.
                        //
                        // Scala's key is tried first; the parent's is the
                        // fallback, so a chain genuinely recorded under
                        // the announced id still wins. Delete the fallback
                        // when upstream settles F5.
                        input_chain_txs: chain_txs,
                        reconstruction_key: chain_key,
                        prev_input_block_id: Some(p),
                    },
                });
            }
            _ => {
                self.request(
                    out,
                    Effect::RequestBlockTransactions { header_id, from },
                    from,
                    header_id,
                );
            }
        }
    }

    fn on_ordering(
        &mut self,
        header_id: OrderingId,
        height: u32,
        reorg: bool,
        ctx: &ProcessorCtx<'_>,
        out: &mut Vec<Effect>,
    ) {
        self.set_best_ordering(Some(header_id), height);
        self.generation += 1;
        // Spec 7.6: the bump invalidates any in-flight job.
        self.in_flight = None;
        self.pending_triggers.clear();
        if reorg {
            // Trees keyed by a header that is no longer on the best chain
            // are unreachable; only the new best chain's tree survives.
            self.trees.retain(|k, _| *k == header_id);
            self.tree_heights.retain(|k, _| *k == header_id);
        }
        self.prune(ctx);
        out.push(Effect::ChainChanged {
            ordering_id: header_id,
            applied: Vec::new(),
            rolled_back: Vec::new(),
        });
        // Before `resume`: the held announcements are what give the new
        // tree its root, and selection has nothing to resume without
        // them.
        self.replay_ahead(header_id, self.now, ctx, out);
        self.resume(header_id, out);
    }

    /// Hold an announcement for the ordering block one ahead of us, so
    /// [`Self::replay_ahead`] can offer it again the moment that block
    /// is applied. Bounded; the oldest entry is dropped on overflow.
    fn hold_ahead(
        &mut self,
        id: InputBlockId,
        ordering_id: OrderingId,
        height: u32,
        ann: InputBlockAnnouncement,
        from: PeerTag,
        out: &mut Vec<Effect>,
    ) {
        if self.ahead.contains_key(&id) {
            return;
        }
        while self.ahead.len() >= self.bounds.waitlist_entries {
            let Some((old, _)) = self.ahead.shift_remove_index(0) else {
                break;
            };
            out.push(Effect::Dropped {
                id: old,
                reason: DropReason::WaitlistFull,
            });
        }
        self.ahead.insert(
            id,
            AheadAnnouncement {
                ann,
                from,
                ordering_id,
                height,
            },
        );
    }

    /// Offer every held announcement for `header_id` again, in arrival
    /// order, now that the ordering block it belongs to is the tip.
    ///
    /// Arrival order matters: the miner publishes the chain forwards, so
    /// replaying it forwards roots the tree with the `prev = None` block
    /// and then extends it linearly. Anything at or below the new best
    /// height can never be `+1` again and is discarded here rather than
    /// left to age out.
    fn replay_ahead(
        &mut self,
        header_id: OrderingId,
        now: Tick,
        ctx: &ProcessorCtx<'_>,
        out: &mut Vec<Effect>,
    ) {
        if self.ahead.is_empty() {
            return;
        }
        let best_height = self.best.ordering_height;
        let mut due = Vec::new();
        let mut keep = indexmap::IndexMap::with_capacity(self.ahead.len());
        for (id, entry) in std::mem::take(&mut self.ahead) {
            if entry.ordering_id == header_id {
                due.push(entry);
            } else if entry.height > best_height {
                keep.insert(id, entry);
            }
        }
        self.ahead = keep;
        if due.is_empty() {
            return;
        }
        tracing::debug!(
            ordering = %HexId(&header_id),
            held = due.len(),
            "input_blocks: replaying announcements held for the new ordering block"
        );
        for entry in due {
            self.on_announcement(entry.ann, entry.from, now, ctx, out);
        }
    }

    /// Scala `prune()` (spec 2.5): trees behind the best height, records
    /// and transaction lists more than `prune_threshold` ordering blocks
    /// behind it (also cleaned out of the waitlist), and ordering
    /// announcements that are stale or already applied.
    fn prune(&mut self, ctx: &ProcessorCtx<'_>) {
        let best_height = self.best.ordering_height;
        let stale_trees: Vec<OrderingId> = self
            .trees
            .keys()
            .filter(|id| best_height > *self.tree_heights.get(*id).unwrap_or(&0))
            .copied()
            .collect();
        for id in stale_trees {
            self.trees.shift_remove(&id);
            self.tree_heights.remove(&id);
        }

        let stale_records: Vec<InputBlockId> = self
            .records
            .iter()
            .filter(|(_, r)| best_height.saturating_sub(r.height) > self.bounds.prune_threshold)
            .map(|(id, _)| *id)
            .collect();
        self.continuation = None;
        for id in stale_records {
            self.records.shift_remove(&id);
            self.tx_refs.remove(&id);
            self.staging.shift_remove(&id);
            self.waitlist.retain(|(w, _)| *w != id);
            self.failed.remove(&id);
            self.reported_evicted.remove(&id);
            self.reported_digest_exhausted.remove(&id);
            self.reported_validation_exhausted.remove(&id);
            self.digest_attempts.remove(&id);
            self.held.remove(&id);
            self.invited.remove(&id);
            self.pending_invitations.remove(&id);
            self.recovery_granted.remove(&id);
            self.validation_attempts.remove(&id);
            self.failed_trigger.remove(&id);
        }

        self.ordering.prune(
            best_height,
            self.bounds.ordering_announcement_prune_threshold,
            ctx.block_transactions_known,
        );
    }

    fn on_tick(&mut self, now: Tick, out: &mut Vec<Effect>) {
        self.cache.expire(now, self.bounds.tx_cache_ttl_ms);
        let ttl = self.bounds.staging_ttl_ms;
        let expired: Vec<InputBlockId> = self
            .staging
            .iter()
            .filter(|(_, s)| s.variants.is_none() && now.0.saturating_sub(s.created.0) > ttl)
            .map(|(id, _)| *id)
            .collect();
        for id in expired {
            self.staging.shift_remove(&id);
        }
        // Outstanding requests expire at an explicit deadline. A request
        // that timed out is REISSUED to the same peer, with the deadline
        // doubled per attempt, until `Bounds::request_retries` is spent;
        // only then is the slot released. One that answers is credited
        // immediately by the matching delivery (residual fix round, D).
        //
        // This is spec 9.2's retry contract and it has to live here: the
        // coordinator forgets timed-out input-block requests without
        // re-requesting (parity — Scala's `checkDelivery` applies no
        // NonDelivery penalty), so without a reissue a lost reply was
        // terminal. Repeated announcements of the recorded block hit
        // `AlreadyKnown` and never asked again.
        //
        // A reissue is a request like any other, so it obeys
        // `requests_per_peer`: expired slots are offered oldest first
        // and only while that peer has room on the wire. One that does
        // not fit stays queued exactly as it is — same attempts, same
        // past deadline — and the next tick offers it again. Reissuing
        // unconditionally would put more requests in flight than the
        // operator allowed (with a cap of one: A expires, B takes the
        // slot, and the tick then adds A back on top of it).
        let timeout = self.bounds.request_timeout_ms;
        let retries = self.bounds.request_retries;
        let cap = self.bounds.requests_per_peer;
        let mut reissued = Vec::new();
        self.outstanding.retain(|_, slots| {
            // A slot whose retry budget is spent is finished whatever
            // the capacity: nothing will ask for it again.
            slots.retain(|p| p.deadline.0 > now.0 || p.attempts <= retries);
            let mut live = slots.iter().filter(|p| p.deadline.0 > now.0).count();
            for p in slots.iter_mut() {
                if live >= cap {
                    break;
                }
                if p.deadline.0 > now.0 {
                    continue;
                }
                let shift = (p.attempts - 1).min(REQUEST_BACKOFF_SHIFT_CAP);
                p.deadline = Tick(now.0.saturating_add(timeout.saturating_mul(1u64 << shift)));
                // Only an ACTUAL reissue costs an attempt and counts as
                // a retry; a request held back for capacity has not
                // been asked again.
                p.attempts += 1;
                live += 1;
                reissued.push(p.effect.clone());
            }
            !slots.is_empty()
        });
        self.requests_retried = self.requests_retried.saturating_add(reissued.len() as u64);
        out.extend(reissued);
        // Slots the sweep freed may be what a deferred invitation needs.
        self.retry_invitations(None, out);
    }

    /// Issue `effect` to `peer` unless that peer is already at the
    /// outstanding-request cap (spec 7.4).
    ///
    /// A slot is a question this node is still pursuing. It is released
    /// by the delivery that answers it ([`Self::request_answered`]) or,
    /// if the peer never answers, by the [`Event::Tick`] sweep once the
    /// request's retry budget is spent — NOT merely by its deadline
    /// passing. A slot past its deadline is awaiting reissue, and this
    /// function must leave it alone: pruning expired slots here meant
    /// any request to the same peer between a deadline and the next tick
    /// deleted the timed-out request outright, so it was never reissued
    /// and later announcements of its recorded child hit `AlreadyKnown`.
    ///
    /// `requests_per_peer` still bounds the requests genuinely IN
    /// FLIGHT, so a retry-pending slot does not hold a live one. It must
    /// not: a retry ladder keeps a slot for minutes, and counting those
    /// against the in-flight cap starved a follower of body requests
    /// under a miner publishing an input block a second (measured on the
    /// devnet smoke: 128 `RequestsFull` drops, the input chain unable to
    /// keep up). `retry_pending_per_peer` bounds the queue separately,
    /// so nothing grows without limit if ticks stall; at that ceiling a
    /// new request is REFUSED, never an old one deleted.
    ///
    /// A request that is already outstanding is **not** re-emitted: spec
    /// 7.6's re-selection reaches the same unresolved block on every
    /// event, and re-emitting without allocating a slot let a peer be
    /// asked the same question arbitrarily often while none of the
    /// answers arrived (residual fix round 2, D). The peer already has
    /// the question; it is dropped silently, and the deadline sweep is
    /// what eventually asks again.
    fn request(
        &mut self,
        out: &mut Vec<Effect>,
        effect: Effect,
        peer: PeerTag,
        subject: [u8; 32],
    ) -> bool {
        let deadline = Tick(self.now.0.saturating_add(self.bounds.request_timeout_ms));
        let key = RequestKey::of(&effect);
        let now = self.now;
        let cap = self.bounds.requests_per_peer;
        let ceiling = cap.saturating_add(self.bounds.retry_pending_per_peer);
        let slots = self.outstanding.entry(peer).or_default();
        if let Some(k) = key {
            if slots.iter().any(|p| p.key == k) {
                return false;
            }
        }
        let live = slots.iter().filter(|p| p.deadline.0 > now.0).count();
        if live >= cap || slots.len() >= ceiling {
            out.push(Effect::Dropped {
                id: subject,
                reason: DropReason::RequestsFull,
            });
            return false;
        }
        // An effect that is not a request holds no slot; nothing to
        // track — and nothing to reissue either.
        if let Some(k) = key {
            slots.push(Pending {
                key: k,
                deadline,
                effect: effect.clone(),
                attempts: 1,
            });
        }
        out.push(effect);
        true
    }

    /// Release the slot a delivery answers. Returns whether the delivery
    /// was in fact solicited from that peer — the announcer-recovery
    /// allowance of the residual fix round (B) needs that distinction.
    /// Release the body request `delivered` answers: the one for this
    /// block that asked for exactly this weak-id set.
    ///
    /// Matching on the block alone let an answer to one set free the
    /// slots still owed for every other set — and a body delivery that
    /// answered nothing at all free them too, because completion is
    /// decided before the bodies are looked at (residual fix round 3).
    /// A set that was only partly answered keeps its slot until its
    /// deadline: the question has not been answered.
    fn bodies_answered(&mut self, peer: PeerTag, id: InputBlockId, delivered: &[Body]) -> bool {
        let weak: Vec<WeakId> = delivered.iter().map(|b| b.weak_id).collect();
        let answered_key = RequestKey::Transactions(id, weak_set_hash(&weak));
        let Some(slots) = self.outstanding.get_mut(&peer) else {
            return false;
        };
        let before = slots.len();
        slots.retain(|p| p.key != answered_key);
        let answered = slots.len() < before;
        if slots.is_empty() {
            self.outstanding.remove(&peer);
        }
        answered
    }

    /// Whether a body request for `id` is currently outstanding to
    /// `peer`. With [`Self::bodies_answered`] this is the whole of
    /// "solicited": a request that is outstanding now, or one this very
    /// delivery answered — never a historical one (residual fix round 2,
    /// ruling B).
    fn bodies_requested(&self, peer: PeerTag, id: InputBlockId) -> bool {
        self.outstanding.get(&peer).is_some_and(|slots| {
            slots
                .iter()
                .any(|p| matches!(p.key, RequestKey::Transactions(b, _) if b == id))
        })
    }

    fn request_answered(&mut self, peer: PeerTag, key: RequestKey) -> bool {
        let Some(slots) = self.outstanding.get_mut(&peer) else {
            return false;
        };
        let before = slots.len();
        slots.retain(|p| p.key != key);
        let answered = slots.len() < before;
        if slots.is_empty() {
            self.outstanding.remove(&peer);
        }
        answered
    }

    // ----- read side (API and p2p serving, Plan 2) -----

    /// The ordering block [`Self::best_input_chain`] and
    /// [`Self::best_input_block`] are read against.
    ///
    /// The REST routes need this to publish a COHERENT pair. Reading the
    /// ordering id from the chain store instead — which is what
    /// `/blocks/bestInputChain` did, and what Scala's own route does —
    /// pairs a freshly-applied ordering block with a chain the processor
    /// has not yet moved to, so for a second after every ordering block
    /// the endpoint reports the PREVIOUS block's input chain under the
    /// NEW block's id. Nothing downstream can tell that apart from a
    /// history disagreement.
    pub fn best_ordering_id(&self) -> Option<OrderingId> {
        self.best.ordering_id
    }

    /// Scala `bestInputBlock()`.
    pub fn best_input_block(&self) -> Option<&InputBlockAnnouncement> {
        let oid = self.best.ordering_id?;
        let tip = self.trees.get(&oid)?.best_tip()?;
        self.records.get(&tip).map(|r| &r.ann)
    }

    /// Scala `bestInputBlocksChain()` — tip first.
    pub fn best_input_chain(&self) -> Vec<InputBlockId> {
        let Some(oid) = self.best.ordering_id else {
            return Vec::new();
        };
        match self.trees.get(&oid) {
            Some(tree) => {
                let mut c = tree.best_chain();
                c.reverse();
                c
            }
            None => Vec::new(),
        }
    }

    /// Every input-block id the processor currently holds a RECORD for —
    /// not merely the ones on [`Self::best_input_chain`]. A losing fork's
    /// block is retained (subject to spec 7.4's `records_per_ordering`
    /// bound) until it is superseded or TTL'd, and Scala can still answer
    /// `getInputBlockTransactions`/`Ids` for it over that window; this is
    /// the accessor a node-side REST bridge uses to serve the same query
    /// (fix-round-1, finding 2). Bounded by the same cap `records`
    /// itself is bounded by — no unbounded enumeration surface.
    pub fn known_input_block_ids(&self) -> Vec<InputBlockId> {
        self.records.keys().copied().collect()
    }

    /// Requests the deadline sweep reissued since start (spec 9.2's
    /// retry contract). Published on the operator status breakdown as
    /// `RequestRetried`.
    pub fn requests_retried(&self) -> u64 {
        self.requests_retried
    }

    /// Monotonic revision counter, bumped once per [`Self::handle`] call.
    /// See the field doc on [`Processor::revision`] for what it does and
    /// does not guarantee. Consumers compare this across calls to detect
    /// a state change even when the call produced no [`Effect`] at all.
    pub fn revision(&self) -> u64 {
        self.revision
    }

    /// The parent input block an announcement claims, as recorded
    /// (`InputBlockAnnouncement.prevInputBlockId`). The node serves this
    /// when answering `−123` requests without re-parsing the proof.
    pub fn prev_input_block(&self, id: &InputBlockId) -> Option<InputBlockId> {
        self.records.get(id).and_then(|r| r.prev)
    }

    /// Scala `getInputBlock`.
    pub fn announcement(&self, id: &InputBlockId) -> Option<&InputBlockAnnouncement> {
        self.records.get(id).map(|r| &r.ann)
    }

    /// Scala `getInputBlockTransactionIds`, in `TxRef` form.
    pub fn transaction_refs(&self, id: &InputBlockId) -> Option<&[TxRef]> {
        self.tx_refs.get(id).map(|v| v.as_slice())
    }

    /// Scala `getInputBlockTransactionWeakIds`.
    pub fn weak_ids(&self, id: &InputBlockId) -> Option<Vec<WeakId>> {
        self.tx_refs
            .get(id)
            .map(|v| v.iter().map(|r| r.weak_id()).collect())
    }

    /// One body by its `TxRef`, for the node to resolve a
    /// [`Effect::Validate`]'s `txs` / `previous` lists without keeping a
    /// second copy of the cache. `None` once the body has been evicted.
    pub fn body(&self, tx_ref: &TxRef) -> Option<&Body> {
        self.cache.get(tx_ref)
    }

    /// Put `bodies` straight into the transaction cache, bypassing the
    /// announce/deliver/validate path.
    ///
    /// Test support only: it exists so a reconstruction test can name
    /// input-chain transactions in a `ReconstructionPlan` without
    /// driving a whole input chain through the processor first. Nothing
    /// in production reaches the cache this way.
    #[cfg(any(test, feature = "test-support"))]
    pub fn seat_bodies_for_test(&mut self, bodies: Vec<Body>) {
        for body in bodies {
            self.cache.insert(body, Tick(0), &self.bounds);
        }
    }

    /// Scala `getInputBlockTransactions` — silently skips bodies the
    /// cache has evicted, exactly as Scala's `getIfPresent` loop does.
    pub fn bodies(&self, id: &InputBlockId) -> Option<Vec<&Body>> {
        self.tx_refs
            .get(id)
            .map(|v| v.iter().filter_map(|r| self.cache.get(r)).collect())
    }

    /// Scala `getInputBlockTransactions(id, toFilter)`.
    pub fn bodies_by_weak_ids(&self, id: &InputBlockId, filter: &[WeakId]) -> Option<Vec<&Body>> {
        self.bodies(id).map(|v| {
            v.into_iter()
                .filter(|b| filter.contains(&b.weak_id))
                .collect()
        })
    }

    /// Scala `getOrderingBlockAnnouncement`.
    pub fn ordering_announcement(
        &self,
        header_id: &OrderingId,
    ) -> Option<&OrderingBlockAnnouncement> {
        self.ordering.get(header_id)
    }

    /// Scala `getCollectedInputBlocksTransactions`: the best chain's
    /// transactions for one ordering block, oldest block first.
    pub fn collected_input_txs(&self, ordering_id: &OrderingId) -> Vec<TxRef> {
        let Some(tree) = self.trees.get(ordering_id) else {
            return Vec::new();
        };
        tree.best_chain()
            .iter()
            .filter_map(|id| self.tx_refs.get(id))
            .flat_map(|v| v.iter().copied())
            .collect()
    }

    /// The collected input-chain transactions an ANNOUNCED ordering
    /// block should be reconstructed from: Scala's key (the announced
    /// header's own id) if it has a tree, else the parent's — the block
    /// the input chain actually sits on, and what the miner seated.
    /// Divergence D5 / upstream finding F5.
    pub fn collected_input_txs_for_announced(
        &self,
        header_id: &OrderingId,
        parent_id: &OrderingId,
    ) -> (Vec<TxRef>, crate::ordering::ReconstructionKey) {
        use crate::ordering::ReconstructionKey;
        if self.trees.contains_key(header_id) {
            return (
                self.collected_input_txs(header_id),
                ReconstructionKey::SelfId,
            );
        }
        (
            self.collected_input_txs(parent_id),
            ReconstructionKey::Parent,
        )
    }

    /// Number of competing forks retained for `ordering_id`.
    pub fn forks(&self, ordering_id: &OrderingId) -> usize {
        self.trees.get(ordering_id).map_or(0, |t| t.forks.len())
    }

    /// Bytes currently held in staging slots (spec 7.4).
    pub fn staged_bytes(&self) -> usize {
        self.staging.values().map(|s| s.bytes).sum()
    }

    /// Scala `disconnectedWaitlist.size`.
    pub fn waitlist_len(&self) -> usize {
        self.waitlist.len()
    }

    /// Whether this exact transaction *combination* has already failed
    /// validation for `id` (spec 7.5). Combination-level, not per-body: a
    /// block whose first witness choice failed must still be able to
    /// retry with a different witness for the offending position without
    /// the other, innocent, transactions being treated as failed too.
    pub fn has_failed_combination(&self, id: &InputBlockId, txs: &[TxRef]) -> bool {
        self.failed
            .get(id)
            .is_some_and(|combos| combos.iter().any(|c| c.as_slice() == txs))
    }

    /// How many transaction combinations have been rejected by
    /// validation for `id`. Bounded by
    /// [`crate::bounds::Bounds::validation_retries_per_block`].
    pub fn failed_combinations(&self, id: &InputBlockId) -> usize {
        self.failed.get(id).map_or(0, |c| c.len())
    }

    /// Validation jobs dispatched for `id` so far, capped by
    /// [`crate::bounds::Bounds::validation_retries_per_block`]. Counts
    /// dispatched work, so a job later invalidated by a delivery is
    /// charged like any other.
    pub fn validation_attempts(&self, id: &InputBlockId) -> usize {
        self.validation_attempts.get(id).copied().unwrap_or(0)
    }

    /// Whether a body is currently in the shared cache — what the node
    /// can actually serve for a `105` request.
    pub fn is_cached(&self, tx_ref: &TxRef) -> bool {
        self.cache.contains(tx_ref)
    }

    /// Application triggers deferred while a validation job is in flight.
    pub fn deferred_triggers(&self) -> usize {
        self.pending_triggers.len()
    }

    /// How many witness variants are retained for each announced
    /// position of a resolved block (spec 7.4's
    /// `candidates_per_position` bound). Empty until the block's digest
    /// has passed.
    pub fn variants_per_position(&self, id: &InputBlockId) -> Vec<usize> {
        self.staging
            .get(id)
            .and_then(|s| s.variants.as_ref())
            .map(|v| v.iter().map(|p| p.len()).collect())
            .unwrap_or_default()
    }

    /// Ordered-digest combinations tried for `id` so far. Monotone over
    /// the block's whole life and capped at
    /// [`crate::bounds::Bounds::digest_attempts_per_block`] (spec 7.5).
    pub fn staged_digest_attempts(&self, id: &InputBlockId) -> usize {
        self.digest_attempts.get(id).copied().unwrap_or(0)
    }

    /// Scala `saveOrderingBlockTransactions`.
    ///
    /// Bounded by [`crate::bounds::Bounds::ordering_announcements`], the
    /// cap that already governs the announcement map: `prune` reaches a
    /// stored section only through its announcement, so a section saved
    /// for an already-evicted or never-announced ordering block needs the
    /// cap to bound it. Returns the id of the oldest section evicted, if
    /// any, so the caller can log or account for the loss.
    pub fn save_ordering_block_transactions(
        &mut self,
        header_id: OrderingId,
        txs: Vec<TxRef>,
    ) -> Option<OrderingId> {
        self.ordering
            .save_block_transactions(header_id, txs, self.bounds.ordering_announcements)
    }

    /// Scala `getOrderingBlockTransactions`.
    pub fn ordering_block_transactions(&self, header_id: &OrderingId) -> Option<&[TxRef]> {
        self.ordering.block_transactions(header_id)
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

    /// The ids a stale-validation drop named, in order.
    fn stale_ids(effects: &[Effect]) -> Vec<[u8; 32]> {
        effects
            .iter()
            .filter_map(|e| match e {
                Effect::Dropped {
                    id,
                    reason: DropReason::StaleValidation { .. },
                } => Some(*id),
                _ => None,
            })
            .collect()
    }

    fn has_validate(effects: &[Effect]) -> bool {
        effects.iter().any(|e| matches!(e, Effect::Validate { .. }))
    }

    /// Deliver an empty transaction set for `ann` — the shape an
    /// announcement that commits to no transactions takes.
    fn deliver_empty(
        p: &mut Processor,
        ctx: &ts::TestCtx,
        ann: &InputBlockAnnouncement,
        now: u64,
    ) -> Vec<Effect> {
        ctx.handle(
            p,
            Event::TransactionsDelivered {
                input_block_id: ts::ann_id(ann),
                bodies: Vec::new(),
                from: Some(ts::PEER),
                now: Tick(now),
            },
        )
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
        let ann = ts::announcement_for(ORD, FULL + 1, 1, None, std::slice::from_ref(&b1));
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

    /// Task 8b, the follower-throughput root cause.
    ///
    /// The first input block under an ordering block is the only one
    /// whose `prev_input_block_id` is `None`, so it is the only one that
    /// can root that ordering block's tree — and the miner publishes it
    /// before any follower has applied the ordering block it sits under,
    /// i.e. always at `best_full_height + 2`. Discarding it (spec 2.7
    /// step 4, and what the Scala reference does) leaves the new tree
    /// permanently rootless: every later announcement has an unknown
    /// parent and the chain has to be rebuilt backwards, one request
    /// round trip per block, against a miner publishing one a second.
    ///
    /// Red first: with the `+2` announcement discarded, `b2` below is
    /// waitlisted, the tree has no forks, and nothing is ever validated.
    #[test]
    fn an_announcement_one_ordering_block_ahead_roots_the_tree_when_that_block_lands() {
        const ORD2: OrderingId = [0xCC; 32];
        let mut p = processor();
        let mut ctx = ts::TestCtx::at(FULL);

        // Both arrive while we are still one ordering block behind: the
        // root of ORD2's chain and its first child.
        let b1 = ts::body(1, 1);
        let b2 = ts::body(2, 1);
        ctx.mempool.add(&b1);
        ctx.mempool.add(&b2);
        let root = ts::announcement_for(ORD2, FULL + 2, 1, None, std::slice::from_ref(&b1));
        let root_id = ts::ann_id(&root);
        let child =
            ts::announcement_for(ORD2, FULL + 2, 2, Some(root_id), std::slice::from_ref(&b2));
        let child_id = ts::ann_id(&child);
        let eff = announce(&mut p, &ctx, &root, ts::PEER);
        assert!(
            eff.iter()
                .any(|e| matches!(e, Effect::RequestOrderingHeader { .. })),
            "the ordering header is still requested: {eff:?}"
        );
        announce(&mut p, &ctx, &child, ts::PEER);
        assert!(
            p.best_input_chain().is_empty(),
            "nothing is applied while the ordering block is unknown"
        );

        // ORD2 lands. The held announcements are replayed in arrival
        // order, so the tree is rooted and the child extends it.
        ctx.full_block_height = FULL + 1;
        let out = ctx.handle(
            &mut p,
            Event::OrderingBlockApplied {
                header_id: ORD2,
                height: FULL + 1,
                now: Tick(1),
            },
        );
        let (_, _, target, _, _) = ts::one_validate(&out);
        assert_eq!(
            target, root_id,
            "the replayed root is what the node validates first"
        );
        let out = ts::validate_ok(&mut p, &ctx, &out, 1);
        assert_eq!(p.best_input_chain(), vec![root_id]);

        // And the child is already in the tree, so it follows without
        // another round trip to the peer.
        let (_, _, next, _, _) = ts::one_validate(&out);
        assert_eq!(next, child_id, "the child extends the rooted tree");
        ts::validate_ok(&mut p, &ctx, &out, 1);
        assert_eq!(p.best_input_chain(), vec![child_id, root_id]);
    }

    /// The hold is bounded and does not outlive its usefulness: an
    /// entry for an ordering block the chain has moved past is dropped
    /// rather than replayed or kept.
    #[test]
    fn held_announcements_are_discarded_once_their_height_is_behind_us() {
        const ORD2: OrderingId = [0xCC; 32];
        const ORD3: OrderingId = [0xDD; 32];
        let mut p = processor();
        let mut ctx = ts::TestCtx::at(FULL);
        let stale = ts::announcement(ORD2, FULL + 2, 1, None);
        announce(&mut p, &ctx, &stale, ts::PEER);

        // Two ordering blocks land at once: ORD2's held announcement is
        // now at or below the best height and can never be `+1` again.
        ctx.full_block_height = FULL + 2;
        let out = ctx.handle(
            &mut p,
            Event::OrderingBlockApplied {
                header_id: ORD3,
                height: FULL + 2,
                now: Tick(1),
            },
        );
        assert!(
            !out.iter().any(|e| matches!(e, Effect::Validate { .. })),
            "a stale held announcement is not replayed: {out:?}"
        );
        assert!(p.ahead.is_empty(), "and it is not kept either");
    }

    /// The hold is capped: a peer cannot make the node retain an
    /// unbounded number of announcements for an ordering block it never
    /// applies.
    #[test]
    fn held_announcements_are_capped_and_report_the_overflow() {
        const ORD2: OrderingId = [0xCC; 32];
        let bounds = Bounds {
            waitlist_entries: 2,
            ..Bounds::default()
        };
        let mut p = processor_with(bounds);
        let ctx = ts::TestCtx::at(FULL);
        let first = ts::announcement(ORD2, FULL + 2, 1, None);
        let first_id = ts::ann_id(&first);
        announce(&mut p, &ctx, &first, ts::PEER);
        announce(
            &mut p,
            &ctx,
            &ts::announcement(ORD2, FULL + 2, 2, None),
            ts::PEER,
        );
        let out = announce(
            &mut p,
            &ctx,
            &ts::announcement(ORD2, FULL + 2, 3, None),
            ts::PEER,
        );
        assert!(
            out.contains(&Effect::Dropped {
                id: first_id,
                reason: DropReason::WaitlistFull,
            }),
            "the oldest hold is dropped, and reported: {out:?}"
        );
        assert_eq!(p.ahead.len(), 2);
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
        let ann = ts::announcement_for(ORD, FULL + 1, 1, None, std::slice::from_ref(&b1));
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
        let ib = ts::announcement_for(ORD, FULL + 1, 1, None, std::slice::from_ref(&b1));
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
                Effect::OrderingReconstruct { plan, .. } => Some(plan.clone()),
                _ => None,
            })
            .unwrap_or_else(|| panic!("no OrderingReconstruct in {out:?}"));
        assert_eq!(plan.prev_input_block_id, Some(ib_id));
        // Divergence D5 / upstream finding F5. Scala's follower looks the
        // chain up under the ANNOUNCED header's own id, which has no tree
        // — the trees are keyed by the ordering block the input chain
        // sits ON, and that is the parent, which is what the miner seated
        // in front of its ordering transactions. Keying it Scala's way
        // hands the planner an EMPTY chain, so reconstruction can never
        // reproduce the root of a block whose transactions came from
        // input blocks; the devnet smoke measured exactly that.
        assert!(
            p.collected_input_txs(&oa_id).is_empty(),
            "Scala's key still names a block with no tree"
        );
        assert_eq!(
            p.collected_input_txs(&ORD),
            vec![b1.tx_ref],
            "the chain is recorded under the block it extends"
        );
        assert_eq!(
            plan.input_chain_txs,
            vec![b1.tx_ref],
            "so the plan falls back to the parent's chain"
        );
        assert_eq!(
            plan.reconstruction_key,
            crate::ordering::ReconstructionKey::Parent,
            "and the telemetry records which key answered (D5)"
        );
    }

    /// The fallback is a FALLBACK: a chain genuinely recorded under the
    /// announced id still wins, so the day upstream settles F5 the
    /// behaviour is already Scala's.
    #[test]
    fn announced_ordering_id_with_its_own_tree_is_preferred_over_the_parent() {
        let mut p = processor();
        let b1 = ts::body(1, 1);
        let mut ctx = ts::TestCtx::at(FULL);
        ctx.mempool.add(&b1);
        let ib = ts::announcement_for(ORD, FULL + 1, 1, None, std::slice::from_ref(&b1));
        let eff = announce(&mut p, &ctx, &ib, ts::PEER);
        ts::validate_ok(&mut p, &ctx, &eff, 1);
        assert_eq!(p.collected_input_txs(&ORD), vec![b1.tx_ref]);

        let no_tree: OrderingId = [0x4f; 32];
        assert!(p.collected_input_txs(&no_tree).is_empty());
        use crate::ordering::ReconstructionKey;
        // Announced id HAS a tree: Scala's key answers, the parent is
        // never consulted, and the telemetry says so.
        assert_eq!(
            p.collected_input_txs_for_announced(&ORD, &no_tree),
            (vec![b1.tx_ref], ReconstructionKey::SelfId)
        );
        // Announced id has none: the parent's chain answers.
        assert_eq!(
            p.collected_input_txs_for_announced(&no_tree, &ORD),
            (vec![b1.tx_ref], ReconstructionKey::Parent)
        );
        // Neither has one: nothing, never a panic.
        assert_eq!(
            p.collected_input_txs_for_announced(&no_tree, &[0x50; 32]),
            (Vec::new(), ReconstructionKey::Parent)
        );
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
        let ann = ts::announcement_for(ORD, FULL + 1, 1, None, std::slice::from_ref(&b1));
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

    /// A binding failure is a policy verdict, not a peer fault: the
    /// pinned Scala miner publishes announcements whose extension carries
    /// the NEW transactions digest in the `prevTransactionsDigest` slot
    /// while the announcement carries the PREVIOUS one (finding
    /// 2026-09-22-2). The announcement is dropped; the peer is not
    /// penalised, or a strict node would ban every honest miner the
    /// moment an input block carried a transaction.
    #[test]
    fn strict_binding_failure_drops_without_penalty() {
        let mut p = Processor::new(
            Bounds::default(),
            AnnouncementPolicy {
                strict_field_binding: true,
            },
        );
        p.set_best_ordering(Some(ORD), FULL);
        let ctx = ts::TestCtx::at(FULL);
        let mut ann = ts::announcement(ORD, FULL + 1, 1, None);
        // Keep the proof reducing to the header's root (the Scala-parity
        // check still passes) but make one announced field disagree with
        // the leaf the proof commits to.
        ann.fields.prev_transactions_digest = [0x5a; 32];
        let eff = announce(&mut p, &ctx, &ann, ts::PEER);
        assert_eq!(drops(&eff), vec![DropReason::FieldsUnbound]);
        assert!(
            !eff.iter().any(|e| matches!(e, Effect::Penalize { .. })),
            "a strict-policy drop must not penalise the peer: {eff:?}"
        );
        assert!(p.announcement(&ts::ann_id(&ann)).is_none());
    }

    #[test]
    fn stale_validation_result_dropped() {
        let mut p = processor();
        let b1 = ts::body(1, 1);
        let mut ctx = ts::TestCtx::at(FULL);
        ctx.mempool.add(&b1);
        let ann = ts::announcement_for(ORD, FULL + 1, 1, None, std::slice::from_ref(&b1));
        let id = ts::ann_id(&ann);
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
                outcome: ValidationOutcome::Valid(1),
            },
        );
        assert_eq!(
            drops(&out),
            vec![DropReason::StaleValidation { generation }]
        );
        assert_eq!(
            stale_ids(&out),
            vec![id],
            "the drop must name the block the stale job was validating"
        );
        assert!(!out.iter().any(|e| matches!(e, Effect::ChainChanged { .. })));
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
        let ann = ts::announcement_for(ORD, FULL + 1, 1, None, std::slice::from_ref(&real));
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
        let ann = ts::announcement_for(ORD, FULL + 1, 1, None, std::slice::from_ref(&real));
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
        let ann = ts::announcement_for(ORD, FULL + 1, 1, None, std::slice::from_ref(&v1));
        let eff = announce(&mut p, &ctx, &ann, ts::PEER);
        let (_, _, _, txs, _) = ts::one_validate(&eff);
        assert_eq!(txs, vec![v1.tx_ref]);

        let retry = ts::validate_err(&mut p, &ctx, &eff);
        let (_, _, _, txs, _) = ts::one_validate(&retry);
        assert_eq!(txs, vec![v2.tx_ref], "the other witness variant is tried");

        let done = ts::validate_err(&mut p, &ctx, &retry);
        assert_eq!(
            drops(&done),
            vec![DropReason::WitnessCombinationsExhausted],
            "validation rejected every combination the digest allows"
        );
        assert!(!has_validate(&done));
        assert!(p.best_input_block().is_none());
    }

    #[test]
    fn validation_failure_marks_block_and_chain_does_not_progress() {
        let mut p = processor();
        let b1 = ts::body(1, 1);
        let mut ctx = ts::TestCtx::at(FULL);
        ctx.mempool.add(&b1);
        let ann = ts::announcement_for(ORD, FULL + 1, 1, None, std::slice::from_ref(&b1));
        let eff = announce(&mut p, &ctx, &ann, ts::PEER);
        let out = ts::validate_err(&mut p, &ctx, &eff);
        assert_eq!(drops(&out), vec![DropReason::ValidationFailed]);
        assert!(!out.iter().any(|e| matches!(e, Effect::ChainChanged { .. })));
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
        let a1 = ts::announcement_for(ORD, FULL + 1, 1, None, std::slice::from_ref(&b1));
        let id1 = ts::ann_id(&a1);
        let eff = announce(&mut p, &ctx, &a1, ts::PEER);
        ts::validate_ok(&mut p, &ctx, &eff, 1);

        let a2 = ts::announcement_for(ORD, FULL + 1, 2, Some(id1), std::slice::from_ref(&b2));
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
        // Room for exactly one slot's worth of bodies, so the second
        // block's staging pushes the total over the cap.
        let one_body = ts::body(1, 1).bytes.len();
        let bounds = Bounds {
            staging_bytes_total: one_body,
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

        let a1 = ts::announcement_for(ORD, FULL + 1, 1, None, &[present1.clone(), absent1.clone()]);
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
        assert!(drops(&eff).contains(&DropReason::StagingFull), "{eff:?}");
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

    // ----- fix round 1: staging, resolution and job lifecycle -----

    /// Finding 1. A weak-id collision candidate that is *not* what the
    /// announcement committed to must never be cached and must never be
    /// offered as a retry: the digest fixes the tx id at every position,
    /// so only witness siblings of the selected body can legitimately
    /// follow it.
    #[test]
    fn collision_candidate_rejected_by_validation_is_never_applied() {
        let mut p = processor();
        let real = ts::body(1, 1);
        let decoy = ts::body(9, 1);
        let mut ctx = ts::TestCtx::at(FULL);
        ctx.mempool.add_under(real.weak_id, &decoy);
        ctx.mempool.add_under(real.weak_id, &real);
        let ann = ts::announcement_for(ORD, FULL + 1, 1, None, std::slice::from_ref(&real));
        let id = ts::ann_id(&ann);
        let eff = announce(&mut p, &ctx, &ann, ts::PEER);
        let (_, _, _, txs, _) = ts::one_validate(&eff);
        assert_eq!(txs, vec![real.tx_ref]);
        assert!(
            !p.is_cached(&decoy.tx_ref),
            "an unverified collision candidate must not reach the cache"
        );

        let out = ts::validate_err(&mut p, &ctx, &eff);
        assert!(
            !has_validate(&out),
            "the colliding transaction is not a legitimate retry: {out:?}"
        );
        assert_eq!(drops(&out), vec![DropReason::ValidationFailed]);
        assert_eq!(p.transaction_refs(&id), Some(&[real.tx_ref][..]));
        assert!(!p.is_cached(&decoy.tx_ref));
        assert!(p.best_input_block().is_none());
    }

    /// Finding 2. `[A_bad, B_valid]` failing must not blacklist
    /// `B_valid`: the retry is `[A_good, B_valid]`.
    #[test]
    fn failed_witness_does_not_poison_other_transactions_in_the_block() {
        let mut p = processor();
        let a1 = ts::body(1, 1);
        let a2 = ts::body(1, 2);
        let b = ts::body(2, 1);
        assert_eq!(a1.tx_ref.tx_id, a2.tx_ref.tx_id);
        let mut ctx = ts::TestCtx::at(FULL);
        ctx.mempool.add_under(a1.weak_id, &a1);
        ctx.mempool.add_under(a1.weak_id, &a2);
        ctx.mempool.add(&b);
        let ann = ts::announcement_for(ORD, FULL + 1, 1, None, &[a1.clone(), b.clone()]);
        let eff = announce(&mut p, &ctx, &ann, ts::PEER);
        let (_, _, _, txs, _) = ts::one_validate(&eff);
        assert_eq!(txs, vec![a1.tx_ref, b.tx_ref]);

        let retry = ts::validate_err(&mut p, &ctx, &eff);
        let (_, _, _, txs, _) = ts::one_validate(&retry);
        assert_eq!(
            txs,
            vec![a2.tx_ref, b.tx_ref],
            "only the offending position may change"
        );
    }

    /// Finding 3. Five local guesses at one position are over the
    /// per-position cap; the announcer's own body must settle it.
    #[test]
    fn peer_delivery_resolves_over_cap_candidate_set() {
        let mut p = processor();
        let real = ts::body(1, 1);
        let mut ctx = ts::TestCtx::at(FULL);
        for seed in 20..25u8 {
            ctx.mempool.add_under(real.weak_id, &ts::body(seed, 1));
        }
        let ann = ts::announcement_for(ORD, FULL + 1, 1, None, std::slice::from_ref(&real));
        let id = ts::ann_id(&ann);
        let eff = announce(&mut p, &ctx, &ann, ts::PEER);
        assert!(eff.contains(&Effect::RequestTransactions {
            input_block_id: id,
            weak_ids: vec![real.weak_id],
            from: ts::PEER,
        }));
        assert!(!has_validate(&eff));

        let out = ctx.handle(
            &mut p,
            Event::TransactionsDelivered {
                input_block_id: id,
                bodies: vec![real.clone()],
                from: Some(ts::PEER),
                now: Tick(2),
            },
        );
        let (_, _, vid, txs, _) = ts::one_validate(&out);
        assert_eq!(vid, id);
        assert_eq!(
            txs,
            vec![real.tx_ref],
            "the peer's body replaces the local guesses"
        );
        let done = ts::validate_ok(&mut p, &ctx, &out, 1);
        assert!(done
            .iter()
            .any(|e| matches!(e, Effect::ChainChanged { .. })));
        assert_eq!(p.best_input_chain(), vec![id]);
    }

    /// Finding 4, as the residual fix round (D) redraws it: a delivery
    /// arriving while a job is outstanding does **not** swap the
    /// selection under it — the listless path is bound by the same
    /// selection state machine as the staged one, so the witness waits
    /// for that job to fail. The late result is still dropped once the
    /// generation moves on.
    #[test]
    fn interleaved_delivery_leaves_the_outstanding_job_alone() {
        let mut p = processor();
        let v1 = ts::body(1, 1);
        let v2 = ts::body(1, 2);
        let ctx = ts::TestCtx::at(FULL);
        // No weak ids announced, so the delivered order is authoritative;
        // both witnesses share a tx id, so both satisfy the digest.
        let ann = ts::announcement_with(
            ORD,
            FULL + 1,
            1,
            None,
            ts::tx_digest(&[v1.tx_ref.tx_id]),
            None,
        );
        let id = ts::ann_id(&ann);
        announce(&mut p, &ctx, &ann, ts::PEER);
        let first = ctx.handle(
            &mut p,
            Event::TransactionsDelivered {
                input_block_id: id,
                bodies: vec![v1.clone()],
                from: Some(ts::PEER),
                now: Tick(2),
            },
        );
        let (old_job, old_gen, _, txs, _) = ts::one_validate(&first);
        assert_eq!(txs, vec![v1.tx_ref]);

        let second = ctx.handle(
            &mut p,
            Event::TransactionsDelivered {
                input_block_id: id,
                bodies: vec![v2.clone()],
                from: Some(ts::PEER),
                now: Tick(3),
            },
        );
        assert!(
            drops(&second).contains(&DropReason::SelectionSettled {
                state: SelectionState::Pending
            }),
            "an outstanding selection must not be swapped: {second:?}"
        );
        assert!(!has_validate(&second), "{second:?}");
        assert_eq!(
            p.transaction_refs(&id),
            Some(&[v1.tx_ref][..]),
            "the outstanding job's bodies must stay frozen"
        );

        // The job that was left alone still answers; a generation bump
        // in between is what makes its result stale.
        ctx.handle(
            &mut p,
            Event::OrderingBlockApplied {
                header_id: [0xBB; 32],
                height: FULL + 1,
                now: Tick(4),
            },
        );
        let late = ctx.handle(
            &mut p,
            Event::ValidationResult {
                job: old_job,
                generation: old_gen,
                outcome: ValidationOutcome::Valid(1),
            },
        );
        assert_eq!(
            drops(&late),
            vec![DropReason::StaleValidation {
                generation: old_gen
            }]
        );
        assert_eq!(stale_ids(&late), vec![id]);
        assert!(!late
            .iter()
            .any(|e| matches!(e, Effect::ChainChanged { .. })));
    }

    /// Finding 5a. Starting one job from the deferred queue must leave
    /// the rest of the queue intact. Three forks deliver bodies while a
    /// job is outstanding; servicing the queue starts exactly one job and
    /// the triggers behind it must survive.
    #[test]
    fn deferred_triggers_survive_a_started_job() {
        let mut p = processor();
        let ctx = ts::TestCtx::at(FULL);
        let mut nonce = 0u64;
        let mut ann = |prev: Option<InputBlockId>| {
            nonce += 1;
            ts::announcement(ORD, FULL + 1, nonce, prev)
        };
        let ib1 = ann(None);
        // Fork A (stays the best fork but never gets a3's bodies).
        let a2 = ann(Some(ts::ann_id(&ib1)));
        let a3 = ann(Some(ts::ann_id(&a2)));
        // Fork B, one block longer than A.
        let b2 = ann(Some(ts::ann_id(&ib1)));
        let b3 = ann(Some(ts::ann_id(&b2)));
        let b4 = ann(Some(ts::ann_id(&b3)));
        // Fork C, same length as A.
        let c2 = ann(Some(ts::ann_id(&ib1)));
        let c3 = ann(Some(ts::ann_id(&c2)));
        for a in [&ib1, &a2, &a3, &b2, &b3, &b4, &c2, &c3] {
            announce(&mut p, &ctx, a, ts::PEER);
        }

        let root = deliver_empty(&mut p, &ctx, &ib1, 2);
        ts::validate_ok(&mut p, &ctx, &root, 1);
        let first = deliver_empty(&mut p, &ctx, &a2, 3);
        assert!(has_validate(&first), "fork A's first child is applied");

        // Everything below arrives while that job is outstanding.
        for (a, t) in [(&b2, 4), (&b3, 5), (&b4, 6), (&c3, 7)] {
            assert!(!has_validate(&deliver_empty(&mut p, &ctx, a, t)));
        }
        assert_eq!(p.deferred_triggers(), 4);

        let out = ts::validate_ok(&mut p, &ctx, &first, 1);
        let (_, _, vid, _, _) = ts::one_validate(&out);
        assert_eq!(
            vid,
            ts::ann_id(&b2),
            "the queue's fork-switch trigger starts the next job"
        );
        assert_eq!(
            p.deferred_triggers(),
            2,
            "triggers behind the one that started a job must survive"
        );
    }

    /// Finding 5b. A terminal validation failure must still service the
    /// deferred queue.
    #[test]
    fn terminal_validation_failure_resumes_queued_work() {
        let mut p = processor();
        let ctx = ts::TestCtx::at(FULL);
        let ib1 = ts::announcement(ORD, FULL + 1, 1, None);
        let ib2 = ts::announcement(ORD, FULL + 1, 2, Some(ts::ann_id(&ib1)));
        for a in [&ib1, &ib2] {
            announce(&mut p, &ctx, a, ts::PEER);
        }
        let first = deliver_empty(&mut p, &ctx, &ib1, 2);
        assert!(has_validate(&first));
        deliver_empty(&mut p, &ctx, &ib2, 3);
        assert_eq!(p.deferred_triggers(), 1);

        let out = ts::validate_err(&mut p, &ctx, &first);
        assert_eq!(drops(&out), vec![DropReason::ValidationFailed]);
        assert_eq!(
            p.deferred_triggers(),
            0,
            "the queue must be serviced after a terminal failure"
        );
    }

    /// Finding 5c. A witness retry during a fork switch must keep the
    /// trigger the switch was selected on; retrying with the block's own
    /// id collapses the selection to the linear branch and stalls.
    #[test]
    fn witness_retry_keeps_the_original_fork_switch_trigger() {
        let mut p = processor();
        let v1 = ts::body(5, 1);
        let v2 = ts::body(5, 2);
        let mut ctx = ts::TestCtx::at(FULL);
        ctx.mempool.add_under(v1.weak_id, &v1);
        ctx.mempool.add_under(v1.weak_id, &v2);

        let ib1 = ts::announcement(ORD, FULL + 1, 1, None);
        announce(&mut p, &ctx, &ib1, ts::PEER);
        let eff = deliver_empty(&mut p, &ctx, &ib1, 2);
        ts::validate_ok(&mut p, &ctx, &eff, 1);

        let ib2a = ts::announcement(ORD, FULL + 1, 2, Some(ts::ann_id(&ib1)));
        announce(&mut p, &ctx, &ib2a, ts::PEER);
        let eff = deliver_empty(&mut p, &ctx, &ib2a, 3);
        ts::validate_ok(&mut p, &ctx, &eff, 1);
        assert_eq!(
            p.best_input_chain(),
            vec![ts::ann_id(&ib2a), ts::ann_id(&ib1)]
        );

        // Fork B, longer, whose first block has two witness variants.
        let ib2b = ts::announcement_for(
            ORD,
            FULL + 1,
            3,
            Some(ts::ann_id(&ib1)),
            std::slice::from_ref(&v1),
        );
        let quiet = announce(&mut p, &ctx, &ib2b, ts::PEER);
        assert!(!has_validate(&quiet), "fork B is not yet longer");
        let ib3b = ts::announcement(ORD, FULL + 1, 4, Some(ts::ann_id(&ib2b)));
        announce(&mut p, &ctx, &ib3b, ts::PEER);
        let switch = deliver_empty(&mut p, &ctx, &ib3b, 4);
        let (_, _, vid, txs, _) = ts::one_validate(&switch);
        assert_eq!(vid, ts::ann_id(&ib2b));
        assert_eq!(txs, vec![v1.tx_ref]);

        let retry = ts::validate_err(&mut p, &ctx, &switch);
        let (_, _, vid, txs, _) = ts::one_validate(&retry);
        assert_eq!(vid, ts::ann_id(&ib2b));
        assert_eq!(
            txs,
            vec![v2.tx_ref],
            "the retry must re-run the same fork switch, not the linear branch"
        );
    }

    /// Finding 6. After the cache expires, redelivering a digest-verified
    /// body must refill it and let the chain move again.
    #[test]
    fn redelivery_refills_evicted_bodies_and_progress_resumes() {
        let mut p = processor();
        let b1 = ts::body(1, 1);
        let b2 = ts::body(2, 1);
        let mut ctx = ts::TestCtx::at(FULL);
        ctx.mempool.add(&b1);
        ctx.mempool.add(&b2);

        let a1 = ts::announcement_for(ORD, FULL + 1, 1, None, std::slice::from_ref(&b1));
        let id1 = ts::ann_id(&a1);
        let eff = announce(&mut p, &ctx, &a1, ts::PEER);
        ts::validate_ok(&mut p, &ctx, &eff, 1);
        assert!(p.is_cached(&b1.tx_ref));

        // Two hours pass: Scala's `expireAfterWrite` clears the cache.
        ctx.handle(
            &mut p,
            Event::Tick {
                now: Tick(10_000_000),
            },
        );
        assert!(!p.is_cached(&b1.tx_ref));

        let a2 = ts::announcement_for(ORD, FULL + 1, 2, Some(id1), std::slice::from_ref(&b2));
        let id2 = ts::ann_id(&a2);
        let stuck = announce(&mut p, &ctx, &a2, ts::PEER);
        assert!(!has_validate(&stuck));
        assert_eq!(drops(&stuck), vec![DropReason::CacheEvicted]);

        let refilled = ctx.handle(
            &mut p,
            Event::TransactionsDelivered {
                input_block_id: id1,
                bodies: vec![b1.clone()],
                from: Some(ts::PEER),
                now: Tick(10_000_001),
            },
        );
        assert!(p.is_cached(&b1.tx_ref), "redelivery must refill the cache");
        let (_, _, vid, _, previous) = ts::one_validate(&refilled);
        assert_eq!(vid, id2, "the chain resumes once the body is back");
        assert_eq!(previous, vec![b1.tx_ref]);
    }

    /// Finding 7. The per-block digest budget is a total, not a
    /// per-delivery allowance.
    #[test]
    fn digest_attempt_budget_is_not_reset_by_redelivery() {
        let mut p = processor();
        let x = ts::body(1, 1);
        let y = ts::body(2, 1);
        let mut ctx = ts::TestCtx::at(FULL);
        // Four non-matching candidates at each of two positions: 16
        // combinations, exactly the budget, none of them correct.
        for seed in 30..34u8 {
            ctx.mempool.add_under(x.weak_id, &ts::body(seed, 1));
        }
        for seed in 40..44u8 {
            ctx.mempool.add_under(y.weak_id, &ts::body(seed, 1));
        }
        let ann = ts::announcement_for(ORD, FULL + 1, 1, None, &[x.clone(), y.clone()]);
        let id = ts::ann_id(&ann);
        let eff = announce(&mut p, &ctx, &ann, ts::PEER);
        assert!(!has_validate(&eff));
        let budget = Bounds::default().digest_attempts_per_block;
        assert_eq!(p.staged_digest_attempts(&id), budget);

        for tick in 0..3u64 {
            ctx.handle(
                &mut p,
                Event::TransactionsDelivered {
                    input_block_id: id,
                    bodies: Vec::new(),
                    from: Some(ts::PEER),
                    now: Tick(10 + tick),
                },
            );
            assert_eq!(
                p.staged_digest_attempts(&id),
                budget,
                "redelivery must not buy a fresh search budget"
            );
        }

        // Fix round 2, finding r2-1: a *non-empty* redelivery after
        // exhaustion, this time from a peer that is not the announcer.
        // It buys nothing — the recovery allowance of the residual fix
        // round (B) belongs to the announcer alone — and, above all, the
        // budget must outlive the deleted staging slot: recreating
        // staging must not hand the block a fresh sixteen attempts.
        let correct = vec![x.clone(), y.clone()];
        let stranger = ctx.handle(
            &mut p,
            Event::TransactionsDelivered {
                input_block_id: id,
                bodies: correct.clone(),
                from: PeerTag::remote(99),
                now: Tick(20),
            },
        );
        assert!(!has_validate(&stranger), "{stranger:?}");
        assert_eq!(
            p.staged_digest_attempts(&id),
            budget,
            "the budget must survive staging-slot deletion"
        );
    }

    // ----- fix round 2 -----

    /// Finding r2-2. When a delivery invalidates an outstanding job, the
    /// trigger that job's selection was made on must survive: a fork
    /// switch chosen on a deep trigger has to be re-run as a fork switch,
    /// not collapsed into the linear branch.
    #[test]
    fn job_invalidation_preserves_the_fork_switch_trigger() {
        let mut p = processor();
        let ctx = ts::TestCtx::at(FULL);
        let v1 = ts::body(5, 1);
        let v2 = ts::body(5, 2);
        assert_eq!(v1.tx_ref.tx_id, v2.tx_ref.tx_id);

        // Fork A: ib1 -> ib2a, both applied.
        let ib1 = ts::announcement(ORD, FULL + 1, 1, None);
        announce(&mut p, &ctx, &ib1, ts::PEER);
        let eff = deliver_empty(&mut p, &ctx, &ib1, 2);
        ts::validate_ok(&mut p, &ctx, &eff, 1);
        let ib2a = ts::announcement(ORD, FULL + 1, 2, Some(ts::ann_id(&ib1)));
        announce(&mut p, &ctx, &ib2a, ts::PEER);
        let eff = deliver_empty(&mut p, &ctx, &ib2a, 3);
        ts::validate_ok(&mut p, &ctx, &eff, 1);

        // Fork B: ib1 -> ib2b -> ib3b. ib2b announces no weak ids, so the
        // delivered order is authoritative and a later delivery really
        // does replace its body.
        let ib2b = ts::announcement_with(
            ORD,
            FULL + 1,
            3,
            Some(ts::ann_id(&ib1)),
            ts::tx_digest(&[v1.tx_ref.tx_id]),
            None,
        );
        let ib2b_id = ts::ann_id(&ib2b);
        announce(&mut p, &ctx, &ib2b, ts::PEER);
        let quiet = ctx.handle(
            &mut p,
            Event::TransactionsDelivered {
                input_block_id: ib2b_id,
                bodies: vec![v1.clone()],
                from: Some(ts::PEER),
                now: Tick(4),
            },
        );
        assert!(!has_validate(&quiet), "fork B is not yet longer");

        let ib3b = ts::announcement(ORD, FULL + 1, 4, Some(ib2b_id));
        announce(&mut p, &ctx, &ib3b, ts::PEER);
        let switch = deliver_empty(&mut p, &ctx, &ib3b, 5);
        let (_, _, vid, txs, _) = ts::one_validate(&switch);
        assert_eq!(vid, ib2b_id, "the deep trigger selected a fork switch");
        assert_eq!(txs, vec![v1.tx_ref]);

        // While that job is outstanding the selection is frozen (residual
        // fix round, D): the witness is refused, not swapped in.
        let refused = ctx.handle(
            &mut p,
            Event::TransactionsDelivered {
                input_block_id: ib2b_id,
                bodies: vec![v2.clone()],
                from: Some(ts::PEER),
                now: Tick(6),
            },
        );
        assert!(!has_validate(&refused), "{refused:?}");
        assert!(drops(&refused).contains(&DropReason::SelectionSettled {
            state: SelectionState::Pending
        }));

        // Once the job fails, the witness that was held for it is taken
        // without another delivery (residual fix round 2, C/D). The
        // reissue must be the same fork switch, for the same block, with
        // the new body.
        let replaced = ts::validate_err(&mut p, &ctx, &switch);
        let (_, _, vid, txs, _) = ts::one_validate(&replaced);
        assert_eq!(vid, ib2b_id, "the fork switch must be re-run");
        assert_eq!(txs, vec![v2.tx_ref]);
    }

    /// Finding r2-3. A resolved block's per-position witness list is still
    /// bounded by `candidates_per_position`; a peer cannot grow it by
    /// spraying witnesses of a committed transaction.
    #[test]
    fn resolved_variant_list_respects_the_candidate_cap() {
        let mut p = processor();
        let base = ts::body(7, 1);
        let mut ctx = ts::TestCtx::at(FULL);
        ctx.mempool.add(&base);
        let ann = ts::announcement_for(ORD, FULL + 1, 1, None, std::slice::from_ref(&base));
        let id = ts::ann_id(&ann);
        let eff = announce(&mut p, &ctx, &ann, ts::PEER);
        assert!(has_validate(&eff));
        assert_eq!(p.variants_per_position(&id), vec![1]);

        let cap = Bounds::default().candidates_per_position;
        let mut rejected = 0;
        for witness in 2..12u8 {
            let out = ctx.handle(
                &mut p,
                Event::TransactionsDelivered {
                    input_block_id: id,
                    bodies: vec![ts::body(7, witness)],
                    from: Some(ts::PEER),
                    now: Tick(10 + u64::from(witness)),
                },
            );
            if drops(&out)
                .iter()
                .any(|r| matches!(r, DropReason::VariantCapExceeded { position: 0 }))
            {
                rejected += 1;
            }
            assert!(
                p.variants_per_position(&id).iter().all(|n| *n <= cap),
                "witness list grew past the cap: {:?}",
                p.variants_per_position(&id)
            );
        }
        assert_eq!(p.variants_per_position(&id), vec![cap]);
        assert!(rejected > 0, "over-cap witnesses must be reported");
        assert_eq!(p.staged_bytes(), 0, "resolved slots hold no bytes");
    }

    #[test]
    fn unavailable_validation_leaves_the_combination_untried() {
        // A node that receives input blocks before it has applied a full
        // block cannot build a validation context. That is node-local and
        // transient — recording the combination as failed would blacklist
        // a perfectly valid chain head for the life of the ordering
        // block, which is exactly what stalled the mixed devnet smoke.
        let mut p = processor();
        let b1 = ts::body(1, 1);
        let mut ctx = ts::TestCtx::at(FULL);
        ctx.mempool.add(&b1);
        let ann = ts::announcement_for(ORD, FULL + 1, 1, None, std::slice::from_ref(&b1));
        let id = ts::ann_id(&ann);
        let eff = announce(&mut p, &ctx, &ann, ts::PEER);
        let out = ts::validate_unavailable(&mut p, &ctx, &eff);
        assert_eq!(drops(&out), vec![DropReason::ValidationUnavailable]);
        assert!(
            !p.has_failed_combination(&id, &[b1.tx_ref]),
            "a node-local miss must not retire the combination"
        );

        // The attempt is refunded too, so a node that is briefly unable
        // to validate does not burn the block's retry budget: the very
        // next delivery re-offers the same bodies.
        let again = ctx.handle(
            &mut p,
            Event::TransactionsDelivered {
                input_block_id: id,
                bodies: vec![b1.clone()],
                from: Some(ts::PEER),
                now: Tick(9),
            },
        );
        assert!(has_validate(&again), "{again:?}");
        let ok = ts::validate_ok(&mut p, &ctx, &again, 1);
        assert!(
            drops(&ok).is_empty(),
            "the retry must apply cleanly: {ok:?}"
        );
    }

    #[test]
    fn failed_variant_is_not_revalidated_on_redelivery() {
        // Spec 7.5: once a body has failed validation for a block, the
        // same body is never offered again — otherwise a peer could
        // re-deliver it to keep the node re-running the job.
        let mut p = processor();
        let b1 = ts::body(1, 1);
        let mut ctx = ts::TestCtx::at(FULL);
        ctx.mempool.add(&b1);
        let ann = ts::announcement_for(ORD, FULL + 1, 1, None, std::slice::from_ref(&b1));
        let id = ts::ann_id(&ann);
        let eff = announce(&mut p, &ctx, &ann, ts::PEER);
        let out = ts::validate_err(&mut p, &ctx, &eff);
        assert_eq!(drops(&out), vec![DropReason::ValidationFailed]);

        let again = ctx.handle(
            &mut p,
            Event::TransactionsDelivered {
                input_block_id: id,
                bodies: vec![b1.clone()],
                from: Some(ts::PEER),
                now: Tick(9),
            },
        );
        assert!(!has_validate(&again), "{again:?}");
        assert!(p.has_failed_combination(&id, &[b1.tx_ref]));
        assert!(p.best_input_block().is_none());
    }

    // ----- final fix wave -----

    /// Build a block whose single announced position has `locals` local
    /// weak-id collisions in the mempool, then let the announcer settle
    /// it with `delivered` bodies of the same transaction. Returns the
    /// processor, the context and the block id.
    fn over_stuffed_position(
        locals: u8,
        delivered: u8,
    ) -> (Processor, ts::TestCtx, InputBlockId, Vec<Effect>) {
        let mut p = processor();
        let base = ts::body(7, 1);
        let mut ctx = ts::TestCtx::at(FULL);
        for w in 1..=locals {
            ctx.mempool.add_under(base.weak_id, &ts::body(7, w));
        }
        let ann = ts::announcement_for(ORD, FULL + 1, 1, None, std::slice::from_ref(&base));
        let id = ts::ann_id(&ann);
        announce(&mut p, &ctx, &ann, ts::PEER);
        let bodies: Vec<Body> = (0..delivered)
            .map(|i| ts::body_under(base.weak_id, 7, locals + 1 + i))
            .collect();
        let eff = ctx.handle(
            &mut p,
            Event::TransactionsDelivered {
                input_block_id: id,
                bodies,
                from: Some(ts::PEER),
                now: Tick(5),
            },
        );
        (p, ctx, id, eff)
    }

    #[test]
    fn initial_variant_list_respects_the_candidate_cap() {
        // Spec 7.4's `candidates_per_position` has to bite when the
        // variant list is first built, not only when a later delivery
        // extends it: the two provenances are capped separately while
        // staging, so `cap + 1` local guesses and `cap` peer answers for
        // one position could otherwise be promoted into `2 * cap + 1`
        // retry variants — and into the shared cache.
        let cap = Bounds::default().candidates_per_position;
        let (p, _ctx, id, eff) = over_stuffed_position(cap as u8 + 1, cap as u8);
        assert!(has_validate(&eff), "the block must resolve: {eff:?}");
        assert_eq!(
            p.variants_per_position(&id),
            vec![cap],
            "the initial variant list must respect the per-position cap"
        );
    }

    #[test]
    fn validation_retry_budget_gives_up_on_the_block() {
        // Two positions with `cap` witness variants each is `cap ^ 2`
        // digest-consistent combinations — every one of them a full block
        // validation, and every failure remembered. The per-block budget
        // is what stops that being a remote-controlled amount of work.
        let bounds = Bounds::default();
        let cap = bounds.candidates_per_position;
        let budget = bounds.validation_retries_per_block;
        assert!(budget < cap * cap, "the budget must be the binding limit");

        let mut p = processor();
        let b1 = ts::body(1, 1);
        let b2 = ts::body(2, 1);
        let mut ctx = ts::TestCtx::at(FULL);
        for w in 1..=cap as u8 {
            ctx.mempool.add_under(b1.weak_id, &ts::body(1, w));
            ctx.mempool.add_under(b2.weak_id, &ts::body(2, w));
        }
        let ann = ts::announcement_for(ORD, FULL + 1, 1, None, &[b1.clone(), b2.clone()]);
        let id = ts::ann_id(&ann);
        let mut eff = announce(&mut p, &ctx, &ann, ts::PEER);

        let mut validations = 0;
        let mut last = Vec::new();
        while has_validate(&eff) {
            validations += 1;
            assert!(validations <= cap * cap, "the retry loop never terminated");
            eff = ts::validate_err(&mut p, &ctx, &eff);
            last = drops(&eff);
        }
        assert_eq!(
            validations, budget,
            "a block must not cost more than its validation budget"
        );
        assert!(
            last.contains(&DropReason::ValidationBudgetExhausted),
            "an exhausted budget must report ValidationBudgetExhausted, got {last:?}"
        );
        assert!(
            p.failed_combinations(&id) <= budget,
            "rejected-combination memory must be bounded by the budget"
        );
    }

    #[test]
    fn later_witness_delivery_revives_a_failed_selection() {
        // The announcer's own body can arrive after the local guess has
        // already been rejected. Appending it to the variant list is not
        // enough: the cursor still points at the failed combination,
        // which `pump` refuses to re-offer, so nothing would ever restart.
        let mut p = processor();
        let b1 = ts::body(1, 1);
        let mut ctx = ts::TestCtx::at(FULL);
        ctx.mempool.add(&b1);
        let ann = ts::announcement_for(ORD, FULL + 1, 1, None, std::slice::from_ref(&b1));
        let id = ts::ann_id(&ann);
        let eff = announce(&mut p, &ctx, &ann, ts::PEER);
        let out = ts::validate_err(&mut p, &ctx, &eff);
        assert_eq!(drops(&out), vec![DropReason::ValidationFailed]);
        assert!(!has_validate(&out));

        let other = ts::body(1, 2);
        let revived = ctx.handle(
            &mut p,
            Event::TransactionsDelivered {
                input_block_id: id,
                bodies: vec![other.clone()],
                from: Some(ts::PEER),
                now: Tick(9),
            },
        );
        let (_, _, block, txs, _) = ts::one_validate(&revived);
        assert_eq!(block, id);
        assert_eq!(
            txs,
            vec![other.tx_ref],
            "the retry must run the newly delivered witness"
        );
    }

    // ----- final fix wave, round 2 -----

    fn validates(effects: &[Effect]) -> usize {
        effects
            .iter()
            .filter(|e| matches!(e, Effect::Validate { .. }))
            .count()
    }

    #[test]
    fn validation_budget_counts_invalidated_dispatches() {
        // The budget has to cost *dispatched* work, not accepted failure
        // results. A peer that keeps delivering fresh witnesses drives
        // `retry_after_delivery`, invalidates whatever job is
        // outstanding through `set_tx_refs` and gets another validation
        // issued — without a single `ValidationResult` being accepted,
        // so a counter charged only on failure never moves.
        let budget = Bounds::default().validation_retries_per_block;
        let mut p = processor();
        let b1 = ts::body(1, 1);
        let b2 = ts::body(2, 1);
        let b3 = ts::body(3, 1);
        let mut ctx = ts::TestCtx::at(FULL);
        ctx.mempool.add(&b1);
        ctx.mempool.add(&b2);
        ctx.mempool.add(&b3);
        let ann = ts::announcement_for(
            ORD,
            FULL + 1,
            1,
            None,
            &[b1.clone(), b2.clone(), b3.clone()],
        );
        let id = ts::ann_id(&ann);

        let eff = announce(&mut p, &ctx, &ann, ts::PEER);
        let mut dispatched = validates(&eff);
        // One accepted failure, so the block is in a rejected state and a
        // delivery may drive a retry at all.
        dispatched += validates(&ts::validate_err(&mut p, &ctx, &eff));

        // Now spray fresh witnesses of the three committed transactions
        // and never answer the jobs they start.
        for (i, (seed, witness)) in [
            (1u8, 2u8),
            (2, 2),
            (3, 2),
            (1, 3),
            (2, 3),
            (3, 3),
            (1, 4),
            (2, 4),
            (3, 4),
        ]
        .into_iter()
        .enumerate()
        {
            let out = ctx.handle(
                &mut p,
                Event::TransactionsDelivered {
                    input_block_id: id,
                    bodies: vec![ts::body(seed, witness)],
                    from: Some(ts::PEER),
                    now: Tick(10 + i as u64),
                },
            );
            dispatched += validates(&out);
        }

        assert!(
            dispatched <= budget,
            "a block dispatched {dispatched} validations against a budget of {budget}"
        );
        assert_eq!(
            p.validation_attempts(&id),
            dispatched,
            "every dispatched job must be charged to the block's budget"
        );
    }

    #[test]
    fn expanded_variants_restart_combination_enumeration() {
        // Variant counts [1, 2]: both combinations are tried and fail,
        // leaving the cursor at [0, 1]. A witness then arrives for
        // position 0. Advancing forward from [0, 1] reaches [1, 1] and
        // then runs out, so [1, 0] — the combination the new witness
        // actually made reachable — is never offered and the block stays
        // stranded. The enumeration has to restart over the expanded
        // space, skipping the combinations already recorded as failed.
        let mut p = processor();
        let a1 = ts::body(1, 1);
        let b1 = ts::body(2, 1);
        let b2 = ts::body(2, 2);
        let mut ctx = ts::TestCtx::at(FULL);
        ctx.mempool.add(&a1);
        ctx.mempool.add_under(b1.weak_id, &b1);
        ctx.mempool.add_under(b1.weak_id, &b2);
        let ann = ts::announcement_for(ORD, FULL + 1, 1, None, &[a1.clone(), b1.clone()]);
        let id = ts::ann_id(&ann);

        let eff = announce(&mut p, &ctx, &ann, ts::PEER);
        assert_eq!(p.variants_per_position(&id), vec![1, 2]);
        let (_, _, _, first, _) = ts::one_validate(&eff);
        assert_eq!(first, vec![a1.tx_ref, b1.tx_ref]);
        let eff = ts::validate_err(&mut p, &ctx, &eff);
        let (_, _, _, second, _) = ts::one_validate(&eff);
        assert_eq!(second, vec![a1.tx_ref, b2.tx_ref]);
        let eff = ts::validate_err(&mut p, &ctx, &eff);
        assert!(!has_validate(&eff), "both combinations are exhausted");

        let a2 = ts::body(1, 2);
        let revived = ctx.handle(
            &mut p,
            Event::TransactionsDelivered {
                input_block_id: id,
                bodies: vec![a2.clone()],
                from: Some(ts::PEER),
                now: Tick(20),
            },
        );
        let (_, _, block, txs, _) = ts::one_validate(&revived);
        assert_eq!(block, id);
        assert_eq!(
            txs,
            vec![a2.tx_ref, b1.tx_ref],
            "the retry must reach the combination the new witness unlocked"
        );
        let applied = ts::validate_ok(&mut p, &ctx, &revived, 1);
        assert!(
            applied.iter().any(|e| matches!(
                e,
                Effect::ChainChanged { applied, .. } if applied == &vec![id]
            )),
            "the block must apply once a valid combination is found: {applied:?}"
        );
    }

    #[test]
    fn applied_block_keeps_its_validated_witnesses() {
        // Witness A fails, witness B is validated and the block applies.
        // A witness C delivered afterwards must not replace B: the block
        // is already processed, so no validation would ever run for C
        // and the applied block would be left exposing an unvalidated
        // body. Only a selection that is *currently* rejected may be
        // swapped.
        let mut p = processor();
        let a1 = ts::body(1, 1);
        let a2 = ts::body(1, 2);
        let mut ctx = ts::TestCtx::at(FULL);
        ctx.mempool.add(&a1);
        ctx.mempool.add_under(a1.weak_id, &a2);
        let ann = ts::announcement_for(ORD, FULL + 1, 1, None, std::slice::from_ref(&a1));
        let id = ts::ann_id(&ann);

        let eff = announce(&mut p, &ctx, &ann, ts::PEER);
        let eff = ts::validate_err(&mut p, &ctx, &eff);
        let (_, _, _, retried, _) = ts::one_validate(&eff);
        assert_eq!(retried, vec![a2.tx_ref], "the retry must run the sibling");
        ts::validate_ok(&mut p, &ctx, &eff, 1);
        assert_eq!(p.transaction_refs(&id), Some(&[a2.tx_ref][..]));
        assert_eq!(p.best_input_chain(), vec![id]);

        let a3 = ts::body(1, 3);
        let late = ctx.handle(
            &mut p,
            Event::TransactionsDelivered {
                input_block_id: id,
                bodies: vec![a3.clone()],
                from: Some(ts::PEER),
                now: Tick(30),
            },
        );
        assert!(
            !has_validate(&late),
            "an applied block must not start a new validation: {late:?}"
        );
        assert_eq!(
            p.transaction_refs(&id),
            Some(&[a2.tx_ref][..]),
            "an applied block's transaction references must stay frozen"
        );
        assert!(
            drops(&late).contains(&DropReason::SelectionSettled {
                state: SelectionState::Applied
            }),
            "the unusable witness must be reported: {late:?}"
        );
    }

    // ----- final fix wave, round 3 -----

    #[test]
    fn variants_expanded_during_validation_restart_the_next_retry() {
        // The delivery-driven restart is refused while a job is
        // outstanding — the selection is settled, so nothing may be
        // swapped under it. But the expansion still happened, and the
        // failure path advances forward: with counts [1,2] it fails
        // [0,0], dispatches [0,1], then the delivery widens position 0 to
        // [2,2] and the failure of [0,1] steps to [1,1], skipping the
        // [1,0] the new witness made reachable. The pending restart has
        // to survive the outstanding job.
        let mut p = processor();
        let a1 = ts::body(1, 1);
        let b1 = ts::body(2, 1);
        let b2 = ts::body(2, 2);
        let mut ctx = ts::TestCtx::at(FULL);
        ctx.mempool.add(&a1);
        ctx.mempool.add_under(b1.weak_id, &b1);
        ctx.mempool.add_under(b1.weak_id, &b2);
        let ann = ts::announcement_for(ORD, FULL + 1, 1, None, &[a1.clone(), b1.clone()]);
        let id = ts::ann_id(&ann);

        let eff = announce(&mut p, &ctx, &ann, ts::PEER);
        assert_eq!(p.variants_per_position(&id), vec![1, 2]);
        let (_, _, _, first, _) = ts::one_validate(&eff);
        assert_eq!(first, vec![a1.tx_ref, b1.tx_ref]);

        // [0,0] fails, [0,1] is dispatched and left outstanding.
        let outstanding = ts::validate_err(&mut p, &ctx, &eff);
        let (_, _, _, second, _) = ts::one_validate(&outstanding);
        assert_eq!(second, vec![a1.tx_ref, b2.tx_ref]);

        // The witness for position 0 arrives mid-validation.
        let a2 = ts::body(1, 2);
        let during = ctx.handle(
            &mut p,
            Event::TransactionsDelivered {
                input_block_id: id,
                bodies: vec![a2.clone()],
                from: Some(ts::PEER),
                now: Tick(20),
            },
        );
        assert!(
            !has_validate(&during),
            "an outstanding selection must not be swapped: {during:?}"
        );
        assert!(drops(&during).contains(&DropReason::SelectionSettled {
            state: SelectionState::Pending
        }));
        assert_eq!(p.variants_per_position(&id), vec![2, 2]);

        // Now the outstanding combination fails. The retry must cover the
        // space the delivery widened, not step past it.
        let revived = ts::validate_err(&mut p, &ctx, &outstanding);
        let (_, _, block, txs, _) = ts::one_validate(&revived);
        assert_eq!(block, id);
        assert_eq!(
            txs,
            vec![a2.tx_ref, b1.tx_ref],
            "the retry must reach the combination unlocked while the job ran"
        );
        let applied = ts::validate_ok(&mut p, &ctx, &revived, 1);
        assert!(
            applied.iter().any(|e| matches!(
                e,
                Effect::ChainChanged { applied, .. } if applied == &vec![id]
            )),
            "the block must apply once the valid combination is reached: {applied:?}"
        );
    }

    // ----- residuals fix round: D (listless path, stale results, requests) -----

    /// An announcement that never announces a weak-id list, so every
    /// delivery takes the listless path of `on_bodies`.
    fn listless(nonce: u64, tx_id: [u8; 32], prev: Option<InputBlockId>) -> InputBlockAnnouncement {
        ts::announcement_with(ORD, FULL + 1, nonce, prev, ts::tx_digest(&[tx_id]), None)
    }

    #[test]
    fn listless_delivery_after_application_keeps_applied_refs() {
        // The defect the residual round fixes: with no announced weak-id
        // list the delivered order *is* the order, so a second delivery
        // naming the same transaction id with a different witness passed
        // the ordered digest and replaced the references of an already
        // applied block — a body no validation ever saw, in a block the
        // tree considers processed.
        let mut p = processor();
        let ctx = ts::TestCtx::at(FULL);
        let v1 = ts::body(1, 1);
        let v2 = ts::body(1, 2);
        assert_eq!(v1.tx_ref.tx_id, v2.tx_ref.tx_id);
        let ann = listless(1, v1.tx_ref.tx_id, None);
        let id = ts::ann_id(&ann);
        announce(&mut p, &ctx, &ann, ts::PEER);
        let first = ctx.handle(
            &mut p,
            Event::TransactionsDelivered {
                input_block_id: id,
                bodies: vec![v1.clone()],
                from: Some(ts::PEER),
                now: Tick(2),
            },
        );
        ts::validate_ok(&mut p, &ctx, &first, 1);
        assert_eq!(p.best_input_chain(), vec![id]);

        let late = ctx.handle(
            &mut p,
            Event::TransactionsDelivered {
                input_block_id: id,
                bodies: vec![v2.clone()],
                from: Some(ts::PEER),
                now: Tick(3),
            },
        );
        assert!(
            !has_validate(&late),
            "an applied block must not start a new validation: {late:?}"
        );
        assert_eq!(
            p.transaction_refs(&id),
            Some(&[v1.tx_ref][..]),
            "an applied block's references must stay frozen"
        );
        assert!(
            drops(&late).contains(&DropReason::SelectionSettled {
                state: SelectionState::Applied
            }),
            "{late:?}"
        );
        assert!(
            !p.is_cached(&v2.tx_ref),
            "an unusable witness must not reach the shared cache"
        );
    }

    #[test]
    fn listless_delivery_after_exhausted_validation_budget_is_refused() {
        // Every listless delivery that replaces a rejected selection buys
        // a block validation, so the per-block budget bounds this path
        // exactly as it bounds the staged one.
        let mut p = processor();
        let ctx = ts::TestCtx::at(FULL);
        let budget = Bounds::default().validation_retries_per_block;
        let first = ts::body(1, 1);
        let ann = listless(1, first.tx_ref.tx_id, None);
        let id = ts::ann_id(&ann);
        announce(&mut p, &ctx, &ann, ts::PEER);

        let mut last = ts::body(1, 1);
        let mut spent: Vec<DropReason> = Vec::new();
        for w in 1..=budget as u8 {
            let b = ts::body(1, w);
            let eff = ctx.handle(
                &mut p,
                Event::TransactionsDelivered {
                    input_block_id: id,
                    bodies: vec![b.clone()],
                    from: Some(ts::PEER),
                    now: Tick(w as u64),
                },
            );
            assert!(has_validate(&eff), "witness {w} must be validated: {eff:?}");
            let failed = ts::validate_err(&mut p, &ctx, &eff);
            spent = drops(&failed);
            last = b;
        }
        assert_eq!(p.validation_attempts(&id), budget);
        assert!(
            spent.contains(&DropReason::ValidationBudgetExhausted),
            "the give-up must be reported when the budget runs out: {spent:?}"
        );

        let extra = ts::body(1, budget as u8 + 1);
        let refused = ctx.handle(
            &mut p,
            Event::TransactionsDelivered {
                input_block_id: id,
                bodies: vec![extra.clone()],
                from: Some(ts::PEER),
                now: Tick(99),
            },
        );
        assert!(!has_validate(&refused), "{refused:?}");
        assert_eq!(p.validation_attempts(&id), budget);
        assert_eq!(
            p.transaction_refs(&id),
            Some(&[last.tx_ref][..]),
            "an exhausted block must not take another selection"
        );
        assert!(
            !drops(&refused).contains(&DropReason::ValidationFailed),
            "a refused delivery must not look like a validation failure: {refused:?}"
        );
    }

    #[test]
    fn stale_validation_result_never_names_the_current_job() {
        // A result for a job the generation bump abandoned used to be
        // reported against whatever block is being validated *now*.
        let mut p = processor();
        let mut ctx = ts::TestCtx::at(FULL);
        let a = ts::body(1, 1);
        let b = ts::body(2, 1);
        ctx.mempool.add(&a);
        ctx.mempool.add(&b);
        let first = ts::announcement_for(ORD, FULL + 1, 1, None, std::slice::from_ref(&a));
        let first_id = ts::ann_id(&first);
        let eff = announce(&mut p, &ctx, &first, ts::PEER);
        let (stale_job, stale_gen, _, _, _) = ts::one_validate(&eff);

        // A new best full block retires that job and moves the tree on.
        const ORD2: OrderingId = [0xCC; 32];
        ctx.full_block_height = FULL + 1;
        ctx.handle(
            &mut p,
            Event::OrderingBlockApplied {
                header_id: ORD2,
                height: FULL + 1,
                now: Tick(3),
            },
        );
        let second = ts::announcement_for(ORD2, FULL + 2, 2, None, std::slice::from_ref(&b));
        let second_id = ts::ann_id(&second);
        let current = announce(&mut p, &ctx, &second, ts::PEER);
        let (current_job, _, current_block, _, _) = ts::one_validate(&current);
        assert_eq!(current_block, second_id);

        let out = ctx.handle(
            &mut p,
            Event::ValidationResult {
                job: stale_job,
                generation: stale_gen,
                outcome: ValidationOutcome::Valid(1),
            },
        );
        assert_eq!(
            drops(&out),
            vec![DropReason::StaleValidation {
                generation: stale_gen
            }]
        );
        assert_eq!(
            stale_ids(&out),
            vec![first_id],
            "the stale job's own block must be named, not the current one"
        );
        // The outstanding job is untouched and still answers.
        let current_gen = p.generation();
        let applied = ctx.handle(
            &mut p,
            Event::ValidationResult {
                job: current_job,
                generation: current_gen,
                outcome: ValidationOutcome::Valid(1),
            },
        );
        assert!(applied.iter().any(
            |e| matches!(e, Effect::ChainChanged { applied, .. } if applied == &vec![second_id])
        ));
    }

    #[test]
    fn request_slot_is_released_by_the_matching_delivery() {
        let bounds = Bounds {
            requests_per_peer: 1,
            ..Bounds::default()
        };
        let mut p = processor_with(bounds);
        let ctx = ts::TestCtx::at(FULL);
        let a1 = ts::announcement(ORD, FULL + 1, 1, None);
        let id1 = ts::ann_id(&a1);
        let eff = announce(&mut p, &ctx, &a1, ts::PEER);
        assert!(eff
            .iter()
            .any(|e| matches!(e, Effect::RequestTransactionIds { .. })));

        // A delivery that answers a *different* request releases nothing.
        let other = ctx.handle(
            &mut p,
            Event::TransactionsDelivered {
                input_block_id: id1,
                bodies: Vec::new(),
                from: Some(ts::PEER),
                now: Tick(1),
            },
        );
        assert!(drops(&other).contains(&DropReason::UnknownBlock) || !other.is_empty());
        let a2 = ts::announcement(ORD, FULL + 1, 2, Some(id1));
        let eff = announce(&mut p, &ctx, &a2, ts::PEER);
        assert!(
            drops(&eff).contains(&DropReason::RequestsFull),
            "an unanswered request keeps holding its slot: {eff:?}"
        );

        // The weak-id list the request asked for releases it.
        ctx.handle(
            &mut p,
            Event::TransactionIdsDelivered {
                input_block_id: id1,
                weak_ids: Vec::new(),
                from: ts::PEER,
                now: Tick(2),
            },
        );
        let a3 = ts::announcement(ORD, FULL + 1, 3, Some(id1));
        let eff = announce(&mut p, &ctx, &a3, ts::PEER);
        assert!(
            eff.iter()
                .any(|e| matches!(e, Effect::RequestTransactionIds { .. })),
            "the answered slot must be free again: {eff:?}"
        );
    }

    #[test]
    fn unanswered_request_slot_expires_only_at_its_deadline() {
        // The counter used to halve on every Tick, so one tick freed a
        // peer's whole budget whatever it owed. Slots now expire at an
        // explicit deadline.
        let bounds = Bounds {
            requests_per_peer: 1,
            ..Bounds::default()
        };
        let timeout = bounds.request_timeout_ms;
        let mut p = processor_with(bounds);
        let ctx = ts::TestCtx::at(FULL);
        let a1 = ts::announcement(ORD, FULL + 1, 1, None);
        let eff = ctx.handle(
            &mut p,
            Event::AnnouncementAccepted {
                ann: a1.clone(),
                from: ts::PEER,
                now: Tick(0),
            },
        );
        assert!(eff
            .iter()
            .any(|e| matches!(e, Effect::RequestTransactionIds { .. })));

        ctx.handle(
            &mut p,
            Event::Tick {
                now: Tick(timeout / 2),
            },
        );
        let a2 = ts::announcement(ORD, FULL + 1, 2, Some(ts::ann_id(&a1)));
        let eff = ctx.handle(
            &mut p,
            Event::AnnouncementAccepted {
                ann: a2.clone(),
                from: ts::PEER,
                now: Tick(timeout / 2),
            },
        );
        assert!(
            drops(&eff).contains(&DropReason::RequestsFull),
            "a tick must not refund an outstanding request: {eff:?}"
        );

        // At the deadline the request is REISSUED to the same peer
        // (finding 4 / spec 9.2), so the slot stays held: the question
        // has not been answered and the node is still asking it.
        let ticked = ctx.handle(
            &mut p,
            Event::Tick {
                now: Tick(timeout + 1),
            },
        );
        assert!(
            ticked
                .iter()
                .any(|e| matches!(e, Effect::RequestTransactionIds { .. })),
            "the deadline reissues the request: {ticked:?}"
        );
        assert_eq!(p.requests_retried(), 1);

        // Only once the retry budget is spent is the slot released.
        // Each tick is well past the doubled deadline of the last.
        let mut at = timeout + 1;
        for _ in 0..=Bounds::default().request_retries {
            at += timeout * 16;
            ctx.handle(&mut p, Event::Tick { now: Tick(at) });
        }
        let a3 = ts::announcement(ORD, FULL + 1, 3, Some(ts::ann_id(&a1)));
        let eff = ctx.handle(
            &mut p,
            Event::AnnouncementAccepted {
                ann: a3,
                from: ts::PEER,
                now: Tick(at),
            },
        );
        assert!(
            eff.iter()
                .any(|e| matches!(e, Effect::RequestTransactionIds { .. })),
            "a request that exhausted its retries releases its slot: {eff:?}"
        );
        assert_eq!(
            p.requests_retried(),
            u64::from(Bounds::default().request_retries),
            "the retry count is capped by the budget"
        );
    }

    // ----- residuals fix round: A (drop reasons a node can act on) -----

    #[test]
    fn spent_digest_budget_is_reported_as_a_budget_not_a_mismatch() {
        // `CandidatesExhausted` used to stand for four different things
        // and a spent digest budget was reported as a *mismatch* — the
        // bodies blamed for a local limit. A node alarming on the reason
        // has to be able to tell the two apart.
        let mut p = processor();
        let x = ts::body(1, 1);
        let y = ts::body(2, 1);
        let mut ctx = ts::TestCtx::at(FULL);
        let cap = Bounds::default().candidates_per_position as u8;
        for seed in 30..30 + cap {
            ctx.mempool.add_under(x.weak_id, &ts::body(seed, 1));
        }
        for seed in 40..40 + cap {
            ctx.mempool.add_under(y.weak_id, &ts::body(seed, 1));
        }
        let ann = ts::announcement_for(ORD, FULL + 1, 1, None, &[x.clone(), y.clone()]);
        let id = ts::ann_id(&ann);
        let eff = announce(&mut p, &ctx, &ann, ts::PEER);

        assert_eq!(
            p.staged_digest_attempts(&id),
            Bounds::default().digest_attempts_per_block
        );
        assert!(
            drops(&eff).contains(&DropReason::DigestBudgetExhausted),
            "{eff:?}"
        );
        assert!(
            !drops(&eff).contains(&DropReason::TxDigestMismatch),
            "a spent budget is not the bodies' fault: {eff:?}"
        );
        // The announcer is still asked for the positions it could settle.
        assert!(
            eff.iter()
                .any(|e| matches!(e, Effect::RequestTransactions { .. })),
            "{eff:?}"
        );
        // Reported once per block, however often re-selection reaches it.
        let again = ctx.handle(
            &mut p,
            Event::TransactionsDelivered {
                input_block_id: id,
                bodies: Vec::new(),
                from: Some(ts::PEER),
                now: Tick(6),
            },
        );
        assert!(
            !drops(&again).contains(&DropReason::DigestBudgetExhausted),
            "the give-up must not repeat: {again:?}"
        );
    }

    #[test]
    fn variant_cap_hit_names_the_position() {
        let cap = Bounds::default().candidates_per_position;
        let (_p, _ctx, _id, eff) = over_stuffed_position(cap as u8 + 1, cap as u8);
        assert!(
            drops(&eff).contains(&DropReason::VariantCapExceeded { position: 0 }),
            "the cap hit must name the announced position: {eff:?}"
        );
        assert!(
            !eff.iter().any(|e| matches!(e, Effect::Penalize { .. })),
            "a cap hit blames nobody: {eff:?}"
        );
    }

    #[test]
    fn dispatch_guard_reports_the_spent_validation_budget() {
        // The give-up used to be reported only after a failure, so a
        // block that reached the guard by any other route was silently
        // stuck. Here a generation bump retires the only dispatch the
        // budget allowed, and re-selection meets the guard.
        let bounds = Bounds {
            validation_retries_per_block: 1,
            ..Bounds::default()
        };
        let mut p = processor_with(bounds);
        let b1 = ts::body(1, 1);
        let mut ctx = ts::TestCtx::at(FULL);
        ctx.mempool.add(&b1);
        let ann = ts::announcement_for(ORD, FULL + 1, 1, None, std::slice::from_ref(&b1));
        let id = ts::ann_id(&ann);
        let eff = announce(&mut p, &ctx, &ann, ts::PEER);
        assert!(has_validate(&eff));
        assert_eq!(p.validation_attempts(&id), 1);

        let bumped = ctx.handle(
            &mut p,
            Event::OrderingBlockApplied {
                header_id: ORD,
                height: FULL,
                now: Tick(4),
            },
        );
        assert!(!has_validate(&bumped), "the budget is spent: {bumped:?}");
        assert!(
            drops(&bumped).contains(&DropReason::ValidationBudgetExhausted),
            "the dispatch guard must report the give-up: {bumped:?}"
        );
        assert!(
            !bumped.iter().any(|e| matches!(e, Effect::Penalize { .. })),
            "a spent local budget blames nobody: {bumped:?}"
        );
    }

    // ----- residuals fix round: B (the announcer's recovery allowance) -----

    /// A block whose ordered-digest budget is spent, with a body request
    /// outstanding to the announcer: the state a recovery delivery
    /// answers. Returns the processor, the context, the block id and the
    /// two bodies the announcement actually committed to.
    fn digest_budget_spent() -> (Processor, ts::TestCtx, InputBlockId, Body, Body) {
        let mut p = processor();
        let x = ts::body(1, 1);
        let y = ts::body(2, 1);
        let mut ctx = ts::TestCtx::at(FULL);
        let cap = Bounds::default().candidates_per_position as u8;
        for seed in 30..30 + cap {
            ctx.mempool.add_under(x.weak_id, &ts::body(seed, 1));
        }
        for seed in 40..40 + cap {
            ctx.mempool.add_under(y.weak_id, &ts::body(seed, 1));
        }
        let ann = ts::announcement_for(ORD, FULL + 1, 1, None, &[x.clone(), y.clone()]);
        let id = ts::ann_id(&ann);
        let eff = announce(&mut p, &ctx, &ann, ts::PEER);
        assert!(
            eff.iter()
                .any(|e| matches!(e, Effect::RequestTransactions { .. })),
            "the announcer must have been asked for bodies: {eff:?}"
        );
        assert!(!has_validate(&eff));
        (p, ctx, id, x, y)
    }

    #[test]
    fn announcer_recovery_confirms_an_exact_delivery_once() {
        // "Permanent until pruned" left even the announcer's own exact
        // answer unable to rescue a block whose budget a pile of local
        // guesses had spent. One extra ordered-digest check — consumed
        // before it is spent, never refunded — fixes that without
        // reopening the budget.
        let budget = Bounds::default().digest_attempts_per_block;
        let (mut p, ctx, id, x, y) = digest_budget_spent();
        assert_eq!(p.staged_digest_attempts(&id), budget);

        let eff = ctx.handle(
            &mut p,
            Event::TransactionsDelivered {
                input_block_id: id,
                bodies: vec![x.clone(), y.clone()],
                from: Some(ts::PEER),
                now: Tick(20),
            },
        );
        let (_, _, block, txs, _) = ts::one_validate(&eff);
        assert_eq!(block, id);
        assert_eq!(txs, vec![x.tx_ref, y.tx_ref]);
        assert_eq!(
            p.staged_digest_attempts(&id),
            budget + 1,
            "recovery buys exactly one more ordered-digest check"
        );
    }

    #[test]
    fn announcer_recovery_is_refused_the_second_time() {
        let budget = Bounds::default().digest_attempts_per_block;
        let (mut p, ctx, id, x, y) = digest_budget_spent();

        // A well-formed but wrong answer spends the allowance: it is
        // consumed before the check, so a failed rescue is not refundable.
        let wrong = vec![
            ts::body_under(x.weak_id, 50, 1),
            ts::body_under(y.weak_id, 51, 1),
        ];
        let spent = ctx.handle(
            &mut p,
            Event::TransactionsDelivered {
                input_block_id: id,
                bodies: wrong,
                from: Some(ts::PEER),
                now: Tick(20),
            },
        );
        assert!(!has_validate(&spent), "{spent:?}");
        assert_eq!(p.staged_digest_attempts(&id), budget + 1);

        let second = ctx.handle(
            &mut p,
            Event::TransactionsDelivered {
                input_block_id: id,
                bodies: vec![x.clone(), y.clone()],
                from: Some(ts::PEER),
                now: Tick(21),
            },
        );
        assert!(
            !has_validate(&second),
            "the allowance is single-use: {second:?}"
        );
        assert_eq!(
            p.staged_digest_attempts(&id),
            budget + 1,
            "a second recovery must not buy another check"
        );
    }

    /// A block that has spent its validation budget, with a body request
    /// outstanding to the announcer.
    fn validation_budget_spent(budget: usize) -> (Processor, ts::TestCtx, InputBlockId, WeakId) {
        let bounds = Bounds {
            validation_retries_per_block: budget,
            ..Bounds::default()
        };
        let mut p = processor_with(bounds);
        let ctx = ts::TestCtx::at(FULL);
        let first = ts::body(1, 1);
        // The mempool is empty, so the bodies are requested from the
        // announcer and every delivery below answers that request.
        let ann = ts::announcement_for(ORD, FULL + 1, 1, None, std::slice::from_ref(&first));
        let id = ts::ann_id(&ann);
        let eff = announce(&mut p, &ctx, &ann, ts::PEER);
        assert!(eff
            .iter()
            .any(|e| matches!(e, Effect::RequestTransactions { .. })));

        for w in 1..=budget as u8 {
            let eff = ctx.handle(
                &mut p,
                Event::TransactionsDelivered {
                    input_block_id: id,
                    bodies: vec![ts::body_under(first.weak_id, 1, w)],
                    from: Some(ts::PEER),
                    now: Tick(u64::from(w)),
                },
            );
            assert!(has_validate(&eff), "witness {w} must run: {eff:?}");
            ts::validate_err(&mut p, &ctx, &eff);
        }
        assert_eq!(p.validation_attempts(&id), budget);
        (p, ctx, id, first.weak_id)
    }

    #[test]
    fn announcer_recovery_buys_one_more_validation() {
        let budget = 2usize;
        let (mut p, ctx, id, weak) = validation_budget_spent(budget);
        let fresh = ts::body_under(weak, 1, budget as u8 + 1);

        let eff = ctx.handle(
            &mut p,
            Event::TransactionsDelivered {
                input_block_id: id,
                bodies: vec![fresh.clone()],
                from: Some(ts::PEER),
                now: Tick(30),
            },
        );
        let (_, _, block, txs, _) = ts::one_validate(&eff);
        assert_eq!(block, id);
        assert_eq!(
            txs,
            vec![fresh.tx_ref],
            "the recovered selection is the one the announcer proposed"
        );
        assert_eq!(p.validation_attempts(&id), budget + 1);

        // Pinned through validation: another witness may not swap it out.
        let during = ctx.handle(
            &mut p,
            Event::TransactionsDelivered {
                input_block_id: id,
                bodies: vec![ts::body_under(weak, 1, budget as u8 + 2)],
                from: Some(ts::PEER),
                now: Tick(31),
            },
        );
        assert!(!has_validate(&during), "{during:?}");
        assert_eq!(p.transaction_refs(&id), Some(&[fresh.tx_ref][..]));

        // And the allowance is spent: once this job fails too, nothing
        // the announcer sends starts another.
        ts::validate_err(&mut p, &ctx, &eff);
        let after = ctx.handle(
            &mut p,
            Event::TransactionsDelivered {
                input_block_id: id,
                bodies: vec![ts::body_under(weak, 1, budget as u8 + 3)],
                from: Some(ts::PEER),
                now: Tick(32),
            },
        );
        assert!(
            !has_validate(&after),
            "the validation allowance is single-use: {after:?}"
        );
        assert_eq!(p.validation_attempts(&id), budget + 1);
    }

    #[test]
    fn a_stranger_cannot_spend_the_announcers_recovery() {
        let budget = 2usize;
        let (mut p, ctx, id, weak) = validation_budget_spent(budget);
        let fresh = ts::body_under(weak, 1, budget as u8 + 1);

        let stranger = ctx.handle(
            &mut p,
            Event::TransactionsDelivered {
                input_block_id: id,
                bodies: vec![fresh.clone()],
                from: PeerTag::remote(99),
                now: Tick(30),
            },
        );
        assert!(
            !has_validate(&stranger),
            "only the announcer may spend the allowance: {stranger:?}"
        );
        assert_eq!(p.validation_attempts(&id), budget);

        // The announcer's own delivery still works afterwards, so the
        // stranger consumed nothing.
        let eff = ctx.handle(
            &mut p,
            Event::TransactionsDelivered {
                input_block_id: id,
                bodies: vec![fresh.clone()],
                from: Some(ts::PEER),
                now: Tick(31),
            },
        );
        let (_, _, _, txs, _) = ts::one_validate(&eff);
        assert_eq!(txs, vec![fresh.tx_ref]);
    }

    #[test]
    fn recovery_never_replaces_applied_references() {
        // The budget can be spent by the very dispatch that applied the
        // block; the allowance must still not reopen it.
        let bounds = Bounds {
            validation_retries_per_block: 1,
            ..Bounds::default()
        };
        let mut p = processor_with(bounds);
        let ctx = ts::TestCtx::at(FULL);
        let good = ts::body(1, 1);
        let ann = ts::announcement_for(ORD, FULL + 1, 1, None, std::slice::from_ref(&good));
        let id = ts::ann_id(&ann);
        announce(&mut p, &ctx, &ann, ts::PEER);
        let eff = ctx.handle(
            &mut p,
            Event::TransactionsDelivered {
                input_block_id: id,
                bodies: vec![good.clone()],
                from: Some(ts::PEER),
                now: Tick(2),
            },
        );
        ts::validate_ok(&mut p, &ctx, &eff, 1);
        assert_eq!(p.best_input_chain(), vec![id]);
        assert!(p.validation_attempts(&id) >= 1);

        let late = ctx.handle(
            &mut p,
            Event::TransactionsDelivered {
                input_block_id: id,
                bodies: vec![ts::body_under(good.weak_id, 1, 2)],
                from: Some(ts::PEER),
                now: Tick(3),
            },
        );
        assert!(!has_validate(&late), "{late:?}");
        assert_eq!(
            p.transaction_refs(&id),
            Some(&[good.tx_ref][..]),
            "applied references are frozen, allowance or not"
        );
        assert!(
            drops(&late).contains(&DropReason::SelectionSettled {
                state: SelectionState::Applied
            }),
            "{late:?}"
        );
    }

    // ----- residuals fix round 2 -----

    /// How many `RequestTransactions` effects in `effects` are addressed
    /// to `peer`.
    fn body_requests_to(effects: &[Effect], peer: PeerTag) -> usize {
        effects
            .iter()
            .filter(|e| matches!(e, Effect::RequestTransactions { from, .. } if *from == peer))
            .count()
    }

    #[test]
    fn repeated_triggering_deliveries_never_exceed_the_request_cap() {
        // Re-selection reaches an unresolved block on every event, so the
        // same question was re-emitted to the same peer on every event
        // too — without allocating a slot, because the key was already
        // there. The cap has to bound *emitted* requests, not just the
        // slots.
        let cap = 2usize;
        let bounds = Bounds {
            requests_per_peer: cap,
            ..Bounds::default()
        };
        let mut p = processor_with(bounds);
        let base = ts::body(7, 1);
        let mut ctx = ts::TestCtx::at(FULL);
        // One position with more local guesses than the per-position cap:
        // the block stays unresolved and every event asks the announcer
        // to settle it.
        for w in 1..=Bounds::default().candidates_per_position as u8 + 1 {
            ctx.mempool.add_under(base.weak_id, &ts::body(7, w));
        }
        let ann = ts::announcement_for(ORD, FULL + 1, 1, None, std::slice::from_ref(&base));
        let id = ts::ann_id(&ann);
        let mut emitted = body_requests_to(&announce(&mut p, &ctx, &ann, ts::PEER), ts::PEER);
        assert_eq!(emitted, 1, "the first request must go out");

        // A stranger keeps poking the block with bodies that resolve
        // nothing; the announcer never answers.
        for tick in 0..10u64 {
            let eff = ctx.handle(
                &mut p,
                Event::TransactionsDelivered {
                    input_block_id: id,
                    bodies: vec![ts::body(200, 1)],
                    from: PeerTag::remote(99),
                    now: Tick(tick),
                },
            );
            emitted += body_requests_to(&eff, ts::PEER);
        }
        assert!(
            emitted <= cap,
            "{emitted} requests emitted to one peer, cap is {cap}"
        );

        // The suppression is not permanent: once the request times out
        // the announcer is asked again — by the deadline sweep itself
        // (finding 4 / spec 9.2), not by whatever event happens next.
        let timeout = Bounds::default().request_timeout_ms;
        let ticked = ctx.handle(
            &mut p,
            Event::Tick {
                now: Tick(timeout + 1),
            },
        );
        assert_eq!(
            body_requests_to(&ticked, ts::PEER),
            1,
            "the deadline reissues the body request: {ticked:?}"
        );
        // And the reissue holds the slot, so the stranger's pokes still
        // cannot make the node ask again on top of it.
        let after = ctx.handle(
            &mut p,
            Event::TransactionsDelivered {
                input_block_id: id,
                bodies: vec![ts::body(200, 2)],
                from: PeerTag::remote(99),
                now: Tick(timeout + 2),
            },
        );
        assert_eq!(
            body_requests_to(&after, ts::PEER),
            0,
            "the reissued request is still outstanding: {after:?}"
        );
    }

    #[test]
    fn announcer_proposal_waits_for_the_outstanding_job() {
        // The budget is already spent when the *last* ordinary job is
        // dispatched, so an announcer delivery arriving before that job
        // answers must not replace its references: that invalidates a
        // job whose result might have been a success, and spends the
        // recovery dispatch on top. The proposal is held instead, and
        // used the moment the job fails.
        let budget = 2usize;
        let bounds = Bounds {
            validation_retries_per_block: budget,
            ..Bounds::default()
        };
        let mut p = processor_with(bounds);
        let ctx = ts::TestCtx::at(FULL);
        let first = ts::body(1, 1);
        let weak = first.weak_id;
        let ann = ts::announcement_for(ORD, FULL + 1, 1, None, std::slice::from_ref(&first));
        let id = ts::ann_id(&ann);
        announce(&mut p, &ctx, &ann, ts::PEER);

        let mut eff = Vec::new();
        for w in 1..=budget as u8 {
            eff = ctx.handle(
                &mut p,
                Event::TransactionsDelivered {
                    input_block_id: id,
                    bodies: vec![ts::body_under(weak, 1, w)],
                    from: Some(ts::PEER),
                    now: Tick(u64::from(w)),
                },
            );
            assert!(has_validate(&eff), "witness {w} must run: {eff:?}");
            if w < budget as u8 {
                ts::validate_err(&mut p, &ctx, &eff);
            }
        }
        // The last ordinary job is outstanding and the budget is spent.
        assert_eq!(p.validation_attempts(&id), budget);
        let outstanding = ts::body_under(weak, 1, budget as u8);

        let proposal = ts::body_under(weak, 1, budget as u8 + 1);
        let held = ctx.handle(
            &mut p,
            Event::TransactionsDelivered {
                input_block_id: id,
                bodies: vec![proposal.clone()],
                from: Some(ts::PEER),
                now: Tick(20),
            },
        );
        assert!(!has_validate(&held), "{held:?}");
        assert!(
            !drops(&held)
                .iter()
                .any(|r| matches!(r, DropReason::StaleValidation { .. })),
            "the outstanding job must not be invalidated: {held:?}"
        );
        assert_eq!(
            p.transaction_refs(&id),
            Some(&[outstanding.tx_ref][..]),
            "the outstanding job's references must stay frozen"
        );
        assert!(drops(&held).contains(&DropReason::SelectionSettled {
            state: SelectionState::Pending
        }));
        assert_eq!(p.validation_attempts(&id), budget, "nothing new dispatched");

        // Now that job fails — and the held proposal is taken without
        // another delivery.
        let revived = ts::validate_err(&mut p, &ctx, &eff);
        let (_, _, block, txs, _) = ts::one_validate(&revived);
        assert_eq!(block, id);
        assert_eq!(
            txs,
            vec![proposal.tx_ref],
            "the held proposal must be the retry"
        );
        assert_eq!(p.validation_attempts(&id), budget + 1);
    }

    #[test]
    fn a_stranger_candidate_cannot_divert_the_recovery_check() {
        // The sole extra digest attempt must check the announcer's own
        // proposal, not whatever the ordinary search reaches first: a
        // stranger that drops one wrong candidate into the block could
        // otherwise spend the allowance on a combination nobody
        // proposed.
        let budget = Bounds::default().digest_attempts_per_block;
        let (mut p, mut ctx, id, x, y) = digest_budget_spent();
        // The guesses that spent the budget have left the mempool, so the
        // second position has no candidate at all: the staging slot the
        // stranger creates survives, waiting for the announcer, with the
        // stranger's candidate in it.
        ctx.mempool = ts::Mempool::default();

        let decoy = ctx.handle(
            &mut p,
            Event::TransactionsDelivered {
                input_block_id: id,
                bodies: vec![ts::body_under(x.weak_id, 60, 1)],
                from: PeerTag::remote(99),
                now: Tick(20),
            },
        );
        assert!(!has_validate(&decoy), "{decoy:?}");
        assert_eq!(
            p.staged_digest_attempts(&id),
            budget,
            "a stranger buys no attempts"
        );

        let eff = ctx.handle(
            &mut p,
            Event::TransactionsDelivered {
                input_block_id: id,
                bodies: vec![x.clone(), y.clone()],
                from: Some(ts::PEER),
                now: Tick(21),
            },
        );
        let (_, _, block, txs, _) = ts::one_validate(&eff);
        assert_eq!(block, id);
        assert_eq!(txs, vec![x.tx_ref, y.tx_ref]);
        assert_eq!(
            p.staged_digest_attempts(&id),
            budget + 1,
            "exactly one extra check, spent on the proposal itself"
        );
    }

    #[test]
    fn listless_alternative_is_retried_after_the_outstanding_job_fails() {
        // A witness refused because a job was outstanding used to be
        // discarded: the failure that followed had nothing to retry with
        // and the block needed another delivery to make progress.
        let mut p = processor();
        let ctx = ts::TestCtx::at(FULL);
        let v1 = ts::body(1, 1);
        let v2 = ts::body(1, 2);
        let ann = listless(1, v1.tx_ref.tx_id, None);
        let id = ts::ann_id(&ann);
        announce(&mut p, &ctx, &ann, ts::PEER);
        let first = ctx.handle(
            &mut p,
            Event::TransactionsDelivered {
                input_block_id: id,
                bodies: vec![v1.clone()],
                from: Some(ts::PEER),
                now: Tick(2),
            },
        );
        assert!(has_validate(&first));

        let refused = ctx.handle(
            &mut p,
            Event::TransactionsDelivered {
                input_block_id: id,
                bodies: vec![v2.clone()],
                from: Some(ts::PEER),
                now: Tick(3),
            },
        );
        assert!(!has_validate(&refused), "{refused:?}");
        assert_eq!(p.transaction_refs(&id), Some(&[v1.tx_ref][..]));
        assert!(drops(&refused).contains(&DropReason::SelectionSettled {
            state: SelectionState::Pending
        }));

        // No further delivery: the failure alone must reach the witness
        // that was waiting.
        let retried = ts::validate_err(&mut p, &ctx, &first);
        let (_, _, block, txs, _) = ts::one_validate(&retried);
        assert_eq!(block, id);
        assert_eq!(
            txs,
            vec![v2.tx_ref],
            "the retained alternative must be dispatched"
        );
    }

    // ----- residuals fix round 3 -----

    #[test]
    fn listless_alternatives_are_kept_until_one_validates() {
        // One held slot per block meant the second alternative evicted
        // the first: with A outstanding, B and then C delivered, the
        // failure of A reached C — and B was unreachable without another
        // delivery. Alternatives are retained up to the per-position cap.
        let mut p = processor();
        let ctx = ts::TestCtx::at(FULL);
        let a = ts::body(1, 1);
        let b = ts::body(1, 2);
        let c = ts::body(1, 3);
        let ann = listless(1, a.tx_ref.tx_id, None);
        let id = ts::ann_id(&ann);
        announce(&mut p, &ctx, &ann, ts::PEER);
        let running = ctx.handle(
            &mut p,
            Event::TransactionsDelivered {
                input_block_id: id,
                bodies: vec![a.clone()],
                from: Some(ts::PEER),
                now: Tick(2),
            },
        );
        assert!(has_validate(&running));

        for (tick, body) in [(3u64, &b), (4, &c)] {
            let refused = ctx.handle(
                &mut p,
                Event::TransactionsDelivered {
                    input_block_id: id,
                    bodies: vec![body.clone()],
                    from: Some(ts::PEER),
                    now: Tick(tick),
                },
            );
            assert!(!has_validate(&refused), "{refused:?}");
            assert!(drops(&refused).contains(&DropReason::SelectionSettled {
                state: SelectionState::Pending
            }));
        }
        assert_eq!(p.transaction_refs(&id), Some(&[a.tx_ref][..]));

        // A fails: the most recent alternative runs.
        let second = ts::validate_err(&mut p, &ctx, &running);
        let (_, _, _, txs, _) = ts::one_validate(&second);
        assert_eq!(txs, vec![c.tx_ref], "the newest alternative runs first");

        // C fails too: the older one must still be there, with no
        // further delivery.
        let third = ts::validate_err(&mut p, &ctx, &second);
        let (_, _, block, txs, _) = ts::one_validate(&third);
        assert_eq!(block, id);
        assert_eq!(
            txs,
            vec![b.tx_ref],
            "the alternative delivered first must not have been evicted"
        );
    }

    #[test]
    fn answering_one_body_request_leaves_the_other_counted() {
        // Completion removed *every* body request for the block, so an
        // answer to one weak-id set — or a body delivery answering
        // nothing at all — freed slots that were still owed.
        let bounds = Bounds {
            requests_per_peer: 2,
            ..Bounds::default()
        };
        let mut p = processor_with(bounds);
        let x0 = ts::body(1, 1);
        let x1 = ts::body(2, 1);
        let mut ctx = ts::TestCtx::at(FULL);
        // Position 0 is over the per-position cap, position 1 is empty:
        // both are asked for in one request.
        for w in 1..=Bounds::default().candidates_per_position as u8 + 1 {
            ctx.mempool.add_under(x0.weak_id, &ts::body(1, w));
        }
        let ann = ts::announcement_for(ORD, FULL + 1, 1, None, &[x0.clone(), x1.clone()]);
        let id = ts::ann_id(&ann);
        let eff = announce(&mut p, &ctx, &ann, ts::PEER);
        assert_eq!(body_requests_to(&eff, ts::PEER), 1, "{eff:?}");

        // The announcer settles position 0. That answers neither set —
        // the request asked for both weak ids — and asking for the one
        // still missing is a second, different request.
        let narrowed = ctx.handle(
            &mut p,
            Event::TransactionsDelivered {
                input_block_id: id,
                bodies: vec![x0.clone()],
                from: Some(ts::PEER),
                now: Tick(2),
            },
        );
        assert_eq!(
            body_requests_to(&narrowed, ts::PEER),
            1,
            "the narrower set is a new request: {narrowed:?}"
        );

        // Both slots are now owed. A body delivery that answers neither
        // must not free one.
        let unrelated = ctx.handle(
            &mut p,
            Event::TransactionsDelivered {
                input_block_id: id,
                bodies: vec![ts::body(200, 1)],
                from: Some(ts::PEER),
                now: Tick(3),
            },
        );
        assert!(!drops(&unrelated).contains(&DropReason::RequestsFull));
        let blocked = ts::announcement(ORD, FULL + 1, 2, None);
        let eff = announce(&mut p, &ctx, &blocked, ts::PEER);
        assert!(
            drops(&eff).contains(&DropReason::RequestsFull),
            "an unrelated delivery must not free a slot: {eff:?}"
        );

        // Answering the outstanding set frees exactly that one slot.
        ctx.handle(
            &mut p,
            Event::TransactionsDelivered {
                input_block_id: id,
                bodies: vec![x1.clone()],
                from: Some(ts::PEER),
                now: Tick(4),
            },
        );
        let freed = ts::announcement(ORD, FULL + 1, 3, None);
        let eff = announce(&mut p, &ctx, &freed, ts::PEER);
        assert!(
            eff.iter()
                .any(|e| matches!(e, Effect::RequestTransactionIds { .. })),
            "the answered request must free its slot: {eff:?}"
        );
    }

    #[test]
    fn a_suppressed_invitation_is_emitted_when_a_slot_frees() {
        // The block was marked invited before the request was emitted,
        // so an invitation the request cap refused was never retried —
        // and the recovery allowance became unreachable for good.
        let bounds = Bounds {
            requests_per_peer: 1,
            validation_retries_per_block: 1,
            ..Bounds::default()
        };
        let mut p = processor_with(bounds);
        let b1 = ts::body(1, 1);
        let mut ctx = ts::TestCtx::at(FULL);
        ctx.mempool.add(&b1);

        // This one takes the peer's only request slot and never answers.
        // It hangs off a different ordering block, so it cannot compete
        // for the tree the validation below runs in.
        const OTHER: OrderingId = [0xEE; 32];
        let holder = ts::announcement(OTHER, FULL + 1, 1, None);
        let holder_id = ts::ann_id(&holder);
        let eff = announce(&mut p, &ctx, &holder, ts::PEER);
        assert!(eff
            .iter()
            .any(|e| matches!(e, Effect::RequestTransactionIds { .. })));

        // The block below resolves from the mempool and its single
        // validation dispatches at once, spending the budget: the
        // invitation is due, and the cap refuses it.
        let ann = ts::announcement_for(ORD, FULL + 1, 2, None, std::slice::from_ref(&b1));
        let id = ts::ann_id(&ann);
        let dispatched = announce(&mut p, &ctx, &ann, ts::PEER);
        assert!(has_validate(&dispatched));
        assert_eq!(
            body_requests_to(&dispatched, ts::PEER),
            0,
            "the cap must refuse the invitation: {dispatched:?}"
        );

        // The holder answers, freeing the slot: the deferred invitation
        // must go out now.
        let freed = ctx.handle(
            &mut p,
            Event::TransactionIdsDelivered {
                input_block_id: holder_id,
                weak_ids: Vec::new(),
                from: ts::PEER,
                now: Tick(5),
            },
        );
        assert!(
            freed.iter().any(|e| matches!(
                e,
                Effect::RequestTransactions { input_block_id, from, .. }
                    if *input_block_id == id && *from == ts::PEER
            )),
            "the deferred invitation must be emitted once a slot frees: {freed:?}"
        );
    }

    #[test]
    fn a_zero_candidate_cap_holds_nothing_instead_of_panicking() {
        // `candidates_per_position: 0` is a nonsensical configuration,
        // but the node reads its bounds from config and the processor
        // must not panic on one: holding the first alternative found
        // `slot.len() >= 0` true and removed from an empty vector.
        let bounds = Bounds {
            candidates_per_position: 0,
            ..Bounds::default()
        };
        let mut p = processor_with(bounds);
        let ctx = ts::TestCtx::at(FULL);
        let a = ts::body(1, 1);
        let b = ts::body(1, 2);
        let ann = listless(1, a.tx_ref.tx_id, None);
        let id = ts::ann_id(&ann);
        announce(&mut p, &ctx, &ann, ts::PEER);
        let running = ctx.handle(
            &mut p,
            Event::TransactionsDelivered {
                input_block_id: id,
                bodies: vec![a.clone()],
                from: Some(ts::PEER),
                now: Tick(2),
            },
        );
        assert!(has_validate(&running));

        // The delivery that used to panic.
        let refused = ctx.handle(
            &mut p,
            Event::TransactionsDelivered {
                input_block_id: id,
                bodies: vec![b.clone()],
                from: Some(ts::PEER),
                now: Tick(3),
            },
        );
        assert!(!has_validate(&refused), "{refused:?}");
        assert!(drops(&refused).contains(&DropReason::SelectionSettled {
            state: SelectionState::Pending
        }));
        assert_eq!(
            p.transaction_refs(&id),
            Some(&[a.tx_ref][..]),
            "the outstanding job keeps its references"
        );

        // The clamp in `Processor::new` means the block still behaves
        // like a one-deep cap rather than losing the alternative.
        let after = ts::validate_err(&mut p, &ctx, &running);
        let (_, _, block, txs, _) = ts::one_validate(&after);
        assert_eq!(block, id);
        assert_eq!(txs, vec![b.tx_ref]);
    }

    #[test]
    fn zero_capacity_bounds_are_clamped_at_construction() {
        // Every bound the processor indexes or evicts against survives a
        // zero from config: the announcement is recorded, its bodies
        // resolve and the block applies, rather than the processor
        // dividing by an empty structure somewhere.
        let bounds = Bounds {
            candidates_per_position: 0,
            forks_per_ordering: 0,
            records_per_ordering: 0,
            waitlist_entries: 0,
            pending_triggers: 0,
            retired_jobs: 0,
            ..Bounds::default()
        };
        let mut p = processor_with(bounds);
        let b1 = ts::body(1, 1);
        let mut ctx = ts::TestCtx::at(FULL);
        ctx.mempool.add(&b1);
        let ann = ts::announcement_for(ORD, FULL + 1, 1, None, std::slice::from_ref(&b1));
        let id = ts::ann_id(&ann);

        let eff = announce(&mut p, &ctx, &ann, ts::PEER);
        assert!(
            has_validate(&eff),
            "a clamped cap still admits one: {eff:?}"
        );
        let applied = ts::validate_ok(&mut p, &ctx, &eff, 1);
        assert!(applied.iter().any(|e| matches!(
            e,
            Effect::ChainChanged { applied, .. } if applied == &vec![id]
        )));
        assert_eq!(p.best_input_chain(), vec![id]);

        // The clamped record cap is one, so the next announcement for
        // this ordering block is refused — the bound bites, rather than
        // the structure misbehaving.
        let second = ts::announcement(ORD, FULL + 1, 2, Some([0x77; 32]));
        let eff = ctx.handle(
            &mut p,
            Event::AnnouncementAccepted {
                ann: second,
                from: ts::PEER,
                now: Tick(5),
            },
        );
        assert_eq!(drops(&eff), vec![DropReason::RecordsFull], "{eff:?}");
    }

    #[test]
    fn zero_ordering_announcement_cap_still_stores_one_section() {
        // `ordering_announcements` is a capacity like the bounds clamped
        // above: `OrderingStore` inserts first and only then evicts down
        // to the cap, so at zero the entry evicted is the one just
        // inserted. Left unclamped, a configured 0 makes both the
        // announcement map and the section map silently forget every
        // write instead of retaining one.
        let mut p = processor_with(Bounds {
            ordering_announcements: 0,
            ..Bounds::default()
        });
        let header_id: OrderingId = [0xab; 32];
        let tx = TxRef {
            tx_id: [0xcd; 32],
            witness_id: [0xef; 31],
        };

        let evicted = p.save_ordering_block_transactions(header_id, vec![tx]);
        assert_eq!(evicted, None, "the only section must not evict itself");
        assert_eq!(
            p.ordering_block_transactions(&header_id),
            Some(&[tx][..]),
            "a clamped cap still retains one section"
        );
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
        // Scala `applyInputBlock`: `ib.header.height > bestOrderingHeight
        // + HeightThreshold(2)` calls `resetState()` (i.e. `prune()`)
        // before recording. The node's reported full-block height (which
        // drives the ±2 window) and the processor's mirrored best-ordering
        // height are separate inputs, so a jump is reachable without
        // tripping the window check.
        let mut p = processor();
        let ctx = ts::TestCtx::at(FULL);
        let old = ts::announcement(ORD, FULL + 1, 1, None); // height 11
        let old_id = ts::ann_id(&old);
        announce(&mut p, &ctx, &old, ts::PEER);

        // No jump: best ordering height 10, announcement at 11, and
        // 11 > 10 + 2 is false — nothing is pruned.
        let flat = ts::announcement(ORD, FULL + 1, 2, None);
        announce(&mut p, &ctx, &flat, ts::PEER);
        assert!(p.announcement(&old_id).is_some());

        // Jump: best ordering height 14 while the node's full height is
        // 19, so an announcement at 20 is inside the ±2 window and
        // 20 > 14 + 2 holds. `resetState()` then prunes the height-11
        // record (14 - 11 == 3 > PruningThreshold).
        p.set_best_ordering(Some(ORD), 14);
        let ctx = ts::TestCtx::at(19);
        let jump = ts::announcement(ORD, 20, 3, None);
        announce(&mut p, &ctx, &jump, ts::PEER);
        assert!(
            p.announcement(&old_id).is_none(),
            "the height jump's resetState() prunes the stale record"
        );
        assert!(p.announcement(&ts::ann_id(&jump)).is_some());
    }

    // ----- fix round 1 (Plan 2 M2 codex review, finding 2) -----

    #[test]
    fn revision_starts_at_zero() {
        let p = processor();
        assert_eq!(p.revision(), 0);
    }

    #[test]
    fn revision_bumps_on_every_handle_call_including_a_no_op_tick() {
        let mut p = processor();
        let ctx = ts::TestCtx::at(FULL);
        let before = p.revision();
        // A tick with nothing to expire and nothing outstanding — no
        // effects, yet the revision must still move (fix-round-1,
        // finding 4: the caller can't tell "nothing happened" from "a
        // silent mutation happened" any other way).
        let eff = ctx.handle(&mut p, Event::Tick { now: Tick(0) });
        assert!(eff.is_empty(), "a bare tick with nothing to sweep is quiet");
        assert_eq!(p.revision(), before + 1);

        announce(
            &mut p,
            &ctx,
            &ts::announcement(ORD, FULL + 1, 1, None),
            ts::PEER,
        );
        assert_eq!(
            p.revision(),
            before + 2,
            "a second handle() call bumps it again"
        );
    }

    #[test]
    fn known_input_block_ids_empty_on_a_fresh_processor() {
        let p = processor();
        assert!(p.known_input_block_ids().is_empty());
    }

    #[test]
    fn known_input_block_ids_includes_records_outside_the_best_chain() {
        let mut p = processor();
        let ctx = ts::TestCtx::at(FULL);
        // Two sibling, fully-applied (zero-tx) blocks, same height, no
        // shared parent: two competing forks, only one of which
        // `best_input_chain()` picks as the tree's tip.
        let a1 = ts::announcement(ORD, FULL + 1, 1, None);
        let a2 = ts::announcement(ORD, FULL + 1, 2, None);
        let id1 = ts::ann_id(&a1);
        let id2 = ts::ann_id(&a2);
        ts::announce_and_apply(&mut p, &ctx, &a1, 0);
        ts::announce_and_apply(&mut p, &ctx, &a2, 0);

        let best_chain = p.best_input_chain();
        assert_eq!(
            best_chain.len(),
            1,
            "only one of the two competing blocks is best"
        );

        let known = p.known_input_block_ids();
        assert_eq!(known.len(), 2, "both records are retained");
        assert!(known.contains(&id1));
        assert!(known.contains(&id2));
        assert!(
            known.iter().any(|id| !best_chain.contains(id)),
            "the losing fork's id must be reachable even though it's not best"
        );
    }

    // ----- fix round 2 (Plan 2 M2 final whole-branch review) -----

    /// Finding 7: an ordering announcement was validated, stored and
    /// relayed before anything asked whether it was worth looking at. A
    /// peer replaying valid HISTORICAL announcements therefore bought,
    /// per frame, a PoW verification, an `Inv` broadcast to every
    /// eligible peer, and the eviction of a live entry from the bounded
    /// 64-slot announcement store.
    ///
    /// Spec 9.3 (and Scala `processOrderingBlockAnnouncement`) applies
    /// the ±2 height window first.
    #[test]
    fn ordering_announcement_outside_the_height_window_is_dropped_before_any_work() {
        let mut p = processor();
        let ctx = ts::TestCtx::at(FULL);
        // Three ordering blocks back: valid, and long since useless.
        let oa = ts::ordering_announcement(ORD, FULL - 3, 9, Vec::new());
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
            out.contains(&Effect::Dropped {
                id: oa_id,
                reason: DropReason::OutsideHeightWindow,
            }),
            "{out:?}"
        );
        assert!(
            !out.iter()
                .any(|e| matches!(e, Effect::RelayOrderingInv { .. })),
            "a replay must not be rebroadcast: {out:?}"
        );
        assert!(
            p.ordering_announcement(&oa_id).is_none(),
            "and must not take a slot in the announcement store"
        );
    }

    /// The same guard's other half: an announcement for a header the
    /// node already holds is dead weight, and spec 9.3 skips it before
    /// PoW, storage and relay.
    #[test]
    fn ordering_announcement_for_a_known_header_is_dropped_before_any_work() {
        let mut p = processor();
        let mut ctx = ts::TestCtx::at(FULL);
        let oa = ts::ordering_announcement(ORD, FULL + 1, 9, Vec::new());
        let oa_id = ts::header_id(&oa.header);
        ctx.known_headers.insert(oa_id);

        let out = ctx.handle(
            &mut p,
            Event::OrderingAnnouncementAccepted {
                ann: oa,
                from: ts::PEER,
                now: Tick(6),
            },
        );

        assert!(
            out.contains(&Effect::Dropped {
                id: oa_id,
                reason: DropReason::OrderingHeaderKnown,
            }),
            "{out:?}"
        );
        assert!(
            !out.iter()
                .any(|e| matches!(e, Effect::RelayOrderingInv { .. })),
            "{out:?}"
        );
        assert!(p.ordering_announcement(&oa_id).is_none());
    }

    /// A re-announcement of one the processor has already stored is the
    /// same replay by another route: the store is the node's own record
    /// of "known", and re-inserting would re-relay and re-evict.
    #[test]
    fn a_replayed_ordering_announcement_is_dropped_without_relaying_again() {
        let mut p = processor();
        let ctx = ts::TestCtx::at(FULL);
        let oa = ts::ordering_announcement(ORD, FULL + 1, 9, Vec::new());
        let oa_id = ts::header_id(&oa.header);

        let first = ctx.handle(
            &mut p,
            Event::OrderingAnnouncementAccepted {
                ann: oa.clone(),
                from: ts::PEER,
                now: Tick(6),
            },
        );
        assert!(
            first.contains(&Effect::RelayOrderingInv { header_id: oa_id }),
            "the first sighting is relayed: {first:?}"
        );
        assert!(p.ordering_announcement(&oa_id).is_some());

        let again = ctx.handle(
            &mut p,
            Event::OrderingAnnouncementAccepted {
                ann: oa,
                from: ts::PEER,
                now: Tick(7),
            },
        );
        assert!(
            again.contains(&Effect::Dropped {
                id: oa_id,
                reason: DropReason::OrderingHeaderKnown,
            }),
            "{again:?}"
        );
        assert!(
            !again
                .iter()
                .any(|e| matches!(e, Effect::RelayOrderingInv { .. })),
            "the second sighting buys the peer nothing: {again:?}"
        );
    }

    /// Finding 4: neither delivery layer reissued a timed-out
    /// input-block request. The coordinator forgets them without
    /// re-requesting (parity: Scala's `checkDelivery` applies no
    /// NonDelivery penalty for the three new type ids) on the
    /// assumption that the processor retries; the processor only expired
    /// the slot. A lost parent announcement or transaction-id reply was
    /// therefore terminal — later announcements of the recorded child
    /// hit `AlreadyKnown`, so the question was never asked again.
    ///
    /// Here the announcer never answers the `-122` request. Every
    /// deadline must reissue it to the same peer, with the wait doubling
    /// per attempt, until `Bounds::request_retries` is spent.
    #[test]
    fn a_timed_out_request_is_reissued_with_backoff_until_the_cap() {
        let bounds = Bounds::default();
        let timeout = bounds.request_timeout_ms;
        let retries = bounds.request_retries;
        let mut p = processor_with(bounds);
        let ctx = ts::TestCtx::at(FULL);

        let ann = ts::announcement(ORD, FULL + 1, 1, None);
        let id = ts::ann_id(&ann);
        let eff = announce(&mut p, &ctx, &ann, ts::PEER);
        let asked = |eff: &[Effect]| {
            eff.iter()
                .filter(|e| {
                    matches!(
                        e,
                        Effect::RequestTransactionIds {
                            input_block_id,
                            from,
                        } if *input_block_id == id && *from == ts::PEER
                    )
                })
                .count()
        };
        assert_eq!(asked(&eff), 1, "the first request goes out");
        assert_eq!(p.requests_retried(), 0);

        // A tick before the deadline changes nothing.
        let early = ctx.handle(
            &mut p,
            Event::Tick {
                now: Tick(timeout - 1),
            },
        );
        assert_eq!(asked(&early), 0, "not due yet: {early:?}");

        // Each deadline reissues once, and the next one is twice as far
        // out — so a tick one plain timeout later is NOT yet due.
        let mut now = timeout + 1;
        for attempt in 1..=retries {
            let out = ctx.handle(&mut p, Event::Tick { now: Tick(now) });
            assert_eq!(asked(&out), 1, "attempt {attempt} reissues: {out:?}");
            assert_eq!(p.requests_retried(), u64::from(attempt));
            let shift = (attempt - 1).min(REQUEST_BACKOFF_SHIFT_CAP);
            let wait = timeout << shift;
            let too_early = ctx.handle(
                &mut p,
                Event::Tick {
                    now: Tick(now + wait - 1),
                },
            );
            assert_eq!(
                asked(&too_early),
                0,
                "attempt {attempt} backs off to {wait} ms: {too_early:?}"
            );
            now += wait + 1;
        }

        // The budget is spent: the deadline now releases the slot
        // instead of asking again, and the count stops rising.
        let done = ctx.handle(&mut p, Event::Tick { now: Tick(now) });
        assert_eq!(asked(&done), 0, "the cap is respected: {done:?}");
        assert_eq!(p.requests_retried(), u64::from(retries));
        let after = ctx.handle(
            &mut p,
            Event::Tick {
                now: Tick(now + timeout * 16),
            },
        );
        assert_eq!(asked(&after), 0, "and stays spent: {after:?}");
        assert_eq!(p.requests_retried(), u64::from(retries));
    }

    /// The retry is not a penalty engine: an answered request is
    /// released by its delivery and never reissued, however long the
    /// node runs afterwards.
    #[test]
    fn an_answered_request_is_never_reissued() {
        let bounds = Bounds::default();
        let timeout = bounds.request_timeout_ms;
        let mut p = processor_with(bounds);
        let ctx = ts::TestCtx::at(FULL);

        let b1 = ts::body(1, 1);
        let ann = ts::announcement(ORD, FULL + 1, 1, None);
        let id = ts::ann_id(&ann);
        announce(&mut p, &ctx, &ann, ts::PEER);
        ctx.handle(
            &mut p,
            Event::TransactionIdsDelivered {
                input_block_id: id,
                weak_ids: vec![b1.weak_id],
                from: ts::PEER,
                now: Tick(1),
            },
        );

        let out = ctx.handle(
            &mut p,
            Event::Tick {
                now: Tick(timeout * 64),
            },
        );
        assert!(
            !out.iter()
                .any(|e| matches!(e, Effect::RequestTransactionIds { .. })),
            "the answered id request is gone, not retried: {out:?}"
        );
    }

    // ----- fix round 3 (M2 final re-review r2) -----

    /// Round-2 finding 1: the retry sweep was not the only thing that
    /// touched an expired slot. `request` pruned expired slots of the
    /// peer it was about to ask, so ANY intervening request to that peer
    /// between a deadline and the next tick deleted the timed-out
    /// request outright — it was never reissued, and later announcements
    /// of its recorded child hit `AlreadyKnown`. The retry contract has
    /// to hold regardless of intervening traffic.
    #[test]
    fn an_expired_request_survives_another_request_to_the_same_peer_and_is_reissued() {
        let bounds = Bounds::default();
        let timeout = bounds.request_timeout_ms;
        let mut p = processor_with(bounds);
        let ctx = ts::TestCtx::at(FULL);

        // Block A: announced, its weak-id list requested from PEER.
        let a = ts::announcement(ORD, FULL + 1, 1, None);
        let a_id = ts::ann_id(&a);
        let asked_for = |eff: &[Effect], want: InputBlockId| {
            eff.iter()
                .filter(|e| {
                    matches!(
                        e,
                        Effect::RequestTransactionIds {
                            input_block_id,
                            from,
                        } if *input_block_id == want && *from == ts::PEER
                    )
                })
                .count()
        };
        let first = announce(&mut p, &ctx, &a, ts::PEER);
        assert_eq!(asked_for(&first, a_id), 1, "A's id request goes out");

        // A's deadline passes. Before the tick can sweep it, a SECOND
        // block is announced by the same peer, which issues its own
        // request to that peer.
        let b = ts::announcement(ORD, FULL + 1, 2, None);
        let b_id = ts::ann_id(&b);
        let between = ctx.handle(
            &mut p,
            Event::AnnouncementAccepted {
                ann: b,
                from: ts::PEER,
                now: Tick(timeout + 1),
            },
        );
        assert_eq!(asked_for(&between, b_id), 1, "B's id request goes out too");
        assert_eq!(
            asked_for(&between, a_id),
            0,
            "and it is not A's request: {between:?}"
        );

        // The tick must still reissue A. Before the fix A's slot had
        // been deleted by B's request and nothing asked for it again.
        let ticked = ctx.handle(
            &mut p,
            Event::Tick {
                now: Tick(timeout + 2),
            },
        );
        assert_eq!(
            asked_for(&ticked, a_id),
            1,
            "the expired request is reissued despite the traffic in between: {ticked:?}"
        );
        assert_eq!(p.requests_retried(), 1, "and it is accounted as a retry");
    }

    /// The other half of the same invariant, and the correction the
    /// devnet smoke forced: a retry-pending slot survives, but it must
    /// NOT hold an in-flight slot — and the reissue that eventually
    /// serves it must still respect the in-flight cap.
    ///
    /// The first cut of this fix counted retry-pending slots against
    /// `requests_per_peer`. A retry ladder keeps a slot for minutes, so
    /// against a miner publishing an input block a second the follower's
    /// 32 slots filled with questions awaiting reissue and every new
    /// body request was dropped `RequestsFull` — 128 of them on the
    /// smoke, with the input chain unable to keep up. The cap bounds
    /// what is on the wire; the retry queue is bounded separately.
    ///
    /// The second cut then let the TICK exceed the cap from the other
    /// side: it reissued every expired request unconditionally, so with
    /// a cap of one, A expiring and B taking the slot left both in
    /// flight the moment the tick ran. A queued request waits for
    /// capacity, and only an actual reissue costs an attempt.
    #[test]
    fn a_retry_pending_slot_does_not_consume_in_flight_capacity() {
        let bounds = Bounds {
            requests_per_peer: 1,
            ..Bounds::default()
        };
        let timeout = bounds.request_timeout_ms;
        let mut p = processor_with(bounds);
        let ctx = ts::TestCtx::at(FULL);

        let a = ts::announcement(ORD, FULL + 1, 1, None);
        let a_id = ts::ann_id(&a);
        announce(&mut p, &ctx, &a, ts::PEER);

        // Past A's deadline: its slot is awaiting reissue, not on the
        // wire, so B may be asked for even at a cap of one.
        let b = ts::announcement(ORD, FULL + 1, 2, None);
        let b_id = ts::ann_id(&b);
        let between = ctx.handle(
            &mut p,
            Event::AnnouncementAccepted {
                ann: b,
                from: ts::PEER,
                now: Tick(timeout + 1),
            },
        );
        assert!(
            !drops(&between).contains(&DropReason::RequestsFull),
            "a retry-pending slot must not block a live request: {between:?}"
        );
        assert!(
            between.iter().any(|e| matches!(
                e,
                Effect::RequestTransactionIds { input_block_id, .. } if *input_block_id == b_id
            )),
            "B's request goes out: {between:?}"
        );

        // B now holds the one in-flight slot, so the tick must NOT
        // reissue A on top of it: that would put two requests on a wire
        // the operator capped at one. A stays queued, unspent.
        let ticked = ctx.handle(
            &mut p,
            Event::Tick {
                now: Tick(timeout + 2),
            },
        );
        assert!(
            !ticked.iter().any(|e| matches!(
                e,
                Effect::RequestTransactionIds { input_block_id, .. } if *input_block_id == a_id
            )),
            "the cap holds A back while B is in flight: {ticked:?}"
        );
        assert_eq!(
            p.requests_retried(),
            0,
            "a request that was not reissued did not spend an attempt"
        );

        // B is answered, freeing the slot; now A gets its reissue.
        ctx.handle(
            &mut p,
            Event::TransactionIdsDelivered {
                input_block_id: b_id,
                weak_ids: Vec::new(),
                from: ts::PEER,
                now: Tick(timeout + 3),
            },
        );
        let after = ctx.handle(
            &mut p,
            Event::Tick {
                now: Tick(timeout + 4),
            },
        );
        assert!(
            after.iter().any(|e| matches!(
                e,
                Effect::RequestTransactionIds { input_block_id, .. } if *input_block_id == a_id
            )),
            "once capacity frees, the queued request is reissued: {after:?}"
        );
        assert_eq!(p.requests_retried(), 1, "and only then is it counted");
    }

    /// The retry queue is bounded: at `requests_per_peer +
    /// retry_pending_per_peer` a NEW request is refused, rather than an
    /// old one being deleted to make room.
    #[test]
    fn the_retry_queue_is_bounded_by_refusing_new_requests_not_dropping_old_ones() {
        let bounds = Bounds {
            requests_per_peer: 1,
            retry_pending_per_peer: 1,
            ..Bounds::default()
        };
        let timeout = bounds.request_timeout_ms;
        let mut p = processor_with(bounds);
        let ctx = ts::TestCtx::at(FULL);

        let a = ts::announcement(ORD, FULL + 1, 1, None);
        let a_id = ts::ann_id(&a);
        announce(&mut p, &ctx, &a, ts::PEER);
        // A expires; B takes the one in-flight slot (total 2 = ceiling).
        let b = ts::announcement(ORD, FULL + 1, 2, None);
        let b_id = ts::ann_id(&b);
        ctx.handle(
            &mut p,
            Event::AnnouncementAccepted {
                ann: b,
                from: ts::PEER,
                now: Tick(timeout + 1),
            },
        );
        // C finds the ceiling and is refused.
        let c = ts::announcement(ORD, FULL + 1, 3, None);
        let third = ctx.handle(
            &mut p,
            Event::AnnouncementAccepted {
                ann: c,
                from: ts::PEER,
                now: Tick(timeout + 2),
            },
        );
        assert!(
            drops(&third).contains(&DropReason::RequestsFull),
            "the ceiling refuses the new request: {third:?}"
        );
        // A — the oldest, retry-pending one — was not sacrificed for
        // it. The tick cannot reissue it yet (B holds the single
        // in-flight slot), but it is still there: once B is answered,
        // A goes back out.
        let ticked = ctx.handle(
            &mut p,
            Event::Tick {
                now: Tick(timeout + 3),
            },
        );
        assert!(
            !ticked.iter().any(|e| matches!(
                e,
                Effect::RequestTransactionIds { input_block_id, .. } if *input_block_id == a_id
            )),
            "still no capacity for A: {ticked:?}"
        );
        ctx.handle(
            &mut p,
            Event::TransactionIdsDelivered {
                input_block_id: b_id,
                weak_ids: Vec::new(),
                from: ts::PEER,
                now: Tick(timeout + 4),
            },
        );
        let after = ctx.handle(
            &mut p,
            Event::Tick {
                now: Tick(timeout + 5),
            },
        );
        assert!(
            after.iter().any(|e| matches!(
                e,
                Effect::RequestTransactionIds { input_block_id, .. } if *input_block_id == a_id
            )),
            "the queued request survived the ceiling and is reissued: {after:?}"
        );
    }
}
