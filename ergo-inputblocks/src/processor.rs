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
    /// A delivered witness cannot replace the block's transaction
    /// selection: that selection is not in a rejected state — it is
    /// either outstanding or already applied — so swapping it would put
    /// an unvalidated body into a processed block.
    SelectionSettled,
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
    failed: HashMap<InputBlockId, Vec<Vec<TxRef>>>,
    pending_triggers: VecDeque<(OrderingId, InputBlockId)>,
    /// Blocks whose unavailable bodies have already been reported. Spec
    /// 7.6's re-selection reaches a stalled block again on every event, so
    /// without this the same `CacheEvicted` is emitted over and over;
    /// the entry is cleared the moment the bodies are back.
    reported_evicted: std::collections::HashSet<InputBlockId>,
    /// Ordered-digest attempts spent per input block. Deliberately keyed
    /// by block rather than held in the staging slot, which is deleted on
    /// a digest mismatch — the budget must not be refundable by making
    /// the slot unresolvable and then recreating it (fix round 2,
    /// finding r2-1). Released when the record is pruned.
    digest_attempts: HashMap<InputBlockId, usize>,
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
    delivered: bool,
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
    fn add(&mut self, i: usize, body: Body, delivered: bool, cap: usize) -> bool {
        if self.variants.is_some() || i >= self.candidates.len() {
            return false;
        }
        if let Some(existing) = self.candidates[i]
            .iter_mut()
            .find(|c| c.body.tx_ref == body.tx_ref)
        {
            if delivered && !existing.delivered {
                existing.delivered = true;
                self.dirty = true;
            }
            return false;
        }
        let limit = if delivered { cap } else { cap + 1 };
        if self.candidates[i]
            .iter()
            .filter(|c| c.delivered == delivered)
            .count()
            >= limit
        {
            return false;
        }
        self.bytes += body.bytes.len();
        self.candidates[i].push(Candidate { body, delivered });
        self.dirty = true;
        true
    }

    /// The candidates that actually count at position `i`: the peer's own
    /// answers when it has given any, else the local guesses (spec 7.5
    /// item 4, "the peer's own body wins over local guesses").
    fn effective(&self, i: usize) -> Vec<&Candidate> {
        let slot = &self.candidates[i];
        if slot.iter().any(|c| c.delivered) {
            slot.iter().filter(|c| c.delivered).collect()
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
    if ambiguous.is_empty() {
        Resolution::DigestMismatch
    } else {
        Resolution::Request(ambiguous)
    }
}

impl Processor {
    /// A fresh processor with no state.
    pub fn new(bounds: Bounds, policy: AnnouncementPolicy) -> Self {
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
            ordering: OrderingStore::default(),
            outstanding: HashMap::new(),
            in_flight: None,
            failed: HashMap::new(),
            pending_triggers: VecDeque::new(),
            reported_evicted: std::collections::HashSet::new(),
            digest_attempts: HashMap::new(),
            validation_attempts: HashMap::new(),
            failed_trigger: HashMap::new(),
            continuation: None,
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
        let mut out = Vec::new();
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
            Event::Tick { now } => self.on_tick(now),
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
        // Step 3: already known (Scala `applyInputBlock`'s first guard).
        if self.records.contains_key(&id) {
            out.push(Effect::Dropped {
                id,
                reason: DropReason::AlreadyKnown,
            });
            return;
        }
        // Step 4 of 2.7: `+2` downloads the ordering header instead.
        if height == full.saturating_add(2) {
            self.request(
                out,
                Effect::RequestOrderingHeader {
                    header_id: ordering_id,
                    from,
                },
                from,
                id,
            );
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
                    st.add(i, b, false, cap);
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
        let budget = self.bounds.digest_attempts_per_block;
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
        }
    }

    /// The digest matched: keep only the bodies that can legitimately
    /// satisfy it, move those into the shared cache, and record the
    /// per-position variants for spec 7.5's retry.
    fn commit_resolution(&mut self, id: InputBlockId, refs: Vec<TxRef>, out: &mut Vec<Effect>) {
        let now = self.staging.get(&id).map(|s| s.created).unwrap_or(Tick(0));
        let cap = self.bounds.candidates_per_position;
        let mut to_cache: Vec<Body> = Vec::new();
        let mut over_cap = false;
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
                            over_cap = true;
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
        if over_cap {
            out.push(Effect::Dropped {
                id,
                reason: DropReason::CandidatesExhausted,
            });
        }
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
        now: Tick,
        out: &mut Vec<Effect>,
    ) -> bool {
        let cap = self.bounds.candidates_per_position;
        let mut to_cache: Vec<Body> = Vec::new();
        let mut over_cap = false;
        let mut admitted = false;
        if let Some(st) = self.staging.get_mut(&id) {
            let Some(variants) = st.variants.as_mut() else {
                return false;
            };
            for b in bodies {
                for variant in variants.iter_mut() {
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
                    } else {
                        // Spec 7.4's per-position bound applies after
                        // resolution too: a peer must not be able to grow
                        // a block's witness list — and, through it, the
                        // shared cache — by spraying witnesses of a
                        // committed transaction (fix round 2, finding
                        // r2-3).
                        over_cap = true;
                    }
                }
            }
        }
        for b in to_cache {
            self.cache.insert(b, now, &self.bounds);
        }
        if over_cap {
            out.push(Effect::Dropped {
                id,
                reason: DropReason::CandidatesExhausted,
            });
        }
        admitted
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
        let settled = match self.tx_refs.get(&id) {
            Some(current) => !self.has_failed_combination(&id, current),
            None => true,
        };
        if settled {
            out.push(Effect::Dropped {
                id,
                reason: DropReason::SelectionSettled,
            });
            return;
        }
        if self.validation_exhausted(&id) {
            return;
        }
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
                    reason: DropReason::StaleValidation,
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
        if let Some(c) = self.outstanding.get_mut(&from) {
            *c = c.saturating_sub(1);
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

    fn on_bodies(
        &mut self,
        id: InputBlockId,
        bodies: Vec<Body>,
        from: Option<PeerTag>,
        now: Tick,
        ctx: &ProcessorCtx<'_>,
        out: &mut Vec<Effect>,
    ) {
        if let Some(p) = from {
            if let Some(c) = self.outstanding.get_mut(&p) {
                *c = c.saturating_sub(1);
            }
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
                let mut refilled = false;
                if self.staging.get(&id).is_some_and(|s| s.variants.is_some()) {
                    // The block's digest already passed; a delivery now
                    // can only refill bodies the cache lost — or offer a
                    // witness the rejected selection did not have.
                    refilled = self.refill_verified(id, &bodies, now, out);
                } else {
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
                                st.add(i, b.clone(), true, cap);
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
                let ids: Vec<[u8; 32]> = bodies.iter().map(|b| b.tx_ref.tx_id).collect();
                if !self.digest_bypassed(&id) {
                    let refs: Vec<&[u8]> = ids.iter().map(|i| &i[..]).collect();
                    let expected = self.announced_digest(&id).unwrap_or_default();
                    if ergo_crypto::merkle::merkle_tree_root(&refs) != expected {
                        out.push(Effect::Dropped {
                            id,
                            reason: DropReason::TxDigestMismatch,
                        });
                        return;
                    }
                }
                let refs: Vec<TxRef> = bodies.iter().map(|b| b.tx_ref).collect();
                for b in bodies {
                    self.cache.insert(b, now, &self.bounds);
                }
                self.set_tx_refs(id, refs, out);
                let Some(ordering_id) = self.records.get(&id).map(|r| r.ordering_id) else {
                    return;
                };
                self.pump(ordering_id, id, out);
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
        // its bodies is offered again. Silent for the same reason as the
        // guard above: re-selection reaches this point on every later
        // event, and the give-up was already reported once.
        if self.validation_exhausted(&target) {
            tracing::debug!("skipping a block that has spent its validation budget");
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
        // The budget buys *dispatched* work. A job that a later delivery
        // invalidates through `set_tx_refs` still cost the node a full
        // block validation, so charging only accepted failure results
        // would let a peer spray witnesses and keep reissuing jobs with
        // the counter stuck at one.
        *self.validation_attempts.entry(target).or_insert(0) += 1;
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
        self.validation_attempts
            .get(id)
            .is_some_and(|n| *n >= self.bounds.validation_retries_per_block)
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
        outcome: Result<u64, String>,
        out: &mut Vec<Effect>,
    ) {
        let Some(inf) = self.in_flight.clone() else {
            // The job was invalidated by a generation bump, which clears
            // `in_flight`; there is no id left to name.
            out.push(Effect::Dropped {
                id: [0u8; 32],
                reason: DropReason::StaleValidation,
            });
            return;
        };
        if inf.job != job || inf.generation != generation {
            out.push(Effect::Dropped {
                id: inf.id,
                reason: DropReason::StaleValidation,
            });
            return;
        }
        self.in_flight = None;
        match outcome {
            Ok(cost) => self.on_validation_ok(inf, cost, out),
            Err(reason) => {
                tracing::debug!(%reason, "input block validation failed");
                self.on_validation_failed(inf, out)
            }
        }
    }

    fn on_validation_ok(&mut self, inf: InFlight, cost: u64, out: &mut Vec<Effect>) {
        // Fix round 1, finding 4: the job froze the bodies it was handed.
        // `set_tx_refs` normally invalidates a job the moment they change,
        // so this is the belt to that braces — it also covers a selection
        // that moved through any path that did not go through `pump`.
        if self.tx_refs.get(&inf.id).map(|v| v.as_slice()) != Some(inf.txs.as_slice()) {
            out.push(Effect::Dropped {
                id: inf.id,
                reason: DropReason::StaleValidation,
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
        if exhausted {
            out.push(Effect::Dropped {
                id,
                reason: DropReason::CandidatesExhausted,
            });
            if self.in_flight.is_none() {
                self.resume(inf.ordering_id, out);
            }
            return;
        }
        match self.next_untried_combination(id, false) {
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
                    DropReason::CandidatesExhausted
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

        match prev {
            Some(p) if self.tx_refs.contains_key(&p) => {
                out.push(Effect::OrderingReconstruct {
                    plan: ReconstructionPlan {
                        header_id,
                        non_broadcasted,
                        broadcasted_ids,
                        // Finding F5, preserved: Scala keys the collected
                        // input-chain transactions by the *announced*
                        // header's own id, not by the ordering block the
                        // input chain extends.
                        input_chain_txs: self.collected_input_txs(&header_id),
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
        self.resume(header_id, out);
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
            self.digest_attempts.remove(&id);
            self.validation_attempts.remove(&id);
            self.failed_trigger.remove(&id);
        }

        self.ordering.prune(
            best_height,
            self.bounds.ordering_announcement_prune_threshold,
            ctx.block_transactions_known,
        );
    }

    fn on_tick(&mut self, now: Tick) {
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
        // Outstanding-request counters decay geometrically: a peer that
        // never answers recovers its budget over a few ticks rather than
        // being blocked forever, and one that answers is credited
        // immediately by `on_bodies`.
        self.outstanding.retain(|_, c| {
            *c /= 2;
            *c > 0
        });
    }

    /// Issue `effect` to `peer` unless that peer is already at the
    /// outstanding-request cap (spec 7.4).
    fn request(&mut self, out: &mut Vec<Effect>, effect: Effect, peer: PeerTag, subject: [u8; 32]) {
        let counter = self.outstanding.entry(peer).or_insert(0);
        if *counter >= self.bounds.requests_per_peer {
            out.push(Effect::Dropped {
                id: subject,
                reason: DropReason::RequestsFull,
            });
            return;
        }
        *counter += 1;
        out.push(effect);
    }

    // ----- read side (API and p2p serving, Plan 2) -----

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
    pub fn save_ordering_block_transactions(&mut self, header_id: OrderingId, txs: Vec<TxRef>) {
        self.ordering.save_block_transactions(header_id, txs);
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

    #[test]
    fn stale_validation_result_dropped() {
        let mut p = processor();
        let b1 = ts::body(1, 1);
        let mut ctx = ts::TestCtx::at(FULL);
        ctx.mempool.add(&b1);
        let ann = ts::announcement_for(ORD, FULL + 1, 1, None, std::slice::from_ref(&b1));
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

    /// Finding 4. A delivery that swaps the body under an outstanding job
    /// invalidates that job; the late result must not be applied.
    #[test]
    fn interleaved_delivery_invalidates_the_outstanding_job() {
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
            drops(&second).contains(&DropReason::StaleValidation),
            "the outstanding job's bodies changed underneath it: {second:?}"
        );
        let (_, _, _, txs, _) = ts::one_validate(&second);
        assert_eq!(txs, vec![v2.tx_ref], "the job is reissued for the new body");

        let late = ctx.handle(
            &mut p,
            Event::ValidationResult {
                job: old_job,
                generation: old_gen,
                outcome: Ok(1),
            },
        );
        assert_eq!(drops(&late), vec![DropReason::StaleValidation]);
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
        // exhaustion. The peer now sends exactly the right bodies, which
        // makes every position unambiguous — but there is no budget left
        // to confirm them, so the slot is dropped as a digest mismatch.
        // The budget must outlive that slot: recreating staging on the
        // next delivery must not hand the block a fresh sixteen attempts.
        let correct = vec![x.clone(), y.clone()];
        let first = ctx.handle(
            &mut p,
            Event::TransactionsDelivered {
                input_block_id: id,
                bodies: correct.clone(),
                from: Some(ts::PEER),
                now: Tick(20),
            },
        );
        assert!(!has_validate(&first), "{first:?}");
        assert_eq!(p.staged_digest_attempts(&id), budget);

        let second = ctx.handle(
            &mut p,
            Event::TransactionsDelivered {
                input_block_id: id,
                bodies: correct,
                from: Some(ts::PEER),
                now: Tick(21),
            },
        );
        assert!(
            !has_validate(&second),
            "an exhausted block must stay exhausted: {second:?}"
        );
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

        // Replacing ib2b's witness invalidates that job; the reissue must
        // be the same fork switch, for the same block, with the new body.
        let replaced = ctx.handle(
            &mut p,
            Event::TransactionsDelivered {
                input_block_id: ib2b_id,
                bodies: vec![v2.clone()],
                from: Some(ts::PEER),
                now: Tick(6),
            },
        );
        assert!(
            drops(&replaced).contains(&DropReason::StaleValidation),
            "{replaced:?}"
        );
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
            if drops(&out).contains(&DropReason::CandidatesExhausted) {
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
            last.contains(&DropReason::CandidatesExhausted),
            "an exhausted budget must report CandidatesExhausted, got {last:?}"
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
            drops(&late).contains(&DropReason::SelectionSettled),
            "the unusable witness must be reported: {late:?}"
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
}
