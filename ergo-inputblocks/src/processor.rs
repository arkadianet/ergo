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
            bytes: 0,
            created,
            from,
        }
    }

    /// Add `body` as a candidate for position `i`, ignoring a duplicate
    /// `TxRef` (the mempool and a peer's delivery routinely overlap).
    fn add(&mut self, i: usize, body: Body) {
        if self.variants.is_some() {
            return;
        }
        if self.candidates[i].iter().any(|b| b.tx_ref == body.tx_ref) {
            return;
        }
        self.bytes += body.bytes.len();
        self.candidates[i].push(body);
    }

    /// The `TxRef`s the current cursor selects, once resolved.
    fn selected(&self) -> Option<Vec<TxRef>> {
        let vars = self.variants.as_ref()?;
        vars.iter()
            .zip(self.cursor.iter())
            .map(|(v, c)| v.get(*c).copied())
            .collect()
    }

    /// Odometer step over the per-position candidate lists (spec 7.5's
    /// witness-variant retry). Returns `false` once every combination
    /// reachable from the current cursor has been tried.
    fn advance(&mut self) -> bool {
        let Some(vars) = self.variants.as_ref() else {
            return false;
        };
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

/// What [`Processor::resolve`] concluded about one block's staged bodies.
enum Resolution {
    /// Every position resolved and the ordered digest matched.
    Complete(Vec<TxRef>),
    /// These announced weak ids still need bodies from the announcer.
    Request(Vec<WeakId>),
    /// Exactly one candidate per position, and the digest disagreed.
    DigestMismatch,
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
            failed: HashSet::new(),
            pending_triggers: VecDeque::new(),
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
        if let Some(st) = self.staging.get_mut(&id) {
            for (i, bodies) in found {
                for b in bodies {
                    st.add(i, b);
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

    /// Spec 7.5 steps 1–4: resolve every announced position to one body.
    fn resolve(&self, id: &InputBlockId) -> Resolution {
        let Some(st) = self.staging.get(id) else {
            return Resolution::Request(Vec::new());
        };
        if let Some(sel) = st.selected() {
            return Resolution::Complete(sel);
        }

        let mut needed: Vec<WeakId> = Vec::new();
        for (i, c) in st.candidates.iter().enumerate() {
            if c.is_empty() || c.len() > self.bounds.candidates_per_position {
                needed.push(st.weak_ids[i]);
            }
        }
        if !needed.is_empty() {
            return Resolution::Request(needed);
        }

        let variants: Vec<Vec<TxRef>> = st
            .candidates
            .iter()
            .map(|c| c.iter().map(|b| b.tx_ref).collect())
            .collect();

        if self.digest_bypassed(id) {
            return Resolution::Complete(
                variants.iter().filter_map(|v| v.first().copied()).collect(),
            );
        }
        let Some(expected) = self.announced_digest(id) else {
            return Resolution::Request(Vec::new());
        };

        // Try candidate combinations (odometer over positions) until the
        // ordered transaction-id digest reproduces the announcement's.
        let mut cursor = vec![0usize; variants.len()];
        let mut attempts = 0usize;
        loop {
            let ids: Vec<[u8; 32]> = variants
                .iter()
                .zip(cursor.iter())
                .map(|(v, c)| v[*c].tx_id)
                .collect();
            let refs: Vec<&[u8]> = ids.iter().map(|i| &i[..]).collect();
            if ergo_crypto::merkle::merkle_tree_root(&refs) == expected {
                return Resolution::Complete(
                    variants
                        .iter()
                        .zip(cursor.iter())
                        .map(|(v, c)| v[*c])
                        .collect(),
                );
            }
            attempts += 1;
            if attempts >= self.bounds.digest_attempts_per_block {
                break;
            }
            let mut stepped = false;
            for (i, v) in variants.iter().enumerate() {
                if cursor[i] + 1 < v.len() {
                    cursor[i] += 1;
                    for c in cursor.iter_mut().take(i) {
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

        // No combination matched. If some position is ambiguous the peer's
        // own body settles it (spec 7.5 item 4); otherwise the delivered
        // bodies simply disagree with the announcement.
        let ambiguous: Vec<WeakId> = st
            .weak_ids
            .iter()
            .enumerate()
            .filter(|(i, _)| variants[*i].len() > 1)
            .map(|(_, w)| *w)
            .collect();
        if ambiguous.is_empty() {
            Resolution::DigestMismatch
        } else {
            Resolution::Request(ambiguous)
        }
    }

    fn complete_or_request(&mut self, id: InputBlockId, out: &mut Vec<Effect>) {
        let from = self
            .staging
            .get(&id)
            .and_then(|s| s.from)
            .or_else(|| self.records.get(&id).map(|r| r.from));
        match self.resolve(&id) {
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

    /// The digest matched: move the block's candidate bodies into the
    /// shared cache, remember the per-position variants for spec 7.5's
    /// retry, and free the staging bytes.
    fn commit_resolution(&mut self, id: InputBlockId, refs: Vec<TxRef>, out: &mut Vec<Effect>) {
        let now = self.staging.get(&id).map(|s| s.created).unwrap_or(Tick(0));
        if let Some(st) = self.staging.get_mut(&id) {
            if st.variants.is_none() {
                let variants: Vec<Vec<TxRef>> = st
                    .candidates
                    .iter()
                    .map(|c| c.iter().map(|b| b.tx_ref).collect())
                    .collect();
                let cursor: Vec<usize> = variants
                    .iter()
                    .zip(refs.iter())
                    .map(|(v, r)| v.iter().position(|x| x == r).unwrap_or(0))
                    .collect();
                let bodies: Vec<Body> = st.candidates.iter().flatten().cloned().collect();
                st.candidates = vec![Vec::new(); variants.len()];
                st.bytes = 0;
                st.variants = Some(variants);
                st.cursor = cursor;
                for b in bodies {
                    self.cache.insert(b, now, &self.bounds);
                }
            }
        }
        self.tx_refs.insert(id, refs);
        let Some(ordering_id) = self.records.get(&id).map(|r| r.ordering_id) else {
            return;
        };
        self.pump(ordering_id, id, out);
    }

    // ----- delivered bodies (message 104) -----

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
        match rec.ann.weak_tx_ids.clone() {
            Some(weak) => {
                self.staging
                    .entry(id)
                    .or_insert_with(|| Staging::new(weak.clone(), now, from.or(Some(announcer))));
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
                            st.add(i, b.clone());
                        }
                    }
                }
                self.refresh_from_mempool(id, ctx);
                self.enforce_staging_bytes(id, out);
                self.complete_or_request(id, out);
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
                self.tx_refs.insert(id, refs);
                let Some(ordering_id) = self.records.get(&id).map(|r| r.ordering_id) else {
                    return;
                };
                self.pump(ordering_id, id, out);
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
            if self.pending_triggers.len() >= self.bounds.pending_triggers {
                self.pending_triggers.pop_front();
            }
            self.pending_triggers.push_back((ordering_id, trigger));
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
        let mut previous: Vec<TxRef> = Vec::new();
        for pid in &prev_chain {
            match self.tx_refs.get(pid) {
                Some(v) => previous.extend(v.iter().copied()),
                None => {
                    out.push(Effect::Dropped {
                        id: *pid,
                        reason: DropReason::CacheEvicted,
                    });
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
            out.push(Effect::Dropped {
                id: target,
                reason: DropReason::CacheEvicted,
            });
            return;
        }
        let job = self.next_job;
        self.next_job += 1;
        self.in_flight = Some(InFlight {
            job,
            generation: self.generation,
            id: target,
            ordering_id,
        });
        out.push(Effect::Validate {
            job,
            generation: self.generation,
            input_block_id: target,
            txs,
            previous,
        });
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
            tree.process(&target, &has_txs, &mut apply)
        };
        self.trees.insert(inf.ordering_id, outcome.tree);
        if !outcome.applied.is_empty() || !outcome.rolled_back.is_empty() {
            out.push(Effect::ChainChanged {
                ordering_id: inf.ordering_id,
                applied: outcome.applied,
                rolled_back: outcome.rolled_back,
            });
            self.generation += 1;
        }
        self.resume(inf.ordering_id, out);
    }

    /// Spec 7.5's witness-variant retry: swap in the next candidate for
    /// the block that failed and re-run it; when the combinations are
    /// exhausted the fork simply stops progressing (Scala: application
    /// failure).
    fn on_validation_failed(&mut self, inf: InFlight, out: &mut Vec<Effect>) {
        let id = inf.id;
        if let Some(refs) = self.tx_refs.get(&id) {
            for r in refs.clone() {
                self.failed.insert((id, r));
            }
        }
        let next =
            self.staging.get_mut(&id).and_then(
                |st| {
                    if st.advance() {
                        st.selected()
                    } else {
                        None
                    }
                },
            );
        if let Some(refs) = next {
            self.tx_refs.insert(id, refs);
            self.pump(inf.ordering_id, id, out);
            return;
        }
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

    /// Spec 7.6's re-selection: on the active tree, take the selected
    /// fork's `first_to_complete()` and validate it when its bodies are
    /// available; otherwise retry whatever triggers were deferred while a
    /// job was in flight.
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
        let deferred: Vec<(OrderingId, InputBlockId)> = self.pending_triggers.drain(..).collect();
        for (oid, trigger) in deferred {
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
        for id in stale_records {
            self.records.shift_remove(&id);
            self.tx_refs.remove(&id);
            self.staging.shift_remove(&id);
            self.waitlist.retain(|(w, _)| *w != id);
            self.failed.retain(|(b, _)| *b != id);
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

    /// Whether `(block, variant)` has already failed validation (spec 7.5).
    pub fn has_failed(&self, id: &InputBlockId, variant: &TxRef) -> bool {
        self.failed.contains(&(*id, *variant))
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
