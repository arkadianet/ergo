#![cfg(feature = "test-support")]
//! The ported `InputBlockProcessorSpecification` corpus (spec 10.3).
//!
//! Run with `cargo test -p ergo-inputblocks --features test-support`.
//! Without the feature the whole file compiles away, so the crate's
//! default `cargo test` stays green.
//!
//! Each case reproduces one Scala property's block/tree shape and its
//! asserted outcome. The Scala tests drive a real `UtxoState`; here
//! validation is an effect, so [`Harness`] answers every `Validate` with
//! the same rule Scala's `UtxoState.applyInputBlock` enforces (spec 2.5):
//! **fail if any input box is spent twice across `previous ++ txs`**.
//! That is enough to reproduce every corpus outcome that depends on
//! validation, including the double-spend and fork-switch cases.
//!
//! Mapping from the Scala API to this port:
//!
//! | Scala | here |
//! |---|---|
//! | `applyInputBlock(ib)` | [`Harness::apply_input_block`] |
//! | `applyInputBlockTransactions(id, txs, us)` | [`Harness::apply_txs`] |
//! | `bestInputBlocksChain()` | `Processor::best_input_chain` |
//! | `getInputBlock(id)` | `Processor::announcement` |
//! | `inputBlocksTree().get.forks.length` | `Processor::forks` |
//! | `updateStateWithOrderingBlock(h)` | `Event::OrderingBlockApplied` |
//! | `disconnectedWaitlist.size` | `Processor::waitlist_len` |
//!
//! Parity notes (Scala outcomes this port reproduces even though they
//! look wrong) are called out at each case.

use std::collections::{HashMap, HashSet};

use ergo_inputblocks::announcement::AnnouncementPolicy;
use ergo_inputblocks::bounds::Bounds;
use ergo_inputblocks::processor::{Body, Effect, Event, Processor};
use ergo_inputblocks::test_support as ts;
use ergo_inputblocks::types::{InputBlockId, OrderingId, Tick, TxRef};
use ergo_ser::input_block::InputBlockAnnouncement;

/// The ordering block the corpus builds on (Scala's `bestFullBlockOpt`).
const ORD: OrderingId = [0xA1; 32];
/// A competing ordering block at the same height.
const ORD2: OrderingId = [0xA2; 32];
/// The height the node reports as its best full block.
const FULL: u32 = 10;

/// Drives a [`Processor`] the way the Scala spec drives `ErgoHistoryReader`.
struct Harness {
    p: Processor,
    ctx: ts::TestCtx,
    tick: u64,
    nonce: u64,
    /// Which box each staged body spends, so validation can detect a
    /// double spend without a UTXO set.
    spends: HashMap<TxRef, [u8; 32]>,
}

impl Harness {
    fn new() -> Self {
        Self::with_bounds(Bounds::default())
    }

    fn with_bounds(bounds: Bounds) -> Self {
        let mut p = Processor::new(
            bounds,
            AnnouncementPolicy {
                strict_field_binding: false,
            },
        );
        p.set_best_ordering(Some(ORD), FULL);
        Self {
            p,
            ctx: ts::TestCtx::at(FULL),
            tick: 0,
            nonce: 0,
            spends: HashMap::new(),
        }
    }

    fn tick(&mut self) -> Tick {
        self.tick += 1;
        Tick(self.tick)
    }

    /// A fresh announcement on `parent` claiming `prev` as its previous
    /// input block and committing to `bodies`. No weak ids are announced
    /// — the delivered order is authoritative, which is what reproduces
    /// Scala's two-call `applyInputBlock` / `applyInputBlockTransactions`
    /// shape. The transactions digest still has to match what
    /// [`Self::apply_txs`] later delivers, because the proof this port
    /// builds is non-empty (Scala's `InputBlockFields.empty` carries an
    /// empty proof, which bypasses the digest check entirely — finding
    /// F4b; that bypass is exercised separately in the unit tests).
    fn ann(
        &mut self,
        parent: OrderingId,
        prev: Option<InputBlockId>,
        bodies: &[Body],
    ) -> InputBlockAnnouncement {
        self.nonce += 1;
        let ids: Vec<[u8; 32]> = bodies.iter().map(|b| b.tx_ref.tx_id).collect();
        // Always one above the node's *current* best full height: the
        // only height the processor applies (spec 9.2 / Scala
        // `processInputBlock`).
        let height = self.ctx.full_block_height + 1;
        ts::announcement_with(parent, height, self.nonce, prev, ts::tx_digest(&ids), None)
    }

    /// A body spending box `[seed; 32]`, registered for double-spend
    /// detection.
    fn body(&mut self, seed: u8) -> Body {
        let b = ts::body(seed, 1);
        self.spends.insert(b.tx_ref, [seed; 32]);
        b
    }

    /// Scala `applyInputBlock(ib)`. Returns the parent id the processor
    /// asked to download, matching Scala's `Option[ModifierId]` return.
    fn apply_input_block(&mut self, ann: &InputBlockAnnouncement) -> Option<InputBlockId> {
        let now = self.tick();
        let effects = self.ctx.handle(
            &mut self.p,
            Event::AnnouncementAccepted {
                ann: ann.clone(),
                from: ts::PEER,
                now,
            },
        );
        effects.iter().find_map(|e| match e {
            Effect::RequestInputBlock { id, .. } => Some(*id),
            _ => None,
        })
    }

    /// Scala `applyInputBlockTransactions(id, txs, state)`: deliver the
    /// bodies, then answer every `Validate` (and its continuations) with
    /// the double-spend rule. Returns the concatenated
    /// `(applied, rolled_back)` of every `ChainChanged` produced.
    fn apply_txs(
        &mut self,
        id: InputBlockId,
        bodies: Vec<Body>,
    ) -> (Vec<InputBlockId>, Vec<InputBlockId>) {
        let now = self.tick();
        let mut effects = self.ctx.handle(
            &mut self.p,
            Event::TransactionsDelivered {
                input_block_id: id,
                bodies,
                from: Some(ts::PEER),
                now,
            },
        );
        let mut applied = Vec::new();
        let mut rolled_back = Vec::new();
        loop {
            for e in &effects {
                if let Effect::ChainChanged {
                    applied: a,
                    rolled_back: r,
                    ..
                } = e
                {
                    applied.extend(a.iter().copied());
                    rolled_back.extend(r.iter().copied());
                }
            }
            let job = effects.iter().find_map(|e| match e {
                Effect::Validate {
                    job,
                    generation,
                    txs,
                    previous,
                    ..
                } => Some((*job, *generation, txs.clone(), previous.clone())),
                _ => None,
            });
            let Some((job, generation, txs, previous)) = job else {
                break;
            };
            let outcome = self.simulate(&txs, &previous);
            effects = self.ctx.handle(
                &mut self.p,
                Event::ValidationResult {
                    job,
                    generation,
                    outcome,
                },
            );
        }
        (applied, rolled_back)
    }

    /// Scala `UtxoState.applyInputBlock` in miniature (spec 2.5): fail on
    /// any box spent twice across `previous ++ txs`.
    fn simulate(&self, txs: &[TxRef], previous: &[TxRef]) -> Result<u64, String> {
        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        for r in previous.iter().chain(txs.iter()) {
            if let Some(box_id) = self.spends.get(r) {
                if !seen.insert(*box_id) {
                    return Err("double spend".to_string());
                }
            }
        }
        Ok(txs.len() as u64 + 1)
    }

    /// Scala `updateStateWithOrderingBlock(h)` for a committed block.
    fn ordering_applied(&mut self, header_id: OrderingId, height: u32) {
        let now = self.tick();
        self.ctx.full_block_height = height;
        self.ctx.handle(
            &mut self.p,
            Event::OrderingBlockApplied {
                header_id,
                height,
                now,
            },
        );
    }

    /// Announce `ann` and immediately deliver an empty transaction set —
    /// the shape most corpus cases use.
    fn apply_empty(
        &mut self,
        ann: &InputBlockAnnouncement,
    ) -> (Vec<InputBlockId>, Vec<InputBlockId>) {
        self.apply_input_block(ann);
        self.apply_txs(ts::ann_id(ann), Vec::new())
    }
}

fn id(a: &InputBlockAnnouncement) -> InputBlockId {
    ts::ann_id(a)
}

// ----- ordering-block context -----

#[test]
fn apply_input_block_with_parent_ordering_block_not_available() {
    // Scala: history has no best full block at all; the input block is
    // recorded but nothing is ever applied.
    let mut h = Harness::new();
    h.p.set_best_ordering(None, 0);
    let ib = h.ann(ORD, None, &[]);
    assert_eq!(h.apply_input_block(&ib), None);
    assert!(h.p.best_input_chain().is_empty());
    assert_eq!(h.apply_txs(id(&ib), Vec::new()), (vec![], vec![]));
    assert!(h.p.best_input_chain().is_empty());
}

#[test]
fn apply_input_block_with_parent_ordering_block_in_the_past() {
    // Scala: the announced ordering block is an ancestor of the best
    // full block, so `applyInputBlockTransactions` bails out.
    let mut h = Harness::new();
    h.p.set_best_ordering(Some(ORD2), FULL);
    let ib = h.ann(ORD, None, &[]);
    assert_eq!(h.apply_input_block(&ib), None);
    assert_eq!(h.apply_txs(id(&ib), Vec::new()), (vec![], vec![]));
    assert!(h.p.best_input_chain().is_empty());
}

#[test]
fn apply_input_block_with_non_best_parent_input_block() {
    // Scala: the ordering block the input block names lost a reorg.
    let mut h = Harness::new();
    let ib = h.ann(ORD2, None, &[]);
    assert_eq!(h.apply_input_block(&ib), None);
    assert_eq!(h.apply_txs(id(&ib), Vec::new()), (vec![], vec![]));
    assert!(h.p.best_input_chain().is_empty());
    assert!(h.p.announcement(&id(&ib)).is_some());
}

#[test]
fn apply_new_best_input_block_on_another_ordering_block_on_the_same_height() {
    let mut h = Harness::new();
    let ib1 = h.ann(ORD, None, &[]);
    h.apply_empty(&ib1);
    let ib2 = h.ann(ORD2, None, &[]);
    h.apply_empty(&ib2);

    assert!(h.p.announcement(&id(&ib1)).is_some());
    assert!(h.p.announcement(&id(&ib2)).is_some());
    let best = h.p.best_input_chain();
    assert_eq!(best, vec![id(&ib1)]);
    assert_eq!(best.len(), 1);
}

#[test]
fn pruning_removes_old_input_blocks_when_new_ordering_blocks_arrive() {
    let mut h = Harness::new();
    let ib1 = h.ann(ORD, None, &[]);
    h.apply_empty(&ib1);
    let ib2 = h.ann(ORD, Some(id(&ib1)), &[]);
    h.apply_empty(&ib2);
    assert!(h.p.announcement(&id(&ib1)).is_some());
    assert!(h.p.announcement(&id(&ib2)).is_some());

    // Scala advances the best chain by a few ordering blocks and asserts
    // the records are still there: at `best - height == 2` the pruning
    // threshold (`> 2`) has not been crossed yet.
    h.ordering_applied([0xB1; 32], FULL + 1);
    h.ordering_applied([0xB2; 32], FULL + 2);
    h.ordering_applied([0xB3; 32], FULL + 3);
    assert!(h.p.announcement(&id(&ib1)).is_some());
    assert!(h.p.announcement(&id(&ib2)).is_some());

    // One more, and `best - height == 3 > 2` prunes them.
    h.ordering_applied([0xB4; 32], FULL + 4);
    assert!(h.p.announcement(&id(&ib1)).is_none());
    assert!(h.p.announcement(&id(&ib2)).is_none());
}

#[test]
fn state_reset_when_new_ordering_blocks_arrive() {
    let mut h = Harness::new();
    let ib1 = h.ann(ORD, None, &[]);
    h.apply_empty(&ib1);
    assert_eq!(h.p.best_input_block().map(ts::ann_id), Some(id(&ib1)));

    h.ordering_applied(ORD2, FULL + 1);
    assert!(h.p.best_input_block().is_none());
}

#[test]
fn forks_spanning_across_multiple_ordering_blocks() {
    let mut h = Harness::new();
    let f1a = h.ann(ORD, None, &[]);
    assert_eq!(h.apply_empty(&f1a), (vec![id(&f1a)], vec![]));
    let f1b = h.ann(ORD, Some(id(&f1a)), &[]);
    assert_eq!(h.apply_empty(&f1b), (vec![id(&f1b)], vec![]));
    assert_eq!(h.p.best_input_chain(), vec![id(&f1b), id(&f1a)]);

    // A second ordering block takes over; its own input chain builds up.
    h.ordering_applied(ORD2, FULL + 1);
    assert!(h.p.best_input_chain().is_empty());
    let f2a = h.ann(ORD2, None, &[]);
    assert_eq!(h.apply_empty(&f2a), (vec![id(&f2a)], vec![]));
    let f2b = h.ann(ORD2, Some(id(&f2a)), &[]);
    assert_eq!(h.apply_empty(&f2b), (vec![id(&f2b)], vec![]));
    let before = h.p.best_input_chain();
    assert_eq!(before.len(), 2);
    assert!(before.contains(&id(&f2a)) && before.contains(&id(&f2b)));

    // A third ordering block resets the input-block context entirely.
    h.ordering_applied([0xA3; 32], FULL + 2);
    assert!(h.p.best_input_chain().is_empty());
    // Records within the pruning window survive the reset.
    assert!(h.p.announcement(&id(&f2a)).is_some());
    assert!(h.p.announcement(&id(&f2b)).is_some());
}

// ----- ordering-block announcements -----

#[test]
fn ordering_block_announcement_storage_and_retrieval() {
    let mut h = Harness::new();
    let oa = ts::ordering_announcement(ORD, FULL + 1, 100, Vec::new());
    let oa_id = ts::header_id(&oa.header);
    let now = h.tick();
    h.ctx.handle(
        &mut h.p,
        Event::OrderingAnnouncementAccepted {
            ann: oa,
            from: ts::PEER,
            now,
        },
    );
    assert!(h.p.ordering_announcement(&oa_id).is_some());
    assert!(h.p.ordering_announcement(&[0u8; 32]).is_none());
}

#[test]
fn ordering_block_announcement_pruning_stale_announcements_removed() {
    let mut h = Harness::new();
    let oa = ts::ordering_announcement(ORD, 3, 101, Vec::new());
    let oa_id = ts::header_id(&oa.header);
    let now = h.tick();
    h.ctx.handle(
        &mut h.p,
        Event::OrderingAnnouncementAccepted {
            ann: oa,
            from: ts::PEER,
            now,
        },
    );
    assert!(h.p.ordering_announcement(&oa_id).is_some());
    // Scala: best height 15, announcement at 3 — 12 behind, threshold 6.
    h.ordering_applied([0xB9; 32], 15);
    assert!(h.p.ordering_announcement(&oa_id).is_none());
}

#[test]
fn ordering_block_announcement_pruning_applied_announcements_removed() {
    let mut h = Harness::new();
    let oa = ts::ordering_announcement(ORD, FULL + 1, 102, Vec::new());
    let oa_id = ts::header_id(&oa.header);
    let now = h.tick();
    h.ctx.handle(
        &mut h.p,
        Event::OrderingAnnouncementAccepted {
            ann: oa,
            from: ts::PEER,
            now,
        },
    );
    assert!(h.p.ordering_announcement(&oa_id).is_some());
    // Scala: `historyReader.contains(header.transactionsId)` — the block's
    // transaction section is now in history, so the announcement goes even
    // though it is not stale by height.
    h.ctx.known_block_txs.insert(oa_id);
    h.ordering_applied([0xBA; 32], FULL + 1);
    assert!(h.p.ordering_announcement(&oa_id).is_none());
}

// ----- duplicate handling -----

#[test]
fn apply_input_block_should_ignore_duplicate_input_block_with_no_parent() {
    let mut h = Harness::new();
    let ib = h.ann(ORD, None, &[]);
    assert_eq!(h.apply_input_block(&ib), None);
    assert!(h.p.announcement(&id(&ib)).is_some());
    assert_eq!(h.apply_input_block(&ib), None);
    assert_eq!(h.p.forks(&ORD), 1);
}

#[test]
fn apply_input_block_should_ignore_duplicate_input_block_with_known_parent() {
    let mut h = Harness::new();
    let ib1 = h.ann(ORD, None, &[]);
    h.apply_empty(&ib1);
    let ib2 = h.ann(ORD, Some(id(&ib1)), &[]);
    assert_eq!(h.apply_input_block(&ib2), None);
    assert_eq!(h.apply_input_block(&ib2), None);
    assert_eq!(h.p.forks(&ORD), 1);
}

#[test]
fn apply_input_block_should_not_re_request_parent_for_duplicate_out_of_order_block() {
    let mut h = Harness::new();
    let parent = h.ann(ORD, None, &[]);
    let child = h.ann(ORD, Some(id(&parent)), &[]);
    assert_eq!(h.apply_input_block(&child), Some(id(&parent)));
    assert_eq!(h.p.waitlist_len(), 1);
    // The duplicate is dropped before `applyInputBlock`'s body runs, so
    // no second download is requested and the waitlist does not grow.
    assert_eq!(h.apply_input_block(&child), None);
    assert_eq!(h.p.waitlist_len(), 1);
}

#[test]
fn apply_input_block_should_ignore_duplicate_after_out_of_order_block_is_reconnected() {
    let mut h = Harness::new();
    let parent = h.ann(ORD, None, &[]);
    let child = h.ann(ORD, Some(id(&parent)), &[]);
    assert_eq!(h.apply_input_block(&child), Some(id(&parent)));
    assert_eq!(h.p.waitlist_len(), 1);
    assert_eq!(h.apply_txs(id(&child), Vec::new()), (vec![], vec![]));

    assert_eq!(h.apply_input_block(&parent), None);
    assert_eq!(
        h.apply_txs(id(&parent), Vec::new()),
        (vec![id(&parent), id(&child)], vec![])
    );
    assert_eq!(h.p.best_input_chain(), vec![id(&child), id(&parent)]);

    assert_eq!(h.apply_input_block(&child), None);
    assert_eq!(h.p.forks(&ORD), 1);
    assert_eq!(h.p.best_input_chain(), vec![id(&child), id(&parent)]);
}

// ----- fork resolution -----

#[test]
fn complex_fork_switching_with_transaction_validation() {
    let mut h = Harness::new();
    let tx1 = h.body(1);
    let ib1 = h.ann(ORD, None, std::slice::from_ref(&tx1));
    h.apply_input_block(&ib1);
    let ib2a = h.ann(ORD, Some(id(&ib1)), &[]);
    h.apply_input_block(&ib2a);
    let ib3a = h.ann(ORD, Some(id(&ib2a)), &[]);
    h.apply_input_block(&ib3a);
    let ib2b = h.ann(ORD, Some(id(&ib1)), &[]);
    h.apply_input_block(&ib2b);
    let ib3b = h.ann(ORD, Some(id(&ib2b)), &[]);
    h.apply_input_block(&ib3b);
    let ib4b = h.ann(ORD, Some(id(&ib3b)), &[]);
    h.apply_input_block(&ib4b);

    assert_eq!(h.apply_txs(id(&ib1), vec![tx1]), (vec![id(&ib1)], vec![]));
    assert_eq!(
        h.apply_txs(id(&ib2a), Vec::new()),
        (vec![id(&ib2a)], vec![])
    );
    assert_eq!(
        h.apply_txs(id(&ib3a), Vec::new()),
        (vec![id(&ib3a)], vec![])
    );

    h.apply_txs(id(&ib2b), Vec::new());
    h.apply_txs(id(&ib3b), Vec::new());
    h.apply_txs(id(&ib4b), Vec::new());

    let best = h.p.best_input_chain();
    assert!(!best.is_empty());
    // Fork B is longer (4 vs 3), so the switch lands on its tip.
    assert_eq!(best, vec![id(&ib4b), id(&ib3b), id(&ib2b), id(&ib1)]);
}

#[test]
fn chain_reorganization_with_input_blocks_no_common_input_block() {
    let mut h = Harness::new();
    let tx1 = h.body(1);
    let tx2 = h.body(2);
    let ib1 = h.ann(ORD, None, std::slice::from_ref(&tx1));
    h.apply_input_block(&ib1);
    let ib2 = h.ann(ORD, Some(id(&ib1)), &[]);
    h.apply_input_block(&ib2);
    assert_eq!(
        h.apply_txs(id(&ib1), vec![tx1.clone()]),
        (vec![id(&ib1)], vec![])
    );
    assert_eq!(h.apply_txs(id(&ib2), Vec::new()), (vec![id(&ib2)], vec![]));
    assert_eq!(h.p.best_input_chain(), vec![id(&ib2), id(&ib1)]);

    let alt1 = h.ann(ORD, None, std::slice::from_ref(&tx2));
    h.apply_input_block(&alt1);
    let alt2 = h.ann(ORD, Some(id(&alt1)), &[]);
    h.apply_input_block(&alt2);
    let alt3 = h.ann(ORD, Some(id(&alt2)), &[]);
    h.apply_input_block(&alt3);

    h.apply_txs(id(&alt1), vec![tx2]);
    h.apply_txs(id(&alt2), Vec::new());
    h.apply_txs(id(&alt3), Vec::new());

    assert_eq!(
        h.p.best_input_chain(),
        vec![id(&alt3), id(&alt2), id(&alt1)]
    );
}

#[test]
fn input_block_transaction_retrieval_methods() {
    let mut h = Harness::new();
    let tx1 = h.body(1);
    let ib1 = h.ann(ORD, None, std::slice::from_ref(&tx1));
    h.apply_input_block(&ib1);

    assert!(h.p.transaction_refs(&id(&ib1)).is_none());
    h.apply_txs(id(&ib1), vec![tx1.clone()]);
    assert_eq!(h.p.transaction_refs(&id(&ib1)), Some(&[tx1.tx_ref][..]));

    let bodies = h.p.bodies(&id(&ib1)).expect("bodies are cached");
    assert_eq!(bodies.len(), 1);
    assert_eq!(bodies[0].tx_ref, tx1.tx_ref);
    assert_eq!(h.p.collected_input_txs(&ORD), vec![tx1.tx_ref]);
    // Shape difference, not a behaviour difference: Scala returns
    // `Option[Seq[_]]` and answers `None` for an unknown ordering block;
    // this port returns an empty `Vec`, since the caller (the node's
    // reconstruction path) treats both the same.
    assert!(h.p.collected_input_txs(&[0x5A; 32]).is_empty());

    assert_eq!(h.p.weak_ids(&id(&ib1)), Some(vec![tx1.weak_id]));
    let filtered =
        h.p.bodies_by_weak_ids(&id(&ib1), &[tx1.weak_id])
            .expect("filtered bodies");
    assert_eq!(filtered.len(), 1);
    assert!(h
        .p
        .bodies_by_weak_ids(&id(&ib1), &[[9u8; 6]])
        .expect("known block")
        .is_empty());
}

#[test]
fn multi_branch_forking_with_longer_chain_switching_should_resolve_correctly() {
    let mut h = Harness::new();
    let ib1 = h.ann(ORD, None, &[]);
    h.apply_input_block(&ib1);
    assert_eq!(h.apply_txs(id(&ib1), Vec::new()), (vec![id(&ib1)], vec![]));
    assert_eq!(h.p.best_input_chain(), vec![id(&ib1)]);

    // Fork A: ib1 -> ib2a -> ib3a
    let ib2a = h.ann(ORD, Some(id(&ib1)), &[]);
    h.apply_input_block(&ib2a);
    let ib3a = h.ann(ORD, Some(id(&ib2a)), &[]);
    h.apply_input_block(&ib3a);
    assert_eq!(
        h.apply_txs(id(&ib2a), Vec::new()),
        (vec![id(&ib2a)], vec![])
    );
    assert_eq!(
        h.apply_txs(id(&ib3a), Vec::new()),
        (vec![id(&ib3a)], vec![])
    );
    assert_eq!(h.p.best_input_chain(), vec![id(&ib3a), id(&ib2a), id(&ib1)]);

    // Fork B: ib1 -> ib2b -> ib3b -> ib4b -> ib5b (longer)
    let mut fork_b = Vec::new();
    let mut prev = id(&ib1);
    for _ in 0..4 {
        let a = h.ann(ORD, Some(prev), &[]);
        h.apply_input_block(&a);
        prev = id(&a);
        fork_b.push(a);
    }
    for a in &fork_b {
        h.apply_txs(id(a), Vec::new());
    }
    let best = h.p.best_input_chain();
    assert_eq!(best.len(), 5);
    assert!(best.contains(&id(&ib1)));

    // Fork C: same length as B, announced later — the first fork with the
    // maximum length wins both `longestIndex` and `bestIndex`, so B keeps
    // the chain (Scala asserts exactly this).
    let mut fork_c = Vec::new();
    let mut prev = id(&ib1);
    for _ in 0..4 {
        let a = h.ann(ORD, Some(prev), &[]);
        h.apply_input_block(&a);
        prev = id(&a);
        fork_c.push(a);
    }
    for a in &fork_c {
        h.apply_txs(id(a), Vec::new());
    }

    let final_best = h.p.best_input_chain();
    assert_eq!(final_best.len(), 5);
    assert_eq!(final_best[0], id(&fork_b[3]));
    assert_eq!(final_best[1], id(&fork_b[2]));
    assert_eq!(final_best[2], id(&fork_b[1]));

    for a in [&ib1, &ib2a, &ib3a] {
        assert!(h.p.announcement(&id(a)).is_some());
    }
    for a in fork_b.iter().chain(fork_c.iter()) {
        assert!(h.p.announcement(&id(a)).is_some());
    }
}

#[test]
fn complex_multi_level_fork_resolution_with_transaction_dependencies() {
    let mut h = Harness::new();
    let initial = h.body(1);
    let dep1 = h.body(2);
    let dep2 = h.body(3);

    let ib1 = h.ann(ORD, None, std::slice::from_ref(&initial));
    h.apply_input_block(&ib1);
    assert_eq!(
        h.apply_txs(id(&ib1), vec![initial]),
        (vec![id(&ib1)], vec![])
    );
    assert_eq!(h.p.best_input_chain(), vec![id(&ib1)]);

    let ib2 = h.ann(ORD, Some(id(&ib1)), std::slice::from_ref(&dep1));
    h.apply_input_block(&ib2);
    let ib3 = h.ann(ORD, Some(id(&ib2)), std::slice::from_ref(&dep2));
    h.apply_input_block(&ib3);

    assert_eq!(h.apply_txs(id(&ib2), vec![dep1]), (vec![id(&ib2)], vec![]));
    assert_eq!(h.apply_txs(id(&ib3), vec![dep2]), (vec![id(&ib3)], vec![]));
    assert_eq!(h.p.best_input_chain(), vec![id(&ib3), id(&ib2), id(&ib1)]);
}

#[test]
fn deep_fork_switching_with_many_blocks() {
    let mut h = Harness::new();
    let initial = h.body(1);
    let ib1 = h.ann(ORD, None, std::slice::from_ref(&initial));
    h.apply_input_block(&ib1);
    assert_eq!(
        h.apply_txs(id(&ib1), vec![initial]),
        (vec![id(&ib1)], vec![])
    );
    assert_eq!(h.p.best_input_chain(), vec![id(&ib1)]);

    let ib2 = h.ann(ORD, Some(id(&ib1)), &[]);
    h.apply_input_block(&ib2);
    assert_eq!(h.apply_txs(id(&ib2), Vec::new()), (vec![id(&ib2)], vec![]));
    assert_eq!(h.p.best_input_chain(), vec![id(&ib2), id(&ib1)]);

    let mut long = Vec::new();
    let mut prev = id(&ib1);
    for _ in 0..5 {
        let a = h.ann(ORD, Some(prev), &[]);
        h.apply_input_block(&a);
        prev = id(&a);
        long.push(a);
    }
    for a in &long {
        h.apply_txs(id(a), Vec::new());
    }

    let best = h.p.best_input_chain();
    assert_eq!(best.len(), 6);
    assert_eq!(best[0], id(&long[4]));
    assert_eq!(best[best.len() - 1], id(&ib1));
    for a in [&ib1, &ib2] {
        assert!(h.p.announcement(&id(a)).is_some());
    }
    for a in &long {
        assert!(h.p.announcement(&id(a)).is_some());
    }
}

#[test]
fn deep_fork_switching_with_many_blocks_and_transaction_validation() {
    // Short chain ib1 -> ib2 -> ib3, long chain ib1 -> 7 alt blocks, each
    // with its own non-conflicting transaction.
    let mut h = Harness::new();
    let initial = h.body(1);
    let ib1 = h.ann(ORD, None, std::slice::from_ref(&initial));
    h.apply_input_block(&ib1);
    assert_eq!(
        h.apply_txs(id(&ib1), vec![initial]),
        (vec![id(&ib1)], vec![])
    );

    let tx2 = h.body(2);
    let tx3 = h.body(3);
    let ib2 = h.ann(ORD, Some(id(&ib1)), std::slice::from_ref(&tx2));
    h.apply_input_block(&ib2);
    let ib3 = h.ann(ORD, Some(id(&ib2)), std::slice::from_ref(&tx3));
    h.apply_input_block(&ib3);
    assert_eq!(h.apply_txs(id(&ib2), vec![tx2]), (vec![id(&ib2)], vec![]));
    assert_eq!(h.apply_txs(id(&ib3), vec![tx3]), (vec![id(&ib3)], vec![]));

    let long_bodies: Vec<Body> = (0..7).map(|i| h.body(20 + i as u8)).collect();
    let mut long = Vec::new();
    let mut prev = id(&ib1);
    for b in &long_bodies {
        let a = h.ann(ORD, Some(prev), std::slice::from_ref(b));
        h.apply_input_block(&a);
        prev = id(&a);
        long.push(a);
    }
    let mut rolled_total = Vec::new();
    for (a, b) in long.iter().zip(long_bodies.iter()) {
        let (_, rolled) = h.apply_txs(id(a), vec![b.clone()]);
        rolled_total.extend(rolled);
    }

    let best = h.p.best_input_chain();
    assert_eq!(best.len(), 8);
    assert_eq!(best[0], id(&long[6]));
    assert_eq!(best[best.len() - 1], id(&ib1));
    // Scala: "if (result2alt._2.nonEmpty) it should contain ib2 and ib3".
    assert!(rolled_total.contains(&id(&ib2)));
    assert!(rolled_total.contains(&id(&ib3)));
    assert!(!rolled_total.contains(&id(&ib1)));
}

#[test]
fn fork_based_double_spending_attempt_prevention() {
    let mut h = Harness::new();
    let ib1 = h.ann(ORD, None, &[]);
    h.apply_input_block(&ib1);
    assert_eq!(h.apply_txs(id(&ib1), Vec::new()), (vec![id(&ib1)], vec![]));
    assert_eq!(h.p.best_input_chain(), vec![id(&ib1)]);

    let spend = h.body(1);
    let ib2a = h.ann(ORD, Some(id(&ib1)), std::slice::from_ref(&spend));
    h.apply_input_block(&ib2a);
    let ib2b = h.ann(ORD, Some(id(&ib1)), std::slice::from_ref(&spend));
    h.apply_input_block(&ib2b);
    let (applied_a, _) = h.apply_txs(id(&ib2a), vec![spend.clone()]);
    assert!(!applied_a.is_empty());
    // Fork B never becomes the longest fork, so its transactions are
    // never even offered for validation — the double spend cannot land.
    let (applied_b, _) = h.apply_txs(id(&ib2b), vec![spend.clone()]);
    assert!(applied_b.is_empty());

    let best = h.p.best_input_chain();
    if best.contains(&id(&ib2a)) {
        assert!(!best.contains(&id(&ib2b)));
    } else if best.contains(&id(&ib2b)) {
        assert!(!best.contains(&id(&ib2a)));
    }
    for a in [&ib1, &ib2a, &ib2b] {
        assert!(h.p.announcement(&id(a)).is_some());
    }
    assert_eq!(h.p.collected_input_txs(&ORD), vec![spend.tx_ref]);
}

#[test]
fn concurrent_fork_creation_and_validation() {
    let mut h = Harness::new();
    let ib1 = h.ann(ORD, None, &[]);
    h.apply_input_block(&ib1);
    assert_eq!(h.apply_txs(id(&ib1), Vec::new()), (vec![id(&ib1)], vec![]));

    // Scala: each fork's transactions spend the same box, so a chain
    // cannot extend past its own first block.
    let txs_a = h.body(1);
    let txs_b = h.body(1);
    let txs_c = h.body(1);

    let ib2a = h.ann(ORD, Some(id(&ib1)), std::slice::from_ref(&txs_a));
    h.apply_input_block(&ib2a);
    let ib3a = h.ann(ORD, Some(id(&ib2a)), std::slice::from_ref(&txs_a));
    h.apply_input_block(&ib3a);
    let ib2b = h.ann(ORD, Some(id(&ib1)), std::slice::from_ref(&txs_b));
    h.apply_input_block(&ib2b);
    let ib3b = h.ann(ORD, Some(id(&ib2b)), std::slice::from_ref(&txs_b));
    h.apply_input_block(&ib3b);
    let ib2c = h.ann(ORD, Some(id(&ib1)), std::slice::from_ref(&txs_c));
    h.apply_input_block(&ib2c);
    let ib3c = h.ann(ORD, Some(id(&ib2c)), std::slice::from_ref(&txs_c));
    h.apply_input_block(&ib3c);

    h.apply_txs(id(&ib3c), vec![txs_c.clone()]);
    h.apply_txs(id(&ib2c), vec![txs_c.clone()]);
    h.apply_txs(id(&ib3c), vec![txs_c]);
    h.apply_txs(id(&ib3a), vec![txs_a.clone()]);
    h.apply_txs(id(&ib2a), vec![txs_a.clone()]);
    h.apply_txs(id(&ib3a), vec![txs_a]);
    h.apply_txs(id(&ib2b), vec![txs_b.clone()]);
    h.apply_txs(id(&ib3b), vec![txs_b]);

    for a in [&ib1, &ib2a, &ib3a, &ib2b, &ib3b, &ib2c, &ib3c] {
        assert!(h.p.announcement(&id(a)).is_some());
    }
    assert!(h.p.forks(&ORD) >= 3);
    // Parity with Scala's final assertion: only fork A's first block is
    // ever applied, because its child re-spends the same box.
    assert_eq!(h.p.best_input_chain(), vec![id(&ib2a), id(&ib1)]);
}

#[test]
fn double_spending_in_rolled_back_blocks_during_fork_switching() {
    let mut h = Harness::new();
    let ib1 = h.ann(ORD, None, &[]);
    h.apply_input_block(&ib1);
    assert_eq!(h.apply_txs(id(&ib1), Vec::new()), (vec![id(&ib1)], vec![]));

    let spend = h.body(1);
    let ib2a = h.ann(ORD, Some(id(&ib1)), std::slice::from_ref(&spend));
    h.apply_input_block(&ib2a);
    h.apply_txs(id(&ib2a), vec![spend.clone()]);

    // Fork B re-spends the same box, but only after it has grown longer
    // than fork A and the switch has rolled fork A's block back.
    let mut fork_b = Vec::new();
    let mut prev = id(&ib1);
    for i in 0..3 {
        let bodies: &[Body] = if i == 0 {
            std::slice::from_ref(&spend)
        } else {
            &[]
        };
        let a = h.ann(ORD, Some(prev), bodies);
        h.apply_input_block(&a);
        prev = id(&a);
        fork_b.push(a);
    }
    h.apply_txs(id(&fork_b[0]), vec![spend.clone()]);
    h.apply_txs(id(&fork_b[1]), Vec::new());
    h.apply_txs(id(&fork_b[2]), Vec::new());

    let best = h.p.best_input_chain();
    assert!(best.len() >= 3, "{best:?}");
    for a in [&ib1, &ib2a] {
        assert!(h.p.announcement(&id(a)).is_some());
    }
    for a in &fork_b {
        assert!(h.p.announcement(&id(a)).is_some());
    }
    // The rolled-back block's transaction is no longer collected; the new
    // fork's re-spend of the same box is.
    assert_eq!(h.p.collected_input_txs(&ORD), vec![spend.tx_ref]);
}

#[test]
fn fork_pruning_when_multiple_forks_exist() {
    let mut h = Harness::new();
    let root = h.ann(ORD, None, &[]);
    h.apply_empty(&root);
    let mut blocks = vec![root.clone()];
    for _ in 0..3 {
        let mut prev = id(&root);
        for _ in 0..2 {
            let a = h.ann(ORD, Some(prev), &[]);
            h.apply_input_block(&a);
            prev = id(&a);
            blocks.push(a);
        }
    }
    assert!(h.p.forks(&ORD) >= 3);

    // Scala applies several ordering blocks and asserts every record is
    // gone once `best - height > PruningThreshold`.
    for i in 1..=4u32 {
        h.ordering_applied([0xC0 + i as u8; 32], FULL + i);
    }
    for a in &blocks {
        assert!(h.p.announcement(&id(a)).is_none(), "record survived prune");
    }
    assert_eq!(h.p.forks(&ORD), 0);
    assert!(h.p.best_input_chain().is_empty());
}

// ----- fork multiplication bounds -----

#[test]
fn exponential_fork_multiplication_reproduction_test() {
    // Scala's own reproduction of the unbounded-fork bug: ten competing
    // children of one mid-chain block produce *more* than ten forks. This
    // port keeps that behaviour but caps the total (spec 7.4).
    let mut h = Harness::new();
    let start = std::time::Instant::now();
    let mut base = Vec::new();
    let mut prev: Option<InputBlockId> = None;
    for _ in 0..5 {
        let a = h.ann(ORD, prev, &[]);
        h.apply_input_block(&a);
        h.apply_txs(id(&a), Vec::new());
        prev = Some(id(&a));
        base.push(a);
    }
    let fork_parent = id(&base[2]);
    for _ in 0..10 {
        let a = h.ann(ORD, Some(fork_parent), &[]);
        h.apply_input_block(&a);
        h.apply_txs(id(&a), Vec::new());
    }
    let forks = h.p.forks(&ORD);
    assert!(
        forks > 10,
        "Scala's reproduction expects >10 forks, got {forks}"
    );
    assert!(
        forks <= Bounds::default().forks_per_ordering,
        "fork count {forks} must stay within the spec 7.4 cap"
    );
    assert!(start.elapsed().as_secs() < 2, "processing must stay linear");
}

#[test]
fn extreme_exponential_fork_multiplication_test() {
    // Scala's "extreme" variant: 3 forks at each of 4 positions of a
    // 5-block base chain. Scala asserts `forkCount == inserted + 1`.
    let mut h = Harness::new();
    let start = std::time::Instant::now();
    let mut base = Vec::new();
    let mut prev: Option<InputBlockId> = None;
    for _ in 0..5 {
        let a = h.ann(ORD, prev, &[]);
        h.apply_input_block(&a);
        h.apply_txs(id(&a), Vec::new());
        prev = Some(id(&a));
        base.push(a);
    }
    let mut inserted = 0usize;
    for parent in base.iter().take(base.len() - 1) {
        for _ in 0..3 {
            let a = h.ann(ORD, Some(id(parent)), &[]);
            h.apply_input_block(&a);
            h.apply_txs(id(&a), Vec::new());
            inserted += 1;
        }
    }
    let forks = h.p.forks(&ORD);
    assert_eq!(
        forks,
        inserted + 1,
        "Scala asserts one fork per inserted block plus the base chain"
    );
    assert!(forks <= Bounds::default().forks_per_ordering);
    assert!(start.elapsed().as_secs() < 2, "processing must stay linear");
}

#[test]
fn forks_per_ordering_bound_holds_under_fork_spam() {
    // Not a Scala case: the spec 7.4 cap must actually bite. With a cap of
    // 4, spamming 50 siblings of one block leaves at most 4 forks and
    // every rejected announcement is reported.
    let bounds = Bounds {
        forks_per_ordering: 4,
        ..Bounds::default()
    };
    let mut h = Harness::with_bounds(bounds);
    let root = h.ann(ORD, None, &[]);
    h.apply_empty(&root);
    let child = h.ann(ORD, Some(id(&root)), &[]);
    h.apply_empty(&child);
    let mut rejected = 0;
    for _ in 0..50 {
        let a = h.ann(ORD, Some(id(&root)), &[]);
        let now = h.tick();
        let effects = h.ctx.handle(
            &mut h.p,
            Event::AnnouncementAccepted {
                ann: a.clone(),
                from: ts::PEER,
                now,
            },
        );
        if effects.iter().any(|e| {
            matches!(
                e,
                Effect::Dropped {
                    reason: ergo_inputblocks::processor::DropReason::ForksFull,
                    ..
                }
            )
        }) {
            rejected += 1;
            assert!(h.p.announcement(&id(&a)).is_none());
        }
    }
    assert!(rejected > 0, "the fork cap never fired");
    assert!(h.p.forks(&ORD) <= 4);
}

/// Plan 2's node wiring drives the full four-message exchange for an
/// announcement that omits its weak-id list: `100` (announcement) →
/// `102` (ids) → `105` (body request) → `104` (bodies) → `Validate`.
/// Every step is an event or effect of the crate's public API, with no
/// resolution or body cache owned by the node — `Processor::body`
/// resolves the `Validate`'s `TxRef`s back to transactions.
#[test]
fn announcement_without_weak_ids_resolves_through_ids_and_bodies_to_validate() {
    let mut h = Harness::new();
    let b1 = h.body(0x51);
    let b2 = h.body(0x52);
    // Message 100: commits to both bodies, announces no weak ids.
    let ann = h.ann(ORD, None, &[b1.clone(), b2.clone()]);
    let block = ts::ann_id(&ann);
    let now = h.tick();
    let effects = h.ctx.handle(
        &mut h.p,
        Event::AnnouncementAccepted {
            ann: ann.clone(),
            from: ts::PEER,
            now,
        },
    );
    assert!(
        effects.iter().any(|e| matches!(
            e,
            Effect::RequestTransactionIds { input_block_id, .. } if *input_block_id == block
        )),
        "expected a message-102 request, got {effects:?}"
    );

    // Message 102: the peer answers with the announced transaction order.
    // The mempool holds neither body, so every position is unresolved and
    // the processor must ask for the bodies themselves.
    let now = h.tick();
    let effects = h.ctx.handle(
        &mut h.p,
        Event::TransactionIdsDelivered {
            input_block_id: block,
            weak_ids: vec![b1.weak_id, b2.weak_id],
            from: ts::PEER,
            now,
        },
    );
    let requested = effects
        .iter()
        .find_map(|e| match e {
            Effect::RequestTransactions {
                input_block_id,
                weak_ids,
                ..
            } if *input_block_id == block => Some(weak_ids.clone()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("expected a message-105 request, got {effects:?}"));
    assert_eq!(requested, vec![b1.weak_id, b2.weak_id]);
    assert!(
        h.p.transaction_refs(&block).is_none(),
        "nothing is resolved before the bodies arrive"
    );

    // Message 104: the bodies. The ordered digest now reproduces the
    // announcement's `transactionsDigest`, so the block is resolved and
    // the tree asks for it to be validated.
    let now = h.tick();
    let effects = h.ctx.handle(
        &mut h.p,
        Event::TransactionsDelivered {
            input_block_id: block,
            bodies: vec![b1.clone(), b2.clone()],
            from: Some(ts::PEER),
            now,
        },
    );
    let txs = effects
        .iter()
        .find_map(|e| match e {
            Effect::Validate {
                input_block_id,
                txs,
                ..
            } if *input_block_id == block => Some(txs.clone()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("expected a Validate, got {effects:?}"));
    assert_eq!(txs, vec![b1.tx_ref, b2.tx_ref]);
    assert_eq!(h.p.transaction_refs(&block), Some(&txs[..]));

    // `Validate::previous` and `txs` are resolvable through the crate, so
    // the node needs no second copy of the body cache.
    for r in &txs {
        let got = h.p.body(r).unwrap_or_else(|| panic!("body {r:?} missing"));
        assert_eq!(got.tx_ref, *r);
    }
    assert!(h.p.body(&ts::body(0x53, 1).tx_ref).is_none());
}

/// Scala applies a fork switch in a single `processInputBlockTransactions`
/// call: the rollback list is computed once, then `applicationStep` walks
/// the rest of the new fork. This port validates one block per job and
/// re-drives the same trigger to continue, so the rollback must not be
/// recomputed — and re-reported — for every block the continuation
/// applies. With the same transaction in both the abandoned block and the
/// first block of the new fork, a repeated rollback would restore it to
/// the mempool *after* the new fork removed it (section 8's
/// restore-then-apply order).
#[test]
fn fork_switch_continuation_rolls_back_once() {
    let mut h = Harness::new();
    let x = h.body(0x77);

    let root = h.ann(ORD, None, &[]);
    h.apply_empty(&root);

    // Fork A: root -> a, applied, carrying x.
    let a = h.ann(ORD, Some(id(&root)), std::slice::from_ref(&x));
    h.apply_input_block(&a);
    let (applied, rolled_back) = h.apply_txs(id(&a), vec![x.clone()]);
    assert_eq!(applied, vec![id(&a)]);
    assert!(rolled_back.is_empty());

    // Fork B: root -> b -> c, with x again in b. Equal-length forks do
    // not switch, so b alone changes nothing.
    let b = h.ann(ORD, Some(id(&root)), std::slice::from_ref(&x));
    h.apply_input_block(&b);
    let (applied, rolled_back) = h.apply_txs(id(&b), vec![x.clone()]);
    assert!(applied.is_empty(), "an equal-length fork must not switch");
    assert!(rolled_back.is_empty());

    let c = h.ann(ORD, Some(id(&b)), &[]);
    h.apply_input_block(&c);
    let (applied, rolled_back) = h.apply_txs(id(&c), Vec::new());

    assert_eq!(applied, vec![id(&b), id(&c)], "the whole fork must apply");
    assert_eq!(
        rolled_back,
        vec![id(&a)],
        "the switch must report its rollback exactly once"
    );
    // `best_input_chain` is Scala's `bestInputBlocksChain()`: tip first.
    assert_eq!(h.p.best_input_chain(), vec![id(&c), id(&b), id(&root)]);
}
