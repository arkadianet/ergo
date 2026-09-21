//! The tree of competing input-block chains for a single ordering
//! block: Scala `InputBlocksProcessor.InputBlocksTree` (weak-blocks
//! branch, `InputBlocksProcessor.scala` lines ~248–657).
//!
//! Like [`crate::chain`], this is pure and validation-free: `insert`
//! never checks PoW or extension proofs, and `process` never validates
//! transactions — it drives the caller-supplied `apply` closure and
//! records what it was told. Task 11's processor owns validation and
//! decides, per milestone, what `apply` returns.

use crate::chain::InputBlocksChain;
use crate::types::InputBlockId;

/// A pending (or freshly-arrived) announcement: an id and the parent id
/// it claims, if any. Mirrors the two fields of Scala's
/// `InputBlockAnnouncement` that `insertInputBlock` and `fork` actually
/// use (`id`, `prevInputBlockId`).
pub struct AnnouncementRef<'a> {
    pub id: InputBlockId,
    pub prev: Option<&'a InputBlockId>,
}

/// The competing forks for one ordering block. Scala
/// `case class InputBlocksTree(forks: Seq[InputBlocksChain])`
/// (line 258).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InputBlocksTree {
    pub forks: Vec<InputBlocksChain>,
}

/// The caller-supplied application closure `process` drives: given the
/// id under consideration and the previously-processed chain prefix
/// (mirroring Scala's `collectedTransactions`), returns the processing
/// cost on success or `Err(())` on validation failure. Task 11 controls
/// what this returns per milestone; this crate only drives it.
pub type ApplyFn<'a> = dyn FnMut(&InputBlockId, &[InputBlockId]) -> Result<u64, ()> + 'a;

/// Result of [`InputBlocksTree::process`]: Scala
/// `processInputBlockTransactions`'s `(Seq[ModifierId], Seq[ModifierId])`
/// return, plus the updated tree (Scala mutates `inputBlockTrees` as a
/// side effect via `.put`; this port returns the new tree instead since
/// it is pure).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessOutcome {
    pub applied: Vec<InputBlockId>,
    pub rolled_back: Vec<InputBlockId>,
    pub tree: InputBlocksTree,
}

impl InputBlocksTree {
    /// Scala `lazy val knownInputBlocks = forks.flatMap(_.chain).toSet`
    /// (lines 265–267), as membership test rather than a cached set.
    pub fn known(&self, id: &InputBlockId) -> bool {
        self.forks.iter().any(|f| f.chain.contains(id))
    }

    /// Scala `private lazy val longestIndex` (lines 270–279): scans from
    /// index 0, strict `>` — so the *first* fork wins ties.
    pub fn longest_index(&self) -> Option<usize> {
        let mut best_len = -1i64;
        let mut best_idx = None;
        for (i, f) in self.forks.iter().enumerate() {
            let len = f.chain.len() as i64;
            if len > best_len {
                best_len = len;
                best_idx = Some(i);
            }
        }
        best_idx
    }

    /// Scala `private lazy val bestIndex` (lines 293–302): same
    /// first-wins-ties scan, over `processedIndex` instead of chain
    /// length. `None` when every fork's `processed_index()` is `-1`
    /// (Scala's `bl` starts at `-1` and the comparison is strict `>`,
    /// so an all-`-1` tree never updates `i` away from its `-1` sentinel).
    pub fn best_index(&self) -> Option<usize> {
        let mut best: i64 = -1;
        let mut best_idx = None;
        for (i, f) in self.forks.iter().enumerate() {
            let pi = f.processed_index() as i64;
            if pi > best {
                best = pi;
                best_idx = Some(i);
            }
        }
        best_idx
    }

    /// Scala `def bestDepth: Int` (lines 309–313): `-1` when there is no
    /// best fork (empty tree).
    pub fn best_depth(&self) -> isize {
        match self.best_index() {
            Some(i) => self.forks[i].processed_index(),
            None => -1,
        }
    }

    /// Scala `def bestTip: Option[ModifierId]` (lines 320–324): the
    /// best fork's `chain.lastOption` — note this is the chain's *last
    /// element*, not its processed tip (Scala reuses `chain.lastOption`
    /// here, unlike `InputBlocksChain.tip`).
    pub fn best_tip(&self) -> Option<InputBlockId> {
        self.best_index()
            .and_then(|i| self.forks[i].chain.last().copied())
    }

    /// Scala `def bestChain: Seq[ModifierId]` (lines 330–335): the
    /// processed prefix (`take(processedIndex + 1)`) of the best fork.
    pub fn best_chain(&self) -> Vec<InputBlockId> {
        match self.best_index() {
            Some(i) => {
                let f = &self.forks[i];
                let take = (f.processed_index() + 1) as usize;
                f.chain[..take].to_vec()
            }
            None => Vec::new(),
        }
    }

    /// Scala `def longestDepth: Option[Int]` (lines 282–286).
    pub fn longest_depth(&self) -> Option<usize> {
        self.longest_index().map(|i| self.forks[i].chain.len())
    }

    /// Scala `def insertInputBlock(ibi): Option[InputBlocksTree]`
    /// (lines 337–390). `waitlist` stands in for Scala's
    /// `disconnectedWaitlist` field — the processor (Task 11) owns that
    /// list and passes it in explicitly since this crate has no mutable
    /// state of its own.
    ///
    /// - `ann.prev.is_none()` → Scala's "no parent" branch (lines
    ///   366–370): start a new single-element chain, then try to attach
    ///   any waitlisted block whose `prev` matches a chain tip in the
    ///   accumulated list (`applyDisconnected`, lines 347–362) — folded
    ///   over `waitlist` in the given order, exactly as Scala folds over
    ///   `disconnectedWaitlist`.
    /// - `ann.prev` known (`self.known(prev)`) → Scala's known-parent
    ///   branch (lines 372–384): find the *first* fork containing `prev`
    ///   (Scala's `processed` flag ensures only one fork is touched even
    ///   if `prev` somehow appears in more than one — `chain.contains`),
    ///   fork it, then run `applyDisconnected` over the resulting
    ///   chain(s) too.
    /// - otherwise → `None`, Scala's disconnected-waitlist branch (lines
    ///   385–389); the caller is responsible for remembering `ann` on
    ///   its own waitlist.
    pub fn insert(
        &self,
        ann: AnnouncementRef<'_>,
        waitlist: &[(InputBlockId, Option<InputBlockId>)],
    ) -> Option<InputBlocksTree> {
        fn apply_disconnected(
            mut acc: Vec<InputBlocksChain>,
            waitlist: &[(InputBlockId, Option<InputBlockId>)],
        ) -> Vec<InputBlocksChain> {
            for (wb_id, wb_prev) in waitlist {
                let idx = acc.iter().position(|c| c.chain.last() == wb_prev.as_ref());
                if let Some(idx) = idx {
                    let c = acc[idx].clone();
                    let new_chains = c.fork(*wb_id, wb_prev.as_ref());
                    let mut rest = new_chains;
                    let head = rest.remove(0);
                    acc[idx] = head;
                    acc.extend(rest);
                }
            }
            acc
        }

        match ann.prev {
            None => {
                let new_chain = InputBlocksChain::single(ann.id);
                let chains = apply_disconnected(vec![new_chain], waitlist);
                let mut forks = self.forks.clone();
                forks.extend(chains);
                Some(InputBlocksTree { forks })
            }
            Some(prev_id) => {
                if self.known(prev_id) {
                    let mut processed = false;
                    let mut new_forks = Vec::with_capacity(self.forks.len());
                    for c in &self.forks {
                        if !processed && c.chain.contains(prev_id) {
                            processed = true;
                            let forked = c.fork(ann.id, Some(prev_id));
                            let forked = apply_disconnected(forked, waitlist);
                            new_forks.extend(forked);
                        } else {
                            new_forks.push(c.clone());
                        }
                    }
                    Some(InputBlocksTree { forks: new_forks })
                } else {
                    None
                }
            }
        }
    }

    /// Scala `def processInputBlockTransactions(ib, txs, state)`
    /// (lines 392–657). `apply(id, previous_chain_ids) -> Result<u64, ()>`
    /// stands in for Scala's `acc._1.applyTransactions(ib, txs, state)`
    /// (`applicationStep`'s recursive core, lines 435–470) — the
    /// processor is responsible for looking up the announcement, its
    /// transactions, and running state validation; this method only
    /// tracks *which* id is being asked about and *what previously
    /// processed chain prefix* (`previous_chain_ids`) the caller should
    /// assemble bodies from, mirroring `collectedTransactions`'s use of
    /// `chain(0..=processedIndex)`.
    ///
    /// `has_txs(id)` stands in for Scala's
    /// `inputBlockTransactions.contains(id)` checks used both by
    /// `switchNeeded` (line 429) and `applicationStep`'s continuation
    /// guard (line 447).
    pub fn process(
        &self,
        id: &InputBlockId,
        has_txs: &dyn Fn(&InputBlockId) -> bool,
        apply: &mut ApplyFn<'_>,
    ) -> ProcessOutcome {
        let empty = ProcessOutcome {
            applied: Vec::new(),
            rolled_back: Vec::new(),
            tree: self.clone(),
        };

        // Scala lines 407–413: `bestIndex = if (this.bestIndex == -1) longestIndex else this.bestIndex`.
        let best_index = match self.best_index() {
            Some(i) => Some(i),
            None => self.longest_index(),
        };
        let best_index = match best_index {
            Some(i) => i,
            None => return empty,
        };
        let best_depth = self.best_depth();

        // Scala `applicationStep` (lines 435–470): applies `id` to
        // `start`, then keeps consuming `first_to_complete()` while it
        // has transactions available, stopping at the first `Err`.
        let application_step = |start: &InputBlocksChain,
                                first_id: &InputBlockId,
                                apply: &mut ApplyFn<'_>|
         -> (InputBlocksChain, Vec<InputBlockId>) {
            let mut current = start.clone();
            let mut next_id = *first_id;
            let mut applied = Vec::new();
            loop {
                let previous_chain_ids: Vec<InputBlockId> = {
                    let take = (current.processed_index() + 1).max(0) as usize;
                    current.chain[..take].to_vec()
                };
                match apply(&next_id, &previous_chain_ids) {
                    Ok(cost) => {
                        let upd = current
                            .register_completion(&next_id, cost)
                            .expect("apply target must be first_to_complete by construction");
                        applied.push(next_id);
                        current = upd;
                        match current.first_to_complete() {
                            Some(nid) if has_txs(&nid) => {
                                next_id = nid;
                            }
                            _ => break,
                        }
                    }
                    Err(()) => break,
                }
            }
            (current, applied)
        };

        // Scala `switchNeeded(id)` (lines 421–433).
        let longest_index = self.longest_index();
        let switch_needed = |id: &InputBlockId| -> bool {
            let Some(li) = longest_index else {
                return false;
            };
            let lf = &self.forks[li];
            let Some(d) = lf.depth_of(id) else {
                return false;
            };
            let d = d as isize;
            if d <= best_depth {
                return false;
            }
            let lo = (lf.processed_index() + 1).max(0) as usize;
            let hi = d as usize;
            (lo..=hi).all(|i| has_txs(&lf.chain[i]))
        };

        if longest_index != Some(best_index) && switch_needed(id) {
            let li = longest_index.unwrap();
            let current_fork = &self.forks[best_index];
            let new_fork = &self.forks[li];

            // Scala `rollbackInputBlocks` (lines 481–497).
            let mut common_idx: isize = -1;
            for idx in 0..current_fork.chain.len() {
                if idx < new_fork.chain.len()
                    && current_fork.chain[idx] == new_fork.chain[idx]
                    && idx as isize <= new_fork.processed_index()
                {
                    common_idx = idx as isize;
                }
            }
            let rollback_input_blocks: Vec<InputBlockId> =
                if common_idx == -1 || common_idx == current_fork.processed_index() {
                    Vec::new()
                } else {
                    let from = (common_idx + 1) as usize;
                    let to = (current_fork.processed_index() + 1) as usize;
                    current_fork.chain[from..to].to_vec()
                };

            // Scala lines 499–508: next unprocessed block in the new fork.
            let next_id = new_fork.chain[(new_fork.processed_index() + 1) as usize];
            let (updated_new_fork, r_applied) = application_step(new_fork, &next_id, apply);

            if !r_applied.is_empty() {
                finalize_progress(
                    &self.forks,
                    li,
                    updated_new_fork,
                    next_id,
                    r_applied,
                    rollback_input_blocks,
                )
            } else {
                empty
            }
        } else if self.forks[best_index].first_to_complete() == Some(*id) {
            let f = &self.forks[best_index];
            let (updated_fork, r_applied) = application_step(f, id, apply);

            if !r_applied.is_empty() {
                finalize_progress(
                    &self.forks,
                    best_index,
                    updated_fork,
                    *id,
                    r_applied,
                    Vec::new(),
                )
            } else {
                empty
            }
        } else {
            empty
        }
    }
}

/// Scala lines 513–524 (fork-switch branch) and 545–556 (linear branch):
/// both branches, after a non-empty `applicationStep`, (1) install the
/// updated fork at `index`, then (2) sweep every fork — including the one
/// just updated, which is now a no-op there since it already consumed
/// `completed_id` — and register a zero-cost completion (the acknowledged
/// `// todo: pass real cost of input block instead of costDelta = 0`) on
/// any other fork whose `first_to_complete()` is also `completed_id`.
/// Extracted once since the two call sites were identical apart from
/// which index/id/rollback list they pass in.
fn finalize_progress(
    forks_before: &[InputBlocksChain],
    index: usize,
    updated_fork: InputBlocksChain,
    completed_id: InputBlockId,
    applied: Vec<InputBlockId>,
    rolled_back: Vec<InputBlockId>,
) -> ProcessOutcome {
    let mut forks = forks_before.to_vec();
    forks[index] = updated_fork;
    for fork in forks.iter_mut() {
        if fork.first_to_complete() == Some(completed_id) {
            // Safe: `register_completion` only fails when `first_to_complete()
            // != completed_id`, which the guard above just excluded — Scala's
            // `Failure` branch here (line 522/554) is unreachable by
            // construction, not swallowed.
            *fork = fork
                .register_completion(&completed_id, 0)
                .expect("register_completion invariant: guarded by first_to_complete() == Some(completed_id) above");
        }
    }
    ProcessOutcome {
        applied,
        rolled_back,
        tree: InputBlocksTree { forks },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    // ----- helpers -----
    fn id(b: u8) -> InputBlockId {
        [b; 32]
    }

    // ----- happy path -----
    #[test]
    fn insert_first_block_without_parent_creates_chain() {
        let tree = InputBlocksTree::default();
        let out = tree
            .insert(
                AnnouncementRef {
                    id: id(1),
                    prev: None,
                },
                &[],
            )
            .unwrap();
        assert_eq!(out.forks.len(), 1);
        assert_eq!(out.forks[0].chain, vec![id(1)]);
        assert_eq!(out.best_depth(), -1);
    }

    #[test]
    fn insert_child_of_tip_extends_chain() {
        let tree = InputBlocksTree {
            forks: vec![InputBlocksChain::single(id(1))],
        };
        let out = tree
            .insert(
                AnnouncementRef {
                    id: id(2),
                    prev: Some(&id(1)),
                },
                &[],
            )
            .unwrap();
        assert_eq!(out.forks.len(), 1);
        assert_eq!(out.forks[0].chain, vec![id(1), id(2)]);
    }

    #[test]
    fn insert_parent_reconnects_waitlisted_child() {
        let tree = InputBlocksTree::default();
        let waitlist = vec![(id(2), Some(id(1)))];
        let out = tree
            .insert(
                AnnouncementRef {
                    id: id(1),
                    prev: None,
                },
                &waitlist,
            )
            .unwrap();
        assert_eq!(out.forks.len(), 1);
        assert_eq!(out.forks[0].chain, vec![id(1), id(2)]);
    }

    #[test]
    fn process_switches_to_longer_disjoint_fork_when_txs_available() {
        let tree = InputBlocksTree {
            forks: vec![
                InputBlocksChain {
                    chain: vec![id(1), id(2)],
                    processed_costs: vec![1, 1],
                },
                InputBlocksChain {
                    chain: vec![id(3), id(4), id(5)],
                    processed_costs: vec![],
                },
            ],
        };
        let with_txs: HashSet<InputBlockId> = [id(3), id(4), id(5)].into_iter().collect();
        let has_txs = |x: &InputBlockId| with_txs.contains(x);
        let mut apply = |_id: &InputBlockId, _prev: &[InputBlockId]| Ok::<u64, ()>(1);
        let out = tree.process(&id(5), &has_txs, &mut apply);
        assert_eq!(out.applied, vec![id(3), id(4), id(5)]);
        // Scala quirk, verified against the real property test ("input
        // block - fork switching - disjoint forks",
        // InputBlockProcessorSpecification.scala lines 186-232): the
        // `commonIdx` scan (lines 481-497) never finds a shared prefix
        // between two genuinely disjoint chains, so it stays at its `-1`
        // sentinel and `rollbackInputBlocks` is `Seq.empty` — even though
        // fork0's two processed blocks *are* being abandoned. The Scala
        // test asserts exactly this: `applyInputBlockTransactions(ib3.id,
        // ...) shouldBe (Seq(ib2.id, ib3.id) -> Seq.empty)`.
        assert!(out.rolled_back.is_empty());
    }

    #[test]
    fn process_switches_to_longer_fork_from_common_root() {
        let tree = InputBlocksTree {
            forks: vec![
                InputBlocksChain {
                    chain: vec![id(1), id(2)],
                    processed_costs: vec![1, 1],
                },
                InputBlocksChain {
                    // id(1) is shared with fork 0 and already processed
                    // there (the real Scala test's ib1: applied once,
                    // then both forks that grow from it carry it as
                    // processed — see InputBlockProcessorSpecification.scala
                    // "input block - fork switching - common root",
                    // `ibc1.processedBlocks.length shouldBe 1`).
                    chain: vec![id(1), id(3), id(4)],
                    processed_costs: vec![1],
                },
            ],
        };
        let with_txs: HashSet<InputBlockId> = [id(1), id(3), id(4)].into_iter().collect();
        let has_txs = |x: &InputBlockId| with_txs.contains(x);
        let mut apply = |_id: &InputBlockId, _prev: &[InputBlockId]| Ok::<u64, ()>(1);
        let out = tree.process(&id(4), &has_txs, &mut apply);
        assert_eq!(out.applied, vec![id(3), id(4)]);
        assert_eq!(out.rolled_back, vec![id(2)]);
    }

    #[test]
    fn process_no_switch_when_longer_fork_lacks_txs() {
        // Regression for codex review finding (Task 10 fix round 1):
        // processing id(4) here has depth 1 in the longer fork, which
        // equals best_depth (1) — `switch_needed`'s `d <= best_depth`
        // short-circuit already rejects the switch before ever reaching
        // the tx-availability scan, so that guard wasn't exercised.
        // Process id(5) instead (depth 2, strictly greater than
        // best_depth) while id(4) — a block strictly between the
        // processed prefix and id(5) — has no transactions, so only the
        // availability guard can reject the switch.
        let tree = InputBlocksTree {
            forks: vec![
                InputBlocksChain {
                    chain: vec![id(1), id(2)],
                    processed_costs: vec![1, 1],
                },
                InputBlocksChain {
                    chain: vec![id(3), id(4), id(5)],
                    processed_costs: vec![],
                },
            ],
        };
        let with_txs: HashSet<InputBlockId> = [id(3), id(5)].into_iter().collect(); // id(4) missing
        let has_txs = |x: &InputBlockId| with_txs.contains(x);
        let apply_calls = std::cell::RefCell::new(Vec::new());
        let mut apply = |id: &InputBlockId, _prev: &[InputBlockId]| {
            apply_calls.borrow_mut().push(*id);
            Ok::<u64, ()>(1)
        };
        let out = tree.process(&id(5), &has_txs, &mut apply);
        assert!(out.applied.is_empty());
        assert!(out.rolled_back.is_empty());
        assert!(
            apply_calls.borrow().is_empty(),
            "apply must not be called when the availability guard rejects the switch"
        );
        assert_eq!(out.tree, tree);
    }

    #[test]
    fn process_linear_applies_first_to_complete_and_continues() {
        let tree = InputBlocksTree {
            forks: vec![InputBlocksChain {
                chain: vec![id(1), id(2), id(3)],
                processed_costs: vec![],
            }],
        };
        let with_txs: HashSet<InputBlockId> = [id(1), id(2), id(3)].into_iter().collect();
        let has_txs = |x: &InputBlockId| with_txs.contains(x);
        let mut apply = |_id: &InputBlockId, _prev: &[InputBlockId]| Ok::<u64, ()>(1);
        let out = tree.process(&id(1), &has_txs, &mut apply);
        assert_eq!(out.applied, vec![id(1), id(2), id(3)]);
    }

    // ----- error paths -----
    #[test]
    fn insert_unknown_parent_returns_none() {
        let tree = InputBlocksTree::default();
        let out = tree.insert(
            AnnouncementRef {
                id: id(2),
                prev: Some(&id(1)),
            },
            &[],
        );
        assert!(out.is_none());
    }

    #[test]
    fn process_stops_at_failed_block() {
        let tree = InputBlocksTree {
            forks: vec![InputBlocksChain {
                chain: vec![id(1), id(2), id(3)],
                processed_costs: vec![],
            }],
        };
        let with_txs: HashSet<InputBlockId> = [id(1), id(2), id(3)].into_iter().collect();
        let has_txs = |x: &InputBlockId| with_txs.contains(x);
        let mut apply = |target: &InputBlockId, _prev: &[InputBlockId]| {
            if *target == id(2) {
                Err(())
            } else {
                Ok::<u64, ()>(1)
            }
        };
        let out = tree.process(&id(1), &has_txs, &mut apply);
        assert_eq!(out.applied, vec![id(1)]);
    }

    // ----- oracle parity -----
    #[test]
    fn process_registers_completion_on_sibling_forks_with_zero_cost() {
        let tree = InputBlocksTree {
            forks: vec![
                InputBlocksChain {
                    chain: vec![id(1), id(2)],
                    processed_costs: vec![1],
                },
                InputBlocksChain {
                    chain: vec![id(1), id(2), id(9)],
                    processed_costs: vec![1],
                },
            ],
        };
        let with_txs: HashSet<InputBlockId> = [id(1), id(2)].into_iter().collect();
        let has_txs = |x: &InputBlockId| with_txs.contains(x);
        let mut apply = |_id: &InputBlockId, _prev: &[InputBlockId]| Ok::<u64, ()>(5);
        let out = tree.process(&id(2), &has_txs, &mut apply);
        // Scala quirk (InputBlocksProcessor.scala switchNeeded/processInputBlockTransactions,
        // lines 421-433 and 476-527): a fork that is merely *longer* by one
        // trailing sibling (`[1,2,9]` vs `[1,2]`) still counts as
        // `longestIndex != bestIndex`, so this takes the fork-switch branch
        // even though both forks already agree on block 2. The "new best"
        // fork (index 1, the longer one) gets the real `apply` cost; the
        // *old* best fork (index 0) is swept as a sibling and completes
        // with `costDelta = 0`. `rollbackInputBlocks` is empty here because
        // `commonIdx == currentFork.processedIndex` (line 494-496).
        assert_eq!(out.applied, vec![id(2)]);
        assert!(out.rolled_back.is_empty());
        assert_eq!(out.tree.forks[0].processed_costs.len(), 2);
        assert_eq!(out.tree.forks[1].processed_costs.len(), 2);
        assert_eq!(out.tree.forks[0].processed_costs[1], 0);
        assert_eq!(out.tree.forks[1].processed_costs[1], 5);
    }

    #[test]
    fn longest_and_best_pick_first_fork_on_ties() {
        let tree = InputBlocksTree {
            forks: vec![
                InputBlocksChain {
                    chain: vec![id(1), id(2)],
                    processed_costs: vec![],
                },
                InputBlocksChain {
                    chain: vec![id(1), id(3)],
                    processed_costs: vec![],
                },
            ],
        };
        assert_eq!(tree.longest_index(), Some(0));
        assert_eq!(tree.best_index(), None);
    }
}
