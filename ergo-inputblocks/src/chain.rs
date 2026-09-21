//! A single input-block chain / fork for one ordering block: Scala
//! `InputBlocksProcessor.InputBlocksChain` (weak-blocks branch,
//! `InputBlocksProcessor.scala` lines ~60–246).
//!
//! Pure and validation-free: this type never checks a block's PoW,
//! transactions, or state — it only tracks *which* ids form the chain
//! and *how many* of them (from the head) have been told they were
//! successfully applied. The caller (Task 11's processor) owns all of
//! that judgment and only reports outcomes here via [`InputBlocksChain::fork`]
//! and [`InputBlocksChain::register_completion`].

use crate::types::InputBlockId;

/// One candidate chain of input blocks for an ordering block. Scala
/// `case class InputBlocksChain(chain: Seq[ModifierId], processedBlocks: Seq[Long])`
/// (lines 61–68). `processed_costs` mirrors Scala's `processedBlocks`:
/// one cost entry per *processed* prefix block (not one per chain
/// element) — its length, not its contents, is what the rest of this
/// module reasons about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputBlocksChain {
    pub chain: Vec<InputBlockId>,
    pub processed_costs: Vec<u64>,
}

/// Failures from [`InputBlocksChain::register_completion`]. Scala's
/// `registerCompletion` returns `Try[InputBlocksChain]`, failing with a
/// plain `Exception` (lines 220–228) when the completed id isn't the
/// chain's `firstToComplete()`.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ChainError {
    #[error("improper completion of {0:?}")]
    ImproperCompletion(InputBlockId),
}

impl InputBlocksChain {
    /// Scala `InputBlocksChain.apply(ib)` (companion object, lines 231–235):
    /// a brand-new chain holding just `id`, nothing processed yet.
    pub fn single(id: InputBlockId) -> Self {
        Self {
            chain: vec![id],
            processed_costs: Vec::new(),
        }
    }

    /// Scala `val processedIndex: Int = processedBlocks.length - 1`
    /// (line 63). `-1` means nothing has been processed yet.
    pub fn processed_index(&self) -> isize {
        self.processed_costs.len() as isize - 1
    }

    /// Scala `def tip: Option[ModifierId]` (lines 71–77): the last
    /// *processed* block, not the chain's tail.
    pub fn tip(&self) -> Option<InputBlockId> {
        let idx = self.processed_index();
        if idx == -1 {
            None
        } else {
            Some(self.chain[idx as usize])
        }
    }

    /// Scala `def depthOf(id): Int = chain.indexOf(id)` (lines 84–86),
    /// re-shaped to `Option<usize>` instead of Scala's `-1`-sentinel.
    pub fn depth_of(&self, id: &InputBlockId) -> Option<usize> {
        self.chain.iter().position(|x| x == id)
    }

    /// Scala `def firstToComplete(): Option[ModifierId]`
    /// (lines 187–193): the next chain element after the processed
    /// prefix, if any remain.
    pub fn first_to_complete(&self) -> Option<InputBlockId> {
        let next = (self.processed_index() + 1) as usize;
        if next < self.chain.len() {
            Some(self.chain[next])
        } else {
            None
        }
    }

    /// Scala `def fork(newInputBlock): Seq[InputBlocksChain]`
    /// (lines 105–137). `prev` is `newInputBlock.prevInputBlockId`.
    ///
    /// - No `prev` at all (`None`) → Scala's `case _` (no-parent) branch:
    ///   logs an error and returns `Seq(this)` unchanged (lines 133–136).
    /// - `prev == chain.lastOption` (comparing against the chain's *last
    ///   element*, not the processed tip) → linear extension: one chain,
    ///   `chain :+ new` (lines 108–113).
    /// - `prev` found elsewhere in `chain` at `idx` → fork: both the
    ///   original chain *and* a new forked chain
    ///   `chain[..=idx] :+ new`, `processed_costs[..=idx]`
    ///   (`processedBlocks.take(idx + 1)`, lines 119–129) — Scala takes
    ///   `idx + 1` elements from `processedBlocks` regardless of whether
    ///   `processedBlocks` is that long; `Vec::truncate`-style `take`
    ///   naturally saturates at the vector's own length, matching
    ///   Scala's `Seq.take` semantics.
    /// - `prev` unknown (not found anywhere in `chain`) → Scala's
    ///   `idx < 0` branch: logs a warning, returns `Seq(this)` unchanged
    ///   (lines 130–133).
    pub fn fork(&self, new_id: InputBlockId, prev: Option<&InputBlockId>) -> Vec<InputBlocksChain> {
        match prev {
            None => vec![self.clone()],
            Some(prev_id) => {
                if Some(prev_id) == self.chain.last() {
                    let mut chain = self.chain.clone();
                    chain.push(new_id);
                    vec![InputBlocksChain {
                        chain,
                        processed_costs: self.processed_costs.clone(),
                    }]
                } else if let Some(idx) = self.chain.iter().position(|x| x == prev_id) {
                    let mut forked_chain: Vec<InputBlockId> = self.chain[..=idx].to_vec();
                    forked_chain.push(new_id);
                    let take = (idx + 1).min(self.processed_costs.len());
                    let forked_costs = self.processed_costs[..take].to_vec();
                    vec![
                        self.clone(),
                        InputBlocksChain {
                            chain: forked_chain,
                            processed_costs: forked_costs,
                        },
                    ]
                } else {
                    vec![self.clone()]
                }
            }
        }
    }

    /// Scala `def registerCompletion(id, costDelta): Try[InputBlocksChain]`
    /// (lines 210–219): only the id currently at `firstToComplete()` may
    /// complete; anything else — including re-completing an already
    /// processed id — is `Failure` (here, `Err(ChainError::ImproperCompletion)`).
    pub fn register_completion(
        &self,
        id: &InputBlockId,
        cost: u64,
    ) -> Result<InputBlocksChain, ChainError> {
        match self.first_to_complete() {
            Some(expected) if &expected == id => {
                let mut processed_costs = self.processed_costs.clone();
                processed_costs.push(cost);
                Ok(InputBlocksChain {
                    chain: self.chain.clone(),
                    processed_costs,
                })
            }
            _ => Err(ChainError::ImproperCompletion(*id)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----
    fn id(b: u8) -> InputBlockId {
        [b; 32]
    }

    // ----- happy path -----
    #[test]
    fn fork_extends_when_prev_is_tip() {
        let c = InputBlocksChain::single(id(1));
        let out = c.fork(id(2), Some(&id(1)));
        assert_eq!(
            out,
            vec![InputBlocksChain {
                chain: vec![id(1), id(2)],
                processed_costs: vec![]
            }]
        );
    }

    #[test]
    fn fork_branches_at_known_ancestor_keeping_processed_prefix() {
        let c = InputBlocksChain {
            chain: vec![id(1), id(2), id(3)],
            processed_costs: vec![10, 20],
        };
        let out = c.fork(id(9), Some(&id(1)));
        assert_eq!(out.len(), 2);
        assert_eq!(out[0], c);
        assert_eq!(
            out[1],
            InputBlocksChain {
                chain: vec![id(1), id(9)],
                processed_costs: vec![10]
            }
        );
    }

    #[test]
    fn register_completion_advances_first_to_complete() {
        let c = InputBlocksChain {
            chain: vec![id(1), id(2)],
            processed_costs: vec![5],
        };
        assert_eq!(c.first_to_complete(), Some(id(2)));
        let c2 = c.register_completion(&id(2), 7).unwrap();
        assert_eq!(c2.processed_costs, vec![5, 7]);
        assert_eq!(c2.first_to_complete(), None);
    }

    // ----- error paths -----
    #[test]
    fn fork_with_unknown_parent_is_unchanged() {
        let c = InputBlocksChain::single(id(1));
        assert_eq!(c.fork(id(2), Some(&id(7))), vec![c.clone()]);
        assert_eq!(c.fork(id(2), None), vec![c]);
    }

    #[test]
    fn register_completion_rejects_unexpected_id() {
        let c = InputBlocksChain {
            chain: vec![id(1), id(2)],
            processed_costs: vec![],
        };
        assert_eq!(
            c.register_completion(&id(2), 0),
            Err(ChainError::ImproperCompletion(id(2)))
        );
    }
}
