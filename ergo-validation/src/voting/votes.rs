//! Vote tallying for the recompute pipeline.
//!
//! Mirrors Scala `VotingData` (`VotingData.scala`) +
//! `ErgoStateContext.process` (`ErgoStateContext.scala:232-264`).

/// Read-only access to header data at a given chain height. The voting
/// recompute path uses this to walk the previous epoch's headers and
/// tally votes; tests use a synthetic implementation, production uses
/// a `StateStore`-backed one.
pub trait ChainHeaderReader {
    /// Look up the header at `height`. Errors must distinguish
    /// "no row" from "backend failure" so the caller can react
    /// appropriately to each.
    fn header_at(&self, height: u32) -> Result<HeaderView, ChainHeaderReaderError>;
}

/// Minimal projection of a block header — just the fields the vote
/// tally needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderView {
    /// The block's `header.votes` field — three bytes, each is one
    /// signed vote id (`i8`) or 0 for "no vote".
    pub votes: [u8; 3],
}

/// Failures returned by [`ChainHeaderReader::header_at`].
#[derive(Debug, thiserror::Error)]
pub enum ChainHeaderReaderError {
    /// No header row exists at `height`.
    #[error("header not found at height {0}")]
    NotFound(u32),
    /// The backing store raised an underlying error reading `height`.
    #[error("header reader failed at height {height}: {source}")]
    Backend {
        /// Height the reader was asked about.
        height: u32,
        /// Underlying backend error.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

/// Compute the vote tally for the voting epoch ending at
/// `epoch_start_height` (i.e. the block at `epoch_start_height` itself
/// is the new epoch's first block — its `header.votes` does NOT count
/// here; that's the *next* epoch's seed).
///
/// Mirrors Scala behavior:
/// - At the previous epoch's start (`epoch_start_height - 1024`):
///   `epochVotes` is initialized to `votes.map(_ -> 1)` IN ORDER
///   (`ErgoStateContext.scala:250`).
/// - For each subsequent block in `[prev_epoch_start + 1,
///   epoch_start_height - 1]`: `VotingData.update(voteFor)` increments
///   every existing entry whose id matches `voteFor`. Votes for ids
///   not already in `epochVotes` are silently dropped
///   (`VotingData.scala:9-13`).
///
/// **Insertion order matters.** Scala's `updateParams` (`Parameters.scala:157-183`)
/// folds over `epochVotes` in iteration order, and reads
/// `currentValue = parametersTable(paramIdAbs)` from the ORIGINAL
/// table on each step, so when both `(+id, count > 512)` and
/// `(-id, count > 512)` for the same param survive thresholding, the
/// LATER write in iteration order determines the final value. Sorting
/// would change consensus.
pub fn compute_epoch_votes(
    chain: &dyn ChainHeaderReader,
    epoch_start_height: u32,
    voting_length: u32,
) -> Result<Vec<(i8, i32)>, ChainHeaderReaderError> {
    assert!(
        epoch_start_height >= voting_length && epoch_start_height.is_multiple_of(voting_length),
        "compute_epoch_votes: epoch_start_height={epoch_start_height} is not an epoch boundary \
         for voting_length={voting_length}"
    );
    let prev_epoch_start = epoch_start_height - voting_length;

    // Initialize epoch_votes from the prev-epoch-start's votes,
    // preserving order. Scala `votes.map(_ -> 1)` produces an Array,
    // not a Map — duplicates would be retained, but
    // `hdrVotesDuplicates` (ErgoStateContext.scala:341) rejects such
    // headers upstream, so we never see them here in production.
    //
    // First-epoch-boundary special case: when
    // `prev_epoch_start == 0`, this Rust storage has no chain row at
    // height 0 (genesis is stored at h=1, see
    // `ergo-state/src/store.rs::apply_genesis`). Scala's protocol
    // convention places genesis at h=0 with `votes=[0,0,0]`; the
    // .filter on non-zero strips them all to empty. Skipping the
    // genesis read and starting from an empty seed produces an
    // identical final tally — pinned by the Scala-fixture oracle in
    // `ergo-validation/tests/votes_first_epoch_oracle.rs`.
    let mut epoch_votes: Vec<(i8, i32)> = if prev_epoch_start == 0 {
        Vec::new()
    } else {
        chain
            .header_at(prev_epoch_start)?
            .votes
            .iter()
            .filter(|&&v| v != 0)
            .map(|&v| (v as i8, 1i32))
            .collect()
    };

    // Off-boundary blocks: `VotingData.update(voteFor)` is a `.map`
    // over the entries that increments every match. With dedup'd
    // headers, at most one entry matches per vote.
    for h in (prev_epoch_start + 1)..epoch_start_height {
        let votes = chain.header_at(h)?.votes;
        for &v in votes.iter().filter(|&&v| v != 0) {
            for entry in epoch_votes.iter_mut() {
                if entry.0 == v as i8 {
                    entry.1 += 1;
                }
            }
            // No matching entry: dropped per VotingData.update.
        }
    }

    Ok(epoch_votes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct StubChain {
        headers: HashMap<u32, [u8; 3]>,
    }

    impl ChainHeaderReader for StubChain {
        fn header_at(&self, h: u32) -> Result<HeaderView, ChainHeaderReaderError> {
            self.headers
                .get(&h)
                .map(|votes| HeaderView { votes: *votes })
                .ok_or(ChainHeaderReaderError::NotFound(h))
        }
    }

    fn build_chain(prev_epoch_start: u32, votes_by_height: &[(u32, [u8; 3])]) -> StubChain {
        let mut headers: HashMap<u32, [u8; 3]> = HashMap::new();
        for h in prev_epoch_start..(prev_epoch_start + 1024) {
            headers.insert(h, [0u8; 3]);
        }
        for (h, v) in votes_by_height {
            headers.insert(*h, *v);
        }
        StubChain { headers }
    }

    #[test]
    fn first_block_seeds_epoch_votes_in_byte_order() {
        let chain = build_chain(1024, &[(1024, [3, (-3i8) as u8, 0])]);
        let votes = compute_epoch_votes(&chain, 2048, 1024).unwrap();
        assert_eq!(votes, vec![(3, 1), (-3, 1)]);
    }

    #[test]
    fn off_boundary_increments_existing_entries() {
        let chain = build_chain(
            1024,
            &[(1024, [3, 0, 0]), (1100, [3, 0, 0]), (1200, [3, 0, 0])],
        );
        let votes = compute_epoch_votes(&chain, 2048, 1024).unwrap();
        assert_eq!(votes, vec![(3, 3)]);
    }

    #[test]
    fn off_boundary_ignores_unseen_ids() {
        // Epoch's first block votes for +3 only; subsequent blocks vote
        // for +5. The +5 votes should be dropped (Scala
        // `VotingData.update` increments existing only).
        let chain = build_chain(
            1024,
            &[(1024, [3, 0, 0]), (1100, [5, 0, 0]), (1200, [5, 0, 0])],
        );
        let votes = compute_epoch_votes(&chain, 2048, 1024).unwrap();
        assert_eq!(votes, vec![(3, 1)]);
    }

    #[test]
    fn negative_vote_ids_count_separately_from_positives() {
        // +3 and -3 are independent ids; both can be present.
        let chain = build_chain(
            1024,
            &[
                (1024, [3, (-3i8) as u8, 0]),
                (1100, [3, 0, 0]),
                (1200, [(-3i8) as u8, 0, 0]),
                (1300, [(-3i8) as u8, 0, 0]),
            ],
        );
        let votes = compute_epoch_votes(&chain, 2048, 1024).unwrap();
        assert_eq!(votes, vec![(3, 2), (-3, 3)]);
    }

    #[test]
    fn insertion_order_preserved_across_byte_orders() {
        let chain_a = build_chain(1024, &[(1024, [3, (-3i8) as u8, 0])]);
        let chain_b = build_chain(1024, &[(1024, [(-3i8) as u8, 3, 0])]);
        let votes_a = compute_epoch_votes(&chain_a, 2048, 1024).unwrap();
        let votes_b = compute_epoch_votes(&chain_b, 2048, 1024).unwrap();
        assert_eq!(votes_a, vec![(3, 1), (-3, 1)]);
        assert_eq!(votes_b, vec![(-3, 1), (3, 1)]);
    }

    #[test]
    fn skips_zero_bytes() {
        // Only non-zero bytes count.
        let chain = build_chain(1024, &[(1024, [0, 3, 0])]);
        let votes = compute_epoch_votes(&chain, 2048, 1024).unwrap();
        assert_eq!(votes, vec![(3, 1)]);
    }

    #[test]
    fn empty_first_block_yields_empty_tally() {
        let chain = build_chain(1024, &[(1024, [0, 0, 0])]);
        let votes = compute_epoch_votes(&chain, 2048, 1024).unwrap();
        assert!(votes.is_empty());
    }

    #[test]
    fn soft_fork_vote_id_120_counted_like_others() {
        let chain = build_chain(
            1024,
            &[
                (1024, [120, 0, 0]),
                (1100, [120, 0, 0]),
                (1200, [120, 0, 0]),
            ],
        );
        let votes = compute_epoch_votes(&chain, 2048, 1024).unwrap();
        assert_eq!(votes, vec![(120, 3)]);
    }

    #[test]
    #[should_panic(expected = "is not an epoch boundary")]
    fn rejects_non_epoch_height() {
        let chain = build_chain(1024, &[]);
        let _ = compute_epoch_votes(&chain, 1500, 1024);
    }

    // ===== First-epoch-boundary tests =====

    /// Build a chain seeded only at heights 1..1023. h=0 is
    /// intentionally absent — Rust storage convention is no chain row
    /// at height 0.
    fn build_first_epoch_chain(votes_by_height: &[(u32, [u8; 3])]) -> StubChain {
        let mut headers: HashMap<u32, [u8; 3]> = HashMap::new();
        for h in 1..1024 {
            headers.insert(h, [0u8; 3]);
        }
        for (h, v) in votes_by_height {
            assert!(*h != 0, "h=0 must not appear in the fixture");
            headers.insert(*h, *v);
        }
        StubChain { headers }
    }

    /// Pins the fix: at the first epoch boundary
    /// (`epoch_start_height = 1024`), `prev_epoch_start = 0` and the
    /// reader has no h=0 entry. The function must NOT error.
    ///
    /// Result is always empty: with `prev_epoch_start == 0` we
    /// initialize from an empty seed (matching Scala's
    /// `votes.map(_ -> 1)` of genesis `[0,0,0]` then `.filter` strips
    /// to empty). The walk h=1..1023 then has nothing to increment —
    /// every incoming vote is "unseen" by `VotingData.update` and
    /// silently dropped. This tally is consensus-irrelevant: at the
    /// first boundary `extension_validation::compute` bypasses
    /// `compute_next_params` (line 101 — `prev_active.epoch_start_height
    /// == 0`), so `epoch_votes` is computed and immediately
    /// discarded. The point of the fix is that the function must
    /// not panic.
    #[test]
    fn first_boundary_no_h0_returns_empty() {
        let chain = build_first_epoch_chain(&[(1, [3, 0, 0]), (500, [3, 0, 0])]);
        let votes = compute_epoch_votes(&chain, 1024, 1024).unwrap();
        assert!(votes.is_empty());
    }

    /// Equivalence pin: a stub chain that DOES expose `h=0 â†’ [0,0,0]`
    /// (matching Scala's protocol convention) must produce the same
    /// tally as the Rust path that skips h=0. Both yield empty.
    #[test]
    fn first_boundary_synthesized_h0_zero_votes_matches() {
        // No-h0 path:
        let chain_no_h0 = build_first_epoch_chain(&[(1, [3, 0, 0]), (500, [3, 0, 0])]);
        let votes_no_h0 = compute_epoch_votes(&chain_no_h0, 1024, 1024).unwrap();

        // With-h0 path: same chain plus genesis at h=0 with [0,0,0].
        let mut headers = chain_no_h0.headers.clone();
        headers.insert(0, [0u8; 3]);
        let chain_with_h0 = StubChain { headers };
        let votes_with_h0 = compute_epoch_votes(&chain_with_h0, 1024, 1024).unwrap();

        assert_eq!(votes_no_h0, votes_with_h0);
        assert!(votes_no_h0.is_empty());
    }

    /// Walk semantics at the first boundary: even with abundant
    /// votes throughout h=1..1023, the tally remains empty because
    /// the seed is empty and `VotingData.update` only increments
    /// existing entries. This is the Scala-bypass-friendly
    /// behavior: epoch 1 inherits launch params unchanged.
    #[test]
    fn first_boundary_walks_but_drops_all_unseen() {
        let chain = build_first_epoch_chain(&[
            (1, [3, 0, 0]),
            (100, [3, 0, 0]),
            (200, [5, 0, 0]),
            (300, [3, (-3i8) as u8, 0]),
        ]);
        let votes = compute_epoch_votes(&chain, 1024, 1024).unwrap();
        assert!(votes.is_empty());
    }
}
