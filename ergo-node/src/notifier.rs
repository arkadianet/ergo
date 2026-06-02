//! Mempool state-change notifier — decouples consensus commit from
//! mempool reconcile.
//!
//! Consensus state commits to redb and updates an atomic best-height
//! counter on the consensus path. This module runs a separate polling
//! task that reads the committed tip identity `(height, header_id)`,
//! detects change, and pushes a `TxDiff` downstream so the mempool can
//! reconcile. The consensus path touches no channels.
//!
//! Tracks `(height, header_id)` — NOT just `best_height` — so
//! equal-height reorgs (same height, different header_id) are detected.
//!
//! The notifier is generic over a [`DiffSource`] so unit tests can
//! inject scripted behavior without a real `StateStore`. Production
//! wires [`StateStore`] via the blanket impl at the bottom of the
//! file.

use ergo_state::diff::{TipPointer, TxDiff, TxDiffError};
use ergo_state::store::StateStore;

/// Abstract chain-state read surface the notifier depends on. Defined
/// as a trait so tests can mock it; production has exactly one impl
/// against the concrete `StateStore`.
pub trait DiffSource {
    /// Committed tip as `(height, header_id)`. Must be monotonic per
    /// chain change: a new value indicates a new tip to diff against.
    fn committed_tip(&self) -> TipPointer;

    /// Compute the diff from `since` to the current committed tip.
    /// Errors propagate to the notifier so the caller can decide
    /// whether to reseed (e.g. `TooFarBehind`) or retry.
    fn tx_diff_since(&self, since: TipPointer) -> Result<TxDiff, TxDiffError>;
}

/// Outcome of a single notifier poll. Callers turn `Emit` into a
/// channel send; `NoChange` and `Initialized` are no-ops for the
/// mempool but drive the logging/metrics paths.
#[derive(Debug)]
pub enum PollOutcome {
    /// First poll — we didn't know the tip yet, so recorded it and
    /// emit nothing. The next change triggers a real diff. The
    /// carried tip is informational (for logs/metrics) — callers
    /// typically destructure it only in tests.
    #[allow(dead_code)]
    Initialized(TipPointer),
    /// Tip unchanged since last poll. No work.
    NoChange,
    /// Tip changed; here is the diff. `last_seen` has been advanced.
    Emit(TxDiff),
    /// Tip changed but the diff couldn't be computed (e.g. beyond
    /// rollback window). Notifier resets `last_seen` to the current
    /// tip so a consumer can reseed from empty. The next poll with
    /// the same tip yields `NoChange`.
    Error { tip: TipPointer, error: TxDiffError },
}

/// Single-writer notifier. Holds the last-observed committed tip and
/// computes the diff on each poll. Drive it from a tokio `interval`
/// tick (default 250 ms).
pub struct MempoolNotifier {
    last_seen: Option<TipPointer>,
}

impl Default for MempoolNotifier {
    fn default() -> Self {
        Self::new()
    }
}

impl MempoolNotifier {
    pub fn new() -> Self {
        Self { last_seen: None }
    }

    #[allow(dead_code)]
    pub fn last_seen(&self) -> Option<TipPointer> {
        self.last_seen
    }

    /// Drive one poll. Returns the outcome; caller decides how to
    /// route.
    pub fn poll<S: DiffSource + ?Sized>(&mut self, source: &S) -> PollOutcome {
        let tip = source.committed_tip();
        match self.last_seen {
            None => {
                self.last_seen = Some(tip);
                PollOutcome::Initialized(tip)
            }
            Some(prev) if prev == tip => PollOutcome::NoChange,
            Some(prev) => match source.tx_diff_since(prev) {
                Ok(diff) => {
                    self.last_seen = Some(diff.new_tip);
                    PollOutcome::Emit(diff)
                }
                Err(error) => {
                    // Advance `last_seen` to the current tip so
                    // subsequent polls don't keep retrying the same
                    // unrecoverable diff. Consumer reseeds from
                    // empty.
                    self.last_seen = Some(tip);
                    PollOutcome::Error { tip, error }
                }
            },
        }
    }
}

impl DiffSource for StateStore {
    fn committed_tip(&self) -> TipPointer {
        StateStore::committed_tip(self)
    }

    fn tx_diff_since(&self, since: TipPointer) -> Result<TxDiff, TxDiffError> {
        StateStore::tx_diff_since(self, since)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_state::diff::{AppliedTx, DemotedTx};
    use std::cell::{Cell, RefCell};
    use std::collections::HashSet;

    /// Scripted DiffSource. Advances through a queue of tip pointers
    /// on each `committed_tip` call and returns pre-configured diffs
    /// from `tx_diff_since`.
    struct ScriptedSource {
        tips: RefCell<Vec<TipPointer>>,
        current: Cell<TipPointer>,
        diff_results: RefCell<Vec<Result<TxDiff, TxDiffError>>>,
    }

    impl ScriptedSource {
        fn new(initial: TipPointer) -> Self {
            Self {
                tips: RefCell::new(Vec::new()),
                current: Cell::new(initial),
                diff_results: RefCell::new(Vec::new()),
            }
        }

        fn push_tip(&self, t: TipPointer) {
            self.tips.borrow_mut().push(t);
        }

        fn push_diff(&self, d: Result<TxDiff, TxDiffError>) {
            self.diff_results.borrow_mut().push(d);
        }

        fn advance_tip(&self) {
            if let Some(next) = self.tips.borrow_mut().drain(..1).next() {
                self.current.set(next);
            }
        }
    }

    impl DiffSource for ScriptedSource {
        fn committed_tip(&self) -> TipPointer {
            self.current.get()
        }

        fn tx_diff_since(&self, _since: TipPointer) -> Result<TxDiff, TxDiffError> {
            self.diff_results
                .borrow_mut()
                .drain(..1)
                .next()
                .expect("scripted diff exhausted")
        }
    }

    fn tip(height: u32, byte: u8) -> TipPointer {
        TipPointer {
            height,
            header_id: [byte; 32],
        }
    }

    fn empty_diff(new_tip: TipPointer) -> TxDiff {
        TxDiff {
            new_tip,
            applied: Vec::new(),
            demoted: Vec::new(),
            applied_spent_inputs: HashSet::new(),
        }
    }

    #[test]
    fn first_poll_initializes_without_emitting() {
        let source = ScriptedSource::new(tip(100, 0xAA));
        let mut n = MempoolNotifier::new();
        match n.poll(&source) {
            PollOutcome::Initialized(t) => assert_eq!(t, tip(100, 0xAA)),
            other => panic!("expected Initialized, got {other:?}"),
        }
        assert_eq!(n.last_seen(), Some(tip(100, 0xAA)));
    }

    #[test]
    fn unchanged_tip_yields_no_change() {
        let source = ScriptedSource::new(tip(100, 0xAA));
        let mut n = MempoolNotifier::new();
        n.poll(&source); // Initialized
        match n.poll(&source) {
            PollOutcome::NoChange => {}
            other => panic!("expected NoChange, got {other:?}"),
        }
    }

    #[test]
    fn tip_change_triggers_diff_and_advances_last_seen() {
        let source = ScriptedSource::new(tip(100, 0xAA));
        let mut n = MempoolNotifier::new();
        n.poll(&source); // Initialized to (100, 0xAA)

        let new_tip = tip(101, 0xBB);
        source.push_diff(Ok(empty_diff(new_tip)));
        source.push_tip(new_tip);
        source.advance_tip();

        match n.poll(&source) {
            PollOutcome::Emit(d) => assert_eq!(d.new_tip, new_tip),
            other => panic!("expected Emit, got {other:?}"),
        }
        assert_eq!(n.last_seen(), Some(new_tip));
    }

    #[test]
    fn equal_height_reorg_is_detected() {
        // Same height, different header_id — classic equal-height
        // reorg. Height alone would miss it; our (height, header_id)
        // pointer does not.
        let source = ScriptedSource::new(tip(1000, 0x01));
        let mut n = MempoolNotifier::new();
        n.poll(&source);

        let forked_tip = tip(1000, 0x02);
        source.push_diff(Ok(empty_diff(forked_tip)));
        source.push_tip(forked_tip);
        source.advance_tip();

        assert!(matches!(n.poll(&source), PollOutcome::Emit(_)));
        assert_eq!(n.last_seen(), Some(forked_tip));
    }

    #[test]
    fn diff_error_advances_last_seen_and_surfaces() {
        let source = ScriptedSource::new(tip(100, 0xAA));
        let mut n = MempoolNotifier::new();
        n.poll(&source);

        let new_tip = tip(400, 0xFF);
        source.push_diff(Err(TxDiffError::TooFarBehind));
        source.push_tip(new_tip);
        source.advance_tip();

        match n.poll(&source) {
            PollOutcome::Error { tip, error } => {
                assert_eq!(tip, new_tip);
                assert_eq!(error, TxDiffError::TooFarBehind);
            }
            other => panic!("expected Error, got {other:?}"),
        }
        // last_seen advanced so we don't keep retrying the bad diff.
        assert_eq!(n.last_seen(), Some(new_tip));
    }

    #[test]
    fn recovery_after_error_returns_no_change_without_retry() {
        let source = ScriptedSource::new(tip(100, 0xAA));
        let mut n = MempoolNotifier::new();
        n.poll(&source);

        let new_tip = tip(400, 0xFF);
        source.push_diff(Err(TxDiffError::TooFarBehind));
        source.push_tip(new_tip);
        source.advance_tip();
        n.poll(&source); // Error, last_seen advanced

        // Next poll with the same tip — no retry of the failed diff.
        match n.poll(&source) {
            PollOutcome::NoChange => {}
            other => panic!("expected NoChange, got {other:?}"),
        }
    }

    #[test]
    fn multi_step_sequence_emits_for_each_change() {
        let source = ScriptedSource::new(tip(100, 0x10));
        let mut n = MempoolNotifier::new();
        n.poll(&source); // Initialized

        for h in 101..=105 {
            let new_tip = tip(h, h as u8);
            source.push_diff(Ok(empty_diff(new_tip)));
            source.push_tip(new_tip);
            source.advance_tip();
            assert!(
                matches!(n.poll(&source), PollOutcome::Emit(_)),
                "step to height {h} should emit"
            );
            assert_eq!(n.last_seen().unwrap().height, h);
        }
    }

    #[test]
    fn emit_carries_applied_and_demoted() {
        // Confirm diff payloads pass through unchanged (notifier does
        // not mutate them).
        let source = ScriptedSource::new(tip(100, 0x10));
        let mut n = MempoolNotifier::new();
        n.poll(&source);

        let new_tip = tip(101, 0x11);
        let applied = vec![AppliedTx {
            tx_id: [0x01; 32],
            spent_inputs: vec![[0xA0; 32]],
        }];
        let demoted = vec![DemotedTx {
            tx_id: [0x02; 32],
            bytes: vec![9, 9, 9],
        }];
        let mut applied_inputs: HashSet<[u8; 32]> = HashSet::new();
        applied_inputs.insert([0xA0; 32]);
        source.push_diff(Ok(TxDiff {
            new_tip,
            applied: applied.clone(),
            demoted: demoted.clone(),
            applied_spent_inputs: applied_inputs.clone(),
        }));
        source.push_tip(new_tip);
        source.advance_tip();

        match n.poll(&source) {
            PollOutcome::Emit(d) => {
                assert_eq!(d.applied.len(), 1);
                assert_eq!(d.applied[0].tx_id, [0x01; 32]);
                assert_eq!(d.demoted.len(), 1);
                assert_eq!(d.demoted[0].bytes, vec![9, 9, 9]);
                assert!(d.applied_spent_inputs.contains(&[0xA0; 32]));
            }
            other => panic!("expected Emit, got {other:?}"),
        }
    }
}
