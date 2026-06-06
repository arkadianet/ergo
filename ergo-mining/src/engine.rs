//! Off-loop candidate engine core (synchronous; the async task loop that
//! drives it lives in `ergo-node`, where the action loop + tokio runtime
//! are).
//!
//! The action loop publishes a [`BuildIntent`] (everything that needs
//! action-loop state access — the expected parent tip, a frozen mempool
//! snapshot, and the resolved miner reward key) and maintains the
//! authoritative [`BestTip`] on the [`MiningHandle`]. The engine task then
//! calls [`build_and_publish`] off the loop: it opens ONE committed redb
//! snapshot, waits for that snapshot to reflect the intent's expected
//! parent (commit visibility), gates on `synced(tip)`, materializes
//! storage-rent-eligible boxes against that snapshot via the injected
//! `resolve_rent` closure (the eligible-id list itself comes from the
//! indexer's eventually-consistent extra-index), runs the unchanged
//! [`generate_candidate`]
//! against the snapshot, and CAS-publishes the result into the served cache
//! only if the live tip still matches the parent it built against. A reorg
//! or tip advance during the build wastes the work, never serves a
//! wrong-parent candidate.

use std::sync::Arc;

use ergo_mempool::MempoolReadSnapshot;
use ergo_ser::ergo_box::ErgoBox;
use ergo_state::reader::ChainStoreReader;
use ergo_state::store::{BaseDisposition, CommittedSnapshot, DryRunBase};

use crate::candidate::{generate_candidate, BuildMode, Candidate};
use crate::error::MiningError;
use crate::handle::MiningHandle;
use crate::state_view::CachedSnapshotView;
use crate::work_message::WorkMessage;

/// Why a build was requested. Recorded on the template identity for metrics;
/// the pool-facing `clean_jobs` signal derives from `chain_seq`, not this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildReason {
    /// Best-full tip advanced (extension or reorg).
    Tip,
    /// Same tip, mempool changed (debounced).
    MempoolRefresh,
    /// Reward key became available.
    WalletReady,
    /// First build once `synced(tip)` first holds.
    Startup,
}

/// The authoritative current tip, maintained by the action loop on the
/// [`MiningHandle`]. The engine CAS-checks against it at publish; serving
/// gates on `synced`.
///
/// `synced` is the full live mining-gate predicate (a committed full block
/// exists and the header tip equals it), computed by the loop on every
/// best-header / best-full transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BestTip {
    pub parent_id: [u8; 32],
    pub chain_seq: u64,
    pub synced: bool,
}

impl BestTip {
    /// Pre-genesis / not-yet-synced default: zeroed parent, not synced, so
    /// serving refuses until the loop publishes a real synced tip.
    pub fn unsynced() -> Self {
        Self {
            parent_id: [0u8; 32],
            chain_seq: 0,
            synced: false,
        }
    }
}

/// One build request, fully resolved by the action loop. Everything that
/// needs action-loop state or wallet access is frozen here; storage-rent
/// boxes are resolved by the engine driver against the build's committed
/// snapshot. Cheap to clone (the heavy inputs are behind `Arc`), so it
/// rides a `tokio::watch`.
#[derive(Debug, Clone)]
pub struct BuildIntent {
    /// In-memory best-full tip the loop saw when it signalled. The engine
    /// builds against THIS parent, waiting for the committed snapshot to
    /// reflect it (commit visibility).
    pub expected_parent: [u8; 32],
    /// Height of `expected_parent` (the candidate is `expected_height + 1`).
    pub expected_height: u32,
    /// Frozen mempool view (built on the loop, where `&Mempool` lives).
    pub mempool: Arc<MempoolReadSnapshot>,
    /// Reward key resolved on the loop (`Ready` only — the loop does not
    /// signal while the wallet key is `Pending`).
    pub miner_pk: [u8; 33],
    pub reason: BuildReason,
}

/// Identity + versioning stamped onto every published template. The serve path
/// (`GET /mining/candidate`) exposes `template_seq` / `clean_jobs` on the work
/// message so a Stratum proxy can roll jobs; `template_id` is the work message's
/// `msg`. The remaining fields (`parent_id` / `chain_seq` / `built_at_ms` /
/// `reason`) stay internal to the cache/engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemplateIdentity {
    /// The header-pre-pow identity — `blake2b256(serialize_header_without_pow)`,
    /// i.e. the candidate's `msg`. Reused as the template id; no new hash.
    pub template_id: [u8; 32],
    pub parent_id: [u8; 32],
    /// The live `best_tip` era at publish time (see
    /// [`MiningHandle::publish_if_current`]) — not the building intent's era,
    /// so an ABA reorg that finishes a stale-era build still stamps the
    /// authoritative current era.
    pub chain_seq: u64,
    /// Monotonic publish counter; bumps on every newly published template.
    pub template_seq: u64,
    /// True iff `chain_seq` advanced versus the previously published template
    /// (the parent changed). True for the first template ever published.
    pub clean_jobs: bool,
    /// Wall-clock at publish, passed in by the caller (the cache never reads the
    /// clock itself, so publish is deterministic under test).
    pub built_at_ms: u64,
    pub reason: BuildReason,
}

/// A published template: the work the miner hashes, the full candidate the
/// solution path reassembles, and the [`TemplateIdentity`] versioning.
#[derive(Debug, Clone)]
pub struct Template {
    pub candidate: Candidate,
    pub work: WorkMessage,
    pub identity: TemplateIdentity,
}

/// Result of a single [`build_and_publish`] attempt. The async driver uses
/// this to decide whether to retry (commit-visibility), drop, or move on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildOutcome {
    /// Built and published into the served cache. Carries the per-phase build
    /// timings so the driver logs one histogram-friendly line per build.
    Published {
        timings: crate::candidate::PhaseTimings,
    },
    /// Built, but the live tip moved off the built parent before publish —
    /// discarded (wasted, not wrong).
    DroppedStale,
    /// The committed snapshot's full tip is an ancestor of (behind) the
    /// intent's `expected_parent`: the in-memory block isn't redb-durable yet
    /// (persisted state lags in-memory apply). The driver retries with a fresh
    /// snapshot, bounded, until the committed tip reaches `expected_parent` or
    /// a newer intent supersedes this one.
    TipNotVisible,
    /// The committed full tip is at or past `expected_height` with a different
    /// id — the chain has moved ahead of or forked away from `expected_parent`,
    /// so this intent can never become commit-visible. A newer intent for the
    /// current tip is (or will be) queued; the driver drops this one instead of
    /// spinning. (Spec §6 step 3: "ahead of / forked from ⇒ drop this intent".)
    IntentSuperseded,
    /// The committed view is not `synced(tip)` (header tip leads full tip).
    /// No candidate is built or served while unsynced.
    NotSynced,
    /// The candidate orchestrator returned `None` (its own in-generation
    /// parent guard caught a flip). Retry on the next intent.
    Raced,
    /// No committed state to build on (pre-genesis). Nothing to do.
    NoState,
}

/// CAS decision: publish only if the live tip still matches the parent the
/// candidate was built against. Extracted so the decision is unit-testable
/// independent of cache mutation.
pub(crate) fn should_publish(best_tip: &BestTip, built_parent: &[u8; 32]) -> bool {
    best_tip.synced && &best_tip.parent_id == built_parent
}

/// Build one candidate off the loop from a single committed snapshot and
/// CAS-publish it. Synchronous + side-effecting only through
/// `handle` (the served cache); the async driver in `ergo-node` calls this
/// per intent and handles retry/debounce/latest-wins.
///
/// `mode` controls what the build includes: [`BuildMode::Minimal`] produces
/// the emission-only template (no rent claim, no mempool selection, no fee tx)
/// for fast publication the instant a new tip lands; [`BuildMode::Full`] adds
/// the rent self-claim, mempool selection, and the fee tx for the enriched
/// refresh.
///
/// `resolve_rent` is called with the snapshot and the candidate height
/// exactly when `mode == Full` and rent is enabled
/// (`handle.claim_storage_rent()` is true); it returns the
/// storage-rent-eligible boxes to sweep into a self-claim. The closure is
/// injected by the engine driver (which owns the indexer handle), keeping
/// ergo-mining free of any ergo-indexer dependency.
///
/// Consensus-safety: the snapshot is one redb read transaction; the build
/// runs the unchanged [`generate_candidate`] against it (byte-identical to
/// an on-loop build for the same parent + tx-set, per the `ergo-state`
/// parity tests); and the result is only served if the live tip still
/// matches — so a reorg during the build wastes work rather than serving a
/// wrong-parent candidate. The submitted block is fully re-validated on the
/// action loop regardless.
///
/// `base` is the optional per-tip dry-run base cache slot. `None` ⇒ the
/// uncached path: every build full-hydrates the AVL tree (today's behaviour;
/// all existing callers and tests pass `None`). `Some(slot)` ⇒ the build's
/// AVL dry-run routes through [`CachedSnapshotView`], reusing the memoized
/// pristine tree when the slot already holds one for this committed tip and
/// rehydrating on a miss/tip-change. The slot is `!Send` (it owns an
/// `Rc<RefCell<Node>>` graph), so it must be owned by the single dedicated
/// build worker thread that calls `build_and_publish`; it is never shared.
/// Either path produces byte-identical `(state_root, ad_proof)` — the cached
/// variant is proven against the uncached oracle in `ergo-state`.
///
/// `disposition_out` is set to the [`BaseDisposition`] only when `base` is
/// `Some` and `generate_candidate` actually ran (i.e. the early-return
/// outcomes — `NoState`, `TipNotVisible`, `IntentSuperseded`, `NotSynced` —
/// leave it `None`). Callers that want the wire-string label should map the
/// value after the call:
/// `Hit → "primed"`, `Advanced → "advanced"`, `Rehydrated → "cold"`,
/// `RehydratedAfterFailedAdvance → "cold_fallback"`,
/// `None` with a `Some(base)` and a building outcome → treat as `"cold"`.
#[allow(clippy::too_many_arguments)]
pub fn build_and_publish(
    reader: &ChainStoreReader,
    handle: &MiningHandle,
    intent: &BuildIntent,
    mode: BuildMode,
    base: Option<&mut Option<DryRunBase>>,
    now_ms: impl Fn() -> u64,
    resolve_rent: impl FnOnce(&CommittedSnapshot, u32) -> Vec<ErgoBox>,
    disposition_out: &mut Option<BaseDisposition>,
) -> Result<BuildOutcome, MiningError> {
    // Reset at entry so the documented None-for-non-building contract holds
    // even when a caller reuses one slot across calls — the early-return
    // outcomes below never write it otherwise.
    *disposition_out = None;
    let snapshot = match reader
        .committed_snapshot()
        .map_err(|e| MiningError::StateRead {
            op: "engine_open_committed_snapshot",
            reason: format!("{e:?}"),
        })? {
        Some(s) => s,
        None => return Ok(BuildOutcome::NoState),
    };

    // Commit-visibility: build against the intent's expected (in-memory)
    // parent, once the committed snapshot reflects it. Persisted state can
    // trail in-memory apply by the persist-pipeline depth, so a snapshot taken
    // right after the loop's signal may not yet contain the new tip. Partition
    // a mismatch by height (spec §6 step 3): a committed tip *behind*
    // `expected_height` is persist-lag → retry; a committed tip at/past
    // `expected_height` with a different id is a superseded/forked intent that
    // can never become visible → drop, so the driver moves to the next intent
    // instead of spinning.
    if snapshot.best_full_block_id() != intent.expected_parent {
        if snapshot.best_full_block_height() < intent.expected_height {
            return Ok(BuildOutcome::TipNotVisible);
        }
        return Ok(BuildOutcome::IntentSuperseded);
    }

    // Synced gate (full live predicate), evaluated within this committed
    // view: never build while the header tip leads the full tip.
    if !snapshot.synced() {
        return Ok(BuildOutcome::NotSynced);
    }

    // Minimal builds freeze nothing from the pool and never touch the
    // indexer: the emission-only template needs neither, and skipping both
    // is what makes the minimal publish fast.
    let (mempool, eligible_rent_boxes) = match mode {
        BuildMode::Minimal => (MempoolReadSnapshot::empty(), Vec::new()),
        BuildMode::Full => {
            // Storage-rent eligibility, resolved HERE so each box is materialized
            // against THIS committed snapshot — never a newer live view (a box
            // spent in an applied-but-uncommitted block must not be claimed from a
            // template that cannot see that spend, and vice versa). The eligible-id
            // list the resolver pages over comes from the indexer's own
            // eventually-consistent extra-index, so it may name boxes the snapshot
            // no longer holds; those are skipped and backfilled in the resolver,
            // never claimed blind. The resolver is injected by the node driver (it
            // owns the indexer handle); rent disabled ⇒ never called.
            let eligible = if handle.claim_storage_rent() {
                resolve_rent(&snapshot, snapshot.best_full_block_height() + 1)
            } else {
                Vec::new()
            };
            ((*intent.mempool).clone(), eligible)
        }
    };

    // The dry-run is the build's dominant cost (full AVL hydration). When a
    // base-cache slot is supplied, route the build through `CachedSnapshotView`
    // so same-tip rebuilds reuse the memoized pristine tree; otherwise build
    // directly against the snapshot (every build full-hydrates). Both views
    // serve every non-dry-run read from the same one held transaction, so the
    // candidate is identical bar the dry-run's hydration source — which is
    // itself byte-identical (proven against the uncached oracle in ergo-state).
    let built = match base {
        Some(slot) => {
            let view = CachedSnapshotView::new(&snapshot, slot);
            let result = generate_candidate(
                &view,
                mode,
                mempool,
                &intent.miner_pk,
                handle.monetary(),
                handle.reemission_ref(),
                handle.chain_config(),
                eligible_rent_boxes.as_slice(),
            );
            // Read disposition from the view regardless of whether the build
            // succeeded — the path taken (Hit/Advanced/Rehydrated/…) is
            // informative even on a dry-run or build error.
            *disposition_out = view.last_disposition();
            result?
        }
        None => generate_candidate(
            &snapshot,
            mode,
            mempool,
            &intent.miner_pk,
            handle.monetary(),
            handle.reemission_ref(),
            handle.chain_config(),
            eligible_rent_boxes.as_slice(),
        )?,
    };
    let Some((candidate, work, timings)) = built else {
        return Ok(BuildOutcome::Raced);
    };

    // CAS-publish: serve only if the live tip still matches the parent we
    // built against. The published template's era is stamped from the live
    // tip under the publish lock, not `intent.chain_seq` — see
    // `publish_if_current` for the ABA-reorg rationale. `now_ms` is forwarded
    // and sampled by `publish_if_current` under the publish lock, so the
    // stamped `built_at_ms` is the actual push instant — not when the
    // (possibly retried) build started.
    match handle.publish_if_current(
        candidate,
        work,
        &intent.expected_parent,
        now_ms,
        intent.reason,
    ) {
        Some(_) => Ok(BuildOutcome::Published { timings }),
        None => Ok(BuildOutcome::DroppedStale),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emission_rules::MonetarySettings;
    use crate::reemission::ReemissionSettings;
    use ergo_crypto::difficulty::DifficultyParams;
    use ergo_state::store::StateStore;

    // ----- helpers -----

    fn handle() -> MiningHandle {
        MiningHandle::new(
            [0x02u8; 33],
            MonetarySettings::mainnet(),
            Some(ReemissionSettings::mainnet()),
            DifficultyParams::mainnet(),
        )
    }

    /// Fixed publish-time wall-clock stamp, returned by the `now_ms` closure
    /// passed to `build_and_publish`. The cache stores it verbatim and no test
    /// asserts on the clock, so a constant keeps publish deterministic.
    const BUILT_AT_MS: u64 = 1_700_000_000_000;

    fn intent(parent: [u8; 32], expected_height: u32) -> BuildIntent {
        BuildIntent {
            expected_parent: parent,
            expected_height,
            mempool: Arc::new(MempoolReadSnapshot::empty()),
            miner_pk: [0x02u8; 33],
            reason: BuildReason::Startup,
        }
    }

    fn genesis_store() -> (tempfile::TempDir, StateStore) {
        let dir = tempfile::tempdir().unwrap();
        let mut store = StateStore::open(dir.path().join("s.redb").as_path()).unwrap();
        let mut id = [0u8; 32];
        id[31] = 1;
        store.initialize_genesis(&[(id, vec![0xAAu8; 32])]).unwrap();
        (dir, store)
    }

    // ----- CAS decision -----

    #[test]
    fn should_publish_only_when_synced_and_parent_matches() {
        let p = [9u8; 32];
        assert!(should_publish(
            &BestTip {
                parent_id: p,
                chain_seq: 3,
                synced: true
            },
            &p
        ));
        // Parent moved.
        assert!(!should_publish(
            &BestTip {
                parent_id: [8u8; 32],
                chain_seq: 4,
                synced: true
            },
            &p
        ));
        // Not synced.
        assert!(!should_publish(
            &BestTip {
                parent_id: p,
                chain_seq: 3,
                synced: false
            },
            &p
        ));
    }

    // ----- non-build outcomes (no chain harness needed) -----

    #[test]
    fn no_state_when_store_has_no_committed_state() {
        let dir = tempfile::tempdir().unwrap();
        let store = StateStore::open(dir.path().join("s.redb").as_path()).unwrap();
        let mut disp = None;
        let out = build_and_publish(
            &store.reader_handle(),
            &handle().with_rent_config(true, 4),
            &intent([0u8; 32], 0),
            BuildMode::Full,
            None,
            || BUILT_AT_MS,
            |_, _| unreachable!("rent resolver must not run when the build is gated off"),
            &mut disp,
        )
        .unwrap();
        assert_eq!(out, BuildOutcome::NoState);
        // No build ran (early return), so disposition stays None.
        assert_eq!(disp, None);
    }

    #[test]
    fn disposition_slot_resets_on_early_return_even_when_reused() {
        // A caller reusing one slot across calls must never see a previous
        // call's disposition leak through a non-building outcome — the
        // entry reset, not caller initialization, enforces the contract.
        let dir = tempfile::tempdir().unwrap();
        let store = StateStore::open(dir.path().join("s.redb").as_path()).unwrap();
        let mut disp = Some(ergo_state::store::BaseDisposition::Hit);
        let out = build_and_publish(
            &store.reader_handle(),
            &handle(),
            &intent([0u8; 32], 0),
            BuildMode::Full,
            None,
            || BUILT_AT_MS,
            |_, _| unreachable!("rent resolver must not run when the build is gated off"),
            &mut disp,
        )
        .unwrap();
        assert_eq!(out, BuildOutcome::NoState);
        assert_eq!(disp, None, "stale disposition must be cleared at entry");
    }

    #[test]
    fn tip_not_visible_when_committed_tip_is_behind_expected_height() {
        let (_dir, store) = genesis_store();
        // Genesis committed tip is [0;32] @ height 0; the intent expects a
        // parent at height 5 (in-memory applied, not yet persisted). Committed
        // height (0) < expected (5) ⇒ persist-lag ⇒ retryable.
        let mut disp = None;
        let out = build_and_publish(
            &store.reader_handle(),
            &handle().with_rent_config(true, 4),
            &intent([0x42u8; 32], 5),
            BuildMode::Full,
            None,
            || BUILT_AT_MS,
            |_, _| unreachable!("rent resolver must not run when the build is gated off"),
            &mut disp,
        )
        .unwrap();
        assert_eq!(out, BuildOutcome::TipNotVisible);
        assert_eq!(disp, None);
    }

    #[test]
    fn intent_superseded_when_committed_tip_is_at_expected_height_with_other_id() {
        let (_dir, store) = genesis_store();
        // Committed tip is [0;32] @ height 0; the intent expects a *different*
        // parent also at height 0. Committed height (0) is not behind expected
        // (0), so the expected parent can never become commit-visible — the
        // chain forked away from it. Drop the stale intent rather than spin.
        let mut disp = None;
        let out = build_and_publish(
            &store.reader_handle(),
            &handle().with_rent_config(true, 4),
            &intent([0x42u8; 32], 0),
            BuildMode::Full,
            None,
            || BUILT_AT_MS,
            |_, _| unreachable!("rent resolver must not run when the build is gated off"),
            &mut disp,
        )
        .unwrap();
        assert_eq!(out, BuildOutcome::IntentSuperseded);
        assert_eq!(disp, None);
    }

    #[test]
    fn not_synced_at_genesis_zero_tip() {
        let (_dir, store) = genesis_store();
        // Genesis: best_full == [0;32] @ height 0 → not synced (height 0).
        // The intent's expected parent matches the committed (zeroed) tip, so
        // the visibility check passes and the synced gate is what rejects.
        let mut disp = None;
        let out = build_and_publish(
            &store.reader_handle(),
            &handle().with_rent_config(true, 4),
            &intent([0u8; 32], 0),
            BuildMode::Full,
            None,
            || BUILT_AT_MS,
            |_, _| unreachable!("rent resolver must not run when the build is gated off"),
            &mut disp,
        )
        .unwrap();
        assert_eq!(out, BuildOutcome::NotSynced);
        assert_eq!(disp, None);
    }

    // NOTE: the Published / DroppedStale paths require generate_candidate to
    // succeed, which needs a synced store with stored extension +
    // block-transactions (emission) sections at a non-recalc height — the
    // chain harness landed with the action-loop wiring (Phase 2b-ii-b/3),
    // where the end-to-end loop→engine→cache→serve path is exercised.
}
