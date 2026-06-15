//! `CandidateStateView`: the read surface the candidate builder needs,
//! abstracted over its committed-state source.
//!
//! `generate_candidate` reads several consensus-bearing inputs — the
//! best-full tip, the parent header, the last-10 applied-header window,
//! the active params + validation settings, epoch headers (difficulty
//! retarget), the parent extension + block-transactions sections
//! (interlinks + emission box), and the AVL+ dry-run. On-loop those come
//! from the live `StateStore`; off-loop (the regeneration engine) they
//! must come from a single `CommittedSnapshot` read transaction so the
//! whole build is one consistent committed view (mixing per-call
//! transactions could splice inputs across a commit boundary and diverge
//! from the on-loop build).
//!
//! This trait is the seam. The `StateStore` impl delegates verbatim to
//! the existing inherent methods, so the on-loop build is byte-for-byte
//! unchanged; the `CommittedSnapshot` impl serves every read from its one
//! held transaction. Each read has already been proven byte-identical
//! between the two (see `ergo-state` `committed_snapshot_parity` +
//! the in-crate snapshot parity tests), so for the same committed tip the
//! two views produce the same candidate.

use std::cell::{Cell, RefCell};

use ergo_primitives::digest::ADDigest;
use ergo_primitives::digest::Digest32;
use ergo_ser::ergo_box::ErgoBox;
use ergo_ser::header::Header;
use ergo_state::store::{BaseDisposition, CommittedSnapshot, DryRunBase, StateError, StateStore};
use ergo_validation::{
    ActiveProtocolParameters, CheckedTransaction, ErgoValidationSettings, UtxoView,
};

/// One consistent committed view of the chain + authenticated state, as
/// the candidate builder consumes it. Implemented for the live
/// `StateStore` (on-loop) and for `CommittedSnapshot` (off-loop engine).
///
/// All methods must reflect ONE committed view; the `CommittedSnapshot`
/// impl guarantees this by sourcing every read from a single redb read
/// transaction.
///
/// Requires [`UtxoView`] (box resolution): the candidate builder seeds its
/// in-block overlay with the view as the committed base UTXO set, so the
/// snapshot's `get_box` must read from the same held transaction as the
/// rest of the build.
pub trait CandidateStateView: UtxoView {
    /// Best fully-applied block id — the candidate's parent.
    fn best_full_block_id(&self) -> [u8; 32];
    /// Height of the best fully-applied block.
    fn best_full_block_height(&self) -> u32;
    /// Raw serialized header bytes by id (`None` if absent).
    fn get_header_bytes(&self, id: &[u8; 32]) -> Result<Option<Vec<u8>>, StateError>;
    /// Canonical header-chain id at `height` (`None` if absent).
    fn header_id_at_height(&self, height: u32) -> Result<Option<[u8; 32]>, StateError>;
    /// Serialized block-section bytes by modifier id (`None` if absent).
    fn block_section(&self, modifier_id: &[u8; 32]) -> Result<Option<Vec<u8>>, StateError>;
    /// Last 10 applied-chain headers, tip-first.
    fn last_applied_chain_window_10(&self) -> Result<[Header; 10], StateError>;
    /// Active protocol params + cumulative validation settings at the tip.
    fn tip_snapshot_params(
        &self,
    ) -> Result<(ActiveProtocolParameters, ErgoValidationSettings), StateError>;
    /// Speculative AVL+ apply of `checked`, returning
    /// `(new_state_root, ad_proof_bytes, snapshot_tip_id)`.
    fn candidate_dry_run(
        &self,
        checked: &[CheckedTransaction],
    ) -> Result<(ADDigest, Vec<u8>, [u8; 32]), StateError>;
    /// Whether the Mode 2 (UTXO-snapshot) first-epoch trust sentinel is armed in
    /// this committed view. While armed, the cumulative validation settings the
    /// view reports are still the launch defaults (not the real pre-snapshot
    /// cumulative), so an epoch-boundary candidate built here would serialize a
    /// `0x02` block peers reject on `exMatchValidationSettings`. The builder
    /// refuses boundary mining while this is `true`.
    fn mode2_trust_first_epoch_armed(&self) -> Result<bool, StateError>;
}

// On-loop: verbatim delegation to the existing inherent methods, so the
// live candidate build is byte-for-byte unchanged. Each body is
// fully-qualified to the inherent method to rule out any trait-vs-inherent
// resolution ambiguity (and accidental self-recursion).
impl CandidateStateView for StateStore {
    fn best_full_block_id(&self) -> [u8; 32] {
        StateStore::chain_state(self).best_full_block_id
    }
    fn best_full_block_height(&self) -> u32 {
        StateStore::chain_state(self).best_full_block_height
    }
    fn get_header_bytes(&self, id: &[u8; 32]) -> Result<Option<Vec<u8>>, StateError> {
        StateStore::get_header(self, id)
    }
    fn header_id_at_height(&self, height: u32) -> Result<Option<[u8; 32]>, StateError> {
        StateStore::get_header_id_at_height(self, height)
    }
    fn block_section(&self, modifier_id: &[u8; 32]) -> Result<Option<Vec<u8>>, StateError> {
        StateStore::get_block_section(self, modifier_id)
    }
    fn last_applied_chain_window_10(&self) -> Result<[Header; 10], StateError> {
        StateStore::last_applied_chain_window_10(self)
    }
    fn tip_snapshot_params(
        &self,
    ) -> Result<(ActiveProtocolParameters, ErgoValidationSettings), StateError> {
        Ok(StateStore::tip_snapshot_params(self))
    }
    fn candidate_dry_run(
        &self,
        checked: &[CheckedTransaction],
    ) -> Result<(ADDigest, Vec<u8>, [u8; 32]), StateError> {
        StateStore::candidate_dry_run(self, checked)
    }
    fn mode2_trust_first_epoch_armed(&self) -> Result<bool, StateError> {
        Ok(StateStore::is_mode2_trust_first_epoch_armed(self))
    }
}

// Off-loop: every read served from the snapshot's one held transaction.
impl CandidateStateView for CommittedSnapshot {
    fn best_full_block_id(&self) -> [u8; 32] {
        CommittedSnapshot::best_full_block_id(self)
    }
    fn best_full_block_height(&self) -> u32 {
        CommittedSnapshot::best_full_block_height(self)
    }
    fn get_header_bytes(&self, id: &[u8; 32]) -> Result<Option<Vec<u8>>, StateError> {
        CommittedSnapshot::get_header_bytes(self, id)
    }
    fn header_id_at_height(&self, height: u32) -> Result<Option<[u8; 32]>, StateError> {
        CommittedSnapshot::header_id_at_height(self, height)
    }
    fn block_section(&self, modifier_id: &[u8; 32]) -> Result<Option<Vec<u8>>, StateError> {
        CommittedSnapshot::block_section(self, modifier_id)
    }
    fn last_applied_chain_window_10(&self) -> Result<[Header; 10], StateError> {
        CommittedSnapshot::last_headers_window(self)
    }
    fn tip_snapshot_params(
        &self,
    ) -> Result<(ActiveProtocolParameters, ErgoValidationSettings), StateError> {
        Ok((
            CommittedSnapshot::active_params(self)?,
            CommittedSnapshot::validation_settings(self)?,
        ))
    }
    fn candidate_dry_run(
        &self,
        checked: &[CheckedTransaction],
    ) -> Result<(ADDigest, Vec<u8>, [u8; 32]), StateError> {
        CommittedSnapshot::candidate_dry_run(self, checked)
    }
    fn mode2_trust_first_epoch_armed(&self) -> Result<bool, StateError> {
        CommittedSnapshot::mode2_trust_first_epoch_armed(self)
    }
}

/// A [`CandidateStateView`] over a committed snapshot that routes the AVL
/// dry-run through a per-tip pristine base cache. Every read except the
/// dry-run delegates straight to `snap`'s `CommittedSnapshot` impl (so the
/// candidate is sourced from the one held transaction exactly as the uncached
/// path); only [`candidate_dry_run`](CandidateStateView::candidate_dry_run)
/// consults `base`, calling [`CommittedSnapshot::candidate_dry_run_cached`] —
/// a cache hit reuses the memoized pristine tree (shallow COW clone), a
/// miss/tip-change full-rehydrates and re-memoizes.
///
/// After a build, [`Self::last_disposition`] returns the path the dry-run
/// took: [`BaseDisposition::Hit`], [`BaseDisposition::Advanced`],
/// [`BaseDisposition::Rehydrated`], or
/// [`BaseDisposition::RehydratedAfterFailedAdvance`]. The disposition is `None`
/// if no build has completed through this view yet (i.e. `candidate_dry_run`
/// has not been called).
///
/// The cached dry-run needs `&mut Option<DryRunBase>`, but the trait method is
/// `&self`. The borrow is reconciled with a [`RefCell`] around the borrowed
/// slot. This is sound because the build is strictly single-threaded and
/// serial: the base graph is `!Send` and lives on the engine's one dedicated
/// build worker thread, which runs at most one build at a time and calls
/// `candidate_dry_run` exactly once per build. There is no other live borrow
/// of the slot during a build, so the `RefCell` never double-borrows; it is
/// purely the type-level bridge from the trait's `&self` to the cache's
/// `&mut`, not a guard against real aliasing.
pub struct CachedSnapshotView<'a> {
    snap: &'a CommittedSnapshot,
    base: RefCell<&'a mut Option<DryRunBase>>,
    /// The disposition reported by the most recent `candidate_dry_run` call.
    /// `Cell` (not `RefCell`) because we write a `Copy` value and never hold a
    /// borrow — there is no aliasing hazard.
    disposition: Cell<Option<BaseDisposition>>,
}

impl<'a> CachedSnapshotView<'a> {
    /// Wrap `snap` so its dry-run routes through the per-tip `base` cache.
    pub fn new(snap: &'a CommittedSnapshot, base: &'a mut Option<DryRunBase>) -> Self {
        Self {
            snap,
            base: RefCell::new(base),
            disposition: Cell::new(None),
        }
    }

    /// The path taken by the most recent [`CandidateStateView::candidate_dry_run`]
    /// call through this view. `None` if no build has run yet.
    pub fn last_disposition(&self) -> Option<BaseDisposition> {
        self.disposition.get()
    }
}

impl UtxoView for CachedSnapshotView<'_> {
    fn get_box(&self, box_id: &Digest32) -> Option<ErgoBox> {
        self.snap.get_box(box_id)
    }
}

impl CandidateStateView for CachedSnapshotView<'_> {
    fn best_full_block_id(&self) -> [u8; 32] {
        CommittedSnapshot::best_full_block_id(self.snap)
    }
    fn best_full_block_height(&self) -> u32 {
        CommittedSnapshot::best_full_block_height(self.snap)
    }
    fn get_header_bytes(&self, id: &[u8; 32]) -> Result<Option<Vec<u8>>, StateError> {
        CommittedSnapshot::get_header_bytes(self.snap, id)
    }
    fn header_id_at_height(&self, height: u32) -> Result<Option<[u8; 32]>, StateError> {
        CommittedSnapshot::header_id_at_height(self.snap, height)
    }
    fn block_section(&self, modifier_id: &[u8; 32]) -> Result<Option<Vec<u8>>, StateError> {
        CommittedSnapshot::block_section(self.snap, modifier_id)
    }
    fn last_applied_chain_window_10(&self) -> Result<[Header; 10], StateError> {
        CommittedSnapshot::last_headers_window(self.snap)
    }
    fn tip_snapshot_params(
        &self,
    ) -> Result<(ActiveProtocolParameters, ErgoValidationSettings), StateError> {
        Ok((
            CommittedSnapshot::active_params(self.snap)?,
            CommittedSnapshot::validation_settings(self.snap)?,
        ))
    }
    fn candidate_dry_run(
        &self,
        checked: &[CheckedTransaction],
    ) -> Result<(ADDigest, Vec<u8>, [u8; 32]), StateError> {
        // Single serial build thread (see the type doc): this is the only
        // borrow of the slot for the duration of the build, so the `RefCell`
        // borrow can never conflict.
        let mut base = self.base.borrow_mut();
        // `base: RefMut<&mut Option<DryRunBase>>`; `&mut base` auto-derefs
        // through `DerefMut` to the `&mut Option<DryRunBase>` the cache wants.
        let mut disp: Option<BaseDisposition> = None;
        let result = self
            .snap
            .candidate_dry_run_cached(&mut base, checked, &mut disp);
        // Record disposition even on error (the path taken is still informative).
        self.disposition.set(disp);
        result
    }
    fn mode2_trust_first_epoch_armed(&self) -> Result<bool, StateError> {
        CommittedSnapshot::mode2_trust_first_epoch_armed(self.snap)
    }
}
