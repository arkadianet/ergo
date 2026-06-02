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

use ergo_primitives::digest::ADDigest;
use ergo_ser::header::Header;
use ergo_state::store::{CommittedSnapshot, StateError, StateStore};
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
}
