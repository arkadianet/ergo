//! Full-block validation: section linkage, merkle roots, extension
//! structural/interlink rules, fork-vote rule 407, per-tx validation
//! (sequential and parallel), and the topological layering that makes
//! the parallel path possible.
//!
//! [`validate::validate_full_block`] and
//! [`validate::validate_full_block_parallel`] (plus its wrappers) are the
//! public entry points; everything else in this module supports them:
//! - [`error`] — [`BlockValidationError`], the shared error type every
//!   other submodule constructs variants of.
//! - [`extension`] — structural extension checks (rules 400/404/405/406).
//! - [`size`] — block-transactions section size cap (rule 306).
//! - [`interlinks`] — interlink validation against the parent extension
//!   (rules 401/402).
//! - [`fork_vote`] — soft-fork vote prohibited-window check (rule 407).
//! - [`overlay`] — the intra-block UTXO overlay both validation paths share.
//! - [`layering`] — topological tx layering for the parallel path.
//! - [`validate`] — `validate_full_block` and `validate_full_block_parallel_impl`
//!   (+ its production wrappers), kept together deliberately: these are
//!   intentionally near-duplicate mirror implementations (sequential vs.
//!   parallel) whose inline comments cross-reference each other's steps.

mod error;
mod extension;
mod fork_vote;
mod interlinks;
mod layering;
mod overlay;
mod size;
mod validate;

pub use error::BlockValidationError;
pub use extension::{
    validate_extension_structural, EXTENSION_FIELD_VALUE_MAX_SIZE, MAX_EXTENSION_SIZE,
};
pub use fork_vote::{check_fork_vote_votes_collected_present, validate_fork_vote};
pub use interlinks::validate_interlinks;
#[cfg(any(test, feature = "test-helpers"))]
pub use validate::validate_full_block;
#[cfg(feature = "test-helpers")]
pub use validate::validate_full_block_parallel_with_costs;
pub use validate::{
    validate_full_block_parallel, validate_full_block_parallel_with_group_elements,
};

use crate::context::{ProtocolParams, UtxoView};
use crate::header::CheckedHeader;
use crate::tx::reemission::ReemissionRuleInputs;
use crate::tx::CheckedTransaction;
use ergo_ser::extension::Extension;

/// Chain context needed to validate a full block.
///
/// Bundles the parent-chain state that a sync loop would hold between
/// successive block validations. Block-specific data (header, body,
/// extension) is passed separately to [`validate_full_block`].
///
/// `parent` and `last_headers` carry the [`CheckedHeader`] type to
/// enforce at the type level that only validated headers enter the
/// block validation pipeline.
/// State of an in-progress soft-fork as Scala's
/// `currentParameters.softForkStartingHeight` and
/// `softForkVotesCollected` describe it, plus the matching
/// `VotingParams` constants needed to compute the rule-407
/// prohibited window. Constructed at the block-validation
/// boundary from `ActiveProtocolParameters` + `VotingParams`;
/// `None` if no soft-fork is in progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SoftForkState {
    /// `softForkStartingHeight` — the height at which the
    /// previous soft-fork's voting window opened.
    pub starting_height: u32,
    /// `softForkVotesCollected` — vote tally accumulated so far
    /// for the soft-fork.
    pub votes_collected: i32,
    /// `votingSettings.votingLength`.
    pub voting_length: u32,
    /// `votingSettings.softForkEpochs`.
    pub soft_fork_epochs: u32,
    /// `votingSettings.activationEpochs`.
    pub activation_epochs: u32,
    /// Approval threshold pre-computed from `votesCollected`. The
    /// state struct caches the boolean rather than re-computing
    /// from votingSettings.softForkApproved internally — the
    /// constructor at the boundary already has the data.
    pub approved: bool,
}

impl SoftForkState {
    /// Compute the prohibited-vote window per Scala
    /// `ErgoStateContext.checkForkVote`.
    /// - `finishing_height = starting_height + voting_length * soft_fork_epochs`
    /// - If rejected: prohibited from `finishing_height` to
    ///   `finishing_height + voting_length`
    /// - If approved: prohibited from `finishing_height` to
    ///   `finishing_height + voting_length * (activation_epochs + 1)`
    ///
    /// Returns `(window_lo, window_hi)` — `window_lo` inclusive,
    /// `window_hi` exclusive. All arithmetic saturates: an
    /// adversarial `starting_height` near `u32::MAX` would clip the
    /// window to the top of the range rather than overflow-wrap.
    pub fn prohibited_window(&self) -> (u32, u32) {
        let finishing = self
            .starting_height
            .saturating_add(self.voting_length.saturating_mul(self.soft_fork_epochs));
        let span_multiplier = if self.approved {
            self.activation_epochs.saturating_add(1)
        } else {
            1
        };
        let upper = finishing.saturating_add(self.voting_length.saturating_mul(span_multiplier));
        (finishing, upper)
    }
}

pub struct BlockValidationContext<'a> {
    /// The validated parent header (provides parent_id and timestamp).
    pub parent: &'a CheckedHeader,
    /// UTXO set for input resolution.
    pub utxo: &'a dyn UtxoView,
    /// Votable protocol parameters at the current epoch.
    pub params: &'a ProtocolParams,
    /// Voting epoch length in blocks (Scala `votingSettings.votingLength`).
    /// Mainnet 1024, testnet 128. Drives rule 215 (`hdrVotesUnknown`) —
    /// the rule only fires on headers at heights where `height %
    /// voting_length == 0 && height > 0`. Carried on this context bundle
    /// rather than on `ProtocolParams` because it's a chain-level constant
    /// (not a votable per-epoch param).
    pub voting_length: u32,
    /// Whether rule 215 (`hdrVotesUnknown`) has been deactivated by an
    /// activated soft-fork (`ErgoValidationSettings::is_rule_disabled(215)`).
    /// Scala marks the rule `mayBeDisabled = true` and mainnet's v6.0
    /// activation disabled it (`rules_to_disable = [215, 409]`) so the
    /// new `SubblocksPerBlock` param and downward proposals are votable
    /// at an epoch start. When `true`, rule 215 is skipped — Scala's
    /// `ValidationState` never runs a disabled rule. Defaults to `false`
    /// (rule active) for callers that don't track validation settings.
    pub votes_unknown_rule_disabled: bool,
    /// Parent block's extension. Drives interlink validation
    /// (rules 401 / 402): when `Some`, the current extension's
    /// interlink fields must decode and equal `update_interlinks(
    /// parent_header, parent_extension_interlinks)`. When `None`
    /// (genesis or pre-NiPoPoW-aware caller), rules 401/402 don't
    /// fire — matches Scala's `exIlUnableToValidate` recoverable
    /// path in `ExtensionValidator.validateInterlinks`.
    pub parent_extension: Option<&'a Extension>,
    /// In-progress soft-fork state, if any. Drives rule 407
    /// (`exCheckForkVote`): when present, headers casting a
    /// SoftFork vote are checked against the prohibited
    /// post-vote / pre-activation window. `None` means there's
    /// no soft-fork in progress (Scala
    /// `currentParameters.softForkStartingHeight.isEmpty`), and
    /// the rule trivially passes.
    pub soft_fork_state: Option<SoftForkState>,
    /// Last ~10 validated headers for `CONTEXT.headers` in script evaluation.
    pub last_headers: &'a [CheckedHeader],
    /// Optional script-validation checkpoint. When `Some((height, id))`:
    ///   - For blocks at or below `height`, per-input ErgoScript evaluation
    ///     is skipped. Structural / monetary / merkle / state-root checks
    ///     still run, so any tx that would violate UTXO conservation or
    ///     produce a wrong AVL digest is still rejected.
    ///   - At exactly `height`, the observed `header_id` MUST equal `id`.
    ///     Mismatch is a hard error — someone has switched chains under us.
    ///
    /// Mirrors Scala `mainnet.conf` `ergo.node.checkpoint`. `None` means
    /// fully validate every block.
    pub script_validation_checkpoint: Option<(u32, [u8; 32])>,
    /// EIP-27 re-emission rule inputs for the network being validated.
    /// When `Some`, every transaction in the block is checked against the
    /// re-emission burning condition (Scala
    /// `ErgoTransaction.verifyReemissionSpending`). `None` disables the
    /// check — the public testnet (no EIP-27) and callers that don't supply
    /// it. See [`ReemissionRuleInputs`].
    pub reemission: Option<&'a ReemissionRuleInputs>,
}

/// A block whose header is PoW/difficulty-validated and whose
/// transactions, section linkage, merkle roots, and intra-block UTXO
/// overlay all pass validation.
///
/// Construction is limited to [`validate_full_block`] — private fields
/// mean no other code can mint a `CheckedBlock`. Downstream consumers
/// (`StateStore::apply_block`) derive every consensus-significant
/// field (height, header_id, expected state root) from the embedded
/// header, not from caller arguments.
#[derive(Debug)]
pub struct CheckedBlock {
    checked_header: CheckedHeader,
    checked_transactions: Vec<CheckedTransaction>,
}

impl CheckedBlock {
    /// Borrow the validated header.
    pub fn header(&self) -> &CheckedHeader {
        &self.checked_header
    }
    /// Borrow the validated transactions in block order.
    pub fn transactions(&self) -> &[CheckedTransaction] {
        &self.checked_transactions
    }
    /// Move the validated header and transactions out of the
    /// container — useful when state apply wants to consume both
    /// without keeping a reference back into `self`.
    pub fn into_parts(self) -> (CheckedHeader, Vec<CheckedTransaction>) {
        (self.checked_header, self.checked_transactions)
    }

    /// Reassemble a `CheckedBlock` from already-validated parts. The
    /// inverse of [`Self::into_parts`]. This bypasses validation, so it
    /// is a test-only escape hatch (gated behind `test-helpers`) for
    /// driving state-apply seams with hand-built fixtures; production
    /// `CheckedBlock`s come only from `validate_full_block`.
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn from_parts(
        checked_header: CheckedHeader,
        checked_transactions: Vec<CheckedTransaction>,
    ) -> Self {
        Self {
            checked_header,
            checked_transactions,
        }
    }
}
