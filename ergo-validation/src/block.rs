use std::collections::{HashMap, HashSet};

use ergo_crypto::merkle::{extension_root, transactions_root};
use ergo_primitives::cost::{CostAccumulator, JitCost};
use ergo_primitives::digest::Digest32;
use ergo_ser::block_transactions::{write_block_transactions_with_version, BlockTransactions};
use ergo_ser::ergo_box::ErgoBox;
use ergo_ser::extension::Extension;
use ergo_ser::header::Header;
use ergo_ser::transaction::Transaction;
use rayon::prelude::*;
use thiserror::Error;

use crate::context::{ProtocolParams, TransactionContext, UtxoView};
use crate::error::ValidationError;
use crate::header::{CheckedHeader, HeaderValidationError};
use crate::tx::{validate_transaction_parsed, CheckedTransaction};

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
}

/// Failures raised by [`validate_full_block`] /
/// [`validate_full_block_parallel`].
#[derive(Debug, Error)]
pub enum BlockValidationError {
    /// A block section's `header_id` does not equal the validated
    /// header's id.
    #[error(
        "section header_id mismatch: {section} expected {}, got {}",
        hex::encode(expected),
        hex::encode(got)
    )]
    SectionIdMismatch {
        /// Name of the section that mismatched (`"transactions"` /
        /// `"extension"` / etc).
        section: &'static str,
        /// Header id from the validated header.
        expected: [u8; 32],
        /// Header id the section actually carried.
        got: [u8; 32],
    },

    /// Recomputed transactions Merkle root does not match
    /// `header.transactions_root`.
    #[error(
        "transactions root mismatch: expected {}, computed {}",
        hex::encode(expected),
        hex::encode(computed)
    )]
    TransactionsRootMismatch {
        /// Root carried by the header.
        expected: [u8; 32],
        /// Root recomputed from the transactions.
        computed: [u8; 32],
    },

    /// Recomputed extension Merkle root does not match
    /// `header.extension_root`.
    #[error(
        "extension root mismatch: expected {}, computed {}",
        hex::encode(expected),
        hex::encode(computed)
    )]
    ExtensionRootMismatch {
        /// Root carried by the header.
        expected: [u8; 32],
        /// Root recomputed from the extension.
        computed: [u8; 32],
    },

    /// A specific transaction inside the block failed validation.
    #[error("transaction {index}: {error}")]
    Transaction {
        /// Index of the failing transaction.
        index: usize,
        /// The underlying transaction-validation error.
        error: ValidationError,
    },

    /// Cumulative JIT cost across all transactions exceeded the per-block limit.
    #[error("block cost exceeded: total={total}, limit={limit}")]
    BlockCostExceeded {
        /// Total accumulated cost.
        total: u64,
        /// Per-block cost limit (from `ProtocolParams::max_block_cost`).
        limit: u64,
    },

    /// Two transactions in the same block reference the same input
    /// `box_id`.
    #[error("intra-block double spend: txs {first} and {second} both consume box {box_id}")]
    DoubleSpendInBlock {
        /// First transaction (lower index) referencing the box.
        first: usize,
        /// Second transaction (higher index) referencing the box.
        second: usize,
        /// Hex-encoded shared `box_id`.
        box_id: String,
    },

    /// Block at the configured checkpoint height has a header id that
    /// does not match the pinned value — someone has switched chains.
    #[error(
        "checkpoint mismatch at height {height}: expected {}, got {}",
        hex::encode(expected),
        hex::encode(got)
    )]
    CheckpointMismatch {
        /// Checkpointed height.
        height: u32,
        /// Pinned header id.
        expected: [u8; 32],
        /// Header id observed at this height.
        got: [u8; 32],
    },

    /// Scala `exSize` (rule 400) — serialized extension size exceeds
    /// `Constants.MaxExtensionSize` (32 KiB).
    #[error("extension too large: serialized size {size}B > {max}B (rule 400)")]
    ExtensionTooLarge {
        /// Computed serialized size of the extension (bytes).
        size: usize,
        /// Hard cap from Scala `Constants.MaxExtensionSize`.
        max: usize,
    },

    /// Scala `bsBlockTransactionsSize` (rule 306) — serialized
    /// `BlockTransactions` section size exceeds the voted
    /// `maxBlockSize` parameter at the current epoch.
    #[error("block transactions too large: serialized size {size}B > {max}B (rule 306)")]
    BlockTransactionsTooLarge {
        /// Computed serialized size of the section (bytes).
        size: usize,
        /// Voted cap (`ProtocolParams::max_block_size`).
        max: u32,
    },

    /// Scala `exValueLength` (rule 404) — an extension field's value
    /// exceeds `Extension.FieldValueMaxSize` (64 bytes). Wire codec
    /// accepts up to 255 (u8 length prefix); validator enforces the
    /// tighter Scala cap.
    #[error("extension field {index}: value length {len}B exceeds cap {max}B (rule 404)")]
    ExtensionFieldValueTooLong {
        /// Position of the offending field inside `extension.fields`.
        index: usize,
        /// Actual value length in bytes.
        len: usize,
        /// Hard cap from Scala `Extension.FieldValueMaxSize`.
        max: usize,
    },

    /// Scala `exDuplicateKeys` (rule 405) — two extension fields share
    /// the same 2-byte key. The wire codec preserves both entries, but
    /// downstream lookup (`extension.find(key)`) would only see the
    /// first; Scala rejects up-front so the behavior is unambiguous.
    #[error("extension duplicate key {key}: fields at positions {first} and {second} (rule 405)")]
    ExtensionDuplicateKey {
        /// Hex-encoded 2-byte duplicate key.
        key: String,
        /// Position of the first occurrence.
        first: usize,
        /// Position of the duplicate.
        second: usize,
    },

    /// Scala `exEmpty` (rule 406) — non-genesis block has empty
    /// extension. Genesis (height 0) is allowed to have zero fields.
    #[error("non-genesis block at height {height} has empty extension (rule 406)")]
    ExtensionEmptyOnNonGenesis {
        /// Header height of the block under validation.
        height: u32,
    },

    /// Scala `exIlEncoding` (rule 401) — extension's interlink
    /// fields do not decode (`NipopowAlgos.unpackInterlinks` raises
    /// `Failure`). Most often: an interlink value's length isn't
    /// the expected `1 + 32` bytes.
    #[error("interlink encoding failure: {reason} (rule 401)")]
    InvalidInterlinkEncoding {
        /// Decoder error message.
        reason: String,
    },

    /// Scala `exCheckForkVote` (rule 407) — at the time a header
    /// casts a SoftFork vote, the previous soft-fork must already
    /// have completed both its voting period and (if approved) its
    /// activation period. The "prohibited window" runs from
    /// `finishingHeight = startingHeight + votingLength * softForkEpochs`
    /// to either `finishingHeight + votingLength` (if rejected) or
    /// `finishingHeight + votingLength * (activationEpochs + 1)` (if
    /// approved). Any SoftFork vote inside that window is rejected.
    #[error("fork-vote at height {height} forbidden in prior soft-fork window {window_lo}..{window_hi} (rule 407)")]
    ForkVoteInProhibitedWindow {
        /// Header height casting the vote.
        height: u32,
        /// Inclusive lower bound of the prohibited window.
        window_lo: u32,
        /// Exclusive upper bound of the prohibited window.
        window_hi: u32,
    },

    /// Scala `exCheckForkVote` (rule 407) — a hostile parameter table carries a
    /// soft-fork *starting height* (`softForkStartingHeight`, id 121) but NO
    /// *votes-collected* entry (`softForkVotesCollected`, id 122). Scala
    /// `checkForkVote` reads `softForkVotesCollected.get` after
    /// `softForkStartingHeight.nonEmpty`, so the missing entry throws
    /// `NoSuchElementException`, surfaced as a rule-407 reject — but only when the
    /// header casts the SoftFork vote (`if (forkVote)`).
    #[error("fork-vote at height {height} with soft-fork start but no votes-collected entry (rule 407, 122-without-121)")]
    ForkVoteVotesCollectedMissing {
        /// Header height casting the vote.
        height: u32,
    },

    /// Scala `exIlStructure` (rule 402) — the extension's interlinks
    /// don't equal `updateInterlinks(parent_header, parent_interlinks)`.
    /// The interlinks vector is consensus-required to be derived
    /// exactly from the parent block's interlinks updated for the
    /// parent header's level.
    ///
    /// `reason` distinguishes the failure mode:
    /// - `"length mismatch"` — both extensions decoded but
    ///   structures differ
    /// - `"parent interlinks decode failed: ..."` — parent extension
    ///   couldn't be parsed (Scala's `Failure` propagation)
    /// - `"parent interlinks empty on non-genesis parent"` — empty
    ///   parent vector on a non-genesis parent would otherwise hit
    ///   `update_interlinks` `assert!` panic; converted to typed
    ///   rule 402 reject for adversarial-input safety
    #[error("interlink structure mismatch ({reason}): expected {expected_len} entries, got {got_len} (rule 402)")]
    InterlinkStructureMismatch {
        /// Number of interlinks expected (derived from parent;
        /// `0` when the derivation itself failed).
        expected_len: usize,
        /// Number of interlinks the current extension carries.
        got_len: usize,
        /// Specific failure-mode message; see variant doc.
        reason: String,
    },

    /// Header-level validation failure surfaced through the block
    /// validator. Currently carries rule 215 (`hdrVotesUnknown`),
    /// which requires `voting_length` from the block validation
    /// context — the per-header validator can't fire it. Future
    /// header rules that need block-level chain config land here
    /// too.
    #[error("header rule failure during block validation: {0}")]
    Header(#[from] HeaderValidationError),
}

/// Scala `Constants.MaxExtensionSize` — 32 KiB. Wire-form upper bound
/// for the entire serialized extension section (not just the fields).
pub const MAX_EXTENSION_SIZE: usize = 32 * 1024;

/// Scala `Extension.FieldValueMaxSize` — 64 bytes. Per-field value
/// cap. Our codec accepts up to 255 (u8 length-prefix wire form);
/// the validator enforces the tighter Scala cap so an oversize-but-
/// parseable value gets rejected at apply time rather than silently
/// passing.
pub const EXTENSION_FIELD_VALUE_MAX_SIZE: usize = 64;

/// VLQ-encoded byte length of a `u16` value as the `VlqWriter::put_u16`
/// emits it. 0..=127 → 1 byte; 128..=16383 → 2 bytes; 16384..=65535 →
/// 3 bytes. The Scala `ExtensionSerializer` uses the same VLQ shape
/// for the field count prefix.
fn vlq_u16_size(v: u16) -> usize {
    if v < 128 {
        1
    } else if v < 16_384 {
        2
    } else {
        3
    }
}

/// Compute the serialized byte-count of an `Extension` without
/// round-tripping through the writer. Mirrors `write_extension`
/// (`ergo-ser/src/extension.rs`) exactly:
/// `32 (header_id) + VLQ(count) + Σ (2 key bytes + 1 length byte +
/// value bytes)`.
///
/// The 32-byte `header_id` and the VLQ-encoded count must both be
/// included; the size cap bounds the FULL serialized section, so a
/// shorter accounting could let an adversarial extension crafted to
/// sit just above the cap slip past.
fn serialized_extension_size(extension: &Extension) -> usize {
    let count = extension.fields.len().min(u16::MAX as usize) as u16;
    let mut total: usize = 32; // header_id
    total = total.saturating_add(vlq_u16_size(count));
    for field in &extension.fields {
        // 2 key bytes + 1 length byte + value bytes
        total = total.saturating_add(3).saturating_add(field.value.len());
    }
    total
}

/// Scala `bsBlockTransactionsSize` (rule 306) — caps the
/// serialized `BlockTransactions` section at
/// `params.max_block_size`. Matches Scala's
/// `fb.blockTransactions.size <= currentParameters.maxBlockSize`
/// at `ErgoStateContext.appendFullBlock:308-310`.
///
/// Re-serializes via `write_block_transactions_with_version`
/// because Scala's `.size` is the cached serialized length (or
/// `bytes.length` when uncached). The cost is O(N) of the block,
/// same as the transactions-root walk that already ran upstream,
/// so the only adversarial concern is that this runs AFTER
/// `transactions_root` confirms the bytes match the header
/// commitment — the "structural check after cryptographic binding"
/// ordering keeps an unbound block from forcing the reserialize.
pub(crate) fn check_block_transactions_size(
    block_transactions: &BlockTransactions,
    block_version: u8,
    max_block_size: u32,
) -> Result<(), BlockValidationError> {
    let mut w = ergo_primitives::writer::VlqWriter::new();
    write_block_transactions_with_version(&mut w, block_transactions, block_version).map_err(
        |e| BlockValidationError::Transaction {
            index: 0,
            error: ValidationError::Deserialization(format!("block_transactions reserialize: {e}")),
        },
    )?;
    let size = w.result().len();
    if size > max_block_size as usize {
        return Err(BlockValidationError::BlockTransactionsTooLarge {
            size,
            max: max_block_size,
        });
    }
    Ok(())
}

/// Scala `exCheckForkVote` (rule 407) — when the header casts a
/// SoftFork vote (parameter byte 120, see `KNOWN_VOTE_IDS` in
/// `header.rs`), reject if `header.height` falls inside the
/// previous soft-fork's prohibited window. `None` soft_fork_state
/// means no fork in progress — Scala's
/// `softForkStartingHeight.isEmpty` case — and the check is a
/// trivial pass.
/// Scala `ErgoStateContext.checkForkVote` reads `softForkVotesCollected.get`
/// immediately after `softForkStartingHeight.nonEmpty`. A hostile parameter
/// table carrying a soft-fork *start height* (id 121) but NO *votes-collected*
/// entry (id 122) makes that `.get` throw `NoSuchElementException`, which
/// `validateNoThrow(exCheckForkVote, ...)` surfaces as a rule-407 reject — but
/// ONLY when the header casts the SoftFork vote (Scala runs `checkForkVote`
/// `if (forkVote)`). The `Option<SoftForkState>` handed to [`validate_fork_vote`]
/// collapses this case to `None` (indistinguishable from "no soft fork in
/// progress"), so the block path must enforce it separately, here, from the raw
/// `softForkStartingHeight` / `softForkVotesCollected` params. Height-independent:
/// Scala throws at the `.get`, before the prohibited-window check, so the sign of
/// the starting height is irrelevant (matching `nonEmpty`).
pub fn check_fork_vote_votes_collected_present(
    header: &Header,
    soft_fork_starting_height: Option<i32>,
    soft_fork_votes_collected: Option<i32>,
    rule_407_disabled: bool,
) -> Result<(), BlockValidationError> {
    if rule_407_disabled {
        // Scala enforces this via `validateNoThrow(exCheckForkVote, ...)`, which
        // is disableable: a disabled rule 407 skips `checkForkVote` entirely, so
        // the `softForkVotesCollected.get` throw is never evaluated.
        return Ok(());
    }
    const SOFT_FORK_VOTE_BYTE: u8 = 120;
    if !header.votes.contains(&SOFT_FORK_VOTE_BYTE) {
        // Scala only evaluates `checkForkVote` `if (forkVote)`.
        return Ok(());
    }
    if soft_fork_starting_height.is_some() && soft_fork_votes_collected.is_none() {
        return Err(BlockValidationError::ForkVoteVotesCollectedMissing {
            height: header.height,
        });
    }
    Ok(())
}

pub fn validate_fork_vote(
    header: &Header,
    soft_fork_state: Option<&SoftForkState>,
) -> Result<(), BlockValidationError> {
    // Scala `Parameters.SoftFork: Byte = 120`. We match the
    // unsigned byte directly so the check is decoupled from i8/u8
    // sign-extension quirks.
    const SOFT_FORK_VOTE_BYTE: u8 = 120;
    let casts_fork_vote = header.votes.contains(&SOFT_FORK_VOTE_BYTE);
    if !casts_fork_vote {
        return Ok(());
    }
    let Some(state) = soft_fork_state else {
        return Ok(());
    };
    let (lo, hi) = state.prohibited_window();
    if header.height >= lo && header.height < hi {
        return Err(BlockValidationError::ForkVoteInProhibitedWindow {
            height: header.height,
            window_lo: lo,
            window_hi: hi,
        });
    }
    Ok(())
}

/// Scala-parity interlink validation for the extension section
/// (rules 401 + 402). Mirrors
/// `ergo-core/.../ExtensionValidator.scala:27-46`. Returns `Ok(())`
/// when there's no parent extension to compare against — that's
/// Scala's `exIlUnableToValidate` recoverable path; only the
/// non-genesis-with-parent-extension case enforces 401/402.
///
/// Behavior on per-input failure modes:
/// - Parent extension decode fails: surfaces rule 402
///   (`InterlinkStructureMismatch`) because the structures can't
///   match (Scala's `Failure(...) == Failure(...)` is always false,
///   so the inequality fires `exIlStructure`).
/// - Current extension decode fails: surfaces rule 401
///   (`InvalidInterlinkEncoding`).
/// - Decoded current != `update_interlinks(parent_header,
///   parent_decoded)`: surfaces rule 402.
pub fn validate_interlinks(
    extension: &Extension,
    parent_header: &Header,
    parent_extension: &Extension,
) -> Result<(), BlockValidationError> {
    let to_kv = |fields: &[ergo_ser::extension::ExtensionField]| -> Vec<(Vec<u8>, Vec<u8>)> {
        fields
            .iter()
            .map(|f| (f.key.to_vec(), f.value.clone()))
            .collect()
    };

    let current_links = crate::popow::algos::unpack_interlinks(&to_kv(&extension.fields))
        .map_err(|reason| BlockValidationError::InvalidInterlinkEncoding { reason })?;

    let parent_links =
        match crate::popow::algos::unpack_interlinks(&to_kv(&parent_extension.fields)) {
            Ok(v) => v,
            Err(decode_err) => {
                // Scala's `Failure` propagates into `expectedLinksTry` and
                // the `expected == current` check fires rule 402.
                return Err(BlockValidationError::InterlinkStructureMismatch {
                    expected_len: 0,
                    got_len: current_links.len(),
                    reason: format!("parent interlinks decode failed: {decode_err}"),
                });
            }
        };

    // Adversarial-input safety: an `Ok([])` parent vector on a
    // non-genesis parent would otherwise hit `update_interlinks`'s
    // `assert!(!prev_interlinks.is_empty(), ...)` and panic the
    // node. Scala's `require` would also raise, but the surrounding
    // `Try` lifts it to a structure mismatch in the validateInterlinks
    // composition. Convert to typed rule 402 reject here so a peer
    // shipping a malformed-but-decodable parent extension cannot
    // crash us.
    if parent_links.is_empty() && !crate::popow::algos::is_genesis(parent_header) {
        return Err(BlockValidationError::InterlinkStructureMismatch {
            expected_len: 0,
            got_len: current_links.len(),
            reason: "parent interlinks empty on non-genesis parent".to_string(),
        });
    }

    let expected_links = crate::popow::algos::update_interlinks(parent_header, &parent_links)
        .map_err(|e| BlockValidationError::InterlinkStructureMismatch {
            expected_len: 0,
            got_len: current_links.len(),
            reason: format!("parent header serialization failed: {e}"),
        })?;
    if expected_links != current_links {
        return Err(BlockValidationError::InterlinkStructureMismatch {
            expected_len: expected_links.len(),
            got_len: current_links.len(),
            reason: "length mismatch".to_string(),
        });
    }

    Ok(())
}

/// Scala-parity structural checks for an extension section
/// (rules 400 / 404 / 405 / 406). Runs on every block, not just
/// epoch boundaries; called from [`validate_full_block`] between
/// the extension-root match and the per-tx loop.
pub fn validate_extension_structural(
    extension: &Extension,
    block_height: u32,
) -> Result<(), BlockValidationError> {
    // 406: non-genesis block must carry at least one extension field.
    if block_height != 0 && extension.fields.is_empty() {
        return Err(BlockValidationError::ExtensionEmptyOnNonGenesis {
            height: block_height,
        });
    }

    // 400: total serialized size cap.
    let size = serialized_extension_size(extension);
    if size > MAX_EXTENSION_SIZE {
        return Err(BlockValidationError::ExtensionTooLarge {
            size,
            max: MAX_EXTENSION_SIZE,
        });
    }

    // 404: per-field value-length cap.
    for (index, field) in extension.fields.iter().enumerate() {
        if field.value.len() > EXTENSION_FIELD_VALUE_MAX_SIZE {
            return Err(BlockValidationError::ExtensionFieldValueTooLong {
                index,
                len: field.value.len(),
                max: EXTENSION_FIELD_VALUE_MAX_SIZE,
            });
        }
    }

    // 405: no two fields share a key. O(N²) over fields is fine —
    // mainnet extensions hold 4-30 entries, never enough to merit
    // a HashSet allocation.
    for first in 0..extension.fields.len() {
        let key = extension.fields[first].key;
        for second in (first + 1)..extension.fields.len() {
            if extension.fields[second].key == key {
                return Err(BlockValidationError::ExtensionDuplicateKey {
                    key: hex::encode(key),
                    first,
                    second,
                });
            }
        }
    }
    Ok(())
}

/// UTXO overlay for intra-block transaction dependencies.
///
/// Wraps a base UtxoView and tracks outputs created and inputs spent
/// within the current block, so transaction N can spend outputs of
/// transaction M (M < N) in the same block.
struct BlockUtxoOverlay<'a> {
    base: &'a dyn UtxoView,
    in_block_outputs: HashMap<Digest32, ErgoBox>,
    spent_in_block: HashSet<Digest32>,
}

impl<'a> BlockUtxoOverlay<'a> {
    fn new(base: &'a dyn UtxoView) -> Self {
        Self {
            base,
            in_block_outputs: HashMap::new(),
            spent_in_block: HashSet::new(),
        }
    }

    fn apply_tx(&mut self, tx: &Transaction) {
        for input in &tx.inputs {
            self.spent_in_block.insert(input.box_id);
        }
        // `transaction_id` is fallible only on write-side errors that
        // require malformed in-memory state (token-id-not-in-table); a
        // Transaction that reached this overlay has already been
        // structurally validated, so the id derivation cannot fail.
        let tx_id = ergo_ser::transaction::transaction_id(tx)
            .expect("validated Transaction yields a deterministic id");
        for (idx, output) in tx.output_candidates.iter().enumerate() {
            let ergo_box = ErgoBox {
                candidate: output.clone(),
                transaction_id: tx_id,
                index: idx as u16,
            };
            if let Ok(box_id) = ergo_box.box_id() {
                self.in_block_outputs.insert(box_id, ergo_box);
            }
        }
    }
}

impl BlockUtxoOverlay<'_> {
    /// Look up a box for data-input resolution.
    ///
    /// Resolves through the union of pre-block UTXO + intra-block
    /// creates, ignoring intra-block spends. This differs from regular
    /// input resolution (`UtxoView::get_box`) which both surfaces
    /// in-block creates AND filters out in-block spends.
    ///
    /// Mainnet oracle evidence:
    /// 1. Block 290684 — data input to a box SPENT earlier in the same
    ///    block resolves (the box was in pre-block UTXO; we don't
    ///    filter on `spent_in_block`).
    /// 2. Block 422179 — tx 2 has a data input on a box with
    ///    `settlementHeight = 422179` (created in this same block by
    ///    an earlier tx). Scala accepts this block — the box must be
    ///    found via `in_block_outputs`.
    ///
    /// An earlier version of this helper went to `base` only, citing
    /// "Scala parity: ErgoState.stateChanges resolves data inputs from
    /// the original state". That reading was wrong — Scala's stateful
    /// validation runs over a sequentially-applied per-block view, so
    /// a tx's data inputs see what earlier txs in the same block have
    /// already added. Mainnet block 422179 is the proof.
    fn get_box_from_base(&self, box_id: &Digest32) -> Option<ErgoBox> {
        if let Some(b) = self.in_block_outputs.get(box_id) {
            return Some(b.clone());
        }
        self.base.get_box(box_id)
    }
}

impl UtxoView for BlockUtxoOverlay<'_> {
    fn get_box(&self, box_id: &Digest32) -> Option<ErgoBox> {
        if self.spent_in_block.contains(box_id) {
            return None;
        }
        if let Some(b) = self.in_block_outputs.get(box_id) {
            return Some(b.clone());
        }
        self.base.get_box(box_id)
    }
}

/// Topological layering of a block's transactions for parallel validation.
///
/// Every tx index in `[0, txs.len())` appears in exactly one layer. For any
/// pair where tx `j` spends (or data-reads) an output of tx `i` within the
/// same block, `layer[j] > layer[i]`. Within a single layer no tx depends
/// on any other in the same layer, so layer members can be validated
/// concurrently against a shared overlay snapshot that contains the
/// outputs of strictly lower layers.
///
/// Also rejects intra-block double-spends (two txs listing the same input
/// `box_id`) up front — this was caught implicitly by the sequential
/// [`BlockUtxoOverlay`] (the second tx's input resolution returned `None`),
/// but parallel validation must reject explicitly since both txs would see
/// the same pre-block UTXO snapshot.
#[derive(Debug)]
pub(crate) struct TxLayers {
    /// `layers[L]` = ascending-sorted tx indices whose dependency depth is `L`.
    pub(crate) layers: Vec<Vec<usize>>,
}

type TxLayerInput = (usize, Vec<u8>, Vec<ErgoBox>, Vec<ErgoBox>);
type TxLayerResult = (usize, Result<(CheckedTransaction, u64), ValidationError>);

#[cfg(test)]
impl TxLayers {
    pub(crate) fn layer_count(&self) -> usize {
        self.layers.len()
    }
    pub(crate) fn tx_count(&self) -> usize {
        self.layers.iter().map(|v| v.len()).sum()
    }
}

/// Build the topological layering for a block's transactions.
///
/// Returns [`BlockValidationError::DoubleSpendInBlock`] if two txs list the
/// same `box_id` as an input.
///
/// Boxes whose `transaction_id` or `box_id` derivation fails (a structural
/// failure: malformed token table, duplicate output ids, etc.) are
/// omitted from the output→owner map. Layering correctness depends only
/// on syntactically well-formed boxes being mapped, which is the case
/// for any tx that will pass per-tx validation. Anything skipped here
/// is a structurally invalid tx that downstream `validate_transaction_parsed`
/// will reject explicitly — typically with `Deserialization` or
/// `InputBoxNotFound`. The whole block is rejected in either case.
///
/// Complexity: O(sum(inputs) + sum(outputs)) hashmap ops, plus one box
/// serialize per output. Benchmarked at <1ms for a 200-tx block.
pub(crate) fn build_tx_layers(txs: &[Transaction]) -> Result<TxLayers, BlockValidationError> {
    // 1. Detect intra-block double-spend. Two txs listing the same box_id
    //    as input are mutually exclusive regardless of whether the box is
    //    pre-block or created by another tx in the same block.
    let mut first_spender: HashMap<Digest32, usize> = HashMap::new();
    for (i, tx) in txs.iter().enumerate() {
        for input in &tx.inputs {
            if let Some(&prev) = first_spender.get(&input.box_id) {
                return Err(BlockValidationError::DoubleSpendInBlock {
                    first: prev,
                    second: i,
                    box_id: hex::encode(input.box_id.as_bytes()),
                });
            }
            first_spender.insert(input.box_id, i);
        }
    }

    // 2. Map each output box_id → owning tx index so input resolution in
    //    step 3 can detect intra-block produce→consume edges.
    let mut output_owner: HashMap<Digest32, usize> = HashMap::new();
    for (i, tx) in txs.iter().enumerate() {
        let tx_id = match ergo_ser::transaction::transaction_id(tx) {
            Ok(id) => id,
            Err(_) => continue, // malformed — will be rejected by canonical check
        };
        for (idx, output) in tx.output_candidates.iter().enumerate() {
            let ergo_box = ErgoBox {
                candidate: output.clone(),
                transaction_id: tx_id,
                index: idx as u16,
            };
            if let Ok(box_id) = ergo_box.box_id() {
                output_owner.insert(box_id, i);
            }
        }
    }

    // 3. Compute dependency depth per tx. A block's canonical tx order
    //    places dependencies at lower indices, so forward iteration with
    //    layer[j] = max(layer[dep]) + 1 is sufficient. Backwards edges
    //    (j depends on k>j) cannot be stitched into a dag here — they
    //    fall through unresolved and the per-tx input resolution will
    //    fail normally, matching sequential behaviour.
    let mut layer: Vec<usize> = vec![0; txs.len()];
    for (i, tx) in txs.iter().enumerate() {
        let mut max_dep_layer: Option<usize> = None;
        let record_dep = |other_idx: usize, cur: &mut Option<usize>| {
            if other_idx < i {
                let l = layer[other_idx];
                *cur = Some(cur.map_or(l, |m| m.max(l)));
            }
        };
        for input in &tx.inputs {
            if let Some(&j) = output_owner.get(&input.box_id) {
                record_dep(j, &mut max_dep_layer);
            }
        }
        for di in &tx.data_inputs {
            if let Some(&j) = output_owner.get(&di.box_id) {
                record_dep(j, &mut max_dep_layer);
            }
        }
        if let Some(ml) = max_dep_layer {
            layer[i] = ml + 1;
        }
    }

    // 4. Bucket tx indices into layer vectors. Preserves ascending order
    //    within each layer because we iterate input in ascending tx index.
    let max_layer = layer.iter().copied().max().unwrap_or(0);
    let mut layers: Vec<Vec<usize>> = vec![Vec::new(); max_layer + 1];
    for (i, l) in layer.iter().enumerate() {
        layers[*l].push(i);
    }

    Ok(TxLayers { layers })
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

/// Validate a full block: section linkage + tx root + ext root + all txs.
///
/// The header is accepted as a [`CheckedHeader`], constructed either via
/// `validate_header()` (during header sync) or `from_persisted_parts()`
/// (during block processing). PoW/difficulty validation is NOT repeated here.
///
/// Returns a [`CheckedBlock`] whose header and transactions are bound
/// together — state application via `StateStore::apply_block` derives
/// height/header_id/state_root from the embedded header, closing the old
/// hole where caller-supplied height could drift from the validated
/// header.
#[tracing::instrument(
    name = "validate_block",
    level = "debug",
    skip_all,
    fields(
        height = checked_header.height(),
        header_id = %hex::encode(checked_header.header_id()),
        n_txs = block_transactions.transactions.len(),
    ),
)]
// Sequential variant retained for differential / regression
// testing against the parallel path. Production uses
// `validate_full_block_parallel` from `ergo-sync::block_proc`;
// gating this behind `test-helpers` keeps the public surface
// narrow without losing cross-validation coverage in the test
// crates.
#[cfg(any(test, feature = "test-helpers"))]
pub fn validate_full_block(
    checked_header: CheckedHeader,
    block_transactions: &BlockTransactions,
    extension: &Extension,
    ctx: &BlockValidationContext<'_>,
) -> Result<CheckedBlock, BlockValidationError> {
    let header = checked_header.header();
    let header_id = checked_header.header_id();

    // Checkpoint enforcement (matches Scala mainnet.conf ergo.node.checkpoint).
    // At exactly the configured height, the observed header_id MUST equal
    // the configured block_id — this is the single point of trust that
    // protects every block below the checkpoint from a chain-switch attack.
    let skip_scripts = match ctx.script_validation_checkpoint {
        Some((ckpt_h, ckpt_id)) => {
            if header.height == ckpt_h && header_id != &ckpt_id {
                return Err(BlockValidationError::CheckpointMismatch {
                    height: ckpt_h,
                    expected: ckpt_id,
                    got: *header_id,
                });
            }
            header.height <= ckpt_h
        }
        None => false,
    };

    // 2. Section-to-header linkage
    if block_transactions.header_id.as_bytes() != header_id {
        return Err(BlockValidationError::SectionIdMismatch {
            section: "BlockTransactions",
            expected: *header_id,
            got: *block_transactions.header_id.as_bytes(),
        });
    }
    if extension.header_id.as_bytes() != header_id {
        return Err(BlockValidationError::SectionIdMismatch {
            section: "Extension",
            expected: *header_id,
            got: *extension.header_id.as_bytes(),
        });
    }

    // 2.5. Header vote-known check (Scala rule 215). Fires only on
    // epoch-start headers; off-epoch headers no-op. Skipped entirely
    // when an activated soft-fork has disabled the rule
    // (`ctx.votes_unknown_rule_disabled`) — mainnet did so at v6.0.
    // Block-level because `voting_length` is a chain config carried on
    // the validation context. Wired into
    // `validate_full_block_parallel_impl` too — keep both paths in sync.
    crate::header::check_votes_known_active(
        header,
        ctx.voting_length,
        ctx.votes_unknown_rule_disabled,
    )
    .map_err(BlockValidationError::Header)?;

    // 2.6. Fork-vote prohibited-window check (Scala rule 407).
    // No-op when no soft-fork is in progress (ctx.soft_fork_state
    // is None) OR when the header doesn't cast a SoftFork vote.
    validate_fork_vote(header, ctx.soft_fork_state.as_ref())?;

    // 3. Transactions root
    let txs = &block_transactions.transactions;
    let mut tx_ids: Vec<Vec<u8>> = Vec::with_capacity(txs.len());
    for (i, tx) in txs.iter().enumerate() {
        let bts = ergo_ser::transaction::bytes_to_sign(tx).map_err(|e| {
            BlockValidationError::Transaction {
                index: i,
                error: ValidationError::Deserialization(format!("bytes_to_sign: {e}")),
            }
        })?;
        tx_ids.push(ergo_crypto::autolykos::common::blake2b256(&bts).to_vec());
    }
    let tx_id_refs: Vec<&[u8]> = tx_ids.iter().map(|id| id.as_slice()).collect();

    let witness_data: Vec<Vec<u8>>;
    let witness_refs: Option<Vec<&[u8]>>;
    if header.version >= 2 {
        witness_data = txs
            .iter()
            .map(|tx| {
                let mut all_proofs = Vec::new();
                for input in &tx.inputs {
                    all_proofs.extend_from_slice(&input.spending_proof.proof);
                }
                let hash = ergo_crypto::autolykos::common::blake2b256(&all_proofs);
                hash[1..].to_vec() // 31 bytes: drop first byte
            })
            .collect();
        let refs: Vec<&[u8]> = witness_data.iter().map(|w| w.as_slice()).collect();
        witness_refs = Some(refs);
    } else {
        witness_refs = None;
    }

    let computed_tx_root = transactions_root(&tx_id_refs, witness_refs.as_deref());
    if computed_tx_root != *header.transactions_root.as_bytes() {
        return Err(BlockValidationError::TransactionsRootMismatch {
            expected: *header.transactions_root.as_bytes(),
            computed: computed_tx_root,
        });
    }

    // 4. Extension root
    let ext_fields: Vec<(&[u8], &[u8])> = extension
        .fields
        .iter()
        .map(|f| (f.key.as_slice(), f.value.as_slice()))
        .collect();
    let computed_ext_root = extension_root(&ext_fields);
    if computed_ext_root != *header.extension_root.as_bytes() {
        return Err(BlockValidationError::ExtensionRootMismatch {
            expected: *header.extension_root.as_bytes(),
            computed: computed_ext_root,
        });
    }

    // 4a. Structural extension checks (rules 400, 404, 405, 406).
    // Runs AFTER the merkle-root recompute so an adversarial unbound
    // extension can't force the O(N²) duplicate scan as a DoS — the
    // root match cryptographically binds the extension to the header
    // before we walk its fields.
    validate_extension_structural(extension, header.height)?;

    // 4a.5. Interlink validation (rules 401, 402). Skipped when the
    // parent extension isn't on the context — that's Scala's
    // `exIlUnableToValidate` recoverable path. Production callers
    // wire `parent_extension` from the store for the consensus-path
    // enforcement; pre-NiPoPoW or genesis paths pass `None`.
    if let Some(parent_ext) = ctx.parent_extension {
        validate_interlinks(extension, ctx.parent.header(), parent_ext)?;
    }

    // 4b. Block-transactions section size (rule 306).
    // Same defensive ordering as 4a: runs AFTER the transactions
    // root recompute so an unbound oversized payload can't force
    // the re-serialize work as a DoS vector. Mirrors Scala's order
    // at `ErgoStateContext.appendFullBlock:308-310` (extension
    // validation → block-tx-size → ex-size).
    check_block_transactions_size(
        block_transactions,
        header.version,
        ctx.params.max_block_size,
    )?;

    // 5. Per-tx validation with intra-block UTXO overlay
    // Extract raw headers for the tx validation layer (which takes &[Header]).
    let raw_last_headers: Vec<Header> = ctx
        .last_headers
        .iter()
        .map(|ch| ch.header().clone())
        .collect();
    let tx_ctx = TransactionContext {
        height: header.height,
        miner_pubkey: *header.solution.pk().as_bytes(),
        pre_header_timestamp: header.timestamp,
        activated_script_version: header.version.saturating_sub(1),
        pre_header_version: header.version,
        pre_header_parent_id: *header.parent_id.as_bytes(),
        pre_header_n_bits: header.n_bits as u64,
        pre_header_votes: header.votes,
    };

    let mut overlay = BlockUtxoOverlay::new(ctx.utxo);
    let mut checked_txs = Vec::with_capacity(txs.len());
    let mut total_block_cost: u64 = 0;

    for (i, tx) in txs.iter().enumerate() {
        let tx_bytes = {
            let mut w = ergo_primitives::writer::VlqWriter::new();
            ergo_ser::transaction::write_transaction(&mut w, tx).map_err(|e| {
                BlockValidationError::Transaction {
                    index: i,
                    error: ValidationError::Deserialization(e.to_string()),
                }
            })?;
            w.result()
        };

        // Resolve inputs from overlay (respects intra-block spending)
        let resolved_inputs: Vec<ErgoBox> = tx
            .inputs
            .iter()
            .map(|inp| {
                overlay
                    .get_box(&inp.box_id)
                    .ok_or_else(|| BlockValidationError::Transaction {
                        index: i,
                        error: ValidationError::InputBoxNotFound {
                            box_id: hex::encode(inp.box_id.as_bytes()),
                        },
                    })
            })
            .collect::<Result<_, _>>()?;

        // Resolve data inputs through `BlockUtxoOverlay::get_box_from_base`,
        // which returns the union of pre-block UTXO + intra-block creates
        // without filtering on `spent_in_block`. See the helper's rustdoc
        // for the mainnet oracle evidence (blocks 290684 + 422179).
        let resolved_data_inputs: Vec<ErgoBox> = tx
            .data_inputs
            .iter()
            .map(|di| {
                overlay.get_box_from_base(&di.box_id).ok_or_else(|| {
                    BlockValidationError::Transaction {
                        index: i,
                        error: ValidationError::DataInputBoxNotFound {
                            box_id: hex::encode(di.box_id.as_bytes()),
                        },
                    }
                })
            })
            .collect::<Result<_, _>>()?;

        let block_cap = JitCost::from_block_cost(ctx.params.max_block_cost).map_err(|e| {
            BlockValidationError::Transaction {
                index: i,
                error: ValidationError::JitCostOverflow(e.to_string()),
            }
        })?;
        let mut cost = CostAccumulator::new(block_cap);

        let mut tx_cx = crate::tx::TxValidationCtx {
            ctx: &tx_ctx,
            params: ctx.params,
            cost: &mut cost,
            last_headers: &raw_last_headers,
        };
        let checked = validate_transaction_parsed(
            tx.clone(),
            &tx_bytes,
            resolved_inputs,
            resolved_data_inputs,
            skip_scripts,
            &mut tx_cx,
        )
        .map_err(|e| BlockValidationError::Transaction { index: i, error: e })?;

        total_block_cost += cost.total_block_cost();
        overlay.apply_tx(checked.transaction());
        checked_txs.push(checked);
    }

    if total_block_cost > ctx.params.max_block_cost {
        return Err(BlockValidationError::BlockCostExceeded {
            total: total_block_cost,
            limit: ctx.params.max_block_cost,
        });
    }

    Ok(CheckedBlock {
        checked_header,
        checked_transactions: checked_txs,
    })
}

/// Parallel equivalent of [`validate_full_block`]: topologically layers the
/// block's transactions by intra-block dependency, then validates each layer
/// via `rayon::par_iter`. Identical output to the sequential path for any
/// block the sequential path accepts (and for every rejection — first-failing
/// tx by index wins, matching Scala's error-order semantics).
///
/// Consensus invariants held constant across both paths:
/// - Per-tx structural / monetary / script validation is untouched — same
///   `validate_transaction_parsed` call, same `CostAccumulator`, same
///   `TransactionContext`.
/// - Section-id linkage + merkle-root checks are performed identically and
///   up-front, before any per-tx work.
/// - Total block cost is summed from per-tx totals after all layers finish;
///   `max_block_cost` comparison is the exact same inequality.
/// - Returned `CheckedBlock.transactions()` is ordered by original tx index,
///   so downstream AVL application mutates the UTXO tree in consensus order.
/// - Intra-block double-spend (two txs listing the same input box_id) is
///   rejected up front via `build_tx_layers` rather than being caught
///   implicitly by the sequential overlay's spent-set.
///
/// Only difference visible to callers: errors report the first-by-index
/// failing tx, which matches sequential behavior. If two txs in the same
/// layer fail concurrently, the lower tx index is reported (deterministic).
fn validate_full_block_parallel_impl(
    checked_header: CheckedHeader,
    block_transactions: &BlockTransactions,
    extension: &Extension,
    ctx: &BlockValidationContext<'_>,
    mut costs_out: Option<&mut Vec<(usize, u64)>>,
) -> Result<CheckedBlock, BlockValidationError> {
    let header = checked_header.header();
    let header_id = checked_header.header_id();

    // Checkpoint enforcement — see validate_full_block for invariant doc.
    let skip_scripts = match ctx.script_validation_checkpoint {
        Some((ckpt_h, ckpt_id)) => {
            if header.height == ckpt_h && header_id != &ckpt_id {
                return Err(BlockValidationError::CheckpointMismatch {
                    height: ckpt_h,
                    expected: ckpt_id,
                    got: *header_id,
                });
            }
            header.height <= ckpt_h
        }
        None => false,
    };

    // Section linkage + merkle roots — identical to sequential path.
    // Kept inline rather than factored so the sequential path is not
    // coupled to the parallel path's later structure.
    if block_transactions.header_id.as_bytes() != header_id {
        return Err(BlockValidationError::SectionIdMismatch {
            section: "BlockTransactions",
            expected: *header_id,
            got: *block_transactions.header_id.as_bytes(),
        });
    }
    if extension.header_id.as_bytes() != header_id {
        return Err(BlockValidationError::SectionIdMismatch {
            section: "Extension",
            expected: *header_id,
            got: *extension.header_id.as_bytes(),
        });
    }

    // 2.5. Header vote-known check (Scala rule 215). Same step as
    // sequential `validate_full_block`; keep both paths in sync. Skipped
    // when an activated soft-fork disabled the rule.
    crate::header::check_votes_known_active(
        header,
        ctx.voting_length,
        ctx.votes_unknown_rule_disabled,
    )
    .map_err(BlockValidationError::Header)?;

    // 2.6. Fork-vote prohibited-window check (Scala rule 407).
    // Mirror of sequential step 2.6.
    validate_fork_vote(header, ctx.soft_fork_state.as_ref())?;

    let txs = &block_transactions.transactions;
    let mut tx_ids: Vec<Vec<u8>> = Vec::with_capacity(txs.len());
    for (i, tx) in txs.iter().enumerate() {
        let bts = ergo_ser::transaction::bytes_to_sign(tx).map_err(|e| {
            BlockValidationError::Transaction {
                index: i,
                error: ValidationError::Deserialization(format!("bytes_to_sign: {e}")),
            }
        })?;
        tx_ids.push(ergo_crypto::autolykos::common::blake2b256(&bts).to_vec());
    }
    let tx_id_refs: Vec<&[u8]> = tx_ids.iter().map(|id| id.as_slice()).collect();

    let witness_data: Vec<Vec<u8>>;
    let witness_refs: Option<Vec<&[u8]>>;
    if header.version >= 2 {
        witness_data = txs
            .iter()
            .map(|tx| {
                let mut all_proofs = Vec::new();
                for input in &tx.inputs {
                    all_proofs.extend_from_slice(&input.spending_proof.proof);
                }
                let hash = ergo_crypto::autolykos::common::blake2b256(&all_proofs);
                hash[1..].to_vec()
            })
            .collect();
        let refs: Vec<&[u8]> = witness_data.iter().map(|w| w.as_slice()).collect();
        witness_refs = Some(refs);
    } else {
        witness_refs = None;
    }

    let computed_tx_root = transactions_root(&tx_id_refs, witness_refs.as_deref());
    if computed_tx_root != *header.transactions_root.as_bytes() {
        return Err(BlockValidationError::TransactionsRootMismatch {
            expected: *header.transactions_root.as_bytes(),
            computed: computed_tx_root,
        });
    }

    let ext_fields: Vec<(&[u8], &[u8])> = extension
        .fields
        .iter()
        .map(|f| (f.key.as_slice(), f.value.as_slice()))
        .collect();
    let computed_ext_root = extension_root(&ext_fields);
    if computed_ext_root != *header.extension_root.as_bytes() {
        return Err(BlockValidationError::ExtensionRootMismatch {
            expected: *header.extension_root.as_bytes(),
            computed: computed_ext_root,
        });
    }

    // 4a. Structural extension checks (rules 400/404/405/406) +
    // 4a.5. interlink validation (rules 401/402) +
    // 4b. block-transactions section size (rule 306).
    // Mirrors the sequential path's steps 4a/4a.5/4b; both must run
    // here too because production routes can switch between the
    // sequential and parallel impls at any height. Same defensive
    // post-merkle ordering: the root match has cryptographically
    // bound the bytes to the header, so an unbound adversarial
    // payload can't trip the O(N²) duplicate scan / re-serialize
    // walks as a DoS vector.
    validate_extension_structural(extension, header.height)?;
    if let Some(parent_ext) = ctx.parent_extension {
        validate_interlinks(extension, ctx.parent.header(), parent_ext)?;
    }
    check_block_transactions_size(
        block_transactions,
        header.version,
        ctx.params.max_block_size,
    )?;

    // Layered parallel tx validation
    let layering = build_tx_layers(txs)?;

    let raw_last_headers: Vec<ergo_ser::header::Header> = ctx
        .last_headers
        .iter()
        .map(|ch| ch.header().clone())
        .collect();
    let tx_ctx = TransactionContext {
        height: header.height,
        miner_pubkey: *header.solution.pk().as_bytes(),
        pre_header_timestamp: header.timestamp,
        activated_script_version: header.version.saturating_sub(1),
        pre_header_version: header.version,
        pre_header_parent_id: *header.parent_id.as_bytes(),
        pre_header_n_bits: header.n_bits as u64,
        pre_header_votes: header.votes,
    };

    let mut overlay = BlockUtxoOverlay::new(ctx.utxo);
    let mut checked_slots: Vec<Option<CheckedTransaction>> = (0..txs.len()).map(|_| None).collect();
    let mut total_block_cost: u64 = 0;

    for layer in &layering.layers {
        // Step 1: resolve inputs + serialize tx_bytes serially. The overlay
        // is mutated between layers, so its lookup must stay single-threaded.
        // Only the CPU-heavy validation (structural/monetary/script eval)
        // is dispatched to rayon.
        let mut per_tx_inputs: Vec<TxLayerInput> = Vec::with_capacity(layer.len());
        for &i in layer {
            let tx = &txs[i];
            let tx_bytes = {
                let mut w = ergo_primitives::writer::VlqWriter::new();
                ergo_ser::transaction::write_transaction(&mut w, tx).map_err(|e| {
                    BlockValidationError::Transaction {
                        index: i,
                        error: ValidationError::Deserialization(e.to_string()),
                    }
                })?;
                w.result()
            };
            let resolved_inputs: Vec<ErgoBox> = tx
                .inputs
                .iter()
                .map(|inp| {
                    overlay
                        .get_box(&inp.box_id)
                        .ok_or_else(|| BlockValidationError::Transaction {
                            index: i,
                            error: ValidationError::InputBoxNotFound {
                                box_id: hex::encode(inp.box_id.as_bytes()),
                            },
                        })
                })
                .collect::<Result<_, _>>()?;
            let resolved_data_inputs: Vec<ErgoBox> = tx
                .data_inputs
                .iter()
                .map(|di| {
                    overlay.get_box_from_base(&di.box_id).ok_or_else(|| {
                        BlockValidationError::Transaction {
                            index: i,
                            error: ValidationError::DataInputBoxNotFound {
                                box_id: hex::encode(di.box_id.as_bytes()),
                            },
                        }
                    })
                })
                .collect::<Result<_, _>>()?;
            per_tx_inputs.push((i, tx_bytes, resolved_inputs, resolved_data_inputs));
        }

        // Step 2: validate_transaction_parsed in parallel. Each closure owns
        // its inputs and runs independently — they cannot reach each other's
        // state. Per-tx CostAccumulator stays local and is folded post-join.
        let max_block_cost = ctx.params.max_block_cost;
        let params = ctx.params;
        let raw_headers_ref = &raw_last_headers;
        let tx_ctx_ref = &tx_ctx;
        let layer_results: Vec<TxLayerResult> = per_tx_inputs
            .into_par_iter()
            .map(|(i, tx_bytes, inputs, data_inputs)| {
                let block_cap = match JitCost::from_block_cost(max_block_cost) {
                    Ok(c) => c,
                    Err(e) => return (i, Err(ValidationError::JitCostOverflow(e.to_string()))),
                };
                let mut cost = CostAccumulator::new(block_cap);
                let mut tx_cx = crate::tx::TxValidationCtx {
                    ctx: tx_ctx_ref,
                    params,
                    cost: &mut cost,
                    last_headers: raw_headers_ref,
                };
                let result = validate_transaction_parsed(
                    txs[i].clone(),
                    &tx_bytes,
                    inputs,
                    data_inputs,
                    skip_scripts,
                    &mut tx_cx,
                );
                match result {
                    Ok(checked) => (i, Ok((checked, cost.total_block_cost()))),
                    Err(e) => (i, Err(e)),
                }
            })
            .collect();

        // Step 3: deterministic error ordering + commit. Layer members
        // are already sorted ascending by tx index in `build_tx_layers`,
        // and par_iter preserves input order in collect, so iterating
        // `layer_results` is ascending. First Err wins — matches the
        // sequential path's early-return on first failing tx (Scala
        // parity). The owned `ValidationError` is taken directly from
        // the parallel result, not reconstructed by re-running the
        // failing tx through a second validator instance.
        let mut successes: Vec<(usize, CheckedTransaction, u64)> =
            Vec::with_capacity(layer_results.len());
        for (i, outcome) in layer_results {
            match outcome {
                Ok((checked, cost)) => successes.push((i, checked, cost)),
                Err(error) => {
                    return Err(BlockValidationError::Transaction { index: i, error });
                }
            }
        }

        // Step 4: commit successful layer results. Overlay.apply_tx is
        // deterministic — applied in ascending tx index, matching the
        // sequential path's commit order.
        for (i, checked, tx_cost) in successes {
            total_block_cost += tx_cost;
            overlay.apply_tx(checked.transaction());
            checked_slots[i] = Some(checked);
            if let Some(ref mut v) = costs_out {
                v.push((i, tx_cost));
            }
        }
    }

    if total_block_cost > ctx.params.max_block_cost {
        return Err(BlockValidationError::BlockCostExceeded {
            total: total_block_cost,
            limit: ctx.params.max_block_cost,
        });
    }

    let checked_txs: Vec<CheckedTransaction> = checked_slots
        .into_iter()
        .map(|opt| {
            opt.expect("every tx index must have a validated slot after successful layering")
        })
        .collect();

    Ok(CheckedBlock {
        checked_header,
        checked_transactions: checked_txs,
    })
}

/// Parallel variant of [`validate_full_block`]. Per-transaction
/// validation runs across rayon worker threads after the structural
/// (root / linkage / layering) checks have passed; output is the same
/// [`CheckedBlock`] type, so callers can use either entry point
/// interchangeably.
pub fn validate_full_block_parallel(
    checked_header: CheckedHeader,
    block_transactions: &BlockTransactions,
    extension: &Extension,
    ctx: &BlockValidationContext<'_>,
) -> Result<CheckedBlock, BlockValidationError> {
    validate_full_block_parallel_impl(checked_header, block_transactions, extension, ctx, None)
}

/// Parallel full-block validation returning per-tx costs indexed by tx
/// position. Only available under `test-helpers` for differential testing.
#[cfg(feature = "test-helpers")]
pub fn validate_full_block_parallel_with_costs(
    checked_header: CheckedHeader,
    block_transactions: &BlockTransactions,
    extension: &Extension,
    ctx: &BlockValidationContext<'_>,
) -> Result<(CheckedBlock, Vec<(usize, u64)>), BlockValidationError> {
    let mut costs = Vec::new();
    validate_full_block_parallel_impl(
        checked_header,
        block_transactions,
        extension,
        ctx,
        Some(&mut costs),
    )
    .map(|block| (block, costs))
}

#[cfg(test)]
mod layering_tests {
    use super::*;
    use ergo_ser::ergo_box::ErgoBoxCandidate;
    use ergo_ser::ergo_tree::ErgoTree;
    use ergo_ser::input::{ContextExtension, DataInput, Input, SpendingProof};
    use ergo_ser::opcode::Expr;
    use ergo_ser::register::AdditionalRegisters;
    use ergo_ser::sigma_type::SigmaType;
    use ergo_ser::sigma_value::SigmaValue;

    fn simple_tree() -> ErgoTree {
        ErgoTree {
            version: 0,
            has_size: true,
            constant_segregation: true,
            constants: vec![(SigmaType::SBoolean, SigmaValue::Boolean(true))],
            body: Expr::Const {
                tpe: SigmaType::SBoolean,
                val: SigmaValue::Boolean(true),
            },
        }
    }

    fn make_candidate(value: u64) -> ErgoBoxCandidate {
        ErgoBoxCandidate::new(
            value,
            simple_tree(),
            100,
            vec![],
            AdditionalRegisters::empty(),
        )
        .unwrap()
    }

    fn input_of(box_id: Digest32) -> Input {
        Input {
            box_id,
            spending_proof: SpendingProof::new(vec![], ContextExtension::empty()).unwrap(),
        }
    }

    fn input_filled(fill: u8) -> Input {
        input_of(Digest32::from_bytes([fill; 32]))
    }

    fn tx_with(inputs: Vec<Input>, data_inputs: Vec<DataInput>, outputs: usize) -> Transaction {
        Transaction {
            inputs,
            data_inputs,
            output_candidates: (0..outputs)
                .map(|_| make_candidate(1_000_000_000))
                .collect(),
        }
    }

    fn first_output_box_id(tx: &Transaction) -> Digest32 {
        let tx_id = ergo_ser::transaction::transaction_id(tx).unwrap();
        let ergo_box = ErgoBox {
            candidate: tx.output_candidates[0].clone(),
            transaction_id: tx_id,
            index: 0,
        };
        ergo_box.box_id().unwrap()
    }

    #[test]
    fn empty_block_has_no_layers() {
        let layers = build_tx_layers(&[]).unwrap();
        // Empty input → Vec::new max → 0, so we allocate one empty layer.
        // Consumers iterate layers, so one empty layer is indistinguishable from zero.
        assert_eq!(layers.tx_count(), 0);
    }

    #[test]
    fn independent_txs_all_in_layer_0() {
        // Three txs, each spending distinct pre-block boxes. No intra-block deps.
        let txs = vec![
            tx_with(vec![input_filled(1)], vec![], 1),
            tx_with(vec![input_filled(2)], vec![], 1),
            tx_with(vec![input_filled(3)], vec![], 1),
        ];
        let layers = build_tx_layers(&txs).unwrap();
        assert_eq!(layers.layer_count(), 1, "no deps → single layer");
        assert_eq!(layers.layers[0], vec![0, 1, 2]);
    }

    #[test]
    fn linear_chain_builds_deep_layering() {
        // tx0 spends pre-block box. tx1 spends tx0's output. tx2 spends tx1's output.
        let tx0 = tx_with(vec![input_filled(1)], vec![], 1);
        let tx0_out = first_output_box_id(&tx0);
        let tx1 = tx_with(vec![input_of(tx0_out)], vec![], 1);
        let tx1_out = first_output_box_id(&tx1);
        let tx2 = tx_with(vec![input_of(tx1_out)], vec![], 1);

        let layers = build_tx_layers(&[tx0, tx1, tx2]).unwrap();
        assert_eq!(layers.layer_count(), 3, "chain length 3 → three layers");
        assert_eq!(layers.layers[0], vec![0]);
        assert_eq!(layers.layers[1], vec![1]);
        assert_eq!(layers.layers[2], vec![2]);
    }

    #[test]
    fn data_input_creates_dependency() {
        // tx0 creates an output, tx1 READS it as a data input — still a dep.
        let tx0 = tx_with(vec![input_filled(1)], vec![], 1);
        let tx0_out = first_output_box_id(&tx0);
        let tx1 = tx_with(
            vec![input_filled(2)],
            vec![DataInput { box_id: tx0_out }],
            1,
        );
        let layers = build_tx_layers(&[tx0, tx1]).unwrap();
        assert_eq!(layers.layer_count(), 2);
        assert_eq!(layers.layers[0], vec![0]);
        assert_eq!(layers.layers[1], vec![1]);
    }

    #[test]
    fn fan_out_single_layer_of_children() {
        // tx0 has two outputs; tx1 and tx2 each spend one. tx1 and tx2 are
        // siblings of each other → both at layer 1, not serialized.
        let tx0 = tx_with(vec![input_filled(1)], vec![], 2);
        let tx_id = ergo_ser::transaction::transaction_id(&tx0).unwrap();
        let out0 = ErgoBox {
            candidate: tx0.output_candidates[0].clone(),
            transaction_id: tx_id,
            index: 0,
        }
        .box_id()
        .unwrap();
        let out1 = ErgoBox {
            candidate: tx0.output_candidates[1].clone(),
            transaction_id: tx_id,
            index: 1,
        }
        .box_id()
        .unwrap();
        let tx1 = tx_with(vec![input_of(out0)], vec![], 1);
        let tx2 = tx_with(vec![input_of(out1)], vec![], 1);

        let layers = build_tx_layers(&[tx0, tx1, tx2]).unwrap();
        assert_eq!(layers.layer_count(), 2);
        assert_eq!(layers.layers[0], vec![0]);
        assert_eq!(
            layers.layers[1],
            vec![1, 2],
            "fan-out children share a layer"
        );
    }

    #[test]
    fn fan_in_uses_max_parent_layer() {
        // tx0, tx1 are independent at layer 0. tx2 spends outputs of both.
        let tx0 = tx_with(vec![input_filled(1)], vec![], 1);
        let tx1 = tx_with(vec![input_filled(2)], vec![], 1);
        let out0 = first_output_box_id(&tx0);
        let out1 = first_output_box_id(&tx1);
        let tx2 = tx_with(vec![input_of(out0), input_of(out1)], vec![], 1);

        let layers = build_tx_layers(&[tx0, tx1, tx2]).unwrap();
        assert_eq!(layers.layer_count(), 2);
        assert_eq!(layers.layers[0], vec![0, 1]);
        assert_eq!(layers.layers[1], vec![2]);
    }

    #[test]
    fn intra_block_double_spend_rejected() {
        // tx0 and tx1 both try to consume the same pre-block box — must reject
        // BEFORE parallel dispatch; sequential overlay's implicit catch is
        // not available when both see the pre-block UTXO snapshot.
        let shared = Digest32::from_bytes([7u8; 32]);
        let tx0 = tx_with(vec![input_of(shared)], vec![], 1);
        let tx1 = tx_with(vec![input_of(shared)], vec![], 1);
        let err = build_tx_layers(&[tx0, tx1]).unwrap_err();
        match err {
            BlockValidationError::DoubleSpendInBlock { first, second, .. } => {
                assert_eq!((first, second), (0, 1));
            }
            other => panic!("expected DoubleSpendInBlock, got {other:?}"),
        }
    }

    /// Test-only `UtxoView` that exposes a single fixed box.
    struct OneBoxUtxo {
        id: Digest32,
        b: ErgoBox,
    }

    impl UtxoView for OneBoxUtxo {
        fn get_box(&self, box_id: &Digest32) -> Option<ErgoBox> {
            if *box_id == self.id {
                Some(self.b.clone())
            } else {
                None
            }
        }
    }

    /// Data-input resolution sees pre-block UTXO ∪ in-block creates,
    /// ignoring intra-block spends.
    ///
    /// Mainnet oracle evidence pinned here:
    /// - Block 290684 — data input to a box SPENT earlier in the same
    ///   block resolves through the pre-block base (we don't filter
    ///   `spent_in_block`).
    /// - Block 422179 — data input to a box CREATED earlier in the
    ///   same block resolves through `in_block_outputs`.
    ///
    /// Complements `data_input_creates_dependency` (the scheduling
    /// edge) with the lookup contract the schedule is defending.
    #[test]
    fn data_input_resolution_unions_preblock_with_inblock_creates() {
        let pre_block_id = Digest32::from_bytes([1u8; 32]);
        let pre_block_box = ErgoBox {
            candidate: make_candidate(1_000_000_000),
            transaction_id: ergo_primitives::digest::ModifierId::from_bytes([0u8; 32]),
            index: 0,
        };
        let base = OneBoxUtxo {
            id: pre_block_id,
            b: pre_block_box.clone(),
        };

        let mut overlay = BlockUtxoOverlay::new(&base);

        // Apply a tx that spends the pre-block box and creates a new one.
        let creator = tx_with(vec![input_of(pre_block_id)], vec![], 1);
        let created_id = first_output_box_id(&creator);
        overlay.apply_tx(&creator);

        // Spending-input view (UtxoView::get_box) respects in-block changes:
        //   - pre-block id is now spent_in_block → None
        //   - newly-created id is in in_block_outputs → Some
        assert!(
            overlay.get_box(&pre_block_id).is_none(),
            "spending view must hide a box spent earlier in the block"
        );
        assert!(
            overlay.get_box(&created_id).is_some(),
            "spending view must surface an in-block-created box for the next tx"
        );

        // Data-input view (get_box_from_base) is the union of pre-block
        // UTXO + in-block creates, with no spent_in_block filter:
        //   - pre-block id still resolves even though it's spent_in_block
        //     (mainnet block 290684)
        //   - newly-created id resolves via in_block_outputs
        //     (mainnet block 422179, tx 2 data input on settlementHeight=422179 box)
        assert!(
            overlay.get_box_from_base(&pre_block_id).is_some(),
            "data-input view must surface a box that pre-block UTXO has, \
             even after intra-block spend (block 290684 parity)"
        );
        assert!(
            overlay.get_box_from_base(&created_id).is_some(),
            "data-input view must surface in-block-created outputs \
             (block 422179 parity: tx 2 data-inputs a box with settlementHeight=422179)"
        );
    }
}

#[cfg(test)]
mod extension_structural_tests {
    //! Tests for `validate_extension_structural` (rules 400, 404, 405, 406).
    use super::*;
    use ergo_primitives::digest::ModifierId;
    use ergo_ser::extension::{Extension, ExtensionField};

    fn ext(header_id: [u8; 32], fields: Vec<ExtensionField>) -> Extension {
        Extension {
            header_id: ModifierId::from_bytes(header_id),
            fields,
        }
    }

    fn field(key: [u8; 2], value: Vec<u8>) -> ExtensionField {
        ExtensionField { key, value }
    }

    // ----- rule 406: exEmpty -----

    #[test]
    fn empty_extension_on_genesis_height_is_allowed() {
        let e = ext([0; 32], Vec::new());
        assert!(validate_extension_structural(&e, 0).is_ok());
    }

    #[test]
    fn empty_extension_on_non_genesis_height_is_rejected() {
        let e = ext([0; 32], Vec::new());
        let err = validate_extension_structural(&e, 1).unwrap_err();
        assert!(matches!(
            err,
            BlockValidationError::ExtensionEmptyOnNonGenesis { height: 1 }
        ));
    }

    // ----- rule 400: exSize -----

    #[test]
    fn extension_under_size_cap_passes() {
        let e = ext([0; 32], vec![field([0x00, 0x01], vec![0xAA; 32])]);
        assert!(validate_extension_structural(&e, 1).is_ok());
    }

    #[test]
    fn extension_over_size_cap_is_rejected() {
        // Construct an extension that overflows the 32 KiB cap.
        // Each entry contributes 2+1+value_len bytes; the count
        // prefix adds 2. With value_len = 60 (under the 404 cap),
        // each field is 63 wire bytes — so 600 fields yield 37+ KB.
        let fields: Vec<ExtensionField> = (0u16..600)
            .map(|i| field([(i >> 8) as u8, i as u8], vec![0xCC; 60]))
            .collect();
        let e = ext([0; 32], fields);
        let err = validate_extension_structural(&e, 1).unwrap_err();
        match err {
            BlockValidationError::ExtensionTooLarge { size, max } => {
                assert_eq!(max, MAX_EXTENSION_SIZE);
                assert!(
                    size > MAX_EXTENSION_SIZE,
                    "fixture must actually exceed cap, got size={size}",
                );
            }
            other => panic!("expected ExtensionTooLarge, got {other:?}"),
        }
    }

    // ----- rule 404: exValueLength -----

    #[test]
    fn field_value_at_cap_passes() {
        let e = ext(
            [0; 32],
            vec![field(
                [0x00, 0x01],
                vec![0xAA; EXTENSION_FIELD_VALUE_MAX_SIZE],
            )],
        );
        assert!(validate_extension_structural(&e, 1).is_ok());
    }

    #[test]
    fn field_value_one_byte_over_cap_is_rejected() {
        let e = ext(
            [0; 32],
            vec![
                field([0x00, 0x01], vec![0xAA; 32]),
                field([0x00, 0x02], vec![0xBB; EXTENSION_FIELD_VALUE_MAX_SIZE + 1]),
            ],
        );
        let err = validate_extension_structural(&e, 1).unwrap_err();
        match err {
            BlockValidationError::ExtensionFieldValueTooLong { index, len, max } => {
                assert_eq!(index, 1);
                assert_eq!(len, EXTENSION_FIELD_VALUE_MAX_SIZE + 1);
                assert_eq!(max, EXTENSION_FIELD_VALUE_MAX_SIZE);
            }
            other => panic!("expected ExtensionFieldValueTooLong, got {other:?}"),
        }
    }

    // ----- rule 405: exDuplicateKeys -----

    #[test]
    fn distinct_keys_pass() {
        let e = ext(
            [0; 32],
            vec![
                field([0x00, 0x01], vec![0xAA]),
                field([0x00, 0x02], vec![0xBB]),
                field([0x00, 0x03], vec![0xCC]),
            ],
        );
        assert!(validate_extension_structural(&e, 1).is_ok());
    }

    #[test]
    fn duplicate_key_is_rejected() {
        let e = ext(
            [0; 32],
            vec![
                field([0x00, 0x01], vec![0xAA]),
                field([0x00, 0x02], vec![0xBB]),
                field([0x00, 0x01], vec![0xCC]), // duplicate of first
            ],
        );
        let err = validate_extension_structural(&e, 1).unwrap_err();
        match err {
            BlockValidationError::ExtensionDuplicateKey { key, first, second } => {
                assert_eq!(key, "0001");
                assert_eq!(first, 0);
                assert_eq!(second, 2);
            }
            other => panic!("expected ExtensionDuplicateKey, got {other:?}"),
        }
    }

    // ----- serialized_extension_size sanity -----

    #[test]
    fn serialized_extension_size_matches_write_extension_round_trip() {
        // The size helper must agree with the actual writer
        // byte-count. Walk a few cardinalities (0, 1, 127, 128,
        // 1000) so the VLQ count-prefix size changes are exercised.
        use ergo_primitives::writer::VlqWriter;
        for n in [0u16, 1, 127, 128, 1000] {
            let fields: Vec<ExtensionField> = (0..n)
                .map(|i| field([(i >> 8) as u8, i as u8], vec![0xAA; 4]))
                .collect();
            let e = ext([0xCC; 32], fields);
            let computed = serialized_extension_size(&e);
            let mut w = VlqWriter::new();
            ergo_ser::extension::write_extension(&mut w, &e).unwrap();
            let actual = w.result().len();
            assert_eq!(
                computed, actual,
                "size helper drift at n={n}: computed={computed}, actual={actual}",
            );
        }
    }

    #[test]
    fn serialized_extension_size_includes_header_id() {
        // Sanity: even an empty extension consumes 32 (header_id)
        // + 1 (VLQ-encoded count=0) = 33 bytes on the wire. An
        // earlier bug used 2 for the count and dropped the
        // header_id entirely, returning 2.
        let e = ext([0; 32], Vec::new());
        assert_eq!(serialized_extension_size(&e), 33);
    }
}

/// Rule 306 (`bsBlockTransactionsSize`) tests.
#[cfg(test)]
mod block_transactions_size_tests {
    use super::*;
    use ergo_primitives::digest::{Digest32, ModifierId};
    use ergo_ser::ergo_box::ErgoBoxCandidate;
    use ergo_ser::ergo_tree::ErgoTree;
    use ergo_ser::input::{ContextExtension, Input, SpendingProof};
    use ergo_ser::opcode::Expr;
    use ergo_ser::register::AdditionalRegisters;
    use ergo_ser::sigma_type::SigmaType;
    use ergo_ser::sigma_value::SigmaValue;

    fn simple_tree() -> ErgoTree {
        ErgoTree {
            version: 0,
            has_size: true,
            constant_segregation: true,
            constants: vec![(SigmaType::SBoolean, SigmaValue::Boolean(true))],
            body: Expr::Const {
                tpe: SigmaType::SBoolean,
                val: SigmaValue::Boolean(true),
            },
        }
    }

    fn make_input(fill: u8) -> Input {
        Input {
            box_id: Digest32::from_bytes([fill; 32]),
            spending_proof: SpendingProof::new(vec![], ContextExtension::empty()).unwrap(),
        }
    }

    fn make_candidate(creation_height: u32) -> ErgoBoxCandidate {
        ErgoBoxCandidate::new(
            1_000_000_000_000,
            simple_tree(),
            creation_height,
            vec![],
            AdditionalRegisters::empty(),
        )
        .unwrap()
    }

    fn one_input_tx(input_fill: u8) -> Transaction {
        Transaction {
            inputs: vec![make_input(input_fill)],
            data_inputs: vec![],
            output_candidates: vec![make_candidate(100)],
        }
    }

    fn make_block_txs(n: usize) -> BlockTransactions {
        // Distinct `input_fill` per tx keeps tx ids distinct without
        // needing per-tx tree variation.
        let transactions: Vec<Transaction> =
            (0..n).map(|i| one_input_tx((i & 0xff) as u8)).collect();
        BlockTransactions {
            header_id: ModifierId::from_bytes([0xAA; 32]),
            transactions,
        }
    }

    fn serialized_size(bt: &BlockTransactions, version: u8) -> usize {
        let mut w = ergo_primitives::writer::VlqWriter::new();
        write_block_transactions_with_version(&mut w, bt, version).unwrap();
        w.result().len()
    }

    #[test]
    fn block_transactions_under_cap_passes() {
        // A single-tx block is far under any reasonable cap.
        let bt = make_block_txs(1);
        let size = serialized_size(&bt, 1);
        // Use mainnet default 524 KiB cap — single tx is well under.
        let max = ProtocolParams::mainnet_default().max_block_size;
        assert!(
            size < max as usize,
            "fixture size {size} must be under {max}"
        );
        check_block_transactions_size(&bt, 1, max).unwrap();
    }

    #[test]
    fn block_transactions_at_cap_passes() {
        // Cap = exact serialized size: the inequality is `<=`,
        // so equality must pass.
        let bt = make_block_txs(5);
        let size = serialized_size(&bt, 1);
        check_block_transactions_size(&bt, 1, size as u32).unwrap();
    }

    #[test]
    fn block_transactions_one_byte_over_cap_rejects() {
        // Set cap to actual_size - 1 and assert reject.
        let bt = make_block_txs(5);
        let size = serialized_size(&bt, 1);
        let cap = (size - 1) as u32;
        let err = check_block_transactions_size(&bt, 1, cap).unwrap_err();
        match err {
            BlockValidationError::BlockTransactionsTooLarge { size: s, max: m } => {
                assert_eq!(s, size);
                assert_eq!(m, cap);
            }
            other => panic!("expected BlockTransactionsTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn block_transactions_far_over_cap_rejects() {
        // Multi-tx block with an artificially tiny cap — exercises
        // the "obvious overlimit" path without needing huge fixtures.
        let bt = make_block_txs(10);
        let err = check_block_transactions_size(&bt, 1, 16).unwrap_err();
        assert!(matches!(
            err,
            BlockValidationError::BlockTransactionsTooLarge { .. }
        ));
    }

    #[test]
    fn block_transactions_size_version_aware() {
        // v1 and v2+ formats produce different byte lengths
        // (v2+ adds the version marker + per-section framing).
        // The check must measure with the supplied block_version,
        // not assume v1.
        let bt = make_block_txs(3);
        let v1_size = serialized_size(&bt, 1);
        let v2_size = serialized_size(&bt, 2);
        assert!(
            v2_size != v1_size,
            "v1 and v2 fixtures must produce different sizes \
             (got v1={v1_size}, v2={v2_size}) — otherwise this test \
             doesn't actually exercise version-awareness",
        );
        // Cap = v1 size, but pass version=2 → the rule must measure
        // v2 and reject because v2 size > v1 size (or accept if v2
        // happens to be smaller — for our 3-tx fixture v2 is larger).
        let cap_at_v1 = v1_size as u32;
        let result = check_block_transactions_size(&bt, 2, cap_at_v1);
        if v2_size > v1_size {
            assert!(matches!(
                result,
                Err(BlockValidationError::BlockTransactionsTooLarge { .. })
            ));
        } else {
            assert!(result.is_ok());
        }
    }
}

/// Rules 401 / 402 (`exIlEncoding` / `exIlStructure`) — interlink
/// validation against the parent extension.
#[cfg(test)]
mod interlinks_tests {
    use super::*;
    use crate::popow::algos::{update_interlinks, INTERLINKS_VECTOR_PREFIX};
    use ergo_primitives::digest::{ADDigest, Digest32, ModifierId};
    use ergo_primitives::group_element::GroupElement;
    use ergo_ser::autolykos::AutolykosSolution;
    use ergo_ser::extension::ExtensionField;

    fn test_header(height: u32, n_bits: u32) -> Header {
        Header {
            version: 2,
            parent_id: ModifierId::from_bytes([0; 32]),
            ad_proofs_root: Digest32::from_bytes([0; 32]),
            transactions_root: Digest32::from_bytes([0; 32]),
            state_root: ADDigest::from_bytes([0; 33]),
            timestamp: 0,
            extension_root: Digest32::from_bytes([0; 32]),
            n_bits,
            height,
            votes: [0; 3],
            unparsed_bytes: Vec::new(),
            solution: AutolykosSolution::V2 {
                pk: GroupElement::from_bytes([0x02; 33]),
                nonce: [0; 8],
            },
        }
    }

    /// Pack an interlinks vector into wire-form extension fields
    /// matching `unpack_interlinks` (RLE: first byte is the
    /// duplicate count of the following 32-byte id).
    fn interlinks_to_fields(links: &[ModifierId]) -> Vec<ExtensionField> {
        // Run-length encode consecutive duplicates.
        let mut out: Vec<ExtensionField> = Vec::new();
        let mut idx: u8 = 0;
        let mut i = 0;
        while i < links.len() {
            let mut run = 1usize;
            while i + run < links.len() && links[i + run] == links[i] && run < 255 {
                run += 1;
            }
            let mut value = Vec::with_capacity(33);
            value.push(run as u8);
            value.extend_from_slice(links[i].as_bytes());
            out.push(ExtensionField {
                key: [INTERLINKS_VECTOR_PREFIX, idx],
                value,
            });
            idx = idx.wrapping_add(1);
            i += run;
        }
        out
    }

    fn ext_with_links(header_id: [u8; 32], links: &[ModifierId]) -> Extension {
        Extension {
            header_id: ModifierId::from_bytes(header_id),
            fields: interlinks_to_fields(links),
        }
    }

    fn ext_with_fields(header_id: [u8; 32], fields: Vec<ExtensionField>) -> Extension {
        Extension {
            header_id: ModifierId::from_bytes(header_id),
            fields,
        }
    }

    #[test]
    fn validate_interlinks_passes_when_current_matches_updated_parent() {
        // Set up: parent header with some parent interlinks.
        // Current interlinks must equal update_interlinks(parent_header,
        // parent_links).
        let parent = test_header(10, 0x20000000);
        let parent_links = vec![
            ModifierId::from_bytes([0xAA; 32]),
            ModifierId::from_bytes([0xBB; 32]),
        ];
        let expected = update_interlinks(&parent, &parent_links)
            .expect("test fixture parent header serializes");

        let parent_ext = ext_with_links([0; 32], &parent_links);
        let current_ext = ext_with_links([1; 32], &expected);

        validate_interlinks(&current_ext, &parent, &parent_ext).unwrap();
    }

    #[test]
    fn validate_interlinks_rejects_structure_mismatch() {
        let parent = test_header(10, 0x20000000);
        let parent_links = vec![ModifierId::from_bytes([0xAA; 32])];
        let expected = update_interlinks(&parent, &parent_links)
            .expect("test fixture parent header serializes");

        let parent_ext = ext_with_links([0; 32], &parent_links);
        // Wrong: drop the last expected entry to force a mismatch.
        let mangled: Vec<ModifierId> = expected[..expected.len().saturating_sub(1)].to_vec();
        let current_ext = ext_with_links([1; 32], &mangled);

        let err = validate_interlinks(&current_ext, &parent, &parent_ext).unwrap_err();
        match err {
            BlockValidationError::InterlinkStructureMismatch {
                expected_len,
                got_len,
                reason,
            } => {
                assert_eq!(expected_len, expected.len());
                assert_eq!(got_len, mangled.len());
                assert_eq!(reason, "length mismatch");
            }
            other => panic!("expected InterlinkStructureMismatch, got {other:?}"),
        }
    }

    #[test]
    fn validate_interlinks_rejects_empty_parent_on_non_genesis_no_panic() {
        // Adversarial-input regression: parent extension has no
        // interlink fields, parent header is non-genesis. Before
        // the guard, this would hit `update_interlinks` `assert!`
        // and panic. Must surface as rule 402 with the named reason.
        let mut parent = test_header(10, 0x20000000);
        // Non-genesis: any non-zero parent_id byte breaks the
        // `parent_id == [0; 32]` test in `is_genesis`.
        parent.parent_id = ModifierId::from_bytes([0xFF; 32]);

        let parent_ext = ext_with_fields([0; 32], vec![]); // no interlink fields
        let current_ext = ext_with_links([1; 32], &[ModifierId::from_bytes([0xCC; 32])]);

        let err = validate_interlinks(&current_ext, &parent, &parent_ext).unwrap_err();
        match err {
            BlockValidationError::InterlinkStructureMismatch { reason, .. } => {
                assert!(
                    reason.contains("empty on non-genesis"),
                    "unexpected reason: {reason}",
                );
            }
            other => panic!("expected InterlinkStructureMismatch, got {other:?}"),
        }
    }

    #[test]
    fn validate_interlinks_rejects_encoding_failure() {
        // Current extension has an interlinks field whose value is
        // an invalid length (rule 401 — decode error).
        let parent = test_header(10, 0x20000000);
        let parent_links = vec![ModifierId::from_bytes([0xAA; 32])];
        let parent_ext = ext_with_links([0; 32], &parent_links);

        let bad_field = ExtensionField {
            key: [INTERLINKS_VECTOR_PREFIX, 0],
            value: vec![0x01, 0xCC], // 2 bytes, expected 33
        };
        let current_ext = ext_with_fields([1; 32], vec![bad_field]);

        let err = validate_interlinks(&current_ext, &parent, &parent_ext).unwrap_err();
        assert!(matches!(
            err,
            BlockValidationError::InvalidInterlinkEncoding { .. }
        ));
    }

    #[test]
    fn validate_interlinks_surfaces_structure_when_parent_decode_fails() {
        // Parent extension itself has malformed interlinks.
        // Scala's `Failure(...) == Failure(...)` is always false, so
        // rule 402 fires. We map that to InterlinkStructureMismatch.
        let parent = test_header(10, 0x20000000);
        let bad_parent_field = ExtensionField {
            key: [INTERLINKS_VECTOR_PREFIX, 0],
            value: vec![0x01], // 1 byte, expected 33
        };
        let parent_ext = ext_with_fields([0; 32], vec![bad_parent_field]);

        // Current has SOME valid links.
        let current_ext = ext_with_links([1; 32], &[ModifierId::from_bytes([0xCC; 32])]);

        let err = validate_interlinks(&current_ext, &parent, &parent_ext).unwrap_err();
        assert!(matches!(
            err,
            BlockValidationError::InterlinkStructureMismatch { .. }
        ));
    }

    #[test]
    fn fork_vote_no_state_passes_even_with_softfork_byte() {
        // No soft-fork in progress (ctx.soft_fork_state is None);
        // rule 407 is a trivial pass.
        let mut h = test_header(100, 0x20000000);
        h.votes = [120, 0, 0]; // SoftFork = 120
        validate_fork_vote(&h, None).unwrap();
    }

    // ---- rule 407: hostile 122-without-121 table (Scala checkForkVote .get) ----

    #[test]
    fn fork_vote_hostile_votes_collected_missing_rejects() {
        // Hostile parameter table: soft-fork START height present (id 121) but NO
        // votes-collected (id 122). Scala `checkForkVote` reads
        // `softForkVotesCollected.get` -> NoSuchElementException -> rule-407 reject,
        // when the header casts the SoftFork vote. Height-independent (the throw is
        // before the prohibited-window check).
        let mut h = test_header(2_000, 0x20000000);
        h.votes = [120, 0, 0];
        let err = check_fork_vote_votes_collected_present(&h, Some(100), None, false).unwrap_err();
        assert!(
            matches!(
                err,
                BlockValidationError::ForkVoteVotesCollectedMissing { height: 2_000 }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn fork_vote_votes_collected_missing_disabled_rule_passes() {
        // Rule 407 disabled by an activated settings update: Scala's
        // `validateNoThrow(exCheckForkVote, ...)` skips `checkForkVote` entirely,
        // so the hostile table is accepted even with the SoftFork vote.
        let mut h = test_header(2_000, 0x20000000);
        h.votes = [120, 0, 0];
        check_fork_vote_votes_collected_present(&h, Some(100), None, true).unwrap();
    }

    #[test]
    fn fork_vote_votes_collected_missing_without_softfork_vote_passes() {
        // Same hostile table but the header does NOT cast the SoftFork vote: Scala
        // only runs `checkForkVote` `if (forkVote)`, so no throw.
        let mut h = test_header(2_000, 0x20000000);
        h.votes = [0, 0, 0];
        check_fork_vote_votes_collected_present(&h, Some(100), None, false).unwrap();
    }

    #[test]
    fn fork_vote_no_starting_height_passes_even_missing_votes() {
        // No soft-fork start height (id 121 absent): `softForkStartingHeight.nonEmpty`
        // is false, so `checkForkVote` does nothing -> pass even with vote 120.
        let mut h = test_header(2_000, 0x20000000);
        h.votes = [120, 0, 0];
        check_fork_vote_votes_collected_present(&h, None, None, false).unwrap();
    }

    #[test]
    fn fork_vote_both_present_defers_to_window_check() {
        // (Some, Some) is well-formed: this guard passes (no `.get` throw); the
        // prohibited-window decision belongs to `validate_fork_vote`.
        let mut h = test_header(2_000, 0x20000000);
        h.votes = [120, 0, 0];
        check_fork_vote_votes_collected_present(&h, Some(100), Some(0), false).unwrap();
    }

    #[test]
    fn fork_vote_outside_window_passes() {
        let mut h = test_header(2_000, 0x20000000);
        h.votes = [120, 0, 0];
        let state = SoftForkState {
            starting_height: 100,
            votes_collected: 0,
            voting_length: 1024,
            soft_fork_epochs: 32,
            activation_epochs: 32,
            approved: false,
        };
        // finishing = 100 + 1024*32 = 32868
        // rejected window: 32868..(32868+1024) = 32868..33892
        // height 2_000 is well below window → pass
        validate_fork_vote(&h, Some(&state)).unwrap();
    }

    #[test]
    fn fork_vote_inside_rejected_window_rejects() {
        let state = SoftForkState {
            starting_height: 100,
            votes_collected: 0,
            voting_length: 1024,
            soft_fork_epochs: 32,
            activation_epochs: 32,
            approved: false, // rejected
        };
        let (lo, _hi) = state.prohibited_window();
        let mut h = test_header(lo + 10, 0x20000000);
        h.votes = [120, 0, 0];
        let err = validate_fork_vote(&h, Some(&state)).unwrap_err();
        match err {
            BlockValidationError::ForkVoteInProhibitedWindow {
                height,
                window_lo,
                window_hi,
            } => {
                assert_eq!(height, lo + 10);
                assert_eq!(window_lo, lo);
                // Rejected window: hi = lo + voting_length
                assert_eq!(window_hi, lo + 1024);
            }
            other => panic!("expected ForkVoteInProhibitedWindow, got {other:?}"),
        }
    }

    #[test]
    fn fork_vote_inside_approved_extended_window_rejects() {
        let state = SoftForkState {
            starting_height: 100,
            votes_collected: 100_000,
            voting_length: 1024,
            soft_fork_epochs: 32,
            activation_epochs: 32,
            approved: true,
        };
        let (lo, hi) = state.prohibited_window();
        // Approved window: hi = lo + voting_length * (activation_epochs + 1)
        // = lo + 1024 * 33
        assert_eq!(hi, lo + 1024 * 33);

        // Pick a height inside the extended window but outside the
        // rejected window (lo + voting_length + 1 onwards).
        let mut h = test_header(lo + 1024 + 5, 0x20000000);
        h.votes = [120, 0, 0];
        let err = validate_fork_vote(&h, Some(&state)).unwrap_err();
        assert!(matches!(
            err,
            BlockValidationError::ForkVoteInProhibitedWindow { .. }
        ));
    }

    #[test]
    fn fork_vote_at_window_upper_bound_passes_exclusive() {
        // window_hi is exclusive: a vote at exactly window_hi passes.
        let state = SoftForkState {
            starting_height: 100,
            votes_collected: 0,
            voting_length: 1024,
            soft_fork_epochs: 32,
            activation_epochs: 32,
            approved: false,
        };
        let (_lo, hi) = state.prohibited_window();
        let mut h = test_header(hi, 0x20000000);
        h.votes = [120, 0, 0];
        validate_fork_vote(&h, Some(&state)).unwrap();
    }

    #[test]
    fn fork_vote_inside_window_without_softfork_byte_passes() {
        // No SoftFork (120) in votes → check doesn't fire even
        // inside the window.
        let state = SoftForkState {
            starting_height: 100,
            votes_collected: 0,
            voting_length: 1024,
            soft_fork_epochs: 32,
            activation_epochs: 32,
            approved: false,
        };
        let (lo, _hi) = state.prohibited_window();
        let mut h = test_header(lo + 10, 0x20000000);
        h.votes = [3, 5, 0]; // not the soft-fork byte
        validate_fork_vote(&h, Some(&state)).unwrap();
    }

    #[test]
    fn fork_vote_window_arithmetic_saturates_on_extreme_starting_height() {
        // Adversarial starting_height near u32::MAX: window
        // calculation must saturate, not wrap.
        let state = SoftForkState {
            starting_height: u32::MAX - 1000,
            votes_collected: 0,
            voting_length: 1024,
            soft_fork_epochs: 32,
            activation_epochs: 32,
            approved: false,
        };
        let (lo, hi) = state.prohibited_window();
        assert_eq!(lo, u32::MAX); // saturated
        assert_eq!(hi, u32::MAX); // saturated
                                  // Empty window: header.height < u32::MAX is below `lo` so passes.
        let mut h = test_header(100, 0x20000000);
        h.votes = [120, 0, 0];
        validate_fork_vote(&h, Some(&state)).unwrap();
    }

    #[test]
    fn validate_interlinks_with_no_interlinks_in_either_extension() {
        // Both extensions carry zero interlink fields. Scala unpacks
        // each as `Success(Vec::empty())` and update_interlinks on a
        // non-genesis parent with empty prev would panic our impl —
        // but we never call update_interlinks here because the
        // parent isn't genesis. Pin behavior at the caller boundary:
        // this combination is what an early-NiPoPoW-disabled node
        // would have, and the check should treat it as
        // "current == expected" only when both are empty AND parent
        // is genesis. For non-genesis with empty interlinks, the
        // update_interlinks `require(prevInterlinks.nonEmpty)`
        // assertion fires — which is correct Scala behavior.
        //
        // Pin: this test only confirms the genesis case is graceful;
        // the assertion-on-empty-prev case is documented as caller
        // responsibility (Scala's `require` is the matching
        // behavior).
        let parent = test_header(0, 0x20000000); // genesis (height 0)
        let parent_ext = ext_with_fields([0; 32], vec![]);
        let expected =
            update_interlinks(&parent, &[]).expect("test fixture genesis header serializes");
        let current_ext = ext_with_links([1; 32], &expected);

        validate_interlinks(&current_ext, &parent, &parent_ext).unwrap();
    }
}
