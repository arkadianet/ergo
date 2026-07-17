use thiserror::Error;

use crate::error::ValidationError;
use crate::header::HeaderValidationError;

/// Failures raised by [`validate_full_block`](super::validate::validate_full_block) /
/// [`validate_full_block_parallel`](super::validate::validate_full_block_parallel).
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
    /// soft-fork *starting height* (`softForkStartingHeight`, id 122) but NO
    /// *votes-collected* entry (`softForkVotesCollected`, id 121). Scala
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
