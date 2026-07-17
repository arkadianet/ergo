//! Header validation: parent linkage, timestamp monotonicity, PoW,
//! difficulty, and the four vote rules (212-215).
//!
//! - [`votes`] — the four vote-rule checks (212/213/214/215), kept
//!   together deliberately: they are similar in shape and are
//!   cross-tested together via `selected_candidate_votes_always_pass_header_validators`.
//! - [`timestamp`] — parent-id / timestamp-monotonicity / future-timestamp
//!   checks (rule 211 + the two structural pre-checks).
//!
//! `CheckedHeader`, `HeaderValidationError`, `PowCheckedHeader`, and the
//! two `validate_header*` entry points stay here since they're the
//! module's public surface and don't belong to either submodule.

mod timestamp;
mod votes;

pub use timestamp::{
    check_future_timestamp, check_parent_id, check_timestamp, FUTURE_TIMESTAMP_DRIFT_MS,
};
pub use votes::{
    check_votes_known, check_votes_known_active, check_votes_no_contradictions,
    check_votes_no_duplicates, check_votes_number, check_votes_number_active,
};

use ergo_crypto::difficulty::DifficultyParams;
use ergo_crypto::pow::{self, DifficultyError, PowError};
use ergo_primitives::digest::blake2b256;
use ergo_primitives::reader::VlqReader;
use ergo_ser::header::{read_header, Header};
use thiserror::Error;

/// A header that has passed all validation checks (PoW, difficulty,
/// parent linkage, timestamp monotonicity).
///
/// Construction in production code is through [`validate_header()`] or
/// [`CheckedHeader::from_persisted_parts()`] (for headers already validated
/// and stored by the header pipeline).
///
/// Design note: a `Header<Checked>` phantom-generic typestate was considered
/// and rejected in favor of a concrete proof object. `CheckedHeader` carries
/// `header_id` (the computed Blake2b256 hash), which a phantom marker could
/// not.
#[derive(Debug, Clone)]
pub struct CheckedHeader {
    header: Header,
    header_id: [u8; 32],
}

impl CheckedHeader {
    /// Borrow the underlying validated [`Header`].
    pub fn header(&self) -> &Header {
        &self.header
    }
    /// 32-byte header identifier (`Blake2b256` of the canonical
    /// header bytes), computed once during validation.
    pub fn header_id(&self) -> &[u8; 32] {
        &self.header_id
    }
    /// Block height of the validated header.
    pub fn height(&self) -> u32 {
        self.header.height
    }

    /// Reconstruct a `CheckedHeader` from persisted header bytes + metadata.
    ///
    /// This is a controlled trust escape hatch for headers that were already
    /// validated by `process_header()` and stored in the header table. It
    /// re-derives the canonical header id from the bytes, checks that it
    /// matches the caller-supplied `expected_id` (typically the storage
    /// key), parses the header, and checks metadata consistency. It does
    /// NOT re-verify PoW or difficulty — PoW validity is trusted from the
    /// header-validation persistence boundary.
    ///
    /// Takes primitive arguments to avoid a dependency on `HeaderMeta`
    /// (which lives in ergo-state and would create a crate cycle).
    ///
    /// # Errors
    /// - `HeaderParseFailed` when `header_bytes` does not deserialize.
    /// - `HeaderIdMismatch` when `blake2b256(header_bytes) != expected_id`
    ///   (storage corruption or wrong-key lookup).
    /// - `PowNotValidated` / `MetaHeightMismatch` / `MetaParentMismatch` /
    ///   `MetaTimestampMismatch` when the cached metadata disagrees with
    ///   the parsed header.
    pub fn from_persisted_parts(
        header_bytes: &[u8],
        expected_id: [u8; 32],
        meta_pow_validity: u8,
        meta_height: u32,
        meta_parent_id: [u8; 32],
        meta_timestamp: u64,
    ) -> Result<Self, HeaderValidationError> {
        let computed_id = *blake2b256(header_bytes).as_bytes();
        if computed_id != expected_id {
            return Err(HeaderValidationError::HeaderIdMismatch {
                expected: expected_id,
                computed: computed_id,
            });
        }
        let mut r = VlqReader::new(header_bytes);
        let header = read_header(&mut r)
            .map_err(|e| HeaderValidationError::HeaderParseFailed(format!("{e:?}")))?;
        // `read_header` does not enforce EOF, so a row of the form
        // `valid_header_bytes ++ junk` (with both hashing to the
        // expected_id, e.g. via a buggy write that stored noncanonical
        // bytes under their own hash) would otherwise hydrate cleanly
        // and silently feed noncanonical bytes to downstream consumers.
        let consumed = r.position();
        if consumed != header_bytes.len() {
            return Err(HeaderValidationError::HeaderParseFailed(format!(
                "trailing bytes after header: parsed {consumed} of {} bytes",
                header_bytes.len(),
            )));
        }
        if meta_pow_validity != 1 {
            return Err(HeaderValidationError::PowNotValidated {
                pow_validity: meta_pow_validity,
            });
        }
        if meta_height != header.height {
            return Err(HeaderValidationError::MetaHeightMismatch {
                meta: meta_height,
                header: header.height,
            });
        }
        if meta_parent_id != *header.parent_id.as_bytes() {
            return Err(HeaderValidationError::MetaParentMismatch {
                meta: meta_parent_id,
                header: *header.parent_id.as_bytes(),
            });
        }
        if meta_timestamp != header.timestamp {
            return Err(HeaderValidationError::MetaTimestampMismatch {
                meta: meta_timestamp,
                header: header.timestamp,
            });
        }
        Ok(Self {
            header,
            header_id: expected_id,
        })
    }

    /// Wrap a header as checked without running validation.
    ///
    /// For use in test harnesses and the just-validated header path where
    /// the header was validated in the same process (not reconstructed from
    /// persisted storage). Prefer `from_persisted_parts()` when loading
    /// from the header store.
    #[cfg(feature = "test-helpers")]
    pub fn trust_me(header: Header, header_id: [u8; 32]) -> Self {
        Self { header, header_id }
    }
}

#[derive(Debug, Error)]
pub enum HeaderValidationError {
    #[error(
        "parent ID mismatch: expected {}, got {}",
        hex::encode(expected),
        hex::encode(got)
    )]
    ParentMismatch { expected: [u8; 32], got: [u8; 32] },

    #[error("timestamp not monotonic: parent={parent_ts}, child={child_ts}")]
    TimestampNotMonotonic { parent_ts: u64, child_ts: u64 },

    #[error("PoW verification failed: {0}")]
    Pow(#[from] PowError),

    #[error("difficulty check failed: {0}")]
    Difficulty(#[from] DifficultyError),

    #[error("persisted header not PoW-validated: pow_validity={pow_validity}")]
    PowNotValidated { pow_validity: u8 },

    #[error("persisted meta height mismatch: meta={meta}, header={header}")]
    MetaHeightMismatch { meta: u32, header: u32 },

    #[error(
        "persisted meta parent_id mismatch: meta={}, header={}",
        hex::encode(meta),
        hex::encode(header)
    )]
    MetaParentMismatch { meta: [u8; 32], header: [u8; 32] },

    #[error("persisted meta timestamp mismatch: meta={meta}, header={header}")]
    MetaTimestampMismatch { meta: u64, header: u64 },

    #[error(
        "persisted header id mismatch: expected={}, computed={}",
        hex::encode(expected),
        hex::encode(computed)
    )]
    HeaderIdMismatch {
        expected: [u8; 32],
        computed: [u8; 32],
    },

    #[error("persisted header bytes failed to parse: {0}")]
    HeaderParseFailed(String),

    /// Scala `hdrFutureTimestamp` (rule 211, recoverable). Header
    /// timestamp is more than [`FUTURE_TIMESTAMP_DRIFT_MS`] ahead of
    /// the validator's clock. Marked recoverable in Scala because the
    /// header may become acceptable after the validator's clock
    /// catches up; this validator surfaces it as a rejection and lets
    /// the caller decide whether to retry later.
    #[error(
        "future timestamp: header.ts={header_ts}, now={now_ms}, drift {drift_ms} > cap {cap_ms}"
    )]
    FutureTimestamp {
        /// Header timestamp (ms since epoch).
        header_ts: u64,
        /// Validator clock at the moment of the check (ms since epoch).
        now_ms: u64,
        /// `header_ts - now_ms` (positive when the header is in the
        /// future).
        drift_ms: u64,
        /// Cap above which the header is rejected.
        cap_ms: u64,
    },

    /// Scala `hdrVotesUnknown` (rule 215). At an epoch-start
    /// header (height > 0, `height % voting_length == 0`), a
    /// non-zero vote byte references an unknown parameter id —
    /// not in `Parameters.parametersDescs`. Off-epoch headers do
    /// not fire this rule.
    #[error("epoch-start header at height {height} votes for unknown parameter {vote} at slot {index} (rule 215)")]
    VotesUnknown {
        /// Block height of the offending header (always an epoch
        /// start when this error fires).
        height: u32,
        /// Slot inside `header.votes` where the unknown vote sits.
        index: usize,
        /// Vote byte value (signed) — not in the known set.
        vote: i8,
    },

    /// Scala `hdrVotesDuplicates` (rule 213). Two non-zero vote bytes
    /// reference the same parameter id in the same direction (e.g.
    /// `[3, 3, 0]` votes twice to increase parameter 3). The
    /// recompute path would silently double-count; we reject
    /// upstream.
    #[error("duplicate votes for parameter id {param_id}: bytes at slots {first} and {second} both = {byte}")]
    VotesDuplicate {
        /// Parameter id (= abs value of the vote byte).
        param_id: u8,
        /// Slot index (0-2) of the first occurrence.
        first: usize,
        /// Slot index (0-2) of the second occurrence.
        second: usize,
        /// The vote byte both slots share (sign-preserved).
        byte: i8,
    },

    /// Scala `hdrVotesContradictory` (rule 214). Two non-zero vote
    /// bytes reference the same parameter id in opposite directions
    /// (e.g. `[3, -3, 0]` votes both to increase and decrease the
    /// same parameter). Vote tally would cancel to zero; we reject
    /// the contradiction explicitly.
    #[error("contradictory votes for parameter id {param_id}: slot {first}={first_byte}, slot {second}={second_byte}")]
    VotesContradictory {
        /// Parameter id (= abs value of both vote bytes).
        param_id: u8,
        /// Slot index (0-2) of the first vote.
        first: usize,
        /// Value at the first slot (sign-preserved).
        first_byte: i8,
        /// Slot index (0-2) of the second vote.
        second: usize,
        /// Value at the second slot (sign-preserved).
        second_byte: i8,
    },

    /// Scala `hdrVotesNumber` (rule 212). After dropping `NoParameter`
    /// (0) slots, the count of remaining votes that are not `SoftFork`
    /// (120) must not exceed `Parameters.ParamVotesCount` (2). A header
    /// proposing three distinct non-soft-fork parameter changes is
    /// malformed — the JVM rejects it (`ErgoStateContext.validateVotes`
    /// `votesCount <= ParamVotesCount`).
    #[error("header casts {count} non-soft-fork votes, exceeds ParamVotesCount=2 (rule 212)")]
    VotesNumber {
        /// Number of non-zero, non-`SoftFork` vote bytes.
        count: usize,
    },
}

/// A header whose PoW solution has been verified.
///
/// Constructed only via [`PowCheckedHeader::verify_pow`]. Downstream
/// validation (parent linkage, timestamp, difficulty) consumes this
/// proof via [`validate_header_after_pow`] to produce a
/// [`CheckedHeader`].
///
/// This type exists so the batch header pipeline can parallelize PoW
/// verification in rayon (phase 1) and pass the unforgeable proof
/// into the sequential finalize phase (phase 2) without repeating the
/// expensive PoW call.
#[derive(Debug, Clone)]
pub struct PowCheckedHeader {
    header: Header,
    header_id: [u8; 32],
}

impl PowCheckedHeader {
    pub fn header(&self) -> &Header {
        &self.header
    }
    pub fn header_id(&self) -> &[u8; 32] {
        &self.header_id
    }

    /// Verify the Autolykos PoW solution and return a proof. Dispatch
    /// is on the solution variant (Scala parity — see `pow.rs` doc), so
    /// no `DifficultyParams` is needed here.
    pub fn verify_pow(header: Header, header_id: [u8; 32]) -> Result<Self, HeaderValidationError> {
        pow::verify_pow_solution(&header)?;
        Ok(Self { header, header_id })
    }

    /// Test-only constructor that bypasses PoW. The returned proof is
    /// **not valid** — never feed the inner header into chain validation.
    /// Used by orphan-buffer probe tests that only exercise buffer
    /// mechanics (push / cap / pop) and never call `finalize_header`.
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn for_test_unchecked(header: Header, header_id: [u8; 32]) -> Self {
        Self { header, header_id }
    }
}

/// Validate a header against its parent and chain context, consuming a
/// PoW proof so PoW is not re-verified.
///
/// Returns a [`CheckedHeader`] that proves all checks passed — parent
/// linkage, timestamp monotonicity, PoW (from the proof), and difficulty.
///
/// Callers that don't have a PoW proof should use [`validate_header`]
/// which constructs the proof internally (one PoW call).
pub fn validate_header_after_pow(
    pow_checked: PowCheckedHeader,
    parent_id: &[u8; 32],
    parent: &Header,
    epoch_headers: &[Header],
    config: &DifficultyParams,
) -> Result<CheckedHeader, HeaderValidationError> {
    let PowCheckedHeader { header, header_id } = pow_checked;
    check_parent_id(&header, parent_id)?;
    check_timestamp(&header, parent)?;
    // Vote checks 213 (duplicates) + 214 (contradictions) are
    // non-deactivatable (`mayBeDisabled = false`) and self-contained — no
    // clock or chain context — so they run here at header time. Rule 212
    // (`hdrVotesNumber`) is soft-fork-DEACTIVATABLE (`mayBeDisabled = true`),
    // so like rule 215 it must be gated on the activated validation settings,
    // which header-only validation cannot see; it is enforced at block
    // validation time (`ergo-sync::block_proc`, gated on
    // `is_rule_disabled(212)`) via [`check_votes_number`]. The
    // future-timestamp check (rule 211) needs a wall-clock reading and runs
    // at the network ingress site; see `check_future_timestamp`.
    check_votes_no_duplicates(&header)?;
    check_votes_no_contradictions(&header)?;
    pow::verify_header_difficulty(&header, epoch_headers, config)?;
    Ok(CheckedHeader { header, header_id })
}

/// Validate a header against its parent and chain context under the
/// supplied [`DifficultyParams`].
///
/// Returns a [`CheckedHeader`] that proves all checks passed. This is the
/// only way to construct a `CheckedHeader` from raw inputs, making it an
/// unforgeable proof-of-validation artifact.
///
/// - `header_id`: computed Blake2b256 ID of this header (caller provides)
/// - `parent_id`: computed Blake2b256 ID of the parent header
/// - `parent`: the parent header (for timestamp check)
/// - `epoch_headers`: headers at epoch boundary heights for difficulty
///   recalculation; the last element must be the parent
pub fn validate_header(
    header: Header,
    header_id: [u8; 32],
    parent_id: &[u8; 32],
    parent: &Header,
    epoch_headers: &[Header],
    config: &DifficultyParams,
) -> Result<CheckedHeader, HeaderValidationError> {
    let pow_checked = PowCheckedHeader::verify_pow(header, header_id)?;
    validate_header_after_pow(pow_checked, parent_id, parent, epoch_headers, config)
}
