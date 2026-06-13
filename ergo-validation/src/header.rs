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
/// Design note: the spec sketches `Header<Checked>` phantom-generic typestate,
/// but we use a concrete proof object instead. `CheckedHeader` carries
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

/// Scala `Constants.FutureTimestampThreshold` — 20 minutes in
/// milliseconds. A header more than this far ahead of the validator's
/// clock is rejected as recoverable (peer can retry once the local
/// clock catches up).
pub const FUTURE_TIMESTAMP_DRIFT_MS: u64 = 20 * 60 * 1000;

/// Check that header.parent_id matches the computed ID of the parent.
pub fn check_parent_id(header: &Header, parent_id: &[u8; 32]) -> Result<(), HeaderValidationError> {
    if header.parent_id.as_bytes() != parent_id {
        return Err(HeaderValidationError::ParentMismatch {
            expected: *parent_id,
            got: *header.parent_id.as_bytes(),
        });
    }
    Ok(())
}

/// Check that header.timestamp > parent.timestamp.
pub fn check_timestamp(header: &Header, parent: &Header) -> Result<(), HeaderValidationError> {
    if header.timestamp <= parent.timestamp {
        return Err(HeaderValidationError::TimestampNotMonotonic {
            parent_ts: parent.timestamp,
            child_ts: header.timestamp,
        });
    }
    Ok(())
}

/// Scala `hdrFutureTimestamp` (rule 211) — reject headers whose
/// timestamp is more than [`FUTURE_TIMESTAMP_DRIFT_MS`] ahead of
/// `now_ms`.
///
/// Standalone (not invoked by [`validate_header_after_pow`]) because
/// the validator clock is a runtime input that varies by caller:
/// production reads `SystemTime::now()` at the ingress site, tests
/// pin an explicit timestamp. Header-proc and any future
/// mempool-style header ingress must call this themselves with the
/// chosen clock value. Returning a typed error rather than a bool
/// keeps the rejection surface symmetric with the other rule
/// helpers.
pub fn check_future_timestamp(header: &Header, now_ms: u64) -> Result<(), HeaderValidationError> {
    let cap_ms = FUTURE_TIMESTAMP_DRIFT_MS;
    if header.timestamp > now_ms.saturating_add(cap_ms) {
        return Err(HeaderValidationError::FutureTimestamp {
            header_ts: header.timestamp,
            now_ms,
            drift_ms: header.timestamp - now_ms,
            cap_ms,
        });
    }
    Ok(())
}

/// Scala `hdrVotesNumber` (rule 212) — reject when a header casts more
/// than `Parameters.ParamVotesCount` (2) non-`SoftFork` votes.
///
/// Mirrors `ErgoStateContext.validateVotes`
/// (`reference/ergo-core/.../nodeView/state/ErgoStateContext.scala:330-339`):
/// `votes = header.votes.filter(_ != NoParameter)` (drop 0 slots), then
/// `votesCount = votes.count(_ != SoftFork)` must be `<= ParamVotesCount`.
/// `NoParameter = 0`, `SoftFork = 120`, `ParamVotesCount = 2`
/// (`Parameters.scala`). The header carries only three vote slots, so the
/// count is at most 3 and only `[a, b, c]` with three distinct non-zero
/// non-120 bytes can trip it.
pub fn check_votes_number(header: &Header) -> Result<(), HeaderValidationError> {
    // Scala: `votes = header.votes.filter(_ != NoParameter)` then
    // `votesCount = votes.count(_ != SoftFork)`; reject when it exceeds
    // ParamVotesCount. NoParameter = 0, SoftFork = 120, ParamVotesCount = 2.
    let count = header
        .votes
        .iter()
        .map(|b| *b as i8)
        .filter(|v| *v != 0 && *v != SOFT_FORK_VOTE)
        .count();
    if count > PARAM_VOTES_COUNT {
        return Err(HeaderValidationError::VotesNumber { count });
    }
    Ok(())
}

/// Rule 212 (`hdrVotesNumber`) gated by its soft-fork deactivation status.
/// Scala marks this rule `mayBeDisabled = true`, so an activated
/// `ErgoValidationSettingsUpdate` can switch it off (after which a header
/// casting three distinct non-soft-fork votes is accepted). When the
/// activated settings disable the rule, Scala's `ValidationState` never runs
/// it; we mirror that by skipping the check. `rule_disabled` is supplied by
/// the caller from `ErgoValidationSettings::is_rule_disabled(212)` — invoked
/// at block-validation time (`ergo-sync::block_proc`), the same layer that
/// gates rule 215, because header-only validation cannot see the settings.
pub fn check_votes_number_active(
    header: &Header,
    rule_disabled: bool,
) -> Result<(), HeaderValidationError> {
    if rule_disabled {
        return Ok(());
    }
    check_votes_number(header)
}

/// Scala `Parameters.SoftFork` (`settings/Parameters.scala`): the vote
/// byte (120) reserved for soft-fork signalling, excluded from the
/// rule-212 `votesCount`.
const SOFT_FORK_VOTE: i8 = 120;

/// Scala `Parameters.ParamVotesCount` (`settings/Parameters.scala`): the
/// maximum number of non-soft-fork parameter votes a header may cast.
const PARAM_VOTES_COUNT: usize = 2;

/// Scala `hdrVotesDuplicates` (rule 213) — reject when two non-zero
/// vote bytes reference the same parameter id in the same direction.
///
/// Header vote slots carry an `i8` per slot: positive byte = vote to
/// increase the param, negative = vote to decrease, zero = no vote.
/// "Duplicate" means two slots with the same byte value (same param
/// id AND same direction); two slots with the same id but opposite
/// signs is `VotesContradictory` (rule 214).
pub fn check_votes_no_duplicates(header: &Header) -> Result<(), HeaderValidationError> {
    for first in 0..header.votes.len() {
        let a = header.votes[first];
        if a == 0 {
            continue;
        }
        for second in (first + 1)..header.votes.len() {
            let b = header.votes[second];
            if a == b {
                return Err(HeaderValidationError::VotesDuplicate {
                    param_id: (a as i8).unsigned_abs(),
                    first,
                    second,
                    byte: a as i8,
                });
            }
        }
    }
    Ok(())
}

/// Scala `hdrVotesContradictory` (rule 214) — reject when two
/// non-zero vote bytes reference the same parameter id with
/// opposite signs (one vote to increase, one to decrease — the
/// tally cancels to zero, so the header carries a deliberately
/// neutral vote that has no effect, which Scala treats as
/// malformed input rather than silently no-oping).
///
/// Untrusted-input guard: we use `wrapping_neg` instead of the raw `-`
/// operator because vote bytes arrive from the network as `u8` and
/// reinterpret as `i8` includes the value `-128` (`i8::MIN`). The
/// negation `-(-128_i8)` overflows: debug builds panic, release builds
/// wrap silently. `wrapping_neg` is exactly the JVM's `(-v).toByte`
/// (`ErgoStateContext.validateVotes:333`): `wrapping_neg(i8::MIN) ==
/// i8::MIN`, so a lone `0x80` is its OWN negation — `reverseVotes`
/// holds `-128` at its own index, `contains(-128)` is true, and rule
/// 214 REJECTS. The earlier `checked_neg`/`continue` swallowed that
/// case (accepting a header the JVM rejects); `wrapping_neg` plus the
/// explicit self-match below restores parity and never panics.
/// Scala `hdrVotesUnknown` (rule 215) — at an epoch-start header,
/// every non-zero vote byte must reference an id in
/// `Parameters.parametersDescs`. Scala source pin:
/// `reference/ergo/.../nodeView/state/ErgoStateContext.scala:344`
/// — the check is `epochStarts &&
/// !Parameters.parametersDescs.contains(v)`.
///
/// `parametersDescs` is keyed by the **Increase** parameter ids
/// (positive bytes) plus `SoftFork`. Concretely, the known set is:
/// `{1, 2, 3, 4, 5, 6, 7, 8, 120}`. Notably the **Decrease**
/// variants (`-1..=-8`) are NOT keys, so a decrease vote at an
/// epoch start would fire this rule — that's literal Scala
/// behavior (Decrease votes go through within an epoch's tally,
/// but the first header of a new epoch is treated as a
/// "proposal" slot and only increases / soft-fork are accepted).
///
/// Off-epoch headers (`height % voting_length != 0` or
/// `height == 0`) are unaffected; the check is a no-op on those.
///
/// Called separately at the network ingress site rather than
/// folded into `validate_header_after_pow` because it requires
/// `voting_length` from the chain config (Scala
/// `votingSettings.votingLength`).
pub fn check_votes_known(header: &Header, voting_length: u32) -> Result<(), HeaderValidationError> {
    // Scala `header.votingStarts(votingLength)`:
    //   height % votingLength == 0 && height > 0
    if voting_length == 0 || header.height == 0 || !header.height.is_multiple_of(voting_length) {
        return Ok(());
    }
    for (index, byte) in header.votes.iter().enumerate() {
        let v = *byte as i8;
        if v == 0 {
            continue;
        }
        if !KNOWN_VOTE_IDS.contains(&v) {
            return Err(HeaderValidationError::VotesUnknown {
                height: header.height,
                index,
                vote: v,
            });
        }
    }
    Ok(())
}

/// Rule 215 (`hdrVotesUnknown`) gated by its soft-fork deactivation
/// status. Scala marks this rule `mayBeDisabled = true`; mainnet's
/// v6.0 activation disabled it (its `ErgoValidationSettingsUpdate`
/// carries `rules_to_disable = [215, 409]`) so the new
/// `SubblocksPerBlock` parameter (id 9, absent from
/// `Parameters.parametersDescs`) — and downward parameter proposals
/// such as `MaxBlockCostDecrease` (-4) — can be voted on at an epoch
/// start. When the activated validation settings disable the rule,
/// Scala's `ValidationState` never runs it; we mirror that by skipping
/// the check entirely. `rule_disabled` is supplied by the caller from
/// `ErgoValidationSettings::is_rule_disabled(215)`.
pub fn check_votes_known_active(
    header: &Header,
    voting_length: u32,
    rule_disabled: bool,
) -> Result<(), HeaderValidationError> {
    if rule_disabled {
        return Ok(());
    }
    check_votes_known(header, voting_length)
}

/// `Parameters.parametersDescs` keys from
/// `reference/ergo/.../settings/Parameters.scala:332-342`. The
/// Increase variants (1-8) for the eight votable parameters plus
/// `SoftFork = 120`. Decrease variants and the future
/// `SubblocksPerBlockIncrease = 9` (v6.0) are intentionally
/// absent — matches the captured Scala source we mirror.
const KNOWN_VOTE_IDS: [i8; 9] = [
    1,   // StorageFeeFactorIncrease
    2,   // MinValuePerByteIncrease
    3,   // MaxBlockSizeIncrease
    4,   // MaxBlockCostIncrease
    5,   // TokenAccessCostIncrease
    6,   // InputCostIncrease
    7,   // DataInputCostIncrease
    8,   // OutputCostIncrease
    120, // SoftFork
];

pub fn check_votes_no_contradictions(header: &Header) -> Result<(), HeaderValidationError> {
    for first in 0..header.votes.len() {
        let a = header.votes[first] as i8;
        if a == 0 {
            continue;
        }
        // The JVM's `reverseVotes = votes.map(v => (-v).toByte)` then
        // `!reverseVotes.contains(v)`. `wrapping_neg` IS `(-v).toByte`.
        let want = a.wrapping_neg();
        // Self-negation: only `i8::MIN` satisfies `want == a`. The JVM's
        // `reverseVotes` holds `a` at a's own index, so `contains(a)` is
        // true -> contradiction. (A non-i8::MIN value never equals its
        // own wrapping negation, so this arm is exactly the lone-0x80
        // case the old `checked_neg`/`continue` wrongly accepted.)
        if want == a {
            return Err(HeaderValidationError::VotesContradictory {
                param_id: a.unsigned_abs(),
                first,
                first_byte: a,
                second: first,
                second_byte: a,
            });
        }
        for second in (first + 1)..header.votes.len() {
            let b = header.votes[second] as i8;
            if b != 0 && b == want {
                return Err(HeaderValidationError::VotesContradictory {
                    param_id: a.unsigned_abs(),
                    first,
                    first_byte: a,
                    second,
                    second_byte: b,
                });
            }
        }
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::digest::{ADDigest, Digest32, ModifierId};
    use ergo_primitives::group_element::GroupElement;
    use ergo_ser::autolykos::AutolykosSolution;

    // ----- helpers -----

    fn test_header(votes: [u8; 3], timestamp: u64) -> Header {
        Header {
            version: 2,
            parent_id: ModifierId::from_bytes([0; 32]),
            ad_proofs_root: Digest32::from_bytes([0; 32]),
            transactions_root: Digest32::from_bytes([0; 32]),
            state_root: ADDigest::from_bytes([0; 33]),
            timestamp,
            extension_root: Digest32::from_bytes([0; 32]),
            n_bits: 0x20000000,
            height: 1,
            votes,
            unparsed_bytes: Vec::new(),
            solution: AutolykosSolution::V2 {
                pk: GroupElement::from_bytes([0x02; 33]),
                nonce: [0; 8],
            },
        }
    }

    // ----- check_future_timestamp (rule 211) -----

    #[test]
    fn future_timestamp_accepts_at_boundary() {
        // header.ts == now + cap: exactly at the cap, accepted
        // (the rejection is `>`, not `>=`).
        let now = 1_700_000_000_000u64;
        let header = test_header([0; 3], now + FUTURE_TIMESTAMP_DRIFT_MS);
        assert!(check_future_timestamp(&header, now).is_ok());
    }

    #[test]
    fn future_timestamp_accepts_in_past() {
        // Headers in the past (or at present) trivially pass.
        let now = 1_700_000_000_000u64;
        let header = test_header([0; 3], now - 60_000);
        assert!(check_future_timestamp(&header, now).is_ok());
    }

    #[test]
    fn future_timestamp_rejects_one_ms_over_cap() {
        let now = 1_700_000_000_000u64;
        let header = test_header([0; 3], now + FUTURE_TIMESTAMP_DRIFT_MS + 1);
        let err = check_future_timestamp(&header, now).unwrap_err();
        match err {
            HeaderValidationError::FutureTimestamp {
                drift_ms, cap_ms, ..
            } => {
                assert_eq!(cap_ms, FUTURE_TIMESTAMP_DRIFT_MS);
                assert_eq!(drift_ms, FUTURE_TIMESTAMP_DRIFT_MS + 1);
            }
            other => panic!("expected FutureTimestamp, got {other:?}"),
        }
    }

    #[test]
    fn future_timestamp_handles_now_near_u64_max() {
        // saturating_add guards: a `now` near u64::MAX must not panic
        // even if the cap addition would overflow. The header.ts would
        // be ≤ u64::MAX which is ≤ saturating_add(now, cap), so
        // accepted.
        let now = u64::MAX - 1_000_000;
        let header = test_header([0; 3], u64::MAX - 500_000);
        assert!(check_future_timestamp(&header, now).is_ok());
    }

    // ----- check_votes_no_duplicates (rule 213) -----

    #[test]
    fn votes_no_duplicates_accepts_zero_filled() {
        assert!(check_votes_no_duplicates(&test_header([0, 0, 0], 0)).is_ok());
    }

    #[test]
    fn votes_no_duplicates_accepts_unique_ids() {
        assert!(check_votes_no_duplicates(&test_header([3, 5, 7], 0)).is_ok());
    }

    #[test]
    fn votes_no_duplicates_accepts_opposite_signs() {
        // [3, -3, 0] is a contradiction (rule 214), NOT a duplicate
        // (rule 213). The duplicate check must let it pass so the
        // contradiction check fires with the right error variant.
        let votes = [3u8, (-3i8) as u8, 0u8];
        assert!(check_votes_no_duplicates(&test_header(votes, 0)).is_ok());
    }

    #[test]
    fn votes_no_duplicates_rejects_same_byte_repeat() {
        let err = check_votes_no_duplicates(&test_header([3, 3, 0], 0)).unwrap_err();
        match err {
            HeaderValidationError::VotesDuplicate {
                param_id,
                first,
                second,
                byte,
            } => {
                assert_eq!(param_id, 3);
                assert_eq!(first, 0);
                assert_eq!(second, 1);
                assert_eq!(byte, 3);
            }
            other => panic!("expected VotesDuplicate, got {other:?}"),
        }
    }

    #[test]
    fn votes_no_duplicates_rejects_same_negative_repeat() {
        let votes = [(-5i8) as u8, 0u8, (-5i8) as u8];
        let err = check_votes_no_duplicates(&test_header(votes, 0)).unwrap_err();
        match err {
            HeaderValidationError::VotesDuplicate {
                param_id,
                first,
                second,
                byte,
            } => {
                assert_eq!(param_id, 5);
                assert_eq!(first, 0);
                assert_eq!(second, 2);
                assert_eq!(byte, -5);
            }
            other => panic!("expected VotesDuplicate, got {other:?}"),
        }
    }

    // ----- check_votes_no_contradictions (rule 214) -----

    #[test]
    fn votes_no_contradictions_accepts_zero_filled() {
        assert!(check_votes_no_contradictions(&test_header([0, 0, 0], 0)).is_ok());
    }

    #[test]
    fn votes_no_contradictions_accepts_unique_ids() {
        assert!(check_votes_no_contradictions(&test_header([3, 5, 7], 0)).is_ok());
    }

    #[test]
    fn votes_no_contradictions_accepts_same_sign_duplicate() {
        // [3, 3, 0] is a duplicate (rule 213), not a contradiction.
        // Contradiction check must let it pass.
        assert!(check_votes_no_contradictions(&test_header([3, 3, 0], 0)).is_ok());
    }

    #[test]
    fn votes_no_contradictions_rejects_plus_minus_pair() {
        let votes = [3u8, (-3i8) as u8, 0u8];
        let err = check_votes_no_contradictions(&test_header(votes, 0)).unwrap_err();
        match err {
            HeaderValidationError::VotesContradictory {
                param_id,
                first_byte,
                second_byte,
                ..
            } => {
                assert_eq!(param_id, 3);
                assert_eq!(first_byte, 3);
                assert_eq!(second_byte, -3);
            }
            other => panic!("expected VotesContradictory, got {other:?}"),
        }
    }

    #[test]
    fn votes_no_contradictions_rejects_when_pair_is_split_by_zero() {
        // Zero slot between contradiction shouldn't hide it.
        let votes = [7u8, 0u8, (-7i8) as u8];
        assert!(check_votes_no_contradictions(&test_header(votes, 0)).is_err());
    }

    #[test]
    fn votes_no_contradictions_rejects_lone_i8_min_self_negation() {
        // Vote byte 0x80 = i8::MIN (-128) is its own negation under the
        // wrapping `(-v).toByte` the JVM uses: `reverseVotes` for a lone
        // -128 is `[-128]`, so `reverseVotes.contains(-128)` is true and
        // `hdrVotesContradictory` (rule 214) REJECTS. A naive `a == -b`
        // would panic in debug / wrap silently in release; the impl must
        // use `wrapping_neg` and treat the self-match as a contradiction.
        let votes = [0x80_u8, 0u8, 0u8];
        let err = check_votes_no_contradictions(&test_header(votes, 0))
            .expect_err("lone 0x80 self-negates -> rule 214 contradiction");
        assert!(
            matches!(err, HeaderValidationError::VotesContradictory { .. }),
            "expected VotesContradictory for lone 0x80, got {err:?}",
        );
    }

    #[test]
    fn votes_no_contradictions_triple_i8_min_does_not_panic() {
        // [0x80, 0x80, 0x80] must not panic on negation. At the header
        // level the duplicate pass (rule 213) fires first; the
        // contradiction pass also flags it (self-negation) but never
        // panics on the adversarial i8::MIN input.
        let votes = [0x80_u8, 0x80_u8, 0x80_u8];
        let dup_err = check_votes_no_duplicates(&test_header(votes, 0)).unwrap_err();
        assert!(matches!(
            dup_err,
            HeaderValidationError::VotesDuplicate { .. }
        ));
        // Contradiction pass: no panic (result is Err, the self-negation).
        let _ = check_votes_no_contradictions(&test_header(votes, 0));
    }

    // ----- check_votes_number (rule 212) -----

    #[test]
    fn votes_number_accepts_zero_filled() {
        assert!(check_votes_number(&test_header([0, 0, 0], 0)).is_ok());
    }

    #[test]
    fn votes_number_accepts_two_non_softfork() {
        // Two distinct parameter votes is the maximum the JVM allows.
        assert!(check_votes_number(&test_header([3, 5, 0], 0)).is_ok());
    }

    #[test]
    fn votes_number_softfork_byte_is_not_counted() {
        // SoftFork (120) is excluded from votesCount, so [120, 3, 5]
        // has only TWO counted votes and is accepted.
        let votes = [120u8, 3u8, 5u8];
        assert!(check_votes_number(&test_header(votes, 0)).is_ok());
    }

    #[test]
    fn votes_number_rejects_three_non_softfork() {
        // Three distinct non-soft-fork votes: votesCount = 3 > 2 -> the
        // JVM `hdrVotesNumber` (rule 212) rejects. This is the chain-tier
        // `count-three-nonfork-reject` coal (we currently ACCEPT it).
        let err = check_votes_number(&test_header([1, 2, 3], 0))
            .expect_err("three non-soft-fork votes exceed ParamVotesCount=2");
        match err {
            HeaderValidationError::VotesNumber { count } => assert_eq!(count, 3),
            other => panic!("expected VotesNumber{{count:3}}, got {other:?}"),
        }
    }

    #[test]
    fn votes_number_rejects_three_with_negatives() {
        // Decrease votes (negative bytes) count too: [-1, -2, -3] -> 3.
        let votes = [(-1i8) as u8, (-2i8) as u8, (-3i8) as u8];
        let err = check_votes_number(&test_header(votes, 0))
            .expect_err("three negative votes also exceed the cap");
        assert!(matches!(
            err,
            HeaderValidationError::VotesNumber { count: 3 }
        ));
    }

    #[test]
    fn votes_number_active_skips_when_rule_212_disabled() {
        // Rule 212 is soft-fork-deactivatable: when disabled, a header with
        // three distinct non-soft-fork votes must be ACCEPTED (Scala stops
        // running the rule); when enabled, it rejects.
        let three = test_header([1, 2, 3], 0);
        assert!(check_votes_number_active(&three, true).is_ok());
        let err = check_votes_number_active(&three, false).unwrap_err();
        assert!(matches!(
            err,
            HeaderValidationError::VotesNumber { count: 3 }
        ));
    }

    #[test]
    fn votes_no_contradictions_no_panic_on_adversarial_input() {
        // Sweep every (a, b) pair across the full u8 domain to
        // ensure the contradiction check never panics on
        // adversarial input. Catches any regression that
        // re-introduces the `-b` arithmetic.
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                let votes = [a, b, 0];
                // Just calling — both checks must return without panic.
                let _ = check_votes_no_contradictions(&test_header(votes, 0));
                let _ = check_votes_no_duplicates(&test_header(votes, 0));
            }
        }
    }

    // ----- integration: validate_header_after_pow wires votes checks -----
    //
    // We cannot easily integration-test this without a real PoW
    // solution, but the wire-up via `check_votes_no_duplicates` /
    // `check_votes_no_contradictions` is one-liner; the unit tests
    // above are the regression guards. A bad-vote regression in a
    // real block would surface as `Validation(VotesDuplicate)` or
    // `Validation(VotesContradictory)` from `header_proc.rs`.

    // ----- check_votes_known (rule 215) -----

    fn header_with_height(height: u32, votes: [u8; 3]) -> Header {
        let mut h = test_header(votes, 0);
        h.height = height;
        h
    }

    const MAINNET_VOTING_LENGTH: u32 = 1024;

    #[test]
    fn votes_known_passes_off_epoch_with_unknown_id() {
        // h=100 isn't an epoch start (100 % 1024 != 0), so the rule
        // is a no-op even if a vote byte is bogus.
        let h = header_with_height(100, [200, 0, 0]);
        assert!(check_votes_known(&h, MAINNET_VOTING_LENGTH).is_ok());
    }

    #[test]
    fn votes_known_passes_at_genesis() {
        // h=0 is explicitly excluded by `votingStarts`.
        let h = header_with_height(0, [200, 0, 0]);
        assert!(check_votes_known(&h, MAINNET_VOTING_LENGTH).is_ok());
    }

    #[test]
    fn votes_known_passes_zero_voting_length() {
        // Defensive guard: voting_length=0 would divide-by-zero
        // without the early return. Treat as "no voting epoch" and
        // skip the rule.
        let h = header_with_height(1024, [200, 0, 0]);
        assert!(check_votes_known(&h, 0).is_ok());
    }

    #[test]
    fn votes_known_passes_epoch_start_all_known_votes() {
        // h=1024 IS an epoch start. Votes 3 (MaxBlockSize), 5
        // (TokenAccessCost), 120 (SoftFork) are all in
        // `parametersDescs`.
        let h = header_with_height(1024, [3, 5, 120]);
        assert!(check_votes_known(&h, MAINNET_VOTING_LENGTH).is_ok());
    }

    #[test]
    fn votes_known_passes_epoch_start_all_no_vote() {
        // h=2048 epoch start, all zeros (NoParameter) — accepted.
        let h = header_with_height(2048, [0, 0, 0]);
        assert!(check_votes_known(&h, MAINNET_VOTING_LENGTH).is_ok());
    }

    #[test]
    fn votes_known_rejects_epoch_start_unknown_id() {
        // h=1024 + vote byte 200 (not in known set).
        let h = header_with_height(1024, [3, 200, 0]);
        let err = check_votes_known(&h, MAINNET_VOTING_LENGTH).unwrap_err();
        match err {
            HeaderValidationError::VotesUnknown {
                height,
                index,
                vote,
            } => {
                assert_eq!(height, 1024);
                assert_eq!(index, 1);
                // 200 as u8 → as i8 → -56 (sign-extended). Verify
                // the variant carries the original signed byte
                // for log triage.
                assert_eq!(vote, 200u8 as i8);
            }
            other => panic!("expected VotesUnknown, got {other:?}"),
        }
    }

    #[test]
    fn votes_known_rejects_epoch_start_decrease_vote() {
        // Literal Scala behavior pin: Decrease variants (-1..=-8)
        // are NOT in `parametersDescs`. At epoch start the rule
        // fires even on a "legitimate" downward proposal.
        let votes_decrease: [u8; 3] = [(-3i8) as u8, 0, 0]; // MaxBlockSizeDecrease
        let h = header_with_height(1024, votes_decrease);
        let err = check_votes_known(&h, MAINNET_VOTING_LENGTH).unwrap_err();
        match err {
            HeaderValidationError::VotesUnknown { vote, .. } => {
                assert_eq!(vote, -3);
            }
            other => panic!("expected VotesUnknown for Decrease vote, got {other:?}"),
        }
    }

    #[test]
    fn votes_known_first_offender_index_pinned() {
        // Multiple unknowns — the rule reports the first slot index.
        let h = header_with_height(1024, [200, 201, 0]);
        match check_votes_known(&h, MAINNET_VOTING_LENGTH).unwrap_err() {
            HeaderValidationError::VotesUnknown { index, .. } => assert_eq!(index, 0),
            other => panic!("expected VotesUnknown at index 0, got {other:?}"),
        }
    }

    #[test]
    fn votes_known_testnet_epoch_length_128() {
        // Testnet voting_length=128. h=256 IS an epoch start at
        // that cadence; same height is OFF-epoch at mainnet's 1024.
        let unknown = header_with_height(256, [200, 0, 0]);
        assert!(check_votes_known(&unknown, MAINNET_VOTING_LENGTH).is_ok());
        let err = check_votes_known(&unknown, 128).unwrap_err();
        assert!(matches!(err, HeaderValidationError::VotesUnknown { .. }));
    }

    #[test]
    fn votes_known_active_skips_when_rule_215_disabled() {
        // Real mainnet block 1802240 — an epoch start (1802240 % 1024
        // == 0) whose header votes are `fc0000`: slot 0 = -4
        // (MaxBlockCostDecrease), slots 1-2 = no-vote. Mainnet's v6.0
        // soft-fork disabled rule 215 (alongside 409) so the new
        // SubblocksPerBlock param id 9 — and downward proposals — are
        // votable at an epoch start; the canonical chain contains this
        // block. Scala's `ValidationState` never runs a disabled rule,
        // so the node must skip rule 215 when the activated validation
        // settings disable it. Enforcing it unconditionally is what
        // stalled the node at 1802240.
        let h = header_with_height(1802240, [(-4i8) as u8, 0, 0]);

        // Rule active (not disabled): still rejected, identical to the
        // raw rule — regression guard that the gate never loosens the
        // active path.
        match check_votes_known_active(&h, MAINNET_VOTING_LENGTH, false).unwrap_err() {
            HeaderValidationError::VotesUnknown {
                height,
                index,
                vote,
            } => {
                assert_eq!(height, 1802240);
                assert_eq!(index, 0);
                assert_eq!(vote, -4);
            }
            other => panic!("expected VotesUnknown when rule active, got {other:?}"),
        }

        // Rule disabled by an activated soft-fork: accepted, matching
        // the canonical mainnet chain and Scala.
        assert!(check_votes_known_active(&h, MAINNET_VOTING_LENGTH, true).is_ok());
    }
}
