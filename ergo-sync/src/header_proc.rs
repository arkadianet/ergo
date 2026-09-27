//! Header processing pipeline: deserialize → validate → persist → update chain state.
//!
//! Handles the coordinator's ValidateHeader action by:
//! 1. Deserializing raw header bytes (ergo-ser)
//! 2. Computing header ID (blake2b256)
//! 3. Looking up parent header from state store
//! 4. Running full header validation (PoW, difficulty, linkage)
//! 5. Computing cumulative score
//! 6. Persisting header + header_meta
//! 7. Updating best_header by cumulative score, preferring an unblocked tie

use ergo_crypto::difficulty::{
    epoch_length_for_height, previous_heights_for_recalculation, DifficultyParams,
};
use ergo_primitives::digest::blake2b256;
use ergo_primitives::reader::VlqReader;
use ergo_ser::difficulty::decode_compact_bits;
use ergo_ser::header::read_header;
use ergo_state::chain::HeaderMeta;
use ergo_state::{ChainStateRead, HeaderSectionStore};
use ergo_validation::header::{CheckedHeader, HeaderValidationError};
use num_bigint::BigUint;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum HeaderProcessError {
    #[error("deserialization failed: {0}")]
    Deserialize(String),
    #[error("parent header not found: {}", hex::encode(parent_id))]
    ParentNotFound { parent_id: [u8; 32] },
    #[error("header already known: {}", hex::encode(header_id))]
    AlreadyKnown { header_id: [u8; 32] },
    #[error("header is invalid: {}", hex::encode(header_id))]
    Invalid { header_id: [u8; 32] },
    #[error("height mismatch: expected {expected}, got {got}")]
    HeightMismatch { expected: u32, got: u32 },
    #[error("epoch header at height {height} not found (needed for difficulty recalculation)")]
    EpochHeaderMissing { height: u32 },
    /// Header was PoW-valid and parent-linked, but the local store did not
    /// hold enough epoch boundary ancestors for the difficulty
    /// recalculation to run (validator returned
    /// `DifficultyError::MissingEpochHeaders`). This is **not** peer
    /// misbehavior — it's a local context gap. Treat like
    /// [`HeaderProcessError::ParentNotFound`]: orphan-buffer + retry once
    /// more ancestors arrive. Never short-circuit to "accept": the
    /// header has not been difficulty-validated.
    #[error(
        "epoch context incomplete at height {height} (parent {})",
        hex::encode(parent_id)
    )]
    EpochContextIncomplete { height: u32, parent_id: [u8; 32] },
    /// The header sits at exactly the configured header-level checkpoint
    /// height but carries a different id than the operator pinned. Scala
    /// `HeadersProcessor.checkpointCondition`
    /// (`HeadersProcessor.scala:437-443`), surfaced through the `hdrCheckpoint`
    /// validation rule at `HeadersProcessor.scala:428`. The sender is
    /// penalised exactly like any other invalid header — this node is on a
    /// different chain than the peer at the one height the operator declared
    /// authoritative.
    #[error(
        "checkpoint mismatch at height {height}: expected {}, got {}",
        hex::encode(expected),
        hex::encode(got)
    )]
    CheckpointMismatch {
        height: u32,
        expected: [u8; 32],
        got: [u8; 32],
    },
    #[error(
        "genesis id mismatch: expected {}, got {}",
        hex::encode(expected),
        hex::encode(got)
    )]
    GenesisIdMismatch { expected: [u8; 32], got: [u8; 32] },
    #[error("validation failed: {0}")]
    Validation(#[from] HeaderValidationError),
    #[error("storage error: {0}")]
    Storage(#[from] ergo_state::store::StateError),
}

/// Operator-supplied header-level trust anchor: "the block at `height`
/// MUST be `block_id`".
///
/// Scala parity: `ergo.node.checkpoint` (`application.conf:113-125`,
/// default `null`) enforced in HEADER validation by
/// `HeadersProcessor.checkpointCondition`
/// (`HeadersProcessor.scala:437-443`), wired in as the `hdrCheckpoint` rule
/// of `validateChildBlockHeader` (`HeadersProcessor.scala:428`). Only the
/// header at *exactly* `height` is constrained: headers below it are
/// validated normally and are NOT skipped or trusted (Scala's
/// `checkpointCondition` returns `true` for every other height), and headers
/// above it inherit the anchor transitively through the parent chain.
/// `validateGenesisBlockHeader` (`HeadersProcessor.scala:402-417`) carries no
/// `hdrCheckpoint` rule, so genesis is likewise unconstrained here.
///
/// DISTINCT FROM the script-validation checkpoint
/// (`[chain] script_validation_checkpoint_height` / `_block_id`, consumed by
/// `BlockValidationContext::script_validation_checkpoint`): that one governs
/// whether per-input ErgoScript evaluation is SKIPPED below a height during
/// full-block validation. This one adds no skipping whatsoever — it only
/// binds one header id, on the header chain, before any full block exists.
/// Scala happens to read both from the same HOCON key; this node keeps them
/// as two settings because the script checkpoint carries per-network
/// defaults while the header anchor is deliberately operator-supplied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderCheckpoint {
    /// Height at which `block_id` is asserted. Always `> 0` as loaded from
    /// config; height 0 has no header.
    pub height: u32,
    /// The header id the operator pins at `height`.
    pub block_id: [u8; 32],
}

impl HeaderCheckpoint {
    /// Scala `checkpointCondition`: pass unless the header is at exactly the
    /// checkpoint height with a different id.
    pub fn check(&self, height: u32, header_id: &[u8; 32]) -> Result<(), HeaderProcessError> {
        if height == self.height && header_id != &self.block_id {
            return Err(HeaderProcessError::CheckpointMismatch {
                height,
                expected: self.block_id,
                got: *header_id,
            });
        }
        Ok(())
    }
}

/// [`HeaderCheckpoint::check`] lifted over `Option` — no checkpoint
/// configured accepts every header, matching Scala's `getOrElse(true)`.
pub fn check_header_checkpoint(
    checkpoint: Option<HeaderCheckpoint>,
    height: u32,
    header_id: &[u8; 32],
) -> Result<(), HeaderProcessError> {
    match checkpoint {
        Some(c) => c.check(height, header_id),
        None => Ok(()),
    }
}

/// Check the first unapplied header on the current best branch. The committed
/// index covers its persisted ancestry; only a pending batch suffix needs a walk.
fn branch_session_blocked<S: HeaderSectionStore + ?Sized>(
    store: &S,
    mut id: [u8; 32],
    chain: &ergo_state::chain::ChainStateMeta,
) -> Result<bool, HeaderProcessError> {
    let first = chain.best_full_block_height + 1;
    while id != chain.best_full_block_id {
        let Some(meta) = store.get_header_meta(&id)? else {
            return Ok(false);
        };
        if meta.height < first {
            return Ok(false);
        }
        if meta.height == first {
            return Ok(store.is_invalid(&id)? && !store.is_durably_invalid(&id)?);
        }
        if store.get_header_id_at_height(meta.height)? == Some(id) {
            return match store.get_header_id_at_height(first)? {
                Some(first_id) => Ok(store.get_header_meta(&first_id)?.is_some()
                    && store.is_invalid(&first_id)?
                    && !store.is_durably_invalid(&first_id)?),
                None => Ok(false),
            };
        }
        id = meta.parent_id;
    }
    Ok(false)
}

/// Bound local escape work on constant-difficulty networks, where arbitrarily
/// long branches can tie. Sixteen heights allow short sibling recovery while
/// keeping per-header ancestry reads independent of the initial-sync gap.
pub(crate) const SESSION_PROMOTION_SEARCH_DEPTH: u32 = 16;

/// Candidates must reach the applied ID itself without crossing any invalid
/// header. Sparse local ancestry is ineligible, never a remote-parent error.
pub(super) fn branch_session_eligible<S: HeaderSectionStore + ?Sized>(
    store: &S,
    mut id: [u8; 32],
    chain: &ergo_state::chain::ChainStateMeta,
) -> Result<bool, ergo_state::store::StateError> {
    let mut walked = 0;
    while id != chain.best_full_block_id {
        if walked >= SESSION_PROMOTION_SEARCH_DEPTH {
            return Ok(false);
        }
        walked += 1;
        let Some(meta) = store.get_header_meta(&id)? else {
            return Ok(false);
        };
        if meta.height <= chain.best_full_block_height || store.is_invalid(&id)? {
            return Ok(false);
        }
        // Joining the committed best branch inherits its blocked first header.
        if store.get_header_id_at_height(meta.height)? == Some(id) {
            if let Some(first) = store.get_header_id_at_height(chain.best_full_block_height + 1)? {
                if store.is_invalid(&first)? {
                    return Ok(false);
                }
            }
        }
        id = meta.parent_id;
    }
    Ok(true)
}

/// Select by cumulative score, allowing an eligible branch to replace a
/// session-blocked branch on an exact tie. Local selection read failures must
/// not turn a fully linked remote header into an orphan or a peer penalty.
fn header_is_new_best<S: HeaderSectionStore + ?Sized>(
    store: &S,
    cumulative_score: &BigUint,
    parent_id: [u8; 32],
    chain: &ergo_state::chain::ChainStateMeta,
) -> bool {
    let current_best_score = BigUint::from_bytes_be(&chain.best_header_score);
    if *cumulative_score > current_best_score {
        return true;
    }
    if *cumulative_score != current_best_score {
        return false;
    }
    let selection = || -> Result<bool, HeaderProcessError> {
        Ok(
            store.has_session_mark_at_height(chain.best_full_block_height + 1)?
                && branch_session_blocked(store, chain.best_header_id, chain)?
                && branch_session_eligible(store, parent_id, chain)?,
        )
    };
    match selection() {
        Ok(eligible) => eligible,
        Err(error) => {
            tracing::warn!(%error, parent = %hex::encode(parent_id), best_full_height = chain.best_full_block_height, "local ancestry unavailable for session tie selection");
            false
        }
    }
}

/// Result of successfully processing a header.
#[derive(Debug)]
pub struct ProcessedHeader {
    pub header_id: [u8; 32],
    pub height: u32,
    pub parent_id: [u8; 32],
    /// True if this header became the new best header by score or an unblocked tie.
    pub is_new_best: bool,
    /// The parsed header's transactions_root, extension_root, ad_proofs_root
    /// for computing expected section IDs.
    pub transactions_root: [u8; 32],
    pub extension_root: [u8; 32],
    pub ad_proofs_root: [u8; 32],
    /// The parsed header, carried through so callers don't re-read from DB.
    pub header: ergo_ser::header::Header,
    /// The validated `CheckedHeader` proof. Plumbed out so consumers
    /// (executor::push_validated_header) consume the real proof produced
    /// by `validate_header_after_pow` instead of reconstructing one via
    /// `trust_me`.
    pub checked: CheckedHeader,
}

/// Process a raw header: deserialize, validate, persist, update chain state.
///
/// Returns `ProcessedHeader` with the info needed to request block sections.
/// A header that has been parsed and PoW-verified but not yet chain-linked
/// or persisted. This is the output of the parallelizable phase.
///
/// Carries an unforgeable `PowCheckedHeader` proof so the sequential
/// finalize phase does not re-verify PoW — there is exactly one PoW call
/// per header in either the single-header or batch path.
///
/// `Clone` is implemented so a header can be PoW'd once and re-used
/// across multiple `finalize_header` attempts (e.g. an orphan buffered
/// while waiting for its parent — re-trying finalize after the parent
/// arrives must not re-pay the PoW cost). `PowCheckedHeader` is a
/// proof-of-work wrapper over plain `Header` data; cloning preserves
/// the proof bit-for-bit.
#[derive(Clone)]
pub struct PreValidatedHeader {
    pow_checked: ergo_validation::header::PowCheckedHeader,
    pub parent_id: [u8; 32],
    pub height: u32,
}

impl PreValidatedHeader {
    pub fn header_id(&self) -> &[u8; 32] {
        self.pow_checked.header_id()
    }
    pub fn header(&self) -> &ergo_ser::header::Header {
        self.pow_checked.header()
    }

    /// Test-only constructor with no PoW. The contained
    /// `PowCheckedHeader` is bypass-built; never feed the inner
    /// header into chain validation. Used by orphan-buffer probe
    /// tests that exercise buffer mechanics (push / cap / pop) only.
    #[cfg(test)]
    pub fn for_test_unchecked(header_id: [u8; 32], parent_id: [u8; 32], height: u32) -> Self {
        use ergo_primitives::digest::{ADDigest, Digest32, ModifierId};
        use ergo_primitives::group_element::GroupElement;
        use ergo_ser::autolykos::AutolykosSolution;
        use ergo_ser::header::Header;
        let header = Header {
            version: 1,
            parent_id: ModifierId::from_bytes(parent_id),
            ad_proofs_root: Digest32::from_bytes([0u8; 32]),
            transactions_root: Digest32::from_bytes([0u8; 32]),
            state_root: ADDigest::from_bytes([0u8; 33]),
            timestamp: 0,
            extension_root: Digest32::from_bytes([0u8; 32]),
            n_bits: 0,
            height,
            votes: [0; 3],
            unparsed_bytes: Vec::new(),
            solution: AutolykosSolution::V2 {
                pk: GroupElement::from_bytes([0u8; 33]),
                nonce: [0u8; 8],
            },
        };
        Self {
            pow_checked: ergo_validation::header::PowCheckedHeader::for_test_unchecked(
                header, header_id,
            ),
            parent_id,
            height,
        }
    }
}

/// Phase 1 of header processing: parse + PoW verify. Pure computation,
/// no DB access, safe to run in parallel via rayon. Does not need a
/// `DifficultyParams` — PoW dispatch is on the solution variant (Scala parity).
#[tracing::instrument(skip_all, fields(block = tracing::field::Empty, height = tracing::field::Empty))]
pub fn pre_validate_header(header_bytes: &[u8]) -> Result<PreValidatedHeader, HeaderProcessError> {
    let header_id = *blake2b256(header_bytes).as_bytes();
    let mut reader = VlqReader::new(header_bytes);
    let header =
        read_header(&mut reader).map_err(|e| HeaderProcessError::Deserialize(format!("{e:?}")))?;
    // Enforce end-of-input at receive, matching the reload path
    // (`ergo-validation/src/header/mod.rs`) and the sibling receive sinks
    // (transaction, block-section, NiPoPoW-proof deserializers all reject
    // trailing bytes). Without this, a header delivered as
    // `canonical_bytes ++ trailing_junk` is accepted, and because
    // `header_id` is `blake2b256(header_bytes)` over the raw bytes, the same
    // block content enters under a non-canonical id.
    if reader.position() != header_bytes.len() {
        return Err(HeaderProcessError::Deserialize(format!(
            "trailing bytes after header: parsed {} of {} bytes",
            reader.position(),
            header_bytes.len()
        )));
    }
    let span = tracing::Span::current();
    span.record("block", hex::encode(header_id));
    span.record("height", header.height);

    // JVM parity: Scala curve-checks every group element at deserialize
    // time, including the Autolykos solution pk. The v2+ PoW hit depends
    // only on (msg, nonce, height), so without this drain an off-curve or
    // bad-prefix pk would parse cleanly, pass PoW, and split the chain
    // against JVM nodes. Runs before PoW so a poisoned pk is rejected on
    // its own (cheapest-specific) verdict.
    let group_elements = reader.take_group_elements();
    ergo_validation::header::validate_header_group_elements(&group_elements)
        .map_err(HeaderProcessError::Validation)?;

    let parent_id = *header.parent_id.as_bytes();
    let height = header.height;

    let pow_checked = ergo_validation::header::PowCheckedHeader::verify_pow(header, header_id)
        .map_err(HeaderProcessError::Validation)?;

    Ok(PreValidatedHeader {
        pow_checked,
        parent_id,
        height,
    })
}

/// Phase 2 of header processing: chain linkage + difficulty + persist.
/// Sequential, requires DB access. Caller provides the raw header bytes
/// (not cloned into PreValidatedHeader to avoid duplicate allocations).
///
/// `checkpoint` is the operator-supplied header-level trust anchor
/// ([`HeaderCheckpoint`]); `None` disables it (Scala's default).
/// `genesis_id` is the operator-supplied first mined header id; `None`
/// disables that check.
pub fn finalize_header<S: HeaderSectionStore + ChainStateRead + ?Sized>(
    store: &mut S,
    pre: PreValidatedHeader,
    header_bytes: &[u8],
    config: &DifficultyParams,
    checkpoint: Option<HeaderCheckpoint>,
    genesis_id: Option<[u8; 32]>,
) -> Result<ProcessedHeader, HeaderProcessError> {
    let header_id = *pre.pow_checked.header_id();
    if pre.height == 1 && pre.parent_id == [0u8; 32] {
        if let Some(expected) = genesis_id {
            if header_id != expected {
                return Err(HeaderProcessError::GenesisIdMismatch {
                    expected,
                    got: header_id,
                });
            }
        }
    }
    // Already known?
    if store.get_header(&header_id)?.is_some() {
        return Err(HeaderProcessError::AlreadyKnown { header_id });
    }
    if store.is_invalid(&header_id)? {
        return Err(HeaderProcessError::Invalid { header_id });
    }

    // Genesis special case — genesis runs its own PoW + initial-difficulty
    // path and doesn't use the proof-consuming validator.
    if pre.height == 1 && pre.parent_id == [0u8; 32] {
        let header = pre.pow_checked.header().clone();
        return process_genesis_header(store, header, header_id, header_bytes, config);
    }

    // Header-level checkpoint (Scala `hdrCheckpoint`,
    // `HeadersProcessor.scala:428` + `:437-443`). Placed after the genesis
    // branch because Scala's `validateGenesisBlockHeader` carries no
    // `hdrCheckpoint` rule. A mismatch is an INVALID header: the caller's
    // catch-all error arm reports it and penalises the sending peer exactly
    // as it does for a bad PoW or a broken difficulty.
    check_header_checkpoint(checkpoint, pre.height, &header_id)?;

    // Chain linkage + difficulty (needs parent from store). Consumes the
    // PoW proof to skip re-verification.
    process_header_inner(store, pre.pow_checked, header_bytes, config)
}

/// Process a header using mainnet chain config. Convenience wrapper.
pub fn process_header<S: HeaderSectionStore + ChainStateRead + ?Sized>(
    store: &mut S,
    header_bytes: &[u8],
) -> Result<ProcessedHeader, HeaderProcessError> {
    process_header_cfg(store, header_bytes, &DifficultyParams::mainnet(), None)
}

/// Process a raw header with network-specific chain configuration.
/// Does everything: parse, PoW, chain linkage, difficulty, persist.
///
/// Thin wrapper over the two-phase primitives. The shadow-duplicate
/// preflight that used to live here (get_header / is_invalid / genesis
/// branch) is now handled by `finalize_header` — single code path.
pub fn process_header_cfg<S: HeaderSectionStore + ChainStateRead + ?Sized>(
    store: &mut S,
    header_bytes: &[u8],
    config: &DifficultyParams,
    checkpoint: Option<HeaderCheckpoint>,
) -> Result<ProcessedHeader, HeaderProcessError> {
    process_header_cfg_with_genesis(store, header_bytes, config, checkpoint, None)
}

/// Process a raw header with network-specific chain configuration and an
/// optional configured genesis id.
pub fn process_header_cfg_with_genesis<S: HeaderSectionStore + ChainStateRead + ?Sized>(
    store: &mut S,
    header_bytes: &[u8],
    config: &DifficultyParams,
    checkpoint: Option<HeaderCheckpoint>,
    genesis_id: Option<[u8; 32]>,
) -> Result<ProcessedHeader, HeaderProcessError> {
    let pre = pre_validate_header(header_bytes)?;
    finalize_header(store, pre, header_bytes, config, checkpoint, genesis_id)
}

/// Chain linkage + difficulty + persist. Shared by process_header_cfg and finalize_header.
///
/// Consumes a [`PowCheckedHeader`] — PoW was already verified in phase 1
/// (or upfront in `process_header_cfg`) and is not re-run here.
fn process_header_inner<S: HeaderSectionStore + ChainStateRead + ?Sized>(
    store: &mut S,
    pow_checked: ergo_validation::header::PowCheckedHeader,
    header_bytes: &[u8],
    config: &DifficultyParams,
) -> Result<ProcessedHeader, HeaderProcessError> {
    let header_id = *pow_checked.header_id();
    let header = pow_checked.header().clone();
    let parent_id = *header.parent_id.as_bytes();
    let height = header.height;

    // Refuse to extend a branch already reported invalid. `finalize_header`
    // rejects a header whose own id is flagged, but a NEVER-SEEN header
    // building on an invalidated parent has no flag of its own yet — the
    // parent check is what makes invalidity hereditary and permanent (Scala
    // `HeadersProcessor.validate` fails a header whose parent
    // `isSemanticallyValid == Invalid`). Without it a peer could re-feed the
    // dead branch one header at a time and re-grow best_header above the
    // re-anchor, re-wedging the apply loop.
    //
    // DURABLE-only: a session-scoped mark is a transient/IO verdict (the parent
    // may still apply), so it must not permanently block the whole descendant
    // subtree for the session. Scala's parent check tests the durable
    // `isSemanticallyValid == Invalid` row.
    if store.is_durably_invalid(&parent_id)? {
        return Err(HeaderProcessError::Invalid { header_id });
    }

    // Look up parent
    let parent_bytes = store
        .get_header(&parent_id)?
        .ok_or(HeaderProcessError::ParentNotFound { parent_id })?;
    let parent_header = {
        let mut r = VlqReader::new(&parent_bytes);
        read_header(&mut r)
            .map_err(|e| HeaderProcessError::Deserialize(format!("parent: {e:?}")))?
    };
    let parent_meta = store
        .get_header_meta(&parent_id)?
        .ok_or(HeaderProcessError::ParentNotFound { parent_id })?;

    // 5b. Verify height = parent.height + 1
    let expected_height = parent_meta.height + 1;
    if height != expected_height {
        return Err(HeaderProcessError::HeightMismatch {
            expected: expected_height,
            got: height,
        });
    }

    // 6. Collect epoch headers for difficulty recalculation.
    // Uses ergo-crypto's previous_heights_for_recalculation to determine
    // which heights are needed. For non-boundary blocks, just the parent.
    // For boundary blocks, up to 9 headers (8 previous epochs + parent).
    //
    // Policy for missing headers:
    // - Height 0: always skipped (Ergo genesis is height 1, no block 0).
    // - Other heights: skipped only during early-chain sync when earlier
    //   epochs don't exist yet (e.g., first boundary at 1025 requests
    //   height 0). The Scala node uses flatMap(bestHeaderAtHeight) which
    //   silently drops heights without headers. We match that behavior.
    //
    // What the difficulty layer does with the (possibly reduced) window:
    // - Pre-EIP-37 `calculate` accepts `len == 1` and falls back to the
    //   parent's normalized difficulty (Scala-parity).
    // - EIP-37 `eip37_calculate` requires `len >= 2`; the `_checked`
    //   helper in ergo-crypto returns
    //   `DifficultyError::MissingEpochHeaders` if the window is
    //   undersized. That escapes here as
    //   `HeaderValidationError::Difficulty(MissingEpochHeaders)` and is
    //   remapped below to `HeaderProcessError::EpochContextIncomplete`
    //   so the executor can buffer-and-retry instead of penalizing the
    //   peer who delivered the header.
    let epoch_len = epoch_length_for_height(height, config);
    let required_heights = previous_heights_for_recalculation(height, epoch_len);
    let mut epoch_headers = Vec::with_capacity(required_heights.len());
    for &h in &required_heights {
        if h == parent_meta.height {
            epoch_headers.push(parent_header.clone());
        } else if h == 0 {
            continue; // no block at height 0
        } else {
            match find_header_at_height(store, &parent_id, parent_meta.height, h) {
                Ok(header_at_h) => epoch_headers.push(header_at_h),
                Err(HeaderProcessError::EpochHeaderMissing { .. }) => continue,
                Err(e) => return Err(e),
            }
        }
    }

    // 7a. Wall-clock future-timestamp check (Scala `hdrFutureTimestamp`,
    // rule 211). Scala marks this recoverable because a peer's clock
    // can be ahead of ours; we surface it as a rejection here and let
    // the coordinator decide whether to retry. Read `now_ms` once at
    // the ingress point so retries against a later clock can succeed
    // naturally.
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(u64::MAX);
    if let Err(e) = ergo_validation::header::check_future_timestamp(&header, now_ms) {
        return Err(HeaderProcessError::Validation(e));
    }

    // 7b. Post-PoW validation: parent, timestamp, vote dedup/contradict,
    // difficulty. Consumes the proof; does NOT re-verify PoW.
    //
    // Intercept *only* the precise error
    // `Difficulty(DifficultyError::MissingEpochHeaders)` and remap it to
    // `EpochContextIncomplete`. Any other Difficulty variant
    // (NbitsMismatch, HeightMismatch) is a real consensus rejection and
    // must continue to flow through `Validation(...)`. **Critical
    // guardrail: this remap never short-circuits to "accept without
    // difficulty validation"; it only changes how the error is
    // classified by the sync executor.**
    let checked = match ergo_validation::header::validate_header_after_pow(
        pow_checked,
        &parent_id,
        &parent_header,
        &epoch_headers,
        config,
    ) {
        Ok(checked) => checked,
        Err(HeaderValidationError::Difficulty(
            ergo_crypto::pow::DifficultyError::MissingEpochHeaders,
        )) => {
            return Err(HeaderProcessError::EpochContextIncomplete { height, parent_id });
        }
        Err(e) => return Err(HeaderProcessError::Validation(e)),
    };

    // 8. Compute cumulative score: parent_score + this_header's required difficulty.
    // Uses ergo_ser::difficulty::decode_compact_bits (shared with ergo-crypto),
    // not a local reimplementation. BigUint → bytes only at the storage boundary.
    let parent_score = BigUint::from_bytes_be(&parent_meta.cumulative_score);
    let header_difficulty = decode_compact_bits(header.n_bits);
    let cumulative_score = parent_score + header_difficulty;
    let score_bytes = cumulative_score.to_bytes_be();

    // 9. Select by score, allowing an eligible escape from a session-blocked tie.
    let chain = store.chain_state_meta();
    let is_new_best = header_is_new_best(store, &cumulative_score, parent_id, &chain);

    // 10. Persist header + meta + optional best-header in one redb transaction.
    let meta = HeaderMeta {
        parent_id,
        height,
        cumulative_score: score_bytes.clone(),
        pow_validity: 1, // valid
        timestamp: header.timestamp,
    };
    let new_best = if is_new_best {
        Some((height, score_bytes))
    } else {
        None
    };
    store.store_validated_header(&header_id, header_bytes, &meta, new_best)?;

    // 11. Extract roots for section ID computation
    let transactions_root = *header.transactions_root.as_bytes();
    let extension_root = *header.extension_root.as_bytes();
    let ad_proofs_root = *header.ad_proofs_root.as_bytes();

    Ok(ProcessedHeader {
        header_id,
        height,
        parent_id,
        is_new_best,
        transactions_root,
        extension_root,
        ad_proofs_root,
        header,
        checked,
    })
}

/// Process the genesis header (height 1). Matches Scala's
/// validateGenesisBlockHeader (HeadersProcessor.scala:402):
/// - parentId == all-zeros
/// - height == 1
/// - requiredDifficulty == chainSettings.initialDifficulty
/// - PoW valid
///
/// No parent header lookup, no timestamp check against parent.
fn process_genesis_header<S: HeaderSectionStore + ?Sized>(
    store: &mut S,
    header: ergo_ser::header::Header,
    header_id: [u8; 32],
    header_bytes: &[u8],
    config: &DifficultyParams,
) -> Result<ProcessedHeader, HeaderProcessError> {
    use ergo_crypto::pow::verify_pow_solution;
    use ergo_ser::difficulty::{decode_compact_bits, encode_compact_bits};
    use num_bigint::BigUint;

    // 1. Validate PoW
    verify_pow_solution(&header).map_err(|e| {
        HeaderProcessError::Validation(ergo_validation::header::HeaderValidationError::Pow(e))
    })?;

    // 2. Validate requiredDifficulty == initialDifficulty (Scala parity)
    let initial_diff = BigUint::from_bytes_be(&config.initial_difficulty);
    let initial_nbits = encode_compact_bits(&initial_diff);
    let header_diff = decode_compact_bits(header.n_bits);
    let header_diff_nbits = encode_compact_bits(&header_diff);
    if header_diff_nbits != initial_nbits {
        return Err(HeaderProcessError::Validation(
            ergo_validation::header::HeaderValidationError::Difficulty(
                ergo_crypto::pow::DifficultyError::NbitsMismatch {
                    height: 1,
                    expected: initial_nbits,
                    actual: header.n_bits,
                },
            ),
        ));
    }

    // Cumulative score = initial difficulty
    let score = initial_diff.to_bytes_be();

    let meta = ergo_state::chain::HeaderMeta {
        parent_id: [0u8; 32],
        height: 1,
        cumulative_score: score.clone(),
        pow_validity: 1,
        timestamp: header.timestamp,
    };
    store.store_validated_header(&header_id, header_bytes, &meta, Some((1, score)))?;

    let transactions_root = *header.transactions_root.as_bytes();
    let extension_root = *header.extension_root.as_bytes();
    let ad_proofs_root = *header.ad_proofs_root.as_bytes();

    // Genesis bypasses `validate_header_after_pow` (no parent), so the
    // CheckedHeader proof is reconstructed via the strict
    // `from_persisted_parts` path: it re-parses the canonical bytes,
    // verifies blake2b256(bytes) == header_id, EOF, and meta consistency.
    // PoW + initial-difficulty were validated above; pow_validity = 1
    // is therefore honest.
    let checked = CheckedHeader::from_persisted_parts(
        header_bytes,
        header_id,
        1,
        1,
        [0u8; 32],
        header.timestamp,
    )
    .map_err(HeaderProcessError::Validation)?;

    Ok(ProcessedHeader {
        header_id,
        height: 1,
        parent_id: [0u8; 32],
        is_new_best: true,
        transactions_root,
        extension_root,
        ad_proofs_root,
        header,
        checked,
    })
}

/// Walk backwards from a known header to find the header ID at `target_height`.
/// Returns the header_id without loading/parsing the header bytes.
pub fn find_header_id_at_height<S: HeaderSectionStore + ?Sized>(
    store: &S,
    start_id: &[u8; 32],
    start_height: u32,
    target_height: u32,
) -> Result<[u8; 32], HeaderProcessError> {
    if target_height > start_height {
        return Err(HeaderProcessError::EpochHeaderMissing {
            height: target_height,
        });
    }
    let mut current_id = *start_id;
    let mut current_height = start_height;
    while current_height > target_height {
        let meta =
            store
                .get_header_meta(&current_id)?
                .ok_or(HeaderProcessError::EpochHeaderMissing {
                    height: current_height,
                })?;
        current_id = meta.parent_id;
        current_height -= 1;
    }
    Ok(current_id)
}

/// Walk backwards from a known header to find the header at `target_height`.
/// Uses header_meta parent_id chain to navigate.
pub fn find_header_at_height<S: HeaderSectionStore + ?Sized>(
    store: &S,
    start_id: &[u8; 32],
    start_height: u32,
    target_height: u32,
) -> Result<ergo_ser::header::Header, HeaderProcessError> {
    if target_height > start_height {
        return Err(HeaderProcessError::EpochHeaderMissing {
            height: target_height,
        });
    }
    let mut current_id = *start_id;
    let mut current_height = start_height;
    while current_height > target_height {
        let meta =
            store
                .get_header_meta(&current_id)?
                .ok_or(HeaderProcessError::EpochHeaderMissing {
                    height: current_height,
                })?;
        current_id = meta.parent_id;
        current_height -= 1;
    }
    // Now current_id should be at target_height — load and parse it.
    let header_bytes =
        store
            .get_header(&current_id)?
            .ok_or(HeaderProcessError::EpochHeaderMissing {
                height: target_height,
            })?;
    let mut r = VlqReader::new(&header_bytes);
    read_header(&mut r).map_err(|e| {
        HeaderProcessError::Deserialize(format!("epoch header at {target_height}: {e:?}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use ergo_state::store::StateError;

    // ----- helpers -----

    struct CountingStore {
        inner: ergo_state::store::StateStore,
        reads: std::cell::Cell<usize>,
        fail_on: Option<[u8; 32]>,
    }

    impl HeaderSectionStore for CountingStore {
        fn has_session_mark_at_height(&self, height: u32) -> Result<bool, StateError> {
            self.inner.has_session_mark_at_height(height)
        }

        fn get_header(&self, header_id: &[u8; 32]) -> Result<Option<Vec<u8>>, StateError> {
            ergo_state::store::StateStore::get_header(&self.inner, header_id)
        }
        fn get_header_meta(&self, header_id: &[u8; 32]) -> Result<Option<HeaderMeta>, StateError> {
            self.reads.set(self.reads.get() + 1);
            if self.fail_on == Some(*header_id) {
                return Err(StateError::InvalidPrecondition {
                    what: "injected local read failure",
                });
            }
            ergo_state::store::StateStore::get_header_meta(&self.inner, header_id)
        }
        fn get_header_id_at_height(&self, height: u32) -> Result<Option<[u8; 32]>, StateError> {
            ergo_state::store::StateStore::get_header_id_at_height(&self.inner, height)
        }
        fn get_block_section(&self, modifier_id: &[u8; 32]) -> Result<Option<Vec<u8>>, StateError> {
            ergo_state::store::StateStore::get_block_section(&self.inner, modifier_id)
        }
        fn get_section_height(&self, section_id: &[u8; 32]) -> Result<Option<u32>, StateError> {
            ergo_state::store::StateStore::get_section_height(&self.inner, section_id)
        }
        fn scan_header_chain_range(
            &self,
            lo: u32,
            hi: u32,
        ) -> Result<Vec<(u32, [u8; 32])>, StateError> {
            ergo_state::store::StateStore::scan_header_chain_range(&self.inner, lo, hi)
        }
        fn store_header(
            &self,
            header_id: &[u8; 32],
            header_bytes: &[u8],
        ) -> Result<(), StateError> {
            ergo_state::store::StateStore::store_header(&self.inner, header_id, header_bytes)
        }
        fn store_validated_header(
            &mut self,
            header_id: &[u8; 32],
            header_bytes: &[u8],
            meta: &HeaderMeta,
            new_best: Option<(u32, Vec<u8>)>,
        ) -> Result<(), StateError> {
            ergo_state::store::StateStore::store_validated_header(
                &mut self.inner,
                header_id,
                header_bytes,
                meta,
                new_best,
            )
        }
        fn store_block_section_typed(
            &self,
            modifier_id: &[u8; 32],
            section_bytes: &[u8],
            section_type: u8,
        ) -> Result<(), StateError> {
            ergo_state::store::StateStore::store_block_section_typed(
                &self.inner,
                modifier_id,
                section_bytes,
                section_type,
            )
        }
        fn store_block_sections_durable(
            &self,
            sections: &[(&[u8; 32], &[u8], u8)],
        ) -> Result<(), StateError> {
            ergo_state::store::StateStore::store_block_sections_durable(&self.inner, sections)
        }
        fn begin_header_batch(&mut self) {
            ergo_state::store::StateStore::begin_header_batch(&mut self.inner)
        }
        fn flush_header_batch(&mut self) -> Result<(), StateError> {
            ergo_state::store::StateStore::flush_header_batch(&mut self.inner)
        }
        fn mark_session_invalid(&mut self, header_id: [u8; 32]) {
            ergo_state::store::StateStore::mark_session_invalid(&mut self.inner, header_id)
        }
        fn invalidate_validation_branch(
            &mut self,
            header_id: [u8; 32],
        ) -> Result<Vec<[u8; 32]>, StateError> {
            ergo_state::store::StateStore::invalidate_validation_branch(&mut self.inner, header_id)
        }
        fn is_invalid(&self, header_id: &[u8; 32]) -> Result<bool, StateError> {
            ergo_state::store::StateStore::is_invalid(&self.inner, header_id)
        }
        fn is_durably_invalid(&self, header_id: &[u8; 32]) -> Result<bool, StateError> {
            ergo_state::store::StateStore::is_durably_invalid(&self.inner, header_id)
        }
        fn reader_handle(&self) -> ergo_state::reader::ChainStoreReader {
            ergo_state::store::StateStore::reader_handle(&self.inner)
        }
        fn shutdown_cleanly(&mut self) -> Result<(), StateError> {
            ergo_state::store::StateStore::shutdown_cleanly(&mut self.inner)
        }
    }

    fn id(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn blocked_branch_fixture(
        validity: u8,
        marked: bool,
    ) -> (tempfile::TempDir, ergo_state::store::StateStore) {
        let dir = tempfile::tempdir().unwrap();
        let mut store =
            ergo_state::store::StateStore::open(&dir.path().join("state.redb")).unwrap();
        for (byte, parent, height) in [(1, 0, 1), (2, 1, 2)] {
            store
                .store_validated_header(
                    &id(byte),
                    &[byte; 8],
                    &HeaderMeta {
                        parent_id: id(parent),
                        height,
                        cumulative_score: vec![byte],
                        pow_validity: if byte == 1 { validity } else { 1 },
                        timestamp: u64::from(height),
                    },
                    Some((height, vec![byte])),
                )
                .unwrap();
        }
        if marked {
            store.mark_session_invalid(id(1));
        }
        (dir, store)
    }

    // ----- happy path -----

    #[test]
    fn header_tie_without_session_marks_performs_no_ancestor_reads() {
        let (_dir, inner) = blocked_branch_fixture(1, false);
        let store = CountingStore {
            inner,
            reads: std::cell::Cell::new(0),
            fail_on: None,
        };
        let chain = store.inner.chain_state_meta();
        assert!(!header_is_new_best(
            &store,
            &BigUint::from(2u8),
            id(0),
            &chain
        ));
        assert_eq!(
            store.reads.get(),
            0,
            "ordinary ties must not walk ancestors"
        );
    }

    #[test]
    fn header_tie_with_session_mark_prefers_only_eligible_branch() {
        let (_dir, inner) = blocked_branch_fixture(1, true);
        let store = CountingStore {
            inner,
            reads: std::cell::Cell::new(0),
            fail_on: None,
        };
        let chain = store.inner.chain_state_meta();
        assert!(header_is_new_best(
            &store,
            &BigUint::from(2u8),
            id(0),
            &chain
        ));
        assert!(!header_is_new_best(
            &store,
            &BigUint::from(2u8),
            id(1),
            &chain
        ));
    }

    #[test]
    fn blocked_branch_first_unapplied_session_mark_detected() {
        let (_dir, store) = blocked_branch_fixture(1, true);
        assert!(branch_session_blocked(&store, id(2), &store.chain_state_meta()).unwrap());
    }

    #[test]
    fn header_tie_stale_mark_below_applied_tip_skips_ancestry() {
        let (_dir, mut inner) = blocked_branch_fixture(1, true);
        for h in 3..=200u8 {
            inner
                .store_validated_header(
                    &id(h),
                    &[h; 8],
                    &HeaderMeta {
                        parent_id: id(h - 1),
                        height: u32::from(h),
                        cumulative_score: vec![h],
                        pow_validity: 1,
                        timestamp: u64::from(h),
                    },
                    Some((u32::from(h), vec![h])),
                )
                .unwrap();
        }
        let mut chain = inner.chain_state_meta();
        chain.best_full_block_height = 100;
        chain.best_full_block_id = id(100);
        let store = CountingStore {
            inner,
            reads: std::cell::Cell::new(0),
            fail_on: None,
        };
        assert!(!header_is_new_best(
            &store,
            &BigUint::from(200u8),
            id(199),
            &chain
        ));
        assert_eq!(store.reads.get(), 0);
    }

    #[test]
    fn header_tie_pending_batch_uses_selected_overlay() {
        let (_dir, mut store) = blocked_branch_fixture(1, true);
        store.begin_header_batch();
        for (byte, parent, height) in [(3, 2, 3), (4, 0, 1), (5, 4, 2)] {
            store
                .store_validated_header(
                    &id(byte),
                    &[byte; 8],
                    &HeaderMeta {
                        parent_id: id(parent),
                        height,
                        cumulative_score: vec![height as u8],
                        pow_validity: 1,
                        timestamp: u64::from(height),
                    },
                    Some((height, vec![height as u8])),
                )
                .unwrap();
            let chain = store.chain_state_meta();
            let selected = header_is_new_best(&store, &BigUint::from(height), id(0), &chain);
            assert_eq!(selected, byte == 3, "pending header {byte}");
        }
        store.flush_header_batch().unwrap();
    }

    #[test]
    fn header_tie_long_blocked_chain_uses_committed_index() {
        let (_dir, mut inner) = blocked_branch_fixture(1, true);
        for h in 3..=200u8 {
            inner
                .store_validated_header(
                    &id(h),
                    &[h; 8],
                    &HeaderMeta {
                        parent_id: id(h - 1),
                        height: u32::from(h),
                        cumulative_score: vec![h],
                        pow_validity: 1,
                        timestamp: u64::from(h),
                    },
                    Some((u32::from(h), vec![h])),
                )
                .unwrap();
        }
        let chain = inner.chain_state_meta();
        let store = CountingStore {
            inner,
            reads: std::cell::Cell::new(0),
            fail_on: None,
        };
        assert!(!header_is_new_best(
            &store,
            &BigUint::from(200u8),
            id(199),
            &chain
        ));
        assert!(store.reads.get() <= 4, "reads: {}", store.reads.get());
    }

    #[test]
    fn header_tie_unknown_mark_skips_ancestry() {
        let (_dir, mut inner) = blocked_branch_fixture(1, false);
        inner.mark_session_invalid(id(99));
        let chain = inner.chain_state_meta();
        let store = CountingStore {
            inner,
            reads: std::cell::Cell::new(0),
            fail_on: None,
        };
        assert!(!header_is_new_best(
            &store,
            &BigUint::from(2u8),
            id(0),
            &chain
        ));
        assert_eq!(store.reads.get(), 0);
    }

    #[test]
    fn applied_anchor_needs_no_ancestry_reads() {
        let (_dir, inner) = blocked_branch_fixture(1, false);
        let mut chain = inner.chain_state_meta();
        chain.best_full_block_height = 1;
        chain.best_full_block_id = id(9);
        let store = CountingStore {
            inner,
            reads: std::cell::Cell::new(0),
            fail_on: None,
        };
        assert!(!branch_session_blocked(&store, id(9), &chain).unwrap());
        assert!(branch_session_eligible(&store, id(9), &chain).unwrap());
        assert_eq!(store.reads.get(), 0);
    }

    #[test]
    fn checkpoint_matching_id_at_checkpoint_height_accepts() {
        let ckpt = HeaderCheckpoint {
            height: 100,
            block_id: id(0xaa),
        };
        assert!(ckpt.check(100, &id(0xaa)).is_ok());
    }

    #[test]
    fn checkpoint_header_below_checkpoint_height_unaffected() {
        // Scala `checkpointCondition` returns true for every height that is
        // not the checkpoint height — the checkpoint neither rejects NOR
        // trusts anything below it.
        let ckpt = HeaderCheckpoint {
            height: 100,
            block_id: id(0xaa),
        };
        assert!(ckpt.check(99, &id(0xbb)).is_ok());
    }

    #[test]
    fn checkpoint_header_above_checkpoint_height_unaffected() {
        let ckpt = HeaderCheckpoint {
            height: 100,
            block_id: id(0xaa),
        };
        assert!(ckpt.check(101, &id(0xbb)).is_ok());
    }

    #[test]
    fn checkpoint_absent_accepts_every_header() {
        assert!(check_header_checkpoint(None, 100, &id(0xbb)).is_ok());
    }

    #[test]
    fn cumulative_score_uses_shared_decoder() {
        // Verify that decode_compact_bits from ergo-ser produces correct
        // BigUint values that convert cleanly to big-endian bytes for storage.
        let nbits = 0x1a_01_76_5e_u32;
        let difficulty = decode_compact_bits(nbits);
        let bytes = difficulty.to_bytes_be();
        assert!(!bytes.is_empty());
        // Roundtrip: bytes → BigUint → bytes should be identity
        let restored = BigUint::from_bytes_be(&bytes);
        assert_eq!(restored, difficulty);
    }

    #[test]
    fn score_accumulation_via_biguint() {
        let parent_score = BigUint::from(1000u64);
        let difficulty = BigUint::from(500u64);
        let result = parent_score + difficulty;
        assert_eq!(result, BigUint::from(1500u64));
        // Bytes roundtrip
        let bytes = result.to_bytes_be();
        assert_eq!(BigUint::from_bytes_be(&bytes), BigUint::from(1500u64));
    }

    // ----- error paths -----

    #[test]
    fn header_tie_local_read_failure_does_not_reject_header() {
        let (_dir, inner) = blocked_branch_fixture(1, true);
        let chain = inner.chain_state_meta();
        let store = CountingStore {
            inner,
            reads: std::cell::Cell::new(0),
            fail_on: Some(id(2)),
        };
        assert!(!header_is_new_best(
            &store,
            &BigUint::from(2u8),
            id(0),
            &chain
        ));
    }

    #[test]
    fn header_tie_missing_ancestor_not_orphan() {
        let (_dir, mut store) = blocked_branch_fixture(1, true);
        store
            .store_validated_header(
                &id(3),
                &[3; 8],
                &HeaderMeta {
                    parent_id: id(99),
                    height: 3,
                    cumulative_score: vec![3],
                    pow_validity: 1,
                    timestamp: 3,
                },
                None,
            )
            .unwrap();
        let mut chain = store.chain_state_meta();
        chain.best_header_id = id(99);
        chain.best_header_score = vec![3];
        assert!(!branch_session_blocked(&store, id(99), &chain).unwrap());
        assert!(!header_is_new_best(
            &store,
            &BigUint::from(3u8),
            id(0),
            &chain
        ));
        assert!(!branch_session_eligible(&store, id(3), &chain).unwrap());
    }

    #[test]
    fn header_tie_below_applied_fork_ineligible() {
        let (_dir, mut store) = blocked_branch_fixture(1, true);
        store.mark_session_invalid(id(2));
        let mut chain = store.chain_state_meta();
        chain.best_full_block_height = 1;
        chain.best_full_block_id = id(9);
        assert!(!header_is_new_best(
            &store,
            &BigUint::from(2u8),
            id(1),
            &chain
        ));
    }

    #[test]
    fn candidate_intermediate_mark_makes_branch_ineligible() {
        let (_dir, mut store) = blocked_branch_fixture(1, true);
        for (byte, parent, height) in [(4, 0, 1), (5, 4, 2)] {
            store
                .store_validated_header(
                    &id(byte),
                    &[byte; 8],
                    &HeaderMeta {
                        parent_id: id(parent),
                        height,
                        cumulative_score: vec![height as u8],
                        pow_validity: 1,
                        timestamp: u64::from(height),
                    },
                    None,
                )
                .unwrap();
        }
        store.mark_session_invalid(id(4));
        assert!(!branch_session_eligible(&store, id(5), &store.chain_state_meta()).unwrap());
    }

    #[test]
    fn candidate_below_applied_height_stops_immediately() {
        let (_dir, inner) = blocked_branch_fixture(1, false);
        let mut chain = inner.chain_state_meta();
        chain.best_full_block_height = 1;
        chain.best_full_block_id = id(9);
        let store = CountingStore {
            inner,
            reads: std::cell::Cell::new(0),
            fail_on: None,
        };
        assert!(!branch_session_eligible(&store, id(1), &chain).unwrap());
        assert_eq!(store.reads.get(), 1);
        store.reads.set(0);
        assert!(!branch_session_blocked(&store, id(1), &chain).unwrap());
        assert_eq!(store.reads.get(), 1);
    }

    #[test]
    fn candidate_long_off_index_fork_bounds_reads() {
        let (_dir, mut inner) = blocked_branch_fixture(1, true);
        for h in 3..=200u8 {
            inner
                .store_validated_header(
                    &id(h),
                    &[h; 8],
                    &HeaderMeta {
                        parent_id: id(h - 1),
                        height: u32::from(h),
                        cumulative_score: vec![h],
                        pow_validity: 1,
                        timestamp: u64::from(h),
                    },
                    None,
                )
                .unwrap();
        }
        let mut chain = inner.chain_state_meta();
        chain.best_full_block_height = 10;
        chain.best_full_block_id = id(250);
        let store = CountingStore {
            inner,
            reads: std::cell::Cell::new(0),
            fail_on: None,
        };
        assert!(!branch_session_eligible(&store, id(200), &chain).unwrap());
        assert!(
            store.reads.get() <= SESSION_PROMOTION_SEARCH_DEPTH as usize,
            "reads: {}",
            store.reads.get()
        );
    }

    #[test]
    fn blocked_branch_durable_or_absent_mark_not_session_blocked() {
        for (validity, marked) in [(1, false), (2, false), (3, false), (3, true)] {
            let (_dir, store) = blocked_branch_fixture(validity, marked);
            assert!(!branch_session_blocked(&store, id(2), &store.chain_state_meta()).unwrap());
            assert!(!branch_session_blocked(&store, id(1), &store.chain_state_meta()).unwrap());
        }
    }

    #[test]
    fn blocked_branch_at_or_below_applied_tip_not_blocked() {
        let (_dir, store) = blocked_branch_fixture(1, true);
        let mut chain = store.chain_state_meta();
        chain.best_full_block_height = 1;
        chain.best_full_block_id = id(9);
        assert!(!branch_session_blocked(&store, id(1), &chain).unwrap());
        // The applied anchor needs no parent lookup, at this nonzero height.
        assert!(!branch_session_blocked(&store, id(9), &chain).unwrap());
    }

    #[test]
    fn checkpoint_mismatching_id_at_checkpoint_height_errors() {
        let ckpt = HeaderCheckpoint {
            height: 100,
            block_id: id(0xaa),
        };
        let err = ckpt
            .check(100, &id(0xbb))
            .expect_err("wrong id at the checkpoint height must be rejected");
        match err {
            HeaderProcessError::CheckpointMismatch {
                height,
                expected,
                got,
            } => {
                assert_eq!(height, 100);
                assert_eq!(expected, id(0xaa));
                assert_eq!(got, id(0xbb));
            }
            other => panic!("expected CheckpointMismatch, got {other:?}"),
        }
    }
}
