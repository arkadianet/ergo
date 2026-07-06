//! Header processing pipeline: deserialize → validate → persist → update chain state.
//!
//! Handles the coordinator's ValidateHeader action by:
//! 1. Deserializing raw header bytes (ergo-ser)
//! 2. Computing header ID (blake2b256)
//! 3. Looking up parent header from state store
//! 4. Running full header validation (PoW, difficulty, linkage)
//! 5. Computing cumulative score
//! 6. Persisting header + header_meta
//! 7. Updating best_header if this header has higher cumulative score

use ergo_crypto::difficulty::{
    epoch_length_for_height, previous_heights_for_recalculation, DifficultyParams,
};
use ergo_primitives::digest::blake2b256;
use ergo_primitives::reader::VlqReader;
use ergo_ser::difficulty::decode_compact_bits;
use ergo_ser::header::read_header;
use ergo_state::chain::HeaderMeta;
use ergo_state::store::StateStore;
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
    #[error("validation failed: {0}")]
    Validation(#[from] HeaderValidationError),
    #[error("storage error: {0}")]
    Storage(#[from] ergo_state::store::StateError),
}

/// Result of successfully processing a header.
#[derive(Debug)]
pub struct ProcessedHeader {
    pub header_id: [u8; 32],
    pub height: u32,
    pub parent_id: [u8; 32],
    /// True if this header became the new best header (higher cumulative score).
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
pub fn pre_validate_header(header_bytes: &[u8]) -> Result<PreValidatedHeader, HeaderProcessError> {
    let header_id = *blake2b256(header_bytes).as_bytes();
    let mut reader = VlqReader::new(header_bytes);
    let header =
        read_header(&mut reader).map_err(|e| HeaderProcessError::Deserialize(format!("{e:?}")))?;

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
pub fn finalize_header(
    store: &mut StateStore,
    pre: PreValidatedHeader,
    header_bytes: &[u8],
    config: &DifficultyParams,
) -> Result<ProcessedHeader, HeaderProcessError> {
    let header_id = *pre.pow_checked.header_id();
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

    // Chain linkage + difficulty (needs parent from store). Consumes the
    // PoW proof to skip re-verification.
    process_header_inner(store, pre.pow_checked, header_bytes, config)
}

/// Process a header using mainnet chain config. Convenience wrapper.
pub fn process_header(
    store: &mut StateStore,
    header_bytes: &[u8],
) -> Result<ProcessedHeader, HeaderProcessError> {
    process_header_cfg(store, header_bytes, &DifficultyParams::mainnet())
}

/// Process a raw header with network-specific chain configuration.
/// Does everything: parse, PoW, chain linkage, difficulty, persist.
///
/// Thin wrapper over the two-phase primitives. The shadow-duplicate
/// preflight that used to live here (get_header / is_invalid / genesis
/// branch) is now handled by `finalize_header` — single code path.
pub fn process_header_cfg(
    store: &mut StateStore,
    header_bytes: &[u8],
    config: &DifficultyParams,
) -> Result<ProcessedHeader, HeaderProcessError> {
    let pre = pre_validate_header(header_bytes)?;
    finalize_header(store, pre, header_bytes, config)
}

/// Chain linkage + difficulty + persist. Shared by process_header_cfg and finalize_header.
///
/// Consumes a [`PowCheckedHeader`] — PoW was already verified in phase 1
/// (or upfront in `process_header_cfg`) and is not re-run here.
fn process_header_inner(
    store: &mut StateStore,
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
    if store.is_invalid(&parent_id)? {
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

    // 9. Check if this is the new best header (heaviest chain by cumulative score).
    let current_best_score = BigUint::from_bytes_be(&store.chain_state().best_header_score);
    let is_new_best = cumulative_score > current_best_score;

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
fn process_genesis_header(
    store: &mut StateStore,
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
pub fn find_header_id_at_height(
    store: &StateStore,
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
pub fn find_header_at_height(
    store: &StateStore,
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
}
