//! Block processing pipeline: load sections → validate → apply to state.
//!
//! Handles the coordinator's AssembleBlock action by:
//! 1. Loading header bytes + BlockTransactions + Extension from store
//! 2. Deserializing all sections
//! 3. Building BlockValidationContext (parent, UTXO, params, last headers)
//! 4. Running validate_full_block (merkle roots + all tx validation)
//! 5. Applying checked transactions to StateStore

use ergo_validation::block::BlockValidationError;
use ergo_validation::context::ProtocolParams;
use ergo_validation::header::CheckedHeader;
use ergo_validation::voting::ExtensionValidationError;
use thiserror::Error;

use crate::perf::BlockPerfCounters;

mod digest;
mod utxo;

use digest::process_block_digest;
use utxo::process_block_utxo;

#[derive(Debug, Error)]
pub enum BlockProcessError {
    #[error("header not found: {}", hex::encode(id))]
    HeaderNotFound { id: [u8; 32] },
    #[error(
        "section not found: type={type_id}, modifier_id={}",
        hex::encode(modifier_id)
    )]
    SectionNotFound { type_id: u8, modifier_id: [u8; 32] },
    #[error("parent header not found: {}", hex::encode(id))]
    ParentNotFound { id: [u8; 32] },
    #[error(
        "block parent {} does not match best full block {} at height {}",
        hex::encode(parent_id),
        hex::encode(best_full_id),
        best_full_height
    )]
    ParentNotBestFull {
        parent_id: [u8; 32],
        best_full_id: [u8; 32],
        best_full_height: u32,
    },
    #[error("deserialization: {0}")]
    Deserialize(String),
    #[error("block validation: {0}")]
    Validation(#[from] BlockValidationError),
    #[error("state application: {0}")]
    State(#[from] ergo_state::store::StateError),
    #[error("header metadata inconsistency: {0}")]
    HeaderMeta(#[from] ergo_validation::header::HeaderValidationError),
    #[error("epoch-start extension validation: {0}")]
    EpochExtension(#[from] ExtensionValidationError),
    /// Digest mode: the block's ADProofs section is not yet stored. This
    /// is data unavailability — the proof has not been downloaded — NOT
    /// block invalidity. Mirrors `SectionNotFound`'s "wait for the
    /// section" semantics; the executor must NOT mark the header invalid.
    #[error(
        "ADProofs section not yet available for header {}",
        hex::encode(header_id)
    )]
    AdProofsUnavailable {
        header_id: [u8; 32],
        ad_proofs_id: [u8; 32],
    },
    /// Digest mode: the block's parent is not the committed full-block
    /// tip. The block is on a fork (or arrived out of order) — NOT
    /// invalid. The digest backend applies linearly only; the executor's
    /// reorg path owns switching the full-block tip.
    #[error(
        "digest block parent {} is not the committed tip {} at height {height}",
        hex::encode(parent_id),
        hex::encode(best_full_id)
    )]
    DigestNonLinearParent {
        height: u32,
        parent_id: [u8; 32],
        best_full_id: [u8; 32],
    },
    /// Digest mode: the block's height is not exactly `tip + 1`. Replay /
    /// skip is not supported on the linear digest apply path. Not invalid.
    #[error("digest block height {got} is not tip+1 (expected {expected})")]
    DigestOutOfOrder { expected: u32, got: u32 },
    /// Digest mode: the proof verifier rejected the block. SESSION-scoped
    /// per the Mode 5 invalidity contract — the orchestrator does not
    /// persist invalidity here (a stale local parent root and a
    /// definitively bad proof are observationally identical at this
    /// layer). The executor marks the header session-invalid.
    #[error("digest proof verification rejected the block: {0}")]
    DigestApply(#[from] ergo_state::DigestApplyError),
}

/// Result of successfully processing a block.
#[derive(Debug)]
pub struct ProcessedBlock {
    pub header_id: [u8; 32],
    pub height: u32,
    /// The validated header. None for genesis (uses apply_block_unchecked).
    /// Used by the executor to update the rolling block-context cache.
    pub checked_header: Option<CheckedHeader>,
}

/// Process a full block against the runtime state backend.
///
/// `header_id`: the header whose block sections are complete.
///
/// The header itself must already be stored (via process_header).
/// BlockTransactions and Extension must already be persisted in
/// block_sections.
///
/// `cached_last_headers`: if provided, used for CONTEXT.headers instead
/// of reading from store. Must be aligned to best_full_block (the parent
/// of the block being processed). Pass None to fall back to store reads.
///
/// `wallet_hook`: forwarded to the UTXO `apply_block` so wallet table
/// writes land inside the same redb write_txn as chain mutations on the
/// synchronous path (M5 atomic commit). The digest backend has no box
/// arena to scan, so a non-`None` hook in digest mode is a wiring bug —
/// the digest arm hard-errors rather than silently dropping it.
///
/// Dispatch is one match on the backend. The UTXO arm runs the original
/// pipeline byte-for-byte (`process_block_utxo`); the digest arm runs the
/// proof-backed validation pipeline (`process_block_digest`). Both share
/// the same header/section reads through their respective stores.
#[allow(clippy::too_many_arguments)]
pub fn process_block(
    store: &mut ergo_state::StateBackendKind,
    header_id: &[u8; 32],
    params: &ProtocolParams,
    cached_last_headers: Option<&[CheckedHeader]>,
    script_validation_checkpoint: Option<(u32, [u8; 32])>,
    reemission: Option<&ergo_validation::ReemissionRuleInputs>,
    perf: Option<&BlockPerfCounters>,
    wallet_hook: Option<&dyn ergo_state::wallet::WalletApplyHook>,
) -> Result<ProcessedBlock, BlockProcessError> {
    match store {
        ergo_state::StateBackendKind::Utxo(s) => process_block_utxo(
            s,
            header_id,
            params,
            cached_last_headers,
            script_validation_checkpoint,
            reemission,
            perf,
            wallet_hook,
        ),
        ergo_state::StateBackendKind::Digest(d) => process_block_digest(
            d,
            header_id,
            cached_last_headers,
            script_validation_checkpoint,
            reemission,
            perf,
            wallet_hook,
        ),
    }
}
