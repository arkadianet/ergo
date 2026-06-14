//! Block processing pipeline: load sections → validate → apply to state.
//!
//! Handles the coordinator's AssembleBlock action by:
//! 1. Loading header bytes + BlockTransactions + Extension from store
//! 2. Deserializing all sections
//! 3. Building BlockValidationContext (parent, UTXO, params, last headers)
//! 4. Running validate_full_block (merkle roots + all tx validation)
//! 5. Applying checked transactions to StateStore

use std::time::Instant;

use tracing::debug;

use ergo_primitives::digest::blake2b256;
use ergo_primitives::reader::VlqReader;
use ergo_ser::ad_proofs::read_ad_proofs;
use ergo_ser::block_transactions::read_block_transactions;
use ergo_ser::extension::read_extension;
use ergo_ser::header::read_header;
use ergo_ser::modifier_id::{compute_section_id, ExpectedSections, TYPE_AD_PROOFS};
use ergo_state::store::StateStore;
use ergo_state::{ChainStateRead, DigestStateStore, HeaderSectionStore};
use ergo_validation::block::{
    validate_full_block_parallel, BlockValidationContext, BlockValidationError, SoftForkState,
};
use ergo_validation::context::ProtocolParams;
use ergo_validation::header::CheckedHeader;
use ergo_validation::voting::{validate_epoch_extension, ExtensionValidationError};
use ergo_validation::{ChainHeaderReader, ChainHeaderReaderError, HeaderView};
use thiserror::Error;

use crate::perf::BlockPerfCounters;

/// Bridge `StateStore` → `ChainHeaderReader` so the voting recompute
/// pipeline can read `header.votes` for the previous voting epoch
/// (`compute_epoch_votes` walks 1024 headers per call).
struct StoreChainHeaderReader<'a> {
    store: &'a StateStore,
}

impl<'a> ChainHeaderReader for StoreChainHeaderReader<'a> {
    fn header_at(&self, height: u32) -> Result<HeaderView, ChainHeaderReaderError> {
        let header_id = self
            .store
            .get_header_id_at_height(height)
            .map_err(|e| ChainHeaderReaderError::Backend {
                height,
                source: Box::new(e),
            })?
            .ok_or(ChainHeaderReaderError::NotFound(height))?;
        let header_bytes = self
            .store
            .get_header(&header_id)
            .map_err(|e| ChainHeaderReaderError::Backend {
                height,
                source: Box::new(e),
            })?
            .ok_or(ChainHeaderReaderError::NotFound(height))?;
        let mut r = VlqReader::new(&header_bytes);
        let header = read_header(&mut r).map_err(|e| ChainHeaderReaderError::Backend {
            height,
            source: format!("header decode at h={height}: {e:?}").into(),
        })?;
        Ok(HeaderView {
            votes: header.votes,
        })
    }
}

/// Digest-backend counterpart of [`StoreChainHeaderReader`]: same
/// `header.votes` lookup over the shared header tables, reading through
/// the `HeaderSectionStore` trait the digest store implements. Kept as a
/// sibling type rather than generalizing `StoreChainHeaderReader` so the
/// UTXO path stays byte-for-byte unchanged.
struct DigestChainHeaderReader<'a> {
    store: &'a DigestStateStore,
}

impl<'a> ChainHeaderReader for DigestChainHeaderReader<'a> {
    fn header_at(&self, height: u32) -> Result<HeaderView, ChainHeaderReaderError> {
        let header_id = self
            .store
            .get_header_id_at_height(height)
            .map_err(|e| ChainHeaderReaderError::Backend {
                height,
                source: Box::new(e),
            })?
            .ok_or(ChainHeaderReaderError::NotFound(height))?;
        let header_bytes = self
            .store
            .get_header(&header_id)
            .map_err(|e| ChainHeaderReaderError::Backend {
                height,
                source: Box::new(e),
            })?
            .ok_or(ChainHeaderReaderError::NotFound(height))?;
        let mut r = VlqReader::new(&header_bytes);
        let header = read_header(&mut r).map_err(|e| ChainHeaderReaderError::Backend {
            height,
            source: format!("header decode at h={height}: {e:?}").into(),
        })?;
        Ok(HeaderView {
            votes: header.votes,
        })
    }
}

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

/// Build the last 10 headers preceding a block at `height` by walking
/// backward from `parent_id`. Used for CONTEXT.headers in script evaluation.
///
/// Returns headers in order: [H-1, H-2, ..., H-10] (most recent first).
/// Stops early if the chain is shorter than 10 blocks.
fn load_last_headers(
    store: &StateStore,
    parent_id: &[u8; 32],
) -> Result<Vec<CheckedHeader>, BlockProcessError> {
    let mut result = Vec::with_capacity(10);
    let mut current_id = *parent_id;

    for _ in 0..10 {
        let header_bytes = match store.get_header(&current_id)? {
            Some(b) => b,
            None => break, // chain shorter than 10
        };
        let meta = match store.get_header_meta(&current_id)? {
            Some(m) => m,
            None => break,
        };
        let checked = CheckedHeader::from_persisted_parts(
            &header_bytes,
            current_id,
            meta.pow_validity,
            meta.height,
            meta.parent_id,
            meta.timestamp,
        )?;
        let next_parent = *checked.header().parent_id.as_bytes();
        result.push(checked);

        if next_parent == [0u8; 32] {
            break; // reached genesis
        }
        current_id = next_parent;
    }

    Ok(result)
}

/// Digest-backend counterpart of [`load_last_headers`]: identical
/// backward walk over the shared header tables, reading through the
/// `HeaderSectionStore` trait. Sibling rather than a generalization so
/// the UTXO path is untouched.
fn load_last_headers_digest(
    store: &DigestStateStore,
    parent_id: &[u8; 32],
) -> Result<Vec<CheckedHeader>, BlockProcessError> {
    let mut result = Vec::with_capacity(10);
    let mut current_id = *parent_id;

    for _ in 0..10 {
        let header_bytes = match store.get_header(&current_id)? {
            Some(b) => b,
            None => break, // chain shorter than 10
        };
        let meta = match store.get_header_meta(&current_id)? {
            Some(m) => m,
            None => break,
        };
        let checked = CheckedHeader::from_persisted_parts(
            &header_bytes,
            current_id,
            meta.pow_validity,
            meta.height,
            meta.parent_id,
            meta.timestamp,
        )?;
        let next_parent = *checked.header().parent_id.as_bytes();
        result.push(checked);

        if next_parent == [0u8; 32] {
            break; // reached genesis
        }
        current_id = next_parent;
    }

    Ok(result)
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
pub fn process_block(
    store: &mut ergo_state::StateBackendKind,
    header_id: &[u8; 32],
    params: &ProtocolParams,
    cached_last_headers: Option<&[CheckedHeader]>,
    script_validation_checkpoint: Option<(u32, [u8; 32])>,
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
            perf,
            wallet_hook,
        ),
        ergo_state::StateBackendKind::Digest(d) => process_block_digest(
            d,
            header_id,
            cached_last_headers,
            script_validation_checkpoint,
            perf,
            wallet_hook,
        ),
    }
}

/// UTXO-backend block processing: load sections, validate, apply to the
/// AVL+ box arena. This is the original `process_block` body, unchanged —
/// the UTXO path stays byte-for-byte equivalent to the pre-Mode-5 code.
fn process_block_utxo(
    store: &mut StateStore,
    header_id: &[u8; 32],
    _params: &ProtocolParams, // legacy arg; ignored — params are now sourced from
    // `store.active_params()`. Kept in the signature to avoid
    // an executor.rs callsite churn; will drop in a follow-up.
    cached_last_headers: Option<&[CheckedHeader]>,
    script_validation_checkpoint: Option<(u32, [u8; 32])>,
    perf: Option<&BlockPerfCounters>,
    wallet_hook: Option<&dyn ergo_state::wallet::WalletApplyHook>,
) -> Result<ProcessedBlock, BlockProcessError> {
    // Build ProtocolParams from the store's in-memory cache. The
    // cache reflects the PREVIOUS epoch's params per the
    // effective-height rule: this block is validated under those
    // params; the new params from this block's extension only take
    // effect for H+1 onward.
    let active_for_this_block = ProtocolParams::from_active(store.active_params());
    let params = &active_for_this_block;
    let t_total = Instant::now();

    // 1. Load and parse header
    let t0 = Instant::now();
    let header_bytes = store
        .get_header(header_id)?
        .ok_or(BlockProcessError::HeaderNotFound { id: *header_id })?;
    let header_id_computed = *blake2b256(&header_bytes).as_bytes();
    if header_id_computed != *header_id {
        return Err(BlockProcessError::Deserialize(format!(
            "stored header_id {} does not match blake2b256 of header bytes {}",
            hex::encode(header_id),
            hex::encode(header_id_computed),
        )));
    }
    let mut r = VlqReader::new(&header_bytes);
    let header = read_header(&mut r)
        .map_err(|e| BlockProcessError::Deserialize(format!("header: {e:?}")))?;
    let height = header.height;
    let state_root = header.state_root;
    let t_header = t0.elapsed();

    // 2. Compute expected section IDs + load/parse sections
    let t0 = Instant::now();
    let expected = ExpectedSections::from_header(
        &header_id_computed,
        header.transactions_root.as_bytes(),
        header.extension_root.as_bytes(),
        header.ad_proofs_root.as_bytes(),
    );

    let bt_bytes = store.get_block_section(&expected.transactions_id)?.ok_or(
        BlockProcessError::SectionNotFound {
            type_id: 102,
            modifier_id: expected.transactions_id,
        },
    )?;
    let mut r = VlqReader::new(&bt_bytes);
    let block_txs = read_block_transactions(&mut r)
        .map_err(|e| BlockProcessError::Deserialize(format!("block_transactions: {e:?}")))?;

    let ext_bytes = store.get_block_section(&expected.extension_id)?.ok_or(
        BlockProcessError::SectionNotFound {
            type_id: 108,
            modifier_id: expected.extension_id,
        },
    )?;
    let mut r = VlqReader::new(&ext_bytes);
    let extension = read_extension(&mut r)
        .map_err(|e| BlockProcessError::Deserialize(format!("extension: {e:?}")))?;
    let t_sections = t0.elapsed();

    // 3. Genesis block (height 1): no parent exists.
    let parent_id = *header.parent_id.as_bytes();
    if height == 1 && parent_id == [0u8; 32] {
        store.apply_genesis(&header_id_computed, &state_root, &block_txs.transactions)?;
        return Ok(ProcessedBlock {
            header_id: header_id_computed,
            height,
            checked_header: None,
        });
    }

    // Voted parameters: at epoch starts, run the full
    // epoch-extension validation before constructing CheckedHeader.
    // The `&header` borrow here is fine — header is still owned at
    // this point. The resulting `voted_params_row` (the recomputed
    // active set; matches parsed for valid blocks) flows into
    // apply_block.
    let voting_length = store.voting_settings().voting_length;
    let (voted_params_row, mode2_trust_consumed): (
        Option<ergo_validation::ActiveProtocolParameters>,
        bool,
    ) = if height > 0 && height.is_multiple_of(voting_length) {
        let chain_reader = StoreChainHeaderReader { store };
        let epoch_votes = ergo_validation::compute_epoch_votes(
            &chain_reader,
            height,
            voting_length,
        )
        .map_err(|e| {
            BlockProcessError::Deserialize(format!("compute_epoch_votes at h={height}: {e}"))
        })?;
        // Mode 2 install trust path: armed by `install_snapshot_state`,
        // peeked here, consumed only AFTER apply commits. Peeking
        // (rather than taking) keeps the flag set across an in-process
        // retry if apply fails for any non-validator reason.
        let trust_extension_settings = store.is_mode2_trust_first_epoch_armed();
        let mut outcome = validate_epoch_extension(
            &extension,
            &header,
            store.active_params(),
            store.validation_settings(),
            &epoch_votes,
            store.voting_settings(),
            trust_extension_settings,
        )?;
        // When the trust path is armed, encode the trusted cumulative
        // into THIS epoch's `activated_update` so the standard
        // apply_block persistence path writes it to `voted_params` on
        // disk and the cache-fold step updates `cached_validation_settings`
        // in lockstep. Without this, the trusted cumulative would live
        // only in RAM and any restart / cache refresh / reorg would
        // recompute from disk and silently drop it — see the codex
        // review notes on persistence/reorg regressions.
        //
        // The genuine `parsed.proposed_update` (the activation that
        // technically belongs to this epoch alone) is folded INTO the
        // trusted cumulative already (parsed_cumulative_from_extension
        // includes everything up to and including this block). So
        // overwriting `activated_update` with the cumulative is a
        // lossless representation for our Mode 2 node, which has no
        // pre-snapshot history to attribute updates to.
        if trust_extension_settings {
            outcome.computed.activated_update = outcome.next_settings.update_from_initial.clone();
        }
        (Some(outcome.computed), trust_extension_settings)
    } else {
        (None, false)
    };

    let chain_state = store.chain_state();
    if height == chain_state.best_full_block_height.saturating_add(1)
        && parent_id != chain_state.best_full_block_id
    {
        return Err(BlockProcessError::ParentNotBestFull {
            parent_id,
            best_full_id: chain_state.best_full_block_id,
            best_full_height: chain_state.best_full_block_height,
        });
    }

    // 4. Build CheckedHeader for parent from persisted metadata
    let t_parent_ctx_start = Instant::now();
    let parent_bytes = store
        .get_header(&parent_id)?
        .ok_or(BlockProcessError::ParentNotFound { id: parent_id })?;
    let parent_meta = store
        .get_header_meta(&parent_id)?
        .ok_or(BlockProcessError::ParentNotFound { id: parent_id })?;
    let parent_checked = CheckedHeader::from_persisted_parts(
        &parent_bytes,
        parent_id,
        parent_meta.pow_validity,
        parent_meta.height,
        parent_meta.parent_id,
        parent_meta.timestamp,
    )?;

    // 5. Build CheckedHeader for this block from persisted metadata.
    // `from_persisted_parts` re-derives the id from `header_bytes` and
    // verifies it matches `*header_id`, which is the same guard the
    // explicit check above already performs — kept as belt-and-braces
    // since it shapes the early-return error type.
    let block_meta = store
        .get_header_meta(header_id)?
        .ok_or(BlockProcessError::HeaderNotFound { id: *header_id })?;
    let checked_header = CheckedHeader::from_persisted_parts(
        &header_bytes,
        *header_id,
        block_meta.pow_validity,
        block_meta.height,
        block_meta.parent_id,
        block_meta.timestamp,
    )?;

    // 6. Load last 10 headers for CONTEXT.headers (use cache if provided)
    let loaded_last_headers;
    let last_headers: &[CheckedHeader] = match cached_last_headers {
        Some(cached) if !cached.is_empty() => cached,
        _ => {
            loaded_last_headers = load_last_headers(store, &parent_id)?;
            &loaded_last_headers
        }
    };
    let t_parent_ctx = t_parent_ctx_start.elapsed();

    // 7. Build validation context.
    // Parent extension is plumbed through `None` for now; rules
    // 401/402 (NiPoPoW interlinks) will fire once the store
    // surfaces a `get_extension(parent_id)` accessor. Matches Scala's
    // recoverable `exIlUnableToValidate` path when the parent
    // extension isn't available — non-fatal, validator falls through.
    let voting_settings = store.voting_settings();
    let voting_length = voting_settings.voting_length;
    // Rule 407 soft-fork-vote state. Sourced from active_params'
    // `extra` slot ids 121 + 122 (Scala
    // `softForkVotesCollected` / `softForkStartingHeight`). Only
    // present when there's an in-progress soft-fork; `None` means
    // the rule trivially passes.
    let sf_starting_height = store.active_params().soft_fork_starting_height();
    let sf_votes_collected = store.active_params().soft_fork_votes_collected();
    // Rule 407 (`exCheckForkVote`) is soft-fork-DISABLEABLE: Scala enforces it
    // via `validateNoThrow(exCheckForkVote, ...)`, so a disabled rule 407 skips
    // `checkForkVote` entirely — no prohibited-window reject AND no
    // `softForkVotesCollected.get` throw. Gate the whole rule here: a disabled
    // 407 nulls `soft_fork_state` (the window check becomes a no-op) and the
    // hostile-table guard short-circuits to Ok.
    let rule_407_disabled = store.validation_settings().is_rule_disabled(407);
    let soft_fork_state = if rule_407_disabled {
        None
    } else {
        match (sf_starting_height, sf_votes_collected) {
            (Some(starting_height), Some(votes_collected)) if starting_height >= 0 => {
                let approved = voting_settings.soft_fork_approved(votes_collected);
                Some(ergo_validation::block::SoftForkState {
                    starting_height: starting_height as u32,
                    votes_collected,
                    voting_length: voting_settings.voting_length,
                    soft_fork_epochs: voting_settings.soft_fork_epochs,
                    activation_epochs: voting_settings.activation_epochs,
                    approved,
                })
            }
            _ => None,
        }
    };
    // Rule 407 hostile-table guard (Scala `checkForkVote` reads
    // `softForkVotesCollected.get`): a soft-fork start height with no
    // votes-collected entry (122-without-121) rejects a SoftFork-voting header.
    // The `Option<SoftForkState>` above collapses this to `None`
    // (indistinguishable from "no soft fork"), so enforce it here from the raw
    // params, before the block validator's prohibited-window check.
    ergo_validation::block::check_fork_vote_votes_collected_present(
        checked_header.header(),
        sf_starting_height,
        sf_votes_collected,
        rule_407_disabled,
    )?;
    // Rule 215 (`hdrVotesUnknown`) is soft-fork-deactivatable. Mainnet's
    // v6.0 activation disabled it (`rules_to_disable = [215, 409]`), so an
    // epoch-start header may legitimately propose downward / new-param
    // votes (e.g. block 1802240 votes -4 = MaxBlockCostDecrease). Honor
    // the activated validation settings so we don't reject canonical
    // blocks the rest of the network accepted.
    let votes_unknown_rule_disabled = store.validation_settings().is_rule_disabled(215);
    // Rule 212 (`hdrVotesNumber`, ≤2 non-soft-fork votes) is also soft-fork-
    // deactivatable; honor the activated settings here at block time (the
    // header pipeline can't see them). 213/214 already ran at header time.
    ergo_validation::header::check_votes_number_active(
        checked_header.header(),
        store.validation_settings().is_rule_disabled(212),
    )
    .map_err(ergo_validation::block::BlockValidationError::Header)?;
    let ctx = BlockValidationContext {
        parent: &parent_checked,
        utxo: store,
        params,
        voting_length,
        votes_unknown_rule_disabled,
        parent_extension: None,
        soft_fork_state,
        last_headers,
        script_validation_checkpoint,
    };

    // 8. Validate the full block (no PoW/difficulty — already validated by header pipeline)
    let t0 = Instant::now();
    let checked_block = validate_full_block_parallel(checked_header, &block_txs, &extension, &ctx)?;
    let t_validate = t0.elapsed();
    let tx_count = checked_block.transactions().len();

    // 9. Apply to UTXO state. apply_block now derives height/header_id/
    // expected_state_root from the embedded CheckedHeader, so we don't
    // pass them separately.
    //
    let t0 = Instant::now();
    // M5 wallet-hook plumbing (atomicity depends on path):
    //   - sync path: chain + wallet commit inside the same redb
    //     write_txn (truly atomic).
    //   - pipeline path: chain commits durably first (flush + fsync
    //     when needed), THEN wallet commits on a separate write_txn.
    //     Two-commit, not atomic; failure mode is "wallet behind
    //     chain" (covered by rescan), not "wallet ahead of chain".
    //     The pipeline-worker integration that would close this seam
    //     is the M5 final slice tracked in audit-todo.
    // Caller threads `wallet_hook` from NodeState; `None` is
    // acceptable for tests and non-wallet deployments.
    store.apply_block(&checked_block, voted_params_row, wallet_hook)?;
    if mode2_trust_consumed {
        // apply_block committed the synthetic `voted_params` row (with
        // `activated_update = trusted cumulative`) and folded it into
        // `cached_validation_settings`. Now consume the trust claim
        // — in-memory + persisted — since the trusted state is durable
        // in the standard tables and the validator's
        // `prev_settings == empty()` gate keeps any stale disk byte
        // from firing again at later epoch boundaries.
        store.consume_mode2_trust_first_epoch();
    }
    let t_apply = t0.elapsed();

    let t_total_elapsed = t_total.elapsed();

    if let Some(p) = perf {
        p.add_block(
            tx_count as u64,
            t_header.as_nanos() as u64,
            t_sections.as_nanos() as u64,
            t_parent_ctx.as_nanos() as u64,
            t_validate.as_nanos() as u64,
            t_apply.as_nanos() as u64,
            t_total_elapsed.as_nanos() as u64,
        );
    }

    if height % 1000 == 0 || height <= 5 {
        debug!(
            height,
            tx_count,
            total_ms = t_total_elapsed.as_secs_f64() * 1000.0,
            hdr_ms = t_header.as_secs_f64() * 1000.0,
            sec_ms = t_sections.as_secs_f64() * 1000.0,
            pctx_ms = t_parent_ctx.as_secs_f64() * 1000.0,
            validate_ms = t_validate.as_secs_f64() * 1000.0,
            apply_ms = t_apply.as_secs_f64() * 1000.0,
            "block apply timing"
        );
    }

    let (validated_header, _) = checked_block.into_parts();
    Ok(ProcessedBlock {
        header_id: header_id_computed,
        height,
        checked_header: Some(validated_header),
    })
}

/// Digest-backend block processing — Mode 5's consensus core.
///
/// The digest node stores no box arena, so it cannot resolve a
/// transaction's inputs by lookup. Instead it resolves them from the
/// block's ADProofs: verifying the proof against the parent digest yields
/// the OLD VALUES of every spent input and pre-existing data input
/// (`apply_block_resolving_boxes`), and the verified post-root is
/// cross-checked against `header.state_root` inside the verifier. Those
/// boxes, plus the block's own outputs, form a [`ergo_state::DigestUtxoView`]
/// — exactly Scala's `DigestState.validateTransactions` `knownBoxes` set —
/// against which the SAME full transaction validation (scripts, amounts)
/// runs that the UTXO backend uses. Only the box source differs.
///
/// The change set comes from `build_utxo_changes_raw` — Mode 1's exact
/// netting (intra-block create-then-spend cancellation), shared so the
/// digest verifier and the UTXO tree cannot diverge on the same block.
/// `to_lookup` is the data-input box ids in transaction order with
/// duplicates kept and NOT sorted — the proof generator replayed them
/// first, so the verifier must too.
///
/// Apply is LINEAR-ONLY: the block's height must be tip+1 and its parent
/// must be the committed full-block tip. A missing ADProofs section or a
/// non-tip parent is data-availability / fork — NOT block invalidity —
/// and is surfaced without marking the header invalid.
fn process_block_digest(
    store: &mut DigestStateStore,
    header_id: &[u8; 32],
    cached_last_headers: Option<&[CheckedHeader]>,
    script_validation_checkpoint: Option<(u32, [u8; 32])>,
    perf: Option<&BlockPerfCounters>,
    wallet_hook: Option<&dyn ergo_state::wallet::WalletApplyHook>,
) -> Result<ProcessedBlock, BlockProcessError> {
    // The digest backend has no box arena, so it cannot drive a wallet
    // scan. Mode 5 gates the wallet routes off, so the executor must
    // never attach a hook here; a `Some` is a wiring bug, surfaced
    // loudly rather than silently dropping updates.
    if wallet_hook.is_some() {
        return Err(BlockProcessError::State(
            ergo_state::store::StateError::InvalidPrecondition {
                what: "digest backend received a wallet hook; Mode 5 has no box arena to scan",
            },
        ));
    }

    let active_for_this_block = ProtocolParams::from_active(store.active_params());
    let params = &active_for_this_block;
    let t_total = Instant::now();

    // 1. Load and parse header.
    let t0 = Instant::now();
    let header_bytes = store
        .get_header(header_id)?
        .ok_or(BlockProcessError::HeaderNotFound { id: *header_id })?;
    let header_id_computed = *blake2b256(&header_bytes).as_bytes();
    if header_id_computed != *header_id {
        return Err(BlockProcessError::Deserialize(format!(
            "stored header_id {} does not match blake2b256 of header bytes {}",
            hex::encode(header_id),
            hex::encode(header_id_computed),
        )));
    }
    let mut r = VlqReader::new(&header_bytes);
    let header = read_header(&mut r)
        .map_err(|e| BlockProcessError::Deserialize(format!("header: {e:?}")))?;
    let height = header.height;
    let t_header = t0.elapsed();

    // 2. Compute expected section IDs + load/parse the tx + extension
    //    sections (same as UTXO — these drive full tx validation).
    let t0 = Instant::now();
    let expected = ExpectedSections::from_header(
        &header_id_computed,
        header.transactions_root.as_bytes(),
        header.extension_root.as_bytes(),
        header.ad_proofs_root.as_bytes(),
    );

    let bt_bytes = store.get_block_section(&expected.transactions_id)?.ok_or(
        BlockProcessError::SectionNotFound {
            type_id: 102,
            modifier_id: expected.transactions_id,
        },
    )?;
    let mut r = VlqReader::new(&bt_bytes);
    let block_txs = read_block_transactions(&mut r)
        .map_err(|e| BlockProcessError::Deserialize(format!("block_transactions: {e:?}")))?;

    let ext_bytes = store.get_block_section(&expected.extension_id)?.ok_or(
        BlockProcessError::SectionNotFound {
            type_id: 108,
            modifier_id: expected.extension_id,
        },
    )?;
    let mut r = VlqReader::new(&ext_bytes);
    let extension = read_extension(&mut r)
        .map_err(|e| BlockProcessError::Deserialize(format!("extension: {e:?}")))?;
    let t_sections = t0.elapsed();

    let parent_id = *header.parent_id.as_bytes();

    // 2b. Genesis block (height 1) on a FRESH tip: no parent header
    //     exists, so this path skips `validate_full_block_parallel`
    //     ENTIRELY — not only the parent-dependent rules (timestamp
    //     monotonicity, interlinks) but also the section-linkage,
    //     `transactions_root`/`extension_root`, and structural/monetary/
    //     script/cost checks that path runs at height >= 2. This is exact
    //     parity with the UTXO arm's `apply_genesis`, which also returns
    //     before `validate_full_block` rather than fabricating a parent
    //     `CheckedHeader` (a synthesized parent risks parity divergence);
    //     Scala likewise applies the hardcoded genesis block without
    //     re-validating its body. The binding consensus anchor at genesis
    //     is purely cryptographic: the verifier replays the block's real
    //     ADProofs against the genesis state root and rejects unless the
    //     computed post-root equals `header.state_root` (plus the
    //     ADProofs-root and section-id bindings), so a transaction set
    //     that does not reproduce the committed root cannot commit.
    //
    //     The `store.height() == 0` guard keeps this an EXCLUSIVELY
    //     genesis path: replaying block 1 on a non-fresh tip falls
    //     through to the step-4 linear preflights, which classify it as
    //     `DigestOutOfOrder` rather than feeding it to the verifier
    //     against the current (non-genesis) tip root. The section-id
    //     linkage (sections are fetched under header-derived ids) and the
    //     ADProofs inner-header-id binding below are still enforced.
    if height == 1 && parent_id == [0u8; 32] && store.height() == 0 {
        // Parent state root = the committed tip digest, which on a
        // fresh Mode 5 store is the network's genesis digest.
        let parent_state_root = store.root_digest();

        let ad_proofs_id = compute_section_id(
            TYPE_AD_PROOFS,
            &header_id_computed,
            header.ad_proofs_root.as_bytes(),
        );
        // A missing ADProofs section is DATA UNAVAILABILITY, not block
        // invalidity — same classification the main path uses.
        let section_bytes = store.get_block_section(&ad_proofs_id)?.ok_or(
            BlockProcessError::AdProofsUnavailable {
                header_id: header_id_computed,
                ad_proofs_id,
            },
        )?;
        let mut reader = VlqReader::new(&section_bytes);
        let ad_proofs = read_ad_proofs(&mut reader).map_err(|e| {
            tracing::warn!(
                header_id = %hex::encode(header_id_computed),
                ad_proofs_id = %hex::encode(ad_proofs_id),
                error = ?e,
                "digest: ADProofs section decode failed"
            );
            BlockProcessError::Deserialize(format!("ad_proofs section: {e:?}"))
        })?;
        if !reader.is_empty() {
            return Err(BlockProcessError::Deserialize(format!(
                "ADProofs section has {} trailing byte(s) after the proof",
                reader.remaining()
            )));
        }
        if ad_proofs.header_id.as_bytes() != &header_id_computed {
            return Err(BlockProcessError::Deserialize(format!(
                "ADProofs section carries header_id {} but is filed under header {}",
                hex::encode(ad_proofs.header_id.as_bytes()),
                hex::encode(header_id_computed),
            )));
        }

        // Net box changes — the same shared raw-tx builder; genesis
        // block 1 has no data inputs but the lookups are derived
        // generically so the path matches the main arm.
        let tx_refs: Vec<&ergo_ser::transaction::Transaction> =
            block_txs.transactions.iter().collect();
        let (to_remove, to_insert) = StateStore::build_utxo_changes_raw(&tx_refs)?;
        let to_lookup: Vec<[u8; 32]> = block_txs
            .transactions
            .iter()
            .flat_map(|tx| tx.data_inputs.iter().map(|di| *di.box_id.as_bytes()))
            .collect();

        // Verify the proof + apply the net changes. The verifier
        // cross-checks the computed root against `header.state_root`
        // internally; every rejection is SESSION-scoped.
        let (new_root, _resolved) = ergo_state::DigestProofVerifier::apply_block_resolving_boxes(
            ad_proofs_id,
            &ad_proofs.proof_bytes,
            &header,
            &parent_state_root,
            &to_lookup,
            &to_remove,
            &to_insert,
        )?;

        // Commit atomically. Height 1 is never an epoch boundary, so no
        // voted-params row co-commits. `apply_block_digest` re-checks
        // height == prev+1 (prev=0) and the chain-state shape invariant.
        let mut new_chain_state = store.chain_state().clone();
        new_chain_state.best_full_block_id = header_id_computed;
        new_chain_state.best_full_block_height = height;
        store.apply_block_digest(new_root, new_chain_state, None)?;

        return Ok(ProcessedBlock {
            header_id: header_id_computed,
            height,
            checked_header: None,
        });
    }

    // 3. Voted parameters at epoch starts — same recompute the UTXO arm
    //    runs (minus the Mode 2 install-trust path, which is UTXO-only:
    //    Mode 5 never bootstraps from a UTXO snapshot). The resulting
    //    `voted_params_row` flows into `apply_block_digest` so epoch-
    //    boundary parameters land on disk in lockstep with the digest.
    let voting_length = store.voting_settings().voting_length;
    let voted_params_row: Option<ergo_validation::ActiveProtocolParameters> =
        if height > 0 && height.is_multiple_of(voting_length) {
            let chain_reader = DigestChainHeaderReader { store };
            let epoch_votes =
                ergo_validation::compute_epoch_votes(&chain_reader, height, voting_length)
                    .map_err(|e| {
                        BlockProcessError::Deserialize(format!(
                            "compute_epoch_votes at h={height}: {e}"
                        ))
                    })?;
            let outcome = validate_epoch_extension(
                &extension,
                &header,
                store.active_params(),
                store.validation_settings(),
                &epoch_votes,
                store.voting_settings(),
                // No install-trust path in digest mode.
                false,
            )?;
            Some(outcome.computed)
        } else {
            None
        };

    // 4. Linear-apply preflights, mirroring `DigestStateStore::apply_full_block`.
    //    Height must be tip+1 and the parent must BE the committed tip.
    //    Both are fork / out-of-order conditions, NOT block invalidity —
    //    classify them before any proof work so the verifier (always
    //    seeded with OUR tip root) cannot misclassify a foreign-parent
    //    block as session-invalid.
    let prev_height = store.height();
    if height != prev_height.saturating_add(1) {
        return Err(BlockProcessError::DigestOutOfOrder {
            expected: prev_height.saturating_add(1),
            got: height,
        });
    }
    let best_full_id = store.chain_state().best_full_block_id;
    if parent_id != best_full_id {
        return Err(BlockProcessError::DigestNonLinearParent {
            height,
            parent_id,
            best_full_id,
        });
    }

    // 5. Build CheckedHeader for the parent + this block from persisted
    //    metadata (same trust boundary the UTXO arm uses).
    let t_parent_ctx_start = Instant::now();
    let parent_bytes = store
        .get_header(&parent_id)?
        .ok_or(BlockProcessError::ParentNotFound { id: parent_id })?;
    let parent_meta = store
        .get_header_meta(&parent_id)?
        .ok_or(BlockProcessError::ParentNotFound { id: parent_id })?;
    let parent_checked = CheckedHeader::from_persisted_parts(
        &parent_bytes,
        parent_id,
        parent_meta.pow_validity,
        parent_meta.height,
        parent_meta.parent_id,
        parent_meta.timestamp,
    )?;
    let block_meta = store
        .get_header_meta(header_id)?
        .ok_or(BlockProcessError::HeaderNotFound { id: *header_id })?;
    let checked_header = CheckedHeader::from_persisted_parts(
        &header_bytes,
        *header_id,
        block_meta.pow_validity,
        block_meta.height,
        block_meta.parent_id,
        block_meta.timestamp,
    )?;

    // 6. Last 10 headers for CONTEXT.headers (use cache if provided).
    let loaded_last_headers;
    let last_headers: &[CheckedHeader] = match cached_last_headers {
        Some(cached) if !cached.is_empty() => cached,
        _ => {
            loaded_last_headers = load_last_headers_digest(store, &parent_id)?;
            &loaded_last_headers
        }
    };
    let t_parent_ctx = t_parent_ctx_start.elapsed();

    // 7. Resolve the block's input/data-input boxes from its ADProofs.
    let t0 = Instant::now();
    let ad_proofs_id = compute_section_id(
        TYPE_AD_PROOFS,
        &header_id_computed,
        header.ad_proofs_root.as_bytes(),
    );
    // A missing ADProofs section is DATA UNAVAILABILITY (the proof has
    // not been downloaded yet), not block invalidity — do NOT mark the
    // header invalid.
    let section_bytes =
        store
            .get_block_section(&ad_proofs_id)?
            .ok_or(BlockProcessError::AdProofsUnavailable {
                header_id: header_id_computed,
                ad_proofs_id,
            })?;
    // Parse the section envelope and re-enforce EOF + inner-header-id
    // binding (the same checks ingress runs), so a persisted blob can
    // never bypass them.
    let mut reader = VlqReader::new(&section_bytes);
    let ad_proofs = read_ad_proofs(&mut reader)
        .map_err(|e| BlockProcessError::Deserialize(format!("ad_proofs section: {e:?}")))?;
    if !reader.is_empty() {
        return Err(BlockProcessError::Deserialize(format!(
            "ADProofs section has {} trailing byte(s) after the proof",
            reader.remaining()
        )));
    }
    if ad_proofs.header_id.as_bytes() != &header_id_computed {
        return Err(BlockProcessError::Deserialize(format!(
            "ADProofs section carries header_id {} but is filed under header {}",
            hex::encode(ad_proofs.header_id.as_bytes()),
            hex::encode(header_id_computed),
        )));
    }

    // Net box changes — Mode 1's RAW-tx builder (create-then-spend
    // cancellation), shared so the digest verifier and the UTXO tree
    // cannot diverge on the same block's change set.
    let tx_refs: Vec<&ergo_ser::transaction::Transaction> = block_txs.transactions.iter().collect();
    let (to_remove, to_insert) = StateStore::build_utxo_changes_raw(&tx_refs)?;

    // Data-input lookups, in transaction order, duplicates kept, NOT
    // sorted — the `toLookup` prefix of Scala's `StateChanges.operations`
    // (`toLookup ++ toRemove ++ toAppend`). The ADProofs were generated
    // by replaying these lookups first, so the verifier consumes them
    // first to keep the proof stream aligned.
    let to_lookup: Vec<[u8; 32]> = block_txs
        .transactions
        .iter()
        .flat_map(|tx| tx.data_inputs.iter().map(|di| *di.box_id.as_bytes()))
        .collect();

    // Parent state root = the committed tip digest (linear path).
    let parent_state_root = store.root_digest();

    // Verify the proof + apply the net changes, returning the resolved
    // spent-input / data-input boxes AND the post-apply root (already
    // cross-checked against `header.state_root` inside the verifier).
    // Every rejection here is SESSION-scoped (the executor marks the
    // header session-invalid); we do NOT persist invalidity.
    let (new_root, resolved) = ergo_state::DigestProofVerifier::apply_block_resolving_boxes(
        ad_proofs_id,
        &ad_proofs.proof_bytes,
        &header,
        &parent_state_root,
        &to_lookup,
        &to_remove,
        &to_insert,
    )?;
    let t_resolve = t0.elapsed();

    // 8. Full transaction validation against the proof-backed view —
    //    Scala's `DigestState.validateTransactions`. Same validator the
    //    UTXO arm runs; only the box source (proof-resolved + block
    //    outputs) differs.
    let digest_view = ergo_state::DigestUtxoView::new(&resolved, &block_txs.transactions)?;

    let voting_settings = store.voting_settings();
    let voting_length = voting_settings.voting_length;
    let sf_starting_height = store.active_params().soft_fork_starting_height();
    let sf_votes_collected = store.active_params().soft_fork_votes_collected();
    // Rule 407 is disableable — see the UTXO arm. A disabled 407 nulls
    // soft_fork_state (window check no-op) and short-circuits the hostile guard.
    let rule_407_disabled = store.validation_settings().is_rule_disabled(407);
    let soft_fork_state = if rule_407_disabled {
        None
    } else {
        match (sf_starting_height, sf_votes_collected) {
            (Some(starting_height), Some(votes_collected)) if starting_height >= 0 => {
                let approved = voting_settings.soft_fork_approved(votes_collected);
                Some(SoftForkState {
                    starting_height: starting_height as u32,
                    votes_collected,
                    voting_length: voting_settings.voting_length,
                    soft_fork_epochs: voting_settings.soft_fork_epochs,
                    activation_epochs: voting_settings.activation_epochs,
                    approved,
                })
            }
            _ => None,
        }
    };
    // Rule 407 hostile-table guard — see the UTXO arm. Scala `checkForkVote`'s
    // `softForkVotesCollected.get` throws for a 122-without-121 table when the
    // header casts the SoftFork vote; enforce it here before the window check.
    ergo_validation::block::check_fork_vote_votes_collected_present(
        checked_header.header(),
        sf_starting_height,
        sf_votes_collected,
        rule_407_disabled,
    )?;
    // Rule 215 honored against the activated soft-fork settings — see the
    // UTXO-arm context above for the full rationale.
    let votes_unknown_rule_disabled = store.validation_settings().is_rule_disabled(215);
    // Rule 212 (`hdrVotesNumber`) honored at block time too — see UTXO arm.
    ergo_validation::header::check_votes_number_active(
        checked_header.header(),
        store.validation_settings().is_rule_disabled(212),
    )
    .map_err(ergo_validation::block::BlockValidationError::Header)?;
    let ctx = BlockValidationContext {
        parent: &parent_checked,
        utxo: &digest_view,
        params,
        voting_length,
        votes_unknown_rule_disabled,
        parent_extension: None,
        soft_fork_state,
        last_headers,
        script_validation_checkpoint,
    };

    let t0 = Instant::now();
    let checked_block = validate_full_block_parallel(checked_header, &block_txs, &extension, &ctx)?;
    let t_validate = t0.elapsed();
    let tx_count = checked_block.transactions().len();

    // 9. Commit the verified root atomically. Header acceptance already
    //    advanced `best_header_*` (the header is validated before its
    //    full block), so applying the full block advances ONLY
    //    `best_full_block_*`. `apply_block_digest` re-checks height ==
    //    prev+1, the `best_header >= best_full_block` shape invariant,
    //    and epoch-boundary voted-params keying, then commits and
    //    refreshes the cached params.
    let t0 = Instant::now();
    let mut new_chain_state = store.chain_state().clone();
    new_chain_state.best_full_block_id = header_id_computed;
    new_chain_state.best_full_block_height = height;
    store.apply_block_digest(new_root, new_chain_state, voted_params_row)?;
    let t_apply = t0.elapsed();

    let t_total_elapsed = t_total.elapsed();

    if let Some(p) = perf {
        p.add_block(
            tx_count as u64,
            t_header.as_nanos() as u64,
            t_sections.as_nanos() as u64,
            // Fold proof resolution into the parent-context phase — both
            // are pre-validate setup work the UTXO arm does not have.
            (t_parent_ctx + t_resolve).as_nanos() as u64,
            t_validate.as_nanos() as u64,
            t_apply.as_nanos() as u64,
            t_total_elapsed.as_nanos() as u64,
        );
    }

    if height % 1000 == 0 || height <= 5 {
        debug!(
            height,
            tx_count,
            total_ms = t_total_elapsed.as_secs_f64() * 1000.0,
            hdr_ms = t_header.as_secs_f64() * 1000.0,
            sec_ms = t_sections.as_secs_f64() * 1000.0,
            resolve_ms = t_resolve.as_secs_f64() * 1000.0,
            validate_ms = t_validate.as_secs_f64() * 1000.0,
            apply_ms = t_apply.as_secs_f64() * 1000.0,
            "digest block apply timing"
        );
    }

    let (validated_header, _) = checked_block.into_parts();
    Ok(ProcessedBlock {
        header_id: header_id_computed,
        height,
        checked_header: Some(validated_header),
    })
}
