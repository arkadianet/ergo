//! NodeViewHolder coordinator for the Ergo node.
//!
//! Coordinates history ([`HistoryDb`]), state, and mempool, processing
//! modifiers sequentially and ensuring atomic updates to the block
//! processing pipeline.

use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use ergo_consensus::block_validation::{validate_full_block, BlockValidationError};
use ergo_consensus::difficulty_adjustment::{
    calculate_classic, calculate_eip37, previous_heights_for_recalculation,
};
use ergo_consensus::header_validation::{
    validate_block_version, validate_child_header, validate_parent_semantics,
};
use ergo_consensus::parameters::Parameters;
use ergo_consensus::tx_stateful_validation::validate_tx_stateful;
use ergo_consensus::tx_validation::validate_tx_stateless;
use ergo_consensus::validation_rules::ValidationSettings;
use ergo_consensus::voting::VotingEpochInfo;
use ergo_state::digest_state::DigestState;
use ergo_state::state_changes::compute_state_changes;
use ergo_state::utxo_state::UtxoState;
use ergo_storage::block_processor::ProgressInfo;
use ergo_storage::chain_scoring::ModifierValidity;
use ergo_storage::history_db::{HistoryDb, StorageError};
use ergo_types::modifier_id::ModifierId;
use ergo_wire::header_ser::parse_header as wire_parse_header;
use ergo_wire::transaction_ser::parse_transaction;

use crate::mempool::ErgoMemPool;

// ---------------------------------------------------------------------------
// Section type IDs
// ---------------------------------------------------------------------------

/// Header modifier type ID.
const HEADER_TYPE_ID: u8 = 101;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that can occur during node view operations.
#[derive(Debug, thiserror::Error)]
pub enum NodeViewError {
    #[error("storage: {0}")]
    Storage(#[from] StorageError),
    #[error("state: {0}")]
    State(String),
    #[error("validation: {0}")]
    Validation(String),
    #[error("block validation: {0}")]
    BlockValidation(#[from] BlockValidationError),
    #[error("tx validation: {0}")]
    TxValidation(String),
    #[error("codec: {0}")]
    Codec(String),
    #[error("invalid extension: {0}")]
    InvalidExtension(String),
}

// ---------------------------------------------------------------------------
// NodeViewHolder
// ---------------------------------------------------------------------------

/// Coordinates history (HistoryDb), state, and mempool.
///
/// Processes modifiers sequentially, ensuring atomic updates.
/// In digest mode, state root is tracked from block headers rather
/// than maintained through a full UTXO set.
pub struct NodeViewHolder {
    /// Persistent block history storage.
    pub history: HistoryDb,
    /// In-memory transaction pool, shared with the HTTP API.
    pub mempool: Arc<RwLock<ErgoMemPool>>,
    /// Whether the node is running in digest (SPV-like) mode.
    digest_mode: bool,
    /// Current AVL+ state root digest.
    current_state_root: Vec<u8>,
    /// ID of the last block whose state was applied.
    current_state_version: ModifierId,
    /// Lightweight state that validates blocks using AD proofs.
    digest_state: DigestState,
    /// Full UTXO state backed by an authenticated AVL+ tree.
    utxo_state: UtxoState,
    /// Block IDs applied since the last drain, used for Inv broadcast.
    applied_blocks: Vec<ModifierId>,
    /// Height of the branch point after the most recent chain reorganization.
    /// Set by `apply_progress` during reorgs; drained by `take_rollback_height`.
    last_rollback_height: Option<u32>,
    /// blocks_to_keep: -1 = keep all, N >= 0 = keep last N blocks' body sections.
    blocks_to_keep: i32,
    /// Epoch length for voting — never prune Extension at epoch start blocks.
    epoch_length: u32,
    /// Voting state machine: tracks accumulated votes and current parameters.
    pub voting_epoch_info: VotingEpochInfo,
    /// Cached height of best_full_block — avoids repeated DB lookups when
    /// skipping stale blocks in a batch after a fast-forward.
    best_full_height: u32,
    /// Height below which sigma proof verification is skipped.
    checkpoint_height: u32,
    /// Autolykos v2 activation height (default 417_792 for mainnet).
    v2_activation_height: u32,
    /// Initial difficulty hex string for Autolykos v2 (e.g. "6f98d5000000").
    v2_activation_difficulty_hex: String,
    /// Maximum allowed timestamp drift in milliseconds (10 * block_interval).
    max_time_drift_ms: u64,
}

/// Compute required nBits for a new block at the given height.
///
/// This is the standalone version of [`NodeViewHolder::compute_required_difficulty`]
/// that can be called without a `NodeViewHolder` reference — useful for mining
/// candidate generation.
///
/// Returns `None` if epoch headers aren't available for recalculation,
/// or if `header_height` is below `checkpoint_height`.
pub fn compute_required_difficulty_from_history(
    history: &HistoryDb,
    header_height: u32,
    parent: &ergo_types::header::Header,
    checkpoint_height: u32,
) -> Option<u32> {
    const EIP37_ACTIVATION_HEIGHT: u32 = 844_673;
    const AUTOLYKOS_V2_HEIGHT: u32 = 417_792;
    const CLASSIC_EPOCH_LENGTH: u32 = 1024;
    const EIP37_EPOCH_LENGTH: u32 = 128;
    const DESIRED_INTERVAL_MS: u64 = 120_000;
    const USE_LAST_EPOCHS: u32 = 8;

    // Below checkpoint, don't compute (will be verified during block application).
    if header_height <= checkpoint_height {
        return None;
    }

    // Skip genesis (height 1) -- no parent comparison.
    if header_height <= 1 {
        return None;
    }

    // Autolykos v2 activation: skip difficulty check at the PoW change boundary.
    if header_height == AUTOLYKOS_V2_HEIGHT {
        return None;
    }

    let is_eip37 = header_height >= EIP37_ACTIVATION_HEIGHT;
    let epoch_length = if is_eip37 {
        EIP37_EPOCH_LENGTH
    } else {
        CLASSIC_EPOCH_LENGTH
    };

    // Mid-epoch: inherit parent's nBits.
    if parent.height > 0 && !parent.height.is_multiple_of(epoch_length) {
        return Some(parent.n_bits as u32);
    }

    // Epoch boundary: need historical headers for recalculation.
    let required_heights =
        previous_heights_for_recalculation(header_height, epoch_length, USE_LAST_EPOCHS);

    let mut header_data: Vec<(u32, u64, u32)> = Vec::with_capacity(required_heights.len());
    for &h in &required_heights {
        let ids = history.header_ids_at_height(h).unwrap_or_default();
        if let Some(id) = ids.first() {
            match history.load_header(id) {
                Ok(Some(hdr)) => {
                    header_data.push((hdr.height, hdr.timestamp, hdr.n_bits as u32));
                }
                _ => return None, // Can't compute, skip check.
            }
        } else {
            return None; // Can't compute, skip check.
        }
    }

    if header_data.len() < 2 {
        return None;
    }

    let expected = if is_eip37 {
        calculate_eip37(&header_data, epoch_length, DESIRED_INTERVAL_MS)
    } else {
        calculate_classic(&header_data, epoch_length, DESIRED_INTERVAL_MS)
    };

    Some(expected)
}

impl NodeViewHolder {
    /// Create a new `NodeViewHolder`.
    ///
    /// - `history`: opened RocksDB-backed history storage.
    /// - `mempool`: transaction pool.
    /// - `digest_mode`: if `true`, state root is taken from headers
    ///   rather than computed from UTXO changes.
    /// - `genesis_digest`: initial state root digest bytes.
    pub fn new(
        history: HistoryDb,
        mempool: Arc<RwLock<ErgoMemPool>>,
        digest_mode: bool,
        genesis_digest: Vec<u8>,
    ) -> Self {
        Self {
            history,
            mempool,
            digest_mode,
            current_state_root: genesis_digest.clone(),
            current_state_version: ModifierId([0u8; 32]),
            digest_state: DigestState::new(genesis_digest, ModifierId([0u8; 32])),
            utxo_state: UtxoState::new(),
            applied_blocks: Vec::new(),
            last_rollback_height: None,
            best_full_height: 0,
            blocks_to_keep: -1,
            epoch_length: 1024,
            voting_epoch_info: VotingEpochInfo::new(Parameters::genesis(), 0),
            checkpoint_height: 0,
            v2_activation_height: 417_792,
            v2_activation_difficulty_hex: "6f98d5000000".to_string(),
            max_time_drift_ms: ergo_consensus::header_validation::DEFAULT_MAX_TIME_DRIFT_MS,
        }
    }

    /// Create a NodeViewHolder with state recovered from the database.
    ///
    /// If a state_version exists in the DB and matches a valid header,
    /// the state root is recovered from that block's header. Otherwise,
    /// falls back to genesis state.
    pub fn with_recovery(
        history: HistoryDb,
        mempool: Arc<RwLock<ErgoMemPool>>,
        digest_mode: bool,
        genesis_digest: Vec<u8>,
    ) -> Self {
        let (state_root, state_version, recovered_height) = match history.get_state_version() {
            Ok(Some(version_id)) => match history.load_header(&version_id) {
                Ok(Some(header)) => {
                    tracing::info!(
                        height = header.height,
                        state_version = ?version_id,
                        "recovering state from persisted version"
                    );
                    (header.state_root.0.to_vec(), version_id, header.height)
                }
                _ => {
                    tracing::warn!(
                        state_version = ?version_id,
                        "state version header not found, starting from genesis"
                    );
                    (genesis_digest.clone(), ModifierId([0u8; 32]), 0)
                }
            },
            _ => {
                tracing::info!("no persisted state version, starting from genesis");
                (genesis_digest.clone(), ModifierId([0u8; 32]), 0)
            }
        };

        // Reconstruct voting_epoch_info from the last epoch-boundary Extension in the DB.
        // On restart, voting_epoch_info would otherwise start at genesis (block_version=1),
        // causing Stage 2b to reject blocks whose version was raised by prior soft-fork votes.
        // Loading the declared parameters from the most recent epoch-start Extension gives us
        // the correct block_version, max_block_size, etc. without replaying all vote history.
        let epoch_length_const = 1024u32;
        let voting_epoch_info = {
            let epoch_start = (recovered_height / epoch_length_const) * epoch_length_const;
            let restored = if epoch_start > 0 {
                history
                    .header_ids_at_height(epoch_start)
                    .ok()
                    .and_then(|ids| ids.into_iter().next())
                    .and_then(|id| history.load_extension(&id).ok().flatten())
                    .and_then(|ext| Parameters::from_extension(epoch_start, &ext).ok())
                    .map(|params| {
                        tracing::info!(
                            epoch_start,
                            block_version = params.block_version(),
                            "restored voting epoch info from DB epoch boundary"
                        );
                        VotingEpochInfo::new(params, epoch_start)
                    })
            } else {
                None
            };
            restored.unwrap_or_else(|| VotingEpochInfo::new(Parameters::genesis(), 0))
        };

        Self {
            history,
            mempool,
            digest_mode,
            current_state_root: state_root.clone(),
            current_state_version: state_version,
            digest_state: DigestState::new(state_root, state_version),
            utxo_state: UtxoState::new(),
            applied_blocks: Vec::new(),
            last_rollback_height: None,
            best_full_height: recovered_height,
            blocks_to_keep: -1,
            epoch_length: 1024,
            voting_epoch_info,
            checkpoint_height: 0,
            v2_activation_height: 417_792,
            v2_activation_difficulty_hex: "6f98d5000000".to_string(),
            max_time_drift_ms: ergo_consensus::header_validation::DEFAULT_MAX_TIME_DRIFT_MS,
        }
    }

    /// Drain and return all block IDs that were applied since the last call.
    pub fn take_applied_blocks(&mut self) -> Vec<ModifierId> {
        std::mem::take(&mut self.applied_blocks)
    }

    /// Drain and return the branch-point height from the most recent chain reorg.
    ///
    /// Returns `Some(height)` if a rollback occurred since the last call,
    /// `None` otherwise.
    pub fn take_rollback_height(&mut self) -> Option<u32> {
        self.last_rollback_height.take()
    }

    /// Set the block pruning window. -1 = keep all, N >= 0 = keep last N.
    pub fn set_blocks_to_keep(&mut self, n: i32) {
        self.blocks_to_keep = n;
    }

    /// Set the checkpoint height below which sigma proof verification is skipped.
    pub fn set_checkpoint_height(&mut self, h: u32) {
        self.checkpoint_height = h;
    }

    /// Set Autolykos v2 activation configuration.
    ///
    /// - `height`: the activation height (default 417_792 for mainnet).
    /// - `diff_hex`: the initial difficulty hex at v2 activation (e.g. "6f98d5000000").
    pub fn set_v2_activation_config(&mut self, height: u32, diff_hex: String) {
        self.v2_activation_height = height;
        self.v2_activation_difficulty_hex = diff_hex;
    }

    /// Set the maximum time drift from the chain's block interval.
    ///
    /// `block_interval_secs` is the desired block interval in seconds
    /// (e.g. 120 for mainnet). MaxTimeDrift = 10 * block_interval.
    pub fn set_max_time_drift_from_interval(&mut self, block_interval_secs: u64) {
        self.max_time_drift_ms = block_interval_secs * 10 * 1000;
    }

    /// Fast-forward `best_full_block_id` past all consecutive already-Valid
    /// blocks on startup.  This avoids replaying through potentially tens of
    /// thousands of blocks one-by-one when body sections arrive later.
    ///
    /// Call this after `restore_consistency()`.
    pub fn fast_forward_valid_blocks(&mut self) -> Result<(), NodeViewError> {
        let best_id = match self.history.best_full_block_id()? {
            Some(id) => id,
            None => return Ok(()),
        };
        let best_height = match self.history.load_header(&best_id)? {
            Some(h) => h.height,
            None => return Ok(()),
        };

        let mut last_valid_id = best_id;
        let mut last_valid_height = best_height;
        let mut expected_parent = best_id;

        for height in (best_height + 1).. {
            let ids = match self.history.header_ids_at_height(height) {
                Ok(ids) if !ids.is_empty() => ids,
                _ => break,
            };
            let mut found = false;
            for id in &ids {
                if let Some(hdr) = self.history.load_header(id)? {
                    if hdr.parent_id == expected_parent {
                        let is_valid = matches!(
                            self.history.get_validity(id),
                            Ok(Some(ModifierValidity::Valid))
                        );
                        if is_valid {
                            last_valid_id = *id;
                            last_valid_height = height;
                            expected_parent = *id;
                            found = true;
                        }
                        break;
                    }
                }
            }
            if !found {
                break;
            }
        }

        if last_valid_id != best_id {
            let skipped = last_valid_height - best_height;
            tracing::info!(
                from_height = best_height,
                to_height = last_valid_height,
                skipped,
                "fast-forwarded best_full_block past already-valid blocks"
            );
            self.history.set_best_full_block_id(&last_valid_id)?;
            self.best_full_height = last_valid_height;

            // In digest mode, state is just the state_root hash chain —
            // advancing state_version here is correct.
            // In UTXO mode, the AVL tree is NOT updated during fast-forward;
            // state_version must only advance when UTXO is actually applied.
            if self.digest_mode {
                self.current_state_version = last_valid_id;
                self.history.set_state_version(&last_valid_id)?;
            }

            // Always update the in-memory digest state root from the target header.
            if let Some(hdr) = self.history.load_header(&last_valid_id)? {
                self.current_state_root = hdr.state_root.0.to_vec();
                self.digest_state = DigestState::new(hdr.state_root.0.to_vec(), last_valid_id);
            }
        }

        Ok(())
    }

    /// Replay state changes for a block that has already been fully validated.
    ///
    /// Used by `restore_consistency` to advance UTXO/digest state for Valid
    /// blocks without running the full validation pipeline.  The normal path
    /// (`validate_and_apply_block`) would trigger Stage 0, which calls
    /// `fast_forward_valid_blocks()` (which in UTXO mode no longer updates
    /// `state_version` after the Task-2a fix) and returns `Ok(())` without
    /// ever applying state, leaving `state_version` stuck in an infinite loop.
    ///
    /// This method runs only:
    /// * Stage 6 — state application (mode-dependent, lenient: no proof
    ///   re-verification since the block was already validated).
    /// * Stage 7 — `state_version` / `best_full_height` update.
    fn apply_block_state_only(&mut self, block_id: &ModifierId) -> Result<(), NodeViewError> {
        let block = self.history.assemble_full_block(block_id)?.ok_or_else(|| {
            NodeViewError::State(format!(
                "apply_block_state_only: cannot assemble block {block_id:?}"
            ))
        })?;

        if self.digest_mode {
            // Digest mode: the block was already validated with ADProofs.
            // Advance the in-memory digest state to match the header's
            // committed state_root — identical to the fast-forward path.
            let new_root = block.header.state_root.0.to_vec();
            self.current_state_root = new_root.clone();
            self.digest_state = DigestState::new(new_root, *block_id);
        } else {
            // UTXO mode: apply state changes leniently (no proof
            // re-verification; trusted because block is already Valid).
            let mut transactions = Vec::with_capacity(block.block_transactions.tx_bytes.len());
            for (i, tx_bytes) in block.block_transactions.tx_bytes.iter().enumerate() {
                let tx = parse_transaction(tx_bytes).map_err(|e| {
                    NodeViewError::Codec(format!("apply_block_state_only: tx {} parse: {e}", i))
                })?;
                transactions.push(tx);
            }
            self.utxo_state
                .apply_block_lenient(&transactions, block.header.height, block_id)
                .map_err(|e| {
                    NodeViewError::State(format!("apply_block_state_only: utxo lenient: {e}"))
                })?;
            self.current_state_root = self
                .utxo_state
                .state_root()
                .map_err(|e| NodeViewError::State(format!("apply_block_state_only: root: {e}")))?;
        }

        // Advance state_version (Stage 7).
        // NOTE: best_full_block_id is intentionally NOT updated here.
        // restore_consistency only calls this helper when best_full_block_id is
        // already set to the target height; this helper only bridges the
        // state_version gap.  Calling set_best_full_block_id here would be
        // redundant at best and could corrupt the pointer if called outside that
        // context.
        self.current_state_version = *block_id;
        self.best_full_height = block.header.height;
        self.history.set_state_version(block_id)?;

        Ok(())
    }

    /// Ensure state and history are consistent on startup.
    ///
    /// Compares `current_state_version` with `history.best_full_block_id()`.
    /// If they match, no-op. If state is behind, replays blocks forward.
    /// If state version is the zero ID (fresh start), no-op.
    pub fn restore_consistency(&mut self) -> Result<(), NodeViewError> {
        let best_block_id = match self.history.best_full_block_id()? {
            Some(id) => id,
            None => return Ok(()), // No blocks in history
        };

        // Zero state version means fresh node — will sync from scratch.
        if self.current_state_version == ModifierId([0u8; 32]) {
            return Ok(());
        }

        if self.current_state_version == best_block_id {
            tracing::info!("state and history are consistent");
            return Ok(());
        }

        // Look up heights by loading headers.
        let state_height = self
            .history
            .load_header(&self.current_state_version)?
            .map(|h| h.height);
        let best_height = self.history.load_header(&best_block_id)?.map(|h| h.height);

        match (state_height, best_height) {
            (Some(sh), Some(bh)) if sh < bh => {
                tracing::warn!(
                    state_height = sh,
                    best_height = bh,
                    "state behind history, replaying {} blocks",
                    bh - sh
                );
                for h in (sh + 1)..=bh {
                    let ids = self.history.header_ids_at_height(h)?;
                    if let Some(block_id) = ids.first() {
                        let is_valid = matches!(
                            self.history.get_validity(block_id),
                            Ok(Some(ModifierValidity::Valid))
                        );
                        if is_valid {
                            // Block is already validated — replay state only.
                            // validate_and_apply_block would trigger Stage 0
                            // which calls fast_forward_valid_blocks() and
                            // returns without applying state, leaving
                            // state_version stuck.
                            match self.apply_block_state_only(block_id) {
                                Ok(()) => {}
                                Err(e) => {
                                    tracing::error!(
                                        height = h,
                                        error = %e,
                                        "failed to replay state for valid block during consistency restore"
                                    );
                                    break;
                                }
                            }
                        }
                    }
                }
                tracing::info!("consistency restore complete");
            }
            _ => {
                tracing::warn!(
                    "state version not found in history or unexpected state, continuing as-is"
                );
            }
        }

        Ok(())
    }

    /// Get the last N headers from the chain, most recent first.
    fn get_last_headers(&self, count: usize) -> Vec<ergo_types::header::Header> {
        let mut headers = Vec::new();
        if let Ok(Some(best_id)) = self.history.best_full_block_id() {
            let mut current_id = best_id;
            for _ in 0..count {
                match self.history.load_header(&current_id) {
                    Ok(Some(h)) => {
                        let parent_id = h.parent_id;
                        headers.push(h);
                        current_id = parent_id;
                    }
                    _ => break,
                }
            }
        }
        headers
    }

    /// Prune body sections for heights that fell off the blocks_to_keep window.
    fn prune_old_blocks(&self, current_height: u32) {
        if self.blocks_to_keep < 0 {
            return; // Keep all blocks
        }
        let keep = self.blocks_to_keep as u32;
        if current_height <= keep {
            return; // Not enough blocks yet to prune anything
        }
        let new_minimal = current_height - keep + 1;
        let old_minimal = self.history.minimal_full_block_height().unwrap_or(0);
        if new_minimal <= old_minimal {
            return; // Already pruned up to this height
        }
        for height in old_minimal..new_minimal {
            let ids = self
                .history
                .header_ids_at_height(height)
                .unwrap_or_default();
            for id in &ids {
                // Delete body sections: BlockTransactions(102), ADProofs(104)
                let _ = self.history.delete_modifier(102, id);
                let _ = self.history.delete_modifier(104, id);
                // Never prune Extension at epoch start blocks (needed for consensus params).
                if height % self.epoch_length != 0 {
                    let _ = self.history.delete_modifier(108, id);
                }
            }
        }
        if let Err(e) = self.history.set_minimal_full_block_height(new_minimal) {
            tracing::warn!(error = %e, "failed to persist minimal_full_block_height");
        }
    }

    /// Process a received block section.
    ///
    /// 1. Store the section in history.
    /// 2. For headers (type 101), call `process_header` to get the
    ///    download list for remaining sections.
    /// 3. For other section types, call `process_block_section` to
    ///    check if the full block is now complete.
    /// 4. If `ProgressInfo` has `to_apply`, apply those blocks.
    /// 5. Return the `ProgressInfo`.
    pub fn process_modifier(
        &mut self,
        type_id: u8,
        modifier_id: &ModifierId,
        data: &[u8],
    ) -> Result<ProgressInfo, NodeViewError> {
        // For headers, parse, validate against parent, and store with indexes.
        if type_id == HEADER_TYPE_ID {
            let header = wire_parse_header(data)
                .map_err(|e| NodeViewError::Validation(format!("header parse failed: {e}")))?;

            // Validate every header — matching Scala which validates PoW,
            // difficulty, and timestamps at all heights with no checkpoint skip.
            if header.is_genesis() {
                let now_ms = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;
                if let Err(e) = ergo_consensus::header_validation::validate_genesis_header(
                    &header,
                    now_ms,
                    None,
                    None,
                    self.max_time_drift_ms,
                ) {
                    return Err(NodeViewError::Validation(format!(
                        "genesis header validation failed: {e}"
                    )));
                }
            } else {
                let parent = self
                    .history
                    .load_header(&header.parent_id)?
                    .ok_or_else(|| {
                        NodeViewError::Validation(format!(
                            "parent header not found for header at height {}",
                            header.height
                        ))
                    })?;
                let now_ms = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;
                let required_n_bits = self.compute_required_difficulty(&header, &parent);
                if let Err(e) = validate_child_header(
                    &header,
                    &parent,
                    now_ms,
                    required_n_bits,
                    self.max_time_drift_ms,
                ) {
                    return Err(NodeViewError::Validation(format!(
                        "header {} validation failed: {e}",
                        header.height
                    )));
                }
            }

            // Store header with full indexing (height, best_header, chain scoring).
            self.history.store_header_with_score(modifier_id, &header)?;
            let info = self.history.process_header(modifier_id)?;
            return Ok(info);
        }

        // For block sections, the modifier_id from the network is the
        // computed section_id.  The actual header_id is embedded in the
        // first 32 bytes of the serialized data.  We extract it and store
        // under header_id (our internal DB key), not section_id.
        let header_id = if data.len() >= 32 {
            let mut hid = [0u8; 32];
            hid.copy_from_slice(&data[..32]);
            ModifierId(hid)
        } else {
            return Err(NodeViewError::Codec(
                "body section data too short to extract header_id".into(),
            ));
        };

        // Diagnostic: log body section reception details
        tracing::info!(
            type_id,
            data_len = data.len(),
            header_id_hex = hex::encode(header_id.0),
            section_id_hex = hex::encode(modifier_id.0),
            first_64_hex = hex::encode(&data[..data.len().min(64)]),
            "body section received"
        );

        self.history.put_modifier(type_id, &header_id, data)?;

        let info = self
            .history
            .process_block_section(type_id, modifier_id, &header_id)?;

        if !info.to_apply.is_empty() {
            self.apply_progress(&info)?;
        }

        Ok(info)
    }

    /// Process a header that has already been parsed and PoW-validated
    /// (e.g., in a parallel batch via rayon). Only parent-dependent checks
    /// remain: height sequencing, timestamp ordering, future-timestamp
    /// drift, and required difficulty.
    pub fn process_prevalidated_header(
        &mut self,
        modifier_id: &ModifierId,
        header: &ergo_types::header::Header,
    ) -> Result<ProgressInfo, NodeViewError> {
        if header.is_genesis() {
            let now_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            if let Err(e) = ergo_consensus::header_validation::validate_genesis_header_skip_pow(
                header,
                now_ms,
                None,
                None,
                self.max_time_drift_ms,
            ) {
                return Err(NodeViewError::Validation(format!(
                    "genesis header validation failed: {e}"
                )));
            }
        } else {
            let parent = self
                .history
                .load_header(&header.parent_id)?
                .ok_or_else(|| {
                    NodeViewError::Validation(format!(
                        "parent header not found for header at height {}",
                        header.height
                    ))
                })?;
            let now_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            let required_n_bits = self.compute_required_difficulty(header, &parent);
            if let Err(e) = ergo_consensus::header_validation::validate_child_header_skip_pow(
                header,
                &parent,
                now_ms,
                required_n_bits,
                self.max_time_drift_ms,
            ) {
                return Err(NodeViewError::Validation(format!(
                    "header {} validation failed: {e}",
                    header.height
                )));
            }
        }
        self.history.store_header_with_score(modifier_id, header)?;
        let info = self.history.process_header(modifier_id)?;
        Ok(info)
    }

    /// Internal: apply `ProgressInfo` by processing blocks in `to_apply`
    /// and handling chain reorganizations via `to_remove`.
    ///
    /// For chain switches (when `branch_point` is set):
    /// 1. Roll back state to the branch point.
    /// 2. Mark all `to_remove` blocks as Invalid.
    ///
    /// For each block in `to_apply`:
    /// 1. Validate and apply the block via [`validate_and_apply_block`].
    /// 2. On failure, mark the block as Invalid and return the error.
    pub fn apply_progress(&mut self, info: &ProgressInfo) -> Result<(), NodeViewError> {
        // Collect transactions from rolled-back blocks for mempool re-addition.
        let mut rolled_back_txs: Vec<ergo_types::transaction::ErgoTransaction> = Vec::new();

        // Handle chain switch: rollback state and unmark old chain.
        if let Some(branch_point) = &info.branch_point {
            if !info.to_remove.is_empty() {
                tracing::info!(
                    branch_point = ?branch_point,
                    to_remove = info.to_remove.len(),
                    to_apply = info.to_apply.len(),
                    "chain reorganization",
                );

                // Collect transactions from rolled-back blocks before state rollback.
                for block_id in &info.to_remove {
                    if let Ok(Some(bt)) = self.history.load_block_transactions(block_id) {
                        for tx_bytes in &bt.tx_bytes {
                            if let Ok(tx) = parse_transaction(tx_bytes) {
                                rolled_back_txs.push(tx);
                            }
                        }
                    }
                }

                // Roll back state to the branch point.
                if self.digest_mode {
                    // In digest mode, rollback is best-effort: the version
                    // history may be empty when blocks were applied via
                    // header-based state root updates rather than through
                    // DigestState.apply_full_block.  If rollback fails, log
                    // a warning and continue -- each subsequent block will
                    // overwrite the state root from its header anyway.
                    match self.digest_state.rollback_to_version(branch_point) {
                        Ok(()) => {
                            self.current_state_root = self.digest_state.state_root().to_vec();
                        }
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                "digest state rollback failed (best-effort), continuing"
                            );
                        }
                    }
                } else {
                    self.utxo_state
                        .rollback_to_version(branch_point)
                        .map_err(|e| NodeViewError::State(format!("rollback failed: {e}")))?;
                    self.current_state_root = self
                        .utxo_state
                        .state_root()
                        .map_err(|e| NodeViewError::State(format!("{e}")))?;
                }
                self.current_state_version = *branch_point;

                // Record the branch point height for wallet rollback.
                if let Ok(Some(bp_header)) = self.history.load_header(branch_point) {
                    self.last_rollback_height = Some(bp_header.height);
                    self.best_full_height = bp_header.height;
                }

                // Unmark old chain blocks.
                for block_id in &info.to_remove {
                    self.history
                        .set_validity(block_id, ModifierValidity::Invalid)?;
                }
            }
        }

        // Collect applied transactions to filter from rolled-back set.
        let mut applied_tx_ids: std::collections::HashSet<ergo_types::transaction::TxId> =
            std::collections::HashSet::new();

        // Apply new chain blocks.
        for block_id in &info.to_apply {
            // Skip blocks whose sections haven't all arrived yet — during
            // initial sync, `chain_from_ancestor` may include intermediate
            // blocks that aren't complete.  These will be retried when their
            // remaining sections arrive.
            if !self.history.has_all_sections(block_id).unwrap_or(false) {
                tracing::debug!(
                    ?block_id,
                    "skipping incomplete block in to_apply (sections not yet received)"
                );
                continue;
            }

            match self.validate_and_apply_block(block_id) {
                Ok(()) => {
                    // Collect tx IDs from this applied block.
                    if !rolled_back_txs.is_empty() {
                        if let Ok(Some(bt)) = self.history.load_block_transactions(block_id) {
                            for tx_bytes in &bt.tx_bytes {
                                if let Ok(tx) = parse_transaction(tx_bytes) {
                                    applied_tx_ids.insert(tx.tx_id);
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(block_id = ?block_id, error = %e, "block validation failed");
                    self.history
                        .set_validity(block_id, ModifierValidity::Invalid)?;
                    return Err(e);
                }
            }
        }

        // Re-add rolled-back transactions to mempool (minus those in the new chain).
        // This matches Scala's updateMemPool behavior in ErgoNodeViewHolder.
        if !rolled_back_txs.is_empty() {
            let eligible: Vec<ergo_types::transaction::ErgoTransaction> = rolled_back_txs
                .into_iter()
                .filter(|tx| !applied_tx_ids.contains(&tx.tx_id))
                .collect();

            if !eligible.is_empty() {
                let mut mp = self.mempool.write().unwrap();
                let mut readded = 0u32;
                for tx in eligible {
                    // Use put_no_fee_check: these txs were previously valid, and
                    // re-adding them should not be blocked by fee requirements.
                    if mp.put_no_fee_check(tx).is_ok() {
                        readded += 1;
                    }
                }
                if readded > 0 {
                    tracing::info!(readded, "re-added rolled-back transactions to mempool");
                }
            }
        }

        Ok(())
    }

    /// Compute the required nBits for a child header given its parent.
    ///
    /// Returns `None` if epoch headers aren't available for recalculation,
    /// or if the header is below the checkpoint height. When `None` is
    /// returned, the difficulty check should be skipped.
    fn compute_required_difficulty(
        &self,
        header: &ergo_types::header::Header,
        parent: &ergo_types::header::Header,
    ) -> Option<u32> {
        compute_required_difficulty_from_history(
            &self.history,
            header.height,
            parent,
            self.checkpoint_height,
        )
    }

    /// Difficulty verification.
    ///
    /// For mid-epoch blocks, verifies that the block's nBits matches the
    /// parent's nBits. For epoch boundary blocks, performs full difficulty
    /// recalculation using historical headers.
    fn verify_difficulty(
        &self,
        block: &ergo_types::transaction::ErgoFullBlock,
    ) -> Result<(), NodeViewError> {
        const EIP37_ACTIVATION_HEIGHT: u32 = 844_673;
        const CLASSIC_EPOCH_LENGTH: u32 = 1024;
        const EIP37_EPOCH_LENGTH: u32 = 128;
        const DESIRED_INTERVAL_MS: u64 = 120_000;
        const USE_LAST_EPOCHS: u32 = 8;

        // Skip genesis (height 1) -- no parent to compare against.
        if block.header.height <= 1 {
            return Ok(());
        }

        // Below checkpoint_height, skip difficulty verification (same mechanism
        // used for sigma proof verification).
        if block.header.height <= self.checkpoint_height {
            return Ok(());
        }

        // Autolykos v2 activation boundary: enforce initialDifficultyVersion2.
        // Scala: parentHeight == v2Height || parentHeight + 1 == v2Height
        // => blockHeight == v2Height + 1 || blockHeight == v2Height
        if self.v2_activation_height > 0 {
            let parent_height = block.header.height - 1;
            if parent_height == self.v2_activation_height
                || parent_height + 1 == self.v2_activation_height
            {
                let v2_diff_bytes =
                    hex::decode(&self.v2_activation_difficulty_hex).unwrap_or_default();
                if v2_diff_bytes.is_empty() {
                    return Ok(()); // no v2 difficulty configured, skip
                }
                let v2_diff = num_bigint::BigUint::from_bytes_be(&v2_diff_bytes);
                let expected_nbits =
                    ergo_consensus::difficulty::encode_compact_bits(&v2_diff) as u32;
                if block.header.n_bits != expected_nbits as u64 {
                    return Err(NodeViewError::Validation(format!(
                        "v2 activation difficulty mismatch at height {}: expected nBits={:08x}, got {:08x}",
                        block.header.height, expected_nbits, block.header.n_bits
                    )));
                }
                return Ok(());
            }
        }

        // Load parent header.
        let parent_header = match self.history.load_header(&block.header.parent_id) {
            Ok(Some(h)) => h,
            Ok(None) => {
                return Err(NodeViewError::Validation(format!(
                    "difficulty check failed at height {}: parent header not found",
                    block.header.height
                )));
            }
            Err(e) => {
                return Err(NodeViewError::State(format!("load parent header: {e}")));
            }
        };

        let parent_height = parent_header.height;

        // Determine if we are at an epoch boundary and which algorithm to use.
        let is_eip37 = block.header.height >= EIP37_ACTIVATION_HEIGHT;
        let epoch_length = if is_eip37 {
            EIP37_EPOCH_LENGTH
        } else {
            CLASSIC_EPOCH_LENGTH
        };
        let at_epoch_boundary = epoch_length > 0 && parent_height % epoch_length == 0;

        if !at_epoch_boundary {
            // Mid-epoch: nBits must equal parent's nBits.
            if block.header.n_bits != parent_header.n_bits {
                return Err(NodeViewError::Validation(format!(
                    "nBits mismatch at height {}: declared={}, parent={}",
                    block.header.height, block.header.n_bits, parent_header.n_bits
                )));
            }
        } else {
            // Epoch boundary: full difficulty recalculation.
            let required_heights = previous_heights_for_recalculation(
                block.header.height,
                epoch_length,
                USE_LAST_EPOCHS,
            );

            // Collect (height, timestamp_ms, n_bits) tuples for required heights.
            let mut header_data: Vec<(u32, u64, u32)> = Vec::with_capacity(required_heights.len());
            for &h in &required_heights {
                let ids = self.history.header_ids_at_height(h).unwrap_or_default();
                if let Some(id) = ids.first() {
                    match self.history.load_header(id) {
                        Ok(Some(hdr)) => {
                            header_data.push((hdr.height, hdr.timestamp, hdr.n_bits as u32));
                        }
                        _ => {
                            return Err(NodeViewError::Validation(format!(
                                "difficulty check failed at height {}: required header at height {} not loadable",
                                block.header.height, h
                            )));
                        }
                    }
                } else {
                    return Err(NodeViewError::Validation(format!(
                        "difficulty check failed at height {}: no header found at required height {}",
                        block.header.height, h
                    )));
                }
            }

            if header_data.len() < 2 {
                return Err(NodeViewError::Validation(format!(
                    "difficulty check failed at height {}: insufficient headers for recalculation (have {}, need >=2)",
                    block.header.height, header_data.len()
                )));
            }

            let expected_nbits = if is_eip37 {
                calculate_eip37(&header_data, epoch_length, DESIRED_INTERVAL_MS)
            } else {
                calculate_classic(&header_data, epoch_length, DESIRED_INTERVAL_MS)
            };

            let declared_nbits = block.header.n_bits as u32;
            if declared_nbits != expected_nbits {
                return Err(NodeViewError::Validation(format!(
                    "nBits mismatch at epoch boundary height {}: declared={}, expected={}",
                    block.header.height, declared_nbits, expected_nbits
                )));
            }
        }

        Ok(())
    }

    /// Validate and apply a single block through the full pipeline.
    ///
    /// Stages:
    /// 1. Assembles the full block from stored sections.
    /// 2. Structural validation (Merkle roots, AD proofs root, header_id consistency).
    /// 3. Best-effort difficulty verification.
    /// 4. Parses transactions from raw bytes.
    /// 5. Stateless validation for each transaction.
    /// 6. State application (mode-dependent: digest or UTXO).
    /// 7. Marks the block as Valid and updates the best full block pointer.
    fn validate_and_apply_block(&mut self, block_id: &ModifierId) -> Result<(), NodeViewError> {
        // Stage 0: Short-circuit already-valid blocks (rule 300).
        // When we encounter an already-valid block, fast-forward past the
        // entire consecutive valid range so subsequent body section arrivals
        // don't re-discover the same blocks 128 at a time.
        if let Ok(Some(ModifierValidity::Valid)) = self.history.get_validity(block_id) {
            // If this block is at or below best_full_block, skip silently.
            // This happens when a 128-block batch becomes stale after a
            // fast-forward jumped past most of its members.
            if let Ok(Some(hdr)) = self.history.load_header(block_id) {
                if hdr.height <= self.best_full_height {
                    return Ok(());
                }
            }
            tracing::debug!(?block_id, "block already applied, fast-forwarding");
            if let Err(e) = self.fast_forward_valid_blocks() {
                tracing::warn!(error = %e, "fast-forward in already-applied path failed, advancing one block");
                if let Err(e) = self.history.set_best_full_block_id(block_id) {
                    tracing::warn!(error = %e, "failed to advance best_full_block for already-applied block");
                }
                if self.digest_mode {
                    self.current_state_version = *block_id;
                    if let Err(e) = self.history.set_state_version(block_id) {
                        tracing::warn!(error = %e, "failed to persist state version for already-applied block");
                    }
                }
            }
            return Ok(());
        }

        // Stage 1: Assemble full block from stored sections.
        let block = self
            .history
            .assemble_full_block(block_id)?
            .ok_or_else(|| NodeViewError::State(format!("cannot assemble block {block_id:?}")))?;

        // Stage 0b: Reject previously-invalid blocks — but below checkpoint,
        // clear stale Invalid markers from prior runs and proceed.
        if let Ok(Some(ModifierValidity::Invalid)) = self.history.get_validity(block_id) {
            if block.header.height > self.checkpoint_height {
                return Err(NodeViewError::Validation(format!(
                    "block {block_id:?} previously marked invalid"
                )));
            }
            // Below checkpoint: clear the stale Invalid marker so we can retry.
            tracing::debug!(
                height = block.header.height,
                ?block_id,
                "clearing stale Invalid marker (below checkpoint)"
            );
            let _ = self.history.clear_validity(block_id);
        }

        // Stage 1c: Reject block sections for pruned headers (rule 305).
        if self.blocks_to_keep >= 0 {
            let min_height = self.history.minimal_full_block_height().unwrap_or(0);
            if min_height > 0 && block.header.height < min_height {
                return Err(NodeViewError::Validation(format!(
                    "block at height {} too old (min: {})",
                    block.header.height, min_height
                )));
            }
        }

        // Stage 1d: Reject headers whose parent is semantically invalid (rule 210).
        // Below checkpoint, skip this check — parents may have stale Invalid markers.
        if block.header.height > self.checkpoint_height {
            let parent_is_invalid = matches!(
                self.history.get_validity(&block.header.parent_id),
                Ok(Some(ModifierValidity::Invalid))
            );
            validate_parent_semantics(&block.header.parent_id, parent_is_invalid).map_err(|e| {
                NodeViewError::Validation(format!(
                    "parent semantics check failed at height {}: {e}",
                    block.header.height
                ))
            })?;
        }

        // Stage 1e: Block transactions size check (rule 306).
        // This is checked early (before structural validation) as a cheap
        // sanity check to avoid wasting time on oversized blocks.
        {
            let bt_size: usize = block
                .block_transactions
                .tx_bytes
                .iter()
                .map(|b| b.len())
                .sum();
            let max_block_size = self.voting_epoch_info.parameters.max_block_size() as usize;
            if bt_size > max_block_size {
                return Err(NodeViewError::Validation(format!(
                    "block transactions size {} exceeds max {} at height {}",
                    bt_size, max_block_size, block.header.height
                )));
            }
        }

        // Stage 2: Structural validation (Merkle roots, AD proofs root, header_id consistency).
        let vs = self.validation_settings().clone();
        validate_full_block(&block, block_id, self.digest_mode, &vs)?;

        // Stage 2b: Block version validation against parameters.
        // The expected version comes from the parameters system (BLOCK_VERSION_ID = 123).
        // Default is version 1 (genesis). After soft-fork activation (e.g. Autolykos v2
        // at height 417,792), the expected version is bumped to 2.
        //
        // On restart, voting_epoch_info starts at genesis (version 1) and is only
        // updated via Stage 7b as blocks are applied.  If we restart mid-sync at
        // height 417,791 and then try to apply 417,792, Stage 7b never ran for the
        // epoch boundary so parameters still show version 1.  Apply the hardcoded
        // v2 activation eagerly here — matching the logic in
        // Parameters::update_at_epoch_start — so the check passes and Stage 7b can
        // then set the persisted parameters correctly.
        let expected_version = {
            let pv = self.voting_epoch_info.parameters.block_version();
            // Hardcoded v2 activation (non-voted hard-fork at 417,792).
            let pv = if block.header.height >= self.v2_activation_height && pv < 2 {
                self.voting_epoch_info
                    .parameters
                    .table
                    .insert(ergo_consensus::parameters::BLOCK_VERSION_ID, 2);
                2u8
            } else {
                pv
            };
            // At epoch boundaries the new parameters are declared in this block's Extension.
            // On restart, voting_epoch_info may not have replayed vote accumulation for the
            // previous epoch, so the computed version can lag behind the declared one.
            // Trust the declared block_version (max with what we computed) so that
            // voted-in version upgrades (e.g. v2→v3) don't block validation.
            if block.header.height % self.epoch_length == 0 && block.header.height > 0 {
                if let Ok(declared) = Parameters::from_extension(
                    block.header.height,
                    &block.extension,
                ) {
                    let dv = declared.block_version();
                    if dv > pv {
                        self.voting_epoch_info
                            .parameters
                            .table
                            .insert(ergo_consensus::parameters::BLOCK_VERSION_ID, dv as i32);
                        dv
                    } else {
                        pv
                    }
                } else {
                    pv
                }
            } else {
                pv
            }
        };
        validate_block_version(&block.header, expected_version).map_err(|e| {
            NodeViewError::Validation(format!(
                "block version check failed at height {}: {e}",
                block.header.height
            ))
        })?;

        // Stage 2c: Vote validation (rules 212-215).
        let epoch_starts = block.header.height > 0 && block.header.height % self.epoch_length == 0;
        ergo_consensus::vote_validation::validate_votes(&block.header.votes, epoch_starts)
            .map_err(|e| {
                NodeViewError::Validation(format!(
                    "vote validation failed at height {}: {e}",
                    block.header.height
                ))
            })?;

        // Stage 2c2: Fork vote prohibition check (rule 407).
        // If the block votes contain SoftFork (120), verify that voting for a
        // fork is not prohibited at this height.
        if block
            .header
            .votes
            .contains(&ergo_consensus::parameters::SOFT_FORK_ID)
        {
            ergo_consensus::parameters::check_fork_vote(
                block.header.height,
                &self.voting_epoch_info.parameters,
                self.epoch_length,
                ergo_consensus::parameters::SOFT_FORK_EPOCHS,
                ergo_consensus::parameters::ACTIVATION_EPOCHS,
            )
            .map_err(|e| {
                NodeViewError::Validation(format!(
                    "fork vote check failed at height {}: {e}",
                    block.header.height
                ))
            })?;
        }

        // Stage 2d: Extension validation (rules 400, 403-406).
        {
            let is_genesis = block.header.height <= 1;
            let serialized_size =
                ergo_consensus::extension_validation::compute_extension_serialized_size(
                    &block.extension,
                );
            ergo_consensus::extension_validation::validate_extension(
                &block.extension,
                is_genesis,
                serialized_size,
            )
            .map_err(|e| {
                NodeViewError::Validation(format!(
                    "extension validation failed at height {}: {e}",
                    block.header.height
                ))
            })?;
        }

        // Stage 2e: Interlinks validation (rules 401/402).
        // Skip for genesis blocks and below checkpoint (consistent with other strict checks).
        if block.header.height > 1 && block.header.height > self.checkpoint_height {
            let parent_ext = self
                .history
                .load_extension(&block.header.parent_id)
                .ok()
                .flatten();
            let parent_header = self
                .history
                .load_header(&block.header.parent_id)
                .ok()
                .flatten();

            if let (Some(p_ext), Some(p_hdr)) = (parent_ext, parent_header) {
                use crate::nipopow::{unpack_interlinks, update_interlinks};
                let current_interlinks = unpack_interlinks(&block.extension);
                let parent_interlinks = unpack_interlinks(&p_ext);
                let expected =
                    update_interlinks(&p_hdr, &block.header.parent_id, &parent_interlinks);

                if current_interlinks != expected {
                    return Err(NodeViewError::InvalidExtension(format!(
                        "interlinks mismatch at height {}: got {} entries, expected {}",
                        block.header.height,
                        current_interlinks.len(),
                        expected.len()
                    )));
                }
            }
        }

        // Stage 3: Best-effort difficulty verification.
        self.verify_difficulty(&block)?;

        // Stage 4: Parse transactions from raw bytes.
        let mut transactions = Vec::with_capacity(block.block_transactions.tx_bytes.len());
        for (i, tx_bytes) in block.block_transactions.tx_bytes.iter().enumerate() {
            let tx = parse_transaction(tx_bytes)
                .map_err(|e| NodeViewError::Codec(format!("tx {} parse failed: {e}", i)))?;
            transactions.push(tx);
        }

        // Stage 5: Stateless validation for each transaction.
        for (i, tx) in transactions.iter().enumerate() {
            validate_tx_stateless(tx, &vs)
                .map_err(|e| NodeViewError::TxValidation(format!("tx {} stateless: {e}", i)))?;
        }

        // Stage 5b: Stateful validation (UTXO mode only, above checkpoint).
        // Below checkpoint, skip input lookups and stateful validation —
        // the Scala reference also skips via `execTransactions` returning Valid(0L).
        // Collect resolved input boxes per-tx for reuse in Stage 5c.
        let above_checkpoint = block.header.height > self.checkpoint_height;
        let all_input_boxes: Vec<Vec<ergo_types::transaction::ErgoBox>> = if !self.digest_mode
            && above_checkpoint
        {
            let mut all = Vec::with_capacity(transactions.len());
            for (i, tx) in transactions.iter().enumerate() {
                let mut input_boxes = Vec::with_capacity(tx.inputs.len());
                for input in &tx.inputs {
                    let ergo_box = self.utxo_state.get_ergo_box(&input.box_id).map_err(|e| {
                        NodeViewError::State(format!("tx {} input box lookup: {e}", i))
                    })?;
                    let ergo_box = ergo_box.ok_or_else(|| {
                        NodeViewError::State(format!(
                            "tx {} input box {:?} not found in UTXO set",
                            i, input.box_id
                        ))
                    })?;
                    input_boxes.push(ergo_box);
                }
                let min_value_per_byte = self
                    .voting_epoch_info
                    .parameters
                    .min_value_per_byte()
                    .max(0) as u64;
                validate_tx_stateful(
                    tx,
                    &input_boxes,
                    block.header.height,
                    block.header.version,
                    min_value_per_byte,
                    &vs,
                )
                .map_err(|e| NodeViewError::TxValidation(format!("tx {} stateful: {e}", i)))?;
                all.push(input_boxes);
            }
            all
        } else {
            Vec::new()
        };

        // Stage 5b2: EIP-27 re-emission validation (UTXO mode only, above checkpoint).
        if !self.digest_mode && above_checkpoint {
            for (i, tx) in transactions.iter().enumerate() {
                let input_boxes = &all_input_boxes[i];
                ergo_consensus::reemission::verify_reemission_spending(
                    tx,
                    input_boxes,
                    block.header.height,
                )
                .map_err(|e| NodeViewError::TxValidation(format!("tx {} reemission: {e}", i)))?;
            }
        }

        // Stage 5c: Sigma proof verification (UTXO mode, above checkpoint).
        //
        // Three-phase pattern:
        //   Phase 1 (sequential): convert context once, compute initial+token costs,
        //           batch-resolve data input boxes, early-exit on cost budget.
        //   Phase 2 (parallel via rayon): sigma verification across all txs.
        //   Phase 3 (sequential): accumulate sigma costs in tx order, final budget check.
        if !self.digest_mode && block.header.height > self.checkpoint_height {
            use ergo_consensus::sigma_verify::{
                convert_state_context, verify_transaction_with_sigma_ctx, SigmaStateContext,
            };
            use rayon::prelude::*;

            // ── Phase 1: Sequential prep ────────────────────────────
            let sigma_ctx = SigmaStateContext {
                last_headers: self.get_last_headers(10),
                current_height: block.header.height,
                current_timestamp: block.header.timestamp,
                current_n_bits: block.header.n_bits,
                current_votes: block.header.votes,
                current_miner_pk: block.header.pow_solution.miner_pk,
                state_digest: block.header.state_root.0,
                parameters: self.voting_epoch_info.parameters.clone(),
                current_version: block.header.version,
                current_parent_id: block.header.parent_id.0,
            };

            // Convert once and share across all txs (avoids per-tx EC-point
            // parsing, parameter BTreeMap lookups, and PreHeader construction).
            let sigma_state_ctx = convert_state_context(&sigma_ctx)
                .map_err(|e| NodeViewError::TxValidation(format!("sigma context: {e}")))?;

            let max_block_cost = self.voting_epoch_info.parameters.max_block_cost() as u64;
            let mut accumulated_cost: u64 = 0;

            // Deduplicate and batch-resolve all data input boxes into a cache.
            let mut data_box_cache: std::collections::HashMap<
                ergo_types::transaction::BoxId,
                ergo_types::transaction::ErgoBox,
            > = std::collections::HashMap::new();
            for (i, tx) in transactions.iter().enumerate() {
                for di in &tx.data_inputs {
                    if let std::collections::hash_map::Entry::Vacant(entry) =
                        data_box_cache.entry(di.box_id)
                    {
                        let b = self
                            .utxo_state
                            .get_ergo_box(&di.box_id)
                            .map_err(|e| {
                                NodeViewError::TxValidation(format!(
                                    "tx {} data input box lookup: {e}",
                                    i
                                ))
                            })?
                            .ok_or_else(|| {
                                NodeViewError::TxValidation(format!(
                                    "tx {} data input box {} not found in UTXO set",
                                    i, di.box_id
                                ))
                            })?;
                        entry.insert(b);
                    }
                }
            }

            // Per-tx prep: compute initial+token costs, build data_boxes vec.
            struct TxPrep {
                data_boxes: Vec<ergo_types::transaction::ErgoBox>,
            }
            let mut prepared: Vec<TxPrep> = Vec::with_capacity(transactions.len());

            for (i, tx) in transactions.iter().enumerate() {
                let initial_cost = ergo_consensus::sigma_verify::compute_initial_tx_cost(
                    tx,
                    &self.voting_epoch_info.parameters,
                );
                accumulated_cost = accumulated_cost.saturating_add(initial_cost);

                let input_boxes = &all_input_boxes[i];
                let token_cost = ergo_consensus::sigma_verify::compute_token_access_cost(
                    input_boxes,
                    &tx.output_candidates,
                    &self.voting_epoch_info.parameters,
                )
                .map_err(|e| NodeViewError::TxValidation(format!("tx {} token cost: {e}", i)))?;
                accumulated_cost = accumulated_cost.saturating_add(token_cost);

                if accumulated_cost > max_block_cost {
                    return Err(NodeViewError::TxValidation(format!(
                        "block cost exceeded at tx {}: {} > {}",
                        i, accumulated_cost, max_block_cost
                    )));
                }

                // Build data_boxes from cache (HashMap lookup, not AVL traversal).
                let data_boxes: Vec<ergo_types::transaction::ErgoBox> = tx
                    .data_inputs
                    .iter()
                    .map(|di| data_box_cache[&di.box_id].clone())
                    .collect();

                prepared.push(TxPrep { data_boxes });
            }

            // ── Phase 2: Parallel sigma verification via rayon ──────
            let sigma_results: Vec<Result<u64, (usize, String)>> = transactions
                .par_iter()
                .zip(all_input_boxes.par_iter())
                .zip(prepared.par_iter())
                .enumerate()
                .map(|(i, ((tx, input_boxes), prep))| {
                    verify_transaction_with_sigma_ctx(
                        tx,
                        input_boxes,
                        &prep.data_boxes,
                        &sigma_state_ctx,
                        block.header.height,
                        self.checkpoint_height,
                    )
                    .map_err(|e| (i, format!("{e}")))
                })
                .collect();

            // ── Phase 3: Sequential cost accumulation ───────────────
            for result in sigma_results {
                let sigma_cost = result.map_err(|(i, e)| {
                    NodeViewError::TxValidation(format!("tx {} sigma: {e}", i))
                })?;
                accumulated_cost = accumulated_cost.saturating_add(sigma_cost);
            }

            if accumulated_cost > max_block_cost {
                return Err(NodeViewError::TxValidation(format!(
                    "total block cost {} exceeds max {}",
                    accumulated_cost, max_block_cost
                )));
            }
        }

        // Stage 6: State application (mode-dependent).
        // Below checkpoint, skip internal tx validation and digest verification
        // in UTXO mode — the chain is trusted below checkpoint.
        if self.digest_mode {
            let changes = compute_state_changes(&transactions);
            self.digest_state
                .apply_full_block(&block, block_id, &changes)
                .map_err(|e| NodeViewError::State(format!("digest state: {e}")))?;
            self.current_state_root = self.digest_state.state_root().to_vec();
        } else if above_checkpoint {
            let expected_root = block.header.state_root.0.as_slice();
            self.utxo_state
                .apply_block(
                    &transactions,
                    block.header.height,
                    block.header.version,
                    block_id,
                    Some(expected_root),
                    &vs,
                )
                .map_err(|e| NodeViewError::State(format!("utxo state: {e}")))?;
            self.current_state_root = self
                .utxo_state
                .state_root()
                .map_err(|e| NodeViewError::State(format!("{e}")))?;
        } else {
            // Below checkpoint: apply state changes without tx validation or
            // digest verification. Removes for non-existent boxes (e.g. genesis
            // boxes that were never seeded) are silently skipped.
            self.utxo_state
                .apply_block_lenient(&transactions, block.header.height, block_id)
                .map_err(|e| NodeViewError::State(format!("utxo state (lenient): {e}")))?;
            self.current_state_root = self
                .utxo_state
                .state_root()
                .map_err(|e| NodeViewError::State(format!("{e}")))?;
        }
        self.current_state_version = *block_id;

        // Persist state version for recovery on restart.
        if let Err(e) = self.history.set_state_version(block_id) {
            tracing::warn!(error = %e, "failed to persist state version");
        }

        // Stage 7: Mark block valid and update best full block.
        self.history
            .set_validity(block_id, ModifierValidity::Valid)?;
        self.history.set_best_full_block_id(block_id)?;
        self.best_full_height = block.header.height;

        // Track applied block for Inv broadcast.
        self.applied_blocks.push(*block_id);

        // Stage 7b: Process votes and update parameters.
        self.voting_epoch_info
            .process_block_votes(&block.header.votes);

        // At epoch boundary, parse Extension parameters and start new epoch.
        if block.header.height > 0 && block.header.height % self.epoch_length == 0 {
            match Parameters::from_extension(block.header.height, &block.extension) {
                Ok(declared) => {
                    let computed = self
                        .voting_epoch_info
                        .compute_epoch_result(self.epoch_length, block.header.height);
                    // Enforce parameter matching (Scala matchParameters).
                    // Below checkpoint, log-only for leniency during initial sync.
                    // Above checkpoint, reject blocks with mismatched parameters.
                    let above_checkpoint = block.header.height > self.checkpoint_height;
                    for (&id, &computed_val) in &computed.table {
                        if let Some(&declared_val) = declared.table.get(&id) {
                            if declared_val != computed_val {
                                if above_checkpoint {
                                    return Err(NodeViewError::InvalidExtension(format!(
                                        "parameter mismatch at epoch boundary: id={}, declared={}, computed={}",
                                        id, declared_val, computed_val
                                    )));
                                } else {
                                    tracing::warn!(
                                        param_id = id,
                                        declared = declared_val,
                                        computed = computed_val,
                                        height = block.header.height,
                                        "parameter mismatch below checkpoint (using declared)"
                                    );
                                }
                            }
                        }
                    }
                    self.voting_epoch_info
                        .start_new_epoch(declared, block.header.height);
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        height = block.header.height,
                        "failed to parse epoch parameters from Extension"
                    );
                }
            }

            // Update validation settings from the epoch boundary Extension (rules 411/412).
            if let Err(e) = self
                .voting_epoch_info
                .update_validation_settings(&block.extension)
            {
                return Err(NodeViewError::Validation(e));
            }
        }

        // Stage 8: Evict conflicting mempool transactions.
        self.mempool
            .write()
            .unwrap()
            .remove_for_block(&transactions);

        // Stage 9: Prune old block body sections if blocks_to_keep is configured.
        self.prune_old_blocks(block.header.height);

        Ok(())
    }

    /// Get current state root digest.
    pub fn state_root(&self) -> &[u8] {
        &self.current_state_root
    }

    /// Get the ID of the last block whose state was applied.
    ///
    /// Returns `None` if no state has been applied yet (all-zero ID).
    pub fn state_version_id(&self) -> Option<[u8; 32]> {
        if self.current_state_version == ModifierId([0u8; 32]) {
            None
        } else {
            Some(self.current_state_version.0)
        }
    }

    /// Get current best full block ID from storage.
    pub fn best_full_block_id(&self) -> Result<Option<ModifierId>, NodeViewError> {
        Ok(self.history.best_full_block_id()?)
    }

    /// Get the current on-chain parameters.
    pub fn current_parameters(&self) -> &Parameters {
        &self.voting_epoch_info.parameters
    }

    /// Whether the node is running in digest (SPV-like) mode.
    pub fn is_digest_mode(&self) -> bool {
        self.digest_mode
    }

    /// Check if a validation rule is currently active.
    pub fn is_rule_active(&self, rule_id: u16) -> bool {
        self.voting_epoch_info
            .validation_settings
            .is_active(rule_id)
    }

    /// Get a reference to the current validation settings.
    pub fn validation_settings(&self) -> &ValidationSettings {
        &self.voting_epoch_info.validation_settings
    }

    /// Check whether a box exists in the UTXO state.
    ///
    /// Only meaningful in UTXO mode. Returns `false` in digest mode
    /// (no UTXO set to query).
    pub fn box_exists_in_utxo(&self, box_id: &ergo_types::transaction::BoxId) -> bool {
        if self.digest_mode {
            return false;
        }
        self.utxo_state.get_box(box_id).is_some()
    }

    /// Replace the UTXO state with a pre-built one (e.g., restored from DB).
    pub fn set_utxo_state(&mut self, utxo_state: UtxoState) {
        self.utxo_state = utxo_state;
    }

    /// Get a reference to the UTXO state, or `None` if in digest mode.
    pub fn utxo_state(&self) -> Option<&UtxoState> {
        if self.digest_mode {
            None
        } else {
            Some(&self.utxo_state)
        }
    }

    /// Get a reference to the UTXO DB (if UTXO mode with persistence).
    pub fn utxo_db(&self) -> Option<&ergo_storage::utxo_db::UtxoDb> {
        self.utxo_state.utxo_db()
    }

    /// Build a [`SigmaStateContext`] suitable for mempool transaction verification.
    ///
    /// Returns `None` if no best full block header is available (e.g., during
    /// initial sync before any block has been applied).
    ///
    /// The context simulates the "next" block: height and timestamp are
    /// incremented by 1 from the best full block header, while nBits, votes,
    /// miner PK, and state digest are taken directly from the best header.
    fn build_mempool_sigma_context(
        &self,
    ) -> Option<ergo_consensus::sigma_verify::SigmaStateContext> {
        let best_id = self.history.best_full_block_id().ok()??;
        let best_header = self.history.load_header(&best_id).ok()??;

        let last_headers = self.get_last_headers(10);

        Some(ergo_consensus::sigma_verify::SigmaStateContext {
            last_headers,
            current_height: best_header.height + 1,
            current_timestamp: best_header.timestamp + 1,
            current_n_bits: best_header.n_bits,
            current_votes: best_header.votes,
            current_miner_pk: best_header.pow_solution.miner_pk,
            state_digest: best_header.state_root.0,
            parameters: self.voting_epoch_info.parameters.clone(),
            current_version: best_header.version,
            current_parent_id: best_id.0,
        })
    }

    /// Attempt sigma proof verification for a mempool transaction.
    ///
    /// This is only meaningful in UTXO mode. In digest mode, or when the
    /// UTXO state is not yet populated, verification is skipped and the
    /// transaction is accepted (returns `Ok(())`).
    ///
    /// If any input box cannot be found in the UTXO set (e.g., it depends
    /// on another unconfirmed transaction), sigma verification is skipped
    /// for that transaction (best-effort approach).
    pub fn try_sigma_verify_mempool_tx(
        &self,
        tx: &ergo_types::transaction::ErgoTransaction,
    ) -> Result<(), ergo_consensus::sigma_verify::SigmaVerifyError> {
        if self.digest_mode {
            return Ok(());
        }

        let sigma_ctx = match self.build_mempool_sigma_context() {
            Some(ctx) => ctx,
            None => return Ok(()),
        };

        // Look up input boxes from the UTXO set. If any box is missing
        // (e.g., it is an output of another unconfirmed tx), skip
        // sigma verification entirely for this transaction.
        let mut input_boxes = Vec::with_capacity(tx.inputs.len());
        for input in &tx.inputs {
            match self.utxo_state.get_ergo_box(&input.box_id) {
                Ok(Some(b)) => input_boxes.push(b),
                _ => {
                    tracing::debug!(
                        box_id = ?input.box_id,
                        "mempool sigma: input box not in UTXO set, skipping verification"
                    );
                    return Ok(());
                }
            }
        }

        // Resolve data input boxes (best-effort: missing data boxes are omitted).
        let mut data_boxes = Vec::new();
        for di in &tx.data_inputs {
            if let Ok(Some(b)) = self.utxo_state.get_ergo_box(&di.box_id) {
                data_boxes.push(b);
            }
        }

        ergo_consensus::sigma_verify::verify_transaction(
            tx,
            &input_boxes,
            &data_boxes,
            &sigma_ctx,
            self.checkpoint_height,
        )?;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_types::ad_proofs::ADProofs;
    use ergo_types::block_transactions::BlockTransactions;
    use ergo_types::extension::Extension;
    use ergo_types::header::Header;
    use tempfile::TempDir;

    /// Compute Blake2b-256 of raw data (test helper).
    fn test_blake2b256(data: &[u8]) -> [u8; 32] {
        use blake2::digest::{Update, VariableOutput};
        use blake2::Blake2bVar;
        let mut hasher = Blake2bVar::new(32).expect("valid output size");
        hasher.update(data);
        let mut out = [0u8; 32];
        hasher
            .finalize_variable(&mut out)
            .expect("correct output size");
        out
    }

    fn open_test_db() -> (HistoryDb, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = HistoryDb::open(dir.path()).unwrap();
        (db, dir)
    }

    fn make_id(fill: u8) -> ModifierId {
        ModifierId([fill; 32])
    }

    /// Returns the initial AVL+ tree root digest from a fresh UtxoState.
    /// This is the genesis state root that all empty-block tests expect.
    fn initial_utxo_root() -> Vec<u8> {
        UtxoState::new()
            .state_root()
            .expect("fresh UtxoState should have a digest")
    }

    fn genesis_digest() -> Vec<u8> {
        initial_utxo_root()
    }

    /// Creates a NodeViewHolder with checkpoint_height=0 (strictest difficulty checking).
    /// Use this for tests that specifically test difficulty verification.
    fn make_node_view(db: HistoryDb) -> NodeViewHolder {
        let mempool = Arc::new(RwLock::new(ErgoMemPool::with_min_fee(1000, 0)));
        let mut nv = NodeViewHolder::new(db, mempool, false, genesis_digest());
        // Test headers use version 2 (current mainnet), so set parameters to match.
        nv.voting_epoch_info
            .parameters
            .table
            .insert(ergo_consensus::parameters::BLOCK_VERSION_ID, 2);
        nv
    }

    /// Creates a NodeViewHolder with a high checkpoint_height so that difficulty
    /// verification is skipped. Use this for pipeline tests where parent headers
    /// are not stored and difficulty verification is not the focus.
    fn make_node_view_skip_difficulty(db: HistoryDb) -> NodeViewHolder {
        let mempool = Arc::new(RwLock::new(ErgoMemPool::with_min_fee(1000, 0)));
        let mut nv = NodeViewHolder::new(db, mempool, false, genesis_digest());
        nv.set_checkpoint_height(u32::MAX);
        // Test headers use version 2 (current mainnet), so set parameters to match.
        nv.voting_epoch_info
            .parameters
            .table
            .insert(ergo_consensus::parameters::BLOCK_VERSION_ID, 2);
        nv
    }

    /// Build a test header whose `state_root` matches the initial AVL tree root.
    /// This ensures that `apply_block` with empty transactions passes the
    /// digest verification check.
    fn make_header(height: u32, fill: u8) -> Header {
        let root = initial_utxo_root();
        let mut state_root = [0u8; 33];
        let len = root.len().min(33);
        state_root[..len].copy_from_slice(&root[..len]);

        let mut h = Header::default_for_test();
        h.version = 2;
        h.height = height;
        h.parent_id = ModifierId([fill; 32]);
        h.state_root = ergo_types::modifier_id::ADDigest(state_root);
        // Empty tx_bytes → empty merkle root
        h.transactions_root =
            ergo_types::modifier_id::Digest32(ergo_consensus::merkle::empty_merkle_root());
        // Set extension_root to match sample_extension() (non-empty).
        h.extension_root = ergo_types::modifier_id::Digest32(sample_extension_root());
        h
    }

    fn sample_block_transactions(header_id: &ModifierId) -> BlockTransactions {
        BlockTransactions {
            header_id: *header_id,
            block_version: 2,
            tx_bytes: Vec::new(), // Empty tx list matches empty_merkle_root()
        }
    }

    /// A single interlink field that makes the extension non-empty so that
    /// extension validation (rule 406 — exEmpty) passes for non-genesis blocks.
    const SAMPLE_EXT_FIELD: ([u8; 2], &[u8]) = ([0x01, 0x00], &[0x00]);

    fn sample_extension(header_id: &ModifierId) -> Extension {
        Extension {
            header_id: *header_id,
            fields: vec![(SAMPLE_EXT_FIELD.0, SAMPLE_EXT_FIELD.1.to_vec())],
        }
    }

    /// Compute the Merkle root that matches `sample_extension`.
    /// Uses Scala kvToLeaf format: [key_length_byte] ++ key ++ value.
    /// Single-element tree: paired with empty node → root = blake2b256(0x01 || leaf_hash).
    fn sample_extension_root() -> [u8; 32] {
        let mut leaf = Vec::new();
        leaf.push(SAMPLE_EXT_FIELD.0.len() as u8); // key length prefix
        leaf.extend_from_slice(&SAMPLE_EXT_FIELD.0);
        leaf.extend_from_slice(SAMPLE_EXT_FIELD.1);
        // Use ergo_consensus::merkle for correct root computation.
        let slices: Vec<&[u8]> = vec![leaf.as_slice()];
        ergo_consensus::merkle::merkle_root(&slices).unwrap()
    }

    fn sample_ad_proofs(header_id: &ModifierId) -> ADProofs {
        ADProofs {
            header_id: *header_id,
            proof_bytes: vec![0xDE, 0xAD, 0xBE, 0xEF],
        }
    }

    // 1. New NodeViewHolder has genesis state.
    #[test]
    fn new_node_view_has_genesis_state() {
        let (db, _dir) = open_test_db();
        let nv = make_node_view(db);
        assert_eq!(nv.state_root(), genesis_digest().as_slice());
    }

    // 2. process_modifier stores section — put raw bytes, verify contains_modifier.
    #[test]
    fn process_modifier_stores_section() {
        let (db, _dir) = open_test_db();
        let mut nv = make_node_view(db);

        // Body section data starts with 32-byte header_id.
        // The modifier_id passed in is the section_id (from the wire).
        let header_id = make_id(0xAA);
        let section_id = make_id(0xBB); // different from header_id
        let mut data = Vec::with_capacity(64);
        data.extend_from_slice(&header_id.0); // first 32 bytes = header_id
        data.extend_from_slice(b"extra-section-payload");

        // Use a non-header type so we exercise the block-section path.
        // type_id 102 = BlockTransactions. The block won't be complete
        // (no header or extension), so no apply happens.
        nv.process_modifier(102, &section_id, &data).unwrap();

        // Should be stored under header_id (extracted from data), not section_id.
        assert!(nv.history.contains_modifier(102, &header_id).unwrap());
        assert!(!nv.history.contains_modifier(102, &section_id).unwrap());
    }

    // 3. state_root returns current digest.
    #[test]
    fn state_root_returns_current_digest() {
        let (db, _dir) = open_test_db();
        let mempool = Arc::new(RwLock::new(ErgoMemPool::with_min_fee(100, 0)));
        let digest = vec![0x42; 33];
        let nv = NodeViewHolder::new(db, mempool, true, digest.clone());
        assert_eq!(nv.state_root(), digest.as_slice());
    }

    // 4. best_full_block_id returns None initially.
    #[test]
    fn best_full_block_id_none_initially() {
        let (db, _dir) = open_test_db();
        let nv = make_node_view(db);
        assert_eq!(nv.best_full_block_id().unwrap(), None);
    }

    // 5. Storing a header and calling process_header returns to_download for sections.
    #[test]
    fn process_header_returns_to_download() {
        let (db, _dir) = open_test_db();
        let nv = make_node_view(db);

        // Store a header directly (bypassing process_modifier which validates
        // PoW — test headers don't have valid PoW). This test verifies that
        // process_header produces the correct download list, not validation.
        let header = make_header(1, 0x00);
        let header_bytes = ergo_wire::header_ser::serialize_header(&header);
        let id = ModifierId(test_blake2b256(&header_bytes));
        nv.history.store_header_with_score(&id, &header).unwrap();
        let info = nv.history.process_header(&id).unwrap();

        // Should request 3 section downloads: BlockTransactions (102),
        // ADProofs (104), Extension (108).
        assert_eq!(info.to_download.len(), 3);
        assert!(info.to_apply.is_empty());

        let type_ids: Vec<u8> = info.to_download.iter().map(|(t, _)| *t).collect();
        assert!(type_ids.contains(&102));
        assert!(type_ids.contains(&104));
        assert!(type_ids.contains(&108));
    }

    // 6. Process all sections -> block assembled and applied.
    #[test]
    fn process_all_sections_block_applied() {
        let (db, _dir) = open_test_db();
        let mut nv = make_node_view_skip_difficulty(db);

        let id = make_id(0xCC);
        let header = make_header(100, 0xCC);

        // Store all sections via typed store methods so they can be
        // properly deserialized during assemble_full_block.
        nv.history.store_header(&id, &header).unwrap();
        nv.history
            .store_block_transactions(&id, &sample_block_transactions(&id))
            .unwrap();
        nv.history
            .store_extension(&id, &sample_extension(&id))
            .unwrap();

        // Now manually build a ProgressInfo and call apply_progress.
        let info = ProgressInfo::apply(vec![id]);
        nv.apply_progress(&info).unwrap();

        // Verify best full block was updated.
        assert_eq!(nv.best_full_block_id().unwrap(), Some(id));

        // Verify state root was updated from the header (digest mode).
        assert_eq!(nv.state_root(), header.state_root.0.as_slice());

        // Verify validity was set.
        let validity = nv.history.get_validity(&id).unwrap();
        assert_eq!(validity, Some(ModifierValidity::Valid));
    }

    // 7. apply_progress unmarks old chain blocks on reorg.
    #[test]
    fn apply_progress_unmarks_old_chain_on_reorg() {
        let (db, _dir) = open_test_db();
        let mut nv = make_node_view_skip_difficulty(db);

        // Store and *apply* a block for the old chain through the pipeline,
        // so the UTXO state records an undo entry for rollback.
        let old_id = make_id(0xD0);
        let old_header = make_header(100, 0xD0);
        nv.history.store_header(&old_id, &old_header).unwrap();
        nv.history
            .store_block_transactions(&old_id, &sample_block_transactions(&old_id))
            .unwrap();
        nv.history
            .store_extension(&old_id, &sample_extension(&old_id))
            .unwrap();
        let info_old = ProgressInfo::apply(vec![old_id]);
        nv.apply_progress(&info_old).unwrap();
        assert_eq!(
            nv.history.get_validity(&old_id).unwrap(),
            Some(ModifierValidity::Valid)
        );

        // Store a block for the new chain.
        let new_id = make_id(0xD1);
        let new_header = make_header(100, 0xD1);
        nv.history.store_header(&new_id, &new_header).unwrap();
        nv.history
            .store_block_transactions(&new_id, &sample_block_transactions(&new_id))
            .unwrap();
        nv.history
            .store_extension(&new_id, &sample_extension(&new_id))
            .unwrap();

        // Build a chain switch ProgressInfo.
        let branch_point = make_id(0x00);
        let info = ProgressInfo::chain_switch(branch_point, vec![old_id], vec![new_id]);
        nv.apply_progress(&info).unwrap();

        // Old chain block should be marked Invalid.
        let old_validity = nv.history.get_validity(&old_id).unwrap();
        assert_eq!(old_validity, Some(ModifierValidity::Invalid));

        // New chain block should be marked Valid.
        let new_validity = nv.history.get_validity(&new_id).unwrap();
        assert_eq!(new_validity, Some(ModifierValidity::Valid));

        // Best full block should be the new chain tip.
        assert_eq!(nv.best_full_block_id().unwrap(), Some(new_id));
    }

    // 8. validate_and_apply_block updates state root from header.
    #[test]
    fn validate_and_apply_block_updates_state_root() {
        let (db, _dir) = open_test_db();
        let mut nv = make_node_view_skip_difficulty(db);

        let id = make_id(0xE0);
        let header = make_header(200, 0xE0);
        let expected_root = header.state_root.0.to_vec();

        nv.history.store_header(&id, &header).unwrap();
        nv.history
            .store_block_transactions(&id, &sample_block_transactions(&id))
            .unwrap();
        nv.history
            .store_extension(&id, &sample_extension(&id))
            .unwrap();

        nv.validate_and_apply_block(&id).unwrap();

        // State root should match the header's state_root.
        assert_eq!(nv.state_root(), expected_root.as_slice());
        assert_eq!(nv.current_state_version, id);
    }

    // 9. validate_and_apply_block fails when block cannot be assembled.
    #[test]
    fn validate_and_apply_block_fails_missing_block() {
        let (db, _dir) = open_test_db();
        let mut nv = make_node_view(db);

        // Try to apply a block_id that has no sections stored.
        let missing_id = make_id(0xF0);
        let result = nv.validate_and_apply_block(&missing_id);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, NodeViewError::State(ref msg) if msg.contains("cannot assemble")),
            "expected State error about assembly, got: {err}"
        );
    }

    // 10. apply_progress skips incomplete blocks (sections not yet received).
    #[test]
    fn apply_progress_skips_incomplete_block() {
        let (db, _dir) = open_test_db();
        let mut nv = make_node_view(db);

        // Build a ProgressInfo with a block_id that has no sections.
        let missing_id = make_id(0xF1);
        let info = ProgressInfo::apply(vec![missing_id]);

        // Should succeed — incomplete blocks are silently skipped during
        // initial sync so they can be retried when sections arrive.
        let result = nv.apply_progress(&info);
        assert!(result.is_ok());

        // The block should have no validity set (not marked Invalid).
        let validity = nv.history.get_validity(&missing_id).unwrap();
        assert_eq!(validity, None);
    }

    // 11. Chain reorg rolls back state and applies new chain.
    //
    // Build two chains from a common ancestor, apply chain A blocks,
    // then create a chain_switch ProgressInfo to chain B. Verify old
    // chain blocks are marked Invalid, new chain blocks are Valid,
    // and best full block is the new chain tip.
    #[test]
    fn chain_reorg_rolls_back_and_applies_new_chain() {
        let (db, _dir) = open_test_db();
        let mut nv = make_node_view_skip_difficulty(db);

        // -- Common ancestor block --
        let ancestor_id = make_id(0xA0);
        let ancestor_header = make_header(99, 0xA0);
        nv.history
            .store_header(&ancestor_id, &ancestor_header)
            .unwrap();
        nv.history
            .store_block_transactions(&ancestor_id, &sample_block_transactions(&ancestor_id))
            .unwrap();
        nv.history
            .store_extension(&ancestor_id, &sample_extension(&ancestor_id))
            .unwrap();
        let info_ancestor = ProgressInfo::apply(vec![ancestor_id]);
        nv.apply_progress(&info_ancestor).unwrap();
        assert_eq!(nv.best_full_block_id().unwrap(), Some(ancestor_id));

        // -- Chain A: two blocks on top of ancestor --
        let chain_a1_id = make_id(0xA1);
        let chain_a1_header = make_header(100, 0xA1);
        nv.history
            .store_header(&chain_a1_id, &chain_a1_header)
            .unwrap();
        nv.history
            .store_block_transactions(&chain_a1_id, &sample_block_transactions(&chain_a1_id))
            .unwrap();
        nv.history
            .store_extension(&chain_a1_id, &sample_extension(&chain_a1_id))
            .unwrap();

        let chain_a2_id = make_id(0xA2);
        let chain_a2_header = make_header(101, 0xA2);
        nv.history
            .store_header(&chain_a2_id, &chain_a2_header)
            .unwrap();
        nv.history
            .store_block_transactions(&chain_a2_id, &sample_block_transactions(&chain_a2_id))
            .unwrap();
        nv.history
            .store_extension(&chain_a2_id, &sample_extension(&chain_a2_id))
            .unwrap();

        // Apply chain A blocks.
        let info_a = ProgressInfo::apply(vec![chain_a1_id, chain_a2_id]);
        nv.apply_progress(&info_a).unwrap();
        assert_eq!(nv.best_full_block_id().unwrap(), Some(chain_a2_id));
        assert_eq!(
            nv.history.get_validity(&chain_a1_id).unwrap(),
            Some(ModifierValidity::Valid)
        );
        assert_eq!(
            nv.history.get_validity(&chain_a2_id).unwrap(),
            Some(ModifierValidity::Valid)
        );

        // -- Chain B: two blocks from ancestor (longer/better chain) --
        let chain_b1_id = make_id(0xB1);
        let chain_b1_header = make_header(100, 0xB1);
        nv.history
            .store_header(&chain_b1_id, &chain_b1_header)
            .unwrap();
        nv.history
            .store_block_transactions(&chain_b1_id, &sample_block_transactions(&chain_b1_id))
            .unwrap();
        nv.history
            .store_extension(&chain_b1_id, &sample_extension(&chain_b1_id))
            .unwrap();

        let chain_b2_id = make_id(0xB2);
        let chain_b2_header = make_header(101, 0xB2);
        nv.history
            .store_header(&chain_b2_id, &chain_b2_header)
            .unwrap();
        nv.history
            .store_block_transactions(&chain_b2_id, &sample_block_transactions(&chain_b2_id))
            .unwrap();
        nv.history
            .store_extension(&chain_b2_id, &sample_extension(&chain_b2_id))
            .unwrap();

        // Chain switch: remove chain A blocks, apply chain B blocks.
        let info_switch = ProgressInfo::chain_switch(
            ancestor_id,
            vec![chain_a1_id, chain_a2_id],
            vec![chain_b1_id, chain_b2_id],
        );
        nv.apply_progress(&info_switch).unwrap();

        // Old chain blocks should be marked Invalid.
        assert_eq!(
            nv.history.get_validity(&chain_a1_id).unwrap(),
            Some(ModifierValidity::Invalid)
        );
        assert_eq!(
            nv.history.get_validity(&chain_a2_id).unwrap(),
            Some(ModifierValidity::Invalid)
        );

        // New chain blocks should be marked Valid.
        assert_eq!(
            nv.history.get_validity(&chain_b1_id).unwrap(),
            Some(ModifierValidity::Valid)
        );
        assert_eq!(
            nv.history.get_validity(&chain_b2_id).unwrap(),
            Some(ModifierValidity::Valid)
        );

        // Best full block should be the new chain tip.
        assert_eq!(nv.best_full_block_id().unwrap(), Some(chain_b2_id));

        // State root should match the last applied header's state root.
        assert_eq!(nv.state_root(), chain_b2_header.state_root.0.as_slice());

        // current_state_version should be the new chain tip.
        assert_eq!(nv.current_state_version, chain_b2_id);
    }

    // 12. Chain reorg unmarks old blocks and applies new ones — thorough
    //     verification of reorg state transitions.
    #[test]
    fn chain_reorg_unmarks_old_blocks_and_applies_new() {
        let (db, _dir) = open_test_db();
        let mut nv = make_node_view_skip_difficulty(db);

        // Store and apply old chain block, marking it Valid.
        let old_id = make_id(0xC0);
        let old_header = make_header(100, 0xC0);
        nv.history.store_header(&old_id, &old_header).unwrap();
        nv.history
            .store_block_transactions(&old_id, &sample_block_transactions(&old_id))
            .unwrap();
        nv.history
            .store_extension(&old_id, &sample_extension(&old_id))
            .unwrap();

        let info_apply = ProgressInfo::apply(vec![old_id]);
        nv.apply_progress(&info_apply).unwrap();
        assert_eq!(
            nv.history.get_validity(&old_id).unwrap(),
            Some(ModifierValidity::Valid)
        );
        let state_root_after_old = nv.state_root().to_vec();
        assert_eq!(state_root_after_old, old_header.state_root.0.as_slice());

        // Store new chain block.
        let new_id = make_id(0xC1);
        let new_header = make_header(100, 0xC1);
        nv.history.store_header(&new_id, &new_header).unwrap();
        nv.history
            .store_block_transactions(&new_id, &sample_block_transactions(&new_id))
            .unwrap();
        nv.history
            .store_extension(&new_id, &sample_extension(&new_id))
            .unwrap();

        // Build chain switch.
        let branch_point = make_id(0x00);
        let info_switch = ProgressInfo::chain_switch(branch_point, vec![old_id], vec![new_id]);
        nv.apply_progress(&info_switch).unwrap();

        // Old block marked Invalid.
        assert_eq!(
            nv.history.get_validity(&old_id).unwrap(),
            Some(ModifierValidity::Invalid)
        );

        // New block marked Valid.
        assert_eq!(
            nv.history.get_validity(&new_id).unwrap(),
            Some(ModifierValidity::Valid)
        );

        // Best full block updated to new chain tip.
        assert_eq!(nv.best_full_block_id().unwrap(), Some(new_id));

        // State root updated from new header.
        assert_eq!(nv.state_root(), new_header.state_root.0.as_slice());
    }

    // 13. Chain reorg with an invalid new block stops early and marks it
    //     Invalid, but still correctly handles the rollback + old chain
    //     invalidation.
    #[test]
    fn chain_reorg_with_invalid_new_block_stops_early() {
        let (db, _dir) = open_test_db();
        let mut nv = make_node_view_skip_difficulty(db);

        // Store and apply old chain block.
        let old_id = make_id(0xE0);
        let old_header = make_header(100, 0xE0);
        nv.history.store_header(&old_id, &old_header).unwrap();
        nv.history
            .store_block_transactions(&old_id, &sample_block_transactions(&old_id))
            .unwrap();
        nv.history
            .store_extension(&old_id, &sample_extension(&old_id))
            .unwrap();

        let info_apply = ProgressInfo::apply(vec![old_id]);
        nv.apply_progress(&info_apply).unwrap();

        // New chain: first block is valid, second block is missing sections
        // (cannot be assembled).
        let new_id_ok = make_id(0xE1);
        let new_header_ok = make_header(100, 0xE1);
        nv.history.store_header(&new_id_ok, &new_header_ok).unwrap();
        nv.history
            .store_block_transactions(&new_id_ok, &sample_block_transactions(&new_id_ok))
            .unwrap();
        nv.history
            .store_extension(&new_id_ok, &sample_extension(&new_id_ok))
            .unwrap();

        let new_id_bad = make_id(0xE2);
        // Intentionally do NOT store any sections for new_id_bad.

        // Chain switch: remove old, apply [ok, bad].
        let branch_point = make_id(0x00);
        let info_switch =
            ProgressInfo::chain_switch(branch_point, vec![old_id], vec![new_id_ok, new_id_bad]);
        let result = nv.apply_progress(&info_switch);

        // Should succeed — incomplete blocks are skipped during apply so
        // they can be retried when their sections arrive.
        assert!(result.is_ok());

        // Old chain block should still be marked Invalid (rollback happened).
        assert_eq!(
            nv.history.get_validity(&old_id).unwrap(),
            Some(ModifierValidity::Invalid)
        );

        // First new block should be marked Valid (it succeeded).
        assert_eq!(
            nv.history.get_validity(&new_id_ok).unwrap(),
            Some(ModifierValidity::Valid)
        );

        // Second new block should have no validity (skipped, not Invalid).
        assert_eq!(nv.history.get_validity(&new_id_bad).unwrap(), None);
    }

    // 14. validate_and_apply_block rejects a block with a tampered transactions root.
    #[test]
    fn validate_and_apply_block_rejects_bad_merkle_root() {
        let (db, _dir) = open_test_db();
        let mut nv = make_node_view(db);

        let id = make_id(0xF2);
        // Build a header with a bad transactions_root: non-zero root but
        // empty tx_bytes (whose Merkle root is all-zeros).
        let mut header = make_header(100, 0xF2);
        header.transactions_root = ergo_types::modifier_id::Digest32([0xFF; 32]);

        nv.history.store_header(&id, &header).unwrap();
        nv.history
            .store_block_transactions(&id, &sample_block_transactions(&id))
            .unwrap();
        nv.history
            .store_extension(&id, &sample_extension(&id))
            .unwrap();

        let result = nv.validate_and_apply_block(&id);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, NodeViewError::BlockValidation(_)),
            "expected BlockValidation error, got: {err}"
        );
    }

    // 15. validate_and_apply_block rejects a block containing a tx with duplicate inputs.
    #[test]
    fn validate_and_apply_block_rejects_invalid_tx() {
        use ergo_consensus::merkle::merkle_root;
        use ergo_types::transaction::{BoxId, ErgoBoxCandidate, ErgoTransaction, Input, TxId};
        use ergo_wire::transaction_ser::serialize_transaction;

        let (db, _dir) = open_test_db();
        let mut nv = make_node_view_skip_difficulty(db);

        // Build a P2PK ErgoTree with size bit set (valid for sigma-rust).
        let ergo_tree_bytes = {
            use ergo_wire::vlq::put_uint;
            let mut body = vec![0x08, 0xCD];
            body.extend_from_slice(&[0x02; 33]); // dummy compressed point
            let mut tree = Vec::new();
            tree.push(0x08); // header: v0 + size bit
            put_uint(&mut tree, body.len() as u32);
            tree.extend_from_slice(&body);
            tree
        };

        // Build a transaction with duplicate inputs (invalid per stateless validation).
        let dup_box_id = BoxId([0x11; 32]);
        let mut bad_tx = ErgoTransaction {
            inputs: vec![
                Input {
                    box_id: dup_box_id,
                    proof_bytes: Vec::new(),
                    extension_bytes: vec![0x00],
                },
                Input {
                    box_id: dup_box_id, // duplicate!
                    proof_bytes: Vec::new(),
                    extension_bytes: vec![0x00],
                },
            ],
            data_inputs: Vec::new(),
            output_candidates: vec![ErgoBoxCandidate {
                value: 1_000_000_000,
                ergo_tree_bytes,
                creation_height: 100_000,
                tokens: Vec::new(),
                additional_registers: Vec::new(),
            }],
            tx_id: TxId([0; 32]),
        };
        bad_tx.tx_id = ergo_wire::transaction_ser::compute_tx_id(&bad_tx);

        let tx_bytes = serialize_transaction(&bad_tx);

        // Compute the correct transactions_root using tx_id (not raw bytes).
        // For v2 blocks: leaves = [tx_id] ++ [witness_id]
        let mut concat_proofs = Vec::new();
        for input in &bad_tx.inputs {
            concat_proofs.extend_from_slice(&input.proof_bytes);
        }
        let witness_hash = test_blake2b256(&concat_proofs);
        let witness_id = &witness_hash[1..]; // 31 bytes
        let tx_root = merkle_root(&[bad_tx.tx_id.0.as_slice(), witness_id]).unwrap();

        let id = make_id(0xF3);
        let mut header = make_header(100, 0xF3);
        header.transactions_root = ergo_types::modifier_id::Digest32(tx_root);

        let block_transactions = BlockTransactions {
            header_id: id,
            block_version: 2,
            tx_bytes: vec![tx_bytes],
        };

        nv.history.store_header(&id, &header).unwrap();
        nv.history
            .store_block_transactions(&id, &block_transactions)
            .unwrap();
        nv.history
            .store_extension(&id, &sample_extension(&id))
            .unwrap();

        let result = nv.validate_and_apply_block(&id);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, NodeViewError::TxValidation(ref msg) if msg.contains("stateless")),
            "expected TxValidation error about stateless validation, got: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // Difficulty verification tests
    // -----------------------------------------------------------------------

    /// Helper: build a full block (with header, block_transactions, extension)
    /// suitable for calling `verify_difficulty` directly.
    fn make_full_block_for_difficulty(
        height: u32,
        parent_id: ModifierId,
        n_bits: u64,
    ) -> ergo_types::transaction::ErgoFullBlock {
        let mut header = Header::default_for_test();
        header.version = 2;
        header.height = height;
        header.parent_id = parent_id;
        header.n_bits = n_bits;
        let header_id = make_id(0xFF);
        ergo_types::transaction::ErgoFullBlock {
            header,
            block_transactions: sample_block_transactions(&header_id),
            extension: sample_extension(&header_id),
            ad_proofs: None,
        }
    }

    // 14. verify_difficulty skips genesis (height 1) with Ok.
    #[test]
    fn difficulty_check_skips_genesis() {
        let (db, _dir) = open_test_db();
        let nv = make_node_view(db);

        let block = make_full_block_for_difficulty(1, ModifierId::GENESIS_PARENT, 12345);
        // Should return Ok regardless of nBits value.
        nv.verify_difficulty(&block).unwrap();
    }

    // 15. verify_difficulty accepts matching nBits mid-epoch.
    #[test]
    fn difficulty_check_mid_epoch_accepts_matching_nbits() {
        let (db, _dir) = open_test_db();
        let nv = make_node_view(db);

        // Store parent at height 500 (mid-epoch: 500 % 1024 != 0) with
        // n_bits = 100663296.
        let parent_id = make_id(0x50);
        let mut parent_header = Header::default_for_test();
        parent_header.version = 2;
        parent_header.height = 500;
        parent_header.n_bits = 100_663_296;
        nv.history.store_header(&parent_id, &parent_header).unwrap();

        // Block at height 501 with same nBits.
        let block = make_full_block_for_difficulty(501, parent_id, 100_663_296);
        nv.verify_difficulty(&block).unwrap();
    }

    // 16. verify_difficulty rejects mismatched nBits mid-epoch.
    #[test]
    fn difficulty_check_mid_epoch_rejects_mismatched_nbits() {
        let (db, _dir) = open_test_db();
        let nv = make_node_view(db);

        // Store parent at height 500 with n_bits = 100663296.
        let parent_id = make_id(0x60);
        let mut parent_header = Header::default_for_test();
        parent_header.version = 2;
        parent_header.height = 500;
        parent_header.n_bits = 100_663_296;
        nv.history.store_header(&parent_id, &parent_header).unwrap();

        // Block at height 501 with DIFFERENT nBits.
        let block = make_full_block_for_difficulty(501, parent_id, 999_999);
        let result = nv.verify_difficulty(&block);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, NodeViewError::Validation(ref msg) if msg.contains("nBits mismatch")),
            "expected Validation error about nBits mismatch, got: {err}"
        );
    }

    // 17. verify_difficulty rejects epoch boundary blocks when required
    //     historical headers are not available (above checkpoint).
    #[test]
    fn difficulty_check_epoch_boundary_rejects_missing_history() {
        let (db, _dir) = open_test_db();
        let nv = make_node_view(db);

        // Store parent at height 1024 (epoch boundary: 1024 % 1024 == 0).
        let parent_id = make_id(0x70);
        let mut parent_header = Header::default_for_test();
        parent_header.version = 2;
        parent_header.height = 1024;
        parent_header.n_bits = 100_663_296;
        nv.history.store_header(&parent_id, &parent_header).unwrap();

        // Block at height 1025 with a DIFFERENT nBits -- this should be
        // rejected because required historical headers for recalculation
        // are not in the height index and we are above checkpoint_height.
        let block = make_full_block_for_difficulty(1025, parent_id, 200_000_000);
        let result = nv.verify_difficulty(&block);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, NodeViewError::Validation(ref msg) if msg.contains("no header found at required height")),
            "expected Validation error about missing header at required height, got: {err}"
        );
    }

    // 18. verify_difficulty rejects when parent header is not found (above checkpoint).
    #[test]
    fn difficulty_check_missing_parent_rejects_above_checkpoint() {
        let (db, _dir) = open_test_db();
        let nv = make_node_view(db);

        // Block at height 100 referencing a parent that doesn't exist.
        let missing_parent_id = make_id(0x80);
        let block = make_full_block_for_difficulty(100, missing_parent_id, 12345);
        // Should return Err because parent not found and height > checkpoint_height (0).
        let result = nv.verify_difficulty(&block);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, NodeViewError::Validation(ref msg) if msg.contains("parent header not found")),
            "expected Validation error about missing parent, got: {err}"
        );
    }

    // 18b. verify_difficulty skips when parent header is not found but below checkpoint.
    #[test]
    fn difficulty_check_missing_parent_skips_below_checkpoint() {
        let (db, _dir) = open_test_db();
        let mut nv = make_node_view(db);
        nv.set_checkpoint_height(500);

        // Block at height 100 (below checkpoint 500) referencing a parent that doesn't exist.
        let missing_parent_id = make_id(0x80);
        let block = make_full_block_for_difficulty(100, missing_parent_id, 12345);
        // Should return Ok because height <= checkpoint_height.
        nv.verify_difficulty(&block).unwrap();
    }

    // 18c. verify_difficulty rejects missing parent at height exactly above checkpoint.
    #[test]
    fn difficulty_check_missing_parent_rejects_at_checkpoint_boundary() {
        let (db, _dir) = open_test_db();
        let mut nv = make_node_view(db);
        nv.set_checkpoint_height(99);

        // Block at height 100 (above checkpoint 99) with missing parent.
        let missing_parent_id = make_id(0x80);
        let block = make_full_block_for_difficulty(100, missing_parent_id, 12345);
        let result = nv.verify_difficulty(&block);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, NodeViewError::Validation(ref msg) if msg.contains("parent header not found")),
            "expected Validation error about missing parent, got: {err}"
        );
    }

    // 18d. verify_difficulty skips at exact checkpoint height.
    #[test]
    fn difficulty_check_skips_at_exact_checkpoint() {
        let (db, _dir) = open_test_db();
        let mut nv = make_node_view(db);
        nv.set_checkpoint_height(100);

        // Block at height 100 (== checkpoint) with missing parent.
        let missing_parent_id = make_id(0x80);
        let block = make_full_block_for_difficulty(100, missing_parent_id, 12345);
        // Should return Ok because height <= checkpoint_height.
        nv.verify_difficulty(&block).unwrap();
    }

    // -----------------------------------------------------------------------
    // Header validation during sync tests
    // -----------------------------------------------------------------------

    /// Compute blake2b256 of serialized header bytes to get the header ID.
    fn compute_header_id(bytes: &[u8]) -> ModifierId {
        use blake2::digest::{Update, VariableOutput};
        let mut hasher = blake2::Blake2bVar::new(32).unwrap();
        hasher.update(bytes);
        let mut hash = [0u8; 32];
        hasher.finalize_variable(&mut hash).unwrap();
        ModifierId(hash)
    }

    // 19. process_modifier rejects a header with wrong height relative to parent.
    #[test]
    fn process_modifier_rejects_bad_height_header() {
        let (db, _dir) = open_test_db();
        let mut nv = make_node_view(db);

        // Store parent at height 100 directly (bypassing process_modifier
        // which would reject it as an orphan).
        let parent = make_header(100, 0x01);
        let parent_bytes = ergo_wire::header_ser::serialize_header(&parent);
        let parent_id = compute_header_id(&parent_bytes);
        nv.history
            .store_header_with_score(&parent_id, &parent)
            .unwrap();

        // Build child with WRONG height (200 instead of 101).
        let mut bad_child = make_header(200, 0x02);
        bad_child.parent_id = parent_id;
        bad_child.timestamp = parent.timestamp + 1000;
        let bad_child_bytes = ergo_wire::header_ser::serialize_header(&bad_child);
        let bad_child_id = compute_header_id(&bad_child_bytes);

        let result = nv.process_modifier(101, &bad_child_id, &bad_child_bytes);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, NodeViewError::Validation(ref msg) if msg.contains("validation failed")),
            "expected Validation error about header validation, got: {err}"
        );
    }

    // 20. process_modifier rejects orphan header (unknown parent).
    #[test]
    fn process_modifier_rejects_orphan_header() {
        let (db, _dir) = open_test_db();
        let mut nv = make_node_view(db);

        // Store a header with an unknown parent — should fail because
        // orphan headers (missing parent) must not be stored.
        let orphan = make_header(500, 0xFF);
        let orphan_bytes = ergo_wire::header_ser::serialize_header(&orphan);
        let orphan_id = compute_header_id(&orphan_bytes);

        let result = nv.process_modifier(101, &orphan_id, &orphan_bytes);
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), NodeViewError::Validation(ref msg) if msg.contains("parent header not found")),
        );
        assert!(!nv.history.contains_modifier(101, &orphan_id).unwrap());
    }

    // -----------------------------------------------------------------------
    // Applied blocks tracking tests
    // -----------------------------------------------------------------------

    // 21. take_applied_blocks is initially empty.
    #[test]
    fn take_applied_blocks_initially_empty() {
        let (db, _dir) = open_test_db();
        let mut nv = make_node_view(db);
        assert!(nv.take_applied_blocks().is_empty());
    }

    // 22. take_applied_blocks drains the buffer.
    #[test]
    fn take_applied_blocks_drains_buffer() {
        let (db, _dir) = open_test_db();
        let mut nv = make_node_view(db);
        // First call returns empty.
        let first = nv.take_applied_blocks();
        assert!(first.is_empty());
        // Second call also returns empty (no double-drain issue).
        let second = nv.take_applied_blocks();
        assert!(second.is_empty());
    }

    // 23. validate_and_apply_block pushes block ID to applied_blocks.
    #[test]
    fn validate_and_apply_block_tracks_applied() {
        let (db, _dir) = open_test_db();
        let mut nv = make_node_view_skip_difficulty(db);

        let id = make_id(0xAB);
        let header = make_header(100, 0xAB);

        nv.history.store_header(&id, &header).unwrap();
        nv.history
            .store_block_transactions(&id, &sample_block_transactions(&id))
            .unwrap();
        nv.history
            .store_extension(&id, &sample_extension(&id))
            .unwrap();

        nv.validate_and_apply_block(&id).unwrap();

        let applied = nv.take_applied_blocks();
        assert_eq!(applied.len(), 1);
        assert_eq!(applied[0], id);

        // Buffer is drained; second call returns empty.
        assert!(nv.take_applied_blocks().is_empty());
    }

    // 24. Mempool is Arc-shared between external reference and NodeViewHolder.
    #[test]
    fn mempool_is_arc_shared() {
        let (db, _dir) = open_test_db();
        let mempool = Arc::new(RwLock::new(ErgoMemPool::with_min_fee(100, 0)));
        let node_view = NodeViewHolder::new(db, mempool.clone(), true, vec![0u8; 33]);

        // Write from external ref.
        {
            let mut mp = mempool.write().unwrap();
            let tx = ergo_types::transaction::ErgoTransaction {
                inputs: vec![ergo_types::transaction::Input {
                    box_id: ergo_types::transaction::BoxId([0xAA; 32]),
                    proof_bytes: vec![],
                    extension_bytes: vec![],
                }],
                data_inputs: vec![],
                output_candidates: vec![ergo_types::transaction::ErgoBoxCandidate {
                    value: 1_000_000,
                    ergo_tree_bytes: vec![0x00],
                    creation_height: 1,
                    tokens: vec![],
                    additional_registers: vec![],
                }],
                tx_id: ergo_types::transaction::TxId([0x01; 32]),
            };
            mp.put(tx).unwrap();
        }

        // Read from NodeViewHolder.
        let mp = node_view.mempool.read().unwrap();
        assert!(mp.contains(&ergo_types::transaction::TxId([0x01; 32])));
    }

    // -----------------------------------------------------------------------
    // Block pruning tests
    // -----------------------------------------------------------------------

    // 25. blocks_to_keep = -1 (default) does not prune anything.
    #[test]
    fn default_blocks_to_keep_no_pruning() {
        let (db, _dir) = open_test_db();
        let mut nv = make_node_view_skip_difficulty(db);

        let id = make_id(0xDA);
        let mut header = make_header(100, 0xDA);
        let ad_proofs = sample_ad_proofs(&id);
        header.ad_proofs_root =
            ergo_types::modifier_id::Digest32(test_blake2b256(&ad_proofs.proof_bytes));
        nv.history.store_header(&id, &header).unwrap();
        nv.history
            .store_block_transactions(&id, &sample_block_transactions(&id))
            .unwrap();
        nv.history
            .store_extension(&id, &sample_extension(&id))
            .unwrap();
        nv.history.store_ad_proofs(&id, &ad_proofs).unwrap();

        let info = ProgressInfo::apply(vec![id]);
        nv.apply_progress(&info).unwrap();

        // All body sections should still be present with default blocks_to_keep = -1.
        assert!(nv.history.contains_modifier(102, &id).unwrap());
        assert!(nv.history.contains_modifier(108, &id).unwrap());
        assert!(nv.history.contains_modifier(104, &id).unwrap());
        assert_eq!(nv.history.minimal_full_block_height().unwrap(), 0);
    }

    // 26. blocks_to_keep = 1 prunes body sections outside the window.
    #[test]
    fn pruning_removes_old_body_sections() {
        let (db, _dir) = open_test_db();
        let mut nv = make_node_view_skip_difficulty(db);
        nv.set_blocks_to_keep(1);

        // Apply block at height 100.
        let id1 = make_id(0xDB);
        let mut header1 = make_header(100, 0xDB);
        let ad_proofs1 = sample_ad_proofs(&id1);
        header1.ad_proofs_root =
            ergo_types::modifier_id::Digest32(test_blake2b256(&ad_proofs1.proof_bytes));
        nv.history.store_header(&id1, &header1).unwrap();
        nv.history
            .store_block_transactions(&id1, &sample_block_transactions(&id1))
            .unwrap();
        nv.history
            .store_extension(&id1, &sample_extension(&id1))
            .unwrap();
        nv.history.store_ad_proofs(&id1, &ad_proofs1).unwrap();

        let info1 = ProgressInfo::apply(vec![id1]);
        nv.apply_progress(&info1).unwrap();

        // All body sections present after first block.
        assert!(nv.history.contains_modifier(102, &id1).unwrap());
        assert!(nv.history.contains_modifier(108, &id1).unwrap());

        // Apply block at height 101.
        let id2 = make_id(0xDC);
        let header2 = make_header(101, 0xDC);
        nv.history.store_header(&id2, &header2).unwrap();
        nv.history
            .store_block_transactions(&id2, &sample_block_transactions(&id2))
            .unwrap();
        nv.history
            .store_extension(&id2, &sample_extension(&id2))
            .unwrap();

        let info2 = ProgressInfo::apply(vec![id2]);
        nv.apply_progress(&info2).unwrap();

        // Height 100 body sections should be pruned.
        assert!(!nv.history.contains_modifier(102, &id1).unwrap());
        assert!(!nv.history.contains_modifier(104, &id1).unwrap());
        assert!(!nv.history.contains_modifier(108, &id1).unwrap());
        // Header should still be present.
        assert!(nv.history.load_header(&id1).unwrap().is_some());
        // Height 101 body sections should still be present.
        assert!(nv.history.contains_modifier(102, &id2).unwrap());
        // minimal_full_block_height should be updated.
        assert!(nv.history.minimal_full_block_height().unwrap() > 0);
    }

    // 27. Extension at epoch start (height % 1024 == 0) is NOT pruned.
    #[test]
    fn pruning_preserves_extension_at_epoch_boundary() {
        let (db, _dir) = open_test_db();
        let mut nv = make_node_view_skip_difficulty(db);
        nv.set_blocks_to_keep(1);

        // Apply block at epoch boundary height 1024.
        // Extension at epoch boundary must include block version so that
        // parameters parsed from it keep block_version = 2.
        let id1 = make_id(0xDD);
        let epoch_ext = Extension {
            header_id: id1,
            fields: vec![(
                [0x00, ergo_consensus::parameters::BLOCK_VERSION_ID],
                2_i32.to_be_bytes().to_vec(),
            )],
        };
        // Compute the correct extension_root for this Extension.
        // Scala kvToLeaf format: [key_length_byte] ++ key ++ value
        let ext_leaves: Vec<Vec<u8>> = epoch_ext
            .fields
            .iter()
            .map(|(key, value)| {
                let mut leaf = Vec::with_capacity(1 + key.len() + value.len());
                leaf.push(key.len() as u8);
                leaf.extend_from_slice(key);
                leaf.extend_from_slice(value);
                leaf
            })
            .collect();
        let ext_slices: Vec<&[u8]> = ext_leaves.iter().map(|v| v.as_slice()).collect();
        let ext_root = ergo_consensus::merkle::merkle_root(&ext_slices).unwrap_or([0u8; 32]);

        let mut header1 = make_header(1024, 0xDD);
        header1.extension_root = ergo_types::modifier_id::Digest32(ext_root);
        nv.history.store_header(&id1, &header1).unwrap();
        nv.history
            .store_block_transactions(&id1, &sample_block_transactions(&id1))
            .unwrap();
        nv.history.store_extension(&id1, &epoch_ext).unwrap();

        let info1 = ProgressInfo::apply(vec![id1]);
        nv.apply_progress(&info1).unwrap();

        // Apply block at height 1025.
        let id2 = make_id(0xDE);
        let header2 = make_header(1025, 0xDE);
        nv.history.store_header(&id2, &header2).unwrap();
        nv.history
            .store_block_transactions(&id2, &sample_block_transactions(&id2))
            .unwrap();
        nv.history
            .store_extension(&id2, &sample_extension(&id2))
            .unwrap();

        let info2 = ProgressInfo::apply(vec![id2]);
        nv.apply_progress(&info2).unwrap();

        // BlockTransactions and ADProofs at height 1024 should be pruned.
        assert!(!nv.history.contains_modifier(102, &id1).unwrap());
        // But Extension at epoch boundary should be PRESERVED.
        assert!(nv.history.contains_modifier(108, &id1).unwrap());
    }

    // 28. blocks_to_keep = 0 prunes immediately (current block only kept).
    #[test]
    fn pruning_with_zero_keep_prunes_all_old() {
        let (db, _dir) = open_test_db();
        let mut nv = make_node_view_skip_difficulty(db);
        nv.set_blocks_to_keep(0);

        // Apply block at height 50.
        let id1 = make_id(0xDF);
        let header1 = make_header(50, 0xDF);
        nv.history.store_header(&id1, &header1).unwrap();
        nv.history
            .store_block_transactions(&id1, &sample_block_transactions(&id1))
            .unwrap();
        nv.history
            .store_extension(&id1, &sample_extension(&id1))
            .unwrap();

        let info1 = ProgressInfo::apply(vec![id1]);
        nv.apply_progress(&info1).unwrap();

        // With blocks_to_keep=0, new_minimal = 50 - 0 + 1 = 51, old_minimal = 0.
        // Heights 0..51 are pruned. Height 50 body sections should be pruned.
        assert!(!nv.history.contains_modifier(102, &id1).unwrap());
        assert!(!nv.history.contains_modifier(108, &id1).unwrap());
        // Header should still be present.
        assert!(nv.history.load_header(&id1).unwrap().is_some());
        assert_eq!(nv.history.minimal_full_block_height().unwrap(), 51);
    }

    // -----------------------------------------------------------------------
    // Voting integration tests
    // -----------------------------------------------------------------------

    // 29. VotingEpochInfo is accessible and properly initialized.
    #[test]
    fn voting_epoch_info_is_accessible() {
        use ergo_consensus::parameters::Parameters;
        use ergo_consensus::voting::VotingEpochInfo;
        let info = VotingEpochInfo::new(Parameters::genesis(), 0);
        assert!(info.voting_data.epoch_votes.is_empty());
    }

    // 30. current_parameters returns genesis parameters for a fresh NodeViewHolder.
    #[test]
    fn current_parameters_returns_genesis() {
        let (db, _dir) = open_test_db();
        let nv = make_node_view(db);
        let params = nv.current_parameters();
        assert_eq!(params.max_block_size(), 524_288);
        assert_eq!(params.storage_fee_factor(), 1_250_000);
    }

    // 31. is_rule_active delegates to validation_settings.
    #[test]
    fn is_rule_active_delegates_to_validation_settings() {
        use ergo_consensus::validation_rules::{HDR_POW, TX_DUST, TX_NO_INPUTS};
        let (db, _dir) = open_test_db();
        let nv = make_node_view(db);
        // All initial rules should be active.
        assert!(nv.is_rule_active(TX_DUST));
        assert!(nv.is_rule_active(TX_NO_INPUTS));
        assert!(nv.is_rule_active(HDR_POW));
        // Unknown rules are treated as active.
        assert!(nv.is_rule_active(9999));
    }

    // 32. validation_settings() returns a reference to the current settings.
    #[test]
    fn validation_settings_returns_ref() {
        use ergo_consensus::validation_rules::TX_DUST;
        let (db, _dir) = open_test_db();
        let nv = make_node_view(db);
        let settings = nv.validation_settings();
        assert!(settings.is_active(TX_DUST));
    }

    // 33. Voting epoch info accumulates votes from applied blocks.
    #[test]
    fn voting_accumulates_from_applied_blocks() {
        let (db, _dir) = open_test_db();
        let mut nv = make_node_view_skip_difficulty(db);

        let id = make_id(0xAC);
        let mut header = make_header(100, 0xAC);
        // Cast a vote for MAX_BLOCK_SIZE (param ID 3).
        header.votes = [3, 0, 0];

        nv.history.store_header(&id, &header).unwrap();
        nv.history
            .store_block_transactions(&id, &sample_block_transactions(&id))
            .unwrap();
        nv.history
            .store_extension(&id, &sample_extension(&id))
            .unwrap();

        nv.validate_and_apply_block(&id).unwrap();

        // The vote for param ID 3 should have been accumulated.
        assert_eq!(
            nv.voting_epoch_info.voting_data.epoch_votes.get(&3),
            Some(&1)
        );
    }

    // -----------------------------------------------------------------------
    // Block section validation tests (rules 300, 303, 305, 306, 210)
    // -----------------------------------------------------------------------

    // Rule 300: Already-applied block (Valid) should be silently skipped.
    #[test]
    fn already_applied_valid_block_is_skipped() {
        let (db, _dir) = open_test_db();
        let mut nv = make_node_view_skip_difficulty(db);

        let id = make_id(0x50);
        let header = make_header(100, 0x50);

        // Store and apply the block.
        nv.history.store_header(&id, &header).unwrap();
        nv.history
            .store_block_transactions(&id, &sample_block_transactions(&id))
            .unwrap();
        nv.history
            .store_extension(&id, &sample_extension(&id))
            .unwrap();
        nv.validate_and_apply_block(&id).unwrap();

        // Applying again should succeed silently (skipped).
        assert!(nv.validate_and_apply_block(&id).is_ok());
    }

    // Rule 300: Already-applied block (Invalid) should return error.
    #[test]
    fn already_applied_invalid_block_is_rejected() {
        let (db, _dir) = open_test_db();
        let mut nv = make_node_view_skip_difficulty(db);
        // Set checkpoint to 0 so the block is "above checkpoint" and the
        // Invalid rejection fires (below checkpoint, stale markers are cleared).
        nv.set_checkpoint_height(0);

        let id = make_id(0x51);
        let header = make_header(100, 0x51);

        // Store block sections so assembly succeeds (Stage 0b runs after
        // assembly since the restructure).
        nv.history.store_header(&id, &header).unwrap();
        nv.history
            .store_block_transactions(&id, &sample_block_transactions(&id))
            .unwrap();
        nv.history
            .store_extension(&id, &sample_extension(&id))
            .unwrap();

        // Manually mark as invalid.
        nv.history
            .set_validity(&id, ModifierValidity::Invalid)
            .unwrap();

        let result = nv.validate_and_apply_block(&id);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(&err, NodeViewError::Validation(msg) if msg.contains("previously marked invalid")),
            "expected validation error about previously invalid, got: {err}"
        );
    }

    // Rule 303: Block with header marked invalid should be rejected.
    // (Stage 0b catches this after assembly.)
    #[test]
    fn block_with_invalid_header_is_rejected() {
        let (db, _dir) = open_test_db();
        let mut nv = make_node_view_skip_difficulty(db);
        // Above checkpoint so the Invalid marker is not cleared.
        nv.set_checkpoint_height(0);

        let id = make_id(0x52);
        let header = make_header(100, 0x52);

        // Store block sections so assembly succeeds.
        nv.history.store_header(&id, &header).unwrap();
        nv.history
            .store_block_transactions(&id, &sample_block_transactions(&id))
            .unwrap();
        nv.history
            .store_extension(&id, &sample_extension(&id))
            .unwrap();

        // Mark the block as invalid.
        nv.history
            .set_validity(&id, ModifierValidity::Invalid)
            .unwrap();

        let result = nv.validate_and_apply_block(&id);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(&err, NodeViewError::Validation(msg) if msg.contains("previously marked invalid")),
            "expected validation error about invalid, got: {err}"
        );
    }

    // Rule 305: Block at pruned height should be rejected.
    #[test]
    fn block_at_pruned_height_is_rejected() {
        let (db, _dir) = open_test_db();
        let mut nv = make_node_view_skip_difficulty(db);

        // Enable pruning with blocks_to_keep = 100.
        nv.set_blocks_to_keep(100);

        // Set minimal full block height to 500 (simulating prior pruning).
        nv.history.set_minimal_full_block_height(500).unwrap();

        let id = make_id(0x53);
        // Create a header at height 400, which is below the minimum of 500.
        let header = make_header(400, 0x53);

        nv.history.store_header(&id, &header).unwrap();
        nv.history
            .store_block_transactions(&id, &sample_block_transactions(&id))
            .unwrap();
        nv.history
            .store_extension(&id, &sample_extension(&id))
            .unwrap();

        let result = nv.validate_and_apply_block(&id);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(&err, NodeViewError::Validation(msg) if msg.contains("too old")),
            "expected validation error about too old, got: {err}"
        );
    }

    // Rule 305: Block at or above min height should pass.
    #[test]
    fn block_at_valid_height_passes_pruning_check() {
        let (db, _dir) = open_test_db();
        let mut nv = make_node_view_skip_difficulty(db);

        // Enable pruning with blocks_to_keep = 100.
        nv.set_blocks_to_keep(100);

        // Set minimal full block height to 500.
        nv.history.set_minimal_full_block_height(500).unwrap();

        let id = make_id(0x54);
        // Create a header at height 500 (at the boundary — should pass).
        let header = make_header(500, 0x54);

        nv.history.store_header(&id, &header).unwrap();
        nv.history
            .store_block_transactions(&id, &sample_block_transactions(&id))
            .unwrap();
        nv.history
            .store_extension(&id, &sample_extension(&id))
            .unwrap();

        // Should pass the pruning check (height >= min_height).
        assert!(nv.validate_and_apply_block(&id).is_ok());
    }

    // Rule 305: When blocks_to_keep is -1 (keep all), no pruning check.
    #[test]
    fn block_passes_when_keep_all() {
        let (db, _dir) = open_test_db();
        let mut nv = make_node_view_skip_difficulty(db);

        // blocks_to_keep = -1 (keep all, the default).
        assert_eq!(nv.blocks_to_keep, -1);

        let id = make_id(0x55);
        let header = make_header(1, 0x55);

        nv.history.store_header(&id, &header).unwrap();
        nv.history
            .store_block_transactions(&id, &sample_block_transactions(&id))
            .unwrap();
        nv.history
            .store_extension(&id, &sample_extension(&id))
            .unwrap();

        // Even with a very low height, should pass when keep_all.
        assert!(nv.validate_and_apply_block(&id).is_ok());
    }

    // Rule 210: Block whose parent is marked invalid should be rejected.
    #[test]
    fn block_with_invalid_parent_is_rejected() {
        let (db, _dir) = open_test_db();
        let mut nv = make_node_view_skip_difficulty(db);
        // Above checkpoint so Stage 1d parent-semantics check is active.
        nv.set_checkpoint_height(0);

        let parent_id = make_id(0x60);
        let id = make_id(0x61);
        let mut header = make_header(100, 0x61);
        header.parent_id = parent_id;

        // Mark parent as invalid.
        nv.history
            .set_validity(&parent_id, ModifierValidity::Invalid)
            .unwrap();

        nv.history.store_header(&id, &header).unwrap();
        nv.history
            .store_block_transactions(&id, &sample_block_transactions(&id))
            .unwrap();
        nv.history
            .store_extension(&id, &sample_extension(&id))
            .unwrap();

        let result = nv.validate_and_apply_block(&id);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(&err, NodeViewError::Validation(msg) if msg.contains("parent") && msg.contains("semantically invalid")),
            "expected parent semantics error, got: {err}"
        );
    }

    // Rule 306: Block transactions exceeding max block size should be rejected.
    #[test]
    fn oversized_block_transactions_rejected() {
        let (db, _dir) = open_test_db();
        let mut nv = make_node_view_skip_difficulty(db);

        // Set max_block_size to a very small value (100 bytes).
        nv.voting_epoch_info
            .parameters
            .table
            .insert(ergo_consensus::parameters::MAX_BLOCK_SIZE_ID, 100);

        let id = make_id(0x70);
        let header = make_header(100, 0x70);

        // Create block transactions with a large payload.
        // Use valid serialized transactions so parse succeeds.
        use ergo_wire::transaction_ser::serialize_transaction;
        let make_tx = |fill: u8| {
            let valid_tree = {
                let mut t = vec![0x08];
                ergo_wire::vlq::put_uint(&mut t, 35);
                t.push(0x08);
                t.push(0xCD);
                t.extend_from_slice(&[0x02; 33]);
                t
            };
            serialize_transaction(&ergo_types::transaction::ErgoTransaction {
                inputs: vec![ergo_types::transaction::Input {
                    box_id: ergo_types::transaction::BoxId([fill; 32]),
                    proof_bytes: Vec::new(),
                    extension_bytes: vec![0x00],
                }],
                data_inputs: Vec::new(),
                output_candidates: vec![ergo_types::transaction::ErgoBoxCandidate {
                    value: 1_000_000_000,
                    ergo_tree_bytes: valid_tree,
                    creation_height: 100_000,
                    tokens: Vec::new(),
                    additional_registers: Vec::new(),
                }],
                tx_id: ergo_types::transaction::TxId([0; 32]),
            })
        };
        // 3 transactions × ~45 bytes each ≈ 135 bytes, exceeds max of 100
        let bt = BlockTransactions {
            header_id: id,
            block_version: 2,
            tx_bytes: vec![make_tx(0x01), make_tx(0x02), make_tx(0x03)],
        };

        nv.history.store_header(&id, &header).unwrap();
        nv.history.store_block_transactions(&id, &bt).unwrap();
        nv.history
            .store_extension(&id, &sample_extension(&id))
            .unwrap();

        let result = nv.validate_and_apply_block(&id);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(&err, NodeViewError::Validation(msg) if msg.contains("exceeds max")),
            "expected block size error, got: {err}"
        );
    }

    // Rule 306: Block transactions within max size should pass.
    #[test]
    fn block_transactions_within_size_limit_passes() {
        let (db, _dir) = open_test_db();
        let mut nv = make_node_view_skip_difficulty(db);

        // Default max_block_size is 524288 bytes — empty tx_bytes is 0, well under limit.
        let id = make_id(0x71);
        let header = make_header(100, 0x71);

        nv.history.store_header(&id, &header).unwrap();
        nv.history
            .store_block_transactions(&id, &sample_block_transactions(&id))
            .unwrap();
        nv.history
            .store_extension(&id, &sample_extension(&id))
            .unwrap();

        assert!(nv.validate_and_apply_block(&id).is_ok());
    }

    // -----------------------------------------------------------------------
    // V2 activation difficulty enforcement tests
    // -----------------------------------------------------------------------

    #[test]
    fn v2_activation_difficulty_enforced() {
        let (db, _dir) = open_test_db();
        let mut nv = make_node_view(db);

        // Configure v2 activation at height 100 with a known difficulty.
        let v2_height: u32 = 100;
        let v2_diff_hex = "6f98d5000000".to_string();
        nv.set_v2_activation_config(v2_height, v2_diff_hex.clone());

        // Compute the expected nBits from the v2 difficulty hex.
        let v2_diff_bytes = hex::decode(&v2_diff_hex).unwrap();
        let v2_diff = num_bigint::BigUint::from_bytes_be(&v2_diff_bytes);
        let expected_nbits = ergo_consensus::difficulty::encode_compact_bits(&v2_diff) as u32;

        // --- Block at height v2_height (parent_height = v2_height - 1) ---
        // parent_height + 1 == v2_height, so v2 difficulty applies.
        let parent_id_a = make_id(0xA0);
        let mut parent_a = Header::default_for_test();
        parent_a.version = 2;
        parent_a.height = v2_height - 1;
        parent_a.n_bits = 12345;
        nv.history.store_header(&parent_id_a, &parent_a).unwrap();

        // Correct nBits: should pass.
        let block_ok =
            make_full_block_for_difficulty(v2_height, parent_id_a, expected_nbits as u64);
        assert!(nv.verify_difficulty(&block_ok).is_ok());

        // Wrong nBits: should fail.
        let block_bad = make_full_block_for_difficulty(v2_height, parent_id_a, 99999);
        let err = nv.verify_difficulty(&block_bad).unwrap_err();
        assert!(
            matches!(err, NodeViewError::Validation(ref msg) if msg.contains("v2 activation difficulty mismatch")),
            "expected v2 activation mismatch, got: {err}"
        );

        // --- Block at height v2_height + 1 (parent_height = v2_height) ---
        // parent_height == v2_height, so v2 difficulty applies.
        let parent_id_b = make_id(0xB0);
        let mut parent_b = Header::default_for_test();
        parent_b.version = 2;
        parent_b.height = v2_height;
        parent_b.n_bits = expected_nbits as u64;
        nv.history.store_header(&parent_id_b, &parent_b).unwrap();

        // Correct nBits: should pass.
        let block_ok2 =
            make_full_block_for_difficulty(v2_height + 1, parent_id_b, expected_nbits as u64);
        assert!(nv.verify_difficulty(&block_ok2).is_ok());

        // Wrong nBits: should fail.
        let block_bad2 = make_full_block_for_difficulty(v2_height + 1, parent_id_b, 77777);
        let err2 = nv.verify_difficulty(&block_bad2).unwrap_err();
        assert!(
            matches!(err2, NodeViewError::Validation(ref msg) if msg.contains("v2 activation difficulty mismatch")),
            "expected v2 activation mismatch, got: {err2}"
        );
    }

    #[test]
    fn v2_activation_disabled_when_height_zero() {
        let (db, _dir) = open_test_db();
        let mut nv = make_node_view(db);

        // Setting v2_activation_height to 0 disables the check.
        nv.set_v2_activation_config(0, "6f98d5000000".to_string());

        // Store parent at height 99 (mid-epoch, non-v2-boundary).
        let parent_id = make_id(0xC0);
        let mut parent = Header::default_for_test();
        parent.version = 2;
        parent.height = 99;
        parent.n_bits = 100_663_296;
        nv.history.store_header(&parent_id, &parent).unwrap();

        // Block at height 100 with matching parent nBits should pass normally.
        let block = make_full_block_for_difficulty(100, parent_id, 100_663_296);
        assert!(nv.verify_difficulty(&block).is_ok());
    }

    // -----------------------------------------------------------------------
    // Rolled-back tx re-addition on reorg
    // -----------------------------------------------------------------------

    // 33. put_no_fee_check is used in reorg to re-add rolled-back txs.
    #[test]
    fn put_no_fee_check_adds_to_mempool() {
        let (db, _dir) = open_test_db();
        let mempool = Arc::new(RwLock::new(ErgoMemPool::with_min_fee(100, 1_000_000)));
        let node_view = NodeViewHolder::new(db, mempool.clone(), true, vec![0u8; 33]);

        // This tx has 0 fee (no fee output), but put_no_fee_check should still accept it.
        let tx = ergo_types::transaction::ErgoTransaction {
            inputs: vec![ergo_types::transaction::Input {
                box_id: ergo_types::transaction::BoxId([0xAA; 32]),
                proof_bytes: vec![],
                extension_bytes: vec![],
            }],
            data_inputs: vec![],
            output_candidates: vec![ergo_types::transaction::ErgoBoxCandidate {
                value: 1_000_000,
                ergo_tree_bytes: vec![0x00],
                creation_height: 1,
                tokens: vec![],
                additional_registers: vec![],
            }],
            tx_id: ergo_types::transaction::TxId([0x01; 32]),
        };

        let mut mp = node_view.mempool.write().unwrap();
        // put() would fail due to fee check
        assert!(mp.put(tx.clone()).is_err());
        // put_no_fee_check should succeed
        mp.put_no_fee_check(tx).unwrap();
        assert_eq!(mp.size(), 1);
    }

    // -----------------------------------------------------------------------
    // process_prevalidated_header
    // -----------------------------------------------------------------------

    // 34. process_prevalidated_header stores header and returns download list.
    #[test]
    fn process_prevalidated_header_stores_and_indexes() {
        let (db, _dir) = open_test_db();
        let mut nv = make_node_view_skip_difficulty(db);

        // Store a parent header first so the child can find it.
        let parent_id = make_id(0xF0);
        let parent = make_header(99, 0x00);
        nv.history
            .store_header_with_score(&parent_id, &parent)
            .unwrap();
        nv.history.process_header(&parent_id).unwrap();

        // Build a child header referencing the parent.
        let mut child = make_header(100, 0xF0);
        child.parent_id = parent_id;
        child.timestamp = parent.timestamp + 60_000;
        let child_bytes = ergo_wire::header_ser::serialize_header(&child);
        let child_id = ModifierId(test_blake2b256(&child_bytes));

        let info = nv.process_prevalidated_header(&child_id, &child).unwrap();

        // Should produce download requests for the 3 body sections.
        assert_eq!(info.to_download.len(), 3);
        let type_ids: Vec<u8> = info.to_download.iter().map(|(t, _)| *t).collect();
        assert!(type_ids.contains(&102)); // BlockTransactions
        assert!(type_ids.contains(&104)); // ADProofs
        assert!(type_ids.contains(&108)); // Extension

        // Header should be retrievable from the DB.
        let loaded = nv.history.load_header(&child_id).unwrap();
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().height, 100);
    }

    // 35. process_prevalidated_header rejects header with missing parent.
    #[test]
    fn process_prevalidated_header_rejects_orphan() {
        let (db, _dir) = open_test_db();
        let mut nv = make_node_view_skip_difficulty(db);

        // Build a header whose parent does not exist in the DB.
        let header = make_header(100, 0xBB);
        let header_bytes = ergo_wire::header_ser::serialize_header(&header);
        let header_id = ModifierId(test_blake2b256(&header_bytes));

        let result = nv.process_prevalidated_header(&header_id, &header);
        assert!(result.is_err());

        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("parent header not found"),
            "expected 'parent header not found' in error, got: {err_msg}"
        );
    }

    #[test]
    fn fast_forward_does_not_advance_state_version_in_utxo_mode() {
        use ergo_storage::chain_scoring::ModifierValidity;
        // Use make_node_view_skip_difficulty to avoid difficulty checks.
        let (db, _dir) = open_test_db();

        // We need fast_forward_valid_blocks to be able to load the header at
        // best_full_block_id.  Use id1 as the starting point (height 1) and
        // id2 as the already-Valid block to fast-forward to (height 2).
        let id1 = make_id(1);
        let id2 = make_id(2);

        // h1 is the current best full block (height 1).
        // h2 is already Valid and should be fast-forwarded to (height 2).
        // store_header_with_score also populates the height → IDs index.
        let h1 = {
            let mut h = make_header(1, 1);
            h.parent_id = ModifierId::GENESIS_PARENT;
            h
        };
        let h2 = {
            let mut h = make_header(2, 2);
            h.parent_id = id1;
            h
        };
        db.store_header_with_score(&id1, &h1).unwrap();
        db.store_header_with_score(&id2, &h2).unwrap();

        // Mark h2 as Valid (h1 is the current tip, only h2 needs fast-forward).
        db.set_validity(&id2, ModifierValidity::Valid).unwrap();

        // best_full_block = id1, state_version = id1 (as if h1 was applied in a
        // previous run but h2 arrived already-valid without being applied in UTXO mode).
        db.set_best_full_block_id(&id1).unwrap();
        db.set_state_version(&id1).unwrap();

        // Create UTXO-mode node view (digest_mode=false).
        let mut nv = make_node_view_skip_difficulty(db);
        nv.current_state_version = id1;
        nv.best_full_height = 1;

        // Run fast-forward.
        nv.fast_forward_valid_blocks().unwrap();

        // best_full_block must advance to id2.
        assert_eq!(nv.history.best_full_block_id().unwrap(), Some(id2));

        // In UTXO mode, state_version must NOT advance during fast-forward
        // because the AVL tree was not updated.
        assert_eq!(
            nv.history.get_state_version().unwrap(),
            Some(id1),
            "state_version must stay at id1 in UTXO mode during fast-forward"
        );
        assert_eq!(
            nv.current_state_version, id1,
            "in-memory current_state_version must also stay at id1"
        );
    }

    // restore_consistency advances state_version for already-Valid blocks in digest mode.
    //
    // Regression test for the infinite-loop / no-progress bug:
    // Previously, restore_consistency called validate_and_apply_block for each
    // already-Valid block. Stage 0 intercepted valid blocks, called
    // fast_forward_valid_blocks() (which in UTXO mode no longer updates
    // state_version after Task 2a), and returned Ok without applying state.
    // state_version never advanced, causing restore_consistency to loop over
    // the same block endlessly.
    //
    // After the fix, restore_consistency uses apply_block_state_only which
    // runs only Stage 6 (state application) and Stage 7 (state_version update)
    // and correctly advances state_version.
    #[test]
    fn restore_consistency_advances_state_version_for_valid_blocks() {
        let (db, _dir) = open_test_db();
        let mempool = Arc::new(RwLock::new(ErgoMemPool::with_min_fee(1000, 0)));
        // Use digest_mode=true so state application is lightweight (just header
        // state_root update, no AVL tree operations). This lets the test work
        // without real transactions.
        let mut nv = NodeViewHolder::new(db, mempool, true, genesis_digest());
        nv.set_checkpoint_height(u32::MAX);
        nv.voting_epoch_info
            .parameters
            .table
            .insert(ergo_consensus::parameters::BLOCK_VERSION_ID, 2);

        // Build two blocks. id0 is "genesis-equivalent" at height 0 (state
        // already applied). id1 is at height 1 and is already marked Valid
        // but state has not been advanced to it yet — simulating a gap that
        // restore_consistency must bridge.
        let id0 = make_id(0x10);
        let id1 = make_id(0x11);

        // Store block at height 0 (the current state version).
        let h0 = make_header(0, 0x10);
        nv.history.store_header(&id0, &h0).unwrap();
        nv.history
            .store_block_transactions(&id0, &sample_block_transactions(&id0))
            .unwrap();
        nv.history
            .store_extension(&id0, &sample_extension(&id0))
            .unwrap();
        nv.history
            .set_validity(&id0, ModifierValidity::Valid)
            .unwrap();

        // Store block at height 1 — already Valid, but state not yet applied.
        let mut h1 = make_header(1, 0x11);
        h1.parent_id = id0; // properly link to parent
        nv.history.store_header(&id1, &h1).unwrap();
        nv.history
            .store_block_transactions(&id1, &sample_block_transactions(&id1))
            .unwrap();
        nv.history
            .store_extension(&id1, &sample_extension(&id1))
            .unwrap();
        nv.history
            .set_validity(&id1, ModifierValidity::Valid)
            .unwrap();

        // Set best_full_block to id1 but state_version to id0 — this is the gap.
        nv.history.set_best_full_block_id(&id1).unwrap();
        nv.history.set_state_version(&id0).unwrap();
        nv.current_state_version = id0;
        nv.best_full_height = 0;

        // restore_consistency should advance state_version from id0 to id1.
        nv.restore_consistency().unwrap();

        assert_eq!(
            nv.current_state_version, id1,
            "restore_consistency must advance in-memory state_version to id1"
        );
        assert_eq!(
            nv.history.get_state_version().unwrap(),
            Some(id1),
            "restore_consistency must persist state_version to id1 in DB"
        );
    }
}
