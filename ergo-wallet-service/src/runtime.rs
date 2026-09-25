#![allow(clippy::result_large_err)]

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;

use ergo_primitives::digest::ModifierId;
use ergo_primitives::reader::VlqReader;
use ergo_ser::ergo_box::{read_ergo_box, serialize_ergo_box};
use thiserror::Error;

use crate::chain::{
    BlocksSinceRequest, BlocksSinceResponse, ChainBlock, ChainClient, ChainClientError,
    ChainCursor, CommittedTip,
};
use crate::wallet::scan::{RescanBlock, RescanReadError, RescanTx};
use crate::wallet::{
    Balance, OwnedBlockOutput, RescanError, RescanState, WalletBox, WalletScanMatcher, WalletStore,
    WalletStoreError, WalletTransaction,
};

pub const DEFAULT_SYNC_BATCH: u32 = 256;
pub const MAX_SYNC_BATCH: u32 = 65_536;
pub const MAX_BLOCKS_PER_REQUEST: u32 = 1_024;

#[derive(Debug, Error)]
pub enum WalletServiceError {
    #[error("wallet store failure: {0}")]
    Store(#[from] WalletStoreError),
    #[error("chain client failure: {0}")]
    Chain(#[from] ChainClientError),
    #[error("wallet rescan failure: {0}")]
    Rescan(#[from] RescanError),
    #[error("invalid wallet request: {0}")]
    InvalidRequest(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletStatus {
    pub committed_tip: Option<CommittedTip>,
    pub wallet_height: u32,
    pub rescan_state: RescanState,
    pub scan_invalidated: bool,
    pub error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RescanRequest {
    pub from_height: u32,
    pub max_blocks: u32,
}

impl RescanRequest {
    pub fn new(from_height: u32, max_blocks: u32) -> Self {
        Self {
            from_height,
            max_blocks,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RescanReport {
    pub from_height: u32,
    pub to_height: u32,
    pub blocks_processed: u32,
    pub completed: bool,
    pub tip: CommittedTip,
}

#[derive(Clone)]
pub struct WalletService {
    store: Arc<dyn WalletStore>,
    chain: Arc<dyn ChainClient>,
}

pub type WalletRuntime = WalletService;
pub type WalletRuntimeError = WalletServiceError;
pub type WalletRuntimeStatus = WalletStatus;

impl WalletService {
    pub fn new(store: Arc<dyn WalletStore>, chain: Arc<dyn ChainClient>) -> Self {
        Self { store, chain }
    }

    pub fn store(&self) -> &Arc<dyn WalletStore> {
        &self.store
    }

    pub fn chain(&self) -> &Arc<dyn ChainClient> {
        &self.chain
    }

    pub fn status(&self) -> Result<WalletStatus, WalletServiceError> {
        let read = self.store.read()?;
        let wallet_height = read.scan_cursor()?.map(|cursor| cursor.height).unwrap_or(0);
        let rescan_state = read.rescan_state()?;
        let scan_invalidated = read.scan_invalidated()?;
        let committed_tip = match self.chain.committed_tip() {
            Ok(tip) => Some(tip),
            Err(ChainClientError::Unsupported) => None,
            Err(error) => return Err(error.into()),
        };
        let error = match &rescan_state {
            RescanState::Idle if scan_invalidated => Some("scan_invalidated".to_string()),
            RescanState::Running { .. } => Some("rescan_running".to_string()),
            RescanState::Failed { reason, .. } => Some(format!("rescan_failed: {reason}")),
            RescanState::Idle => None,
        };
        Ok(WalletStatus {
            committed_tip,
            wallet_height,
            rescan_state,
            scan_invalidated,
            error,
        })
    }

    pub fn balance(&self) -> Result<Balance, WalletServiceError> {
        Ok(self.store.read()?.balance()?)
    }

    pub fn confirmed_balance(&self) -> Result<Balance, WalletServiceError> {
        let mut balance = self.balance()?;
        balance.immature_nano_ergs = 0;
        Ok(balance)
    }

    pub fn boxes(&self) -> Result<Vec<WalletBox>, WalletServiceError> {
        Ok(self.store.read()?.all_boxes()?)
    }

    pub fn confirmed_boxes(&self) -> Result<Vec<WalletBox>, WalletServiceError> {
        Ok(self.store.read()?.unspent_boxes()?)
    }

    pub fn box_by_id(&self, box_id: &[u8; 32]) -> Result<Option<WalletBox>, WalletServiceError> {
        Ok(self.store.read()?.box_by_id(box_id)?)
    }

    pub fn transactions(&self) -> Result<Vec<WalletTransaction>, WalletServiceError> {
        Ok(self.store.read()?.all_transactions()?)
    }

    pub fn transaction_by_id(
        &self,
        tx_id: &[u8; 32],
    ) -> Result<Option<WalletTransaction>, WalletServiceError> {
        Ok(self.store.read()?.transaction_by_id(tx_id)?)
    }

    pub fn rescan(
        &self,
        from_height: u32,
        max_blocks: u32,
    ) -> Result<RescanReport, WalletServiceError> {
        self.rescan_request(RescanRequest::new(from_height, max_blocks))
    }

    pub fn rescan_full(&self) -> Result<RescanReport, WalletServiceError> {
        self.rescan_to_tip(0)
    }

    pub fn rescan_to_tip(&self, from_height: u32) -> Result<RescanReport, WalletServiceError> {
        self.rescan_to_tip_with_cancellation(from_height, || false)
    }

    pub fn rescan_to_tip_with_cancellation<F>(
        &self,
        from_height: u32,
        is_cancelled: F,
    ) -> Result<RescanReport, WalletServiceError>
    where
        F: FnMut() -> bool,
    {
        self.rescan_to_tip_bounded(from_height, DEFAULT_SYNC_BATCH, is_cancelled)
    }

    fn rescan_to_tip_bounded<F>(
        &self,
        from_height: u32,
        max_blocks: u32,
        mut is_cancelled: F,
    ) -> Result<RescanReport, WalletServiceError>
    where
        F: FnMut() -> bool,
    {
        self.validate_batch_size(max_blocks)?;
        let batch_size = max_blocks.min(DEFAULT_SYNC_BATCH);
        self.set_rescan_state(&RescanState::Running { from_height })?;
        let initial_tip = match self.chain.committed_tip() {
            Ok(tip) => tip,
            Err(error) => return Err(self.fail_rescan(from_height, error.into())),
        };
        let next_height = initial_tip.height.saturating_add(1);
        if from_height > next_height {
            let error = WalletServiceError::InvalidRequest(format!(
                "rescan start {from_height} is ahead of committed tip {}",
                initial_tip.height
            ));
            return Err(self.fail_rescan(from_height, error));
        }
        if from_height == next_height {
            if let Err(error) = self.set_rescan_state(&RescanState::Idle) {
                return Err(self.fail_rescan(from_height, error.into()));
            }
            return Ok(RescanReport {
                from_height,
                to_height: initial_tip.height,
                blocks_processed: 0,
                completed: true,
                tip: initial_tip,
            });
        }
        if from_height == 0 {
            if let Err(error) = self.store.persist_scan_invalidation(true) {
                let _ = self.set_rescan_state(&RescanState::Failed {
                    height: from_height,
                    reason: error.to_string(),
                });
                return Err(error.into());
            }
        }
        let setup = (|| {
            let cursor = self.cursor_for_height(from_height.saturating_sub(1))?;
            let read = self.store.read()?;
            let tracked = read.tracked_pubkeys_with_paths()?;
            let mut tracked_trees = BTreeSet::new();
            let mut cached_pubkeys = BTreeMap::new();
            for (index, pubkey, _) in tracked {
                let tree = ergo_ser::address::build_p2pk_tree_bytes(&pubkey).map_err(|error| {
                    WalletServiceError::InvalidRequest(format!(
                        "tracked pubkey {index} cannot build a P2PK tree: {error:?}"
                    ))
                })?;
                tracked_trees.insert(tree);
                cached_pubkeys.insert(index, pubkey);
            }
            drop(read);
            let scan_matcher = if from_height == 0 {
                Some(WalletScanMatcher::from_store(self.store.as_ref())?)
            } else {
                None
            };
            Ok::<_, WalletServiceError>((cursor, tracked_trees, cached_pubkeys, scan_matcher))
        })();
        let (cursor, tracked_trees, cached_pubkeys, scan_matcher) = match setup {
            Ok(setup) => setup,
            Err(error) => return Err(self.fail_rescan(from_height, error)),
        };
        let tip_cell = RefCell::new(initial_tip.clone());
        let mut pending = VecDeque::<(u32, RescanBlock)>::new();
        let mut next_cursor = cursor.clone();
        let read_block = |height: u32| loop {
            if let Some((block_height, _)) = pending.front() {
                if *block_height != height {
                    return Err(RescanReadError::Corrupt {
                        height,
                        reason: "rescan block page is not contiguous".to_string(),
                    });
                }
                let (_, block) = pending.pop_front().expect("front exists");
                next_cursor = ChainCursor {
                    height,
                    header_id: block.block_id,
                };
                return Ok(Some(block));
            }
            let (_, page_blocks) = self
                .fetch_page(next_cursor.clone(), batch_size)
                .map_err(|source| RescanReadError::Chain { height, source })?;
            pending = page_blocks;
            if pending.is_empty() {
                return Err(RescanReadError::Missing { height });
            }
        };
        let read_tip = || {
            let tip = self
                .chain
                .committed_tip()
                .map_err(|source| RescanReadError::Chain {
                    height: tip_cell.borrow().height,
                    source,
                })?;
            *tip_cell.borrow_mut() = tip.clone();
            Ok(tip)
        };
        let on_batch = |_height, _tip| {
            self.set_rescan_state(&RescanState::Running { from_height })
                .map_err(RescanError::from)
        };
        let result = crate::wallet::WalletScanService::rescan_bounded_store(
            self.store.as_ref(),
            tracked_trees,
            cached_pubkeys,
            from_height,
            initial_tip,
            read_block,
            read_tip,
            &mut is_cancelled,
            scan_matcher
                .as_ref()
                .map(|matcher| matcher as &dyn crate::wallet::ScanRescanMatcher),
            batch_size,
            on_batch,
        );
        let processed = match result {
            Ok(processed) => processed,
            Err(error) => {
                return Err(self.fail_rescan(from_height, map_rescan_error(error)));
            }
        };
        let observed_tip = match self.chain.committed_tip() {
            Ok(tip) => tip,
            Err(error) => return Err(self.fail_rescan(from_height, error.into())),
        };
        let cell_tip = tip_cell.borrow().clone();
        if observed_tip != cell_tip {
            let error = ChainClientError::stale_tip(cell_tip, observed_tip);
            return Err(self.fail_rescan(from_height, WalletServiceError::Chain(error)));
        }
        if let Err(error) = self.set_rescan_state(&RescanState::Idle) {
            return Err(self.fail_rescan(from_height, error.into()));
        }
        Ok(RescanReport {
            from_height,
            to_height: observed_tip.height,
            blocks_processed: processed,
            completed: true,
            tip: observed_tip,
        })
    }

    fn fail_rescan(&self, from_height: u32, error: WalletServiceError) -> WalletServiceError {
        let height = rescan_error_height(&error, from_height);
        let _ = self.store.persist_scan_invalidation(true);
        let state_result = self.set_rescan_state(&RescanState::Failed {
            height,
            reason: error.to_string(),
        });
        state_result
            .err()
            .map_or(error, |state_error| state_error.into())
    }

    fn fetch_page(
        &self,
        cursor: ChainCursor,
        limit: u32,
    ) -> Result<(ChainCursor, VecDeque<(u32, RescanBlock)>), ChainClientError> {
        let response = self.chain.blocks_since(BlocksSinceRequest {
            cursor: cursor.clone(),
            limit: limit.min(MAX_BLOCKS_PER_REQUEST),
        })?;
        let forward = match response {
            BlocksSinceResponse::Forward(forward) => forward,
            BlocksSinceResponse::Ancestor(ancestor) => {
                return Err(ChainClientError::Failure(format!(
                    "chain reorged before wallet rescan height {}; ancestor is {}",
                    cursor.height.saturating_add(1),
                    ancestor.ancestor.height
                )));
            }
            BlocksSinceResponse::Pruned(pruned) => {
                return Err(ChainClientError::Failure(format!(
                    "wallet rescan height {} is below pruned floor {}",
                    cursor.height.saturating_add(1),
                    pruned.minimum_height
                )));
            }
        };
        if forward.blocks.is_empty() {
            return Err(ChainClientError::Failure(format!(
                "chain returned no blocks after cursor height {}",
                cursor.height
            )));
        }
        if forward.blocks.len() > limit.min(MAX_BLOCKS_PER_REQUEST) as usize {
            return Err(ChainClientError::Failure(
                "chain returned more blocks than requested".to_string(),
            ));
        }
        let mut expected_height = cursor.height.saturating_add(1);
        let mut expected_parent = (cursor.height > 0).then_some(cursor.header_id);
        let mut last_id = None;
        let mut page = VecDeque::with_capacity(forward.blocks.len());
        for block in forward.blocks {
            if block.height != expected_height {
                return Err(ChainClientError::Failure(format!(
                    "chain returned height {} while wallet rescan expected {expected_height}",
                    block.height
                )));
            }
            if expected_parent.is_some_and(|parent| block.parent_id != parent) {
                return Err(ChainClientError::Failure(format!(
                    "chain parent mismatch at wallet rescan height {expected_height}"
                )));
            }
            expected_parent = Some(block.block_id);
            last_id = Some(block.block_id);
            let block_height = block.height;
            expected_height = expected_height.saturating_add(1);
            page.push_back((
                block_height,
                self.convert_block(block)
                    .map_err(|error| ChainClientError::Failure(error.to_string()))?,
            ));
        }
        let last_id = last_id.ok_or_else(|| {
            ChainClientError::Failure("chain page did not contain a block identity".to_string())
        })?;
        Ok((
            ChainCursor {
                height: expected_height.saturating_sub(1),
                header_id: last_id,
            },
            page,
        ))
    }

    pub fn rescan_request(
        &self,
        request: RescanRequest,
    ) -> Result<RescanReport, WalletServiceError> {
        self.validate_batch_size(request.max_blocks)?;
        self.rescan_from(request.from_height, request.max_blocks)
    }

    pub fn sync_default(&self) -> Result<RescanReport, WalletServiceError> {
        self.sync(DEFAULT_SYNC_BATCH)
    }

    pub fn sync(&self, max_blocks: u32) -> Result<RescanReport, WalletServiceError> {
        self.validate_batch_size(max_blocks)?;
        let read = self.store.read()?;
        let cursor = read.scan_cursor()?;
        let invalidated = read.scan_invalidated()?;
        let tip = self.chain.committed_tip()?;
        if let Some(cursor) = cursor {
            if cursor.height > tip.height {
                return Err(WalletServiceError::InvalidRequest(format!(
                    "wallet cursor {} is ahead of committed tip {}",
                    cursor.height, tip.height
                )));
            }
        }
        let from_height = match (invalidated, cursor) {
            (true, _) | (_, None) => 0,
            (false, Some(cursor)) => cursor.height.saturating_add(1),
        };
        drop(read);
        self.rescan_from(from_height, max_blocks)
    }

    fn validate_batch_size(&self, max_blocks: u32) -> Result<(), WalletServiceError> {
        if max_blocks > MAX_SYNC_BATCH {
            return Err(WalletServiceError::InvalidRequest(format!(
                "max_blocks {max_blocks} exceeds {MAX_SYNC_BATCH}"
            )));
        }
        Ok(())
    }

    fn set_rescan_state(&self, state: &RescanState) -> Result<(), WalletStoreError> {
        let mut write = self.store.begin_write()?;
        write.set_rescan_state(state)?;
        write.commit()?;
        Ok(())
    }

    fn rescan_from(
        &self,
        from_height: u32,
        max_blocks: u32,
    ) -> Result<RescanReport, WalletServiceError> {
        self.rescan_from_with_cancellation(from_height, max_blocks, || false)
    }

    fn rescan_from_with_cancellation<F>(
        &self,
        from_height: u32,
        max_blocks: u32,
        mut is_cancelled: F,
    ) -> Result<RescanReport, WalletServiceError>
    where
        F: FnMut() -> bool,
    {
        self.set_rescan_state(&RescanState::Running { from_height })?;
        let tip = match self.chain.committed_tip() {
            Ok(tip) => tip,
            Err(error) => return Err(self.fail_rescan(from_height, error.into())),
        };
        let next_height = tip.height.saturating_add(1);
        if from_height > next_height {
            if let Err(error) = self.set_rescan_state(&RescanState::Idle) {
                return Err(self.fail_rescan(from_height, error.into()));
            }
            return Err(WalletServiceError::InvalidRequest(format!(
                "rescan start {from_height} is ahead of committed tip {}",
                tip.height
            )));
        }
        if max_blocks == 0 || from_height == next_height {
            if let Err(error) = self.set_rescan_state(&RescanState::Idle) {
                return Err(self.fail_rescan(from_height, error.into()));
            }
            return Ok(RescanReport {
                from_height,
                to_height: from_height.saturating_sub(1),
                blocks_processed: 0,
                completed: true,
                tip,
            });
        }
        let first_height = from_height.max(1);
        let batch_limit = max_blocks.min(DEFAULT_SYNC_BATCH);
        let available = tip.height.saturating_sub(first_height).saturating_add(1);
        let batch_blocks = available.min(batch_limit);
        let last_height = first_height.saturating_add(batch_blocks.saturating_sub(1));
        let result = (|| {
            let cursor = self.cursor_for_height(first_height.saturating_sub(1))?;
            let blocks_by_height: BTreeMap<u32, RescanBlock> = self
                .fetch_blocks(cursor, first_height, last_height)?
                .into_iter()
                .collect();
            let read = self.store.read()?;
            let tracked = read.tracked_pubkeys_with_paths()?;
            let mut tracked_trees = BTreeSet::new();
            let mut cached_pubkeys = BTreeMap::new();
            for (index, pubkey, _) in tracked {
                let tree = ergo_ser::address::build_p2pk_tree_bytes(&pubkey).map_err(|error| {
                    WalletServiceError::InvalidRequest(format!(
                        "tracked pubkey {index} cannot build a P2PK tree: {error:?}"
                    ))
                })?;
                tracked_trees.insert(tree);
                cached_pubkeys.insert(index, pubkey);
            }
            drop(read);
            let scan_matcher = if from_height == 0 {
                Some(WalletScanMatcher::from_store(self.store.as_ref())?)
            } else {
                None
            };
            let scan_result = crate::wallet::WalletScanService::rescan_full_rebuild_store(
                self.store.as_ref(),
                tracked_trees,
                cached_pubkeys,
                from_height,
                last_height,
                |height| Ok(blocks_by_height.get(&height).cloned()),
                || Ok::<u32, RescanReadError>(last_height),
                &mut is_cancelled,
                scan_matcher
                    .as_ref()
                    .map(|matcher| matcher as &dyn crate::wallet::ScanRescanMatcher),
            );
            scan_result.map_err(WalletServiceError::Rescan)
        })();
        let processed = match result {
            Ok(processed) => processed,
            Err(error) => return Err(self.fail_rescan(from_height, error)),
        };
        let observed_tip = match self.chain.committed_tip() {
            Ok(tip) => tip,
            Err(error) => return Err(self.fail_rescan(from_height, error.into())),
        };
        if observed_tip.height < tip.height
            || (observed_tip.height == tip.height && observed_tip.header_id != tip.header_id)
        {
            let error = WalletServiceError::Chain(ChainClientError::stale_tip(tip, observed_tip));
            return Err(self.fail_rescan(from_height, error));
        }
        if let Err(error) = self.set_rescan_state(&RescanState::Idle) {
            return Err(self.fail_rescan(from_height, error.into()));
        }
        Ok(RescanReport {
            from_height,
            to_height: last_height,
            blocks_processed: processed,
            completed: last_height == observed_tip.height,
            tip: observed_tip,
        })
    }

    fn cursor_for_height(
        &self,
        height: u32,
    ) -> Result<crate::chain::ChainCursor, WalletServiceError> {
        if height == 0 {
            return Ok(ChainCursor::genesis());
        }
        let cursor = self.store.read()?.scan_cursor()?.ok_or_else(|| {
            WalletServiceError::InvalidRequest("wallet scan cursor is missing".to_string())
        })?;
        if cursor.height != height {
            return Err(WalletServiceError::InvalidRequest(format!(
                "wallet cursor height {} does not match requested boundary {height}",
                cursor.height
            )));
        }
        let header_id = cursor.header_id.ok_or_else(|| {
            WalletServiceError::InvalidRequest("wallet cursor has no header identity".to_string())
        })?;
        Ok(crate::chain::ChainCursor { height, header_id })
    }

    fn fetch_blocks(
        &self,
        initial_cursor: ChainCursor,
        first_height: u32,
        last_height: u32,
    ) -> Result<Vec<(u32, RescanBlock)>, WalletServiceError> {
        let mut result: Vec<(u32, RescanBlock)> = Vec::new();
        let mut next_height = first_height;
        let mut cursor = initial_cursor;
        while next_height <= last_height {
            let remaining = last_height.saturating_sub(next_height).saturating_add(1);
            let response = self.chain.blocks_since(BlocksSinceRequest {
                cursor: cursor.clone(),
                limit: remaining.min(MAX_BLOCKS_PER_REQUEST),
            })?;
            let blocks = match response {
                BlocksSinceResponse::Forward(forward) => forward.blocks,
                BlocksSinceResponse::Ancestor(ancestor) => {
                    return Err(WalletServiceError::Chain(ChainClientError::Failure(
                        format!(
                            "chain reorged before wallet rescan height {next_height}; ancestor is {}",
                            ancestor.ancestor.height
                        ),
                    )));
                }
                BlocksSinceResponse::Pruned(pruned) => {
                    return Err(WalletServiceError::Chain(ChainClientError::Failure(
                        format!(
                            "wallet rescan height {next_height} is below pruned floor {}",
                            pruned.minimum_height
                        ),
                    )));
                }
            };
            if blocks.is_empty() {
                return Err(WalletServiceError::Chain(ChainClientError::Failure(
                    format!("chain returned no block at wallet rescan height {next_height}"),
                )));
            }
            let mut expected_height = next_height;
            let mut expected_parent = (cursor.height > 0).then_some(cursor.header_id);
            let mut last_block_id = None;
            for block in blocks {
                if block.height < expected_height {
                    continue;
                }
                if block.height > expected_height {
                    return Err(WalletServiceError::Chain(ChainClientError::Failure(
                        format!(
                            "chain skipped wallet rescan height {expected_height}, next was {}",
                            block.height
                        ),
                    )));
                }
                if expected_parent.is_some_and(|parent| block.parent_id != parent) {
                    return Err(WalletServiceError::Chain(ChainClientError::Failure(
                        format!("chain parent mismatch at wallet rescan height {expected_height}"),
                    )));
                }
                expected_parent = Some(block.block_id);
                last_block_id = Some(block.block_id);
                result.push((block.height, self.convert_block(block)?));
                expected_height = expected_height.saturating_add(1);
            }
            let Some(last_block_id) = last_block_id else {
                return Err(WalletServiceError::Chain(ChainClientError::Failure(
                    format!("chain made no progress at wallet rescan height {next_height}"),
                )));
            };
            next_height = expected_height;
            cursor = ChainCursor {
                height: next_height.saturating_sub(1),
                header_id: last_block_id,
            };
        }
        Ok(result)
    }

    fn convert_block(&self, block: ChainBlock) -> Result<RescanBlock, WalletServiceError> {
        let transactions = block
            .transactions
            .into_iter()
            .map(|transaction| {
                let modifier_id = ModifierId::from_bytes(transaction.tx_id);
                let outputs = transaction
                    .outputs
                    .into_iter()
                    .map(|output| {
                        let mut reader = VlqReader::new(&output.bytes);
                        let ergo_box = read_ergo_box(&mut reader).map_err(|error| {
                            WalletServiceError::InvalidRequest(format!(
                                "decode output {} of transaction {}: {error}",
                                hex::encode(output.box_id),
                                hex::encode(transaction.tx_id)
                            ))
                        })?;
                        let canonical_bytes = serialize_ergo_box(&ergo_box).map_err(|error| {
                            WalletServiceError::InvalidRequest(format!(
                                "serialize output {}: {error}",
                                hex::encode(output.box_id)
                            ))
                        })?;
                        let box_id = ergo_box.box_id().map_err(|error| {
                            WalletServiceError::InvalidRequest(format!(
                                "box id for output {}: {error}",
                                hex::encode(output.box_id)
                            ))
                        })?;
                        if *box_id.as_bytes() != output.box_id
                            || ergo_box.transaction_id != modifier_id
                            || ergo_box.index != output.index
                            || canonical_bytes != output.bytes
                        {
                            return Err(WalletServiceError::InvalidRequest(format!(
                                "chain output identity mismatch at {}:{}",
                                hex::encode(transaction.tx_id),
                                output.index
                            )));
                        }
                        Ok(OwnedBlockOutput {
                            box_id: output.box_id,
                            output_index: output.index,
                            ergo_tree_bytes: ergo_box.candidate.ergo_tree_bytes().to_vec(),
                            value: ergo_box.candidate.value,
                            assets: ergo_box
                                .candidate
                                .tokens
                                .iter()
                                .map(|token| (*token.token_id.as_bytes(), token.amount))
                                .collect(),
                            miner_reward_pubkey:
                                ergo_wallet::proving::miner_reward::extract_miner_reward_pubkey(
                                    ergo_box.candidate.ergo_tree_bytes(),
                                ),
                            box_bytes: output.bytes,
                        })
                    })
                    .collect::<Result<Vec<_>, WalletServiceError>>()?;
                Ok(RescanTx {
                    tx_id: transaction.tx_id,
                    inputs: transaction
                        .inputs
                        .into_iter()
                        .map(|input| input.box_id)
                        .collect(),
                    outputs,
                })
            })
            .collect::<Result<Vec<_>, WalletServiceError>>()?;
        Ok(RescanBlock {
            block_id: block.block_id,
            txs: transactions,
        })
    }
}

fn map_rescan_error(error: RescanError) -> WalletServiceError {
    match error {
        RescanError::Read(RescanReadError::Chain { source, .. }) => {
            WalletServiceError::Chain(source)
        }
        RescanError::TipChanged { expected, actual } => {
            WalletServiceError::Chain(ChainClientError::StaleTip { expected, actual })
        }
        other => WalletServiceError::Rescan(other),
    }
}

fn rescan_error_height(error: &WalletServiceError, fallback: u32) -> u32 {
    match error {
        WalletServiceError::Rescan(RescanError::Read(RescanReadError::Missing { height }))
        | WalletServiceError::Rescan(RescanError::Read(RescanReadError::Corrupt {
            height, ..
        }))
        | WalletServiceError::Rescan(RescanError::Read(RescanReadError::Storage {
            height, ..
        }))
        | WalletServiceError::Rescan(RescanError::Read(RescanReadError::Chain {
            height, ..
        }))
        | WalletServiceError::Rescan(RescanError::Cancelled { height })
        | WalletServiceError::Rescan(RescanError::Matcher { height, .. }) => *height,
        WalletServiceError::Rescan(RescanError::TipChanged { expected, .. }) => expected.height,
        WalletServiceError::Chain(ChainClientError::StaleTip { expected, .. }) => expected.height,
        _ => fallback,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Mutex;

    use super::*;
    use crate::chain::{
        ChainAsset, ChainOutput, ChainSnapshot, ChainTransaction, SubmitRequest, SubmitResponse,
        UtxoLookup,
    };
    use crate::scan::{ScanRequest, WalletInteraction};
    use crate::wallet::reader::{ReservedScanBox, RewardKeyResolution, TrackedAddressMeta};
    use crate::wallet::store::{ScanRegistrySnapshot, TrackedPubkeyPath, WalletWrite};
    use crate::wallet::types::{BoxProvenance, BoxStatus, ScanTrackedBox, ScanTxRecord};
    use crate::wallet::{RedbWalletStore, WalletRead};
    use redb::Database;

    #[derive(Clone)]
    struct RuntimeFacts {
        cursor: Option<crate::wallet::WalletScanCursor>,
        invalidated: bool,
        rescan_state: RescanState,
        tip: Option<(u32, [u8; 32])>,
        balance: Balance,
        boxes: Vec<WalletBox>,
        transactions: Vec<WalletTransaction>,
    }

    #[derive(Clone)]
    struct ReadOnlyStore {
        facts: Arc<Mutex<RuntimeFacts>>,
    }

    impl ReadOnlyStore {
        fn new(facts: RuntimeFacts) -> Self {
            Self {
                facts: Arc::new(Mutex::new(facts)),
            }
        }
    }

    impl WalletStore for ReadOnlyStore {
        fn begin_read(&self) -> Result<Box<dyn WalletRead>, WalletStoreError> {
            Ok(Box::new(ReadOnly {
                facts: self.facts.clone(),
            }))
        }

        fn begin_write(&self) -> Result<Box<dyn WalletWrite>, WalletStoreError> {
            Err(WalletStoreError::Decode("read-only test store".to_string()))
        }
    }

    struct ReadOnly {
        facts: Arc<Mutex<RuntimeFacts>>,
    }

    impl WalletRead for ReadOnly {
        fn scan_cursor(&self) -> Result<Option<crate::wallet::WalletScanCursor>, WalletStoreError> {
            Ok(self.facts.lock().unwrap().cursor)
        }

        fn chain_index_header(&self, _height: u32) -> Result<Option<[u8; 32]>, WalletStoreError> {
            Ok(None)
        }

        fn scan_invalidated(&self) -> Result<bool, WalletStoreError> {
            Ok(self.facts.lock().unwrap().invalidated)
        }

        fn rescan_state(&self) -> Result<RescanState, WalletStoreError> {
            Ok(self.facts.lock().unwrap().rescan_state.clone())
        }

        fn all_boxes(&self) -> Result<Vec<WalletBox>, WalletStoreError> {
            Ok(self.facts.lock().unwrap().boxes.clone())
        }

        fn unspent_boxes(&self) -> Result<Vec<WalletBox>, WalletStoreError> {
            Ok(self
                .facts
                .lock()
                .unwrap()
                .boxes
                .iter()
                .filter(|wallet_box| matches!(wallet_box.status, BoxStatus::Confirmed))
                .cloned()
                .collect())
        }

        fn box_by_id(&self, box_id: &[u8; 32]) -> Result<Option<WalletBox>, WalletStoreError> {
            Ok(self
                .facts
                .lock()
                .unwrap()
                .boxes
                .iter()
                .find(|wallet_box| &wallet_box.box_id == box_id)
                .cloned())
        }

        fn all_transactions(&self) -> Result<Vec<WalletTransaction>, WalletStoreError> {
            Ok(self.facts.lock().unwrap().transactions.clone())
        }

        fn transaction_by_id(
            &self,
            tx_id: &[u8; 32],
        ) -> Result<Option<WalletTransaction>, WalletStoreError> {
            Ok(self
                .facts
                .lock()
                .unwrap()
                .transactions
                .iter()
                .find(|transaction| &transaction.tx_id == tx_id)
                .cloned())
        }

        fn balance(&self) -> Result<Balance, WalletStoreError> {
            Ok(self.facts.lock().unwrap().balance.clone())
        }

        fn reserved_scan_boxes(
            &self,
            _mining: bool,
            _spent: bool,
        ) -> Result<Vec<ReservedScanBox>, WalletStoreError> {
            Ok(Vec::new())
        }

        fn tracked_pubkeys_with_paths(&self) -> Result<Vec<TrackedPubkeyPath>, WalletStoreError> {
            Ok(Vec::new())
        }

        fn tracked_addresses_with_meta(&self) -> Result<Vec<TrackedAddressMeta>, WalletStoreError> {
            Ok(Vec::new())
        }

        fn visible_pubkeys(&self) -> Result<Vec<(u32, [u8; 33])>, WalletStoreError> {
            Ok(Vec::new())
        }

        fn derivation_head(&self) -> Result<u64, WalletStoreError> {
            Ok(0)
        }

        fn change_address_pubkey(&self) -> Result<Option<[u8; 33]>, WalletStoreError> {
            Ok(None)
        }

        fn committed_tip(&self) -> Result<Option<(u32, [u8; 32])>, WalletStoreError> {
            Ok(self.facts.lock().unwrap().tip)
        }

        fn scan_boxes(&self, _scan_id: u16) -> Result<Vec<ScanTrackedBox>, WalletStoreError> {
            Ok(Vec::new())
        }

        fn scan_boxes_with_tip(
            &self,
            _scan_id: u16,
        ) -> Result<(u32, Vec<ScanTrackedBox>), WalletStoreError> {
            Ok((0, Vec::new()))
        }

        fn reserved_scan_boxes_with_tip(
            &self,
            mining: bool,
            spent: bool,
        ) -> Result<(u32, Vec<ReservedScanBox>), WalletStoreError> {
            Ok((0, self.reserved_scan_boxes(mining, spent)?))
        }

        fn scan_transactions(&self, _scan_id: u16) -> Result<Vec<ScanTxRecord>, WalletStoreError> {
            Ok(Vec::new())
        }

        fn resolve_reward_key(&self) -> Result<RewardKeyResolution, WalletStoreError> {
            Ok(RewardKeyResolution::Pending)
        }

        fn registered_scan_count(&self) -> Result<usize, WalletStoreError> {
            Ok(0)
        }

        fn scan_registry(&self) -> Result<ScanRegistrySnapshot, WalletStoreError> {
            Ok(ScanRegistrySnapshot::default())
        }
    }

    struct FakeChain {
        tip: CommittedTip,
        blocks: Vec<ChainBlock>,
    }

    impl ChainClient for FakeChain {
        fn committed_tip(&self) -> Result<CommittedTip, ChainClientError> {
            Ok(self.tip.clone())
        }

        fn snapshot(&self) -> Result<ChainSnapshot, ChainClientError> {
            Ok(ChainSnapshot {
                tip: self.tip.clone(),
                headers: Vec::new(),
                active_parameters: serde_json::json!({}),
                reemission_inputs: Vec::new(),
                snapshot_id: self.tip.header_id,
            })
        }

        fn blocks_since(
            &self,
            request: BlocksSinceRequest,
        ) -> Result<BlocksSinceResponse, ChainClientError> {
            let blocks: Vec<ChainBlock> = self
                .blocks
                .iter()
                .filter(|block| block.height > request.cursor.height)
                .take(request.limit as usize)
                .cloned()
                .collect();
            if blocks.is_empty() {
                return Ok(BlocksSinceResponse::Pruned(
                    crate::chain::PrunedBlocksSince {
                        tip: self.tip.clone(),
                        minimum_height: self.tip.height,
                    },
                ));
            }
            Ok(BlocksSinceResponse::Forward(
                crate::chain::ForwardBlocksSince {
                    tip: self.tip.clone(),
                    blocks,
                },
            ))
        }

        fn lookup_utxo(
            &self,
            box_id: [u8; 32],
            expected_tip: CommittedTip,
        ) -> Result<UtxoLookup, ChainClientError> {
            Ok(UtxoLookup {
                tip: expected_tip,
                utxo: Some(crate::chain::Utxo {
                    box_id,
                    bytes: vec![1],
                    value: 1,
                    assets: Vec::<ChainAsset>::new(),
                    creation_tx_id: [2; 32],
                    creation_output_index: 0,
                    creation_height: 1,
                }),
            })
        }

        fn submit(&self, request: SubmitRequest) -> Result<SubmitResponse, ChainClientError> {
            Ok(SubmitResponse::Accepted {
                tip: self.tip.clone(),
                tx_id: [request.transaction.len() as u8; 32],
            })
        }
    }

    struct RecordingChain {
        inner: FakeChain,
        cursors: Arc<Mutex<Vec<ChainCursor>>>,
    }

    impl ChainClient for RecordingChain {
        fn committed_tip(&self) -> Result<CommittedTip, ChainClientError> {
            self.inner.committed_tip()
        }

        fn snapshot(&self) -> Result<ChainSnapshot, ChainClientError> {
            self.inner.snapshot()
        }

        fn blocks_since(
            &self,
            request: BlocksSinceRequest,
        ) -> Result<BlocksSinceResponse, ChainClientError> {
            self.cursors.lock().unwrap().push(request.cursor.clone());
            self.inner.blocks_since(request)
        }

        fn lookup_utxo(
            &self,
            box_id: [u8; 32],
            expected_tip: CommittedTip,
        ) -> Result<UtxoLookup, ChainClientError> {
            self.inner.lookup_utxo(box_id, expected_tip)
        }

        fn submit(&self, request: SubmitRequest) -> Result<SubmitResponse, ChainClientError> {
            self.inner.submit(request)
        }
    }

    struct ReorgAfterFetchChain {
        new_tip: CommittedTip,
        blocks: Vec<ChainBlock>,
        tip: Arc<Mutex<CommittedTip>>,
        flipped: Arc<AtomicBool>,
    }

    impl ChainClient for ReorgAfterFetchChain {
        fn committed_tip(&self) -> Result<CommittedTip, ChainClientError> {
            Ok(self.tip.lock().unwrap().clone())
        }

        fn snapshot(&self) -> Result<ChainSnapshot, ChainClientError> {
            Ok(ChainSnapshot {
                tip: self.committed_tip()?,
                headers: Vec::new(),
                active_parameters: serde_json::json!({}),
                reemission_inputs: Vec::new(),
                snapshot_id: self.committed_tip()?.header_id,
            })
        }

        fn blocks_since(
            &self,
            request: BlocksSinceRequest,
        ) -> Result<BlocksSinceResponse, ChainClientError> {
            let tip = self.committed_tip()?;
            let blocks: Vec<_> = self
                .blocks
                .iter()
                .filter(|block| block.height > request.cursor.height)
                .take(request.limit as usize)
                .cloned()
                .collect();
            if !self.flipped.swap(true, Ordering::SeqCst) {
                *self.tip.lock().unwrap() = self.new_tip.clone();
            }
            Ok(BlocksSinceResponse::Forward(
                crate::chain::ForwardBlocksSince { tip, blocks },
            ))
        }

        fn lookup_utxo(
            &self,
            _box_id: [u8; 32],
            _expected_tip: CommittedTip,
        ) -> Result<UtxoLookup, ChainClientError> {
            Err(ChainClientError::Unsupported)
        }

        fn submit(&self, _request: SubmitRequest) -> Result<SubmitResponse, ChainClientError> {
            Err(ChainClientError::Unsupported)
        }
    }

    struct StateProbeChain {
        inner: FakeChain,
        store: Arc<RedbWalletStore>,
    }

    impl ChainClient for StateProbeChain {
        fn committed_tip(&self) -> Result<CommittedTip, ChainClientError> {
            self.inner.committed_tip()
        }

        fn snapshot(&self) -> Result<ChainSnapshot, ChainClientError> {
            self.inner.snapshot()
        }

        fn blocks_since(
            &self,
            request: BlocksSinceRequest,
        ) -> Result<BlocksSinceResponse, ChainClientError> {
            assert_eq!(
                self.store.read().unwrap().rescan_state().unwrap(),
                RescanState::Running { from_height: 0 }
            );
            self.inner.blocks_since(request)
        }

        fn lookup_utxo(
            &self,
            box_id: [u8; 32],
            expected_tip: CommittedTip,
        ) -> Result<UtxoLookup, ChainClientError> {
            self.inner.lookup_utxo(box_id, expected_tip)
        }

        fn submit(&self, request: SubmitRequest) -> Result<SubmitResponse, ChainClientError> {
            self.inner.submit(request)
        }
    }

    struct FailNthWriteStore {
        inner: RedbWalletStore,
        writes: AtomicUsize,
    }

    impl WalletStore for FailNthWriteStore {
        fn begin_read(&self) -> Result<Box<dyn WalletRead>, WalletStoreError> {
            self.inner.begin_read()
        }

        fn begin_write(&self) -> Result<Box<dyn WalletWrite>, WalletStoreError> {
            let attempt = self.writes.fetch_add(1, Ordering::SeqCst);
            if attempt == 2 {
                return Err(WalletStoreError::Decode(
                    "injected apply failure".to_string(),
                ));
            }
            self.inner.begin_write()
        }
    }

    #[test]
    fn confirmed_balance_box_and_transaction_reads_use_service_types() {
        let wallet_box = WalletBox {
            box_id: [7; 32],
            creation_tx_id: [8; 32],
            creation_output_index: 0,
            creation_height: 4,
            value: 100,
            assets: vec![([9; 32], 3)],
            status: BoxStatus::Confirmed,
            provenance: BoxProvenance::Owned,
        };
        let transaction = WalletTransaction {
            tx_id: [8; 32],
            block_height: 4,
            block_id: [10; 32],
            wallet_outputs: vec![[7; 32]],
            wallet_inputs: Vec::new(),
        };
        let store = Arc::new(ReadOnlyStore::new(RuntimeFacts {
            cursor: Some(crate::wallet::WalletScanCursor {
                height: 4,
                header_id: Some([10; 32]),
            }),
            invalidated: false,
            rescan_state: RescanState::Idle,
            tip: Some((4, [10; 32])),
            balance: Balance {
                confirmed_nano_ergs: 100,
                immature_nano_ergs: 50,
                tokens: [([9; 32], 3)].into_iter().collect(),
            },
            boxes: vec![wallet_box.clone()],
            transactions: vec![transaction.clone()],
        }));
        let chain = Arc::new(FakeChain {
            tip: CommittedTip::new(4, [10; 32]),
            blocks: Vec::new(),
        });
        let service = WalletService::new(store, chain);
        assert_eq!(
            service.confirmed_balance().unwrap().confirmed_nano_ergs,
            100
        );
        assert_eq!(service.confirmed_balance().unwrap().immature_nano_ergs, 0);
        assert_eq!(
            service
                .box_by_id(&[7; 32])
                .unwrap()
                .map(|wallet_box| wallet_box.box_id),
            Some([7; 32])
        );
        assert_eq!(
            service
                .transaction_by_id(&[8; 32])
                .unwrap()
                .map(|transaction| transaction.tx_id),
            Some([8; 32])
        );
        assert_eq!(service.status().unwrap().wallet_height, 4);
    }

    #[test]
    fn service_rescan_rebuilds_registered_scan_rows() {
        use ergo_primitives::digest::ModifierId;
        use ergo_ser::ergo_box::{serialize_ergo_box, ErgoBox, ErgoBoxCandidate};
        use ergo_ser::ergo_tree::ErgoTree;
        use ergo_ser::opcode::Expr;
        use ergo_ser::register::AdditionalRegisters;
        use ergo_ser::sigma_type::SigmaType;
        use ergo_ser::sigma_value::SigmaValue;
        use ergo_ser::token::Token;

        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::create(dir.path().join("wallet.redb")).unwrap());
        let store: Arc<dyn WalletStore> = Arc::new(RedbWalletStore::new(db));
        let scan = ScanRequest {
            scan_name: "asset".to_string(),
            tracking_rule: crate::scan::predicate::ScanningPredicate::ContainsAsset {
                asset_id: [0x11; 32],
            },
            wallet_interaction: Some(WalletInteraction::Shared),
            remove_offchain: Some(true),
        }
        .into_scan(11);
        let mut write = store.begin_write().unwrap();
        write
            .put_scan(11, serde_json::to_vec(&scan).unwrap(), 11)
            .unwrap();
        write.commit().unwrap();

        let tree = ErgoTree {
            version: 0,
            has_size: true,
            constant_segregation: true,
            constants: vec![(SigmaType::SBoolean, SigmaValue::Boolean(true))],
            body: Expr::Const {
                tpe: SigmaType::SBoolean,
                val: SigmaValue::Boolean(true),
            },
        };
        let candidate = ErgoBoxCandidate::new(
            1_000_000,
            tree,
            1,
            vec![Token {
                token_id: ergo_ser::token::TokenId::from_bytes([0x11; 32]),
                amount: 1,
            }],
            AdditionalRegisters::empty(),
        )
        .unwrap();
        let ergo_box = ErgoBox {
            candidate,
            transaction_id: ModifierId::from_bytes([7; 32]),
            index: 0,
        };
        let bytes = serialize_ergo_box(&ergo_box).unwrap();
        let box_id = *ergo_box.box_id().unwrap().as_bytes();
        let chain = Arc::new(FakeChain {
            tip: CommittedTip::new(1, [1; 32]),
            blocks: vec![ChainBlock {
                block_id: [1; 32],
                height: 1,
                parent_id: [0; 32],
                transactions: vec![ChainTransaction {
                    tx_id: [7; 32],
                    inputs: Vec::new(),
                    outputs: vec![ChainOutput {
                        box_id,
                        index: 0,
                        bytes,
                    }],
                }],
            }],
        });
        let service = WalletService::new(store.clone(), chain);
        let report = service.rescan_full().unwrap();
        assert_eq!(report.blocks_processed, 1);
        assert_eq!(store.read().unwrap().scan_boxes(11).unwrap().len(), 1);
    }

    #[test]
    fn empty_registry_rescan_clears_orphaned_scan_rows() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::create(dir.path().join("wallet.redb")).unwrap());
        let store: Arc<dyn WalletStore> = Arc::new(RedbWalletStore::new(db));
        let mut write = store.begin_write().unwrap();
        write
            .replace_scan_box(&[11], [9; 32], 1, 0, vec![1, 2, 3])
            .unwrap();
        write.commit().unwrap();
        let chain = Arc::new(FakeChain {
            tip: CommittedTip::new(1, [1; 32]),
            blocks: vec![ChainBlock {
                block_id: [1; 32],
                height: 1,
                parent_id: [0; 32],
                transactions: Vec::new(),
            }],
        });
        let service = WalletService::new(store.clone(), chain);
        service.rescan_full().unwrap();
        assert!(store.read().unwrap().scan_boxes(11).unwrap().is_empty());
    }

    #[test]
    fn bounded_rescan_at_next_height_is_zero_work() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::create(dir.path().join("wallet.redb")).unwrap());
        let store = Arc::new(RedbWalletStore::new(db));
        let cursors = Arc::new(Mutex::new(Vec::new()));
        let chain = Arc::new(RecordingChain {
            inner: FakeChain {
                tip: CommittedTip::new(2, [2; 32]),
                blocks: Vec::new(),
            },
            cursors: cursors.clone(),
        });
        let service = WalletService::new(store.clone(), chain);

        let report = service.rescan(3, 1).unwrap();
        assert_eq!(report.blocks_processed, 0);
        assert_eq!(report.to_height, 2);
        assert!(report.completed);
        assert_eq!(report.tip, CommittedTip::new(2, [2; 32]));

        let to_tip = service.rescan_to_tip(3).unwrap();
        assert_eq!(to_tip.blocks_processed, 0);
        assert_eq!(to_tip.to_height, 2);
        assert!(to_tip.completed);
        assert!(cursors.lock().unwrap().is_empty());
        assert_eq!(
            store.read().unwrap().rescan_state().unwrap(),
            RescanState::Idle
        );
    }

    #[test]
    fn bounded_rescan_persists_running_before_fetch() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::create(dir.path().join("wallet.redb")).unwrap());
        let store = Arc::new(RedbWalletStore::new(db));
        let chain = StateProbeChain {
            inner: FakeChain {
                tip: CommittedTip::new(1, [1; 32]),
                blocks: vec![ChainBlock {
                    block_id: [1; 32],
                    height: 1,
                    parent_id: [0; 32],
                    transactions: Vec::new(),
                }],
            },
            store: store.clone(),
        };
        let service = WalletService::new(store, Arc::new(chain));
        assert_eq!(service.rescan(0, 1).unwrap().blocks_processed, 1);
    }

    #[test]
    fn bounded_rescan_rejects_a_same_height_reorg_with_stale_tip() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::create(dir.path().join("wallet.redb")).unwrap());
        let store = Arc::new(RedbWalletStore::new(db));
        let old_tip = CommittedTip::new(1, [1; 32]);
        let new_tip = CommittedTip::new(1, [9; 32]);
        let chain = Arc::new(ReorgAfterFetchChain {
            new_tip: new_tip.clone(),
            blocks: vec![ChainBlock {
                block_id: old_tip.header_id,
                height: 1,
                parent_id: [0; 32],
                transactions: Vec::new(),
            }],
            tip: Arc::new(Mutex::new(old_tip.clone())),
            flipped: Arc::new(AtomicBool::new(false)),
        });
        let service = WalletService::new(store.clone(), chain);

        assert!(matches!(
            service.rescan(0, 1),
            Err(WalletServiceError::Chain(ChainClientError::StaleTip {
                expected,
                actual,
            })) if expected == old_tip && actual == new_tip
        ));
        assert!(matches!(
            store.read().unwrap().rescan_state().unwrap(),
            RescanState::Failed { .. }
        ));
        assert!(store.read().unwrap().scan_invalidated().unwrap());
    }

    #[test]
    fn bounded_rescan_persists_failed_on_apply_error() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::create(dir.path().join("wallet.redb")).unwrap());
        let store = Arc::new(FailNthWriteStore {
            inner: RedbWalletStore::new(db),
            writes: AtomicUsize::new(0),
        });
        let chain = Arc::new(FakeChain {
            tip: CommittedTip::new(1, [1; 32]),
            blocks: vec![ChainBlock {
                block_id: [1; 32],
                height: 1,
                parent_id: [0; 32],
                transactions: Vec::new(),
            }],
        });
        let service = WalletService::new(store.clone(), chain);

        assert!(service.rescan(0, 1).is_err());
        assert!(matches!(
            store.read().unwrap().rescan_state().unwrap(),
            RescanState::Failed { .. }
        ));
        assert!(store.read().unwrap().scan_invalidated().unwrap());
    }

    #[test]
    fn rescan_is_bounded_and_uses_the_chain_client() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::create(dir.path().join("wallet.redb")).unwrap());
        let store: Arc<dyn WalletStore> = Arc::new(RedbWalletStore::new(db));
        let chain = Arc::new(FakeChain {
            tip: CommittedTip::new(2, [2; 32]),
            blocks: vec![
                ChainBlock {
                    block_id: [1; 32],
                    height: 1,
                    parent_id: [9; 32],
                    transactions: Vec::new(),
                },
                ChainBlock {
                    block_id: [2; 32],
                    height: 2,
                    parent_id: [1; 32],
                    transactions: Vec::new(),
                },
            ],
        });
        let service = WalletService::new(store.clone(), chain);
        let report = service.rescan(0, 1).unwrap();
        assert_eq!(report.blocks_processed, 1);
        assert!(!report.completed);
        assert_eq!(report.to_height, 1);
        assert_eq!(
            store.read().unwrap().scan_cursor().unwrap().unwrap().height,
            1
        );
        assert_eq!(
            store.read().unwrap().rescan_state().unwrap(),
            RescanState::Idle
        );
    }

    #[test]
    fn rescan_to_tip_processes_large_tips_in_bounded_batches() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::create(dir.path().join("wallet.redb")).unwrap());
        let store: Arc<dyn WalletStore> = Arc::new(RedbWalletStore::new(db));
        let mut blocks = Vec::new();
        let mut parent = [0; 32];
        for height in 1..=600 {
            let block_id = [((height % 255) + 1) as u8; 32];
            blocks.push(ChainBlock {
                block_id,
                height,
                parent_id: parent,
                transactions: Vec::new(),
            });
            parent = block_id;
        }
        let cursors = Arc::new(Mutex::new(Vec::new()));
        let chain = Arc::new(RecordingChain {
            inner: FakeChain {
                tip: CommittedTip::new(600, parent),
                blocks,
            },
            cursors: cursors.clone(),
        });
        let service = WalletService::new(store.clone(), chain);
        let report = service.rescan_full().unwrap();
        assert!(report.completed);
        assert_eq!(report.blocks_processed, 600);
        assert_eq!(report.to_height, 600);
        assert_eq!(
            store.read().unwrap().scan_cursor().unwrap().unwrap().height,
            600
        );
        assert_eq!(
            store.read().unwrap().rescan_state().unwrap(),
            RescanState::Idle
        );
        assert!(!store.read().unwrap().scan_invalidated().unwrap());
        let cursors = cursors.lock().unwrap();
        assert_eq!(cursors.len(), 3);
        assert_eq!(
            cursors[0],
            ChainCursor {
                height: 0,
                header_id: [0; 32]
            }
        );
        assert_eq!(
            cursors[1],
            ChainCursor {
                height: 256,
                header_id: [2; 32]
            }
        );
        assert_eq!(
            cursors[2],
            ChainCursor {
                height: 512,
                header_id: [3; 32]
            }
        );
    }

    #[test]
    fn rescan_fetch_failure_is_persisted_as_failed_and_invalidated() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::create(dir.path().join("wallet.redb")).unwrap());
        let store: Arc<dyn WalletStore> = Arc::new(RedbWalletStore::new(db));
        let chain = Arc::new(FakeChain {
            tip: CommittedTip::new(2, [2; 32]),
            blocks: vec![ChainBlock {
                block_id: [1; 32],
                height: 1,
                parent_id: [0; 32],
                transactions: Vec::new(),
            }],
        });
        let service = WalletService::new(store.clone(), chain);
        assert!(service.rescan_full().is_err());
        assert!(matches!(
            store.read().unwrap().rescan_state().unwrap(),
            RescanState::Failed { .. }
        ));
        assert!(store.read().unwrap().scan_invalidated().unwrap());
    }

    #[test]
    fn chain_client_remains_object_safe_for_runtime() {
        let client: &dyn ChainClient = &FakeChain {
            tip: CommittedTip::new(3, [4; 32]),
            blocks: Vec::new(),
        };
        assert_eq!(client.committed_tip().unwrap().height, 3);
    }
}
