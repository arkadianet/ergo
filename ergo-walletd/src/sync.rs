#![allow(clippy::result_large_err)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ergo_ser::address::build_p2pk_tree_bytes;
use ergo_wallet_service::wallet::scan::{RescanBlock, ScanRescanMatcher};
use ergo_wallet_service::{
    ChainBlock, ChainClientError, ChainCursor, CommittedTip, RescanState, ScanMatchRecord,
    WalletScanMatcher, WalletService, WalletServiceError, WalletStoreError,
};
use thiserror::Error;

const MAX_REORG_REBUILDS: u8 = 8;
const MAX_RETRY_ATTEMPTS: usize = 4;
const MAX_RETRY_DELAY: Duration = Duration::from_secs(8);

#[derive(Debug, Clone, Copy)]
pub struct SyncConfig {
    pub batch: u32,
    pub retry_delay: Duration,
    pub max_retry_delay: Duration,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            batch: 256,
            retry_delay: Duration::from_millis(250),
            max_retry_delay: MAX_RETRY_DELAY,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncReport {
    pub from_height: u32,
    pub wallet_height: u32,
    pub blocks_processed: u32,
    pub completed: bool,
    pub tip: CommittedTip,
}

#[derive(Debug, Error)]
pub enum SyncError {
    #[error("wallet store failure: {0}")]
    Store(#[from] WalletStoreError),
    #[error("wallet service failure: {0}")]
    Service(#[from] WalletServiceError),
    #[error("chain failure: {0}")]
    Chain(#[from] ChainClientError),
    #[error("chain protocol failure: {0}")]
    Protocol(String),
    #[error("chain history is pruned at minimum height {0}")]
    Pruned(u32),
}

impl SyncError {
    pub fn retryable(&self) -> bool {
        matches!(self, Self::Chain(error) if is_retryable(error))
    }
}

pub struct StandaloneSyncer {
    service: Arc<WalletService>,
    config: SyncConfig,
    fail_next_commit: Arc<AtomicBool>,
}

impl StandaloneSyncer {
    pub fn new(service: Arc<WalletService>, config: SyncConfig) -> Self {
        Self {
            service,
            config,
            fail_next_commit: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn inject_next_commit_failure(&self) {
        self.fail_next_commit.store(true, Ordering::SeqCst);
    }

    pub fn service(&self) -> &Arc<WalletService> {
        &self.service
    }

    pub fn sync_once(&self) -> Result<SyncReport, SyncError> {
        if self.config.batch == 0 || self.config.batch > 1024 {
            return Err(SyncError::Protocol(
                "sync batch must be between 1 and 1024".to_string(),
            ));
        }
        let (mut cursor, mut rebuild, start_height) = self.initial_cursor()?;
        self.persist_state(RescanState::Running {
            from_height: start_height,
        })?;
        let mut tip = self.retry(|| self.service.chain().committed_tip())?;
        if cursor.height > tip.height {
            return Err(self.fail(SyncError::Protocol(format!(
                "wallet cursor {} is ahead of node tip {}",
                cursor.height, tip.height
            ))));
        }
        let mut processed = 0u32;
        let mut reorgs = 0u8;
        loop {
            if rebuild {
                self.prepare_full_rebuild()?;
                cursor = ChainCursor::genesis();
                rebuild = false;
            }
            if cursor.height >= tip.height {
                if rebuild || processed == 0 {
                    self.finish_full_rebuild_if_needed(start_height, true)?;
                }
                self.persist_state(RescanState::Idle)?;
                return Ok(SyncReport {
                    from_height: start_height,
                    wallet_height: cursor.height,
                    blocks_processed: processed,
                    completed: true,
                    tip,
                });
            }
            if processed >= self.config.batch {
                return Ok(SyncReport {
                    from_height: start_height,
                    wallet_height: cursor.height,
                    blocks_processed: processed,
                    completed: false,
                    tip,
                });
            }
            let remaining = tip.height.saturating_sub(cursor.height).saturating_add(1);
            let limit = remaining.min(self.config.batch - processed).min(1024);
            let response = self.retry(|| {
                self.service
                    .chain()
                    .blocks_since(ergo_wallet_service::BlocksSinceRequest {
                        cursor: cursor.clone(),
                        limit,
                    })
            })?;
            match response {
                ergo_wallet_service::BlocksSinceResponse::Forward(forward) => {
                    if forward.tip.height < tip.height {
                        return Err(self.fail(SyncError::Protocol(
                            "chain tip regressed during forward sync".to_string(),
                        )));
                    }
                    let forward_tip_height = forward.tip.height;
                    tip = forward.tip;
                    if forward_tip_height < cursor.height {
                        return Err(self.fail(SyncError::Protocol(
                            "chain page tip is behind the wallet cursor".to_string(),
                        )));
                    }
                    validate_page(&cursor, &forward.blocks, forward_tip_height)
                        .map_err(|error| self.fail(error))?;
                    if forward.blocks.is_empty() {
                        if cursor.height < tip.height {
                            return Err(self.fail(SyncError::Protocol(
                                "chain returned an empty page before the tip".to_string(),
                            )));
                        }
                        continue;
                    }
                    let (tracked_trees, cached_pubkeys) = self.tracked_keys()?;
                    let matcher = WalletScanMatcher::from_store(self.service.store().as_ref())?;
                    for block in forward.blocks {
                        let height = block.height;
                        let rescan_block = self.service.convert_block(block).map_err(|error| {
                            self.fail(SyncError::Protocol(format!(
                                "block conversion failed: {error}"
                            )))
                        })?;
                        let records = scan_records(&matcher, height, &rescan_block)
                            .map_err(|error| self.fail(error))?;
                        let mut write = self.service.store().begin_write()?;
                        write.apply_rescan_block(
                            height,
                            &tracked_trees,
                            &cached_pubkeys,
                            &rescan_block,
                            records.as_deref(),
                        )?;
                        write.commit()?;
                        if self.fail_next_commit.swap(false, Ordering::SeqCst) {
                            return Err(SyncError::Protocol(
                                "injected post-commit failure".to_string(),
                            ));
                        }
                        cursor = ChainCursor {
                            height,
                            header_id: rescan_block.block_id,
                        };
                        processed = processed.saturating_add(1);
                        if processed >= self.config.batch {
                            break;
                        }
                    }
                }
                ergo_wallet_service::BlocksSinceResponse::Ancestor(ancestor) => {
                    if ancestor.ancestor.height > cursor.height {
                        return Err(self.fail(SyncError::Protocol(
                            "chain ancestor is ahead of the wallet cursor".to_string(),
                        )));
                    }
                    reorgs = reorgs.saturating_add(1);
                    if reorgs > MAX_REORG_REBUILDS {
                        return Err(self.fail(SyncError::Protocol(
                            "chain reorg exceeded the rebuild limit".to_string(),
                        )));
                    }
                    rebuild = true;
                    tip = self.retry(|| self.service.chain().committed_tip())?;
                }
                ergo_wallet_service::BlocksSinceResponse::Pruned(pruned) => {
                    self.service.store().persist_scan_invalidation(true)?;
                    let error = SyncError::Pruned(pruned.minimum_height);
                    return Err(self.fail(error));
                }
            }
            if cursor.height > tip.height {
                return Err(self.fail(SyncError::Protocol(
                    "chain page advanced beyond its tip".to_string(),
                )));
            }
            if processed >= self.config.batch {
                return Ok(SyncReport {
                    from_height: start_height,
                    wallet_height: cursor.height,
                    blocks_processed: processed,
                    completed: false,
                    tip,
                });
            }
            if cursor.height >= tip.height {
                self.finish_full_rebuild_if_needed(start_height, true)?;
                self.persist_state(RescanState::Idle)?;
                return Ok(SyncReport {
                    from_height: start_height,
                    wallet_height: cursor.height,
                    blocks_processed: processed,
                    completed: true,
                    tip,
                });
            }
        }
    }

    fn initial_cursor(&self) -> Result<(ChainCursor, bool, u32), SyncError> {
        let read = self.service.store().read()?;
        let invalidated = read.scan_invalidated()?;
        let cursor = read.scan_cursor()?;
        drop(read);
        match cursor {
            None => Ok((ChainCursor::genesis(), true, 0)),
            Some(cursor) if cursor.height == 0 && cursor.header_id.is_none() => {
                Ok((ChainCursor::genesis(), invalidated, 0))
            }
            Some(cursor) => {
                let header_id = cursor.header_id.ok_or_else(|| {
                    SyncError::Protocol("positive wallet cursor has no header identity".to_string())
                })?;
                Ok((
                    ChainCursor {
                        height: cursor.height,
                        header_id,
                    },
                    invalidated,
                    cursor.height.saturating_add(1),
                ))
            }
        }
    }

    fn prepare_full_rebuild(&self) -> Result<(), SyncError> {
        let mut write = self.service.store().begin_write()?;
        write.prepare_rescan(0, true)?;
        write.commit()?;
        Ok(())
    }

    fn finish_full_rebuild_if_needed(
        &self,
        _start_height: u32,
        complete: bool,
    ) -> Result<(), SyncError> {
        if !complete {
            return Ok(());
        }
        let read = self.service.store().read()?;
        let invalidated = read.scan_invalidated()?;
        drop(read);
        if invalidated {
            let mut write = self.service.store().begin_write()?;
            write.finish_rescan(0)?;
            write.commit()?;
        }
        Ok(())
    }

    #[allow(clippy::type_complexity)]
    fn tracked_keys(&self) -> Result<(BTreeSet<Vec<u8>>, BTreeMap<u64, [u8; 33]>), SyncError> {
        let read = self.service.store().read()?;
        let tracked = read.tracked_pubkeys_with_paths()?;
        drop(read);
        let mut trees = BTreeSet::new();
        let mut pubkeys = BTreeMap::new();
        for (index, pubkey, _) in tracked {
            let tree = build_p2pk_tree_bytes(&pubkey).map_err(|error| {
                SyncError::Protocol(format!("tracked public key {index} is invalid: {error:?}"))
            })?;
            trees.insert(tree);
            pubkeys.insert(index, pubkey);
        }
        Ok((trees, pubkeys))
    }

    fn persist_state(&self, state: RescanState) -> Result<(), SyncError> {
        let mut write = self.service.store().begin_write()?;
        write.set_rescan_state(&state)?;
        write.commit()?;
        Ok(())
    }

    fn retry<T, F>(&self, mut operation: F) -> Result<T, ChainClientError>
    where
        F: FnMut() -> Result<T, ChainClientError>,
    {
        let mut attempt = 0usize;
        let mut delay = self.config.retry_delay;
        loop {
            match operation() {
                Ok(value) => return Ok(value),
                Err(error) if is_retryable(&error) && attempt + 1 < MAX_RETRY_ATTEMPTS => {
                    if !delay.is_zero() {
                        std::thread::sleep(delay.min(self.config.max_retry_delay));
                    }
                    delay = delay.saturating_mul(2).min(self.config.max_retry_delay);
                    attempt += 1;
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn fail(&self, error: SyncError) -> SyncError {
        if matches!(error, SyncError::Pruned(_)) {
            let _ = self.service.store().persist_scan_invalidation(true);
        }
        let height = self
            .service
            .store()
            .read()
            .ok()
            .and_then(|read| {
                read.scan_cursor()
                    .ok()
                    .flatten()
                    .map(|cursor| cursor.height)
            })
            .unwrap_or(0);
        let reason = error.to_string();
        let _ = self.persist_state(RescanState::Failed { height, reason });
        error
    }
}

fn is_retryable(error: &ChainClientError) -> bool {
    matches!(
        error,
        ChainClientError::Transport(_)
            | ChainClientError::Unavailable(_)
            | ChainClientError::Timeout(_)
            | ChainClientError::Overloaded(_)
            | ChainClientError::ShuttingDown(_)
    )
}

fn validate_page(
    cursor: &ChainCursor,
    blocks: &[ChainBlock],
    tip_height: u32,
) -> Result<(), SyncError> {
    let mut page_cursor = cursor.clone();
    for block in blocks {
        if block.height > tip_height {
            return Err(SyncError::Protocol(
                "chain page contains a block above its tip".to_string(),
            ));
        }
        validate_block(&page_cursor, block)?;
        page_cursor.height = block.height;
        page_cursor.header_id = block.block_id;
    }
    Ok(())
}

fn validate_block(cursor: &ChainCursor, block: &ChainBlock) -> Result<(), SyncError> {
    let expected_height = cursor.height.saturating_add(1);
    if block.height != expected_height {
        return Err(SyncError::Protocol(format!(
            "block height {} does not match expected {expected_height}",
            block.height
        )));
    }
    if cursor.height > 0 && block.parent_id != cursor.header_id {
        return Err(SyncError::Protocol(format!(
            "block parent mismatch at height {}",
            block.height
        )));
    }
    Ok(())
}

fn scan_records(
    matcher: &WalletScanMatcher,
    height: u32,
    block: &RescanBlock,
) -> Result<Option<Vec<ScanMatchRecord>>, SyncError> {
    if matcher.registry().is_empty() {
        return Ok(None);
    }
    let mut bytes = Vec::new();
    let mut metadata = Vec::new();
    for transaction in &block.txs {
        for output in &transaction.outputs {
            bytes.push(output.box_bytes.as_slice());
            metadata.push((output.box_id, output.output_index));
        }
    }
    let matches = matcher
        .match_boxes(&bytes)
        .map_err(|reason| SyncError::Protocol(format!("scan matcher failed: {reason}")))?;
    if matches.len() != bytes.len() {
        return Err(SyncError::Protocol(
            "scan matcher returned the wrong result count".to_string(),
        ));
    }
    Ok(Some(
        metadata
            .into_iter()
            .zip(matches)
            .zip(bytes)
            .filter(|((_, scan_ids), _)| !scan_ids.is_empty())
            .map(
                |(((box_id, output_index), scan_ids), box_bytes)| ScanMatchRecord {
                    box_id,
                    scan_ids,
                    box_bytes: box_bytes.to_vec(),
                    inclusion_height: height,
                    creation_out_index: output_index,
                },
            )
            .collect(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_wallet_service::{ChainClient, RedbWalletStore, WalletStore};
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct FakeState {
        tip: CommittedTip,
        responses: Arc<Mutex<Vec<ergo_wallet_service::BlocksSinceResponse>>>,
        tip_calls: Arc<Mutex<usize>>,
    }

    struct FakeClient {
        state: FakeState,
    }

    impl ChainClient for FakeClient {
        fn committed_tip(&self) -> Result<CommittedTip, ChainClientError> {
            *self.state.tip_calls.lock().unwrap() += 1;
            Ok(self.state.tip.clone())
        }

        fn snapshot(&self) -> Result<ergo_wallet_service::ChainSnapshot, ChainClientError> {
            Err(ChainClientError::Unsupported)
        }

        fn blocks_since(
            &self,
            _request: ergo_wallet_service::BlocksSinceRequest,
        ) -> Result<ergo_wallet_service::BlocksSinceResponse, ChainClientError> {
            let mut responses = self.state.responses.lock().unwrap();
            if responses.is_empty() {
                Ok(ergo_wallet_service::BlocksSinceResponse::Forward(
                    ergo_wallet_service::ForwardBlocksSince {
                        tip: self.state.tip.clone(),
                        blocks: Vec::new(),
                    },
                ))
            } else {
                Ok(responses.remove(0))
            }
        }

        fn lookup_utxo(
            &self,
            _box_id: [u8; 32],
            _expected_tip: CommittedTip,
        ) -> Result<ergo_wallet_service::UtxoLookup, ChainClientError> {
            Err(ChainClientError::Unsupported)
        }

        fn submit(
            &self,
            _request: ergo_wallet_service::SubmitRequest,
        ) -> Result<ergo_wallet_service::SubmitResponse, ChainClientError> {
            Err(ChainClientError::Unsupported)
        }
    }

    fn block(height: u32, parent: u8) -> ChainBlock {
        ChainBlock {
            block_id: [height as u8; 32],
            height,
            parent_id: [parent; 32],
            transactions: Vec::new(),
        }
    }

    fn syncer(
        dir: &tempfile::TempDir,
        responses: Vec<ergo_wallet_service::BlocksSinceResponse>,
        tip: CommittedTip,
    ) -> StandaloneSyncer {
        let store =
            Arc::new(RedbWalletStore::open_standalone(dir.path().join("wallet.redb")).unwrap());
        let state = FakeState {
            tip,
            responses: Arc::new(Mutex::new(responses)),
            tip_calls: Arc::new(Mutex::new(0)),
        };
        let chain = Arc::new(FakeClient { state });
        let service = Arc::new(WalletService::new(store, chain));
        StandaloneSyncer::new(
            service,
            SyncConfig {
                batch: 16,
                retry_delay: Duration::ZERO,
                max_retry_delay: Duration::ZERO,
            },
        )
    }

    #[test]
    fn forward_sync_is_incremental_and_persists_cursor() {
        let dir = tempfile::tempdir().unwrap();
        let tip = CommittedTip::new(2, [2; 32]);
        let syncer = syncer(
            &dir,
            vec![ergo_wallet_service::BlocksSinceResponse::Forward(
                ergo_wallet_service::ForwardBlocksSince {
                    tip: tip.clone(),
                    blocks: vec![block(1, 0), block(2, 1)],
                },
            )],
            tip.clone(),
        );
        let report = syncer.sync_once().unwrap();
        assert_eq!(report.blocks_processed, 2);
        assert_eq!(report.wallet_height, 2);
        let read = syncer.service().store().read().unwrap();
        assert_eq!(read.scan_cursor().unwrap().unwrap().height, 2);
        assert_eq!(
            read.scan_cursor().unwrap().unwrap().header_id,
            Some([2; 32])
        );
    }

    #[test]
    fn ancestor_rebuilds_and_does_not_skip_lower_blocks() {
        let dir = tempfile::tempdir().unwrap();
        let tip = CommittedTip::new(3, [3; 32]);
        let store =
            Arc::new(RedbWalletStore::open_standalone(dir.path().join("wallet.redb")).unwrap());
        let mut write = store.begin_write().unwrap();
        write.set_scan_cursor(2, Some(&[9; 32])).unwrap();
        write.commit().unwrap();
        let state = FakeState {
            tip: tip.clone(),
            responses: Arc::new(Mutex::new(vec![
                ergo_wallet_service::BlocksSinceResponse::Ancestor(
                    ergo_wallet_service::AncestorBlocksSince {
                        tip: tip.clone(),
                        ancestor: ChainCursor {
                            height: 1,
                            header_id: [1; 32],
                        },
                    },
                ),
                ergo_wallet_service::BlocksSinceResponse::Forward(
                    ergo_wallet_service::ForwardBlocksSince {
                        tip: tip.clone(),
                        blocks: vec![block(1, 0), block(2, 1), block(3, 2)],
                    },
                ),
            ])),
            tip_calls: Arc::new(Mutex::new(0)),
        };
        let service = Arc::new(WalletService::new(store, Arc::new(FakeClient { state })));
        let syncer = StandaloneSyncer::new(
            service,
            SyncConfig {
                batch: 16,
                retry_delay: Duration::ZERO,
                max_retry_delay: Duration::ZERO,
            },
        );
        let report = syncer.sync_once().unwrap();
        assert_eq!(report.blocks_processed, 3);
        assert_eq!(
            syncer
                .service()
                .store()
                .read()
                .unwrap()
                .scan_cursor()
                .unwrap()
                .unwrap()
                .height,
            3
        );
    }

    #[test]
    fn gap_and_duplicate_pages_are_terminal_protocol_errors() {
        for blocks in [vec![block(2, 1)], vec![block(1, 0), block(1, 0)]] {
            let dir = tempfile::tempdir().unwrap();
            let tip = CommittedTip::new(2, [2; 32]);
            let syncer = syncer(
                &dir,
                vec![ergo_wallet_service::BlocksSinceResponse::Forward(
                    ergo_wallet_service::ForwardBlocksSince { tip, blocks },
                )],
                CommittedTip::new(2, [2; 32]),
            );
            assert!(matches!(syncer.sync_once(), Err(SyncError::Protocol(_))));
        }
    }

    #[test]
    fn restart_after_commit_fault_resumes_from_persisted_cursor() {
        let dir = tempfile::tempdir().unwrap();
        let store =
            Arc::new(RedbWalletStore::open_standalone(dir.path().join("wallet.redb")).unwrap());
        let mut write = store.begin_write().unwrap();
        write.prepare_rescan(0, false).unwrap();
        write
            .apply_rescan_block(
                1,
                &BTreeSet::new(),
                &BTreeMap::new(),
                &RescanBlock {
                    block_id: [1; 32],
                    txs: Vec::new(),
                },
                None,
            )
            .unwrap();
        write.commit().unwrap();
        let mut write = store.begin_write().unwrap();
        write.finish_rescan(0).unwrap();
        write.commit().unwrap();
        let tip = CommittedTip::new(2, [2; 32]);
        let state = FakeState {
            tip: tip.clone(),
            responses: Arc::new(Mutex::new(vec![
                ergo_wallet_service::BlocksSinceResponse::Forward(
                    ergo_wallet_service::ForwardBlocksSince {
                        tip,
                        blocks: vec![block(2, 1)],
                    },
                ),
            ])),
            tip_calls: Arc::new(Mutex::new(0)),
        };
        let service = Arc::new(WalletService::new(store, Arc::new(FakeClient { state })));
        let syncer = StandaloneSyncer::new(
            service,
            SyncConfig {
                batch: 16,
                retry_delay: Duration::ZERO,
                max_retry_delay: Duration::ZERO,
            },
        );
        syncer.inject_next_commit_failure();
        assert!(matches!(syncer.sync_once(), Err(SyncError::Protocol(_))));
        assert_eq!(
            syncer
                .service()
                .store()
                .read()
                .unwrap()
                .scan_cursor()
                .unwrap()
                .unwrap()
                .height,
            2
        );
        let report = syncer.sync_once().unwrap();
        assert!(report.completed);
    }

    #[test]
    fn pruned_invalidates_and_stops() {
        let dir = tempfile::tempdir().unwrap();
        let syncer = syncer(
            &dir,
            vec![ergo_wallet_service::BlocksSinceResponse::Pruned(
                ergo_wallet_service::PrunedBlocksSince {
                    tip: CommittedTip::new(10, [10; 32]),
                    minimum_height: 4,
                },
            )],
            CommittedTip::new(10, [10; 32]),
        );
        assert!(matches!(syncer.sync_once(), Err(SyncError::Pruned(4))));
        assert!(syncer
            .service()
            .store()
            .read()
            .unwrap()
            .scan_invalidated()
            .unwrap());
    }
}
