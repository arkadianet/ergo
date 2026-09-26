#![allow(clippy::result_large_err)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ergo_ser::address::build_p2pk_tree_bytes;
use ergo_wallet_service::wallet::scan::{RescanBlock, ScanRescanMatcher, WalletScanMatcher};
use ergo_wallet_service::{
    ChainBlock, ChainClientError, ChainCursor, CommittedTip, RescanState, ScanMatchRecord,
    WalletService, WalletServiceError, WalletStoreError,
};
use thiserror::Error;

use crate::tip::CachedNodeTip;

const MAX_RETRY_ATTEMPTS: usize = 4;
const MAX_RETRY_DELAY: Duration = Duration::from_secs(8);

/// Consecutive ancestor (reorg) responses tolerated *without a single forward
/// block in between*. This is not a rebuild budget: a chain that reorgs,
/// advances, and reorgs again resets the counter on every forward block, so a
/// normal reorg-heavy network never trips it. It only fires when the node keeps
/// answering "rewind me" and never lets the wallet make progress, which is a
/// protocol-level non-convergence, not a reorg. The old per-batch cap of 8
/// ancestor responses (independent of progress) is deliberately gone: a
/// legitimate chain can serve more than 8 reorgs in one batch.
const MAX_UNPROGRESSIVE_REWINDS: u32 = 64;

/// Upper bound for both sync knobs. Matches the node's own `blocks-since`
/// request limit and the adapter's request validation, so a pass can never ask
/// for a page the node would reject or that `validate_page` would refuse.
pub const MAX_SYNC_BLOCKS: u32 = 1024;

/// Blocks requested per `blocks-since` HTTP call, by default.
///
/// This is deliberately **not** the apply budget. The adapter refuses any
/// response body over `MAX_RESPONSE_BODY_BYTES` (8 MiB), and the chain
/// protocol carries every output box as a hex string, so a page's JSON body
/// costs roughly twice the bytes of the blocks it carries. Consensus bounds one
/// block's `BlockTransactions` section by the voted `maxBlockSize` parameter,
/// and this node documents a `maxBlockSize = 2097152` (2 MiB) vote, so one
/// maxed-out block is already 4 MiB of hex: two of them are 8 MiB *before* any
/// JSON envelope, so a page of `2` is **not provably** under the cap while a
/// page of `1` is — 4 MiB plus an envelope of a few hundred kilobytes, less
/// than half the cap. That is the whole reason this is `1` and not `2`: the
/// safe default is the largest page whose *worst legal* body still fits, and a
/// real mainnet page is far smaller. A page sized from `sync_batch` (the old
/// behaviour: `min(batch, remaining)`) could ask for up to 1024 blocks and
/// simply hit the cap on any real chain.
///
/// Raising it is allowed and bounded (`1..=1024`), but it is an operator
/// decision made against their own node's `maxBlockSize`, not a default.
///
/// A block too large even for a one-block page is **not** retried smaller: the
/// daemon never shrinks a page, so `HttpChainClient` reports it as a terminal
/// bounded error naming the cap and the page size (see `crate::chain_http`).
pub const DEFAULT_BLOCKS_PER_PAGE: u32 = 1;

#[derive(Debug, Clone, Copy)]
pub struct SyncConfig {
    /// Maximum blocks **applied** per pass — the work budget of one
    /// `sync_once`. Independent of how those blocks are fetched: a pass applies
    /// up to `batch` blocks and may therefore issue several HTTP calls.
    pub batch: u32,
    /// Maximum blocks requested per `blocks-since` call. Bounds one response
    /// body; see [`DEFAULT_BLOCKS_PER_PAGE`] for why it is separate from
    /// `batch`.
    pub page: u32,
    pub retry_delay: Duration,
    pub max_retry_delay: Duration,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            batch: 256,
            page: DEFAULT_BLOCKS_PER_PAGE,
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
    tip: Arc<CachedNodeTip>,
    fail_next_commit: Arc<AtomicBool>,
}

#[derive(Debug, Clone)]
struct SyncStart {
    cursor: ChainCursor,
    rebuild: bool,
    from_height: u32,
}

impl StandaloneSyncer {
    pub fn new(service: Arc<WalletService>, config: SyncConfig, tip: Arc<CachedNodeTip>) -> Self {
        Self {
            service,
            config,
            tip,
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
        match self.sync_once_inner() {
            Ok(report) => Ok(report),
            Err(error) if error.retryable() => Err(error),
            Err(SyncError::Pruned(minimum_height)) => {
                Err(self.fail(SyncError::Pruned(minimum_height)))
            }
            Err(error) => Err(self.fail(error)),
        }
    }

    fn sync_once_inner(&self) -> Result<SyncReport, SyncError> {
        if self.config.batch == 0 || self.config.batch > MAX_SYNC_BLOCKS {
            return Err(SyncError::Protocol(format!(
                "sync batch must be between 1 and {MAX_SYNC_BLOCKS}"
            )));
        }
        if self.config.page == 0 || self.config.page > MAX_SYNC_BLOCKS {
            return Err(SyncError::Protocol(format!(
                "blocks page size must be between 1 and {MAX_SYNC_BLOCKS}"
            )));
        }
        let start = self.initial_cursor()?;
        let mut full_rebuild = start.rebuild && start.cursor.is_genesis_sentinel();
        let mut cursor = start.cursor;
        let mut rebuild = start.rebuild;
        let mut rebuild_origin = start.rebuild;
        let mut from_height = start.from_height;
        let mut tip = self.tip()?;
        if cursor.height > tip.height {
            return Err(SyncError::Chain(ChainClientError::stale_tip(
                CommittedTip::new(cursor.height, cursor.header_id),
                tip,
            )));
        }
        let mut processed = 0u32;
        let mut rewinds_without_progress = 0u32;
        let mut full_rebuilds = 0u32;
        let mut reorgs = 0u32;
        // `Running` is published *below* the at-tip check, not here: a
        // caught-up daemon has no work to report, and writing `Running` only to
        // overwrite it with `Idle` on the same idle tick costs a durable write
        // every `sync_interval` forever. The reorg branches publish their own
        // `Running` with the post-rewind `from_height`, so this stays true
        // across them.
        let mut running_published = false;

        loop {
            if rebuild {
                self.prepare_rebuild(&mut cursor, full_rebuild)?;
                rebuild = false;
                full_rebuild = false;
            }
            if cursor.height == tip.height && cursor.header_id == tip.header_id {
                self.finish_rebuild(rebuild_origin)?;
                self.persist_state(RescanState::Idle)?;
                return Ok(SyncReport {
                    from_height,
                    wallet_height: cursor.height,
                    blocks_processed: processed,
                    completed: true,
                    tip,
                });
            }
            if processed >= self.config.batch {
                return Ok(SyncReport {
                    from_height,
                    wallet_height: cursor.height,
                    blocks_processed: processed,
                    completed: false,
                    tip,
                });
            }
            if cursor.height > tip.height {
                return Err(SyncError::Protocol(
                    "chain page advanced beyond its tip".to_string(),
                ));
            }
            if !running_published {
                self.persist_state(RescanState::Running { from_height })?;
                running_published = true;
            }

            let remaining = tip.height.saturating_sub(cursor.height).saturating_add(1);
            // Two independent ceilings: the page budget bounds this one
            // response body, the apply budget bounds the whole pass.
            let limit = remaining
                .min(self.config.page)
                .min(self.config.batch - processed);
            let response = self.blocks_since(cursor.clone(), limit)?;
            match response {
                ergo_wallet_service::BlocksSinceResponse::Forward(forward) => {
                    if forward.tip.height < tip.height {
                        return Err(SyncError::Chain(ChainClientError::stale_tip(
                            tip,
                            forward.tip,
                        )));
                    }
                    if forward.tip.height < cursor.height {
                        return Err(SyncError::Protocol(
                            "chain page tip is behind the wallet cursor".to_string(),
                        ));
                    }
                    tip = forward.tip;
                    validate_page(&cursor, &forward.blocks, &tip, limit)?;
                    if forward.blocks.is_empty() {
                        if cursor.height < tip.height {
                            return Err(SyncError::Protocol(
                                "chain returned an empty page before the tip".to_string(),
                            ));
                        }
                        continue;
                    }
                    let (tracked_trees, cached_pubkeys) = self.tracked_keys()?;
                    let matcher = WalletScanMatcher::from_store(self.service.store().as_ref())?;
                    for block in forward.blocks {
                        let height = block.height;
                        let rescan_block = self.service.convert_block(block).map_err(|error| {
                            SyncError::Protocol(format!("block conversion failed: {error}"))
                        })?;
                        let records = scan_records(&matcher, height, &rescan_block)?;
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
                    // Forward progress was made: a following reorg is a normal
                    // chain event, not a non-converging loop.
                    rewinds_without_progress = 0;
                }
                ergo_wallet_service::BlocksSinceResponse::Ancestor(ancestor) => {
                    // A reorg is only actionable if it actually rewinds: an
                    // ancestor at or above the wallet cursor is a protocol
                    // violation, not a reorg.
                    if ancestor.ancestor.height > cursor.height {
                        return Err(SyncError::Protocol(
                            "chain ancestor is ahead of the wallet cursor".to_string(),
                        ));
                    }
                    rewinds_without_progress = rewinds_without_progress.saturating_add(1);
                    if rewinds_without_progress > MAX_UNPROGRESSIVE_REWINDS {
                        return Err(SyncError::Protocol(format!(
                            "chain returned {} consecutive rewinds without applying a block",
                            rewinds_without_progress
                        )));
                    }
                    reorgs = reorgs.saturating_add(1);
                    let from = cursor.height;
                    match self.service.rewind_to_ancestor(ancestor.ancestor.clone()) {
                        Ok(()) => {
                            tracing::warn!(
                                wallet_height = from,
                                ancestor_height = ancestor.ancestor.height,
                                node_tip = ancestor.tip.height,
                                reorg = reorgs,
                                "chain reorg: rewinding wallet to the common ancestor"
                            );
                            cursor = ancestor.ancestor;
                            processed = 0;
                            from_height = cursor.height.saturating_add(1);
                            self.persist_state(RescanState::Running { from_height })?;
                        }
                        Err(WalletServiceError::RewindUnavailable(reason)) => {
                            // The ancestor is outside the wallet's retained
                            // history. One full rebuild can recover from that;
                            // a second one cannot, so this is a terminal
                            // deeper-than-history condition.
                            if full_rebuilds > 0 {
                                return Err(SyncError::Protocol(format!(
                                    "chain reorg to height {} is deeper than retained history: {reason}",
                                    ancestor.ancestor.height
                                )));
                            }
                            full_rebuilds = full_rebuilds.saturating_add(1);
                            tracing::warn!(
                                wallet_height = from,
                                ancestor_height = ancestor.ancestor.height,
                                node_tip = ancestor.tip.height,
                                reorg = reorgs,
                                "chain reorg: ancestor is outside retained history, rebuilding from genesis"
                            );
                            rebuild = true;
                            full_rebuild = true;
                            rebuild_origin = true;
                            from_height = 0;
                            self.persist_state(RescanState::Running { from_height })?;
                        }
                        Err(error) => return Err(SyncError::Service(error)),
                    }
                    tip = self.tip()?;
                }
                ergo_wallet_service::BlocksSinceResponse::Pruned(pruned) => {
                    return Err(SyncError::Pruned(pruned.minimum_height));
                }
            }
        }
    }

    fn initial_cursor(&self) -> Result<SyncStart, SyncError> {
        let read = self.service.store().read()?;
        let invalidated = read.scan_invalidated()?;
        let cursor = read.scan_cursor()?;
        drop(read);
        match cursor {
            None => Ok(SyncStart {
                cursor: ChainCursor::genesis(),
                rebuild: true,
                from_height: 0,
            }),
            Some(cursor) if cursor.height == 0 && cursor.header_id.is_none() => Ok(SyncStart {
                cursor: ChainCursor::genesis(),
                rebuild: invalidated,
                from_height: 0,
            }),
            Some(cursor) => {
                let header_id = cursor.header_id.ok_or_else(|| {
                    SyncError::Protocol("positive wallet cursor has no header identity".to_string())
                })?;
                Ok(SyncStart {
                    cursor: ChainCursor {
                        height: cursor.height,
                        header_id,
                    },
                    rebuild: invalidated,
                    from_height: if invalidated {
                        0
                    } else {
                        cursor.height.saturating_add(1)
                    },
                })
            }
        }
    }

    fn prepare_rebuild(
        &self,
        cursor: &mut ChainCursor,
        full_rebuild: bool,
    ) -> Result<(), SyncError> {
        let mut write = self.service.store().begin_write()?;
        if full_rebuild {
            write.prepare_rescan(0, true)?;
            *cursor = ChainCursor::genesis();
        } else {
            write.prepare_rescan(cursor.height.saturating_add(1), false)?;
        }
        write.commit()?;
        Ok(())
    }

    fn finish_rebuild(&self, was_rebuild: bool) -> Result<(), SyncError> {
        if !was_rebuild {
            return Ok(());
        }
        let read = self.service.store().read()?;
        let invalidated = read.scan_invalidated()?;
        drop(read);
        if !invalidated {
            return Ok(());
        }
        let mut write = self.service.store().begin_write()?;
        write.finish_rescan(0)?;
        write.commit()?;
        Ok(())
    }

    fn tip(&self) -> Result<CommittedTip, SyncError> {
        let tip = self
            .retry(|| self.service.chain().committed_tip())
            .map_err(map_chain_error)?;
        // Publish for the read API so a local `/status` read never has to probe
        // the node itself.
        self.tip.record(tip.clone());
        Ok(tip)
    }

    fn blocks_since(
        &self,
        cursor: ChainCursor,
        limit: u32,
    ) -> Result<ergo_wallet_service::BlocksSinceResponse, SyncError> {
        self.retry(|| {
            self.service
                .chain()
                .blocks_since(ergo_wallet_service::BlocksSinceRequest {
                    cursor: cursor.clone(),
                    limit,
                })
        })
        .map_err(map_chain_error)
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
                    // Retryable only: the error string is generated locally by
                    // the chain adapter, never a node response body.
                    tracing::warn!(
                        error = %error,
                        attempt = attempt + 1,
                        max_attempts = MAX_RETRY_ATTEMPTS,
                        delay_ms = delay.min(self.config.max_retry_delay).as_millis() as u64,
                        "chain request failed; retrying"
                    );
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
        // Terminal: the loop stops and the daemon exits with this error, so it
        // is logged at error level. Protocol violations and pruned history are
        // operator-actionable; the text is generated locally.
        tracing::error!(
            error = %error,
            wallet_height = height,
            terminal = true,
            "wallet sync failed; the daemon will not continue"
        );
        let reason = error.to_string();
        if let Ok(mut write) = self.service.store().begin_write() {
            if matches!(error, SyncError::Pruned(_)) {
                let _ = write.set_scan_invalidated(true);
            }
            let _ = write.set_rescan_state(&RescanState::Failed { height, reason });
            let _ = write.commit();
        }
        error
    }
}

fn map_chain_error(error: ChainClientError) -> SyncError {
    match error {
        ChainClientError::HistoryPruned {
            minimum_height: Some(minimum_height),
        } => SyncError::Pruned(minimum_height),
        ChainClientError::HistoryPruned {
            minimum_height: None,
        } => SyncError::Protocol(
            "chain reported pruned history without a minimum height".to_string(),
        ),
        // A protocol failure — a malformed page, a response over the byte cap,
        // a continuity break — is this daemon's own invariant vocabulary, not
        // a transport condition, so it is terminal in the same way either way
        // and reads without the doubled "chain failure: chain protocol
        // failure:" prefix. It is never retried: `Protocol` has no retryable
        // arm, and a smaller page is not something the daemon will ask for.
        ChainClientError::Protocol(detail) => SyncError::Protocol(detail),
        other => SyncError::Chain(other),
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
            | ChainClientError::Conflict
            | ChainClientError::StaleTip { .. }
    )
}

fn validate_page(
    cursor: &ChainCursor,
    blocks: &[ChainBlock],
    tip: &CommittedTip,
    limit: u32,
) -> Result<(), SyncError> {
    if blocks.len() > limit as usize || blocks.len() > MAX_SYNC_BLOCKS as usize {
        return Err(SyncError::Protocol(
            "chain returned more blocks than requested".to_string(),
        ));
    }
    let mut page_cursor = cursor.clone();
    for block in blocks {
        if block.height > tip.height {
            return Err(SyncError::Protocol(
                "chain page contains a block above its tip".to_string(),
            ));
        }
        validate_block(&page_cursor, block)?;
        page_cursor.height = block.height;
        page_cursor.header_id = block.block_id;
    }
    if let Some(last) = blocks.last() {
        if last.height == tip.height && last.block_id != tip.header_id {
            return Err(SyncError::Protocol(
                "chain page tip block id does not match the reported tip".to_string(),
            ));
        }
    } else if cursor.height == tip.height && cursor.header_id != tip.header_id {
        return Err(SyncError::Protocol(
            "empty chain page does not match the reported tip".to_string(),
        ));
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
    if block.height > 0 && block.block_id == [0; 32] {
        return Err(SyncError::Protocol(format!(
            "positive-height block {} has a zero block id",
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
        requests: Arc<Mutex<Vec<(u32, u32)>>>,
        dynamic: bool,
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
            request: ergo_wallet_service::BlocksSinceRequest,
        ) -> Result<ergo_wallet_service::BlocksSinceResponse, ChainClientError> {
            self.state
                .requests
                .lock()
                .unwrap()
                .push((request.cursor.height, request.limit));
            let mut responses = self.state.responses.lock().unwrap();
            if responses.is_empty() && self.state.dynamic {
                let first = request.cursor.height.saturating_add(1);
                let last = self
                    .state
                    .tip
                    .height
                    .min(first.saturating_add(request.limit.saturating_sub(1)));
                let blocks = (first..=last)
                    .map(|height| block(height, height.saturating_sub(1) as u8))
                    .collect();
                return Ok(ergo_wallet_service::BlocksSinceResponse::Forward(
                    ergo_wallet_service::ForwardBlocksSince {
                        tip: self.state.tip.clone(),
                        blocks,
                    },
                ));
            }
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

    type RequestLog = Arc<Mutex<Vec<(u32, u32)>>>;

    fn syncer_with_log(
        dir: &tempfile::TempDir,
        responses: Vec<ergo_wallet_service::BlocksSinceResponse>,
        tip: CommittedTip,
    ) -> (StandaloneSyncer, RequestLog) {
        let store =
            Arc::new(RedbWalletStore::open_standalone(dir.path().join("wallet.redb")).unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let state = FakeState {
            tip,
            responses: Arc::new(Mutex::new(responses)),
            tip_calls: Arc::new(Mutex::new(0)),
            requests: requests.clone(),
            dynamic: false,
        };
        let chain: Arc<dyn ChainClient> = Arc::new(FakeClient { state });
        let service = Arc::new(WalletService::new(store, chain.clone()));
        (
            StandaloneSyncer::new(
                service,
                SyncConfig {
                    batch: 16,
                    page: 16,
                    retry_delay: Duration::ZERO,
                    max_retry_delay: Duration::ZERO,
                },
                Arc::new(CachedNodeTip::new(chain)),
            ),
            requests,
        )
    }

    fn syncer(
        dir: &tempfile::TempDir,
        responses: Vec<ergo_wallet_service::BlocksSinceResponse>,
        tip: CommittedTip,
    ) -> StandaloneSyncer {
        syncer_with_log(dir, responses, tip).0
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
        assert!(!read.scan_invalidated().unwrap());
    }

    #[test]
    fn rebuild_progress_advances_across_batches() {
        let dir = tempfile::tempdir().unwrap();
        let tip = CommittedTip::new(20, [20; 32]);
        let store =
            Arc::new(RedbWalletStore::open_standalone(dir.path().join("wallet.redb")).unwrap());
        let mut write = store.begin_write().unwrap();
        write.prepare_rescan(0, true).unwrap();
        write.commit().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let state = FakeState {
            tip: tip.clone(),
            responses: Arc::new(Mutex::new(Vec::new())),
            tip_calls: Arc::new(Mutex::new(0)),
            requests: requests.clone(),
            dynamic: true,
        };
        let chain: Arc<dyn ChainClient> = Arc::new(FakeClient { state });
        let service = Arc::new(WalletService::new(store, chain.clone()));
        let syncer = StandaloneSyncer::new(
            service,
            SyncConfig {
                batch: 4,
                page: 4,
                retry_delay: Duration::ZERO,
                max_retry_delay: Duration::ZERO,
            },
            Arc::new(CachedNodeTip::new(chain)),
        );
        for (index, (expected, completed)) in
            [(4, false), (8, false), (12, false), (16, false), (20, true)]
                .into_iter()
                .enumerate()
        {
            let report = syncer.sync_once().unwrap();
            assert_eq!(report.wallet_height, expected, "batch {index}");
            assert_eq!(report.completed, completed, "batch {index}");
            let read = syncer.service().store().read().unwrap();
            assert_eq!(read.scan_cursor().unwrap().unwrap().height, expected);
            assert_eq!(read.scan_invalidated().unwrap(), !completed);
        }
        let requests = requests.lock().unwrap().clone();
        assert_eq!(requests, vec![(0, 4), (4, 4), (8, 4), (12, 4), (16, 4)]);
    }

    #[test]
    fn ancestor_rewinds_and_uses_returned_cursor() {
        let dir = tempfile::tempdir().unwrap();
        let tip = CommittedTip::new(3, [30; 32]);
        let store =
            Arc::new(RedbWalletStore::open_standalone(dir.path().join("wallet.redb")).unwrap());
        let mut write = store.begin_write().unwrap();
        write.prepare_rescan(0, true).unwrap();
        for height in 1..=3u32 {
            write
                .apply_rescan_block(
                    height,
                    &BTreeSet::new(),
                    &BTreeMap::new(),
                    &RescanBlock {
                        block_id: [height as u8; 32],
                        txs: Vec::new(),
                    },
                    None,
                )
                .unwrap();
        }
        write.finish_rescan(0).unwrap();
        write.commit().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
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
                        blocks: vec![
                            ChainBlock {
                                block_id: [21; 32],
                                height: 2,
                                parent_id: [1; 32],
                                transactions: Vec::new(),
                            },
                            ChainBlock {
                                block_id: [30; 32],
                                height: 3,
                                parent_id: [21; 32],
                                transactions: Vec::new(),
                            },
                        ],
                    },
                ),
            ])),
            tip_calls: Arc::new(Mutex::new(0)),
            requests: requests.clone(),
            dynamic: false,
        };
        let chain: Arc<dyn ChainClient> = Arc::new(FakeClient { state });
        let service = Arc::new(WalletService::new(store, chain.clone()));
        let syncer = StandaloneSyncer::new(
            service,
            SyncConfig {
                batch: 16,
                page: 16,
                retry_delay: Duration::ZERO,
                max_retry_delay: Duration::ZERO,
            },
            Arc::new(CachedNodeTip::new(chain)),
        );
        let report = syncer.sync_once().unwrap();
        assert_eq!(report.wallet_height, 3);
        assert_eq!(report.blocks_processed, 2);
        assert_eq!(requests.lock().unwrap().clone(), vec![(3, 1), (1, 3)]);
        assert_eq!(
            syncer
                .service()
                .store()
                .read()
                .unwrap()
                .scan_cursor()
                .unwrap()
                .unwrap()
                .header_id,
            Some([30; 32])
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
            let state = syncer
                .service()
                .store()
                .read()
                .unwrap()
                .rescan_state()
                .unwrap();
            assert!(matches!(state, RescanState::Failed { .. }));
        }
    }

    #[test]
    fn pruned_invalidates_and_persists_failed_state() {
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
        let read = syncer.service().store().read().unwrap();
        assert!(read.scan_invalidated().unwrap());
        assert!(matches!(
            read.rescan_state().unwrap(),
            RescanState::Failed { .. }
        ));
    }

    #[test]
    fn http_pruned_and_conflict_are_typed_and_retryable() {
        assert!(matches!(
            map_chain_error(ChainClientError::HistoryPruned {
                minimum_height: Some(7)
            }),
            SyncError::Pruned(7)
        ));
        assert!(SyncError::Chain(ChainClientError::Conflict).retryable());
        assert!(!SyncError::Pruned(7).retryable());
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
            requests: Arc::new(Mutex::new(Vec::new())),
            dynamic: false,
        };
        let chain: Arc<dyn ChainClient> = Arc::new(FakeClient { state });
        let service = Arc::new(WalletService::new(store, chain.clone()));
        let syncer = StandaloneSyncer::new(
            service,
            SyncConfig {
                batch: 16,
                page: 16,
                retry_delay: Duration::ZERO,
                max_retry_delay: Duration::ZERO,
            },
            Arc::new(CachedNodeTip::new(chain)),
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
        assert!(matches!(
            syncer
                .service()
                .store()
                .read()
                .unwrap()
                .rescan_state()
                .unwrap(),
            RescanState::Failed { .. }
        ));
        let report = syncer.sync_once().unwrap();
        assert!(report.completed);
    }
}
