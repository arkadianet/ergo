//! Full-chain rescan helper for /wallet/rescan.
//!
//! Iterates blocks from a start height up to the chain tip, replaying
//! `apply_block_to_wallet_rescan` for each block. Used when the operator
//! wants to rescan after restoring an existing wallet or after adding new
//! tracked pubkeys.
//!
//! Atomicity note: each block applies in its own write txn (NOT one txn
//! for the whole rescan). This avoids holding the redb write lock for
//! the duration of a long rescan, at the cost of partial-progress
//! visibility. Rescan progress is observable via WALLET_SCAN_HEIGHT.

#![allow(clippy::result_large_err)] // redb::Error shape is fixed upstream

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use ergo_primitives::reader::VlqReader;
use ergo_ser::ergo_box::read_ergo_box;
use redb::Database;

use thiserror::Error;

use crate::chain::CommittedTip;
use crate::scan::registry::{Scan, ScanRegistry};
use crate::wallet::error::WalletStoreError;
use crate::wallet::store::{RedbWalletStore, WalletStore};
use crate::wallet::tables::WALLET_SCAN_HEIGHT;
pub use crate::wallet::types::OwnedBlockOutput;

/// Matches a block's output boxes against registered scan rules during a
/// rescan. The chain integration supplies this matcher, mirroring the live
/// `WalletApplyHook::match_boxes` path.
pub trait ScanRescanMatcher {
    /// For each serialized output box (in block order, across all of the
    /// block's transactions), the ids of registered scans whose rule matches
    /// it. MUST return exactly one result per input box, in the same order.
    fn match_boxes(&self, boxes: &[&[u8]]) -> Result<Vec<Vec<u16>>, String>;
}

#[derive(Clone, Debug)]
pub struct WalletScanMatcher {
    registry: ScanRegistry,
}

impl WalletScanMatcher {
    pub fn empty() -> Self {
        Self {
            registry: ScanRegistry::new(),
        }
    }

    pub fn from_store(store: &dyn WalletStore) -> Result<Self, WalletStoreError> {
        let snapshot = store.read()?.scan_registry()?;
        let mut scans = Vec::with_capacity(snapshot.scans.len());
        let mut ids = BTreeSet::new();
        for stored in snapshot.scans {
            let scan: Scan = serde_json::from_slice(&stored.json).map_err(|error| {
                WalletStoreError::decode(format!("scan registry decode: {error}"))
            })?;
            scan.tracking_rule.validate().map_err(|error| {
                WalletStoreError::decode(format!("scan registry rule: {error}"))
            })?;
            if !ids.insert(scan.scan_id) {
                return Err(WalletStoreError::decode(format!(
                    "duplicate scan id {}",
                    scan.scan_id
                )));
            }
            if scan.scan_id <= crate::scan::registry::PAYMENTS_SCAN_ID {
                return Err(WalletStoreError::decode(format!(
                    "reserved or invalid scan id {}",
                    scan.scan_id
                )));
            }
            if scan.scan_id != stored.id {
                return Err(WalletStoreError::decode(format!(
                    "scan key {} does not match embedded id {}",
                    stored.id, scan.scan_id
                )));
            }
            scans.push(scan);
        }
        Ok(Self {
            registry: ScanRegistry::from_persisted(
                scans,
                snapshot
                    .last_used_id
                    .unwrap_or(crate::scan::registry::PAYMENTS_SCAN_ID),
            ),
        })
    }

    pub fn registry(&self) -> &ScanRegistry {
        &self.registry
    }
}

impl ScanRescanMatcher for WalletScanMatcher {
    fn match_boxes(&self, boxes: &[&[u8]]) -> Result<Vec<Vec<u16>>, String> {
        boxes
            .iter()
            .map(|bytes| {
                let mut reader = VlqReader::new(bytes);
                let ergo_box = read_ergo_box(&mut reader)
                    .map_err(|error| format!("output box parse failed: {error}"))?;
                if !reader.is_empty() {
                    return Err("output box has trailing data".to_string());
                }
                Ok(self.registry.matching_scan_ids(&ergo_box))
            })
            .collect()
    }
}

/// A failure while reading the chain data required by a wallet rescan.
#[derive(Debug, Error)]
pub enum RescanReadError {
    #[error("block data missing at height {height}")]
    Missing { height: u32 },
    #[error("block data corrupt at height {height}: {reason}")]
    Corrupt { height: u32, reason: String },
    #[error("block data storage failure at height {height}: {source}")]
    Storage {
        height: u32,
        #[source]
        source: WalletStoreError,
    },
    #[error("chain client failure at height {height}: {source}")]
    Chain {
        height: u32,
        #[source]
        source: crate::chain::ChainClientError,
    },
}

impl RescanReadError {
    pub fn storage(height: u32, source: impl Into<WalletStoreError>) -> Self {
        Self::Storage {
            height,
            source: source.into(),
        }
    }
}

/// A failure during a wallet rescan operation.
#[derive(Debug, Error)]
pub enum RescanError {
    #[error(transparent)]
    Read(#[from] RescanReadError),
    #[error("rescan cancelled at height {height}")]
    Cancelled { height: u32 },
    #[error("scan matcher failed at height {height}: {reason}")]
    Matcher { height: u32, reason: String },
    #[error("rescan storage failure: {0}")]
    Storage(#[source] redb::Error),
    #[error(
        "rescan tip changed from ({expected_height}, {expected_id}) to ({actual_height}, {actual_id})",
        expected_height = expected.height,
        expected_id = hex::encode(expected.header_id),
        actual_height = actual.height,
        actual_id = hex::encode(actual.header_id)
    )]
    TipChanged {
        expected: CommittedTip,
        actual: CommittedTip,
    },
    #[error("invalid positive rescan start {requested}; fromHeight=0 is required")]
    InvalidStart { requested: u32, cursor: Option<u32> },
    #[error("failed to persist scan invalidation after rescan failure: {source}")]
    Invalidation {
        #[source]
        source: WalletStoreError,
    },
}

impl From<redb::Error> for RescanError {
    fn from(error: redb::Error) -> Self {
        Self::Storage(error)
    }
}

impl From<WalletStoreError> for RescanError {
    fn from(error: WalletStoreError) -> Self {
        Self::Storage(redb::Error::from(error))
    }
}

macro_rules! impl_rescan_error_from {
    ($($error:ty),+ $(,)?) => {
        $(
            impl From<$error> for RescanError {
                fn from(error: $error) -> Self {
                    Self::Storage(error.into())
                }
            }
        )+
    };
}

impl_rescan_error_from!(
    redb::StorageError,
    redb::TableError,
    redb::DatabaseError,
    redb::TransactionError,
    redb::CommitError,
);

/// Service that drives a rescan against a chain-state read interface.
pub struct WalletScanService;

impl WalletScanService {
    pub fn validate_rescan_start(
        store: &dyn WalletStore,
        requested: u32,
        _tip_height: u32,
    ) -> Result<(), RescanError> {
        if requested > 0 && store.read()?.discovery_coverage()?.is_some() {
            return Err(RescanError::Matcher {
                height: requested,
                reason: "UTXO-discovered wallets require a full historical rebuild (fromHeight=0)"
                    .into(),
            });
        }
        if requested > 0 && store.read()?.scan_invalidated()? {
            return Err(RescanError::InvalidStart {
                requested,
                cursor: store.read()?.scan_cursor()?.map(|cursor| cursor.height),
            });
        }
        Ok(())
    }

    /// Full-rebuild (or range-scoped) rescan.
    ///
    /// When `start_height == 0`: full rebuild — clears WALLET_BOXES,
    /// WALLET_BOXES_BY_TX, and WALLET_TXS, sets WALLET_SCAN_INVALIDATED=true,
    /// resets WALLET_SCAN_HEIGHT=0, then replays all blocks in [1..=tip_height].
    /// Clears WALLET_SCAN_INVALIDATED at the end.
    ///
    /// When `start_height > 0`: range-scoped rebuild — deletes rows whose
    /// recorded height >= start_height, rewinds surviving rows whose state
    /// changed at/above start_height back to their pre-start_height status,
    /// rewinds WALLET_SCAN_HEIGHT to start_height-1, then replays
    /// [start_height..=tip_height]. Does NOT touch WALLET_SCAN_INVALIDATED.
    ///
    /// After the main replay, a catch-up loop re-reads the tip and replays
    /// any blocks that arrived during the rebuild, until steady state.
    ///
    /// `is_cancelled` is polled at every iteration boundary; returns true
    /// if rollback (or operator action) aborted the rescan.
    ///
    /// `scan_matcher` drives registered-`/scan/*` rebuild: when `Some` AND
    /// this is a full rebuild (`start_height == 0`), the scan tables
    /// (`WALLET_SCAN_BOXES` / `_INDEX` / `_TXS`) are cleared up front and
    /// rebuilt per block via the same `apply_block_to_scans` the live path
    /// uses — so a rescan reproduces live scan tracking exactly. `None` (a
    /// node with no registered scans) leaves the scan tables untouched. Scan
    /// rebuild is gated to the full-rebuild path because scans have no
    /// range-rewind semantics; a partial wallet rescan does not touch them.
    ///
    /// Returns the count of blocks processed.
    #[allow(clippy::too_many_arguments)]
    pub fn rescan_full_rebuild<F, T, C>(
        db: &Arc<Database>,
        tracked_p2pk_trees: BTreeSet<Vec<u8>>,
        cached_pubkeys: BTreeMap<u64, [u8; 33]>,
        start_height: u32,
        tip_height: u32,
        mut read_block: F,
        mut read_tip: T,
        mut is_cancelled: C,
        scan_matcher: Option<&dyn ScanRescanMatcher>,
    ) -> Result<u32, RescanError>
    where
        F: FnMut(u32) -> Result<Option<RescanBlock>, RescanReadError>,
        T: FnMut() -> Result<u32, RescanReadError>,
        C: FnMut() -> bool,
    {
        let store = RedbWalletStore::new(db.clone());
        Self::rescan_full_rebuild_store(
            &store,
            tracked_p2pk_trees,
            cached_pubkeys,
            start_height,
            tip_height,
            &mut read_block,
            &mut read_tip,
            &mut is_cancelled,
            scan_matcher,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn rescan_full_rebuild_store<F, T, C>(
        store: &dyn WalletStore,
        tracked_p2pk_trees: BTreeSet<Vec<u8>>,
        cached_pubkeys: BTreeMap<u64, [u8; 33]>,
        start_height: u32,
        tip_height: u32,
        mut read_block: F,
        mut read_tip: T,
        mut is_cancelled: C,
        scan_matcher: Option<&dyn ScanRescanMatcher>,
    ) -> Result<u32, RescanError>
    where
        F: FnMut(u32) -> Result<Option<RescanBlock>, RescanReadError>,
        T: FnMut() -> Result<u32, RescanReadError>,
        C: FnMut() -> bool,
    {
        let start_height = start_height.min(tip_height);
        Self::validate_rescan_start(store, start_height, tip_height)?;
        if start_height > 0 && read_block(start_height)?.is_none() {
            return Err(RescanError::Read(RescanReadError::Missing {
                height: start_height,
            }));
        }
        Self::rescan_full_rebuild_dyn_store(
            store,
            tracked_p2pk_trees,
            cached_pubkeys,
            start_height,
            tip_height,
            &mut read_block,
            &mut read_tip,
            &mut is_cancelled,
            scan_matcher,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn rescan_bounded_store<F, T, C, P>(
        store: &dyn WalletStore,
        tracked_p2pk_trees: BTreeSet<Vec<u8>>,
        cached_pubkeys: BTreeMap<u64, [u8; 33]>,
        start_height: u32,
        initial_tip: CommittedTip,
        mut read_block: F,
        mut read_tip: T,
        mut is_cancelled: C,
        scan_matcher: Option<&dyn ScanRescanMatcher>,
        max_blocks_per_batch: u32,
        mut on_batch: P,
    ) -> Result<u32, RescanError>
    where
        F: FnMut(u32) -> Result<Option<RescanBlock>, RescanReadError>,
        T: FnMut() -> Result<CommittedTip, RescanReadError>,
        C: FnMut() -> bool,
        P: FnMut(u32, CommittedTip) -> Result<(), RescanError>,
    {
        if max_blocks_per_batch == 0 {
            return Err(RescanError::InvalidStart {
                requested: start_height,
                cursor: None,
            });
        }
        let start_height = start_height.min(initial_tip.height);
        Self::validate_rescan_start(store, start_height, initial_tip.height)?;
        let invalidation_guard = InvalidateOnError::new(store);
        let result = Self::rescan_bounded_dyn_store_inner(
            store,
            tracked_p2pk_trees,
            cached_pubkeys,
            start_height,
            initial_tip,
            &mut read_block,
            &mut read_tip,
            &mut is_cancelled,
            scan_matcher,
            max_blocks_per_batch,
            &mut on_batch,
        );
        invalidation_guard.finish(result)
    }

    #[allow(clippy::too_many_arguments)]
    fn rescan_bounded_dyn_store_inner<F, T, C, P>(
        store: &dyn WalletStore,
        tracked_p2pk_trees: BTreeSet<Vec<u8>>,
        cached_pubkeys: BTreeMap<u64, [u8; 33]>,
        start_height: u32,
        initial_tip: CommittedTip,
        read_block: &mut F,
        read_tip: &mut T,
        is_cancelled: &mut C,
        scan_matcher: Option<&dyn ScanRescanMatcher>,
        max_blocks_per_batch: u32,
        on_batch: &mut P,
    ) -> Result<u32, RescanError>
    where
        F: FnMut(u32) -> Result<Option<RescanBlock>, RescanReadError>,
        T: FnMut() -> Result<CommittedTip, RescanReadError>,
        C: FnMut() -> bool,
        P: FnMut(u32, CommittedTip) -> Result<(), RescanError>,
    {
        if is_cancelled() {
            return Err(RescanError::Cancelled {
                height: start_height,
            });
        }
        let mut write = WalletStore::begin_write(store)?;
        if is_cancelled() {
            return Err(RescanError::Cancelled {
                height: start_height,
            });
        }
        write.prepare_rescan(start_height, scan_matcher.is_some() && start_height == 0)?;
        write.commit()?;

        let scan_rebuild = scan_matcher.is_some() && start_height == 0;
        let mut current_height = start_height.saturating_sub(1);
        let mut target_tip = initial_tip;
        let mut processed = 0u32;
        loop {
            if current_height < target_tip.height {
                let first_height = current_height.saturating_add(1);
                let available = target_tip
                    .height
                    .saturating_sub(first_height)
                    .saturating_add(1);
                let batch_count = available.min(max_blocks_per_batch);
                let batch_end = first_height.saturating_add(batch_count.saturating_sub(1));
                for height in first_height..=batch_end {
                    if is_cancelled() {
                        return Err(RescanError::Cancelled { height });
                    }
                    let block = read_block(height)?
                        .ok_or(RescanError::Read(RescanReadError::Missing { height }))?;
                    let scan_records = if scan_rebuild {
                        let matcher = scan_matcher.expect("scan rebuild requires a matcher");
                        let mut box_refs: Vec<&[u8]> = Vec::new();
                        let mut box_meta = Vec::new();
                        for tx in &block.txs {
                            for output in &tx.outputs {
                                box_refs.push(&output.box_bytes);
                                box_meta.push((output.box_id, output.output_index));
                            }
                        }
                        let matches = matcher
                            .match_boxes(&box_refs)
                            .map_err(|reason| RescanError::Matcher { height, reason })?;
                        if matches.len() != box_refs.len() {
                            return Err(RescanError::Matcher {
                                height,
                                reason: format!(
                                    "wrong result count: got {}, want {}",
                                    matches.len(),
                                    box_refs.len()
                                ),
                            });
                        }
                        Some(
                            box_meta
                                .into_iter()
                                .zip(matches)
                                .zip(box_refs)
                                .filter(|((_, scan_ids), _)| !scan_ids.is_empty())
                                .map(|(((box_id, out_idx), scan_ids), bytes)| {
                                    crate::wallet::types::ScanMatchRecord {
                                        box_id,
                                        scan_ids,
                                        box_bytes: bytes.to_vec(),
                                        inclusion_height: height,
                                        creation_out_index: out_idx,
                                    }
                                })
                                .collect::<Vec<_>>(),
                        )
                    } else {
                        None
                    };
                    let mut write = WalletStore::begin_write(store)?;
                    if is_cancelled() {
                        return Err(RescanError::Cancelled { height });
                    }
                    write.apply_rescan_block(
                        height,
                        &tracked_p2pk_trees,
                        &cached_pubkeys,
                        &block,
                        scan_records.as_deref(),
                    )?;
                    write.commit()?;
                    processed = processed.saturating_add(1);
                }
                current_height = batch_end;
                on_batch(batch_end, target_tip.clone())?;
            }

            if is_cancelled() {
                return Err(RescanError::Cancelled {
                    height: current_height,
                });
            }
            let observed_tip = read_tip()?;
            if observed_tip.height < target_tip.height {
                return Err(RescanError::Cancelled {
                    height: current_height,
                });
            }
            if observed_tip.height == target_tip.height
                && observed_tip.header_id != target_tip.header_id
            {
                return Err(RescanError::TipChanged {
                    expected: target_tip,
                    actual: observed_tip,
                });
            }
            if observed_tip.height > target_tip.height {
                target_tip = observed_tip;
                continue;
            }
            if current_height < observed_tip.height {
                target_tip = observed_tip;
                continue;
            }
            if is_cancelled() {
                return Err(RescanError::Cancelled {
                    height: current_height,
                });
            }
            let mut write = WalletStore::begin_write(store)?;
            if is_cancelled() {
                return Err(RescanError::Cancelled {
                    height: current_height,
                });
            }
            write.finish_rescan(start_height)?;
            write.commit()?;
            return Ok(processed);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn rescan_full_rebuild_dyn_store<F, T, C>(
        store: &dyn WalletStore,
        tracked_p2pk_trees: BTreeSet<Vec<u8>>,
        cached_pubkeys: BTreeMap<u64, [u8; 33]>,
        start_height: u32,
        tip_height: u32,
        read_block: &mut F,
        read_tip: &mut T,
        is_cancelled: &mut C,
        scan_matcher: Option<&dyn ScanRescanMatcher>,
    ) -> Result<u32, RescanError>
    where
        F: FnMut(u32) -> Result<Option<RescanBlock>, RescanReadError>,
        T: FnMut() -> Result<u32, RescanReadError>,
        C: FnMut() -> bool,
    {
        let invalidation_guard = InvalidateOnError::new(store);
        let result = Self::rescan_full_rebuild_dyn_store_inner(
            store,
            tracked_p2pk_trees,
            cached_pubkeys,
            start_height,
            tip_height,
            read_block,
            read_tip,
            is_cancelled,
            scan_matcher,
        );
        invalidation_guard.finish(result)
    }

    #[allow(clippy::too_many_arguments)]
    fn rescan_full_rebuild_dyn_store_inner<F, T, C>(
        store: &dyn WalletStore,
        tracked_p2pk_trees: BTreeSet<Vec<u8>>,
        cached_pubkeys: BTreeMap<u64, [u8; 33]>,
        start_height: u32,
        tip_height: u32,
        read_block: &mut F,
        read_tip: &mut T,
        is_cancelled: &mut C,
        scan_matcher: Option<&dyn ScanRescanMatcher>,
    ) -> Result<u32, RescanError>
    where
        F: FnMut(u32) -> Result<Option<RescanBlock>, RescanReadError>,
        T: FnMut() -> Result<u32, RescanReadError>,
        C: FnMut() -> bool,
    {
        // Registered-scan rebuild only on a full rebuild (scans have no
        // range-rewind path). `None` matcher = a node with no scans.
        let scan_rebuild = scan_matcher.is_some() && start_height == 0;

        if is_cancelled() {
            return Err(RescanError::Cancelled {
                height: start_height,
            });
        }
        let mut write = WalletStore::begin_write(store)?;
        if is_cancelled() {
            return Err(RescanError::Cancelled {
                height: start_height,
            });
        }
        write.prepare_rescan(start_height, scan_rebuild)?;
        write.commit()?;

        // STEP 2: replay block-by-block with maturity promotion per block.
        // Catch-up loop: after the main replay, re-read tip and replay any
        // blocks that arrived during the rebuild.
        let mut processed = 0u32;
        let mut current_target = tip_height;
        let mut current_start = start_height.max(1);

        loop {
            for h in current_start..=current_target {
                // Per-block cancellation check.
                if is_cancelled() {
                    return Err(RescanError::Cancelled { height: h });
                }
                let block = match read_block(h)? {
                    Some(b) => b,
                    None => {
                        return Err(RescanError::Read(RescanReadError::Missing { height: h }));
                    }
                };
                let scan_records: Option<Vec<crate::wallet::types::ScanMatchRecord>> =
                    if let Some(matcher) = scan_matcher.filter(|_| scan_rebuild) {
                        let mut box_refs: Vec<&[u8]> = Vec::new();
                        let mut box_meta: Vec<([u8; 32], u16)> = Vec::new();
                        for tx in &block.txs {
                            for o in &tx.outputs {
                                box_refs.push(&o.box_bytes);
                                box_meta.push((o.box_id, o.output_index));
                            }
                        }
                        let matches = matcher
                            .match_boxes(&box_refs)
                            .map_err(|reason| RescanError::Matcher { height: h, reason })?;
                        if matches.len() != box_refs.len() {
                            return Err(RescanError::Matcher {
                                height: h,
                                reason: format!(
                                    "wrong result count: got {}, want {}",
                                    matches.len(),
                                    box_refs.len()
                                ),
                            });
                        }
                        Some(
                            box_meta
                                .into_iter()
                                .zip(matches)
                                .zip(box_refs)
                                .filter(|((_, scan_ids), _)| !scan_ids.is_empty())
                                .map(|(((box_id, out_idx), scan_ids), bytes)| {
                                    crate::wallet::types::ScanMatchRecord {
                                        box_id,
                                        scan_ids,
                                        box_bytes: bytes.to_vec(),
                                        inclusion_height: h,
                                        creation_out_index: out_idx,
                                    }
                                })
                                .collect(),
                        )
                    } else {
                        None
                    };
                let mut write = WalletStore::begin_write(store)?;
                if is_cancelled() {
                    return Err(RescanError::Cancelled { height: h });
                }
                write.apply_rescan_block(
                    h,
                    &tracked_p2pk_trees,
                    &cached_pubkeys,
                    &block,
                    scan_records.as_deref(),
                )?;
                write.commit()?;
                processed += 1;
            }

            // Cancellation check at catch-up boundary.
            if is_cancelled() {
                return Err(RescanError::Cancelled {
                    height: current_target,
                });
            }
            let new_target = read_tip()?;
            if new_target < current_target {
                return Err(RescanError::Cancelled {
                    height: current_target,
                });
            }
            if new_target > current_target {
                current_start = current_target + 1;
                current_target = new_target;
                continue;
            }

            if is_cancelled() {
                return Err(RescanError::Cancelled {
                    height: current_target,
                });
            }
            let mut write = WalletStore::begin_write(store)?;
            if is_cancelled() {
                return Err(RescanError::Cancelled {
                    height: current_target,
                });
            }
            write.finish_rescan(start_height)?;
            write.commit()?;
            return Ok(processed);
        }
    }

    /// Read the current scan height from `WALLET_SCAN_HEIGHT`.
    /// Returns 0 if the table doesn't exist yet (fresh wallet).
    pub fn current_scan_height(db: &Database) -> Result<u32, redb::Error> {
        let txn = crate::wallet::store::read_redb(db)?;
        let tbl = match txn.open_table(WALLET_SCAN_HEIGHT) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(0),
            Err(e) => return Err(e.into()),
        };
        Ok(tbl.get(())?.map(|g| g.value()).unwrap_or(0))
    }
}

struct InvalidateOnError<'a> {
    store: &'a dyn WalletStore,
    armed: bool,
}
impl<'a> InvalidateOnError<'a> {
    fn new(store: &'a dyn WalletStore) -> Self {
        Self { store, armed: true }
    }
    fn disarm(&mut self) {
        self.armed = false;
    }

    fn finish(mut self, result: Result<u32, RescanError>) -> Result<u32, RescanError> {
        let original_error = match result {
            Ok(processed) => {
                self.disarm();
                return Ok(processed);
            }
            Err(error) => error,
        };
        match self.store.persist_scan_invalidation(true) {
            Ok(()) => {
                self.disarm();
                Err(original_error)
            }
            Err(error) => {
                // A poisoned database can also fail the invalidation write.
                // Preserve the read/storage failure that explains that state.
                // For other failures, report that invalidation was not durable.
                if matches!(
                    &original_error,
                    RescanError::Storage(_) | RescanError::Read(RescanReadError::Storage { .. })
                ) {
                    tracing::error!(%error, "failed to persist rescan invalidation; preserving original storage error");
                    Err(original_error)
                } else {
                    Err(RescanError::Invalidation { source: error })
                }
            }
        }
    }
}
impl Drop for InvalidateOnError<'_> {
    fn drop(&mut self) {
        if self.armed {
            if let Err(error) = self.store.persist_scan_invalidation(true) {
                tracing::error!(%error, "wallet rescan: failed to persist scan invalidation");
            }
        }
    }
}

// --- public types ---

/// Block snapshot passed to `read_block` during rescan. Owns all its
/// data so the integrator's closure doesn't need to hold redb read
/// locks across block iterations.
#[derive(Clone)]
pub struct RescanBlock {
    pub block_id: [u8; 32],
    pub txs: Vec<RescanTx>,
}

/// Transaction snapshot inside a `RescanBlock`. Uses owned byte vecs
/// for the ErgoTree bytes so the lifetime is self-contained.
#[derive(Clone)]
pub struct RescanTx {
    pub tx_id: [u8; 32],
    pub inputs: Vec<[u8; 32]>,
    pub outputs: Vec<OwnedBlockOutput>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::store::{
        RedbWalletStore, WalletRead, WalletStore, WalletStoreError, WalletWrite,
    };
    use redb::Database;
    use std::sync::Arc;

    struct FailingInvalidationStore {
        inner: RedbWalletStore,
    }

    impl WalletStore for FailingInvalidationStore {
        fn begin_read(&self) -> Result<Box<dyn WalletRead>, WalletStoreError> {
            self.inner.begin_read()
        }

        fn begin_write(&self) -> Result<Box<dyn WalletWrite>, WalletStoreError> {
            self.inner.begin_write()
        }

        fn persist_scan_invalidation(&self, _invalidated: bool) -> Result<(), WalletStoreError> {
            Err(WalletStoreError::Decode("injected failure".to_string()))
        }
    }

    #[test]
    fn rescan_replays_a_tip_observed_during_finalization() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::create(dir.path().join("state.redb")).unwrap());
        let store = RedbWalletStore::new(db);
        let mut tip_reads = 0;
        let result = WalletScanService::rescan_full_rebuild_store(
            &store,
            BTreeSet::new(),
            BTreeMap::new(),
            0,
            0,
            |height| {
                Ok(Some(RescanBlock {
                    block_id: [height as u8; 32],
                    txs: Vec::new(),
                }))
            },
            || {
                tip_reads += 1;
                Ok(1)
            },
            || false,
            None,
        );
        assert_eq!(result.unwrap(), 1);
        assert_eq!(tip_reads, 2);
        assert_eq!(
            store.read().unwrap().scan_cursor().unwrap().unwrap().height,
            1
        );
        assert!(!store.read().unwrap().scan_invalidated().unwrap());
    }

    #[test]
    fn rescan_rejects_tip_regression_during_finalization() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::create(dir.path().join("state.redb")).unwrap());
        let store = RedbWalletStore::new(db);
        let result = WalletScanService::rescan_full_rebuild_store(
            &store,
            BTreeSet::new(),
            BTreeMap::new(),
            0,
            1,
            |height| {
                Ok(Some(RescanBlock {
                    block_id: [height as u8; 32],
                    txs: Vec::new(),
                }))
            },
            || Ok(0),
            || false,
            None,
        );
        assert!(matches!(result, Err(RescanError::Cancelled { height: 1 })));
        assert!(store.read().unwrap().scan_invalidated().unwrap());
    }

    #[test]
    fn partial_rescan_from_tip_minus_two_replays_exactly_three_blocks() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::create(dir.path().join("state.redb")).unwrap());
        let txn = db.begin_write().unwrap();
        for height in 1..=5u32 {
            txn.open_table(crate::wallet::tables::CHAIN_INDEX)
                .unwrap()
                .insert(height as u64, [height as u8; 32].as_slice())
                .unwrap();
        }
        txn.commit().unwrap();
        let store = RedbWalletStore::new(db);
        let mut write = store.begin_write().unwrap();
        write.set_scan_cursor(5, Some(&[5; 32])).unwrap();
        write.commit().unwrap();
        let mut replayed = Vec::new();
        let count = WalletScanService::rescan_full_rebuild_store(
            &store,
            BTreeSet::new(),
            BTreeMap::new(),
            3,
            5,
            |height| {
                replayed.push(height);
                Ok(Some(RescanBlock {
                    block_id: [height as u8; 32],
                    txs: vec![],
                }))
            },
            || Ok(5),
            || false,
            None,
        )
        .unwrap();
        assert_eq!(count, 3);
        // The first read checks availability before mutating wallet state.
        assert_eq!(replayed, vec![3, 3, 4, 5]);
        assert_eq!(
            store.read().unwrap().scan_cursor().unwrap().unwrap().height,
            5
        );
        assert!(!store.read().unwrap().scan_invalidated().unwrap());
    }

    #[test]
    fn positive_rescan_probes_start_before_prepare() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::create(dir.path().join("state.redb")).unwrap());
        let store = RedbWalletStore::new(db);
        let mut write = store.begin_write().unwrap();
        write.set_scan_cursor(0, None).unwrap();
        write.commit().unwrap();
        let mut tip_read = false;

        let result = WalletScanService::rescan_full_rebuild_store(
            &store,
            BTreeSet::new(),
            BTreeMap::new(),
            1,
            1,
            |height| {
                assert_eq!(height, 1);
                Ok(None)
            },
            || {
                tip_read = true;
                Ok(1)
            },
            || false,
            None,
        );

        assert!(matches!(
            result,
            Err(RescanError::Read(RescanReadError::Missing { height: 1 }))
        ));
        assert!(!tip_read);
        assert_eq!(
            store.read().unwrap().scan_cursor().unwrap().unwrap().height,
            0
        );
    }

    #[test]
    fn invalidation_failure_is_returned_as_a_distinct_rescan_error() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::create(dir.path().join("state.redb")).unwrap());
        let store = FailingInvalidationStore {
            inner: RedbWalletStore::new(db),
        };
        let result = WalletScanService::rescan_full_rebuild_store(
            &store,
            BTreeSet::new(),
            BTreeMap::new(),
            0,
            0,
            |_height| Ok(None),
            || Ok(0),
            || true,
            None,
        );
        assert!(matches!(result, Err(RescanError::Invalidation { .. })));
    }

    #[test]
    fn bounded_rescan_reports_invalidation_failure_after_cancellation() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::create(dir.path().join("state.redb")).unwrap());
        let store = FailingInvalidationStore {
            inner: RedbWalletStore::new(db),
        };
        let result = WalletScanService::rescan_bounded_store(
            &store,
            BTreeSet::new(),
            BTreeMap::new(),
            0,
            CommittedTip::new(1, [1; 32]),
            |_height| panic!("cancelled rescan must not read a block"),
            || panic!("cancelled rescan must not read the tip"),
            || true,
            None,
            1,
            |_, _| panic!("cancelled rescan must not publish progress"),
        );
        assert!(matches!(
            result,
            Err(RescanError::Invalidation {
                source: WalletStoreError::Decode(message),
            }) if message == "injected failure"
        ));
        assert_eq!(store.read().unwrap().scan_cursor().unwrap(), None);
    }

    #[test]
    fn invalidation_failure_preserves_original_block_storage_error() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::create(dir.path().join("state.redb")).unwrap());
        let store = FailingInvalidationStore {
            inner: RedbWalletStore::new(db),
        };
        let result = WalletScanService::rescan_full_rebuild_store(
            &store,
            BTreeSet::new(),
            BTreeMap::new(),
            0,
            1,
            |height| {
                Err(RescanReadError::storage(
                    height,
                    WalletStoreError::Decode("original block read failure".to_string()),
                ))
            },
            || Ok(1),
            || false,
            None,
        );
        assert!(matches!(
            result,
            Err(RescanError::Read(RescanReadError::Storage {
                height: 1,
                source: WalletStoreError::Decode(message),
            })) if message == "original block read failure"
        ));
    }
}

#[cfg(test)]
mod main_safety_tests {
    use super::*;
    use crate::wallet::apply::set_scan_cursor;
    use crate::wallet::tables::{
        WALLET_BOXES, WALLET_BOXES_BY_TX, WALLET_BOX_BYTES, WALLET_SCAN_HEIGHT,
        WALLET_SCAN_INVALIDATED, WALLET_TXS,
    };
    use redb::ReadableTable;
    use std::cell::Cell;

    // ----- helpers -----

    fn database() -> (tempfile::TempDir, Arc<Database>) {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::create(dir.path().join("rescan.redb")).unwrap());
        (dir, db)
    }

    fn empty_block() -> RescanBlock {
        RescanBlock {
            block_id: [1; 32],
            txs: vec![],
        }
    }

    fn invalidated(db: &Database) -> bool {
        crate::wallet::store::read_redb(db)
            .unwrap()
            .open_table(WALLET_SCAN_INVALIDATED)
            .unwrap()
            .get(())
            .unwrap()
            .unwrap()
            .value()
    }

    fn tracked_block(height: u32) -> Option<RescanBlock> {
        (height == 1).then(|| RescanBlock {
            block_id: [1; 32],
            txs: vec![RescanTx {
                tx_id: [2; 32],
                inputs: vec![],
                outputs: vec![OwnedBlockOutput {
                    box_id: [3; 32],
                    output_index: 0,
                    ergo_tree_bytes: vec![0, 8, 205],
                    value: 1_000_000,
                    assets: vec![],
                    miner_reward_pubkey: None,
                    box_bytes: vec![4; 32],
                }],
            }],
        })
    }

    fn assert_wallet_tables_unchanged(before: &redb::ReadTransaction, db: &Database) {
        let after = crate::wallet::store::read_redb(db).unwrap();
        macro_rules! assert_table_unchanged {
            ($table:expr) => {{
                let rows = |read: &redb::ReadTransaction| {
                    read.open_table($table)
                        .unwrap()
                        .iter()
                        .unwrap()
                        .map(|entry| {
                            let (key, value) = entry.unwrap();
                            (key.value(), value.value())
                        })
                        .collect::<Vec<_>>()
                };
                assert_eq!(rows(before), rows(&after), "{}", stringify!($table));
            }};
        }
        assert_table_unchanged!(WALLET_BOXES);
        assert_table_unchanged!(WALLET_BOX_BYTES);
        assert_table_unchanged!(WALLET_BOXES_BY_TX);
        assert_table_unchanged!(WALLET_TXS);
        assert_table_unchanged!(WALLET_SCAN_HEIGHT);
        assert_table_unchanged!(crate::wallet::tables::WALLET_SCAN_HEADER_ID);
    }

    fn assert_cancelled_rebuild_preserves_tables(start_height: u32) {
        let (_dir, db) = database();
        WalletScanService::rescan_full_rebuild(
            &db,
            BTreeSet::from([vec![0, 8, 205]]),
            BTreeMap::new(),
            0,
            1,
            |height| Ok(tracked_block(height)),
            || Ok(1),
            || false,
            None,
        )
        .unwrap();
        let before = crate::wallet::store::read_redb(&db).unwrap();
        assert!(before
            .open_table(WALLET_BOXES)
            .unwrap()
            .get([3; 32])
            .unwrap()
            .is_some());
        let cancelled = Cell::new(false);
        let result = WalletScanService::rescan_full_rebuild(
            &db,
            BTreeSet::from([vec![0, 8, 205]]),
            BTreeMap::new(),
            start_height,
            1,
            |height| Ok(tracked_block(height)),
            || Ok(1),
            || {
                let observed = cancelled.get();
                if !observed {
                    // Cancellation commits after the entry check's snapshot,
                    // before the rebuild acquires its writer transaction.
                    let txn = db.begin_write().unwrap();
                    cancelled.set(true);
                    txn.open_table(WALLET_SCAN_INVALIDATED)
                        .unwrap()
                        .insert((), true)
                        .unwrap();
                    txn.commit().unwrap();
                }
                observed
            },
            None,
        );
        assert_wallet_tables_unchanged(&before, &db);
        assert!(matches!(result, Err(RescanError::Cancelled { height }) if height == start_height));
        assert!(invalidated(&db));
    }

    #[derive(Debug)]
    struct ReadFaultBackend {
        inner: redb::backends::FileBackend,
        reads: Arc<std::sync::Mutex<Option<Vec<u64>>>>,
        fail_offset: Arc<std::sync::atomic::AtomicU64>,
    }

    impl redb::StorageBackend for ReadFaultBackend {
        fn len(&self) -> std::io::Result<u64> {
            self.inner.len()
        }
        fn read(&self, offset: u64, out: &mut [u8]) -> std::io::Result<()> {
            use std::sync::atomic::Ordering;
            if let Some(reads) = self.reads.lock().unwrap().as_mut() {
                reads.push(offset);
            }
            if self
                .fail_offset
                .compare_exchange(offset, u64::MAX, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return Err(std::io::Error::other(
                    "injected transaction-row read failure",
                ));
            }
            self.inner.read(offset, out)
        }
        fn set_len(&self, len: u64) -> std::io::Result<()> {
            self.inner.set_len(len)
        }
        fn sync_data(&self) -> std::io::Result<()> {
            self.inner.sync_data()
        }
        fn write(&self, offset: u64, data: &[u8]) -> std::io::Result<()> {
            self.inner.write(offset, data)
        }
        fn close(&self) -> std::io::Result<()> {
            self.inner.close()
        }
        fn try_lock_range(
            &self,
            start: std::ops::Bound<u64>,
            end: std::ops::Bound<u64>,
        ) -> Result<bool, redb::BackendError> {
            self.inner.try_lock_range(start, end)
        }
        fn try_lock_shared_range(
            &self,
            start: std::ops::Bound<u64>,
            end: std::ops::Bound<u64>,
        ) -> Result<bool, redb::BackendError> {
            self.inner.try_lock_shared_range(start, end)
        }
        fn lock_range(
            &self,
            start: std::ops::Bound<u64>,
            end: std::ops::Bound<u64>,
        ) -> Result<(), redb::BackendError> {
            self.inner.lock_range(start, end)
        }
        fn lock_shared_range(
            &self,
            start: std::ops::Bound<u64>,
            end: std::ops::Bound<u64>,
        ) -> Result<(), redb::BackendError> {
            self.inner.lock_shared_range(start, end)
        }
        fn unlock_range(
            &self,
            start: std::ops::Bound<u64>,
            end: std::ops::Bound<u64>,
        ) -> Result<(), redb::BackendError> {
            self.inner.unlock_range(start, end)
        }
        fn query_lock_range(
            &self,
            start: std::ops::Bound<u64>,
            end: std::ops::Bound<u64>,
        ) -> Result<bool, redb::BackendError> {
            self.inner.query_lock_range(start, end)
        }
    }

    // ----- happy path -----

    #[test]
    fn partial_rescan_success_preserves_invalidation() {
        for initial in [false, true] {
            let (_dir, db) = database();
            let txn = db.begin_write().unwrap();
            txn.open_table(WALLET_SCAN_INVALIDATED)
                .unwrap()
                .insert((), initial)
                .unwrap();
            txn.commit().unwrap();
            let result = WalletScanService::rescan_full_rebuild(
                &db,
                BTreeSet::new(),
                BTreeMap::new(),
                1,
                1,
                |_| Ok(Some(empty_block())),
                || Ok(1),
                || false,
                None,
            );
            if initial {
                assert!(matches!(result, Err(RescanError::InvalidStart { .. })));
            } else {
                assert_eq!(result.unwrap(), 1);
            }
            assert_eq!(invalidated(&db), initial);
        }
    }

    // ----- error paths -----

    #[test]
    fn rescan_cancel_under_block_writer_lock_commits_nothing_for_that_block() {
        let (_dir, db) = database();
        let cancelled = Cell::new(false);
        let mut before = None;
        let result = WalletScanService::rescan_full_rebuild(
            &db,
            BTreeSet::from([vec![0, 8, 205]]),
            BTreeMap::new(),
            0,
            1,
            |height| {
                assert_eq!(height, 1);
                before = Some(crate::wallet::store::read_redb(&db).unwrap());
                // The unlocked per-block check has passed. Rollback owns
                // the writer lock when it cancels the rescan.
                let txn = db.begin_write().unwrap();
                cancelled.set(true);
                txn.open_table(WALLET_SCAN_INVALIDATED)
                    .unwrap()
                    .insert((), true)
                    .unwrap();
                txn.commit().unwrap();
                Ok(tracked_block(height))
            },
            || Ok(1),
            || cancelled.get(),
            None,
        );
        assert!(matches!(result, Err(RescanError::Cancelled { height: 1 })));
        assert_wallet_tables_unchanged(&before.unwrap(), &db);
        assert_eq!(WalletScanService::current_scan_height(&db).unwrap(), 0);
        assert!(invalidated(&db));
    }

    #[test]
    fn rescan_cancel_under_full_rebuild_writer_lock_leaves_tables_untouched() {
        assert_cancelled_rebuild_preserves_tables(0);
    }

    #[test]
    fn rescan_cancel_under_range_rebuild_writer_lock_leaves_tables_untouched() {
        assert_cancelled_rebuild_preserves_tables(1);
    }

    #[test]
    fn full_rebuild_unreadable_transaction_row_preserves_original_error() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rescan.redb");
        let reads = Arc::new(std::sync::Mutex::new(None));
        let fail_offset = Arc::new(AtomicU64::new(u64::MAX));
        let db = Arc::new(
            Database::builder()
                .set_cache_size(0)
                .create_with_backend(ReadFaultBackend {
                    inner: redb::backends::FileBackend::new(
                        std::fs::OpenOptions::new()
                            .read(true)
                            .write(true)
                            .create_new(true)
                            .open(&path)
                            .unwrap(),
                    )
                    .unwrap(),
                    reads: reads.clone(),
                    fail_offset: fail_offset.clone(),
                })
                .unwrap(),
        );
        let txn = db.begin_write().unwrap();
        {
            let mut table = txn.open_table(WALLET_TXS).unwrap();
            for index in 0u32..512 {
                let mut key = [0; 36];
                key[..4].copy_from_slice(&index.to_be_bytes());
                table.insert(key, vec![0; 128]).unwrap();
            }
        }
        // A recovery rescan starts with durable invalidation already set.
        txn.open_table(WALLET_SCAN_INVALIDATED)
            .unwrap()
            .insert((), true)
            .unwrap();
        set_scan_cursor(&txn, 7, Some(&[7; 32])).unwrap();
        txn.commit().unwrap();

        // Find a leaf-page read caused by advancing the iterator, after its
        // construction has already loaded the first and last pages.
        let offset = {
            let txn = crate::wallet::store::read_redb(&db).unwrap();
            let table = txn.open_table(WALLET_TXS).unwrap();
            let iter = table.iter().unwrap();
            *reads.lock().unwrap() = Some(Vec::new());
            let mut offset = None;
            for entry in iter {
                entry.unwrap();
                if let Some(first) = reads.lock().unwrap().as_ref().unwrap().first() {
                    offset = Some(*first);
                    break;
                }
            }
            *reads.lock().unwrap() = None;
            offset.expect("transaction rows must span multiple leaf pages")
        };
        fail_offset.store(offset, Ordering::SeqCst);
        let result = WalletScanService::rescan_full_rebuild(
            &db,
            BTreeSet::new(),
            BTreeMap::new(),
            0,
            1,
            |_| Ok(Some(empty_block())),
            || Ok(1),
            || false,
            None,
        );
        let error = result.unwrap_err();
        assert!(matches!(error, RescanError::Storage(_)), "{error:?}");
        assert!(
            error
                .to_string()
                .contains("injected transaction-row read failure"),
            "{error}"
        );
        assert_eq!(
            fail_offset.load(Ordering::SeqCst),
            u64::MAX,
            "fault must fire"
        );
        // redb poisons the handle on I/O failure. Reopen to inspect the last
        // durable commit; the failed clear transaction must not publish rows.
        drop(db);
        let db = Database::open(&path).unwrap();
        assert!(invalidated(&db));
        assert_eq!(WalletScanService::current_scan_height(&db).unwrap(), 7);
        assert_eq!(
            crate::wallet::store::read_redb(&db)
                .unwrap()
                .open_table(WALLET_TXS)
                .unwrap()
                .iter()
                .unwrap()
                .count(),
            512
        );
    }

    #[test]
    fn rescan_mid_loop_cancellation_invalidates() {
        let (_dir, db) = database();
        let txn = db.begin_write().unwrap();
        txn.open_table(WALLET_SCAN_INVALIDATED)
            .unwrap()
            .insert((), false)
            .unwrap();
        txn.commit().unwrap();
        let cancelled = Cell::new(false);
        let result = WalletScanService::rescan_full_rebuild(
            &db,
            BTreeSet::new(),
            BTreeMap::new(),
            1,
            2,
            |height| {
                assert_eq!(height, 1);
                cancelled.set(true);
                Ok(Some(empty_block()))
            },
            || Ok(2),
            || cancelled.get(),
            None,
        );
        assert!(matches!(result, Err(RescanError::Cancelled { .. })));
        assert!(invalidated(&db));
    }

    #[test]
    fn rescan_rollback_before_final_write_preserves_invalidation() {
        let (_dir, db) = database();
        let reached_tip = Cell::new(false);
        let cancelled = Cell::new(false);
        let result = WalletScanService::rescan_full_rebuild(
            &db,
            BTreeSet::new(),
            BTreeMap::new(),
            0,
            1,
            |height| Ok((height == 1).then(empty_block)),
            || {
                reached_tip.set(true);
                Ok(1)
            },
            || {
                let observed = cancelled.get();
                if reached_tip.get() && !observed {
                    // Commit rollback invalidation after the last unlocked check
                    // took its snapshot, before the rescan acquires the writer.
                    let txn = db.begin_write().unwrap();
                    cancelled.set(true);
                    txn.open_table(WALLET_SCAN_INVALIDATED)
                        .unwrap()
                        .insert((), true)
                        .unwrap();
                    txn.commit().unwrap();
                }
                observed
            },
            None,
        );
        assert!(matches!(result, Err(RescanError::Cancelled { .. })));
        assert!(invalidated(&db));
    }
}
