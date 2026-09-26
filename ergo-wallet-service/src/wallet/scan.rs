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
        tip_height: u32,
    ) -> Result<(), RescanError> {
        if requested == 0 {
            return Ok(());
        }
        let read = store.read()?;
        let cursor = match read.scan_cursor() {
            Ok(cursor) => cursor,
            Err(_) => {
                return Err(RescanError::InvalidStart {
                    requested,
                    cursor: None,
                })
            }
        };
        let Some(cursor) = cursor else {
            return Err(RescanError::InvalidStart {
                requested,
                cursor: None,
            });
        };
        if cursor.height > tip_height
            || (cursor.height == 0 && cursor.header_id.is_some())
            || (cursor.height > 0 && cursor.header_id.is_none())
        {
            return Err(RescanError::InvalidStart {
                requested,
                cursor: Some(cursor.height),
            });
        }
        if read.scan_invalidated()? {
            return Err(RescanError::InvalidStart {
                requested,
                cursor: Some(cursor.height),
            });
        }
        if cursor.height > 0
            && read.chain_index_header(cursor.height).ok().flatten() != cursor.header_id
        {
            return Err(RescanError::InvalidStart {
                requested,
                cursor: Some(cursor.height),
            });
        }
        let expected = cursor
            .height
            .checked_add(1)
            .ok_or(RescanError::InvalidStart {
                requested,
                cursor: Some(cursor.height),
            })?;
        if requested != expected || requested > tip_height {
            return Err(RescanError::InvalidStart {
                requested,
                cursor: Some(cursor.height),
            });
        }
        Ok(())
    }

    /// Full-rebuild (or range-scoped) rescan.
    ///
    /// When `start_height == 0`: full rebuild — clears WALLET_BOXES,
    /// WALLET_BOXES_BY_TX, and WALLET_TXS, sets WALLET_SCAN_INVALIDATED=true,
    /// resets WALLET_SCAN_HEIGHT=0, then replays all blocks in [0..=tip_height].
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
        Self::validate_rescan_start(store, start_height, initial_tip.height)?;
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
        if result.is_err() {
            if let Err(source) = store.persist_scan_invalidation(true) {
                return Err(RescanError::Invalidation { source });
            }
        }
        result
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
            let finalization_guard = crate::wallet::chain_apply_write_guard();
            if is_cancelled() {
                drop(finalization_guard);
                return Err(RescanError::Cancelled {
                    height: current_height,
                });
            }
            let observed_tip = read_tip()?;
            if observed_tip.height < target_tip.height {
                drop(finalization_guard);
                return Err(RescanError::Cancelled {
                    height: current_height,
                });
            }
            if observed_tip.height == target_tip.height
                && observed_tip.header_id != target_tip.header_id
            {
                drop(finalization_guard);
                return Err(RescanError::TipChanged {
                    expected: target_tip,
                    actual: observed_tip,
                });
            }
            if observed_tip.height > target_tip.height {
                drop(finalization_guard);
                target_tip = observed_tip;
                continue;
            }
            if current_height < observed_tip.height {
                drop(finalization_guard);
                target_tip = observed_tip;
                continue;
            }
            let mut write = WalletStore::begin_write(store)?;
            write.finish_rescan(start_height)?;
            write.commit()?;
            let owned = crate::wallet::wallet_finalization_owned();
            crate::wallet::set_wallet_finalization_in_progress(true);
            if !owned {
                crate::wallet::set_wallet_finalization_in_progress(false);
            }
            drop(finalization_guard);
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
        if result.is_err() {
            if let Err(source) = store.persist_scan_invalidation(true) {
                return Err(RescanError::Invalidation { source });
            }
        }
        result
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

        let mut write = WalletStore::begin_write(store)?;
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

            let finalization_guard = crate::wallet::chain_apply_write_guard();
            if is_cancelled() {
                drop(finalization_guard);
                return Err(RescanError::Cancelled {
                    height: current_target,
                });
            }
            let new_target = read_tip()?;
            if new_target < current_target {
                drop(finalization_guard);
                return Err(RescanError::Cancelled {
                    height: current_target,
                });
            }
            if new_target > current_target {
                drop(finalization_guard);
                current_start = current_target + 1;
                current_target = new_target;
                continue;
            }

            let mut write = WalletStore::begin_write(store)?;
            write.finish_rescan(start_height)?;
            write.commit()?;
            let owned = crate::wallet::wallet_finalization_owned();
            crate::wallet::set_wallet_finalization_in_progress(true);
            if !owned {
                crate::wallet::set_wallet_finalization_in_progress(false);
            }
            drop(finalization_guard);
            return Ok(processed);
        }
    }

    /// Read the current scan height from `WALLET_SCAN_HEIGHT`.
    /// Returns 0 if the table doesn't exist yet (fresh wallet).
    pub fn current_scan_height(db: &Database) -> Result<u32, redb::Error> {
        let txn = db.begin_read()?;
        let tbl = match txn.open_table(WALLET_SCAN_HEIGHT) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(0),
            Err(e) => return Err(e.into()),
        };
        Ok(tbl.get(())?.map(|g| g.value()).unwrap_or(0))
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
    use std::sync::mpsc;
    use std::sync::Arc;
    use std::thread;

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
    fn rescan_finalization_holds_chain_write_lock_during_tip_read() {
        let _guard = crate::wallet::WALLET_APPLY_TEST_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::create(dir.path().join("state.redb")).unwrap());
        let store = Arc::new(RedbWalletStore::new(db));
        let (tip_entered_tx, tip_entered_rx) = mpsc::sync_channel(0);
        let (release_tx, release_rx) = mpsc::sync_channel(0);
        let worker_store = store.clone();
        let worker = thread::spawn(move || {
            WalletScanService::rescan_full_rebuild_store(
                worker_store.as_ref(),
                BTreeSet::new(),
                BTreeMap::new(),
                0,
                0,
                |_height| Ok(None),
                || {
                    tip_entered_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    Ok(0)
                },
                || false,
                None,
            )
        });

        tip_entered_rx.recv().unwrap();
        let read_was_blocked = crate::wallet::CHAIN_APPLY_FINALIZATION_LOCK
            .try_read()
            .is_err();
        release_tx.send(()).unwrap();
        let result = worker.join().unwrap();
        assert!(read_was_blocked);
        assert_eq!(result.unwrap(), 0);
        crate::wallet::set_wallet_finalization_in_progress(false);
        assert!(!store.read().unwrap().scan_invalidated().unwrap());
    }

    #[test]
    fn rescan_replays_a_tip_observed_during_finalization() {
        let _guard = crate::wallet::WALLET_APPLY_TEST_LOCK.lock().unwrap();
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
        crate::wallet::set_wallet_finalization_in_progress(false);
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
        let _guard = crate::wallet::WALLET_APPLY_TEST_LOCK.lock().unwrap();
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
    fn positive_rescan_requires_existing_contiguous_cursor() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::create(dir.path().join("state.redb")).unwrap());
        let store = RedbWalletStore::new(db.clone());
        assert!(matches!(
            WalletScanService::validate_rescan_start(&store, 1, 1),
            Err(RescanError::InvalidStart { cursor: None, .. })
        ));
        let mut write = store.begin_write().unwrap();
        write.set_scan_cursor(0, None).unwrap();
        write.commit().unwrap();
        assert!(WalletScanService::validate_rescan_start(&store, 1, 1).is_ok());
        let mut write = store.begin_write().unwrap();
        write.set_scan_cursor(1, Some(&[4; 32])).unwrap();
        write.commit().unwrap();
        {
            let txn = db.begin_write().unwrap();
            txn.open_table(crate::wallet::tables::CHAIN_INDEX)
                .unwrap()
                .insert(1u64, &[4u8; 32][..])
                .unwrap();
            txn.commit().unwrap();
        }
        assert!(WalletScanService::validate_rescan_start(&store, 2, 2).is_ok());
        assert!(matches!(
            WalletScanService::validate_rescan_start(&store, 3, 3),
            Err(RescanError::InvalidStart {
                cursor: Some(1),
                ..
            })
        ));
        let result = WalletScanService::rescan_full_rebuild_store(
            &store,
            BTreeSet::new(),
            BTreeMap::new(),
            3,
            3,
            |_height| Ok(None),
            || Ok(3),
            || false,
            None,
        );
        assert!(matches!(result, Err(RescanError::InvalidStart { .. })));
    }

    #[test]
    fn positive_rescan_rejects_invalidated_or_mismatched_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::create(dir.path().join("state.redb")).unwrap());
        let store = RedbWalletStore::new(db.clone());
        {
            let txn = db.begin_write().unwrap();
            txn.open_table(crate::wallet::tables::CHAIN_INDEX)
                .unwrap()
                .insert(1u64, &[4u8; 32][..])
                .unwrap();
            txn.commit().unwrap();
        }
        let mut write = store.begin_write().unwrap();
        write.set_scan_cursor(1, Some(&[5; 32])).unwrap();
        write.commit().unwrap();
        assert!(matches!(
            WalletScanService::validate_rescan_start(&store, 2, 2),
            Err(RescanError::InvalidStart {
                cursor: Some(1),
                ..
            })
        ));

        let mut write = store.begin_write().unwrap();
        write.set_scan_cursor(0, None).unwrap();
        write.set_scan_invalidated(true).unwrap();
        write.commit().unwrap();
        assert!(matches!(
            WalletScanService::validate_rescan_start(&store, 1, 1),
            Err(RescanError::InvalidStart {
                cursor: Some(0),
                ..
            })
        ));
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
}
