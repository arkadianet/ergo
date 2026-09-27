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

use redb::Database;

use thiserror::Error;

use crate::store::StateError;
use crate::wallet::store::{RedbWalletStore, WalletStore, WalletStoreError};
use crate::wallet::tables::WALLET_SCAN_HEIGHT;

/// Matches a block's output boxes against the registered `/scan/*` rules
/// during a rescan. The `ergo-wallet` predicate matcher isn't reachable from
/// `ergo-state` (dependency direction), so the integrator (`ergo-node`)
/// supplies this — the rescan analog of the live `WalletApplyHook::match_boxes`.
pub trait ScanRescanMatcher {
    /// For each serialized output box (in block order, across all of the
    /// block's transactions), the ids of registered scans whose rule matches
    /// it. MUST return exactly one result per input box, in the same order.
    fn match_boxes(&self, boxes: &[&[u8]]) -> Result<Vec<Vec<u16>>, String>;
}

/// A failure while reading the chain data required by a wallet rescan.
#[derive(Debug, Error)]
pub enum RescanReadError {
    #[error("block data missing at height {height}")]
    Missing { height: u32 },
    #[error("block data corrupt at height {height}: {source}")]
    Corrupt {
        height: u32,
        #[source]
        source: StateError,
    },
    #[error("block data storage failure at height {height}: {source}")]
    Storage {
        height: u32,
        #[source]
        source: StateError,
    },
}

impl RescanReadError {
    pub fn from_state(height: u32, source: StateError) -> Self {
        match source {
            StateError::Serialization(_) | StateError::DbCorruption { .. } => {
                Self::Corrupt { height, source }
            }
            other => Self::Storage {
                height,
                source: other,
            },
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
                let scan_records: Option<Vec<crate::store::ScanMatchRecord>> =
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
                                    crate::store::ScanMatchRecord {
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

            let mut write = WalletStore::begin_write(store)?;
            write.finish_rescan(start_height)?;
            write.commit()?;
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

/// An owned-bytes analog of `BlockOutput<'a>`. The rescan loop
/// borrows from these to build `BlockOutput<'_>` values.
#[derive(Clone)]
pub struct OwnedBlockOutput {
    pub box_id: [u8; 32],
    pub output_index: u16,
    pub ergo_tree_bytes: Vec<u8>,
    pub value: u64,
    pub assets: Vec<([u8; 32], u64)>,
    pub miner_reward_pubkey: Option<[u8; 33]>,
    /// Full serialized `ErgoBox` bytes — supplied by the section reader so
    /// the rescan loop can match registered scans against historical boxes
    /// and persist `ScanTrackedBox.box_bytes`. Empty when scan rescan is
    /// not in play.
    pub box_bytes: Vec<u8>,
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
            txn.open_table(crate::store::CHAIN_INDEX)
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
}
