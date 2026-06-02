//! `IndexerStore` owns the redb database file holding all indexer
//! state. The file is separate from the chain store so an indexer-DB
//! wipe never touches consensus data.

pub(crate) mod address;
pub(crate) mod boxes;
pub(crate) mod meta;
pub(crate) mod numeric;
pub(crate) mod segment;
pub(crate) mod storage_rent;
pub(crate) mod tables;
pub(crate) mod template;
pub(crate) mod token;
pub(crate) mod txs;
pub(crate) mod undo;

pub use meta::{IndexerMeta, INDEXER_SCHEMA_VERSION};
pub use undo::{UndoEntry, ROLLBACK_WINDOW};

use ergo_indexer_types::{IndexedErgoBox, IndexedErgoTransaction};
use ergo_primitives::digest::Digest32;

use crate::address::IndexedAddress;
use crate::segment::Segment;
use crate::template::IndexedTemplate;
use crate::token::IndexedToken;
use crate::{BoxId, TokenId, TxId};

use std::path::{Path, PathBuf};
use std::sync::Arc;

use redb::Database;

use crate::error::IndexerError;
use ergo_indexer_types::IndexerHaltReason;

/// Outcome of running the wipe/resume table on `IndexerStore::open`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenOutcome {
    /// File did not exist — DB created fresh, meta empty.
    CreatedFresh,
    /// File present and `schema_version` matched — resumed from
    /// persisted meta.
    Resumed,
    /// File present but `schema_version` mismatched — file deleted and
    /// recreated, meta empty.
    WipedAndRecreated { previous_version: u32 },
}

/// Owning handle around `redb::Database` plus the path it lives at.
/// Cheap to `Clone` (Arc-wrapped). `read_meta` / `read_undo` /
/// The read methods snapshot under their own redb read transaction;
/// the `apply_block` / `rollback_one_block` paths are layered on top
/// via the `commit_apply_meta_only` / `commit_rollback_meta_only`
/// helpers below.
#[derive(Clone)]
pub struct IndexerStore {
    db: Arc<Database>,
    #[allow(dead_code)] // read by future debug/log helpers
    path: PathBuf,
}

impl IndexerStore {
    /// Open the indexer DB at `path`, applying the wipe/resume
    /// table:
    ///
    /// | DB state | Action |
    /// |---|---|
    /// | File absent | Create fresh, `schema_version = INDEXER_SCHEMA_VERSION`. |
    /// | File present, `schema_version` matches | Resume. |
    /// | File present, `schema_version` mismatches | Delete, recreate fresh. |
    /// | File present, `schema_version` key missing | Halt `SchemaCorruption`. |
    /// | File present, redb open / table / decode failure | Halt `DbCorruption`. |
    pub fn open(path: &Path) -> Result<(Self, OpenOutcome), IndexerError> {
        if !path.exists() {
            return Self::create_fresh(path).map(|s| (s, OpenOutcome::CreatedFresh));
        }

        // Use `open_with_repair_logging` so an unclean shutdown that
        // needs a full repair walk surfaces as structured journal
        // events (`redb_repair_started` / `_progress` / `_complete`)
        // rather than a silent multi-minute hang. The helper goes
        // through `Database::builder().create(path)`, which is
        // create-or-open semantically — equivalent to `Database::open`
        // here since `path.exists()` is already checked above.
        let db = ergo_state::open_with_repair_logging(path, "indexer")?;
        let read_txn = db.begin_read()?;

        // Propagate the original typed error — `read_schema_version`
        // already returns the precise variant (`SchemaTableMissing`,
        // `Db`, or `DbRowLength`) for each failure shape, so swallowing
        // them into a single category here would discard the diagnosis
        // operators need.
        let persisted = match meta::read_schema_version(&read_txn) {
            Ok(v) => v,
            Err(e) => {
                drop(read_txn);
                drop(db);
                return Err(e);
            }
        };

        match persisted {
            None => {
                // File present but no schema_version key → corruption.
                Err(IndexerError::SchemaCorruption)
            }
            Some(v) if v == INDEXER_SCHEMA_VERSION => {
                drop(read_txn);
                Ok((
                    Self {
                        db: Arc::new(db),
                        path: path.to_path_buf(),
                    },
                    OpenOutcome::Resumed,
                ))
            }
            Some(previous_version) => {
                drop(read_txn);
                drop(db);
                tracing::info!(
                    previous_version,
                    new_version = INDEXER_SCHEMA_VERSION,
                    "schema bump detected, full resync required",
                );
                std::fs::remove_file(path).map_err(|e| IndexerError::FsIo {
                    context: "remove_file schema-wipe",
                    source: e,
                })?;
                let store = Self::create_fresh(path)?;
                Ok((store, OpenOutcome::WipedAndRecreated { previous_version }))
            }
        }
    }

    fn create_fresh(path: &Path) -> Result<Self, IndexerError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| IndexerError::FsIo {
                    context: "create_dir_all",
                    source: e,
                })?;
            }
        }
        let db = ergo_state::open_with_repair_logging(path, "indexer")?;
        let write_txn = ergo_state::begin_write_qr(&db)?;
        tables::create_all(&write_txn)?;
        meta::write_schema_version(&write_txn, INDEXER_SCHEMA_VERSION)?;
        meta::write_meta(&write_txn, &IndexerMeta::empty())?;
        write_txn.commit()?;
        Ok(Self {
            db: Arc::new(db),
            path: path.to_path_buf(),
        })
    }

    /// Cumulative count of redb cache evictions for the indexer DB.
    /// Only non-zero when the `cache_metrics` feature is enabled on the
    /// redb crate (otherwise stays at 0). A persistently rising value
    /// indicates redb's internal page cache is under pressure for the
    /// indexer's tables.
    pub fn redb_cache_evictions(&self) -> u64 {
        self.db.cache_stats().evictions()
    }

    /// Snapshot the current meta block. Cheap — one redb read txn.
    pub fn read_meta(&self) -> Result<IndexerMeta, IndexerError> {
        let read_txn = self.db.begin_read()?;
        meta::read_meta(&read_txn)
    }

    /// Look up the undo entry recorded for `height`. `None` means "no
    /// entry" — caller must classify that as `IndexerError::UndoMissing`
    /// when in rollback context.
    pub fn read_undo(&self, height: u64) -> Result<Option<UndoEntry>, IndexerError> {
        let read_txn = self.db.begin_read()?;
        undo::read_undo(&read_txn, height)
    }

    /// Fetch the `IndexedErgoBox` row keyed by `box_id`. Returns `None`
    /// when the box has never been indexed (i.e. created above
    /// `indexed_height` or not present on this chain).
    pub fn read_box(&self, box_id: &BoxId) -> Result<Option<IndexedErgoBox>, IndexerError> {
        let read_txn = self.db.begin_read()?;
        boxes::read_box_in(&read_txn, box_id)
    }

    /// Fetch the `IndexedErgoTransaction` row keyed by `tx_id`.
    pub fn read_tx(&self, tx_id: &TxId) -> Result<Option<IndexedErgoTransaction>, IndexerError> {
        let read_txn = self.db.begin_read()?;
        txs::read_tx_in(&read_txn, tx_id)
    }

    /// Resolve a global box index `n` (always non-negative on the box
    /// record — the spent flag lives on segment entries) to its `BoxId`.
    pub fn read_numeric_box(&self, n: u64) -> Result<Option<BoxId>, IndexerError> {
        let read_txn = self.db.begin_read()?;
        numeric::read_numeric_box_in(&read_txn, n)
    }

    /// Resolve a global tx index `n` to its `TxId`.
    pub fn read_numeric_tx(&self, n: u64) -> Result<Option<TxId>, IndexerError> {
        let read_txn = self.db.begin_read()?;
        numeric::read_numeric_tx_in(&read_txn, n)
    }

    /// Fetch the `IndexedAddress` parent record keyed by `tree_hash`.
    /// `None` means the address has never been touched on this chain
    /// (no inputs spent, no outputs created).
    pub fn read_address(
        &self,
        tree_hash: &Digest32,
    ) -> Result<Option<IndexedAddress>, IndexerError> {
        let read_txn = self.db.begin_read()?;
        address::read_address_in(&read_txn, tree_hash)
    }

    /// Concatenate all box-segment entries under `tree_hash` in
    /// oldest-first order (spill_0 ++ ... ++ spill_(N-1) ++ head). The
    /// list mixes signed entries: positive entries are unspent boxes,
    /// negative entries are spent boxes (sign-flipped).
    /// Callers filter by sign for `unspent/byAddress` and dereference
    /// each entry via `read_box / read_numeric_box(abs(entry))`.
    pub fn read_address_box_entries(
        &self,
        tree_hash: &Digest32,
    ) -> Result<Option<Vec<i64>>, IndexerError> {
        let read_txn = self.db.begin_read()?;
        address::read_address_box_entries_in(&read_txn, tree_hash)
    }

    /// Concatenate all tx-segment entries under `tree_hash` in
    /// oldest-first order. All entries are positive (tx segments have
    /// no spent flag.
    pub fn read_address_tx_entries(
        &self,
        tree_hash: &Digest32,
    ) -> Result<Option<Vec<i64>>, IndexerError> {
        let read_txn = self.db.begin_read()?;
        address::read_address_tx_entries_in(&read_txn, tree_hash)
    }

    /// Fetch the `IndexedTemplate` parent record keyed by `template_hash`.
    /// `None` means no output ever indexed under that template (e.g.
    /// every output's tree was soft-fork-wrapped, or the template
    /// hasn't been touched on this chain).
    pub fn read_template(
        &self,
        template_hash: &Digest32,
    ) -> Result<Option<IndexedTemplate>, IndexerError> {
        let read_txn = self.db.begin_read()?;
        template::read_template_in(&read_txn, template_hash)
    }

    /// Concatenate all box-segment entries under `template_hash` in
    /// oldest-first order. Same sign-encoding as
    /// `read_address_box_entries` — positive entries are unspent boxes,
    /// negative entries are spent boxes (sign-flipped).
    pub fn read_template_box_entries(
        &self,
        template_hash: &Digest32,
    ) -> Result<Option<Vec<i64>>, IndexerError> {
        let read_txn = self.db.begin_read()?;
        template::read_template_box_entries_in(&read_txn, template_hash)
    }

    /// Fetch the `IndexedToken` parent record keyed by `token_id`. The
    /// redb key is `token_unique_id(token_id)` — callers pass the raw
    /// token id and the store derives the unique id internally. `None`
    /// means no EIP-4 mint has ever recorded this token on this chain.
    pub fn read_token(&self, token_id: &TokenId) -> Result<Option<IndexedToken>, IndexerError> {
        let read_txn = self.db.begin_read()?;
        token::read_token_in(&read_txn, token_id)
    }

    /// Concatenate all box-segment entries under `token_id` in
    /// oldest-first order. Same sign-encoding as
    /// `read_address_box_entries` — positive entries are unspent boxes
    /// holding this token, negative entries are spent boxes (sign-flipped
    /// (sign-flipped).
    pub fn read_token_box_entries(
        &self,
        token_id: &TokenId,
    ) -> Result<Option<Vec<i64>>, IndexerError> {
        let read_txn = self.db.begin_read()?;
        token::read_token_box_entries_in(&read_txn, token_id)
    }

    /// Snapshot every `unspent_by_creation_height` row in ascending
    /// `(creation_height, global_box_index)` order. The table is
    /// lazy-created on first apply, so on a fresh store with no
    /// blocks applied the call returns an empty Vec.
    pub fn read_storage_rent_entries(
        &self,
    ) -> Result<Vec<storage_rent::StorageRentRow>, IndexerError> {
        use redb::ReadableTable;
        let read_txn = self.db.begin_read()?;
        let table = match read_txn.open_table(storage_rent::UNSPENT_BY_CREATION_HEIGHT) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let mut out = Vec::new();
        let iter = table.iter()?;
        for entry in iter {
            let (k, v) = entry?;
            let (creation_height, global_index) = k.value();
            let (box_id, box_value, box_bytes_len) = storage_rent::decode_value(v.value())?;
            out.push((
                creation_height,
                global_index,
                box_id,
                box_value,
                box_bytes_len,
            ));
        }
        Ok(out)
    }

    /// Paged scan of `unspent_by_creation_height` for boxes with
    /// `creationHeight ≤ height_cutoff`. Sort direction picks the scan
    /// side; both directions decode the same value bytes, just
    /// traversed in opposite order.
    pub fn read_storage_rent_eligible_paged(
        &self,
        height_cutoff: u32,
        offset: u32,
        limit: u32,
        dir: ergo_indexer_types::SortDir,
    ) -> Result<Vec<ergo_indexer_types::StorageRentEligibleDto>, IndexerError> {
        use ergo_indexer_types::{SortDir, StorageRentEligibleDto};
        let read_txn = self.db.begin_read()?;
        let table = match read_txn.open_table(storage_rent::UNSPENT_BY_CREATION_HEIGHT) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };

        // Range: (0, MIN) ..= (height_cutoff, MAX). redb tuple keys
        // sort lexicographically by component, so this captures every
        // row with creation_height ≤ cutoff regardless of global_index.
        let lo = (0u32, i64::MIN);
        let hi = (height_cutoff, i64::MAX);
        let range = table.range(lo..=hi)?;

        let mut out = Vec::with_capacity(limit.min(1024) as usize);
        let mut skipped = 0u32;
        let need = limit as usize;

        // `.rev()` flips the iteration without re-querying. redb's
        // range iterator is double-ended.
        let take_one = |entry: redb::Result<_>,
                        out: &mut Vec<StorageRentEligibleDto>|
         -> Result<(), IndexerError> {
            let (k, v): (
                redb::AccessGuard<'_, (u32, i64)>,
                redb::AccessGuard<'_, &[u8]>,
            ) = entry?;
            let (creation_height, global_box_index) = k.value();
            let (box_id, box_value, box_bytes_len) = storage_rent::decode_value(v.value())?;
            out.push(StorageRentEligibleDto {
                creation_height,
                global_box_index,
                box_id,
                box_value,
                box_bytes_len,
            });
            Ok(())
        };

        match dir {
            SortDir::Asc => {
                for entry in range {
                    if skipped < offset {
                        skipped += 1;
                        continue;
                    }
                    if out.len() >= need {
                        break;
                    }
                    take_one(entry, &mut out)?;
                }
            }
            SortDir::Desc => {
                for entry in range.rev() {
                    if skipped < offset {
                        skipped += 1;
                        continue;
                    }
                    if out.len() >= need {
                        break;
                    }
                    take_one(entry, &mut out)?;
                }
            }
        }
        Ok(out)
    }

    /// Total count of rows with `creationHeight ≤ height_cutoff`. Used
    /// to populate the paged response envelope's `total` field. Walks
    /// the keyspace without decoding values.
    pub fn read_storage_rent_eligible_total(
        &self,
        height_cutoff: u32,
    ) -> Result<u64, IndexerError> {
        let read_txn = self.db.begin_read()?;
        let table = match read_txn.open_table(storage_rent::UNSPENT_BY_CREATION_HEIGHT) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(0),
            Err(e) => return Err(e.into()),
        };
        let lo = (0u32, i64::MIN);
        let hi = (height_cutoff, i64::MAX);
        let range = table.range(lo..=hi)?;
        let mut total = 0u64;
        for entry in range {
            entry?;
            total += 1;
        }
        Ok(total)
    }

    /// Paged scan of `unspent_by_creation_height` over a closed
    /// creation-height range `[height_lo, height_hi]`. Backs the
    /// `maturesAt(H)` (single-height slice when `lo == hi`) and
    /// `maturesInRange(lo, hi)` API endpoints.
    pub fn read_storage_rent_in_creation_range_paged(
        &self,
        height_lo: u32,
        height_hi: u32,
        offset: u32,
        limit: u32,
        dir: ergo_indexer_types::SortDir,
    ) -> Result<Vec<ergo_indexer_types::StorageRentEligibleDto>, IndexerError> {
        use ergo_indexer_types::{SortDir, StorageRentEligibleDto};
        if height_lo > height_hi {
            return Ok(Vec::new());
        }
        let read_txn = self.db.begin_read()?;
        let table = match read_txn.open_table(storage_rent::UNSPENT_BY_CREATION_HEIGHT) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };

        let lo = (height_lo, i64::MIN);
        let hi = (height_hi, i64::MAX);
        let range = table.range(lo..=hi)?;

        let mut out = Vec::with_capacity(limit.min(1024) as usize);
        let mut skipped = 0u32;
        let need = limit as usize;

        let take_one = |entry: redb::Result<_>,
                        out: &mut Vec<StorageRentEligibleDto>|
         -> Result<(), IndexerError> {
            let (k, v): (
                redb::AccessGuard<'_, (u32, i64)>,
                redb::AccessGuard<'_, &[u8]>,
            ) = entry?;
            let (creation_height, global_box_index) = k.value();
            let (box_id, box_value, box_bytes_len) = storage_rent::decode_value(v.value())?;
            out.push(StorageRentEligibleDto {
                creation_height,
                global_box_index,
                box_id,
                box_value,
                box_bytes_len,
            });
            Ok(())
        };

        match dir {
            SortDir::Asc => {
                for entry in range {
                    if skipped < offset {
                        skipped += 1;
                        continue;
                    }
                    if out.len() >= need {
                        break;
                    }
                    take_one(entry, &mut out)?;
                }
            }
            SortDir::Desc => {
                for entry in range.rev() {
                    if skipped < offset {
                        skipped += 1;
                        continue;
                    }
                    if out.len() >= need {
                        break;
                    }
                    take_one(entry, &mut out)?;
                }
            }
        }
        Ok(out)
    }

    /// Total count of rows with `creationHeight ∈ [height_lo, height_hi]`.
    /// Drives the `maturesAt` / `maturesInRange` page envelope `total`.
    pub fn read_storage_rent_total_in_creation_range(
        &self,
        height_lo: u32,
        height_hi: u32,
    ) -> Result<u64, IndexerError> {
        if height_lo > height_hi {
            return Ok(0);
        }
        let read_txn = self.db.begin_read()?;
        let table = match read_txn.open_table(storage_rent::UNSPENT_BY_CREATION_HEIGHT) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(0),
            Err(e) => return Err(e.into()),
        };
        let lo = (height_lo, i64::MIN);
        let hi = (height_hi, i64::MAX);
        let range = table.range(lo..=hi)?;
        let mut total = 0u64;
        for entry in range {
            entry?;
            total += 1;
        }
        Ok(total)
    }

    /// Fetch a spill `Segment` keyed by its derived segment id (see
    /// `crate::segment_id::box_segment_id` / `tx_segment_id`). `None`
    /// means no spill has been produced yet under that id.
    pub fn read_spill_segment(
        &self,
        segment_id: &Digest32,
    ) -> Result<Option<Segment>, IndexerError> {
        let read_txn = self.db.begin_read()?;
        segment::read_spill_in(&read_txn, segment_id)
    }

    /// Begin a write transaction. Exactly one block per txn — the
    /// apply / rollback paths each call `commit_block_txn` to wrap a
    /// full block's worth of mutations.
    ///
    /// Delegates to [`ergo_state::begin_write_qr`] so every indexer
    /// write commit carries quick-repair; see that helper's module
    /// docs for the non-monotonicity contract.
    pub(crate) fn begin_write(&self) -> Result<redb::WriteTransaction, IndexerError> {
        Ok(ergo_state::begin_write_qr(&self.db)?)
    }

    /// Convenience: write `meta`, write `undo` for `height`, prune the
    /// rollback window, and commit — all in a single redb txn. Used by
    /// the apply path; rollback uses the symmetric `commit_rollback_txn`
    /// helper below.
    pub fn commit_apply_meta_only(
        &self,
        meta: &IndexerMeta,
        undo_height: u64,
        undo: &UndoEntry,
    ) -> Result<(), IndexerError> {
        let write_txn = self.begin_write()?;
        meta::write_meta(&write_txn, meta)?;
        undo::write_undo(&write_txn, undo_height, undo)?;
        undo::prune_below_window(&write_txn, undo_height)?;
        write_txn.commit()?;
        Ok(())
    }

    /// Convenience: write `meta` (rolled-back snapshot) and remove the
    /// undo entry at `height` in a single txn.
    pub fn commit_rollback_meta_only(
        &self,
        meta: &IndexerMeta,
        height_removed: u64,
    ) -> Result<(), IndexerError> {
        let write_txn = self.begin_write()?;
        meta::write_meta(&write_txn, meta)?;
        {
            let mut table = write_txn.open_table(tables::INDEXER_UNDO)?;
            table.remove(height_removed)?;
        }
        write_txn.commit()?;
        Ok(())
    }
}

impl std::fmt::Debug for IndexerStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IndexerStore")
            .field("path", &self.path)
            .finish()
    }
}

impl From<IndexerError> for IndexerHaltReason {
    fn from(e: IndexerError) -> Self {
        e.halt_reason()
    }
}
