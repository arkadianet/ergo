use std::path::Path;
use std::sync::{Arc, RwLock};

use crate::config::IndexerConfig;
use crate::error::IndexerError;
use crate::segment::SEGMENT_THRESHOLD;
use crate::store::IndexerStore;
use crate::{BoxId, TemplateHash, TokenId, TreeHash, TxId};
use ergo_indexer_types::{
    BalanceDto, IndexedBoxDto, IndexedTokenDto, IndexedTxDto, IndexerHaltReason, IndexerHealthDto,
    IndexerQuery, IndexerStatus, Page, SortDir, StorageRentEligibleDto,
};

/// Public read-side handle wired into `ergo-api`. Holds the in-memory
/// `IndexerStatus` (never persisted), the cached `indexed_height`
/// mirror so `/blockchain/indexedHeight` answers without a redb read
/// txn, and the `Arc<IndexerStore>` that the per-type read methods
/// drive.
///
/// Construction policy:
/// - `IndexerHandle::boot(config, datadir)` returns `None` only when
///   `config.enabled = false`. Otherwise it always returns `Some` —
///   either a `Syncing` handle backed by an open `IndexerStore`, or a
///   `Halted(reason)` handle with no store attached.
/// - A halted handle cannot serve reads (`IndexerStore` is `None`) and
///   the polling task is not spawned.
#[derive(Debug, Clone)]
pub struct IndexerHandle {
    inner: Arc<HandleInner>,
}

#[derive(Debug)]
struct HandleInner {
    status: RwLock<IndexerStatus>,
    indexed_height: RwLock<u64>,
    /// `None` for boot-time-halted handles; `Some` once a successful
    /// `IndexerStore::open` has produced the backing store.
    store: Option<Arc<IndexerStore>>,
}

impl IndexerHandle {
    /// Apply the boot contract:
    /// - `config.enabled = false` → `None`. (No `/blockchain/*` router
    ///   mounts; `ergo-api` returns 404 on any indexed path.)
    /// - `config.enabled = true` and `IndexerStore::open` succeeds →
    ///   `Some(syncing_handle)` with `indexed_height` seeded from the
    ///   persisted meta and the store wired in.
    /// - Boot-time `IndexerError::SchemaCorruption` → `Some(halted)`
    ///   with `IndexerHaltReason::SchemaCorruption`. No store wired.
    /// - Any other boot-time `IndexerError` → `Some(halted)` with
    ///   `IndexerHaltReason::DbCorruption`. No store wired.
    ///
    /// The polling task is *not* spawned here — the handle is returned
    /// to the caller (the node-startup wiring) which then spawns the
    /// task against the same store.
    pub fn boot(config: &IndexerConfig, datadir: &Path) -> Option<Self> {
        if !config.enabled {
            return None;
        }

        let path = datadir.join(&config.db_filename);
        match IndexerStore::open(&path) {
            Ok((mut store, _outcome)) => {
                store.set_rollback_window(config.rollback_window);
                let meta = match store.read_meta() {
                    Ok(m) => m,
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            reason = ?e.halt_reason(),
                            "indexer halted: read_meta failed on boot",
                        );
                        return Some(Self::halted(e.halt_reason()));
                    }
                };
                Some(Self::with_store(store, meta.indexed_height))
            }
            Err(IndexerError::SchemaCorruption) => {
                tracing::error!(
                    reason = ?IndexerHaltReason::SchemaCorruption,
                    "indexer halted: schema_version key missing",
                );
                Some(Self::halted(IndexerHaltReason::SchemaCorruption))
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    reason = ?e.halt_reason(),
                    "indexer halted: store open failed",
                );
                Some(Self::halted(e.halt_reason()))
            }
        }
    }

    /// Construct a handle pre-set to `Halted(reason)`. Used by the
    /// boot-time halt path when the indexer is enabled but the DB is
    /// unopenable / schema is corrupt.
    pub fn halted(reason: IndexerHaltReason) -> Self {
        Self {
            inner: Arc::new(HandleInner {
                status: RwLock::new(IndexerStatus::Halted(reason)),
                indexed_height: RwLock::new(0),
                store: None,
            }),
        }
    }

    /// Construct a fresh handle in the `Syncing` state with
    /// `indexed_height = 0` and no store attached. Useful for tests
    /// that don't need a real backing DB.
    pub fn syncing(indexed_height: u64) -> Self {
        Self {
            inner: Arc::new(HandleInner {
                status: RwLock::new(IndexerStatus::Syncing),
                indexed_height: RwLock::new(indexed_height),
                store: None,
            }),
        }
    }

    /// Successful-boot constructor: `Syncing` status, store wired in,
    /// `indexed_height` mirror seeded from persisted meta.
    pub fn with_store(store: IndexerStore, indexed_height: u64) -> Self {
        Self {
            inner: Arc::new(HandleInner {
                status: RwLock::new(IndexerStatus::Syncing),
                indexed_height: RwLock::new(indexed_height),
                store: Some(Arc::new(store)),
            }),
        }
    }

    /// Read-only access to the backing store (used by the polling
    /// task and the per-type read methods). `None` for halted handles.
    pub fn store(&self) -> Option<Arc<IndexerStore>> {
        self.inner.store.clone()
    }

    /// Update the in-memory status. Called by the polling task on
    /// transition.
    pub fn set_status(&self, next: IndexerStatus) {
        *self.inner.status.write().unwrap_or_else(|p| p.into_inner()) = next;
    }

    /// Update the cached `indexed_height` after a successful per-block
    /// commit. The in-loop halt contract relies on this mirroring the
    /// last successful redb commit.
    pub fn set_indexed_height(&self, height: u64) {
        *self
            .inner
            .indexed_height
            .write()
            .unwrap_or_else(|p| p.into_inner()) = height;
    }
}

impl IndexerQuery for IndexerHandle {
    fn indexed_height(&self) -> u64 {
        // Recover from a poisoned lock rather than propagating the
        // poison panic — a poisoned status lock means a prior writer
        // panicked, but `IndexedHeight: u64` is atomic-write at the
        // bit level so the data behind the guard is always a valid
        // height. Letting `/blockchain/indexedHeight` continue to
        // serve reads after an indexer fault is the explicit
        // recovery posture (audit-2 M11).
        *self
            .inner
            .indexed_height
            .read()
            .unwrap_or_else(|p| p.into_inner())
    }

    fn status(&self) -> IndexerStatus {
        // Same recovery posture as `indexed_height`: `IndexerStatus`
        // is a small enum, always in some valid variant, so a
        // poisoned read guard still wraps a meaningful status — and
        // serving it lets the API surface report Halted (or whatever
        // the last writer set) instead of taking down the API task.
        self.inner
            .status
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    fn health(&self) -> IndexerHealthDto {
        // One redb read txn per call (see `IndexerStore::health_snapshot`) —
        // acceptable at dashboard-poll cadence, unlike `indexed_height`,
        // whose cached mirror exists because the status-gate middleware
        // reads it on EVERY gated request. Best-effort: a failed snapshot
        // degrades to the healthy default rather than erroring the surface
        // — which must keep answering exactly when the store is unwell.
        let drift_skips = crate::segment_buffer::secondary_index_drift_skips();
        let Some(store) = self.inner.store.as_ref() else {
            // Boot-halted handle: no store, only the process counter.
            return IndexerHealthDto {
                drift_skips,
                ..IndexerHealthDto::default()
            };
        };
        match store.health_snapshot() {
            Ok(s) => IndexerHealthDto {
                repair_pending: s.repair_pending,
                repair_next_gi: s.repair_next_gi,
                repair_skipped: s.repair_skipped,
                drift_skips,
                global_boxes: s.meta.global_box_index,
                global_txs: s.meta.global_tx_index,
            },
            Err(e) => {
                tracing::warn!(error = %e, "indexer health snapshot failed");
                IndexerHealthDto {
                    drift_skips,
                    ..IndexerHealthDto::default()
                }
            }
        }
    }

    fn box_by_id(&self, box_id: &BoxId) -> Option<IndexedBoxDto> {
        let store = self.inner.store.as_ref()?;
        store
            .read_box(box_id)
            .inspect_err(
                |e| tracing::warn!(handler = "box_by_id", error = %e, "indexer read failed"),
            )
            .ok()
            .flatten()
    }
    fn box_by_global_index(&self, n: u64) -> Option<IndexedBoxDto> {
        let store = self.inner.store.as_ref()?;
        let id = store
            .read_numeric_box(n)
            .inspect_err(|e| {
                tracing::warn!(
                    handler = "box_by_global_index",
                    op = "numeric_box",
                    n,
                    error = %e,
                    "indexer read failed",
                )
            })
            .ok()
            .flatten()?;
        store
            .read_box(&id)
            .inspect_err(|e| {
                tracing::warn!(
                    handler = "box_by_global_index",
                    op = "box",
                    error = %e,
                    "indexer read failed",
                )
            })
            .ok()
            .flatten()
    }
    fn boxes_by_global_range(&self, _lo: u64, _hi: u64) -> Vec<IndexedBoxDto> {
        Vec::new()
    }

    fn tx_by_id(&self, tx_id: &TxId) -> Option<IndexedTxDto> {
        let store = self.inner.store.as_ref()?;
        store
            .read_tx(tx_id)
            .inspect_err(
                |e| tracing::warn!(handler = "tx_by_id", error = %e, "indexer read failed"),
            )
            .ok()
            .flatten()
    }
    fn tx_by_global_index(&self, n: u64) -> Option<IndexedTxDto> {
        let store = self.inner.store.as_ref()?;
        let id = store
            .read_numeric_tx(n)
            .inspect_err(|e| {
                tracing::warn!(
                    handler = "tx_by_global_index",
                    op = "numeric_tx",
                    n,
                    error = %e,
                    "indexer read failed",
                )
            })
            .ok()
            .flatten()?;
        store
            .read_tx(&id)
            .inspect_err(|e| {
                tracing::warn!(
                    handler = "tx_by_global_index",
                    op = "tx",
                    error = %e,
                    "indexer read failed",
                )
            })
            .ok()
            .flatten()
    }
    fn txs_by_global_range(&self, _lo: u64, _hi: u64) -> Vec<IndexedTxDto> {
        Vec::new()
    }

    fn address_balance(&self, tree_hash: &TreeHash) -> Option<BalanceDto> {
        let store = self.inner.store.as_ref()?;
        let addr = store
            .read_address(tree_hash)
            .inspect_err(
                |e| tracing::warn!(handler = "address_balance", error = %e, "indexer read failed"),
            )
            .ok()
            .flatten()?;
        let balance = addr.balance?;
        Some(BalanceDto {
            nano_ergs: balance.nano_ergs,
            tokens: balance.tokens,
        })
    }
    fn address_txs_paged(&self, tree_hash: &TreeHash, p: Page, dir: SortDir) -> Vec<IndexedTxDto> {
        let Some(store) = self.inner.store.as_ref() else {
            return Vec::new();
        };
        let entries = match store.read_address_tx_entries(tree_hash) {
            Ok(Some(e)) => e,
            Ok(None) => return Vec::new(),
            Err(e) => {
                tracing::warn!(
                    handler = "address_txs_paged",
                    error = %e,
                    "indexer read failed",
                );
                return Vec::new();
            }
        };
        slice_paged(&entries, p, dir)
            .iter()
            .filter_map(|&entry| dereference_tx(store.as_ref(), entry))
            .collect()
    }
    fn address_boxes_paged(
        &self,
        tree_hash: &TreeHash,
        p: Page,
        dir: SortDir,
    ) -> Vec<IndexedBoxDto> {
        let Some(store) = self.inner.store.as_ref() else {
            return Vec::new();
        };
        let entries = match store.read_address_box_entries(tree_hash) {
            Ok(Some(e)) => e,
            Ok(None) => return Vec::new(),
            Err(e) => {
                tracing::warn!(
                    handler = "address_boxes_paged",
                    error = %e,
                    "indexer read failed",
                );
                return Vec::new();
            }
        };
        slice_paged(&entries, p, dir)
            .iter()
            .filter_map(|&entry| dereference_box(store.as_ref(), entry))
            .collect()
    }
    fn address_unspent_paged(
        &self,
        tree_hash: &TreeHash,
        p: Page,
        dir: SortDir,
    ) -> Vec<IndexedBoxDto> {
        let Some(store) = self.inner.store.as_ref() else {
            return Vec::new();
        };
        let entries = match store.read_address_box_entries(tree_hash) {
            Ok(Some(e)) => e,
            Ok(None) => return Vec::new(),
            Err(e) => {
                tracing::warn!(
                    handler = "address_unspent_paged",
                    error = %e,
                    "indexer read failed",
                );
                return Vec::new();
            }
        };
        // Filter THEN paginate — `unspent/byAddress` exposes only
        // positive entries, then applies `(offset, limit)`.
        let unspent: Vec<i64> = entries.into_iter().filter(|&e| e > 0).collect();
        slice_paged(&unspent, p, dir)
            .iter()
            .filter_map(|&entry| dereference_box(store.as_ref(), entry))
            .collect()
    }
    fn address_total_txs(&self, tree_hash: &TreeHash) -> u64 {
        let Some(store) = self.inner.store.as_ref() else {
            return 0;
        };
        match store.read_address(tree_hash) {
            Ok(Some(addr)) => total_count(addr.segment.tx_segment_count, addr.segment.txs.len()),
            Ok(None) => 0,
            Err(e) => {
                tracing::warn!(
                    handler = "address_total_txs",
                    error = %e,
                    "indexer read failed",
                );
                0
            }
        }
    }
    fn address_total_boxes(&self, tree_hash: &TreeHash) -> u64 {
        let Some(store) = self.inner.store.as_ref() else {
            return 0;
        };
        match store.read_address(tree_hash) {
            Ok(Some(addr)) => total_count(addr.segment.box_segment_count, addr.segment.boxes.len()),
            Ok(None) => 0,
            Err(e) => {
                tracing::warn!(
                    handler = "address_total_boxes",
                    error = %e,
                    "indexer read failed",
                );
                0
            }
        }
    }

    fn template_boxes_paged(&self, h: &TemplateHash, p: Page) -> Vec<IndexedBoxDto> {
        let Some(store) = self.inner.store.as_ref() else {
            return Vec::new();
        };
        let entries = match store.read_template_box_entries(h) {
            Ok(Some(e)) => e,
            Ok(None) => return Vec::new(),
            Err(e) => {
                tracing::warn!(
                    handler = "template_boxes_paged",
                    error = %e,
                    "indexer read failed",
                );
                return Vec::new();
            }
        };
        // No `dir` parameter on the trait — Scala `byTemplateHash` exposes
        // only paged (no `sortDirection`); the implementation pins newest-
        // first to mirror the address-keyed default.
        slice_paged(&entries, p, SortDir::Desc)
            .iter()
            .filter_map(|&entry| dereference_box(store.as_ref(), entry))
            .collect()
    }
    fn template_unspent_paged(
        &self,
        h: &TemplateHash,
        p: Page,
        dir: SortDir,
    ) -> Vec<IndexedBoxDto> {
        let Some(store) = self.inner.store.as_ref() else {
            return Vec::new();
        };
        let entries = match store.read_template_box_entries(h) {
            Ok(Some(e)) => e,
            Ok(None) => return Vec::new(),
            Err(e) => {
                tracing::warn!(
                    handler = "template_unspent_paged",
                    error = %e,
                    "indexer read failed",
                );
                return Vec::new();
            }
        };
        // Mirrors `address_unspent_paged` — filter positives THEN
        // paginate; `unspent/byTemplateHash` exposes only positive
        // entries.
        let unspent: Vec<i64> = entries.into_iter().filter(|&e| e > 0).collect();
        slice_paged(&unspent, p, dir)
            .iter()
            .filter_map(|&entry| dereference_box(store.as_ref(), entry))
            .collect()
    }
    fn template_total_boxes(&self, h: &TemplateHash) -> u64 {
        let Some(store) = self.inner.store.as_ref() else {
            return 0;
        };
        match store.read_template(h) {
            Ok(Some(t)) => total_count(t.segment.box_segment_count, t.segment.boxes.len()),
            Ok(None) => 0,
            Err(e) => {
                tracing::warn!(
                    handler = "template_total_boxes",
                    error = %e,
                    "indexer read failed",
                );
                0
            }
        }
    }

    fn token_by_id(&self, token_id: &TokenId) -> Option<IndexedTokenDto> {
        let store = self.inner.store.as_ref()?;
        match store.read_token(token_id) {
            Ok(Some(t)) => Some(token_to_dto(&t)),
            Ok(None) => None,
            Err(e) => {
                tracing::warn!(
                    handler = "token_by_id",
                    error = %e,
                    "indexer read failed",
                );
                None
            }
        }
    }
    fn tokens_by_ids(&self, ids: &[TokenId]) -> Vec<IndexedTokenDto> {
        let Some(store) = self.inner.store.as_ref() else {
            return Vec::new();
        };
        // Scala flatMap semantics: misses are dropped from the result
        // array. DB-error misses are also dropped — logged for
        // diagnostics — to match the same flatMap shape.
        ids.iter()
            .filter_map(|id| match store.read_token(id) {
                Ok(Some(t)) => Some(token_to_dto(&t)),
                Ok(None) => None,
                Err(e) => {
                    tracing::warn!(
                        handler = "tokens_by_ids",
                        error = %e,
                        "indexer read failed",
                    );
                    None
                }
            })
            .collect()
    }
    fn token_boxes_paged(&self, token_id: &TokenId, p: Page) -> Vec<IndexedBoxDto> {
        let Some(store) = self.inner.store.as_ref() else {
            return Vec::new();
        };
        let entries = match store.read_token_box_entries(token_id) {
            Ok(Some(e)) => e,
            Ok(None) => return Vec::new(),
            Err(e) => {
                tracing::warn!(
                    handler = "token_boxes_paged",
                    error = %e,
                    "indexer read failed",
                );
                return Vec::new();
            }
        };
        // Scala `byTokenId` exposes only paged (no `sortDirection`);
        // we pin newest-first to mirror the address-keyed default.
        slice_paged(&entries, p, SortDir::Desc)
            .iter()
            .filter_map(|&entry| dereference_box(store.as_ref(), entry))
            .collect()
    }
    fn token_unspent_paged(&self, token_id: &TokenId, p: Page, dir: SortDir) -> Vec<IndexedBoxDto> {
        let Some(store) = self.inner.store.as_ref() else {
            return Vec::new();
        };
        let entries = match store.read_token_box_entries(token_id) {
            Ok(Some(e)) => e,
            Ok(None) => return Vec::new(),
            Err(e) => {
                tracing::warn!(
                    handler = "token_unspent_paged",
                    error = %e,
                    "indexer read failed",
                );
                return Vec::new();
            }
        };
        // Mirrors `template_unspent_paged` — filter positives THEN
        // paginate; `unspent/byTokenId` exposes only positive entries.
        let unspent: Vec<i64> = entries.into_iter().filter(|&e| e > 0).collect();
        slice_paged(&unspent, p, dir)
            .iter()
            .filter_map(|&entry| dereference_box(store.as_ref(), entry))
            .collect()
    }
    fn token_total_boxes(&self, token_id: &TokenId) -> u64 {
        let Some(store) = self.inner.store.as_ref() else {
            return 0;
        };
        match store.read_token(token_id) {
            Ok(Some(t)) => total_count(t.segment.box_segment_count, t.segment.boxes.len()),
            Ok(None) => 0,
            Err(e) => {
                tracing::warn!(
                    handler = "token_total_boxes",
                    error = %e,
                    "indexer read failed",
                );
                0
            }
        }
    }

    fn storage_rent_eligible_paged(
        &self,
        height_cutoff: u32,
        p: Page,
        dir: SortDir,
    ) -> Vec<StorageRentEligibleDto> {
        let Some(store) = self.store() else {
            return Vec::new();
        };
        store
            .read_storage_rent_eligible_paged(height_cutoff, p.offset, p.limit, dir)
            .unwrap_or_default()
    }

    fn storage_rent_eligible_total(&self, height_cutoff: u32) -> u64 {
        let Some(store) = self.store() else {
            return 0;
        };
        store
            .read_storage_rent_eligible_total(height_cutoff)
            .unwrap_or(0)
    }

    fn storage_rent_in_creation_range(
        &self,
        height_lo: u32,
        height_hi: u32,
        p: Page,
        dir: SortDir,
    ) -> Vec<StorageRentEligibleDto> {
        let Some(store) = self.store() else {
            return Vec::new();
        };
        store
            .read_storage_rent_in_creation_range_paged(height_lo, height_hi, p.offset, p.limit, dir)
            .unwrap_or_default()
    }

    fn storage_rent_total_in_creation_range(&self, height_lo: u32, height_hi: u32) -> u64 {
        let Some(store) = self.store() else {
            return 0;
        };
        store
            .read_storage_rent_total_in_creation_range(height_lo, height_hi)
            .unwrap_or(0)
    }
}

/// `box_segment_count * SEGMENT_THRESHOLD + head_len` — exact total
/// because each spill is exactly 512 entries (`segment_buffer.rs`
/// drains in fixed-size chunks).
fn total_count(segment_count: i32, head_len: usize) -> u64 {
    let segments = segment_count.max(0) as u64;
    segments * SEGMENT_THRESHOLD as u64 + head_len as u64
}

/// Apply `(offset, limit)` after sort direction. Returns a slice of the
/// caller's `entries` buffer; ASC keeps oldest-first order, DESC reverses.
fn slice_paged(entries: &[i64], page: Page, dir: SortDir) -> Vec<i64> {
    let len = entries.len();
    let offset = (page.offset as usize).min(len);
    let end = offset.saturating_add(page.limit as usize).min(len);
    match dir {
        SortDir::Asc => entries[offset..end].to_vec(),
        // Reverse-then-slice avoids materializing the full reversed list:
        // newest is at index `len - 1`, so window [len - end, len - offset]
        // contains the page when reversed.
        SortDir::Desc => {
            let lo = len.saturating_sub(end);
            let hi = len.saturating_sub(offset);
            entries[lo..hi].iter().rev().copied().collect()
        }
    }
}

/// Resolve a tx-segment entry (always positive) to its full
/// `IndexedTxDto`. Two redb reads per result: numeric_tx → tx_id,
/// then tx → record. Missing rows surface as `None` with a warning —
/// they would indicate apply/rollback skew, not a normal "not indexed"
/// case (segment entries always reference a row written in the same
/// block).
fn dereference_tx(store: &IndexerStore, entry: i64) -> Option<IndexedTxDto> {
    if entry < 0 {
        tracing::warn!(
            handler = "address_txs_paged",
            entry,
            "negative tx-segment entry",
        );
        return None;
    }
    let n = entry as u64;
    let id = match store.read_numeric_tx(n) {
        Ok(Some(id)) => id,
        Ok(None) => {
            tracing::warn!(
                handler = "address_txs_paged",
                op = "numeric_tx",
                n,
                "entry missing",
            );
            return None;
        }
        Err(e) => {
            tracing::warn!(
                handler = "address_txs_paged",
                op = "numeric_tx",
                n,
                error = %e,
                "indexer read failed",
            );
            return None;
        }
    };
    match store.read_tx(&id) {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(
                handler = "address_txs_paged",
                op = "tx",
                tx_id = %hex::encode(id.as_bytes()),
                error = %e,
                "indexer read failed",
            );
            None
        }
    }
}

/// Resolve a box-segment entry to its full `IndexedBoxDto`.
/// Sign-flipped entries dereference via `abs(entry)` — the box record
/// stays under its positive global index.
fn dereference_box(store: &IndexerStore, entry: i64) -> Option<IndexedBoxDto> {
    let n = entry.unsigned_abs();
    let id = match store.read_numeric_box(n) {
        Ok(Some(id)) => id,
        Ok(None) => {
            tracing::warn!(
                handler = "dereference_box",
                op = "numeric_box",
                n,
                "entry missing",
            );
            return None;
        }
        Err(e) => {
            tracing::warn!(
                handler = "dereference_box",
                op = "numeric_box",
                n,
                error = %e,
                "indexer read failed",
            );
            return None;
        }
    };
    match store.read_box(&id) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(
                handler = "dereference_box",
                op = "box",
                box_id = %hex::encode(id.as_bytes()),
                error = %e,
                "indexer read failed",
            );
            None
        }
    }
}

/// Project a persisted `IndexedToken` to the wire DTO. Per
/// `IndexedToken::from_box` (token.rs:75-112), all five `Option` fields
/// are pinned to `Some(_)` for well-formed records; missing R4/R5/R6
/// registers are stored as `Some("")` / `Some("")` / `Some(0)` so the
/// `unwrap_or_default()` paths below are vacuous on the apply path
/// they only fire if a record is truncated or constructed via
/// `IndexedToken::empty` (which apply paths never persist).
///
/// `emission_amount` is u64 in storage but `i64` on the wire to match
/// Scala's `Long` JSON shape (openapi `format: int64, minimum: 1`).
/// The cast is loss-free for any realistic emission value.
fn token_to_dto(t: &crate::token::IndexedToken) -> IndexedTokenDto {
    IndexedTokenDto {
        token_id: t.token_id,
        creating_box_id: t
            .creating_box_id
            .unwrap_or_else(|| BoxId::from_bytes([0u8; 32])),
        emission_amount: t.emission_amount.unwrap_or(0) as i64,
        name: t.name.clone().unwrap_or_default(),
        description: t.description.clone().unwrap_or_default(),
        decimals: t.decimals.unwrap_or(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- happy path -----

    #[test]
    fn syncing_handle_reports_syncing() {
        let h = IndexerHandle::syncing(0);
        assert_eq!(h.status(), IndexerStatus::Syncing);
        assert!(!h.is_caught_up());
        assert_eq!(h.indexed_height(), 0);
        assert!(h.store().is_none());
    }

    #[test]
    fn halted_handle_reports_halt_reason() {
        let h = IndexerHandle::halted(IndexerHaltReason::DbCorruption);
        assert_eq!(
            h.status(),
            IndexerStatus::Halted(IndexerHaltReason::DbCorruption)
        );
        assert!(!h.is_caught_up());
        assert!(h.store().is_none());
    }

    #[test]
    fn caught_up_transition_flips_is_caught_up() {
        let h = IndexerHandle::syncing(0);
        h.set_status(IndexerStatus::CaughtUp);
        h.set_indexed_height(1234);
        assert!(h.is_caught_up());
        assert_eq!(h.indexed_height(), 1234);
    }

    mod address_balance {
        use super::*;
        use crate::address::{BalanceInfo, IndexedAddress};
        use crate::segment::Segment;
        use crate::store::address::write_address;
        use ergo_primitives::digest::Digest32;
        use tempfile::TempDir;

        fn d(seed: u8) -> Digest32 {
            Digest32::from_bytes([seed; 32])
        }

        fn handle_with_store() -> (IndexerHandle, TempDir) {
            let tmp = TempDir::new().unwrap();
            let path = tmp.path().join("indexer.redb");
            let (store, _) = crate::store::IndexerStore::open(&path).unwrap();
            (IndexerHandle::with_store(store, 0), tmp)
        }

        #[test]
        fn returns_none_for_halted_handle_without_store() {
            let h = IndexerHandle::halted(IndexerHaltReason::DbCorruption);
            assert!(h.address_balance(&d(0xAA)).is_none());
        }

        #[test]
        fn returns_none_when_address_not_indexed() {
            let (h, _tmp) = handle_with_store();
            assert!(h.address_balance(&d(0xAA)).is_none());
        }

        #[test]
        fn projects_persisted_balance_to_dto() {
            let (h, _tmp) = handle_with_store();
            let store = h.store().unwrap();

            let tree_hash = d(0xAA);
            let token_a = d(0xB1);
            let token_b = d(0xB2);
            let rec = IndexedAddress {
                tree_hash,
                balance: Some(BalanceInfo {
                    nano_ergs: 1_000_000_000,
                    tokens: vec![(token_a, 5), (token_b, 7)],
                }),
                segment: Segment::empty(),
            };

            let write_txn = store.begin_write().unwrap();
            write_address(&write_txn, &tree_hash, &rec).unwrap();
            write_txn.commit().unwrap();

            let dto = h.address_balance(&tree_hash).expect("address present");
            assert_eq!(dto.nano_ergs, 1_000_000_000);
            assert_eq!(dto.tokens, vec![(token_a, 5), (token_b, 7)]);
        }

        #[test]
        fn preserves_token_insertion_order() {
            // Order parity with Scala BalanceInfo.tokens ArrayBuffer:
            // first-touch order is the on-wire order.
            let (h, _tmp) = handle_with_store();
            let store = h.store().unwrap();

            let tree_hash = d(0xCC);
            let id_first = d(0x10);
            let id_second = d(0x20);
            let id_third = d(0x30);
            let rec = IndexedAddress {
                tree_hash,
                balance: Some(BalanceInfo {
                    nano_ergs: 0,
                    tokens: vec![(id_first, 1), (id_second, 2), (id_third, 3)],
                }),
                segment: Segment::empty(),
            };

            let write_txn = store.begin_write().unwrap();
            write_address(&write_txn, &tree_hash, &rec).unwrap();
            write_txn.commit().unwrap();

            let dto = h.address_balance(&tree_hash).expect("address present");
            assert_eq!(
                dto.tokens,
                vec![(id_first, 1), (id_second, 2), (id_third, 3)]
            );
        }

        #[test]
        fn returns_none_for_record_without_balance() {
            // Spill-style records carry `balance: None` per address.rs:138.
            // Surfacing them as `None` keeps the reader contract clean
            // (the API layer can fall back to zero-balance).
            let (h, _tmp) = handle_with_store();
            let store = h.store().unwrap();

            let tree_hash = d(0xDD);
            let rec = IndexedAddress {
                tree_hash,
                balance: None,
                segment: Segment::empty(),
            };
            let write_txn = store.begin_write().unwrap();
            write_address(&write_txn, &tree_hash, &rec).unwrap();
            write_txn.commit().unwrap();

            assert!(h.address_balance(&tree_hash).is_none());
        }
    }

    mod paged_helpers {
        use super::*;

        #[test]
        fn total_count_zero_segments_zero_head_is_zero() {
            assert_eq!(total_count(0, 0), 0);
        }

        #[test]
        fn total_count_head_only() {
            assert_eq!(total_count(0, 5), 5);
            assert_eq!(total_count(0, 512), 512);
        }

        #[test]
        fn total_count_with_one_spill() {
            // 1 spill of 512 + head of 100 → 612.
            assert_eq!(total_count(1, 100), 512 + 100);
        }

        #[test]
        fn total_count_with_multiple_spills() {
            assert_eq!(total_count(3, 7), 3 * 512 + 7);
        }

        #[test]
        fn total_count_clamps_negative_segment_count_to_zero() {
            // Defense-in-depth: corrupt segment_count must not panic.
            assert_eq!(total_count(-1, 10), 10);
        }

        fn page(offset: u32, limit: u32) -> Page {
            Page { offset, limit }
        }

        #[test]
        fn slice_paged_asc_empty_returns_empty() {
            assert!(slice_paged(&[], page(0, 5), SortDir::Asc).is_empty());
        }

        #[test]
        fn slice_paged_asc_first_page() {
            let entries = vec![1, 2, 3, 4, 5];
            assert_eq!(
                slice_paged(&entries, page(0, 3), SortDir::Asc),
                vec![1, 2, 3]
            );
        }

        #[test]
        fn slice_paged_asc_offset_partway() {
            let entries = vec![1, 2, 3, 4, 5];
            assert_eq!(slice_paged(&entries, page(2, 2), SortDir::Asc), vec![3, 4]);
        }

        #[test]
        fn slice_paged_asc_offset_past_end_returns_empty() {
            let entries = vec![1, 2, 3];
            assert!(slice_paged(&entries, page(10, 5), SortDir::Asc).is_empty());
        }

        #[test]
        fn slice_paged_asc_limit_overshoots_clamps() {
            let entries = vec![1, 2, 3];
            assert_eq!(
                slice_paged(&entries, page(0, 10), SortDir::Asc),
                vec![1, 2, 3]
            );
        }

        #[test]
        fn slice_paged_desc_first_page_is_newest() {
            let entries = vec![1, 2, 3, 4, 5];
            // DESC: newest-first → reverse of [..5] gives [5, 4, 3].
            assert_eq!(
                slice_paged(&entries, page(0, 3), SortDir::Desc),
                vec![5, 4, 3]
            );
        }

        #[test]
        fn slice_paged_desc_offset_skips_newest() {
            let entries = vec![10, 20, 30, 40, 50];
            // DESC offset=2, limit=2 → skip 50, 40 → return [30, 20].
            assert_eq!(
                slice_paged(&entries, page(2, 2), SortDir::Desc),
                vec![30, 20]
            );
        }

        #[test]
        fn slice_paged_desc_full_reverse_when_limit_covers_all() {
            let entries = vec![1, 2, 3, 4];
            assert_eq!(
                slice_paged(&entries, page(0, 100), SortDir::Desc),
                vec![4, 3, 2, 1]
            );
        }

        #[test]
        fn slice_paged_desc_offset_past_end_returns_empty() {
            let entries = vec![1, 2, 3];
            assert!(slice_paged(&entries, page(10, 5), SortDir::Desc).is_empty());
        }

        #[test]
        fn slice_paged_zero_limit_returns_empty() {
            let entries = vec![1, 2, 3, 4, 5];
            assert!(slice_paged(&entries, page(0, 0), SortDir::Asc).is_empty());
            assert!(slice_paged(&entries, page(0, 0), SortDir::Desc).is_empty());
        }
    }

    mod paged_readers_with_synthetic_segment {
        //! Exercises the paged readers against an `IndexedAddress` whose
        //! segment is hand-built without going through the apply path.
        //! Box/tx records are NOT written, so the dereference returns
        //! `None` — these tests only verify the entry enumeration +
        //! `slice_paged` integration. End-to-end coverage with real
        //! box/tx records lives in `tests/paged_readers.rs`.
        use super::*;
        use crate::address::IndexedAddress;
        use crate::segment::Segment;
        use crate::segment_id::{box_segment_id, tx_segment_id};
        use crate::store::address::write_address;
        use crate::store::segment::write_spill;
        use ergo_primitives::digest::Digest32;
        use tempfile::TempDir;

        fn d(seed: u8) -> Digest32 {
            Digest32::from_bytes([seed; 32])
        }

        fn handle_with_store() -> (IndexerHandle, TempDir) {
            let tmp = TempDir::new().unwrap();
            let path = tmp.path().join("indexer.redb");
            let (store, _) = crate::store::IndexerStore::open(&path).unwrap();
            (IndexerHandle::with_store(store, 0), tmp)
        }

        fn write_synthetic_address(
            store: &crate::store::IndexerStore,
            tree_hash: Digest32,
            head_boxes: Vec<i64>,
            head_txs: Vec<i64>,
            box_spills: Vec<Vec<i64>>,
            tx_spills: Vec<Vec<i64>>,
        ) {
            let segment = Segment {
                txs: head_txs,
                boxes: head_boxes,
                box_segment_count: box_spills.len() as i32,
                tx_segment_count: tx_spills.len() as i32,
            };
            let rec = IndexedAddress {
                tree_hash,
                balance: None,
                segment,
            };
            let write_txn = store.begin_write().unwrap();
            write_address(&write_txn, &tree_hash, &rec).unwrap();
            for (i, boxes) in box_spills.iter().enumerate() {
                let seg_id = box_segment_id(&tree_hash, i as i32);
                let spill = Segment {
                    txs: Vec::new(),
                    boxes: boxes.clone(),
                    box_segment_count: 0,
                    tx_segment_count: 0,
                };
                write_spill(&write_txn, &seg_id, &spill).unwrap();
            }
            for (i, txs) in tx_spills.iter().enumerate() {
                let seg_id = tx_segment_id(&tree_hash, i as i32);
                let spill = Segment {
                    txs: txs.clone(),
                    boxes: Vec::new(),
                    box_segment_count: 0,
                    tx_segment_count: 0,
                };
                write_spill(&write_txn, &seg_id, &spill).unwrap();
            }
            write_txn.commit().unwrap();
        }

        #[test]
        fn total_boxes_with_no_spills_is_head_len() {
            let (h, _tmp) = handle_with_store();
            let store = h.store().unwrap();
            let tree_hash = d(0x01);
            write_synthetic_address(
                &store,
                tree_hash,
                vec![1, 2, 3, 4, 5],
                vec![10, 20],
                Vec::new(),
                Vec::new(),
            );
            assert_eq!(h.address_total_boxes(&tree_hash), 5);
            assert_eq!(h.address_total_txs(&tree_hash), 2);
        }

        #[test]
        fn total_boxes_with_two_spills() {
            let (h, _tmp) = handle_with_store();
            let store = h.store().unwrap();
            let tree_hash = d(0x02);
            let spill_0: Vec<i64> = (0..512).collect();
            let spill_1: Vec<i64> = (512..1024).collect();
            write_synthetic_address(
                &store,
                tree_hash,
                vec![1024, 1025, 1026],
                Vec::new(),
                vec![spill_0, spill_1],
                Vec::new(),
            );
            assert_eq!(h.address_total_boxes(&tree_hash), 1027);
        }

        #[test]
        fn total_returns_zero_for_unindexed_address() {
            let (h, _tmp) = handle_with_store();
            assert_eq!(h.address_total_boxes(&d(0xFF)), 0);
            assert_eq!(h.address_total_txs(&d(0xFF)), 0);
        }

        #[test]
        fn read_address_box_entries_returns_oldest_first_concatenation() {
            let (h, _tmp) = handle_with_store();
            let store = h.store().unwrap();
            let tree_hash = d(0x03);
            let spill_0: Vec<i64> = (100..612).collect();
            let spill_1: Vec<i64> = (700..1212).collect();
            let head: Vec<i64> = vec![2000, 2001];
            write_synthetic_address(
                &store,
                tree_hash,
                head.clone(),
                Vec::new(),
                vec![spill_0.clone(), spill_1.clone()],
                Vec::new(),
            );
            let entries = store.read_address_box_entries(&tree_hash).unwrap().unwrap();
            // Concatenation order: spill_0 ++ spill_1 ++ head.
            let mut expected: Vec<i64> = Vec::new();
            expected.extend(&spill_0);
            expected.extend(&spill_1);
            expected.extend(&head);
            assert_eq!(entries, expected);
        }

        #[test]
        fn read_address_box_entries_for_unindexed_returns_none() {
            let (h, _tmp) = handle_with_store();
            let store = h.store().unwrap();
            assert!(store.read_address_box_entries(&d(0x99)).unwrap().is_none());
        }

        #[test]
        fn read_address_box_entries_errors_on_missing_spill_row() {
            // Defense-in-depth: a parent that claims spill_0 but no spill
            // row exists is a consistency bug — surface as an error.
            let (h, _tmp) = handle_with_store();
            let store = h.store().unwrap();
            let tree_hash = d(0x04);
            let segment = Segment {
                txs: Vec::new(),
                boxes: Vec::new(),
                box_segment_count: 1,
                tx_segment_count: 0,
            };
            let rec = IndexedAddress {
                tree_hash,
                balance: None,
                segment,
            };
            let write_txn = store.begin_write().unwrap();
            write_address(&write_txn, &tree_hash, &rec).unwrap();
            write_txn.commit().unwrap();
            // Parent claims a spill but none was written → error.
            assert!(store.read_address_box_entries(&tree_hash).is_err());
        }
    }
}
