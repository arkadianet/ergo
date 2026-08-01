use crate::status::IndexerStatus;
use crate::types::{IndexedErgoBox, IndexedErgoTransaction};
use crate::{BoxId, TemplateHash, TokenId, TreeHash, TxId};

/// Page descriptor matching Scala's `(offset, limit)` paging
/// (`BlockchainApiRoute.scala:41`). `MaxItems = 16384` per route is
/// enforced at the API layer — the trait does not validate.
#[derive(Debug, Clone, Copy)]
pub struct Page {
    pub offset: u32,
    pub limit: u32,
}

/// Sort direction for paged surfaces. Default `Desc` per Scala
/// (`BlockchainApiRoute.scala:50, 52, 57`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortDir {
    Asc,
    Desc,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexerReadError {
    message: String,
}

impl IndexerReadError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for IndexerReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for IndexerReadError {}

/// Confirmed-only indexer reader surface. Mempool overlay is layered
/// at the API handler. Existing infallible reads retain their
/// compatibility behavior; fallible adapters expose storage failures
/// to callers that need to distinguish them from missing data.
///
/// The full 25-route surface is declared up-front; per-phase
/// implementations on `IndexerStore` fill in the methods
/// progressively. Methods declared but unimplemented at a given stage
/// have no callers because their corresponding routes are unmounted.
pub trait IndexerQuery: Send + Sync + 'static {
    fn indexed_height(&self) -> u64;
    fn status(&self) -> IndexerStatus;

    /// Live health snapshot for the operator surface (`/api/v1/indexer/status`):
    /// the durable self-repair markers plus running totals. Deliberately
    /// separate from `status()` — a `CaughtUp` index can still be degraded
    /// (repair pending / completed-with-skips), and the operator UI must be
    /// able to say so.
    ///
    /// Default impl returns the healthy-empty snapshot so fixture / stub
    /// implementations stay terse; production `IndexerHandle` overrides with
    /// the real meta reads.
    fn health(&self) -> IndexerHealthDto {
        IndexerHealthDto::default()
    }

    /// Convenience wrapper for non-router callers (metrics, logs,
    /// tests). The normative API gate primitive is `status()` — the
    /// axum middleware needs the full enum to select between the
    /// `503 indexer-syncing` and `503 indexer-halted` envelopes,
    /// which a bare boolean cannot express.
    fn is_caught_up(&self) -> bool {
        matches!(self.status(), IndexerStatus::CaughtUp)
    }

    fn box_by_id(&self, box_id: &BoxId) -> Option<IndexedBoxDto>;

    fn try_box_by_id(&self, box_id: &BoxId) -> Result<Option<IndexedBoxDto>, IndexerReadError> {
        Ok(self.box_by_id(box_id))
    }

    fn box_by_global_index(&self, n: u64) -> Option<IndexedBoxDto>;
    fn boxes_by_global_range(&self, lo: u64, hi: u64) -> Vec<IndexedBoxDto>;

    fn tx_by_id(&self, tx_id: &TxId) -> Option<IndexedTxDto>;
    fn tx_by_global_index(&self, n: u64) -> Option<IndexedTxDto>;
    fn txs_by_global_range(&self, lo: u64, hi: u64) -> Vec<IndexedTxDto>;

    fn address_balance(&self, tree_hash: &TreeHash) -> Option<BalanceDto>;
    fn address_txs_paged(&self, tree_hash: &TreeHash, p: Page, dir: SortDir) -> Vec<IndexedTxDto>;
    fn address_boxes_paged(
        &self,
        tree_hash: &TreeHash,
        p: Page,
        dir: SortDir,
    ) -> Vec<IndexedBoxDto>;
    fn address_unspent_paged(
        &self,
        tree_hash: &TreeHash,
        p: Page,
        dir: SortDir,
    ) -> Vec<IndexedBoxDto>;
    fn address_total_txs(&self, tree_hash: &TreeHash) -> u64;
    fn address_total_boxes(&self, tree_hash: &TreeHash) -> u64;

    fn template_boxes_paged(&self, template_hash: &TemplateHash, p: Page) -> Vec<IndexedBoxDto>;
    fn template_unspent_paged(
        &self,
        template_hash: &TemplateHash,
        p: Page,
        dir: SortDir,
    ) -> Vec<IndexedBoxDto>;

    fn try_template_unspent_paged(
        &self,
        template_hash: &TemplateHash,
        p: Page,
        dir: SortDir,
    ) -> Result<Vec<IndexedBoxDto>, IndexerReadError> {
        Ok(self.template_unspent_paged(template_hash, p, dir))
    }

    fn template_total_boxes(&self, template_hash: &TemplateHash) -> u64;

    fn token_by_id(&self, token_id: &TokenId) -> Option<IndexedTokenDto>;

    fn try_token_by_id(
        &self,
        token_id: &TokenId,
    ) -> Result<Option<IndexedTokenDto>, IndexerReadError> {
        Ok(self.token_by_id(token_id))
    }

    fn tokens_by_ids(&self, ids: &[TokenId]) -> Vec<IndexedTokenDto>;
    fn token_boxes_paged(&self, token_id: &TokenId, p: Page) -> Vec<IndexedBoxDto>;
    fn token_unspent_paged(&self, token_id: &TokenId, p: Page, dir: SortDir) -> Vec<IndexedBoxDto>;
    fn token_total_boxes(&self, token_id: &TokenId) -> u64;

    /// Paged scan of `unspent_by_creation_height` for boxes whose
    /// `creationHeight ≤ height_cutoff`. Sort direction picks the
    /// scan side: `Asc` returns oldest-first, `Desc` returns
    /// newest-first. Caller handles `(offset, limit)` paging plus the
    /// `H_cutoff = query_height - StoragePeriod` derivation; the
    /// trait method takes the resolved cutoff directly so it stays
    /// uncoupled from voted-parameter lookups.
    ///
    /// Default impl returns an empty Vec — fixture / stub
    /// implementations that don't model the storage-rent table
    /// inherit this. Production `IndexerHandle` overrides with the
    /// real redb scan.
    fn storage_rent_eligible_paged(
        &self,
        _height_cutoff: u32,
        _p: Page,
        _dir: SortDir,
    ) -> Vec<StorageRentEligibleDto> {
        Vec::new()
    }

    /// Total count of boxes with `creationHeight ≤ height_cutoff` in
    /// `unspent_by_creation_height`. Walks the same range the paged
    /// scan does, but counts only — no value decode. Used to populate
    /// the page envelope's `total` field.
    ///
    /// Default impl returns 0; production overrides.
    fn storage_rent_eligible_total(&self, _height_cutoff: u32) -> u64 {
        0
    }

    /// Paged scan of `unspent_by_creation_height` over a closed
    /// creation-height range `[height_lo, height_hi]`. Inclusive on
    /// both ends; `height_lo == height_hi` returns the single-height
    /// slice (the `maturesAt` use case); a wider range returns every
    /// row whose creation_height falls in the interval (the
    /// `maturesInRange` use case).
    ///
    /// `eligibleAt(H)` is expressible here as `(0, H − StoragePeriod)`,
    /// but the dedicated `storage_rent_eligible_paged` retains its
    /// explicit cutoff for handlers that already speak in cutoff terms.
    ///
    /// Default impl returns empty Vec.
    fn storage_rent_in_creation_range(
        &self,
        _height_lo: u32,
        _height_hi: u32,
        _p: Page,
        _dir: SortDir,
    ) -> Vec<StorageRentEligibleDto> {
        Vec::new()
    }

    /// Total count of rows whose `creationHeight ∈ [height_lo, height_hi]`.
    /// Drives the page envelope's `total` for `maturesAt` /
    /// `maturesInRange`.
    ///
    /// Default impl returns 0.
    fn storage_rent_total_in_creation_range(&self, _height_lo: u32, _height_hi: u32) -> u64 {
        0
    }
}

// DTO surface — what the trait methods return to the API layer.
//
// For boxes/txs the DTO is a transparent alias to the persisted in-memory
// type — the API layer enriches with derived fields (`address` from the
// `ErgoTree`, `blockId` / `timestamp` from the chain header, and
// `numConfirmations` from `indexer.indexed_height()`) at response time.
// Keeping the indexer surface confined to persisted data avoids
// cross-crate dependencies (chain reader, address encoder) inside the
// reader trait.
//
// Address / token / block DTOs that aren't fully wired yet remain
// placeholders — they fill in alongside their respective segment apply
// paths.

/// Live indexer-health snapshot (see [`IndexerQuery::health`]).
///
/// Field semantics mirror the durable `INDEXER_META` repair markers:
/// - `repair_pending` — the derived template/token segments are degraded and a
///   chain-free rebuild is owed or in progress.
/// - `repair_next_gi` — rebuild phase-1 cursor (boxes re-derived so far);
///   `None` when no rebuild is running (or phase 0 hasn't finished). Progress
///   percentage = `repair_next_gi / global_boxes`.
/// - `repair_skipped` — undecodable boxes a rebuild had to omit. A non-zero
///   value with `repair_pending == false` means the index completed its repair
///   knowingly incomplete (the honest marker) — surface it, never hide it.
/// - `drift_skips` — CUMULATIVE process-lifetime count of live secondary
///   sign-flips skipped on topology drift. Diagnostic only: resets on restart
///   and is NOT cleared by a successful rebuild.
/// - `global_boxes` / `global_txs` — running totals from the meta counters.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IndexerHealthDto {
    pub repair_pending: bool,
    pub repair_next_gi: Option<u64>,
    pub repair_skipped: u64,
    pub drift_skips: u64,
    pub global_boxes: u64,
    pub global_txs: u64,
}

/// Confirmed indexed-box record.
pub type IndexedBoxDto = IndexedErgoBox;

/// Confirmed indexed-tx record.
pub type IndexedTxDto = IndexedErgoTransaction;

/// One row of `unspent_by_creation_height`. Carries the immutable
/// fields rent computation needs without re-fetching `INDEXED_BOX`.
/// `box_bytes_len` is the canonical serialized `ErgoBox` length stored
/// as `i32` so the rent helper consumes it without re-cast.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageRentEligibleDto {
    pub creation_height: u32,
    pub global_box_index: i64,
    pub box_id: BoxId,
    pub box_value: u64,
    pub box_bytes_len: i32,
}

/// Address balance bundle (ERG nanos + tokens).
///
/// Mirrors Scala `BalanceInfo` (`BalanceInfo.scala:18-23`) on the
/// reader surface. `tokens` is order-preserving — the underlying
/// `BalanceInfo.tokens` `ArrayBuffer` records first-touch insertion
/// order, and external callers diff against Scala byte-for-byte.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BalanceDto {
    pub nano_ergs: i64,
    pub tokens: Vec<(TokenId, i64)>,
}

/// Indexed token record (mint metadata).
///
/// Mirrors the openapi `IndexedToken` schema (`openapi.yaml:378-412`):
/// `id`, `boxId`, `emissionAmount`, `name`, `description`, `decimals`.
/// All six fields are required JSON properties — well-formed records
/// constructed via `IndexedToken::from_box` always populate them, even
/// when the source registers are absent (defaults: `""`, `""`, `0`).
///
/// `emission_amount` is `i64` to match Scala's signed `Long` JSON shape
/// (`emissionAmount: int64, minimum: 1`). The persisted record stores
/// `u64` to keep the wire format unsigned (avoids round-trip wrap), and
/// the projection from `IndexedToken` to this DTO casts via `as i64`.
/// Realistic token emissions never approach `u64::MAX` so the cast is
/// loss-free in practice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedTokenDto {
    pub token_id: TokenId,
    pub creating_box_id: BoxId,
    pub emission_amount: i64,
    pub name: String,
    pub description: String,
    pub decimals: i32,
}

/// Indexed block (header + transactions reassembly).
#[derive(Debug, Clone)]
pub struct IndexedBlockDto;

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[derive(Default)]
    struct DefaultAdapterStub {
        box_reads: AtomicUsize,
        template_reads: AtomicUsize,
        token_reads: AtomicUsize,
    }

    impl IndexerQuery for DefaultAdapterStub {
        fn indexed_height(&self) -> u64 {
            0
        }

        fn status(&self) -> IndexerStatus {
            IndexerStatus::CaughtUp
        }

        fn box_by_id(&self, _box_id: &BoxId) -> Option<IndexedBoxDto> {
            self.box_reads.fetch_add(1, Ordering::Relaxed);
            None
        }

        fn box_by_global_index(&self, _n: u64) -> Option<IndexedBoxDto> {
            None
        }

        fn boxes_by_global_range(&self, _lo: u64, _hi: u64) -> Vec<IndexedBoxDto> {
            Vec::new()
        }

        fn tx_by_id(&self, _tx_id: &TxId) -> Option<IndexedTxDto> {
            None
        }

        fn tx_by_global_index(&self, _n: u64) -> Option<IndexedTxDto> {
            None
        }

        fn txs_by_global_range(&self, _lo: u64, _hi: u64) -> Vec<IndexedTxDto> {
            Vec::new()
        }

        fn address_balance(&self, _tree_hash: &TreeHash) -> Option<BalanceDto> {
            None
        }

        fn address_txs_paged(
            &self,
            _tree_hash: &TreeHash,
            _p: Page,
            _dir: SortDir,
        ) -> Vec<IndexedTxDto> {
            Vec::new()
        }

        fn address_boxes_paged(
            &self,
            _tree_hash: &TreeHash,
            _p: Page,
            _dir: SortDir,
        ) -> Vec<IndexedBoxDto> {
            Vec::new()
        }

        fn address_unspent_paged(
            &self,
            _tree_hash: &TreeHash,
            _p: Page,
            _dir: SortDir,
        ) -> Vec<IndexedBoxDto> {
            Vec::new()
        }

        fn address_total_txs(&self, _tree_hash: &TreeHash) -> u64 {
            0
        }

        fn address_total_boxes(&self, _tree_hash: &TreeHash) -> u64 {
            0
        }

        fn template_boxes_paged(
            &self,
            _template_hash: &TemplateHash,
            _p: Page,
        ) -> Vec<IndexedBoxDto> {
            Vec::new()
        }

        fn template_unspent_paged(
            &self,
            _template_hash: &TemplateHash,
            _p: Page,
            _dir: SortDir,
        ) -> Vec<IndexedBoxDto> {
            self.template_reads.fetch_add(1, Ordering::Relaxed);
            Vec::new()
        }

        fn template_total_boxes(&self, _template_hash: &TemplateHash) -> u64 {
            0
        }

        fn token_by_id(&self, _token_id: &TokenId) -> Option<IndexedTokenDto> {
            self.token_reads.fetch_add(1, Ordering::Relaxed);
            None
        }

        fn tokens_by_ids(&self, _ids: &[TokenId]) -> Vec<IndexedTokenDto> {
            Vec::new()
        }

        fn token_boxes_paged(&self, _token_id: &TokenId, _p: Page) -> Vec<IndexedBoxDto> {
            Vec::new()
        }

        fn token_unspent_paged(
            &self,
            _token_id: &TokenId,
            _p: Page,
            _dir: SortDir,
        ) -> Vec<IndexedBoxDto> {
            Vec::new()
        }

        fn token_total_boxes(&self, _token_id: &TokenId) -> u64 {
            0
        }
    }

    // ----- happy path -----

    #[test]
    fn fallible_defaults_delegate_to_existing_infallible_methods() {
        let stub = DefaultAdapterStub::default();
        let box_id = BoxId::from_bytes([0x11; 32]);
        let template_hash = TemplateHash::from_bytes([0x22; 32]);
        let token_id = TokenId::from_bytes([0x33; 32]);

        assert_eq!(stub.try_box_by_id(&box_id), Ok(None));
        assert_eq!(
            stub.try_template_unspent_paged(
                &template_hash,
                Page {
                    offset: 4,
                    limit: 10,
                },
                SortDir::Asc,
            ),
            Ok(Vec::new())
        );
        assert_eq!(stub.try_token_by_id(&token_id), Ok(None));
        assert_eq!(stub.box_reads.load(Ordering::Relaxed), 1);
        assert_eq!(stub.template_reads.load(Ordering::Relaxed), 1);
        assert_eq!(stub.token_reads.load(Ordering::Relaxed), 1);
    }
}
