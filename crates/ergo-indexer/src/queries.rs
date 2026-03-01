//! Higher-level query functions for the extra-indexer store.
//!
//! These helpers sit on top of [`ExtraIndexerDb`] and the segment logic,
//! providing pagination, filtering, and sorting for all blockchain API
//! endpoints.

use std::cmp::Reverse;

use ergo_types::modifier_id::ModifierId;

use crate::db::*;
use crate::segment::collect_all_indexes;
use crate::types::*;

// ---------------------------------------------------------------------------
// Single-entity lookups
// ---------------------------------------------------------------------------

/// Get the current indexed height.
pub fn indexed_height(db: &ExtraIndexerDb) -> Result<u32, IndexerDbError> {
    db.get_progress_u32(&indexed_height_key())
}

/// Load a single [`IndexedErgoBox`] by box_id.
pub fn get_box(
    db: &ExtraIndexerDb,
    box_id: &[u8; 32],
) -> Result<Option<IndexedErgoBox>, IndexerDbError> {
    match db.get(box_id)? {
        Some(data) => Ok(Some(IndexedErgoBox::deserialize(&data)?)),
        None => Ok(None),
    }
}

/// Load a single [`IndexedErgoBox`] by global index.
pub fn get_box_by_index(
    db: &ExtraIndexerDb,
    n: u64,
) -> Result<Option<IndexedErgoBox>, IndexerDbError> {
    let key = numeric_box_key(n);
    match db.get(&key)? {
        Some(data) => {
            let nbi = NumericBoxIndex::deserialize(&data)?;
            get_box(db, &nbi.box_id.0)
        }
        None => Ok(None),
    }
}

/// Load a single [`IndexedErgoTransaction`] by tx_id.
pub fn get_tx(
    db: &ExtraIndexerDb,
    tx_id: &[u8; 32],
) -> Result<Option<IndexedErgoTransaction>, IndexerDbError> {
    match db.get(tx_id)? {
        Some(data) => Ok(Some(IndexedErgoTransaction::deserialize(&data)?)),
        None => Ok(None),
    }
}

/// Load a single [`IndexedErgoTransaction`] by global index.
pub fn get_tx_by_index(
    db: &ExtraIndexerDb,
    n: u64,
) -> Result<Option<IndexedErgoTransaction>, IndexerDbError> {
    let key = numeric_tx_key(n);
    match db.get(&key)? {
        Some(data) => {
            let nti = NumericTxIndex::deserialize(&data)?;
            get_tx(db, &nti.tx_id.0)
        }
        None => Ok(None),
    }
}

/// Load an [`IndexedToken`] by token ID.
pub fn get_token(
    db: &ExtraIndexerDb,
    token_id: &ModifierId,
) -> Result<Option<IndexedToken>, IndexerDbError> {
    let key = token_key(token_id);
    match db.get(&key)? {
        Some(data) => Ok(Some(IndexedToken::deserialize(&data)?)),
        None => Ok(None),
    }
}

/// Load an [`IndexedErgoAddress`] by ErgoTree bytes.
pub fn get_address(
    db: &ExtraIndexerDb,
    ergo_tree_bytes: &[u8],
) -> Result<Option<IndexedErgoAddress>, IndexerDbError> {
    let key = tree_hash_key(ergo_tree_bytes);
    match db.get(&key)? {
        Some(data) => Ok(Some(IndexedErgoAddress::deserialize(&data)?)),
        None => Ok(None),
    }
}

// ---------------------------------------------------------------------------
// Paginated box queries
// ---------------------------------------------------------------------------

/// Internal helper: paginate and resolve box indexes to [`IndexedErgoBox`].
///
/// Takes a raw `Vec<i64>` of signed box indexes (positive = unspent,
/// negative = spent), applies unspent filtering, sorts, paginates, and
/// resolves each index to a full box record.
///
/// Returns `(items, total_count)` where `total_count` is the number of
/// items *after* filtering but *before* pagination.
fn paginate_box_indexes(
    db: &ExtraIndexerDb,
    all_indexes: Vec<i64>,
    offset: u32,
    limit: u32,
    unspent_only: bool,
    sort_desc: bool,
) -> Result<(Vec<IndexedErgoBox>, u64), IndexerDbError> {
    // Filter
    let mut filtered: Vec<i64> = if unspent_only {
        all_indexes.into_iter().filter(|&i| i > 0).collect()
    } else {
        all_indexes
    };

    // Sort by unsigned absolute value of the index
    if sort_desc {
        filtered.sort_by_key(|v| Reverse(v.unsigned_abs()));
    } else {
        filtered.sort_by_key(|v| v.unsigned_abs());
    }

    let total = filtered.len() as u64;

    // Paginate
    let page: Vec<i64> = filtered
        .into_iter()
        .skip(offset as usize)
        .take(limit as usize)
        .collect();

    // Resolve each global index to a full box record
    let mut boxes = Vec::with_capacity(page.len());
    for idx in page {
        let global_idx = idx.unsigned_abs();
        if let Some(b) = get_box_by_index(db, global_idx)? {
            boxes.push(b);
        }
    }

    Ok((boxes, total))
}

/// Load boxes by address (paginated).
///
/// Returns `(items, total_count)`.
pub fn boxes_by_address(
    db: &ExtraIndexerDb,
    ergo_tree_bytes: &[u8],
    offset: u32,
    limit: u32,
    unspent_only: bool,
    sort_desc: bool,
) -> Result<(Vec<IndexedErgoBox>, u64), IndexerDbError> {
    let key = tree_hash_key(ergo_tree_bytes);
    let address = match db.get(&key)? {
        Some(data) => IndexedErgoAddress::deserialize(&data)?,
        None => return Ok((Vec::new(), 0)),
    };

    let all_indexes = collect_all_indexes(
        &address.box_indexes,
        db,
        &key,
        address.box_segment_count,
        true,
    )?;

    paginate_box_indexes(db, all_indexes, offset, limit, unspent_only, sort_desc)
}

/// Load boxes by token ID (paginated).
///
/// Returns `(items, total_count)`.
pub fn boxes_by_token(
    db: &ExtraIndexerDb,
    token_id: &ModifierId,
    offset: u32,
    limit: u32,
    unspent_only: bool,
    sort_desc: bool,
) -> Result<(Vec<IndexedErgoBox>, u64), IndexerDbError> {
    let key = token_key(token_id);
    let token = match db.get(&key)? {
        Some(data) => IndexedToken::deserialize(&data)?,
        None => return Ok((Vec::new(), 0)),
    };

    let all_indexes =
        collect_all_indexes(&token.box_indexes, db, &key, token.box_segment_count, true)?;

    paginate_box_indexes(db, all_indexes, offset, limit, unspent_only, sort_desc)
}

/// Load boxes by contract template hash (paginated).
///
/// Returns `(items, total_count)`.
pub fn boxes_by_template(
    db: &ExtraIndexerDb,
    template_bytes: &[u8],
    offset: u32,
    limit: u32,
    unspent_only: bool,
    sort_desc: bool,
) -> Result<(Vec<IndexedErgoBox>, u64), IndexerDbError> {
    let key = template_hash_key(template_bytes);
    let template = match db.get(&key)? {
        Some(data) => IndexedContractTemplate::deserialize(&data)?,
        None => return Ok((Vec::new(), 0)),
    };

    let all_indexes = collect_all_indexes(
        &template.box_indexes,
        db,
        &key,
        template.box_segment_count,
        true,
    )?;

    paginate_box_indexes(db, all_indexes, offset, limit, unspent_only, sort_desc)
}

// ---------------------------------------------------------------------------
// Paginated transaction queries
// ---------------------------------------------------------------------------

/// Load transactions by address (paginated).
///
/// Returns `(items, total_count)`.
pub fn txs_by_address(
    db: &ExtraIndexerDb,
    ergo_tree_bytes: &[u8],
    offset: u32,
    limit: u32,
    sort_desc: bool,
) -> Result<(Vec<IndexedErgoTransaction>, u64), IndexerDbError> {
    let key = tree_hash_key(ergo_tree_bytes);
    let address = match db.get(&key)? {
        Some(data) => IndexedErgoAddress::deserialize(&data)?,
        None => return Ok((Vec::new(), 0)),
    };

    let all_indexes = collect_all_indexes(
        &address.tx_indexes,
        db,
        &key,
        address.tx_segment_count,
        false,
    )?;

    // Sort by unsigned absolute value
    let mut sorted = all_indexes;
    if sort_desc {
        sorted.sort_by_key(|v| Reverse(v.unsigned_abs()));
    } else {
        sorted.sort_by_key(|v| v.unsigned_abs());
    }

    let total = sorted.len() as u64;

    // Paginate
    let page: Vec<i64> = sorted
        .into_iter()
        .skip(offset as usize)
        .take(limit as usize)
        .collect();

    // Resolve each global index to a full tx record
    let mut txs = Vec::with_capacity(page.len());
    for idx in page {
        let global_idx = idx.unsigned_abs();
        if let Some(tx) = get_tx_by_index(db, global_idx)? {
            txs.push(tx);
        }
    }

    Ok((txs, total))
}

// ---------------------------------------------------------------------------
// Range queries (for numeric iteration)
// ---------------------------------------------------------------------------

/// Iterate `NumericTxIndex` from `offset` to `offset + limit`, returning
/// tx_ids as `[u8; 32]`.
pub fn tx_id_range(
    db: &ExtraIndexerDb,
    offset: u64,
    limit: u32,
) -> Result<Vec<[u8; 32]>, IndexerDbError> {
    let mut ids = Vec::with_capacity(limit as usize);
    for n in offset..offset + limit as u64 {
        let key = numeric_tx_key(n);
        match db.get(&key)? {
            Some(data) => {
                let nti = NumericTxIndex::deserialize(&data)?;
                ids.push(nti.tx_id.0);
            }
            None => break,
        }
    }
    Ok(ids)
}

/// Iterate `NumericBoxIndex` from `offset` to `offset + limit`, returning
/// box_ids as `[u8; 32]`.
pub fn box_id_range(
    db: &ExtraIndexerDb,
    offset: u64,
    limit: u32,
) -> Result<Vec<[u8; 32]>, IndexerDbError> {
    let mut ids = Vec::with_capacity(limit as usize);
    for n in offset..offset + limit as u64 {
        let key = numeric_box_key(n);
        match db.get(&key)? {
            Some(data) => {
                let nbi = NumericBoxIndex::deserialize(&data)?;
                ids.push(nbi.box_id.0);
            }
            None => break,
        }
    }
    Ok(ids)
}

// ---------------------------------------------------------------------------
// Balance query
// ---------------------------------------------------------------------------

/// Return the [`BalanceInfo`] for an address identified by ErgoTree bytes.
///
/// Returns `None` if the address has never been indexed.
pub fn balance_for_address(
    db: &ExtraIndexerDb,
    ergo_tree_bytes: &[u8],
) -> Result<Option<BalanceInfo>, IndexerDbError> {
    let key = tree_hash_key(ergo_tree_bytes);
    match db.get(&key)? {
        Some(data) => {
            let address = IndexedErgoAddress::deserialize(&data)?;
            Ok(Some(address.balance))
        }
        None => Ok(None),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_box_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let db = ExtraIndexerDb::open(tmp.path()).unwrap();
        let missing_id = [0xFFu8; 32];
        let result = get_box(&db, &missing_id).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn boxes_by_address_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let db = ExtraIndexerDb::open(tmp.path()).unwrap();
        let (boxes, total) =
            boxes_by_address(&db, b"nonexistent ergo tree", 0, 10, false, false).unwrap();
        assert!(boxes.is_empty());
        assert_eq!(total, 0);
    }

    #[test]
    fn tx_id_range_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let db = ExtraIndexerDb::open(tmp.path()).unwrap();
        let ids = tx_id_range(&db, 0, 10).unwrap();
        assert!(ids.is_empty());
    }
}
