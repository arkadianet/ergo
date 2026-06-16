//! Persistent storage of active protocol parameters per epoch.
//!
//! One row per epoch start (key `epoch_start_height` as big-endian
//! `u64`), plus a height-0 row holding Scala launch parameters so the
//! read path always finds *some* row.
//!
//! The `ActiveProtocolParameters` type, its codec, parser, and the
//! `scala_launch()` constructor live in `ergo_validation::active_params`.
//! This module owns only the redb table definition and the small set
//! of read/write helpers used by the store.

// `dead_code` is allowed because the helpers below are exercised by
// integration tests and store.rs paths that aren't reachable from the
// crate's public re-exports — the production wiring is still narrowing.
#![allow(dead_code)]

use ergo_validation::ActiveProtocolParameters;
use redb::{ReadableTable, TableDefinition, WriteTransaction};

pub(crate) const VOTED_PARAMS: TableDefinition<u64, &[u8]> = TableDefinition::new("voted_params");

/// Insert or overwrite the row at the parameters' `epoch_start_height`.
///
/// Returns an error if the parameter set fails its own invariant check
/// (see `ActiveProtocolParameters::validate`) or if the redb operation
/// fails. The caller is expected to be holding the same `write_txn`
/// that mutates the AVL / chain_index / state_meta tables, so the
/// failure aborts the whole epoch-boundary commit.
pub(crate) fn insert(
    txn: &WriteTransaction,
    params: &ActiveProtocolParameters,
) -> Result<(), VotedParamsWriteError> {
    let bytes = params
        .serialize()
        .map_err(VotedParamsWriteError::InvalidParams)?;
    let mut t = txn.open_table(VOTED_PARAMS)?;
    t.insert(params.epoch_start_height as u64, bytes.as_slice())?;
    Ok(())
}

/// Failures returned by the `voted_params` write helpers.
#[derive(Debug, thiserror::Error)]
pub enum VotedParamsWriteError {
    /// The supplied [`ActiveProtocolParameters`] failed its
    /// `validate()` invariant check.
    #[error("voted_params: parameter set failed its invariant check: {0}")]
    InvalidParams(#[source] ergo_validation::ActiveParamsError),
    /// Underlying redb operation failed.
    #[error("voted_params: db error: {0}")]
    Db(#[source] Box<redb::Error>),
}

impl From<redb::Error> for VotedParamsWriteError {
    fn from(e: redb::Error) -> Self {
        VotedParamsWriteError::Db(Box::new(e))
    }
}

impl From<redb::TableError> for VotedParamsWriteError {
    fn from(e: redb::TableError) -> Self {
        VotedParamsWriteError::Db(Box::new(e.into()))
    }
}

impl From<redb::StorageError> for VotedParamsWriteError {
    fn from(e: redb::StorageError) -> Self {
        VotedParamsWriteError::Db(Box::new(e.into()))
    }
}

/// Read the latest row with `key <= height` (the active set for `height`).
///
/// Returns `Ok(None)` only if the table is empty — once `StateStore::open`
/// has run the active-params reconcile path, the height-0 row is always
/// present and this call always returns `Some`.
///
/// Cross-checks the redb table key against the embedded
/// `epoch_start_height` in the deserialized row. A mismatch implies
/// either a writer bug or on-disk corruption; either way, surfacing
/// the wrong active set is worse than failing loud.
pub(crate) fn read_latest_at(
    txn: &redb::ReadTransaction,
    height: u32,
) -> Result<Option<ActiveProtocolParameters>, ActiveParamsReadError> {
    let t = match txn.open_table(VOTED_PARAMS) {
        Ok(t) => t,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let mut iter = t.range(0u64..=height as u64)?;
    let Some(entry) = iter.next_back() else {
        return Ok(None);
    };
    let (k, val) = entry?;
    let key = k.value();
    let bytes = val.value();
    let params = ActiveProtocolParameters::deserialize(bytes)
        .map_err(|e| ActiveParamsReadError::Decode { height, source: e })?;
    if params.epoch_start_height as u64 != key {
        return Err(ActiveParamsReadError::KeyMismatch {
            row_key: key,
            embedded_height: params.epoch_start_height,
        });
    }
    Ok(Some(params))
}

/// Fold every `voted_params` row's `activated_update` from key 0 up to
/// the highest row with `key <= height`, yielding the cumulative
/// [`ergo_validation::ErgoValidationSettings`] active at `height`.
///
/// An absent or empty table yields `ErgoValidationSettings::empty()` —
/// the genesis baseline before any soft-fork activation. This is the
/// single source of truth for both the UTXO and digest backends'
/// validation-settings cache; each holds an `Arc<Database>` and calls
/// it through its own read txn.
pub(crate) fn compute_validation_settings_at(
    txn: &redb::ReadTransaction,
    height: u32,
) -> Result<ergo_validation::ErgoValidationSettings, ActiveParamsReadError> {
    let t = match txn.open_table(VOTED_PARAMS) {
        Ok(t) => t,
        Err(redb::TableError::TableDoesNotExist(_)) => {
            return Ok(ergo_validation::ErgoValidationSettings::empty());
        }
        Err(e) => return Err(e.into()),
    };
    let mut settings = ergo_validation::ErgoValidationSettings::empty();
    for entry in t.range(0u64..=height as u64)? {
        let (_, val) = entry?;
        let row = ActiveProtocolParameters::deserialize(val.value())
            .map_err(|e| ActiveParamsReadError::Decode { height, source: e })?;
        settings = settings.updated(&row.activated_update);
    }
    Ok(settings)
}

/// Every `voted_params` row in ascending epoch-start-height order.
///
/// One row per epoch boundary (plus the height-0 genesis row), so the table
/// is sparse — at most one entry per `voting_length` blocks. The operator
/// votes-history endpoint walks these and diffs consecutive rows to recover
/// the parameter-change timeline. An absent table yields an empty vec.
pub(crate) fn read_all(
    txn: &redb::ReadTransaction,
) -> Result<Vec<ActiveProtocolParameters>, ActiveParamsReadError> {
    let t = match txn.open_table(VOTED_PARAMS) {
        Ok(t) => t,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    let mut out = Vec::new();
    for entry in t.iter()? {
        let (k, val) = entry?;
        let key = k.value();
        let params = ActiveProtocolParameters::deserialize(val.value()).map_err(|e| {
            ActiveParamsReadError::Decode {
                height: key as u32,
                source: e,
            }
        })?;
        if params.epoch_start_height as u64 != key {
            return Err(ActiveParamsReadError::KeyMismatch {
                row_key: key,
                embedded_height: params.epoch_start_height,
            });
        }
        out.push(params);
    }
    Ok(out)
}

/// Collect the set of keys present in `voted_params`.
pub(crate) fn present_keys(
    txn: &redb::ReadTransaction,
) -> Result<std::collections::BTreeSet<u64>, ActiveParamsReadError> {
    let t = match txn.open_table(VOTED_PARAMS) {
        Ok(t) => t,
        Err(redb::TableError::TableDoesNotExist(_)) => {
            return Ok(std::collections::BTreeSet::new());
        }
        Err(e) => return Err(e.into()),
    };
    let mut keys = std::collections::BTreeSet::new();
    for entry in t.iter()? {
        let (k, _) = entry?;
        keys.insert(k.value());
    }
    Ok(keys)
}

/// Delete every row with `key > target_height` from an open write txn.
/// Used by `rollback_to`.
pub(crate) fn delete_above(
    txn: &WriteTransaction,
    target_height: u32,
) -> Result<(), VotedParamsWriteError> {
    let mut t = txn.open_table(VOTED_PARAMS)?;
    let lower = (target_height as u64).saturating_add(1);
    let mut to_delete: Vec<u64> = Vec::new();
    for entry in t.range(lower..=u64::MAX)? {
        let (k, _) = entry?;
        to_delete.push(k.value());
    }
    for k in to_delete {
        t.remove(k)?;
    }
    Ok(())
}

/// Failures returned by the `voted_params` read helpers.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ActiveParamsReadError {
    /// Underlying redb read failed.
    #[error("voted_params: db error")]
    Db(#[source] Box<redb::Error>),
    /// A row was read but its body did not parse as
    /// `ActiveProtocolParameters`.
    #[error("voted_params: row at or below height {height} failed to decode")]
    Decode {
        /// Query height the read was for.
        height: u32,
        /// Underlying decode error from `ergo-validation`.
        source: ergo_validation::ActiveParamsError,
    },
    /// A row's redb key did not match the `epoch_start_height` embedded
    /// in its body — implies on-disk corruption or a writer bug.
    #[error(
        "voted_params: row key {row_key} does not match embedded epoch_start_height {embedded_height} \
         (db corruption or writer bug)"
    )]
    KeyMismatch {
        /// Key the row is stored under.
        row_key: u64,
        /// `epoch_start_height` carried by the row body.
        embedded_height: u32,
    },
}

impl From<redb::Error> for ActiveParamsReadError {
    fn from(e: redb::Error) -> Self {
        ActiveParamsReadError::Db(Box::new(e))
    }
}

impl From<redb::TableError> for ActiveParamsReadError {
    fn from(e: redb::TableError) -> Self {
        ActiveParamsReadError::Db(Box::new(e.into()))
    }
}

impl From<redb::StorageError> for ActiveParamsReadError {
    fn from(e: redb::StorageError) -> Self {
        ActiveParamsReadError::Db(Box::new(e.into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_validation::scala_launch;
    use redb::Database;
    use tempfile::tempdir;

    fn open_db() -> (tempfile::TempDir, Database) {
        let dir = tempdir().unwrap();
        let db = Database::create(dir.path().join("voted_params_test.redb")).unwrap();
        (dir, db)
    }

    // ----- happy path -----

    #[test]
    fn insert_then_read_latest_at_returns_row() {
        let (_dir, db) = open_db();
        let txn = crate::begin_write_qr(&db).unwrap();
        insert(&txn, &scala_launch()).unwrap();
        txn.commit().unwrap();

        let r = db.begin_read().unwrap();
        let p = read_latest_at(&r, 100).unwrap().unwrap();
        assert_eq!(p, scala_launch());
    }

    #[test]
    fn read_latest_at_picks_highest_key_le_height() {
        let (_dir, db) = open_db();
        let mut launch = scala_launch();
        let mut at_1024 = scala_launch();
        at_1024.epoch_start_height = 1024;
        at_1024.input_cost = 9999;
        let mut at_2048 = scala_launch();
        at_2048.epoch_start_height = 2048;
        at_2048.input_cost = 8888;

        let txn = crate::begin_write_qr(&db).unwrap();
        insert(&txn, &launch).unwrap();
        insert(&txn, &at_1024).unwrap();
        insert(&txn, &at_2048).unwrap();
        txn.commit().unwrap();

        let r = db.begin_read().unwrap();
        assert_eq!(read_latest_at(&r, 0).unwrap().unwrap(), launch);
        assert_eq!(read_latest_at(&r, 1023).unwrap().unwrap(), launch);
        launch.epoch_start_height = 0;
        assert_eq!(read_latest_at(&r, 1024).unwrap().unwrap(), at_1024);
        assert_eq!(read_latest_at(&r, 2047).unwrap().unwrap(), at_1024);
        assert_eq!(read_latest_at(&r, 2048).unwrap().unwrap(), at_2048);
        assert_eq!(read_latest_at(&r, 999_999).unwrap().unwrap(), at_2048);
    }

    #[test]
    fn read_latest_at_returns_none_when_table_missing() {
        let (_dir, db) = open_db();
        let r = db.begin_read().unwrap();
        assert!(read_latest_at(&r, 0).unwrap().is_none());
    }

    #[test]
    fn read_latest_at_returns_none_when_no_row_le_height() {
        let (_dir, db) = open_db();
        let mut at_1024 = scala_launch();
        at_1024.epoch_start_height = 1024;
        let txn = crate::begin_write_qr(&db).unwrap();
        insert(&txn, &at_1024).unwrap();
        txn.commit().unwrap();

        let r = db.begin_read().unwrap();
        assert!(read_latest_at(&r, 1023).unwrap().is_none());
    }

    #[test]
    fn read_latest_at_rejects_key_embedded_height_mismatch() {
        let (_dir, db) = open_db();
        // Write a row whose key is 2048 but whose embedded height is 1024.
        let mut params = scala_launch();
        params.epoch_start_height = 1024;
        let bytes = params.serialize().unwrap();
        let txn = crate::begin_write_qr(&db).unwrap();
        {
            let mut t = txn.open_table(VOTED_PARAMS).unwrap();
            t.insert(2048u64, bytes.as_slice()).unwrap();
        }
        txn.commit().unwrap();

        let r = db.begin_read().unwrap();
        let err = read_latest_at(&r, 9999).unwrap_err();
        match err {
            ActiveParamsReadError::KeyMismatch {
                row_key,
                embedded_height,
            } => {
                assert_eq!(row_key, 2048);
                assert_eq!(embedded_height, 1024);
            }
            other => panic!("expected KeyMismatch, got {other:?}"),
        }
    }

    #[test]
    fn delete_above_removes_only_rows_strictly_greater() {
        let (_dir, db) = open_db();
        let launch = scala_launch();
        let mut at_1024 = scala_launch();
        at_1024.epoch_start_height = 1024;
        let mut at_2048 = scala_launch();
        at_2048.epoch_start_height = 2048;
        let mut at_3072 = scala_launch();
        at_3072.epoch_start_height = 3072;

        let txn = crate::begin_write_qr(&db).unwrap();
        insert(&txn, &launch).unwrap();
        insert(&txn, &at_1024).unwrap();
        insert(&txn, &at_2048).unwrap();
        insert(&txn, &at_3072).unwrap();
        txn.commit().unwrap();

        let txn = crate::begin_write_qr(&db).unwrap();
        delete_above(&txn, 1024).unwrap();
        txn.commit().unwrap();

        let r = db.begin_read().unwrap();
        let keys = present_keys(&r).unwrap();
        assert_eq!(keys, [0, 1024].into_iter().collect());

        // Genesis row is preserved; trying to delete at target=u32::MAX is a no-op.
        let txn = crate::begin_write_qr(&db).unwrap();
        delete_above(&txn, u32::MAX).unwrap();
        txn.commit().unwrap();
        let r = db.begin_read().unwrap();
        let keys = present_keys(&r).unwrap();
        assert_eq!(keys, [0, 1024].into_iter().collect());
    }

    #[test]
    fn read_all_returns_every_row_ascending() {
        let (_dir, db) = open_db();
        let launch = scala_launch();
        let mut at_1024 = scala_launch();
        at_1024.epoch_start_height = 1024;
        let mut at_2048 = scala_launch();
        at_2048.epoch_start_height = 2048;

        // Insert out of height order; the scan must still return ascending by key.
        let txn = crate::begin_write_qr(&db).unwrap();
        insert(&txn, &at_2048).unwrap();
        insert(&txn, &launch).unwrap();
        insert(&txn, &at_1024).unwrap();
        txn.commit().unwrap();

        let r = db.begin_read().unwrap();
        let heights: Vec<u32> = read_all(&r)
            .unwrap()
            .iter()
            .map(|p| p.epoch_start_height)
            .collect();
        assert_eq!(heights, vec![0, 1024, 2048]);
    }

    #[test]
    fn read_all_empty_when_table_missing() {
        let (_dir, db) = open_db();
        let r = db.begin_read().unwrap();
        assert!(read_all(&r).unwrap().is_empty());
    }

    #[test]
    fn present_keys_empty_when_table_missing() {
        let (_dir, db) = open_db();
        let r = db.begin_read().unwrap();
        let keys = present_keys(&r).unwrap();
        assert!(keys.is_empty());
    }

    #[test]
    fn insert_rejects_invalid_extras() {
        let (_dir, db) = open_db();
        let mut p = scala_launch();
        p.extra = vec![(1, 999_999)]; // collides with named id 1
        let txn = crate::begin_write_qr(&db).unwrap();
        let err = insert(&txn, &p).unwrap_err();
        match err {
            VotedParamsWriteError::InvalidParams(_) => {}
            other => panic!("expected InvalidParams, got {other:?}"),
        }
    }
}
