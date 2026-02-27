//! Persistent header sync protocol logic.
//!
//! Provides the same sync operations as [`crate::sync`] but backed by
//! [`HistoryDb`] (RocksDB) instead of the in-memory [`crate::header_chain::HeaderChain`].

use ergo_consensus::header_validation::{
    validate_child_header, validate_genesis_header, HeaderValidationError,
};
use ergo_storage::history_db::{HistoryDb, StorageError};
use ergo_types::modifier_id::ModifierId;
use ergo_wire::header_ser::parse_header;
use ergo_wire::inv::ModifiersData;
use ergo_wire::sync_info::{ErgoSyncInfo, ErgoSyncInfoV2};
use ergo_wire::vlq::CodecError;
use thiserror::Error;

/// Maximum number of headers to include in a SyncInfo V2 message.
const MAX_SYNC_HEADERS: u32 = 10;

/// Modifier type ID for headers.
const HEADER_TYPE_ID: u8 = 101;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors arising from the persistent sync protocol.
#[derive(Debug, Error)]
pub enum PersistentSyncError {
    /// Wire-level codec error (parsing/serialization).
    #[error("codec error: {0}")]
    Codec(#[from] CodecError),

    /// Header validation failed.
    #[error("header validation error: {0}")]
    Validation(#[from] HeaderValidationError),

    /// The modifier type in the response is not the expected header type.
    #[error("unexpected modifier type: expected 101, got {0}")]
    UnexpectedModifierType(i8),

    /// A header referenced a parent that is not in our database.
    #[error("parent header not found: {0}")]
    ParentNotFound(ModifierId),

    /// Storage layer error.
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
}

// ---------------------------------------------------------------------------
// build_sync_info_persistent
// ---------------------------------------------------------------------------

/// Build an `ErgoSyncInfo` V2 message from the persistent database state.
///
/// If the database contains headers, includes the last N (up to 10) headers,
/// oldest first. If the database is empty, returns an empty V2 SyncInfo.
pub fn build_sync_info_persistent(db: &HistoryDb) -> Result<ErgoSyncInfo, PersistentSyncError> {
    let best_id = match db.best_header_id()? {
        None => {
            return Ok(ErgoSyncInfo::V2(ErgoSyncInfoV2 {
                last_headers: vec![],
            }));
        }
        Some(id) => id,
    };

    // Load the best header to determine its height.
    let best_header = db
        .load_header(&best_id)?
        .expect("best header ID set but header missing");
    let best_height = best_header.height;

    let start = if best_height > MAX_SYNC_HEADERS {
        best_height - MAX_SYNC_HEADERS + 1
    } else {
        1
    };

    let mut headers = Vec::new();
    for h in start..=best_height {
        let ids = db.header_ids_at_height(h)?;
        if let Some(id) = ids.first() {
            if let Some(header) = db.load_header(id)? {
                headers.push(header);
            }
        }
    }

    Ok(ErgoSyncInfo::V2(ErgoSyncInfoV2 {
        last_headers: headers,
    }))
}

// ---------------------------------------------------------------------------
// process_modifiers_persistent
// ---------------------------------------------------------------------------

/// Parse a `ModifiersData` response, validate each header, and store valid
/// headers into the persistent database.
///
/// Returns the count of new headers successfully added.
///
/// Headers are validated against their parent (which must already be in the
/// database or the header must be a genesis header). Headers already present
/// in the database are silently skipped.
pub fn process_modifiers_persistent(
    body: &[u8],
    db: &HistoryDb,
    now_ms: u64,
) -> Result<u32, PersistentSyncError> {
    let data = ModifiersData::parse(body)?;

    // Only process header modifiers (type_id = 101).
    if data.type_id != 101 {
        return Err(PersistentSyncError::UnexpectedModifierType(data.type_id));
    }

    let mut added = 0u32;

    for (id, payload) in &data.modifiers {
        // Skip headers we already have.
        if db.contains_modifier(HEADER_TYPE_ID, id)? {
            continue;
        }

        // Parse the header from the payload bytes.
        let header = parse_header(payload)?;

        // Validate: genesis headers vs child headers.
        if header.is_genesis() {
            validate_genesis_header(&header, now_ms, None, None)?;
        } else {
            let parent = db
                .load_header(&header.parent_id)?
                .ok_or(PersistentSyncError::ParentNotFound(header.parent_id))?;
            validate_child_header(&header, &parent, now_ms, None)?;
        }

        db.store_header_with_score(id, &header)?;
        added += 1;
    }

    Ok(added)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_types::header::Header;
    use ergo_types::modifier_id::ModifierId;
    use tempfile::TempDir;

    /// Create a v2 test header at the given height with a distinct fill byte
    /// for the parent_id.
    fn make_header(height: u32, fill: u8) -> Header {
        let mut h = Header::default_for_test();
        h.version = 2;
        h.height = height;
        h.parent_id = ModifierId([fill; 32]);
        h
    }

    /// Deterministic modifier ID derived from a fill byte.
    fn make_id(fill: u8) -> ModifierId {
        ModifierId([fill; 32])
    }

    fn open_test_db() -> (HistoryDb, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = HistoryDb::open(dir.path()).unwrap();
        (db, dir)
    }

    #[test]
    fn sync_info_empty_db() {
        let (db, _dir) = open_test_db();
        let sync = build_sync_info_persistent(&db).unwrap();
        match sync {
            ErgoSyncInfo::V2(v2) => assert!(v2.last_headers.is_empty()),
            _ => panic!("expected V2"),
        }
    }

    #[test]
    fn sync_info_with_headers() {
        let (db, _dir) = open_test_db();
        let header = make_header(1, 0xAA);
        let id = make_id(0x01);
        db.store_header(&id, &header).unwrap();

        let sync = build_sync_info_persistent(&db).unwrap();
        match sync {
            ErgoSyncInfo::V2(v2) => assert_eq!(v2.last_headers.len(), 1),
            _ => panic!("expected V2"),
        }
    }

    #[test]
    fn sync_info_max_10_headers() {
        let (db, _dir) = open_test_db();

        // Store 15 headers at heights 1..=15.
        for i in 1..=15u32 {
            let header = make_header(i, i as u8);
            let id = make_id(i as u8 + 0x10);
            db.store_header(&id, &header).unwrap();
        }

        let sync = build_sync_info_persistent(&db).unwrap();
        match sync {
            ErgoSyncInfo::V2(v2) => {
                assert_eq!(v2.last_headers.len(), 10);
                // Should contain heights 6..=15 (last 10).
                assert_eq!(v2.last_headers[0].height, 6);
                assert_eq!(v2.last_headers[9].height, 15);
            }
            _ => panic!("expected V2"),
        }
    }

    #[test]
    fn persistent_sync_survives_reopen() {
        let dir = TempDir::new().unwrap();

        // First open: store 5 headers.
        {
            let db = HistoryDb::open(dir.path()).unwrap();
            for i in 1..=5u32 {
                let header = make_header(i, i as u8);
                let id = make_id(i as u8 + 0x20);
                db.store_header(&id, &header).unwrap();
            }
        }

        // Second open: verify SyncInfo has 5 headers.
        {
            let db = HistoryDb::open(dir.path()).unwrap();
            let sync = build_sync_info_persistent(&db).unwrap();
            match sync {
                ErgoSyncInfo::V2(v2) => {
                    assert_eq!(v2.last_headers.len(), 5);
                    assert_eq!(v2.last_headers[0].height, 1);
                    assert_eq!(v2.last_headers[4].height, 5);
                }
                _ => panic!("expected V2"),
            }
        }
    }
}
