//! Header-specific storage operations for [`HistoryDb`].
//!
//! Provides methods to store/load headers, track the best (highest) header,
//! and maintain height-to-ID indexes for fork management.

use ergo_types::header::Header;
use ergo_types::modifier_id::ModifierId;
use ergo_wire::header_ser::{parse_header, serialize_header};

use crate::chain_scoring::{add_scores, difficulty_from_nbits};
use crate::history_db::{
    best_header_key, header_height_key, height_ids_key, HistoryDb, StorageError,
};

/// Modifier type ID for headers in the `objects` column family.
const HEADER_TYPE_ID: u8 = 101;

// ---------------------------------------------------------------------------
// Internal helpers (free functions)
// ---------------------------------------------------------------------------

/// Concatenate the raw 32-byte representations of each [`ModifierId`].
fn serialize_id_list(ids: &[ModifierId]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(ids.len() * 32);
    for id in ids {
        buf.extend_from_slice(&id.0);
    }
    buf
}

/// Split a byte slice into 32-byte chunks and reconstruct [`ModifierId`]s.
///
/// If `data.len()` is not a multiple of 32 the trailing bytes are silently
/// dropped (this should never happen in practice).
fn deserialize_id_list(data: &[u8]) -> Vec<ModifierId> {
    data.chunks_exact(32)
        .map(|chunk| {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(chunk);
            ModifierId(arr)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// HistoryDb impl
// ---------------------------------------------------------------------------

impl HistoryDb {
    /// Serialize and persist a header, updating all associated indexes.
    ///
    /// The following entries are written atomically:
    /// - The serialized header in the `objects` CF (type 101).
    /// - A height-to-ID index entry (appends `id` to the list at the header's
    ///   height).
    /// - A header-to-height index entry.
    /// - If this header is higher than the current best, updates the best
    ///   header pointer.
    pub fn store_header(&self, id: &ModifierId, header: &Header) -> Result<(), StorageError> {
        let bytes = serialize_header(header);

        let mut batch = self.new_batch();

        // 1. Store the serialized header as modifier type 101.
        batch.put_modifier(HEADER_TYPE_ID, id, &bytes);

        // 2. Height -> IDs index: append this ID to the existing list.
        let height_key = height_ids_key(header.height);
        let mut ids = self.load_ids_at_key(&height_key)?;
        if !ids.contains(id) {
            ids.push(*id);
        }
        batch.put_index(&height_key, &serialize_id_list(&ids));

        // 3. Header -> height index.
        let h_key = header_height_key(id);
        batch.put_index(&h_key, &header.height.to_be_bytes());

        // 4. Update best header if this one is higher.
        let current_best_height = self.best_header_height()?;
        if header.height > current_best_height {
            batch.put_index(&best_header_key(), &id.0);
        }

        batch.write()
    }

    /// Load and deserialize a header by its [`ModifierId`].
    ///
    /// Returns `Ok(None)` if no header with the given ID exists.
    pub fn load_header(&self, id: &ModifierId) -> Result<Option<Header>, StorageError> {
        match self.get_modifier(HEADER_TYPE_ID, id)? {
            None => Ok(None),
            Some(data) => {
                let header =
                    parse_header(&data).map_err(|e| StorageError::Codec(e.to_string()))?;
                Ok(Some(header))
            }
        }
    }

    /// Returns the [`ModifierId`] of the current best (highest) header, or
    /// `None` if no headers have been stored yet.
    pub fn best_header_id(&self) -> Result<Option<ModifierId>, StorageError> {
        match self.get_index(&best_header_key())? {
            None => Ok(None),
            Some(data) => {
                if data.len() != 32 {
                    return Err(StorageError::Codec(format!(
                        "best header ID has invalid length: {}",
                        data.len()
                    )));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&data);
                Ok(Some(ModifierId(arr)))
            }
        }
    }

    /// Returns all header IDs stored at the given `height`.
    ///
    /// Returns an empty vec if no headers exist at that height.
    pub fn header_ids_at_height(&self, height: u32) -> Result<Vec<ModifierId>, StorageError> {
        self.load_ids_at_key(&height_ids_key(height))
    }

    // -----------------------------------------------------------------------
    // Score-aware storage
    // -----------------------------------------------------------------------

    /// Store a header **and** compute/store its cumulative chain score.
    ///
    /// The cumulative score for a header is defined as:
    ///
    /// ```text
    /// score(H) = score(parent(H)) + difficulty(H.n_bits)
    /// ```
    ///
    /// After storing the score the method checks whether this header now leads
    /// the highest-scoring chain.  If it does the best-header pointer is
    /// updated.
    ///
    /// Returns `true` if this header became the new best.
    pub fn store_header_with_score(
        &self,
        id: &ModifierId,
        header: &Header,
    ) -> Result<bool, StorageError> {
        // Capture previous best *before* store_header (which may update the
        // height-based best pointer).
        let prev_best = self.best_header_id()?;

        // 1. Store the header itself (indexes, height map, etc.).
        self.store_header(id, header)?;

        // 2. Compute cumulative score = parent_score + difficulty.
        let parent_score = if header.parent_id == ModifierId::GENESIS_PARENT {
            vec![0u8]
        } else {
            self.get_header_score(&header.parent_id)?
                .unwrap_or_else(|| vec![0u8])
        };
        let difficulty = difficulty_from_nbits(header.n_bits);
        let new_score = add_scores(&parent_score, &difficulty);
        self.put_header_score(id, &new_score)?;

        // 3. Determine whether this chain now has the highest score.
        let is_best = match prev_best {
            None => true,
            Some(prev_best_id) => {
                let prev_score = self
                    .get_header_score(&prev_best_id)?
                    .unwrap_or_else(|| vec![0u8]);
                Self::is_score_greater(&new_score, &prev_score)
            }
        };

        if is_best {
            self.set_best_header_id(id)?;
        }

        Ok(is_best)
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Returns the height of the current best header, or `0` if none is set.
    pub fn best_header_height(&self) -> Result<u32, StorageError> {
        let best_id = match self.best_header_id()? {
            None => return Ok(0),
            Some(id) => id,
        };

        let h_key = header_height_key(&best_id);
        match self.get_index(&h_key)? {
            None => Ok(0),
            Some(data) => {
                if data.len() != 4 {
                    return Err(StorageError::Codec(format!(
                        "header height has invalid length: {}",
                        data.len()
                    )));
                }
                let mut arr = [0u8; 4];
                arr.copy_from_slice(&data);
                Ok(u32::from_be_bytes(arr))
            }
        }
    }

    /// Walk backward from the best header, collecting up to `n` headers in
    /// descending height order (newest first).
    ///
    /// Returns an empty `Vec` if `n == 0` or if no headers have been stored.
    /// Stops early when the genesis parent is reached or when a header cannot
    /// be loaded.
    pub fn last_n_headers(&self, n: usize) -> Result<Vec<Header>, StorageError> {
        if n == 0 {
            return Ok(Vec::new());
        }
        let mut result = Vec::with_capacity(n);
        let mut current_id = match self.best_header_id()? {
            Some(id) => id,
            None => return Ok(Vec::new()),
        };
        for _ in 0..n {
            match self.load_header(&current_id)? {
                Some(header) => {
                    let parent = header.parent_id;
                    result.push(header);
                    if parent == ModifierId::GENESIS_PARENT {
                        break;
                    }
                    current_id = parent;
                }
                None => break,
            }
        }
        Ok(result)
    }

    /// Load a list of [`ModifierId`]s from the index at the given key.
    fn load_ids_at_key(&self, key: &[u8; 32]) -> Result<Vec<ModifierId>, StorageError> {
        match self.get_index(key)? {
            None => Ok(Vec::new()),
            Some(data) => Ok(deserialize_id_list(&data)),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_types::header::Header;
    use tempfile::TempDir;

    /// Create a v2 test header at the given height with a distinct fill byte.
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

    // 1. store_and_load_header — roundtrip
    #[test]
    fn store_and_load_header() {
        let (db, _dir) = open_test_db();
        let header = make_header(100, 0xAA);
        let id = make_id(0x01);

        db.store_header(&id, &header).unwrap();

        let loaded = db.load_header(&id).unwrap().expect("header should exist");
        assert_eq!(loaded, header);
    }

    // 2. best_header_id_updates — None -> first -> second (higher)
    #[test]
    fn best_header_id_updates() {
        let (db, _dir) = open_test_db();

        // Initially no best header.
        assert!(db.best_header_id().unwrap().is_none());

        // Store first header at height 10.
        let id1 = make_id(0x01);
        let h1 = make_header(10, 0xAA);
        db.store_header(&id1, &h1).unwrap();
        assert_eq!(db.best_header_id().unwrap(), Some(id1));

        // Store second header at height 20 — should become new best.
        let id2 = make_id(0x02);
        let h2 = make_header(20, 0xBB);
        db.store_header(&id2, &h2).unwrap();
        assert_eq!(db.best_header_id().unwrap(), Some(id2));
    }

    // 3. best_header_doesnt_regress — storing lower header doesn't change best
    #[test]
    fn best_header_doesnt_regress() {
        let (db, _dir) = open_test_db();

        // Store a header at height 50.
        let id_high = make_id(0x10);
        let h_high = make_header(50, 0xCC);
        db.store_header(&id_high, &h_high).unwrap();
        assert_eq!(db.best_header_id().unwrap(), Some(id_high));

        // Store a header at height 5 — best should not change.
        let id_low = make_id(0x20);
        let h_low = make_header(5, 0xDD);
        db.store_header(&id_low, &h_low).unwrap();
        assert_eq!(db.best_header_id().unwrap(), Some(id_high));
    }

    // 4. header_ids_at_height — single ID, then missing height
    #[test]
    fn header_ids_at_height() {
        let (db, _dir) = open_test_db();

        let id = make_id(0x01);
        let header = make_header(42, 0xAA);
        db.store_header(&id, &header).unwrap();

        let ids = db.header_ids_at_height(42).unwrap();
        assert_eq!(ids, vec![id]);

        // Missing height returns empty.
        let missing = db.header_ids_at_height(999).unwrap();
        assert!(missing.is_empty());
    }

    // 5. multiple_ids_at_same_height — fork scenario
    #[test]
    fn multiple_ids_at_same_height() {
        let (db, _dir) = open_test_db();

        let id1 = make_id(0x01);
        let h1 = make_header(100, 0xAA);
        db.store_header(&id1, &h1).unwrap();

        let id2 = make_id(0x02);
        let h2 = make_header(100, 0xBB);
        db.store_header(&id2, &h2).unwrap();

        let ids = db.header_ids_at_height(100).unwrap();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&id1));
        assert!(ids.contains(&id2));
    }

    // 6. persists_across_reopen — close + reopen
    #[test]
    fn persists_across_reopen() {
        let dir = TempDir::new().unwrap();
        let id = make_id(0x42);
        let header = make_header(77, 0xEE);

        // First open: store header.
        {
            let db = HistoryDb::open(dir.path()).unwrap();
            db.store_header(&id, &header).unwrap();
        }

        // Second open: data should still be there.
        {
            let db = HistoryDb::open(dir.path()).unwrap();
            let loaded = db.load_header(&id).unwrap().expect("header should persist");
            assert_eq!(loaded, header);
            assert_eq!(db.best_header_id().unwrap(), Some(id));
            assert_eq!(db.header_ids_at_height(77).unwrap(), vec![id]);
        }
    }

    // -- store_header_with_score tests --

    // 7. store_header_with_score sets score
    #[test]
    fn store_header_with_score_sets_score() {
        let (db, _dir) = open_test_db();
        let mut h = make_header(1, 0x00);
        h.parent_id = ModifierId::GENESIS_PARENT;
        // Use a valid compact nBits encoding: size=1, mantissa=0x01 => difficulty 1
        h.n_bits = 0x01010000;
        let id = make_id(0x01);

        let is_best = db.store_header_with_score(&id, &h).unwrap();
        assert!(is_best);

        // Score must exist and equal difficulty_from_nbits(0x01010000).
        let score = db.get_header_score(&id).unwrap().expect("score should exist");
        let expected = crate::chain_scoring::add_scores(
            &[0],
            &crate::chain_scoring::difficulty_from_nbits(0x01010000),
        );
        assert_eq!(score, expected);
    }

    // 8. store_header_with_score accumulates
    #[test]
    fn store_header_with_score_accumulates() {
        let (db, _dir) = open_test_db();

        // Parent header at height 1.
        // Use valid compact nBits: size=1, mantissa=0x01 => difficulty 1
        let parent_id = make_id(0x01);
        let mut parent = make_header(1, 0x00);
        parent.parent_id = ModifierId::GENESIS_PARENT;
        parent.n_bits = 0x01010000;
        db.store_header_with_score(&parent_id, &parent).unwrap();

        // Child header at height 2 referencing parent.
        // Use valid compact nBits: size=1, mantissa=0x02 => difficulty 2
        let child_id = make_id(0x02);
        let mut child = make_header(2, 0x00);
        child.parent_id = parent_id;
        child.n_bits = 0x01020000;
        db.store_header_with_score(&child_id, &child).unwrap();

        let parent_score = db.get_header_score(&parent_id).unwrap().unwrap();
        let child_score = db.get_header_score(&child_id).unwrap().unwrap();
        assert!(HistoryDb::is_score_greater(&child_score, &parent_score));
    }

    // 9. store_header_with_score updates best
    #[test]
    fn store_header_with_score_updates_best() {
        let (db, _dir) = open_test_db();

        // First header with low difficulty.
        // Valid compact nBits: size=1, mantissa=0x01 => difficulty 1
        let id1 = make_id(0x01);
        let mut h1 = make_header(1, 0x00);
        h1.parent_id = ModifierId::GENESIS_PARENT;
        h1.n_bits = 0x01010000;
        let best1 = db.store_header_with_score(&id1, &h1).unwrap();
        assert!(best1);
        assert_eq!(db.best_header_id().unwrap(), Some(id1));

        // Second header with much higher difficulty at same height
        // (fork scenario). It should become best because its score is higher.
        // Valid compact nBits: size=4, mantissa=0x01 => difficulty 16777216
        let id2 = make_id(0x02);
        let mut h2 = make_header(1, 0x00);
        h2.parent_id = ModifierId::GENESIS_PARENT;
        h2.n_bits = 0x04010000;
        let best2 = db.store_header_with_score(&id2, &h2).unwrap();
        assert!(best2);
        assert_eq!(db.best_header_id().unwrap(), Some(id2));
    }

    // 10. id_list_roundtrip — serialize/deserialize list
    #[test]
    fn id_list_roundtrip() {
        let ids = vec![make_id(0x01), make_id(0x02), make_id(0x03)];
        let bytes = serialize_id_list(&ids);
        assert_eq!(bytes.len(), 96); // 3 * 32
        let recovered = deserialize_id_list(&bytes);
        assert_eq!(recovered, ids);
    }

    // 8. id_list_empty — empty list
    #[test]
    fn id_list_empty() {
        let ids: Vec<ModifierId> = Vec::new();
        let bytes = serialize_id_list(&ids);
        assert!(bytes.is_empty());
        let recovered = deserialize_id_list(&bytes);
        assert!(recovered.is_empty());
    }

    // -- best_header_height tests --

    #[test]
    fn best_header_height_public() {
        let (db, _dir) = open_test_db();
        // Empty DB should return 0.
        assert_eq!(db.best_header_height().unwrap(), 0);
    }

    // -- last_n_headers tests --

    #[test]
    fn last_n_headers_empty_db() {
        let (db, _dir) = open_test_db();
        let result = db.last_n_headers(5).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn last_n_headers_zero_returns_empty() {
        let (db, _dir) = open_test_db();
        // Even if headers exist, n==0 should return empty.
        let mut h = make_header(1, 0x00);
        h.parent_id = ModifierId::GENESIS_PARENT;
        db.store_header(&make_id(0x01), &h).unwrap();

        let result = db.last_n_headers(0).unwrap();
        assert!(result.is_empty());
    }

    /// Helper: store a chain of `count` headers linked via parent_id.
    /// Returns Vec of (ModifierId, Header) in ascending height order.
    fn store_chain(db: &HistoryDb, count: u32) -> Vec<(ModifierId, Header)> {
        let mut chain = Vec::new();
        let mut parent_id = ModifierId::GENESIS_PARENT;
        for i in 1..=count {
            let id = make_id(i as u8);
            let mut h = make_header(i, 0x00);
            h.parent_id = parent_id;
            db.store_header(&id, &h).unwrap();
            chain.push((id, h));
            parent_id = id;
        }
        chain
    }

    #[test]
    fn last_n_headers_returns_in_descending_order() {
        let (db, _dir) = open_test_db();
        let chain = store_chain(&db, 5);

        let result = db.last_n_headers(3).unwrap();
        assert_eq!(result.len(), 3);
        // Should be heights 5, 4, 3 (newest first).
        assert_eq!(result[0].height, 5);
        assert_eq!(result[1].height, 4);
        assert_eq!(result[2].height, 3);

        // Verify actual header content matches what we stored.
        assert_eq!(result[0], chain[4].1); // height 5
        assert_eq!(result[1], chain[3].1); // height 4
        assert_eq!(result[2], chain[2].1); // height 3
    }

    #[test]
    fn last_n_headers_capped_at_chain_length() {
        let (db, _dir) = open_test_db();
        let chain = store_chain(&db, 3);

        // Request 100 but only 3 exist.
        let result = db.last_n_headers(100).unwrap();
        assert_eq!(result.len(), 3);
        // Heights should be 3, 2, 1.
        assert_eq!(result[0].height, 3);
        assert_eq!(result[1].height, 2);
        assert_eq!(result[2].height, 1);

        // Verify content matches.
        assert_eq!(result[0], chain[2].1);
        assert_eq!(result[1], chain[1].1);
        assert_eq!(result[2], chain[0].1);
    }
}
