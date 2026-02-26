//! Segment overflow logic for the extra-indexer.
//!
//! When an `IndexedErgoAddress`, `IndexedToken`, or `IndexedContractTemplate`
//! accumulates more than [`SEGMENT_THRESHOLD`] box or tx indexes, the excess
//! indexes are split off into serialized segments and persisted to the DB.
//!
//! ## Serialization format
//!
//! Each segment is encoded as:
//!
//! ```text
//! indexes_len (4 bytes BE u32) + foreach(index (i64 = 8 bytes BE))
//! ```

use crate::db::{box_segment_key, tx_segment_key, ExtraIndexerDb, IndexerDbError};

// ---------------------------------------------------------------------------
// Constants & type aliases
// ---------------------------------------------------------------------------

/// Maximum number of indexes kept in the hot (in-record) array before overflow
/// segments are created.
pub const SEGMENT_THRESHOLD: usize = 512;

/// A list of `(segment_key, serialized_bytes)` pairs to persist to the DB.
pub type SegmentUpdates = Vec<([u8; 32], Vec<u8>)>;

// ---------------------------------------------------------------------------
// Segment serialization helpers
// ---------------------------------------------------------------------------

/// Serialize a slice of i64 indexes into the segment wire format.
///
/// Format: `len(4 BE u32) + foreach(index(8 BE i64))`.
pub fn serialize_segment(indexes: &[i64]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + indexes.len() * 8);
    buf.extend_from_slice(&(indexes.len() as u32).to_be_bytes());
    for &idx in indexes {
        buf.extend_from_slice(&idx.to_be_bytes());
    }
    buf
}

/// Deserialize a segment from its wire format back into a `Vec<i64>`.
pub fn deserialize_segment(data: &[u8]) -> Result<Vec<i64>, IndexerDbError> {
    if data.len() < 4 {
        return Err(IndexerDbError::Codec(
            "segment too short for length prefix".into(),
        ));
    }
    let len = u32::from_be_bytes(data[0..4].try_into().unwrap()) as usize;
    let expected = 4 + len * 8;
    if data.len() < expected {
        return Err(IndexerDbError::Codec(format!(
            "segment data too short: expected {expected}, got {}",
            data.len()
        )));
    }
    let mut indexes = Vec::with_capacity(len);
    for i in 0..len {
        let offset = 4 + i * 8;
        let val = i64::from_be_bytes(data[offset..offset + 8].try_into().unwrap());
        indexes.push(val);
    }
    Ok(indexes)
}

// ---------------------------------------------------------------------------
// split_segments
// ---------------------------------------------------------------------------

/// Split overflow indexes into persisted segments.
///
/// If `indexes.len() > SEGMENT_THRESHOLD`, full chunks of 512 are split off
/// from the *front* of the vector, serialized, and returned as
/// `(segment_key, serialized_bytes)` pairs ready for DB persistence.
///
/// `segment_count` is incremented for each new segment produced, and `indexes`
/// is left with only the remaining tail (always <= SEGMENT_THRESHOLD items).
pub fn split_segments(
    indexes: &mut Vec<i64>,
    segment_count: &mut u32,
    parent_key: &[u8; 32],
    is_box: bool,
) -> SegmentUpdates {
    let mut segments = Vec::new();

    while indexes.len() > SEGMENT_THRESHOLD {
        // Drain the first SEGMENT_THRESHOLD items.
        let chunk: Vec<i64> = indexes.drain(..SEGMENT_THRESHOLD).collect();

        let key = if is_box {
            box_segment_key(parent_key, *segment_count)
        } else {
            tx_segment_key(parent_key, *segment_count)
        };
        let serialized = serialize_segment(&chunk);
        segments.push((key, serialized));

        *segment_count += 1;
    }

    segments
}

// ---------------------------------------------------------------------------
// load_segment_indexes
// ---------------------------------------------------------------------------

/// Load a single persisted segment's indexes from the DB.
pub fn load_segment_indexes(
    db: &ExtraIndexerDb,
    parent_key: &[u8; 32],
    segment_num: u32,
    is_box: bool,
) -> Result<Vec<i64>, IndexerDbError> {
    let key = if is_box {
        box_segment_key(parent_key, segment_num)
    } else {
        tx_segment_key(parent_key, segment_num)
    };
    match db.get(&key)? {
        Some(data) => deserialize_segment(&data),
        None => Ok(Vec::new()),
    }
}

// ---------------------------------------------------------------------------
// find_and_negate_index
// ---------------------------------------------------------------------------

/// Negate (mark as spent) a positive index to mark it consumed.
///
/// 1. Search the current `indexes` array for `target` (as positive i64).
/// 2. If found, negate it in place and return `(true, vec![])`.
/// 3. If not in current, iterate through DB-persisted segments `0..segment_count`:
///    - Load segment, search for the target.
///    - If found, negate it, re-serialize, and return `(true, vec![(key, bytes)])`.
/// 4. If not found anywhere, return `(false, vec![])`.
pub fn find_and_negate_index(
    indexes: &mut [i64],
    target: u64,
    db: &ExtraIndexerDb,
    parent_key: &[u8; 32],
    segment_count: u32,
    is_box: bool,
) -> Result<(bool, SegmentUpdates), IndexerDbError> {
    let target_i64 = target as i64;

    // 1. Search current array.
    if let Some(pos) = indexes.iter().position(|&v| v == target_i64) {
        indexes[pos] = -indexes[pos];
        return Ok((true, Vec::new()));
    }

    // 2. Search persisted segments.
    for seg_num in 0..segment_count {
        let key = if is_box {
            box_segment_key(parent_key, seg_num)
        } else {
            tx_segment_key(parent_key, seg_num)
        };

        let data = match db.get(&key)? {
            Some(d) => d,
            None => continue,
        };

        let mut seg_indexes = deserialize_segment(&data)?;

        if let Some(pos) = seg_indexes.iter().position(|&v| v == target_i64) {
            seg_indexes[pos] = -seg_indexes[pos];
            let updated = serialize_segment(&seg_indexes);
            return Ok((true, vec![(key, updated)]));
        }
    }

    // 3. Not found.
    Ok((false, Vec::new()))
}

// ---------------------------------------------------------------------------
// find_and_unnegate_index
// ---------------------------------------------------------------------------

/// Reverse a previous negation (un-spend) of a box index during rollback.
///
/// Searches for `-target` in the current array and persisted segments.
/// If found, replaces it with `+target` and returns `true`.
pub fn find_and_unnegate_index(
    indexes: &mut [i64],
    target: u64,
    db: &ExtraIndexerDb,
    parent_key: &[u8; 32],
    segment_count: u32,
    is_box: bool,
) -> Result<(bool, SegmentUpdates), IndexerDbError> {
    let negated = -(target as i64);

    // 1. Search current array.
    if let Some(pos) = indexes.iter().position(|&v| v == negated) {
        indexes[pos] = target as i64;
        return Ok((true, Vec::new()));
    }

    // 2. Search persisted segments.
    for seg_num in 0..segment_count {
        let key = if is_box {
            box_segment_key(parent_key, seg_num)
        } else {
            tx_segment_key(parent_key, seg_num)
        };

        let data = match db.get(&key)? {
            Some(d) => d,
            None => continue,
        };

        let mut seg_indexes = deserialize_segment(&data)?;

        if let Some(pos) = seg_indexes.iter().position(|&v| v == negated) {
            seg_indexes[pos] = target as i64;
            let updated = serialize_segment(&seg_indexes);
            return Ok((true, vec![(key, updated)]));
        }
    }

    Ok((false, Vec::new()))
}

// ---------------------------------------------------------------------------
// remove_index_entry
// ---------------------------------------------------------------------------

/// Remove an index entry entirely (positive or negative) from the current
/// array or persisted segments.  Used during rollback to undo box creation.
///
/// Returns `true` if the index was found and removed.
pub fn remove_index_entry(
    indexes: &mut Vec<i64>,
    target: u64,
    db: &ExtraIndexerDb,
    parent_key: &[u8; 32],
    segment_count: u32,
    is_box: bool,
) -> Result<(bool, SegmentUpdates), IndexerDbError> {
    let pos_val = target as i64;
    let neg_val = -(target as i64);

    // 1. Search current array (positive or negative).
    if let Some(pos) = indexes
        .iter()
        .position(|&v| v == pos_val || v == neg_val)
    {
        indexes.remove(pos);
        return Ok((true, Vec::new()));
    }

    // 2. Search persisted segments.
    for seg_num in 0..segment_count {
        let key = if is_box {
            box_segment_key(parent_key, seg_num)
        } else {
            tx_segment_key(parent_key, seg_num)
        };

        let data = match db.get(&key)? {
            Some(d) => d,
            None => continue,
        };

        let mut seg_indexes = deserialize_segment(&data)?;

        if let Some(pos) = seg_indexes
            .iter()
            .position(|&v| v == pos_val || v == neg_val)
        {
            seg_indexes.remove(pos);
            let updated = serialize_segment(&seg_indexes);
            return Ok((true, vec![(key, updated)]));
        }
    }

    Ok((false, Vec::new()))
}

// ---------------------------------------------------------------------------
// collect_all_indexes
// ---------------------------------------------------------------------------

/// Collect ALL indexes (all persisted segments + current hot array) into one
/// `Vec<i64>` for query purposes.
///
/// Segments are appended in order (0..segment_count), followed by `current`.
pub fn collect_all_indexes(
    current: &[i64],
    db: &ExtraIndexerDb,
    parent_key: &[u8; 32],
    segment_count: u32,
    is_box: bool,
) -> Result<Vec<i64>, IndexerDbError> {
    let mut all = Vec::new();

    for seg_num in 0..segment_count {
        let seg = load_segment_indexes(db, parent_key, seg_num, is_box)?;
        all.extend_from_slice(&seg);
    }

    all.extend_from_slice(current);
    Ok(all)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a parent key for tests.
    fn test_parent_key() -> [u8; 32] {
        [0xAB; 32]
    }

    // -----------------------------------------------------------------------
    // split_segments tests
    // -----------------------------------------------------------------------

    #[test]
    fn split_under_threshold_noop() {
        let mut indexes: Vec<i64> = (1..=100).collect();
        let mut seg_count = 0u32;
        let parent = test_parent_key();

        let segments = split_segments(&mut indexes, &mut seg_count, &parent, true);

        assert!(segments.is_empty());
        assert_eq!(seg_count, 0);
        assert_eq!(indexes.len(), 100);
    }

    #[test]
    fn split_at_threshold() {
        let mut indexes: Vec<i64> = (1..=512).collect();
        let mut seg_count = 0u32;
        let parent = test_parent_key();

        let segments = split_segments(&mut indexes, &mut seg_count, &parent, true);

        // Exactly 512 does NOT exceed SEGMENT_THRESHOLD, so no split.
        assert!(segments.is_empty());
        assert_eq!(seg_count, 0);
        assert_eq!(indexes.len(), 512);
    }

    #[test]
    fn split_over_threshold() {
        let mut indexes: Vec<i64> = (1..=600).collect();
        let mut seg_count = 0u32;
        let parent = test_parent_key();

        let segments = split_segments(&mut indexes, &mut seg_count, &parent, true);

        // 600 > 512 => 1 segment of 512, 88 remaining.
        assert_eq!(segments.len(), 1);
        assert_eq!(seg_count, 1);
        assert_eq!(indexes.len(), 88);

        // The remaining indexes should be 513..=600.
        assert_eq!(indexes[0], 513);
        assert_eq!(*indexes.last().unwrap(), 600);

        // Verify segment serialization roundtrip.
        let (key, bytes) = &segments[0];
        assert_eq!(*key, box_segment_key(&parent, 0));
        let deserialized = deserialize_segment(bytes).unwrap();
        assert_eq!(deserialized.len(), 512);
        assert_eq!(deserialized[0], 1);
        assert_eq!(*deserialized.last().unwrap(), 512);
    }

    #[test]
    fn split_double_over() {
        let mut indexes: Vec<i64> = (1..=1100).collect();
        let mut seg_count = 0u32;
        let parent = test_parent_key();

        let segments = split_segments(&mut indexes, &mut seg_count, &parent, false);

        // 1100 > 512 => split off 2 segments of 512 each, 76 remaining.
        assert_eq!(segments.len(), 2);
        assert_eq!(seg_count, 2);
        assert_eq!(indexes.len(), 76); // 1100 - 512*2 = 76

        // Remaining: 1025..=1100.
        assert_eq!(indexes[0], 1025);
        assert_eq!(*indexes.last().unwrap(), 1100);

        // First segment: 1..=512 under tx segment key 0.
        let (key0, bytes0) = &segments[0];
        assert_eq!(*key0, tx_segment_key(&parent, 0));
        let seg0 = deserialize_segment(bytes0).unwrap();
        assert_eq!(seg0.len(), 512);
        assert_eq!(seg0[0], 1);
        assert_eq!(*seg0.last().unwrap(), 512);

        // Second segment: 513..=1024 under tx segment key 1.
        let (key1, bytes1) = &segments[1];
        assert_eq!(*key1, tx_segment_key(&parent, 1));
        let seg1 = deserialize_segment(bytes1).unwrap();
        assert_eq!(seg1.len(), 512);
        assert_eq!(seg1[0], 513);
        assert_eq!(*seg1.last().unwrap(), 1024);
    }

    // -----------------------------------------------------------------------
    // find_and_negate_index tests
    // -----------------------------------------------------------------------

    #[test]
    fn find_and_negate_in_current() {
        let tmp = tempfile::tempdir().unwrap();
        let db = ExtraIndexerDb::open(tmp.path()).unwrap();
        let parent = test_parent_key();

        let mut indexes: Vec<i64> = vec![10, 20, 30, 40, 50];
        let (found, updates) =
            find_and_negate_index(&mut indexes, 30, &db, &parent, 0, true).unwrap();

        assert!(found);
        assert!(updates.is_empty());
        assert_eq!(indexes, vec![10, 20, -30, 40, 50]);
    }

    #[test]
    fn find_and_negate_in_segment() {
        let tmp = tempfile::tempdir().unwrap();
        let db = ExtraIndexerDb::open(tmp.path()).unwrap();
        let parent = test_parent_key();

        // Persist a segment with indexes [100, 200, 300, 400, 500].
        let seg_indexes: Vec<i64> = vec![100, 200, 300, 400, 500];
        let seg_key = box_segment_key(&parent, 0);
        let seg_bytes = serialize_segment(&seg_indexes);
        db.put(&seg_key, &seg_bytes).unwrap();

        // Current array does NOT contain 300.
        let mut current: Vec<i64> = vec![600, 700, 800];

        let (found, updates) =
            find_and_negate_index(&mut current, 300, &db, &parent, 1, true).unwrap();

        assert!(found);
        assert_eq!(updates.len(), 1);

        // The current array should be unchanged.
        assert_eq!(current, vec![600, 700, 800]);

        // The returned update should contain the negated segment.
        let (update_key, update_bytes) = &updates[0];
        assert_eq!(*update_key, seg_key);
        let updated_seg = deserialize_segment(update_bytes).unwrap();
        assert_eq!(updated_seg, vec![100, 200, -300, 400, 500]);
    }

    // -----------------------------------------------------------------------
    // collect_all_indexes test
    // -----------------------------------------------------------------------

    #[test]
    fn collect_all_merges_segments() {
        let tmp = tempfile::tempdir().unwrap();
        let db = ExtraIndexerDb::open(tmp.path()).unwrap();
        let parent = test_parent_key();

        // Persist two segments.
        let seg0: Vec<i64> = (1..=512).collect();
        let seg1: Vec<i64> = (513..=1024).collect();
        let key0 = box_segment_key(&parent, 0);
        let key1 = box_segment_key(&parent, 1);
        db.put(&key0, &serialize_segment(&seg0)).unwrap();
        db.put(&key1, &serialize_segment(&seg1)).unwrap();

        // Current array.
        let current: Vec<i64> = vec![1025, 1026, 1027];

        let all =
            collect_all_indexes(&current, &db, &parent, 2, true).unwrap();

        assert_eq!(all.len(), 512 + 512 + 3);
        // First 512 from segment 0.
        assert_eq!(all[0], 1);
        assert_eq!(all[511], 512);
        // Next 512 from segment 1.
        assert_eq!(all[512], 513);
        assert_eq!(all[1023], 1024);
        // Last 3 from current.
        assert_eq!(all[1024], 1025);
        assert_eq!(all[1025], 1026);
        assert_eq!(all[1026], 1027);
    }
}
