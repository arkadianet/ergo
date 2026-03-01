//! Continuation and common-point logic for syncing with peers.
//!
//! Provides methods on [`HistoryDb`] to find a common ancestor with a peer's
//! header chain and to compute the list of canonical header IDs that the peer
//! is missing.

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;

use ergo_types::header::Header;
use ergo_types::modifier_id::ModifierId;
use ergo_wire::header_ser::serialize_header;

use crate::history_db::{header_height_key, HistoryDb, StorageError};

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

/// Compute the header ID (blake2b256 of the full serialized header).
pub fn compute_header_id(bytes: &[u8]) -> ModifierId {
    let mut hasher = Blake2bVar::new(32).expect("valid output size");
    hasher.update(bytes);
    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("correct output size");
    ModifierId(out)
}

// ---------------------------------------------------------------------------
// HistoryDb impl
// ---------------------------------------------------------------------------

impl HistoryDb {
    /// Find the most recent common header between our chain and the peer's
    /// advertised headers.
    ///
    /// Iterates `peer_headers` from **newest to oldest** (forward order,
    /// since headers are stored newest-first in SyncInfo V2).
    /// For each header, serializes it and computes its blake2b256 ID, then
    /// checks whether we have that header in our DB (type 101 = Header).
    ///
    /// Returns `Some((id, height))` for the first match, or `None` if no
    /// common header is found.
    pub fn common_point(
        &self,
        peer_headers: &[Header],
    ) -> Result<Option<(ModifierId, u32)>, StorageError> {
        for header in peer_headers.iter() {
            let bytes = serialize_header(header);
            let id = compute_header_id(&bytes);
            if self.contains_modifier(101, &id)? {
                return Ok(Some((id, header.height)));
            }
        }
        Ok(None)
    }

    /// Compute the list of canonical header IDs that a peer is missing,
    /// starting from the block after the common point.
    ///
    /// Walks from `common_height + 1` up to
    /// `min(our_best_height, common_height + 400)`, collecting the first
    /// (canonical) header ID at each height.
    ///
    /// Returns an empty vec if no common point is found with the peer.
    pub fn continuation_ids_v2(
        &self,
        peer_headers: &[Header],
    ) -> Result<Vec<ModifierId>, StorageError> {
        let (_common_id, common_height) = match self.common_point(peer_headers)? {
            Some(cp) => cp,
            None => return Ok(Vec::new()),
        };

        // Look up our best header height.
        let best_height = match self.best_header_id()? {
            Some(best_id) => self.get_header_height(&best_id)?,
            None => return Ok(Vec::new()),
        };

        let end_height = best_height.min(common_height + 400);
        let mut ids = Vec::with_capacity((end_height - common_height) as usize);

        for h in (common_height + 1)..=end_height {
            let height_ids = self.header_ids_at_height(h)?;
            if let Some(first_id) = height_ids.first() {
                ids.push(*first_id);
            }
        }

        Ok(ids)
    }

    /// Read the stored height for a header ID from the index.
    fn get_header_height(&self, id: &ModifierId) -> Result<u32, StorageError> {
        let key = header_height_key(id);
        match self.get_index(&key)? {
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
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn open_test_db() -> (HistoryDb, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = HistoryDb::open(dir.path()).unwrap();
        (db, dir)
    }

    /// Create a v2 test header at the given height with a distinct fill byte
    /// for the parent_id.
    fn make_header(height: u32, fill: u8) -> Header {
        let mut h = Header::default_for_test();
        h.version = 2;
        h.height = height;
        h.parent_id = ModifierId([fill; 32]);
        h
    }

    /// Compute the ID for a header (serialize + blake2b256).
    fn header_id(h: &Header) -> ModifierId {
        compute_header_id(&serialize_header(h))
    }

    #[test]
    fn common_point_empty_returns_none() {
        let (db, _dir) = open_test_db();
        let result = db.common_point(&[]).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn common_point_finds_matching_header() {
        let (db, _dir) = open_test_db();
        let h = make_header(100, 0xAA);
        let id = header_id(&h);

        // Store the header so it exists in our DB.
        db.store_header(&id, &h).unwrap();

        // Pass the same header as peer_headers — should find it.
        let result = db.common_point(&[h]).unwrap();
        assert_eq!(result, Some((id, 100)));
    }

    #[test]
    fn common_point_prefers_newest() {
        let (db, _dir) = open_test_db();

        let h1 = make_header(100, 0xAA);
        let id1 = header_id(&h1);
        db.store_header(&id1, &h1).unwrap();

        let h2 = make_header(200, 0xBB);
        let id2 = header_id(&h2);
        db.store_header(&id2, &h2).unwrap();

        // Pass both newest-first (matching SyncInfo V2 convention); h2 at 200
        // should be found first since we iterate forward.
        let result = db.common_point(&[h2.clone(), h1.clone()]).unwrap();
        assert_eq!(result, Some((id2, 200)));
    }

    #[test]
    fn continuation_ids_v2_empty_when_no_common() {
        let (db, _dir) = open_test_db();
        let unknown = make_header(500, 0xFF);
        let ids = db.continuation_ids_v2(&[unknown]).unwrap();
        assert!(ids.is_empty());
    }

    #[test]
    fn continuation_ids_v2_returns_subsequent_headers() {
        let (db, _dir) = open_test_db();

        // Build a small chain: heights 1..5
        let mut headers = Vec::new();
        let mut header_ids = Vec::new();
        for h in 1..=5u32 {
            let hdr = make_header(h, h as u8);
            let id = header_id(&hdr);
            db.store_header(&id, &hdr).unwrap();
            headers.push(hdr);
            header_ids.push(id);
        }

        // Peer knows header at height 2. continuation should return heights 3,4,5.
        let result = db.continuation_ids_v2(&[headers[1].clone()]).unwrap();
        assert_eq!(result.len(), 3);
        assert_eq!(result[0], header_ids[2]); // height 3
        assert_eq!(result[1], header_ids[3]); // height 4
        assert_eq!(result[2], header_ids[4]); // height 5
    }
}
