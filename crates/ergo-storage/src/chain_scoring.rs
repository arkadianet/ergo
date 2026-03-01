use ergo_consensus::difficulty::decode_compact_bits;
use ergo_types::modifier_id::ModifierId;

use crate::history_db::{
    best_full_block_key, best_header_key, header_score_key, state_version_key, validity_key,
    HistoryDb, StorageError,
};

// ---------------------------------------------------------------------------
// Score arithmetic helpers
// ---------------------------------------------------------------------------

/// Convert nBits to a big-endian difficulty byte array for scoring.
///
/// Decodes the compact nBits encoding into the full difficulty target via
/// `decode_compact_bits` (matching the Scala `DifficultySerializer.decodeCompactBits`),
/// then returns the `BigUint` result as big-endian bytes.
pub fn difficulty_from_nbits(n_bits: u64) -> Vec<u8> {
    let difficulty = decode_compact_bits(n_bits);
    let bytes = difficulty.to_bytes_be();
    if bytes.is_empty() {
        vec![0]
    } else {
        bytes
    }
}

/// Add two big-endian score byte arrays, returning the sum.
///
/// The result is stripped of leading zeros (except the final byte is always
/// kept so a zero sum is `[0]`).
pub fn add_scores(a: &[u8], b: &[u8]) -> Vec<u8> {
    let max_len = a.len().max(b.len());
    let mut result = vec![0u8; max_len + 1];
    let mut carry: u16 = 0;
    for i in 0..max_len {
        let av = if i < a.len() {
            a[a.len() - 1 - i] as u16
        } else {
            0
        };
        let bv = if i < b.len() {
            b[b.len() - 1 - i] as u16
        } else {
            0
        };
        let sum = av + bv + carry;
        result[max_len - i] = sum as u8;
        carry = sum >> 8;
    }
    result[0] = carry as u8;
    // Strip leading zeros, keeping at least one byte.
    let start = result
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(result.len() - 1);
    result[start..].to_vec()
}

// ---------------------------------------------------------------------------
// ModifierValidity
// ---------------------------------------------------------------------------

/// Semantic validity state for a block modifier.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModifierValidity {
    Invalid = 0,
    Valid = 1,
}

// ---------------------------------------------------------------------------
// Chain scoring & validity methods on HistoryDb
// ---------------------------------------------------------------------------

impl HistoryDb {
    /// Store cumulative difficulty score for a header.
    /// Score is stored as big-endian bytes of arbitrary length.
    pub fn put_header_score(&self, id: &ModifierId, score: &[u8]) -> Result<(), StorageError> {
        self.put_index(&header_score_key(id), score)
    }

    /// Get cumulative difficulty score for a header.
    pub fn get_header_score(&self, id: &ModifierId) -> Result<Option<Vec<u8>>, StorageError> {
        self.get_index(&header_score_key(id))
    }

    /// Compare two scores (big-endian byte arrays). Returns true if `a > b`.
    ///
    /// Strips leading zeros, then compares by length (longer wins), then
    /// compares byte-by-byte from the most-significant end.
    pub fn is_score_greater(a: &[u8], b: &[u8]) -> bool {
        // Strip leading zeros.
        let a = strip_leading_zeros(a);
        let b = strip_leading_zeros(b);

        if a.len() != b.len() {
            return a.len() > b.len();
        }
        // Same length: compare byte-by-byte (most significant first).
        a > b
    }

    /// Set semantic validity for a modifier.
    pub fn set_validity(
        &self,
        id: &ModifierId,
        valid: ModifierValidity,
    ) -> Result<(), StorageError> {
        self.put_index(&validity_key(id), &[valid as u8])
    }

    /// Get semantic validity for a modifier. Returns `None` if not yet validated.
    pub fn get_validity(&self, id: &ModifierId) -> Result<Option<ModifierValidity>, StorageError> {
        match self.get_index(&validity_key(id))? {
            None => Ok(None),
            Some(bytes) => {
                if bytes.is_empty() {
                    return Err(StorageError::Codec("validity value is empty".to_string()));
                }
                match bytes[0] {
                    0 => Ok(Some(ModifierValidity::Invalid)),
                    1 => Ok(Some(ModifierValidity::Valid)),
                    v => Err(StorageError::Codec(format!("unknown validity byte: {v}"))),
                }
            }
        }
    }

    /// Update the best header ID pointer.
    ///
    /// This writes directly to the same index key that [`best_header_id`](Self::best_header_id)
    /// reads from, so callers can use it to switch the canonical chain tip.
    pub fn set_best_header_id(&self, id: &ModifierId) -> Result<(), StorageError> {
        self.put_index(&best_header_key(), &id.0)
    }

    /// Store the best full block ID.
    pub fn set_best_full_block_id(&self, id: &ModifierId) -> Result<(), StorageError> {
        self.put_index(&best_full_block_key(), &id.0)
    }

    /// Get the best full block ID.
    pub fn best_full_block_id(&self) -> Result<Option<ModifierId>, StorageError> {
        match self.get_index(&best_full_block_key())? {
            None => Ok(None),
            Some(bytes) => {
                let arr: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
                    StorageError::Codec(format!(
                        "best_full_block_id: expected 32 bytes, got {}",
                        v.len()
                    ))
                })?;
                Ok(Some(ModifierId(arr)))
            }
        }
    }

    /// Store the last-applied block state version.
    pub fn set_state_version(&self, id: &ModifierId) -> Result<(), StorageError> {
        self.put_index(&state_version_key(), &id.0)
    }

    /// Get the last-applied block state version.
    pub fn get_state_version(&self) -> Result<Option<ModifierId>, StorageError> {
        match self.get_index(&state_version_key())? {
            None => Ok(None),
            Some(bytes) => {
                let arr: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
                    StorageError::Codec(format!(
                        "state_version: expected 32 bytes, got {}",
                        v.len()
                    ))
                })?;
                Ok(Some(ModifierId(arr)))
            }
        }
    }
}

/// Strips leading zero bytes from a big-endian byte slice.
fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let first_nonzero = bytes.iter().position(|&b| b != 0);
    match first_nonzero {
        Some(pos) => &bytes[pos..],
        None => &[], // all zeros or empty
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;
    use tempfile::TempDir;

    fn open_test_db() -> (HistoryDb, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = HistoryDb::open(dir.path()).unwrap();
        (db, dir)
    }

    fn test_modifier_id(fill: u8) -> ModifierId {
        ModifierId([fill; 32])
    }

    // --- Score tests ---

    #[test]
    fn put_get_header_score_roundtrip() {
        let (db, _dir) = open_test_db();
        let id = test_modifier_id(0xA1);
        let score = vec![0x00, 0x01, 0xFF]; // arbitrary big-endian score

        db.put_header_score(&id, &score).unwrap();
        let got = db.get_header_score(&id).unwrap();
        assert_eq!(got, Some(score));
    }

    #[test]
    fn missing_score_returns_none() {
        let (db, _dir) = open_test_db();
        let id = test_modifier_id(0xB2);
        assert_eq!(db.get_header_score(&id).unwrap(), None);
    }

    #[test]
    fn is_score_greater_basic() {
        // 0 vs 1
        assert!(HistoryDb::is_score_greater(&[1], &[0]));
        assert!(!HistoryDb::is_score_greater(&[0], &[1]));

        // 255 vs 256 (0x00FF vs 0x0100)
        assert!(HistoryDb::is_score_greater(&[0x01, 0x00], &[0xFF]));
        assert!(!HistoryDb::is_score_greater(&[0xFF], &[0x01, 0x00]));

        // Equal values
        assert!(!HistoryDb::is_score_greater(&[0x42], &[0x42]));
        assert!(!HistoryDb::is_score_greater(&[0x00, 0x42], &[0x42]));
    }

    #[test]
    fn is_score_greater_different_lengths() {
        // Longer (after stripping) is greater.
        let short = [0x01, 0x00]; // 256
        let long = [0x01, 0x00, 0x00]; // 65536
        assert!(HistoryDb::is_score_greater(&long, &short));
        assert!(!HistoryDb::is_score_greater(&short, &long));

        // Leading zeros should not affect comparison.
        let padded_short = [0x00, 0x00, 0x01, 0x00]; // still 256
        assert!(HistoryDb::is_score_greater(&long, &padded_short));
        assert!(!HistoryDb::is_score_greater(&padded_short, &long));
    }

    // --- Validity tests ---

    #[test]
    fn set_get_validity_roundtrip() {
        let (db, _dir) = open_test_db();
        let id_valid = test_modifier_id(0xC1);
        let id_invalid = test_modifier_id(0xC2);

        db.set_validity(&id_valid, ModifierValidity::Valid).unwrap();
        db.set_validity(&id_invalid, ModifierValidity::Invalid)
            .unwrap();

        assert_eq!(
            db.get_validity(&id_valid).unwrap(),
            Some(ModifierValidity::Valid)
        );
        assert_eq!(
            db.get_validity(&id_invalid).unwrap(),
            Some(ModifierValidity::Invalid)
        );
    }

    #[test]
    fn missing_validity_returns_none() {
        let (db, _dir) = open_test_db();
        let id = test_modifier_id(0xD1);
        assert_eq!(db.get_validity(&id).unwrap(), None);
    }

    // --- Best full block tests ---

    #[test]
    fn set_get_best_full_block_id_roundtrip() {
        let (db, _dir) = open_test_db();
        let id = test_modifier_id(0xE1);

        db.set_best_full_block_id(&id).unwrap();
        assert_eq!(db.best_full_block_id().unwrap(), Some(id));
    }

    #[test]
    fn missing_best_full_block_returns_none() {
        let (db, _dir) = open_test_db();
        assert_eq!(db.best_full_block_id().unwrap(), None);
    }

    // --- add_scores tests ---

    #[test]
    fn add_scores_basic() {
        assert_eq!(add_scores(&[0, 1], &[0, 2]), vec![3]);
    }

    #[test]
    fn add_scores_with_carry() {
        assert_eq!(add_scores(&[255], &[1]), vec![1, 0]);
    }

    // --- set_best_header_id tests ---

    #[test]
    fn set_best_header_id_roundtrip() {
        let (db, _dir) = open_test_db();
        let id = test_modifier_id(0xA5);

        assert!(db.best_header_id().unwrap().is_none());
        db.set_best_header_id(&id).unwrap();
        assert_eq!(db.best_header_id().unwrap(), Some(id));
    }

    // --- Persistence tests ---

    #[test]
    fn score_persists_across_reopen() {
        let dir = TempDir::new().unwrap();
        let id = test_modifier_id(0xF1);
        let score = vec![0x07, 0xFF, 0xAB];

        {
            let db = HistoryDb::open(dir.path()).unwrap();
            db.put_header_score(&id, &score).unwrap();
        }

        {
            let db = HistoryDb::open(dir.path()).unwrap();
            assert_eq!(db.get_header_score(&id).unwrap(), Some(score.clone()));
        }
    }

    #[test]
    fn validity_persists_across_reopen() {
        let dir = TempDir::new().unwrap();
        let id = test_modifier_id(0xF2);

        {
            let db = HistoryDb::open(dir.path()).unwrap();
            db.set_validity(&id, ModifierValidity::Valid).unwrap();
        }

        {
            let db = HistoryDb::open(dir.path()).unwrap();
            assert_eq!(db.get_validity(&id).unwrap(), Some(ModifierValidity::Valid));
        }
    }

    // --- State version tests ---

    #[test]
    fn state_version_roundtrip() {
        let (db, _dir) = open_test_db();
        let id = test_modifier_id(0xA7);

        assert!(db.get_state_version().unwrap().is_none());
        db.set_state_version(&id).unwrap();
        assert_eq!(db.get_state_version().unwrap(), Some(id));
    }

    #[test]
    fn state_version_persists_across_reopen() {
        let dir = TempDir::new().unwrap();
        let id = test_modifier_id(0xA8);

        {
            let db = HistoryDb::open(dir.path()).unwrap();
            db.set_state_version(&id).unwrap();
        }

        {
            let db = HistoryDb::open(dir.path()).unwrap();
            assert_eq!(db.get_state_version().unwrap(), Some(id));
        }
    }

    // --- difficulty_from_nbits regression tests ---

    #[test]
    fn difficulty_from_nbits_not_raw_bytes() {
        // The old buggy implementation returned the raw 4-byte nBits encoding.
        // The fixed version returns the decoded difficulty which is much larger.
        let n_bits: u64 = 0x1d00ffff;
        let result = difficulty_from_nbits(n_bits);
        let raw_nbits_bytes = (n_bits as u32).to_be_bytes().to_vec();

        // The decoded difficulty must NOT equal the raw nBits bytes.
        assert_ne!(
            result, raw_nbits_bytes,
            "difficulty_from_nbits must decode nBits, not return raw bytes"
        );

        // The decoded difficulty should be much longer than 4 bytes for this nBits value.
        assert!(
            result.len() > 4,
            "decoded difficulty for 0x1d00ffff should be more than 4 bytes, got {} bytes",
            result.len()
        );
    }

    #[test]
    fn difficulty_from_nbits_bitcoin_genesis_value() {
        // nBits = 0x1d00ffff is the classic Bitcoin genesis difficulty target.
        // decode_compact_bits(0x1d00ffff) should produce:
        //   0x00ffff * 2^(8*(0x1d-3)) = 0x00ffff * 2^(8*26) = 0x00ffff << 208
        // This is a 28-byte number (0x00ffff followed by 26 zero bytes).
        let n_bits: u64 = 0x1d00ffff;
        let result = difficulty_from_nbits(n_bits);
        let difficulty = BigUint::from_bytes_be(&result);

        // The expected value: 0xffff * 2^208
        let expected = BigUint::from(0xffffu64) << 208;
        assert_eq!(
            difficulty, expected,
            "decoded difficulty for 0x1d00ffff should be 0xffff * 2^208"
        );
    }

    #[test]
    fn difficulty_from_nbits_ergo_mainnet_value() {
        // A real Ergo mainnet nBits value.
        let n_bits: u64 = 0x1903842e;
        let result = difficulty_from_nbits(n_bits);
        let difficulty = BigUint::from_bytes_be(&result);

        // decode_compact_bits(0x1903842e):
        //   size = 0x19 = 25, mantissa = 0x03842e
        //   This expands to 0x03842e << (8 * (25 - 3)) = 0x03842e << 176
        let expected = BigUint::from(0x03842eu64) << 176;
        assert_eq!(
            difficulty, expected,
            "decoded difficulty for 0x1903842e should match decode_compact_bits"
        );

        // The decoded value should be much larger than 4 bytes.
        assert!(result.len() > 4);
    }

    #[test]
    fn cumulative_score_decoded_vs_raw_differ() {
        // Demonstrate that cumulative scores computed with decoded difficulties
        // are very different from scores computed with raw nBits bytes.
        let n_bits_a: u64 = 0x1d00ffff;
        let n_bits_b: u64 = 0x1903842e;

        // Decoded difficulty scores (correct).
        let score_a = difficulty_from_nbits(n_bits_a);
        let score_b = difficulty_from_nbits(n_bits_b);
        let cumulative_decoded = add_scores(&score_a, &score_b);

        // Raw nBits scores (old buggy behavior).
        let raw_a = (n_bits_a as u32).to_be_bytes().to_vec();
        let raw_b = (n_bits_b as u32).to_be_bytes().to_vec();
        let cumulative_raw = add_scores(&raw_a, &raw_b);

        // They must be different — the decoded scores are vastly larger.
        assert_ne!(
            cumulative_decoded, cumulative_raw,
            "cumulative scores from decoded vs raw nBits must differ"
        );

        // The decoded cumulative score should be much longer (more bytes).
        assert!(
            cumulative_decoded.len() > cumulative_raw.len(),
            "decoded cumulative score ({} bytes) should be longer than raw ({} bytes)",
            cumulative_decoded.len(),
            cumulative_raw.len()
        );
    }

    #[test]
    fn difficulty_from_nbits_small_value() {
        // nBits encoding for difficulty = 1: 0x01010000
        // size = 1, mantissa high byte = 0x01
        let n_bits: u64 = 0x01010000;
        let result = difficulty_from_nbits(n_bits);
        assert_eq!(result, vec![1], "difficulty 1 should encode as [1]");
    }
}
