//! RocksDB-backed persistent storage for wallet metadata.
//!
//! Stores derived addresses, the change address, and the next derivation index
//! using prefixed keys so everything lives in a single column family.

use std::path::Path;

use thiserror::Error;

// ---------------------------------------------------------------------------
// Key prefixes
// ---------------------------------------------------------------------------

/// `0x01` + index (u32 big-endian) -> address string (UTF-8 bytes).
const PREFIX_ADDRESS: u8 = 0x01;
/// `0x02` -> change address (UTF-8 bytes).
const PREFIX_CHANGE: u8 = 0x02;
/// `0x03` -> next derivation index (u32 big-endian).
const PREFIX_NEXT_INDEX: u8 = 0x03;
/// `0x04` + scan_id (u16 big-endian) -> Scan JSON bytes.
const PREFIX_SCAN: u8 = 0x04;
/// `0x05` -> last used scan ID (u16 big-endian).
const PREFIX_LAST_SCAN_ID: u8 = 0x05;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced by [`WalletStorage`] operations.
#[derive(Error, Debug)]
pub enum WalletStorageError {
    /// RocksDB error.
    #[error("rocksdb error: {0}")]
    Rocks(#[from] rocksdb::Error),
}

// ---------------------------------------------------------------------------
// WalletStorage
// ---------------------------------------------------------------------------

/// Persistent wallet metadata backed by RocksDB.
pub struct WalletStorage {
    db: rocksdb::DB,
}

impl WalletStorage {
    /// Open (or create) the wallet storage database at `path`.
    pub fn open(path: &Path) -> Result<Self, WalletStorageError> {
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        let db = rocksdb::DB::open(&opts, path)?;
        Ok(Self { db })
    }

    /// Store a derived address at the given derivation index.
    pub fn store_address(&self, index: u32, address: &str) -> Result<(), WalletStorageError> {
        let key = address_key(index);
        self.db.put(key, address.as_bytes())?;
        Ok(())
    }

    /// Return all stored (index, address) pairs, sorted by index.
    pub fn get_addresses(&self) -> Vec<(u32, String)> {
        let prefix = [PREFIX_ADDRESS];
        let iter = self.db.prefix_iterator(prefix);
        let mut result = Vec::new();

        for item in iter {
            let (key, value) = match item {
                Ok(kv) => kv,
                Err(_) => continue,
            };
            // Keys must be exactly 5 bytes: 1 prefix + 4 index.
            if key.len() == 5 && key[0] == PREFIX_ADDRESS {
                let index = u32::from_be_bytes([key[1], key[2], key[3], key[4]]);
                if let Ok(addr) = String::from_utf8(value.to_vec()) {
                    result.push((index, addr));
                }
            } else {
                // We have iterated past the prefix.
                break;
            }
        }

        result.sort_by_key(|(idx, _)| *idx);
        result
    }

    /// Set the wallet's change address.
    pub fn set_change_address(&self, addr: &str) -> Result<(), WalletStorageError> {
        self.db.put([PREFIX_CHANGE], addr.as_bytes())?;
        Ok(())
    }

    /// Get the wallet's change address, if set.
    pub fn get_change_address(&self) -> Option<String> {
        self.db
            .get([PREFIX_CHANGE])
            .ok()
            .flatten()
            .and_then(|v| String::from_utf8(v).ok())
    }

    /// Set the next derivation index.
    pub fn set_next_index(&self, idx: u32) -> Result<(), WalletStorageError> {
        self.db.put([PREFIX_NEXT_INDEX], idx.to_be_bytes())?;
        Ok(())
    }

    /// Get the next derivation index. Returns 0 if not yet set.
    pub fn get_next_index(&self) -> u32 {
        self.db
            .get([PREFIX_NEXT_INDEX])
            .ok()
            .flatten()
            .and_then(|v| v.try_into().ok().map(u32::from_be_bytes))
            .unwrap_or(0)
    }

    // -- Scan persistence ------------------------------------------------

    /// Persist a scan, keyed by its `scan_id`.
    pub fn store_scan(
        &self,
        scan: &crate::scan_types::Scan,
    ) -> Result<(), WalletStorageError> {
        let key = scan_key(scan.scan_id);
        let value =
            serde_json::to_vec(scan).expect("Scan serialization must not fail");
        self.db.put(key, value)?;
        Ok(())
    }

    /// Remove a scan by ID. No-op if the scan does not exist.
    pub fn remove_scan(&self, scan_id: u16) -> Result<(), WalletStorageError> {
        self.db.delete(scan_key(scan_id))?;
        Ok(())
    }

    /// Load a single scan by ID, returning `None` if not found.
    pub fn get_scan(&self, scan_id: u16) -> Option<crate::scan_types::Scan> {
        self.db
            .get(scan_key(scan_id))
            .ok()
            .flatten()
            .and_then(|v| serde_json::from_slice(&v).ok())
    }

    /// Return all stored scans, sorted by `scan_id`.
    pub fn get_all_scans(&self) -> Vec<crate::scan_types::Scan> {
        let prefix = [PREFIX_SCAN];
        let iter = self.db.prefix_iterator(prefix);
        let mut result = Vec::new();

        for item in iter {
            let (key, value) = match item {
                Ok(kv) => kv,
                Err(_) => continue,
            };
            // Keys must be exactly 3 bytes: 1 prefix + 2 scan_id.
            if key.len() == 3 && key[0] == PREFIX_SCAN {
                if let Ok(scan) = serde_json::from_slice::<crate::scan_types::Scan>(&value) {
                    result.push(scan);
                }
            } else {
                // We have iterated past the prefix.
                break;
            }
        }

        result.sort_by_key(|s| s.scan_id);
        result
    }

    /// Allocate and return the next available scan ID.
    ///
    /// Reads the last used scan ID (defaulting to
    /// [`crate::scan_types::PAYMENTS_SCAN_ID`] = 10 when unset), increments it
    /// by one, persists the new value, and returns it.
    pub fn next_scan_id(&self) -> Result<u16, WalletStorageError> {
        let current = self.get_last_scan_id();
        let next = current + 1;
        self.db
            .put([PREFIX_LAST_SCAN_ID], next.to_be_bytes())?;
        Ok(next)
    }

    /// Return the last used scan ID. Defaults to 10 (`PAYMENTS_SCAN_ID`) when
    /// no value has been stored yet.
    pub fn get_last_scan_id(&self) -> u16 {
        self.db
            .get([PREFIX_LAST_SCAN_ID])
            .ok()
            .flatten()
            .and_then(|v| v.try_into().ok().map(u16::from_be_bytes))
            .unwrap_or(10)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build the 5-byte key for an address entry: `[PREFIX_ADDRESS, idx[0..4]]`.
fn address_key(index: u32) -> [u8; 5] {
    let idx = index.to_be_bytes();
    [PREFIX_ADDRESS, idx[0], idx[1], idx[2], idx[3]]
}

/// Build the 3-byte key for a scan entry: `[PREFIX_SCAN, id[0], id[1]]`.
fn scan_key(scan_id: u16) -> [u8; 3] {
    let id = scan_id.to_be_bytes();
    [PREFIX_SCAN, id[0], id[1]]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn store_and_get_addresses() {
        let dir = TempDir::new().unwrap();
        let ws = WalletStorage::open(dir.path()).unwrap();

        ws.store_address(0, "9addr0").unwrap();
        ws.store_address(1, "9addr1").unwrap();
        ws.store_address(2, "9addr2").unwrap();

        let addrs = ws.get_addresses();
        assert_eq!(addrs.len(), 3);
        assert_eq!(addrs[0], (0, "9addr0".to_string()));
        assert_eq!(addrs[1], (1, "9addr1".to_string()));
        assert_eq!(addrs[2], (2, "9addr2".to_string()));
    }

    #[test]
    fn change_address_roundtrip() {
        let dir = TempDir::new().unwrap();
        let ws = WalletStorage::open(dir.path()).unwrap();

        assert!(ws.get_change_address().is_none());

        ws.set_change_address("9changeAddr").unwrap();
        assert_eq!(ws.get_change_address(), Some("9changeAddr".to_string()));
    }

    #[test]
    fn next_index_default_zero() {
        let dir = TempDir::new().unwrap();
        let ws = WalletStorage::open(dir.path()).unwrap();

        assert_eq!(ws.get_next_index(), 0);
    }

    #[test]
    fn next_index_roundtrip() {
        let dir = TempDir::new().unwrap();
        let ws = WalletStorage::open(dir.path()).unwrap();

        ws.set_next_index(42).unwrap();
        assert_eq!(ws.get_next_index(), 42);
    }

    #[test]
    fn storage_survives_reopen() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("wallet_db");

        // Open, write, drop.
        {
            let ws = WalletStorage::open(&db_path).unwrap();
            ws.store_address(0, "9persist0").unwrap();
            ws.store_address(1, "9persist1").unwrap();
            ws.set_change_address("9change").unwrap();
            ws.set_next_index(7).unwrap();
        }

        // Reopen and verify.
        {
            let ws = WalletStorage::open(&db_path).unwrap();
            let addrs = ws.get_addresses();
            assert_eq!(addrs.len(), 2);
            assert_eq!(addrs[0], (0, "9persist0".to_string()));
            assert_eq!(addrs[1], (1, "9persist1".to_string()));
            assert_eq!(ws.get_change_address(), Some("9change".to_string()));
            assert_eq!(ws.get_next_index(), 7);
        }
    }

    // -- Scan persistence ------------------------------------------------

    fn test_scan(id: u16, name: &str) -> crate::scan_types::Scan {
        crate::scan_types::Scan {
            scan_id: id,
            scan_name: name.to_owned(),
            tracking_rule: crate::scan_types::ScanningPredicate::ContainsAsset {
                asset_id: "aa".repeat(32),
            },
            wallet_interaction: crate::scan_types::ScanWalletInteraction::Off,
            remove_offchain: false,
        }
    }

    #[test]
    fn scan_crud_operations() {
        let dir = TempDir::new().unwrap();
        let ws = WalletStorage::open(dir.path()).unwrap();

        // Initially empty.
        assert!(ws.get_all_scans().is_empty());
        assert!(ws.get_scan(11).is_none());

        // Store two scans.
        let scan_a = test_scan(11, "Scan A");
        let scan_b = test_scan(12, "Scan B");
        ws.store_scan(&scan_a).unwrap();
        ws.store_scan(&scan_b).unwrap();

        // Get by ID.
        assert_eq!(ws.get_scan(11), Some(scan_a.clone()));
        assert_eq!(ws.get_scan(12), Some(scan_b.clone()));
        assert!(ws.get_scan(99).is_none());

        // Get all (sorted by scan_id).
        let all = ws.get_all_scans();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].scan_id, 11);
        assert_eq!(all[1].scan_id, 12);

        // Remove one.
        ws.remove_scan(11).unwrap();
        assert!(ws.get_scan(11).is_none());
        let all = ws.get_all_scans();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].scan_id, 12);

        // Remove again is a no-op.
        ws.remove_scan(11).unwrap();
    }

    #[test]
    fn next_scan_id_increments() {
        let dir = TempDir::new().unwrap();
        let ws = WalletStorage::open(dir.path()).unwrap();

        // Default last scan ID is 10 (PAYMENTS_SCAN_ID).
        assert_eq!(ws.get_last_scan_id(), 10);

        // First call returns 11.
        assert_eq!(ws.next_scan_id().unwrap(), 11);
        assert_eq!(ws.get_last_scan_id(), 11);

        // Subsequent calls continue incrementing.
        assert_eq!(ws.next_scan_id().unwrap(), 12);
        assert_eq!(ws.next_scan_id().unwrap(), 13);
        assert_eq!(ws.get_last_scan_id(), 13);
    }
}
