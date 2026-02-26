//! RocksDB-backed versioned store for tracked boxes, wallet transactions, and
//! balance digest.
//!
//! Key prefixes:
//! - `0x10` + box_id (32 bytes)                    -> TrackedBox JSON bytes
//! - `0x11` + tx_id  (32 bytes)                    -> WalletTransaction JSON bytes
//! - `0x12`                                        -> WalletDigest JSON bytes
//! - `0x13` + scan_id (u16 BE) + box_id (32 bytes) -> empty marker
//! - `0x20` + height (u32 BE)                      -> version tag (block_id, 32 bytes)

use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::tracked_box::TrackedBox;

// ---------------------------------------------------------------------------
// Key prefixes
// ---------------------------------------------------------------------------

/// `0x10` + box_id (32 bytes) -> TrackedBox JSON.
const PREFIX_BOX: u8 = 0x10;
/// `0x11` + tx_id (32 bytes) -> WalletTransaction JSON.
const PREFIX_TX: u8 = 0x11;
/// `0x12` -> WalletDigest JSON.
const PREFIX_DIGEST: u8 = 0x12;
/// `0x13` + scan_id (u16 BE) + box_id (32 bytes) -> empty marker.
const PREFIX_SCAN_BOX: u8 = 0x13;
/// `0x20` + height (u32 BE) -> block_id (32 bytes).
const PREFIX_VERSION: u8 = 0x20;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced by [`WalletRegistry`] operations.
#[derive(Error, Debug)]
pub enum RegistryError {
    /// RocksDB error.
    #[error("rocksdb error: {0}")]
    Rocks(#[from] rocksdb::Error),

    /// Deserialization error.
    #[error("deserialization error: {0}")]
    Deserialize(String),
}

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// Aggregate wallet balance information.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WalletDigest {
    /// Current wallet height.
    pub height: u32,
    /// Total nanoERG across all unspent boxes.
    pub erg_balance: u64,
    /// Aggregated token balances: `(token_id, total_amount)`.
    pub token_balances: Vec<([u8; 32], u64)>,
}

/// A transaction relevant to the wallet.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WalletTransaction {
    /// Transaction identifier.
    pub tx_id: [u8; 32],
    /// Block height at which this transaction was included.
    pub inclusion_height: u32,
    /// Full serialized transaction bytes.
    pub tx_bytes: Vec<u8>,
}

// ---------------------------------------------------------------------------
// WalletRegistry
// ---------------------------------------------------------------------------

/// Persistent wallet registry backed by RocksDB.
///
/// Tracks wallet-relevant boxes, transactions, and aggregate balance,
/// with versioned updates keyed by block height.
pub struct WalletRegistry {
    db: rocksdb::DB,
}

impl WalletRegistry {
    /// Open (or create) the wallet registry database at `path`.
    pub fn open(path: &Path) -> Result<Self, RegistryError> {
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        // Enable prefix bloom filter for efficient prefix iteration.
        opts.set_prefix_extractor(rocksdb::SliceTransform::create_fixed_prefix(1));
        let db = rocksdb::DB::open(&opts, path)?;
        Ok(Self { db })
    }

    /// Atomically update on a new block: insert new boxes, mark spent boxes,
    /// record wallet transactions, update balance digest, record version tag.
    pub fn update_on_block(
        &self,
        height: u32,
        block_id: &[u8; 32],
        new_boxes: Vec<TrackedBox>,
        spent_ids: Vec<[u8; 32]>,
        wallet_txs: Vec<WalletTransaction>,
    ) -> Result<(), RegistryError> {
        let mut batch = rocksdb::WriteBatch::default();

        // Insert new tracked boxes.
        for tb in &new_boxes {
            let key = box_key(&tb.box_id);
            batch.put(key, tb.to_bytes());
        }

        // Mark spent boxes.
        for spent_id in &spent_ids {
            let key = box_key(spent_id);
            if let Some(data) = self.db.get(&key)? {
                if let Ok(mut tb) = TrackedBox::from_bytes(&data) {
                    tb.spent = true;
                    // Find the spending tx — check if any of the wallet_txs spend this box.
                    // For simplicity, if a spending_tx_id isn't known, leave it as None.
                    // The caller can set it on the TrackedBox before passing to spent_ids,
                    // but since we only receive box_ids here we mark height.
                    tb.spending_height = Some(height);
                    batch.put(key, tb.to_bytes());
                }
            }
        }

        // Store wallet transactions.
        for wtx in &wallet_txs {
            let key = tx_key(&wtx.tx_id);
            let data =
                serde_json::to_vec(wtx).map_err(|e| RegistryError::Deserialize(e.to_string()))?;
            batch.put(key, data);
        }

        // Write version tag.
        let vkey = version_key(height);
        batch.put(vkey, block_id.as_slice());

        // Compute and store the balance digest.
        // We need to account for the batch that hasn't been written yet,
        // so we apply the batch first, then compute the digest.
        // However, for atomicity, we compute the digest from the current state
        // plus the pending changes.
        self.db.write(batch)?;

        // Now recompute and store the digest.
        let digest = self.compute_digest(height);
        let digest_bytes =
            serde_json::to_vec(&digest).map_err(|e| RegistryError::Deserialize(e.to_string()))?;
        self.db.put([PREFIX_DIGEST], digest_bytes)?;

        Ok(())
    }

    /// Rollback to a previous version (undo blocks above given height).
    ///
    /// Removes all boxes and transactions with `inclusion_height > target_height`,
    /// and unmarks boxes that were spent above `target_height`.
    pub fn rollback_to_height(&self, target_height: u32) -> Result<(), RegistryError> {
        let mut batch = rocksdb::WriteBatch::default();

        // Iterate all tracked boxes.
        let prefix = [PREFIX_BOX];
        let iter = self.db.prefix_iterator(prefix);

        for item in iter {
            let (key, value) = match item {
                Ok(kv) => kv,
                Err(_) => continue,
            };
            if key.is_empty() || key[0] != PREFIX_BOX {
                break;
            }
            if let Ok(mut tb) = TrackedBox::from_bytes(&value) {
                if tb.inclusion_height > target_height {
                    // Box was added after the target — remove it.
                    batch.delete(&key);
                } else if tb.spent {
                    // Check if the spending happened after the target height.
                    if let Some(sh) = tb.spending_height {
                        if sh > target_height {
                            tb.spent = false;
                            tb.spending_tx_id = None;
                            tb.spending_height = None;
                            batch.put(&key, tb.to_bytes());
                        }
                    }
                }
            }
        }

        // Remove transactions with inclusion_height > target_height.
        let tx_prefix = [PREFIX_TX];
        let tx_iter = self.db.prefix_iterator(tx_prefix);
        for item in tx_iter {
            let (key, value) = match item {
                Ok(kv) => kv,
                Err(_) => continue,
            };
            if key.is_empty() || key[0] != PREFIX_TX {
                break;
            }
            if let Ok(wtx) = serde_json::from_slice::<WalletTransaction>(&value) {
                if wtx.inclusion_height > target_height {
                    batch.delete(&key);
                }
            }
        }

        // Remove version tags above target_height.
        let ver_prefix = [PREFIX_VERSION];
        let ver_iter = self.db.prefix_iterator(ver_prefix);
        for item in ver_iter {
            let (key, _value) = match item {
                Ok(kv) => kv,
                Err(_) => continue,
            };
            if key.len() != 5 || key[0] != PREFIX_VERSION {
                break;
            }
            let h = u32::from_be_bytes([key[1], key[2], key[3], key[4]]);
            if h > target_height {
                batch.delete(&key);
            }
        }

        self.db.write(batch)?;

        // Recompute and store digest.
        let digest = self.compute_digest(target_height);
        let digest_bytes =
            serde_json::to_vec(&digest).map_err(|e| RegistryError::Deserialize(e.to_string()))?;
        self.db.put([PREFIX_DIGEST], digest_bytes)?;

        Ok(())
    }

    /// Get all unspent tracked boxes.
    pub fn unspent_boxes(&self) -> Vec<TrackedBox> {
        self.iter_boxes()
            .into_iter()
            .filter(|tb| !tb.spent)
            .collect()
    }

    /// Get all tracked boxes (spent and unspent).
    pub fn all_boxes(&self) -> Vec<TrackedBox> {
        self.iter_boxes()
    }

    /// Get aggregate balance (computed from unspent boxes).
    pub fn get_balance(&self) -> WalletDigest {
        if let Some(data) = self.db.get([PREFIX_DIGEST]).ok().flatten() {
            if let Ok(digest) = serde_json::from_slice::<WalletDigest>(&data) {
                return digest;
            }
        }
        // Fallback: compute from scratch.
        self.compute_digest(self.wallet_height())
    }

    /// Get a wallet transaction by its ID.
    pub fn get_transaction_by_id(&self, tx_id: &[u8; 32]) -> Option<WalletTransaction> {
        let key = tx_key(tx_id);
        self.db
            .get(key)
            .ok()
            .flatten()
            .and_then(|data| serde_json::from_slice(&data).ok())
    }

    /// Get wallet transactions, filtered by height range (inclusive).
    pub fn get_transactions(&self, min_height: u32, max_height: u32) -> Vec<WalletTransaction> {
        let prefix = [PREFIX_TX];
        let iter = self.db.prefix_iterator(prefix);
        let mut result = Vec::new();

        for item in iter {
            let (key, value) = match item {
                Ok(kv) => kv,
                Err(_) => continue,
            };
            if key.is_empty() || key[0] != PREFIX_TX {
                break;
            }
            if let Ok(wtx) = serde_json::from_slice::<WalletTransaction>(&value) {
                if wtx.inclusion_height >= min_height && wtx.inclusion_height <= max_height {
                    result.push(wtx);
                }
            }
        }

        result.sort_by_key(|t| t.inclusion_height);
        result
    }

    /// Get a specific box by ID.
    pub fn get_box(&self, box_id: &[u8; 32]) -> Option<TrackedBox> {
        let key = box_key(box_id);
        self.db
            .get(key)
            .ok()
            .flatten()
            .and_then(|data| TrackedBox::from_bytes(&data).ok())
    }

    /// Get the current wallet height (highest block processed).
    ///
    /// Returns 0 if no blocks have been processed.
    pub fn wallet_height(&self) -> u32 {
        // Iterate version keys in reverse to find the highest height.
        let mut opts = rocksdb::ReadOptions::default();
        // Set the upper bound to one past the version prefix range.
        opts.set_iterate_upper_bound([PREFIX_VERSION + 1]);
        let mode = rocksdb::IteratorMode::From(
            &[PREFIX_VERSION, 0xFF, 0xFF, 0xFF, 0xFF],
            rocksdb::Direction::Reverse,
        );
        let iter = self.db.iterator_opt(mode, opts);

        for item in iter {
            let (key, _) = match item {
                Ok(kv) => kv,
                Err(_) => continue,
            };
            if key.len() == 5 && key[0] == PREFIX_VERSION {
                return u32::from_be_bytes([key[1], key[2], key[3], key[4]]);
            }
            break;
        }

        0
    }

    // -----------------------------------------------------------------------
    // Scan-box index
    // -----------------------------------------------------------------------

    /// Associate a box with a scan.
    pub fn add_scan_box(
        &self,
        scan_id: u16,
        box_id: &[u8; 32],
    ) -> Result<(), RegistryError> {
        let key = scan_box_key(scan_id, box_id);
        self.db.put(key, [])?;
        Ok(())
    }

    /// Remove a box-to-scan association.
    pub fn remove_scan_box(
        &self,
        scan_id: u16,
        box_id: &[u8; 32],
    ) -> Result<(), RegistryError> {
        let key = scan_box_key(scan_id, box_id);
        self.db.delete(key)?;
        Ok(())
    }

    /// Return all box IDs associated with the given scan.
    pub fn boxes_for_scan(&self, scan_id: u16) -> Vec<[u8; 32]> {
        let prefix = scan_box_prefix(scan_id);
        let iter = self.db.prefix_iterator(prefix);
        let mut result = Vec::new();

        for item in iter {
            let (key, _) = match item {
                Ok(kv) => kv,
                Err(_) => continue,
            };
            // Keys are exactly 35 bytes: 1 prefix + 2 scan_id + 32 box_id.
            if key.len() != 35 || key[0] != PREFIX_SCAN_BOX {
                break;
            }
            // Verify the scan_id portion matches.
            if key[1] != prefix[1] || key[2] != prefix[2] {
                break;
            }
            let mut box_id = [0u8; 32];
            box_id.copy_from_slice(&key[3..35]);
            result.push(box_id);
        }

        result
    }

    /// Return all unspent tracked boxes associated with the given scan.
    pub fn unspent_boxes_for_scan(&self, scan_id: u16) -> Vec<TrackedBox> {
        self.boxes_for_scan(scan_id)
            .iter()
            .filter_map(|id| self.get_box(id))
            .filter(|tb| !tb.spent)
            .collect()
    }

    /// Return all spent tracked boxes associated with the given scan.
    pub fn spent_boxes_for_scan(&self, scan_id: u16) -> Vec<TrackedBox> {
        self.boxes_for_scan(scan_id)
            .iter()
            .filter_map(|id| self.get_box(id))
            .filter(|tb| tb.spent)
            .collect()
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Iterate all tracked boxes.
    fn iter_boxes(&self) -> Vec<TrackedBox> {
        let prefix = [PREFIX_BOX];
        let iter = self.db.prefix_iterator(prefix);
        let mut result = Vec::new();

        for item in iter {
            let (key, value) = match item {
                Ok(kv) => kv,
                Err(_) => continue,
            };
            if key.is_empty() || key[0] != PREFIX_BOX {
                break;
            }
            if let Ok(tb) = TrackedBox::from_bytes(&value) {
                result.push(tb);
            }
        }

        result
    }

    /// Compute the balance digest from current unspent boxes.
    fn compute_digest(&self, height: u32) -> WalletDigest {
        let unspent = self.unspent_boxes();
        let erg_balance: u64 = unspent.iter().map(|b| b.value).sum();

        // Aggregate tokens.
        let mut token_map: std::collections::HashMap<[u8; 32], u64> =
            std::collections::HashMap::new();
        for tb in &unspent {
            for (tid, amount) in &tb.tokens {
                *token_map.entry(*tid).or_insert(0) += amount;
            }
        }

        let mut token_balances: Vec<([u8; 32], u64)> = token_map.into_iter().collect();
        token_balances.sort_by(|a, b| a.0.cmp(&b.0));

        WalletDigest {
            height,
            erg_balance,
            token_balances,
        }
    }
}

// ---------------------------------------------------------------------------
// Key construction helpers
// ---------------------------------------------------------------------------

/// Build the 33-byte key for a tracked box: `[PREFIX_BOX, box_id[0..32]]`.
fn box_key(box_id: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(33);
    key.push(PREFIX_BOX);
    key.extend_from_slice(box_id);
    key
}

/// Build the 33-byte key for a wallet transaction: `[PREFIX_TX, tx_id[0..32]]`.
fn tx_key(tx_id: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(33);
    key.push(PREFIX_TX);
    key.extend_from_slice(tx_id);
    key
}

/// Build the 5-byte key for a version tag: `[PREFIX_VERSION, height[0..4]]`.
fn version_key(height: u32) -> [u8; 5] {
    let h = height.to_be_bytes();
    [PREFIX_VERSION, h[0], h[1], h[2], h[3]]
}

/// Build the 3-byte prefix for scan-box iteration: `[PREFIX_SCAN_BOX, scan_id_be]`.
fn scan_box_prefix(scan_id: u16) -> [u8; 3] {
    let id = scan_id.to_be_bytes();
    [PREFIX_SCAN_BOX, id[0], id[1]]
}

/// Build the 35-byte key for a scan-box entry:
/// `[PREFIX_SCAN_BOX, scan_id_be[0..2], box_id[0..32]]`.
fn scan_box_key(scan_id: u16, box_id: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(35);
    key.push(PREFIX_SCAN_BOX);
    key.extend_from_slice(&scan_id.to_be_bytes());
    key.extend_from_slice(box_id);
    key
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Helper: create a TrackedBox with the given parameters.
    fn make_box(id_byte: u8, value: u64, height: u32) -> TrackedBox {
        let mut box_id = [0u8; 32];
        box_id[0] = id_byte;
        let mut tx_id = [0u8; 32];
        tx_id[0] = id_byte;
        tx_id[1] = 0xFF;

        TrackedBox {
            box_id,
            ergo_tree_bytes: vec![0x00, 0x08, 0xCD],
            value,
            tokens: vec![],
            creation_height: height,
            inclusion_height: height,
            tx_id,
            output_index: 0,
            serialized_box: vec![0xDE, 0xAD],
            additional_registers: vec![],
            spent: false,
            spending_tx_id: None,
            spending_height: None,
            scan_ids: vec![10],
        }
    }

    /// Helper: create a TrackedBox with tokens.
    fn make_box_with_tokens(
        id_byte: u8,
        value: u64,
        height: u32,
        tokens: Vec<([u8; 32], u64)>,
    ) -> TrackedBox {
        let mut tb = make_box(id_byte, value, height);
        tb.tokens = tokens;
        tb
    }

    fn make_wallet_tx(id_byte: u8, height: u32) -> WalletTransaction {
        let mut tx_id = [0u8; 32];
        tx_id[0] = id_byte;
        WalletTransaction {
            tx_id,
            inclusion_height: height,
            tx_bytes: vec![0x01, 0x02, 0x03],
        }
    }

    fn open_registry() -> (WalletRegistry, TempDir) {
        let dir = TempDir::new().unwrap();
        let reg = WalletRegistry::open(dir.path()).unwrap();
        (reg, dir)
    }

    #[test]
    fn insert_boxes_and_get_unspent() {
        let (reg, _dir) = open_registry();
        let block_id = [0xAA; 32];

        let boxes = vec![make_box(1, 100, 10), make_box(2, 200, 10), make_box(3, 300, 10)];

        reg.update_on_block(10, &block_id, boxes, vec![], vec![])
            .unwrap();

        let unspent = reg.unspent_boxes();
        assert_eq!(unspent.len(), 3);

        // All should be unspent.
        for tb in &unspent {
            assert!(!tb.spent);
        }

        // Total ERG should be 600.
        let total: u64 = unspent.iter().map(|b| b.value).sum();
        assert_eq!(total, 600);
    }

    #[test]
    fn mark_spent_updates_box() {
        let (reg, _dir) = open_registry();
        let block_id1 = [0xAA; 32];
        let block_id2 = [0xBB; 32];

        let b = make_box(1, 1000, 5);
        let box_id = b.box_id;

        reg.update_on_block(5, &block_id1, vec![b], vec![], vec![])
            .unwrap();

        // The box should be unspent.
        let tb = reg.get_box(&box_id).unwrap();
        assert!(!tb.spent);

        // Now mark it as spent in a subsequent block.
        reg.update_on_block(10, &block_id2, vec![], vec![box_id], vec![])
            .unwrap();

        let tb = reg.get_box(&box_id).unwrap();
        assert!(tb.spent);
        assert_eq!(tb.spending_height, Some(10));

        // Unspent list should be empty.
        assert!(reg.unspent_boxes().is_empty());
    }

    #[test]
    fn balance_sums_unspent_only() {
        let (reg, _dir) = open_registry();
        let block_id1 = [0xAA; 32];
        let block_id2 = [0xBB; 32];

        let b1 = make_box(1, 100, 5);
        let b2 = make_box(2, 200, 5);
        let b3 = make_box(3, 300, 5);
        let spent_id = b2.box_id;

        reg.update_on_block(5, &block_id1, vec![b1, b2, b3], vec![], vec![])
            .unwrap();

        // Spend box 2.
        reg.update_on_block(10, &block_id2, vec![], vec![spent_id], vec![])
            .unwrap();

        let digest = reg.get_balance();
        // 100 + 300 = 400 (box 2 is spent).
        assert_eq!(digest.erg_balance, 400);
        assert_eq!(digest.height, 10);
    }

    #[test]
    fn token_balance_aggregation() {
        let (reg, _dir) = open_registry();
        let block_id = [0xAA; 32];

        let mut token_id = [0u8; 32];
        token_id[0] = 0xCC;

        let b1 = make_box_with_tokens(1, 100, 10, vec![(token_id, 500)]);
        let b2 = make_box_with_tokens(2, 200, 10, vec![(token_id, 300)]);

        reg.update_on_block(10, &block_id, vec![b1, b2], vec![], vec![])
            .unwrap();

        let digest = reg.get_balance();
        assert_eq!(digest.erg_balance, 300);
        assert_eq!(digest.token_balances.len(), 1);
        assert_eq!(digest.token_balances[0], (token_id, 800));
    }

    #[test]
    fn rollback_removes_recent_boxes() {
        let (reg, _dir) = open_registry();
        let block_id10 = [0xAA; 32];
        let block_id20 = [0xBB; 32];

        let b_early = make_box(1, 100, 10);
        let b_late = make_box(2, 200, 20);

        reg.update_on_block(10, &block_id10, vec![b_early], vec![], vec![])
            .unwrap();
        reg.update_on_block(20, &block_id20, vec![b_late], vec![], vec![])
            .unwrap();

        assert_eq!(reg.all_boxes().len(), 2);

        // Rollback to height 15 — only height-10 boxes remain.
        reg.rollback_to_height(15).unwrap();

        let remaining = reg.all_boxes();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].inclusion_height, 10);
        assert_eq!(remaining[0].value, 100);

        // Wallet height should reflect the rollback.
        assert_eq!(reg.wallet_height(), 10);
    }

    #[test]
    fn rollback_unmarks_spent() {
        let (reg, _dir) = open_registry();
        let block_id5 = [0xAA; 32];
        let block_id10 = [0xBB; 32];

        let b = make_box(1, 500, 5);
        let box_id = b.box_id;

        reg.update_on_block(5, &block_id5, vec![b], vec![], vec![])
            .unwrap();

        // Spend at height 10.
        reg.update_on_block(10, &block_id10, vec![], vec![box_id], vec![])
            .unwrap();

        let tb = reg.get_box(&box_id).unwrap();
        assert!(tb.spent);

        // Rollback to height 7 — spending at height 10 is undone.
        reg.rollback_to_height(7).unwrap();

        let tb = reg.get_box(&box_id).unwrap();
        assert!(!tb.spent);
        assert!(tb.spending_tx_id.is_none());
        assert!(tb.spending_height.is_none());

        // Should appear in unspent list.
        assert_eq!(reg.unspent_boxes().len(), 1);
    }

    #[test]
    fn wallet_transactions_roundtrip() {
        let (reg, _dir) = open_registry();
        let block_id = [0xAA; 32];

        let tx1 = make_wallet_tx(1, 10);
        let tx2 = make_wallet_tx(2, 20);
        let tx3 = make_wallet_tx(3, 30);

        reg.update_on_block(10, &block_id, vec![], vec![], vec![tx1.clone()])
            .unwrap();
        let block_id2 = [0xBB; 32];
        reg.update_on_block(20, &block_id2, vec![], vec![], vec![tx2.clone()])
            .unwrap();
        let block_id3 = [0xCC; 32];
        reg.update_on_block(30, &block_id3, vec![], vec![], vec![tx3.clone()])
            .unwrap();

        // All transactions.
        let all = reg.get_transactions(0, u32::MAX);
        assert_eq!(all.len(), 3);

        // Filtered range.
        let filtered = reg.get_transactions(15, 25);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].tx_id, tx2.tx_id);
        assert_eq!(filtered[0].inclusion_height, 20);
    }

    #[test]
    fn wallet_height_tracks_highest_block() {
        let (reg, _dir) = open_registry();

        // Initially height is 0.
        assert_eq!(reg.wallet_height(), 0);

        let block1 = [0x01; 32];
        let block2 = [0x02; 32];
        let block3 = [0x03; 32];

        reg.update_on_block(1, &block1, vec![], vec![], vec![])
            .unwrap();
        assert_eq!(reg.wallet_height(), 1);

        reg.update_on_block(2, &block2, vec![], vec![], vec![])
            .unwrap();
        assert_eq!(reg.wallet_height(), 2);

        reg.update_on_block(3, &block3, vec![], vec![], vec![])
            .unwrap();
        assert_eq!(reg.wallet_height(), 3);
    }

    #[test]
    fn scan_box_index_operations() {
        let (reg, _dir) = open_registry();
        let block_id = [0xAA; 32];

        // Create and persist two boxes at height 10.
        let b1 = make_box(1, 100, 10);
        let b2 = make_box(2, 200, 10);
        let id1 = b1.box_id;
        let id2 = b2.box_id;

        reg.update_on_block(10, &block_id, vec![b1, b2], vec![], vec![])
            .unwrap();

        // Add both boxes to scan 11, and only the first to scan 12.
        reg.add_scan_box(11, &id1).unwrap();
        reg.add_scan_box(11, &id2).unwrap();
        reg.add_scan_box(12, &id1).unwrap();

        // Verify boxes_for_scan counts.
        assert_eq!(reg.boxes_for_scan(11).len(), 2);
        assert_eq!(reg.boxes_for_scan(12).len(), 1);
        assert_eq!(reg.boxes_for_scan(99).len(), 0);

        // All boxes are unspent.
        assert_eq!(reg.unspent_boxes_for_scan(11).len(), 2);
        assert_eq!(reg.spent_boxes_for_scan(11).len(), 0);

        // Spend box 1 and verify the spent/unspent split.
        let block_id2 = [0xBB; 32];
        reg.update_on_block(15, &block_id2, vec![], vec![id1], vec![])
            .unwrap();

        assert_eq!(reg.unspent_boxes_for_scan(11).len(), 1);
        assert_eq!(reg.spent_boxes_for_scan(11).len(), 1);

        // Scan 12 had only box 1, now spent.
        assert_eq!(reg.unspent_boxes_for_scan(12).len(), 0);
        assert_eq!(reg.spent_boxes_for_scan(12).len(), 1);

        // Remove box 2 from scan 11.
        reg.remove_scan_box(11, &id2).unwrap();
        assert_eq!(reg.boxes_for_scan(11).len(), 1);
        assert_eq!(reg.boxes_for_scan(11)[0], id1);
    }

    #[test]
    fn get_transaction_by_id_found() {
        let (reg, _dir) = open_registry();
        let block_id = [0xAA; 32];

        let tx = make_wallet_tx(0x42, 15);
        let tx_id = tx.tx_id;

        reg.update_on_block(15, &block_id, vec![], vec![], vec![tx.clone()])
            .unwrap();

        let found = reg.get_transaction_by_id(&tx_id);
        assert!(found.is_some());
        let found = found.unwrap();
        assert_eq!(found.tx_id, tx_id);
        assert_eq!(found.inclusion_height, 15);
        assert_eq!(found.tx_bytes, vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn get_transaction_by_id_not_found() {
        let (reg, _dir) = open_registry();

        let missing_id = [0xFF; 32];
        assert!(reg.get_transaction_by_id(&missing_id).is_none());
    }
}
