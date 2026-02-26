//! Block section storage helpers for [`HistoryDb`].
//!
//! Provides methods to store and load Extension, ADProofs, and
//! BlockTransactions sections by serializing them through the ergo-wire
//! codec and persisting the bytes under type-specific keys.

use ergo_types::ad_proofs::ADProofs;
use ergo_types::block_transactions::BlockTransactions;
use ergo_types::extension::Extension;
use ergo_types::modifier_id::ModifierId;
use ergo_wire::ad_proofs_ser::{parse_ad_proofs, serialize_ad_proofs};
use ergo_wire::block_transactions_ser::{parse_block_transactions, serialize_block_transactions};
use ergo_wire::extension_ser::{parse_extension, serialize_extension};

use crate::history_db::{HistoryDb, StorageError};

/// Modifier type ID for Extension sections (matches Scala `Extension.modifierTypeId = 108`).
const EXTENSION_TYPE_ID: u8 = 108;

/// Modifier type ID for ADProofs sections (matches Scala `ADProofs.modifierTypeId = 104`).
const AD_PROOFS_TYPE_ID: u8 = 104;

/// Modifier type ID for BlockTransactions sections (matches Scala `BlockTransactions.modifierTypeId = 102`).
const BLOCK_TX_TYPE_ID: u8 = 102;

impl HistoryDb {
    /// Serialize and store an [`Extension`] section.
    pub fn store_extension(
        &self,
        id: &ModifierId,
        ext: &Extension,
    ) -> Result<(), StorageError> {
        let bytes = serialize_extension(ext);
        self.put_modifier(EXTENSION_TYPE_ID, id, &bytes)
    }

    /// Load and deserialize an [`Extension`] section.
    ///
    /// Returns `Ok(None)` if no extension with the given ID exists.
    pub fn load_extension(&self, id: &ModifierId) -> Result<Option<Extension>, StorageError> {
        match self.get_modifier(EXTENSION_TYPE_ID, id)? {
            None => Ok(None),
            Some(data) => {
                let ext =
                    parse_extension(&data).map_err(|e| StorageError::Codec(e.to_string()))?;
                Ok(Some(ext))
            }
        }
    }

    /// Serialize and store an [`ADProofs`] section.
    pub fn store_ad_proofs(
        &self,
        id: &ModifierId,
        proofs: &ADProofs,
    ) -> Result<(), StorageError> {
        let bytes = serialize_ad_proofs(proofs);
        self.put_modifier(AD_PROOFS_TYPE_ID, id, &bytes)
    }

    /// Load and deserialize an [`ADProofs`] section.
    ///
    /// Returns `Ok(None)` if no AD proofs with the given ID exist.
    pub fn load_ad_proofs(&self, id: &ModifierId) -> Result<Option<ADProofs>, StorageError> {
        match self.get_modifier(AD_PROOFS_TYPE_ID, id)? {
            None => Ok(None),
            Some(data) => {
                let proofs =
                    parse_ad_proofs(&data).map_err(|e| StorageError::Codec(e.to_string()))?;
                Ok(Some(proofs))
            }
        }
    }

    /// Serialize and store a [`BlockTransactions`] section.
    pub fn store_block_transactions(
        &self,
        id: &ModifierId,
        bt: &BlockTransactions,
    ) -> Result<(), StorageError> {
        let bytes = serialize_block_transactions(bt);
        self.put_modifier(BLOCK_TX_TYPE_ID, id, &bytes)
    }

    /// Load and deserialize a [`BlockTransactions`] section.
    ///
    /// Returns `Ok(None)` if no block transactions with the given ID exist.
    pub fn load_block_transactions(
        &self,
        id: &ModifierId,
    ) -> Result<Option<BlockTransactions>, StorageError> {
        match self.get_modifier(BLOCK_TX_TYPE_ID, id)? {
            None => Ok(None),
            Some(data) => {
                let bt = parse_block_transactions(&data)
                    .map_err(|e| StorageError::Codec(e.to_string()))?;
                Ok(Some(bt))
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

    fn make_id(fill: u8) -> ModifierId {
        ModifierId([fill; 32])
    }

    fn sample_extension() -> Extension {
        Extension {
            header_id: ModifierId([0xAA; 32]),
            fields: vec![
                ([0x00, 0x01], vec![0x10, 0x20]),
                ([0x01, 0x00], vec![0xFF; 32]),
            ],
        }
    }

    fn sample_ad_proofs() -> ADProofs {
        ADProofs {
            header_id: ModifierId([0xBB; 32]),
            proof_bytes: vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03],
        }
    }

    fn sample_block_transactions() -> BlockTransactions {
        BlockTransactions {
            header_id: ModifierId([0xCC; 32]),
            block_version: 2,
            tx_bytes: vec![vec![0x01, 0x02, 0x03], vec![0x04, 0x05]],
        }
    }

    // 1. store_load_extension — roundtrip with fields
    #[test]
    fn store_load_extension() {
        let (db, _dir) = open_test_db();
        let id = make_id(0x01);
        let ext = sample_extension();

        db.store_extension(&id, &ext).unwrap();

        let loaded = db.load_extension(&id).unwrap().expect("extension should exist");
        assert_eq!(loaded, ext);
        assert_eq!(loaded.fields.len(), 2);
        assert_eq!(loaded.fields[0].0, [0x00, 0x01]);
        assert_eq!(loaded.fields[0].1, vec![0x10, 0x20]);
    }

    // 2. store_load_ad_proofs — roundtrip with proof bytes
    #[test]
    fn store_load_ad_proofs() {
        let (db, _dir) = open_test_db();
        let id = make_id(0x02);
        let proofs = sample_ad_proofs();

        db.store_ad_proofs(&id, &proofs).unwrap();

        let loaded = db.load_ad_proofs(&id).unwrap().expect("proofs should exist");
        assert_eq!(loaded, proofs);
        assert_eq!(loaded.proof_bytes, vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03]);
    }

    // 3. store_load_block_transactions — roundtrip with tx bytes
    #[test]
    fn store_load_block_transactions() {
        let (db, _dir) = open_test_db();
        let id = make_id(0x03);
        let bt = sample_block_transactions();

        db.store_block_transactions(&id, &bt).unwrap();

        let loaded = db
            .load_block_transactions(&id)
            .unwrap()
            .expect("block transactions should exist");
        assert_eq!(loaded, bt);
        assert_eq!(loaded.block_version, 2);
        assert_eq!(loaded.tx_bytes.len(), 2);
    }

    // 4. load_missing_returns_none — all three return None for missing ID
    #[test]
    fn load_missing_returns_none() {
        let (db, _dir) = open_test_db();
        let id = make_id(0xFF);

        assert!(db.load_extension(&id).unwrap().is_none());
        assert!(db.load_ad_proofs(&id).unwrap().is_none());
        assert!(db.load_block_transactions(&id).unwrap().is_none());
    }

    // 5. sections_independent_by_type — same ID, different section types don't interfere
    #[test]
    fn sections_independent_by_type() {
        let (db, _dir) = open_test_db();
        let id = make_id(0x42);

        let ext = sample_extension();
        let proofs = sample_ad_proofs();
        let bt = sample_block_transactions();

        db.store_extension(&id, &ext).unwrap();
        db.store_ad_proofs(&id, &proofs).unwrap();
        db.store_block_transactions(&id, &bt).unwrap();

        // Each section type should load independently.
        let loaded_ext = db.load_extension(&id).unwrap().unwrap();
        let loaded_proofs = db.load_ad_proofs(&id).unwrap().unwrap();
        let loaded_bt = db.load_block_transactions(&id).unwrap().unwrap();

        assert_eq!(loaded_ext, ext);
        assert_eq!(loaded_proofs, proofs);
        assert_eq!(loaded_bt, bt);
    }

    // 6. sections_persist_across_reopen — close + reopen
    #[test]
    fn sections_persist_across_reopen() {
        let dir = TempDir::new().unwrap();
        let id = make_id(0x77);

        let ext = sample_extension();
        let proofs = sample_ad_proofs();
        let bt = sample_block_transactions();

        // First open: store all three sections.
        {
            let db = HistoryDb::open(dir.path()).unwrap();
            db.store_extension(&id, &ext).unwrap();
            db.store_ad_proofs(&id, &proofs).unwrap();
            db.store_block_transactions(&id, &bt).unwrap();
        }

        // Second open: data should still be there.
        {
            let db = HistoryDb::open(dir.path()).unwrap();
            assert_eq!(db.load_extension(&id).unwrap().unwrap(), ext);
            assert_eq!(db.load_ad_proofs(&id).unwrap().unwrap(), proofs);
            assert_eq!(db.load_block_transactions(&id).unwrap().unwrap(), bt);
        }
    }
}
