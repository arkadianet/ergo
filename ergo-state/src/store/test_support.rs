//! Test-only unsafe corruption / force-set helpers for
//! [`StateStore`], gated on `#[cfg(any(test, feature =
//! "test-helpers"))]`. These deliberately bypass the production
//! validation paths to synthesize corruption shapes and forced
//! pointers for storage-layer tests.
//!
//! Sibling of `mod.rs`; pure impl relocation.

#![cfg(any(test, feature = "test-helpers"))]

use super::{
    StateError, StateStore, CHAIN_INDEX, CHAIN_STATE_META, HEADERS, HEADER_CHAIN_INDEX,
    HEADER_META, STATE_META,
};

impl StateStore {
    /// Test-only, unsafe: forcibly overwrite the best-header pointer without
    /// validating that the header exists in HEADERS/HEADER_META or that the
    /// chain below it is persisted.
    ///
    /// HAZARDS:
    /// - Does NOT write HEADER_CHAIN_INDEX. The function instead clears the
    ///   `hci_version` sentinel, so the next `StateStore::open` will re-run
    ///   the backfill walk. If the fake header has no HEADER_META, backfill
    ///   will return an error — which is the intended failure mode.
    /// - Leaves CHAIN_STATE_META and HEADER_CHAIN_INDEX intentionally out of
    ///   sync until the next open. Tests that exercise startup loading after
    ///   calling this must either also arrange HEADER_META for the full chain
    ///   OR accept that backfill will fail.
    ///
    /// Prefer `store_validated_header` in tests that exercise any startup/load
    /// logic. This helper exists only for tests that need to bypass validation
    /// to assert on storage-layer behavior (e.g. "does pointer survive restart?").
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn test_force_set_best_header_unsafe(
        &mut self,
        header_id: [u8; 32],
        height: u32,
        cumulative_score: Vec<u8>,
    ) -> Result<(), StateError> {
        let mut cs = self.chain_state.to_persisted();
        cs.best_header_id = header_id;
        cs.best_header_height = height;
        cs.best_header_score = cumulative_score.clone();

        let write_txn = crate::begin_write_qr(&self.db)?;
        {
            let mut cs_table = write_txn.open_table(CHAIN_STATE_META)?;
            cs_table.insert("chain_state", cs.serialize().as_slice())?;
            // Clear the sentinel — backfill must re-run next open.
            let mut meta_table = write_txn.open_table(STATE_META)?;
            meta_table.remove("hci_version")?;
        }
        write_txn.commit()?;

        self.chain_state.best_header_id = header_id;
        self.chain_state.best_header_height = height;
        self.chain_state.best_header_score = cumulative_score;
        Ok(())
    }

    /// Insert a single HEADER_CHAIN_INDEX entry for tests that pre-seed a
    /// chain but bypass the normal persist path (which maintains the index).
    /// Without such an entry, a subsequent real persist_apply triggers
    /// `rewrite_best_chain_into_index` which walks back past the seeded
    /// range and hits a zero parent_id.
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn test_force_put_header_chain_index(
        &self,
        height: u32,
        header_id: &[u8; 32],
    ) -> Result<(), StateError> {
        let write_txn = crate::begin_write_qr(&self.db)?;
        {
            let mut idx_table = write_txn.open_table(HEADER_CHAIN_INDEX)?;
            idx_table.insert(height as u64, header_id.as_slice())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Insert a single `CHAIN_INDEX` (applied chain) entry. Companion to
    /// `test_force_put_header_chain_index`, used by tests that need to
    /// pin a divergence between the applied chain and the best-header
    /// chain — e.g. identity-aware "applied at height" tests.
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn test_force_put_chain_index(
        &self,
        height: u32,
        header_id: &[u8; 32],
    ) -> Result<(), StateError> {
        let write_txn = crate::begin_write_qr(&self.db)?;
        {
            let mut chain_table = write_txn.open_table(CHAIN_INDEX)?;
            chain_table.insert(height as u64, header_id.as_slice())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Read the applied-chain header id at a given height directly
    /// from `CHAIN_INDEX`. `None` if no row exists. Intended for
    /// tests that assert CHAIN_INDEX coverage independently of the
    /// in-memory chain_state mirror.
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn chain_index_id_at_height(&self, height: u32) -> Result<Option<[u8; 32]>, StateError> {
        let read_txn = self.db.begin_read()?;
        let table = match read_txn.open_table(CHAIN_INDEX) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        match table.get(height as u64)? {
            Some(g) => {
                let bytes = g.value();
                if bytes.len() != 32 {
                    return Err(StateError::DbCorruption {
                        table: "chain_index",
                        key: height.to_string(),
                        reason: format!("payload length {} (expected 32)", bytes.len()),
                    });
                }
                let mut id = [0u8; 32];
                id.copy_from_slice(bytes);
                Ok(Some(id))
            }
            None => Ok(None),
        }
    }

    /// Test helper: force-set `best_full_block_*` alongside `best_header_*`
    /// without running the normal apply path. Used by diff-module tests
    /// to pin a synthetic committed tip. Persists the full `ChainStateMeta`
    /// and mirrors into in-memory `chain_state`.
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn test_force_set_best_full_block_unsafe(
        &mut self,
        header_id: [u8; 32],
        height: u32,
    ) -> Result<(), StateError> {
        let mut cs = self.chain_state.to_persisted();
        cs.best_full_block_id = header_id;
        cs.best_full_block_height = height;
        let write_txn = crate::begin_write_qr(&self.db)?;
        {
            let mut cs_table = write_txn.open_table(CHAIN_STATE_META)?;
            cs_table.insert("chain_state", cs.serialize().as_slice())?;
        }
        write_txn.commit()?;
        self.chain_state.best_full_block_id = header_id;
        self.chain_state.best_full_block_height = height;
        Ok(())
    }

    /// Delete the persisted header bytes for a given id without touching
    /// `chain_state` or `header_meta`. Used by integrity tests to
    /// synthesize the "header row missing while DB key still in
    /// chain_index / chain_state" corruption shape that production
    /// hydration paths must reject.
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn test_remove_header_row_unsafe(
        &mut self,
        header_id: &[u8; 32],
    ) -> Result<(), StateError> {
        let write_txn = crate::begin_write_qr(&self.db)?;
        {
            let mut t = write_txn.open_table(HEADERS)?;
            t.remove(header_id.as_slice())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Delete the persisted `header_meta` row for a given id without
    /// touching anything else. Companion to `test_remove_header_row_unsafe`
    /// for exercising the "meta missing while bytes still present"
    /// corruption shape.
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn test_remove_header_meta_row_unsafe(
        &mut self,
        header_id: &[u8; 32],
    ) -> Result<(), StateError> {
        let write_txn = crate::begin_write_qr(&self.db)?;
        {
            let mut t = write_txn.open_table(HEADER_META)?;
            t.remove(header_id.as_slice())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Overwrite the persisted header bytes for a given id with
    /// arbitrary bytes, bypassing the canonical-hash invariant the
    /// production path enforces. Used to synthesize trailing-bytes
    /// and body/key drift corruption shapes — the hardened
    /// `CheckedHeader::from_persisted_parts` constructor is supposed
    /// to detect both.
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn test_corrupt_header_bytes_unsafe(
        &mut self,
        header_id: &[u8; 32],
        new_bytes: &[u8],
    ) -> Result<(), StateError> {
        let write_txn = crate::begin_write_qr(&self.db)?;
        {
            let mut t = write_txn.open_table(HEADERS)?;
            t.insert(header_id.as_slice(), new_bytes)?;
        }
        write_txn.commit()?;
        Ok(())
    }
}
