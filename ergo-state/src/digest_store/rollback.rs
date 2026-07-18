//! Rollback for [`super::DigestStateStore`]: the pre-read -> validate
//! -> commit `rollback_to` three-phase seam, the post-commit cached
//! params refresh (deliberate fail-fast panics — see its doc), and the
//! per-height history-row readers + height-indexed table truncation it
//! drives.
//!
//! Sibling of `mod.rs`; pure impl relocation.

use redb::{Database, ReadableTable, TableDefinition};

use crate::active_params;
use crate::chain::ChainStateMeta;
use crate::store::StateError;

use super::{
    chain_state_internal_invariant, decode_32_bytes, decode_33_bytes,
    require_root_matches_tip_header, DigestStateStore, CHAIN_STATE_HISTORY, CHAIN_STATE_KEY,
    DIGEST_HISTORY, ROOT_DIGEST_KEY,
};

impl DigestStateStore {
    /// Roll back to `target_height`. Reads
    /// `DIGEST_HISTORY[target_height]` and
    /// `CHAIN_STATE_HISTORY[target_height]`, writes them back to
    /// `STATE_META["root_digest"]` and
    /// `CHAIN_STATE_META["chain_state"]`, truncates every height-
    /// indexed table (`DIGEST_HISTORY`, `CHAIN_STATE_HISTORY`,
    /// `CHAIN_INDEX`, `VOTED_PARAMS`) above the target, all inside
    /// one redb write_txn.
    ///
    /// `target_height` must be `<= self.height()` and rows must
    /// exist at the target. Rolling FORWARD via this seam is
    /// meaningless.
    pub fn rollback_to(&mut self, target_height: u32) -> Result<(), StateError> {
        if target_height > self.height() {
            return Err(StateError::RollbackBeyondTip {
                target: target_height,
                tip: self.height(),
            });
        }
        if target_height == self.height() {
            return Ok(());
        }

        // Pre-read both restoration rows in a read txn so we fail
        // before touching the write txn if either is missing.
        let restored_root = read_digest_history_row(&self.db, target_height)?;
        let restored_chain_state = read_chain_state_history_row(&self.db, target_height)?;

        // Validate the restored ROOT digest BEFORE committing it —
        // applied live so a reorg never installs a poisoned root.
        // Rolling back to height 0 MUST restore exactly the network's
        // genesis root (digest_history[0] is the genesis row, and there
        // is no applied tip header at genesis to anchor against). For an
        // applied target `h >= 1` the restored root is instead anchored
        // to the tip header's committed `state_root` below, so a mutated
        // `DIGEST_HISTORY[h]` cannot install a wrong root. Other
        // torn-write cases are caught by the snapshot height/id and
        // chain_index cross-checks below.
        if target_height == 0 && restored_root != self.genesis_state_digest {
            return Err(StateError::DbCorruption {
                table: "digest_history",
                key: "0".into(),
                reason: format!(
                    "rollback to genesis would restore root {} != the network's \
                     genesis digest — digest_history[0] is corrupt",
                    hex::encode(restored_root)
                ),
            });
        }

        // Validate the restored snapshot's payload BEFORE committing
        // it: a `CHAIN_STATE_HISTORY` row that decodes cleanly but
        // carries the wrong height or block id (torn write / external
        // mutation) would otherwise be written straight into
        // `CHAIN_STATE_META`, leaving the store internally
        // inconsistent. The snapshot at key `target_height` must
        // claim exactly that height, and (for an applied target) its
        // `best_full_block_id` must equal `CHAIN_INDEX[target]` — the
        // row that becomes the post-rollback tip.
        if restored_chain_state.best_full_block_height != target_height {
            return Err(StateError::DbCorruption {
                table: "chain_state_history",
                key: format!("{target_height}"),
                reason: format!(
                    "snapshot at key {target_height} claims height {} — body does not \
                     match its key",
                    restored_chain_state.best_full_block_height
                ),
            });
        }
        if let Err(reason) = chain_state_internal_invariant(&restored_chain_state) {
            return Err(StateError::DbCorruption {
                table: "chain_state_history",
                key: format!("{target_height}"),
                reason: reason.into(),
            });
        }
        if target_height >= 1 {
            let tip_id = read_chain_index_id(&self.db, target_height)?;
            if tip_id != restored_chain_state.best_full_block_id {
                return Err(StateError::DbCorruption {
                    table: "chain_state_history",
                    key: format!("{target_height}"),
                    reason: format!(
                        "snapshot best_full_block_id {} disagrees with chain_index[{target_height}] {}",
                        hex::encode(restored_chain_state.best_full_block_id),
                        hex::encode(tip_id),
                    ),
                });
            }
            // Header-anchor the root being restored: the snapshot root must
            // equal the target tip header's committed `state_root`, else a
            // mutated `DIGEST_HISTORY[target]` would install a poisoned root
            // live — the converse of the open-path check, enforced here so a
            // reorg cannot reach what open would have rejected.
            require_root_matches_tip_header(
                &self.headers,
                &restored_chain_state.best_full_block_id,
                &restored_root,
            )?;
        }

        let write_txn = crate::begin_write_qr(&self.db)?;
        {
            let mut meta = write_txn.open_table(crate::store::STATE_META)?;
            meta.insert(ROOT_DIGEST_KEY, &restored_root[..])?;
            drop(meta);

            let mut chain_state_table = write_txn.open_table(crate::store::CHAIN_STATE_META)?;
            let restored_bytes = restored_chain_state.serialize();
            chain_state_table.insert(CHAIN_STATE_KEY, restored_bytes.as_slice())?;
            drop(chain_state_table);

            truncate_above_height(&write_txn, DIGEST_HISTORY, target_height)?;
            truncate_above_height(&write_txn, CHAIN_STATE_HISTORY, target_height)?;
            truncate_above_height(&write_txn, crate::store::CHAIN_INDEX, target_height)?;

            // VOTED_PARAMS rows above target_height roll back too —
            // an epoch-boundary reorg must not leave future epoch
            // parameters in tree.
            active_params::delete_above(&write_txn, target_height).map_err(|e| {
                StateError::VotedParamsWriteFailed {
                    op: "digest-mode rollback prune",
                    height: target_height,
                    source: Box::new(e),
                }
            })?;
        }
        write_txn.commit()?;

        self.root_digest = restored_root;
        self.chain_state = restored_chain_state;
        self.refresh_cached_params_post_commit();
        Ok(())
    }

    /// Refresh the cached active params + validation settings from the
    /// committed tip after a successful apply or rollback. Mirrors the
    /// UTXO backend's fatal posture: the caches govern later block
    /// validation, so a stale cache after a successful commit would
    /// validate against the wrong active set — a consensus divergence.
    /// Every failure mode here (db read error, missing genesis row,
    /// row-decode failure) is a stop-the-world event, so we panic
    /// rather than let the store drift silently from Scala. The genesis
    /// `voted_params` row is seeded at open, so the `None` arm is a
    /// should-never-happen guard, not a normal path.
    pub(super) fn refresh_cached_params_post_commit(&mut self) {
        let h = self.chain_state.best_full_block_height;
        let read = self.db.begin_read().unwrap_or_else(|e| {
            panic!(
                "[digest-state] FATAL: cache refresh begin_read failed at h={h}: {e}. \
                 Validation cannot continue safely after a successful commit."
            )
        });
        match crate::active_params::read_latest_at(&read, h) {
            Ok(Some(p)) => self.active_params = p,
            Ok(None) => panic!(
                "[digest-state] FATAL: voted_params cache refresh found no row <= h={h} \
                 post-commit. open()'s seed should have written the genesis row — \
                 this is a bug or db corruption."
            ),
            Err(e) => panic!(
                "[digest-state] FATAL: active_params cache refresh failed at h={h}: {e}. \
                 Validation cannot continue safely after a successful commit."
            ),
        }
        match crate::active_params::compute_validation_settings_at(&read, h) {
            Ok(s) => self.validation_settings = s,
            Err(e) => panic!(
                "[digest-state] FATAL: validation_settings cache refresh failed at h={h}: {e}. \
                 Validation cannot continue safely after a successful commit."
            ),
        }
    }
}

fn read_digest_history_row(db: &Database, height: u32) -> Result<[u8; 33], StateError> {
    let read = db.begin_read()?;
    let table = read.open_table(DIGEST_HISTORY)?;
    let row = table
        .get(height as u64)?
        .ok_or(StateError::DigestHistoryMissing { height })?;
    decode_33_bytes(row.value(), "digest_history", &format!("{height}"))
}

/// Read the `best_full_block_id` recorded at `height` in
/// `CHAIN_INDEX`. Used by `rollback_to` to cross-check the restored
/// snapshot against the row that becomes the post-rollback tip.
fn read_chain_index_id(db: &Database, height: u32) -> Result<[u8; 32], StateError> {
    let read = db.begin_read()?;
    let table = read.open_table(crate::store::CHAIN_INDEX)?;
    let row = table.get(height as u64)?.ok_or(StateError::DbCorruption {
        table: "chain_index",
        key: format!("{height}"),
        reason: "rollback target has no chain_index row".into(),
    })?;
    decode_32_bytes(row.value(), "chain_index")
}

fn read_chain_state_history_row(db: &Database, height: u32) -> Result<ChainStateMeta, StateError> {
    let read = db.begin_read()?;
    let table = read.open_table(CHAIN_STATE_HISTORY)?;
    let row = table
        .get(height as u64)?
        .ok_or(StateError::DigestHistoryMissing { height })?;
    ChainStateMeta::deserialize(row.value()).map_err(|e| StateError::DbCorruption {
        table: "chain_state_history",
        key: format!("{height}"),
        reason: format!("{e:?}"),
    })
}

fn truncate_above_height(
    txn: &redb::WriteTransaction,
    table_def: TableDefinition<u64, &[u8]>,
    target_height: u32,
) -> Result<(), StateError> {
    let mut t = txn.open_table(table_def)?;
    let lower = (target_height as u64).saturating_add(1);
    // Collect the keys to remove first (can't delete while the
    // range iterator borrows the table). Iterator errors propagate
    // — a swallowed read error here would leave rows above the
    // target and still commit the rollback, corrupting the suffix.
    let mut to_remove: Vec<u64> = Vec::new();
    for entry in t.range(lower..=u64::MAX)? {
        let (k, _) = entry?;
        to_remove.push(k.value());
    }
    for h in to_remove {
        t.remove(h)?;
    }
    Ok(())
}
