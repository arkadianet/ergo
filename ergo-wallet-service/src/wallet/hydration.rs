pub use crate::state::HydrationSource;

/// Owned, fully read wallet data. A failed read never becomes an empty cache.
pub struct HydrationSnapshot {
    tracked: Vec<(u64, [u8; 33])>,
    visible: Vec<(u32, [u8; 33])>,
    change: Option<[u8; 33]>,
}

impl HydrationSnapshot {
    /// Read all hydration data from one store snapshot before mutating state.
    pub fn load(
        read: &dyn crate::wallet::WalletRead,
    ) -> Result<Self, crate::wallet::WalletStoreError> {
        Ok(Self {
            tracked: read
                .tracked_pubkeys_with_paths()?
                .into_iter()
                .map(|(index, pubkey, _)| (index, pubkey))
                .collect(),
            visible: read.visible_pubkeys()?,
            change: read.change_address_pubkey()?,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.tracked.is_empty()
    }
}

impl HydrationSource for HydrationSnapshot {
    fn tracked_pubkeys(&self) -> Box<dyn Iterator<Item = (u64, [u8; 33])> + '_> {
        Box::new(self.tracked.iter().copied())
    }

    fn visible_pubkeys(&self) -> Box<dyn Iterator<Item = (u32, [u8; 33])> + '_> {
        Box::new(self.visible.iter().copied())
    }

    fn change_address_pubkey(&self) -> Option<[u8; 33]> {
        self.change
    }
}

use std::collections::{BTreeMap, BTreeSet};

/// Hook the chain-apply pipeline calls inside the same redb write
/// transaction as chain state mutations. Provides snapshots of the
/// wallet's tracked-pubkey state so the wallet apply hook can
/// classify outputs.
///
/// Implementors wrap live wallet state and return snapshots. The
/// apply path uses primitive key and tree data only.
pub trait WalletApplyHook: Send + Sync {
    /// Snapshot of P2PK ErgoTree bytes for all currently-tracked
    /// pubkeys. The apply hook does `set.contains(output.ergo_tree_bytes)`.
    fn tracked_p2pk_trees(&self) -> BTreeSet<Vec<u8>>;

    /// Snapshot of `derivation_path_index → pubkey` for all tracked
    /// pubkeys. The apply hook uses this for miner-reward classification
    /// (extracts the embedded pubkey from a wrapper-script output and
    /// checks if it's in this map's values).
    fn cached_pubkeys(&self) -> BTreeMap<u64, [u8; 33]>;

    fn wallet_state_snapshot(&self) -> (BTreeSet<Vec<u8>>, BTreeMap<u64, [u8; 33]>) {
        (self.tracked_p2pk_trees(), self.cached_pubkeys())
    }

    fn allow_non_contiguous_wallet_apply(&self) -> bool {
        false
    }

    /// Number of registered `/scan/*` scans. The apply path skips ALL scan
    /// matching when this is 0 (the common case, especially during IBD before
    /// any scan exists), so it must be cheap. Defaults to 0 so non-scan hook
    /// impls (e.g. test stubs) need not override it.
    fn registered_scan_count(&self) -> usize {
        0
    }

    /// For each box in `boxes` (a block's outputs), the ids of registered scans
    /// whose tracking rule matches it — returned in the SAME order as `boxes`.
    /// Called once per block, ONLY when `registered_scan_count() > 0`. The
    /// implementor loads the scan registry once and runs the predicate matcher.
    /// Defaults to "nothing matches".
    fn match_boxes(&self, boxes: &[ergo_ser::ergo_box::ErgoBox]) -> Vec<Vec<u16>> {
        vec![Vec::new(); boxes.len()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::{tables::*, WalletStore};

    #[test]
    fn hydration_snapshot_propagates_each_table_read_failure() {
        for name in [
            "wallet_tracked_pubkeys",
            "wallet_visible_addresses",
            "wallet_change_address",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let db = redb::Database::create(dir.path().join("wallet.redb")).unwrap();
            let write = db.begin_write().unwrap();
            // A real redb schema mismatch must not look like an absent table.
            write
                .open_table(redb::TableDefinition::<(), u8>::new(name))
                .unwrap();
            write.commit().unwrap();
            let read = WalletStore::read(&db).unwrap();
            assert!(HydrationSnapshot::load(read.as_ref()).is_err(), "{name}");
        }
    }

    #[test]
    fn hydration_snapshot_rejects_corrupt_tracked_key_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let db = redb::Database::create(dir.path().join("wallet.redb")).unwrap();
        let write = db.begin_write().unwrap();
        write
            .open_table(WALLET_TRACKED_PUBKEYS)
            .unwrap()
            .insert(tracked_pubkey_key(0, &[2; 33]), vec![0xff])
            .unwrap();
        write.commit().unwrap();
        let read = WalletStore::read(&db).unwrap();
        assert!(HydrationSnapshot::load(read.as_ref()).is_err());
    }

    #[test]
    fn hydration_snapshot_accepts_absent_tables() {
        let dir = tempfile::tempdir().unwrap();
        let db = redb::Database::create(dir.path().join("wallet.redb")).unwrap();
        let read = WalletStore::read(&db).unwrap();
        let snapshot = HydrationSnapshot::load(read.as_ref()).unwrap();
        assert!(snapshot.is_empty());
        assert_eq!(snapshot.visible_pubkeys().count(), 0);
        assert_eq!(snapshot.change_address_pubkey(), None);
    }
}
