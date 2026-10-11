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
    fn tracked_pubkeys(&self) -> Result<Vec<(u64, [u8; 33])>, String> {
        Ok(self.tracked.clone())
    }

    fn visible_pubkeys(&self) -> Result<Vec<(u32, [u8; 33])>, String> {
        Ok(self.visible.clone())
    }

    fn change_address_pubkey(&self) -> Result<Option<[u8; 33]>, String> {
        Ok(self.change)
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
        assert_eq!(snapshot.visible_pubkeys().unwrap().len(), 0);
        assert_eq!(snapshot.change_address_pubkey().unwrap(), None);
    }
}
