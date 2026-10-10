//! An embedded wallet this node no longer hosts.
//!
//! Its rows stay in `state.redb` and its encrypted secret stays in
//! `data_dir/wallet/`; the node never writes either again. On start the node
//! hands the wallet to the standalone daemon by publishing a verified copy at
//! `data_dir/wallet-handoff/` (`ergo-walletd adopt` then takes it), and a
//! miner without a configured reward key keeps the legacy wallet's reward key.
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ergo_wallet::error::WalletError;
use ergo_wallet::storage::SecretStorage;
use ergo_wallet_service::wallet::handoff::{
    publish_seed_directory, read_single_secret, PublishOptions,
};

use crate::config::Network;

/// Directory of the published handoff copy.
pub(crate) const HANDOFF_DIR: &str = "wallet-handoff";
/// Written by `ergo-walletd adopt` once the daemon owns the wallet.
pub(crate) const ADOPTED_MARKER: &str = "wallet-handoff.adopted";

/// The reward key of the legacy wallet's first EIP-3 address, read once.
/// `None` when no legacy wallet ever derived one.
pub(crate) fn reward_key(db: &Arc<redb::Database>) -> Result<Option<[u8; 33]>, String> {
    let store = ergo_state::wallet::RedbWalletStore::new(db.clone());
    let read = ergo_state::wallet::WalletStore::read(&store)
        .map_err(|error| format!("legacy wallet read: {error}"))?;
    match read
        .resolve_reward_key()
        .map_err(|error| format!("legacy wallet reward key: {error}"))?
    {
        ergo_state::wallet::RewardKeyResolution::Ready(key) => Ok(Some(key)),
        ergo_state::wallet::RewardKeyResolution::Pending => Ok(None),
        ergo_state::wallet::RewardKeyResolution::Corrupt => Err(
            "the legacy wallet's tracked keys are inconsistent; set [mining] miner_reward_address"
                .into(),
        ),
    }
}

/// What [`write_handoff`] found or did.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Handoff {
    /// No encrypted secret: there is no wallet to hand off.
    NoLegacyWallet,
    /// The daemon already adopted this wallet.
    Adopted,
    /// A complete handoff copy is already waiting at the path.
    Waiting(PathBuf),
    /// A handoff copy was published at the path.
    Written(PathBuf),
}

/// Publish the legacy wallet at `data_dir/wallet-handoff/`, once.
///
/// The copy comes from one read transaction on the open database, so it is a
/// consistent snapshot while the node runs. The secret is copied byte for
/// byte and never decrypted. Job records are carried as they are: this node
/// no longer runs the wallet scheduler, so the daemon becomes their only owner.
pub(crate) fn write_handoff(
    db: &redb::Database,
    data_dir: &Path,
    network: Network,
) -> Result<Handoff, String> {
    let secret_dir = data_dir.join("wallet");
    match SecretStorage::find_secret_file(&secret_dir) {
        Ok(_) => {}
        Err(WalletError::WalletUninitialized) => return Ok(Handoff::NoLegacyWallet),
        Err(error) => return Err(format!("legacy wallet secret: {error}")),
    }
    if data_dir.join(ADOPTED_MARKER).exists() {
        return Ok(Handoff::Adopted);
    }
    let destination = data_dir.join(HANDOFF_DIR);
    if destination.exists() {
        if destination.join("wallet-mode").is_file() {
            return Ok(Handoff::Waiting(destination));
        }
        // An interrupted publication never wrote its ownership marker and
        // cannot be adopted; replace it.
        std::fs::remove_dir_all(&destination)
            .map_err(|error| format!("remove an incomplete handoff: {error}"))?;
    }
    let (name, bytes) = read_single_secret(&secret_dir).map_err(|error| error.to_string())?;
    publish_seed_directory(
        db,
        (&name, &bytes),
        &destination,
        PublishOptions {
            network,
            source_database_sha256: None,
            wallet_jobs_quarantined: 0,
            carry_scheduler_jobs: true,
        },
        || Ok(()),
    )
    .map_err(|error| error.to_string())?;
    Ok(Handoff::Written(destination))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn handoff_is_published_once_and_skipped_after_adoption() {
        ergo_wallet::storage::use_fast_keystore_kdf_for_tests();
        let dir = tempfile::tempdir().unwrap();
        let db =
            std::sync::Arc::new(redb::Database::create(dir.path().join("state.redb")).unwrap());
        // A committed testnet tip at height 7, as `ergo-walletd migrate`'s
        // tests record it.
        let transaction = db.begin_write().unwrap();
        transaction
            .open_table(redb::TableDefinition::<u64, &[u8]>::new("chain_index"))
            .unwrap()
            .insert(7, [7u8; 32].as_slice())
            .unwrap();
        let mut chain_meta = vec![7u8; 32];
        chain_meta.extend_from_slice(&7u32.to_be_bytes());
        chain_meta.extend_from_slice(&0u32.to_be_bytes());
        chain_meta.extend_from_slice(&[7u8; 32]);
        chain_meta.extend_from_slice(&7u32.to_be_bytes());
        chain_meta.push(0);
        transaction
            .open_table(redb::TableDefinition::<&str, &[u8]>::new(
                "chain_state_meta",
            ))
            .unwrap()
            .insert("chain_state", chain_meta.as_slice())
            .unwrap();
        transaction
            .open_table(redb::TableDefinition::<&[u8], &[u8]>::new(
                "emission_identities",
            ))
            .unwrap()
            .insert([7u8; 32].as_slice(), [1u8].as_slice())
            .unwrap();
        transaction.commit().unwrap();
        assert_eq!(
            write_handoff(&db, dir.path(), Network::Testnet).unwrap(),
            Handoff::NoLegacyWallet
        );
        let mut secrets = SecretStorage::open(dir.path().join("wallet"));
        secrets.restore(PHRASE, "", "pw", false).unwrap();
        ergo_state::wallet::migrate_schema(&db).unwrap();
        let destination = dir.path().join(HANDOFF_DIR);
        assert_eq!(
            write_handoff(&db, dir.path(), Network::Testnet).unwrap(),
            Handoff::Written(destination.clone())
        );
        for name in [
            "wallet.redb",
            "migration.json",
            "wallet-network",
            "wallet-mode",
        ] {
            assert!(destination.join(name).is_file(), "{name}");
        }
        let original =
            std::fs::read(SecretStorage::find_secret_file(&dir.path().join("wallet")).unwrap())
                .unwrap();
        let copy =
            std::fs::read(SecretStorage::find_secret_file(&destination.join("wallet")).unwrap())
                .unwrap();
        assert_eq!(original, copy, "the secret is copied, never re-encrypted");
        assert_eq!(
            write_handoff(&db, dir.path(), Network::Testnet).unwrap(),
            Handoff::Waiting(destination.clone())
        );
        // A wrong network is refused before anything is written.
        std::fs::remove_dir_all(&destination).unwrap();
        assert!(write_handoff(&db, dir.path(), Network::Mainnet).is_err());
        assert!(!destination.exists());
        std::fs::write(dir.path().join(ADOPTED_MARKER), b"adopted\n").unwrap();
        assert_eq!(
            write_handoff(&db, dir.path(), Network::Testnet).unwrap(),
            Handoff::Adopted
        );
        assert_eq!(
            reward_key(&db).unwrap(),
            None,
            "never unlocked: no reward key yet"
        );
    }
}
