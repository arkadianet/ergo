//! Copy a stopped embedded wallet into a separate standalone database.
//!
//! The caller owns source locking and a private, recoverable source copy.
//! Chain state and encrypted secrets are never transferred by this module.
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use redb::{
    Database, MultimapTableHandle, ReadableDatabase, ReadableTable, ReadableTableMetadata,
    TableHandle,
};

use super::{mining_jobs, tables::*, utxo_scan, RedbWalletStore, WalletStore, WalletStoreError};

#[derive(Debug, Clone, serde::Serialize)]
pub struct MigrationReport {
    pub tables: BTreeMap<String, u64>,
    pub applied_headers: u64,
    pub wallet_height: u32,
    pub history_complete: bool,
}

/// Export only supported wallet tables from a privately opened source copy.
/// `destination` must not exist. Unknown wallet tables,
/// transient discovery work and active mining jobs require operator recovery
/// before cutover; no durable operation is silently discarded or duplicated.
pub fn export_embedded_wallet(
    source: &Database,
    destination: &Path,
) -> Result<MigrationReport, WalletStoreError> {
    let original = ReadableDatabase::begin_read(source)?;
    let mut supported = BTreeMap::new();
    let mut reservation = std::fs::OpenOptions::new();
    reservation.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        reservation.mode(0o600);
    }
    reservation
        .open(destination)
        .map_err(|error| WalletStoreError::decode(format!("reserve wallet export: {error}")))?;
    let target = Arc::new(Database::create(destination)?);
    let write = target.begin_write()?;
    macro_rules! copy {
        ($definition:expr) => {{
            let definition = $definition;
            let name = definition.name().to_string();
            let mut count = 0u64;
            match original.open_table(definition) {
                Ok(table) => {
                    let mut copied = write.open_table(definition)?;
                    for row in table.iter()? {
                        let (key, value) = row?;
                        copied.insert(key.value(), value.value())?;
                        count += 1;
                    }
                }
                Err(redb::TableError::TableDoesNotExist(_)) => {}
                Err(error) => return Err(error.into()),
            }
            supported.insert(name, count);
        }};
    }
    // Keep every durable wallet family, including incomplete-history coverage
    // and quarantined job records. Each uses its original typed schema.
    copy!(WALLET_SCAN_HEIGHT);
    copy!(WALLET_SCAN_HEADER_ID);
    copy!(WALLET_BOXES);
    copy!(WALLET_BOX_BYTES);
    copy!(WALLET_BOXES_BY_TX);
    copy!(WALLET_TXS);
    copy!(WALLET_DERIVATION_HEAD);
    copy!(WALLET_TRACKED_PUBKEYS);
    copy!(WALLET_VISIBLE_ADDRESSES);
    copy!(WALLET_CHANGE_ADDRESS);
    copy!(WALLET_SCANS);
    copy!(WALLET_LAST_USED_SCAN_ID);
    copy!(WALLET_SCAN_BOXES);
    copy!(WALLET_SCAN_BOX_INDEX);
    copy!(WALLET_SCAN_TXS);
    copy!(WALLET_SCHEMA_VERSION_TABLE);
    copy!(WALLET_SCAN_INVALIDATED);
    copy!(WALLET_RESCAN_STATE);
    copy!(WALLET_UTXO_DISCOVERY);
    copy!(WALLET_DISCOVERED_BOXES);
    copy!(mining_jobs::META);
    copy!(mining_jobs::JOURNAL);
    copy!(mining_jobs::QUARANTINE);
    for handle in original.list_tables()? {
        let name = handle.name().to_owned();
        if name.starts_with("wallet_") && !supported.contains_key(&name) {
            if matches!(
                name.as_str(),
                "wallet_utxo_discovery_job" | "wallet_utxo_discovery_staging"
            ) && original.open_untyped_table(handle)?.len()? == 0
            {
                continue;
            }
            return Err(WalletStoreError::decode(format!(
                "unsupported or unfinished wallet table {name}"
            )));
        }
    }
    if original
        .list_multimap_tables()?
        .any(|table| table.name().starts_with("wallet_"))
    {
        return Err(WalletStoreError::decode("wallet multimaps are unsupported"));
    }
    let version = original
        .open_table(WALLET_SCHEMA_VERSION_TABLE)?
        .get(())?
        .map(|row| row.value());
    if version != Some(super::WALLET_SCHEMA_VERSION) {
        return Err(WalletStoreError::decode(
            "upgrade the embedded wallet schema with the current node before cutover",
        ));
    }
    if !mining_jobs::pending_jobs(&original)?.is_empty() {
        return Err(WalletStoreError::decode(
            "wallet jobs retain scheduler ownership, including mined/conflicted transactions; cancel queued work before stopping the node, then explicitly use --quarantine-mining-jobs to retain the journal in the private migration copy",
        ));
    }
    let reader = super::WalletReader::new(&original);
    let height = reader.scan_height()?.unwrap_or(0);
    let cursor_id = match original.open_table(WALLET_SCAN_HEADER_ID) {
        Ok(table) => table.get(())?.map(|row| row.value()),
        Err(redb::TableError::TableDoesNotExist(_)) => None,
        Err(error) => return Err(error.into()),
    };
    let coverage = utxo_scan::coverage(&original)?;
    let mut applied_headers = 0;
    {
        let mut forward = write.open_table(WALLET_APPLIED_HEADERS)?;
        let mut reverse = write.open_table(WALLET_APPLIED_HEADER_IDS)?;
        match original.open_table(CHAIN_INDEX) {
            Ok(index) => {
                for row in index.range(..=u64::from(height))? {
                    let (key, value) = row?;
                    let id: [u8; 32] = value
                        .value()
                        .try_into()
                        .map_err(|_| WalletStoreError::decode("invalid applied-chain header id"))?;
                    if key.value() == 0 {
                        continue;
                    }
                    if reverse.insert(id, key.value())?.is_some() {
                        return Err(WalletStoreError::decode(
                            "duplicate applied-chain header id",
                        ));
                    }
                    forward.insert(key.value(), id.as_slice())?;
                    applied_headers += 1;
                }
            }
            Err(redb::TableError::TableDoesNotExist(_)) => {}
            Err(error) => return Err(error.into()),
        }
        if height > 0 && forward.get(u64::from(height))?.is_none() {
            // Snapshot discovery may have no historical index. Its verified
            // committed anchor is sufficient to resume forward wallet sync.
            let anchor = coverage
                .as_ref()
                .filter(|meta| meta.anchor_height == height)
                .and_then(|meta| hex::decode(&meta.anchor_header_id).ok())
                .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok());
            if anchor.is_none()
                || anchor != cursor_id
                || super::reader::committed_tip_in(&original)? != anchor.map(|id| (height, id))
            {
                return Err(WalletStoreError::decode(
                    "wallet cursor has no authenticated applied-chain or discovery anchor",
                ));
            }
            let id = anchor.unwrap();
            forward.insert(u64::from(height), id.as_slice())?;
            reverse.insert(id, u64::from(height))?;
            applied_headers += 1;
        }
        if height > 0
            && forward
                .get(u64::from(height))?
                .map(|row| row.value().to_vec())
                != cursor_id.map(|id| id.to_vec())
        {
            return Err(WalletStoreError::decode(
                "wallet cursor disagrees with applied-chain header",
            ));
        }
    }
    write.commit()?;
    let copied = ReadableDatabase::begin_read(target.as_ref())?;
    macro_rules! verify {
        ($definition:expr) => {{
            match original.open_table($definition) {
                Ok(before) => {
                    let after = copied.open_table($definition)?;
                    let mut before = before.iter()?;
                    let mut after = after.iter()?;
                    loop {
                        match (before.next(), after.next()) {
                            (None, None) => break,
                            (Some(left), Some(right)) => {
                                let (lk, lv) = left?;
                                let (rk, rv) = right?;
                                if lk.value() != rk.value() || lv.value() != rv.value() {
                                    return Err(WalletStoreError::decode(
                                        "copied wallet content differs",
                                    ));
                                }
                            }
                            _ => {
                                return Err(WalletStoreError::decode(
                                    "copied wallet row count differs",
                                ))
                            }
                        }
                    }
                }
                Err(redb::TableError::TableDoesNotExist(_)) => {}
                Err(error) => return Err(error.into()),
            }
        }};
    }
    verify!(WALLET_SCAN_HEIGHT);
    verify!(WALLET_SCAN_HEADER_ID);
    verify!(WALLET_BOXES);
    verify!(WALLET_BOX_BYTES);
    verify!(WALLET_BOXES_BY_TX);
    verify!(WALLET_TXS);
    verify!(WALLET_DERIVATION_HEAD);
    verify!(WALLET_TRACKED_PUBKEYS);
    verify!(WALLET_VISIBLE_ADDRESSES);
    verify!(WALLET_CHANGE_ADDRESS);
    verify!(WALLET_SCANS);
    verify!(WALLET_LAST_USED_SCAN_ID);
    verify!(WALLET_SCAN_BOXES);
    verify!(WALLET_SCAN_BOX_INDEX);
    verify!(WALLET_SCAN_TXS);
    verify!(WALLET_SCHEMA_VERSION_TABLE);
    verify!(WALLET_SCAN_INVALIDATED);
    verify!(WALLET_RESCAN_STATE);
    verify!(WALLET_UTXO_DISCOVERY);
    verify!(WALLET_DISCOVERED_BOXES);
    verify!(mining_jobs::META);
    verify!(mining_jobs::JOURNAL);
    verify!(mining_jobs::QUARANTINE);
    drop(copied);
    let store = RedbWalletStore::from_standalone_db(target)?;
    let read = store.read()?;
    read.all_boxes()?;
    read.all_transactions()?;
    read.scan_registry()?;
    super::hydration::HydrationSnapshot::load(read.as_ref())?;
    Ok(MigrationReport {
        tables: supported,
        applied_headers,
        wallet_height: height,
        history_complete: coverage.is_none_or(|meta| meta.history_complete),
    })
}

/// Identify a copied stopped node's committed network without depending on
/// node/state crates or modifying chain metadata. Unknown or contradictory
/// network evidence is unsuitable for publishing a wallet ownership marker.
pub fn source_network(
    snapshot: &redb::ReadTransaction,
) -> Result<ergo_chain_spec::Network, WalletStoreError> {
    use ergo_chain_spec::{GenesisParams, Network};
    use redb::TableDefinition;
    let (height, header_id) = super::reader::committed_tip_in(snapshot)?.ok_or_else(|| {
        WalletStoreError::decode("committed chain network identity is unavailable")
    })?;
    if height == 0 && header_id != [0; 32] {
        return Err(WalletStoreError::decode(
            "invalid genesis committed header identity",
        ));
    }
    let emission_table: TableDefinition<&[u8], &[u8]> = TableDefinition::new("emission_identities");
    let emission = match snapshot.open_table(emission_table) {
        Ok(table) => table
            .get(header_id.as_slice())?
            .map(|row| {
                let bytes = row.value();
                if !matches!(bytes.len(), 1 | 33) {
                    return Err(WalletStoreError::decode(
                        "invalid committed emission identity length",
                    ));
                }
                match bytes[0] {
                    0 => Ok(Network::Mainnet),
                    1 => Ok(Network::Testnet),
                    2 => Ok(Network::Devnet),
                    _ => Err(WalletStoreError::decode(
                        "invalid committed emission network",
                    )),
                }
            })
            .transpose()?,
        Err(redb::TableError::TableDoesNotExist(_)) => None,
        Err(error) => return Err(error.into()),
    };
    let genesis = match snapshot.open_table(CHAIN_INDEX) {
        Ok(index) => index
            .get(1)?
            .map(|row| {
                let id: [u8; 32] = row.value().try_into().map_err(|_| {
                    WalletStoreError::decode("invalid genesis chain-index header identity")
                })?;
                Ok::<_, WalletStoreError>(
                    [Network::Mainnet, Network::Testnet, Network::Devnet]
                        .into_iter()
                        .find(|network| GenesisParams::for_network(*network).header_id == Some(id)),
                )
            })
            .transpose()?
            .flatten(),
        Err(redb::TableError::TableDoesNotExist(_)) => None,
        Err(error) => return Err(error.into()),
    };
    match (emission,genesis) {
        (Some(left),Some(right)) if left != right => Err(WalletStoreError::decode("committed emission and genesis network identities disagree")),
        (Some(network),_) | (_,Some(network)) => Ok(network),
        (None,None) => Err(WalletStoreError::decode("committed chain network identity is unavailable; start and cleanly stop a current node before wallet migration or discovery")),
    }
}

#[cfg(test)]
mod network_tests {
    use super::*;
    use ergo_chain_spec::{GenesisParams, Network};
    use redb::TableDefinition;

    fn tip_bytes() -> Vec<u8> {
        let mut bytes = vec![7u8; 32];
        bytes.extend_from_slice(&7u32.to_be_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&[7; 32]);
        bytes.extend_from_slice(&7u32.to_be_bytes());
        bytes.push(0);
        bytes
    }
    #[test]
    fn network_uses_committed_identity_and_rejects_unknown_or_contradictory_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::create(dir.path().join("source.redb")).unwrap();
        let txn = db.begin_write().unwrap();
        txn.open_table(TableDefinition::<&str, &[u8]>::new("chain_state_meta"))
            .unwrap()
            .insert("chain_state", tip_bytes().as_slice())
            .unwrap();
        // An unrelated fork's identity is not evidence about the committed tip.
        txn.open_table(TableDefinition::<&[u8], &[u8]>::new("emission_identities"))
            .unwrap()
            .insert([8u8; 32].as_slice(), [0u8].as_slice())
            .unwrap();
        txn.commit().unwrap();
        assert!(
            source_network(&redb::ReadableDatabase::begin_read(&db).unwrap())
                .unwrap_err()
                .to_string()
                .contains("unavailable")
        );
        let txn = db.begin_write().unwrap();
        txn.open_table(TableDefinition::<&[u8], &[u8]>::new("emission_identities"))
            .unwrap()
            .insert([7u8; 32].as_slice(), [1u8].as_slice())
            .unwrap();
        txn.commit().unwrap();
        assert_eq!(
            source_network(&redb::ReadableDatabase::begin_read(&db).unwrap()).unwrap(),
            Network::Testnet
        );
        let txn = db.begin_write().unwrap();
        txn.open_table(CHAIN_INDEX)
            .unwrap()
            .insert(1, GenesisParams::mainnet().header_id.unwrap().as_slice())
            .unwrap();
        txn.commit().unwrap();
        assert!(
            source_network(&redb::ReadableDatabase::begin_read(&db).unwrap())
                .unwrap_err()
                .to_string()
                .contains("disagree")
        );
    }
    #[test]
    fn network_uses_canonical_genesis_when_legacy_emission_identity_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::create(dir.path().join("source.redb")).unwrap();
        let txn = db.begin_write().unwrap();
        txn.open_table(TableDefinition::<&str, &[u8]>::new("chain_state_meta"))
            .unwrap()
            .insert("chain_state", tip_bytes().as_slice())
            .unwrap();
        txn.open_table(CHAIN_INDEX)
            .unwrap()
            .insert(1, GenesisParams::testnet().header_id.unwrap().as_slice())
            .unwrap();
        txn.commit().unwrap();
        let before = std::fs::read(dir.path().join("source.redb")).unwrap();
        assert_eq!(
            source_network(&redb::ReadableDatabase::begin_read(&db).unwrap()).unwrap(),
            Network::Testnet
        );
        assert_eq!(
            std::fs::read(dir.path().join("source.redb")).unwrap(),
            before
        );
    }
}
