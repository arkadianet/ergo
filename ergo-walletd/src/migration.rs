//! Explicit, offline embedded-to-daemon cutover. Original files are retained.
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::ops::Bound;
use std::path::{Path, PathBuf};

use clap::Args;
use ergo_wallet::storage::SecretStorage;
use ergo_wallet_service::wallet::migration::{export_embedded_wallet, MigrationReport};
use redb::StorageBackend;
use sha2::{Digest, Sha256};

use crate::config::{ConfigError, Network};

#[derive(Debug, Clone, Args)]
pub struct MigrateArgs {
    /// Stopped embedded node directory containing state.redb.
    #[arg(long)]
    pub source_data_dir: PathBuf,
    /// Encrypted-secret directory (defaults to SOURCE_DATA_DIR/wallet).
    #[arg(long)]
    pub source_secret_dir: Option<PathBuf>,
    /// Fresh destination directory; existing paths are always refused.
    #[arg(long)]
    pub destination: PathBuf,
    /// Network of the existing embedded wallet and future daemon.
    #[arg(long)]
    pub network: Network,
    /// Preserve wallet jobs in quarantine in the private copy instead of transferring scheduler ownership.
    /// Withdraw queued private transactions on the node before stopping it.
    #[arg(long)]
    pub quarantine_mining_jobs: bool,
}

#[derive(Debug, serde::Serialize)]
pub struct CutoverReport {
    pub version: u32,
    pub network: String,
    pub source_database_sha256: String,
    pub encrypted_secret_sha256: String,
    pub wallet_jobs_quarantined: u64,
    pub wallet: MigrationReport,
}

fn invalid(message: impl Into<String>) -> ConfigError {
    ConfigError::Invalid(message.into())
}

fn protected_open(path: &Path, writable_lock: bool) -> Result<File, ConfigError> {
    if !fs::symlink_metadata(path)?.is_file() {
        return Err(invalid(format!(
            "expected a regular file: {}",
            path.display()
        )));
    }
    let mut options = OpenOptions::new();
    options.read(true).write(writable_lock);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(
            (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
        );
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(invalid("opened migration source is not a regular file"));
    }
    Ok(file)
}

fn sync_directory(path: &Path) -> Result<(), ConfigError> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn create_private_directory(path: &Path) -> Result<(), ConfigError> {
    let builder = fs::DirBuilder::new();
    #[cfg(unix)]
    let mut builder = builder;
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)?;
    Ok(())
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), ConfigError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

/// Locks raw source bytes without opening/recovering the original database.
/// Verification and schema work occur solely in a private temporary copy.
pub fn migrate(args: &MigrateArgs) -> Result<CutoverReport, ConfigError> {
    match fs::symlink_metadata(&args.destination) {
        Ok(_) => return Err(invalid("migration destination already exists")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let parent = args
        .destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let raw = protected_open(&args.source_data_dir.join("state.redb"), true)?;
    // Linux uses separate flock and OFD byte-range lock namespaces, so both
    // locks are needed to exclude legacy and current redb owners. Elsewhere,
    // the backend's whole-storage range lock also excludes legacy file locks;
    // taking a file lock first can conflict with our own range lock on macOS.
    #[cfg(target_os = "linux")]
    raw.try_lock()
        .map_err(|error| invalid(format!("stop the source node before migration: {error}")))?;
    let backend =
        redb::backends::FileBackend::new(raw).map_err(|error| invalid(error.to_string()))?;
    if !backend
        .try_lock_range(Bound::Unbounded, Bound::Unbounded)
        .map_err(|error| invalid(format!("lock source: {error}")))?
    {
        return Err(invalid("stop the source node before migration"));
    }
    let temporary = tempfile::Builder::new()
        .prefix(".ergo-wallet-cutover-")
        .tempdir_in(parent)?;
    let source_copy_path = temporary.path().join("source.redb");
    let mut source_copy = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&source_copy_path)?;
    let length = backend.len()?;
    let mut original_hash = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    let mut offset = 0;
    while offset < length {
        let count = (length - offset).min(buffer.len() as u64) as usize;
        backend.read(offset, &mut buffer[..count])?;
        original_hash.update(&buffer[..count]);
        source_copy.write_all(&buffer[..count])?;
        offset += count as u64;
    }
    source_copy.sync_all()?;
    drop(source_copy);
    let original_hash = original_hash.finalize();
    let secret_dir = args
        .source_secret_dir
        .clone()
        .unwrap_or_else(|| args.source_data_dir.join("wallet"));
    if fs::symlink_metadata(&secret_dir)?.file_type().is_symlink() {
        return Err(invalid("migration secret directory must not be a symlink"));
    }
    let secret_path =
        SecretStorage::find_secret_file(&secret_dir).map_err(|error| invalid(error.to_string()))?;
    let eligible_files = fs::read_dir(&secret_dir)?
        .filter_map(Result::ok)
        .filter(|entry| {
            entry.path().is_file()
                && !entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".ergo-wallet-pending-")
        })
        .count();
    if eligible_files != 1 {
        return Err(invalid(
            "migration requires one unambiguous encrypted secret file",
        ));
    }
    let mut secret = protected_open(&secret_path, false)?;
    let mut encrypted = Vec::new();
    Read::by_ref(&mut secret)
        .take(4 * 1024 * 1024 + 1)
        .read_to_end(&mut encrypted)?;
    if encrypted.len() > 4 * 1024 * 1024 {
        return Err(invalid("encrypted secret exceeds migration size limit"));
    }
    let candidate = temporary.path().join("candidate");
    create_private_directory(&candidate)?;
    create_private_directory(&candidate.join("wallet"))?;
    let secret_name = secret_path
        .file_name()
        .ok_or_else(|| invalid("secret has no filename"))?;
    write_private(&candidate.join("wallet").join(secret_name), &encrypted)?;
    // Parse only public encryption metadata. Never request or decrypt a seed.
    SecretStorage::open(candidate.join("wallet"))
        .load_metadata()
        .map_err(|error| invalid(error.to_string()))?;
    let source = redb::Database::open(&source_copy_path).map_err(|error| invalid(format!("open private source copy (legacy formats require ergo-node migrate-redb first): {error}")))?;
    let source_read =
        redb::ReadableDatabase::begin_read(&source).map_err(|error| invalid(error.to_string()))?;
    let source_network = ergo_wallet_service::wallet::migration::source_network(&source_read)
        .map_err(|error| invalid(error.to_string()))?;
    let expected_network = match args.network {
        Network::Mainnet => ergo_chain_spec::Network::Mainnet,
        Network::Testnet => ergo_chain_spec::Network::Testnet,
    };
    if source_network != expected_network {
        return Err(invalid(
            "migration network differs from committed source chain identity",
        ));
    }
    drop(source_read);
    // This database is solely the recoverable private copy. The locked source
    // bytes and the node's private queue remain untouched, even on failure.
    let wallet_jobs_quarantined = if args.quarantine_mining_jobs {
        ergo_wallet_service::wallet::mining_jobs::quarantine(&source)
            .map_err(|error| invalid(error.to_string()))?
    } else {
        0
    };
    let wallet = export_embedded_wallet(&source, &candidate.join("wallet.redb"))
        .map_err(|error| invalid(error.to_string()))?;
    drop(source);
    let mut current_hash = Sha256::new();
    offset = 0;
    while offset < length {
        let count = (length - offset).min(buffer.len() as u64) as usize;
        backend.read(offset, &mut buffer[..count])?;
        current_hash.update(&buffer[..count]);
        offset += count as u64;
    }
    if backend.len()? != length || current_hash.finalize() != original_hash {
        return Err(invalid("source database changed during migration"));
    }
    secret.rewind()?;
    let mut secret_check = Vec::new();
    Read::by_ref(&mut secret)
        .take(4 * 1024 * 1024 + 1)
        .read_to_end(&mut secret_check)?;
    if secret_check != encrypted {
        return Err(invalid("source encrypted secret changed during migration"));
    }
    let report = CutoverReport {
        version: 1,
        network: args.network.as_str().into(),
        source_database_sha256: hex::encode(original_hash),
        encrypted_secret_sha256: hex::encode(Sha256::digest(&encrypted)),
        wallet_jobs_quarantined,
        wallet,
    };
    write_private(
        &candidate.join("migration.json"),
        &serde_json::to_vec_pretty(&report).map_err(|error| invalid(error.to_string()))?,
    )?;
    write_private(
        &candidate.join("wallet-network"),
        format!("{}\n", args.network.as_str()).as_bytes(),
    )?;
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(candidate.join("wallet.redb"))?
        .sync_all()?;
    // Reserve the destination without replacing any file or symlink. Publishing
    // the ownership marker last makes an interrupted cutover fail closed.
    create_private_directory(&args.destination)?;
    sync_directory(parent)?;
    create_private_directory(&args.destination.join("wallet"))?;
    for name in ["wallet.redb", "migration.json", "wallet-network"] {
        fs::hard_link(candidate.join(name), args.destination.join(name))?;
    }
    fs::hard_link(
        candidate.join("wallet").join(secret_name),
        args.destination.join("wallet").join(secret_name),
    )?;
    sync_directory(&args.destination.join("wallet"))?;
    sync_directory(&args.destination)?;
    write_private(&args.destination.join("wallet-mode"), b"seed\n")?;
    sync_directory(&args.destination)?;
    sync_directory(parent)?;
    backend.close()?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_wallet_service::wallet::{
        tables::*, BoxProvenance, BoxStatus, TrackedPubkeyMeta, WalletBox,
    };
    use ergo_wallet_service::{RedbWalletStore, WalletStore};
    use std::sync::Arc;

    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn embedded_source(dir: &Path) -> Arc<redb::Database> {
        let mut secrets = SecretStorage::open(dir.join("wallet"));
        secrets
            .restore(PHRASE, "", "migration-test-password", false)
            .unwrap();
        secrets.unlock("migration-test-password").unwrap();
        let pubkey = secrets.unlocked().unwrap().master.master_pubkey().unwrap();
        let db = Arc::new(redb::Database::create(dir.join("state.redb")).unwrap());
        ergo_wallet_service::wallet::migrate_schema(&db).unwrap();
        let store = RedbWalletStore::new(db.clone());
        let mut write = store.begin_write().unwrap();
        write
            .insert_tracked_pubkey(
                0,
                pubkey,
                &TrackedPubkeyMeta {
                    derivation_path: Vec::new(),
                    derivation_path_label: "master".into(),
                    added_at_height: 0,
                },
            )
            .unwrap();
        write.rebuild_visible_addresses().unwrap();
        write.set_change_address(pubkey).unwrap();
        write.set_derivation_head(5).unwrap();
        write.set_scan_cursor(7, Some(&[7; 32])).unwrap();
        write.commit().unwrap();
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
        let wallet_box = WalletBox {
            box_id: [9; 32],
            creation_tx_id: [8; 32],
            creation_output_index: 0,
            creation_height: 7,
            value: 10_000_000,
            assets: vec![([6; 32], 42)],
            status: BoxStatus::Confirmed,
            provenance: BoxProvenance::Owned,
        };
        transaction
            .open_table(WALLET_BOXES)
            .unwrap()
            .insert([9; 32], bincode::serialize(&wallet_box).unwrap())
            .unwrap();
        transaction.commit().unwrap();
        db
    }

    fn args(source: &Path, destination: &Path) -> MigrateArgs {
        MigrateArgs {
            source_data_dir: source.to_owned(),
            source_secret_dir: None,
            destination: destination.to_owned(),
            network: Network::Testnet,
            quarantine_mining_jobs: false,
        }
    }

    #[test]
    fn cutover_refuses_selected_network_that_disagrees_with_source_before_publication() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        fs::create_dir(&source).unwrap();
        drop(embedded_source(&source));
        let before = fs::read(source.join("state.redb")).unwrap();
        let destination = root.path().join("standalone");
        let mut args = args(&source, &destination);
        args.network = Network::Mainnet;
        assert!(migrate(&args)
            .unwrap_err()
            .to_string()
            .contains("network differs"));
        assert!(!destination.exists());
        assert_eq!(fs::read(source.join("state.redb")).unwrap(), before);
    }

    #[test]
    fn cutover_preserves_original_bytes_keys_balance_anchor_and_encrypted_seed() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        fs::create_dir(&source).unwrap();
        drop(embedded_source(&source));
        let original_db = fs::read(source.join("state.redb")).unwrap();
        let original_secret =
            fs::read(SecretStorage::find_secret_file(&source.join("wallet")).unwrap()).unwrap();
        let destination = root.path().join("standalone");
        let report = migrate(&args(&source, &destination)).unwrap();
        assert_eq!(report.wallet_jobs_quarantined, 0);
        assert_eq!(report.wallet.wallet_height, 7);
        assert_eq!(report.wallet.applied_headers, 1);
        assert_eq!(fs::read(source.join("state.redb")).unwrap(), original_db);
        assert_eq!(
            fs::read(SecretStorage::find_secret_file(&destination.join("wallet")).unwrap())
                .unwrap(),
            original_secret
        );
        let store = RedbWalletStore::open_standalone(destination.join("wallet.redb")).unwrap();
        let read = store.read().unwrap();
        assert_eq!(
            read.scan_cursor().unwrap().unwrap().header_id,
            Some([7; 32])
        );
        assert_eq!(read.balance().unwrap().confirmed_nano_ergs, 10_000_000);
        assert_eq!(read.balance().unwrap().tokens[&[6; 32]], 42);
        assert_eq!(read.derivation_head().unwrap(), 5);
        assert_eq!(read.tracked_pubkeys_with_paths().unwrap().len(), 1);
        let mut secrets = SecretStorage::open(destination.join("wallet"));
        secrets.load_metadata().unwrap();
        assert!(secrets.unlocked().is_none());
        secrets.unlock("migration-test-password").unwrap();
        assert_eq!(
            secrets.unlocked().unwrap().master.master_pubkey().unwrap(),
            read.tracked_pubkeys_with_paths().unwrap()[0].1
        );
        crate::ownership::claim(&destination, crate::config::WalletMode::Seed).unwrap();
        crate::ownership::claim_network(&destination, Network::Testnet).unwrap();
        assert!(crate::ownership::claim_network(&destination, Network::Mainnet).is_err());
        assert_eq!(
            fs::read_to_string(destination.join("wallet-mode")).unwrap(),
            "seed\n"
        );
        assert!(!destination.join("state.redb").exists());
    }

    #[test]
    fn cutover_refuses_a_live_source_and_never_overwrites_a_destination() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        fs::create_dir(&source).unwrap();
        let live = embedded_source(&source);
        let destination = root.path().join("standalone");
        assert!(migrate(&args(&source, &destination)).is_err());
        assert!(!destination.exists());
        drop(live);
        fs::create_dir(&destination).unwrap();
        fs::write(destination.join("keep"), "preserved").unwrap();
        assert!(migrate(&args(&source, &destination)).is_err());
        assert_eq!(
            fs::read_to_string(destination.join("keep")).unwrap(),
            "preserved"
        );
    }

    #[test]
    fn cutover_refuses_legacy_whole_file_owner_without_mutating_source() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        fs::create_dir(&source).unwrap();
        drop(embedded_source(&source));
        let source_path = source.join("state.redb");
        let original = fs::read(&source_path).unwrap();
        let owner = protected_open(&source_path, true).unwrap();
        owner.try_lock().unwrap();
        let destination = root.path().join("standalone");
        assert!(migrate(&args(&source, &destination))
            .unwrap_err()
            .to_string()
            .contains("stop the source node"));
        assert!(!destination.exists());
        drop(owner);
        assert!(
            fs::read(&source_path).unwrap() == original,
            "refused migration modified the source database"
        );
    }

    #[test]
    fn explicit_quarantine_keeps_terminal_followers_inert_and_preserves_originals() {
        use ergo_wallet_protocol::native::dto::{
            WalletJob, WalletJobRequest, WalletJobState, WalletJobTask,
        };
        use ergo_wallet_service::engine::jobs::Record;
        use ergo_wallet_service::wallet::mining_jobs;
        use redb::{ReadableDatabase, ReadableTableMetadata};

        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        fs::create_dir(&source).unwrap();
        let db = embedded_source(&source);
        let mut records = Vec::new();
        let write = db.begin_write().unwrap();
        {
            let mut journal = write.open_table(mining_jobs::JOURNAL).unwrap();
            for (id, state) in [
                (1u64, WalletJobState::Mined),
                (2, WalletJobState::Conflicted),
            ] {
                let record = Record {
                    job: WalletJob {
                        id: id.to_string(),
                        request: WalletJobRequest {
                            label: "retained private approval".into(),
                            task: WalletJobTask::Renew {
                                box_ids: vec!["11".repeat(32)],
                            },
                            not_before_height: 5,
                            expires_at_height: 100,
                            max_attempts: 3,
                        },
                        state,
                        created_at_ms: 1,
                        updated_at_ms: 2,
                        attempts: 1,
                        tx_id: Some(format!("{id:064x}")),
                        detail: Some("follow this transaction through rollback".into()),
                    },
                    signed_hex: Some("aabbccdd".into()),
                    last_attempt_height: Some(7),
                };
                let bytes = serde_json::to_vec(&record).unwrap();
                journal.insert(id, bytes.as_slice()).unwrap();
                records.push((id, bytes));
            }
        }
        let prior_quarantine = b"previously quarantined full record";
        write
            .open_table(mining_jobs::QUARANTINE)
            .unwrap()
            .insert(41, prior_quarantine.as_slice())
            .unwrap();
        write
            .open_table(mining_jobs::META)
            .unwrap()
            .insert("next_id", 42)
            .unwrap();
        write.commit().unwrap();
        drop(db);
        fs::write(
            source.join("private-mining-queue.json"),
            b"source queue stays owned by the node",
        )
        .unwrap();
        let original_db = fs::read(source.join("state.redb")).unwrap();
        let original_secret =
            fs::read(SecretStorage::find_secret_file(&source.join("wallet")).unwrap()).unwrap();
        let original_queue = fs::read(source.join("private-mining-queue.json")).unwrap();
        let destination = root.path().join("standalone");
        let mut options = args(&source, &destination);
        assert!(migrate(&options)
            .unwrap_err()
            .to_string()
            .contains("scheduler ownership"));
        assert!(!destination.exists());
        assert_eq!(fs::read(source.join("state.redb")).unwrap(), original_db);

        options.quarantine_mining_jobs = true;
        let report = migrate(&options).unwrap();
        assert_eq!(report.wallet_jobs_quarantined, 2);
        assert_eq!(report.wallet.tables["wallet_mining_jobs_v1"], 0);
        assert_eq!(report.wallet.tables["wallet_mining_jobs_quarantined_v1"], 3);
        assert_eq!(fs::read(source.join("state.redb")).unwrap(), original_db);
        assert_eq!(
            fs::read(source.join("private-mining-queue.json")).unwrap(),
            original_queue
        );
        assert_eq!(
            fs::read(SecretStorage::find_secret_file(&source.join("wallet")).unwrap()).unwrap(),
            original_secret
        );
        assert_eq!(
            fs::read(SecretStorage::find_secret_file(&destination.join("wallet")).unwrap())
                .unwrap(),
            original_secret
        );
        assert!(!destination.join("private-mining-queue.json").exists());
        let exported = redb::Database::open(destination.join("wallet.redb")).unwrap();
        let read = ReadableDatabase::begin_read(&exported).unwrap();
        assert!(mining_jobs::pending_jobs(&read).unwrap().is_empty());
        assert_eq!(
            read.open_table(mining_jobs::JOURNAL)
                .unwrap()
                .len()
                .unwrap(),
            0
        );
        let saved = read.open_table(mining_jobs::QUARANTINE).unwrap();
        for (id, bytes) in records {
            assert_eq!(saved.get(id).unwrap().unwrap().value(), bytes);
        }
        assert_eq!(saved.get(41).unwrap().unwrap().value(), prior_quarantine);
        assert_eq!(
            read.open_table(mining_jobs::META)
                .unwrap()
                .get("next_id")
                .unwrap()
                .unwrap()
                .value(),
            42
        );
        let stored_report: serde_json::Value =
            serde_json::from_slice(&fs::read(destination.join("migration.json")).unwrap()).unwrap();
        assert_eq!(stored_report["wallet_jobs_quarantined"], 2);
    }

    #[test]
    fn unknown_wallet_tables_refuse_cutover_without_touching_original() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        fs::create_dir(&source).unwrap();
        let db = embedded_source(&source);
        let write = db.begin_write().unwrap();
        write
            .open_table(redb::TableDefinition::<(), u64>::new(
                "wallet_future_schema",
            ))
            .unwrap()
            .insert((), 17)
            .unwrap();
        write.commit().unwrap();
        drop(db);
        let original = fs::read(source.join("state.redb")).unwrap();
        let destination = root.path().join("standalone");
        assert!(migrate(&args(&source, &destination)).is_err());
        assert!(!destination.exists());
        assert_eq!(fs::read(source.join("state.redb")).unwrap(), original);
    }
}
