//! Offline operator commands. Source databases are held read-only and locked
//! throughout verification/copy. Existing destinations are never overwritten.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{SystemTime, UNIX_EPOCH};

thread_local! {
    static CANCELLED: std::cell::RefCell<Option<Arc<AtomicBool>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
thread_local! {
    static BEFORE_UTXO_VISIT: std::cell::Cell<Option<fn()>> = const { std::cell::Cell::new(None) };
}

#[cfg(all(test, target_os = "linux"))]
thread_local! {
    static BEFORE_PUBLISH: std::cell::Cell<Option<fn(&Path)>> = const { std::cell::Cell::new(None) };
}

fn check_interrupted() -> Result<()> {
    if CANCELLED.with(|flag| {
        flag.borrow()
            .as_ref()
            .is_some_and(|f| f.load(Ordering::Relaxed))
    }) {
        return Err(fail(
            "operator command interrupted; any staging copy cleaned up",
        ));
    }
    Ok(())
}

fn requires_interruption_cleanup(command: &crate::config::Command) -> bool {
    use crate::config::Command;
    match command {
        Command::Backup { .. } | Command::Restore { .. } | Command::UpgradeData { .. } => true,
        Command::Init(_)
        | Command::ApiKey { .. }
        | Command::MigrateRedb { .. }
        | Command::VerifyBackup { .. }
        | Command::Doctor { .. }
        | Command::UtxoStats { .. }
        | Command::WalletScanUtxo { .. }
        | Command::WalletLegacyPurge { .. } => false,
    }
}

/// Backup/restore keep signal handling alive until the worker drops staging.
/// Other commands retain the default signal action on every platform.
pub async fn run_interruptible(command: &crate::config::Command) -> Result<String> {
    if !requires_interruption_cleanup(command) {
        let command = command.clone();
        return tokio::task::spawn_blocking(move || run(&command)).await?;
    }
    let command = command.clone();
    run_cancellable(move |_| run(&command)).await
}

/// Keep handlers installed until a blocking cleanup worker has released storage.
/// Startup upgrades share this mechanism with offline maintenance commands.
pub(crate) async fn run_cancellable<T: Send + 'static>(
    work: impl FnOnce(Arc<AtomicBool>) -> Result<T> + Send + 'static,
) -> Result<T> {
    #[cfg(unix)]
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    #[cfg(unix)]
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let cancellation = Arc::new(AtomicBool::new(false));
    let worker_flag = cancellation.clone();
    let mut worker = tokio::task::spawn_blocking(move || {
        CANCELLED.with(|flag| *flag.borrow_mut() = Some(worker_flag.clone()));
        let result = work(worker_flag);
        CANCELLED.with(|flag| *flag.borrow_mut() = None);
        result
    });
    let signal = async {
        #[cfg(unix)]
        tokio::select! { _ = interrupt.recv() => {}, _ = terminate.recv() => {} }
        #[cfg(not(unix))]
        let _ = tokio::signal::ctrl_c().await;
    };
    tokio::select! {
        result = &mut worker => result?,
        _ = signal => {
            cancellation.store(true, Ordering::Relaxed);
            let result = worker.await?;
            result.and_then(|_| Err(fail("operator command interrupted; any staging copy cleaned up")))
        }
    }
}

struct Staging(PathBuf);

impl Staging {
    fn create(parent: &Path, destination: &Path, operation: &str) -> Result<Self> {
        let name = destination
            .file_name()
            .ok_or_else(|| fail("destination needs a directory name"))?;
        let mut staging_name = std::ffi::OsString::from(".");
        staging_name.push(name);
        staging_name.push(format!(".ergo-{operation}-staging"));
        let path = parent.join(staging_name);
        if fs::symlink_metadata(&path).is_ok() {
            return Err(fail(format!("staging path already exists: {}; after confirming no copy is running, remove this stale staging copy before retrying (it may contain wallet secrets)", path.display())));
        }
        private_dir(&path)?;
        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        if self.0.exists() {
            if let Err(error) = fs::remove_dir_all(&self.0) {
                eprintln!(
                    "could not remove staging copy {}: {error}",
                    self.0.display()
                );
            }
        }
    }
}

use ergo_state::maintenance::{inspect_tip, visit_utxos, MaintenanceTip, UtxoStats};
use redb::{
    MultimapTableHandle, ReadOnlyDatabase, ReadableDatabase, ReadableTableMetadata, TableHandle,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
const MANIFEST: &str = "ergo-backup.json";

pub fn run(command: &crate::config::Command) -> Result<String> {
    use crate::config::Command;
    let value = match command {
        Command::Init(_) | Command::ApiKey { .. } => {
            return Err(fail(
                "init and api-key must be dispatched before the runtime",
            ));
        }
        Command::MigrateRedb {
            source,
            destination,
        } => {
            let report = ergo_state::redb_migration::migrate_database(source, destination)?;
            return Ok(format!(
                "verified migration: {} -> {} ({} tables); original preserved",
                source.display(),
                destination.display(),
                report.tables
            ));
        }
        Command::UpgradeData {
            data_dir,
            indexer_db,
            discard_backups,
            keep_stale_indexer,
        } => {
            // Startup may create a fresh data directory; this command must not,
            // or a mistyped path would report a no-op upgrade of a new empty one.
            match fs::metadata(data_dir) {
                Ok(metadata) if metadata.is_dir() => {}
                Ok(_) => {
                    return Err(fail(format!(
                        "data directory is not a directory: {}",
                        data_dir.display()
                    )))
                }
                Err(error) => {
                    return Err(fail(format!(
                        "cannot use data directory {}: {error}",
                        data_dir.display()
                    )))
                }
            }
            let lock = crate::data_upgrade::DataDirectoryLock::acquire(data_dir)?;
            let report = crate::data_upgrade::upgrade_with_logging(
                &lock,
                data_dir,
                indexer_db,
                *discard_backups,
                *keep_stale_indexer,
                false,
                &|| check_interrupted().is_err(),
            )?;
            return Ok(if report.is_noop() {
                "upgrade-data: no-op; no legacy databases or unfinished upgrades".into()
            } else {
                format!("upgrade-data: {} databases migrated, {} stale indexers handled, {} interrupted upgrades recovered, {} retained backups discarded", report.migrated, report.stale_indexers, report.recovered, report.discarded_existing_backups)
            });
        }
        Command::Backup {
            data_dir,
            destination,
        } => serde_json::to_value(backup(data_dir, destination)?)?,
        Command::VerifyBackup { directory } => serde_json::to_value(verify_backup(directory)?)?,
        Command::Restore {
            directory,
            destination,
            keep_pending_work,
        } => serde_json::to_value(restore_with_options(
            directory,
            destination,
            *keep_pending_work,
        )?)?,
        Command::Doctor { data_dir } => serde_json::to_value(doctor(data_dir)?)?,
        Command::UtxoStats { data_dir } => serde_json::to_value(
            doctor(data_dir)?
                .utxo
                .ok_or_else(|| fail("logical UTXO statistics require a UTXO backend"))?,
        )?,
        Command::WalletScanUtxo {
            data_dir,
            wallet_data_dir,
            restart,
        } => {
            match fs::symlink_metadata(data_dir.join(MANIFEST)) {
                Ok(_) => {
                    return Err(fail(
                        "directory contains a backup manifest; restore it before wallet discovery",
                    ))
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            if let Some(wallet_data_dir) = wallet_data_dir {
                serde_json::to_value(discover_external_wallet(
                    data_dir,
                    wallet_data_dir,
                    *restart,
                )?)?
            } else {
                let database = redb::Database::open(data_dir.join("state.redb"))?;
                serde_json::to_value(ergo_state::wallet::utxo_scan::discover(
                    &database, *restart,
                )?)?
            }
        }
        Command::WalletLegacyPurge {
            data_dir,
            remove_keystore,
        } => serde_json::to_value(purge_legacy_wallet(data_dir, *remove_keystore)?)?,
    };
    Ok(serde_json::to_string_pretty(&value)?)
}

#[derive(Debug, Serialize)]
struct LegacyPurgeReport {
    tables_removed: Vec<String>,
    keystore_removed: bool,
}

/// Drop every `wallet_*` table of a stopped node after the daemon adopted
/// the wallet, and compact the file. Freed pages are not securely erased.
fn purge_legacy_wallet(data_dir: &Path, remove_keystore: bool) -> Result<LegacyPurgeReport> {
    use redb::{MultimapTableHandle, TableHandle};
    if !data_dir
        .join(crate::node::legacy_wallet::ADOPTED_MARKER)
        .is_file()
    {
        return Err(fail(
            "the wallet daemon has not adopted this node's wallet; run `ergo-walletd adopt` first",
        ));
    }
    // Database::open takes the exclusive lock, so a running node is refused.
    let mut database = redb::Database::open(data_dir.join("state.redb"))?;
    let write = ergo_state::begin_write_qr(&database)?;
    let tables: Vec<_> = write
        .list_tables()?
        .filter(|table| table.name().starts_with("wallet_"))
        .collect();
    let multimaps: Vec<_> = write
        .list_multimap_tables()?
        .filter(|table| table.name().starts_with("wallet_"))
        .collect();
    let mut names = Vec::new();
    for table in tables {
        names.push(table.name().to_string());
        write.delete_table(table)?;
    }
    for table in multimaps {
        names.push(table.name().to_string());
        write.delete_multimap_table(table)?;
    }
    write.commit()?;
    database.compact()?;
    drop(database);
    let keystore = data_dir.join("wallet");
    let keystore_removed = remove_keystore && keystore.exists();
    if keystore_removed {
        fs::remove_dir_all(&keystore)?;
    }
    Ok(LegacyPurgeReport {
        tables_removed: names,
        keystore_removed,
    })
}

fn read_wallet_marker(directory: &Path, name: &str) -> Result<String> {
    let path = directory.join(name);
    if !fs::symlink_metadata(&path)?.is_file() {
        return Err(fail(format!(
            "external wallet {name} must be a regular file"
        )));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(
            (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
        );
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(fail("external wallet marker changed type"));
    }
    let mut text = String::new();
    file.take(32).read_to_string(&mut text)?;
    if text.len() > 24 {
        return Err(fail("external wallet marker is invalid"));
    }
    Ok(text.trim().to_owned())
}

/// The node owns verified chain traversal; the wallet daemon owns the target
/// projection and seeds. This command needs neither a password nor a secret.
fn discover_external_wallet(
    data_dir: &Path,
    wallet_data_dir: &Path,
    restart: bool,
) -> Result<ergo_state::wallet::utxo_scan::DiscoveryCoverage> {
    if !matches!(
        read_wallet_marker(wallet_data_dir, "wallet-mode")?.as_str(),
        "seed" | "watch_only"
    ) {
        return Err(fail("external wallet has an invalid mode marker"));
    }
    let target_network = read_wallet_marker(wallet_data_dir, "wallet-network")?;
    if !matches!(target_network.as_str(), "mainnet" | "testnet" | "devnet") {
        return Err(fail("external wallet has an invalid network marker"));
    }
    let source_path = data_dir.join("state.redb");
    let target_path = wallet_data_dir.join("wallet.redb");
    for path in [&source_path, &target_path] {
        if !fs::symlink_metadata(path)?.is_file() {
            return Err(fail(
                "wallet discovery database paths must be regular files",
            ));
        }
    }
    if fs::canonicalize(&source_path)? == fs::canonicalize(&target_path)? {
        return Err(fail(
            "external wallet database must differ from the node state database",
        ));
    }
    let source = ReadOnlyDatabase::open(&source_path)
        .map_err(|error| database_access_error("state.redb", error, cfg!(windows)))?;
    let snapshot = source.begin_read()?;
    let source_network = ergo_state::maintenance::committed_network(&snapshot)?;
    if source_network.to_string() != target_network {
        return Err(fail(
            "external wallet network differs from the committed node network",
        ));
    }
    // Database::open never creates a fresh target. Its exclusive lock refuses
    // a live daemon before any staging or wallet-table mutation can occur.
    let target = redb::Database::open(&target_path).map_err(|error| {
        fail(format!(
            "cannot lock wallet.redb; stop the wallet daemon before discovery: {error}"
        ))
    })?;
    Ok(ergo_state::wallet::utxo_scan::discover_into(
        &snapshot, &target, restart,
    )?)
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupManifest {
    pub format_version: u32,
    pub node_version: String,
    pub created_unix_seconds: u64,
    pub tip: MaintenanceTip,
    pub utxo: Option<UtxoStats>,
    pub files: Vec<BackupFile>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupFile {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Serialize)]
pub struct RestoreReport {
    pub backup: BackupManifest,
    pub kept_pending_work: bool,
    pub pending_private_transactions: Vec<ergo_mining::private_queue::PrivateTransactionEntry>,
    pub pending_wallet_jobs: Vec<u64>,
    pub private_queue_quarantine: Option<String>,
    pub wallet_jobs_quarantined: u64,
}

#[derive(Debug, Serialize)]
pub struct DoctorReport {
    pub tip: MaintenanceTip,
    pub utxo: Option<UtxoStats>,
    pub databases: BTreeMap<String, BTreeMap<String, u64>>,
}

fn fail(message: impl Into<String>) -> Box<dyn std::error::Error + Send + Sync> {
    std::io::Error::other(message.into()).into()
}

fn safe_relative(name: &str) -> Result<PathBuf> {
    let path: PathBuf = name.split('/').collect();
    if name.is_empty()
        || name.contains(['\\', ':'])
        || name
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || path
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err(fail(format!("unsafe manifest path {name:?}")));
    }
    Ok(path)
}

fn collect(root: &Path, relative: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(root.join(relative))? {
        let entry = entry?;
        let kind = entry.file_type()?;
        let next = relative.join(entry.file_name());
        if kind.is_symlink() {
            return Err(fail(format!(
                "symlinks are unsupported: {}",
                next.display()
            )));
        }
        if kind.is_dir() {
            collect(root, &next, files)?;
        } else if kind.is_file() {
            files.push(next);
        } else {
            return Err(fail(format!("non-regular file: {}", next.display())));
        }
    }
    files.sort();
    Ok(())
}

fn inventory(root: &Path) -> Result<Vec<PathBuf>> {
    if fs::symlink_metadata(root)?.file_type().is_symlink() {
        return Err(fail("data directory must not be a symlink"));
    }
    let mut files = Vec::new();
    collect(root, Path::new(""), &mut files)?;
    Ok(files)
}

fn database_access_error(
    name: &str,
    error: redb::DatabaseError,
    windows: bool,
) -> Box<dyn std::error::Error + Send + Sync> {
    match &error {
        redb::DatabaseError::RepairAborted => fail(format!("{name} requires recovery after an unclean shutdown; start the node with this data directory to complete redb recovery, then shut it down cleanly before retrying; this command never repairs storage")),
        redb::DatabaseError::DatabaseAlreadyOpen => fail(format!("cannot lock {name} read-only; stop the node first: {error}")),
        // Windows can reject the header probe or database open before redb reports a lock conflict.
        redb::DatabaseError::Storage(redb::StorageError::Io(io))
            if windows && matches!(io.raw_os_error(), Some(5 | 32 | 33)) =>
        {
            fail(format!("cannot lock {name} read-only; stop the node first: {error}"))
        }
        _ => fail(format!("cannot open {name} read-only: {error}")),
    }
}

fn lock_databases(root: &Path, files: &[PathBuf]) -> Result<BTreeMap<String, ReadOnlyDatabase>> {
    let mut databases = BTreeMap::new();
    for file in files {
        // Retained originals are rollback artifacts, not active databases. They
        // stay in the checksummed file inventory and the complete backup copy.
        if file
            .file_name()
            .is_some_and(|name| name.to_string_lossy().ends_with(".redb2-backup"))
        {
            continue;
        }
        let mut header = [0; 9];
        let n = File::open(root.join(file))
            .and_then(|mut input| input.read(&mut header))
            .map_err(|error| {
                database_access_error(&file.display().to_string(), error.into(), cfg!(windows))
            })?;
        let redb_magic = [b'r', b'e', b'd', b'b', 0x1a, 0x0a, 0xa9, 0x0d, 0x0a];
        if !file.extension().is_some_and(|ext| ext == "redb") && (n != 9 || header != redb_magic) {
            continue;
        }
        let name = file
            .to_str()
            .ok_or_else(|| fail("non-UTF8 database filename"))?;
        databases.insert(
            name.to_string(),
            ReadOnlyDatabase::open(root.join(file))
                .map_err(|error| database_access_error(name, error, cfg!(windows)))?,
        );
    }
    if !databases.contains_key("state.redb") {
        return Err(fail("state.redb is missing"));
    }
    Ok(databases)
}

fn inspect(databases: &BTreeMap<String, ReadOnlyDatabase>) -> Result<DoctorReport> {
    let txn = databases["state.redb"].begin_read()?;
    let tip = inspect_tip(&txn)?;
    let utxo = if tip.state_type.as_deref().is_none_or(|v| v == "utxo") && tip.state_root.is_some()
    {
        #[cfg(test)]
        BEFORE_UTXO_VISIT.with(|hook| {
            if let Some(check) = hook.get() {
                check();
            }
        });
        let mut leaves = 0u64;
        Some(visit_utxos(&txn, |_, _, _| {
            if leaves.is_multiple_of(4096) {
                check_interrupted()
                    .map_err(|_| ergo_state::store::StateError::OperatorInterrupted)?;
            }
            leaves += 1;
            Ok(())
        })?)
    } else {
        None
    };
    let mut counts = BTreeMap::new();
    for (name, database) in databases {
        let txn = database.begin_read()?;
        let mut tables = BTreeMap::new();
        for handle in txn.list_tables()? {
            let table_name = handle.name().to_string();
            let table = txn.open_untyped_table(handle)?;
            // stats traverses the table pages and surfaces unreadable storage.
            table.stats()?;
            tables.insert(table_name, table.len()?);
        }
        for handle in txn.list_multimap_tables()? {
            let table_name = handle.name().to_string();
            let table = txn.open_untyped_multimap_table(handle)?;
            table.stats()?;
            tables.insert(table_name, table.len()?);
        }
        counts.insert(name.clone(), tables);
    }
    Ok(DoctorReport {
        tip,
        utxo,
        databases: counts,
    })
}

pub fn doctor(data_dir: &Path) -> Result<DoctorReport> {
    let files = inventory(data_dir)?;
    let databases = lock_databases(data_dir, &files)?;
    inspect(&databases)
}

fn digest_file(path: &Path) -> Result<(u64, String)> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0; 1024 * 1024];
    let mut bytes = 0u64;
    loop {
        check_interrupted()?;
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
        bytes = bytes
            .checked_add(n as u64)
            .ok_or_else(|| fail("file size overflow"))?;
    }
    Ok((bytes, hex::encode(hasher.finalize())))
}

fn private_directories(path: &Path, recursive: bool) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(recursive);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)?;
    Ok(())
}

fn private_dir(path: &Path) -> Result<()> {
    private_directories(path, false)
}

fn private_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok(options.open(path)?)
}

fn sync_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        File::open(path)?.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

fn sync_directories(path: &Path) -> Result<()> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            sync_directories(&entry.path())?;
        }
    }
    sync_directory(path)
}

fn copy_checked(source: &Path, destination: &Path) -> Result<BackupFile> {
    if let Some(parent) = destination.parent() {
        private_directories(parent, true)?;
    }
    let before = fs::metadata(source)?;
    let mut input = File::open(source)?;
    let mut output = private_file(destination)?;
    let mut buffer = vec![0; 1024 * 1024];
    let mut copied = 0u64;
    loop {
        check_interrupted()?;
        let n = input.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        output.write_all(&buffer[..n])?;
        copied += n as u64;
    }
    output.sync_all()?;
    let (bytes, hash) = digest_file(destination)?;
    if copied != bytes || before.len() != bytes || digest_file(source)? != (bytes, hash.clone()) {
        return Err(fail(format!(
            "source changed while copying {}",
            source.display()
        )));
    }
    Ok(BackupFile {
        path: String::new(),
        bytes,
        sha256: hash,
    })
}

fn destination_parent(source: &Path, destination: &Path) -> Result<PathBuf> {
    if destination.try_exists()? {
        return Err(fail("destination already exists"));
    }
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = fs::canonicalize(parent)?;
    if parent.starts_with(fs::canonicalize(source)?) {
        return Err(fail("destination must be outside the source directory"));
    }
    Ok(parent)
}

// Reserve with create_dir to reject even an empty existing destination. Publish
// the entire verified tree with one same-filesystem rename, never file-by-file.
// Interruption can leave an empty reservation, never bootable partial data.
fn publish(staging: &Path, destination: &Path) -> Result<()> {
    check_interrupted()?;
    #[cfg(all(test, target_os = "linux"))]
    BEFORE_PUBLISH.with(|hook| {
        if let Some(check) = hook.get() {
            check(staging);
        }
    });
    private_dir(destination)?;
    // Unix rename replaces the empty reservation. Windows refuses any existing
    // destination; release our reservation there before the same atomic rename.
    #[cfg(windows)]
    fs::remove_dir(destination)?;
    if let Err(error) = fs::rename(staging, destination) {
        let _ = fs::remove_dir(destination);
        return Err(error.into());
    }
    sync_directory(destination)?;
    if let Some(parent) = destination.parent().filter(|p| !p.as_os_str().is_empty()) {
        sync_directory(parent)?;
    }
    Ok(())
}

pub fn backup(data_dir: &Path, destination: &Path) -> Result<BackupManifest> {
    let parent = destination_parent(data_dir, destination)?;
    let files = inventory(data_dir)?;
    if files.iter().any(|f| f == Path::new(MANIFEST)) {
        return Err(fail("source contains a backup manifest; use restore first"));
    }
    let databases = lock_databases(data_dir, &files)?;
    let report = inspect(&databases)?;
    let staging = Staging::create(&parent, destination, "backup")?;
    let mut copied = Vec::new();
    for path in &files {
        let mut file = copy_checked(&data_dir.join(path), &staging.path().join(path))?;
        file.path = path
            .components()
            .map(|component| {
                component
                    .as_os_str()
                    .to_str()
                    .ok_or_else(|| fail("non-UTF8 filename"))
            })
            .collect::<Result<Vec<_>>>()?
            .join("/");
        safe_relative(&file.path)?;
        copied.push(file);
    }
    if inventory(data_dir)? != files {
        return Err(fail("source file inventory changed during backup"));
    }
    let manifest = BackupManifest {
        format_version: 1,
        node_version: env!("CARGO_PKG_VERSION").to_string(),
        created_unix_seconds: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        tip: report.tip,
        utxo: report.utxo,
        files: copied,
    };
    let mut output = private_file(&staging.path().join(MANIFEST))?;
    serde_json::to_writer_pretty(&mut output, &manifest)?;
    output.write_all(b"\n")?;
    output.sync_all()?;
    // Windows cannot rename the staging directory with its manifest still open.
    drop(output);
    // Verify the copied databases, hashes and committed metadata before publish.
    verify_backup(staging.path())?;
    sync_directories(staging.path())?;
    publish(staging.path(), destination)?;
    Ok(manifest)
}

pub fn verify_backup(directory: &Path) -> Result<BackupManifest> {
    let manifest_path = directory.join(MANIFEST);
    let metadata = fs::symlink_metadata(&manifest_path)?;
    if !metadata.file_type().is_file() {
        return Err(fail(
            "backup manifest must be a regular file, not a symlink or special file",
        ));
    }
    if metadata.len() > 16 * 1024 * 1024 {
        return Err(fail("backup manifest is too large"));
    }
    let manifest: BackupManifest = serde_json::from_reader(File::open(manifest_path)?)?;
    if manifest.format_version != 1 {
        return Err(fail("unsupported backup format"));
    }
    let mut listed = BTreeSet::new();
    for file in &manifest.files {
        let path = safe_relative(&file.path)?;
        if file.path == MANIFEST || !listed.insert(path.to_owned()) {
            return Err(fail("duplicate/reserved backup path"));
        }
        if file.sha256.len() != 64 || hex::decode(&file.sha256).is_err() {
            return Err(fail("invalid SHA256 checksum"));
        }
    }
    let files = inventory(directory)?;
    let actual: BTreeSet<_> = files
        .iter()
        .filter(|f| *f != Path::new(MANIFEST))
        .cloned()
        .collect();
    if actual != listed {
        return Err(fail("backup contains missing or unlisted files"));
    }
    let databases = lock_databases(directory, &files)?;
    for file in &manifest.files {
        if digest_file(&directory.join(&file.path))? != (file.bytes, file.sha256.clone()) {
            return Err(fail(format!("checksum mismatch: {}", file.path)));
        }
    }
    let report = inspect(&databases)?;
    if report.tip != manifest.tip || report.utxo != manifest.utxo {
        return Err(fail("backup metadata disagrees with verified databases"));
    }
    Ok(manifest)
}

pub fn restore(directory: &Path, destination: &Path) -> Result<RestoreReport> {
    restore_with_options(directory, destination, false)
}

fn restore_with_options(
    directory: &Path,
    destination: &Path,
    keep_pending_work: bool,
) -> Result<RestoreReport> {
    let parent = destination_parent(directory, destination)?;
    let manifest = verify_backup(directory)?;
    let files = inventory(directory)?;
    let _locks = lock_databases(directory, &files)?;
    let staging = Staging::create(&parent, destination, "restore")?;
    for file in &manifest.files {
        let copied = copy_checked(
            &directory.join(&file.path),
            &staging.path().join(&file.path),
        )?;
        if copied.bytes != file.bytes || copied.sha256 != file.sha256 {
            return Err(fail("backup changed after verification"));
        }
    }
    let report = doctor(staging.path())?;
    if report.tip != manifest.tip || report.utxo != manifest.utxo {
        return Err(fail("restored metadata verification failed"));
    }
    let queue_path = staging.path().join("private-mining-queue.json");
    let queue_exists = queue_path.try_exists()?;
    let pending_private_transactions = if queue_exists {
        ergo_mining::private_queue::PrivateTransactionQueue::open(&queue_path)
            .map_err(fail)?
            .list()
            .into_iter()
            .filter(|entry| entry.state.is_pending())
            .collect()
    } else {
        Vec::new()
    };
    let database = redb::Database::open(staging.path().join("state.redb"))?;
    let pending_wallet_jobs =
        ergo_state::wallet::mining_jobs::pending_jobs(&database.begin_read()?)?;
    let wallet_jobs_quarantined = if keep_pending_work {
        0
    } else {
        ergo_state::wallet::mining_jobs::quarantine(&database)?
    };
    drop(database);
    let private_queue_quarantine = if queue_exists && !keep_pending_work {
        let mut suffix = 0u64;
        let name = loop {
            let name = if suffix == 0 {
                "private-mining-queue.restored-quarantine.json".to_string()
            } else {
                format!("private-mining-queue.restored-quarantine-{suffix}.json")
            };
            if !staging.path().join(&name).try_exists()? {
                break name;
            }
            suffix = suffix
                .checked_add(1)
                .ok_or_else(|| fail("quarantine filename overflow"))?;
        };
        fs::rename(&queue_path, staging.path().join(&name))?;
        Some(name)
    } else {
        None
    };
    sync_directories(staging.path())?;
    publish(staging.path(), destination)?;
    Ok(RestoreReport {
        backup: manifest,
        kept_pending_work: keep_pending_work,
        pending_private_transactions,
        pending_wallet_jobs,
        private_queue_quarantine,
        wallet_jobs_quarantined,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_state::store::StateStore;

    #[test]
    fn only_staging_commands_require_interruption_cleanup() {
        use clap::Parser;
        for (args, expected) in [
            (vec!["ergo-node", "migrate-redb", "/old", "/new"], false),
            (vec!["ergo-node", "backup", "/data", "/backup"], true),
            (vec!["ergo-node", "upgrade-data", "/data"], true),
            (vec!["ergo-node", "verify-backup", "/backup"], false),
            (vec!["ergo-node", "restore", "/backup", "/restored"], true),
            (vec!["ergo-node", "doctor", "/data"], false),
            (vec!["ergo-node", "utxo-stats", "/data"], false),
            (vec!["ergo-node", "wallet-scan-utxo", "/data"], false),
        ] {
            let cli = crate::config::Cli::try_parse_from(&args).unwrap();
            assert_eq!(
                requires_interruption_cleanup(cli.command.as_ref().unwrap()),
                expected,
                "{args:?}"
            );
        }
    }

    #[test]
    fn backup_interrupts_inspection_before_staging() {
        assert_inspection_interrupts("backup");
    }

    #[test]
    fn restore_interrupts_inspection_before_staging() {
        assert_inspection_interrupts("restore");
    }

    fn assert_inspection_interrupts(operation: &str) {
        struct ResetCancellation;
        impl Drop for ResetCancellation {
            fn drop(&mut self) {
                CANCELLED.with(|flag| *flag.borrow_mut() = None);
                BEFORE_UTXO_VISIT.with(|hook| hook.set(None));
            }
        }
        fn cancel() {
            CANCELLED.with(|flag| {
                flag.borrow()
                    .as_ref()
                    .unwrap()
                    .store(true, Ordering::Relaxed);
            });
        }

        let data = seeded_directory();
        let parent = tempfile::tempdir().unwrap();
        let source_backup = parent.path().join("source-backup");
        backup(data.path(), &source_backup).unwrap();
        let source_before = digest_file(&data.path().join("state.redb")).unwrap();
        let backup_before = digest_file(&source_backup.join("state.redb")).unwrap();
        fs::write(parent.path().join("keep"), b"existing destination contents").unwrap();
        let _reset = ResetCancellation;
        let cancellation = Arc::new(AtomicBool::new(false));
        CANCELLED.with(|flag| *flag.borrow_mut() = Some(cancellation.clone()));
        let destination = parent.path().join(operation);
        if operation == "backup" {
            cancellation.store(true, Ordering::Relaxed);
        } else {
            // Let checksum verification finish, then signal before its UTXO walk.
            cancellation.store(false, Ordering::Relaxed);
            BEFORE_UTXO_VISIT.with(|hook| hook.set(Some(cancel)));
        }
        let error = if operation == "backup" {
            backup(data.path(), &destination).unwrap_err()
        } else {
            restore(&source_backup, &destination).unwrap_err()
        };
        assert!(
            matches!(
                error.downcast_ref::<ergo_state::store::StateError>(),
                Some(ergo_state::store::StateError::OperatorInterrupted)
            ),
            "inspection must report operator interruption: {error}"
        );
        assert_eq!(error.to_string(), "operator command interrupted");
        assert!(!destination.exists());
        assert!(!parent
            .path()
            .join(format!(".{operation}.ergo-{operation}-staging"))
            .exists());
        assert_eq!(
            fs::read(parent.path().join("keep")).unwrap(),
            b"existing destination contents"
        );
        cancellation.store(false, Ordering::Relaxed);
        BEFORE_UTXO_VISIT.with(|hook| hook.set(None));
        assert_eq!(
            digest_file(&data.path().join("state.redb")).unwrap(),
            source_before
        );
        assert_eq!(
            digest_file(&source_backup.join("state.redb")).unwrap(),
            backup_before
        );
    }

    fn seeded_directory() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let mut store = StateStore::open(&dir.path().join("state.redb")).unwrap();
        store
            .initialize_genesis(&crate::genesis::mainnet_genesis_boxes())
            .unwrap();
        drop(store);
        fs::create_dir(dir.path().join("wallet")).unwrap();
        fs::write(
            dir.path().join("wallet/encrypted-seed"),
            b"opaque encrypted secret",
        )
        .unwrap();
        fs::write(
            dir.path().join("mining-policy.json"),
            serde_json::to_vec(&ergo_mining::policy::BlockPolicy::default()).unwrap(),
        )
        .unwrap();
        // Operators can configure a non-.redb indexer filename.
        let db = redb::Database::create(dir.path().join("custom-index-file")).unwrap();
        let txn = ergo_state::begin_write_qr(&db).unwrap();
        txn.open_table(redb::TableDefinition::<u32, u32>::new("test"))
            .unwrap()
            .insert(1, 2)
            .unwrap();
        txn.commit().unwrap();
        dir
    }

    fn external_wallet_directory(network: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("wallet-mode"), b"seed\n").unwrap();
        fs::write(dir.path().join("wallet-network"), format!("{network}\n")).unwrap();
        // The command must never inspect or copy this deliberately opaque seed.
        fs::create_dir(dir.path().join("wallet")).unwrap();
        fs::write(
            dir.path().join("wallet/encrypted-seed"),
            b"opaque external secret",
        )
        .unwrap();
        let db = redb::Database::create(dir.path().join("wallet.redb")).unwrap();
        let txn = ergo_state::begin_write_qr(&db).unwrap();
        let pk: [u8; 33] =
            hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap()
                .try_into()
                .unwrap();
        let meta = ergo_wallet_service::wallet::types::TrackedPubkeyMeta {
            derivation_path: vec![],
            derivation_path_label: String::new(),
            added_at_height: 0,
        };
        txn.open_table(ergo_wallet_service::wallet::tables::WALLET_TRACKED_PUBKEYS)
            .unwrap()
            .insert(
                ergo_wallet_service::wallet::tables::tracked_pubkey_key(0, &pk),
                bincode::serialize(&meta).unwrap(),
            )
            .unwrap();
        txn.commit().unwrap();
        drop(db);
        dir
    }

    #[test]
    fn external_wallet_discovery_preserves_source_chain_and_encrypted_seeds() {
        let data = seeded_directory();
        let wallet = external_wallet_directory("mainnet");
        let chain_before = digest_file(&data.path().join("state.redb")).unwrap();
        let embedded_secret = fs::read(data.path().join("wallet/encrypted-seed")).unwrap();
        let external_secret = fs::read(wallet.path().join("wallet/encrypted-seed")).unwrap();
        let output = run(&crate::config::Command::WalletScanUtxo {
            data_dir: data.path().into(),
            wallet_data_dir: Some(wallet.path().into()),
            restart: false,
        })
        .unwrap();
        let result: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(result["history_complete"], false);
        assert_eq!(result["anchor_height"], 0);
        assert_eq!(
            digest_file(&data.path().join("state.redb")).unwrap(),
            chain_before
        );
        assert_eq!(
            fs::read(data.path().join("wallet/encrypted-seed")).unwrap(),
            embedded_secret
        );
        assert_eq!(
            fs::read(wallet.path().join("wallet/encrypted-seed")).unwrap(),
            external_secret
        );
        let source = ReadOnlyDatabase::open(data.path().join("state.redb")).unwrap();
        assert!(
            ergo_wallet_service::wallet::utxo_scan::coverage(&source.begin_read().unwrap())
                .unwrap()
                .is_none()
        );
        let target = ReadOnlyDatabase::open(wallet.path().join("wallet.redb")).unwrap();
        assert!(
            ergo_wallet_service::wallet::utxo_scan::coverage(&target.begin_read().unwrap())
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn external_wallet_discovery_refuses_missing_mode_wrong_network_and_running_owners() {
        let data = seeded_directory();
        let wallet = external_wallet_directory("testnet");
        let target_before = digest_file(&wallet.path().join("wallet.redb")).unwrap();
        assert!(discover_external_wallet(data.path(), wallet.path(), false)
            .unwrap_err()
            .to_string()
            .contains("network differs"));
        assert_eq!(
            digest_file(&wallet.path().join("wallet.redb")).unwrap(),
            target_before
        );
        fs::write(wallet.path().join("wallet-network"), b"mainnet\n").unwrap();
        fs::remove_file(wallet.path().join("wallet-mode")).unwrap();
        assert!(discover_external_wallet(data.path(), wallet.path(), false).is_err());
        assert_eq!(
            digest_file(&wallet.path().join("wallet.redb")).unwrap(),
            target_before
        );
        fs::write(wallet.path().join("wallet-mode"), b"seed\n").unwrap();
        let target = redb::Database::open(wallet.path().join("wallet.redb")).unwrap();
        // Windows prevents raw reads of the live owner's redb file. Compare
        // the complete table inventory and exact rows through that owner.
        let target_contents = || {
            use ergo_wallet_service::wallet::tables::WALLET_TRACKED_PUBKEYS;
            use redb::ReadableTable;

            let read = target.begin_read().unwrap();
            let tables: Vec<_> = read
                .list_tables()
                .unwrap()
                .map(|handle| handle.name().to_owned())
                .collect();
            assert_eq!(tables, vec![WALLET_TRACKED_PUBKEYS.name().to_owned()]);
            assert!(read.list_multimap_tables().unwrap().next().is_none());
            let pubkeys: Vec<_> = read
                .open_table(WALLET_TRACKED_PUBKEYS)
                .unwrap()
                .iter()
                .unwrap()
                .map(|row| {
                    let (key, value) = row.unwrap();
                    (key.value(), value.value().to_vec())
                })
                .collect();
            (tables, pubkeys)
        };
        let target_locked = target_contents();
        assert!(discover_external_wallet(data.path(), wallet.path(), false)
            .unwrap_err()
            .to_string()
            .contains("stop the wallet daemon"));
        assert_eq!(target_contents(), target_locked);
        drop(target);
        // Opening the simulated owner changes redb's recovery header; compare
        // each rejected discovery with the bytes left by that owner's close.
        let target_closed = digest_file(&wallet.path().join("wallet.redb")).unwrap();
        let source = redb::Database::open(data.path().join("state.redb")).unwrap();
        assert!(discover_external_wallet(data.path(), wallet.path(), false)
            .unwrap_err()
            .to_string()
            .contains("stop the node first"));
        drop(source);
        assert_eq!(
            digest_file(&wallet.path().join("wallet.redb")).unwrap(),
            target_closed
        );
    }

    #[cfg(unix)]
    #[test]
    fn external_wallet_discovery_rejects_symlink_markers_without_opening_seeds() {
        let data = seeded_directory();
        let wallet = external_wallet_directory("mainnet");
        fs::remove_file(wallet.path().join("wallet-mode")).unwrap();
        std::os::unix::fs::symlink("wallet/encrypted-seed", wallet.path().join("wallet-mode"))
            .unwrap();
        assert!(discover_external_wallet(data.path(), wallet.path(), false)
            .unwrap_err()
            .to_string()
            .contains("regular file"));
        assert_eq!(
            fs::read(wallet.path().join("wallet/encrypted-seed")).unwrap(),
            b"opaque external secret"
        );
    }

    #[test]
    fn verified_backup_restore_preserves_real_genesis_and_operator_files() {
        let data = seeded_directory();
        let parent = tempfile::tempdir().unwrap();
        let dest = parent.path().join("backup");
        let before = digest_file(&data.path().join("state.redb")).unwrap();
        let report = doctor(data.path()).unwrap();
        let stats = report.utxo.unwrap();
        assert_eq!(
            stats.box_count,
            crate::genesis::mainnet_genesis_boxes().len() as u64
        );
        assert!(stats.state_root_verified);
        assert_eq!(report.databases["custom-index-file"]["test"], 1);
        let manifest = backup(data.path(), &dest).unwrap();
        assert!(manifest
            .files
            .iter()
            .any(|f| f.path == "mining-policy.json"));
        assert_eq!(verify_backup(&dest).unwrap().tip, manifest.tip);
        let restored = parent.path().join("restored");
        restore(&dest, &restored).unwrap();
        assert_eq!(doctor(&restored).unwrap().tip, manifest.tip);
        assert_eq!(
            fs::read(restored.join("wallet/encrypted-seed")).unwrap(),
            b"opaque encrypted secret"
        );
        assert_eq!(
            digest_file(&data.path().join("state.redb")).unwrap(),
            before
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&dest).unwrap().permissions().mode() & 0o777,
                0o700
            );
            for root in [&dest, &restored] {
                assert_eq!(
                    fs::metadata(root.join("wallet"))
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o777,
                    0o700
                );
            }
            assert_eq!(
                fs::metadata(restored.join("wallet/encrypted-seed"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    fn seed_private_work(data: &Path) -> (String, Vec<u8>) {
        use ergo_primitives::{digest::Digest32, reader::VlqReader, writer::VlqWriter};
        use ergo_ser::{
            ergo_box::ErgoBoxCandidate,
            input::{ContextExtension, Input, SpendingProof},
            register::AdditionalRegisters,
            transaction::{transaction_id, write_transaction, Transaction},
        };
        let tx = Transaction {
            inputs: vec![Input {
                box_id: Digest32::from_bytes([0x55; 32]),
                spending_proof: SpendingProof::new(vec![], ContextExtension::empty()).unwrap(),
            }],
            data_inputs: vec![],
            output_candidates: vec![ErgoBoxCandidate::new(
                1_000_000,
                ergo_ser::ergo_tree::read_ergo_tree(&mut VlqReader::new(&[0, 8, 0xd3])).unwrap(),
                100,
                vec![],
                AdditionalRegisters::empty(),
            )
            .unwrap()],
        };
        let id = transaction_id(&tx).unwrap();
        let mut writer = VlqWriter::new();
        write_transaction(&mut writer, &tx).unwrap();
        let bytes = writer.result();
        let entry = ergo_mempool::pool::Entry::new(
            Digest32::from_bytes(*id.as_bytes()),
            Arc::from(bytes.clone()),
            vec![Digest32::from_bytes([0x55; 32])],
            vec![],
            vec![],
            0,
            0,
            bytes.len() as u32,
            100,
            ergo_mempool::types::TxSource::Wallet,
        );
        let queue = ergo_mining::private_queue::PrivateTransactionQueue::open(
            data.join("private-mining-queue.json"),
        )
        .unwrap();
        let private = queue.admit(&entry, Default::default(), 10, 100).unwrap();
        let record = serde_json::to_vec(&serde_json::json!({
            "job": { "id": "1", "request": { "label": "restore-sensitive", "task": { "type": "renew", "boxIds": ["55".repeat(32)] }, "notBeforeHeight": 10, "expiresAtHeight": 100, "maxAttempts": 1 }, "state": "prepared", "createdAtMs": 10, "updatedAtMs": 10, "attempts": 1, "txId": private.tx_id, "detail": null },
            "signed_hex": hex::encode(&bytes), "last_attempt_height": 10
        })).unwrap();
        let db = redb::Database::open(data.join("state.redb")).unwrap();
        let txn = ergo_state::begin_write_qr(&db).unwrap();
        txn.open_table(ergo_state::wallet::mining_jobs::JOURNAL)
            .unwrap()
            .insert(1, record.as_slice())
            .unwrap();
        txn.commit().unwrap();
        (hex::encode(id.as_bytes()), record)
    }

    #[test]
    fn restore_quarantines_private_work_unless_operator_explicitly_keeps_it() {
        let data = seeded_directory();
        let (tx_id, record) = seed_private_work(data.path());
        let original_queue = fs::read(data.path().join("private-mining-queue.json")).unwrap();
        fs::write(
            data.path()
                .join("private-mining-queue.restored-quarantine.json"),
            b"earlier quarantine",
        )
        .unwrap();
        fs::write(data.path().join("mining-history.json"), b"history fixture").unwrap();
        let parent = tempfile::tempdir().unwrap();
        let backup_dir = parent.path().join("backup");
        backup(data.path(), &backup_dir).unwrap();
        let dest = parent.path().join("safe-restore");
        let report = restore(&backup_dir, &dest).unwrap();
        assert!(!report.kept_pending_work);
        assert_eq!(report.pending_private_transactions[0].tx_id, tx_id);
        assert_eq!(report.pending_wallet_jobs, vec![1]);
        assert_eq!(report.wallet_jobs_quarantined, 1);
        assert_eq!(
            report.private_queue_quarantine.as_deref(),
            Some("private-mining-queue.restored-quarantine-1.json")
        );
        assert_eq!(
            fs::read(dest.join("private-mining-queue.restored-quarantine.json")).unwrap(),
            b"earlier quarantine"
        );
        assert!(!dest.join("private-mining-queue.json").exists());
        assert_eq!(
            fs::read(dest.join(report.private_queue_quarantine.unwrap())).unwrap(),
            original_queue
        );
        assert_eq!(
            fs::read(dest.join("mining-history.json")).unwrap(),
            b"history fixture"
        );
        assert_eq!(
            fs::read(dest.join("mining-policy.json")).unwrap(),
            fs::read(data.path().join("mining-policy.json")).unwrap()
        );
        assert_eq!(doctor(&dest).unwrap().tip, report.backup.tip);
        assert_eq!(doctor(&dest).unwrap().utxo, report.backup.utxo);
        let db = redb::Database::open(dest.join("state.redb")).unwrap();
        let read = db.begin_read().unwrap();
        assert!(ergo_state::wallet::mining_jobs::pending_jobs(&read)
            .unwrap()
            .is_empty());
        assert_eq!(
            read.open_table(ergo_state::wallet::mining_jobs::QUARANTINE)
                .unwrap()
                .get(1)
                .unwrap()
                .unwrap()
                .value(),
            record
        );
        drop(read);
        drop(db);
        let confirmed = parent.path().join("confirmed-restore");
        let report = restore_with_options(&backup_dir, &confirmed, true).unwrap();
        assert!(report.kept_pending_work);
        assert_eq!(report.wallet_jobs_quarantined, 0);
        assert!(report.private_queue_quarantine.is_none());
        assert_eq!(
            fs::read(confirmed.join("private-mining-queue.json")).unwrap(),
            original_queue
        );
        assert_eq!(doctor(&confirmed).unwrap().tip, report.backup.tip);
        assert_eq!(doctor(&confirmed).unwrap().utxo, report.backup.utxo);
        let db = redb::Database::open(confirmed.join("state.redb")).unwrap();
        assert_eq!(
            ergo_state::wallet::mining_jobs::pending_jobs(&db.begin_read().unwrap()).unwrap(),
            vec![1]
        );
        verify_backup(&backup_dir).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn publication_closes_all_staging_handles() {
        thread_local! {
            static PUBLICATIONS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
        }
        fn assert_closed(staging: &Path) {
            for entry in fs::read_dir("/proc/self/fd").unwrap() {
                // Another test's descriptor may close between enumeration and readlink.
                if let Ok(path) = fs::read_link(entry.unwrap().path()) {
                    assert!(!path.starts_with(staging), "open staging handle: {path:?}");
                }
            }
            PUBLICATIONS.with(|count| count.set(count.get() + 1));
        }
        struct ResetHook;
        impl Drop for ResetHook {
            fn drop(&mut self) {
                BEFORE_PUBLISH.with(|hook| hook.set(None));
            }
        }

        let data = seeded_directory();
        seed_private_work(data.path());
        let parent = tempfile::tempdir().unwrap();
        let backup_dir = parent.path().join("backup");
        let _reset = ResetHook;
        BEFORE_PUBLISH.with(|hook| hook.set(Some(assert_closed)));
        backup(data.path(), &backup_dir).unwrap();
        restore(&backup_dir, &parent.path().join("quarantined")).unwrap();
        restore_with_options(&backup_dir, &parent.path().join("kept"), true).unwrap();
        PUBLICATIONS.with(|count| assert_eq!(count.get(), 3));
    }

    #[test]
    fn live_database_and_existing_destination_are_refused_without_changes() {
        let data = seeded_directory();
        let parent = tempfile::tempdir().unwrap();
        let live = redb::Database::open(data.path().join("state.redb")).unwrap();
        let destination = parent.path().join("backup");
        assert!(backup(data.path(), &destination)
            .unwrap_err()
            .to_string()
            .contains("stop the node"));
        assert!(!destination.exists());
        drop(live);
        fs::create_dir(&destination).unwrap();
        fs::write(destination.join("keep"), b"existing").unwrap();
        assert!(backup(data.path(), &destination).is_err());
        assert_eq!(fs::read(destination.join("keep")).unwrap(), b"existing");
        assert!(backup(data.path(), &data.path().join("nested")).is_err());
    }

    #[test]
    fn windows_database_access_errors_preserve_operator_guidance() {
        for windows in [false, true] {
            for code in [5, 32, 33, 2, 13] {
                let error = database_access_error(
                    "state.redb",
                    std::io::Error::from_raw_os_error(code).into(),
                    windows,
                )
                .to_string();
                assert!(error.contains("state.redb"));
                assert!(error.contains(&format!("os error {code}")), "{error}");
                assert_eq!(
                    error.contains("stop the node first"),
                    windows && matches!(code, 5 | 32 | 33),
                    "{error}"
                );
                assert!(!error.contains("unclean shutdown"));
            }
            let live = database_access_error(
                "state.redb",
                redb::DatabaseError::DatabaseAlreadyOpen,
                windows,
            )
            .to_string();
            assert!(live.contains("stop the node first"));
            let unclean =
                database_access_error("state.redb", redb::DatabaseError::RepairAborted, windows)
                    .to_string();
            assert!(unclean.contains("unclean shutdown"));
            assert!(unclean.contains("shut it down cleanly"));
            assert!(!unclean.contains("stop the node first"));
        }
    }

    #[test]
    fn corruption_unlisted_files_and_manifest_traversal_block_restore() {
        let data = seeded_directory();
        let parent = tempfile::tempdir().unwrap();
        let dest = parent.path().join("backup");
        backup(data.path(), &dest).unwrap();
        let file = dest.join("wallet/encrypted-seed");
        fs::write(&file, b"changed secret").unwrap();
        let restore_dest = parent.path().join("restore");
        assert!(restore(&dest, &restore_dest)
            .unwrap_err()
            .to_string()
            .contains("checksum mismatch"));
        assert!(!restore_dest.exists());
        fs::write(file, b"opaque encrypted secret").unwrap();
        fs::write(dest.join("extra"), b"unlisted").unwrap();
        assert!(verify_backup(&dest)
            .unwrap_err()
            .to_string()
            .contains("unlisted"));
        fs::remove_file(dest.join("extra")).unwrap();
        let mut manifest = verify_backup(&dest).unwrap();
        manifest.files[0].path = "../outside".into();
        fs::write(dest.join(MANIFEST), serde_json::to_vec(&manifest).unwrap()).unwrap();
        assert!(verify_backup(&dest)
            .unwrap_err()
            .to_string()
            .contains("unsafe manifest path"));
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_refused_before_publication() {
        let data = seeded_directory();
        std::os::unix::fs::symlink("state.redb", data.path().join("alias")).unwrap();
        let parent = tempfile::tempdir().unwrap();
        assert!(backup(data.path(), &parent.path().join("backup"))
            .unwrap_err()
            .to_string()
            .contains("symlinks"));
        assert!(!parent.path().join("backup").exists());
    }

    #[test]
    fn manifest_paths_are_portable_and_reject_windows_prefixes() {
        let data = seeded_directory();
        let parent = tempfile::tempdir().unwrap();
        let manifest = backup(data.path(), &parent.path().join("backup")).unwrap();
        assert!(manifest
            .files
            .iter()
            .any(|f| f.path == "wallet/encrypted-seed"));
        assert!(manifest.files.iter().all(|f| !f.path.contains('\\')));
        assert_eq!(
            safe_relative("wallet/encrypted-seed").unwrap(),
            Path::new("wallet").join("encrypted-seed")
        );
        for path in [
            r"wallet\encrypted-seed",
            "C:/secret",
            "C:secret",
            "../secret",
            "/secret",
            "wallet//secret",
            "wallet/./secret",
        ] {
            assert!(safe_relative(path).is_err(), "accepted {path:?}");
        }
    }

    #[test]
    fn staging_is_destination_scoped_and_stale_copies_are_refused() {
        let data = seeded_directory();
        let parent = tempfile::tempdir().unwrap();
        for operation in ["backup", "restore"] {
            let destination = parent.path().join(operation);
            let stale = parent
                .path()
                .join(format!(".{operation}.ergo-{operation}-staging"));
            fs::create_dir(&stale).unwrap();
            fs::write(stale.join("secret"), b"recoverable").unwrap();
            let error = if operation == "backup" {
                backup(data.path(), &destination).unwrap_err()
            } else {
                let source = parent.path().join("source-backup");
                backup(data.path(), &source).unwrap();
                restore(&source, &destination).unwrap_err()
            };
            assert!(error.to_string().contains("staging path already exists"));
            assert_eq!(fs::read(stale.join("secret")).unwrap(), b"recoverable");
            assert!(!destination.exists());
            fs::remove_dir_all(&stale).unwrap();
        }
        let destination = parent.path().join("cancelled");
        CANCELLED.with(|flag| *flag.borrow_mut() = Some(Arc::new(AtomicBool::new(true))));
        let error = backup(data.path(), &destination).unwrap_err();
        CANCELLED.with(|flag| *flag.borrow_mut() = None);
        assert!(error.to_string().contains("interrupted"));
        assert!(!destination.exists());
        assert!(!parent
            .path()
            .join(".cancelled.ergo-backup-staging")
            .exists());
    }

    #[test]
    fn discovery_refuses_backup_without_opening_database() {
        let data = seeded_directory();
        let parent = tempfile::tempdir().unwrap();
        let dest = parent.path().join("backup");
        backup(data.path(), &dest).unwrap();
        let before = digest_file(&dest.join("state.redb")).unwrap();
        let error = run(&crate::config::Command::WalletScanUtxo {
            data_dir: dest.clone(),
            wallet_data_dir: None,
            restart: false,
        })
        .unwrap_err();
        assert!(error.to_string().contains("backup manifest"));
        assert_eq!(digest_file(&dest.join("state.redb")).unwrap(), before);
        verify_backup(&dest).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_manifest_is_refused_before_reading() {
        let data = seeded_directory();
        let parent = tempfile::tempdir().unwrap();
        let dest = parent.path().join("backup");
        backup(data.path(), &dest).unwrap();
        fs::rename(dest.join(MANIFEST), parent.path().join("manifest")).unwrap();
        std::os::unix::fs::symlink(parent.path().join("manifest"), dest.join(MANIFEST)).unwrap();
        assert!(verify_backup(&dest)
            .unwrap_err()
            .to_string()
            .contains("manifest must be a regular file"));
    }

    #[cfg(unix)]
    #[test]
    fn fifo_manifest_is_refused_before_opening() {
        let parent = tempfile::tempdir().unwrap();
        assert!(std::process::Command::new("mkfifo")
            .arg(parent.path().join(MANIFEST))
            .status()
            .unwrap()
            .success());
        assert!(verify_backup(parent.path())
            .unwrap_err()
            .to_string()
            .contains("manifest must be a regular file"));
    }

    #[test]
    fn unclean_database_requires_clean_restart_without_read_only_repair() {
        const CHILD_PATH: &str = "ERGO_TEST_UNCLEAN_DATABASE_PATH";
        if let Some(path) = std::env::var_os(CHILD_PATH) {
            let db = redb::Database::open(path).unwrap();
            let txn = ergo_state::begin_write_qr(&db).unwrap();
            txn.open_table(redb::TableDefinition::<u32, u32>::new("unclean"))
                .unwrap()
                .insert(1, 1)
                .unwrap();
            txn.commit().unwrap();
            // Deliberately bypass Database::drop in this disposable child.
            std::process::exit(0);
        }
        let data = seeded_directory();
        assert!(std::process::Command::new(std::env::current_exe().unwrap()).args(["--exact", "maintenance::tests::unclean_database_requires_clean_restart_without_read_only_repair"]).env(CHILD_PATH, data.path().join("state.redb")).status().unwrap().success());
        let before = digest_file(&data.path().join("state.redb")).unwrap();
        let parent = tempfile::tempdir().unwrap();
        for error in [
            doctor(data.path()).unwrap_err(),
            backup(data.path(), &parent.path().join("backup")).unwrap_err(),
        ] {
            assert!(error.to_string().contains("unclean shutdown"), "{error}");
            assert!(error.to_string().contains("shut it down cleanly"));
            assert!(!error.to_string().contains("stop the node first"));
        }
        assert_eq!(
            digest_file(&data.path().join("state.redb")).unwrap(),
            before
        );
    }

    #[test]
    fn offline_commands_parse_without_startup_arguments() {
        use clap::Parser;
        for args in [
            vec!["ergo-node", "backup", "/data", "/backup"],
            vec!["ergo-node", "verify-backup", "/backup"],
            vec!["ergo-node", "restore", "/backup", "/restored"],
            vec!["ergo-node", "doctor", "/data"],
            vec!["ergo-node", "utxo-stats", "/data"],
            vec!["ergo-node", "wallet-scan-utxo", "/data", "--restart"],
            vec![
                "ergo-node",
                "wallet-scan-utxo",
                "/data",
                "--wallet-data-dir",
                "/wallet",
            ],
        ] {
            assert!(crate::config::Cli::try_parse_from(args)
                .unwrap()
                .command
                .is_some());
        }
    }

    #[test]
    fn upgrade_data_refuses_missing_or_non_directory_data_dir_without_creating_it() {
        let parent = tempfile::tempdir().unwrap();
        let file = parent.path().join("not-a-directory");
        fs::write(&file, b"keep").unwrap();
        for (data_dir, expected) in [
            (
                parent.path().join("mistyped/ergo-data"),
                "cannot use data directory",
            ),
            (file.clone(), "data directory is not a directory"),
        ] {
            let error = run(&crate::config::Command::UpgradeData {
                data_dir: data_dir.clone(),
                indexer_db: "indexer.redb".into(),
                discard_backups: false,
                keep_stale_indexer: false,
            })
            .unwrap_err()
            .to_string();
            assert!(error.contains(expected), "{error}");
        }
        assert!(!parent.path().join("mistyped").exists());
        assert_eq!(fs::read(&file).unwrap(), b"keep");
    }
}
