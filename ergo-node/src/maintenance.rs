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

fn check_interrupted() -> Result<()> {
    if CANCELLED.with(|flag| {
        flag.borrow()
            .as_ref()
            .is_some_and(|f| f.load(Ordering::Relaxed))
    }) {
        return Err(fail(
            "operator command interrupted; staging copy cleaned up",
        ));
    }
    Ok(())
}

/// Keep signal handling alive until the blocking copy has closed its files and
/// dropped its staging guard. Cancellation is checked between copy/hash chunks.
pub async fn run_interruptible(command: &crate::config::Command) -> Result<String> {
    #[cfg(unix)]
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    #[cfg(unix)]
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let cancellation = Arc::new(AtomicBool::new(false));
    let worker_flag = cancellation.clone();
    let command = command.clone();
    let mut worker = tokio::task::spawn_blocking(move || {
        CANCELLED.with(|flag| *flag.borrow_mut() = Some(worker_flag));
        let result = run(&command);
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
            worker.await?
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
    let value =
        match command {
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
            Command::Backup {
                data_dir,
                destination,
            } => serde_json::to_value(backup(data_dir, destination)?)?,
            Command::VerifyBackup { directory } => serde_json::to_value(verify_backup(directory)?)?,
            Command::Restore {
                directory,
                destination,
            } => serde_json::to_value(restore(directory, destination)?)?,
            Command::Doctor { data_dir } => serde_json::to_value(doctor(data_dir)?)?,
            Command::UtxoStats { data_dir } => serde_json::to_value(
                doctor(data_dir)?
                    .utxo
                    .ok_or_else(|| fail("logical UTXO statistics require a UTXO backend"))?,
            )?,
            Command::WalletScanUtxo { data_dir, restart } => {
                match fs::symlink_metadata(data_dir.join(MANIFEST)) {
                    Ok(_) => return Err(fail(
                        "directory contains a backup manifest; restore it before wallet discovery",
                    )),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
                let database = redb::Database::open(data_dir.join("state.redb"))?;
                serde_json::to_value(ergo_state::wallet::utxo_scan::discover(
                    &database, *restart,
                )?)?
            }
        };
    Ok(serde_json::to_string_pretty(&value)?)
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

fn lock_databases(root: &Path, files: &[PathBuf]) -> Result<BTreeMap<String, ReadOnlyDatabase>> {
    let mut databases = BTreeMap::new();
    for file in files {
        let mut header = [0; 9];
        let n = File::open(root.join(file))?.read(&mut header)?;
        let redb_magic = [b'r', b'e', b'd', b'b', 0x1a, 0x0a, 0xa9, 0x0d, 0x0a];
        if !file.extension().is_some_and(|ext| ext == "redb") && (n != 9 || header != redb_magic) {
            continue;
        }
        let name = file
            .to_str()
            .ok_or_else(|| fail("non-UTF8 database filename"))?;
        databases.insert(
            name.to_string(),
            ReadOnlyDatabase::open(root.join(file)).map_err(|error| match error {
                redb::DatabaseError::RepairAborted => fail(format!("{name} requires recovery after an unclean shutdown; start the node with this data directory to complete redb recovery, then shut it down cleanly before retrying; this command never repairs storage")),
                redb::DatabaseError::DatabaseAlreadyOpen => fail(format!("cannot lock {name} read-only; stop the node first: {error}")),
                _ => fail(format!("cannot open {name} read-only: {error}")),
            })?,
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
        Some(visit_utxos(&txn, |_, _, _| Ok(()))?)
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

pub fn restore(directory: &Path, destination: &Path) -> Result<BackupManifest> {
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
    sync_directories(staging.path())?;
    publish(staging.path(), destination)?;
    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_state::store::StateStore;

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
        ] {
            assert!(crate::config::Cli::try_parse_from(args)
                .unwrap()
                .command
                .is_some());
        }
    }
}
