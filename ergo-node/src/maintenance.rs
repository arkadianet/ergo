//! Offline operator commands. Source databases are held read-only and locked
//! throughout verification/copy. Existing destinations are never overwritten.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

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
        || name.split('/').any(|part| part.is_empty() || part == "." || part == "..")
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
            ReadOnlyDatabase::open(root.join(file)).map_err(|e| {
                fail(format!(
                    "cannot lock {name} read-only; stop the node first: {e}"
                ))
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

fn private_dir(path: &Path) -> Result<()> {
    fs::create_dir(path)?;
    secure_directory(path)
}

fn secure_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
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
        fs::create_dir_all(parent)?;
    }
    let before = fs::metadata(source)?;
    let mut input = File::open(source)?;
    let mut output = private_file(destination)?;
    let copied = std::io::copy(&mut input, &mut output)?;
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
    let staging = tempfile::Builder::new()
        .prefix(".ergo-backup-")
        .tempdir_in(parent)?;
    secure_directory(staging.path())?;
    let mut copied = Vec::new();
    for path in &files {
        let mut file = copy_checked(&data_dir.join(path), &staging.path().join(path))?;
        file.path = path
            .components()
            .map(|component| component.as_os_str().to_str().ok_or_else(|| fail("non-UTF8 filename")))
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
    if fs::metadata(&manifest_path)?.len() > 16 * 1024 * 1024 {
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
    let staging = tempfile::Builder::new()
        .prefix(".ergo-restore-")
        .tempdir_in(parent)?;
    secure_directory(staging.path())?;
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
            dir.path().join("credentials-revoked.json"),
            b"{\"version\":1,\"ids\":[\"retired\"]}",
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
            .any(|f| f.path == "credentials-revoked.json"));
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
        assert!(manifest.files.iter().any(|f| f.path == "wallet/encrypted-seed"));
        assert!(manifest.files.iter().all(|f| !f.path.contains('\\')));
        assert_eq!(safe_relative("wallet/encrypted-seed").unwrap(), Path::new("wallet").join("encrypted-seed"));
        for path in [r"wallet\encrypted-seed", "C:/secret", "C:secret", "../secret", "/secret", "wallet//secret", "wallet/./secret"] {
            assert!(safe_relative(path).is_err(), "accepted {path:?}");
        }
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
