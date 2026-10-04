//! In-place file-format upgrades, shared by startup and the offline command.
//!
//! Inventory: state.redb (UTXO/digest and embedded wallet tables), peers.redb,
//! webhooks.redb, and `[indexer] db_filename`. The wallet secret, mining queue,
//! policy/history, credentials and maintenance journals are JSON/files, not redb.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ergo_state::redb_migration::{
    migrate_database_observed, MigrationError, MigrationProgress, MigrationReport,
};
use redb_legacy::StorageBackend;
use serde::{Deserialize, Serialize};

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Held before inventory/upgrade and until the running node releases storage.
/// Never unlink this file: all processes must lock the same inode.
#[derive(Debug)]
pub struct DataDirectoryLock {
    file: File,
    directory: PathBuf,
}

impl DataDirectoryLock {
    pub fn acquire(directory: &Path) -> Result<Self> {
        fs::create_dir_all(directory)?;
        let path = directory.join(".ergo-node.lock");
        if fs::symlink_metadata(&path).is_ok_and(|m| !m.is_file() || m.file_type().is_symlink()) {
            return Err(fail(format!(
                "invalid data-directory lock: {}",
                path.display()
            )));
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        file.try_lock().map_err(|e| {
            fail(format!(
                "data directory is in use; stop the other node or upgrade command: {e}"
            ))
        })?;
        Ok(Self {
            file,
            directory: fs::canonicalize(directory)?,
        })
    }
}

impl DataDirectoryLock {
    fn check_directory(&self, directory: &Path) -> Result<()> {
        if self.directory != fs::canonicalize(directory)? {
            return Err(fail("data-directory lock does not cover this directory"));
        }
        Ok(())
    }
}

impl Drop for DataDirectoryLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

#[derive(Debug, Default, PartialEq, Eq, Serialize)]
pub struct UpgradeReport {
    pub migrated: usize,
    pub stale_indexers: usize,
    pub recovered: usize,
    pub discarded_existing_backups: usize,
}

impl UpgradeReport {
    pub fn is_noop(&self) -> bool {
        self == &Self::default()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileFormat {
    Current,
    LegacyV2,
}

fn fail(message: impl Into<String>) -> Box<dyn std::error::Error + Send + Sync> {
    io::Error::other(message.into()).into()
}

fn regular(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_file() => Ok(true),
        Ok(_) => Err(fail(format!(
            "expected a regular file, not a symlink: {}",
            path.display()
        ))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// Current reader classification never writes recovery markers to the source.
/// A current file needing recovery is left for the normal store open to repair.
pub fn classify(path: &Path) -> Result<FileFormat> {
    if !regular(path)? {
        return Err(fail(format!("missing database: {}", path.display())));
    }
    std::panic::catch_unwind(|| {
        match redb::Database::builder()
            .set_cache_size(8 * 1024 * 1024)
            .open_read_only(path)
        {
            Ok(_) | Err(redb::DatabaseError::RepairAborted) => Ok(FileFormat::Current),
            Err(redb::DatabaseError::UpgradeRequired(2)) => Ok(FileFormat::LegacyV2),
            Err(e) => Err(fail(format!(
                "cannot classify {} without writing: {e}",
                path.display()
            ))),
        }
    })
    .map_err(|_| fail(format!("malformed database metadata: {}", path.display())))?
}

fn database_paths(directory: &Path, indexer_filename: &Path) -> Result<Vec<PathBuf>> {
    let indexer = directory.join(indexer_filename);
    if indexer.components().any(|component| {
        let name = component.as_os_str().to_string_lossy();
        name.ends_with(".redb-upgrade")
    }) || indexer
        .file_name()
        .is_some_and(|name| name.to_string_lossy().ends_with(".redb2-backup"))
    {
        return Err(fail(
            "indexer db_filename uses a reserved upgrade artifact name",
        ));
    }
    // The config permits nested and absolute paths. Resolve the parent to catch
    // aliases before ever treating a consensus/peer/webhook file as an indexer.
    fn identity(path: &Path) -> Result<PathBuf> {
        match fs::canonicalize(path) {
            Ok(path) => Ok(path),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let parent = path
                    .parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or(Path::new("."));
                Ok(identity(parent)?.join(
                    path.file_name()
                        .ok_or_else(|| fail("database needs a filename"))?,
                ))
            }
            Err(error) => Err(error.into()),
        }
    }
    let mut paths = vec![indexer];
    for filename in ["state.redb", "peers.redb", "webhooks.redb"] {
        let path = directory.join(filename);
        if identity(&paths[0])? == identity(&path)? {
            return Err(fail("indexer db_filename aliases another node database"));
        }
        paths.push(path);
    }
    Ok(paths)
}

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

fn sync_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path; // Same directory-sync limitation as migrate_database.
    Ok(())
}

/// Query the filesystem containing the file, rather than the root filesystem.
/// Refreshed before each copy; tests inject a provider into UpgradeOptions.
pub fn available_space(path: &Path) -> Result<u64> {
    let canonical = fs::canonicalize(path)?;
    #[cfg(windows)]
    let canonical = PathBuf::from(canonical.to_string_lossy().trim_start_matches(r"\\?\"));
    sysinfo::Disks::new_with_refreshed_list()
        .iter()
        .filter(|disk| canonical.starts_with(disk.mount_point()))
        .max_by_key(|disk| disk.mount_point().as_os_str().len())
        .map(|disk| disk.available_space())
        .ok_or_else(|| {
            fail(format!(
                "cannot determine available bytes for {}",
                path.display()
            ))
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpgradeStep {
    StageCreated,
    Copied,
    Verified,
    CopyPublished,
    Ready,
    OriginalRenamed,
    Installed,
    BeforeDirectorySync,
    DirectorySynced,
    BackupDiscarded,
}

/// Copy headroom: file size plus max(10%, 256 MiB). The original remains
/// allocated when renamed to a backup; discard frees it only after publication.
pub fn required_space(bytes: u64) -> u64 {
    bytes.saturating_add((bytes / 10).max(256 * 1024 * 1024))
}

pub struct UpgradeOptions<'a> {
    pub discard_backups: bool,
    pub keep_stale_indexer: bool,
    pub indexer_enabled: bool,
    pub warning: &'a mut dyn FnMut(&str),
    pub free_space: &'a dyn Fn(&Path) -> Result<u64>,
    pub cancelled: &'a dyn Fn() -> bool,
    pub progress: &'a mut dyn FnMut(&Path, u64, Duration, &MigrationProgress),
    pub step: &'a mut dyn FnMut(UpgradeStep) -> Result<()>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    stale_indexer: bool,
    discard_backup: bool,
    #[serde(default)]
    stale_indexer_bytes: Option<u64>,
}

fn write_intent(stage: &Path, intent: &Intent) -> Result<()> {
    let mut marker = tempfile::NamedTempFile::new_in(stage)?;
    marker.write_all(&serde_json::to_vec(intent)?)?;
    marker.as_file().sync_all()?;
    marker.persist_noclobber(stage.join("ready"))?;
    sync_directory(stage)
}

// Durable states (under the data-directory lock):
// 1. No stage: original is legacy/current; an existing backup is never replaced.
// 2. Stage without ready: original untouched, copy incomplete/untrusted. Remove
//    stage and retry. SIGKILL may leave the converter's private temp inside it.
// 3. ready + original + copy: verified copy and intent synced. Rename original
//    to backup, sync its parent BEFORE installing copy. For stale indexers the
//    ready intent has no copy and only the original-to-backup step is needed.
// 4. ready + backup + copy, no original: finish installing the verified copy;
//    backup is the original, so failed publication always has a rollback source.
// 5. ready + original + backup, no copy: installation complete. Sync parent,
//    optionally delete backup, sync again, remove stage and sync parent.
//    If both current and copy are absent but backup survives, restore backup
//    and retry conversion.
// 6. ready + current original, no backup/copy: discard already completed;
//    finish stage cleanup. Stale+discard may instead have neither database.
// We never delete the only copy of migrated data, or replace an existing backup.
// Cancellation before ready drops staging; after ready we finish the bounded
// rename/sync sequence before reporting interruption. No copy work runs here.
fn finish_swap(
    path: &Path,
    stage: &Path,
    intent: &Intent,
    source_verified: bool,
    options: &mut UpgradeOptions<'_>,
) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| fail("database needs a parent"))?;
    let backup = sibling(path, ".redb2-backup");
    let copy = stage.join("copy.redb");
    let original_exists = regular(path)?;
    let backup_exists = regular(&backup)?;
    let copy_exists = regular(&copy)?;
    if intent.stale_indexer {
        if copy_exists || (original_exists && backup_exists) {
            return Err(fail(
                "ambiguous stale-indexer upgrade state; retain all files",
            ));
        }
        if original_exists {
            if !source_verified && classify(path)? != FileFormat::LegacyV2 {
                return Err(fail("stale-indexer original changed; retain all files"));
            }
            fs::rename(path, &backup)?;
            (options.step)(UpgradeStep::OriginalRenamed)?;
        } else if !backup_exists && !intent.discard_backup {
            return Err(fail("stale-indexer rollback backup is missing"));
        }
    } else if copy_exists {
        if classify(&copy)? != FileFormat::Current {
            return Err(fail("invalid verified-copy state; retain all files"));
        }
        if original_exists && backup_exists {
            // A power loss may retain the old source-directory entry for the
            // second rename. The installed file is durable before copy removal.
            if classify(path)? != FileFormat::Current {
                return Err(fail("ambiguous upgrade state; retain all files"));
            }
            fs::remove_file(&copy)?;
        } else if original_exists {
            if !source_verified && classify(path)? != FileFormat::LegacyV2 {
                return Err(fail("upgrade original changed; retain all files"));
            }
            fs::rename(path, &backup)?;
            (options.step)(UpgradeStep::OriginalRenamed)?;
            sync_directory(parent)?;
        } else if !backup_exists {
            return Err(fail(
                "upgrade original and rollback backup are both missing",
            ));
        }
        if regular(&copy)? {
            fs::rename(&copy, path)?;
            (options.step)(UpgradeStep::Installed)?;
        }
    } else if !original_exists && backup_exists {
        // If the verified copy's directory entry is unavailable after a power
        // loss, restore the retained original. The outer loop can migrate it
        // again; never strand a directory with only a renamed original.
        fs::rename(&backup, path)?;
        sync_directory(parent)?;
        fs::remove_dir_all(stage)?;
        sync_directory(parent)?;
        return Ok(());
    } else if !original_exists
        || classify(path)? != FileFormat::Current
        || (!backup_exists && !intent.discard_backup)
    {
        return Err(fail(
            "incomplete upgrade has no verified current database; retain all files",
        ));
    }
    (options.step)(UpgradeStep::BeforeDirectorySync)?;
    sync_directory(parent)?;
    // Install is durable before syncing removal from the source directory.
    sync_directory(stage)?;
    (options.step)(UpgradeStep::DirectorySynced)?;
    if intent.discard_backup && regular(&backup)? {
        fs::remove_file(&backup)?;
        sync_directory(parent)?;
        (options.step)(UpgradeStep::BackupDiscarded)?;
    }
    fs::remove_dir_all(stage)?;
    sync_directory(parent)
}

fn recover(path: &Path, options: &mut UpgradeOptions<'_>) -> Result<bool> {
    let stage = sibling(path, ".redb-upgrade");
    match fs::symlink_metadata(&stage) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e.into()),
        Ok(m) if !m.file_type().is_dir() => {
            return Err(fail("upgrade staging path is not a directory"))
        }
        Ok(_) => {}
    }
    eprintln!("upgrade-data: recovering journal for {}", path.display());
    if regular(&stage.join("ready"))? {
        let intent: Intent = serde_json::from_slice(&fs::read(stage.join("ready"))?)?;
        // Retain the legacy writer lock across recovery's renames too.
        let original_legacy = regular(path)? && classify(path)? == FileFormat::LegacyV2;
        let source_path = if original_legacy {
            path.to_owned()
        } else {
            sibling(path, ".redb2-backup")
        };
        let source_lock = if regular(&source_path)? {
            Some(redb_legacy::backends::FileBackend::new(File::open(
                &source_path,
            )?)?)
        } else {
            None
        };
        finish_swap(path, &stage, &intent, original_legacy, options)?;
        drop(source_lock);
    } else {
        if !regular(path)? || regular(&sibling(path, ".redb2-backup"))? {
            return Err(fail(
                "unjournaled upgrade is missing its original or has a conflicting backup",
            ));
        }
        fs::remove_dir_all(stage)?;
        sync_directory(
            path.parent()
                .ok_or_else(|| fail("database needs a parent"))?,
        )?;
    }
    Ok(true)
}

// A space-limited automatic attempt may have already retained the stale index.
// Explicit discard must reclaim that copy on retry, before the state space
// check. Current databases must open read-only before their rollback file is
// removed. A missing non-stale original is never permission to delete its only
// surviving copy. Hold the legacy writer lock until deletion completes.
fn discard_existing_backup(path: &Path, indexer: bool) -> Result<bool> {
    let backup = sibling(path, ".redb2-backup");
    if !regular(&backup)? {
        return Ok(false);
    }
    if classify(&backup)? != FileFormat::LegacyV2 {
        return Err(fail(format!(
            "rollback artifact is not legacy v2; retain {}",
            backup.display()
        )));
    }
    let current_reader;
    let backup_lock;
    if regular(path)? {
        if classify(path)? != FileFormat::Current {
            return Ok(false);
        }
        current_reader = Some(
            redb::Database::builder()
                .set_cache_size(8 * 1024 * 1024)
                .open_read_only(path)
                .map_err(|e| {
                    fail(format!(
                        "cannot discard rollback backup until {} opens read-only: {e}",
                        path.display()
                    ))
                })?,
        );
        backup_lock = Arc::new(redb_legacy::backends::FileBackend::new(File::open(
            &backup,
        )?)?);
    } else if indexer {
        let (schema, lock) = legacy_indexer_schema(&backup)?;
        if schema >= ergo_indexer::store::INDEXER_SCHEMA_VERSION {
            return Err(fail(format!(
                "current-schema indexer is missing; retain its only copy at {}",
                backup.display()
            )));
        }
        current_reader = None;
        backup_lock = lock;
    } else {
        return Err(fail(format!(
            "database {} is missing; retain its only copy at {}",
            path.display(),
            backup.display()
        )));
    }
    let bytes = fs::metadata(&backup)?.len();
    fs::remove_file(&backup)?;
    sync_directory(
        path.parent()
            .ok_or_else(|| fail("database needs a parent"))?,
    )?;
    drop(backup_lock);
    drop(current_reader);
    eprintln!(
        "upgrade-data: discarded retained legacy backup {} ({bytes} bytes)",
        backup.display()
    );
    Ok(true)
}

fn log_warning(message: &str) {
    if tracing::enabled!(tracing::Level::WARN) {
        tracing::warn!("{message}");
    } else {
        eprintln!("WARN upgrade-data: {message}");
    }
}

fn warn_backup(path: &Path, warning: &mut dyn FnMut(&str)) -> Result<()> {
    let bytes = fs::metadata(path)?.len();
    warning(&format!("retained legacy backup {} ({bytes} bytes): this is a plain file the node never opens; deleting it is safe while the node runs once you are satisfied with the upgrade. Alternatively, stop the node and run ergo-node upgrade-data DATA_DIR --indexer-db INDEXER_DB --discard-backups", path.display()));
    Ok(())
}

fn warn_retained_backups(
    directory: &Path,
    indexer_filename: &Path,
    warning: &mut dyn FnMut(&str),
) -> Result<()> {
    fn visit(directory: &Path, warning: &mut dyn FnMut(&str)) -> Result<()> {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            if kind.is_dir() {
                visit(&entry.path(), warning)?;
            } else if kind.is_file()
                && entry
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".redb2-backup")
            {
                warn_backup(&entry.path(), warning)?;
            }
        }
        Ok(())
    }
    visit(directory, warning)?;
    let indexer = directory.join(indexer_filename);
    let backup = sibling(&indexer, ".redb2-backup");
    if regular(&backup)? && !fs::canonicalize(&backup)?.starts_with(fs::canonicalize(directory)?) {
        warn_backup(&backup, warning)?;
    }
    Ok(())
}

fn check_space(path: &Path, size: u64, options: &mut UpgradeOptions<'_>) -> Result<()> {
    let needed = required_space(size);
    let available = (options.free_space)(path)?;
    if available < needed {
        return Err(fail(format!("insufficient space for {}: need {needed} bytes, available {available} bytes; free space, use --discard-backups, or use ergo-node migrate-redb to another disk", path.display())));
    }
    Ok(())
}

/// Caller must retain this lock across subsequent database opens at startup.
pub fn upgrade_data(
    _lock: &DataDirectoryLock,
    directory: &Path,
    indexer_filename: &Path,
    options: &mut UpgradeOptions<'_>,
) -> Result<UpgradeReport> {
    _lock.check_directory(directory)?;
    let paths = database_paths(directory, indexer_filename)?;
    warn_retained_backups(directory, indexer_filename, options.warning)?;
    let mut report = UpgradeReport::default();
    let mut deleted_indexer = None;
    for (position, path) in paths.iter().enumerate() {
        if (options.cancelled)() {
            return Err(MigrationError::Interrupted.into());
        }
        let ready = sibling(path, ".redb-upgrade").join("ready");
        let pending = if position == 0 && regular(&ready)? {
            Some(serde_json::from_slice::<Intent>(&fs::read(ready)?)?)
        } else {
            None
        };
        if recover(path, options)? {
            report.recovered += 1;
            if let Some(intent) = pending.filter(|i| i.stale_indexer && i.discard_backup) {
                deleted_indexer = intent.stale_indexer_bytes.map(|size| (path.clone(), size));
            }
        }
        if options.discard_backups && discard_existing_backup(path, position == 0)? {
            report.discarded_existing_backups += 1;
        }
        if !regular(path)? || classify(path)? == FileFormat::Current {
            continue;
        }
        let size = fs::metadata(path)?.len();
        let start = Instant::now();
        let (stale, indexer_lock) = if position == 0 {
            let (schema, lock) = legacy_indexer_schema(path)?;
            (
                schema < ergo_indexer::store::INDEXER_SCHEMA_VERSION,
                Some(lock),
            )
        } else {
            (false, None)
        };
        let indexer_lock = if stale {
            indexer_lock
        } else {
            drop(indexer_lock);
            None
        };
        if !stale {
            check_space(path, size, options)?;
        } else if options.keep_stale_indexer {
            // Retaining the index frees no space. Reject a known state-space
            // shortage before moving the index or creating any upgrade journal.
            for other in &paths[1..] {
                if regular(other)? && classify(other)? == FileFormat::LegacyV2 {
                    check_space(other, fs::metadata(other)?.len(), options)?;
                }
            }
        }
        let backup = sibling(path, ".redb2-backup");
        if regular(&backup)? {
            return Err(fail(format!(
                "refusing to replace rollback backup: {}",
                backup.display()
            )));
        }
        let stage = sibling(path, ".redb-upgrade");
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&stage)?;
        let intent = Intent {
            stale_indexer: stale,
            discard_backup: options.discard_backups || (stale && !options.keep_stale_indexer),
            stale_indexer_bytes: stale.then_some(size),
        };
        let result = (|| -> Result<()> {
            sync_directory(
                path.parent()
                    .ok_or_else(|| fail("database needs a parent"))?,
            )?;
            (options.step)(UpgradeStep::StageCreated)?;
            if stale {
                write_intent(&stage, &intent)?;
                (options.step)(UpgradeStep::Ready)?;
                finish_swap(path, &stage, &intent, true, options)?;
                report.stale_indexers += 1;
                if intent.discard_backup {
                    deleted_indexer = Some((path.clone(), size));
                }
                (options.warning)("stale legacy indexer will be rebuilt from genesis; rolling back to 0.11 rebuilds this index too");
            } else {
                migrate_database_observed(path, &stage.join("copy.redb"), &mut |event| {
                    if (options.cancelled)() {
                        return Err(MigrationError::Interrupted);
                    }
                    (options.progress)(path, size, start.elapsed(), &event);
                    let step = match &event {
                        MigrationProgress::Copied => Some(UpgradeStep::Copied),
                        MigrationProgress::Verified { .. } => Some(UpgradeStep::Verified),
                        _ => None,
                    };
                    if let Some(step) = step {
                        (options.step)(step).map_err(|e| MigrationError::Io {
                            operation: "upgrade step",
                            source: io::Error::other(e.to_string()),
                        })?;
                    }
                    if let MigrationProgress::Published(_) = event {
                        (|| -> Result<()> {
                            (options.step)(UpgradeStep::CopyPublished)?;
                            write_intent(&stage, &intent)?;
                            (options.step)(UpgradeStep::Ready)?;
                            // The converter still owns the source lock. It also
                            // prevents a running 0.11 writer from racing this swap.
                            finish_swap(path, &stage, &intent, true, options)
                        })()
                        .map_err(|e| MigrationError::Io {
                            operation: "install verified upgrade",
                            source: io::Error::other(e.to_string()),
                        })?;
                    }
                    Ok(())
                })?;
                report.migrated += 1;
            }
            eprintln!(
                "upgrade-data: {} ({} bytes) {} in {:.1}s",
                path.display(),
                size,
                if stale {
                    if intent.discard_backup {
                        "stale indexer deleted"
                    } else {
                        "stale indexer retained"
                    }
                } else {
                    "upgrade complete"
                },
                start.elapsed().as_secs_f64()
            );
            Ok(())
        })();
        if result.is_err() && stage.exists() && !stage.join("ready").exists() {
            fs::remove_dir_all(&stage)?;
            sync_directory(
                path.parent()
                    .ok_or_else(|| fail("database needs a parent"))?,
            )?;
        }
        result?;
        drop(indexer_lock);
        if regular(&backup)? {
            warn_backup(&backup, options.warning)?;
        }
        if (options.cancelled)() {
            return Err(MigrationError::Interrupted.into());
        }
    }
    if options.indexer_enabled {
        if let Some((path, size)) = deleted_indexer {
            let parent = path
                .parent()
                .ok_or_else(|| fail("indexer needs a parent"))?;
            let available = (options.free_space)(parent)?;
            if available < size {
                (options.warning)(&format!("indexer rebuild at {} needs about {size} bytes (the deleted indexer's size), but only {available} bytes are free; remove retained state backups once satisfied with the upgrade, or free space before rebuilding", path.display()));
            }
        }
    }
    Ok(report)
}

/// Fail before any normal database open when automatic conversion is disabled.
pub fn require_current_data(
    _lock: &DataDirectoryLock,
    directory: &Path,
    indexer_filename: &Path,
) -> Result<()> {
    _lock.check_directory(directory)?;
    for path in database_paths(directory, indexer_filename)? {
        if sibling(&path, ".redb-upgrade").exists()
            || (regular(&path)? && classify(&path)? == FileFormat::LegacyV2)
        {
            return Err(fail(format!("legacy or unfinished database upgrade at {}; run ergo-node upgrade-data {} --indexer-db {} (automatic upgrade is disabled)", path.display(), directory.display(), indexer_filename.display())));
        }
    }
    Ok(())
}

/// A small header overlay lets the real legacy reader inspect a clean v2
/// database without writing its open/close recovery marker to disk. All page
/// writes/resizes are rejected and recovery is explicitly aborted. Reading an
/// unclean indexer fails safely: stop 0.11 cleanly or use the copy-only converter.
#[derive(Debug)]
struct LegacyProbe {
    source: Arc<redb_legacy::backends::FileBackend>,
    header: Mutex<Vec<u8>>,
}

impl StorageBackend for LegacyProbe {
    fn len(&self) -> io::Result<u64> {
        self.source.len()
    }
    fn read(&self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        let mut bytes = self.source.read(offset, len)?;
        let header = self
            .header
            .lock()
            .map_err(|_| io::Error::other("header lock poisoned"))?;
        if offset < header.len() as u64 {
            let count = len.min(header.len() - offset as usize);
            bytes[..count].copy_from_slice(&header[offset as usize..offset as usize + count]);
        }
        Ok(bytes)
    }
    fn write(&self, offset: u64, bytes: &[u8]) -> io::Result<()> {
        let mut header = self
            .header
            .lock()
            .map_err(|_| io::Error::other("header lock poisoned"))?;
        let end = offset
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| io::Error::other("header offset overflow"))?;
        if end > header.len() as u64 {
            return Err(io::Error::other("legacy probe refuses page writes"));
        }
        header[offset as usize..end as usize].copy_from_slice(bytes);
        Ok(())
    }
    fn set_len(&self, len: u64) -> io::Result<()> {
        if len == self.source.len()? {
            Ok(())
        } else {
            Err(io::Error::other("legacy probe refuses resize"))
        }
    }
    fn sync_data(&self, _: bool) -> io::Result<()> {
        Ok(())
    }
}

fn legacy_indexer_schema(path: &Path) -> Result<(u32, Arc<redb_legacy::backends::FileBackend>)> {
    let source = Arc::new(redb_legacy::backends::FileBackend::new(File::open(path)?)?);
    let header = Mutex::new(source.read(0, 4096.min(source.len()? as usize))?);
    let probe = LegacyProbe {
        source: source.clone(),
        header,
    };
    let schema = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<u32> {
        let db = redb_legacy::Database::builder().set_cache_size(8 * 1024 * 1024)
            .set_repair_callback(|session| session.abort()).create_with_backend(probe)
            .map_err(|e| fail(format!("cannot read legacy indexer {} without writing: {e}; shut down 0.11 cleanly or use migrate-redb to another disk", path.display())))?;
        let read = db.begin_read()?;
        let table = match read.open_table(redb_legacy::TableDefinition::<&str, &[u8]>::new("indexer_meta")) {
            Ok(table) => table,
            Err(redb_legacy::TableError::TableDoesNotExist(_)) => return Ok(0),
            Err(e) => return Err(e.into()),
        };
        let value = table.get("schema_version")?;
        match value {
            None => Ok(0),
            Some(value) => Ok(u32::from_be_bytes(value.value().try_into().map_err(|_| fail("invalid legacy indexer schema_version length"))?)),
        }
    })).map_err(|_| fail("malformed legacy indexer metadata"))??;
    Ok((schema, source))
}

/// Boot hook: runs after config load, before sentinel reads or database opens.
/// Returns the directory lock for the caller to retain throughout node lifetime.
pub async fn prepare_startup(config: &crate::config::NodeConfig) -> Result<Arc<DataDirectoryLock>> {
    let directory = config.data_dir.clone();
    let indexer = PathBuf::from(&config.indexer_config.db_filename);
    let automatic = config.auto_upgrade_legacy;
    let keep_stale_indexer = config.auto_upgrade_keep_stale_indexer;
    let indexer_enabled = config.indexer_config.enabled;
    crate::maintenance::run_cancellable(move |cancelled| {
        let lock = Arc::new(DataDirectoryLock::acquire(&directory)?);
        if automatic {
            let report = upgrade_with_logging(
                &lock,
                &directory,
                &indexer,
                false,
                keep_stale_indexer,
                indexer_enabled,
                &|| cancelled.load(std::sync::atomic::Ordering::Relaxed),
            )?;
            if report.is_noop() {
                tracing::info!("data-directory upgrade: no-op; no legacy databases");
            }
        } else {
            warn_retained_backups(&directory, &indexer, &mut log_warning)?;
            require_current_data(&lock, &directory, &indexer)?;
        }
        Ok(lock)
    })
    .await
}

/// Human-readable progress also works before CLI tracing is initialized.
pub fn upgrade_with_logging(
    lock: &DataDirectoryLock,
    directory: &Path,
    indexer_filename: &Path,
    discard_backups: bool,
    keep_stale_indexer: bool,
    indexer_enabled: bool,
    cancelled: &dyn Fn() -> bool,
) -> Result<UpgradeReport> {
    if discard_backups {
        eprintln!("upgrade-data: --discard-backups enabled; rolling back to 0.11 requires an external backup");
    }
    let mut last = None;
    upgrade_data(
        lock,
        directory,
        indexer_filename,
        &mut UpgradeOptions {
            discard_backups,
            keep_stale_indexer,
            indexer_enabled,
            warning: &mut log_warning,
            free_space: &available_space,
            cancelled,
            step: &mut |_| Ok(()),
            progress: &mut |path, size, elapsed, event| {
                let published = matches!(event, MigrationProgress::Published(_));
                if last.is_none_or(|time: Instant| time.elapsed() >= Duration::from_secs(5))
                    || published
                {
                    match event {
                    MigrationProgress::Published(MigrationReport { tables, rows, .. }) => eprintln!("upgrade-data: {} ({size} bytes), {:.1}s: verified {tables} tables, {rows} rows", path.display(), elapsed.as_secs_f64()),
                    _ => eprintln!("upgrade-data: {} ({size} bytes), {:.1}s: {event:?}", path.display(), elapsed.as_secs_f64()),
                }
                    last = Some(Instant::now());
                }
            },
        },
    )
}

#[cfg(test)]
mod tests;
