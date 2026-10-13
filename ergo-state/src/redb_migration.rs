//! Offline, copy-only migration of node databases from redb 2.6 to redb 4.
//!
//! [`migrate_database`] never opens the source as a database: it acquires the
//! legacy backend's nonblocking exclusive file lock, then reads raw bytes.
//! Recovery, file-format upgrade and integrity checks operate only on a private
//! temporary copy. Every supported table's typed key/value content is hashed
//! before upgrading and again after opening under redb 4. The verified copy is
//! published without replacing any existing destination; the source is retained.
//!
//! Stop the node and preserve a complete data-directory backup first. Migrate
//! each database into a separate directory, copy the encrypted wallet/config,
//! and switch directories only after every migration succeeds. See
//! `docs/operating.md` for recovery and rollback instructions. This migrates the
//! database file format, not the node's application schema. Unknown table types
//! and multimaps are rejected instead of guessing their serialization.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use blake2::{digest::consts::U32, Blake2b, Digest};
use redb::ReadableDatabase;
use redb_legacy::StorageBackend;

/// Successful verification of a migrated copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationReport {
    /// Number of tables whose schemas, row counts and contents were verified.
    pub tables: usize,
    /// Total number of verified key/value rows.
    pub rows: u64,
    /// Whether redb 2.6 upgraded the copy from file format v2 to v3.
    pub upgraded: bool,
}

/// Migration failures preserve the source and never overwrite the destination.
#[derive(Debug, thiserror::Error)]
pub enum MigrationError {
    #[error("database upgrade interrupted; original preserved")]
    Interrupted,
    #[error("source must be a regular file, not a symlink: {0}")]
    InvalidSource(PathBuf),
    #[error("database already opens under redb 4; no legacy migration is needed")]
    AlreadyCurrent,
    #[error("database metadata could not be decoded safely")]
    MalformedMetadata,
    #[error("destination already exists (including a symlink): {0}")]
    DestinationExists(PathBuf),
    #[error("migration {operation} failed: {source}")]
    Io {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("legacy database {operation} failed: {source}")]
    Legacy {
        operation: &'static str,
        #[source]
        source: Box<redb_legacy::Error>,
    },
    #[error("migrated database {operation} failed: {source}")]
    Current {
        operation: &'static str,
        #[source]
        source: Box<redb::Error>,
    },
    #[error("unsupported table schema or multimap: {0}")]
    UnsupportedSchema(String),
    #[error("database integrity or content verification failed: {0}")]
    Verification(&'static str),
}

/// Streaming progress and cancellation points for directory upgrades.
#[derive(Debug, Clone)]
pub enum MigrationProgress {
    Copy {
        bytes: u64,
        total: u64,
    },
    Copied,
    Verify {
        reader: &'static str,
        table: String,
        rows: u64,
    },
    SourceCheck {
        bytes: u64,
        total: u64,
    },
    Verified {
        tables: usize,
        rows: u64,
    },
    /// The verified destination is durable; the source lock is still held.
    Published(MigrationReport),
}

type Observer<'a> = dyn FnMut(MigrationProgress) -> Result<(), MigrationError> + 'a;

fn io_error(operation: &'static str, source: io::Error) -> MigrationError {
    MigrationError::Io { operation, source }
}

fn legacy_error(operation: &'static str, source: impl Into<redb_legacy::Error>) -> MigrationError {
    MigrationError::Legacy {
        operation,
        source: Box::new(source.into()),
    }
}

fn current_error(operation: &'static str, source: impl Into<redb::Error>) -> MigrationError {
    MigrationError::Current {
        operation,
        source: Box::new(source.into()),
    }
}

#[derive(Debug, PartialEq, Eq)]
struct TableFingerprint {
    schema: &'static str,
    rows: u64,
    contents: [u8; 32],
}

type Inventory = BTreeMap<String, TableFingerprint>;

// These are the actual key/value families in state, digest, indexer, peer and
// wallet tables. In particular, the indexer's tuple is fixed-width: no redb 3
// `Legacy` variable-width tuple conversion is necessary. Both versions must
// accept the same typed definition and return the same encoded row contents.
macro_rules! supported_schemas {
    ($check:ident) => {
        $check!(u64, &[u8]);
        $check!(&[u8], &[u8]);
        $check!(&str, &[u8]);
        $check!(&[u8], u8);
        $check!(&[u8], u32);
        $check!(&str, u64);
        $check!((u32, i64), &[u8]);
        $check!((), u32);
        $check!((), [u8; 32]);
        $check!([u8; 32], Vec<u8>);
        $check!([u8; 32], u64);
        $check!([u8; 34], [u8; 32]);
        $check!([u8; 36], Vec<u8>);
        $check!((), u64);
        $check!([u8; 41], Vec<u8>);
        $check!(u32, [u8; 33]);
        $check!((), [u8; 33]);
        $check!(u16, Vec<u8>);
        $check!((), u16);
        $check!([u8; 34], Vec<u8>);
        $check!((), bool);
        $check!((), Vec<u8>);
    };
}

// Sharing the enumeration keeps the cross-version verification symmetric.
// Iteration and Value::as_bytes are supplied by each real dependency version.
macro_rules! inventory_reader {
    ($name:ident, $version:ident, $error:ident) => {
        fn $name(
            db: &$version::Database,
            observer: &mut Observer<'_>,
        ) -> Result<Inventory, MigrationError> {
            use $version::{ReadableTable, TableHandle};
            let read = db
                .begin_read()
                .map_err(|e| $error("begin verification read", e))?;
            if let Some(table) = read
                .list_multimap_tables()
                .map_err(|e| $error("list multimaps", e))?
                .next()
            {
                use $version::MultimapTableHandle;
                return Err(MigrationError::UnsupportedSchema(table.name().to_owned()));
            }
            let mut result = BTreeMap::new();
            for handle in read.list_tables().map_err(|e| $error("list tables", e))? {
                let name = handle.name();
                let mut fingerprint = None;
                macro_rules! check {
                    ($key:ty, $value:ty) => {
                        if fingerprint.is_none() {
                            match read
                                .open_table($version::TableDefinition::<$key, $value>::new(name))
                            {
                                Ok(table) => {
                                    let mut hash = Blake2b::<U32>::new();
                                    let mut rows = 0u64;
                                    for row in
                                        table.iter().map_err(|e| $error("iterate table", e))?
                                    {
                                        let (key, value) =
                                            row.map_err(|e| $error("read table row", e))?;
                                        let key_value = key.value();
                                        let value_value = value.value();
                                        let key = <$key as $version::Value>::as_bytes(&key_value);
                                        let value =
                                            <$value as $version::Value>::as_bytes(&value_value);
                                        let key_bytes: &[u8] = key.as_ref();
                                        let value_bytes: &[u8] = value.as_ref();
                                        for bytes in [key_bytes, value_bytes] {
                                            hash.update((bytes.len() as u64).to_le_bytes());
                                            hash.update(bytes);
                                        }
                                        rows += 1;
                                        if rows.is_multiple_of(4096) {
                                            observer(MigrationProgress::Verify {
                                                reader: stringify!($version),
                                                table: name.to_owned(),
                                                rows,
                                            })?;
                                        }
                                    }
                                    fingerprint = Some(TableFingerprint {
                                        schema: concat!(
                                            stringify!($key),
                                            " -> ",
                                            stringify!($value)
                                        ),
                                        rows,
                                        contents: hash.finalize().into(),
                                    });
                                }
                                Err($version::TableError::TableTypeMismatch { .. }) => {}
                                Err(error) => return Err($error("open typed table", error)),
                            }
                        }
                    };
                }
                supported_schemas!(check);
                let fingerprint = fingerprint
                    .ok_or_else(|| MigrationError::UnsupportedSchema(name.to_owned()))?;
                observer(MigrationProgress::Verify {
                    reader: stringify!($version),
                    table: name.to_owned(),
                    rows: fingerprint.rows,
                })?;
                result.insert(name.to_owned(), fingerprint);
            }
            Ok(result)
        }
    };
}

inventory_reader!(legacy_inventory, redb_legacy, legacy_error);
inventory_reader!(current_inventory, redb, current_error);

fn source_hash(
    source: &impl StorageBackend,
    observer: &mut Observer<'_>,
) -> Result<[u8; 32], MigrationError> {
    let len = source
        .len()
        .map_err(|e| io_error("read source length", e))?;
    let mut hash = Blake2b::<U32>::new();
    let mut offset = 0;
    while offset < len {
        let bytes = source
            .read(offset, (len - offset).min(1024 * 1024) as usize)
            .map_err(|e| io_error("read source", e))?;
        offset += bytes.len() as u64;
        hash.update(bytes);
        observer(MigrationProgress::SourceCheck {
            bytes: offset,
            total: len,
        })?;
    }
    Ok(hash.finalize().into())
}

/// Upgrade and verify a new copy of a stopped node's redb database.
///
/// `source` must be a regular file. Its exclusive writer lock is held throughout
/// copying and verification; a live/open database is rejected without waiting.
/// `destination` must not exist and its parent must already exist. All recovery
/// and upgrade writes are confined to a temporary copy in that parent. Before
/// publishing, both database versions verify integrity and every supported
/// table's schema, row count and key/value contents agree. On Unix the destination
/// file and parent directory are synced; Windows syncs the file and uses a
/// no-replace publish, matching the wallet's documented directory-sync limit.
///
/// A failure before publication removes the temporary copy. A parent-sync error
/// or Windows permission-restoration error after publication returns an error
/// with the verified destination retained;
/// the original source is still untouched. Process termination can leave a
/// `.ergo-redb-migrate-*` temporary copy, which is never used by normal startup.
/// Do not delete originals until the complete migrated node has been validated.
/// Unknown application schemas and variable-width tuples require a separate
/// schema-aware migration rather than this file-format converter.
pub fn migrate_database(
    source: &Path,
    destination: &Path,
) -> Result<MigrationReport, MigrationError> {
    migrate_database_observed(source, destination, &mut |_| Ok(()))
}

/// Run the same verified migration with streaming progress and cancellation.
/// Returning an error before publication removes the private temporary copy.
/// `Published` runs under the source lock, allowing a directory upgrader to
/// journal and swap the verified copy without a writer racing the renames.
pub fn migrate_database_observed(
    source: &Path,
    destination: &Path,
    observer: &mut Observer<'_>,
) -> Result<MigrationReport, MigrationError> {
    migrate_impl(source, destination, observer, |_| Ok(()))
}

#[cfg(test)]
fn migrate_with_hook(
    source: &Path,
    destination: &Path,
    before_publish: impl FnOnce(&Path) -> io::Result<()>,
) -> Result<MigrationReport, MigrationError> {
    migrate_impl(source, destination, &mut |_| Ok(()), before_publish)
}

fn migrate_impl(
    source: &Path,
    destination: &Path,
    observer: &mut Observer<'_>,
    before_publish: impl FnOnce(&Path) -> io::Result<()>,
) -> Result<MigrationReport, MigrationError> {
    let metadata = fs::symlink_metadata(source).map_err(|e| io_error("inspect source", e))?;
    if !metadata.file_type().is_file() {
        return Err(MigrationError::InvalidSource(source.to_owned()));
    }
    match fs::symlink_metadata(destination) {
        Ok(_) => return Err(MigrationError::DestinationExists(destination.to_owned())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(io_error("inspect destination", e)),
    }
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let file = File::open(source).map_err(|e| io_error("open source read-only", e))?;
    let metadata = file
        .metadata()
        .map_err(|e| io_error("inspect opened source", e))?;
    if !metadata.is_file() {
        return Err(MigrationError::InvalidSource(source.to_owned()));
    }
    // This locks without constructing a Database or writing recovery markers.
    // Use the legacy backend's lock to match the live v2 writer on Unix/Windows.
    let source = redb_legacy::backends::FileBackend::new(file)
        .map_err(|e| legacy_error("lock source; stop the node before migration", e))?;
    let mut copy = tempfile::Builder::new()
        .prefix(".ergo-redb-migrate-")
        .tempfile_in(parent)
        .map_err(|e| io_error("create temporary copy", e))?;
    let len = source
        .len()
        .map_err(|e| io_error("read source length", e))?;
    let mut hash = Blake2b::<U32>::new();
    let mut offset = 0;
    while offset < len {
        observer(MigrationProgress::Copy {
            bytes: offset,
            total: len,
        })?;
        let bytes = source
            .read(offset, (len - offset).min(1024 * 1024) as usize)
            .map_err(|e| io_error("copy source", e))?;
        offset += bytes.len() as u64;
        hash.update(&bytes);
        copy.write_all(&bytes)
            .map_err(|e| io_error("write copy", e))?;
    }
    copy.as_file()
        .sync_all()
        .map_err(|e| io_error("sync copy", e))?;
    observer(MigrationProgress::Copied)?;
    let original_hash: [u8; 32] = hash.finalize().into();
    // Classify with the current reader first: legacy redb cannot decode new
    // composite type tags in an already-current v3 file. Only actual v2 inputs
    // go through the legacy upgrade. All opens and recovery touch the copy.
    let (expected, upgraded) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        match redb::Database::builder()
            .set_cache_size(8 * 1024 * 1024)
            .open(copy.path())
        {
            Err(redb::DatabaseError::UpgradeRequired(2)) => {}
            Ok(_) => return Err(MigrationError::AlreadyCurrent),
            Err(error) => return Err(current_error("inspect copied file format", error)),
        }
        let (expected, upgraded) = {
            let mut db = redb_legacy::Database::builder()
                .set_cache_size(8 * 1024 * 1024)
                .open(copy.path())
                .map_err(|e| legacy_error("open copy", e))?;
            if !db
                .check_integrity()
                .map_err(|e| legacy_error("check legacy copy", e))?
            {
                return Err(MigrationError::Verification(
                    "legacy integrity check required repair",
                ));
            }
            let expected = legacy_inventory(&db, observer)?;
            let upgraded = db.upgrade().map_err(|e| legacy_error("upgrade copy", e))?;
            (expected, upgraded)
        };
        {
            let mut db = redb::Database::builder()
                .set_cache_size(8 * 1024 * 1024)
                .open(copy.path())
                .map_err(|e| current_error("reopen upgraded copy", e))?;
            if !db
                .check_integrity()
                .map_err(|e| current_error("check upgraded copy", e))?
            {
                return Err(MigrationError::Verification(
                    "upgraded integrity check required repair",
                ));
            }
            if current_inventory(&db, observer)? != expected {
                return Err(MigrationError::Verification(
                    "table schemas, counts or contents changed",
                ));
            }
        }
        Ok((expected, upgraded))
    }))
    .map_err(|_| MigrationError::MalformedMetadata)??;
    if source_hash(&source, observer)? != original_hash {
        return Err(MigrationError::Verification("source changed while locked"));
    }
    fs::set_permissions(copy.path(), metadata.permissions().clone())
        .map_err(|e| io_error("preserve permissions", e))?;
    copy.as_file()
        .sync_all()
        .map_err(|e| io_error("sync verified copy", e))?;
    observer(MigrationProgress::Verified {
        tables: expected.len(),
        rows: expected.values().map(|table| table.rows).sum(),
    })?;
    before_publish(copy.path()).map_err(|e| io_error("prepare publication", e))?;
    let _published = copy
        .persist_noclobber(destination)
        .map_err(|e| io_error("publish destination without replacement", e.error))?;
    // tempfile's Windows publish clears FILE_ATTRIBUTE_READONLY. Restore it
    // after publication; a failure retains the verified destination.
    #[cfg(windows)]
    fs::set_permissions(destination, metadata.permissions()).map_err(|e| {
        io_error(
            "restore destination permissions (verified copy is retained)",
            e,
        )
    })?;
    #[cfg(unix)]
    File::open(parent)
        .and_then(|dir| dir.sync_all())
        .map_err(|e| io_error("sync destination directory (verified copy is retained)", e))?;
    let report = MigrationReport {
        tables: expected.len(),
        rows: expected.values().map(|table| table.rows).sum(),
        upgraded,
    };
    observer(MigrationProgress::Published(report.clone()))?;
    Ok(report)
}

#[cfg(test)]
mod tests;
