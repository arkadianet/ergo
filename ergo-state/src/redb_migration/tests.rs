#![cfg(test)]

use super::*;

// The fixture is written by real redb 2.6.3, whose default format is v2.
// Values deliberately cover all node key/value families, including the fixed
// width indexer tuple and the wallet's arrays, Vecs and unit keys.
macro_rules! fixture_rows {
    ($row:ident) => {
        $row!("avl_nodes", u64, &[u8], 17, b"AVL node".as_slice());
        $row!(
            "headers",
            &[u8],
            &[u8],
            b"header id".as_slice(),
            b"header".as_slice()
        );
        $row!(
            "state_meta",
            &str,
            &[u8],
            "height",
            23u32.to_le_bytes().as_slice()
        );
        $row!("modifier_type_index", &[u8], u8, b"section".as_slice(), 102);
        $row!(
            "section_height_index",
            &[u8],
            u32,
            b"section".as_slice(),
            23
        );
        $row!("meta", &str, u64, "schema_version", 1);
        $row!(
            "unspent_by_creation_height",
            (u32, i64),
            &[u8],
            (23, -7),
            b"box".as_slice()
        );
        $row!("wallet_scan_height", (), u32, (), 23);
        $row!("wallet_scan_header_id", (), [u8; 32], (), [1; 32]);
        $row!("wallet_boxes", [u8; 32], Vec<u8>, [2; 32], vec![3, 4]);
        $row!("wallet_boxes_by_tx", [u8; 34], [u8; 32], [5; 34], [2; 32]);
        $row!("wallet_txs", [u8; 36], Vec<u8>, [6; 36], vec![7, 8]);
        $row!("wallet_derivation_head", (), u64, (), 9);
        $row!(
            "wallet_tracked_pubkeys",
            [u8; 41],
            Vec<u8>,
            [10; 41],
            vec![11, 12]
        );
        $row!("wallet_visible_addresses", u32, [u8; 33], 13, [14; 33]);
        $row!("wallet_change_address", (), [u8; 33], (), [14; 33]);
        $row!("wallet_scans", u16, Vec<u8>, 15, vec![16, 17]);
        $row!("wallet_last_used_scan_id", (), u16, (), 15);
        $row!(
            "wallet_scan_boxes",
            [u8; 34],
            Vec<u8>,
            [18; 34],
            vec![19, 20]
        );
        $row!("wallet_scan_invalidated", (), bool, (), true);
        $row!("wallet_rescan_state", (), Vec<u8>, (), vec![21, 22]);
    };
}

fn fixture(path: &Path) {
    let db = redb_legacy::Database::builder()
        .set_cache_size(1024 * 1024)
        .create(path)
        .unwrap();
    let txn = db.begin_write().unwrap();
    macro_rules! insert {
        ($name:literal, $key:ty, $value:ty, $k:expr, $v:expr) => {
            txn.open_table(redb_legacy::TableDefinition::<$key, $value>::new($name))
                .unwrap()
                .insert($k, $v)
                .unwrap();
        };
    }
    fixture_rows!(insert);
    txn.commit().unwrap();
}

fn assert_source_and_cleanup(dir: &Path, source: &Path, bytes: &[u8]) {
    assert!(
        fs::read(source).unwrap() == bytes,
        "source must be byte-for-byte unchanged"
    );
    assert!(
        !fs::read_dir(dir).unwrap().any(|entry| entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".ergo-redb-migrate-")),
        "failed migration must clean temporary copies"
    );
}

#[test]
fn actual_v2_tables_upgrade_and_reopen_with_identical_typed_values() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.redb");
    let destination = dir.path().join("destination.redb");
    fixture(&source);
    let bytes = fs::read(&source).unwrap();
    assert!(matches!(
        redb::Database::open(&source),
        Err(redb::DatabaseError::UpgradeRequired(2))
    ));
    let report = migrate_database(&source, &destination).unwrap();
    assert_eq!(
        report,
        MigrationReport {
            tables: 21,
            rows: 21,
            upgraded: true
        }
    );
    let db = redb::Database::open(&destination).unwrap();
    let txn = db.begin_read().unwrap();
    macro_rules! check {
        ($name:literal, $key:ty, $value:ty, $k:expr, $v:expr) => {
            assert_eq!(
                txn.open_table(redb::TableDefinition::<$key, $value>::new($name))
                    .unwrap()
                    .get($k)
                    .unwrap()
                    .unwrap()
                    .value(),
                $v
            );
        };
    }
    fixture_rows!(check);
    assert_source_and_cleanup(dir.path(), &source, &bytes);
    assert!(matches!(
        migrate_database(&source, &destination),
        Err(MigrationError::DestinationExists(_))
    ));
}

#[test]
fn live_legacy_and_current_writers_are_rejected_without_waiting_or_mutating() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.redb");
    let destination = dir.path().join("destination.redb");
    fixture(&source);
    let live = redb_legacy::Database::open(&source).unwrap();
    let expected = legacy_inventory(&live).unwrap();
    assert!(matches!(
        migrate_database(&source, &destination),
        Err(MigrationError::Legacy { .. })
    ));
    assert!(!destination.exists());
    assert_eq!(legacy_inventory(&live).unwrap(), expected);
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    drop(live);
    migrate_database(&source, &destination).unwrap();
    let live = redb::Database::open(&destination).unwrap();
    let expected = current_inventory(&live).unwrap();
    assert!(migrate_database(&destination, &dir.path().join("another.redb")).is_err());
    assert_eq!(current_inventory(&live).unwrap(), expected);
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
}

#[test]
fn malformed_source_and_persistent_savepoints_fail_without_writing_original() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.redb");
    let destination = dir.path().join("destination.redb");
    for bytes in [b"not redb".as_slice(), &[0u8; 4096]] {
        fs::write(&source, bytes).unwrap();
        assert!(migrate_database(&source, &destination).is_err());
        assert!(!destination.exists());
        assert_source_and_cleanup(dir.path(), &source, bytes);
    }
    fs::remove_file(&source).unwrap();
    fixture(&source);
    {
        let db = redb_legacy::Database::open(&source).unwrap();
        let txn = db.begin_write().unwrap();
        txn.persistent_savepoint().unwrap();
        txn.commit().unwrap();
    }
    let bytes = fs::read(&source).unwrap();
    assert!(matches!(
        migrate_database(&source, &destination),
        Err(MigrationError::Legacy {
            operation: "upgrade copy",
            ..
        })
    ));
    assert!(!destination.exists());
    assert_source_and_cleanup(dir.path(), &source, &bytes);
}

#[test]
fn unsupported_variable_width_tuple_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.redb");
    {
        let db = redb_legacy::Database::create(&source).unwrap();
        let txn = db.begin_write().unwrap();
        txn.open_table(redb_legacy::TableDefinition::<(&str, &str), u32>::new(
            "foreign_table",
        ))
        .unwrap()
        .insert(("a", "b"), 1)
        .unwrap();
        txn.commit().unwrap();
    }
    let bytes = fs::read(&source).unwrap();
    let destination = dir.path().join("destination.redb");
    assert!(
        matches!(migrate_database(&source, &destination), Err(MigrationError::UnsupportedSchema(name)) if name == "foreign_table")
    );
    assert_source_and_cleanup(dir.path(), &source, &bytes);
    assert!(!destination.exists());
}

#[test]
fn publication_failure_cleans_copy_and_can_retry_without_clobbering() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.redb");
    let destination = dir.path().join("destination.redb");
    fixture(&source);
    let bytes = fs::read(&source).unwrap();
    assert!(
        migrate_with_hook(&source, &destination, |_| Err(io::Error::other(
            "injected failure"
        )))
        .is_err()
    );
    assert_source_and_cleanup(dir.path(), &source, &bytes);
    assert!(!destination.exists());
    // Another creator wins the race after our preliminary existence check.
    assert!(migrate_with_hook(&source, &destination, |_| fs::write(
        &destination,
        b"do not replace"
    ))
    .is_err());
    assert_eq!(fs::read(&destination).unwrap(), b"do not replace");
    assert_source_and_cleanup(dir.path(), &source, &bytes);
    fs::remove_file(&destination).unwrap();
    migrate_database(&source, &destination).unwrap();
    assert_source_and_cleanup(dir.path(), &source, &bytes);
}

#[test]
fn non_files_and_existing_destinations_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.redb");
    let destination = dir.path().join("destination.redb");
    assert!(matches!(
        migrate_database(dir.path(), &destination),
        Err(MigrationError::InvalidSource(_))
    ));
    fixture(&source);
    let bytes = fs::read(&source).unwrap();
    fs::write(&destination, b"original destination").unwrap();
    assert!(matches!(
        migrate_database(&source, &destination),
        Err(MigrationError::DestinationExists(_))
    ));
    assert_eq!(fs::read(&destination).unwrap(), b"original destination");
    assert_source_and_cleanup(dir.path(), &source, &bytes);
}

#[cfg(unix)]
#[test]
fn symlinks_are_rejected_including_dangling_destinations() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.redb");
    let destination = dir.path().join("destination.redb");
    fixture(&source);
    let bytes = fs::read(&source).unwrap();
    let link = dir.path().join("link.redb");
    symlink(&source, &link).unwrap();
    assert!(matches!(
        migrate_database(&link, &destination),
        Err(MigrationError::InvalidSource(_))
    ));
    symlink("missing", &destination).unwrap();
    assert!(matches!(
        migrate_database(&source, &destination),
        Err(MigrationError::DestinationExists(_))
    ));
    assert_source_and_cleanup(dir.path(), &source, &bytes);
}

#[cfg(windows)]
#[test]
fn readonly_source_remains_readonly_and_destination_preserves_attribute() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.redb");
    let destination = dir.path().join("destination.redb");
    fixture(&source);
    let mut permissions = fs::metadata(&source).unwrap().permissions();
    permissions.set_readonly(true);
    fs::set_permissions(&source, permissions).unwrap();
    let bytes = fs::read(&source).unwrap();
    migrate_database(&source, &destination).unwrap();
    assert_source_and_cleanup(dir.path(), &source, &bytes);
    assert!(fs::metadata(&source).unwrap().permissions().readonly());
    assert!(fs::metadata(&destination).unwrap().permissions().readonly());
    // Allow TempDir to clean the two readonly files on Windows.
    for path in [&source, &destination] {
        let mut permissions = fs::metadata(path).unwrap().permissions();
        permissions.set_readonly(false);
        fs::set_permissions(path, permissions).unwrap();
    }
}

#[test]
fn current_wallet_composite_metadata_is_rejected_without_dependency_panic() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.redb");
    {
        let db = redb::Database::create(&source).unwrap();
        let txn = db.begin_write().unwrap();
        txn.open_table(redb::TableDefinition::<[u8; 32], Vec<u8>>::new(
            "wallet_boxes",
        ))
        .unwrap()
        .insert([1; 32], vec![2, 3])
        .unwrap();
        txn.commit().unwrap();
    }
    let bytes = fs::read(&source).unwrap();
    let destination = dir.path().join("destination.redb");
    assert!(matches!(
        migrate_database(&source, &destination),
        Err(MigrationError::AlreadyCurrent)
    ));
    assert!(!destination.exists());
    assert_source_and_cleanup(dir.path(), &source, &bytes);
}

#[test]
fn unsupported_multimap_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.redb");
    {
        let db = redb_legacy::Database::create(&source).unwrap();
        let txn = db.begin_write().unwrap();
        txn.open_multimap_table(redb_legacy::MultimapTableDefinition::<u64, u64>::new(
            "foreign_multimap",
        ))
        .unwrap()
        .insert(1, 2)
        .unwrap();
        txn.commit().unwrap();
    }
    let bytes = fs::read(&source).unwrap();
    let destination = dir.path().join("destination.redb");
    assert!(
        matches!(migrate_database(&source, &destination), Err(MigrationError::UnsupportedSchema(name)) if name == "foreign_multimap")
    );
    assert!(!destination.exists());
    assert_source_and_cleanup(dir.path(), &source, &bytes);
}

#[test]
fn unclean_legacy_fixture_worker() {
    let Some(path) = std::env::var_os("ERGO_REDB_MIGRATION_UNCLEAN_FIXTURE") else {
        return;
    };
    let db = redb_legacy::Database::create(Path::new(&path)).unwrap();
    let txn = db.begin_write().unwrap();
    txn.open_table(redb_legacy::TableDefinition::<&str, u64>::new("meta"))
        .unwrap()
        .insert("committed_before_crash", 47)
        .unwrap();
    txn.commit().unwrap();
    // Skip Database::drop just as a process crash does. The parent waits for
    // process termination before locking this genuine legacy fixture.
    std::process::exit(0);
}

#[test]
fn unclean_v2_recovery_is_confined_to_the_copy() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("unclean.redb");
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "redb_migration::tests::unclean_legacy_fixture_worker",
        ])
        .env("ERGO_REDB_MIGRATION_UNCLEAN_FIXTURE", &source)
        .status()
        .unwrap();
    assert!(status.success());
    let bytes = fs::read(&source).unwrap();
    let destination = dir.path().join("migrated.redb");
    migrate_database(&source, &destination).unwrap();
    let db = redb::Database::open(&destination).unwrap();
    assert_eq!(
        db.begin_read()
            .unwrap()
            .open_table(redb::TableDefinition::<&str, u64>::new("meta"))
            .unwrap()
            .get("committed_before_crash")
            .unwrap()
            .unwrap()
            .value(),
        47
    );
    assert_source_and_cleanup(dir.path(), &source, &bytes);
}

#[test]
fn held_raw_writer_lock_preserves_exact_source_bytes_on_rejection() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("legacy.redb");
    fixture(&path);
    let bytes = fs::read(&path).unwrap();
    let backend = redb_legacy::backends::FileBackend::new(File::open(&path).unwrap()).unwrap();
    assert!(migrate_database(&path, &dir.path().join("copy.redb")).is_err());
    // Use the lock-owning handle; Windows rejects reads through a second one.
    assert!(backend.read(0, bytes.len()).unwrap() == bytes);
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn unsupported_v1_header_is_rejected_without_modifying_source() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.redb");
    fixture(&source);
    let mut bytes = fs::read(&source).unwrap();
    // Both real legacy commit slots start with a format version; the current
    // reader returns UpgradeRequired(1) before checking their checksums.
    bytes[64] = 1;
    bytes[192] = 1;
    fs::write(&source, &bytes).unwrap();
    let destination = dir.path().join("destination.redb");
    assert!(matches!(
        migrate_database(&source, &destination),
        Err(MigrationError::Current { .. })
    ));
    assert!(!destination.exists());
    assert_source_and_cleanup(dir.path(), &source, &bytes);
}
