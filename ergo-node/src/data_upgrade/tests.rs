use super::*;
use redb::{ReadableDatabase, TableDefinition};
use std::cell::Cell;

fn legacy(path: &Path) -> Vec<u8> {
    let db = redb_legacy::Database::builder()
        .set_cache_size(1024 * 1024)
        .create(path)
        .unwrap();
    let write = db.begin_write().unwrap();
    write
        .open_table(redb_legacy::TableDefinition::<&str, &[u8]>::new("rows"))
        .unwrap()
        .insert("preserved", b"original data".as_slice())
        .unwrap();
    write
        .open_table(redb_legacy::TableDefinition::<[u8; 32], Vec<u8>>::new(
            "wallet_boxes",
        ))
        .unwrap()
        .insert([7; 32], vec![1, 2, 3])
        .unwrap();
    write.commit().unwrap();
    drop(db);
    fs::read(path).unwrap()
}

fn indexer(path: &Path, schema: u32) -> Vec<u8> {
    legacy(path);
    let db = redb_legacy::Database::open(path).unwrap();
    let write = db.begin_write().unwrap();
    write
        .open_table(redb_legacy::TableDefinition::<&str, &[u8]>::new(
            "indexer_meta",
        ))
        .unwrap()
        .insert("schema_version", schema.to_be_bytes().as_slice())
        .unwrap();
    write.commit().unwrap();
    drop(db);
    fs::read(path).unwrap()
}

fn assert_current(path: &Path) {
    let db = redb::ReadOnlyDatabase::open(path).unwrap();
    let read = db.begin_read().unwrap();
    assert_eq!(
        read.open_table(TableDefinition::<&str, &[u8]>::new("rows"))
            .unwrap()
            .get("preserved")
            .unwrap()
            .unwrap()
            .value(),
        b"original data"
    );
    assert_eq!(
        read.open_table(TableDefinition::<[u8; 32], Vec<u8>>::new("wallet_boxes"))
            .unwrap()
            .get([7; 32])
            .unwrap()
            .unwrap()
            .value(),
        vec![1, 2, 3]
    );
}

fn run(lock: &DataDirectoryLock, dir: &Path, discard: bool) -> UpgradeReport {
    upgrade_data(
        lock,
        dir,
        Path::new("custom-index.redb"),
        &mut UpgradeOptions {
            discard_backups: discard,
            free_space: &|_| Ok(u64::MAX),
            cancelled: &|| false,
            progress: &mut |_, _, _, _| {},
            step: &mut |_| Ok(()),
        },
    )
    .unwrap()
}

#[test]
fn real_v2_directory_preserves_rows_wallet_and_backups_then_is_noop() {
    let dir = tempfile::tempdir().unwrap();
    let lock = DataDirectoryLock::acquire(dir.path()).unwrap();
    let mut originals = Vec::new();
    for name in ["state.redb", "peers.redb", "webhooks.redb"] {
        let path = dir.path().join(name);
        originals.push((path.clone(), legacy(&path)));
    }
    let idx = dir.path().join("custom-index.redb");
    let idx_bytes = indexer(&idx, 2);
    assert!(require_current_data(&lock, dir.path(), Path::new("custom-index.redb")).is_err());
    assert_eq!(
        run(&lock, dir.path(), false),
        UpgradeReport {
            migrated: 3,
            stale_indexers: 1,
            recovered: 0
        }
    );
    for (path, bytes) in originals {
        assert_current(&path);
        assert_eq!(fs::read(sibling(&path, ".redb2-backup")).unwrap(), bytes);
    }
    assert!(!idx.exists());
    assert_eq!(fs::read(sibling(&idx, ".redb2-backup")).unwrap(), idx_bytes);
    assert!(run(&lock, dir.path(), false).is_noop());
}

#[test]
fn current_schema_v2_indexer_is_migrated_and_probe_does_not_write() {
    let dir = tempfile::tempdir().unwrap();
    let lock = DataDirectoryLock::acquire(dir.path()).unwrap();
    let path = dir.path().join("custom-index.redb");
    let bytes = indexer(&path, ergo_indexer::store::INDEXER_SCHEMA_VERSION);
    let (schema, probe_lock) = legacy_indexer_schema(&path).unwrap();
    assert_eq!(schema, ergo_indexer::store::INDEXER_SCHEMA_VERSION);
    assert_eq!(fs::read(&path).unwrap(), bytes);
    drop(probe_lock);
    assert_eq!(run(&lock, dir.path(), false).migrated, 1);
    assert_current(&path);
    assert_eq!(fs::read(sibling(&path, ".redb2-backup")).unwrap(), bytes);
}

#[test]
fn every_swap_step_can_be_retried_without_losing_original_data() {
    for discard in [false, true] {
        for step in [
            UpgradeStep::StageCreated,
            UpgradeStep::Copied,
            UpgradeStep::Verified,
            UpgradeStep::CopyPublished,
            UpgradeStep::Ready,
            UpgradeStep::OriginalRenamed,
            UpgradeStep::Installed,
            UpgradeStep::BeforeDirectorySync,
            UpgradeStep::DirectorySynced,
            UpgradeStep::BackupDiscarded,
        ] {
            if step == UpgradeStep::BackupDiscarded && !discard {
                continue;
            }
            let dir = tempfile::tempdir().unwrap();
            let lock = DataDirectoryLock::acquire(dir.path()).unwrap();
            let path = dir.path().join("state.redb");
            let bytes = legacy(&path);
            let error = upgrade_data(
                &lock,
                dir.path(),
                Path::new("custom-index.redb"),
                &mut UpgradeOptions {
                    discard_backups: discard,
                    free_space: &|_| Ok(u64::MAX),
                    cancelled: &|| false,
                    progress: &mut |_, _, _, _| {},
                    step: &mut |at| {
                        if at == step {
                            Err(fail("injected crash"))
                        } else {
                            Ok(())
                        }
                    },
                },
            )
            .unwrap_err();
            assert!(
                error.to_string().contains("injected crash"),
                "{discard} {step:?}: {error}"
            );
            let backup = sibling(&path, ".redb2-backup");
            if backup.exists() {
                assert_eq!(fs::read(&backup).unwrap(), bytes);
            } else if !path.exists() {
                panic!("original data lost at {step:?}");
            } else if classify(&path).unwrap() == FileFormat::LegacyV2 {
                assert_eq!(fs::read(&path).unwrap(), bytes);
            } else {
                assert_current(&path);
            }
            run(&lock, dir.path(), discard);
            assert_current(&path);
            assert_eq!(backup.exists(), !discard);
            if !discard {
                assert_eq!(fs::read(backup).unwrap(), bytes);
            }
            assert!(!sibling(&path, ".redb-upgrade").exists());
            assert!(run(&lock, dir.path(), discard).is_noop());
        }
    }
}

#[test]
fn stale_indexer_steps_retry_and_discard_precedes_state_space_query() {
    for discard in [false, true] {
        for step in [
            UpgradeStep::Ready,
            UpgradeStep::OriginalRenamed,
            UpgradeStep::BeforeDirectorySync,
            UpgradeStep::DirectorySynced,
            UpgradeStep::BackupDiscarded,
        ] {
            if step == UpgradeStep::BackupDiscarded && !discard {
                continue;
            }
            let dir = tempfile::tempdir().unwrap();
            let lock = DataDirectoryLock::acquire(dir.path()).unwrap();
            let idx = dir.path().join("custom-index.redb");
            let bytes = indexer(&idx, 2);
            assert!(upgrade_data(
                &lock,
                dir.path(),
                Path::new("custom-index.redb"),
                &mut UpgradeOptions {
                    discard_backups: discard,
                    free_space: &|_| panic!("stale indexer should not be copied"),
                    cancelled: &|| false,
                    progress: &mut |_, _, _, _| {},
                    step: &mut |at| if at == step {
                        Err(fail("injected crash"))
                    } else {
                        Ok(())
                    },
                }
            )
            .is_err());
            let state = dir.path().join("state.redb");
            legacy(&state);
            upgrade_data(
                &lock,
                dir.path(),
                Path::new("custom-index.redb"),
                &mut UpgradeOptions {
                    discard_backups: discard,
                    free_space: &|path| {
                        assert_eq!(path, state);
                        assert!(!idx.exists());
                        let backup = sibling(&idx, ".redb2-backup");
                        assert_eq!(backup.exists(), !discard);
                        if !discard {
                            assert_eq!(fs::read(backup).unwrap(), bytes);
                        }
                        Ok(u64::MAX)
                    },
                    cancelled: &|| false,
                    progress: &mut |_, _, _, _| {},
                    step: &mut |_| Ok(()),
                },
            )
            .unwrap();
            assert_current(&state);
        }
    }
}

#[test]
fn space_error_has_numbers_and_options_without_changing_file() {
    let dir = tempfile::tempdir().unwrap();
    let lock = DataDirectoryLock::acquire(dir.path()).unwrap();
    let path = dir.path().join("state.redb");
    let bytes = legacy(&path);
    let needed = required_space(bytes.len() as u64);
    let error = upgrade_data(
        &lock,
        dir.path(),
        Path::new("custom-index.redb"),
        &mut UpgradeOptions {
            discard_backups: false,
            free_space: &|_| Ok(17),
            cancelled: &|| false,
            progress: &mut |_, _, _, _| {},
            step: &mut |_| panic!("no mutation before space check"),
        },
    )
    .unwrap_err()
    .to_string();
    for text in [
        needed.to_string(),
        "17".into(),
        "free space".into(),
        "--discard-backups".into(),
        "migrate-redb".into(),
    ] {
        assert!(error.contains(&text), "{error}");
    }
    assert_eq!(fs::read(&path).unwrap(), bytes);
    assert!(!sibling(&path, ".redb-upgrade").exists());
    assert!(!sibling(&path, ".redb2-backup").exists());
}

#[test]
fn cancellation_mid_copy_and_verification_removes_all_temporaries() {
    for phase in ["copy", "verify", "source"] {
        let dir = tempfile::tempdir().unwrap();
        let lock = DataDirectoryLock::acquire(dir.path()).unwrap();
        let path = dir.path().join("state.redb");
        let bytes = legacy(&path);
        let cancelled = Cell::new(false);
        let error = upgrade_data(
            &lock,
            dir.path(),
            Path::new("custom-index.redb"),
            &mut UpgradeOptions {
                discard_backups: false,
                free_space: &|_| Ok(u64::MAX),
                cancelled: &|| cancelled.get(),
                progress: &mut |_, _, _, event| {
                    if matches!(
                        (phase, event),
                        ("copy", MigrationProgress::Copy { .. })
                            | ("verify", MigrationProgress::Verify { .. })
                            | ("source", MigrationProgress::SourceCheck { .. })
                    ) {
                        cancelled.set(true);
                    }
                },
                step: &mut |_| Ok(()),
            },
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("interrupted"), "{phase}: {error}");
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert!(!sibling(&path, ".redb-upgrade").exists());
        assert!(!sibling(&path, ".redb2-backup").exists());
    }
}

#[test]
fn discard_backups_keeps_verified_data_and_removes_stale_indexer() {
    let dir = tempfile::tempdir().unwrap();
    let lock = DataDirectoryLock::acquire(dir.path()).unwrap();
    for name in ["state.redb", "peers.redb", "webhooks.redb"] {
        legacy(&dir.path().join(name));
    }
    indexer(&dir.path().join("custom-index.redb"), 2);
    let report = run(&lock, dir.path(), true);
    assert_eq!(report.migrated, 3);
    assert_eq!(report.stale_indexers, 1);
    for name in ["state.redb", "peers.redb", "webhooks.redb"] {
        assert_current(&dir.path().join(name));
        assert!(!sibling(&dir.path().join(name), ".redb2-backup").exists());
    }
    assert!(!dir.path().join("custom-index.redb").exists());
    assert!(!sibling(&dir.path().join("custom-index.redb"), ".redb2-backup").exists());
}

#[test]
fn exclusive_directory_lock_invalid_files_and_backup_collisions_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let lock = DataDirectoryLock::acquire(dir.path()).unwrap();
    assert!(DataDirectoryLock::acquire(dir.path()).is_err());
    let path = dir.path().join("state.redb");
    fs::write(&path, b"corrupt").unwrap();
    assert!(classify(&path).is_err());
    fs::remove_file(&path).unwrap();
    let bytes = legacy(&path);
    fs::write(sibling(&path, ".redb2-backup"), b"existing backup").unwrap();
    assert!(upgrade_with_logging(
        &lock,
        dir.path(),
        Path::new("custom-index.redb"),
        false,
        &|| false
    )
    .is_err());
    assert_eq!(fs::read(&path).unwrap(), bytes);
    assert_eq!(
        fs::read(sibling(&path, ".redb2-backup")).unwrap(),
        b"existing backup"
    );
    assert!(
        upgrade_with_logging(&lock, dir.path(), Path::new("state.redb"), true, &|| false).is_err()
    );
}

#[test]
fn abrupt_worker_exit() {
    let Ok(directory) = std::env::var("ERGO_UPGRADE_CRASH_DIRECTORY") else {
        return;
    };
    let directory = Path::new(&directory);
    let target = std::env::var("ERGO_UPGRADE_CRASH_STEP").unwrap();
    let lock = DataDirectoryLock::acquire(directory).unwrap();
    let _ = upgrade_data(
        &lock,
        directory,
        Path::new("custom-index.redb"),
        &mut UpgradeOptions {
            discard_backups: false,
            free_space: &|_| Ok(u64::MAX),
            cancelled: &|| false,
            progress: &mut |_, _, _, _| {},
            step: &mut |step| {
                if format!("{step:?}") == target {
                    // No destructors or staging cleanup; same on-disk evidence a
                    // SIGKILL leaves. The parent retries using a new lock/process.
                    std::process::exit(77);
                }
                Ok(())
            },
        },
    );
    panic!("crash point was not reached");
}

#[test]
fn process_death_leaves_staging_that_a_new_process_recovers() {
    for step in [
        UpgradeStep::StageCreated,
        UpgradeStep::Copied,
        UpgradeStep::Verified,
        UpgradeStep::CopyPublished,
        UpgradeStep::Ready,
        UpgradeStep::OriginalRenamed,
        UpgradeStep::Installed,
        UpgradeStep::BeforeDirectorySync,
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.redb");
        let bytes = legacy(&path);
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "data_upgrade::tests::abrupt_worker_exit"])
            .env("ERGO_UPGRADE_CRASH_DIRECTORY", dir.path())
            .env("ERGO_UPGRADE_CRASH_STEP", format!("{step:?}"))
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(77),
            "{step:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let lock = DataDirectoryLock::acquire(dir.path()).unwrap();
        run(&lock, dir.path(), false);
        assert_current(&path);
        assert_eq!(fs::read(sibling(&path, ".redb2-backup")).unwrap(), bytes);
        assert!(!sibling(&path, ".redb-upgrade").exists());
    }
}

#[tokio::test]
async fn signal_copy_worker() {
    let Ok(directory) = std::env::var("ERGO_UPGRADE_SIGNAL_DIRECTORY") else {
        return;
    };
    let result = crate::maintenance::run_cancellable(move |cancelled| {
        let directory = Path::new(&directory);
        let lock = DataDirectoryLock::acquire(directory)?;
        upgrade_data(
            &lock,
            directory,
            Path::new("custom-index.redb"),
            &mut UpgradeOptions {
                discard_backups: false,
                free_space: &|_| Ok(u64::MAX),
                cancelled: &|| cancelled.load(std::sync::atomic::Ordering::Relaxed),
                progress: &mut |_, _, _, event| {
                    if matches!(event, MigrationProgress::Copy { .. }) {
                        fs::write(directory.join("worker-copying"), []).unwrap();
                        let deadline = Instant::now() + Duration::from_secs(10);
                        while !cancelled.load(std::sync::atomic::Ordering::Relaxed)
                            && Instant::now() < deadline
                        {
                            std::thread::sleep(Duration::from_millis(5));
                        }
                    }
                },
                step: &mut |_| Ok(()),
            },
        )
    })
    .await;
    assert!(result.unwrap_err().to_string().contains("interrupted"));
}

#[cfg(unix)]
#[test]
fn sigint_and_sigterm_mid_copy_release_lock_and_remove_temporaries() {
    for signal in ["-INT", "-TERM"] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.redb");
        let bytes = legacy(&path);
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "data_upgrade::tests::signal_copy_worker"])
            .env("ERGO_UPGRADE_SIGNAL_DIRECTORY", dir.path())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !dir.path().join("worker-copying").exists() {
            if Instant::now() >= deadline || child.try_wait().unwrap().is_some() {
                let _ = child.kill();
                let _ = child.wait();
                panic!("worker did not reach copy phase");
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(std::process::Command::new("kill")
            .args([signal, &child.id().to_string()])
            .status()
            .unwrap()
            .success());
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success(), "{signal}: {status}");
                break;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("signal cleanup worker did not exit");
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let lock = DataDirectoryLock::acquire(dir.path()).unwrap();
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert!(!sibling(&path, ".redb-upgrade").exists());
        assert!(!sibling(&path, ".redb2-backup").exists());
        drop(lock);
    }
}

#[test]
fn missing_indexer_parent_is_skipped_and_lock_must_cover_requested_directory() {
    let dir = tempfile::tempdir().unwrap();
    let lock = DataDirectoryLock::acquire(dir.path()).unwrap();
    let mut options = UpgradeOptions {
        discard_backups: false,
        free_space: &|_| panic!("no database to migrate"),
        cancelled: &|| false,
        progress: &mut |_, _, _, _| {},
        step: &mut |_| Ok(()),
    };
    assert!(upgrade_data(
        &lock,
        dir.path(),
        Path::new("absent/index.redb"),
        &mut options
    )
    .unwrap()
    .is_noop());
    assert!(!dir.path().join("absent").exists());
    let other = tempfile::tempdir().unwrap();
    assert!(
        upgrade_data(&lock, other.path(), Path::new("indexer.redb"), &mut options)
            .unwrap_err()
            .to_string()
            .contains("lock does not cover")
    );
}

#[test]
fn missing_verified_copy_restores_original_before_retrying() {
    let dir = tempfile::tempdir().unwrap();
    let lock = DataDirectoryLock::acquire(dir.path()).unwrap();
    let path = dir.path().join("state.redb");
    let bytes = legacy(&path);
    assert!(upgrade_data(
        &lock,
        dir.path(),
        Path::new("custom-index.redb"),
        &mut UpgradeOptions {
            discard_backups: false,
            free_space: &|_| Ok(u64::MAX),
            cancelled: &|| false,
            progress: &mut |_, _, _, _| {},
            step: &mut |step| if step == UpgradeStep::OriginalRenamed {
                Err(fail("injected crash"))
            } else {
                Ok(())
            },
        }
    )
    .is_err());
    assert!(!path.exists());
    fs::remove_file(sibling(&path, ".redb-upgrade").join("copy.redb")).unwrap();
    assert_eq!(
        run(&lock, dir.path(), false),
        UpgradeReport {
            migrated: 1,
            stale_indexers: 0,
            recovered: 1
        }
    );
    assert_current(&path);
    assert_eq!(fs::read(sibling(&path, ".redb2-backup")).unwrap(), bytes);
}

