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
            keep_stale_indexer: true,
            indexer_enabled: false,
            warning: &mut |_| {},
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
            recovered: 0,
            discarded_existing_backups: 0,
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
    let (schema, probe_lock) = legacy_indexer_schema(&path, &mut |_| {}).unwrap();
    assert_eq!(schema, ergo_indexer::store::INDEXER_SCHEMA_VERSION);
    // Windows byte-range locks are mandatory: read only after releasing the probe.
    drop(probe_lock);
    assert_eq!(fs::read(&path).unwrap(), bytes);
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
                    keep_stale_indexer: true,
                    indexer_enabled: false,
                    warning: &mut |_| {},
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
                    keep_stale_indexer: true,
                    indexer_enabled: false,
                    warning: &mut |_| {},
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
                    keep_stale_indexer: true,
                    indexer_enabled: false,
                    warning: &mut |_| {},
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
            keep_stale_indexer: true,
            indexer_enabled: false,
            warning: &mut |_| {},
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
                keep_stale_indexer: true,
                indexer_enabled: false,
                warning: &mut |_| {},
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
        false,
        false,
        &|| false
    )
    .is_err());
    assert_eq!(fs::read(&path).unwrap(), bytes);
    assert_eq!(
        fs::read(sibling(&path, ".redb2-backup")).unwrap(),
        b"existing backup"
    );
    assert!(upgrade_with_logging(
        &lock,
        dir.path(),
        Path::new("state.redb"),
        true,
        false,
        false,
        &|| false
    )
    .is_err());
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
            keep_stale_indexer: true,
            indexer_enabled: false,
            warning: &mut |_| {},
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
                keep_stale_indexer: true,
                indexer_enabled: false,
                warning: &mut |_| {},
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
        keep_stale_indexer: true,
        indexer_enabled: false,
        warning: &mut |_| {},
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
            keep_stale_indexer: true,
            indexer_enabled: false,
            warning: &mut |_| {},
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
            recovered: 1,
            discarded_existing_backups: 0,
        }
    );
    assert_current(&path);
    assert_eq!(fs::read(sibling(&path, ".redb2-backup")).unwrap(), bytes);
}

#[test]
fn configured_indexer_cannot_consume_a_retained_rollback_backup() {
    let dir = tempfile::tempdir().unwrap();
    let lock = DataDirectoryLock::acquire(dir.path()).unwrap();
    let path = dir.path().join("state.redb.redb2-backup");
    let bytes = indexer(&path, 2);
    let error = upgrade_with_logging(
        &lock,
        dir.path(),
        Path::new("state.redb.redb2-backup"),
        true,
        false,
        false,
        &|| false,
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("reserved upgrade artifact"), "{error}");
    assert_eq!(fs::read(&path).unwrap(), bytes);
}

#[test]
fn discard_retry_reclaims_stale_backup_before_checking_state_space() {
    let dir = tempfile::tempdir().unwrap();
    let lock = DataDirectoryLock::acquire(dir.path()).unwrap();
    let idx = dir.path().join("custom-index.redb");
    indexer(&idx, 2);
    run(&lock, dir.path(), false);
    let state = dir.path().join("state.redb");
    let bytes = legacy(&state);
    let mut options = UpgradeOptions {
        discard_backups: false,
        keep_stale_indexer: true,
        indexer_enabled: false,
        warning: &mut |_| {},
        free_space: &|path| {
            assert_eq!(path, state);
            Ok(0)
        },
        cancelled: &|| false,
        progress: &mut |_, _, _, _| {},
        step: &mut |_| Ok(()),
    };
    assert!(upgrade_data(
        &lock,
        dir.path(),
        Path::new("custom-index.redb"),
        &mut options
    )
    .unwrap_err()
    .to_string()
    .contains("insufficient space"));
    assert!(!idx.exists());
    assert!(sibling(&idx, ".redb2-backup").exists());
    assert_eq!(fs::read(&state).unwrap(), bytes);
    options.discard_backups = true;
    let reclaimed_space = |path: &Path| {
        assert_eq!(path, state);
        assert!(
            !sibling(&idx, ".redb2-backup").exists(),
            "discard must reclaim the earlier indexer backup first"
        );
        Ok(u64::MAX)
    };
    options.free_space = &reclaimed_space;
    let report = upgrade_data(
        &lock,
        dir.path(),
        Path::new("custom-index.redb"),
        &mut options,
    )
    .unwrap();
    assert_eq!(report.migrated, 1);
    assert_eq!(report.discarded_existing_backups, 1);
    assert_current(&state);
    assert!(!sibling(&state, ".redb2-backup").exists());
}

#[test]
fn discard_completed_upgrade_removes_retained_backups_then_is_noop() {
    let dir = tempfile::tempdir().unwrap();
    let lock = DataDirectoryLock::acquire(dir.path()).unwrap();
    for name in ["state.redb", "peers.redb", "webhooks.redb"] {
        legacy(&dir.path().join(name));
    }
    indexer(&dir.path().join("custom-index.redb"), 2);
    run(&lock, dir.path(), false);
    let report = run(&lock, dir.path(), true);
    assert_eq!(report.migrated, 0);
    assert_eq!(report.discarded_existing_backups, 4);
    for name in ["state.redb", "peers.redb", "webhooks.redb"] {
        assert_current(&dir.path().join(name));
        assert!(!sibling(&dir.path().join(name), ".redb2-backup").exists());
    }
    assert!(run(&lock, dir.path(), true).is_noop());
}

#[test]
fn discard_refuses_to_delete_a_sole_state_or_current_schema_indexer_backup() {
    for name in ["state.redb", "custom-index.redb"] {
        let dir = tempfile::tempdir().unwrap();
        let lock = DataDirectoryLock::acquire(dir.path()).unwrap();
        let path = dir.path().join(name);
        let bytes = if name == "state.redb" {
            legacy(&path)
        } else {
            indexer(&path, ergo_indexer::store::INDEXER_SCHEMA_VERSION)
        };
        let backup = sibling(&path, ".redb2-backup");
        fs::rename(&path, &backup).unwrap();
        let error = upgrade_with_logging(
            &lock,
            dir.path(),
            Path::new("custom-index.redb"),
            true,
            false,
            false,
            &|| false,
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("missing") && error.contains("only copy"),
            "{error}"
        );
        assert_eq!(fs::read(&backup).unwrap(), bytes);
    }
}

#[test]
fn constrained_drive_deletes_stale_index_before_state_copy_and_warns_about_rebuild() {
    for keep_stale_indexer in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let lock = DataDirectoryLock::acquire(dir.path()).unwrap();
        let idx = dir.path().join("custom-index.redb");
        let idx_bytes = indexer(&idx, 2);
        let state = dir.path().join("state.redb");
        let state_bytes = legacy(&state);
        let needed = required_space(state_bytes.len() as u64);
        let idx_size = idx_bytes.len() as u64;
        let initial_free = needed - idx_size / 2;
        let mut warnings = Vec::new();
        let result = upgrade_data(
            &lock,
            dir.path(),
            Path::new("custom-index.redb"),
            &mut UpgradeOptions {
                discard_backups: false,
                keep_stale_indexer,
                indexer_enabled: true,
                free_space: &|path| {
                    let retained_index = idx.exists() || sibling(&idx, ".redb2-backup").exists();
                    let free = initial_free + if retained_index { 0 } else { idx_size };
                    assert!(path == idx || path == state || path == dir.path());
                    let copied_state = sibling(&state, ".redb2-backup").exists();
                    // Model a copy using its full preflight budget, including
                    // page-growth headroom; the retained source frees nothing.
                    Ok(free - if copied_state { needed } else { 0 })
                },
                warning: &mut |message| warnings.push(message.to_owned()),
                cancelled: &|| false,
                progress: &mut |_, _, _, _| {},
                step: &mut |_| Ok(()),
            },
        );
        if keep_stale_indexer {
            let error = result.unwrap_err().to_string();
            assert!(
                error.contains(&needed.to_string()) && error.contains(&initial_free.to_string()),
                "{error}"
            );
            assert_eq!(fs::read(&idx).unwrap(), idx_bytes);
            assert_eq!(fs::read(&state).unwrap(), state_bytes);
            for path in [&idx, &state] {
                assert!(!sibling(path, ".redb2-backup").exists());
                assert!(!sibling(path, ".redb-upgrade").exists());
            }
        } else {
            assert_eq!(result.unwrap().migrated, 1);
            assert!(!idx.exists());
            assert!(!sibling(&idx, ".redb2-backup").exists());
            assert_current(&state);
            assert_eq!(
                fs::read(sibling(&state, ".redb2-backup")).unwrap(),
                state_bytes
            );
            let messages = warnings.join("\n");
            for expected in [
                "rolling back to 0.11 rebuilds",
                "state.redb.redb2-backup",
                "plain file",
                "safe while the node runs",
                "--discard-backups",
                "indexer rebuild",
                &idx_size.to_string(),
                &(idx_size / 2).to_string(),
            ] {
                assert!(
                    messages.contains(expected),
                    "missing {expected}: {messages}"
                );
            }
        }
    }
}

#[tokio::test]
async fn backup_warning_startup_worker() {
    use clap::Parser;
    let Ok(directory) = std::env::var("ERGO_BACKUP_WARNING_DIRECTORY") else {
        return;
    };
    let directory = PathBuf::from(directory);
    let log = File::create(directory.join("startup.log")).unwrap();
    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || log.try_clone().unwrap())
            .finish(),
    )
    .unwrap();
    let cli = crate::config::Cli::try_parse_from([
        "ergo-node",
        "--data-dir",
        directory.to_str().unwrap(),
        "--config",
        directory.join("node.toml").to_str().unwrap(),
    ])
    .unwrap();
    let config = crate::config::NodeConfig::load(cli).unwrap();
    let _lock = prepare_startup(&config).await.unwrap();
}

#[test]
fn every_startup_warns_about_existing_backups_even_when_conversion_is_disabled() {
    for automatic in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("archive");
        fs::create_dir(&nested).unwrap();
        let external = tempfile::tempdir().unwrap();
        let paths = [
            dir.path().join("state.redb.redb2-backup"),
            nested.join("old.redb2-backup"),
            external.path().join("index.redb.redb2-backup"),
        ];
        for path in &paths {
            fs::write(path, b"retained").unwrap();
        }
        fs::write(
            dir.path().join("node.toml"),
            format!(
                "[store]\nauto_upgrade_legacy = {automatic}\n[indexer]\ndb_filename = {:?}\n",
                external.path().join("index.redb").to_str().unwrap()
            ),
        )
        .unwrap();
        // A new process gives startup's blocking worker a real tracing
        // subscriber, without changing the parallel test runner's subscriber.
        for _ in 0..2 {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "data_upgrade::tests::backup_warning_startup_worker",
                ])
                .env("ERGO_BACKUP_WARNING_DIRECTORY", dir.path())
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let log = fs::read_to_string(dir.path().join("startup.log")).unwrap();
            for path in &paths {
                assert!(log.contains(path.to_str().unwrap()), "{log}");
            }
            for expected in [
                "WARN",
                "8 bytes",
                "safe while the node runs",
                "stop the node",
                "--discard-backups",
            ] {
                assert!(log.contains(expected), "missing {expected}: {log}");
            }
        }
    }
}

#[test]
fn default_stale_indexer_deletion_recovers_and_remembers_rebuild_size() {
    for crash_at in [
        UpgradeStep::Ready,
        UpgradeStep::OriginalRenamed,
        UpgradeStep::DirectorySynced,
        UpgradeStep::BackupDiscarded,
    ] {
        let dir = tempfile::tempdir().unwrap();
        let lock = DataDirectoryLock::acquire(dir.path()).unwrap();
        let idx = dir.path().join("custom-index.redb");
        let size = indexer(&idx, 2).len();
        let mut warnings = Vec::new();
        let mut options = UpgradeOptions {
            discard_backups: false,
            keep_stale_indexer: false,
            indexer_enabled: true,
            free_space: &|_| Ok(0),
            warning: &mut |message| warnings.push(message.to_owned()),
            cancelled: &|| false,
            progress: &mut |_, _, _, _| {},
            step: &mut |at| {
                if at == crash_at {
                    Err(fail("injected crash"))
                } else {
                    Ok(())
                }
            },
        };
        assert!(upgrade_data(
            &lock,
            dir.path(),
            Path::new("custom-index.redb"),
            &mut options
        )
        .unwrap_err()
        .to_string()
        .contains("injected crash"));
        // The journal's deletion intent survives an explicit retain request.
        options.keep_stale_indexer = true;
        let mut resume = |_| Ok(());
        options.step = &mut resume;
        assert_eq!(
            upgrade_data(
                &lock,
                dir.path(),
                Path::new("custom-index.redb"),
                &mut options
            )
            .unwrap()
            .recovered,
            1
        );
        assert!(!idx.exists());
        assert!(!sibling(&idx, ".redb2-backup").exists());
        assert!(!sibling(&idx, ".redb-upgrade").exists());
        let warnings = warnings.join("\n");
        assert!(
            warnings.contains("indexer rebuild") && warnings.contains(&size.to_string()),
            "{warnings}"
        );
    }
}

#[test]
fn unknown_free_space_warns_and_proceeds_including_the_index_rebuild_check() {
    for indexer_enabled in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let lock = DataDirectoryLock::acquire(dir.path()).unwrap();
        let idx = dir.path().join("custom-index.redb");
        indexer(&idx, 2);
        let state = dir.path().join("state.redb");
        let bytes = legacy(&state);
        let mut warnings = Vec::new();
        let report = upgrade_data(
            &lock,
            dir.path(),
            Path::new("custom-index.redb"),
            &mut UpgradeOptions {
                discard_backups: false,
                keep_stale_indexer: false,
                indexer_enabled,
                free_space: &|_| Err(fail("injected filesystem query failure")),
                warning: &mut |message| warnings.push(message.to_owned()),
                cancelled: &|| false,
                progress: &mut |_, _, _, _| {},
                step: &mut |_| Ok(()),
            },
        )
        .unwrap();
        assert_eq!(report.migrated, 1);
        assert_eq!(report.stale_indexers, 1);
        assert!(!idx.exists());
        assert_current(&state);
        assert_eq!(fs::read(sibling(&state, ".redb2-backup")).unwrap(), bytes);
        let space_warnings: Vec<_> = warnings
            .iter()
            .filter(|message| message.contains("cannot determine available bytes"))
            .collect();
        assert_eq!(space_warnings.len(), if indexer_enabled { 3 } else { 2 });
        assert!(space_warnings
            .iter()
            .all(|message| message.contains("injected filesystem query failure")));
        assert!(space_warnings
            .iter()
            .any(|message| message.contains("deleting schema-2 indexer")));
        assert!(space_warnings
            .iter()
            .any(|message| message.contains("proceeding without")));
    }
}

#[test]
fn filesystem_space_provider_accepts_files_and_directories() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("database.redb");
    fs::write(&file, b"fixture").unwrap();
    for path in [dir.path(), file.as_path()] {
        assert!(available_space(path).unwrap() > 0);
    }
    assert!(available_space(&dir.path().join("missing")).is_err());
    // Non-UTF-8 names: Linux filesystems accept them; macOS APFS rejects them.
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::ffi::OsStringExt;
        let path = dir
            .path()
            .join(std::ffi::OsString::from_vec(vec![b'd', 0xff]));
        fs::write(&path, b"fixture").unwrap();
        assert!(available_space(&path).unwrap() > 0);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn filesystem_space_provider_queries_a_filtered_filesystem_itself() {
    // procfs has no allocatable disk blocks and is omitted from sysinfo's
    // disk list. Matching it to the root mount returns the wrong filesystem.
    assert_eq!(available_space(Path::new("/proc/self/status")).unwrap(), 0);
}

#[test]
fn unclean_indexer_fixture_worker() {
    let Ok(path) = std::env::var("ERGO_UNCLEAN_INDEXER_FIXTURE") else {
        return;
    };
    let path = Path::new(&path);
    indexer(path, ergo_indexer::store::INDEXER_SCHEMA_VERSION);
    let db = redb_legacy::Database::open(path).unwrap();
    let write = db.begin_write().unwrap();
    write
        .open_table(redb_legacy::TableDefinition::<&str, &[u8]>::new("rows"))
        .unwrap()
        .insert("before-crash", b"committed".as_slice())
        .unwrap();
    write.commit().unwrap();
    // Leave a real recovery marker and committed transaction, as after SIGKILL.
    std::process::exit(0);
}

fn unclean_indexer(path: &Path) -> Vec<u8> {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "data_upgrade::tests::unclean_indexer_fixture_worker",
        ])
        .env("ERGO_UNCLEAN_INDEXER_FIXTURE", path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    fs::read(path).unwrap()
}

#[test]
fn unclean_legacy_indexer_is_stale_without_repair_and_honors_explicit_retention() {
    for keep_stale_indexer in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let lock = DataDirectoryLock::acquire(dir.path()).unwrap();
        let idx = dir.path().join("custom-index.redb");
        let bytes = unclean_indexer(&idx);
        let mut warnings = Vec::new();
        let (schema, probe_lock) =
            legacy_indexer_schema(&idx, &mut |message| warnings.push(message.to_owned())).unwrap();
        assert_eq!(schema, 0);
        // Windows byte-range locks are mandatory: read only after releasing the probe.
        drop(probe_lock);
        assert_eq!(fs::read(&idx).unwrap(), bytes);
        let report = upgrade_data(
            &lock,
            dir.path(),
            Path::new("custom-index.redb"),
            &mut UpgradeOptions {
                discard_backups: false,
                keep_stale_indexer,
                indexer_enabled: false,
                free_space: &|_| panic!("unclean derived index must not be copied"),
                warning: &mut |message| warnings.push(message.to_owned()),
                cancelled: &|| false,
                progress: &mut |_, _, _, _| {},
                step: &mut |_| Ok(()),
            },
        )
        .unwrap();
        assert_eq!(report.stale_indexers, 1);
        assert_eq!(report.migrated, 0);
        assert!(!idx.exists());
        assert!(!sibling(&idx, ".redb-upgrade").exists());
        let messages = warnings.join("\n");
        assert!(
            messages.contains("requires repair")
                && messages.contains("treating this derived index as stale"),
            "{messages}"
        );
        let backup = sibling(&idx, ".redb2-backup");
        assert_eq!(backup.exists(), keep_stale_indexer);
        if keep_stale_indexer {
            assert_eq!(fs::read(&backup).unwrap(), bytes);
            // Offline discard can also identify the retained unclean index
            // without repairing it or deleting sole consensus/peer data.
            assert_eq!(run(&lock, dir.path(), true).discarded_existing_backups, 1);
            assert!(!backup.exists());
        }
    }
}

#[test]
fn unclean_non_indexer_databases_still_use_verified_private_copy_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let lock = DataDirectoryLock::acquire(dir.path()).unwrap();
    let fixture = dir.path().join("fixture.redb");
    let bytes = unclean_indexer(&fixture);
    for name in ["state.redb", "peers.redb", "webhooks.redb"] {
        fs::copy(&fixture, dir.path().join(name)).unwrap();
    }
    let report = run(&lock, dir.path(), false);
    assert_eq!(report.migrated, 3);
    assert_eq!(report.stale_indexers, 0);
    for name in ["state.redb", "peers.redb", "webhooks.redb"] {
        let path = dir.path().join(name);
        assert_current(&path);
        assert_eq!(fs::read(sibling(&path, ".redb2-backup")).unwrap(), bytes);
        let db = redb::ReadOnlyDatabase::open(&path).unwrap();
        assert_eq!(
            db.begin_read()
                .unwrap()
                .open_table(TableDefinition::<&str, &[u8]>::new("rows"))
                .unwrap()
                .get("before-crash")
                .unwrap()
                .unwrap()
                .value(),
            b"committed"
        );
    }
}

#[test]
fn malformed_clean_indexer_schema_remains_an_error_without_mutation() {
    let dir = tempfile::tempdir().unwrap();
    let lock = DataDirectoryLock::acquire(dir.path()).unwrap();
    let path = dir.path().join("custom-index.redb");
    indexer(&path, 2);
    let db = redb_legacy::Database::open(&path).unwrap();
    let write = db.begin_write().unwrap();
    write
        .open_table(redb_legacy::TableDefinition::<&str, &[u8]>::new(
            "indexer_meta",
        ))
        .unwrap()
        .insert("schema_version", [1, 2, 3].as_slice())
        .unwrap();
    write.commit().unwrap();
    drop(db);
    let bytes = fs::read(&path).unwrap();
    let error = upgrade_with_logging(
        &lock,
        dir.path(),
        Path::new("custom-index.redb"),
        false,
        false,
        false,
        &|| false,
    )
    .unwrap_err()
    .to_string();
    assert!(
        error.contains("invalid legacy indexer schema_version length"),
        "{error}"
    );
    assert_eq!(fs::read(&path).unwrap(), bytes);
    assert!(!sibling(&path, ".redb2-backup").exists());
    assert!(!sibling(&path, ".redb-upgrade").exists());
}

fn complete_schema_two_indexer(path: &Path) -> Vec<u8> {
    use ergo_primitives::{digest::Digest32, reader::VlqReader, writer::VlqWriter};
    use ergo_ser::ergo_box::ErgoBoxCandidate;
    use ergo_ser::ergo_tree::{read_ergo_tree, template_hash_from_bytes};
    use ergo_ser::input::{ContextExtension, Input, SpendingProof};
    use ergo_ser::register::{AdditionalRegisters, RegisterValue};
    use ergo_ser::sigma_type::SigmaType;
    use ergo_ser::sigma_value::{CollValue, SigmaValue};
    use ergo_ser::token::Token;
    use ergo_ser::transaction::Transaction;
    use redb::{ReadableTable, TableHandle};

    // Build the complete primary index, then retain the historical v2
    // projections in the legacy-format fixture. Apply-time v2 derivation is
    // independently exercised by ergo-indexer's every-table equivalence test.
    let current_path = path.with_extension("fixture.redb");
    let (store, _) = ergo_indexer::IndexerStore::open(&current_path).unwrap();
    let regs = AdditionalRegisters {
        registers: ["eda080", "eda080", "efbc99"]
            .into_iter()
            .map(|hex| RegisterValue {
                tpe: SigmaType::SColl(Box::new(SigmaType::SByte)),
                value: SigmaValue::Coll(CollValue::Bytes(hex::decode(hex).unwrap())),
            })
            .collect(),
    };
    let id = Digest32::from_bytes([77; 32]);
    let normal_tree = read_ergo_tree(&mut VlqReader::new(&hex::decode("0008d3").unwrap())).unwrap();
    let wrapped_bytes = hex::decode("092f0204a00b08cd021dde34603426402615658f1d970cfa7c7bd92ac81a8b16ee20427901040404040004020504040402").unwrap();
    let wrapped_tree = read_ergo_tree(&mut VlqReader::new(&wrapped_bytes)).unwrap();
    let tx = Transaction {
        inputs: vec![Input {
            box_id: id,
            spending_proof: SpendingProof::new(vec![], ContextExtension::empty()).unwrap(),
        }],
        data_inputs: vec![],
        output_candidates: vec![
            ErgoBoxCandidate::new(
                1_000_000,
                normal_tree,
                1,
                vec![Token {
                    token_id: id,
                    amount: 100,
                }],
                regs,
            )
            .unwrap(),
            ErgoBoxCandidate::new(
                1_000_000,
                wrapped_tree,
                1,
                vec![],
                AdditionalRegisters::empty(),
            )
            .unwrap(),
        ],
    };
    ergo_indexer::apply_block(
        &store,
        &store.read_meta().unwrap(),
        &ergo_indexer::IndexerBlock {
            height: 1,
            header_id: id,
            transactions: &[tx],
        },
    )
    .unwrap();
    drop(store);
    let source = redb::Database::open(&current_path).unwrap();
    let write = source.begin_write().unwrap();
    {
        let mut tokens = write
            .open_table(TableDefinition::<&[u8], &[u8]>::new("indexed_token"))
            .unwrap();
        let key = ergo_indexer::segment_id::token_unique_id(&id);
        let mut token = {
            let row = tokens.get(key.as_bytes().as_slice()).unwrap().unwrap();
            ergo_indexer::token::read_indexed_token(&mut VlqReader::new(row.value())).unwrap()
        };
        token.name = Some(String::from_utf8_lossy(&hex::decode("eda080").unwrap()).into_owned());
        token.description = token.name.clone();
        token.decimals = Some(0);
        let mut writer = VlqWriter::new();
        ergo_indexer::token::write_indexed_token(&mut writer, &token);
        tokens
            .insert(key.as_bytes().as_slice(), writer.as_slice())
            .unwrap();
    }
    write
        .open_table(TableDefinition::<&[u8], &[u8]>::new("indexed_template"))
        .unwrap()
        .remove(template_hash_from_bytes(&wrapped_bytes).unwrap().as_slice())
        .unwrap();
    write
        .open_table(TableDefinition::<&str, &[u8]>::new("indexer_meta"))
        .unwrap()
        .insert("schema_version", 2u32.to_be_bytes().as_slice())
        .unwrap();
    write.commit().unwrap();
    let read = source.begin_read().unwrap();
    let legacy = redb_legacy::Database::create(path).unwrap();
    let write = legacy.begin_write().unwrap();
    for handle in read.list_tables().unwrap() {
        let name = handle.name();
        match name {
            "indexer_meta" => {
                let mut target = write
                    .open_table(redb_legacy::TableDefinition::<&str, &[u8]>::new(name))
                    .unwrap();
                for row in read
                    .open_table(TableDefinition::<&str, &[u8]>::new(name))
                    .unwrap()
                    .iter()
                    .unwrap()
                {
                    let (k, v) = row.unwrap();
                    target.insert(k.value(), v.value()).unwrap();
                }
            }
            "indexer_undo" => {
                let mut target = write
                    .open_table(redb_legacy::TableDefinition::<u64, &[u8]>::new(name))
                    .unwrap();
                for row in read
                    .open_table(TableDefinition::<u64, &[u8]>::new(name))
                    .unwrap()
                    .iter()
                    .unwrap()
                {
                    let (k, v) = row.unwrap();
                    target.insert(k.value(), v.value()).unwrap();
                }
            }
            "unspent_by_creation_height" => {
                let mut target = write
                    .open_table(redb_legacy::TableDefinition::<(u32, i64), &[u8]>::new(name))
                    .unwrap();
                for row in read
                    .open_table(TableDefinition::<(u32, i64), &[u8]>::new(name))
                    .unwrap()
                    .iter()
                    .unwrap()
                {
                    let (k, v) = row.unwrap();
                    target.insert(k.value(), v.value()).unwrap();
                }
            }
            _ => {
                let mut target = write
                    .open_table(redb_legacy::TableDefinition::<&[u8], &[u8]>::new(name))
                    .unwrap();
                for row in read
                    .open_table(TableDefinition::<&[u8], &[u8]>::new(name))
                    .unwrap()
                    .iter()
                    .unwrap()
                {
                    let (k, v) = row.unwrap();
                    target.insert(k.value(), v.value()).unwrap();
                }
            }
        }
    }
    write.commit().unwrap();
    drop(legacy);
    drop(read);
    drop(source);
    fs::remove_file(current_path).unwrap();
    fs::read(path).unwrap()
}

#[test]
fn legacy_indexer_preservation_follows_registered_path_and_space_policy() {
    for (schema, registered, enough_space, keep_stale) in [
        (1, true, true, false),
        (1, true, false, false),
        (1, true, true, true),
        (2, false, true, false),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let lock = DataDirectoryLock::acquire(dir.path()).unwrap();
        let idx = dir.path().join("custom-index.redb");
        let original = indexer(&idx, schema);
        let state = dir.path().join("state.redb");
        let state_bytes = legacy(&state);
        let combined =
            required_space(original.len() as u64) + required_space(state_bytes.len() as u64);
        let mut warnings = Vec::new();
        let report = upgrade_data_with_migration_path(
            &lock,
            dir.path(),
            Path::new("custom-index.redb"),
            &mut UpgradeOptions {
                discard_backups: false,
                keep_stale_indexer: keep_stale,
                indexer_enabled: true,
                warning: &mut |s| warnings.push(s.to_owned()),
                free_space: &|_| Ok(if enough_space { combined } else { combined - 1 }),
                cancelled: &|| false,
                progress: &mut |_, _, _, _| {},
                step: &mut |_| Ok(()),
            },
            // Model a future registry accepting schema 1, or dropping schema 2.
            |version| registered && version == schema,
        )
        .unwrap();
        assert_current(&state);
        let preserved = registered && enough_space && !keep_stale;
        assert_eq!(report.migrated, if preserved { 2 } else { 1 });
        assert_eq!(report.stale_indexers, usize::from(!preserved));
        assert_eq!(idx.exists(), preserved);
        if preserved {
            assert_current(&idx);
            assert!(warnings
                .iter()
                .any(|s| s.contains("registered schema migrations")));
        } else if registered && !enough_space && !keep_stale {
            assert!(warnings
                .iter()
                .any(|s| s.contains("schema-1 legacy indexer cannot be preserved")));
        }
        if preserved || keep_stale {
            assert_eq!(fs::read(sibling(&idx, ".redb2-backup")).unwrap(), original);
        } else {
            assert!(!sibling(&idx, ".redb2-backup").exists());
        }
    }
}

#[test]
fn schema_two_indexer_is_converted_and_migrated_only_with_combined_headroom() {
    for enough_space in [true, false] {
        let dir = tempfile::tempdir().unwrap();
        let lock = DataDirectoryLock::acquire(dir.path()).unwrap();
        let idx = dir.path().join("custom-index.redb");
        let original = complete_schema_two_indexer(&idx);
        let state = dir.path().join("state.redb");
        let state_bytes = legacy(&state);
        let state_needed = required_space(state_bytes.len() as u64);
        let combined = state_needed + required_space(original.len() as u64);
        let mut warnings = Vec::new();
        let report = upgrade_data(
            &lock,
            dir.path(),
            Path::new("custom-index.redb"),
            &mut UpgradeOptions {
                discard_backups: false,
                keep_stale_indexer: false,
                indexer_enabled: true,
                warning: &mut |s| warnings.push(s.to_owned()),
                free_space: &|_| {
                    Ok(if enough_space { combined } else { combined - 1 }
                        - if sibling(&idx, ".redb2-backup").exists() {
                            required_space(original.len() as u64)
                        } else {
                            0
                        })
                },
                cancelled: &|| false,
                progress: &mut |_, _, _, _| {},
                step: &mut |_| Ok(()),
            },
        )
        .unwrap();
        assert_current(&state);
        assert_eq!(
            fs::read(sibling(&state, ".redb2-backup")).unwrap(),
            state_bytes
        );
        if enough_space {
            assert_eq!(report.migrated, 2);
            assert_eq!(report.stale_indexers, 0);
            assert_eq!(fs::read(sibling(&idx, ".redb2-backup")).unwrap(), original);
            let (store, outcome) = ergo_indexer::IndexerStore::open(&idx).unwrap();
            assert_eq!(
                outcome,
                ergo_indexer::OpenOutcome::Migrated {
                    previous_version: 2
                }
            );
            assert_eq!(store.read_meta().unwrap().indexed_height, 1);
            assert_eq!(store.read_meta().unwrap().global_box_index, 2);
            let token = store
                .read_token(&ergo_primitives::digest::Digest32::from_bytes([77; 32]))
                .unwrap()
                .unwrap();
            assert_eq!(token.name.as_deref(), Some("\u{fffd}"));
            assert_eq!(token.description.as_deref(), Some("\u{fffd}"));
            assert_eq!(token.decimals, Some(9));
            let wrapped = ergo_primitives::digest::Digest32::from_bytes(
                hex::decode("c7f899c5518eddc86a5052a932551fd54706cd8d12641150b160c25cdbd4befd")
                    .unwrap()
                    .try_into()
                    .unwrap(),
            );
            assert_eq!(
                store.read_template_box_entries(&wrapped).unwrap(),
                Some(vec![1])
            );
        } else {
            assert_eq!(report.migrated, 1);
            assert_eq!(report.stale_indexers, 1);
            assert!(!idx.exists());
            assert!(!sibling(&idx, ".redb2-backup").exists());
            assert!(warnings
                .iter()
                .any(|s| s.contains("state upgrade has priority")));
        }
    }
}
