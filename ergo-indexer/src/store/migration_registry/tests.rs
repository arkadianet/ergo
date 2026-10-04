use super::*;
use crate::store::{IndexerMeta, IndexerStore, OpenOutcome};
use redb::{ReadableTable, TableDefinition};

const MARKERS: TableDefinition<u32, u32> = TableDefinition::new("migration_test_markers");
const TWO_STEPS: &[MigrationStep] = &[
    MigrationStep {
        from: 1,
        to: 2,
        name: "first",
        apply: first,
    },
    MigrationStep {
        from: 2,
        to: 3,
        name: "second",
        apply: second,
    },
];

fn marker_step(db: &Database, cancel: &AtomicBool, from: u32) -> Result<(), IndexerError> {
    let read = db.begin_read()?;
    assert_eq!(meta::read_schema_version(&read)?, Some(from));
    let mut write = ergo_state::begin_write_qr(db)?;
    write.set_durability(redb::Durability::Immediate)?;
    {
        let mut markers = write.open_table(MARKERS)?;
        assert!(markers.get(from)?.is_none(), "step applied twice");
        if from == 2 {
            assert_eq!(
                markers.get(1)?.unwrap().value(),
                2,
                "steps ran out of order"
            );
        }
        markers.insert(from, from + 1)?;
    }
    meta::write_schema_version(&write, from + 1)?;
    if cancel.load(Ordering::Acquire) {
        return Err(IndexerError::MigrationCancelled);
    }
    write.commit()?;
    Ok(())
}

fn first(db: &Database, cancel: &AtomicBool) -> Result<(), IndexerError> {
    marker_step(db, cancel, 1)
}

fn second(db: &Database, cancel: &AtomicBool) -> Result<(), IndexerError> {
    marker_step(db, cancel, 2)
}

fn legacy(path: &std::path::Path, version: u32) {
    let (store, _) = IndexerStore::open(path).unwrap();
    let write = store.begin_write().unwrap();
    meta::write_schema_version(&write, version).unwrap();
    let mut checkpoint = IndexerMeta::empty();
    checkpoint.indexed_height = 7;
    checkpoint.indexed_header_id = Some(ergo_primitives::digest::Digest32::from_bytes([7; 32]));
    meta::write_meta(&write, &checkpoint).unwrap();
    write.commit().unwrap();
}

fn pending(path: &std::path::Path, registry: &[MigrationStep]) -> IndexerStore {
    let (store, outcome) = IndexerStore::open_with_registry(path, 65536, None, registry).unwrap();
    assert_eq!(outcome, OpenOutcome::MigrationPending);
    store
}

fn assert_version(db: &Database, expected: u32) {
    assert_eq!(
        meta::read_schema_version(&db.begin_read().unwrap()).unwrap(),
        Some(expected)
    );
}

#[test]
fn registry_invariants() {
    assert!(valid_registry(MIGRATIONS));
    assert!(valid_registry(TWO_STEPS));
    let froms: std::collections::HashSet<_> = MIGRATIONS.iter().map(|step| step.from).collect();
    assert_eq!(froms.len(), MIGRATIONS.len());
    assert!(!valid_registry(&[]));
    for (from, to) in [(1, 3), (2, 2), (3, 4), (u32::MAX, 0)] {
        assert!(!valid_registry(&[MigrationStep {
            from,
            to,
            name: "invalid",
            apply: first
        }]));
    }
    assert!(!valid_registry(&[TWO_STEPS[0], TWO_STEPS[0]]));
    assert!(!valid_registry(&[
        MigrationStep {
            from: 0,
            to: 1,
            name: "gap",
            apply: first
        },
        TWO_STEPS[1],
    ]));
    assert!(has_migration_path(2));
    for version in [0, 1, INDEXER_SCHEMA_VERSION, u32::MAX] {
        assert!(!has_migration_path(version));
    }
}

#[test]
fn registry_two_steps_apply_in_order_on_worker() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("indexer.redb");
    legacy(&path, 1);
    let store = pending(&path, TWO_STEPS);
    assert_version(&store.db, 1);
    let worker = std::thread::spawn(move || {
        let cancel = AtomicBool::new(false);
        store
            .finish_migration_with(&cancel, |db| run(db, &cancel, TWO_STEPS))
            .unwrap()
    });
    let store = worker.join().unwrap();
    assert_version(&store.db, 3);
    assert_eq!(store.read_meta().unwrap().indexed_height, 7);
    let read = store.db.begin_read().unwrap();
    let markers = read.open_table(MARKERS).unwrap();
    assert_eq!(markers.get(1).unwrap().unwrap().value(), 2);
    assert_eq!(markers.get(2).unwrap().unwrap().value(), 3);
}

#[test]
fn registry_interruption_preserves_first_step_and_reopen_resumes_second_only() {
    for cancellation in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("indexer.redb");
        legacy(&path, 1);
        let store = pending(&path, TWO_STEPS);
        let interrupted = [
            TWO_STEPS[0],
            MigrationStep {
                from: 2,
                to: 3,
                name: "interrupted",
                apply: |db, cancel| {
                    // Simulate a failure after staging writes in the second step.
                    let write = ergo_state::begin_write_qr(db)?;
                    write.open_table(MARKERS)?.insert(2, 99)?;
                    if cancel.load(Ordering::Acquire) {
                        Err(IndexerError::MigrationCancelled)
                    } else {
                        Err(IndexerError::SchemaCorruption)
                    }
                },
            },
        ];
        let cancel = AtomicBool::new(false);
        // The first step requests shutdown only after its transaction commits.
        let cancelling = [
            MigrationStep {
                from: 1,
                to: 2,
                name: "commit then cancel",
                apply: |db, cancel| {
                    first(db, cancel)?;
                    cancel.store(true, Ordering::Release);
                    Ok(())
                },
            },
            TWO_STEPS[1],
        ];
        let result = run(
            &store.db,
            &cancel,
            if cancellation {
                &cancelling
            } else {
                &interrupted
            },
        );
        assert!(result.is_err());
        if cancellation {
            assert!(matches!(result, Err(IndexerError::MigrationCancelled)));
        }
        assert_version(&store.db, 2);
        {
            let read = store.db.begin_read().unwrap();
            let markers = read.open_table(MARKERS).unwrap();
            assert_eq!(markers.get(1).unwrap().unwrap().value(), 2);
            assert!(markers.get(2).unwrap().is_none());
        }
        drop(store);
        let store = pending(&path, TWO_STEPS);
        let cancel = AtomicBool::new(false);
        let store = store
            .finish_migration_with(&cancel, |db| run(db, &cancel, TWO_STEPS))
            .unwrap();
        assert_version(&store.db, 3);
        assert_eq!(store.read_meta().unwrap().indexed_height, 7);
        assert_eq!(
            store
                .db
                .begin_read()
                .unwrap()
                .open_table(MARKERS)
                .unwrap()
                .get(2)
                .unwrap()
                .unwrap()
                .value(),
            3
        );
    }
}

#[test]
fn registry_no_path_rebuilds_instead_of_running_a_partial_chain() {
    for version in [0, 1, INDEXER_SCHEMA_VERSION + 1, u32::MAX] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("indexer.redb");
        legacy(&path, version);
        let (store, outcome) =
            IndexerStore::open_with_registry(&path, 65536, None, MIGRATIONS).unwrap();
        assert_eq!(
            outcome,
            OpenOutcome::WipedAndRecreated {
                previous_version: version
            }
        );
        assert_version(&store.db, INDEXER_SCHEMA_VERSION);
        assert_eq!(store.read_meta().unwrap(), IndexerMeta::empty());
    }
}

#[test]
fn registry_failed_second_step_falls_back_to_background_rebuild() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("indexer.redb");
    legacy(&path, 1);
    let store = pending(&path, TWO_STEPS);
    let worker = std::thread::spawn(move || {
        let steps = [
            TWO_STEPS[0],
            MigrationStep {
                from: 2,
                to: 3,
                name: "failing second",
                apply: |db, _| {
                    assert_version(db, 2);
                    Err(IndexerError::SchemaCorruption)
                },
            },
        ];
        let cancel = AtomicBool::new(false);
        store
            .finish_migration_with(&cancel, |db| run(db, &cancel, &steps))
            .unwrap()
    });
    let rebuilt = worker.join().unwrap();
    assert_version(&rebuilt.db, INDEXER_SCHEMA_VERSION);
    assert_eq!(rebuilt.read_meta().unwrap(), IndexerMeta::empty());
    assert!(matches!(
        rebuilt.db.begin_read().unwrap().open_table(MARKERS),
        Err(redb::TableError::TableDoesNotExist(_))
    ));
}
