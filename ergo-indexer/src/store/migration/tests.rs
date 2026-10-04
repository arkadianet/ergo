use super::*;
use crate::apply::{apply_block, apply_block_with_derivation, IndexerBlock};
use crate::scratch::BlockApplyScratch;
use crate::store::{IndexerMeta, IndexerStore, OpenOutcome};
use crate::token::IndexedToken;
use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::read_ergo_tree;
use ergo_ser::input::{ContextExtension, Input, SpendingProof};
use ergo_ser::register::{AdditionalRegisters, RegisterId, RegisterValue};
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::{CollValue, SigmaValue};
use ergo_ser::token::Token;
use ergo_ser::transaction::{transaction_id, Transaction};
use redb::{TableDefinition, TableHandle};
use std::collections::BTreeMap;

// These are the pre-ccbb8f81 and pre-4a7823be derivations, used DURING
// block apply so both output appends and subsequent input spends use v2.
fn old_template(bytes: &[u8]) -> Result<Option<Digest32>, IndexerError> {
    let tree = read_ergo_tree(&mut VlqReader::new(bytes)).unwrap();
    if matches!(tree.body, Expr::Unparsed(_)) {
        Ok(None)
    } else {
        template_hash_for_box_bytes(bytes)
    }
}

fn old_token(box_id: &Digest32, token: &Token, regs: &AdditionalRegisters) -> IndexedToken {
    let text = |id| match regs.get(id).map(|r| &r.value) {
        Some(SigmaValue::Coll(CollValue::Bytes(bytes))) => {
            String::from_utf8_lossy(bytes).into_owned()
        }
        _ => String::new(),
    };
    let mut record = IndexedToken::from_box(box_id, token, regs);
    record.name = Some(text(RegisterId::R4));
    record.description = Some(text(RegisterId::R5));
    record.decimals = Some(match regs.get(RegisterId::R6).map(|r| &r.value) {
        Some(SigmaValue::Coll(CollValue::Bytes(bytes))) => std::str::from_utf8(bytes)
            .ok()
            .and_then(|s| s.parse::<i32>().ok())
            .unwrap_or(0),
        Some(SigmaValue::Int(n)) => *n,
        _ => 0,
    });
    record
}

fn candidate(tree: &str, regs: AdditionalRegisters, tokens: Vec<Token>) -> ErgoBoxCandidate {
    let bytes = hex::decode(tree).unwrap();
    let tree = read_ergo_tree(&mut VlqReader::new(&bytes)).unwrap();
    ErgoBoxCandidate::new(1_000_000, tree, 1, tokens, regs).unwrap()
}

fn input(id: Digest32) -> Input {
    Input {
        box_id: id,
        spending_proof: SpendingProof::new(vec![], ContextExtension::empty()).unwrap(),
    }
}

fn box_id(tx: &Transaction, index: u16) -> Digest32 {
    ErgoBox {
        candidate: tx.output_candidates[index as usize].clone(),
        transaction_id: transaction_id(tx).unwrap(),
        index,
    }
    .box_id()
    .unwrap()
}

fn blocks() -> Vec<Vec<Transaction>> {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../test-vectors/ergo-indexer/token-text/stdout.json"
    ))
    .unwrap();
    let mut genesis = Vec::new();
    for (i, case) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        let bytes = hex::decode(case["hex"].as_str().unwrap()).unwrap();
        let regs = AdditionalRegisters {
            registers: (0..3)
                .map(|_| RegisterValue {
                    tpe: SigmaType::SColl(Box::new(SigmaType::SByte)),
                    value: SigmaValue::Coll(CollValue::Bytes(bytes.clone())),
                })
                .collect(),
        };
        let id = Digest32::from_bytes([i as u8 + 1; 32]);
        genesis.push(Transaction {
            inputs: vec![input(id)],
            data_inputs: vec![],
            output_candidates: vec![candidate(
                "0008d3",
                regs,
                vec![Token {
                    token_id: id,
                    amount: 100,
                }],
            )],
        });
    }
    // 1,100 wrapped outputs force two spills. The v4 wrap's cached template
    // is the same 08d3 as ordinary v0 trees, exercising merge/interleaving.
    let mut outputs = Vec::new();
    for i in 0..1100 {
        outputs.push(candidate(
            if i % 3 == 0 { "0008d3" } else { "0c0208d3" },
            AdditionalRegisters::empty(),
            vec![],
        ));
    }
    // Captured mainnet h=1,702,686 output tree, inside our undo window.
    outputs.push(candidate("092f0204a00b08cd021dde34603426402615658f1d970cfa7c7bd92ac81a8b16ee20427901040404040004020504040402", AdditionalRegisters::empty(), vec![]));
    let wrapped_tx = Transaction {
        inputs: vec![input(Digest32::from_bytes([99; 32]))],
        data_inputs: vec![],
        output_candidates: outputs,
    };
    let spend = Transaction {
        inputs: [1, 511, 514, 1099, 1100]
            .into_iter()
            .map(|i| input(box_id(&wrapped_tx, i)))
            .collect(),
        data_inputs: vec![],
        output_candidates: vec![candidate("0c0208d3", AdditionalRegisters::empty(), vec![])],
    };
    genesis.push(wrapped_tx);
    let third = Transaction {
        inputs: vec![input(box_id(&spend, 0))],
        data_inputs: vec![],
        output_candidates: vec![candidate("0c0208d3", AdditionalRegisters::empty(), vec![])],
    };
    vec![genesis, vec![spend], vec![third]]
}

fn block(txs: &[Transaction], height: usize) -> IndexerBlock<'_> {
    IndexerBlock {
        height: height as i32,
        header_id: Digest32::from_bytes([height as u8; 32]),
        transactions: txs,
    }
}

fn build(path: &std::path::Path, blocks: &[Vec<Transaction>], legacy: bool) -> IndexerStore {
    let (store, _) = IndexerStore::open(path).unwrap();
    let mut checkpoint = IndexerMeta::empty();
    for (i, txs) in blocks.iter().enumerate() {
        let b = block(txs, i + 1);
        checkpoint = if legacy {
            let write = store.begin_write().unwrap();
            let applied = apply_block_with_derivation(
                &write,
                store.rollback_window(),
                &checkpoint,
                &b,
                &mut BlockApplyScratch::new(),
                old_template,
                old_token,
            )
            .unwrap();
            write.commit().unwrap();
            applied.meta
        } else {
            apply_block(&store, &checkpoint, &b).unwrap()
        };
    }
    if legacy {
        let write = store.begin_write().unwrap();
        meta::write_schema_version(&write, 2).unwrap();
        write.commit().unwrap();
    }
    store
}

type Rows = BTreeMap<String, Vec<(Vec<u8>, Vec<u8>)>>;
fn snapshot(store: &IndexerStore) -> Rows {
    let read = store.db.begin_read().unwrap();
    read.list_tables()
        .unwrap()
        .map(|handle| {
            let name = handle.name().to_owned();
            let rows = match name.as_str() {
                "indexer_meta" => read
                    .open_table(super::super::tables::INDEXER_META)
                    .unwrap()
                    .iter()
                    .unwrap()
                    .map(|r| {
                        let (k, v) = r.unwrap();
                        (k.value().as_bytes().to_vec(), v.value().to_vec())
                    })
                    .collect(),
                "indexer_undo" => read
                    .open_table(INDEXER_UNDO)
                    .unwrap()
                    .iter()
                    .unwrap()
                    .map(|r| {
                        let (k, v) = r.unwrap();
                        (k.value().to_be_bytes().to_vec(), v.value().to_vec())
                    })
                    .collect(),
                "unspent_by_creation_height" => read
                    .open_table(super::super::storage_rent::UNSPENT_BY_CREATION_HEIGHT)
                    .unwrap()
                    .iter()
                    .unwrap()
                    .map(|r| {
                        let (k, v) = r.unwrap();
                        let (height, index) = k.value();
                        (
                            [
                                height.to_be_bytes().as_slice(),
                                index.to_be_bytes().as_slice(),
                            ]
                            .concat(),
                            v.value().to_vec(),
                        )
                    })
                    .collect(),
                _ => read
                    .open_table(TableDefinition::<&[u8], &[u8]>::new(&name))
                    .unwrap()
                    .iter()
                    .unwrap()
                    .map(|r| {
                        let (k, v) = r.unwrap();
                        (k.value().to_vec(), v.value().to_vec())
                    })
                    .collect(),
            };
            (name, rows)
        })
        .collect()
}

#[test]
fn schema_two_migration_matches_every_table() {
    let tmp = tempfile::tempdir().unwrap();
    let blocks = blocks();
    let fresh = build(&tmp.path().join("fresh.redb"), &blocks, false);
    let path = tmp.path().join("legacy.redb");
    let legacy = build(&path, &blocks, true);
    assert_ne!(snapshot(&legacy), snapshot(&fresh));
    drop(legacy);
    let (migrated, outcome) = IndexerStore::open(&path).unwrap();
    assert_eq!(
        outcome,
        OpenOutcome::Migrated {
            previous_version: 2
        }
    );
    assert_eq!(snapshot(&migrated), snapshot(&fresh));
}

#[test]
fn schema_two_rollback_matches_fresh_across_migrated_blocks() {
    let tmp = tempfile::tempdir().unwrap();
    let blocks = blocks();
    let fresh = build(&tmp.path().join("fresh.redb"), &blocks, false);
    let path = tmp.path().join("legacy.redb");
    drop(build(&path, &blocks, true));
    let (migrated, _) = IndexerStore::open(&path).unwrap();
    for i in (0..blocks.len()).rev() {
        let b = block(&blocks[i], i + 1);
        for store in [&migrated, &fresh] {
            crate::rollback::rollback_one_block(store, &store.read_meta().unwrap(), &b).unwrap();
        }
        assert_eq!(
            snapshot(&migrated),
            snapshot(&fresh),
            "rollback height {}",
            i + 1
        );
    }
}

#[test]
fn schema_two_migration_failure_is_atomic_and_open_rebuilds_corruption() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("legacy.redb");
    let store = build(&path, &blocks(), true);
    let before_rows = snapshot(&store);
    // Windows byte-range locks are mandatory, so the open database blocks raw
    // reads there; every table's rows are still compared on all platforms.
    #[cfg(not(windows))]
    let before_bytes = std::fs::read(&path).unwrap();
    let mut writes = 0;
    let result = migrate_observed(&store.db, &mut || {
        writes += 1;
        if writes == 2 {
            Err(invalid("injected failure after metadata writes"))
        } else {
            Ok(())
        }
    });
    assert!(result.is_err());
    assert_eq!(writes, 2);
    assert_eq!(snapshot(&store), before_rows);
    #[cfg(not(windows))]
    assert_eq!(std::fs::read(&path).unwrap(), before_bytes);
    drop(store);
    let (rebuilt, outcome) = IndexerStore::open_with_migration(&path, 1024 * 1024, |db| {
        migrate_observed(db, &mut || Err(invalid("injected open migration failure")))
    })
    .unwrap();
    assert_eq!(
        outcome,
        OpenOutcome::WipedAndRecreated {
            previous_version: 2
        }
    );
    assert_eq!(rebuilt.read_meta().unwrap(), IndexerMeta::empty());
}

#[test]
fn schema_two_missing_or_undecodable_issuing_box_rebuilds() {
    for missing in [true, false] {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("legacy.redb");
        let store = build(&path, &blocks(), true);
        // Make the migration persistently unserviceable: its issuing
        // box cannot be decoded. Open must rebuild rather than publish schema 3.
        let issuing = store
            .read_token(&Digest32::from_bytes([2; 32]))
            .unwrap()
            .unwrap()
            .creating_box_id
            .unwrap();
        let write = store.begin_write().unwrap();
        {
            let mut boxes = write.open_table(INDEXED_BOX).unwrap();
            if missing {
                boxes.remove(issuing.as_bytes().as_slice()).unwrap();
            } else {
                boxes
                    .insert(issuing.as_bytes().as_slice(), [0xff].as_slice())
                    .unwrap();
            }
        }
        write.commit().unwrap();
        drop(store);
        let (rebuilt, outcome) = IndexerStore::open(&path).unwrap();
        assert_eq!(
            outcome,
            OpenOutcome::WipedAndRecreated {
                previous_version: 2
            }
        );
        assert_eq!(rebuilt.read_meta().unwrap(), IndexerMeta::empty());
    }
}

fn boot_legacy(path: &std::path::Path) -> crate::IndexerHandle {
    let start = Instant::now();
    let handle = crate::IndexerHandle::boot(
        &crate::IndexerConfig {
            enabled: true,
            ..crate::IndexerConfig::default()
        },
        path,
    );
    assert!(
        start.elapsed() < Duration::from_secs(1),
        "boot performed conversion"
    );
    let handle = handle.unwrap();
    use ergo_indexer_types::IndexerQuery;
    assert_eq!(
        handle.status(),
        ergo_indexer_types::IndexerStatus::Migrating
    );
    assert!(handle.store().is_none());
    assert_eq!(handle.health().unwrap().global_boxes, 0);
    handle
}

struct MigrationChain;
impl crate::IndexerChainSource for MigrationChain {
    fn committed_tip(&self) -> Result<crate::ChainTip, IndexerError> {
        Ok(crate::ChainTip {
            height: 4,
            header_id: Digest32::from_bytes([4; 32]),
        })
    }
    fn header_id_at(&self, height: u32) -> Result<Option<Digest32>, IndexerError> {
        Ok((1..=4)
            .contains(&height)
            .then(|| Digest32::from_bytes([height as u8; 32])))
    }
    fn best_header_id_at(&self, height: u32) -> Result<Option<Digest32>, IndexerError> {
        self.header_id_at(height)
    }
    fn full_block(&self, id: &Digest32) -> Result<Option<crate::IndexerFullBlock>, IndexerError> {
        Ok(Some(crate::IndexerFullBlock {
            height: i32::from(id.as_bytes()[0]),
            header_id: *id,
            transactions: vec![],
        }))
    }
}

fn wait_ready(handle: &crate::IndexerHandle) {
    use ergo_indexer_types::{IndexerQuery, IndexerStatus};
    let start = Instant::now();
    while handle.status() != IndexerStatus::CaughtUp {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "worker failed to become ready: {:?}",
            handle.status()
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(handle.indexed_height(), 4);
}

#[test]
fn schema_two_boot_defers_migration_then_worker_preserves_and_advances() {
    use ergo_indexer_types::IndexerQuery;
    use std::sync::{atomic::AtomicBool, Arc};
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("indexer.redb");
    let legacy = build(&path, &blocks(), true);
    let box_count = legacy.read_meta().unwrap().global_box_index;
    drop(legacy);
    let handle = boot_legacy(tmp.path());
    assert_eq!(handle.indexed_height(), 3);
    let worker = crate::IndexerTask::new(handle.clone(), Arc::new(MigrationChain))
        .spawn(Arc::new(AtomicBool::new(false)), Duration::from_millis(50))
        .unwrap();
    wait_ready(&handle);
    assert_eq!(
        handle
            .store()
            .unwrap()
            .read_meta()
            .unwrap()
            .global_box_index,
        box_count
    );
    worker.join().unwrap();
}

#[test]
fn direct_step_finishes_a_pending_migration_before_polling() {
    use ergo_indexer_types::IndexerQuery;
    use std::sync::Arc;
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("indexer.redb");
    let legacy = build(&path, &blocks(), true);
    let box_count = legacy.read_meta().unwrap().global_box_index;
    drop(legacy);
    let handle = boot_legacy(tmp.path());
    assert!(matches!(
        handle.status(),
        ergo_indexer_types::IndexerStatus::Migrating
    ));
    let mut task = crate::IndexerTask::new(handle.clone(), Arc::new(MigrationChain));
    let poll = task.step();
    assert!(
        !matches!(poll, crate::IndexerPoll::Halted(_)),
        "a direct step must migrate, not halt"
    );
    assert!(!matches!(
        handle.status(),
        ergo_indexer_types::IndexerStatus::Halted(_) | ergo_indexer_types::IndexerStatus::Migrating
    ));
    assert_eq!(
        handle
            .store()
            .unwrap()
            .read_meta()
            .unwrap()
            .global_box_index,
        box_count
    );
}

#[test]
fn schema_two_boot_failure_rebuilds_on_worker_without_blocking_boot() {
    use std::sync::{atomic::AtomicBool, Arc};
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("indexer.redb");
    let legacy = build(&path, &blocks(), true);
    let write = legacy.begin_write().unwrap();
    write
        .open_table(INDEXED_TOKEN)
        .unwrap()
        .insert([0; 32].as_slice(), [0xff].as_slice())
        .unwrap();
    write.commit().unwrap();
    drop(legacy);
    let handle = boot_legacy(tmp.path());
    let worker = crate::IndexerTask::new(handle.clone(), Arc::new(MigrationChain))
        .spawn(Arc::new(AtomicBool::new(false)), Duration::from_millis(50))
        .unwrap();
    wait_ready(&handle);
    assert_eq!(
        handle
            .store()
            .unwrap()
            .read_meta()
            .unwrap()
            .global_box_index,
        0,
        "fallback rebuilt from genesis"
    );
    worker.join().unwrap();
}

#[test]
fn schema_two_shutdown_aborts_staged_writes_and_next_boot_migrates() {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    };
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("indexer.redb");
    let legacy = build(&path, &blocks(), true);
    let before = snapshot(&legacy);
    drop(legacy);
    let handle = boot_legacy(tmp.path());
    let cancel = Arc::new(AtomicBool::new(false));
    let worker_handle = handle.clone();
    let worker_cancel = cancel.clone();
    let (staged_tx, staged_rx) = mpsc::channel();
    let (resume_tx, resume_rx) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        worker_handle.finish_boot_with(&worker_cancel, |store| {
            store.finish_migration_with(&worker_cancel, |db| {
                let mut first = true;
                migrate_cancellable_observed(db, &worker_cancel, &mut || {
                    if first {
                        first = false;
                        staged_tx.send(()).unwrap();
                        resume_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                    }
                    Ok(())
                })
            })
        })
    });
    staged_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let shutdown_start = Instant::now();
    cancel.store(true, Ordering::Release);
    resume_tx.send(()).unwrap();
    assert!(matches!(
        thread.join().unwrap(),
        Err(IndexerError::MigrationCancelled)
    ));
    assert!(shutdown_start.elapsed() < Duration::from_secs(1));
    assert!(handle.store().is_none());
    // Read without invoking the normal open policy (which would convert).
    let db = redb::Database::open(&path).unwrap();
    assert_eq!(
        meta::read_schema_version(&db.begin_read().unwrap()).unwrap(),
        Some(2)
    );
    let store = IndexerStore {
        db: Arc::new(db),
        repair_running: Arc::new(AtomicBool::new(false)),
        path: path.clone(),
        redb_cache_bytes: 1024 * 1024,
        rollback_window: super::super::ROLLBACK_WINDOW,
    };
    assert_eq!(snapshot(&store), before);
    drop(store);
    let handle = boot_legacy(tmp.path());
    let worker = crate::IndexerTask::new(handle.clone(), Arc::new(MigrationChain))
        .spawn(Arc::new(AtomicBool::new(false)), Duration::from_millis(50))
        .unwrap();
    wait_ready(&handle);
    worker.join().unwrap();
}

#[test]
fn schema_two_parallel_scan_matches_serial_additions_and_uses_workers() {
    use std::sync::Mutex;
    let tmp = tempfile::tempdir().unwrap();
    let legacy = build(&tmp.path().join("legacy.redb"), &blocks(), true);
    let total = legacy.read_meta().unwrap().global_box_index;
    // Pin the snapshot exactly as the migration does, including uncommitted writes.
    let write = legacy.begin_write().unwrap();
    meta::write_schema_version(&write, 3).unwrap();
    let read = legacy.db.begin_read().unwrap();
    let serial = scan_box_range(&read, 0..total, &|| Ok(())).unwrap();
    assert!(!serial.is_empty());
    for workers in [1, 2, 4, 7] {
        let threads = Mutex::new(HashSet::new());
        let log_path = tmp.path().join(format!("workers-{workers}.log"));
        let log = std::fs::File::create(&log_path).unwrap();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || log.try_clone().unwrap())
            .finish();
        let parallel = tracing::subscriber::with_default(subscriber, || {
            scan_boxes_parallel(&legacy.db, total, workers, &|| Ok(()), &|| {
                threads.lock().unwrap().insert(std::thread::current().id());
                tracing::info!("migration worker snapshot");
            })
        })
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(log_path)
                .unwrap()
                .matches("migration worker snapshot")
                .count(),
            workers
        );
        assert_eq!(
            threads.into_inner().unwrap().len(),
            workers,
            "scan must use the requested workers"
        );
        assert_eq!(parallel, serial);
        for entries in parallel.values() {
            assert!(entries.windows(2).all(|pair| pair[0].abs() < pair[1].abs()));
        }
    }
    assert_eq!(meta::read_schema_version(&read).unwrap(), Some(2));
}

fn migrate_copy(source: &std::path::Path) -> tempfile::TempDir {
    let target = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("target");
    std::fs::create_dir_all(&target).unwrap();
    let copy = tempfile::Builder::new()
        .prefix("indexer-schema-bench-")
        .tempdir_in(target)
        .unwrap();
    let path = copy.path().join("indexer.redb");
    let copy_start = Instant::now();
    let bytes =
        std::fs::copy(source, &path).expect("copy index; source is never opened for writing");
    eprintln!(
        "copy: {bytes} bytes in {:.3}s -> {}",
        copy_start.elapsed().as_secs_f64(),
        path.display()
    );
    let open_start = Instant::now();
    let (store, outcome) =
        IndexerStore::open_for_boot(&path, ergo_state::DEFAULT_REDB_CACHE_BYTES).unwrap();
    assert_eq!(
        outcome,
        OpenOutcome::MigrationPending,
        "source must be a redb-4 schema-2 index"
    );
    eprintln!("open: {:.3}s", open_start.elapsed().as_secs_f64());
    let before = store.read_meta().unwrap();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_max_level(tracing::Level::INFO)
        .finish();
    // Use the migration directly: failures must fail the benchmark, not rebuild its copy.
    tracing::subscriber::with_default(subscriber, || migrate_schema_2_to_3(&store.db)).unwrap();
    assert_eq!(
        store.read_meta().unwrap(),
        before,
        "checkpoint must be preserved"
    );
    assert_eq!(
        meta::read_schema_version(&store.db.begin_read().unwrap()).unwrap(),
        Some(3)
    );
    eprintln!(
        "preserved: height={}, boxes={}, transactions={}",
        before.indexed_height, before.global_box_index, before.global_tx_index
    );
    drop(store);
    copy
}

#[test]
fn schema_two_copy_harness_never_changes_source() {
    let tmp = tempfile::tempdir().unwrap();
    let source = tmp.path().join("source.redb");
    drop(build(&source, &blocks(), true));
    let before = std::fs::read(&source).unwrap();
    let copy = migrate_copy(&source);
    assert!(
        std::fs::read(&source).unwrap() == before,
        "harness changed source bytes"
    );
    let (migrated, outcome) = IndexerStore::open(&copy.path().join("indexer.redb")).unwrap();
    assert_eq!(outcome, OpenOutcome::Resumed);
    assert_eq!(migrated.read_meta().unwrap().indexed_height, 3);
}

#[test]
#[ignore = "copies ERGO_INDEXER_MIGRATION_SOURCE into worktree target before benchmarking"]
fn schema_two_real_data_copy_benchmark() {
    let source = std::env::var_os("ERGO_INDEXER_MIGRATION_SOURCE")
        .expect("set ERGO_INDEXER_MIGRATION_SOURCE to an offline redb-4 schema-2 index");
    let copy = migrate_copy(std::path::Path::new(&source));
    eprintln!("migrated copy retained at {}", copy.keep().display());
}
