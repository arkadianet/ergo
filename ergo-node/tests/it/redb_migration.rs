//! Real redb 2.6 files must reopen through the production store APIs after the
//! offline migration. Application rows come from the actual store writers;
//! real redb 2.6 serializes the old-format fixture, never a fabricated header.

use std::fs;
use std::path::Path;
use std::time::SystemTime;

use clap::Parser;
use ergo_indexer::store::{IndexerMeta, IndexerStore, OpenOutcome, UndoEntry};
use ergo_node::config::{Cli, Command, NodeConfig};
use ergo_p2p::address_book::{AddressBook, BanRecord, LastDirection};
use ergo_primitives::digest::Digest32;
use ergo_state::reader::ChainStoreReader;
use ergo_state::redb_migration::migrate_database;
use ergo_state::store::StateStore;
use redb::{ReadableDatabase, ReadableTable, TableDefinition, TableHandle};

// Copy typed values from the actual application writer to the actual legacy
// writer. This helper is fixture generation only; production migration never
// reconstructs the source or opens it through either database version.
fn legacy_fixture(current: &Path, legacy: &Path) {
    let current = redb::Database::open(current).unwrap();
    let read = current.begin_read().unwrap();
    let legacy = redb_legacy::Database::builder()
        .set_cache_size(1024 * 1024)
        .create(legacy)
        .unwrap();
    let write = legacy.begin_write().unwrap();
    for handle in read.list_tables().unwrap() {
        let name = handle.name();
        let mut copied = false;
        macro_rules! copy {
            ($key:ty, $value:ty) => {
                if !copied {
                    match read.open_table(TableDefinition::<$key, $value>::new(name)) {
                        Ok(table) => {
                            let mut old = write
                                .open_table(redb_legacy::TableDefinition::<$key, $value>::new(name))
                                .unwrap();
                            for row in table.iter().unwrap() {
                                let (key, value) = row.unwrap();
                                old.insert(key.value(), value.value()).unwrap();
                            }
                            copied = true;
                        }
                        Err(redb::TableError::TableTypeMismatch { .. }) => {}
                        Err(error) => panic!("cannot export {name}: {error}"),
                    }
                }
            };
        }
        copy!(u64, &[u8]);
        copy!(&[u8], &[u8]);
        copy!(&str, &[u8]);
        copy!(&[u8], u8);
        copy!(&[u8], u32);
        copy!(&str, u64);
        copy!((u32, i64), &[u8]);
        copy!((), u32);
        copy!((), [u8; 32]);
        copy!([u8; 32], Vec<u8>);
        copy!([u8; 34], [u8; 32]);
        copy!([u8; 36], Vec<u8>);
        copy!((), u64);
        copy!([u8; 41], Vec<u8>);
        copy!(u32, [u8; 33]);
        copy!((), [u8; 33]);
        copy!(u16, Vec<u8>);
        copy!((), u16);
        copy!([u8; 34], Vec<u8>);
        copy!((), bool);
        copy!((), Vec<u8>);
        assert!(copied, "uncovered application table {name}");
    }
    write.commit().unwrap();
}

#[test]
fn migrated_state_reopens_with_mainnet_genesis_metadata_and_wallet_rows() {
    let dir = tempfile::tempdir().unwrap();
    let current = dir.path().join("current.redb");
    let legacy = dir.path().join("legacy.redb");
    let migrated = dir.path().join("migrated.redb");
    let genesis = ergo_node::genesis::mainnet_genesis_boxes();
    let root = {
        let mut state = StateStore::open_with_cache(&current, 1024 * 1024).unwrap();
        state.initialize_genesis(&genesis).unwrap();
        let db = state.db_arc();
        let write = ergo_state::begin_write_qr(&db).unwrap();
        write
            .open_table(ergo_state::wallet::tables::WALLET_SCAN_HEIGHT)
            .unwrap()
            .insert((), 0)
            .unwrap();
        write
            .open_table(ergo_state::wallet::tables::WALLET_SCAN_INVALIDATED)
            .unwrap()
            .insert((), true)
            .unwrap();
        write.commit().unwrap();
        *state.root_digest().as_bytes()
    };
    assert_eq!(root, ergo_chain_spec::GenesisParams::mainnet().state_digest);
    legacy_fixture(&current, &legacy);
    let bytes = fs::read(&legacy).unwrap();
    assert!(StateStore::open_with_cache(&legacy, 1024 * 1024).is_err());
    assert_eq!(
        fs::read(&legacy).unwrap(),
        bytes,
        "normal startup must fail closed"
    );
    migrate_database(&legacy, &migrated).unwrap();
    let mut state = StateStore::open_with_cache(&migrated, 1024 * 1024).unwrap();
    assert_eq!(state.height(), 0);
    assert!(state.genesis_committed());
    assert_eq!(*state.root_digest().as_bytes(), root);
    let reader = ChainStoreReader::new_from_db(state.db_arc());
    for (id, bytes) in genesis {
        assert_eq!(reader.lookup_box(&id).unwrap(), Some(bytes));
    }
    let db = state.db_arc();
    let read = db.begin_read().unwrap();
    assert_eq!(
        read.open_table(ergo_state::wallet::tables::WALLET_SCAN_HEIGHT)
            .unwrap()
            .get(())
            .unwrap()
            .unwrap()
            .value(),
        0
    );
    assert!(read
        .open_table(ergo_state::wallet::tables::WALLET_SCAN_INVALIDATED)
        .unwrap()
        .get(())
        .unwrap()
        .unwrap()
        .value());
    assert_eq!(fs::read(&legacy).unwrap(), bytes);
}

#[test]
fn migrated_indexer_resumes_metadata_undo_and_fixed_width_tuple_index() {
    let dir = tempfile::tempdir().unwrap();
    let current = dir.path().join("current.redb");
    let legacy = dir.path().join("legacy.redb");
    let migrated = dir.path().join("migrated.redb");
    let meta = IndexerMeta {
        indexed_height: 23,
        indexed_header_id: Some(Digest32::from_bytes([1; 32])),
        global_tx_index: 29,
        global_box_index: 31,
    };
    let undo = UndoEntry {
        prev_indexed_header_id: Some(Digest32::from_bytes([2; 32])),
        prev_global_tx_index: 19,
        prev_global_box_index: 21,
    };
    {
        let (store, _) = IndexerStore::open_with_cache(&current, 1024 * 1024).unwrap();
        store.commit_apply_meta_only(&meta, 23, &undo).unwrap();
    }
    {
        let db = redb::Database::open(&current).unwrap();
        let write = ergo_state::begin_write_qr(&db).unwrap();
        write
            .open_table(TableDefinition::<(u32, i64), &[u8]>::new(
                "unspent_by_creation_height",
            ))
            .unwrap()
            .insert((23, 7), [3; 32].as_slice())
            .unwrap();
        write.commit().unwrap();
    }
    legacy_fixture(&current, &legacy);
    let bytes = fs::read(&legacy).unwrap();
    assert!(IndexerStore::open_with_cache(&legacy, 1024 * 1024).is_err());
    assert_eq!(fs::read(&legacy).unwrap(), bytes);
    migrate_database(&legacy, &migrated).unwrap();
    {
        let (store, outcome) = IndexerStore::open_with_cache(&migrated, 1024 * 1024).unwrap();
        assert_eq!(outcome, OpenOutcome::Resumed);
        assert_eq!(store.read_meta().unwrap(), meta);
        assert_eq!(store.read_undo(23).unwrap(), Some(undo));
    }
    let db = redb::Database::open(&migrated).unwrap();
    let read = db.begin_read().unwrap();
    assert_eq!(
        read.open_table(TableDefinition::<(u32, i64), &[u8]>::new(
            "unspent_by_creation_height"
        ))
        .unwrap()
        .get((23, 7))
        .unwrap()
        .unwrap()
        .value(),
        &[3; 32]
    );
    assert_eq!(fs::read(&legacy).unwrap(), bytes);
}

#[test]
fn migrated_peers_preserve_records_bans_schema_and_reject_unsupported_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let current = dir.path().join("current.redb");
    let legacy = dir.path().join("legacy.redb");
    let migrated = dir.path().join("migrated.redb");
    let addr = "1.2.3.4:9030".parse().unwrap();
    let ban_ip = "5.6.7.8".parse().unwrap();
    {
        let book = AddressBook::open_at_with_cache(&current, 1024 * 1024).unwrap();
        book.upsert_handshaked(
            addr,
            "reference",
            [6, 0, 7],
            "migration-test",
            LastDirection::Outbound,
            SystemTime::now(),
        )
        .unwrap();
        book.record_ban(&BanRecord {
            ip: ban_ip,
            until: SystemTime::now(),
            count: 7,
            permanent: true,
            operator: true,
        })
        .unwrap();
    }
    legacy_fixture(&current, &legacy);
    let bytes = fs::read(&legacy).unwrap();
    assert!(AddressBook::open_at_with_cache(&legacy, 1024 * 1024).is_err());
    assert_eq!(fs::read(&legacy).unwrap(), bytes);
    assert!(!fs::read_dir(dir.path()).unwrap().any(|e| e
        .unwrap()
        .file_name()
        .to_string_lossy()
        .contains("corrupt-")));
    migrate_database(&legacy, &migrated).unwrap();
    let book = AddressBook::open_at_with_cache(&migrated, 1024 * 1024).unwrap();
    let loaded = book.load_all(false).unwrap();
    assert_eq!(loaded.peers.len(), 1);
    assert_eq!(loaded.peers[0].addr, addr);
    assert_eq!(loaded.peers[0].agent_name, "reference");
    assert_eq!(loaded.peers[0].node_name, "migration-test");
    assert_eq!(
        loaded.peers[0].last_direction,
        Some(LastDirection::Outbound)
    );
    assert_eq!(loaded.bans.len(), 1);
    assert_eq!(loaded.bans[0].ip, ban_ip);
    assert_eq!(loaded.bans[0].count, 7);
    assert!(loaded.bans[0].permanent);
    assert_eq!(fs::read(&legacy).unwrap(), bytes);
}

#[test]
fn offline_command_requires_both_paths_and_never_loads_node_configuration() {
    let cli = Cli::try_parse_from(["ergo-node", "migrate-redb", "old.redb", "new.redb"]).unwrap();
    assert!(
        matches!(&cli.command, Some(Command::MigrateRedb { source, destination }) if source == Path::new("old.redb") && destination == Path::new("new.redb"))
    );
    assert!(NodeConfig::load(cli).unwrap_err().contains("offline"));
    assert!(Cli::try_parse_from(["ergo-node", "migrate-redb", "old.redb"]).is_err());
    assert!(Cli::try_parse_from([
        "ergo-node",
        "--data-dir",
        "unused",
        "migrate-redb",
        "old.redb",
        "new.redb"
    ])
    .is_err());
}

#[test]
fn packaged_operator_binary_migrates_without_config_or_node_startup() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("legacy.redb");
    let destination = dir.path().join("migrated.redb");
    {
        let db = redb_legacy::Database::create(&source).unwrap();
        let txn = db.begin_write().unwrap();
        txn.open_table(redb_legacy::TableDefinition::<&str, u64>::new("meta"))
            .unwrap()
            .insert("schema_version", 1)
            .unwrap();
        txn.commit().unwrap();
    }
    let bytes = fs::read(&source).unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_ergo-node"))
        .current_dir(dir.path())
        .arg("migrate-redb")
        .arg(&source)
        .arg(&destination)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("verified migration"));
    assert_eq!(fs::read(&source).unwrap(), bytes);
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_ergo-node"))
        .current_dir(dir.path())
        .arg("migrate-redb")
        .arg(&source)
        .arg(&destination)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("already exists"));
    assert!(!dir.path().join("ergo-data").exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_boot_refuses_mixed_current_state_and_unsupported_peer_formats() {
    for version in [2, 4] {
        let dir = tempfile::tempdir().unwrap();
        let peer_path = dir.path().join("peers.redb");
        let current_peers = dir.path().join("fixture-peers.redb");
        let state_path = dir.path().join("state.redb");
        {
            let mut state = StateStore::open_with_cache(&state_path, 1024 * 1024).unwrap();
            state
                .initialize_genesis(&ergo_node::genesis::mainnet_genesis_boxes())
                .unwrap();
        }
        {
            let book = AddressBook::open_at_with_cache(&current_peers, 1024 * 1024).unwrap();
            book.record_ban(&BanRecord {
                ip: "5.6.7.8".parse().unwrap(),
                until: SystemTime::now(),
                count: 7,
                permanent: true,
                operator: true,
            })
            .unwrap();
        }
        if version == 2 {
            legacy_fixture(&current_peers, &peer_path);
        } else {
            fs::copy(&current_peers, &peer_path).unwrap();
            let mut bytes = fs::read(&peer_path).unwrap();
            // Exercise the second slot alone: both version offsets must be
            // checked before deciding this is recoverable corruption.
            bytes[192] = 4;
            fs::write(&peer_path, bytes).unwrap();
        }
        let bytes = fs::read(&peer_path).unwrap();
        let mut config = super::common::make_test_config(dir.path().to_path_buf());
        config.auto_upgrade_legacy = false;
        config.cache_bytes = Some(1024 * 1024);
        config.redb_cache_budgets.state = 1024 * 1024;
        config.redb_cache_budgets.peers = 1024 * 1024;
        let error = match ergo_node::run_inner(config).await {
            Err(error) => error,
            Ok(handle) => {
                handle.shutdown().await.unwrap();
                panic!("boot must refuse unsupported peer format {version}");
            }
        };
        let error = error.to_string();
        if version == 2 {
            assert!(error.contains("ergo-node upgrade-data"), "{error}");
        } else {
            assert!(
                error.contains("cannot classify") && error.contains("4"),
                "{error}"
            );
        }
        assert!(fs::read(&peer_path).unwrap() == bytes);
        assert!(!fs::read_dir(dir.path()).unwrap().any(|e| e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains("corrupt-")));
    }
}

fn directory_upgrade_fixture(directory: &Path, schema: u32) -> Vec<(String, Vec<u8>)> {
    let source = tempfile::tempdir().unwrap();
    {
        let mut state =
            StateStore::open_with_cache(&source.path().join("state.redb"), 1024 * 1024).unwrap();
        state
            .initialize_genesis(&ergo_node::genesis::mainnet_genesis_boxes())
            .unwrap();
        state.verify_or_init_state_type("utxo").unwrap();
        let db = state.db_arc();
        let write = ergo_state::begin_write_qr(&db).unwrap();
        write
            .open_table(ergo_state::wallet::tables::WALLET_SCAN_HEIGHT)
            .unwrap()
            .insert((), 0)
            .unwrap();
        write
            .open_table(ergo_state::wallet::tables::WALLET_SCAN_INVALIDATED)
            .unwrap()
            .insert((), true)
            .unwrap();
        write.commit().unwrap();
    }
    {
        let book = AddressBook::open_at_with_cache(&source.path().join("peers.redb"), 1024 * 1024)
            .unwrap();
        book.upsert_handshaked(
            "1.2.3.4:9030".parse().unwrap(),
            "reference",
            [6, 0, 7],
            "upgrade-test",
            LastDirection::Outbound,
            SystemTime::now(),
        )
        .unwrap();
    }
    {
        let db = redb::Database::create(source.path().join("webhooks.redb")).unwrap();
        let write = ergo_state::begin_write_qr(&db).unwrap();
        write
            .open_table(TableDefinition::<&str, &[u8]>::new("webhook_snapshot_v1"))
            .unwrap()
            .insert("snapshot", b"webhook registrations".as_slice())
            .unwrap();
        write.commit().unwrap();
    }
    drop(
        IndexerStore::open_with_cache(&source.path().join("archive-index.redb"), 1024 * 1024)
            .unwrap(),
    );
    let mut originals = Vec::new();
    for name in [
        "state.redb",
        "peers.redb",
        "webhooks.redb",
        "archive-index.redb",
    ] {
        let path = directory.join(name);
        legacy_fixture(&source.path().join(name), &path);
        if name == "archive-index.redb" {
            let db = redb_legacy::Database::open(&path).unwrap();
            let write = db.begin_write().unwrap();
            write
                .open_table(redb_legacy::TableDefinition::<&str, &[u8]>::new(
                    "indexer_meta",
                ))
                .unwrap()
                .insert("schema_version", schema.to_be_bytes().as_slice())
                .unwrap();
            write.commit().unwrap();
        }
        originals.push((name.to_string(), fs::read(path).unwrap()));
    }
    originals
}

fn assert_upgraded_directory(
    directory: &Path,
    originals: &[(String, Vec<u8>)],
    stale: bool,
    discard: bool,
) {
    for (name, bytes) in originals {
        let backup = directory.join(format!("{name}.redb2-backup"));
        assert_eq!(backup.exists(), !discard);
        if !discard {
            assert_eq!(fs::read(backup).unwrap(), *bytes);
        }
        if name == "archive-index.redb" && stale {
            assert!(!directory.join(name).exists());
        } else {
            redb::ReadOnlyDatabase::open(directory.join(name)).unwrap();
        }
    }
    let mut state =
        StateStore::open_with_cache(&directory.join("state.redb"), 1024 * 1024).unwrap();
    assert_eq!(
        *state.root_digest().as_bytes(),
        ergo_chain_spec::GenesisParams::mainnet().state_digest
    );
    let reader = ChainStoreReader::new_from_db(state.db_arc());
    for (id, bytes) in ergo_node::genesis::mainnet_genesis_boxes() {
        assert_eq!(reader.lookup_box(&id).unwrap(), Some(bytes));
    }
    let db = state.db_arc();
    let read = db.begin_read().unwrap();
    assert!(read
        .open_table(ergo_state::wallet::tables::WALLET_SCAN_INVALIDATED)
        .unwrap()
        .get(())
        .unwrap()
        .unwrap()
        .value());
    assert_eq!(
        read.open_table(ergo_state::wallet::tables::WALLET_SCAN_HEIGHT)
            .unwrap()
            .get(())
            .unwrap()
            .unwrap()
            .value(),
        0
    );
    let peers = AddressBook::open_at_with_cache(&directory.join("peers.redb"), 1024 * 1024)
        .unwrap()
        .load_all(false)
        .unwrap();
    assert_eq!(peers.peers.len(), 1);
    assert_eq!(peers.peers[0].node_name, "upgrade-test");
    let db = redb::ReadOnlyDatabase::open(directory.join("webhooks.redb")).unwrap();
    assert_eq!(
        db.begin_read()
            .unwrap()
            .open_table(TableDefinition::<&str, &[u8]>::new("webhook_snapshot_v1"))
            .unwrap()
            .get("snapshot")
            .unwrap()
            .unwrap()
            .value(),
        b"webhook registrations"
    );
    if !stale {
        let (_, outcome) =
            IndexerStore::open_with_cache(&directory.join("archive-index.redb"), 1024 * 1024)
                .unwrap();
        assert_eq!(outcome, OpenOutcome::Resumed);
    }
}

#[test]
fn packaged_upgrade_data_command_upgrades_entire_directory_and_is_idempotent() {
    for (schema, discard) in [
        (2, false),
        (ergo_indexer::store::INDEXER_SCHEMA_VERSION, false),
        (2, true),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let originals = directory_upgrade_fixture(dir.path(), schema);
        let command = || {
            let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_ergo-node"));
            command
                .current_dir(dir.path())
                .arg("upgrade-data")
                .arg(dir.path())
                .args(["--indexer-db", "archive-index.redb"]);
            if discard {
                command.arg("--discard-backups");
            }
            command
        };
        let output = command().output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("databases migrated"));
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("tables") && stderr.contains("rows") && stderr.contains("bytes"),
            "{stderr}"
        );
        if discard {
            assert!(stderr.contains("external backup"));
        }
        assert_upgraded_directory(dir.path(), &originals, schema == 2, discard);
        let output = command().output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("no-op"));
        assert!(!dir.path().join("ergo-data").exists());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn startup_hook_upgrades_without_networking_and_disabled_switch_gives_guidance() {
    let dir = tempfile::tempdir().unwrap();
    let originals = directory_upgrade_fixture(dir.path(), 2);
    let mut config = super::common::make_test_config(dir.path().to_path_buf());
    config.indexer_config.db_filename = "archive-index.redb".into();
    config.auto_upgrade_legacy = false;
    let error = ergo_node::data_upgrade::prepare_startup(&config)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("ergo-node upgrade-data") && error.contains("archive-index.redb"),
        "{error}"
    );
    for (name, bytes) in &originals {
        assert_eq!(fs::read(dir.path().join(name)).unwrap(), *bytes);
    }
    config.auto_upgrade_legacy = true;
    let lock = ergo_node::data_upgrade::prepare_startup(&config)
        .await
        .unwrap();
    assert!(ergo_node::data_upgrade::DataDirectoryLock::acquire(dir.path()).is_err());
    assert_upgraded_directory(dir.path(), &originals, true, false);
    drop(lock);
    let lock = ergo_node::data_upgrade::prepare_startup(&config)
        .await
        .unwrap();
    assert_upgraded_directory(dir.path(), &originals, true, false);
    drop(lock);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn boot_hook_precedes_sentinel_peek_and_refuses_a_second_directory_owner() {
    let dir = tempfile::tempdir().unwrap();
    let original = directory_upgrade_fixture(dir.path(), 2);
    let mut config = super::common::make_test_config(dir.path().to_path_buf());
    config.indexer_config.db_filename = "archive-index.redb".into();
    config.cache_bytes = Some(1024 * 1024);
    config.redb_cache_budgets.state = 1024 * 1024;
    config.redb_cache_budgets.peers = 1024 * 1024;
    // Current application schema fails later in boot: this test never binds or
    // dials a network socket, but runs the actual pre-open production ordering.
    config.state_type = ergo_node::config::StateType::Digest;
    config.verify_transactions = false;
    config.blocks_to_keep = 0;
    config.mempool_config.enabled = false;
    let error = match ergo_node::run_inner(config).await {
        Err(error) => error.to_string(),
        Ok(handle) => {
            handle.shutdown().await.unwrap();
            panic!("UTXO sentinel must reject digest mode");
        }
    };
    assert!(error.contains("initialized for state backend"), "{error}");
    assert_upgraded_directory(dir.path(), &original, true, false);
    let lock = ergo_node::data_upgrade::DataDirectoryLock::acquire(dir.path()).unwrap();
    let config = super::common::make_test_config(dir.path().to_path_buf());
    let error = match ergo_node::run_inner(config).await {
        Err(error) => error.to_string(),
        Ok(handle) => {
            handle.shutdown().await.unwrap();
            panic!("second owner must fail");
        }
    };
    assert!(error.contains("data directory is in use"), "{error}");
    drop(lock);
}

