//! Reconcile-on-open coverage for `voted_params`.
//!
//! Scope is limited to the `StateStore::open()` reconcile path:
//! - Fresh-store genesis row write.
//! - Idempotency on a complete table.
//! - Filling a missing epoch row from chain_index + headers + block_sections.
//! - Loud failure on extra rows or missing prerequisites.
//!
//! The apply / rollback / reorg storage paths land voted_params via
//! `crate::active_params::insert` and `delete_above`, both fully
//! exercised by the unit tests in `ergo-state/src/active_params.rs`.
//! Atomicity is by construction: those calls live inside the same
//! `write_txn` that writes AVL + chain_index + state_meta, so they
//! commit-or-abort with everything else (the existing rollback/reorg
//! integration tests prove the txn-level atomicity for the rest of
//! that table set; voted_params inherits it).

use std::sync::Arc;

use ergo_primitives::digest::{blake2b256, Digest32, ModifierId};
use ergo_primitives::group_element::GroupElement;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::autolykos::AutolykosSolution;
use ergo_ser::extension::{write_extension, Extension, ExtensionField};
use ergo_ser::header::{write_header, Header};
use ergo_state::store::{StateError, StateStore};
use ergo_validation::{scala_launch, ActiveProtocolParameters};
use redb::{Database, ReadableTable, TableDefinition};

const VOTED_PARAMS: TableDefinition<u64, &[u8]> = TableDefinition::new("voted_params");
const HEADERS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("headers");
const BLOCK_SECTIONS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("block_sections");
const CHAIN_INDEX: TableDefinition<u64, &[u8]> = TableDefinition::new("chain_index");
const CHAIN_STATE_META: TableDefinition<&str, &[u8]> = TableDefinition::new("chain_state_meta");
const STATE_META: TableDefinition<&str, &[u8]> = TableDefinition::new("state_meta");

/// Pin the HCI backfill sentinel so the existing
/// `backfill_header_chain_index_if_needed` open-time pass becomes a
/// no-op. Without this, tests that pre-populate chain_state_meta with a
/// non-zero `best_header_height` would force HCI backfill to walk
/// HEADER_META, which we deliberately don't seed for these scenarios
/// (we're isolating the voted_params reconcile path).
fn install_hci_sentinel(db_path: &std::path::Path) {
    let db = Arc::new(Database::create(db_path).unwrap());
    let txn = ergo_state::begin_write_qr(&db).unwrap();
    {
        let mut t = txn.open_table(STATE_META).unwrap();
        t.insert("hci_version", [1u8].as_slice()).unwrap();
    }
    txn.commit().unwrap();
}

fn epoch_params(height: u32, input_cost: i32) -> ActiveProtocolParameters {
    let mut p = scala_launch();
    p.epoch_start_height = height;
    p.input_cost = input_cost;
    p
}

fn make_extension(header_id: &[u8; 32], params: &ActiveProtocolParameters) -> Extension {
    let mut fields = vec![
        ExtensionField {
            key: [0x00, 1],
            value: params.storage_fee_factor.to_be_bytes().to_vec(),
        },
        ExtensionField {
            key: [0x00, 2],
            value: params.min_value_per_byte.to_be_bytes().to_vec(),
        },
        ExtensionField {
            key: [0x00, 3],
            value: params.max_block_size.to_be_bytes().to_vec(),
        },
        ExtensionField {
            key: [0x00, 4],
            value: params.max_block_cost.to_be_bytes().to_vec(),
        },
        ExtensionField {
            key: [0x00, 5],
            value: params.token_access_cost.to_be_bytes().to_vec(),
        },
        ExtensionField {
            key: [0x00, 6],
            value: params.input_cost.to_be_bytes().to_vec(),
        },
        ExtensionField {
            key: [0x00, 7],
            value: params.data_input_cost.to_be_bytes().to_vec(),
        },
        ExtensionField {
            key: [0x00, 8],
            value: params.output_cost.to_be_bytes().to_vec(),
        },
        ExtensionField {
            key: [0x00, 123],
            value: (params.block_version as i32).to_be_bytes().to_vec(),
        },
    ];
    if let Some(v) = params.subblocks_per_block {
        fields.push(ExtensionField {
            key: [0x00, 9],
            value: v.to_be_bytes().to_vec(),
        });
    }
    Extension {
        header_id: ModifierId::from_bytes(*header_id),
        fields,
    }
}

/// Build a synthetic header that points at the given extension. The header
/// is not validated — we only need its `extension_root` to drive
/// `compute_section_id` during reconcile.
fn make_header(extension: &Extension) -> (Vec<u8>, [u8; 32], Header) {
    let extension_root = {
        let mut w = VlqWriter::new();
        write_extension(&mut w, extension).expect("synthetic extension fits wire bounds");
        let bytes = w.result();
        // Match the way ergo's section root works for our purposes here:
        // any 32-byte digest is fine — reconcile recomputes the section_id
        // from this exact value, then looks up block_sections at that key.
        // Using blake2b256 over the serialized extension is a reasonable
        // synthetic stand-in.
        Digest32::from_bytes(*blake2b256(&bytes).as_bytes())
    };
    let header = Header {
        version: 4,
        parent_id: ModifierId::from_bytes([0u8; 32]),
        ad_proofs_root: Digest32::from_bytes([0u8; 32]),
        state_root: ergo_primitives::digest::ADDigest::from_bytes([0u8; 33]),
        transactions_root: Digest32::from_bytes([0u8; 32]),
        timestamp: 1_700_000_000,
        n_bits: 0x1234_5678,
        height: 1024,
        extension_root,
        votes: [0u8; 3],
        unparsed_bytes: Vec::new(),
        solution: AutolykosSolution::V2 {
            pk: GroupElement::from_bytes([0x02; 33]),
            nonce: [0u8; 8],
        },
    };
    let mut w = VlqWriter::new();
    write_header(&mut w, &header).expect("synthetic header fits wire bounds");
    let header_bytes = w.result();
    let header_id = *blake2b256(&header_bytes).as_bytes();
    (header_bytes, header_id, header)
}

fn compute_extension_section_id(header_id: &[u8; 32], extension_root: &[u8; 32]) -> [u8; 32] {
    use ergo_ser::modifier_id::{compute_section_id, TYPE_EXTENSION};
    compute_section_id(TYPE_EXTENSION, header_id, extension_root)
}

/// Pre-populate chain_index, headers, block_sections so reconcile can
/// fill voted_params at `height`. Returns the header_id used.
fn seed_disk_for_reconcile_at(
    db_path: &std::path::Path,
    height: u32,
    params: &ActiveProtocolParameters,
) -> [u8; 32] {
    assert_eq!(height % 1024, 0);
    let db = Arc::new(Database::create(db_path).unwrap());

    // Build extension for these params, then a header pointing at it.
    let placeholder_id = [0xAAu8; 32];
    let extension = make_extension(&placeholder_id, params);
    let (header_bytes, header_id, header) = make_header(&extension);

    // Rebuild extension's header_id field to match the real header_id.
    let extension = make_extension(&header_id, params);
    let mut ext_buf = VlqWriter::new();
    write_extension(&mut ext_buf, &extension).expect("synthetic extension fits wire bounds");
    let extension_bytes = ext_buf.result();

    let section_id = compute_extension_section_id(&header_id, header.extension_root.as_bytes());

    let txn = ergo_state::begin_write_qr(&db).unwrap();
    {
        let mut h_table = txn.open_table(HEADERS).unwrap();
        h_table
            .insert(header_id.as_slice(), header_bytes.as_slice())
            .unwrap();

        let mut s_table = txn.open_table(BLOCK_SECTIONS).unwrap();
        s_table
            .insert(section_id.as_slice(), extension_bytes.as_slice())
            .unwrap();

        let mut c_table = txn.open_table(CHAIN_INDEX).unwrap();
        c_table.insert(height as u64, header_id.as_slice()).unwrap();

        // Set chain_state_meta so open() believes tip == height.
        let mut cs_table = txn.open_table(CHAIN_STATE_META).unwrap();
        let cs = ergo_state::chain::ChainStateMeta {
            best_header_id: header_id,
            best_header_height: height,
            best_header_score: vec![1u8],
            best_full_block_id: header_id,
            best_full_block_height: height,
            header_availability: ergo_state::chain::HeaderAvailability::Dense,
        };
        cs_table
            .insert("chain_state", cs.serialize().as_slice())
            .unwrap();
    }
    txn.commit().unwrap();
    drop(db);
    header_id
}

/// Read the set of keys present in voted_params at the given path.
fn read_voted_params_keys(db_path: &std::path::Path) -> Vec<u64> {
    let db = Arc::new(Database::create(db_path).unwrap());
    let r = db.begin_read().unwrap();
    let t = match r.open_table(VOTED_PARAMS) {
        Ok(t) => t,
        Err(redb::TableError::TableDoesNotExist(_)) => return Vec::new(),
        Err(e) => panic!("voted_params table: {e}"),
    };
    let mut keys = Vec::new();
    for entry in t.iter().unwrap() {
        let (k, _) = entry.unwrap();
        keys.push(k.value());
    }
    keys
}

fn read_voted_params_at(db_path: &std::path::Path, key: u64) -> Option<ActiveProtocolParameters> {
    let db = Arc::new(Database::create(db_path).unwrap());
    let r = db.begin_read().unwrap();
    let t = r.open_table(VOTED_PARAMS).ok()?;
    let guard = t.get(key).ok().flatten()?;
    Some(ActiveProtocolParameters::deserialize(guard.value()).unwrap())
}

// ----- happy path -----

#[test]
fn open_writes_genesis_row_on_fresh_store() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("state.redb");

    {
        let _store = StateStore::open(&db_path).unwrap();
    }

    let keys = read_voted_params_keys(&db_path);
    assert_eq!(keys, vec![0]);

    let row = read_voted_params_at(&db_path, 0).unwrap();
    assert_eq!(row, scala_launch());
}

#[test]
fn open_is_idempotent_when_table_already_complete() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("state.redb");

    {
        let _ = StateStore::open(&db_path).unwrap();
    }
    let keys_first = read_voted_params_keys(&db_path);

    {
        let _ = StateStore::open(&db_path).unwrap();
    }
    let keys_second = read_voted_params_keys(&db_path);

    assert_eq!(keys_first, vec![0]);
    assert_eq!(keys_second, vec![0]);
}

#[test]
fn open_fills_missing_epoch_row_from_block_sections() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("state.redb");

    let want = epoch_params(1024, 7777);
    seed_disk_for_reconcile_at(&db_path, 1024, &want);
    install_hci_sentinel(&db_path);

    {
        let _ = StateStore::open(&db_path).unwrap();
    }

    let keys = read_voted_params_keys(&db_path);
    assert_eq!(keys, vec![0, 1024]);

    let row = read_voted_params_at(&db_path, 1024).unwrap();
    assert_eq!(row.epoch_start_height, 1024);
    assert_eq!(row.input_cost, 7777);
}

#[test]
fn open_rejects_extra_voted_params_rows() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("state.redb");

    // Pre-write an out-of-range row at 99999 with tip = 0, so the
    // expected key set is {0} but actual contains {99999}.
    {
        let db = Arc::new(Database::create(&db_path).unwrap());
        let txn = ergo_state::begin_write_qr(&db).unwrap();
        {
            let bytes = epoch_params(99_999, 1).serialize().unwrap();
            let mut t = txn.open_table(VOTED_PARAMS).unwrap();
            t.insert(99_999u64, bytes.as_slice()).unwrap();
        }
        txn.commit().unwrap();
    }

    match StateStore::open(&db_path) {
        Err(StateError::VotedParamsExtraRows { extras }) => {
            assert_eq!(extras, vec![99_999]);
        }
        Err(other) => panic!("expected VotedParamsExtraRows, got Err({other:?})"),
        Ok(_) => panic!("expected VotedParamsExtraRows, got Ok"),
    }
}

#[test]
fn open_rejects_corrupt_voted_params_row_at_expected_key() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("state.redb");

    // Pre-write a row at key 0 whose bytes won't deserialize.
    {
        let db = Arc::new(Database::create(&db_path).unwrap());
        let txn = ergo_state::begin_write_qr(&db).unwrap();
        {
            let mut t = txn.open_table(VOTED_PARAMS).unwrap();
            // 4-byte height + count=0 + no entries → MissingRequired on decode.
            t.insert(0u64, &[0u8, 0, 0, 0, 0][..]).unwrap();
        }
        txn.commit().unwrap();
    }

    match StateStore::open(&db_path) {
        Err(StateError::VotedParamsRowCorrupt { height, .. }) => {
            assert_eq!(height, 0);
        }
        Err(other) => panic!("expected VotedParamsRowCorrupt, got Err({other:?})"),
        Ok(_) => panic!("expected VotedParamsRowCorrupt, got Ok"),
    }
}

#[test]
fn open_fails_loud_when_chain_index_missing_for_required_height() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("state.redb");

    // Set tip = 1024 in chain_state_meta but write NOTHING into
    // chain_index/headers/block_sections — reconcile must fail loud
    // rather than silently leave key 1024 unfilled.
    {
        let db = Arc::new(Database::create(&db_path).unwrap());
        let txn = ergo_state::begin_write_qr(&db).unwrap();
        {
            let cs = ergo_state::chain::ChainStateMeta {
                best_header_id: [0xCCu8; 32],
                best_header_height: 1024,
                best_header_score: vec![1u8],
                best_full_block_id: [0xCCu8; 32],
                best_full_block_height: 1024,
                header_availability: ergo_state::chain::HeaderAvailability::Dense,
            };
            let mut cs_table = txn.open_table(CHAIN_STATE_META).unwrap();
            cs_table
                .insert("chain_state", cs.serialize().as_slice())
                .unwrap();
        }
        txn.commit().unwrap();
    }
    install_hci_sentinel(&db_path);

    match StateStore::open(&db_path) {
        Err(StateError::VotedParamsMissingChainIndex { height }) => {
            assert_eq!(height, 1024);
        }
        Err(other) => panic!("expected VotedParamsMissingChainIndex, got Err({other:?})"),
        Ok(_) => panic!("expected VotedParamsMissingChainIndex, got Ok"),
    }
}
