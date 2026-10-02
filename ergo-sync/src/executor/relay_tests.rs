use super::tests::apply_empty_block;
use super::*;
use ergo_primitives::reader::VlqReader;
use ergo_primitives::{digest::ModifierId, writer::VlqWriter};
use ergo_ser::block_transactions::{write_block_transactions, BlockTransactions};
use ergo_ser::ergo_box::{serialize_ergo_box, ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::read_ergo_tree;
use ergo_ser::extension::{write_extension, Extension, ExtensionField};
use ergo_ser::header::read_header;
use ergo_ser::modifier_id::ExpectedSections;
use ergo_ser::register::{AdditionalRegisters, RegisterValue};
use ergo_ser::sigma_value::read_constant;
use ergo_state::store::StateStore;
use ergo_state::{BlockApply, HeaderSectionStore};
use ergo_validation::popow::algos::{pack_interlinks, update_interlinks};

// ----- helpers -----

#[derive(serde::Deserialize)]
struct GenesisBoxJson {
    value: u64,
    #[serde(rename = "ergoTree")]
    ergo_tree: String,
    #[serde(rename = "creationHeight")]
    creation_height: u32,
    #[serde(rename = "additionalRegisters", default)]
    additional_registers: std::collections::HashMap<String, String>,
    #[serde(rename = "transactionId")]
    transaction_id: String,
    index: u16,
}

fn parse_genesis_box(json: &GenesisBoxJson) -> ErgoBox {
    let tree_bytes = hex::decode(&json.ergo_tree).unwrap();
    let mut r = VlqReader::new(&tree_bytes);
    let ergo_tree = read_ergo_tree(&mut r).unwrap();
    let mut reg_vec: Vec<(usize, RegisterValue)> = Vec::new();
    for (key, val_hex) in &json.additional_registers {
        let reg_idx = match key.as_str() {
            "R4" => 0,
            "R5" => 1,
            "R6" => 2,
            "R7" => 3,
            "R8" => 4,
            "R9" => 5,
            _ => panic!("unknown register {key}"),
        };
        let val_bytes = hex::decode(val_hex).unwrap();
        let mut vr = VlqReader::new(&val_bytes);
        let (tpe, value) = read_constant(&mut vr).unwrap();
        reg_vec.push((reg_idx, RegisterValue { tpe, value }));
    }
    reg_vec.sort_by_key(|(idx, _)| *idx);
    let registers = AdditionalRegisters {
        registers: reg_vec.into_iter().map(|(_, rv)| rv).collect(),
    };
    let candidate = ErgoBoxCandidate::new(
        json.value,
        ergo_tree,
        json.creation_height,
        Vec::new(),
        registers,
    )
    .unwrap();
    let tx_id_bytes: [u8; 32] = hex::decode(&json.transaction_id)
        .unwrap()
        .try_into()
        .unwrap();
    ErgoBox {
        candidate,
        transaction_id: ModifierId::from_bytes(tx_id_bytes),
        index: json.index,
    }
}

fn init_genesis(store: &mut StateStore) {
    let genesis_data =
        std::fs::read_to_string("../test-vectors/mainnet/genesis_boxes.json").unwrap();
    let genesis_boxes: Vec<GenesisBoxJson> = serde_json::from_str(&genesis_data).unwrap();
    let boxes: Vec<([u8; 32], Vec<u8>)> = genesis_boxes
        .iter()
        .map(|json_box| {
            let ergo_box = parse_genesis_box(json_box);
            let box_id = ergo_box.box_id().unwrap();
            let serialized = serialize_ergo_box(&ergo_box).unwrap();
            (*box_id.as_bytes(), serialized)
        })
        .collect();
    store.initialize_genesis(&boxes).unwrap();
}

fn load_headers() -> Vec<serde_json::Value> {
    let data = std::fs::read_to_string("../test-vectors/mainnet/headers_1_10.json").unwrap();
    serde_json::from_str(&data).unwrap()
}

// Mainnet headers/transactions pin real full-block validation. Extensions are
// reconstructed from interlinks and checked against those headers' roots by
// process_block; this is a feedback test, not a codec oracle.
fn prepare_chain(store: &mut StateStore) -> Vec<[u8; 32]> {
    init_genesis(store);
    let headers = load_headers();
    let txs: Vec<serde_json::Value> = serde_json::from_str(include_str!(
        "../../../test-vectors/mainnet/transactions_1_10.json"
    ))
    .unwrap();
    let mut ids = Vec::new();
    let mut prev = None;
    let mut links = Vec::new();
    for height in 1..=3 {
        let row = &headers[height - 1];
        let bytes = hex::decode(row["bytes"].as_str().unwrap()).unwrap();
        let id: [u8; 32] = hex::decode(row["id"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let header = read_header(&mut VlqReader::new(&bytes)).unwrap();
        if let Some(parent) = prev.as_ref() {
            links = update_interlinks(parent, &links).unwrap();
        }
        store
            .store_validated_header(
                &id,
                &bytes,
                &ergo_state::chain::HeaderMeta {
                    parent_id: *header.parent_id.as_bytes(),
                    height: header.height,
                    cumulative_score: vec![height as u8],
                    pow_validity: 1,
                    timestamp: header.timestamp,
                },
                Some((height as u32, vec![height as u8])),
            )
            .unwrap();
        let tx_row = txs
            .iter()
            .find(|t| t["height"].as_u64() == Some(height as u64))
            .unwrap();
        let tx = ergo_ser::transaction::read_transaction(&mut VlqReader::new(
            &hex::decode(tx_row["bytes"].as_str().unwrap()).unwrap(),
        ))
        .unwrap();
        let sections = ExpectedSections::from_header(
            &id,
            header.transactions_root.as_bytes(),
            header.extension_root.as_bytes(),
            header.ad_proofs_root.as_bytes(),
        );
        let mut w = VlqWriter::new();
        write_block_transactions(
            &mut w,
            &BlockTransactions {
                header_id: ModifierId::from_bytes(id),
                transactions: vec![tx],
            },
        )
        .unwrap();
        store
            .store_block_section_typed(&sections.transactions_id, &w.result(), 102)
            .unwrap();
        let mut w = VlqWriter::new();
        write_extension(
            &mut w,
            &Extension {
                header_id: ModifierId::from_bytes(id),
                fields: pack_interlinks(&links)
                    .into_iter()
                    .map(|(key, value)| ExtensionField {
                        key: key.try_into().unwrap(),
                        value,
                    })
                    .collect(),
            },
        )
        .unwrap();
        store
            .store_block_section_typed(&sections.extension_id, &w.result(), 108)
            .unwrap();
        ids.push(id);
        prev = Some(header);
    }
    ids
}

// ----- happy path -----

#[test]
fn applied_feedback_sequential_batch_records_height_order_and_drains() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(&dir.path().join("state.redb")).unwrap();
    let ids = prepare_chain(&mut store);
    let mut store = ergo_state::StateBackendKind::Utxo(store);
    let mut executor = SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        DifficultyParams::mainnet(),
    );
    let mut coordinator = SyncCoordinator::new(0);
    executor.try_apply_next_blocks(&mut store, &mut coordinator, Instant::now(), None);
    assert_eq!(
        store.chain_state_meta().best_full_block_height,
        3,
        "fixture must really apply all three blocks: {:?}",
        executor.last_block_apply_error()
    );
    assert_eq!(
        executor.take_applied_blocks(),
        ids,
        "one id per successful apply in height order"
    );
    assert!(
        executor.take_applied_blocks().is_empty(),
        "drain must clear feedback"
    );
}

#[test]
fn applied_feedback_reorg_records_only_applied_new_branch() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(&dir.path().join("state.redb")).unwrap();
    let ids = prepare_chain(&mut store);
    // Validate the fixture chain, roll it back to the common genesis, then
    // seed an old synthetic branch using the established store fixture.
    // New-branch replay below goes through the real executor/validation.
    let mut store = ergo_state::StateBackendKind::Utxo(store);
    let mut executor = SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        DifficultyParams::mainnet(),
    );
    let mut coordinator = SyncCoordinator::new(0);
    executor.try_apply_next_blocks(&mut store, &mut coordinator, Instant::now(), None);
    assert_eq!(executor.take_applied_blocks(), ids);
    store.rollback_to(1, None, None).unwrap();
    let concrete = store.as_utxo_mut().unwrap();
    let old2 = apply_empty_block(concrete, 2, ids[0]);
    let old3 = apply_empty_block(concrete, 3, old2);
    for (height, id, parent) in [(2, old2, ids[0]), (3, old3, old2)] {
        let bytes = concrete.get_header(&id).unwrap().unwrap();
        let header = read_header(&mut VlqReader::new(&bytes)).unwrap();
        concrete
            .store_header_meta(
                &id,
                &ergo_state::chain::HeaderMeta {
                    parent_id: parent,
                    height,
                    cumulative_score: vec![(height - 1) as u8],
                    pow_validity: 1,
                    timestamp: header.timestamp,
                },
            )
            .unwrap();
    }
    concrete
        .test_force_set_best_header_unsafe(ids[2], 3, vec![9])
        .unwrap();
    concrete
        .test_force_put_header_chain_index(2, &ids[1])
        .unwrap();
    concrete
        .test_force_put_header_chain_index(3, &ids[2])
        .unwrap();
    assert_eq!(
        executor
            .rollback_full_chain_to_best_header(&mut store, &mut coordinator, None)
            .unwrap(),
        ReorgOutcome::Performed
    );
    assert_eq!(store.chain_state_meta().best_full_block_id, ids[0]);
    assert!(
        executor.take_applied_blocks().is_empty(),
        "rollback must not report an applied id"
    );
    executor.try_apply_next_blocks(&mut store, &mut coordinator, Instant::now(), None);
    assert_eq!(
        store.chain_state_meta().best_full_block_id,
        ids[2],
        "new branch must apply: {:?}",
        executor.last_block_apply_error()
    );
    let applied = executor.take_applied_blocks();
    assert_eq!(
        applied,
        ids[1..],
        "exactly new branch, excluding common ancestor and old tip {old3:?}"
    );
    assert!(executor.take_applied_blocks().is_empty());
}

#[test]
fn applied_feedback_non_draining_embedder_drops_oldest_at_cap() {
    let mut executor = SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        DifficultyParams::mainnet(),
    );
    let ids: Vec<[u8; 32]> = (0u32..4100)
        .map(|n| {
            let mut id = [0; 32];
            id[..4].copy_from_slice(&n.to_le_bytes());
            id
        })
        .collect();
    for id in &ids {
        executor.record_applied_block(*id);
    }
    assert_eq!(executor.take_applied_blocks(), ids[4..]);
    assert!(executor.take_applied_blocks().is_empty());
}

// A valid mainnet replacement branch, with a synthetic applied branch sharing
// block 1. Replacement blocks still go through the real block validator.
fn competing_fixture() -> (
    tempfile::TempDir,
    ergo_state::StateBackendKind,
    Vec<[u8; 32]>,
    [u8; 32],
) {
    let dir = tempfile::tempdir().unwrap();
    let mut concrete = StateStore::open(&dir.path().join("state.redb")).unwrap();
    let ids = prepare_chain(&mut concrete);
    let mut store = ergo_state::StateBackendKind::Utxo(concrete);
    let mut executor = SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        DifficultyParams::mainnet(),
    );
    let mut coordinator = SyncCoordinator::new(0);
    executor.try_apply_next_blocks(&mut store, &mut coordinator, Instant::now(), None);
    assert_eq!(store.chain_state_meta().best_full_block_id, ids[2]);
    store.rollback_to(1, None, None).unwrap();
    let concrete = store.as_utxo_mut().unwrap();
    let old2 = apply_empty_block(concrete, 2, ids[0]);
    let old3 = apply_empty_block(concrete, 3, old2);
    for (height, id, parent) in [(2, old2, ids[0]), (3, old3, old2)] {
        let raw = concrete.get_header(&id).unwrap().unwrap();
        let header = read_header(&mut VlqReader::new(&raw)).unwrap();
        concrete
            .store_header_meta(
                &id,
                &ergo_state::chain::HeaderMeta {
                    parent_id: parent,
                    height,
                    cumulative_score: vec![(height - 1) as u8],
                    pow_validity: 1,
                    timestamp: header.timestamp,
                },
            )
            .unwrap();
    }
    let raw = concrete.get_header(&ids[2]).unwrap().unwrap();
    let meta = concrete.get_header_meta(&ids[2]).unwrap().unwrap();
    concrete
        .store_validated_header(&ids[2], &raw, &meta, Some((3, vec![3])))
        .unwrap();
    (dir, store, ids, old3)
}

#[test]
fn missing_replacement_sections_preserve_tip_until_complete_better_chain() {
    let (_dir, mut store, ids, old3) = competing_fixture();
    let raw = store.get_header(&ids[2]).unwrap().unwrap();
    let header = read_header(&mut VlqReader::new(&raw)).unwrap();
    let expected = ExpectedSections::from_header(
        &ids[2],
        header.transactions_root.as_bytes(),
        header.extension_root.as_bytes(),
        header.ad_proofs_root.as_bytes(),
    );
    let saved = store
        .get_block_section(&expected.transactions_id)
        .unwrap()
        .unwrap();
    withhold_transactions(&store, expected.transactions_id);
    let mut executor = SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        DifficultyParams::mainnet(),
    );
    let mut coordinator = SyncCoordinator::new(3);
    executor.try_apply_next_blocks(&mut store, &mut coordinator, Instant::now(), None);
    assert_eq!(
        store.chain_state_meta().best_full_block_id,
        old3,
        "B2 only ties A3; B3 is unavailable"
    );
    store
        .store_block_section_typed(&expected.transactions_id, &saved, 102)
        .unwrap();
    executor.try_apply_next_blocks(&mut store, &mut coordinator, Instant::now(), None);
    assert_eq!(store.chain_state_meta().best_full_block_id, ids[2]);
    assert_eq!(executor.take_applied_blocks(), ids[1..]);
}

#[test]
fn shorter_heavier_available_chain_is_adopted_by_full_score() {
    let (_dir, mut store, ids, _old3) = competing_fixture();
    let concrete = store.as_utxo_mut().unwrap();
    let raw = concrete.get_header(&ids[1]).unwrap().unwrap();
    let mut meta = concrete.get_header_meta(&ids[1]).unwrap().unwrap();
    meta.cumulative_score = vec![9];
    concrete
        .store_validated_header(&ids[1], &raw, &meta, Some((2, vec![9])))
        .unwrap();
    // The stronger branch stops at B2; B3's body is unavailable.
    let raw3 = concrete.get_header(&ids[2]).unwrap().unwrap();
    let header3 = read_header(&mut VlqReader::new(&raw3)).unwrap();
    let sections3 = ExpectedSections::from_header(
        &ids[2],
        header3.transactions_root.as_bytes(),
        header3.extension_root.as_bytes(),
        header3.ad_proofs_root.as_bytes(),
    );
    withhold_transactions(&store, sections3.transactions_id);
    let mut executor = SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        DifficultyParams::mainnet(),
    );
    let mut coordinator = SyncCoordinator::new(3);
    executor.try_apply_next_blocks(&mut store, &mut coordinator, Instant::now(), None);
    assert_eq!(store.chain_state_meta().best_full_block_id, ids[1]);
    assert_eq!(store.chain_state_meta().best_full_block_height, 2);
    assert_eq!(executor.take_applied_blocks(), vec![ids[1]]);
}

#[test]
fn digest_executor_adopts_shorter_heavier_chain_after_restart() {
    let (_source_dir, source, ids, old3) = competing_fixture();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("digest.redb");
    let genesis =
        ergo_chain_spec::GenesisParams::for_network(ergo_chain_spec::Network::Mainnet).state_digest;
    let mut digest = ergo_state::DigestStateStore::open(
        &path,
        ergo_validation::scala_launch(),
        ergo_chain_spec::VotingParams::mainnet(),
        genesis,
    )
    .unwrap();
    for id in &ids {
        let raw = source.get_header(id).unwrap().unwrap();
        let meta = source.get_header_meta(id).unwrap().unwrap();
        digest
            .store_validated_header(
                id,
                &raw,
                &meta,
                Some((meta.height, meta.cumulative_score.clone())),
            )
            .unwrap();
        let header = read_header(&mut VlqReader::new(&raw)).unwrap();
        let expected = ExpectedSections::from_header(
            id,
            header.transactions_root.as_bytes(),
            header.extension_root.as_bytes(),
            header.ad_proofs_root.as_bytes(),
        );
        for (section, type_id) in [
            (expected.transactions_id, 102),
            (expected.extension_id, 108),
            (expected.ad_proofs_id, 104),
        ] {
            if id == &ids[2] && type_id == 102 {
                continue;
            }
            let Some(bytes) = source.get_block_section(&section).unwrap() else {
                assert!(
                    id == &ids[0] && type_id == 104,
                    "missing section {type_id} for {}",
                    hex::encode(id)
                );
                continue; // Scala genesis block carries no ADProofs section.
            };
            digest
                .store_block_section_typed(&section, &bytes, type_id)
                .unwrap();
        }
    }
    // Seed the known common mainnet state; replacement B2 is validated from
    // its real ADProofs below. Genesis proof generation is outside this test.
    let raw = digest.get_header(&ids[0]).unwrap().unwrap();
    let header = read_header(&mut VlqReader::new(&raw)).unwrap();
    let mut common_state = digest.chain_state_meta();
    common_state.best_full_block_id = ids[0];
    common_state.best_full_block_height = 1;
    digest
        .apply_block_digest(*header.state_root.as_bytes(), common_state, None)
        .unwrap();
    let mut backend = ergo_state::StateBackendKind::Digest(digest);
    let old2 = source.get_header_meta(&old3).unwrap().unwrap().parent_id;
    let ergo_state::StateBackendKind::Digest(ref mut digest) = backend else {
        unreachable!()
    };
    for id in [old2, old3] {
        let raw = source.get_header(&id).unwrap().unwrap();
        let meta = source.get_header_meta(&id).unwrap().unwrap();
        digest
            .store_validated_header(&id, &raw, &meta, None)
            .unwrap();
        let mut chain = digest.chain_state_meta();
        chain.best_full_block_id = id;
        chain.best_full_block_height = meta.height;
        let header = read_header(&mut VlqReader::new(&raw)).unwrap();
        digest
            .apply_block_digest(*header.state_root.as_bytes(), chain, None)
            .unwrap();
    }
    let raw = digest.get_header(&ids[1]).unwrap().unwrap();
    let mut meta = digest.get_header_meta(&ids[1]).unwrap().unwrap();
    meta.cumulative_score = vec![9];
    digest
        .store_validated_header(&ids[1], &raw, &meta, Some((2, vec![9])))
        .unwrap();
    drop(backend);
    let digest = ergo_state::DigestStateStore::open(
        &path,
        ergo_validation::scala_launch(),
        ergo_chain_spec::VotingParams::mainnet(),
        genesis,
    )
    .unwrap();
    let mut backend = ergo_state::StateBackendKind::Digest(digest);
    let mut executor = SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        DifficultyParams::mainnet(),
    );
    let mut coordinator = SyncCoordinator::new(3);
    executor.try_apply_next_blocks(&mut backend, &mut coordinator, Instant::now(), None);
    assert_eq!(
        backend.chain_state_meta().best_full_block_id,
        ids[1],
        "{:?}",
        executor.last_block_apply_error()
    );
    assert_eq!(executor.take_applied_blocks(), vec![ids[1]]);
}

fn withhold_transactions(store: &ergo_state::StateBackendKind, section_id: [u8; 32]) {
    let db = store.db_arc();
    let txn = db.begin_write().unwrap();
    {
        let mut table = txn
            .open_table(redb::TableDefinition::<&[u8], &[u8]>::new("block_sections"))
            .unwrap();
        table.remove(&section_id[..]).unwrap();
    }
    txn.commit().unwrap();
}

#[test]
fn available_prefix_can_outscore_applied_tip_before_header_tip_body_arrives() {
    let (_dir, mut store, ids, _old3) = competing_fixture();
    let concrete = store.as_utxo_mut().unwrap();
    for (index, score) in [(1, 9), (2, 10)] {
        let raw = concrete.get_header(&ids[index]).unwrap().unwrap();
        let mut meta = concrete.get_header_meta(&ids[index]).unwrap().unwrap();
        meta.cumulative_score = vec![score];
        concrete
            .store_validated_header(
                &ids[index],
                &raw,
                &meta,
                (index == 2).then_some((3, vec![score])),
            )
            .unwrap();
    }
    let raw = store.get_header(&ids[2]).unwrap().unwrap();
    let header = read_header(&mut VlqReader::new(&raw)).unwrap();
    let expected = ExpectedSections::from_header(
        &ids[2],
        header.transactions_root.as_bytes(),
        header.extension_root.as_bytes(),
        header.ad_proofs_root.as_bytes(),
    );
    withhold_transactions(&store, expected.transactions_id);
    let mut executor = SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        DifficultyParams::mainnet(),
    );
    let mut coordinator = SyncCoordinator::new(3);
    executor.try_apply_next_blocks(&mut store, &mut coordinator, Instant::now(), None);
    assert_eq!(store.chain_state_meta().best_full_block_id, ids[1]);
    assert_eq!(store.chain_state_meta().best_header_id, ids[2]);
    assert_eq!(executor.take_applied_blocks(), vec![ids[1]]);
}

#[test]
fn complete_side_branch_can_beat_full_tip_while_best_headers_withhold_bodies() {
    let (_dir, mut store, ids, _old3) = competing_fixture();
    let concrete = store.as_utxo_mut().unwrap();
    let mut parent = ids[0];
    let mut withheld_tip = [0; 32];
    for height in 2..=3 {
        let raw = concrete.get_header(&ids[height - 1]).unwrap().unwrap();
        let mut header = read_header(&mut VlqReader::new(&raw)).unwrap();
        header.parent_id = ModifierId::from_bytes(parent);
        match &mut header.solution {
            ergo_ser::autolykos::AutolykosSolution::V1 { nonce, .. }
            | ergo_ser::autolykos::AutolykosSolution::V2 { nonce, .. } => nonce[0] ^= 1,
        }
        let mut writer = VlqWriter::new();
        ergo_ser::header::write_header(&mut writer, &header).unwrap();
        let raw = writer.result();
        let id = *ergo_primitives::digest::blake2b256(&raw).as_bytes();
        concrete
            .store_validated_header(
                &id,
                &raw,
                &ergo_state::chain::HeaderMeta {
                    parent_id: parent,
                    height: height as u32,
                    cumulative_score: vec![10 + height as u8],
                    pow_validity: 1,
                    timestamp: header.timestamp,
                },
                Some((height as u32, vec![10 + height as u8])),
            )
            .unwrap();
        parent = id;
        withheld_tip = id;
    }
    let mut executor = SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        DifficultyParams::mainnet(),
    );
    let mut coordinator = SyncCoordinator::new(3);
    executor.handle_assemble_block(&ids[2], &mut store, &mut coordinator, None);
    assert_eq!(store.chain_state_meta().best_full_block_id, ids[2]);
    assert_eq!(store.chain_state_meta().best_header_id, withheld_tip);
    assert_eq!(executor.take_applied_blocks(), ids[1..]);
}

// ----- interrupted reorg recovery -----

/// Copy the established fork scaffold into an owned crash-test database. The
/// abandoned branch is synthetic; replacement blocks and expected roots are
/// the externally captured mainnet blocks 1..=3 used by prepare_chain.
fn crash_backend(
    path: &std::path::Path,
    digest_mode: bool,
) -> (ergo_state::StateBackendKind, Vec<[u8; 32]>) {
    let (source_dir, source, ids, old3) = competing_fixture();
    if !digest_mode {
        drop(source);
        std::fs::copy(source_dir.path().join("state.redb"), path).unwrap();
        return (
            ergo_state::StateBackendKind::Utxo(StateStore::open(path).unwrap()),
            ids,
        );
    }
    let genesis = ergo_chain_spec::GenesisParams::mainnet().state_digest;
    let mut digest = ergo_state::DigestStateStore::open(
        path,
        ergo_validation::scala_launch(),
        ergo_chain_spec::VotingParams::mainnet(),
        genesis,
    )
    .unwrap();
    for id in &ids {
        let raw = source.get_header(id).unwrap().unwrap();
        let meta = source.get_header_meta(id).unwrap().unwrap();
        digest
            .store_validated_header(
                id,
                &raw,
                &meta,
                Some((meta.height, meta.cumulative_score.clone())),
            )
            .unwrap();
        let header = read_header(&mut VlqReader::new(&raw)).unwrap();
        let expected = ExpectedSections::from_header(
            id,
            header.transactions_root.as_bytes(),
            header.extension_root.as_bytes(),
            header.ad_proofs_root.as_bytes(),
        );
        for (section, kind) in [
            (expected.transactions_id, 102),
            (expected.extension_id, 108),
            (expected.ad_proofs_id, 104),
        ] {
            if let Some(bytes) = source.get_block_section(&section).unwrap() {
                digest
                    .store_block_section_typed(&section, &bytes, kind)
                    .unwrap();
            }
        }
    }
    let raw = digest.get_header(&ids[0]).unwrap().unwrap();
    let header = read_header(&mut VlqReader::new(&raw)).unwrap();
    let mut state = digest.chain_state_meta();
    state.best_full_block_id = ids[0];
    state.best_full_block_height = 1;
    digest
        .apply_block_digest(*header.state_root.as_bytes(), state, None)
        .unwrap();
    let old2 = source.get_header_meta(&old3).unwrap().unwrap().parent_id;
    for id in [old2, old3] {
        let raw = source.get_header(&id).unwrap().unwrap();
        let meta = source.get_header_meta(&id).unwrap().unwrap();
        digest
            .store_validated_header(&id, &raw, &meta, None)
            .unwrap();
        let header = read_header(&mut VlqReader::new(&raw)).unwrap();
        let mut state = digest.chain_state_meta();
        state.best_full_block_id = id;
        state.best_full_block_height = meta.height;
        digest
            .apply_block_digest(*header.state_root.as_bytes(), state, None)
            .unwrap();
    }
    (ergo_state::StateBackendKind::Digest(digest), ids)
}

fn promote_crash_branch(store: &mut ergo_state::StateBackendKind, id: [u8; 32], score: u8) {
    let bytes = store.get_header(&id).unwrap().unwrap();
    let mut meta = store.get_header_meta(&id).unwrap().unwrap();
    meta.cumulative_score = vec![score];
    store
        .store_validated_header(&id, &bytes, &meta, Some((meta.height, vec![score])))
        .unwrap();
}

fn backend_root(store: &mut ergo_state::StateBackendKind) -> [u8; 33] {
    match store {
        ergo_state::StateBackendKind::Utxo(store) => *store.root_digest().as_bytes(),
        ergo_state::StateBackendKind::Digest(store) => store.root_digest(),
    }
}

/// Internal subprocess entry point. The parent kills this process while the
/// database and executor are still live, so shutdown/Drop cannot make the
/// restart test accidentally exercise only a clean close.
#[test]
#[ignore = "subprocess entry point; exercised by reorg_interrupted_* tests"]
fn reorg_crash_child() {
    let path = std::path::PathBuf::from(
        std::env::var_os("ERGO_REORG_TEST_DATABASE").expect("parent supplies an owned database"),
    );
    let digest_mode = std::env::var("ERGO_REORG_TEST_BACKEND").unwrap() == "digest";
    let phase = std::env::var("ERGO_REORG_TEST_PHASE").unwrap();
    let (mut backend, ids) = crash_backend(&path, digest_mode);
    // A shorter, heavier AVAILABLE replacement suffix commits rollback even
    // though its header height is lower than the abandoned full-block tip.
    promote_crash_branch(&mut backend, ids[1], 9);
    let raw = backend.get_header(&ids[2]).unwrap().unwrap();
    let header = read_header(&mut VlqReader::new(&raw)).unwrap();
    let sections = ExpectedSections::from_header(
        &ids[2],
        header.transactions_root.as_bytes(),
        header.extension_root.as_bytes(),
        header.ad_proofs_root.as_bytes(),
    );
    let transactions = backend
        .get_block_section(&sections.transactions_id)
        .unwrap()
        .unwrap();
    std::fs::write(path.with_extension("transactions"), transactions).unwrap();
    withhold_transactions(&backend, sections.transactions_id);
    let mut executor = SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        DifficultyParams::mainnet(),
    );
    let mut coordinator = SyncCoordinator::new(3);
    assert!(matches!(
        executor
            .rollback_full_chain_to_best_header(&mut backend, &mut coordinator, None)
            .unwrap(),
        super::ReorgOutcome::Performed
    ));
    assert_eq!(backend.chain_state_meta().best_full_block_id, ids[0]);
    if phase == "partial_apply" {
        executor.try_apply_next_blocks(&mut backend, &mut coordinator, Instant::now(), None);
        assert_eq!(backend.chain_state_meta().best_full_block_id, ids[1]);
    } else {
        assert_eq!(phase, "rollback");
    }
    let tip = backend.chain_state_meta().best_full_block_height;
    let header_bytes = backend.get_header(&ids[tip as usize - 1]).unwrap().unwrap();
    let header = read_header(&mut VlqReader::new(&header_bytes)).unwrap();
    assert_eq!(backend_root(&mut backend), *header.state_root.as_bytes());
    std::fs::write(path.with_extension("ready"), b"committed").unwrap();
    loop {
        std::thread::park();
    }
}

struct CrashChild(std::process::Child);
impl Drop for CrashChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn interrupted_reorg_restarts(digest_mode: bool, phase: &str) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("state.redb");
    let output = std::fs::File::create(directory.path().join("child.log")).unwrap();
    let mut child = CrashChild(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "executor::relay_tests::reorg_crash_child",
                "--nocapture",
            ])
            .env("ERGO_REORG_TEST_DATABASE", &path)
            .env(
                "ERGO_REORG_TEST_BACKEND",
                if digest_mode { "digest" } else { "utxo" },
            )
            .env("ERGO_REORG_TEST_PHASE", phase)
            .stdout(output.try_clone().unwrap())
            .stderr(output)
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + std::time::Duration::from_secs(30);
    while !path.with_extension("ready").exists() {
        if let Some(status) = child.0.try_wait().unwrap() {
            panic!(
                "crash subprocess exited before checkpoint ({status}): {}",
                std::fs::read_to_string(directory.path().join("child.log")).unwrap()
            );
        }
        assert!(
            Instant::now() < deadline,
            "crash subprocess did not reach {phase}"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    child.0.kill().unwrap();
    let status = child.0.wait().unwrap();
    assert!(!status.success(), "interruption must bypass clean shutdown");
    let mut backend = if digest_mode {
        ergo_state::StateBackendKind::Digest(
            ergo_state::DigestStateStore::open(
                &path,
                ergo_validation::scala_launch(),
                ergo_chain_spec::VotingParams::mainnet(),
                ergo_chain_spec::GenesisParams::mainnet().state_digest,
            )
            .unwrap(),
        )
    } else {
        ergo_state::StateBackendKind::Utxo(StateStore::open(&path).unwrap())
    };
    let headers = load_headers();
    let ids: Vec<[u8; 32]> = headers
        .iter()
        .take(3)
        .map(|row| {
            hex::decode(row["id"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap()
        })
        .collect();
    let expected_height = if phase == "rollback" { 1 } else { 2 };
    assert_eq!(
        backend.chain_state_meta().best_full_block_height,
        expected_height
    );
    let expected_header = read_header(&mut VlqReader::new(
        &hex::decode(
            headers[expected_height as usize - 1]["bytes"]
                .as_str()
                .unwrap(),
        )
        .unwrap(),
    ))
    .unwrap();
    assert_eq!(
        backend_root(&mut backend),
        *expected_header.state_root.as_bytes()
    );
    assert_eq!(backend.chain_state_meta().best_header_id, ids[1]);
    let params_before = backend.active_params().clone();
    let raw = backend.get_header(&ids[2]).unwrap().unwrap();
    let header = read_header(&mut VlqReader::new(&raw)).unwrap();
    let sections = ExpectedSections::from_header(
        &ids[2],
        header.transactions_root.as_bytes(),
        header.extension_root.as_bytes(),
        header.ad_proofs_root.as_bytes(),
    );
    backend
        .store_block_section_typed(
            &sections.transactions_id,
            &std::fs::read(path.with_extension("transactions")).unwrap(),
            102,
        )
        .unwrap();
    promote_crash_branch(&mut backend, ids[2], 10);
    let mut executor = SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        DifficultyParams::mainnet(),
    );
    let mut coordinator = SyncCoordinator::new(expected_height);
    executor.rebuild_block_context(&backend).unwrap();
    executor
        .recover_coordinator(&backend, &mut coordinator)
        .unwrap();
    executor.try_apply_next_blocks(&mut backend, &mut coordinator, Instant::now(), None);
    assert_eq!(
        backend.chain_state_meta().best_full_block_id,
        ids[2],
        "restart must recover the replacement suffix: {:?}",
        executor.last_block_apply_error()
    );
    let expected_header = read_header(&mut VlqReader::new(
        &hex::decode(headers[2]["bytes"].as_str().unwrap()).unwrap(),
    ))
    .unwrap();
    assert_eq!(
        backend_root(&mut backend),
        *expected_header.state_root.as_bytes(),
        "final root must match external mainnet bytes"
    );
    assert_eq!(backend.active_params(), &params_before);
    assert_eq!(
        executor.take_applied_blocks(),
        ids[expected_height as usize..]
    );
    assert_eq!(coordinator.sync_state().best_full_block_height(), 3);
}

#[test]
fn reorg_interrupted_utxo_rollback_recovers_after_process_death() {
    interrupted_reorg_restarts(false, "rollback");
}
#[test]
fn reorg_interrupted_utxo_partial_apply_recovers_after_process_death() {
    interrupted_reorg_restarts(false, "partial_apply");
}
#[test]
fn reorg_interrupted_digest_rollback_recovers_after_process_death() {
    interrupted_reorg_restarts(true, "rollback");
}
#[test]
fn reorg_interrupted_digest_partial_apply_recovers_after_process_death() {
    interrupted_reorg_restarts(true, "partial_apply");
}
