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
use ergo_state::BlockApply;
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
                    cumulative_score: vec![height as u8],
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
