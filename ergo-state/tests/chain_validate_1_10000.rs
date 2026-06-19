//! State-backed transaction validation for blocks 1-10,000.
//!
//! Validates every transaction through the full pipeline using real StateStore
//! UTXO lookups. Handles multi-tx blocks (188 blocks with 2+ transactions in
//! this range). Block 1 is applied unchecked; blocks 2-10,000 are fully validated.
//!
//! This test pins both transaction-level validation across blocks 1-10,000 and
//! multi-tx state-root parity (188 multi-tx blocks verified against
//! Scala-produced state digests).

use std::collections::{BTreeMap, HashMap};

use ergo_primitives::digest::{ADDigest, Digest32, ModifierId};
use ergo_primitives::reader::VlqReader;
use ergo_ser::ergo_box::{serialize_ergo_box, ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::read_ergo_tree;
use ergo_ser::register::{AdditionalRegisters, RegisterValue};
use ergo_ser::sigma_value::read_constant;
use ergo_ser::transaction::read_transaction;
use ergo_state::store::StateStore;
use ergo_validation::{
    validate_transaction, CostAccumulator, LocalPolicy, ProtocolParams, TransactionContext,
    UtxoView,
};

/// Layered UTXO view: checks in-block outputs first, then falls back to store.
/// Handles intra-block dependencies (tx N spending output of tx M where M < N).
struct BlockUtxoOverlay<'a> {
    store: &'a StateStore,
    in_block_outputs: HashMap<Digest32, ErgoBox>,
    spent_in_block: std::collections::HashSet<Digest32>,
}

impl<'a> BlockUtxoOverlay<'a> {
    fn new(store: &'a StateStore) -> Self {
        Self {
            store,
            in_block_outputs: HashMap::new(),
            spent_in_block: std::collections::HashSet::new(),
        }
    }

    fn add_tx_outputs(&mut self, tx: &ergo_ser::transaction::Transaction) {
        let tx_id = ergo_ser::transaction::transaction_id(tx).unwrap();
        for (idx, output) in tx.output_candidates.iter().enumerate() {
            let ergo_box = ErgoBox {
                candidate: output.clone(),
                transaction_id: tx_id,
                index: idx as u16,
            };
            let box_id = ergo_box.box_id().unwrap();
            self.in_block_outputs.insert(box_id, ergo_box);
        }
    }

    fn mark_inputs_spent(&mut self, tx: &ergo_ser::transaction::Transaction) {
        for input in &tx.inputs {
            self.spent_in_block.insert(input.box_id);
        }
    }
}

impl UtxoView for BlockUtxoOverlay<'_> {
    fn get_box(&self, box_id: &Digest32) -> Option<ErgoBox> {
        if self.spent_in_block.contains(box_id) {
            return None;
        }
        if let Some(b) = self.in_block_outputs.get(box_id) {
            return Some(b.clone());
        }
        self.store.get_box(box_id)
    }
}

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct GenesisBoxJson {
    #[serde(rename = "boxId")]
    box_id: String,
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

#[derive(serde::Deserialize)]
struct TxVector {
    id: String,
    bytes: String,
    height: u32,
}

#[derive(serde::Deserialize)]
struct DigestJson {
    height: u32,
    #[serde(rename = "stateRoot")]
    state_root: String,
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

struct HeaderInfo {
    header_id: [u8; 32],
    header: ergo_ser::header::Header,
    miner_pubkey: [u8; 33],
    timestamp: u64,
}

fn load_header_info(path: &str) -> std::collections::HashMap<u32, HeaderInfo> {
    let data = std::fs::read_to_string(path).unwrap();
    let headers: Vec<serde_json::Value> = serde_json::from_str(&data).unwrap();
    let mut info = std::collections::HashMap::new();
    for h in &headers {
        let height = h["height"].as_u64().unwrap() as u32;
        let header_id: [u8; 32] = hex::decode(h["id"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let header_bytes = hex::decode(h["bytes"].as_str().unwrap()).unwrap();
        let mut r = VlqReader::new(&header_bytes);
        let header = ergo_ser::header::read_header(&mut r).unwrap();
        let pk = *header.solution.pk().as_bytes();
        let ts = header.timestamp;
        info.insert(
            height,
            HeaderInfo {
                header_id,
                miner_pubkey: pk,
                timestamp: ts,
                header,
            },
        );
    }
    info
}

fn load_digests(path: &str) -> std::collections::HashMap<u32, ADDigest> {
    let data = std::fs::read_to_string(path).unwrap();
    let digests: Vec<DigestJson> = serde_json::from_str(&data).unwrap();
    digests
        .into_iter()
        .map(|d| {
            let digest =
                ADDigest::from_bytes(hex::decode(&d.state_root).unwrap().try_into().unwrap());
            (d.height, digest)
        })
        .collect()
}

/// Group transaction vectors by height, preserving order within each block.
fn group_by_height(vectors: Vec<TxVector>) -> BTreeMap<u32, Vec<TxVector>> {
    let mut map: BTreeMap<u32, Vec<TxVector>> = BTreeMap::new();
    for v in vectors {
        map.entry(v.height).or_default().push(v);
    }
    map
}

/// Validate all transactions in blocks 2-10,000 using real state store.
///
/// Handles multi-tx blocks (188 blocks with 2+ transactions). For each block:
/// 1. Validate every transaction through the full pipeline
/// 2. Apply all validated transactions to the state store atomically
/// 3. Verify the resulting state digest matches the Scala node
///
/// This proves both transaction validation correctness AND multi-tx
/// state-root parity through the collect-sort-batch ordering model.
#[test]
fn chain_validate_blocks_2_10000_with_state_store() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(dir.path().join("state.redb").as_path()).unwrap();
    init_genesis(&mut store);

    let tx_data =
        std::fs::read_to_string("../test-vectors/mainnet/transactions_1_10000.json").unwrap();
    let vectors: Vec<TxVector> = serde_json::from_str(&tx_data).unwrap();
    let total_txs = vectors.len();
    let blocks = group_by_height(vectors);
    let digests = load_digests("../test-vectors/mainnet/utxo_digests_1_10000.json");
    let header_info = load_header_info("../test-vectors/mainnet/headers_1_10000.json");

    let params = ProtocolParams::mainnet_default();
    let policy = LocalPolicy::default_policy();

    // Apply block 1 unchecked (genesis coinbase bootstrap)
    let block_1 = blocks.get(&1).expect("block 1 missing");
    assert_eq!(block_1.len(), 1);
    let tx1_bytes = hex::decode(&block_1[0].bytes).unwrap();
    let mut r = VlqReader::new(&tx1_bytes);
    let tx1 = read_transaction(&mut r).unwrap();
    let h1 = header_info.get(&1).unwrap();
    store
        .apply_block_unchecked_for_test(1, &h1.header_id, digests.get(&1).unwrap(), &[tx1])
        .unwrap();

    // Validate and apply blocks 2-10,000
    let mut validated_txs = 0;
    let mut multi_tx_blocks = 0;
    let mut total_cost: u64 = 0;

    let mut header_checks = 0u32;
    let mut header_skipped_epoch = 0u32;
    let mut tx_root_checks = 0u32;

    for (&height, block_txs) in blocks.range(2..) {
        let hi = header_info
            .get(&height)
            .unwrap_or_else(|| panic!("missing header info for height {height}"));
        let ctx = TransactionContext {
            height,
            miner_pubkey: hi.miner_pubkey,
            pre_header_timestamp: hi.timestamp,
            activated_script_version: hi.header.version.saturating_sub(1),
            pre_header_version: 0,
            pre_header_parent_id: [0u8; 32],
            pre_header_n_bits: 0,
            pre_header_votes: [0u8; 3],
        };

        if block_txs.len() > 1 {
            multi_tx_blocks += 1;
        }

        // Header linkage + PoW checks.
        if let Some(parent_hi) = header_info.get(&(height - 1)) {
            // Parent ID linkage
            assert_eq!(
                hi.header.parent_id.as_bytes(),
                &parent_hi.header_id,
                "parent_id mismatch at height {height}"
            );
            // Timestamp monotonicity
            assert!(
                hi.header.timestamp > parent_hi.header.timestamp,
                "timestamp not monotonic at height {height}"
            );
            // PoW solution
            let cfg = ergo_crypto::difficulty::DifficultyParams::mainnet();
            ergo_crypto::pow::verify_pow_solution(&hi.header)
                .unwrap_or_else(|e| panic!("PoW failed at height {height}: {e}"));
            // Difficulty (skip epoch boundaries lacking lookback)
            if ergo_crypto::difficulty::is_recalculation_height(height, &cfg) {
                header_skipped_epoch += 1;
            } else {
                ergo_crypto::pow::verify_header_difficulty(
                    &hi.header,
                    std::slice::from_ref(&parent_hi.header),
                    &cfg,
                )
                .unwrap_or_else(|e| panic!("difficulty failed at height {height}: {e}"));
            }
            header_checks += 1;
        }

        // Validate all transactions in this block.
        // Use overlay for multi-tx blocks so intra-block dependencies resolve.
        let mut overlay = BlockUtxoOverlay::new(&store);
        let mut checked_txs = Vec::with_capacity(block_txs.len());
        for v in block_txs {
            let tx_bytes = hex::decode(&v.bytes).unwrap();
            let mut cost = CostAccumulator::recording_only();
            let mut tx_cx = ergo_validation::TxValidationCtx {
                ctx: &ctx,
                params: &params,
                cost: &mut cost,
                last_headers: &[],
                rules: ergo_validation::TxValidationRules::default(),
            };

            match validate_transaction(&tx_bytes, &overlay, &policy, &mut tx_cx) {
                Ok(checked) => {
                    let computed_id =
                        ergo_ser::transaction::transaction_id(checked.transaction()).unwrap();
                    assert_eq!(
                        hex::encode(computed_id.as_bytes()),
                        v.id,
                        "tx ID mismatch at height {}",
                        height
                    );
                    total_cost += cost.total().value();
                    // Update overlay so subsequent txs can see this tx's outputs
                    overlay.add_tx_outputs(checked.transaction());
                    overlay.mark_inputs_spent(checked.transaction());
                    checked_txs.push(checked);
                }
                Err(e) => {
                    panic!(
                        "height {} tx {}: validation failed: {e}",
                        height,
                        &v.id[..16]
                    );
                }
            }
        }

        // Transactions root verification
        {
            let txs: Vec<&ergo_ser::transaction::Transaction> =
                checked_txs.iter().map(|c| c.transaction()).collect();
            let tx_ids: Vec<Vec<u8>> = txs
                .iter()
                .map(|tx| {
                    let bts = ergo_ser::transaction::bytes_to_sign(tx).unwrap();
                    ergo_crypto::autolykos::common::blake2b256(&bts).to_vec()
                })
                .collect();
            let tx_id_refs: Vec<&[u8]> = tx_ids.iter().map(|id| id.as_slice()).collect();

            let computed_root = if hi.header.version >= 2 {
                let witness_data: Vec<Vec<u8>> = txs
                    .iter()
                    .map(|tx| {
                        let mut proofs = Vec::new();
                        for input in &tx.inputs {
                            proofs.extend_from_slice(&input.spending_proof.proof);
                        }
                        let hash = ergo_crypto::autolykos::common::blake2b256(&proofs);
                        hash[1..].to_vec()
                    })
                    .collect();
                let wrefs: Vec<&[u8]> = witness_data.iter().map(|w| w.as_slice()).collect();
                ergo_crypto::merkle::transactions_root(&tx_id_refs, Some(&wrefs))
            } else {
                ergo_crypto::merkle::transactions_root(&tx_id_refs, None)
            };
            assert_eq!(
                computed_root,
                *hi.header.transactions_root.as_bytes(),
                "transactions root mismatch at height {height}"
            );
            tx_root_checks += 1;
        }

        // Apply all validated transactions to state atomically
        let expected_digest = digests
            .get(&height)
            .unwrap_or_else(|| panic!("missing digest for height {height}"));
        store
            .apply_block_checked_for_test(height, &hi.header_id, expected_digest, &checked_txs)
            .unwrap_or_else(|e| panic!("apply_block failed at height {height}: {e}"));

        validated_txs += checked_txs.len();
    }

    assert_eq!(store.height(), 10000);
    eprintln!(
        "Validated {validated_txs}/{total_txs} transactions ({multi_tx_blocks} multi-tx blocks), total cost: {total_cost}"
    );
    eprintln!(
        "Header checks: {header_checks} verified, {header_skipped_epoch} epoch boundaries skipped (lacking lookback)"
    );
    eprintln!("Tx root checks: {tx_root_checks} verified");
    // 10,405 total transactions, block 1 skipped = 10,404 validated
    assert_eq!(
        validated_txs, 10_404,
        "expected exactly 10,404 validated txs"
    );
    assert_eq!(multi_tx_blocks, 188, "expected exactly 188 multi-tx blocks");
    // Header checks: 9,999 blocks checked (2-10,000), epoch boundaries skipped
    assert_eq!(header_checks, 9_999, "expected exactly 9,999 header checks");
    // Pre-EIP37 epoch length = 1024. Heights 1025, 2049, ..., 9217 = 9 boundaries
    assert_eq!(
        header_skipped_epoch, 9,
        "expected exactly 9 epoch boundary skips"
    );
    assert_eq!(
        tx_root_checks, 9_999,
        "expected exactly 9,999 tx root checks"
    );
}
