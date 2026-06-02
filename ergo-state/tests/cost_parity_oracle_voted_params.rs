//! Cost-parity oracle — differential test framework.
//!
//! Asserts that `validate_full_block_parallel_with_costs` produces the same
//! per-tx block cost as the Scala oracle across heights 700000-700200, using
//! the active parameter set at H-1.
//!
//! **Test vectors (all in `test-vectors/mainnet/`)**
//! - `tx_costs_700000_700200.json` — corpus (589 records): `{tx_id, height, block_cost}`
//! - `transactions_700000_700200.json` — tx bytes: `{id, bytes, height}`
//! - `extensions_700000_700200.json` — extension fields: `{headerId, height, fields}`
//! - `headers_700000_700500.json` — header bytes: `{height, bytes}`
//! - `input_boxes_700000_700200.json` — pre-extracted input boxes (MapUtxo seed)
//!
//! **Running**
//! ```
//! cargo test --release --features test-helpers \
//!   --test cost_parity_oracle_voted_params -- --ignored --nocapture
//! ```
//! No running node or StateStore required once vectors are on disk.
//!
//! **Corpus notes**
//! - ~50% of 700k txs are Spectrum DEX contracts excluded from corpus by design
//!   (call `error()` internally — cannot verify without full historical state).
//!   Only tx_ids present in corpus are compared; remaining txs in each block are
//!   skipped without penalty.
//! - Params at epoch h=699392: `blockVersion=2`, `maxBlockCost=8001091`,
//!   `activatedScriptVersion=1`. Hardcoded via `ActiveProtocolParameters`.
//!
//! Pins per-tx block cost against the Scala oracle for the voted-parameters
//! era — divergence here means our cost model has drifted from Scala.

#![cfg(feature = "test-helpers")]

use std::collections::HashMap;

use ergo_primitives::digest::{Digest32, ModifierId};
use ergo_primitives::reader::VlqReader;
use ergo_ser::block_transactions::BlockTransactions;
use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::read_ergo_tree;
use ergo_ser::extension::{Extension, ExtensionField};
use ergo_ser::header::{read_header, serialize_header};
use ergo_ser::register::{AdditionalRegisters, RegisterValue};
use ergo_ser::sigma_value::read_constant;
use ergo_ser::transaction::read_transaction;
use ergo_validation::block::{validate_full_block_parallel_with_costs, BlockValidationContext};
use ergo_validation::context::{ProtocolParams, UtxoView};
use ergo_validation::header::CheckedHeader;
use ergo_validation::scala_launch;

use serde::Deserialize;

// ── JSON shapes ──────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct CorpusEntry {
    tx_id: String,
    height: u32,
    block_cost: u64,
}

#[derive(Deserialize)]
struct TxVec {
    id: String,
    bytes: String,
    height: u32,
}

#[derive(Deserialize)]
struct ExtVec {
    #[allow(dead_code)]
    #[serde(rename = "headerId")]
    header_id: String,
    height: u32,
    fields: Vec<(String, String)>,
}

#[derive(Deserialize)]
struct HeaderVec {
    height: u32,
    bytes: String,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct InputBoxJson {
    #[serde(rename = "boxId")]
    box_id: String,
    value: u64,
    #[serde(rename = "ergoTree")]
    ergo_tree: String,
    #[serde(rename = "creationHeight")]
    creation_height: u32,
    #[serde(rename = "transactionId")]
    transaction_id: String,
    index: u16,
    #[serde(default)]
    assets: Vec<AssetJson>,
    #[serde(rename = "additionalRegisters", default)]
    additional_registers: HashMap<String, String>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct AssetJson {
    #[serde(rename = "tokenId")]
    token_id: String,
    amount: u64,
}

// ── MapUtxo (same pattern as full_block_700k.rs) ─────────────────────────────

struct MapUtxo {
    boxes: HashMap<Digest32, ErgoBox>,
}

impl MapUtxo {
    fn new() -> Self {
        Self {
            boxes: HashMap::new(),
        }
    }

    fn insert(&mut self, b: ErgoBox) {
        if let Ok(id) = b.box_id() {
            self.boxes.insert(id, b);
        }
    }

    fn apply_checked(&mut self, checked: &[ergo_validation::CheckedTransaction]) {
        for c in checked {
            for input in &c.transaction().inputs {
                self.boxes.remove(&input.box_id);
            }
            let tx_id = ergo_ser::transaction::transaction_id(c.transaction()).unwrap();
            for (i, cand) in c.transaction().output_candidates.iter().enumerate() {
                self.insert(ErgoBox {
                    candidate: cand.clone(),
                    transaction_id: tx_id,
                    index: i as u16,
                });
            }
        }
    }
}

impl UtxoView for MapUtxo {
    fn get_box(&self, box_id: &Digest32) -> Option<ErgoBox> {
        self.boxes.get(box_id).cloned()
    }
}

// ── Box parsing (same as full_block_700k.rs) ─────────────────────────────────

fn parse_input_box(json: &InputBoxJson) -> ErgoBox {
    let ergo_tree_bytes = hex::decode(&json.ergo_tree).unwrap();
    let mut r = VlqReader::new(&ergo_tree_bytes);
    let ergo_tree = read_ergo_tree(&mut r).unwrap();

    let mut reg_entries: Vec<(usize, Vec<u8>, RegisterValue)> = Vec::new();
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
        let raw = hex::decode(val_hex).unwrap();
        let mut vr = VlqReader::new(&raw);
        let (tpe, value) = read_constant(&mut vr).unwrap();
        reg_entries.push((reg_idx, raw, RegisterValue { tpe, value }));
    }
    reg_entries.sort_by_key(|(idx, _, _)| *idx);

    let mut register_bytes = Vec::new();
    register_bytes.push(reg_entries.len() as u8);
    for (_, raw, _) in &reg_entries {
        register_bytes.extend_from_slice(raw);
    }

    let registers = AdditionalRegisters {
        registers: reg_entries.into_iter().map(|(_, _, rv)| rv).collect(),
    };
    let tokens: Vec<ergo_ser::token::Token> = json
        .assets
        .iter()
        .map(|a| {
            let id: [u8; 32] = hex::decode(&a.token_id).unwrap().try_into().unwrap();
            ergo_ser::token::Token {
                token_id: Digest32::from_bytes(id),
                amount: a.amount,
            }
        })
        .collect();

    let candidate = ErgoBoxCandidate::from_trusted_raw_parts(
        json.value,
        ergo_tree,
        ergo_tree_bytes,
        json.creation_height,
        tokens,
        registers,
        register_bytes,
    );
    let tx_id: [u8; 32] = hex::decode(&json.transaction_id)
        .unwrap()
        .try_into()
        .unwrap();
    ErgoBox {
        candidate,
        transaction_id: ModifierId::from_bytes(tx_id),
        index: json.index,
    }
}

// ── Params at epoch covering h=700000 ────────────────────────────────────────

fn params_at_700k() -> ProtocolParams {
    // Epoch start h=699392: blockVersion=2, maxBlockCost=8001091, all other
    // cost constants from mainnet extension fields at that height.
    // activatedScriptVersion = blockVersion - 1 = 1 (JIT model).
    let mut p = scala_launch();
    p.block_version = 2;
    p.max_block_cost = 8_001_091;
    // Cost constants confirmed by ComputeTransactionCosts.scala extraction:
    p.max_block_size = 524_288;
    p.token_access_cost = 100;
    p.input_cost = 2_000;
    p.data_input_cost = 100;
    p.output_cost = 100;
    ProtocolParams::from_active(&p)
}

// ── Test ─────────────────────────────────────────────────────────────────────

#[test]
#[ignore = "requires test-vectors/mainnet/{tx_costs,transactions,extensions,headers,input_boxes}_700000_700200*.json"]
fn cost_parity_against_scala_corpus_sampled() {
    let corpus: Vec<CorpusEntry> = serde_json::from_str(
        &std::fs::read_to_string("../test-vectors/mainnet/tx_costs_700000_700200.json")
            .expect("corpus missing — run extract_block_costs_voted_params.sh"),
    )
    .expect("parse corpus");

    // Group corpus by height.
    let mut corpus_by_height: HashMap<u32, HashMap<String, u64>> = HashMap::new();
    for e in &corpus {
        corpus_by_height
            .entry(e.height)
            .or_default()
            .insert(e.tx_id.clone(), e.block_cost);
    }

    // Load headers.
    let headers_raw: Vec<HeaderVec> = serde_json::from_str(
        &std::fs::read_to_string("../test-vectors/mainnet/headers_700000_700500.json").unwrap(),
    )
    .unwrap();
    let headers: HashMap<u32, (ergo_ser::header::Header, [u8; 32])> = headers_raw
        .iter()
        .map(|v| {
            let bytes = hex::decode(&v.bytes).unwrap();
            let h = read_header(&mut VlqReader::new(&bytes)).unwrap();
            let (_, id) = serialize_header(&h).expect("real mainnet header serializes");
            (v.height, (h, *id.as_bytes()))
        })
        .collect();

    // Load transactions grouped by height.
    let txs_raw: Vec<TxVec> = serde_json::from_str(
        &std::fs::read_to_string("../test-vectors/mainnet/transactions_700000_700200.json")
            .unwrap(),
    )
    .unwrap();
    let mut txs_by_height: HashMap<u32, Vec<(String, Vec<u8>)>> = HashMap::new();
    for t in &txs_raw {
        txs_by_height
            .entry(t.height)
            .or_default()
            .push((t.id.clone(), hex::decode(&t.bytes).unwrap()));
    }

    // Load extensions by height.
    let exts_raw: Vec<ExtVec> = serde_json::from_str(
        &std::fs::read_to_string("../test-vectors/mainnet/extensions_700000_700200.json").unwrap(),
    )
    .unwrap();
    let exts_by_height: HashMap<u32, ExtVec> =
        exts_raw.into_iter().map(|e| (e.height, e)).collect();

    // Seed MapUtxo from pre-extracted input boxes.
    let boxes_raw: Vec<InputBoxJson> = serde_json::from_str(
        &std::fs::read_to_string("../test-vectors/mainnet/input_boxes_700000_700200.json").unwrap(),
    )
    .unwrap();
    let mut utxo = MapUtxo::new();
    for ib in &boxes_raw {
        utxo.insert(parse_input_box(ib));
    }
    eprintln!("Seeded UTXO with {} input boxes", boxes_raw.len());

    let params = params_at_700k();
    let mut sorted_heights: Vec<u32> = headers.keys().copied().collect();
    sorted_heights.sort();

    let mut matches = 0usize;
    let mut mismatches = 0usize;

    let mut heights: Vec<u32> = corpus_by_height.keys().copied().collect();
    heights.sort();

    for h in heights {
        let (ref header, ref header_id) = match headers.get(&h) {
            Some(v) => v,
            None => {
                eprintln!("SKIP h={h}: no header");
                continue;
            }
        };
        let (ref parent, ref parent_id) = match headers.get(&(h - 1)) {
            Some(v) => v,
            None => {
                eprintln!("SKIP h={h}: no parent header");
                continue;
            }
        };

        // Build BlockTransactions from pre-extracted tx bytes.
        let txs_vec = txs_by_height.get(&h).cloned().unwrap_or_default();
        let transactions: Vec<ergo_ser::transaction::Transaction> = txs_vec
            .iter()
            .map(|(_, b)| read_transaction(&mut VlqReader::new(b)).expect("parse tx"))
            .collect();
        let bt = BlockTransactions {
            header_id: ModifierId::from_bytes(*header_id),
            transactions,
        };

        // Build Extension from pre-extracted fields.
        let ext = match exts_by_height.get(&h) {
            Some(ev) => {
                let hid = ModifierId::from_bytes(*header_id);
                let fields = ev
                    .fields
                    .iter()
                    .map(|(k, v)| ExtensionField {
                        key: hex::decode(k).unwrap().try_into().unwrap(),
                        value: hex::decode(v).unwrap(),
                    })
                    .collect();
                Extension {
                    header_id: hid,
                    fields,
                }
            }
            None => {
                eprintln!("SKIP h={h}: no extension");
                continue;
            }
        };

        // Build last 10 headers (Scala oracle uses empty — match it).
        let pos = sorted_heights.partition_point(|&hh| hh < h);
        let start = pos.saturating_sub(10);
        let last_headers: Vec<CheckedHeader> = sorted_heights[start..pos]
            .iter()
            .filter_map(|hh| {
                headers
                    .get(hh)
                    .map(|(hdr, id)| CheckedHeader::trust_me(hdr.clone(), *id))
            })
            .collect();

        let parent_checked = CheckedHeader::trust_me(parent.clone(), *parent_id);
        let checked_header = CheckedHeader::trust_me(header.clone(), *header_id);

        let ctx = BlockValidationContext {
            parent: &parent_checked,
            utxo: &utxo,
            params: &params,
            voting_length: 1024,
            parent_extension: None,
            soft_fork_state: None,
            last_headers: &last_headers,
            script_validation_checkpoint: None,
        };

        let (checked_block, per_tx_costs) =
            match validate_full_block_parallel_with_costs(checked_header, &bt, &ext, &ctx) {
                Ok(r) => r,
                Err(e) => panic!("validation failed at h={h}: {e}"),
            };

        // Advance UTXO overlay.
        utxo.apply_checked(checked_block.transactions());

        // Map tx index → hex tx_id → cost.
        let block_txs = checked_block.transactions();
        let mut computed: HashMap<String, u64> = HashMap::new();
        for (idx, cost) in &per_tx_costs {
            if let Some(tx) = block_txs.get(*idx) {
                if let Ok(tx_id) = ergo_ser::transaction::transaction_id(tx.transaction()) {
                    computed.insert(hex::encode(tx_id.as_bytes()), *cost);
                }
            }
        }

        for (tx_id, &expected_cost) in &corpus_by_height[&h] {
            match computed.get(tx_id) {
                Some(&got) if got == expected_cost => {
                    matches += 1;
                }
                Some(&got) => {
                    mismatches += 1;
                    eprintln!(
                        "MISMATCH h={h} tx={}.. expected={expected_cost} got={got}",
                        &tx_id[..8]
                    );
                }
                None => {
                    mismatches += 1;
                    eprintln!(
                        "MISSING  h={h} tx={}.. (not in validated output)",
                        &tx_id[..8]
                    );
                }
            }
        }
    }

    let total = matches + mismatches;
    eprintln!(
        "[cost_parity] {matches}/{total} exact matches ({} corpus entries)",
        corpus.len()
    );
    assert_eq!(
        mismatches, 0,
        "{mismatches}/{total} cost mismatches — see stderr for details"
    );
}

#[test]
#[ignore = "requires extracted corpus + pre-extracted UTXO snapshots"]
fn cost_parity_at_v2_activation_h_417792() {
    // v1 → v2 forced-activation oracle.
    eprintln!("[cost_parity_oracle] STUB: v2 activation fixture pending");
}

#[test]
#[ignore = "requires soft-fork activation fixture"]
fn cost_parity_at_eip37_activation() {
    // EIP-37 activation: rule 409 disabled at this epoch boundary.
    eprintln!("[cost_parity_oracle] STUB: EIP-37 activation fixture pending");
}
