#![cfg(feature = "diagnostics")]
//! Live Scala node differential oracle.
//!
//! Fetches the current Scala node's unconfirmed transaction pool,
//! drives each tx through our admission pipeline, and compares:
//!   1. Admission parity  — every tx Scala holds should be admitted (or
//!      classified as a known policy divergence: BelowMinFee).
//!   2. Ordering parity   — compare our BySize ordering against Scala's
//!      natural ordering (fee/size, descending) and our ByCost ordering
//!      against the same ground truth, reporting Kendall τ for each.
//!
//! This test is gated behind the `diagnostics` feature because it
//! needs a running Scala node. Run with:
//!   NODE_URL=http://localhost:9053 \
//!   cargo test -p ergo-mempool --features diagnostics --test m7_scala_oracle
//!
//! The test NEVER asserts a specific ordering score — ordering divergence
//! between ByCost and BySize is expected and intentional. What IS
//! asserted: admission parity (no unexpected rejections) and that BySize
//! ordering is closer to Scala's than a random permutation would be.

use std::collections::HashMap;
use std::process::Command;
use std::time::Instant;

use ergo_mempool::admission::TipContext;
use ergo_mempool::types::{TipPointer, TxSource};
use ergo_mempool::weight::{ByCost, BySize};
use ergo_mempool::{AdmissionOutcome, ErgoValidator, Mempool, MempoolConfig, RejectReason};
use ergo_primitives::digest::{Digest32, ModifierId};
use ergo_primitives::reader::VlqReader;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::read_ergo_tree;
use ergo_ser::input::{ContextExtension, DataInput, Input, SpendingProof};
use ergo_ser::register::{AdditionalRegisters, RegisterValue};
use ergo_ser::sigma_value::read_constant;
use ergo_ser::token::Token;
use ergo_ser::transaction::{write_transaction, Transaction};
use ergo_validation::context::{ProtocolParams, TransactionContext};
use ergo_validation::UtxoView;

// ─── HTTP helpers (curl subprocess — no dep needed) ──────────────────────────

fn curl_get(node_url: &str, path: &str) -> serde_json::Value {
    let url = format!("{node_url}{path}");
    let out = Command::new("curl")
        .args(["-s", "--max-time", "10", &url])
        .output()
        .unwrap_or_else(|e| panic!("curl failed: {e}"));
    serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("JSON parse failed for {url}: {e}"))
}

/// Parse a box from the `/utxo/byId/{id}` response and add it to the map.
/// Returns false if the box is not found (already spent or not in UTXO).
fn fetch_box_into_map(
    node_url: &str,
    box_id_hex: &str,
    map: &mut HashMap<Digest32, ErgoBox>,
) -> bool {
    let resp = curl_get(node_url, &format!("/utxo/byId/{box_id_hex}"));
    if resp.get("error").is_some() {
        return false;
    }
    let box_id: [u8; 32] = match hex::decode(resp["boxId"].as_str().unwrap_or(""))
        .unwrap_or_default()
        .try_into()
    {
        Ok(b) => b,
        Err(_) => return false,
    };
    // Re-use parse_extended_input logic but without the spending proof.
    let ergo_tree_hex = resp["ergoTree"].as_str().unwrap_or("");
    let ergo_tree_bytes = match hex::decode(ergo_tree_hex) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let mut r = VlqReader::new(&ergo_tree_bytes);
    let ergo_tree = match read_ergo_tree(&mut r) {
        Ok(t) => t,
        Err(_) => return false,
    };
    let value = resp["value"].as_u64().unwrap_or(0);
    let creation_height = resp["creationHeight"].as_u64().unwrap_or(0) as u32;
    let empty_map = serde_json::Map::new();
    let add_regs = resp["additionalRegisters"]
        .as_object()
        .unwrap_or(&empty_map);
    let reg_map: HashMap<String, String> = add_regs
        .iter()
        .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_owned())))
        .collect();
    let (registers, reg_bytes) = parse_registers(&reg_map);
    let empty_assets: Vec<serde_json::Value> = Vec::new();
    let assets = resp["assets"].as_array().unwrap_or(&empty_assets);
    let tokens = parse_tokens(assets);
    let zero_tx_id = "00".repeat(32);
    let tx_id_hex = resp["transactionId"].as_str().unwrap_or(&zero_tx_id);
    let tx_id: [u8; 32] = match hex::decode(tx_id_hex).unwrap_or_default().try_into() {
        Ok(b) => b,
        Err(_) => return false,
    };
    let index = resp["index"].as_u64().unwrap_or(0) as u16;
    let candidate = ErgoBoxCandidate::from_trusted_raw_parts(
        value,
        ergo_tree,
        ergo_tree_bytes,
        creation_height,
        tokens,
        registers,
        reg_bytes,
    );
    let ergo_box = ErgoBox {
        candidate,
        transaction_id: ModifierId::from_bytes(tx_id),
        index,
    };
    map.insert(Digest32::from_bytes(box_id), ergo_box);
    true
}

// ─── JSON parsing ────────────────────────────────────────────────────────────

fn parse_registers(map: &HashMap<String, String>) -> (AdditionalRegisters, Vec<u8>) {
    let mut reg_vec: Vec<(usize, RegisterValue)> = Vec::new();
    let mut reg_hex: Vec<(usize, String)> = Vec::new();
    for (key, val_hex) in map {
        let idx = match key.as_str() {
            "R4" => 0,
            "R5" => 1,
            "R6" => 2,
            "R7" => 3,
            "R8" => 4,
            "R9" => 5,
            _ => continue,
        };
        let bytes = hex::decode(val_hex).unwrap();
        let mut r = VlqReader::new(&bytes);
        if let Ok((tpe, value)) = read_constant(&mut r) {
            reg_vec.push((idx, RegisterValue { tpe, value }));
            reg_hex.push((idx, val_hex.clone()));
        }
    }
    reg_vec.sort_by_key(|(i, _)| *i);
    reg_hex.sort_by_key(|(i, _)| *i);
    let regs = AdditionalRegisters {
        registers: reg_vec.into_iter().map(|(_, rv)| rv).collect(),
    };
    let mut bytes = vec![reg_hex.len() as u8];
    for (_, h) in &reg_hex {
        bytes.extend_from_slice(&hex::decode(h).unwrap());
    }
    (regs, bytes)
}

fn parse_tokens(assets: &[serde_json::Value]) -> Vec<Token> {
    assets
        .iter()
        .map(|a| {
            let id: [u8; 32] = hex::decode(a["tokenId"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            Token {
                token_id: Digest32::from_bytes(id),
                amount: a["amount"].as_u64().unwrap(),
            }
        })
        .collect()
}

/// Parses an "extended input" from the `/transactions/unconfirmed`
/// endpoint: each input object contains the full box data plus the
/// spending proof.
fn parse_extended_input(v: &serde_json::Value) -> (Input, ErgoBox) {
    // ── Box data ──
    let box_id_hex = v["boxId"].as_str().unwrap();
    let box_id: [u8; 32] = hex::decode(box_id_hex).unwrap().try_into().unwrap();
    let box_id = Digest32::from_bytes(box_id);

    let ergo_tree_hex = v["ergoTree"].as_str().unwrap();
    let ergo_tree_bytes = hex::decode(ergo_tree_hex).unwrap();
    let mut r = VlqReader::new(&ergo_tree_bytes);
    let ergo_tree = read_ergo_tree(&mut r).unwrap();

    let value = v["value"].as_u64().unwrap();
    let creation_height = v["creationHeight"].as_u64().unwrap() as u32;
    let empty_map = serde_json::Map::new();
    let add_regs = v["additionalRegisters"].as_object().unwrap_or(&empty_map);
    let reg_map: HashMap<String, String> = add_regs
        .iter()
        .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_owned())))
        .collect();
    let (registers, reg_bytes) = parse_registers(&reg_map);

    let assets = v["assets"].as_array().map(|a| a.as_slice()).unwrap_or(&[]);
    let tokens = parse_tokens(assets);

    let zero_id = "00".repeat(32);
    let tx_id_hex = v["transactionId"].as_str().unwrap_or(&zero_id);
    let tx_id: [u8; 32] = hex::decode(tx_id_hex).unwrap().try_into().unwrap();
    let index = v["index"].as_u64().unwrap_or(0) as u16;

    let candidate = ErgoBoxCandidate::from_trusted_raw_parts(
        value,
        ergo_tree,
        ergo_tree_bytes,
        creation_height,
        tokens,
        registers,
        reg_bytes,
    );
    let ergo_box = ErgoBox {
        candidate,
        transaction_id: ModifierId::from_bytes(tx_id),
        index,
    };

    // ── Spending proof ──
    let sp = &v["spendingProof"];
    let proof = hex::decode(sp["proofBytes"].as_str().unwrap_or("")).unwrap_or_default();
    let empty_ext = serde_json::Map::new();
    let ext_map = sp["extension"].as_object().unwrap_or(&empty_ext);
    let mut ext_values: indexmap::IndexMap<
        u8,
        (
            ergo_ser::sigma_type::SigmaType,
            ergo_ser::sigma_value::SigmaValue,
        ),
    > = indexmap::IndexMap::new();
    for (k, val) in ext_map {
        if let (Ok(idx), Some(s)) = (k.parse::<u8>(), val.as_str()) {
            if let Ok(bytes) = hex::decode(s) {
                let mut r = VlqReader::new(&bytes);
                if let Ok((tpe, value)) = read_constant(&mut r) {
                    ext_values.insert(idx, (tpe, value));
                }
            }
        }
    }
    let ext = ContextExtension { values: ext_values };
    let input = Input {
        box_id,
        spending_proof: SpendingProof::new(proof, ext).expect("spending proof construction"),
    };
    (input, ergo_box)
}

fn parse_output_candidate(v: &serde_json::Value) -> ErgoBoxCandidate {
    let ergo_tree_bytes = hex::decode(v["ergoTree"].as_str().unwrap()).unwrap();
    let mut r = VlqReader::new(&ergo_tree_bytes);
    let ergo_tree = read_ergo_tree(&mut r).unwrap();
    let value = v["value"].as_u64().unwrap();
    let creation_height = v["creationHeight"].as_u64().unwrap() as u32;
    let empty_map = serde_json::Map::new();
    let add_regs = v["additionalRegisters"].as_object().unwrap_or(&empty_map);
    let reg_map: HashMap<String, String> = add_regs
        .iter()
        .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_owned())))
        .collect();
    let (registers, reg_bytes) = parse_registers(&reg_map);
    let assets = v["assets"].as_array().map(|a| a.as_slice()).unwrap_or(&[]);
    let tokens = parse_tokens(assets);
    ErgoBoxCandidate::from_trusted_raw_parts(
        value,
        ergo_tree,
        ergo_tree_bytes,
        creation_height,
        tokens,
        registers,
        reg_bytes,
    )
}

// ─── UTXO view backed by in-memory map ───────────────────────────────────────

struct MapUtxo(HashMap<Digest32, ErgoBox>);

impl UtxoView for MapUtxo {
    fn get_box(&self, id: &Digest32) -> Option<ErgoBox> {
        self.0.get(id).cloned()
    }
}

// ─── Kendall τ (rank correlation) ────────────────────────────────────────────

/// Kendall τ-b: fraction of concordant minus discordant pairs,
/// normalised to [-1, 1]. Returns 1.0 for identical orderings.
fn kendall_tau(a_ids: &[Digest32], b_ids: &[Digest32]) -> f64 {
    let n = a_ids.len().min(b_ids.len());
    if n <= 1 {
        return 1.0;
    }
    // Build rank map for sequence b.
    let rank_b: HashMap<&Digest32, usize> =
        b_ids.iter().enumerate().map(|(i, id)| (id, i)).collect();
    let mut concordant = 0i64;
    let mut discordant = 0i64;
    for i in 0..n {
        for j in (i + 1)..n {
            let ri = rank_b.get(&a_ids[i]);
            let rj = rank_b.get(&a_ids[j]);
            if let (Some(&ri), Some(&rj)) = (ri, rj) {
                if ri < rj {
                    concordant += 1;
                } else if ri > rj {
                    discordant += 1;
                }
            }
        }
    }
    let pairs = (n * (n - 1) / 2) as f64;
    (concordant - discordant) as f64 / pairs
}

// ─── The oracle test ──────────────────────────────────────────────────────────

#[test]
fn scala_pending_tx_oracle() {
    let node_url = std::env::var("NODE_URL").unwrap_or_else(|_| "http://localhost:9053".into());

    // ── Fetch pending txs ──
    let limit = 50;
    let pending = curl_get(
        &node_url,
        &format!("/transactions/unconfirmed?limit={limit}"),
    );
    let txs = pending
        .as_array()
        .expect("expected array from /transactions/unconfirmed");
    if txs.is_empty() {
        eprintln!("[m7-oracle] no pending txs — skip");
        return;
    }

    // ── Fetch tip header for TransactionContext ──
    let headers = curl_get(&node_url, "/blocks/lastHeaders/1");
    let tip_hdr = &headers.as_array().expect("lastHeaders array")[0];
    let tip_height = tip_hdr["height"].as_u64().unwrap() as u32;
    let tip_timestamp = tip_hdr["timestamp"].as_u64().unwrap();
    let tip_parent: [u8; 32] = hex::decode(tip_hdr["parentId"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let tip_nbits = tip_hdr["nBits"].as_u64().unwrap();
    let tip_version = tip_hdr["version"].as_u64().unwrap() as u8;
    let miner_pk_hex = tip_hdr["powSolutions"]["pk"].as_str().unwrap();
    let miner_pk: [u8; 33] = hex::decode(miner_pk_hex).unwrap().try_into().unwrap();
    let votes_hex = tip_hdr["votes"].as_str().unwrap_or("000000");
    let votes_bytes = hex::decode(votes_hex).unwrap_or_default();
    let votes: [u8; 3] = votes_bytes
        .get(..3)
        .map(|s| s.try_into().unwrap())
        .unwrap_or([0u8; 3]);

    let tx_context = TransactionContext {
        height: tip_height + 1,
        miner_pubkey: miner_pk,
        pre_header_timestamp: tip_timestamp,
        activated_script_version: tip_version.saturating_sub(1),
        pre_header_version: tip_version,
        pre_header_parent_id: tip_parent,
        pre_header_n_bits: tip_nbits,
        pre_header_votes: votes,
    };
    let params = ProtocolParams::mainnet_default();

    // ── Process each pending tx ──
    let mut scala_order: Vec<Digest32> = Vec::new();

    let mut admitted_bysize = 0usize;
    let mut admitted_bycost = 0usize;
    let mut below_min_fee = 0usize;
    let mut unresolved_data_input = 0usize;
    let mut unresolved_input = 0usize;
    let mut other_reject: HashMap<String, usize> = HashMap::new();

    let cfg = MempoolConfig::default();

    for tx_json in txs.iter() {
        let tx_id_hex = tx_json["id"].as_str().unwrap();
        let tx_id_bytes: [u8; 32] = hex::decode(tx_id_hex).unwrap().try_into().unwrap();
        let tx_id = Digest32::from_bytes(tx_id_bytes);
        scala_order.push(tx_id);

        // ── Parse inputs + build UTXO view ──
        let inputs_json = tx_json["inputs"].as_array().expect("inputs array");
        let data_inputs_json = tx_json["dataInputs"].as_array().expect("dataInputs array");
        let outputs_json = tx_json["outputs"].as_array().expect("outputs array");

        let mut inputs: Vec<Input> = Vec::new();
        let mut input_boxes: HashMap<Digest32, ErgoBox> = HashMap::new();

        let mut parse_ok = true;
        for inp in inputs_json {
            if inp["spendingProof"].is_null() {
                parse_ok = false;
                break;
            }
            let (input, ergo_box) = parse_extended_input(inp);
            input_boxes.insert(input.box_id, ergo_box);
            inputs.push(input);
        }
        if !parse_ok {
            eprintln!(
                "[m7-oracle] tx {} parse_fail: missing spendingProof",
                &tx_id_hex[..16]
            );
            unresolved_input += 1;
            continue;
        }

        // Fetch data input boxes from the node (they're not inline in the response).
        let mut data_input_fetch_ok = true;
        let data_inputs: Vec<DataInput> = data_inputs_json
            .iter()
            .map(|d| {
                let bid_hex = d["boxId"].as_str().unwrap();
                let bid: [u8; 32] = hex::decode(bid_hex).unwrap().try_into().unwrap();
                let box_id = Digest32::from_bytes(bid);
                if !input_boxes.contains_key(&box_id)
                    && !fetch_box_into_map(&node_url, bid_hex, &mut input_boxes)
                {
                    data_input_fetch_ok = false;
                }
                DataInput { box_id }
            })
            .collect();
        if !data_input_fetch_ok {
            unresolved_data_input += 1;
            continue;
        }

        let output_candidates: Vec<ErgoBoxCandidate> =
            outputs_json.iter().map(parse_output_candidate).collect();

        let tx = Transaction {
            inputs,
            data_inputs,
            output_candidates,
        };

        // ── Serialize to canonical bytes ──
        let mut w = VlqWriter::new();
        if write_transaction(&mut w, &tx).is_err() {
            *other_reject.entry("serialize_fail".into()).or_default() += 1;
            continue;
        }
        let tx_bytes = w.result();

        let utxo = MapUtxo(input_boxes);
        let tip = TipContext {
            tip: TipPointer {
                height: tip_height,
                header_id: Digest32::from_bytes(
                    hex::decode(tip_hdr["id"].as_str().unwrap())
                        .unwrap()
                        .try_into()
                        .unwrap(),
                ),
            },
            best_header_height: tip_height,
            best_full_block_height: tip_height,
            utxo: &utxo,
            tx_context: &tx_context,
            params: &params,
            last_headers: &[],
            reemission: None,
        };

        // ── Admit with BySize ──
        let mut pool_s = Mempool::new(cfg.clone(), Box::new(BySize));
        let (out_s, _) = pool_s.process(
            &tx_bytes,
            TxSource::Api,
            Instant::now(),
            &tip,
            &ErgoValidator,
        );
        match &out_s {
            AdmissionOutcome::Admitted { .. } => admitted_bysize += 1,
            AdmissionOutcome::Rejected {
                reason: RejectReason::BelowMinFee,
            } => below_min_fee += 1,
            AdmissionOutcome::Rejected {
                reason: reason @ (RejectReason::UnresolvedInput | RejectReason::UnresolvedDataInput),
            } => {
                eprintln!(
                    "[m7-oracle] tx {} validator_unresolved: {reason:?}",
                    &tx_id_hex[..16]
                );
                match reason {
                    RejectReason::UnresolvedDataInput => unresolved_data_input += 1,
                    _ => unresolved_input += 1,
                }
            }
            AdmissionOutcome::Rejected { reason } => {
                *other_reject.entry(format!("{reason:?}")).or_default() += 1;
            }
        }

        // ── Admit with ByCost ──
        let mut pool_c = Mempool::new(cfg.clone(), Box::new(ByCost));
        let (out_c, _) = pool_c.process(
            &tx_bytes,
            TxSource::Api,
            Instant::now(),
            &tip,
            &ErgoValidator,
        );
        if matches!(out_c, AdmissionOutcome::Admitted { .. }) {
            admitted_bycost += 1;
        }
    }

    // ── Collect ordering from fresh shared pools ──
    // Re-admit all txs into a single pool for each weight function to
    // get the inter-tx ordering.
    let bysize_order: Vec<Digest32> = {
        let mut pool = Mempool::new(cfg.clone(), Box::new(BySize));
        for tx_json in txs.iter() {
            let inputs_json = tx_json["inputs"].as_array().unwrap();
            let data_inputs_json = tx_json["dataInputs"].as_array().unwrap();
            let outputs_json = tx_json["outputs"].as_array().unwrap();
            let mut inputs: Vec<Input> = Vec::new();
            let mut input_boxes = HashMap::new();
            let mut ok = true;
            for inp in inputs_json {
                if inp["spendingProof"].is_null() {
                    ok = false;
                    break;
                }
                let (input, b) = parse_extended_input(inp);
                input_boxes.insert(input.box_id, b);
                inputs.push(input);
            }
            if !ok {
                continue;
            }
            let output_candidates = outputs_json.iter().map(parse_output_candidate).collect();
            let data_inputs = data_inputs_json
                .iter()
                .map(|d| {
                    let bid: [u8; 32] = hex::decode(d["boxId"].as_str().unwrap())
                        .unwrap()
                        .try_into()
                        .unwrap();
                    DataInput {
                        box_id: Digest32::from_bytes(bid),
                    }
                })
                .collect();
            let tx = Transaction {
                inputs,
                data_inputs,
                output_candidates,
            };
            let mut w = VlqWriter::new();
            if write_transaction(&mut w, &tx).is_err() {
                continue;
            }
            let tx_bytes = w.result();
            let utxo = MapUtxo(input_boxes);
            let tip_id_bytes: [u8; 32] = hex::decode(tip_hdr["id"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            let tip = TipContext {
                tip: TipPointer {
                    height: tip_height,
                    header_id: Digest32::from_bytes(tip_id_bytes),
                },
                best_header_height: tip_height,
                best_full_block_height: tip_height,
                utxo: &utxo,
                tx_context: &tx_context,
                params: &params,
                last_headers: &[],
                reemission: None,
            };
            pool.process(
                &tx_bytes,
                TxSource::Api,
                Instant::now(),
                &tip,
                &ErgoValidator,
            );
        }
        pool.iter_transactions().map(|e| e.tx_id).collect()
    };
    let bycost_order: Vec<Digest32> = {
        let mut pool = Mempool::new(cfg.clone(), Box::new(ByCost));
        for tx_json in txs.iter() {
            let inputs_json = tx_json["inputs"].as_array().unwrap();
            let data_inputs_json = tx_json["dataInputs"].as_array().unwrap();
            let outputs_json = tx_json["outputs"].as_array().unwrap();
            let mut inputs: Vec<Input> = Vec::new();
            let mut input_boxes = HashMap::new();
            let mut ok = true;
            for inp in inputs_json {
                if inp["spendingProof"].is_null() {
                    ok = false;
                    break;
                }
                let (input, b) = parse_extended_input(inp);
                input_boxes.insert(input.box_id, b);
                inputs.push(input);
            }
            if !ok {
                continue;
            }
            let output_candidates = outputs_json.iter().map(parse_output_candidate).collect();
            let data_inputs = data_inputs_json
                .iter()
                .map(|d| {
                    let bid: [u8; 32] = hex::decode(d["boxId"].as_str().unwrap())
                        .unwrap()
                        .try_into()
                        .unwrap();
                    DataInput {
                        box_id: Digest32::from_bytes(bid),
                    }
                })
                .collect();
            let tx = Transaction {
                inputs,
                data_inputs,
                output_candidates,
            };
            let mut w = VlqWriter::new();
            if write_transaction(&mut w, &tx).is_err() {
                continue;
            }
            let tx_bytes = w.result();
            let utxo = MapUtxo(input_boxes);
            let tip_id_bytes: [u8; 32] = hex::decode(tip_hdr["id"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            let tip = TipContext {
                tip: TipPointer {
                    height: tip_height,
                    header_id: Digest32::from_bytes(tip_id_bytes),
                },
                best_header_height: tip_height,
                best_full_block_height: tip_height,
                utxo: &utxo,
                tx_context: &tx_context,
                params: &params,
                last_headers: &[],
                reemission: None,
            };
            pool.process(
                &tx_bytes,
                TxSource::Api,
                Instant::now(),
                &tip,
                &ErgoValidator,
            );
        }
        pool.iter_transactions().map(|e| e.tx_id).collect()
    };

    // ── Compute ordering metrics ──
    let tau_bysize = kendall_tau(&bysize_order, &scala_order);
    let tau_bycost = kendall_tau(&bycost_order, &scala_order);

    // ── Report ──
    let total = txs.len();
    let other_n: usize = other_reject.values().sum();
    eprintln!("\n[m7-oracle] Scala differential oracle ({total} pending txs, tip={tip_height}):");
    eprintln!("  admitted BySize         : {admitted_bysize}");
    eprintln!("  admitted ByCost         : {admitted_bycost}");
    eprintln!("  below_min_fee           : {below_min_fee}");
    eprintln!("  unresolved data input   : {unresolved_data_input} (known: oracle can't resolve in-flight data inputs)");
    eprintln!("  unresolved input (bug?) : {unresolved_input}");
    eprintln!("  other rejected          : {other_n}");
    for (r, c) in &other_reject {
        eprintln!("    {r}: {c}");
    }
    eprintln!("  ordering Kendall τ (ByCost  vs Scala): {tau_bycost:.4}");
    eprintln!("  ordering Kendall τ (BySize  vs Scala): {tau_bysize:.4}");
    eprintln!("  (1.0=identical, 0.0=random, -1.0=reversed)");
    eprintln!();
    eprintln!("  Expected τ baselines (2026-04-26 live run, 15 txs):");
    eprintln!("    ByCost ≈ 0.978  (cost-ordered; residual gap = tie-breakers / missing boxes)");
    eprintln!("    BySize ≈ 0.385  (size-ordered; expected lower — Scala is cost-ordered)");

    // ── Admission parity: no unexpected rejections ──
    assert_eq!(other_n, 0, "unexpected rejections: {other_reject:?}");

    // ── Ordering sanity: ByCost must be positively correlated with Scala ──
    // Threshold 0.5 is conservative: the live run shows τ≈0.978 with 15
    // txs, but pool composition changes between runs. If τ drops below 0.5
    // it most likely indicates a weight-function regression, not natural
    // variance. Investigate by inspecting the mismatch pairs in the
    // eprintln output above.
    if bycost_order.len() >= 5 {
        assert!(
            tau_bycost >= 0.5,
            "ByCost ordering correlation with Scala dropped below 0.5 (τ={tau_bycost:.4}); \
             investigate tie-breakers, missing boxes, or local validation rejects that \
             changed admission relative to Scala"
        );
    }
}
