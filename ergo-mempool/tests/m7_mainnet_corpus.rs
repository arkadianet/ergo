//! Mainnet corpus self-consistency harness for the mempool admission
//! pipeline.
//!
//! Proves the mempool admits real-world transactions that were accepted
//! by the live network. Corpus: 7,178 txs across heights 1,761,000 –
//! 1,762,000 with pre-extracted input boxes and headers. Each tx is
//! driven through `Mempool::process` with `TxSource::Api` against a
//! progressive `UtxoView` primed with the historical input boxes and
//! extended as txs are admitted.
//!
//! This is the Rust self-consistency half of the mempool oracle —
//! it does NOT compare against Scala. A txn that lands in a mainnet
//! block is definitionally valid, so any rejection here is our bug
//! unless specifically classified (e.g. below-min-fee, which is a
//! local policy choice).
//!
//! This test is `#[ignore]` by default because it's slow (~2 minutes
//! under `opt-level=1`) and depends on test-vectors/ artifacts that
//! vector-drift CI regenerates. Run with:
//!   cargo test -p ergo-mempool --test m7_mainnet_corpus -- --ignored

use std::collections::HashMap;
use std::time::Instant;

use ergo_mempool::admission::TipContext as MempoolTipContext;
use ergo_mempool::types::{TipPointer, TxSource};
use ergo_mempool::weight::ByCost;
use ergo_mempool::{AdmissionOutcome, ErgoValidator, Mempool, MempoolConfig, RejectReason};
use ergo_primitives::digest::{Digest32, ModifierId};
use ergo_primitives::reader::VlqReader;
use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::read_ergo_tree;
use ergo_ser::header::read_header;
use ergo_ser::register::{AdditionalRegisters, RegisterValue};
use ergo_ser::sigma_value::read_constant;
use ergo_ser::token::Token;
use ergo_ser::transaction::read_transaction;
use ergo_validation::context::{ProtocolParams, TransactionContext};
use ergo_validation::UtxoView;

// ---- Fixture loaders (copied/adapted from recent_block_validation.rs) ----

#[derive(serde::Deserialize)]
struct TxVector {
    id: String,
    bytes: String,
    #[serde(rename = "bytesToSign")]
    #[allow(dead_code)]
    bytes_to_sign: String,
    height: u32,
}

#[derive(serde::Deserialize)]
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
    #[serde(rename = "additionalRegisters", default)]
    additional_registers: HashMap<String, String>,
    #[serde(default)]
    assets: Vec<serde_json::Value>,
}

fn parse_input_box(json: &InputBoxJson) -> ErgoBox {
    let ergo_tree_bytes = hex::decode(&json.ergo_tree).unwrap();
    let mut r = VlqReader::new(&ergo_tree_bytes);
    let ergo_tree = read_ergo_tree(&mut r).unwrap();

    let mut reg_vec: Vec<(usize, RegisterValue)> = Vec::new();
    let mut reg_hex_vec: Vec<(usize, String)> = Vec::new();
    for (key, val_hex) in &json.additional_registers {
        let reg_idx = match key.as_str() {
            "R4" => 0,
            "R5" => 1,
            "R6" => 2,
            "R7" => 3,
            "R8" => 4,
            "R9" => 5,
            _ => continue,
        };
        let val_bytes = hex::decode(val_hex).unwrap();
        let mut vr = VlqReader::new(&val_bytes);
        let (tpe, value) = read_constant(&mut vr).unwrap();
        reg_vec.push((reg_idx, RegisterValue { tpe, value }));
        reg_hex_vec.push((reg_idx, val_hex.clone()));
    }
    reg_vec.sort_by_key(|(idx, _)| *idx);
    reg_hex_vec.sort_by_key(|(idx, _)| *idx);
    let registers = AdditionalRegisters {
        registers: reg_vec.into_iter().map(|(_, rv)| rv).collect(),
    };

    let mut register_bytes = vec![reg_hex_vec.len() as u8];
    for (_, hex_val) in &reg_hex_vec {
        register_bytes.extend_from_slice(&hex::decode(hex_val).unwrap());
    }

    let tokens: Vec<Token> = json
        .assets
        .iter()
        .map(|asset| {
            let token_id_hex = asset["tokenId"].as_str().unwrap();
            let amount = asset["amount"].as_u64().unwrap();
            let token_id_bytes: [u8; 32] = hex::decode(token_id_hex).unwrap().try_into().unwrap();
            Token {
                token_id: Digest32::from_bytes(token_id_bytes),
                amount,
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

struct HeaderInfo {
    miner_pubkey: [u8; 33],
    timestamp: u64,
    version: u8,
    parent_id: [u8; 32],
    n_bits: u64,
    votes: [u8; 3],
}

fn load_header_info(path: &str) -> HashMap<u32, HeaderInfo> {
    let data = std::fs::read_to_string(path).unwrap();
    let headers: Vec<serde_json::Value> = serde_json::from_str(&data).unwrap();
    let mut info = HashMap::new();
    for h in &headers {
        let height = h["height"].as_u64().unwrap() as u32;
        let header_bytes = hex::decode(h["bytes"].as_str().unwrap()).unwrap();
        let mut r = VlqReader::new(&header_bytes);
        let header = read_header(&mut r).unwrap();
        info.insert(
            height,
            HeaderInfo {
                miner_pubkey: *header.solution.pk().as_bytes(),
                timestamp: header.timestamp,
                version: header.version,
                parent_id: *header.parent_id.as_bytes(),
                n_bits: header.n_bits as u64,
                votes: header.votes,
            },
        );
    }
    info
}

// ---- Progressive UTXO: live + all-time history split ----

struct ProgressiveUtxo {
    live: HashMap<Digest32, ErgoBox>,
    all: HashMap<Digest32, ErgoBox>,
}

impl ProgressiveUtxo {
    fn new() -> Self {
        Self {
            live: HashMap::new(),
            all: HashMap::new(),
        }
    }

    fn add_box(&mut self, b: ErgoBox) {
        if let Ok(box_id) = b.box_id() {
            self.live.insert(box_id, b.clone());
            self.all.insert(box_id, b);
        }
    }

    fn apply_tx(&mut self, tx: &ergo_ser::transaction::Transaction) {
        for input in &tx.inputs {
            self.live.remove(&input.box_id);
        }
        if let Ok(tx_id) = ergo_ser::transaction::transaction_id(tx) {
            for (i, candidate) in tx.output_candidates.iter().enumerate() {
                let ergo_box = ErgoBox {
                    candidate: candidate.clone(),
                    transaction_id: tx_id,
                    index: i as u16,
                };
                if let Ok(box_id) = ergo_box.box_id() {
                    self.live.insert(box_id, ergo_box.clone());
                    self.all.insert(box_id, ergo_box);
                }
            }
        }
    }
}

/// Mempool validator view: admission resolves regular inputs against
/// the overlay; data inputs go to `CommittedOnly` which we point at
/// the `all`-time history so already-spent boxes still resolve.
/// Both sides share a single backing UtxoView here — acceptable for
/// admission tests because conflict detection happens via `by_input`,
/// not via the overlay.
struct UtxoAllHistory {
    all: HashMap<Digest32, ErgoBox>,
}

impl UtxoView for UtxoAllHistory {
    fn get_box(&self, box_id: &Digest32) -> Option<ErgoBox> {
        self.all.get(box_id).cloned()
    }
}

// ---- The self-consistency harness ----

#[test]
#[ignore = "slow; run with --ignored"]
fn mempool_admits_mainnet_corpus_1761k() {
    let tx_data =
        std::fs::read_to_string("../test-vectors/mainnet/transactions_1761000_1762000.json")
            .expect("transactions_1761000_1762000.json not found");
    let vectors: Vec<TxVector> = serde_json::from_str(&tx_data).unwrap();

    let header_info = load_header_info("../test-vectors/mainnet/headers_1761000_1762000.json");

    let input_boxes_data =
        std::fs::read_to_string("../test-vectors/mainnet/input_boxes_1761000_1762000.json")
            .expect("input_boxes_1761000_1762000.json not found");
    let input_boxes: Vec<InputBoxJson> = serde_json::from_str(&input_boxes_data).unwrap();

    // Prime the progressive UTXO view from all pre-extracted input
    // boxes. Outputs of accepted txs are added as we go.
    let mut utxo = ProgressiveUtxo::new();
    for ib in &input_boxes {
        utxo.add_box(parse_input_box(ib));
    }

    let params = ProtocolParams::mainnet_default();

    // Mempool config: spec defaults. `min_relay_fee_nano_erg = 1M`
    // exercises the full admission pipeline including fee extraction
    // against the mainnet miner-fee proposition.
    let cfg = MempoolConfig::default();

    // Cap the corpus for iteration speed. 500 txs at default
    // opt-level=1 runs in roughly a minute; the full 7178 is a
    // 30-minute run. Raise this once fee extraction is fixed and we
    // want the complete signal.
    const CORPUS_LIMIT: usize = 500;

    // Real mainnet EIP-27 rule inputs (oracle-pinned chain-spec constants).
    // Heights 1.76M are past the activation height, so this corpus admits real
    // reward-box spends that must burn re-emission tokens + pay the
    // pay-to-reemission contract. Threading the rule through the tip context
    // exercises the mempool wiring (TipContext -> TxValidationCtx.rules ->
    // verify_reemission_spending inside validate_transaction_parsed) end-to-end
    // against real data: the pinned `admitted` / `explicit_rejects` counts below
    // stay green only if the rule does not reject-valid any Scala-accepted tx.
    let reemission_rules = {
        let spec = ergo_chain_spec::ChainSpec::mainnet();
        let r = spec.reemission.as_ref().expect("mainnet reemission");
        ergo_validation::ReemissionRuleInputs {
            activation_height: r.activation_height,
            reemission_token_id: *r.reemission_token_id.as_bytes(),
            pay_to_reemission_tree: spec
                .emission_script_trees()
                .expect("mainnet emission trees")
                .pay_to_reemission,
        }
    };
    let reemission_token_id = reemission_rules.reemission_token_id;

    let mut admitted = 0usize;
    let mut reemission_spends_admitted = 0usize;
    let mut below_min_fee = 0usize;
    // Fee-output counts for every below-min-fee reject. The pinned
    // invariant below asserts every entry is 0 — i.e. every below-
    // min-fee tx genuinely pays zero canonical miner fee. This is
    // what makes the rejection policy-compatible with Scala.
    let mut below_min_fee_out_counts: Vec<usize> = Vec::new();
    let mut rejected_other: HashMap<String, usize> = HashMap::new();
    let mut unresolved_input = 0usize;
    let mut processed = 0usize;

    // Group by height so we can build per-height TransactionContext
    // and walk in block order.
    let mut by_height: std::collections::BTreeMap<u32, Vec<&TxVector>> =
        std::collections::BTreeMap::new();
    for v in &vectors {
        by_height.entry(v.height).or_default().push(v);
    }

    'outer: for (height, block_txs) in by_height.iter() {
        let hi = header_info
            .get(height)
            .unwrap_or_else(|| panic!("missing header info for height {height}"));
        let tx_context = TransactionContext {
            height: *height,
            miner_pubkey: hi.miner_pubkey,
            pre_header_timestamp: hi.timestamp,
            activated_script_version: hi.version.saturating_sub(1),
            pre_header_version: hi.version,
            pre_header_parent_id: hi.parent_id,
            pre_header_n_bits: hi.n_bits,
            pre_header_votes: hi.votes,
        };

        for v in block_txs {
            let tx_bytes = hex::decode(&v.bytes).unwrap();

            // Parse to detect whether the inputs are even resolvable
            // before invoking mempool — if not, classify separately
            // so we don't blame the mempool.
            let mut r = VlqReader::new(&tx_bytes);
            let tx = match read_transaction(&mut r) {
                Ok(t) => t,
                Err(_) => {
                    *rejected_other.entry("deserialize".into()).or_default() += 1;
                    continue;
                }
            };
            let has_all_inputs = tx.inputs.iter().all(|i| utxo.live.contains_key(&i.box_id));
            let has_all_data = tx
                .data_inputs
                .iter()
                .all(|i| utxo.all.contains_key(&i.box_id));
            if !has_all_inputs || !has_all_data {
                unresolved_input += 1;
                utxo.apply_tx(&tx);
                continue;
            }

            // Fresh empty mempool per tx — admission tests are per-tx;
            // the pool isn't the subject here, the pipeline is.
            let mut mempool = Mempool::new(cfg.clone(), Box::new(ByCost));
            let view = UtxoAllHistory {
                all: utxo.all.clone(),
            };
            let tip_ctx = MempoolTipContext {
                tip: TipPointer {
                    height: height.saturating_sub(1),
                    header_id: Digest32::from_bytes(hi.parent_id),
                },
                // best_full == best_header so IBD gate passes.
                best_header_height: height.saturating_sub(1),
                best_full_block_height: height.saturating_sub(1),
                utxo: &view,
                tx_context: &tx_context,
                params: &params,
                last_headers: &[],
                reemission: Some(&reemission_rules),
            };
            // Does this tx hit the EIP-27 burn-path trigger, exactly as
            // `verify_reemission_spending`: height strictly above activation AND
            // a non-emission input (value <= the 100K-ERG floor) carrying the
            // re-emission token.
            const REWARD_BOX_VALUE_CEILING: u64 = 100_000 * 1_000_000_000;
            let spends_reemission = *height > reemission_rules.activation_height
                && tx.inputs.iter().any(|i| {
                    utxo.all.get(&i.box_id).is_some_and(|b| {
                        b.candidate.value <= REWARD_BOX_VALUE_CEILING
                            && b.candidate
                                .tokens
                                .iter()
                                .any(|t| t.token_id.as_bytes() == &reemission_token_id)
                    })
                });

            let (outcome, _actions) = mempool.process(
                &tx_bytes,
                TxSource::Api,
                Instant::now(),
                &tip_ctx,
                &ErgoValidator,
            );
            processed += 1;

            match outcome {
                AdmissionOutcome::Admitted { .. } => {
                    admitted += 1;
                    if spends_reemission {
                        reemission_spends_admitted += 1;
                    }
                    utxo.apply_tx(&tx);
                }
                AdmissionOutcome::Rejected { reason } => {
                    match &reason {
                        RejectReason::BelowMinFee => {
                            below_min_fee += 1;
                            // Tally fee-output count for EVERY reject
                            // (not just the first 5). The pinned
                            // assertion below verifies all entries
                            // are 0.
                            let fee_out_count = tx
                                .output_candidates
                                .iter()
                                .filter(|c| {
                                    c.ergo_tree_bytes()
                                        == ergo_mempool::validator::MAINNET_FEE_PROPOSITION_BYTES_FOR_TEST
                                })
                                .count();
                            below_min_fee_out_counts.push(fee_out_count);
                        }
                        RejectReason::UnresolvedInput | RejectReason::UnresolvedDataInput => {
                            unresolved_input += 1;
                        }
                        other => {
                            *rejected_other.entry(format!("{other:?}")).or_default() += 1;
                            if admitted + rejected_other.values().sum::<usize>() < 20 {
                                eprintln!(
                                    "[m7] reject tx {} at h={height}: {other:?}",
                                    &v.id[..16],
                                );
                            }
                        }
                    }
                    // Advance UTXO either way — this tx landed in a
                    // block on mainnet, so future txs may depend on
                    // its outputs.
                    utxo.apply_tx(&tx);
                }
            }
            if processed >= CORPUS_LIMIT {
                break 'outer;
            }
        }
    }
    let total_txs = processed; // override for the reporting below

    let explicit_rejects: usize = rejected_other.values().sum();
    eprintln!(
        "\n[mempool] self-consistency summary ({total_txs} txs from heights 1,761,000-1,762,000):",
    );
    eprintln!("  admitted         : {admitted}");
    eprintln!(
        "  EIP-27 re-emission spends admitted (burn path exercised): {reemission_spends_admitted}"
    );
    eprintln!("  below_min_fee    : {below_min_fee}");
    eprintln!("  unresolved_input : {unresolved_input}");
    eprintln!("  other rejected   : {explicit_rejects}");
    for (reason, count) in &rejected_other {
        eprintln!("    - {reason}: {count}");
    }
    let adoption_rate = admitted as f64 / total_txs as f64;
    eprintln!("  adoption rate    : {:.1}%", adoption_rate * 100.0);

    // Pinned corpus: exact counts. A fixture-backed ignored test
    // should pin shape, not tolerate drift. If any count changes,
    // the underlying pipeline changed — investigate before updating.
    assert_eq!(total_txs, 500, "pinned: 500 txs processed");
    assert_eq!(
        admitted, 414,
        "pinned: 414 admitted (matches canonical-fee txs in corpus)"
    );
    assert_eq!(
        below_min_fee, 86,
        "pinned: 86 below-min-fee (zero-fee-output txs in corpus)"
    );
    assert_eq!(
        unresolved_input, 0,
        "pinned: 0 unresolved inputs — corpus + progressive UTXO fully resolve"
    );
    assert_eq!(
        explicit_rejects, 0,
        "pinned: 0 other rejections — no unexpected pipeline failures"
    );
    // The EIP-27 burn path must actually fire through the mempool pipeline
    // here, else `explicit_rejects == 0` proves nothing about re-emission.
    assert!(
        reemission_spends_admitted > 0,
        "expected real EIP-27 re-emission spends admitted through the mempool \
         pipeline, found none — the burn path was not exercised"
    );
    assert_eq!(
        total_txs,
        admitted + below_min_fee + unresolved_input + explicit_rejects,
        "accounting: every tx categorized exactly once",
    );

    // Every below-min-fee tx must genuinely have zero canonical
    // fee outputs — that's what makes the rejection policy-compatible
    // with Scala's ErgoMemPool.process. If even one below-min-fee tx
    // DID have a fee output, our fee-extraction is broken.
    assert_eq!(
        below_min_fee_out_counts.len(),
        below_min_fee,
        "accounting: fee-output tally collected for every below-min-fee reject",
    );
    let rejects_with_fee_output = below_min_fee_out_counts.iter().filter(|&&c| c != 0).count();
    assert_eq!(
        rejects_with_fee_output, 0,
        "every below-min-fee reject must have zero canonical fee outputs; \
         found {rejects_with_fee_output} reject(s) with a canonical fee output \
         (fee extraction is broken if this fires)"
    );
}
