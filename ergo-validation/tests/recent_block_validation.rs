//! Recent-block validation: 1,000 modern mainnet blocks.
//!
//! Validates every transaction in heights 1,761,000-1,762,000 through the
//! full pipeline (structural, monetary, script, cost recording). Uses
//! pre-extracted input boxes as the UtxoView, with progressive output
//! tracking for intra-window dependencies.
//!
//! Strict mode: asserts zero script/proof failures, zero unresolved
//! inputs, >=95% pass rate, and >=500 multi-tx blocks. Any regression in
//! the evaluator surfaces as a panic at the failing height.
//!
//! Limitation — pre-header context is partially stubbed (`parent_id`,
//! `n_bits`, `votes`, `version` all zero, `activated_script_version = 1`).
//! Scripts that read those header fields can still pass here while
//! diverging on a fully-contextualized block run. Full pre-header
//! parity is exercised by `full_block_validation.rs`; this harness
//! covers transaction-shape and evaluator-coverage breadth.
//!
//! Covers modern script patterns, recent protocol behavior, and higher
//! transaction density than the early-chain corpus.
//!
//! Note: input_boxes_1761000_1762000.json is extracted from the explorer
//! PostgreSQL database (extract_input_boxes_db.sh), not from the Scala
//! node API. Box data on mainnet is immutable, so drift detection is not
//! needed for this file. Transactions and headers ARE covered by vector-drift CI.

use std::collections::{BTreeMap, HashMap};

use ergo_primitives::digest::{Digest32, ModifierId};
use ergo_primitives::reader::VlqReader;
use ergo_ser::ergo_box::ErgoBox;
use ergo_ser::ergo_tree::read_ergo_tree;
use ergo_ser::register::{AdditionalRegisters, RegisterValue};
use ergo_ser::sigma_value::read_constant;
use ergo_ser::token::Token;
use ergo_ser::transaction::{read_transaction, Transaction};

use ergo_validation::context::{ProtocolParams, TransactionContext};
use ergo_validation::cost::CostAccumulator;
use ergo_validation::tx::{
    validate_transaction_parsed, validate_transaction_parsed_with_group_elements,
};

/// Progressive UTXO state with split resolution semantics.
///
/// - `live`: current UTXO set — spending inputs MUST resolve here
/// - `all`: every box ever seen — data inputs MAY reference spent boxes
///
/// Spending inputs are resolved strictly from `live`. Data inputs are
/// resolved from `all`, matching the protocol rule that data inputs are
/// read-only references that can point to already-spent boxes.
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
        let box_id = b.box_id().unwrap();
        self.live.insert(box_id, b.clone());
        self.all.insert(box_id, b);
    }

    fn apply_validated_tx(&mut self, tx: &Transaction) {
        for input in &tx.inputs {
            self.live.remove(&input.box_id);
        }
        let tx_id = ergo_ser::transaction::transaction_id(tx).unwrap();
        for (i, candidate) in tx.output_candidates.iter().enumerate() {
            let ergo_box = ErgoBox {
                candidate: candidate.clone(),
                transaction_id: tx_id,
                index: i as u16,
            };
            let box_id = ergo_box.box_id().unwrap();
            self.live.insert(box_id, ergo_box.clone());
            self.all.insert(box_id, ergo_box);
        }
    }

    /// Resolve spending inputs strictly from live UTXO.
    fn resolve_inputs(&self, tx: &Transaction) -> Result<Vec<ErgoBox>, Digest32> {
        tx.inputs
            .iter()
            .map(|input| self.live.get(&input.box_id).cloned().ok_or(input.box_id))
            .collect()
    }

    /// Resolve data inputs from the full historical set (data inputs are
    /// read-only references that may point to already-spent boxes).
    fn resolve_data_inputs(&self, tx: &Transaction) -> Result<Vec<ErgoBox>, Digest32> {
        tx.data_inputs
            .iter()
            .map(|di| self.all.get(&di.box_id).cloned().ok_or(di.box_id))
            .collect()
    }
}

#[derive(serde::Deserialize)]
struct TxVector {
    id: String,
    bytes: String,
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
    // Parse ergoTree but keep raw bytes verbatim (avoid re-serialization drift)
    let ergo_tree_bytes = hex::decode(&json.ergo_tree).unwrap();
    let mut r = VlqReader::new(&ergo_tree_bytes);
    let ergo_tree = read_ergo_tree(&mut r).unwrap();

    // Parse registers and build raw register bytes verbatim
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

    // Build raw register bytes: count(1 byte) + concatenated raw register hex
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

    // Construct with raw bytes to avoid re-serialization drift
    let candidate = ergo_ser::ergo_box::ErgoBoxCandidate::from_trusted_raw_parts(
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
}

fn load_header_info(path: &str) -> HashMap<u32, HeaderInfo> {
    let data = std::fs::read_to_string(path).unwrap();
    let headers: Vec<serde_json::Value> = serde_json::from_str(&data).unwrap();
    let mut info = HashMap::new();
    for h in &headers {
        let height = h["height"].as_u64().unwrap() as u32;
        let header_bytes = hex::decode(h["bytes"].as_str().unwrap()).unwrap();
        let mut r = VlqReader::new(&header_bytes);
        let header = ergo_ser::header::read_header(&mut r).unwrap();
        let pk = *header.solution.pk().as_bytes();
        info.insert(
            height,
            HeaderInfo {
                miner_pubkey: pk,
                timestamp: header.timestamp,
            },
        );
    }
    info
}

fn group_by_height(vectors: Vec<TxVector>) -> BTreeMap<u32, Vec<TxVector>> {
    let mut map: BTreeMap<u32, Vec<TxVector>> = BTreeMap::new();
    for v in vectors {
        map.entry(v.height).or_default().push(v);
    }
    map
}

/// Validate all transactions in a 1,000-block recent window.
///
/// Pre-populates the UTXO view with extracted input boxes, then processes
/// blocks in height order. For each transaction:
/// 1. Validate through full pipeline (structural + monetary + script)
/// 2. If accepted, add outputs to UTXO view for subsequent transactions
/// 3. Assert acceptance (all transactions were accepted on mainnet)
#[test]
fn validate_recent_1000_blocks() {
    // Load fixtures
    let tx_data =
        std::fs::read_to_string("../test-vectors/mainnet/transactions_1761000_1762000.json")
            .expect("transactions_1761000_1762000.json not found");
    let vectors: Vec<TxVector> = serde_json::from_str(&tx_data).unwrap();
    let total_txs = vectors.len();

    let header_info = load_header_info("../test-vectors/mainnet/headers_1761000_1762000.json");

    let input_boxes_data =
        std::fs::read_to_string("../test-vectors/mainnet/input_boxes_1761000_1762000.json")
            .expect("input_boxes_1761000_1762000.json not found");
    let input_boxes: Vec<InputBoxJson> = serde_json::from_str(&input_boxes_data).unwrap();

    // Build progressive UTXO view
    let mut utxo = ProgressiveUtxo::new();
    let mut loaded_boxes = 0;
    for ib in &input_boxes {
        let ergo_box = parse_input_box(ib);
        utxo.add_box(ergo_box);
        loaded_boxes += 1;
    }

    let blocks = group_by_height(vectors);
    let params = ProtocolParams::mainnet_default();

    // EIP-27 re-emission rules sourced from the oracle-pinned mainnet chain
    // spec (same constants the production node wires into block validation).
    // Heights 1.76M are well past the activation height (777_217), where the
    // emission box pays 12 ERG/block of re-emission tokens into reward boxes,
    // so this corpus contains real on-chain reward-box spends that must burn
    // the tokens and pay the pay-to-reemission contract. Scala accepted every
    // one of these blocks, so `verify_reemission_spending` must NOT reject any
    // of them (no reject-valid) — and the byte-exact pay-to-reemission tree
    // match is proven against real outputs by their acceptance.
    let reemission_spec = ergo_chain_spec::ChainSpec::mainnet();
    let reemission_params = reemission_spec
        .reemission
        .as_ref()
        .expect("mainnet reemission");
    let reemission_rules = ergo_validation::ReemissionRuleInputs {
        activation_height: reemission_params.activation_height,
        reemission_token_id: *reemission_params.reemission_token_id.as_bytes(),
        pay_to_reemission_tree: reemission_spec
            .emission_script_trees()
            .expect("mainnet emission trees")
            .pay_to_reemission,
    };
    let reemission_token_id = *reemission_params.reemission_token_id.as_bytes();

    let mut validated = 0;
    let mut multi_tx_blocks = 0;
    let mut missing_input_skipped = 0;
    let mut eval_gap_skipped = 0;
    // Count of validated txs that actually spend re-emission tokens (the
    // burn-path trigger), so the assertion below proves the rule was
    // exercised against real burns, not trivially skipped.
    let mut reemission_spends_checked = 0u32;
    // One-time regression: prove the threaded GE path curve-checks the points it
    // is given (perf follow-up — block path supplies pre-collected points instead
    // of re-parsing). Flipped true after the first successful tx is re-checked.
    let mut threaded_offcurve_checked = false;

    for (&height, block_txs) in &blocks {
        let hi = header_info
            .get(&height)
            .unwrap_or_else(|| panic!("missing header info for height {height}"));
        let ctx = TransactionContext {
            height,
            miner_pubkey: hi.miner_pubkey,
            pre_header_timestamp: hi.timestamp,
            activated_script_version: 1,
            pre_header_version: 0,
            pre_header_parent_id: [0u8; 32],
            pre_header_n_bits: 0,
            pre_header_votes: [0u8; 3],
        };

        if block_txs.len() > 1 {
            multi_tx_blocks += 1;
        }

        for v in block_txs {
            let tx_bytes = hex::decode(&v.bytes).unwrap();
            let mut r = VlqReader::new(&tx_bytes);
            let tx = read_transaction(&mut r).unwrap();

            // Resolve spending inputs from live UTXO only (strict)
            let resolved_inputs = match utxo.resolve_inputs(&tx) {
                Ok(inputs) => inputs,
                Err(_) => {
                    missing_input_skipped += 1;
                    utxo.apply_validated_tx(&tx);
                    continue;
                }
            };

            // Resolve data inputs from full historical set (data inputs
            // are read-only and may reference already-spent boxes)
            let resolved_data_inputs = match utxo.resolve_data_inputs(&tx) {
                Ok(data_inputs) => data_inputs,
                Err(_) => {
                    missing_input_skipped += 1;
                    utxo.apply_validated_tx(&tx);
                    continue;
                }
            };

            // Clone the (valid) tx + resolved inputs once, so that after a
            // successful validation we can re-run the THREADED group-element
            // variant with a deliberately off-curve point and confirm it is
            // rejected — i.e. that supplied points are actually curve-checked.
            let threaded_probe = (!threaded_offcurve_checked).then(|| {
                (
                    tx.clone(),
                    resolved_inputs.clone(),
                    resolved_data_inputs.clone(),
                )
            });

            let mut cost = CostAccumulator::recording_only();
            let mut tx_cx = ergo_validation::TxValidationCtx {
                ctx: &ctx,
                params: &params,
                cost: &mut cost,
                last_headers: &[],
            };
            match validate_transaction_parsed(
                tx,
                &tx_bytes,
                resolved_inputs,
                resolved_data_inputs,
                false,
                &mut tx_cx,
            ) {
                Ok(checked) => {
                    if let Some((tx_c, ri_c, rdi_c)) = threaded_probe {
                        // 0x02 + 32 zero bytes: valid prefix, not on secp256k1
                        // (the ge.rs off-curve fixture). The tx is otherwise the
                        // same one that just validated, so it reaches the GE
                        // stage and must reject there.
                        let mut off_curve = [0u8; 33];
                        off_curve[0] = 0x02;
                        let mut probe_cost = CostAccumulator::recording_only();
                        let mut probe_cx = ergo_validation::TxValidationCtx {
                            ctx: &ctx,
                            params: &params,
                            cost: &mut probe_cost,
                            last_headers: &[],
                        };
                        let res = validate_transaction_parsed_with_group_elements(
                            tx_c,
                            &tx_bytes,
                            &[off_curve],
                            ri_c,
                            rdi_c,
                            false,
                            &mut probe_cx,
                        );
                        assert!(
                            matches!(
                                res,
                                Err(ergo_validation::error::ValidationError::Deserialization(_))
                            ),
                            "threaded GE path must reject a supplied off-curve point; got {res:?}"
                        );
                        threaded_offcurve_checked = true;
                    }
                    let computed_id =
                        ergo_ser::transaction::transaction_id(checked.transaction()).unwrap();
                    assert_eq!(
                        hex::encode(computed_id.as_bytes()),
                        v.id,
                        "tx ID mismatch at height {}",
                        height
                    );
                    // EIP-27 re-emission burning (Scala verifyReemissionSpending):
                    // every real mainnet tx here must pass. A rejection would be
                    // a reject-valid divergence (Scala accepted this block).
                    ergo_validation::verify_reemission_spending(
                        checked.transaction(),
                        checked.resolved_inputs(),
                        height,
                        &reemission_rules,
                    )
                    .unwrap_or_else(|e| {
                        panic!(
                            "reject-valid: real mainnet tx {} at height {height} failed the \
                             EIP-27 re-emission check: {e}",
                            &v.id[..16]
                        )
                    });
                    if checked.resolved_inputs().iter().any(|b| {
                        b.candidate
                            .tokens
                            .iter()
                            .any(|t| t.token_id.as_bytes() == &reemission_token_id)
                    }) {
                        reemission_spends_checked += 1;
                    }
                    utxo.apply_validated_tx(checked.transaction());
                    validated += 1;
                }
                Err(ergo_validation::error::ValidationError::ProofFailed { .. })
                | Err(ergo_validation::error::ValidationError::ScriptError { .. }) => {
                    eval_gap_skipped += 1;
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
    }

    eprintln!(
        "Recent blocks: {validated}/{total_txs} validated, {missing_input_skipped} skipped (missing input), {eval_gap_skipped} skipped (script/proof), {multi_tx_blocks} multi-tx blocks, {loaded_boxes} pre-loaded boxes, {reemission_spends_checked} EIP-27 re-emission spends accepted"
    );

    // The corpus is post-activation and contains real re-emission-bearing
    // reward-box spends (~hundreds in this window); confirm the burn path was
    // actually exercised, not silently skipped, so the no-reject-valid result
    // above is meaningful.
    assert!(
        reemission_spends_checked > 0,
        "expected real EIP-27 re-emission spends in the 1.76M corpus, found none — \
         the burn path was not exercised"
    );

    assert_eq!(
        eval_gap_skipped, 0,
        "evaluator regression: {eval_gap_skipped} transactions failed on script/proof"
    );
    assert_eq!(
        missing_input_skipped, 0,
        "missing input regression: {missing_input_skipped} transactions had unresolvable inputs"
    );

    // Remaining skips are missing input/data-input boxes only.
    let pass_rate = validated as f64 / total_txs as f64 * 100.0;
    assert!(
        pass_rate >= 95.0,
        "expected >= 95% pass rate, got {pass_rate:.1}% ({validated}/{total_txs})"
    );
    assert!(
        multi_tx_blocks >= 500,
        "expected >= 500 multi-tx blocks in recent window, got {multi_tx_blocks}"
    );
}
