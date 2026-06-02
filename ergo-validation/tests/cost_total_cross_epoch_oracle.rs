//! Cross-epoch Scala-anchored cost-total parity.
//!
//! The companion `cost_total_oracle.rs` exercises h=700000-700001 where
//! every cost-bearing voted parameter happens to equal
//! `ProtocolParams::mainnet_default()`. This test exercises h=1500000+
//! where the epoch at h=1499136 has voted `inputCost=2407`
//! (default=2000) and `outputCost=298` (default=100) — so a Rust
//! oracle that uses `mainnet_default()` would over- or under-count by
//! `(num_inputs * 407) + (num_outputs * 198)` per transaction.
//!
//! The fixture bundles a `voted_params_epoch_1499136` snapshot. The
//! test reconstructs `ActiveProtocolParameters` from that snapshot and
//! threads it through `ProtocolParams::from_active`. A drift in voted-
//! params handling, or in any of `compute_tx_init_cost`'s per-param
//! multipliers, fails this test.
//!
//! Fixture is fully self-contained: `tx_bytes`, `input_boxes`, per-
//! height header context, and the voted-params snapshot all live in
//! `mainnet_1500000_cross_epoch.json`. No network, no feature flag.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use ergo_primitives::digest::{Digest32, ModifierId};
use ergo_primitives::reader::VlqReader;
use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::read_ergo_tree;
use ergo_ser::register::{AdditionalRegisters, RegisterValue};
use ergo_ser::sigma_value::read_constant;
use ergo_ser::token::Token;

use ergo_validation::active_params::ActiveProtocolParameters;
use ergo_validation::context::{LocalPolicy, ProtocolParams, TransactionContext};
use ergo_validation::cost::{CostAccumulator, JitCost};
use ergo_validation::tx::validate_transaction;
use ergo_validation::voting::validation_settings::ErgoValidationSettingsUpdate;
use ergo_validation::UtxoView;

#[derive(serde::Deserialize)]
struct HeaderRecord {
    timestamp: u64,
    n_bits: u64,
    version: u8,
    miner_pk_hex: String,
}

#[derive(serde::Deserialize)]
struct VotedParams {
    #[serde(rename = "storageFeeFactor")]
    storage_fee_factor: i32,
    #[serde(rename = "minValuePerByte")]
    min_value_per_byte: i32,
    #[serde(rename = "maxBlockSize")]
    max_block_size: i32,
    #[serde(rename = "maxBlockCost")]
    max_block_cost: i32,
    #[serde(rename = "tokenAccessCost")]
    token_access_cost: i32,
    #[serde(rename = "inputCost")]
    input_cost: i32,
    #[serde(rename = "dataInputCost")]
    data_input_cost: i32,
    #[serde(rename = "outputCost")]
    output_cost: i32,
    #[serde(rename = "blockVersion")]
    block_version: i32,
}

#[derive(serde::Deserialize)]
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
    assets: Vec<serde_json::Value>,
    #[serde(rename = "additionalRegisters", default)]
    additional_registers: serde_json::Value,
}

#[derive(serde::Deserialize)]
struct TxRecord {
    tx_id: String,
    height: u32,
    block_cost: u64,
    tx_bytes: String,
    input_boxes: Vec<InputBoxJson>,
}

#[derive(serde::Deserialize)]
struct Fixture {
    #[serde(rename = "voted_params_epoch_1499136")]
    voted_params: VotedParams,
    headers: HashMap<String, HeaderRecord>,
    fixtures: Vec<TxRecord>,
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace parent")
        .to_path_buf()
}

fn load_fixture() -> Fixture {
    let path = workspace_root()
        .join("test-vectors/ergo-sigma/cost-total/mainnet_1500000_cross_epoch.json");
    let raw =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&raw).expect("cross-epoch fixture json")
}

fn parse_input_box(b: &InputBoxJson) -> (Digest32, ErgoBox) {
    let box_id_bytes: [u8; 32] = hex::decode(&b.box_id)
        .expect("boxId hex")
        .try_into()
        .expect("boxId len");
    let json_box_id = Digest32::from_bytes(box_id_bytes);

    let ergo_tree_bytes = hex::decode(&b.ergo_tree).expect("ergoTree hex");
    let mut r = VlqReader::new(&ergo_tree_bytes);
    let ergo_tree = read_ergo_tree(&mut r).expect("ergoTree parse");

    let reg_map: HashMap<String, String> = b
        .additional_registers
        .as_object()
        .map(|obj| {
            obj.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_owned())))
                .collect()
        })
        .unwrap_or_default();
    let (registers, reg_bytes) = parse_registers(&reg_map);
    let tokens = parse_tokens(&b.assets);

    let tx_id_bytes: [u8; 32] = hex::decode(&b.transaction_id)
        .expect("transactionId hex")
        .try_into()
        .expect("transactionId len");

    let candidate = ErgoBoxCandidate::from_trusted_raw_parts(
        b.value,
        ergo_tree,
        ergo_tree_bytes,
        b.creation_height,
        tokens,
        registers,
        reg_bytes,
    );
    let ebox = ErgoBox {
        candidate,
        transaction_id: ModifierId::from_bytes(tx_id_bytes),
        index: b.index,
    };

    let computed = ebox
        .box_id()
        .unwrap_or_else(|e| panic!("box_id() for {}: {e}", b.box_id));
    assert_eq!(
        computed, json_box_id,
        "reconstructed input box bytes diverge for boxId={}",
        b.box_id,
    );
    (json_box_id, ebox)
}

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
        let bytes = hex::decode(val_hex).expect("register hex");
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
        bytes.extend_from_slice(&hex::decode(h).expect("register hex"));
    }
    (regs, bytes)
}

fn parse_tokens(assets: &[serde_json::Value]) -> Vec<Token> {
    assets
        .iter()
        .map(|a| {
            let id: [u8; 32] = hex::decode(a["tokenId"].as_str().expect("tokenId"))
                .expect("tokenId hex")
                .try_into()
                .expect("tokenId len");
            Token {
                token_id: Digest32::from_bytes(id),
                amount: a["amount"].as_u64().expect("token amount"),
            }
        })
        .collect()
}

struct MapUtxo(HashMap<Digest32, ErgoBox>);

impl UtxoView for MapUtxo {
    fn get_box(&self, id: &Digest32) -> Option<ErgoBox> {
        self.0.get(id).cloned()
    }
}

fn build_active_params(voted: &VotedParams) -> ActiveProtocolParameters {
    ActiveProtocolParameters {
        epoch_start_height: 1499136,
        block_version: voted.block_version as u8,
        storage_fee_factor: voted.storage_fee_factor,
        min_value_per_byte: voted.min_value_per_byte,
        max_block_size: voted.max_block_size,
        max_block_cost: voted.max_block_cost,
        token_access_cost: voted.token_access_cost,
        input_cost: voted.input_cost,
        data_input_cost: voted.data_input_cost,
        output_cost: voted.output_cost,
        subblocks_per_block: None,
        extra: vec![],
        proposed_update: ErgoValidationSettingsUpdate::empty(),
        activated_update: ErgoValidationSettingsUpdate::empty(),
    }
}

fn build_ctx(h: &HeaderRecord, height: u32) -> TransactionContext {
    let pk_bytes = hex::decode(&h.miner_pk_hex).expect("miner pk hex");
    let miner_pubkey: [u8; 33] = pk_bytes.try_into().expect("miner pk len");
    TransactionContext {
        height,
        miner_pubkey,
        pre_header_timestamp: h.timestamp,
        activated_script_version: h.version.saturating_sub(1),
        pre_header_version: h.version,
        pre_header_parent_id: [0u8; 32],
        pre_header_n_bits: h.n_bits,
        pre_header_votes: [0u8; 3],
    }
}

fn build_utxo(tx_record: &TxRecord) -> MapUtxo {
    let mut map: HashMap<Digest32, ErgoBox> = HashMap::new();
    for ib in &tx_record.input_boxes {
        let (id, ebox) = parse_input_box(ib);
        map.insert(id, ebox);
    }
    MapUtxo(map)
}

/// For each cross-epoch fixture, drive `validate_transaction` with
/// `ProtocolParams::from_active(voted_snapshot)` and assert
/// `cost.total_block_cost() == fixture.block_cost`. A regression
/// that mistakenly uses `mainnet_default()` for cross-epoch heights
/// would shift the init-cost by `n_inputs * 407 + n_outputs * 198`
/// and fail here.
#[test]
fn cost_total_oracle_epoch_1499136_uses_voted_params() {
    let fixture = load_fixture();
    assert!(!fixture.fixtures.is_empty(), "fixture has at least one tx");

    let defaults = ProtocolParams::mainnet_default();
    assert_ne!(
        fixture.voted_params.input_cost as u64, defaults.input_cost,
        "voted inputCost must differ from default for this oracle to be meaningful",
    );
    assert_ne!(
        fixture.voted_params.output_cost as u64, defaults.output_cost,
        "voted outputCost must differ from default for this oracle to be meaningful",
    );

    let active = build_active_params(&fixture.voted_params);
    let params = ProtocolParams::from_active(&active);
    let policy = LocalPolicy::default_policy();

    let mut report: Vec<String> = Vec::new();
    for rec in &fixture.fixtures {
        let tx_bytes = hex::decode(&rec.tx_bytes).expect("tx_bytes hex");
        let header = fixture
            .headers
            .get(&rec.height.to_string())
            .unwrap_or_else(|| panic!("missing header for height {}", rec.height));
        let ctx = build_ctx(header, rec.height);
        let utxo = build_utxo(rec);

        let mut cost = CostAccumulator::new(
            JitCost::from_block_cost(params.max_block_cost).expect("block cap"),
        );
        let mut tx_cx = ergo_validation::TxValidationCtx {
            ctx: &ctx,
            params: &params,
            cost: &mut cost,
            last_headers: &[],
        };
        match validate_transaction(&tx_bytes, &utxo, &policy, &mut tx_cx) {
            Ok(_) => {
                let rust_cost = cost.total_block_cost();
                if rust_cost != rec.block_cost {
                    report.push(format!(
                        "tx={} h={} rust={} scala={} delta={}",
                        rec.tx_id,
                        rec.height,
                        rust_cost,
                        rec.block_cost,
                        rust_cost as i64 - rec.block_cost as i64,
                    ));
                }
            }
            Err(e) => {
                report.push(format!(
                    "tx={} h={} VALIDATOR REJECTED: {e}",
                    rec.tx_id, rec.height
                ));
            }
        }
    }
    assert!(
        report.is_empty(),
        "cross-epoch cost parity FAILED on {} of {} fixtures:\n{}",
        report.len(),
        fixture.fixtures.len(),
        report.join("\n"),
    );
}

/// Negative control: running the same cross-epoch fixtures with
/// `mainnet_default()` MUST diverge by EXACTLY the delta predicted
/// by the voted-vs-default param differences. For each fixture:
///
///   expected_delta = n_inputs  * (voted.input_cost  - default.input_cost)
///                  + n_outputs * (voted.output_cost - default.output_cost)
///                  + n_data_in * (voted.data_input_cost - default.data_input_cost)
///
/// At epoch 1499136 the cost-bearing differences are:
///   input_cost  : 2407 vs 2000 -> +407 per input
///   output_cost : 298  vs 100  -> +198 per output
///   data_input_cost / token_access_cost : equal, contribute 0
///
/// So default_cost = scala_cost - expected_delta. Asserting the
/// exact delta (not just "any divergence") catches a regression
/// that drifts input_cost by 407 from the wrong direction, or one
/// that accidentally compensates one delta against another.
#[test]
fn cost_total_with_mainnet_default_diverges_by_exact_delta() {
    let fixture = load_fixture();
    let defaults = ProtocolParams::mainnet_default();
    let voted_input_cost = fixture.voted_params.input_cost as i64;
    let voted_output_cost = fixture.voted_params.output_cost as i64;
    let voted_data_input_cost = fixture.voted_params.data_input_cost as i64;

    let input_delta = voted_input_cost - defaults.input_cost as i64;
    let output_delta = voted_output_cost - defaults.output_cost as i64;
    let data_input_delta = voted_data_input_cost - defaults.data_input_cost as i64;

    let policy = LocalPolicy::default_policy();
    let mut all_diverged_by_predicted_delta = true;
    let mut report = Vec::new();

    for rec in &fixture.fixtures {
        let tx_bytes = hex::decode(&rec.tx_bytes).expect("tx_bytes hex");
        let mut r = VlqReader::new(&tx_bytes);
        let tx = ergo_ser::transaction::read_transaction(&mut r).expect("tx parse");
        let n_inputs = tx.inputs.len() as i64;
        let n_data_inputs = tx.data_inputs.len() as i64;
        let n_outputs = tx.output_candidates.len() as i64;
        let expected_delta =
            n_inputs * input_delta + n_outputs * output_delta + n_data_inputs * data_input_delta;
        assert!(
            expected_delta != 0,
            "tx {} has no input/output delta — fixture is not exercising voted-param drift",
            rec.tx_id,
        );

        let header = fixture.headers.get(&rec.height.to_string()).expect("hdr");
        let ctx = build_ctx(header, rec.height);
        let utxo = build_utxo(rec);
        let mut cost =
            CostAccumulator::new(JitCost::from_block_cost(defaults.max_block_cost).expect("cap"));
        let mut tx_cx = ergo_validation::TxValidationCtx {
            ctx: &ctx,
            params: &defaults,
            cost: &mut cost,
            last_headers: &[],
        };
        match validate_transaction(&tx_bytes, &utxo, &policy, &mut tx_cx) {
            Ok(_) => {
                let rust_cost = cost.total_block_cost() as i64;
                let scala_cost = rec.block_cost as i64;
                // default_cost should equal scala_cost MINUS expected_delta
                // (positive delta means voted params cost more; defaults
                // cost less).
                let actual_delta = scala_cost - rust_cost;
                if actual_delta != expected_delta {
                    all_diverged_by_predicted_delta = false;
                    report.push(format!(
                        "tx={} h={} n_inputs={n_inputs} n_outputs={n_outputs} \
                         expected_delta={expected_delta} actual_delta={actual_delta} \
                         (rust_default={rust_cost} scala_voted={scala_cost})",
                        rec.tx_id, rec.height,
                    ));
                }
            }
            Err(e) => {
                report.push(format!(
                    "tx={} h={} VALIDATOR REJECTED under defaults: {e}",
                    rec.tx_id, rec.height
                ));
                all_diverged_by_predicted_delta = false;
            }
        }
    }
    assert!(
        all_diverged_by_predicted_delta,
        "default-vs-voted divergence does not match the predicted (n_inputs * 407 + n_outputs * 198) delta on at least one fixture:\n{}",
        report.join("\n"),
    );
}
