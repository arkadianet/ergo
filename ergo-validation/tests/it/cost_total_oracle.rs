//! Scala-anchored exact-equality oracle for `cost.total_block_cost()`.
//!
//! For each `(tx_id, height, block_cost)` tuple in the cost-total
//! fixture, this test:
//!
//! 1. Parses the tx from the fixture's `tx_bytes` field.
//! 2. Resolves input boxes from the tracked input-box pool, asserting
//!    `reconstructed.box_id() == fixture.boxId` per input (the
//!    validator does not re-verify box ids after UTXO resolution, so
//!    fabricated box bodies would otherwise certify spurious parity).
//! 3. Builds a `TransactionContext` from the fixture's per-height
//!    header record. `last_headers` is empty — scripts that read
//!    `CONTEXT.headers` or `LastBlockUtxoRootHash` will diverge from
//!    the Scala extractor's emitted cost, so such fixtures must not
//!    be added without the matching context plumbing.
//! 4. Runs the production `validate_transaction` path.
//! 5. Asserts `cost.total_block_cost() == fixture.block_cost`
//!    exactly. A drift here is a chain-fork-class divergence at the
//!    cost-limit gate.
//!
//! The reject-path test caps `max_block_cost` at `expected - 1` for
//! the largest-cost fixture entry and asserts the validator surfaces
//! either `CostExceeded` (init-cost over budget) or
//! `ScriptError(cost-limit)` (per-input eval over budget) with the
//! tight cap on the boundary.
//!
//! Fixture provenance + extraction recipe live next to the fixture.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use ergo_primitives::digest::{Digest32, ModifierId};
use ergo_primitives::reader::VlqReader;
use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::read_ergo_tree;
use ergo_ser::register::{AdditionalRegisters, RegisterValue};
use ergo_ser::sigma_value::read_constant;
use ergo_ser::token::Token;
use ergo_ser::transaction::read_transaction;

use ergo_validation::context::{LocalPolicy, ProtocolParams, TransactionContext};
use ergo_validation::cost::{CostAccumulator, JitCost};
use ergo_validation::error::ValidationError;
use ergo_validation::tx::validate_transaction;
use ergo_validation::UtxoView;

// ----- helpers -----

#[derive(serde::Deserialize)]
struct HeaderRecord {
    timestamp: u64,
    n_bits: u64,
    version: u8,
    miner_pk_hex: String,
}

#[derive(serde::Deserialize)]
struct TxRecord {
    tx_id: String,
    height: u32,
    block_cost: u64,
    tx_bytes: String,
}

#[derive(serde::Deserialize)]
struct CostFixture {
    headers: HashMap<String, HeaderRecord>,
    transactions: Vec<TxRecord>,
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace parent")
        .to_path_buf()
}

fn load_fixture() -> CostFixture {
    let path =
        workspace_root().join("test-vectors/ergo-sigma/cost-total/mainnet_700000_700001.json");
    let raw =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&raw).expect("cost fixture json")
}

fn load_input_box_pool() -> HashMap<Digest32, ErgoBox> {
    let path = workspace_root().join("test-vectors/mainnet/input_boxes_700000_700010.json");
    let raw =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let boxes: Vec<serde_json::Value> = serde_json::from_str(&raw).expect("input box json");
    let mut map = HashMap::new();
    for b in &boxes {
        let (id, ebox) = parse_box(b);
        map.insert(id, ebox);
    }
    map
}

/// Reconstruct an `ErgoBox` from the tracked input-box JSON shape
/// (`{boxId, value, ergoTree, creationHeight, transactionId, index,
/// assets, additionalRegisters}`). After assembly, the reconstructed
/// box's `box_id()` is asserted equal to the JSON-supplied `boxId` —
/// `parse_registers` only handles values that round-trip through
/// `read_constant`, so a box carrying a tuple- or collection-encoded
/// register would assemble bytes diverging from the on-chain box;
/// the id check fails loudly instead of certifying parity on a
/// fabricated body.
fn parse_box(v: &serde_json::Value) -> (Digest32, ErgoBox) {
    let box_id_hex = v["boxId"].as_str().expect("boxId");
    let box_id_bytes: [u8; 32] = hex::decode(box_id_hex)
        .expect("boxId hex")
        .try_into()
        .expect("boxId len");
    let json_box_id = Digest32::from_bytes(box_id_bytes);

    let ergo_tree_hex = v["ergoTree"].as_str().expect("ergoTree");
    let ergo_tree_bytes = hex::decode(ergo_tree_hex).expect("ergoTree hex");
    let mut r = VlqReader::new(&ergo_tree_bytes);
    let ergo_tree = read_ergo_tree(&mut r).expect("ergoTree parse");

    let value = v["value"].as_u64().expect("value");
    let creation_height = v["creationHeight"].as_u64().expect("creationHeight") as u32;
    let empty_map = serde_json::Map::new();
    let add_regs = v["additionalRegisters"].as_object().unwrap_or(&empty_map);
    let reg_map: HashMap<String, String> = add_regs
        .iter()
        .filter_map(|(k, val)| val.as_str().map(|s| (k.clone(), s.to_owned())))
        .collect();
    let (registers, reg_bytes) = parse_registers(&reg_map);

    let empty_assets: Vec<serde_json::Value> = Vec::new();
    let assets = v["assets"].as_array().unwrap_or(&empty_assets);
    let tokens = parse_tokens(assets);

    let zero_tx_id = "00".repeat(32);
    let tx_id_hex = v["transactionId"].as_str().unwrap_or(&zero_tx_id);
    let tx_id: [u8; 32] = hex::decode(tx_id_hex)
        .expect("transactionId hex")
        .try_into()
        .expect("transactionId len");
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
    let ebox = ErgoBox {
        candidate,
        transaction_id: ModifierId::from_bytes(tx_id),
        index,
    };

    let computed = ebox
        .box_id()
        .unwrap_or_else(|e| panic!("compute box_id for {box_id_hex}: {e}"));
    assert_eq!(
        computed, json_box_id,
        "reconstructed box bytes diverge from on-chain bytes for boxId={box_id_hex} \
         (likely a non-constant register encoding parse_registers dropped); \
         oracle cannot certify cost parity on a fabricated box body",
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

/// Build a `TransactionContext` matching the Scala extractor's
/// per-height stub. PROVISIONING.md documents the contract — only
/// `height`, `miner_pubkey`, `pre_header_timestamp`,
/// `activated_script_version`, `pre_header_version`, and
/// `pre_header_n_bits` carry real values; the rest are zeroed.
fn build_ctx(header: &HeaderRecord, height: u32) -> TransactionContext {
    let pk_bytes = hex::decode(&header.miner_pk_hex).expect("miner pk hex");
    let miner_pubkey: [u8; 33] = pk_bytes.try_into().expect("miner pk len");
    TransactionContext {
        height,
        miner_pubkey,
        pre_header_timestamp: header.timestamp,
        activated_script_version: header.version.saturating_sub(1),
        pre_header_version: header.version,
        pre_header_parent_id: [0u8; 32],
        pre_header_n_bits: header.n_bits,
        pre_header_votes: [0u8; 3],
    }
}

/// Resolve a tx record against the input-box pool. Panics if any input
/// box is missing — the fixture is hermetic and the input-box pool
/// must cover every input id the fixture txs declare.
fn build_utxo_for_tx(tx_bytes: &[u8], pool: &HashMap<Digest32, ErgoBox>, tx_id: &str) -> MapUtxo {
    let mut r = VlqReader::new(tx_bytes);
    let tx = read_transaction(&mut r).expect("tx bytes parse");
    let mut map: HashMap<Digest32, ErgoBox> = HashMap::new();
    for input in &tx.inputs {
        match pool.get(&input.box_id) {
            Some(b) => {
                map.insert(input.box_id, b.clone());
            }
            None => panic!(
                "input box {} not in tracked pool for tx {}",
                hex::encode(input.box_id.as_bytes()),
                tx_id,
            ),
        }
    }
    for di in &tx.data_inputs {
        if let Some(b) = pool.get(&di.box_id) {
            map.insert(di.box_id, b.clone());
        }
    }
    MapUtxo(map)
}

// ----- oracle parity -----

/// For each fixture entry, run `validate_transaction` and assert the
/// production cost accumulator lands exactly on the Scala interpreter's
/// `block_cost`. Drift is chain-fork-class at the cost-limit gate.
#[test]
fn cost_total_oracle_mainnet_700000_700001() {
    let fixture = load_fixture();
    assert!(
        !fixture.transactions.is_empty(),
        "fixture has at least one tx"
    );

    let pool = load_input_box_pool();
    let params = ProtocolParams::mainnet_default();
    let policy = LocalPolicy::default_policy();

    let mut report: Vec<String> = Vec::new();
    for rec in &fixture.transactions {
        let tx_bytes = hex::decode(&rec.tx_bytes).expect("tx_bytes hex");
        let header = fixture
            .headers
            .get(&rec.height.to_string())
            .unwrap_or_else(|| panic!("fixture missing header for height {}", rec.height));
        let ctx = build_ctx(header, rec.height);
        let utxo = build_utxo_for_tx(&tx_bytes, &pool, &rec.tx_id);

        let mut cost = CostAccumulator::new(
            JitCost::from_block_cost(params.max_block_cost).expect("block cap"),
        );
        let mut tx_cx = ergo_validation::TxValidationCtx {
            ctx: &ctx,
            params: &params,
            cost: &mut cost,
            last_headers: &[],
            rules: ergo_validation::TxValidationRules::default(),
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
        "cost-total parity FAILED on {} of {} fixtures:\n{}",
        report.len(),
        fixture.transactions.len(),
        report.join("\n"),
    );
}

/// Reject path A: per-input script evaluation exceeds budget. Cap
/// `max_block_cost` at `expected - 1` for the largest-cost fixture
/// (init cost fits, script eval overruns). The validator surfaces
/// the in-eval overrun as `ScriptError` whose `reason` carries the
/// JitCost-unit numbers from `EvalError::CostExceeded`. Pins the
/// JitCost-unit boundary so any future drift in the block-cost ↔
/// JitCost scale factor fails this test.
#[test]
fn cost_limit_rejects_inside_script_eval_at_one_below_expected() {
    let fixture = load_fixture();
    let rec = fixture
        .transactions
        .iter()
        .max_by_key(|t| t.block_cost)
        .expect("at least one fixture entry");

    let pool = load_input_box_pool();
    let tx_bytes = hex::decode(&rec.tx_bytes).expect("tx_bytes hex");
    let header = fixture
        .headers
        .get(&rec.height.to_string())
        .expect("fixture header");
    let ctx = build_ctx(header, rec.height);
    let utxo = build_utxo_for_tx(&tx_bytes, &pool, &rec.tx_id);

    let mut params = ProtocolParams::mainnet_default();
    params.max_block_cost = rec.block_cost - 1;
    let policy = LocalPolicy::default_policy();

    let mut cost =
        CostAccumulator::new(JitCost::from_block_cost(params.max_block_cost).expect("tight cap"));
    let mut tx_cx = ergo_validation::TxValidationCtx {
        ctx: &ctx,
        params: &params,
        cost: &mut cost,
        last_headers: &[],
        rules: ergo_validation::TxValidationRules::default(),
    };
    let result = validate_transaction(&tx_bytes, &utxo, &policy, &mut tx_cx);

    let expected_jit_cap = (rec.block_cost - 1) * 10;
    match result {
        Err(ValidationError::ScriptError { reason, .. }) => {
            assert!(
                reason.contains("cost limit exceeded"),
                "ScriptError reason must mention cost-limit failure, got: {reason}",
            );
            let needle = format!("> {expected_jit_cap}");
            assert!(
                reason.contains(&needle),
                "ScriptError reason must pin the JitCost-unit cap ({needle}), got: {reason}",
            );
        }
        other => panic!(
            "expected ScriptError(cost-limit) at JitCost cap {expected_jit_cap}, got {:?}",
            other,
        ),
    }
}

/// Reject path B: transaction init cost alone exceeds budget. Cap
/// `max_block_cost` below `INTERPRETER_INIT_COST` so the validator
/// hits the cap on the very first `cost.add(init_jit)` charge,
/// before any script even runs. Surfaces as
/// `ValidationError::CostExceeded` (NOT `ScriptError` — the in-eval
/// path is never reached) with `current`/`limit` in JitCost units.
#[test]
fn cost_limit_rejects_at_init_cost_charge() {
    let fixture = load_fixture();
    let rec = &fixture.transactions[0];

    let pool = load_input_box_pool();
    let tx_bytes = hex::decode(&rec.tx_bytes).expect("tx_bytes hex");
    let header = fixture
        .headers
        .get(&rec.height.to_string())
        .expect("fixture header");
    let ctx = build_ctx(header, rec.height);
    let utxo = build_utxo_for_tx(&tx_bytes, &pool, &rec.tx_id);

    // Cap below `INTERPRETER_INIT_COST` (10_000). Any tx — even one
    // with zero inputs/outputs — has init_cost ≥ 10_000, so the
    // validator's `cost.add(init_jit)` overflows the cap immediately.
    let tight_block_cap = (ergo_validation::INTERPRETER_INIT_COST - 1) as u32;
    let mut params = ProtocolParams::mainnet_default();
    params.max_block_cost = tight_block_cap as u64;
    let policy = LocalPolicy::default_policy();

    let mut cost =
        CostAccumulator::new(JitCost::from_block_cost(params.max_block_cost).expect("tight cap"));
    let mut tx_cx = ergo_validation::TxValidationCtx {
        ctx: &ctx,
        params: &params,
        cost: &mut cost,
        last_headers: &[],
        rules: ergo_validation::TxValidationRules::default(),
    };
    let result = validate_transaction(&tx_bytes, &utxo, &policy, &mut tx_cx);

    let expected_jit_cap = (tight_block_cap as u64) * 10;
    match result {
        Err(ValidationError::CostExceeded { current, limit }) => {
            assert_eq!(
                limit, expected_jit_cap,
                "init-cost reject must surface JitCost-unit limit at tight cap",
            );
            assert!(
                current > limit,
                "CostExceeded surfaces current > limit (got current={current}, limit={limit})",
            );
        }
        other => panic!(
            "expected CostExceeded at init-cost charge with limit={expected_jit_cap} (JitCost units), got {:?}",
            other,
        ),
    }
}
