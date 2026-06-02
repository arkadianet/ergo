//! Differential JSON parity oracle for `/blockchain/transaction/byId/{id}`
//! and `/blockchain/box/byId/{id}` against a captured Scala node corpus.
//!
//! What this proves: for the canonical heights 1..200 corpus, the Rust
//! router emits a JSON shape that matches Scala's `extraIndex`
//! responses field-for-field once well-known divergences are projected
//! away. This is the "Scala parity" gate for the byId-shaped
//! extra-index surface.
//!
//! Oracle source: `test-vectors/extra-index/heights_1_200.json`,
//! produced by `test-vectors/scripts/extract_extra_index.sh` against a
//! synced Scala node with `extraIndex = true` running at
//! `http://localhost:9053`. Re-run the script to refresh.
//!
//! ## Normalizations
//!
//! Both sides are projected through `normalize_for_parity` before
//! comparison. The set of allowed normalizations is intentionally tiny
//! so a real wire-shape divergence still fires the assertion:
//!
//! 1. **`numConfirmations` is dropped.** Volatile (depends on chain
//!    tip). Stripped at oracle-capture time and not computed in the
//!    test harness either.
//!
//! 2. **`spendingHeight` is omitted by both sides.** Scala's
//!    `/blockchain/box/byId` never serializes this field. Rust used
//!    to emit it (from `IndexedErgoBox.spending_height`) and the
//!    parity harness stripped it before comparison; as of the
//!    §10.5 follow-up the Rust DTO drops the field at the source,
//!    so no normalization is needed here. The indexer still tracks
//!    `spending_height` internally — the change is API-surface only.
//!
//! 3. **Out-of-range spend metadata is nulled on the Scala side.**
//!    Scala captures `spentTransactionId` for every box spent at any
//!    height ≤ chain tip (≈1.7M). Our Rust harness only sees heights
//!    1..200, so any spend whose `spentTransactionId` is OUTSIDE the
//!    backfilled tx-id set is projected to `null` on the Scala side
//!    (along with `spendingProof`) — Rust naturally has them as `null`
//!    because the spending tx hasn't been applied.
//!
//! 4. **Genesis box 71bc... is always projected to "unspent".** The
//!    genesis tx 4c62... has `boxId 71bc` as both input #0 AND output
//!    #0 (a unique self-referential property of the Ergo genesis).
//!    Scala's `extraIndex` *never* marks this box as spent, even
//!    though tx 34a247 at h=2 consumes it (verified against live
//!    Scala node `/blockchain/box/byId/71bc...` returning
//!    `spentTransactionId: null`). The Rust apply path correctly
//!    marks it as spent at h=2, which is the more useful behaviour.
//!    For byte parity we project the Rust spend metadata for this box
//!    to `null` everywhere it appears (standalone box response and
//!    nested in tx 34a247's `inputs[0]`). Known Scala divergence.
//!
//! ## Skipped: genesis tx (height 1)
//!
//! Per `apply.rs:148`, `apply_block` skips input processing at
//! `block_height == 1` (genesis exception — there is no
//! pre-existing UTxO set for genesis inputs to dereference). Scala's
//! `/blockchain/transaction/byId/<genesis_tx_id>` returns a 1-element
//! `inputs` array referencing the self-referential genesis box; the
//! Rust handler returns `inputs: []`. This is a structural divergence,
//! not a serialization quirk, so we skip the genesis tx from the tx
//! parity loop. Genesis box parity (both `/box/byId/71bc...` and
//! `/box/byId/45dc...`) is still asserted — both sides agree the boxes
//! exist with matching field values.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ergo_api::compat::traits::NodeChainQuery;
use ergo_api::compat::types::{
    Parameters, ScalaFullBlock, ScalaHeader, ScalaInfo, ScalaPowSolutions,
};
use ergo_api::server::router;
use ergo_api::traits::NodeReadState;
use ergo_api::types::{
    ApiFullBlockRef, ApiHeaderRef, ApiHealth, ApiInfo, ApiMempoolSummary, ApiMempoolTransaction,
    ApiMempoolTransactions, ApiPeer, ApiStatus, ApiSyncStatus, ApiTip, ApiWeightFunction,
    HealthStatus, SyncStateLabel,
};
use ergo_indexer::{apply_block, IndexerBlock, IndexerHandle, IndexerMeta, IndexerStore};
use ergo_indexer_types::{IndexerQuery, IndexerStatus};
use ergo_primitives::digest::Digest32;
use ergo_primitives::reader::VlqReader;
use ergo_ser::address::NetworkPrefix;
use ergo_ser::transaction::{read_transaction, Transaction};
use http_body_util::BodyExt;
use serde::Deserialize;
use serde_json::Value;
use tempfile::TempDir;
use tower::ServiceExt;

const BACKFILL_LO: u32 = 1;
const BACKFILL_HI: u32 = 200;
/// Genesis tx id at height 1 — `apply.rs` skips inputs at h=1 so the
/// `inputs` array structurally diverges from Scala. Skipped from tx
/// parity loop (boxes still asserted).
const GENESIS_TX_ID: &str = "4c6282be413c6e300a530618b37790be5f286ded758accc2aebd41554a1be308";

/// Genesis box id — both input #0 and output #0 of the genesis tx have
/// this id (a unique self-referential property of the Ergo genesis).
/// Scala's extraIndex never marks this box as spent; we project Rust's
/// (correct) spend metadata for this box to null everywhere.
const GENESIS_BOX_ID: &str = "71bc9534d4a4fe8ff67698a5d0f29782836970635de8418da39fee1cd964fcbe";

#[derive(Debug, Deserialize)]
struct TxVector {
    id: String,
    bytes: String,
    height: u32,
}

#[derive(Debug, Deserialize)]
struct OracleFile {
    transactions: HashMap<String, Value>,
    boxes: HashMap<String, Value>,
}

fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("test-vectors")
}

fn load_corpus() -> Vec<TxVector> {
    let path = vectors_dir().join("mainnet/transactions_1_200.json");
    let data = fs::read_to_string(&path).expect("read transactions corpus");
    serde_json::from_str(&data).expect("parse transactions corpus")
}

fn load_oracle() -> OracleFile {
    let path = vectors_dir().join("extra-index/heights_1_200.json");
    let data = fs::read_to_string(&path).expect("read extra-index oracle");
    serde_json::from_str(&data).expect("parse extra-index oracle")
}

fn parse_id(s: &str) -> Digest32 {
    let bytes = hex::decode(s).expect("hex id");
    let arr: [u8; 32] = bytes.try_into().expect("32-byte id");
    Digest32::from_bytes(arr)
}

fn parse_tx(v: &TxVector) -> Transaction {
    let raw = hex::decode(&v.bytes).expect("hex tx bytes");
    let mut r = VlqReader::new(&raw);
    read_transaction(&mut r).expect("parse tx")
}

// ---------- chain stub keyed off captured oracle data ---------------------

#[derive(Clone)]
struct HeightHeader {
    id: String,
    timestamp: u64,
}

struct ParityChain {
    by_height: HashMap<u32, HeightHeader>,
    by_id: HashMap<String, HeightHeader>,
}

impl NodeChainQuery for ParityChain {
    fn info(&self) -> ScalaInfo {
        empty_info()
    }
    fn header_ids_at_height(&self, height: u32) -> Vec<String> {
        self.by_height
            .get(&height)
            .map(|h| vec![h.id.clone()])
            .unwrap_or_default()
    }
    fn full_block_by_id(&self, _: &str) -> Option<ScalaFullBlock> {
        None
    }
    fn header_by_id(&self, header_id_hex: &str) -> Option<ScalaHeader> {
        self.by_id.get(header_id_hex).map(|h| ScalaHeader {
            extension_id: String::new(),
            difficulty: String::new(),
            votes: String::new(),
            timestamp: h.timestamp,
            size: 0,
            unparsed_bytes: String::new(),
            state_root: String::new(),
            height: 0,
            n_bits: 0,
            version: 0,
            id: header_id_hex.to_string(),
            ad_proofs_root: String::new(),
            transactions_root: String::new(),
            extension_hash: String::new(),
            pow_solutions: ScalaPowSolutions {
                pk: String::new(),
                w: String::new(),
                n: String::new(),
                d: serde_json::Value::Null,
            },
            ad_proofs_id: String::new(),
            transactions_id: String::new(),
            parent_id: String::new(),
        })
    }
}

fn empty_info() -> ScalaInfo {
    ScalaInfo {
        last_mempool_update_time: 0,
        current_time: 0,
        network: String::new(),
        name: String::new(),
        state_type: String::new(),
        difficulty: 0,
        best_full_header_id: String::new(),
        best_header_id: String::new(),
        peers_count: 0,
        unconfirmed_count: 0,
        app_version: String::new(),
        eip37_supported: false,
        state_root: String::new(),
        genesis_block_id: String::new(),
        rest_api_url: None,
        previous_full_header_id: String::new(),
        full_height: 0,
        headers_height: 0,
        state_version: String::new(),
        full_blocks_score: 0,
        max_peer_height: 0,
        launch_time: 0,
        is_explorer: false,
        last_seen_message_time: 0,
        eip27_supported: false,
        headers_score: 0,
        parameters: Parameters {
            output_cost: 0,
            token_access_cost: 0,
            max_block_cost: 0,
            height: 0,
            max_block_size: 0,
            data_input_cost: 0,
            block_version: 0,
            input_cost: 0,
            storage_fee_factor: 0,
            subblocks_per_block: 0,
            min_value_per_byte: 0,
        },
        is_mining: false,
    }
}

// ---------- read-state stub (stable defaults; numConfirmations is
// stripped on both sides so `full_height` doesn't influence parity) ----

struct StubReadState;

impl NodeReadState for StubReadState {
    fn info(&self) -> ApiInfo {
        ApiInfo {
            agent_name: "ergo-rust".into(),
            node_name: "stub".into(),
            network: "mainnet".into(),
            version: "0.1.0".into(),
            started_at_unix_ms: 0,
            uptime_seconds: 0,
            target_block_interval_ms: 120_000,
        }
    }
    fn status(&self) -> ApiStatus {
        ApiStatus {
            sync_state: SyncStateLabel::AtTip,
            peer_count: 0,
            best_header_height: 0,
            best_full_block_height: 0,
            headers_ahead_of_full_blocks: 0,
            mempool_size: 0,
            snapshot_age_ms: 0,
            bootstrap: None,
        }
    }
    fn tip(&self) -> ApiTip {
        ApiTip {
            best_header: ApiHeaderRef {
                height: 0,
                header_id: String::new(),
                parent_id: String::new(),
                timestamp_unix_ms: 0,
                n_bits: 0,
                difficulty: String::new(),
            },
            best_full_block: ApiFullBlockRef {
                height: 0,
                header_id: String::new(),
                parent_id: String::new(),
                timestamp_unix_ms: 0,
                state_root_avl: String::new(),
                n_bits: 0,
                difficulty: String::new(),
            },
            headers_ahead_of_full_blocks: 0,
        }
    }
    fn sync(&self) -> ApiSyncStatus {
        ApiSyncStatus {
            headers_chain_synced: true,
            best_header_height: 0,
            best_full_block_height: 0,
            gap: 0,
            download_window: 0,
            pending_blocks: 0,
            recovery_done: true,
        }
    }
    fn peers(&self) -> Vec<ApiPeer> {
        Vec::new()
    }
    fn mempool_summary(&self) -> ApiMempoolSummary {
        ApiMempoolSummary {
            size: 0,
            total_bytes: 0,
            capacity_count: 0,
            capacity_bytes: 0,
            revalidation_pending: 0,
        }
    }
    fn mempool_transactions(&self) -> ApiMempoolTransactions {
        ApiMempoolTransactions {
            transactions: Vec::new(),
            weight_function: ApiWeightFunction::Cost,
        }
    }
    fn mempool_transaction(&self, _: &str) -> Option<ApiMempoolTransaction> {
        None
    }
    fn health(&self) -> ApiHealth {
        ApiHealth {
            status: HealthStatus::Ok,
            behind: 0,
            last_progress_age_ms: 0,
            peer_count: 0,
        }
    }
}

// ---------- harness ------------------------------------------------------

struct Harness {
    handle: IndexerHandle,
    chain: Arc<ParityChain>,
    /// Set of tx ids that landed in the indexer (heights 1..200). Used
    /// by `normalize_for_parity` to project out-of-range Scala spends
    /// to `null` so they match the Rust "not yet spent" view.
    applied_tx_ids: HashSet<String>,
    _tmp: TempDir,
}

fn build_harness(oracle: &OracleFile) -> Harness {
    let corpus = load_corpus();

    let tmp = TempDir::new().expect("tempdir");
    let path = tmp.path().join("indexer.redb");
    let (store, _) = IndexerStore::open(&path).expect("open store");

    // Build the chain stub from the captured txs: each tx record
    // carries `inclusionHeight`, `blockId`, `timestamp`, which is
    // exactly what `header_ids_at_height` + `header_by_id` need.
    let mut by_height: HashMap<u32, HeightHeader> = HashMap::new();
    for tx in oracle.transactions.values() {
        let h = tx["inclusionHeight"].as_u64().expect("inclusionHeight u64") as u32;
        let id = tx["blockId"].as_str().expect("blockId str").to_string();
        let timestamp = tx["timestamp"].as_u64().expect("timestamp u64");
        by_height.entry(h).or_insert(HeightHeader { id, timestamp });
    }
    let by_id: HashMap<String, HeightHeader> = by_height
        .values()
        .map(|h| (h.id.clone(), h.clone()))
        .collect();
    let chain = Arc::new(ParityChain { by_height, by_id });

    let mut meta = IndexerMeta::empty();
    let mut applied_tx_ids = HashSet::with_capacity((BACKFILL_HI - BACKFILL_LO + 1) as usize);
    for h in BACKFILL_LO..=BACKFILL_HI {
        let tv = corpus
            .iter()
            .find(|t| t.height == h)
            .unwrap_or_else(|| panic!("no tx at height {h} in corpus"));
        let tx = parse_tx(tv);
        let header_id = parse_id(&chain.by_height[&h].id);
        let txs = std::slice::from_ref(&tx);
        let block = IndexerBlock {
            height: h as i32,
            header_id,
            transactions: txs,
        };
        meta = apply_block(&store, &meta, &block)
            .unwrap_or_else(|e| panic!("apply_block height {h}: {e:?}"));
        applied_tx_ids.insert(tv.id.clone());
    }

    let handle = IndexerHandle::with_store(store, meta.indexed_height);
    handle.set_status(IndexerStatus::CaughtUp);

    Harness {
        handle,
        chain,
        applied_tx_ids,
        _tmp: tmp,
    }
}

fn build_app(h: &Harness) -> axum::Router {
    let read: Arc<dyn NodeReadState> = Arc::new(StubReadState);
    let chain: Arc<dyn NodeChainQuery> = h.chain.clone();
    let indexer: Arc<dyn IndexerQuery> = Arc::new(h.handle.clone());
    router(
        read,
        Some(chain),
        None,
        Some(indexer),
        NetworkPrefix::Mainnet,
    )
}

async fn json_get(app: axum::Router, path: &str) -> (StatusCode, Value) {
    let resp = app
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .expect("router service");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, value)
}

// ---------- normalization -------------------------------------------------

/// Recursively project both sides into a comparable shape. See the
/// module docstring for the allowed normalizations.
fn normalize_for_parity(v: &mut Value, applied_tx_ids: &HashSet<String>) {
    match v {
        Value::Object(map) => {
            map.remove("numConfirmations");
            // `spendingHeight` is not emitted by either side
            // (`IndexedErgoBoxResponse` drops the field; Scala 6.0.3RC1
            // doesn't emit it either). No normalization needed here.
            // Genesis box 71bc... is self-referential (input #0 + output
            // #0 of the genesis tx). Scala never marks it spent; Rust
            // correctly does. Project Rust's spend metadata to null for
            // this specific box so the wire shape matches.
            let is_genesis_box = map
                .get("boxId")
                .and_then(Value::as_str)
                .is_some_and(|s| s == GENESIS_BOX_ID);
            if is_genesis_box {
                map.insert("spentTransactionId".into(), Value::Null);
                map.insert("spendingProof".into(), Value::Null);
            } else {
                // Project out-of-range Scala spend metadata to null so
                // it matches Rust's "spending tx hasn't been applied"
                // view.
                let stid_in_range = map
                    .get("spentTransactionId")
                    .and_then(Value::as_str)
                    .map(|s| applied_tx_ids.contains(s));
                if matches!(stid_in_range, Some(false)) {
                    map.insert("spentTransactionId".into(), Value::Null);
                    map.insert("spendingProof".into(), Value::Null);
                }
            }
            for child in map.values_mut() {
                normalize_for_parity(child, applied_tx_ids);
            }
        }
        Value::Array(arr) => {
            for child in arr.iter_mut() {
                normalize_for_parity(child, applied_tx_ids);
            }
        }
        _ => {}
    }
}

// ---------- tests ---------------------------------------------------------

#[tokio::test]
async fn box_byid_parity_heights_1_200() {
    let oracle = load_oracle();
    let harness = build_harness(&oracle);

    let mut failures: Vec<String> = Vec::new();
    for (box_id, expected_raw) in &oracle.boxes {
        let app = build_app(&harness);
        let (status, mut got) = json_get(app, &format!("/blockchain/box/byId/{box_id}")).await;
        if status != StatusCode::OK {
            failures.push(format!("box {box_id}: status {status} body {got}"));
            continue;
        }
        let mut expected = expected_raw.clone();
        normalize_for_parity(&mut got, &harness.applied_tx_ids);
        normalize_for_parity(&mut expected, &harness.applied_tx_ids);
        if got != expected {
            failures.push(format!(
                "box {box_id}:\n  rust:  {}\n  scala: {}",
                serde_json::to_string(&got).unwrap_or_default(),
                serde_json::to_string(&expected).unwrap_or_default(),
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} box parity failures (first 3):\n{}",
        failures.len(),
        oracle.boxes.len(),
        failures
            .iter()
            .take(3)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n"),
    );
}

#[tokio::test]
async fn tx_byid_parity_heights_1_200() {
    let oracle = load_oracle();
    let harness = build_harness(&oracle);

    let mut compared = 0_usize;
    let mut failures: Vec<String> = Vec::new();
    for (tx_id, expected_raw) in &oracle.transactions {
        if tx_id == GENESIS_TX_ID {
            continue;
        }
        let app = build_app(&harness);
        let (status, mut got) =
            json_get(app, &format!("/blockchain/transaction/byId/{tx_id}")).await;
        if status != StatusCode::OK {
            failures.push(format!("tx {tx_id}: status {status} body {got}"));
            continue;
        }
        let mut expected = expected_raw.clone();
        normalize_for_parity(&mut got, &harness.applied_tx_ids);
        normalize_for_parity(&mut expected, &harness.applied_tx_ids);
        if got != expected {
            failures.push(format!(
                "tx {tx_id}:\n  rust:  {}\n  scala: {}",
                serde_json::to_string(&got).unwrap_or_default(),
                serde_json::to_string(&expected).unwrap_or_default(),
            ));
        }
        compared += 1;
    }
    // Sanity check: the corpus has 200 txs, we skip 1 (genesis), so we
    // expect to have compared 199.
    assert_eq!(compared, 199, "expected to compare 199 txs, got {compared}");
    assert!(
        failures.is_empty(),
        "{} of {} tx parity failures (first 3):\n{}",
        failures.len(),
        compared,
        failures
            .iter()
            .take(3)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n"),
    );
}

#[tokio::test]
async fn box_byindex_parity_heights_1_200() {
    // Hits `/blockchain/box/byIndex/{n}` for every captured globalIndex
    // (0..400). Same record shape as byId — this exercises the
    // numeric→id dispatch path, asserting it lands on the same
    // `IndexedErgoBox` record and produces byte-identical JSON modulo
    // the documented normalizations.
    let oracle = load_oracle();
    let harness = build_harness(&oracle);

    let mut failures: Vec<String> = Vec::new();
    for expected_raw in oracle.boxes.values() {
        let global_index = expected_raw["globalIndex"]
            .as_i64()
            .expect("box globalIndex i64");
        let app = build_app(&harness);
        let (status, mut got) =
            json_get(app, &format!("/blockchain/box/byIndex/{global_index}")).await;
        if status != StatusCode::OK {
            failures.push(format!("box gi={global_index}: status {status} body {got}"));
            continue;
        }
        let mut expected = expected_raw.clone();
        normalize_for_parity(&mut got, &harness.applied_tx_ids);
        normalize_for_parity(&mut expected, &harness.applied_tx_ids);
        if got != expected {
            failures.push(format!(
                "box gi={global_index}:\n  rust:  {}\n  scala: {}",
                serde_json::to_string(&got).unwrap_or_default(),
                serde_json::to_string(&expected).unwrap_or_default(),
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} byIndex box parity failures (first 3):\n{}",
        failures.len(),
        oracle.boxes.len(),
        failures
            .iter()
            .take(3)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n"),
    );
}

#[tokio::test]
async fn tx_byindex_parity_heights_1_200() {
    // Hits `/blockchain/transaction/byIndex/{n}` for every captured
    // globalIndex (0..200). Genesis tx (globalIndex=0, height=1) is
    // still skipped — same structural reason as the byId test.
    let oracle = load_oracle();
    let harness = build_harness(&oracle);

    let mut compared = 0_usize;
    let mut failures: Vec<String> = Vec::new();
    for (tx_id, expected_raw) in &oracle.transactions {
        if tx_id == GENESIS_TX_ID {
            continue;
        }
        let global_index = expected_raw["globalIndex"]
            .as_i64()
            .expect("tx globalIndex i64");
        let app = build_app(&harness);
        let (status, mut got) = json_get(
            app,
            &format!("/blockchain/transaction/byIndex/{global_index}"),
        )
        .await;
        if status != StatusCode::OK {
            failures.push(format!("tx gi={global_index}: status {status} body {got}"));
            continue;
        }
        let mut expected = expected_raw.clone();
        normalize_for_parity(&mut got, &harness.applied_tx_ids);
        normalize_for_parity(&mut expected, &harness.applied_tx_ids);
        if got != expected {
            failures.push(format!(
                "tx gi={global_index}:\n  rust:  {}\n  scala: {}",
                serde_json::to_string(&got).unwrap_or_default(),
                serde_json::to_string(&expected).unwrap_or_default(),
            ));
        }
        compared += 1;
    }
    assert_eq!(compared, 199, "expected to compare 199 txs, got {compared}");
    assert!(
        failures.is_empty(),
        "{} of {} byIndex tx parity failures (first 3):\n{}",
        failures.len(),
        compared,
        failures
            .iter()
            .take(3)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n"),
    );
}
