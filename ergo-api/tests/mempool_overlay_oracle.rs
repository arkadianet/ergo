//! Mempool-overlay oracle — captured-Scala genesis-output quirk +
//! synthetic pinned-shape contracts.
//!
//! Companion to `blockchain_scala_parity.rs`. Where that file pins
//! byte/JSON parity for `/box/byId` and `/box/byIndex` against a
//! captured Scala corpus, this file pins the mempool-overlay contracts
//! that per-slice tests don't consolidate in one place:
//!
//! 1. **Genesis-output `globalIndex = 0` segment-filter quirk.** The
//!    genesis output is invisible to *all* segment-backed unspent
//!    routes due to the `_ > 0` filter inherited from Scala
//!    (`Segment.scala:247, 252, 259, 263` → Rust `handle.rs:298, 370,
//!    457`). It IS visible to the by-id and numeric-box reads. Both
//!    observations are verified against the live Scala node at capture
//!    time:
//!    - Scala `/blockchain/box/byId/71bc...` returns the box
//!      (captured in `extra-index/heights_1_200.json`).
//!    - Scala `/blockchain/box/unspent/byAddress/{genesis_addr}` does
//!      not include `globalIndex = 0` in any returned entry (spot-
//!      checked at oracle-build time against `localhost:9053`).
//!
//!    Both Rust queries must match.
//!
//! 2. **Pool-output `IndexedErgoBox` JSON shape.** Every pool-output
//!    entry surfaced by an unspent route with `includeUnconfirmed=true`
//!    carries `inclusionHeight = 0`, `globalIndex = 0`,
//!    `spentTransactionId = null`, `spendingProof = null`, AND omits
//!    `spendingHeight` entirely (Scala 6.0.3RC1 parity per the
//!    2026-05-19 probe — see `IndexedErgoBoxResponse` in
//!    `ergo-api/src/blockchain/boxes.rs`). Pinned as a full key-set
//!    assertion below — per-slice tests assert a subset each, this
//!    consolidates them into one citable wire pin.
//!
//! 3. **`/balance` is strictly additive.** The unconfirmed
//!    `BalanceInfo` is computed by walking `tx.outputs` only —
//!    `tx.inputs` are never inspected, so a mempool tx that spends
//!    *every* confirmed UTXO of an address leaves `confirmed`
//!    untouched and only contributes pool outputs that pay the
//!    address back. This `[inherited]` Scala behavior is the
//!    most-likely-misunderstood corner of the overlay contract; the
//!    test below pins it explicitly with a stub mempool whose
//!    `spentInputs` set covers the user's confirmed box.
//!
//! Per-route flag-matrix coverage (the 4 flag combos × 5 unspent
//! routes) lives in the per-slice test files
//! (`blockchain_unspent_byaddress_routes.rs`,
//! `blockchain_template_routes.rs`, `blockchain_token_routes.rs`,
//! `blockchain_byergotree_routes.rs`). This file deliberately does
//! not duplicate them.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ergo_api::server::{router, router_with_mempool};
use ergo_api::traits::{MempoolView, NodeReadState};
use ergo_api::types::{
    ApiFullBlockRef, ApiHeaderRef, ApiHealth, ApiInfo, ApiMempoolSummary, ApiMempoolTransaction,
    ApiMempoolTransactions, ApiPeer, ApiStatus, ApiSyncStatus, ApiTip, ApiWeightFunction,
    HealthStatus, SyncStateLabel,
};
use ergo_indexer::{apply_block, IndexerBlock, IndexerHandle, IndexerMeta, IndexerStore};
use ergo_indexer_types::{
    BalanceDto, BoxId, IndexedBoxDto, IndexedTokenDto, IndexedTxDto, IndexerQuery, IndexerStatus,
    Page, SortDir, TemplateHash, TokenId, TreeHash, TxId,
};
use ergo_primitives::digest::{blake2b256, Digest32, ModifierId};
use ergo_primitives::group_element::GroupElement;
use ergo_primitives::reader::VlqReader;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::address::{encode_address, NetworkPrefix};
use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::{write_ergo_tree, ErgoTree};
use ergo_ser::opcode::Expr;
use ergo_ser::register::AdditionalRegisters;
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::{SigmaBoolean, SigmaValue};
use ergo_ser::transaction::{read_transaction, Transaction};
use http_body_util::BodyExt;
use serde::Deserialize;
use serde_json::Value;
use tempfile::TempDir;
use tower::ServiceExt;

// =============================================================================
// Genesis-output quirk: backfill h=1 only, then exercise segment-vs-direct
// reads.
// =============================================================================

/// Genesis box id — both input #0 and output #0 of the genesis tx.
/// Carries `globalIndex = 0`. Backfilling only h=1 keeps it unspent so
/// the segment-filter `_ > 0` is the *only* reason it could be missing
/// from an unspent query (no spend-state confounding).
const GENESIS_BOX_ID: &str = "71bc9534d4a4fe8ff67698a5d0f29782836970635de8418da39fee1cd964fcbe";

#[derive(Debug, Deserialize)]
struct TxVector {
    bytes: String,
    height: u32,
}

fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("test-vectors")
}

fn load_genesis_tx_vector() -> TxVector {
    let path = vectors_dir().join("mainnet/transactions_1_200.json");
    let data = fs::read_to_string(&path).expect("read transactions corpus");
    let all: Vec<TxVector> = serde_json::from_str(&data).expect("parse transactions corpus");
    all.into_iter()
        .find(|t| t.height == 1)
        .expect("corpus contains genesis tx at height=1")
}

fn parse_tx(v: &TxVector) -> Transaction {
    let raw = hex::decode(&v.bytes).expect("hex tx bytes");
    let mut r = VlqReader::new(&raw);
    read_transaction(&mut r).expect("parse tx")
}

/// Backfill ONLY h=1 (the genesis block), leaving the genesis box
/// `71bc...` unspent at `globalIndex = 0`. Returns a caught-up
/// indexer handle ready for the segment-filter-quirk tests.
struct GenesisHarness {
    handle: IndexerHandle,
    _tmp: TempDir,
}

fn build_genesis_harness() -> GenesisHarness {
    let tx_vec = load_genesis_tx_vector();
    let tx = parse_tx(&tx_vec);
    let tmp = TempDir::new().expect("tempdir");
    let path = tmp.path().join("indexer.redb");
    let (store, _) = IndexerStore::open(&path).expect("open store");

    let header_id = ModifierId::from_bytes([0x11; 32]);
    let txs = std::slice::from_ref(&tx);
    let block = IndexerBlock {
        height: 1,
        header_id: *header_id.as_digest(),
        transactions: txs,
    };
    let meta = apply_block(&store, &IndexerMeta::empty(), &block).expect("apply genesis block");

    let handle = IndexerHandle::with_store(store, meta.indexed_height as u64);
    handle.set_status(IndexerStatus::CaughtUp);
    GenesisHarness { handle, _tmp: tmp }
}

fn build_genesis_app(h: &GenesisHarness) -> axum::Router {
    let read: Arc<dyn NodeReadState> = Arc::new(StubReadState { full_height: 1 });
    let indexer: Arc<dyn IndexerQuery> = Arc::new(h.handle.clone());
    router(read, None, None, Some(indexer), NetworkPrefix::Mainnet)
}

#[tokio::test]
async fn genesis_output_visible_to_byid_and_byindex() {
    // Direct reads (`/box/byId`, `/box/byIndex`) bypass the segment
    // filter — they read the per-box rows directly via the by-id table
    // and the numeric-box table. Both must surface the genesis output
    // even though `globalIndex = 0`. This is the dual of the segment-
    // filter test below: the quirk is *segment-only*; it does not
    // affect direct keyed reads.
    let harness = build_genesis_harness();

    let (status, body_byid) = json_get(
        build_genesis_app(&harness),
        &format!("/blockchain/box/byId/{GENESIS_BOX_ID}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "byId genesis box: {body_byid}");
    assert_eq!(body_byid["boxId"], GENESIS_BOX_ID);
    assert_eq!(body_byid["globalIndex"], 0);
    assert_eq!(body_byid["inclusionHeight"], 1);

    let (status, body_byindex) =
        json_get(build_genesis_app(&harness), "/blockchain/box/byIndex/0").await;
    assert_eq!(status, StatusCode::OK, "byIndex 0: {body_byindex}");
    assert_eq!(body_byindex["boxId"], GENESIS_BOX_ID);
    assert_eq!(body_byindex["globalIndex"], 0);
    assert_eq!(body_byindex["inclusionHeight"], 1);
}

#[tokio::test]
async fn genesis_output_invisible_to_segment_backed_unspent_routes() {
    // After backfilling only h=1, the genesis box `71bc...` is unspent
    // and lives at `globalIndex = 0`. The segment-filter `_ > 0` in
    // `handle.rs:298, 370, 457` mirrors Scala's `Segment.scala:247,
    // 252, 259, 263` and drops it from every segment-backed unspent
    // route. This test pins that observable contract on:
    //   - /box/unspent/byAddress/{genesis_addr}
    //   - /box/unspent/byErgoTree (via the same address-keyed dispatch)
    //   - /box/unspent/byTemplateHash/{genesis_template}
    // The token route is trivially empty (genesis output carries no
    // tokens) and is therefore not part of the quirk's surface.
    let harness = build_genesis_harness();

    // First pull the genesis box's address + ergoTree from the byId
    // response (avoids hard-coding the long P2S address inline).
    let (_, byid) = json_get(
        build_genesis_app(&harness),
        &format!("/blockchain/box/byId/{GENESIS_BOX_ID}"),
    )
    .await;
    let genesis_addr = byid["address"].as_str().expect("address str").to_string();
    let genesis_tree_hex = byid["ergoTree"].as_str().expect("ergoTree hex").to_string();

    // 1. byAddress: empty array (segment filter drops globalIndex=0).
    //    `/box/unspent/byAddress` returns a bare `[IndexedErgoBox]`
    //    array.
    let (status, body) = json_get(
        build_genesis_app(&harness),
        &format!("/blockchain/box/unspent/byAddress/{genesis_addr}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unspent byAddress: {body}");
    let arr = body.as_array().expect("bare JSON array");
    assert!(
        arr.is_empty(),
        "genesis box must be invisible to /box/unspent/byAddress \
         (segment filter `_ > 0`); got {arr:?}",
    );

    // 2. byErgoTree: same dispatch — body is the raw tree hex string.
    let (status, body) = json_post(
        build_genesis_app(&harness),
        "/blockchain/box/unspent/byErgoTree",
        &serde_json::to_string(&genesis_tree_hex).unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unspent byErgoTree: {body}");
    let arr = body.as_array().expect("bare JSON array");
    assert!(
        arr.is_empty(),
        "genesis box must be invisible to /box/unspent/byErgoTree; got {arr:?}",
    );

    // 3. byTemplateHash: derive the template hash from the genesis
    //    tree's raw bytes via `template_hash_from_bytes` (the same
    //    helper the indexer uses on the apply path). At h=1 in this
    //    harness the genesis output is the only box keyed under this
    //    template, so the segment is observably non-empty unfiltered
    //    and observably empty after the `_ > 0` filter — exactly what
    //    we want to pin.
    let template_hash =
        ergo_ser::ergo_tree::template_hash_from_bytes(&hex::decode(&genesis_tree_hex).unwrap())
            .expect("template hash from genesis tree bytes");
    let template_hash_hex = hex::encode(template_hash);
    let (status, body) = json_get(
        build_genesis_app(&harness),
        &format!("/blockchain/box/unspent/byTemplateHash/{template_hash_hex}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unspent byTemplateHash: {body}");
    // `/box/unspent/byTemplateHash` returns a bare `[IndexedErgoBox]`
    // array (only the non-unspent twin uses the `{items, total}`
    // envelope).
    let arr = body.as_array().expect("bare JSON array");
    assert!(
        arr.is_empty(),
        "genesis box must be invisible to /box/unspent/byTemplateHash; got {arr:?}",
    );
}

// =============================================================================
// Pool-output IndexedErgoBox JSON shape pin (synthetic harness).
// =============================================================================

#[tokio::test]
async fn pool_output_indexed_box_json_shape_is_pinned() {
    // Every pool-output IndexedErgoBox surfaced by an unspent route
    // with `includeUnconfirmed=true` is
    // shaped `IndexedErgoBox(0, None, None, None, _, 0)` — i.e.
    // `inclusionHeight = 0`, `globalIndex = 0`, all spending fields
    // null. Per-slice tests assert subsets of this; we pin the full
    // wire shape as one citable assertion against the byAddress route
    // (which is the canonical `/box/unspent/*` surface — the other
    // routes share the `build_indexed_box_response` JSON path).
    let pubkey = [0x21u8; 33];
    let (addr, _tree_hash) = p2pk_address_and_hash(pubkey);
    let pool_box = make_pool_box(pubkey, 1_234_567, 0xAA);
    let mempool: Arc<dyn MempoolView> = Arc::new(StubMempoolView::with_outputs(vec![pool_box]));
    let app = build_app_with_mempool(Arc::new(StubIndexer::caught_up()), mempool);
    let path = format!("/blockchain/box/unspent/byAddress/{addr}?includeUnconfirmed=true");
    let (status, body) = json_get(app, &path).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let arr = body.as_array().expect("bare JSON array");
    assert_eq!(arr.len(), 1, "one pool-output overlay entry");
    let entry = arr[0].as_object().expect("entry is object");

    // Pinned mempool-overlay sentinel fields.
    assert_eq!(entry["inclusionHeight"], 0, "inclusionHeight sentinel");
    assert_eq!(entry["globalIndex"], 0, "globalIndex sentinel");
    assert!(
        entry["spentTransactionId"].is_null(),
        "spentTransactionId must be null for pool outputs",
    );
    // `spendingHeight` is absent (NOT just null) — Scala 6.0.3RC1
    // omits the field entirely, and the Rust wire shape matches
    // that behaviour as of the §10.5 parity probe follow-up.
    assert!(
        !entry.contains_key("spendingHeight"),
        "spendingHeight must be absent (Scala omits this field)",
    );
    assert!(
        entry["spendingProof"].is_null(),
        "spendingProof must be null for pool outputs",
    );

    // Standard IndexedErgoBox fields are present and reflect the pool
    // box's contents, proving the response goes through the same
    // shaping path as confirmed boxes (so consumers parsing the
    // wire-shape don't see a divergence in field set).
    assert_eq!(entry["value"], 1_234_567);
    assert_eq!(entry["address"], addr);
    assert!(entry.contains_key("boxId"), "boxId must be set");
    assert!(entry.contains_key("ergoTree"), "ergoTree must be set");
    assert!(entry.contains_key("assets"), "assets must be set");
    assert!(
        entry.contains_key("creationHeight"),
        "creationHeight must be set"
    );
    assert!(
        entry.contains_key("transactionId"),
        "transactionId must be set"
    );
    assert!(entry.contains_key("index"), "index must be set");
    assert!(
        entry.contains_key("additionalRegisters"),
        "additionalRegisters must be set",
    );
}

// =============================================================================
// /balance strictly additive: pool spend of confirmed never subtracts.
// =============================================================================

#[tokio::test]
async fn balance_is_strictly_additive_under_pool_spend_of_confirmed() {
    // The `unconfirmed` slice on /balance is computed by walking
    // `tx.outputs` only. `tx.inputs` is never
    // inspected, so a mempool tx that spends every confirmed UTXO of
    // an address leaves `confirmed` untouched. The unconfirmed slice
    // contributes ONLY matching pool outputs.
    //
    // Concrete user-visible consequence (pinned here):
    //   - Address X has confirmed_balance = 1_000_000_000 (from one
    //     confirmed box).
    //   - A mempool tx spends that confirmed box AND outputs 50 ERG
    //     (in nanoErgs) back to address X.
    //   - /balance returns: confirmed = 1_000_000_000 (NOT zero),
    //     unconfirmed = 50 (the matching pool output only).
    //
    // The `is_spent_by_pool` set is populated for the confirmed box's
    // id below — but the /balance handler must never read it. If a
    // future wiring change starts subtracting from confirmed, this
    // test will fire (confirmed would drop to zero or change shape).
    let pubkey = [0x22u8; 33];
    let (addr, tree_hash) = p2pk_address_and_hash(pubkey);

    // Stub indexer: address has 1_000_000_000 confirmed.
    let stub_idx = StubIndexer::caught_up().with_balance(
        tree_hash,
        BalanceDto {
            nano_ergs: 1_000_000_000,
            tokens: Vec::new(),
        },
    );

    // Stub mempool: one pool-output paying 50 nanoErgs to the same
    // address, AND a `spentInputs` set covering an arbitrary box id
    // that we'll claim is the user's confirmed UTXO (the stub indexer
    // doesn't dereference balance from boxes — it returns the seeded
    // BalanceDto verbatim — so any non-empty `spent` set drives the
    // /balance handler under the same wiring it would face in prod).
    let pool_box = make_pool_box(pubkey, 50, 0xBB);
    let user_confirmed_box_id = Digest32::from_bytes([0x99; 32]);
    let mempool: Arc<dyn MempoolView> = Arc::new(
        StubMempoolView::with_outputs(vec![pool_box]).with_spent(vec![user_confirmed_box_id]),
    );

    let app = build_app_with_mempool(Arc::new(stub_idx), mempool);
    let (status, body) = json_post(
        app,
        "/blockchain/balance",
        &serde_json::to_string(&addr).unwrap(),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(
        body["confirmed"]["nanoErgs"], 1_000_000_000_i64,
        "confirmed must be untouched by mempool spend (strictly additive)",
    );
    assert!(
        body["confirmed"]["tokens"].as_array().unwrap().is_empty(),
        "confirmed.tokens unchanged",
    );
    assert_eq!(
        body["unconfirmed"]["nanoErgs"], 50_i64,
        "unconfirmed reflects pool-output payment to addr only",
    );
    assert!(
        body["unconfirmed"]["tokens"].as_array().unwrap().is_empty(),
        "unconfirmed.tokens empty (pool box has no tokens)",
    );
    assert!(
        body.get("warning").is_none(),
        "pre-P5 `warning` field is fully retired",
    );
}

// =============================================================================
// Helpers (synthetic stub harness shared with per-slice tests' style).
// =============================================================================

fn p2pk_tree(pubkey: [u8; 33]) -> (ErgoTree, Vec<u8>) {
    let tree = ErgoTree {
        version: 0,
        has_size: false,
        constant_segregation: false,
        constants: Vec::new(),
        body: Expr::Const {
            tpe: SigmaType::SSigmaProp,
            val: SigmaValue::SigmaProp(SigmaBoolean::ProveDlog(GroupElement::from_bytes(pubkey))),
        },
    };
    let mut w = VlqWriter::new();
    write_ergo_tree(&mut w, &tree).unwrap();
    let bytes = w.result();
    (tree, bytes)
}

fn p2pk_address_and_hash(pubkey: [u8; 33]) -> (String, Digest32) {
    let (tree, bytes) = p2pk_tree(pubkey);
    let addr = encode_address(NetworkPrefix::Mainnet, &tree, &bytes);
    let tree_hash = blake2b256(&bytes);
    (addr, tree_hash)
}

fn make_pool_box(pubkey: [u8; 33], value: u64, tx_id_byte: u8) -> ErgoBox {
    let (tree, _bytes) = p2pk_tree(pubkey);
    let candidate = ErgoBoxCandidate::new(value, tree, 0, Vec::new(), AdditionalRegisters::empty())
        .expect("ErgoBoxCandidate::new");
    ErgoBox {
        candidate,
        transaction_id: ModifierId::from_bytes([tx_id_byte; 32]),
        index: 0,
    }
}

fn build_app_with_mempool(
    indexer: Arc<dyn IndexerQuery>,
    mempool: Arc<dyn MempoolView>,
) -> axum::Router {
    let read: Arc<dyn NodeReadState> = Arc::new(StubReadState { full_height: 1234 });
    router_with_mempool(
        ergo_api::ServerCtx {
            read,
            compat: None,
            submit: None,
            indexer: Some(indexer),
            mempool,
            network: NetworkPrefix::Mainnet,
            chain_params: None,
            mining: None,
            emission: None,
            emission_scripts: None,
            utxo_reads_supported: true,
        },
        None, // admin — tests don't exercise the shutdown endpoint
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

async fn json_post(app: axum::Router, path: &str, body: &str) -> (StatusCode, Value) {
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
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

// ---------- StubReadState (mirrors balance_routes harness) ----------------

struct StubReadState {
    full_height: u32,
}

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
            best_header_height: self.full_height,
            best_full_block_height: self.full_height,
            ..Default::default()
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

// ---------- StubMempoolView (full surface: outputs + spent set) -----------

struct StubMempoolView {
    outputs: Arc<HashMap<BoxId, ErgoBox>>,
    spent: std::collections::HashSet<BoxId>,
}

impl StubMempoolView {
    fn with_outputs(boxes: Vec<ErgoBox>) -> Self {
        let mut outputs = HashMap::new();
        for b in boxes {
            let id = b.box_id().expect("box_id");
            outputs.insert(id, b);
        }
        Self {
            outputs: Arc::new(outputs),
            spent: std::collections::HashSet::new(),
        }
    }
    fn with_spent(mut self, spent: Vec<BoxId>) -> Self {
        self.spent = spent.into_iter().collect();
        self
    }
}

impl MempoolView for StubMempoolView {
    fn is_spent_by_pool(&self, box_id: &BoxId) -> bool {
        self.spent.contains(box_id)
    }
    fn pool_spending_tx(&self, _box_id: &BoxId) -> Option<TxId> {
        None
    }
    fn pool_outputs(&self) -> Arc<HashMap<BoxId, ErgoBox>> {
        self.outputs.clone()
    }
}

// ---------- StubIndexer (minimal balance-seedable surface) ----------------

struct StubIndexer {
    status: IndexerStatus,
    balance: Option<(TreeHash, BalanceDto)>,
}

impl StubIndexer {
    fn caught_up() -> Self {
        Self {
            status: IndexerStatus::CaughtUp,
            balance: None,
        }
    }
    fn with_balance(mut self, tree_hash: TreeHash, dto: BalanceDto) -> Self {
        self.balance = Some((tree_hash, dto));
        self
    }
}

impl IndexerQuery for StubIndexer {
    fn indexed_height(&self) -> u64 {
        700_000
    }
    fn status(&self) -> IndexerStatus {
        self.status.clone()
    }
    fn box_by_id(&self, _: &BoxId) -> Option<IndexedBoxDto> {
        None
    }
    fn box_by_global_index(&self, _: u64) -> Option<IndexedBoxDto> {
        None
    }
    fn boxes_by_global_range(&self, _: u64, _: u64) -> Vec<IndexedBoxDto> {
        Vec::new()
    }
    fn tx_by_id(&self, _: &TxId) -> Option<IndexedTxDto> {
        None
    }
    fn tx_by_global_index(&self, _: u64) -> Option<IndexedTxDto> {
        None
    }
    fn txs_by_global_range(&self, _: u64, _: u64) -> Vec<IndexedTxDto> {
        Vec::new()
    }
    fn address_balance(&self, tree_hash: &TreeHash) -> Option<BalanceDto> {
        self.balance
            .as_ref()
            .filter(|(h, _)| h == tree_hash)
            .map(|(_, dto)| dto.clone())
    }
    fn address_txs_paged(&self, _: &TreeHash, _: Page, _: SortDir) -> Vec<IndexedTxDto> {
        Vec::new()
    }
    fn address_boxes_paged(&self, _: &TreeHash, _: Page, _: SortDir) -> Vec<IndexedBoxDto> {
        Vec::new()
    }
    fn address_unspent_paged(&self, _: &TreeHash, _: Page, _: SortDir) -> Vec<IndexedBoxDto> {
        Vec::new()
    }
    fn address_total_txs(&self, _: &TreeHash) -> u64 {
        0
    }
    fn address_total_boxes(&self, _: &TreeHash) -> u64 {
        0
    }
    fn template_boxes_paged(&self, _: &TemplateHash, _: Page) -> Vec<IndexedBoxDto> {
        Vec::new()
    }
    fn template_unspent_paged(&self, _: &TemplateHash, _: Page, _: SortDir) -> Vec<IndexedBoxDto> {
        Vec::new()
    }
    fn template_total_boxes(&self, _: &TemplateHash) -> u64 {
        0
    }
    fn token_by_id(&self, _: &TokenId) -> Option<IndexedTokenDto> {
        None
    }
    fn tokens_by_ids(&self, _: &[TokenId]) -> Vec<IndexedTokenDto> {
        Vec::new()
    }
    fn token_boxes_paged(&self, _: &TokenId, _: Page) -> Vec<IndexedBoxDto> {
        Vec::new()
    }
    fn token_unspent_paged(&self, _: &TokenId, _: Page, _: SortDir) -> Vec<IndexedBoxDto> {
        Vec::new()
    }
    fn token_total_boxes(&self, _: &TokenId) -> u64 {
        0
    }
}
