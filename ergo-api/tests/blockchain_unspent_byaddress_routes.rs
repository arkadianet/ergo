//! `POST /blockchain/box/unspent/byAddress` and the GET twin.
//!
//! Pinned behavior:
//! - The status gate fronts both routes; `Syncing` / `Halted`
//!   short-circuit before paging math runs.
//! - Wire shape is a bare `[IndexedErgoBox]` JSON array per the openapi
//!   schema (NOT the `{items, total}` envelope used by /box/byAddress).
//! - Default `sortDirection` is `desc` per Scala
//!   (`BlockchainApiRoute.scala:50, 52, 57`); `asc`/`desc` parsed
//!   case-insensitively. Anything else → 400 bad-request with the
//!   literal Scala `"Invalid parameter for sort direction, valid values
//!   are 'ASC' and 'DESC'"` detail.
//! - **Mempool overlay:** `includeUnconfirmed` / `excludeMempoolSpent`
//!   are strictly orthogonal. `excludeMempoolSpent=true` filters
//!   confirmed *and* unconfirmed slices by `mempool.spentInputs`;
//!   `includeUnconfirmed=true` appends the matching pool-output
//!   extension shaped as `IndexedErgoBox(0, None, None, None, _, 0)`.
//!   Sort direction determines merge order (DESC = unconfirmed first,
//!   ASC = confirmed first). Confirmed slice is paged at the indexer;
//!   the unconfirmed extension is appended without further pagination,
//!   so the response may exceed `limit` — `[inherited]` Scala paging
//!   quirk.
//! - Validation order matches the Scala directive chain: paging →
//!   sortDirection → address parse → read+overlay. Overlay flags never
//!   gate; they alter behavior. Tests below pin the chain by sending
//!   requests that violate multiple rules at once and asserting which
//!   envelope wins.

use std::collections::HashMap;
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
use ergo_indexer::{IndexerHaltReason, IndexerHandle};
use ergo_indexer_types::types::{IndexedErgoBox, IndexedErgoTransaction};
use ergo_indexer_types::{
    BalanceDto, BoxId, IndexedBoxDto, IndexedTokenDto, IndexedTxDto, IndexerQuery, IndexerStatus,
    Page, SortDir, TemplateHash, TokenId, TreeHash, TxId,
};
use ergo_primitives::digest::{blake2b256, Digest32, ModifierId};
use ergo_primitives::group_element::GroupElement;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::address::{encode_address, NetworkPrefix};
use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::{write_ergo_tree, ErgoTree};
use ergo_ser::opcode::Expr;
use ergo_ser::register::AdditionalRegisters;
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::{SigmaBoolean, SigmaValue};
use http_body_util::BodyExt;
use tower::ServiceExt;

const SORT_DETAIL: &str = "Invalid parameter for sort direction, valid values are 'ASC' and 'DESC'";

// ---------------- 503 status-gate ------------------------------------------

#[tokio::test]
async fn post_unspent_by_address_503_indexer_syncing() {
    let app = build_app(Arc::new(StubIndexer::with_status(IndexerStatus::Syncing)));
    let (status, body) = json_post(
        app,
        "/blockchain/box/unspent/byAddress",
        &json_str(&p2pk_address()),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["reason"], "indexer-syncing");
}

#[tokio::test]
async fn get_unspent_by_address_503_indexer_halted() {
    let app = build_app(Arc::new(StubIndexer::with_status(IndexerStatus::Halted(
        IndexerHaltReason::DbCorruption,
    ))));
    let path = format!("/blockchain/box/unspent/byAddress/{}", p2pk_address());
    let (status, body) = json_get(app, &path).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["reason"], "indexer-halted");
}

// ---------------- 400 invalid-address --------------------------------------

#[tokio::test]
async fn post_unspent_by_address_400_on_invalid_address() {
    let app = build_app(Arc::new(StubIndexer::caught_up()));
    let (status, body) = json_post(
        app,
        "/blockchain/box/unspent/byAddress",
        "\"!!!not-base58!!!\"",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["reason"], "invalid-address");
}

// ---------------- 400 bad-request: paging validation -----------------------

#[tokio::test]
async fn post_unspent_by_address_400_on_limit_above_max() {
    let app = build_app(Arc::new(StubIndexer::caught_up()));
    let (status, body) = json_post(
        app,
        "/blockchain/box/unspent/byAddress?limit=16385",
        &json_str(&p2pk_address()),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["reason"], "bad-request");
    assert_eq!(body["detail"], "No more than 16384 boxes can be requested");
}

#[tokio::test]
async fn get_unspent_by_address_400_on_negative_offset() {
    let app = build_app(Arc::new(StubIndexer::caught_up()));
    let path = format!(
        "/blockchain/box/unspent/byAddress/{}?offset=-3",
        p2pk_address()
    );
    let (status, body) = json_get(app, &path).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["reason"], "bad-request");
    assert_eq!(body["detail"], "offset is negative");
}

// ---------------- 400 bad-request: sortDirection ---------------------------

#[tokio::test]
async fn get_unspent_by_address_400_on_unknown_sort_direction() {
    let app = build_app(Arc::new(StubIndexer::caught_up()));
    let path = format!(
        "/blockchain/box/unspent/byAddress/{}?sortDirection=sideways",
        p2pk_address()
    );
    let (status, body) = json_get(app, &path).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["reason"], "bad-request");
    assert_eq!(body["detail"], SORT_DETAIL);
}

// ---------------- Overlay: includeUnconfirmed ------------------------------

// Pool output for the queried address is appended to the response and
// shaped as the pool-output `IndexedErgoBox` sentinel:
// `inclusionHeight = 0` (the unique mempool sentinel — confirmed boxes
// always have height ≥ 1), `globalIndex = 0`, all spending fields null.
#[tokio::test]
async fn unspent_overlay_include_unconfirmed_appends_matching_pool_output() {
    let pubkey = [0x41u8; 33];
    let (addr, _tree_hash) = p2pk_address_and_hash(pubkey);
    let pool_box = make_pool_box(pubkey, 7_000_000, 0xAA);
    let mempool: Arc<dyn MempoolView> = Arc::new(StubMempoolView::with_outputs(vec![pool_box]));
    let app = build_app_with_mempool(Arc::new(StubIndexer::caught_up()), mempool);
    let path = format!("/blockchain/box/unspent/byAddress/{addr}?includeUnconfirmed=true");
    let (status, body) = json_get(app, &path).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let arr = body.as_array().expect("bare JSON array");
    assert_eq!(arr.len(), 1, "one pool-output overlay entry");
    let entry = &arr[0];
    assert_eq!(entry["inclusionHeight"], 0, "P5 sentinel");
    assert_eq!(entry["globalIndex"], 0);
    assert!(entry["spentTransactionId"].is_null());
    // Scala omits `spendingHeight` entirely (parity probe 2026-05-19).
    assert!(!entry.as_object().unwrap().contains_key("spendingHeight"));
    assert!(entry["spendingProof"].is_null());
    assert_eq!(entry["value"], 7_000_000);
    assert_eq!(entry["address"], addr);
}

// Pool outputs that don't match the queried tree_hash must be filtered
// out — overlay is per-address, not "show me everything in the pool".
#[tokio::test]
async fn unspent_overlay_pool_output_for_other_address_excluded() {
    let queried = [0x42u8; 33];
    let (queried_addr, _) = p2pk_address_and_hash(queried);
    let other = [0x43u8; 33];
    let pool_box_other = make_pool_box(other, 1_234_567, 0xAB);
    let mempool: Arc<dyn MempoolView> =
        Arc::new(StubMempoolView::with_outputs(vec![pool_box_other]));
    let app = build_app_with_mempool(Arc::new(StubIndexer::caught_up()), mempool);
    let path = format!("/blockchain/box/unspent/byAddress/{queried_addr}?includeUnconfirmed=true");
    let (status, body) = json_get(app, &path).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.as_array().expect("bare JSON array").is_empty());
}

// ---------------- P5 overlay: excludeMempoolSpent -------------------------

// `excludeMempoolSpent=true` drops confirmed unspent rows whose box_id
// is in `mempool.spentInputs` per `Segment.scala:265`. Stub indexer
// emits two confirmed boxes; the spent-set covers one — only the other
// survives. `globalIndex` is preserved for the survivor (it is a real
// confirmed box, not an overlay entry).
#[tokio::test]
async fn unspent_overlay_exclude_mempool_spent_drops_confirmed_box() {
    let pubkey = [0x44u8; 33];
    let (addr, tree_hash) = p2pk_address_and_hash(pubkey);
    let confirmed = vec![
        fixture_box(pubkey, 700_010, 1_000, 11),
        fixture_box(pubkey, 700_011, 2_000, 12),
    ];
    let confirmed_ids: Vec<BoxId> = confirmed
        .iter()
        .map(|b| b.box_data.box_id().expect("box_id"))
        .collect();
    let stub_idx = StubIndexer::caught_up().with_unspent(tree_hash, confirmed);
    // Only the first confirmed box's id is "spent in pool" — the second
    // survives. Overlay supplies no pool-output extension, so the
    // result is exactly the surviving confirmed entry.
    let mempool: Arc<dyn MempoolView> =
        Arc::new(StubMempoolView::with_outputs(Vec::new()).with_spent(vec![confirmed_ids[0]]));
    let app = build_app_with_mempool(Arc::new(stub_idx), mempool);
    let path = format!("/blockchain/box/unspent/byAddress/{addr}?excludeMempoolSpent=true");
    let (status, body) = json_get(app, &path).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let arr = body.as_array().expect("bare JSON array");
    assert_eq!(arr.len(), 1, "one survivor (the unspent-by-pool box)");
    assert_eq!(arr[0]["globalIndex"], 12);
}

// Per `Segment.scala:268`, `excludeMempoolSpent=true` also filters the
// pool-output extension — chained pool spends (one pool tx outputs to
// the address, another pool tx consumes that output) must not appear in
// the unconfirmed slice when the flag is set. Two pool outputs for the
// queried address; the first id is in the spent set, only the second
// surfaces.
#[tokio::test]
async fn unspent_overlay_exclude_mempool_spent_drops_chained_pool_output() {
    let pubkey = [0x45u8; 33];
    let (addr, _) = p2pk_address_and_hash(pubkey);
    let pool_a = make_pool_box(pubkey, 10_000, 0xC0);
    let pool_b = make_pool_box(pubkey, 20_000, 0xC1);
    let pool_a_id = pool_a.box_id().expect("box_id");
    let mempool: Arc<dyn MempoolView> =
        Arc::new(StubMempoolView::with_outputs(vec![pool_a, pool_b]).with_spent(vec![pool_a_id]));
    let app = build_app_with_mempool(Arc::new(StubIndexer::caught_up()), mempool);
    let path = format!(
        "/blockchain/box/unspent/byAddress/{addr}?includeUnconfirmed=true&excludeMempoolSpent=true"
    );
    let (status, body) = json_get(app, &path).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let arr = body.as_array().expect("bare JSON array");
    assert_eq!(arr.len(), 1, "chained pool spend filtered out");
    assert_eq!(arr[0]["value"], 20_000);
    assert_eq!(arr[0]["inclusionHeight"], 0);
}

// ---------------- P5 overlay: merge order ---------------------------------

// `Segment.scala:269-272` DESC branch: `unconfirmedBoxes ++ confirmedBoxes`.
// Two confirmed (sorted desc by globalIndex by the stub) precede zero pool
// boxes (control case: trivial). With one pool box added, the pool box
// must come *first* in the merged response.
#[tokio::test]
async fn unspent_overlay_default_desc_places_unconfirmed_first() {
    let pubkey = [0x46u8; 33];
    let (addr, tree_hash) = p2pk_address_and_hash(pubkey);
    let confirmed = vec![
        fixture_box(pubkey, 700_020, 1_000, 21),
        fixture_box(pubkey, 700_021, 2_000, 22),
    ];
    let pool_box = make_pool_box(pubkey, 999_999, 0xD1);
    let stub_idx = StubIndexer::caught_up().with_unspent(tree_hash, confirmed);
    let mempool: Arc<dyn MempoolView> = Arc::new(StubMempoolView::with_outputs(vec![pool_box]));
    let app = build_app_with_mempool(Arc::new(stub_idx), mempool);
    let path = format!("/blockchain/box/unspent/byAddress/{addr}?includeUnconfirmed=true");
    let (status, body) = json_get(app, &path).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let arr = body.as_array().expect("bare JSON array");
    assert_eq!(arr.len(), 3);
    // Unconfirmed first (P5 sentinel inclusionHeight=0), then confirmed
    // descending by globalIndex per the stub's sort.
    assert_eq!(arr[0]["inclusionHeight"], 0, "unconfirmed first under DESC");
    assert_eq!(arr[1]["globalIndex"], 22);
    assert_eq!(arr[2]["globalIndex"], 21);
}

// ASC branch: `confirmedBoxes ++ unconfirmedBoxes`. Confirmed precede
// the pool-output extension.
#[tokio::test]
async fn unspent_overlay_asc_places_confirmed_first() {
    let pubkey = [0x47u8; 33];
    let (addr, tree_hash) = p2pk_address_and_hash(pubkey);
    let confirmed = vec![
        fixture_box(pubkey, 700_030, 1_000, 31),
        fixture_box(pubkey, 700_031, 2_000, 32),
    ];
    let pool_box = make_pool_box(pubkey, 999_999, 0xD2);
    let stub_idx = StubIndexer::caught_up().with_unspent(tree_hash, confirmed);
    let mempool: Arc<dyn MempoolView> = Arc::new(StubMempoolView::with_outputs(vec![pool_box]));
    let app = build_app_with_mempool(Arc::new(stub_idx), mempool);
    let path = format!(
        "/blockchain/box/unspent/byAddress/{addr}?includeUnconfirmed=true&sortDirection=asc"
    );
    let (status, body) = json_get(app, &path).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let arr = body.as_array().expect("bare JSON array");
    assert_eq!(arr.len(), 3);
    // Confirmed first ascending by globalIndex, then unconfirmed.
    assert_eq!(arr[0]["globalIndex"], 31);
    assert_eq!(arr[1]["globalIndex"], 32);
    assert_eq!(arr[2]["inclusionHeight"], 0, "unconfirmed last under ASC");
}

// `[inherited]` paging quirk: confirmed slicing happens at the
// indexer (`Segment.scala:254/264`) *before* the
// unconfirmed merge, so when `includeUnconfirmed=true` the response can
// exceed `limit`. Concretely: limit=1 + 1 confirmed + 1 pool output →
// response has 2 items, not 1. Operator scripts that depend on
// `result.length <= limit` must update when migrating to a Rust node.
#[tokio::test]
async fn unspent_overlay_response_can_exceed_limit_when_include_unconfirmed() {
    let pubkey = [0x48u8; 33];
    let (addr, tree_hash) = p2pk_address_and_hash(pubkey);
    let confirmed = vec![
        fixture_box(pubkey, 700_040, 1_000, 41),
        fixture_box(pubkey, 700_041, 2_000, 42),
    ];
    let pool_box = make_pool_box(pubkey, 999_999, 0xD3);
    let stub_idx = StubIndexer::caught_up().with_unspent(tree_hash, confirmed);
    let mempool: Arc<dyn MempoolView> = Arc::new(StubMempoolView::with_outputs(vec![pool_box]));
    let app = build_app_with_mempool(Arc::new(stub_idx), mempool);
    let path = format!("/blockchain/box/unspent/byAddress/{addr}?limit=1&includeUnconfirmed=true");
    let (status, body) = json_get(app, &path).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let arr = body.as_array().expect("bare JSON array");
    // 1 paged confirmed + 1 unpaged pool output = 2; over the limit by
    // the count of overlay entries. Documented Scala parity quirk.
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0]["inclusionHeight"], 0, "DESC: unconfirmed first");
}

// ---------------- validation order: paging > sort > address ---------------

// Validation order: paging > sortDirection > address parse. Overlay
// flags don't gate — they alter behavior — so a request with both flags
// set + invalid sort + over-limit + invalid address still surfaces the
// limit error first because that's the cheapest gate.
#[tokio::test]
async fn paging_error_wins_over_sort_and_overlay_flags() {
    let app = build_app(Arc::new(StubIndexer::caught_up()));
    let path = format!(
        "/blockchain/box/unspent/byAddress/{}?limit=99999&sortDirection=sideways&includeUnconfirmed=true&excludeMempoolSpent=true",
        p2pk_address()
    );
    let (status, body) = json_get(app, &path).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["detail"], "No more than 16384 boxes can be requested");
}

// ---------------- 200 success: bare array, sort default desc ---------------

#[tokio::test]
async fn get_unspent_by_address_200_default_sort_desc() {
    let pubkey = [0x21u8; 33];
    let (addr, tree_hash) = p2pk_address_and_hash(pubkey);
    // Three unspent fixtures with global_index 10, 20, 30. The stub
    // sorts by `dir` before paging, so default (`desc`) yields 30,20,10.
    let boxes = vec![
        fixture_box(pubkey, 700_000, 1_000, 10),
        fixture_box(pubkey, 700_001, 2_000, 20),
        fixture_box(pubkey, 700_002, 3_000, 30),
    ];
    let stub = StubIndexer::caught_up().with_unspent(tree_hash, boxes);
    let app = build_app(Arc::new(stub));
    let path = format!("/blockchain/box/unspent/byAddress/{addr}");
    let (status, body) = json_get(app, &path).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let arr = body.as_array().expect("bare JSON array");
    assert_eq!(arr.len(), 3);
    assert_eq!(arr[0]["globalIndex"], 30);
    assert_eq!(arr[1]["globalIndex"], 20);
    assert_eq!(arr[2]["globalIndex"], 10);
}

// `sortDirection=asc` (case-insensitive — sent uppercase to verify the
// `to_ascii_lowercase` normalization) flips the order. The stub records
// the dir it received and orders boxes accordingly.
#[tokio::test]
async fn post_unspent_by_address_200_sort_asc_case_insensitive() {
    let pubkey = [0x22u8; 33];
    let (addr, tree_hash) = p2pk_address_and_hash(pubkey);
    let boxes = vec![
        fixture_box(pubkey, 700_000, 1_000, 10),
        fixture_box(pubkey, 700_001, 2_000, 20),
        fixture_box(pubkey, 700_002, 3_000, 30),
    ];
    let stub = StubIndexer::caught_up().with_unspent(tree_hash, boxes);
    let app = build_app(Arc::new(stub));
    let (status, body) = json_post(
        app,
        "/blockchain/box/unspent/byAddress?sortDirection=ASC",
        &json_str(&addr),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let arr = body.as_array().unwrap();
    assert_eq!(arr.len(), 3);
    assert_eq!(arr[0]["globalIndex"], 10);
    assert_eq!(arr[1]["globalIndex"], 20);
    assert_eq!(arr[2]["globalIndex"], 30);
}

// Unindexed address (no `with_unspent` call) still returns 200 with an
// empty array — distinguishes a legit "no records" from any error path.
#[tokio::test]
async fn get_unspent_by_address_200_unindexed_returns_empty_array() {
    let app = build_app(Arc::new(StubIndexer::caught_up()));
    let path = format!("/blockchain/box/unspent/byAddress/{}", p2pk_address());
    let (status, body) = json_get(app, &path).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.as_array().expect("bare JSON array").is_empty());
}

// ---------------- POST/GET parity ------------------------------------------

#[tokio::test]
async fn post_and_get_emit_identical_arrays() {
    let pubkey = [0x33u8; 33];
    let (addr, tree_hash) = p2pk_address_and_hash(pubkey);
    let boxes = vec![fixture_box(pubkey, 700_005, 7_654_321, 99)];
    let post_app = build_app(Arc::new(
        StubIndexer::caught_up().with_unspent(tree_hash, boxes.clone()),
    ));
    let get_app = build_app(Arc::new(
        StubIndexer::caught_up().with_unspent(tree_hash, boxes),
    ));
    let (post_status, post_body) = json_post(
        post_app,
        "/blockchain/box/unspent/byAddress",
        &json_str(&addr),
    )
    .await;
    let path = format!("/blockchain/box/unspent/byAddress/{addr}");
    let (get_status, get_body) = json_get(get_app, &path).await;
    assert_eq!(post_status, StatusCode::OK);
    assert_eq!(get_status, StatusCode::OK);
    assert_eq!(post_body, get_body);
}

// ---------------- helpers --------------------------------------------------

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

fn p2pk_address() -> String {
    p2pk_address_and_hash([0x02; 33]).0
}

fn fixture_box(pubkey: [u8; 33], height: i32, value: u64, global_index: i64) -> IndexedErgoBox {
    let (tree, _bytes) = p2pk_tree(pubkey);
    let candidate = ErgoBoxCandidate::new(
        value,
        tree,
        height as u32,
        Vec::new(),
        AdditionalRegisters::empty(),
    )
    .expect("ErgoBoxCandidate::new");
    let box_data = ErgoBox {
        candidate,
        transaction_id: ModifierId::from_bytes([0xCC; 32]),
        index: 0,
    };
    IndexedErgoBox {
        inclusion_height: height,
        spending_tx_id: None,
        spending_height: None,
        spending_proof: None,
        box_data,
        global_index,
    }
}

fn json_str(s: &str) -> String {
    serde_json::to_string(s).unwrap()
}

fn build_app(indexer: Arc<dyn IndexerQuery>) -> axum::Router {
    let read: Arc<dyn NodeReadState> = Arc::new(StubReadState { full_height: 1234 });
    // Unspent box routes mount unconditionally — they don't need a chain
    // reader since `build_indexed_box_response` enriches only via the
    // network prefix. Pass `None` to confirm the route is reachable
    // without a compat-side dependency. `router()` wires `NoopMempoolView`
    // (overlay-disabled), which is the right default for the validation
    // / status-gate / shape tests above.
    router(read, None, None, Some(indexer), NetworkPrefix::Mainnet)
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

/// Build an `ErgoBox` with the given P2PK ergo tree, value, and a
/// distinct `transaction_id` (`tx_id_byte` repeated 32x) so the box's
/// derived `box_id` is unique within a test even when value/tree match
/// another fixture. Mirrors the helper in `blockchain_balance_routes.rs`
/// so the two suites read alike.
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

/// Stub `MempoolView`: a fixed pool-output set + an explicit
/// `spentInputs` set so tests can drive the `is_spent_by_pool` filter
/// independently from the pool-output extension. No `pool_spending_tx`
/// caller in the unspent path, so that method returns `None`.
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

async fn json_get(app: axum::Router, path: &str) -> (StatusCode, serde_json::Value) {
    let resp = app
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let value = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    };
    (status, value)
}

async fn json_post(app: axum::Router, path: &str, body: &str) -> (StatusCode, serde_json::Value) {
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
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let value = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    };
    (status, value)
}

// ---------------- StubIndexer: paged unspent reader -----------------------

struct StubIndexer {
    status: IndexerStatus,
    unspent: Option<(TreeHash, Vec<IndexedErgoBox>)>,
}

impl StubIndexer {
    fn caught_up() -> Self {
        Self {
            status: IndexerStatus::CaughtUp,
            unspent: None,
        }
    }
    fn with_status(status: IndexerStatus) -> Self {
        Self {
            status,
            unspent: None,
        }
    }
    fn with_unspent(mut self, tree_hash: TreeHash, boxes: Vec<IndexedErgoBox>) -> Self {
        self.unspent = Some((tree_hash, boxes));
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

    fn address_balance(&self, _: &TreeHash) -> Option<BalanceDto> {
        None
    }
    fn address_txs_paged(&self, _: &TreeHash, _: Page, _: SortDir) -> Vec<IndexedTxDto> {
        Vec::new()
    }
    fn address_boxes_paged(&self, _: &TreeHash, _: Page, _: SortDir) -> Vec<IndexedBoxDto> {
        Vec::new()
    }
    fn address_unspent_paged(
        &self,
        tree_hash: &TreeHash,
        p: Page,
        dir: SortDir,
    ) -> Vec<IndexedBoxDto> {
        match &self.unspent {
            Some((h, boxes)) if h == tree_hash => {
                // Sort by global_index per the requested direction so the
                // test asserts dir gets threaded all the way to the
                // reader. Real implementations filter+sort upstream; the
                // stub does it here for fixture brevity.
                let mut sorted: Vec<IndexedErgoBox> = boxes.clone();
                match dir {
                    SortDir::Asc => sorted.sort_by_key(|b| b.global_index),
                    SortDir::Desc => sorted.sort_by_key(|b| -b.global_index),
                }
                let lo = p.offset as usize;
                let hi = lo.saturating_add(p.limit as usize).min(sorted.len());
                if lo >= sorted.len() {
                    Vec::new()
                } else {
                    sorted[lo..hi].to_vec()
                }
            }
            _ => Vec::new(),
        }
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

// ---------------- StubReadState (mirrors blockchain_byaddress_routes.rs) ---

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
            peer_count: 0,
            best_header_height: self.full_height,
            best_full_block_height: self.full_height,
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

// Ensure the dev-only IndexerHandle import path stays referenced.
#[allow(dead_code)]
fn _ensure_handle_use_compiles() {
    let _ = IndexerHandle::syncing(0);
}

// Suppress lints on imported but here-unused symbols that other tests
// in this crate exercise. Keeping the import surface aligned with the
// sibling `blockchain_byaddress_routes.rs` file makes the two suites
// easier to diff.
#[allow(dead_code)]
fn _ensure_indexed_tx_compiles() {
    let _: Option<IndexedErgoTransaction> = None;
}
