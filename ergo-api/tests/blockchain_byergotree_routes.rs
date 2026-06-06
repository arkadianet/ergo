//! `POST /blockchain/box/byErgoTree` and
//! `POST /blockchain/box/unspent/byErgoTree` — byErgoTree dispatch
//! routes (#24, #25).
//!
//! Pinned behavior:
//! - Body is a JSON-string holding the hex-encoded canonical
//!   `ErgoTree.bytes`.
//! - Both routes hex-decode → parse → re-serialize → blake2b256 the
//!   tree. The resulting tree_hash is the same key the indexer's
//!   address-keyed tables use, so the dispatch lands on
//!   `address_boxes_paged` / `address_unspent_paged` without any new
//!   trait surface (extra-index parity doc lines 1553-1554).
//! - Wire shapes match the address counterparts:
//!   #24 → `{items, total}` envelope (mirrors #9/#10)
//!   #25 → bare `[IndexedErgoBox]` array (mirrors #11/#12)
//! - **Mempool overlay:** `includeUnconfirmed` / `excludeMempoolSpent`
//!   are strictly orthogonal. Same `pool_unspent_for_tree` filter, same
//!   `Segment.scala:265` confirmed-side filter, and same DESC/ASC merge
//!   order as `unspent/byAddress` — the byErgoTree route hashes the
//!   body and dispatches into the address-keyed reader, so the overlay
//!   semantics are byte-identical.
//! - Validation order on #25 mirrors /unspent/byAddress: paging →
//!   sortDirection → tree decode → read+overlay. Overlay flags never
//!   gate; they alter behavior.
//! - Hex-decode failure and ergotree-parse failure both surface as the
//!   pinned `400 invalid-ergo-tree` envelope (Scala flattens both into
//!   one 400; we keep the failure mode in `detail` for diagnostics).
//! - The status gate fronts both routes — `Syncing` / `Halted`
//!   short-circuits before the body is even decoded.

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
use ergo_indexer_types::types::IndexedErgoBox;
use ergo_indexer_types::{
    BalanceDto, BoxId, IndexedBoxDto, IndexedTokenDto, IndexedTxDto, IndexerQuery, IndexerStatus,
    Page, SortDir, TemplateHash, TokenId, TreeHash, TxId,
};
use ergo_primitives::digest::{blake2b256, Digest32, ModifierId};
use ergo_primitives::group_element::GroupElement;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::address::NetworkPrefix;
use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::{write_ergo_tree, ErgoTree};
use ergo_ser::opcode::Expr;
use ergo_ser::register::AdditionalRegisters;
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::{SigmaBoolean, SigmaValue};
use http_body_util::BodyExt;
use tower::ServiceExt;

// ---------------- 503 status-gate ------------------------------------------

#[tokio::test]
async fn post_by_ergo_tree_503_indexer_syncing() {
    let app = build_app(Arc::new(StubIndexer::with_status(IndexerStatus::Syncing)));
    let (status, body) = json_post(
        app,
        "/blockchain/box/byErgoTree",
        &json_str(&p2pk_tree_hex([0x02; 33])),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["reason"], "indexer-syncing");
}

#[tokio::test]
async fn post_unspent_by_ergo_tree_503_indexer_halted() {
    let app = build_app(Arc::new(StubIndexer::with_status(IndexerStatus::Halted(
        IndexerHaltReason::DbCorruption,
    ))));
    let (status, body) = json_post(
        app,
        "/blockchain/box/unspent/byErgoTree",
        &json_str(&p2pk_tree_hex([0x02; 33])),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["reason"], "indexer-halted");
}

// ---------------- 400 invalid-ergo-tree ------------------------------------

#[tokio::test]
async fn post_by_ergo_tree_400_on_invalid_hex() {
    let app = build_app(Arc::new(StubIndexer::caught_up()));
    let (status, body) = json_post(app, "/blockchain/box/byErgoTree", "\"not-hex!!!\"").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["reason"], "invalid-ergo-tree");
}

#[tokio::test]
async fn post_unspent_by_ergo_tree_400_on_unparsable_tree() {
    // Valid hex but garbage opcode bytes that parse as an ergotree
    // header followed by an undefined opcode — read_ergo_tree fails.
    let app = build_app(Arc::new(StubIndexer::caught_up()));
    let (status, body) = json_post(
        app,
        "/blockchain/box/unspent/byErgoTree",
        "\"00ff00ff00ff\"",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["reason"], "invalid-ergo-tree");
}

// ---------------- 400 bad-request: paging ----------------------------------

#[tokio::test]
async fn post_by_ergo_tree_400_on_limit_above_max() {
    let app = build_app(Arc::new(StubIndexer::caught_up()));
    let (status, body) = json_post(
        app,
        "/blockchain/box/byErgoTree?limit=99999",
        &json_str(&p2pk_tree_hex([0x02; 33])),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["reason"], "bad-request");
    assert_eq!(body["detail"], "No more than 16384 boxes can be requested");
}

// ---------------- P5 overlay (slice 7) -------------------------------------
//
// `unspent/byErgoTree` dispatches by `tree_hash` after hex-decoding +
// re-serializing the body, so its overlay is byte-identical to
// `unspent/byAddress`: same `pool_unspent_for_tree` filter on pool
// outputs, same `Segment.scala:265` confirmed filter, same DESC/ASC
// merge order, same `[inherited]` paging quirk. These tests pin the
// strictly-orthogonal flag matrix at the byErgoTree wire.

// `includeUnconfirmed=true` appends matching pool outputs as
// `IndexedErgoBox(0, None, None, None, _, 0)` — the `inclusionHeight=0`
// sentinel is the unique discriminator from confirmed boxes (heights ≥ 1).
#[tokio::test]
async fn unspent_overlay_include_unconfirmed_appends_matching_pool_output() {
    let pubkey = [0x41u8; 33];
    let tree_hex = p2pk_tree_hex(pubkey);
    let pool_box = make_pool_box(pubkey, 7_000_000, 0xAA);
    let mempool: Arc<dyn MempoolView> = Arc::new(StubMempoolView::with_outputs(vec![pool_box]));
    let app = build_app_with_mempool(Arc::new(StubIndexer::caught_up()), mempool);
    let (status, body) = json_post(
        app,
        "/blockchain/box/unspent/byErgoTree?includeUnconfirmed=true",
        &json_str(&tree_hex),
    )
    .await;
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
}

// Pool outputs whose canonical `tree_hash` doesn't match the queried
// ergotree are excluded — overlay is per-tree, not "show me the pool".
#[tokio::test]
async fn unspent_overlay_pool_output_for_other_tree_excluded() {
    let queried = [0x42u8; 33];
    let queried_hex = p2pk_tree_hex(queried);
    let other = [0x43u8; 33];
    let pool_box_other = make_pool_box(other, 1_234_567, 0xAB);
    let mempool: Arc<dyn MempoolView> =
        Arc::new(StubMempoolView::with_outputs(vec![pool_box_other]));
    let app = build_app_with_mempool(Arc::new(StubIndexer::caught_up()), mempool);
    let (status, body) = json_post(
        app,
        "/blockchain/box/unspent/byErgoTree?includeUnconfirmed=true",
        &json_str(&queried_hex),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.as_array().expect("bare JSON array").is_empty());
}

// `excludeMempoolSpent=true` filters confirmed unspent rows whose
// box_id is in `mempool.spentInputs` per `Segment.scala:265`. Mirrors
// slice 4 byAddress test of the same name.
#[tokio::test]
async fn unspent_overlay_exclude_mempool_spent_drops_confirmed_box() {
    let pubkey = [0x44u8; 33];
    let (tree_hex, tree_hash) = p2pk_tree_hex_and_hash(pubkey);
    let confirmed = vec![
        fixture_box(pubkey, 700_010, 1_000, 11),
        fixture_box(pubkey, 700_011, 2_000, 12),
    ];
    let confirmed_ids: Vec<BoxId> = confirmed
        .iter()
        .map(|b| b.box_data.box_id().expect("box_id"))
        .collect();
    let stub_idx = StubIndexer::caught_up().with_addr_unspent(tree_hash, confirmed);
    let mempool: Arc<dyn MempoolView> =
        Arc::new(StubMempoolView::with_outputs(Vec::new()).with_spent(vec![confirmed_ids[0]]));
    let app = build_app_with_mempool(Arc::new(stub_idx), mempool);
    let (status, body) = json_post(
        app,
        "/blockchain/box/unspent/byErgoTree?excludeMempoolSpent=true",
        &json_str(&tree_hex),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let arr = body.as_array().expect("bare JSON array");
    assert_eq!(arr.len(), 1, "one survivor (the unspent-by-pool box)");
    assert_eq!(arr[0]["globalIndex"], 12);
}

// `excludeMempoolSpent=true` also filters chained pool spends from the
// unconfirmed extension (`Segment.scala:268`). Two pool outputs match
// the queried tree; the first is in the spent set.
#[tokio::test]
async fn unspent_overlay_exclude_mempool_spent_drops_chained_pool_output() {
    let pubkey = [0x45u8; 33];
    let tree_hex = p2pk_tree_hex(pubkey);
    let pool_a = make_pool_box(pubkey, 10_000, 0xC0);
    let pool_b = make_pool_box(pubkey, 20_000, 0xC1);
    let pool_a_id = pool_a.box_id().expect("box_id");
    let mempool: Arc<dyn MempoolView> =
        Arc::new(StubMempoolView::with_outputs(vec![pool_a, pool_b]).with_spent(vec![pool_a_id]));
    let app = build_app_with_mempool(Arc::new(StubIndexer::caught_up()), mempool);
    let (status, body) = json_post(
        app,
        "/blockchain/box/unspent/byErgoTree?includeUnconfirmed=true&excludeMempoolSpent=true",
        &json_str(&tree_hex),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let arr = body.as_array().expect("bare JSON array");
    assert_eq!(arr.len(), 1, "chained pool spend filtered out");
    assert_eq!(arr[0]["value"], 20_000);
    assert_eq!(arr[0]["inclusionHeight"], 0);
}

// `Segment.scala:269-272` ASC branch: confirmed first, unconfirmed
// last. Default DESC is covered by the merged-paging test below.
#[tokio::test]
async fn unspent_overlay_asc_places_confirmed_first() {
    let pubkey = [0x47u8; 33];
    let (tree_hex, tree_hash) = p2pk_tree_hex_and_hash(pubkey);
    let confirmed = vec![
        fixture_box(pubkey, 700_030, 1_000, 31),
        fixture_box(pubkey, 700_031, 2_000, 32),
    ];
    let pool_box = make_pool_box(pubkey, 999_999, 0xD2);
    let stub_idx = StubIndexer::caught_up().with_addr_unspent(tree_hash, confirmed);
    let mempool: Arc<dyn MempoolView> = Arc::new(StubMempoolView::with_outputs(vec![pool_box]));
    let app = build_app_with_mempool(Arc::new(stub_idx), mempool);
    let (status, body) = json_post(
        app,
        "/blockchain/box/unspent/byErgoTree?includeUnconfirmed=true&sortDirection=asc",
        &json_str(&tree_hex),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let arr = body.as_array().expect("bare JSON array");
    assert_eq!(arr.len(), 3);
    assert_eq!(arr[0]["globalIndex"], 31);
    assert_eq!(arr[1]["globalIndex"], 32);
    assert_eq!(arr[2]["inclusionHeight"], 0, "unconfirmed last under ASC");
}

// `[inherited]` paging quirk: confirmed slicing
// happens at the indexer before the unconfirmed merge, so when
// `includeUnconfirmed=true` the response can exceed `limit`.
#[tokio::test]
async fn unspent_overlay_response_can_exceed_limit_when_include_unconfirmed() {
    let pubkey = [0x48u8; 33];
    let (tree_hex, tree_hash) = p2pk_tree_hex_and_hash(pubkey);
    let confirmed = vec![
        fixture_box(pubkey, 700_040, 1_000, 41),
        fixture_box(pubkey, 700_041, 2_000, 42),
    ];
    let pool_box = make_pool_box(pubkey, 999_999, 0xD3);
    let stub_idx = StubIndexer::caught_up().with_addr_unspent(tree_hash, confirmed);
    let mempool: Arc<dyn MempoolView> = Arc::new(StubMempoolView::with_outputs(vec![pool_box]));
    let app = build_app_with_mempool(Arc::new(stub_idx), mempool);
    let (status, body) = json_post(
        app,
        "/blockchain/box/unspent/byErgoTree?limit=1&includeUnconfirmed=true",
        &json_str(&tree_hex),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let arr = body.as_array().expect("bare JSON array");
    // 1 paged confirmed + 1 unpaged pool output = 2; documented quirk.
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0]["inclusionHeight"], 0, "DESC: unconfirmed first");
}

// Both flags off: no pool outputs surfaced, no confirmed filtering —
// pure indexer pass-through, identical to the pre-P5 success path.
// Locks the orthogonality contract from the off side.
#[tokio::test]
async fn unspent_overlay_both_flags_off_skips_pool_entirely() {
    let pubkey = [0x49u8; 33];
    let (tree_hex, tree_hash) = p2pk_tree_hex_and_hash(pubkey);
    let confirmed = vec![fixture_box(pubkey, 700_050, 1_000, 51)];
    let pool_box = make_pool_box(pubkey, 999_999, 0xD4);
    let stub_idx = StubIndexer::caught_up().with_addr_unspent(tree_hash, confirmed);
    let mempool: Arc<dyn MempoolView> = Arc::new(StubMempoolView::with_outputs(vec![pool_box]));
    let app = build_app_with_mempool(Arc::new(stub_idx), mempool);
    let (status, body) = json_post(
        app,
        "/blockchain/box/unspent/byErgoTree",
        &json_str(&tree_hex),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let arr = body.as_array().expect("bare JSON array");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["globalIndex"], 51, "confirmed only");
}

// Validation order: paging fires before tree decoding, so a request
// with both bad paging and bad hex still surfaces the paging envelope.
#[tokio::test]
async fn paging_error_wins_over_tree_decode() {
    let app = build_app(Arc::new(StubIndexer::caught_up()));
    let (status, body) = json_post(
        app,
        "/blockchain/box/byErgoTree?offset=-7",
        "\"not-hex!!!\"",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["reason"], "bad-request");
    assert_eq!(body["detail"], "offset is negative");
}

// ---------------- 200 success: dispatch into address-keyed methods --------

#[tokio::test]
async fn post_by_ergo_tree_200_dispatches_to_address_methods() {
    let pubkey = [0x42u8; 33];
    let (tree_hex, tree_hash) = p2pk_tree_hex_and_hash(pubkey);
    let box_data = fixture_box(pubkey, 700_010, 5_000_000, 42);
    // The stub records boxes against the address tree_hash. If the
    // route's hex→hash pipeline matches the indexer's blake2b256 keying,
    // this lookup succeeds.
    let stub = StubIndexer::caught_up().with_addr_boxes(tree_hash, vec![box_data], 17);
    let app = build_app(Arc::new(stub));
    let (status, body) = json_post(app, "/blockchain/box/byErgoTree", &json_str(&tree_hex)).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let items = body["items"].as_array().expect("{items, total} envelope");
    assert_eq!(items.len(), 1);
    assert_eq!(body["total"], 17);
    assert_eq!(items[0]["value"], 5_000_000_u64);
    assert_eq!(items[0]["globalIndex"], 42);
}

/// Multi-item regression for the per-page reverse landed in 447519c.
/// Mirrors `BlockchainApiRoute::getBoxesByErgoTree`'s `.reverse` —
/// fetch DESC, reverse the resulting Seq, so items[].globalIndex is
/// ASC within the page. A future refactor that drops or misplaces
/// the reverse on this handler flips the assertion.
#[tokio::test]
async fn post_boxes_by_ergo_tree_200_reverses_page_to_ascending() {
    let pubkey = [0x43u8; 33];
    let (tree_hex, tree_hash) = p2pk_tree_hex_and_hash(pubkey);
    let boxes_desc = vec![
        fixture_box(pubkey, 700_005, 5_000, 205),
        fixture_box(pubkey, 700_004, 5_000, 204),
        fixture_box(pubkey, 700_003, 5_000, 203),
        fixture_box(pubkey, 700_002, 5_000, 202),
        fixture_box(pubkey, 700_001, 5_000, 201),
    ];
    let stub = StubIndexer::caught_up().with_addr_boxes(tree_hash, boxes_desc.clone(), 100);
    let app = build_app(Arc::new(stub));
    let (status, body) = json_post(
        app,
        "/blockchain/box/byErgoTree?offset=0&limit=5",
        &json_str(&tree_hex),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let order: Vec<i64> = body["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["globalIndex"].as_i64().unwrap())
        .collect();
    assert_eq!(
        order,
        vec![201, 202, 203, 204, 205],
        "items must be ASC within page after .reverse on DESC fetch"
    );

    // offset > 0 sanity: [2..4] = [203, 202] → reverse → [202, 203].
    let stub2 = StubIndexer::caught_up().with_addr_boxes(tree_hash, boxes_desc, 100);
    let app2 = build_app(Arc::new(stub2));
    let (status2, body2) = json_post(
        app2,
        "/blockchain/box/byErgoTree?offset=2&limit=2",
        &json_str(&tree_hex),
    )
    .await;
    assert_eq!(status2, StatusCode::OK);
    let order2: Vec<i64> = body2["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["globalIndex"].as_i64().unwrap())
        .collect();
    assert_eq!(order2, vec![202, 203], "offset>0 stays ASC after reverse");
}

#[tokio::test]
async fn post_unspent_by_ergo_tree_200_emits_bare_array() {
    let pubkey = [0x43u8; 33];
    let (tree_hex, tree_hash) = p2pk_tree_hex_and_hash(pubkey);
    let boxes = vec![
        fixture_box(pubkey, 700_000, 1_000, 10),
        fixture_box(pubkey, 700_001, 2_000, 20),
        fixture_box(pubkey, 700_002, 3_000, 30),
    ];
    let stub = StubIndexer::caught_up().with_addr_unspent(tree_hash, boxes);
    let app = build_app(Arc::new(stub));
    let (status, body) = json_post(
        app,
        "/blockchain/box/unspent/byErgoTree",
        &json_str(&tree_hex),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let arr = body.as_array().expect("bare JSON array");
    assert_eq!(arr.len(), 3);
    // Default sortDirection is desc — globalIndex 30 first.
    assert_eq!(arr[0]["globalIndex"], 30);
    assert_eq!(arr[1]["globalIndex"], 20);
    assert_eq!(arr[2]["globalIndex"], 10);
}

// Asserts the dispatch is byte-identical: the tree_hash computed from
// the hex POST body equals what the address-keyed lookup needs.
// `with_unspent` is keyed on the address tree_hash; the request matches
// only if our blake2b256(canonical ergo-tree bytes) agrees.
#[tokio::test]
async fn unrelated_tree_hash_returns_empty() {
    // Stub records boxes against pubkey #1's tree_hash. We POST with
    // pubkey #2's hex → different tree_hash → empty array (no match).
    let stub = StubIndexer::caught_up().with_addr_unspent(
        p2pk_tree_hex_and_hash([0xAA; 33]).1,
        vec![fixture_box([0xAA; 33], 700_000, 1, 1)],
    );
    let app = build_app(Arc::new(stub));
    let (other_hex, _) = p2pk_tree_hex_and_hash([0xBB; 33]);
    let (status, body) = json_post(
        app,
        "/blockchain/box/unspent/byErgoTree",
        &json_str(&other_hex),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.as_array().unwrap().is_empty());
}

// ---------------- helpers --------------------------------------------------

fn p2pk_tree_bytes(pubkey: [u8; 33]) -> Vec<u8> {
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
    w.result()
}

fn p2pk_tree_hex(pubkey: [u8; 33]) -> String {
    hex::encode(p2pk_tree_bytes(pubkey))
}

fn p2pk_tree_hex_and_hash(pubkey: [u8; 33]) -> (String, Digest32) {
    let bytes = p2pk_tree_bytes(pubkey);
    (hex::encode(&bytes), blake2b256(&bytes))
}

fn fixture_box(pubkey: [u8; 33], height: i32, value: u64, global_index: i64) -> IndexedErgoBox {
    let bytes = p2pk_tree_bytes(pubkey);
    let mut reader = ergo_primitives::reader::VlqReader::new(&bytes);
    let tree = ergo_ser::ergo_tree::read_ergo_tree(&mut reader).unwrap();
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
            utxo_reads_supported: true,
        },
        None, // admin — tests don't exercise the shutdown endpoint
    )
}

/// Build an `ErgoBox` with the given P2PK ergo tree, value, and a
/// distinct `transaction_id` (`tx_id_byte` repeated 32x) so the box's
/// derived `box_id` is unique within a test even when value/tree match
/// another fixture. Mirrors the helper in
/// `blockchain_unspent_byaddress_routes.rs`.
fn make_pool_box(pubkey: [u8; 33], value: u64, tx_id_byte: u8) -> ErgoBox {
    let bytes = p2pk_tree_bytes(pubkey);
    let mut reader = ergo_primitives::reader::VlqReader::new(&bytes);
    let tree = ergo_ser::ergo_tree::read_ergo_tree(&mut reader).unwrap();
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
/// independently from the pool-output extension.
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

// ---------------- StubIndexer ---------------------------------------------
//
// Holds optional address-keyed boxes (for #24) and unspent boxes (for #25).
// The byErgoTree routes hash the tree first, then dispatch into the same
// `address_*_paged` reader methods used by /box/byAddress, so the stub
// records its data under the *address* tree_hash and asserts dispatch
// landed on the right key.

struct StubIndexer {
    status: IndexerStatus,
    addr_boxes: Option<(TreeHash, Vec<IndexedErgoBox>, u64)>,
    addr_unspent: Option<(TreeHash, Vec<IndexedErgoBox>)>,
}

impl StubIndexer {
    fn caught_up() -> Self {
        Self {
            status: IndexerStatus::CaughtUp,
            addr_boxes: None,
            addr_unspent: None,
        }
    }
    fn with_status(status: IndexerStatus) -> Self {
        Self {
            status,
            addr_boxes: None,
            addr_unspent: None,
        }
    }
    fn with_addr_boxes(
        mut self,
        tree_hash: TreeHash,
        boxes: Vec<IndexedErgoBox>,
        total: u64,
    ) -> Self {
        self.addr_boxes = Some((tree_hash, boxes, total));
        self
    }
    fn with_addr_unspent(mut self, tree_hash: TreeHash, boxes: Vec<IndexedErgoBox>) -> Self {
        self.addr_unspent = Some((tree_hash, boxes));
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
    fn address_boxes_paged(
        &self,
        tree_hash: &TreeHash,
        p: Page,
        _dir: SortDir,
    ) -> Vec<IndexedBoxDto> {
        match &self.addr_boxes {
            Some((h, boxes, _)) if h == tree_hash => {
                let lo = p.offset as usize;
                let hi = lo.saturating_add(p.limit as usize).min(boxes.len());
                if lo >= boxes.len() {
                    Vec::new()
                } else {
                    boxes[lo..hi].to_vec()
                }
            }
            _ => Vec::new(),
        }
    }
    fn address_unspent_paged(
        &self,
        tree_hash: &TreeHash,
        p: Page,
        dir: SortDir,
    ) -> Vec<IndexedBoxDto> {
        match &self.addr_unspent {
            Some((h, boxes)) if h == tree_hash => {
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
    fn address_total_boxes(&self, tree_hash: &TreeHash) -> u64 {
        match &self.addr_boxes {
            Some((h, _, total)) if h == tree_hash => *total,
            _ => 0,
        }
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

// ---------------- StubReadState (mirrors sibling test files) --------------

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

#[allow(dead_code)]
fn _ensure_handle_use_compiles() {
    let _ = IndexerHandle::syncing(0);
}
