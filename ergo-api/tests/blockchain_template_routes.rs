//! `GET /blockchain/box/byTemplateHash/{hash}` and
//! `GET /blockchain/box/unspent/byTemplateHash/{hash}` — template
//! routes (#15, #16).
//!
//! Pinned behavior:
//! - Path param is a 64-char hex template hash. Bad hex (length ≠ 64 or
//!   non-hex chars) returns 404 with `not_found` envelope, mirroring
//!   Scala's `path(modifierId)` rejection (Akka default 404).
//! - Wire shapes:
//!   #15 → `{items, total}` envelope (mirrors #9/#10 byAddress)
//!   #16 → bare `[IndexedErgoBox]` array (mirrors #11/#12 unspent/byAddress)
//! - Empty-fallback parity (`BlockchainApiRoute.scala:304-307,
//!   323-325`): unknown template returns 200 with `{items: [], total: 0}`
//!   for #15 and `200 []` for #16 — Scala falls back to an empty
//!   `IndexedContractTemplate(hash)` rather than 404.
//! - Validation order on #16 mirrors `/unspent/byAddress`: path → paging
//!   → sortDirection → read+overlay. Overlay flags don't gate; they
//!   alter behavior.
//! - **Mempool overlay:** `includeUnconfirmed` / `excludeMempoolSpent`
//!   are strictly orthogonal.
//!   Pool outputs are matched by `template_hash_from_bytes(tree_bytes)`
//!   (NOT `tree_hash_from_bytes`); merge order follows
//!   `Segment.scala:269-272` (DESC = unconfirmed first, ASC = confirmed
//!   first). Confirmed slicing happens at the indexer before merge — the
//!   `[inherited]` paging quirk lets responses exceed `limit` by
//!   `|pool_outputs|`.
//! - The status gate fronts both routes — `Syncing` / `Halted`
//!   short-circuits before the handler runs.

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
use ergo_indexer::IndexerHaltReason;
use ergo_indexer_types::types::IndexedErgoBox;
use ergo_indexer_types::{
    BalanceDto, BoxId, IndexedBoxDto, IndexedTokenDto, IndexedTxDto, IndexerQuery, IndexerStatus,
    Page, SortDir, TemplateHash, TokenId, TreeHash, TxId,
};
use ergo_primitives::digest::{Digest32, ModifierId};
use ergo_primitives::group_element::GroupElement;
use ergo_ser::address::NetworkPrefix;
use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::{template_hash_from_bytes, ErgoTree};
use ergo_ser::opcode::Expr;
use ergo_ser::register::AdditionalRegisters;
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::{SigmaBoolean, SigmaValue};
use http_body_util::BodyExt;
use tower::ServiceExt;

const SAMPLE_HASH_HEX: &str = "11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff";
const OTHER_HASH_HEX: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

fn sample_template_hash() -> TemplateHash {
    let mut raw = [0u8; 32];
    hex::decode_to_slice(SAMPLE_HASH_HEX, &mut raw).unwrap();
    TemplateHash::from_bytes(raw)
}

// ---------------- 503 status-gate ------------------------------------------

#[tokio::test]
async fn by_template_hash_503_indexer_syncing() {
    let app = build_app(Arc::new(StubIndexer::with_status(IndexerStatus::Syncing)));
    let (status, body) = json_get(
        app,
        &format!("/blockchain/box/byTemplateHash/{SAMPLE_HASH_HEX}"),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["reason"], "indexer-syncing");
}

#[tokio::test]
async fn unspent_by_template_hash_503_indexer_halted() {
    let app = build_app(Arc::new(StubIndexer::with_status(IndexerStatus::Halted(
        IndexerHaltReason::DbCorruption,
    ))));
    let (status, body) = json_get(
        app,
        &format!("/blockchain/box/unspent/byTemplateHash/{SAMPLE_HASH_HEX}"),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["reason"], "indexer-halted");
}

// ---------------- 404 bad-hex path param -----------------------------------

#[tokio::test]
async fn by_template_hash_404_on_short_hex() {
    let app = build_app(Arc::new(StubIndexer::caught_up()));
    // 63 chars — one short of the 64 required for a 32-byte hash.
    let bad = "11223344556677889900aabbccddeeff00112233445566778899aabbccddeef";
    let (status, body) = json_get(app, &format!("/blockchain/box/byTemplateHash/{bad}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["reason"], "not-found");
}

#[tokio::test]
async fn unspent_by_template_hash_404_on_non_hex() {
    let app = build_app(Arc::new(StubIndexer::caught_up()));
    // 64 chars but contains non-hex characters.
    let bad = "GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG";
    let (status, body) = json_get(
        app,
        &format!("/blockchain/box/unspent/byTemplateHash/{bad}"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["reason"], "not-found");
}

// ---------------- 200 empty fallback (Scala parity) ------------------------

#[tokio::test]
async fn by_template_hash_200_empty_envelope_on_unknown_hash() {
    // Scala falls back to an empty IndexedContractTemplate(hash) rather
    // than 404. We must mirror — `{items: [], total: 0}` with status 200.
    let app = build_app(Arc::new(StubIndexer::caught_up()));
    let (status, body) = json_get(
        app,
        &format!("/blockchain/box/byTemplateHash/{OTHER_HASH_HEX}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["total"], 0);
    assert!(body["items"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn unspent_by_template_hash_200_empty_array_on_unknown_hash() {
    // Same parity: unknown template → 200 [] (NOT 404).
    let app = build_app(Arc::new(StubIndexer::caught_up()));
    let (status, body) = json_get(
        app,
        &format!("/blockchain/box/unspent/byTemplateHash/{OTHER_HASH_HEX}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.as_array().unwrap().is_empty());
}

// ---------------- 200 happy path -------------------------------------------

#[tokio::test]
async fn by_template_hash_200_returns_paged_items_and_total() {
    let template_hash = sample_template_hash();
    let stub = StubIndexer::caught_up().with_template_boxes(
        template_hash,
        vec![
            fixture_box([0xAA; 33], 700_000, 1, 10),
            fixture_box([0xAA; 33], 700_001, 2, 11),
            fixture_box([0xAA; 33], 700_002, 3, 12),
        ],
        7, // total > items.len() to verify total flows through independently
    );
    let app = build_app(Arc::new(stub));
    let (status, body) = json_get(
        app,
        &format!("/blockchain/box/byTemplateHash/{SAMPLE_HASH_HEX}?offset=0&limit=10"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["total"], 7);
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 3);
    assert_eq!(items[0]["globalIndex"], 10);
    assert_eq!(items[2]["globalIndex"], 12);
}

#[tokio::test]
async fn unspent_by_template_hash_200_returns_bare_array() {
    let template_hash = sample_template_hash();
    let stub = StubIndexer::caught_up().with_template_unspent(
        template_hash,
        vec![
            fixture_box([0xAA; 33], 700_000, 1, 100),
            fixture_box([0xAA; 33], 700_001, 2, 101),
        ],
    );
    let app = build_app(Arc::new(stub));
    let (status, body) = json_get(
        app,
        &format!("/blockchain/box/unspent/byTemplateHash/{SAMPLE_HASH_HEX}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let arr = body.as_array().unwrap();
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0]["globalIndex"], 101); // default Desc → newest first
    assert_eq!(arr[1]["globalIndex"], 100);
}

#[tokio::test]
async fn unspent_by_template_hash_sort_direction_asc_is_oldest_first() {
    let template_hash = sample_template_hash();
    let stub = StubIndexer::caught_up().with_template_unspent(
        template_hash,
        vec![
            fixture_box([0xAA; 33], 700_000, 1, 200),
            fixture_box([0xAA; 33], 700_001, 2, 201),
            fixture_box([0xAA; 33], 700_002, 3, 202),
        ],
    );
    let app = build_app(Arc::new(stub));
    let (status, body) = json_get(
        app,
        &format!("/blockchain/box/unspent/byTemplateHash/{SAMPLE_HASH_HEX}?sortDirection=asc"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let arr = body.as_array().unwrap();
    assert_eq!(arr.len(), 3);
    assert_eq!(arr[0]["globalIndex"], 200);
    assert_eq!(arr[2]["globalIndex"], 202);
}

// ---------------- 400 paging -----------------------------------------------

#[tokio::test]
async fn by_template_hash_400_on_limit_above_max() {
    let app = build_app(Arc::new(StubIndexer::caught_up()));
    let (status, body) = json_get(
        app,
        &format!("/blockchain/box/byTemplateHash/{SAMPLE_HASH_HEX}?limit=99999"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["reason"], "bad-request");
    assert!(
        body["detail"].as_str().unwrap().contains("16384"),
        "detail should cite MaxItems literal: {body}"
    );
}

#[tokio::test]
async fn unspent_by_template_hash_400_on_negative_offset() {
    let app = build_app(Arc::new(StubIndexer::caught_up()));
    let (status, body) = json_get(
        app,
        &format!("/blockchain/box/unspent/byTemplateHash/{SAMPLE_HASH_HEX}?offset=-1"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["reason"], "bad-request");
}

// ---------------- 400 sort direction (#16 only) ----------------------------

#[tokio::test]
async fn unspent_by_template_hash_400_on_invalid_sort_direction() {
    let app = build_app(Arc::new(StubIndexer::caught_up()));
    let (status, body) = json_get(
        app,
        &format!("/blockchain/box/unspent/byTemplateHash/{SAMPLE_HASH_HEX}?sortDirection=sideways"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["detail"]
            .as_str()
            .unwrap()
            .contains("Invalid parameter for sort direction"),
        "detail should match Scala literal: {body}"
    );
}

// ---------------- Overlay: includeUnconfirmed ------------------------------

// Pool output whose tree hashes to the queried template_hash is appended
// to the response and shaped as the pool-output sentinel:
// `inclusionHeight = 0`
// (mempool sentinel — confirmed boxes always have height ≥ 1),
// `globalIndex = 0`, all spending fields null. Mirrors the
// `unspent/byAddress` overlay test, but keys on template hash.
#[tokio::test]
async fn unspent_overlay_include_unconfirmed_appends_matching_pool_output() {
    let pubkey = [0x51u8; 33];
    let template_hash = p2pk_template_hash(pubkey);
    let pool_box = make_pool_box(pubkey, 7_000_000, 0xAA);
    let mempool: Arc<dyn MempoolView> = Arc::new(StubMempoolView::with_outputs(vec![pool_box]));
    let app = build_app_with_mempool(Arc::new(StubIndexer::caught_up()), mempool);
    let path = format!(
        "/blockchain/box/unspent/byTemplateHash/{}?includeUnconfirmed=true",
        hex::encode(template_hash.as_bytes())
    );
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
}

// Pool output whose tree hashes to a *different* template_hash must be
// filtered out — overlay is per-template, not "show me everything in the
// pool". A queried template that no pool output matches yields 200 [].
#[tokio::test]
async fn unspent_overlay_pool_output_for_other_template_excluded() {
    let queried = [0x52u8; 33];
    let queried_template = p2pk_template_hash(queried);
    let other = [0x53u8; 33];
    let pool_box_other = make_pool_box(other, 1_234_567, 0xAB);
    // Sanity: same body shape (P2PK) → same template hash because
    // template hash is over the body excluding constants. Skip the
    // assertion if templates collide for the chosen pubkeys, since the
    // discriminator at template-level is the body skeleton, not the
    // pubkey constant. Concretely: P2PK trees with no constant
    // segregation embed the GroupElement inline; the template body
    // *does* include the inline constant. So distinct pubkeys → distinct
    // template bytes → distinct hashes.
    assert_ne!(
        queried_template,
        p2pk_template_hash(other),
        "test fixture relies on distinct pubkeys yielding distinct template hashes",
    );
    let mempool: Arc<dyn MempoolView> =
        Arc::new(StubMempoolView::with_outputs(vec![pool_box_other]));
    let app = build_app_with_mempool(Arc::new(StubIndexer::caught_up()), mempool);
    let path = format!(
        "/blockchain/box/unspent/byTemplateHash/{}?includeUnconfirmed=true",
        hex::encode(queried_template.as_bytes())
    );
    let (status, body) = json_get(app, &path).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.as_array().expect("bare JSON array").is_empty());
}

// ---------------- P5 overlay: excludeMempoolSpent -------------------------

// `excludeMempoolSpent=true` drops confirmed unspent rows whose box_id
// is in `mempool.spentInputs` per `Segment.scala:265`. Stub records two
// confirmed boxes for the queried template; the spent-set covers one —
// only the survivor remains. No pool-output extension is supplied by
// the mempool stub here, so the result is exactly the survivor.
#[tokio::test]
async fn unspent_overlay_exclude_mempool_spent_drops_confirmed_box() {
    let pubkey = [0x54u8; 33];
    let template_hash = p2pk_template_hash(pubkey);
    let confirmed = vec![
        fixture_box(pubkey, 700_010, 1_000, 11),
        fixture_box(pubkey, 700_011, 2_000, 12),
    ];
    let confirmed_ids: Vec<BoxId> = confirmed
        .iter()
        .map(|b| b.box_data.box_id().expect("box_id"))
        .collect();
    let stub_idx = StubIndexer::caught_up().with_template_unspent(template_hash, confirmed);
    let mempool: Arc<dyn MempoolView> =
        Arc::new(StubMempoolView::with_outputs(Vec::new()).with_spent(vec![confirmed_ids[0]]));
    let app = build_app_with_mempool(Arc::new(stub_idx), mempool);
    let path = format!(
        "/blockchain/box/unspent/byTemplateHash/{}?excludeMempoolSpent=true",
        hex::encode(template_hash.as_bytes())
    );
    let (status, body) = json_get(app, &path).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let arr = body.as_array().expect("bare JSON array");
    assert_eq!(arr.len(), 1, "one survivor (the unspent-by-pool box)");
    assert_eq!(arr[0]["globalIndex"], 12);
}

// `Segment.scala:268`: chained pool spends (one pool tx outputs to a
// template, another pool tx consumes that output) must not appear in the
// unconfirmed slice when `excludeMempoolSpent=true`. Two pool outputs
// match the queried template; the first id is in the spent set, only
// the second surfaces.
#[tokio::test]
async fn unspent_overlay_exclude_mempool_spent_drops_chained_pool_output() {
    let pubkey = [0x55u8; 33];
    let template_hash = p2pk_template_hash(pubkey);
    let pool_a = make_pool_box(pubkey, 10_000, 0xC0);
    let pool_b = make_pool_box(pubkey, 20_000, 0xC1);
    let pool_a_id = pool_a.box_id().expect("box_id");
    let mempool: Arc<dyn MempoolView> =
        Arc::new(StubMempoolView::with_outputs(vec![pool_a, pool_b]).with_spent(vec![pool_a_id]));
    let app = build_app_with_mempool(Arc::new(StubIndexer::caught_up()), mempool);
    let path = format!(
        "/blockchain/box/unspent/byTemplateHash/{}?includeUnconfirmed=true&excludeMempoolSpent=true",
        hex::encode(template_hash.as_bytes())
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
// One pool output prepended to the desc-sorted confirmed slice.
#[tokio::test]
async fn unspent_overlay_default_desc_places_unconfirmed_first() {
    let pubkey = [0x56u8; 33];
    let template_hash = p2pk_template_hash(pubkey);
    let confirmed = vec![
        fixture_box(pubkey, 700_020, 1_000, 21),
        fixture_box(pubkey, 700_021, 2_000, 22),
    ];
    let pool_box = make_pool_box(pubkey, 999_999, 0xD1);
    let stub_idx = StubIndexer::caught_up().with_template_unspent(template_hash, confirmed);
    let mempool: Arc<dyn MempoolView> = Arc::new(StubMempoolView::with_outputs(vec![pool_box]));
    let app = build_app_with_mempool(Arc::new(stub_idx), mempool);
    let path = format!(
        "/blockchain/box/unspent/byTemplateHash/{}?includeUnconfirmed=true",
        hex::encode(template_hash.as_bytes())
    );
    let (status, body) = json_get(app, &path).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let arr = body.as_array().expect("bare JSON array");
    assert_eq!(arr.len(), 3);
    assert_eq!(arr[0]["inclusionHeight"], 0, "unconfirmed first under DESC");
    assert_eq!(arr[1]["globalIndex"], 22);
    assert_eq!(arr[2]["globalIndex"], 21);
}

// ASC branch: `confirmedBoxes ++ unconfirmedBoxes`.
#[tokio::test]
async fn unspent_overlay_asc_places_confirmed_first() {
    let pubkey = [0x57u8; 33];
    let template_hash = p2pk_template_hash(pubkey);
    let confirmed = vec![
        fixture_box(pubkey, 700_030, 1_000, 31),
        fixture_box(pubkey, 700_031, 2_000, 32),
    ];
    let pool_box = make_pool_box(pubkey, 999_999, 0xD2);
    let stub_idx = StubIndexer::caught_up().with_template_unspent(template_hash, confirmed);
    let mempool: Arc<dyn MempoolView> = Arc::new(StubMempoolView::with_outputs(vec![pool_box]));
    let app = build_app_with_mempool(Arc::new(stub_idx), mempool);
    let path = format!(
        "/blockchain/box/unspent/byTemplateHash/{}?includeUnconfirmed=true&sortDirection=asc",
        hex::encode(template_hash.as_bytes())
    );
    let (status, body) = json_get(app, &path).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let arr = body.as_array().expect("bare JSON array");
    assert_eq!(arr.len(), 3);
    assert_eq!(arr[0]["globalIndex"], 31);
    assert_eq!(arr[1]["globalIndex"], 32);
    assert_eq!(arr[2]["inclusionHeight"], 0, "unconfirmed last under ASC");
}

// `[inherited]` paging quirk: confirmed slicing happens at the indexer
// before the unconfirmed merge — `includeUnconfirmed=true` responses can
// exceed `limit` by `|pool_outputs|`. Concretely: limit=1 + 1 confirmed
// + 1 pool output → 2 items, not 1.
#[tokio::test]
async fn unspent_overlay_response_can_exceed_limit_when_include_unconfirmed() {
    let pubkey = [0x58u8; 33];
    let template_hash = p2pk_template_hash(pubkey);
    let confirmed = vec![
        fixture_box(pubkey, 700_040, 1_000, 41),
        fixture_box(pubkey, 700_041, 2_000, 42),
    ];
    let pool_box = make_pool_box(pubkey, 999_999, 0xD3);
    let stub_idx = StubIndexer::caught_up().with_template_unspent(template_hash, confirmed);
    let mempool: Arc<dyn MempoolView> = Arc::new(StubMempoolView::with_outputs(vec![pool_box]));
    let app = build_app_with_mempool(Arc::new(stub_idx), mempool);
    let path = format!(
        "/blockchain/box/unspent/byTemplateHash/{}?limit=1&includeUnconfirmed=true",
        hex::encode(template_hash.as_bytes())
    );
    let (status, body) = json_get(app, &path).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let arr = body.as_array().expect("bare JSON array");
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0]["inclusionHeight"], 0, "DESC: unconfirmed first");
}

// ---------------- validation order: paging > sort > overlay ----------------

// Overlay flags don't gate; they alter behavior. A request with both
// flags set + invalid sort + over-limit still surfaces the limit error
// first because that's the cheapest gate.
#[tokio::test]
async fn paging_error_wins_over_sort_and_overlay_flags() {
    let app = build_app(Arc::new(StubIndexer::caught_up()));
    let (status, body) = json_get(
        app,
        &format!(
            "/blockchain/box/unspent/byTemplateHash/{SAMPLE_HASH_HEX}\
             ?limit=99999&sortDirection=sideways&includeUnconfirmed=true&excludeMempoolSpent=true"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["detail"], "No more than 16384 boxes can be requested");
}

// ---------------- helpers --------------------------------------------------

fn p2pk_tree(pubkey: [u8; 33]) -> ErgoTree {
    ErgoTree {
        version: 0,
        has_size: false,
        constant_segregation: false,
        constants: Vec::new(),
        body: Expr::Const {
            tpe: SigmaType::SSigmaProp,
            val: SigmaValue::SigmaProp(SigmaBoolean::ProveDlog(GroupElement::from_bytes(pubkey))),
        },
    }
}

fn fixture_box(pubkey: [u8; 33], height: i32, value: u64, global_index: i64) -> IndexedErgoBox {
    let candidate = ErgoBoxCandidate::new(
        value,
        p2pk_tree(pubkey),
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
            emission_scripts: None,
            utxo_reads_supported: true,
        },
        None, // admin — tests don't exercise the shutdown endpoint
    )
}

/// Compute the template hash of the canonical p2pk tree for `pubkey`.
/// Mirrors what `pool_unspent_for_template` does at handler time so the
/// pool-output match is exact.
fn p2pk_template_hash(pubkey: [u8; 33]) -> TemplateHash {
    let tree = p2pk_tree(pubkey);
    let candidate = ErgoBoxCandidate::new(1, tree, 0, Vec::new(), AdditionalRegisters::empty())
        .expect("ErgoBoxCandidate::new");
    let raw =
        template_hash_from_bytes(candidate.ergo_tree_bytes()).expect("template_hash_from_bytes");
    TemplateHash::from_bytes(raw)
}

/// Build a P2PK `ErgoBox` (no global_index / inclusion_height — those
/// only exist on the wrapping `IndexedErgoBox`). `tx_id_byte` makes the
/// derived `box_id` distinct across fixtures even when value/tree match.
fn make_pool_box(pubkey: [u8; 33], value: u64, tx_id_byte: u8) -> ErgoBox {
    let candidate = ErgoBoxCandidate::new(
        value,
        p2pk_tree(pubkey),
        0,
        Vec::new(),
        AdditionalRegisters::empty(),
    )
    .expect("ErgoBoxCandidate::new");
    ErgoBox {
        candidate,
        transaction_id: ModifierId::from_bytes([tx_id_byte; 32]),
        index: 0,
    }
}

/// Stub `MempoolView`: a fixed pool-output set + an explicit `spent`
/// set so tests can drive `is_spent_by_pool` independently from the
/// pool-output extension. No `pool_spending_tx` caller in the unspent
/// path, so that method returns `None`.
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
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(path)
                .body(Body::empty())
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
// Holds optional template-keyed boxes (for #15) and unspent boxes (for #16),
// keyed by `TemplateHash`. The handler matches on the template_hash; only
// the recorded hash dispatches into the data — other hashes get the
// empty-fallback path.

struct StubIndexer {
    status: IndexerStatus,
    tmpl_boxes: Option<(TemplateHash, Vec<IndexedErgoBox>, u64)>,
    tmpl_unspent: Option<(TemplateHash, Vec<IndexedErgoBox>)>,
}

impl StubIndexer {
    fn caught_up() -> Self {
        Self {
            status: IndexerStatus::CaughtUp,
            tmpl_boxes: None,
            tmpl_unspent: None,
        }
    }
    fn with_status(status: IndexerStatus) -> Self {
        Self {
            status,
            tmpl_boxes: None,
            tmpl_unspent: None,
        }
    }
    fn with_template_boxes(
        mut self,
        h: TemplateHash,
        boxes: Vec<IndexedErgoBox>,
        total: u64,
    ) -> Self {
        self.tmpl_boxes = Some((h, boxes, total));
        self
    }
    fn with_template_unspent(mut self, h: TemplateHash, boxes: Vec<IndexedErgoBox>) -> Self {
        self.tmpl_unspent = Some((h, boxes));
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
    fn address_unspent_paged(&self, _: &TreeHash, _: Page, _: SortDir) -> Vec<IndexedBoxDto> {
        Vec::new()
    }
    fn address_total_txs(&self, _: &TreeHash) -> u64 {
        0
    }
    fn address_total_boxes(&self, _: &TreeHash) -> u64 {
        0
    }

    fn template_boxes_paged(&self, h: &TemplateHash, p: Page) -> Vec<IndexedBoxDto> {
        match &self.tmpl_boxes {
            Some((stored, boxes, _)) if stored == h => {
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
    fn template_unspent_paged(
        &self,
        h: &TemplateHash,
        p: Page,
        dir: SortDir,
    ) -> Vec<IndexedBoxDto> {
        match &self.tmpl_unspent {
            Some((stored, boxes)) if stored == h => {
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
    fn template_total_boxes(&self, h: &TemplateHash) -> u64 {
        match &self.tmpl_boxes {
            Some((stored, _, total)) if stored == h => *total,
            _ => 0,
        }
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
            last_block_apply_error: None,
            block_apply_errors_total: 0,
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

// `Digest32` import only used through TemplateHash alias — silence unused warning.
const _: Option<Digest32> = None;
