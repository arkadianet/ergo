//! `GET /blockchain/token/byId/{tokenId}`,
//! `POST /blockchain/tokens`,
//! `GET /blockchain/box/byTokenId/{tokenId}`, and
//! `GET /blockchain/box/unspent/byTokenId/{tokenId}` — token routes
//! (#17, #18, #19, #20).
//!
//! Pinned behavior:
//! - Path param is a 64-char hex tokenId (32 bytes). Bad hex (length ≠
//!   64 or non-hex chars) returns 404 with `not_found` envelope on
//!   #17/#19/#20, mirroring Scala's `path(modifierId)` rejection.
//! - Wire shapes:
//!   #17 → `IndexedToken` object (id/boxId/emissionAmount/name/description/decimals)
//!   #18 → bare `[IndexedToken]` array; misses dropped (Scala flatMap)
//!   #19 → `{items, total}` envelope
//!   #20 → bare `[IndexedErgoBox]` array
//! - Empty-fallback parity (`BlockchainApiRoute.scala`):
//!   - #17 unknown token → 404 (Scala `IndexedToken.getById` returns
//!     None and the route surfaces 404).
//!   - #18 with unknown ids → 200 with the misses dropped (per
//!     `flatMap`); empty body returns 200 [].
//!   - #19 unknown token → 200 `{items: [], total: 0}` (Scala falls
//!     back to empty box list rather than 404).
//!   - #20 unknown token → 200 [] for the same reason.
//! - Validation order on #20 mirrors `/unspent/byAddress`: path → paging
//!   → sortDirection → read+overlay. Overlay flags don't gate; they
//!   alter behavior.
//! - **Mempool overlay:** `includeUnconfirmed` / `excludeMempoolSpent`
//!   are strictly orthogonal.
//!   Pool outputs are matched by token-id membership in
//!   `box.candidate.tokens`; merge order follows
//!   `Segment.scala:269-272` (DESC = unconfirmed first, ASC = confirmed
//!   first). Confirmed slicing happens at the indexer before merge —
//!   the `[inherited]` paging quirk lets responses exceed `limit` by
//!   `|pool_outputs|`.
//! - The status gate fronts all four routes — `Syncing` / `Halted`
//!   short-circuits before the handler runs.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
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
use ergo_primitives::digest::ModifierId;
use ergo_primitives::group_element::GroupElement;
use ergo_ser::address::NetworkPrefix;
use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::ErgoTree;
use ergo_ser::opcode::Expr;
use ergo_ser::register::AdditionalRegisters;
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::{SigmaBoolean, SigmaValue};
use ergo_ser::token::Token;
use http_body_util::BodyExt;
use tower::ServiceExt;

const SAMPLE_TOKEN_HEX: &str = "11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff";
const OTHER_TOKEN_HEX: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
const SAMPLE_BOX_HEX: &str = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";

fn sample_token_id() -> TokenId {
    let mut raw = [0u8; 32];
    hex::decode_to_slice(SAMPLE_TOKEN_HEX, &mut raw).unwrap();
    TokenId::from_bytes(raw)
}

fn sample_box_id() -> BoxId {
    let mut raw = [0u8; 32];
    hex::decode_to_slice(SAMPLE_BOX_HEX, &mut raw).unwrap();
    BoxId::from_bytes(raw)
}

fn sample_token_dto() -> IndexedTokenDto {
    IndexedTokenDto {
        token_id: sample_token_id(),
        creating_box_id: sample_box_id(),
        emission_amount: 3_500_000,
        name: "TKN".into(),
        description: "test token".into(),
        decimals: 8,
    }
}

// ---------------- 503 status-gate ------------------------------------------

#[tokio::test]
async fn token_by_id_503_indexer_syncing() {
    let app = build_app(Arc::new(StubIndexer::with_status(IndexerStatus::Syncing)));
    let (status, body) = json_get(app, &format!("/blockchain/token/byId/{SAMPLE_TOKEN_HEX}")).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["reason"], "indexer-syncing");
}

#[tokio::test]
async fn tokens_post_503_indexer_halted() {
    let app = build_app(Arc::new(StubIndexer::with_status(IndexerStatus::Halted(
        IndexerHaltReason::DbCorruption,
    ))));
    let body_json = serde_json::to_vec(&vec![SAMPLE_TOKEN_HEX]).unwrap();
    let (status, body) = json_post(app, "/blockchain/tokens", body_json).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["reason"], "indexer-halted");
}

#[tokio::test]
async fn boxes_by_token_id_503_indexer_syncing() {
    let app = build_app(Arc::new(StubIndexer::with_status(IndexerStatus::Syncing)));
    let (status, body) = json_get(
        app,
        &format!("/blockchain/box/byTokenId/{SAMPLE_TOKEN_HEX}"),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["reason"], "indexer-syncing");
}

#[tokio::test]
async fn unspent_by_token_id_503_indexer_halted() {
    let app = build_app(Arc::new(StubIndexer::with_status(IndexerStatus::Halted(
        IndexerHaltReason::DbCorruption,
    ))));
    let (status, body) = json_get(
        app,
        &format!("/blockchain/box/unspent/byTokenId/{SAMPLE_TOKEN_HEX}"),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["reason"], "indexer-halted");
}

// ---------------- 404 bad-hex path param -----------------------------------

#[tokio::test]
async fn token_by_id_404_on_short_hex() {
    let app = build_app(Arc::new(StubIndexer::caught_up()));
    let bad = "11223344556677889900aabbccddeeff00112233445566778899aabbccddeef";
    let (status, body) = json_get(app, &format!("/blockchain/token/byId/{bad}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["reason"], "not-found");
}

#[tokio::test]
async fn boxes_by_token_id_404_on_non_hex() {
    let app = build_app(Arc::new(StubIndexer::caught_up()));
    let bad = "GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG";
    let (status, body) = json_get(app, &format!("/blockchain/box/byTokenId/{bad}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["reason"], "not-found");
}

#[tokio::test]
async fn unspent_by_token_id_404_on_short_hex() {
    let app = build_app(Arc::new(StubIndexer::caught_up()));
    let bad = "00";
    let (status, body) = json_get(app, &format!("/blockchain/box/unspent/byTokenId/{bad}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["reason"], "not-found");
}

// ---------------- #17 byId hit / miss ---------------------------------------

#[tokio::test]
async fn token_by_id_200_returns_indexed_token_object() {
    let stub = StubIndexer::caught_up().with_token(sample_token_dto());
    let app = build_app(Arc::new(stub));
    let (status, body) = json_get(app, &format!("/blockchain/token/byId/{SAMPLE_TOKEN_HEX}")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["id"], SAMPLE_TOKEN_HEX);
    assert_eq!(body["boxId"], SAMPLE_BOX_HEX);
    assert_eq!(body["emissionAmount"], 3_500_000);
    assert_eq!(body["name"], "TKN");
    assert_eq!(body["description"], "test token");
    assert_eq!(body["decimals"], 8);
}

#[tokio::test]
async fn token_by_id_404_on_unknown_token() {
    // Unlike the byTokenId routes, #17 is 404 on miss (Scala
    // `IndexedToken.getById` returns `None` → 404).
    let app = build_app(Arc::new(StubIndexer::caught_up()));
    let (status, body) = json_get(app, &format!("/blockchain/token/byId/{OTHER_TOKEN_HEX}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["reason"], "not-found");
}

// ---------------- #18 batch tokens (POST) -----------------------------------

#[tokio::test]
async fn tokens_post_200_returns_known_tokens_in_input_order() {
    let stub = StubIndexer::caught_up().with_token(sample_token_dto());
    let app = build_app(Arc::new(stub));
    let body_json = serde_json::to_vec(&vec![SAMPLE_TOKEN_HEX, OTHER_TOKEN_HEX]).unwrap();
    let (status, body) = json_post(app, "/blockchain/tokens", body_json).await;
    assert_eq!(status, StatusCode::OK);
    let arr = body.as_array().unwrap();
    // Misses dropped per Scala flatMap: only the known token survives.
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["id"], SAMPLE_TOKEN_HEX);
}

#[tokio::test]
async fn tokens_post_200_empty_array_on_empty_input() {
    let app = build_app(Arc::new(StubIndexer::caught_up()));
    let body_json = serde_json::to_vec::<Vec<String>>(&vec![]).unwrap();
    let (status, body) = json_post(app, "/blockchain/tokens", body_json).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn tokens_post_200_drops_malformed_hex_ids() {
    // Mixed input: one valid hex id + one non-hex string. The non-hex
    // entry is dropped at the parse step (parse_modifier_id returns
    // None → filter_map drops). The valid id misses the stub registry,
    // so the final array is empty — but the request still 200's, not
    // 400. This mirrors Scala's flatMap which silently drops both
    // unparseable ids and unknown ids.
    let app = build_app(Arc::new(StubIndexer::caught_up()));
    let body_json = serde_json::to_vec(&vec![SAMPLE_TOKEN_HEX, "not-a-hex-id"]).unwrap();
    let (status, body) = json_post(app, "/blockchain/tokens", body_json).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.as_array().unwrap().is_empty());
}

// ---------------- #19 boxes/byTokenId ---------------------------------------

#[tokio::test]
async fn boxes_by_token_id_200_returns_paged_items_and_total() {
    let token_id = sample_token_id();
    let stub = StubIndexer::caught_up().with_token_boxes(
        token_id,
        vec![
            fixture_box([0xAA; 33], 700_000, 1, 50),
            fixture_box([0xAA; 33], 700_001, 2, 51),
            fixture_box([0xAA; 33], 700_002, 3, 52),
        ],
        9, // total > items.len() to verify total flows through independently
    );
    let app = build_app(Arc::new(stub));
    let (status, body) = json_get(
        app,
        &format!("/blockchain/box/byTokenId/{SAMPLE_TOKEN_HEX}?offset=0&limit=10"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["total"], 9);
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 3);
    assert_eq!(items[0]["globalIndex"], 50);
    assert_eq!(items[2]["globalIndex"], 52);
}

#[tokio::test]
async fn boxes_by_token_id_200_empty_envelope_on_unknown_token() {
    // Scala falls back to an empty box list rather than 404. We must
    // mirror — `{items: [], total: 0}` with status 200.
    let app = build_app(Arc::new(StubIndexer::caught_up()));
    let (status, body) =
        json_get(app, &format!("/blockchain/box/byTokenId/{OTHER_TOKEN_HEX}")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["total"], 0);
    assert!(body["items"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn boxes_by_token_id_400_on_limit_above_max() {
    let app = build_app(Arc::new(StubIndexer::caught_up()));
    let (status, body) = json_get(
        app,
        &format!("/blockchain/box/byTokenId/{SAMPLE_TOKEN_HEX}?limit=99999"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["reason"], "bad-request");
    assert!(
        body["detail"].as_str().unwrap().contains("16384"),
        "detail should cite MaxItems literal: {body}"
    );
}

// ---------------- #20 unspent/byTokenId -------------------------------------

#[tokio::test]
async fn unspent_by_token_id_200_returns_bare_array() {
    let token_id = sample_token_id();
    let stub = StubIndexer::caught_up().with_token_unspent(
        token_id,
        vec![
            fixture_box([0xAA; 33], 700_000, 1, 200),
            fixture_box([0xAA; 33], 700_001, 2, 201),
        ],
    );
    let app = build_app(Arc::new(stub));
    let (status, body) = json_get(
        app,
        &format!("/blockchain/box/unspent/byTokenId/{SAMPLE_TOKEN_HEX}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let arr = body.as_array().unwrap();
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0]["globalIndex"], 201); // default Desc → newest first
    assert_eq!(arr[1]["globalIndex"], 200);
}

#[tokio::test]
async fn unspent_by_token_id_200_empty_array_on_unknown_token() {
    // Empty fallback like #19 — unknown token → 200 [].
    let app = build_app(Arc::new(StubIndexer::caught_up()));
    let (status, body) = json_get(
        app,
        &format!("/blockchain/box/unspent/byTokenId/{OTHER_TOKEN_HEX}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn unspent_by_token_id_sort_direction_asc_is_oldest_first() {
    let token_id = sample_token_id();
    let stub = StubIndexer::caught_up().with_token_unspent(
        token_id,
        vec![
            fixture_box([0xAA; 33], 700_000, 1, 300),
            fixture_box([0xAA; 33], 700_001, 2, 301),
            fixture_box([0xAA; 33], 700_002, 3, 302),
        ],
    );
    let app = build_app(Arc::new(stub));
    let (status, body) = json_get(
        app,
        &format!("/blockchain/box/unspent/byTokenId/{SAMPLE_TOKEN_HEX}?sortDirection=asc"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let arr = body.as_array().unwrap();
    assert_eq!(arr.len(), 3);
    assert_eq!(arr[0]["globalIndex"], 300);
    assert_eq!(arr[2]["globalIndex"], 302);
}

#[tokio::test]
async fn unspent_by_token_id_400_on_invalid_sort_direction() {
    let app = build_app(Arc::new(StubIndexer::caught_up()));
    let (status, body) = json_get(
        app,
        &format!("/blockchain/box/unspent/byTokenId/{SAMPLE_TOKEN_HEX}?sortDirection=sideways"),
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

// Pool output containing the queried token in `box.candidate.tokens` is
// appended to the response and shaped as the pool-output sentinel:
// `inclusionHeight
// = 0` (mempool sentinel — confirmed boxes always have height ≥ 1),
// `globalIndex = 0`, all spending fields null.
#[tokio::test]
async fn unspent_overlay_include_unconfirmed_appends_matching_pool_output() {
    let pubkey = [0x61u8; 33];
    let token_id = sample_token_id();
    let pool_box = make_pool_box_with_token(pubkey, 7_000_000, 0xAA, token_id, 42);
    let mempool: Arc<dyn MempoolView> = Arc::new(StubMempoolView::with_outputs(vec![pool_box]));
    let app = build_app_with_mempool(Arc::new(StubIndexer::caught_up()), mempool);
    let path =
        format!("/blockchain/box/unspent/byTokenId/{SAMPLE_TOKEN_HEX}?includeUnconfirmed=true");
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

// Pool output without the queried token must be filtered out. Pool box
// here carries a *different* token id; queried id sees an empty array.
#[tokio::test]
async fn unspent_overlay_pool_output_for_other_token_excluded() {
    let queried = sample_token_id();
    let other_token = TokenId::from_bytes([0x99u8; 32]);
    assert_ne!(queried, other_token);
    let pubkey = [0x62u8; 33];
    let pool_box = make_pool_box_with_token(pubkey, 1_234_567, 0xAB, other_token, 1);
    let mempool: Arc<dyn MempoolView> = Arc::new(StubMempoolView::with_outputs(vec![pool_box]));
    let app = build_app_with_mempool(Arc::new(StubIndexer::caught_up()), mempool);
    let path =
        format!("/blockchain/box/unspent/byTokenId/{SAMPLE_TOKEN_HEX}?includeUnconfirmed=true");
    let (status, body) = json_get(app, &path).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.as_array().expect("bare JSON array").is_empty());
}

// A pool box carrying *multiple* tokens is matched by any of its token
// ids — Scala's segment indexes the box once per token, but the API
// response surfaces it once per query. Here the pool box carries the
// queried token plus a noise token; only one entry surfaces.
#[tokio::test]
async fn unspent_overlay_multi_token_pool_box_matches_on_any_token() {
    let pubkey = [0x63u8; 33];
    let queried = sample_token_id();
    let noise = TokenId::from_bytes([0xBBu8; 32]);
    let pool_box =
        make_pool_box_with_tokens(pubkey, 500_000, 0xAC, vec![(queried, 7), (noise, 11)]);
    let mempool: Arc<dyn MempoolView> = Arc::new(StubMempoolView::with_outputs(vec![pool_box]));
    let app = build_app_with_mempool(Arc::new(StubIndexer::caught_up()), mempool);
    let path =
        format!("/blockchain/box/unspent/byTokenId/{SAMPLE_TOKEN_HEX}?includeUnconfirmed=true");
    let (status, body) = json_get(app, &path).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let arr = body.as_array().expect("bare JSON array");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["inclusionHeight"], 0);
}

// ---------------- P5 overlay: excludeMempoolSpent -------------------------

// `excludeMempoolSpent=true` drops confirmed unspent rows whose box_id
// is in `mempool.spentInputs` per `Segment.scala:265`. Two confirmed
// boxes for the queried token; the spent-set covers one — only the
// survivor remains. Mempool stub supplies no pool-output extension.
#[tokio::test]
async fn unspent_overlay_exclude_mempool_spent_drops_confirmed_box() {
    let pubkey = [0x64u8; 33];
    let token_id = sample_token_id();
    let confirmed = vec![
        fixture_box_with_token(pubkey, 700_010, 1_000, 11, token_id, 5),
        fixture_box_with_token(pubkey, 700_011, 2_000, 12, token_id, 5),
    ];
    let confirmed_ids: Vec<BoxId> = confirmed
        .iter()
        .map(|b| b.box_data.box_id().expect("box_id"))
        .collect();
    let stub_idx = StubIndexer::caught_up().with_token_unspent(token_id, confirmed);
    let mempool: Arc<dyn MempoolView> =
        Arc::new(StubMempoolView::with_outputs(Vec::new()).with_spent(vec![confirmed_ids[0]]));
    let app = build_app_with_mempool(Arc::new(stub_idx), mempool);
    let path =
        format!("/blockchain/box/unspent/byTokenId/{SAMPLE_TOKEN_HEX}?excludeMempoolSpent=true");
    let (status, body) = json_get(app, &path).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let arr = body.as_array().expect("bare JSON array");
    assert_eq!(arr.len(), 1, "one survivor (the unspent-by-pool box)");
    assert_eq!(arr[0]["globalIndex"], 12);
}

// `Segment.scala:268`: chained pool spends must not appear in the
// unconfirmed slice when `excludeMempoolSpent=true`. Two pool outputs
// carry the queried token; the first id is in the spent set, only the
// second surfaces.
#[tokio::test]
async fn unspent_overlay_exclude_mempool_spent_drops_chained_pool_output() {
    let pubkey = [0x65u8; 33];
    let token_id = sample_token_id();
    let pool_a = make_pool_box_with_token(pubkey, 10_000, 0xC0, token_id, 1);
    let pool_b = make_pool_box_with_token(pubkey, 20_000, 0xC1, token_id, 2);
    let pool_a_id = pool_a.box_id().expect("box_id");
    let mempool: Arc<dyn MempoolView> =
        Arc::new(StubMempoolView::with_outputs(vec![pool_a, pool_b]).with_spent(vec![pool_a_id]));
    let app = build_app_with_mempool(Arc::new(StubIndexer::caught_up()), mempool);
    let path = format!(
        "/blockchain/box/unspent/byTokenId/{SAMPLE_TOKEN_HEX}?includeUnconfirmed=true&excludeMempoolSpent=true"
    );
    let (status, body) = json_get(app, &path).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let arr = body.as_array().expect("bare JSON array");
    assert_eq!(arr.len(), 1, "chained pool spend filtered out");
    assert_eq!(arr[0]["value"], 20_000);
    assert_eq!(arr[0]["inclusionHeight"], 0);
}

// ---------------- P5 overlay: merge order ---------------------------------

#[tokio::test]
async fn unspent_overlay_default_desc_places_unconfirmed_first() {
    let pubkey = [0x66u8; 33];
    let token_id = sample_token_id();
    let confirmed = vec![
        fixture_box_with_token(pubkey, 700_020, 1_000, 21, token_id, 5),
        fixture_box_with_token(pubkey, 700_021, 2_000, 22, token_id, 5),
    ];
    let pool_box = make_pool_box_with_token(pubkey, 999_999, 0xD1, token_id, 7);
    let stub_idx = StubIndexer::caught_up().with_token_unspent(token_id, confirmed);
    let mempool: Arc<dyn MempoolView> = Arc::new(StubMempoolView::with_outputs(vec![pool_box]));
    let app = build_app_with_mempool(Arc::new(stub_idx), mempool);
    let path =
        format!("/blockchain/box/unspent/byTokenId/{SAMPLE_TOKEN_HEX}?includeUnconfirmed=true");
    let (status, body) = json_get(app, &path).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let arr = body.as_array().expect("bare JSON array");
    assert_eq!(arr.len(), 3);
    assert_eq!(arr[0]["inclusionHeight"], 0, "unconfirmed first under DESC");
    assert_eq!(arr[1]["globalIndex"], 22);
    assert_eq!(arr[2]["globalIndex"], 21);
}

#[tokio::test]
async fn unspent_overlay_asc_places_confirmed_first() {
    let pubkey = [0x67u8; 33];
    let token_id = sample_token_id();
    let confirmed = vec![
        fixture_box_with_token(pubkey, 700_030, 1_000, 31, token_id, 5),
        fixture_box_with_token(pubkey, 700_031, 2_000, 32, token_id, 5),
    ];
    let pool_box = make_pool_box_with_token(pubkey, 999_999, 0xD2, token_id, 7);
    let stub_idx = StubIndexer::caught_up().with_token_unspent(token_id, confirmed);
    let mempool: Arc<dyn MempoolView> = Arc::new(StubMempoolView::with_outputs(vec![pool_box]));
    let app = build_app_with_mempool(Arc::new(stub_idx), mempool);
    let path = format!(
        "/blockchain/box/unspent/byTokenId/{SAMPLE_TOKEN_HEX}?includeUnconfirmed=true&sortDirection=asc"
    );
    let (status, body) = json_get(app, &path).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let arr = body.as_array().expect("bare JSON array");
    assert_eq!(arr.len(), 3);
    assert_eq!(arr[0]["globalIndex"], 31);
    assert_eq!(arr[1]["globalIndex"], 32);
    assert_eq!(arr[2]["inclusionHeight"], 0, "unconfirmed last under ASC");
}

// `[inherited]` paging quirk: limit=1 + 1 confirmed + 1 pool output → 2
// items, not 1.
#[tokio::test]
async fn unspent_overlay_response_can_exceed_limit_when_include_unconfirmed() {
    let pubkey = [0x68u8; 33];
    let token_id = sample_token_id();
    let confirmed = vec![
        fixture_box_with_token(pubkey, 700_040, 1_000, 41, token_id, 5),
        fixture_box_with_token(pubkey, 700_041, 2_000, 42, token_id, 5),
    ];
    let pool_box = make_pool_box_with_token(pubkey, 999_999, 0xD3, token_id, 7);
    let stub_idx = StubIndexer::caught_up().with_token_unspent(token_id, confirmed);
    let mempool: Arc<dyn MempoolView> = Arc::new(StubMempoolView::with_outputs(vec![pool_box]));
    let app = build_app_with_mempool(Arc::new(stub_idx), mempool);
    let path = format!(
        "/blockchain/box/unspent/byTokenId/{SAMPLE_TOKEN_HEX}?limit=1&includeUnconfirmed=true"
    );
    let (status, body) = json_get(app, &path).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let arr = body.as_array().expect("bare JSON array");
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0]["inclusionHeight"], 0, "DESC: unconfirmed first");
}

// ---------------- validation order: paging > sort > overlay ----------------

#[tokio::test]
async fn paging_error_wins_over_sort_and_overlay_flags() {
    let app = build_app(Arc::new(StubIndexer::caught_up()));
    let (status, body) = json_get(
        app,
        &format!(
            "/blockchain/box/unspent/byTokenId/{SAMPLE_TOKEN_HEX}\
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

/// `IndexedErgoBox` carrying a single token. `tx_id_byte` keeps box_ids
/// distinct across fixtures.
fn fixture_box_with_token(
    pubkey: [u8; 33],
    height: i32,
    value: u64,
    global_index: i64,
    token_id: TokenId,
    amount: u64,
) -> IndexedErgoBox {
    let candidate = ErgoBoxCandidate::new(
        value,
        p2pk_tree(pubkey),
        height as u32,
        vec![Token { token_id, amount }],
        AdditionalRegisters::empty(),
    )
    .expect("ErgoBoxCandidate::new");
    let box_data = ErgoBox {
        candidate,
        transaction_id: ModifierId::from_bytes([global_index as u8 ^ 0xCC; 32]),
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

/// Pool `ErgoBox` carrying a single token. `tx_id_byte` keeps box_ids
/// distinct across fixtures even when value/tree match.
fn make_pool_box_with_token(
    pubkey: [u8; 33],
    value: u64,
    tx_id_byte: u8,
    token_id: TokenId,
    amount: u64,
) -> ErgoBox {
    make_pool_box_with_tokens(pubkey, value, tx_id_byte, vec![(token_id, amount)])
}

/// Pool `ErgoBox` carrying multiple tokens. Used to verify multi-token
/// boxes match the byTokenId overlay on any of their tokens.
fn make_pool_box_with_tokens(
    pubkey: [u8; 33],
    value: u64,
    tx_id_byte: u8,
    tokens: Vec<(TokenId, u64)>,
) -> ErgoBox {
    let candidate = ErgoBoxCandidate::new(
        value,
        p2pk_tree(pubkey),
        0,
        tokens
            .into_iter()
            .map(|(token_id, amount)| Token { token_id, amount })
            .collect(),
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
/// pool-output extension.
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

async fn json_post(
    app: axum::Router,
    path: &str,
    body: Vec<u8>,
) -> (StatusCode, serde_json::Value) {
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body))
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
// Holds optional per-token data: a registered token DTO (for #17 / #18),
// per-token paged boxes (#19), and per-token unspent boxes (#20). All
// keyed by `TokenId` so unknown ids fall through to the empty-fallback
// path.

struct StubIndexer {
    status: IndexerStatus,
    token: Option<IndexedTokenDto>,
    token_boxes: Option<(TokenId, Vec<IndexedErgoBox>, u64)>,
    token_unspent: Option<(TokenId, Vec<IndexedErgoBox>)>,
}

impl StubIndexer {
    fn caught_up() -> Self {
        Self {
            status: IndexerStatus::CaughtUp,
            token: None,
            token_boxes: None,
            token_unspent: None,
        }
    }
    fn with_status(status: IndexerStatus) -> Self {
        Self {
            status,
            token: None,
            token_boxes: None,
            token_unspent: None,
        }
    }
    fn with_token(mut self, t: IndexedTokenDto) -> Self {
        self.token = Some(t);
        self
    }
    fn with_token_boxes(
        mut self,
        token_id: TokenId,
        boxes: Vec<IndexedErgoBox>,
        total: u64,
    ) -> Self {
        self.token_boxes = Some((token_id, boxes, total));
        self
    }
    fn with_token_unspent(mut self, token_id: TokenId, boxes: Vec<IndexedErgoBox>) -> Self {
        self.token_unspent = Some((token_id, boxes));
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

    fn template_boxes_paged(&self, _: &TemplateHash, _: Page) -> Vec<IndexedBoxDto> {
        Vec::new()
    }
    fn template_unspent_paged(&self, _: &TemplateHash, _: Page, _: SortDir) -> Vec<IndexedBoxDto> {
        Vec::new()
    }
    fn template_total_boxes(&self, _: &TemplateHash) -> u64 {
        0
    }

    fn token_by_id(&self, id: &TokenId) -> Option<IndexedTokenDto> {
        self.token.as_ref().filter(|t| &t.token_id == id).cloned()
    }
    fn tokens_by_ids(&self, ids: &[TokenId]) -> Vec<IndexedTokenDto> {
        ids.iter().filter_map(|id| self.token_by_id(id)).collect()
    }
    fn token_boxes_paged(&self, id: &TokenId, p: Page) -> Vec<IndexedBoxDto> {
        match &self.token_boxes {
            Some((stored, boxes, _)) if stored == id => {
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
    fn token_unspent_paged(&self, id: &TokenId, p: Page, dir: SortDir) -> Vec<IndexedBoxDto> {
        match &self.token_unspent {
            Some((stored, boxes)) if stored == id => {
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
    fn token_total_boxes(&self, id: &TokenId) -> u64 {
        match &self.token_boxes {
            Some((stored, _, total)) if stored == id => *total,
            _ => 0,
        }
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
            mempool_tx_requested_total: 0,
            mempool_peer_tx_admitted_total: 0,
            mempool_peer_tx_rejected_total: 0,
            reorgs_total: 0,
            last_reorg_depth: None,
            last_reorg_unix_ms: None,
            apply_in_progress: false,
            last_apply_duration_ms: 0,
            last_applied_height: 0,
            last_apply_age_ms: None,
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
