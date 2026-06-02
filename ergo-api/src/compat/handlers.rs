use std::collections::BTreeMap;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, Query};
use axum::http::StatusCode;
use axum::{extract::State, response::IntoResponse, response::Response, Json};
use serde::Deserialize;

use crate::compat::traits::NodeChainQuery;
use crate::types::ApiSubmitError;

pub async fn info_handler(State(q): State<Arc<dyn NodeChainQuery>>) -> Response {
    Json(q.info()).into_response()
}

/// `/blocks/at/{height}` — Scala emits a JSON array of hex header IDs.
/// Negative or non-numeric heights are rejected by axum's path parser
/// with 400. An out-of-range height yields 200 with an empty array,
/// matching Scala's behavior for unknown heights.
pub async fn block_ids_at_height_handler(
    State(q): State<Arc<dyn NodeChainQuery>>,
    Path(height): Path<u32>,
) -> Response {
    Json(q.header_ids_at_height(height)).into_response()
}

/// `/blocks/{header_id}` — full block reassembly. Returns 404 with a
/// minimal error body when the header is unknown, malformed-hex, or any
/// required section is missing. Scala emits a structured error here; we
/// match the status code and surface a brief message body.
pub async fn block_by_id_handler(
    State(q): State<Arc<dyn NodeChainQuery>>,
    Path(header_id): Path<String>,
) -> Response {
    match q.full_block_by_id(&header_id) {
        Some(block) => Json(block).into_response(),
        None => not_found("block not found"),
    }
}

/// `/blocks/{headerId}/header` — single header DTO. 404 with the same
/// error envelope as `/blocks/{id}` when missing or the id is malformed.
pub async fn header_by_id_handler(
    State(q): State<Arc<dyn NodeChainQuery>>,
    Path(header_id): Path<String>,
) -> Response {
    match q.header_by_id(&header_id) {
        Some(h) => Json(h).into_response(),
        None => not_found("header not found"),
    }
}

/// `/blocks/{headerId}/transactions` — block-transactions section DTO.
pub async fn block_transactions_by_id_handler(
    State(q): State<Arc<dyn NodeChainQuery>>,
    Path(header_id): Path<String>,
) -> Response {
    match q.block_transactions_by_id(&header_id) {
        Some(bt) => Json(bt).into_response(),
        None => not_found("block transactions not found"),
    }
}

/// `GET /blocks/{headerId}/proofFor/{txId}` — Merkle proof. 404 when
/// the header is unknown, the block_transactions section is pruned,
/// or the tx is not in the block.
pub async fn proof_for_tx_handler(
    State(q): State<Arc<dyn NodeChainQuery>>,
    Path((header_id, tx_id)): Path<(String, String)>,
) -> Response {
    match q.proof_for_tx(&header_id, &tx_id) {
        Some(p) => Json(p).into_response(),
        None => not_found("proof not found"),
    }
}

/// `GET /blocks/modifier/{modifierId}` — generic-by-id lookup. Returns
/// 404 for unknown ids (V3 verification: `ApiResponse.scala:30-31`).
/// Body shape on hit is the variant's bare object — see `ScalaBlockSection`.
pub async fn modifier_by_id_handler(
    State(q): State<Arc<dyn NodeChainQuery>>,
    Path(modifier_id): Path<String>,
) -> Response {
    match q.modifier_by_id(&modifier_id) {
        Some(s) => Json(s).into_response(),
        None => not_found("modifier not found"),
    }
}

/// `POST /blocks/headerIds` — bulk full-block fetch.
///
/// Body is a JSON array of base16 modifier ids
/// (`ErgoBaseApiRoute.scala:31`). Behaviour mirrors Scala:
/// - any id with malformed hex → 400, entire request rejected
///   (`handleModifierIds` ValidationRejection)
/// - valid hex but not in storage → silently dropped from response
/// - response is `Vec<ScalaFullBlock>` in request order, with missing
///   ids gone (not nulled)
///
/// Scala does not enforce a length cap on this endpoint; we apply
/// `MAX_HEADERS = 16384` defensively (banner-flagged in openapi).
pub async fn block_by_ids_handler(
    State(q): State<Arc<dyn NodeChainQuery>>,
    Json(ids): Json<Vec<String>>,
) -> Response {
    if ids.len() as i64 > MAX_HEADERS {
        return bad_request(&format!("No more than {MAX_HEADERS} ids can be requested"));
    }
    for id in &ids {
        if !is_valid_modifier_hex(id) {
            return bad_request(&format!("Wrong modifierId format for: {id}"));
        }
    }
    Json(q.full_blocks_by_header_ids(&ids)).into_response()
}

/// Validate that a string is a 64-char lowercase/uppercase hex modifier
/// id. Mirrors `Algos.decode` in `handleModifierIds` — Scala's path
/// directive accepts mixed-case hex, so we do too.
fn is_valid_modifier_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Cap shared by `/blocks`, `/blocks/chainSlice`, and `/blocks/lastHeaders`,
/// matching `BlocksApiRoute.MaxHeaders` (`BlocksApiRoute.scala:27`).
const MAX_HEADERS: i64 = 16_384;

/// `/blocks/lastHeaders/{count}` — Scala caps `count > 16384` with 400
/// (`BlocksApiRoute.scala:159-164`). Negative / non-numeric paths
/// short-circuit at the path extractor with 400.
pub async fn last_headers_handler(
    State(q): State<Arc<dyn NodeChainQuery>>,
    Path(count): Path<u32>,
) -> Response {
    if (count as i64) > MAX_HEADERS {
        return bad_request(&format!(
            "No more than {MAX_HEADERS} headers can be requested"
        ));
    }
    Json(q.last_headers(count)).into_response()
}

#[derive(Debug, Deserialize)]
pub struct ChainSliceQuery {
    #[serde(default, rename = "fromHeight")]
    pub from_height: Option<i64>,
    #[serde(default, rename = "toHeight")]
    pub to_height: Option<i64>,
}

/// `/blocks/chainSlice?fromHeight=&toHeight=` — Scala defaults
/// `fromHeight=1, toHeight=16384` (`BlocksApiRoute.scala:111-112`),
/// rejects `toHeight < fromHeight` with 400 (`:142-148`). Negative
/// `to_height` falls back to tip in `getChainSlice` (`:95-102`); we
/// pass `u32::MAX` as the sentinel so the bridge's chain-index lookup
/// misses and falls back to tip, identical to Scala's `orElse`.
pub async fn chain_slice_handler(
    State(q): State<Arc<dyn NodeChainQuery>>,
    Query(p): Query<ChainSliceQuery>,
) -> Response {
    let from = p.from_height.unwrap_or(1);
    let to = p.to_height.unwrap_or(MAX_HEADERS);
    if to < from {
        return bad_request("toHeight < fromHeight");
    }
    // Negative `from` is preserved as 0 in u32-land. Scala's predicate
    // `_.height <= fromHeight + 1` then never triggers on positive
    // heights for negative `from`, which collapses to "walk back the
    // 16384 cap from top". The bridge's `from + 1 = 1` predicate plus
    // the 16384 cap reaches the same lo for any tip, so 0 is correct.
    let from_u = from.max(0).min(u32::MAX as i64) as u32;
    let to_u = if to < 0 {
        u32::MAX
    } else {
        to.min(u32::MAX as i64) as u32
    };
    Json(q.chain_slice(from_u, to_u)).into_response()
}

#[derive(Debug, Deserialize)]
pub struct HeaderIdsQuery {
    #[serde(default)]
    pub limit: Option<i64>,
    #[serde(default)]
    pub offset: Option<i64>,
}

/// `/blocks?limit=&offset=` — Scala defaults `offset=1, limit=50`
/// (`BlocksApiRoute.scala:31`), rejects `offset < 0`, `limit < 0`,
/// and `limit > 16384` with 400 (`:114-124`). `offset` is a **start
/// height**, not a tip-relative skip.
pub async fn header_ids_paged_handler(
    State(q): State<Arc<dyn NodeChainQuery>>,
    Query(p): Query<HeaderIdsQuery>,
) -> Response {
    let offset = p.offset.unwrap_or(1);
    let limit = p.limit.unwrap_or(50);
    if offset < 0 {
        return bad_request("offset is negative");
    }
    if limit < 0 {
        return bad_request("limit is negative");
    }
    if limit > MAX_HEADERS {
        return bad_request(&format!(
            "No more than {MAX_HEADERS} headers can be requested"
        ));
    }
    Json(q.header_ids_paged(limit as u32, offset as u32)).into_response()
}

fn not_found(detail: &str) -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({
            "error": 404,
            "reason": "not-found",
            "detail": detail
        })),
    )
        .into_response()
}

/// 400 envelope mirroring the not_found shape. The `detail` carries the
/// Scala-source error string verbatim so clients matching on error
/// substrings see the same surface.
fn bad_request(detail: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({
            "error": 400,
            "reason": "bad-request",
            "detail": detail
        })),
    )
        .into_response()
}

/// `/peers/all` — every tracked peer.
pub async fn peers_all_handler(State(q): State<Arc<dyn NodeChainQuery>>) -> Response {
    Json(q.peers_all()).into_response()
}

/// `/peers/connected` — peers in `Connected` state (post-handshake).
pub async fn peers_connected_handler(State(q): State<Arc<dyn NodeChainQuery>>) -> Response {
    Json(q.peers_connected()).into_response()
}

/// `GET /peers/blacklisted` — `{"addresses": [...]}` host-only list.
pub async fn peers_blacklisted_handler(State(q): State<Arc<dyn NodeChainQuery>>) -> Response {
    Json(q.peers_blacklisted()).into_response()
}

/// `GET /peers/status` — `{lastIncomingMessage, currentSystemTime}`
/// freshness probe.
pub async fn peers_status_handler(State(q): State<Arc<dyn NodeChainQuery>>) -> Response {
    Json(q.peers_status()).into_response()
}

/// `GET /peers/syncInfo` — per-peer sync-state array.
pub async fn peers_sync_info_handler(State(q): State<Arc<dyn NodeChainQuery>>) -> Response {
    Json(q.peers_sync_info()).into_response()
}

/// `GET /peers/trackInfo` — `{numRequested, numReceived, numFailed}`
/// counters.
pub async fn peers_track_info_handler(State(q): State<Arc<dyn NodeChainQuery>>) -> Response {
    Json(q.peers_track_info()).into_response()
}

/// `/transactions/unconfirmed/transactionIds` — array of pool tx ids.
pub async fn pool_tx_ids_handler(State(q): State<Arc<dyn NodeChainQuery>>) -> Response {
    Json(q.pool_tx_ids()).into_response()
}

/// `HEAD /transactions/unconfirmed/{txId}` — 200 if pooled else 404,
/// no body either way (HEAD semantics).
pub async fn pool_contains_handler(
    State(q): State<Arc<dyn NodeChainQuery>>,
    Path(tx_id): Path<String>,
) -> Response {
    let status = if q.pool_contains(&tx_id) {
        StatusCode::OK
    } else {
        StatusCode::NOT_FOUND
    };
    (status, ()).into_response()
}

/// `GET /transactions/unconfirmed/{txId}` — returns 400 with the
/// standard `ApiSubmitError` envelope and a "use byTransactionId"
/// hint detail. Matches Scala 6.0.3RC1: the same path serves HEAD
/// as a presence probe; GET is rejected because the full-tx GET
/// lives at `/byTransactionId/{txId}`. Without this handler axum
/// would surface 405 on GET, which differs from Scala (parity probe
/// 2026-05-19).
pub async fn pool_contains_get_hint_handler(Path(_tx_id): Path<String>) -> Response {
    api_error_400(
        "deserialize",
        Some(
            "GET on /transactions/unconfirmed/{txId} is reserved for HEAD presence probes; \
             use /transactions/unconfirmed/byTransactionId/{txId} for the full transaction"
                .to_string(),
        ),
    )
}

/// `GET /transactions/unconfirmed?offset=&limit=` — paged list of
/// full unconfirmed transactions. Scala defaults: `offset=0,
/// limit=50` with no upper-bound clamp. Caller-side load shedding
/// is the bridge's responsibility, not the handler's — matches
/// Scala's `TransactionsApiRoute.scala` which forwards `(offset,
/// limit)` to the mempool reader unmodified.
pub async fn pool_txs_paged_handler(
    State(q): State<Arc<dyn NodeChainQuery>>,
    axum::extract::Query(p): axum::extract::Query<PoolPagingParams>,
) -> Response {
    let offset = p.offset.unwrap_or(0);
    let limit = p.limit.unwrap_or(50);
    Json(q.pool_txs_paged(offset, limit)).into_response()
}

#[derive(serde::Deserialize, Default)]
pub struct PoolPagingParams {
    pub offset: Option<u32>,
    pub limit: Option<u32>,
}

/// `GET /transactions/unconfirmed/byTransactionId/{txId}` — full
/// `ScalaTransaction` for a single pooled tx. `None` → 404 with the
/// standard `ApiError` envelope.
pub async fn pool_tx_by_id_handler(
    State(q): State<Arc<dyn NodeChainQuery>>,
    Path(tx_id): Path<String>,
) -> Response {
    match q.pool_tx_by_id(&tx_id) {
        Some(tx) => Json(tx).into_response(),
        None => not_found("unconfirmed transaction not found"),
    }
}

/// `POST /transactions/unconfirmed/byTransactionIds` — batch lookup.
/// Always 200 with a (possibly empty) JSON array; unresolved ids
/// silently skipped per Scala's `flatMap` semantics.
pub async fn pool_txs_by_ids_handler(
    State(q): State<Arc<dyn NodeChainQuery>>,
    Json(ids): Json<Vec<String>>,
) -> Response {
    Json(q.pool_txs_by_ids(&ids)).into_response()
}

/// `GET /transactions/unconfirmed/size` — bare JSON integer.
pub async fn pool_size_handler(State(q): State<Arc<dyn NodeChainQuery>>) -> Response {
    Json(q.pool_size()).into_response()
}

/// Parse a Scala `fromJsonOrPlain`-style hex body into bytes.
///
/// Algorithm (matches Scala's `fromJsonOrPlain` semantics):
/// 1. Try to parse the body as JSON.
/// 2. If parse succeeds AND the value is a JSON string → use it.
/// 3. If parse succeeds AND the value is any other JSON type
///    (number, array, object, bool, null) → 400 `deserialize`.
/// 4. If parse fails → treat the body as raw plain hex.
///
/// The strict middle branch matters: a body like `1234` is BOTH
/// valid JSON (a number) AND valid hex (`[0x12, 0x34]`). Scala
/// rejects it because the route contract is "JSON-quoted hex
/// string OR plain hex"; an unquoted-but-JSON-parseable number is
/// ambiguous and the strict path matches Scala's behavior.
///
/// Both JSON-shape failures (non-string JSON) and hex-decode
/// failures surface as 400 with the standard `ApiSubmitError`
/// envelope so the whole `/transactions/*` parse-failure surface
/// stays uniform.
fn parse_hex_body(body: &[u8], field_name: &str) -> Result<Vec<u8>, Box<Response>> {
    let trimmed: &[u8] = {
        let s = body
            .iter()
            .position(|c| !c.is_ascii_whitespace())
            .unwrap_or(body.len());
        let e = body
            .iter()
            .rposition(|c| !c.is_ascii_whitespace())
            .map(|p| p + 1)
            .unwrap_or(s);
        &body[s..e]
    };
    let hex_str: String = match serde_json::from_slice::<serde_json::Value>(trimmed) {
        Ok(serde_json::Value::String(s)) => s,
        Ok(other) => {
            let actual = match other {
                serde_json::Value::Null => "null",
                serde_json::Value::Bool(_) => "bool",
                serde_json::Value::Number(_) => "number",
                serde_json::Value::Array(_) => "array",
                serde_json::Value::Object(_) => "object",
                serde_json::Value::String(_) => unreachable!(),
            };
            return Err(Box::new(api_error_400(
                "deserialize",
                Some(format!(
                    "{field_name} must be a JSON-quoted hex string or raw hex; got JSON {actual}",
                )),
            )));
        }
        Err(_) => match std::str::from_utf8(trimmed) {
            Ok(s) => s.to_string(),
            Err(e) => {
                return Err(Box::new(api_error_400(
                    "deserialize",
                    Some(format!("{field_name} body is not valid UTF-8 hex: {e}")),
                )));
            }
        },
    };
    hex::decode(hex_str.trim()).map_err(|e| {
        Box::new(api_error_400(
            "deserialize",
            Some(format!("{field_name} hex decode failed: {e}")),
        ))
    })
}

/// Same as [`parse_hex_body`] but additionally requires the decoded
/// bytes to be exactly 32 bytes — used by `byBoxId` / `byTokenId`
/// which take a 32-byte modifier id.
fn parse_id_body(body: &[u8], field_name: &str) -> Result<[u8; 32], Box<Response>> {
    let bytes = parse_hex_body(body, field_name)?;
    bytes.as_slice().try_into().map_err(|_| {
        Box::new(api_error_400(
            "deserialize",
            Some(format!(
                "{field_name} must decode to exactly 32 bytes, got {} bytes",
                bytes.len(),
            )),
        ))
    })
}

fn api_error_400(reason: &str, detail: Option<String>) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(ApiSubmitError {
            error: StatusCode::BAD_REQUEST.as_u16(),
            reason: reason.to_string(),
            detail,
        }),
    )
        .into_response()
}

/// `POST /transactions/unconfirmed/byErgoTree` — pool txs whose
/// outputs include a box paying to the supplied ergoTree. Body is
/// hex (`fromJsonOrPlain` — accepts either JSON-quoted or
/// unquoted), matching the broader `/transactions/*` parse
/// convention. Returns a bare JSON array; bad hex maps to 400
/// `deserialize` before reaching the bridge.
pub async fn pool_txs_by_ergo_tree_handler(
    State(q): State<Arc<dyn NodeChainQuery>>,
    body: Bytes,
) -> Response {
    let bytes = match parse_hex_body(&body, "ergoTree") {
        Ok(b) => b,
        Err(resp) => return *resp,
    };
    Json(q.pool_txs_by_ergo_tree(&bytes)).into_response()
}

/// `POST /transactions/unconfirmed/byBoxId` — pool txs that spend
/// the supplied 32-byte box id (input-side match). Wallets use
/// this to detect that a known unspent box has been picked up by
/// a pending tx.
pub async fn pool_txs_by_box_id_handler(
    State(q): State<Arc<dyn NodeChainQuery>>,
    body: Bytes,
) -> Response {
    let id = match parse_id_body(&body, "boxId") {
        Ok(b) => b,
        Err(resp) => return *resp,
    };
    Json(q.pool_txs_by_box_id(&id)).into_response()
}

/// `POST /transactions/unconfirmed/byTokenId` — pool txs whose
/// outputs include the supplied 32-byte token id (either as a new
/// asset entry or carried through from an input). DEX UIs use
/// this to track pending swaps for a specific token.
pub async fn pool_txs_by_token_id_handler(
    State(q): State<Arc<dyn NodeChainQuery>>,
    body: Bytes,
) -> Response {
    let id = match parse_id_body(&body, "tokenId") {
        Ok(b) => b,
        Err(resp) => return *resp,
    };
    Json(q.pool_txs_by_token_id(&id)).into_response()
}

/// `POST /transactions/unconfirmed/byRegisters` — pool txs with
/// at least one output whose `additionalRegisters` map contains
/// every (name, hex) pair in the request. Body shape:
/// `{"R4": "0e2010..", "R5": "..."}`. Protocol indexers use this
/// to track pending txs that touch a specific register value
/// (e.g. an oracle box update).
pub async fn pool_txs_by_registers_handler(
    State(q): State<Arc<dyn NodeChainQuery>>,
    body: Bytes,
) -> Response {
    let registers: BTreeMap<String, String> = match serde_json::from_slice(&body) {
        Ok(m) => m,
        Err(e) => {
            return api_error_400("deserialize", Some(format!("invalid registers map: {e}")));
        }
    };
    Json(q.pool_txs_by_registers(&registers)).into_response()
}

#[derive(Deserialize)]
pub struct PoolHistogramParams {
    pub bins: Option<u32>,
    pub maxtime: Option<u64>,
}

/// `GET /transactions/poolHistogram?bins=&maxtime=` — wait-time
/// histogram of the pool. Bare JSON array of `ScalaFeeHistogramBin`.
/// OpenAPI defaults: `bins=10`, `maxtime=60000` (ms).
pub async fn pool_fee_histogram_handler(
    State(q): State<Arc<dyn NodeChainQuery>>,
    Query(p): Query<PoolHistogramParams>,
) -> Response {
    let bins = p.bins.unwrap_or(10);
    let maxtime = p.maxtime.unwrap_or(60_000);
    Json(q.pool_fee_histogram(bins, maxtime)).into_response()
}

#[derive(Deserialize)]
pub struct PoolFeeParams {
    #[serde(rename = "waitTime")]
    pub wait_time: Option<u32>,
    #[serde(rename = "txSize")]
    pub tx_size: Option<u32>,
}

/// `GET /transactions/getFee?waitTime=<minutes>&txSize=<bytes>` —
/// recommended fee in nanoErgs. Bare JSON integer response.
/// Defaults match the Scala OpenAPI: `waitTime=1`, `txSize=100`.
pub async fn pool_recommended_fee_handler(
    State(q): State<Arc<dyn NodeChainQuery>>,
    Query(p): Query<PoolFeeParams>,
) -> Response {
    let wait = p.wait_time.unwrap_or(1);
    let size = p.tx_size.unwrap_or(100);
    Json(q.pool_recommended_fee(wait, size)).into_response()
}

#[derive(Deserialize)]
pub struct PoolWaitParams {
    pub fee: Option<u64>,
    #[serde(rename = "txSize")]
    pub tx_size: Option<u32>,
}

/// `GET /transactions/waitTime?fee=<nanoErgs>&txSize=<bytes>` —
/// expected wait in milliseconds. Bare JSON integer response.
/// Defaults match the Scala OpenAPI: `fee=1`, `txSize=100`.
pub async fn pool_wait_time_handler(
    State(q): State<Arc<dyn NodeChainQuery>>,
    Query(p): Query<PoolWaitParams>,
) -> Response {
    let fee = p.fee.unwrap_or(1);
    let size = p.tx_size.unwrap_or(100);
    Json(q.pool_expected_wait_time_ms(fee, size)).into_response()
}

/// `/utxo/byId/{boxId}` — single UTXO by id. Scala wraps the lookup in
/// `ApiResponse(Option)` (`UtxoApiRoute.scala:65-71`), so `None` →
/// 404 with the standard error envelope. Malformed-hex ids fail
/// `parse_box_id` upstream and surface as 404 too — matching Scala's
/// `Base16.decode(id).get` which throws on bad hex and bubbles up as a
/// not-found, not a 400.
pub async fn utxo_box_by_id_handler(
    State(q): State<Arc<dyn NodeChainQuery>>,
    Path(box_id): Path<String>,
) -> Response {
    match q.utxo_box_by_id(&box_id) {
        Some(out) => Json(out).into_response(),
        None => not_found("utxo box not found"),
    }
}

/// `/utxo/byIdBinary/{boxId}` — `{boxId, bytes}` envelope.
/// Same `Option` semantics as `byId` (`UtxoApiRoute.scala:73-85`).
pub async fn utxo_box_bytes_by_id_handler(
    State(q): State<Arc<dyn NodeChainQuery>>,
    Path(box_id): Path<String>,
) -> Response {
    match q.utxo_box_bytes_by_id(&box_id) {
        Some(env) => Json(env).into_response(),
        None => not_found("utxo box not found"),
    }
}

/// `/utxo/genesis` — the genesis state boxes. Scala returns a non-Optional
/// `Seq[ErgoBox]` (`UtxoApiRoute.scala:87-89`,
/// `ErgoState.scala:262-264`); the route always emits 200, even for an
/// (unreachable in practice) empty vector.
pub async fn utxo_genesis_handler(State(q): State<Arc<dyn NodeChainQuery>>) -> Response {
    Json(q.utxo_genesis_boxes()).into_response()
}

/// `/utxo/withPool/byId/{boxId}` — committed UTXO + mempool overlay.
/// Same `Option`/404 envelope as `/utxo/byId`; the bridge consults the
/// chain store first, then falls back to the snapshot's pool overlay.
pub async fn utxo_with_pool_box_by_id_handler(
    State(q): State<Arc<dyn NodeChainQuery>>,
    Path(box_id): Path<String>,
) -> Response {
    match q.utxo_with_pool_box_by_id(&box_id) {
        Some(out) => Json(out).into_response(),
        None => not_found("utxo box not found"),
    }
}

/// `/utxo/withPool/byIdBinary/{boxId}` — `{boxId, bytes}` envelope with
/// mempool overlay. Same `None` rules as `byIdBinary`.
pub async fn utxo_with_pool_box_bytes_by_id_handler(
    State(q): State<Arc<dyn NodeChainQuery>>,
    Path(box_id): Path<String>,
) -> Response {
    match q.utxo_with_pool_box_bytes_by_id(&box_id) {
        Some(env) => Json(env).into_response(),
        None => not_found("utxo box not found"),
    }
}

/// `POST /utxo/withPool/byIds` — batch overlay lookup. Always 200 with a
/// JSON array of resolved boxes; misses are silently dropped to match
/// Scala's `flatMap`-based filtering (`UtxoApiRoute.scala:41-48`).
pub async fn utxo_with_pool_boxes_by_ids_handler(
    State(q): State<Arc<dyn NodeChainQuery>>,
    Json(ids): Json<Vec<String>>,
) -> Response {
    Json(q.utxo_with_pool_boxes_by_ids(&ids)).into_response()
}
