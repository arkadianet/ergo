use super::super::*;

#[utoipa::path(
    get,
    path = "/blockchain/indexedHeight",
    tag = "blockchain",
    responses(
        (status = 200, description = "Current indexed height", body = IndexedHeightResponse)
    )
)]
/// `GET /blockchain/indexedHeight` — current indexed height vs full chain height.
pub(crate) async fn indexed_height_handler(
    State(state): State<ApiState>,
) -> Result<Json<IndexedHeightResponse>, (StatusCode, String)> {
    let db = require_indexer(&state)?;
    let indexed = ergo_indexer::queries::indexed_height(db)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let shared = state.shared.read().await;
    Ok(Json(IndexedHeightResponse {
        indexed_height: indexed,
        full_height: shared.full_height as u32,
    }))
}

#[utoipa::path(
    get,
    path = "/blockchain/transaction/byId/{id}",
    tag = "blockchain",
    params(
        ("id" = String, Path, description = "Transaction ID (hex)")
    ),
    responses(
        (status = 200, description = "Indexed transaction", body = IndexedErgoTransactionResponse),
        (status = 404, description = "Transaction not found")
    )
)]
/// `GET /blockchain/transaction/byId/{id}` — look up an indexed transaction by ID.
pub(crate) async fn blockchain_tx_by_id_handler(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<IndexedErgoTransactionResponse>, (StatusCode, String)> {
    let db = require_indexer(&state)?;
    let tx_id = hex_to_32bytes(&id)?;
    let tx = ergo_indexer::queries::get_tx(db, &tx_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "Transaction not found".into()))?;
    let shared = state.shared.read().await;
    Ok(Json(tx_to_response(
        &tx,
        db,
        shared.full_height as u32,
        &state.network,
        &state.history,
    )))
}

#[utoipa::path(
    get,
    path = "/blockchain/transaction/byIndex/{n}",
    tag = "blockchain",
    params(
        ("n" = u64, Path, description = "Global transaction index")
    ),
    responses(
        (status = 200, description = "Indexed transaction", body = IndexedErgoTransactionResponse),
        (status = 404, description = "Transaction not found")
    )
)]
/// `GET /blockchain/transaction/byIndex/{n}` — look up an indexed transaction by global index.
pub(crate) async fn blockchain_tx_by_index_handler(
    State(state): State<ApiState>,
    Path(n): Path<u64>,
) -> Result<Json<IndexedErgoTransactionResponse>, (StatusCode, String)> {
    let db = require_indexer(&state)?;
    let tx = ergo_indexer::queries::get_tx_by_index(db, n)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "Transaction not found".into()))?;
    let shared = state.shared.read().await;
    Ok(Json(tx_to_response(
        &tx,
        db,
        shared.full_height as u32,
        &state.network,
        &state.history,
    )))
}

#[utoipa::path(
    post,
    path = "/blockchain/transaction/byAddress",
    tag = "blockchain",
    request_body = String,
    params(
        ("offset" = Option<u32>, Query, description = "Offset"),
        ("limit" = Option<u32>, Query, description = "Limit"),
        ("sortDirection" = Option<String>, Query, description = "Sort direction (asc/desc)")
    ),
    responses(
        (status = 200, description = "Paginated transactions for address", body = PaginatedTxResponse)
    )
)]
/// `POST /blockchain/transaction/byAddress` — transactions for an address (body = address string).
pub(crate) async fn blockchain_txs_by_address_post_handler(
    State(state): State<ApiState>,
    Query(params): Query<BlockchainPaginationParams>,
    body: String,
) -> Result<Json<PaginatedTxResponse>, (StatusCode, String)> {
    let db = require_indexer(&state)?;
    let ergo_tree = address_to_ergo_tree(body.trim(), &state.network)?;
    let sort_desc = params.sort_direction.as_deref() != Some("asc");
    let (txs, total) = ergo_indexer::queries::txs_by_address(
        db,
        &ergo_tree,
        params.offset,
        params.limit,
        sort_desc,
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let shared = state.shared.read().await;
    let height = shared.full_height as u32;
    let items = txs
        .iter()
        .map(|tx| tx_to_response(tx, db, height, &state.network, &state.history))
        .collect();
    Ok(Json(PaginatedTxResponse { items, total }))
}

#[utoipa::path(
    get,
    path = "/blockchain/transaction/byAddress/{addr}",
    tag = "blockchain",
    params(
        ("addr" = String, Path, description = "Ergo address"),
        ("offset" = Option<u32>, Query, description = "Offset"),
        ("limit" = Option<u32>, Query, description = "Limit"),
        ("sortDirection" = Option<String>, Query, description = "Sort direction (asc/desc)")
    ),
    responses(
        (status = 200, description = "Paginated transactions for address", body = PaginatedTxResponse)
    )
)]
/// `GET /blockchain/transaction/byAddress/{addr}` — transactions for an address (path param).
pub(crate) async fn blockchain_txs_by_address_get_handler(
    State(state): State<ApiState>,
    Path(addr): Path<String>,
    Query(params): Query<BlockchainPaginationParams>,
) -> Result<Json<PaginatedTxResponse>, (StatusCode, String)> {
    let db = require_indexer(&state)?;
    let ergo_tree = address_to_ergo_tree(&addr, &state.network)?;
    let sort_desc = params.sort_direction.as_deref() != Some("asc");
    let (txs, total) = ergo_indexer::queries::txs_by_address(
        db,
        &ergo_tree,
        params.offset,
        params.limit,
        sort_desc,
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let shared = state.shared.read().await;
    let height = shared.full_height as u32;
    let items = txs
        .iter()
        .map(|tx| tx_to_response(tx, db, height, &state.network, &state.history))
        .collect();
    Ok(Json(PaginatedTxResponse { items, total }))
}

#[utoipa::path(
    get,
    path = "/blockchain/transaction/range",
    tag = "blockchain",
    params(
        ("offset" = Option<u32>, Query, description = "Offset"),
        ("limit" = Option<u32>, Query, description = "Limit")
    ),
    responses(
        (status = 200, description = "Transaction IDs in range", body = Vec<String>)
    )
)]
/// `GET /blockchain/transaction/range?offset=0&limit=5` — range of tx IDs by global index.
pub(crate) async fn blockchain_tx_range_handler(
    State(state): State<ApiState>,
    Query(params): Query<BlockchainPaginationParams>,
) -> Result<Json<Vec<String>>, (StatusCode, String)> {
    let db = require_indexer(&state)?;
    let ids = ergo_indexer::queries::tx_id_range(db, params.offset as u64, params.limit)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(ids.into_iter().map(hex::encode).collect()))
}

#[utoipa::path(
    get,
    path = "/blockchain/box/byId/{id}",
    tag = "blockchain",
    params(
        ("id" = String, Path, description = "Box ID (hex)")
    ),
    responses(
        (status = 200, description = "Indexed box", body = IndexedErgoBoxResponse),
        (status = 404, description = "Box not found")
    )
)]
/// `GET /blockchain/box/byId/{id}` — single box lookup.
pub(crate) async fn blockchain_box_by_id_handler(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<IndexedErgoBoxResponse>, (StatusCode, Json<ApiError>)> {
    let db = require_indexer(&state).map_err(|(status, msg)| api_error(status, &msg))?;
    let box_id = hex_to_32bytes(&id).map_err(|(status, msg)| api_error(status, &msg))?;
    let b = ergo_indexer::queries::get_box(db, &box_id)
        .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "Box not found"))?;
    Ok(Json(box_to_response(&b, &state.network)))
}

#[utoipa::path(
    get,
    path = "/blockchain/box/byIndex/{n}",
    tag = "blockchain",
    params(
        ("n" = u64, Path, description = "Global box index")
    ),
    responses(
        (status = 200, description = "Indexed box", body = IndexedErgoBoxResponse),
        (status = 404, description = "Box not found")
    )
)]
/// `GET /blockchain/box/byIndex/{n}` — box by global index.
pub(crate) async fn blockchain_box_by_index_handler(
    State(state): State<ApiState>,
    Path(n): Path<u64>,
) -> Result<Json<IndexedErgoBoxResponse>, (StatusCode, String)> {
    let db = require_indexer(&state)?;
    let b = ergo_indexer::queries::get_box_by_index(db, n)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "Box not found".into()))?;
    Ok(Json(box_to_response(&b, &state.network)))
}

#[utoipa::path(
    get,
    path = "/blockchain/box/byTokenId/{id}",
    tag = "blockchain",
    params(
        ("id" = String, Path, description = "Token ID (hex)"),
        ("offset" = Option<u32>, Query, description = "Offset"),
        ("limit" = Option<u32>, Query, description = "Limit"),
        ("sortDirection" = Option<String>, Query, description = "Sort direction")
    ),
    responses(
        (status = 200, description = "Boxes containing token", body = PaginatedBoxResponse)
    )
)]
/// `GET /blockchain/box/byTokenId/{id}` — boxes containing token (paginated).
pub(crate) async fn blockchain_boxes_by_token_handler(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Query(params): Query<BlockchainPaginationParams>,
) -> Result<Json<PaginatedBoxResponse>, (StatusCode, String)> {
    let db = require_indexer(&state)?;
    let token_id_arr = hex_to_32bytes(&id)?;
    let token_id = ModifierId(token_id_arr);
    let sort_desc = params.sort_direction.as_deref() != Some("asc");
    let (boxes, total) = ergo_indexer::queries::boxes_by_token(
        db,
        &token_id,
        params.offset,
        params.limit,
        false,
        sort_desc,
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let items = boxes
        .iter()
        .map(|b| box_to_response(b, &state.network))
        .collect();
    Ok(Json(PaginatedBoxResponse { items, total }))
}

#[utoipa::path(
    get,
    path = "/blockchain/box/unspent/byTokenId/{id}",
    tag = "blockchain",
    params(
        ("id" = String, Path, description = "Token ID (hex)"),
        ("offset" = Option<u32>, Query, description = "Offset"),
        ("limit" = Option<u32>, Query, description = "Limit"),
        ("sortDirection" = Option<String>, Query, description = "Sort direction"),
        ("includeUnconfirmed" = Option<bool>, Query, description = "Include unconfirmed"),
        ("excludeMempoolSpent" = Option<bool>, Query, description = "Exclude mempool spent")
    ),
    responses(
        (status = 200, description = "Unspent boxes with token", body = PaginatedBoxResponse)
    )
)]
/// `GET /blockchain/box/unspent/byTokenId/{id}` — unspent boxes with token (paginated, mempool params).
pub(crate) async fn blockchain_unspent_boxes_by_token_handler(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Query(params): Query<UnspentBoxParams>,
) -> Result<Json<PaginatedBoxResponse>, (StatusCode, String)> {
    let db = require_indexer(&state)?;
    let token_id_arr = hex_to_32bytes(&id)?;
    let token_id = ModifierId(token_id_arr);
    let sort_desc = params.sort_direction.as_deref() != Some("asc");
    let (boxes, total) = ergo_indexer::queries::boxes_by_token(
        db,
        &token_id,
        params.offset,
        params.limit,
        true,
        sort_desc,
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let mut items: Vec<IndexedErgoBoxResponse> = boxes
        .iter()
        .map(|b| box_to_response(b, &state.network))
        .collect();
    let mut total = total;
    let mp = state.mempool.read().unwrap();
    apply_mempool_box_filters(&mut items, &mut total, &mp, &params, None, &state.network);
    Ok(Json(PaginatedBoxResponse { items, total }))
}

#[utoipa::path(
    post,
    path = "/blockchain/box/byAddress",
    tag = "blockchain",
    request_body = String,
    params(
        ("offset" = Option<u32>, Query, description = "Offset"),
        ("limit" = Option<u32>, Query, description = "Limit"),
        ("sortDirection" = Option<String>, Query, description = "Sort direction")
    ),
    responses(
        (status = 200, description = "Boxes for address", body = PaginatedBoxResponse)
    )
)]
/// `POST /blockchain/box/byAddress` — boxes for address (body: address string, paginated).
pub(crate) async fn blockchain_boxes_by_address_post_handler(
    State(state): State<ApiState>,
    Query(params): Query<BlockchainPaginationParams>,
    body: String,
) -> Result<Json<PaginatedBoxResponse>, (StatusCode, String)> {
    let db = require_indexer(&state)?;
    let ergo_tree = address_to_ergo_tree(body.trim(), &state.network)?;
    let sort_desc = params.sort_direction.as_deref() != Some("asc");
    let (boxes, total) = ergo_indexer::queries::boxes_by_address(
        db,
        &ergo_tree,
        params.offset,
        params.limit,
        false,
        sort_desc,
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let items = boxes
        .iter()
        .map(|b| box_to_response(b, &state.network))
        .collect();
    Ok(Json(PaginatedBoxResponse { items, total }))
}

#[utoipa::path(
    get,
    path = "/blockchain/box/byAddress/{addr}",
    tag = "blockchain",
    params(
        ("addr" = String, Path, description = "Ergo address"),
        ("offset" = Option<u32>, Query, description = "Offset"),
        ("limit" = Option<u32>, Query, description = "Limit"),
        ("sortDirection" = Option<String>, Query, description = "Sort direction")
    ),
    responses(
        (status = 200, description = "Boxes for address", body = PaginatedBoxResponse)
    )
)]
/// `GET /blockchain/box/byAddress/{addr}` — boxes for address (path variant, paginated).
pub(crate) async fn blockchain_boxes_by_address_get_handler(
    State(state): State<ApiState>,
    Path(addr): Path<String>,
    Query(params): Query<BlockchainPaginationParams>,
) -> Result<Json<PaginatedBoxResponse>, (StatusCode, String)> {
    let db = require_indexer(&state)?;
    let ergo_tree = address_to_ergo_tree(&addr, &state.network)?;
    let sort_desc = params.sort_direction.as_deref() != Some("asc");
    let (boxes, total) = ergo_indexer::queries::boxes_by_address(
        db,
        &ergo_tree,
        params.offset,
        params.limit,
        false,
        sort_desc,
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let items = boxes
        .iter()
        .map(|b| box_to_response(b, &state.network))
        .collect();
    Ok(Json(PaginatedBoxResponse { items, total }))
}

#[utoipa::path(
    post,
    path = "/blockchain/box/unspent/byAddress",
    tag = "blockchain",
    request_body = String,
    params(
        ("offset" = Option<u32>, Query, description = "Offset"),
        ("limit" = Option<u32>, Query, description = "Limit"),
        ("sortDirection" = Option<String>, Query, description = "Sort direction"),
        ("includeUnconfirmed" = Option<bool>, Query, description = "Include unconfirmed"),
        ("excludeMempoolSpent" = Option<bool>, Query, description = "Exclude mempool spent")
    ),
    responses(
        (status = 200, description = "Unspent boxes for address", body = PaginatedBoxResponse)
    )
)]
/// `POST /blockchain/box/unspent/byAddress` — unspent boxes for address (paginated, mempool params).
pub(crate) async fn blockchain_unspent_boxes_by_address_post_handler(
    State(state): State<ApiState>,
    Query(params): Query<UnspentBoxParams>,
    body: String,
) -> Result<Json<PaginatedBoxResponse>, (StatusCode, String)> {
    let db = require_indexer(&state)?;
    let ergo_tree = address_to_ergo_tree(body.trim(), &state.network)?;
    let sort_desc = params.sort_direction.as_deref() != Some("asc");
    let (boxes, total) = ergo_indexer::queries::boxes_by_address(
        db,
        &ergo_tree,
        params.offset,
        params.limit,
        true,
        sort_desc,
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let mut items: Vec<IndexedErgoBoxResponse> = boxes
        .iter()
        .map(|b| box_to_response(b, &state.network))
        .collect();
    let mut total = total;
    let mp = state.mempool.read().unwrap();
    apply_mempool_box_filters(
        &mut items,
        &mut total,
        &mp,
        &params,
        Some(&ergo_tree),
        &state.network,
    );
    Ok(Json(PaginatedBoxResponse { items, total }))
}

#[utoipa::path(
    get,
    path = "/blockchain/box/unspent/byAddress/{addr}",
    tag = "blockchain",
    params(
        ("addr" = String, Path, description = "Ergo address"),
        ("offset" = Option<u32>, Query, description = "Offset"),
        ("limit" = Option<u32>, Query, description = "Limit"),
        ("sortDirection" = Option<String>, Query, description = "Sort direction"),
        ("includeUnconfirmed" = Option<bool>, Query, description = "Include unconfirmed"),
        ("excludeMempoolSpent" = Option<bool>, Query, description = "Exclude mempool spent")
    ),
    responses(
        (status = 200, description = "Unspent boxes for address", body = PaginatedBoxResponse)
    )
)]
/// `GET /blockchain/box/unspent/byAddress/{addr}` — unspent boxes for address (path variant, paginated, mempool params).
pub(crate) async fn blockchain_unspent_boxes_by_address_get_handler(
    State(state): State<ApiState>,
    Path(addr): Path<String>,
    Query(params): Query<UnspentBoxParams>,
) -> Result<Json<PaginatedBoxResponse>, (StatusCode, String)> {
    let db = require_indexer(&state)?;
    let ergo_tree = address_to_ergo_tree(&addr, &state.network)?;
    let sort_desc = params.sort_direction.as_deref() != Some("asc");
    let (boxes, total) = ergo_indexer::queries::boxes_by_address(
        db,
        &ergo_tree,
        params.offset,
        params.limit,
        true,
        sort_desc,
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let mut items: Vec<IndexedErgoBoxResponse> = boxes
        .iter()
        .map(|b| box_to_response(b, &state.network))
        .collect();
    let mut total = total;
    let mp = state.mempool.read().unwrap();
    apply_mempool_box_filters(
        &mut items,
        &mut total,
        &mp,
        &params,
        Some(&ergo_tree),
        &state.network,
    );
    Ok(Json(PaginatedBoxResponse { items, total }))
}

#[utoipa::path(
    get,
    path = "/blockchain/box/byTemplateHash/{hash}",
    tag = "blockchain",
    params(
        ("hash" = String, Path, description = "Template hash (hex)"),
        ("offset" = Option<u32>, Query, description = "Offset"),
        ("limit" = Option<u32>, Query, description = "Limit"),
        ("sortDirection" = Option<String>, Query, description = "Sort direction")
    ),
    responses(
        (status = 200, description = "Boxes by template hash", body = PaginatedBoxResponse)
    )
)]
/// `GET /blockchain/box/byTemplateHash/{hash}` — boxes by contract template (paginated).
pub(crate) async fn blockchain_boxes_by_template_handler(
    State(state): State<ApiState>,
    Path(hash): Path<String>,
    Query(params): Query<BlockchainPaginationParams>,
) -> Result<Json<PaginatedBoxResponse>, (StatusCode, String)> {
    let db = require_indexer(&state)?;
    let template_hash =
        hex::decode(&hash).map_err(|_| (StatusCode::BAD_REQUEST, "Invalid hex string".into()))?;
    let sort_desc = params.sort_direction.as_deref() != Some("asc");
    let (boxes, total) = ergo_indexer::queries::boxes_by_template(
        db,
        &template_hash,
        params.offset,
        params.limit,
        false,
        sort_desc,
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let items = boxes
        .iter()
        .map(|b| box_to_response(b, &state.network))
        .collect();
    Ok(Json(PaginatedBoxResponse { items, total }))
}

#[utoipa::path(
    get,
    path = "/blockchain/box/unspent/byTemplateHash/{hash}",
    tag = "blockchain",
    params(
        ("hash" = String, Path, description = "Template hash (hex)"),
        ("offset" = Option<u32>, Query, description = "Offset"),
        ("limit" = Option<u32>, Query, description = "Limit"),
        ("sortDirection" = Option<String>, Query, description = "Sort direction"),
        ("includeUnconfirmed" = Option<bool>, Query, description = "Include unconfirmed"),
        ("excludeMempoolSpent" = Option<bool>, Query, description = "Exclude mempool spent")
    ),
    responses(
        (status = 200, description = "Unspent boxes by template", body = PaginatedBoxResponse)
    )
)]
/// `GET /blockchain/box/unspent/byTemplateHash/{hash}` — unspent boxes by template (paginated, mempool params).
pub(crate) async fn blockchain_unspent_boxes_by_template_handler(
    State(state): State<ApiState>,
    Path(hash): Path<String>,
    Query(params): Query<UnspentBoxParams>,
) -> Result<Json<PaginatedBoxResponse>, (StatusCode, String)> {
    let db = require_indexer(&state)?;
    let template_hash =
        hex::decode(&hash).map_err(|_| (StatusCode::BAD_REQUEST, "Invalid hex string".into()))?;
    let sort_desc = params.sort_direction.as_deref() != Some("asc");
    let (boxes, total) = ergo_indexer::queries::boxes_by_template(
        db,
        &template_hash,
        params.offset,
        params.limit,
        true,
        sort_desc,
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let mut items: Vec<IndexedErgoBoxResponse> = boxes
        .iter()
        .map(|b| box_to_response(b, &state.network))
        .collect();
    let mut total = total;
    let mp = state.mempool.read().unwrap();
    apply_mempool_box_filters(&mut items, &mut total, &mp, &params, None, &state.network);
    Ok(Json(PaginatedBoxResponse { items, total }))
}

#[utoipa::path(
    get,
    path = "/blockchain/box/range",
    tag = "blockchain",
    params(
        ("offset" = Option<u32>, Query, description = "Offset"),
        ("limit" = Option<u32>, Query, description = "Limit")
    ),
    responses(
        (status = 200, description = "Box IDs in range", body = Vec<String>)
    )
)]
/// `GET /blockchain/box/range` — box IDs by global index range.
pub(crate) async fn blockchain_box_range_handler(
    State(state): State<ApiState>,
    Query(params): Query<BlockchainPaginationParams>,
) -> Result<Json<Vec<String>>, (StatusCode, String)> {
    let db = require_indexer(&state)?;
    let ids = ergo_indexer::queries::box_id_range(db, params.offset as u64, params.limit)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(ids.into_iter().map(hex::encode).collect()))
}

#[utoipa::path(
    post,
    path = "/blockchain/box/byErgoTree",
    tag = "blockchain",
    request_body = String,
    params(
        ("offset" = Option<u32>, Query, description = "Offset"),
        ("limit" = Option<u32>, Query, description = "Limit"),
        ("sortDirection" = Option<String>, Query, description = "Sort direction")
    ),
    responses(
        (status = 200, description = "Boxes by ErgoTree", body = PaginatedBoxResponse)
    )
)]
/// `POST /blockchain/box/byErgoTree` — boxes by ErgoTree hex body (paginated).
pub(crate) async fn blockchain_boxes_by_ergo_tree_handler(
    State(state): State<ApiState>,
    Query(params): Query<BlockchainPaginationParams>,
    body: String,
) -> Result<Json<PaginatedBoxResponse>, (StatusCode, String)> {
    let db = require_indexer(&state)?;
    let ergo_tree = hex::decode(body.trim())
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid hex ErgoTree".into()))?;
    let sort_desc = params.sort_direction.as_deref() != Some("asc");
    let (boxes, total) = ergo_indexer::queries::boxes_by_address(
        db,
        &ergo_tree,
        params.offset,
        params.limit,
        false,
        sort_desc,
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let items = boxes
        .iter()
        .map(|b| box_to_response(b, &state.network))
        .collect();
    Ok(Json(PaginatedBoxResponse { items, total }))
}

#[utoipa::path(
    post,
    path = "/blockchain/box/unspent/byErgoTree",
    tag = "blockchain",
    request_body = String,
    params(
        ("offset" = Option<u32>, Query, description = "Offset"),
        ("limit" = Option<u32>, Query, description = "Limit"),
        ("sortDirection" = Option<String>, Query, description = "Sort direction"),
        ("includeUnconfirmed" = Option<bool>, Query, description = "Include unconfirmed"),
        ("excludeMempoolSpent" = Option<bool>, Query, description = "Exclude mempool spent")
    ),
    responses(
        (status = 200, description = "Unspent boxes by ErgoTree", body = PaginatedBoxResponse)
    )
)]
/// `POST /blockchain/box/unspent/byErgoTree` — unspent by ErgoTree hex (paginated, mempool params).
pub(crate) async fn blockchain_unspent_boxes_by_ergo_tree_handler(
    State(state): State<ApiState>,
    Query(params): Query<UnspentBoxParams>,
    body: String,
) -> Result<Json<PaginatedBoxResponse>, (StatusCode, String)> {
    let db = require_indexer(&state)?;
    let ergo_tree = hex::decode(body.trim())
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid hex ErgoTree".into()))?;
    let sort_desc = params.sort_direction.as_deref() != Some("asc");
    let (boxes, total) = ergo_indexer::queries::boxes_by_address(
        db,
        &ergo_tree,
        params.offset,
        params.limit,
        true,
        sort_desc,
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let mut items: Vec<IndexedErgoBoxResponse> = boxes
        .iter()
        .map(|b| box_to_response(b, &state.network))
        .collect();
    let mut total = total;
    let mp = state.mempool.read().unwrap();
    apply_mempool_box_filters(
        &mut items,
        &mut total,
        &mp,
        &params,
        Some(&ergo_tree),
        &state.network,
    );
    Ok(Json(PaginatedBoxResponse { items, total }))
}

#[utoipa::path(
    get,
    path = "/blockchain/token/byId/{id}",
    tag = "blockchain",
    params(
        ("id" = String, Path, description = "Token ID (hex)")
    ),
    responses(
        (status = 200, description = "Token metadata", body = IndexedTokenResponse),
        (status = 404, description = "Token not found")
    )
)]
/// `GET /blockchain/token/byId/{id}` — single token metadata.
pub(crate) async fn blockchain_token_by_id_handler(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<IndexedTokenResponse>, (StatusCode, String)> {
    let db = require_indexer(&state)?;
    let token_id_bytes = hex_to_32bytes(&id)?;
    let token_id = ModifierId(token_id_bytes);
    let token = ergo_indexer::queries::get_token(db, &token_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "Token not found".into()))?;
    Ok(Json(token_to_response(&token)))
}

#[utoipa::path(
    post,
    path = "/blockchain/tokens",
    tag = "blockchain",
    request_body = Vec<String>,
    responses(
        (status = 200, description = "Batch token metadata", body = Vec<IndexedTokenResponse>)
    )
)]
/// `POST /blockchain/tokens` — batch token lookup.
pub(crate) async fn blockchain_tokens_handler(
    State(state): State<ApiState>,
    Json(ids): Json<Vec<String>>,
) -> Result<Json<Vec<IndexedTokenResponse>>, (StatusCode, String)> {
    let db = require_indexer(&state)?;
    let mut results = Vec::new();
    for id_hex in &ids {
        let token_id_bytes = hex_to_32bytes(id_hex)?;
        let token_id = ModifierId(token_id_bytes);
        if let Some(token) = ergo_indexer::queries::get_token(db, &token_id)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        {
            results.push(token_to_response(&token));
        }
    }
    Ok(Json(results))
}

/// Build a [`BalanceResponse`] for the given address string.
pub(crate) async fn balance_for_address(
    state: &ApiState,
    addr: &str,
) -> Result<Json<BalanceResponse>, (StatusCode, String)> {
    let db = require_indexer(state)?;
    let ergo_tree = address_to_ergo_tree(addr, &state.network)?;

    // Confirmed balance from indexer
    let confirmed_balance = ergo_indexer::queries::balance_for_address(db, &ergo_tree)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let confirmed = match confirmed_balance {
        Some(b) => BalanceInfoResponse {
            nano_ergs: b.nano_ergs,
            tokens: b
                .tokens
                .iter()
                .map(|(id, amt)| {
                    let meta = ergo_indexer::queries::get_token(db, id).ok().flatten();
                    TokenBalanceResponse {
                        token_id: hex::encode(id.0),
                        amount: *amt,
                        decimals: meta.as_ref().and_then(|m| m.decimals),
                        name: meta.as_ref().and_then(|m| m.name.clone()),
                    }
                })
                .collect(),
        },
        None => BalanceInfoResponse {
            nano_ergs: 0,
            tokens: vec![],
        },
    };

    // Unconfirmed balance from mempool
    let unconfirmed = {
        let mempool = state.mempool.read().unwrap();
        let tree_hash = blake2b256(&ergo_tree);
        let unconf_outputs = mempool.find_outputs_by_tree_hash(&tree_hash);
        let mut nano_ergs: u64 = 0;
        let mut token_map: std::collections::HashMap<[u8; 32], u64> =
            std::collections::HashMap::new();
        for output_ref in &unconf_outputs {
            nano_ergs += output_ref.candidate.value;
            for (tok_id, amt) in &output_ref.candidate.tokens {
                *token_map.entry(tok_id.0).or_default() += amt;
            }
        }
        BalanceInfoResponse {
            nano_ergs,
            tokens: token_map
                .into_iter()
                .map(|(id, amt)| TokenBalanceResponse {
                    token_id: hex::encode(id),
                    amount: amt,
                    decimals: None,
                    name: None,
                })
                .collect(),
        }
    };

    Ok(Json(BalanceResponse {
        confirmed,
        unconfirmed,
    }))
}

#[utoipa::path(
    post,
    path = "/blockchain/balance",
    tag = "blockchain",
    request_body = String,
    responses(
        (status = 200, description = "Balance for address", body = BalanceResponse)
    )
)]
/// `POST /blockchain/balance` — balance for address (body = address string).
pub(crate) async fn blockchain_balance_post_handler(
    State(state): State<ApiState>,
    body: String,
) -> Result<Json<BalanceResponse>, (StatusCode, String)> {
    balance_for_address(&state, body.trim()).await
}

#[utoipa::path(
    get,
    path = "/blockchain/balanceForAddress/{addr}",
    tag = "blockchain",
    params(
        ("addr" = String, Path, description = "Ergo address")
    ),
    responses(
        (status = 200, description = "Balance for address", body = BalanceResponse)
    )
)]
/// `GET /blockchain/balanceForAddress/{addr}` — balance for address (path param).
pub(crate) async fn blockchain_balance_get_handler(
    State(state): State<ApiState>,
    Path(addr): Path<String>,
) -> Result<Json<BalanceResponse>, (StatusCode, String)> {
    balance_for_address(&state, &addr).await
}

#[utoipa::path(
    get,
    path = "/blockchain/block/byHeaderId/{id}",
    tag = "blockchain",
    params(
        ("id" = String, Path, description = "Header ID (hex)")
    ),
    responses(
        (status = 200, description = "Indexed block", body = IndexedBlockResponse),
        (status = 404, description = "Block not found")
    )
)]
/// `GET /blockchain/block/byHeaderId/{id}` — indexed block by header ID.
pub(crate) async fn blockchain_block_by_header_id_handler(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<IndexedBlockResponse>, (StatusCode, String)> {
    let db = require_indexer(&state)?;
    let header_id_bytes = hex_to_32bytes(&id)?;
    let header_id = ModifierId(header_id_bytes);

    let header = state
        .history
        .load_header(&header_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "Header not found".into()))?;

    let block_txs = state
        .history
        .load_block_transactions(&header_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "Block transactions not found".into()))?;

    let shared = state.shared.read().await;
    let current_height = shared.full_height as u32;
    drop(shared);

    Ok(Json(build_indexed_block_response(
        &state,
        db,
        &header,
        &block_txs,
        current_height,
    )))
}

#[utoipa::path(
    post,
    path = "/blockchain/block/byHeaderIds",
    tag = "blockchain",
    request_body = Vec<String>,
    responses(
        (status = 200, description = "Indexed blocks", body = Vec<IndexedBlockResponse>)
    )
)]
/// `POST /blockchain/block/byHeaderIds` — batch block lookup by header IDs.
pub(crate) async fn blockchain_block_by_header_ids_handler(
    State(state): State<ApiState>,
    Json(ids): Json<Vec<String>>,
) -> Result<Json<Vec<IndexedBlockResponse>>, (StatusCode, String)> {
    let db = require_indexer(&state)?;
    let shared = state.shared.read().await;
    let current_height = shared.full_height as u32;
    drop(shared);

    let mut results = Vec::new();
    for id_hex in &ids {
        let header_id_bytes = hex_to_32bytes(id_hex)?;
        let header_id = ModifierId(header_id_bytes);

        let header = match state.history.load_header(&header_id) {
            Ok(Some(h)) => h,
            _ => continue,
        };
        let block_txs = match state.history.load_block_transactions(&header_id) {
            Ok(Some(bt)) => bt,
            _ => continue,
        };

        results.push(build_indexed_block_response(
            &state,
            db,
            &header,
            &block_txs,
            current_height,
        ));
    }
    Ok(Json(results))
}
