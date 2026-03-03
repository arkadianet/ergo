use super::super::*;

#[utoipa::path(
    get,
    path = "/peers/connected",
    tag = "peers",
    responses(
        (status = 200, description = "List of connected peers", body = Vec<PeerResponse>)
    )
)]
pub(crate) async fn peers_connected_handler(
    State(state): State<ApiState>,
) -> Json<Vec<PeerResponse>> {
    let shared = state.shared.read().await;
    // Build a peer_id → (status, height) map from the sync tracker snapshot.
    let sync_map = build_sync_map(&shared);
    Json(
        shared
            .connected_peers
            .iter()
            .map(|p| {
                let (chain_status, height) =
                    sync_map.get(&p.peer_id).cloned().unwrap_or((None, None));
                let geo = parse_ip_from_addr(&p.address)
                    .and_then(|ip| state.geoip.as_ref().as_ref().and_then(|g| g.lookup(ip)));
                PeerResponse {
                    address: p.address.clone(),
                    name: p.name.clone(),
                    node_name: p.node_name.clone(),
                    last_message: p.last_message.unwrap_or(0),
                    last_handshake: p.last_handshake,
                    connection_type: p.connection_type.clone(),
                    version: p.version.clone(),
                    state_type: p.state_type.clone(),
                    verifying_transactions: p.verifying_transactions,
                    blocks_to_keep: p.blocks_to_keep,
                    chain_status,
                    height,
                    geo,
                }
            })
            .collect(),
    )
}

/// `GET /peers/map` — lightweight projection for map rendering.
#[utoipa::path(
    get,
    path = "/peers/map",
    tag = "peers",
    responses(
        (status = 200, description = "Peer map entries for rendering", body = Vec<PeerMapEntry>)
    )
)]
pub(crate) async fn peers_map_handler(State(state): State<ApiState>) -> Json<Vec<PeerMapEntry>> {
    let shared = state.shared.read().await;
    let sync_map = build_sync_map(&shared);
    let geoip = state.geoip.as_ref().as_ref();
    let mut entries = Vec::new();
    if let Some(geo) = geoip {
        for p in &shared.connected_peers {
            if let Some(ip) = parse_ip_from_addr(&p.address) {
                if let Some(info) = geo.lookup(ip) {
                    if let (Some(lat), Some(lon)) = (info.latitude, info.longitude) {
                        let chain_status = sync_map.get(&p.peer_id).and_then(|(s, _)| s.clone());
                        entries.push(PeerMapEntry {
                            lat,
                            lon,
                            country_code: info.country_code,
                            address: p.address.clone(),
                            name: p.name.clone(),
                            chain_status,
                        });
                    }
                }
            }
        }
    }
    Json(entries)
}

/// `GET /peers/all` — all known peers from discovery + peer_db.
#[utoipa::path(
    get,
    path = "/peers/all",
    tag = "peers",
    responses(
        (status = 200, description = "All known peer addresses", body = Vec<String>)
    )
)]
pub(crate) async fn peers_all_handler(State(state): State<ApiState>) -> Json<Vec<String>> {
    let shared = state.shared.read().await;
    Json(shared.known_peers.clone())
}

/// `GET /peers/blacklisted` — blacklisted/banned peer IDs from PenaltyManager.
#[utoipa::path(
    get,
    path = "/peers/blacklisted",
    tag = "peers",
    responses(
        (status = 200, description = "Blacklisted peer IDs", body = Vec<u64>)
    )
)]
pub(crate) async fn peers_blacklisted_handler(State(state): State<ApiState>) -> Json<Vec<u64>> {
    let shared = state.shared.read().await;
    Json(shared.banned_peers.clone())
}

/// `POST /peers/connect` — manually initiate connection to "host:port".
#[utoipa::path(
    post,
    path = "/peers/connect",
    tag = "peers",
    request_body = String,
    responses(
        (status = 200, description = "Connection initiated", body = Object),
        (status = 400, description = "Invalid address or unavailable")
    )
)]
pub(crate) async fn peers_connect_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
    Json(addr_str): Json<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let addr: std::net::SocketAddr = addr_str
        .parse()
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "Invalid socket address"))?;
    let sender = state.peer_connect.as_ref().ok_or_else(|| {
        api_error(
            StatusCode::BAD_REQUEST,
            "Peer connect channel not available",
        )
    })?;
    sender.try_send(addr).map_err(|_| {
        api_error(
            StatusCode::BAD_REQUEST,
            "Failed to send peer connect request",
        )
    })?;
    Ok(Json(
        serde_json::json!({ "status": "connecting", "address": addr.to_string() }),
    ))
}

/// `GET /peers/status` — P2P layer status.
#[utoipa::path(
    get,
    path = "/peers/status",
    tag = "peers",
    responses(
        (status = 200, description = "P2P layer status", body = PeerStatusResponse)
    )
)]
pub(crate) async fn peers_status_handler(
    State(state): State<ApiState>,
) -> Json<PeerStatusResponse> {
    let shared = state.shared.read().await;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    Json(PeerStatusResponse {
        connected_count: shared.peer_count,
        uptime_secs: now.saturating_sub(shared.start_time),
        last_message_time: shared.last_message_time,
    })
}

/// `GET /peers/syncInfo` — SyncTracker state dump.
#[utoipa::path(
    get,
    path = "/peers/syncInfo",
    tag = "peers",
    responses(
        (status = 200, description = "SyncTracker state dump", body = Object)
    )
)]
pub(crate) async fn peers_sync_info_handler(
    State(state): State<ApiState>,
) -> Json<serde_json::Value> {
    let shared = state.shared.read().await;
    Json(
        shared
            .sync_tracker_snapshot
            .clone()
            .unwrap_or_else(|| serde_json::json!({})),
    )
}

/// `GET /peers/trackInfo` — DeliveryTracker state dump.
#[utoipa::path(
    get,
    path = "/peers/trackInfo",
    tag = "peers",
    responses(
        (status = 200, description = "DeliveryTracker state dump", body = Object)
    )
)]
pub(crate) async fn peers_track_info_handler(
    State(state): State<ApiState>,
) -> Json<serde_json::Value> {
    let shared = state.shared.read().await;
    Json(
        shared
            .delivery_tracker_snapshot
            .clone()
            .unwrap_or_else(|| serde_json::json!({})),
    )
}
