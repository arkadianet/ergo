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
                // Add leading "/" to address to match Scala reference format.
                let address = format!("/{}", p.address);
                PeerResponse {
                    address,
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

/// `GET /peers/all` — all known peers from discovery + peer_db, Scala-compatible format.
#[utoipa::path(
    get,
    path = "/peers/all",
    tag = "peers",
    responses(
        (status = 200, description = "All known peers", body = Vec<PeerInfoResponse>)
    )
)]
pub(crate) async fn peers_all_handler(
    State(state): State<ApiState>,
) -> Json<Vec<PeerInfoResponse>> {
    let shared = state.shared.read().await;

    // Build a lookup from address string to connected peer info for lastHandshake / connectionType.
    let connected_map: std::collections::HashMap<String, &crate::event_loop::ConnectedPeerInfo> =
        shared
            .connected_peers
            .iter()
            .map(|p| (p.address.clone(), p))
            .collect();

    let peers = shared
        .known_peers
        .iter()
        .map(|addr| {
            // Address with leading "/" to match Scala reference format.
            let address = format!("/{}", addr);
            if let Some(conn) = connected_map.get(addr) {
                PeerInfoResponse {
                    address,
                    last_message: conn.last_message.unwrap_or(0),
                    last_handshake: conn.last_handshake,
                    name: conn.name.clone(),
                    connection_type: conn.connection_type.clone(),
                }
            } else {
                PeerInfoResponse {
                    address,
                    last_message: 0,
                    last_handshake: 0,
                    name: String::new(),
                    connection_type: None,
                }
            }
        })
        .collect();

    Json(peers)
}

/// `GET /peers/blacklisted` — blacklisted/banned peers, Scala-compatible format.
#[utoipa::path(
    get,
    path = "/peers/blacklisted",
    tag = "peers",
    responses(
        (status = 200, description = "Blacklisted peers", body = BlacklistedPeersResponse)
    )
)]
pub(crate) async fn peers_blacklisted_handler(
    State(state): State<ApiState>,
) -> Json<BlacklistedPeersResponse> {
    let shared = state.shared.read().await;
    // Convert peer IDs to address strings where possible. If no address is available,
    // fall back to the numeric ID as a string (Scala uses address strings here).
    let addresses: Vec<String> = shared
        .banned_peers
        .iter()
        .map(|id| id.to_string())
        .collect();
    Json(BlacklistedPeersResponse { addresses })
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

/// `GET /peers/status` — P2P layer status (Scala-compatible schema).
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
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    // last_message_time is stored as seconds; convert to milliseconds.
    let last_incoming_message = shared.last_message_time.unwrap_or(0) * 1000;
    Json(PeerStatusResponse {
        last_incoming_message,
        current_system_time: now_ms,
    })
}

/// `GET /peers/syncInfo` — per-peer sync status, Scala-compatible format.
#[utoipa::path(
    get,
    path = "/peers/syncInfo",
    tag = "peers",
    responses(
        (status = 200, description = "Per-peer sync status", body = Vec<PeerSyncInfoResponse>)
    )
)]
pub(crate) async fn peers_sync_info_handler(
    State(state): State<ApiState>,
) -> Json<Vec<PeerSyncInfoResponse>> {
    let shared = state.shared.read().await;
    let sync_map = build_sync_map(&shared);

    // Build a lookup from peer_id to ConnectedPeerInfo.
    let peer_map: std::collections::HashMap<u64, &crate::event_loop::ConnectedPeerInfo> = shared
        .connected_peers
        .iter()
        .map(|p| (p.peer_id, p))
        .collect();

    let mut result = Vec::new();
    for (&peer_id, (status_opt, height_opt)) in &sync_map {
        let status = status_opt.clone().unwrap_or_else(|| "Unknown".to_string());
        let height = height_opt.unwrap_or(0);

        if let Some(peer) = peer_map.get(&peer_id) {
            let address = format!("/{}", peer.address);
            let version = peer.version.clone().unwrap_or_default();
            let state_type = peer
                .state_type
                .clone()
                .unwrap_or_else(|| "utxo".to_string());
            let verifying_transactions = peer.verifying_transactions.unwrap_or(true);
            // blocks_to_keep: -1 means keep all blocks (full node), positive means suffix only.
            let full_blocks_suffix = peer.blocks_to_keep.unwrap_or(-1);

            result.push(PeerSyncInfoResponse {
                address,
                version,
                mode: PeerModeResponse {
                    state: state_type,
                    verifying_transactions,
                    full_blocks_suffix,
                },
                status,
                height,
            });
        }
    }

    Json(result)
}

/// `GET /peers/trackInfo` — DeliveryTracker state, Scala-compatible schema.
#[utoipa::path(
    get,
    path = "/peers/trackInfo",
    tag = "peers",
    responses(
        (status = 200, description = "Delivery tracker state", body = Object)
    )
)]
pub(crate) async fn peers_track_info_handler(
    State(_state): State<ApiState>,
) -> Json<serde_json::Value> {
    // Return the Scala-compatible schema:
    // { "invalidModifierApproxSize": 0, "requested": {type_id: {},...}, "received": {type_id: {},...} }
    // Type IDs: 101=Headers, 104=ADProofs, 108=Extension, 102=BlockTransactions, 2=Transaction
    let empty_map = serde_json::json!({
        "101": {},
        "104": {},
        "2": {},
        "108": {},
        "102": {}
    });
    Json(serde_json::json!({
        "invalidModifierApproxSize": 0,
        "requested": empty_map,
        "received": empty_map
    }))
}
