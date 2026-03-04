use super::super::*;

#[utoipa::path(
    get,
    path = "/info",
    tag = "info",
    responses(
        (status = 200, description = "Node information", body = NodeInfoResponse)
    )
)]
pub(crate) async fn info_handler(State(state): State<ApiState>) -> Json<NodeInfoResponse> {
    let unconfirmed_count = state.mempool.read().unwrap().size();
    let shared = state.shared.read().await;
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    // Normalize network name to lowercase for API response
    let network_lc = state.network.to_lowercase();
    let network_lower: &str = match network_lc.as_str() {
        "mainnet" => "mainnet",
        "testnet" => "testnet",
        "devnet" => "devnet",
        _ => "mainnet",
    };

    let genesis_id = match network_lower {
        "testnet" => "0000000000000000000000000000000000000000000000000000000000000000",
        _ => "b0244dfc267baca974a4caee06120321562784303a8a688976ae56170e4d175b",
    };

    // Heights of 0 mean no headers/blocks yet — report as null
    let headers_height = if shared.headers_height > 0 {
        Some(shared.headers_height)
    } else {
        None
    };
    let full_height = if shared.full_height > 0 {
        Some(shared.full_height)
    } else {
        None
    };
    let max_peer_height = if shared.max_peer_height > 0 {
        Some(shared.max_peer_height)
    } else {
        None
    };

    // Mining is enabled when a candidate generator has been initialized.
    let is_mining = shared.is_mining || state.candidate_generator.is_some();

    Json(NodeInfoResponse {
        name: state.node_name.clone(),
        app_version: state.app_version.clone(),
        network: network_lower.to_string(),
        headers_height,
        full_height,
        max_peer_height,
        best_header_id: shared.best_header_id.map(hex::encode),
        best_full_header_id: shared.best_full_block_id.map(hex::encode),
        previous_full_header_id: shared.previous_full_header_id.map(hex::encode),
        state_root: hex::encode(&shared.state_root),
        state_version: shared.state_version.map(hex::encode),
        state_type: state.state_type.clone(),
        peers_count: shared.peer_count,
        sync_state: shared.sync_state.clone(),
        unconfirmed_count,
        difficulty: shared.difficulty.clone(),
        headers_score: shared.headers_score.clone(),
        full_blocks_score: shared.full_blocks_score.clone(),
        launch_time: shared.start_time * 1000,
        last_seen_message_time: shared.last_message_time.unwrap_or(0),
        genesis_block_id: genesis_id.to_string(),
        is_mining,
        is_explorer: state.extra_db.is_some(),
        eip27_supported: true,
        eip37_supported: true,
        rest_api_url: None,
        current_time: now_ms,
        parameters: shared.parameters.clone(),
        last_mempool_update_time: shared.last_mempool_update_time,
        fast_sync_active: shared.fast_sync_active,
    })
}
