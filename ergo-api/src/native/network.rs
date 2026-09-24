use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use ergo_api_core::error::ServiceError;
use ergo_api_core::network::{NetworkSnapshot, PeerRecord, PeerState, PeerSyncRecord};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use utoipa::IntoParams;

use super::dto;
use super::{error, NativeState};

pub const PEERS_DEFAULT_LIMIT: u32 = 256;
pub const PEERS_MAX_LIMIT: u32 = 1024;
pub const NETWORK_DEFAULT_LIMIT: u32 = 100;
pub const NETWORK_MAX_LIMIT: u32 = 500;

#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct PeerListQuery {
    #[param(minimum = 1, maximum = 1024, default = 256)]
    limit: Option<u32>,
    cursor: Option<String>,
}

#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct NetworkListQuery {
    #[param(minimum = 1, maximum = 500, default = 100)]
    limit: Option<u32>,
    cursor: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct NetworkOffsetCursor {
    off: u32,
}

fn invalid_query() -> Response {
    error::response(ServiceError::validation(
        "invalid_params",
        "query parameters are malformed",
    ))
}

fn invalid_cursor() -> Response {
    error::response(ServiceError::validation(
        "invalid_cursor",
        "pagination cursor is malformed",
    ))
}

fn list_query<Q>(query: Result<Query<Q>, QueryRejection>) -> Result<Q, Response>
where
    Q: DeserializeOwned,
{
    match query {
        Ok(Query(query)) => Ok(query),
        Err(_error) => Err(invalid_query()),
    }
}

fn page<T>(
    mut items: Vec<T>,
    requested_limit: Option<u32>,
    cursor: Option<&str>,
    default_limit: u32,
    max_limit: u32,
) -> Result<(Vec<T>, dto::NetworkPage), Response> {
    let limit = crate::v1::cursor::clamp_limit(requested_limit, default_limit, max_limit);
    let offset = match cursor {
        Some(value) => crate::v1::cursor::decode_cursor::<NetworkOffsetCursor>(value)
            .map(|cursor| cursor.off)
            .map_err(|_| invalid_cursor())?,
        None => 0,
    };
    let start = (offset as usize).min(items.len());
    let mut window = items
        .split_off(start)
        .into_iter()
        .take(limit as usize + 1)
        .collect::<Vec<_>>();
    let has_more = window.len() > limit as usize;
    if has_more {
        window.truncate(limit as usize);
    }
    let next_cursor = has_more.then(|| {
        crate::v1::cursor::encode_cursor(&NetworkOffsetCursor {
            off: offset.saturating_add(limit),
        })
    });
    Ok((
        window,
        dto::NetworkPage {
            limit,
            next_cursor,
            has_more,
        },
    ))
}

fn snapshot(state: &NativeState) -> Result<NetworkSnapshot, Response> {
    state
        .peers
        .as_ref()
        .map(|source| source.snapshot())
        .ok_or_else(|| {
            error::unavailable(
                "network_unavailable",
                "network peer reads are not wired on this node",
            )
        })
}

fn clean_blacklist_addr(raw: &str) -> String {
    raw.rsplit_once('/')
        .map_or_else(|| raw.to_string(), |(_, tail)| tail.to_string())
}

fn peer_view(peer: &PeerRecord) -> dto::NetworkPeerView {
    dto::NetworkPeerView {
        addr: peer.addr.clone(),
        direction: peer.direction.as_str().to_string(),
        state: peer.state.as_str().to_string(),
        score: peer.score,
        agent: peer.agent.clone(),
        node_name: peer.node_name.clone(),
        version: peer.version.clone(),
        sync_version: peer.sync_version.clone(),
        connected_seconds: peer.connected_seconds,
        last_seen_seconds: peer.last_seen_seconds,
        bytes_in: peer.bytes_in,
        bytes_out: peer.bytes_out,
        peer_height: peer.peer_height,
        rest_api_url: peer.rest_api_url.clone(),
        declared_address: peer.declared_address.clone(),
    }
}

fn sync_view(value: &PeerSyncRecord) -> Option<dto::NetworkSyncInfoView> {
    value
        .peer_height
        .map(|peer_height| dto::NetworkSyncInfoView {
            addr: value.addr.clone(),
            peer_height,
            status: value.status.as_str().to_string(),
        })
}

#[utoipa::path(
    get,
    path = "/api/v1/network/peers",
    tag = "network",
    params(PeerListQuery),
    responses(
        (status = 200, body = dto::NetworkPeerPage),
        (status = 400, body = error::ErrorEnvelope),
        (status = 503, body = error::ErrorEnvelope)
    )
)]
pub(crate) async fn peers(
    State(state): State<NativeState>,
    query: Result<Query<PeerListQuery>, QueryRejection>,
) -> Response {
    let query = match list_query(query) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let value = match snapshot(&state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let items = value.peers.iter().map(peer_view).collect();
    match page(
        items,
        query.limit,
        query.cursor.as_deref(),
        PEERS_DEFAULT_LIMIT,
        PEERS_MAX_LIMIT,
    ) {
        Ok((items, page)) => Json(dto::NetworkPeerPage { items, page }).into_response(),
        Err(response) => response,
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/network/connected",
    tag = "network",
    params(PeerListQuery),
    responses(
        (status = 200, body = dto::NetworkPeerPage),
        (status = 400, body = error::ErrorEnvelope),
        (status = 503, body = error::ErrorEnvelope)
    )
)]
pub(crate) async fn connected(
    State(state): State<NativeState>,
    query: Result<Query<PeerListQuery>, QueryRejection>,
) -> Response {
    let query = match list_query(query) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let value = match snapshot(&state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let items = value
        .peers
        .iter()
        .filter(|peer| peer.state == PeerState::Active)
        .map(peer_view)
        .collect();
    match page(
        items,
        query.limit,
        query.cursor.as_deref(),
        PEERS_DEFAULT_LIMIT,
        PEERS_MAX_LIMIT,
    ) {
        Ok((items, page)) => Json(dto::NetworkPeerPage { items, page }).into_response(),
        Err(response) => response,
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/network/blacklisted",
    tag = "network",
    params(NetworkListQuery),
    responses(
        (status = 200, body = dto::NetworkBlacklistedPage),
        (status = 400, body = error::ErrorEnvelope),
        (status = 503, body = error::ErrorEnvelope)
    )
)]
pub(crate) async fn blacklisted(
    State(state): State<NativeState>,
    query: Result<Query<NetworkListQuery>, QueryRejection>,
) -> Response {
    let query = match list_query(query) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let value = match snapshot(&state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let items = value
        .blacklisted
        .iter()
        .map(|entry| dto::NetworkBlacklistedView {
            addr: clean_blacklist_addr(&entry.addr),
        })
        .collect();
    match page(
        items,
        query.limit,
        query.cursor.as_deref(),
        NETWORK_DEFAULT_LIMIT,
        NETWORK_MAX_LIMIT,
    ) {
        Ok((items, page)) => Json(dto::NetworkBlacklistedPage { items, page }).into_response(),
        Err(response) => response,
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/network/sync-info",
    tag = "network",
    params(NetworkListQuery),
    responses(
        (status = 200, body = dto::NetworkSyncInfoPage),
        (status = 400, body = error::ErrorEnvelope),
        (status = 503, body = error::ErrorEnvelope)
    )
)]
pub(crate) async fn sync_info(
    State(state): State<NativeState>,
    query: Result<Query<NetworkListQuery>, QueryRejection>,
) -> Response {
    let query = match list_query(query) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let value = match snapshot(&state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let items = value.sync_info.iter().filter_map(sync_view).collect();
    match page(
        items,
        query.limit,
        query.cursor.as_deref(),
        NETWORK_DEFAULT_LIMIT,
        NETWORK_MAX_LIMIT,
    ) {
        Ok((items, page)) => Json(dto::NetworkSyncInfoPage { items, page }).into_response(),
        Err(response) => response,
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/network/track-info",
    tag = "network",
    responses(
        (status = 200, body = dto::NetworkTrackInfoView),
        (status = 503, body = error::ErrorEnvelope)
    )
)]
pub(crate) async fn track_info(State(state): State<NativeState>) -> Response {
    let value = match snapshot(&state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    Json(dto::NetworkTrackInfoView {
        num_requested: value.track_info.requested,
        num_received: value.track_info.received,
        num_failed: value.track_info.failed,
    })
    .into_response()
}

pub fn router(state: NativeState) -> Router {
    if state.peers.is_none() {
        return Router::new();
    }
    let response_limit = state.config.max_response_bytes;
    Router::new()
        .route("/api/v1/network/peers", get(peers))
        .route("/api/v1/network/connected", get(connected))
        .route("/api/v1/network/blacklisted", get(blacklisted))
        .route("/api/v1/network/sync-info", get(sync_info))
        .route("/api/v1/network/track-info", get(track_info))
        .with_state(state)
        .layer(axum::middleware::from_fn_with_state(
            response_limit,
            super::enforce_response_limit,
        ))
}
