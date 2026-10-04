//! `network/*` handlers. Reads (T0) project the same
//! peer/sync state the compat `/peers/*` routes read, reshaped into the
//! standard collection envelope + snake_case. `connect` (T1) reuses
//! [`NodeAdmin::connect_to_peer`](crate::traits::NodeAdmin). Manual ban/unban,
//! disconnect and saved-peer removal are acknowledged by the node action loop.

use std::net::SocketAddr;
use utoipa::ToSchema;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use serde_json::json;

use super::{keyed_collection, ListQuery, OperatorState};
use crate::types::{ApiPeer, ApiPeerState};
use crate::v1::error::{v1_error, Reason, V1Error};
use crate::v1::routes::dto::Collection;

/// Default/hard page size for the peer list (node-bounded, so the
/// default is generous and `has_more:false` in the common case).
const PEERS_DEFAULT_LIMIT: u32 = 256;
const PEERS_MAX_LIMIT: u32 = 1024;
/// Default/hard page size for the smaller network lists (blacklist / sync-info).
const NET_DEFAULT_LIMIT: u32 = 100;
const NET_MAX_LIMIT: u32 = 500;

/// `GET /api/v1/network/peers` — T0. Collection of `ApiPeer` (reused verbatim,
/// already snake_case) — a superset view (every tracked entry, any state).
#[utoipa::path(
    get, path = "/api/v1/network/peers", tag = "network",
    params(
        ("limit" = Option<u32>, Query, description = "Page size (default 256, cap 1024)"),
        ("cursor" = Option<String>, Query, description = "Opaque stable keyset cursor from this list; resumes after the last address in byte-wise order"),
    ),
    responses(
        (status = 200, description = "Every tracked peer (any state)", body = Collection<ApiPeer>),
        (status = 400, description = "Invalid cursor", body = V1Error),
    ),
)]
pub(crate) async fn peers(State(s): State<OperatorState>, Query(q): Query<ListQuery>) -> Response {
    keyed_collection(
        s.read.peers(),
        "peers",
        |p| &p.addr,
        &q,
        PEERS_DEFAULT_LIMIT,
        PEERS_MAX_LIMIT,
    )
}

/// `GET /api/v1/network/connected` — T0. Server-side filter of the same
/// `peers()` data down to handshake-complete (`state == active`) peers — no
/// new trait method.
#[utoipa::path(
    get, path = "/api/v1/network/connected", tag = "network",
    params(
        ("limit" = Option<u32>, Query, description = "Page size (default 256, cap 1024)"),
        ("cursor" = Option<String>, Query, description = "Opaque stable keyset cursor from this list; resumes after the last address in byte-wise order"),
    ),
    responses(
        (status = 200, description = "Handshake-complete peers only", body = Collection<ApiPeer>),
        (status = 400, description = "Invalid cursor", body = V1Error),
    ),
)]
pub(crate) async fn connected(
    State(s): State<OperatorState>,
    Query(q): Query<ListQuery>,
) -> Response {
    let active: Vec<_> = s
        .read
        .peers()
        .into_iter()
        .filter(|p| p.state == ApiPeerState::Active)
        .collect();
    keyed_collection(
        active,
        "connected",
        |p| &p.addr,
        &q,
        PEERS_DEFAULT_LIMIT,
        PEERS_MAX_LIMIT,
    )
}

/// One blacklisted-peer entry. `addr` is the clean canonical
/// `ip[:port]` — the compat path keeps the ugly Java `InetAddress.toString()`
/// `hostname/ip` double-form for byte-parity; v1 strips it.
#[derive(Serialize, ToSchema)]
pub(crate) struct BlacklistedPeer {
    addr: String,
}

/// Strip the Java `InetAddress.toString()` decoration (`hostname/1.2.3.4:9030`
/// or `/1.2.3.4:9030`) down to the bare `ip[:port]` after the last `/`.
fn clean_blacklist_addr(raw: &str) -> String {
    match raw.rsplit_once('/') {
        Some((_, tail)) => tail.to_string(),
        None => raw.to_string(),
    }
}

/// `GET /api/v1/network/blacklisted` — T0. Collection `{items:[{addr}], page}`
/// over [`NodeChainQuery::peers_blacklisted`](crate::compat::NodeChainQuery),
/// addresses cleaned to canonical form. `503 chain_reader_unavailable` when no
/// chain reader is wired.
#[utoipa::path(
    get, path = "/api/v1/network/blacklisted", tag = "network",
    params(
        ("limit" = Option<u32>, Query, description = "Page size (default 100, cap 500)"),
        ("cursor" = Option<String>, Query, description = "Opaque stable keyset cursor from this list; resumes after the last address in byte-wise order"),
    ),
    responses(
        (status = 200, description = "Blacklisted peer addresses", body = Collection<BlacklistedPeer>),
        (status = 400, description = "Invalid cursor", body = V1Error),
        (status = 503, description = "Chain reader unavailable", body = V1Error),
    ),
)]
pub(crate) async fn blacklisted(
    State(s): State<OperatorState>,
    Query(q): Query<ListQuery>,
) -> Response {
    let chain = match s.chain() {
        Ok(c) => c,
        Err(e) => return *e,
    };
    let items: Vec<BlacklistedPeer> = chain
        .peers_blacklisted()
        .addresses
        .iter()
        .map(|a| BlacklistedPeer {
            addr: clean_blacklist_addr(a),
        })
        .collect();
    keyed_collection(
        items,
        "blacklisted",
        |p| &p.addr,
        &q,
        NET_DEFAULT_LIMIT,
        NET_MAX_LIMIT,
    )
}

/// One per-peer sync-info entry. `peer_height` (not bare `height`)
/// disambiguates whose height; `status` is the lowercased Scala
/// `PeerChainStatus` set (`equal|younger|older|fork|unknown|nonsense`).
#[derive(Serialize, ToSchema)]
pub(crate) struct SyncInfoEntry {
    addr: String,
    peer_height: u32,
    status: String,
}

/// `GET /api/v1/network/sync-info` — T0. Collection reshape of
/// [`NodeChainQuery::peers_sync_info`](crate::compat::NodeChainQuery).
#[utoipa::path(
    get, path = "/api/v1/network/sync-info", tag = "network",
    params(
        ("limit" = Option<u32>, Query, description = "Page size (default 100, cap 500)"),
        ("cursor" = Option<String>, Query, description = "Opaque stable keyset cursor from this list; resumes after the last address in byte-wise order"),
    ),
    responses(
        (status = 200, description = "Per-peer sync status", body = Collection<SyncInfoEntry>),
        (status = 400, description = "Invalid cursor", body = V1Error),
        (status = 503, description = "Chain reader unavailable", body = V1Error),
    ),
)]
pub(crate) async fn sync_info(
    State(s): State<OperatorState>,
    Query(q): Query<ListQuery>,
) -> Response {
    let chain = match s.chain() {
        Ok(c) => c,
        Err(e) => return *e,
    };
    let items: Vec<SyncInfoEntry> = chain
        .peers_sync_info()
        .into_iter()
        .map(|e| SyncInfoEntry {
            addr: e.address,
            peer_height: e.height,
            status: e.status.to_lowercase(),
        })
        .collect();
    keyed_collection(
        items,
        "sync_info",
        |p| &p.addr,
        &q,
        NET_DEFAULT_LIMIT,
        NET_MAX_LIMIT,
    )
}

/// The `network/track-info` aggregate counters. Bare object, not a
/// collection.
#[derive(Serialize, ToSchema)]
pub(crate) struct TrackInfo {
    num_requested: u32,
    num_received: u32,
    num_failed: u32,
}

/// `GET /api/v1/network/track-info` — T0. Bare-object reshape of
/// [`NodeChainQuery::peers_track_info`](crate::compat::NodeChainQuery).
#[utoipa::path(
    get, path = "/api/v1/network/track-info", tag = "network",
    responses(
        (status = 200, description = "Aggregate modifier-tracking counters", body = TrackInfo),
        (status = 503, description = "Chain reader unavailable", body = V1Error),
    ),
)]
pub(crate) async fn track_info(State(s): State<OperatorState>) -> Response {
    let chain = match s.chain() {
        Ok(c) => c,
        Err(e) => return *e,
    };
    let t = chain.peers_track_info();
    Json(TrackInfo {
        num_requested: t.num_requested,
        num_received: t.num_received,
        num_failed: t.num_failed,
    })
    .into_response()
}

/// `POST /api/v1/network/connect` — T1. Body: JSON string `"host:port"`. Reuses
/// [`NodeAdmin::connect_to_peer`](crate::traits::NodeAdmin) (fire-and-forget
/// dial). `200 "OK"` on accepted; `400 invalid_address` on unparseable input.
/// Preserves the saner-than-Scala divergences (IPv6 accepted, unresolvable host
/// → 400 not 500, out-of-range port → 400). `503 route_unavailable` with no
/// admin bridge.
#[utoipa::path(
    post, path = "/api/v1/network/connect", tag = "network",
    request_body(content = String, description = "JSON string \"host:port\" to dial"),
    responses(
        (status = 200, description = "Dial accepted (fire-and-forget) — literal \"OK\"", body = String),
        (status = 400, description = "Malformed body, or host:port did not parse/resolve", body = V1Error),
        (status = 503, description = "Admin control bridge not wired on this node", body = V1Error),
    ),
    security(("ApiKeyAuth" = [])),
)]
pub(crate) async fn connect(State(s): State<OperatorState>, body: axum::body::Bytes) -> Response {
    let admin = match s.admin() {
        Ok(a) => a,
        Err(e) => return *e,
    };
    let addr_str = match serde_json::from_slice::<String>(&body) {
        Ok(s) => s,
        Err(_) => {
            return v1_error(
                Reason::BadRequest,
                "request body must be a json string \"host:port\"",
                "send a JSON string, e.g. \"1.2.3.4:9030\"",
            )
        }
    };
    // Fast path: literal ip:port. Fallback: async DNS for hostnames.
    let addr = match addr_str.parse::<SocketAddr>() {
        Ok(a) => a,
        Err(_) => match tokio::net::lookup_host(addr_str.as_str()).await {
            Ok(mut iter) => match iter.next() {
                Some(a) => a,
                None => {
                    return v1_error(
                        Reason::InvalidAddress,
                        "address resolved to nothing",
                        "supply a reachable host:port",
                    )
                }
            },
            Err(_) => {
                return v1_error(
                    Reason::InvalidAddress,
                    "not a valid host:port",
                    "supply an ip:port or a resolvable host:port",
                )
            }
        },
    };
    admin.connect_to_peer(addr);
    (StatusCode::OK, Json(json!("OK"))).into_response()
}

#[derive(Debug, serde::Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct BanRequest {
    addr: String,
    #[serde(default = "default_ban_duration")]
    duration_secs: u64,
}

fn default_ban_duration() -> u64 {
    1800
}

fn parse_ip(raw: &str) -> Option<std::net::IpAddr> {
    raw.parse()
        .ok()
        .or_else(|| raw.parse::<SocketAddr>().ok().map(|addr| addr.ip()))
}

#[utoipa::path(post, path = "/api/v1/network/blacklist", tag = "network",
    request_body = BanRequest,
    responses((status = 204, description = "IP-wide timed ban persisted and sessions disconnected"),
        (status = 400, description = "Invalid address or duration", body = V1Error),
        (status = 503, description = "Persistence or runtime unavailable", body = V1Error)),
    security(("ApiKeyAuth" = [])))]
pub(crate) async fn blacklist_add(
    State(s): State<OperatorState>,
    body: axum::body::Bytes,
) -> Response {
    let request: BanRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(error) => {
            return v1_error(Reason::BadRequest, "invalid ban request", error.to_string())
        }
    };
    let Some(ip) = parse_ip(&request.addr) else {
        return v1_error(
            Reason::InvalidAddress,
            "ban address must be an IP or socket address",
            "hostnames are not accepted for IP-wide bans",
        );
    };
    if !(1..=31_536_000).contains(&request.duration_secs) {
        return v1_error(
            Reason::OutOfRange,
            "invalid ban duration",
            "duration_secs must be between 1 and 31536000",
        );
    }
    control(
        s,
        crate::operator_control::PeerControl::Ban {
            ip,
            duration_secs: request.duration_secs,
        },
    )
    .await
}

#[utoipa::path(delete, path = "/api/v1/network/blacklist/{addr}", tag = "network",
    params(("addr" = String, Path, description = "IP or socket address to unban, including IPv6")),
    responses((status = 204, description = "Unban persisted"),
        (status = 400, description = "Invalid address", body = V1Error)),
    security(("ApiKeyAuth" = [])))]
pub(crate) async fn blacklist_remove(
    State(s): State<OperatorState>,
    Path(addr): Path<String>,
) -> Response {
    let Some(ip) = parse_ip(&addr) else {
        return v1_error(
            Reason::InvalidAddress,
            "unban address must be an IP or socket address",
            "supply the canonical IP shown in blacklisted peers",
        );
    };
    control(s, crate::operator_control::PeerControl::Unban { ip }).await
}

#[utoipa::path(post, path = "/api/v1/network/disconnect", tag = "network",
    request_body = String,
    responses((status = 200, description = "Reports whether a session was closed; future dialing remains enabled", body = crate::operator_control::PeerControlResult)),
    security(("ApiKeyAuth" = [])))]
pub(crate) async fn disconnect(
    State(s): State<OperatorState>,
    body: axum::body::Bytes,
) -> Response {
    let addr = match serde_json::from_slice::<String>(&body)
        .ok()
        .and_then(|raw| raw.parse().ok())
    {
        Some(addr) => addr,
        None => {
            return v1_error(
                Reason::InvalidAddress,
                "body must be a JSON socket-address string",
                "send the exact ip:port from the peer list",
            )
        }
    };
    control(s, crate::operator_control::PeerControl::Disconnect { addr }).await
}

#[utoipa::path(delete, path = "/api/v1/network/peers/{addr}", tag = "network",
    params(("addr" = String, Path, description = "Socket address to remove from saved peers")),
    responses((status = 200, description = "Saved dial metadata removed; reports whether a session was closed", body = crate::operator_control::PeerControlResult)),
    security(("ApiKeyAuth" = [])))]
pub(crate) async fn remove(State(s): State<OperatorState>, Path(addr): Path<String>) -> Response {
    let addr = match addr.parse() {
        Ok(addr) => addr,
        Err(_) => {
            return v1_error(
                Reason::InvalidAddress,
                "peer address must be ip:port",
                "configured seeds may reappear after restart; use a ban to prevent all dialing",
            )
        }
    };
    control(s, crate::operator_control::PeerControl::Remove { addr }).await
}

async fn control(s: OperatorState, command: crate::operator_control::PeerControl) -> Response {
    let admin = match s.admin() {
        Ok(admin) => admin,
        Err(error) => return *error,
    };
    match admin.peer_control(command).await {
        Ok(result) if result.session_closed.is_some() => Json(result).into_response(),
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => super::control_error(error),
    }
}
