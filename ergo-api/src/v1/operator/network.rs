//! `network/*` handlers (`v1-api-design.md` §3.2). Reads (T0) project the same
//! peer/sync state the compat `/peers/*` routes read, reshaped into the §1.3
//! collection envelope + §1.1 snake_case. `connect` (T1) reuses
//! [`NodeAdmin::connect_to_peer`](crate::traits::NodeAdmin). Manual blacklist
//! writes have no node-side seam yet (§3.2 #7/#8 — the peer manager exposes no
//! externally-triggered ban), so they answer the honest `route_unavailable`.

use utoipa::ToSchema;
use std::net::SocketAddr;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use serde_json::json;

use super::{offset_collection, ListQuery, OperatorState};
use crate::types::ApiPeerState;
use crate::v1::error::{v1_error, Reason};

/// Default/hard page size for the peer list (§3.2 #1 — node-bounded, so the
/// default is generous and `has_more:false` in the common case).
const PEERS_DEFAULT_LIMIT: u32 = 256;
const PEERS_MAX_LIMIT: u32 = 1024;
/// Default/hard page size for the smaller network lists (blacklist / sync-info).
const NET_DEFAULT_LIMIT: u32 = 100;
const NET_MAX_LIMIT: u32 = 500;

/// `GET /api/v1/network/peers` — T0. Collection of `ApiPeer` (reused verbatim,
/// already snake_case) — a superset view (every tracked entry, any state).
pub(super) async fn peers(State(s): State<OperatorState>, Query(q): Query<ListQuery>) -> Response {
    offset_collection(s.read.peers(), &q, PEERS_DEFAULT_LIMIT, PEERS_MAX_LIMIT)
}

/// `GET /api/v1/network/connected` — T0. Server-side filter of the same
/// `peers()` data down to handshake-complete (`state == active`) peers (§3.2
/// #2) — no new trait method.
pub(super) async fn connected(
    State(s): State<OperatorState>,
    Query(q): Query<ListQuery>,
) -> Response {
    let active: Vec<_> = s
        .read
        .peers()
        .into_iter()
        .filter(|p| p.state == ApiPeerState::Active)
        .collect();
    offset_collection(active, &q, PEERS_DEFAULT_LIMIT, PEERS_MAX_LIMIT)
}

/// One blacklisted-peer entry (§3.2 #3). `addr` is the clean canonical
/// `ip[:port]` — the compat path keeps the ugly Java `InetAddress.toString()`
/// `hostname/ip` double-form for byte-parity; v1 strips it.
#[derive(Serialize, ToSchema)]
struct BlacklistedPeer {
    addr: String,
}

/// Strip the Java `InetAddress.toString()` decoration (`hostname/1.2.3.4:9030`
/// or `/1.2.3.4:9030`) down to the bare `ip[:port]` after the last `/` (§3.2 #3).
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
pub(super) async fn blacklisted(
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
    offset_collection(items, &q, NET_DEFAULT_LIMIT, NET_MAX_LIMIT)
}

/// One per-peer sync-info entry (§3.2 #4). `peer_height` (not bare `height`)
/// disambiguates whose height; `status` is the lowercased Scala
/// `PeerChainStatus` set (`equal|younger|older|fork|unknown|nonsense`).
#[derive(Serialize, ToSchema)]
struct SyncInfoEntry {
    addr: String,
    peer_height: u32,
    status: String,
}

/// `GET /api/v1/network/sync-info` — T0. Collection reshape of
/// [`NodeChainQuery::peers_sync_info`](crate::compat::NodeChainQuery).
pub(super) async fn sync_info(
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
    offset_collection(items, &q, NET_DEFAULT_LIMIT, NET_MAX_LIMIT)
}

/// The `network/track-info` aggregate counters (§3.2 #5). Bare object, not a
/// collection.
#[derive(Serialize, ToSchema)]
struct TrackInfo {
    num_requested: u32,
    num_received: u32,
    num_failed: u32,
}

/// `GET /api/v1/network/track-info` — T0. Bare-object reshape of
/// [`NodeChainQuery::peers_track_info`](crate::compat::NodeChainQuery).
pub(super) async fn track_info(State(s): State<OperatorState>) -> Response {
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
pub(super) async fn connect(State(s): State<OperatorState>, body: axum::body::Bytes) -> Response {
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

/// `POST /api/v1/network/blacklist` — T1, seam-deferred. No manual-ban write
/// path exists on the peer manager yet (§3.2 #7), so this answers the honest
/// `route_unavailable` rather than pretending to ban.
pub(super) async fn blacklist_add(State(_s): State<OperatorState>) -> Response {
    v1_error(
        Reason::RouteUnavailable,
        "manual peer blacklisting is not wired on this node",
        "the peer manager exposes no externally-triggered ban seam yet (Phase-2)",
    )
}

/// `DELETE /api/v1/network/blacklist/{addr}` — T1, seam-deferred (same gap as
/// [`blacklist_add`]).
pub(super) async fn blacklist_remove(
    State(_s): State<OperatorState>,
    Path(_addr): Path<String>,
) -> Response {
    v1_error(
        Reason::RouteUnavailable,
        "manual peer un-blacklisting is not wired on this node",
        "the peer manager exposes no externally-triggered ban seam yet (Phase-2)",
    )
}
