//! `node/*` handlers (`v1-api-design.md` §3.1). Reads (T0) reuse
//! [`NodeReadState`](crate::traits::NodeReadState) verbatim (its DTOs are
//! already snake_case, no reshape); `shutdown` (T2) reuses
//! [`NodeAdmin::request_shutdown`](crate::traits::NodeAdmin). `config` GET/PATCH
//! has no node-side trait seam yet, so it answers the honest `route_unavailable`.

use utoipa::ToSchema;
use axum::{
    extract::State,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

use super::OperatorState;
use crate::types::{
    ApiHealth, ApiHost, ApiIdentity, ApiInfo, ApiStatus, ApiSyncStatus, ApiTip, HealthStatus,
};
use crate::v1::error::{v1_error, Reason, V1Error};

/// `GET /api/v1/node/info` — T0. Bare `ApiInfo` (reused verbatim, §3.1).
#[utoipa::path(
    get, path = "/api/v1/node/info", tag = "node",
    responses((status = 200, description = "Node info", body = ApiInfo)),
)]
pub(super) async fn info(State(s): State<OperatorState>) -> Response {
    Json(s.read.info()).into_response()
}

/// `GET /api/v1/node/status` — T0. Bare `ApiStatus` (reused verbatim).
#[utoipa::path(
    get, path = "/api/v1/node/status", tag = "node",
    responses((status = 200, description = "Dashboard status snapshot", body = ApiStatus)),
)]
pub(super) async fn status(State(s): State<OperatorState>) -> Response {
    Json(s.read.status()).into_response()
}

/// `GET /api/v1/node/sync` — T0. Bare `ApiSyncStatus` (reused verbatim).
#[utoipa::path(
    get, path = "/api/v1/node/sync", tag = "node",
    responses((status = 200, description = "Sync status", body = ApiSyncStatus)),
)]
pub(super) async fn sync(State(s): State<OperatorState>) -> Response {
    Json(s.read.sync()).into_response()
}

/// `GET /api/v1/node/tip` — T0. Bare `ApiTip` (reused verbatim).
#[utoipa::path(
    get, path = "/api/v1/node/tip", tag = "node",
    responses((status = 200, description = "Chain tip", body = ApiTip)),
)]
pub(super) async fn tip(State(s): State<OperatorState>) -> Response {
    Json(s.read.tip()).into_response()
}

/// `GET /api/v1/node/identity` — T0. Bare `ApiIdentity` (reused verbatim).
#[utoipa::path(
    get, path = "/api/v1/node/identity", tag = "node",
    responses((status = 200, description = "Node identity", body = ApiIdentity)),
)]
pub(super) async fn identity(State(s): State<OperatorState>) -> Response {
    Json(s.read.identity()).into_response()
}

/// `GET /api/v1/node/host` — T0. Bare `ApiHost` (reused verbatim). Fold of the
/// pre-existing flat `/api/v1/host` (design gap G1) into the `node/*` group.
#[utoipa::path(
    get, path = "/api/v1/node/host", tag = "node",
    responses((status = 200, description = "Host info", body = ApiHost)),
)]
pub(super) async fn host(State(s): State<OperatorState>) -> Response {
    Json(s.read.host()).into_response()
}

/// `GET /api/v1/node/health` — T0, dual status. `200` when `status = ok`; `503`
/// for `stalled|disconnected|rejecting`, WITH the full typed body (§3.1 — never
/// a bare error). Same mapping as the compat `health_handler`.
#[utoipa::path(
    get, path = "/api/v1/node/health", tag = "node",
    responses(
        (status = 200, description = "Healthy", body = ApiHealth),
        (status = 503, description = "Stalled, disconnected, or rejecting a block", body = ApiHealth),
    ),
)]
pub(super) async fn health(State(s): State<OperatorState>) -> Response {
    let h = s.read.health();
    let code = match h.status {
        HealthStatus::Ok => StatusCode::OK,
        HealthStatus::Stalled | HealthStatus::Disconnected | HealthStatus::Rejecting => {
            StatusCode::SERVICE_UNAVAILABLE
        }
    };
    let body = serde_json::to_vec(&h).unwrap_or_else(|_| b"{}".to_vec());
    (code, [(header::CONTENT_TYPE, "application/json")], body).into_response()
}

/// The `node/version` probe body (§3.1 #7): an ultra-cheap liveness/version
/// read, distinct from `info`. `activated_protocol_version` is the currently
/// active block-format version — sourced from the same snapshot's votes view
/// (`ApiVotes.block_version`), the one place the node already surfaces it.
#[derive(Serialize, ToSchema)]
struct NodeVersion {
    software_version: String,
    api_versions: Vec<&'static str>,
    activated_protocol_version: u8,
}

/// `GET /api/v1/node/version` — T0. Composed from existing snapshot reads
/// (`info().version` + `votes().block_version`); no new read path.
#[utoipa::path(
    get, path = "/api/v1/node/version", tag = "node",
    responses((status = 200, description = "Version + activated protocol version", body = NodeVersion)),
)]
pub(super) async fn version(State(s): State<OperatorState>) -> Response {
    Json(NodeVersion {
        software_version: s.read.info().version,
        api_versions: vec!["v1"],
        activated_protocol_version: s.read.votes().block_version,
    })
    .into_response()
}

/// `GET /api/v1/node/config` — T1. No `NodeConfigView` seam exists on the node
/// yet (§3.1 #8, Phase-2 ASSUMED-new), so this answers the honest
/// `route_unavailable` (503) rather than fabricating or half-projecting a config
/// tree. Gated at `Tier::Operator` so the closed shape is still auth-bounded.
#[utoipa::path(
    get, path = "/api/v1/node/config", tag = "node",
    responses((status = 503, description = "Effective-config read not wired on this node", body = V1Error)),
    security(("ApiKeyAuth" = [])),
)]
pub(super) async fn config_get(State(_s): State<OperatorState>) -> Response {
    v1_error(
        Reason::RouteUnavailable,
        "effective-config read is not wired on this node",
        "GET /node/config needs a NodeConfigView seam (Phase-2); not yet available",
    )
}

/// `PATCH /api/v1/node/config` — T2. Config mutation is the more dangerous half
/// of `node/config`, so it sits at `Tier::Admin` (loopback-preferred). No
/// `apply_config_patch` seam exists yet, so it answers `route_unavailable`
/// rather than exposing a mutation that isn't safely backed.
#[utoipa::path(
    patch, path = "/api/v1/node/config", tag = "node",
    responses((status = 503, description = "Config mutation not wired on this node", body = V1Error)),
    security(("ApiKeyAuth" = [])),
)]
pub(super) async fn config_patch(State(_s): State<OperatorState>) -> Response {
    v1_error(
        Reason::RouteUnavailable,
        "config mutation is not wired on this node",
        "PATCH /node/config needs a NodeAdmin::apply_config_patch seam (Phase-2); not yet available",
    )
}

// NOTE: `POST /api/v1/node/shutdown` (T2) is served by the frozen compat admin
// mount at that exact path (`server.rs`, `NodeAdmin::request_shutdown` via
// `require_api_key`). This group does not re-mount it — see the T2 note in
// `super::operator_router`.
