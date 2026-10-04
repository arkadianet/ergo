//! `node/*` handlers. Reads (T0) reuse
//! [`NodeReadState`](crate::traits::NodeReadState) verbatim (its DTOs are
//! already snake_case, no reshape); `shutdown` (T2) reuses
//! [`NodeAdmin::request_shutdown`](crate::traits::NodeAdmin). Operational config
//! and probes use explicit node-side control and heartbeat bridges.

use axum::{
    extract::State,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use utoipa::ToSchema;

use super::OperatorState;
use crate::types::{
    ApiHealth, ApiHost, ApiIdentity, ApiInfo, ApiStatus, ApiSyncStatus, ApiTip, HealthStatus,
};
use crate::v1::error::{v1_error, Reason, V1Error};

/// `GET /api/v1/node/info` — T0. Bare `ApiInfo` (reused verbatim).
#[utoipa::path(
    get, path = "/api/v1/node/info", tag = "node",
    responses((status = 200, description = "Node info", body = ApiInfo)),
)]
pub(crate) async fn info(State(s): State<OperatorState>) -> Response {
    Json(s.read.info()).into_response()
}

/// `GET /api/v1/node/status` — T0. Bare `ApiStatus` (reused verbatim).
#[utoipa::path(
    get, path = "/api/v1/node/status",
    operation_id = "v1_node_status_get", tag = "node",
    responses((status = 200, description = "Dashboard status snapshot", body = ApiStatus)),
)]
pub(crate) async fn status(State(s): State<OperatorState>) -> Response {
    Json(s.read.status()).into_response()
}

/// `GET /api/v1/node/sync` — T0. Bare `ApiSyncStatus` (reused verbatim).
#[utoipa::path(
    get, path = "/api/v1/node/sync", tag = "node",
    responses((status = 200, description = "Sync status", body = ApiSyncStatus)),
)]
pub(crate) async fn sync(State(s): State<OperatorState>) -> Response {
    Json(s.read.sync()).into_response()
}

/// `GET /api/v1/node/tip` — T0. Bare `ApiTip` (reused verbatim).
#[utoipa::path(
    get, path = "/api/v1/node/tip", tag = "node",
    responses((status = 200, description = "Chain tip", body = ApiTip)),
)]
pub(crate) async fn tip(State(s): State<OperatorState>) -> Response {
    Json(s.read.tip()).into_response()
}

/// `GET /api/v1/node/identity` — T0. Bare `ApiIdentity` (reused verbatim).
#[utoipa::path(
    get, path = "/api/v1/node/identity", tag = "node",
    responses((status = 200, description = "Node identity", body = ApiIdentity)),
)]
pub(crate) async fn identity(State(s): State<OperatorState>) -> Response {
    Json(s.read.identity()).into_response()
}

/// `GET /api/v1/node/host` — T0. Bare `ApiHost` (reused verbatim). Fold of the
/// pre-existing flat `/api/v1/host` (design gap G1) into the `node/*` group.
#[utoipa::path(
    get, path = "/api/v1/node/host", tag = "node",
    responses((status = 200, description = "Host info", body = ApiHost)),
)]
pub(crate) async fn host(State(s): State<OperatorState>) -> Response {
    Json(s.read.host()).into_response()
}

/// `GET /api/v1/node/health` — T0, dual status. `200` when `status = ok`; `503`
/// for `stalled|disconnected|rejecting|wedged`, WITH the full typed body
/// (never a bare error). Same mapping as the compat `health_handler`.
#[utoipa::path(
    get, path = "/api/v1/node/health", tag = "node",
    responses(
        (status = 200, description = "Healthy", body = ApiHealth),
        (status = 503, description = "Stalled, disconnected, rejecting a block, or wedged", body = ApiHealth),
    ),
)]
pub(crate) async fn health(State(s): State<OperatorState>) -> Response {
    let h = s.read.health();
    let code = match h.status {
        HealthStatus::Ok => StatusCode::OK,
        HealthStatus::Stalled
        | HealthStatus::Disconnected
        | HealthStatus::Rejecting
        | HealthStatus::Wedged => StatusCode::SERVICE_UNAVAILABLE,
    };
    let body = serde_json::to_vec(&h).unwrap_or_else(|_| b"{}".to_vec());
    (code, [(header::CONTENT_TYPE, "application/json")], body).into_response()
}

/// The `node/version` probe body: an ultra-cheap liveness/version
/// read, distinct from `info`. `activated_protocol_version` is the currently
/// active block-format version — sourced from the same snapshot's votes view
/// (`ApiVotes.block_version`), the one place the node already surfaces it.
#[derive(Serialize, ToSchema)]
pub(crate) struct NodeVersion {
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
pub(crate) async fn version(State(s): State<OperatorState>) -> Response {
    Json(NodeVersion {
        software_version: s.read.info().version,
        api_versions: vec!["v1"],
        activated_protocol_version: s.read.votes().block_version,
    })
    .into_response()
}

/// `GET /api/v1/node/config` — authenticated allowlisted effective settings.
#[utoipa::path(get, path = "/api/v1/node/config", tag = "node",
    responses((status = 200, description = "Redacted boot and live operational settings"),
        (status = 503, description = "Control bridge unavailable", body = V1Error)),
    security(("ApiKeyAuth" = [])))]
pub(crate) async fn config_get(State(s): State<OperatorState>) -> Response {
    match s.admin().and_then(|admin| {
        admin.effective_config().ok_or_else(|| {
            Box::new(v1_error(
                Reason::RouteUnavailable,
                "effective config is unavailable",
                "this node does not expose an operator configuration bridge",
            ))
        })
    }) {
        Ok(config) => Json(config).into_response(),
        Err(error) => *error,
    }
}

/// `PATCH /api/v1/node/config` — validate all members before applying any.
#[utoipa::path(patch, path = "/api/v1/node/config", tag = "node",
    request_body = crate::operator_control::RuntimeConfigPatch,
    responses((status = 200, description = "Updated live operational settings"),
        (status = 400, description = "Invalid or restart-only setting", body = V1Error),
        (status = 409, description = "Revision conflict", body = V1Error)),
    security(("ApiKeyAuth" = [])))]
pub(crate) async fn config_patch(
    State(s): State<OperatorState>,
    body: axum::body::Bytes,
) -> Response {
    let admin = match s.admin() {
        Ok(admin) => admin,
        Err(error) => return *error,
    };
    let patch = match serde_json::from_slice(&body) {
        Ok(patch) => patch,
        Err(error) => {
            return v1_error(
                Reason::NotHotReloadable,
                "invalid runtime config patch",
                format!("only api_limits/readiness are reloadable: {error}"),
            )
        }
    };
    match admin.apply_config_patch(patch) {
        Ok(config) => Json(config).into_response(),
        Err(error) => super::control_error(error),
    }
}

fn probe_response(s: OperatorState, kind: &str) -> Response {
    let Some(probes) = s.read.probes() else {
        return v1_error(
            Reason::RouteUnavailable,
            "runtime probes are unavailable",
            "use a node with a runtime heartbeat bridge",
        );
    };
    let report = match kind {
        "startup" => probes.startup,
        "liveness" => probes.liveness,
        _ => probes.readiness,
    };
    let code = if report.ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (code, Json(report)).into_response()
}

#[utoipa::path(get, path = "/api/v1/node/startup", tag = "node",
    responses((status = 200, description = "Runtime started", body = crate::operator_control::ProbeReport),
        (status = 503, description = "Runtime not started or stopped", body = crate::operator_control::ProbeReport)))]
pub(crate) async fn startup(State(s): State<OperatorState>) -> Response {
    probe_response(s, "startup")
}

#[utoipa::path(get, path = "/api/v1/node/liveness", tag = "node",
    responses((status = 200, description = "Runtime heartbeat fresh", body = crate::operator_control::ProbeReport),
        (status = 503, description = "Runtime stopped or heartbeat stale", body = crate::operator_control::ProbeReport)))]
pub(crate) async fn liveness(State(s): State<OperatorState>) -> Response {
    probe_response(s, "liveness")
}

#[utoipa::path(get, path = "/api/v1/node/readiness", tag = "node",
    responses((status = 200, description = "Chain service ready", body = crate::operator_control::ProbeReport),
        (status = 503, description = "Sync, freshness or dependency checks failed", body = crate::operator_control::ProbeReport)))]
pub(crate) async fn readiness(State(s): State<OperatorState>) -> Response {
    probe_response(s, "readiness")
}

#[utoipa::path(get, path = "/api/v1/node/credentials", tag = "node",
    responses((status = 200, description = "Named credential scopes and revocation flags; no hashes", body = Vec<crate::auth::CredentialInfo>)),
    security(("ApiKeyAuth" = [])))]
pub(crate) async fn credentials(State(s): State<OperatorState>) -> Response {
    let admin = match s.admin() {
        Ok(admin) => admin,
        Err(error) => return *error,
    };
    match admin.credentials() {
        Some(keys) => Json(keys).into_response(),
        None => v1_error(
            Reason::RouteUnavailable,
            "credential control unavailable",
            "configure API security on this node",
        ),
    }
}

#[utoipa::path(delete, path = "/api/v1/node/credentials/{id}", tag = "node",
    params(("id" = String, Path, description = "Named credential id; master key is not revocable through this endpoint")),
    responses((status = 204, description = "Credential revoked durably"),
        (status = 404, description = "Unknown credential id", body = V1Error),
        (status = 503, description = "Ledger could not be persisted", body = V1Error)),
    security(("ApiKeyAuth" = [])))]
pub(crate) async fn revoke_credential(
    State(s): State<OperatorState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Response {
    let admin = match s.admin() {
        Ok(admin) => admin,
        Err(error) => return *error,
    };
    let admin = admin.clone();
    match tokio::task::spawn_blocking(move || admin.revoke_credential(&id)).await {
        Ok(Ok(())) => StatusCode::NO_CONTENT.into_response(),
        Ok(Err(error)) => super::control_error(error),
        Err(error) => v1_error(
            Reason::InternalError,
            "credential revoke failed",
            error.to_string(),
        ),
    }
}
