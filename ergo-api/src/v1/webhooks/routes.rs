//! `webhooks/*` — the T1 (operator) management surface (`v1-api-design.md`
//! §4.1, fragment §3.1). Registration is an outbound-request lever, so every
//! endpoint is gated by [`require_tier`](crate::v1::auth::require_tier) at
//! `Tier::Operator` — the same api-key gate as `/wallet/*` and `POST /votes`.
//!
//! Handlers consume the shared G2 primitives (error envelope + [`Reason`],
//! cursor page builder) and gate *inside* the handler on the subsystem being
//! wired, so a node without the webhook store answers `webhooks_disabled`
//! (409) — never a bare 404 (§4 subsystem-off rule).

use utoipa::ToSchema;
use std::sync::Arc;

use axum::{
    extract::{Path, State},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use ergo_ser::address::NetworkPrefix;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::engine::{generate_secret, RegisterError, WebhookEngine};
use super::model::{validate_url, UrlPolicy, UrlReject};
use crate::v1::auth::{require_tier, Tier, V1AuthConfig};
use crate::v1::cursor::{
    clamp_limit, decode_opt_cursor, encode_cursor, Page, DEFAULT_LIMIT, MAX_LIMIT,
};
use crate::v1::error::{v1_error, Reason};
use crate::v1::realtime::{parse_channel, RealtimeBus};
use crate::v1::routes::extract::{V1Json, V1Query};

/// The webhook subsystem handle threaded into [`WebhooksState`]: the store
/// (engine) + the event source (bus, for channel-liveness at registration) +
/// the SSRF URL policy.
#[derive(Clone)]
pub struct WebhooksHandle {
    /// The registry + delivery-log + retry state machine.
    pub engine: Arc<WebhookEngine>,
    /// The realtime event source — used only to reject registrations for
    /// channel classes without a live upstream feed (`channel_unavailable`).
    pub bus: Arc<RealtimeBus>,
    /// SSRF guard policy applied to registration URLs.
    pub url_policy: UrlPolicy,
}

/// Router state for the `webhooks/*` group. `handle: None` ⇒ every endpoint
/// answers `webhooks_disabled` (never a 404), per the subsystem-off rule.
#[derive(Clone)]
pub struct WebhooksState {
    /// The subsystem handle, or `None` when the store is not wired.
    pub handle: Option<WebhooksHandle>,
    /// Address-encoding network (validates `address:` channel selectors).
    pub network: NetworkPrefix,
}

impl WebhooksState {
    /// The wired subsystem handle, or the boxed `409 webhooks_disabled`
    /// response (§4). Boxed to keep the `Ok` path small — the repo convention
    /// for handler early-returns (a rendered [`Response`] is large).
    fn handle(&self) -> Result<&WebhooksHandle, Box<Response>> {
        self.handle.as_ref().ok_or_else(|| {
            Box::new(v1_error(
                Reason::WebhooksDisabled,
                "the webhook store is not wired on this node",
                "webhooks require the durable delivery subsystem to be enabled",
            ))
        })
    }
}

/// `POST /api/v1/webhooks` body.
#[derive(Debug, Deserialize, ToSchema)]
struct RegisterRequest {
    url: String,
    channels: Vec<String>,
    #[serde(default)]
    secret: Option<String>,
    #[serde(default)]
    confirmations: Option<u32>,
}

/// `PATCH /api/v1/webhooks/{id}` body (pause / resume).
#[derive(Debug, Deserialize, ToSchema)]
struct PatchRequest {
    active: bool,
}

/// Cursor + limit query for the paginated list endpoints.
#[derive(Debug, Deserialize, ToSchema)]
struct ListQuery {
    limit: Option<u32>,
    cursor: Option<String>,
}

/// Opaque offset cursor for the webhook + delivery lists.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
struct OffsetCursor {
    off: usize,
}

fn offset_from(cursor: Option<&str>) -> Result<usize, Box<Response>> {
    Ok(decode_opt_cursor::<OffsetCursor>(cursor)?
        .map(|c| c.off)
        .unwrap_or(0))
}

fn url_reject_response(rej: UrlReject) -> Response {
    match rej {
        UrlReject::Insecure => v1_error(
            Reason::InsecureUrl,
            "webhook url must be https",
            "use an https endpoint, or enable loopback/dev delivery in the node config",
        ),
        UrlReject::Malformed => v1_error(
            Reason::ForbiddenTarget,
            "webhook url is malformed",
            "supply an absolute https url with a host, e.g. https://host/path",
        ),
        UrlReject::ForbiddenTarget => v1_error(
            Reason::ForbiddenTarget,
            "webhook url targets a forbidden (private/loopback) host",
            "point the webhook at a public https endpoint",
        ),
    }
}

/// `POST /api/v1/webhooks` — register a subscription (T1). Returns 201 with the
/// subscription **and** the secret echoed exactly once.
async fn register(
    State(state): State<WebhooksState>,
    body: Result<Json<serde_json::Value>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let handle = match state.handle() {
        Ok(h) => h,
        Err(e) => return *e,
    };
    let Json(raw) = match body {
        Ok(j) => j,
        Err(_) => {
            return v1_error(
                Reason::BadRequest,
                "request body must be a json object",
                "send {url, channels, secret?, confirmations?}",
            )
        }
    };
    let req: RegisterRequest = match serde_json::from_value(raw) {
        Ok(r) => r,
        Err(e) => {
            return v1_error(
                Reason::BadRequest,
                "invalid webhook registration body",
                e.to_string(),
            )
        }
    };

    // SSRF guard on the URL.
    if let Err(rej) = validate_url(&req.url, &handle.url_policy) {
        return url_reject_response(rej);
    }

    // Validate + normalize every channel (selector shape, then liveness).
    if req.channels.is_empty() {
        return v1_error(
            Reason::InvalidSelector,
            "at least one channel is required",
            "list one or more channels, e.g. [\"blocks\"]",
        );
    }
    let mut keys = Vec::with_capacity(req.channels.len());
    for raw in &req.channels {
        let parsed = match parse_channel(raw, state.network) {
            Ok(p) => p,
            Err(rej) => {
                return v1_error(
                    Reason::InvalidSelector,
                    "invalid channel selector",
                    rej.message,
                )
            }
        };
        if !handle.bus.is_live(parsed.class) {
            return v1_error(
                Reason::ChannelUnavailable,
                format!("channel `{}` has no live feed on this node", parsed.key),
                "only channels backed by a live event feed can be registered; \
                 the fine-grained taps are a follow-up",
            );
        }
        keys.push(parsed.key);
    }

    // Generated-if-absent secret; echoed once on the response. An
    // operator-supplied empty/whitespace secret would report `secret_set`
    // with nothing usable to sign against — reject it.
    let secret = match req.secret {
        Some(s) if s.trim().is_empty() => {
            return v1_error(
                Reason::BadRequest,
                "secret must not be empty",
                "omit `secret` to have one generated, or supply a non-blank value",
            );
        }
        Some(s) => Some(s),
        None => Some(generate_secret()),
    };
    let min_conf = req.confirmations.unwrap_or(1);

    match handle.engine.register(
        req.url,
        keys,
        secret,
        min_conf,
        crate::v1::webhooks::worker::now_unix_ms(),
    ) {
        Ok(sub) => (
            axum::http::StatusCode::CREATED,
            Json(sub.to_dto_with_secret()),
        )
            .into_response(),
        Err(RegisterError::LimitReached) => v1_error(
            Reason::WebhookLimit,
            "the maximum number of webhooks is registered",
            "delete an existing webhook before registering another",
        ),
        Err(RegisterError::TooManyChannels) => v1_error(
            Reason::LimitExceeded,
            "too many channels for one webhook",
            "reduce the channel list",
        ),
    }
}

/// `GET /api/v1/webhooks` — list subscriptions (T1), cursor-paginated.
async fn list(State(state): State<WebhooksState>, V1Query(q): V1Query<ListQuery>) -> Response {
    let handle = match state.handle() {
        Ok(h) => h,
        Err(e) => return *e,
    };
    let limit = clamp_limit(q.limit, DEFAULT_LIMIT, MAX_LIMIT);
    let off = match offset_from(q.cursor.as_deref()) {
        Ok(o) => o,
        Err(e) => return *e,
    };
    let mut rows = handle.engine.list(off, limit as usize + 1);
    let has_more = rows.len() > limit as usize;
    if has_more {
        rows.truncate(limit as usize);
    }
    let items: Vec<serde_json::Value> = rows.iter().map(|s| s.to_dto()).collect();
    let next_cursor = has_more.then(|| {
        encode_cursor(&OffsetCursor {
            off: off + limit as usize,
        })
    });
    Json(json!({
        "items": items,
        "page": Page { limit, next_cursor, has_more },
    }))
    .into_response()
}

/// `GET /api/v1/webhooks/{webhook_id}` — one subscription (T1). Never the secret.
async fn detail(State(state): State<WebhooksState>, Path(id): Path<String>) -> Response {
    let handle = match state.handle() {
        Ok(h) => h,
        Err(e) => return *e,
    };
    match handle.engine.get(&id) {
        Some(sub) => Json(sub.to_dto()).into_response(),
        None => webhook_not_found(),
    }
}

/// `DELETE /api/v1/webhooks/{webhook_id}` — deregister (T1).
async fn delete(State(state): State<WebhooksState>, Path(id): Path<String>) -> Response {
    let handle = match state.handle() {
        Ok(h) => h,
        Err(e) => return *e,
    };
    if handle.engine.delete(&id) {
        Json(json!({ "webhook_id": id, "deleted": true })).into_response()
    } else {
        webhook_not_found()
    }
}

/// `PATCH /api/v1/webhooks/{webhook_id}` — pause / resume (T1).
async fn patch_active(
    State(state): State<WebhooksState>,
    Path(id): Path<String>,
    V1Json(body): V1Json<PatchRequest>,
) -> Response {
    let handle = match state.handle() {
        Ok(h) => h,
        Err(e) => return *e,
    };
    match handle.engine.set_active(&id, body.active) {
        Some(sub) => Json(sub.to_dto()).into_response(),
        None => webhook_not_found(),
    }
}

/// `GET /api/v1/webhooks/{webhook_id}/deliveries` — delivery-status log (T1),
/// cursor-paginated, newest-first.
async fn deliveries(
    State(state): State<WebhooksState>,
    Path(id): Path<String>,
    V1Query(q): V1Query<ListQuery>,
) -> Response {
    let handle = match state.handle() {
        Ok(h) => h,
        Err(e) => return *e,
    };
    if handle.engine.get(&id).is_none() {
        return webhook_not_found();
    }
    let limit = clamp_limit(q.limit, DEFAULT_LIMIT, MAX_LIMIT);
    let off = match offset_from(q.cursor.as_deref()) {
        Ok(o) => o,
        Err(e) => return *e,
    };
    let mut rows = handle.engine.deliveries_for(&id, off, limit as usize + 1);
    let has_more = rows.len() > limit as usize;
    if has_more {
        rows.truncate(limit as usize);
    }
    let items: Vec<serde_json::Value> = rows.iter().map(|d| d.to_dto()).collect();
    let next_cursor = has_more.then(|| {
        encode_cursor(&OffsetCursor {
            off: off + limit as usize,
        })
    });
    Json(json!({
        "items": items,
        "page": Page { limit, next_cursor, has_more },
    }))
    .into_response()
}

fn webhook_not_found() -> Response {
    v1_error(
        Reason::WebhookNotFound,
        "no webhook with that id",
        "list webhooks to find a valid webhook_id",
    )
}

/// Build the T1 `webhooks/*` router. Every route is gated by the operator
/// api-key (`require_tier(Tier::Operator)`), mounted as a `route_layer` — the
/// same pattern the wallet + votes surfaces use.
pub fn webhooks_router(state: WebhooksState, auth: Arc<V1AuthConfig>) -> Router {
    Router::new()
        .route("/api/v1/webhooks", get(list).post(register))
        .route(
            "/api/v1/webhooks/:webhook_id",
            get(detail).patch(patch_active).delete(delete),
        )
        .route("/api/v1/webhooks/:webhook_id/deliveries", get(deliveries))
        .route_layer(axum::middleware::from_fn_with_state(
            auth.state(Tier::Operator),
            require_tier,
        ))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::ApiSecurity;
    use crate::v1::webhooks::engine::WebhookEngineConfig;
    use axum::body::to_bytes;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    // ----- helpers -----

    fn security() -> Arc<ApiSecurity> {
        Arc::new(ApiSecurity::new(ApiSecurity::hash_key(b"operator-secret")).unwrap())
    }

    fn state_enabled() -> WebhooksState {
        WebhooksState {
            handle: Some(WebhooksHandle {
                engine: Arc::new(WebhookEngine::new(WebhookEngineConfig::default())),
                bus: Arc::new(RealtimeBus::blocks_only()),
                url_policy: UrlPolicy::default(),
            }),
            network: NetworkPrefix::Mainnet,
        }
    }

    fn app(state: WebhooksState) -> Router {
        let auth = V1AuthConfig::new(Some(security())).into_shared();
        webhooks_router(state, auth)
    }

    fn req(
        method: &str,
        uri: &str,
        key: Option<&str>,
        body: Option<serde_json::Value>,
    ) -> Request<axum::body::Body> {
        let mut b = Request::builder().method(method).uri(uri);
        if let Some(k) = key {
            b = b.header(crate::auth::API_KEY_HEADER, k);
        }
        let body = match body {
            Some(v) => {
                b = b.header("content-type", "application/json");
                axum::body::Body::from(v.to_string())
            }
            None => axum::body::Body::empty(),
        };
        b.body(body).unwrap()
    }

    async fn json_of(resp: Response) -> (StatusCode, serde_json::Value) {
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap()
        };
        (status, v)
    }

    // ----- T1 auth gate -----

    #[tokio::test]
    async fn register_requires_api_key() {
        let resp = app(state_enabled())
            .oneshot(req(
                "POST",
                "/api/v1/webhooks",
                None,
                Some(json!({"url":"https://x.example/h","channels":["blocks"]})),
            ))
            .await
            .unwrap();
        let (status, v) = json_of(resp).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(v["error"]["reason"], "unauthorized");
    }

    // ----- register happy path + secret echoed once -----

    #[tokio::test]
    async fn register_returns_201_and_echoes_secret_once() {
        let resp = app(state_enabled())
            .oneshot(req(
                "POST",
                "/api/v1/webhooks",
                Some("operator-secret"),
                Some(json!({"url":"https://x.example/h","channels":["blocks"]})),
            ))
            .await
            .unwrap();
        let (status, v) = json_of(resp).await;
        assert_eq!(status, StatusCode::CREATED);
        assert!(v["webhook_id"].as_str().unwrap().starts_with("wh_"));
        assert_eq!(v["secret_set"], true);
        // Secret echoed exactly once on create.
        assert!(v["secret"].as_str().unwrap().starts_with("whsec_"));
        assert_eq!(v["channels"][0], "blocks");
    }

    #[tokio::test]
    async fn register_rejects_http_url_insecure() {
        let resp = app(state_enabled())
            .oneshot(req(
                "POST",
                "/api/v1/webhooks",
                Some("operator-secret"),
                Some(json!({"url":"http://x.example/h","channels":["blocks"]})),
            ))
            .await
            .unwrap();
        let (status, v) = json_of(resp).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(v["error"]["reason"], "insecure_url");
    }

    #[tokio::test]
    async fn register_rejects_loopback_ssrf() {
        let resp = app(state_enabled())
            .oneshot(req(
                "POST",
                "/api/v1/webhooks",
                Some("operator-secret"),
                Some(json!({"url":"https://127.0.0.1/h","channels":["blocks"]})),
            ))
            .await
            .unwrap();
        let (status, v) = json_of(resp).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(v["error"]["reason"], "forbidden_target");
    }

    #[tokio::test]
    async fn register_rejects_unlive_channel() {
        // token:* is a valid selector but has no live feed on a blocks_only bus
        // → channel_unavailable (the liveness gate, distinct from a malformed
        // selector which would be a 400 invalid_selector).
        let tok = "6a2d1e0f6a2d1e0f6a2d1e0f6a2d1e0f6a2d1e0f6a2d1e0f6a2d1e0f6a2d1e0f";
        let resp = app(state_enabled())
            .oneshot(req(
                "POST",
                "/api/v1/webhooks",
                Some("operator-secret"),
                Some(json!({"url":"https://x.example/h","channels":[format!("token:{tok}")]})),
            ))
            .await
            .unwrap();
        let (status, v) = json_of(resp).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(v["error"]["reason"], "channel_unavailable");
    }

    // ----- list / detail / delete / patch -----

    #[tokio::test]
    async fn list_detail_delete_lifecycle_never_echoes_secret() {
        let state = state_enabled();
        let router = app(state.clone());
        // register
        let resp = router
            .oneshot(req(
                "POST",
                "/api/v1/webhooks",
                Some("operator-secret"),
                Some(json!({"url":"https://x.example/h","channels":["blocks"]})),
            ))
            .await
            .unwrap();
        let (_, created) = json_of(resp).await;
        let id = created["webhook_id"].as_str().unwrap().to_string();

        // detail — no secret echoed
        let (status, v) = json_of(
            app(state.clone())
                .oneshot(req(
                    "GET",
                    &format!("/api/v1/webhooks/{id}"),
                    Some("operator-secret"),
                    None,
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            v.get("secret").is_none(),
            "detail must never echo the secret"
        );
        assert_eq!(v["secret_set"], true);

        // list
        let (status, v) = json_of(
            app(state.clone())
                .oneshot(req(
                    "GET",
                    "/api/v1/webhooks",
                    Some("operator-secret"),
                    None,
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(v["items"].as_array().unwrap().len(), 1);
        assert!(v["items"][0].get("secret").is_none());

        // patch pause
        let (status, v) = json_of(
            app(state.clone())
                .oneshot(req(
                    "PATCH",
                    &format!("/api/v1/webhooks/{id}"),
                    Some("operator-secret"),
                    Some(json!({"active": false})),
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(v["active"], false);

        // delete
        let (status, v) = json_of(
            app(state.clone())
                .oneshot(req(
                    "DELETE",
                    &format!("/api/v1/webhooks/{id}"),
                    Some("operator-secret"),
                    None,
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(v["deleted"], true);

        // detail now 404
        let (status, v) = json_of(
            app(state)
                .oneshot(req(
                    "GET",
                    &format!("/api/v1/webhooks/{id}"),
                    Some("operator-secret"),
                    None,
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(v["error"]["reason"], "webhook_not_found");
    }

    // ----- subsystem-off -----

    #[tokio::test]
    async fn disabled_subsystem_answers_webhooks_disabled_not_404() {
        let state = WebhooksState {
            handle: None,
            network: NetworkPrefix::Mainnet,
        };
        let (status, v) = json_of(
            app(state)
                .oneshot(req(
                    "GET",
                    "/api/v1/webhooks",
                    Some("operator-secret"),
                    None,
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(v["error"]["reason"], "webhooks_disabled");
    }
}
