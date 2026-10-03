//! `webhooks/*` — durable, retried, signed outbound delivery: the **T1**
//! sibling of the WS [`RealtimeBus`](crate::v1::realtime).
//!
//! Webhooks POST admitted events to operator-registered URLs with bounded
//! exponential-backoff retries and HMAC signatures. Successful admission is
//! durable; retries can produce duplicate requests. Bus fanout and delivery-ring
//! admission are best effort under overload. Because registration makes the
//! node emit outbound requests, the management surface is **T1** (api-key).
//!
//! Layering (mirrors the `realtime/` sibling):
//! * [`model`] — the subscription + delivery records, their wire DTOs, the
//!   HMAC-SHA256 signing recipe, and the SSRF URL policy.
//! * [`engine`] — [`WebhookEngine`], the transport-free registry, delivery-log,
//!   and retry/backoff/dedupe/auto-disable state machine (clock-injected, fully
//!   unit-testable).
//! * [`worker`] — the [`WebhookSink`] transport seam + the [`crate::v1::realtime::RealtimeBus`]
//!   subscriber loop that drives it.
//! * [`routes`] — the T1 axum handlers + [`webhooks_router`].
//!
//! **Reuse, not reinvention.** Webhooks are an *internal subscriber* to the same
//! [`crate::v1::realtime::RealtimeBus`] the WS surface uses: one event source, one global `seq`, one
//! channel vocabulary ([`parse_channel`](crate::v1::realtime::parse_channel)),
//! the same `channel_unavailable` liveness gate for not-yet-live classes.
//!
//! **Live delivery.** The production sink ([`worker::ReqwestSink`], rustls-TLS
//! only — no system OpenSSL, see `ergo-api/Cargo.toml`) is wired at the server
//! seam with its lifetime tied to the production API server. Registered
//! webhooks now actually POST to their operator-configured URL under the
//! engine's bounded retry and HMAC signing policy.
//!
//! **Restart durability.** Production persists subscriptions, signing secrets,
//! bounded delivery history, retry deadlines and acknowledgements in a private
//! redb store. Unknown in-flight outcomes retry with the same delivery ID/body.
//! The bounded queue may reject new events when all entries are still pending;
//! No webhook gap marker is sent for pre-admission loss; consumers should
//! periodically reconcile chain state via REST.

pub mod blocking;
pub mod engine;
pub mod model;
pub mod routes;
pub mod worker;

pub use blocking::{WebhookAttempt, WebhookExecutionError, WebhookExecutor};
pub use engine::{
    DeliveryOutcome, PreparedRequest, RegisterError, WebhookEngine, WebhookEngineConfig,
};
pub use model::{sign_body, Subscription, UrlPolicy};
pub use routes::{webhooks_router, WebhooksHandle, WebhooksState};
pub use worker::{spawn_webhook_worker, ReqwestSink, WebhookSink, DEFAULT_WORKER_TICK};
