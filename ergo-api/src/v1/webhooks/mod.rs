//! `webhooks/*` — durable, retried, signed outbound delivery: the **T1**
//! sibling of the WS [`RealtimeBus`](crate::v1::realtime) (`v1-api-design.md`
//! §4.1, fragment `realtime-ws-webhooks.md` §3).
//!
//! Where WS pushes to an open socket, a webhook makes the node POST each
//! matching event to an operator-registered URL with an **at-least-once,
//! exponential-backoff, HMAC-signed** delivery guarantee — the infrastructure a
//! dApp backend would otherwise rebuild. Because registration makes the node
//! emit outbound requests, the whole management surface is **T1** (api-key).
//!
//! Layering (mirrors the `realtime/` sibling):
//! * [`model`] — the subscription + delivery records, their wire DTOs, the
//!   HMAC-SHA256 signing recipe, and the SSRF URL policy.
//! * [`engine`] — [`WebhookEngine`], the transport-free registry, delivery-log,
//!   and retry/backoff/dedupe/auto-disable state machine (clock-injected, fully
//!   unit-testable).
//! * [`worker`] — the [`WebhookSink`] transport seam + the [`RealtimeBus`]
//!   subscriber loop that drives it.
//! * [`routes`] — the T1 axum handlers + [`webhooks_router`].
//!
//! **Reuse, not reinvention.** Webhooks are an *internal subscriber* to the same
//! [`RealtimeBus`] the WS surface uses: one event source, one global `seq`, one
//! channel vocabulary ([`parse_channel`](crate::v1::realtime::parse_channel)),
//! the same `channel_unavailable` liveness gate for not-yet-live classes.
//!
//! **Live delivery.** The production sink ([`worker::ReqwestSink`], rustls-TLS
//! only — no system OpenSSL, see `ergo-api/Cargo.toml`) is wired at the server
//! seam and spawned exactly once per process, guarded to a live Tokio runtime
//! (same idiom as the O4 depth sampler / realtime-bridge feeder). Registered
//! webhooks now actually POST to their operator-configured URL under the
//! engine's at-least-once, exponential-backoff, HMAC-signed discipline.
//!
//! **One remaining honest deferral (see the PR report): persistence.** The
//! registry + delivery log are bounded and in-memory; registrations are LOST
//! on node restart until a `*-db` schema lands (CLAUDE.md §2). No schema is
//! invented here.

pub mod engine;
pub mod model;
pub mod routes;
pub mod worker;

pub use engine::{
    DeliveryOutcome, PreparedRequest, RegisterError, WebhookEngine, WebhookEngineConfig,
};
pub use model::{sign_body, Subscription, UrlPolicy};
pub use routes::{webhooks_router, WebhooksHandle, WebhooksState};
pub use worker::{
    spawn_webhook_worker, spawn_webhook_worker_once, ReqwestSink, WebhookSink, DEFAULT_WORKER_TICK,
};
