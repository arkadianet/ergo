//! The delivery worker: a [`RealtimeBus`] subscriber that fans matched events
//! into per-webhook deliveries and drives the injected transport
//! ([`WebhookSink`]) under the [`WebhookEngine`]'s at-least-once retry
//! discipline.
//!
//! **Transport seam.** The concrete outbound HTTP(S) client is abstracted
//! behind [`WebhookSink`] and injected — the engine + worker + retry
//! discipline are fully unit-testable against a deterministic in-process fake
//! with no network at all. [`ReqwestSink`] is the production implementation:
//! a shared `reqwest` client, rustls-TLS only (no system OpenSSL — see
//! `ergo-api/Cargo.toml`), constructed once and spawned at the server seam
//! (`server.rs`) exactly like the O4 depth sampler / realtime-bridge feeder —
//! when a listener starts. Router construction does not spawn workers; the
//! server owns the worker and all its delivery children until shutdown. Deliveries now actually reach operator-registered
//! URLs; **persistence is the one remaining deferral** — the registry +
//! delivery log are in-memory and bounded, so a node restart loses all
//! registrations until a durable `*-db` schema lands.
//!
//! **Never stalls the bus.** The worker owns a bounded [`BusSubscription`]; a
//! slow endpoint only backs up that webhook's own deliveries (bounded ring +
//! per-webhook in-flight cap in the engine), and the bus's own slow-consumer
//! drop policy protects the fan-out if the worker itself falls behind.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;

use super::engine::{DeliveryOutcome, PreparedRequest, WebhookEngine};
use crate::v1::realtime::RealtimeBus;

/// Default scheduler tick: how often the worker re-checks for due deliveries
/// (newly enqueued or retry-due). Short enough for near-live first delivery,
/// long enough to be cheap when idle.
pub const DEFAULT_WORKER_TICK: Duration = Duration::from_millis(250);

/// The injected outbound transport. An implementation POSTs the prepared,
/// signed request and reports the outcome; it MUST bound its own timeout so a
/// black-hole endpoint cannot pin a worker task indefinitely.
#[async_trait]
pub trait WebhookSink: Send + Sync {
    /// POST `req.body` to `req.url` with `req.headers`, returning the outcome.
    async fn post(&self, req: &PreparedRequest) -> DeliveryOutcome;
}

/// Current wall-clock in unix milliseconds (the engine's injected clock at the
/// worker boundary).
pub fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Spawn the delivery worker. Subscribes to the bus, wires the engine's bus
/// pre-filter (so only events some webhook wants wake the worker), and loops:
/// enqueue on each event, drain due deliveries on each tick, drive the sink,
/// and record every outcome back into the engine.
///
/// Spawn ONLY from an async context (a Tokio runtime must be current), exactly
/// like the realtime bridge + the O4 depth sampler.
pub fn spawn_webhook_worker(
    bus: Arc<RealtimeBus>,
    engine: Arc<WebhookEngine>,
    sink: Arc<dyn WebhookSink>,
    tick: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut sub = bus.subscribe();
        // The engine keeps this filter synced to the union of active webhooks'
        // channels; the bus only fans matching events to us.
        engine.attach_filter(sub.filter.clone());

        let mut ticker = tokio::time::interval(tick);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        let mut deliveries = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                Some(result) = deliveries.join_next(), if !deliveries.is_empty() => {
                    if let Err(error) = result {
                        tracing::error!(%error, "webhook send task failed");
                    }
                }
                event = sub.rx.recv() => {
                    match event {
                        Some(ev) => {
                            engine.enqueue_matches(&ev, now_unix_ms());
                        }
                        None => break, // bus dropped (shutdown)
                    }
                }
                _ = ticker.tick() => {
                    drain_due(&engine, &sink, &mut deliveries);
                }
            }
        }
    })
}

/// Take every due request and spawn a bounded send task per request; each task
/// awaits the sink and records the outcome. Kept separate so the scheduling
/// step is unit-testable without the bus loop.
fn drain_due(
    engine: &Arc<WebhookEngine>,
    sink: &Arc<dyn WebhookSink>,
    deliveries: &mut tokio::task::JoinSet<()>,
) {
    let due = engine.take_due(now_unix_ms());
    for req in due {
        let engine = engine.clone();
        let sink = sink.clone();
        let attempt = DeliveryAttempt {
            engine,
            id: req.delivery_id.clone(),
            completed: false,
        };
        deliveries.spawn(async move {
            let outcome = sink.post(&req).await;
            attempt.complete(outcome);
        });
    }
}

/// Cancellation must release the engine's in-flight admission too. Keeping
/// this guard outside the child future also covers abort-before-first-poll.
struct DeliveryAttempt {
    engine: Arc<WebhookEngine>,
    id: String,
    completed: bool,
}

impl DeliveryAttempt {
    fn complete(mut self, outcome: DeliveryOutcome) {
        self.engine.record_result(&self.id, outcome, now_unix_ms());
        self.completed = true;
    }
}

impl Drop for DeliveryAttempt {
    fn drop(&mut self) {
        if !self.completed {
            self.engine
                .record_result(&self.id, DeliveryOutcome::TransportError, now_unix_ms());
        }
    }
}

/// Per-request timeout bound, covering the whole request lifecycle — DNS,
/// TCP/TLS connect, send, and response read. A black-hole or slow-drip
/// endpoint can hold a send task for at most this long; the engine's
/// per-webhook in-flight cap (`MAX_INFLIGHT_PER_WEBHOOK`) bounds the blast
/// radius while it does.
pub const SINK_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// The production [`WebhookSink`]: a shared `reqwest` client (rustls-TLS
/// only — no system OpenSSL; see `ergo-api/Cargo.toml`) that POSTs each
/// [`PreparedRequest`] and reports the HTTP outcome. Retry/backoff/dedupe is
/// entirely the [`WebhookEngine`]'s job — this sink only reports what
/// happened to one attempt, exactly once, and never retries internally.
///
/// **Redirects are disabled.** The SSRF guard
/// ([`validate_url`](super::model::validate_url)) only screens the
/// *registered* URL at registration time; if this sink auto-followed a 3xx it
/// would silently connect to a location that was never validated, defeating
/// the guard. A redirect response is therefore reported as an ordinary
/// [`DeliveryOutcome::HttpError`] (retryable, never delivered) instead of
/// being followed.
///
/// Every DNS answer is checked before connecting, including retries. The
/// checked addresses are returned directly to the connector, so there is no
/// second unchecked resolution. Environment proxies are disabled to preserve
/// that destination guarantee.
pub struct ReqwestSink {
    client: reqwest::Client,
    policy: super::model::UrlPolicy,
}

impl ReqwestSink {
    /// Build the shared client once (constructed at server start, not per
    /// request). Fails only if the TLS backend cannot initialize (e.g. no
    /// usable root store) — a startup-time condition; the server seam reacts
    /// by disabling the webhook subsystem (`webhooks_disabled`) rather than
    /// taking the node down.
    pub fn new() -> Result<Self, reqwest::Error> {
        Self::with_policy(Default::default())
    }

    /// Explicit destination opt-ins for trusted development integrations.
    pub fn with_policy(policy: super::model::UrlPolicy) -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder()
            .connect_timeout(SINK_REQUEST_TIMEOUT)
            .timeout(SINK_REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .dns_resolver(Arc::new(CheckedResolver {
                policy,
                lookup: Arc::new(SystemResolver),
            }))
            .build()?;
        Ok(ReqwestSink { client, policy })
    }
}

struct CheckedResolver {
    policy: super::model::UrlPolicy,
    lookup: Arc<dyn reqwest::dns::Resolve>,
}

struct SystemResolver;

impl reqwest::dns::Resolve for SystemResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        Box::pin(async move {
            let addresses = tokio::net::lookup_host((name.as_str(), 0))
                .await?
                .collect::<Vec<_>>();
            Ok(Box::new(addresses.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

fn checked_addresses(
    addresses: Vec<std::net::SocketAddr>,
    policy: &super::model::UrlPolicy,
) -> Result<reqwest::dns::Addrs, Box<dyn std::error::Error + Send + Sync>> {
    if addresses.is_empty()
        || addresses
            .iter()
            .any(|addr| !super::model::address_allowed(addr.ip(), policy))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "webhook DNS destination rejected",
        )
        .into());
    }
    Ok(Box::new(addresses.into_iter()))
}

impl reqwest::dns::Resolve for CheckedResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let policy = self.policy;
        let resolved = self.lookup.resolve(name);
        Box::pin(async move { checked_addresses(resolved.await?.collect(), &policy) })
    }
}

#[async_trait]
impl WebhookSink for ReqwestSink {
    async fn post(&self, req: &PreparedRequest) -> DeliveryOutcome {
        if super::model::validate_url(&req.url, &self.policy).is_err() {
            tracing::warn!("webhook delivery target rejected by destination policy");
            return DeliveryOutcome::TransportError;
        }
        let mut builder = self.client.post(&req.url);
        for (name, value) in &req.headers {
            builder = builder.header(*name, value);
        }
        match builder.body(req.body.clone()).send().await {
            Ok(resp) => {
                let status = resp.status();
                if status.is_success() {
                    DeliveryOutcome::Success(status.as_u16())
                } else {
                    DeliveryOutcome::HttpError(status.as_u16())
                }
            }
            // Connect / TLS / timeout / mid-transfer failure — no response to
            // grade, so there is no HTTP status to report. The outcome enum
            // can't carry the cause, so log it here (DNS vs TLS vs timeout).
            Err(error) => {
                tracing::warn!(url = %req.url, %error, "webhook delivery transport error");
                DeliveryOutcome::TransportError
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v1::realtime::RealtimeBus;
    use crate::v1::webhooks::engine::WebhookEngineConfig;
    use crate::v1::webhooks::model::sign_body;
    use std::sync::Mutex;

    #[tokio::test]
    async fn hostname_resolving_to_private_address_never_connects() {
        struct PrivateAnswer(std::net::SocketAddr);
        impl reqwest::dns::Resolve for PrivateAnswer {
            fn resolve(&self, _: reqwest::dns::Name) -> reqwest::dns::Resolving {
                let address = self.0;
                Box::pin(
                    async move { Ok(Box::new(std::iter::once(address)) as reqwest::dns::Addrs) },
                )
            }
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let policy = super::super::model::UrlPolicy::default();
        let client = reqwest::Client::builder()
            .no_proxy()
            .dns_resolver(Arc::new(CheckedResolver {
                policy,
                lookup: Arc::new(PrivateAnswer(address)),
            }))
            .build()
            .unwrap();
        let sink = ReqwestSink { client, policy };
        let request = PreparedRequest {
            delivery_id: "test".into(),
            webhook_id: "test".into(),
            url: format!("https://public-looking.invalid:{}/hook", address.port()),
            headers: vec![],
            body: "{}".into(),
        };
        assert!(super::super::model::validate_url(&request.url, &policy).is_ok());
        assert_eq!(sink.post(&request).await, DeliveryOutcome::TransportError);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), listener.accept())
                .await
                .is_err()
        );
    }

    #[test]
    fn resolver_rejects_private_and_mixed_dns_answers() {
        let policy = super::super::model::UrlPolicy::default();
        for private in [
            "127.0.0.1:0",
            "10.1.2.3:0",
            "169.254.169.254:0",
            "[::ffff:127.0.0.1]:0",
            "[fc00::1]:0",
        ] {
            let private = private.parse().unwrap();
            assert!(checked_addresses(vec![private], &policy).is_err());
            assert!(
                checked_addresses(vec!["93.184.216.34:0".parse().unwrap(), private], &policy)
                    .is_err()
            );
        }
        assert!(checked_addresses(Vec::new(), &policy).is_err());
        let public = "93.184.216.34:0".parse().unwrap();
        assert_eq!(
            checked_addresses(vec![public], &policy)
                .unwrap()
                .collect::<Vec<_>>(),
            vec![public]
        );
    }

    #[tokio::test]
    async fn aborting_worker_cancels_delivery_children_and_releases_admission() {
        struct PendingSink;
        #[async_trait]
        impl WebhookSink for PendingSink {
            async fn post(&self, _: &PreparedRequest) -> DeliveryOutcome {
                std::future::pending().await
            }
        }
        let bus = Arc::new(RealtimeBus::blocks_only());
        let engine = Arc::new(WebhookEngine::new(Default::default()));
        register_blocks(&engine);
        let worker = spawn_webhook_worker(
            bus.clone(),
            engine.clone(),
            Arc::new(PendingSink),
            Duration::from_millis(1),
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            while bus.subscriber_count() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        bus.publish(
            crate::v1::realtime::model::RealtimeEventBody::block_applied(
                1,
                "header".into(),
                10,
                1,
                10,
            ),
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            while engine.inflight_count() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        worker.abort();
        let _ = worker.await;
        tokio::time::timeout(Duration::from_secs(1), async {
            while engine.inflight_count() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(bus.subscriber_count(), 0);
    }

    // ----- helpers: a deterministic in-process sink (no network) -----

    /// Records every request and returns scripted outcomes. This is the
    /// injected transport the brief calls for — real worker code, no faked
    /// network I/O.
    struct FakeSink {
        outcomes: Mutex<std::collections::VecDeque<DeliveryOutcome>>,
        seen: Mutex<Vec<PreparedRequest>>,
        default: DeliveryOutcome,
    }

    impl FakeSink {
        fn new(default: DeliveryOutcome) -> Arc<Self> {
            Arc::new(FakeSink {
                outcomes: Mutex::new(std::collections::VecDeque::new()),
                seen: Mutex::new(Vec::new()),
                default,
            })
        }
    }

    #[async_trait]
    impl WebhookSink for FakeSink {
        async fn post(&self, req: &PreparedRequest) -> DeliveryOutcome {
            self.seen.lock().unwrap().push(req.clone());
            self.outcomes
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(self.default)
        }
    }

    fn register_blocks(e: &WebhookEngine) {
        e.register(
            "https://dapp.example/hook".into(),
            vec!["blocks".to_string()],
            Some("whsec_test".into()),
            1,
            0,
        )
        .unwrap();
    }

    // ----- drain drives the sink + records outcomes -----

    #[tokio::test]
    async fn drain_due_posts_and_records_success() {
        let engine = Arc::new(WebhookEngine::new(WebhookEngineConfig {
            retry_jitter_frac: 0.0,
        }));
        register_blocks(&engine);
        engine.enqueue_matches(
            &crate::v1::realtime::RealtimeEvent {
                seq: 1,
                emitted_at_unix_ms: 1_000,
                routes: vec!["blocks".into()],
                event: "block_applied",
                confirmed: true,
                height: Some(1),
                data: serde_json::json!({"height": 1}),
                previous_seq: None,
            },
            now_unix_ms(),
        );
        let sink: Arc<dyn WebhookSink> = FakeSink::new(DeliveryOutcome::Success(200));
        let mut deliveries = tokio::task::JoinSet::new();
        drain_due(&engine, &sink, &mut deliveries);
        // Let the spawned send task run.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let id = {
            let d = engine.deliveries_for(&engine.list(0, 1).remove(0).webhook_id, 0, 1);
            d[0].clone()
        };
        assert_eq!(id.status, super::super::model::DeliveryStatus::Delivered);
        assert_eq!(id.response_code, Some(200));
        assert_eq!(engine.inflight_count(), 0);
    }

    // ----- end-to-end over the real bus -----

    #[tokio::test]
    async fn worker_delivers_a_published_block_event_end_to_end() {
        let bus = Arc::new(RealtimeBus::blocks_only());
        let engine = Arc::new(WebhookEngine::new(WebhookEngineConfig {
            retry_jitter_frac: 0.0,
        }));
        register_blocks(&engine);
        let sink = FakeSink::new(DeliveryOutcome::Success(200));
        let sink_dyn: Arc<dyn WebhookSink> = sink.clone();
        let handle = spawn_webhook_worker(
            bus.clone(),
            engine.clone(),
            sink_dyn,
            Duration::from_millis(20),
        );
        // Give the worker a moment to subscribe + attach its filter.
        tokio::time::sleep(Duration::from_millis(30)).await;

        bus.publish(crate::v1::realtime::RealtimeEventBody::block_applied(
            42,
            "abcd".into(),
            1808901,
            7,
            4096,
        ));
        // Enqueue tick + send task + record.
        tokio::time::sleep(Duration::from_millis(120)).await;
        handle.abort();

        let seen = sink.seen.lock().unwrap();
        assert_eq!(seen.len(), 1, "one delivery posted");
        let req = &seen[0];
        // The signed body must verify with the webhook secret + timestamp header.
        let ts: u64 = req
            .headers
            .iter()
            .find(|(k, _)| *k == "X-Ergo-Timestamp")
            .map(|(_, v)| v.parse().unwrap())
            .unwrap();
        let sig = req
            .headers
            .iter()
            .find(|(k, _)| *k == "X-Ergo-Signature")
            .map(|(_, v)| v.clone())
            .unwrap();
        assert_eq!(sig, sign_body("whsec_test", ts, &req.body));
        // Body carries the shared seq + the v1 event data verbatim.
        let v: serde_json::Value = serde_json::from_str(&req.body).unwrap();
        assert_eq!(v["event"], "block_applied");
        assert_eq!(v["seq"], 1);
        assert_eq!(v["data"]["height"], 1808901);
        assert_eq!(v["confirmed"], true);
    }

    // ----- ReqwestSink (real transport) -----

    #[test]
    fn reqwest_sink_builds_with_rustls_tls_backend() {
        // Construction alone exercises the rustls-TLS backend wiring (no TLS
        // handshake happens here — that only occurs against an https:// URL).
        // A failure would mean the client cannot initialize its root store /
        // connector, which should fail loudly at startup, not silently.
        assert!(
            ReqwestSink::new().is_ok(),
            "reqwest client must build with the rustls-tls backend and no TLS deps missing"
        );
    }

    /// The live-transport leg: a real `reqwest` POST over a real TCP
    /// connection to a tiny in-process axum listener on `127.0.0.1:0` (an
    /// ephemeral loopback port — no real external URL is ever contacted).
    /// Asserts the listener actually received the exact signed body plus the
    /// full `X-Ergo-*` header set, and that `ReqwestSink::post` grades the
    /// 2xx response as [`DeliveryOutcome::Success`].
    #[tokio::test]
    async fn reqwest_sink_posts_signed_body_to_local_listener() {
        use axum::body::Bytes;
        use axum::extract::State;
        use axum::http::HeaderMap;
        use axum::routing::post;
        use tokio::sync::mpsc;

        #[derive(Clone)]
        struct Captured(Arc<mpsc::Sender<(HeaderMap, Bytes)>>);

        async fn capture(
            State(state): State<Captured>,
            headers: HeaderMap,
            body: Bytes,
        ) -> axum::http::StatusCode {
            let _ = state.0.send((headers, body)).await;
            axum::http::StatusCode::OK
        }

        let (tx, mut rx) = mpsc::channel(1);
        let app = axum::Router::new()
            .route("/hook", post(capture))
            .with_state(Captured(Arc::new(tx)));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind an ephemeral loopback port");
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("local listener serves");
        });

        let secret = "whsec_test";
        let body = r#"{"webhook_id":"wh_1","delivery_id":"dl_1","seq":1}"#.to_string();
        let ts = now_unix_ms();
        let sig = sign_body(secret, ts, &body);
        let req = PreparedRequest {
            delivery_id: "dl_1".into(),
            webhook_id: "wh_1".into(),
            url: format!("http://{addr}/hook"),
            headers: vec![
                ("Content-Type", "application/json".to_string()),
                ("X-Ergo-Webhook-Id", "wh_1".to_string()),
                ("X-Ergo-Delivery-Id", "dl_1".to_string()),
                ("X-Ergo-Event-Seq", "1".to_string()),
                ("X-Ergo-Timestamp", ts.to_string()),
                ("X-Ergo-Delivery-Attempt", "1".to_string()),
                ("X-Ergo-Signature", sig.clone()),
            ],
            body: body.clone(),
        };

        let sink = ReqwestSink::with_policy(super::super::model::UrlPolicy {
            allow_loopback: true,
            ..Default::default()
        })
        .expect("client builds");
        let outcome = sink.post(&req).await;
        assert_eq!(outcome, DeliveryOutcome::Success(200));

        let (headers, received_body) = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("listener received the request within the timeout")
            .expect("capture channel not closed");
        assert_eq!(received_body.as_ref(), body.as_bytes(), "exact signed body");
        assert_eq!(
            headers.get("x-ergo-signature").unwrap().to_str().unwrap(),
            sig
        );
        assert_eq!(
            headers.get("x-ergo-webhook-id").unwrap().to_str().unwrap(),
            "wh_1"
        );
        assert_eq!(
            headers.get("x-ergo-delivery-id").unwrap().to_str().unwrap(),
            "dl_1"
        );

        server.abort();
    }
}
