//! The delivery worker: a [`RealtimeBus`] subscriber that fans matched events
//! into per-webhook deliveries and drives the injected transport
//! ([`WebhookSink`]) under the [`WebhookEngine`]'s at-least-once retry
//! discipline (`v1-api-design.md` §4.1, fragment §3.3).
//!
//! **Transport seam (design decision).** The concrete outbound HTTP(S) client
//! is abstracted behind [`WebhookSink`] and **injected**. The node's lock has
//! no HTTP client and no TLS stack (`reqwest`/`hyper-rustls` are absent;
//! `hyper` is only a transitive axum dep), so shipping a real HTTPS client
//! would be exactly the heavy new dependency the brief says not to add
//! unilaterally. This PR therefore ships the full worker + engine + retry state
//! machine, tested end-to-end against a deterministic in-process sink (no
//! network, nothing faked). Wiring a concrete TLS-capable sink is the one
//! remaining, documented deferral — see the PR report.
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

        loop {
            tokio::select! {
                event = sub.rx.recv() => {
                    match event {
                        Some(ev) => {
                            engine.enqueue_matches(&ev, now_unix_ms());
                        }
                        None => break, // bus dropped (shutdown)
                    }
                }
                _ = ticker.tick() => {
                    drain_due(&engine, &sink);
                }
            }
        }
    })
}

/// Take every due request and spawn a bounded send task per request; each task
/// awaits the sink and records the outcome. Kept separate so the scheduling
/// step is unit-testable without the bus loop.
fn drain_due(engine: &Arc<WebhookEngine>, sink: &Arc<dyn WebhookSink>) {
    let due = engine.take_due(now_unix_ms());
    for req in due {
        let engine = engine.clone();
        let sink = sink.clone();
        tokio::spawn(async move {
            let outcome = sink.post(&req).await;
            engine.record_result(&req.delivery_id, outcome, now_unix_ms());
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v1::realtime::RealtimeBus;
    use crate::v1::webhooks::engine::WebhookEngineConfig;
    use crate::v1::webhooks::model::sign_body;
    use std::sync::Mutex;

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
        drain_due(&engine, &sink);
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
}
