//! Per-node API state and background-task ownership. Building a router is pure;
//! only starting a listener starts workers, which stop with that listener.

use std::sync::{Arc, Mutex};

use tokio::task::{AbortHandle, JoinHandle};

use crate::traits::NodeReadState;
use crate::v1::webhooks::blocking::WebhookExecutor;
use crate::v1::{
    MempoolDepthRing, RealtimeHandle, ReqwestSink, WebhookEngine, WebhookSink, WebhooksHandle,
};

/// Shared services for one node. Clone the `Arc` when rebuilding its router;
/// construct a fresh instance for another node, including in the same process.
pub struct ApiServices {
    pub realtime: RealtimeHandle,
    pub compute: crate::v1::ComputePool,
    pub reads: crate::v1::BlockingReads,
    pub mempool_depth: Arc<MempoolDepthRing>,
    pub webhooks: Option<WebhooksHandle>,
    sink: Option<Arc<dyn WebhookSink>>,
    background: Arc<BackgroundControl>,
}

impl ApiServices {
    pub fn new() -> Self {
        Self::with_webhooks(Some(Arc::new(WebhookEngine::new(Default::default()))))
    }

    /// Construct one node's services with an already-opened webhook engine.
    /// `None` disables webhook routes and delivery without an in-memory fallback.
    /// The fresh bus is seeded above recovered obligations before any publisher
    /// or worker starts, so delivery dedupe keys cannot alias after restart.
    pub fn with_webhooks(engine: Option<Arc<WebhookEngine>>) -> Self {
        let realtime = RealtimeHandle::blocks_and_mempool();
        if let Some(engine) = &engine {
            realtime
                .bus
                .advance_cursor_to(engine.highest_event_seq().saturating_add(1));
        }
        let (webhooks, sink) = match engine.map(|engine| (engine, ReqwestSink::new())) {
            Some((engine, Ok(sink))) => (
                Some(WebhooksHandle {
                    executor: Arc::new(WebhookExecutor::new(engine)),
                    bus: realtime.bus.clone(),
                    url_policy: Default::default(),
                }),
                Some(Arc::new(sink) as Arc<dyn WebhookSink>),
            ),
            Some((_, Err(error))) => {
                tracing::error!(%error, "webhook HTTP sink failed to build; webhooks disabled");
                (None, None)
            }
            None => (None, None),
        };
        Self {
            realtime,
            compute: Default::default(),
            reads: crate::v1::BlockingReads::new(Default::default())
                .expect("default read bounds are valid"),
            mempool_depth: Arc::new(MempoolDepthRing::new()),
            webhooks,
            sink,
            background: Arc::new(BackgroundControl::default()),
        }
    }

    /// Close admission when an owner is dropped or node shutdown begins.
    pub fn close_blocking(&self) {
        self.compute.close();
        self.reads.close();
    }

    /// Explicit shutdown waits for accepted CPU work and store reads before closure.
    pub async fn shutdown_blocking(&self) {
        self.close_blocking();
        let shutdown = async {
            tokio::join!(self.compute.shutdown(), self.reads.shutdown());
        };
        tokio::pin!(shutdown);
        tokio::select! {
            _ = &mut shutdown => {},
            _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {
                tracing::info!("waiting for API blocking jobs to finish before storage shutdown");
                shutdown.await;
            }
        }
    }

    /// Join background workers even if the HTTP server was aborted while
    /// draining. Durable webhook requests finish their cancellation accounting
    /// before this returns; retaining this services owner preserves the join
    /// handles across cancellation of an earlier shutdown future.
    pub async fn shutdown_background(&self) {
        self.background.shutdown(None).await;
        if let Some(webhooks) = &self.webhooks {
            // Worker guards have now enqueued every unknown outcome. Keep the
            // shared lane owned until all accepted persistence jobs complete.
            webhooks.executor.shutdown().await;
        }
    }

    pub(super) fn start(&self, read: Arc<dyn NodeReadState>) -> Option<BackgroundTasks> {
        let mut tasks = self.background.tasks.try_lock().ok()?;
        if tasks.is_some() {
            return None;
        }
        let handles = vec![
            crate::v1::spawn_depth_sampler(
                read.clone(),
                self.mempool_depth.clone(),
                crate::v1::DEFAULT_SAMPLE_INTERVAL,
            ),
            crate::v1::spawn_event_bridge(
                read,
                self.realtime.bus.clone(),
                crate::v1::realtime::DEFAULT_BRIDGE_INTERVAL,
            ),
        ];
        let (webhook, webhook_shutdown) =
            if let (Some(webhooks), Some(sink)) = (&self.webhooks, &self.sink) {
                let (shutdown, signal) = tokio::sync::oneshot::channel();
                (
                    Some(
                        crate::v1::webhooks::worker::spawn_webhook_worker_with_executor(
                            self.realtime.bus.clone(),
                            webhooks.executor.clone(),
                            sink.clone(),
                            crate::v1::webhooks::worker::DEFAULT_WORKER_TICK,
                            signal,
                        ),
                    ),
                    Some(shutdown),
                )
            } else {
                (None, None)
            };
        let stop = Arc::new(StopSignals {
            readers: handles.iter().map(JoinHandle::abort_handle).collect(),
            webhook: Mutex::new(webhook_shutdown),
        });
        *tasks = Some(OwnedTasks {
            handles,
            webhook,
            stop: stop.clone(),
        });
        Some(BackgroundTasks {
            control: self.background.clone(),
            stop,
        })
    }
}

impl Default for ApiServices {
    fn default() -> Self {
        Self::new()
    }
}

/// The server's stop guard. Join ownership stays with ApiServices, so aborting
/// the HTTP task cannot detach workers from explicit node shutdown.
pub(super) struct BackgroundTasks {
    control: Arc<BackgroundControl>,
    stop: Arc<StopSignals>,
}

impl BackgroundTasks {
    pub async fn shutdown(self) {
        self.control.shutdown(Some(&self.stop)).await;
    }
}

#[derive(Default)]
struct BackgroundControl {
    tasks: tokio::sync::Mutex<Option<OwnedTasks>>,
}

struct OwnedTasks {
    handles: Vec<JoinHandle<()>>,
    webhook: Option<JoinHandle<()>>,
    stop: Arc<StopSignals>,
}

struct StopSignals {
    readers: Vec<AbortHandle>,
    webhook: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
}

impl StopSignals {
    fn request_stop(&self) {
        for reader in &self.readers {
            reader.abort();
        }
        if let Some(shutdown) = self
            .webhook
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            let _ = shutdown.send(());
        }
    }
}

impl BackgroundControl {
    async fn shutdown(&self, expected: Option<&Arc<StopSignals>>) {
        let mut owned = self.tasks.lock().await;
        if let Some(expected) = expected {
            if !owned
                .as_ref()
                .is_some_and(|tasks| Arc::ptr_eq(&tasks.stop, expected))
            {
                return;
            }
        }
        if let Some(tasks) = owned.as_mut() {
            // Select and stop this generation under the same lock used to
            // install a listener, so a waiting drain cannot join fresh workers.
            tasks.stop.request_stop();
            // Never abort the top-level webhook task: its cooperative stop
            // cancels AND joins delivery children. The retained handle remains
            // observable if this shutdown future itself is cancelled.
            if let Some(handle) = &mut tasks.webhook {
                if let Err(error) = handle.await {
                    tracing::error!(%error, "webhook worker failed during shutdown");
                }
            }
            tasks.webhook.take();
            while let Some(handle) = tasks.handles.last_mut() {
                if let Err(error) = handle.await {
                    if !error.is_cancelled() {
                        tracing::error!(%error, "API background reader failed during shutdown");
                    }
                }
                // Remove completed joins before awaiting another handle. A
                // cancelled drain must not poll an observed completion twice.
                tasks.handles.pop();
            }
        }
        owned.take();
    }
}

impl Drop for BackgroundTasks {
    fn drop(&mut self) {
        // This guard only owns signals for its listener. A completed or stale
        // guard cannot stop workers installed by a later listener.
        self.stop.request_stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    struct Read {
        size: u32,
        samples: AtomicUsize,
        events: AtomicUsize,
    }

    impl NodeReadState for Read {
        fn info(&self) -> ApiInfo {
            unreachable!()
        }
        fn status(&self) -> ApiStatus {
            unreachable!()
        }
        fn tip(&self) -> ApiTip {
            unreachable!()
        }
        fn sync(&self) -> ApiSyncStatus {
            unreachable!()
        }
        fn peers(&self) -> Vec<ApiPeer> {
            unreachable!()
        }
        fn mempool_summary(&self) -> ApiMempoolSummary {
            self.samples.fetch_add(1, Ordering::Relaxed);
            ApiMempoolSummary {
                size: self.size,
                total_bytes: 0,
                capacity_count: 100,
                capacity_bytes: 1000,
                revalidation_pending: 0,
            }
        }
        fn mempool_transactions(&self) -> ApiMempoolTransactions {
            ApiMempoolTransactions {
                transactions: vec![],
                weight_function: ApiWeightFunction::Cost,
            }
        }
        fn mempool_transaction(&self, _: &str) -> Option<ApiMempoolTransaction> {
            None
        }
        fn health(&self) -> ApiHealth {
            unreachable!()
        }
        fn events(&self) -> ApiNodeEvents {
            self.events.fetch_add(1, Ordering::Relaxed);
            ApiNodeEvents::default()
        }
    }

    async fn wait_sample(services: &ApiServices) {
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while services.mempool_depth.is_empty() || services.realtime.bus.subscriber_count() == 0
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[test]
    fn recovered_cursor_is_seeded_before_publishers_and_is_node_local() {
        #[derive(Default)]
        struct Store(Mutex<Option<Vec<u8>>>);
        impl crate::v1::webhooks::engine::WebhookStore for Store {
            fn load(&self) -> Result<Option<Vec<u8>>, String> {
                Ok(self.0.lock().unwrap().clone())
            }
            fn commit(&self, snapshot: &[u8]) -> Result<(), String> {
                *self.0.lock().unwrap() = Some(snapshot.to_vec());
                Ok(())
            }
        }
        let store = Arc::new(Store::default());
        let engine = WebhookEngine::durable(Default::default(), store.clone()).unwrap();
        engine
            .register(
                "https://example.com/hook".into(),
                vec!["blocks".into()],
                None,
                1,
                0,
            )
            .unwrap();
        engine.enqueue_matches(
            &crate::v1::realtime::RealtimeEvent {
                seq: 41,
                emitted_at_unix_ms: 0,
                routes: vec!["blocks".into()],
                event: "block_applied",
                confirmed: true,
                height: Some(1),
                data: serde_json::json!({"height":1}),
                previous_seq: None,
            },
            0,
        );
        drop(engine);
        let recovered = Arc::new(WebhookEngine::durable(Default::default(), store).unwrap());
        let first = ApiServices::with_webhooks(Some(recovered));
        let second = ApiServices::with_webhooks(None);
        assert_eq!(first.realtime.bus.latest_seq(), 41);
        assert_eq!(second.realtime.bus.latest_seq(), 0);
        assert_eq!(first.realtime.bus.subscriber_count(), 0);
        assert_eq!(
            first.realtime.bus.publish(
                crate::v1::realtime::model::RealtimeEventBody::block_applied(
                    1,
                    "header".into(),
                    1,
                    1,
                    1,
                )
            ),
            42
        );
        assert_eq!(second.realtime.bus.latest_seq(), 0);
    }

    #[tokio::test]
    async fn missing_engine_disables_delivery_without_fallback() {
        let services = ApiServices::with_webhooks(None);
        assert!(services.webhooks.is_none());
        assert!(services.sink.is_none());
        let read = Arc::new(Read {
            size: 3,
            samples: AtomicUsize::new(0),
            events: AtomicUsize::new(0),
        });
        let tasks = services.start(read).unwrap();
        assert!(services
            .background
            .tasks
            .lock()
            .await
            .as_ref()
            .unwrap()
            .webhook
            .is_none());
        tasks.shutdown().await;
        assert_eq!(services.realtime.bus.subscriber_count(), 0);
    }

    #[tokio::test]
    async fn cancelled_server_drain_retains_worker_for_explicit_services_join() {
        struct Dropped(Arc<AtomicBool>);
        impl Drop for Dropped {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }
        let services = ApiServices::with_webhooks(None);
        let (shutdown, signal) = tokio::sync::oneshot::channel();
        let (stopping, stopped) = tokio::sync::oneshot::channel();
        let (release, parked) = tokio::sync::oneshot::channel();
        let dropped = Arc::new(AtomicBool::new(false));
        let guard = Dropped(dropped.clone());
        let worker = tokio::spawn(async move {
            let _guard = guard;
            let _ = signal.await;
            stopping.send(()).unwrap();
            let _ = parked.await;
        });
        let stop = Arc::new(StopSignals {
            readers: vec![],
            webhook: Mutex::new(Some(shutdown)),
        });
        *services.background.tasks.lock().await = Some(OwnedTasks {
            handles: vec![],
            webhook: Some(worker),
            stop: stop.clone(),
        });
        let server_guard = BackgroundTasks {
            control: services.background.clone(),
            stop,
        };
        let server = tokio::spawn(server_guard.shutdown());
        tokio::time::timeout(std::time::Duration::from_secs(1), stopped)
            .await
            .unwrap()
            .unwrap();
        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
        assert!(!dropped.load(Ordering::Acquire));
        let mut drain = Box::pin(services.shutdown_background());
        tokio::select! {
            biased;
            _ = &mut drain => panic!("shutdown returned while its worker was parked"),
            _ = std::future::ready(()) => {},
        }
        release.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), drain)
            .await
            .unwrap();
        assert!(dropped.load(Ordering::Acquire));
        assert!(services.background.tasks.lock().await.is_none());
    }

    #[tokio::test]
    async fn stale_listener_guard_cannot_stop_or_join_restarted_workers() {
        let services = ApiServices::new();
        let read = Arc::new(Read {
            size: 3,
            samples: AtomicUsize::new(0),
            events: AtomicUsize::new(0),
        });
        let stale = services.start(read.clone()).unwrap();
        wait_sample(&services).await;
        // Another owner completed this listener's nonterminal drain, but its
        // server guard may still be unwinding on a different runtime thread.
        services.background.shutdown(None).await;
        let current = services.start(read).unwrap();
        wait_sample(&services).await;
        stale.shutdown().await;
        assert!(services.background.tasks.lock().await.is_some());
        assert!(
            current.stop.webhook.lock().unwrap().is_some(),
            "the stale guard consumed the restarted listener's stop signal"
        );
        assert_eq!(services.realtime.bus.subscriber_count(), 1);
        current.shutdown().await;
        services.shutdown_background().await;
    }

    #[tokio::test]
    async fn cancelled_reader_drain_does_not_repoll_completed_joins() {
        let services = ApiServices::with_webhooks(None);
        let completed = tokio::spawn(async {});
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while !completed.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let (release, parked) = tokio::sync::oneshot::channel();
        let pending = tokio::spawn(async move {
            let _ = parked.await;
        });
        *services.background.tasks.lock().await = Some(OwnedTasks {
            handles: vec![pending, completed],
            webhook: None,
            stop: Arc::new(StopSignals {
                readers: vec![],
                webhook: Mutex::new(None),
            }),
        });
        let mut drain = Box::pin(services.background.shutdown(None));
        tokio::select! {
            biased;
            _ = &mut drain => panic!("reader drain returned while a reader was parked"),
            _ = std::future::ready(()) => {},
        }
        drop(drain);
        assert_eq!(
            services
                .background
                .tasks
                .lock()
                .await
                .as_ref()
                .unwrap()
                .handles
                .len(),
            1
        );
        release.send(()).unwrap();
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            services.shutdown_background(),
        )
        .await
        .unwrap();
        assert!(services.background.tasks.lock().await.is_none());
    }

    #[tokio::test]
    async fn node_services_are_isolated_stop_and_restart() {
        let first = ApiServices::new();
        let second = ApiServices::new();
        assert!(!Arc::ptr_eq(&first.realtime.bus, &second.realtime.bus));
        let first_read = Arc::new(Read {
            size: 10,
            samples: AtomicUsize::new(0),
            events: AtomicUsize::new(0),
        });
        let second_read = Arc::new(Read {
            size: 20,
            samples: AtomicUsize::new(0),
            events: AtomicUsize::new(0),
        });
        // Construction is pure, even under a live runtime.
        tokio::task::yield_now().await;
        assert!(first.mempool_depth.is_empty());
        assert_eq!(first.realtime.bus.subscriber_count(), 0);
        let first_tasks = first.start(first_read.clone()).unwrap();
        let second_tasks = second.start(second_read.clone()).unwrap();
        assert!(first.start(first_read.clone()).is_none());
        wait_sample(&first).await;
        wait_sample(&second).await;
        assert_eq!(first.mempool_depth.latest().unwrap().size, 10);
        assert_eq!(second.mempool_depth.latest().unwrap().size, 20);
        first
            .webhooks
            .as_ref()
            .unwrap()
            .executor
            .run(|engine| {
                let registration = engine
                    .register(
                        "https://example.com/hook".into(),
                        vec!["blocks".into()],
                        None,
                        1,
                        0,
                    )
                    .unwrap();
                // Keep this ownership test independent of outbound network timing.
                engine.set_active(&registration.webhook_id, false);
            })
            .await
            .unwrap();
        assert_eq!(
            second
                .webhooks
                .as_ref()
                .unwrap()
                .executor
                .run(WebhookEngine::count)
                .await
                .unwrap(),
            0
        );
        first.realtime.bus.publish(
            crate::v1::realtime::model::RealtimeEventBody::block_applied(
                1,
                "header".into(),
                10,
                1,
                10,
            ),
        );
        assert_eq!(second.realtime.bus.latest_seq(), 0);
        first_tasks.shutdown().await;
        second_tasks.shutdown().await;
        assert_eq!(first.realtime.bus.subscriber_count(), 0);
        assert_eq!(second.realtime.bus.subscriber_count(), 0);
        let before = first_read.samples.load(Ordering::Relaxed);
        let restarted = first.start(first_read.clone()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while first_read.samples.load(Ordering::Relaxed) == before {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        restarted.shutdown().await;
        assert_eq!(first.realtime.bus.subscriber_count(), 0);
        first.shutdown_background().await;
        second.shutdown_background().await;
    }

    #[tokio::test]
    async fn dropping_owner_requests_stop_and_retains_join_ownership() {
        let services = ApiServices::new();
        let read = Arc::new(Read {
            size: 1,
            samples: AtomicUsize::new(0),
            events: AtomicUsize::new(0),
        });
        let tasks = services.start(read.clone()).unwrap();
        wait_sample(&services).await;
        drop(tasks);
        assert!(services.background.tasks.lock().await.is_some());
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            services.shutdown_background(),
        )
        .await
        .unwrap();
        assert_eq!(services.realtime.bus.subscriber_count(), 0);
        assert!(services.background.tasks.lock().await.is_none());
    }
}
