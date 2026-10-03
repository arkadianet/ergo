//! Per-node API state and background-task ownership. Building a router is pure;
//! only starting a listener starts workers, which stop with that listener.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::task::JoinHandle;

use crate::traits::NodeReadState;
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
    started: Arc<AtomicBool>,
}

impl ApiServices {
    pub fn new() -> Self {
        let realtime = RealtimeHandle::blocks_and_mempool();
        let engine = Arc::new(WebhookEngine::new(Default::default()));
        let (webhooks, sink) = match ReqwestSink::new() {
            Ok(sink) => (
                Some(WebhooksHandle {
                    engine,
                    bus: realtime.bus.clone(),
                    url_policy: Default::default(),
                }),
                Some(Arc::new(sink) as Arc<dyn WebhookSink>),
            ),
            Err(error) => {
                tracing::error!(%error, "webhook HTTP sink failed to build; webhooks disabled");
                (None, None)
            }
        };
        Self {
            realtime,
            compute: Default::default(),
            reads: crate::v1::BlockingReads::new(Default::default())
                .expect("default read bounds are valid"),
            mempool_depth: Arc::new(MempoolDepthRing::new()),
            webhooks,
            sink,
            started: Arc::new(AtomicBool::new(false)),
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

    pub(super) fn start(&self, read: Arc<dyn NodeReadState>) -> Option<BackgroundTasks> {
        if self.started.swap(true, Ordering::AcqRel) {
            return None;
        }
        let mut handles = vec![
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
        if let (Some(webhooks), Some(sink)) = (&self.webhooks, &self.sink) {
            handles.push(crate::v1::spawn_webhook_worker(
                self.realtime.bus.clone(),
                webhooks.engine.clone(),
                sink.clone(),
                crate::v1::webhooks::worker::DEFAULT_WORKER_TICK,
            ));
        }
        Some(BackgroundTasks {
            handles,
            started: self.started.clone(),
        })
    }
}

impl Default for ApiServices {
    fn default() -> Self {
        Self::new()
    }
}

/// A server owns its workers. Abort is cancellation-safe: webhook children are
/// kept in a JoinSet inside the worker, so they are aborted along with it.
pub(super) struct BackgroundTasks {
    handles: Vec<JoinHandle<()>>,
    started: Arc<AtomicBool>,
}

impl BackgroundTasks {
    pub async fn shutdown(mut self) {
        for handle in &self.handles {
            handle.abort();
        }
        for handle in self.handles.drain(..) {
            let _ = handle.await;
        }
    }
}

impl Drop for BackgroundTasks {
    fn drop(&mut self) {
        for handle in &self.handles {
            handle.abort();
        }
        self.started.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;
    use std::sync::atomic::AtomicUsize;

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
        let registration = first
            .webhooks
            .as_ref()
            .unwrap()
            .engine
            .register(
                "https://example.com/hook".into(),
                vec!["blocks".into()],
                None,
                1,
                0,
            )
            .unwrap();
        // Keep this ownership test independent of outbound network timing.
        first
            .webhooks
            .as_ref()
            .unwrap()
            .engine
            .set_active(&registration.webhook_id, false);
        assert_eq!(second.webhooks.as_ref().unwrap().engine.count(), 0);
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
    }

    #[tokio::test]
    async fn dropping_owner_aborts_workers() {
        let services = ApiServices::new();
        let read = Arc::new(Read {
            size: 1,
            samples: AtomicUsize::new(0),
            events: AtomicUsize::new(0),
        });
        let tasks = services.start(read.clone()).unwrap();
        wait_sample(&services).await;
        drop(tasks);
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while services.realtime.bus.subscriber_count() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(!services.started.load(Ordering::Acquire));
    }
}
