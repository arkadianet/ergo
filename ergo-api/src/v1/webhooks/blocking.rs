//! Owned blocking execution for durable webhook state. The thread starts on
//! first use; constructing a router does not start background work. Management,
//! scheduling and reserved outcomes have separate admission budgets, so a full
//! management queue cannot prevent cancellation acknowledgements.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};

use axum::{http::header::RETRY_AFTER, response::Response};
use tokio::sync::{mpsc, oneshot, Notify, OwnedSemaphorePermit, Semaphore};

use super::engine::{DeliveryOutcome, PreparedRequest, WebhookEngine, MAX_INFLIGHT_GLOBAL};
use super::worker::now_unix_ms;
use crate::v1::error::{v1_error, Reason};

/// Maximum accepted management operations, including the running operation.
pub const MANAGEMENT_CAPACITY: usize = 8;
/// One scheduler operation and one outcome slot for each possible in-flight send.
const QUEUE_CAPACITY: usize = MANAGEMENT_CAPACITY + 1 + MAX_INFLIGHT_GLOBAL;

type Job = Box<dyn FnOnce(&WebhookEngine) + Send + 'static>;

enum Message {
    Job(Job),
    Stop,
}

struct Admission {
    closed: bool,
    stopped: bool,
    engine: Option<Arc<WebhookEngine>>,
    sender: Option<mpsc::Sender<Message>>,
    thread: Option<std::thread::JoinHandle<()>>,
    join: Option<tokio::task::JoinHandle<()>>,
}

struct Shared {
    admission: Mutex<Admission>,
    management: Arc<Semaphore>,
    scheduler: Arc<Semaphore>,
    outcomes: Arc<Semaphore>,
    stopped: Arc<AtomicBool>,
    finished: Arc<Notify>,
}

/// Failure before admission, or a caught panic from an accepted operation.
/// Accepted storage work has no response timeout and continues if its caller
/// disconnects. API errors and tracing messages exclude panic payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebhookExecutionError {
    /// The operation's bounded admission budget is occupied.
    Overloaded,
    /// The executor is shutting down or its thread could not start.
    Closed,
    /// An accepted operation panicked.
    Panicked,
}

impl std::fmt::Display for WebhookExecutionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Overloaded => "webhook operation admission is full",
            Self::Closed => "webhook operation admission is closed",
            Self::Panicked => "webhook operation panicked",
        })
    }
}

impl std::error::Error for WebhookExecutionError {}

impl WebhookExecutionError {
    /// Render the v1 error envelope. Admission failures are retryable 503s.
    pub fn into_response(self) -> Response {
        let mut response = match self {
            Self::Overloaded | Self::Closed => v1_error(
                Reason::Overloaded,
                "webhook storage is busy or shutting down",
                "retry the request shortly",
            ),
            Self::Panicked => v1_error(
                Reason::InternalError,
                "the webhook operation could not be completed",
                "an internal error occurred",
            ),
        };
        if self != Self::Panicked {
            response
                .headers_mut()
                .insert(RETRY_AFTER, "1".parse().unwrap());
        }
        response
    }
}

/// A shared, lazy blocking lane for one webhook engine. All production reads,
/// mutations and response serialization run here rather than on Tokio threads.
/// Call [`Self::shutdown`] after stopping the delivery worker to join accepted
/// work and release the lane's database ownership.
#[derive(Clone)]
pub struct WebhookExecutor {
    shared: Arc<Shared>,
}

impl WebhookExecutor {
    /// Wrap the engine without starting a thread. Share this same executor
    /// between management routes and the delivery worker.
    pub fn new(engine: Arc<WebhookEngine>) -> Self {
        Self {
            shared: Arc::new(Shared {
                admission: Mutex::new(Admission {
                    closed: false,
                    stopped: false,
                    engine: Some(engine),
                    sender: None,
                    thread: None,
                    join: None,
                }),
                management: Arc::new(Semaphore::new(MANAGEMENT_CAPACITY)),
                scheduler: Arc::new(Semaphore::new(1)),
                outcomes: Arc::new(Semaphore::new(MAX_INFLIGHT_GLOBAL)),
                stopped: Arc::new(AtomicBool::new(false)),
                finished: Arc::new(Notify::new()),
            }),
        }
    }

    /// Admit a management operation or return overload before it starts.
    /// The permit remains with physical work if the awaiting HTTP caller drops.
    pub async fn run<T, F>(&self, work: F) -> Result<T, WebhookExecutionError>
    where
        T: Send + 'static,
        F: FnOnce(&WebhookEngine) -> T + Send + 'static,
    {
        let permit = self
            .shared
            .management
            .clone()
            .try_acquire_owned()
            .map_err(|_| WebhookExecutionError::Overloaded)?;
        self.run_admitted(work, permit, false).await
    }

    /// Admit one scheduler operation independently of management pressure.
    /// The worker awaits completion without a timeout; accepted work is owned
    /// by the lane even if that worker is cancelled.
    pub async fn run_worker<T, F>(&self, work: F) -> Result<T, WebhookExecutionError>
    where
        T: Send + 'static,
        F: FnOnce(&WebhookEngine) -> T + Send + 'static,
    {
        let permit = self
            .shared
            .scheduler
            .clone()
            .try_acquire_owned()
            .map_err(|_| WebhookExecutionError::Overloaded)?;
        self.run_admitted(work, permit, false).await
    }

    async fn run_admitted<T, F>(
        &self,
        work: F,
        permit: OwnedSemaphorePermit,
        allow_closed: bool,
    ) -> Result<T, WebhookExecutionError>
    where
        T: Send + 'static,
        F: FnOnce(&WebhookEngine) -> T + Send + 'static,
    {
        let (send, receive) = oneshot::channel();
        self.enqueue(
            Box::new(move |engine| {
                let result =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| work(engine)))
                        .map_err(|_| {
                            engine.fail_closed_after_panic();
                            WebhookExecutionError::Panicked
                        });
                // Publish only after physical work and its admission are
                // complete; the caller may immediately schedule its next job.
                drop(permit);
                // A cancelled receiver drops its result on this blocking
                // thread. In particular, returned attempt guards enqueue their
                // cancellation outcomes before releasing reserved capacity.
                let _ = send.send(result);
            }),
            allow_closed,
        )?;
        receive.await.unwrap_or(Err(WebhookExecutionError::Closed))
    }

    /// Reserve due requests together with guaranteed outcome capacity. Dropping
    /// the response or any returned attempt queues a transport-error outcome;
    /// no persisted reservation is left without owned cancellation accounting.
    pub async fn take_due(&self, now: u64) -> Result<Vec<WebhookAttempt>, WebhookExecutionError> {
        let shared = self.shared.clone();
        self.run_worker(move |engine| {
            let mut permits = Vec::new();
            while let Ok(permit) = shared.outcomes.clone().try_acquire_owned() {
                permits.push(permit);
            }
            let due = engine.take_due_bounded(now, permits.len());
            due.into_iter()
                .zip(permits)
                .map(|(request, permit)| WebhookAttempt {
                    request,
                    completion: Some(Completion {
                        executor: Self {
                            shared: shared.clone(),
                        },
                        permit,
                    }),
                })
                .collect()
        })
        .await
    }

    fn enqueue(&self, job: Job, allow_closed: bool) -> Result<(), WebhookExecutionError> {
        let mut state = self
            .shared
            .admission
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if state.stopped || (state.closed && !allow_closed) {
            return Err(WebhookExecutionError::Closed);
        }
        if state.sender.is_none() {
            let (sender, mut receive) = mpsc::channel(QUEUE_CAPACITY);
            let engine = state.engine.as_ref().expect("unstarted engine").clone();
            let thread = std::thread::Builder::new()
                .name("ergo-webhooks".into())
                .spawn(move || {
                    while let Some(message) = receive.blocking_recv() {
                        match message {
                            Message::Job(job) => {
                                if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                    job(&engine)
                                }))
                                .is_err()
                                {
                                    engine.fail_closed_after_panic();
                                    tracing::error!("webhook blocking operation panicked");
                                }
                            }
                            Message::Stop => break,
                        }
                    }
                    drop(engine);
                })
                .map_err(|error| {
                    tracing::error!(%error, "webhook blocking thread could not start");
                    state.closed = true;
                    WebhookExecutionError::Closed
                })?;
            state.engine = None;
            state.sender = Some(sender);
            state.thread = Some(thread);
        }
        state
            .sender
            .as_ref()
            .expect("started sender")
            .try_send(Message::Job(job))
            .map_err(|error| {
                // Every queued/running operation owns one of the 73 permits.
                // Critical outcomes reuse their reservation's permit, so even
                // a guard dropped on this thread always has queue capacity.
                tracing::error!(%error, "webhook operation queue invariant failed");
                WebhookExecutionError::Closed
            })
    }

    /// Reject new management and scheduler admission. Reserved outcomes remain
    /// accepted until their physical commits complete.
    pub fn close(&self) {
        self.shared
            .admission
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .closed = true;
    }

    /// Join work queued before this nonterminal barrier and all reserved
    /// outcomes. Listener shutdown calls this after joining send tasks, without
    /// disabling listener restart. Live attempts must be completed or dropped
    /// before awaiting the barrier.
    pub async fn drain(&self) -> Result<(), WebhookExecutionError> {
        let permit = self
            .shared
            .scheduler
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| WebhookExecutionError::Closed)?;
        let _outcomes = self
            .shared
            .outcomes
            .clone()
            .acquire_many_owned(MAX_INFLIGHT_GLOBAL as u32)
            .await
            .map_err(|_| WebhookExecutionError::Closed)?;
        {
            let state = self
                .shared
                .admission
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if state.stopped || state.sender.is_none() {
                return Ok(());
            }
        }
        self.run_admitted(|_| (), permit, true).await
    }

    /// Close admission and join all accepted work and reserved outcomes. This
    /// can be called again if a previous shutdown awaiter was cancelled: thread
    /// ownership stays here, and stopping never precedes outcome completion.
    pub async fn shutdown(&self) {
        self.close();
        let _scheduler = self
            .shared
            .scheduler
            .clone()
            .acquire_owned()
            .await
            .expect("scheduler semaphore remains open for shutdown");
        let _outcomes = self
            .shared
            .outcomes
            .clone()
            .acquire_many_owned(MAX_INFLIGHT_GLOBAL as u32)
            .await
            .expect("outcome semaphore remains open for shutdown");
        {
            let mut state = self
                .shared
                .admission
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if !state.stopped {
                state.stopped = true;
                if let Some(sender) = &state.sender {
                    // Scheduler and outcome permits are held here. At most
                    // eight management jobs remain, leaving room for Stop.
                    sender
                        .try_send(Message::Stop)
                        .expect("reserved shutdown queue space");
                }
            }
            let thread = state.thread.take();
            let engine = state.engine.take();
            if thread.is_some() || engine.is_some() {
                let done = self.shared.stopped.clone();
                let finished = self.shared.finished.clone();
                // The handle stays owned by Admission if a shutdown awaiter
                // disconnects. Completion is signalled after the OS thread is
                // joined, including release of its engine/store captures.
                state.join = Some(tokio::task::spawn_blocking(move || {
                    if let Some(thread) = thread {
                        if thread.join().is_err() {
                            tracing::error!("webhook blocking thread panicked");
                        }
                    }
                    // Even a never-started durable engine can flush on Drop.
                    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(engine)))
                        .is_err()
                    {
                        tracing::error!("webhook engine destruction panicked");
                    }
                    done.store(true, Ordering::Release);
                    finished.notify_waiters();
                }));
            }
        }
        loop {
            let notified = self.shared.finished.notified();
            if self.shared.stopped.load(Ordering::Acquire) {
                break;
            }
            notified.await;
        }
    }
}

struct Completion {
    executor: WebhookExecutor,
    permit: OwnedSemaphorePermit,
}

impl Completion {
    fn enqueue(
        self,
        id: String,
        outcome: DeliveryOutcome,
        now: u64,
    ) -> Result<oneshot::Receiver<Result<(), WebhookExecutionError>>, WebhookExecutionError> {
        let (send, receive) = oneshot::channel();
        let permit = self.permit;
        self.executor.enqueue(
            Box::new(move |engine| {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    engine.record_result(&id, outcome, now)
                }))
                .map_err(|_| {
                    engine.fail_closed_after_panic();
                    WebhookExecutionError::Panicked
                });
                drop(permit);
                let _ = send.send(result);
            }),
            true,
        )?;
        Ok(receive)
    }
}

/// One reserved request with owned outcome capacity. Cancellation queues its
/// retry accounting without waiting for a mutex, serialization or filesystem IO.
pub struct WebhookAttempt {
    request: PreparedRequest,
    completion: Option<Completion>,
}

impl WebhookAttempt {
    /// The signed request; its body and delivery ID remain stable across retries.
    pub fn request(&self) -> &PreparedRequest {
        &self.request
    }

    /// Commit an outcome off-runtime. Once enqueued, acknowledgement work is
    /// retained even if this awaiting future is cancelled.
    pub async fn complete(
        mut self,
        outcome: DeliveryOutcome,
        now: u64,
    ) -> Result<(), WebhookExecutionError> {
        let completion = self
            .completion
            .take()
            .expect("attempt owns outcome capacity");
        completion
            .enqueue(self.request.delivery_id.clone(), outcome, now)?
            .await
            .unwrap_or(Err(WebhookExecutionError::Closed))
    }
}

impl Drop for WebhookAttempt {
    fn drop(&mut self) {
        if let Some(completion) = self.completion.take() {
            if let Err(error) = completion.enqueue(
                self.request.delivery_id.clone(),
                DeliveryOutcome::TransportError,
                now_unix_ms(),
            ) {
                tracing::error!(?error, "webhook cancellation outcome could not be queued");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v1::realtime::RealtimeEvent;
    use crate::v1::webhooks::engine::WebhookStore;
    use std::sync::{atomic::AtomicU8, Condvar};
    use std::time::Duration;

    #[derive(Default)]
    struct Gate {
        blocked: Mutex<bool>,
        wake: Condvar,
        entered: Notify,
    }

    impl Gate {
        fn arm(self: &Arc<Self>) -> Release {
            *self.blocked.lock().unwrap() = true;
            Release(self.clone())
        }

        fn wait(&self) -> Result<(), String> {
            self.entered.notify_one();
            let state = self.blocked.lock().unwrap();
            // A regression must fail, rather than leave the test runtime hung
            // on an intentionally blocked commit or final database drop.
            let (state, timeout) = self
                .wake
                .wait_timeout_while(state, Duration::from_secs(5), |blocked| *blocked)
                .unwrap();
            if timeout.timed_out() && *state {
                Err("test storage gate timed out".into())
            } else {
                Ok(())
            }
        }

        async fn entered(&self) {
            tokio::time::timeout(Duration::from_secs(2), self.entered.notified())
                .await
                .unwrap();
        }
    }

    struct Release(Arc<Gate>);

    impl Drop for Release {
        fn drop(&mut self) {
            *self.0.blocked.lock().unwrap() = false;
            self.0.wake.notify_all();
        }
    }

    #[derive(Default)]
    struct TestStore {
        snapshot: Mutex<Option<Vec<u8>>>,
        gate: Arc<Gate>,
        next_commit: AtomicU8,
    }

    impl TestStore {
        fn block_next(&self) -> Release {
            let release = self.gate.arm();
            self.next_commit.store(1, Ordering::Release);
            release
        }
    }

    impl WebhookStore for TestStore {
        fn load(&self) -> Result<Option<Vec<u8>>, String> {
            Ok(self.snapshot.lock().unwrap().clone())
        }

        fn commit(&self, snapshot: &[u8]) -> Result<(), String> {
            match self.next_commit.swap(0, Ordering::AcqRel) {
                1 => self.gate.wait()?,
                2 => panic!("injected store panic"),
                _ => {}
            }
            *self.snapshot.lock().unwrap() = Some(snapshot.to_vec());
            Ok(())
        }
    }

    fn fixture() -> (Arc<WebhookExecutor>, Arc<TestStore>) {
        let store = Arc::new(TestStore::default());
        let engine = WebhookEngine::durable(Default::default(), store.clone()).unwrap();
        (Arc::new(WebhookExecutor::new(Arc::new(engine))), store)
    }

    fn register(engine: &WebhookEngine) -> String {
        engine
            .register(
                "https://example.com/hook".into(),
                vec!["blocks".into()],
                Some("private-secret".into()),
                1,
                0,
            )
            .unwrap()
            .webhook_id
    }

    fn event(seq: u64) -> RealtimeEvent {
        RealtimeEvent {
            seq,
            emitted_at_unix_ms: 1,
            routes: vec!["blocks".into()],
            event: "block_applied",
            confirmed: true,
            height: Some(100),
            data: serde_json::json!({"height":100}),
            previous_seq: None,
        }
    }

    async fn pending_delivery(executor: &WebhookExecutor) -> String {
        executor
            .run(|engine| {
                let id = register(engine);
                engine.enqueue_matches(&event(1), 0);
                id
            })
            .await
            .unwrap()
    }

    async fn saturated(executor: &WebhookExecutor) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while executor.shared.management.available_permits() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn blocked_commit_keeps_timer_and_reads_off_reactor() {
        let (executor, store) = fixture();
        use crate::auth::ApiSecurity;
        use crate::v1::auth::V1AuthConfig;
        use crate::v1::webhooks::{webhooks_router, UrlPolicy, WebhooksHandle, WebhooksState};
        use axum::{
            body::Body,
            http::{Request, StatusCode},
        };
        use tower::ServiceExt;
        let auth = V1AuthConfig::new(Some(Arc::new(
            ApiSecurity::new(ApiSecurity::hash_key(b"operator-secret")).unwrap(),
        )))
        .into_shared();
        let app = webhooks_router(
            WebhooksState {
                handle: Some(WebhooksHandle {
                    executor: executor.clone(),
                    bus: Arc::new(crate::v1::realtime::RealtimeBus::blocks_only()),
                    url_policy: UrlPolicy::default(),
                }),
                network: ergo_ser::address::NetworkPrefix::Mainnet,
            },
            auth,
        );
        let post = Request::builder()
            .method("POST")
            .uri("/api/v1/webhooks")
            .header(crate::auth::API_KEY_HEADER, "operator-secret")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"url":"https://example.com/hook","channels":["blocks"]}"#,
            ))
            .unwrap();
        let release = store.block_next();
        let writing = {
            let app = app.clone();
            tokio::spawn(async move { app.oneshot(post).await.unwrap() })
        };
        store.gate.entered().await;
        let reading = {
            let get = Request::builder()
                .uri("/api/v1/webhooks")
                .header(crate::auth::API_KEY_HEADER, "operator-secret")
                .body(Body::empty())
                .unwrap();
            tokio::spawn(async move { app.oneshot(get).await.unwrap() })
        };
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert!(
            !writing.is_finished(),
            "commit was acknowledged while blocked"
        );
        assert!(
            !reading.is_finished(),
            "read must wait behind the physical commit"
        );
        drop(release);
        assert_eq!(writing.await.unwrap().status(), StatusCode::CREATED);
        assert_eq!(reading.await.unwrap().status(), StatusCode::OK);
        assert_eq!(executor.run(|engine| engine.count()).await.unwrap(), 1);
        executor.shutdown().await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancelled_management_holds_admission_until_commit_and_shutdown_is_resumable() {
        let (executor, store) = fixture();
        let release = store.block_next();
        let writing = {
            let executor = executor.clone();
            tokio::spawn(async move { executor.run(register).await })
        };
        store.gate.entered().await;
        let mut queued = Vec::new();
        for _ in 1..MANAGEMENT_CAPACITY {
            let executor = executor.clone();
            queued.push(tokio::spawn(async move {
                executor.run(|engine| engine.count()).await
            }));
        }
        saturated(&executor).await;
        writing.abort();
        assert!(writing.await.unwrap_err().is_cancelled());
        assert_eq!(
            executor.run(|_| ()).await,
            Err(WebhookExecutionError::Overloaded)
        );
        let shutdown = {
            let executor = executor.clone();
            tokio::spawn(async move { executor.shutdown().await })
        };
        tokio::task::yield_now().await;
        assert!(!shutdown.is_finished());
        shutdown.abort();
        assert!(shutdown.await.unwrap_err().is_cancelled());
        drop(release);
        for task in queued {
            assert_eq!(task.await.unwrap().unwrap(), 1);
        }
        tokio::time::timeout(Duration::from_secs(2), executor.shutdown())
            .await
            .unwrap();
        let recovered = WebhookEngine::durable(Default::default(), store).unwrap();
        assert_eq!(
            recovered.count(),
            1,
            "accepted cancelled mutation must finish"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancelled_reservation_reply_commits_cleanup_before_drain() {
        let (executor, store) = fixture();
        let id = pending_delivery(&executor).await;
        let release = store.block_next();
        let taking = {
            let executor = executor.clone();
            tokio::spawn(async move { executor.take_due(0).await })
        };
        store.gate.entered().await;
        taking.abort();
        assert!(taking.await.err().unwrap().is_cancelled());
        drop(release);
        executor.drain().await.unwrap();
        let rows = executor
            .run(move |engine| {
                assert_eq!(engine.inflight_count(), 0);
                engine.deliveries_for(&id, 0, 1)
            })
            .await
            .unwrap();
        assert_eq!(rows[0].attempts, 1);
        assert!(rows[0].next_retry_at_unix_ms.is_some());
        executor.shutdown().await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancellation_outcome_has_capacity_when_management_is_full_and_closed() {
        let (executor, store) = fixture();
        let id = executor
            .run(|engine| {
                let first = register(engine);
                for _ in 1..(MAX_INFLIGHT_GLOBAL / super::super::engine::MAX_INFLIGHT_PER_WEBHOOK) {
                    register(engine);
                }
                for seq in 1..=super::super::engine::MAX_INFLIGHT_PER_WEBHOOK as u64 {
                    engine.enqueue_matches(&event(seq), 0);
                }
                first
            })
            .await
            .unwrap();
        let attempts = executor.take_due(0).await.unwrap();
        assert_eq!(attempts.len(), MAX_INFLIGHT_GLOBAL);
        let release = store.block_next();
        let writing = {
            let executor = executor.clone();
            tokio::spawn(async move { executor.run(register).await })
        };
        store.gate.entered().await;
        let mut queued = Vec::new();
        for _ in 1..MANAGEMENT_CAPACITY {
            let executor = executor.clone();
            queued.push(tokio::spawn(async move { executor.run(|_| ()).await }));
        }
        saturated(&executor).await;
        executor.close();
        drop(attempts); // Must enqueue without a management permit or any IO.
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert_eq!(executor.shared.outcomes.available_permits(), 0);
        assert_eq!(
            executor.run_worker(|_| ()).await,
            Err(WebhookExecutionError::Closed)
        );
        drop(release);
        writing.await.unwrap().unwrap();
        for task in queued {
            task.await.unwrap().unwrap();
        }
        executor.drain().await.unwrap();
        executor.shutdown().await;
        let recovered = WebhookEngine::durable(Default::default(), store).unwrap();
        assert_eq!(recovered.delivery_count(), MAX_INFLIGHT_GLOBAL);
        let row = recovered.deliveries_for(&id, 0, 1).remove(0);
        assert_eq!(row.attempts, 1);
        assert!(row.next_retry_at_unix_ms.is_some());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancelled_outcome_awaiter_retains_commit_and_shutdown_ownership() {
        let (executor, store) = fixture();
        let id = pending_delivery(&executor).await;
        let attempt = executor.take_due(0).await.unwrap().remove(0);
        let release = store.block_next();
        let completing =
            tokio::spawn(async move { attempt.complete(DeliveryOutcome::Success(204), 1).await });
        store.gate.entered().await;
        completing.abort();
        assert!(completing.await.unwrap_err().is_cancelled());
        assert_eq!(
            executor.shared.outcomes.available_permits(),
            MAX_INFLIGHT_GLOBAL - 1
        );
        let shutting = {
            let executor = executor.clone();
            tokio::spawn(async move { executor.shutdown().await })
        };
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert!(!shutting.is_finished());
        drop(release);
        tokio::time::timeout(Duration::from_secs(2), shutting)
            .await
            .unwrap()
            .unwrap();
        let recovered = WebhookEngine::durable(Default::default(), store).unwrap();
        let row = recovered.deliveries_for(&id, 0, 1).remove(0);
        assert_eq!(row.status, super::super::model::DeliveryStatus::Delivered);
        assert_eq!(row.attempts, 1);
        assert_eq!(row.response_code, Some(204));
        assert_eq!(row.next_retry_at_unix_ms, None);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn outcome_store_panic_fails_closed_and_shutdown_finishes() {
        let (executor, store) = fixture();
        pending_delivery(&executor).await;
        let attempt = executor.take_due(0).await.unwrap().remove(0);
        store.next_commit.store(2, Ordering::Release);
        assert_eq!(
            attempt.complete(DeliveryOutcome::Success(200), 1).await,
            Err(WebhookExecutionError::Panicked)
        );
        assert!(!executor.run(|engine| engine.is_available()).await.unwrap());
        assert!(executor.take_due(100).await.unwrap().is_empty());
        tokio::time::timeout(Duration::from_secs(2), executor.shutdown())
            .await
            .unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn lazy_final_drop_is_off_reactor_and_retained_after_shutdown_cancellation() {
        struct DroppingStore(Arc<Gate>);
        impl WebhookStore for DroppingStore {
            fn load(&self) -> Result<Option<Vec<u8>>, String> {
                Ok(None)
            }
            fn commit(&self, _: &[u8]) -> Result<(), String> {
                Ok(())
            }
        }
        impl Drop for DroppingStore {
            fn drop(&mut self) {
                self.0.wait().unwrap();
            }
        }
        let gate = Arc::new(Gate::default());
        let release = gate.arm();
        let engine = Arc::new(
            WebhookEngine::durable(Default::default(), Arc::new(DroppingStore(gate.clone())))
                .unwrap(),
        );
        let weak = Arc::downgrade(&engine);
        let executor = Arc::new(WebhookExecutor::new(engine));
        assert!(executor.shared.admission.lock().unwrap().sender.is_none());
        let shutting = {
            let executor = executor.clone();
            tokio::spawn(async move { executor.shutdown().await })
        };
        gate.entered().await;
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert!(!shutting.is_finished());
        shutting.abort();
        assert!(shutting.await.unwrap_err().is_cancelled());
        assert!(executor.shared.admission.lock().unwrap().join.is_some());
        drop(release);
        tokio::time::timeout(Duration::from_secs(2), executor.shutdown())
            .await
            .unwrap();
        assert!(weak.upgrade().is_none());
        assert_eq!(
            executor.run(|_| ()).await,
            Err(WebhookExecutionError::Closed)
        );
    }
}
