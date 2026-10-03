//! Tracked per-node blocking work; native and Scala script routes share the
//! compute lane, while point/scan readers reuse the same ownership mechanism.

use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use axum::{http::header::RETRY_AFTER, response::Response};
use tokio::{
    sync::{Notify, Semaphore},
    time::timeout,
};

use super::error::{v1_error, Reason};

/// Bounded CPU work, shared across native and Scala-compatible script routes.
/// The blocking task owns admission until it returns, even if its caller
/// times out or disconnects. Cost bounds still apply to each interpreter run.
#[derive(Clone)]
pub struct ComputePool {
    permits: Arc<Semaphore>,
    queue: Arc<Semaphore>,
    queue_wait: Duration,
    run_timeout: Duration,
    state: Arc<Mutex<Jobs>>,
    finished: Arc<Notify>,
    service: &'static str,
}

#[derive(Default)]
struct Jobs {
    closed: bool,
    tasks: Vec<(Arc<AtomicBool>, tokio::task::JoinHandle<()>)>,
}

struct JobFinished {
    flag: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

impl Drop for JobFinished {
    fn drop(&mut self) {
        self.flag.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }
}

impl ComputePool {
    pub fn new(
        permits: usize,
        queue_wait: Duration,
        run_timeout: Duration,
    ) -> Result<Self, &'static str> {
        if !(1..=32).contains(&permits) || queue_wait.is_zero() || run_timeout.is_zero() {
            return Err("compute permits must be in 1..=32 and timeouts must be positive");
        }
        Ok(Self::from_bounds(
            permits,
            queue_wait,
            run_timeout,
            "compute",
        ))
    }

    pub(crate) fn for_reads(permits: usize, queue_wait: Duration, run_timeout: Duration) -> Self {
        Self::from_bounds(permits, queue_wait, run_timeout, "read")
    }

    fn from_bounds(
        permits: usize,
        queue_wait: Duration,
        run_timeout: Duration,
        service: &'static str,
    ) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(permits)),
            queue: Arc::new(Semaphore::new(permits * 4)),
            queue_wait,
            run_timeout,
            state: Arc::new(Mutex::new(Jobs::default())),
            finished: Arc::new(Notify::new()),
            service,
        }
    }

    #[cfg(test)]
    pub(crate) fn available_permits(&self) -> usize {
        self.permits.available_permits()
    }

    pub async fn run<T, F>(&self, work: F) -> Result<T, Box<Response>>
    where
        T: Send + 'static,
        F: FnOnce() -> T + Send + 'static,
    {
        // Bound the number of requests waiting as well as the running jobs.
        // The queue permit is released on admission or cancellation.
        let queued = match self.queue.clone().try_acquire_owned() {
            Ok(queued) => queued,
            Err(tokio::sync::TryAcquireError::Closed) => return Err(shutting_down(self.service)),
            Err(tokio::sync::TryAcquireError::NoPermits) => return Err(overloaded(self.service)),
        };
        let permit = match timeout(self.queue_wait, self.permits.clone().acquire_owned()).await {
            Ok(Ok(permit)) => permit,
            Ok(Err(_)) => return Err(shutting_down(self.service)),
            Err(_) => return Err(overloaded(self.service)),
        };
        drop(queued);
        let (send, receive) = tokio::sync::oneshot::channel();
        {
            let mut jobs = self.state.lock().unwrap_or_else(|error| error.into_inner());
            if jobs.closed {
                return Err(shutting_down(self.service));
            }
            jobs.tasks.retain(|(_, task)| !task.is_finished());
            let flag = Arc::new(AtomicBool::new(false));
            let finished = JobFinished {
                flag: flag.clone(),
                notify: self.finished.clone(),
            };
            let service = self.service;
            let task = tokio::task::spawn_blocking(move || {
                // Drop admission before marking the job finished. Shutdown
                // observes this flag only after work and its captures are gone.
                let _finished = finished;
                let _permit = permit;
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(work));
                if result.is_err() {
                    tracing::error!(service, "blocking API task panicked");
                }
                let _ = send.send(result);
            });
            jobs.tasks.push((flag, task));
        }
        match timeout(self.run_timeout, receive).await {
            Ok(Ok(Ok(value))) => Ok(value),
            Ok(Ok(Err(_))) | Ok(Err(_)) => Err(Box::new(v1_error(
                Reason::InternalError,
                if self.service == "read" {
                    "the read could not be completed"
                } else {
                    "the computation could not be completed"
                },
                "an internal error occurred",
            ))),
            Err(_) => Err(Box::new(v1_error(
                Reason::Timeout,
                if self.service == "read" {
                    "the read timed out"
                } else {
                    "the computation timed out"
                },
                "retry the request shortly",
            ))),
        }
    }

    /// Stop new admission, including requests already queued for capacity.
    pub fn close(&self) {
        self.state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .closed = true;
        self.queue.close();
        self.permits.close();
    }

    /// Close admission and join every accepted job, including jobs whose HTTP
    /// caller disconnected or timed out. Cancellation leaves handles owned here.
    pub async fn shutdown(&self) {
        self.close();
        let tasks = loop {
            let notified = self.finished.notified();
            {
                let mut jobs = self.state.lock().unwrap_or_else(|error| error.into_inner());
                if jobs
                    .tasks
                    .iter()
                    .all(|(flag, _)| flag.load(Ordering::Acquire))
                {
                    break std::mem::take(&mut jobs.tasks);
                }
            }
            notified.await;
        };
        for (_, task) in tasks {
            let _ = task.await;
        }
    }

    pub async fn response<F>(&self, work: F) -> Response
    where
        F: FnOnce() -> Response + Send + 'static,
    {
        self.run(work).await.unwrap_or_else(|response| *response)
    }
}

fn shutting_down(service: &str) -> Box<Response> {
    Box::new(v1_error(
        Reason::ShuttingDown,
        format!("{service} service is shutting down"),
        "retry when the node is available",
    ))
}

fn overloaded(service: &str) -> Box<Response> {
    let mut response = v1_error(
        Reason::Overloaded,
        format!("{service} capacity is busy"),
        "retry the request shortly",
    );
    response
        .headers_mut()
        .insert(RETRY_AFTER, axum::http::HeaderValue::from_static("1"));
    Box::new(response)
}

impl Default for ComputePool {
    fn default() -> Self {
        Self::new(2, Duration::from_secs(2), Duration::from_secs(30))
            .expect("default compute bounds are valid")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[tokio::test(flavor = "current_thread")]
    async fn cancelled_request_keeps_capacity_until_blocking_work_finishes() {
        let pool = ComputePool::new(1, Duration::from_millis(25), Duration::from_secs(1)).unwrap();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (finish_tx, finish_rx) = mpsc::channel();
        let first = pool.clone();
        let request = tokio::spawn(async move {
            first
                .run(move || {
                    let _ = started_tx.send(());
                    finish_rx.recv().unwrap();
                })
                .await
        });
        started_rx.await.unwrap();
        // The current-thread runtime remains responsive while the work blocks.
        tokio::time::timeout(Duration::from_millis(100), tokio::task::yield_now())
            .await
            .unwrap();
        request.abort();
        let _ = request.await;
        assert_eq!(
            pool.run(|| ()).await.unwrap_err().status(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        );
        finish_tx.send(()).unwrap();
        assert!(tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if pool.permits.available_permits() == 1 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .is_ok());
        assert!(pool.run(|| ()).await.is_ok());
    }

    #[tokio::test]
    async fn full_waiting_queue_refuses_immediately_and_cancellation_frees_it() {
        let pool = ComputePool::new(1, Duration::from_secs(1), Duration::from_secs(2)).unwrap();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (finish_tx, finish_rx) = mpsc::channel();
        let first = pool.clone();
        let running = tokio::spawn(async move {
            first
                .run(move || {
                    let _ = started_tx.send(());
                    finish_rx.recv().unwrap();
                })
                .await
        });
        started_rx.await.unwrap();
        let mut waiting = Vec::new();
        for _ in 0..4 {
            let queued = pool.clone();
            waiting.push(tokio::spawn(async move { queued.run(|| ()).await }));
        }
        tokio::time::timeout(Duration::from_millis(100), async {
            while pool.queue.available_permits() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let refused = tokio::time::timeout(Duration::from_millis(100), pool.run(|| ()))
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(
            refused.status(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        );
        for request in waiting {
            request.abort();
            let _ = request.await;
        }
        assert_eq!(pool.queue.available_permits(), 4);
        finish_tx.send(()).unwrap();
        assert!(running.await.unwrap().is_ok());
        assert!(pool.run(|| ()).await.is_ok());
    }

    #[tokio::test]
    async fn shutdown_waits_for_timed_out_job_and_releases_its_owned_state() {
        let pool =
            ComputePool::new(1, Duration::from_millis(10), Duration::from_millis(20)).unwrap();
        let owner = Arc::new(());
        let weak = Arc::downgrade(&owner);
        let (finish_tx, finish_rx) = mpsc::channel();
        assert!(pool
            .run(move || {
                let _owner = owner;
                finish_rx.recv().unwrap();
            })
            .await
            .is_err());
        let drain = pool.clone();
        let shutdown = tokio::spawn(async move { drain.shutdown().await });
        tokio::task::yield_now().await;
        assert!(!shutdown.is_finished());
        assert!(pool.run(|| ()).await.is_err());
        assert!(weak.upgrade().is_some());
        finish_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(1), shutdown)
            .await
            .unwrap()
            .unwrap();
        assert!(weak.upgrade().is_none());
        assert!(pool.state.lock().unwrap().tasks.is_empty());
    }

    #[tokio::test]
    async fn response_timeout_keeps_capacity_until_work_finishes() {
        let pool =
            ComputePool::new(1, Duration::from_millis(10), Duration::from_millis(20)).unwrap();
        let (finish_tx, finish_rx) = mpsc::channel();
        assert!(pool
            .run(move || {
                finish_rx.recv().unwrap();
            })
            .await
            .is_err());
        assert_eq!(pool.permits.available_permits(), 0);
        finish_tx.send(()).unwrap();
        while pool.permits.available_permits() == 0 {
            tokio::task::yield_now().await;
        }
    }
}
