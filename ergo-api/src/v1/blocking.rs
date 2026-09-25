//! Bounded store reads whose work, including response serialization, runs off the runtime.

use std::{sync::Arc, time::Duration};

use axum::{http::header::RETRY_AFTER, response::Response};
use tokio::{sync::Semaphore, time::timeout};

use super::error::{v1_error, Reason};

/// Separate capacity for bounded point lookups and bulk scans.
#[derive(Debug, Clone, Copy)]
pub enum ReadLane {
    Point,
    Scan,
}

/// Per-node concurrency and wait bounds for product API store reads.
#[derive(Debug, Clone)]
pub struct BlockingReadsConfig {
    pub point_permits: usize,
    pub scan_permits: usize,
    pub queue_wait: Duration,
    pub run_timeout: Duration,
}

impl Default for BlockingReadsConfig {
    fn default() -> Self {
        Self {
            point_permits: 16,
            scan_permits: 4,
            queue_wait: Duration::from_secs(2),
            run_timeout: Duration::from_secs(30),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BlockingReadsConfigError {
    #[error("{lane} permits must be in 1..=256, got {value}")]
    Permits { lane: &'static str, value: usize },
    #[error("{field} must be greater than zero")]
    Duration { field: &'static str },
}

impl BlockingReadsConfig {
    pub fn validate(&self) -> Result<(), BlockingReadsConfigError> {
        for (lane, value) in [("point", self.point_permits), ("scan", self.scan_permits)] {
            if !(1..=256).contains(&value) {
                return Err(BlockingReadsConfigError::Permits { lane, value });
            }
        }
        for (field, value) in [
            ("queue_wait", self.queue_wait),
            ("run_timeout", self.run_timeout),
        ] {
            if value.is_zero() {
                return Err(BlockingReadsConfigError::Duration { field });
            }
        }
        Ok(())
    }
}

/// Clones share both lanes; operator and public readers use the same instance.
#[derive(Clone)]
pub struct BlockingReads {
    point: Arc<Semaphore>,
    scan: Arc<Semaphore>,
    queue_wait: Duration,
    run_timeout: Duration,
}

impl BlockingReads {
    pub fn new(cfg: BlockingReadsConfig) -> Result<Self, BlockingReadsConfigError> {
        cfg.validate()?;
        Ok(Self {
            point: Arc::new(Semaphore::new(cfg.point_permits)),
            scan: Arc::new(Semaphore::new(cfg.scan_permits)),
            queue_wait: cfg.queue_wait,
            run_timeout: cfg.run_timeout,
        })
    }

    /// Acquire capacity after request extraction and validation, then build the response off-runtime.
    pub async fn run<F>(&self, lane: ReadLane, work: F) -> Response
    where
        F: FnOnce() -> Response + Send + 'static,
    {
        let semaphore = match lane {
            ReadLane::Point => &self.point,
            ReadLane::Scan => &self.scan,
        };
        let permit = match timeout(self.queue_wait, semaphore.clone().acquire_owned()).await {
            Ok(Ok(permit)) => permit,
            Ok(Err(_)) => return shutting_down(),
            Err(_) => {
                let mut response = v1_error(
                    Reason::Overloaded,
                    "read capacity is busy",
                    "retry the request shortly",
                );
                response
                    .headers_mut()
                    .insert(RETRY_AFTER, axum::http::HeaderValue::from_static("1"));
                return response;
            }
        };
        let task = tokio::task::spawn_blocking(move || {
            // The task owns the permit even after a timeout or request cancellation.
            // Detached work keeps capacity occupied until it returns, bounding the pool.
            let _permit = permit;
            work()
        });
        match timeout(self.run_timeout, task).await {
            Ok(Ok(response)) => response,
            Ok(Err(error)) if error.is_panic() => {
                tracing::error!(%error, "blocking API read panicked");
                v1_error(
                    Reason::InternalError,
                    "the read could not be completed",
                    "an internal error occurred",
                )
            }
            Ok(Err(_)) => shutting_down(),
            Err(_) => v1_error(
                Reason::Timeout,
                "the read timed out",
                "retry the request shortly",
            ),
        }
    }
}

fn shutting_down() -> Response {
    v1_error(
        Reason::ShuttingDown,
        "read service is shutting down",
        "retry when the node is available",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::to_bytes, http::StatusCode, response::IntoResponse};

    // ----- helpers -----

    fn reads() -> BlockingReads {
        BlockingReads::new(BlockingReadsConfig::default()).unwrap()
    }

    // ----- happy path -----

    #[tokio::test]
    async fn blocking_reads_permit_released_after_work_completes() {
        let reads = reads();
        let point = reads.point.clone();
        let response = reads
            .run(ReadLane::Point, move || {
                assert_eq!(point.available_permits(), 15);
                StatusCode::OK.into_response()
            })
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(reads.point.available_permits(), 16);
    }

    // ----- error paths -----

    #[tokio::test]
    async fn blocking_reads_panicking_work_is_internal_error_500() {
        let response = reads()
            .run(ReadLane::Point, || panic!("private store details"))
            .await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn blocking_reads_panic_payload_not_in_body() {
        let response = reads()
            .run(ReadLane::Point, || panic!("private store details"))
            .await;
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(!body.contains("private store details"));
        assert!(body.contains("internal_error"));
    }

    #[test]
    fn blocking_reads_config_zero_permits_rejected() {
        for cfg in [
            BlockingReadsConfig {
                point_permits: 0,
                ..Default::default()
            },
            BlockingReadsConfig {
                scan_permits: 0,
                ..Default::default()
            },
        ] {
            assert!(matches!(
                cfg.validate(),
                Err(BlockingReadsConfigError::Permits { .. })
            ));
        }
    }
}
