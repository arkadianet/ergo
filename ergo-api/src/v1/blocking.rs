//! Bounded store reads whose work, including response serialization, runs off the runtime.

use std::time::Duration;

use super::compute::ComputePool;
use axum::response::Response;

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
    point: ComputePool,
    scan: ComputePool,
}

impl BlockingReads {
    pub fn new(cfg: BlockingReadsConfig) -> Result<Self, BlockingReadsConfigError> {
        cfg.validate()?;
        Ok(Self {
            point: ComputePool::for_reads(cfg.point_permits, cfg.queue_wait, cfg.run_timeout),
            scan: ComputePool::for_reads(cfg.scan_permits, cfg.queue_wait, cfg.run_timeout),
        })
    }

    pub fn close(&self) {
        self.point.close();
        self.scan.close();
    }

    pub async fn shutdown(&self) {
        self.close();
        tokio::join!(self.point.shutdown(), self.scan.shutdown());
    }

    /// Acquire capacity after request extraction and validation, then build the response off-runtime.
    pub async fn run<F>(&self, lane: ReadLane, work: F) -> Response
    where
        F: FnOnce() -> Response + Send + 'static,
    {
        match lane {
            ReadLane::Point => self.point.response(work).await,
            ReadLane::Scan => self.scan.response(work).await,
        }
    }
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
