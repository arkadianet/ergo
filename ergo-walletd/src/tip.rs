//! Cached node-tip projection for the local read API.
//!
//! `/status` needs the node's committed tip, but a fresh HTTP probe is a
//! blocking request with a multi-second timeout: doing one on every local read
//! would tie a read route to node latency. The sync loop already fetches the
//! tip on every cycle, so it records each observation here and `/status`
//! serves the cached value while it is fresh.
//!
//! The cache is an optimisation, never an authority: it is refreshed by the
//! syncer, and when no fresh observation exists the reader falls back to a
//! *capped* probe (`probe_timeout`) so a read can never block on an unbounded
//! chain request. A read that still cannot get a tip reports
//! `nodeTip: null` / `sync: unavailable` rather than inventing one.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ergo_wallet_service::{ChainClient, CommittedTip};

/// Hard ceiling on the fallback tip probe. The default HTTP client allows 30s
/// per request; a local read must not inherit that.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone)]
struct Observation {
    tip: CommittedTip,
    observed_at: Instant,
}

/// Last observed node tip, shared between the sync loop (writer) and the read
/// API (reader).
pub struct CachedNodeTip {
    chain: Arc<dyn ChainClient>,
    latest: Mutex<Option<Observation>>,
}

impl std::fmt::Debug for CachedNodeTip {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CachedNodeTip")
            .field("cached", &self.cached())
            .finish()
    }
}

impl CachedNodeTip {
    pub fn new(chain: Arc<dyn ChainClient>) -> Self {
        Self {
            chain,
            latest: Mutex::new(None),
        }
    }

    /// Record a tip observed by the sync loop. Monotonic by observation time:
    /// a tip that arrives late from a slower path still refreshes the cache,
    /// because the height it carries is validated by the sync loop itself.
    pub fn record(&self, tip: CommittedTip) {
        let mut latest = self
            .latest
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *latest = Some(Observation {
            tip,
            observed_at: Instant::now(),
        });
    }

    /// The cached tip, regardless of age.
    pub fn cached(&self) -> Option<CommittedTip> {
        self.latest
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .map(|observation| observation.tip.clone())
    }

    /// Age of the cached observation, if any.
    pub fn age(&self) -> Option<Duration> {
        self.latest
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .map(|observation| observation.observed_at.elapsed())
    }

    /// Tip for a read: the cached value when it is younger than `max_age`,
    /// otherwise a probe bounded by `probe_timeout`. Failures degrade to `None`
    /// (the caller reports the tip as unavailable) and never propagate an
    /// error to the read route.
    pub fn tip_within(&self, max_age: Duration, probe_timeout: Duration) -> Option<CommittedTip> {
        if let Some(tip) = self.cached() {
            if self.age().is_some_and(|age| age < max_age) {
                return Some(tip);
            }
        }
        match self.chain.committed_tip_within(probe_timeout) {
            Ok(tip) => {
                self.record(tip.clone());
                Some(tip)
            }
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    timeout_ms = probe_timeout.as_millis() as u64,
                    "node tip probe failed; /status reports the tip as unavailable"
                );
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_wallet_service::{
        BlocksSinceRequest, BlocksSinceResponse, ChainClientError, ChainSnapshot, SubmitRequest,
        SubmitResponse, UtxoLookup,
    };

    struct CountingChain {
        tip: CommittedTip,
        calls: Mutex<usize>,
        error: bool,
    }

    impl ChainClient for CountingChain {
        fn committed_tip(&self) -> Result<CommittedTip, ChainClientError> {
            *self.calls.lock().unwrap() += 1;
            if self.error {
                return Err(ChainClientError::Unavailable("node is down".to_string()));
            }
            Ok(self.tip.clone())
        }

        fn committed_tip_within(
            &self,
            _timeout: Duration,
        ) -> Result<CommittedTip, ChainClientError> {
            self.committed_tip()
        }

        fn snapshot(&self) -> Result<ChainSnapshot, ChainClientError> {
            Err(ChainClientError::Unsupported)
        }

        fn blocks_since(
            &self,
            _request: BlocksSinceRequest,
        ) -> Result<BlocksSinceResponse, ChainClientError> {
            Err(ChainClientError::Unsupported)
        }

        fn lookup_utxo(
            &self,
            _box_id: [u8; 32],
            _expected_tip: CommittedTip,
        ) -> Result<UtxoLookup, ChainClientError> {
            Err(ChainClientError::Unsupported)
        }

        fn submit(&self, _request: SubmitRequest) -> Result<SubmitResponse, ChainClientError> {
            Err(ChainClientError::Unsupported)
        }
    }

    fn counting_chain(error: bool) -> Arc<CountingChain> {
        Arc::new(CountingChain {
            tip: CommittedTip::new(7, [7; 32]),
            calls: Mutex::new(0),
            error,
        })
    }

    #[test]
    fn fresh_cache_is_served_without_touching_the_node() {
        let chain = counting_chain(false);
        let cache = CachedNodeTip::new(chain.clone());
        assert!(cache.cached().is_none());
        // Cold cache probes once.
        assert_eq!(
            cache
                .tip_within(Duration::from_secs(30), PROBE_TIMEOUT)
                .unwrap()
                .height,
            7
        );
        assert_eq!(*chain.calls.lock().unwrap(), 1);
        // A recorded observation is served without another probe.
        cache.record(CommittedTip::new(9, [9; 32]));
        for _ in 0..5 {
            assert_eq!(
                cache
                    .tip_within(Duration::from_secs(30), PROBE_TIMEOUT)
                    .unwrap()
                    .height,
                9
            );
        }
        assert_eq!(
            *chain.calls.lock().unwrap(),
            1,
            "cached tip must not re-probe"
        );
    }

    #[test]
    fn stale_cache_reprobes_and_failures_degrade_to_none() {
        let chain = counting_chain(false);
        let cache = CachedNodeTip::new(chain.clone());
        cache.record(CommittedTip::new(1, [1; 32]));
        // A zero max age makes every observation stale.
        assert_eq!(
            cache
                .tip_within(Duration::ZERO, PROBE_TIMEOUT)
                .unwrap()
                .height,
            7
        );
        assert_eq!(*chain.calls.lock().unwrap(), 1);

        let failing = counting_chain(true);
        let cache = CachedNodeTip::new(failing.clone());
        assert!(cache
            .tip_within(Duration::from_secs(30), PROBE_TIMEOUT)
            .is_none());
        assert!(cache.cached().is_none());
        assert_eq!(*failing.calls.lock().unwrap(), 1);
    }
}
