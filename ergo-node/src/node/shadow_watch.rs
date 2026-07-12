//! Shadow validation (operator workload §D): live cross-check of this node's
//! chain against a configured Scala reference node, surfacing divergence as
//! an event + metric instead of a day of log archaeology.
//!
//! Two signals, both from two cheap reference reads per tick (`/info` +
//! `/blocks/at/{h}`), never touching the apply path:
//!
//! * **S1 `header_mismatch`** — the canonical header id at a depth-floored
//!   height differs: the accept-invalid class (we kept a branch the
//!   reference refused).
//! * **S2 `tip_stall`** — the reference tip advances while ours does not:
//!   the reject-valid class (we refused a block the network accepted).
//!
//! A separate state-root compare is deliberately absent: the state root is
//! committed INSIDE the header, so header-id equality at a height already
//! pins it, and our own apply path enforces our-state-vs-our-header.
//!
//! False-positive discipline (design §6): compares run `lag_tolerance`
//! blocks below `min(tips)`; an S1 mismatch must reproduce on the NEXT tick
//! before it fires (transient cross-node reorgs clear themselves); an
//! unreachable reference sets a gauge and skips — never an event; confirmed
//! divergence latches per fork point so one incident is one event.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Mutex;

use tracing::{debug, warn};

/// Resolved `[shadow]` config (defaults in `config::load`).
#[derive(Clone, Debug)]
pub struct ShadowConfig {
    pub enabled: bool,
    /// Scala reference node base URL, e.g. `http://127.0.0.1:9053`.
    pub reference_url: String,
    pub interval_secs: u64,
    /// Compare `lag_tolerance` blocks below `min(our_tip, ref_tip)` so tip
    /// races and shallow reorgs never read as divergence.
    pub lag_tolerance: u32,
    /// S2 fires when the reference is ahead by MORE than this many blocks.
    pub stall_gap_threshold: u32,
    pub request_timeout_secs: u64,
}

impl Default for ShadowConfig {
    fn default() -> Self {
        ShadowConfig {
            enabled: false,
            reference_url: "http://127.0.0.1:9053".to_string(),
            interval_secs: 30,
            lag_tolerance: 3,
            stall_gap_threshold: 10,
            request_timeout_secs: 5,
        }
    }
}

/// The reference node, behind a trait so the comparator is stub-testable
/// (same idiom as the webhook `WebhookSink`).
#[async_trait::async_trait]
pub trait ShadowReference: Send + Sync {
    /// The reference's best FULL-block height (`/info` `fullHeight`).
    async fn tip_height(&self) -> Result<u32, String>;
    /// Canonical-first header ids at a height (`/blocks/at/{h}`).
    async fn header_ids_at(&self, height: u32) -> Result<Vec<String>, String>;
}

/// Production reference client over the Scala REST API. rustls-only reqwest,
/// same dependency policy as the webhook sink.
pub struct HttpShadowReference {
    base: String,
    client: reqwest::Client,
}

impl HttpShadowReference {
    pub fn new(base_url: &str, timeout_secs: u64) -> Result<Self, String> {
        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(timeout_secs))
            .timeout(std::time::Duration::from_secs(timeout_secs))
            .build()
            .map_err(|e| e.to_string())?;
        Ok(HttpShadowReference {
            base: base_url.trim_end_matches('/').to_string(),
            client,
        })
    }

    async fn get_json(&self, path: &str) -> Result<serde_json::Value, String> {
        let url = format!("{}{}", self.base, path);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("GET {url}: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("GET {url}: HTTP {}", resp.status()));
        }
        resp.json().await.map_err(|e| format!("GET {url}: {e}"))
    }
}

#[async_trait::async_trait]
impl ShadowReference for HttpShadowReference {
    async fn tip_height(&self) -> Result<u32, String> {
        let v = self.get_json("/info").await?;
        v.get("fullHeight")
            .and_then(serde_json::Value::as_u64)
            .map(|h| h as u32)
            .ok_or_else(|| "reference /info has no numeric fullHeight".to_string())
    }

    async fn header_ids_at(&self, height: u32) -> Result<Vec<String>, String> {
        let v = self.get_json(&format!("/blocks/at/{height}")).await?;
        v.as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .ok_or_else(|| "reference /blocks/at is not an array".to_string())
    }
}

/// One confirmed divergence, surfaced through the snapshot → event differ →
/// `/api/v1/events` + WS path (the `SyncWedged` shape).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShadowDivergence {
    /// `header_mismatch` (S1) or `tip_stall` (S2).
    pub kind: &'static str,
    pub height: u32,
    /// Our canonical header id at `height` (empty for `tip_stall`).
    pub ours: String,
    /// The reference's canonical header id at `height` (empty for `tip_stall`).
    pub theirs: String,
}

/// Shared shadow outcome state: written by the watch task, read by the
/// snapshot emitter (status/metrics) and the event differ.
#[derive(Default)]
pub struct ShadowState {
    /// Highest height a compare completed at (gauge; 0 = none yet).
    pub last_compared_height: AtomicU32,
    /// Reference unreachable on the most recent tick (0/1 gauge).
    pub reference_unreachable: AtomicBool,
    /// Confirmed divergences since start (counter).
    pub divergence_total: AtomicU64,
    /// The active confirmed divergence, if any (cleared when ids re-agree /
    /// the stall gap closes). The differ latches events off transitions.
    pub active: Mutex<Option<ShadowDivergence>>,
}

impl ShadowState {
    pub fn snapshot_active(&self) -> Option<ShadowDivergence> {
        self.active.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

/// Our side of the compare — the two chain reads the comparator needs,
/// passed as closures so the tick logic stays store-agnostic and testable.
pub struct LocalChainView<T, H> {
    /// Best full-block height.
    pub tip: T,
    /// Canonical-first header ids at a height.
    pub header_ids_at: H,
}

/// Per-task compare progress (not shared): the S1 suspect awaiting its
/// confirming re-check, and the S2 gap step already reported.
#[derive(Default, Debug)]
pub struct TickMemory {
    /// `(height, ours, theirs)` of an unconfirmed S1 mismatch.
    suspect: Option<(u32, String, String)>,
    /// The stall gap (in `stall_gap_threshold` steps) already latched, so a
    /// persistent stall re-fires only as it WORSENS by another full step.
    stall_steps_latched: u32,
}

/// One comparator tick. Pure with respect to its inputs; all IO is behind
/// `reference` and the `local` closures.
pub async fn tick<T, H>(
    config: &ShadowConfig,
    reference: &dyn ShadowReference,
    local: &LocalChainView<T, H>,
    state: &ShadowState,
    memory: &mut TickMemory,
) where
    T: Fn() -> u32,
    H: Fn(u32) -> Vec<String>,
{
    let ref_tip = match reference.tip_height().await {
        Ok(h) => h,
        Err(e) => {
            debug!(error = %e, "shadow: reference unreachable");
            state.reference_unreachable.store(true, Ordering::Relaxed);
            return;
        }
    };
    state.reference_unreachable.store(false, Ordering::Relaxed);
    let our_tip = (local.tip)();

    // ----- S2: tip stall (reject-valid class) -----
    let gap = ref_tip.saturating_sub(our_tip);
    if gap > config.stall_gap_threshold {
        let steps = gap / config.stall_gap_threshold.max(1);
        if steps > memory.stall_steps_latched {
            memory.stall_steps_latched = steps;
            let d = ShadowDivergence {
                kind: "tip_stall",
                height: our_tip,
                ours: String::new(),
                theirs: String::new(),
            };
            warn!(
                our_tip,
                ref_tip, gap, "shadow: reference tip advancing past ours (tip_stall)"
            );
            state.divergence_total.fetch_add(1, Ordering::Relaxed);
            *state.active.lock().unwrap_or_else(|e| e.into_inner()) = Some(d);
        }
    } else {
        memory.stall_steps_latched = 0;
        // A cleared stall releases the active latch (unless S1 owns it).
        let mut active = state.active.lock().unwrap_or_else(|e| e.into_inner());
        if matches!(&*active, Some(d) if d.kind == "tip_stall") {
            *active = None;
        }
    }

    // ----- S1: header id at depth (accept-invalid class) -----
    let compare_h = our_tip
        .min(ref_tip)
        .saturating_sub(config.lag_tolerance);
    if compare_h == 0 {
        return;
    }
    let ours = (local.header_ids_at)(compare_h).into_iter().next();
    let theirs = match reference.header_ids_at(compare_h).await {
        Ok(ids) => ids.into_iter().next(),
        Err(e) => {
            debug!(error = %e, height = compare_h, "shadow: reference header read failed");
            state.reference_unreachable.store(true, Ordering::Relaxed);
            return;
        }
    };
    state
        .last_compared_height
        .store(compare_h, Ordering::Relaxed);

    let (ours, theirs) = match (ours, theirs) {
        (Some(o), Some(t)) => (o, t),
        // Either side lacking a canonical id at a depth-floored height is a
        // read anomaly, not a verdict — skip the tick.
        _ => return,
    };

    if ours == theirs {
        memory.suspect = None;
        let mut active = state.active.lock().unwrap_or_else(|e| e.into_inner());
        if matches!(&*active, Some(d) if d.kind == "header_mismatch") {
            *active = None;
        }
        return;
    }

    // Mismatch: arm on first sight, confirm on reproduction (design §6.2).
    // Reproduction = a mismatch was armed on a previous tick and one is
    // still visible at the same-or-later height — the ids themselves may
    // legitimately change as the compare window advances along the fork.
    match &memory.suspect {
        Some((h, _, _)) if *h <= compare_h => {
            let confirmed = ShadowDivergence {
                kind: "header_mismatch",
                height: compare_h,
                ours: ours.clone(),
                theirs: theirs.clone(),
            };
            let mut active = state.active.lock().unwrap_or_else(|e| e.into_inner());
            let already = matches!(&*active, Some(d) if d.kind == "header_mismatch");
            if !already {
                warn!(
                    height = compare_h,
                    ours, theirs, "shadow: CONFIRMED header divergence vs reference"
                );
                state.divergence_total.fetch_add(1, Ordering::Relaxed);
                *active = Some(confirmed);
            }
        }
        _ => {
            debug!(
                height = compare_h,
                ours, theirs, "shadow: header mismatch armed (awaiting re-check)"
            );
            memory.suspect = Some((compare_h, ours, theirs));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    struct FakeReference {
        tip: std::sync::atomic::AtomicU32,
        /// Header id served at EVERY height (or None → error).
        id: Mutex<Option<String>>,
    }

    impl FakeReference {
        fn new(tip: u32, id: &str) -> Self {
            FakeReference {
                tip: AtomicU32::new(tip),
                id: Mutex::new(Some(id.to_string())),
            }
        }
        fn unreachable() -> Self {
            FakeReference {
                tip: AtomicU32::new(0),
                id: Mutex::new(None),
            }
        }
    }

    #[async_trait::async_trait]
    impl ShadowReference for FakeReference {
        async fn tip_height(&self) -> Result<u32, String> {
            match &*self.id.lock().unwrap() {
                Some(_) => Ok(self.tip.load(Ordering::Relaxed)),
                None => Err("connection refused".to_string()),
            }
        }
        async fn header_ids_at(&self, _height: u32) -> Result<Vec<String>, String> {
            match &*self.id.lock().unwrap() {
                Some(id) => Ok(vec![id.clone()]),
                None => Err("connection refused".to_string()),
            }
        }
    }

    fn local(tip: u32, id: &'static str) -> LocalChainView<impl Fn() -> u32, impl Fn(u32) -> Vec<String>>
    {
        LocalChainView {
            tip: move || tip,
            header_ids_at: move |_h| vec![id.to_string()],
        }
    }

    fn cfg() -> ShadowConfig {
        ShadowConfig::default()
    }

    // ----- happy path -----

    #[tokio::test]
    async fn agreement_stays_quiet_and_advances_gauge() {
        let reference = FakeReference::new(1000, "aa");
        let state = ShadowState::default();
        let mut mem = TickMemory::default();
        for _ in 0..5 {
            tick(&cfg(), &reference, &local(1000, "aa"), &state, &mut mem).await;
        }
        assert_eq!(state.divergence_total.load(Ordering::Relaxed), 0);
        assert!(state.snapshot_active().is_none());
        assert_eq!(state.last_compared_height.load(Ordering::Relaxed), 997);
        assert!(!state.reference_unreachable.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn tip_jitter_within_lag_stays_quiet() {
        // Reference a couple blocks ahead — normal propagation lag.
        let reference = FakeReference::new(1002, "aa");
        let state = ShadowState::default();
        let mut mem = TickMemory::default();
        tick(&cfg(), &reference, &local(1000, "aa"), &state, &mut mem).await;
        assert_eq!(state.divergence_total.load(Ordering::Relaxed), 0);
        assert!(state.snapshot_active().is_none());
    }

    // ----- S1: header mismatch -----

    #[tokio::test]
    async fn header_mismatch_arms_then_confirms_once() {
        let reference = FakeReference::new(1000, "bb");
        let state = ShadowState::default();
        let mut mem = TickMemory::default();
        // Tick 1: armed, NOT fired (transient-reorg discipline).
        tick(&cfg(), &reference, &local(1000, "aa"), &state, &mut mem).await;
        assert_eq!(state.divergence_total.load(Ordering::Relaxed), 0);
        assert!(state.snapshot_active().is_none());
        // Tick 2: reproduced → confirmed, fired once.
        tick(&cfg(), &reference, &local(1000, "aa"), &state, &mut mem).await;
        assert_eq!(state.divergence_total.load(Ordering::Relaxed), 1);
        let d = state.snapshot_active().expect("latched");
        assert_eq!(d.kind, "header_mismatch");
        assert_eq!(d.height, 997);
        assert_eq!((d.ours.as_str(), d.theirs.as_str()), ("aa", "bb"));
        // Tick 3+: latched — no re-fire.
        tick(&cfg(), &reference, &local(1000, "aa"), &state, &mut mem).await;
        assert_eq!(state.divergence_total.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn transient_mismatch_clears_without_firing() {
        let reference = FakeReference::new(1000, "bb");
        let state = ShadowState::default();
        let mut mem = TickMemory::default();
        tick(&cfg(), &reference, &local(1000, "aa"), &state, &mut mem).await;
        // The disagreement resolves before the re-check (cross-node reorg).
        *reference.id.lock().unwrap() = Some("aa".to_string());
        tick(&cfg(), &reference, &local(1000, "aa"), &state, &mut mem).await;
        assert_eq!(state.divergence_total.load(Ordering::Relaxed), 0);
        assert!(state.snapshot_active().is_none());
        assert!(mem.suspect.is_none(), "suspect cleared on agreement");
    }

    #[tokio::test]
    async fn latch_clears_when_ids_reagree() {
        let reference = FakeReference::new(1000, "bb");
        let state = ShadowState::default();
        let mut mem = TickMemory::default();
        tick(&cfg(), &reference, &local(1000, "aa"), &state, &mut mem).await;
        tick(&cfg(), &reference, &local(1000, "aa"), &state, &mut mem).await;
        assert!(state.snapshot_active().is_some());
        *reference.id.lock().unwrap() = Some("aa".to_string());
        tick(&cfg(), &reference, &local(1000, "aa"), &state, &mut mem).await;
        assert!(state.snapshot_active().is_none(), "latch released");
        // Counter is monotonic history, not current state.
        assert_eq!(state.divergence_total.load(Ordering::Relaxed), 1);
    }

    // ----- S2: tip stall -----

    #[tokio::test]
    async fn stall_fires_per_threshold_step_and_clears() {
        let reference = FakeReference::new(1015, "aa");
        let state = ShadowState::default();
        let mut mem = TickMemory::default();
        // Gap 15 > threshold 10 → fires immediately (no re-check: the gap IS
        // already a persistent observation).
        tick(&cfg(), &reference, &local(1000, "aa"), &state, &mut mem).await;
        assert_eq!(state.divergence_total.load(Ordering::Relaxed), 1);
        assert_eq!(state.snapshot_active().unwrap().kind, "tip_stall");
        // Same gap: latched, no re-fire.
        tick(&cfg(), &reference, &local(1000, "aa"), &state, &mut mem).await;
        assert_eq!(state.divergence_total.load(Ordering::Relaxed), 1);
        // Gap doubles past the next step → re-fires once.
        reference.tip.store(1025, Ordering::Relaxed);
        tick(&cfg(), &reference, &local(1000, "aa"), &state, &mut mem).await;
        assert_eq!(state.divergence_total.load(Ordering::Relaxed), 2);
        // We catch back up → latch clears.
        tick(&cfg(), &reference, &local(1024, "aa"), &state, &mut mem).await;
        assert!(state.snapshot_active().is_none());
    }

    // ----- error paths -----

    #[tokio::test]
    async fn unreachable_sets_gauge_never_event() {
        let reference = FakeReference::unreachable();
        let state = ShadowState::default();
        let mut mem = TickMemory::default();
        tick(&cfg(), &reference, &local(1000, "aa"), &state, &mut mem).await;
        assert!(state.reference_unreachable.load(Ordering::Relaxed));
        assert_eq!(state.divergence_total.load(Ordering::Relaxed), 0);
        assert!(state.snapshot_active().is_none());
    }

    #[tokio::test]
    async fn near_genesis_skips_compare() {
        let reference = FakeReference::new(2, "bb");
        let state = ShadowState::default();
        let mut mem = TickMemory::default();
        tick(&cfg(), &reference, &local(2, "aa"), &state, &mut mem).await;
        assert_eq!(state.last_compared_height.load(Ordering::Relaxed), 0);
        assert_eq!(state.divergence_total.load(Ordering::Relaxed), 0);
    }
}
