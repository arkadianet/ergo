//! `diagnostics` — the WARGAMES operator signals as product
//! (`v1-api-design.md` §3.15).
//!
//! Not `up/down` health, but "am I on the majority chain / lone-producing a
//! fork / are my peers good / is my tip stuck / how fast do I build
//! candidates." The incident-defining insight: a forking node reported
//! `HealthStatus::Ok` through a 2-day outage because `classify()` only flags
//! the *victim* symptom. These endpoints make that never-again-silent.
//!
//! Every signal is a **re-projection of the lock-free node snapshot** exposed
//! through [`NodeReadState`](crate::traits::NodeReadState) (sync, health,
//! peers, recent blocks, identity). Where a signal's input is not plumbed
//! through to the API layer yet — the aggregate delivery counters, the banned
//! set, per-peer chain-status, the node's own reward pk, and the
//! candidate-build latency ring, all ASSUMED-new in the design — the field is
//! reported as `null` (unknown), **never a fabricated green**. The `unknown`
//! vector on each signal names those gaps explicitly.

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use utoipa::ToSchema;

use super::V1State;
use crate::types::{ApiPeer, ApiPeerDirection, ApiPeerState, HealthStatus};

/// A tip is "stuck" once full-block progress has been frozen this long while a
/// header gap remains (the headers-advance-but-full-frozen signature).
const STALL_THRESHOLD_MS: u64 = 120_000;
/// Below this, a full-block progress age is "slow" (elevated, not yet stuck).
const SLOW_THRESHOLD_MS: u64 = 60_000;
/// A self-height lead beyond every known peer by more than this is the
/// lone-fork tell (instantaneous; the sustained-window latch is node-side).
const AHEAD_MARGIN: u32 = 1;
/// Peers-ahead lag beyond this reads as `behind`.
const BEHIND_THRESHOLD: u32 = 4;
/// Anti-eclipse outbound floor for the `min_outbound_healthy` verdict.
const MIN_OUTBOUND: u32 = 8;
/// Cap on the `worst_peers` detail list.
const WORST_PEERS_CAP: usize = 10;

// ----- shared peer-height fold --------------------------------------------

/// The subset of peer data the signals derive from, folded once from `peers()`.
struct PeerFold {
    peer_count: u32,
    inbound: u32,
    outbound: u32,
    good: u32,
    degraded: u32,
    /// Peers that advertised a height (`peer_height` is `Some`).
    sampled: u32,
    max_height: Option<u32>,
    median_height: Option<u32>,
    at_or_above: u32,
}

fn fold_peers(peers: &[ApiPeer], self_full_height: u32) -> PeerFold {
    let mut inbound = 0;
    let mut outbound = 0;
    let mut good = 0;
    let mut degraded = 0;
    let mut at_or_above = 0;
    let mut heights: Vec<u32> = Vec::new();
    for p in peers {
        match p.direction {
            ApiPeerDirection::Inbound => inbound += 1,
            ApiPeerDirection::Outbound => outbound += 1,
        }
        match p.state {
            ApiPeerState::Active => good += 1,
            ApiPeerState::Degraded => degraded += 1,
            ApiPeerState::Connecting | ApiPeerState::Handshaking | ApiPeerState::Disconnected => {}
        }
        if let Some(h) = p.peer_height {
            heights.push(h);
            if h >= self_full_height {
                at_or_above += 1;
            }
        }
    }
    heights.sort_unstable();
    let max_height = heights.last().copied();
    let median_height = (!heights.is_empty()).then(|| heights[heights.len() / 2]);
    PeerFold {
        peer_count: peers.len() as u32,
        inbound,
        outbound,
        good,
        degraded,
        sampled: heights.len() as u32,
        max_height,
        median_height,
        at_or_above,
    }
}

// ----- C2 chain-position --------------------------------------------------

#[derive(Debug, Serialize, ToSchema)]
pub struct ChainPosition {
    /// `majority | behind | ahead_suspicious | isolated | unknown`.
    pub status: String,
    pub self_full_height: u32,
    pub self_header_height: u32,
    pub max_peer_height: Option<u32>,
    pub median_peer_height: Option<u32>,
    pub lead: u32,
    pub lag: u32,
    pub peers_at_or_above: u32,
    pub peers_sampled: u32,
    /// Named inputs that could not be derived at the API layer (honest gaps).
    pub unknown: Vec<String>,
}

fn chain_position_of(state: &V1State, fold: &PeerFold) -> ChainPosition {
    let sync = state.read.sync();
    let self_full = sync.best_full_block_height;
    let (lead, lag, status, mut unknown) = match fold.max_height {
        _ if fold.peer_count == 0 => (0, 0, "isolated".to_string(), Vec::new()),
        None => (
            0,
            0,
            "unknown".to_string(),
            vec![
                "max_peer_height: peers advertised no height (sync layer not plumbed to API)"
                    .to_string(),
            ],
        ),
        Some(maxh) => {
            let lead = self_full.saturating_sub(maxh);
            let lag = maxh.saturating_sub(self_full);
            let status = if lead > AHEAD_MARGIN {
                // Instantaneous lone-fork tell; the sustained-window latch that
                // would confirm it is ASSUMED-new node-side state (WARGAMES 1a).
                "ahead_suspicious".to_string()
            } else if lag > BEHIND_THRESHOLD {
                "behind".to_string()
            } else {
                "majority".to_string()
            };
            (lead, lag, status, Vec::new())
        }
    };
    if status == "ahead_suspicious" {
        unknown.push(
            "sustained_window: the ahead-suspicious latch is instantaneous only (node-side \
             sustained-window state is ASSUMED-new)"
                .to_string(),
        );
    }
    ChainPosition {
        status,
        self_full_height: self_full,
        self_header_height: sync.best_header_height,
        max_peer_height: fold.max_height,
        median_peer_height: fold.median_height,
        lead,
        lag,
        peers_at_or_above: fold.at_or_above,
        peers_sampled: fold.sampled,
        unknown,
    }
}

/// `GET /api/v1/diagnostics/chain-position`.
#[utoipa::path(
    get, path = "/api/v1/diagnostics/chain-position", tag = "diagnostics",
    responses((status = 200, description = "Position vs peers: majority/behind/ahead_suspicious/isolated/unknown", body = ChainPosition)),
)]
pub async fn chain_position(State(state): State<V1State>) -> Response {
    let peers = state.read.peers();
    let self_full = state.read.sync().best_full_block_height;
    let fold = fold_peers(&peers, self_full);
    Json(chain_position_of(&state, &fold)).into_response()
}

// ----- C3 fork-risk -------------------------------------------------------

#[derive(Debug, Serialize, ToSchema)]
pub struct ForkRisk {
    /// `none | watch | forking`.
    pub status: String,
    pub lone_producer: bool,
    /// Fraction of recent blocks this node mined — `null`: the node's own
    /// reward pk is not exposed at the API layer, so it cannot be attributed.
    pub self_mined_fraction_pct: Option<String>,
    pub rejecting_block: bool,
    /// `null`: the deep-reorg wedge is only a `debug!` today (WARGAMES 4a);
    /// no snapshot field carries it yet (ASSUMED-new).
    pub fork_too_deep: Option<bool>,
    pub best_header_vs_full_gap: u32,
    /// `null`: same ASSUMED-new deep-reorg state.
    pub resync_required: Option<bool>,
    pub unknown: Vec<String>,
}

fn fork_risk_of(state: &V1State, chain_pos: &ChainPosition) -> ForkRisk {
    let health = state.read.health();
    let identity = state.read.identity();
    let sync = state.read.sync();
    // Wedged counts as forking: the node IS stranded on a branch the
    // network abandoned (that is what made the reorg too deep to serve).
    let rejecting_block = matches!(
        health.status,
        HealthStatus::Rejecting | HealthStatus::Wedged
    );
    let lone_producer = identity.mining && chain_pos.status == "ahead_suspicious";
    let status = if rejecting_block || lone_producer {
        "forking".to_string()
    } else if chain_pos.status == "ahead_suspicious" || sync.gap > BEHIND_THRESHOLD {
        "watch".to_string()
    } else {
        "none".to_string()
    };
    ForkRisk {
        status,
        lone_producer,
        self_mined_fraction_pct: None,
        rejecting_block,
        fork_too_deep: None,
        best_header_vs_full_gap: sync.gap,
        resync_required: None,
        unknown: vec![
            "self_mined_fraction_pct: node reward pk not exposed at the API layer".to_string(),
            "fork_too_deep/resync_required: deep-reorg wedge state is ASSUMED-new (only a \
             debug! log today)"
                .to_string(),
        ],
    }
}

/// `GET /api/v1/diagnostics/fork-risk`.
#[utoipa::path(
    get, path = "/api/v1/diagnostics/fork-risk", tag = "diagnostics",
    responses((status = 200, description = "Fork-risk verdict: none/watch/forking", body = ForkRisk)),
)]
pub async fn fork_risk(State(state): State<V1State>) -> Response {
    let peers = state.read.peers();
    let self_full = state.read.sync().best_full_block_height;
    let fold = fold_peers(&peers, self_full);
    let cp = chain_position_of(&state, &fold);
    Json(fork_risk_of(&state, &cp)).into_response()
}

// ----- C4 tip-health ------------------------------------------------------

#[derive(Debug, Serialize, ToSchema)]
pub struct TipHealth {
    /// `advancing | slow | stuck`.
    pub status: String,
    pub headers_synced: bool,
    pub gap: u32,
    pub best_header_height: u32,
    pub best_full_block_height: u32,
    pub last_progress_age_ms: u64,
    pub stall_threshold_ms: u64,
    pub pending_blocks: u32,
    pub download_window: u32,
    /// `null`: the aggregate `DeliveryCounters` are not plumbed to the API
    /// layer (ASSUMED-new), so the failure rate cannot be computed here.
    pub delivery_failure_rate_pct: Option<String>,
    pub unknown: Vec<String>,
}

fn tip_health_of(state: &V1State) -> TipHealth {
    let sync = state.read.sync();
    let health = state.read.health();
    let age = health.last_progress_age_ms;
    let status = if sync.gap > 0 && age >= STALL_THRESHOLD_MS {
        "stuck".to_string()
    } else if sync.gap > 0 && age >= SLOW_THRESHOLD_MS {
        "slow".to_string()
    } else {
        "advancing".to_string()
    };
    TipHealth {
        status,
        headers_synced: sync.headers_chain_synced,
        gap: sync.gap,
        best_header_height: sync.best_header_height,
        best_full_block_height: sync.best_full_block_height,
        last_progress_age_ms: age,
        stall_threshold_ms: STALL_THRESHOLD_MS,
        pending_blocks: sync.pending_blocks,
        download_window: sync.download_window,
        delivery_failure_rate_pct: None,
        unknown: vec![
            "delivery_failure_rate_pct: aggregate DeliveryCounters not plumbed to the API layer"
                .to_string(),
        ],
    }
}

/// `GET /api/v1/diagnostics/tip-health`.
#[utoipa::path(
    get, path = "/api/v1/diagnostics/tip-health", tag = "diagnostics",
    responses((status = 200, description = "Tip progress verdict: advancing/slow/stuck", body = TipHealth)),
)]
pub async fn tip_health(State(state): State<V1State>) -> Response {
    Json(tip_health_of(&state)).into_response()
}

// ----- C5 peer-quality ----------------------------------------------------

#[derive(Debug, Serialize, ToSchema)]
pub struct PeerRow {
    pub addr: String,
    pub score: i32,
    pub state: String,
    pub peer_height: Option<u32>,
    pub last_seen_seconds: u64,
    /// `null`: per-peer delivery attribution is ASSUMED-new (only aggregate
    /// counters exist, and they are not plumbed here).
    pub delivery_failures: Option<u32>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PeerQualitySummary {
    /// `healthy | thin | degraded`.
    pub status: String,
    pub peer_count: u32,
    pub inbound: u32,
    pub outbound: u32,
    pub good_peers: u32,
    pub degraded_peers: u32,
    /// `null`: the banned set is not plumbed to the API layer (ASSUMED-new).
    pub banned_count: Option<u32>,
    pub at_or_above_tip: u32,
    /// `null`: per-peer chain-status (Equal/Fork/…) is not plumbed here.
    pub on_fork: Option<u32>,
    /// `null`: aggregate `DeliveryCounters` not plumbed to the API layer.
    pub delivery: Option<()>,
    pub min_outbound_healthy: bool,
    pub unknown: Vec<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PeerQuality {
    pub summary: PeerQualitySummary,
    pub worst_peers: Vec<PeerRow>,
}

fn peer_state_str(s: ApiPeerState) -> &'static str {
    match s {
        ApiPeerState::Connecting => "connecting",
        ApiPeerState::Handshaking => "handshaking",
        ApiPeerState::Active => "active",
        ApiPeerState::Degraded => "degraded",
        ApiPeerState::Disconnected => "disconnected",
    }
}

fn peer_quality_of(peers: &[ApiPeer], fold: &PeerFold) -> PeerQuality {
    let min_outbound_healthy = fold.outbound >= MIN_OUTBOUND;
    let degraded_heavy = fold.peer_count > 0 && fold.degraded * 4 > fold.peer_count;
    let status = if !min_outbound_healthy {
        "thin".to_string()
    } else if degraded_heavy {
        "degraded".to_string()
    } else {
        "healthy".to_string()
    };
    let mut worst: Vec<&ApiPeer> = peers.iter().collect();
    worst.sort_by_key(|p| p.score);
    let worst_peers = worst
        .into_iter()
        .take(WORST_PEERS_CAP)
        .map(|p| PeerRow {
            addr: p.addr.clone(),
            score: p.score,
            state: peer_state_str(p.state).to_string(),
            peer_height: p.peer_height,
            last_seen_seconds: p.last_seen_seconds,
            delivery_failures: None,
        })
        .collect();
    PeerQuality {
        summary: PeerQualitySummary {
            status,
            peer_count: fold.peer_count,
            inbound: fold.inbound,
            outbound: fold.outbound,
            good_peers: fold.good,
            degraded_peers: fold.degraded,
            banned_count: None,
            at_or_above_tip: fold.at_or_above,
            on_fork: None,
            delivery: None,
            min_outbound_healthy,
            unknown: vec![
                "banned_count: banned set not plumbed to the API layer".to_string(),
                "on_fork: per-peer chain-status not plumbed to the API layer".to_string(),
                "delivery: aggregate DeliveryCounters not plumbed to the API layer".to_string(),
            ],
        },
        worst_peers,
    }
}

/// `GET /api/v1/diagnostics/peer-quality`.
#[utoipa::path(
    get, path = "/api/v1/diagnostics/peer-quality", tag = "diagnostics",
    responses((status = 200, description = "Peer-set verdict + worst-scoring peers: healthy/thin/degraded", body = PeerQuality)),
)]
pub async fn peer_quality(State(state): State<V1State>) -> Response {
    let peers = state.read.peers();
    let self_full = state.read.sync().best_full_block_height;
    let fold = fold_peers(&peers, self_full);
    Json(peer_quality_of(&peers, &fold)).into_response()
}

// ----- C6 candidate-build -------------------------------------------------

#[derive(Debug, Serialize, ToSchema)]
pub struct CandidateBuild {
    /// `unknown | disabled` today (`ok | slow | stalled` once the build-latency
    /// telemetry is plumbed — without it a health verdict would be fabricated).
    pub status: String,
    pub mining_enabled: bool,
    /// `null`: base-cache flag not plumbed to the API layer.
    pub base_cache_enabled: Option<bool>,
    /// `null`: the latency is logged (`mining_engine.rs:489`) but not persisted
    /// as a snapshot gauge/ring (ASSUMED-new).
    pub last_build_ms: Option<u64>,
    pub p50_build_ms: Option<u64>,
    pub p90_build_ms: Option<u64>,
    pub last_built_at_unix_ms: Option<u64>,
    pub builds_sampled: u32,
    /// `null`: candidate availability not plumbed to the API layer.
    pub candidate_available: Option<bool>,
    pub unknown: Vec<String>,
}

fn candidate_build_of(state: &V1State) -> CandidateBuild {
    let mining_enabled = state.read.identity().mining;
    // With no latency ring plumbed, we can only honestly report
    // enabled-but-unmeasured / disabled — never a fake "ok" (or "slow")
    // latency verdict. `unknown` is severity-neutral in the composite.
    let status = if mining_enabled {
        "unknown".to_string()
    } else {
        "disabled".to_string()
    };
    CandidateBuild {
        status,
        mining_enabled,
        base_cache_enabled: None,
        last_build_ms: None,
        p50_build_ms: None,
        p90_build_ms: None,
        last_built_at_unix_ms: None,
        builds_sampled: 0,
        candidate_available: None,
        unknown: vec![
            "last_build_ms/p50/p90/builds_sampled: candidate-build latency ring is ASSUMED-new \
             (logged today, not persisted)"
                .to_string(),
        ],
    }
}

/// `GET /api/v1/diagnostics/candidate-build`.
#[utoipa::path(
    get, path = "/api/v1/diagnostics/candidate-build", tag = "diagnostics",
    responses((status = 200, description = "Mining candidate-build health (unknown/disabled until latency telemetry is plumbed)", body = CandidateBuild)),
)]
pub async fn candidate_build(State(state): State<V1State>) -> Response {
    Json(candidate_build_of(&state)).into_response()
}

// ----- C1 composite -------------------------------------------------------

#[derive(Debug, Serialize, ToSchema)]
pub struct Diagnostics {
    /// Worst of the sub-verdicts: `ok | degraded | critical`.
    pub verdict: String,
    pub chain_position: ChainPosition,
    pub fork_risk: ForkRisk,
    pub tip_health: TipHealth,
    pub peer_quality: PeerQuality,
    pub candidate_build: CandidateBuild,
    pub generated_at_unix_ms: u64,
}

/// Map a sub-signal status string to a verdict tier severity (0 ok .. 2 crit).
fn severity(status: &str) -> u8 {
    match status {
        // critical tells
        "ahead_suspicious" | "isolated" | "forking" | "stuck" | "stalled" => 2,
        // degraded
        "behind" | "watch" | "slow" | "thin" | "degraded" => 1,
        // ok / neutral (majority, none, advancing, healthy, ok, disabled, unknown)
        _ => 0,
    }
}

fn verdict_str(worst: u8) -> &'static str {
    match worst {
        2 => "critical",
        1 => "degraded",
        _ => "ok",
    }
}

/// `GET /api/v1/diagnostics` — the one-call operator health verdict.
#[utoipa::path(
    get, path = "/api/v1/diagnostics", tag = "diagnostics",
    responses((status = 200, description = "Composite verdict (worst of every sub-signal): ok/degraded/critical", body = Diagnostics)),
)]
pub async fn composite(State(state): State<V1State>) -> Response {
    let peers = state.read.peers();
    let self_full = state.read.sync().best_full_block_height;
    let fold = fold_peers(&peers, self_full);

    let chain_position = chain_position_of(&state, &fold);
    let fork_risk = fork_risk_of(&state, &chain_position);
    let tip_health = tip_health_of(&state);
    let peer_quality = peer_quality_of(&peers, &fold);
    let candidate_build = candidate_build_of(&state);

    let worst = [
        severity(&chain_position.status),
        severity(&fork_risk.status),
        severity(&tip_health.status),
        severity(&peer_quality.summary.status),
        severity(&candidate_build.status),
    ]
    .into_iter()
    .max()
    .unwrap_or(0);

    let generated_at_unix_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    Json(Diagnostics {
        verdict: verdict_str(worst).to_string(),
        chain_position,
        fork_risk,
        tip_health,
        peer_quality,
        candidate_build,
        generated_at_unix_ms,
    })
    .into_response()
}

/// `GET /api/v1/diagnostics/reorgs` — last-N / max-age postmortem ring.
#[utoipa::path(
    get, path = "/api/v1/diagnostics/reorgs", tag = "diagnostics",
    responses(
        (status = 200, description = "Retained tip-replacement reorgs (newest first)",
         body = crate::types::ApiReorgHistory)
    )
)]
pub async fn reorgs(State(state): State<V1State>) -> Response {
    Json(state.read.reorgs()).into_response()
}
