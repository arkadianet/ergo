//! `mining/*` handlers (`v1-api-design.md` §3.3). The candidate/solution/reward
//! endpoints (T1) reuse [`NodeMining`](crate::mining::NodeMining) — the existing
//! PoW/candidate machinery — mapping its [`MiningApiError`] onto the §1.4 error
//! envelope. `miner-stats` (T0) folds the same headers the compat handler reads;
//! `status` (T0) composes existing snapshot reads. `candidate-with-txs` has no
//! trait seam yet (§3.3 #5), so it answers the honest `route_unavailable`.

use utoipa::ToSchema;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use ergo_rest_json::mining::AutolykosSolutionJson;
use ergo_ser::address::encode_p2pk_from_pubkey;
use serde::{Deserialize, Serialize};

use super::OperatorState;
use crate::mining::MiningApiError;
use crate::types::{ApiMinerStat, ApiMinerStats, SyncStateLabel};
use crate::v1::error::{v1_error, Reason};

/// Map a [`MiningApiError`] onto the §1.4 v1 error envelope. `unavailable`
/// picks the endpoint-appropriate 503 reason (`candidate_unavailable` for the
/// candidate path, `reward_unavailable` for the reward path).
fn map_mining_error(e: MiningApiError, unavailable: Reason) -> Response {
    match e {
        MiningApiError::InvalidPow => v1_error(
            Reason::InvalidPow,
            "the posted nonce does not satisfy the candidate's target",
            "re-fetch the current candidate and mine against its msg/b",
        ),
        MiningApiError::StaleParent => v1_error(
            Reason::StaleCandidate,
            "the cached candidate's parent flipped (best-full advanced)",
            "re-fetch GET /api/v1/mining/candidate and resubmit",
        ),
        MiningApiError::Unavailable(detail) => v1_error(
            unavailable,
            "the mining subsystem cannot answer right now",
            detail,
        ),
        MiningApiError::BadRequest(detail) => {
            v1_error(Reason::BadRequest, "malformed mining request", detail)
        }
        MiningApiError::Unauthorized => v1_error(
            Reason::Unauthorized,
            "missing or invalid api_key",
            "send the operator api_key header",
        ),
        MiningApiError::Timeout(detail) => v1_error(
            Reason::Timeout,
            "the node main loop did not reply within the deadline",
            detail,
        ),
        MiningApiError::Internal(detail) => {
            v1_error(Reason::InternalError, "internal mining error", detail)
        }
    }
}

/// `?window=<u32>` for `miner-stats` (default 720 ≈ 1 day at 120s; clamp
/// `[1, 16384]`).
#[derive(Debug, Default, Deserialize, ToSchema)]
pub(super) struct WindowQuery {
    window: Option<u32>,
}

/// `GET /api/v1/mining/miner-stats` — T0. Bare `ApiMinerStats` (already
/// snake_case; the only compat violation was the `minerStats` camelCase path).
/// Folds [`NodeChainQuery::last_headers`](crate::compat::NodeChainQuery) by
/// miner pk, same logic as the compat `miner_stats_handler`.
pub(super) async fn miner_stats(
    State(s): State<OperatorState>,
    Query(q): Query<WindowQuery>,
) -> Response {
    let chain = match s.chain() {
        Ok(c) => c,
        Err(e) => return *e,
    };
    let window = q.window.unwrap_or(720).clamp(1, 16_384);
    let headers = chain.last_headers(window);
    let blocks = headers.len() as u32;
    let tip_height = headers.last().map(|h| h.height).unwrap_or(0);
    // Fold by pk hex: (count, last_height). Headers arrive ascending, so a
    // plain max keeps the latest height per miner.
    let mut agg: std::collections::HashMap<String, (u32, u32)> = std::collections::HashMap::new();
    for h in &headers {
        let e = agg.entry(h.pow_solutions.pk.clone()).or_insert((0, 0));
        e.0 += 1;
        if h.height > e.1 {
            e.1 = h.height;
        }
    }
    let mut miners: Vec<ApiMinerStat> = agg
        .into_iter()
        .map(|(pk, (count, last_height))| {
            let address = hex::decode(&pk)
                .ok()
                .and_then(|b| encode_p2pk_from_pubkey(s.network, &b).ok());
            ApiMinerStat {
                pk,
                address,
                count,
                last_height,
            }
        })
        .collect();
    miners.sort_by(|a, b| {
        b.count
            .cmp(&a.count)
            .then(b.last_height.cmp(&a.last_height))
    });
    Json(ApiMinerStats {
        tip_height,
        window,
        blocks,
        miners,
    })
    .into_response()
}

/// The `mining/status` aggregate (§3.3 #7). Always `200` — safe to poll from an
/// unauthenticated dashboard even when mining is off (hence T0). The
/// `last_template_*` / `template_seq` fields require the mining bridge to cache
/// its last-published template metadata; that seam is not wired yet, so they are
/// emitted as `null` (honest) rather than fabricated.
#[derive(Serialize, ToSchema)]
struct MiningStatus {
    mining_enabled: bool,
    synced: bool,
    longpoll_supported: bool,
    last_template_msg: Option<String>,
    last_template_height: Option<u32>,
    last_template_age_ms: Option<u64>,
    template_seq: Option<u64>,
}

/// `GET /api/v1/mining/status` — T0. Composed from existing snapshot reads
/// (`identity().mining` + `status().sync_state`); never triggers a `candidate()`
/// build just to health-check.
pub(super) async fn status(State(s): State<OperatorState>) -> Response {
    let mining_enabled = s.read.identity().mining;
    let synced = s.read.status().sync_state == SyncStateLabel::AtTip;
    Json(MiningStatus {
        mining_enabled,
        synced,
        longpoll_supported: true,
        last_template_msg: None,
        last_template_height: None,
        last_template_age_ms: None,
        template_seq: None,
    })
    .into_response()
}

/// `?longpoll=<hex msg>` for `candidate` (getblocktemplate-style bounded block).
#[derive(Debug, Default, Deserialize, ToSchema)]
pub(super) struct CandidateQuery {
    longpoll: Option<String>,
}

/// `GET /api/v1/mining/candidate` — T1. Reuses [`NodeMining::candidate`]
/// (longpoll semantics preserved). Bare `WorkMessageJson` (reused verbatim —
/// already snake_case + Scala-parity). `503 candidate_unavailable` when no
/// candidate can be built. This CLOSES the finding-3 gap: the flat compat
/// `/mining/candidate` mounts ungated; this v1 path is api_key-gated.
pub(super) async fn candidate(
    State(s): State<OperatorState>,
    Query(q): Query<CandidateQuery>,
) -> Response {
    let mining = match s.mining() {
        Ok(m) => m,
        Err(e) => return *e,
    };
    match mining.candidate(q.longpoll).await {
        Ok(Some(w)) => Json(w).into_response(),
        Ok(None) => v1_error(
            Reason::CandidateUnavailable,
            "no candidate could be built (not synced or generation race)",
            "retry once the node reports at_tip",
        ),
        Err(e) => map_mining_error(e, Reason::CandidateUnavailable),
    }
}

/// `POST /api/v1/mining/solution` — T1. Reuses [`NodeMining::submit_solution`].
/// Body = `AutolykosSolutionJson`. `200` empty on accept. Same auth-gate closure
/// as [`candidate`].
pub(super) async fn solution(State(s): State<OperatorState>, body: axum::body::Bytes) -> Response {
    let mining = match s.mining() {
        Ok(m) => m,
        Err(e) => return *e,
    };
    let sol: AutolykosSolutionJson = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return v1_error(
                Reason::BadRequest,
                "invalid mining solution body",
                e.to_string(),
            )
        }
    };
    match mining.submit_solution(sol).await {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) => map_mining_error(e, Reason::CandidateUnavailable),
    }
}

/// Fresh snake_case reward-address DTO (§3.3 #3 — the compat
/// `RewardAddressResponse` is hard-renamed camelCase + pinned by a unit test, so
/// a new DTO is required).
#[derive(Serialize, ToSchema)]
struct RewardAddress {
    reward_address: String,
}

/// Fresh snake_case reward-pubkey DTO (§3.3 #4 — same rationale).
#[derive(Serialize, ToSchema)]
struct RewardPubkey {
    reward_pubkey: String,
}

/// `GET /api/v1/mining/reward-address` — T1. Reuses
/// [`NodeMining::reward_address`] into a fresh snake_case DTO.
/// `503 reward_unavailable` while the wallet-resolved key isn't ready.
pub(super) async fn reward_address(State(s): State<OperatorState>) -> Response {
    let mining = match s.mining() {
        Ok(m) => m,
        Err(e) => return *e,
    };
    match mining.reward_address().await {
        Ok(reward_address) => Json(RewardAddress { reward_address }).into_response(),
        Err(e) => map_mining_error(e, Reason::RewardUnavailable),
    }
}

/// `GET /api/v1/mining/reward-pubkey` — T1. Reuses [`NodeMining::reward_pubkey`]
/// into a fresh snake_case DTO.
pub(super) async fn reward_pubkey(State(s): State<OperatorState>) -> Response {
    let mining = match s.mining() {
        Ok(m) => m,
        Err(e) => return *e,
    };
    match mining.reward_pubkey().await {
        Ok(reward_pubkey) => Json(RewardPubkey { reward_pubkey }).into_response(),
        Err(e) => map_mining_error(e, Reason::RewardUnavailable),
    }
}

/// `POST /api/v1/mining/candidate-with-txs` — T1, seam-deferred. The wire shape
/// is documented (§3.3 #5) but no `NodeMining::candidate_with_txs` seam exists,
/// so this answers the honest `route_unavailable` rather than silently ignoring
/// the forced-tx set. Still gated at `Tier::Operator`.
pub(super) async fn candidate_with_txs(State(_s): State<OperatorState>) -> Response {
    v1_error(
        Reason::RouteUnavailable,
        "forced-transaction candidate building is not wired on this node",
        "POST /mining/candidate-with-txs needs a NodeMining::candidate_with_txs seam (Phase-1 machinery exists; the trait method does not)",
    )
}
