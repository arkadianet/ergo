//! `mining/*` handlers. The candidate/solution/reward
//! endpoints (T1) reuse [`NodeMining`](crate::mining::NodeMining) — the existing
//! PoW/candidate machinery — mapping its [`MiningApiError`] onto the standard
//! error envelope. `miner-stats` (T0) folds the same headers the compat handler
//! reads; `status` (T0) composes existing snapshot reads. `candidate-with-txs`
//! uses the same bounded transaction-candidate seam as the Scala API.

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use ergo_rest_json::mining::AutolykosSolutionJson;
use ergo_ser::address::encode_p2pk_from_pubkey;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::OperatorState;
use crate::mining::MiningApiError;
use crate::types::{ApiMinerStat, ApiMinerStats, SyncStateLabel};
use crate::v1::blocking::ReadLane;
use crate::v1::error::{v1_error, Reason, V1Error};
use crate::v1::routes::chain::chain_read_failed;

/// Map a [`MiningApiError`] onto the standard v1 error envelope. `unavailable`
/// picks the endpoint-appropriate 503 reason (`candidate_unavailable` for the
/// candidate path, `reward_unavailable` for the reward path).
pub(super) fn map_mining_error(e: MiningApiError, unavailable: Reason) -> Response {
    match e {
        MiningApiError::InvalidPow => v1_error(
            Reason::InvalidPow,
            "the posted nonce does not satisfy the candidate's target",
            "re-fetch the current candidate and mine against its msg/b",
        ),
        MiningApiError::StaleParent => v1_error(
            Reason::StaleCandidate,
            "the solved candidate is no longer current (best-full advanced, or \
             the candidate was withdrawn after a block mined from it failed to apply)",
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
pub(crate) struct WindowQuery {
    window: Option<u32>,
}

/// `GET /api/v1/mining/miner-stats` — T0. Bare `ApiMinerStats` (already
/// snake_case; the only compat violation was the `minerStats` camelCase path).
/// Folds [`NodeChainQuery::last_headers`](crate::compat::NodeChainQuery) by
/// miner pk, same logic as the compat `miner_stats_handler`.
#[utoipa::path(
    get, path = "/api/v1/mining/miner-stats", tag = "mining",
    params(("window" = Option<u32>, Query, description = "Trailing headers to fold (default 720, clamped 1..=16384)")),
    responses(
        (status = 200, description = "Miner attribution over the trailing window", body = ApiMinerStats),
        (status = 500, description = "Internal read failure (internal_error)", body = V1Error),
        (status = 503, description = "Chain reader unavailable; overloaded (Retry-After: 1) or shutting_down", body = V1Error),
        (status = 504, description = "Read timed out (timeout)", body = V1Error),
    ),
)]
pub(crate) async fn miner_stats(
    State(s): State<OperatorState>,
    Query(q): Query<WindowQuery>,
) -> Response {
    let chain = match s.chain() {
        Ok(c) => c.clone(),
        Err(e) => return *e,
    };
    let window = q.window.unwrap_or(720).clamp(1, 16_384);
    s.blocking
        .clone()
        .run(ReadLane::Scan, move || {
            let headers = match chain.try_last_headers(window) {
                Ok(headers) => headers,
                Err(error) => return chain_read_failed(error),
            };
            let blocks = headers.len() as u32;
            let tip_height = headers.last().map(|h| h.height).unwrap_or(0);
            // Fold by pk hex: (count, last_height). Headers arrive ascending, so a
            // plain max keeps the latest height per miner.
            let mut agg: std::collections::HashMap<String, (u32, u32)> =
                std::collections::HashMap::new();
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
        })
        .await
}

/// The `mining/status` aggregate. Always `200` — safe to poll from an
/// unauthenticated dashboard even when mining is off (hence T0). The
/// Freshness comes from the served cache and contains no transaction content.
/// `synced` means the mining-started latch when mining is enabled.
#[derive(Serialize, ToSchema)]
pub(crate) struct MiningStatus {
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
#[utoipa::path(
    get, path = "/api/v1/mining/status",
    operation_id = "v1_mining_status_get", tag = "mining",
    responses((status = 200, description = "Mining capability and current served-template freshness", body = MiningStatus)),
)]
pub(crate) async fn status(State(s): State<OperatorState>) -> Response {
    let mining_enabled = s.read.identity().mining;
    let freshness = match &s.mining {
        Some(m) => m.mining_freshness().await.unwrap_or_default(),
        None => Default::default(),
    };
    let synced = if mining_enabled {
        freshness.mining_started
    } else {
        s.read.status().sync_state == SyncStateLabel::AtTip
    };
    Json(MiningStatus {
        mining_enabled,
        synced,
        longpoll_supported: true,
        last_template_msg: freshness.last_template_msg,
        last_template_height: freshness.last_template_height,
        last_template_age_ms: freshness.last_template_age_ms,
        template_seq: freshness.template_seq,
    })
    .into_response()
}

/// `?longpoll=<hex msg>` for `candidate` (getblocktemplate-style bounded block).
#[derive(Debug, Default, Deserialize, ToSchema)]
pub(crate) struct CandidateQuery {
    longpoll: Option<String>,
}

/// `GET /api/v1/mining/candidate` — T1. Reuses [`NodeMining::candidate`]
/// (longpoll semantics preserved). Bare `WorkMessageJson` (reused verbatim —
/// already snake_case + Scala-parity). `503 candidate_unavailable` when no
/// candidate can be built. This CLOSES the finding-3 gap: the flat compat
/// Both `/mining/candidate` and this v1 path require a configured API key.
#[utoipa::path(
    get, path = "/api/v1/mining/candidate",
    operation_id = "v1_mining_candidate_get", tag = "mining",
    params(("longpoll" = Option<String>, Query, description = "getblocktemplate-style longpoll id — block until the candidate changes from this msg")),
    responses(
        (status = 200, description = "Work message (WorkMessageJson — Scala-parity shape)", body = serde_json::Value),
        (status = 409, description = "Mining disabled on this node", body = V1Error),
        (status = 503, description = "No candidate could be built (not synced or generation race)", body = V1Error),
    ),
    security(("ApiKeyAuth" = [])),
)]
pub(crate) async fn candidate(
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

/// Select a retained template precisely; combining selectors is an AND.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub(crate) struct InspectionQuery {
    msg: Option<String>,
    template_seq: Option<u64>,
}

/// Operator-only transaction and rent inventory of one frozen template.
#[utoipa::path(
    get, path = "/api/v1/mining/candidate-details",
    operation_id = "v1_mining_candidate_details_get", tag = "mining",
    params(("msg" = Option<String>, Query, description = "32-byte hexadecimal work ID"), ("template_seq" = Option<u64>, Query, description = "Exact retained publish sequence")),
    responses((status = 200, description = "Frozen template inventory and miner proceeds", body = serde_json::Value), (status = 404, description = "Template was evicted or selectors do not match", body = V1Error), (status = 503, description = "No current template", body = V1Error)),
    security(("ApiKeyAuth" = [])),
)]
pub(crate) async fn candidate_details(
    State(s): State<OperatorState>,
    Query(q): Query<InspectionQuery>,
) -> Response {
    let mining = match s.mining() {
        Ok(m) => m,
        Err(e) => return *e,
    };
    let historical = q.msg.is_some() || q.template_seq.is_some();
    match mining.candidate_details(q.msg, q.template_seq).await {
        Ok(Some(details)) => Json(details).into_response(),
        Ok(None) if historical => v1_error(
            Reason::TemplateNotFound,
            "no retained template matches both selectors",
            "re-fetch current work; templates are retained briefly and reset on restart",
        ),
        Ok(None) => v1_error(
            Reason::CandidateUnavailable,
            "no current template",
            "retry once mining work is available",
        ),
        Err(e) => map_mining_error(e, Reason::CandidateUnavailable),
    }
}

/// Bounded local template and solution history. Resets on restart.
#[utoipa::path(
    get, path = "/api/v1/mining/history",
    operation_id = "v1_mining_history_get", tag = "mining",
    responses((status = 200, description = "Bounded operator mining history", body = serde_json::Value), (status = 503, description = "Mining history unavailable", body = V1Error)),
    security(("ApiKeyAuth" = [])),
)]
pub(crate) async fn history(State(s): State<OperatorState>) -> Response {
    let mining = match s.mining() {
        Ok(m) => m,
        Err(e) => return *e,
    };
    let mut history = match mining.mining_history().await {
        Ok(history) => history,
        Err(e) => return map_mining_error(e, Reason::CandidateUnavailable),
    };
    let Some(chain) = s.chain.clone() else {
        return Json(history).into_response();
    };
    s.blocking
        .run(ReadLane::Scan, move || {
            let heights: Vec<u32> = history
                .outcomes
                .iter()
                .filter_map(|e| e.accounting.as_ref().map(|a| a.height))
                .collect();
            let snapshot = match chain.applied_chain_at_heights(&heights) {
                Ok(Some(snapshot)) => snapshot,
                Ok(None) => return Json(history).into_response(),
                Err(e) => return chain_read_failed(e),
            };
            for event in &mut history.outcomes {
                let Some(accounting) = &event.accounting else {
                    continue;
                };
                let Some(block_id) = &event.block_id else {
                    continue;
                };
                match snapshot
                    .blocks
                    .iter()
                    .find(|(h, _)| *h == accounting.height)
                    .and_then(|(_, id)| id.as_ref())
                {
                    Some(applied) => {
                        let canonical = applied == block_id;
                        event.canonical = Some(canonical);
                        event.confirmations = canonical.then(|| {
                            snapshot
                                .tip
                                .height
                                .saturating_sub(accounting.height)
                                .saturating_add(1)
                        });
                    }
                    None => {
                        event.canonical = None;
                        event.confirmations = None;
                    }
                }
            }
            history.chain_tip = Some(snapshot.tip);
            Json(history).into_response()
        })
        .await
}

/// `POST /api/v1/mining/solution` — T1. Reuses [`NodeMining::submit_solution`].
/// Body = `AutolykosSolutionJson`. `200` empty on accept. Same auth-gate closure
/// as [`candidate`].
#[utoipa::path(
    post, path = "/api/v1/mining/solution", tag = "mining",
    request_body(content = serde_json::Value, description = "AutolykosSolutionJson — Scala-parity shape"),
    responses(
        (status = 200, description = "Accepted"),
        (status = 400, description = "Malformed solution body, or invalid PoW / stale candidate", body = V1Error),
        (status = 409, description = "Mining disabled on this node", body = V1Error),
        (status = 503, description = "Mining subsystem cannot answer right now", body = V1Error),
    ),
    security(("ApiKeyAuth" = [])),
)]
pub(crate) async fn solution(State(s): State<OperatorState>, body: axum::body::Bytes) -> Response {
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

/// Fresh snake_case reward-address DTO (the compat
/// `RewardAddressResponse` is hard-renamed camelCase + pinned by a unit test, so
/// a new DTO is required).
#[derive(Serialize, ToSchema)]
pub(crate) struct RewardAddress {
    reward_address: String,
}

/// Fresh snake_case reward-pubkey DTO (same rationale).
#[derive(Serialize, ToSchema)]
pub(crate) struct RewardPubkey {
    reward_pubkey: String,
}

/// `GET /api/v1/mining/reward-address` — T1. Reuses
/// [`NodeMining::reward_address`] into a fresh snake_case DTO.
/// `503 reward_unavailable` while the wallet-resolved key isn't ready.
#[utoipa::path(
    get, path = "/api/v1/mining/reward-address", tag = "mining",
    responses(
        (status = 200, description = "Miner reward address", body = RewardAddress),
        (status = 409, description = "Mining disabled on this node", body = V1Error),
        (status = 503, description = "Wallet-resolved reward key not yet ready", body = V1Error),
    ),
    security(("ApiKeyAuth" = [])),
)]
pub(crate) async fn reward_address(State(s): State<OperatorState>) -> Response {
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
#[utoipa::path(
    get, path = "/api/v1/mining/reward-pubkey", tag = "mining",
    responses(
        (status = 200, description = "Miner reward pubkey", body = RewardPubkey),
        (status = 409, description = "Mining disabled on this node", body = V1Error),
        (status = 503, description = "Wallet-resolved reward key not yet ready", body = V1Error),
    ),
    security(("ApiKeyAuth" = [])),
)]
pub(crate) async fn reward_pubkey(State(s): State<OperatorState>) -> Response {
    let mining = match s.mining() {
        Ok(m) => m,
        Err(e) => return *e,
    };
    match mining.reward_pubkey().await {
        Ok(reward_pubkey) => Json(RewardPubkey { reward_pubkey }).into_response(),
        Err(e) => map_mining_error(e, Reason::RewardUnavailable),
    }
}

/// `POST /api/v1/mining/candidate-with-txs` — T1. Accepts either a Scala
/// transaction array (configured miner key) or `{txs, pk}` (explicit miner key).
/// Decodes directly from the body to preserve context extension ordering.
#[utoipa::path(
    post, path = "/api/v1/mining/candidate-with-txs", tag = "mining",
    request_body(content = serde_json::Value, description = "A transaction array, or {txs: [...], pk: compressed secp256k1 key hex}. At most 1024 transactions and 2 MiB. Request order and context-extension insertion order are preserved. Returns proofs only for supplied transactions admitted to the candidate."),
    responses(
        (status = 200, description = "WorkMessageJson with header preimage and transaction inclusion proofs", body = serde_json::Value),
        (status = 400, description = "Malformed transactions, invalid miner key, or request limit exceeded", body = V1Error),
        (status = 409, description = "Mining disabled on this node", body = V1Error),
        (status = 503, description = "Candidate unavailable", body = V1Error),
        (status = 504, description = "Candidate build timed out", body = V1Error),
    ),
    security(("ApiKeyAuth" = [])),
)]
pub(crate) async fn candidate_with_txs(
    State(s): State<OperatorState>,
    body: Result<axum::body::Bytes, axum::extract::rejection::BytesRejection>,
) -> Response {
    let mining = match s.mining() {
        Ok(m) => m,
        Err(e) => return *e,
    };
    let body = match body {
        Ok(body) => body,
        Err(e) => {
            return map_mining_error(
                MiningApiError::BadRequest(e.to_string()),
                Reason::CandidateUnavailable,
            )
        }
    };
    let request = if body.iter().copied().find(|b| !b.is_ascii_whitespace()) == Some(b'{') {
        crate::mining::decode_candidate_with_pk(&body)
            .map(|request| (request.txs, Some(request.pk)))
    } else {
        crate::mining::decode_candidate_transactions(&body).map(|txs| (txs, None))
    };
    let (txs, pk) = match request {
        Ok(request) => request,
        Err(e) => return map_mining_error(e, Reason::CandidateUnavailable),
    };
    match mining.candidate_with_txs(txs, pk).await {
        Ok(Some(work)) => Json(work).into_response(),
        Ok(None) => v1_error(
            Reason::CandidateUnavailable,
            "no candidate could be built (not synced or generation race)",
            "retry once the node reports at_tip",
        ),
        Err(e) => map_mining_error(e, Reason::CandidateUnavailable),
    }
}
