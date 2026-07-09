//! `voting/*` handlers (`v1-api-design.md` §3.4). The reads (T0) reshape the
//! camelCase `ApiVotes` / `ApiVotesHistory` DTOs into §1.1 snake_case;
//! `voting/votes` drops the operator-private `configured_votes` (finding 5),
//! which moves to the T1 `operator-votes` read. The operator write (T1) reuses
//! [`NodeAdmin::set_voting_targets`](crate::traits::NodeAdmin).

use utoipa::ToSchema;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};

use super::{offset_collection, ListQuery, OperatorState};
use crate::traits::VotingControlError;
use crate::v1::error::{v1_error, Reason, V1Error};
use crate::v1::routes::dto::Collection;

/// A votable parameter + bounds, snake_case (reshape of the camelCase
/// `ApiVotableParam`).
#[derive(Serialize, ToSchema)]
struct VotableParam {
    id: u8,
    name: String,
    description: String,
    current: i32,
    step: i32,
    min: i32,
    max: i32,
}

/// The public `voting/votes` body — ONLY the public half (§3.4 #1). The
/// operator's own `configured_votes` is dropped here and served (gated) at
/// `operator-votes`.
#[derive(Serialize, ToSchema)]
struct PublicVotes {
    block_height: u32,
    block_version: u8,
    epoch_start_height: u32,
    votable_parameters: Vec<VotableParam>,
}

/// `GET /api/v1/voting/votes` — T0. Public votable-parameter descriptor only;
/// `configured_votes` is NOT exposed here (moved to the T1 `operator-votes`).
#[utoipa::path(
    get, path = "/api/v1/voting/votes", tag = "voting",
    responses((status = 200, description = "Public votable-parameter descriptor (no configured_votes — see operator-votes)", body = PublicVotes)),
)]
pub(super) async fn votes(State(s): State<OperatorState>) -> Response {
    let v = s.read.votes();
    Json(PublicVotes {
        block_height: v.block_height,
        block_version: v.block_version,
        epoch_start_height: v.epoch_start_height,
        votable_parameters: v
            .votable_parameters
            .into_iter()
            .map(|p| VotableParam {
                id: p.id,
                name: p.name,
                description: p.description,
                current: p.current,
                step: p.step,
                min: p.min,
                max: p.max,
            })
            .collect(),
    })
    .into_response()
}

/// A single parameter change across an epoch boundary, snake_case.
#[derive(Serialize, ToSchema)]
struct ParamChange {
    id: u8,
    name: String,
    description: String,
    from: Option<i64>,
    to: i64,
}

/// One epoch boundary at which the active parameters changed, snake_case.
#[derive(Serialize, ToSchema)]
struct VoteChange {
    height: u32,
    params: Vec<ParamChange>,
}

/// The `voting/history` body, snake_case (reshape of the camelCase
/// `ApiVotesHistory`).
#[derive(Serialize, ToSchema)]
struct VotesHistory {
    epoch_length: u32,
    current_height: u32,
    changes: Vec<VoteChange>,
}

/// `GET /api/v1/voting/history` — T0. Bare-object reshape of
/// [`NodeChainQuery::votes_history`](crate::compat::NodeChainQuery).
/// `503 chain_reader_unavailable` with no chain reader.
#[utoipa::path(
    get, path = "/api/v1/voting/history", tag = "voting",
    responses(
        (status = 200, description = "Per-epoch parameter changes", body = VotesHistory),
        (status = 503, description = "Chain reader unavailable", body = V1Error),
    ),
)]
pub(super) async fn history(State(s): State<OperatorState>) -> Response {
    let chain = match s.chain() {
        Ok(c) => c,
        Err(e) => return *e,
    };
    let h = chain.votes_history();
    Json(VotesHistory {
        epoch_length: h.epoch_length,
        current_height: h.current_height,
        changes: h
            .changes
            .into_iter()
            .map(|c| VoteChange {
                height: c.height,
                params: c
                    .params
                    .into_iter()
                    .map(|p| ParamChange {
                        id: p.id,
                        name: p.name,
                        description: p.description,
                        from: p.from,
                        to: p.to,
                    })
                    .collect(),
            })
            .collect(),
    })
    .into_response()
}

/// `GET /api/v1/voting/candidate` — T0, seam-deferred. The next-block vote-byte
/// preview (§3.4 #3) has no projection in `ergo-api` and needs a read threaded
/// through the candidate-builder crate; until then it answers the honest
/// `route_unavailable` rather than fabricating vote bytes.
#[utoipa::path(
    get, path = "/api/v1/voting/candidate", tag = "voting",
    responses((status = 503, description = "Next-block vote-byte preview not wired on this node", body = V1Error)),
)]
pub(super) async fn candidate(State(_s): State<OperatorState>) -> Response {
    v1_error(
        Reason::RouteUnavailable,
        "the next-block vote preview is not wired on this node",
        "GET /voting/candidate needs a candidate-builder vote-byte projection (Phase-2)",
    )
}

/// One configured operator vote, snake_case (reshape of the camelCase
/// `ApiConfiguredVote`).
#[derive(Serialize, ToSchema)]
struct ConfiguredVote {
    parameter_id: u8,
    name: String,
    target: i64,
}

/// `GET /api/v1/voting/operator-votes` — T1. The operator-private half split off
/// `ApiVotes.configured_votes` (finding 5), now gated. Collection envelope
/// (bounded, ≤ ~9 entries).
#[utoipa::path(
    get, path = "/api/v1/voting/operator-votes", tag = "voting",
    params(
        ("limit" = Option<u32>, Query, description = "Page size (default 50, cap 100)"),
        ("cursor" = Option<String>, Query, description = "Opaque page cursor from a prior response"),
    ),
    responses(
        (status = 200, description = "The operator's configured votes", body = Collection<ConfiguredVote>),
        (status = 400, description = "Invalid cursor", body = V1Error),
    ),
    security(("ApiKeyAuth" = [])),
)]
pub(super) async fn operator_votes_get(
    State(s): State<OperatorState>,
    Query(q): Query<ListQuery>,
) -> Response {
    let items: Vec<ConfiguredVote> = s
        .read
        .votes()
        .configured_votes
        .into_iter()
        .map(|c| ConfiguredVote {
            parameter_id: c.parameter_id,
            name: c.name,
            target: c.target,
        })
        .collect();
    offset_collection(items, &q, 50, 100)
}

/// One desired vote in a `POST /voting/operator-votes` body, snake_case.
#[derive(Debug, Deserialize, ToSchema)]
struct VoteTarget {
    parameter_id: u8,
    target: i64,
}

/// `POST /api/v1/voting/operator-votes` body — the FULL desired set (REPLACES;
/// an empty list clears all votes), snake_case.
#[derive(Debug, Deserialize, ToSchema)]
struct SetVotesRequest {
    votes: Vec<VoteTarget>,
}

/// `POST /api/v1/voting/operator-votes` — T1. Reuses
/// [`NodeAdmin::set_voting_targets`]. REPLACES the configured set. `204` on
/// success; `400 not_votable` / `400 out_of_range` / `409 mining_disabled`
/// (reason re-spelled from the dot-form `mining.disabled` per §1.4 rule 7).
#[utoipa::path(
    post, path = "/api/v1/voting/operator-votes", tag = "voting",
    request_body = SetVotesRequest,
    responses(
        (status = 204, description = "Replaced — the configured set now exactly matches the request"),
        (status = 400, description = "Malformed body, non-votable parameter id, or target outside its bounds", body = V1Error),
        (status = 409, description = "Mining disabled on this node", body = V1Error),
        (status = 503, description = "Admin control bridge not wired on this node", body = V1Error),
    ),
    security(("ApiKeyAuth" = [])),
)]
pub(super) async fn operator_votes_set(
    State(s): State<OperatorState>,
    body: axum::body::Bytes,
) -> Response {
    let admin = match s.admin() {
        Ok(a) => a,
        Err(e) => return *e,
    };
    let req: SetVotesRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return v1_error(
                Reason::BadRequest,
                "invalid operator-votes body",
                e.to_string(),
            )
        }
    };
    let targets: Vec<(u8, i64)> = req
        .votes
        .iter()
        .map(|v| (v.parameter_id, v.target))
        .collect();
    match admin.set_voting_targets(targets) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(VotingControlError::NotVotable { parameter_id }) => v1_error(
            Reason::NotVotable,
            format!("parameter id {parameter_id} is not operator-votable"),
            "votable ids are 1..=8 and 9 (subblocks_per_block); block_version/soft-fork are not",
        ),
        Err(VotingControlError::OutOfRange {
            parameter_id,
            target,
            min,
            max,
        }) => v1_error(
            Reason::OutOfRange,
            format!("target {target} for parameter id {parameter_id} is outside [{min}, {max}]"),
            "the recompute only steps toward a bound and won't pin past it",
        ),
        Err(VotingControlError::MiningDisabled) => v1_error(
            Reason::MiningDisabled,
            "voting targets can only be set on a mining node",
            "start the node with [mining] enabled = true",
        ),
    }
}
