//! Voting DTOs: votable-parameter views, operator vote-target reads
//! and writes, and the protocol-parameter change timeline.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// `GET /api/v1/votes` — what the node operator can vote on. Native operator
/// endpoint (no Scala equivalent; ungated like the other `/api/v1/*` reads).
/// The votable set + per-parameter bounds come from the same table the
/// consensus vote-recompute uses, so an operator (and the candidate-vote
/// selector) sees exactly which votes are legal.
#[derive(Clone, Debug, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApiVotes {
    /// Current full-block height (votes are cast by the miner at the next height).
    pub block_height: u32,
    /// Active block-format version.
    pub block_version: u8,
    /// Height the current voting epoch's parameters took effect from.
    pub epoch_start_height: u32,
    /// The numeric parameters an operator can vote to change, with the bounds a
    /// vote must respect. Excludes blockVersion (soft-fork driven, not voted).
    pub votable_parameters: Vec<ApiVotableParam>,
    /// The operator's configured voting targets — the boot `[voting]` config
    /// plus any successful runtime `POST /api/v1/votes` edits (the live policy).
    /// Empty when no targets are configured.
    pub configured_votes: Vec<ApiConfiguredVote>,
}

/// A votable numeric protocol parameter and the inclusive `[min, max]` target
/// bounds. A vote moves the parameter at most one `step` per voting epoch toward
/// the target and only while it is inside the bound, so a target outside
/// `[min, max]` is rejected. Mirror of `ergo_validation::voting::ParamDescriptor`.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApiVotableParam {
    pub id: u8,
    pub name: String,
    /// One-line operator-facing explanation of what the parameter governs and
    /// the implication of voting it higher. Sourced from
    /// `ergo_validation::voting::votable_param_description`.
    pub description: String,
    pub current: i32,
    pub step: i32,
    /// Inclusive lower target bound. The recompute gates at the bound (won't
    /// step a parameter further past it) rather than hard-clamping.
    pub min: i32,
    /// Inclusive upper target bound.
    pub max: i32,
}

/// An operator's configured vote target for one parameter.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApiConfiguredVote {
    pub parameter_id: u8,
    pub name: String,
    /// Desired target value; the node votes up/down toward it.
    pub target: i64,
}

/// Request body for `POST /api/v1/votes` (auth-gated operator write). The
/// `votes` list is the FULL desired set and REPLACES the node's current voting
/// targets — an empty list clears all votes.
#[derive(Clone, Debug, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApiSetVotesRequest {
    /// The operator's desired votes, one entry per parameter to target.
    pub votes: Vec<ApiVoteTarget>,
}

/// One desired vote in a `POST /api/v1/votes` request.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApiVoteTarget {
    /// Votable parameter id (1..=8, or 9 = subblocksPerBlock). `blockVersion`
    /// (123) and soft-fork (120) are not operator-votable and are rejected.
    pub parameter_id: u8,
    /// Desired value; the node votes up/down one step per voting epoch toward it
    /// (consistent with `ApiVotableParam` above and the per-epoch history rows).
    pub target: i64,
}

/// Response for `GET /api/v1/votes/history` — the protocol-parameter change
/// timeline reconstructed from the node's stored per-epoch parameter rows.
/// Each entry is an epoch boundary at which one or more parameters actually
/// changed (boundaries with no change are omitted), so this reads as the
/// governance history: what the network's votes have changed, and when.
#[derive(Clone, Debug, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApiVotesHistory {
    /// Voting epoch length in blocks (mainnet 1024, testnet 128). Parameter
    /// changes can only take effect at heights that are multiples of this.
    pub epoch_length: u32,
    /// Current full-block height, for context.
    pub current_height: u32,
    /// Epoch boundaries where at least one parameter changed, oldest first.
    pub changes: Vec<ApiVoteChangeEvent>,
}

/// One epoch boundary at which the active protocol parameters changed.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApiVoteChangeEvent {
    /// Epoch-start height at which these new values took effect.
    pub height: u32,
    /// The parameters that changed at this boundary.
    pub params: Vec<ApiParamChange>,
}

/// A single parameter's change across one epoch boundary.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApiParamChange {
    /// Parameter id (1..=8, 9 = subblocksPerBlock, or 123 = blockVersion).
    pub id: u8,
    /// Stable camelCase parameter name.
    pub name: String,
    /// One-line operator-facing explanation of the parameter.
    pub description: String,
    /// Value before this boundary. `null` when the parameter first became
    /// active here (e.g. `subblocksPerBlock` at its activation fork).
    pub from: Option<i64>,
    /// Value from this boundary onward.
    pub to: i64,
}
