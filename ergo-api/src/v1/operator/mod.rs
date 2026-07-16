//! `/api/v1/{node,network,mining,voting}/*` — the operator/control group.
//! Mixed tiers:
//!
//! * **T0 reads** — `node/{info,status,sync,tip,identity,health,version,host}`,
//!   `network/{peers,connected,blacklisted,sync-info,track-info}`,
//!   `mining/{miner-stats,status}`, `voting/{votes,history,candidate}`. Bounded
//!   by the shared [`Governor`](crate::v1::governor) (route-class `CheapRead`),
//!   not by auth — same posture as [`crate::v1::v1_router`]'s T0 reads.
//! * **T1 controls** — `network/connect`, `network/blacklist`,
//!   `mining/{candidate,solution,reward-address,reward-pubkey,candidate-with-txs}`,
//!   `voting/operator-votes` (GET+POST), `node/config` GET. Gated by
//!   [`require_tier`](crate::v1::auth::require_tier) at `Tier::Operator`.
//! * **T2 admin** — `node/config` PATCH (mutation). Gated at `Tier::Admin`
//!   (`api_key` + loopback-preferred). `node/shutdown` is the canonical T2
//!   endpoint but stays on the frozen compat mount (see the T2 note in
//!   [`operator_router`]); this group does not re-mount it.
//!
//! Every endpoint **reuses an existing node capability** — the same
//! [`NodeReadState`](crate::traits::NodeReadState) /
//! [`NodeChainQuery`](crate::compat::NodeChainQuery) /
//! [`NodeAdmin`](crate::traits::NodeAdmin) /
//! [`NodeMining`](crate::mining::NodeMining) traits the compat surface reads —
//! reshaped into the standard envelope + snake_case glossary. Where a
//! capability has no trait seam yet (manual peer-ban, config read/patch,
//! forced-tx candidate, next-block vote preview), the endpoint mounts and
//! answers the honest `route_unavailable` rather than a bare 404.

pub(crate) mod mining;
pub(crate) mod network;
pub(crate) mod node;
pub(crate) mod voting;

use std::sync::Arc;
use utoipa::ToSchema;

use axum::{
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use ergo_ser::address::NetworkPrefix;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::compat::NodeChainQuery;
use crate::mining::NodeMining;
use crate::traits::{NodeAdmin, NodeReadState};
use crate::v1::auth::{require_tier, Tier, V1AuthConfig};
use crate::v1::cursor::{clamp_limit, decode_opt_cursor, encode_cursor, Page};
use crate::v1::error::{v1_error, Reason};
use crate::v1::governor::{governor_mw, Governor, RouteClass};

/// Shared state for the operator/control group. Every node-capability handle is
/// `Option` where the subsystem may be absent, so a handler answers the honest
/// `*_unavailable` reason instead of a bare 404 — the group mounts
/// unconditionally and gates *inside* each handler, mirroring [`crate::v1::V1State`].
#[derive(Clone)]
pub struct OperatorState {
    /// Snapshot reader — every `node/*` read, `network/peers[/connected]`, and
    /// the `voting/*` reads project off this.
    pub read: Arc<dyn NodeReadState>,
    /// Live-store chain reader — the peer blacklist / sync-info / track-info
    /// projections, `voting/history`, and `mining/miner-stats` (folded headers).
    /// `None` ⇒ those endpoints answer `chain_reader_unavailable`.
    pub chain: Option<Arc<dyn NodeChainQuery>>,
    /// Out-of-band admin boundary — `node/shutdown`, `network/connect`, and the
    /// `voting/operator-votes` write. `None` ⇒ those endpoints answer
    /// `route_unavailable`.
    pub admin: Option<Arc<dyn NodeAdmin>>,
    /// Mining subsystem — `mining/{candidate,solution,reward-*}`. `None` ⇒ those
    /// endpoints answer `mining_disabled`.
    pub mining: Option<Arc<dyn NodeMining>>,
    /// Address-encoding network prefix (miner-stats P2PK derivation +
    /// `network/connect` address parsing).
    pub network: NetworkPrefix,
}

impl OperatorState {
    /// The live chain reader, or the boxed `503 chain_reader_unavailable`
    /// when the node was wired without one. Boxed to keep the `Ok` path small
    /// (repo convention).
    fn chain(&self) -> Result<&Arc<dyn NodeChainQuery>, Box<Response>> {
        self.chain.as_ref().ok_or_else(|| {
            Box::new(v1_error(
                Reason::ChainReaderUnavailable,
                "the chain reader is not wired on this node",
                "peer/voting history reads require the live-store NodeChainQuery bridge",
            ))
        })
    }

    /// The admin boundary, or the boxed `503 route_unavailable` when the node was
    /// wired without an admin handle (read-only mirror / test fixture).
    fn admin(&self) -> Result<&Arc<dyn NodeAdmin>, Box<Response>> {
        self.admin.as_ref().ok_or_else(|| {
            Box::new(v1_error(
                Reason::RouteUnavailable,
                "the admin control bridge is not wired on this node",
                "shutdown / peer-connect / voting writes require a NodeAdmin handle",
            ))
        })
    }

    /// The mining subsystem, or the boxed `409 mining_disabled` when the
    /// node runs with `[mining] enabled = false`.
    fn mining(&self) -> Result<&Arc<dyn NodeMining>, Box<Response>> {
        self.mining.as_ref().ok_or_else(|| {
            Box::new(v1_error(
                Reason::MiningDisabled,
                "mining is not enabled on this node",
                "start the node with [mining] enabled = true to use the mining control surface",
            ))
        })
    }
}

/// `?limit=&cursor=` query for the bounded operator list endpoints.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub(crate) struct ListQuery {
    pub limit: Option<u32>,
    pub cursor: Option<String>,
}

/// Opaque offset cursor for the bounded operator collections (peers, blacklist,
/// sync-info, operator-votes). These lists are node-bounded (well under a few
/// hundred entries), so an offset alias is stable enough; opaque to clients so a
/// keyset seek can replace it without a wire break.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
struct OffsetCursor {
    off: u32,
}

/// Build a `{items, page}` collection envelope from a fully-materialized
/// bounded list via offset pagination + overfetch-by-one. Used by every
/// operator list endpoint (all are node-bounded snapshot reads).
pub(super) fn offset_collection<T: Serialize>(
    all: Vec<T>,
    q: &ListQuery,
    default_limit: u32,
    max_limit: u32,
) -> Response {
    let limit = clamp_limit(q.limit, default_limit, max_limit);
    let off = match decode_opt_cursor::<OffsetCursor>(q.cursor.as_deref()) {
        Ok(c) => c.map(|c| c.off).unwrap_or(0),
        Err(e) => return *e,
    };
    let start = (off as usize).min(all.len());
    let mut window: Vec<T> = all
        .into_iter()
        .skip(start)
        .take(limit as usize + 1)
        .collect();
    let has_more = window.len() > limit as usize;
    if has_more {
        window.truncate(limit as usize);
    }
    let next_cursor = has_more.then(|| {
        encode_cursor(&OffsetCursor {
            off: off.saturating_add(limit),
        })
    });
    Json(json!({
        "items": window,
        "page": Page { limit, next_cursor, has_more },
    }))
    .into_response()
}

/// Build the operator/control router (`node/*`, `network/*`, `mining/*`,
/// `voting/*`). Three tier layers over one [`OperatorState`]:
///
/// * a **T0** sub-router fronted by the shared [`Governor`] at `CheapRead` (no
///   auth — bounded by the governor, like every other v1 read);
/// * a **T1** sub-router gated by `require_tier(Tier::Operator)`;
/// * a **T2** sub-router gated by `require_tier(Tier::Admin)` (loopback-preferred).
///
/// State-erased for merging under `/api/v1`, the same shape as
/// [`crate::v1::v1_router`] and [`crate::v1::webhooks_router`].
pub fn operator_router(
    state: OperatorState,
    governor: Arc<Governor>,
    auth: Arc<V1AuthConfig>,
) -> Router {
    // ----- T0: public, governor-bounded reads -----
    let t0: Router<OperatorState> = Router::new()
        // node/*
        .route("/api/v1/node/info", get(node::info))
        .route("/api/v1/node/status", get(node::status))
        .route("/api/v1/node/sync", get(node::sync))
        .route("/api/v1/node/tip", get(node::tip))
        .route("/api/v1/node/identity", get(node::identity))
        .route("/api/v1/node/health", get(node::health))
        .route("/api/v1/node/version", get(node::version))
        .route("/api/v1/node/host", get(node::host))
        // network/*
        .route("/api/v1/network/peers", get(network::peers))
        .route("/api/v1/network/connected", get(network::connected))
        .route("/api/v1/network/blacklisted", get(network::blacklisted))
        .route("/api/v1/network/sync-info", get(network::sync_info))
        .route("/api/v1/network/track-info", get(network::track_info))
        // mining/*
        .route("/api/v1/mining/miner-stats", get(mining::miner_stats))
        .route("/api/v1/mining/status", get(mining::status))
        // voting/*
        .route("/api/v1/voting/votes", get(voting::votes))
        .route("/api/v1/voting/history", get(voting::history))
        .route("/api/v1/voting/candidate", get(voting::candidate))
        .route_layer(axum::middleware::from_fn_with_state(
            governor.state(RouteClass::CheapRead),
            governor_mw,
        ));

    // ----- T1: operator (api_key) controls -----
    let t1: Router<OperatorState> = Router::new()
        // node config read (mutation is T2, below)
        .route("/api/v1/node/config", get(node::config_get))
        // network controls
        .route("/api/v1/network/connect", post(network::connect))
        .route("/api/v1/network/blacklist", post(network::blacklist_add))
        .route(
            "/api/v1/network/blacklist/:addr",
            axum::routing::delete(network::blacklist_remove),
        )
        // mining controls
        .route("/api/v1/mining/candidate", get(mining::candidate))
        .route("/api/v1/mining/solution", post(mining::solution))
        .route("/api/v1/mining/reward-address", get(mining::reward_address))
        .route("/api/v1/mining/reward-pubkey", get(mining::reward_pubkey))
        .route(
            "/api/v1/mining/candidate-with-txs",
            post(mining::candidate_with_txs),
        )
        // voting operator writes/reads
        .route(
            "/api/v1/voting/operator-votes",
            get(voting::operator_votes_get).post(voting::operator_votes_set),
        )
        .route_layer(axum::middleware::from_fn_with_state(
            auth.state(Tier::Operator),
            require_tier,
        ));

    // ----- T2: admin (api_key + loopback-preferred) -----
    //
    // `POST /api/v1/node/shutdown` is deliberately NOT mounted here: it already
    // exists at that exact path on the frozen compat admin block
    // (`server.rs`, `require_api_key`-gated), and its 404/202/403 mount-matrix is
    // pinned by `tests/openapi_native_runtime_mount.rs`. Re-mounting it would be
    // a route collision, and relocating it to this stricter T2 (fail-closed +
    // loopback-preferred) gate would change that pinned behavior. That hardening
    // is a separately-reviewable behavior change, deferred out of this additive
    // group. `config` PATCH (mutation) is the T2 control this group carries.
    let t2: Router<OperatorState> = Router::new()
        // config mutation is the more dangerous half of node/config → T2
        .route(
            "/api/v1/node/config",
            axum::routing::patch(node::config_patch),
        )
        .route_layer(axum::middleware::from_fn_with_state(
            auth.state(Tier::Admin),
            require_tier,
        ));

    t0.merge(t1).merge(t2).with_state(state)
}
