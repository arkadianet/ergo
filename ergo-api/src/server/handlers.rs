//! Native operator-API handlers for the `/api/v1/*` routes mounted by
//! the parent module's router builders: node identity/status/health,
//! chain views (tip, recent blocks, difficulty/miner/votes history),
//! peers, the operator event feed, the Prometheus `/metrics`
//! exposition, and the admin-gated shutdown / votes / peers-connect
//! writes.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};

use crate::compat::traits::NodeChainQuery;
use crate::traits::{NodeAdmin, NodeReadState, VotingControlError};
use crate::types::{
    ApiDifficultyPoint, ApiDifficultySeries, ApiHealth, ApiHost, ApiIdentity, ApiInfo,
    ApiMinerStat, ApiMinerStats, ApiPeer, ApiRecentBlock, ApiSetVotesRequest, ApiStatus,
    ApiSyncStatus, ApiTip, ApiVotes, ApiVotesHistory, HealthStatus,
};
use ergo_ser::address::{encode_p2pk_from_pubkey, NetworkPrefix};

#[utoipa::path(
    get,
    path = "/api/v1/difficulty/history",
    tag = "chain",
    params(
        ("blocks" = Option<u32>, Query,
         description = "Most-recent blocks to return, ascending by height. \
Defaults to 720 (~one day at 120s blocks); clamped to [2, 16384]."),
    ),
    responses(
        (status = 200,
         description = "Per-block network difficulty across the recent chain, \
oldest first. Conditional: mounted only when the node is wired with a chain \
reader (the same handle the Scala-compat routes use).",
         body = ApiDifficultySeries, content_type = "application/json"),
    ),
)]
pub(super) async fn difficulty_history_handler(
    State(chain): State<Arc<dyn NodeChainQuery>>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let blocks = params
        .get("blocks")
        .and_then(|raw| raw.parse::<u32>().ok())
        .unwrap_or(720)
        .clamp(2, 16_384);
    let points = chain
        .last_headers(blocks)
        .into_iter()
        .map(|h| ApiDifficultyPoint {
            height: h.height,
            timestamp_unix_ms: h.timestamp,
            difficulty: h.difficulty,
        })
        .collect();
    Json(ApiDifficultySeries { points }).into_response()
}

#[utoipa::path(
    get,
    path = "/api/v1/mining/minerStats",
    tag = "chain",
    params(
        ("window" = Option<u32>, Query,
         description = "Most-recent headers to fold, by miner pk. \
Defaults to 720 (~one day at 120s blocks); clamped to [1, 16384]."),
    ),
    responses(
        (status = 200,
         description = "Blocks-per-miner over the recent chain, sorted by \
count descending, each with the P2PK address derived from the miner pk. \
Conditional: mounted only when the node is wired with a chain reader.",
         body = ApiMinerStats, content_type = "application/json"),
    ),
)]
pub(super) async fn miner_stats_handler(
    State((chain, network)): State<(Arc<dyn NodeChainQuery>, NetworkPrefix)>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let window = params
        .get("window")
        .and_then(|raw| raw.parse::<u32>().ok())
        .unwrap_or(720)
        .clamp(1, 16_384);
    let headers = chain.last_headers(window);
    let blocks = headers.len() as u32;
    let tip_height = headers.last().map(|h| h.height).unwrap_or(0);
    // Fold by pk hex: (count, last_height). Headers arrive ascending, so
    // a plain max keeps the latest height per miner.
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
                .and_then(|b| encode_p2pk_from_pubkey(network, &b).ok());
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

#[utoipa::path(
    get,
    path = "/api/v1/votes/history",
    tag = "node",
    responses(
        (status = 200,
         description = "Protocol-parameter change timeline (epoch boundaries where a \
parameter changed, oldest first). Conditional: mounted only when the node is wired with \
a chain reader (the same handle the Scala-compat routes use).",
         body = ApiVotesHistory, content_type = "application/json"),
    ),
)]
pub(super) async fn votes_history_handler(
    State(chain): State<Arc<dyn NodeChainQuery>>,
) -> Response {
    Json(chain.votes_history()).into_response()
}

#[utoipa::path(
    get,
    path = "/api/v1/blocks/recent",
    tag = "chain",
    description = "Most-recent full blocks for the dashboard, newest first. \
Reflects the *committed* full-block chain: it reads durably-stored section \
bytes, whereas `/api/v1/tip` reads the in-memory tip. During the async-persist \
window this list may therefore trail `/tip` by a block or two — it never \
advertises a block whose sections are not yet committed. Self-heals as the \
sections commit.",
    params(
        ("n" = Option<u32>, Query, minimum = 1, maximum = 32,
         description = "Number of most-recent full blocks, newest first. \
Defaults to 10. Out-of-range values are clamped to [1, 32] (the \
snapshot-precomputed tail), not rejected."),
    ),
    responses(
        (status = 200, description = "Most-recent full blocks, newest first",
         body = Vec<ApiRecentBlock>, content_type = "application/json"),
    ),
)]
pub(super) async fn recent_blocks_handler(
    State(read): State<Arc<dyn NodeReadState>>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Response {
    // Parse as `i64` so an out-of-range numeric value (e.g. `?n=-1` or
    // `?n=999`) clamps to the [1, 32] bound rather than silently falling
    // back to the default — only a non-numeric value uses the default.
    let n = params
        .get("n")
        .and_then(|raw| raw.parse::<i64>().ok())
        .map(|v| v.clamp(1, 32) as u32)
        .unwrap_or(10);
    Json(read.recent_blocks(n)).into_response()
}

#[utoipa::path(
    get,
    path = "/api/v1/events",
    tag = "node",
    description = "Operator event feed, oldest-first: block applies, reorgs, peer \
connects/disconnects, extra-index status transitions. Backed by a bounded node-side \
ring (512 events) whose FULL retained tail is projected into the lock-free snapshot, \
so this read never touches live node state and a cold poll returns up to 512 events. \
`seq` is monotonic; a gap between polls means the ring evicted entries in between — \
eviction is the ONLY gap source. Reorg detection is approximate: derived from the \
committed recent-block tail (a replaced block within the last 32 heights), so a reorg \
deeper than that tail surfaces as plain `blockApplied` events only.",
    params(
        ("since" = Option<u64>, Query,
         description = "Return only events with `seq` strictly greater than this. \
Poll with the previous response's `latestSeq` to receive only what is new. \
Omitted or non-numeric = the full retained tail."),
    ),
    responses(
        (status = 200, description = "Retained event tail (filtered by `since`), oldest first",
         body = crate::types::ApiNodeEvents, content_type = "application/json"),
    ),
)]
pub(super) async fn events_handler(
    State(read): State<Arc<dyn NodeReadState>>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let since = params
        .get("since")
        .and_then(|raw| raw.parse::<u64>().ok())
        .unwrap_or(0);
    let mut feed = read.events();
    if since > 0 {
        feed.events.retain(|e| e.seq > since);
    }
    Json(feed).into_response()
}

#[utoipa::path(
    get,
    path = "/api/v1/info",
    tag = "node",
    responses(
        (status = 200, description = "Static node identity snapshot",
         body = ApiInfo, content_type = "application/json"),
    ),
)]
pub(super) async fn info_handler(State(read): State<Arc<dyn NodeReadState>>) -> Response {
    Json(read.info()).into_response()
}

#[utoipa::path(
    get,
    path = "/api/v1/identity",
    tag = "node",
    responses(
        (status = 200, description = "Node mode and protocol-visible flags",
         body = ApiIdentity, content_type = "application/json"),
    ),
)]
pub(super) async fn identity_handler(State(read): State<Arc<dyn NodeReadState>>) -> Response {
    Json(read.identity()).into_response()
}

#[utoipa::path(
    get,
    path = "/api/v1/host",
    tag = "node",
    responses(
        (status = 200, description = "Host-process metrics (memory, disk, CPU, network)",
         body = ApiHost, content_type = "application/json"),
    ),
)]
pub(super) async fn host_handler(State(read): State<Arc<dyn NodeReadState>>) -> Response {
    Json(read.host()).into_response()
}

#[utoipa::path(
    get,
    path = "/api/v1/votes",
    tag = "node",
    responses(
        (status = 200, description = "Votable protocol parameters + bounds and the operator's configured votes",
         body = ApiVotes, content_type = "application/json"),
    ),
)]
pub(super) async fn votes_handler(State(read): State<Arc<dyn NodeReadState>>) -> Response {
    Json(read.votes()).into_response()
}

#[utoipa::path(
    post,
    path = "/api/v1/votes",
    tag = "admin",
    request_body = ApiSetVotesRequest,
    security(("ApiKeyAuth" = [])),
    responses(
        (status = 204, description = "Voting targets replaced"),
        (status = 400, description = "A target named a non-votable parameter, or fell \
outside the parameter's allowable [min, max] voting range"),
        (status = 403, description = "Missing or invalid api_key"),
        (status = 409, description = "Node is not mining"),
    ),
)]
pub(super) async fn set_votes_handler(
    State(admin): State<Arc<dyn NodeAdmin>>,
    body: axum::body::Bytes,
) -> Response {
    let req: crate::types::ApiSetVotesRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return crate::utils::bad_request(format!("invalid request body: {e}")),
    };
    let targets: Vec<(u8, i64)> = req
        .votes
        .iter()
        .map(|v| (v.parameter_id, v.target))
        .collect();
    match admin.set_voting_targets(targets) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(VotingControlError::NotVotable { parameter_id }) => crate::utils::bad_request(format!(
            "parameter id {parameter_id} is not operator-votable (votable ids: 1..=8, 9)"
        )),
        Err(VotingControlError::OutOfRange {
            parameter_id,
            target,
            min,
            max,
        }) => crate::utils::bad_request(format!(
            "target {target} for parameter id {parameter_id} is outside its allowable \
             voting range [{min}, {max}]"
        )),
        Err(VotingControlError::MiningDisabled) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": 409,
                "reason": "mining.disabled",
                "detail": "voting targets can only be set on a mining node",
            })),
        )
            .into_response(),
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/status",
    tag = "node",
    responses(
        (status = 200, description = "Collapsed sync + tip + peer-count dashboard view",
         body = ApiStatus, content_type = "application/json"),
    ),
)]
pub(super) async fn status_handler(State(read): State<Arc<dyn NodeReadState>>) -> Response {
    Json(read.status()).into_response()
}

#[utoipa::path(
    get,
    path = "/api/v1/tip",
    tag = "chain",
    responses(
        (status = 200, description = "Best-header and best-full-block tip pointers",
         body = ApiTip, content_type = "application/json"),
    ),
)]
pub(super) async fn tip_handler(State(read): State<Arc<dyn NodeReadState>>) -> Response {
    Json(read.tip()).into_response()
}

#[utoipa::path(
    get,
    path = "/api/v1/sync",
    tag = "chain",
    responses(
        (status = 200, description = "Sync-pipeline state",
         body = ApiSyncStatus, content_type = "application/json"),
    ),
)]
pub(super) async fn sync_handler(State(read): State<Arc<dyn NodeReadState>>) -> Response {
    Json(read.sync()).into_response()
}

#[utoipa::path(
    get,
    path = "/api/v1/peers",
    tag = "peers",
    responses(
        (status = 200, description = "Connected and known peer view",
         body = Vec<ApiPeer>, content_type = "application/json"),
    ),
)]
pub(super) async fn peers_handler(State(read): State<Arc<dyn NodeReadState>>) -> Response {
    Json(read.peers()).into_response()
}

/// Prometheus-text exposition derived from the same `NodeReadState`
/// DTOs the operator API already serves. No new node state — every
/// metric is a projection of `status()` + `mempool_summary()` +
/// `info()`. Always at `/metrics` on the operator API; bind the
/// API to loopback (or behind a reverse proxy with auth) before
/// scraping over a network.
pub(super) async fn metrics_handler(State(read): State<Arc<dyn NodeReadState>>) -> Response {
    let info = read.info();
    let status = read.status();
    let mempool = read.mempool_summary();

    let body = format!(
        "\
# HELP ergo_node_uptime_seconds Seconds since node start.
# TYPE ergo_node_uptime_seconds gauge
ergo_node_uptime_seconds {uptime}
# HELP ergo_node_best_header_height Best header chain height.
# TYPE ergo_node_best_header_height gauge
ergo_node_best_header_height {bh}
# HELP ergo_node_best_full_block_height Best full-block chain height.
# TYPE ergo_node_best_full_block_height gauge
ergo_node_best_full_block_height {bfb}
# HELP ergo_node_sync_gap Headers ahead of full blocks (catch-up gap).
# TYPE ergo_node_sync_gap gauge
ergo_node_sync_gap {gap}
# HELP ergo_node_peer_count Connected peers (handshaked).
# TYPE ergo_node_peer_count gauge
ergo_node_peer_count {peers}
# HELP ergo_node_mempool_size Pooled transactions.
# TYPE ergo_node_mempool_size gauge
ergo_node_mempool_size {pool_size}
# HELP ergo_node_mempool_bytes Pooled-transaction byte total.
# TYPE ergo_node_mempool_bytes gauge
ergo_node_mempool_bytes {pool_bytes}
# HELP ergo_node_mempool_capacity_count Configured pool capacity (count).
# TYPE ergo_node_mempool_capacity_count gauge
ergo_node_mempool_capacity_count {cap_count}
# HELP ergo_node_mempool_capacity_bytes Configured pool capacity (bytes).
# TYPE ergo_node_mempool_capacity_bytes gauge
ergo_node_mempool_capacity_bytes {cap_bytes}
# HELP ergo_node_mempool_revalidation_pending Demoted txs pending revalidation.
# TYPE ergo_node_mempool_revalidation_pending gauge
ergo_node_mempool_revalidation_pending {revalidating}
# HELP ergo_node_snapshot_age_ms Snapshot age — how stale the read view is.
# TYPE ergo_node_snapshot_age_ms gauge
ergo_node_snapshot_age_ms {snap_age}
# HELP ergo_node_block_apply_errors_total Block-apply rejections since node start.
# TYPE ergo_node_block_apply_errors_total counter
ergo_node_block_apply_errors_total {apply_errs}
# HELP ergo_node_sync_wedged Terminal deep-fork wedge (1 = resync required).
# TYPE ergo_node_sync_wedged gauge
ergo_node_sync_wedged {wedged}
# HELP ergo_node_mempool_tx_requested_total Unconfirmed-tx ids requested from peers since node start.
# TYPE ergo_node_mempool_tx_requested_total counter
ergo_node_mempool_tx_requested_total {tx_requested}
# HELP ergo_node_mempool_peer_tx_admitted_total Peer-sourced txs admitted to the mempool since node start.
# TYPE ergo_node_mempool_peer_tx_admitted_total counter
ergo_node_mempool_peer_tx_admitted_total {peer_tx_admitted}
# HELP ergo_node_mempool_peer_tx_rejected_total Peer-sourced txs rejected by admission since node start.
# TYPE ergo_node_mempool_peer_tx_rejected_total counter
ergo_node_mempool_peer_tx_rejected_total {peer_tx_rejected}
# HELP ergo_node_reorg_total Tip-replacement reorgs detected since node start.
# TYPE ergo_node_reorg_total counter
ergo_node_reorg_total {reorgs_total}
# HELP ergo_node_last_reorg_depth Depth of the most recent retained reorg (0 if none).
# TYPE ergo_node_last_reorg_depth gauge
ergo_node_last_reorg_depth {last_reorg_depth}
# HELP ergo_node_last_reorg_age_ms Age of the most recent retained reorg in ms (-1 if none).
# TYPE ergo_node_last_reorg_age_ms gauge
ergo_node_last_reorg_age_ms {last_reorg_age_ms}
# HELP ergo_node_apply_in_progress 1 while a full-block process_block is running on the action loop.
# TYPE ergo_node_apply_in_progress gauge
ergo_node_apply_in_progress {apply_in_progress}
# HELP ergo_node_last_apply_duration_ms Wall ms of the last finished full-block apply attempt.
# TYPE ergo_node_last_apply_duration_ms gauge
ergo_node_last_apply_duration_ms {last_apply_duration_ms}
# HELP ergo_node_last_applied_height Height of the last successful full-block apply (0 if none).
# TYPE ergo_node_last_applied_height gauge
ergo_node_last_applied_height {last_applied_height}
# HELP ergo_node_last_apply_age_ms Age of the last finished apply attempt in ms (-1 if none).
# TYPE ergo_node_last_apply_age_ms gauge
ergo_node_last_apply_age_ms {last_apply_age_ms}
",
        uptime = info.uptime_seconds,
        bh = status.best_header_height,
        bfb = status.best_full_block_height,
        gap = status.headers_ahead_of_full_blocks,
        peers = status.peer_count,
        pool_size = mempool.size,
        pool_bytes = mempool.total_bytes,
        cap_count = mempool.capacity_count,
        cap_bytes = mempool.capacity_bytes,
        revalidating = mempool.revalidation_pending,
        snap_age = status.snapshot_age_ms,
        apply_errs = status.block_apply_errors_total,
        wedged = u8::from(status.sync_wedged.is_some()),
        tx_requested = status.mempool_tx_requested_total,
        peer_tx_admitted = status.mempool_peer_tx_admitted_total,
        peer_tx_rejected = status.mempool_peer_tx_rejected_total,
        reorgs_total = status.reorgs_total,
        last_reorg_depth = status.last_reorg_depth.unwrap_or(0),
        last_reorg_age_ms = {
            // Approximate "now" as snapshot build time: status.snapshot_age_ms
            // is how stale the snapshot is relative to wall clock at read.
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            status
                .last_reorg_unix_ms
                .map(|t| now_ms.saturating_sub(t) as i64)
                .unwrap_or(-1)
        },
        apply_in_progress = if status.apply_in_progress { 1 } else { 0 },
        last_apply_duration_ms = status.last_apply_duration_ms,
        last_applied_height = status.last_applied_height,
        last_apply_age_ms = status
            .last_apply_age_ms
            .map(|a| a as i64)
            .unwrap_or(-1),
    );

    // Shadow-validation series — emitted only when the mode is enabled, so
    // "absent" and "quiet" stay distinguishable in Prometheus.
    let body = match &status.shadow {
        Some(sh) => format!(
            "{body}\
# HELP ergo_node_shadow_divergence_total Confirmed shadow divergences vs the reference node since start.
# TYPE ergo_node_shadow_divergence_total counter
ergo_node_shadow_divergence_total {dv}
# HELP ergo_node_shadow_last_compared_height Highest height a shadow compare completed at.
# TYPE ergo_node_shadow_last_compared_height gauge
ergo_node_shadow_last_compared_height {lc}
# HELP ergo_node_shadow_reference_unreachable 1 when the reference node failed the most recent compare tick.
# TYPE ergo_node_shadow_reference_unreachable gauge
ergo_node_shadow_reference_unreachable {ur}
# HELP ergo_node_shadow_diverged 1 while a confirmed divergence is ACTIVE (latched).
# TYPE ergo_node_shadow_diverged gauge
ergo_node_shadow_diverged {ad}
",
            dv = sh.divergence_total,
            lc = sh.last_compared_height,
            ur = u8::from(!sh.reference_reachable),
            ad = u8::from(sh.diverged.is_some()),
        ),
        None => body,
    };

    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
        .into_response()
}

/// `POST /node/shutdown` (Scala-compat) and `POST /api/v1/node/shutdown`.
/// Fires the action loop's shutdown signal and returns 202 immediately.
/// The actual drain (UTXO commit, redb close) happens asynchronously in
/// the action loop's existing shutdown path. Operators that need to
/// confirm completion should poll `GET /api/v1/health` until the
/// connection refuses.
#[utoipa::path(
    post,
    path = "/api/v1/node/shutdown",
    tag = "admin",
    security(("ApiKeyAuth" = [])),
    responses(
        (status = 202,
         description = "Shutdown accepted; body is the literal text `shutdown_requested`. Drain proceeds asynchronously.",
         body = String, content_type = "text/plain"),
        (status = 403, description = "Missing or invalid api_key (when API security is configured)"),
    ),
)]
pub(super) async fn shutdown_handler(
    State(admin): State<Arc<dyn NodeAdmin>>,
) -> (StatusCode, &'static str) {
    admin.request_shutdown();
    (StatusCode::ACCEPTED, "shutdown_requested")
}

/// `POST /peers/connect` — Scala `ErgoPeersApiRoute.connect`: the body is
/// a JSON string `"host:port"`; a parse failure is 400; success fires the
/// dial at the node and answers 200 (the JSON string `"OK"`, Scala's
/// `ApiResponse.OK`) without waiting for the dial's outcome. Hostnames
/// resolve asynchronously.
///
/// Deliberate divergences (all saner-direction, behind the api key):
/// Scala 500s on an unresolvable hostname (`InetAddress.getByName`
/// throws) and on regex-valid ports > 65535 — both are 400 here; Scala's
/// unanchored regex mis-truncates hyphenated hostnames and accepts
/// junk-wrapped input — rejected here; IPv6 literals work here, 400 in
/// Scala.
pub(super) async fn peers_connect_handler(
    State(admin): State<Arc<dyn NodeAdmin>>,
    body: axum::body::Bytes,
) -> Response {
    let addr_str = match crate::utils::parse_json_string_body(&body) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    // Fast path: literal ip:port. Fallback: async DNS for hostnames.
    let addr = match addr_str.parse::<SocketAddr>() {
        Ok(a) => a,
        Err(_) => match tokio::net::lookup_host(addr_str.as_str()).await {
            Ok(mut iter) => match iter.next() {
                Some(a) => a,
                None => return crate::utils::bad_request("address resolved to nothing"),
            },
            Err(_) => return crate::utils::bad_request("invalid host:port"),
        },
    };
    admin.connect_to_peer(addr);
    (StatusCode::OK, Json(serde_json::json!("OK"))).into_response()
}

#[utoipa::path(
    get,
    path = "/api/v1/health",
    tag = "health",
    responses(
        (status = 200, description = "Node is healthy (synced and connected)",
         body = ApiHealth, content_type = "application/json"),
        (status = 503, description = "Node is stalled, disconnected, or rejecting blocks",
         body = ApiHealth, content_type = "application/json"),
    ),
)]
pub(super) async fn health_handler(State(read): State<Arc<dyn NodeReadState>>) -> Response {
    let h = read.health();
    let status = match h.status {
        HealthStatus::Ok => StatusCode::OK,
        // `Rejecting` (an outstanding block-apply rejection) and `Wedged`
        // (terminal deep-fork wedge) are page-worthy not-healthy conditions,
        // same 503 as Stalled/Disconnected.
        HealthStatus::Stalled
        | HealthStatus::Disconnected
        | HealthStatus::Rejecting
        | HealthStatus::Wedged => StatusCode::SERVICE_UNAVAILABLE,
    };
    let body = serde_json::to_vec(&h).unwrap_or_else(|_| b"{}".to_vec());
    (status, [(header::CONTENT_TYPE, "application/json")], body).into_response()
}
