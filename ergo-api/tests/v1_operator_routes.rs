//! Route-level integration tests for the operator/control group
//! (`node/*`, `network/*`, `mining/*`, `voting/*` — `v1-api-design.md`
//! §3.1–§3.4). Convention-lock:
//! * a T0 read shape per subgroup (envelope + snake_case reshape);
//! * a T1 endpoint rejects with no/invalid api_key (401) and accepts with a
//!   valid key;
//! * the T2 `node/shutdown` loopback-preference (hard-deny remote vs loopback);
//! * honest `*_unavailable` / `mining_disabled` where a capability isn't wired.

use std::sync::Arc;

use async_trait::async_trait;
use axum::body::{to_bytes, Body};
use axum::extract::ConnectInfo;
use axum::http::{Method, Request, StatusCode};
use axum::response::Response;
use axum::Router;
use ergo_api::auth::{ApiSecurity, API_KEY_HEADER};
use ergo_api::compat::types::{
    Parameters, ScalaBlacklistedPeers, ScalaInfo, ScalaSyncInfoEntry, ScalaTrackInfo,
};
use ergo_api::compat::NodeChainQuery;
use ergo_api::mining::{MiningApiError, NodeMining};
use ergo_api::traits::{NodeAdmin, NodeReadState, VotingControlError};
use ergo_api::types::{
    ApiConfiguredVote, ApiFullBlockRef, ApiHeaderRef, ApiHealth, ApiIdentity, ApiInfo,
    ApiMempoolSummary, ApiMempoolTransaction, ApiMempoolTransactions, ApiPeer, ApiPeerDirection,
    ApiPeerState, ApiStatus, ApiSyncStatus, ApiTip, ApiVotableParam, ApiVotes, ApiWeightFunction,
    HealthStatus, SyncStateLabel,
};
use ergo_api::v1::{operator_router, Governor, OperatorState, V1AuthConfig};
use ergo_rest_json::mining::{AutolykosSolutionJson, WorkMessageJson};
use ergo_ser::address::NetworkPrefix;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

// ----- helpers / stubs -----

struct StubRead;

impl NodeReadState for StubRead {
    fn info(&self) -> ApiInfo {
        ApiInfo {
            agent_name: "ergo-rust".into(),
            node_name: "stub".into(),
            network: "mainnet".into(),
            version: "0.9.1".into(),
            started_at_unix_ms: 0,
            uptime_seconds: 42,
            target_block_interval_ms: 120_000,
        }
    }
    fn status(&self) -> ApiStatus {
        ApiStatus {
            sync_state: SyncStateLabel::AtTip,
            peer_count: 2,
            best_header_height: 100,
            best_full_block_height: 100,
            headers_ahead_of_full_blocks: 0,
            mempool_size: 0,
            snapshot_age_ms: 0,
            bootstrap: None,
            last_block_apply_error: None,
            block_apply_errors_total: 0,
            mempool_tx_requested_total: 0,
            mempool_peer_tx_admitted_total: 0,
            mempool_peer_tx_rejected_total: 0,
        }
    }
    fn tip(&self) -> ApiTip {
        ApiTip {
            best_header: ApiHeaderRef {
                height: 100,
                header_id: "aa".repeat(32),
                parent_id: "bb".repeat(32),
                timestamp_unix_ms: 0,
                n_bits: 0,
                difficulty: "1".into(),
            },
            best_full_block: ApiFullBlockRef {
                height: 100,
                header_id: "aa".repeat(32),
                parent_id: "bb".repeat(32),
                timestamp_unix_ms: 0,
                state_root_avl: String::new(),
                n_bits: 0,
                difficulty: "1".into(),
            },
            headers_ahead_of_full_blocks: 0,
        }
    }
    fn sync(&self) -> ApiSyncStatus {
        ApiSyncStatus {
            headers_chain_synced: true,
            best_header_height: 100,
            best_full_block_height: 100,
            gap: 0,
            download_window: 0,
            pending_blocks: 0,
            recovery_done: true,
        }
    }
    fn peers(&self) -> Vec<ApiPeer> {
        vec![
            peer("1.2.3.4:9030", ApiPeerState::Active),
            peer("5.6.7.8:9030", ApiPeerState::Disconnected),
        ]
    }
    fn mempool_summary(&self) -> ApiMempoolSummary {
        ApiMempoolSummary {
            size: 0,
            total_bytes: 0,
            capacity_count: 0,
            capacity_bytes: 0,
            revalidation_pending: 0,
        }
    }
    fn mempool_transactions(&self) -> ApiMempoolTransactions {
        ApiMempoolTransactions {
            transactions: Vec::new(),
            weight_function: ApiWeightFunction::Cost,
        }
    }
    fn mempool_transaction(&self, _: &str) -> Option<ApiMempoolTransaction> {
        None
    }
    fn health(&self) -> ApiHealth {
        ApiHealth {
            status: HealthStatus::Ok,
            behind: 0,
            last_progress_age_ms: 0,
            peer_count: 2,
        }
    }
    fn identity(&self) -> ApiIdentity {
        ApiIdentity {
            mining: true,
            ..Default::default()
        }
    }
    fn votes(&self) -> ApiVotes {
        ApiVotes {
            block_height: 100,
            block_version: 3,
            epoch_start_height: 96,
            votable_parameters: vec![ApiVotableParam {
                id: 2,
                name: "storage_fee_factor".into(),
                description: "storage rent".into(),
                current: 1_250_000,
                step: 25_000,
                min: 0,
                max: 2_500_000,
            }],
            configured_votes: vec![ApiConfiguredVote {
                parameter_id: 2,
                name: "storage_fee_factor".into(),
                target: 1_300_000,
            }],
        }
    }
}

fn peer(addr: &str, state: ApiPeerState) -> ApiPeer {
    ApiPeer {
        addr: addr.into(),
        direction: ApiPeerDirection::Outbound,
        state,
        score: 0,
        agent: None,
        node_name: None,
        version: None,
        sync_version: String::new(),
        connected_seconds: 0,
        last_seen_seconds: 0,
        bytes_in: None,
        bytes_out: None,
        peer_height: None,
        rest_api_url: None,
        declared_address: None,
    }
}

struct StubChain;

impl NodeChainQuery for StubChain {
    fn header_ids_at_height(&self, _: u32) -> Vec<String> {
        Vec::new()
    }
    fn full_block_by_id(&self, _: &str) -> Option<ergo_rest_json::types::ScalaFullBlock> {
        None
    }
    fn info(&self) -> ScalaInfo {
        ScalaInfo {
            last_mempool_update_time: 0,
            current_time: 0,
            network: "mainnet".into(),
            name: "stub".into(),
            state_type: "utxo".into(),
            difficulty: 0,
            best_full_header_id: String::new(),
            best_header_id: String::new(),
            peers_count: 0,
            unconfirmed_count: 0,
            app_version: "0.1.0".into(),
            eip37_supported: true,
            state_root: String::new(),
            genesis_block_id: String::new(),
            rest_api_url: None,
            previous_full_header_id: String::new(),
            full_height: 0,
            headers_height: 0,
            state_version: String::new(),
            full_blocks_score: 0,
            max_peer_height: 0,
            launch_time: 0,
            is_explorer: false,
            last_seen_message_time: 0,
            eip27_supported: true,
            headers_score: 0,
            parameters: Parameters {
                output_cost: 0,
                token_access_cost: 0,
                max_block_cost: 0,
                height: 0,
                max_block_size: 0,
                data_input_cost: 0,
                block_version: 0,
                input_cost: 0,
                storage_fee_factor: 0,
                subblocks_per_block: 0,
                min_value_per_byte: 0,
            },
            is_mining: false,
        }
    }
    fn peers_blacklisted(&self) -> ScalaBlacklistedPeers {
        ScalaBlacklistedPeers {
            addresses: vec!["somehost/1.2.3.4:9030".into(), "/5.6.7.8:9030".into()],
        }
    }
    fn peers_sync_info(&self) -> Vec<ScalaSyncInfoEntry> {
        vec![ScalaSyncInfoEntry {
            address: "1.2.3.4:9030".into(),
            height: 100,
            status: "Younger".into(),
        }]
    }
    fn peers_track_info(&self) -> ScalaTrackInfo {
        ScalaTrackInfo {
            num_requested: 5,
            num_received: 3,
            num_failed: 1,
        }
    }
}

#[derive(Default)]
struct SpyAdmin {
    voting_result: Option<VotingControlError>,
}

impl NodeAdmin for SpyAdmin {
    fn request_shutdown(&self) {}
    fn set_voting_targets(&self, _targets: Vec<(u8, i64)>) -> Result<(), VotingControlError> {
        match &self.voting_result {
            None => Ok(()),
            Some(e) => Err(e.clone()),
        }
    }
}

struct StubMining;

fn fixed_work() -> WorkMessageJson {
    serde_json::from_value(serde_json::json!({
        "msg": "ab".repeat(32),
        "b": "1",
        "h": 100,
        "pk": "02".repeat(33),
        "template_seq": 7,
        "clean_jobs": true,
    }))
    .expect("valid WorkMessageJson")
}

#[async_trait]
impl NodeMining for StubMining {
    async fn candidate(
        &self,
        _longpoll: Option<String>,
    ) -> Result<Option<WorkMessageJson>, MiningApiError> {
        Ok(Some(fixed_work()))
    }
    async fn submit_solution(&self, _: AutolykosSolutionJson) -> Result<(), MiningApiError> {
        Ok(())
    }
    async fn reward_address(&self) -> Result<String, MiningApiError> {
        Ok("9hAddr".into())
    }
    async fn reward_pubkey(&self) -> Result<String, MiningApiError> {
        Ok("02".repeat(33))
    }
}

fn security() -> Arc<ApiSecurity> {
    Arc::new(ApiSecurity::new(ApiSecurity::hash_key(b"operator-secret")).unwrap())
}

/// Full-featured app: chain + admin + mining all wired.
fn app_full(auth: Arc<V1AuthConfig>) -> Router {
    let state = OperatorState {
        read: Arc::new(StubRead),
        chain: Some(Arc::new(StubChain)),
        admin: Some(Arc::new(SpyAdmin::default())),
        mining: Some(Arc::new(StubMining)),
        network: NetworkPrefix::Mainnet,
    };
    let gov = Governor::new(Default::default()).expect("valid governor config");
    operator_router(state, gov, auth)
}

/// App with a chosen admin (for the voting-error + shutdown-spy paths).
fn app_with_admin(admin: Arc<SpyAdmin>, auth: Arc<V1AuthConfig>) -> Router {
    let state = OperatorState {
        read: Arc::new(StubRead),
        chain: Some(Arc::new(StubChain)),
        admin: Some(admin),
        mining: Some(Arc::new(StubMining)),
        network: NetworkPrefix::Mainnet,
    };
    let gov = Governor::new(Default::default()).expect("valid governor config");
    operator_router(state, gov, auth)
}

/// App with mining absent (honest `mining_disabled`).
fn app_no_mining(auth: Arc<V1AuthConfig>) -> Router {
    let state = OperatorState {
        read: Arc::new(StubRead),
        chain: Some(Arc::new(StubChain)),
        admin: Some(Arc::new(SpyAdmin::default())),
        mining: None,
        network: NetworkPrefix::Mainnet,
    };
    let gov = Governor::new(Default::default()).expect("valid governor config");
    operator_router(state, gov, auth)
}

fn default_auth() -> Arc<V1AuthConfig> {
    V1AuthConfig::new(Some(security())).into_shared()
}

fn req(
    method: Method,
    uri: &str,
    key: Option<&str>,
    peer_ip: Option<IpAddr>,
    body: Option<Body>,
) -> Request<Body> {
    let mut b = Request::builder().method(method).uri(uri);
    if let Some(k) = key {
        b = b.header(API_KEY_HEADER, k);
    }
    let mut r = b.body(body.unwrap_or_else(Body::empty)).unwrap();
    if let Some(ip) = peer_ip {
        r.extensions_mut()
            .insert(ConnectInfo(SocketAddr::new(ip, 40000)));
    }
    r
}

async fn send(app: Router, r: Request<Body>) -> (StatusCode, serde_json::Value) {
    use tower::ServiceExt;
    let resp: Response = app.oneshot(r).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let v = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    };
    (status, v)
}

const REMOTE: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
const LOCAL: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

// ----- T0 read shapes (one per subgroup) -----

#[tokio::test]
async fn node_info_t0_bare_snake_case() {
    let (status, v) = send(
        app_full(default_auth()),
        req(Method::GET, "/api/v1/node/info", None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["agent_name"], "ergo-rust");
    assert_eq!(v["version"], "0.9.1");
}

#[tokio::test]
async fn node_version_t0_composed() {
    let (status, v) = send(
        app_full(default_auth()),
        req(Method::GET, "/api/v1/node/version", None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["software_version"], "0.9.1");
    assert_eq!(v["api_versions"][0], "v1");
    assert_eq!(v["activated_protocol_version"], 3);
}

#[tokio::test]
async fn node_health_t0_dual_status_ok() {
    let (status, v) = send(
        app_full(default_auth()),
        req(Method::GET, "/api/v1/node/health", None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["status"], "ok");
}

#[tokio::test]
async fn network_peers_t0_collection_envelope() {
    let (status, v) = send(
        app_full(default_auth()),
        req(Method::GET, "/api/v1/network/peers", None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["items"].as_array().unwrap().len(), 2);
    assert_eq!(v["page"]["has_more"], false);
    assert!(v["page"]["next_cursor"].is_null());
}

#[tokio::test]
async fn network_connected_t0_filters_active_only() {
    let (status, v) = send(
        app_full(default_auth()),
        req(Method::GET, "/api/v1/network/connected", None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let items = v["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["state"], "active");
}

#[tokio::test]
async fn network_blacklisted_t0_cleans_java_addr_form() {
    let (status, v) = send(
        app_full(default_auth()),
        req(Method::GET, "/api/v1/network/blacklisted", None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let items = v["items"].as_array().unwrap();
    assert_eq!(items[0]["addr"], "1.2.3.4:9030");
    assert_eq!(items[1]["addr"], "5.6.7.8:9030");
}

#[tokio::test]
async fn network_sync_info_t0_reshape() {
    let (status, v) = send(
        app_full(default_auth()),
        req(Method::GET, "/api/v1/network/sync-info", None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["items"][0]["peer_height"], 100);
    assert_eq!(v["items"][0]["status"], "younger");
}

#[tokio::test]
async fn network_track_info_t0_bare_object() {
    let (status, v) = send(
        app_full(default_auth()),
        req(Method::GET, "/api/v1/network/track-info", None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["num_requested"], 5);
    assert_eq!(v["num_received"], 3);
    assert_eq!(v["num_failed"], 1);
}

#[tokio::test]
async fn mining_miner_stats_t0_ok() {
    let (status, v) = send(
        app_full(default_auth()),
        req(Method::GET, "/api/v1/mining/miner-stats", None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(v["miners"].is_array());
    assert_eq!(v["window"], 720);
}

#[tokio::test]
async fn mining_status_t0_composed_always_200() {
    let (status, v) = send(
        app_full(default_auth()),
        req(Method::GET, "/api/v1/mining/status", None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["mining_enabled"], true);
    assert_eq!(v["synced"], true);
    assert_eq!(v["longpoll_supported"], true);
    assert!(v["last_template_msg"].is_null());
}

#[tokio::test]
async fn voting_votes_t0_drops_configured_votes() {
    let (status, v) = send(
        app_full(default_auth()),
        req(Method::GET, "/api/v1/voting/votes", None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["block_version"], 3);
    assert_eq!(v["votable_parameters"][0]["name"], "storage_fee_factor");
    assert!(
        v.get("configured_votes").is_none(),
        "operator-private votes must not leak on the public read"
    );
}

#[tokio::test]
async fn voting_history_t0_snake_case() {
    let (status, v) = send(
        app_full(default_auth()),
        req(Method::GET, "/api/v1/voting/history", None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(v["changes"].is_array());
}

// ----- T1 gate: reject no/invalid key, accept valid key -----

#[tokio::test]
async fn mining_candidate_t1_rejects_missing_key() {
    let (status, v) = send(
        app_full(default_auth()),
        req(
            Method::GET,
            "/api/v1/mining/candidate",
            None,
            Some(REMOTE),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(v["error"]["reason"], "unauthorized");
}

#[tokio::test]
async fn mining_candidate_t1_rejects_wrong_key() {
    let (status, _) = send(
        app_full(default_auth()),
        req(
            Method::GET,
            "/api/v1/mining/candidate",
            Some("wrong"),
            Some(REMOTE),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn mining_candidate_t1_accepts_valid_key() {
    let (status, v) = send(
        app_full(default_auth()),
        req(
            Method::GET,
            "/api/v1/mining/candidate",
            Some("operator-secret"),
            Some(REMOTE),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["msg"], "ab".repeat(32));
    assert_eq!(v["template_seq"], 7);
}

#[tokio::test]
async fn mining_reward_address_t1_fresh_snake_case_dto() {
    let (status, v) = send(
        app_full(default_auth()),
        req(
            Method::GET,
            "/api/v1/mining/reward-address",
            Some("operator-secret"),
            Some(REMOTE),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["reward_address"], "9hAddr");
}

#[tokio::test]
async fn voting_operator_votes_get_t1_gated_and_lists_configured() {
    // no key → 401
    let (status, _) = send(
        app_full(default_auth()),
        req(
            Method::GET,
            "/api/v1/voting/operator-votes",
            None,
            Some(REMOTE),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // valid key → the operator-private list
    let (status, v) = send(
        app_full(default_auth()),
        req(
            Method::GET,
            "/api/v1/voting/operator-votes",
            Some("operator-secret"),
            Some(REMOTE),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["items"][0]["parameter_id"], 2);
    assert_eq!(v["items"][0]["target"], 1_300_000);
}

#[tokio::test]
async fn voting_operator_votes_set_t1_replaces_returns_204() {
    let admin = Arc::new(SpyAdmin::default());
    let body =
        Body::from(serde_json::json!({"votes":[{"parameter_id":2,"target":1300000}]}).to_string());
    let (status, _) = send(
        app_with_admin(admin, default_auth()),
        req(
            Method::POST,
            "/api/v1/voting/operator-votes",
            Some("operator-secret"),
            Some(REMOTE),
            Some(body),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn voting_operator_votes_set_maps_mining_disabled_409() {
    let admin = Arc::new(SpyAdmin {
        voting_result: Some(VotingControlError::MiningDisabled),
    });
    let body = Body::from(serde_json::json!({"votes":[]}).to_string());
    let (status, v) = send(
        app_with_admin(admin, default_auth()),
        req(
            Method::POST,
            "/api/v1/voting/operator-votes",
            Some("operator-secret"),
            Some(REMOTE),
            Some(body),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(v["error"]["reason"], "mining_disabled");
}

#[tokio::test]
async fn network_connect_t1_accepts_valid_key_and_addr() {
    let body = Body::from(serde_json::json!("1.2.3.4:9030").to_string());
    let (status, v) = send(
        app_full(default_auth()),
        req(
            Method::POST,
            "/api/v1/network/connect",
            Some("operator-secret"),
            Some(REMOTE),
            Some(body),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v, serde_json::json!("OK"));
}

// ----- T2 loopback preference (node/config PATCH is this group's T2 control) -----
//
// `node/shutdown` (also T2) stays on the frozen compat mount; the operator
// group's own T2 gate is exercised here via `PATCH /api/v1/node/config`.

#[tokio::test]
async fn config_patch_t2_hard_deny_rejects_remote_even_with_valid_key() {
    let auth = V1AuthConfig::new(Some(security()))
        .with_admin_hard_deny(true)
        .into_shared();
    let (status, v) = send(
        app_full(auth),
        req(
            Method::PATCH,
            "/api/v1/node/config",
            Some("operator-secret"),
            Some(REMOTE),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(v["error"]["reason"], "sensitive_op_disabled");
}

#[tokio::test]
async fn config_patch_t2_hard_deny_allows_loopback_then_seam_deferred() {
    // Loopback passes the T2 gate; the handler is seam-deferred, so a passed
    // gate surfaces as the honest 503 route_unavailable — proving the gate let
    // the loopback caller through rather than blocking it like the remote one.
    let auth = V1AuthConfig::new(Some(security()))
        .with_admin_hard_deny(true)
        .into_shared();
    let (status, v) = send(
        app_full(auth),
        req(
            Method::PATCH,
            "/api/v1/node/config",
            Some("operator-secret"),
            Some(LOCAL),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(v["error"]["reason"], "route_unavailable");
}

#[tokio::test]
async fn config_patch_t2_rejects_missing_key() {
    let (status, _) = send(
        app_full(default_auth()),
        req(
            Method::PATCH,
            "/api/v1/node/config",
            None,
            Some(LOCAL),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ----- honest *_unavailable where a capability isn't wired -----

#[tokio::test]
async fn mining_candidate_mining_off_is_mining_disabled_not_404() {
    let (status, v) = send(
        app_no_mining(default_auth()),
        req(
            Method::GET,
            "/api/v1/mining/candidate",
            Some("operator-secret"),
            Some(REMOTE),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(v["error"]["reason"], "mining_disabled");
}

#[tokio::test]
async fn mining_candidate_with_txs_seam_deferred_route_unavailable() {
    let (status, v) = send(
        app_full(default_auth()),
        req(
            Method::POST,
            "/api/v1/mining/candidate-with-txs",
            Some("operator-secret"),
            Some(REMOTE),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(v["error"]["reason"], "route_unavailable");
}

#[tokio::test]
async fn network_blacklist_post_seam_deferred_route_unavailable() {
    let body = Body::from(serde_json::json!({"addr":"1.2.3.4:9030"}).to_string());
    let (status, v) = send(
        app_full(default_auth()),
        req(
            Method::POST,
            "/api/v1/network/blacklist",
            Some("operator-secret"),
            Some(REMOTE),
            Some(body),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(v["error"]["reason"], "route_unavailable");
}

#[tokio::test]
async fn node_config_get_t1_seam_deferred_route_unavailable() {
    let (status, v) = send(
        app_full(default_auth()),
        req(
            Method::GET,
            "/api/v1/node/config",
            Some("operator-secret"),
            Some(REMOTE),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(v["error"]["reason"], "route_unavailable");
}

#[tokio::test]
async fn voting_candidate_t0_seam_deferred_route_unavailable() {
    let (status, v) = send(
        app_full(default_auth()),
        req(Method::GET, "/api/v1/voting/candidate", None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(v["error"]["reason"], "route_unavailable");
}
