//! Route-level tests for the `light/*`, `stats/*`, and `diagnostics` groups
//! (`dev-docs/v1-api-design.md` §3.13–§3.15). Convention-lock coverage: exact
//! snake_case field names, the `{items, page}` series envelope, the canonical
//! error `reason`s, honest `*_unavailable` / `*_disabled` gating, the O2
//! membership-proof dual mount, and the diagnostics signals over a stub
//! node-state (including the `unknown` gaps that must NOT read as a fake green).

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::extract::ConnectInfo;
use axum::http::{Method, Request, StatusCode};
use axum::Router;
use ergo_api::compat::types::ScalaMerkleProof;
use ergo_api::compat::NodeChainQuery;
use ergo_api::emission::{EmissionInfoJson, EmissionSchedule};
use ergo_api::traits::{MempoolView, NodeReadState, NoopMempoolView};
use ergo_api::types::{
    ApiFullBlockRef, ApiHeaderRef, ApiHealth, ApiIdentity, ApiInfo, ApiMempoolSummary,
    ApiMempoolTransaction, ApiMempoolTransactions, ApiPeer, ApiPeerDirection, ApiPeerState,
    ApiStatus, ApiSyncStatus, ApiTip, ApiWeightFunction, HealthStatus, SyncStateLabel,
};
use ergo_api::v1::{v1_router, MempoolDepthRing, V1State};
use ergo_rest_json::types::{
    ScalaBatchMerkleProof, ScalaBatchProofElement, ScalaBatchProofIndex, ScalaBlockTransactions,
    ScalaHeader, ScalaNipopowProof, ScalaOutput, ScalaPopowHeader, ScalaPowSolutions,
    ScalaTransaction,
};
use ergo_ser::address::NetworkPrefix;
use tower::ServiceExt;

// ----- fixtures -----------------------------------------------------------

const SELF_HEIGHT: u32 = 100;
const MINER_PK: &str = "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2";

fn id(n: u32) -> String {
    format!("{n:064x}")
}

fn scala_header(height: u32) -> ScalaHeader {
    ScalaHeader {
        extension_id: id(0xe1),
        difficulty: "1200000".to_string(),
        votes: "000000".to_string(),
        timestamp: 1_700_000_000_000 + u64::from(height) * 120_000,
        size: 200,
        unparsed_bytes: String::new(),
        state_root: id(0x57),
        height,
        n_bits: 83_886_080,
        version: 3,
        id: id(height),
        ad_proofs_root: id(0xad),
        transactions_root: id(0x77),
        extension_hash: id(0xe2),
        pow_solutions: ScalaPowSolutions {
            pk: MINER_PK.to_string(),
            w: "03".to_string() + &"00".repeat(32),
            n: "0000000000000000".to_string(),
            d: serde_json::json!(0),
        },
        ad_proofs_id: id(0xa1),
        transactions_id: id(0x77),
        parent_id: id(height.saturating_sub(1)),
    }
}

fn scala_popow_header(height: u32) -> ScalaPopowHeader {
    ScalaPopowHeader {
        header: scala_header(height),
        interlinks: vec![id(0), id(1)],
        interlinks_proof: ScalaBatchMerkleProof {
            indices: vec![ScalaBatchProofIndex {
                index: 0,
                digest: id(0xdd),
            }],
            // First a real sibling, then the odd-trailing empty sibling.
            proofs: vec![
                ScalaBatchProofElement {
                    digest: id(0xbb),
                    side: 0,
                },
                ScalaBatchProofElement {
                    digest: String::new(),
                    side: 1,
                },
            ],
        },
    }
}

// ----- stub node-read -----------------------------------------------------

#[derive(Clone)]
struct StubRead {
    peers: Vec<ApiPeer>,
    self_full: u32,
    self_header: u32,
    gap: u32,
    progress_age_ms: u64,
    health: HealthStatus,
    mining: bool,
    nipopow_bootstrap: bool,
    pool_txs: Vec<ApiMempoolTransaction>,
}

impl Default for StubRead {
    fn default() -> Self {
        StubRead {
            peers: Vec::new(),
            self_full: SELF_HEIGHT,
            self_header: SELF_HEIGHT,
            gap: 0,
            progress_age_ms: 1_000,
            health: HealthStatus::Ok,
            mining: false,
            nipopow_bootstrap: true,
            pool_txs: Vec::new(),
        }
    }
}

fn peer(
    direction: ApiPeerDirection,
    state: ApiPeerState,
    score: i32,
    height: Option<u32>,
) -> ApiPeer {
    ApiPeer {
        addr: "1.2.3.4:9030".to_string(),
        direction,
        state,
        score,
        agent: None,
        node_name: None,
        version: None,
        sync_version: String::new(),
        connected_seconds: 10,
        last_seen_seconds: 5,
        bytes_in: None,
        bytes_out: None,
        peer_height: height,
        rest_api_url: None,
        declared_address: None,
    }
}

impl NodeReadState for StubRead {
    fn info(&self) -> ApiInfo {
        ApiInfo {
            agent_name: String::new(),
            node_name: String::new(),
            network: String::new(),
            version: String::new(),
            started_at_unix_ms: 0,
            uptime_seconds: 0,
            target_block_interval_ms: 120_000,
        }
    }
    fn status(&self) -> ApiStatus {
        ApiStatus {
            sync_state: SyncStateLabel::AtTip,
            peer_count: self.peers.len() as u32,
            best_header_height: self.self_header,
            best_full_block_height: self.self_full,
            headers_ahead_of_full_blocks: self.gap,
            mempool_size: 0,
            snapshot_age_ms: 0,
            bootstrap: None,
            last_block_apply_error: None,
            block_apply_errors_total: 0,
            mempool_tx_requested_total: 0,
            mempool_peer_tx_admitted_total: 0,
            mempool_peer_tx_rejected_total: 0,
            reorgs_total: 0,
            last_reorg_depth: None,
            last_reorg_unix_ms: None,
            apply_in_progress: false,
            last_apply_duration_ms: 0,
            last_applied_height: 0,
            last_apply_age_ms: None,
        }
    }
    fn tip(&self) -> ApiTip {
        ApiTip {
            best_header: ApiHeaderRef {
                height: self.self_header,
                header_id: String::new(),
                parent_id: String::new(),
                timestamp_unix_ms: 0,
                n_bits: 0,
                difficulty: String::new(),
            },
            best_full_block: ApiFullBlockRef {
                height: self.self_full,
                header_id: String::new(),
                parent_id: String::new(),
                timestamp_unix_ms: 0,
                state_root_avl: String::new(),
                n_bits: 0,
                difficulty: String::new(),
            },
            headers_ahead_of_full_blocks: self.gap,
        }
    }
    fn sync(&self) -> ApiSyncStatus {
        ApiSyncStatus {
            headers_chain_synced: true,
            best_header_height: self.self_header,
            best_full_block_height: self.self_full,
            gap: self.gap,
            download_window: 256,
            pending_blocks: 0,
            recovery_done: true,
        }
    }
    fn peers(&self) -> Vec<ApiPeer> {
        self.peers.clone()
    }
    fn mempool_summary(&self) -> ApiMempoolSummary {
        ApiMempoolSummary {
            size: self.pool_txs.len() as u32,
            total_bytes: 2_048,
            capacity_count: 2_000,
            capacity_bytes: 100_000_000,
            revalidation_pending: 0,
        }
    }
    fn mempool_transactions(&self) -> ApiMempoolTransactions {
        ApiMempoolTransactions {
            transactions: self.pool_txs.clone(),
            weight_function: ApiWeightFunction::Cost,
        }
    }
    fn mempool_transaction(&self, _tx_id_hex: &str) -> Option<ApiMempoolTransaction> {
        None
    }
    fn health(&self) -> ApiHealth {
        ApiHealth {
            status: self.health,
            behind: 0,
            last_progress_age_ms: self.progress_age_ms,
            peer_count: self.peers.len() as u32,
        }
    }
    fn identity(&self) -> ApiIdentity {
        ApiIdentity {
            mining: self.mining,
            nipopow_bootstrap: self.nipopow_bootstrap,
            ..ApiIdentity::default()
        }
    }
}

// ----- stub chain ---------------------------------------------------------

#[derive(Default)]
struct StubChain {
    proof: Option<Result<ScalaNipopowProof, String>>,
    popow_headers: bool,
    slice: bool,
    merkle: bool,
    block_txs: bool,
}

const FEE_TREE: &str = "1005040004000e36100204a00b08cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ea02d192a39a8cc7a701730073011001020402d19683030193a38cc7b2a57300000193c2b2a57301007473027303830108cdeeac93b1a57304";

fn scala_fee_output(value: u64) -> ScalaOutput {
    ScalaOutput {
        box_id: id(0x0b),
        value,
        ergo_tree: FEE_TREE.to_string(),
        assets: Vec::new(),
        creation_height: 1,
        additional_registers: std::collections::BTreeMap::new(),
        transaction_id: id(0x77),
        index: 0,
    }
}

impl NodeChainQuery for StubChain {
    fn info(&self) -> ergo_api::compat::types::ScalaInfo {
        unreachable!("chain.info() is not on these read paths")
    }
    fn header_ids_at_height(&self, height: u32) -> Vec<String> {
        vec![id(height)]
    }
    fn full_block_by_id(
        &self,
        _header_id_hex: &str,
    ) -> Option<ergo_rest_json::types::ScalaFullBlock> {
        None
    }
    fn nipopow_proof(
        &self,
        _m: u32,
        _k: u32,
        _header_id_hex: Option<&str>,
    ) -> Result<ScalaNipopowProof, String> {
        match &self.proof {
            Some(Ok(p)) => Ok(p.clone()),
            Some(Err(e)) => Err(e.clone()),
            None => Err("nipopow proving unavailable on this bridge".to_string()),
        }
    }
    fn nipopow_header_at_height(&self, height: u32) -> Option<ScalaPopowHeader> {
        (self.popow_headers && height <= SELF_HEIGHT).then(|| scala_popow_header(height))
    }
    fn chain_slice(&self, from_height: u32, to_height: u32) -> Vec<ScalaHeader> {
        if !self.slice {
            return Vec::new();
        }
        (from_height..=to_height)
            .filter(|h| *h <= SELF_HEIGHT)
            .map(scala_header)
            .collect()
    }
    fn proof_for_tx(&self, _header_id_hex: &str, _tx_id_hex: &str) -> Option<ScalaMerkleProof> {
        self.merkle.then(|| ScalaMerkleProof {
            leaf_data: id(42),
            levels: vec![("11".to_string(), 0), ("22".to_string(), 1)],
        })
    }
    fn block_transactions_by_id(&self, header_id_hex: &str) -> Option<ScalaBlockTransactions> {
        self.block_txs.then(|| ScalaBlockTransactions {
            header_id: header_id_hex.to_string(),
            transactions: vec![ScalaTransaction {
                id: id(0x77),
                inputs: Vec::new(),
                data_inputs: Vec::new(),
                // One output paying a 1_000_000 nanoERG fee over a 200-byte tx.
                outputs: vec![scala_fee_output(1_000_000)],
                size: 200,
            }],
            block_version: 3,
            size: 300,
        })
    }
}

// ----- stub emission ------------------------------------------------------

struct StubEmission;
impl EmissionSchedule for StubEmission {
    fn emission_info_at(&self, height: u32) -> EmissionInfoJson {
        EmissionInfoJson {
            height,
            miner_reward: 15_000_000_000,
            total_coins_issued: 97_000_000_000_000_000 + u64::from(height),
            total_remain_coins: 100_000,
            reemitted: 0,
        }
    }
}

// ----- harness ------------------------------------------------------------

#[derive(Default)]
struct Deps {
    read: Option<StubRead>,
    chain: Option<StubChain>,
    emission: bool,
}

fn app(deps: Deps) -> Router {
    let read: Arc<dyn NodeReadState> = Arc::new(deps.read.unwrap_or_default());
    let chain: Option<Arc<dyn NodeChainQuery>> = match deps.chain {
        Some(c) => Some(Arc::new(c)),
        None => Some(Arc::new(StubChain::default())),
    };
    let mempool: Arc<dyn MempoolView> = Arc::new(NoopMempoolView::new());
    let emission: Option<Arc<dyn EmissionSchedule>> = deps.emission.then(|| {
        let e: Arc<dyn EmissionSchedule> = Arc::new(StubEmission);
        e
    });
    let state = V1State {
        read,
        chain,
        indexer: None,
        submit: None,
        tx_builder: None,
        mempool,
        mempool_depth: Arc::new(MempoolDepthRing::new()),
        emission,
        realtime: None,
        network: NetworkPrefix::Mainnet,
    };
    let governor =
        ergo_api::v1::governor::Governor::new(Default::default()).expect("valid governor config");
    v1_router(state, governor)
}

async fn get(deps: Deps, uri: &str) -> (StatusCode, serde_json::Value) {
    let mut request = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(Body::empty())
        .unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40_000))));
    let resp = app(deps).oneshot(request).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, value)
}

fn reason(v: &serde_json::Value) -> &str {
    v["error"]["reason"].as_str().unwrap_or("<none>")
}

// ===== light/* ============================================================

#[tokio::test]
async fn light_status_advertises_caps_and_flags() {
    let (status, body) = get(Deps::default(), "/api/v1/light/status").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["nipopow_bootstrap"], true);
    assert_eq!(body["serves_bootstrap_proof"], true);
    assert_eq!(body["serves_membership_proof"], true);
    assert_eq!(body["interlinks_available"], true);
    assert_eq!(body["max_proof_m"], 100);
    assert_eq!(body["max_proof_k"], 100);
}

#[tokio::test]
async fn light_bootstrap_proof_returns_snake_case_proof() {
    let deps = Deps {
        chain: Some(StubChain {
            proof: Some(Ok(ScalaNipopowProof {
                m: 6,
                k: 6,
                prefix: vec![scala_popow_header(1)],
                suffix_head: scala_popow_header(2),
                suffix_tail: vec![scala_header(3)],
                continuous: true,
            })),
            ..StubChain::default()
        }),
        ..Deps::default()
    };
    let (status, body) = get(deps, "/api/v1/light/bootstrap-proof?m=6&k=6").await;
    assert_eq!(status, StatusCode::OK);
    // snake_case field names, prefix/suffix_head/suffix/params.
    assert_eq!(body["prefix"][0]["header"]["header_id"], id(1));
    assert!(body["prefix"][0]["interlinks"].is_array());
    assert!(body["prefix"][0]["interlinks_proof"]["indices"].is_array());
    // Odd-trailing empty sibling surfaces as null (not "").
    assert!(body["prefix"][0]["interlinks_proof"]["proofs"][1]["digest"].is_null());
    assert_eq!(body["suffix_head"]["header"]["header_id"], id(2));
    assert_eq!(body["suffix"][0]["header_id"], id(3));
    assert_eq!(body["params"]["m"], 6);
    assert_eq!(body["params"]["k"], 6);
}

#[tokio::test]
async fn light_bootstrap_proof_pruned_is_nipopow_unavailable() {
    // Default StubChain: prover Err path (pruned / no extension data).
    let (status, body) = get(Deps::default(), "/api/v1/light/bootstrap-proof").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(reason(&body), "nipopow_unavailable");
}

#[tokio::test]
async fn light_bootstrap_proof_out_of_range_m_is_invalid_params() {
    let (status, body) = get(Deps::default(), "/api/v1/light/bootstrap-proof?m=0").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(reason(&body), "invalid_params");
    let (status, _) = get(Deps::default(), "/api/v1/light/bootstrap-proof?m=101").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn light_headers_interlinks_pages_popow_headers() {
    let deps = Deps {
        chain: Some(StubChain {
            popow_headers: true,
            ..StubChain::default()
        }),
        ..Deps::default()
    };
    let (status, body) = get(
        deps,
        "/api/v1/light/headers-interlinks?from_height=1&limit=3",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"].as_array().unwrap().len(), 3);
    assert_eq!(body["items"][0]["header"]["header_id"], id(1));
    assert!(body["items"][0]["interlinks_proof"]["proofs"].is_array());
    assert_eq!(body["page"]["limit"], 3);
    assert_eq!(body["page"]["has_more"], true);
    assert!(body["page"]["next_cursor"].is_string());
}

#[tokio::test]
async fn light_headers_interlinks_requires_from_height() {
    let (status, body) = get(Deps::default(), "/api/v1/light/headers-interlinks").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(reason(&body), "invalid_params");
}

#[tokio::test]
async fn light_membership_proof_dual_mount_matches_chain_proof() {
    let deps = Deps {
        chain: Some(StubChain {
            merkle: true,
            ..StubChain::default()
        }),
        ..Deps::default()
    };
    let uri = format!(
        "/api/v1/light/membership-proof?header_id={}&tx_id={}",
        id(5),
        id(42)
    );
    let (status, body) = get(deps, &uri).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["tx_id"], id(42));
    assert_eq!(body["levels"][0]["sibling"], "11");
    assert_eq!(body["levels"][0]["side"], "left");
    assert_eq!(body["levels"][1]["side"], "right");
}

#[tokio::test]
async fn light_membership_proof_requires_both_ids() {
    let (status, body) = get(Deps::default(), "/api/v1/light/membership-proof").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(reason(&body), "invalid_params");
}

// ===== stats/* ============================================================

#[tokio::test]
async fn stats_supply_series_shape() {
    let deps = Deps {
        chain: Some(StubChain {
            slice: true,
            ..StubChain::default()
        }),
        emission: true,
        ..Deps::default()
    };
    let (status, body) = get(deps, "/api/v1/stats/supply?from_height=1&limit=3").await;
    assert_eq!(status, StatusCode::OK);
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 3);
    assert_eq!(items[0]["height"], 1);
    assert!(items[0]["emitted"].is_string());
    assert!(items[0]["remaining"].is_string());
    assert!(items[0]["block_reward"].is_string());
    // timestamps come from the header fold (chain_slice).
    assert!(items[0]["timestamp_unix_ms"].is_number());
    assert!(items[0]["timestamp_iso"].is_string());
    assert_eq!(body["page"]["limit"], 3);
}

#[tokio::test]
async fn stats_supply_without_emission_is_state_unavailable() {
    let (status, body) = get(Deps::default(), "/api/v1/stats/supply").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(reason(&body), "state_unavailable");
}

#[tokio::test]
async fn stats_emission_schedule_projects_forward() {
    let deps = Deps {
        emission: true,
        ..Deps::default()
    };
    let (status, body) = get(
        deps,
        "/api/v1/stats/emission-schedule?from_height=100&to_height=104&step=2",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 3); // 100, 102, 104
    assert_eq!(items[0]["height"], 100);
    assert_eq!(items[1]["height"], 102);
    // Projected: no timestamps.
    assert!(items[0]["timestamp_unix_ms"].is_null());
}

#[tokio::test]
async fn stats_emission_schedule_cursor_round_trips() {
    let deps = || Deps {
        emission: true,
        ..Deps::default()
    };
    // Page 1: limit 2 of the 100..=104 step-2 walk → 100, 102 + a cursor.
    let (status, body) = get(
        deps(),
        "/api/v1/stats/emission-schedule?from_height=100&to_height=104&step=2&limit=2",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"].as_array().unwrap().len(), 2);
    assert_eq!(body["page"]["has_more"], serde_json::json!(true));
    let cur = body["page"]["next_cursor"].as_str().unwrap().to_string();

    // Page 2: the handler's own cursor round-trips (supersedes from_height).
    let uri = format!("/api/v1/stats/emission-schedule?to_height=104&step=2&limit=2&cursor={cur}");
    let (status, body) = get(deps(), &uri).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["height"], 104);
    assert_eq!(body["page"]["has_more"], serde_json::json!(false));
    assert!(body["page"]["next_cursor"].is_null());
}

#[tokio::test]
async fn stats_emission_schedule_saturated_walk_terminates_without_duplicates() {
    let deps = Deps {
        emission: true,
        ..Deps::default()
    };
    // A step that saturates at u32::MAX must not repeat the height or mint a
    // cursor that never terminates.
    let (status, body) = get(
        deps,
        "/api/v1/stats/emission-schedule?from_height=4294967290&to_height=4294967295&step=3&limit=50",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let heights: Vec<u64> = body["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["height"].as_u64().unwrap())
        .collect();
    assert_eq!(heights, vec![4294967290, 4294967293, 4294967295]);
    assert_eq!(body["page"]["has_more"], serde_json::json!(false));
    assert!(body["page"]["next_cursor"].is_null());
}

#[tokio::test]
async fn stats_emission_schedule_requires_to_height() {
    let deps = Deps {
        emission: true,
        ..Deps::default()
    };
    let (status, body) = get(deps, "/api/v1/stats/emission-schedule?from_height=1").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(reason(&body), "invalid_params");
}

#[tokio::test]
async fn stats_difficulty_series_shape_with_hashrate() {
    let deps = Deps {
        chain: Some(StubChain {
            slice: true,
            ..StubChain::default()
        }),
        ..Deps::default()
    };
    let (status, body) = get(deps, "/api/v1/stats/difficulty?from_height=1&limit=2").await;
    assert_eq!(status, StatusCode::OK);
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    assert!(items[0]["difficulty"].is_string());
    assert!(items[0]["hashrate"].is_string());
    assert!(items[0]["n_bits"].is_number());
    // hashrate = difficulty(1_200_000) / 120s = 10000.
    assert_eq!(items[0]["hashrate"], "10000");
}

#[tokio::test]
async fn stats_mempool_depth_serves_current_point_on_fresh_node() {
    let (status, body) = get(Deps::default(), "/api/v1/stats/mempool-depth").await;
    assert_eq!(status, StatusCode::OK);
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert!(items[0]["timestamp_unix_ms"].is_number());
    assert!(items[0]["min_fee_per_byte"].is_string());
    assert_eq!(body["page"]["has_more"], false);
}

#[tokio::test]
async fn stats_holders_without_indexer_is_indexer_disabled() {
    let uri = format!("/api/v1/stats/holders?token_id={}", id(9));
    let (status, body) = get(Deps::default(), &uri).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(reason(&body), "indexer_disabled");
}

// ===== diagnostics ========================================================

#[tokio::test]
async fn diagnostics_composite_has_all_five_signals() {
    let (status, body) = get(Deps::default(), "/api/v1/diagnostics").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["verdict"].is_string());
    for k in [
        "chain_position",
        "fork_risk",
        "tip_health",
        "peer_quality",
        "candidate_build",
    ] {
        assert!(body[k].is_object(), "missing signal {k}");
    }
    assert!(body["generated_at_unix_ms"].is_number());
}

#[tokio::test]
async fn diagnostics_chain_position_isolated_with_no_peers() {
    let (status, body) = get(Deps::default(), "/api/v1/diagnostics/chain-position").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "isolated");
    assert_eq!(body["self_full_height"], SELF_HEIGHT);
    assert!(body["max_peer_height"].is_null());
}

#[tokio::test]
async fn diagnostics_chain_position_ahead_suspicious_is_the_lone_fork_tell() {
    // Self at 100, every peer at 90 → self leads every peer → ahead_suspicious.
    let read = StubRead {
        peers: vec![
            peer(
                ApiPeerDirection::Outbound,
                ApiPeerState::Active,
                0,
                Some(90),
            ),
            peer(
                ApiPeerDirection::Outbound,
                ApiPeerState::Active,
                0,
                Some(88),
            ),
        ],
        ..StubRead::default()
    };
    let deps = Deps {
        read: Some(read),
        ..Deps::default()
    };
    let (status, body) = get(deps, "/api/v1/diagnostics/chain-position").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ahead_suspicious");
    assert_eq!(body["lead"], 10);
    assert_eq!(body["max_peer_height"], 90);
    // The un-plumbed sustained-window latch is surfaced honestly, not hidden.
    assert!(body["unknown"]
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s.as_str().unwrap().contains("sustained_window")));
}

#[tokio::test]
async fn diagnostics_fork_risk_forking_when_mining_and_ahead() {
    let read = StubRead {
        mining: true,
        peers: vec![peer(
            ApiPeerDirection::Outbound,
            ApiPeerState::Active,
            0,
            Some(90),
        )],
        ..StubRead::default()
    };
    let deps = Deps {
        read: Some(read),
        ..Deps::default()
    };
    let (status, body) = get(deps, "/api/v1/diagnostics/fork-risk").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["lone_producer"], true);
    assert_eq!(body["status"], "forking");
    // self_mined_fraction is honestly null (reward pk not at the API layer).
    assert!(body["self_mined_fraction_pct"].is_null());
}

#[tokio::test]
async fn diagnostics_tip_health_stuck_when_gap_and_stale() {
    let read = StubRead {
        gap: 5,
        progress_age_ms: 200_000,
        ..StubRead::default()
    };
    let deps = Deps {
        read: Some(read),
        ..Deps::default()
    };
    let (status, body) = get(deps, "/api/v1/diagnostics/tip-health").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "stuck");
    assert_eq!(body["gap"], 5);
    assert_eq!(body["stall_threshold_ms"], 120_000);
    // delivery failure rate is honestly null (counters not plumbed here).
    assert!(body["delivery_failure_rate_pct"].is_null());
}

#[tokio::test]
async fn diagnostics_peer_quality_thin_below_outbound_floor() {
    let read = StubRead {
        peers: vec![peer(
            ApiPeerDirection::Outbound,
            ApiPeerState::Active,
            0,
            Some(100),
        )],
        ..StubRead::default()
    };
    let deps = Deps {
        read: Some(read),
        ..Deps::default()
    };
    let (status, body) = get(deps, "/api/v1/diagnostics/peer-quality").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["summary"]["status"], "thin");
    assert_eq!(body["summary"]["min_outbound_healthy"], false);
    assert!(body["summary"]["banned_count"].is_null());
    assert!(body["worst_peers"].is_array());
}

#[tokio::test]
async fn diagnostics_candidate_build_disabled_when_not_mining() {
    let (status, body) = get(Deps::default(), "/api/v1/diagnostics/candidate-build").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "disabled");
    assert_eq!(body["mining_enabled"], false);
    assert_eq!(body["builds_sampled"], 0);
    assert!(body["last_build_ms"].is_null());
}

#[tokio::test]
async fn stats_fees_series_shape() {
    let deps = Deps {
        chain: Some(StubChain {
            slice: true,
            block_txs: true,
            ..StubChain::default()
        }),
        ..Deps::default()
    };
    let (status, body) = get(deps, "/api/v1/stats/fees?from_height=1&limit=2").await;
    assert_eq!(status, StatusCode::OK);
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    assert_eq!(items[0]["tx_count"], 1);
    assert_eq!(items[0]["total_fee"], "1000000");
    // 1_000_000 / 200 bytes = 5000 nanoERG/byte across all percentiles.
    assert_eq!(items[0]["fee_per_byte_median"], "5000");
    assert!(items[0]["fee_per_byte_p10"].is_string());
    assert!(items[0]["fee_per_byte_p90"].is_string());
    assert!(items[0]["min_fee"].is_string());
}
