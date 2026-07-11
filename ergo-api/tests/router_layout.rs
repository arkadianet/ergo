//! Router-layout regression test.
//!
//! Pins two facts: (1) the operator surface at `/api/v1/*` and the Scala
//! compat surface at bare paths can coexist on one router, and (2) when
//! the compat surface is omitted, bare paths return 404 instead of being
//! silently aliased to operator routes.
//!
//! The test drives the router through `tower::ServiceExt::oneshot`, no
//! TCP listener, no async runtime contention with `serve`.

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use ergo_api::compat::traits::NodeChainQuery;
use ergo_api::compat::traits::UtxoBoxBytes;
use ergo_api::compat::types::{
    Parameters, ScalaAsset, ScalaBlacklistedPeers, ScalaBlockSection, ScalaBlockTransactions,
    ScalaFullBlock, ScalaHeader, ScalaInfo, ScalaMerkleProof, ScalaOutput, ScalaPeer,
    ScalaPeersStatus, ScalaPowSolutions, ScalaSyncInfoEntry, ScalaTrackInfo, ScalaTransaction,
};
use ergo_api::server::router;
use ergo_api::traits::NodeReadState;
use ergo_api::types::{
    ApiFullBlockRef, ApiHeaderRef, ApiHealth, ApiInfo, ApiMempoolSummary, ApiMempoolTransaction,
    ApiMempoolTransactions, ApiPeer, ApiStatus, ApiSyncStatus, ApiTip, ApiWeightFunction,
    HealthStatus, SyncStateLabel,
};
use std::collections::BTreeMap;
use tower::ServiceExt;

struct StubReadState;

impl NodeReadState for StubReadState {
    fn info(&self) -> ApiInfo {
        ApiInfo {
            agent_name: "ergo-rust".into(),
            node_name: "stub".into(),
            network: "mainnet".into(),
            version: "0.1.0".into(),
            started_at_unix_ms: 0,
            uptime_seconds: 0,
            target_block_interval_ms: 120_000,
        }
    }
    fn status(&self) -> ApiStatus {
        ApiStatus {
            sync_state: SyncStateLabel::AtTip,
            peer_count: 0,
            best_header_height: 0,
            best_full_block_height: 0,
            headers_ahead_of_full_blocks: 0,
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
                height: 0,
                header_id: String::new(),
                parent_id: String::new(),
                timestamp_unix_ms: 0,
                n_bits: 0,
                difficulty: String::new(),
            },
            best_full_block: ApiFullBlockRef {
                height: 0,
                header_id: String::new(),
                parent_id: String::new(),
                timestamp_unix_ms: 0,
                state_root_avl: String::new(),
                n_bits: 0,
                difficulty: String::new(),
            },
            headers_ahead_of_full_blocks: 0,
        }
    }
    fn sync(&self) -> ApiSyncStatus {
        ApiSyncStatus {
            headers_chain_synced: true,
            best_header_height: 0,
            best_full_block_height: 0,
            gap: 0,
            download_window: 0,
            pending_blocks: 0,
            recovery_done: true,
        }
    }
    fn peers(&self) -> Vec<ApiPeer> {
        Vec::new()
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
    fn mempool_transaction(&self, _tx_id_hex: &str) -> Option<ApiMempoolTransaction> {
        None
    }
    fn health(&self) -> ApiHealth {
        ApiHealth {
            status: HealthStatus::Ok,
            behind: 0,
            last_progress_age_ms: 0,
            peer_count: 0,
        }
    }
}

struct StubCompat;

const HEADER_ID_HEX_AA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn stub_header_with(height: u32, id_hex: &str) -> ScalaHeader {
    ScalaHeader {
        extension_id: "00".repeat(32),
        difficulty: "0".into(),
        votes: "000000".into(),
        timestamp: 0,
        size: 0,
        unparsed_bytes: String::new(),
        state_root: "00".repeat(33),
        height,
        n_bits: 0,
        version: 4,
        id: id_hex.into(),
        ad_proofs_root: "00".repeat(32),
        transactions_root: "00".repeat(32),
        extension_hash: "00".repeat(32),
        pow_solutions: ScalaPowSolutions {
            pk: "00".repeat(33),
            w: "00".repeat(33),
            n: "00".repeat(8),
            d: serde_json::Value::Number(0u64.into()),
        },
        ad_proofs_id: "00".repeat(32),
        transactions_id: "00".repeat(32),
        parent_id: "00".repeat(32),
    }
}

impl NodeChainQuery for StubCompat {
    fn header_ids_at_height(&self, height: u32) -> Vec<String> {
        if height == 100 {
            vec!["aa".repeat(32)]
        } else {
            Vec::new()
        }
    }

    fn full_block_by_id(&self, _header_id_hex: &str) -> Option<ScalaFullBlock> {
        None
    }

    fn header_by_id(&self, header_id_hex: &str) -> Option<ScalaHeader> {
        if header_id_hex == HEADER_ID_HEX_AA {
            Some(stub_header_with(100, HEADER_ID_HEX_AA))
        } else {
            None
        }
    }

    fn block_transactions_by_id(&self, header_id_hex: &str) -> Option<ScalaBlockTransactions> {
        if header_id_hex == HEADER_ID_HEX_AA {
            Some(ScalaBlockTransactions {
                header_id: header_id_hex.into(),
                transactions: Vec::new(),
                block_version: 4,
                size: 0,
            })
        } else {
            None
        }
    }

    fn full_blocks_by_header_ids(&self, _ids: &[String]) -> Vec<ScalaFullBlock> {
        // No fixture full block in this stub; the layout test only
        // verifies the route is mounted and accepts the body shape.
        Vec::new()
    }

    fn modifier_by_id(&self, modifier_id_hex: &str) -> Option<ScalaBlockSection> {
        if modifier_id_hex == HEADER_ID_HEX_AA {
            Some(ScalaBlockSection::Header(Box::new(stub_header_with(
                100,
                HEADER_ID_HEX_AA,
            ))))
        } else {
            None
        }
    }

    fn proof_for_tx(&self, header_id_hex: &str, _tx_id_hex: &str) -> Option<ScalaMerkleProof> {
        if header_id_hex == HEADER_ID_HEX_AA {
            Some(ScalaMerkleProof {
                leaf_data: "ab".repeat(32),
                levels: vec![(String::new(), 0)],
            })
        } else {
            None
        }
    }

    fn last_headers(&self, count: u32) -> Vec<ScalaHeader> {
        // Pretend the chain has heights 1..=10. Return the last `count`
        // ascending — clamping mirrors the bridge's saturating sub.
        let tip = 10u32;
        let lo = tip.saturating_sub(count.max(1) - 1).max(1);
        (lo..=tip)
            .map(|h| stub_header_with(h, &format!("{:02x}", h).repeat(32)))
            .collect()
    }

    fn chain_slice(&self, from_height: u32, to_height: u32) -> Vec<ScalaHeader> {
        // Mirrors the bridge's Scala-source semantic. Stub chain is heights
        // 1..=10. `top` falls back to tip if `to_height` isn't in our chain.
        let tip = 10u32;
        let top = if to_height >= 1 && to_height <= tip {
            to_height
        } else {
            tip
        };
        if top == 0 {
            return Vec::new();
        }
        const MAX_HEADERS: u32 = 16_384;
        let lo = if top <= from_height.saturating_add(1) {
            top
        } else {
            let raw_lo = from_height.saturating_add(1);
            let cap_lo = top.saturating_sub(MAX_HEADERS - 1);
            raw_lo.max(cap_lo).max(1)
        };
        (lo..=top)
            .map(|h| stub_header_with(h, &format!("{:02x}", h).repeat(32)))
            .collect()
    }

    fn header_ids_paged(&self, limit: u32, offset: u32) -> Vec<String> {
        if limit == 0 {
            return Vec::new();
        }
        let tip = 10u32;
        let lo = offset;
        let hi = offset.saturating_add(limit).saturating_sub(1);
        // Stub chain has heights 1..=tip; missing heights drop out (matches
        // Scala's `flatMap(bestHeaderIdAtHeight)`).
        (lo..=hi)
            .filter(|&h| (1..=tip).contains(&h))
            .map(|h| format!("{:02x}", h).repeat(32))
            .collect()
    }

    fn peers_all(&self) -> Vec<ScalaPeer> {
        vec![
            ScalaPeer {
                address: "1.2.3.4:9030".into(),
                rest_api_url: None,
                name: Some("alice".into()),
                last_seen: 1_000,
                connection_type: Some("Outgoing".into()),
            },
            ScalaPeer {
                address: "5.6.7.8:9030".into(),
                rest_api_url: None,
                name: Some("bob".into()),
                last_seen: 2_000,
                connection_type: Some("Incoming".into()),
            },
        ]
    }

    fn peers_connected(&self) -> Vec<ScalaPeer> {
        vec![ScalaPeer {
            address: "1.2.3.4:9030".into(),
            rest_api_url: None,
            name: Some("alice".into()),
            last_seen: 1_000,
            connection_type: Some("Outgoing".into()),
        }]
    }

    fn pool_tx_ids(&self) -> Vec<String> {
        vec!["aa".repeat(32), "bb".repeat(32)]
    }

    fn pool_contains(&self, tx_id_hex: &str) -> bool {
        tx_id_hex == "aa".repeat(32)
    }

    fn pool_txs_paged(&self, offset: u32, limit: u32) -> Vec<ScalaTransaction> {
        // Stub pool of 3 dummy txs with distinguishable ids. Slice
        // by offset+limit so paging is exercised.
        let pool: Vec<ScalaTransaction> = (0..3)
            .map(|i| ScalaTransaction {
                id: format!("{:02x}", i).repeat(32),
                inputs: vec![],
                data_inputs: vec![],
                outputs: vec![],
                size: 100 + i as u32,
            })
            .collect();
        pool.into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .collect()
    }

    fn pool_tx_by_id(&self, tx_id_hex: &str) -> Option<ScalaTransaction> {
        if tx_id_hex == "00".repeat(32) {
            Some(ScalaTransaction {
                id: tx_id_hex.into(),
                inputs: vec![],
                data_inputs: vec![],
                outputs: vec![],
                size: 99,
            })
        } else {
            None
        }
    }

    fn pool_txs_by_ids(&self, tx_ids_hex: &[String]) -> Vec<ScalaTransaction> {
        // Resolve only ids that match `pool_tx_by_id`. Unresolved
        // ids silently skipped — Scala `flatMap(getById)` parity.
        tx_ids_hex
            .iter()
            .filter_map(|id| self.pool_tx_by_id(id))
            .collect()
    }

    fn pool_size(&self) -> u32 {
        3
    }

    fn pool_txs_by_ergo_tree(&self, tree_bytes: &[u8]) -> Vec<ScalaTransaction> {
        // Stub: a magic 2-byte ergoTree `0xab 0xcd` resolves to one
        // canned tx; anything else returns an empty array. Pins the
        // route-handler hex-parsing + body-shape contract without
        // depending on real ergoTree wire bytes.
        if tree_bytes == [0xab, 0xcd] {
            vec![ScalaTransaction {
                id: "01".repeat(32),
                inputs: vec![],
                data_inputs: vec![],
                outputs: vec![],
                size: 42,
            }]
        } else {
            Vec::new()
        }
    }

    fn pool_txs_by_box_id(&self, box_id: &[u8; 32]) -> Vec<ScalaTransaction> {
        if box_id == &[0xAA; 32] {
            vec![ScalaTransaction {
                id: "02".repeat(32),
                inputs: vec![],
                data_inputs: vec![],
                outputs: vec![],
                size: 43,
            }]
        } else {
            Vec::new()
        }
    }

    fn pool_txs_by_token_id(&self, token_id: &[u8; 32]) -> Vec<ScalaTransaction> {
        if token_id == &[0xBB; 32] {
            vec![ScalaTransaction {
                id: "03".repeat(32),
                inputs: vec![],
                data_inputs: vec![],
                outputs: vec![],
                size: 44,
            }]
        } else {
            Vec::new()
        }
    }

    fn pool_txs_by_registers(
        &self,
        registers: &std::collections::BTreeMap<String, String>,
    ) -> Vec<ScalaTransaction> {
        // Magic match: a single entry `R4 -> "0e20" + 32 0xCC bytes`
        // (a typical SBoolean-tagged Const register value) resolves
        // to one canned tx.
        let expected = "0e20".to_string() + &"cc".repeat(32);
        if registers.len() == 1 && registers.get("R4") == Some(&expected) {
            vec![ScalaTransaction {
                id: "04".repeat(32),
                inputs: vec![],
                data_inputs: vec![],
                outputs: vec![],
                size: 45,
            }]
        } else {
            Vec::new()
        }
    }

    fn pool_fee_histogram(
        &self,
        bins: u32,
        _maxtime_ms: u64,
    ) -> Vec<ergo_api::compat::types::ScalaFeeHistogramBin> {
        // Stub mirrors the production contract: returns `bins + 1`
        // entries. First two bins synthetic, rest zero — pins the
        // wire shape (camelCase rename) without depending on real
        // pool data.
        let mut out = vec![
            ergo_api::compat::types::ScalaFeeHistogramBin {
                n_txns: 0,
                total_fee: 0,
            };
            (bins as usize) + 1
        ];
        if !out.is_empty() {
            out[0] = ergo_api::compat::types::ScalaFeeHistogramBin {
                n_txns: 12,
                total_fee: 1_500_000,
            };
        }
        if out.len() > 1 {
            out[1] = ergo_api::compat::types::ScalaFeeHistogramBin {
                n_txns: 4,
                total_fee: 200_000,
            };
        }
        out
    }

    fn pool_recommended_fee(&self, wait_time_minutes: u32, tx_size_bytes: u32) -> u64 {
        // Magic: waitTime=5 returns 100 nanoErg/byte * tx_size.
        if wait_time_minutes == 5 {
            100u64.saturating_mul(tx_size_bytes as u64)
        } else {
            // Default minimum floor for the test harness.
            tx_size_bytes as u64
        }
    }

    fn pool_expected_wait_time_ms(&self, fee: u64, tx_size_bytes: u32) -> u64 {
        // Magic: fee >= 100 * tx_size → 0 ms (instant). Below →
        // 60_000 ms (1 minute).
        let fee_per_byte = fee / tx_size_bytes.max(1) as u64;
        if fee_per_byte >= 100 {
            0
        } else {
            60_000
        }
    }

    fn peers_blacklisted(&self) -> ScalaBlacklistedPeers {
        // Java `InetAddress.toString()` form: `/literal-ip` when
        // no reverse-DNS hostname is bound (the typical case for
        // raw blacklisted IPs). Matches Scala-emitted output.
        ScalaBlacklistedPeers {
            addresses: vec!["/1.2.3.4".into(), "/5.6.7.8".into()],
        }
    }

    fn peers_status(&self) -> ScalaPeersStatus {
        ScalaPeersStatus {
            last_incoming_message: 1_700_000_000_000,
            current_system_time: 1_700_000_001_000,
        }
    }

    fn peers_sync_info(&self) -> Vec<ScalaSyncInfoEntry> {
        // Stub populated with one entry per recognised Scala
        // chain-status string. Real peers without a SyncInfo
        // observation are omitted (NOT fabricated as "unknown").
        vec![
            ScalaSyncInfoEntry {
                address: "1.2.3.4:9030".into(),
                height: 1_770_000,
                status: "Equal".into(),
            },
            ScalaSyncInfoEntry {
                address: "5.6.7.8:9030".into(),
                height: 1_769_500,
                status: "Younger".into(),
            },
            ScalaSyncInfoEntry {
                address: "9.10.11.12:9030".into(),
                height: 1_770_500,
                status: "Older".into(),
            },
        ]
    }

    fn peers_track_info(&self) -> ScalaTrackInfo {
        ScalaTrackInfo {
            num_requested: 12,
            num_received: 100,
            num_failed: 3,
        }
    }

    fn utxo_box_by_id(&self, box_id_hex: &str) -> Option<ScalaOutput> {
        if box_id_hex == "cc".repeat(32) {
            Some(ScalaOutput {
                box_id: box_id_hex.into(),
                value: 1_000_000_000,
                ergo_tree: "0008cd03".to_string() + &"00".repeat(33),
                assets: vec![ScalaAsset {
                    token_id: "11".repeat(32),
                    amount: 7,
                }],
                creation_height: 100,
                additional_registers: BTreeMap::from([("R4".to_string(), "0402".to_string())]),
                transaction_id: "dd".repeat(32),
                index: 0,
            })
        } else {
            None
        }
    }

    fn utxo_box_bytes_by_id(&self, box_id_hex: &str) -> Option<UtxoBoxBytes> {
        if box_id_hex == "cc".repeat(32) {
            Some(UtxoBoxBytes {
                box_id: box_id_hex.into(),
                bytes: "deadbeef".into(),
            })
        } else {
            None
        }
    }

    fn utxo_genesis_boxes(&self) -> Vec<ScalaOutput> {
        vec![
            ScalaOutput {
                box_id: "11".repeat(32),
                value: 1,
                ergo_tree: String::new(),
                assets: Vec::new(),
                creation_height: 0,
                additional_registers: BTreeMap::new(),
                transaction_id: "00".repeat(32),
                index: 0,
            },
            ScalaOutput {
                box_id: "22".repeat(32),
                value: 2,
                ergo_tree: String::new(),
                assets: Vec::new(),
                creation_height: 0,
                additional_registers: BTreeMap::new(),
                transaction_id: "00".repeat(32),
                index: 1,
            },
            ScalaOutput {
                box_id: "33".repeat(32),
                value: 3,
                ergo_tree: String::new(),
                assets: Vec::new(),
                creation_height: 0,
                additional_registers: BTreeMap::new(),
                transaction_id: "00".repeat(32),
                index: 2,
            },
        ]
    }

    /// Stub overlay: committed UTXO id is `cc..`, pool-only id is `aa..`.
    /// `cc..` falls through to `utxo_box_by_id` (committed wins), `aa..` is
    /// the pool-only hit. Anything else → None.
    fn utxo_with_pool_box_by_id(&self, box_id_hex: &str) -> Option<ScalaOutput> {
        if let Some(committed) = self.utxo_box_by_id(box_id_hex) {
            return Some(committed);
        }
        if box_id_hex == "aa".repeat(32) {
            Some(ScalaOutput {
                box_id: box_id_hex.into(),
                value: 500_000_000,
                ergo_tree: "0008cd02".to_string() + &"00".repeat(33),
                assets: Vec::new(),
                creation_height: 200,
                additional_registers: BTreeMap::new(),
                transaction_id: "ee".repeat(32),
                index: 1,
            })
        } else {
            None
        }
    }

    fn utxo_with_pool_box_bytes_by_id(&self, box_id_hex: &str) -> Option<UtxoBoxBytes> {
        if let Some(committed) = self.utxo_box_bytes_by_id(box_id_hex) {
            return Some(committed);
        }
        if box_id_hex == "aa".repeat(32) {
            Some(UtxoBoxBytes {
                box_id: box_id_hex.into(),
                bytes: "feedface".into(),
            })
        } else {
            None
        }
    }

    fn utxo_with_pool_boxes_by_ids(&self, box_ids_hex: &[String]) -> Vec<ScalaOutput> {
        box_ids_hex
            .iter()
            .filter_map(|id| self.utxo_with_pool_box_by_id(id))
            .collect()
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
}

async fn json_get(app: axum::Router, path: &str) -> (StatusCode, serde_json::Value) {
    let resp = app
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let value = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    };
    (status, value)
}

async fn json_post(
    app: axum::Router,
    path: &str,
    body: &serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let value = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    };
    (status, value)
}

#[tokio::test]
async fn merged_router_serves_both_surfaces_with_distinct_dtos() {
    let read: Arc<dyn NodeReadState> = Arc::new(StubReadState);
    let compat: Arc<dyn NodeChainQuery> = Arc::new(StubCompat);
    let app = router(
        read,
        Some(compat),
        None,
        None,
        ergo_ser::address::NetworkPrefix::Mainnet,
    );

    let (s1, v1) = json_get(app.clone(), "/api/v1/info").await;
    assert_eq!(s1, StatusCode::OK);
    let o1 = v1.as_object().expect("operator /info is an object");
    assert!(o1.contains_key("agent_name"), "operator surface");
    assert!(
        !o1.contains_key("stateType"),
        "no Scala fields leak into operator"
    );

    let (s2, v2) = json_get(app, "/info").await;
    assert_eq!(s2, StatusCode::OK);
    let o2 = v2.as_object().expect("scala /info is an object");
    assert!(o2.contains_key("stateType"), "scala surface");
    assert!(
        !o2.contains_key("agent_name"),
        "no operator fields leak into scala"
    );
}

#[tokio::test]
async fn bare_info_is_404_when_compat_disabled() {
    let read: Arc<dyn NodeReadState> = Arc::new(StubReadState);
    let app = router(
        read,
        None,
        None,
        None,
        ergo_ser::address::NetworkPrefix::Mainnet,
    );

    let (s, _) = json_get(app, "/info").await;
    assert_eq!(
        s,
        StatusCode::NOT_FOUND,
        "without compat, /info must not alias to /api/v1/info",
    );
}

#[tokio::test]
async fn swagger_ui_and_openapi_spec_are_served() {
    let read: Arc<dyn NodeReadState> = Arc::new(StubReadState);
    let app = router(
        read,
        None,
        None,
        None,
        ergo_ser::address::NetworkPrefix::Mainnet,
    );

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/swagger")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.starts_with("text/html"),
        "swagger page must be html, got {ct}"
    );
    let body = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(
        html.contains("/api-docs/openapi.yaml"),
        "swagger page must reference spec url"
    );

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api-docs/openapi.yaml")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(ct, "application/yaml", "spec must be served as yaml");
    let body = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let yaml = std::str::from_utf8(&body).unwrap();
    assert!(
        yaml.starts_with("openapi:"),
        "spec must start with openapi key"
    );
}

fn build_compat_app() -> axum::Router {
    let read: Arc<dyn NodeReadState> = Arc::new(StubReadState);
    let compat: Arc<dyn NodeChainQuery> = Arc::new(StubCompat);
    router(
        read,
        Some(compat),
        None,
        None,
        ergo_ser::address::NetworkPrefix::Mainnet,
    )
}

#[tokio::test]
async fn header_by_id_returns_known_and_404s_unknown() {
    let path = format!("/blocks/{HEADER_ID_HEX_AA}/header");
    let (s, v) = json_get(build_compat_app(), &path).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v.get("id").and_then(|x| x.as_str()), Some(HEADER_ID_HEX_AA));
    assert_eq!(v.get("height").and_then(|x| x.as_u64()), Some(100));

    let unknown = "0".repeat(64);
    let path = format!("/blocks/{unknown}/header");
    let (s, _) = json_get(build_compat_app(), &path).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn block_transactions_by_id_returns_known_and_404s_unknown() {
    let path = format!("/blocks/{HEADER_ID_HEX_AA}/transactions");
    let (s, v) = json_get(build_compat_app(), &path).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        v.get("headerId").and_then(|x| x.as_str()),
        Some(HEADER_ID_HEX_AA)
    );
    assert!(v.get("transactions").unwrap().is_array());

    let unknown = "0".repeat(64);
    let path = format!("/blocks/{unknown}/transactions");
    let (s, _) = json_get(build_compat_app(), &path).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn last_headers_returns_ascending_count() {
    let (s, v) = json_get(build_compat_app(), "/blocks/lastHeaders/3").await;
    assert_eq!(s, StatusCode::OK);
    let arr = v.as_array().expect("lastHeaders is an array");
    assert_eq!(arr.len(), 3);
    let heights: Vec<u64> = arr
        .iter()
        .map(|h| h.get("height").unwrap().as_u64().unwrap())
        .collect();
    assert_eq!(heights, vec![8, 9, 10], "ascending heights ending at tip");
}

// ---- /blocks/chainSlice parity (BlocksApiRoute.scala:93-149) ----

#[tokio::test]
async fn chain_slice_default_skips_genesis_due_to_off_by_one() {
    // Scala defaults: fromHeight=1, toHeight=16384. Predicate
    // `_.height <= 2` triggers at height 2 (included), so the lowest
    // height returned is 2 — height 1 is excluded. Stub tip = 10.
    let (s, v) = json_get(build_compat_app(), "/blocks/chainSlice").await;
    assert_eq!(s, StatusCode::OK);
    let heights: Vec<u64> = v
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h.get("height").unwrap().as_u64().unwrap())
        .collect();
    assert_eq!(
        heights,
        (2..=10).collect::<Vec<u64>>(),
        "default chainSlice excludes fromHeight=1 (Scala off-by-one)",
    );
}

#[tokio::test]
async fn chain_slice_explicit_range_excludes_from_height() {
    // fromHeight=3, toHeight=5. Predicate `_.height <= 4`; walk back
    // from 5 → 4 (predicate triggers, included) → stop. Heights: [4, 5].
    let (s, v) = json_get(
        build_compat_app(),
        "/blocks/chainSlice?fromHeight=3&toHeight=5",
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let heights: Vec<u64> = v
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h.get("height").unwrap().as_u64().unwrap())
        .collect();
    assert_eq!(
        heights,
        vec![4, 5],
        "fromHeight excluded; lowest returned is fromHeight + 1",
    );
}

#[tokio::test]
async fn chain_slice_to_equals_from_returns_single_header() {
    // fromHeight=5, toHeight=5. Predicate triggers at start; returns [5].
    let (s, v) = json_get(
        build_compat_app(),
        "/blocks/chainSlice?fromHeight=5&toHeight=5",
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let heights: Vec<u64> = v
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h.get("height").unwrap().as_u64().unwrap())
        .collect();
    assert_eq!(heights, vec![5]);
}

#[tokio::test]
async fn chain_slice_to_equals_from_plus_one_returns_single_header() {
    // fromHeight=4, toHeight=5. Predicate `_.height <= 5` triggers at
    // start (5 <= 5). Returns just [5].
    let (s, v) = json_get(
        build_compat_app(),
        "/blocks/chainSlice?fromHeight=4&toHeight=5",
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let heights: Vec<u64> = v
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h.get("height").unwrap().as_u64().unwrap())
        .collect();
    assert_eq!(heights, vec![5]);
}

#[tokio::test]
async fn chain_slice_both_negative_falls_back_to_tip() {
    // Scala's `toHeight >= 0` branch is only reachable when `fromHeight`
    // is also non-positive — otherwise the `to < from` guard rejects it.
    // fromHeight=-5, toHeight=-1: passes the guard (-1 >= -5), then
    // `getChainSlice` takes the `else` branch and uses bestHeader (tip).
    // Predicate `_.height <= -4` never triggers; walk back 16384 entries
    // from tip. For our 10-block stub, that's heights [1, 10].
    let (s, v) = json_get(
        build_compat_app(),
        "/blocks/chainSlice?fromHeight=-5&toHeight=-1",
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let heights: Vec<u64> = v
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h.get("height").unwrap().as_u64().unwrap())
        .collect();
    assert_eq!(heights, (1..=10).collect::<Vec<u64>>());
}

#[tokio::test]
async fn chain_slice_positive_from_with_negative_to_is_400() {
    // fromHeight=8, toHeight=-1: -1 < 8 → 400. The negative-toHeight
    // fallback in `getChainSlice` is unreachable in this case.
    let (s, v) = json_get(
        build_compat_app(),
        "/blocks/chainSlice?fromHeight=8&toHeight=-1",
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(
        v.get("detail").and_then(|x| x.as_str()),
        Some("toHeight < fromHeight"),
    );
}

#[tokio::test]
async fn chain_slice_to_less_than_from_is_400_with_scala_message() {
    let (s, v) = json_get(
        build_compat_app(),
        "/blocks/chainSlice?fromHeight=5&toHeight=3",
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(
        v.get("detail").and_then(|x| x.as_str()),
        Some("toHeight < fromHeight"),
    );
}

// ---- /blocks paging parity (BlocksApiRoute.scala:31, :114-124) ----

#[tokio::test]
async fn header_ids_paged_default_is_ascending_from_height_one() {
    // Scala defaults: offset=1, limit=50. Range [1, 51) ascending.
    // Stub chain has heights 1..=10, so result is heights 1..10 → 10 ids.
    let (s, v) = json_get(build_compat_app(), "/blocks").await;
    assert_eq!(s, StatusCode::OK);
    let ids: Vec<String> = v
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap().to_string())
        .collect();
    assert_eq!(ids.len(), 10);
    assert_eq!(
        ids[0],
        format!("{:02x}", 1).repeat(32),
        "first id at offset=1"
    );
    assert_eq!(ids[9], format!("{:02x}", 10).repeat(32), "last id at tip");
}

#[tokio::test]
async fn header_ids_paged_offset_is_start_height_not_skip() {
    // offset=2, limit=3 → heights [2, 3, 4] ascending.
    let (s, v) = json_get(build_compat_app(), "/blocks?offset=2&limit=3").await;
    assert_eq!(s, StatusCode::OK);
    let ids: Vec<String> = v
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        ids,
        vec![
            format!("{:02x}", 2).repeat(32),
            format!("{:02x}", 3).repeat(32),
            format!("{:02x}", 4).repeat(32),
        ],
    );
}

#[tokio::test]
async fn header_ids_paged_offset_past_tip_returns_empty_array() {
    // offset=100 on a 10-block stub chain. Scala drops missing heights;
    // we get an empty array, not 404.
    let (s, v) = json_get(build_compat_app(), "/blocks?offset=100&limit=3").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v.as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn header_ids_paged_negative_offset_is_400_with_scala_message() {
    let (s, v) = json_get(build_compat_app(), "/blocks?offset=-1").await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(
        v.get("detail").and_then(|x| x.as_str()),
        Some("offset is negative"),
    );
}

#[tokio::test]
async fn header_ids_paged_negative_limit_is_400_with_scala_message() {
    let (s, v) = json_get(build_compat_app(), "/blocks?limit=-1").await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(
        v.get("detail").and_then(|x| x.as_str()),
        Some("limit is negative"),
    );
}

#[tokio::test]
async fn header_ids_paged_limit_above_max_headers_is_400() {
    // Scala: 16384 OK, 16385 rejected.
    let (s, _) = json_get(build_compat_app(), "/blocks?limit=16384").await;
    assert_eq!(s, StatusCode::OK);
    let (s, v) = json_get(build_compat_app(), "/blocks?limit=16385").await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(
        v.get("detail").and_then(|x| x.as_str()),
        Some("No more than 16384 headers can be requested"),
    );
}

// ---- /blocks/lastHeaders cap (BlocksApiRoute.scala:159-164) ----

#[tokio::test]
async fn last_headers_above_max_headers_is_400() {
    let (s, _) = json_get(build_compat_app(), "/blocks/lastHeaders/16384").await;
    assert_eq!(s, StatusCode::OK);
    let (s, v) = json_get(build_compat_app(), "/blocks/lastHeaders/16385").await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(
        v.get("detail").and_then(|x| x.as_str()),
        Some("No more than 16384 headers can be requested"),
    );
}

#[tokio::test]
async fn peers_all_returns_scala_shape() {
    let (s, v) = json_get(build_compat_app(), "/peers/all").await;
    assert_eq!(s, StatusCode::OK);
    let arr = v.as_array().expect("/peers/all is an array");
    assert_eq!(arr.len(), 2);
    let first = arr[0].as_object().unwrap();
    for k in [
        "address",
        "restApiUrl",
        "name",
        "lastSeen",
        "connectionType",
    ] {
        assert!(first.contains_key(k), "missing scala field {k}");
    }
    assert_eq!(
        first.get("connectionType").and_then(|x| x.as_str()),
        Some("Outgoing"),
        "connectionType must be capital-I/O per Scala spec",
    );
}

#[tokio::test]
async fn peers_connected_filters_to_connected_only() {
    let (s, v) = json_get(build_compat_app(), "/peers/connected").await;
    assert_eq!(s, StatusCode::OK);
    let arr = v.as_array().unwrap();
    assert_eq!(arr.len(), 1, "stub returns one connected peer");
    assert_eq!(
        arr[0].get("address").and_then(|x| x.as_str()),
        Some("1.2.3.4:9030"),
    );
}

#[tokio::test]
async fn pool_tx_ids_returns_array() {
    let (s, v) = json_get(
        build_compat_app(),
        "/transactions/unconfirmed/transactionIds",
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let arr = v.as_array().unwrap();
    assert_eq!(arr.len(), 2);
    assert!(arr.iter().all(|x| x.as_str().unwrap().len() == 64));
}

#[tokio::test]
async fn pool_contains_head_200_when_present() {
    let app = build_compat_app();
    let path = format!("/transactions/unconfirmed/{}", "aa".repeat(32));
    let resp = app
        .oneshot(
            Request::builder()
                .method(axum::http::Method::HEAD)
                .uri(&path)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn pool_contains_head_404_when_absent() {
    let app = build_compat_app();
    let path = format!("/transactions/unconfirmed/{}", "00".repeat(32));
    let resp = app
        .oneshot(
            Request::builder()
                .method(axum::http::Method::HEAD)
                .uri(&path)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// GET on the HEAD-presence path returns 400 with the standard
/// error envelope. Scala 6.0.3RC1 returns 400 here (not the 405
/// axum would surface natively). Parity probe 2026-05-19.
#[tokio::test]
async fn pool_contains_get_returns_400_with_hint() {
    let app = build_compat_app();
    let path = format!("/transactions/unconfirmed/{}", "aa".repeat(32));
    let resp = app
        .oneshot(
            Request::builder()
                .method(axum::http::Method::GET)
                .uri(&path)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        v.get("reason").and_then(|x| x.as_str()),
        Some("deserialize")
    );
    assert!(
        v.get("detail")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .contains("byTransactionId"),
        "detail should hint at the full-tx route: {:?}",
        v.get("detail"),
    );
}

#[tokio::test]
async fn pool_unconfirmed_paged_returns_full_txs() {
    // Default page: stub yields 3 dummy txs.
    let (s, v) = json_get(build_compat_app(), "/transactions/unconfirmed").await;
    assert_eq!(s, StatusCode::OK);
    let arr = v.as_array().unwrap();
    assert_eq!(arr.len(), 3);
    // Each entry must carry the `ScalaTransaction` shape.
    for entry in arr {
        assert!(entry.get("id").and_then(|x| x.as_str()).is_some());
        assert!(entry.get("inputs").is_some());
        assert!(entry.get("outputs").is_some());
        assert!(entry.get("dataInputs").is_some());
        assert!(entry.get("size").is_some());
    }
}

#[tokio::test]
async fn pool_unconfirmed_paged_honours_offset_and_limit() {
    let (s, v) = json_get(
        build_compat_app(),
        "/transactions/unconfirmed?offset=1&limit=1",
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let arr = v.as_array().unwrap();
    assert_eq!(arr.len(), 1, "limit=1 must clip the page");
    // Stub builds ids `00...` `01...` `02...`; offset=1 → second.
    assert!(arr[0]
        .get("id")
        .and_then(|x| x.as_str())
        .unwrap()
        .starts_with("01"));
}

#[tokio::test]
async fn pool_unconfirmed_by_tx_id_200_when_present() {
    let path = format!(
        "/transactions/unconfirmed/byTransactionId/{}",
        "00".repeat(32),
    );
    let (s, v) = json_get(build_compat_app(), &path).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        v.get("id").and_then(|x| x.as_str()),
        Some("00".repeat(32).as_str()),
    );
}

#[tokio::test]
async fn pool_unconfirmed_by_tx_id_404_when_absent() {
    let path = format!(
        "/transactions/unconfirmed/byTransactionId/{}",
        "ee".repeat(32),
    );
    let (s, _v) = json_get(build_compat_app(), &path).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn pool_unconfirmed_by_tx_ids_batch_filters_unresolved() {
    // Body: 3 ids, only the first resolves in the stub.
    let body = serde_json::json!(["00".repeat(32), "ee".repeat(32), "ff".repeat(32)]);
    let resp = build_compat_app()
        .oneshot(
            Request::builder()
                .method(axum::http::Method::POST)
                .uri("/transactions/unconfirmed/byTransactionIds")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let arr = parsed.as_array().unwrap();
    assert_eq!(arr.len(), 1, "only the resolvable id is returned");
}

#[tokio::test]
async fn pool_unconfirmed_size_returns_bare_integer() {
    let (s, v) = json_get(build_compat_app(), "/transactions/unconfirmed/size").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v.as_u64(), Some(3));
}

#[tokio::test]
async fn pool_unconfirmed_by_ergo_tree_returns_matches() {
    // Hex `abcd` decodes to the magic 2-byte tree the stub matches.
    let body = serde_json::Value::String("abcd".into());
    let resp = build_compat_app()
        .oneshot(
            Request::builder()
                .method(axum::http::Method::POST)
                .uri("/transactions/unconfirmed/byErgoTree")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let arr: Vec<serde_json::Value> = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(
        arr[0].get("id").and_then(|v| v.as_str()).unwrap(),
        "01".repeat(32)
    );
}

#[tokio::test]
async fn pool_unconfirmed_by_ergo_tree_empty_for_unmatched_tree() {
    let body = serde_json::Value::String("ff".repeat(32));
    let resp = build_compat_app()
        .oneshot(
            Request::builder()
                .method(axum::http::Method::POST)
                .uri("/transactions/unconfirmed/byErgoTree")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let arr: Vec<serde_json::Value> = serde_json::from_slice(&bytes).unwrap();
    assert!(arr.is_empty());
}

#[tokio::test]
async fn pool_unconfirmed_by_ergo_tree_rejects_bad_hex() {
    // Odd-length / non-hex → 400 deserialize, bridge never invoked.
    let body = serde_json::Value::String("not-hex!".into());
    let resp = build_compat_app()
        .oneshot(
            Request::builder()
                .method(axum::http::Method::POST)
                .uri("/transactions/unconfirmed/byErgoTree")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        v.get("reason").and_then(|x| x.as_str()),
        Some("deserialize")
    );
}

/// `fromJsonOrPlain`: unquoted hex body decodes too. Pins
/// surface consistency with `/transactions/bytes`. `abcd` is
/// not valid JSON (not a recognized JSON token), so the helper
/// falls through to plain-hex parsing.
#[tokio::test]
async fn pool_unconfirmed_by_ergo_tree_accepts_unquoted_hex() {
    let resp = build_compat_app()
        .oneshot(
            Request::builder()
                .method(axum::http::Method::POST)
                .uri("/transactions/unconfirmed/byErgoTree")
                .body(Body::from("abcd"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let arr: Vec<serde_json::Value> = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(arr.len(), 1);
}

/// Non-string JSON (number / array / object / bool / null) must NOT
/// be accepted as plain hex even when the bytes happen to also be
/// valid hex. Body `1234` is both valid hex (`[0x12, 0x34]`) and
/// valid JSON (a number), and the route must take the JSON branch
/// and reject because Scala's `fromJsonOrPlain` does the same.
#[tokio::test]
async fn pool_unconfirmed_by_ergo_tree_rejects_non_string_json() {
    let cases: &[&str] = &[
        "1234",          // JSON number — also valid as hex; reject anyway
        "[1,2,3]",       // JSON array
        "{\"k\":\"v\"}", // JSON object
        "true",          // JSON bool
        "null",          // JSON null
    ];
    for body in cases {
        let resp = build_compat_app()
            .oneshot(
                Request::builder()
                    .method(axum::http::Method::POST)
                    .uri("/transactions/unconfirmed/byErgoTree")
                    .body(Body::from(*body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "body {body:?} should 400 (non-string JSON)",
        );
        let v: serde_json::Value =
            serde_json::from_slice(&to_bytes(resp.into_body(), 1 << 20).await.unwrap()).unwrap();
        assert_eq!(
            v.get("reason").and_then(|x| x.as_str()),
            Some("deserialize")
        );
        let detail = v.get("detail").and_then(|x| x.as_str()).unwrap_or("");
        assert!(
            detail.contains("JSON"),
            "body {body:?} detail should mention JSON shape: {detail}",
        );
    }
}

#[tokio::test]
async fn pool_unconfirmed_by_box_id_returns_matches() {
    let body = serde_json::Value::String("aa".repeat(32));
    let resp = build_compat_app()
        .oneshot(
            Request::builder()
                .method(axum::http::Method::POST)
                .uri("/transactions/unconfirmed/byBoxId")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let arr: Vec<serde_json::Value> =
        serde_json::from_slice(&to_bytes(resp.into_body(), 1 << 20).await.unwrap()).unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(
        arr[0].get("id").and_then(|v| v.as_str()).unwrap(),
        "02".repeat(32)
    );
}

#[tokio::test]
async fn pool_unconfirmed_by_box_id_rejects_wrong_length() {
    // 31-byte hex (62 chars) → 400 deserialize with the length detail.
    let body = serde_json::Value::String("aa".repeat(31));
    let resp = build_compat_app()
        .oneshot(
            Request::builder()
                .method(axum::http::Method::POST)
                .uri("/transactions/unconfirmed/byBoxId")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let v: serde_json::Value =
        serde_json::from_slice(&to_bytes(resp.into_body(), 1 << 20).await.unwrap()).unwrap();
    assert_eq!(
        v.get("reason").and_then(|x| x.as_str()),
        Some("deserialize")
    );
    assert!(v
        .get("detail")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .contains("32 bytes"),);
}

#[tokio::test]
async fn pool_unconfirmed_by_token_id_returns_matches() {
    let body = serde_json::Value::String("bb".repeat(32));
    let resp = build_compat_app()
        .oneshot(
            Request::builder()
                .method(axum::http::Method::POST)
                .uri("/transactions/unconfirmed/byTokenId")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let arr: Vec<serde_json::Value> =
        serde_json::from_slice(&to_bytes(resp.into_body(), 1 << 20).await.unwrap()).unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(
        arr[0].get("id").and_then(|v| v.as_str()).unwrap(),
        "03".repeat(32)
    );
}

#[tokio::test]
async fn pool_unconfirmed_by_registers_returns_matches() {
    let body = serde_json::json!({
        "R4": "0e20".to_string() + &"cc".repeat(32),
    });
    let resp = build_compat_app()
        .oneshot(
            Request::builder()
                .method(axum::http::Method::POST)
                .uri("/transactions/unconfirmed/byRegisters")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let arr: Vec<serde_json::Value> =
        serde_json::from_slice(&to_bytes(resp.into_body(), 1 << 20).await.unwrap()).unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(
        arr[0].get("id").and_then(|v| v.as_str()).unwrap(),
        "04".repeat(32)
    );
}

#[tokio::test]
async fn pool_unconfirmed_by_registers_rejects_malformed_json() {
    let resp = build_compat_app()
        .oneshot(
            Request::builder()
                .method(axum::http::Method::POST)
                .uri("/transactions/unconfirmed/byRegisters")
                .header("content-type", "application/json")
                .body(Body::from("{not json"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let v: serde_json::Value =
        serde_json::from_slice(&to_bytes(resp.into_body(), 1 << 20).await.unwrap()).unwrap();
    assert_eq!(
        v.get("reason").and_then(|x| x.as_str()),
        Some("deserialize")
    );
}

// ----- §10.4 fee stats -----

#[tokio::test]
async fn pool_fee_histogram_returns_default_11_bins() {
    // OpenAPI defaults bins=10, maxtime=60000. Stub returns
    // `bins + 1 = 11` entries.
    let (s, v) = json_get(build_compat_app(), "/transactions/poolHistogram").await;
    assert_eq!(s, StatusCode::OK);
    let arr = v.as_array().expect("histogram is an array");
    assert_eq!(arr.len(), 11, "OpenAPI default bins=10 → 11 entries");
    // Wire-shape: each bin must have `nTxns` and `totalFee` fields
    // (Scala-camelCase). Pins the rename on `ScalaFeeHistogramBin`.
    for bin in arr {
        assert!(bin.get("nTxns").is_some(), "missing nTxns: {bin:?}");
        assert!(bin.get("totalFee").is_some(), "missing totalFee: {bin:?}");
    }
    assert_eq!(arr[0].get("nTxns").and_then(|x| x.as_u64()), Some(12));
    assert_eq!(
        arr[0].get("totalFee").and_then(|x| x.as_u64()),
        Some(1_500_000)
    );
}

#[tokio::test]
async fn pool_fee_histogram_honours_bins_query_param() {
    // bins=3 → 4 entries.
    let (s, v) = json_get(
        build_compat_app(),
        "/transactions/poolHistogram?bins=3&maxtime=60000",
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let arr = v.as_array().expect("histogram is an array");
    assert_eq!(arr.len(), 4);
}

#[tokio::test]
async fn pool_get_fee_returns_bare_integer() {
    // waitTime=5, txSize=200 → stub returns 100 * 200 = 20_000.
    let (s, v) = json_get(
        build_compat_app(),
        "/transactions/getFee?waitTime=5&txSize=200",
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v.as_u64(), Some(20_000));
}

#[tokio::test]
async fn pool_get_fee_defaults_when_query_absent() {
    // No params → waitTime=1, txSize=100 defaults from OpenAPI.
    // Stub's `wait_time_minutes != 5` branch returns tx_size_bytes
    // unmodified — 100.
    let (s, v) = json_get(build_compat_app(), "/transactions/getFee").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v.as_u64(), Some(100));
}

#[tokio::test]
async fn pool_wait_time_returns_bare_integer_ms() {
    // fee=20_000, txSize=200 → fee/byte = 100 → 0 ms.
    let (s, v) = json_get(
        build_compat_app(),
        "/transactions/waitTime?fee=20000&txSize=200",
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v.as_u64(), Some(0));
}

#[tokio::test]
async fn pool_wait_time_for_low_fee_returns_nonzero() {
    // fee=1000, txSize=200 → fee/byte = 5 → 60_000 ms.
    let (s, v) = json_get(
        build_compat_app(),
        "/transactions/waitTime?fee=1000&txSize=200",
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v.as_u64(), Some(60_000));
}

// ----- §10.6 /peers/* reads -----

#[tokio::test]
async fn peers_blacklisted_returns_addresses_envelope() {
    let (s, v) = json_get(build_compat_app(), "/peers/blacklisted").await;
    assert_eq!(s, StatusCode::OK);
    // Scala emits `{"addresses": [...]}` where each entry is Java
    // `InetAddress.toString()` form (`/literal-ip` for raw IPs).
    let addrs = v.get("addresses").and_then(|x| x.as_array()).unwrap();
    assert_eq!(addrs.len(), 2);
    assert_eq!(addrs[0].as_str(), Some("/1.2.3.4"));
    assert_eq!(addrs[1].as_str(), Some("/5.6.7.8"));
}

#[tokio::test]
async fn peers_sync_info_returns_observed_peers_only() {
    // Stub returns three peers with three different statuses. The
    // bridge contract is "only peers with a real SyncInfo
    // observation appear"; the stub mirrors that.
    let (s, v) = json_get(build_compat_app(), "/peers/syncInfo").await;
    assert_eq!(s, StatusCode::OK);
    let arr = v.as_array().unwrap();
    assert_eq!(arr.len(), 3);
    // Verify all three statuses surface with the Scala-exact
    // PeerChainStatus stringification.
    let statuses: Vec<&str> = arr
        .iter()
        .map(|e| e.get("status").and_then(|x| x.as_str()).unwrap())
        .collect();
    assert!(statuses.contains(&"Equal"));
    assert!(statuses.contains(&"Younger"));
    assert!(statuses.contains(&"Older"));
}

#[tokio::test]
async fn peers_track_info_returns_counter_envelope() {
    let (s, v) = json_get(build_compat_app(), "/peers/trackInfo").await;
    assert_eq!(s, StatusCode::OK);
    // Pin the Scala serde rename direction.
    assert_eq!(v.get("numRequested").and_then(|x| x.as_u64()), Some(12));
    assert_eq!(v.get("numReceived").and_then(|x| x.as_u64()), Some(100));
    assert_eq!(v.get("numFailed").and_then(|x| x.as_u64()), Some(3));
}

#[tokio::test]
async fn peers_status_returns_freshness_probe() {
    let (s, v) = json_get(build_compat_app(), "/peers/status").await;
    assert_eq!(s, StatusCode::OK);
    // Scala field names exactly: `lastIncomingMessage` /
    // `currentSystemTime`. Pin the rename so a future serde
    // refactor doesn't drift.
    assert_eq!(
        v.get("lastIncomingMessage").and_then(|x| x.as_u64()),
        Some(1_700_000_000_000)
    );
    assert_eq!(
        v.get("currentSystemTime").and_then(|x| x.as_u64()),
        Some(1_700_000_001_000)
    );
}

/// Route-shadowing pin: the wildcard
/// `/transactions/unconfirmed/:tx_id` (HEAD presence probe; GET
/// returns 400 with a hint envelope) must NOT shadow the static-
/// segment routes `transactionIds`, `byTransactionIds`, `size`, nor
/// the longer `byTransactionId/:tx_id` GET route. Each fixed segment
/// must dispatch to its own handler.
#[tokio::test]
async fn pool_unconfirmed_route_shadowing_does_not_capture_static_segments() {
    let app = build_compat_app();
    // `transactionIds` is a static segment; should NOT be matched
    // as `:tx_id` by the HEAD route.
    let (s, _v) = json_get(app, "/transactions/unconfirmed/transactionIds").await;
    assert_eq!(
        s,
        StatusCode::OK,
        "static transactionIds segment must reach pool_tx_ids_handler",
    );

    // `byTransactionIds` is a static segment; POST should reach
    // batch handler, NOT trip on HEAD-route :tx_id.
    let body = serde_json::json!(["00".repeat(32)]);
    let resp = build_compat_app()
        .oneshot(
            Request::builder()
                .method(axum::http::Method::POST)
                .uri("/transactions/unconfirmed/byTransactionIds")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "POST byTransactionIds must reach batch handler",
    );

    // `byTransactionId/{id}` is longer than `:tx_id`; should still
    // dispatch to the by-id handler.
    let path = format!(
        "/transactions/unconfirmed/byTransactionId/{}",
        "00".repeat(32),
    );
    let (s, _v) = json_get(build_compat_app(), &path).await;
    assert_eq!(
        s,
        StatusCode::OK,
        "byTransactionId/:id must reach by-id handler"
    );

    // `size` is a static segment.
    let (s, _v) = json_get(build_compat_app(), "/transactions/unconfirmed/size").await;
    assert_eq!(s, StatusCode::OK, "size segment must reach size handler");
}

#[tokio::test]
async fn new_blocks_routes_404_when_compat_disabled() {
    let read: Arc<dyn NodeReadState> = Arc::new(StubReadState);
    let app = router(
        read,
        None,
        None,
        None,
        ergo_ser::address::NetworkPrefix::Mainnet,
    );
    for path in [
        "/blocks",
        "/blocks/chainSlice",
        "/blocks/lastHeaders/3",
        &format!("/blocks/{HEADER_ID_HEX_AA}/header"),
        &format!("/blocks/{HEADER_ID_HEX_AA}/transactions"),
    ] {
        let (s, _) = json_get(app.clone(), path).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{path} must 404 without compat");
    }
}

// ---- /utxo parity (UtxoApiRoute.scala:65-89) ----

#[tokio::test]
async fn utxo_by_id_returns_known_box_with_scala_shape() {
    let path = format!("/utxo/byId/{}", "cc".repeat(32));
    let (s, v) = json_get(build_compat_app(), &path).await;
    assert_eq!(s, StatusCode::OK);
    let obj = v.as_object().expect("byId is object");
    for k in [
        "boxId",
        "value",
        "ergoTree",
        "assets",
        "creationHeight",
        "additionalRegisters",
        "transactionId",
        "index",
    ] {
        assert!(obj.contains_key(k), "missing scala field {k}");
    }
    assert_eq!(
        obj.get("boxId").and_then(|x| x.as_str()),
        Some("cc".repeat(32).as_str())
    );
    assert_eq!(
        obj.get("value").and_then(|x| x.as_u64()),
        Some(1_000_000_000)
    );
}

#[tokio::test]
async fn utxo_by_id_404s_unknown_box() {
    let path = format!("/utxo/byId/{}", "00".repeat(32));
    let (s, _) = json_get(build_compat_app(), &path).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn utxo_by_id_404s_malformed_hex() {
    // Scala's `Base16.decode(id).get` throws on bad hex; at the route
    // level the failure surfaces as a not-found, not a 400. The handler
    // path goes via `parse_box_id` which returns `None` for non-64-hex
    // strings, and the trait-level `None` → 404 envelope follows.
    let (s, _) = json_get(build_compat_app(), "/utxo/byId/zz").await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn utxo_by_id_binary_returns_envelope_with_known_box() {
    let path = format!("/utxo/byIdBinary/{}", "cc".repeat(32));
    let (s, v) = json_get(build_compat_app(), &path).await;
    assert_eq!(s, StatusCode::OK);
    let obj = v.as_object().expect("byIdBinary is object");
    assert_eq!(
        obj.get("boxId").and_then(|x| x.as_str()),
        Some("cc".repeat(32).as_str())
    );
    assert_eq!(obj.get("bytes").and_then(|x| x.as_str()), Some("deadbeef"));
    // Scala emits exactly two keys; nothing else should leak in.
    assert_eq!(obj.len(), 2, "envelope must be {{boxId, bytes}} only");
}

#[tokio::test]
async fn utxo_by_id_binary_404s_unknown_box() {
    let path = format!("/utxo/byIdBinary/{}", "00".repeat(32));
    let (s, _) = json_get(build_compat_app(), &path).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn utxo_genesis_returns_array_always_200() {
    let (s, v) = json_get(build_compat_app(), "/utxo/genesis").await;
    assert_eq!(s, StatusCode::OK);
    let arr = v.as_array().expect("genesis is array");
    assert_eq!(arr.len(), 3, "stub returns three boxes");
    let first = arr[0].as_object().unwrap();
    assert!(first.contains_key("boxId"));
    assert!(first.contains_key("value"));
    assert!(first.contains_key("ergoTree"));
}

#[tokio::test]
async fn utxo_get_snapshots_info_returns_empty_manifests_when_none_cached() {
    // Scala `UtxoApiRoute.getSnapshotsInfo` serves the locally-stored
    // snapshot set. This build's serve cache is empty at boot (in-memory
    // only) and StubCompat carries no snapshot view, so the response is
    // the empty container — value-identical to a Scala UTXO node that has
    // taken no snapshots: {"availableManifests": {}}.
    let (s, v) = json_get(build_compat_app(), "/utxo/getSnapshotsInfo").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v, serde_json::json!({ "availableManifests": {} }));
}

#[tokio::test]
async fn utxo_get_snapshots_info_renders_the_served_manifest() {
    // When the bridge exposes a cached serve-side snapshot (the Mode-2
    // build at a 52,224 boundary), the REST view must report it — the
    // same data the P2P `SnapshotsInfo` reply serves, so wire and REST
    // can never disagree.
    struct SnapshotCompat;
    impl NodeChainQuery for SnapshotCompat {
        fn info(&self) -> ergo_api::compat::types::ScalaInfo {
            StubCompat.info()
        }
        fn header_ids_at_height(&self, h: u32) -> Vec<String> {
            StubCompat.header_ids_at_height(h)
        }
        fn full_block_by_id(&self, id: &str) -> Option<ergo_api::compat::types::ScalaFullBlock> {
            StubCompat.full_block_by_id(id)
        }
        fn snapshots_info(&self) -> Vec<(i32, String)> {
            vec![(52_224, "ab".repeat(32))]
        }
    }
    let compat: Arc<dyn NodeChainQuery> = Arc::new(SnapshotCompat);
    let read: Arc<dyn NodeReadState> = Arc::new(StubReadState);
    let app = router(
        read,
        Some(compat),
        None,
        None,
        ergo_ser::address::NetworkPrefix::Mainnet,
    );
    let (s, v) = json_get(app, "/utxo/getSnapshotsInfo").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        v,
        serde_json::json!({ "availableManifests": { "52224": "ab".repeat(32) } }),
        "height-keyed map, hex manifest id — Scala SnapshotInfoEncoder shape",
    );
}

#[tokio::test]
async fn utxo_routes_404_when_compat_disabled() {
    let read: Arc<dyn NodeReadState> = Arc::new(StubReadState);
    let app = router(
        read,
        None,
        None,
        None,
        ergo_ser::address::NetworkPrefix::Mainnet,
    );
    for path in [
        "/utxo/genesis",
        "/utxo/getSnapshotsInfo",
        &format!("/utxo/byId/{}", "cc".repeat(32)),
        &format!("/utxo/byIdBinary/{}", "cc".repeat(32)),
        &format!("/utxo/withPool/byId/{}", "aa".repeat(32)),
        &format!("/utxo/withPool/byIdBinary/{}", "aa".repeat(32)),
    ] {
        let (s, _) = json_get(app.clone(), path).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{path} must 404 without compat");
    }
}

// ---- /utxo/withPool parity (UtxoApiRoute.scala:33-63, UtxoStateReader.scala:164-172) ----

/// `withPool/byId` returns committed UTXOs unchanged. The overlay rule
/// is purely additive — pool data must never alter what the chain store
/// reports for an already-committed box.
#[tokio::test]
async fn utxo_with_pool_by_id_returns_committed_box_unchanged() {
    let path = format!("/utxo/withPool/byId/{}", "cc".repeat(32));
    let (s, v) = json_get(build_compat_app(), &path).await;
    assert_eq!(s, StatusCode::OK);
    let obj = v.as_object().expect("object");
    assert_eq!(
        obj.get("boxId").and_then(|x| x.as_str()),
        Some("cc".repeat(32).as_str())
    );
    // Same value the committed-only `/utxo/byId` returns.
    assert_eq!(
        obj.get("value").and_then(|x| x.as_u64()),
        Some(1_000_000_000)
    );
}

/// Pool-only id is returned only via the overlay endpoint. Confirms
/// the overlay actually exists (a buggy bridge that always falls through
/// to the chain store would 404 here).
#[tokio::test]
async fn utxo_with_pool_by_id_returns_pool_only_box() {
    let path = format!("/utxo/withPool/byId/{}", "aa".repeat(32));
    let (s, v) = json_get(build_compat_app(), &path).await;
    assert_eq!(s, StatusCode::OK);
    let obj = v.as_object().expect("object");
    assert_eq!(
        obj.get("boxId").and_then(|x| x.as_str()),
        Some("aa".repeat(32).as_str())
    );
    assert_eq!(obj.get("value").and_then(|x| x.as_u64()), Some(500_000_000));
}

/// The pool-only id is NOT visible through the committed-only endpoint —
/// pins the boundary between `/utxo/byId` and `/utxo/withPool/byId`.
#[tokio::test]
async fn utxo_by_id_does_not_see_pool_only_box() {
    let path = format!("/utxo/byId/{}", "aa".repeat(32));
    let (s, _) = json_get(build_compat_app(), &path).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn utxo_with_pool_by_id_404s_unknown_box() {
    let path = format!("/utxo/withPool/byId/{}", "00".repeat(32));
    let (s, _) = json_get(build_compat_app(), &path).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn utxo_with_pool_by_id_404s_malformed_hex() {
    let (s, _) = json_get(build_compat_app(), "/utxo/withPool/byId/zz").await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn utxo_with_pool_by_id_binary_returns_envelope_for_pool_box() {
    let path = format!("/utxo/withPool/byIdBinary/{}", "aa".repeat(32));
    let (s, v) = json_get(build_compat_app(), &path).await;
    assert_eq!(s, StatusCode::OK);
    let obj = v.as_object().expect("envelope is object");
    assert_eq!(
        obj.get("boxId").and_then(|x| x.as_str()),
        Some("aa".repeat(32).as_str())
    );
    assert_eq!(obj.get("bytes").and_then(|x| x.as_str()), Some("feedface"));
    assert_eq!(obj.len(), 2, "envelope must be {{boxId, bytes}} only");
}

#[tokio::test]
async fn utxo_with_pool_by_id_binary_returns_committed_envelope() {
    let path = format!("/utxo/withPool/byIdBinary/{}", "cc".repeat(32));
    let (s, v) = json_get(build_compat_app(), &path).await;
    assert_eq!(s, StatusCode::OK);
    let obj = v.as_object().expect("envelope");
    // Committed wins → bytes match the chain-store path.
    assert_eq!(obj.get("bytes").and_then(|x| x.as_str()), Some("deadbeef"));
}

#[tokio::test]
async fn utxo_with_pool_by_id_binary_404s_unknown_box() {
    let path = format!("/utxo/withPool/byIdBinary/{}", "00".repeat(32));
    let (s, _) = json_get(build_compat_app(), &path).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

/// `byIds` is POST. Confirms axum dispatches by method and the body shape
/// matches Scala's `Seq[String]`. Misses are silently dropped.
#[tokio::test]
async fn utxo_with_pool_by_ids_returns_only_resolved_boxes() {
    let body = serde_json::json!([
        "cc".repeat(32), // committed → resolved
        "aa".repeat(32), // pool      → resolved
        "00".repeat(32), // unknown   → dropped
        "zz",            // bad hex   → dropped
    ]);
    let (s, v) = json_post(build_compat_app(), "/utxo/withPool/byIds", &body).await;
    assert_eq!(s, StatusCode::OK);
    let arr = v.as_array().expect("array");
    assert_eq!(arr.len(), 2, "only the two known ids must come back");
    let ids: Vec<&str> = arr
        .iter()
        .filter_map(|b| b.get("boxId").and_then(|x| x.as_str()))
        .collect();
    assert!(ids.contains(&"cc".repeat(32).as_str()));
    assert!(ids.contains(&"aa".repeat(32).as_str()));
}

#[tokio::test]
async fn utxo_with_pool_by_ids_empty_input_returns_empty_array() {
    let body = serde_json::json!([]);
    let (s, v) = json_post(build_compat_app(), "/utxo/withPool/byIds", &body).await;
    assert_eq!(s, StatusCode::OK);
    let arr = v.as_array().expect("array");
    assert!(arr.is_empty());
}

#[tokio::test]
async fn utxo_with_pool_by_ids_404s_when_compat_disabled() {
    let read: Arc<dyn NodeReadState> = Arc::new(StubReadState);
    let app = router(
        read,
        None,
        None,
        None,
        ergo_ser::address::NetworkPrefix::Mainnet,
    );
    let body = serde_json::json!(["aa".repeat(32)]);
    let (s, _) = json_post(app, "/utxo/withPool/byIds", &body).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

// ---- /utxo/* mode-aware predicate (Mode 5 digest backend) ----------

/// Build the compat app with the digest backend's
/// `utxo_reads_supported = false`. The seven `/utxo/*` Scala routes
/// are replaced with a single wildcard returning
/// 503 + Scala-parity body.
fn build_compat_app_digest_backend() -> axum::Router {
    use ergo_api::server::router_with_mempool;
    let read: Arc<dyn NodeReadState> = Arc::new(StubReadState);
    let compat: Arc<dyn NodeChainQuery> = Arc::new(StubCompat);
    router_with_mempool(
        ergo_api::ServerCtx {
            read,
            compat: Some(compat),
            submit: None,
            indexer: None,
            mempool: Arc::new(ergo_api::NoopMempoolView::new()),
            network: ergo_ser::address::NetworkPrefix::Mainnet,
            chain_params: None,
            mining: None,
            emission: None,
            emission_scripts: None,
            utxo_reads_supported: false,
        },
        None,
    )
}

#[tokio::test]
async fn utxo_genesis_returns_503_under_digest_backend() {
    let (s, v) = json_get(build_compat_app_digest_backend(), "/utxo/genesis").await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(v.get("error").and_then(|x| x.as_u64()), Some(503));
    assert_eq!(
        v.get("reason").and_then(|x| x.as_str()),
        Some("Lookup is not supported for stateType=digest"),
    );
}

#[tokio::test]
async fn utxo_by_id_returns_503_under_digest_backend() {
    let path = format!("/utxo/byId/{}", "aa".repeat(32));
    let (s, v) = json_get(build_compat_app_digest_backend(), &path).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(v.get("error").and_then(|x| x.as_u64()), Some(503));
}

#[tokio::test]
async fn utxo_with_pool_by_ids_returns_503_under_digest_backend() {
    let body = serde_json::json!([]);
    let (s, v) = json_post(
        build_compat_app_digest_backend(),
        "/utxo/withPool/byIds",
        &body,
    )
    .await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(v.get("error").and_then(|x| x.as_u64()), Some(503));
}

#[tokio::test]
async fn non_utxo_routes_still_mount_under_digest_backend() {
    // The digest-backend gate ONLY replaces /utxo/*; every other
    // Scala-compat route still mounts. Confirm via a /blocks/...
    // route that exercises StubCompat and asserts a non-503 response.
    let path = format!("/blocks/{HEADER_ID_HEX_AA}/header");
    let (s, _) = json_get(build_compat_app_digest_backend(), &path).await;
    assert_ne!(s, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(s, StatusCode::OK);
}

#[tokio::test]
async fn snapshots_info_503s_under_digest_backend() {
    // Same posture as the rest of the digest /utxo arm. (Known Scala
    // oracle, derivable from source: digest state isn't a
    // UtxoSetSnapshotPersistence, so Scala's `case _ => None` becomes a
    // 404 not-found via ApiResponse — the blanket 503 is the
    // pre-existing documented /utxo digest divergence.)
    let (s, _) = json_get(build_compat_app_digest_backend(), "/utxo/getSnapshotsInfo").await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn unknown_utxo_subpath_still_404s_under_digest_backend() {
    // The digest-backend mount is the SAME seven (path, method)
    // shapes as Mode 1, just with the 503 handler. An unknown
    // `/utxo/...` subpath that doesn't match any of the seven routes
    // must still 404 — not be swallowed by an over-broad wildcard.
    // Mirrors Mode 1 behavior for unknown routes.
    let (s, _) = json_get(build_compat_app_digest_backend(), "/utxo/nonexistent").await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn wrong_method_on_utxo_route_still_405s_under_digest_backend() {
    // POST on `/utxo/byId/:box_id` (a GET-only route) must still
    // surface as 405 Method Not Allowed, not get rerouted to the
    // 503 handler. Confirms the digest mount preserves the per-
    // method registration shape that the live Mode 1 routes use.
    let path = format!("/utxo/byId/{}", "aa".repeat(32));
    let body = serde_json::json!({});
    let (s, _) = json_post(build_compat_app_digest_backend(), &path, &body).await;
    assert_eq!(s, StatusCode::METHOD_NOT_ALLOWED);
}

// ---- blocks-parity (PR1/PR2/PR3) — route-mounting layout ------------

#[tokio::test]
async fn post_blocks_header_ids_mounted_under_compat() {
    let body = serde_json::json!([HEADER_ID_HEX_AA]);
    let (s, v) = json_post(build_compat_app(), "/blocks/headerIds", &body).await;
    assert_eq!(s, StatusCode::OK);
    assert!(v.is_array(), "POST /blocks/headerIds returns a JSON array");
}

#[tokio::test]
async fn post_blocks_header_ids_404s_when_compat_disabled() {
    let read: Arc<dyn NodeReadState> = Arc::new(StubReadState);
    let app = router(
        read,
        None,
        None,
        None,
        ergo_ser::address::NetworkPrefix::Mainnet,
    );
    let body = serde_json::json!([HEADER_ID_HEX_AA]);
    let (s, _) = json_post(app, "/blocks/headerIds", &body).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn get_blocks_modifier_mounted_under_compat() {
    let path = format!("/blocks/modifier/{HEADER_ID_HEX_AA}");
    let (s, _) = json_get(build_compat_app(), &path).await;
    assert_eq!(s, StatusCode::OK);
}

#[tokio::test]
async fn get_blocks_modifier_404s_when_compat_disabled() {
    let read: Arc<dyn NodeReadState> = Arc::new(StubReadState);
    let app = router(
        read,
        None,
        None,
        None,
        ergo_ser::address::NetworkPrefix::Mainnet,
    );
    let path = format!("/blocks/modifier/{HEADER_ID_HEX_AA}");
    let (s, _) = json_get(app, &path).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn get_blocks_proof_for_tx_mounted_under_compat() {
    let tx = "ab".repeat(32);
    let path = format!("/blocks/{HEADER_ID_HEX_AA}/proofFor/{tx}");
    let (s, v) = json_get(build_compat_app(), &path).await;
    assert_eq!(s, StatusCode::OK);
    // Wire shape: {leafData, levels}.
    assert!(v.get("leafData").is_some());
    assert!(v.get("levels").is_some());
}

#[tokio::test]
async fn get_blocks_proof_for_tx_404s_when_compat_disabled() {
    let read: Arc<dyn NodeReadState> = Arc::new(StubReadState);
    let app = router(
        read,
        None,
        None,
        None,
        ergo_ser::address::NetworkPrefix::Mainnet,
    );
    let tx = "ab".repeat(32);
    let path = format!("/blocks/{HEADER_ID_HEX_AA}/proofFor/{tx}");
    let (s, _) = json_get(app, &path).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}
