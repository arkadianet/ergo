//! `GET /blockchain/box/byId/{id}` and `GET /blockchain/box/byIndex/{n}`.
//!
//! These tests focus on the routing primitives and the status-gate
//! middleware contract. The wire-shape success-path test (round-trip an
//! `IndexedErgoBox` from a real `IndexerStore`) lives with the
//! corpus-backed integration suite where the indexer DB is loaded from
//! the 700k–700200 mainnet fixture.
//!
//! What this file pins:
//! - `Syncing` returns the pinned `503 indexer-syncing` envelope with
//!   exact field set + body bytes deterministic given (`indexed_height`,
//!   `best_full_block_height`).
//! - `Halted(reason)` returns the `503 indexer-halted` envelope; the
//!   `<reason>` substitution is the kebab-case form of `IndexerHaltReason`.
//! - `CaughtUp` lets the handler run; with no record in the (None) store
//!   the handler emits the canonical `404 not-found` envelope.
//! - Negative byIndex values short-circuit to 404 (i64 → u64 guard).
//! - Malformed byId hex (wrong length, non-hex chars) maps to 404 — Scala's
//!   "Option-driven not found" pattern conflates parse failure with miss.
//!
//! Test wiring: `IndexerHandle::syncing()` / `::halted()` are the existing
//! store-less constructors; their `box_by_id` / `box_by_global_index`
//! always return `None`, which is exactly what we want for testing the
//! gate + miss paths in isolation.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ergo_api::server::router;
use ergo_api::traits::NodeReadState;
use ergo_api::types::{
    ApiFullBlockRef, ApiHeaderRef, ApiHealth, ApiInfo, ApiMempoolSummary, ApiMempoolTransaction,
    ApiMempoolTransactions, ApiPeer, ApiStatus, ApiSyncStatus, ApiTip, ApiWeightFunction,
    HealthStatus, SyncStateLabel,
};
use ergo_indexer::{IndexerHaltReason, IndexerHandle, IndexerQuery, IndexerStatus};
use http_body_util::BodyExt;
use tower::ServiceExt;

const HEX_64_AA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

// ---------- gate: Syncing → 503 indexer-syncing -------------------------

#[tokio::test]
async fn box_by_id_503_indexer_syncing_pins_envelope() {
    let app = build_app(|| {
        let h = IndexerHandle::syncing(500);
        h.set_status(IndexerStatus::Syncing);
        h
    });
    let (status, body) = json_get(app, &format!("/blockchain/box/byId/{HEX_64_AA}")).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], 503);
    assert_eq!(body["reason"], "indexer-syncing");
    // Detail substitution: indexed_height=500 (handle), full_height=1234 (read).
    assert_eq!(body["detail"], "indexer at height 500, target 1234");
}

#[tokio::test]
async fn box_by_index_503_indexer_syncing_pins_envelope() {
    let app = build_app(|| IndexerHandle::syncing(0));
    let (status, body) = json_get(app, "/blockchain/box/byIndex/42").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], 503);
    assert_eq!(body["reason"], "indexer-syncing");
    assert_eq!(body["detail"], "indexer at height 0, target 1234");
}

// ---------- gate: Halted → 503 indexer-halted ---------------------------

#[tokio::test]
async fn box_by_id_503_indexer_halted_pins_envelope_db_corruption() {
    let app = build_app(|| IndexerHandle::halted(IndexerHaltReason::DbCorruption));
    let (status, body) = json_get(app, &format!("/blockchain/box/byId/{HEX_64_AA}")).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], 503);
    assert_eq!(body["reason"], "indexer-halted");
    assert_eq!(body["detail"], "indexer halted: db-corruption");
}

#[tokio::test]
async fn box_by_index_503_indexer_halted_pins_envelope_undo_missing() {
    let app = build_app(|| IndexerHandle::halted(IndexerHaltReason::UndoMissing));
    let (status, body) = json_get(app, "/blockchain/box/byIndex/0").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], 503);
    assert_eq!(body["reason"], "indexer-halted");
    assert_eq!(body["detail"], "indexer halted: undo-missing");
}

#[tokio::test]
async fn halt_reason_kebab_case_covers_every_variant() {
    // The error-envelope contract pins the exact set of `<reason>`
    // substitutions. If a future variant lands without a kebab-case
    // mapping the
    // `as_kebab_case` panic would be silent in production — this
    // test exists to catch it.
    let cases = [
        (IndexerHaltReason::DbCorruption, "db-corruption"),
        (IndexerHaltReason::UndoMissing, "undo-missing"),
        (IndexerHaltReason::SectionMissing, "section-missing"),
        (IndexerHaltReason::InputMissing, "input-missing"),
        (IndexerHaltReason::SchemaCorruption, "schema-corruption"),
    ];
    for (reason, expected) in cases {
        let app = build_app(move || IndexerHandle::halted(reason));
        let (status, body) = json_get(app, &format!("/blockchain/box/byId/{HEX_64_AA}")).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            body["detail"],
            format!("indexer halted: {expected}"),
            "halt reason {reason:?} must serialize as {expected:?} in the error envelope"
        );
    }
}

// ---------- gate passthrough: CaughtUp → handler runs -------------------

#[tokio::test]
async fn box_by_id_404_when_caught_up_and_record_absent() {
    let app = build_app(|| {
        let h = IndexerHandle::syncing(700_000);
        h.set_status(IndexerStatus::CaughtUp);
        h
    });
    let (status, body) = json_get(app, &format!("/blockchain/box/byId/{HEX_64_AA}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"], 404);
    assert_eq!(body["reason"], "not-found");
    assert_eq!(body["detail"], "box not found");
}

#[tokio::test]
async fn box_by_index_404_when_caught_up_and_record_absent() {
    let app = build_app(|| {
        let h = IndexerHandle::syncing(700_000);
        h.set_status(IndexerStatus::CaughtUp);
        h
    });
    let (status, body) = json_get(app, "/blockchain/box/byIndex/123456789").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["reason"], "not-found");
}

// ---------- input validation ---------------------------------------------

#[tokio::test]
async fn box_by_id_404_on_malformed_hex_short() {
    let app = build_app(caught_up);
    let (status, body) = json_get(app, "/blockchain/box/byId/aabbcc").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["reason"], "not-found");
}

#[tokio::test]
async fn box_by_id_404_on_malformed_hex_nonhex_chars() {
    let app = build_app(caught_up);
    // 64 chars but contains 'z'.
    let bad = format!("z{}", &HEX_64_AA[1..]);
    let (status, _) = json_get(app, &format!("/blockchain/box/byId/{bad}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn box_by_index_404_on_negative_value() {
    let app = build_app(caught_up);
    // axum's `:n` extractor accepts negative i64 because we typed it
    // as i64. The handler must reject sub-zero before casting to u64.
    let (status, body) = json_get(app, "/blockchain/box/byIndex/-1").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["reason"], "not-found");
}

// ---------- helpers ------------------------------------------------------

fn caught_up() -> IndexerHandle {
    let h = IndexerHandle::syncing(700_000);
    h.set_status(IndexerStatus::CaughtUp);
    h
}

fn build_app<F>(make: F) -> axum::Router
where
    F: FnOnce() -> IndexerHandle,
{
    let read: Arc<dyn NodeReadState> = Arc::new(StubReadState { full_height: 1234 });
    let indexer: Arc<dyn IndexerQuery> = Arc::new(make());
    router(
        read,
        None,
        None,
        Some(indexer),
        ergo_ser::address::NetworkPrefix::Mainnet,
    )
}

async fn json_get(app: axum::Router, path: &str) -> (StatusCode, serde_json::Value) {
    let resp = app
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let value = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    };
    (status, value)
}

struct StubReadState {
    full_height: u32,
}

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
            best_header_height: self.full_height,
            best_full_block_height: self.full_height,
            headers_ahead_of_full_blocks: 0,
            mempool_size: 0,
            snapshot_age_ms: 0,
            bootstrap: None,
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
