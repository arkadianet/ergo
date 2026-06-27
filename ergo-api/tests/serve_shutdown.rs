//! `serve_on` graceful-shutdown wiring contract.
//!
//! Load-bearing assertion: when `shutdown_rx` resolves, the spawned
//! axum task must complete naturally without an external `abort()`.
//! Without `with_graceful_shutdown` wired, `axum::serve(listener, app)`
//! runs the accept loop indefinitely — only `abort()` (or a listener
//! error) would ever surface the JoinHandle as Ready. So this test
//! deterministically pins the wiring: if a future change drops
//! `with_graceful_shutdown`, `tokio::time::timeout` below fires and
//! the test fails.
//!
//! The integration-level shutdown test in
//! `ergo-node/tests/submit_e2e.rs` can't differentiate graceful drain
//! from abort-with-timeout because the handler completes on the
//! closed-channel path before the timeout fires. This unit test
//! removes the action loop from the picture and checks the API-level
//! wiring directly.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ergo_api::server::{serve, serve_on};
use ergo_api::traits::NodeReadState;
use ergo_api::types::{
    ApiFullBlockRef, ApiHeaderRef, ApiHealth, ApiInfo, ApiMempoolSummary, ApiMempoolTransaction,
    ApiMempoolTransactions, ApiPeer, ApiStatus, ApiSyncStatus, ApiTip, ApiWeightFunction,
    HealthStatus, SyncStateLabel,
};

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

#[tokio::test]
async fn serve_on_completes_naturally_when_shutdown_signal_fires() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let read: Arc<dyn NodeReadState> = Arc::new(StubReadState);
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();

    let handle = serve_on(
        read,
        None,
        None,
        None,
        ergo_ser::address::NetworkPrefix::Mainnet,
        true,
        listener,
        rx,
    );

    // Fire the shutdown signal. With `with_graceful_shutdown` wired,
    // the inner future resolves and axum exits the accept loop, then
    // (with no in-flight connections) the task completes.
    let _ = tx.send(());

    // Bound timeout: this is the load-bearing assertion. Without
    // graceful shutdown wired, the task runs forever and the timeout
    // fires.
    let result = tokio::time::timeout(Duration::from_secs(2), handle).await;
    let join_result = result.expect(
        "serve_on must complete within 2s of `shutdown_rx` firing — \
         a hang here means `with_graceful_shutdown` was dropped or never wired \
         (axum::serve runs the accept loop indefinitely without it)",
    );
    join_result.expect("axum task should not panic on graceful shutdown");
}

#[tokio::test]
async fn serve_wrapper_forwards_shutdown_signal_to_serve_on() {
    // `serve` is a thin wrapper: `bind(addr).await + serve_on(...)`.
    // The wiring proof for `serve_on` covers the load-bearing
    // `with_graceful_shutdown` call, but the wrapper still owns the
    // shutdown_rx handoff: prior coverage hit only `serve_on`
    // directly, so a future change that dropped the shutdown_rx
    // parameter from `serve` (or stopped forwarding it) would slip
    // through. This test pins the wrapper contract.
    let read: Arc<dyn NodeReadState> = Arc::new(StubReadState);
    let addr: SocketAddr = "127.0.0.1:0".parse().expect("parse loopback addr");
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();

    let (_bound_addr, handle) = serve(
        read,
        None,
        None,
        None,
        ergo_ser::address::NetworkPrefix::Mainnet,
        true,
        addr,
        rx,
    )
    .await
    .expect("serve must bind ephemeral port");

    let _ = tx.send(());

    let result = tokio::time::timeout(Duration::from_secs(2), handle).await;
    let join_result = result.expect(
        "serve must complete within 2s of `shutdown_rx` firing — \
         hang here means the wrapper isn't forwarding shutdown_rx to serve_on",
    );
    join_result.expect("axum task should not panic on graceful shutdown via serve()");
}

#[tokio::test]
async fn serve_on_completes_when_shutdown_sender_is_dropped() {
    // Symmetric: dropping the sender is also a shutdown signal because
    // `shutdown_rx.await` resolves with `RecvError`. The shutdown
    // future inside `with_graceful_shutdown` ignores the result and
    // proceeds to drain. Exercises the same wiring through the
    // sender-dropped path that an embedder might trigger by simply
    // dropping their side of the oneshot.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let read: Arc<dyn NodeReadState> = Arc::new(StubReadState);
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();

    let handle = serve_on(
        read,
        None,
        None,
        None,
        ergo_ser::address::NetworkPrefix::Mainnet,
        true,
        listener,
        rx,
    );

    drop(tx);

    let result = tokio::time::timeout(Duration::from_secs(2), handle).await;
    let join_result = result.expect(
        "serve_on must complete within 2s when the shutdown sender is dropped — \
         hang here means the RecvError branch isn't being treated as a shutdown signal",
    );
    join_result.expect("axum task should not panic on sender-dropped shutdown");
}
