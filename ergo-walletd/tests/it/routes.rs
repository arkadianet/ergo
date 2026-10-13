use std::sync::Arc;
use std::time::Duration;

use axum::body::to_bytes;
use axum::http::{Method, StatusCode};
use ergo_wallet_service::{ChainClient, RedbWalletStore, WalletService};
use tower::ServiceExt;

use ergo_walletd::api::{router, ApiContext, READ_ROUTE_INVENTORY};
use ergo_walletd::config::Network;
use ergo_walletd::tip::CachedNodeTip;

use crate::support::NoChain;

fn app(dir: &tempfile::TempDir) -> axum::Router {
    app_with_network(dir, Network::Mainnet)
}

fn app_with_network(dir: &tempfile::TempDir, network: Network) -> axum::Router {
    let store = Arc::new(RedbWalletStore::open_standalone(dir.path().join("wallet.redb")).unwrap());
    let chain: Arc<dyn ChainClient> = Arc::new(NoChain);
    router(ApiContext {
        service: Arc::new(WalletService::new(store, chain.clone())),
        network,
        tip: Arc::new(CachedNodeTip::new(chain)),
        tip_max_age: ApiContext::default_tip_max_age(Duration::from_secs(15)),
    })
}

#[tokio::test]
async fn read_route_inventory_is_the_only_mounted_surface() {
    let dir = tempfile::tempdir().unwrap();
    for route in READ_ROUTE_INVENTORY {
        let path = route.replace(":id", &"11".repeat(32));
        let response = app(&dir)
            .oneshot(
                axum::http::Request::builder()
                    .method(Method::POST)
                    .uri(&path)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED, "{route}");
    }
    for route in [
        "/unlock",
        "/init",
        "/restore",
        "/send",
        "/sign",
        "/private-key",
        "/multisig",
        "/ws",
        "/api/v1/wallet/unlock",
        "/api/v1/wallet/init",
        "/api/v1/wallet/restore",
        "/api/v1/wallet/send",
        "/api/v1/wallet/sign",
        "/api/v1/wallet/private-key",
        "/api/v1/wallet/multisig",
        "/api/v1/wallet/ws",
        "/api/v1/wallet/lock",
    ] {
        let response = app(&dir)
            .oneshot(
                axum::http::Request::builder()
                    .uri(route)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{route}");
    }
}

#[tokio::test]
async fn reads_use_protocol_pages_and_status_contains_durable_identity() {
    let dir = tempfile::tempdir().unwrap();
    let response = app(&dir)
        .oneshot(
            axum::http::Request::builder()
                .uri("/api/v1/wallet/status")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let value: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 1 << 20).await.unwrap()).unwrap();
    assert!(value.get("scanCursor").is_some());
    assert!(value.get("nodeTip").is_some());
    assert!(value.get("lag").is_some());
    assert!(value.get("scanInvalidated").is_some());
    assert!(value.get("rescan").is_some());
    assert!(value.get("sync").is_some());

    for (path, keys) in [
        (
            "/api/v1/wallet/balance",
            vec!["height", "nanoErg", "assets"],
        ),
        ("/api/v1/wallet/boxes", vec!["items", "total", "asOf"]),
        (
            "/api/v1/wallet/transactions",
            vec!["items", "total", "asOf"],
        ),
        ("/api/v1/wallet/addresses", vec!["items", "total", "asOf"]),
    ] {
        let response = app(&dir)
            .oneshot(
                axum::http::Request::builder()
                    .uri(path)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        let value: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 1 << 20).await.unwrap())
                .unwrap();
        for key in keys {
            assert!(value.get(key).is_some(), "{path}: {value}");
        }
    }
}
