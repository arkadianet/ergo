//! Operator controls exercised through the real node's HTTP and disk seams.

use super::common::{make_test_config, spawn_node};
use ergo_api::auth::{ApiSecurity, CredentialScope, ScopedCredentialConfig};
use reqwest::StatusCode;
use serde_json::{json, Value};

fn config(path: &std::path::Path) -> ergo_node::config::NodeConfig {
    let mut config = make_test_config(path.to_path_buf());
    config.api_scoped_keys = vec![
        ScopedCredentialConfig {
            id: "observer".into(),
            hash: ApiSecurity::hash_key(b"observer-key"),
            scopes: vec![CredentialScope::Operator],
            revoked: false,
        },
        ScopedCredentialConfig {
            id: "pool".into(),
            hash: ApiSecurity::hash_key(b"pool-key"),
            scopes: vec![CredentialScope::Mining],
            revoked: false,
        },
    ];
    config.peer_details.auto_download = false;
    config.peer_details.reverse_dns = false;
    config
}

#[tokio::test]
async fn controls_are_authenticated_atomic_and_survive_restart_where_promised() {
    let directory = tempfile::tempdir().unwrap();
    let node = spawn_node(config(directory.path())).await;
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let base = format!("http://{}", node.api_addr.unwrap());

    // Startup and liveness are meaningful even though this isolated fixture is
    // disconnected and cannot be ready to serve a current network chain.
    for route in ["startup", "liveness"] {
        let mut response = None;
        for _ in 0..40 {
            let current = client
                .get(format!("{base}/api/v1/node/{route}"))
                .send()
                .await
                .unwrap();
            if current.status() == StatusCode::OK {
                response = Some(current);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        assert!(
            response.is_some(),
            "runtime must start and produce a heartbeat"
        );
    }
    assert_eq!(
        client
            .get(format!("{base}/api/v1/node/readiness"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );

    let config_url = format!("{base}/api/v1/node/config");
    assert_eq!(
        client.get(&config_url).send().await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        client
            .get(&config_url)
            .header("api_key", "pool-key")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let initial: Value = client
        .get(&config_url)
        .header("api_key", "observer-key")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(initial["revision"].is_string());
    assert!(!initial
        .to_string()
        .contains(&ApiSecurity::hash_key(b"hello")));
    assert!(!initial
        .to_string()
        .contains(&ApiSecurity::hash_key(b"observer-key")));
    assert_eq!(
        client
            .patch(&config_url)
            .header("api_key", "observer-key")
            .json(&json!({"api_limits":{"burst":80}}))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let bad = client
        .patch(&config_url)
        .header("api_key", "hello")
        .json(&json!({"api_limits":{"burst":80},"readiness":{"tip_max_age_ms":0}}))
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
    let unchanged: Value = client
        .get(&config_url)
        .header("api_key", "hello")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(initial, unchanged);
    let changed: Value = client
        .patch(&config_url)
        .header("api_key", "hello")
        .json(&json!({"expected_revision":initial["revision"],"api_limits":{"burst":80}}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_ne!(changed["revision"], initial["revision"]);
    assert_eq!(
        changed["runtime"]["api_limits"]["burst"].as_f64(),
        Some(80.0)
    );
    assert_eq!(
        client
            .patch(&config_url)
            .header("api_key", "hello")
            .json(&json!({"expected_revision":initial["revision"],"api_limits":{"burst":90}}))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        client
            .patch(&config_url)
            .header("api_key", "hello")
            .json(&json!({"node":{"verify_transactions":false}}))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );

    let ban_url = format!("{base}/api/v1/network/blacklist");
    assert_eq!(
        client
            .post(&ban_url)
            .header("api_key", "pool-key")
            .json(&json!({"addr":"203.0.113.8"}))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        client
            .post(&ban_url)
            .header("api_key", "observer-key")
            .json(&json!({"addr":"203.0.113.8","duration_secs":3600}))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NO_CONTENT
    );
    let disconnected: Value = client
        .post(format!("{base}/api/v1/network/disconnect"))
        .header("api_key", "observer-key")
        .json(&"203.0.113.8:9030")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(disconnected["session_closed"], false);
    let forgotten: Value = client
        .delete(format!("{base}/api/v1/network/peers/203.0.113.8:9030"))
        .header("api_key", "observer-key")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(forgotten["session_closed"], false);
    assert_eq!(
        client
            .get(format!("{base}/wallet/status"))
            .header("api_key", "pool-key")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        client
            .delete(format!("{base}/api/v1/node/credentials/observer"))
            .header("api_key", "hello")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        client
            .get(&config_url)
            .header("api_key", "observer-key")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    node.shutdown().await.unwrap();

    let restarted = spawn_node(config(directory.path())).await;
    let base = format!("http://{}", restarted.api_addr.unwrap());
    assert_eq!(
        client
            .get(format!("{base}/api/v1/node/config"))
            .header("api_key", "observer-key")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let config: Value = client
        .get(format!("{base}/api/v1/node/config"))
        .header("api_key", "hello")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_ne!(
        config["revision"], initial["revision"],
        "boot nonce must change at restart"
    );
    assert_eq!(
        client
            .patch(format!("{base}/api/v1/node/config"))
            .header("api_key", "hello")
            .json(&json!({"expected_revision":initial["revision"],"api_limits":{"burst":90}}))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );
    let mut restored = false;
    for _ in 0..60 {
        let bans: Value = client
            .get(format!("{base}/api/v1/network/blacklisted"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        if bans["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["addr"] == "203.0.113.8")
        {
            restored = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(
        restored,
        "durable ban must appear after the first runtime snapshot"
    );
    assert_eq!(
        client
            .delete(format!("{base}/api/v1/network/blacklist/203.0.113.8"))
            .header("api_key", "hello")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NO_CONTENT
    );
    restarted.shutdown().await.unwrap();
    let book = ergo_p2p::address_book::AddressBook::open(directory.path()).unwrap();
    assert!(book.load_all(false).unwrap().bans.is_empty());
}

#[tokio::test]
async fn config_patch_changes_the_live_http_rate_limiter() {
    let dir = tempfile::tempdir().unwrap();
    let mut settings = config(dir.path());
    settings.api_local_reverse_proxy = true;
    settings.api_limits.refill_per_sec = 0.01;
    settings.api_limits.burst = 10.0;
    settings.api_limits.cheap_weight = 10.0;
    let node = spawn_node(settings).await;
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let base = format!("http://{}", node.api_addr.unwrap());
    let info = format!("{base}/api/v1/node/info");
    assert_eq!(
        client.get(&info).send().await.unwrap().status(),
        StatusCode::OK
    );
    assert_eq!(
        client.get(&info).send().await.unwrap().status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    let response = client
        .patch(format!("{base}/api/v1/node/config"))
        .header("api_key", "hello")
        .json(&json!({"api_limits":{"refill_per_sec":1000.0,"burst":100.0,"cheap_weight":1.0}}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    for _ in 0..5 {
        assert_eq!(
            client.get(&info).send().await.unwrap().status(),
            StatusCode::OK
        );
    }
    node.shutdown().await.unwrap();
}
