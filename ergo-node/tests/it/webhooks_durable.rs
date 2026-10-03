//! Real production bootstrap/HTTP coverage for independent durable engines.
use super::common::{make_test_config, spawn_node};

async fn detail(
    client: &reqwest::Client,
    address: std::net::SocketAddr,
    id: &str,
) -> serde_json::Value {
    client
        .get(format!("http://{address}/api/v1/webhooks/{id}"))
        .header("api_key", "hello")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn independent_api_engines_and_restart_preserve_private_registrations() {
    let first_dir = tempfile::tempdir().unwrap();
    let second_dir = tempfile::tempdir().unwrap();
    let first = spawn_node(make_test_config(first_dir.path().to_path_buf())).await;
    let second = spawn_node(make_test_config(second_dir.path().to_path_buf())).await;
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let channel = format!("tx:{}", "ab".repeat(32)); // no generated test event targets this ID
    let mut ids = Vec::new();
    for (node, suffix) in [(&first, "first"), (&second, "second")] {
        let registration: serde_json::Value = client
            .post(format!("http://{}/api/v1/webhooks", node.api_addr.unwrap()))
            .header("api_key", "hello")
            .json(&serde_json::json!({"url":format!("https://{suffix}.invalid/hook"),"channels":[channel],"secret":format!("private-{suffix}")}))
            .send().await.unwrap().error_for_status().unwrap().json().await.unwrap();
        assert_eq!(registration["secret"], format!("private-{suffix}"));
        ids.push(registration["webhook_id"].as_str().unwrap().to_owned());
    }
    assert_eq!(ids[0], "wh_0000000000000001");
    assert_eq!(ids[1], "wh_0000000000000001");
    for (node, suffix, id) in [(&first, "first", &ids[0]), (&second, "second", &ids[1])] {
        let value = detail(&client, node.api_addr.unwrap(), id).await;
        assert_eq!(value["url"], format!("https://{suffix}.invalid/hook"));
        assert_eq!(value["secret_set"], true);
        assert!(value.get("secret").is_none());
    }
    first.shutdown().await.unwrap();
    // Awaited shutdown must release the durable engine immediately, before a
    // queued Drop supervisor gets another poll on this current-thread runtime.
    drop(
        redb::Database::open(first_dir.path().join("webhooks.redb"))
            .expect("shutdown must release webhook database without yielding"),
    );
    second.shutdown().await.unwrap();
    let restarted = spawn_node(make_test_config(first_dir.path().to_path_buf())).await;
    let value = detail(&client, restarted.api_addr.unwrap(), &ids[0]).await;
    assert_eq!(value["url"], "https://first.invalid/hook");
    assert_eq!(value["secret_set"], true);
    assert!(value.get("secret").is_none());
    restarted.shutdown().await.unwrap();
}

#[tokio::test]
async fn corrupt_webhook_store_disables_hooks_while_api_remains_available() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("webhooks.redb"), b"corrupt database").unwrap();
    let node = spawn_node(make_test_config(directory.path().to_path_buf())).await;
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let address = node
        .api_addr
        .expect("webhook corruption must not disable the API");
    let response = client
        .get(format!("http://{address}/api/v1/webhooks"))
        .header("api_key", "hello")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::CONFLICT);
    let value: serde_json::Value = response.json().await.unwrap();
    assert_eq!(value["error"]["reason"], "webhooks_disabled");
    client
        .get(format!("http://{address}/api/v1/info"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    node.shutdown().await.unwrap();
}
