//! Production wiring: the dedicated indexer serves reads and drains on shutdown.
use std::time::Duration;

use super::common::{make_test_config, spawn_node};

#[tokio::test]
async fn indexer_worker_shutdown_releases_database_for_restart() {
    let tmp = tempfile::tempdir().unwrap();
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    for _ in 0..2 {
        let mut config = make_test_config(tmp.path().to_path_buf());
        config.indexer_config.enabled = true;
        config.indexer_config.poll_idle_ms = 60_000;
        let index_path = tmp.path().join(&config.indexer_config.db_filename);
        let handle = spawn_node(config).await;
        let url = format!("http://{}/api/v1/indexer/status", handle.api_addr.unwrap());
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let status: serde_json::Value = client
                    .get(&url)
                    .send()
                    .await
                    .unwrap()
                    .error_for_status()
                    .unwrap()
                    .json()
                    .await
                    .unwrap();
                assert_ne!(status["status"], "halted", "{status}");
                if status["status"] == "caughtUp" {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("worker should reach idle and API remain responsive");
        tokio::time::timeout(Duration::from_secs(5), handle.shutdown())
            .await
            .expect("shutdown must interrupt the 60-second idle sleep")
            .expect("clean shutdown");
        // Independent reopen verifies the worker and API dropped DB references.
        let (store, _) = ergo_indexer::IndexerStore::open(&index_path).unwrap();
        assert_eq!(store.read_meta().unwrap().indexed_height, 0);
    }
}
