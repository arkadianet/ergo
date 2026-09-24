use ergo_node::config::WalletMode;

use super::common::make_test_config;

#[tokio::test]
async fn external_wallet_boot_does_not_open_secret_storage() {
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().join("node");
    std::fs::create_dir_all(&data_dir).expect("data dir");
    let db = redb::Database::create(data_dir.join("state.redb")).expect("state db");
    let write = db.begin_write().expect("state write");
    write
        .open_table(ergo_state::wallet::tables::WALLET_SCHEMA_VERSION_TABLE)
        .expect("wallet schema table")
        .insert((), u32::MAX)
        .expect("unsupported wallet schema fixture");
    write.commit().expect("commit fixture");
    drop(db);
    let mut config = make_test_config(data_dir.clone());
    config.wallet_mode = WalletMode::External;
    config.wallet_daemon_address = "http://127.0.0.1:19090".into();

    let handle = ergo_node::run_inner(config)
        .await
        .expect("external wallet mode boots without a wallet directory");
    assert!(!data_dir.join("wallet").exists());
    handle.shutdown().await.expect("clean shutdown");
}

#[tokio::test]
async fn external_wallet_boot_rejects_wallet_backed_mining_key() {
    let temp = tempfile::tempdir().expect("tempdir");
    let mut config = make_test_config(temp.path().join("node"));
    config.wallet_mode = WalletMode::External;
    config.mining_config.enabled = true;
    config.mining_config.miner_public_key_hex = None;

    let error = match ergo_node::run_inner(config).await {
        Ok(_) => panic!("external mining without a pinned key unexpectedly booted"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("miner_public_key_hex"));
}
