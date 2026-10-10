//! Exercise the shipped offline command and reload its files through the node loader.
use std::fs;
use std::io::Read;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use clap::Parser;
use ergo_node::config::{Cli, NodeConfig, StateType};

const PK: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

fn command(root: &Path, preset: &str, sync: &str, network: &str) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ergo-node"));
    cmd.args([
        "init",
        "--preset",
        preset,
        "--sync",
        sync,
        "--network",
        network,
        "--non-interactive",
        "--allow-low-disk",
        "--data-dir",
    ])
    .arg(root.join("data"));
    if preset.starts_with("mining-") {
        cmd.args([
            "--reward",
            "public-key",
            "--miner-public-key",
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        ]);
    }
    cmd.stdin(Stdio::null());
    cmd
}
fn combined(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}
fn success(out: &Output) {
    assert!(out.status.success(), "{}", combined(out));
}
fn refused(out: &Output, reason: &str) {
    assert_eq!(out.status.code(), Some(2), "{}", combined(out));
    assert!(combined(out).contains(reason), "{}", combined(out));
}

#[test]
fn every_allowed_preset_sync_network_writes_loader_accepted_config() {
    for preset in [
        "wallet",
        "mining-fast",
        "mining-full",
        "explorer",
        "archival",
    ] {
        for sync in ["fast", "genesis"] {
            if sync == "fast" && !["wallet", "mining-fast"].contains(&preset) {
                continue;
            }
            for network in ["mainnet", "testnet"] {
                let root = tempfile::tempdir().unwrap();
                let mut cmd = command(root.path(), preset, sync, network);
                if sync == "fast" {
                    cmd.arg("--accept-unanchored-bootstrap");
                }
                if network == "testnet" {
                    cmd.arg("--json");
                }
                let out = cmd.output().unwrap();
                success(&out);
                let config = root.path().join("data/ergo-node.toml");
                let cli = Cli::parse_from(["ergo-node", "--config", config.to_str().unwrap()]);
                let loaded = NodeConfig::load(cli).unwrap();
                assert_eq!(loaded.network.as_str(), network);
                assert_eq!(
                    fs::canonicalize(&loaded.data_dir).unwrap(),
                    fs::canonicalize(root.path().join("data")).unwrap()
                );
                assert_eq!(loaded.state_type, StateType::Utxo);
                assert!(loaded.verify_transactions);
                assert_eq!(loaded.blocks_to_keep, -1);
                assert_eq!(loaded.utxo_bootstrap, sync == "fast");
                assert_eq!(loaded.nipopow_bootstrap, sync == "fast");
                assert_eq!(loaded.p2p_nipopows, 2);
                assert_eq!(
                    loaded.indexer_config.enabled,
                    ["mining-full", "explorer"].contains(&preset)
                );
                assert_eq!(loaded.mining_config.enabled, preset.starts_with("mining-"));
                assert!(loaded.mining_config.use_external_miner);
                assert_eq!(
                    loaded.mining_config.claim_storage_rent,
                    preset == "mining-full"
                );
                assert_eq!(
                    loaded.mining_config.miner_public_key_hex.is_some(),
                    preset.starts_with("mining-")
                );
                assert!(loaded.mempool_config.enabled);
                assert!(!loaded.allow_unauthenticated_legacy_mining);
                assert!(loaded.bind_addr.is_none());
                assert!(loaded.declared_addr.is_none());
                assert_eq!(loaded.api_bind.unwrap().to_string(), "127.0.0.1:9099");
                assert!(!loaded.known_peers.is_empty(), "embedded seeds");
                let contents = fs::read_to_string(&config).unwrap();
                assert!(!contents.contains("voting"));
                assert!(!contents.contains("expose_private_keys"));
                assert!(!contents.contains("allow_unauthenticated_legacy_mining"));
                assert!(!contents.contains("known ="));
                let key = fs::read_to_string(root.path().join("data/secrets/api-key")).unwrap();
                assert_eq!(
                    loaded.api_key_hash.unwrap(),
                    ergo_api::auth::ApiSecurity::hash_key(key.trim_end().as_bytes())
                );
                assert!(!combined(&out).contains(key.trim_end()));
                assert!(combined(&out).contains("--config"));
                assert!(combined(&out).contains("--data-dir"));
                assert!(combined(&out).contains("Ctrl-C"));
                if preset.starts_with("mining-") {
                    assert!(combined(&out).contains("ergo-stratum-rs"));
                }
                if ["mining-full", "explorer"].contains(&preset) {
                    assert!(combined(&out).contains("index catch-up"));
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    assert_eq!(
                        fs::metadata(root.path().join("data/secrets"))
                            .unwrap()
                            .permissions()
                            .mode()
                            & 0o777,
                        0o700
                    );
                    assert_eq!(
                        fs::metadata(root.path().join("data/secrets/api-key"))
                            .unwrap()
                            .permissions()
                            .mode()
                            & 0o777,
                        0o600
                    );
                }
            }
        }
    }
}

#[test]
fn disallowed_fast_presets_and_missing_consent_are_refused() {
    for preset in ["mining-full", "explorer", "archival"] {
        let root = tempfile::tempdir().unwrap();
        let out = command(root.path(), preset, "fast", "mainnet")
            .arg("--accept-unanchored-bootstrap")
            .output()
            .unwrap();
        refused(&out, "requires --sync genesis");
        assert!(!root.path().join("data").exists());
    }
    let root = tempfile::tempdir().unwrap();
    let out = command(root.path(), "wallet", "fast", "mainnet")
        .output()
        .unwrap();
    refused(&out, "--accept-unanchored-bootstrap");
    assert!(combined(&out).contains("cross-check the UTXO root"));
    assert!(!root.path().join("data").exists());
}

#[test]
fn existing_config_and_node_data_are_never_modified() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("data")).unwrap();
    let config = root.path().join("data/ergo-node.toml");
    fs::write(&config, "existing config").unwrap();
    let out = command(root.path(), "wallet", "genesis", "mainnet")
        .output()
        .unwrap();
    refused(&out, "v1 creates new configs only");
    assert_eq!(fs::read_to_string(&config).unwrap(), "existing config");
    fs::remove_file(&config).unwrap();
    let database = root.path().join("data/state.redb");
    fs::write(&database, "node database").unwrap();
    let out = command(root.path(), "wallet", "fast", "testnet")
        .arg("--accept-unanchored-bootstrap")
        .output()
        .unwrap();
    refused(&out, "existing node data");
    assert_eq!(fs::read_to_string(database).unwrap(), "node database");
    assert!(!config.exists());
    assert!(!root.path().join("data/secrets").exists());
}

#[test]
fn invalid_points_are_rejected_and_valid_points_show_network_address() {
    for key in [
        "xx".to_string(),
        "02".to_string(),
        format!("04{}", "00".repeat(32)),
        format!("02{}", "ff".repeat(32)),
    ] {
        let root = tempfile::tempdir().unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_ergo-node"));
        let out = cmd
            .args([
                "init",
                "--preset",
                "mining-fast",
                "--sync",
                "genesis",
                "--network",
                "mainnet",
                "--reward",
                "public-key",
                "--miner-public-key",
                &key,
                "--non-interactive",
                "--allow-low-disk",
                "--data-dir",
            ])
            .arg(root.path().join("data"))
            .output()
            .unwrap();
        refused(&out, "--miner-public-key");
        assert!(!root.path().join("data").exists());
    }
    for (network, prefix) in [
        ("mainnet", ergo_ser::address::NetworkPrefix::Mainnet),
        ("testnet", ergo_ser::address::NetworkPrefix::Testnet),
    ] {
        let root = tempfile::tempdir().unwrap();
        let bytes: [u8; 33] = hex::decode(PK).unwrap().try_into().unwrap();
        let address = ergo_ser::address::encode_p2pk_from_pubkey(prefix, &bytes).unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_ergo-node"))
            .args([
                "init",
                "--preset",
                "mining-full",
                "--sync",
                "genesis",
                "--network",
                network,
                "--reward",
                "public-key",
                "--miner-public-key",
                PK,
                "--non-interactive",
                "--allow-low-disk",
                "--data-dir",
            ])
            .arg(root.path().join("data"))
            .output()
            .unwrap();
        success(&out);
        assert!(combined(&out).contains(&address));
        let loaded = NodeConfig::load(Cli::parse_from([
            "ergo-node",
            "--config",
            root.path().join("data/ergo-node.toml").to_str().unwrap(),
        ]))
        .unwrap();
        assert_eq!(
            loaded.mining_config.miner_public_key_hex.as_deref(),
            Some(PK)
        );
    }
}

#[test]
fn dry_run_json_and_text_write_nothing_even_with_missing_parents() {
    for json in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let mut cmd = command(root.path(), "wallet", "fast", "testnet");
        cmd.args(["--accept-unanchored-bootstrap", "--dry-run", "--config"])
            .arg(root.path().join("new/config/ergo.toml"));
        if json {
            cmd.arg("--json");
        }
        let out = cmd.output().unwrap();
        success(&out);
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
        let stdout = String::from_utf8(out.stdout).unwrap();
        assert!(stdout.contains("<API_HASH_ELIDED>"));
        if json {
            let plan: serde_json::Value = serde_json::from_str(&stdout).unwrap();
            assert_eq!(plan["schema_version"], 1);
            assert_eq!(plan["dry_run"], true);
            assert!(Path::new(plan["config_path"].as_str().unwrap()).is_absolute());
            assert!(Path::new(plan["data_dir"].as_str().unwrap()).is_absolute());
            assert_eq!(plan["network"], "testnet");
            assert!(plan["next_steps"].as_array().unwrap().len() >= 5);
        }
    }
}

#[test]
fn noninteractive_missing_choices_exits_two_promptly_with_stdin_open() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ergo-node"))
        .args(["init", "--non-interactive"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() > deadline {
            child.kill().unwrap();
            panic!("init waited for input");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(status.code(), Some(2));
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    for required in ["--preset", "--sync", "--network"] {
        assert!(stderr.contains(required), "{stderr}");
    }
    let root = tempfile::tempdir().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_ergo-node"))
        .args([
            "init",
            "--preset",
            "mining-fast",
            "--sync",
            "genesis",
            "--network",
            "mainnet",
            "--non-interactive",
            "--data-dir",
        ])
        .arg(root.path().join("data"))
        .output()
        .unwrap();
    refused(&out, "--reward");
}

#[test]
fn explicit_public_api_bind_satisfies_loader_and_reports_its_policy() {
    let root = tempfile::tempdir().unwrap();
    let out = command(root.path(), "wallet", "genesis", "mainnet")
        .args(["--api-bind", "0.0.0.0:9099", "--json"])
        .output()
        .unwrap();
    success(&out);
    let plan: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(plan["dashboard_url"], "http://127.0.0.1:9099/");
    assert!(combined(&out).contains("publicly callable"));
    let config = root.path().join("data/ergo-node.toml");
    let contents = fs::read_to_string(&config).unwrap();
    assert!(contents.contains("public_bind = true"));
    let loaded = NodeConfig::load(Cli::parse_from([
        "ergo-node",
        "--config",
        config.to_str().unwrap(),
    ]))
    .unwrap();
    assert_eq!(loaded.api_bind.unwrap().to_string(), "0.0.0.0:9099");
    let secret = fs::read_to_string(root.path().join("data/secrets/api-key")).unwrap();
    assert!(!combined(&out).contains(secret.trim_end()));
}

#[test]
fn explicit_paths_and_peer_addresses_are_written_without_seeds() {
    let root = tempfile::tempdir().unwrap();
    let out = command(root.path(), "archival", "genesis", "testnet")
        .args([
            "--config",
            "custom/config.toml",
            "--p2p-bind",
            "127.0.0.1:19991",
            "--declared-addr",
            "192.0.2.5:19991",
        ])
        .current_dir(root.path())
        .output()
        .unwrap();
    success(&out);
    let config = root.path().join("custom/config.toml");
    let loaded = NodeConfig::load(Cli::parse_from([
        "ergo-node",
        "--config",
        config.to_str().unwrap(),
    ]))
    .unwrap();
    assert_eq!(loaded.bind_addr.unwrap().to_string(), "127.0.0.1:19991");
    assert_eq!(loaded.declared_addr.unwrap().to_string(), "192.0.2.5:19991");
    assert!(root.path().join("custom/secrets/api-key").exists());
    assert!(!root.path().join("data/ergo-node.toml").exists());
    assert!(combined(&out).contains("port forwarding"));
}

#[test]
fn preexisting_secret_is_refused_without_overwriting() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir_all(root.path().join("data/secrets")).unwrap();
    let secret = root.path().join("data/secrets/api-key");
    fs::write(&secret, "old credential").unwrap();
    let out = command(root.path(), "wallet", "genesis", "mainnet")
        .output()
        .unwrap();
    refused(&out, "API key file already exists");
    assert_eq!(fs::read_to_string(secret).unwrap(), "old credential");
    assert!(!root.path().join("data/ergo-node.toml").exists());
}
