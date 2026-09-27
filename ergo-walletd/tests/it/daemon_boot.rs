//! End-to-end daemon boot, against the real in-process node API from
//! [`crate::node_api`].
//!
//! This is the regression test for the dev-build startup abort: the daemon used
//! to build its blocking `reqwest` client from inside an `async fn` under
//! `#[tokio::main]`, and `reqwest` drops a shell Tokio runtime *while it is
//! entered*, which Tokio refuses — so `cargo run -p ergo-walletd` aborted before
//! its first log line.
//!
//! The test reproduces the production startup shape exactly:
//!
//! 1. write a real config + api-key file (mode 0600) + descriptor file;
//! 2. `prepare()` on the test thread — the same blocking call `main` makes
//!    *before* it builds a runtime;
//! 3. build a runtime and `block_on(run_until(...))` on another thread, with a
//!    programmatic shutdown in place of SIGINT;
//! 4. drive the daemon's read API over its Unix socket while the blocking sync
//!    loop pulls the wallet to the real node's tip;
//! 5. shut down and assert the socket guard cleaned up.
//!
//! If the blocking client were built inside step 3's async context, steps 2/3
//! would abort the process rather than fail an assertion — which is the signal
//! this test exists to keep.

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ergo_walletd::config::{Cli, Config, LoadedConfig};
use ergo_walletd::{prepare, run_until};

use crate::node_api::{seeded_node, serve_node_api, NODE_API_KEY, TIP_HEIGHT};

const DESCRIPTORS: &str = concat!(
    "version = 1\n",
    "[[keys]]\n",
    "path = \"m/44'/429'/0'/0/0\"\n",
    "public_key = \"0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2\"\n",
);

/// A write config that points at `node_url` and whose api-key file holds
/// exactly the key `crate::node_api`'s router is gated on. If the two ever drift,
/// the daemon's sync loop answers 401 and the wallet never reaches the tip, so
/// this is the fixture's own guard against silently not exercising auth.
fn write_config(dir: &Path, node_url: &str, socket: &Path) -> PathBuf {
    let key_file = dir.join("node-api-key");
    let mut key = NODE_API_KEY.to_vec();
    key.push(b'\n');
    std::fs::write(&key_file, &key).unwrap();
    std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let descriptors = dir.join("descriptors.toml");
    std::fs::write(&descriptors, DESCRIPTORS).unwrap();
    let config_path = dir.join("ergo-walletd.toml");
    std::fs::write(
        &config_path,
        format!(
            "network = \"mainnet\"\ndata_dir = \"{}\"\nnode_url = \"{node_url}\"\n\
             api_key_file = \"{}\"\ndescriptor_file = \"{}\"\n\
             sync_interval = \"1s\"\nsync_batch = 8\nunix_socket = \"{}\"\n",
            dir.join("data").display(),
            key_file.display(),
            descriptors.display(),
            socket.display(),
        ),
    )
    .unwrap();
    config_path
}

fn load(config_path: &Path) -> LoadedConfig {
    Config::load(Cli {
        config: config_path.to_path_buf(),
        network: None,
        data_dir: None,
        node_url: None,
        api_key_file: None,
        descriptor_file: None,
        sync_interval: None,
        sync_batch: None,
        blocks_page: None,
        unix_socket: None,
        tcp_fallback: None,
    })
    .unwrap()
}

/// One blocking HTTP/1.1 GET over the daemon's Unix socket.
fn socket_get(socket: &Path, path: &str) -> String {
    let mut stream = UnixStream::connect(socket).unwrap();
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: local\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

fn body(response: &str) -> serde_json::Value {
    let (head, body) = response.split_once("\r\n\r\n").expect("HTTP response head");
    assert!(
        head.starts_with("HTTP/1.1 200"),
        "unexpected status: {}",
        head.lines().next().unwrap_or_default()
    );
    serde_json::from_str(body.trim()).expect("JSON body")
}

#[test]
fn daemon_prepares_outside_the_runtime_and_serves_its_read_api() {
    let node_dir = tempfile::tempdir().unwrap();
    let (store, _ids) = seeded_node(node_dir.path());
    let node = serve_node_api(&store);

    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("walletd.sock");
    let config_path = write_config(dir.path(), &node.url(), &socket);

    // --- step 2: the blocking half, on a thread that is not in a runtime ---
    let daemon = prepare(load(&config_path)).expect("prepare builds the blocking chain client");
    assert!(
        dir.path().join("data").is_dir(),
        "prepare created the data dir"
    );
    assert!(
        dir.path().join("data").join("wallet.redb").is_file(),
        "prepare opened the wallet database"
    );
    assert!(!socket.exists(), "the socket is bound by the async half");

    // --- step 3: the async half, entered only now (this is `main`'s shape) ---
    // A programmatic stand-in for SIGINT/SIGTERM, so the test never signals the
    // harness.
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    // The daemon's `Result` crosses the thread boundary as text: `DaemonError`
    // is a large enum, and a `Result<(), DaemonError>` return type would trip
    // `result_large_err` for no benefit here.
    let worker = std::thread::spawn(move || -> Result<(), String> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        runtime
            .block_on(run_until(daemon, async move {
                let _ = stop_rx.await;
                Ok(())
            }))
            .map_err(|error| error.to_string())
    });

    // One deadline for the whole wait: the listener bind, then the sync loop
    // reaching the node's tip.
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(socket.exists(), "the daemon did not bind its Unix socket");
    // The socket is owner-only, per the daemon's loopback-by-construction rule.
    let mode = std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "the read API must not be world-accessible");

    // --- step 4: the read API answers, and the blocking sync loop reaches the
    // real node's tip ---
    loop {
        let status = body(&socket_get(&socket, "/api/v1/wallet/status"));
        let settled = status["scanCursor"]["height"] == TIP_HEIGHT
            && !status["scanInvalidated"].as_bool().unwrap_or(true)
            && status["sync"]["type"] == "atTip"
            && status["rescan"]["type"] == "idle";
        if settled || Instant::now() >= deadline {
            assert_eq!(
                status["scanCursor"]["height"], TIP_HEIGHT,
                "sync did not reach the node tip: {status}"
            );
            assert!(
                !status["scanInvalidated"].as_bool().unwrap_or(true),
                "the rebuild did not finish: {status}"
            );
            assert_eq!(status["rescan"]["type"], "idle", "{status}");
            assert_eq!(status["sync"]["type"], "atTip", "{status}");
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // The sync loop publishes every tip it observes, so `/status` never has to
    // probe the node itself.
    let status = body(&socket_get(&socket, "/api/v1/wallet/status"));
    let node_tip = status["nodeTip"]
        .as_object()
        .expect("the sync loop publishes the tip it observed");
    assert_eq!(node_tip["height"], TIP_HEIGHT);
    assert_eq!(status["lag"], 0);

    // The descriptor import is visible, rendered for the configured network.
    let addresses = body(&socket_get(&socket, "/api/v1/wallet/addresses"));
    let items = addresses["items"].as_array().expect("items");
    assert_eq!(items.len(), 1);
    let address = items[0]["address"].as_str().expect("address");
    assert!(address.starts_with('9'), "mainnet P2PK address: {address}");

    // The standalone descriptor file carries public keys only, so it cannot
    // register a scan: the registry is always empty and `/scans` is an empty
    // list rather than an error. This is the documented limitation — the node's
    // `/scan/register` route is not part of the daemon's surface.
    assert_eq!(
        body(&socket_get(&socket, "/api/v1/scans")),
        serde_json::json!([])
    );

    // Read-only: nothing that can spend or sign is mounted.
    for path in [
        "/api/v1/wallet/send",
        "/api/v1/wallet/sign",
        "/api/v1/wallet/private-key",
        "/api/v1/wallet/unlock",
    ] {
        let refused = socket_get(&socket, path);
        assert!(refused.starts_with("HTTP/1.1 404"), "{path}: {refused}");
    }

    // --- step 5: programmatic shutdown, then the socket guard cleanup ---
    stop_tx.send(()).unwrap();
    worker
        .join()
        .expect("the daemon thread does not panic")
        .expect("the daemon exits cleanly on shutdown");
    assert!(!socket.exists(), "the socket guard removed the socket");
    let mut owner = socket.clone().into_os_string();
    owner.push(".owner");
    assert!(
        !PathBuf::from(owner).exists(),
        "the socket guard removed its owner marker"
    );
}

/// The api-key file is the daemon's only secret-adjacent input: it must be
/// owner-only, and its value must never reach a `Debug` or log line.
#[test]
fn daemon_refuses_a_group_readable_api_key_file_and_redacts_its_value() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("w.sock");
    let key_file = dir.path().join("node-api-key");
    std::fs::write(&key_file, b"walletd-boot-key\n").unwrap();
    std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o644)).unwrap();
    let descriptors = dir.path().join("descriptors.toml");
    std::fs::write(&descriptors, DESCRIPTORS).unwrap();
    let config_path = dir.path().join("ergo-walletd.toml");
    std::fs::write(
        &config_path,
        format!(
            "data_dir = \"{}\"\nnode_url = \"http://127.0.0.1:9099\"\napi_key_file = \"{}\"\n\
             descriptor_file = \"{}\"\nunix_socket = \"{}\"\n",
            dir.path().join("data").display(),
            key_file.display(),
            descriptors.display(),
            socket.display(),
        ),
    )
    .unwrap();
    let error = Config::load(Cli {
        config: config_path,
        network: None,
        data_dir: None,
        node_url: None,
        api_key_file: None,
        descriptor_file: None,
        sync_interval: None,
        sync_batch: None,
        blocks_page: None,
        unix_socket: None,
        tcp_fallback: None,
    })
    .expect_err("a group-readable key file is a load error");
    assert!(
        error
            .to_string()
            .contains("must not be accessible by group or other users"),
        "{error}"
    );

    std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let key = ergo_walletd::config::read_api_key(&key_file).unwrap();
    assert_eq!(key.expose(), NODE_API_KEY_TRAILING);
    assert!(
        !format!("{key:?}").contains(std::str::from_utf8(NODE_API_KEY_TRAILING).unwrap()),
        "the key must be redacted in Debug output"
    );
}

const NODE_API_KEY_TRAILING: &[u8] = b"walletd-boot-key";
