//! Production-shaped seed startup: load protected credentials, prepare before
//! creating Tokio, serve real TCP requests, and restart the standalone store.

use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ergo_walletd::config::{Cli, Config, LoadedConfig};
use ergo_walletd::{prepare, run_until, Daemon};
use reqwest::blocking::{Client, Response};
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};

use crate::node_api::{seeded_node, serve_node_api, NODE_API_KEY, TIP_HEIGHT};

const LOCAL_KEY: &str = "wallet-daemon-boot-local-credential";
const PASSWORD: &str = "seed-boot-password";
const LIFECYCLE_STATUS: &str = "/api/v1/wallet/lifecycle/status";
const DESCRIPTORS: &str = concat!(
    "version = 1\n",
    "[[keys]]\n",
    "path = \"m/44'/429'/0'/0/0\"\n",
    "public_key = \"0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2\"\n",
);

fn write_key(path: &Path, value: &[u8]) {
    std::fs::write(path, value).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn quote_path(path: &Path) -> String {
    serde_json::to_string(path.to_str().expect("temporary paths are UTF-8")).unwrap()
}

fn write_config(
    root: &Path,
    data_dir: &Path,
    mode: &str,
    node_url: &str,
    address: SocketAddr,
) -> PathBuf {
    let node_key = root.join("node-key");
    let local_key = root.join("local-key");
    write_key(&node_key, NODE_API_KEY);
    write_key(&local_key, LOCAL_KEY.as_bytes());
    let mode_fields = if mode == "seed" {
        format!("local_api_key_file = {}\n", quote_path(&local_key))
    } else {
        let descriptors = root.join("descriptors.toml");
        std::fs::write(&descriptors, DESCRIPTORS).unwrap();
        format!("descriptor_file = {}\n", quote_path(&descriptors))
    };
    let path = root.join(format!("{mode}.toml"));
    std::fs::write(
        &path,
        format!(
            "mode = \"{mode}\"\nnetwork = \"mainnet\"\ndata_dir = {}\n\
             node_url = \"{node_url}\"\napi_key_file = {}\n{mode_fields}\
             sync_interval = \"1s\"\nsync_batch = 8\nblocks_page = 1\n\
             tcp_fallback = \"{address}\"\nshutdown_timeout_secs = 5\n",
            quote_path(data_dir),
            quote_path(&node_key),
        ),
    )
    .unwrap();
    path
}

fn load(path: &Path) -> LoadedConfig {
    Config::load(Cli {
        command: None,
        config: path.to_path_buf(),
        mode: None,
        local_api_key_file: None,
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

fn free_address() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

struct RunningDaemon {
    url: String,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    worker: Option<std::thread::JoinHandle<Result<(), String>>>,
}

impl RunningDaemon {
    fn start(daemon: Daemon, address: SocketAddr, client: &Client) -> Self {
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let worker = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap();
            let result = runtime
                .block_on(run_until(daemon, async move {
                    let _ = stopped.await;
                    Ok(())
                }))
                .map_err(|error| error.to_string());
            runtime.shutdown_background();
            result
        });
        let running = Self {
            url: format!("http://{address}"),
            stop: Some(stop),
            worker: Some(worker),
        };
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if request(
                client,
                &running.url,
                Method::GET,
                LIFECYCLE_STATUS,
                Some(LOCAL_KEY),
                None,
            )
            .is_ok()
            {
                return running;
            }
            assert!(
                Instant::now() < deadline,
                "seed daemon did not bind its TCP listener"
            );
            assert!(
                !running.worker.as_ref().unwrap().is_finished(),
                "seed daemon exited before listener startup"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn stop(mut self) {
        self.stop.take().unwrap().send(()).unwrap();
        self.worker
            .take()
            .unwrap()
            .join()
            .expect("seed daemon worker does not panic")
            .expect("seed daemon exits cleanly");
    }
}

impl Drop for RunningDaemon {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn request(
    client: &Client,
    base_url: &str,
    method: Method,
    route: &str,
    key: Option<&str>,
    body: Option<Value>,
) -> Result<Response, reqwest::Error> {
    let mut request = client.request(method, format!("{}{route}", base_url.trim_end_matches('/')));
    if let Some(key) = key {
        request = request.header("api_key", key);
    }
    if let Some(body) = body {
        request = request
            .header("content-type", "application/json")
            .body(body.to_string());
    }
    request.send()
}

fn local_response(
    client: &Client,
    daemon: &RunningDaemon,
    method: Method,
    route: &str,
    body: Option<Value>,
) -> Response {
    let response = request(client, &daemon.url, method, route, Some(LOCAL_KEY), body).unwrap();
    assert_eq!(response.headers()["cache-control"], "no-store");
    response
}

fn json_body(response: Response) -> Value {
    assert_eq!(response.status(), StatusCode::OK);
    serde_json::from_slice(&response.bytes().unwrap()).unwrap()
}

#[test]
fn seed_daemon_loads_separate_credentials_syncs_and_restarts_locked() {
    let node_dir = tempfile::tempdir().unwrap();
    let (store, _ids) = seeded_node(node_dir.path());
    let node = serve_node_api(&store);
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let address = free_address();
    let config = write_config(dir.path(), &data, "seed", &node.url(), address);
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    // prepare performs blocking HTTP-client construction before Tokio exists.
    let daemon = RunningDaemon::start(prepare(load(&config)).unwrap(), address, &client);
    assert_eq!(
        json_body(local_response(
            &client,
            &daemon,
            Method::GET,
            LIFECYCLE_STATUS,
            None
        )),
        json!({"initialized": false, "locked": true})
    );
    for key in [None, Some(std::str::from_utf8(NODE_API_KEY).unwrap())] {
        let response = request(
            &client,
            &daemon.url,
            Method::GET,
            LIFECYCLE_STATUS,
            key,
            None,
        )
        .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers()["cache-control"], "no-store");
    }
    // The local credential is not an operator credential accepted by the node.
    assert_eq!(
        request(
            &client,
            &node.url(),
            Method::GET,
            "/api/v1/chain/tip",
            Some(LOCAL_KEY),
            None
        )
        .unwrap()
        .status(),
        StatusCode::UNAUTHORIZED
    );
    let initialized = json_body(local_response(
        &client,
        &daemon,
        Method::POST,
        "/api/v1/wallet/init",
        Some(json!({"pass": PASSWORD, "strength": 12})),
    ));
    assert_eq!(
        initialized["mnemonic"]
            .as_str()
            .unwrap()
            .split_whitespace()
            .count(),
        12
    );
    assert_eq!(
        json_body(local_response(
            &client,
            &daemon,
            Method::GET,
            LIFECYCLE_STATUS,
            None
        )),
        json!({"initialized": true, "locked": true})
    );
    let unlock = local_response(
        &client,
        &daemon,
        Method::POST,
        "/api/v1/wallet/unlock",
        Some(json!({"pass": PASSWORD})),
    );
    assert_eq!(unlock.status(), StatusCode::OK);
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let status = json_body(local_response(
            &client,
            &daemon,
            Method::GET,
            "/status",
            None,
        ));
        if status["scanCursor"]["height"] == TIP_HEIGHT
            && status["scanInvalidated"] == false
            && status["sync"]["type"] == "atTip"
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "seed sync did not reach authenticated node tip: {status}"
        );
        std::thread::sleep(Duration::from_millis(30));
    }
    let addresses_before = json_body(local_response(
        &client,
        &daemon,
        Method::GET,
        "/api/v1/wallet/addresses",
        None,
    ));
    // Native addresses expose persisted master and first EIP-3 child metadata.
    assert_eq!(addresses_before["items"].as_array().unwrap().len(), 2);
    // Shut down while unlocked; prepare must never resurrect the master key.
    daemon.stop();
    let restarted = RunningDaemon::start(prepare(load(&config)).unwrap(), address, &client);
    assert_eq!(
        json_body(local_response(
            &client,
            &restarted,
            Method::GET,
            LIFECYCLE_STATUS,
            None
        )),
        json!({"initialized": true, "locked": true})
    );
    assert_eq!(
        json_body(local_response(
            &client,
            &restarted,
            Method::GET,
            "/api/v1/wallet/addresses",
            None
        )),
        addresses_before
    );
    assert_eq!(
        local_response(
            &client,
            &restarted,
            Method::POST,
            "/api/v1/wallet/lock",
            None
        )
        .status(),
        StatusCode::OK
    );
    restarted.stop();
}

#[test]
fn daemon_data_directories_refuse_mode_changes_and_keep_legacy_watch_usable() {
    let dir = tempfile::tempdir().unwrap();
    let address = free_address();
    let watch_data = dir.path().join("watch-data");
    let watch = write_config(
        dir.path(),
        &watch_data,
        "watch_only",
        "http://127.0.0.1:9",
        address,
    );
    drop(prepare(load(&watch)).unwrap());
    let seed = write_config(
        dir.path(),
        &watch_data,
        "seed",
        "http://127.0.0.1:9",
        address,
    );
    assert!(
        prepare(load(&seed)).is_err(),
        "watch directory must not become a seed wallet"
    );
    // Simulate a Phase 2 data directory without the new ownership marker.
    std::fs::remove_file(watch_data.join("wallet-mode")).unwrap();
    assert!(
        prepare(load(&seed)).is_err(),
        "legacy watch database must not be claimed by seed mode"
    );
    assert!(
        !watch_data.join("wallet-mode").exists(),
        "a refused conversion must not publish a seed marker"
    );
    drop(prepare(load(&watch)).expect("failed seed boot preserves legacy watch startup"));

    let seed_data = dir.path().join("seed-data");
    let seed = write_config(
        dir.path(),
        &seed_data,
        "seed",
        "http://127.0.0.1:9",
        address,
    );
    drop(prepare(load(&seed)).unwrap());
    let watch = write_config(
        dir.path(),
        &seed_data,
        "watch_only",
        "http://127.0.0.1:9",
        address,
    );
    assert!(
        prepare(load(&watch)).is_err(),
        "seed-owned directory must not expose watch reads"
    );
}

#[test]
fn watch_boot_refuses_a_secret_directory_even_without_a_seed_marker() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let config = write_config(
        dir.path(),
        &data,
        "watch_only",
        "http://127.0.0.1:9",
        free_address(),
    );
    drop(prepare(load(&config)).unwrap());
    std::fs::create_dir(data.join("wallet")).unwrap();
    std::fs::write(
        data.join("wallet/secret.json"),
        b"encrypted-secret-placeholder",
    )
    .unwrap();
    assert!(
        prepare(load(&config)).is_err(),
        "watch startup must refuse a directory containing a seed"
    );
}
