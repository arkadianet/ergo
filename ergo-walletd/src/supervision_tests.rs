//! Regression tests for recovery and connection teardown in the real daemon
//! supervisor. Fixtures use the real standalone store, syncer and seed host.

use super::*;

use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use ergo_wallet_service::{
    BlocksSinceRequest, BlocksSinceResponse, ChainBlock, ChainClient, ChainClientError,
    ChainSnapshot, CommittedTip, ForwardBlocksSince, RescanState, SubmitRequest, SubmitResponse,
    UtxoLookup,
};

use crate::config::{Network, WalletMode};
use crate::engine_chain::LifecycleChainAccess;
use crate::sync::SyncConfig;
use ergo_wallet_service::{RedbWalletStore, WalletService};

const LOCAL_KEY: &str = "supervision-local-key";

struct RecoverableChain {
    fail_blocks: AtomicBool,
    block_requests: AtomicUsize,
}

impl RecoverableChain {
    fn new(fail_blocks: bool) -> Arc<Self> {
        Arc::new(Self {
            fail_blocks: AtomicBool::new(fail_blocks),
            block_requests: AtomicUsize::new(0),
        })
    }
}

impl ChainClient for RecoverableChain {
    fn committed_tip(&self) -> Result<CommittedTip, ChainClientError> {
        Ok(CommittedTip::new(3, [3; 32]))
    }

    fn snapshot(&self) -> Result<ChainSnapshot, ChainClientError> {
        Err(ChainClientError::Unsupported)
    }

    fn blocks_since(
        &self,
        request: BlocksSinceRequest,
    ) -> Result<BlocksSinceResponse, ChainClientError> {
        self.block_requests.fetch_add(1, Ordering::SeqCst);
        if self.fail_blocks.load(Ordering::SeqCst) {
            return Err(ChainClientError::Protocol(
                "injected terminal page failure".into(),
            ));
        }
        let last = 3.min(request.cursor.height.saturating_add(request.limit));
        let blocks = (request.cursor.height.saturating_add(1)..=last)
            .map(|height| ChainBlock {
                height,
                block_id: [height as u8; 32],
                parent_id: [height.saturating_sub(1) as u8; 32],
                header_bytes: Vec::new(),
                transactions: Vec::new(),
            })
            .collect();
        Ok(BlocksSinceResponse::Forward(ForwardBlocksSince {
            tip: self.committed_tip()?,
            blocks,
        }))
    }

    fn lookup_utxo(
        &self,
        _box_id: [u8; 32],
        _expected_tip: CommittedTip,
    ) -> Result<UtxoLookup, ChainClientError> {
        Err(ChainClientError::Unsupported)
    }

    fn submit(&self, _request: SubmitRequest) -> Result<SubmitResponse, ChainClientError> {
        panic!("seed lifecycle supervisor must not submit")
    }
}

fn seed_daemon(dir: &Path, chain: Arc<RecoverableChain>) -> TestDaemon {
    let store = Arc::new(
        RedbWalletStore::open_standalone(dir.join("wallet.redb"))
            .unwrap()
            .rebuild_history_on_key_additions(),
    );
    let service = Arc::new(WalletService::new(store.clone(), chain.clone()));
    let tip = Arc::new(CachedNodeTip::new(chain.clone()));
    let host = WalletHost::new(
        store.clone(),
        service.clone(),
        Arc::new(LifecycleChainAccess::new(store, chain)),
        dir,
        Network::Testnet,
    )
    .unwrap();
    let syncer = Arc::new(StandaloneSyncer::new(
        service.clone(),
        SyncConfig {
            batch: 3,
            page: 3,
            retry_delay: Duration::ZERO,
            max_retry_delay: Duration::ZERO,
        },
        tip.clone(),
    ));
    TestDaemon {
        config: Config {
            mode: WalletMode::Seed,
            network: Network::Testnet,
            data_dir: dir.to_owned(),
            node_url: "http://127.0.0.1:9/".parse().unwrap(),
            api_key_file: dir.join("node-key"),
            descriptor_file: None,
            local_api_key_file: dir.join("local-key"),
            node_ca_file: None,
            sync_interval: Duration::from_millis(10),
            shutdown_timeout: Duration::from_secs(2),
            sync_batch: 3,
            blocks_page: 3,
            unix_socket: None,
            tcp_fallback: Some("127.0.0.1:0".parse().unwrap()),
            allowed_hosts: Vec::new(),
            lock_policy: crate::config::LockPolicy::default(),
            lock_memory: false,
            unseal_key_file: None,
        },
        service,
        syncer,
        tip,
        host: Some(host),
        local_api_key: ApiKey::from_test(LOCAL_KEY.as_bytes().to_vec()),
    }
}

async fn wait_for(mut condition: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .expect("daemon did not reach the expected state");
}

#[tokio::test]
async fn seed_terminal_sync_waits_for_a_key_reset_and_recovers_without_restart() {
    let dir = tempfile::tempdir().unwrap();
    let chain = RecoverableChain::new(true);
    let daemon = seed_daemon(dir.path(), chain.clone());
    let host = daemon.host.as_ref().unwrap().clone();
    host.init("test".into(), String::new(), 12).await.unwrap();
    host.unlock("test".into()).await.unwrap();
    let store = daemon.service.store().clone();
    let config = daemon.config;
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let supervisor = tokio::spawn(async move {
        supervise_sync(
            daemon.syncer,
            &config,
            daemon.host,
            None,
            tokio::task::JoinSet::new(),
            async move {
                let _ = stopped.await;
                Ok(())
            },
        )
        .await
    });
    wait_for(|| {
        matches!(
            store.read().unwrap().rescan_state().unwrap(),
            RescanState::Failed { .. }
        )
    })
    .await;
    let failed_requests = chain.block_requests.load(Ordering::SeqCst);
    assert_eq!(failed_requests, 1);
    // Several intervals pass with the failure retained. Repairing the node
    // alone must not cause the parked worker to retry a terminal failure.
    chain.fail_blocks.store(false, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(chain.block_requests.load(Ordering::SeqCst), failed_requests);
    assert!(matches!(
        store.read().unwrap().rescan_state().unwrap(),
        RescanState::Failed { .. }
    ));
    // Failure persistence is best effort. An older Idle marker must not
    // resume a terminal pass without an actual committed tracking change.
    let mut write = store.begin_write().unwrap();
    write.set_rescan_state(&RescanState::Idle).unwrap();
    write.commit().unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(chain.block_requests.load(Ordering::SeqCst), failed_requests);
    // A real key command atomically resets the durable state to idle. The
    // same supervised worker must notice it and replay with the new key set.
    host.derive_next_key().await.unwrap();
    assert!(!matches!(
        store.read().unwrap().rescan_state().unwrap(),
        RescanState::Failed { .. }
    ));
    wait_for(|| {
        let read = store.read().unwrap();
        read.scan_cursor()
            .unwrap()
            .is_some_and(|cursor| cursor.height == 3)
            && !read.scan_invalidated().unwrap()
            && matches!(read.rescan_state().unwrap(), RescanState::Idle)
    })
    .await;
    assert!(chain.block_requests.load(Ordering::SeqCst) > failed_requests);
    stop.send(()).unwrap();
    supervisor.await.unwrap().unwrap();
    assert!(matches!(
        host.status().await,
        Err(ergo_wallet_protocol::WalletAdminError::ShuttingDown)
    ));
}

#[cfg(unix)]
#[tokio::test]
async fn shutdown_closes_idle_unix_connections_and_releases_the_wallet_database() {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wallet.sock");
    let mut daemon = seed_daemon(dir.path(), RecoverableChain::new(false));
    daemon.config.unix_socket = Some(path.clone());
    daemon.config.tcp_fallback = None;
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let running = tokio::spawn(run_until(daemon.into(), async move {
        let _ = stopped.await;
        Ok(())
    }));
    wait_for(|| path.exists()).await;
    let mut stream = tokio::net::UnixStream::connect(&path).await.unwrap();
    stream
        .write_all(format!(
            "GET /api/v1/wallet/lifecycle/status HTTP/1.1\r\nHost: local\r\napi_key: {LOCAL_KEY}\r\nConnection: keep-alive\r\n\r\n"
        ).as_bytes())
        .await
        .unwrap();
    let mut stream = tokio::io::BufReader::new(stream);
    let mut status = String::new();
    stream.read_line(&mut status).await.unwrap();
    assert!(status.starts_with("HTTP/1.1 200"));
    let mut content_length = None;
    loop {
        let mut line = String::new();
        assert!(
            stream.read_line(&mut line).await.unwrap() > 0,
            "server closed before completing its response headers"
        );
        if line == "\r\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                content_length = Some(value.trim().parse::<usize>().unwrap());
            }
        }
    }
    let mut body = vec![0; content_length.expect("JSON response has a content length")];
    stream.read_exact(&mut body).await.unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
        serde_json::json!({"initialized":false,"locked":true})
    );
    // Keep the client socket alive while the daemon tears down its listeners.
    // Detached server connections would retain the router and redb handle.
    stop.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), running)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let mut byte = [0];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), stream.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert!(!path.exists());
    let reopened = RedbWalletStore::open_standalone(dir.path().join("wallet.redb"));
    assert!(
        reopened.is_ok(),
        "shutdown must release the old database before returning"
    );
}
