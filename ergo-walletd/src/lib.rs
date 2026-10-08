#![allow(clippy::result_large_err)]

pub mod api;
pub mod chain_http;
pub mod config;
pub mod descriptor;
pub mod engine_chain;
pub mod host;
pub mod lifecycle_api;
mod ownership;
#[cfg(unix)]
pub mod socket;
#[cfg(test)]
mod supervision_tests;
pub mod sync;
pub mod tip;

use std::sync::Arc;

use ergo_wallet_service::{RedbWalletStore, WalletService};
#[cfg(unix)]
use hyper_util::rt::{TokioExecutor, TokioIo};
#[cfg(unix)]
use hyper_util::server::conn::auto::Builder;
#[cfg(unix)]
use hyper_util::service::TowerToHyperService;
use thiserror::Error;
use tokio::net::TcpListener;
#[cfg(unix)]
use tower::ServiceExt;

use crate::api::ApiContext;
use crate::chain_http::HttpChainClient;
use crate::config::{ApiKey, Config, ConfigError, LoadedConfig, WalletMode};
use crate::engine_chain::LifecycleChainAccess;
use crate::host::WalletHost;
use crate::sync::{StandaloneSyncer, SyncConfig, SyncError};
use crate::tip::CachedNodeTip;

#[derive(Debug, Error)]
pub enum DaemonError {
    #[error(transparent)]
    Config(#[from] config::ConfigError),
    #[error(transparent)]
    Descriptor(#[from] descriptor::DescriptorError),
    #[error(transparent)]
    WalletStore(#[from] ergo_wallet_service::WalletStoreError),
    #[error(transparent)]
    Host(#[from] host::HostError),
    #[error(transparent)]
    Chain(#[from] ergo_wallet_service::ChainClientError),
    #[error(transparent)]
    Sync(#[from] SyncError),
    #[error("daemon I/O failure: {0}")]
    Io(#[from] std::io::Error),
    #[error("local API server failure: {0}")]
    Server(String),
    #[cfg(unix)]
    #[error("local API socket failure: {0}")]
    Socket(#[from] socket::SocketError),
}

/// Everything the daemon needs, built by the **blocking** half of startup.
///
/// Split out of [`run`] on purpose. `reqwest::blocking`'s client creates a
/// private Tokio runtime inside `ClientBuilder::build` and drops it with the
/// client, and Tokio refuses to drop a runtime on a thread that is inside an
/// async context — so building the chain client from inside an `async fn`
/// (or under `#[tokio::main]`) panics at startup. [`prepare`] performs every
/// blocking construction step, and the binary calls it *before* it creates the
/// daemon's own runtime. From there on the client is an ordinary value: the
/// sync loop drives it from `spawn_blocking`, and the read API only touches the
/// cached tip.
pub struct Daemon {
    config: Config,
    service: Arc<WalletService>,
    syncer: Arc<StandaloneSyncer>,
    tip: Arc<CachedNodeTip>,
    host: Option<WalletHost>,
    local_api_key: Option<ApiKey>,
}

/// Blocking startup half. **Call this from outside any Tokio runtime** — see
/// [`Daemon`] for why.
pub fn prepare(config: LoadedConfig) -> Result<Daemon, DaemonError> {
    match config.config.mode {
        WalletMode::Seed => {
            if config.config.descriptor_file.is_some()
                || config.local_api_key.as_ref().is_none_or(|key| {
                    key.expose().is_empty() || key.expose() == config.api_key.expose()
                })
            {
                return Err(ConfigError::Invalid(
                    "seed mode requires a separate local API credential and no descriptor_file"
                        .into(),
                )
                .into());
            }
        }
        WalletMode::WatchOnly if config.local_api_key.is_some() => {
            return Err(
                ConfigError::Invalid("local API credential requires seed mode".into()).into(),
            );
        }
        WalletMode::WatchOnly => {}
    }
    ownership::claim(&config.config.data_dir, config.config.mode)?;
    let mut store = RedbWalletStore::open_standalone(config.config.data_dir.join("wallet.redb"))?;
    if config.config.mode == WalletMode::Seed {
        store = store.rebuild_history_on_key_additions();
    }
    let store = Arc::new(store);
    if config.config.mode == WalletMode::WatchOnly {
        let path = config.config.descriptor_file.as_deref().ok_or_else(|| {
            ConfigError::Invalid("watch_only mode requires descriptor_file".into())
        })?;
        let descriptors = descriptor::parse_file(path, config.config.network)?;
        descriptor::import(store.as_ref(), &descriptors)?;
    }
    let chain = Arc::new(HttpChainClient::new(
        config.config.node_url.clone(),
        config.api_key.clone(),
    )?);
    let tip = Arc::new(CachedNodeTip::new(chain.clone()));
    let service = Arc::new(WalletService::new(store.clone(), chain.clone()));
    let host = if config.config.mode == WalletMode::Seed {
        Some(WalletHost::new(
            store.clone(),
            service.clone(),
            Arc::new(LifecycleChainAccess::new(store, chain)),
            &config.config.data_dir,
            config.config.network,
        )?)
    } else {
        None
    };
    let syncer = Arc::new(StandaloneSyncer::new(
        service.clone(),
        SyncConfig {
            batch: config.config.sync_batch,
            page: config.config.blocks_page,
            ..SyncConfig::default()
        },
        tip.clone(),
    ));
    Ok(Daemon {
        config: config.config,
        service,
        syncer,
        tip,
        host,
        local_api_key: config.local_api_key,
    })
}

/// Async startup half: bind the local API, run the blocking sync loop on
/// the blocking pool, and supervise both until a signal arrives.
pub async fn run(daemon: Daemon) -> Result<(), DaemonError> {
    run_until(daemon, shutdown_signal()).await
}

/// [`run`], with the shutdown trigger supplied by the caller.
///
/// Production uses `shutdown_signal` (SIGINT / SIGTERM); a test needs a
/// programmatic trigger, because raising a real signal would take the whole
/// harness down with the daemon. `shutdown` takes over the `run_listeners`
/// select arm, so the rest of the supervision path — the blocking sync worker,
/// the listener join set, and the socket guard cleanup — is identical to
/// production.
pub async fn run_until<F>(daemon: Daemon, shutdown: F) -> Result<(), DaemonError>
where
    F: std::future::Future<Output = Result<(), DaemonError>>,
{
    let Daemon {
        config,
        service,
        syncer,
        tip,
        host,
        local_api_key,
    } = daemon;
    run_listeners(
        syncer,
        &config,
        ApiContext {
            service,
            network: config.network,
            tip,
            tip_max_age: ApiContext::default_tip_max_age(config.sync_interval),
        },
        host,
        local_api_key,
        shutdown,
    )
    .await
}

async fn run_listeners<F>(
    syncer: Arc<StandaloneSyncer>,
    config: &Config,
    context: ApiContext,
    host: Option<WalletHost>,
    local_api_key: Option<ApiKey>,
    shutdown: F,
) -> Result<(), DaemonError>
where
    F: std::future::Future<Output = Result<(), DaemonError>>,
{
    let router = match (&host, local_api_key) {
        (Some(host), Some(key)) => api::seed_router(context, host.clone(), key),
        (None, None) => api::router(context),
        _ => return Err(DaemonError::Server("inconsistent wallet API mode".into())),
    };
    let (api_shutdown_tx, api_shutdown_rx) = tokio::sync::watch::channel(());
    let mut listeners = tokio::task::JoinSet::new();
    let tcp_listener = if let Some(address) = config.tcp_fallback {
        tracing::info!(%address, "wallet API listening on loopback TCP");
        Some(TcpListener::bind(address).await?)
    } else {
        None
    };
    #[cfg(unix)]
    let mut unix_guard = None;
    #[cfg(unix)]
    let unix_listener = if let Some(path) = config.unix_socket.clone() {
        let (listener, guard) = crate::socket::bind_restricted(&path)?;
        unix_guard = Some(guard);
        tracing::info!(path = %path.display(), "wallet API listening on Unix socket");
        Some(listener)
    } else {
        None
    };
    if let Some(listener) = tcp_listener {
        let tcp_router = router.clone();
        let shutdown = api_shutdown_rx.clone();
        listeners.spawn(async move {
            axum::serve(listener, tcp_router)
                .with_graceful_shutdown(listener_shutdown(shutdown))
                .await
                .map_err(|error| DaemonError::Server(error.to_string()))
        });
    }
    #[cfg(unix)]
    if let Some(listener) = unix_listener {
        listeners.spawn(serve_unix(listener, router, api_shutdown_rx));
    }
    if listeners.is_empty() {
        return Err(DaemonError::Server(
            "no local API listener configured".to_string(),
        ));
    }
    let result = supervise_sync(
        syncer,
        config,
        host,
        Some(api_shutdown_tx),
        listeners,
        shutdown,
    )
    .await;
    #[cfg(unix)]
    if let Some(mut guard) = unix_guard {
        guard.cleanup();
    }
    result
}

async fn supervise_sync<F>(
    syncer: Arc<StandaloneSyncer>,
    config: &Config,
    host: Option<WalletHost>,
    api_shutdown: Option<tokio::sync::watch::Sender<()>>,
    mut listeners: tokio::task::JoinSet<Result<(), DaemonError>>,
    shutdown: F,
) -> Result<(), DaemonError>
where
    F: std::future::Future<Output = Result<(), DaemonError>>,
{
    let (shutdown_tx, shutdown_rx) = std::sync::mpsc::channel::<()>();
    let interval = config.sync_interval;
    let worker_syncer = syncer.clone();
    let worker_host = host.clone();
    let mut worker = tokio::task::spawn_blocking(move || {
        let syncer = worker_syncer;
        let mut terminal_tracking = None;
        loop {
            if syncer.is_cancelled() {
                return;
            }
            let pass = match &worker_host {
                Some(host) => host.sync_once_with_recovery(&syncer, &mut terminal_tracking),
                None => syncer.sync_once().map(Some),
            };
            match pass {
                Ok(Some(report)) => {
                    tracing::info!(
                        wallet_height = report.wallet_height,
                        blocks_processed = report.blocks_processed,
                        completed = report.completed,
                        "wallet sync completed"
                    );
                    if !report.completed {
                        continue;
                    }
                }
                Ok(None) => {}
                Err(SyncError::Cancelled) => return,
                Err(error) if error.retryable() => {
                    tracing::warn!(error = %error, "wallet sync transport unavailable; retrying");
                }
                Err(error) => {
                    tracing::error!(%error, "wallet sync stopped; inspect /status for the terminal failure");
                    if worker_host.is_none() {
                        return;
                    }
                    // Park instead of repeatedly retrying a terminal error.
                    // The host captured this pass's tracked rows under the
                    // writer. Only an actual key/history reset requests a
                    // new replay; stale failure metadata cannot do so.
                }
            }
            match shutdown_rx.recv_timeout(interval) {
                Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            }
        }
    });
    tokio::pin!(shutdown);
    let mut worker_finished = false;
    let result = loop {
        tokio::select! {
            result = &mut shutdown => break result,
            Some(result) = listeners.join_next(), if !listeners.is_empty() => {
                break match result {
                    Ok(Ok(())) => Err(DaemonError::Server("local API listener stopped".to_string())),
                    Ok(Err(error)) => Err(error),
                    Err(error) => Err(DaemonError::Server(error.to_string())),
                };
            }
            result = &mut worker, if !worker_finished => {
                worker_finished = true;
                if let Err(error) = result {
                    break Err(DaemonError::Server(format!("wallet sync task failed: {error}")));
                }
                // A recorded terminal sync failure leaves authenticated
                // status available; a worker panic shuts the daemon down.
            }
        }
    };
    if let Some(host) = &host {
        host.begin_shutdown();
    }
    syncer.cancel();
    drop(shutdown_tx);
    let deadline = tokio::time::Instant::now() + config.shutdown_timeout;
    if let Some(shutdown) = api_shutdown {
        let _ = shutdown.send(());
        if tokio::time::timeout_at(deadline, async {
            while listeners.join_next().await.is_some() {}
        })
        .await
        .is_err()
        {
            listeners.shutdown().await;
        }
    } else {
        listeners.shutdown().await;
    }
    if !worker_finished && tokio::time::timeout_at(deadline, worker).await.is_err() {
        tracing::warn!("wallet sync request did not finish before the shutdown timeout");
    }
    if let Some(host) = host {
        match tokio::time::timeout_at(deadline, host.shutdown()).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => return Err(DaemonError::Server(error.to_string())),
            Err(_) => {
                // spawn_blocking drains and locks the engine even if this
                // supervisor's bounded wait expires.
                tracing::warn!("wallet commands did not drain before the shutdown timeout");
            }
        }
    }
    result
}

#[cfg(unix)]
async fn serve_unix(
    listener: tokio::net::UnixListener,
    router: axum::Router,
    mut shutdown: tokio::sync::watch::Receiver<()>,
) -> Result<(), DaemonError> {
    let mut connections = tokio::task::JoinSet::new();
    loop {
        let (stream, _) = tokio::select! {
            _ = shutdown.changed() => {
                connections.shutdown().await;
                return Ok(());
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => continue,
            result = listener.accept() => result.map_err(|error| DaemonError::Server(error.to_string()))?,
        };
        let service =
            router
                .clone()
                .map_request(|request: hyper::Request<hyper::body::Incoming>| {
                    request.map(axum::body::Body::new)
                });
        let service = TowerToHyperService::new(service);
        connections.spawn(async move {
            let _ = Builder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(TokioIo::new(stream), service)
                .await;
        });
    }
}

async fn listener_shutdown(mut shutdown: tokio::sync::watch::Receiver<()>) {
    let _ = shutdown.changed().await;
}

/// SIGINT / SIGTERM, mapped to a future that completes when either arrives. A
/// failure to install the handler is reported through the future's output so
/// `run` can exit non-zero instead of running unkillably.
async fn shutdown_signal() -> Result<(), DaemonError> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .map_err(|error| DaemonError::Server(error.to_string()))?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                result.map_err(|error| DaemonError::Server(error.to_string()))
            }
            _ = terminate.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .map_err(|error| DaemonError::Server(error.to_string()))
    }
}

pub fn init_logging() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}

#[cfg(all(test, unix))]
mod review_tests {
    use super::*;
    use ergo_wallet_service::{
        BlocksSinceRequest, BlocksSinceResponse, ChainBlock, ChainClient, ChainClientError,
        ChainSnapshot, CommittedTip, ForwardBlocksSince, SubmitRequest, SubmitResponse, UtxoLookup,
    };
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Condvar, Mutex};
    use std::time::Duration;

    struct TestChain {
        entered: AtomicBool,
        released: (Mutex<bool>, Condvar),
        block: bool,
        release_on_cancel: bool,
        panic_on_blocks: AtomicBool,
    }

    impl TestChain {
        fn new(block: bool) -> Arc<Self> {
            Arc::new(Self {
                entered: AtomicBool::new(false),
                released: (Mutex::new(false), Condvar::new()),
                block,
                release_on_cancel: true,
                panic_on_blocks: AtomicBool::new(false),
            })
        }
    }

    impl ChainClient for TestChain {
        fn cancel(&self) {
            if self.release_on_cancel {
                *self.released.0.lock().unwrap() = true;
                self.released.1.notify_all();
            }
        }
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
            assert!(
                !self.panic_on_blocks.load(Ordering::SeqCst),
                "test sync worker panic"
            );
            self.entered.store(true, Ordering::SeqCst);
            if self.block {
                let mut released = self.released.0.lock().unwrap();
                while !*released {
                    released = self.released.1.wait(released).unwrap();
                }
            }
            let height = request.cursor.height + 1;
            Ok(BlocksSinceResponse::Forward(ForwardBlocksSince {
                tip: self.committed_tip()?,
                blocks: vec![ChainBlock {
                    height,
                    block_id: [height as u8; 32],
                    parent_id: request.cursor.header_id,
                    header_bytes: Vec::new(),
                    transactions: vec![],
                }],
            }))
        }
        fn lookup_utxo(
            &self,
            _: [u8; 32],
            _: CommittedTip,
        ) -> Result<UtxoLookup, ChainClientError> {
            Err(ChainClientError::Unsupported)
        }
        fn submit(&self, _: SubmitRequest) -> Result<SubmitResponse, ChainClientError> {
            Err(ChainClientError::Unsupported)
        }
    }

    fn daemon(dir: &tempfile::TempDir, chain: Arc<TestChain>) -> Daemon {
        let store =
            Arc::new(RedbWalletStore::open_standalone(dir.path().join("wallet.redb")).unwrap());
        let tip = Arc::new(CachedNodeTip::new(chain.clone()));
        let service = Arc::new(WalletService::new(store, chain));
        let syncer = Arc::new(StandaloneSyncer::new(
            service.clone(),
            SyncConfig {
                batch: 1,
                page: 1,
                ..SyncConfig::default()
            },
            tip.clone(),
        ));
        Daemon {
            config: Config {
                mode: WalletMode::WatchOnly,
                network: config::Network::Mainnet,
                data_dir: dir.path().to_owned(),
                node_url: "http://127.0.0.1:9053/".parse().unwrap(),
                api_key_file: dir.path().join("key"),
                descriptor_file: Some(dir.path().join("descriptor")),
                local_api_key_file: None,
                sync_interval: Duration::from_secs(60),
                shutdown_timeout: Duration::from_millis(500),
                sync_batch: 1,
                blocks_page: 1,
                unix_socket: Some(dir.path().join("wallet.sock")),
                tcp_fallback: None,
            },
            service,
            syncer,
            tip,
            host: None,
            local_api_key: None,
        }
    }

    async fn run_without_binding<F>(daemon: Daemon, shutdown: F) -> Result<(), DaemonError>
    where
        F: std::future::Future<Output = Result<(), DaemonError>>,
    {
        let mut listeners = tokio::task::JoinSet::new();
        listeners.spawn(std::future::pending::<Result<(), DaemonError>>());
        supervise_sync(
            daemon.syncer,
            &daemon.config,
            daemon.host,
            None,
            listeners,
            shutdown,
        )
        .await
    }

    #[tokio::test]
    async fn run_until_cancels_blocked_pass_within_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let chain = TestChain::new(true);
        let daemon = daemon(&dir, chain.clone());
        let service = daemon.service.clone();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(run_until(daemon, async {
            shutdown_rx.await.unwrap();
            Ok(())
        }));
        tokio::time::timeout(Duration::from_secs(2), async {
            while !chain.entered.load(Ordering::SeqCst) {
                assert!(
                    !task.is_finished(),
                    "daemon stopped before the fake request"
                );
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        let started = std::time::Instant::now();
        shutdown_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_millis(500), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(started.elapsed() < Duration::from_millis(500));
        assert_eq!(
            service
                .store()
                .read()
                .unwrap()
                .scan_cursor()
                .unwrap()
                .unwrap()
                .height,
            0
        );
    }

    #[tokio::test]
    async fn shutdown_cancels_blocked_pass_within_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let chain = TestChain::new(true);
        let daemon = daemon(&dir, chain.clone());
        let service = daemon.service.clone();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(run_without_binding(daemon, async {
            shutdown_rx.await.unwrap();
            Ok(())
        }));
        tokio::time::timeout(Duration::from_secs(2), async {
            while !chain.entered.load(Ordering::SeqCst) {
                assert!(
                    !task.is_finished(),
                    "daemon stopped before the fake request"
                );
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        let started = std::time::Instant::now();
        shutdown_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_millis(500), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(started.elapsed() < Duration::from_millis(500));
        assert_eq!(
            service
                .store()
                .read()
                .unwrap()
                .scan_cursor()
                .unwrap()
                .unwrap()
                .height,
            0
        );
    }

    #[tokio::test]
    async fn shutdown_timeout_bounds_an_uncooperative_request() {
        let dir = tempfile::tempdir().unwrap();
        let chain = Arc::new(TestChain {
            entered: AtomicBool::new(false),
            released: (Mutex::new(false), Condvar::new()),
            block: true,
            release_on_cancel: false,
            panic_on_blocks: AtomicBool::new(false),
        });
        let mut daemon = daemon(&dir, chain.clone());
        daemon.config.shutdown_timeout = Duration::from_millis(25);
        let syncer = daemon.syncer.clone();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(run_without_binding(daemon, async {
            shutdown_rx.await.unwrap();
            Ok(())
        }));
        tokio::time::timeout(Duration::from_secs(2), async {
            while !chain.entered.load(Ordering::SeqCst) {
                assert!(
                    !task.is_finished(),
                    "daemon stopped before the fake request"
                );
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        shutdown_tx.send(()).unwrap();
        let result = tokio::time::timeout(Duration::from_millis(250), task).await;
        // Release the fake even if the timeout assertion below fails.
        *chain.released.0.lock().unwrap() = true;
        chain.released.1.notify_all();
        result.unwrap().unwrap().unwrap();
        assert!(syncer.is_cancelled());
    }

    #[test]
    fn cancelled_request_does_not_commit_returned_block() {
        let dir = tempfile::tempdir().unwrap();
        let chain = TestChain::new(true);
        let daemon = daemon(&dir, chain.clone());
        let syncer = daemon.syncer.clone();
        let worker = std::thread::spawn(move || syncer.sync_once());
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while !chain.entered.load(Ordering::SeqCst) {
            assert!(std::time::Instant::now() < deadline);
            std::thread::yield_now();
        }
        daemon.syncer.cancel();
        assert!(matches!(worker.join().unwrap(), Err(SyncError::Cancelled)));
        assert_eq!(
            daemon
                .service
                .store()
                .read()
                .unwrap()
                .scan_cursor()
                .unwrap()
                .unwrap()
                .height,
            0
        );
    }

    #[tokio::test]
    async fn unfinished_pass_continues_without_waiting_for_sync_interval() {
        let dir = tempfile::tempdir().unwrap();
        let daemon = daemon(&dir, TestChain::new(false));
        let service = daemon.service.clone();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(run_without_binding(daemon, async {
            shutdown_rx.await.unwrap();
            Ok(())
        }));
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                assert!(!task.is_finished(), "daemon stopped before catching up");
                if service
                    .store()
                    .read()
                    .unwrap()
                    .scan_cursor()
                    .unwrap()
                    .is_some_and(|cursor| cursor.height == 3)
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        shutdown_tx.send(()).unwrap();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn sync_worker_panic_stops_seed_admission_and_cancels_sync() {
        let dir = tempfile::tempdir().unwrap();
        let chain = TestChain::new(false);
        chain.panic_on_blocks.store(true, Ordering::SeqCst);
        let mut daemon = daemon(&dir, chain.clone());
        let host = WalletHost::new(
            daemon.service.store().clone(),
            daemon.service.clone(),
            Arc::new(LifecycleChainAccess::new(
                daemon.service.store().clone(),
                chain,
            )),
            dir.path(),
            config::Network::Mainnet,
        )
        .unwrap();
        host.init("pass".into(), String::new(), 12).await.unwrap();
        host.unlock("pass".into()).await.unwrap();
        daemon.host = Some(host.clone());
        let syncer = daemon.syncer.clone();
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            run_without_binding(daemon, std::future::pending()),
        )
        .await
        .unwrap();
        assert!(
            matches!(result, Err(DaemonError::Server(message)) if message.contains("wallet sync task failed"))
        );
        assert!(syncer.is_cancelled());
        assert!(matches!(
            host.status().await,
            Err(ergo_wallet_protocol::WalletAdminError::ShuttingDown)
        ));
    }
}
