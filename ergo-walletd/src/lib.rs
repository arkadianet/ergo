#![allow(clippy::result_large_err)]

pub mod api;
pub mod chain_http;
pub mod config;
pub mod descriptor;
#[cfg(unix)]
pub mod socket;
pub mod sync;
pub mod tip;

use std::fs;
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
use crate::config::{Config, LoadedConfig};
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
}

/// Blocking startup half. **Call this from outside any Tokio runtime** — see
/// [`Daemon`] for why.
pub fn prepare(config: LoadedConfig) -> Result<Daemon, DaemonError> {
    fs::create_dir_all(&config.config.data_dir)?;
    let store = Arc::new(RedbWalletStore::open_standalone(
        config.config.data_dir.join("wallet.redb"),
    )?);
    let descriptors =
        descriptor::parse_file(&config.config.descriptor_file, config.config.network)?;
    descriptor::import(store.as_ref(), &descriptors)?;
    let chain = Arc::new(HttpChainClient::new(
        config.config.node_url.clone(),
        config.api_key.clone(),
    )?);
    let tip = Arc::new(CachedNodeTip::new(chain.clone()));
    let service = Arc::new(WalletService::new(store, chain));
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
    })
}

/// Async startup half: bind the local read API, run the blocking sync loop on
/// the blocking pool, and supervise both until a signal arrives.
pub async fn run(daemon: Daemon) -> Result<(), DaemonError> {
    run_until(daemon, shutdown_signal()).await
}

/// [`run`], with the shutdown trigger supplied by the caller.
///
/// Production uses [`shutdown_signal`] (SIGINT / SIGTERM); a test needs a
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
        shutdown,
    )
    .await
}

async fn run_listeners<F>(
    syncer: Arc<StandaloneSyncer>,
    config: &Config,
    context: ApiContext,
    shutdown: F,
) -> Result<(), DaemonError>
where
    F: std::future::Future<Output = Result<(), DaemonError>>,
{
    let router = api::router(context);
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
        listeners.spawn(async move {
            axum::serve(listener, tcp_router)
                .await
                .map_err(|error| DaemonError::Server(error.to_string()))
        });
    }
    #[cfg(unix)]
    if let Some(listener) = unix_listener {
        listeners.spawn(serve_unix(listener, router));
    }
    if listeners.is_empty() {
        return Err(DaemonError::Server(
            "no local API listener configured".to_string(),
        ));
    }
    let (terminal_tx, mut terminal_rx) = tokio::sync::mpsc::channel::<SyncError>(1);
    let (shutdown_tx, shutdown_rx) = std::sync::mpsc::channel::<()>();
    let interval = config.sync_interval;
    let worker = tokio::task::spawn_blocking(move || {
        let terminal_sender = terminal_tx;
        loop {
            match syncer.sync_once() {
                Ok(report) => {
                    tracing::info!(
                        wallet_height = report.wallet_height,
                        blocks_processed = report.blocks_processed,
                        completed = report.completed,
                        "wallet sync completed"
                    );
                }
                Err(error) if error.retryable() => {
                    tracing::warn!(error = %error, "wallet sync transport unavailable; retrying");
                }
                Err(error) => {
                    let _ = terminal_sender.blocking_send(error);
                    return;
                }
            }
            match shutdown_rx.recv_timeout(interval) {
                Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            }
        }
    });
    let result = tokio::select! {
        result = shutdown => result,
        Some(error) = terminal_rx.recv() => Err(DaemonError::Sync(error)),
        Some(result) = listeners.join_next(), if !listeners.is_empty() => {
            match result {
                Ok(Ok(())) => Err(DaemonError::Server("local API listener stopped".to_string())),
                Ok(Err(error)) => Err(error),
                Err(error) => Err(DaemonError::Server(error.to_string())),
            }
        }
    };
    drop(shutdown_tx);
    worker.abort();
    listeners.shutdown().await;
    #[cfg(unix)]
    if let Some(mut guard) = unix_guard {
        guard.cleanup();
    }
    result
}

#[cfg(unix)]
async fn serve_unix(
    listener: tokio::net::UnixListener,
    router: axum::Router,
) -> Result<(), DaemonError> {
    loop {
        let (stream, _) = listener
            .accept()
            .await
            .map_err(|error| DaemonError::Server(error.to_string()))?;
        let service =
            router
                .clone()
                .map_request(|request: hyper::Request<hyper::body::Incoming>| {
                    request.map(axum::body::Body::new)
                });
        let service = TowerToHyperService::new(service);
        tokio::spawn(async move {
            let _ = Builder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(TokioIo::new(stream), service)
                .await;
        });
    }
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
