#![allow(clippy::result_large_err)]

pub mod api;
pub mod chain_http;
pub mod config;
pub mod descriptor;
pub mod sync;

use std::fs;
use std::sync::Arc;

use ergo_wallet_service::{RedbWalletStore, WalletService, WalletStore};
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

use crate::chain_http::HttpChainClient;
use crate::config::{Config, LoadedConfig};
use crate::sync::{StandaloneSyncer, SyncConfig, SyncError};

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
}

pub async fn run(config: LoadedConfig) -> Result<(), DaemonError> {
    fs::create_dir_all(&config.config.data_dir)?;
    let store = Arc::new(RedbWalletStore::open_standalone(
        config.config.data_dir.join("wallet.redb"),
    )?);
    let descriptors = descriptor::parse_file(&config.config.descriptor_file)?;
    let import_report = descriptor::import(store.as_ref(), &descriptors)?;
    if import_report.changed() {
        let mut write = store.begin_write()?;
        write.set_scan_invalidated(true)?;
        write.set_rescan_state(&ergo_wallet_service::RescanState::Idle)?;
        write.commit()?;
    }
    let chain = Arc::new(HttpChainClient::new(
        config.config.node_url.clone(),
        config.api_key.clone(),
    )?);
    let service = Arc::new(WalletService::new(store, chain));
    let syncer = Arc::new(StandaloneSyncer::new(
        service.clone(),
        SyncConfig {
            batch: config.config.sync_batch,
            ..SyncConfig::default()
        },
    ));
    run_listeners(service, syncer, &config.config).await
}

async fn run_listeners(
    service: Arc<WalletService>,
    syncer: Arc<StandaloneSyncer>,
    config: &Config,
) -> Result<(), DaemonError> {
    let router = api::router(service);
    let mut tasks = Vec::new();
    #[cfg(unix)]
    let mut unix_path = None;
    if let Some(address) = config.tcp_fallback {
        let listener = TcpListener::bind(address).await?;
        tracing::info!(%address, "wallet API listening on loopback TCP");
        let tcp_router = router.clone();
        tasks.push(tokio::spawn(async move {
            axum::serve(listener, tcp_router)
                .await
                .map_err(|error| DaemonError::Server(error.to_string()))
        }));
    }
    #[cfg(unix)]
    if let Some(path) = config.unix_socket.clone() {
        if path.exists() {
            return Err(DaemonError::Server(format!(
                "Unix socket path already exists: {}",
                path.display()
            )));
        }
        let listener = tokio::net::UnixListener::bind(&path)?;
        set_unix_socket_permissions(&path)?;
        unix_path = Some(path.clone());
        tracing::info!(path = %path.display(), "wallet API listening on Unix socket");
        tasks.push(tokio::spawn(serve_unix(listener, router)));
    }
    let (terminal_tx, mut terminal_rx) = tokio::sync::mpsc::channel::<SyncError>(1);
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
            std::thread::sleep(interval);
        }
    });
    let result = tokio::select! {
        result = tokio::signal::ctrl_c() => {
            result.map_err(|error| DaemonError::Server(error.to_string()))?;
            Ok(())
        }
        Some(error) = terminal_rx.recv() => Err(DaemonError::Sync(error)),
        result = join_first(&mut tasks) => result,
    };
    worker.abort();
    for task in tasks {
        task.abort();
    }
    #[cfg(unix)]
    if let Some(path) = unix_path {
        let _ = fs::remove_file(path);
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

async fn join_first(
    tasks: &mut [tokio::task::JoinHandle<Result<(), DaemonError>>],
) -> Result<(), DaemonError> {
    if tasks.is_empty() {
        return Err(DaemonError::Server(
            "no local API listener configured".to_string(),
        ));
    }
    let mut handles = tasks.iter_mut();
    handles
        .next()
        .expect("non-empty listener task list")
        .await
        .map_err(|error| DaemonError::Server(error.to_string()))?
}

#[cfg(unix)]
fn set_unix_socket_permissions(path: &std::path::Path) -> Result<(), DaemonError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

pub fn init_logging() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}
