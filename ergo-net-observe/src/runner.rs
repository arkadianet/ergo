//! Multi-peer observer runner: bounded concurrency, dial spacing, and
//! exponential backoff.
//!
//! Each worker task owns one connection slot. Slots rotate through the
//! configured peer list, so a long run eventually visits every seed without
//! ever exceeding `max_peers` concurrent dials.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::{debug, info};

use crate::session::{run_session, SessionConfig, Shared, SharedSeen};
use crate::sink::ObserverSink;

#[derive(Debug, Clone)]
pub struct RunnerConfig {
    pub session: Arc<SessionConfig>,
    pub peers: Vec<SocketAddr>,
    pub max_peers: usize,
    pub dial_spacing: Duration,
    pub reconnect_min: Duration,
    pub reconnect_max: Duration,
}

impl RunnerConfig {
    pub fn new(session: SessionConfig, peers: Vec<SocketAddr>) -> Self {
        Self {
            session: Arc::new(session),
            peers,
            max_peers: 8,
            dial_spacing: Duration::from_secs(2),
            reconnect_min: Duration::from_secs(5),
            reconnect_max: Duration::from_secs(120),
        }
    }
}

/// Run until `shutdown` flips to `true`.
pub async fn run(cfg: RunnerConfig, sink: ObserverSink, mut shutdown: watch::Receiver<bool>) {
    if cfg.peers.is_empty() || cfg.max_peers == 0 {
        info!("observer: no peers configured");
        return;
    }
    let peers = Arc::new(cfg.peers.clone());
    let next = Arc::new(AtomicUsize::new(0));
    let shared: Shared = Arc::new(std::sync::Mutex::new(SharedSeen::default()));
    let mut tasks = JoinSet::new();

    for slot in 0..cfg.max_peers {
        let peers = peers.clone();
        let next = next.clone();
        let shared = shared.clone();
        let sink = sink.clone();
        let cfg = cfg.clone();
        let shutdown = shutdown.clone();
        // Space out the initial dials so a page of seeds does not look like
        // a burst to the network.
        tokio::time::sleep(cfg.dial_spacing * slot as u32).await;
        tasks.spawn(async move {
            worker(slot, cfg, peers, next, shared, sink, shutdown).await;
        });
    }

    // Also stop if the caller's shutdown sender is dropped.
    let _ = shutdown.changed().await;
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    info!("observer: runner stopped");
}

async fn worker(
    slot: usize,
    cfg: RunnerConfig,
    peers: Arc<Vec<SocketAddr>>,
    next: Arc<AtomicUsize>,
    shared: Shared,
    sink: ObserverSink,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut backoff = cfg.reconnect_min;
    loop {
        if *shutdown.borrow() {
            return;
        }
        let idx = next.fetch_add(1, Ordering::Relaxed);
        let peer = peers[idx % peers.len()];
        let started = Instant::now();
        match tokio::time::timeout(cfg.session.connect_timeout, TcpStream::connect(peer)).await {
            Ok(Ok(stream)) => {
                let addr = stream.peer_addr().unwrap_or(peer);
                debug!(slot, peer = %addr, "observer: connected");
                run_session(
                    stream,
                    addr,
                    cfg.session.clone(),
                    sink.clone(),
                    shared.clone(),
                    None,
                )
                .await;
                let lived = started.elapsed();
                // A session that lasted long enough means the peer is fine;
                // reset the backoff instead of escalating forever.
                if lived >= Duration::from_secs(60) {
                    backoff = cfg.reconnect_min;
                }
            }
            Ok(Err(e)) => {
                debug!(slot, peer = %peer, error = %e, "observer: connect failed");
            }
            Err(_) => {
                debug!(slot, peer = %peer, "observer: connect timed out");
            }
        }

        let sleep_for = if backoff > cfg.reconnect_max {
            cfg.reconnect_max
        } else {
            backoff
        };
        tokio::select! {
            _ = tokio::time::sleep(sleep_for) => {}
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return;
                }
            }
        }
        backoff = (backoff * 2).min(cfg.reconnect_max);
    }
}
