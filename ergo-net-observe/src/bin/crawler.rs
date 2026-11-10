//! Standalone Phase 0 network crawler.
//!
//! The same honest, read-mostly legacy session as the `observer` binary,
//! plus a bounded discovery walk: live sessions forward their `Peers`
//! replies to a shared frontier, and idle slots dial learned addresses at
//! a capped global rate with per-address exponential retry backoff.
//!
//! The crawler never relays blocks or transactions and never claims a
//! state mode. Its state file contains raw peer addresses — keep it
//! private, it is not part of the publishable dataset.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use clap::Parser;
use ergo_chain_spec::Network;
use ergo_net_observe::crawler::{
    AttemptOutcome, CrawlChannel, CrawlConfig, CrawlState, STATE_SAVE_INTERVAL,
};
use ergo_net_observe::session::{
    run_session, SessionConfig, Shared, SharedSeen, OUTBOUND_BYTES_PER_SEC,
};
use ergo_net_observe::sink::{ObserverSink, SinkConfig};
use ergo_net_observe::util::{is_local, parse_peer_list, read_peer_file, resolve_clock};
use ergo_net_observe::Event;
use ergo_net_observe::Pseudonymizer;
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

/// How often an idle slot re-polls the frontier for the next dial.
const SLOT_POLL: Duration = Duration::from_millis(500);

#[derive(Parser)]
#[command(
    name = "crawler",
    about = "Phase 0 bounded Ergo P2P discovery crawler (honest legacy peer)"
)]
struct Cli {
    /// Network to walk.
    #[arg(long, default_value = "mainnet")]
    network: String,

    /// Seed peer `host:port`; any provided seed replaces the chain's seed
    /// list entirely.
    #[arg(long)]
    peers: Vec<String>,

    /// Seed peer list file: one `host:port` per line, `#` comments.
    #[arg(long)]
    peers_file: Option<PathBuf>,

    /// Maximum concurrent sessions.
    #[arg(long, default_value_t = 8)]
    max_peers: u32,

    /// Maximum *new* dials per minute across all slots.
    #[arg(long, default_value_t = 12)]
    dial_rate: u32,

    /// Per-address retry backoff floor, seconds.
    #[arg(long, default_value_t = 60)]
    backoff_min_secs: u64,

    /// Per-address retry backoff cap, seconds.
    #[arg(long, default_value_t = 21_600)]
    backoff_max_secs: u64,

    /// Persistent frontier state file (raw addresses — keep private).
    /// Omit for in-memory only.
    #[arg(long)]
    state: Option<PathBuf>,

    /// Permit dialing local/private learned addresses (lab use).
    #[arg(long, default_value_t = false)]
    allow_local: bool,

    /// JSONL output file (`ergo-observer/1`).
    #[arg(long)]
    out: PathBuf,

    /// Operator label copied into every record.
    #[arg(long)]
    vantage: String,

    /// Wall-clock offset to record (ms), when `--clock-source operator`.
    #[arg(long, default_value_t = 0.0)]
    clock_offset_ms: f64,

    /// Where the clock offset came from: unset | operator | chrony.
    #[arg(long, default_value = "unset")]
    clock_source: String,

    /// Pseudonymisation key file.
    #[arg(long)]
    pseudonym_key: PathBuf,

    /// Emit raw peer addresses. Debugging only; do not publish such a file.
    #[arg(long, default_value_t = false)]
    reveal_peer_addresses: bool,

    /// Agent name advertised in the handshake. Must be truthful.
    #[arg(long, default_value = "ergo-rust-crawler")]
    agent_name: String,

    /// Node name advertised in the handshake.
    #[arg(long, default_value = "ergo-rust-crawler-phase0")]
    node_name: String,

    /// Request announced header ids. Bodies and txs are never requested.
    #[arg(long, default_value_t = true)]
    request_headers: bool,

    /// TCP connect timeout, seconds.
    #[arg(long, default_value_t = 10)]
    connect_timeout_secs: u64,

    /// Session idle timeout, seconds.
    #[arg(long, default_value_t = 600)]
    idle_timeout_secs: u64,

    /// Stop after this many seconds. Zero means run until interrupted.
    #[arg(long, default_value_t = 0)]
    duration_secs: u64,

    /// Log filter for the crawler process itself (not the dataset).
    #[arg(long, default_value = "info")]
    log: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_new(&cli.log)?)
        .with_writer(std::io::stderr)
        .init();

    let network: Network = cli.network.parse().map_err(|e| format!("--network: {e}"))?;
    let chain = ergo_chain_spec::ChainSpec::for_network(network);

    let mut raw: Vec<String> = cli.peers.clone();
    if let Some(path) = &cli.peers_file {
        raw.extend(read_peer_file(path)?);
    }
    let seeds = parse_peer_list(raw, chain.bootstrap.seed_peers.clone())?;
    if seeds.is_empty() {
        return Err("no seed peers: pass --peers/--peers-file or use a network with seeds".into());
    }
    if !cli.allow_local {
        if let Some(local) = seeds.iter().find(|p| is_local(p.ip())) {
            return Err(format!(
                "refusing local/private seed {local}: pass --allow-local to permit lab use"
            )
            .into());
        }
    }

    let (clock_offset_ms, clock_source) = resolve_clock(cli.clock_offset_ms, &cli.clock_source);

    let pseudonymizer =
        Pseudonymizer::from_key_file(&cli.pseudonym_key, !cli.reveal_peer_addresses)?;

    let (crawl, mut gossip_rx) = CrawlChannel::new(256);
    let crawl = Arc::new(crawl);
    let session_cfg = Arc::new(SessionConfig {
        magic: chain.network_params.magic,
        network: network.to_string(),
        agent_name: cli.agent_name.clone(),
        node_name: cli.node_name.clone(),
        connect_timeout: Duration::from_secs(cli.connect_timeout_secs),
        idle_timeout: Duration::from_secs(cli.idle_timeout_secs),
        request_headers: cli.request_headers,
        request_bodies: false,
        request_txs: false,
        crawl: Some(crawl),
        ..SessionConfig::default()
    });

    let sink = ObserverSink::spawn(SinkConfig {
        vantage: cli.vantage.clone(),
        clock_offset_ms,
        clock_source: clock_source.clone(),
        path: cli.out.clone(),
        queue: 8192,
        pseudonymizer,
    })?;

    sink.try_emit(Event::ObserverStart {
        network: session_cfg.network.clone(),
        agent: session_cfg.agent_name.clone(),
        node_name: session_cfg.node_name.clone(),
        version: session_cfg.protocol_version.to_string(),
        peer_count: seeds.len(),
        request_headers: session_cfg.request_headers,
        request_bodies: false,
        request_txs: false,
        outbound_bytes_per_sec: OUTBOUND_BYTES_PER_SEC,
    });

    info!(
        network = %network,
        seeds = seeds.len(),
        max_peers = cli.max_peers,
        dial_rate_per_min = cli.dial_rate,
        out = %cli.out.display(),
        state = ?cli.state.as_deref(),
        "crawler starting"
    );

    let state = CrawlState::new(
        CrawlConfig {
            dial_rate_per_min: cli.dial_rate.max(1),
            backoff_min: Duration::from_secs(cli.backoff_min_secs.max(1)),
            backoff_max: Duration::from_secs(cli.backoff_max_secs.max(1)),
            state_path: cli.state.clone(),
            allow_local: cli.allow_local,
            ..CrawlConfig::default()
        },
        sink.clone(),
        seeds,
    );

    let shared: Shared = Arc::new(Mutex::new(SharedSeen::default()));
    let (shutdown_tx, shutdown) = watch::channel(false);

    // Gossip consumer: learn addresses from live sessions.
    let learn_state = state.clone();
    let learn_handle = tokio::spawn(async move {
        while let Some(report) = gossip_rx.recv().await {
            learn_state.learn(report);
        }
    });

    // Periodic frontier persistence.
    let save_state = state.clone();
    let mut save_shutdown = shutdown.clone();
    let save_handle = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(STATE_SAVE_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = save_shutdown.changed() => break,
                _ = ticker.tick() => save_state.save(),
            }
        }
    });

    // Dial slots.
    let mut slots = JoinSet::new();
    for _ in 0..cli.max_peers.max(1) {
        let state = state.clone();
        let cfg = session_cfg.clone();
        let sink = sink.clone();
        let shared = shared.clone();
        let slot_shutdown = shutdown.clone();
        slots.spawn(slot_worker(state, cfg, sink, shared, slot_shutdown));
    }

    if cli.duration_secs > 0 {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => info!("interrupted"),
            _ = tokio::time::sleep(Duration::from_secs(cli.duration_secs)) => {
                info!(seconds = cli.duration_secs, "duration reached")
            }
        }
    } else {
        let _ = tokio::signal::ctrl_c().await;
        info!("interrupted");
    }

    let _ = shutdown_tx.send(true);
    slots.abort_all();
    while slots.join_next().await.is_some() {}
    // Sessions spawned by slots outlive the slot abort; they drop their
    // gossip-channel senders as they end. Do not wait for that here —
    // abort the consumers and finish persistence.
    learn_handle.abort();
    let _ = save_handle.await;
    state.save();

    let dropped = sink.dropped();
    if dropped > 0 {
        sink.try_emit(Event::Gap { dropped });
        error!(dropped, "crawler sink dropped records");
    }
    // Give the sink writer one idle-flush window so final records land
    // before the runtime (and its writer task) is dropped.
    tokio::time::sleep(Duration::from_millis(300)).await;
    info!(tracked = state.tracked(), dropped, "crawler stopped");
    Ok(())
}

/// One dial slot: take the next due address from the frontier, connect,
/// run one honest session, record the outcome, repeat.
async fn slot_worker(
    state: Arc<CrawlState>,
    cfg: Arc<SessionConfig>,
    sink: ObserverSink,
    shared: Shared,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        if *shutdown.borrow() {
            return;
        }
        let Some(addr) = state.next_due() else {
            wait_for_shutdown(SLOT_POLL, &mut shutdown).await;
            continue;
        };
        let started = Instant::now();
        match tokio::time::timeout(cfg.connect_timeout, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                // Record the dial outcome as soon as the handshake resolves,
                // then wait for the session to finish before the slot takes
                // its next dial (concurrency stays bounded by max_peers).
                let (tx, rx) = tokio::sync::oneshot::channel();
                let session = tokio::spawn(run_session(
                    stream,
                    addr,
                    cfg.clone(),
                    sink.clone(),
                    shared.clone(),
                    Some(tx),
                ));
                let handshaken = rx.await.unwrap_or(false);
                let outcome = if handshaken {
                    AttemptOutcome::Handshaken
                } else {
                    AttemptOutcome::HandshakeFail
                };
                state.note_result(addr, outcome, None);
                session.await.ok();
            }
            Ok(Err(e)) => {
                let kind = if e.kind() == std::io::ErrorKind::ConnectionRefused {
                    AttemptOutcome::ConnectRefused
                } else {
                    AttemptOutcome::ConnectTimeout
                };
                tracing::debug!(peer = %addr, error = %e, "crawler: connect failed");
                state.note_result(addr, kind, Some(started.elapsed().as_millis() as u64));
            }
            Err(_) => {
                state.note_result(
                    addr,
                    AttemptOutcome::ConnectTimeout,
                    Some(cfg.connect_timeout.as_millis() as u64),
                );
            }
        }
        if *shutdown.borrow() {
            return;
        }
    }
}

/// Sleep up to `duration` but return early when `shutdown` flips.
async fn wait_for_shutdown(duration: Duration, shutdown: &mut watch::Receiver<bool>) {
    tokio::select! {
        _ = tokio::time::sleep(duration) => {}
        _ = shutdown.changed() => {}
    }
}
