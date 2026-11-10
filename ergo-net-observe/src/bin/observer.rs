//! Standalone Phase 0 network observer.
//!
//! Connects to a bounded set of legacy P2P peers, performs the ordinary
//! handshake, and records announce/request/receive timing plus connection
//! lifecycle as `ergo-observer/1` JSONL. It is deliberately read-mostly:
//! it requests only what the operator enables, rate-limits every request,
//! and enforces a global outbound byte ceiling.
//!
//! The observer is not a full node. It never advertises a declared address,
//! never claims a chain state mode, never mines, and never relays blocks or
//! transactions. See `docs/unverified.md` for what it can and cannot infer.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use ergo_chain_spec::Network;
use ergo_net_observe::util::is_local;
use ergo_net_observe::{
    runner::{run, RunnerConfig},
    session::{SessionConfig, OUTBOUND_BYTES_PER_SEC},
    sink::{ObserverSink, SinkConfig},
    Event, Pseudonymizer,
};
use tokio::sync::watch;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "ergo-net-observe",
    about = "Phase 0 Ergo P2P observer: honest legacy sessions + JSONL timing records"
)]
struct Cli {
    /// Network whose magic bytes and default seed peers to use.
    #[arg(long, default_value = "mainnet")]
    network: String,

    /// Comma-separated `host:port` peers. Overrides the network seed list.
    #[arg(long, value_delimiter = ',')]
    peers: Vec<String>,

    /// File with one `host:port` per line (`#` comments allowed). Added to
    /// `--peers` and the network seed list when either is absent.
    #[arg(long)]
    peers_file: Option<PathBuf>,

    /// JSONL output path.
    #[arg(long, default_value = "observer.jsonl")]
    out: PathBuf,

    /// Operator label for this vantage, copied into every record.
    #[arg(long, default_value = "local")]
    vantage: String,

    /// Wall-clock offset in milliseconds (true time minus local wall time).
    /// Ignored when `--clock-source` is `chrony`.
    #[arg(long, default_value_t = 0.0)]
    clock_offset_ms: f64,

    /// Clock-discipline source recorded with every sample: `unset`,
    /// `operator`, or `chrony` (read from `chronyc tracking`).
    #[arg(long, default_value = "unset")]
    clock_source: String,

    /// Key file for keyed peer-address pseudonymisation. Created with a
    /// random key and mode 0600 when missing. Never written to the output.
    #[arg(long, default_value = "observer-pseudonym.key")]
    pseudonym_key: PathBuf,

    /// Emit raw peer addresses instead of keyed pseudonyms. For local
    /// debugging only.
    #[arg(long)]
    reveal_peer_addresses: bool,

    /// Maximum concurrent peer sessions.
    #[arg(long, default_value_t = 8)]
    max_peers: usize,

    /// Seconds between consecutive outbound dials at startup.
    #[arg(long, default_value_t = 2)]
    dial_spacing_secs: u64,

    /// TCP connect timeout.
    #[arg(long, default_value_t = 10)]
    connect_timeout_secs: u64,

    /// Close a session after this long without any message from the peer.
    #[arg(long, default_value_t = 600)]
    idle_timeout_secs: u64,

    /// Whole-handshake deadline (send + read).
    #[arg(long, default_value_t = 30)]
    handshake_timeout_secs: u64,

    /// Minimum seconds between RequestModifier frames to one peer.
    #[arg(long, default_value_t = 2)]
    request_interval_secs: u64,

    /// Maximum unanswered requests in flight to one peer.
    #[arg(long, default_value_t = 4)]
    max_outstanding: usize,

    /// Maximum modifier ids per RequestModifier.
    #[arg(long, default_value_t = 64)]
    max_ids_per_request: usize,

    /// Ask for announced block headers.
    #[arg(long, default_value_t = true)]
    request_headers: bool,

    /// Ask for announced block sections (block transactions, AD proofs,
    /// extension).
    #[arg(long, default_value_t = false)]
    request_bodies: bool,

    /// Ask for announced transactions. Off by default: the standalone
    /// observer cannot validate them, and tx traffic is the most expensive
    /// thing on the network.
    #[arg(long, default_value_t = false)]
    request_txs: bool,

    /// Agent name advertised in the handshake. Must be truthful.
    #[arg(long, default_value = "ergo-rust-observer")]
    agent_name: String,

    /// Node name advertised in the handshake.
    #[arg(long, default_value = "ergo-rust-observer-phase0")]
    node_name: String,

    /// Stop after this many seconds. Zero means run until interrupted.
    #[arg(long, default_value_t = 0)]
    duration_secs: u64,

    /// Permit loopback / private / link-local peers. Required for testnet
    /// nodes on localhost and for any lab setup.
    #[arg(long)]
    allow_local: bool,

    /// Capture raw handshake bytes as hex on the handshake records.
    /// Offline replay analysis only; off in the standing dataset streams.
    #[arg(long, default_value_t = false)]
    capture_handshake_hex: bool,

    /// Log filter for the observer process itself (not the dataset).
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

    let peers = resolve_peers(&cli, &chain)?;
    if peers.is_empty() {
        return Err("no peers: pass --peers/--peers-file or use a network with seeds".into());
    }
    if !cli.allow_local {
        if let Some(local) = peers.iter().find(|p| is_local(p.ip())) {
            return Err(format!(
                "refusing local/private peer {local}: pass --allow-local to permit lab use"
            )
            .into());
        }
    }

    let (clock_offset_ms, clock_source) = resolve_clock(&cli);

    let pseudonymizer =
        Pseudonymizer::from_key_file(&cli.pseudonym_key, !cli.reveal_peer_addresses)?;

    let session = SessionConfig {
        magic: chain.network_params.magic,
        network: network.to_string(),
        agent_name: cli.agent_name.clone(),
        node_name: cli.node_name.clone(),
        connect_timeout: Duration::from_secs(cli.connect_timeout_secs),
        idle_timeout: Duration::from_secs(cli.idle_timeout_secs),
        request_headers: cli.request_headers,
        request_bodies: cli.request_bodies,
        request_txs: cli.request_txs,
        request_interval: Duration::from_secs(cli.request_interval_secs),
        max_outstanding: cli.max_outstanding.max(1),
        max_ids_per_request: cli.max_ids_per_request.max(1),
        request_handshake_timeout: Duration::from_secs(cli.handshake_timeout_secs),
        respond_to_sync_info: true,
        capture_handshake_hex: cli.capture_handshake_hex,
        ..SessionConfig::default()
    };

    let sink = ObserverSink::spawn(SinkConfig {
        vantage: cli.vantage.clone(),
        clock_offset_ms,
        clock_source: clock_source.clone(),
        path: cli.out.clone(),
        queue: 8192,
        pseudonymizer,
    })?;

    sink.try_emit(Event::ObserverStart {
        network: session.network.clone(),
        agent: session.agent_name.clone(),
        node_name: session.node_name.clone(),
        version: session.protocol_version.to_string(),
        peer_count: peers.len(),
        request_headers: session.request_headers,
        request_bodies: session.request_bodies,
        request_txs: session.request_txs,
        outbound_bytes_per_sec: OUTBOUND_BYTES_PER_SEC,
    });

    info!(
        network = %network,
        peers = peers.len(),
        max_peers = cli.max_peers,
        out = %cli.out.display(),
        outbound_cap_bps = OUTBOUND_BYTES_PER_SEC,
        "observer starting"
    );

    let runner = RunnerConfig {
        session: std::sync::Arc::new(session),
        peers,
        max_peers: cli.max_peers.max(1),
        dial_spacing: Duration::from_secs(cli.dial_spacing_secs),
        reconnect_min: Duration::from_secs(5),
        reconnect_max: Duration::from_secs(120),
    };

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let sink_for_task = sink.clone();
    let mut runner_handle = tokio::spawn(async move {
        run(runner, sink_for_task, shutdown_rx).await;
    });

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
    let _ = tokio::time::timeout(Duration::from_secs(5), &mut runner_handle).await;
    let dropped = sink.dropped();
    if dropped > 0 {
        sink.try_emit(Event::Gap { dropped });
        error!(dropped, "observer sink dropped records");
    }
    // Give the sink writer one idle-flush window so final records land
    // before the runtime (and its writer task) is dropped.
    tokio::time::sleep(Duration::from_millis(300)).await;
    info!(dropped, "observer stopped");
    Ok(())
}

fn resolve_peers(
    cli: &Cli,
    chain: &ergo_chain_spec::ChainSpec,
) -> Result<Vec<SocketAddr>, Box<dyn std::error::Error>> {
    let mut raw: Vec<String> = cli.peers.clone();
    if let Some(path) = &cli.peers_file {
        raw.extend(ergo_net_observe::util::read_peer_file(path)?);
    }
    ergo_net_observe::util::parse_peer_list(raw, chain.bootstrap.seed_peers.clone())
        .map_err(Box::<dyn std::error::Error>::from)
}

/// Best-effort clock offset. `chronyc tracking` reports the system clock's
/// error against NTP; we record `true - local` in milliseconds.
fn resolve_clock(cli: &Cli) -> (f64, String) {
    let (offset, source) =
        ergo_net_observe::util::resolve_clock(cli.clock_offset_ms, &cli.clock_source);
    if source == "unset" && cli.clock_source == "chrony" {
        error!("--clock-source chrony requested but `chronyc tracking` unavailable");
    }
    (offset, source)
}
