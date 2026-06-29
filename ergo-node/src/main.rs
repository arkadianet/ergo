use clap::Parser;
use ergo_node::config::{Cli, LoggingConfig, LoggingFormat, NodeConfig};
use tracing::{error, info};
use tracing_appender::non_blocking::{NonBlockingBuilder, WorkerGuard};
use tracing_appender::rolling::Rotation;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter, Layer, Registry};

#[tokio::main]
async fn main() {
    // Config load runs before tracing init so the subscriber knows
    // whether `[logging.file]` was requested. Errors here predate the
    // subscriber and go to stderr directly. The single warn emitted
    // inside config-load (non-loopback API bind) reaches a no-op
    // subscriber by design — operators see it on next boot once the
    // file appender is wired, and rejected configs error out instead.
    let cli = Cli::parse();
    let config = match NodeConfig::load(cli) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config load failed: {e}");
            std::process::exit(1);
        }
    };

    let _file_guard = init_tracing(&config.logging);

    // Route panics through tracing so a crash lands in the structured/file
    // (and JSON) sink with a wall-clock timestamp, not only on raw stderr.
    // Installed right after the subscriber so the hook's events are captured.
    std::panic::set_hook(Box::new(|info| {
        // An expected, already-contained AVL verifier panic: a malformed
        // attacker-supplied proof, caught in ergo-sigma's `avl.rs` and surfaced
        // as a fail-closed tx-invalid error. Suppress the alarming "node
        // panicked" log so a flood of crafted transactions cannot amplify into
        // a log-flood DoS; the rejection stays observable on the validation
        // path. (Do NOT mutate the global hook per-operation — that would be
        // racy under Rayon block validation.)
        if ergo_sigma::avl::in_expected_avl_panic() {
            return;
        }
        let location = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_else(|| "unknown".to_string());
        error!(panic = %info, location = %location, "node panicked");
    }));

    // Single structured `node_starting` event consolidates what used
    // to be three loose info!s (`network` / `data dir` / `peers`)
    // plus the file-logging field block. Downstream parsers (any
    // future journal-events consumer, dashboards, log aggregators)
    // see one row per boot rather than a fixed-order trio that drifts
    // across refactors.
    if let Some(file) = &config.logging.file {
        info!(
            event = "node_starting",
            network = ?config.network,
            data_dir = %config.data_dir.display(),
            known_peers = config.known_peers.len(),
            file_logging = true,
            file_dir = %file.dir.display(),
            file_prefix = %file.prefix,
            file_rotation = %file.rotation,
            file_max_files = file.max_files,
            file_loss_mode = "non_lossy",
            "node starting",
        );
    } else {
        info!(
            event = "node_starting",
            network = ?config.network,
            data_dir = %config.data_dir.display(),
            known_peers = config.known_peers.len(),
            file_logging = false,
            "node starting",
        );
    }

    if let Err(e) = ergo_node::run(config).await {
        error!(error = %e, "node fatal error");
        std::process::exit(1);
    }
}

/// Wire tracing-subscriber: stderr always, plus an optional non-blocking
/// rolling-file appender when `[logging.file]` is set. The returned
/// `WorkerGuard` (when present) MUST live for the rest of `main` —
/// dropping it flushes the background writer and closes the file. We
/// bind it as `_file_guard` for that exact reason.
///
/// Compression of rotated files is intentionally out of scope:
/// tracing-appender writes plain text. Pair with `logrotate(8)` (Linux)
/// or an equivalent OS scheduler if `.gz` rotation is required —
/// `max_files` provides retention via deletion.
///
/// `tracing-log` bridges `log::*!` from transitive deps (redb, hyper,
/// axum) through tracing so RUST_LOG filters them uniformly. The
/// bridge is installed by `tracing-subscriber`'s `.init()` because the
/// crate's default features include `tracing-log` — calling
/// `LogTracer::init()` manually here too would fail with
/// `SetLoggerError` on the second install.
fn init_tracing(cfg: &LoggingConfig) -> Option<WorkerGuard> {
    // EnvFilter is attached per-layer so the layers can be boxed to a
    // single trait-object type — applying EnvFilter as a top-level layer
    // changes the subscriber's concrete type, which makes
    // `Box<dyn Layer<Registry>>` fail to satisfy the next `.with(...)`.
    // Per-layer filters yield identical filtering behavior here because
    // both layers share the same filter expression.
    let mk_filter = || -> EnvFilter {
        EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new(cfg.default_level.as_str()))
    };

    let stderr_layer: Box<dyn Layer<Registry> + Send + Sync> = match cfg.format {
        LoggingFormat::Text => Box::new(
            fmt::layer()
                .with_target(true)
                .with_timer(fmt::time::SystemTime)
                .with_writer(std::io::stderr)
                .with_filter(mk_filter()),
        ),
        LoggingFormat::Json => Box::new(
            fmt::layer()
                .json()
                .with_current_span(true)
                .with_span_list(true)
                .with_target(true)
                .with_timer(fmt::time::SystemTime)
                .with_writer(std::io::stderr)
                .with_filter(mk_filter()),
        ),
    };

    let mut layers: Vec<Box<dyn Layer<Registry> + Send + Sync>> = vec![stderr_layer];
    let guard = if let Some(file) = &cfg.file {
        match build_file_layer(file, cfg.format) {
            Ok((file_layer, g)) => {
                layers.push(file_layer);
                Some(g)
            }
            Err(msg) => {
                // Subscriber isn't installed yet — bypass tracing so the
                // operator sees why file output dropped, then continue
                // with stderr-only.
                eprintln!("{msg}");
                None
            }
        }
    } else {
        None
    };

    // `Vec<Box<dyn Layer<Registry>>>` implements `Layer<Registry>` as a
    // single combined layer, sidestepping the trait-object subscriber-type
    // mismatch that chained `.with(box).with(box)` runs into.
    Registry::default().with(layers).init();
    guard
}

fn build_file_layer(
    file: &ergo_node::config::LoggingFileConfig,
    format: LoggingFormat,
) -> Result<(Box<dyn Layer<Registry> + Send + Sync>, WorkerGuard), String> {
    std::fs::create_dir_all(&file.dir).map_err(|e| {
        format!(
            "logging file output disabled: failed to create {}: {e}",
            file.dir.display()
        )
    })?;

    let rotation = match file.rotation.as_str() {
        "minutely" => Rotation::MINUTELY,
        "hourly" => Rotation::HOURLY,
        "daily" => Rotation::DAILY,
        "never" => Rotation::NEVER,
        // Validated at config-load time; an unknown value here is a
        // programmer error.
        other => unreachable!("unvalidated rotation {other:?}"),
    };

    let appender = tracing_appender::rolling::Builder::new()
        .filename_prefix(&file.prefix)
        .filename_suffix("log")
        .rotation(rotation)
        .max_log_files(file.max_files)
        .build(&file.dir)
        .map_err(|e| {
            format!(
                "logging file output disabled: failed to build appender at {}: {e}",
                file.dir.display()
            )
        })?;
    // Non-lossy: when the worker thread's queue fills, writers block
    // rather than silently dropping log lines. We prefer back-pressure
    // on hot loggers over invisible loss — operators need full event
    // streams for post-mortem. Default `tracing_appender::non_blocking`
    // is lossy; the builder is the only way to flip it.
    let (non_blocking, guard) = NonBlockingBuilder::default()
        .lossy(false)
        .thread_name("ergo-node-log")
        .finish(appender);

    let env_filter = || -> EnvFilter {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))
    };

    let layer: Box<dyn Layer<Registry> + Send + Sync> = match format {
        LoggingFormat::Text => Box::new(
            fmt::layer()
                .with_target(true)
                .with_timer(fmt::time::SystemTime)
                .with_ansi(false)
                .with_writer(non_blocking)
                .with_filter(env_filter()),
        ),
        LoggingFormat::Json => Box::new(
            fmt::layer()
                .json()
                .with_current_span(true)
                .with_span_list(true)
                .with_target(true)
                .with_timer(fmt::time::SystemTime)
                .with_writer(non_blocking)
                .with_filter(env_filter()),
        ),
    };
    Ok((layer, guard))
}
