//! Offline replay benchmark. Only accepts a marked, disposable DB copy.
//! Example: cargo run --release -p ergo-sync --example replay_persist -- /scratch/state.redb 150
//! No peers or API listeners; full script validation, no trusted checkpoint.

use ergo_state::{store::StateStore, StateBackendKind};
use ergo_sync::{block_proc::process_block, perf::BlockPerfCounters};
use ergo_validation::context::ProtocolParams;
use std::{error::Error, path::PathBuf, time::Instant};

fn main() -> Result<(), Box<dyn Error>> {
    // Opt in only for diagnosis; timed comparisons normally leave this off.
    if std::env::var_os("ERGO_REPLAY_TRACE").is_some() {
        tracing_subscriber::fmt()
            .with_env_filter("warn,ergo_state::persist=debug")
            .with_writer(std::io::stderr)
            .with_ansi(false)
            .init();
    }
    let mut args = std::env::args().skip(1);
    let path = PathBuf::from(args.next().ok_or("provide disposable state.redb path")?);
    let count: u32 = args.next().unwrap_or_else(|| "150".into()).parse()?;
    if count == 0 || count > 150 {
        return Err("replay count must be 1..=150".into());
    }
    if std::fs::symlink_metadata(&path)?.file_type().is_symlink()
        || path
            .parent()
            .ok_or("missing parent")?
            .join(".benchmark-copy")
            .read_link()
            .is_ok()
        || std::fs::read_to_string(path.parent().unwrap().join(".benchmark-copy"))?
            != "disposable ergo sync benchmark\n"
    {
        return Err("refusing to mutate an unmarked database or symlink".into());
    }
    // Use the same arena, queue and IBD interval as this host's node.
    let mut store = StateStore::open_with_cache(&path, 2 * 1024 * 1024 * 1024)?;
    let tip = store.height();
    // This example is scoped to the pre-EIP-27 chain interval being diagnosed.
    // A later interval needs the chain-spec re-emission rule bundle.
    if tip >= 777_217 {
        return Err("benchmark requires a pre-EIP-27 snapshot".into());
    }
    let expected_root = store.root_digest();
    let start_height = tip.checked_sub(count).ok_or("snapshot too short")?;
    let ids: Vec<_> = (start_height + 1..=tip)
        .map(|h| {
            store
                .get_header_id_at_height(h)?
                .ok_or_else(|| format!("missing header at {h}").into())
        })
        .collect::<Result<_, Box<dyn Error>>>()?;
    store.set_rollback_window(200);
    store.rollback_to(start_height, None, None)?;
    store.set_ibd_mode(true, 500);
    store.enable_persist_pipeline(64);
    let mut backend = StateBackendKind::Utxo(store);
    let perf = BlockPerfCounters::default();
    let mut executor = ergo_sync::executor::SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        ergo_crypto::difficulty::DifficultyParams::mainnet(),
    );
    executor.hydrate_block_context(&backend)?;
    let mut cached = executor.block_context_headers().to_vec();
    let started = Instant::now();
    for id in ids {
        let processed = process_block(
            &mut backend,
            &id,
            &ProtocolParams::mainnet_default(),
            if cached.is_empty() {
                None
            } else {
                Some(&cached)
            },
            None,
            None,
            Some(&perf),
            None,
        )?;
        if let Some(header) = processed.checked_header {
            cached.insert(0, header);
            cached.truncate(10);
        }
    }
    let enqueue_secs = started.elapsed().as_secs_f64();
    let StateBackendKind::Utxo(store) = &mut backend else {
        unreachable!()
    };
    store.flush_persist_pipeline()?;
    let committed_secs = started.elapsed().as_secs_f64();
    assert_eq!(store.height(), tip);
    assert_eq!(
        store.root_digest(),
        expected_root,
        "replay changed consensus root"
    );
    let p = perf.take();
    store.shutdown_cleanly()?;
    let durable_secs = started.elapsed().as_secs_f64();
    drop(backend);
    let mut reopened = StateStore::open_with_cache(&path, 2 * 1024 * 1024 * 1024)?;
    assert_eq!(reopened.height(), tip);
    assert_eq!(
        reopened.root_digest(),
        expected_root,
        "restart changed consensus root"
    );
    reopened.shutdown_cleanly()?;
    println!("replay start={start_height} end={tip} blocks={count} enqueue_secs={enqueue_secs:.6} committed_secs={committed_secs:.6} durable_secs={durable_secs:.6} bps={:.3} proof_ms={:.3} validate_ms={:.3} apply_ms={:.3} root={}",
        count as f64 / durable_secs, p.proof_ns as f64 / 1e6, p.validate_ns as f64 / 1e6, p.apply_ns as f64 / 1e6,
        hex::encode(expected_root));
    Ok(())
}
