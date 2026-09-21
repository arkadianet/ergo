//! Manually-run benchmark against a populated ergo-data/ directory.

use std::path::PathBuf;
use std::time::Instant;

use ergo_crypto::difficulty::DifficultyParams;
use ergo_state::store::StateStore;
use ergo_sync::executor::SyncExecutor;
use ergo_validation::context::ProtocolParams;

#[test]
#[ignore = "requires populated ergo-data/ — run manually"]
fn startup_under_60_seconds_on_mainnet_snapshot() {
    let path = PathBuf::from(
        std::env::var("ERGO_DATA_PATH").unwrap_or_else(|_| "ergo-data/mainnet/state".into()),
    );
    let t0 = Instant::now();
    let store = ergo_state::StateBackendKind::Utxo(StateStore::open(&path).unwrap());
    let t_open = t0.elapsed();

    let t0 = Instant::now();
    let mut exec = SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        DifficultyParams::mainnet(),
    );
    exec.hydrate_from_store(&store).expect("hydrate_from_store");
    exec.hydrate_block_context(&store)
        .expect("hydrate_block_context");
    exec.load_header_index(&store).expect("load_header_index");
    let t_hydrate = t0.elapsed();

    eprintln!(
        "open={t_open:?} hydrate+index={t_hydrate:?} total={:?}",
        t_open + t_hydrate,
    );
    assert!(
        (t_open + t_hydrate).as_secs() < 60,
        "startup exceeded 60s: open={t_open:?} hydrate+index={t_hydrate:?}",
    );
}
