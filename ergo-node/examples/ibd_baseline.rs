//! Bounded offline mainnet IBD body replay using production validation and persistence.
//! Run through scripts/bench-ibd.py; never opens an existing node database.
pub use ergo_node::{mem_csv, mem_probe, mem_smaps};
use ergo_primitives::{digest::ModifierId, reader::VlqReader, writer::VlqWriter};
use ergo_ser::{
    block_transactions::{write_block_transactions, BlockTransactions},
    extension::{write_extension, Extension, ExtensionField},
    modifier_id::ExpectedSections,
};
use std::{
    collections::HashMap,
    error::Error,
    path::PathBuf,
    time::{Duration, Instant},
};
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[path = "../src/mem_maps.rs"]
mod mem_maps;
#[path = "../src/mem_marker.rs"]
mod mem_marker;

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

type FixtureSet = (Vec<[u8; 32]>, HashMap<[u8; 32], (u8, Vec<u8>)>, [u8; 33]);

fn fixtures() -> Result<FixtureSet> {
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../test-vectors/mainnet");
    let headers: Vec<serde_json::Value> = serde_json::from_str(&std::fs::read_to_string(
        directory.join("headers_1_2000.json"),
    )?)?;
    let txs: Vec<serde_json::Value> = serde_json::from_str(&std::fs::read_to_string(
        directory.join("transactions_1_1000.json"),
    )?)?;
    let mut ids = Vec::new();
    let mut data = HashMap::new();
    let mut previous = None;
    let mut links = Vec::new();
    let mut root = [0; 33];
    for row in headers.iter().take(1000) {
        let raw = hex::decode(row["bytes"].as_str().ok_or("header bytes")?)?;
        let id = *ergo_primitives::digest::blake2b256(&raw).as_bytes();
        let header = ergo_ser::header::read_header(&mut VlqReader::new(&raw))?;
        if let Some(parent) = previous.as_ref() {
            links = ergo_validation::popow::algos::update_interlinks(parent, &links)?;
        }
        let sections = ExpectedSections::from_header(
            &id,
            header.transactions_root.as_bytes(),
            header.extension_root.as_bytes(),
            header.ad_proofs_root.as_bytes(),
        );
        let transactions = txs
            .iter()
            .filter(|t| t["height"].as_u64() == Some(u64::from(header.height)))
            .map(|t| {
                let raw = hex::decode(t["bytes"].as_str().ok_or("tx bytes")?)?;
                Ok(ergo_ser::transaction::read_transaction(
                    &mut VlqReader::new(&raw),
                )?)
            })
            .collect::<Result<Vec<_>>>()?;
        let mut writer = VlqWriter::new();
        write_block_transactions(
            &mut writer,
            &BlockTransactions {
                header_id: ModifierId::from_bytes(id),
                transactions,
            },
        )?;
        let tx_bytes = writer.result();
        ergo_sync::coordinator::verify_section_modifier_id(
            102,
            &sections.transactions_id,
            &tx_bytes,
        )?;
        data.insert(sections.transactions_id, (102, tx_bytes));
        let extension = Extension {
            header_id: ModifierId::from_bytes(id),
            fields: ergo_validation::popow::algos::pack_interlinks(&links)
                .into_iter()
                .map(|(key, value)| ExtensionField {
                    key: key.try_into().expect("interlink key"),
                    value,
                })
                .collect(),
        };
        let mut writer = VlqWriter::new();
        write_extension(&mut writer, &extension)?;
        let extension_bytes = writer.result();
        ergo_sync::coordinator::verify_section_modifier_id(
            108,
            &sections.extension_id,
            &extension_bytes,
        )?;
        data.insert(sections.extension_id, (108, extension_bytes));
        root = *header.state_root.as_bytes();
        previous = Some(header);
        data.insert(id, (101, raw));
        ids.push(id);
    }
    Ok((ids, data, root))
}

fn sample(
    store: &ergo_state::store::StateStore,
    phase: &'static str,
    file: &mut std::fs::File,
) -> Result<()> {
    let metrics = store.metrics();
    let row = mem_csv::MemSample {
        ts_ms: mem_csv::now_ms(),
        best_header: store.chain_state().best_header_height,
        best_full_block: store.height(),
        sync_phase: phase,
        proc: mem_probe::read_proc_status().ok_or("process status unavailable")?,
        smaps: mem_smaps::read_smaps_rollup().ok_or("smaps unavailable")?,
        avl_cache_clean_bytes: metrics.arena_cache_clean_bytes as u64,
        avl_cache_capacity_bytes: metrics.arena_cache_capacity_bytes as u64,
        avl_clean_len: metrics.arena_cache_clean_len as u64,
        avl_dirty_len: metrics.arena_cache_dirty_len as u64,
        avl_read_count: metrics.arena_read_count,
        batch_headers_len: metrics.batch_headers_len as u64,
        batch_headers_bytes: metrics.batch_headers_bytes as u64,
        batch_meta_len: metrics.batch_meta_len as u64,
        ..Default::default()
    };
    mem_csv::append_row(file, &row)?;
    Ok(())
}

fn apply(
    backend: &mut ergo_state::StateBackendKind,
    ids: &[[u8; 32]],
    perf: &ergo_sync::perf::BlockPerfCounters,
    mut sample_file: Option<&mut std::fs::File>,
) -> Result<(usize, usize)> {
    let mut cached = Vec::new();
    let mut queue_peak = 0;
    let mut pinned_peak = 0;
    for (index, id) in ids.iter().enumerate() {
        let block = ergo_sync::block_proc::process_block(
            backend,
            id,
            &ergo_validation::context::ProtocolParams::mainnet_default(),
            if cached.is_empty() {
                None
            } else {
                Some(&cached)
            },
            None,
            None,
            Some(perf),
            None,
        )?;
        if let Some(header) = block.checked_header {
            cached.insert(0, header);
            cached.truncate(10);
        }
        let store = backend.as_utxo().ok_or("UTXO store")?;
        let metrics = store.metrics();
        queue_peak = queue_peak.max(metrics.persist_queue_len);
        pinned_peak = pinned_peak.max(metrics.arena_unpersisted_pinned_bytes);
        if index % 10 == 0 {
            if let Some(file) = sample_file.as_deref_mut() {
                sample(store, "OfflineIBD", file)?;
            }
        }
    }
    Ok((queue_peak, pinned_peak))
}

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let mode = args
        .next()
        .ok_or("prepare|replay NEW_DIRECTORY CACHE_BYTES")?;
    let directory = PathBuf::from(args.next().ok_or("NEW directory")?);
    let cache: usize = args.next().ok_or("cache bytes")?.parse()?;
    if directory.exists() {
        return Err("refusing existing directory".into());
    }
    std::fs::create_dir_all(&directory)?;
    let path = directory.join("state.redb");
    if mode == "prepare" {
        let (ids, data, expected_root) = fixtures()?;
        let mut store = ergo_state::store::StateStore::open_with_cache(&path, cache)?;
        store.initialize_genesis(&ergo_node::genesis::mainnet_genesis_boxes())?;
        // Real PoW and difficulty validation during preparation, outside the
        // measured full-block interval. No trusted script checkpoint.
        for id in &ids {
            ergo_sync::header_proc::process_header(&mut store, &data[id].1)?;
        }
        for (id, (kind, raw)) in &data {
            if *kind != 101 {
                store.store_block_section_typed(id, raw, *kind)?;
            }
        }
        drop(data);
        store.set_ibd_mode(true, 500);
        store.enable_persist_pipeline(64);
        let mut backend = ergo_state::StateBackendKind::Utxo(store);
        apply(&mut backend, &ids, &Default::default(), None)?;
        let store = backend.as_utxo_mut().ok_or("UTXO store")?;
        if store.root_digest().as_bytes() != &expected_root {
            return Err("preparation root mismatch".into());
        }
        store.shutdown_cleanly()?;
        println!(
            "{}",
            serde_json::json!({"snapshot":path,"tip":1000,"root":hex::encode(expected_root)})
        );
        return Ok(());
    }
    if mode != "replay" {
        return Err("expected prepare|replay".into());
    }
    let snapshot = PathBuf::from(args.next().ok_or("snapshot file")?);
    if !snapshot.is_file() {
        return Err("missing snapshot".into());
    }
    std::fs::copy(snapshot, &path)?;
    // Exclude the initial file copy and rollback from the measured interval.
    std::fs::File::open(&path)?.sync_all()?;
    let mut store = ergo_state::store::StateStore::open_with_cache(&path, cache)?;
    let tip = store.height();
    if tip != 1000 {
        return Err("requires the pinned early-mainnet snapshot at 1000".into());
    }
    let root = store.root_digest();
    let start = tip - 150;
    let ids: Vec<_> = (start + 1..=tip)
        .map(|height| {
            store
                .get_header_id_at_height(height)?
                .ok_or("missing header".into())
        })
        .collect::<Result<_>>()?;
    store.rollback_to(start, None, None)?;
    store.set_ad_proofs_apply_policy(ergo_state::store::AdProofsApplyPolicy::VerifyShipped);
    store.set_ibd_mode(true, 500);
    store.enable_persist_pipeline(64);
    let csv_path = std::env::var_os("ERGO_MEM_CSV").ok_or("set ERGO_MEM_CSV")?;
    let mut file = mem_csv::open_or_init(std::path::Path::new(&csv_path))?;
    mem_marker::record_init_marker("benchmark_before_apply");
    sample(&store, "BeforeApply", &mut file)?;
    let mut backend = ergo_state::StateBackendKind::Utxo(store);
    let perf = ergo_sync::perf::BlockPerfCounters::default();
    let started = Instant::now();
    let (queue_peak, pinned_peak) = apply(&mut backend, &ids, &perf, Some(&mut file))?;
    let enqueue_seconds = started.elapsed().as_secs_f64();
    let store = backend.as_utxo_mut().ok_or("UTXO store")?;
    store.flush_persist_pipeline()?;
    let committed_seconds = started.elapsed().as_secs_f64();
    if store.height() != tip || store.root_digest() != root {
        return Err("replay root/height mismatch".into());
    }
    let phases = perf.take();
    mem_marker::record_init_marker("benchmark_after_commit");
    sample(store, "AfterCommit", &mut file)?;
    store.shutdown_cleanly()?;
    let durable_seconds = started.elapsed().as_secs_f64();
    // Keep the same open process at rest to measure retained allocations.
    for _ in 0..3 {
        std::thread::sleep(Duration::from_millis(500));
        sample(store, "Plateau", &mut file)?;
    }
    mem_marker::record_init_marker("benchmark_plateau");
    drop(backend);
    let mut reopened = ergo_state::store::StateStore::open_with_cache(&path, cache)?;
    if reopened.height() != tip || reopened.root_digest() != root {
        return Err("restart root/height mismatch".into());
    }
    reopened.shutdown_cleanly()?;
    println!(
        "{}",
        serde_json::json!({"start_height":start,"end_height":tip,"blocks":150,"enqueue_seconds":enqueue_seconds,
        "committed_seconds":committed_seconds,"durable_seconds":durable_seconds,"blocks_per_second":150.0/durable_seconds,
        "cache_bytes":cache,"root":hex::encode(root.as_bytes()),"restart_verified":true,"persist_queue_sampled_peak":queue_peak,
        "unpersisted_pinned_bytes_sampled_peak":pinned_peak,"phases_ms":{"header_load":phases.header_load_ns as f64/1e6,
        "sections_load":phases.sections_load_ns as f64/1e6,"parent_context":phases.parent_ctx_ns as f64/1e6,
        "validation":phases.validate_ns as f64/1e6,"apply_enqueue":phases.apply_ns as f64/1e6,"total":phases.total_ns as f64/1e6}})
    );
    Ok(())
}
