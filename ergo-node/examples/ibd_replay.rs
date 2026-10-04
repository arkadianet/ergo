//! Offline mainnet replay of a marked disposable snapshot copy.
//! Use scripts/bench-ibd.py to lock, hash and copy a closed snapshot first.
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
        redb_state_capacity_bytes: metrics.redb_cache_capacity_bytes as u64,
        redb_state_evictions: metrics.redb_cache_evictions,
        avl_unpersisted_pinned_bytes: metrics.arena_unpersisted_pinned_bytes as u64,
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
    let spec = ergo_chain_spec::ChainSpec::for_network(ergo_chain_spec::Network::Mainnet);
    let rules = spec
        .reemission
        .as_ref()
        .map(|r| ergo_validation::ReemissionRuleInputs {
            activation_height: r.activation_height,
            reemission_token_id: *r.reemission_token_id.as_bytes(),
            pay_to_reemission_tree: spec
                .emission_script_trees()
                .expect("mainnet emission scripts")
                .pay_to_reemission,
        });
    let mut executor = ergo_sync::executor::SyncExecutor::new(
        ergo_validation::context::ProtocolParams::mainnet_default(),
        ergo_crypto::difficulty::DifficultyParams::mainnet(),
    );
    executor.hydrate_block_context(backend)?;
    let mut cached = executor.block_context_headers().to_vec();
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
            rules.as_ref(),
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

#[derive(clap::Parser)]
#[command(about = "Offline full-validation mainnet replay; no network listeners")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Subcommand)]
enum Command {
    /// Build an owned smoke snapshot from the committed first 1000 mainnet blocks.
    Prepare { directory: PathBuf },
    /// Replay the last N blocks on a runner-created disposable copy.
    Replay {
        directory: PathBuf,
        #[arg(long, default_value_t = 150)]
        blocks: u32,
        #[arg(long, default_value_t = 1073741824)]
        avl_cache_bytes: usize,
        #[arg(long, default_value_t = 1073741824)]
        redb_cache_bytes: usize,
        #[arg(long, value_enum, default_value_t = ProofPolicy::Regenerate)]
        proof_policy: ProofPolicy,
        #[arg(long, default_value_t = 64)]
        persist_jobs: usize,
        #[arg(long, default_value_t = 500)]
        flush_interval: u32,
        #[arg(long, default_value_t = 3)]
        retained_seconds: u32,
    },
}

#[derive(Clone, Copy, Debug, clap::ValueEnum, PartialEq, Eq)]
enum ProofPolicy {
    Regenerate,
    VerifyShipped,
}

fn open(path: &std::path::Path, avl: usize, redb: usize) -> Result<ergo_state::store::StateStore> {
    Ok(
        ergo_state::store::StateStore::open_with_cache_budgets_launch_voting(
            path,
            avl,
            redb,
            ergo_validation::scala_launch(),
            ergo_chain_spec::VotingParams::mainnet(),
        )?,
    )
}

fn main() -> Result<()> {
    use clap::Parser;
    match Cli::parse().command {
        Command::Prepare { directory } => {
            // create_dir is exclusive; never reuse a node directory.
            std::fs::create_dir(&directory)?;
            let path = directory.join("state.redb");
            let (ids, data, expected_root) = fixtures()?;
            let mut store = open(&path, 16777216, 16777216)?;
            store.initialize_genesis(&ergo_node::genesis::mainnet_genesis_boxes())?;
            for id in &ids {
                ergo_sync::header_proc::process_header(&mut store, &data[id].1)?;
            }
            for (id, (kind, raw)) in &data {
                if *kind != 101 {
                    store.store_block_section_typed(id, raw, *kind)?;
                }
            }
            drop(data);
            store.set_ibd_mode(true, 500)?;
            store.enable_persist_pipeline(64)?;
            let mut backend = ergo_state::StateBackendKind::Utxo(store);
            apply(&mut backend, &ids, &Default::default(), None)?;
            let store = backend.as_utxo_mut().ok_or("UTXO store")?;
            store.flush_persist_pipeline()?;
            if store.root_digest().as_bytes() != &expected_root {
                return Err("preparation root mismatch".into());
            }
            store.shutdown_cleanly()?;
            drop(backend);
            let mut reopened = open(&path, 16777216, 16777216)?;
            if reopened.height() != 1000 || reopened.root_digest().as_bytes() != &expected_root {
                return Err("prepared snapshot reopen mismatch".into());
            }
            reopened.shutdown_cleanly()?;
            println!(
                "{}",
                serde_json::json!({"snapshot":path,"tip":1000,"root":hex::encode(expected_root),"restart_verified":true})
            );
        }
        Command::Replay {
            directory,
            blocks,
            avl_cache_bytes,
            redb_cache_bytes,
            proof_policy,
            persist_jobs,
            flush_interval,
            retained_seconds,
        } => {
            if blocks == 0 || persist_jobs == 0 || retained_seconds == 0 {
                return Err("blocks, persist jobs and retained seconds must be positive".into());
            }
            // Canonical directory and regular files stop symlink aliases bypassing ownership.
            let canonical = directory.canonicalize()?;
            if canonical != directory
                || std::fs::symlink_metadata(&directory)?
                    .file_type()
                    .is_symlink()
            {
                return Err("replay directory must be an absolute canonical path".into());
            }
            let marker = directory.join(".ergo-replay-copy");
            let path = directory.join("state.redb");
            for entry in [&marker, &path] {
                if !std::fs::symlink_metadata(entry)?.file_type().is_file() {
                    return Err("replay marker and database must be regular files".into());
                }
            }
            if std::fs::read_to_string(marker)? != "disposable ergo replay copy\n" {
                return Err("unowned replay database".into());
            }
            let mut store = open(&path, avl_cache_bytes, redb_cache_bytes)?;
            let tip = store.height();
            let start = tip
                .checked_sub(blocks)
                .ok_or("snapshot shorter than replay")?;
            if blocks > store.rollback_window() {
                return Err("requested interval exceeds snapshot rollback window".into());
            }
            let root = store.root_digest();
            let ids = (start + 1..=tip)
                .map(|height| {
                    store
                        .get_header_id_at_height(height)?
                        .ok_or("missing canonical header".into())
                })
                .collect::<Result<Vec<_>>>()?;
            // Headers/bodies/protocol history remain in the copy; no downloads or header PoW timing.
            store.rollback_to(start, None, None)?;
            store.set_ad_proofs_apply_policy(match proof_policy {
                ProofPolicy::Regenerate => ergo_state::store::AdProofsApplyPolicy::Regenerate,
                ProofPolicy::VerifyShipped => ergo_state::store::AdProofsApplyPolicy::VerifyShipped,
            });
            store.set_ibd_mode(true, flush_interval)?;
            store.enable_persist_pipeline(persist_jobs)?;
            let csv_path = std::env::var_os("ERGO_MEM_CSV").ok_or("set ERGO_MEM_CSV")?;
            let mut file = mem_csv::open_or_init(std::path::Path::new(&csv_path))?;
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
            sample(store, "AfterCommit", &mut file)?;
            store.shutdown_cleanly()?;
            let durable_seconds = started.elapsed().as_secs_f64();
            for _ in 0..retained_seconds {
                std::thread::sleep(Duration::from_secs(1));
                sample(store, "Retained", &mut file)?;
            }
            drop(backend);
            let mut reopened = open(&path, avl_cache_bytes, redb_cache_bytes)?;
            if reopened.height() != tip || reopened.root_digest() != root {
                return Err("restart root/height mismatch".into());
            }
            reopened.shutdown_cleanly()?;
            println!(
                "{}",
                serde_json::json!({
                    "start_height":start,"end_height":tip,"blocks":blocks,"transactions":phases.txs,
                    "enqueue_seconds":enqueue_seconds,"committed_seconds":committed_seconds,"durable_seconds":durable_seconds,
                    "committed_blocks_per_second":f64::from(blocks)/committed_seconds,"durable_blocks_per_second":f64::from(blocks)/durable_seconds,
                    "avl_cache_bytes":avl_cache_bytes,"redb_cache_bytes":redb_cache_bytes,"proof_policy":format!("{:?}",proof_policy),
                    "persist_jobs":persist_jobs,"flush_interval":flush_interval,"retained_seconds":retained_seconds,
                    "root":hex::encode(root.as_bytes()),"restart_verified":true,"persist_channel_observed_peak_jobs":queue_peak,
                    "unpersisted_pinned_observed_peak_bytes":pinned_peak,"phases_ms":{
                        "header_load":phases.header_load_ns as f64/1e6,"sections_load":phases.sections_load_ns as f64/1e6,
                        "proof":phases.proof_ns as f64/1e6,"parent_context":phases.parent_ctx_ns as f64/1e6,
                        "validation":phases.validate_ns as f64/1e6,"apply_enqueue":phases.apply_ns as f64/1e6,"instrumented_total":phases.total_ns as f64/1e6
                    }
                })
            );
        }
    }
    Ok(())
}
