//! Repeatable mempool/API microbenchmark; see docs/perf/mempool-publication-2026-10-03.md.
//!
//! CSV goes to stdout. Setup and summary checks are untimed; warm-up is discarded.
//! Admission deliberately supplies a synthetic constant-cost validator: results
//! describe pool/observer bookkeeping, never consensus deserialization or scripts.

use std::collections::HashMap;
use std::hint::black_box;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

use ergo_api::types::{
    ApiInfo, ApiMempoolTransaction, ApiMempoolTransactions, ApiTxSource, ApiWeightFunction,
};
use ergo_api::v1::realtime::{BusSubscription, RealtimeHandle};
use ergo_mempool::admission::{
    PeekedStructure, PeekedTx, TipContext, Validated, ValidationErr, Validator,
};
use ergo_mempool::types::{TipPointer, TxSource};
use ergo_mempool::weight::ByCost;
use ergo_mempool::{AdmissionOutcome, Mempool, MempoolConfig, MempoolObserver};
use ergo_node::realtime_mempool_bridge::RealtimeMempoolObserver;
use ergo_node::snapshot::{SnapshotParts, SnapshotPublisher};
use ergo_primitives::cost::JitCost;
use ergo_primitives::digest::Digest32;
use ergo_ser::ergo_box::ErgoBox;
use ergo_validation::{ProtocolParams, TransactionContext, TxValidationCtx, UtxoView};

const SAMPLES: usize = 5;
const ADMISSIONS: usize = 256;
const PUBLICATIONS: usize = 16_384;
const SNAPSHOTS: usize = 128;
const JSON_RESPONSES: usize = 32;
const FEE: u64 = 1_000_000;

type FullTransactions = Arc<Vec<(Digest32, Arc<[u8]>)>>;

struct EmptyUtxo;
impl UtxoView for EmptyUtxo {
    fn get_box(&self, _: &Digest32) -> Option<ErgoBox> {
        None
    }
}

fn id(bytes: &[u8], kind: u8) -> Digest32 {
    let mut id = [0; 32];
    id[..8].copy_from_slice(&bytes[..8]);
    id[31] = kind;
    Digest32::from_bytes(id)
}

fn tx_bytes(index: usize, size: usize) -> Vec<u8> {
    let mut bytes = vec![0; size];
    bytes[..8].copy_from_slice(&(index as u64).to_le_bytes());
    bytes
}

struct SyntheticValidator;
impl Validator for SyntheticValidator {
    fn peek_fee(&self, bytes: &[u8]) -> Result<PeekedTx, ValidationErr> {
        Ok(PeekedTx {
            tx_id: id(bytes, 1),
            fee: FEE,
            contains_storage_rent_claim: false,
        })
    }

    fn peek_structure(&self, bytes: &[u8]) -> Result<PeekedStructure, ValidationErr> {
        Ok(PeekedStructure {
            tx_id: id(bytes, 1),
            fee: FEE,
            input_box_ids: vec![id(bytes, 2)],
            output_box_ids: vec![id(bytes, 3)],
            data_input_box_ids: vec![],
        })
    }

    fn validate(
        &self,
        bytes: &[u8],
        _: &dyn UtxoView,
        _: &dyn UtxoView,
        cx: &mut TxValidationCtx<'_>,
    ) -> Result<Validated, ValidationErr> {
        cx.cost
            .add(JitCost::from_jit(10))
            .map_err(|_| ValidationErr::CostExceeded)?;
        Ok(Validated {
            tx_id: id(bytes, 1),
            input_box_ids: vec![id(bytes, 2)],
            output_box_ids: vec![id(bytes, 3)],
            outputs: vec![],
            fee: FEE,
            size_bytes: bytes.len() as u32,
            consumed_cost: 1,
        })
    }
}

fn context<'a>(
    tx_context: &'a TransactionContext,
    params: &'a ProtocolParams,
    utxo: &'a EmptyUtxo,
) -> TipContext<'a> {
    TipContext {
        tip: TipPointer {
            height: 1000,
            header_id: Digest32::ZERO,
        },
        best_header_height: 1000,
        best_full_block_height: 1000,
        utxo,
        tx_context,
        params,
        last_headers: &[],
        reemission: None,
    }
}

fn subscribers(handle: &RealtimeHandle, count: usize) -> Vec<BusSubscription> {
    (0..count)
        .map(|_| {
            let sub = handle.bus.subscribe();
            sub.filter.write().unwrap().insert("mempool".into());
            sub
        })
        .collect()
}

fn drain(subs: &mut [BusSubscription], expected: usize) {
    for sub in subs {
        let mut received = 0;
        while let Ok(event) = sub.rx.try_recv() {
            black_box(event);
            received += 1;
        }
        assert_eq!(received, expected);
        assert!(!sub.lagged.load(Ordering::Relaxed));
    }
}

fn row(name: &str, pool: usize, size: usize, subs: usize, ops: usize, sample: usize, ns: u128) {
    if sample != 0 {
        println!(
            "{name},{pool},{size},{subs},{ops},{sample},{ns},{:.3}",
            ns as f64 / ops as f64
        );
    }
}

fn bench_admission(initial_pool: usize, size: usize, subscriber_count: usize) {
    let tx_context = TransactionContext {
        height: 1000,
        miner_pubkey: [0; 33],
        pre_header_timestamp: 0,
        activated_script_version: 2,
        pre_header_version: 3,
        pre_header_parent_id: [0; 32],
        pre_header_n_bits: 0,
        pre_header_votes: [0; 3],
    };
    let params = ProtocolParams::mainnet_default();
    let utxo = EmptyUtxo;
    let ctx = context(&tx_context, &params, &utxo);
    let validator = SyntheticValidator;
    let payloads: Vec<_> = (0..initial_pool + ADMISSIONS)
        .map(|n| tx_bytes(n, size))
        .collect();
    for sample in 0..=SAMPLES {
        let mut pool = Mempool::new(
            MempoolConfig {
                max_pool_size: initial_pool + ADMISSIONS + 1,
                ..MempoolConfig::default()
            },
            Box::new(ByCost),
        );
        for bytes in &payloads[..initial_pool] {
            assert!(matches!(
                pool.process(bytes, TxSource::Api, Instant::now(), &ctx, &validator)
                    .0,
                AdmissionOutcome::Admitted { .. }
            ));
        }
        let handle = RealtimeHandle::blocks_and_mempool();
        let mut subs = subscribers(&handle, subscriber_count);
        // Install even with zero subscribers so the zero-fanout baseline still
        // measures the production observer and bounded resume-window work.
        pool.set_observer(Some(Arc::new(RealtimeMempoolObserver::new(
            handle.bus.clone(),
        ))));
        let now = Instant::now();
        let started = Instant::now();
        for bytes in &payloads[initial_pool..] {
            let result = pool.process(bytes, TxSource::Api, now, &ctx, &validator);
            assert!(matches!(result.0, AdmissionOutcome::Admitted { .. }));
            black_box(result);
        }
        let ns = started.elapsed().as_nanos();
        assert_eq!(pool.size(), initial_pool + ADMISSIONS);
        assert_eq!(pool.total_bytes(), (initial_pool + ADMISSIONS) * size);
        assert_eq!(handle.bus.latest_seq(), ADMISSIONS as u64);
        drain(&mut subs, ADMISSIONS);
        row(
            "admission",
            initial_pool,
            size,
            subscriber_count,
            ADMISSIONS,
            sample,
            ns,
        );
    }
}

fn bench_realtime(subscriber_count: usize, stalled: bool) {
    for sample in 0..=SAMPLES {
        let handle = RealtimeHandle::blocks_and_mempool();
        let mut subs = subscribers(&handle, subscriber_count);
        let observer = RealtimeMempoolObserver::new(handle.bus.clone());
        let tx_id = Digest32::from_bytes([1; 32]);
        let mut ns = 0;
        // Draining is untimed; every measured publish still enters the real
        // bounded fanout queues. Stalled subscribers never consume their queue.
        for _ in 0..PUBLICATIONS / 128 {
            let started = Instant::now();
            for _ in 0..128 {
                observer.on_admitted(black_box(tx_id), FEE, 256);
            }
            ns += started.elapsed().as_nanos();
            if !stalled {
                drain(&mut subs, 128);
            }
        }
        assert_eq!(handle.bus.latest_seq(), PUBLICATIONS as u64);
        if stalled {
            for sub in &subs {
                assert!(sub.lagged.load(Ordering::Relaxed));
                assert_eq!(sub.rx.len(), sub.rx.max_capacity());
            }
        }
        row(
            if stalled {
                "realtime_stalled"
            } else {
                "realtime_drained"
            },
            0,
            256,
            subscriber_count,
            PUBLICATIONS,
            sample,
            ns,
        );
    }
}

fn snapshot_fixture(pool_size: usize, size: usize) -> (ApiMempoolTransactions, FullTransactions) {
    let bytes: Vec<_> = (0..pool_size).map(|n| tx_bytes(n, size)).collect();
    let transactions = bytes
        .iter()
        .map(|bytes| ApiMempoolTransaction {
            tx_id: hex::encode(id(bytes, 1).as_bytes()),
            fee_nano_erg: FEE,
            fee_per_byte_nano_erg: FEE / size as u64,
            size_bytes: size as u32,
            validation_cost_units: 1,
            priority_weight: FEE * 1024,
            source: ApiTxSource::Api,
            input_count: 1,
            output_count: 1,
            parents_in_pool: 0,
            first_seen_unix_ms: 0,
            first_seen_age_ms: 0,
            last_checked_age_ms: 0,
        })
        .collect();
    let full = Arc::new(
        bytes
            .into_iter()
            .map(|bytes| (id(&bytes, 1), Arc::from(bytes)))
            .collect(),
    );
    (
        ApiMempoolTransactions {
            transactions,
            weight_function: ApiWeightFunction::Cost,
        },
        full,
    )
}

fn bench_snapshot(pool_size: usize, size: usize) {
    let (transactions, full_txs) = snapshot_fixture(pool_size, size);
    let mut publisher = SnapshotPublisher::new(
        ApiInfo {
            agent_name: "benchmark".into(),
            node_name: "benchmark".into(),
            network: "mainnet".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            started_at_unix_ms: 0,
            uptime_seconds: 0,
            target_block_interval_ms: 120_000,
        },
        Instant::now(),
        ApiWeightFunction::Cost,
    );
    let handle = publisher.handle();
    for sample in 0..=SAMPLES {
        let started = Instant::now();
        for _ in 0..SNAPSHOTS {
            publisher.publish(snapshot_parts(transactions.clone(), full_txs.clone(), size));
            black_box(handle.load_full());
        }
        let ns = started.elapsed().as_nanos();
        let snapshot = handle.load_full();
        assert_eq!(snapshot.mempool_transactions.transactions.len(), pool_size);
        assert!(Arc::ptr_eq(&snapshot.pool_full_txs, &full_txs));
        row(
            "snapshot_publish",
            pool_size,
            size,
            0,
            SNAPSHOTS,
            sample,
            ns,
        );
        let started = Instant::now();
        for _ in 0..JSON_RESPONSES {
            let snapshot = handle.load_full();
            black_box(serde_json::to_vec(&snapshot.mempool_transactions).unwrap());
        }
        let ns = started.elapsed().as_nanos();
        row(
            "api_mempool_json",
            pool_size,
            size,
            0,
            JSON_RESPONSES,
            sample,
            ns,
        );
    }
}

fn main() {
    println!(
        "benchmark,pool_size,tx_bytes,subscribers,operations,sample,elapsed_ns,ns_per_operation"
    );
    // Cargo bench passes --bench to custom harnesses. Keep test/direct
    // invocation a small behavioral smoke run; only bench runs the full matrix.
    if !std::env::args().any(|arg| arg == "--bench") {
        bench_admission(0, 256, 1);
        bench_snapshot(0, 256);
        bench_realtime(1, false);
        bench_realtime(1, true);
        return;
    }
    for pool in [0, 1000, 5000] {
        for size in [256, 4096] {
            for subs in [0, 1, 32] {
                bench_admission(pool, size, subs);
            }
            bench_snapshot(pool, size);
        }
    }
    for subs in [0, 1, 32] {
        bench_realtime(subs, false);
        bench_realtime(subs, true);
    }
}

fn snapshot_parts(
    transactions: ApiMempoolTransactions,
    full_txs: FullTransactions,
    size: usize,
) -> SnapshotParts<'static> {
    SnapshotParts {
        now_unix_ms: 0,
        sync_gauges: Default::default(),
        snapshot_built_at: Instant::now(),
        best_header_height: 0,
        best_header_id: [0; 32],
        best_header_parent_id: [2u8; 32],
        best_header_timestamp_ms: 1_700_000_000_000,
        best_full_block_height: 0,
        best_full_block_id: [0; 32],
        best_full_block_parent_id: [4u8; 32],
        best_full_block_timestamp_ms: 1_700_000_000_000,
        // Captured Scala mainnet nBits (test-vectors scala_chainslice);
        // decodes to difficulty "263500538576896" — an external oracle.
        best_header_n_bits: Some(0),
        best_full_block_n_bits: Some(0),
        state_digest: [5u8; 33],
        headers_chain_synced: false,
        download_window: 384,
        pending_blocks: 0,
        recovery_done: false,
        peer_count: 0,
        mempool_size: full_txs.len() as u32,
        mempool_total_bytes: (full_txs.len() * size) as u64,
        mempool_capacity_count: 1000,
        mempool_capacity_bytes: 1024,
        mempool_revalidation_pending: 0,
        mempool_transactions: transactions,
        peers: &[],
        best_header_score: Vec::new(),
        best_full_block_score: Vec::new(),
        genesis_block_id: [0u8; 32],
        last_seen_message_unix_ms: 0,
        last_mempool_update_unix_ms: 0,
        active_params: ergo_validation::scala_launch(),
        pool_outputs: Arc::new(HashMap::new()),
        pool_inputs: Arc::new(HashMap::new()),
        pool_full_txs: full_txs,
        peer_sync: Arc::new(HashMap::new()),
        delivery_counts: ergo_node::snapshot::DeliveryCounters::default(),
        banned_ips: Arc::new(Vec::new()),
        bootstrap: None,
        recent_blocks: Arc::new(Vec::new()),
        events: Arc::new(ergo_api::types::ApiNodeEvents::default()),
        reorgs: Arc::new(ergo_api::types::ApiReorgHistory::default()),
        max_peer_height: 0,
        mining_enabled: false,
        snapshot_manifests: Vec::new(),
        last_block_apply_error: None,
        block_apply_errors_total: 0,
        storage_errors_state_total: 0,
        storage_errors_indexer_total: 0,
        storage_errors_peers_total: 0,
        last_storage_error: None,
        sync_wedged: None,
        shadow: None,
        mempool_tx_requested_total: 0,
        mempool_peer_tx_admitted_total: 0,
        mempool_peer_tx_rejected_total: 0,
    }
}
