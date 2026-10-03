//! Scheduler recovery and RPC bounds with a real durable job journal.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::{Mutex, RwLock};

use super::*;
use crate::node::wallet_bridge::{ChainStateAccessor, TxSubmitter, WriterConfig};

#[derive(Default)]
struct Probe {
    snapshots: AtomicUsize,
    snapshot_hangs: AtomicBool,
    snapshot_fails: AtomicBool,
    entries: Mutex<Vec<ergo_api::mining::PrivateTransactionEntry>>,
    submissions: Mutex<Vec<Vec<u8>>>,
    submit_hangs: AtomicBool,
    cancellations: AtomicUsize,
    cancel_hangs: AtomicBool,
}

#[async_trait]
impl TxSubmitter for Probe {
    async fn submit_transaction(&self, _: Vec<u8>) -> Result<String, ergo_api::types::SubmitError> {
        panic!("maintenance must never broadcast");
    }

    async fn private_transactions(
        &self,
    ) -> Result<Vec<ergo_api::mining::PrivateTransactionEntry>, ergo_api::types::SubmitError> {
        self.snapshots.fetch_add(1, Ordering::SeqCst);
        if self.snapshot_hangs.load(Ordering::SeqCst) {
            return std::future::pending().await;
        }
        if self.snapshot_fails.load(Ordering::SeqCst) {
            return Err(ergo_api::types::SubmitError {
                reason: "private_mining_unavailable".into(),
                detail: None,
            });
        }
        Ok(self.entries.lock().clone())
    }

    async fn submit_private_transaction(
        &self,
        bytes: Vec<u8>,
        _: ergo_api::mining::PrivateTransactionOptions,
    ) -> Result<String, ergo_api::types::SubmitError> {
        self.submissions.lock().push(bytes);
        if self.submit_hangs.load(Ordering::SeqCst) {
            return std::future::pending().await;
        }
        Ok("22".repeat(32))
    }

    async fn cancel_private_transaction(
        &self,
        _: String,
    ) -> Result<(), ergo_api::types::SubmitError> {
        self.cancellations.fetch_add(1, Ordering::SeqCst);
        if self.cancel_hangs.load(Ordering::SeqCst) {
            return std::future::pending().await;
        }
        Ok(())
    }
}

struct Chain(AtomicU32);

impl ChainStateAccessor for Chain {
    fn wallet_scan_height(&self) -> Result<u32, ergo_state::store::StateError> {
        self.tip_height()
    }

    fn tip_height(&self) -> Result<u32, ergo_state::store::StateError> {
        Ok(self.0.load(Ordering::SeqCst))
    }

    fn is_pruned(&self) -> bool {
        false
    }

    fn read_block_at(
        &self,
        _: u32,
    ) -> Result<
        Option<ergo_state::wallet::scan::RescanBlock>,
        ergo_state::wallet::scan::RescanReadError,
    > {
        Ok(None)
    }
}

struct Harness {
    _directory: tempfile::TempDir,
    db: Arc<redb::Database>,
    storage: Arc<RwLock<ergo_wallet::storage::SecretStorage>>,
    state: Arc<RwLock<ergo_wallet::state::WalletState>>,
    store: Arc<dyn ergo_state::wallet::WalletStore>,
    chain: Arc<dyn ChainStateAccessor>,
    height: Arc<Chain>,
    submitter: Arc<dyn TxSubmitter>,
    probe: Arc<Probe>,
    mempool: Arc<dyn ergo_api::MempoolView>,
    rescan: Arc<crate::wallet_boot::RescanControl>,
    config: WriterConfig,
}

impl Harness {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let db = Arc::new(redb::Database::create(directory.path().join("jobs.redb")).unwrap());
        let height = Arc::new(Chain(AtomicU32::new(10)));
        let probe = Arc::new(Probe::default());
        Self {
            storage: Arc::new(RwLock::new(ergo_wallet::storage::SecretStorage::open(
                directory.path().join("wallet"),
            ))),
            state: Arc::new(RwLock::new(ergo_wallet::state::WalletState::empty(false))),
            store: Arc::new(ergo_state::wallet::RedbWalletStore::new(db.clone())),
            db,
            chain: height.clone(),
            height,
            submitter: probe.clone(),
            probe,
            mempool: Arc::new(ergo_api::NoopMempoolView::new()),
            rescan: Arc::new(crate::wallet_boot::RescanControl::default()),
            config: WriterConfig {
                network: ergo_ser::address::NetworkPrefix::Mainnet,
                expose_private_keys: false,
                min_relay_fee_nano_erg: 1_000_000,
                max_tx_size_bytes: 98_304,
                reemission: None,
            },
            _directory: directory,
        }
    }

    fn context(&self) -> WriterContext<'_> {
        WriterContext {
            rescan: &self.rescan,
            rescan_workers: &self.rescan.workers,
            storage: &self.storage,
            state: &self.state,
            db: &self.db,
            store: &self.store,
            chain: &self.chain,
            cfg: &self.config,
            submit_handle: &self.submitter,
            mempool: &self.mempool,
        }
    }

    fn seed(&self, state: WalletJobState, signed: bool) -> u64 {
        let job = create(
            &self.db,
            WalletJobRequest {
                label: "approved renewal".into(),
                task: WalletJobTask::Renew {
                    box_ids: vec!["11".repeat(32)],
                },
                not_before_height: 10,
                expires_at_height: 100,
                max_attempts: 3,
            },
        )
        .unwrap();
        let key = id(&job.id).unwrap();
        let mut record = records(&self.db).unwrap().pop().unwrap().1;
        if signed {
            // At this layer prepared signed bytes are opaque. An uninitialized
            // wallet and absent inputs ensure retry cannot rebuild this record.
            record.signed_hex = Some("abcd".into());
            record.job.tx_id = Some(format!("{key:064x}"));
        }
        transition(&mut record, state, None);
        save(&self.db, key, &record).unwrap();
        key
    }

    fn queue_entry(&self, key: u64, state: &str) {
        self.probe
            .entries
            .lock()
            .push(ergo_api::mining::PrivateTransactionEntry {
                tx_id: format!("{key:064x}"),
                state: state.into(),
                reason: None,
                created_at_ms: 0,
                expires_at_ms: None,
                expires_at_height: Some(100),
                priority: 0,
                label: None,
                input_ids: vec!["11".repeat(32)],
                fee_nano_erg: "0".into(),
                size_bytes: 2,
                validation_cost: 1,
                mined_block_id: None,
                mined_height: None,
            });
    }
}

// ----- happy path -----
#[tokio::test(start_paused = true)]
async fn one_bulk_snapshot_updates_every_retained_job_including_recovered_conflict() {
    let harness = Harness::new();
    for state in [WalletJobState::Queued, WalletJobState::Conflicted] {
        let key = harness.seed(state, true);
        harness.queue_entry(key, "in_candidate");
    }
    tick(&harness.context()).await.unwrap();
    assert_eq!(harness.probe.snapshots.load(Ordering::SeqCst), 1);
    assert!(list(&harness.db)
        .unwrap()
        .items
        .iter()
        .all(|job| job.state == WalletJobState::InCandidate));
    assert!(harness.probe.submissions.lock().is_empty());
}

#[tokio::test(start_paused = true)]
async fn unsigned_locked_job_needs_no_queue_rpc_or_retry_attempt() {
    let harness = Harness::new();
    harness.seed(WalletJobState::Waiting, false);
    harness.probe.snapshot_hangs.store(true, Ordering::SeqCst);
    tick(&harness.context()).await.unwrap();
    assert_eq!(harness.probe.snapshots.load(Ordering::SeqCst), 0);
    let job = list(&harness.db).unwrap().items.remove(0);
    assert_eq!(job.state, WalletJobState::WaitingForWallet);
    assert_eq!(job.attempts, 0);
}

// ----- error paths -----
#[tokio::test(start_paused = true)]
async fn unavailable_snapshot_is_bounded_and_preserves_uncertain_admissions() {
    let harness = Harness::new();
    for _ in 0..8 {
        harness.seed(WalletJobState::Queued, true);
    }
    harness.probe.snapshot_hangs.store(true, Ordering::SeqCst);
    let start = tokio::time::Instant::now();
    tick(&harness.context()).await.unwrap();
    assert_eq!(start.elapsed(), BACKGROUND_RPC_TIMEOUT);
    assert_eq!(harness.probe.snapshots.load(Ordering::SeqCst), 1);
    assert!(harness.probe.submissions.lock().is_empty());
    for (_, record) in records(&harness.db).unwrap() {
        assert_eq!(record.job.state, WalletJobState::Queued);
        assert_eq!(record.job.attempts, 0);
        assert_eq!(record.signed_hex.as_deref(), Some("abcd"));
    }
    assert!(!harness.rescan.stopping());
}

#[tokio::test(start_paused = true)]
async fn uncertain_submission_retries_same_bytes_only_after_successful_absence() {
    let harness = Harness::new();
    harness.seed(WalletJobState::Prepared, true);
    harness.probe.submit_hangs.store(true, Ordering::SeqCst);
    let start = tokio::time::Instant::now();
    tick(&harness.context()).await.unwrap();
    assert_eq!(start.elapsed(), BACKGROUND_RPC_TIMEOUT);
    let record = records(&harness.db).unwrap().remove(0).1;
    assert_eq!(record.job.state, WalletJobState::Prepared);
    assert_eq!(record.job.attempts, 1);
    harness.height.0.store(11, Ordering::SeqCst);
    harness.probe.snapshot_fails.store(true, Ordering::SeqCst);
    tick(&harness.context()).await.unwrap();
    assert_eq!(harness.probe.submissions.lock().len(), 1);
    assert_eq!(records(&harness.db).unwrap().remove(0).1.job.attempts, 1);
    harness.height.0.store(12, Ordering::SeqCst);
    harness.probe.snapshot_fails.store(false, Ordering::SeqCst);
    harness.probe.submit_hangs.store(false, Ordering::SeqCst);
    tick(&harness.context()).await.unwrap();
    assert_eq!(*harness.probe.submissions.lock(), vec![vec![0xab, 0xcd]; 2]);
    let record = records(&harness.db).unwrap().remove(0).1;
    assert_eq!(record.job.state, WalletJobState::Queued);
    assert_eq!(record.job.attempts, 2);
    assert_eq!(record.signed_hex.as_deref(), Some("abcd"));
}

#[tokio::test(start_paused = true)]
async fn expiring_many_jobs_attempts_only_one_bounded_cancellation_per_wake() {
    let harness = Harness::new();
    for _ in 0..8 {
        let key = harness.seed(WalletJobState::Queued, true);
        harness.queue_entry(key, "queued");
    }
    harness.height.0.store(100, Ordering::SeqCst);
    harness.probe.cancel_hangs.store(true, Ordering::SeqCst);
    let start = tokio::time::Instant::now();
    tick(&harness.context()).await.unwrap();
    assert_eq!(start.elapsed(), BACKGROUND_RPC_TIMEOUT);
    assert_eq!(harness.probe.cancellations.load(Ordering::SeqCst), 1);
    assert_eq!(harness.probe.snapshots.load(Ordering::SeqCst), 1);
    assert!(list(&harness.db)
        .unwrap()
        .items
        .iter()
        .all(|job| job.state == WalletJobState::Queued));
}

#[tokio::test(start_paused = true)]
async fn manual_cancel_timeout_keeps_the_durable_job_pending() {
    let harness = Harness::new();
    let key = harness.seed(WalletJobState::Queued, true);
    harness.queue_entry(key, "queued");
    harness.probe.cancel_hangs.store(true, Ordering::SeqCst);
    let start = tokio::time::Instant::now();
    assert!(cancel(&harness.context(), &key.to_string()).await.is_err());
    assert_eq!(start.elapsed(), BACKGROUND_RPC_TIMEOUT);
    assert_eq!(harness.probe.cancellations.load(Ordering::SeqCst), 1);
    let record = records(&harness.db).unwrap().remove(0).1;
    assert_eq!(record.job.state, WalletJobState::Queued);
    assert_eq!(record.signed_hex.as_deref(), Some("abcd"));
}
