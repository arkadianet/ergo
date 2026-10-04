//! Scheduler recovery and RPC bounds with a real durable job journal.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::{Mutex, RwLock};

use super::*;
use crate::node::wallet_bridge::{ChainStateAccessor, TxSubmitter, WriterConfig};

#[derive(Default)]
struct Probe {
    /// Behaves like a node without `[mining]`: every private call fails.
    mining_disabled: AtomicBool,
    snapshots: AtomicUsize,
    snapshot_hangs: AtomicBool,
    snapshot_fails: AtomicBool,
    entries: Mutex<Vec<ergo_api::mining::PrivateTransactionEntry>>,
    submissions: Mutex<Vec<Vec<u8>>>,
    submit_hangs: AtomicBool,
    submit_refusal: Mutex<Option<&'static str>>,
    cancellations: AtomicUsize,
    cancel_hangs: AtomicBool,
}

#[async_trait]
impl TxSubmitter for Probe {
    async fn submit_transaction(&self, _: Vec<u8>) -> Result<String, ergo_api::types::SubmitError> {
        panic!("maintenance must never broadcast");
    }

    fn private_mining_configured(&self) -> bool {
        !self.mining_disabled.load(Ordering::SeqCst)
    }

    async fn private_transactions(
        &self,
    ) -> Result<Vec<ergo_api::mining::PrivateTransactionEntry>, ergo_api::types::SubmitError> {
        self.snapshots.fetch_add(1, Ordering::SeqCst);
        if self.snapshot_hangs.load(Ordering::SeqCst) {
            return std::future::pending().await;
        }
        if self.snapshot_fails.load(Ordering::SeqCst) || self.mining_disabled.load(Ordering::SeqCst)
        {
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
        if self.mining_disabled.load(Ordering::SeqCst) {
            return Err(ergo_api::types::SubmitError {
                reason: "private_mining_unavailable".into(),
                detail: None,
            });
        }
        self.submissions.lock().push(bytes);
        if self.submit_hangs.load(Ordering::SeqCst) {
            return std::future::pending().await;
        }
        if let Some(reason) = *self.submit_refusal.lock() {
            return Err(ergo_api::types::SubmitError {
                reason: reason.into(),
                detail: Some("private admission waits for chain synchronization".into()),
            });
        }
        Ok("22".repeat(32))
    }

    async fn cancel_private_transaction(
        &self,
        _: String,
    ) -> Result<(), ergo_api::types::SubmitError> {
        self.cancellations.fetch_add(1, Ordering::SeqCst);
        if self.mining_disabled.load(Ordering::SeqCst) {
            return Err(ergo_api::types::SubmitError {
                reason: "private_mining_unavailable".into(),
                detail: None,
            });
        }
        if self.cancel_hangs.load(Ordering::SeqCst) {
            return std::future::pending().await;
        }
        Ok(())
    }
}

/// Applied tip height; `UNREADABLE_TIP` makes tip reads fail.
struct Chain(AtomicU32);

const UNREADABLE_TIP: u32 = u32::MAX;

impl ChainStateAccessor for Chain {
    fn wallet_scan_height(&self) -> Result<u32, ergo_state::store::StateError> {
        self.tip_height()
    }

    fn tip_height(&self) -> Result<u32, ergo_state::store::StateError> {
        match self.0.load(Ordering::SeqCst) {
            UNREADABLE_TIP => Err(ergo_state::store::StateError::InternalInvariant {
                what: "test tip read failure",
            }),
            height => Ok(height),
        }
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
        self.seed_until(state, signed, 100)
    }

    fn seed_until(&self, state: WalletJobState, signed: bool, expires_at_height: u32) -> u64 {
        let job = create(
            &self.db,
            WalletJobRequest {
                label: "approved renewal".into(),
                task: WalletJobTask::Renew {
                    box_ids: vec!["11".repeat(32)],
                },
                not_before_height: 1,
                expires_at_height,
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
async fn retired_jobs_drop_their_unpublished_signed_bytes() {
    let harness = Harness::new();
    let cancelled = harness.seed(WalletJobState::Prepared, true);
    let expired = harness.seed_until(WalletJobState::Prepared, true, 10);
    let exhausted = harness.seed(WalletJobState::Prepared, true);
    let mut record = records(&harness.db).unwrap().remove(2).1;
    record.job.attempts = record.job.request.max_attempts;
    save(&harness.db, exhausted, &record).unwrap();
    let mined = harness.seed(WalletJobState::Queued, true);
    harness.queue_entry(mined, "mined");
    cancel(&harness.context(), &cancelled.to_string())
        .await
        .unwrap();
    tick(&harness.context()).await.unwrap();
    let jobs: BTreeMap<_, _> = records(&harness.db).unwrap().into_iter().collect();
    for (key, state) in [
        (cancelled, WalletJobState::Cancelled),
        (expired, WalletJobState::Expired),
        (exhausted, WalletJobState::Failed),
    ] {
        assert_eq!(jobs[&key].job.state, state);
        assert_eq!(jobs[&key].signed_hex, None, "{state:?}");
        assert_eq!(jobs[&key].job.tx_id, Some(format!("{key:064x}")));
    }
    // Mined work still follows queue reorgs with its exact bytes.
    assert_eq!(jobs[&mined].job.state, WalletJobState::Mined);
    assert_eq!(jobs[&mined].signed_hex.as_deref(), Some("abcd"));
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

#[tokio::test(start_paused = true)]
async fn disabled_private_mining_waits_then_retires_jobs_locally() {
    let harness = Harness::new();
    harness.probe.mining_disabled.store(true, Ordering::SeqCst);
    let queued = harness.seed(WalletJobState::Queued, true);
    let prepared = harness.seed(WalletJobState::Prepared, true);
    let unsigned = harness.seed(WalletJobState::Waiting, false);
    tick(&harness.context()).await.unwrap();
    assert_eq!(harness.probe.snapshots.load(Ordering::SeqCst), 0);
    for (_, record) in records(&harness.db).unwrap() {
        assert_eq!(record.job.attempts, 0);
        assert_eq!(
            record.job.detail.as_deref(),
            Some("private mining is not enabled on this node")
        );
    }
    // Nothing can be queued on such a node, so cancellation needs no RPC.
    let cancelled = cancel(&harness.context(), &queued.to_string())
        .await
        .unwrap();
    assert_eq!(cancelled.state, WalletJobState::Cancelled);
    assert_eq!(harness.probe.cancellations.load(Ordering::SeqCst), 0);
    harness.height.0.store(100, Ordering::SeqCst);
    tick(&harness.context()).await.unwrap();
    let states: BTreeMap<_, _> = records(&harness.db)
        .unwrap()
        .into_iter()
        .map(|(key, record)| (key, record.job.state))
        .collect();
    assert_eq!(states[&queued], WalletJobState::Cancelled);
    assert_eq!(states[&prepared], WalletJobState::Expired);
    assert_eq!(states[&unsigned], WalletJobState::Expired);
    assert!(reserved_inputs(&harness.db).unwrap().is_empty());
    assert!(harness.probe.submissions.lock().is_empty());
}

#[tokio::test(start_paused = true)]
async fn deadline_without_queue_knowledge_reports_a_wallet_confirmed_transaction() {
    let harness = Harness::new();
    let confirmed = harness.seed_until(WalletJobState::Queued, true, 10);
    let unconfirmed = harness.seed_until(WalletJobState::Queued, true, 10);
    let tx_id: [u8; 32] = hex::decode(format!("{confirmed:064x}"))
        .unwrap()
        .try_into()
        .unwrap();
    let write = harness.db.begin_write().unwrap();
    write
        .open_table(ergo_state::wallet::tables::WALLET_TXS)
        .unwrap()
        .insert(
            ergo_state::wallet::tables::wallet_tx_key(10, &tx_id),
            bincode::serialize(&ergo_state::wallet::types::WalletTransaction {
                tx_id,
                block_height: 10,
                block_id: [0x33; 32],
                wallet_outputs: Vec::new(),
                wallet_inputs: vec![[0x11; 32]],
            })
            .unwrap(),
        )
        .unwrap();
    write.commit().unwrap();
    harness.probe.snapshot_fails.store(true, Ordering::SeqCst);
    tick(&harness.context()).await.unwrap();
    let jobs: BTreeMap<_, _> = records(&harness.db).unwrap().into_iter().collect();
    assert_eq!(jobs[&confirmed].job.state, WalletJobState::Mined);
    assert_eq!(
        jobs[&confirmed].job.detail.as_deref(),
        Some(MINED_IN_WALLET)
    );
    assert_eq!(jobs[&unconfirmed].job.state, WalletJobState::Expired);
}

// ----- error paths -----
#[tokio::test(start_paused = true)]
async fn unavailable_snapshot_is_bounded_and_preserves_uncertain_admissions() {
    let harness = Harness::new();
    for _ in 0..8 {
        harness.seed(WalletJobState::Queued, true);
    }
    // Neither unsigned work nor a passed deadline depends on the queue.
    let unsigned = harness.seed(WalletJobState::Waiting, false);
    let late = harness.seed_until(WalletJobState::Queued, true, 10);
    harness.probe.snapshot_hangs.store(true, Ordering::SeqCst);
    let start = tokio::time::Instant::now();
    tick(&harness.context()).await.unwrap();
    assert_eq!(start.elapsed(), BACKGROUND_RPC_TIMEOUT);
    assert_eq!(harness.probe.snapshots.load(Ordering::SeqCst), 1);
    assert!(harness.probe.submissions.lock().is_empty());
    for (key, record) in records(&harness.db).unwrap() {
        if key == unsigned {
            assert_eq!(record.job.state, WalletJobState::WaitingForWallet);
        } else if key == late {
            assert_eq!(record.job.state, WalletJobState::Expired);
        } else {
            assert_eq!(record.job.state, WalletJobState::Queued);
            assert_eq!(record.signed_hex.as_deref(), Some("abcd"));
        }
        assert_eq!(record.job.attempts, 0);
    }
    assert!(!harness.rescan.stopping());
}

#[tokio::test(start_paused = true)]
async fn unreadable_chain_tip_skips_the_wake_without_stopping_the_writer() {
    let harness = Harness::new();
    harness.seed(WalletJobState::Waiting, false);
    harness.height.0.store(UNREADABLE_TIP, Ordering::SeqCst);
    tick(&harness.context()).await.unwrap();
    let job = list(&harness.db).unwrap().items.remove(0);
    assert_eq!(job.state, WalletJobState::Waiting);
    assert_eq!(job.attempts, 0);
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
    // A queue that never answered has not judged the transaction.
    assert_eq!(record.job.attempts, 0);
    harness.height.0.store(11, Ordering::SeqCst);
    harness.probe.snapshot_fails.store(true, Ordering::SeqCst);
    tick(&harness.context()).await.unwrap();
    assert_eq!(harness.probe.submissions.lock().len(), 1);
    assert_eq!(records(&harness.db).unwrap().remove(0).1.job.attempts, 0);
    harness.height.0.store(12, Ordering::SeqCst);
    harness.probe.snapshot_fails.store(false, Ordering::SeqCst);
    harness.probe.submit_hangs.store(false, Ordering::SeqCst);
    tick(&harness.context()).await.unwrap();
    assert_eq!(*harness.probe.submissions.lock(), vec![vec![0xab, 0xcd]; 2]);
    let record = records(&harness.db).unwrap().remove(0).1;
    assert_eq!(record.job.state, WalletJobState::Queued);
    assert_eq!(record.job.attempts, 1);
    assert_eq!(record.signed_hex.as_deref(), Some("abcd"));
}

#[tokio::test(start_paused = true)]
async fn queue_refusals_while_catching_up_spend_no_attempts() {
    let harness = Harness::new();
    harness.seed(WalletJobState::Prepared, true);
    *harness.probe.submit_refusal.lock() = Some("private_mining_unavailable");
    for height in 10..20 {
        harness.height.0.store(height, Ordering::SeqCst);
        tick(&harness.context()).await.unwrap();
    }
    let record = records(&harness.db).unwrap().remove(0).1;
    assert_eq!(harness.probe.submissions.lock().len(), 10);
    assert_eq!(record.job.state, WalletJobState::Prepared);
    assert_eq!(record.job.attempts, 0);
    // A verdict on the transaction itself counts.
    *harness.probe.submit_refusal.lock() = Some("private_transaction_rejected");
    harness.height.0.store(20, Ordering::SeqCst);
    tick(&harness.context()).await.unwrap();
    assert_eq!(records(&harness.db).unwrap().remove(0).1.job.attempts, 1);
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
