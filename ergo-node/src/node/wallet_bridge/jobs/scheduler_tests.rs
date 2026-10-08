//! Scheduler recovery and RPC bounds with a real durable job journal.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::{Mutex, RwLock};

use super::super::BACKGROUND_RPC_TIMEOUT;
use super::*;

#[derive(Default)]
struct Probe {
    /// Behaves like a node without `[mining]`: every private call fails.
    mining_disabled: AtomicBool,
    /// With mining disabled, a queue file loaded at boot still answers
    /// listing and cancellation.
    stored_queue: AtomicBool,
    snapshots: AtomicUsize,
    snapshot_hangs: AtomicBool,
    snapshot_fails: AtomicBool,
    entries: Mutex<Vec<ergo_wallet_protocol::mining::PrivateTransactionEntry>>,
    submissions: Mutex<Vec<Vec<u8>>>,
    submit_hangs: AtomicBool,
    submit_refusal: Mutex<Option<&'static str>>,
    cancellations: AtomicUsize,
    cancel_hangs: AtomicBool,
}

#[async_trait]
impl TxSubmitter for Probe {
    async fn submit_transaction(&self, _: Vec<u8>) -> Result<String, TxSubmitError> {
        panic!("maintenance must never broadcast");
    }

    fn private_mining_configured(&self) -> bool {
        !self.mining_disabled.load(Ordering::SeqCst)
    }

    async fn private_transactions(
        &self,
    ) -> Result<Vec<ergo_wallet_protocol::mining::PrivateTransactionEntry>, TxSubmitError> {
        self.snapshots.fetch_add(1, Ordering::SeqCst);
        if self.snapshot_hangs.load(Ordering::SeqCst) {
            return std::future::pending().await;
        }
        if self.snapshot_fails.load(Ordering::SeqCst) || self.queue_absent() {
            return Err(TxSubmitError {
                reason: "private_mining_unavailable".into(),
                detail: None,
            });
        }
        Ok(self.entries.lock().clone())
    }

    async fn submit_private_transaction(
        &self,
        bytes: Vec<u8>,
        _: ergo_wallet_protocol::mining::PrivateTransactionOptions,
    ) -> Result<String, TxSubmitError> {
        if self.mining_disabled.load(Ordering::SeqCst) {
            return Err(TxSubmitError {
                reason: "private_mining_unavailable".into(),
                detail: None,
            });
        }
        self.submissions.lock().push(bytes);
        if self.submit_hangs.load(Ordering::SeqCst) {
            return std::future::pending().await;
        }
        if let Some(reason) = *self.submit_refusal.lock() {
            return Err(TxSubmitError {
                reason: reason.into(),
                detail: Some("private admission waits for chain synchronization".into()),
            });
        }
        Ok("22".repeat(32))
    }

    async fn cancel_private_transaction(&self, _: String) -> Result<(), TxSubmitError> {
        self.cancellations.fetch_add(1, Ordering::SeqCst);
        if self.queue_absent() {
            return Err(TxSubmitError {
                reason: "private_mining_unavailable".into(),
                detail: None,
            });
        }
        if self.cancel_hangs.load(Ordering::SeqCst) {
            return std::future::pending().await;
        }
        Ok(())
    }
    async fn job_private_transactions(
        &self,
    ) -> Result<Vec<ergo_wallet_protocol::mining::PrivateTransactionEntry>, TxSubmitError> {
        super::super::bounded_private_rpc(self.private_transactions()).await
    }
    async fn job_private_transaction_status(
        &self,
        tx_id: String,
    ) -> Result<Option<ergo_wallet_protocol::mining::PrivateTransactionEntry>, TxSubmitError> {
        super::super::bounded_private_rpc(self.private_transaction_status(tx_id)).await
    }
    async fn job_submit_private_transaction(
        &self,
        bytes: Vec<u8>,
        options: ergo_wallet_protocol::mining::PrivateTransactionOptions,
    ) -> Result<String, TxSubmitError> {
        super::super::bounded_private_rpc(self.submit_private_transaction(bytes, options)).await
    }
    async fn job_cancel_private_transaction(&self, tx_id: String) -> Result<(), TxSubmitError> {
        super::super::bounded_private_rpc(self.cancel_private_transaction(tx_id)).await
    }
}

impl Probe {
    fn queue_absent(&self) -> bool {
        self.mining_disabled.load(Ordering::SeqCst) && !self.stored_queue.load(Ordering::SeqCst)
    }
}

/// Applied tip height, and how many blocks the wallet scan trails it;
/// `UNREADABLE_TIP` makes tip reads fail.
struct Chain(AtomicU32, AtomicU32);

const UNREADABLE_TIP: u32 = u32::MAX;

impl WalletChainAccess for Chain {
    fn wallet_scan_height(&self) -> Result<u32, ChainAccessError> {
        Ok(self.tip_height()? - self.1.load(Ordering::SeqCst))
    }

    fn tip_height(&self) -> Result<u32, ChainAccessError> {
        match self.0.load(Ordering::SeqCst) {
            UNREADABLE_TIP => Err(ChainAccessError::State("test tip read failure".into())),
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
    state: Arc<RwLock<ergo_wallet_service::state::WalletState>>,
    store: Arc<dyn ergo_state::wallet::WalletStore>,
    chain: Arc<dyn WalletChainAccess>,
    height: Arc<Chain>,
    submitter: Arc<dyn TxSubmitter>,
    probe: Arc<Probe>,
    mempool: Arc<dyn ergo_wallet_service::engine::MempoolOverlay>,
    rescan: Arc<RescanCoordinator>,
    config: WalletEngineConfig,
}

impl Harness {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let db = Arc::new(redb::Database::create(directory.path().join("jobs.redb")).unwrap());
        let height = Arc::new(Chain(AtomicU32::new(10), AtomicU32::new(0)));
        let probe = Arc::new(Probe::default());
        Self {
            storage: Arc::new(RwLock::new(ergo_wallet::storage::SecretStorage::open(
                directory.path().join("wallet"),
            ))),
            state: Arc::new(RwLock::new(ergo_wallet_service::state::WalletState::empty(
                false,
            ))),
            store: Arc::new(ergo_state::wallet::RedbWalletStore::new(db.clone())),
            db,
            chain: height.clone(),
            height,
            submitter: probe.clone(),
            probe,
            mempool: Arc::new(ergo_wallet_service::engine::NoopMempoolOverlay::new()),
            rescan: Arc::new(RescanCoordinator::default()),
            config: WalletEngineConfig {
                network: ergo_ser::address::NetworkPrefix::Mainnet,
                expose_private_keys: false,
                min_relay_fee_nano_erg: 1_000_000,
                max_tx_size_bytes: 98_304,
                reemission: None,
            },
            _directory: directory,
        }
    }

    fn context(&self) -> WalletEngine {
        WalletEngine::new(WalletEngineParts {
            rescan: self.rescan.clone(),
            storage: self.storage.clone(),
            state: self.state.clone(),
            store: self.store.clone(),
            chain: self.chain.clone(),
            config: self.config.clone(),
            submitter: self.submitter.clone(),
            mempool: self.mempool.clone(),
            service: None,
        })
    }

    fn seed(&self, state: WalletJobState, signed: bool) -> u64 {
        self.seed_until(state, signed, 100)
    }

    fn seed_until(&self, state: WalletJobState, signed: bool, expires_at_height: u32) -> u64 {
        let job = create(
            self.db.as_ref(),
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
        let key = job.id.parse::<u64>().unwrap();
        let mut record = records(self.db.as_ref()).unwrap().pop().unwrap().1;
        if signed {
            // At this layer prepared signed bytes are opaque. An uninitialized
            // wallet and absent inputs ensure retry cannot rebuild this record.
            record.signed_hex = Some("abcd".into());
            record.job.tx_id = Some(format!("{key:064x}"));
        }
        transition(&mut record, state, None);
        save(self.db.as_ref(), key, &record).unwrap();
        key
    }

    /// Record job `key`'s transaction in the wallet's history at `height`.
    fn confirm_in_wallet(&self, key: u64, height: u32) {
        let tx_id: [u8; 32] = hex::decode(format!("{key:064x}"))
            .unwrap()
            .try_into()
            .unwrap();
        let write = self.db.begin_write().unwrap();
        write
            .open_table(ergo_state::wallet::tables::WALLET_TXS)
            .unwrap()
            .insert(
                ergo_state::wallet::tables::wallet_tx_key(height, &tx_id),
                bincode::serialize(&ergo_state::wallet::types::WalletTransaction {
                    tx_id,
                    block_height: height,
                    block_id: [0x33; 32],
                    wallet_outputs: Vec::new(),
                    wallet_inputs: vec![[0x11; 32]],
                })
                .unwrap(),
            )
            .unwrap();
        write.commit().unwrap();
    }

    fn queue_entry(&self, key: u64, state: &str) {
        self.probe
            .entries
            .lock()
            .push(ergo_wallet_protocol::mining::PrivateTransactionEntry {
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
    tick(&mut harness.context()).await.unwrap();
    assert_eq!(harness.probe.snapshots.load(Ordering::SeqCst), 1);
    assert!(list(harness.db.as_ref())
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
    let mut record = records(harness.db.as_ref()).unwrap().remove(2).1;
    record.job.attempts = record.job.request.max_attempts;
    save(harness.db.as_ref(), exhausted, &record).unwrap();
    let mined = harness.seed(WalletJobState::Queued, true);
    harness.queue_entry(mined, "mined");
    cancel(&mut harness.context(), &cancelled.to_string())
        .await
        .unwrap();
    tick(&mut harness.context()).await.unwrap();
    let jobs: BTreeMap<_, _> = records(harness.db.as_ref()).unwrap().into_iter().collect();
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
    tick(&mut harness.context()).await.unwrap();
    assert_eq!(harness.probe.snapshots.load(Ordering::SeqCst), 0);
    let job = list(harness.db.as_ref()).unwrap().items.remove(0);
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
    tick(&mut harness.context()).await.unwrap();
    assert_eq!(harness.probe.snapshots.load(Ordering::SeqCst), 0);
    for (_, record) in records(harness.db.as_ref()).unwrap() {
        assert_eq!(record.job.attempts, 0);
        assert_eq!(
            record.job.detail.as_deref(),
            Some("private mining is not enabled on this node")
        );
    }
    // Nothing can be queued on such a node, so nothing is withdrawn.
    let cancelled = cancel(&mut harness.context(), &queued.to_string())
        .await
        .unwrap();
    assert_eq!(cancelled.state, WalletJobState::Cancelled);
    assert_eq!(harness.probe.cancellations.load(Ordering::SeqCst), 0);
    harness.height.0.store(100, Ordering::SeqCst);
    tick(&mut harness.context()).await.unwrap();
    let states: BTreeMap<_, _> = records(harness.db.as_ref())
        .unwrap()
        .into_iter()
        .map(|(key, record)| (key, record.job.state))
        .collect();
    assert_eq!(states[&queued], WalletJobState::Cancelled);
    assert_eq!(states[&prepared], WalletJobState::Expired);
    assert_eq!(states[&unsigned], WalletJobState::Expired);
    assert!(reserved_inputs(harness.db.as_ref()).unwrap().is_empty());
    assert!(harness.probe.submissions.lock().is_empty());
}

#[tokio::test(start_paused = true)]
async fn cancelling_with_mining_disabled_withdraws_the_stored_queue_entry() {
    let harness = Harness::new();
    harness.probe.mining_disabled.store(true, Ordering::SeqCst);
    // The queue file loaded at boot still holds the admitted transaction.
    harness.probe.stored_queue.store(true, Ordering::SeqCst);
    let key = harness.seed(WalletJobState::Queued, true);
    harness.queue_entry(key, "queued");
    let cancelled = cancel(&mut harness.context(), &key.to_string())
        .await
        .unwrap();
    assert_eq!(cancelled.state, WalletJobState::Cancelled);
    assert_eq!(
        harness.probe.cancellations.load(Ordering::SeqCst),
        1,
        "enabling mining again must not mine a cancelled job's transaction"
    );
}

#[tokio::test(start_paused = true)]
async fn deadline_without_queue_knowledge_reports_a_wallet_confirmed_transaction() {
    let harness = Harness::new();
    let confirmed = harness.seed_until(WalletJobState::Queued, true, 10);
    let unconfirmed = harness.seed_until(WalletJobState::Queued, true, 10);
    harness.confirm_in_wallet(confirmed, 10);
    harness.probe.snapshot_fails.store(true, Ordering::SeqCst);
    tick(&mut harness.context()).await.unwrap();
    let jobs: BTreeMap<_, _> = records(harness.db.as_ref()).unwrap().into_iter().collect();
    assert_eq!(jobs[&confirmed].job.state, WalletJobState::Mined);
    assert_eq!(
        jobs[&confirmed].job.detail.as_deref(),
        Some(MINED_IN_WALLET)
    );
    assert_eq!(jobs[&unconfirmed].job.state, WalletJobState::Expired);
}

#[tokio::test(start_paused = true)]
async fn deadline_block_confirmation_reported_late_by_the_queue_is_kept() {
    let harness = Harness::new();
    let key = harness.seed_until(WalletJobState::Queued, true, 10);
    // Block 10 mined the transaction; the queue has not read it yet.
    harness.queue_entry(key, "queued");
    tick(&mut harness.context()).await.unwrap();
    assert_eq!(
        harness.probe.cancellations.load(Ordering::SeqCst),
        0,
        "a possible confirmation is not withdrawn at the deadline height"
    );
    assert_eq!(
        list(harness.db.as_ref()).unwrap().items[0].state,
        WalletJobState::Queued
    );
    harness.probe.entries.lock()[0].state = "mined".into();
    tick(&mut harness.context()).await.unwrap();
    assert_eq!(
        list(harness.db.as_ref()).unwrap().items[0].state,
        WalletJobState::Mined
    );
}

#[tokio::test(start_paused = true)]
async fn deadline_without_queue_knowledge_waits_for_the_wallet_to_scan_its_block() {
    let harness = Harness::new();
    let key = harness.seed_until(WalletJobState::Queued, true, 10);
    harness.probe.snapshot_fails.store(true, Ordering::SeqCst);
    // The wallet has scanned through block 9 only.
    harness.height.1.store(1, Ordering::SeqCst);
    tick(&mut harness.context()).await.unwrap();
    assert_eq!(
        list(harness.db.as_ref()).unwrap().items[0].state,
        WalletJobState::Queued,
        "history that stops short of the deadline block cannot tell"
    );
    harness.confirm_in_wallet(key, 10);
    harness.height.1.store(0, Ordering::SeqCst);
    tick(&mut harness.context()).await.unwrap();
    assert_eq!(
        list(harness.db.as_ref()).unwrap().items[0].state,
        WalletJobState::Mined
    );
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
    tick(&mut harness.context()).await.unwrap();
    assert_eq!(start.elapsed(), BACKGROUND_RPC_TIMEOUT);
    assert_eq!(harness.probe.snapshots.load(Ordering::SeqCst), 1);
    assert!(harness.probe.submissions.lock().is_empty());
    for (key, record) in records(harness.db.as_ref()).unwrap() {
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
    assert!(!harness.rescan.shutdown_requested());
}

#[tokio::test(start_paused = true)]
async fn unreadable_chain_tip_skips_the_wake_without_stopping_the_writer() {
    let harness = Harness::new();
    harness.seed(WalletJobState::Waiting, false);
    harness.height.0.store(UNREADABLE_TIP, Ordering::SeqCst);
    tick(&mut harness.context()).await.unwrap();
    let job = list(harness.db.as_ref()).unwrap().items.remove(0);
    assert_eq!(job.state, WalletJobState::Waiting);
    assert_eq!(job.attempts, 0);
}

#[tokio::test(start_paused = true)]
async fn uncertain_submission_retries_same_bytes_only_after_successful_absence() {
    let harness = Harness::new();
    harness.seed(WalletJobState::Prepared, true);
    harness.probe.submit_hangs.store(true, Ordering::SeqCst);
    let start = tokio::time::Instant::now();
    tick(&mut harness.context()).await.unwrap();
    assert_eq!(start.elapsed(), BACKGROUND_RPC_TIMEOUT);
    let record = records(harness.db.as_ref()).unwrap().remove(0).1;
    assert_eq!(record.job.state, WalletJobState::Prepared);
    // A queue that never answered has not judged the transaction.
    assert_eq!(record.job.attempts, 0);
    harness.height.0.store(11, Ordering::SeqCst);
    harness.probe.snapshot_fails.store(true, Ordering::SeqCst);
    tick(&mut harness.context()).await.unwrap();
    assert_eq!(harness.probe.submissions.lock().len(), 1);
    assert_eq!(
        records(harness.db.as_ref())
            .unwrap()
            .remove(0)
            .1
            .job
            .attempts,
        0
    );
    harness.height.0.store(12, Ordering::SeqCst);
    harness.probe.snapshot_fails.store(false, Ordering::SeqCst);
    harness.probe.submit_hangs.store(false, Ordering::SeqCst);
    tick(&mut harness.context()).await.unwrap();
    assert_eq!(*harness.probe.submissions.lock(), vec![vec![0xab, 0xcd]; 2]);
    let record = records(harness.db.as_ref()).unwrap().remove(0).1;
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
        tick(&mut harness.context()).await.unwrap();
    }
    let record = records(harness.db.as_ref()).unwrap().remove(0).1;
    assert_eq!(harness.probe.submissions.lock().len(), 10);
    assert_eq!(record.job.state, WalletJobState::Prepared);
    assert_eq!(record.job.attempts, 0);
    // A verdict on the transaction itself counts.
    *harness.probe.submit_refusal.lock() = Some("private_transaction_rejected");
    harness.height.0.store(20, Ordering::SeqCst);
    tick(&mut harness.context()).await.unwrap();
    assert_eq!(
        records(harness.db.as_ref())
            .unwrap()
            .remove(0)
            .1
            .job
            .attempts,
        1
    );
}

#[tokio::test(start_paused = true)]
async fn expiring_many_jobs_attempts_only_one_bounded_cancellation_per_wake() {
    let harness = Harness::new();
    for _ in 0..8 {
        let key = harness.seed(WalletJobState::Queued, true);
        harness.queue_entry(key, "queued");
    }
    // A block past the deadline the queue still lists them as unfinished.
    harness.height.0.store(101, Ordering::SeqCst);
    harness.probe.cancel_hangs.store(true, Ordering::SeqCst);
    let start = tokio::time::Instant::now();
    tick(&mut harness.context()).await.unwrap();
    assert_eq!(start.elapsed(), BACKGROUND_RPC_TIMEOUT);
    assert_eq!(harness.probe.cancellations.load(Ordering::SeqCst), 1);
    assert_eq!(harness.probe.snapshots.load(Ordering::SeqCst), 1);
    assert!(list(harness.db.as_ref())
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
    assert!(cancel(&mut harness.context(), &key.to_string())
        .await
        .is_err());
    assert_eq!(start.elapsed(), BACKGROUND_RPC_TIMEOUT);
    assert_eq!(harness.probe.cancellations.load(Ordering::SeqCst), 1);
    let record = records(harness.db.as_ref()).unwrap().remove(0).1;
    assert_eq!(record.job.state, WalletJobState::Queued);
    assert_eq!(record.signed_hex.as_deref(), Some("abcd"));
}
