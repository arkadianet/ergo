//! The seed wallet's single writer. Lifecycle commands and complete sync
//! passes share the same gate, so a key mutation cannot race a page that was
//! classified with an older key set. Blocking work stays off Tokio workers.

use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use ergo_wallet::error::WalletError;
use ergo_wallet::storage::SecretStorage;
use ergo_wallet_protocol::scala::admin_advanced::{
    DeriveKeyRequest, DeriveKeyResponse, DeriveNextKeyResponse,
};
use ergo_wallet_protocol::scala::types::WalletStatus;
use ergo_wallet_protocol::WalletAdminError;
use ergo_wallet_service::engine::{
    MempoolOverlay, NoopMempoolOverlay, RescanCoordinator, TxSubmitError, TxSubmitter,
    WalletChainAccess, WalletEngine, WalletEngineConfig, WalletEngineParts,
};
use ergo_wallet_service::state::WalletState;
use ergo_wallet_service::wallet::hydration::HydrationSnapshot;
use ergo_wallet_service::{WalletService, WalletStore, WalletStoreError};
use parking_lot::{Mutex, RwLock};
use thiserror::Error;
use tokio::sync::Semaphore;

use crate::config::Network;
use crate::sync::{StandaloneSyncer, SyncError, SyncReport};

/// Includes the running command and commands waiting for the writer. A burst
/// of password guesses cannot create an unbounded blocking-thread backlog.
const MAX_ADMITTED_COMMANDS: usize = 32;

/// Called under the writer immediately before a command consumes node state.
/// Implementations replace their chain, pool and reservation views together,
/// and fail before entering the engine if any required component is missing.
pub trait SpendingPreparation: Send + Sync {
    fn refresh(&self) -> Result<WalletEngineConfig, WalletAdminError>;
    /// Release command-local pinned state, including on errors or unwinding.
    fn finish(&self) {}
}

struct SpendingScope(Arc<dyn SpendingPreparation>);
impl Drop for SpendingScope {
    fn drop(&mut self) {
        self.0.finish();
    }
}

pub struct SpendingCapabilities {
    pub chain: Arc<dyn WalletChainAccess>,
    pub preparation: Arc<dyn SpendingPreparation>,
    pub submitter: Arc<dyn TxSubmitter>,
    pub mempool: Arc<dyn MempoolOverlay>,
}

#[derive(Debug, Error)]
pub enum HostError {
    #[error("seed wallet storage failure: {0}")]
    Secret(#[from] WalletError),
    #[error("seed wallet store failure: {0}")]
    Store(#[from] WalletStoreError),
    #[error("seed wallet public-state hydration failed: {0}")]
    Hydration(String),
    #[error("seed wallet has public wallet state but no encrypted secret; use a separate data_dir for watch-only and seed wallets")]
    PublicStateWithoutSecret,
}

/// File in the data directory holding the unlock failed-attempt record.
pub const UNLOCK_ATTEMPTS_FILE: &str = "unlock-attempts.json";

/// Owner-only, atomically replaced JSON record of unlock failures, so that
/// restarting the daemon neither resets the guess budget nor ends a lockout.
pub(crate) struct FileAttemptJournal(pub(crate) std::path::PathBuf);

impl ergo_wallet_service::engine::AttemptJournal for FileAttemptJournal {
    fn load(&self) -> Result<Option<ergo_wallet_service::engine::AttemptRecord>, String> {
        match std::fs::read(&self.0) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|error| error.to_string()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.to_string()),
        }
    }

    fn save(&self, record: &ergo_wallet_service::engine::AttemptRecord) -> Result<(), String> {
        use std::io::Write;
        let dir = self
            .0
            .parent()
            .ok_or_else(|| "attempt record has no directory".to_string())?;
        let bytes = serde_json::to_vec(record).map_err(|error| error.to_string())?;
        let mut pending = tempfile::Builder::new()
            .prefix(".unlock-attempts-")
            .tempfile_in(dir)
            .map_err(|error| error.to_string())?;
        pending
            .write_all(&bytes)
            .map_err(|error| error.to_string())?;
        pending
            .as_file()
            .sync_all()
            .map_err(|error| error.to_string())?;
        pending
            .persist(&self.0)
            .map_err(|error| error.error.to_string())?;
        // Make the rename durable too, or a power loss could restore the
        // previous record and with it a spent guess budget.
        #[cfg(unix)]
        std::fs::File::open(dir)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| error.to_string())?;
        Ok(())
    }
}

struct Inner {
    engine: Mutex<WalletEngine>,
    store: Arc<dyn WalletStore>,
    closing: AtomicBool,
    admission: Arc<Semaphore>,
    preparation: Option<Arc<dyn SpendingPreparation>>,
    submitter: Arc<dyn TxSubmitter>,
    rescan: Arc<RescanCoordinator>,
    rescan_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    recovery_generation: AtomicU64,
    /// When the current unlock began and when the last wallet operation ran.
    session: Mutex<Option<UnlockSession>>,
    /// Multisig nonces kept by the daemon, when enabled.
    nonce_vault: Mutex<Option<Arc<crate::nonce_vault::NonceVault>>>,
}

#[derive(Debug, Clone, Copy)]
struct UnlockSession {
    unlocked_at: std::time::Instant,
    last_activity: std::time::Instant,
}

/// Why [`WalletHost::enforce_lock_policy`] locked the wallet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoLock {
    Idle,
    MaxUnlocked,
}

impl UnlockSession {
    fn expired(
        &self,
        policy: crate::config::LockPolicy,
        now: std::time::Instant,
    ) -> Option<AutoLock> {
        let elapsed = |since: std::time::Instant| now.saturating_duration_since(since);
        if policy
            .max_unlocked
            .is_some_and(|limit| elapsed(self.unlocked_at) >= limit)
        {
            return Some(AutoLock::MaxUnlocked);
        }
        if policy
            .idle
            .is_some_and(|limit| elapsed(self.last_activity) >= limit)
        {
            return Some(AutoLock::Idle);
        }
        None
    }
}

/// The tracked rows used by a failed pass. Compare the committed key set,
/// rather than failure metadata: recording Failed itself can fail under an
/// I/O error, and an old Idle marker is not a request to retry that pass.
pub(crate) struct TrackingSnapshot(
    Vec<ergo_wallet_service::wallet::reader::TrackedAddressMeta>,
    u64,
);

impl TrackingSnapshot {
    fn matches(&self, rows: &Self) -> bool {
        self.1 == rows.1
            && self.0.len() == rows.0.len()
            && self.0.iter().zip(&rows.0).all(|(left, right)| {
                left.path_idx == right.path_idx
                    && left.pubkey == right.pubkey
                    && left.derivation_path == right.derivation_path
                    && left.label == right.label
                    && left.added_at_height == right.added_at_height
            })
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        // Also covers startup/listener failures and a timed-out shutdown: the
        // final admitted worker owns this Arc until it has finished.
        let _ = self.engine.get_mut().lock();
    }
}

/// Cloneable command handle for one seed wallet. The engine itself is never
/// exposed, and every command takes the same writer gate used by sync.
#[derive(Clone)]
pub struct WalletHost {
    inner: Arc<Inner>,
}

impl WalletHost {
    /// Construct a locked engine. The store must have been opened with
    /// `RedbWalletStore::rebuild_history_on_key_additions`: new keys and the
    /// corresponding history reset then commit atomically.
    pub fn new(
        store: Arc<dyn WalletStore>,
        service: Arc<WalletService>,
        chain: Arc<dyn WalletChainAccess>,
        data_dir: &Path,
        network: Network,
    ) -> Result<Self, HostError> {
        Self::construct(store, service, chain, data_dir, network, None)
    }

    /// Host the complete engine using one shared, coherently refreshed node
    /// adapter. Construction does not require a reachable node.
    pub fn with_spending(
        store: Arc<dyn WalletStore>,
        service: Arc<WalletService>,
        capabilities: SpendingCapabilities,
        data_dir: &Path,
        network: Network,
    ) -> Result<Self, HostError> {
        Self::construct(
            store,
            service,
            capabilities.chain.clone(),
            data_dir,
            network,
            Some(capabilities),
        )
    }

    fn construct(
        store: Arc<dyn WalletStore>,
        service: Arc<WalletService>,
        chain: Arc<dyn WalletChainAccess>,
        data_dir: &Path,
        network: Network,
        capabilities: Option<SpendingCapabilities>,
    ) -> Result<Self, HostError> {
        let secret_dir = data_dir.join("wallet");
        let mut storage = SecretStorage::open(secret_dir.clone());
        let read = store.read()?;
        let use_pre_1627 = match SecretStorage::find_secret_file(&secret_dir) {
            Ok(_) => storage.load_metadata()?,
            Err(WalletError::WalletUninitialized) => {
                if !read.tracked_pubkeys_with_paths()?.is_empty()
                    || !read.visible_pubkeys()?.is_empty()
                    || read.change_address_pubkey()?.is_some()
                    || read.registered_scan_count()? != 0
                {
                    return Err(HostError::PublicStateWithoutSecret);
                }
                false
            }
            Err(error) => return Err(error.into()),
        };
        let hydration = HydrationSnapshot::load(read.as_ref())?;
        drop(read);
        let mut state = WalletState::empty(use_pre_1627);
        state
            .hydrate_from_reader(&hydration, network.prefix())
            .map_err(|error| HostError::Hydration(error.to_string()))?;
        let rescan = Arc::new(RescanCoordinator::new());
        ergo_wallet_service::engine::recover_interrupted_rescan(store.as_ref(), rescan.as_ref())?;
        let submitter: Arc<dyn TxSubmitter> = capabilities.as_ref().map_or_else(
            || Arc::new(DisabledSubmitter) as Arc<dyn TxSubmitter>,
            |capabilities| capabilities.submitter.clone(),
        );
        let mempool: Arc<dyn MempoolOverlay> = capabilities.as_ref().map_or_else(
            || Arc::new(NoopMempoolOverlay::new()) as Arc<dyn MempoolOverlay>,
            |capabilities| capabilities.mempool.clone(),
        );
        let preparation = capabilities.map(|capabilities| capabilities.preparation);
        let mut engine = WalletEngine::new(WalletEngineParts {
            storage: Arc::new(RwLock::new(storage)),
            state: Arc::new(RwLock::new(state)),
            store: store.clone(),
            chain,
            config: WalletEngineConfig {
                network: network.prefix(),
                expose_private_keys: false,
                // Replaced under the writer before each spending command.
                reemission: None,
                min_relay_fee_nano_erg: 0,
                max_tx_size_bytes: 0,
            },
            submitter: submitter.clone(),
            mempool,
            service: Some(service),
            rescan: rescan.clone(),
        });
        engine.set_unlock_attempt_journal(Arc::new(FileAttemptJournal(
            data_dir.join(UNLOCK_ATTEMPTS_FILE),
        )));
        engine
            .recover_mining_jobs()
            .map_err(|error| HostError::Hydration(error.to_string()))?;
        Ok(Self {
            inner: Arc::new(Inner {
                engine: Mutex::new(engine),
                store,
                closing: AtomicBool::new(false),
                admission: Arc::new(Semaphore::new(MAX_ADMITTED_COMMANDS)),
                preparation,
                submitter,
                rescan,
                rescan_task: Mutex::new(None),
                recovery_generation: AtomicU64::new(0),
                session: Mutex::new(None),
                nonce_vault: Mutex::new(None),
            }),
        })
    }

    pub(crate) async fn call<T, F>(&self, command: F) -> Result<T, WalletAdminError>
    where
        T: Send + 'static,
        F: FnOnce(&mut WalletEngine) -> Result<T, WalletAdminError> + Send + 'static,
    {
        self.call_inner(command, false).await
    }

    async fn call_inner<T, F>(&self, command: F, during_rescan: bool) -> Result<T, WalletAdminError>
    where
        T: Send + 'static,
        F: FnOnce(&mut WalletEngine) -> Result<T, WalletAdminError> + Send + 'static,
    {
        if self.inner.closing.load(Ordering::SeqCst) {
            return Err(WalletAdminError::ShuttingDown);
        }
        let permit = self
            .inner
            .admission
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                if self.inner.closing.load(Ordering::SeqCst) {
                    WalletAdminError::ShuttingDown
                } else {
                    WalletAdminError::RateLimited
                }
            })?;
        let inner = self.inner.clone();
        let result = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let mut engine = inner.engine.lock();
            if inner.closing.load(Ordering::SeqCst) {
                return Err(WalletAdminError::ShuttingDown);
            }
            if !during_rescan && inner.rescan.task_active() {
                return Err(WalletAdminError::RescanUnavailable(
                    "wallet rescan is running".into(),
                ));
            }
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| command(&mut engine))) {
                Ok(result) => result,
                Err(_) => {
                    // Latch before releasing the gate: a queued command
                    // must never enter the partially changed engine.
                    inner.closing.store(true, Ordering::SeqCst);
                    inner.admission.close();
                    engine.lock()?;
                    Err(WalletAdminError::Internal(
                        "wallet command task panicked".to_string(),
                    ))
                }
            }
        })
        .await;
        match result {
            Ok(result) => result,
            Err(error) => {
                // A panicked command may have changed part of the engine.
                // Refuse subsequent work and erase its key before returning.
                self.shutdown().await?;
                Err(WalletAdminError::Internal(format!(
                    "wallet command task failed: {error}"
                )))
            }
        }
    }

    pub(crate) async fn call_async<T, F>(&self, command: F) -> Result<T, WalletAdminError>
    where
        T: Send + 'static,
        F: for<'a> FnOnce(
                &'a mut WalletEngine,
            )
                -> Pin<Box<dyn Future<Output = Result<T, WalletAdminError>> + Send + 'a>>
            + Send
            + 'static,
    {
        let runtime = tokio::runtime::Handle::current();
        self.call(move |engine| runtime.block_on(command(engine)))
            .await
    }

    pub(crate) async fn call_spending<T, F>(&self, command: F) -> Result<T, WalletAdminError>
    where
        T: Send + 'static,
        F: FnOnce(&mut WalletEngine) -> Result<T, WalletAdminError> + Send + 'static,
    {
        let preparation = self.inner.preparation.clone();
        self.call(move |engine| {
            let preparation = preparation.ok_or_else(|| {
                WalletAdminError::StaleChainTip("wallet spending is unavailable".into())
            })?;
            let scope = SpendingScope(preparation);
            engine.refresh_spending_config(scope.0.refresh()?);
            command(engine)
        })
        .await
    }

    pub(crate) async fn call_spending_async<T, F>(&self, command: F) -> Result<T, WalletAdminError>
    where
        T: Send + 'static,
        F: for<'a> FnOnce(
                &'a mut WalletEngine,
            )
                -> Pin<Box<dyn Future<Output = Result<T, WalletAdminError>> + Send + 'a>>
            + Send
            + 'static,
    {
        let runtime = tokio::runtime::Handle::current();
        self.call_spending(move |engine| runtime.block_on(command(engine)))
            .await
    }

    pub(crate) fn submitter(&self) -> Arc<dyn TxSubmitter> {
        self.inner.submitter.clone()
    }

    /// Claim the rescan while holding the writer. Its background replay is
    /// the sole public-state writer until the coordinator releases its fence.
    pub async fn rescan(&self, from_height: u32) -> Result<(), WalletAdminError> {
        let inner = self.inner.clone();
        self.call_spending(move |engine| {
            let job = engine.prepare_rescan(from_height)?;
            inner.recovery_generation.fetch_add(1, Ordering::SeqCst);
            let owner = inner.clone();
            let task = tokio::task::spawn_blocking(move || {
                if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| job.run())).is_err() {
                    owner.closing.store(true, Ordering::SeqCst);
                    owner.admission.close();
                    let _ = owner.engine.lock().lock();
                }
            });
            *inner.rescan_task.lock() = Some(task);
            Ok(())
        })
        .await
    }

    pub(crate) async fn tick_mining_jobs(&self) -> Result<(), WalletAdminError> {
        let preparation = self.inner.preparation.clone();
        self.call_async(move |engine| {
            Box::pin(async move {
                let jobs = engine.mining_jobs()?;
                if !jobs
                    .items
                    .iter()
                    .any(|job| !job.state.terminal() || job.tx_id.is_some())
                {
                    return Ok(());
                }
                let preparation = preparation.ok_or_else(|| {
                    WalletAdminError::StaleChainTip("wallet spending is unavailable".into())
                })?;
                let scope = SpendingScope(preparation);
                engine.refresh_spending_config(scope.0.refresh()?);
                engine.tick_mining_jobs().await
            })
        })
        .await
    }

    pub async fn status(&self) -> Result<WalletStatus, WalletAdminError> {
        self.call_inner(|engine| engine.status(), true).await
    }

    pub async fn native_status(
        &self,
    ) -> Result<ergo_wallet_protocol::native::dto::WalletStatusDto, WalletAdminError> {
        let preparation = self.inner.preparation.clone();
        self.call_inner(
            move |engine| {
                // Pruning and EIP-27 are properties of a validated node view.
                // Keep that view pinned until status finishes reading it.
                let scope = preparation.map(SpendingScope);
                if let Some(scope) = &scope {
                    engine.refresh_spending_config(scope.0.refresh()?);
                }
                engine.native_status()
            },
            true,
        )
        .await
    }

    pub async fn init(
        &self,
        pass: String,
        mnemonic_pass: String,
        strength: u8,
    ) -> Result<String, WalletAdminError> {
        self.call(move |engine| engine.init(pass, mnemonic_pass, strength))
            .await
    }

    pub async fn restore(
        &self,
        mnemonic: String,
        mnemonic_pass: String,
        pass: String,
        use_pre_1627: bool,
    ) -> Result<(), WalletAdminError> {
        self.call(move |engine| engine.restore(mnemonic, mnemonic_pass, pass, use_pre_1627))
            .await
    }

    pub async fn unlock(&self, pass: String) -> Result<(), WalletAdminError> {
        self.call(move |engine| engine.unlock(pass)).await?;
        let now = std::time::Instant::now();
        *self.inner.session.lock() = Some(UnlockSession {
            unlocked_at: now,
            last_activity: now,
        });
        Ok(())
    }

    pub async fn lock(&self) -> Result<(), WalletAdminError> {
        self.call_inner(|engine| engine.lock(), true).await?;
        *self.inner.session.lock() = None;
        if let Some(vault) = self.inner.nonce_vault.lock().as_ref() {
            vault.clear();
        }
        Ok(())
    }

    /// Keep multisig nonces in the daemon: `generateCommitments` returns
    /// single-use handles, and locking wipes every held nonce.
    pub fn enable_nonce_custody(&self) {
        let vault = Arc::new(crate::nonce_vault::NonceVault::default());
        self.inner.engine.lock().set_nonce_custody(vault.clone());
        *self.inner.nonce_vault.lock() = Some(vault);
    }

    /// Seal the wallet database key into the keystore a later `init` or
    /// `restore` creates.
    pub fn set_new_wallet_data_key(&self, key: &crate::encrypted_db::DataKey) {
        self.inner
            .engine
            .lock()
            .set_new_wallet_data_key(*key.expose());
    }

    /// Record a wallet operation for the idle lock. Reads do not count, so a
    /// polling client cannot keep the wallet unlocked.
    pub fn note_activity(&self) {
        if let Some(session) = self.inner.session.lock().as_mut() {
            session.last_activity = std::time::Instant::now();
        }
    }

    /// Lock the wallet when its unlock has outlived `policy`. Returns why it
    /// locked, if it did.
    pub async fn enforce_lock_policy(
        &self,
        policy: crate::config::LockPolicy,
    ) -> Result<Option<AutoLock>, WalletAdminError> {
        self.enforce_lock_policy_at(policy, std::time::Instant::now())
            .await
    }

    async fn enforce_lock_policy_at(
        &self,
        policy: crate::config::LockPolicy,
        now: std::time::Instant,
    ) -> Result<Option<AutoLock>, WalletAdminError> {
        let expired = self
            .inner
            .session
            .lock()
            .and_then(|session| session.expired(policy, now));
        let Some(reason) = expired else {
            return Ok(None);
        };
        self.lock().await?;
        tracing::info!(?reason, "wallet locked automatically");
        Ok(Some(reason))
    }

    pub async fn check(
        &self,
        mnemonic: String,
        mnemonic_pass: String,
    ) -> Result<bool, WalletAdminError> {
        self.call(move |engine| engine.check(mnemonic, mnemonic_pass))
            .await
    }

    pub async fn derive_key(
        &self,
        request: DeriveKeyRequest,
    ) -> Result<DeriveKeyResponse, WalletAdminError> {
        self.call(move |engine| engine.derive_key(request)).await
    }

    pub async fn derive_next_key(&self) -> Result<DeriveNextKeyResponse, WalletAdminError> {
        self.call(|engine| engine.derive_next_key()).await
    }

    pub async fn update_change_address(&self, address: String) -> Result<(), WalletAdminError> {
        self.call(move |engine| engine.update_change_address(address))
            .await
    }

    /// Run from the daemon's blocking sync worker. An uninitialized wallet
    /// has no known keys: publishing a caught-up cursor then would skip old
    /// funds when its first unlock derives keys.
    pub fn sync_once(&self, syncer: &StandaloneSyncer) -> Result<Option<SyncReport>, SyncError> {
        self.sync_once_with_recovery(syncer, &mut None)
    }

    /// A terminal pass parks until a key change commits its history reset.
    /// Both capturing the failed key set and checking the next one happen
    /// under the writer, so a concurrent derivation cannot lose its replay.
    pub(crate) fn sync_once_with_recovery(
        &self,
        syncer: &StandaloneSyncer,
        terminal_tracking: &mut Option<TrackingSnapshot>,
    ) -> Result<Option<SyncReport>, SyncError> {
        let _engine = self.inner.engine.lock();
        if self.inner.closing.load(Ordering::SeqCst) {
            return Err(SyncError::Cancelled);
        }
        if self.inner.rescan.task_active() {
            return Ok(None);
        }
        let tracking = TrackingSnapshot(
            self.inner.store.read()?.tracked_addresses_with_meta()?,
            self.inner.recovery_generation.load(Ordering::SeqCst),
        );
        if terminal_tracking
            .as_ref()
            .is_some_and(|failed| failed.matches(&tracking))
        {
            return Ok(None);
        }
        *terminal_tracking = None;
        if tracking.0.is_empty() {
            return Ok(None);
        }
        let result = syncer.sync_once().map(Some);
        if result
            .as_ref()
            .is_ok_and(|report| report.as_ref().is_some_and(|report| report.completed))
        {
            let read = self.inner.store.read()?;
            if !read.scan_invalidated()?
                && matches!(read.rescan_state()?, ergo_wallet_service::RescanState::Idle)
            {
                // A key/history reset can recover an earlier failed rescan
                // through ordinary sync. Release only an inactive generation,
                // after its complete durable history is valid again.
                self.inner.rescan.clear_guards();
            }
        }
        if result
            .as_ref()
            .is_err_and(|error| !error.retryable() && !matches!(error, SyncError::Cancelled))
        {
            *terminal_tracking = Some(tracking);
        }
        result
    }

    /// Close command admission before cancelling sync or stopping listeners.
    pub fn begin_shutdown(&self) {
        self.inner.closing.store(true, Ordering::SeqCst);
        self.inner.admission.close();
        self.inner.rescan.request_shutdown();
    }

    /// Drain work that already acquired the writer, then erase the unlocked
    /// master key. Commands waiting for it observe the shutdown latch.
    pub async fn shutdown(&self) -> Result<(), WalletAdminError> {
        self.begin_shutdown();
        // Schedule the key-erasure barrier before any cancellable await.
        // A rescan command which already owns the writer can still publish
        // its task; taking that slot before this barrier would miss it.
        let owner = self.inner.clone();
        let barrier = tokio::task::spawn_blocking(move || owner.engine.lock().lock());
        let owner = self.inner.clone();
        let finalizer = tokio::spawn(async move {
            let drained = barrier.await;
            let task = owner.rescan_task.lock().take();
            let replay = match task {
                Some(task) => task.await,
                None => Ok(()),
            };
            let erased = drained.map_err(|error| {
                WalletAdminError::Internal(format!("wallet shutdown task failed: {error}"))
            })?;
            erased?;
            replay.map_err(|error| {
                WalletAdminError::Internal(format!("wallet rescan task failed: {error}"))
            })
        });
        // Dropping the caller's wait does not cancel the finalizer or barrier.
        finalizer.await.map_err(|error| {
            WalletAdminError::Internal(format!("wallet shutdown finalizer failed: {error}"))
        })?
    }
}

struct DisabledSubmitter;

#[async_trait]
impl TxSubmitter for DisabledSubmitter {
    async fn submit_transaction(&self, _tx_bytes: Vec<u8>) -> Result<String, TxSubmitError> {
        Err(TxSubmitError {
            reason: "wallet_spending_unavailable".to_string(),
            detail: Some("daemon spending is not enabled".to_string()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    use ergo_wallet_service::{
        BlocksSinceRequest, BlocksSinceResponse, ChainBlock, ChainClient, ChainClientError,
        ChainSnapshot, CommittedTip, ForwardBlocksSince, RedbWalletStore, RescanState,
        SubmitRequest, SubmitResponse, UtxoLookup,
    };

    use crate::engine_chain::LifecycleChainAccess;
    use crate::sync::SyncConfig;
    use crate::tip::CachedNodeTip;

    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[derive(Default)]
    struct TestChain {
        calls: AtomicUsize,
    }

    impl ChainClient for TestChain {
        fn committed_tip(&self) -> Result<CommittedTip, ChainClientError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(CommittedTip::new(3, [3; 32]))
        }

        fn snapshot(&self) -> Result<ChainSnapshot, ChainClientError> {
            Err(ChainClientError::Unsupported)
        }

        fn blocks_since(
            &self,
            request: BlocksSinceRequest,
        ) -> Result<BlocksSinceResponse, ChainClientError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let last = 3.min(request.cursor.height.saturating_add(request.limit));
            let blocks = (request.cursor.height.saturating_add(1)..=last)
                .map(|height| ChainBlock {
                    height,
                    block_id: [height as u8; 32],
                    parent_id: [height.saturating_sub(1) as u8; 32],
                    header_bytes: Vec::new(),
                    transactions: Vec::new(),
                })
                .collect();
            Ok(BlocksSinceResponse::Forward(ForwardBlocksSince {
                tip: CommittedTip::new(3, [3; 32]),
                blocks,
            }))
        }

        fn lookup_utxo(
            &self,
            _box_id: [u8; 32],
            _expected_tip: CommittedTip,
        ) -> Result<UtxoLookup, ChainClientError> {
            Err(ChainClientError::Unsupported)
        }

        fn submit(&self, _request: SubmitRequest) -> Result<SubmitResponse, ChainClientError> {
            panic!("the lifecycle host must never submit")
        }
    }

    struct Fixture {
        dir: tempfile::TempDir,
        store: Arc<RedbWalletStore>,
        chain: Arc<TestChain>,
        service: Arc<WalletService>,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let store = Arc::new(
                RedbWalletStore::open_standalone(dir.path().join("wallet.redb"))
                    .unwrap()
                    .rebuild_history_on_key_additions(),
            );
            let chain = Arc::new(TestChain::default());
            let service = Arc::new(WalletService::new(store.clone(), chain.clone()));
            Self {
                dir,
                store,
                chain,
                service,
            }
        }

        fn host(&self) -> Result<WalletHost, HostError> {
            WalletHost::new(
                self.store.clone(),
                self.service.clone(),
                Arc::new(LifecycleChainAccess::new(
                    self.store.clone(),
                    self.chain.clone(),
                )),
                self.dir.path(),
                Network::Testnet,
            )
        }

        fn syncer(&self) -> StandaloneSyncer {
            StandaloneSyncer::new(
                self.service.clone(),
                SyncConfig {
                    batch: 3,
                    page: 3,
                    retry_delay: Duration::ZERO,
                    max_retry_delay: Duration::ZERO,
                },
                Arc::new(CachedNodeTip::new(self.chain.clone())),
            )
        }
    }

    async fn restore_and_unlock(host: &WalletHost) {
        host.restore(PHRASE.to_string(), String::new(), "test".to_string(), false)
            .await
            .unwrap();
        host.unlock("test".to_string()).await.unwrap();
    }

    #[tokio::test]
    async fn unlock_failures_survive_a_restart() {
        let fixture = Fixture::new();
        let host = fixture.host().unwrap();
        host.restore(PHRASE.to_string(), String::new(), "test".to_string(), false)
            .await
            .unwrap();
        for _ in 0..4 {
            assert_eq!(
                host.unlock("wrong".to_string()).await.unwrap_err(),
                WalletAdminError::WrongPassword
            );
        }
        host.shutdown().await.unwrap();
        drop(host);
        let path = fixture.dir.path().join(UNLOCK_ATTEMPTS_FILE);
        assert!(path.is_file(), "the attempt record is persisted");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o077,
                0
            );
        }
        // The fifth failure after a restart still exhausts the budget.
        let reopened = fixture.host().unwrap();
        assert_eq!(
            reopened.unlock("wrong".to_string()).await.unwrap_err(),
            WalletAdminError::WrongPassword
        );
        assert_eq!(
            reopened.unlock("test".to_string()).await.unwrap_err(),
            WalletAdminError::RateLimited
        );
        reopened.shutdown().await.unwrap();
        drop(reopened);
        let again = fixture.host().unwrap();
        assert_eq!(
            again.unlock("test".to_string()).await.unwrap_err(),
            WalletAdminError::RateLimited,
            "a restart does not end the lockout"
        );
        again.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn lock_policy_locks_after_idle_or_maximum_and_reads_do_not_extend() {
        use crate::config::LockPolicy;
        let fixture = Fixture::new();
        let host = fixture.host().unwrap();
        let policy = LockPolicy {
            idle: Some(Duration::from_secs(60)),
            max_unlocked: Some(Duration::from_secs(600)),
        };
        // Locked wallets have no session to expire.
        assert_eq!(host.enforce_lock_policy(policy).await.unwrap(), None);
        restore_and_unlock(&host).await;
        let start = std::time::Instant::now();
        assert_eq!(
            host.enforce_lock_policy_at(policy, start).await.unwrap(),
            None
        );
        // Reads do not count as activity.
        host.status().await.unwrap();
        assert_eq!(
            host.enforce_lock_policy_at(policy, start + Duration::from_secs(61))
                .await
                .unwrap(),
            Some(AutoLock::Idle)
        );
        assert!(!host.status().await.unwrap().is_unlocked);

        host.unlock("test".to_string()).await.unwrap();
        let start = std::time::Instant::now();
        for minute in 1..=9 {
            // Operations keep the idle timer fresh...
            host.inner.session.lock().as_mut().unwrap().last_activity =
                start + Duration::from_secs(minute * 60);
            assert_eq!(
                host.enforce_lock_policy_at(policy, start + Duration::from_secs(minute * 60 + 30))
                    .await
                    .unwrap(),
                None
            );
        }
        host.note_activity();
        // ...but never past the maximum unlock duration.
        host.inner.session.lock().as_mut().unwrap().last_activity =
            start + Duration::from_secs(599);
        assert_eq!(
            host.enforce_lock_policy_at(policy, start + Duration::from_secs(600))
                .await
                .unwrap(),
            Some(AutoLock::MaxUnlocked)
        );
        assert!(!host.status().await.unwrap().is_unlocked);

        // An explicit lock ends the session; disabled limits never lock.
        host.unlock("test".to_string()).await.unwrap();
        host.lock().await.unwrap();
        assert!(host.inner.session.lock().is_none());
        host.unlock("test".to_string()).await.unwrap();
        let unlimited = LockPolicy {
            idle: None,
            max_unlocked: None,
        };
        assert_eq!(
            host.enforce_lock_policy_at(
                unlimited,
                std::time::Instant::now() + Duration::from_secs(86_400 * 30)
            )
            .await
            .unwrap(),
            None
        );
        assert!(host.status().await.unwrap().is_unlocked);
        host.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn lifecycle_is_local_and_restart_keeps_keys_but_locks_secrets() {
        let fixture = Fixture::new();
        let host = fixture.host().unwrap();
        assert!(!host.status().await.unwrap().is_initialized);
        assert_eq!(
            host.unlock("test".to_string()).await.unwrap_err(),
            WalletAdminError::Uninitialized
        );
        let phrase = host
            .init("test".to_string(), String::new(), 12)
            .await
            .unwrap();
        let initialized = host.status().await.unwrap();
        assert!(initialized.is_initialized);
        assert!(!initialized.is_unlocked);
        host.unlock("test".to_string()).await.unwrap();
        assert!(host.check(phrase, String::new()).await.unwrap());
        let derived = host.derive_next_key().await.unwrap();
        let keys = fixture
            .store
            .read()
            .unwrap()
            .tracked_pubkeys_with_paths()
            .unwrap();
        assert_eq!(keys.len(), 3);
        host.update_change_address(derived.address).await.unwrap();
        assert_eq!(fixture.chain.calls.load(Ordering::SeqCst), 1);
        // The single node call above records added_at_height for derivation;
        // initialization, passwords and lifecycle status are entirely local.
        host.shutdown().await.unwrap();
        assert!(matches!(
            host.status().await,
            Err(WalletAdminError::ShuttingDown)
        ));
        drop(host);
        let reopened = fixture.host().unwrap();
        let status = reopened.status().await.unwrap();
        assert!(status.is_initialized);
        assert!(!status.is_unlocked);
        assert_eq!(
            keys,
            fixture
                .store
                .read()
                .unwrap()
                .tracked_pubkeys_with_paths()
                .unwrap()
        );
        reopened.unlock("test".to_string()).await.unwrap();
        assert!(reopened.status().await.unwrap().is_unlocked);
        reopened.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn first_unlock_resets_old_cursor_atomically_but_wrong_password_preserves_it() {
        let fixture = Fixture::new();
        let host = fixture.host().unwrap();
        host.init("test".to_string(), String::new(), 12)
            .await
            .unwrap();
        {
            let mut write = fixture.store.begin_write().unwrap();
            write.set_scan_cursor(3, Some(&[3; 32])).unwrap();
            write.set_scan_invalidated(false).unwrap();
            write.commit().unwrap();
        }
        assert_eq!(
            host.unlock("wrong".to_string()).await.unwrap_err(),
            WalletAdminError::WrongPassword
        );
        {
            let read = fixture.store.read().unwrap();
            assert_eq!(read.scan_cursor().unwrap().unwrap().height, 3);
            assert!(!read.scan_invalidated().unwrap());
            assert!(read.tracked_pubkeys_with_paths().unwrap().is_empty());
        }
        host.unlock("test".to_string()).await.unwrap();
        let read = fixture.store.read().unwrap();
        assert_eq!(read.scan_cursor().unwrap().unwrap().height, 0);
        assert!(read.scan_invalidated().unwrap());
        assert_eq!(read.rescan_state().unwrap(), RescanState::Idle);
        assert_eq!(read.tracked_pubkeys_with_paths().unwrap().len(), 2);
    }

    #[test]
    fn seed_boot_refuses_watch_rows_without_secrets_and_corrupt_secrets() {
        let fixture = Fixture::new();
        {
            let mut write = fixture.store.begin_write().unwrap();
            write
                .insert_tracked_pubkey(
                    0,
                    [2; 33],
                    &ergo_wallet_service::TrackedPubkeyMeta {
                        derivation_path: Vec::new(),
                        derivation_path_label: String::new(),
                        added_at_height: 0,
                    },
                )
                .unwrap();
            write.commit().unwrap();
        }
        assert!(matches!(
            fixture.host(),
            Err(HostError::PublicStateWithoutSecret)
        ));
        let clean = Fixture::new();
        std::fs::create_dir(clean.dir.path().join("wallet")).unwrap();
        std::fs::write(clean.dir.path().join("wallet/broken.json"), b"broken").unwrap();
        assert!(matches!(clean.host(), Err(HostError::Secret(_))));
    }

    #[test]
    fn no_key_sync_never_publishes_an_empty_wallet_cursor() {
        let fixture = Fixture::new();
        let host = fixture.host().unwrap();
        assert!(host.sync_once(&fixture.syncer()).unwrap().is_none());
        assert_eq!(fixture.chain.calls.load(Ordering::SeqCst), 0);
        assert!(fixture
            .store
            .read()
            .unwrap()
            .scan_cursor()
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn sync_waits_for_the_command_writer_and_resumes_afterwards() {
        let fixture = Fixture::new();
        let host = fixture.host().unwrap();
        restore_and_unlock(&host).await;
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let command_host = host.clone();
        let command = tokio::spawn(async move {
            command_host
                .call(move |engine| {
                    entered_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    engine.lock()
                })
                .await
        });
        entered_rx.await.unwrap();
        let sync_host = host.clone();
        let syncer = fixture.syncer();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let mut sync = tokio::task::spawn_blocking(move || {
            started_tx.send(()).unwrap();
            sync_host.sync_once(&syncer)
        });
        started_rx.await.unwrap();
        assert!(tokio::time::timeout(Duration::from_millis(20), &mut sync)
            .await
            .is_err());
        assert_eq!(fixture.chain.calls.load(Ordering::SeqCst), 0);
        release_tx.send(()).unwrap();
        command.await.unwrap().unwrap();
        assert!(sync.await.unwrap().unwrap().unwrap().completed);
        assert_eq!(
            fixture
                .store
                .read()
                .unwrap()
                .scan_cursor()
                .unwrap()
                .unwrap()
                .height,
            3
        );
    }

    #[tokio::test]
    async fn shutdown_rejects_queued_commands_and_locks_after_running_work() {
        let fixture = Fixture::new();
        let host = fixture.host().unwrap();
        restore_and_unlock(&host).await;
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let command_host = host.clone();
        let command = tokio::spawn(async move {
            command_host
                .call(move |engine| {
                    entered_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    engine.status()
                })
                .await
        });
        entered_rx.await.unwrap();
        let mut queued = Vec::new();
        for _ in 1..MAX_ADMITTED_COMMANDS {
            let queued_host = host.clone();
            queued.push(tokio::spawn(async move { queued_host.status().await }));
        }
        tokio::time::timeout(Duration::from_secs(5), async {
            while host.inner.admission.available_permits() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(matches!(
            host.lock().await,
            Err(WalletAdminError::RateLimited)
        ));
        host.begin_shutdown();
        assert!(matches!(
            host.lock().await,
            Err(WalletAdminError::ShuttingDown)
        ));
        let shutdown_host = host.clone();
        let shutdown = tokio::spawn(async move { shutdown_host.shutdown().await });
        release_tx.send(()).unwrap();
        assert!(command.await.unwrap().unwrap().is_unlocked);
        shutdown.await.unwrap().unwrap();
        for queued in queued {
            assert!(matches!(
                queued.await.unwrap(),
                Err(WalletAdminError::ShuttingDown)
            ));
        }
        assert!(!host.inner.engine.lock().status().unwrap().is_unlocked);
    }

    #[tokio::test]
    async fn shutdown_waits_for_replay_published_by_an_admitted_command() {
        let fixture = Fixture::new();
        let host = fixture.host().unwrap();
        restore_and_unlock(&host).await;
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (publish_tx, publish_rx) = std::sync::mpsc::channel();
        let (finish_tx, finish_rx) = tokio::sync::oneshot::channel();
        let command_host = host.clone();
        let owner = host.inner.clone();
        let command = tokio::spawn(async move {
            command_host
                .call(move |_| {
                    entered_tx.send(()).unwrap();
                    publish_rx.recv().unwrap();
                    // Rescan prepares under the writer and publishes its task
                    // before releasing it. Reproduce that publication boundary.
                    *owner.rescan_task.lock() = Some(tokio::spawn(async move {
                        finish_rx.await.unwrap();
                    }));
                    Ok(())
                })
                .await
        });
        entered_rx.await.unwrap();
        let shutdown_host = host.clone();
        let mut shutdown = tokio::spawn(async move { shutdown_host.shutdown().await });
        tokio::time::timeout(Duration::from_secs(5), async {
            while !host.inner.closing.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        publish_tx.send(()).unwrap();
        command.await.unwrap().unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut shutdown)
                .await
                .is_err()
        );
        finish_tx.send(()).unwrap();
        shutdown.await.unwrap().unwrap();
        assert!(!host.inner.engine.lock().status().unwrap().is_unlocked);
    }

    #[tokio::test]
    async fn panicked_command_closes_admission_and_locks_the_wallet() {
        let fixture = Fixture::new();
        let host = fixture.host().unwrap();
        restore_and_unlock(&host).await;
        assert!(matches!(
            host.call::<(), _>(|_| panic!("injected command failure"))
                .await,
            Err(WalletAdminError::Internal(_))
        ));
        assert!(matches!(
            host.status().await,
            Err(WalletAdminError::ShuttingDown)
        ));
        assert!(!host.inner.engine.lock().status().unwrap().is_unlocked);
    }
}
