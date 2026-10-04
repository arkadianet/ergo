//! Wallet engine: the transport-neutral wallet orchestration shared by the
//! embedded node wallet and (in phase 3) the standalone wallet daemon.
//!
//! [`WalletEngine`] owns the wallet's secret storage, in-memory state, wallet
//! store and service-level seams, and exposes one method per wallet command
//! (lifecycle, reads, build / sign / send, reward sweep, multi-sig, key
//! derivation, `/scan/*`, rescan). Every method returns
//! `Result<_, WalletAdminError>`; methods are synchronous except the ones
//! that await submission, and the ones that change wallet state take
//! `&mut self`. The embedding process owns transport and task scheduling:
//! the node's single writer task owns the engine, calls these methods in
//! command order, and spawns a [`RescanJob`] on a blocking thread.
//!
//! The engine depends only on service-level seams, never on a node runtime:
//!
//! - [`chain`] — [`WalletChainAccess`] / [`SigningView`]: committed chain
//!   reads for signing, self-verify and rescan replay.
//! - [`mempool`] — [`MempoolOverlay`]: the pool reads behind the
//!   unconfirmed overlays and the reward sweep.
//! - [`submit`] — [`TxSubmitter`]: async submission with a typed
//!   [`TxSubmitError`].
//! - [`rescan`] — [`RescanCoordinator`]: per-wallet rescan fence flags and
//!   transition lock, shared with the chain-apply [`WalletStateHook`] and its
//!   rollback [`WalletRescanGuard`].
//! - [`config`] — [`WalletEngineConfig`]: network, operator flags, EIP-27
//!   rules and admission limits.
//!
//! Wallet logic modules:
//!
//! - `admin` — status, init / restore, unlock / lock, seed check, change
//!   address, and the failed-attempt budget.
//! - `reads` — compat and native balance / address / box / transaction
//!   reads.
//! - `build` — the shared burn-aware unsigned-tx builder + native
//!   `boxes/select` / `transactions/build`.
//! - `sign` — native `transactions/sign` + `transactions/send`, and the
//!   shared sign/self-verify/serialize building blocks.
//! - `send` — `PaymentSend` / `TransactionGenerate*` / `TransactionSign` /
//!   `TransactionSend` / `BoxesCollect` and the native send commands.
//! - `sweep` — the "retrieve matured mining rewards" sweep.
//! - `dto` — box/tx status strings, wallet-row → wire-entry projections,
//!   pagination.
//! - `multisig` — input/data-input resolution + `generateCommitments` /
//!   `extractHints`.
//! - `hints_codec` — `TransactionHintsBag` ↔ `TxHintsBagDto` JSON converters.
//! - `keys` — `deriveKey` / `deriveNextKey` / `getPrivateKey` and the
//!   unlock-time key derivation ([`WalletBootService`]).
//! - `scan` — the `/scan/*` registry, tracked-box reads and writes, and the
//!   rescan scan matcher.
//! - `hook` — [`WalletStateHook`], the chain-apply hook.

use std::sync::Arc;

use ergo_wallet::storage::SecretStorage;
use parking_lot::RwLock;

use crate::runtime::WalletService;
use crate::state::WalletState;
use crate::wallet::WalletStore;

mod admin;
mod build;
pub mod chain;
pub mod config;
mod dto;
mod hints_codec;
mod hook;
mod keys;
pub mod mempool;
mod multisig;
mod reads;
pub mod rescan;
mod scan;
mod scan_guard;
mod send;
mod sign;
pub mod submit;
mod sweep;

pub use chain::{map_chain_error, ChainAccessError, SigningView, WalletChainAccess};
pub use config::WalletEngineConfig;
pub use hook::WalletStateHook;
pub use keys::WalletBootService;
pub use mempool::{MempoolOverlay, NoopMempoolOverlay};
pub use rescan::{
    recover_interrupted_rescan, BeginRescanError, RescanCoordinator, RescanJob, WalletRescanGuard,
};
pub use submit::{map_submit_error, TxSubmitError, TxSubmitter};

/// Everything a [`WalletEngine`] is built from.
pub struct WalletEngineParts {
    /// Encrypted seed storage (locked / unlocked master key).
    pub storage: Arc<RwLock<SecretStorage>>,
    /// In-memory wallet projection, shared with the chain-apply hook.
    pub state: Arc<RwLock<WalletState>>,
    /// The persistent wallet store.
    pub store: Arc<dyn WalletStore>,
    /// Committed chain reads for signing, self-verify and rescan replay.
    pub chain: Arc<dyn WalletChainAccess>,
    pub config: WalletEngineConfig,
    /// Signed-transaction submission.
    pub submitter: Arc<dyn TxSubmitter>,
    /// Pool reads for the unconfirmed overlays and the reward sweep.
    pub mempool: Arc<dyn MempoolOverlay>,
    /// Runtime-backed reads and rescans when present; the store directly
    /// otherwise.
    pub service: Option<Arc<WalletService>>,
    /// The wallet's rescan coordinator, shared with the chain-apply hook.
    pub rescan: Arc<RescanCoordinator>,
}

/// The wallet orchestration core: one method per wallet command.
///
/// Single writer, enforced by the borrow checker: every command that writes
/// the secret storage, the in-memory state or the wallet store, claims a
/// rescan, or updates a failed-attempt budget takes `&mut self`, so it never
/// runs alongside any other command on the same engine. Read-only commands
/// take `&self`. The node's writer task owns its engine by value and runs
/// commands one at a time in arrival order. Locks are taken at the
/// granularity each command always used.
pub struct WalletEngine {
    storage: Arc<RwLock<SecretStorage>>,
    state: Arc<RwLock<WalletState>>,
    store: Arc<dyn WalletStore>,
    chain: Arc<dyn WalletChainAccess>,
    config: WalletEngineConfig,
    submitter: Arc<dyn TxSubmitter>,
    mempool: Arc<dyn MempoolOverlay>,
    service: Option<Arc<WalletService>>,
    rescan: Arc<RescanCoordinator>,
    /// Failed-attempt budget for `unlock` (see [`admin::AttemptLimiter`]).
    unlock_limiter: admin::AttemptLimiter,
    /// Failed-attempt budget for the seed `check` oracle.
    check_limiter: admin::AttemptLimiter,
}

impl WalletEngine {
    pub fn new(parts: WalletEngineParts) -> Self {
        let WalletEngineParts {
            storage,
            state,
            store,
            chain,
            config,
            submitter,
            mempool,
            service,
            rescan,
        } = parts;
        Self {
            storage,
            state,
            store,
            chain,
            config,
            submitter,
            mempool,
            service,
            rescan,
            unlock_limiter: admin::AttemptLimiter::new(),
            check_limiter: admin::AttemptLimiter::new(),
        }
    }

    /// The wallet's rescan coordinator (fence flags + transition lock).
    pub fn rescan_coordinator(&self) -> &Arc<RescanCoordinator> {
        &self.rescan
    }

    pub fn config(&self) -> &WalletEngineConfig {
        &self.config
    }

    /// Refuse commands that consume scan results while the durable history
    /// is invalidated. Status, recovery, keys and registry administration stay
    /// available independently of wallet history.
    fn require_valid_scan(&self) -> Result<(), ergo_wallet_protocol::WalletAdminError> {
        scan_guard::require_valid_scan(self.store.as_ref())
    }

    /// Whether the wallet is locked (no in-memory master key). Native
    /// build/select require an unlocked wallet and map `Locked` →
    /// `409 wallet_locked`.
    fn is_locked(&self) -> bool {
        self.storage.read().unlocked().is_none()
    }
}
