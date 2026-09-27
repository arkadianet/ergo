//! Wallet engine: the transport-neutral wallet orchestration shared by the
//! embedded node wallet and (in phase 3) the standalone wallet daemon.
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
//!   transition lock, shared with the chain-apply hook and the rollback
//!   [`WalletRescanGuard`].
//! - [`config`] — [`WalletEngineConfig`]: network, operator flags, EIP-27
//!   rules and admission limits.

pub mod chain;
pub mod config;
pub mod mempool;
pub mod rescan;
pub mod submit;

pub use chain::{map_chain_error, ChainAccessError, SigningView, WalletChainAccess};
pub use config::WalletEngineConfig;
pub use mempool::{MempoolOverlay, NoopMempoolOverlay};
pub use rescan::{BeginRescanError, RescanCoordinator, WalletRescanGuard};
pub use submit::{map_submit_error, TxSubmitError, TxSubmitter};
