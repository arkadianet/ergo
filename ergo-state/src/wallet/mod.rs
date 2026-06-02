//! Wallet persistence layer per spec §7.1.
//!
//! Tables live in the SAME `state.redb` as chain state. Atomicity
//! with chain mutations depends on the apply path:
//!
//! - **Synchronous forward apply**: wallet writes land inside the
//!   same redb write_txn as AVL/undo/chain_index/state_meta in
//!   `persist_apply`. Truly atomic.
//! - **Pipeline forward apply**: chain is queued + drained durably,
//!   then wallet commits on a separate write_txn. Two-commit;
//!   failure mode "wallet behind chain" recoverable via rescan-on-
//!   restart. M5 final-slice work extends `PersistJob` so the
//!   worker consumes wallet writes atomically too.
//! - **Rollback (both paths)**: chain rollback + wallet rollback
//!   share a single write_txn in `persist_rollback`. Atomic.
//!
//! The `tables` submodule defines the redb `TableDefinition`
//! constants; `types` defines the value structs; `apply` and
//! `maturity` contain the chain-hook logic; `reader` exposes the
//! read-only interface the REST layer uses.

pub mod apply;
pub mod hydration;
pub mod maturity;
pub mod miner_reward;
pub mod reader;
pub mod scan;
pub mod tables;
pub mod types;

/// Bump on every breaking change to any wallet table's key or
/// value encoding. The migration policy is "wallet/scan_height = 0,
/// trigger a full rescan from genesis". Wallet data is derivable
/// from chain state, so any schema break is recoverable; we just
/// rescan.
pub const WALLET_SCHEMA_VERSION: u32 = 1;

pub use apply::RescanGuard;
pub use hydration::{HydrationSource, WalletApplyHook};
pub use reader::{RewardKeyResolution, WalletReader};
pub use types::{Balance, BoxProvenance, BoxStatus, WalletBox, WalletTransaction};

/// Bundle of wallet-side dependencies threaded through the chain-
/// apply / chain-rollback paths. Carries the apply hook (snapshot of
/// tracked-pubkey state at block-apply time) plus the rescan guard
/// (aborts an in-progress rescan atomically with rollback). Both
/// references live on the main thread; this struct is short-lived
/// and never crosses the persist-pipeline worker boundary.
#[derive(Copy, Clone)]
pub struct WalletWiring<'a> {
    pub hook: &'a dyn WalletApplyHook,
    pub rescan_guard: &'a dyn RescanGuard,
}
