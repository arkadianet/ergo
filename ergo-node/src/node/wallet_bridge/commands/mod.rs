//! `run_wallet_writer` per-command handlers.
//!
//! Each `WalletCommand` variant has a dedicated `async fn` here so
//! the parent `wallet_bridge.rs` loop's match collapses to one-line
//! dispatch arms. Handlers take a `WriterContext` of borrowed
//! handles + the per-command params + the reply oneshot, do the
//! work, and send the result themselves. Each handler is a thin
//! relocation of an inline match arm, kept in a sibling submodule
//! for navigability.
//!
//! Grouping (3 files max per submodule):
//! - `admin` — lifecycle + read-side queries (15 variants):
//!   status, init, restore, rescan, unlock, lock, check,
//!   update_change_address, balances, addresses, boxes,
//!   boxes_unspent, transactions, transaction_by_id,
//!   transactions_by_scan_id.
//! - `send` — build / sign / submit (6 variants): payment_send,
//!   transaction_generate, transaction_generate_unsigned,
//!   transaction_sign, transaction_send, boxes_collect.
//! - `multisig` — commitments / hints + key derivation
//!   (5 variants): generate_commitments, extract_hints,
//!   derive_key, derive_next_key, get_private_key.

use std::sync::Arc;

use parking_lot::RwLock;

use ergo_wallet::state::WalletState;
use ergo_wallet::storage::SecretStorage;

use super::{ChainStateAccessor, TxSubmitter, WriterConfig};

// Re-export the `support::*` business-logic helpers the per-command
// handlers call, so each handler file gets a single one-level
// `super::<name>` path instead of `super::support::<submodule>::<name>`.
pub(super) use super::support::dto::{paginate_boxes, paginate_transactions, wallet_tx_to_entry};
pub(super) use super::support::generate_sign::{
    boxes_collect_impl, payment_send_impl, transaction_generate_impl,
    transaction_generate_unsigned_impl, transaction_sign_impl,
};
pub(super) use super::support::key_derivation::{
    derive_key_impl, derive_next_key_impl, get_private_key_impl, render_derivation_path,
};
pub(super) use super::support::multisig_helpers::{extract_hints_impl, generate_commitments_impl};
pub(super) use super::support::sign_submit::{
    send_transaction_native_impl, sign_transaction_native_impl,
};
pub(super) use super::support::sweep::retrieve_rewards_impl;
pub(super) use super::support::tx_build::{build_transaction_impl, select_boxes_impl};

pub(super) mod admin;
pub(super) mod multisig;
pub(super) mod scan;
pub(super) mod send;

/// Borrowed view of the writer-task's captured state. Built once per
/// loop iteration in `run_wallet_writer` and passed to whichever
/// handler the dispatch picks. Refs are cheap to copy; each handler
/// acquires the locks it needs at the granularity the arm previously
/// did inline.
pub(super) struct WriterContext<'a> {
    pub storage: &'a Arc<RwLock<SecretStorage>>,
    pub state: &'a Arc<RwLock<WalletState>>,
    pub db: &'a Arc<redb::Database>,
    pub chain: &'a Arc<dyn ChainStateAccessor>,
    pub cfg: &'a WriterConfig,
    pub submit_handle: &'a Arc<dyn TxSubmitter>,
    /// Snapshot-backed mempool view for the unconfirmed-balance overlay
    /// (`balances/withUnconfirmed`). Read-only; cheap per-call snapshot reads.
    pub mempool: &'a Arc<dyn ergo_api::MempoolView>,
}
