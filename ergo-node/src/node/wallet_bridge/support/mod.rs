//! Business-logic helpers `run_wallet_writer`'s per-command handlers
//! (`commands/*`) delegate into. Each submodule mirrors one or more
//! `commands/*.rs` files:
//!
//! - `tx_build` — the shared burn-aware unsigned-tx builder + native
//!   `boxes/select` / `transactions/build`.
//! - `sign_submit` — native `transactions/sign` + `transactions/send`, and
//!   the shared sign/self-verify/serialize building blocks.
//! - `generate_sign` — `PaymentSend` / `TransactionGenerate*` /
//!   `TransactionSign` / `BoxesCollect`.
//! - `sweep` — the "retrieve matured mining rewards" sweep.
//! - `dto` — box/tx status strings, wallet-row → wire-entry projections,
//!   pagination.
//! - `multisig_helpers` — input/data-input resolution + `generateCommitments`
//!   / `extractHints`.
//! - `hints_codec` — `TransactionHintsBag` ↔ `TxHintsBagDto` JSON converters.
//! - `key_derivation` — `deriveKey` / `deriveNextKey` / `getPrivateKey`.

pub(crate) mod dto;
pub(crate) mod generate_sign;
pub(crate) mod hints_codec;
pub(crate) mod key_derivation;
pub(crate) mod multisig_helpers;
pub(crate) mod sign_submit;
pub(crate) mod sweep;
pub(crate) mod tx_build;
