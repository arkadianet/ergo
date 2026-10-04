//! Mining for the Ergo Rust node.
//!
//! Public surface:
//!
//! * [`MiningConfig`] / [`MiningError`] — node-level configuration and
//!   error types for the mining subsystem.
//!
//! External-miner work generation and submitted-solution verification; there
//! is no internal CPU miner or `/mining/candidateWithTxs` route. Reward keys
//! may come from a configured key or the wallet's EIP-3 first address. The
//! builder selects vote bytes from configured targets and handles supported
//! epoch boundaries. `offline_generation` permits the configured devnet
//! freshness exception; ordinary network mining requires a current applied tip.

pub mod candidate;
pub mod candidate_selection;
pub mod coinbase;
pub mod config;
pub mod emission_box;
pub mod emission_rules;
pub mod engine;
pub mod error;
pub mod extension_builder;
pub mod handle;
pub mod inspection;
mod outcome_journal;
pub mod policy;
pub mod private_queue;
pub mod reemission;
pub mod reward_script;
pub mod solution;
pub mod state_view;
pub mod storage_rent_claim;
pub mod submit;
pub mod tx_selection;
pub mod work_message;

pub use config::MiningConfig;
pub use emission_rules::{
    emission_at_height, miners_reward_at_height, MonetarySettings, COINS_IN_ONE_ERGO,
};
pub use error::MiningError;
pub use reward_script::{reward_output_script, reward_output_script_from_hex, REWARD_SCRIPT_LEN};

mod genesis;
mod policy_store;
