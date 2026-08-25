//! Single integration-test binary for this crate.
//!
//! Each former `tests/<name>.rs` is now `tests/it/<name>.rs` and is
//! declared here. One binary instead of one per file: the workspace
//! links each test binary against every rlib, so per-file binaries put
//! link time on the CI critical path. nextest still runs one process
//! per test, so isolation is unchanged.

mod auction_divergence;
mod avl_scala_oracle_parity;
mod avl_verifier_panic_differential;
mod cost_trace_smoke;
mod dex_oracle_mainnet;
mod dht_synthetic;
mod emission_contract_mainnet;
mod mining_reward_mainnet;
mod schnorr_mainnet;
mod sigma_composition;
mod spending_proof_mainnet;
mod traced_untraced_parity;
mod treasury_contract_mainnet;
mod tuple_register_eval_divergence;
mod v6_unsigned_bigint_oracle;
