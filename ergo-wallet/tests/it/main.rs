//! Single integration-test binary for this crate.
//!
//! Each former `tests/<name>.rs` is now `tests/it/<name>.rs` and is
//! declared here. One binary instead of one per file: the workspace
//! links each test binary against every rlib, so per-file binaries put
//! link time on the CI critical path. nextest still runs one process
//! per test, so isolation is unchanged.

mod aes_gcm_pbkdf2_oracle;
mod bip32_oracle;
mod bip39_oracle;
mod box_selection_oracle;
mod cli_smoke;
mod ergo_p2pk_address_oracle;
mod hints_bag_basic;
mod multi_sig_oracle;
mod node_position_basic;
mod pre_1627_derivation_oracle;
mod pre_eip3_path_oracle;
mod proving_scala_oracle;
mod secret_registry_basic;
mod storage_oracle;
mod tx_builder_oracle;
