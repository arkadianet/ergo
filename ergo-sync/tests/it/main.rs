//! Single integration-test binary for this crate.
//!
//! Each former `tests/<name>.rs` is now `tests/it/<name>.rs` and is
//! declared here. One binary instead of one per file: the workspace
//! links each test binary against every rlib, so per-file binaries put
//! link time on the CI critical path. nextest still runs one process
//! per test, so isolation is unchanged.

mod boundary_tests;
mod header_index_startup;
mod header_pk_curve_check;
mod header_sync_integration;
mod hydration_error_propagation;
mod mode5_executor_replay;
mod mode5_genesis_block;
mod prune_e2e_activation;
mod restart_benchmark;
