//! Single integration-test binary for this crate.
//!
//! Each former `tests/<name>.rs` is now `tests/it/<name>.rs` and is
//! declared here. One binary instead of one per file: the workspace
//! links each test binary against every rlib, so per-file binaries put
//! link time on the CI critical path. nextest still runs one process
//! per test, so isolation is unchanged.

mod common;
mod identity_live_refresh;
mod mining_e2e;
mod mode4_acceptance;
mod mode4_boot_refusal;
mod mode_runtime_gate;
mod submit_e2e;
mod wallet_admin_roundtrip;
mod wallet_e2e_helpers;
mod wallet_restart_parity;
mod wallet_send_e2e;
