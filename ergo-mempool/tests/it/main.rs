//! Single integration-test binary for this crate.
//!
//! Each former `tests/<name>.rs` is now `tests/it/<name>.rs` and is
//! declared here. One binary instead of one per file: the workspace
//! links each test binary against every rlib, so per-file binaries put
//! link time on the CI critical path. nextest still runs one process
//! per test, so isolation is unchanged.

mod admit_span;
mod m7_mainnet_corpus;
mod m7_ordering_oracle;
mod m7_pending_tx_cost;
mod m7_scala_oracle;
mod mempool_lifecycle;
mod observer;
