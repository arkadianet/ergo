//! Single integration-test binary for this crate.
//!
//! Each former `tests/<name>.rs` is now `tests/it/<name>.rs` and is
//! declared here. One binary instead of one per file: the workspace
//! links each test binary against every rlib, so per-file binaries put
//! link time on the CI critical path. nextest still runs one process
//! per test, so isolation is unchanged.

mod boxes_roundtrip;
mod ergotrees_roundtrip;
mod headers_roundtrip;
mod nipopow_scala_oracle;
mod roundtrip_triage;
mod sbigint_cap_oracle;
mod sigma_type_golden;
mod stypevar_utf8_parity;
mod transactions_roundtrip;
