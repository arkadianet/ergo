//! Single integration-test binary for this crate.
//!
//! Each former `tests/<name>.rs` is now `tests/it/<name>.rs` and is
//! declared here. One binary instead of one per file: the workspace
//! links each test binary against every rlib, so per-file binaries put
//! link time on the CI critical path. nextest still runs one process
//! per test, so isolation is unchanged.

mod decode_mode_routing;
mod decode_scala_full_block;
mod decode_scala_header_roundtrip;
mod headers_json_scala_oracle;
mod nipopow_json_fixtures;
