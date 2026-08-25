//! Single integration-test binary for this crate.
//!
//! Each former `tests/<name>.rs` is now `tests/it/<name>.rs` and is
//! declared here. One binary instead of one per file: the workspace
//! links each test binary against every rlib, so per-file binaries put
//! link time on the CI critical path. nextest still runs one process
//! per test, so isolation is unchanged.

mod compile_semantic_parity;
mod contract_template_parity;
mod corpus_smoke;
mod sigma_parser_spec;
mod sigma_typer_spec;
mod typer_oracle_parity;
