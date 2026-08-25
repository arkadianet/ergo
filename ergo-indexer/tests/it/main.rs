//! Single integration-test binary for this crate.
//!
//! Each former `tests/<name>.rs` is now `tests/it/<name>.rs` and is
//! declared here. One binary instead of one per file: the workspace
//! links each test binary against every rlib, so per-file binaries put
//! link time on the CI critical path. nextest still runs one process
//! per test, so isolation is unchanged.

mod apply_block;
mod backfill_corpus;
mod error_taxonomy;
mod handle_boot;
mod handle_query;
mod rebuild;
mod reorg_depth;
mod reorg_spill;
mod reorg_token;
mod resume_contract;
mod rollback;
mod storage_rent_apply;
mod store_open;
mod task_step;
mod template_index;
mod token_index;
