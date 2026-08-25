//! Single integration-test binary for this crate.
//!
//! Each former `tests/<name>.rs` is now `tests/it/<name>.rs` and is
//! declared here. One binary instead of one per file: the workspace
//! links each test binary against every rlib, so per-file binaries put
//! link time on the CI critical path. nextest still runs one process
//! per test, so isolation is unchanged.

mod ad_proofs_root_oracle;
mod avl_cold_restart;
mod avl_format_compat;
mod avl_labels_oracle;
mod avl_root_digest_reads;
mod before_image_undo;
mod bootstrap_pruning_sentinel;
mod branch_invalidation;
mod cached_disk_arena;
mod chain_storage_reorg;
mod chain_validate_1_1000;
mod committed_snapshot_parity;
mod cost_parity_oracle_voted_params;
mod data_dir_state_type_sentinel;
mod diff_tx_diff_since;
mod digest_chain_1_1000;
mod digest_chain_1_200;
mod error_variants;
mod full_block_700k;
mod full_block_with_state;
mod genesis_digest;
mod header_chain_index;
mod headers_by_height;
mod last_applied_chain_window;
mod miner_reward_oracle;
mod minimal_full_block_height_lifecycle;
mod mode2_trust_lifecycle;
mod modifier_type_index;
mod multi_tx_ordering;
mod persistent_blocks_1_10;
mod popow_apply;
mod popow_header_persisted_accessor;
mod popow_prove_mainnet;
mod prune_eviction_pipeline_oracle;
mod prune_eviction_sync_oracle;
mod prune_formula_scala_oracle;
mod prune_phase3a_phase4_guards;
mod reader_lookup_box;
mod scan_rescan;
mod storage_observability;
mod utxo_view_integration;
mod validation_settings_cache;
mod voted_params_lifecycle;
mod wallet_apply_basic;
mod wallet_chain_integration;
mod wallet_maturity;
mod wallet_rescan_partial;
mod wallet_tables_basic;
mod write_txn_routing;
