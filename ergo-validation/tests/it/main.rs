//! Single integration-test binary for this crate.
//!
//! Each former `tests/<name>.rs` is now `tests/it/<name>.rs` and is
//! declared here. One binary instead of one per file: the workspace
//! links each test binary against every rlib, so per-file binaries put
//! link time on the CI critical path. nextest still runs one process
//! per test, so isolation is unchanged.

mod batch_merkle_oracle;
mod bridge_type_invariants;
mod chain_spec_parity;
mod context_headers_window_parity;
mod cost_parity;
mod cost_sanity;
mod cost_total_cross_epoch_oracle;
mod cost_total_oracle;
mod diagnose_block_303967;
mod diagnose_block_555672;
mod diagnose_block_836113;
mod divergence_b_oracle_parity;
mod epoch_boundary_extension_oracle;
mod eval_error_triage;
mod full_block_validation;
mod header_validation;
mod interlinks_packing_mainnet_corpus;
mod interlinks_proof_oracle;
mod negative_validation;
mod nipopow_proof_mainnet_roundtrip;
mod parity_triage;
mod popow_batch_merkle_scrypto_parity;
mod popow_header_mainnet_roundtrip;
mod popow_level_scala_parity;
mod popow_panic_freedom;
mod popow_scala_fixture_validation;
mod rejection_parity;
mod scala_full_block_pow_verify;
mod scala_rejection_parity;
mod trace_emission_700000;
mod trace_mismatch_889k;
mod tree_version_oracle_parity;
mod tx_triage_700000;
mod tx_validation_corpus;
mod vector_integrity;
mod votes_first_epoch_oracle;
