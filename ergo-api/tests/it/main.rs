//! Single integration-test binary for this crate.
//!
//! Each former `tests/<name>.rs` is now `tests/it/<name>.rs` and is
//! declared here. One binary instead of one per file: the workspace
//! links each test binary against every rlib, so per-file binaries put
//! link time on the CI critical path. nextest still runs one process
//! per test, so isolation is unchanged.

mod api_family_inventory;
mod auth;
mod blockchain_balance_routes;
mod blockchain_block_routes;
mod blockchain_box_range_route;
mod blockchain_box_routes;
mod blockchain_byaddress_routes;
mod blockchain_byergotree_routes;
mod blockchain_indexed_height;
mod blockchain_scala_parity;
mod blockchain_template_routes;
mod blockchain_token_routes;
mod blockchain_transaction_range_route;
mod blockchain_tx_routes;
mod blockchain_unspent_byaddress_routes;
mod blocks_at_parity;
mod blocks_header_ids_parity;
mod blocks_id_parity;
mod blocks_modifier_parity;
mod blocks_proof_for_tx_parity;
mod boundary;
mod compat_blocks_submit_route;
mod compat_submit_routes;
mod difficulty_history_route;
mod events_endpoint;
mod extra_index_router_walk;
mod host_schema;
mod identity_schema;
mod indexer_status_endpoint;
mod mempool_overlay_oracle;
mod mempool_source_schema;
mod metrics_gauges;
mod miner_stats_route;
mod mining_auth_gate;
mod nipopow_routes_parity;
mod openapi_native_runtime_mount;
mod openapi_native_snapshot;
mod openapi_v1_snapshot;
mod recent_blocks_route;
mod router_layout;
mod scala_parity;
mod scan_routes;
mod script_address_routes;
mod script_compile_routes;
mod serve_shutdown;
mod storage_rent_assets_route;
mod submit_routes;
mod track_b_touch_surface;
mod tx_hints_bag_dto_roundtrip;
mod utils_routes;
mod v1_batch_routes;
mod v1_boxes_tokens_addresses_routes;
mod v1_chain_tx_routes;
mod v1_light_stats_diag_routes;
mod v1_mempool_routes;
mod v1_operator_routes;
mod v1_prices_routes;
mod v1_scan_accounts_routes;
mod v1_script_routes;
mod wallet_lock_matrix;
mod wallet_reads;
mod wallet_send_oracle;
mod wallet_state_mut;
mod wallet_status;
mod wallet_stubs;
mod wallet_ui_auth_scope;
mod wallet_ui_headers;
mod wallet_ui_two_step_unlock;
