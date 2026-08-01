//! Scala API router facade.

use std::sync::Arc;

use axum::routing::{get, head, post};
use axum::Router;
use ergo_ser::address::NetworkPrefix;

use crate::api_family::ApiFamily;
use crate::blockchain::{
    balance_for_address_handler, balance_post_handler, block_by_header_id_handler,
    blocks_by_header_ids_handler, box_by_id_handler, box_by_index_handler, box_range_get_handler,
    box_range_post_handler, boxes_by_address_get_handler, boxes_by_address_post_handler,
    boxes_by_ergo_tree_post_handler, boxes_by_template_hash_handler, boxes_by_token_id_handler,
    boxes_unspent_by_address_get_handler, boxes_unspent_by_address_post_handler,
    boxes_unspent_by_ergo_tree_post_handler, boxes_unspent_by_template_hash_handler,
    boxes_unspent_by_token_id_handler, enforce_status_gate, indexed_height_handler,
    token_by_id_handler, tokens_by_ids_handler, transaction_range_get_handler,
    transaction_range_post_handler, tx_by_id_handler, tx_by_index_handler,
    txs_by_address_get_handler, txs_by_address_post_handler, BlockchainState,
};
use crate::compat::handlers::{
    block_by_id_handler, block_by_ids_handler, block_ids_at_height_handler,
    block_transactions_by_id_handler, chain_slice_handler, header_by_id_handler,
    header_ids_paged_handler, info_handler, last_headers_handler, modifier_by_id_handler,
    nipopow_header_by_height_handler, nipopow_header_by_id_handler, nipopow_proof_at_handler,
    nipopow_proof_handler, peers_all_handler, peers_connected_handler, pool_contains_handler,
    pool_tx_ids_handler, proof_for_tx_handler,
};
use crate::compat::NodeChainQuery;
use crate::traits::{NodeAdmin, NodeSubmit};

use super::handlers::{peers_connect_handler, shutdown_handler};
use super::route_registry::FamilyRouter;

pub(super) fn admin_router(
    admin: Option<Arc<dyn NodeAdmin>>,
    security: Option<Arc<crate::auth::ApiSecurity>>,
) -> FamilyRouter {
    let Some(admin) = admin else {
        return FamilyRouter::new(ApiFamily::Scala);
    };
    let routes = FamilyRouter::new(ApiFamily::Scala)
        .route(
            "/node/shutdown",
            "/node/shutdown",
            &["post"],
            post(shutdown_handler),
        )
        .route(
            "/peers/connect",
            "/peers/connect",
            &["post"],
            post(peers_connect_handler),
        )
        .route(
            "/node",
            "/node",
            &[],
            axum::routing::any(crate::auth::unknown_gated_subpath),
        )
        .route(
            "/node/*rest",
            "/node/{rest}",
            &[],
            axum::routing::any(crate::auth::unknown_gated_subpath),
        )
        .with_state(admin);
    match security {
        Some(security) => routes.route_layer(axum::middleware::from_fn_with_state(
            security,
            crate::auth::require_api_key,
        )),
        None => routes,
    }
}

pub(super) fn auxiliary_router(
    network: NetworkPrefix,
    wallet_admin: Arc<dyn crate::wallet::WalletAdmin>,
    mining: Option<Arc<dyn crate::mining::NodeMining>>,
    emission: Option<Arc<dyn crate::emission::EmissionSchedule>>,
    emission_scripts: Option<Arc<crate::emission::EmissionScriptsJson>>,
) -> FamilyRouter {
    let documented = super::scala_openapi_operations();
    let mut operations = std::collections::BTreeSet::new();
    let mut router = Router::new();
    if let Some(mining) = mining {
        router = router.merge(crate::mining::mining_router(mining));
        operations.extend(
            documented
                .iter()
                .filter(|operation| operation.path.starts_with("/mining/"))
                .cloned(),
        );
    }
    if let Some(emission) = emission {
        router = router.merge(crate::emission::emission_router(emission));
        operations.extend(
            documented
                .iter()
                .filter(|operation| operation.path == "/emission/at/{blockHeight}")
                .cloned(),
        );
    }
    if let Some(scripts) = emission_scripts {
        router = router.merge(crate::emission::emission_scripts_router(scripts));
        operations.extend(
            documented
                .iter()
                .filter(|operation| operation.path == "/emission/scripts")
                .cloned(),
        );
    }

    let utilities: Router<NetworkPrefix> = Router::new()
        .route("/utils/seed", get(crate::utils::seed_default_handler))
        .route(
            "/utils/seed/:length",
            get(crate::utils::seed_length_handler),
        )
        .route(
            "/utils/hash/blake2b",
            post(crate::utils::hash_blake2b_handler),
        )
        .route(
            "/utils/rawToAddress/:pubkey_hex",
            get(crate::utils::raw_to_address_handler),
        )
        .route(
            "/utils/addressToRaw/:address",
            get(crate::utils::address_to_raw_handler),
        )
        .route(
            "/utils/address/:address",
            get(crate::utils::validate_address_get_handler),
        )
        .route(
            "/utils/address",
            post(crate::utils::validate_address_post_handler),
        )
        .route(
            "/utils/ergoTreeToAddress/:tree_hex",
            get(crate::utils::ergo_tree_to_address_get_handler),
        )
        .route(
            "/utils/ergoTreeToAddress",
            post(crate::utils::ergo_tree_to_address_post_handler),
        )
        .route(
            "/script/addressToTree/:address",
            get(crate::utils::script_address_to_tree_handler),
        )
        .route(
            "/script/addressToBytes/:address",
            get(crate::utils::script_address_to_bytes_handler),
        );
    let scripts: Router<(NetworkPrefix, Arc<dyn crate::wallet::WalletAdmin>)> = Router::new()
        .route(
            "/script/p2sAddress",
            post(crate::script::p2s_address_handler),
        )
        .route(
            "/script/p2shAddress",
            post(crate::script::p2sh_address_handler),
        );
    operations.extend(
        documented
            .iter()
            .filter(|operation| {
                operation.path.starts_with("/utils/") || operation.path.starts_with("/script/")
            })
            .cloned(),
    );
    FamilyRouter::new(ApiFamily::Scala).merge_documented(
        router
            .merge(utilities.with_state(network))
            .merge(scripts.with_state((network, wallet_admin))),
        operations,
    )
}

pub(super) fn indexer_router(state: BlockchainState) -> FamilyRouter {
    let always_open: FamilyRouter<BlockchainState> = FamilyRouter::new(ApiFamily::Scala).route(
        "/blockchain/indexedHeight",
        "/blockchain/indexedHeight",
        &["get"],
        get(indexed_height_handler),
    );
    let mut gated: FamilyRouter<BlockchainState> = FamilyRouter::new(ApiFamily::Scala)
        .route(
            "/blockchain/box/byId/:box_id",
            "/blockchain/box/byId/{boxId}",
            &["get"],
            get(box_by_id_handler),
        )
        .route(
            "/blockchain/box/byIndex/:n",
            "/blockchain/box/byIndex/{boxIndex}",
            &["get"],
            get(box_by_index_handler),
        )
        .route(
            "/blockchain/balance",
            "/blockchain/balance",
            &["post"],
            post(balance_post_handler),
        )
        .route(
            "/blockchain/balanceForAddress/:address",
            "/blockchain/balanceForAddress/{address}",
            &["get"],
            get(balance_for_address_handler),
        )
        .route(
            "/blockchain/box/byAddress",
            "/blockchain/box/byAddress",
            &["post"],
            post(boxes_by_address_post_handler),
        )
        .route(
            "/blockchain/box/byAddress/:address",
            "/blockchain/box/byAddress/{address}",
            &["get"],
            get(boxes_by_address_get_handler),
        )
        .route(
            "/blockchain/box/unspent/byAddress",
            "/blockchain/box/unspent/byAddress",
            &["post"],
            post(boxes_unspent_by_address_post_handler),
        )
        .route(
            "/blockchain/box/unspent/byAddress/:address",
            "/blockchain/box/unspent/byAddress/{address}",
            &["get"],
            get(boxes_unspent_by_address_get_handler),
        )
        .route(
            "/blockchain/box/byErgoTree",
            "/blockchain/box/byErgoTree",
            &["post"],
            post(boxes_by_ergo_tree_post_handler),
        )
        .route(
            "/blockchain/box/unspent/byErgoTree",
            "/blockchain/box/unspent/byErgoTree",
            &["post"],
            post(boxes_unspent_by_ergo_tree_post_handler),
        )
        .route(
            "/blockchain/box/byTemplateHash/:hash",
            "/blockchain/box/byTemplateHash/{hash}",
            &["get"],
            get(boxes_by_template_hash_handler),
        )
        .route(
            "/blockchain/box/unspent/byTemplateHash/:hash",
            "/blockchain/box/unspent/byTemplateHash/{hash}",
            &["get"],
            get(boxes_unspent_by_template_hash_handler),
        )
        .route(
            "/blockchain/token/byId/:token_id",
            "/blockchain/token/byId/{tokenId}",
            &["get"],
            get(token_by_id_handler),
        )
        .route(
            "/blockchain/tokens",
            "/blockchain/tokens",
            &["post"],
            post(tokens_by_ids_handler),
        )
        .route(
            "/blockchain/box/byTokenId/:token_id",
            "/blockchain/box/byTokenId/{tokenId}",
            &["get"],
            get(boxes_by_token_id_handler),
        )
        .route(
            "/blockchain/box/unspent/byTokenId/:token_id",
            "/blockchain/box/unspent/byTokenId/{tokenId}",
            &["get"],
            get(boxes_unspent_by_token_id_handler),
        );
    if state.chain.is_some() {
        gated = gated
            .route(
                "/blockchain/transaction/byId/:tx_id",
                "/blockchain/transaction/byId/{txId}",
                &["get"],
                get(tx_by_id_handler),
            )
            .route(
                "/blockchain/transaction/byIndex/:n",
                "/blockchain/transaction/byIndex/{txIndex}",
                &["get"],
                get(tx_by_index_handler),
            )
            .route(
                "/blockchain/transaction/byAddress",
                "/blockchain/transaction/byAddress",
                &["post"],
                post(txs_by_address_post_handler),
            )
            .route(
                "/blockchain/transaction/byAddress/:address",
                "/blockchain/transaction/byAddress/{address}",
                &["get"],
                get(txs_by_address_get_handler),
            )
            .route(
                "/blockchain/transaction/range",
                "/blockchain/transaction/range",
                &["get", "post"],
                get(transaction_range_get_handler).post(transaction_range_post_handler),
            )
            .route(
                "/blockchain/box/range",
                "/blockchain/box/range",
                &["get", "post"],
                get(box_range_get_handler).post(box_range_post_handler),
            )
            .route(
                "/blockchain/block/byHeaderId/:header_id",
                "/blockchain/block/byHeaderId/{headerId}",
                &["get"],
                get(block_by_header_id_handler),
            )
            .route(
                "/blockchain/block/byHeaderIds",
                "/blockchain/block/byHeaderIds",
                &["post"],
                post(blocks_by_header_ids_handler),
            );
    }
    let gated = gated.route_layer(axum::middleware::from_fn_with_state(
        state.clone(),
        enforce_status_gate,
    ));
    always_open.merge(gated).with_state(state)
}

pub(super) fn compat_read_router(
    chain: Arc<dyn NodeChainQuery>,
    utxo_reads_supported: bool,
) -> FamilyRouter {
    let router = Router::new()
        .route("/info", get(info_handler))
        .route("/blocks", get(header_ids_paged_handler))
        .route("/blocks/at/:height", get(block_ids_at_height_handler))
        .route("/blocks/chainSlice", get(chain_slice_handler))
        .route("/blocks/lastHeaders/:count", get(last_headers_handler))
        .route("/blocks/headerIds", post(block_by_ids_handler))
        .route("/blocks/modifier/:modifier_id", get(modifier_by_id_handler))
        .route("/blocks/:header_id", get(block_by_id_handler))
        .route("/blocks/:header_id/header", get(header_by_id_handler))
        .route(
            "/blocks/:header_id/transactions",
            get(block_transactions_by_id_handler),
        )
        .route(
            "/blocks/:header_id/proofFor/:tx_id",
            get(proof_for_tx_handler),
        )
        .route(
            "/nipopow/popowHeaderById/:header_id",
            get(nipopow_header_by_id_handler),
        )
        .route(
            "/nipopow/popowHeaderByHeight/:height",
            get(nipopow_header_by_height_handler),
        )
        .route("/nipopow/proof/:m/:k", get(nipopow_proof_handler))
        .route(
            "/nipopow/proof/:m/:k/:header_id",
            get(nipopow_proof_at_handler),
        )
        .merge(super::scala_utxo_subtree(utxo_reads_supported))
        .route("/peers/all", get(peers_all_handler))
        .route("/peers/connected", get(peers_connected_handler))
        .route(
            "/peers/blacklisted",
            get(crate::compat::handlers::peers_blacklisted_handler),
        )
        .route(
            "/peers/status",
            get(crate::compat::handlers::peers_status_handler),
        )
        .route(
            "/peers/syncInfo",
            get(crate::compat::handlers::peers_sync_info_handler),
        )
        .route(
            "/peers/trackInfo",
            get(crate::compat::handlers::peers_track_info_handler),
        )
        .route(
            "/transactions/unconfirmed/transactionIds",
            get(pool_tx_ids_handler),
        )
        .route(
            "/transactions/unconfirmed/:tx_id",
            head(pool_contains_handler)
                .get(crate::compat::handlers::pool_contains_get_hint_handler),
        )
        .route(
            "/transactions/unconfirmed",
            get(crate::compat::handlers::pool_txs_paged_handler),
        )
        .route(
            "/transactions/unconfirmed/byTransactionId/:tx_id",
            get(crate::compat::handlers::pool_tx_by_id_handler),
        )
        .route(
            "/transactions/unconfirmed/byTransactionIds",
            post(crate::compat::handlers::pool_txs_by_ids_handler),
        )
        .route(
            "/transactions/unconfirmed/size",
            get(crate::compat::handlers::pool_size_handler),
        )
        .route(
            "/transactions/unconfirmed/byErgoTree",
            post(crate::compat::handlers::pool_txs_by_ergo_tree_handler),
        )
        .route(
            "/transactions/unconfirmed/byBoxId",
            post(crate::compat::handlers::pool_txs_by_box_id_handler),
        )
        .route(
            "/transactions/unconfirmed/byTokenId",
            post(crate::compat::handlers::pool_txs_by_token_id_handler),
        )
        .route(
            "/transactions/unconfirmed/byRegisters",
            post(crate::compat::handlers::pool_txs_by_registers_handler),
        )
        .route(
            "/transactions/poolHistogram",
            get(crate::compat::handlers::pool_fee_histogram_handler),
        )
        .route(
            "/transactions/getFee",
            get(crate::compat::handlers::pool_recommended_fee_handler),
        )
        .route(
            "/transactions/waitTime",
            get(crate::compat::handlers::pool_wait_time_handler),
        )
        .with_state(chain);
    let excluded = [
        super::RouteOperation::new("/blocks", "post"),
        super::RouteOperation::new("/transactions", "post"),
        super::RouteOperation::new("/transactions/check", "post"),
        super::RouteOperation::new("/transactions/bytes", "post"),
        super::RouteOperation::new("/transactions/checkBytes", "post"),
        super::RouteOperation::new("/peers/connect", "post"),
    ];
    let operations = super::scala_openapi_operations()
        .into_iter()
        .filter(|operation| {
            (operation.path == "/info"
                || operation.path.starts_with("/blocks")
                || operation.path.starts_with("/nipopow/")
                || operation.path.starts_with("/utxo/")
                || operation.path.starts_with("/peers/")
                || operation.path.starts_with("/transactions/"))
                && !excluded.contains(operation)
        });
    FamilyRouter::new(ApiFamily::Scala).merge_documented(router, operations)
}

pub(super) fn compat_write_router(submit: Arc<dyn NodeSubmit>) -> FamilyRouter {
    FamilyRouter::new(ApiFamily::Scala)
        .route(
            "/transactions/bytes",
            "/transactions/bytes",
            &["post"],
            post(crate::compat::transactions::submit_bytes_handler),
        )
        .route(
            "/transactions/checkBytes",
            "/transactions/checkBytes",
            &["post"],
            post(crate::compat::transactions::check_bytes_handler),
        )
        .route(
            "/transactions",
            "/transactions",
            &["post"],
            post(crate::compat::transactions::submit_handler),
        )
        .route(
            "/transactions/check",
            "/transactions/check",
            &["post"],
            post(crate::compat::transactions::check_handler),
        )
        .route(
            "/blocks",
            "/blocks",
            &["post"],
            post(crate::compat::blocks::submit_handler),
        )
        .with_state(submit)
}

pub(super) fn wallet_router(
    wallet_admin: Arc<dyn crate::wallet::WalletAdmin>,
    security: Option<Arc<crate::auth::ApiSecurity>>,
) -> FamilyRouter {
    let router = super::wallet_ui_router()
        .merge(crate::wallet::router_with_security(wallet_admin, security));
    let operations = super::scala_openapi_operations()
        .into_iter()
        .filter(|operation| {
            operation.path.starts_with("/wallet/") || operation.path.starts_with("/scan/")
        });
    FamilyRouter::new(ApiFamily::Scala).merge_documented(router, operations)
}
