//! RUST API router facade.

use std::sync::Arc;

use axum::routing::{get, post};
use axum::Router;
use ergo_ser::address::NetworkPrefix;

use crate::api_family::ApiFamily;
use crate::blockchain::{enforce_status_gate, BlockchainState};
use crate::traits::{NodeAdmin, NodeReadState};

use super::handlers::{
    difficulty_history_handler, events_handler, health_handler, host_handler, identity_handler,
    info_handler, miner_stats_handler, peers_handler, recent_blocks_handler, set_votes_handler,
    shutdown_handler, status_handler, sync_handler, tip_handler, votes_handler,
    votes_history_handler,
};

use super::route_registry::FamilyRouter;

pub(super) fn legacy_router(read: Arc<dyn NodeReadState>) -> FamilyRouter {
    FamilyRouter::new(ApiFamily::Rust)
        .route("/api/v1/info", "/api/v1/info", &["get"], get(info_handler))
        .route(
            "/api/v1/identity",
            "/api/v1/identity",
            &["get"],
            get(identity_handler),
        )
        .route("/api/v1/host", "/api/v1/host", &["get"], get(host_handler))
        .route(
            "/api/v1/status",
            "/api/v1/status",
            &["get"],
            get(status_handler),
        )
        .route(
            "/api/v1/votes",
            "/api/v1/votes",
            &["get"],
            get(votes_handler),
        )
        .route("/api/v1/tip", "/api/v1/tip", &["get"], get(tip_handler))
        .route(
            "/api/v1/blocks/recent",
            "/api/v1/blocks/recent",
            &["get"],
            get(recent_blocks_handler),
        )
        .route(
            "/api/v1/events",
            "/api/v1/events",
            &["get"],
            get(events_handler),
        )
        .route("/api/v1/sync", "/api/v1/sync", &["get"], get(sync_handler))
        .route(
            "/api/v1/peers",
            "/api/v1/peers",
            &["get"],
            get(peers_handler),
        )
        .route(
            "/api/v1/health",
            "/api/v1/health",
            &["get"],
            get(health_handler),
        )
        .with_state(read)
}

pub(super) fn admin_router(
    admin: Option<Arc<dyn NodeAdmin>>,
    security: Option<Arc<crate::auth::ApiSecurity>>,
) -> FamilyRouter {
    let Some(admin) = admin else {
        return FamilyRouter::new(ApiFamily::Rust);
    };
    let routes = FamilyRouter::new(ApiFamily::Rust)
        .route(
            "/api/v1/node/shutdown",
            "/api/v1/node/shutdown",
            &["post"],
            post(shutdown_handler),
        )
        .route(
            "/api/v1/votes",
            "/api/v1/votes",
            &["post"],
            post(set_votes_handler),
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

pub(super) fn conditional_chain_router(
    chain: Option<Arc<dyn crate::compat::NodeChainQuery>>,
    network: NetworkPrefix,
) -> FamilyRouter {
    let Some(chain) = chain else {
        return FamilyRouter::new(ApiFamily::Rust);
    };
    let miner_stats = FamilyRouter::new(ApiFamily::Rust)
        .route(
            "/api/v1/mining/minerStats",
            "/api/v1/mining/minerStats",
            &["get"],
            get(miner_stats_handler),
        )
        .with_state((chain.clone(), network));
    FamilyRouter::new(ApiFamily::Rust)
        .route(
            "/api/v1/difficulty/history",
            "/api/v1/difficulty/history",
            &["get"],
            get(difficulty_history_handler),
        )
        .route(
            "/api/v1/votes/history",
            "/api/v1/votes/history",
            &["get"],
            get(votes_history_handler),
        )
        .with_state(chain)
        .merge(miner_stats)
}

pub(super) fn indexer_router(state: BlockchainState) -> FamilyRouter {
    let always_open: FamilyRouter<BlockchainState> = FamilyRouter::new(ApiFamily::Rust)
        .route(
            "/api/v1/indexer/status",
            "/api/v1/indexer/status",
            &["get"],
            get(crate::blockchain::indexer_status_handler),
        )
        .route(
            "/api/v1/transactions/:tx_id/detail",
            "/api/v1/transactions/{txId}/detail",
            &["get"],
            get(crate::blockchain::tx_detail_handler),
        );

    let conditional: FamilyRouter<BlockchainState> = if state.chain_params.is_some() {
        FamilyRouter::new(ApiFamily::Rust)
            .route(
                "/blockchain/storageRent/eligibleAt/:height",
                "/blockchain/storageRent/eligibleAt/{height}",
                &["get"],
                get(crate::blockchain::storage_rent_eligible_handler),
            )
            .route(
                "/blockchain/storageRent/maturesAt/:height",
                "/blockchain/storageRent/maturesAt/{height}",
                &["get"],
                get(crate::blockchain::storage_rent_matures_at_handler),
            )
            .route(
                "/blockchain/storageRent/maturesInRange",
                "/blockchain/storageRent/maturesInRange",
                &["get"],
                get(crate::blockchain::storage_rent_matures_in_range_handler),
            )
            .route_layer(axum::middleware::from_fn_with_state(
                state.clone(),
                enforce_status_gate,
            ))
    } else {
        FamilyRouter::new(ApiFamily::Rust)
    };
    always_open.merge(conditional).with_state(state)
}

pub(super) fn wallet_router(
    wallet_admin: Arc<dyn crate::wallet::WalletAdmin>,
    security: Option<Arc<crate::auth::ApiSecurity>>,
) -> FamilyRouter {
    let operations = super::openapi_operations(&super::legacy_rust_openapi())
        .into_iter()
        .filter(|operation| operation.path.starts_with("/api/v1/wallet/"));
    FamilyRouter::new(ApiFamily::Rust).merge_documented(
        crate::wallet::native::router_with_security(wallet_admin, security),
        operations,
    )
}

pub(super) struct ProductRouterState {
    pub script: crate::v1::script::ScriptState,
    pub api: crate::v1::V1State,
    pub operator: crate::v1::OperatorState,
    pub accounts: crate::v1::AccountsState,
    pub webhooks: crate::v1::WebhooksState,
    pub governor: Arc<crate::v1::governor::Governor>,
    pub auth: Arc<crate::v1::auth::V1AuthConfig>,
}

pub(super) fn product_router(state: ProductRouterState) -> FamilyRouter {
    let router = Router::new()
        .merge(crate::v1::script::script_router(
            state.script,
            state.governor.clone(),
            state.auth.clone(),
        ))
        .merge(crate::v1::v1_router(
            state.api.clone(),
            state.governor.clone(),
        ))
        .merge(crate::v1::operator_router(
            state.operator,
            state.governor.clone(),
            state.auth.clone(),
        ))
        .merge(crate::v1::accounts_router(
            state.accounts,
            state.governor.clone(),
            state.auth.clone(),
        ))
        .merge(crate::v1::batch_router(state.api, state.governor))
        .merge(crate::v1::webhooks_router(state.webhooks, state.auth));
    let mut operations = super::openapi_operations(&super::v1_openapi_fragment());
    operations.extend(super::openapi::supplemental_rust_operations());
    FamilyRouter::new(ApiFamily::Rust).merge_documented(router, operations)
}
