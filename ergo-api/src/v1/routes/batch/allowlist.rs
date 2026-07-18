//! The closed batch allow-list: a mechanical manifest of every
//! `(method, path template)` pair `POST /api/v1/batch` may dispatch,
//! registered via the `route!` macro on BOTH the restricted dispatch
//! router and the classification table in one call so the two can never
//! drift apart. Dispatch/handler logic lives in [`super::dispatch`].

use axum::{
    http::Method,
    routing::{get, post},
    Router,
};

use super::super::{
    addresses, boxes, chain, decode, diagnostics, light, mempool, stats, tokens, transactions,
    tx_intel, V1State,
};
use super::dispatch::AllowedRoute;
use crate::v1::governor::RouteClass;

/// Registers one allow-listed route on BOTH the restricted dispatch
/// [`Router`] and the classification table in a single call, so the two can
/// never drift apart (the risk a hand-duplicated second list would carry).
macro_rules! route {
    ($router:expr, $table:expr, GET, $path:expr, $class:expr, $handler:expr) => {{
        $table.push(AllowedRoute {
            method: Method::GET,
            template: $path,
            class: $class,
        });
        $router = $router.route($path, get($handler));
    }};
    ($router:expr, $table:expr, POST, $path:expr, $class:expr, $handler:expr) => {{
        $table.push(AllowedRoute {
            method: Method::POST,
            template: $path,
            class: $class,
        });
        $router = $router.route($path, post($handler));
    }};
}

/// Build the restricted dispatch router + its parallel classification table.
/// Every route here is a SECOND mount of a handler already wired in
/// [`super::v1_router`] — copied verbatim, minus the submit-domain / build /
/// simulate / WS / script / webhooks surfaces this module's docs enumerate.
pub(super) fn allowed_routes() -> (Router<V1State>, Vec<AllowedRoute>) {
    use RouteClass::{CheapRead, HeavyRead};

    let mut table: Vec<AllowedRoute> = Vec::new();
    let mut router: Router<V1State> = Router::new();

    // ----- cheap point reads / discovery -----
    route!(
        router,
        table,
        GET,
        "/api/v1/boxes/:box_id",
        CheapRead,
        boxes::box_by_id
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/tokens/:token_id",
        CheapRead,
        tokens::token_by_id
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/mempool/summary",
        CheapRead,
        mempool::summary
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/mempool/transactions/:tx_id",
        CheapRead,
        mempool::transaction_by_id
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/mempool/fee-histogram",
        CheapRead,
        mempool::fee_histogram
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/protocols",
        CheapRead,
        decode::list_protocols
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/protocols/:protocol_id",
        CheapRead,
        decode::protocol_by_id
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/light/status",
        CheapRead,
        light::status
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/diagnostics",
        CheapRead,
        diagnostics::composite
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/diagnostics/chain-position",
        CheapRead,
        diagnostics::chain_position
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/diagnostics/fork-risk",
        CheapRead,
        diagnostics::fork_risk
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/diagnostics/tip-health",
        CheapRead,
        diagnostics::tip_health
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/diagnostics/peer-quality",
        CheapRead,
        diagnostics::peer_quality
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/diagnostics/candidate-build",
        CheapRead,
        diagnostics::candidate_build
    );

    // ----- chain/* -----
    route!(
        router,
        table,
        GET,
        "/api/v1/chain/blocks",
        HeavyRead,
        chain::list_blocks
    );
    route!(
        router,
        table,
        POST,
        "/api/v1/chain/blocks/by-ids",
        HeavyRead,
        chain::blocks_by_ids
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/chain/blocks/at-height/:height",
        HeavyRead,
        chain::blocks_at_height
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/chain/blocks/:header_id",
        HeavyRead,
        chain::block_by_id
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/chain/blocks/:header_id/transactions",
        HeavyRead,
        chain::block_transactions
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/chain/headers",
        HeavyRead,
        chain::list_headers
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/chain/headers/at-height/:height",
        HeavyRead,
        chain::headers_at_height
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/chain/headers/:header_id",
        HeavyRead,
        chain::header_by_id
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/chain/modifiers/:modifier_id",
        HeavyRead,
        chain::modifier_by_id
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/chain/proofs/:header_id",
        HeavyRead,
        chain::block_ad_proofs
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/chain/proofs/:header_id/transactions/:tx_id",
        HeavyRead,
        chain::proof_for_tx
    );

    // ----- transactions/* reads (submit/check/build/simulate excluded) -----
    route!(
        router,
        table,
        GET,
        "/api/v1/transactions/:tx_id",
        HeavyRead,
        transactions::tx_by_id
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/transactions/fee-estimate",
        HeavyRead,
        tx_intel::fee_estimate
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/transactions/:tx_id/status",
        HeavyRead,
        tx_intel::status
    );

    // ----- mempool/* lists -----
    route!(
        router,
        table,
        GET,
        "/api/v1/mempool/transactions",
        HeavyRead,
        mempool::transactions
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/mempool/by-address/:address",
        HeavyRead,
        mempool::by_address
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/mempool/by-ergo-tree/:ergo_tree",
        HeavyRead,
        mempool::by_ergo_tree
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/mempool/by-box-id/:box_id",
        HeavyRead,
        mempool::by_box_id
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/mempool/by-token-id/:token_id",
        HeavyRead,
        mempool::by_token_id
    );

    // ----- boxes/* -----
    route!(
        router,
        table,
        GET,
        "/api/v1/boxes/range",
        HeavyRead,
        boxes::box_range
    );
    route!(
        router,
        table,
        POST,
        "/api/v1/boxes/decode",
        HeavyRead,
        decode::decode_off_chain_box
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/protocols/:protocol_id/state",
        HeavyRead,
        decode::protocol_state
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/boxes/by-address/:address",
        HeavyRead,
        boxes::boxes_by_address
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/boxes/unspent/by-address/:address",
        HeavyRead,
        boxes::boxes_unspent_by_address
    );
    route!(
        router,
        table,
        POST,
        "/api/v1/boxes/by-ergo-tree",
        HeavyRead,
        boxes::boxes_by_ergo_tree
    );
    route!(
        router,
        table,
        POST,
        "/api/v1/boxes/unspent/by-ergo-tree",
        HeavyRead,
        boxes::boxes_unspent_by_ergo_tree
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/boxes/by-template/:template_hash",
        HeavyRead,
        boxes::boxes_by_template
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/boxes/unspent/by-template/:template_hash",
        HeavyRead,
        boxes::boxes_unspent_by_template
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/boxes/by-token/:token_id",
        HeavyRead,
        boxes::boxes_by_token
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/boxes/unspent/by-token/:token_id",
        HeavyRead,
        boxes::boxes_unspent_by_token
    );

    // ----- tokens/* -----
    route!(
        router,
        table,
        GET,
        "/api/v1/tokens",
        HeavyRead,
        tokens::tokens_list
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/tokens/:token_id/holders",
        HeavyRead,
        tokens::token_holders
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/tokens/:token_id/stats",
        HeavyRead,
        tokens::token_stats
    );

    // ----- addresses/* -----
    route!(
        router,
        table,
        GET,
        "/api/v1/addresses/:address/balance",
        HeavyRead,
        addresses::balance
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/addresses/:address/transactions",
        HeavyRead,
        addresses::transactions
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/addresses/:address/boxes",
        HeavyRead,
        boxes::boxes_by_address
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/addresses/:address/unspent",
        HeavyRead,
        boxes::boxes_unspent_by_address
    );

    // ----- light/* -----
    route!(
        router,
        table,
        GET,
        "/api/v1/light/bootstrap-proof",
        HeavyRead,
        light::bootstrap_proof
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/light/headers-interlinks",
        HeavyRead,
        light::headers_interlinks
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/light/membership-proof",
        HeavyRead,
        light::membership_proof
    );

    // ----- stats/* -----
    route!(
        router,
        table,
        GET,
        "/api/v1/stats/supply",
        HeavyRead,
        stats::supply
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/stats/emission-schedule",
        HeavyRead,
        stats::emission_schedule
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/stats/difficulty",
        HeavyRead,
        stats::difficulty
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/stats/fees",
        HeavyRead,
        stats::fees
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/stats/mempool-depth",
        HeavyRead,
        stats::mempool_depth
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/stats/holders",
        HeavyRead,
        stats::holders
    );

    (router, table)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowed_routes_table_excludes_mutating_submit_domain() {
        let (_router, table) = allowed_routes();
        let has = |m: Method, p: &str| table.iter().any(|r| r.method == m && r.template == p);
        assert!(!has(Method::POST, "/api/v1/transactions/submit"));
        assert!(!has(Method::POST, "/api/v1/transactions/check"));
        assert!(!has(Method::POST, "/api/v1/transactions/build"));
        assert!(!has(Method::POST, "/api/v1/transactions/simulate"));
        assert!(!has(Method::POST, "/api/v1/mempool/submit"));
        assert!(!has(Method::POST, "/api/v1/mempool/check"));
        // Sanity: the table is non-trivially populated (a real read surface).
        assert!(table.len() > 40);
    }
}
