//! Scala-compatible wallet and scan adapters using shared protocol DTOs.
use super::facade::WalletApi;
use std::sync::Arc;
mod admin_advanced;
mod lifecycle;
mod multi_sig;
mod reads;
mod scan;
mod sending;
mod state_mut;

pub(super) fn router(admin: Arc<WalletApi>) -> axum::Router {
    use axum::routing::{get, post};
    axum::Router::new()
        .route("/wallet/status", get(lifecycle::status))
        .route(
            "/wallet/init",
            post(lifecycle::init).layer(axum::extract::DefaultBodyLimit::max(
                crate::lifecycle_api::MAX_LIFECYCLE_BODY_BYTES,
            )),
        )
        .route(
            "/wallet/restore",
            post(lifecycle::restore).layer(axum::extract::DefaultBodyLimit::max(
                crate::lifecycle_api::MAX_LIFECYCLE_BODY_BYTES,
            )),
        )
        .route(
            "/wallet/unlock",
            post(lifecycle::unlock).layer(axum::extract::DefaultBodyLimit::max(
                crate::lifecycle_api::MAX_LIFECYCLE_BODY_BYTES,
            )),
        )
        .route("/wallet/lock", get(lifecycle::lock).post(lifecycle::lock))
        .route(
            "/wallet/check",
            post(lifecycle::check).layer(axum::extract::DefaultBodyLimit::max(
                crate::lifecycle_api::MAX_LIFECYCLE_BODY_BYTES,
            )),
        )
        .route("/wallet/rescan", post(state_mut::rescan))
        .route(
            "/wallet/updateChangeAddress",
            post(state_mut::update_change_address).layer(axum::extract::DefaultBodyLimit::max(
                crate::lifecycle_api::MAX_LIFECYCLE_BODY_BYTES,
            )),
        )
        .route("/wallet/balances", get(reads::balances))
        .route(
            "/wallet/balances/withUnconfirmed",
            get(reads::balances_with_unconfirmed),
        )
        .route("/wallet/addresses", get(reads::addresses))
        .route("/wallet/boxes", get(reads::boxes))
        .route("/wallet/boxes/unspent", get(reads::boxes_unspent))
        .route("/wallet/boxes/collect", post(sending::boxes_collect))
        .route("/wallet/transactions", get(reads::transactions))
        .route("/wallet/transactionById", get(reads::transaction_by_id))
        .route(
            "/wallet/transactionsByScanId/:scan_id",
            get(reads::transactions_by_scan_id),
        )
        .route("/wallet/extractHints", post(multi_sig::extract_hints))
        .route(
            "/wallet/generateCommitments",
            post(multi_sig::generate_commitments),
        )
        .route("/wallet/transaction/sign", post(sending::transaction_sign))
        .route(
            "/wallet/transaction/generateUnsigned",
            post(sending::transaction_generate_unsigned),
        )
        .route(
            "/wallet/transaction/generate",
            post(sending::transaction_generate),
        )
        .route("/wallet/transaction/send", post(sending::transaction_send))
        .route("/wallet/payment/send", post(sending::payment_send))
        .route(
            "/wallet/deriveKey",
            post(admin_advanced::derive_key).layer(axum::extract::DefaultBodyLimit::max(
                crate::lifecycle_api::MAX_LIFECYCLE_BODY_BYTES,
            )),
        )
        .route(
            "/wallet/deriveNextKey",
            get(admin_advanced::derive_next_key).post(admin_advanced::derive_next_key),
        )
        .route(
            "/wallet/getPrivateKey",
            post(admin_advanced::get_private_key).layer(axum::extract::DefaultBodyLimit::max(
                crate::lifecycle_api::MAX_LIFECYCLE_BODY_BYTES,
            )),
        )
        // Scan routes (Scala `ScanApiRoute`, full surface). Share the wallet
        // admin state + auth route-layer.
        .route("/scan/register", post(scan::register))
        .route("/scan/deregister", post(scan::deregister))
        .route("/scan/listAll", get(scan::list_all))
        .route("/scan/unspentBoxes/:scan_id", get(scan::unspent_boxes))
        .route("/scan/spentBoxes/:scan_id", get(scan::spent_boxes))
        .route("/scan/stopTracking", post(scan::stop_tracking))
        .route("/scan/addBox", post(scan::add_box))
        .route(
            "/scan/p2sRule",
            post(scan::p2s_rule).layer(axum::extract::DefaultBodyLimit::max(
                crate::lifecycle_api::MAX_LIFECYCLE_BODY_BYTES,
            )),
        )
        .with_state(admin)
}
