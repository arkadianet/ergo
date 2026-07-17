//! The v1 product-API OpenAPI document (`/api/v1/*`, distinct from the older
//! pre-v1 [`crate::server::NativeOpenApi`] surface — wallet/mining/votes/
//! indexer/node — that this derive does NOT re-document). v1 is its own
//! product surface, so it gets its own spec + Swagger page
//! (`/swagger/v1`, `/api-docs/openapi-v1.yaml`) rather than being folded
//! into the pre-v1 doc.
//!
//! Registers every `#[utoipa::path]`-annotated handler across
//! `crate::v1::{routes,accounts,operator,script,webhooks,realtime}` — see
//! the module docs on each for the endpoint's semantics. Kept in this one
//! file (rather than scattered `#[openapi(...)]` fragments) so the full
//! v1 surface is auditable at a glance and the golden-snapshot test
//! (`tests/openapi_v1_snapshot.rs`) has one obvious source of truth.

use utoipa::OpenApi;

/// Registers the `ApiKeyAuth` security scheme on the v1 spec — the SAME
/// scheme (and header) as `crate::server`'s `SecurityAddon` on the pre-v1
/// doc, since both gate on the identical `api_key` header
/// (`crate::auth::API_KEY_HEADER`) via `crate::v1::auth::require_tier`.
/// T1/T2 operations opt in via `security(("ApiKeyAuth" = []))`.
struct V1SecurityAddon;

impl utoipa::Modify for V1SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        use utoipa::openapi::security::{ApiKey, ApiKeyValue, SecurityScheme};
        let components = openapi
            .components
            .get_or_insert_with(utoipa::openapi::Components::new);
        components.add_security_scheme(
            "ApiKeyAuth",
            SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::new(
                crate::auth::API_KEY_HEADER,
            ))),
        );
    }
}

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Ergo Rust Node — v1 API",
        description = "The Rust-native v1 product API (`/api/v1/*`): chain/boxes/tokens/addresses/mempool/transactions \
reads, tx-intelligence (build/simulate/fee-estimate/status), the ErgoScript playground (`script/*`), semantic decode \
(`protocols/*`, `boxes/decode`), light-client trustless-sync proofs (`light/*`), time-series analytics (`stats/*`), \
operator diagnostics, webhooks, real-time WebSocket subscriptions, the scan/accounts surface, and node/network/mining/voting \
operator controls. Distinct from the pre-v1 native surface documented at `/swagger/native` (wallet/mining/votes/indexer/node) \
— the two specs are additive, not overlapping. Every v1 error follows the nested error envelope \
(`error.reason`/`error.message`/`error.detail`); `reason` is the stable machine-readable field to switch on. Query \
`GET /api/v1/node/health` to confirm a running node's state."
    ),
    paths(
        crate::v1::accounts::scan::register,
        crate::v1::accounts::scan::list,
        crate::v1::accounts::scan::get_one,
        crate::v1::accounts::scan::deregister,
        crate::v1::accounts::scan::watch_unspent,
        crate::v1::accounts::scan::unspent,
        crate::v1::accounts::scan::transactions,
        crate::v1::accounts::scan::attach_box,
        crate::v1::accounts::scan::detach_box,
        crate::v1::accounts::watch_register,
        crate::v1::accounts::watch_list,
        crate::v1::accounts::watch_delete,
        crate::v1::accounts::private_key,
        crate::v1::accounts::accounts_seam,
        crate::v1::accounts::psbt_seam,
        crate::v1::operator::node::info,
        crate::v1::operator::node::status,
        crate::v1::operator::node::sync,
        crate::v1::operator::node::tip,
        crate::v1::operator::node::identity,
        crate::v1::operator::node::host,
        crate::v1::operator::node::health,
        crate::v1::operator::node::version,
        crate::v1::operator::node::config_get,
        crate::v1::operator::node::config_patch,
        crate::v1::operator::network::peers,
        crate::v1::operator::network::connected,
        crate::v1::operator::network::blacklisted,
        crate::v1::operator::network::sync_info,
        crate::v1::operator::network::track_info,
        crate::v1::operator::network::connect,
        crate::v1::operator::network::blacklist_add,
        crate::v1::operator::network::blacklist_remove,
        crate::v1::operator::mining::miner_stats,
        crate::v1::operator::mining::status,
        crate::v1::operator::mining::candidate,
        crate::v1::operator::mining::solution,
        crate::v1::operator::mining::reward_address,
        crate::v1::operator::mining::reward_pubkey,
        crate::v1::operator::mining::candidate_with_txs,
        crate::v1::operator::voting::votes,
        crate::v1::operator::voting::history,
        crate::v1::operator::voting::candidate,
        crate::v1::operator::voting::operator_votes_get,
        crate::v1::operator::voting::operator_votes_set,
        crate::v1::realtime::ws::ws_handler,
        crate::v1::routes::chain::list_blocks,
        crate::v1::routes::chain::block_by_id,
        crate::v1::routes::chain::block_transactions,
        crate::v1::routes::chain::blocks_at_height,
        crate::v1::routes::chain::blocks_by_ids,
        crate::v1::routes::chain::list_headers,
        crate::v1::routes::chain::header_by_id,
        crate::v1::routes::chain::headers_at_height,
        crate::v1::routes::chain::modifier_by_id,
        crate::v1::routes::chain::block_ad_proofs,
        crate::v1::routes::chain::proof_for_tx,
        crate::v1::routes::boxes::box_by_id,
        crate::v1::routes::boxes::boxes_by_address,
        crate::v1::routes::boxes::boxes_unspent_by_address,
        crate::v1::routes::boxes::boxes_by_ergo_tree,
        crate::v1::routes::boxes::boxes_unspent_by_ergo_tree,
        crate::v1::routes::boxes::boxes_by_template,
        crate::v1::routes::boxes::boxes_unspent_by_template,
        crate::v1::routes::boxes::boxes_by_token,
        crate::v1::routes::boxes::boxes_unspent_by_token,
        crate::v1::routes::boxes::box_range,
        crate::v1::routes::tokens::token_by_id,
        crate::v1::routes::tokens::tokens_list,
        crate::v1::routes::tokens::token_holders,
        crate::v1::routes::tokens::token_stats,
        crate::v1::routes::addresses::balance,
        crate::v1::routes::addresses::transactions,
        crate::v1::routes::mempool::summary,
        crate::v1::routes::mempool::transactions,
        crate::v1::routes::mempool::transaction_by_id,
        crate::v1::routes::mempool::by_address,
        crate::v1::routes::mempool::by_ergo_tree,
        crate::v1::routes::mempool::by_box_id,
        crate::v1::routes::mempool::by_token_id,
        crate::v1::routes::mempool::fee_histogram,
        crate::v1::routes::transactions::tx_by_id,
        crate::v1::routes::transactions::submit,
        crate::v1::routes::transactions::check,
        crate::v1::routes::tx_intel::build::build,
        crate::v1::routes::tx_intel::simulate::simulate,
        crate::v1::routes::tx_intel::fee_estimate::fee_estimate,
        crate::v1::routes::tx_intel::status::status,
        crate::v1::routes::decode::list_protocols,
        crate::v1::routes::decode::protocol_by_id,
        crate::v1::routes::decode::decode_off_chain_box,
        crate::v1::routes::decode::protocol_state,
        crate::v1::routes::light::bootstrap_proof,
        crate::v1::routes::light::headers_interlinks,
        crate::v1::routes::light::membership_proof,
        crate::v1::routes::light::status,
        crate::v1::routes::stats::supply,
        crate::v1::routes::stats::emission_schedule,
        crate::v1::routes::stats::difficulty,
        crate::v1::routes::stats::fees,
        crate::v1::routes::stats::mempool_depth,
        crate::v1::routes::stats::holders,
        crate::v1::routes::diagnostics::chain_position,
        crate::v1::routes::diagnostics::fork_risk,
        crate::v1::routes::diagnostics::tip_health,
        crate::v1::routes::diagnostics::peer_quality,
        crate::v1::routes::diagnostics::candidate_build,
        crate::v1::routes::diagnostics::reorgs,
        crate::v1::routes::diagnostics::composite,
        crate::v1::routes::batch::dispatch::batch_handler,
        crate::v1::script::handlers::compile,
        crate::v1::script::handlers::inspect,
        crate::v1::script::handlers::execute,
        crate::v1::script::handlers::cost,
        crate::v1::script::handlers::simulate,
        crate::v1::script::handlers::explain,
        crate::v1::script::handlers::diff,
        crate::v1::webhooks::routes::register,
        crate::v1::webhooks::routes::list,
        crate::v1::webhooks::routes::detail,
        crate::v1::webhooks::routes::delete,
        crate::v1::webhooks::routes::patch_active,
        crate::v1::webhooks::routes::deliveries
    ),
    components(schemas(
            crate::types::ApiHealth,
            crate::types::ApiHost,
            crate::types::ApiIdentity,
            crate::types::ApiInfo,
            crate::types::ApiMinerStats,
            crate::types::ApiPeer,
            crate::types::ApiStatus,
            crate::types::ApiReorgHistory,
            crate::types::ApiReorgRecord,
            crate::types::ApiSyncStatus,
            crate::types::ApiTip,
            crate::types::RawTransactionBytes,
            crate::v1::accounts::PrivateKeyRequest,
            crate::v1::accounts::WatchRequest,
            crate::v1::accounts::scan::AttachBoxRequest,
            crate::v1::accounts::scan::ScanBoxView,
            crate::v1::accounts::scan::ScanRegisterRequest,
            crate::v1::accounts::scan::ScanView,
            crate::v1::error::V1Error,
            crate::v1::operator::mining::MiningStatus,
            crate::v1::operator::mining::RewardAddress,
            crate::v1::operator::mining::RewardPubkey,
            crate::v1::operator::network::BlacklistedPeer,
            crate::v1::operator::network::SyncInfoEntry,
            crate::v1::operator::network::TrackInfo,
            crate::v1::operator::node::NodeVersion,
            crate::v1::operator::voting::ConfiguredVote,
            crate::v1::operator::voting::PublicVotes,
            crate::v1::operator::voting::SetVotesRequest,
            crate::v1::operator::voting::VotesHistory,
            crate::v1::routes::batch::BatchRequest,
            crate::v1::routes::batch::BatchResponse,
            crate::v1::routes::boxes::ErgoTreeBody,
            crate::v1::routes::decode::DecodeBoxBody,
            crate::v1::routes::decode::DecodeBoxResponse,
            crate::v1::routes::decode::ProtocolDetail,
            crate::v1::routes::decode::ProtocolListItem,
            crate::v1::routes::decode::ProtocolStateResponse,
            crate::v1::routes::diagnostics::CandidateBuild,
            crate::v1::routes::diagnostics::ChainPosition,
            crate::v1::routes::diagnostics::Diagnostics,
            crate::v1::routes::diagnostics::ForkRisk,
            crate::v1::routes::diagnostics::PeerQuality,
            crate::v1::routes::diagnostics::TipHealth,
            crate::v1::routes::dto::Collection<String>,
            crate::v1::routes::dto::Collection<crate::types::ApiPeer>,
            crate::v1::routes::dto::Collection<crate::v1::accounts::scan::ScanBoxView>,
            crate::v1::routes::dto::Collection<crate::v1::operator::network::BlacklistedPeer>,
            crate::v1::routes::dto::Collection<crate::v1::operator::network::SyncInfoEntry>,
            crate::v1::routes::dto::Collection<crate::v1::operator::voting::ConfiguredVote>,
            crate::v1::routes::dto::Collection<crate::v1::routes::decode::ProtocolListItem>,
            crate::v1::routes::dto::Collection<crate::v1::routes::dto::V1AddressTxSummary>,
            crate::v1::routes::dto::Collection<crate::v1::routes::dto::V1Block>,
            crate::v1::routes::dto::Collection<crate::v1::routes::dto::V1BlockSummary>,
            crate::v1::routes::dto::Collection<crate::v1::routes::dto::V1BlockTx>,
            crate::v1::routes::dto::Collection<crate::v1::routes::dto::V1Box>,
            crate::v1::routes::dto::Collection<crate::v1::routes::dto::V1Header>,
            crate::v1::routes::dto::Collection<crate::v1::routes::dto::V1MempoolTx>,
            crate::v1::routes::dto::CollectionMeta<crate::v1::routes::dto::V1TokenHolder, crate::v1::routes::dto::HoldersMeta>,
            crate::v1::routes::dto::CollectionMeta<crate::v1::routes::stats::HolderRow, crate::v1::routes::stats::HolderMetrics>,
            crate::v1::routes::dto::V1AddressTxSummary,
            crate::v1::routes::dto::V1Balance,
            crate::v1::routes::dto::V1Block,
            crate::v1::routes::dto::V1BlockAdProofs,
            crate::v1::routes::dto::V1BlockSummary,
            crate::v1::routes::dto::V1BlockTx,
            crate::v1::routes::dto::V1Box,
            crate::v1::routes::dto::V1FeeHistogram,
            crate::v1::routes::dto::V1Header,
            crate::v1::routes::dto::V1MempoolDepthPoint,
            crate::v1::routes::dto::V1MempoolSummary,
            crate::v1::routes::dto::V1MempoolTx,
            crate::v1::routes::dto::V1MempoolTxDetail,
            crate::v1::routes::dto::V1MerkleProof,
            crate::v1::routes::dto::V1Modifier,
            crate::v1::routes::dto::V1Token,
            crate::v1::routes::dto::V1TokenHolder,
            crate::v1::routes::dto::V1TokenStats,
            crate::v1::routes::dto::V1Tx,
            crate::v1::routes::light::LightHeadersPage,
            crate::v1::routes::light::LightPopowProof,
            crate::v1::routes::light::LightStatus,
            crate::v1::routes::stats::DifficultyPoint,
            crate::v1::routes::stats::FeesPoint,
            crate::v1::routes::stats::HolderMetrics,
            crate::v1::routes::stats::HolderRow,
            crate::v1::routes::stats::SeriesPage<crate::v1::routes::dto::V1MempoolDepthPoint>,
            crate::v1::routes::stats::SeriesPage<crate::v1::routes::stats::DifficultyPoint>,
            crate::v1::routes::stats::SeriesPage<crate::v1::routes::stats::FeesPoint>,
            crate::v1::routes::stats::SeriesPage<crate::v1::routes::stats::SupplyPoint>,
            crate::v1::routes::stats::SupplyPoint,
            crate::v1::routes::tx_intel::BuildBody,
            crate::v1::routes::tx_intel::BuildResponse,
            crate::v1::routes::tx_intel::FeeEstimateResponse,
            crate::v1::routes::tx_intel::SimulateBody,
            crate::v1::routes::tx_intel::SimulateResponse,
            crate::v1::routes::tx_intel::StatusResponse,
            crate::v1::script::handlers::CompileBody,
            crate::v1::script::handlers::CompileResponse,
            crate::v1::script::handlers::CostResponse,
            crate::v1::script::handlers::DiffBody,
            crate::v1::script::handlers::DiffResponse,
            crate::v1::script::handlers::ExecuteBody,
            crate::v1::script::handlers::ExecuteResponse,
            crate::v1::script::handlers::ExplainResponse,
            crate::v1::script::handlers::InspectBody,
            crate::v1::script::handlers::InspectResponse,
            crate::v1::webhooks::routes::PatchRequest,
            crate::v1::webhooks::routes::RegisterRequest
    )),
    modifiers(&V1SecurityAddon),
)]
pub(crate) struct V1OpenApi;

/// Serialise the v1 OpenAPI document to YAML.
///
/// Serialisation is deterministic in-memory work; a failure would be a bug
/// rather than a runtime condition, so this panics instead of serving an
/// empty spec (mirrors `crate::server::native_openapi_yaml`).
pub fn v1_openapi_yaml() -> String {
    V1OpenApi::openapi()
        .to_yaml()
        .expect("openapi yaml serialize")
}
