//! OpenAPI aggregation for the Rust-native `/api/v1/*` surface:
//! the [`NativeOpenApi`] derive, its `ApiKeyAuth` security addon, and
//! the YAML serializer. The Scala-parity `openapi.yaml` is a separate,
//! untouched surface (see [`super::assets`]).

use utoipa::OpenApi;

use crate::types::{
    ApiBlockApplyError, ApiBootstrapStatus, ApiConfiguredVote, ApiDifficultyPoint,
    ApiDifficultySeries, ApiFullBlockRef, ApiHeaderRef, ApiHealth, ApiHistoryMode, ApiHost,
    ApiIdentity, ApiInfo, ApiMempoolSummary, ApiMempoolTransaction, ApiMempoolTransactions,
    ApiMinerStat, ApiMinerStats, ApiNativeSubmitError, ApiParamChange, ApiPeer, ApiRecentBlock,
    ApiSetVotesRequest, ApiStatus, ApiSubmitError, ApiSubmitResponse, ApiSyncStatus, ApiTip,
    ApiTxSource, ApiVotableParam, ApiVoteChangeEvent, ApiVoteTarget, ApiVotes, ApiVotesHistory,
    ApiWeightFunction, HealthStatus, RawTransactionBytes, SyncStateLabel,
};

/// OpenAPI aggregator for the Rust-native `/api/v1/*` surface.
///
/// Defined here in `server.rs` so the derive can name the private handler
/// functions directly without widening their visibility. The Scala-parity
/// `openapi.yaml` and its `/swagger` mount are a separate surface,
/// untouched by this type.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "Ergo Rust Node — Native API",
        description = "Rust-native operator API for the Ergo node (`/api/v1/*`). \
This document describes the production-superset route set: the conditional routes \
(`/api/v1/node/shutdown`, \
`/api/v1/difficulty/history`, `/api/v1/mining/minerStats`, `/api/v1/votes/history`) are mounted only when the node is wired with the matching \
admin / chain-reader handles, so a given process may serve fewer routes than \
appear here. The `mempool/*` product routes are documented in the v1 product \
router. Query `GET /api/v1/health` to confirm a running node's state."
    ),
    paths(
        super::handlers::info_handler,
        super::handlers::difficulty_history_handler,
        super::handlers::miner_stats_handler,
        super::handlers::votes_history_handler,
        crate::blockchain::indexer_status_handler,
        super::handlers::identity_handler,
        super::handlers::host_handler,
        super::handlers::status_handler,
        super::handlers::votes_handler,
        super::handlers::set_votes_handler,
        super::handlers::tip_handler,
        super::handlers::recent_blocks_handler,
        super::handlers::events_handler,
        super::handlers::sync_handler,
        super::handlers::peers_handler,
        super::handlers::health_handler,
        super::handlers::shutdown_handler,
        crate::wallet::native::balance,
        crate::wallet::native::status,
        crate::wallet::native::addresses,
        crate::wallet::native::boxes,
        crate::wallet::native::box_by_id,
        crate::wallet::native::transactions,
        crate::wallet::native::transaction_by_id,
        crate::wallet::native::init,
        crate::wallet::native::restore,
        crate::wallet::native::unlock,
        crate::wallet::native::lock,
        crate::wallet::native::mnemonic_verify,
        crate::wallet::native::derive_address,
        crate::wallet::native::change_address_get,
        crate::wallet::native::change_address_put,
        crate::wallet::native::rescan,
        crate::wallet::native::select_boxes,
        crate::wallet::native::build_transaction,
        crate::wallet::native::sign_transaction,
        crate::wallet::native::send_transaction,
        crate::wallet::native::retrieve_rewards,
    ),
    components(schemas(
        ApiInfo,
        ApiIdentity,
        ApiHost,
        ApiStatus,
        ApiVotes,
        ApiVotableParam,
        ApiConfiguredVote,
        ApiSetVotesRequest,
        ApiVoteTarget,
        ApiVotesHistory,
        ApiVoteChangeEvent,
        ApiParamChange,
        ApiTip,
        ApiRecentBlock,
        ApiSyncStatus,
        ApiPeer,
        ApiMempoolSummary,
        ApiMempoolTransactions,
        ApiMempoolTransaction,
        ApiHealth,
        ApiSubmitResponse,
        ApiSubmitError,
        ApiNativeSubmitError,
        RawTransactionBytes,
        ApiHistoryMode,
        ApiBootstrapStatus,
        ApiBlockApplyError,
        ApiHeaderRef,
        ApiFullBlockRef,
        ApiDifficultyPoint,
        ApiDifficultySeries,
        ApiMinerStat,
        ApiMinerStats,
        crate::types::ApiNodeEvent,
        crate::types::ApiNodeEvents,
        crate::types::ApiIndexerStatus,
        crate::types::ApiIndexerRepair,
        crate::types::ApiIndexerTotals,
        ApiWeightFunction,
        ApiTxSource,
        SyncStateLabel,
        HealthStatus,
        crate::wallet::native::dto::WalletBalanceDto,
        crate::wallet::native::dto::NanoErgBreakdownDto,
        crate::wallet::native::dto::ReemissionInfoDto,
        crate::wallet::native::dto::UnconfirmedDeltaDto,
        crate::wallet::native::dto::ScopeDto,
        crate::wallet::native::dto::WalletAssetDto,
        crate::wallet::native::dto::WalletStatusDto,
        crate::wallet::native::dto::NetworkDto,
        crate::wallet::native::dto::RescanStateDto,
        crate::wallet::native::dto::WalletAddressDto,
        crate::wallet::native::dto::AddressPage,
        crate::wallet::native::dto::WalletBoxSummary,
        crate::wallet::native::dto::BoxStatusDto,
        crate::wallet::native::dto::BoxProvenanceDto,
        crate::wallet::native::dto::BoxPage,
        crate::wallet::native::dto::WalletTransactionSummary,
        crate::wallet::native::dto::TxPage,
        crate::wallet::native::dto::UnlockRequest,
        crate::wallet::native::dto::MnemonicVerifyRequest,
        crate::wallet::native::dto::MnemonicVerifyResult,
        crate::wallet::native::dto::InitRequest,
        crate::wallet::native::dto::InitResponse,
        crate::wallet::native::dto::RestoreRequest,
        crate::wallet::native::dto::DerivationMode,
        crate::wallet::native::dto::DeriveKeyRequest,
        crate::wallet::native::dto::DerivedAddress,
        crate::wallet::native::dto::ChangeAddressDto,
        crate::wallet::native::dto::SetChangeAddressRequest,
        crate::wallet::native::dto::RescanRequest,
        crate::wallet::native::dto::TxRepr,
        crate::wallet::native::dto::OutputIntent,
        crate::wallet::native::dto::InputSource,
        crate::wallet::native::dto::DataInputSource,
        crate::wallet::native::dto::TxIntent,
        crate::wallet::native::dto::SelectTarget,
        crate::wallet::native::dto::BoxSelectRequest,
        crate::wallet::native::dto::SelectedBoxRef,
        crate::wallet::native::dto::ChangePlan,
        crate::wallet::native::dto::ReemissionBurn,
        crate::wallet::native::dto::BoxSelectResponse,
        crate::wallet::native::dto::BuildTxResponse,
        crate::wallet::native::dto::ExternalSecret,
        crate::wallet::native::dto::SignTxRequest,
        crate::wallet::native::dto::SignTxResponse,
        crate::wallet::native::dto::SendTxRequest,
        crate::wallet::native::dto::SendTxResponse,
        crate::wallet::native::dto::RetrieveRewardsRequest,
        crate::wallet::native::dto::RetrieveRewardsResultDto,
        crate::wallet::native::dto::SweptTokenDto,
        crate::wallet::native::error::NativeWalletError,
    )),
    tags(
        (name = "node", description = "Node identity, host, status"),
        (name = "chain", description = "Tip, sync progress"),
        (name = "peers", description = "Peer manager view"),
        (name = "mempool", description = "Mempool overlay + submission"),
        (name = "admin", description = "API-key-gated operator routes"),
        (name = "health", description = "Liveness + readiness"),
        (name = "wallet", description = "Native api-key-gated wallet surface"),
    ),
    modifiers(&SecurityAddon),
)]
pub(crate) struct NativeOpenApi;

/// Registers the `ApiKeyAuth` security scheme on the native spec so Swagger UI
/// renders an Authorize control (and a per-operation padlock) for the
/// api-key-gated routes. The scheme matches the runtime gate exactly: the secret
/// rides the `api_key` request header ([`crate::auth::API_KEY_HEADER`]), which is
/// what [`crate::auth::require_api_key`] checks. Individual gated operations opt
/// in via `security(("ApiKeyAuth" = []))` on their `#[utoipa::path]`.
struct SecurityAddon;

impl utoipa::Modify for SecurityAddon {
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

/// Serialise the native OpenAPI document to YAML.
///
/// Serialisation is deterministic in-memory work; a failure would be a
/// bug rather than a runtime condition, so this panics instead of serving
/// an empty spec.
pub fn native_openapi_yaml() -> String {
    NativeOpenApi::openapi()
        .to_yaml()
        .expect("openapi yaml serialize")
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- happy path -----

    /// The native spec serialises to a non-empty OpenAPI 3.1 document.
    /// Pins utoipa's default emission version and exercises the
    /// panic-on-error branch of [`native_openapi_yaml`].
    #[test]
    fn native_openapi_yaml_emits_openapi_3_1_document() {
        let yaml = native_openapi_yaml();
        assert!(
            yaml.starts_with("openapi: 3.1."),
            "expected utoipa 5 default OpenAPI 3.1 emission, got first line: {:?}",
            yaml.lines().next(),
        );
    }
}
