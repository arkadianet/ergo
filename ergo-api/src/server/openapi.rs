//! OpenAPI fragments and canonical family documents.

use std::collections::BTreeSet;

use utoipa::openapi::{
    path::{HttpMethod, Operation, ParameterBuilder, ParameterIn},
    schema::{ObjectBuilder, Type},
    Components, Info, OpenApi as OpenApiDocument, Paths, Required,
};
use utoipa::OpenApi;

use crate::api_family::RUST_API;

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
        title = "Ergo Rust Node — RUST API",
        description = "Compatibility fragment for the original RUST API operator routes. \
The canonical complete RUST API document is served at `/api-docs/openapi-rust.yaml`. \
This fragment describes the production-superset route set: the conditional routes \
(`/api/v1/node/shutdown`, \
`/api/v1/difficulty/history`, `/api/v1/mining/minerStats`, `/api/v1/votes/history`) are mounted only when the node is wired with the matching \
admin / chain-reader handles, so a given process may serve fewer routes than \
appear here. Query `GET /api/v1/health` to confirm a running node's state."
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

/// A documented HTTP operation in one API family.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RouteOperation {
    pub path: String,
    pub method: String,
}

impl RouteOperation {
    pub fn new(path: impl Into<String>, method: impl AsRef<str>) -> Self {
        Self {
            path: path.into(),
            method: method.as_ref().to_ascii_lowercase(),
        }
    }
}

/// A conflict that would make an OpenAPI merge ambiguous.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OpenApiMergeError {
    #[error("OpenAPI operation collision at {method} {path}")]
    PathMethodCollision { path: String, method: String },
    #[error("OpenAPI component conflict in {section}.{name}")]
    ComponentConflict { section: String, name: String },
    #[error("OpenAPI alias source is missing: {method} {path}")]
    MissingSourceOperation { path: String, method: String },
}

const HTTP_METHODS: [&str; 8] = [
    "get", "put", "post", "delete", "options", "head", "patch", "trace",
];

fn http_method_name(method: &HttpMethod) -> &'static str {
    match method {
        HttpMethod::Get => "get",
        HttpMethod::Put => "put",
        HttpMethod::Post => "post",
        HttpMethod::Delete => "delete",
        HttpMethod::Options => "options",
        HttpMethod::Head => "head",
        HttpMethod::Patch => "patch",
        HttpMethod::Trace => "trace",
    }
}

/// Merge `incoming` only when operations are disjoint and duplicate components
/// are structurally identical.
pub fn merge_openapi_checked(
    base: &mut OpenApiDocument,
    incoming: OpenApiDocument,
) -> Result<(), OpenApiMergeError> {
    let base_paths = serde_json::to_value(&base.paths).expect("OpenAPI paths serialize");
    let incoming_paths = serde_json::to_value(&incoming.paths).expect("OpenAPI paths serialize");
    if let (Some(base_paths), Some(incoming_paths)) =
        (base_paths.as_object(), incoming_paths.as_object())
    {
        for (path, incoming_item) in incoming_paths {
            let Some(base_item) = base_paths.get(path).and_then(serde_json::Value::as_object)
            else {
                continue;
            };
            let Some(incoming_item) = incoming_item.as_object() else {
                continue;
            };
            for method in HTTP_METHODS {
                if base_item.get(method).is_some_and(|v| !v.is_null())
                    && incoming_item.get(method).is_some_and(|v| !v.is_null())
                {
                    return Err(OpenApiMergeError::PathMethodCollision {
                        path: path.clone(),
                        method: method.to_string(),
                    });
                }
            }
        }
    }

    let base_components =
        serde_json::to_value(&base.components).expect("OpenAPI components serialize");
    let incoming_components =
        serde_json::to_value(&incoming.components).expect("OpenAPI components serialize");
    if let (Some(base_components), Some(incoming_components)) =
        (base_components.as_object(), incoming_components.as_object())
    {
        for (section, incoming_entries) in incoming_components {
            let Some(base_entries) = base_components
                .get(section)
                .and_then(serde_json::Value::as_object)
            else {
                continue;
            };
            let Some(incoming_entries) = incoming_entries.as_object() else {
                continue;
            };
            for (name, incoming_value) in incoming_entries {
                if let Some(base_value) = base_entries.get(name) {
                    if base_value != incoming_value {
                        return Err(OpenApiMergeError::ComponentConflict {
                            section: section.clone(),
                            name: name.clone(),
                        });
                    }
                }
            }
        }
    }

    base.merge(incoming);
    Ok(())
}

pub fn legacy_rust_openapi() -> OpenApiDocument {
    NativeOpenApi::openapi()
}

pub fn v1_openapi_fragment() -> OpenApiDocument {
    crate::v1::openapi::V1OpenApi::openapi()
}

fn operation_for(
    api: &OpenApiDocument,
    path: &str,
    method: HttpMethod,
) -> Result<Operation, OpenApiMergeError> {
    let item = api.paths.paths.get(path);
    let operation = item.and_then(|item| match method {
        HttpMethod::Get => item.get.as_ref(),
        HttpMethod::Put => item.put.as_ref(),
        HttpMethod::Post => item.post.as_ref(),
        HttpMethod::Delete => item.delete.as_ref(),
        HttpMethod::Options => item.options.as_ref(),
        HttpMethod::Head => item.head.as_ref(),
        HttpMethod::Patch => item.patch.as_ref(),
        HttpMethod::Trace => item.trace.as_ref(),
    });
    operation
        .cloned()
        .ok_or_else(|| OpenApiMergeError::MissingSourceOperation {
            path: path.to_string(),
            method: http_method_name(&method).to_string(),
        })
}

fn add_alias(
    api: &mut OpenApiDocument,
    source_path: &str,
    target_path: &str,
    method: HttpMethod,
    operation_id: &str,
) -> Result<(), OpenApiMergeError> {
    let mut operation = operation_for(api, source_path, method.clone())?;
    operation.operation_id = Some(operation_id.to_string());
    api.paths
        .add_path_operation(target_path, vec![method], operation);
    Ok(())
}

fn add_path_parameters(operation: &mut Operation, path: &str) {
    let parameters = operation.parameters.get_or_insert_with(Vec::new);
    let mut rest = path;
    while let Some(start) = rest.find('{') {
        let after_start = &rest[start + 1..];
        let Some(end) = after_start.find('}') else {
            break;
        };
        let name = &after_start[..end];
        parameters.push(
            ParameterBuilder::new()
                .name(name)
                .parameter_in(ParameterIn::Path)
                .required(Required::True)
                .schema(Some(ObjectBuilder::new().schema_type(Type::String)))
                .build(),
        );
        rest = &after_start[end + 1..];
    }
}

fn collect_schema_references(value: &serde_json::Value, references: &mut BTreeSet<String>) {
    match value {
        serde_json::Value::String(value) => {
            if let Some(name) = value.strip_prefix("#/components/schemas/") {
                references.insert(name.to_string());
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                collect_schema_references(value, references);
            }
        }
        serde_json::Value::Object(values) => {
            for value in values.values() {
                collect_schema_references(value, references);
            }
        }
        _ => {}
    }
}

fn established_openapi_json() -> &'static serde_json::Value {
    static SOURCE: std::sync::LazyLock<serde_json::Value> = std::sync::LazyLock::new(|| {
        serde_norway::from_str(crate::web::OPENAPI_YAML)
            .expect("established OpenAPI document must parse")
    });
    &SOURCE
}

pub fn established_openapi_operations() -> BTreeSet<RouteOperation> {
    let mut operations = BTreeSet::new();
    for (path, path_item) in established_openapi_json()["paths"]
        .as_object()
        .expect("established OpenAPI paths are present")
    {
        let path_item = path_item
            .as_object()
            .unwrap_or_else(|| panic!("established OpenAPI path item is invalid: {path}"));
        for method in HTTP_METHODS {
            if path_item.contains_key(method) {
                operations.insert(RouteOperation::new(path, method));
            }
        }
    }
    operations
}

fn established_rust_contracts() -> OpenApiDocument {
    const PATHS: [&str; 4] = [
        "/api/v1/transactions/{txId}/detail",
        "/blockchain/storageRent/eligibleAt/{height}",
        "/blockchain/storageRent/maturesAt/{height}",
        "/blockchain/storageRent/maturesInRange",
    ];

    let source = established_openapi_json();
    let mut paths = Paths::new();
    for path in PATHS {
        let value = source["paths"]
            .get(path)
            .unwrap_or_else(|| panic!("established OpenAPI path is missing: {path}"));
        let item = serde_json::from_value(value.clone()).unwrap_or_else(|error| {
            panic!("established OpenAPI path is invalid ({path}): {error}")
        });
        paths.paths.insert(path.to_string(), item);
    }

    let mut references = BTreeSet::new();
    collect_schema_references(
        &serde_json::to_value(&paths).expect("established paths serialize"),
        &mut references,
    );
    let source_schemas = source["components"]["schemas"]
        .as_object()
        .expect("established OpenAPI schemas are present");
    let mut components = Components::new();
    let mut pending: Vec<String> = references.iter().cloned().collect();
    while let Some(name) = pending.pop() {
        if components.schemas.contains_key(&name) {
            continue;
        }
        let value = source_schemas
            .get(&name)
            .unwrap_or_else(|| panic!("referenced established schema is missing: {name}"));
        let schema = serde_json::from_value(value.clone()).unwrap_or_else(|error| {
            panic!("referenced established schema is invalid ({name}): {error}")
        });
        let mut nested = BTreeSet::new();
        collect_schema_references(
            &serde_json::to_value(&schema).expect("established schema serializes"),
            &mut nested,
        );
        pending.extend(nested);
        components.schemas.insert(name, schema);
    }

    let mut fragment = OpenApiDocument::new(
        Info::new("Established RUST API contracts", "compatibility"),
        paths,
    );
    fragment.components = Some(components);
    fragment
}

pub(crate) fn supplemental_rust_operations() -> BTreeSet<RouteOperation> {
    crate::v1::SUPPLEMENTAL_ROUTES
        .iter()
        .flat_map(|route| {
            route
                .methods
                .iter()
                .map(|method| RouteOperation::new(route.openapi_path, method))
        })
        .collect()
}

fn supplemental_seam_operation(
    source: &Operation,
    path: &str,
    operation_id: &str,
    summary: &str,
    description: &str,
) -> Operation {
    let mut operation = Operation::new();
    operation.tags = source.tags.clone();
    operation.summary = Some(summary.to_string());
    operation.description = Some(description.to_string());
    operation.operation_id = Some(operation_id.to_string());
    operation.responses = source.responses.clone();
    operation.security = source.security.clone();
    add_path_parameters(&mut operation, path);
    operation
}

fn add_rust_only_operations(api: &mut OpenApiDocument) -> Result<(), OpenApiMergeError> {
    add_alias(
        api,
        "/api/v1/transactions/submit",
        crate::v1::MEMPOOL_SUBMIT_ALIAS.openapi_path,
        HttpMethod::Post,
        "mempool_submit",
    )?;
    add_alias(
        api,
        "/api/v1/transactions/check",
        crate::v1::MEMPOOL_CHECK_ALIAS.openapi_path,
        HttpMethod::Post,
        "mempool_check",
    )?;
    add_alias(
        api,
        "/api/v1/boxes/by-address/{address}",
        crate::v1::ADDRESS_BOXES_ALIAS.openapi_path,
        HttpMethod::Get,
        "address_boxes",
    )?;
    add_alias(
        api,
        "/api/v1/boxes/unspent/by-address/{address}",
        crate::v1::ADDRESS_UNSPENT_ALIAS.openapi_path,
        HttpMethod::Get,
        "address_unspent_boxes",
    )?;

    let account_get = operation_for(api, "/api/v1/accounts", HttpMethod::Get)?;
    let psbt_post = operation_for(api, "/api/v1/transactions-psbt", HttpMethod::Post)?;
    for (path, method, source, operation_id, summary, description) in [
        (
            crate::v1::ACCOUNTS_SEAM.openapi_path,
            HttpMethod::Post,
            &account_get,
            "accounts_create",
            "Create named account (unavailable)",
            "The named-accounts subsystem is not wired; this operation returns 503.",
        ),
        (
            crate::v1::ACCOUNT_SEAM.openapi_path,
            HttpMethod::Get,
            &account_get,
            "account_get",
            "Get named account (unavailable)",
            "The named-accounts subsystem is not wired; this operation returns 503.",
        ),
        (
            crate::v1::ACCOUNT_SEAM.openapi_path,
            HttpMethod::Patch,
            &account_get,
            "account_patch",
            "Update named account (unavailable)",
            "The named-accounts subsystem is not wired; this operation returns 503.",
        ),
        (
            crate::v1::ACCOUNT_SEAM.openapi_path,
            HttpMethod::Delete,
            &account_get,
            "account_delete",
            "Delete named account (unavailable)",
            "The named-accounts subsystem is not wired; this operation returns 503.",
        ),
        (
            crate::v1::ACCOUNT_BALANCE_SEAM.openapi_path,
            HttpMethod::Get,
            &account_get,
            "account_balance",
            "Get named-account balance (unavailable)",
            "The named-accounts subsystem is not wired; this operation returns 503.",
        ),
        (
            crate::v1::ACCOUNT_ADDRESSES_SEAM.openapi_path,
            HttpMethod::Get,
            &account_get,
            "account_addresses",
            "List named-account addresses (unavailable)",
            "The named-accounts subsystem is not wired; this operation returns 503.",
        ),
        (
            crate::v1::ACCOUNT_ADDRESSES_SEAM.openapi_path,
            HttpMethod::Post,
            &account_get,
            "account_address_create",
            "Create named-account address (unavailable)",
            "The named-accounts subsystem is not wired; this operation returns 503.",
        ),
        (
            crate::v1::PSBT_SEAM.openapi_path,
            HttpMethod::Get,
            &psbt_post,
            "psbt_get",
            "Get PSBT session (unavailable)",
            "The PSBT-session subsystem is not wired; this operation returns 503.",
        ),
        (
            crate::v1::PSBT_CONTRIBUTIONS_SEAM.openapi_path,
            HttpMethod::Post,
            &psbt_post,
            "psbt_contribute",
            "Add PSBT contribution (unavailable)",
            "The PSBT-session subsystem is not wired; this operation returns 503.",
        ),
        (
            crate::v1::PSBT_FINALIZE_SEAM.openapi_path,
            HttpMethod::Post,
            &psbt_post,
            "psbt_finalize",
            "Finalize PSBT session (unavailable)",
            "The PSBT-session subsystem is not wired; this operation returns 503.",
        ),
    ] {
        let operation =
            supplemental_seam_operation(source, path, operation_id, summary, description);
        api.paths.add_path_operation(path, vec![method], operation);
    }
    Ok(())
}

/// One canonical OpenAPI document for every RUST API operation.
pub fn rust_openapi() -> Result<OpenApiDocument, OpenApiMergeError> {
    let mut openapi = legacy_rust_openapi();
    merge_openapi_checked(&mut openapi, v1_openapi_fragment())?;
    merge_openapi_checked(&mut openapi, established_rust_contracts())?;
    add_rust_only_operations(&mut openapi)?;
    openapi.info.title = format!("Ergo Rust Node — {}", RUST_API.label);
    openapi.info.description = Some(
        "The complete Rust-native API, including legacy operator routes and all \
         versioned `/api/v1/*` operations."
            .to_string(),
    );
    Ok(openapi)
}

pub fn rust_openapi_json() -> &'static OpenApiDocument {
    static RUST_OPENAPI: std::sync::LazyLock<OpenApiDocument> = std::sync::LazyLock::new(|| {
        rust_openapi().expect("RUST API OpenAPI fragments must merge without conflicts")
    });
    &RUST_OPENAPI
}

pub fn rust_openapi_yaml() -> &'static str {
    static RUST_OPENAPI_YAML: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
        rust_openapi_json()
            .to_yaml()
            .expect("OpenAPI YAML serialize")
    });
    RUST_OPENAPI_YAML.as_str()
}

pub fn openapi_operations(openapi: &OpenApiDocument) -> BTreeSet<RouteOperation> {
    let paths = serde_json::to_value(&openapi.paths).expect("OpenAPI paths serialize");
    let mut operations = BTreeSet::new();
    let Some(paths) = paths.as_object() else {
        return operations;
    };
    for (path, item) in paths {
        let Some(item) = item.as_object() else {
            continue;
        };
        for method in HTTP_METHODS {
            if item.get(method).is_some_and(|value| !value.is_null()) {
                operations.insert(RouteOperation::new(path, method));
            }
        }
    }
    operations
}

fn exclude_from_scala_openapi(path: &str) -> bool {
    path.starts_with("/api/v1/")
        || path.starts_with("/blockchain/storageRent/")
        || matches!(
            path,
            "/transactions/unconfirmed/inputs/byBoxId/{boxId}"
                | "/transactions/unconfirmed/outputs/byBoxId/{boxId}"
                | "/transactions/unconfirmed/outputs/byErgoTree"
                | "/transactions/unconfirmed/outputs/byTokenId/{tokenId}"
                | "/transactions/unconfirmed/outputs/byRegisters"
                | "/mining/candidateWithTxs"
                | "/utxo/getBoxesBinaryProof"
                | "/script/executeWithContext"
        )
}

pub fn scala_openapi_yaml() -> &'static str {
    static SCALA_OPENAPI: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
        let mut output = String::new();
        let mut in_paths = false;
        let mut skip_path = false;
        let mut skip_rust_description = false;
        for line in crate::web::OPENAPI_YAML.lines() {
            if line == "    ## Rust-exclusive additions" {
                skip_rust_description = true;
                continue;
            }
            if skip_rust_description {
                if line == "    ## Everything else" {
                    skip_rust_description = false;
                } else {
                    continue;
                }
            }
            if line == "paths:" {
                in_paths = true;
                skip_path = false;
            } else if in_paths && !line.starts_with(' ') && !line.is_empty() {
                in_paths = false;
                skip_path = false;
            } else if in_paths {
                if let Some(path) = line
                    .strip_prefix("  /")
                    .and_then(|path| path.strip_suffix(':'))
                {
                    skip_path = exclude_from_scala_openapi(&format!("/{path}"));
                }
            }
            if !skip_path {
                output.push_str(line);
                output.push('\n');
            }
        }
        let title_source = "title: Ergo Node API — legacy compatibility document";
        let title = output.replace(title_source, "title: Ergo Node — Scala API");
        assert_ne!(
            title, output,
            "Scala OpenAPI title source literal is missing"
        );

        let description_source = "OpenAPI spec inherited from the Scala reference node. The Rust\n    node implements most of the Scala wire surface plus a small\n    Rust-exclusive operator overlay. This page is the authoritative\n    map of what this build serves: the sections below enumerate every\n    route that returns **404**, every config-gated route, and every\n    Rust-exclusive addition. Anything not called out here matches the\n    Scala wire shape (see **Everything else**).";
        let description = title.replace(
            description_source,
            "OpenAPI spec for the Scala-compatible operations served by this node.\n    Rust-native operations are documented separately as the RUST API.",
        );
        assert_ne!(
            description, title,
            "Scala OpenAPI description source literal is missing"
        );
        description
    });
    SCALA_OPENAPI.as_str()
}

pub fn scala_openapi_operations() -> BTreeSet<RouteOperation> {
    static OPERATIONS: std::sync::LazyLock<BTreeSet<RouteOperation>> =
        std::sync::LazyLock::new(|| {
            let document: serde_json::Value = serde_norway::from_str(scala_openapi_yaml())
                .expect("Scala OpenAPI document must parse");
            let mut operations = BTreeSet::new();
            for (path, path_item) in document["paths"]
                .as_object()
                .expect("Scala OpenAPI paths are present")
            {
                let path_item = path_item
                    .as_object()
                    .unwrap_or_else(|| panic!("Scala OpenAPI path item is invalid: {path}"));
                for method in HTTP_METHODS {
                    if path_item.contains_key(method) {
                        operations.insert(RouteOperation::new(path, method));
                    }
                }
            }
            operations
        });
    OPERATIONS.clone()
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
