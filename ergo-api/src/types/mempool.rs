//! Mempool + submission DTOs: pool summary/transaction views, the
//! tx-detail drawer shapes, the priority-weight function (with its
//! boot-time `TryFrom<&str>`), tx provenance, and the submit
//! request/response/error envelopes.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiMempoolSummary {
    pub size: u32,
    pub total_bytes: u64,
    pub capacity_count: u32,
    pub capacity_bytes: u64,
    pub revalidation_pending: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiMempoolTransactions {
    pub transactions: Vec<ApiMempoolTransaction>,
    /// Active priority-weight function for the running node — one of
    /// `"cost"`, `"size"`, `"min"`. Clients dividing `priority_weight`
    /// by 1024 and the matching denominator recover raw fee-per-resource.
    pub weight_function: ApiWeightFunction,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiMempoolTransaction {
    pub tx_id: String,
    pub fee_nano_erg: u64,
    pub fee_per_byte_nano_erg: u64,
    pub size_bytes: u32,
    /// Sigma-interpreter execution cost in block-budget units. Compare
    /// against the active epoch's `maxBlockCost`.
    pub validation_cost_units: u64,
    /// Mempool priority weight = `(fee × 1024) / denom`, where `denom`
    /// is set by `weight_function` on the envelope.
    pub priority_weight: u64,
    pub source: ApiTxSource,
    pub input_count: u32,
    pub output_count: u32,
    pub parents_in_pool: u32,
    pub first_seen_unix_ms: u64,
    pub first_seen_age_ms: u64,
    pub last_checked_age_ms: u64,
}

/// A single resolved input or output box for the tx-detail drawer.
/// `box_id`/`address`/`value`/`tokens` are all `Option` because an
/// unconfirmed tx's spent input may not resolve against the extra-index
/// or the pool-output overlay (dangling, or an indexer-lag miss). When a
/// box is unresolved the wire emits `null` for every projected field —
/// including `tokens` — so a consumer cannot mistake "unknown" for
/// "known to have no tokens" (`null` ≠ `[]`).
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiIoBox {
    pub box_id: Option<String>,
    pub address: Option<String>,
    pub value: Option<u64>,
    pub tokens: Option<Vec<ApiAsset>>,
}

/// `{tokenId, amount}` asset entry on an [`ApiIoBox`].
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiAsset {
    pub token_id: String,
    pub amount: u64,
}

/// Inputs/outputs of a transaction resolved to addresses + values for the
/// UI detail drawer, backing `GET /api/v1/transactions/{tx_id}/detail`.
///
/// No `confirmed` flag: the endpoint resolves a tx found in either the
/// extra-index or the mempool, but the extra-index is not chain-state, so
/// during indexer lag a chain-confirmed tx could be indistinguishable
/// from a pooled one — rather than emit a label that can be wrong, the
/// caller relies on its own context (the page it opened the drawer from).
/// Fee is intentionally omitted: it's shown on the mempool row already,
/// and recomputing it from possibly-unresolved inputs would be unreliable.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiTxDetail {
    pub tx_id: String,
    pub inputs: Vec<ApiIoBox>,
    pub outputs: Vec<ApiIoBox>,
}

/// Active mempool priority-weight function. Wire strings match
/// `ergo_mempool::WeightFunction::name()` exactly: `"cost"`, `"size"`,
/// `"min"`. Boot-time `TryFrom<&str>` rejects unknown names.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
pub enum ApiWeightFunction {
    #[default]
    #[serde(rename = "cost")]
    Cost,
    #[serde(rename = "size")]
    Size,
    #[serde(rename = "min")]
    Min,
}

/// Error returned by [`ApiWeightFunction::try_from`] for an unknown
/// weight-function name. The boot path propagates this as a hard
/// failure rather than silently falling back to a default.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnknownWeightFunction(pub String);

impl std::fmt::Display for UnknownWeightFunction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "unknown mempool weight function {:?}; expected one of \"cost\", \"size\", \"min\"",
            self.0
        )
    }
}

impl std::error::Error for UnknownWeightFunction {}

impl TryFrom<&str> for ApiWeightFunction {
    type Error = UnknownWeightFunction;
    fn try_from(name: &str) -> Result<Self, Self::Error> {
        match name {
            "cost" => Ok(Self::Cost),
            "size" => Ok(Self::Size),
            "min" => Ok(Self::Min),
            other => Err(UnknownWeightFunction(other.to_string())),
        }
    }
}

/// Where a mempool transaction entered our pool. Tagged union — clients
/// switch on `kind` and read `addr` only for `peer`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ApiTxSource {
    Peer { addr: String },
    Api,
    Wallet,
    DemotedFromBlock,
}

/// Submission mode picks the commit boundary inside the shared admission
/// pipeline. `Broadcast` runs steps 0–14 and commits to the pool +
/// emits `BroadcastInv`. `CheckOnly` runs steps 0–14 and stops — no
/// pool mutation, no Inv. Both still mutate the anti-DoS bookkeeping
/// per mempool invariant #7.
///
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubmitMode {
    Broadcast,
    CheckOnly,
}

/// Stable wire-shape for a submission rejection. Mirrors the keys of
/// `RejectReason` flattened to short snake_case strings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubmitError {
    pub reason: String,
    pub detail: Option<String>,
}

/// 200 body for `POST /api/v1/mempool/{submit,check}`.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiSubmitResponse {
    pub tx_id: String,
}

/// 4xx/5xx body for the Scala-compat submit endpoints
/// (`POST /transactions`, `/transactions/bytes`, `/transactions/checkBytes`).
/// Shape matches Scala's `ApiError` (`{error, reason, detail}`) where
/// `error` is the HTTP status code repeated as an integer for
/// Scala-client parity. Kept on the compat surface only.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiSubmitError {
    pub error: u16,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// 4xx/5xx body for `POST /api/v1/mempool/{submit,check}`. Identical to
/// [`ApiSubmitError`] minus the `error` field — Rust-native clients have
/// the HTTP status from the response line, so duplicating it in the body
/// is just bytes on the wire.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiNativeSubmitError {
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl From<ApiSubmitError> for ApiNativeSubmitError {
    fn from(e: ApiSubmitError) -> Self {
        Self {
            reason: e.reason,
            detail: e.detail,
        }
    }
}

/// OpenAPI request-body schema for the raw transaction bytes accepted by
/// `POST /api/v1/mempool/{submit,check}`. The handlers take an opaque
/// `axum::body::Bytes` and forward it verbatim; this renders that body as
/// `application/octet-stream` binary (`type: string, format: binary`) in
/// the generated spec. Documentation only — never constructed at runtime.
#[derive(ToSchema)]
#[schema(value_type = String, format = Binary)]
pub struct RawTransactionBytes(pub Vec<u8>);

#[cfg(test)]
mod tests {
    use super::*;

    // ----- happy path -----

    /// `Peer` variant serializes as `{"kind":"peer","addr":"..."}`.
    /// `kind` is snake_case; `addr` is the only payload field.
    #[test]
    fn api_tx_source_peer_serializes_with_kind_and_addr() {
        let src = ApiTxSource::Peer {
            addr: "159.65.11.55:9030".to_string(),
        };
        let json = serde_json::to_value(&src).unwrap();
        assert_eq!(
            json,
            serde_json::json!({ "kind": "peer", "addr": "159.65.11.55:9030" }),
            "peer wire shape regression: got {json}",
        );
    }

    /// Unit variants serialize as bare `{"kind":"..."}` with no payload.
    /// snake_case rename covers the multi-word `DemotedFromBlock`.
    #[test]
    fn api_tx_source_unit_variants_serialize_kind_only() {
        let cases: &[(ApiTxSource, &str)] = &[
            (ApiTxSource::Api, "api"),
            (ApiTxSource::Wallet, "wallet"),
            (ApiTxSource::DemotedFromBlock, "demoted_from_block"),
        ];
        for (variant, kind) in cases {
            let json = serde_json::to_value(variant).unwrap();
            assert_eq!(
                json,
                serde_json::json!({ "kind": kind }),
                "{variant:?} wire shape regression: got {json}",
            );
        }
    }

    // ----- round-trips -----

    /// Every variant survives serialize → deserialize byte-for-byte.
    /// Pins that the tag-based discriminator can be both written and
    /// read with no asymmetry.
    #[test]
    fn api_tx_source_roundtrips_all_variants() {
        let cases = [
            ApiTxSource::Peer {
                addr: "127.0.0.1:9030".to_string(),
            },
            ApiTxSource::Api,
            ApiTxSource::Wallet,
            ApiTxSource::DemotedFromBlock,
        ];
        for original in cases {
            let json = serde_json::to_string(&original).unwrap();
            let decoded: ApiTxSource = serde_json::from_str(&json).unwrap();
            assert_eq!(decoded, original, "roundtrip failed for {original:?}");
        }
    }

    // ----- error paths -----

    /// An unknown `kind` value must fail deserialization rather than
    /// silently fall through to a default variant. Pins that we don't
    /// regress to an `#[serde(other)]` catch-all.
    #[test]
    fn api_tx_source_unknown_kind_rejects() {
        let bad = serde_json::json!({ "kind": "satellite" });
        let result: Result<ApiTxSource, _> = serde_json::from_value(bad);
        assert!(
            result.is_err(),
            "unknown kind must reject, got Ok({:?})",
            result.ok(),
        );
    }

    // ----- ApiWeightFunction: happy path -----

    /// Each variant serializes to the canonical mempool name —
    /// `Cost → "cost"`, `Size → "size"`, `Min → "min"`. Matches
    /// `ergo_mempool::WeightFunction::name()` exactly so no two
    /// strings claim to mean the same policy.
    #[test]
    fn api_weight_function_serializes_to_canonical_lowercase() {
        let cases = [
            (ApiWeightFunction::Cost, "cost"),
            (ApiWeightFunction::Size, "size"),
            (ApiWeightFunction::Min, "min"),
        ];
        for (variant, expected) in cases {
            let json = serde_json::to_value(variant).unwrap();
            assert_eq!(
                json,
                serde_json::Value::String(expected.to_string()),
                "{variant:?} must serialize as {expected:?}, got {json}",
            );
        }
    }

    // ----- ApiWeightFunction: round-trips -----

    #[test]
    fn api_weight_function_roundtrips_all_variants() {
        let cases = [
            ApiWeightFunction::Cost,
            ApiWeightFunction::Size,
            ApiWeightFunction::Min,
        ];
        for variant in cases {
            let json = serde_json::to_string(&variant).unwrap();
            let decoded: ApiWeightFunction = serde_json::from_str(&json).unwrap();
            assert_eq!(decoded, variant);
        }
    }

    // ----- ApiWeightFunction: TryFrom<&str> contract -----

    #[test]
    fn api_weight_function_try_from_accepts_canonical_names() {
        assert_eq!(
            ApiWeightFunction::try_from("cost").unwrap(),
            ApiWeightFunction::Cost,
        );
        assert_eq!(
            ApiWeightFunction::try_from("size").unwrap(),
            ApiWeightFunction::Size,
        );
        assert_eq!(
            ApiWeightFunction::try_from("min").unwrap(),
            ApiWeightFunction::Min,
        );
    }

    // ----- ApiWeightFunction: error paths -----

    /// Unknown names propagate as `UnknownWeightFunction(name)` —
    /// the boot path surfaces this as `NodeError` and refuses to
    /// start. No silent fallback, no `"unknown"` wire sentinel.
    #[test]
    fn api_weight_function_try_from_rejects_unknown() {
        let err = ApiWeightFunction::try_from("by_cost").unwrap_err();
        assert_eq!(err, UnknownWeightFunction("by_cost".to_string()));
        // Error message includes the bad name so the boot log is actionable.
        let msg = err.to_string();
        assert!(
            msg.contains("by_cost"),
            "error message must echo input: {msg}"
        );
        assert!(
            msg.contains("cost"),
            "error message must list canonical names: {msg}"
        );
    }

    /// Unit Default → `Cost`. `ApiMempoolTransactions::default()`
    /// downstream relies on this for empty-snapshot stubs that don't
    /// know the configured policy.
    #[test]
    fn api_weight_function_default_is_cost() {
        assert_eq!(ApiWeightFunction::default(), ApiWeightFunction::Cost);
    }

    #[test]
    fn api_native_submit_error_omits_redundant_http_status_field() {
        // Rust-native clients have the HTTP status from the response line
        // already; duplicating it in the body is just bytes on the wire.
        // Pin the absence so a future refactor cannot accidentally
        // reintroduce the `error` field on the native shape.
        let e = ApiNativeSubmitError {
            reason: "non_canonical".to_string(),
            detail: Some("amount mismatch".to_string()),
        };
        let v = serde_json::to_value(&e).unwrap();
        let obj = v.as_object().expect("object");
        assert!(
            !obj.contains_key("error"),
            "native shape must not duplicate the HTTP status code as `error`"
        );
        assert_eq!(
            obj.get("reason").and_then(|x| x.as_str()),
            Some("non_canonical"),
        );
        assert_eq!(
            obj.get("detail").and_then(|x| x.as_str()),
            Some("amount mismatch"),
        );
    }

    #[test]
    fn api_native_submit_error_omits_detail_when_none() {
        let v = serde_json::to_value(ApiNativeSubmitError {
            reason: "pool_full".to_string(),
            detail: None,
        })
        .unwrap();
        let obj = v.as_object().expect("object");
        assert!(
            !obj.contains_key("detail"),
            "absent detail must omit the key, not serialize as null"
        );
    }

    #[test]
    fn api_native_submit_error_projects_from_scala_compat_shape() {
        // The `From<ApiSubmitError>` impl drops `.error` and keeps
        // `reason` / `detail`. Pin field-by-field so a future expansion
        // of either type can't silently lose data.
        let compat = ApiSubmitError {
            error: 503,
            reason: "overloaded".to_string(),
            detail: Some("retry".to_string()),
        };
        let native: ApiNativeSubmitError = compat.into();
        assert_eq!(native.reason, "overloaded");
        assert_eq!(native.detail.as_deref(), Some("retry"));
    }

    #[test]
    fn api_mempool_transactions_envelope_does_not_emit_redundant_size() {
        // The envelope's pre-rename `size` field duplicated `transactions.len()`
        // exactly (the producer wrote `transactions.len() as u32`); dropping
        // it means clients read the array length directly. Pin the absence
        // so a future refactor cannot accidentally reintroduce the field.
        let v = serde_json::to_value(ApiMempoolTransactions {
            transactions: Vec::new(),
            weight_function: ApiWeightFunction::Cost,
        })
        .unwrap();
        let obj = v.as_object().expect("object");
        assert!(
            !obj.contains_key("size"),
            "the redundant size field must not appear on the wire"
        );
        assert!(
            obj.contains_key("transactions"),
            "transactions array must remain on the wire"
        );
        assert!(
            obj.contains_key("weight_function"),
            "weight_function tag must remain on the wire"
        );
    }
}
