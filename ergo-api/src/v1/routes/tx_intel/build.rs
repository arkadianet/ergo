//! `POST /api/v1/transactions/build` — keyless intent -> unsigned tx:
//! the intent DTOs, the handler, the intent-shaping helpers, and the
//! build-error mapping.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use ergo_ser::address::decode_address_to_tree_bytes;

use super::super::extract::V1Json;
use super::super::V1State;
use super::{err, is_id64, parse_amount, MAX_INPUTS, MAX_OUTPUTS};
use crate::traits::{
    BuiltUnsigned, KeylessAsset, KeylessBuildRequest, KeylessFee, KeylessInputs, KeylessOutput,
    KeylessTarget,
};
use crate::v1::error::{Reason, V1Error};

// ==========================================================================
//  POST /transactions/build
// ==========================================================================

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct BuildBody {
    inputs: InputsDto,
    outputs: Vec<OutputDto>,
    #[serde(default)]
    data_inputs: Option<DataInputsDto>,
    #[serde(default)]
    fee: Option<FeeDto>,
    change_address: String,
    #[serde(default)]
    context: Option<ContextDto>,
    #[serde(default)]
    allow_token_burn: bool,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum InputsDto {
    Select {
        #[serde(default)]
        from_addresses: Vec<String>,
        #[serde(default = "default_min_conf")]
        min_confirmations: i64,
        #[serde(default)]
        exclude_box_ids: Vec<String>,
        #[serde(default)]
        target: Option<String>,
    },
    BoxIds {
        box_ids: Vec<String>,
    },
    Boxes {
        boxes: Vec<String>,
    },
}

fn default_min_conf() -> i64 {
    1
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum OutputDto {
    Payment {
        address: String,
        value: String,
        #[serde(default)]
        assets: Vec<AssetDto>,
        #[serde(default)]
        registers: Option<serde_json::Map<String, serde_json::Value>>,
    },
    Mint {
        address: String,
        amount: String,
    },
    Burn {
        assets: Vec<AssetDto>,
    },
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct AssetDto {
    token_id: String,
    amount: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum DataInputsDto {
    BoxIds { box_ids: Vec<String> },
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum FeeDto {
    Auto {
        #[serde(default = "default_target_blocks")]
        target_blocks: u32,
    },
    Fixed {
        value: String,
    },
}

fn default_target_blocks() -> u32 {
    3
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct ContextDto {
    height: u32,
}

#[derive(Debug, Serialize, ToSchema)]
struct WireBytes {
    #[serde(rename = "type")]
    kind: &'static str,
    bytes: String,
}

#[derive(Debug, Serialize, ToSchema)]
struct WireAsset {
    token_id: String,
    amount: String,
}

#[derive(Debug, Serialize, ToSchema)]
struct WireChange {
    address: String,
    value: String,
    assets: Vec<WireAsset>,
}

#[derive(Debug, Serialize, ToSchema)]
struct BuildSummary {
    input_box_ids: Vec<String>,
    selected_value: String,
    fee: String,
    fee_source: String,
    change: Vec<WireChange>,
    size_bytes: u32,
    estimated_cost_units: u64,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct BuildResponse {
    unsigned_tx: WireBytes,
    tx_id: String,
    summary: BuildSummary,
}

/// `POST /api/v1/transactions/build` — keyless `tx_intent` → unsigned tx. T0:
/// no secret material crosses this boundary (explicit inputs + change address).
#[utoipa::path(
    post, path = "/api/v1/transactions/build", tag = "transactions",
    request_body = BuildBody,
    responses(
        (status = 200, description = "Unsigned tx + summary", body = BuildResponse),
        (status = 400, description = "Invalid intent (bad address/amount/too many inputs)", body = V1Error),
        (status = 404, description = "No spendable inputs found", body = V1Error),
        (status = 409, description = "Extra index disabled", body = V1Error),
        (status = 422, description = "Well-formed but not-yet-supported intent (mint/burn/registers/raw boxes)", body = V1Error),
        (status = 500, description = "Build failed", body = V1Error),
        (status = 503, description = "Keyless builder not wired on this node", body = V1Error),
    ),
)]
pub async fn build(State(state): State<V1State>, body: V1Json<BuildBody>) -> Response {
    let V1Json(body) = body;
    match build_inner(&state, body).await {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err(resp) => *resp,
    }
}

async fn build_inner(state: &V1State, body: BuildBody) -> Result<BuildResponse, Box<Response>> {
    if body.outputs.is_empty() {
        return Err(err(
            Reason::BadRequest,
            "an intent needs at least one output",
            "add a payment output to `outputs`",
        ));
    }
    if body.outputs.len() > MAX_OUTPUTS {
        return Err(err(
            Reason::IntentTooLarge,
            "too many outputs",
            format!("outputs are capped at {MAX_OUTPUTS}"),
        ));
    }

    // Change address is REQUIRED and must be valid for this network.
    decode_address_to_tree_bytes(&body.change_address, state.network).map_err(|e| {
        err(
            Reason::InvalidAddress,
            "change_address is not valid base58 for this network",
            e.to_string(),
        )
    })?;

    let inputs = shape_inputs(state, body.inputs)?;
    let outputs = shape_outputs(state, body.outputs)?;
    let data_input_box_ids = shape_data_inputs(body.data_inputs)?;
    let fee = shape_fee(body.fee)?;

    let request = KeylessBuildRequest {
        inputs,
        outputs,
        data_input_box_ids,
        fee,
        change_address: body.change_address,
        context_height: body.context.map(|c| c.height),
        allow_token_burn: body.allow_token_burn,
    };

    let Some(builder) = state.tx_builder.as_ref() else {
        return Err(err(
            Reason::RouteUnavailable,
            "the keyless transaction builder is not wired on this node",
            "build requires the extracted keyless TxBuilder",
        ));
    };

    match builder.build_unsigned(request).await {
        Ok(built) => Ok(render_built(built)),
        Err(e) => Err(map_build_error(&e.reason, e.detail)),
    }
}

fn shape_inputs(state: &V1State, inputs: InputsDto) -> Result<KeylessInputs, Box<Response>> {
    match inputs {
        InputsDto::Select {
            from_addresses,
            min_confirmations,
            exclude_box_ids,
            target,
        } => {
            if from_addresses.len() > MAX_INPUTS {
                return Err(err(
                    Reason::IntentTooLarge,
                    "too many source addresses",
                    format!("from_addresses is capped at {MAX_INPUTS}"),
                ));
            }
            if exclude_box_ids.len() > MAX_INPUTS {
                return Err(err(
                    Reason::IntentTooLarge,
                    "too many excluded box ids",
                    format!("exclude_box_ids is capped at {MAX_INPUTS}"),
                ));
            }
            // `-1` is the documented include-pool sentinel; anything below it
            // is meaningless, never a valid depth.
            if min_confirmations < -1 {
                return Err(err(
                    Reason::InvalidParams,
                    "min_confirmations must be >= -1",
                    "-1 includes pool outputs; 0+ is a confirmed depth",
                ));
            }
            for addr in &from_addresses {
                decode_address_to_tree_bytes(addr, state.network).map_err(|e| {
                    err(
                        Reason::InvalidAddress,
                        "a from_addresses entry is not valid base58 for this network",
                        e.to_string(),
                    )
                })?;
            }
            for id in &exclude_box_ids {
                if !is_id64(id) {
                    return Err(err(
                        Reason::InvalidBoxId,
                        "an exclude_box_ids entry is not a 64-char hex box id",
                        "supply unprefixed hex box ids",
                    ));
                }
            }
            let target = match target.as_deref() {
                None | Some("auto") => KeylessTarget::Auto,
                Some(s) => KeylessTarget::Value(parse_amount(s, "target")?),
            };
            Ok(KeylessInputs::Select {
                from_addresses,
                min_confirmations,
                exclude_box_ids,
                target,
            })
        }
        InputsDto::BoxIds { box_ids } => {
            if box_ids.is_empty() {
                return Err(err(
                    Reason::NoInputsFound,
                    "box_ids selection named no inputs",
                    "supply at least one input box id",
                ));
            }
            if box_ids.len() > MAX_INPUTS {
                return Err(err(
                    Reason::IntentTooLarge,
                    "too many input box ids",
                    format!("box_ids is capped at {MAX_INPUTS}"),
                ));
            }
            for id in &box_ids {
                if !is_id64(id) {
                    return Err(err(
                        Reason::InvalidBoxId,
                        "a box_ids entry is not a 64-char hex box id",
                        "supply unprefixed hex box ids",
                    ));
                }
            }
            Ok(KeylessInputs::BoxIds { box_ids })
        }
        // Raw pre-resolved boxes need off-chain assembly the keyless builder
        // does not yet accept — well-formed but unwired (additive 422→200).
        InputsDto::Boxes { boxes } => Err(err(
            Reason::UnsupportedIntent,
            "raw `boxes` inputs are not supported yet",
            format!(
                "use `select` (from_addresses) or `box_ids` inputs; got {} raw box(es)",
                boxes.len()
            ),
        )),
    }
}

fn shape_outputs(
    state: &V1State,
    outputs: Vec<OutputDto>,
) -> Result<Vec<KeylessOutput>, Box<Response>> {
    let mut out = Vec::with_capacity(outputs.len());
    for o in outputs {
        match o {
            OutputDto::Payment {
                address,
                value,
                assets,
                registers,
            } => {
                if registers.is_some() {
                    // Register-carrying payments need typed-constant encoding
                    // the builder does not yet wire — additive 422→200.
                    return Err(err(
                        Reason::UnsupportedIntent,
                        "payment `registers` are not supported yet",
                        "omit `registers`; register-carrying outputs ship later",
                    ));
                }
                decode_address_to_tree_bytes(&address, state.network).map_err(|e| {
                    err(
                        Reason::InvalidAddress,
                        "an output address is not valid base58 for this network",
                        e.to_string(),
                    )
                })?;
                let value_nano_erg = parse_amount(&value, "output value")?;
                let mut shaped_assets = Vec::with_capacity(assets.len());
                for a in assets {
                    if !is_id64(&a.token_id) {
                        return Err(err(
                            Reason::InvalidTokenId,
                            "an output asset token_id is not a 64-char hex id",
                            "supply unprefixed hex token ids",
                        ));
                    }
                    shaped_assets.push(KeylessAsset {
                        token_id: a.token_id,
                        amount: parse_amount(&a.amount, "asset amount")?,
                    });
                }
                out.push(KeylessOutput {
                    address,
                    value_nano_erg,
                    assets: shaped_assets,
                });
            }
            // Token minting derives a new id + EIP-4 registers the builder does
            // not yet wire; token burn likewise (allow_token_burn is reserved).
            OutputDto::Mint { address, amount } => {
                return Err(err(
                    Reason::UnsupportedIntent,
                    "`mint` outputs are not supported yet",
                    format!("token minting ships later; requested mint of {amount} to {address}"),
                ))
            }
            OutputDto::Burn { assets } => {
                return Err(err(
                    Reason::UnsupportedIntent,
                    "`burn` outputs are not supported yet",
                    format!(
                        "token burning ships later; requested burn of {} asset kind(s)",
                        assets.len()
                    ),
                ))
            }
        }
    }
    Ok(out)
}

fn shape_data_inputs(data_inputs: Option<DataInputsDto>) -> Result<Vec<String>, Box<Response>> {
    let ids = match data_inputs {
        None => Vec::new(),
        Some(DataInputsDto::BoxIds { box_ids }) => box_ids,
    };
    if ids.len() > MAX_INPUTS {
        return Err(err(
            Reason::IntentTooLarge,
            "too many data-input box ids",
            format!("data_inputs box_ids is capped at {MAX_INPUTS}"),
        ));
    }
    for id in &ids {
        if !is_id64(id) {
            return Err(err(
                Reason::InvalidBoxId,
                "a data_inputs box id is not a 64-char hex id",
                "supply unprefixed hex box ids",
            ));
        }
    }
    Ok(ids)
}

fn shape_fee(fee: Option<FeeDto>) -> Result<KeylessFee, Box<Response>> {
    Ok(match fee {
        None => KeylessFee::Auto {
            target_blocks: default_target_blocks(),
        },
        Some(FeeDto::Auto { target_blocks }) => KeylessFee::Auto { target_blocks },
        Some(FeeDto::Fixed { value }) => KeylessFee::Fixed {
            value: parse_amount(&value, "fee value")?,
        },
    })
}

fn render_built(built: BuiltUnsigned) -> BuildResponse {
    BuildResponse {
        unsigned_tx: WireBytes {
            kind: "bytes",
            bytes: hex::encode(&built.unsigned_tx_bytes),
        },
        tx_id: built.tx_id,
        summary: BuildSummary {
            input_box_ids: built.input_box_ids,
            selected_value: built.selected_value_nano_erg.to_string(),
            fee: built.fee_nano_erg.to_string(),
            fee_source: built.fee_source,
            change: built
                .change
                .into_iter()
                .map(|c| WireChange {
                    address: c.address,
                    value: c.value_nano_erg.to_string(),
                    assets: c
                        .assets
                        .into_iter()
                        .map(|a| WireAsset {
                            token_id: a.token_id,
                            amount: a.amount.to_string(),
                        })
                        .collect(),
                })
                .collect(),
            size_bytes: built.size_bytes,
            estimated_cost_units: built.estimated_cost_units,
        },
    }
}

/// Map a [`crate::traits::TxBuildError`] reason verb onto the canonical v1
/// [`Reason`]. Unknown verbs fail closed as an internal error (never a silent
/// success or a fabricated plan).
fn map_build_error(reason: &str, detail: Option<String>) -> Box<Response> {
    let (r, msg) = match reason {
        "insufficient_funds" => (
            Reason::InsufficientFunds,
            "the inputs cannot cover outputs + fee",
        ),
        "no_inputs_found" => (Reason::NoInputsFound, "no spendable inputs were found"),
        "invalid_address" => (
            Reason::InvalidAddress,
            "an address in the intent is invalid",
        ),
        "invalid_token_id" => (
            Reason::InvalidTokenId,
            "a token id in the intent is invalid",
        ),
        "dust_change" => (
            Reason::DustChange,
            "the computed change is below the dust floor",
        ),
        "unsupported_intent" => (
            Reason::UnsupportedIntent,
            "the intent is well-formed but unwired",
        ),
        "intent_too_large" => (Reason::IntentTooLarge, "the intent exceeds the build caps"),
        "indexer_disabled" => (
            Reason::IndexerDisabled,
            "coin selection requires the extra index",
        ),
        "route_disabled" => (
            Reason::RouteUnavailable,
            "the keyless transaction builder is not wired on this node",
        ),
        _ => (Reason::InternalError, "the transaction build failed"),
    };
    err(r, msg, detail.unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_build_error_maps_known_verbs() {
        // Sample the load-bearing arms + the fail-closed default.
        let mk = |r: &str| map_build_error(r, None).status();
        assert_eq!(mk("insufficient_funds"), StatusCode::BAD_REQUEST);
        assert_eq!(mk("unsupported_intent"), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(mk("indexer_disabled"), StatusCode::CONFLICT);
        assert_eq!(mk("route_disabled"), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(mk("brand_new_verb"), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
