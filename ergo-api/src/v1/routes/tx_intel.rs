//! `transactions/*` intelligence group — the `v1-api-design.md` §3.6 Phase-2
//! subset (with §4.2): intent-based `build`, non-mutating `simulate` (G8), the
//! mempool `fee-estimate` oracle, and lifecycle `status`.
//!
//! These are the "help me transact" endpoints. Two are honestly backed by
//! existing node hooks today — `fee-estimate` (the chain reader's
//! `pool_recommended_fee`/`pool_expected_wait_time_ms`) and `status` (the pool
//! snapshot + the extra index) — and two ride net-new node seams that ship
//! honest-unavailable until the node wires them:
//!
//! - `build` delegates to [`crate::traits::NodeTxBuilder`] — the ONE keyless
//!   builder (O7). `V1State::tx_builder` is `None` until the extracted core is
//!   wired, and the endpoint answers `route_unavailable` (never fake coin
//!   selection).
//! - `simulate` delegates to [`crate::traits::NodeSubmit::simulate`], a
//!   **non-mutating** validate entrypoint (G8). It must never use
//!   [`SubmitMode::CheckOnly`], which still mutates the mempool anti-DoS
//!   bookkeeping (mempool invariant #7); the default impl is unavailable so a
//!   node without the read-only validator answers `route_unavailable`.
//!
//! `build`/`simulate` sit at the governor's `Compute` class (they run coin
//! selection / validation); `fee-estimate`/`status` sit at `HeavyRead`.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use ergo_indexer_types::{IndexerStatus, TxId};
use ergo_ser::address::decode_address_to_tree_bytes;

use super::dto::unix_ms_to_iso;
use super::extract::{V1Json, V1Query};
use super::V1State;
use crate::traits::{
    BuiltUnsigned, KeylessAsset, KeylessBuildRequest, KeylessFee, KeylessInputs, KeylessOutput,
    KeylessTarget, SimulateOutcome,
};
use crate::v1::error::{v1_error, Reason};

// ----- caps (§2.2 tx-intelligence row) ------------------------------------

/// Max outputs an intent may request.
const MAX_OUTPUTS: usize = 128;
/// Max explicit inputs (box ids / select universe) an intent may name.
const MAX_INPUTS: usize = 256;
/// Max assembled-tx body accepted by `simulate` (bytes).
const MAX_SIMULATE_BYTES: usize = 512 * 1024;
/// Default assumed tx size (bytes) for `fee-estimate` when the caller omits it.
const DEFAULT_TX_SIZE_BYTES: u32 = 200;
/// The fee tiers `fee-estimate` always reports, in target-blocks.
const FEE_TIERS: [u32; 3] = [1, 3, 10];
/// Long horizon (minutes) whose recommended fee converges to the protocol
/// floor — the node's `pool_recommended_fee` returns the size-scaled minimum
/// once the wait exceeds the fee buckets.
const FLOOR_HORIZON_MINUTES: u32 = 24 * 60;

// ----- shared helpers -----------------------------------------------------

fn invalid_tx_id() -> Response {
    v1_error(
        Reason::InvalidTxId,
        "tx_id is not a 64-character lowercase hex string",
        "supply an unprefixed lowercase hex transaction id",
    )
}

/// An unprefixed 64-char LOWERCASE hex id (tx / box / token) — the shared v1
/// modifier-id contract, so intent-shaping rejects uppercase/mixed-case
/// exactly like every other v1 id surface.
fn is_id64(s: &str) -> bool {
    super::valid_modifier_id(s)
}

/// A boxed v1 error — the intent-shaping helpers return `Result<_, Box<Response>>`
/// so the `Ok` value stays small (repo convention; a rendered [`Response`] is
/// large — clippy `result_large_err`).
fn err(reason: Reason, message: impl Into<String>, detail: impl Into<String>) -> Box<Response> {
    Box::new(v1_error(reason, message, detail))
}

/// Parse a decimal nanoERG amount string, or the honest `invalid_params`.
fn parse_amount(s: &str, what: &str) -> Result<u64, Box<Response>> {
    s.parse::<u64>().map_err(|_| {
        err(
            Reason::InvalidParams,
            format!("{what} must be a decimal nanoERG amount string"),
            "amounts are u64 encoded as base-10 strings (§1.1)",
        )
    })
}

// ==========================================================================
//  POST /transactions/build
// ==========================================================================

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AssetDto {
    token_id: String,
    amount: String,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum DataInputsDto {
    BoxIds { box_ids: Vec<String> },
}

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContextDto {
    height: u32,
}

#[derive(Debug, Serialize)]
struct WireBytes {
    #[serde(rename = "type")]
    kind: &'static str,
    bytes: String,
}

#[derive(Debug, Serialize)]
struct WireAsset {
    token_id: String,
    amount: String,
}

#[derive(Debug, Serialize)]
struct WireChange {
    address: String,
    value: String,
    assets: Vec<WireAsset>,
}

#[derive(Debug, Serialize)]
struct BuildSummary {
    input_box_ids: Vec<String>,
    selected_value: String,
    fee: String,
    fee_source: String,
    change: Vec<WireChange>,
    size_bytes: u32,
    estimated_cost_units: u64,
}

#[derive(Debug, Serialize)]
struct BuildResponse {
    unsigned_tx: WireBytes,
    tx_id: String,
    summary: BuildSummary,
}

/// `POST /api/v1/transactions/build` — keyless `tx_intent` → unsigned tx. T0:
/// no secret material crosses this boundary (explicit inputs + change address).
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
            "build requires the extracted keyless TxBuilder (v1-api-design.md §4.2 O7)",
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
                    format!(
 "token minting ships later (v1-api-design.md §4.2); requested mint of {amount} to {address}"
                    ),
                ))
            }
            OutputDto::Burn { assets } => {
                return Err(err(
                    Reason::UnsupportedIntent,
                    "`burn` outputs are not supported yet",
                    format!(
 "token burning ships later (v1-api-design.md §4.2); requested burn of {} asset kind(s)",
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

// ==========================================================================
//  POST /transactions/simulate
// ==========================================================================

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SimulateBody {
    tx: TxReprDto,
    #[serde(default)]
    assume_context: Option<AssumeContextDto>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum TxReprDto {
    Bytes { bytes: String },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AssumeContextDto {
    height: u32,
}

#[derive(Debug, Serialize)]
struct WireConflict {
    box_id: String,
    conflicting_tx_id: String,
}

#[derive(Debug, Serialize)]
struct SimulateResponse {
    valid: bool,
    tx_id: String,
    cost_units: u64,
    max_block_cost: u64,
    size_bytes: u32,
    fee: String,
    min_fee_required: String,
    fee_sufficient: bool,
    spends_unknown_inputs: bool,
    conflicts: Vec<WireConflict>,
    warnings: Vec<String>,
}

/// `POST /api/v1/transactions/simulate` — dry-run an assembled tx: accept/reject
/// + cost + conflicts, NO broadcast and NO mempool mutation (G8).
pub async fn simulate(State(state): State<V1State>, body: V1Json<SimulateBody>) -> Response {
    let V1Json(body) = body;
    let TxReprDto::Bytes { bytes } = body.tx;
    let bytes = match hex::decode(bytes.trim()) {
        Ok(b) => b,
        Err(e) => {
            return v1_error(
                Reason::Deserialize,
                "tx bytes are not valid hex",
                format!("hex decode: {e}"),
            )
        }
    };
    if bytes.len() > MAX_SIMULATE_BYTES {
        return v1_error(
            Reason::IntentTooLarge,
            "assembled tx exceeds the simulate body cap",
            format!("tx bytes are capped at {MAX_SIMULATE_BYTES} bytes"),
        );
    }

    let Some(submit) = state.submit.as_ref() else {
        return v1_error(
            Reason::SubmitDisabled,
            "transaction validation is not wired on this node",
            "the submit bridge is unavailable in this configuration",
        );
    };

    let assume_height = body.assume_context.map(|c| c.height);
    match submit.simulate(bytes, assume_height).await {
        Ok(outcome) => Json(render_sim(outcome)).into_response(),
        // A malformed/transient rejection is an error envelope; a cleanly
        // invalid-but-simulable tx returns `Ok(valid:false)` above, as a 200.
        Err(e) => v1_error(
            super::transactions::submit_reason(&e.reason),
            "the transaction could not be simulated",
            e.detail.unwrap_or_default(),
        ),
    }
}

fn render_sim(o: SimulateOutcome) -> SimulateResponse {
    SimulateResponse {
        valid: o.valid,
        tx_id: o.tx_id,
        cost_units: o.cost_units,
        max_block_cost: o.max_block_cost,
        size_bytes: o.size_bytes,
        fee: o.fee_nano_erg.to_string(),
        min_fee_required: o.min_fee_required_nano_erg.to_string(),
        fee_sufficient: o.fee_sufficient,
        spends_unknown_inputs: o.spends_unknown_inputs,
        conflicts: o
            .conflicts
            .into_iter()
            .map(|c| WireConflict {
                box_id: c.box_id,
                conflicting_tx_id: c.conflicting_tx_id,
            })
            .collect(),
        warnings: o.warnings,
    }
}

// ==========================================================================
//  GET /transactions/fee-estimate
// ==========================================================================

#[derive(Debug, Default, Deserialize)]
pub struct FeeEstimateQuery {
    #[serde(default)]
    target_blocks: Option<u32>,
    #[serde(default)]
    tx_size_bytes: Option<u32>,
}

#[derive(Debug, Serialize)]
struct FeeTier {
    target_blocks: u32,
    fee_per_byte: String,
    recommended_fee: String,
}

#[derive(Debug, Serialize)]
struct FeeEstimateResponse {
    target_blocks: u32,
    tx_size_bytes: u32,
    recommended_fee: String,
    fee_per_byte: String,
    tiers: Vec<FeeTier>,
    pool_size: u32,
    floor_fee_per_byte: String,
}

/// `GET /api/v1/transactions/fee-estimate?target_blocks=1|3|10&tx_size_bytes=` —
/// mempool-derived fee tiers (nanoERG-per-byte as strings). Backed by the chain
/// reader's `pool_recommended_fee`; honest `mempool_view_disabled` if unwired.
pub async fn fee_estimate(
    State(state): State<V1State>,
    V1Query(q): V1Query<FeeEstimateQuery>,
) -> Response {
    let target_blocks = q.target_blocks.unwrap_or(3);
    if !FEE_TIERS.contains(&target_blocks) {
        return v1_error(
            Reason::InvalidParams,
            "target_blocks must be 1, 3, or 10",
            "pick one of the supported fee horizons",
        );
    }
    let size = q.tx_size_bytes.unwrap_or(DEFAULT_TX_SIZE_BYTES);
    if size == 0 {
        return v1_error(
            Reason::InvalidParams,
            "tx_size_bytes must be a positive byte count",
            "omit tx_size_bytes to use the nominal default",
        );
    }

    let Some(chain) = state.chain.as_ref() else {
        return v1_error(
            Reason::MempoolViewDisabled,
            "fee estimation requires the chain-reader mempool bridge",
            "this node was wired without the pool fee oracle",
        );
    };

    let interval_ms = state.read.info().target_block_interval_ms.max(1);
    let per_byte = |fee: u64| (fee / u64::from(size)).to_string();

    let tiers: Vec<FeeTier> = FEE_TIERS
        .iter()
        .map(|&tb| {
            let minutes = tier_minutes(tb, interval_ms);
            let fee = chain.pool_recommended_fee(minutes, size);
            FeeTier {
                target_blocks: tb,
                fee_per_byte: per_byte(fee),
                recommended_fee: fee.to_string(),
            }
        })
        .collect();

    let selected = tiers
        .iter()
        .find(|t| t.target_blocks == target_blocks)
        .expect("target_blocks is one of FEE_TIERS");
    let floor_fee = chain.pool_recommended_fee(FLOOR_HORIZON_MINUTES, size);

    Json(FeeEstimateResponse {
        target_blocks,
        tx_size_bytes: size,
        recommended_fee: selected.recommended_fee.clone(),
        fee_per_byte: selected.fee_per_byte.clone(),
        pool_size: state.read.mempool_summary().size,
        floor_fee_per_byte: per_byte(floor_fee),
        tiers,
    })
    .into_response()
}

/// Wait-time (minutes) for a `target_blocks` horizon, at least 1 minute.
fn tier_minutes(target_blocks: u32, interval_ms: u64) -> u32 {
    let ms = u64::from(target_blocks) * interval_ms;
    let minutes = ms.div_ceil(60_000);
    minutes.max(1).min(u64::from(u32::MAX)) as u32
}

// ==========================================================================
//  GET /transactions/{tx_id}/status
// ==========================================================================

#[derive(Debug, Serialize)]
struct PoolStatus {
    priority_weight: String,
    fee: String,
    fee_per_byte: String,
    rank: u32,
    pool_size: u32,
    ahead_of_you_bytes: u64,
    fee_competitiveness_pct: f64,
    /// `null` when the node has no pool wait-time oracle wired — a missing
    /// estimate must not read as "next block".
    #[serde(skip_serializing_if = "Option::is_none")]
    eta_blocks: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    eta_ms: Option<u64>,
    parents_in_pool: u32,
}

#[derive(Debug, Serialize)]
struct StatusResponse {
    tx_id: String,
    state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pool: Option<PoolStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    first_seen_unix_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    first_seen_iso: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    inclusion_height: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    confirmations: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    header_id: Option<String>,
}

/// `GET /api/v1/transactions/{tx_id}/status` — lifecycle + ETA. Confirmed
/// (extra-index) wins over pooled; a well-formed unknown id is a 200
/// `state:"unknown"` (a legitimate polled answer), only a malformed id is a 400.
pub async fn status(State(state): State<V1State>, Path(tx_id_hex): Path<String>) -> Response {
    let Some(raw) = super::parse_id32(&tx_id_hex) else {
        return invalid_tx_id();
    };
    let tx_id = TxId::from_bytes(raw);

    // Confirmed path (extra index, when caught up).
    if let Some(indexer) = state.indexer.as_ref() {
        if matches!(indexer.status(), IndexerStatus::CaughtUp) {
            if let Some(itx) = indexer.tx_by_id(&tx_id) {
                let bstate = state.blockchain_state(indexer);
                return match crate::blockchain::build_indexed_tx_response(&bstate, &itx) {
                    Ok(resp) => Json(StatusResponse {
                        tx_id: resp.id,
                        state: "confirmed",
                        pool: None,
                        first_seen_unix_ms: None,
                        first_seen_iso: None,
                        inclusion_height: Some(resp.inclusion_height),
                        confirmations: Some(i64::from(resp.num_confirmations)),
                        header_id: Some(resp.block_id),
                    })
                    .into_response(),
                    Err(detail) => v1_error(
                        Reason::InternalError,
                        "failed to assemble the confirmed transaction status",
                        detail,
                    ),
                };
            }
        }
    }

    // Pooled path.
    if let Some(row) = state.read.mempool_transaction(&tx_id_hex) {
        return Json(pooled_status(&state, row)).into_response();
    }

    // Unknown: a legitimate lifecycle answer, not an error.
    Json(StatusResponse {
        tx_id: tx_id_hex,
        state: "unknown",
        pool: None,
        first_seen_unix_ms: None,
        first_seen_iso: None,
        inclusion_height: None,
        confirmations: None,
        header_id: None,
    })
    .into_response()
}

fn pooled_status(state: &V1State, row: crate::types::ApiMempoolTransaction) -> StatusResponse {
    let rows = state.read.mempool_transactions().transactions;
    let pool_size = rows.len() as u32;

    // Rank in the mining order (priority-weight DESC, tx_id ASC tiebreak) and
    // the total size of everything strictly ahead. One ordered pass.
    let mut ahead_bytes: u64 = 0;
    let mut rank: u32 = 1;
    let mut max_fpb: u64 = row.fee_per_byte_nano_erg;
    for other in &rows {
        max_fpb = max_fpb.max(other.fee_per_byte_nano_erg);
        if other.tx_id == row.tx_id {
            continue;
        }
        let ahead = other.priority_weight > row.priority_weight
            || (other.priority_weight == row.priority_weight && other.tx_id < row.tx_id);
        if ahead {
            rank += 1;
            ahead_bytes += u64::from(other.size_bytes);
        }
    }

    let competitiveness = if max_fpb == 0 {
        1.0
    } else {
        row.fee_per_byte_nano_erg as f64 / max_fpb as f64
    };

    let interval_ms = state.read.info().target_block_interval_ms.max(1);
    // No wait-time oracle (chain reader unwired) → an honest null, never a
    // fabricated one-block estimate.
    let eta_ms = state
        .chain
        .as_ref()
        .map(|c| c.pool_expected_wait_time_ms(row.fee_nano_erg, row.size_bytes));
    let eta_blocks =
        eta_ms.map(|ms| (ms.div_ceil(interval_ms)).max(1).min(u64::from(u32::MAX)) as u32);

    StatusResponse {
        tx_id: row.tx_id.clone(),
        state: "pending",
        pool: Some(PoolStatus {
            priority_weight: row.priority_weight.to_string(),
            fee: row.fee_nano_erg.to_string(),
            fee_per_byte: row.fee_per_byte_nano_erg.to_string(),
            rank,
            pool_size,
            ahead_of_you_bytes: ahead_bytes,
            fee_competitiveness_pct: competitiveness,
            eta_blocks,
            eta_ms,
            parents_in_pool: row.parents_in_pool,
        }),
        first_seen_unix_ms: Some(row.first_seen_unix_ms),
        first_seen_iso: Some(unix_ms_to_iso(row.first_seen_unix_ms)),
        inclusion_height: None,
        confirmations: None,
        header_id: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    // ----- happy path -----

    #[test]
    fn tier_minutes_rounds_up_and_floors_at_one() {
        // 120s block interval → 1/3/10-block horizons.
        assert_eq!(tier_minutes(1, 120_000), 2);
        assert_eq!(tier_minutes(3, 120_000), 6);
        assert_eq!(tier_minutes(10, 120_000), 20);
        // Sub-minute horizons floor at 1 minute.
        assert_eq!(tier_minutes(1, 1_000), 1);
    }

    #[test]
    fn is_id64_accepts_only_64_lowercase_hex() {
        assert!(is_id64(&"a".repeat(64)));
        assert!(!is_id64(&"a".repeat(63)));
        assert!(!is_id64(&"g".repeat(64)));
        // Uppercase is non-canonical — same contract as `valid_modifier_id`.
        assert!(!is_id64(&"A".repeat(64)));
    }

    // ----- error paths -----

    #[test]
    fn parse_amount_rejects_non_numeric() {
        assert_eq!(parse_amount("1000", "x").unwrap(), 1000);
        assert!(parse_amount("-1", "x").is_err());
        assert!(parse_amount("abc", "x").is_err());
    }

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
