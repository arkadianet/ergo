//! `POST /api/v1/transactions/simulate` — non-mutating dry-run of an
//! assembled transaction (accept/reject + cost + conflicts, no
//! broadcast, no mempool mutation).

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::super::extract::V1Json;
use super::super::V1State;
use super::MAX_SIMULATE_BYTES;
use crate::traits::SimulateOutcome;
use crate::v1::error::{v1_error, Reason, V1Error};

// ==========================================================================
//  POST /transactions/simulate
// ==========================================================================

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SimulateBody {
    tx: TxReprDto,
    #[serde(default)]
    assume_context: Option<AssumeContextDto>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum TxReprDto {
    Bytes { bytes: String },
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct AssumeContextDto {
    height: u32,
}

#[derive(Debug, Serialize, ToSchema)]
struct WireConflict {
    box_id: String,
    conflicting_tx_id: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct SimulateResponse {
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
/// + cost + conflicts, NO broadcast and NO mempool mutation.
#[utoipa::path(
    post, path = "/api/v1/transactions/simulate", tag = "transactions",
    request_body = SimulateBody,
    responses(
        (status = 200, description = "Simulation outcome (valid:false is a normal result, not an error)", body = SimulateResponse),
        (status = 400, description = "Malformed tx bytes, or a malformed/transient admission rejection", body = V1Error),
        (status = 413, description = "Assembled tx exceeds the simulate body cap", body = V1Error),
        (status = 409, description = "Simulation not wired on this node", body = V1Error),
        (status = 503, description = "Node overloaded or shutting down", body = V1Error),
        (status = 504, description = "Simulation timed out", body = V1Error),
    ),
)]
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
            super::super::transactions::submit_reason(&e.reason),
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
