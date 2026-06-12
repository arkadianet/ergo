//! Scala-compat `/emission/*` surface.
//!
//! Mirrors `EmissionApiRoute.scala` — emission-schedule data for a given
//! height. **Public by parity**: the Scala route carries no `withAuth`,
//! so nothing here goes near the `api_key` gate (regression pinned by
//! `tests/openapi_native_runtime_mount.rs`: this route must answer bare
//! requests even when security is wired).
//!
//! The schedule math itself lives in `ergo-mining::emission_rules`
//! (single source of truth, oracle-tested against the live Scala node);
//! this crate stays trait-decoupled from the engine crates, so the node
//! hands in an [`EmissionSchedule`] view built over that math.
//!
//! `GET /emission/scripts` (emission / reemission / pay2Reemission P2S
//! addresses) is **not implemented** — the contract-tree predefs aren't
//! exposed in the workspace yet. The live-Scala oracle for it is already
//! captured at `test-vectors/api/emission/scripts.json` for whoever
//! picks that up.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    routing::get,
    Json, Router,
};
use serde::Serialize;

/// Per-height emission schedule view. One method: the Scala
/// `EmissionApiRoute.emissionInfoAtHeight` quintuple, fully computed
/// (the implementor owns the per-network parameters and the cached
/// `coinsTotal`).
pub trait EmissionSchedule: Send + Sync {
    /// Emission info for `height`. Pure math — never fails, any `u32`
    /// height is answerable (past-the-end heights clamp at the totals).
    fn emission_info_at(&self, height: u32) -> EmissionInfoJson;
}

/// Wire shape of `GET /emission/at/{blockHeight}` — field names and
/// order pin the Scala envelope (`EmissionApiRoute.scala:82-88`):
/// `height`, `minerReward`, `totalCoinsIssued`, `totalRemainCoins`,
/// `reemitted`. Values are nanoERG; ≥ 2^53 magnitudes serialize as raw
/// JSON numbers exactly like Scala's circe `Long` encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EmissionInfoJson {
    pub height: u32,
    pub miner_reward: u64,
    pub total_coins_issued: u64,
    pub total_remain_coins: u64,
    pub reemitted: u64,
}

/// Build the `/emission/*` router. Mounted by `crate::server` whenever
/// the view is wired (always, in production — the schedule is static
/// per-network math, available in every node mode including digest).
pub fn emission_router(view: Arc<dyn EmissionSchedule>) -> Router {
    Router::new()
        .route("/emission/at/:height", get(emission_at_handler))
        .with_state(view)
}

/// `GET /emission/at/{blockHeight}`. A malformed (non-`u32`) height
/// rejects with the axum-default 400 — the same house pattern as
/// `/blocks/at/:height` (`compat/handlers.rs`).
async fn emission_at_handler(
    State(view): State<Arc<dyn EmissionSchedule>>,
    Path(height): Path<u32>,
) -> Json<EmissionInfoJson> {
    Json(view.emission_info_at(height))
}

/// Wire shape of `GET /emission/scripts` — the three emission-related
/// contracts as P2S addresses, pre-rendered by the node (the bridge owns
/// the per-network tree constants + address rendering; the live-Scala
/// oracle parity test lives there against
/// `test-vectors/api/emission/scripts.json`). Keys pin the Scala
/// `EmissionApiRoute.scripts` envelope: `emission`, `reemission`,
/// `pay2Reemission`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EmissionScriptsJson {
    pub emission: String,
    pub reemission: String,
    pub pay2_reemission: String,
}

/// Build the `/emission/scripts` router. Mounted only when the node's
/// chain spec carries verified script constants (mainnet; testnet/dev
/// return 404 pending an oracle capture — documented in the openapi).
/// Public like the rest of `/emission/*` (no `withAuth` in Scala).
pub fn emission_scripts_router(scripts: Arc<EmissionScriptsJson>) -> Router {
    Router::new()
        .route("/emission/scripts", get(emission_scripts_handler))
        .with_state(scripts)
}

async fn emission_scripts_handler(
    State(scripts): State<Arc<EmissionScriptsJson>>,
) -> Json<EmissionScriptsJson> {
    Json((*scripts).clone())
}
