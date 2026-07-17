//! `POST /api/v1/batch` — bounded read-only multiplexer over the v1 read
//! surface. One round trip, many v1 reads: each sub-request is dispatched,
//! in-process, to the SAME `routes::*` handlers every standalone v1 endpoint
//! uses — never HTTP-to-itself (that would be a self-inflicted DoS
//! amplifier). Batch answers `200` for any structurally valid, in-cap
//! request even when individual items fail (partial-failure semantics) —
//! only a malformed/empty/oversize request short-circuits before any item
//! runs.
//!
//! **Closed allow-list, not a proxy.** Batch allow-lists concrete
//! `(method, path template)` pairs — `chain/*`, `boxes/*`, `tokens/*`,
//! `addresses/*`, `mempool/*`, `transactions/*` (reads), `stats/*`,
//! `diagnostics`, `light/*`, and `protocols/*` — and dispatches through a
//! SECOND, restricted `Router<V1State>` wired to the exact same handler
//! functions (never a re-implementation). This is the same dual-mount idiom
//! already used in this crate for `mempool/{submit,check}` aliasing
//! `transactions::{submit,check}`, and `light/membership-proof` aliasing the
//! `chain/proofs` core — a second mount of an existing handler, not a second
//! implementation.
//!
//! A `(method, path)` not on [`allowed_routes`]'s table is REJECTED before
//! any dispatch — `forbidden_target`, never proxied, never a bare 404. The
//! submit-domain routes (`transactions/{submit,check}` — `check` also
//! mutates mempool bookkeeping, not a pure read), the keyless builder
//! (`transactions/build`), the compute-class `transactions/simulate`, and
//! the whole `script/*` playground are deliberately absent from the table:
//! batch is read-only by hard invariant, not by convention.
//!
//! **Cost.** Every allowed entry inherits the SAME [`RouteClass`] (cheap /
//! heavy) the standalone route's own governor layer already charges — batch
//! does not invent a second weight vocabulary, it reuses the one that
//! shipped. The whole batch call is charged ONCE, up front, for the SUM of
//! its dispatchable members' weights against the SAME per-IP [`Governor`]
//! bucket every other T0 surface draws from; a rejected (not-allow-listed)
//! item costs nothing, since it never reaches a handler.
//! The restricted dispatch router itself carries no per-route governor
//! layer — that would double-charge every dispatched item.
//!
//! **Mixed tiers (deferred, not forgotten).** Every entry on today's table is
//! T0 — no v1 T1 read group (wallet/mining/scan) has landed on this stacked
//! branch yet. A per-item-auth design (batch itself stays ungated, a T1/T2
//! `kind` is checked per item) has an obvious extension point here (an
//! `AllowedRoute::tier` field + the shared `crate::v1::auth` check before
//! dispatch) but is not built until a T1 v1 route actually exists to gate —
//! building it now would be untested, unreachable machinery.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;

use crate::v1::error::{Reason, V1Error};

mod allowlist;
pub(crate) mod dispatch;

pub use dispatch::batch_router;

/// Hard cap on sub-requests per batch call.
/// ASSUMED policy constant — not yet an operator-config knob, same as every
/// other T0 bound at launch.
pub const MAX_BATCH_ITEMS: usize = 32;

/// Hard cap on the SUMMED [`RouteClass`] weight of one batch call's
/// dispatchable members, independent of the governor's own per-IP burst —
/// a structural request-shape bound, not a rate limit. A rejected (not
/// allow-listed) item contributes zero.
pub const MAX_BATCH_WEIGHT: f64 = 200.0;

// ----- wire types -----------------------------------------------------------

#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct BatchRequest {
    requests: Vec<BatchItemRequest>,
}

#[derive(Debug, Deserialize, ToSchema)]
struct BatchItemRequest {
    #[serde(default)]
    id: Option<String>,
    method: String,
    path: String,
    #[serde(default)]
    query: Option<String>,
    #[serde(default)]
    body: Option<Value>,
}

#[derive(Debug, Serialize, ToSchema)]
struct BatchItemResult {
    id: String,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<Value>,
}

impl BatchItemResult {
    fn ok(id: String, data: Value) -> Self {
        BatchItemResult {
            id,
            status: "ok",
            data: Some(data),
            error: None,
        }
    }

    /// Build an item-slot error from the canonical [`Reason`] triple — the
    /// exact `{reason, message, detail}` shape a standalone endpoint's
    /// [`v1_error`] would have rendered, just nested under `error` inside
    /// the item instead of at the top level.
    fn error(
        id: String,
        reason: Reason,
        message: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        let inner = V1Error::new(reason, message, detail).error;
        let err_json = serde_json::to_value(inner).expect("V1ErrorInner always serializes");
        BatchItemResult {
            id,
            status: "error",
            data: None,
            error: Some(err_json),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct BatchResponse {
    items: Vec<BatchItemResult>,
}
