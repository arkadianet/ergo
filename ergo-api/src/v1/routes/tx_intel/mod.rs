//! `transactions/*` intelligence group: intent-based `build`, non-mutating
//! `simulate`, the mempool `fee-estimate` oracle, and lifecycle `status`.
//!
//! These are the "help me transact" endpoints. Two are honestly backed by
//! existing node hooks today — `fee-estimate` (the chain reader's
//! `pool_recommended_fee`/`pool_expected_wait_time_ms`) and `status` (the pool
//! snapshot + the extra index) — and two ride net-new node seams that ship
//! honest-unavailable until the node wires them:
//!
//! - `build` delegates to [`crate::traits::NodeTxBuilder`] — the ONE keyless
//!   builder. `V1State::tx_builder` is `None` until the extracted core is
//!   wired, and the endpoint answers `route_unavailable` (never fake coin
//!   selection).
//! - `simulate` delegates to [`crate::traits::NodeSubmit::simulate`], a
//!   **non-mutating** validate entrypoint. It must never use
//!   [`SubmitMode::CheckOnly`], which still mutates the mempool anti-DoS
//!   bookkeeping (mempool invariant #7); the default impl is unavailable so a
//!   node without the read-only validator answers `route_unavailable`.
//!
//! `build`/`simulate` sit at the governor's `Compute` class (they run coin
//! selection / validation); `fee-estimate`/`status` sit at `HeavyRead`.

use axum::response::Response;

use crate::v1::error::{v1_error, Reason};

pub(crate) mod build;
pub(crate) mod fee_estimate;
pub(crate) mod simulate;
pub(crate) mod status;

pub(crate) use build::BuildResponse;
pub use build::{build, BuildBody};
pub use fee_estimate::fee_estimate;
pub(crate) use fee_estimate::FeeEstimateResponse;
pub(crate) use simulate::SimulateResponse;
pub use simulate::{simulate, SimulateBody};
pub use status::status;
pub(crate) use status::StatusResponse;

// ----- caps ----------------------------------------------------------------

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
            "amounts are u64 encoded as base-10 strings",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
