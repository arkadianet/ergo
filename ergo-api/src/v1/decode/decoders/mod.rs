//! Family decoders — one module per protocol family. A decoder renders the
//! `state` object for a matched box from its already-parsed registers + tokens.
//! Adding a protocol adds a module here (or reuses an existing family) + a
//! registry entry + a `test-vectors/decode/` oracle (fragment §6).

pub mod sigmausd;

use super::registry::DecoderId;
use super::service::DecodeInput;
use serde_json::Value;

/// Dispatch to the family decoder named by `decoder`. Returns the `state` JSON
/// and whether the decoder downgraded (a missing/ill-typed field → `heuristic`).
pub fn render_state(decoder: DecoderId, input: &DecodeInput, matched_key: &str) -> (Value, bool) {
    match decoder {
        DecoderId::SigmaUsdBank => {
            let r = sigmausd::decode_state(input, matched_key);
            (r.state, r.downgraded)
        }
    }
}
