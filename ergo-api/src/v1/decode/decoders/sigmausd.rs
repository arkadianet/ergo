//! SigmaUSD (AgeUSD) bank-box decoder — the one family whose register/token
//! layout is verified (semantic-decode fragment §5, `bank`).
//!
//! Grounded facts (AgeUSD v2 bank box; token ids cross-checked against mainnet
//! token metadata 2026-07):
//! * `value` (nanoERG) = the ERG **reserve** the bank holds;
//! * `R4: Long` = **StableCoin (SigUSD) in circulation** (the authoritative
//!   circulating counter — minted coins that left the bank);
//! * `R5: Long` = **ReserveCoin (SigRSV) in circulation**;
//! * the bank box holds the bank NFT plus the not-yet-circulating SigUSD and
//!   SigRSV supply as tokens (matched here by id, so token *order* is irrelevant).
//!
//! **Honesty (fragment §5 note):** nominal SigUSD/SigRSV prices and the reserve
//! ratio need the current ERG/USD rate from the linked oracle-pool data-input —
//! which a single-box decode cannot see. This decoder therefore emits only the
//! reserve, the register-derived circulating counts, the in-bank token balances,
//! and the token ids; it never fabricates a price or a ratio.

use super::super::registry::{SIGUSD_V2_RC_TOKEN, SIGUSD_V2_SC_TOKEN};
use super::super::service::DecodeInput;
use ergo_ser::sigma_value::SigmaValue;
use serde_json::{json, Value};

/// The rendered `state` plus whether the decoder had to fall back (a missing or
/// ill-typed register downgrades `confidence` to `heuristic` upstream).
pub struct StateResult {
    pub state: Value,
    pub downgraded: bool,
}

/// Read a register as an `i64` (`SLong`), returning `None` when the register is
/// absent or not a `Long` — the decoder then downgrades to `heuristic` rather
/// than guessing.
fn register_long(input: &DecodeInput, name: &str) -> Option<i64> {
    match input.registers.get(name) {
        Some((_ty, SigmaValue::Long(n))) => Some(*n),
        _ => None,
    }
}

/// Sum the amount of a given token id held in the box (the not-yet-circulating
/// supply the bank custodies). Returns `"0"` when the token is absent.
fn token_amount(input: &DecodeInput, token_id: &str) -> String {
    input
        .tokens
        .iter()
        .filter(|(id, _)| id == token_id)
        .map(|(_, amt)| *amt)
        .sum::<u64>()
        .to_string()
}

/// Decode the SigmaUSD bank box. `bank_nft` is the identifying NFT that matched.
pub fn decode_state(input: &DecodeInput, bank_nft: &str) -> StateResult {
    let circulating_sc = register_long(input, "R4");
    let circulating_rc = register_long(input, "R5");
    // A well-formed bank box always carries both counters; a miss means the box
    // matched the NFT but is not the shape we verified — stay honest.
    let downgraded = circulating_sc.is_none() || circulating_rc.is_none();

    let state = json!({
        "peg_asset": "USD",
        "bank_nft": bank_nft,
        "reserve_nanoerg": input.value.to_string(),
        "circulating_sigusd": circulating_sc.map(|n| n.to_string()),
        "circulating_sigrsv": circulating_rc.map(|n| n.to_string()),
        "sigusd_token_id": SIGUSD_V2_SC_TOKEN,
        "sigrsv_token_id": SIGUSD_V2_RC_TOKEN,
        "sigusd_in_bank": token_amount(input, SIGUSD_V2_SC_TOKEN),
        "sigrsv_in_bank": token_amount(input, SIGUSD_V2_RC_TOKEN),
        // Deliberately no price/ratio: those need the ERG/USD oracle rate from a
        // data-input, which a single-box decode cannot resolve (fragment §5).
        "oracle_derived_price_available": false,
    });
    StateResult { state, downgraded }
}
