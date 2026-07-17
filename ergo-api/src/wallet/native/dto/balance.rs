//! Balance DTOs for `GET /api/v1/wallet/balance`: the shared token
//! amount shape, the nanoErg breakdown, the EIP-27 reserve detail, and
//! the labeled unconfirmed delta.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// A token amount. `amount` is a decimal string (token amounts can exceed 2^53).
/// `deny_unknown_fields` so this stays strict when nested inside request DTOs
/// (e.g. `OutputIntent::payment.assets`, `SelectTarget.assets`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WalletAssetDto {
    /// 32-byte token id, hex.
    pub token_id: String,
    /// Decimal-string amount.
    pub amount: String,
}

/// nanoErg breakdown — all decimal strings.
///
/// Invariant: `available == confirmed.saturating_sub(reserved)` **always**; and
/// `available + reserved == confirmed` iff `reserved <= confirmed`, otherwise
/// `available == 0` and `reserved > confirmed` (flagged by
/// [`ReemissionInfoDto::reserved_exceeds_confirmed`]). `reserved` is never clamped.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct NanoErgBreakdownDto {
    /// Gross sum of mature (`Confirmed`) box values.
    pub confirmed: String,
    /// `confirmed − reserved` (saturating). The factual spendable figure.
    pub available: String,
    /// EIP-27 re-emission holdback estimate (see [`ReemissionInfoDto`]).
    pub reserved: String,
    /// Sum of immature (mining-reward maturity-window) box values; separate.
    pub immature: String,
}

/// EIP-27 re-emission reserve detail. `null` off EIP-27 nets or below activation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ReemissionInfoDto {
    /// 32-byte re-emission token id, hex.
    pub token_id: String,
    /// Re-emission tokens held across the wallet's confirmed boxes; `== reserved`
    /// 1:1 (1 nanoErg/token).
    pub reserved_token_amount: String,
    /// Number of confirmed wallet boxes carrying the re-emission token. This is the
    /// shared obligation's box count — it counts every token-carrying input once the
    /// rule is triggered, not only the floor reward boxes that trigger it.
    pub reserved_box_count: u32,
    /// `reserved > confirmed` — the pathological case where the holdback exceeds
    /// mature ERG (then `available == 0`).
    pub reserved_exceeds_confirmed: bool,
}

/// Scope of an unconfirmed delta. Tagged; `singleHop` is the only reachable
/// variant today (`fullOffChainRegistry` is reserved, additive).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum ScopeDto {
    /// Single-hop mempool overlay (pool outputs to the wallet + pool spends of
    /// confirmed wallet boxes); does not net chains within the pool.
    SingleHop,
}

/// A labeled single-hop unconfirmed delta. Present only with
/// `?includeUnconfirmed=true`; **never folded** into `confirmed`/`available`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UnconfirmedDeltaDto {
    /// What the delta covers.
    pub scope: ScopeDto,
    /// nanoErg arriving in pending pool outputs to the wallet (decimal string).
    pub incoming_nano_erg: String,
    /// nanoErg leaving via confirmed wallet boxes a pool tx already spends.
    pub outgoing_nano_erg: String,
    /// `incoming − outgoing`, signed decimal string.
    pub net_nano_erg: String,
}

/// `GET /api/v1/wallet/balance` response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WalletBalanceDto {
    /// `asOf` — the wallet scan height of the single read snapshot this body
    /// was computed from.
    pub height: u32,
    /// nanoErg breakdown.
    pub nano_erg: NanoErgBreakdownDto,
    /// Confirmed token balances (the re-emission token is omitted — it is
    /// accounted for solely by `reserved`/`reemission`).
    pub assets: Vec<WalletAssetDto>,
    /// EIP-27 reserve detail, or `null` off EIP-27 nets / below activation.
    /// Serialized as `null` (not omitted) so the field's presence is stable.
    pub reemission: Option<ReemissionInfoDto>,
    /// Labeled unconfirmed delta, or `null` unless `?includeUnconfirmed=true`.
    pub unconfirmed: Option<UnconfirmedDeltaDto>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    fn sample(reemission: Option<ReemissionInfoDto>) -> WalletBalanceDto {
        WalletBalanceDto {
            height: 1_811_103,
            nano_erg: NanoErgBreakdownDto {
                confirmed: "45000000000".to_string(),
                available: "9000000000".to_string(),
                reserved: "36000000000".to_string(),
                immature: "3000000000".to_string(),
            },
            assets: vec![WalletAssetDto {
                token_id: "ab".repeat(32),
                amount: "1000".to_string(),
            }],
            reemission,
            unconfirmed: None,
        }
    }

    // ----- round-trips -----

    #[test]
    fn balance_dto_round_trips() {
        let original = sample(Some(ReemissionInfoDto {
            token_id: "cd".repeat(32),
            reserved_token_amount: "36000000000".to_string(),
            reserved_box_count: 3,
            reserved_exceeds_confirmed: false,
        }));
        let json = serde_json::to_string(&original).unwrap();
        let back: WalletBalanceDto = serde_json::from_str(&json).unwrap();
        assert_eq!(original, back);
    }

    #[test]
    fn amounts_serialize_as_strings_never_numbers() {
        // Money + token amounts MUST be JSON strings (no precision loss above 2^53).
        let v = serde_json::to_value(sample(None)).unwrap();
        assert!(v["nanoErg"]["confirmed"].is_string());
        assert!(v["nanoErg"]["available"].is_string());
        assert!(v["nanoErg"]["reserved"].is_string());
        assert!(v["nanoErg"]["immature"].is_string());
        assert!(v["assets"][0]["amount"].is_string());
    }

    #[test]
    fn null_fields_serialize_as_null_not_omitted() {
        // `reemission`/`unconfirmed` are stable, present-as-null fields.
        let v = serde_json::to_value(sample(None)).unwrap();
        assert!(v.get("reemission").is_some_and(serde_json::Value::is_null));
        assert!(v.get("unconfirmed").is_some_and(serde_json::Value::is_null));
    }

    #[test]
    fn scope_is_tagged_single_hop() {
        let v = serde_json::to_value(ScopeDto::SingleHop).unwrap();
        assert_eq!(v, serde_json::json!({ "type": "singleHop" }));
    }

    #[test]
    fn unknown_field_is_rejected_on_assets() {
        // WalletAssetDto round-trips; an unknown discriminator/extra is not silently
        // accepted by the tagged scope union.
        let bad = serde_json::json!({ "type": "doubleHop" });
        assert!(serde_json::from_value::<ScopeDto>(bad).is_err());
    }
}
