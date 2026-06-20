//! Native `/api/v1/wallet/*` response DTOs.
//!
//! Factual-only, built for permanence (see `dev-docs/native-wallet-v1-design.md`):
//! money and token amounts are decimal **strings** (JSON numbers lose precision
//! above 2^53); status/provenance/scope are **tagged unions** `{type:"…"}`; lean
//! summaries extend additively. These are distinct from the Scala-compat
//! `super::super::types` DTOs — neither is reused or mutated.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// A token amount. `amount` is a decimal string (token amounts can exceed 2^53).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
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

// ----- status & lifecycle -----

/// The network this wallet is on (from `cfg.network`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum NetworkDto {
    Mainnet,
    Testnet,
}

/// Wallet rescan lifecycle phase. `running` is a real full-rebuild-in-progress
/// state; `unavailable` is returned only on a backend that cannot replay blocks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum RescanStateDto {
    Idle,
    #[serde(rename_all = "camelCase")]
    Running {
        from_height: u32,
    },
    #[serde(rename_all = "camelCase")]
    Unavailable {
        detail: String,
    },
}

/// `GET /api/v1/wallet/status` — wallet state snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WalletStatusDto {
    /// A wallet exists (seed stored), independent of lock state.
    pub initialized: bool,
    /// The in-memory master key is NOT loaded.
    pub locked: bool,
    /// Height the wallet has scanned through (the read snapshot's `asOf`).
    pub scan_height: u32,
    /// Chain frontier height (so a client can compute the sync gap).
    pub tip_height: u32,
    /// Current change address, or `null` when unset (never `""`). Surfaced even
    /// while locked — it is read from the persisted change-address state, not the
    /// in-memory key.
    pub change_address: Option<String>,
    /// The network this wallet is on.
    pub network: NetworkDto,
    /// EIP-27 is active for the next wallet spend (`cfg.reemission` set AND
    /// `tip+1 > activation`) — the same inputs as the balance `reserved` trigger.
    pub eip27_active: bool,
    /// Rescan lifecycle phase.
    pub rescan: RescanStateDto,
    /// The wallet scan was invalidated (balances/addresses may be stale until a rescan).
    pub scan_invalidated: bool,
}

// ----- addresses -----

/// A tracked wallet address with its derivation metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WalletAddressDto {
    /// The encoded P2PK address for this network.
    pub address: String,
    /// BIP32 derivation path, e.g. `m/44'/429'/0'/0/0`.
    pub derivation_path: String,
    /// Monotonic tracked-pubkey index (insertion / derivation order). `u64` to
    /// match the storage `TrackedAddressMeta.path_idx` exactly — narrowing to
    /// `u32` would silently alias distinct addresses past `u32::MAX`.
    pub index: u64,
    /// Operator label, or `null` when unset.
    pub label: Option<String>,
    /// Height at which this pubkey was first tracked.
    pub added_at_height: u32,
}

/// Paged tracked-address list. `total` = full count, `asOf` = scan height, both
/// from the same read snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AddressPage {
    pub items: Vec<WalletAddressDto>,
    pub total: u32,
    pub as_of: u32,
}

// ----- boxes -----

/// Lifecycle status of a wallet box. Tagged; lean (no full box rendering).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum BoxStatusDto {
    Confirmed,
    #[serde(rename_all = "camelCase")]
    Immature {
        matures_at_height: u32,
    },
    #[serde(rename_all = "camelCase")]
    Spent {
        tx_id: String,
        height: u32,
    },
}

/// How a wallet box was classified at apply time. Tagged.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum BoxProvenanceDto {
    Owned,
    MinerReward,
    #[serde(rename_all = "camelCase")]
    Custom {
        scan_id: u16,
    },
}

/// A lean wallet box summary — no ergoTree/registers/address (full hydration is
/// an additive follow-up, never a reshape of this summary).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WalletBoxSummary {
    pub box_id: String,
    /// Box value in nanoErg (decimal string).
    pub value: String,
    pub assets: Vec<WalletAssetDto>,
    pub creation_tx_id: String,
    pub creation_output_index: u16,
    pub creation_height: u32,
    pub status: BoxStatusDto,
    pub provenance: BoxProvenanceDto,
}

/// Paged wallet-box list, ordered `(creationHeight desc, boxId asc)`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct BoxPage {
    pub items: Vec<WalletBoxSummary>,
    pub total: u32,
    pub as_of: u32,
}

// ----- transactions -----

/// A lean wallet-transaction summary — references only (no full IO/fee/bytes).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WalletTransactionSummary {
    pub tx_id: String,
    pub block_id: String,
    pub block_height: u32,
    pub wallet_input_box_ids: Vec<String>,
    pub wallet_output_box_ids: Vec<String>,
}

/// Paged wallet-transaction list, ordered `(blockHeight desc, txId asc)`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TxPage {
    pub items: Vec<WalletTransactionSummary>,
    pub total: u32,
    pub as_of: u32,
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

    // ----- tagged-union wire shapes (per-variant fields must be camelCase) -----

    #[test]
    fn box_status_wire_shapes() {
        assert_eq!(
            serde_json::to_value(BoxStatusDto::Confirmed).unwrap(),
            serde_json::json!({ "type": "confirmed" }),
        );
        assert_eq!(
            serde_json::to_value(BoxStatusDto::Immature {
                matures_at_height: 720
            })
            .unwrap(),
            serde_json::json!({ "type": "immature", "maturesAtHeight": 720 }),
        );
        assert_eq!(
            serde_json::to_value(BoxStatusDto::Spent {
                tx_id: "ab".to_string(),
                height: 5
            })
            .unwrap(),
            serde_json::json!({ "type": "spent", "txId": "ab", "height": 5 }),
        );
    }

    #[test]
    fn provenance_wire_shapes() {
        assert_eq!(
            serde_json::to_value(BoxProvenanceDto::MinerReward).unwrap(),
            serde_json::json!({ "type": "minerReward" }),
        );
        assert_eq!(
            serde_json::to_value(BoxProvenanceDto::Custom { scan_id: 9 }).unwrap(),
            serde_json::json!({ "type": "custom", "scanId": 9 }),
        );
    }

    #[test]
    fn network_and_rescan_wire_shapes() {
        assert_eq!(
            serde_json::to_value(NetworkDto::Mainnet).unwrap(),
            serde_json::json!({ "type": "mainnet" }),
        );
        assert_eq!(
            serde_json::to_value(RescanStateDto::Idle).unwrap(),
            serde_json::json!({ "type": "idle" }),
        );
        assert_eq!(
            serde_json::to_value(RescanStateDto::Running { from_height: 100 }).unwrap(),
            serde_json::json!({ "type": "running", "fromHeight": 100 }),
        );
        assert_eq!(
            serde_json::to_value(RescanStateDto::Unavailable {
                detail: "pruned".to_string()
            })
            .unwrap(),
            serde_json::json!({ "type": "unavailable", "detail": "pruned" }),
        );
    }

    #[test]
    fn page_envelopes_carry_as_of() {
        let v = serde_json::to_value(AddressPage {
            items: vec![],
            total: 0,
            as_of: 42,
        })
        .unwrap();
        assert_eq!(v["asOf"], 42);
        assert_eq!(v["total"], 0);
    }

    #[test]
    fn box_summary_round_trips() {
        let b = WalletBoxSummary {
            box_id: "aa".repeat(32),
            value: "1000".to_string(),
            assets: vec![],
            creation_tx_id: "bb".repeat(32),
            creation_output_index: 2,
            creation_height: 5,
            status: BoxStatusDto::Confirmed,
            provenance: BoxProvenanceDto::Owned,
        };
        let back: WalletBoxSummary =
            serde_json::from_str(&serde_json::to_string(&b).unwrap()).unwrap();
        assert_eq!(b, back);
        // value is a string, not a number.
        assert!(serde_json::to_value(&b).unwrap()["value"].is_string());
    }

    #[test]
    fn status_dto_round_trips() {
        let s = WalletStatusDto {
            initialized: true,
            locked: false,
            scan_height: 10,
            tip_height: 12,
            change_address: None,
            network: NetworkDto::Mainnet,
            eip27_active: true,
            rescan: RescanStateDto::Idle,
            scan_invalidated: false,
        };
        let back: WalletStatusDto =
            serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        assert_eq!(s, back);
        // changeAddress serializes as null (present, not omitted).
        let v = serde_json::to_value(&s).unwrap();
        assert!(v
            .get("changeAddress")
            .is_some_and(serde_json::Value::is_null));
    }
}
