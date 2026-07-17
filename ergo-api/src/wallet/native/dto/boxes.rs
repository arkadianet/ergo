//! Wallet-box DTOs for `GET /api/v1/wallet/boxes[/:box_id]`: lean box
//! summaries with tagged status/provenance unions.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::balance::WalletAssetDto;

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
