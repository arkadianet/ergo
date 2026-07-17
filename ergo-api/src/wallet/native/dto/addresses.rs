//! Tracked-address DTOs for `GET /api/v1/wallet/addresses`.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
