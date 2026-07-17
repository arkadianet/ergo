//! Wallet status / lifecycle-state DTOs (`GET /api/v1/wallet/status`)
//! plus the strict tagged-enum request shapes DerivationMode and
//! DeriveKeyRequest (manual Deserialize: unknown sibling fields and
//! cross-variant leakage are rejected, moved verbatim).

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

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

/// Key-derivation mode for `restore` (tagged). Required — no default (the
/// legacy-default trap is deliberately removed). Manual `Deserialize` so unknown
/// sibling fields are rejected (serde can't `deny_unknown_fields` an
/// internally-tagged enum).
#[derive(Clone, Debug, ToSchema)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum DerivationMode {
    /// Modern EIP-3 derivation.
    Eip3,
    /// Pre-1627 derivation (matches an old CLI restore).
    LegacyPre1627,
}

impl<'de> Deserialize<'de> for DerivationMode {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Tagged {
            #[serde(rename = "type")]
            ty: String,
        }
        let t = Tagged::deserialize(d)?;
        match t.ty.as_str() {
            "eip3" => Ok(DerivationMode::Eip3),
            "legacyPre1627" => Ok(DerivationMode::LegacyPre1627),
            other => Err(serde::de::Error::unknown_variant(
                other,
                &["eip3", "legacyPre1627"],
            )),
        }
    }
}

/// `POST /api/v1/wallet/addresses` (derive) request (tagged). `next` derives the
/// next sequential key; `path` derives at an explicit BIP32 path. Manual
/// `Deserialize` so unknown sibling fields are rejected and each variant's fields
/// are validated (serde can't `deny_unknown_fields` an internally-tagged enum).
#[derive(Clone, Debug, ToSchema)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum DeriveKeyRequest {
    Next,
    #[serde(rename_all = "camelCase")]
    Path {
        derivation_path: String,
    },
}

impl<'de> Deserialize<'de> for DeriveKeyRequest {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields, rename_all = "camelCase")]
        struct Raw {
            #[serde(rename = "type")]
            ty: String,
            #[serde(default)]
            derivation_path: Option<String>,
        }
        let r = Raw::deserialize(d)?;
        match r.ty.as_str() {
            "next" => match r.derivation_path {
                None => Ok(DeriveKeyRequest::Next),
                Some(_) => Err(serde::de::Error::custom(
                    "`next` does not take a derivationPath",
                )),
            },
            "path" => {
                let derivation_path = r
                    .derivation_path
                    .ok_or_else(|| serde::de::Error::missing_field("derivationPath"))?;
                Ok(DeriveKeyRequest::Path { derivation_path })
            }
            other => Err(serde::de::Error::unknown_variant(other, &["next", "path"])),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{ChangeAddressDto, RescanRequest};
    use super::*;

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

    #[test]
    fn keys_dto_shapes() {
        // DeriveKeyRequest is tagged next|path.
        let n: DeriveKeyRequest = serde_json::from_str(r#"{"type":"next"}"#).unwrap();
        assert!(matches!(n, DeriveKeyRequest::Next));
        let p: DeriveKeyRequest =
            serde_json::from_str(r#"{"type":"path","derivationPath":"m/44'/429'/0'/0/3"}"#)
                .unwrap();
        assert!(matches!(p, DeriveKeyRequest::Path { .. }));
        // ChangeAddressDto serializes null (present, not omitted).
        let v = serde_json::to_value(ChangeAddressDto { address: None }).unwrap();
        assert!(v.get("address").is_some_and(serde_json::Value::is_null));
        // RescanRequest defaults fromHeight=0; rejects unknown fields.
        let r: RescanRequest = serde_json::from_str("{}").unwrap();
        assert_eq!(r.from_height, 0);
        assert!(serde_json::from_str::<RescanRequest>(r#"{"bogus":1}"#).is_err());
        // Tagged request enums reject unknown sibling fields (manual Deserialize).
        assert!(serde_json::from_str::<DeriveKeyRequest>(r#"{"type":"next","bogus":1}"#).is_err());
        assert!(serde_json::from_str::<DerivationMode>(r#"{"type":"eip3","bogus":1}"#).is_err());
        // `next` rejects a stray derivationPath; `path` requires it.
        assert!(serde_json::from_str::<DeriveKeyRequest>(
            r#"{"type":"next","derivationPath":"m/0"}"#
        )
        .is_err());
        assert!(serde_json::from_str::<DeriveKeyRequest>(r#"{"type":"path"}"#).is_err());
        // Unknown discriminator rejected.
        assert!(serde_json::from_str::<DerivationMode>(r#"{"type":"bogus"}"#).is_err());
    }
}
