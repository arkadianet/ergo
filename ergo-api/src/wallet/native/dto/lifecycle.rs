//! Wallet lifecycle request/response DTOs: unlock, mnemonic verify,
//! init, restore, key derivation output, change address, and rescan.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::status::DerivationMode;

// ----- lifecycle (requests/responses) -----

/// `POST /api/v1/wallet/unlock` request. `pass` is body-only, never logged.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UnlockRequest {
    /// Wallet password.
    pub pass: String,
}

/// `POST /api/v1/wallet/mnemonic/verify` request. Body-only secrets, never logged.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MnemonicVerifyRequest {
    /// Candidate recovery phrase to compare against the persisted seed.
    pub mnemonic: String,
    /// BIP39 passphrase (empty if none).
    #[serde(default)]
    pub mnemonic_pass: String,
}

/// `POST /api/v1/wallet/mnemonic/verify` result. `matched=false` is a factual
/// answer, not an error.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MnemonicVerifyResult {
    pub matched: bool,
}

/// `POST /api/v1/wallet/init` request. Secrets body-only, never logged.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InitRequest {
    /// Wallet password.
    pub pass: String,
    /// BIP39 passphrase (empty if none).
    #[serde(default)]
    pub mnemonic_pass: String,
    /// Mnemonic word count: one of 12/15/18/21/24.
    #[serde(default = "default_strength")]
    pub strength: u16,
}

fn default_strength() -> u16 {
    24
}

/// `POST /api/v1/wallet/init` response — the generated mnemonic, returned ONCE
/// (no-store; the page is the only place it should ever live).
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct InitResponse {
    pub mnemonic: String,
}

/// `POST /api/v1/wallet/restore` request. Secrets body-only, never logged.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RestoreRequest {
    /// Recovery phrase.
    pub mnemonic: String,
    /// BIP39 passphrase (empty if none).
    #[serde(default)]
    pub mnemonic_pass: String,
    /// Wallet password.
    pub pass: String,
    /// Required derivation mode.
    pub derivation: DerivationMode,
}

/// `POST /api/v1/wallet/addresses` (derive) response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DerivedAddress {
    /// Encoded P2PK address for the derived key.
    pub address: String,
    /// BIP32 derivation path of the derived key.
    pub derivation_path: String,
    /// Address index — the last path component.
    pub index: u32,
}

/// `GET /api/v1/wallet/change-address` response. `null` when unset.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ChangeAddressDto {
    pub address: Option<String>,
}

/// `PUT /api/v1/wallet/change-address` request.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SetChangeAddressRequest {
    /// The address to use for change — must be a tracked P2PK on this network.
    pub address: String,
}

/// `POST /api/v1/wallet/rescan` request (body optional; defaults to a full rebuild).
#[derive(Clone, Debug, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RescanRequest {
    /// Height to rescan from (0 = full rebuild).
    #[serde(default)]
    pub from_height: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_dto_shapes() {
        // matched is a plain bool result.
        assert_eq!(
            serde_json::to_value(MnemonicVerifyResult { matched: true }).unwrap(),
            serde_json::json!({ "matched": true }),
        );
        // UnlockRequest rejects unknown fields (deny_unknown_fields).
        assert!(serde_json::from_str::<UnlockRequest>(r#"{"pass":"x"}"#).is_ok());
        assert!(serde_json::from_str::<UnlockRequest>(r#"{"pass":"x","extra":1}"#).is_err());
        // mnemonicPass defaults to "".
        let r: MnemonicVerifyRequest = serde_json::from_str(r#"{"mnemonic":"a b c"}"#).unwrap();
        assert_eq!(r.mnemonic_pass, "");
    }

    #[test]
    fn init_restore_dto_shapes() {
        // InitRequest: strength defaults to 24; unknown field rejected.
        let r: InitRequest = serde_json::from_str(r#"{"pass":"x"}"#).unwrap();
        assert_eq!(r.strength, 24);
        assert!(serde_json::from_str::<InitRequest>(r#"{"pass":"x","bogus":1}"#).is_err());
        // RestoreRequest requires `derivation` (no default — kills the legacy trap).
        assert!(serde_json::from_str::<RestoreRequest>(r#"{"mnemonic":"a","pass":"x"}"#).is_err());
        let rr: RestoreRequest =
            serde_json::from_str(r#"{"mnemonic":"a","pass":"x","derivation":{"type":"eip3"}}"#)
                .unwrap();
        assert!(matches!(rr.derivation, DerivationMode::Eip3));
        let rr2: RestoreRequest = serde_json::from_str(
            r#"{"mnemonic":"a","pass":"x","derivation":{"type":"legacyPre1627"}}"#,
        )
        .unwrap();
        assert!(matches!(rr2.derivation, DerivationMode::LegacyPre1627));
    }
}
