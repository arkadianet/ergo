//! `POST /api/v1/wallet/messages/sign`: a wallet key signs one message of a
//! named, domain-separated scheme. There is no raw-bytes mode.
use serde::{Deserialize, Serialize};

/// The key that signs: exactly one of a wallet address or a derivation path,
/// and in either case a key the wallet already tracks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MessageKeyDto {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignMessageRequest {
    /// `kadia-maker-quote-v1` or `rosen-intents-quote-v1`.
    pub scheme: String,
    pub key: MessageKeyDto,
    /// The scheme's typed message: [`MakerQuoteMessageDto`] or
    /// [`RosenQuoteMessageDto`]. Decoded strictly once the scheme is known.
    pub message: serde_json::Value,
    /// Allow the wallet's first key (`m/44'/429'/0'/0/0`, or the master key)
    /// or its change key to sign. Off by default: those keys hold the wallet's
    /// funds, and a quote key is better kept separate from them.
    #[serde(default)]
    pub allow_spend_key: bool,
}

/// `kadia-maker-quote-v1` message: the maker-vault quote's fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MakerQuoteMessageDto {
    /// The vault box id, 32 bytes hex.
    pub vault_box_id: String,
    pub side: i64,
    pub price_num: i64,
    pub price_den: i64,
    pub min_in: i64,
    pub max_in: i64,
    pub expiry_height: i64,
    pub exec_fee: i64,
}

/// `rosen-intents-quote-v1` message: the full canonical quote encoding, hex.
/// The wallet checks and hashes it; it never signs a caller-supplied hash.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RosenQuoteMessageDto {
    pub quote: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignMessageResponse {
    pub scheme: String,
    /// The signing key's address.
    pub address: String,
    /// The public key `Q`, 33 bytes compressed, hex.
    pub public_key: String,
    /// The commitment `a`, 33 bytes compressed, hex.
    pub a: String,
    /// The response `z`, 32 bytes big-endian, hex.
    pub z: String,
    /// `a ‖ z`, 65 bytes, hex.
    pub signature: String,
    /// The bytes the challenge commits to, hex: the 112-byte maker message,
    /// or the 32-byte Rosen quote hash.
    pub signed_message: String,
}
