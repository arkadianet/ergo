use serde::{Deserialize, Serialize};

use super::balance::WalletAssetDto;
use super::transactions::WalletTransactionSummary;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum TxRepr {
    Bytes { bytes: String },
}

impl TxRepr {
    pub fn bytes_hex(&self) -> &str {
        match self {
            TxRepr::Bytes { bytes } => bytes,
        }
    }

    pub fn from_bytes(raw: &[u8]) -> Self {
        TxRepr::Bytes {
            bytes: hex::encode(raw),
        }
    }
}

impl<'de> Deserialize<'de> for TxRepr {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields, rename_all = "camelCase")]
        struct Raw {
            #[serde(rename = "type")]
            ty: String,
            #[serde(default)]
            bytes: Option<String>,
        }
        let r = Raw::deserialize(d)?;
        match r.ty.as_str() {
            "bytes" => Ok(TxRepr::Bytes {
                bytes: r
                    .bytes
                    .ok_or_else(|| serde::de::Error::missing_field("bytes"))?,
            }),
            other => Err(serde::de::Error::unknown_variant(other, &["bytes"])),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum OutputIntent {
    #[serde(rename_all = "camelCase")]
    Payment {
        address: String,
        value: String,
        #[serde(default)]
        assets: Vec<WalletAssetDto>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        registers: Option<std::collections::BTreeMap<String, String>>,
    },
    #[serde(rename_all = "camelCase")]
    Mint {
        address: String,
        amount: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        decimals: Option<u8>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
    },
    #[serde(rename_all = "camelCase")]
    Burn { assets: Vec<WalletAssetDto> },
}

impl<'de> Deserialize<'de> for OutputIntent {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields, rename_all = "camelCase")]
        struct Raw {
            #[serde(rename = "type")]
            ty: String,
            address: Option<String>,
            value: Option<String>,
            assets: Option<Vec<WalletAssetDto>>,
            registers: Option<std::collections::BTreeMap<String, String>>,
            amount: Option<String>,
            name: Option<String>,
            decimals: Option<u8>,
            description: Option<String>,
        }
        fn forbid<E: serde::de::Error>(present: bool, field: &str, ty: &str) -> Result<(), E> {
            if present {
                Err(E::custom(format!("`{ty}` output does not take `{field}`")))
            } else {
                Ok(())
            }
        }
        let r = Raw::deserialize(d)?;
        match r.ty.as_str() {
            "payment" => {
                forbid::<D::Error>(r.amount.is_some(), "amount", "payment")?;
                forbid::<D::Error>(r.name.is_some(), "name", "payment")?;
                forbid::<D::Error>(r.decimals.is_some(), "decimals", "payment")?;
                forbid::<D::Error>(r.description.is_some(), "description", "payment")?;
                Ok(OutputIntent::Payment {
                    address: r
                        .address
                        .ok_or_else(|| D::Error::missing_field("address"))?,
                    value: r.value.ok_or_else(|| D::Error::missing_field("value"))?,
                    assets: r.assets.unwrap_or_default(),
                    registers: r.registers,
                })
            }
            "mint" => {
                forbid::<D::Error>(r.value.is_some(), "value", "mint")?;
                forbid::<D::Error>(r.assets.is_some(), "assets", "mint")?;
                forbid::<D::Error>(r.registers.is_some(), "registers", "mint")?;
                Ok(OutputIntent::Mint {
                    address: r
                        .address
                        .ok_or_else(|| D::Error::missing_field("address"))?,
                    amount: r.amount.ok_or_else(|| D::Error::missing_field("amount"))?,
                    name: r.name,
                    decimals: r.decimals,
                    description: r.description,
                })
            }
            "burn" => {
                forbid::<D::Error>(r.address.is_some(), "address", "burn")?;
                forbid::<D::Error>(r.value.is_some(), "value", "burn")?;
                forbid::<D::Error>(r.registers.is_some(), "registers", "burn")?;
                forbid::<D::Error>(r.amount.is_some(), "amount", "burn")?;
                forbid::<D::Error>(r.name.is_some(), "name", "burn")?;
                forbid::<D::Error>(r.decimals.is_some(), "decimals", "burn")?;
                forbid::<D::Error>(r.description.is_some(), "description", "burn")?;
                let assets = r.assets.ok_or_else(|| D::Error::missing_field("assets"))?;
                if assets.is_empty() {
                    return Err(D::Error::custom("`burn` requires at least one asset"));
                }
                Ok(OutputIntent::Burn { assets })
            }
            other => Err(D::Error::unknown_variant(
                other,
                &["payment", "mint", "burn"],
            )),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum InputSource {
    #[serde(rename_all = "camelCase")]
    Auto {
        #[serde(default)]
        min_confirmations: i64,
        #[serde(default)]
        exclude_box_ids: Vec<String>,
    },
    #[serde(rename_all = "camelCase")]
    BoxIds { box_ids: Vec<String> },
    #[serde(rename_all = "camelCase")]
    Boxes { boxes_hex: Vec<String> },
}

impl Default for InputSource {
    fn default() -> Self {
        InputSource::Auto {
            min_confirmations: 0,
            exclude_box_ids: Vec::new(),
        }
    }
}

impl<'de> Deserialize<'de> for InputSource {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields, rename_all = "camelCase")]
        struct Raw {
            #[serde(rename = "type")]
            ty: String,
            min_confirmations: Option<i64>,
            exclude_box_ids: Option<Vec<String>>,
            box_ids: Option<Vec<String>>,
            boxes_hex: Option<Vec<String>>,
        }
        let r = Raw::deserialize(d)?;
        let extra = |a: bool, b: bool, c: bool| a || b || c;
        match r.ty.as_str() {
            "auto" => {
                if extra(r.box_ids.is_some(), r.boxes_hex.is_some(), false) {
                    return Err(D::Error::custom(
                        "`auto` takes only minConfirmations/excludeBoxIds",
                    ));
                }
                Ok(InputSource::Auto {
                    min_confirmations: r.min_confirmations.unwrap_or(0),
                    exclude_box_ids: r.exclude_box_ids.unwrap_or_default(),
                })
            }
            "boxIds" => {
                if extra(
                    r.min_confirmations.is_some(),
                    r.exclude_box_ids.is_some(),
                    r.boxes_hex.is_some(),
                ) {
                    return Err(D::Error::custom("`boxIds` takes only boxIds"));
                }
                Ok(InputSource::BoxIds {
                    box_ids: r.box_ids.ok_or_else(|| D::Error::missing_field("boxIds"))?,
                })
            }
            "boxes" => {
                if extra(
                    r.min_confirmations.is_some(),
                    r.exclude_box_ids.is_some(),
                    r.box_ids.is_some(),
                ) {
                    return Err(D::Error::custom("`boxes` takes only boxesHex"));
                }
                Ok(InputSource::Boxes {
                    boxes_hex: r
                        .boxes_hex
                        .ok_or_else(|| D::Error::missing_field("boxesHex"))?,
                })
            }
            other => Err(D::Error::unknown_variant(
                other,
                &["auto", "boxIds", "boxes"],
            )),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum DataInputSource {
    #[serde(rename_all = "camelCase")]
    BoxIds { box_ids: Vec<String> },
    #[serde(rename_all = "camelCase")]
    Boxes { boxes_hex: Vec<String> },
}

impl Default for DataInputSource {
    fn default() -> Self {
        DataInputSource::BoxIds {
            box_ids: Vec::new(),
        }
    }
}

impl<'de> Deserialize<'de> for DataInputSource {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields, rename_all = "camelCase")]
        struct Raw {
            #[serde(rename = "type")]
            ty: String,
            box_ids: Option<Vec<String>>,
            boxes_hex: Option<Vec<String>>,
        }
        let r = Raw::deserialize(d)?;
        match r.ty.as_str() {
            "boxIds" => {
                if r.boxes_hex.is_some() {
                    return Err(serde::de::Error::custom("`boxIds` takes only boxIds"));
                }
                Ok(DataInputSource::BoxIds {
                    box_ids: r
                        .box_ids
                        .ok_or_else(|| serde::de::Error::missing_field("boxIds"))?,
                })
            }
            "boxes" => {
                if r.box_ids.is_some() {
                    return Err(serde::de::Error::custom("`boxes` takes only boxesHex"));
                }
                Ok(DataInputSource::Boxes {
                    boxes_hex: r
                        .boxes_hex
                        .ok_or_else(|| serde::de::Error::missing_field("boxesHex"))?,
                })
            }
            other => Err(serde::de::Error::unknown_variant(
                other,
                &["boxIds", "boxes"],
            )),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TxIntent {
    pub outputs: Vec<OutputIntent>,
    #[serde(default)]
    pub fee: Option<String>,
    #[serde(default)]
    pub inputs: InputSource,
    #[serde(default)]
    pub data_inputs: DataInputSource,
    #[serde(default)]
    pub change_address: Option<String>,
    #[serde(default)]
    pub allow_reemission_spend: bool,
    #[serde(default)]
    pub allow_token_burn: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SelectTarget {
    pub nano_erg: String,
    #[serde(default)]
    pub assets: Vec<WalletAssetDto>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BoxSelectRequest {
    pub target: SelectTarget,
    #[serde(default)]
    pub inputs: InputSource,
    #[serde(default)]
    pub change_address: Option<String>,
    #[serde(default)]
    pub allow_reemission_spend: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SelectedBoxRef {
    pub box_id: String,
    pub value: String,
    pub assets: Vec<WalletAssetDto>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangePlan {
    pub nano_erg: String,
    pub assets: Vec<WalletAssetDto>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReemissionBurn {
    pub token_id: String,
    pub tokens_burned: String,
    pub nano_erg_routed: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BoxSelectResponse {
    pub inputs_selected: Vec<SelectedBoxRef>,
    pub change: ChangePlan,
    pub reemission_burn: Option<ReemissionBurn>,
    pub as_of: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildTxResponse {
    pub unsigned_transaction: TxRepr,
    pub inputs_selected: Vec<SelectedBoxRef>,
    pub change_outputs: Vec<ChangePlan>,
    pub fee: String,
    pub reemission_burn: Option<ReemissionBurn>,
    pub as_of: u32,
}

#[derive(Clone)]
pub enum ExternalSecret {
    Dlog {
        secret: String,
    },
    DhTuple {
        g: String,
        h: String,
        u: String,
        v: String,
        secret: String,
    },
}

impl std::fmt::Debug for ExternalSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExternalSecret::Dlog { .. } => f.write_str("ExternalSecret::Dlog(<redacted>)"),
            ExternalSecret::DhTuple { .. } => f.write_str("ExternalSecret::DhTuple(<redacted>)"),
        }
    }
}

impl<'de> Deserialize<'de> for ExternalSecret {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields, rename_all = "camelCase")]
        struct Raw {
            #[serde(rename = "type")]
            ty: String,
            g: Option<String>,
            h: Option<String>,
            u: Option<String>,
            v: Option<String>,
            secret: Option<String>,
        }
        let r = Raw::deserialize(d)?;
        let secret = r
            .secret
            .ok_or_else(|| serde::de::Error::missing_field("secret"))?;
        match r.ty.as_str() {
            "dlog" => {
                if r.g.is_some() || r.h.is_some() || r.u.is_some() || r.v.is_some() {
                    return Err(serde::de::Error::custom("`dlog` takes only `secret`"));
                }
                Ok(ExternalSecret::Dlog { secret })
            }
            "dhTuple" => Ok(ExternalSecret::DhTuple {
                g: r.g.ok_or_else(|| serde::de::Error::missing_field("g"))?,
                h: r.h.ok_or_else(|| serde::de::Error::missing_field("h"))?,
                u: r.u.ok_or_else(|| serde::de::Error::missing_field("u"))?,
                v: r.v.ok_or_else(|| serde::de::Error::missing_field("v"))?,
                secret,
            }),
            other => Err(serde::de::Error::unknown_variant(
                other,
                &["dlog", "dhTuple"],
            )),
        }
    }
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignTxRequest {
    pub unsigned_transaction: TxRepr,
    #[serde(default)]
    pub external_secrets: Vec<ExternalSecret>,
}

impl std::fmt::Debug for SignTxRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignTxRequest")
            .field("unsigned_transaction", &self.unsigned_transaction)
            .field("external_secrets", &self.external_secrets.len())
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignTxResponse {
    pub signed_transaction: TxRepr,
    pub tx_id: String,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum SendTxRequest {
    Intent {
        intent: TxIntent,
    },
    #[serde(rename_all = "camelCase")]
    Signed {
        signed_transaction: TxRepr,
    },
}

impl<'de> Deserialize<'de> for SendTxRequest {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields, rename_all = "camelCase")]
        struct Raw {
            #[serde(rename = "type")]
            ty: String,
            intent: Option<TxIntent>,
            signed_transaction: Option<TxRepr>,
        }
        let r = Raw::deserialize(d)?;
        match r.ty.as_str() {
            "intent" => {
                if r.signed_transaction.is_some() {
                    return Err(serde::de::Error::custom(
                        "`intent` does not take `signedTransaction`",
                    ));
                }
                Ok(SendTxRequest::Intent {
                    intent: r
                        .intent
                        .ok_or_else(|| serde::de::Error::missing_field("intent"))?,
                })
            }
            "signed" => {
                if r.intent.is_some() {
                    return Err(serde::de::Error::custom("`signed` does not take `intent`"));
                }
                Ok(SendTxRequest::Signed {
                    signed_transaction: r
                        .signed_transaction
                        .ok_or_else(|| serde::de::Error::missing_field("signedTransaction"))?,
                })
            }
            other => Err(serde::de::Error::unknown_variant(
                other,
                &["intent", "signed"],
            )),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendTxResponse {
    pub tx_id: String,
    pub accepted: bool,
    pub transaction: Option<WalletTransactionSummary>,
}
