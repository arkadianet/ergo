use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum NetworkDto {
    Mainnet,
    Testnet,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum RescanStateDto {
    Idle,
    #[serde(rename_all = "camelCase")]
    Running {
        from_height: u32,
    },
    #[serde(rename_all = "camelCase")]
    Failed {
        height: u32,
        reason: String,
    },
    #[serde(rename_all = "camelCase")]
    Unavailable {
        detail: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletStatusDto {
    pub initialized: bool,
    pub locked: bool,
    pub scan_height: u32,
    pub tip_height: u32,
    pub change_address: Option<String>,
    pub network: NetworkDto,
    pub eip27_active: bool,
    pub rescan: RescanStateDto,
    pub scan_invalidated: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum DerivationMode {
    Eip3,
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
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
