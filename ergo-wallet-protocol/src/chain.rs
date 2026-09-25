use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};

pub const CHAIN_API_VERSION: u16 = 1;
pub const CHAIN_WIRE_VERSION: u16 = CHAIN_API_VERSION;
pub type ChainApiVersion = u16;
pub const ID32_HEX_LEN: usize = 64;
pub const RESERVED_ZERO_ID: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
pub const RESERVED_MAX_ID: &str =
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
pub const GENESIS_CURSOR_ID: &str = RESERVED_ZERO_ID;
pub const GENESIS_CURSOR_HEADER_ID: &str = GENESIS_CURSOR_ID;

pub fn validate_id32(value: &str, field: &str) -> Result<(), String> {
    if value.len() != ID32_HEX_LEN
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(format!("{field} must be 64 lowercase hex characters"));
    }
    Ok(())
}

pub fn validate_hex_bytes(value: &str, field: &str) -> Result<(), String> {
    if !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(format!("{field} must be lowercase hex"));
    }
    Ok(())
}

pub fn validate_snapshot_id(value: &str) -> Result<(), String> {
    validate_id32(value, "snapshot_id")?;
    if value == RESERVED_ZERO_ID || value == RESERVED_MAX_ID {
        return Err("snapshot_id is reserved".to_string());
    }
    Ok(())
}

fn deserialize_id32<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    validate_id32(&value, "id").map_err(serde::de::Error::custom)?;
    Ok(value)
}

fn deserialize_header_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    validate_id32(&value, "header_id").map_err(serde::de::Error::custom)?;
    Ok(value)
}

fn deserialize_snapshot_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    validate_snapshot_id(&value).map_err(serde::de::Error::custom)?;
    Ok(value)
}

fn deserialize_optional_header_id<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;
    value
        .map(|value| {
            validate_id32(&value, "tip").map_err(serde::de::Error::custom)?;
            Ok(value)
        })
        .transpose()
}

fn deserialize_optional_snapshot_id<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;
    value
        .map(|value| {
            validate_snapshot_id(&value).map_err(serde::de::Error::custom)?;
            Ok(value)
        })
        .transpose()
}

fn deserialize_hex_bytes<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    validate_hex_bytes(&value, "bytes").map_err(serde::de::Error::custom)?;
    Ok(value)
}

fn deserialize_id32_vec<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let values = Vec::<String>::deserialize(deserializer)?;
    values
        .into_iter()
        .map(|value| {
            validate_id32(&value, "id").map_err(serde::de::Error::custom)?;
            Ok(value)
        })
        .collect()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct Id32(String);

impl Id32 {
    pub fn new(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        validate_id32(&value, "id")?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Id32 {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<&str> for Id32 {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl AsRef<str> for Id32 {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for Id32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Id32 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

pub type HeaderId = Id32;
pub type BlockId = Id32;
pub type BoxId = Id32;
pub type TxId = Id32;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct HexBytes(String);

impl HexBytes {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(bytes))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        hex::decode(&self.0).map_err(|error| error.to_string())
    }
}

impl TryFrom<&[u8]> for HexBytes {
    type Error = String;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self::from_bytes(value))
    }
}

impl<'de> Deserialize<'de> for HexBytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        validate_hex_bytes(&value, "bytes").map_err(serde::de::Error::custom)?;
        Ok(Self(value))
    }
}

pub type RawBytes = HexBytes;
pub type SerializedBytes = HexBytes;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainTip {
    pub height: u32,
    #[serde(deserialize_with = "deserialize_header_id")]
    pub header_id: String,
}

impl ChainTip {
    pub fn new(height: u32, header_id: impl Into<String>) -> Result<Self, String> {
        let header_id = header_id.into();
        validate_id32(&header_id, "header_id")?;
        Ok(Self { height, header_id })
    }
}

pub type Tip = ChainTip;
pub type TipResponse = ChainTip;
pub type ChainTipResponse = ChainTip;
pub type ExpectedTip = ChainTip;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainCursor {
    pub height: u32,
    #[serde(deserialize_with = "deserialize_header_id")]
    pub header_id: String,
}

impl ChainCursor {
    pub fn genesis() -> Self {
        Self {
            height: 0,
            header_id: GENESIS_CURSOR_ID.to_string(),
        }
    }

    pub fn is_genesis_sentinel(&self) -> bool {
        self.height == 0 && self.header_id == GENESIS_CURSOR_ID
    }
}

pub type Cursor = ChainCursor;
pub type ChainCursorResponse = ChainCursor;
pub type SnapshotCursor = ChainCursor;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainHeader {
    pub height: u32,
    #[serde(deserialize_with = "deserialize_header_id")]
    pub header_id: String,
    #[serde(deserialize_with = "deserialize_header_id")]
    pub parent_id: String,
    pub timestamp_unix_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReemissionInput {
    #[serde(deserialize_with = "deserialize_id32")]
    pub token_id: String,
    pub amount: String,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_id32_vec"
    )]
    pub box_ids: Vec<String>,
}

pub type Reemission = ReemissionInput;
pub type ActiveParameters = serde_json::Value;
pub type ProtocolParameters = serde_json::Value;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainSnapshot {
    pub tip: ChainTip,
    #[serde(default, alias = "ancestors")]
    pub headers: Vec<ChainHeader>,
    #[serde(
        alias = "parameters",
        alias = "activeParams",
        alias = "protocolParameters"
    )]
    pub active_parameters: ActiveParameters,
    #[serde(default, alias = "reemission", alias = "reEmission")]
    pub reemission_inputs: Vec<ReemissionInput>,
    #[serde(alias = "id", deserialize_with = "deserialize_snapshot_id")]
    pub snapshot_id: String,
}

pub type Snapshot = ChainSnapshot;
pub type ChainSnapshotResponse = ChainSnapshot;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainAsset {
    #[serde(deserialize_with = "deserialize_id32")]
    pub token_id: String,
    pub amount: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainBox {
    #[serde(deserialize_with = "deserialize_id32")]
    pub box_id: String,
    #[serde(
        alias = "boxBytes",
        alias = "box_bytes",
        deserialize_with = "deserialize_hex_bytes"
    )]
    pub bytes: String,
    pub value: u64,
    pub assets: Vec<ChainAsset>,
    #[serde(deserialize_with = "deserialize_id32")]
    pub creation_tx_id: String,
    pub creation_output_index: u16,
    pub creation_height: u32,
}

pub type WalletBox = ChainBox;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainInput {
    #[serde(deserialize_with = "deserialize_id32")]
    pub box_id: String,
    pub index: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainOutput {
    #[serde(deserialize_with = "deserialize_id32")]
    pub box_id: String,
    pub index: u16,
    #[serde(
        alias = "boxBytes",
        alias = "box_bytes",
        deserialize_with = "deserialize_hex_bytes"
    )]
    pub bytes: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainTransaction {
    #[serde(deserialize_with = "deserialize_id32")]
    pub tx_id: String,
    pub inputs: Vec<ChainInput>,
    pub outputs: Vec<ChainOutput>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainBlock {
    #[serde(deserialize_with = "deserialize_id32")]
    pub block_id: String,
    pub height: u32,
    #[serde(deserialize_with = "deserialize_id32")]
    pub parent_id: String,
    #[serde(alias = "txs")]
    pub transactions: Vec<ChainTransaction>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlocksSinceRequest {
    pub height: u32,
    #[serde(deserialize_with = "deserialize_header_id")]
    pub id: String,
    pub limit: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForwardBlocksSince {
    pub tip: ChainTip,
    pub blocks: Vec<ChainBlock>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AncestorBlocksSince {
    pub tip: ChainTip,
    pub ancestor: ChainCursor,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrunedBlocksSince {
    pub tip: ChainTip,
    #[serde(alias = "minHeight", alias = "historyFloor")]
    pub minimum_height: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum BlocksSinceResponse {
    #[serde(alias = "blocks")]
    Forward(ForwardBlocksSince),
    #[serde(alias = "reorg")]
    Ancestor(AncestorBlocksSince),
    #[serde(alias = "historyPruned")]
    Pruned(PrunedBlocksSince),
}

pub type BlocksSinceResult = BlocksSinceResponse;
pub type ForwardBlocks = ForwardBlocksSince;
pub type AncestorBlocks = AncestorBlocksSince;
pub type PrunedBlocks = PrunedBlocksSince;
pub type ForwardBlocksResponse = ForwardBlocksSince;
pub type AncestorBlocksResponse = AncestorBlocksSince;
pub type PrunedBlocksResponse = PrunedBlocksSince;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BoxLookupRequest {
    #[serde(deserialize_with = "deserialize_id32")]
    pub box_id: String,
    #[serde(
        default,
        alias = "expectedTip",
        deserialize_with = "deserialize_optional_header_id",
        skip_serializing_if = "Option::is_none"
    )]
    pub tip: Option<String>,
    #[serde(default, alias = "tipHeight", skip_serializing_if = "Option::is_none")]
    pub height: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BoxLookupResponse {
    pub tip: ChainTip,
    #[serde(rename = "box")]
    pub box_info: ChainBox,
}

pub type BoxLookup = BoxLookupResponse;
pub type ChainBoxLookupRequest = BoxLookupRequest;
pub type ChainBoxLookupResponse = BoxLookupResponse;
pub type UtxoLookupRequest = BoxLookupRequest;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmitRequest {
    #[serde(
        alias = "bytes",
        alias = "transactionBytes",
        alias = "txBytes",
        deserialize_with = "deserialize_hex_bytes"
    )]
    pub transaction: String,
    #[serde(default, deserialize_with = "deserialize_optional_snapshot_id")]
    pub snapshot_id: Option<String>,
}

pub type SubmitTransactionRequest = SubmitRequest;
pub type ChainSubmitRequest = SubmitRequest;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SubmitError {
    Duplicate,
    Invalid,
    Fee,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "camelCase")]
pub enum SubmitResponse {
    Accepted {
        tip: ChainTip,
        #[serde(deserialize_with = "deserialize_id32")]
        tx_id: String,
    },
    Duplicate {
        tip: ChainTip,
        #[serde(deserialize_with = "deserialize_id32")]
        tx_id: String,
    },
    Rejected {
        tip: ChainTip,
        reason: SubmitError,
        #[serde(skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
    },
}

pub type SubmitTransactionResponse = SubmitResponse;
pub type ChainSubmitResponse = SubmitResponse;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct SnapshotId(String);

impl SnapshotId {
    pub fn new(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        validate_snapshot_id(&value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl TryFrom<String> for SnapshotId {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<&str> for SnapshotId {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl AsRef<str> for SnapshotId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl From<SnapshotId> for String {
    fn from(value: SnapshotId) -> Self {
        value.into_inner()
    }
}

impl fmt::Display for SnapshotId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SnapshotId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct UserScanId(u16);

impl UserScanId {
    pub const MINING: Self = Self(crate::scala::scan::MINING_SCAN_ID);
    pub const PAYMENTS: Self = Self(crate::scala::scan::PAYMENTS_SCAN_ID);

    pub fn new(value: u16) -> Result<Self, String> {
        crate::scala::scan::validate_user_scan_id(value)
            .map_err(|_| "scan id is reserved".to_string())?;
        Ok(Self(value))
    }

    pub fn get(self) -> u16 {
        self.0
    }
}

impl TryFrom<u16> for UserScanId {
    type Error = String;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl<'de> Deserialize<'de> for UserScanId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = u16::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

pub mod v1 {
    pub use super::*;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(fill: char) -> String {
        std::iter::repeat_n(fill, 64).collect()
    }

    #[test]
    fn chain_tip_round_trips_and_keeps_hex_shape() {
        let tip = ChainTip::new(42, id('a')).unwrap();
        let json = serde_json::to_string(&tip).unwrap();
        assert_eq!(json, format!(r#"{{"height":42,"headerId":"{}"}}"#, id('a')));
        assert_eq!(serde_json::from_str::<ChainTip>(&json).unwrap(), tip);
    }

    #[test]
    fn snapshot_and_submit_round_trip() {
        let snapshot = ChainSnapshot {
            tip: ChainTip::new(7, id('1')).unwrap(),
            headers: vec![],
            active_parameters: serde_json::json!({"hardFork": 1}),
            reemission_inputs: vec![],
            snapshot_id: id('2'),
        };
        let json = serde_json::to_string(&snapshot).unwrap();
        assert_eq!(
            serde_json::from_str::<ChainSnapshot>(&json).unwrap(),
            snapshot
        );

        let request = SubmitRequest {
            transaction: "00ff".to_string(),
            snapshot_id: Some(id('2')),
        };
        let json = serde_json::to_string(&request).unwrap();
        assert_eq!(
            serde_json::from_str::<SubmitRequest>(&json).unwrap(),
            request
        );
    }

    #[test]
    fn blocks_since_tagged_variants_are_distinct() {
        let tip = ChainTip::new(8, id('3')).unwrap();
        let responses = [
            BlocksSinceResponse::Forward(ForwardBlocksSince {
                tip: tip.clone(),
                blocks: vec![],
            }),
            BlocksSinceResponse::Ancestor(AncestorBlocksSince {
                tip: tip.clone(),
                ancestor: ChainCursor {
                    height: 3,
                    header_id: id('4'),
                },
            }),
            BlocksSinceResponse::Pruned(PrunedBlocksSince {
                tip,
                minimum_height: 5,
            }),
        ];
        for response in responses {
            let value = serde_json::to_value(&response).unwrap();
            let tag = value["type"].as_str().unwrap().to_string();
            let back: BlocksSinceResponse = serde_json::from_value(value).unwrap();
            assert_eq!(back, response);
            assert!(matches!(
                (tag.as_str(), back),
                ("forward", BlocksSinceResponse::Forward(_))
                    | ("ancestor", BlocksSinceResponse::Ancestor(_))
                    | ("pruned", BlocksSinceResponse::Pruned(_))
            ));
        }
    }

    #[test]
    fn box_lookup_tip_round_trips_as_a_header_id_query() {
        let request = BoxLookupRequest {
            box_id: id('a'),
            tip: Some(id('b')),
            height: Some(12),
        };
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains(r#""tip":""#));
        assert!(json.contains(r#""height":12"#));
        assert_eq!(
            serde_json::from_str::<BoxLookupRequest>(&json).unwrap(),
            request
        );
        let query = serde_json::json!({
            "boxId": id('a'),
            "tip": id('b')
        });
        assert_eq!(
            serde_json::from_value::<BoxLookupRequest>(query).unwrap(),
            BoxLookupRequest {
                box_id: id('a'),
                tip: Some(id('b')),
                height: None,
            }
        );
        assert!(
            serde_json::from_value::<BoxLookupRequest>(serde_json::json!({
                "boxId": id('a'),
                "tip": {"height": 12, "headerId": id('b')}
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<BoxLookupRequest>(serde_json::json!({
                "boxId": id('a'),
                "tip": "not-an-id"
            }))
            .is_err()
        );
    }

    #[test]
    fn raw_bytes_and_id_helpers_validate_wire_encoding() {
        let bytes = HexBytes::from_bytes(&[0xde, 0xad]);
        assert_eq!(bytes.as_str(), "dead");
        assert_eq!(bytes.to_bytes().unwrap(), vec![0xde, 0xad]);
        assert!(serde_json::from_str::<HexBytes>(r#""DEAD""#).is_err());
        assert!(Id32::new("ab").is_err());
        assert!(Id32::new(id('a')).is_ok());
    }

    #[test]
    fn invalid_and_reserved_ids_are_rejected() {
        let bad = serde_json::json!({"height": 1, "headerId": "AA"});
        assert!(serde_json::from_value::<ChainTip>(bad).is_err());
        let reserved = serde_json::json!({
            "transaction": "00",
            "snapshotId": RESERVED_ZERO_ID
        });
        assert!(serde_json::from_value::<SubmitRequest>(reserved).is_err());
        assert!(UserScanId::new(10).is_err());
        assert!(UserScanId::new(11).is_ok());
    }
}
