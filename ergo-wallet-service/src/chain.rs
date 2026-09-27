use std::time::Duration;

use ergo_primitives::digest::blake2b256;
use ergo_primitives::reader::VlqReader;
use ergo_ser::header::{read_header, Header};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub type HeaderId = [u8; 32];
pub type BlockId = [u8; 32];
pub type BoxId = [u8; 32];
pub type TxId = [u8; 32];
pub const GENESIS_CURSOR_ID: HeaderId = [0; 32];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommittedTip {
    pub height: u32,
    pub header_id: HeaderId,
}

impl CommittedTip {
    pub fn new(height: u32, header_id: HeaderId) -> Self {
        Self { height, header_id }
    }

    pub fn header_id_hex(&self) -> String {
        hex::encode(self.header_id)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainCursor {
    pub height: u32,
    pub header_id: HeaderId,
}

impl ChainCursor {
    pub const fn genesis() -> Self {
        Self {
            height: 0,
            header_id: GENESIS_CURSOR_ID,
        }
    }

    pub fn is_genesis_sentinel(&self) -> bool {
        self.height == 0 && self.header_id == GENESIS_CURSOR_ID
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainHeader {
    pub height: u32,
    pub header_id: HeaderId,
    pub parent_id: HeaderId,
    pub timestamp_unix_ms: u64,
    /// The raw serialized header, PoW solution included. Every other field
    /// is derivable from it; see [`ChainHeader::authenticate`].
    pub header_bytes: Vec<u8>,
}

impl ChainHeader {
    /// Check that `header_bytes` is the header this record claims:
    /// it hashes to `header_id` and carries the claimed height, parent and
    /// timestamp.
    pub fn authenticate(&self) -> Result<Header, HeaderAuthError> {
        let header = authenticate_header(
            &self.header_bytes,
            &self.header_id,
            self.height,
            &self.parent_id,
        )?;
        if header.timestamp != self.timestamp_unix_ms {
            return Err(HeaderAuthError::TimestampMismatch {
                claimed: self.timestamp_unix_ms,
                actual: header.timestamp,
            });
        }
        Ok(header)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReemissionInput {
    pub token_id: [u8; 32],
    pub amount: u64,
    #[serde(default)]
    pub box_ids: Vec<BoxId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainSnapshot {
    pub tip: CommittedTip,
    #[serde(default)]
    pub headers: Vec<ChainHeader>,
    pub active_parameters: serde_json::Value,
    #[serde(default)]
    pub reemission_inputs: Vec<ReemissionInput>,
    pub snapshot_id: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainInput {
    pub box_id: BoxId,
    pub index: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainOutput {
    pub box_id: BoxId,
    pub index: u16,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainTransaction {
    pub tx_id: TxId,
    pub inputs: Vec<ChainInput>,
    pub outputs: Vec<ChainOutput>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainBlock {
    pub block_id: BlockId,
    pub height: u32,
    pub parent_id: BlockId,
    /// The raw serialized header, PoW solution included. `block_id`,
    /// `height` and `parent_id` are derivable from it; see
    /// [`ChainBlock::authenticate_header`].
    pub header_bytes: Vec<u8>,
    pub transactions: Vec<ChainTransaction>,
}

impl ChainBlock {
    /// Check that `header_bytes` is the header this block claims: it hashes
    /// to `block_id` and carries the claimed height and parent.
    ///
    /// This authenticates the block's identity and chain position only. The
    /// transactions are not bound to the header's transactions root, because
    /// the wallet protocol carries wallet-relevant transaction parts rather
    /// than full transaction bytes.
    pub fn authenticate_header(&self) -> Result<Header, HeaderAuthError> {
        authenticate_header(
            &self.header_bytes,
            &self.block_id,
            self.height,
            &self.parent_id,
        )
    }
}

/// Why a header record failed authentication against its raw bytes.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum HeaderAuthError {
    #[error("header bytes are empty")]
    Empty,
    #[error("header bytes do not decode: {0}")]
    Decode(String),
    #[error("header bytes carry {0} trailing byte(s)")]
    TrailingBytes(usize),
    #[error("header bytes hash to {actual}, not the claimed id {claimed}")]
    IdMismatch { claimed: String, actual: String },
    #[error("header height {actual} does not match the claimed height {claimed}")]
    HeightMismatch { claimed: u32, actual: u32 },
    #[error("header parent {actual} does not match the claimed parent {claimed}")]
    ParentMismatch { claimed: String, actual: String },
    #[error("header timestamp {actual} does not match the claimed timestamp {claimed}")]
    TimestampMismatch { claimed: u64, actual: u64 },
}

/// Decode `bytes` as one complete Ergo header and check it against a claimed
/// identity: `blake2b256(bytes)` must equal `id`, and the decoded height and
/// parent must equal `height` and `parent_id`.
///
/// The id is computed over the bytes as received, never over a re-encoding:
/// the decoder drops the unparsed section of v2-v4 headers, so re-encoding a
/// decoded header does not always reproduce the bytes its id was taken over.
pub fn authenticate_header(
    bytes: &[u8],
    id: &HeaderId,
    height: u32,
    parent_id: &HeaderId,
) -> Result<Header, HeaderAuthError> {
    if bytes.is_empty() {
        return Err(HeaderAuthError::Empty);
    }
    let mut reader = VlqReader::new(bytes);
    let header =
        read_header(&mut reader).map_err(|error| HeaderAuthError::Decode(format!("{error:?}")))?;
    if !reader.is_empty() {
        return Err(HeaderAuthError::TrailingBytes(reader.remaining()));
    }
    let actual_id = *blake2b256(bytes).as_bytes();
    if actual_id != *id {
        return Err(HeaderAuthError::IdMismatch {
            claimed: hex::encode(id),
            actual: hex::encode(actual_id),
        });
    }
    if header.height != height {
        return Err(HeaderAuthError::HeightMismatch {
            claimed: height,
            actual: header.height,
        });
    }
    if header.parent_id.as_bytes() != parent_id {
        return Err(HeaderAuthError::ParentMismatch {
            claimed: hex::encode(parent_id),
            actual: hex::encode(header.parent_id.as_bytes()),
        });
    }
    Ok(header)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardBlocksSince {
    pub tip: CommittedTip,
    pub blocks: Vec<ChainBlock>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AncestorBlocksSince {
    pub tip: CommittedTip,
    pub ancestor: ChainCursor,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrunedBlocksSince {
    pub tip: CommittedTip,
    pub minimum_height: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum BlocksSinceResponse {
    Forward(ForwardBlocksSince),
    Ancestor(AncestorBlocksSince),
    Pruned(PrunedBlocksSince),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlocksSinceRequest {
    pub cursor: ChainCursor,
    pub limit: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainAsset {
    pub token_id: [u8; 32],
    pub amount: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Utxo {
    pub box_id: BoxId,
    pub bytes: Vec<u8>,
    pub value: u64,
    pub assets: Vec<ChainAsset>,
    pub creation_tx_id: TxId,
    pub creation_output_index: u16,
    pub creation_height: u32,
}

pub type ChainTip = CommittedTip;
pub type ExpectedTip = CommittedTip;
pub type Tip = CommittedTip;
pub type Snapshot = ChainSnapshot;
pub type BlocksSince = BlocksSinceResponse;
pub type ForwardBlocks = ForwardBlocksSince;
pub type AncestorBlocks = AncestorBlocksSince;
pub type PrunedBlocks = PrunedBlocksSince;
pub type ChainBox = Utxo;
pub type BoxLookup = UtxoLookup;
pub type Submit = SubmitResponse;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UtxoLookupRequest {
    pub box_id: BoxId,
    pub expected_tip: ExpectedTip,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UtxoLookup {
    pub tip: CommittedTip,
    pub utxo: Option<Utxo>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitRequest {
    pub transaction: Vec<u8>,
    #[serde(default)]
    pub snapshot_id: Option<[u8; 32]>,
}

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
        tip: CommittedTip,
        tx_id: TxId,
    },
    Duplicate {
        tip: CommittedTip,
        tx_id: TxId,
    },
    Rejected {
        tip: CommittedTip,
        reason: SubmitError,
        detail: Option<String>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum ChainClientError {
    #[error("unsupported chain operation")]
    Unsupported,
    #[error("chain endpoint unauthorized")]
    Unauthorized,
    #[error("chain endpoint conflict")]
    Conflict,
    #[error("chain endpoint unavailable: {0}")]
    Unavailable(String),
    #[error("chain transport failure: {0}")]
    Transport(String),
    #[error("chain protocol failure: {0}")]
    Protocol(String),
    #[error("chain client overloaded: {0}")]
    Overloaded(String),
    #[error("chain client shutting down: {0}")]
    ShuttingDown(String),
    #[error("chain client submission timed out: {0}")]
    Timeout(String),
    #[error(
        "stale chain tip: expected ({expected_height}, {expected_id}), actual ({actual_height}, {actual_id})",
        expected_height = expected.height,
        expected_id = hex::encode(expected.header_id),
        actual_height = actual.height,
        actual_id = hex::encode(actual.header_id)
    )]
    StaleTip {
        expected: CommittedTip,
        actual: CommittedTip,
    },
    #[error("chain history is pruned (minimum height: {minimum_height:?})")]
    HistoryPruned { minimum_height: Option<u32> },
    #[error("chain history is unavailable: {reason}")]
    UnsupportedHistory { reason: String },
    #[error("chain client failure: {0}")]
    Failure(String),
}

impl ChainClientError {
    pub fn stale_tip(expected: CommittedTip, actual: CommittedTip) -> Self {
        Self::StaleTip { expected, actual }
    }
}

impl UtxoLookupRequest {
    pub fn from_wire(
        request: &ergo_wallet_protocol::chain::BoxLookupRequest,
        current_tip: CommittedTip,
    ) -> Result<Self, ChainClientError> {
        ergo_wallet_protocol::chain::validate_id32(&request.box_id, "box_id")
            .map_err(ChainClientError::Failure)?;
        let box_id = hex::decode(&request.box_id)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| ChainClientError::Failure("box_id must be 32 bytes".to_string()))?;
        let Some(tip) = request.tip.as_deref() else {
            if request.height.is_some() {
                return Err(ChainClientError::Failure(
                    "lookup height requires a tip header id".to_string(),
                ));
            }
            return Ok(Self {
                box_id,
                expected_tip: current_tip,
            });
        };
        ergo_wallet_protocol::chain::validate_id32(tip, "tip")
            .map_err(ChainClientError::Failure)?;
        let header_id = hex::decode(tip)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| ChainClientError::Failure("tip must be 32 bytes".to_string()))?;
        let height = request.height.unwrap_or(current_tip.height);
        Ok(Self {
            box_id,
            expected_tip: CommittedTip::new(height, header_id),
        })
    }
}

impl TryFrom<&ergo_wallet_protocol::chain::BoxLookupRequest> for UtxoLookupRequest {
    type Error = ChainClientError;

    fn try_from(
        request: &ergo_wallet_protocol::chain::BoxLookupRequest,
    ) -> Result<Self, Self::Error> {
        let height = request.height.ok_or_else(|| {
            ChainClientError::Failure("lookup height is required without a current tip".to_string())
        })?;
        Self::from_wire(request, CommittedTip::new(height, [0; 32]))
    }
}

impl TryFrom<(&ergo_wallet_protocol::chain::BoxLookupRequest, CommittedTip)> for UtxoLookupRequest {
    type Error = ChainClientError;

    fn try_from(
        (request, current_tip): (&ergo_wallet_protocol::chain::BoxLookupRequest, CommittedTip),
    ) -> Result<Self, Self::Error> {
        Self::from_wire(request, current_tip)
    }
}

pub trait ChainClient: Send + Sync {
    /// Stop starting requests during shutdown. Blocking implementations may
    /// finish an in-flight request, but must not start another one.
    fn cancel(&self) {}

    fn committed_tip(&self) -> Result<CommittedTip, ChainClientError>;

    fn snapshot(&self) -> Result<ChainSnapshot, ChainClientError>;

    fn blocks_since(
        &self,
        request: BlocksSinceRequest,
    ) -> Result<BlocksSinceResponse, ChainClientError>;

    fn lookup_utxo(
        &self,
        box_id: BoxId,
        expected_tip: CommittedTip,
    ) -> Result<UtxoLookup, ChainClientError>;

    fn submit(&self, request: SubmitRequest) -> Result<SubmitResponse, ChainClientError>;

    fn tip(&self) -> Result<CommittedTip, ChainClientError> {
        self.committed_tip()
    }

    /// Fetch the committed tip, giving up after `timeout`.
    ///
    /// Used by read paths that must not block on an unbounded chain request
    /// (the standalone daemon's `/status`). Implementations that own a network
    /// client with a request-level deadline override this; the default keeps
    /// the unbounded call so a transport that cannot bound the wait is never
    /// silently truncated into a false "tip unavailable".
    fn committed_tip_within(&self, timeout: Duration) -> Result<CommittedTip, ChainClientError> {
        let _ = timeout;
        self.committed_tip()
    }

    fn chain_snapshot(&self) -> Result<ChainSnapshot, ChainClientError> {
        self.snapshot()
    }

    fn blocks_since_cursor(
        &self,
        cursor: ChainCursor,
        limit: u32,
    ) -> Result<BlocksSinceResponse, ChainClientError> {
        self.blocks_since(BlocksSinceRequest { cursor, limit })
    }

    fn lookup_utxo_by_id(&self, box_id: BoxId) -> Result<UtxoLookup, ChainClientError> {
        let tip = self.committed_tip()?;
        self.lookup_utxo(box_id, tip)
    }

    fn lookup_utxo_at_tip(
        &self,
        box_id: BoxId,
        expected_tip: CommittedTip,
    ) -> Result<UtxoLookup, ChainClientError> {
        self.lookup_utxo(box_id, expected_tip)
    }

    fn lookup_utxo_request(
        &self,
        request: UtxoLookupRequest,
    ) -> Result<UtxoLookup, ChainClientError> {
        self.lookup_utxo(request.box_id, request.expected_tip)
    }

    fn lookup_utxo_wire(
        &self,
        request: &ergo_wallet_protocol::chain::BoxLookupRequest,
    ) -> Result<UtxoLookup, ChainClientError> {
        let current_tip = self.committed_tip()?;
        self.lookup_utxo_request(UtxoLookupRequest::from_wire(request, current_tip)?)
    }

    fn submit_bytes(&self, transaction: Vec<u8>) -> Result<SubmitResponse, ChainClientError> {
        let tip = self.committed_tip()?;
        self.submit(SubmitRequest {
            transaction,
            snapshot_id: Some(tip.header_id),
        })
    }
}

pub mod wire {
    pub use ergo_wallet_protocol::chain::*;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Stub;

    impl ChainClient for Stub {
        fn committed_tip(&self) -> Result<CommittedTip, ChainClientError> {
            Ok(CommittedTip::new(9, [1; 32]))
        }

        fn snapshot(&self) -> Result<ChainSnapshot, ChainClientError> {
            Ok(ChainSnapshot {
                tip: self.committed_tip()?,
                headers: Vec::new(),
                active_parameters: serde_json::json!({"hardFork": 1}),
                reemission_inputs: Vec::new(),
                snapshot_id: [2; 32],
            })
        }

        fn blocks_since(
            &self,
            _request: BlocksSinceRequest,
        ) -> Result<BlocksSinceResponse, ChainClientError> {
            Ok(BlocksSinceResponse::Pruned(PrunedBlocksSince {
                tip: self.committed_tip()?,
                minimum_height: 4,
            }))
        }

        fn lookup_utxo(
            &self,
            box_id: BoxId,
            expected_tip: CommittedTip,
        ) -> Result<UtxoLookup, ChainClientError> {
            Ok(UtxoLookup {
                tip: expected_tip,
                utxo: Some(Utxo {
                    box_id,
                    bytes: vec![1, 2, 3],
                    value: 10,
                    assets: Vec::new(),
                    creation_tx_id: [3; 32],
                    creation_output_index: 0,
                    creation_height: 8,
                }),
            })
        }

        fn submit(&self, request: SubmitRequest) -> Result<SubmitResponse, ChainClientError> {
            Ok(SubmitResponse::Accepted {
                tip: self.committed_tip()?,
                tx_id: [request.transaction.len() as u8; 32],
            })
        }
    }

    #[test]
    fn neutral_response_shapes_cover_all_blocks_since_variants() {
        let tip = CommittedTip::new(9, [1; 32]);
        let cursor = ChainCursor {
            height: 5,
            header_id: [4; 32],
        };
        let block = ChainBlock {
            block_id: [5; 32],
            height: 9,
            parent_id: [4; 32],
            header_bytes: Vec::new(),
            transactions: Vec::new(),
        };
        let responses = [
            BlocksSinceResponse::Forward(ForwardBlocksSince {
                tip: tip.clone(),
                blocks: vec![block],
            }),
            BlocksSinceResponse::Ancestor(AncestorBlocksSince {
                tip: tip.clone(),
                ancestor: cursor,
            }),
            BlocksSinceResponse::Pruned(PrunedBlocksSince {
                tip,
                minimum_height: 2,
            }),
        ];
        assert_eq!(responses.len(), 3);
        assert!(matches!(responses[0], BlocksSinceResponse::Forward(_)));
        assert!(matches!(responses[1], BlocksSinceResponse::Ancestor(_)));
        assert!(matches!(responses[2], BlocksSinceResponse::Pruned(_)));
    }

    #[test]
    fn neutral_snapshot_utxo_and_submit_shapes_are_owned() {
        let tip = CommittedTip::new(12, [8; 32]);
        let snapshot = ChainSnapshot {
            tip: tip.clone(),
            headers: vec![ChainHeader {
                height: 12,
                header_id: [8; 32],
                parent_id: [7; 32],
                timestamp_unix_ms: 123,
                header_bytes: Vec::new(),
            }],
            active_parameters: serde_json::json!({"hardFork": 1}),
            reemission_inputs: vec![ReemissionInput {
                token_id: [9; 32],
                amount: 4,
                box_ids: vec![[10; 32]],
            }],
            snapshot_id: [11; 32],
        };
        assert_eq!(snapshot.tip, tip);
        assert_eq!(snapshot.headers[0].parent_id, [7; 32]);

        let lookup = UtxoLookup {
            tip: tip.clone(),
            utxo: Some(Utxo {
                box_id: [12; 32],
                bytes: vec![1, 2],
                value: 99,
                assets: vec![ChainAsset {
                    token_id: [13; 32],
                    amount: 2,
                }],
                creation_tx_id: [14; 32],
                creation_output_index: 1,
                creation_height: 11,
            }),
        };
        assert_eq!(lookup.utxo.unwrap().assets[0].amount, 2);

        let accepted = SubmitResponse::Accepted {
            tip: tip.clone(),
            tx_id: [15; 32],
        };
        let duplicate = SubmitResponse::Duplicate {
            tip: tip.clone(),
            tx_id: [15; 32],
        };
        let rejected = SubmitResponse::Rejected {
            tip,
            reason: SubmitError::Fee,
            detail: Some("fee".to_string()),
        };
        assert!(matches!(accepted, SubmitResponse::Accepted { .. }));
        assert!(matches!(duplicate, SubmitResponse::Duplicate { .. }));
        assert!(matches!(rejected, SubmitResponse::Rejected { .. }));
    }

    #[test]
    fn wire_lookup_converts_header_id_query_to_a_full_expected_tip() {
        let current = CommittedTip::new(9, [1; 32]);
        let request = ergo_wallet_protocol::chain::BoxLookupRequest {
            box_id: hex::encode([2; 32]),
            tip: Some(hex::encode([3; 32])),
            height: Some(7),
        };
        let converted = UtxoLookupRequest::try_from((&request, current.clone())).unwrap();
        assert_eq!(converted.box_id, [2; 32]);
        assert_eq!(converted.expected_tip, CommittedTip::new(7, [3; 32]));
        assert_eq!(
            UtxoLookupRequest::try_from(&request).unwrap().expected_tip,
            CommittedTip::new(7, [3; 32])
        );

        let no_height = ergo_wallet_protocol::chain::BoxLookupRequest {
            box_id: hex::encode([2; 32]),
            tip: Some(hex::encode([3; 32])),
            height: None,
        };
        assert_eq!(
            UtxoLookupRequest::from_wire(&no_height, current.clone())
                .unwrap()
                .expected_tip,
            CommittedTip::new(9, [3; 32])
        );
        let no_tip = ergo_wallet_protocol::chain::BoxLookupRequest {
            box_id: hex::encode([2; 32]),
            tip: None,
            height: None,
        };
        assert_eq!(
            UtxoLookupRequest::from_wire(&no_tip, current.clone())
                .unwrap()
                .expected_tip,
            current
        );
    }

    #[test]
    fn wire_lookup_rejects_a_height_without_a_tip() {
        let request = ergo_wallet_protocol::chain::BoxLookupRequest {
            box_id: hex::encode([2; 32]),
            tip: None,
            height: Some(1),
        };
        assert!(matches!(
            UtxoLookupRequest::from_wire(&request, CommittedTip::new(1, [1; 32])),
            Err(ChainClientError::Failure(_))
        ));
    }

    #[test]
    fn chain_client_is_object_safe_and_returns_owned_values() {
        let client: &dyn ChainClient = &Stub;
        assert_eq!(client.committed_tip().unwrap().height, 9);
        assert_eq!(client.snapshot().unwrap().snapshot_id, [2; 32]);
        assert!(matches!(
            client.blocks_since_cursor(
                ChainCursor {
                    height: 0,
                    header_id: [0; 32],
                },
                10,
            ),
            Ok(BlocksSinceResponse::Pruned(_))
        ));
        assert_eq!(
            client
                .lookup_utxo([6; 32], CommittedTip::new(9, [1; 32]))
                .unwrap()
                .utxo
                .unwrap()
                .value,
            10
        );
        assert!(matches!(
            client.submit_bytes(vec![7]),
            Ok(SubmitResponse::Accepted { .. })
        ));
    }

    mod header_auth {
        use super::super::*;
        use ergo_primitives::digest::{ADDigest, Digest32, ModifierId};
        use ergo_primitives::group_element::GroupElement;
        use ergo_ser::autolykos::AutolykosSolution;
        use ergo_ser::header::{serialize_header, serialize_header_without_pow};

        fn header(version: u8, height: u32, parent: [u8; 32], unparsed: Vec<u8>) -> Header {
            Header {
                version,
                parent_id: ModifierId::from_bytes(parent),
                ad_proofs_root: Digest32::from_bytes([1; 32]),
                transactions_root: Digest32::from_bytes([2; 32]),
                state_root: ADDigest::from_bytes([3; 33]),
                timestamp: 1_700_000_000_000 + u64::from(height),
                extension_root: Digest32::from_bytes([4; 32]),
                n_bits: 16842752,
                height,
                votes: [0; 3],
                unparsed_bytes: unparsed,
                solution: AutolykosSolution::V2 {
                    pk: GroupElement::from([2; 33]),
                    nonce: [5; 8],
                },
            }
        }

        fn block(height: u32, parent: [u8; 32]) -> ChainBlock {
            let (header_bytes, id) =
                serialize_header(&header(2, height, parent, Vec::new())).unwrap();
            ChainBlock {
                block_id: *id.as_bytes(),
                height,
                parent_id: parent,
                header_bytes,
                transactions: Vec::new(),
            }
        }

        #[test]
        fn genuine_block_header_authenticates() {
            let block = block(7, [9; 32]);
            let decoded = block.authenticate_header().unwrap();
            assert_eq!(decoded.height, 7);
            assert_eq!(decoded.parent_id.as_bytes(), &[9; 32]);
        }

        #[test]
        fn a_block_served_under_another_id_is_rejected() {
            let mut block = block(7, [9; 32]);
            block.block_id = [0xAA; 32];
            assert!(matches!(
                block.authenticate_header(),
                Err(HeaderAuthError::IdMismatch { .. })
            ));
        }

        #[test]
        fn claimed_height_and_parent_must_match_the_header() {
            let mut wrong_height = block(7, [9; 32]);
            wrong_height.height = 8;
            assert_eq!(
                wrong_height.authenticate_header(),
                Err(HeaderAuthError::HeightMismatch {
                    claimed: 8,
                    actual: 7
                })
            );
            let mut wrong_parent = block(7, [9; 32]);
            wrong_parent.parent_id = [8; 32];
            assert!(matches!(
                wrong_parent.authenticate_header(),
                Err(HeaderAuthError::ParentMismatch { .. })
            ));
        }

        #[test]
        fn empty_truncated_and_padded_header_bytes_are_rejected() {
            let genuine = block(7, [9; 32]);
            let mut empty = genuine.clone();
            empty.header_bytes.clear();
            assert_eq!(empty.authenticate_header(), Err(HeaderAuthError::Empty));

            let mut truncated = genuine.clone();
            truncated.header_bytes.truncate(40);
            assert!(matches!(
                truncated.authenticate_header(),
                Err(HeaderAuthError::Decode(_))
            ));

            // Padding is caught before hashing, so a node cannot smuggle bytes
            // past the decoder even with a matching id.
            let mut padded = genuine;
            padded.header_bytes.push(0);
            padded.block_id = *blake2b256(&padded.header_bytes).as_bytes();
            assert_eq!(
                padded.authenticate_header(),
                Err(HeaderAuthError::TrailingBytes(1))
            );
        }

        #[test]
        fn id_is_taken_over_received_bytes_not_a_re_encoding() {
            // A v2 header may carry an unparsed section on the wire, which the
            // decoder drops (the encoder refuses to write one), so re-encoding
            // the decoded header yields different bytes and a different id.
            // Authentication must hash what was received. Splice a 3-byte
            // section in where the encoder writes its empty length byte: the
            // last byte of the PoW-less encoding.
            let plain = header(2, 7, [9; 32], Vec::new());
            let (plain_bytes, _) = serialize_header(&plain).unwrap();
            let length_at = serialize_header_without_pow(&plain).unwrap().len() - 1;
            assert_eq!(plain_bytes[length_at], 0);
            let mut bytes = plain_bytes[..length_at].to_vec();
            bytes.extend_from_slice(&[3, 1, 2, 3]);
            bytes.extend_from_slice(&plain_bytes[length_at + 1..]);
            let id = *blake2b256(&bytes).as_bytes();

            let decoded = authenticate_header(&bytes, &id, 7, &[9; 32]).unwrap();
            assert!(decoded.unparsed_bytes.is_empty());
            let (reencoded, reencoded_id) = serialize_header(&decoded).unwrap();
            assert_eq!(reencoded, plain_bytes);
            assert_ne!(reencoded, bytes);
            assert_ne!(*reencoded_id.as_bytes(), id);
        }

        #[test]
        fn snapshot_header_timestamp_must_match() {
            let block = block(7, [9; 32]);
            let decoded = block.authenticate_header().unwrap();
            let mut record = ChainHeader {
                height: 7,
                header_id: block.block_id,
                parent_id: [9; 32],
                timestamp_unix_ms: decoded.timestamp,
                header_bytes: block.header_bytes.clone(),
            };
            assert!(record.authenticate().is_ok());
            record.timestamp_unix_ms += 1;
            assert!(matches!(
                record.authenticate(),
                Err(HeaderAuthError::TimestampMismatch { .. })
            ));
        }
    }
}
