use serde::{Deserialize, Serialize};
use thiserror::Error;

pub type HeaderId = [u8; 32];
pub type BlockId = [u8; 32];
pub type BoxId = [u8; 32];
pub type TxId = [u8; 32];

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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainHeader {
    pub height: u32,
    pub header_id: HeaderId,
    pub parent_id: HeaderId,
    pub timestamp_unix_ms: u64,
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
    pub transactions: Vec<ChainTransaction>,
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
    #[error("chain client failure: {0}")]
    Failure(String),
}

pub trait ChainClient: Send + Sync {
    fn committed_tip(&self) -> Result<CommittedTip, ChainClientError>;

    fn snapshot(&self) -> Result<ChainSnapshot, ChainClientError>;

    fn blocks_since(
        &self,
        request: BlocksSinceRequest,
    ) -> Result<BlocksSinceResponse, ChainClientError>;

    fn lookup_utxo(&self, box_id: BoxId) -> Result<UtxoLookup, ChainClientError>;

    fn submit(&self, request: SubmitRequest) -> Result<SubmitResponse, ChainClientError>;

    fn tip(&self) -> Result<CommittedTip, ChainClientError> {
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
        self.lookup_utxo(box_id)
    }

    fn submit_bytes(&self, transaction: Vec<u8>) -> Result<SubmitResponse, ChainClientError> {
        self.submit(SubmitRequest {
            transaction,
            snapshot_id: None,
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

        fn lookup_utxo(&self, box_id: BoxId) -> Result<UtxoLookup, ChainClientError> {
            Ok(UtxoLookup {
                tip: self.committed_tip()?,
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
        assert_eq!(client.lookup_utxo([6; 32]).unwrap().utxo.unwrap().value, 10);
        assert!(matches!(
            client.submit_bytes(vec![7]),
            Ok(SubmitResponse::Accepted { .. })
        ));
    }
}
