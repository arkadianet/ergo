use std::sync::Arc;
use std::time::Duration;

use ergo_api::traits::{WalletChain, WalletChainError};
use ergo_api::types::{SubmitError as ApiSubmitError, SubmitMode};
use ergo_primitives::digest::ModifierId;
use ergo_primitives::reader::VlqReader;
use ergo_ser::block_transactions::read_stored_block_transactions;
use ergo_ser::ergo_box::read_ergo_box;
use ergo_ser::header::{read_header, Header};
use ergo_ser::modifier_id::{compute_section_id, TYPE_BLOCK_TRANSACTIONS};
use ergo_ser::transaction::{read_transaction, transaction_id};
use ergo_state::reader::ChainStoreReader;
use ergo_wallet_protocol::chain as wire;
use ergo_wallet_service::chain::{
    BlocksSinceRequest, BlocksSinceResponse, ChainBlock, ChainClient, ChainClientError,
    ChainCursor, ChainHeader, ChainInput, ChainOutput, ChainSnapshot, ChainTransaction,
    CommittedTip, ReemissionInput, SubmitRequest, SubmitResponse, Utxo, UtxoLookup,
    UtxoLookupRequest, GENESIS_CURSOR_ID,
};

use super::ChainStateAccessor;

const MAX_BLOCKS_PER_RESPONSE: u32 = 1_024;
const MAX_ANCESTOR_WALK: u32 = 4_096;
const SUBMIT_WAIT: Duration = Duration::from_secs(6);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SubmitFailureClass {
    Duplicate,
    RejectedInvalid,
    RejectedFee,
    Overloaded,
    ShuttingDown,
    Timeout,
    Unsupported,
    Internal,
}

pub trait IntoChainSubmitter {
    fn into_chain_submitter(self) -> Option<Arc<dyn ergo_api::NodeSubmit>>;
}

impl IntoChainSubmitter for Option<Arc<dyn ergo_api::NodeSubmit>> {
    fn into_chain_submitter(self) -> Option<Arc<dyn ergo_api::NodeSubmit>> {
        self
    }
}

impl IntoChainSubmitter for Arc<dyn ergo_api::NodeSubmit> {
    fn into_chain_submitter(self) -> Option<Arc<dyn ergo_api::NodeSubmit>> {
        Some(self)
    }
}

impl<T> IntoChainSubmitter for Arc<T>
where
    T: ergo_api::NodeSubmit + Send + Sync + 'static,
{
    fn into_chain_submitter(self) -> Option<Arc<dyn ergo_api::NodeSubmit>> {
        Some(self)
    }
}

pub struct InProcessChainClient {
    reader: ChainStoreReader,
    state: Option<Arc<dyn ChainStateAccessor>>,
    submitter: Option<Arc<dyn ergo_api::NodeSubmit>>,
    reemission_inputs: Vec<ReemissionInput>,
    #[cfg(test)]
    tip_movement_hook: Option<Arc<dyn Fn() -> Result<(), ChainClientError> + Send + Sync>>,
}

impl InProcessChainClient {
    pub fn new<S>(reader: ChainStoreReader, submitter: S) -> Self
    where
        S: IntoChainSubmitter,
    {
        Self {
            reader,
            state: None,
            submitter: submitter.into_chain_submitter(),
            reemission_inputs: Vec::new(),
            #[cfg(test)]
            tip_movement_hook: None,
        }
    }

    pub fn from_reader(reader: ChainStoreReader) -> Self {
        Self {
            reader,
            state: None,
            submitter: None,
            reemission_inputs: Vec::new(),
            #[cfg(test)]
            tip_movement_hook: None,
        }
    }

    pub fn from_chain_reader<S>(
        reader: ChainStoreReader,
        submitter: S,
        is_pruned: bool,
        reemission: Option<ergo_validation::ReemissionRuleInputs>,
    ) -> Self
    where
        S: IntoChainSubmitter,
    {
        let state = Arc::new(super::ChainStateAccessorImpl::chain_only(
            reader.clone(),
            is_pruned,
            reemission,
        ));
        Self::new(reader, submitter).with_state_accessor(state)
    }

    pub fn from_state_store<S>(store: &ergo_state::store::StateStore, submitter: S) -> Self
    where
        S: IntoChainSubmitter,
    {
        let reader = store.reader_handle();
        let wallet_store: Arc<dyn ergo_state::wallet::WalletStore> =
            Arc::new(ergo_state::wallet::RedbWalletStore::new(store.db_arc()));
        let state = Arc::new(super::ChainStateAccessorImpl::new(
            reader.clone(),
            wallet_store,
            false,
            None,
        ));
        Self::new(reader, submitter).with_state_accessor(state)
    }

    pub fn with_state_accessor(mut self, state: Arc<dyn ChainStateAccessor>) -> Self {
        self.state = Some(state);
        self
    }

    pub fn with_reemission_inputs(mut self, inputs: Vec<ReemissionInput>) -> Self {
        self.reemission_inputs = inputs;
        self
    }

    #[cfg(test)]
    fn with_tip_movement_hook(
        mut self,
        hook: impl Fn() -> Result<(), ChainClientError> + Send + Sync + 'static,
    ) -> Self {
        self.tip_movement_hook = Some(Arc::new(hook));
        self
    }

    #[cfg(test)]
    fn run_tip_movement_hook(&self) -> Result<(), ChainClientError> {
        self.tip_movement_hook
            .as_ref()
            .map(|hook| hook())
            .unwrap_or(Ok(()))
    }

    #[cfg(not(test))]
    fn run_tip_movement_hook(&self) -> Result<(), ChainClientError> {
        Ok(())
    }

    pub fn reader(&self) -> &ChainStoreReader {
        &self.reader
    }

    pub fn submitter(&self) -> Option<&Arc<dyn ergo_api::NodeSubmit>> {
        self.submitter.as_ref()
    }

    fn state_error(context: &str, error: impl std::fmt::Display) -> ChainClientError {
        ChainClientError::Failure(format!("{context}: {error}"))
    }

    fn chain_state_error(error: super::ChainStateError) -> ChainClientError {
        match error {
            super::ChainStateError::StaleTip {
                expected_height,
                expected_id,
                actual_height,
                actual_id,
            } => {
                let parse = |value: String| {
                    hex::decode(value)
                        .ok()
                        .and_then(|bytes| bytes.try_into().ok())
                };
                match (parse(expected_id), parse(actual_id)) {
                    (Some(expected), Some(actual)) => ChainClientError::StaleTip {
                        expected: CommittedTip::new(expected_height, expected),
                        actual: CommittedTip::new(actual_height, actual),
                    },
                    _ => ChainClientError::Failure("invalid stale-tip identity".to_string()),
                }
            }
            super::ChainStateError::NoCommittedState | super::ChainStateError::Unsupported => {
                ChainClientError::Unsupported
            }
            other => Self::state_error("chain snapshot", other),
        }
    }

    fn tip_from_state(&self) -> Result<CommittedTip, ChainClientError> {
        if let Some(state) = &self.state {
            return state
                .committed_tip()
                .map_err(Self::chain_state_error)?
                .map(|tip| CommittedTip::new(tip.height, tip.header_id))
                .ok_or(ChainClientError::Unsupported);
        }
        self.reader
            .committed_tip()
            .map_err(|error| Self::state_error("committed tip", error))?
            .map(|(height, header_id)| CommittedTip::new(height, header_id))
            .ok_or(ChainClientError::Unsupported)
    }

    fn ensure_tip(&self, expected: &CommittedTip) -> Result<CommittedTip, ChainClientError> {
        let actual = self.tip_from_state()?;
        if actual != *expected {
            return Err(ChainClientError::stale_tip(expected.clone(), actual));
        }
        Ok(actual)
    }

    fn header(&self, header_id: &[u8; 32]) -> Result<Header, ChainClientError> {
        let bytes = self
            .reader
            .get_header(header_id)
            .map_err(|error| Self::state_error("header read", error))?
            .ok_or_else(|| ChainClientError::Failure(format!("header {header_id:?} is missing")))?;
        let mut reader = VlqReader::new(&bytes);
        read_header(&mut reader).map_err(|error| Self::state_error("header decode", error))
    }

    fn block_from_state(&self, height: u32) -> Result<ChainBlock, ChainClientError> {
        let block_id = self
            .reader
            .committed_block_id_at_height(height)
            .map_err(|error| Self::state_error("applied header index read", error))?
            .ok_or_else(|| {
                ChainClientError::Failure(format!("no committed header at height {height}"))
            })?;
        let header = self.header(&block_id)?;
        if header.height != height {
            return Err(ChainClientError::Failure(format!(
                "header height {} does not match applied height {height}",
                header.height
            )));
        }
        let section_id = compute_section_id(
            TYPE_BLOCK_TRANSACTIONS,
            &block_id,
            header.transactions_root.as_bytes(),
        );
        let section = self
            .reader
            .get_block_section(&section_id)
            .map_err(|error| Self::state_error("block transaction read", error))?;
        if let Some(section) = section {
            let transactions = read_stored_block_transactions(&section)
                .map_err(|error| Self::state_error("block transaction decode", error))?;
            if transactions.header_id != ModifierId::from_bytes(block_id) {
                return Err(ChainClientError::Failure(format!(
                    "block transaction header mismatch at height {height}"
                )));
            }
            return self.chain_block_from_transactions(block_id, header, transactions.transactions);
        }
        if let Some(state) = &self.state {
            let block = state
                .read_block_at(height)
                .map_err(|error| Self::state_error("state block read", error))?
                .ok_or_else(|| {
                    ChainClientError::Failure(format!("no committed block at height {height}"))
                })?;
            return self.chain_block_from_rescan(block_id, header, block);
        }
        Err(ChainClientError::Failure(format!(
            "block transaction section is missing at height {height}"
        )))
    }

    fn chain_block_from_transactions(
        &self,
        block_id: [u8; 32],
        header: Header,
        transactions: Vec<ergo_ser::transaction::Transaction>,
    ) -> Result<ChainBlock, ChainClientError> {
        let transactions: Vec<ChainTransaction> = transactions
            .into_iter()
            .map(|transaction| {
                let tx_id = *transaction_id(&transaction)
                    .map_err(|error| Self::state_error("transaction id", error))?
                    .as_bytes();
                let inputs = transaction
                    .inputs
                    .iter()
                    .enumerate()
                    .map(|(index, input)| {
                        let input_index = u16::try_from(index).map_err(|_| {
                            Self::state_error("transaction input index overflow", "")
                        })?;
                        Ok(ChainInput {
                            box_id: *input.box_id.as_bytes(),
                            index: input_index,
                        })
                    })
                    .collect::<Result<Vec<_>, ChainClientError>>()?;
                let outputs = transaction
                    .output_candidates
                    .iter()
                    .enumerate()
                    .map(|(index, candidate)| {
                        let output_index = u16::try_from(index).map_err(|_| {
                            Self::state_error("transaction output index overflow", "")
                        })?;
                        let modifier_id = ModifierId::from_bytes(tx_id);
                        let ergo_box = ergo_ser::ergo_box::ErgoBox {
                            candidate: candidate.clone(),
                            transaction_id: modifier_id,
                            index: output_index,
                        };
                        let bytes = ergo_ser::ergo_box::serialize_ergo_box(&ergo_box)
                            .map_err(|error| Self::state_error("box encode", error))?;
                        let box_id = ergo_box
                            .box_id()
                            .map_err(|error| Self::state_error("box id", error))?;
                        Ok(ChainOutput {
                            box_id: *box_id.as_bytes(),
                            index: output_index,
                            bytes,
                        })
                    })
                    .collect::<Result<Vec<_>, ChainClientError>>()?;
                Ok(ChainTransaction {
                    tx_id,
                    inputs,
                    outputs,
                })
            })
            .collect::<Result<Vec<_>, ChainClientError>>()?;
        Ok(ChainBlock {
            block_id,
            height: header.height,
            parent_id: *header.parent_id.as_bytes(),
            transactions,
        })
    }

    fn chain_block_from_rescan(
        &self,
        block_id: [u8; 32],
        header: Header,
        block: ergo_wallet_service::wallet::scan::RescanBlock,
    ) -> Result<ChainBlock, ChainClientError> {
        let transactions: Vec<ChainTransaction> = block
            .txs
            .into_iter()
            .map(|transaction| {
                Ok(ChainTransaction {
                    tx_id: transaction.tx_id,
                    inputs: transaction
                        .inputs
                        .into_iter()
                        .enumerate()
                        .map(|(index, box_id)| {
                            Ok(ChainInput {
                                box_id,
                                index: u16::try_from(index).map_err(|_| {
                                    Self::state_error("transaction input index overflow", "")
                                })?,
                            })
                        })
                        .collect::<Result<Vec<_>, ChainClientError>>()?,
                    outputs: transaction
                        .outputs
                        .into_iter()
                        .map(|output| ChainOutput {
                            box_id: output.box_id,
                            index: output.output_index,
                            bytes: output.box_bytes,
                        })
                        .collect(),
                })
            })
            .collect::<Result<Vec<_>, ChainClientError>>()?;
        Ok(ChainBlock {
            block_id,
            height: header.height,
            parent_id: *header.parent_id.as_bytes(),
            transactions,
        })
    }

    fn common_ancestor(
        &self,
        cursor: ChainCursor,
        tip: CommittedTip,
    ) -> Result<ChainCursor, ChainClientError> {
        self.common_ancestor_with_limit(cursor, tip, MAX_ANCESTOR_WALK)
    }

    fn common_ancestor_with_limit(
        &self,
        cursor: ChainCursor,
        tip: CommittedTip,
        max_walk: u32,
    ) -> Result<ChainCursor, ChainClientError> {
        let mut left = (cursor.height, cursor.header_id);
        let mut right = (tip.height, tip.header_id);
        for _ in 0..max_walk {
            if left == right {
                return Ok(ChainCursor {
                    height: left.0,
                    header_id: left.1,
                });
            }
            if left.0 == 0 || right.0 == 0 {
                return Err(self.history_unavailable(format!(
                    "ancestor walk reached height 0 without a common header (left {}, right {})",
                    left.0, right.0
                )));
            }
            if left.0 > right.0 {
                let Some(parent_id) = self.parent_id(left.1)? else {
                    return Err(self.history_unavailable(format!(
                        "ancestor history is missing parent for height {}",
                        left.0
                    )));
                };
                left = (left.0 - 1, parent_id);
            } else {
                let Some(parent_id) = self.parent_id(right.1)? else {
                    return Err(self.history_unavailable(format!(
                        "ancestor history is missing parent for height {}",
                        right.0
                    )));
                };
                right = (right.0 - 1, parent_id);
            }
        }
        Err(ChainClientError::UnsupportedHistory {
            reason: format!("ancestor walk exceeded {max_walk} headers"),
        })
    }

    fn history_unavailable(&self, reason: String) -> ChainClientError {
        self.history_unavailable_at(None, reason)
    }

    fn history_unavailable_at(
        &self,
        cursor_height: Option<u32>,
        reason: String,
    ) -> ChainClientError {
        match self.reader.minimal_full_block_height() {
            Ok(minimum_height) if cursor_height.is_some_and(|height| minimum_height > height) => {
                ChainClientError::HistoryPruned {
                    minimum_height: Some(minimum_height),
                }
            }
            _ => ChainClientError::UnsupportedHistory { reason },
        }
    }

    fn ensure_tip_unchanged(
        &self,
        expected: &CommittedTip,
    ) -> Result<CommittedTip, ChainClientError> {
        let actual = self.tip_from_state()?;
        if actual != *expected {
            return Err(ChainClientError::stale_tip(expected.clone(), actual));
        }
        Ok(actual)
    }

    fn validate_cursor(&self, cursor: ChainCursor) -> Result<(), ChainClientError> {
        if cursor.height == 0 {
            if cursor.header_id != GENESIS_CURSOR_ID {
                return Err(ChainClientError::Failure(
                    "height-zero cursor must use the genesis sentinel".to_string(),
                ));
            }
            return Ok(());
        }
        if cursor.header_id == [0; 32] {
            return Err(ChainClientError::Failure(
                "positive-height cursor is missing its header identity".to_string(),
            ));
        }
        Ok(())
    }

    fn parent_id(&self, header_id: [u8; 32]) -> Result<Option<[u8; 32]>, ChainClientError> {
        if let Some(meta) = self
            .reader
            .get_header_meta(&header_id)
            .map_err(|error| Self::state_error("header metadata read", error))?
        {
            return Ok(Some(meta.parent_id));
        }
        self.reader
            .get_header(&header_id)
            .map_err(|error| Self::state_error("header read", error))?
            .map(|bytes| {
                let mut reader = VlqReader::new(&bytes);
                read_header(&mut reader)
                    .map(|header| *header.parent_id.as_bytes())
                    .map_err(|error| Self::state_error("header decode", error))
            })
            .transpose()
    }

    fn submit_bytes(&self, bytes: Vec<u8>) -> Result<String, ApiSubmitError> {
        let submitter = self.submitter.clone().ok_or_else(|| ApiSubmitError {
            reason: "unsupported".to_string(),
            detail: Some("in-process submitter is not configured".to_string()),
        })?;
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::Builder::new()
            .name("wallet-chain-submit".to_string())
            .spawn(move || {
                let result = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|error| ApiSubmitError {
                        reason: "runtime".to_string(),
                        detail: Some(error.to_string()),
                    })
                    .and_then(|runtime| {
                        runtime.block_on(submitter.submit_transaction(bytes, SubmitMode::Broadcast))
                    });
                let _ = sender.send(result);
            });
        if worker.is_err() {
            return Err(ApiSubmitError {
                reason: "submitter".to_string(),
                detail: Some("failed to start submit worker".to_string()),
            });
        }
        match receiver.recv_timeout(SUBMIT_WAIT) {
            Ok(result) => result,
            Err(_) => Err(ApiSubmitError {
                reason: "timeout".to_string(),
                detail: Some("submit worker did not reply".to_string()),
            }),
        }
    }

    fn classify_submit_error(reason: &str) -> SubmitFailureClass {
        match reason {
            "duplicate" => SubmitFailureClass::Duplicate,
            "fee" | "below_min_fee" | "insufficient_fee" => SubmitFailureClass::RejectedFee,
            "overloaded" => SubmitFailureClass::Overloaded,
            "shutting_down" => SubmitFailureClass::ShuttingDown,
            "timeout" => SubmitFailureClass::Timeout,
            "unsupported" | "route_disabled" => SubmitFailureClass::Unsupported,
            "internal_error" | "runtime" | "submitter" => SubmitFailureClass::Internal,
            _ => SubmitFailureClass::RejectedInvalid,
        }
    }

    fn map_submit_error(
        &self,
        tip: CommittedTip,
        transaction: &[u8],
        error: ApiSubmitError,
    ) -> Result<SubmitResponse, ChainClientError> {
        let ApiSubmitError {
            reason,
            detail: source_detail,
        } = error;
        let detail = source_detail
            .as_ref()
            .map(|detail| format!("{reason}: {detail}"));
        match Self::classify_submit_error(&reason) {
            SubmitFailureClass::Duplicate => {
                let tx_id = self.tx_id_from_bytes(transaction)?;
                Ok(SubmitResponse::Duplicate { tip, tx_id })
            }
            SubmitFailureClass::RejectedFee => Ok(SubmitResponse::Rejected {
                tip,
                reason: ergo_wallet_service::chain::SubmitError::Fee,
                detail,
            }),
            SubmitFailureClass::RejectedInvalid => Ok(SubmitResponse::Rejected {
                tip,
                reason: ergo_wallet_service::chain::SubmitError::Invalid,
                detail,
            }),
            SubmitFailureClass::Overloaded => Err(ChainClientError::Overloaded(
                source_detail
                    .unwrap_or_else(|| "node submission channel is overloaded".to_string()),
            )),
            SubmitFailureClass::ShuttingDown => Err(ChainClientError::ShuttingDown(
                source_detail.unwrap_or_else(|| "node is shutting down".to_string()),
            )),
            SubmitFailureClass::Timeout => Err(ChainClientError::Timeout(
                source_detail.unwrap_or_else(|| "node submission timed out".to_string()),
            )),
            SubmitFailureClass::Unsupported => Err(ChainClientError::Unsupported),
            SubmitFailureClass::Internal => Err(ChainClientError::Failure(format!(
                "submit failed: {reason}{}",
                source_detail
                    .map(|detail| format!(": {detail}"))
                    .unwrap_or_default()
            ))),
        }
    }

    fn tx_id_from_bytes(&self, bytes: &[u8]) -> Result<[u8; 32], ChainClientError> {
        let mut reader = VlqReader::new(bytes);
        let transaction = read_transaction(&mut reader)
            .map_err(|error| Self::state_error("submit transaction decode", error))?;
        if !reader.is_empty() {
            return Err(ChainClientError::Failure(
                "submit transaction has trailing bytes".to_string(),
            ));
        }
        Ok(*transaction_id(&transaction)
            .map_err(|error| Self::state_error("submit transaction id", error))?
            .as_bytes())
    }
}

fn wire_tip(tip: CommittedTip) -> Result<wire::ChainTip, WalletChainError> {
    wire::ChainTip::new(tip.height, hex::encode(tip.header_id)).map_err(WalletChainError::internal)
}

fn map_service_error(error: ChainClientError) -> WalletChainError {
    match error {
        ChainClientError::Unsupported => WalletChainError::Unsupported,
        ChainClientError::Unauthorized | ChainClientError::Conflict => {
            WalletChainError::Failure("chain request was rejected".to_string())
        }
        ChainClientError::Unavailable(detail) | ChainClientError::Transport(detail) => {
            WalletChainError::Overloaded(detail)
        }
        ChainClientError::Protocol(detail) => WalletChainError::Failure(detail),
        ChainClientError::Overloaded(detail) => WalletChainError::Overloaded(detail),
        ChainClientError::ShuttingDown(detail) => WalletChainError::ShuttingDown(detail),
        ChainClientError::Timeout(detail) => WalletChainError::Timeout(detail),
        ChainClientError::StaleTip { expected, actual } => {
            match (wire_tip(expected), wire_tip(actual)) {
                (Ok(expected), Ok(actual)) => WalletChainError::StaleTip { expected, actual },
                _ => WalletChainError::Internal("invalid stale-tip identity".to_string()),
            }
        }
        ChainClientError::HistoryPruned {
            minimum_height: Some(minimum_height),
        } => WalletChainError::history_pruned(minimum_height),
        ChainClientError::HistoryPruned {
            minimum_height: None,
        } => WalletChainError::Failure(
            "chain history is unavailable without a minimum height".to_string(),
        ),
        ChainClientError::UnsupportedHistory { reason } => {
            WalletChainError::Failure(format!("chain history is unavailable: {reason}"))
        }
        ChainClientError::Failure(message) => WalletChainError::Failure(message),
    }
}

fn map_request_error(error: ChainClientError) -> WalletChainError {
    match error {
        ChainClientError::Failure(message) => WalletChainError::invalid(message),
        other => map_service_error(other),
    }
}

fn decode_wire_id(value: &str, field: &str) -> Result<[u8; 32], WalletChainError> {
    wire::validate_id32(value, field).map_err(WalletChainError::invalid)?;
    hex::decode(value)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| WalletChainError::invalid(format!("{field} must be 32 bytes")))
}

fn decode_wire_bytes(value: &str, field: &str) -> Result<Vec<u8>, WalletChainError> {
    wire::validate_hex_bytes(value, field).map_err(WalletChainError::invalid)?;
    hex::decode(value).map_err(|error| WalletChainError::invalid(format!("{field}: {error}")))
}

fn wire_snapshot(snapshot: ChainSnapshot) -> Result<wire::ChainSnapshot, WalletChainError> {
    Ok(wire::ChainSnapshot {
        tip: wire_tip(snapshot.tip)?,
        headers: snapshot
            .headers
            .into_iter()
            .map(|header| wire::ChainHeader {
                height: header.height,
                header_id: hex::encode(header.header_id),
                parent_id: hex::encode(header.parent_id),
                timestamp_unix_ms: header.timestamp_unix_ms,
            })
            .collect(),
        active_parameters: snapshot.active_parameters,
        reemission_inputs: snapshot
            .reemission_inputs
            .into_iter()
            .map(|input| {
                let box_ids = input
                    .box_ids
                    .into_iter()
                    .map(hex::encode)
                    .collect::<Vec<_>>();
                wire::ReemissionInput {
                    token_id: hex::encode(input.token_id),
                    amount: input.amount.to_string(),
                    box_ids: (!box_ids.is_empty()).then_some(box_ids),
                }
            })
            .collect(),
        snapshot_id: hex::encode(snapshot.snapshot_id),
    })
}

fn wire_blocks_since(
    response: BlocksSinceResponse,
) -> Result<wire::BlocksSinceResponse, WalletChainError> {
    match response {
        BlocksSinceResponse::Forward(response) => Ok(wire::BlocksSinceResponse::Forward(
            wire::ForwardBlocksSince {
                tip: wire_tip(response.tip)?,
                blocks: response
                    .blocks
                    .into_iter()
                    .map(|block| {
                        Ok(wire::ChainBlock {
                            block_id: hex::encode(block.block_id),
                            height: block.height,
                            parent_id: hex::encode(block.parent_id),
                            transactions: block
                                .transactions
                                .into_iter()
                                .map(|transaction| wire::ChainTransaction {
                                    tx_id: hex::encode(transaction.tx_id),
                                    inputs: transaction
                                        .inputs
                                        .into_iter()
                                        .map(|input| wire::ChainInput {
                                            box_id: hex::encode(input.box_id),
                                            index: input.index,
                                        })
                                        .collect(),
                                    outputs: transaction
                                        .outputs
                                        .into_iter()
                                        .map(|output| wire::ChainOutput {
                                            box_id: hex::encode(output.box_id),
                                            index: output.index,
                                            bytes: hex::encode(output.bytes),
                                        })
                                        .collect(),
                                })
                                .collect(),
                        })
                    })
                    .collect::<Result<Vec<_>, WalletChainError>>()?,
            },
        )),
        BlocksSinceResponse::Ancestor(response) => Ok(wire::BlocksSinceResponse::Ancestor(
            wire::AncestorBlocksSince {
                tip: wire_tip(response.tip)?,
                ancestor: wire::ChainCursor {
                    height: response.ancestor.height,
                    header_id: hex::encode(response.ancestor.header_id),
                },
            },
        )),
        BlocksSinceResponse::Pruned(response) => {
            Ok(wire::BlocksSinceResponse::Pruned(wire::PrunedBlocksSince {
                tip: wire_tip(response.tip)?,
                minimum_height: response.minimum_height,
            }))
        }
    }
}

fn wire_box(utxo: Utxo) -> wire::ChainBox {
    wire::ChainBox {
        box_id: hex::encode(utxo.box_id),
        bytes: hex::encode(utxo.bytes),
        value: utxo.value,
        assets: utxo
            .assets
            .into_iter()
            .map(|asset| wire::ChainAsset {
                token_id: hex::encode(asset.token_id),
                amount: asset.amount.to_string(),
            })
            .collect(),
        creation_tx_id: hex::encode(utxo.creation_tx_id),
        creation_output_index: utxo.creation_output_index,
        creation_height: utxo.creation_height,
    }
}

fn wire_box_lookup(lookup: UtxoLookup) -> Result<wire::BoxLookupResponse, WalletChainError> {
    let Some(utxo) = lookup.utxo else {
        return Err(WalletChainError::BoxNotFound);
    };
    Ok(wire::BoxLookupResponse {
        tip: wire_tip(lookup.tip)?,
        box_info: wire_box(utxo),
    })
}

fn wire_submit(response: SubmitResponse) -> Result<wire::SubmitResponse, WalletChainError> {
    match response {
        SubmitResponse::Accepted { tip, tx_id } => Ok(wire::SubmitResponse::Accepted {
            tip: wire_tip(tip)?,
            tx_id: hex::encode(tx_id),
        }),
        SubmitResponse::Duplicate { tip, tx_id } => Ok(wire::SubmitResponse::Duplicate {
            tip: wire_tip(tip)?,
            tx_id: hex::encode(tx_id),
        }),
        SubmitResponse::Rejected {
            tip,
            reason,
            detail,
        } => Ok(wire::SubmitResponse::Rejected {
            tip: wire_tip(tip)?,
            reason: match reason {
                ergo_wallet_service::chain::SubmitError::Duplicate => wire::SubmitError::Duplicate,
                ergo_wallet_service::chain::SubmitError::Invalid => wire::SubmitError::Invalid,
                ergo_wallet_service::chain::SubmitError::Fee => wire::SubmitError::Fee,
            },
            detail,
        }),
    }
}

pub struct WalletChainAdapter {
    client: Arc<dyn ChainClient>,
}

impl WalletChainAdapter {
    pub fn new(client: Arc<dyn ChainClient>) -> Self {
        Self { client }
    }

    pub fn from_client(client: Arc<dyn ChainClient>) -> Self {
        Self::new(client)
    }

    pub fn into_dyn(self) -> Arc<dyn WalletChain> {
        Arc::new(self)
    }
}

impl WalletChain for WalletChainAdapter {
    fn tip(&self) -> Result<wire::ChainTip, WalletChainError> {
        wire_tip(self.client.committed_tip().map_err(map_service_error)?)
    }

    fn snapshot(&self) -> Result<wire::ChainSnapshot, WalletChainError> {
        wire_snapshot(self.client.snapshot().map_err(map_service_error)?)
    }

    fn blocks_since(
        &self,
        request: wire::BlocksSinceRequest,
    ) -> Result<wire::BlocksSinceResponse, WalletChainError> {
        let cursor = ChainCursor {
            height: request.height,
            header_id: decode_wire_id(&request.id, "id")?,
        };
        let response = self
            .client
            .blocks_since(BlocksSinceRequest {
                cursor,
                limit: request.limit,
            })
            .map_err(map_service_error)?;
        wire_blocks_since(response)
    }

    fn box_lookup(
        &self,
        request: wire::BoxLookupRequest,
    ) -> Result<wire::BoxLookupResponse, WalletChainError> {
        wire::validate_id32(&request.box_id, "box_id").map_err(WalletChainError::invalid)?;
        if let Some(tip) = request.tip.as_deref() {
            wire::validate_id32(tip, "tip").map_err(WalletChainError::invalid)?;
        } else if request.height.is_some() {
            return Err(WalletChainError::invalid(
                "lookup height requires a tip header id",
            ));
        }
        let current_tip = self.client.committed_tip().map_err(map_service_error)?;
        let service_request =
            UtxoLookupRequest::from_wire(&request, current_tip).map_err(map_request_error)?;
        let lookup = self
            .client
            .lookup_utxo_request(service_request)
            .map_err(map_service_error)?;
        wire_box_lookup(lookup)
    }

    fn submit(
        &self,
        request: wire::SubmitRequest,
    ) -> Result<wire::SubmitResponse, WalletChainError> {
        if request.transaction.is_empty() {
            return Err(WalletChainError::invalid(
                "transaction bytes must be non-empty lowercase hex",
            ));
        }
        let transaction = decode_wire_bytes(&request.transaction, "transaction")?;
        let snapshot_id = request
            .snapshot_id
            .as_deref()
            .map(|value| {
                wire::validate_snapshot_id(value).map_err(WalletChainError::invalid)?;
                decode_wire_id(value, "snapshot_id")
            })
            .transpose()?;
        let response = self
            .client
            .submit(SubmitRequest {
                transaction,
                snapshot_id,
            })
            .map_err(map_service_error)?;
        wire_submit(response)
    }
}

impl ChainClient for InProcessChainClient {
    fn committed_tip(&self) -> Result<CommittedTip, ChainClientError> {
        self.tip_from_state()
    }

    fn snapshot(&self) -> Result<ChainSnapshot, ChainClientError> {
        let state = self.state.as_ref().ok_or(ChainClientError::Unsupported)?;
        let snapshot = state.chain_snapshot().map_err(Self::chain_state_error)?;
        let tip = snapshot.tip();
        let headers = snapshot
            .headers()
            .iter()
            .zip(snapshot.header_ids())
            .map(|(header, header_id)| ChainHeader {
                height: header.height,
                header_id: *header_id,
                parent_id: *header.parent_id.as_bytes(),
                timestamp_unix_ms: header.timestamp,
            })
            .collect();
        let active_parameters = snapshot.active_params();
        let active_parameters = serde_json::json!({
            "epochStartHeight": active_parameters.epoch_start_height,
            "blockVersion": active_parameters.block_version,
            "storageFeeFactor": active_parameters.storage_fee_factor,
            "minValuePerByte": active_parameters.min_value_per_byte,
            "maxBlockSize": active_parameters.max_block_size,
            "maxBlockCost": active_parameters.max_block_cost,
            "tokenAccessCost": active_parameters.token_access_cost,
            "inputCost": active_parameters.input_cost,
            "dataInputCost": active_parameters.data_input_cost,
            "outputCost": active_parameters.output_cost,
            "subblocksPerBlock": active_parameters.subblocks_per_block,
            "extra": active_parameters.extra,
        });
        let reemission_inputs = if self.reemission_inputs.is_empty() {
            snapshot
                .reemission_rules()
                .map(|rules| {
                    vec![ReemissionInput {
                        token_id: rules.reemission_token_id,
                        amount: 0,
                        box_ids: Vec::new(),
                    }]
                })
                .unwrap_or_default()
        } else {
            self.reemission_inputs.clone()
        };
        Ok(ChainSnapshot {
            tip: CommittedTip::new(tip.height, tip.header_id),
            headers,
            active_parameters,
            reemission_inputs,
            snapshot_id: tip.header_id,
        })
    }

    fn blocks_since(
        &self,
        request: BlocksSinceRequest,
    ) -> Result<BlocksSinceResponse, ChainClientError> {
        self.validate_cursor(request.cursor.clone())?;
        let tip = self.tip_from_state()?;
        if request.cursor.height > tip.height {
            return Err(ChainClientError::stale_tip(
                CommittedTip::new(request.cursor.height, request.cursor.header_id),
                tip,
            ));
        }
        let minimum_height = self
            .reader
            .minimal_full_block_height()
            .map_err(|error| Self::state_error("prune floor read", error))?;
        if request.cursor.height.saturating_add(1) < minimum_height {
            return Ok(BlocksSinceResponse::Pruned(
                ergo_wallet_service::chain::PrunedBlocksSince {
                    tip,
                    minimum_height,
                },
            ));
        }
        if request.cursor.height > 0 {
            let canonical = self
                .reader
                .committed_block_id_at_height(request.cursor.height)
                .map_err(|error| Self::state_error("cursor lookup", error))?;
            let Some(canonical) = canonical else {
                return Err(self.history_unavailable_at(
                    Some(request.cursor.height),
                    format!(
                        "cursor height {} is not locally indexed",
                        request.cursor.height
                    ),
                ));
            };
            if canonical != request.cursor.header_id {
                let ancestor = self.common_ancestor(request.cursor.clone(), tip.clone())?;
                self.run_tip_movement_hook()?;
                self.ensure_tip_unchanged(&tip)?;
                return Ok(BlocksSinceResponse::Ancestor(
                    ergo_wallet_service::chain::AncestorBlocksSince { tip, ancestor },
                ));
            }
        }
        if request.limit == 0 || request.cursor.height == tip.height {
            self.run_tip_movement_hook()?;
            self.ensure_tip_unchanged(&tip)?;
            return Ok(BlocksSinceResponse::Forward(
                ergo_wallet_service::chain::ForwardBlocksSince {
                    tip,
                    blocks: Vec::new(),
                },
            ));
        }
        let first_height = request.cursor.height.saturating_add(1);
        let count = request
            .limit
            .min(MAX_BLOCKS_PER_RESPONSE)
            .min(tip.height.saturating_sub(first_height).saturating_add(1));
        let mut blocks = Vec::with_capacity(count as usize);
        for offset in 0..count {
            let height = first_height.saturating_add(offset);
            blocks.push(self.block_from_state(height)?);
        }
        self.run_tip_movement_hook()?;
        self.ensure_tip_unchanged(&tip)?;
        Ok(BlocksSinceResponse::Forward(
            ergo_wallet_service::chain::ForwardBlocksSince { tip, blocks },
        ))
    }

    fn lookup_utxo(
        &self,
        box_id: [u8; 32],
        expected_tip: CommittedTip,
    ) -> Result<UtxoLookup, ChainClientError> {
        self.ensure_tip(&expected_tip)?;
        let bytes = self
            .reader
            .lookup_box(&box_id)
            .map_err(|error| Self::state_error("utxo lookup", error))?;
        let Some(bytes) = bytes else {
            self.ensure_tip(&expected_tip)?;
            return Ok(UtxoLookup {
                tip: expected_tip,
                utxo: None,
            });
        };
        let mut reader = VlqReader::new(&bytes);
        let ergo_box =
            read_ergo_box(&mut reader).map_err(|error| Self::state_error("utxo decode", error))?;
        if !reader.is_empty() {
            return Err(ChainClientError::Failure(
                "utxo bytes have trailing data".to_string(),
            ));
        }
        let actual_id = ergo_box
            .box_id()
            .map_err(|error| Self::state_error("utxo id", error))?;
        if *actual_id.as_bytes() != box_id {
            return Err(ChainClientError::Failure(
                "utxo id does not match its persisted bytes".to_string(),
            ));
        }
        self.ensure_tip(&expected_tip)?;
        Ok(UtxoLookup {
            tip: expected_tip,
            utxo: Some(Utxo {
                box_id,
                bytes,
                value: ergo_box.candidate.value,
                assets: ergo_box
                    .candidate
                    .tokens
                    .iter()
                    .map(|token| ergo_wallet_service::chain::ChainAsset {
                        token_id: *token.token_id.as_bytes(),
                        amount: token.amount,
                    })
                    .collect(),
                creation_tx_id: *ergo_box.transaction_id.as_bytes(),
                creation_output_index: ergo_box.index,
                creation_height: ergo_box.candidate.creation_height,
            }),
        })
    }

    fn submit(&self, request: SubmitRequest) -> Result<SubmitResponse, ChainClientError> {
        let tip = self.tip_from_state()?;
        if let Some(snapshot_id) = request.snapshot_id {
            if snapshot_id != tip.header_id {
                return Err(ChainClientError::stale_tip(
                    CommittedTip::new(tip.height, snapshot_id),
                    tip,
                ));
            }
        }
        let admission = self.submit_bytes(request.transaction.clone());
        let after = self.tip_from_state()?;
        if after != tip {
            return Err(ChainClientError::stale_tip(tip, after));
        }
        match admission {
            Ok(tx_id) => {
                let bytes = hex::decode(&tx_id).map_err(|error| {
                    ChainClientError::Failure(format!("submit returned invalid tx id: {error}"))
                })?;
                let tx_id: [u8; 32] = bytes.try_into().map_err(|_| {
                    ChainClientError::Failure(
                        "submit returned a tx id that is not 32 bytes".to_string(),
                    )
                })?;
                Ok(SubmitResponse::Accepted { tip, tx_id })
            }
            Err(error) => self.map_submit_error(tip, &request.transaction, error),
        }
    }
}

pub type NodeChainClient = InProcessChainClient;
pub type ChainClientAdapter = InProcessChainClient;

#[cfg(test)]
mod tests {
    use ergo_primitives::digest::{ADDigest, Digest32, ModifierId};
    use ergo_primitives::writer::VlqWriter;
    use ergo_ser::autolykos::AutolykosSolution;
    use ergo_ser::block_transactions::{write_block_transactions, BlockTransactions};
    use ergo_ser::header::serialize_header;
    use ergo_ser::modifier_id::compute_section_id;
    use ergo_state::store::StateStore;
    use ergo_state::wallet::RedbWalletStore;
    use std::sync::Arc;

    use super::*;

    struct AcceptSubmit;

    #[async_trait::async_trait]
    impl ergo_api::NodeSubmit for AcceptSubmit {
        async fn submit_transaction(
            &self,
            _bytes: Vec<u8>,
            _mode: SubmitMode,
        ) -> Result<String, ApiSubmitError> {
            Ok(hex::encode([9; 32]))
        }

        async fn submit_transaction_json(
            &self,
            _input: ergo_api::compat::types::ScalaTransactionInput,
            _mode: SubmitMode,
        ) -> Result<String, ApiSubmitError> {
            Err(ApiSubmitError {
                reason: "unsupported".to_string(),
                detail: None,
            })
        }
    }

    struct AdvancingSubmit {
        store: Arc<std::sync::Mutex<StateStore>>,
    }

    #[async_trait::async_trait]
    impl ergo_api::NodeSubmit for AdvancingSubmit {
        async fn submit_transaction(
            &self,
            _bytes: Vec<u8>,
            _mode: SubmitMode,
        ) -> Result<String, ApiSubmitError> {
            let mut store = self.store.lock().unwrap();
            let (height, header_id) = store.reader_handle().committed_tip().unwrap().unwrap();
            apply_empty_block_at(&mut store, height + 1, ModifierId::from_bytes(header_id));
            Ok(hex::encode([9; 32]))
        }

        async fn submit_transaction_json(
            &self,
            _input: ergo_api::compat::types::ScalaTransactionInput,
            _mode: SubmitMode,
        ) -> Result<String, ApiSubmitError> {
            Err(ApiSubmitError {
                reason: "unsupported".to_string(),
                detail: None,
            })
        }
    }

    fn header(height: u32, parent: ModifierId) -> Header {
        Header {
            version: 2,
            parent_id: parent,
            ad_proofs_root: Digest32::from_bytes([0; 32]),
            transactions_root: Digest32::from_bytes([0; 32]),
            state_root: ADDigest::from_bytes([0; 33]),
            timestamp: 1_000_000 + height as u64,
            extension_root: Digest32::from_bytes([0; 32]),
            n_bits: 16842752,
            height,
            votes: [0; 3],
            unparsed_bytes: Vec::new(),
            solution: AutolykosSolution::V2 {
                pk: ergo_primitives::group_element::GroupElement::from([2; 33]),
                nonce: [0; 8],
            },
        }
    }

    fn valid_utxo_box() -> ([u8; 32], Vec<u8>) {
        let tree = ergo_ser::ergo_tree::ErgoTree {
            version: 0,
            has_size: true,
            constant_segregation: true,
            constants: vec![(
                ergo_ser::sigma_type::SigmaType::SBoolean,
                ergo_ser::sigma_value::SigmaValue::Boolean(true),
            )],
            body: ergo_ser::opcode::Expr::Const {
                tpe: ergo_ser::sigma_type::SigmaType::SBoolean,
                val: ergo_ser::sigma_value::SigmaValue::Boolean(true),
            },
        };
        let candidate = ergo_ser::ergo_box::ErgoBoxCandidate::new(
            1_000_000,
            tree,
            1,
            Vec::new(),
            ergo_ser::register::AdditionalRegisters::empty(),
        )
        .unwrap();
        let ergo_box = ergo_ser::ergo_box::ErgoBox {
            candidate,
            transaction_id: ModifierId::from_bytes([7; 32]),
            index: 0,
        };
        let box_id = *ergo_box.box_id().unwrap().as_bytes();
        let bytes = ergo_ser::ergo_box::serialize_ergo_box(&ergo_box).unwrap();
        (box_id, bytes)
    }

    fn apply_empty_block_at(store: &mut StateStore, height: u32, parent: ModifierId) -> [u8; 32] {
        let (bytes, id) = serialize_header(&header(height, parent)).unwrap();
        let id_bytes = *id.as_bytes();
        store.store_header(&id_bytes, &bytes).unwrap();
        let mut writer = VlqWriter::new();
        write_block_transactions(
            &mut writer,
            &BlockTransactions {
                header_id: id,
                transactions: Vec::new(),
            },
        )
        .unwrap();
        let section_id = compute_section_id(
            TYPE_BLOCK_TRANSACTIONS,
            &id_bytes,
            header(height, parent).transactions_root.as_bytes(),
        );
        store
            .store_block_section(&section_id, &writer.result())
            .unwrap();
        let root = store.root_digest();
        store
            .apply_block_unchecked_for_test(height, &id_bytes, &root, &[])
            .unwrap();
        id_bytes
    }

    fn apply_empty_block_at_with_nonce(
        store: &mut StateStore,
        height: u32,
        parent: ModifierId,
        nonce: [u8; 8],
    ) -> [u8; 32] {
        let mut header = header(height, parent);
        if let AutolykosSolution::V2 { nonce: value, .. } = &mut header.solution {
            *value = nonce;
        }
        let (bytes, id) = serialize_header(&header).unwrap();
        let id_bytes = *id.as_bytes();
        store.store_header(&id_bytes, &bytes).unwrap();
        let mut writer = VlqWriter::new();
        write_block_transactions(
            &mut writer,
            &BlockTransactions {
                header_id: id,
                transactions: Vec::new(),
            },
        )
        .unwrap();
        let section_id = compute_section_id(
            TYPE_BLOCK_TRANSACTIONS,
            &id_bytes,
            header.transactions_root.as_bytes(),
        );
        store
            .store_block_section(&section_id, &writer.result())
            .unwrap();
        let root = store.root_digest();
        store
            .apply_block_unchecked_for_test(height, &id_bytes, &root, &[])
            .unwrap();
        id_bytes
    }

    fn apply_empty_blocks(store: &mut StateStore, count: u32) -> Vec<[u8; 32]> {
        let mut parent = ModifierId::from_bytes([0; 32]);
        let mut ids = Vec::new();
        for height in 1..=count {
            let id_bytes = apply_empty_block_at(store, height, parent);
            parent = ModifierId::from_bytes(id_bytes);
            ids.push(id_bytes);
        }
        ids
    }

    #[test]
    fn snapshot_uses_state_adapter_and_stale_tip_is_typed() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = StateStore::open(&dir.path().join("state.redb")).unwrap();
        store.initialize_genesis(&[]).unwrap();
        let ids = apply_empty_blocks(&mut store, 3);
        store
            .test_force_put_header_chain_index(2, &[0xEE; 32])
            .unwrap();
        let reader = ChainStoreReader::new_from_db(store.db_arc());
        let wallet_store: Arc<dyn ergo_state::wallet::WalletStore> =
            Arc::new(RedbWalletStore::new(store.db_arc()));
        let accessor = Arc::new(super::super::ChainStateAccessorImpl::new(
            reader.clone(),
            wallet_store,
            false,
            None,
        ));
        let client = InProcessChainClient::from_reader(reader).with_state_accessor(accessor);
        let first = client.snapshot().unwrap();
        let second = client.snapshot().unwrap();
        assert_eq!(first, second);
        assert_eq!(first.snapshot_id, ids[2]);
        assert_eq!(first.headers[0].header_id, ids[2]);
        assert_eq!(first.headers[1].header_id, ids[1]);
        assert_eq!(first.headers[2].header_id, ids[0]);
        assert_eq!(first.headers[0].parent_id, ids[1]);
        assert_eq!(first.snapshot_id, first.tip.header_id);

        apply_empty_blocks(&mut store, 1);
        let error = client.lookup_utxo([1; 32], first.tip.clone()).unwrap_err();
        assert!(matches!(error, ChainClientError::StaleTip { .. }));
    }

    #[test]
    fn lookup_utxo_distinguishes_absent_from_decode_failure() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = StateStore::open(&dir.path().join("state.redb")).unwrap();
        store
            .initialize_genesis(&[([0x77; 32], vec![0x01, 0x02])])
            .unwrap();
        let client =
            InProcessChainClient::from_reader(ChainStoreReader::new_from_db(store.db_arc()));
        let tip = CommittedTip::new(0, [0; 32]);

        let absent = client.lookup_utxo([0x78; 32], tip.clone()).unwrap();
        assert!(absent.utxo.is_none());
        let invalid = client.lookup_utxo([0x77; 32], tip).unwrap_err();
        assert!(matches!(invalid, ChainClientError::Failure(_)));
    }

    #[test]
    fn lookup_utxo_rejects_trailing_bytes_and_box_id_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = StateStore::open(&dir.path().join("state.redb")).unwrap();
        let (box_id, bytes) = valid_utxo_box();
        let mut trailing = bytes.clone();
        trailing.push(0xAA);
        store
            .initialize_genesis(&[(box_id, trailing), ([0x99; 32], bytes)])
            .unwrap();
        let client =
            InProcessChainClient::from_reader(ChainStoreReader::new_from_db(store.db_arc()));
        let tip = CommittedTip::new(0, [0; 32]);

        let trailing_error = client.lookup_utxo(box_id, tip.clone()).unwrap_err();
        assert!(matches!(
            trailing_error,
            ChainClientError::Failure(message) if message.contains("trailing")
        ));
        let mismatch_error = client.lookup_utxo([0x99; 32], tip).unwrap_err();
        assert!(matches!(
            mismatch_error,
            ChainClientError::Failure(message) if message.contains("does not match")
        ));
    }

    #[test]
    fn blocks_since_returns_forward_blocks_and_snapshot_uses_ten_header_window() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = StateStore::open(&dir.path().join("state.redb")).unwrap();
        store.initialize_genesis(&[]).unwrap();
        let ids = apply_empty_blocks(&mut store, 12);
        let client =
            InProcessChainClient::from_state_store(&store, None::<Arc<dyn ergo_api::NodeSubmit>>);
        let response = client
            .blocks_since(BlocksSinceRequest {
                cursor: ChainCursor {
                    height: 0,
                    header_id: [0; 32],
                },
                limit: 3,
            })
            .unwrap();
        match response {
            BlocksSinceResponse::Forward(forward) => {
                assert_eq!(forward.tip.height, 12);
                assert_eq!(forward.blocks.len(), 3);
                assert_eq!(forward.blocks[0].height, 1);
                assert_eq!(forward.blocks[2].height, 3);
            }
            other => panic!("unexpected response: {other:?}"),
        }
        let snapshot = client.snapshot().unwrap();
        assert_eq!(snapshot.tip.height, 12);
        assert_eq!(snapshot.headers.len(), 10);
        assert_eq!(snapshot.headers[0].height, 12);
        assert_eq!(snapshot.snapshot_id, ids[11]);
    }

    #[test]
    fn submit_reason_table_maps_admission_transport_and_internal_failures() {
        let cases = [
            ("duplicate", SubmitFailureClass::Duplicate),
            ("deserialize", SubmitFailureClass::RejectedInvalid),
            ("validation_failed", SubmitFailureClass::RejectedInvalid),
            ("script_failed", SubmitFailureClass::RejectedInvalid),
            ("monetary_failed", SubmitFailureClass::RejectedInvalid),
            ("cost_exceeded", SubmitFailureClass::RejectedInvalid),
            ("reemission_policy", SubmitFailureClass::RejectedInvalid),
            ("below_min_fee", SubmitFailureClass::RejectedFee),
            ("pool_full", SubmitFailureClass::RejectedInvalid),
            ("double_spend_loser", SubmitFailureClass::RejectedInvalid),
            ("size_limit", SubmitFailureClass::RejectedInvalid),
            ("unresolved_input", SubmitFailureClass::RejectedInvalid),
            ("unresolved_data_input", SubmitFailureClass::RejectedInvalid),
            ("budget_exhausted", SubmitFailureClass::RejectedInvalid),
            ("disabled", SubmitFailureClass::RejectedInvalid),
            ("ibd_gated", SubmitFailureClass::RejectedInvalid),
            ("tip_unready", SubmitFailureClass::RejectedInvalid),
            ("overloaded", SubmitFailureClass::Overloaded),
            ("shutting_down", SubmitFailureClass::ShuttingDown),
            ("timeout", SubmitFailureClass::Timeout),
            ("route_disabled", SubmitFailureClass::Unsupported),
            ("internal_error", SubmitFailureClass::Internal),
        ];
        for (reason, expected) in cases {
            assert_eq!(
                InProcessChainClient::classify_submit_error(reason),
                expected,
                "reason {reason}"
            );
        }
    }

    #[test]
    fn submit_maps_api_success_to_neutral_response() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = StateStore::open(&dir.path().join("state.redb")).unwrap();
        store.initialize_genesis(&[]).unwrap();
        let client = InProcessChainClient::new(
            ChainStoreReader::new_from_db(store.db_arc()),
            Arc::new(AcceptSubmit) as Arc<dyn ergo_api::NodeSubmit>,
        );
        let response = client
            .submit(SubmitRequest {
                transaction: vec![1, 2, 3],
                snapshot_id: None,
            })
            .unwrap();
        assert!(matches!(response, SubmitResponse::Accepted { .. }));
    }

    #[test]
    fn submit_rejects_a_stale_snapshot_before_admission() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = StateStore::open(&dir.path().join("state.redb")).unwrap();
        store.initialize_genesis(&[]).unwrap();
        apply_empty_blocks(&mut store, 1);
        let (height, _) = store.reader_handle().committed_tip().unwrap().unwrap();
        let client = InProcessChainClient::new(
            ChainStoreReader::new_from_db(store.db_arc()),
            Arc::new(AcceptSubmit) as Arc<dyn ergo_api::NodeSubmit>,
        );
        let error = client
            .submit(SubmitRequest {
                transaction: vec![1, 2, 3],
                snapshot_id: Some([0xEE; 32]),
            })
            .unwrap_err();
        assert!(matches!(
            error,
            ChainClientError::StaleTip {
                expected,
                actual,
            } if expected.height == height && expected.header_id == [0xEE; 32] && actual.height == height
        ));
    }

    #[test]
    fn submit_rejects_a_tip_that_moves_after_admission() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = StateStore::open(&dir.path().join("state.redb")).unwrap();
        store.initialize_genesis(&[]).unwrap();
        apply_empty_blocks(&mut store, 1);
        let old_tip = store.reader_handle().committed_tip().unwrap().unwrap();
        let store = Arc::new(std::sync::Mutex::new(store));
        let client = InProcessChainClient::new(
            ChainStoreReader::new_from_db(store.lock().unwrap().db_arc()),
            Arc::new(AdvancingSubmit {
                store: store.clone(),
            }) as Arc<dyn ergo_api::NodeSubmit>,
        );
        let error = client
            .submit(SubmitRequest {
                transaction: vec![1, 2, 3],
                snapshot_id: Some(old_tip.1),
            })
            .unwrap_err();
        assert!(matches!(error, ChainClientError::StaleTip { .. }));
    }

    #[test]
    fn blocks_since_reports_ancestor_for_a_stale_cursor() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = StateStore::open(&dir.path().join("state.redb")).unwrap();
        store.initialize_genesis(&[]).unwrap();
        apply_empty_blocks(&mut store, 3);
        let client =
            InProcessChainClient::from_reader(ChainStoreReader::new_from_db(store.db_arc()));
        let response = client.blocks_since(BlocksSinceRequest {
            cursor: ChainCursor {
                height: 2,
                header_id: [0xEE; 32],
            },
            limit: 10,
        });
        assert!(matches!(
            response,
            Err(ChainClientError::HistoryPruned { .. })
                | Err(ChainClientError::UnsupportedHistory { .. })
        ));
    }

    #[test]
    fn blocks_since_returns_the_common_ancestor_for_a_same_height_reorg() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = StateStore::open(&dir.path().join("state.redb")).unwrap();
        store.initialize_genesis(&[]).unwrap();
        let old_ids = apply_empty_blocks(&mut store, 3);
        store.rollback_to(1, None, None).unwrap();
        let new_tip = apply_empty_block_at_with_nonce(
            &mut store,
            2,
            ModifierId::from_bytes(old_ids[0]),
            [1; 8],
        );
        let client =
            InProcessChainClient::from_reader(ChainStoreReader::new_from_db(store.db_arc()));
        let response = client.blocks_since(BlocksSinceRequest {
            cursor: ChainCursor {
                height: 2,
                header_id: old_ids[1],
            },
            limit: 1,
        });
        match response {
            Ok(BlocksSinceResponse::Ancestor(response)) => {
                assert_eq!(response.tip.header_id, new_tip);
                assert_eq!(response.ancestor.height, 1);
                assert_eq!(response.ancestor.header_id, old_ids[0]);
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn blocks_since_rejects_an_invalid_genesis_cursor() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = StateStore::open(&dir.path().join("state.redb")).unwrap();
        store.initialize_genesis(&[]).unwrap();
        apply_empty_blocks(&mut store, 1);
        let client =
            InProcessChainClient::from_reader(ChainStoreReader::new_from_db(store.db_arc()));
        assert!(matches!(
            client.blocks_since(BlocksSinceRequest {
                cursor: ChainCursor {
                    height: 0,
                    header_id: [1; 32],
                },
                limit: 1,
            }),
            Err(ChainClientError::Failure(_))
        ));
    }

    #[test]
    fn blocks_since_missing_cursor_history_is_typed() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = StateStore::open(&dir.path().join("state.redb")).unwrap();
        store.initialize_genesis(&[]).unwrap();
        store
            .test_force_set_best_full_block_unsafe([9; 32], 3)
            .unwrap();
        let client =
            InProcessChainClient::from_reader(ChainStoreReader::new_from_db(store.db_arc()));
        assert!(matches!(
            client.blocks_since(BlocksSinceRequest {
                cursor: ChainCursor {
                    height: 1,
                    header_id: [1; 32],
                },
                limit: 1,
            }),
            Err(ChainClientError::HistoryPruned { .. })
                | Err(ChainClientError::UnsupportedHistory { .. })
        ));
    }

    #[test]
    fn blocks_since_maps_final_tip_movement_to_stale_tip() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = StateStore::open(&dir.path().join("state.redb")).unwrap();
        store.initialize_genesis(&[]).unwrap();
        apply_empty_blocks(&mut store, 1);
        let store = Arc::new(std::sync::Mutex::new(store));
        let reader = ChainStoreReader::new_from_db(store.lock().unwrap().db_arc());
        let moved = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let moved_hook = moved.clone();
        let client = InProcessChainClient::new(reader, None::<Arc<dyn ergo_api::NodeSubmit>>)
            .with_tip_movement_hook(move || {
                if moved_hook.swap(true, std::sync::atomic::Ordering::SeqCst) {
                    return Ok(());
                }
                let mut state = store.lock().unwrap();
                let (height, header_id) = state.reader_handle().committed_tip().unwrap().unwrap();
                apply_empty_block_at(&mut state, height + 1, ModifierId::from_bytes(header_id));
                Ok(())
            });
        assert!(matches!(
            client.blocks_since(BlocksSinceRequest {
                cursor: ChainCursor {
                    height: 0,
                    header_id: [0; 32],
                },
                limit: 1,
            }),
            Err(ChainClientError::StaleTip { .. })
        ));
    }

    #[test]
    fn ancestor_walk_exhaustion_is_typed_and_never_returns_zero() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = StateStore::open(&dir.path().join("state.redb")).unwrap();
        store.initialize_genesis(&[]).unwrap();
        let ids = apply_empty_blocks(&mut store, 3);
        let client =
            InProcessChainClient::from_reader(ChainStoreReader::new_from_db(store.db_arc()));
        let result = client.common_ancestor_with_limit(
            ChainCursor {
                height: 1,
                header_id: ids[0],
            },
            CommittedTip::new(3, ids[2]),
            1,
        );
        assert!(matches!(
            result,
            Err(ChainClientError::UnsupportedHistory { .. })
        ));
    }

    #[test]
    fn blocks_since_reports_pruned_floor_and_unsupported_without_state() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = StateStore::open(&dir.path().join("state.redb")).unwrap();
        store.initialize_genesis(&[]).unwrap();
        apply_empty_blocks(&mut store, 3);
        store.write_minimal_full_block_height(3).unwrap();
        let client =
            InProcessChainClient::from_reader(ChainStoreReader::new_from_db(store.db_arc()));
        let response = client
            .blocks_since(BlocksSinceRequest {
                cursor: ChainCursor {
                    height: 0,
                    header_id: [0; 32],
                },
                limit: 10,
            })
            .unwrap();
        assert!(matches!(response, BlocksSinceResponse::Pruned(_)));

        let fresh_dir = tempfile::tempdir().unwrap();
        let fresh = StateStore::open(&fresh_dir.path().join("state.redb")).unwrap();
        let fresh_client =
            InProcessChainClient::from_reader(ChainStoreReader::new_from_db(fresh.db_arc()));
        assert!(matches!(
            fresh_client.committed_tip(),
            Err(ChainClientError::Unsupported)
        ));
    }

    #[test]
    fn api_wallet_chain_adapter_reads_committed_snapshot_without_wallet_store() {
        let dir = tempfile::tempdir().unwrap();
        let (box_id, box_bytes) = valid_utxo_box();
        let mut store = StateStore::open(&dir.path().join("state.redb")).unwrap();
        store.initialize_genesis(&[(box_id, box_bytes)]).unwrap();
        let ids = apply_empty_blocks(&mut store, 2);
        let client = InProcessChainClient::from_chain_reader(
            ChainStoreReader::new_from_db(store.db_arc()),
            None::<Arc<dyn ergo_api::NodeSubmit>>,
            false,
            None,
        );
        let adapter = WalletChainAdapter::new(Arc::new(client) as Arc<dyn ChainClient>);

        let tip = WalletChain::committed_tip(&adapter).unwrap();
        assert_eq!(tip.height, 2);
        assert_eq!(tip.header_id, hex::encode(ids[1]));

        let snapshot = WalletChain::snapshot(&adapter).unwrap();
        assert_eq!(snapshot.tip, tip);
        assert_eq!(snapshot.snapshot_id, hex::encode(ids[1]));
        assert_eq!(snapshot.headers.len(), 2);
        assert_eq!(snapshot.headers[0].parent_id, hex::encode(ids[0]));

        let blocks = WalletChain::blocks_since(
            &adapter,
            wire::BlocksSinceRequest {
                height: 0,
                id: wire::GENESIS_CURSOR_ID.to_string(),
                limit: 2,
            },
        )
        .unwrap();
        match blocks {
            wire::BlocksSinceResponse::Forward(response) => {
                assert_eq!(response.tip, tip);
                assert_eq!(response.blocks.len(), 2);
                assert_eq!(response.blocks[0].block_id, hex::encode(ids[0]));
                assert_eq!(response.blocks[1].block_id, hex::encode(ids[1]));
            }
            other => panic!("unexpected response: {other:?}"),
        }

        let box_response = WalletChain::box_lookup(
            &adapter,
            wire::BoxLookupRequest {
                box_id: hex::encode(box_id),
                tip: Some(tip.header_id.clone()),
                height: Some(tip.height),
            },
        )
        .unwrap();
        assert_eq!(box_response.tip, tip);
        assert_eq!(box_response.box_info.box_id, hex::encode(box_id));
        assert_eq!(box_response.box_info.value, 1_000_000);
        assert!(matches!(
            WalletChain::box_lookup(
                &adapter,
                wire::BoxLookupRequest {
                    box_id: "ee".repeat(32),
                    tip: Some(tip.header_id),
                    height: Some(tip.height),
                },
            ),
            Err(WalletChainError::BoxNotFound)
        ));
    }
}
