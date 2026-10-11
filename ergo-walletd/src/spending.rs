//! Owned remote signing inputs shared by chain, mempool and admission adapters.
//! The host refreshes once while holding its writer gate. A failed refresh
//! clears the prior view; engine calls never fall back to stale or empty data.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ergo_primitives::digest::{ADDigest, Digest32};
use ergo_primitives::reader::VlqReader;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::ergo_box::ErgoBox;
use ergo_ser::header::Header;
use ergo_ser::transaction::{
    read_transaction, transaction_id, write_transaction_preserving_extension_encodings,
};
use ergo_validation::{
    ActiveProtocolParameters, EmissionRuleInputs, ErgoValidationSettings,
    ErgoValidationSettingsUpdate, ProtocolParams, ReemissionRuleInputs,
};
use ergo_wallet::tx_context::{BlockchainParameters, BlockchainStateContext};
use ergo_wallet_protocol::{chain as wire, mining, WalletAdminError};
use ergo_wallet_service::engine::mempool::MempoolBoxSnapshot;
use ergo_wallet_service::engine::{
    ChainAccessError, MempoolOverlay, SigningView, TxSubmitError, TxSubmitter, WalletChainAccess,
    WalletEngineConfig,
};
use ergo_wallet_service::wallet::scan::{OwnedBlockOutput, RescanBlock, RescanReadError, RescanTx};
use ergo_wallet_service::{ChainClient, ChainClientError, CommittedTip, WalletStore};
use parking_lot::RwLock;
use serde::Deserialize;

use crate::chain_http::{
    canonical_box, decode_hex, decode_id, neutral_tip, rpc_status_error, HttpChainClient,
};
use crate::config::Network;
use crate::host::SpendingPreparation;
use crate::tip::PROBE_TIMEOUT;

const RPC_TIMEOUT: Duration = Duration::from_secs(10);

struct OwnedContext {
    tip: CommittedTip,
    headers: Vec<Header>,
    header_ids: Vec<[u8; 32]>,
    state: BlockchainStateContext,
    active: ActiveProtocolParameters,
    signing: BlockchainParameters,
    protocol: ProtocolParams,
    reemission: Option<ReemissionRuleInputs>,
    outputs: Arc<HashMap<Digest32, ErgoBox>>,
    inputs: HashMap<Digest32, Digest32>,
    private_inputs: BTreeSet<[u8; 32]>,
    private_configured: bool,
    private_queue_available: bool,
    pruned: bool,
    min_relay_fee: u64,
    max_tx_size: usize,
}

#[derive(Clone)]
pub struct RemoteSpendingAccess {
    store: Arc<dyn WalletStore>,
    chain: Arc<HttpChainClient>,
    network: Network,
    context: Arc<RwLock<Option<Arc<OwnedContext>>>>,
}

impl RemoteSpendingAccess {
    pub fn new(store: Arc<dyn WalletStore>, chain: Arc<HttpChainClient>, network: Network) -> Self {
        Self {
            store,
            chain,
            network,
            context: Arc::new(RwLock::new(None)),
        }
    }

    fn context(&self) -> Result<Arc<OwnedContext>, ChainAccessError> {
        self.context
            .read()
            .clone()
            .ok_or(ChainAccessError::Unsupported)
    }

    fn node_tip(&self) -> Result<CommittedTip, ChainAccessError> {
        self.chain
            .committed_tip_within(PROBE_TIMEOUT)
            .map_err(chain_error)
    }

    async fn private_rpc<T: serde::de::DeserializeOwned + Send + 'static>(
        &self,
        method: reqwest::Method,
        path: String,
        body: Option<serde_json::Value>,
    ) -> Result<T, TxSubmitError> {
        if !self
            .context
            .read()
            .as_ref()
            .is_some_and(|context| context.private_queue_available)
        {
            return Err(submit_error("private_mining_unavailable"));
        }
        let chain = self.chain.clone();
        tokio::task::spawn_blocking(move || {
            let (status, bytes) = chain
                .rpc(method, &path, body, RPC_TIMEOUT)
                .map_err(submit_chain_error)?;
            if !status.is_success() {
                if status.is_server_error() {
                    return Err(submit_chain_error(rpc_status_error(status)));
                }
                #[derive(Deserialize)]
                struct Failure {
                    error: FailureInner,
                }
                #[derive(Deserialize)]
                struct FailureInner {
                    reason: String,
                }
                if let Ok(failure) = serde_json::from_slice::<Failure>(&bytes) {
                    if !failure.error.reason.is_empty()
                        && failure.error.reason.len() <= 64
                        && failure
                            .error
                            .reason
                            .bytes()
                            .all(|b| b.is_ascii_lowercase() || b == b'_')
                    {
                        return Err(submit_error(&failure.error.reason));
                    }
                }
                return Err(submit_chain_error(rpc_status_error(status)));
            }
            serde_json::from_slice(&bytes).map_err(|_| submit_error("invalid_node_response"))
        })
        .await
        .map_err(|_| submit_error("node_rpc_worker_failed"))?
    }
}

impl SpendingPreparation for RemoteSpendingAccess {
    fn refresh(&self) -> Result<WalletEngineConfig, WalletAdminError> {
        *self.context.write() = None;
        let wire = self.chain.spending_context().map_err(preparation_error)?;
        let context = Arc::new(
            decode_context(wire, self.network)
                .map_err(|error| WalletAdminError::Internal(error.to_string()))?,
        );
        let config = WalletEngineConfig {
            network: self.network.prefix(),
            expose_private_keys: false,
            reemission: context.reemission.clone(),
            min_relay_fee_nano_erg: context.min_relay_fee,
            max_tx_size_bytes: context.max_tx_size,
        };
        *self.context.write() = Some(context);
        Ok(config)
    }
    fn finish(&self) {
        *self.context.write() = None;
    }
}

fn preparation_error(error: ChainClientError) -> WalletAdminError {
    match error {
        ChainClientError::Conflict | ChainClientError::StaleTip { .. } => {
            WalletAdminError::StaleChainTip(
                "the committed node tip changed; retry the operation".into(),
            )
        }
        ChainClientError::ShuttingDown(_) => WalletAdminError::ShuttingDown,
        ChainClientError::Unauthorized => {
            WalletAdminError::NodeUnavailable("node operator authentication rejected".into())
        }
        ChainClientError::Timeout(_) => {
            WalletAdminError::NodeUnavailable("node signing context timed out".into())
        }
        ChainClientError::Unsupported | ChainClientError::UnsupportedHistory { .. } => {
            WalletAdminError::NodeUnavailable("node spending capability unavailable".into())
        }
        ChainClientError::Unavailable(_)
        | ChainClientError::Overloaded(_)
        | ChainClientError::Transport(_)
        | ChainClientError::HistoryPruned { .. } => {
            WalletAdminError::NodeUnavailable("node signing context unavailable".into())
        }
        ChainClientError::Protocol(_) | ChainClientError::Failure(_) => {
            WalletAdminError::Internal("invalid node spending context".into())
        }
    }
}

impl WalletChainAccess for RemoteSpendingAccess {
    fn wallet_scan_height(&self) -> Result<u32, ChainAccessError> {
        self.store
            .read()
            .and_then(|read| read.scan_cursor())
            .map(|cursor| cursor.map_or(0, |cursor| cursor.height))
            .map_err(|error| ChainAccessError::State(error.to_string()))
    }
    fn tip_height(&self) -> Result<u32, ChainAccessError> {
        let height = self
            .context
            .read()
            .as_ref()
            .map(|context| context.tip.height);
        match height {
            Some(height) => Ok(height),
            None => self.node_tip().map(|tip| tip.height),
        }
    }
    fn is_pruned(&self) -> bool {
        self.context.read().as_ref().is_none_or(|ctx| ctx.pruned)
    }
    fn reserved_wallet_inputs(&self) -> Result<BTreeSet<[u8; 32]>, WalletAdminError> {
        self.context()
            .map(|ctx| ctx.private_inputs.clone())
            .map_err(|e| WalletAdminError::Internal(e.to_string()))
    }
    fn reemission_rules_owned(&self) -> Option<ReemissionRuleInputs> {
        self.context
            .read()
            .as_ref()
            .and_then(|ctx| ctx.reemission.clone())
    }
    fn read_block_at_supported(&self) -> Result<bool, RescanReadError> {
        let tip = self.node_tip().map_err(|e| RescanReadError::Corrupt {
            height: 0,
            reason: e.to_string(),
        })?;
        if tip.height == 0 {
            return Ok(true);
        }
        self.chain
            .block_at(1, tip)
            .map(|_| true)
            .map_err(|source| RescanReadError::Chain { height: 1, source })
    }
    fn read_block_at(&self, height: u32) -> Result<Option<RescanBlock>, RescanReadError> {
        let tip = self.node_tip().map_err(|e| RescanReadError::Corrupt {
            height,
            reason: e.to_string(),
        })?;
        let block = self
            .chain
            .block_at(height, tip)
            .map_err(|source| RescanReadError::Chain { height, source })?;
        let txs = block
            .transactions
            .into_iter()
            .map(|tx| {
                let outputs = tx
                    .outputs
                    .into_iter()
                    .map(|output| {
                        let parsed = canonical_box(&output.bytes, "rescan output")
                            .map_err(|source| RescanReadError::Chain { height, source })?;
                        Ok(OwnedBlockOutput {
                            box_id: output.box_id,
                            output_index: output.index,
                            ergo_tree_bytes: parsed.candidate.ergo_tree_bytes().to_vec(),
                            value: parsed.candidate.value,
                            assets: parsed
                                .candidate
                                .tokens
                                .iter()
                                .map(|token| (*token.token_id.as_bytes(), token.amount))
                                .collect(),
                            miner_reward_pubkey: ergo_wallet::proving::extract_miner_reward_pubkey(
                                parsed.candidate.ergo_tree_bytes(),
                            ),
                            box_bytes: output.bytes,
                        })
                    })
                    .collect::<Result<Vec<_>, RescanReadError>>()?;
                Ok(RescanTx {
                    tx_id: tx.tx_id,
                    inputs: tx.inputs.into_iter().map(|input| input.box_id).collect(),
                    outputs,
                })
            })
            .collect::<Result<Vec<_>, RescanReadError>>()?;
        Ok(Some(RescanBlock {
            block_id: block.block_id,
            txs,
        }))
    }
    fn signing_view(&self) -> Result<Box<dyn SigningView>, ChainAccessError> {
        Ok(Box::new(RemoteSigningView {
            context: self.context()?,
            chain: self.chain.clone(),
        }))
    }
    fn committed_tip(&self) -> Result<Option<CommittedTip>, ChainAccessError> {
        self.node_tip().map(Some)
    }
    fn build_signing_context(&self) -> Result<BlockchainStateContext, ChainAccessError> {
        Ok(self.context()?.state.clone())
    }
    fn build_signing_params(&self) -> Result<BlockchainParameters, ChainAccessError> {
        Ok(self.context()?.signing.clone())
    }
    fn build_protocol_params(&self) -> Result<ProtocolParams, ChainAccessError> {
        Ok(self.context()?.protocol.clone())
    }
    fn lookup_utxo(&self, id: &[u8; 32]) -> Result<Option<ErgoBox>, ChainAccessError> {
        RemoteSigningView {
            context: self.context()?,
            chain: self.chain.clone(),
        }
        .lookup_utxo(id)
    }
}

struct RemoteSigningView {
    context: Arc<OwnedContext>,
    chain: Arc<HttpChainClient>,
}
impl SigningView for RemoteSigningView {
    fn tip(&self) -> CommittedTip {
        self.context.tip.clone()
    }
    fn headers(&self) -> &[Header] {
        &self.context.headers
    }
    fn header_ids(&self) -> &[[u8; 32]] {
        &self.context.header_ids
    }
    fn state_context(&self) -> &BlockchainStateContext {
        &self.context.state
    }
    fn active_params(&self) -> &ActiveProtocolParameters {
        &self.context.active
    }
    fn signing_params(&self) -> &BlockchainParameters {
        &self.context.signing
    }
    fn protocol_params(&self) -> &ProtocolParams {
        &self.context.protocol
    }
    fn reemission_rules(&self) -> Option<&ReemissionRuleInputs> {
        self.context.reemission.as_ref()
    }
    fn lookup_utxo(&self, id: &[u8; 32]) -> Result<Option<ErgoBox>, ChainAccessError> {
        let response = self
            .chain
            .lookup_utxo(*id, self.context.tip.clone())
            .map_err(chain_error)?;
        response
            .utxo
            .map(|utxo| canonical_box(&utxo.bytes, "signing input").map_err(chain_error))
            .transpose()
    }
}

impl MempoolOverlay for RemoteSpendingAccess {
    fn is_spent_by_pool(&self, id: &Digest32) -> bool {
        self.context
            .read()
            .as_ref()
            .is_some_and(|ctx| ctx.inputs.contains_key(id))
    }
    fn pool_spending_tx(&self, id: &Digest32) -> Option<Digest32> {
        self.context
            .read()
            .as_ref()
            .and_then(|ctx| ctx.inputs.get(id).copied())
    }
    fn pool_outputs(&self) -> Arc<HashMap<Digest32, ErgoBox>> {
        self.context
            .read()
            .as_ref()
            .map(|ctx| ctx.outputs.clone())
            .unwrap_or_default()
    }
    fn box_snapshot(&self, _ids: &[Digest32]) -> MempoolBoxSnapshot {
        match self.context.read().as_ref() {
            Some(ctx) => MempoolBoxSnapshot {
                outputs: ctx.outputs.clone(),
                spent_box_ids: ctx.inputs.keys().copied().collect(),
            },
            None => MempoolBoxSnapshot {
                outputs: Arc::default(),
                spent_box_ids: HashSet::new(),
            },
        }
    }
}

#[async_trait]
impl TxSubmitter for RemoteSpendingAccess {
    async fn submit_transaction(&self, bytes: Vec<u8>) -> Result<String, TxSubmitError> {
        let context = self
            .context()
            .map_err(|_| submit_error("signing_context_unavailable"))?;
        let chain = self.chain.clone();
        let expected = transaction_id_from_bytes(&bytes).map_err(submit_chain_error)?;
        let response = tokio::task::spawn_blocking(move || {
            chain.admit_transaction(wire::SubmitRequest {
                transaction: hex::encode(bytes),
                snapshot_id: Some(hex::encode(context.tip.header_id)),
            })
        })
        .await
        .map_err(|_| submit_error("node_rpc_worker_failed"))?
        .map_err(submit_chain_error)?;
        match response {
            wire::AdmissionResponse::Accepted { tx_id }
            | wire::AdmissionResponse::Duplicate { tx_id } => {
                if tx_id != expected {
                    return Err(submit_error("invalid_node_transaction_id"));
                }
                Ok(tx_id)
            }
            wire::AdmissionResponse::Rejected { reason, detail } => {
                Err(TxSubmitError { reason, detail })
            }
        }
    }
    fn private_mining_configured(&self) -> bool {
        self.context
            .read()
            .as_ref()
            .is_some_and(|ctx| ctx.private_configured)
    }
    async fn submit_private_transaction(
        &self,
        bytes: Vec<u8>,
        options: mining::PrivateTransactionOptions,
    ) -> Result<String, TxSubmitError> {
        if !self.private_mining_configured() {
            return Err(submit_error("private_mining_unavailable"));
        }
        let expected = transaction_id_from_bytes(&bytes).map_err(submit_chain_error)?;
        let entry: mining::PrivateTransactionEntry = self.private_rpc(reqwest::Method::POST,
            "api/v1/mining/private-transactions".into(), Some(serde_json::json!({"signed_transaction_hex": hex::encode(bytes), "options": options}))).await?;
        if entry.tx_id != expected {
            return Err(submit_error("invalid_node_transaction_id"));
        }
        Ok(entry.tx_id)
    }
    async fn private_transactions(
        &self,
    ) -> Result<Vec<mining::PrivateTransactionEntry>, TxSubmitError> {
        #[derive(Deserialize)]
        struct Entries {
            items: Vec<mining::PrivateTransactionEntry>,
        }
        let entries: Entries = self
            .private_rpc(
                reqwest::Method::GET,
                "api/v1/mining/private-transactions".into(),
                None,
            )
            .await?;
        for entry in &entries.items {
            decode_id(&entry.tx_id, "private transaction id").map_err(submit_chain_error)?;
        }
        Ok(entries.items)
    }
    async fn cancel_private_transaction(&self, id: String) -> Result<(), TxSubmitError> {
        decode_id(&id, "private transaction id").map_err(submit_chain_error)?;
        let entry: mining::PrivateTransactionEntry = self
            .private_rpc(
                reqwest::Method::POST,
                format!("api/v1/mining/private-transactions/{id}/cancel"),
                None,
            )
            .await?;
        if entry.tx_id != id {
            return Err(submit_error("invalid_node_transaction_id"));
        }
        Ok(())
    }
}

fn chain_error(error: ChainClientError) -> ChainAccessError {
    match error {
        ChainClientError::StaleTip { expected, actual } => {
            ChainAccessError::StaleTip { expected, actual }
        }
        ChainClientError::Unsupported => ChainAccessError::Unsupported,
        error => ChainAccessError::State(error.to_string()),
    }
}
fn submit_error(reason: &str) -> TxSubmitError {
    TxSubmitError {
        reason: reason.into(),
        detail: None,
    }
}
fn submit_chain_error(error: ChainClientError) -> TxSubmitError {
    let reason = match error {
        ChainClientError::Unauthorized => "unauthorized",
        ChainClientError::Conflict | ChainClientError::StaleTip { .. } => "stale_chain_tip",
        ChainClientError::Timeout(_) => "timeout",
        ChainClientError::Overloaded(_) => "overloaded",
        ChainClientError::ShuttingDown(_) => "shutting_down",
        _ => "node_rpc_failed",
    };
    submit_error(reason)
}
fn protocol_error(message: &str) -> ChainClientError {
    ChainClientError::Protocol(message.into())
}
fn transaction_id_from_bytes(bytes: &[u8]) -> Result<String, ChainClientError> {
    let mut reader = VlqReader::new(bytes);
    let tx = read_transaction(&mut reader)
        .map_err(|_| protocol_error("invalid canonical transaction"))?;
    if !reader.is_empty() {
        return Err(protocol_error("transaction has trailing bytes"));
    }
    let mut writer = VlqWriter::new();
    write_transaction_preserving_extension_encodings(&mut writer, &tx)
        .map_err(|_| protocol_error("transaction cannot be canonicalized"))?;
    if writer.result() != bytes {
        return Err(protocol_error("transaction is noncanonical"));
    }
    transaction_id(&tx)
        .map(|id| hex::encode(id.as_bytes()))
        .map_err(|_| protocol_error("transaction id failed"))
}

fn decode_update(hex: &str) -> Result<ErgoValidationSettingsUpdate, ChainClientError> {
    let update =
        ErgoValidationSettingsUpdate::deserialize_exact(&decode_hex(hex, "validation settings")?)
            .map_err(|_| protocol_error("invalid validation settings codec"))?;
    update
        .validate_sigma_status_ids()
        .map_err(|_| protocol_error("unsupported validation settings"))?;
    Ok(update)
}

fn decode_context(
    wire: wire::SpendingContext,
    network: Network,
) -> Result<OwnedContext, ChainClientError> {
    if wire.version != wire::SPENDING_CONTEXT_VERSION || wire.network != network.as_str() {
        return Err(protocol_error(
            "spending context version or network mismatch",
        ));
    }
    let tip = neutral_tip(wire.tip)?;
    if wire.headers.is_empty()
        || wire.headers.len() > 10
        || wire.headers.len() < tip.height.min(10) as usize
        || wire.mempool_sequence == 0
        || wire.max_tx_size_bytes == 0
    {
        return Err(protocol_error("spending context is incomplete"));
    }
    let mut headers = Vec::new();
    let mut header_ids = Vec::new();
    for encoded in wire.headers {
        let header = ergo_wallet_service::ChainHeader {
            height: encoded.height,
            header_id: decode_id(&encoded.header_id, "header id")?,
            parent_id: decode_id(&encoded.parent_id, "parent id")?,
            timestamp_unix_ms: encoded.timestamp_unix_ms,
            header_bytes: decode_hex(&encoded.header_bytes, "header bytes")?,
        };
        let decoded = header
            .authenticate()
            .map_err(|_| protocol_error("spending header authentication failed"))?;
        header_ids.push(header.header_id);
        headers.push(decoded);
    }
    if header_ids[0] != tip.header_id || headers[0].height != tip.height {
        return Err(protocol_error("spending header window has wrong tip"));
    }
    for i in 1..headers.len() {
        if headers[i - 1].parent_id.as_bytes() != &header_ids[i]
            || headers[i].height.checked_add(1) != Some(headers[i - 1].height)
        {
            return Err(protocol_error("spending header window is discontinuous"));
        }
    }
    let pre = wire.pre_header;
    let miner: [u8; 33] = decode_hex(&pre.miner_pubkey, "preheader miner")?
        .try_into()
        .map_err(|_| protocol_error("invalid preheader miner length"))?;
    if decode_id(&pre.parent_id, "preheader parent")? != tip.header_id
        || tip.height.checked_add(1) != Some(pre.height)
        || pre.version != headers[0].version
        || headers[0].timestamp.checked_add(1) != Some(pre.timestamp)
        || pre.n_bits != headers[0].n_bits
        || pre.votes != [0; 3]
        || miner != *headers[0].solution.pk().as_bytes()
    {
        return Err(protocol_error(
            "synthetic preheader does not match committed tip",
        ));
    }
    let digest: [u8; 33] = decode_hex(&wire.previous_state_digest, "state digest")?
        .try_into()
        .map_err(|_| protocol_error("invalid state digest length"))?;
    if digest != *headers[0].state_root.as_bytes() {
        return Err(protocol_error("state digest does not match tip header"));
    }
    let p = wire.parameters;
    if p.missing_core_parameters & !0x01ff != 0 {
        return Err(protocol_error(
            "active parameter missing-field mask is invalid",
        ));
    }
    let active = ActiveProtocolParameters {
        missing_core_parameters: p.missing_core_parameters,
        epoch_start_height: p.epoch_start_height,
        block_version: p.block_version,
        storage_fee_factor: p.storage_fee_factor,
        min_value_per_byte: p.min_value_per_byte,
        max_block_size: p.max_block_size,
        max_block_cost: p.max_block_cost,
        token_access_cost: p.token_access_cost,
        input_cost: p.input_cost,
        data_input_cost: p.data_input_cost,
        output_cost: p.output_cost,
        subblocks_per_block: p.subblocks_per_block,
        extra: p.extra,
        proposed_update: decode_update(&p.proposed_update)?,
        activated_update: decode_update(&p.activated_update)?,
        announced_settings: p
            .announced_settings
            .as_deref()
            .map(decode_update)
            .transpose()?,
    };
    active
        .validate()
        .map_err(|_| protocol_error("invalid active spending parameters"))?;
    if active.epoch_start_height > tip.height {
        return Err(protocol_error("active parameters begin above tip"));
    }
    let settings = ErgoValidationSettings {
        update_from_initial: decode_update(&wire.validation_settings)?,
    };
    let protocol = ProtocolParams::from_active_with_settings(&active, &settings);
    let signing = BlockchainParameters {
        max_block_cost: active.max_block_cost as u64,
        input_cost: active.input_cost as u64,
        data_input_cost: active.data_input_cost as u64,
        output_cost: active.output_cost as u64,
        token_access_cost: active.token_access_cost as u64,
        interpreter_init_cost: ergo_validation::INTERPRETER_INIT_COST,
        block_version: active.block_version,
    };
    let reemission = wire
        .reemission
        .map(|r| -> Result<ReemissionRuleInputs, ChainClientError> {
            Ok(ReemissionRuleInputs {
                check_rules: r.check_rules,
                activation_height: r.activation_height,
                reemission_token_id: decode_id(&r.reemission_token_id, "reemission token")?,
                pay_to_reemission_tree: decode_hex(&r.pay_to_reemission_tree, "reemission tree")?,
                emission: r
                    .emission
                    .map(|e| -> Result<EmissionRuleInputs, ChainClientError> {
                        let m = e.monetary;
                        if m.epoch_length == 0 {
                            return Err(protocol_error("emission epoch length is zero"));
                        }
                        Ok(EmissionRuleInputs {
                            emission_nft_id: decode_id(&e.emission_nft_id, "emission NFT")?,
                            emission_tree: decode_hex(&e.emission_tree, "emission tree")?,
                            monetary: ergo_chain_spec::MonetaryParams {
                                fixed_rate: m.fixed_rate,
                                fixed_rate_period: m.fixed_rate_period,
                                epoch_length: m.epoch_length,
                                one_epoch_reduction: m.one_epoch_reduction,
                                founders_initial_reward: m.founders_initial_reward,
                                miner_reward_delay: m.miner_reward_delay,
                            },
                        })
                    })
                    .transpose()?,
            })
        })
        .transpose()?;
    let mut outputs = HashMap::new();
    let mut inputs = HashMap::new();
    let mut tx_ids = HashSet::new();
    for encoded in wire.mempool_transactions {
        let bytes = decode_hex(&encoded, "pool transaction")?;
        let mut reader = VlqReader::new(&bytes);
        let tx = read_transaction(&mut reader)
            .map_err(|_| protocol_error("invalid pool transaction"))?;
        if !reader.is_empty() {
            return Err(protocol_error("pool transaction has trailing bytes"));
        }
        let mut writer = VlqWriter::new();
        write_transaction_preserving_extension_encodings(&mut writer, &tx)
            .map_err(|_| protocol_error("pool transaction cannot be canonicalized"))?;
        if writer.result() != bytes {
            return Err(protocol_error("pool transaction is noncanonical"));
        }
        let tx_id =
            transaction_id(&tx).map_err(|_| protocol_error("pool transaction id failed"))?;
        let digest = Digest32::from_bytes(*tx_id.as_bytes());
        if !tx_ids.insert(digest) {
            return Err(protocol_error("duplicate pool transaction"));
        }
        for input in tx.inputs {
            if inputs
                .insert(Digest32::from_bytes(*input.box_id.as_bytes()), digest)
                .is_some()
            {
                return Err(protocol_error("conflicting pool inputs"));
            }
        }
        for (index, candidate) in tx.output_candidates.into_iter().enumerate() {
            let ergo_box = ErgoBox {
                candidate,
                transaction_id: tx_id,
                index: u16::try_from(index)
                    .map_err(|_| protocol_error("pool output index overflow"))?,
            };
            let id = ergo_box
                .box_id()
                .map_err(|_| protocol_error("pool box id failed"))?;
            if outputs
                .insert(Digest32::from_bytes(*id.as_bytes()), ergo_box)
                .is_some()
            {
                return Err(protocol_error("duplicate pool output"));
            }
        }
    }
    let private_inputs = wire
        .private_reserved_inputs
        .iter()
        .map(|id| decode_id(id, "private reservation"))
        .collect::<Result<BTreeSet<_>, _>>()?;
    if private_inputs.len() != wire.private_reserved_inputs.len()
        || (wire.private_queue_revision.is_none()
            && (!private_inputs.is_empty() || wire.private_mining_configured))
    {
        return Err(protocol_error(
            "private queue reservation snapshot is inconsistent",
        ));
    }
    Ok(OwnedContext {
        tip,
        header_ids,
        state: BlockchainStateContext {
            sigma_last_headers: headers.clone(),
            sigma_pre_header: ergo_validation::pre_header::CandidatePreHeader {
                version: pre.version,
                parent_id: decode_id(&pre.parent_id, "preheader parent")?,
                height: pre.height,
                timestamp: pre.timestamp,
                n_bits: pre.n_bits,
                votes: pre.votes,
                miner_pubkey: miner,
            },
            previous_state_digest: ADDigest::from_bytes(digest),
        },
        headers,
        active,
        signing,
        protocol,
        reemission,
        outputs: Arc::new(outputs),
        inputs,
        private_inputs,
        private_configured: wire.private_mining_configured,
        private_queue_available: wire.private_queue_revision.is_some(),
        // A snapshot-bootstrap node can retain no genesis history even while
        // its configured pruning flag is false. Unknown coverage also cannot
        // authorize a full replay; current UTXO/signing data stays usable.
        pruned: wire.pruned || wire.minimum_history_height.is_none_or(|height| height > 1),
        min_relay_fee: wire.min_relay_fee_nano_erg,
        max_tx_size: wire.max_tx_size_bytes as usize,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context_fixture() -> wire::SpendingContext {
        let miner: [u8; 33] =
            hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap()
                .try_into()
                .unwrap();
        let header = Header {
            version: 2,
            parent_id: ergo_primitives::digest::ModifierId::from_bytes([0; 32]),
            ad_proofs_root: Digest32::from_bytes([0; 32]),
            transactions_root: Digest32::from_bytes([0; 32]),
            state_root: ADDigest::from_bytes([0; 33]),
            timestamp: 1_000_001,
            extension_root: Digest32::from_bytes([0; 32]),
            n_bits: 16842752,
            height: 1,
            votes: [0; 3],
            unparsed_bytes: Vec::new(),
            solution: ergo_ser::autolykos::AutolykosSolution::V2 {
                pk: ergo_primitives::group_element::GroupElement::from(miner),
                nonce: [0; 8],
            },
        };
        let (bytes, id) = ergo_ser::header::serialize_header(&header).unwrap();
        let p = ergo_validation::scala_launch();
        wire::SpendingContext {
            version: wire::SPENDING_CONTEXT_VERSION,
            network: "mainnet".into(),
            tip: wire::ChainTip {
                height: 1,
                header_id: hex::encode(id.as_bytes()),
            },
            headers: vec![wire::ChainHeader {
                height: 1,
                header_id: hex::encode(id.as_bytes()),
                parent_id: "00".repeat(32),
                timestamp_unix_ms: header.timestamp,
                header_bytes: hex::encode(bytes),
            }],
            pre_header: wire::SpendingPreHeader {
                version: header.version,
                parent_id: hex::encode(id.as_bytes()),
                height: 2,
                timestamp: header.timestamp + 1,
                n_bits: header.n_bits,
                votes: [0; 3],
                miner_pubkey: hex::encode(miner),
            },
            pre_header_source: wire::SpendingPreHeaderSource::SyntheticCommittedTip,
            previous_state_digest: hex::encode(header.state_root.as_bytes()),
            parameters: wire::SpendingParameters {
                missing_core_parameters: p.missing_core_parameters,
                epoch_start_height: p.epoch_start_height,
                block_version: p.block_version,
                storage_fee_factor: p.storage_fee_factor,
                min_value_per_byte: p.min_value_per_byte,
                max_block_size: p.max_block_size,
                max_block_cost: p.max_block_cost,
                token_access_cost: p.token_access_cost,
                input_cost: p.input_cost,
                data_input_cost: p.data_input_cost,
                output_cost: p.output_cost,
                subblocks_per_block: p.subblocks_per_block,
                extra: p.extra,
                proposed_update: hex::encode(p.proposed_update.serialize()),
                activated_update: hex::encode(p.activated_update.serialize()),
                announced_settings: None,
            },
            validation_settings: hex::encode(ErgoValidationSettingsUpdate::empty().serialize()),
            reemission: None,
            pruned: false,
            minimum_history_height: Some(0),
            min_relay_fee_nano_erg: 1_000_000,
            max_tx_size_bytes: 90_000,
            mempool_sequence: 1,
            mempool_transactions: Vec::new(),
            private_mining_configured: false,
            private_queue_revision: None,
            private_reserved_inputs: Vec::new(),
        }
    }

    #[test]
    fn pruning_requires_known_genesis_history_even_without_configured_pruning() {
        let fixture = context_fixture();
        let baseline = decode_context(fixture.clone(), Network::Mainnet).unwrap();
        for (configured, minimum, expected) in [
            (false, None, true),
            (false, Some(0), false),
            (false, Some(1), false),
            (false, Some(2), true),
            (true, Some(0), true),
            (true, Some(1), true),
        ] {
            let mut wire = fixture.clone();
            wire.pruned = configured;
            wire.minimum_history_height = minimum;
            let context = decode_context(wire, Network::Mainnet).unwrap();
            assert_eq!(
                context.pruned, expected,
                "configured={configured}, minimum={minimum:?}"
            );
            // Restricted replay coverage does not erase the authenticated
            // current state, adopted parameters or pinned signing context.
            assert_eq!(context.tip, baseline.tip);
            assert_eq!(
                context.state.previous_state_digest,
                baseline.state.previous_state_digest
            );
            assert_eq!(
                context.state.sigma_pre_header.height,
                baseline.state.sigma_pre_header.height
            );
            assert_eq!(context.header_ids, baseline.header_ids);
            assert_eq!(context.active, baseline.active);
        }
    }
}
