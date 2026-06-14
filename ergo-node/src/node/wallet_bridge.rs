//! Production WalletAdmin bridge. Single-writer pattern: the action
//! loop in ergo-node owns the wallet storage + state behind a RwLock.
//! The axum API task sends commands via a channel; the loop processes
//! them serially and sends the responses back via the per-command
//! oneshot channel.

use std::collections::BTreeMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::RwLock;
use tokio::sync::{mpsc, oneshot};

use ergo_api::wallet::scan::{ScanBoxEntry, ScanBoxFilter, ScanDto, ScanRequestDto};
use ergo_api::wallet::sending::PaymentRequestDto;
use ergo_api::wallet::sending::{
    BoxesCollectRequest, BoxesCollectResponse, TransactionGenerateRequest,
    TransactionGenerateResponse, TransactionGenerateUnsignedRequest,
    TransactionGenerateUnsignedResponse, TransactionSendRequest, TransactionSignRequest,
    TransactionSignResponse,
};
use ergo_api::wallet::types::{
    Page, WalletAddressList, WalletBalances, WalletBoxEntry, WalletBoxesPage, WalletStatus,
    WalletTransactionEntry, WalletTransactionsPage,
};
use ergo_api::wallet::{WalletAdmin, WalletAdminError};
use ergo_wallet::state::WalletState;
use ergo_wallet::storage::SecretStorage;

/// Abstracts the chain submit path so the wallet writer can submit a
/// signed transaction without depending on the API crate's concrete
/// `SubmitBridge`. Production impl wraps `NodeSubmit`; tests can
/// inject a stub.
#[async_trait]
pub trait TxSubmitter: Send + Sync {
    async fn submit_transaction(&self, tx_bytes: Vec<u8>) -> Result<String, WalletAdminError>;
}

/// Production `TxSubmitter` backed by the node's `NodeSubmit` bridge.
pub struct NodeSubmitAdapter {
    inner: Arc<dyn ergo_api::traits::NodeSubmit>,
}

impl NodeSubmitAdapter {
    pub fn new(inner: Arc<dyn ergo_api::traits::NodeSubmit>) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl TxSubmitter for NodeSubmitAdapter {
    async fn submit_transaction(&self, tx_bytes: Vec<u8>) -> Result<String, WalletAdminError> {
        use ergo_api::types::SubmitMode;
        self.inner
            .submit_transaction(tx_bytes, SubmitMode::Broadcast)
            .await
            .map_err(|e| WalletAdminError::Internal(format!("submit: {}", e.reason)))
    }
}

/// Command sent from the API task to the wallet writer task.
pub enum WalletCommand {
    Status {
        reply: oneshot::Sender<Result<WalletStatus, WalletAdminError>>,
    },
    Init {
        pass: String,
        mnemonic_pass: String,
        strength: u8,
        reply: oneshot::Sender<Result<String, WalletAdminError>>,
    },
    Restore {
        mnemonic: String,
        mnemonic_pass: String,
        pass: String,
        use_pre_1627: bool,
        reply: oneshot::Sender<Result<(), WalletAdminError>>,
    },
    Unlock {
        pass: String,
        reply: oneshot::Sender<Result<(), WalletAdminError>>,
    },
    Lock {
        reply: oneshot::Sender<Result<(), WalletAdminError>>,
    },
    Check {
        mnemonic: String,
        mnemonic_pass: String,
        reply: oneshot::Sender<Result<bool, WalletAdminError>>,
    },
    Rescan {
        from_height: u32,
        reply: oneshot::Sender<Result<(), WalletAdminError>>,
    },
    UpdateChangeAddress {
        address: String,
        reply: oneshot::Sender<Result<(), WalletAdminError>>,
    },
    Balances {
        reply: oneshot::Sender<Result<WalletBalances, WalletAdminError>>,
    },
    BalancesWithUnconfirmed {
        reply: oneshot::Sender<Result<WalletBalances, WalletAdminError>>,
    },
    Addresses {
        reply: oneshot::Sender<Result<WalletAddressList, WalletAdminError>>,
    },
    Boxes {
        page: Page,
        reply: oneshot::Sender<Result<WalletBoxesPage, WalletAdminError>>,
    },
    BoxesUnspent {
        page: Page,
        reply: oneshot::Sender<Result<WalletBoxesPage, WalletAdminError>>,
    },
    Transactions {
        page: Page,
        reply: oneshot::Sender<Result<WalletTransactionsPage, WalletAdminError>>,
    },
    TransactionById {
        tx_id_hex: String,
        reply: oneshot::Sender<Result<Option<WalletTransactionEntry>, WalletAdminError>>,
    },
    TransactionsByScanId {
        scan_id: u32,
        page: Page,
        reply: oneshot::Sender<Result<WalletTransactionsPage, WalletAdminError>>,
    },

    // --- send commands ---
    PaymentSend {
        requests: Vec<PaymentRequestDto>,
        reply: oneshot::Sender<Result<String, WalletAdminError>>,
    },
    TransactionGenerate {
        request: TransactionGenerateRequest,
        reply: oneshot::Sender<Result<TransactionGenerateResponse, WalletAdminError>>,
    },
    TransactionGenerateUnsigned {
        request: TransactionGenerateUnsignedRequest,
        reply: oneshot::Sender<Result<TransactionGenerateUnsignedResponse, WalletAdminError>>,
    },
    TransactionSign {
        request: TransactionSignRequest,
        reply: oneshot::Sender<Result<TransactionSignResponse, WalletAdminError>>,
    },
    TransactionSend {
        request: TransactionSendRequest,
        reply: oneshot::Sender<Result<String, WalletAdminError>>,
    },
    BoxesCollect {
        request: BoxesCollectRequest,
        reply: oneshot::Sender<Result<BoxesCollectResponse, WalletAdminError>>,
    },
    // --- multi-sig commands ---
    GenerateCommitments {
        request: ergo_api::wallet::multi_sig::GenerateCommitmentsRequest,
        reply: oneshot::Sender<
            Result<ergo_api::wallet::multi_sig::GenerateCommitmentsResponse, WalletAdminError>,
        >,
    },
    ExtractHints {
        request: ergo_api::wallet::multi_sig::HintExtractionRequest,
        reply: oneshot::Sender<
            Result<ergo_api::wallet::multi_sig::HintExtractionResponse, WalletAdminError>,
        >,
    },
    // --- advanced HD-key commands ---
    DeriveKey {
        request: ergo_api::wallet::admin_advanced::DeriveKeyRequest,
        reply: oneshot::Sender<
            Result<ergo_api::wallet::admin_advanced::DeriveKeyResponse, WalletAdminError>,
        >,
    },
    DeriveNextKey {
        reply: oneshot::Sender<
            Result<ergo_api::wallet::admin_advanced::DeriveNextKeyResponse, WalletAdminError>,
        >,
    },
    GetPrivateKey {
        request: ergo_api::wallet::admin_advanced::GetPrivateKeyRequest,
        reply: oneshot::Sender<
            Result<ergo_api::wallet::admin_advanced::GetPrivateKeyResponse, WalletAdminError>,
        >,
    },
    // --- scan registry commands ---
    RegisterScan {
        request: ScanRequestDto,
        reply: oneshot::Sender<Result<u16, WalletAdminError>>,
    },
    DeregisterScan {
        scan_id: u16,
        reply: oneshot::Sender<Result<(), WalletAdminError>>,
    },
    ListScans {
        reply: oneshot::Sender<Result<Vec<ScanDto>, WalletAdminError>>,
    },
    ScanUnspentBoxes {
        scan_id: u16,
        filter: ScanBoxFilter,
        reply: oneshot::Sender<Result<Vec<ScanBoxEntry>, WalletAdminError>>,
    },
    ScanSpentBoxes {
        scan_id: u16,
        filter: ScanBoxFilter,
        reply: oneshot::Sender<Result<Vec<ScanBoxEntry>, WalletAdminError>>,
    },
    ScanStopTracking {
        scan_id: u16,
        box_id: String,
        reply: oneshot::Sender<Result<(), WalletAdminError>>,
    },
    ScanAddBox {
        scan_ids: Vec<u16>,
        box_json: serde_json::Value,
        reply: oneshot::Sender<Result<String, WalletAdminError>>,
    },
    ScanP2sRule {
        p2s: String,
        reply: oneshot::Sender<Result<u16, WalletAdminError>>,
    },
}

/// `WalletAdmin` impl backed by a command channel. Constructed by
/// `Node::run` and handed to `ergo-api`'s router builder.
pub struct NodeWalletAdmin {
    tx: mpsc::Sender<WalletCommand>,
}

impl NodeWalletAdmin {
    pub fn new(tx: mpsc::Sender<WalletCommand>) -> Self {
        Self { tx }
    }

    async fn send_cmd<R, F>(&self, build: F) -> Result<R, WalletAdminError>
    where
        F: FnOnce(oneshot::Sender<Result<R, WalletAdminError>>) -> WalletCommand,
    {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(build(reply_tx))
            .await
            .map_err(|_| WalletAdminError::Internal("wallet writer task is gone".to_string()))?;
        reply_rx.await.map_err(|_| {
            WalletAdminError::Internal("wallet writer task dropped reply".to_string())
        })?
    }
}

#[async_trait]
impl WalletAdmin for NodeWalletAdmin {
    async fn status(&self) -> Result<WalletStatus, WalletAdminError> {
        self.send_cmd(|reply| WalletCommand::Status { reply }).await
    }

    async fn init(
        &self,
        pass: String,
        mnemonic_pass: String,
        strength_words: u8,
    ) -> Result<String, WalletAdminError> {
        self.send_cmd(move |reply| WalletCommand::Init {
            pass,
            mnemonic_pass,
            strength: strength_words,
            reply,
        })
        .await
    }

    async fn restore(
        &self,
        mnemonic: String,
        mnemonic_pass: String,
        pass: String,
        use_pre_1627: bool,
    ) -> Result<(), WalletAdminError> {
        self.send_cmd(move |reply| WalletCommand::Restore {
            mnemonic,
            mnemonic_pass,
            pass,
            use_pre_1627,
            reply,
        })
        .await
    }

    async fn unlock(&self, pass: String) -> Result<(), WalletAdminError> {
        self.send_cmd(move |reply| WalletCommand::Unlock { pass, reply })
            .await
    }

    async fn lock(&self) -> Result<(), WalletAdminError> {
        self.send_cmd(|reply| WalletCommand::Lock { reply }).await
    }

    async fn check(
        &self,
        mnemonic: String,
        mnemonic_pass: String,
    ) -> Result<bool, WalletAdminError> {
        self.send_cmd(move |reply| WalletCommand::Check {
            mnemonic,
            mnemonic_pass,
            reply,
        })
        .await
    }

    async fn rescan(&self, from_height: u32) -> Result<(), WalletAdminError> {
        self.send_cmd(move |reply| WalletCommand::Rescan { from_height, reply })
            .await
    }

    async fn update_change_address(&self, address: String) -> Result<(), WalletAdminError> {
        self.send_cmd(move |reply| WalletCommand::UpdateChangeAddress { address, reply })
            .await
    }

    async fn balances(&self) -> Result<WalletBalances, WalletAdminError> {
        self.send_cmd(|reply| WalletCommand::Balances { reply })
            .await
    }

    async fn balances_with_unconfirmed(&self) -> Result<WalletBalances, WalletAdminError> {
        self.send_cmd(|reply| WalletCommand::BalancesWithUnconfirmed { reply })
            .await
    }

    async fn addresses(&self) -> Result<WalletAddressList, WalletAdminError> {
        self.send_cmd(|reply| WalletCommand::Addresses { reply })
            .await
    }

    async fn boxes(&self, page: Page) -> Result<WalletBoxesPage, WalletAdminError> {
        self.send_cmd(move |reply| WalletCommand::Boxes { page, reply })
            .await
    }

    async fn boxes_unspent(&self, page: Page) -> Result<WalletBoxesPage, WalletAdminError> {
        self.send_cmd(move |reply| WalletCommand::BoxesUnspent { page, reply })
            .await
    }

    async fn transactions(&self, page: Page) -> Result<WalletTransactionsPage, WalletAdminError> {
        self.send_cmd(move |reply| WalletCommand::Transactions { page, reply })
            .await
    }

    async fn transaction_by_id(
        &self,
        tx_id_hex: String,
    ) -> Result<Option<WalletTransactionEntry>, WalletAdminError> {
        self.send_cmd(move |reply| WalletCommand::TransactionById { tx_id_hex, reply })
            .await
    }

    async fn transactions_by_scan_id(
        &self,
        scan_id: u32,
        page: Page,
    ) -> Result<WalletTransactionsPage, WalletAdminError> {
        self.send_cmd(move |reply| WalletCommand::TransactionsByScanId {
            scan_id,
            page,
            reply,
        })
        .await
    }

    async fn payment_send(
        &self,
        requests: Vec<PaymentRequestDto>,
    ) -> Result<String, WalletAdminError> {
        self.send_cmd(move |reply| WalletCommand::PaymentSend { requests, reply })
            .await
    }

    async fn transaction_generate(
        &self,
        request: TransactionGenerateRequest,
    ) -> Result<TransactionGenerateResponse, WalletAdminError> {
        self.send_cmd(move |reply| WalletCommand::TransactionGenerate { request, reply })
            .await
    }

    async fn transaction_generate_unsigned(
        &self,
        request: TransactionGenerateUnsignedRequest,
    ) -> Result<TransactionGenerateUnsignedResponse, WalletAdminError> {
        self.send_cmd(move |reply| WalletCommand::TransactionGenerateUnsigned { request, reply })
            .await
    }

    async fn transaction_sign(
        &self,
        request: TransactionSignRequest,
    ) -> Result<TransactionSignResponse, WalletAdminError> {
        self.send_cmd(move |reply| WalletCommand::TransactionSign { request, reply })
            .await
    }

    async fn transaction_send(
        &self,
        request: TransactionSendRequest,
    ) -> Result<String, WalletAdminError> {
        self.send_cmd(move |reply| WalletCommand::TransactionSend { request, reply })
            .await
    }

    async fn boxes_collect(
        &self,
        request: BoxesCollectRequest,
    ) -> Result<BoxesCollectResponse, WalletAdminError> {
        self.send_cmd(move |reply| WalletCommand::BoxesCollect { request, reply })
            .await
    }

    async fn generate_commitments(
        &self,
        request: ergo_api::wallet::multi_sig::GenerateCommitmentsRequest,
    ) -> Result<ergo_api::wallet::multi_sig::GenerateCommitmentsResponse, WalletAdminError> {
        self.send_cmd(move |reply| WalletCommand::GenerateCommitments { request, reply })
            .await
    }

    async fn extract_hints(
        &self,
        request: ergo_api::wallet::multi_sig::HintExtractionRequest,
    ) -> Result<ergo_api::wallet::multi_sig::HintExtractionResponse, WalletAdminError> {
        self.send_cmd(move |reply| WalletCommand::ExtractHints { request, reply })
            .await
    }

    async fn derive_key(
        &self,
        request: ergo_api::wallet::admin_advanced::DeriveKeyRequest,
    ) -> Result<ergo_api::wallet::admin_advanced::DeriveKeyResponse, WalletAdminError> {
        self.send_cmd(move |reply| WalletCommand::DeriveKey { request, reply })
            .await
    }

    async fn derive_next_key(
        &self,
    ) -> Result<ergo_api::wallet::admin_advanced::DeriveNextKeyResponse, WalletAdminError> {
        self.send_cmd(|reply| WalletCommand::DeriveNextKey { reply })
            .await
    }

    async fn get_private_key(
        &self,
        request: ergo_api::wallet::admin_advanced::GetPrivateKeyRequest,
    ) -> Result<ergo_api::wallet::admin_advanced::GetPrivateKeyResponse, WalletAdminError> {
        self.send_cmd(move |reply| WalletCommand::GetPrivateKey { request, reply })
            .await
    }

    async fn register_scan(&self, request: ScanRequestDto) -> Result<u16, WalletAdminError> {
        self.send_cmd(move |reply| WalletCommand::RegisterScan { request, reply })
            .await
    }

    async fn deregister_scan(&self, scan_id: u16) -> Result<(), WalletAdminError> {
        self.send_cmd(move |reply| WalletCommand::DeregisterScan { scan_id, reply })
            .await
    }

    async fn list_scans(&self) -> Result<Vec<ScanDto>, WalletAdminError> {
        self.send_cmd(|reply| WalletCommand::ListScans { reply })
            .await
    }

    async fn scan_unspent_boxes(
        &self,
        scan_id: u16,
        filter: ScanBoxFilter,
    ) -> Result<Vec<ScanBoxEntry>, WalletAdminError> {
        self.send_cmd(move |reply| WalletCommand::ScanUnspentBoxes {
            scan_id,
            filter,
            reply,
        })
        .await
    }

    async fn scan_spent_boxes(
        &self,
        scan_id: u16,
        filter: ScanBoxFilter,
    ) -> Result<Vec<ScanBoxEntry>, WalletAdminError> {
        self.send_cmd(move |reply| WalletCommand::ScanSpentBoxes {
            scan_id,
            filter,
            reply,
        })
        .await
    }

    async fn scan_stop_tracking(
        &self,
        scan_id: u16,
        box_id: String,
    ) -> Result<(), WalletAdminError> {
        self.send_cmd(move |reply| WalletCommand::ScanStopTracking {
            scan_id,
            box_id,
            reply,
        })
        .await
    }

    async fn scan_add_box(
        &self,
        scan_ids: Vec<u16>,
        box_json: serde_json::Value,
    ) -> Result<String, WalletAdminError> {
        self.send_cmd(move |reply| WalletCommand::ScanAddBox {
            scan_ids,
            box_json,
            reply,
        })
        .await
    }

    async fn scan_p2s_rule(&self, p2s: String) -> Result<u16, WalletAdminError> {
        self.send_cmd(move |reply| WalletCommand::ScanP2sRule { p2s, reply })
            .await
    }
}

/// Read-only access to the chain state. The writer task uses this
/// for: (a) `walletHeight` in `/wallet/status`, (b) pruning check
/// in `/wallet/restore`, (c) block fetch during `/wallet/rescan`,
/// and (d) signing-context + UTXO lookup for send routes.
pub trait ChainStateAccessor: Send + Sync {
    /// Current `WALLET_SCAN_HEIGHT` — populates `walletHeight`.
    fn wallet_scan_height(&self) -> u32;
    /// Best full-block tip height. Used as the rescan upper bound.
    fn tip_height(&self) -> u32;
    /// True if the node is configured with `blocks_to_keep != -1`.
    /// `/wallet/restore` refuses on pruned nodes per Scala parity.
    fn is_pruned(&self) -> bool;
    /// Fetch the block at `height` for rescan replay. Returns `None`
    /// only if pruned past the requested height.
    fn read_block_at(&self, height: u32) -> Option<ergo_state::wallet::scan::RescanBlock>;
    /// True when `read_block_at` can return real block data. Distinct from
    /// `is_pruned()` (which gates `/wallet/restore`) — this gates
    /// `/wallet/rescan`. When false, rescan is refused before touching any
    /// wallet state, preventing the destructive clear-then-skip sequence.
    /// Default impl probes `read_block_at(0)`; override for efficiency.
    fn read_block_at_supported(&self) -> bool {
        self.read_block_at(0).is_some()
    }

    /// Build the blockchain state context needed for signing: last ≤10
    /// applied headers + candidate pre-header + previous state digest.
    /// Returns `Err` if the chain tip is below 10 blocks (still syncing).
    fn build_signing_context(
        &self,
    ) -> Result<ergo_wallet::tx_context::BlockchainStateContext, WalletAdminError> {
        Err(WalletAdminError::Internal(
            "build_signing_context not implemented for this accessor".into(),
        ))
    }

    /// Build per-block cost parameters from the active protocol parameters
    /// at the tip.
    fn build_signing_params(
        &self,
    ) -> Result<ergo_wallet::tx_context::BlockchainParameters, WalletAdminError> {
        Err(WalletAdminError::Internal(
            "build_signing_params not implemented for this accessor".into(),
        ))
    }

    /// Structural protocol parameters at the tip (min-value-per-byte,
    /// box/collection caps) for pre-submit structural validation. Mirrors
    /// the consensus validator's `ProtocolParams`; the wallet runs
    /// `ergo_validation::validate_structural` against these so it never
    /// submits a tx the node would reject (e.g. a dust output).
    fn build_protocol_params(&self) -> Result<ergo_validation::ProtocolParams, WalletAdminError> {
        Err(WalletAdminError::Internal(
            "build_protocol_params not implemented for this accessor".into(),
        ))
    }

    /// Look up a full `ErgoBox` from the UTXO set by its 32-byte box ID.
    /// Returns `None` if the box is not present (spent or unknown).
    fn lookup_utxo(&self, box_id: &[u8; 32]) -> Option<ergo_ser::ergo_box::ErgoBox> {
        let _ = box_id;
        None
    }
}

/// Production `ChainStateAccessor` backed by the shared redb `Database`
/// and a snapshot of the tip height + pruning flag captured at boot.
///
/// The wallet writer task reads these values for:
/// - `wallet_scan_height`: current `WALLET_SCAN_HEIGHT` from a fresh
///   read transaction (reflects live chain progress without blocking the
///   main action loop).
/// - `tip_height`: the last full-block height snapshotted at boot — good
///   enough for the rescan upper bound; the rescan task calls `read_tip()`
///   in a closure that re-reads the actual chain tip from the action-loop
///   snapshot publisher (not wired through this accessor — rescan reads
///   the tip via the `read_tip` closure passed to
///   `WalletScanService::rescan_full_rebuild`).
/// - `is_pruned`: static from config (archive-only today).
/// - `read_block_at`: delegates to `block_txs_for_wallet_at_height`.
/// - `build_signing_context` / `build_signing_params` / `lookup_utxo`:
///   use the `ChainStoreReader` to read from committed state without
///   acquiring the action-loop's mutable `StateStore`.
pub struct ChainStateAccessorImpl {
    db: Arc<redb::Database>,
    /// Lock-free reader for chain state (headers, UTXO, active params).
    reader: ergo_state::reader::ChainStoreReader,
    /// Best full-block height at the time the accessor was constructed.
    /// Updated lazily: for rescan bounds this value is recomputed via the
    /// `read_tip` closure inside `rescan_full_rebuild`; for status reads
    /// it's close enough.
    tip_height: u32,
    is_pruned: bool,
}

impl ChainStateAccessorImpl {
    pub fn new(db: Arc<redb::Database>, tip_height: u32, is_pruned: bool) -> Self {
        let reader = ergo_state::reader::ChainStoreReader::new_from_db(db.clone());
        Self {
            db,
            reader,
            tip_height,
            is_pruned,
        }
    }
}

impl ChainStateAccessor for ChainStateAccessorImpl {
    fn wallet_scan_height(&self) -> u32 {
        let Ok(read_txn) = self.db.begin_read() else {
            return 0;
        };
        let Ok(tbl) = read_txn.open_table(ergo_state::wallet::tables::WALLET_SCAN_HEIGHT) else {
            return 0;
        };
        tbl.get(()).ok().flatten().map(|g| g.value()).unwrap_or(0)
    }

    fn tip_height(&self) -> u32 {
        self.tip_height
    }

    fn is_pruned(&self) -> bool {
        self.is_pruned
    }

    fn read_block_at(&self, height: u32) -> Option<ergo_state::wallet::scan::RescanBlock> {
        use ergo_state::store::block_txs_for_wallet_at_height;
        use ergo_state::wallet::scan::{OwnedBlockOutput, RescanBlock, RescanTx};

        let (block_id, owned) = match block_txs_for_wallet_at_height(&self.db, height) {
            Ok(Some(pair)) => pair,
            Ok(None) => return None,
            Err(e) => {
                // A DB read error here used to be swallowed as "no block at
                // this height" (unwrap_or(None)), which on a wallet rescan
                // would silently skip the height and could drop owned txs.
                // Behaviour is unchanged (still None), but the fault is now
                // visible instead of masquerading as an empty block.
                tracing::warn!(
                    height,
                    error = %e,
                    "wallet rescan: block_txs_for_wallet_at_height failed — skipping height"
                );
                return None;
            }
        };

        let txs = owned
            .into_iter()
            .map(|d| RescanTx {
                tx_id: d.tx_id,
                inputs: d.inputs,
                outputs: d
                    .outputs
                    .into_iter()
                    .map(|o| OwnedBlockOutput {
                        box_id: o.box_id,
                        output_index: o.output_index,
                        ergo_tree_bytes: o.ergo_tree_bytes,
                        value: o.value,
                        assets: o.assets,
                        miner_reward_pubkey: o.miner_reward_pubkey,
                        // Carried for the rescan scan-matcher + ScanTrackedBox.
                        box_bytes: o.box_bytes,
                    })
                    .collect(),
            })
            .collect();

        Some(RescanBlock { block_id, txs })
    }

    fn build_signing_context(
        &self,
    ) -> Result<ergo_wallet::tx_context::BlockchainStateContext, WalletAdminError> {
        use ergo_primitives::digest::ADDigest;
        use ergo_primitives::reader::VlqReader;
        use ergo_ser::header::read_header;
        use ergo_validation::pre_header::CandidatePreHeader;

        // Determine committed tip from chain_state_meta.
        let (tip_height, tip_id) = self
            .reader
            .committed_tip()
            .map_err(|e| WalletAdminError::Internal(format!("committed_tip: {e}")))?
            .ok_or_else(|| {
                WalletAdminError::Internal("no committed tip (chain not started)".into())
            })?;

        if tip_height < 10 {
            return Err(WalletAdminError::Internal(format!(
                "chain tip {tip_height} < 10; wait for more sync before signing"
            )));
        }

        // Read the last ≤10 applied headers from the canonical chain.
        let window_lo = tip_height.saturating_sub(9);
        let header_ids = self
            .reader
            .scan_header_chain_range(window_lo, tip_height)
            .map_err(|e| WalletAdminError::Internal(format!("scan_header_chain_range: {e}")))?;

        let mut sigma_last_headers = Vec::with_capacity(header_ids.len());
        for (_, hid) in &header_ids {
            let hdr_bytes = self
                .reader
                .get_header(hid)
                .map_err(|e| WalletAdminError::Internal(format!("get_header: {e}")))?
                .ok_or_else(|| {
                    WalletAdminError::Internal(format!(
                        "header missing for id {}",
                        hex::encode(hid)
                    ))
                })?;
            let mut r = VlqReader::new(&hdr_bytes);
            let h = read_header(&mut r)
                .map_err(|e| WalletAdminError::Internal(format!("read_header: {e:?}")))?;
            sigma_last_headers.push(h);
        }
        // Reverse so index 0 = most recent (tip) — `sigma_last_headers[0]` is
        // the parent of the candidate block per BlockchainStateContext contract.
        sigma_last_headers.reverse();

        let tip_header = sigma_last_headers
            .first()
            .ok_or_else(|| WalletAdminError::Internal("empty header window".into()))?;

        // Read previous state digest (STATE_META). We fall back to the tip
        // header's state_root if STATE_META isn't readable.
        let previous_state_digest = ADDigest::from_bytes(*tip_header.state_root.as_bytes());

        // Build CandidatePreHeader from the tip header.
        let sigma_pre_header = CandidatePreHeader {
            version: tip_header.version,
            parent_id: tip_id,
            height: tip_height + 1,
            timestamp: tip_header.timestamp + 1,
            n_bits: tip_header.n_bits,
            votes: [0, 0, 0],
            // Use the tip header's miner pubkey as a stand-in. Wallet signing
            // doesn't mine — the pubkey only affects CONTEXT.preHeader.minerPk
            // in script evaluation (rare for P2PK spend scripts).
            miner_pubkey: *tip_header.solution.pk().as_bytes(),
        };

        Ok(ergo_wallet::tx_context::BlockchainStateContext {
            sigma_last_headers,
            sigma_pre_header,
            previous_state_digest,
        })
    }

    fn build_signing_params(
        &self,
    ) -> Result<ergo_wallet::tx_context::BlockchainParameters, WalletAdminError> {
        let (tip_height, _) = self
            .reader
            .committed_tip()
            .map_err(|e| WalletAdminError::Internal(format!("committed_tip: {e}")))?
            .ok_or_else(|| WalletAdminError::Internal("no committed tip".into()))?;

        let params = self
            .reader
            .active_params_at(tip_height)
            .map_err(|e| WalletAdminError::Internal(format!("active_params_at: {e}")))?
            .ok_or_else(|| WalletAdminError::Internal("no active params at tip".into()))?;

        Ok(ergo_wallet::tx_context::BlockchainParameters {
            max_block_cost: params.max_block_cost as u64,
            input_cost: params.input_cost as u64,
            data_input_cost: params.data_input_cost as u64,
            output_cost: params.output_cost as u64,
            token_access_cost: params.token_access_cost as u64,
            // interpreter_init_cost is a fixed constant not stored in voted params;
            // must match ergo_validation::INTERPRETER_INIT_COST (10_000) exactly so
            // wallet self-verify reproduces the chain validator's cost accounting.
            interpreter_init_cost: ergo_validation::INTERPRETER_INIT_COST,
            block_version: params.block_version,
        })
    }

    fn build_protocol_params(&self) -> Result<ergo_validation::ProtocolParams, WalletAdminError> {
        let (tip_height, _) = self
            .reader
            .committed_tip()
            .map_err(|e| WalletAdminError::Internal(format!("committed_tip: {e}")))?
            .ok_or_else(|| WalletAdminError::Internal("no committed tip".into()))?;
        let active = self
            .reader
            .active_params_at(tip_height)
            .map_err(|e| WalletAdminError::Internal(format!("active_params_at: {e}")))?
            .ok_or_else(|| WalletAdminError::Internal("no active params at tip".into()))?;
        // Authoritative per-epoch params — the same source the consensus
        // validator uses, so the wallet's pre-submit structural check can't
        // drift from on-chain min-box-value / box-cap rules.
        Ok(ergo_validation::ProtocolParams::from_active(&active))
    }

    fn lookup_utxo(&self, box_id: &[u8; 32]) -> Option<ergo_ser::ergo_box::ErgoBox> {
        use ergo_primitives::reader::VlqReader;
        let bytes = self.reader.lookup_box(box_id).ok()??;
        let mut r = VlqReader::new(&bytes);
        ergo_ser::ergo_box::read_ergo_box(&mut r).ok()
    }
}

/// Production `WalletApplyHook` backed by the shared `Arc<RwLock<WalletState>>`
/// (synchronous `parking_lot::RwLock`).
///
/// Invoked from `StateStore::apply_block` and `rollback_to` on the chain-apply
/// path inside `handle_sync_tick`. The trait is synchronous because the apply
/// path is synchronous; the lock is synchronous because `WalletState` is plain
/// in-memory data. Both hook methods clone one collection and drop the guard.
///
/// Contention coupling: admin commands (`unlock`, `restore`, `derive_*`) take
/// the writer side across PBKDF2 / key-derivation work, so the hook can wait
/// briefly when one is in flight. Block-apply cadence (~120 s mainnet) is
/// much slower than even a slow PBKDF2 (sub-second), so the worst case is a
/// single delayed apply per admin operation.
pub struct WalletStateHook {
    pub wallet: Arc<RwLock<ergo_wallet::state::WalletState>>,
    /// Shared redb handle — used to read the registered scans for block-apply
    /// matching (the scans live in redb, not `WalletState`).
    pub db: Arc<redb::Database>,
}

impl ergo_state::wallet::WalletApplyHook for WalletStateHook {
    fn tracked_p2pk_trees(&self) -> std::collections::BTreeSet<Vec<u8>> {
        // Skip during rescan: the live apply hook returns empty so chain-apply
        // doesn't interfere with the background rescan writing the same tables.
        if crate::wallet_boot::RESCAN_IN_PROGRESS.load(Ordering::SeqCst) {
            return std::collections::BTreeSet::new();
        }
        let state = self.wallet.read();
        state.tracked_p2pk_trees().clone()
    }

    fn cached_pubkeys(&self) -> std::collections::BTreeMap<u64, [u8; 33]> {
        if crate::wallet_boot::RESCAN_IN_PROGRESS.load(Ordering::SeqCst) {
            return std::collections::BTreeMap::new();
        }
        let state = self.wallet.read();
        state.cached_pubkeys().clone()
    }

    fn registered_scan_count(&self) -> usize {
        // Skip live scan apply while a full rescan is rebuilding the scan
        // tables: the rebuild clears and repopulates WALLET_SCAN_* block by
        // block, so a concurrent live write would race it (miss a spend
        // against the cleared reverse index, or stale that index). Mirrors
        // how the pubkey path skips during RESCAN_IN_PROGRESS. A PARTIAL
        // rescan does not set this flag, so live scan tracking continues
        // across it (scans have no range-rewind rebuild).
        if crate::wallet_boot::SCAN_REBUILD_IN_PROGRESS.load(Ordering::SeqCst) {
            return 0;
        }
        // Cheap per-block gate: count rows in WALLET_SCANS. Scan tracking is
        // independent of the wallet-pubkey rescan, so (unlike the methods above)
        // it is NOT skipped while a *partial* rescan is in progress. A read error
        // skips scan work for this block (logged) rather than aborting chain apply.
        use redb::ReadableTableMetadata;
        let count = self.db.begin_read().ok().and_then(|r| {
            match r.open_table(ergo_state::wallet::tables::WALLET_SCANS) {
                Ok(t) => t.len().ok().map(|n| n as usize),
                Err(redb::TableError::TableDoesNotExist(_)) => Some(0),
                Err(_) => None,
            }
        });
        match count {
            Some(n) => n,
            None => {
                tracing::error!("scan apply: WALLET_SCANS count read failed; skipping this block");
                0
            }
        }
    }

    fn match_boxes(&self, boxes: &[ergo_ser::ergo_box::ErgoBox]) -> Vec<Vec<u16>> {
        // Quiesced during a scan rebuild (see `registered_scan_count`). The
        // count gate already returns 0 then, so this is defense in depth —
        // mirrors the pubkey path gating both of its hook methods.
        if crate::wallet_boot::SCAN_REBUILD_IN_PROGRESS.load(Ordering::SeqCst) {
            return vec![Vec::new(); boxes.len()];
        }
        // Load the registry once for the whole block, then match each box.
        match commands::scan::load_registry(&self.db) {
            Ok(registry) => boxes
                .iter()
                .map(|b| registry.matching_scan_ids(b))
                .collect(),
            Err(e) => {
                tracing::error!(error = %e, "scan apply: registry load failed; no matches this block");
                vec![Vec::new(); boxes.len()]
            }
        }
    }
}

/// Pruning + network + operator-flag config supplied at boot.
pub struct WriterConfig {
    pub network: ergo_ser::address::NetworkPrefix,
    /// `[wallet] expose_private_keys`: gates `POST /wallet/getPrivateKey`.
    /// `false` (default) returns 403 Forbidden; `true` allows the
    /// route to return the derived secret scalar.
    pub expose_private_keys: bool,
}

/// Writer-task loop. Runs in a dedicated tokio task; receives commands and
/// dispatches against owned `storage` + `state` + `db` + `chain` accessor.
/// Each command's reply is sent back via its oneshot.
#[allow(clippy::result_large_err)] // redb::Error is large; closures in rescan dispatch can't avoid it
#[allow(clippy::too_many_arguments)] // task spawn-point: owned deps unpacked straight into WriterContext
pub async fn run_wallet_writer(
    mut rx: mpsc::Receiver<WalletCommand>,
    storage: Arc<RwLock<SecretStorage>>,
    state: Arc<RwLock<WalletState>>,
    db: Arc<redb::Database>,
    chain: Arc<dyn ChainStateAccessor>,
    cfg: WriterConfig,
    submit_handle: Arc<dyn TxSubmitter>,
    mempool: Arc<dyn ergo_api::MempoolView>,
) {
    let ctx = commands::WriterContext {
        storage: &storage,
        state: &state,
        db: &db,
        chain: &chain,
        cfg: &cfg,
        submit_handle: &submit_handle,
        mempool: &mempool,
    };
    while let Some(cmd) = rx.recv().await {
        match cmd {
            WalletCommand::Status { reply } => commands::admin::status(&ctx, reply).await,
            WalletCommand::Init {
                pass,
                mnemonic_pass,
                strength,
                reply,
            } => commands::admin::init(&ctx, pass, mnemonic_pass, strength, reply).await,
            WalletCommand::Restore {
                mnemonic,
                mnemonic_pass,
                pass,
                use_pre_1627,
                reply,
            } => {
                commands::admin::restore(&ctx, mnemonic, mnemonic_pass, pass, use_pre_1627, reply)
                    .await
            }
            WalletCommand::Rescan { from_height, reply } => {
                commands::admin::rescan(&ctx, from_height, reply).await
            }
            WalletCommand::Unlock { pass, reply } => {
                commands::admin::unlock(&ctx, pass, reply).await
            }
            WalletCommand::Lock { reply } => commands::admin::lock(&ctx, reply).await,
            WalletCommand::Check {
                mnemonic,
                mnemonic_pass,
                reply,
            } => commands::admin::check(&ctx, mnemonic, mnemonic_pass, reply).await,
            WalletCommand::UpdateChangeAddress { address, reply } => {
                commands::admin::update_change_address(&ctx, address, reply).await
            }
            WalletCommand::Balances { reply } => commands::admin::balances(&ctx, reply).await,
            WalletCommand::BalancesWithUnconfirmed { reply } => {
                commands::admin::balances_with_unconfirmed(&ctx, reply).await
            }
            WalletCommand::Addresses { reply } => commands::admin::addresses(&ctx, reply).await,
            WalletCommand::Boxes { page, reply } => commands::admin::boxes(&ctx, page, reply).await,
            WalletCommand::BoxesUnspent { page, reply } => {
                commands::admin::boxes_unspent(&ctx, page, reply).await
            }
            WalletCommand::Transactions { page, reply } => {
                commands::admin::transactions(&ctx, page, reply).await
            }
            WalletCommand::TransactionById { tx_id_hex, reply } => {
                commands::admin::transaction_by_id(&ctx, tx_id_hex, reply).await
            }
            WalletCommand::TransactionsByScanId {
                scan_id,
                page,
                reply,
            } => commands::admin::transactions_by_scan_id(&ctx, scan_id, page, reply).await,
            WalletCommand::PaymentSend { requests, reply } => {
                commands::send::payment_send(&ctx, requests, reply).await
            }
            WalletCommand::TransactionGenerate { request, reply } => {
                commands::send::transaction_generate(&ctx, request, reply).await
            }
            WalletCommand::TransactionGenerateUnsigned { request, reply } => {
                commands::send::transaction_generate_unsigned(&ctx, request, reply).await
            }
            WalletCommand::TransactionSign { request, reply } => {
                commands::send::transaction_sign(&ctx, request, reply).await
            }
            WalletCommand::TransactionSend { request, reply } => {
                commands::send::transaction_send(&ctx, request, reply).await
            }
            WalletCommand::BoxesCollect { request, reply } => {
                commands::send::boxes_collect(&ctx, request, reply).await
            }
            WalletCommand::GenerateCommitments { request, reply } => {
                commands::multisig::generate_commitments(&ctx, request, reply).await
            }
            WalletCommand::ExtractHints { request, reply } => {
                commands::multisig::extract_hints(&ctx, request, reply).await
            }
            WalletCommand::DeriveKey { request, reply } => {
                commands::multisig::derive_key(&ctx, request, reply).await
            }
            WalletCommand::DeriveNextKey { reply } => {
                commands::multisig::derive_next_key(&ctx, reply).await
            }
            WalletCommand::GetPrivateKey { request, reply } => {
                commands::multisig::get_private_key(&ctx, request, reply).await
            }
            WalletCommand::RegisterScan { request, reply } => {
                commands::scan::register(&ctx, request, reply).await
            }
            WalletCommand::DeregisterScan { scan_id, reply } => {
                commands::scan::deregister(&ctx, scan_id, reply).await
            }
            WalletCommand::ListScans { reply } => commands::scan::list(&ctx, reply).await,
            WalletCommand::ScanUnspentBoxes {
                scan_id,
                filter,
                reply,
            } => commands::scan::unspent_boxes(&ctx, scan_id, filter, reply).await,
            WalletCommand::ScanSpentBoxes {
                scan_id,
                filter,
                reply,
            } => commands::scan::spent_boxes(&ctx, scan_id, filter, reply).await,
            WalletCommand::ScanStopTracking {
                scan_id,
                box_id,
                reply,
            } => commands::scan::stop_tracking(&ctx, scan_id, box_id, reply).await,
            WalletCommand::ScanAddBox {
                scan_ids,
                box_json,
                reply,
            } => commands::scan::add_box(&ctx, scan_ids, box_json, reply).await,
            WalletCommand::ScanP2sRule { p2s, reply } => {
                commands::scan::p2s_rule(&ctx, p2s, reply).await
            }
        }
    }
}

// `run_wallet_writer` per-command handlers split into per-group
// submodules. Each handler receives a borrowed
// `commands::WriterContext` plus the per-command params +
// reply oneshot.
mod commands;

// ---- C.15 send-path helpers ----

/// Minimum fee in nanoERG. Mirrors Scala's `Parameters.MinFee`.
const MIN_FEE: u64 = 1_000_000;
/// Minimum box value in nanoERG. Mirrors Scala's `BoxUtils.MinBoxValue`.
const MIN_BOX_VALUE: u64 = 1_000_000;

/// Build an unsigned transaction from payment requests (the shared build path).
///
/// `override_inputs` / `override_data_inputs`: hex box ids supplied by the
/// caller; `None` means "use automatic box selection".
/// `fee_override`: explicit fee; `None` uses `MIN_FEE`.
///
/// Returns serialised `UnsignedTransaction` bytes.
#[allow(clippy::too_many_arguments)]
async fn build_unsigned_tx(
    requests: &[PaymentRequestDto],
    override_inputs: Option<&[String]>,
    override_data_inputs: Option<&[String]>,
    fee_override: Option<u64>,
    state: &RwLock<ergo_wallet::state::WalletState>,
    db: &redb::Database,
    chain: &dyn ChainStateAccessor,
    network: ergo_ser::address::NetworkPrefix,
) -> Result<Vec<u8>, WalletAdminError> {
    let state = state.read();

    // Decode payment requests: address → pubkey → ErgoTree bytes.
    let payment_reqs: Vec<ergo_wallet::tx_builder::PaymentRequest> = requests
        .iter()
        .map(|r| {
            let pubkey =
                ergo_ser::address::decode_p2pk_address(&r.address, network).map_err(|e| {
                    WalletAdminError::BadRequest(format!("bad address {}: {e}", r.address))
                })?;
            // Canonical (non-segregated) P2PK tree — matches Scala
            // ErgoAddressEncoder and the wallet's own tracked_p2pk_trees.
            // The segregated build_prove_dlog_ergo_tree would emit a P2S
            // shape that recipients' wallets render as the wrong address
            // and that our own scan would not recognize as change.
            let to_ergo_tree = ergo_ser::address::build_p2pk_tree_bytes(&pubkey)
                .map_err(|e| WalletAdminError::Internal(format!("recipient p2pk tree: {e:?}")))?;
            let assets: BTreeMap<[u8; 32], u64> = r
                .assets
                .iter()
                .map(|a| {
                    let id = hex::decode(&a.token_id)
                        .ok()
                        .and_then(|v| v.try_into().ok())
                        .ok_or_else(|| {
                            WalletAdminError::Internal(format!("bad token_id: {}", a.token_id))
                        })?;
                    Ok((id, a.amount))
                })
                .collect::<Result<_, WalletAdminError>>()?;
            Ok(ergo_wallet::tx_builder::PaymentRequest {
                to_ergo_tree,
                value: r.value,
                assets,
            })
        })
        .collect::<Result<_, WalletAdminError>>()?;

    let fee = fee_override.unwrap_or(MIN_FEE);

    // Resolve change address → ErgoTree bytes.
    let change_address = state
        .change_address()
        .ok_or_else(|| WalletAdminError::Internal("no change address set".into()))?;
    let change_pubkey = ergo_ser::address::decode_p2pk_address(change_address, network)
        .map_err(|_| WalletAdminError::Internal("change address decode failed".into()))?;
    // Canonical (non-segregated) P2PK tree so the change box matches the
    // wallet's own tracked_p2pk_trees and is recognized on the next scan.
    let change_ergo_tree = ergo_ser::address::build_p2pk_tree_bytes(&change_pubkey)
        .map_err(|e| WalletAdminError::Internal(format!("change p2pk tree: {e:?}")))?;

    let fee_ergo_tree = ergo_mempool::validator::MAINNET_FEE_PROPOSITION_BYTES.to_vec();

    // Get the chain tip height for candidate creation_height.
    let current_height = chain.tip_height();

    // Build unsigned tx.
    if let Some(explicit_inputs) = override_inputs {
        // Caller-supplied box ids: decode, look up full boxes from UTXO set,
        // sum ERG + tokens, compute change, emit change output if any.

        let data_inputs: Vec<ergo_ser::input::DataInput> = override_data_inputs
            .unwrap_or(&[])
            .iter()
            .map(|hex_id| {
                let id: [u8; 32] = hex::decode(hex_id)
                    .ok()
                    .and_then(|v| v.try_into().ok())
                    .ok_or_else(|| {
                        WalletAdminError::Internal(format!("bad data input id: {hex_id}"))
                    })?;
                Ok(ergo_ser::input::DataInput {
                    box_id: ergo_primitives::digest::Digest32::from_bytes(id),
                })
            })
            .collect::<Result<_, WalletAdminError>>()?;

        // Decode, look up, and sum all provided input boxes.
        let mut input_erg_total: u64 = 0;
        let mut input_tokens_total: BTreeMap<[u8; 32], u64> = BTreeMap::new();
        let mut inputs: Vec<ergo_ser::input::UnsignedInput> =
            Vec::with_capacity(explicit_inputs.len());

        for hex_id in explicit_inputs {
            let id: [u8; 32] = hex::decode(hex_id)
                .ok()
                .and_then(|v| v.try_into().ok())
                .ok_or_else(|| WalletAdminError::Internal(format!("bad input id: {hex_id}")))?;

            let ergo_box = chain.lookup_utxo(&id).ok_or_else(|| {
                WalletAdminError::Internal(format!("input box {} not found in UTXO set", hex_id))
            })?;

            input_erg_total = input_erg_total
                .checked_add(ergo_box.candidate.value)
                .ok_or_else(|| WalletAdminError::Internal("input ERG overflow".into()))?;

            for token in &ergo_box.candidate.tokens {
                let entry = input_tokens_total
                    .entry(*token.token_id.as_bytes())
                    .or_insert(0);
                *entry = entry
                    .checked_add(token.amount)
                    .ok_or_else(|| WalletAdminError::Internal("input token overflow".into()))?;
            }

            inputs.push(ergo_ser::input::UnsignedInput {
                box_id: ergo_primitives::digest::Digest32::from_bytes(id),
                extension: ergo_ser::input::ContextExtension::empty(),
            });
        }

        // Sum required outputs (payments + fee).
        let mut required_erg: u64 = fee;
        let mut required_tokens: BTreeMap<[u8; 32], u64> = BTreeMap::new();
        for req in &payment_reqs {
            required_erg = required_erg
                .checked_add(req.value)
                .ok_or_else(|| WalletAdminError::Internal("output ERG overflow".into()))?;
            for (&id, &amt) in &req.assets {
                let entry = required_tokens.entry(id).or_insert(0);
                *entry = entry
                    .checked_add(amt)
                    .ok_or_else(|| WalletAdminError::Internal("output token overflow".into()))?;
            }
        }

        // Verify ERG coverage.
        if input_erg_total < required_erg {
            return Err(WalletAdminError::Internal(format!(
                "override-inputs insufficient ERG: have {input_erg_total}, need {required_erg}"
            )));
        }

        // Verify token coverage.
        for (token_id, &required_amt) in &required_tokens {
            let available = input_tokens_total.get(token_id).copied().unwrap_or(0);
            if available < required_amt {
                return Err(WalletAdminError::Internal(format!(
                    "override-inputs insufficient token {}: have {available}, need {required_amt}",
                    hex::encode(token_id)
                )));
            }
        }

        // Compute change.
        let change_erg = input_erg_total - required_erg;
        let mut change_tokens: BTreeMap<[u8; 32], u64> = BTreeMap::new();
        for (&id, &input_amt) in &input_tokens_total {
            let required_amt = required_tokens.get(&id).copied().unwrap_or(0);
            let rem = input_amt - required_amt;
            if rem > 0 {
                change_tokens.insert(id, rem);
            }
        }

        // Build output candidates.
        let mut output_candidates: Vec<ergo_ser::ergo_box::ErgoBoxCandidate> = Vec::new();
        for req in &payment_reqs {
            let ergo_tree = {
                let mut r = ergo_primitives::reader::VlqReader::new(&req.to_ergo_tree);
                ergo_ser::ergo_tree::read_ergo_tree(&mut r)
                    .map_err(|e| WalletAdminError::Internal(format!("payment ergo_tree: {e:?}")))?
            };
            let tokens = req
                .assets
                .iter()
                .map(|(&id, &amt)| ergo_ser::token::Token {
                    token_id: ergo_primitives::digest::Digest32::from_bytes(id),
                    amount: amt,
                })
                .collect();
            output_candidates.push(
                ergo_ser::ergo_box::ErgoBoxCandidate::new(
                    req.value,
                    ergo_tree,
                    current_height,
                    tokens,
                    ergo_ser::register::AdditionalRegisters::empty(),
                )
                .map_err(|e| {
                    WalletAdminError::Internal(format!("ErgoBoxCandidate (payment): {e:?}"))
                })?,
            );
        }

        // Decide change vs fee-fold, matching the auto-selection builder and
        // Scala `TransactionBuilder.buildUnsignedTx` (`changeGoesToFee`):
        // token-less change below MIN_BOX_VALUE is folded into the miner fee
        // rather than emitted as a dust box the validator rejects; change
        // carrying tokens is always kept as a box regardless of ERG value.
        let change_goes_to_fee =
            change_erg > 0 && change_erg < MIN_BOX_VALUE && change_tokens.is_empty();
        let fee_value = if change_goes_to_fee {
            fee.checked_add(change_erg)
                .ok_or_else(|| WalletAdminError::Internal("fee + folded change overflow".into()))?
        } else {
            fee
        };

        // Fee output (value includes any folded sub-minimum change).
        let fee_tree = {
            let mut r = ergo_primitives::reader::VlqReader::new(&fee_ergo_tree);
            ergo_ser::ergo_tree::read_ergo_tree(&mut r)
                .map_err(|e| WalletAdminError::Internal(format!("fee ergo_tree: {e:?}")))?
        };
        output_candidates.push(
            ergo_ser::ergo_box::ErgoBoxCandidate::new(
                fee_value,
                fee_tree,
                current_height,
                vec![],
                ergo_ser::register::AdditionalRegisters::empty(),
            )
            .map_err(|e| WalletAdminError::Internal(format!("ErgoBoxCandidate (fee): {e:?}")))?,
        );

        // Change output — emitted unless folded into the fee above. Exact
        // selection (change_erg == 0, no tokens) emits nothing.
        if !change_goes_to_fee && (change_erg > 0 || !change_tokens.is_empty()) {
            let change_tree = {
                let mut r = ergo_primitives::reader::VlqReader::new(&change_ergo_tree);
                ergo_ser::ergo_tree::read_ergo_tree(&mut r)
                    .map_err(|e| WalletAdminError::Internal(format!("change ergo_tree: {e:?}")))?
            };
            let change_token_vec: Vec<ergo_ser::token::Token> = change_tokens
                .iter()
                .map(|(&id, &amt)| ergo_ser::token::Token {
                    token_id: ergo_primitives::digest::Digest32::from_bytes(id),
                    amount: amt,
                })
                .collect();
            output_candidates.push(
                ergo_ser::ergo_box::ErgoBoxCandidate::new(
                    change_erg,
                    change_tree,
                    current_height,
                    change_token_vec,
                    ergo_ser::register::AdditionalRegisters::empty(),
                )
                .map_err(|e| {
                    WalletAdminError::Internal(format!("ErgoBoxCandidate (change): {e:?}"))
                })?,
            );
        }

        let unsigned_tx = ergo_ser::transaction::UnsignedTransaction {
            inputs,
            data_inputs,
            output_candidates,
        };
        serialize_unsigned_tx(&unsigned_tx)
    } else {
        // Automatic box selection from wallet unspent boxes.
        let read_txn = db
            .begin_read()
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
        let wallet_reader = ergo_state::wallet::reader::WalletReader::new(&read_txn);
        let unspent = wallet_reader
            .unspent_boxes()
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?;

        let summaries: Vec<ergo_wallet::box_selector::BoxSummary> = unspent
            .iter()
            .map(|wb| ergo_wallet::box_selector::BoxSummary {
                box_id: wb.box_id,
                value: wb.value,
                tokens: wb.assets.iter().copied().collect(),
            })
            .collect();

        let data_inputs: Vec<ergo_ser::input::DataInput> = override_data_inputs
            .unwrap_or(&[])
            .iter()
            .map(|hex_id| {
                let id: [u8; 32] = hex::decode(hex_id)
                    .ok()
                    .and_then(|v| v.try_into().ok())
                    .ok_or_else(|| {
                        WalletAdminError::Internal(format!("bad data input id: {hex_id}"))
                    })?;
                Ok(ergo_ser::input::DataInput {
                    box_id: ergo_primitives::digest::Digest32::from_bytes(id),
                })
            })
            .collect::<Result<_, WalletAdminError>>()?;

        let selector = ergo_wallet::box_selector::default::DefaultBoxSelector;
        let builder = ergo_wallet::tx_builder::UnsignedTxBuilder {
            available_summaries: &summaries,
            selector: &selector,
            fee,
            fee_ergo_tree,
            change_ergo_tree,
            current_height,
            min_box_value: MIN_BOX_VALUE,
            data_inputs,
        };

        let unsigned_tx = builder
            .build(&payment_reqs)
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?;

        serialize_unsigned_tx(&unsigned_tx)
    }
}

fn serialize_unsigned_tx(
    utx: &ergo_ser::transaction::UnsignedTransaction,
) -> Result<Vec<u8>, WalletAdminError> {
    let mut w = ergo_primitives::writer::VlqWriter::new();
    ergo_ser::transaction::write_unsigned_transaction(&mut w, utx)
        .map_err(|e| WalletAdminError::Internal(format!("serialize unsigned tx: {e:?}")))?;
    Ok(w.result())
}

fn serialize_signed_tx(
    tx: &ergo_ser::transaction::Transaction,
) -> Result<Vec<u8>, WalletAdminError> {
    let mut w = ergo_primitives::writer::VlqWriter::new();
    ergo_ser::transaction::write_transaction(&mut w, tx)
        .map_err(|e| WalletAdminError::Internal(format!("serialize signed tx: {e:?}")))?;
    Ok(w.result())
}

/// Decode an `ExternalSecretDto` hex payload into `ProverExternalSecret`.
fn decode_external_secret(
    dto: &ergo_api::wallet::sending::ExternalSecretDto,
) -> Result<ergo_wallet::proving::external::ProverExternalSecret, WalletAdminError> {
    use ergo_api::wallet::sending::ExternalSecretDto;
    use ergo_wallet::proving::external::ProverExternalSecret;
    use k256::elliptic_curve::ops::Reduce;
    use k256::{FieldBytes, Scalar, U256};

    fn decode_scalar(hex_str: &str) -> Result<Scalar, WalletAdminError> {
        let bytes: [u8; 32] = hex::decode(hex_str)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| {
                // Never interpolate the value — this is a raw private-key
                // scalar. Report only the structural fault.
                WalletAdminError::Internal(format!(
                    "external secret: invalid scalar hex (expected 64 hex chars / 32 bytes, got {} chars)",
                    hex_str.len()
                ))
            })?;
        let s = <Scalar as Reduce<U256>>::reduce_bytes(&FieldBytes::from(bytes));
        if s == Scalar::ZERO {
            return Err(WalletAdminError::Internal(
                "external secret: scalar is zero".into(),
            ));
        }
        Ok(s)
    }
    fn decode_pk(hex_str: &str, label: &str) -> Result<[u8; 33], WalletAdminError> {
        hex::decode(hex_str)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| {
                WalletAdminError::Internal(format!("external secret: bad point hex for {label}"))
            })
    }

    match dto {
        ExternalSecretDto::Dlog { dlog } => {
            let scalar = decode_scalar(dlog)?;
            // Recover the corresponding pubkey from the scalar. Read the
            // scalar through a borrow so we don't hold a bare copy past
            // the wrap below.
            use k256::elliptic_curve::group::GroupEncoding;
            use k256::elliptic_curve::ops::MulByGenerator;
            use k256::ProjectivePoint;
            let pk_point = ProjectivePoint::mul_by_generator(&scalar);
            let pk_bytes: [u8; 33] = pk_point.to_affine().to_bytes().into();
            Ok(ProverExternalSecret::Dlog {
                pk: pk_bytes,
                // Wrap so the scalar zeroizes when the enum drops.
                scalar: zeroize::Zeroizing::new(scalar),
            })
        }
        ExternalSecretDto::DhTuple { g, h, u, v, x } => Ok(ProverExternalSecret::DhTuple {
            g: decode_pk(g, "g")?,
            h: decode_pk(h, "h")?,
            u: decode_pk(u, "u")?,
            v: decode_pk(v, "v")?,
            scalar: zeroize::Zeroizing::new(decode_scalar(x)?),
        }),
    }
}

/// Build a `Prover` from wallet secrets and/or caller-supplied external secrets.
///
/// If the wallet is unlocked, the HD-derived secrets for all tracked pubkeys
/// are pre-loaded into the registry. If the wallet is locked, the registry
/// starts empty and relies on `externals` to cover all required propositions.
/// A locked wallet with no externals will produce a registry that fails at
/// proof time with `MissingSecret` — that is the correct failure mode.
fn build_prover(
    storage: &ergo_wallet::storage::SecretStorage,
    db: &redb::Database,
    chain: &dyn ChainStateAccessor,
    externals: &[ergo_wallet::proving::external::ProverExternalSecret],
) -> Result<ergo_wallet::proving::prover::Prover, WalletAdminError> {
    let registry = if let Some(unlocked) = storage.unlocked() {
        // Wallet unlocked: pre-derive secrets for all tracked pubkeys.
        let read_txn = db
            .begin_read()
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
        let wallet_reader = ergo_state::wallet::reader::WalletReader::new(&read_txn);
        let tracked_with_paths: BTreeMap<u64, ([u8; 33], Vec<u32>)> = wallet_reader
            .tracked_pubkeys_with_paths()
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?
            .into_iter()
            .map(|(idx, pk, path)| (idx, (pk, path)))
            .collect();

        ergo_wallet::proving::secrets::SecretRegistry::from_master_key(
            &unlocked.master,
            &tracked_with_paths,
        )
        .map_err(|e| WalletAdminError::Internal(e.to_string()))?
        .merge_external_secrets(externals)
        .map_err(|e| WalletAdminError::Internal(e.to_string()))?
    } else {
        // Wallet locked: start with an empty registry. If externals cover all
        // required propositions, signing succeeds; otherwise prove_sigma returns
        // MissingSecret, which surfaces as a sign error (not a Locked error).
        ergo_wallet::proving::secrets::SecretRegistry::empty()
            .merge_external_secrets(externals)
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?
    };

    let params = chain.build_signing_params()?;
    Ok(ergo_wallet::proving::prover::Prover::new(registry, params))
}

/// Sign an `UnsignedTransaction` using the wallet prover, performing
/// mandatory self-verify before returning the signed bytes.
///
/// `hints` is threaded through to the prover so multi-sig callers can
/// supply a populated `TransactionHintsBag`; single-sig callers pass
/// `&TransactionHintsBag::empty()`.
fn sign_unsigned_tx(
    unsigned_tx: &ergo_ser::transaction::UnsignedTransaction,
    storage: &ergo_wallet::storage::SecretStorage,
    db: &redb::Database,
    chain: &dyn ChainStateAccessor,
    externals: &[ergo_wallet::proving::external::ProverExternalSecret],
    hints: &ergo_wallet::proving::hints::TransactionHintsBag,
) -> Result<ergo_ser::transaction::Transaction, WalletAdminError> {
    let state_ctx = chain.build_signing_context()?;
    let params = chain.build_signing_params()?;
    let prover = build_prover(storage, db, chain, externals)?;

    // Look up the full ErgoBox for each input.
    let boxes_to_spend: Vec<ergo_ser::ergo_box::ErgoBox> = unsigned_tx
        .inputs
        .iter()
        .enumerate()
        .map(|(idx, ui)| {
            let box_id = ui.box_id.as_bytes();
            chain.lookup_utxo(box_id).ok_or_else(|| {
                WalletAdminError::Internal(format!(
                    "input {} box {} not found in UTXO set",
                    idx,
                    hex::encode(box_id)
                ))
            })
        })
        .collect::<Result<_, _>>()?;

    let data_boxes: Vec<ergo_ser::ergo_box::ErgoBox> = unsigned_tx
        .data_inputs
        .iter()
        .enumerate()
        .map(|(idx, di)| {
            let box_id = di.box_id.as_bytes();
            chain.lookup_utxo(box_id).ok_or_else(|| {
                WalletAdminError::Internal(format!(
                    "data input {} box {} not found in UTXO set",
                    idx,
                    hex::encode(box_id)
                ))
            })
        })
        .collect::<Result<_, _>>()?;

    let signed_tx = prover
        .sign(unsigned_tx, &boxes_to_spend, &data_boxes, &state_ctx, hints)
        .map_err(|e| WalletAdminError::Internal(format!("sign: {e}")))?;

    // Pre-submit structural validation against the SAME ruleset the node's
    // consensus validator runs (size-aware min box value =
    // serialized_box_size * min_value_per_byte, box/collection caps). This
    // replaces the wallet's old flat MIN_BOX_VALUE heuristic so the wallet
    // never builds a tx the node would reject as dust. Runs on the final
    // signed tx, before the cost-accounting self-verify and submit.
    let protocol_params = chain.build_protocol_params()?;
    ergo_validation::tx::structural::validate_structural(&signed_tx, &protocol_params)
        .map_err(|e| WalletAdminError::BadRequest(format!("transaction rejected: {e}")))?;

    // Mandatory self-verify: reproduces chain validator cost accounting before submission.
    self_verify_signed_tx(
        &signed_tx,
        &boxes_to_spend,
        &data_boxes,
        &state_ctx,
        &params,
    )?;

    Ok(signed_tx)
}

/// Self-verify every input's spending proof against the real block cost limit.
///
/// Reproduces the chain validator's cost accounting exactly:
///
/// 1. Compute the transaction-level init cost (same formula as
///    `ergo_validation::compute_tx_init_cost`) and pre-charge it into the
///    accumulator before the input loop.
/// 2. Reuse ONE `CostAccumulator` across all inputs — this matches
///    `ergo-validation/src/tx/mod.rs` where the accumulator is threaded
///    through `validate_scripts` across the entire input set.  A per-input
///    fresh accumulator would miss cross-input cost overages that the chain
///    validator would catch.
///
/// The per-call `verify_spending_proof_with_context_and_cost` still fires
/// its own cost check, so a single input that alone exceeds the limit is
/// still caught immediately.
fn self_verify_signed_tx(
    tx: &ergo_ser::transaction::Transaction,
    boxes_to_spend: &[ergo_ser::ergo_box::ErgoBox],
    data_boxes: &[ergo_ser::ergo_box::ErgoBox],
    state_ctx: &ergo_wallet::tx_context::BlockchainStateContext,
    params: &ergo_wallet::tx_context::BlockchainParameters,
) -> Result<(), WalletAdminError> {
    use ergo_primitives::cost::{CostAccumulator, JitCost};
    use ergo_sigma::reduce::verify_spending_proof_with_context_and_cost;

    let jit_limit = JitCost::from_block_cost(params.max_block_cost)
        .map_err(|e| WalletAdminError::Internal(format!("self-verify cost limit: {e}")))?;

    // ONE accumulator for the entire tx, matching ergo-validation's tx-wide accounting.
    let mut cost_acc = CostAccumulator::new(jit_limit);

    // Pre-charge the tx-level init cost.  Mirrors the validator's Stage 5.5
    // (ergo-validation/src/tx/mod.rs: `compute_tx_init_cost` → `cx.cost.add`).
    // Shared with the consensus validator via ergo-validation, so the
    // self-verify gate can't drift from on-chain cost accounting.
    let init_cost = ergo_validation::compute_tx_init_cost_with_costs(
        tx,
        boxes_to_spend,
        params.interpreter_init_cost,
        params.input_cost,
        params.data_input_cost,
        params.output_cost,
        params.token_access_cost,
    );
    let init_jit = JitCost::from_block_cost(init_cost)
        .map_err(|e| WalletAdminError::Internal(format!("self-verify init cost: {e}")))?;
    cost_acc.add(init_jit).map_err(|_| {
        WalletAdminError::Internal("self-verify: tx init cost exceeds limit".into())
    })?;

    let message = ergo_ser::transaction::bytes_to_sign(tx)
        .map_err(|e| WalletAdminError::Internal(format!("bytes_to_sign: {e:?}")))?;

    let all_input_extensions: Vec<ergo_ser::input::ContextExtension> = tx
        .inputs
        .iter()
        .map(|i| i.spending_proof.extension.clone())
        .collect();

    for (idx, (input, input_box)) in tx.inputs.iter().zip(boxes_to_spend.iter()).enumerate() {
        let owned_rc = state_ctx.build_reduction_owned(
            input_box,
            &input.spending_proof.extension,
            boxes_to_spend,
            data_boxes,
            &tx.output_candidates,
            &all_input_extensions,
        );
        let ctx = owned_rc.as_borrowed();
        let ergo_tree = input_box.candidate.ergo_tree();
        let ok = verify_spending_proof_with_context_and_cost(
            ergo_tree,
            &input.spending_proof.proof,
            &message,
            &ctx,
            &mut cost_acc,
        )
        .map_err(|e| WalletAdminError::Internal(format!("self-verify input {idx}: {e:?}")))?;
        if !ok {
            return Err(WalletAdminError::Internal(format!(
                "self-verify failed for input {idx}"
            )));
        }
    }
    Ok(())
}

/// `PaymentSend` + `TransactionSend` shared path: build, sign, self-verify, submit.
///
/// Requires an unlocked wallet: change-address derivation and HD-key signing
/// both need the decrypted master key. Returns `WalletAdminError::Locked`
/// (HTTP 400 wallet_locked) before attempting to build the tx, preventing a
/// confusing Internal/500 from `MissingSecret` deep in the signing path.
/// `transaction_sign` is the only route that accepts the locked + externals path.
#[allow(clippy::too_many_arguments)]
async fn payment_send_impl(
    requests: &[PaymentRequestDto],
    override_inputs: Option<&[String]>,
    override_data_inputs: Option<&[String]>,
    fee_override: Option<u64>,
    storage: &RwLock<ergo_wallet::storage::SecretStorage>,
    state: &RwLock<ergo_wallet::state::WalletState>,
    db: &redb::Database,
    chain: &dyn ChainStateAccessor,
    submitter: &dyn TxSubmitter,
    network: ergo_ser::address::NetworkPrefix,
) -> Result<String, WalletAdminError> {
    // Reject immediately with a clean 400 wallet_locked rather than letting
    // the signing path fail deep inside prove_sigma with MissingSecret → 500.
    if storage.read().unlocked().is_none() {
        return Err(WalletAdminError::Locked);
    }

    let unsigned_bytes = build_unsigned_tx(
        requests,
        override_inputs,
        override_data_inputs,
        fee_override,
        state,
        db,
        chain,
        network,
    )
    .await?;

    let unsigned_tx = {
        let mut r = ergo_primitives::reader::VlqReader::new(&unsigned_bytes);
        ergo_ser::transaction::read_unsigned_transaction(&mut r)
            .map_err(|e| WalletAdminError::Internal(format!("deserialize unsigned tx: {e:?}")))?
    };

    // Scope the guard so it lexically ends before the .await below —
    // `parking_lot::RwLockReadGuard` is `!Send`, and the future returned by
    // `payment_send_impl` is spawned on a multi-thread runtime where any
    // value live across an .await must be `Send`. An explicit `drop()`
    // does not shrink the future state machine's scope; a block does.
    let signed_tx = {
        let storage = storage.read();
        sign_unsigned_tx(
            &unsigned_tx,
            &storage,
            db,
            chain,
            &[],
            &ergo_wallet::proving::hints::TransactionHintsBag::empty(),
        )?
    };

    let tx_id = ergo_ser::transaction::transaction_id(&signed_tx)
        .map_err(|e| WalletAdminError::Internal(format!("transaction_id: {e:?}")))?;
    let tx_id_hex = hex::encode(tx_id.as_bytes());

    let tx_bytes = serialize_signed_tx(&signed_tx)?;
    submitter.submit_transaction(tx_bytes).await?;

    Ok(tx_id_hex)
}

/// `TransactionGenerate` path: build, sign, self-verify; do NOT submit.
///
/// Requires an unlocked wallet for the same reason as `payment_send_impl`.
/// Returns `WalletAdminError::Locked` (400 wallet_locked) when locked.
#[allow(clippy::too_many_arguments)]
async fn transaction_generate_impl(
    requests: &[PaymentRequestDto],
    override_inputs: Option<&[String]>,
    override_data_inputs: Option<&[String]>,
    fee_override: Option<u64>,
    storage: &RwLock<ergo_wallet::storage::SecretStorage>,
    state: &RwLock<ergo_wallet::state::WalletState>,
    db: &redb::Database,
    chain: &dyn ChainStateAccessor,
    network: ergo_ser::address::NetworkPrefix,
) -> Result<Vec<u8>, WalletAdminError> {
    if storage.read().unlocked().is_none() {
        return Err(WalletAdminError::Locked);
    }

    let unsigned_bytes = build_unsigned_tx(
        requests,
        override_inputs,
        override_data_inputs,
        fee_override,
        state,
        db,
        chain,
        network,
    )
    .await?;

    let unsigned_tx = {
        let mut r = ergo_primitives::reader::VlqReader::new(&unsigned_bytes);
        ergo_ser::transaction::read_unsigned_transaction(&mut r)
            .map_err(|e| WalletAdminError::Internal(format!("deserialize unsigned tx: {e:?}")))?
    };

    let storage = storage.read();
    let signed_tx = sign_unsigned_tx(
        &unsigned_tx,
        &storage,
        db,
        chain,
        &[],
        &ergo_wallet::proving::hints::TransactionHintsBag::empty(),
    )?;
    drop(storage);

    serialize_signed_tx(&signed_tx)
}

/// `TransactionGenerateUnsigned` path: build only; no sign, no submit.
#[allow(clippy::too_many_arguments)]
async fn transaction_generate_unsigned_impl(
    requests: &[PaymentRequestDto],
    override_inputs: Option<&[String]>,
    override_data_inputs: Option<&[String]>,
    fee_override: Option<u64>,
    storage: &RwLock<ergo_wallet::storage::SecretStorage>,
    state: &RwLock<ergo_wallet::state::WalletState>,
    db: &redb::Database,
    chain: &dyn ChainStateAccessor,
    network: ergo_ser::address::NetworkPrefix,
) -> Result<Vec<u8>, WalletAdminError> {
    // Require the wallet to be unlocked so change-address is available.
    {
        let _storage = storage.read();
    }
    build_unsigned_tx(
        requests,
        override_inputs,
        override_data_inputs,
        fee_override,
        state,
        db,
        chain,
        network,
    )
    .await
}

/// `TransactionSign` path: decode an unsigned tx hex, sign it, self-verify.
/// Works with external secrets even when the wallet is locked.
async fn transaction_sign_impl(
    unsigned_tx_hex: &str,
    external_secret_dtos: Option<&[ergo_api::wallet::sending::ExternalSecretDto]>,
    hints: Option<&ergo_api::wallet::sending::TxHintsBagDto>,
    storage: &RwLock<ergo_wallet::storage::SecretStorage>,
    _state: &RwLock<ergo_wallet::state::WalletState>,
    db: &redb::Database,
    chain: &dyn ChainStateAccessor,
) -> Result<Vec<u8>, WalletAdminError> {
    let unsigned_tx_bytes = hex::decode(unsigned_tx_hex)
        .map_err(|_| WalletAdminError::Internal("unsigned_tx: bad hex".into()))?;
    let unsigned_tx = {
        let mut r = ergo_primitives::reader::VlqReader::new(&unsigned_tx_bytes);
        ergo_ser::transaction::read_unsigned_transaction(&mut r)
            .map_err(|e| WalletAdminError::Internal(format!("unsigned_tx decode: {e:?}")))?
    };

    let externals: Vec<ergo_wallet::proving::external::ProverExternalSecret> = external_secret_dtos
        .unwrap_or(&[])
        .iter()
        .map(decode_external_secret)
        .collect::<Result<_, _>>()?;

    let hints_bag: ergo_wallet::proving::hints::TransactionHintsBag = match hints {
        Some(dto) => tx_hints_bag_from_dto(dto)
            .map_err(|e| WalletAdminError::Internal(format!("decode hints: {e:?}")))?,
        None => ergo_wallet::proving::hints::TransactionHintsBag::empty(),
    };

    let storage = storage.read();
    let signed_tx = sign_unsigned_tx(&unsigned_tx, &storage, db, chain, &externals, &hints_bag)?;
    drop(storage);

    serialize_signed_tx(&signed_tx)
}

/// `BoxesCollect` path: run box selection; no signing, no submit.
fn boxes_collect_impl(
    request: &BoxesCollectRequest,
    _storage: &RwLock<ergo_wallet::storage::SecretStorage>,
    _state: &RwLock<ergo_wallet::state::WalletState>,
    db: &redb::Database,
    chain: &dyn ChainStateAccessor,
) -> Result<BoxesCollectResponse, WalletAdminError> {
    let _ = chain; // used for UTXO lookup in future phases
    let read_txn = db
        .begin_read()
        .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
    let wallet_reader = ergo_state::wallet::reader::WalletReader::new(&read_txn);
    let unspent = wallet_reader
        .unspent_boxes()
        .map_err(|e| WalletAdminError::Internal(e.to_string()))?;

    let summaries: Vec<ergo_wallet::box_selector::BoxSummary> = unspent
        .iter()
        .map(|wb| ergo_wallet::box_selector::BoxSummary {
            box_id: wb.box_id,
            value: wb.value,
            tokens: wb.assets.iter().copied().collect(),
        })
        .collect();

    let target_tokens: BTreeMap<[u8; 32], u64> = request
        .target_assets
        .iter()
        .map(|a| {
            let id: [u8; 32] = hex::decode(&a.token_id)
                .ok()
                .and_then(|v| v.try_into().ok())
                .ok_or_else(|| {
                    WalletAdminError::Internal(format!("bad token_id: {}", a.token_id))
                })?;
            Ok((id, a.amount))
        })
        .collect::<Result<_, WalletAdminError>>()?;

    let target = ergo_wallet::box_selector::SelectionTarget {
        erg_amount: request.target_balance,
        tokens: target_tokens,
        min_change_value: MIN_BOX_VALUE,
    };

    let selector = ergo_wallet::box_selector::default::DefaultBoxSelector;
    let selection = ergo_wallet::box_selector::BoxSelector::select(&selector, &summaries, &target)
        .map_err(|e| WalletAdminError::Internal(e.to_string()))?;

    let boxes = selection.selected_ids.iter().map(hex::encode).collect();
    let change_boxes = if selection.change_erg > 0 || !selection.change_tokens.is_empty() {
        // There is change; the actual change box will be built at tx-construction time.
        // For now report the ERG change amount as a synthetic hex-encoded placeholder.
        vec![hex::encode(selection.change_erg.to_be_bytes())]
    } else {
        vec![]
    };

    Ok(BoxesCollectResponse {
        boxes,
        change_boxes,
    })
}

// ---- DTO conversion helpers ----

fn box_status_str(status: &ergo_state::wallet::types::BoxStatus) -> String {
    match status {
        ergo_state::wallet::types::BoxStatus::Confirmed => "Confirmed".to_string(),
        ergo_state::wallet::types::BoxStatus::Immature { .. } => "Immature".to_string(),
        ergo_state::wallet::types::BoxStatus::Spent { .. } => "Spent".to_string(),
    }
}

fn box_provenance_str(provenance: &ergo_state::wallet::types::BoxProvenance) -> String {
    match provenance {
        ergo_state::wallet::types::BoxProvenance::Owned => "Owned".to_string(),
        ergo_state::wallet::types::BoxProvenance::MinerReward => "MinerReward".to_string(),
        ergo_state::wallet::types::BoxProvenance::Custom { .. } => "Custom".to_string(),
    }
}

fn wallet_box_to_entry(wb: ergo_state::wallet::types::WalletBox) -> WalletBoxEntry {
    WalletBoxEntry {
        box_id: hex::encode(wb.box_id),
        value: wb.value,
        creation_height: wb.creation_height,
        status: box_status_str(&wb.status),
        provenance: box_provenance_str(&wb.provenance),
    }
}

fn wallet_tx_to_entry(wt: ergo_state::wallet::types::WalletTransaction) -> WalletTransactionEntry {
    WalletTransactionEntry {
        tx_id: hex::encode(wt.tx_id),
        block_height: wt.block_height,
        block_id: hex::encode(wt.block_id),
        wallet_outputs: wt.wallet_outputs.iter().map(hex::encode).collect(),
        wallet_inputs: wt.wallet_inputs.iter().map(hex::encode).collect(),
        // Wallet rows carry no scan tagging; empty is omitted from the wire,
        // keeping the existing wallet listing shape unchanged.
        scan_ids: Vec::new(),
    }
}

fn paginate_boxes(all: Vec<ergo_state::wallet::types::WalletBox>, page: Page) -> WalletBoxesPage {
    let total = all.len() as u32;
    let offset = page.offset as usize;
    let limit = page.limit as usize;
    let items = all
        .into_iter()
        .skip(offset)
        .take(limit)
        .map(wallet_box_to_entry)
        .collect();
    WalletBoxesPage { total, items }
}

fn paginate_transactions(
    all: Vec<ergo_state::wallet::types::WalletTransaction>,
    page: Page,
) -> WalletTransactionsPage {
    let total = all.len() as u32;
    let offset = page.offset as usize;
    let limit = page.limit as usize;
    let items = all
        .into_iter()
        .skip(offset)
        .take(limit)
        .map(wallet_tx_to_entry)
        .collect();
    WalletTransactionsPage { total, items }
}

// ---- multi-sig dispatch helpers ----

/// Collect all `SigmaBoolean` propositions the registry can prove.
///
/// Builds the `generate_for` list from:
/// - All tracked DLog pubkeys (when the wallet is unlocked).
/// - All externally-supplied DLog and DHT secrets.
///
/// Used by `generate_commitments_impl` to tell `generate_commitments_for_tx`
/// which leaves to generate commitments for.
fn collect_generate_for(
    storage: &ergo_wallet::storage::SecretStorage,
    db: &redb::Database,
    externals: &[ergo_wallet::proving::external::ProverExternalSecret],
) -> Result<Vec<ergo_ser::sigma_value::SigmaBoolean>, WalletAdminError> {
    use ergo_primitives::group_element::GroupElement;
    use ergo_ser::sigma_value::SigmaBoolean;
    use ergo_wallet::proving::external::ProverExternalSecret;

    let mut generate_for: Vec<SigmaBoolean> = Vec::new();

    // Wallet-derived DLog keys (available when unlocked).
    if storage.unlocked().is_some() {
        let read_txn = db
            .begin_read()
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
        let wallet_reader = ergo_state::wallet::reader::WalletReader::new(&read_txn);
        let tracked: Vec<(u64, [u8; 33], Vec<u32>)> = wallet_reader
            .tracked_pubkeys_with_paths()
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
        for (_, pk, _) in tracked {
            generate_for.push(SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk)));
        }
    }

    // Externally-supplied secrets.
    for ext in externals {
        match ext {
            ProverExternalSecret::Dlog { pk, .. } => {
                generate_for.push(SigmaBoolean::ProveDlog(GroupElement::from_bytes(*pk)));
            }
            ProverExternalSecret::DhTuple { g, h, u, v, .. } => {
                generate_for.push(SigmaBoolean::ProveDHTuple {
                    g: GroupElement::from_bytes(*g),
                    h: GroupElement::from_bytes(*h),
                    u: GroupElement::from_bytes(*u),
                    v: GroupElement::from_bytes(*v),
                });
            }
        }
    }

    Ok(generate_for)
}

/// Parse a proposition string for `POST /wallet/extractHints`.
///
/// Accepts two forms:
/// - **Hex string** (66 hex chars = 33 bytes): `ProveDlog(GroupElement)`.
///   Kept for backwards compatibility with the original DLog-only REST API.
/// - **JSON object**: `{"g":"<hex>","h":"<hex>","u":"<hex>","v":"<hex>"}` →
///   `ProveDHTuple`. Detect by trying `serde_json::from_str` first; fall back
///   to hex-DLog parse on failure.
fn hex_pk_to_sigma_boolean(
    s: &str,
) -> Result<ergo_ser::sigma_value::SigmaBoolean, WalletAdminError> {
    use ergo_primitives::group_element::GroupElement;
    use ergo_ser::sigma_value::SigmaBoolean;

    // Try structured JSON form first (ProveDHTuple).
    let trimmed = s.trim();
    if trimmed.starts_with('{') {
        #[derive(serde::Deserialize)]
        struct DhtJson {
            g: String,
            h: String,
            u: String,
            v: String,
        }

        fn decode_ge_field(hex_str: &str, field: &str) -> Result<GroupElement, WalletAdminError> {
            let bytes: [u8; 33] = hex::decode(hex_str)
                .ok()
                .and_then(|v| v.try_into().ok())
                .ok_or_else(|| {
                    WalletAdminError::Internal(format!(
                        "extractHints: ProveDHTuple bad point hex for '{field}'"
                    ))
                })?;
            Ok(GroupElement::from_bytes(bytes))
        }

        let dto: DhtJson = serde_json::from_str(trimmed).map_err(|e| {
            WalletAdminError::Internal(format!("extractHints: JSON proposition parse failed: {e}"))
        })?;
        return Ok(SigmaBoolean::ProveDHTuple {
            g: decode_ge_field(&dto.g, "g")?,
            h: decode_ge_field(&dto.h, "h")?,
            u: decode_ge_field(&dto.u, "u")?,
            v: decode_ge_field(&dto.v, "v")?,
        });
    }

    // Fall back to hex-encoded 33-byte DLog pubkey.
    let bytes: [u8; 33] = hex::decode(trimmed)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| {
            WalletAdminError::Internal(format!(
                "extractHints: bad proposition (expected 33-byte hex pubkey or DHT JSON object): {s}"
            ))
        })?;
    Ok(SigmaBoolean::ProveDlog(GroupElement::from_bytes(bytes)))
}

/// Resolve input box IDs: use `override_ids` if supplied, else look up every
/// input in the unsigned transaction from the UTXO set via `chain`.
fn resolve_inputs_for_unsigned(
    unsigned_tx: &ergo_ser::transaction::UnsignedTransaction,
    override_ids: Option<&[String]>,
    chain: &dyn ChainStateAccessor,
    label: &str,
) -> Result<Vec<ergo_ser::ergo_box::ErgoBox>, WalletAdminError> {
    match override_ids {
        Some(ids) => ids
            .iter()
            .enumerate()
            .map(|(i, hex_id)| {
                let id: [u8; 32] = hex::decode(hex_id)
                    .ok()
                    .and_then(|v| v.try_into().ok())
                    .ok_or_else(|| {
                        WalletAdminError::Internal(format!("{label} override[{i}]: bad box id hex"))
                    })?;
                chain.lookup_utxo(&id).ok_or_else(|| {
                    WalletAdminError::Internal(format!(
                        "{label} override[{i}] box {} not in UTXO set",
                        hex_id
                    ))
                })
            })
            .collect(),
        None => unsigned_tx
            .inputs
            .iter()
            .enumerate()
            .map(|(i, ui)| {
                let box_id = ui.box_id.as_bytes();
                chain.lookup_utxo(box_id).ok_or_else(|| {
                    WalletAdminError::Internal(format!(
                        "{label}[{i}] box {} not in UTXO set",
                        hex::encode(box_id)
                    ))
                })
            })
            .collect(),
    }
}

/// Resolve data-input box IDs (same logic, from `unsigned_tx.data_inputs`).
fn resolve_data_inputs_for_unsigned(
    unsigned_tx: &ergo_ser::transaction::UnsignedTransaction,
    override_ids: Option<&[String]>,
    chain: &dyn ChainStateAccessor,
) -> Result<Vec<ergo_ser::ergo_box::ErgoBox>, WalletAdminError> {
    match override_ids {
        Some(ids) => ids
            .iter()
            .enumerate()
            .map(|(i, hex_id)| {
                let id: [u8; 32] = hex::decode(hex_id)
                    .ok()
                    .and_then(|v| v.try_into().ok())
                    .ok_or_else(|| {
                        WalletAdminError::Internal(format!(
                            "data_input override[{i}]: bad box id hex"
                        ))
                    })?;
                chain.lookup_utxo(&id).ok_or_else(|| {
                    WalletAdminError::Internal(format!(
                        "data_input override[{i}] box {} not in UTXO set",
                        hex_id
                    ))
                })
            })
            .collect(),
        None => unsigned_tx
            .data_inputs
            .iter()
            .enumerate()
            .map(|(i, di)| {
                let box_id = di.box_id.as_bytes();
                chain.lookup_utxo(box_id).ok_or_else(|| {
                    WalletAdminError::Internal(format!(
                        "data_input[{i}] box {} not in UTXO set",
                        hex::encode(box_id)
                    ))
                })
            })
            .collect(),
    }
}

/// Resolve input box IDs for a signed transaction.
fn resolve_inputs_for_signed(
    tx: &ergo_ser::transaction::Transaction,
    override_ids: Option<&[String]>,
    chain: &dyn ChainStateAccessor,
) -> Result<Vec<ergo_ser::ergo_box::ErgoBox>, WalletAdminError> {
    match override_ids {
        Some(ids) => ids
            .iter()
            .enumerate()
            .map(|(i, hex_id)| {
                let id: [u8; 32] = hex::decode(hex_id)
                    .ok()
                    .and_then(|v| v.try_into().ok())
                    .ok_or_else(|| {
                        WalletAdminError::Internal(format!("input override[{i}]: bad box id hex"))
                    })?;
                chain.lookup_utxo(&id).ok_or_else(|| {
                    WalletAdminError::Internal(format!(
                        "input override[{i}] box {} not in UTXO set",
                        hex_id
                    ))
                })
            })
            .collect(),
        None => tx
            .inputs
            .iter()
            .enumerate()
            .map(|(i, inp)| {
                let box_id = inp.box_id.as_bytes();
                chain.lookup_utxo(box_id).ok_or_else(|| {
                    WalletAdminError::Internal(format!(
                        "input[{i}] box {} not in UTXO set",
                        hex::encode(box_id)
                    ))
                })
            })
            .collect(),
    }
}

/// Resolve data-input boxes for a signed transaction.
fn resolve_data_inputs_for_signed(
    tx: &ergo_ser::transaction::Transaction,
    override_ids: Option<&[String]>,
    chain: &dyn ChainStateAccessor,
) -> Result<Vec<ergo_ser::ergo_box::ErgoBox>, WalletAdminError> {
    match override_ids {
        Some(ids) => ids
            .iter()
            .enumerate()
            .map(|(i, hex_id)| {
                let id: [u8; 32] = hex::decode(hex_id)
                    .ok()
                    .and_then(|v| v.try_into().ok())
                    .ok_or_else(|| {
                        WalletAdminError::Internal(format!(
                            "data_input override[{i}]: bad box id hex"
                        ))
                    })?;
                chain.lookup_utxo(&id).ok_or_else(|| {
                    WalletAdminError::Internal(format!(
                        "data_input override[{i}] box {} not in UTXO set",
                        hex_id
                    ))
                })
            })
            .collect(),
        None => tx
            .data_inputs
            .iter()
            .enumerate()
            .map(|(i, di)| {
                let box_id = di.box_id.as_bytes();
                chain.lookup_utxo(box_id).ok_or_else(|| {
                    WalletAdminError::Internal(format!(
                        "data_input[{i}] box {} not in UTXO set",
                        hex::encode(box_id)
                    ))
                })
            })
            .collect(),
    }
}

/// `POST /wallet/generateCommitments` writer-task implementation.
///
/// Decodes the unsigned tx, collects all propositions the wallet knows
/// secrets for (HD-derived + external), builds a signing context, and
/// calls `generate_commitments_for_tx`.
async fn generate_commitments_impl(
    request: &ergo_api::wallet::multi_sig::GenerateCommitmentsRequest,
    storage: &RwLock<ergo_wallet::storage::SecretStorage>,
    db: &redb::Database,
    chain: &dyn ChainStateAccessor,
) -> Result<ergo_api::wallet::multi_sig::GenerateCommitmentsResponse, WalletAdminError> {
    use ergo_api::wallet::multi_sig::GenerateCommitmentsResponse;

    let unsigned_tx_bytes = hex::decode(&request.unsigned_tx).map_err(|_| {
        WalletAdminError::Internal("generateCommitments: unsigned_tx bad hex".into())
    })?;
    let unsigned_tx = {
        let mut r = ergo_primitives::reader::VlqReader::new(&unsigned_tx_bytes);
        ergo_ser::transaction::read_unsigned_transaction(&mut r).map_err(|e| {
            WalletAdminError::Internal(format!("generateCommitments: unsigned_tx decode: {e:?}"))
        })?
    };

    let externals: Vec<ergo_wallet::proving::external::ProverExternalSecret> = request
        .external_secrets
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .map(decode_external_secret)
        .collect::<Result<_, _>>()?;

    let storage_guard = storage.read();
    let generate_for = collect_generate_for(&storage_guard, db, &externals)?;
    drop(storage_guard);

    let boxes_to_spend =
        resolve_inputs_for_unsigned(&unsigned_tx, request.inputs.as_deref(), chain, "input")?;
    let data_boxes =
        resolve_data_inputs_for_unsigned(&unsigned_tx, request.data_inputs.as_deref(), chain)?;

    let state_ctx = chain.build_signing_context()?;

    let mut rng = ergo_wallet::proving::randomness::OsRngBackend;
    let tbag = ergo_wallet::proving::commitments::generate_commitments_for_tx(
        &unsigned_tx,
        &boxes_to_spend,
        &data_boxes,
        &state_ctx,
        &generate_for,
        &mut rng,
    )
    .map_err(|e| WalletAdminError::Internal(format!("generateCommitments: {e}")))?;

    let hints_dto = tx_hints_bag_to_dto(&tbag);
    Ok(GenerateCommitmentsResponse { hints: hints_dto })
}

/// `POST /wallet/extractHints` writer-task implementation.
///
/// Decodes the signed tx, parses the `real` / `simulated` pubkey lists,
/// and calls `bag_for_transaction`.
async fn extract_hints_impl(
    request: &ergo_api::wallet::multi_sig::HintExtractionRequest,
    _storage: &RwLock<ergo_wallet::storage::SecretStorage>,
    chain: &dyn ChainStateAccessor,
) -> Result<ergo_api::wallet::multi_sig::HintExtractionResponse, WalletAdminError> {
    use ergo_api::wallet::multi_sig::HintExtractionResponse;

    let tx_bytes = hex::decode(&request.tx)
        .map_err(|_| WalletAdminError::Internal("extractHints: tx bad hex".into()))?;
    let tx = {
        let mut r = ergo_primitives::reader::VlqReader::new(&tx_bytes);
        ergo_ser::transaction::read_transaction(&mut r)
            .map_err(|e| WalletAdminError::Internal(format!("extractHints: tx decode: {e:?}")))?
    };

    let real: Vec<ergo_ser::sigma_value::SigmaBoolean> = request
        .real
        .iter()
        .map(|s| hex_pk_to_sigma_boolean(s))
        .collect::<Result<_, _>>()?;

    let simulated: Vec<ergo_ser::sigma_value::SigmaBoolean> = request
        .simulated
        .iter()
        .map(|s| hex_pk_to_sigma_boolean(s))
        .collect::<Result<_, _>>()?;

    let boxes_to_spend = resolve_inputs_for_signed(&tx, request.inputs.as_deref(), chain)?;
    let data_boxes = resolve_data_inputs_for_signed(&tx, request.data_inputs.as_deref(), chain)?;

    let state_ctx = chain.build_signing_context()?;

    let tbag = ergo_wallet::proving::extract::bag_for_transaction(
        &tx,
        &boxes_to_spend,
        &data_boxes,
        &state_ctx,
        &real,
        &simulated,
    )
    .map_err(|e| WalletAdminError::Internal(format!("extractHints: {e}")))?;

    let hints_dto = tx_hints_bag_to_dto(&tbag);
    Ok(HintExtractionResponse { hints: hints_dto })
}

// ---- TransactionHintsBag ↔ TxHintsBagDto converters ----
//
// These live here (not in ergo-api) because ergo-api has no ergo-wallet dep.
// The ergo-api layer uses the opaque `SigmaBooleanJson` for the `image` field;
// here we convert to/from the canonical JSON shape used by Scala/sigma-rust:
//   ProveDlog  → { "type": "proveDlog", "h": "<33-byte-hex>" }
//   ProveDHTuple → { "type": "proveDhTuple", "g": "...", "h": "...", "u": "...", "v": "..." }
//   Other      → { "type": "other" }
//
// For `from_dto`, the `image` field is only used to reconstruct the `SigmaBoolean`
// for hint matching inside the prover; we parse it from the tagged JSON object.

/// Serialize a `SigmaBoolean` to the `SigmaBooleanJson` wire shape.
fn sigma_boolean_to_json(
    sb: &ergo_ser::sigma_value::SigmaBoolean,
) -> ergo_api::wallet::sending::SigmaBooleanJson {
    use ergo_api::wallet::sending::SigmaBooleanJson;
    use ergo_ser::sigma_value::SigmaBoolean;
    use serde_json::{json, Value};

    let inner: Value = match sb {
        SigmaBoolean::ProveDlog(ge) => json!({
            "type": "proveDlog",
            "h": hex::encode(ge.as_bytes()),
        }),
        SigmaBoolean::ProveDHTuple { g, h, u, v } => json!({
            "type": "proveDhTuple",
            "g": hex::encode(g.as_bytes()),
            "h": hex::encode(h.as_bytes()),
            "u": hex::encode(u.as_bytes()),
            "v": hex::encode(v.as_bytes()),
        }),
        SigmaBoolean::TrivialProp(b) => json!({ "type": "trivialProp", "condition": b }),
        SigmaBoolean::Cand(children) => json!({
            "type": "cand",
            "args": children.iter().map(|c| sigma_boolean_to_json(c).inner).collect::<Vec<_>>(),
        }),
        SigmaBoolean::Cor(children) => json!({
            "type": "cor",
            "args": children.iter().map(|c| sigma_boolean_to_json(c).inner).collect::<Vec<_>>(),
        }),
        SigmaBoolean::Cthreshold { k, children } => json!({
            "type": "cthreshold",
            "k": k,
            "args": children.iter().map(|c| sigma_boolean_to_json(c).inner).collect::<Vec<_>>(),
        }),
    };
    SigmaBooleanJson { inner }
}

/// Parse a `SigmaBooleanJson` back to a `SigmaBoolean`.
/// Returns `Err` for unrecognised shapes.
fn sigma_boolean_from_json(
    json: &ergo_api::wallet::sending::SigmaBooleanJson,
) -> Result<ergo_ser::sigma_value::SigmaBoolean, WalletAdminError> {
    use ergo_primitives::group_element::GroupElement;
    use ergo_ser::sigma_value::SigmaBoolean;

    let obj = json.inner.as_object().ok_or_else(|| {
        WalletAdminError::Internal("SigmaBooleanJson: expected JSON object".into())
    })?;
    let typ = obj
        .get("type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| WalletAdminError::Internal("SigmaBooleanJson: missing 'type'".into()))?;

    fn decode_ge(
        obj: &serde_json::Map<String, serde_json::Value>,
        field: &str,
    ) -> Result<GroupElement, WalletAdminError> {
        let hex_str = obj.get(field).and_then(|v| v.as_str()).ok_or_else(|| {
            WalletAdminError::Internal(format!("SigmaBooleanJson: missing '{field}'"))
        })?;
        let bytes: [u8; 33] = hex::decode(hex_str)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| {
                WalletAdminError::Internal(format!("SigmaBooleanJson: bad point hex for '{field}'"))
            })?;
        Ok(GroupElement::from_bytes(bytes))
    }

    match typ {
        "proveDlog" => Ok(SigmaBoolean::ProveDlog(decode_ge(obj, "h")?)),
        "proveDhTuple" => Ok(SigmaBoolean::ProveDHTuple {
            g: decode_ge(obj, "g")?,
            h: decode_ge(obj, "h")?,
            u: decode_ge(obj, "u")?,
            v: decode_ge(obj, "v")?,
        }),
        other => Err(WalletAdminError::Internal(format!(
            "SigmaBooleanJson: unknown type '{other}'"
        ))),
    }
}

/// Serialize a `FirstProverMessage` to its `FirstProverMessageJson` wire shape.
fn fpm_to_json(
    fpm: &ergo_wallet::proving::hints::FirstProverMessage,
) -> ergo_api::wallet::sending::FirstProverMessageJson {
    use ergo_api::wallet::sending::FirstProverMessageJson;
    use ergo_wallet::proving::hints::FirstProverMessage;

    match fpm {
        FirstProverMessage::Schnorr(a) => FirstProverMessageJson::Dlog { a: hex::encode(a) },
        FirstProverMessage::DhTuple { a, b } => FirstProverMessageJson::DhTuple {
            a: hex::encode(a),
            b: hex::encode(b),
        },
    }
}

/// Parse a `FirstProverMessageJson` back to `FirstProverMessage`.
fn fpm_from_json(
    json: &ergo_api::wallet::sending::FirstProverMessageJson,
) -> Result<ergo_wallet::proving::hints::FirstProverMessage, WalletAdminError> {
    use ergo_api::wallet::sending::FirstProverMessageJson;
    use ergo_wallet::proving::hints::FirstProverMessage;

    fn decode_pt(hex_str: &str, label: &str) -> Result<[u8; 33], WalletAdminError> {
        hex::decode(hex_str)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| {
                WalletAdminError::Internal(format!(
                    "FirstProverMessageJson: bad point hex for '{label}'"
                ))
            })
    }

    match json {
        FirstProverMessageJson::Dlog { a } => Ok(FirstProverMessage::Schnorr(decode_pt(a, "a")?)),
        FirstProverMessageJson::DhTuple { a, b } => Ok(FirstProverMessage::DhTuple {
            a: decode_pt(a, "a")?,
            b: decode_pt(b, "b")?,
        }),
    }
}

/// Convert a `TransactionHintsBag` to its `TxHintsBagDto` wire representation.
///
/// Partitions each per-input bag into (secret, public) using the same
/// semantics as `HintsBag::partition`: `OwnCommitment` goes into
/// `secret_hints`, everything else into `public_hints`.
fn tx_hints_bag_to_dto(
    bag: &ergo_wallet::proving::hints::TransactionHintsBag,
) -> ergo_api::wallet::sending::TxHintsBagDto {
    use ergo_api::wallet::sending::node_position_to_str;
    use ergo_api::wallet::sending::{HintDto, TxHintsBagDto};
    use ergo_wallet::proving::hints::Hint;
    use std::collections::BTreeMap;

    fn hint_to_dto(hint: &Hint) -> HintDto {
        match hint {
            Hint::OwnCommitment(oc) => HintDto::OwnCommitment {
                image: sigma_boolean_to_json(&oc.image),
                secret: hex::encode(oc.secret_randomness),
                commitment: fpm_to_json(&oc.commitment),
                position: node_position_to_str(&oc.position.positions),
            },
            Hint::RealCommitment(rc) => HintDto::RealCommitment {
                image: sigma_boolean_to_json(&rc.image),
                commitment: fpm_to_json(&rc.commitment),
                position: node_position_to_str(&rc.position.positions),
            },
            Hint::SimulatedCommitment(sc) => HintDto::SimulatedCommitment {
                image: sigma_boolean_to_json(&sc.image),
                commitment: fpm_to_json(&sc.commitment),
                challenge: hex::encode(sc.challenge),
                position: node_position_to_str(&sc.position.positions),
            },
            Hint::RealSecretProof(rsp) => HintDto::RealSecretProof {
                image: sigma_boolean_to_json(&rsp.image),
                challenge: hex::encode(rsp.challenge),
                response: hex::encode(rsp.response),
                position: node_position_to_str(&rsp.position.positions),
            },
            Hint::SimulatedSecretProof(ssp) => HintDto::SimulatedSecretProof {
                image: sigma_boolean_to_json(&ssp.image),
                challenge: hex::encode(ssp.challenge),
                response: hex::encode(ssp.response),
                position: node_position_to_str(&ssp.position.positions),
            },
        }
    }

    let mut secret_hints: BTreeMap<String, Vec<HintDto>> = BTreeMap::new();
    let mut public_hints: BTreeMap<String, Vec<HintDto>> = BTreeMap::new();

    // secret_hints from the bag's secret_hints map.
    for (idx, hints_bag) in &bag.secret_hints {
        let dtos: Vec<HintDto> = hints_bag.hints.iter().map(hint_to_dto).collect();
        if !dtos.is_empty() {
            secret_hints.insert(idx.to_string(), dtos);
        }
    }

    // public_hints from the bag's public_hints map.
    for (idx, hints_bag) in &bag.public_hints {
        let dtos: Vec<HintDto> = hints_bag.hints.iter().map(hint_to_dto).collect();
        if !dtos.is_empty() {
            public_hints.insert(idx.to_string(), dtos);
        }
    }

    TxHintsBagDto {
        secret_hints,
        public_hints,
    }
}

/// Convert a `TxHintsBagDto` back to a `TransactionHintsBag`.
///
/// Called by `transaction_sign_impl` to thread operator-supplied hints into
/// the prover. The `image` field is parsed so the prover can match hints
/// by proposition at sign time.
fn tx_hints_bag_from_dto(
    dto: &ergo_api::wallet::sending::TxHintsBagDto,
) -> Result<ergo_wallet::proving::hints::TransactionHintsBag, WalletAdminError> {
    use ergo_api::wallet::sending::{node_position_from_str, HintDto};
    use ergo_wallet::proving::hints::{
        Hint, HintsBag, OwnCommitment, RealCommitment, RealSecretProof, SimulatedCommitment,
        SimulatedSecretProof, TransactionHintsBag,
    };
    use ergo_wallet::proving::node_position::NodePosition;

    fn parse_challenge(hex_str: &str) -> Result<[u8; 24], WalletAdminError> {
        hex::decode(hex_str)
            .ok()
            .and_then(|v| v.try_into().ok())
            // Public value (Fiat-Shamir challenge), but report length only —
            // error strings reach the node log via the API boundary, and
            // echoing arbitrary caller hex there is needless noise.
            .ok_or_else(|| {
                WalletAdminError::Internal(format!(
                    "hint challenge: invalid hex (expected 48 hex chars / 24 bytes, got {} chars)",
                    hex_str.len()
                ))
            })
    }

    fn parse_response(hex_str: &str) -> Result<[u8; 32], WalletAdminError> {
        hex::decode(hex_str)
            .ok()
            .and_then(|v| v.try_into().ok())
            // Public value (Schnorr response z), but report length only for
            // the same log-hygiene reason as `parse_challenge`.
            .ok_or_else(|| {
                WalletAdminError::Internal(format!(
                    "hint response: invalid hex (expected 64 hex chars / 32 bytes, got {} chars)",
                    hex_str.len()
                ))
            })
    }

    fn parse_secret(hex_str: &str) -> Result<[u8; 32], WalletAdminError> {
        hex::decode(hex_str)
            .ok()
            .and_then(|v| v.try_into().ok())
            // Never interpolate the value — this is the OwnCommitment secret
            // randomness. Report only the structural fault.
            .ok_or_else(|| {
                WalletAdminError::Internal(format!(
                    "hint secret: invalid hex (expected 64 hex chars / 32 bytes, got {} chars)",
                    hex_str.len()
                ))
            })
    }

    fn dto_to_hint(h: &HintDto) -> Result<Hint, WalletAdminError> {
        match h {
            HintDto::OwnCommitment {
                image,
                secret,
                commitment,
                position,
            } => {
                let sb = sigma_boolean_from_json(image)?;
                let pos = NodePosition {
                    positions: node_position_from_str(position)
                        .map_err(|e| WalletAdminError::Internal(format!("bad position: {e}")))?,
                };
                Ok(Hint::OwnCommitment(OwnCommitment {
                    image: sb,
                    secret_randomness: parse_secret(secret)?,
                    commitment: fpm_from_json(commitment)?,
                    position: pos,
                }))
            }
            HintDto::RealCommitment {
                image,
                commitment,
                position,
            } => {
                let sb = sigma_boolean_from_json(image)?;
                let pos = NodePosition {
                    positions: node_position_from_str(position)
                        .map_err(|e| WalletAdminError::Internal(format!("bad position: {e}")))?,
                };
                Ok(Hint::RealCommitment(RealCommitment {
                    image: sb,
                    commitment: fpm_from_json(commitment)?,
                    position: pos,
                }))
            }
            HintDto::SimulatedCommitment {
                image,
                commitment,
                challenge,
                position,
            } => {
                let sb = sigma_boolean_from_json(image)?;
                let pos = NodePosition {
                    positions: node_position_from_str(position)
                        .map_err(|e| WalletAdminError::Internal(format!("bad position: {e}")))?,
                };
                Ok(Hint::SimulatedCommitment(SimulatedCommitment {
                    image: sb,
                    commitment: fpm_from_json(commitment)?,
                    challenge: parse_challenge(challenge)?,
                    position: pos,
                }))
            }
            HintDto::RealSecretProof {
                image,
                challenge,
                response,
                position,
            } => {
                let sb = sigma_boolean_from_json(image)?;
                let pos = NodePosition {
                    positions: node_position_from_str(position)
                        .map_err(|e| WalletAdminError::Internal(format!("bad position: {e}")))?,
                };
                Ok(Hint::RealSecretProof(RealSecretProof {
                    image: sb,
                    challenge: parse_challenge(challenge)?,
                    response: parse_response(response)?,
                    position: pos,
                }))
            }
            HintDto::SimulatedSecretProof {
                image,
                challenge,
                response,
                position,
            } => {
                let sb = sigma_boolean_from_json(image)?;
                let pos = NodePosition {
                    positions: node_position_from_str(position)
                        .map_err(|e| WalletAdminError::Internal(format!("bad position: {e}")))?,
                };
                Ok(Hint::SimulatedSecretProof(SimulatedSecretProof {
                    image: sb,
                    challenge: parse_challenge(challenge)?,
                    response: parse_response(response)?,
                    position: pos,
                }))
            }
        }
    }

    let mut tbag = TransactionHintsBag::empty();

    // Secret hints (OwnCommitment) → secret_hints in TransactionHintsBag.
    for (idx_str, hints_list) in &dto.secret_hints {
        let idx: u32 = idx_str
            .parse()
            .map_err(|_| WalletAdminError::Internal(format!("bad input index: {idx_str}")))?;
        let mut bag = HintsBag::empty();
        for h in hints_list {
            bag.add(dto_to_hint(h)?);
        }
        // Use add_for_input (preserves existing) — mirrors Scala addHintsForInput.
        tbag.add_for_input(idx, bag);
    }

    // Public hints → public_hints in TransactionHintsBag.
    for (idx_str, hints_list) in &dto.public_hints {
        let idx: u32 = idx_str
            .parse()
            .map_err(|_| WalletAdminError::Internal(format!("bad input index: {idx_str}")))?;
        let mut bag = HintsBag::empty();
        for h in hints_list {
            bag.add(dto_to_hint(h)?);
        }
        tbag.add_for_input(idx, bag);
    }

    Ok(tbag)
}

// ---- derive-key + get-private-key helpers ----

/// Render a BIP32 path (raw u32 component slice) as a `m/...` string.
/// Mirrors `DerivationPath::Display` without constructing the struct.
fn render_derivation_path(components: &[u32]) -> String {
    use ergo_wallet::derivation::HARDENED_OFFSET;
    if components.is_empty() {
        return "m/".to_string();
    }
    let mut s = "m".to_string();
    for &c in components {
        if c >= HARDENED_OFFSET {
            s.push('/');
            s.push_str(&(c - HARDENED_OFFSET).to_string());
            s.push('\'');
        } else {
            s.push('/');
            s.push_str(&c.to_string());
        }
    }
    s
}

/// Shared write path: persist a new tracked pubkey + rebuild WALLET_VISIBLE_ADDRESSES.
///
/// The write is atomic (single redb write transaction). Returns the new
/// `derivation_path_index` used for the entry.
///
/// WALLET_VISIBLE_ADDRESSES is rebuilt from scratch from all tracked pubkeys
/// except the hidden master (path_idx == 0, derivation_path == []).
/// Matches `wallet_boot.rs` and spec §7.3 step 4.
fn persist_tracked_pubkey(
    db: &redb::Database,
    path_idx: u64,
    pubkey: &[u8; 33],
    meta: &ergo_state::wallet::types::TrackedPubkeyMeta,
) -> Result<(), WalletAdminError> {
    use ergo_state::wallet::tables::{
        tracked_pubkey_key, WALLET_TRACKED_PUBKEYS, WALLET_VISIBLE_ADDRESSES,
    };
    use redb::ReadableTable;

    let meta_bytes = bincode::serialize(meta)
        .map_err(|e| WalletAdminError::Internal(format!("bincode TrackedPubkeyMeta: {e}")))?;

    let write_txn = db
        .begin_write()
        .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
    {
        // Insert the new tracked pubkey.
        let mut tracked = write_txn
            .open_table(WALLET_TRACKED_PUBKEYS)
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
        tracked
            .insert(tracked_pubkey_key(path_idx, pubkey), meta_bytes)
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?;

        // Rebuild WALLET_VISIBLE_ADDRESSES from all tracked entries (skip
        // hidden master: path_idx 0 with empty derivation_path).
        // We clear first, then reinsert all visible entries. The table is
        // small (typically < 1000 keys), so a full rebuild is safe.
        let all_tracked: Vec<(u64, [u8; 33], Vec<u32>)> = {
            let mut rows = Vec::new();
            for entry in tracked
                .iter()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?
            {
                let (k, v) = entry.map_err(|e| WalletAdminError::Internal(e.to_string()))?;
                let key_bytes: [u8; 41] = k.value();
                let (idx, pk) = ergo_state::wallet::tables::parse_tracked_pubkey_key(&key_bytes);
                let row_meta: ergo_state::wallet::types::TrackedPubkeyMeta =
                    bincode::deserialize(v.value().as_slice()).map_err(|e| {
                        WalletAdminError::Internal(format!("bincode TrackedPubkeyMeta read: {e}"))
                    })?;
                rows.push((idx, pk, row_meta.derivation_path));
            }
            rows
        };

        let mut visible = write_txn
            .open_table(WALLET_VISIBLE_ADDRESSES)
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?;

        // Clear all existing visible entries.
        let existing_keys: Vec<u32> = visible
            .iter()
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?
            .map(|entry| entry.map(|(k, _)| k.value()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e: redb::StorageError| WalletAdminError::Internal(e.to_string()))?;
        for key in existing_keys {
            visible
                .remove(key)
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
        }

        // Reinsert all visible (non-hidden-master) entries.
        // Hidden master: path_idx == 0 with empty derivation_path (matches boot logic).
        let mut visible_idx = 0u32;
        for (idx, pk, path) in &all_tracked {
            let is_hidden_master = *idx == 0 && path.is_empty();
            if !is_hidden_master {
                visible
                    .insert(visible_idx, *pk)
                    .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
                visible_idx += 1;
            }
        }
    }
    write_txn
        .commit()
        .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
    Ok(())
}

/// `POST /wallet/deriveKey` writer-task implementation.
async fn derive_key_impl(
    request: &ergo_api::wallet::admin_advanced::DeriveKeyRequest,
    storage: &RwLock<ergo_wallet::storage::SecretStorage>,
    state: &RwLock<ergo_wallet::state::WalletState>,
    db: &redb::Database,
    chain: &dyn ChainStateAccessor,
    network: ergo_ser::address::NetworkPrefix,
) -> Result<ergo_api::wallet::admin_advanced::DeriveKeyResponse, WalletAdminError> {
    use ergo_api::wallet::admin_advanced::DeriveKeyResponse;
    use ergo_wallet::derivation::DerivationPath;

    // Require unlocked.
    let storage_guard = storage.read();
    let unlocked = storage_guard.unlocked().ok_or(WalletAdminError::Locked)?;

    // Parse the requested path.
    let path: DerivationPath =
        request
            .derivation_path
            .parse()
            .map_err(|e: ergo_wallet::error::WalletError| {
                WalletAdminError::Internal(format!("deriveKey: invalid path: {e}"))
            })?;

    // Dedup: compare against every existing tracked path via tracked_pubkeys_with_paths.
    let read_txn = db
        .begin_read()
        .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
    let wallet_reader = ergo_state::wallet::reader::WalletReader::new(&read_txn);
    let existing: Vec<(u64, [u8; 33], Vec<u32>)> = wallet_reader
        .tracked_pubkeys_with_paths()
        .map_err(|e| WalletAdminError::Internal(e.to_string()))?;

    // Path-component comparison.
    for (_, _, existing_path) in &existing {
        if existing_path.as_slice() == path.components() {
            return Err(WalletAdminError::Internal(format!(
                "derivation: path already tracked: {}",
                path
            )));
        }
    }

    // Compute next derivation_path_index = max existing + 1.
    let next_idx = existing
        .iter()
        .map(|(idx, _, _)| *idx)
        .max()
        .map(|m| m + 1)
        .unwrap_or(0);

    // Derive the pubkey.
    let pubkey = unlocked
        .master
        .derive_pubkey_at_path(&path)
        .map_err(|e| WalletAdminError::Internal(format!("deriveKey: derivation failed: {e}")))?;

    drop(read_txn);

    // Build metadata.
    let meta = ergo_state::wallet::types::TrackedPubkeyMeta {
        derivation_path: path.components().to_vec(),
        derivation_path_label: String::new(),
        added_at_height: chain.tip_height(),
    };

    // Persist atomically (WALLET_TRACKED_PUBKEYS + WALLET_VISIBLE_ADDRESSES).
    persist_tracked_pubkey(db, next_idx, &pubkey, &meta)?;
    drop(storage_guard);

    // Update in-memory WalletState.
    {
        let mut s = state.write();
        s.insert_tracked_pubkey(next_idx, pubkey, network)
            .map_err(|e| WalletAdminError::Internal(format!("deriveKey: state update: {e}")))?;
    }

    // Encode to address string.
    let address = ergo_wallet::address::pubkey_to_p2pk_address(&pubkey, network)
        .map_err(|e| WalletAdminError::Internal(format!("deriveKey: address encode: {e}")))?;

    Ok(DeriveKeyResponse { address })
}

/// `GET /wallet/deriveNextKey` writer-task implementation.
async fn derive_next_key_impl(
    storage: &RwLock<ergo_wallet::storage::SecretStorage>,
    state: &RwLock<ergo_wallet::state::WalletState>,
    db: &redb::Database,
    chain: &dyn ChainStateAccessor,
    network: ergo_ser::address::NetworkPrefix,
) -> Result<ergo_api::wallet::admin_advanced::DeriveNextKeyResponse, WalletAdminError> {
    use ergo_api::wallet::admin_advanced::DeriveNextKeyResponse;
    use ergo_state::wallet::tables::WALLET_DERIVATION_HEAD;
    use ergo_wallet::derivation::{DerivationPath, HARDENED_OFFSET};

    // Require unlocked.
    let storage_guard = storage.read();
    let unlocked = storage_guard.unlocked().ok_or(WalletAdminError::Locked)?;

    // Read WALLET_DERIVATION_HEAD singleton (default 0 if missing).
    let head: u64 = {
        let read_txn = db
            .begin_read()
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
        match read_txn.open_table(WALLET_DERIVATION_HEAD) {
            Ok(tbl) => tbl
                .get(())
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?
                .map(|g| g.value())
                .unwrap_or(0),
            Err(redb::TableError::TableDoesNotExist(_)) => 0,
            Err(e) => return Err(WalletAdminError::Internal(e.to_string())),
        }
    };

    let new_head = head + 1;

    // Build path: m/44'/429'/0'/0/{new_head}
    // new_head is the non-hardened address index (sequential counter).
    let path_components = vec![
        HARDENED_OFFSET | 44,
        HARDENED_OFFSET | 429,
        HARDENED_OFFSET,
        0u32,
        new_head as u32,
    ];
    let path = DerivationPath::from_components(path_components.clone());
    let path_str = render_derivation_path(&path_components);

    // Dedup check (same as derive_key).
    let read_txn = db
        .begin_read()
        .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
    let wallet_reader = ergo_state::wallet::reader::WalletReader::new(&read_txn);
    let existing: Vec<(u64, [u8; 33], Vec<u32>)> = wallet_reader
        .tracked_pubkeys_with_paths()
        .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
    for (_, _, existing_path) in &existing {
        if existing_path.as_slice() == path.components() {
            return Err(WalletAdminError::Internal(format!(
                "derivation: path already tracked: {path_str}"
            )));
        }
    }

    let next_idx = existing
        .iter()
        .map(|(idx, _, _)| *idx)
        .max()
        .map(|m| m + 1)
        .unwrap_or(0);

    // Derive the pubkey.
    let pubkey = unlocked.master.derive_pubkey_at_path(&path).map_err(|e| {
        WalletAdminError::Internal(format!("deriveNextKey: derivation failed: {e}"))
    })?;

    drop(read_txn);

    let meta = ergo_state::wallet::types::TrackedPubkeyMeta {
        derivation_path: path.components().to_vec(),
        derivation_path_label: String::new(),
        added_at_height: chain.tip_height(),
    };

    // Persist WALLET_TRACKED_PUBKEYS + WALLET_VISIBLE_ADDRESSES + WALLET_DERIVATION_HEAD atomically.
    {
        use ergo_state::wallet::tables::{
            tracked_pubkey_key, WALLET_TRACKED_PUBKEYS, WALLET_VISIBLE_ADDRESSES,
        };
        use redb::ReadableTable;

        let meta_bytes = bincode::serialize(&meta)
            .map_err(|e| WalletAdminError::Internal(format!("bincode TrackedPubkeyMeta: {e}")))?;

        let write_txn = db
            .begin_write()
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
        {
            let mut tracked = write_txn
                .open_table(WALLET_TRACKED_PUBKEYS)
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
            tracked
                .insert(tracked_pubkey_key(next_idx, &pubkey), meta_bytes)
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?;

            // Rebuild WALLET_VISIBLE_ADDRESSES.
            let all_tracked: Vec<(u64, [u8; 33], Vec<u32>)> = {
                let mut rows = Vec::new();
                for entry in tracked
                    .iter()
                    .map_err(|e| WalletAdminError::Internal(e.to_string()))?
                {
                    let (k, v) = entry.map_err(|e| WalletAdminError::Internal(e.to_string()))?;
                    let key_bytes: [u8; 41] = k.value();
                    let (idx, pk) =
                        ergo_state::wallet::tables::parse_tracked_pubkey_key(&key_bytes);
                    let row_meta: ergo_state::wallet::types::TrackedPubkeyMeta =
                        bincode::deserialize(v.value().as_slice()).map_err(|e| {
                            WalletAdminError::Internal(format!(
                                "bincode TrackedPubkeyMeta read: {e}"
                            ))
                        })?;
                    rows.push((idx, pk, row_meta.derivation_path));
                }
                rows
            };

            let mut visible = write_txn
                .open_table(WALLET_VISIBLE_ADDRESSES)
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
            let existing_keys: Vec<u32> = visible
                .iter()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?
                .map(|entry| entry.map(|(k, _)| k.value()))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e: redb::StorageError| WalletAdminError::Internal(e.to_string()))?;
            for key in existing_keys {
                visible
                    .remove(key)
                    .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
            }
            let mut visible_idx = 0u32;
            for (idx, pk, path) in &all_tracked {
                let is_hidden_master = *idx == 0 && path.is_empty();
                if !is_hidden_master {
                    visible
                        .insert(visible_idx, *pk)
                        .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
                    visible_idx += 1;
                }
            }

            // Update WALLET_DERIVATION_HEAD to new_head.
            let mut head_tbl = write_txn
                .open_table(WALLET_DERIVATION_HEAD)
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
            head_tbl
                .insert((), new_head)
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
        }
        write_txn
            .commit()
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
    }
    drop(storage_guard);

    // Update in-memory WalletState.
    {
        let mut s = state.write();
        s.insert_tracked_pubkey(next_idx, pubkey, network)
            .map_err(|e| WalletAdminError::Internal(format!("deriveNextKey: state update: {e}")))?;
    }

    let address = ergo_wallet::address::pubkey_to_p2pk_address(&pubkey, network)
        .map_err(|e| WalletAdminError::Internal(format!("deriveNextKey: address encode: {e}")))?;

    Ok(DeriveNextKeyResponse {
        derivation_path: path_str,
        address,
    })
}

/// `POST /wallet/getPrivateKey` writer-task implementation.
///
/// Operator-flag gated by `cfg.expose_private_keys` (resolved from
/// `[wallet] expose_private_keys` at config-load): when `false`,
/// returns `Forbidden` immediately; when `true`, derives the scalar
/// for the requested address and returns it as 32-byte big-endian
/// hex.
async fn get_private_key_impl(
    request: &ergo_api::wallet::admin_advanced::GetPrivateKeyRequest,
    storage: &RwLock<ergo_wallet::storage::SecretStorage>,
    db: &redb::Database,
    cfg: &WriterConfig,
) -> Result<ergo_api::wallet::admin_advanced::GetPrivateKeyResponse, WalletAdminError> {
    use ergo_api::wallet::admin_advanced::GetPrivateKeyResponse;
    use ergo_wallet::derivation::DerivationPath;

    if !cfg.expose_private_keys {
        return Err(WalletAdminError::Forbidden(
            "getPrivateKey disabled — set [wallet] expose_private_keys = true in config".into(),
        ));
    }

    // Require unlocked.
    let storage_guard = storage.read();
    let unlocked = storage_guard.unlocked().ok_or(WalletAdminError::Locked)?;

    // Decode address → pubkey.
    let pubkey =
        ergo_ser::address::decode_p2pk_address(&request.address, cfg.network).map_err(|e| {
            WalletAdminError::BadRequest(format!("bad address {}: {e}", request.address))
        })?;

    // Look up derivation path for this pubkey in WALLET_TRACKED_PUBKEYS.
    let read_txn = db
        .begin_read()
        .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
    let wallet_reader = ergo_state::wallet::reader::WalletReader::new(&read_txn);
    let tracked = wallet_reader
        .tracked_pubkeys_with_paths()
        .map_err(|e| WalletAdminError::Internal(e.to_string()))?;

    let path_components = tracked
        .into_iter()
        .find(|(_, pk, _)| pk == &pubkey)
        .map(|(_, _, path)| path)
        .ok_or_else(|| {
            WalletAdminError::Internal(format!(
                "getPrivateKey: address {} not in tracked keys",
                request.address
            ))
        })?;

    let path = DerivationPath::from_components(path_components);

    // Derive the scalar.
    let scalar = unlocked.master.derive_scalar_at_path(&path).map_err(|e| {
        WalletAdminError::Internal(format!("getPrivateKey: derivation failed: {e}"))
    })?;

    // Encode as 32-byte big-endian hex.
    let scalar_bytes: [u8; 32] = scalar.to_bytes().into();
    let w = hex::encode(scalar_bytes);

    Ok(GetPrivateKeyResponse { w })
}
