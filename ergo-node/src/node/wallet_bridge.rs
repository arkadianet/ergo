//! Production WalletAdmin bridge. Single-writer pattern: the action
//! loop in ergo-node owns the wallet storage + state behind a RwLock.
//! The axum API task sends commands via a channel; the loop processes
//! them serially and sends the responses back via the per-command
//! oneshot channel.

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
    Page, WalletAddressList, WalletBalances, WalletBoxesPage, WalletStatus, WalletTransactionEntry,
    WalletTransactionsPage,
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
    /// Submit signed tx bytes; returns the tx id on admission. The error is the
    /// **typed** [`ergo_api::types::SubmitError`] `{reason, detail}` — NOT collapsed
    /// to a string — so callers can distinguish a `duplicate` admission (map to an
    /// idempotent success) from a real failure (map to 5xx) at their own boundary.
    /// The native send path maps `duplicate` → `200 accepted`; the existing
    /// compat callers map it to `WalletAdminError::Internal` exactly as before.
    async fn submit_transaction(
        &self,
        tx_bytes: Vec<u8>,
    ) -> Result<String, ergo_api::types::SubmitError>;
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
    async fn submit_transaction(
        &self,
        tx_bytes: Vec<u8>,
    ) -> Result<String, ergo_api::types::SubmitError> {
        use ergo_api::types::SubmitMode;
        // Forward the typed SubmitError unmodified — each caller maps it intentionally.
        self.inner
            .submit_transaction(tx_bytes, SubmitMode::Broadcast)
            .await
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
    /// Native `/api/v1/wallet/balance` — EIP-27-aware breakdown.
    NativeBalance {
        include_unconfirmed: bool,
        reply: oneshot::Sender<
            Result<ergo_api::wallet::native::dto::WalletBalanceDto, WalletAdminError>,
        >,
    },
    /// Native `/api/v1/wallet/status`.
    NativeStatus {
        reply: oneshot::Sender<
            Result<ergo_api::wallet::native::dto::WalletStatusDto, WalletAdminError>,
        >,
    },
    /// Native `/api/v1/wallet/addresses` (paged).
    NativeAddresses {
        offset: u32,
        limit: u32,
        reply:
            oneshot::Sender<Result<ergo_api::wallet::native::dto::AddressPage, WalletAdminError>>,
    },
    /// Native `/api/v1/wallet/boxes` (paged).
    NativeBoxes {
        offset: u32,
        limit: u32,
        reply: oneshot::Sender<Result<ergo_api::wallet::native::dto::BoxPage, WalletAdminError>>,
    },
    /// Native `/api/v1/wallet/boxes/{boxId}`.
    NativeBoxById {
        box_id_hex: String,
        reply: oneshot::Sender<
            Result<Option<ergo_api::wallet::native::dto::WalletBoxSummary>, WalletAdminError>,
        >,
    },
    /// Native `/api/v1/wallet/transactions` (paged).
    NativeTransactions {
        offset: u32,
        limit: u32,
        reply: oneshot::Sender<Result<ergo_api::wallet::native::dto::TxPage, WalletAdminError>>,
    },
    /// Native `/api/v1/wallet/transactions/{txId}`.
    NativeTransactionById {
        tx_id_hex: String,
        reply: oneshot::Sender<
            Result<
                Option<ergo_api::wallet::native::dto::WalletTransactionSummary>,
                WalletAdminError,
            >,
        >,
    },
    /// Native `/api/v1/wallet/boxes/select` (burn-aware selection dry-run).
    NativeSelectBoxes {
        req: Box<ergo_api::wallet::native::dto::BoxSelectRequest>,
        reply: oneshot::Sender<
            Result<ergo_api::wallet::native::dto::BoxSelectResponse, WalletAdminError>,
        >,
    },
    /// Native `/api/v1/wallet/transactions/build` (burn-aware unsigned build).
    NativeBuildTransaction {
        intent: Box<ergo_api::wallet::native::dto::TxIntent>,
        reply: oneshot::Sender<
            Result<ergo_api::wallet::native::dto::BuildTxResponse, WalletAdminError>,
        >,
    },
    /// Native `/api/v1/wallet/transactions/sign`.
    NativeSignTransaction {
        req: Box<ergo_api::wallet::native::dto::SignTxRequest>,
        reply: oneshot::Sender<
            Result<ergo_api::wallet::native::dto::SignTxResponse, WalletAdminError>,
        >,
    },
    /// Native `/api/v1/wallet/transactions/send`.
    NativeSendTransaction {
        req: Box<ergo_api::wallet::native::dto::SendTxRequest>,
        reply: oneshot::Sender<
            Result<ergo_api::wallet::native::dto::SendTxResponse, WalletAdminError>,
        >,
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
    RetrieveRewards {
        req: ergo_api::wallet::native::dto::RetrieveRewardsRequest,
        reply: oneshot::Sender<
            Result<ergo_api::wallet::native::dto::RetrieveRewardsResultDto, WalletAdminError>,
        >,
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

    async fn native_balance(
        &self,
        include_unconfirmed: bool,
    ) -> Result<ergo_api::wallet::native::dto::WalletBalanceDto, WalletAdminError> {
        self.send_cmd(move |reply| WalletCommand::NativeBalance {
            include_unconfirmed,
            reply,
        })
        .await
    }

    async fn native_status(
        &self,
    ) -> Result<ergo_api::wallet::native::dto::WalletStatusDto, WalletAdminError> {
        self.send_cmd(|reply| WalletCommand::NativeStatus { reply })
            .await
    }

    async fn native_addresses(
        &self,
        offset: u32,
        limit: u32,
    ) -> Result<ergo_api::wallet::native::dto::AddressPage, WalletAdminError> {
        self.send_cmd(move |reply| WalletCommand::NativeAddresses {
            offset,
            limit,
            reply,
        })
        .await
    }

    async fn native_boxes(
        &self,
        offset: u32,
        limit: u32,
    ) -> Result<ergo_api::wallet::native::dto::BoxPage, WalletAdminError> {
        self.send_cmd(move |reply| WalletCommand::NativeBoxes {
            offset,
            limit,
            reply,
        })
        .await
    }

    async fn native_box_by_id(
        &self,
        box_id_hex: String,
    ) -> Result<Option<ergo_api::wallet::native::dto::WalletBoxSummary>, WalletAdminError> {
        self.send_cmd(move |reply| WalletCommand::NativeBoxById { box_id_hex, reply })
            .await
    }

    async fn native_transactions(
        &self,
        offset: u32,
        limit: u32,
    ) -> Result<ergo_api::wallet::native::dto::TxPage, WalletAdminError> {
        self.send_cmd(move |reply| WalletCommand::NativeTransactions {
            offset,
            limit,
            reply,
        })
        .await
    }

    async fn native_transaction_by_id(
        &self,
        tx_id_hex: String,
    ) -> Result<Option<ergo_api::wallet::native::dto::WalletTransactionSummary>, WalletAdminError>
    {
        self.send_cmd(move |reply| WalletCommand::NativeTransactionById { tx_id_hex, reply })
            .await
    }

    async fn select_boxes(
        &self,
        req: ergo_api::wallet::native::dto::BoxSelectRequest,
    ) -> Result<ergo_api::wallet::native::dto::BoxSelectResponse, WalletAdminError> {
        self.send_cmd(move |reply| WalletCommand::NativeSelectBoxes {
            req: Box::new(req),
            reply,
        })
        .await
    }

    async fn build_transaction(
        &self,
        intent: ergo_api::wallet::native::dto::TxIntent,
    ) -> Result<ergo_api::wallet::native::dto::BuildTxResponse, WalletAdminError> {
        self.send_cmd(move |reply| WalletCommand::NativeBuildTransaction {
            intent: Box::new(intent),
            reply,
        })
        .await
    }

    async fn sign_transaction(
        &self,
        req: ergo_api::wallet::native::dto::SignTxRequest,
    ) -> Result<ergo_api::wallet::native::dto::SignTxResponse, WalletAdminError> {
        self.send_cmd(move |reply| WalletCommand::NativeSignTransaction {
            req: Box::new(req),
            reply,
        })
        .await
    }

    async fn send_transaction(
        &self,
        req: ergo_api::wallet::native::dto::SendTxRequest,
    ) -> Result<ergo_api::wallet::native::dto::SendTxResponse, WalletAdminError> {
        self.send_cmd(move |reply| WalletCommand::NativeSendTransaction {
            req: Box::new(req),
            reply,
        })
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

    async fn retrieve_rewards(
        &self,
        req: ergo_api::wallet::native::dto::RetrieveRewardsRequest,
    ) -> Result<ergo_api::wallet::native::dto::RetrieveRewardsResultDto, WalletAdminError> {
        self.send_cmd(move |reply| WalletCommand::RetrieveRewards { req, reply })
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
    /// EIP-27 re-emission rule inputs for this network (`None` off EIP-27 nets,
    /// e.g. testnet). Built at boot from the chain spec — the same source the
    /// block/mempool validator uses. The wallet's burn-aware builder and the
    /// self-verify EIP-27 gate read it here so a built spend can never violate
    /// consensus. Default `None` (test stubs / non-EIP-27 backends).
    fn reemission_rules(&self) -> Option<&ergo_validation::ReemissionRuleInputs> {
        None
    }
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
    is_pruned: bool,
    /// EIP-27 re-emission rules (mainnet) or `None` (testnet). See
    /// [`ChainStateAccessor::reemission_rules`].
    reemission: Option<ergo_validation::ReemissionRuleInputs>,
}

impl ChainStateAccessorImpl {
    pub fn new(
        db: Arc<redb::Database>,
        is_pruned: bool,
        reemission: Option<ergo_validation::ReemissionRuleInputs>,
    ) -> Self {
        let reader = ergo_state::reader::ChainStoreReader::new_from_db(db.clone());
        Self {
            db,
            reader,
            is_pruned,
            reemission,
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
        // Live committed tip (best full-block height), read each call — NOT a
        // value captured at construction. A node that boots below EIP-27
        // activation and then syncs past it MUST observe the new tip, or the
        // native `reserved`/`eip27Active` (candidate height `tip+1`) would stay
        // wrong forever. Same `chain_state_meta` source the block
        // validator's candidate height uses. `Ok(None)` = chain unstarted → 0; a
        // read FAILURE is surfaced in the log (not silently downgraded to 0, which
        // would mask an operational fault as "below activation").
        match self.reader.committed_tip() {
            Ok(Some((h, _))) => h,
            Ok(None) => 0,
            Err(e) => {
                tracing::warn!(error = %e, "wallet chain accessor: committed_tip read failed; reporting tip=0");
                0
            }
        }
    }

    fn is_pruned(&self) -> bool {
        self.is_pruned
    }

    fn reemission_rules(&self) -> Option<&ergo_validation::ReemissionRuleInputs> {
        self.reemission.as_ref()
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
                mark_scan_invalidated(&self.db);
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
                mark_scan_invalidated(&self.db);
                vec![Vec::new(); boxes.len()]
            }
        }
    }
}

/// Best-effort: flip `WALLET_SCAN_INVALIDATED` after a scan-registry read
/// failure silently dropped a block's matches, so `/wallet/status` surfaces
/// `scan_invalidated` and the operator runs a `/wallet/rescan` (the contract
/// that clears it). "Best-effort": the same redb fault that broke the read may
/// also break this write, in which case it's only logged; a recoverable failure
/// (e.g. one corrupt `WALLET_SCANS` row) does get flagged.
///
/// Deliberately reuses the wallet-wide flag rather than adding a scan-specific
/// one: a registry read failure during apply is a corruption/IO-class event
/// whose recovery contract is already a full rescan, so pausing all wallet apply
/// (`apply_block_to_wallet` no-ops while set) is the correct fail-closed posture
/// — an availability cost on an exceptional path, not a correctness risk. Runs
/// during payload build (no chain write txn is open on this thread yet), so the
/// short write txn here can't deadlock — at worst it briefly waits on an
/// in-flight persist-pipeline write.
fn mark_scan_invalidated(db: &redb::Database) {
    if let Err(e) = try_mark_scan_invalidated(db) {
        tracing::error!(error = %e, "scan apply: failed to set scan-invalidated flag after a registry read failure");
    }
}

#[allow(clippy::result_large_err)] // redb::Error shape is fixed upstream
fn try_mark_scan_invalidated(db: &redb::Database) -> Result<(), redb::Error> {
    // Quick-repair commit (see ergo_state::begin_write_qr): a single
    // non-quick-repair commit can force an O(file-size) repair on the next
    // unclean restart, so route this production write through the helper.
    let w = ergo_state::begin_write_qr(db)?;
    w.open_table(ergo_state::wallet::tables::WALLET_SCAN_INVALIDATED)?
        .insert((), true)?;
    w.commit()?;
    Ok(())
}

/// Network + operator-flag + EIP-27 config supplied at boot.
pub struct WriterConfig {
    pub network: ergo_ser::address::NetworkPrefix,
    /// `[wallet] expose_private_keys`: gates `POST /wallet/getPrivateKey`.
    /// `false` (default) returns 403 Forbidden; `true` allows the
    /// route to return the derived secret scalar.
    pub expose_private_keys: bool,
    /// EIP-27 re-emission rule inputs for this network (`None` off EIP-27
    /// nets, e.g. testnet, where `ChainSpec::reemission` is `None`). Built at
    /// boot from `build_reemission_rules(&config.chain_spec)` — the same source
    /// the block/mempool validator uses, so the wallet's re-emission reserve
    /// estimate and burn-aware builder share one trigger/token-id/floor with
    /// consensus. When `None`, the wallet surfaces no re-emission reserve.
    pub reemission: Option<ergo_validation::ReemissionRuleInputs>,
    /// `[mempool] min_relay_fee_nano_erg` — the local relay-fee floor. A tx built
    /// below it is rejected by submit before validation, so fee defaults derive
    /// from `max(MIN_FEE, this)` and overrides below it are rejected (keeps the
    /// reward-sweep preview/execute contract honest under non-default configs).
    pub min_relay_fee_nano_erg: u64,
    /// `[mempool] max_tx_size_bytes` — the local admission tx-size cap. The
    /// reward sweep bounds its built tx against this so a preview can't approve a
    /// sweep the submit path rejects as `too_big` under a lowered config.
    pub max_tx_size_bytes: usize,
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
            WalletCommand::NativeBalance {
                include_unconfirmed,
                reply,
            } => commands::admin::native_balance(&ctx, include_unconfirmed, reply).await,
            WalletCommand::NativeStatus { reply } => {
                commands::admin::native_status(&ctx, reply).await
            }
            WalletCommand::NativeAddresses {
                offset,
                limit,
                reply,
            } => commands::admin::native_addresses(&ctx, offset, limit, reply).await,
            WalletCommand::NativeBoxes {
                offset,
                limit,
                reply,
            } => commands::admin::native_boxes(&ctx, offset, limit, reply).await,
            WalletCommand::NativeBoxById { box_id_hex, reply } => {
                commands::admin::native_box_by_id(&ctx, box_id_hex, reply).await
            }
            WalletCommand::NativeTransactions {
                offset,
                limit,
                reply,
            } => commands::admin::native_transactions(&ctx, offset, limit, reply).await,
            WalletCommand::NativeTransactionById { tx_id_hex, reply } => {
                commands::admin::native_transaction_by_id(&ctx, tx_id_hex, reply).await
            }
            WalletCommand::NativeSelectBoxes { req, reply } => {
                commands::send::native_select_boxes(&ctx, *req, reply).await
            }
            WalletCommand::NativeBuildTransaction { intent, reply } => {
                commands::send::native_build_transaction(&ctx, *intent, reply).await
            }
            WalletCommand::NativeSignTransaction { req, reply } => {
                commands::send::native_sign_transaction(&ctx, *req, reply).await
            }
            WalletCommand::NativeSendTransaction { req, reply } => {
                commands::send::native_send_transaction(&ctx, *req, reply).await
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
            WalletCommand::RetrieveRewards { req, reply } => {
                commands::send::retrieve_rewards(&ctx, req, reply).await
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

mod support;
#[cfg(test)]
mod scan_invalidation_tests {
    use super::*;
    use ergo_state::wallet::tables::{WALLET_SCANS, WALLET_SCAN_INVALIDATED};

    fn temp_db() -> (tempfile::TempDir, Arc<redb::Database>) {
        let dir = tempfile::tempdir().unwrap();
        let db = redb::Database::create(dir.path().join("wallet.redb")).unwrap();
        (dir, Arc::new(db))
    }

    fn flag_set(db: &redb::Database) -> bool {
        let r = db.begin_read().unwrap();
        match r.open_table(WALLET_SCAN_INVALIDATED) {
            Ok(t) => t.get(()).unwrap().map(|g| g.value()).unwrap_or(false),
            Err(_) => false,
        }
    }

    #[test]
    fn mark_scan_invalidated_sets_the_flag() {
        let (_d, db) = temp_db();
        assert!(!flag_set(&db), "flag starts clear");
        mark_scan_invalidated(&db);
        assert!(flag_set(&db), "flag set after mark");
    }

    #[test]
    fn match_boxes_registry_load_failure_invalidates_for_rescan() {
        let (_d, db) = temp_db();
        // A corrupt WALLET_SCANS row (not valid Scan JSON) makes load_registry
        // fail when match_boxes loads it for the block.
        {
            let w = db.begin_write().unwrap();
            w.open_table(WALLET_SCANS)
                .unwrap()
                .insert(11u16, vec![0xFFu8, 0x00])
                .unwrap();
            w.commit().unwrap();
        }
        let hook = WalletStateHook {
            wallet: Arc::new(RwLock::new(ergo_wallet::state::WalletState::empty(false))),
            db: db.clone(),
        };
        // match_boxes loads the registry first (regardless of the box slice), so
        // the corrupt row trips the Err branch even with no boxes.
        let out = ergo_state::wallet::WalletApplyHook::match_boxes(&hook, &[]);
        assert!(out.is_empty());
        assert!(
            flag_set(&db),
            "a registry load failure must set WALLET_SCAN_INVALIDATED for rescan"
        );
    }
}
