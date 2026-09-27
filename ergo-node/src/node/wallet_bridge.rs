//! Production WalletAdmin bridge. Single-writer pattern: the action
//! loop in ergo-node owns the wallet storage + state behind a RwLock.
//! The axum API task sends commands via a channel; the loop processes
//! them serially and sends the responses back via the per-command
//! oneshot channel.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::RwLock;
use tokio::sync::{mpsc, oneshot};

use ergo_api::wallet::WalletAdmin;
use ergo_primitives::digest::Digest32;
use ergo_ser::ergo_box::ErgoBox;
use ergo_wallet::storage::SecretStorage;
use ergo_wallet_protocol::scala::scan::{ScanBoxEntry, ScanBoxFilter, ScanDto, ScanRequestDto};
use ergo_wallet_protocol::scala::sending::PaymentRequestDto;
use ergo_wallet_protocol::scala::sending::{
    BoxesCollectRequest, BoxesCollectResponse, TransactionGenerateRequest,
    TransactionGenerateResponse, TransactionGenerateUnsignedRequest,
    TransactionGenerateUnsignedResponse, TransactionSendRequest, TransactionSignRequest,
    TransactionSignResponse,
};
use ergo_wallet_protocol::scala::types::{
    Page, WalletAddressList, WalletBalances, WalletBoxesPage, WalletStatus, WalletTransactionEntry,
    WalletTransactionsPage,
};
use ergo_wallet_protocol::WalletAdminError;
use ergo_wallet_service::chain::CommittedTip;
use ergo_wallet_service::engine::{
    ChainAccessError, MempoolOverlay, RescanCoordinator, SigningView, TxSubmitError, TxSubmitter,
    WalletChainAccess, WalletEngineConfig, WalletRescanGuard,
};
use ergo_wallet_service::state::WalletState;
use ergo_wallet_service::wallet::scan::{RescanBlock, RescanReadError};

pub mod chain_client;
pub mod chain_snapshot;
pub use chain_client::{
    ChainClientAdapter, InProcessChainClient, IntoChainSubmitter, NodeChainClient,
    WalletChainAdapter,
};
use chain_snapshot::chain_state_read_failed;
pub use chain_snapshot::ChainSnapshot;

/// Production [`TxSubmitter`] backed by the node's `NodeSubmit` bridge.
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
    async fn submit_transaction(&self, tx_bytes: Vec<u8>) -> Result<String, TxSubmitError> {
        use ergo_api::types::SubmitMode;
        // Forward the typed SubmitError unmodified — each caller maps it intentionally.
        self.inner
            .submit_transaction(tx_bytes, SubmitMode::Broadcast)
            .await
            .map_err(|error| TxSubmitError {
                reason: error.reason,
                detail: error.detail,
            })
    }
}

/// Adapts the API's snapshot-backed [`ergo_api::MempoolView`] to the wallet
/// engine's [`MempoolOverlay`] seam (the three pool reads the wallet makes).
pub struct MempoolViewOverlay {
    inner: Arc<dyn ergo_api::MempoolView>,
}

impl MempoolViewOverlay {
    pub fn new(inner: Arc<dyn ergo_api::MempoolView>) -> Self {
        Self { inner }
    }
}

impl MempoolOverlay for MempoolViewOverlay {
    fn is_spent_by_pool(&self, box_id: &Digest32) -> bool {
        self.inner.is_spent_by_pool(box_id)
    }

    fn pool_spending_tx(&self, box_id: &Digest32) -> Option<Digest32> {
        self.inner.pool_spending_tx(box_id)
    }

    fn pool_outputs(&self) -> Arc<HashMap<Digest32, ErgoBox>> {
        self.inner.pool_outputs()
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
            Result<ergo_wallet_protocol::native::dto::WalletBalanceDto, WalletAdminError>,
        >,
    },
    /// Native `/api/v1/wallet/status`.
    NativeStatus {
        reply: oneshot::Sender<
            Result<ergo_wallet_protocol::native::dto::WalletStatusDto, WalletAdminError>,
        >,
    },
    /// Native `/api/v1/wallet/addresses` (paged).
    NativeAddresses {
        offset: u32,
        limit: u32,
        reply: oneshot::Sender<
            Result<ergo_wallet_protocol::native::dto::AddressPage, WalletAdminError>,
        >,
    },
    /// Native `/api/v1/wallet/boxes` (paged).
    NativeBoxes {
        offset: u32,
        limit: u32,
        reply:
            oneshot::Sender<Result<ergo_wallet_protocol::native::dto::BoxPage, WalletAdminError>>,
    },
    /// Native `/api/v1/wallet/boxes/{boxId}`.
    NativeBoxById {
        box_id_hex: String,
        reply: oneshot::Sender<
            Result<Option<ergo_wallet_protocol::native::dto::WalletBoxSummary>, WalletAdminError>,
        >,
    },
    /// Native `/api/v1/wallet/transactions` (paged).
    NativeTransactions {
        offset: u32,
        limit: u32,
        reply: oneshot::Sender<Result<ergo_wallet_protocol::native::dto::TxPage, WalletAdminError>>,
    },
    /// Native `/api/v1/wallet/transactions/{txId}`.
    NativeTransactionById {
        tx_id_hex: String,
        reply: oneshot::Sender<
            Result<
                Option<ergo_wallet_protocol::native::dto::WalletTransactionSummary>,
                WalletAdminError,
            >,
        >,
    },
    /// Native `/api/v1/wallet/boxes/select` (burn-aware selection dry-run).
    NativeSelectBoxes {
        req: Box<ergo_wallet_protocol::native::dto::BoxSelectRequest>,
        reply: oneshot::Sender<
            Result<ergo_wallet_protocol::native::dto::BoxSelectResponse, WalletAdminError>,
        >,
    },
    /// Native `/api/v1/wallet/transactions/build` (burn-aware unsigned build).
    NativeBuildTransaction {
        intent: Box<ergo_wallet_protocol::native::dto::TxIntent>,
        reply: oneshot::Sender<
            Result<ergo_wallet_protocol::native::dto::BuildTxResponse, WalletAdminError>,
        >,
    },
    /// Native `/api/v1/wallet/transactions/sign`.
    NativeSignTransaction {
        req: Box<ergo_wallet_protocol::native::dto::SignTxRequest>,
        reply: oneshot::Sender<
            Result<ergo_wallet_protocol::native::dto::SignTxResponse, WalletAdminError>,
        >,
    },
    /// Native `/api/v1/wallet/transactions/send`.
    NativeSendTransaction {
        req: Box<ergo_wallet_protocol::native::dto::SendTxRequest>,
        reply: oneshot::Sender<
            Result<ergo_wallet_protocol::native::dto::SendTxResponse, WalletAdminError>,
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
        req: ergo_wallet_protocol::native::dto::RetrieveRewardsRequest,
        reply: oneshot::Sender<
            Result<ergo_wallet_protocol::native::dto::RetrieveRewardsResultDto, WalletAdminError>,
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
        request: ergo_wallet_protocol::scala::multi_sig::GenerateCommitmentsRequest,
        reply: oneshot::Sender<
            Result<
                ergo_wallet_protocol::scala::multi_sig::GenerateCommitmentsResponse,
                WalletAdminError,
            >,
        >,
    },
    ExtractHints {
        request: ergo_wallet_protocol::scala::multi_sig::HintExtractionRequest,
        reply: oneshot::Sender<
            Result<
                ergo_wallet_protocol::scala::multi_sig::HintExtractionResponse,
                WalletAdminError,
            >,
        >,
    },
    // --- advanced HD-key commands ---
    DeriveKey {
        request: ergo_wallet_protocol::scala::admin_advanced::DeriveKeyRequest,
        reply: oneshot::Sender<
            Result<
                ergo_wallet_protocol::scala::admin_advanced::DeriveKeyResponse,
                WalletAdminError,
            >,
        >,
    },
    DeriveNextKey {
        reply: oneshot::Sender<
            Result<
                ergo_wallet_protocol::scala::admin_advanced::DeriveNextKeyResponse,
                WalletAdminError,
            >,
        >,
    },
    GetPrivateKey {
        request: ergo_wallet_protocol::scala::admin_advanced::GetPrivateKeyRequest,
        reply: oneshot::Sender<
            Result<
                ergo_wallet_protocol::scala::admin_advanced::GetPrivateKeyResponse,
                WalletAdminError,
            >,
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

fn reject_wallet_reply<T>(reply: oneshot::Sender<Result<T, WalletAdminError>>) {
    let _ = reply.send(Err(WalletAdminError::RescanUnavailable(
        "wallet recovery required: run rescan before using wallet operations".to_string(),
    )));
}

impl WalletCommand {
    fn is_rescan_control(&self) -> bool {
        matches!(
            self,
            Self::Status { .. }
                | Self::NativeStatus { .. }
                | Self::Lock { .. }
                | Self::Rescan { .. }
        )
    }

    fn reject_during_rescan(self) {
        macro_rules! reject {
            ($($variant:ident),+ $(,)?) => {
                match self {
                    $(Self::$variant { reply, .. } => reject_wallet_reply(reply),)+
                }
            };
        }
        reject!(
            Status,
            Init,
            Restore,
            Unlock,
            Lock,
            Check,
            Rescan,
            UpdateChangeAddress,
            Balances,
            BalancesWithUnconfirmed,
            NativeBalance,
            NativeStatus,
            NativeAddresses,
            NativeBoxes,
            NativeBoxById,
            NativeTransactions,
            NativeTransactionById,
            NativeSelectBoxes,
            NativeBuildTransaction,
            NativeSignTransaction,
            NativeSendTransaction,
            Addresses,
            Boxes,
            BoxesUnspent,
            Transactions,
            TransactionById,
            TransactionsByScanId,
            PaymentSend,
            RetrieveRewards,
            TransactionGenerate,
            TransactionGenerateUnsigned,
            TransactionSign,
            TransactionSend,
            BoxesCollect,
            GenerateCommitments,
            ExtractHints,
            DeriveKey,
            DeriveNextKey,
            GetPrivateKey,
            RegisterScan,
            DeregisterScan,
            ListScans,
            ScanUnspentBoxes,
            ScanSpentBoxes,
            ScanStopTracking,
            ScanAddBox,
            ScanP2sRule,
        );
    }
}

/// `WalletAdmin` impl backed by a command channel. Constructed by
/// `Node::run` and handed to `ergo-api`'s router builder.
pub struct NodeWalletAdmin {
    tx: mpsc::Sender<WalletCommand>,
    /// The wallet's rescan coordinator: the pre-enqueue fence reads it.
    rescan: Arc<RescanCoordinator>,
}

impl NodeWalletAdmin {
    /// Begin a new wallet session owned by `rescan` and wrap the command
    /// channel of the writer task that shares the same coordinator.
    pub fn new(tx: mpsc::Sender<WalletCommand>, rescan: Arc<RescanCoordinator>) -> Self {
        crate::wallet_boot::begin_wallet_session(rescan.clone());
        Self { tx, rescan }
    }

    pub(super) fn with_session(
        tx: mpsc::Sender<WalletCommand>,
        rescan: Arc<RescanCoordinator>,
    ) -> Self {
        Self { tx, rescan }
    }

    /// The rescan coordinator this admin's pre-enqueue fence reads (shared
    /// with its writer task and the chain-apply hook).
    pub fn rescan_coordinator(&self) -> &Arc<RescanCoordinator> {
        &self.rescan
    }

    async fn send_cmd<R, F>(&self, build: F) -> Result<R, WalletAdminError>
    where
        F: FnOnce(oneshot::Sender<Result<R, WalletAdminError>>) -> WalletCommand,
    {
        self.send_cmd_with_policy(build, false).await
    }

    async fn send_rescan_cmd<R, F>(&self, build: F) -> Result<R, WalletAdminError>
    where
        F: FnOnce(oneshot::Sender<Result<R, WalletAdminError>>) -> WalletCommand,
    {
        self.send_cmd_with_policy(build, true).await
    }

    async fn send_control_cmd<R, F>(&self, build: F) -> Result<R, WalletAdminError>
    where
        F: FnOnce(oneshot::Sender<Result<R, WalletAdminError>>) -> WalletCommand,
    {
        self.send_cmd_with_policy(build, true).await
    }

    async fn send_cmd_with_policy<R, F>(
        &self,
        build: F,
        allow_during_rescan: bool,
    ) -> Result<R, WalletAdminError>
    where
        F: FnOnce(oneshot::Sender<Result<R, WalletAdminError>>) -> WalletCommand,
    {
        if !allow_during_rescan && self.rescan.operations_fenced() {
            return Err(WalletAdminError::RescanUnavailable(
                "wallet recovery required: run rescan before using wallet operations".to_string(),
            ));
        }
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
        self.send_control_cmd(|reply| WalletCommand::Status { reply })
            .await
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
        self.send_control_cmd(|reply| WalletCommand::Lock { reply })
            .await
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
        self.send_rescan_cmd(move |reply| WalletCommand::Rescan { from_height, reply })
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
    ) -> Result<ergo_wallet_protocol::native::dto::WalletBalanceDto, WalletAdminError> {
        self.send_cmd(move |reply| WalletCommand::NativeBalance {
            include_unconfirmed,
            reply,
        })
        .await
    }

    async fn native_status(
        &self,
    ) -> Result<ergo_wallet_protocol::native::dto::WalletStatusDto, WalletAdminError> {
        self.send_control_cmd(|reply| WalletCommand::NativeStatus { reply })
            .await
    }

    async fn native_addresses(
        &self,
        offset: u32,
        limit: u32,
    ) -> Result<ergo_wallet_protocol::native::dto::AddressPage, WalletAdminError> {
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
    ) -> Result<ergo_wallet_protocol::native::dto::BoxPage, WalletAdminError> {
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
    ) -> Result<Option<ergo_wallet_protocol::native::dto::WalletBoxSummary>, WalletAdminError> {
        self.send_cmd(move |reply| WalletCommand::NativeBoxById { box_id_hex, reply })
            .await
    }

    async fn native_transactions(
        &self,
        offset: u32,
        limit: u32,
    ) -> Result<ergo_wallet_protocol::native::dto::TxPage, WalletAdminError> {
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
    ) -> Result<Option<ergo_wallet_protocol::native::dto::WalletTransactionSummary>, WalletAdminError>
    {
        self.send_cmd(move |reply| WalletCommand::NativeTransactionById { tx_id_hex, reply })
            .await
    }

    async fn select_boxes(
        &self,
        req: ergo_wallet_protocol::native::dto::BoxSelectRequest,
    ) -> Result<ergo_wallet_protocol::native::dto::BoxSelectResponse, WalletAdminError> {
        self.send_cmd(move |reply| WalletCommand::NativeSelectBoxes {
            req: Box::new(req),
            reply,
        })
        .await
    }

    async fn build_transaction(
        &self,
        intent: ergo_wallet_protocol::native::dto::TxIntent,
    ) -> Result<ergo_wallet_protocol::native::dto::BuildTxResponse, WalletAdminError> {
        self.send_cmd(move |reply| WalletCommand::NativeBuildTransaction {
            intent: Box::new(intent),
            reply,
        })
        .await
    }

    async fn sign_transaction(
        &self,
        req: ergo_wallet_protocol::native::dto::SignTxRequest,
    ) -> Result<ergo_wallet_protocol::native::dto::SignTxResponse, WalletAdminError> {
        self.send_cmd(move |reply| WalletCommand::NativeSignTransaction {
            req: Box::new(req),
            reply,
        })
        .await
    }

    async fn send_transaction(
        &self,
        req: ergo_wallet_protocol::native::dto::SendTxRequest,
    ) -> Result<ergo_wallet_protocol::native::dto::SendTxResponse, WalletAdminError> {
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
        req: ergo_wallet_protocol::native::dto::RetrieveRewardsRequest,
    ) -> Result<ergo_wallet_protocol::native::dto::RetrieveRewardsResultDto, WalletAdminError> {
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
        request: ergo_wallet_protocol::scala::multi_sig::GenerateCommitmentsRequest,
    ) -> Result<ergo_wallet_protocol::scala::multi_sig::GenerateCommitmentsResponse, WalletAdminError>
    {
        self.send_cmd(move |reply| WalletCommand::GenerateCommitments { request, reply })
            .await
    }

    async fn extract_hints(
        &self,
        request: ergo_wallet_protocol::scala::multi_sig::HintExtractionRequest,
    ) -> Result<ergo_wallet_protocol::scala::multi_sig::HintExtractionResponse, WalletAdminError>
    {
        self.send_cmd(move |reply| WalletCommand::ExtractHints { request, reply })
            .await
    }

    async fn derive_key(
        &self,
        request: ergo_wallet_protocol::scala::admin_advanced::DeriveKeyRequest,
    ) -> Result<ergo_wallet_protocol::scala::admin_advanced::DeriveKeyResponse, WalletAdminError>
    {
        self.send_cmd(move |reply| WalletCommand::DeriveKey { request, reply })
            .await
    }

    async fn derive_next_key(
        &self,
    ) -> Result<ergo_wallet_protocol::scala::admin_advanced::DeriveNextKeyResponse, WalletAdminError>
    {
        self.send_cmd(|reply| WalletCommand::DeriveNextKey { reply })
            .await
    }

    async fn get_private_key(
        &self,
        request: ergo_wallet_protocol::scala::admin_advanced::GetPrivateKeyRequest,
    ) -> Result<ergo_wallet_protocol::scala::admin_advanced::GetPrivateKeyResponse, WalletAdminError>
    {
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

/// Production [`WalletChainAccess`] backed by the shared redb `Database`
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
/// - `signing_view` / `build_signing_context` / `build_signing_params` /
///   `lookup_utxo`: use the `ChainStoreReader` to read from committed state
///   without acquiring the action-loop's mutable `StateStore`.
pub struct ChainStateAccessorImpl {
    /// Lock-free reader for chain state (headers, UTXO, active params).
    reader: ergo_state::reader::ChainStoreReader,
    wallet_store: Option<Arc<dyn ergo_wallet_service::wallet::WalletStore>>,
    is_pruned: bool,
    /// EIP-27 re-emission rules (mainnet) or `None` (testnet). See
    /// [`WalletChainAccess::reemission_rules`].
    reemission: Option<ergo_validation::ReemissionRuleInputs>,
}

impl ChainStateAccessorImpl {
    pub fn new(
        reader: ergo_state::reader::ChainStoreReader,
        wallet_store: Arc<dyn ergo_wallet_service::wallet::WalletStore>,
        is_pruned: bool,
        reemission: Option<ergo_validation::ReemissionRuleInputs>,
    ) -> Self {
        Self {
            reader,
            wallet_store: Some(wallet_store),
            is_pruned,
            reemission,
        }
    }

    pub fn chain_only(
        reader: ergo_state::reader::ChainStoreReader,
        is_pruned: bool,
        reemission: Option<ergo_validation::ReemissionRuleInputs>,
    ) -> Self {
        Self {
            reader,
            wallet_store: None,
            is_pruned,
            reemission,
        }
    }

    /// The concrete committed [`ChainSnapshot`] behind
    /// [`WalletChainAccess::signing_view`].
    pub fn chain_snapshot(&self) -> Result<ChainSnapshot, ChainAccessError> {
        let committed = self
            .reader
            .committed_snapshot()
            .map_err(chain_state_read_failed)?
            .ok_or(ChainAccessError::NoCommittedState)?;
        ChainSnapshot::from_committed(committed, self.reemission.as_ref())
            .map_err(chain_state_read_failed)
    }

    fn wallet_scan_height_state(&self) -> Result<u32, ergo_state::store::StateError> {
        let wallet_store =
            self.wallet_store
                .as_ref()
                .ok_or(ergo_state::store::StateError::InternalInvariant {
                    what: "chain-only accessor cannot read wallet scan height",
                })?;
        let read = wallet_store
            .read()
            .map_err(ergo_state::store::StateError::from)?;
        Ok(read
            .scan_cursor()
            .map_err(ergo_state::store::StateError::from)?
            .map(|cursor| cursor.height)
            .unwrap_or(0))
    }
}

impl WalletChainAccess for ChainStateAccessorImpl {
    fn wallet_scan_height(&self) -> Result<u32, ChainAccessError> {
        self.wallet_scan_height_state()
            .map_err(|error| ChainAccessError::State(error.to_string()))
    }

    fn tip_height(&self) -> Result<u32, ChainAccessError> {
        Ok(self
            .reader
            .committed_tip()
            .map_err(|error| ChainAccessError::State(error.to_string()))?
            .map(|(height, _)| height)
            .unwrap_or(0))
    }

    fn is_pruned(&self) -> bool {
        self.is_pruned
    }

    fn reemission_rules(&self) -> Option<&ergo_validation::ReemissionRuleInputs> {
        self.reemission.as_ref()
    }

    fn read_block_at(&self, height: u32) -> Result<Option<RescanBlock>, RescanReadError> {
        use ergo_wallet_service::wallet::scan::RescanTx;
        use ergo_wallet_service::wallet::OwnedBlockOutput;

        let (block_id, owned) = match self.reader.wallet_block_txs_at_height(height)? {
            Some(pair) => pair,
            None => return Ok(None),
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

        Ok(Some(RescanBlock { block_id, txs }))
    }

    fn signing_view(&self) -> Result<Box<dyn SigningView>, ChainAccessError> {
        Ok(Box::new(self.chain_snapshot()?))
    }

    fn committed_tip(&self) -> Result<Option<CommittedTip>, ChainAccessError> {
        Ok(self
            .reader
            .committed_tip()
            .map_err(chain_state_read_failed)?
            .map(|(height, header_id)| CommittedTip { height, header_id }))
    }

    fn build_signing_context(
        &self,
    ) -> Result<ergo_wallet::tx_context::BlockchainStateContext, ChainAccessError> {
        self.chain_snapshot()
            .map(|snapshot| snapshot.state_context().clone())
    }

    fn build_signing_params(
        &self,
    ) -> Result<ergo_wallet::tx_context::BlockchainParameters, ChainAccessError> {
        self.chain_snapshot()
            .map(|snapshot| snapshot.signing_params().clone())
    }

    fn build_protocol_params(&self) -> Result<ergo_validation::ProtocolParams, ChainAccessError> {
        self.chain_snapshot()
            .map(|snapshot| snapshot.protocol_params().clone())
    }

    fn lookup_utxo(
        &self,
        box_id: &[u8; 32],
    ) -> Result<Option<ergo_ser::ergo_box::ErgoBox>, ChainAccessError> {
        let Some(bytes) = self
            .reader
            .lookup_box(box_id)
            .map_err(chain_state_read_failed)?
        else {
            return Ok(None);
        };
        chain_snapshot::decode_utxo_box(box_id, &bytes)
            .map(Some)
            .map_err(chain_state_read_failed)
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
    wallet: Arc<RwLock<WalletState>>,
    /// Shared wallet store used for block-apply matching and invalidation.
    store: Arc<dyn ergo_wallet_service::wallet::WalletStore>,
    /// The wallet's rollback guard; its coordinator also drives this hook's
    /// full-rescan quiesce gates.
    rescan_guard: WalletRescanGuard,
}

impl WalletStateHook {
    pub fn new(
        wallet: Arc<RwLock<WalletState>>,
        store: Arc<dyn ergo_wallet_service::wallet::WalletStore>,
        rescan: Arc<RescanCoordinator>,
    ) -> Self {
        Self {
            wallet,
            store,
            rescan_guard: WalletRescanGuard::new(rescan),
        }
    }

    /// The chain-rollback guard sharing this hook's rescan coordinator.
    pub fn rescan_guard(&self) -> &WalletRescanGuard {
        &self.rescan_guard
    }

    /// The hook + rollback guard pair threaded through chain apply/rollback.
    pub fn wiring(&self) -> ergo_wallet_service::wallet::WalletWiring<'_> {
        ergo_wallet_service::wallet::WalletWiring {
            hook: self,
            rescan_guard: &self.rescan_guard,
        }
    }

    fn rescan(&self) -> &RescanCoordinator {
        self.rescan_guard.coordinator()
    }
}

impl ergo_wallet_service::wallet::WalletApplyHook for WalletStateHook {
    fn tracked_p2pk_trees(&self) -> std::collections::BTreeSet<Vec<u8>> {
        // Full rescans and fail-closed recovery suppress wallet payloads;
        // partial rescans leave live wallet apply enabled.
        if self.rescan().scan_rebuild_in_progress() {
            return std::collections::BTreeSet::new();
        }
        let state = self.wallet.read();
        state.tracked_p2pk_trees().clone()
    }

    fn cached_pubkeys(&self) -> std::collections::BTreeMap<u64, [u8; 33]> {
        if self.rescan().scan_rebuild_in_progress() {
            return std::collections::BTreeMap::new();
        }
        let state = self.wallet.read();
        state.cached_pubkeys().clone()
    }

    fn wallet_state_snapshot(
        &self,
    ) -> (
        std::collections::BTreeSet<Vec<u8>>,
        std::collections::BTreeMap<u64, [u8; 33]>,
    ) {
        if self.rescan().scan_rebuild_in_progress() {
            return (Default::default(), Default::default());
        }
        let state = self.wallet.read();
        (
            state.tracked_p2pk_trees().clone(),
            state.cached_pubkeys().clone(),
        )
    }

    fn allow_non_contiguous_wallet_apply(&self) -> bool {
        self.rescan().in_progress() && !self.rescan().scan_rebuild_in_progress()
    }

    fn registered_scan_count(&self) -> usize {
        // Skip live scan apply while a full rescan is rebuilding the scan
        // tables: the rebuild clears and repopulates WALLET_SCAN_* block by
        // block, so a concurrent live write would race it (miss a spend
        // against the cleared reverse index, or stale that index). Mirrors
        // the full-rescan gate on the pubkey path. A PARTIAL
        // rescan does not set this flag, so live scan tracking continues
        // across it (scans have no range-rewind rebuild).
        if self.rescan().scan_rebuild_in_progress() {
            return 0;
        }
        // Cheap per-block gate: count rows in WALLET_SCANS. Scan tracking is
        // independent of the wallet-pubkey rescan, so (unlike the methods above)
        // it is NOT skipped while a *partial* rescan is in progress. A read error
        // skips scan work for this block (logged) rather than aborting chain apply.
        let count = self
            .store
            .read()
            .and_then(|read| read.registered_scan_count());
        match count {
            Ok(n) => n,
            Err(e) => {
                tracing::error!(error = %e, "scan apply: wallet store scan count read failed; skipping this block");
                mark_scan_invalidated(self.store.as_ref(), self.rescan());
                0
            }
        }
    }

    fn match_boxes(&self, boxes: &[ergo_ser::ergo_box::ErgoBox]) -> Vec<Vec<u16>> {
        // Quiesced during a scan rebuild (see `registered_scan_count`). The
        // count gate already returns 0 then, so this is defense in depth —
        // mirrors the pubkey path gating both of its hook methods.
        if self.rescan().scan_rebuild_in_progress() {
            return vec![Vec::new(); boxes.len()];
        }
        // Load the registry once for the whole block, then match each box.
        match commands::scan::load_registry_from_store(self.store.as_ref()) {
            Ok(registry) => boxes
                .iter()
                .map(|b| registry.matching_scan_ids(b))
                .collect(),
            Err(e) => {
                tracing::error!(error = %e, "scan apply: registry load failed; no matches this block");
                mark_scan_invalidated(self.store.as_ref(), self.rescan());
                vec![Vec::new(); boxes.len()]
            }
        }
    }
}

/// Flip `WALLET_SCAN_INVALIDATED` after a scan-registry read failure so
/// `/wallet/status` surfaces the condition and the operator can rescan. The
/// rescan guards are latched before the write attempt, regardless of whether
/// the durable flag write succeeds; the flag remains the recovery signal.
fn mark_scan_invalidated(
    store: &dyn ergo_wallet_service::wallet::WalletStore,
    rescan: &RescanCoordinator,
) {
    const RETRIES: usize = 3;
    rescan.latch_fail_closed();
    let mut last_error = None;
    for attempt in 0..RETRIES {
        match try_mark_scan_invalidated(store) {
            Ok(()) => return,
            Err(error) => {
                last_error = Some(error);
                if attempt + 1 < RETRIES {
                    std::thread::yield_now();
                }
            }
        }
    }
    if let Some(error) = last_error {
        tracing::error!(error = %error, "scan apply: failed to set scan-invalidated flag after a registry read failure; continuing with in-memory invalidation");
    }
}

fn try_mark_scan_invalidated(
    store: &dyn ergo_wallet_service::wallet::WalletStore,
) -> Result<(), ergo_wallet_service::wallet::WalletStoreError> {
    store.persist_scan_invalidation(true)
}

/// Writer-task loop. Runs in a dedicated tokio task; receives commands and
/// dispatches against owned `storage` + `state` + wallet store + `chain`
/// accessor. Each command's reply is sent back via its oneshot. `rescan` is
/// the wallet's rescan coordinator, shared with the [`NodeWalletAdmin`] fence
/// and the chain-apply [`WalletStateHook`].
#[allow(clippy::too_many_arguments)] // task spawn-point: owned deps unpacked straight into WriterContext
pub async fn run_wallet_writer(
    rx: mpsc::Receiver<WalletCommand>,
    storage: Arc<RwLock<SecretStorage>>,
    state: Arc<RwLock<WalletState>>,
    store: Arc<dyn ergo_wallet_service::wallet::WalletStore>,
    chain: Arc<dyn WalletChainAccess>,
    cfg: WalletEngineConfig,
    submit_handle: Arc<dyn TxSubmitter>,
    mempool: Arc<dyn ergo_api::MempoolView>,
    rescan: Arc<RescanCoordinator>,
) {
    let session_id = crate::wallet_boot::wallet_session_id();
    run_wallet_writer_with_session(
        rx,
        storage,
        state,
        store,
        chain,
        cfg,
        submit_handle,
        mempool,
        rescan,
        session_id,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn run_wallet_writer_with_session(
    rx: mpsc::Receiver<WalletCommand>,
    storage: Arc<RwLock<SecretStorage>>,
    state: Arc<RwLock<WalletState>>,
    store: Arc<dyn ergo_wallet_service::wallet::WalletStore>,
    chain: Arc<dyn WalletChainAccess>,
    cfg: WalletEngineConfig,
    submit_handle: Arc<dyn TxSubmitter>,
    mempool: Arc<dyn ergo_api::MempoolView>,
    rescan: Arc<RescanCoordinator>,
    wallet_session_id: u64,
) {
    run_wallet_writer_inner(
        rx,
        storage,
        state,
        store,
        chain,
        cfg,
        submit_handle,
        mempool,
        rescan,
        wallet_session_id,
        None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn run_wallet_writer_with_service(
    rx: mpsc::Receiver<WalletCommand>,
    storage: Arc<RwLock<SecretStorage>>,
    state: Arc<RwLock<WalletState>>,
    store: Arc<dyn ergo_wallet_service::wallet::WalletStore>,
    chain: Arc<dyn WalletChainAccess>,
    cfg: WalletEngineConfig,
    submit_handle: Arc<dyn TxSubmitter>,
    mempool: Arc<dyn ergo_api::MempoolView>,
    rescan: Arc<RescanCoordinator>,
    wallet_session_id: u64,
    service: Arc<ergo_wallet_service::runtime::WalletService>,
) {
    run_wallet_writer_inner(
        rx,
        storage,
        state,
        store,
        chain,
        cfg,
        submit_handle,
        mempool,
        rescan,
        wallet_session_id,
        Some(service),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn run_wallet_writer_inner(
    mut rx: mpsc::Receiver<WalletCommand>,
    storage: Arc<RwLock<SecretStorage>>,
    state: Arc<RwLock<WalletState>>,
    store: Arc<dyn ergo_wallet_service::wallet::WalletStore>,
    chain: Arc<dyn WalletChainAccess>,
    cfg: WalletEngineConfig,
    submit_handle: Arc<dyn TxSubmitter>,
    mempool: Arc<dyn ergo_api::MempoolView>,
    rescan: Arc<RescanCoordinator>,
    wallet_session_id: u64,
    service: Option<Arc<ergo_wallet_service::runtime::WalletService>>,
) {
    let mempool: Arc<dyn MempoolOverlay> = Arc::new(MempoolViewOverlay::new(mempool));
    let ctx = commands::WriterContext {
        storage: &storage,
        state: &state,
        store: &store,
        chain: &chain,
        cfg: &cfg,
        submit_handle: &submit_handle,
        mempool: &mempool,
        service: service.as_deref(),
        rescan: &rescan,
        wallet_session_id,
    };
    // Sensitive-op failed-attempt budgets, owned by this loop (the single
    // choke point every wallet surface funnels through). See
    // `commands::admin::AttemptLimiter`.
    let unlock_limiter = commands::admin::AttemptLimiter::new();
    let check_limiter = commands::admin::AttemptLimiter::new();
    while let Some(cmd) = rx.recv().await {
        if !cmd.is_rescan_control() && rescan.operations_fenced() {
            cmd.reject_during_rescan();
            continue;
        }
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
                commands::admin::unlock(&ctx, &unlock_limiter, pass, reply).await
            }
            WalletCommand::Lock { reply } => commands::admin::lock(&ctx, reply).await,
            WalletCommand::Check {
                mnemonic,
                mnemonic_pass,
                reply,
            } => commands::admin::check(&ctx, &check_limiter, mnemonic, mnemonic_pass, reply).await,
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
mod command_fencing_tests {
    use super::*;
    use ergo_wallet_service::wallet::{WalletRead, WalletStore, WalletStoreError, WalletWrite};

    #[tokio::test]
    async fn normal_commands_are_fenced_but_rescan_is_allowed() {
        let coordinator = Arc::new(RescanCoordinator::new());
        coordinator.latch_fail_closed();
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let admin = NodeWalletAdmin::new(tx, coordinator.clone());
        let normal = admin.balances().await;
        let queued = rx.try_recv();
        assert!(matches!(
            normal,
            Err(WalletAdminError::RescanUnavailable(_))
        ));
        assert!(queued.is_err());

        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let admin = NodeWalletAdmin::new(tx, coordinator.clone());
        let rescan = tokio::spawn(async move { admin.rescan(0).await });
        drop(rx);
        let rescan = rescan.await.unwrap();
        assert!(!matches!(
            rescan,
            Err(WalletAdminError::RescanUnavailable(_))
        ));
    }

    #[tokio::test]
    async fn normal_commands_are_fenced_during_rescan() {
        let coordinator = Arc::new(RescanCoordinator::new());
        coordinator.set_in_progress_for_test(true);
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let admin = NodeWalletAdmin::new(tx, coordinator.clone());
        let result = admin.balances().await;
        assert!(matches!(
            result,
            Err(WalletAdminError::RescanUnavailable(_))
        ));
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn control_commands_bypass_pre_enqueue_fence() {
        let coordinator = Arc::new(RescanCoordinator::new());
        coordinator.latch_fail_closed();
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let admin = NodeWalletAdmin::new(tx, coordinator.clone());
        let status = tokio::spawn(async move { admin.status().await });
        match rx.recv().await.unwrap() {
            WalletCommand::Status { reply } => {
                let _ = reply.send(Err(WalletAdminError::Internal(
                    "status reached".to_string(),
                )));
            }
            _ => panic!("unexpected command"),
        }
        assert!(matches!(
            status.await.unwrap(),
            Err(WalletAdminError::Internal(message)) if message == "status reached"
        ));

        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let admin = NodeWalletAdmin::new(tx, coordinator.clone());
        let lock = tokio::spawn(async move { admin.lock().await });
        match rx.recv().await.unwrap() {
            WalletCommand::Lock { reply } => {
                let _ = reply.send(Err(WalletAdminError::Internal("lock reached".to_string())));
            }
            _ => panic!("unexpected command"),
        }
        assert!(matches!(
            lock.await.unwrap(),
            Err(WalletAdminError::Internal(message)) if message == "lock reached"
        ));

        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let admin = NodeWalletAdmin::new(tx, coordinator.clone());
        let native_status = tokio::spawn(async move { admin.native_status().await });
        match rx.recv().await.unwrap() {
            WalletCommand::NativeStatus { reply } => {
                let _ = reply.send(Err(WalletAdminError::Internal(
                    "native status reached".to_string(),
                )));
            }
            _ => panic!("unexpected command"),
        }
        assert!(matches!(
            native_status.await.unwrap(),
            Err(WalletAdminError::Internal(message)) if message == "native status reached"
        ));
    }

    #[tokio::test]
    async fn queued_non_control_command_is_rejected_by_execution_fence() {
        let (reply_tx, reply_rx) = oneshot::channel();
        WalletCommand::Balances { reply: reply_tx }.reject_during_rescan();
        assert!(matches!(
            reply_rx.await.unwrap(),
            Err(WalletAdminError::RescanUnavailable(_))
        ));
    }

    struct FailingInvalidationStore;

    impl WalletStore for FailingInvalidationStore {
        fn begin_read(&self) -> Result<Box<dyn WalletRead>, WalletStoreError> {
            panic!("read is not used by this test")
        }

        fn begin_write(&self) -> Result<Box<dyn WalletWrite>, WalletStoreError> {
            Err(WalletStoreError::Decode("injected".to_string()))
        }
    }

    #[tokio::test]
    async fn invalidation_write_failure_latches_fail_closed_guards() {
        let coordinator = RescanCoordinator::new();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            super::mark_scan_invalidated(&FailingInvalidationStore, &coordinator)
        }));
        assert!(result.is_ok());
        assert!(coordinator.fail_closed());
        assert!(coordinator.in_progress());
        assert!(coordinator.scan_rebuild_in_progress());
    }
}

#[cfg(test)]
mod scan_invalidation_tests {
    use super::*;
    use ergo_wallet_service::wallet::tables::{WALLET_SCANS, WALLET_SCAN_INVALIDATED};

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
        let coordinator = RescanCoordinator::new();
        let (_d, db) = temp_db();
        assert!(!flag_set(&db), "flag starts clear");
        let store: Arc<dyn ergo_wallet_service::wallet::WalletStore> = Arc::new(
            ergo_wallet_service::wallet::RedbWalletStore::new(db.clone()),
        );
        mark_scan_invalidated(store.as_ref(), &coordinator);
        assert!(flag_set(&db), "flag set after mark");
        assert!(coordinator.fail_closed());
        assert!(coordinator.in_progress());
        assert!(coordinator.scan_rebuild_in_progress());
    }

    #[test]
    fn wallet_state_hook_snapshots_trees_and_pubkeys_together() {
        let state = Arc::new(RwLock::new(ergo_wallet_service::state::WalletState::empty(
            false,
        )));
        state
            .write()
            .insert_tracked_pubkey(0, [2; 33], ergo_ser::address::NetworkPrefix::Mainnet)
            .unwrap();
        let (_dir, db) = temp_db();
        let hook = WalletStateHook::new(
            state,
            Arc::new(ergo_wallet_service::wallet::RedbWalletStore::new(db)),
            Arc::new(RescanCoordinator::new()),
        );
        let (trees, pubkeys) =
            ergo_wallet_service::wallet::WalletApplyHook::wallet_state_snapshot(&hook);
        assert!(!trees.is_empty());
        assert!(!pubkeys.is_empty());
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
        let store: Arc<dyn ergo_wallet_service::wallet::WalletStore> = Arc::new(
            ergo_wallet_service::wallet::RedbWalletStore::new(db.clone()),
        );
        let hook = WalletStateHook::new(
            Arc::new(RwLock::new(ergo_wallet_service::state::WalletState::empty(
                false,
            ))),
            store,
            Arc::new(RescanCoordinator::new()),
        );
        // match_boxes loads the registry first (regardless of the box slice), so
        // the corrupt row trips the Err branch even with no boxes.
        let out = ergo_wallet_service::wallet::WalletApplyHook::match_boxes(&hook, &[]);
        assert!(out.is_empty());
        assert!(
            flag_set(&db),
            "a registry load failure must set WALLET_SCAN_INVALIDATED for rescan"
        );
    }
}
