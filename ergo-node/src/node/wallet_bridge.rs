//! The node's thin adapter over the wallet engine
//! ([`ergo_wallet_service::engine::WalletEngine`]).
//!
//! Single-writer pattern: [`EmbeddedWallet::new`] builds the engine and
//! begins a wallet session for it, returning the three pieces that share the
//! engine's rescan coordinator — the [`NodeWalletAdmin`] (the `ergo_api`
//! `WalletAdmin` impl), the [`WalletWriter`] task that owns the engine (and
//! through it the wallet storage + state behind a `RwLock`), and the
//! chain-apply [`WalletStateHook`]. The axum API task sends
//! [`WalletCommand`]s through the admin; the writer processes them serially,
//! calls the engine method for each, and sends the response back via the
//! per-command oneshot channel. Everything wallet-specific lives in the
//! engine; this module owns only the transport and runtime concerns:
//!
//! - the command channel, the pre-enqueue and execution rescan fences, and
//!   the rescan-control policy;
//! - spawning a rescan's [`ergo_wallet_service::engine::RescanJob`] on a
//!   blocking thread and tracking it with the wallet session;
//! - the node-side seam implementations: [`ChainStateAccessorImpl`]
//!   (`WalletChainAccess` over `ergo-state`), [`ChainSnapshot`]
//!   (`SigningView`), [`NodeSubmitAdapter`] (`TxSubmitter` over the node's
//!   admission bridge) and [`MempoolViewOverlay`] (`MempoolOverlay` over the
//!   API mempool view);
//! - decoding the Scala box JSON of `/scan/addBox`;
//! - the in-process chain client / API adapter (`chain_client`).

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::{mpsc, oneshot};

use ergo_api::wallet::WalletAdmin;
use ergo_primitives::digest::Digest32;
use ergo_ser::ergo_box::ErgoBox;
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
    WalletChainAccess, WalletEngine, WalletEngineParts,
};
use ergo_wallet_service::wallet::scan::{RescanBlock, RescanReadError};

pub mod chain_client;
pub mod chain_snapshot;
pub use chain_client::{
    ChainClientAdapter, InProcessChainClient, IntoChainSubmitter, NodeChainClient,
    WalletChainAdapter,
};
use chain_snapshot::chain_state_read_failed;
pub use chain_snapshot::ChainSnapshot;
/// The chain-apply hook lives in the wallet service; the node wires it into
/// block apply / rollback.
pub use ergo_wallet_service::engine::WalletStateHook;

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

/// `WalletAdmin` impl backed by a command channel. Built by
/// [`EmbeddedWallet::new`] and handed to `ergo-api`'s router builder.
pub struct NodeWalletAdmin {
    tx: mpsc::Sender<WalletCommand>,
    /// The wallet's rescan coordinator: the pre-enqueue fence reads it.
    rescan: Arc<RescanCoordinator>,
}

impl NodeWalletAdmin {
    /// Wrap the command channel of the writer whose engine owns `rescan`.
    /// Private: only [`EmbeddedWallet::new`] (and this module's tests) pair
    /// an admin with its writer's coordinator.
    fn new(tx: mpsc::Sender<WalletCommand>, rescan: Arc<RescanCoordinator>) -> Self {
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

/// Capacity of the command channel between the API and the wallet writer.
const WALLET_COMMAND_QUEUE: usize = 64;

/// The embedded wallet of one node wallet session, wired around a single
/// [`WalletEngine`]: the API-side [`NodeWalletAdmin`], the [`WalletWriter`]
/// task that owns the engine, and the chain-apply [`WalletStateHook`].
///
/// All three take the engine's rescan coordinator, so the admin's
/// pre-enqueue fence, the writer's execution fence and rescans, and the
/// hook's full-rebuild quiesce and rollback guard always act on the same
/// wallet; the session registry holds it too, so a shutdown of this session
/// cancels this wallet's rescan. None of them can be handed a coordinator of
/// its own.
pub struct EmbeddedWallet {
    /// The `WalletAdmin` the API serves the wallet routes through.
    pub admin: NodeWalletAdmin,
    /// The single writer; spawn [`WalletWriter::run`] on the runtime.
    pub writer: WalletWriter,
    /// The chain-apply hook (and its rollback guard) for block apply and
    /// rollback.
    pub hook: WalletStateHook,
    /// This wallet session's id: the writer's rescan tasks are tracked under
    /// it, and a node shutdown is routed by it.
    pub(crate) session_id: u64,
}

impl EmbeddedWallet {
    /// Build the engine from `parts` and begin a new node wallet session for
    /// it, registering the engine's rescan coordinator for shutdown routing.
    pub fn new(parts: WalletEngineParts) -> Self {
        let engine = WalletEngine::new(parts);
        let rescan = engine.rescan_coordinator().clone();
        let session_id = crate::wallet_boot::begin_wallet_session(rescan.clone());
        let (tx, rx) = mpsc::channel(WALLET_COMMAND_QUEUE);
        Self {
            admin: NodeWalletAdmin::new(tx, rescan),
            hook: engine.state_hook(),
            writer: WalletWriter {
                rx,
                engine,
                session_id,
            },
            session_id,
        }
    }
}

/// The wallet's single writer: owns the [`WalletEngine`] and serves the
/// [`NodeWalletAdmin`]'s commands one at a time, in arrival order, until
/// every admin handle is dropped. Built by [`EmbeddedWallet::new`].
pub struct WalletWriter {
    rx: mpsc::Receiver<WalletCommand>,
    engine: WalletEngine,
    session_id: u64,
}

impl WalletWriter {
    /// The writer-task loop: receive each command, reject it at execution
    /// time while the rescan fence is up (unless it is rescan control), and
    /// otherwise dispatch it to the engine; each reply goes back via the
    /// command's oneshot.
    pub async fn run(self) {
        let Self {
            mut rx,
            mut engine,
            session_id,
        } = self;
        while let Some(cmd) = rx.recv().await {
            if !cmd.is_rescan_control() && engine.rescan_coordinator().operations_fenced() {
                cmd.reject_during_rescan();
                continue;
            }
            dispatch(&mut engine, session_id, cmd).await;
        }
    }
}

/// Run one command against the engine and send its reply. Commands run one
/// at a time, in arrival order: this is the wallet's single writer, and the
/// only holder of the engine's `&mut`.
async fn dispatch(engine: &mut WalletEngine, wallet_session_id: u64, cmd: WalletCommand) {
    match cmd {
        WalletCommand::Status { reply } => {
            let _ = reply.send(engine.status());
        }
        WalletCommand::Init {
            pass,
            mnemonic_pass,
            strength,
            reply,
        } => {
            let _ = reply.send(engine.init(pass, mnemonic_pass, strength));
        }
        WalletCommand::Restore {
            mnemonic,
            mnemonic_pass,
            pass,
            use_pre_1627,
            reply,
        } => {
            let _ = reply.send(engine.restore(mnemonic, mnemonic_pass, pass, use_pre_1627));
        }
        WalletCommand::Rescan { from_height, reply } => {
            rescan(engine, wallet_session_id, from_height, reply).await
        }
        WalletCommand::Unlock { pass, reply } => {
            let _ = reply.send(engine.unlock(pass));
        }
        WalletCommand::Lock { reply } => {
            let _ = reply.send(engine.lock());
        }
        WalletCommand::Check {
            mnemonic,
            mnemonic_pass,
            reply,
        } => {
            let _ = reply.send(engine.check(mnemonic, mnemonic_pass));
        }
        WalletCommand::UpdateChangeAddress { address, reply } => {
            let _ = reply.send(engine.update_change_address(address));
        }
        WalletCommand::Balances { reply } => {
            let _ = reply.send(engine.balances());
        }
        WalletCommand::BalancesWithUnconfirmed { reply } => {
            let _ = reply.send(engine.balances_with_unconfirmed());
        }
        WalletCommand::NativeBalance {
            include_unconfirmed,
            reply,
        } => {
            let _ = reply.send(engine.native_balance(include_unconfirmed));
        }
        WalletCommand::NativeStatus { reply } => {
            let _ = reply.send(engine.native_status());
        }
        WalletCommand::NativeAddresses {
            offset,
            limit,
            reply,
        } => {
            let _ = reply.send(engine.native_addresses(offset, limit));
        }
        WalletCommand::NativeBoxes {
            offset,
            limit,
            reply,
        } => {
            let _ = reply.send(engine.native_boxes(offset, limit));
        }
        WalletCommand::NativeBoxById { box_id_hex, reply } => {
            let _ = reply.send(engine.native_box_by_id(box_id_hex));
        }
        WalletCommand::NativeTransactions {
            offset,
            limit,
            reply,
        } => {
            let _ = reply.send(engine.native_transactions(offset, limit));
        }
        WalletCommand::NativeTransactionById { tx_id_hex, reply } => {
            let _ = reply.send(engine.native_transaction_by_id(tx_id_hex));
        }
        WalletCommand::NativeSelectBoxes { req, reply } => {
            let _ = reply.send(engine.native_select_boxes(*req));
        }
        WalletCommand::NativeBuildTransaction { intent, reply } => {
            let _ = reply.send(engine.native_build_transaction(*intent));
        }
        WalletCommand::NativeSignTransaction { req, reply } => {
            let _ = reply.send(engine.native_sign_transaction(*req));
        }
        WalletCommand::NativeSendTransaction { req, reply } => {
            let _ = reply.send(engine.native_send_transaction(*req).await);
        }
        WalletCommand::Addresses { reply } => {
            let _ = reply.send(engine.addresses());
        }
        WalletCommand::Boxes { page, reply } => {
            let _ = reply.send(engine.boxes(page));
        }
        WalletCommand::BoxesUnspent { page, reply } => {
            let _ = reply.send(engine.boxes_unspent(page));
        }
        WalletCommand::Transactions { page, reply } => {
            let _ = reply.send(engine.transactions(page));
        }
        WalletCommand::TransactionById { tx_id_hex, reply } => {
            let _ = reply.send(engine.transaction_by_id(tx_id_hex));
        }
        WalletCommand::TransactionsByScanId {
            scan_id,
            page,
            reply,
        } => {
            let _ = reply.send(engine.transactions_by_scan_id(scan_id, page));
        }
        WalletCommand::PaymentSend { requests, reply } => {
            let _ = reply.send(engine.payment_send(requests).await);
        }
        WalletCommand::RetrieveRewards { req, reply } => {
            let _ = reply.send(engine.retrieve_rewards(req).await);
        }
        WalletCommand::TransactionGenerate { request, reply } => {
            let _ = reply.send(engine.transaction_generate(request));
        }
        WalletCommand::TransactionGenerateUnsigned { request, reply } => {
            let _ = reply.send(engine.transaction_generate_unsigned(request));
        }
        WalletCommand::TransactionSign { request, reply } => {
            let _ = reply.send(engine.transaction_sign(request));
        }
        WalletCommand::TransactionSend { request, reply } => {
            let _ = reply.send(engine.transaction_send(request).await);
        }
        WalletCommand::BoxesCollect { request, reply } => {
            let _ = reply.send(engine.boxes_collect(request));
        }
        WalletCommand::GenerateCommitments { request, reply } => {
            let _ = reply.send(engine.generate_commitments(request));
        }
        WalletCommand::ExtractHints { request, reply } => {
            let _ = reply.send(engine.extract_hints(request));
        }
        WalletCommand::DeriveKey { request, reply } => {
            let _ = reply.send(engine.derive_key(request));
        }
        WalletCommand::DeriveNextKey { reply } => {
            let _ = reply.send(engine.derive_next_key());
        }
        WalletCommand::GetPrivateKey { request, reply } => {
            let _ = reply.send(engine.get_private_key(request));
        }
        WalletCommand::RegisterScan { request, reply } => {
            let _ = reply.send(engine.register_scan(request));
        }
        WalletCommand::DeregisterScan { scan_id, reply } => {
            let _ = reply.send(engine.deregister_scan(scan_id));
        }
        WalletCommand::ListScans { reply } => {
            let _ = reply.send(engine.list_scans());
        }
        WalletCommand::ScanUnspentBoxes {
            scan_id,
            filter,
            reply,
        } => {
            let _ = reply.send(engine.scan_unspent_boxes(scan_id, filter));
        }
        WalletCommand::ScanSpentBoxes {
            scan_id,
            filter,
            reply,
        } => {
            let _ = reply.send(engine.scan_spent_boxes(scan_id, filter));
        }
        WalletCommand::ScanStopTracking {
            scan_id,
            box_id,
            reply,
        } => {
            let _ = reply.send(engine.scan_stop_tracking(scan_id, box_id));
        }
        WalletCommand::ScanAddBox {
            scan_ids,
            box_json,
            reply,
        } => {
            let _ = reply.send(engine.scan_add_box(&scan_ids, || decode_scan_box(&box_json)));
        }
        WalletCommand::ScanP2sRule { p2s, reply } => {
            let _ = reply.send(engine.scan_p2s_rule(p2s));
        }
    }
}

/// `/wallet/rescan`: the engine validates and claims the rescan, the replay
/// runs on a blocking thread tracked with the wallet session (so shutdown
/// waits for it), and the reply is sent once the task is registered — the
/// RPC never waits for the replay itself.
async fn rescan(
    engine: &mut WalletEngine,
    wallet_session_id: u64,
    from_height: u32,
    reply: oneshot::Sender<Result<(), WalletAdminError>>,
) {
    let job = match engine.prepare_rescan(from_height) {
        Ok(job) => job,
        Err(error) => {
            let _ = reply.send(Err(error));
            return;
        }
    };
    let uses_service = job.uses_service();
    let task = tokio::task::spawn_blocking(move || job.run());
    if let Err(error) = crate::wallet_boot::track_wallet_task(wallet_session_id, task).await {
        if uses_service {
            tracing::error!(%error, "wallet service rescan task failed");
        } else {
            tracing::error!(%error, "wallet rescan task failed");
        }
        let _ = reply.send(Err(WalletAdminError::Internal(format!(
            "wallet rescan task failed: {error}"
        ))));
        return;
    }
    let _ = reply.send(Ok(()));
}

/// Decode the `box` member of a `/scan/addBox` body (Scala SDK `ErgoBox`
/// JSON) for the engine. The JSON wire shape is the transport's concern; the
/// decoder keeps on-chain wire bytes verbatim so the box id is preserved.
fn decode_scan_box(box_json: &serde_json::Value) -> Result<ErgoBox, WalletAdminError> {
    ergo_rest_json::decode::decode_on_chain_ergo_box_json(box_json)
        .map_err(WalletAdminError::BadRequest)
}
#[cfg(test)]
mod command_fencing_tests {
    use super::*;
    use ergo_wallet_service::wallet::{RedbWalletStore, WalletStore};

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
        // A real partial rescan claim (cursor 0, tip 1): `in_progress` is set
        // without the fail-closed or scan-rebuild fences, so the admin's
        // fence has only `in_progress` to trip on.
        let dir = tempfile::tempdir().unwrap();
        let store = RedbWalletStore::new(Arc::new(
            redb::Database::create(dir.path().join("wallet.redb")).unwrap(),
        ));
        let mut write = store.begin_write().unwrap();
        write.set_scan_cursor(0, None).unwrap();
        write.commit().unwrap();
        let coordinator = Arc::new(RescanCoordinator::new());
        coordinator.begin_rescan(1, &store, 1).unwrap();
        assert!(coordinator.in_progress());
        assert!(!coordinator.fail_closed());
        assert!(!coordinator.scan_rebuild_in_progress());
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
}
