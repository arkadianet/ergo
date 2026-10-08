//! Typed transport facade over the daemon's serialized engine host.
use super::native;
use crate::host::WalletHost;
use ergo_wallet_protocol::scala::{admin_advanced, multi_sig, scan, sending, types};
use ergo_wallet_protocol::WalletAdminError;

pub(crate) struct WalletApi {
    pub host: WalletHost,
    pub reads: crate::api::ApiContext,
}
impl WalletApi {
    pub async fn status(&self) -> Result<types::WalletStatus, WalletAdminError> {
        self.host.status().await
    }
    pub async fn init(
        &self,
        pass: String,
        mnemonic_pass: String,
        strength_words: u8,
    ) -> Result<String, WalletAdminError> {
        self.host
            .call(move |engine| engine.init(pass, mnemonic_pass, strength_words))
            .await
    }
    pub async fn restore(
        &self,
        mnemonic: String,
        mnemonic_pass: String,
        pass: String,
        use_pre_1627: bool,
    ) -> Result<(), WalletAdminError> {
        self.host
            .call(move |engine| engine.restore(mnemonic, mnemonic_pass, pass, use_pre_1627))
            .await
    }
    pub async fn unlock(&self, pass: String) -> Result<(), WalletAdminError> {
        self.host.call(move |engine| engine.unlock(pass)).await
    }
    pub async fn lock(&self) -> Result<(), WalletAdminError> {
        self.host.lock().await
    }
    pub async fn check(
        &self,
        mnemonic: String,
        mnemonic_pass: String,
    ) -> Result<bool, WalletAdminError> {
        self.host
            .call(move |engine| engine.check(mnemonic, mnemonic_pass))
            .await
    }
    pub async fn rescan(&self, from_height: u32) -> Result<(), WalletAdminError> {
        self.host.rescan(from_height).await
    }
    pub async fn update_change_address(&self, address: String) -> Result<(), WalletAdminError> {
        self.host
            .call(move |engine| engine.update_change_address(address))
            .await
    }
    pub async fn balances(&self) -> Result<types::WalletBalances, WalletAdminError> {
        self.host.call(move |engine| engine.balances()).await
    }
    pub async fn balances_with_unconfirmed(
        &self,
    ) -> Result<types::WalletBalances, WalletAdminError> {
        self.host
            .call_spending(move |engine| engine.balances_with_unconfirmed())
            .await
    }
    pub async fn addresses(&self) -> Result<types::WalletAddressList, WalletAdminError> {
        self.host.call(move |engine| engine.addresses()).await
    }
    pub async fn boxes(
        &self,
        page: types::Page,
    ) -> Result<types::WalletBoxesPage, WalletAdminError> {
        self.host.call(move |engine| engine.boxes(page)).await
    }
    pub async fn boxes_unspent(
        &self,
        page: types::Page,
    ) -> Result<types::WalletBoxesPage, WalletAdminError> {
        self.host
            .call(move |engine| engine.boxes_unspent(page))
            .await
    }
    pub async fn transactions(
        &self,
        page: types::Page,
    ) -> Result<types::WalletTransactionsPage, WalletAdminError> {
        self.host
            .call(move |engine| engine.transactions(page))
            .await
    }
    pub async fn transaction_by_id(
        &self,
        tx_id_hex: String,
    ) -> Result<Option<types::WalletTransactionEntry>, WalletAdminError> {
        self.host
            .call(move |engine| engine.transaction_by_id(tx_id_hex))
            .await
    }
    pub async fn transactions_by_scan_id(
        &self,
        scan_id: u32,
        page: types::Page,
    ) -> Result<types::WalletTransactionsPage, WalletAdminError> {
        self.host
            .call(move |engine| engine.transactions_by_scan_id(scan_id, page))
            .await
    }
    pub async fn payment_send(
        &self,
        requests: Vec<sending::PaymentRequestDto>,
    ) -> Result<String, WalletAdminError> {
        self.host
            .call_spending_async(move |engine| {
                Box::pin(async move { engine.payment_send(requests).await })
            })
            .await
    }
    pub async fn retrieve_rewards(
        &self,
        req: native::dto::RetrieveRewardsRequest,
    ) -> Result<native::dto::RetrieveRewardsResultDto, WalletAdminError> {
        self.host
            .call_spending_async(move |engine| {
                Box::pin(async move { engine.retrieve_rewards(req).await })
            })
            .await
    }
    pub async fn transaction_generate(
        &self,
        request: sending::TransactionGenerateRequest,
    ) -> Result<sending::TransactionGenerateResponse, WalletAdminError> {
        self.host
            .call_spending(move |engine| engine.transaction_generate(request))
            .await
    }
    pub async fn transaction_generate_unsigned(
        &self,
        request: sending::TransactionGenerateUnsignedRequest,
    ) -> Result<sending::TransactionGenerateUnsignedResponse, WalletAdminError> {
        self.host
            .call_spending(move |engine| engine.transaction_generate_unsigned(request))
            .await
    }
    pub async fn transaction_sign(
        &self,
        request: sending::TransactionSignRequest,
    ) -> Result<sending::TransactionSignResponse, WalletAdminError> {
        self.host
            .call_spending(move |engine| engine.transaction_sign(request))
            .await
    }
    pub async fn transaction_send(
        &self,
        request: sending::TransactionSendRequest,
    ) -> Result<String, WalletAdminError> {
        self.host
            .call_spending_async(move |engine| {
                Box::pin(async move { engine.transaction_send(request).await })
            })
            .await
    }
    pub async fn boxes_collect(
        &self,
        request: sending::BoxesCollectRequest,
    ) -> Result<sending::BoxesCollectResponse, WalletAdminError> {
        self.host
            .call_spending(move |engine| engine.boxes_collect(request))
            .await
    }
    pub async fn generate_commitments(
        &self,
        request: multi_sig::GenerateCommitmentsRequest,
    ) -> Result<multi_sig::GenerateCommitmentsResponse, WalletAdminError> {
        self.host
            .call_spending(move |engine| engine.generate_commitments(request))
            .await
    }
    pub async fn extract_hints(
        &self,
        request: multi_sig::HintExtractionRequest,
    ) -> Result<multi_sig::HintExtractionResponse, WalletAdminError> {
        self.host
            .call_spending(move |engine| engine.extract_hints(request))
            .await
    }
    pub async fn derive_key(
        &self,
        request: admin_advanced::DeriveKeyRequest,
    ) -> Result<admin_advanced::DeriveKeyResponse, WalletAdminError> {
        self.host
            .call(move |engine| engine.derive_key(request))
            .await
    }
    pub async fn derive_next_key(
        &self,
    ) -> Result<admin_advanced::DeriveNextKeyResponse, WalletAdminError> {
        self.host.call(move |engine| engine.derive_next_key()).await
    }
    pub async fn get_private_key(
        &self,
        request: admin_advanced::GetPrivateKeyRequest,
    ) -> Result<admin_advanced::GetPrivateKeyResponse, WalletAdminError> {
        self.host
            .call(move |engine| engine.get_private_key(request))
            .await
    }
    pub async fn register_scan(
        &self,
        request: scan::ScanRequestDto,
    ) -> Result<u16, WalletAdminError> {
        self.host
            .call(move |engine| engine.register_scan(request))
            .await
    }
    pub async fn deregister_scan(&self, scan_id: u16) -> Result<(), WalletAdminError> {
        self.host
            .call(move |engine| engine.deregister_scan(scan_id))
            .await
    }
    pub async fn list_scans(&self) -> Result<Vec<scan::ScanDto>, WalletAdminError> {
        self.host.call(move |engine| engine.list_scans()).await
    }
    pub async fn scan_unspent_boxes(
        &self,
        scan_id: u16,
        filter: scan::ScanBoxFilter,
    ) -> Result<Vec<scan::ScanBoxEntry>, WalletAdminError> {
        self.host
            .call_spending(move |engine| engine.scan_unspent_boxes(scan_id, filter))
            .await
    }
    pub async fn scan_spent_boxes(
        &self,
        scan_id: u16,
        filter: scan::ScanBoxFilter,
    ) -> Result<Vec<scan::ScanBoxEntry>, WalletAdminError> {
        self.host
            .call(move |engine| engine.scan_spent_boxes(scan_id, filter))
            .await
    }
    pub async fn scan_stop_tracking(
        &self,
        scan_id: u16,
        box_id: String,
    ) -> Result<(), WalletAdminError> {
        self.host
            .call(move |engine| engine.scan_stop_tracking(scan_id, box_id))
            .await
    }
    pub async fn scan_add_box(
        &self,
        scan_ids: Vec<u16>,
        box_json: serde_json::Value,
    ) -> Result<String, WalletAdminError> {
        self.host
            .call(move |engine| {
                engine.scan_add_box(&scan_ids, || {
                    ergo_rest_json::decode::decode_on_chain_ergo_box_json(&box_json)
                        .map_err(WalletAdminError::BadRequest)
                })
            })
            .await
    }
    pub async fn scan_p2s_rule(&self, p2s: String) -> Result<u16, WalletAdminError> {
        self.host
            .call(move |engine| engine.scan_p2s_rule(p2s))
            .await
    }
    pub async fn native_balance(
        &self,
        include_unconfirmed: bool,
    ) -> Result<native::dto::WalletBalanceDto, WalletAdminError> {
        self.host
            .call_spending(move |engine| engine.native_balance(include_unconfirmed))
            .await
    }
    pub async fn native_status(&self) -> Result<native::dto::WalletStatusDto, WalletAdminError> {
        self.host.native_status().await
    }
    pub async fn native_addresses(
        &self,
        offset: u32,
        limit: u32,
    ) -> Result<native::dto::AddressPage, WalletAdminError> {
        self.host
            .call(move |engine| engine.native_addresses(offset, limit))
            .await
    }
    pub async fn native_boxes(
        &self,
        offset: u32,
        limit: u32,
    ) -> Result<native::dto::BoxPage, WalletAdminError> {
        self.host
            .call(move |engine| engine.native_boxes(offset, limit))
            .await
    }
    pub async fn native_box_by_id(
        &self,
        box_id_hex: String,
    ) -> Result<Option<native::dto::WalletBoxSummary>, WalletAdminError> {
        self.host
            .call(move |engine| engine.native_box_by_id(box_id_hex))
            .await
    }
    pub async fn native_transactions(
        &self,
        offset: u32,
        limit: u32,
    ) -> Result<native::dto::TxPage, WalletAdminError> {
        self.host
            .call(move |engine| engine.native_transactions(offset, limit))
            .await
    }
    pub async fn native_transaction_by_id(
        &self,
        tx_id_hex: String,
    ) -> Result<Option<native::dto::WalletTransactionSummary>, WalletAdminError> {
        self.host
            .call(move |engine| engine.native_transaction_by_id(tx_id_hex))
            .await
    }
    pub async fn select_boxes(
        &self,
        req: native::dto::BoxSelectRequest,
    ) -> Result<native::dto::BoxSelectResponse, WalletAdminError> {
        self.host
            .call_spending(move |engine| engine.native_select_boxes(req))
            .await
    }
    pub async fn build_transaction(
        &self,
        intent: native::dto::TxIntent,
    ) -> Result<native::dto::BuildTxResponse, WalletAdminError> {
        self.host
            .call_spending(move |engine| engine.native_build_transaction(intent))
            .await
    }
    pub async fn sign_transaction(
        &self,
        req: native::dto::SignTxRequest,
    ) -> Result<native::dto::SignTxResponse, WalletAdminError> {
        self.host
            .call_spending(move |engine| engine.native_sign_transaction(req))
            .await
    }
    pub async fn mining_jobs(&self) -> Result<native::dto::WalletJobs, WalletAdminError> {
        self.host.call(move |engine| engine.mining_jobs()).await
    }
    pub async fn create_mining_job(
        &self,
        request: native::dto::WalletJobRequest,
    ) -> Result<native::dto::WalletJob, WalletAdminError> {
        self.host
            .call_spending_async(move |engine| {
                Box::pin(async move { engine.create_mining_job(request).await })
            })
            .await
    }
    pub async fn cancel_mining_job(
        &self,
        job_id: String,
    ) -> Result<native::dto::WalletJob, WalletAdminError> {
        self.host
            .call_spending_async(move |engine| {
                Box::pin(async move { engine.cancel_mining_job(&job_id).await })
            })
            .await
    }
    pub async fn send_transaction(
        &self,
        req: native::dto::SendTxRequest,
    ) -> Result<native::dto::SendTxResponse, WalletAdminError> {
        self.host
            .call_spending_async(move |engine| {
                Box::pin(async move { engine.native_send_transaction(req).await })
            })
            .await
    }
}
