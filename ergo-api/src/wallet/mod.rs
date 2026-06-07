//! REST handlers for the `/wallet/*` routes per spec §8.
//!
//! Submodules:
//! - `lifecycle`  — status/init/restore/unlock/lock/check
//! - `state_mut`  — rescan/updateChangeAddress
//! - `reads`      — balances/addresses/boxes/transactions
//! - `sending`    — 5 send handlers + DTOs
//! - `stubs`      — deferred handlers returning 501
//! - `lock_guard` — request-time guard helper for unlock-gated routes
//! - `types`      — Scala-camelCase response DTOs
//!
//! Router builder: `router(admin) -> axum::Router`.

pub mod admin_advanced;
pub mod lifecycle;
pub mod lock_guard;
pub mod multi_sig;
pub mod reads;
pub mod sending;
pub mod state_mut;
pub mod types;

use std::sync::Arc;

/// `WalletAdmin` is the trait the integrator implements to give
/// the API task access to the wallet. The trait is `async` because
/// most lifecycle operations cross task boundaries (the wallet
/// owner is a single-writer task; the API task sends commands via
/// channel). Implementors in `ergo-node` wrap the send-and-await
/// in this trait so the handlers don't need to know about channels.
///
/// Read-side accessors return owned values (snapshots) so the
/// handler doesn't hold a lock across an `await`.
#[async_trait::async_trait]
pub trait WalletAdmin: Send + Sync {
    // --- lifecycle ---

    /// Current status (always served — lock-aware).
    async fn status(&self) -> Result<types::WalletStatus, WalletAdminError>;

    /// Generate a fresh wallet. `pass` is the wallet password;
    /// `mnemonic_pass` is the BIP39 passphrase (empty allowed).
    /// Returns the generated mnemonic phrase.
    async fn init(
        &self,
        pass: String,
        mnemonic_pass: String,
        strength_words: u8,
    ) -> Result<String, WalletAdminError>;

    /// Restore from a known mnemonic.
    async fn restore(
        &self,
        mnemonic: String,
        mnemonic_pass: String,
        pass: String,
        use_pre_1627: bool,
    ) -> Result<(), WalletAdminError>;

    /// Unlock the wallet with the given password.
    async fn unlock(&self, pass: String) -> Result<(), WalletAdminError>;

    /// Lock the wallet (drops in-memory master key).
    async fn lock(&self) -> Result<(), WalletAdminError>;

    /// Verify a mnemonic matches the currently-unlocked wallet.
    /// Returns false when wallet is locked (Scala parity).
    async fn check(
        &self,
        mnemonic: String,
        mnemonic_pass: String,
    ) -> Result<bool, WalletAdminError>;

    // --- cache-only mutations ---

    /// Trigger a full chain rescan from genesis.
    async fn rescan(&self, from_height: u32) -> Result<(), WalletAdminError>;

    /// Update the persisted change address. Address must point at
    /// a tracked pubkey (strict mode per spec §7.4).
    async fn update_change_address(&self, address: String) -> Result<(), WalletAdminError>;

    // --- reads ---

    /// Snapshot of confirmed balance.
    async fn balances(&self) -> Result<types::WalletBalances, WalletAdminError>;

    /// Confirmed balance with a single-hop mempool overlay folded in: pool
    /// outputs to wallet keys add; confirmed wallet boxes spent by pool txs
    /// subtract. Same wire shape as `balances`. NOT a full Scala
    /// `OffChainRegistry` — it does not net chains within the pool (a pool
    /// output later spent by another pool tx still counts), so it can
    /// overstate under chained mempool activity; exact for the common
    /// single-hop case. See the writer-side handler for the full scope note.
    async fn balances_with_unconfirmed(&self) -> Result<types::WalletBalances, WalletAdminError>;

    /// All visible addresses.
    async fn addresses(&self) -> Result<types::WalletAddressList, WalletAdminError>;

    /// Paginated wallet boxes.
    async fn boxes(&self, page: types::Page) -> Result<types::WalletBoxesPage, WalletAdminError>;

    /// Unspent boxes only.
    async fn boxes_unspent(
        &self,
        page: types::Page,
    ) -> Result<types::WalletBoxesPage, WalletAdminError>;

    /// Paginated wallet transactions.
    async fn transactions(
        &self,
        page: types::Page,
    ) -> Result<types::WalletTransactionsPage, WalletAdminError>;

    /// One transaction by id.
    async fn transaction_by_id(
        &self,
        tx_id_hex: String,
    ) -> Result<Option<types::WalletTransactionEntry>, WalletAdminError>;

    /// Wallet transactions filtered by scan id (spec §B-3).
    /// Only the default payments-scan id is supported; other ids
    /// return 404 from the handler. The trait returns Ok(empty) for
    /// the default id with no matches; Ok(filled) for matches; the
    /// handler maps `scan_id != default` to 404.
    async fn transactions_by_scan_id(
        &self,
        scan_id: u32,
        page: types::Page,
    ) -> Result<types::WalletTransactionsPage, WalletAdminError>;

    // --- send routes ---

    /// Build + sign + verify + submit using automatic box selection.
    /// Returns the submitted transaction ID string.
    async fn payment_send(
        &self,
        requests: Vec<sending::PaymentRequestDto>,
    ) -> Result<String, WalletAdminError>;

    /// Build + sign (no submit). Returns the signed-tx response (hex bytes).
    async fn transaction_generate(
        &self,
        request: sending::TransactionGenerateRequest,
    ) -> Result<sending::TransactionGenerateResponse, WalletAdminError>;

    /// Build only (no sign, no submit). Returns the unsigned-tx response (hex bytes).
    async fn transaction_generate_unsigned(
        &self,
        request: sending::TransactionGenerateUnsignedRequest,
    ) -> Result<sending::TransactionGenerateUnsignedResponse, WalletAdminError>;

    /// Sign a caller-supplied unsigned transaction (may use external secrets
    /// so this can work while the wallet is locked).
    async fn transaction_sign(
        &self,
        request: sending::TransactionSignRequest,
    ) -> Result<sending::TransactionSignResponse, WalletAdminError>;

    /// Build + sign + verify + submit with explicit input/dataInput overrides.
    /// Mirrors Scala's `sendTransactionR` (RequestsHolder path).
    /// Returns the submitted transaction ID string.
    async fn transaction_send(
        &self,
        request: sending::TransactionSendRequest,
    ) -> Result<String, WalletAdminError>;

    /// Run box selection without submitting. Returns selected + change boxes.
    async fn boxes_collect(
        &self,
        request: sending::BoxesCollectRequest,
    ) -> Result<sending::BoxesCollectResponse, WalletAdminError>;

    // --- multi-sig routes ---

    /// Generate sigma-protocol commitments for the given unsigned transaction.
    /// Returns `OwnCommitment` (secret, local) + `RealCommitment` (public, to share).
    async fn generate_commitments(
        &self,
        request: multi_sig::GenerateCommitmentsRequest,
    ) -> Result<multi_sig::GenerateCommitmentsResponse, WalletAdminError>;

    /// Extract hints from a signed transaction for the given real / simulated
    /// proposition sets.
    async fn extract_hints(
        &self,
        request: multi_sig::HintExtractionRequest,
    ) -> Result<multi_sig::HintExtractionResponse, WalletAdminError>;

    // --- advanced HD-key routes ---

    /// Derive a pubkey at an explicit BIP32 path and register it as a
    /// tracked address. Returns the resulting P2PK address.
    /// Fails with `WalletAdminError::Internal` wrapping
    /// `WalletError::DerivationPathExists` when the path is already tracked.
    async fn derive_key(
        &self,
        request: admin_advanced::DeriveKeyRequest,
    ) -> Result<admin_advanced::DeriveKeyResponse, WalletAdminError>;

    /// Derive the next sequential key at the EIP-3 base path
    /// (`m/44'/429'/0'/0/{head+1}`), increment the derivation head, and
    /// register the new address. Returns both the path and address.
    async fn derive_next_key(
        &self,
    ) -> Result<admin_advanced::DeriveNextKeyResponse, WalletAdminError>;

    /// Return the private scalar for the tracked address. Requires the
    /// `wallet.expose_private_keys = true` operator flag; returns
    /// `WalletAdminError::Forbidden` (HTTP 403) when disabled.
    async fn get_private_key(
        &self,
        request: admin_advanced::GetPrivateKeyRequest,
    ) -> Result<admin_advanced::GetPrivateKeyResponse, WalletAdminError>;
}

/// Errors the admin trait can return. Maps to HTTP responses in
/// the handler layer.
#[derive(Debug, thiserror::Error)]
pub enum WalletAdminError {
    #[error("wallet uninitialized")]
    Uninitialized,
    #[error("wallet locked")]
    Locked,
    #[error("invalid mnemonic")]
    InvalidMnemonic,
    #[error("wrong password")]
    WrongPassword,
    #[error("pruning unsupported for restore")]
    RestorePruningUnsupported,
    #[error("change address untracked")]
    ChangeAddressUntracked,
    #[error("scan not found")]
    ScanNotFound,
    /// A client-correctable request error — malformed input, insufficient
    /// funds, or a tx that fails structural validation (e.g. a dust output
    /// below the min box value). Maps to HTTP 400 so the caller can fix the
    /// request, rather than the opaque 500 that `Internal` implies.
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("internal: {0}")]
    Internal(String),
    /// Operation refused by an operator flag. Maps to HTTP 403.
    /// Used by `getPrivateKey` when `wallet.expose_private_keys = false`.
    #[error("forbidden: {0}")]
    Forbidden(String),
}

/// Build the `/wallet/*` axum router and, if `security` is `Some`,
/// wrap it with the [`crate::auth::require_api_key`] middleware via
/// `route_layer` — which fires only on matched routes. A plain `layer`
/// here would also wrap this subtree's implicit fallback, which
/// `Router::merge` then propagates router-wide, auth-gating every
/// unmatched path on the node (the `/emission/at` 403 regression).
/// Whole-prefix coverage — Scala's `(pathPrefix("wallet") & withAuth)`
/// rejects unknown subpaths on the key before route matching — is kept
/// via the explicit `/wallet` + `/wallet/*rest` catch-all routes, which
/// `route_layer` does cover.
///
/// **Security boundary**: callers MUST pass an explicit `Option` — no
/// convenience wrapper exists that hides the choice. Production callers
/// pass `Some(operator_security)`; tests that don't exercise the auth
/// gate pass `None` and document why at the call site. This makes
/// "no auth" a deliberate per-call decision rather than a default
/// fallthrough.
pub fn router_with_security(
    admin: Arc<dyn WalletAdmin>,
    security: Option<Arc<crate::auth::ApiSecurity>>,
) -> axum::Router {
    use axum::routing::{any, get, post};
    let r = axum::Router::new()
        .route("/wallet/status", get(lifecycle::status))
        .route("/wallet/init", post(lifecycle::init))
        .route("/wallet/restore", post(lifecycle::restore))
        .route("/wallet/unlock", post(lifecycle::unlock))
        .route("/wallet/lock", get(lifecycle::lock))
        .route("/wallet/check", post(lifecycle::check))
        .route("/wallet/rescan", post(state_mut::rescan))
        .route(
            "/wallet/updateChangeAddress",
            post(state_mut::update_change_address),
        )
        .route("/wallet/balances", get(reads::balances))
        .route(
            "/wallet/balances/withUnconfirmed",
            get(reads::balances_with_unconfirmed),
        )
        .route("/wallet/addresses", get(reads::addresses))
        .route("/wallet/boxes", get(reads::boxes))
        .route("/wallet/boxes/unspent", get(reads::boxes_unspent))
        .route("/wallet/boxes/collect", post(sending::boxes_collect))
        .route("/wallet/transactions", get(reads::transactions))
        .route("/wallet/transactionById", get(reads::transaction_by_id))
        .route(
            "/wallet/transactionsByScanId/:scan_id",
            get(reads::transactions_by_scan_id),
        )
        .route("/wallet/extractHints", post(multi_sig::extract_hints))
        .route(
            "/wallet/generateCommitments",
            post(multi_sig::generate_commitments),
        )
        .route("/wallet/transaction/sign", post(sending::transaction_sign))
        .route(
            "/wallet/transaction/generateUnsigned",
            post(sending::transaction_generate_unsigned),
        )
        .route(
            "/wallet/transaction/generate",
            post(sending::transaction_generate),
        )
        .route("/wallet/transaction/send", post(sending::transaction_send))
        .route("/wallet/payment/send", post(sending::payment_send))
        .route("/wallet/deriveKey", post(admin_advanced::derive_key))
        .route(
            "/wallet/deriveNextKey",
            get(admin_advanced::derive_next_key),
        )
        .route(
            "/wallet/getPrivateKey",
            post(admin_advanced::get_private_key),
        )
        // Whole-prefix gate parity: real catch-all routes (not a
        // fallback) so the `route_layer` below covers them.
        .route("/wallet", any(crate::auth::unknown_gated_subpath))
        .route("/wallet/*rest", any(crate::auth::unknown_gated_subpath))
        .with_state(admin);
    match security {
        Some(sec) => r.route_layer(axum::middleware::from_fn_with_state(
            sec,
            crate::auth::require_api_key,
        )),
        None => r,
    }
}

/// No-op `WalletAdmin` that returns `Uninitialized` for every call.
/// Used by the main `server::router()` (which preserves its existing
/// 5-arg signature) so existing tests that don't exercise wallet routes
/// continue to compile without changes.
pub struct NoopWalletAdmin;

#[async_trait::async_trait]
impl WalletAdmin for NoopWalletAdmin {
    async fn status(&self) -> Result<types::WalletStatus, WalletAdminError> {
        Ok(types::WalletStatus::default())
    }

    async fn init(
        &self,
        _pass: String,
        _mnemonic_pass: String,
        _strength_words: u8,
    ) -> Result<String, WalletAdminError> {
        Err(WalletAdminError::Uninitialized)
    }

    async fn restore(
        &self,
        _mnemonic: String,
        _mnemonic_pass: String,
        _pass: String,
        _use_pre_1627: bool,
    ) -> Result<(), WalletAdminError> {
        Err(WalletAdminError::Uninitialized)
    }

    async fn unlock(&self, _pass: String) -> Result<(), WalletAdminError> {
        Err(WalletAdminError::Uninitialized)
    }

    async fn lock(&self) -> Result<(), WalletAdminError> {
        Err(WalletAdminError::Uninitialized)
    }

    async fn check(
        &self,
        _mnemonic: String,
        _mnemonic_pass: String,
    ) -> Result<bool, WalletAdminError> {
        Err(WalletAdminError::Uninitialized)
    }

    async fn rescan(&self, _from_height: u32) -> Result<(), WalletAdminError> {
        Err(WalletAdminError::Uninitialized)
    }

    async fn update_change_address(&self, _address: String) -> Result<(), WalletAdminError> {
        Err(WalletAdminError::Uninitialized)
    }

    async fn balances(&self) -> Result<types::WalletBalances, WalletAdminError> {
        Err(WalletAdminError::Uninitialized)
    }

    async fn balances_with_unconfirmed(&self) -> Result<types::WalletBalances, WalletAdminError> {
        Err(WalletAdminError::Uninitialized)
    }

    async fn addresses(&self) -> Result<types::WalletAddressList, WalletAdminError> {
        Err(WalletAdminError::Uninitialized)
    }

    async fn boxes(&self, _page: types::Page) -> Result<types::WalletBoxesPage, WalletAdminError> {
        Err(WalletAdminError::Uninitialized)
    }

    async fn boxes_unspent(
        &self,
        _page: types::Page,
    ) -> Result<types::WalletBoxesPage, WalletAdminError> {
        Err(WalletAdminError::Uninitialized)
    }

    async fn transactions(
        &self,
        _page: types::Page,
    ) -> Result<types::WalletTransactionsPage, WalletAdminError> {
        Err(WalletAdminError::Uninitialized)
    }

    async fn transaction_by_id(
        &self,
        _tx_id_hex: String,
    ) -> Result<Option<types::WalletTransactionEntry>, WalletAdminError> {
        Err(WalletAdminError::Uninitialized)
    }

    async fn transactions_by_scan_id(
        &self,
        _scan_id: u32,
        _page: types::Page,
    ) -> Result<types::WalletTransactionsPage, WalletAdminError> {
        Err(WalletAdminError::Uninitialized)
    }

    async fn payment_send(
        &self,
        _requests: Vec<sending::PaymentRequestDto>,
    ) -> Result<String, WalletAdminError> {
        Err(WalletAdminError::Uninitialized)
    }

    async fn transaction_generate(
        &self,
        _request: sending::TransactionGenerateRequest,
    ) -> Result<sending::TransactionGenerateResponse, WalletAdminError> {
        Err(WalletAdminError::Uninitialized)
    }

    async fn transaction_generate_unsigned(
        &self,
        _request: sending::TransactionGenerateUnsignedRequest,
    ) -> Result<sending::TransactionGenerateUnsignedResponse, WalletAdminError> {
        Err(WalletAdminError::Uninitialized)
    }

    async fn transaction_sign(
        &self,
        _request: sending::TransactionSignRequest,
    ) -> Result<sending::TransactionSignResponse, WalletAdminError> {
        Err(WalletAdminError::Uninitialized)
    }

    async fn transaction_send(
        &self,
        _request: sending::TransactionSendRequest,
    ) -> Result<String, WalletAdminError> {
        Err(WalletAdminError::Uninitialized)
    }

    async fn boxes_collect(
        &self,
        _request: sending::BoxesCollectRequest,
    ) -> Result<sending::BoxesCollectResponse, WalletAdminError> {
        Err(WalletAdminError::Uninitialized)
    }

    async fn generate_commitments(
        &self,
        _request: multi_sig::GenerateCommitmentsRequest,
    ) -> Result<multi_sig::GenerateCommitmentsResponse, WalletAdminError> {
        Err(WalletAdminError::Uninitialized)
    }

    async fn extract_hints(
        &self,
        _request: multi_sig::HintExtractionRequest,
    ) -> Result<multi_sig::HintExtractionResponse, WalletAdminError> {
        Err(WalletAdminError::Uninitialized)
    }

    async fn derive_key(
        &self,
        _request: admin_advanced::DeriveKeyRequest,
    ) -> Result<admin_advanced::DeriveKeyResponse, WalletAdminError> {
        Err(WalletAdminError::Uninitialized)
    }

    async fn derive_next_key(
        &self,
    ) -> Result<admin_advanced::DeriveNextKeyResponse, WalletAdminError> {
        Err(WalletAdminError::Uninitialized)
    }

    async fn get_private_key(
        &self,
        _request: admin_advanced::GetPrivateKeyRequest,
    ) -> Result<admin_advanced::GetPrivateKeyResponse, WalletAdminError> {
        Err(WalletAdminError::Uninitialized)
    }
}
