//! REST handlers for the `/wallet/*` routes.
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
/// Native `/api/v1/wallet/*` surface (a second adapter over [`WalletAdmin`]).
pub mod native;
pub mod reads;
pub mod scan;
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
    /// `WalletAdmin::transactions_by_scan_id` serves the default payments
    /// scan (10, the wallet's own listing) AND user scan ids (transactions
    /// tagged at block apply). Unknown / deregistered scan ids return
    /// `Ok` with an empty page — the handler no longer maps them to 404
    /// (the pre-scan-subsystem behavior).
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

    /// Sweep all matured miner-reward boxes into one P2PK output, EIP-27-correct
    /// (burns the re-emission token, routes its ERG to pay-to-reemission, carries
    /// other tokens through). `dryRun` returns the breakdown without submitting.
    /// Default impl errors `Uninitialized`; the live wallet bridge overrides it.
    async fn retrieve_rewards(
        &self,
        _req: native::dto::RetrieveRewardsRequest,
    ) -> Result<native::dto::RetrieveRewardsResultDto, WalletAdminError> {
        Err(WalletAdminError::Uninitialized)
    }

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

    // --- scan registry routes ---
    //
    // These carry default impls returning `Internal` (a safe 500, never a
    // panic) so the many test mocks that don't exercise scans need not stub
    // them. The production `NodeWalletAdmin` overrides all three with the real
    // channel calls; the scan route tests use a focused mock that overrides
    // only these.

    /// Register a scan (Scala `addScan`), allocating its id. Returns the
    /// assigned `scanId`.
    async fn register_scan(&self, _request: scan::ScanRequestDto) -> Result<u16, WalletAdminError> {
        Err(WalletAdminError::Internal(
            "register_scan not implemented".to_string(),
        ))
    }

    /// Deregister a scan by id (Scala `removeScan`). Not idempotent: a missing
    /// id is `WalletAdminError::BadRequest` (HTTP 400), matching the Scala
    /// route's bad-request mapping.
    async fn deregister_scan(&self, _scan_id: u16) -> Result<(), WalletAdminError> {
        Err(WalletAdminError::Internal(
            "deregister_scan not implemented".to_string(),
        ))
    }

    /// All registered scans, ascending by id (Scala `allScans`).
    async fn list_scans(&self) -> Result<Vec<scan::ScanDto>, WalletAdminError> {
        Err(WalletAdminError::Internal(
            "list_scans not implemented".to_string(),
        ))
    }

    /// Unspent boxes tracked by a scan, filtered + paginated.
    async fn scan_unspent_boxes(
        &self,
        _scan_id: u16,
        _filter: scan::ScanBoxFilter,
    ) -> Result<Vec<scan::ScanBoxEntry>, WalletAdminError> {
        Err(WalletAdminError::Internal(
            "scan_unspent_boxes not implemented".to_string(),
        ))
    }

    /// Spent boxes tracked by a scan, filtered + paginated.
    async fn scan_spent_boxes(
        &self,
        _scan_id: u16,
        _filter: scan::ScanBoxFilter,
    ) -> Result<Vec<scan::ScanBoxEntry>, WalletAdminError> {
        Err(WalletAdminError::Internal(
            "scan_spent_boxes not implemented".to_string(),
        ))
    }

    /// Stop a scan from tracking a box (Scala `/scan/stopTracking`).
    async fn scan_stop_tracking(
        &self,
        _scan_id: u16,
        _box_id: String,
    ) -> Result<(), WalletAdminError> {
        Err(WalletAdminError::Internal(
            "scan_stop_tracking not implemented".to_string(),
        ))
    }

    /// Manually add a box to scans (Scala `/scan/addBox`); returns the box id
    /// hex. The box is carried opaquely as JSON — `ergo-node` parses it.
    async fn scan_add_box(
        &self,
        _scan_ids: Vec<u16>,
        _box_json: serde_json::Value,
    ) -> Result<String, WalletAdminError> {
        Err(WalletAdminError::Internal(
            "scan_add_box not implemented".to_string(),
        ))
    }

    /// Register an `equals(R1, <address script>)` scan for an address
    /// (Scala `/scan/p2sRule`); returns the new scan id.
    async fn scan_p2s_rule(&self, _p2s: String) -> Result<u16, WalletAdminError> {
        Err(WalletAdminError::Internal(
            "scan_p2s_rule not implemented".to_string(),
        ))
    }

    // --- native (/api/v1/wallet) ---
    // Native methods returning native DTOs, kept separate from the Scala-compat
    // methods above. Default impls error so existing mocks compile unchanged; the
    // production `NodeWalletAdmin` overrides them with the real channel calls.

    /// Native EIP-27-aware balance breakdown (`confirmed`/`available`/`reserved`
    /// /`immature` + reserve detail). `include_unconfirmed` adds the labeled
    /// single-hop mempool delta. Distinct from the Scala-compat [`Self::balances`]
    /// (which surfaces only a single confirmed total).
    async fn native_balance(
        &self,
        _include_unconfirmed: bool,
    ) -> Result<native::dto::WalletBalanceDto, WalletAdminError> {
        Err(WalletAdminError::Internal(
            "native_balance not implemented".to_string(),
        ))
    }

    /// Native wallet status snapshot (init/lock, scan/tip height, network,
    /// EIP-27-active, rescan phase, scan-invalidated).
    async fn native_status(&self) -> Result<native::dto::WalletStatusDto, WalletAdminError> {
        Err(WalletAdminError::Internal(
            "native_status not implemented".to_string(),
        ))
    }

    /// Native paged tracked-address list with derivation metadata.
    async fn native_addresses(
        &self,
        _offset: u32,
        _limit: u32,
    ) -> Result<native::dto::AddressPage, WalletAdminError> {
        Err(WalletAdminError::Internal(
            "native_addresses not implemented".to_string(),
        ))
    }

    /// Native paged wallet-box list, ordered `(creationHeight desc, boxId asc)`.
    async fn native_boxes(
        &self,
        _offset: u32,
        _limit: u32,
    ) -> Result<native::dto::BoxPage, WalletAdminError> {
        Err(WalletAdminError::Internal(
            "native_boxes not implemented".to_string(),
        ))
    }

    /// Native single wallet box by id (hex). `None` if not tracked.
    async fn native_box_by_id(
        &self,
        _box_id_hex: String,
    ) -> Result<Option<native::dto::WalletBoxSummary>, WalletAdminError> {
        Err(WalletAdminError::Internal(
            "native_box_by_id not implemented".to_string(),
        ))
    }

    /// Native paged wallet-transaction list, ordered `(blockHeight desc, txId asc)`.
    async fn native_transactions(
        &self,
        _offset: u32,
        _limit: u32,
    ) -> Result<native::dto::TxPage, WalletAdminError> {
        Err(WalletAdminError::Internal(
            "native_transactions not implemented".to_string(),
        ))
    }

    /// Native single wallet transaction by id (hex). `None` if not found.
    async fn native_transaction_by_id(
        &self,
        _tx_id_hex: String,
    ) -> Result<Option<native::dto::WalletTransactionSummary>, WalletAdminError> {
        Err(WalletAdminError::Internal(
            "native_transaction_by_id not implemented".to_string(),
        ))
    }

    /// Native box-selection dry-run: real selected inputs + computed change plan +
    /// the exact EIP-27 re-emission burn the selection incurs (from
    /// `reemission_obligation_core` over the selected inputs at `tip+1`), in one
    /// read txn. No state mutation, no tx built. Needs an unlocked wallet only for
    /// the change-address resolution path; the selection itself is read-only.
    async fn select_boxes(
        &self,
        _req: native::dto::BoxSelectRequest,
    ) -> Result<native::dto::BoxSelectResponse, WalletAdminError> {
        Err(WalletAdminError::Internal(
            "select_boxes not implemented".to_string(),
        ))
    }

    /// Native burn-aware unsigned-tx build from a [`native::dto::TxIntent`]. Both
    /// input branches (auto selection and explicit boxes) are EIP-27 burn-aware
    /// (the shared `reemission_obligation_core`). Returns the unsigned tx + the
    /// real selected inputs, change outputs, fee, and the re-emission burn.
    async fn build_transaction(
        &self,
        _intent: native::dto::TxIntent,
    ) -> Result<native::dto::BuildTxResponse, WalletAdminError> {
        Err(WalletAdminError::Internal(
            "build_transaction not implemented".to_string(),
        ))
    }

    /// Native `transactions/sign`: sign a caller-supplied unsigned tx (no `Locked`
    /// precondition — succeeds while locked when external secrets cover all inputs).
    /// The EIP-27 self-verify gate runs before returning.
    async fn sign_transaction(
        &self,
        _req: native::dto::SignTxRequest,
    ) -> Result<native::dto::SignTxResponse, WalletAdminError> {
        Err(WalletAdminError::Internal(
            "sign_transaction not implemented".to_string(),
        ))
    }

    /// Native `transactions/send`: build+sign+submit an intent (needs unlock) or
    /// submit a caller-supplied signed tx. txId-first idempotency; a duplicate is
    /// an idempotent accept.
    async fn send_transaction(
        &self,
        _req: native::dto::SendTxRequest,
    ) -> Result<native::dto::SendTxResponse, WalletAdminError> {
        Err(WalletAdminError::Internal(
            "send_transaction not implemented".to_string(),
        ))
    }
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
    // ----- native /api/v1/wallet typed variants -----
    // Added for the native surface so its handlers map cleanly to a specific
    // `{reason, detail?}` + status instead of the opaque `Internal`/`BadRequest`.
    // The Scala-compat handlers keep their existing mappings; the native and
    // compat `map_err` tables translate these independently (e.g. `Locked` →
    // native 409 vs compat 400). Constructed by the native bridge in later phases.
    /// `init`/`restore` on an already-initialized wallet. Native 409.
    #[error("wallet already exists")]
    WalletExists,
    /// Deriving a key at an already-tracked derivation path. Native 409.
    #[error("derivation path already exists")]
    DerivationPathExists,
    /// A named address is not in the wallet's tracked set. Native 404.
    #[error("address not tracked")]
    AddressNotTracked,
    /// Rescan requested on a backend that cannot replay blocks. Native 409.
    #[error("rescan unavailable: {0}")]
    RescanUnavailable(String),
    /// Sensitive op disabled by `[wallet] expose_private_keys = false`. Native 403.
    #[error("sensitive operation disabled")]
    SensitiveOpDisabled,
    /// Private-key export acknowledgement missing/incorrect. Native 400.
    #[error("acknowledgement required")]
    AcknowledgementRequired,
    /// Sensitive-op rate limiter tripped. Native 429.
    #[error("rate limited")]
    RateLimited,
    /// A referenced box id is absent from the wallet/UTXO set. Native 404.
    #[error("box not found")]
    BoxNotFound,
    /// An input ErgoTree is not a supported (bare ProveDlog/DHT or matured
    /// reward) script for wallet construction/multisig. Native 422.
    #[error("unsupported script")]
    UnsupportedScript,
    /// The prover lacks a secret for an input and externals don't cover it.
    /// Native 422 (never `wallet_locked` — the sign path has no lock precheck).
    #[error("missing secret")]
    MissingSecret,
    /// A well-formed intent variant the builder does not yet support
    /// (`mint`/`registers`). Native 422 (distinct from `bad_request`).
    #[error("unsupported intent")]
    UnsupportedIntent,
    /// A transaction violates the EIP-27 re-emission burn rule (a reward box is
    /// spent without burning the re-emission tokens + paying pay-to-reemission).
    /// Raised by the wallet's fail-closed self-verify gate so it never emits a tx
    /// the consensus validator would reject. Native 422.
    #[error("re-emission obligation unmet: {0}")]
    ReemissionObligationUnmet(String),
    /// Box selection / build cannot cover the requested target (ERG and/or
    /// tokens), including the case where the inputs cannot fund their own EIP-27
    /// re-emission burn. Native 422 (distinct from `bad_request`: the request is
    /// well-formed, the wallet just lacks the funds).
    #[error("insufficient funds: {0}")]
    InsufficientFunds(String),
    /// A selected input carries the re-emission token (a reward-box spend) while
    /// the intent left `allowReemissionSpend = false` (fail-closed against an
    /// accidental reward-box spend). Native 422.
    #[error("re-emission spend not allowed: {0}")]
    ReemissionSpendNotAllowed(String),
    /// A non-re-emission token surplus on the selected inputs would be dropped
    /// (burned) and the intent left `allowTokenBurn = false`. Native 422.
    #[error("token burn not allowed: {0}")]
    TokenBurnNotAllowed(String),
    /// A referenced transaction id is absent from the wallet/chain. Native 404.
    #[error("transaction not found")]
    TxNotFound,
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
        // Scan routes (Scala `ScanApiRoute`, full surface). Share the wallet
        // admin state + auth route-layer.
        .route("/scan/register", post(scan::register))
        .route("/scan/deregister", post(scan::deregister))
        .route("/scan/listAll", get(scan::list_all))
        .route("/scan/unspentBoxes/:scan_id", get(scan::unspent_boxes))
        .route("/scan/spentBoxes/:scan_id", get(scan::spent_boxes))
        .route("/scan/stopTracking", post(scan::stop_tracking))
        .route("/scan/addBox", post(scan::add_box))
        .route("/scan/p2sRule", post(scan::p2s_rule))
        // Whole-prefix gate parity (Scala `pathPrefix("scan") & withAuth`):
        // real catch-all routes (not a fallback) so the `route_layer`
        // below covers unknown `/scan/*` on the key, same as `/wallet`.
        .route("/wallet", any(crate::auth::unknown_gated_subpath))
        .route("/wallet/*rest", any(crate::auth::unknown_gated_subpath))
        .route("/scan", any(crate::auth::unknown_gated_subpath))
        .route("/scan/*rest", any(crate::auth::unknown_gated_subpath))
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
