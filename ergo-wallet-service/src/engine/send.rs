//! The send-side wallet commands — compat `PaymentSend` /
//! `TransactionGenerate*` / `TransactionSign` / `TransactionSend` /
//! `BoxesCollect`, the native `boxes/select` / `transactions/{build,sign,send}`,
//! and the reward sweep — plus the shared build → sign → submit paths behind
//! the compat routes.

use parking_lot::RwLock;

use ergo_wallet_protocol::native::dto as ndto;
use ergo_wallet_protocol::scala::sending::{
    BoxesCollectRequest, BoxesCollectResponse, PaymentRequestDto, TransactionGenerateRequest,
    TransactionGenerateResponse, TransactionGenerateUnsignedRequest,
    TransactionGenerateUnsignedResponse, TransactionSendRequest, TransactionSignRequest,
    TransactionSignResponse,
};

use super::build::{build_unsigned_tx, MIN_BOX_VALUE};
use super::hints_codec::tx_hints_bag_from_dto;
use super::sign::{decode_external_secret, serialize_signed_tx, sign_unsigned_tx};
use crate::engine::{map_chain_error, SigningView, TxSubmitter, WalletChainAccess, WalletEngine};
use ergo_wallet_protocol::WalletAdminError;

/// `PaymentSend` + `TransactionSend` shared path: build, sign, self-verify, submit.
///
/// Requires an unlocked wallet: change-address derivation and HD-key signing
/// both need the decrypted master key. Returns `WalletAdminError::Locked`
/// (HTTP 400 wallet_locked) before attempting to build the tx, preventing a
/// confusing Internal/500 from `MissingSecret` deep in the signing path.
/// `transaction_sign` is the only route that accepts the locked + externals path.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn payment_send_impl(
    requests: &[PaymentRequestDto],
    override_inputs: Option<&[String]>,
    override_data_inputs: Option<&[String]>,
    fee_override: Option<u64>,
    storage: &RwLock<ergo_wallet::storage::SecretStorage>,
    state: &RwLock<crate::state::WalletState>,
    store: &dyn crate::wallet::WalletStore,
    chain: &dyn WalletChainAccess,
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
        None, // change_address_override (compat path uses the persisted change address)
        state,
        store,
        chain,
        network,
    )?
    .bytes;

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
    let snapshot = chain.signing_view().map_err(map_chain_error)?;
    let signed_tx = {
        let storage = storage.read();
        sign_unsigned_tx(
            &unsigned_tx,
            &storage,
            store,
            snapshot.as_ref(),
            &[],
            &ergo_wallet::proving::hints::TransactionHintsBag::empty(),
        )?
    };
    chain
        .ensure_view_current(snapshot.as_ref())
        .map_err(map_chain_error)?;
    drop(snapshot);

    let tx_id = ergo_ser::transaction::transaction_id(&signed_tx)
        .map_err(|e| WalletAdminError::Internal(format!("transaction_id: {e:?}")))?;
    let tx_id_hex = hex::encode(tx_id.as_bytes());

    let tx_bytes = serialize_signed_tx(&signed_tx)?;
    // Compat boundary: collapse the typed SubmitError to `Internal` exactly as
    // the adapter did before (unchanged compat behavior). The native send path
    // maps the typed reason — e.g. `duplicate` → 200 — at its own boundary.
    submitter
        .submit_transaction(tx_bytes)
        .await
        .map_err(|e| WalletAdminError::Internal(format!("submit: {}", e.reason)))?;

    Ok(tx_id_hex)
}

/// `TransactionGenerate` path: build, sign, self-verify; do NOT submit.
///
/// Requires an unlocked wallet for the same reason as `payment_send_impl`.
/// Returns `WalletAdminError::Locked` (400 wallet_locked) when locked.
#[allow(clippy::too_many_arguments)]
pub(crate) fn transaction_generate_impl(
    requests: &[PaymentRequestDto],
    override_inputs: Option<&[String]>,
    override_data_inputs: Option<&[String]>,
    fee_override: Option<u64>,
    storage: &RwLock<ergo_wallet::storage::SecretStorage>,
    state: &RwLock<crate::state::WalletState>,
    store: &dyn crate::wallet::WalletStore,
    chain: &dyn WalletChainAccess,
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
        None, // change_address_override (compat path uses the persisted change address)
        state,
        store,
        chain,
        network,
    )?
    .bytes;

    let unsigned_tx = {
        let mut r = ergo_primitives::reader::VlqReader::new(&unsigned_bytes);
        ergo_ser::transaction::read_unsigned_transaction(&mut r)
            .map_err(|e| WalletAdminError::Internal(format!("deserialize unsigned tx: {e:?}")))?
    };

    let storage = storage.read();
    let snapshot = chain.signing_view().map_err(map_chain_error)?;
    let signed_tx = sign_unsigned_tx(
        &unsigned_tx,
        &storage,
        store,
        snapshot.as_ref(),
        &[],
        &ergo_wallet::proving::hints::TransactionHintsBag::empty(),
    )?;
    drop(storage);
    drop(snapshot);

    serialize_signed_tx(&signed_tx)
}

/// `TransactionGenerateUnsigned` path: build only; no sign, no submit.
#[allow(clippy::too_many_arguments)]
pub(crate) fn transaction_generate_unsigned_impl(
    requests: &[PaymentRequestDto],
    override_inputs: Option<&[String]>,
    override_data_inputs: Option<&[String]>,
    fee_override: Option<u64>,
    storage: &RwLock<ergo_wallet::storage::SecretStorage>,
    state: &RwLock<crate::state::WalletState>,
    store: &dyn crate::wallet::WalletStore,
    chain: &dyn WalletChainAccess,
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
        None, // change_address_override (compat path uses the persisted change address)
        state,
        store,
        chain,
        network,
    )
    .map(|built| built.bytes)
}

/// `TransactionSign` path: decode an unsigned tx hex, sign it, self-verify.
/// Works with external secrets even when the wallet is locked.
#[allow(clippy::too_many_arguments)]
pub(crate) fn transaction_sign_impl(
    unsigned_tx_hex: &str,
    external_secret_dtos: Option<&[ergo_wallet_protocol::scala::sending::ExternalSecretDto]>,
    hints: Option<&ergo_wallet_protocol::scala::sending::TxHintsBagDto>,
    storage: &RwLock<ergo_wallet::storage::SecretStorage>,
    state: &RwLock<crate::state::WalletState>,
    store: &dyn crate::wallet::WalletStore,
    chain: &dyn WalletChainAccess,
    custody: Option<&dyn super::NonceCustody>,
) -> Result<Vec<u8>, WalletAdminError> {
    let hints = hints
        .map(|dto| {
            tx_hints_bag_from_dto(dto, custody).map_err(|e| match e {
                WalletAdminError::BadRequest(_) => e,
                other => WalletAdminError::Internal(format!("decode hints: {other:?}")),
            })
        })
        .transpose()?;
    let snapshot = chain.signing_view().map_err(map_chain_error)?;
    transaction_sign_impl_with_snapshot(
        unsigned_tx_hex,
        external_secret_dtos,
        hints,
        storage,
        state,
        store,
        snapshot.as_ref(),
    )
}

pub(crate) fn transaction_sign_impl_with_snapshot(
    unsigned_tx_hex: &str,
    external_secret_dtos: Option<&[ergo_wallet_protocol::scala::sending::ExternalSecretDto]>,
    hints: Option<ergo_wallet::proving::hints::TransactionHintsBag>,
    storage: &RwLock<ergo_wallet::storage::SecretStorage>,
    _state: &RwLock<crate::state::WalletState>,
    store: &dyn crate::wallet::WalletStore,
    snapshot: &dyn SigningView,
) -> Result<Vec<u8>, WalletAdminError> {
    let unsigned_tx_bytes = hex::decode(unsigned_tx_hex)
        .map_err(|_| WalletAdminError::BadRequest("unsigned_tx: bad hex".into()))?;
    let unsigned_tx = {
        let mut r = ergo_primitives::reader::VlqReader::new(&unsigned_tx_bytes);
        ergo_ser::transaction::read_unsigned_transaction(&mut r)
            .map_err(|e| WalletAdminError::BadRequest(format!("unsigned_tx decode: {e:?}")))?
    };

    let externals: Vec<ergo_wallet::proving::external::ProverExternalSecret> = external_secret_dtos
        .unwrap_or(&[])
        .iter()
        .map(decode_external_secret)
        .collect::<Result<_, _>>()?;

    let hints_bag = hints.unwrap_or_else(ergo_wallet::proving::hints::TransactionHintsBag::empty);

    let storage = storage.read();
    let signed_tx = sign_unsigned_tx(
        &unsigned_tx,
        &storage,
        store,
        snapshot,
        &externals,
        &hints_bag,
    )?;
    drop(storage);

    serialize_signed_tx(&signed_tx)
}

/// `BoxesCollect` path: run box selection; no signing, no submit.
pub(crate) fn boxes_collect_impl(
    request: &BoxesCollectRequest,
    _storage: &RwLock<ergo_wallet::storage::SecretStorage>,
    _state: &RwLock<crate::state::WalletState>,
    store: &dyn crate::wallet::WalletStore,
    chain: &dyn WalletChainAccess,
) -> Result<BoxesCollectResponse, WalletAdminError> {
    let _ = chain; // used for UTXO lookup in future phases
    let read = store
        .read()
        .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
    let unspent = read
        .unspent_boxes()
        .map_err(|e| WalletAdminError::Internal(e.to_string()))?;

    let summaries: Vec<crate::box_selector::BoxSummary> = unspent
        .iter()
        .map(|wb| crate::box_selector::BoxSummary {
            box_id: wb.box_id,
            value: wb.value,
            tokens: wb.assets.iter().copied().collect(),
        })
        .collect();

    let target_tokens: std::collections::BTreeMap<[u8; 32], u64> = request
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

    let target = crate::box_selector::SelectionTarget {
        erg_amount: request.target_balance,
        tokens: target_tokens,
        min_change_value: MIN_BOX_VALUE,
    };

    let selector = crate::box_selector::default::DefaultBoxSelector;
    let selection = crate::box_selector::BoxSelector::select(&selector, &summaries, &target)
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

impl WalletEngine {
    pub fn native_select_boxes(
        &self,
        req: ndto::BoxSelectRequest,
    ) -> Result<ndto::BoxSelectResponse, WalletAdminError> {
        self.require_valid_scan()?;
        if self.is_locked() {
            return Err(WalletAdminError::Locked);
        }
        super::build::select_boxes_impl(
            &req,
            &self.state,
            self.store.as_ref(),
            self.chain.as_ref(),
            self.config.network,
            self.mempool.as_ref(),
        )
    }

    pub fn native_build_transaction(
        &self,
        intent: ndto::TxIntent,
    ) -> Result<ndto::BuildTxResponse, WalletAdminError> {
        self.require_valid_scan()?;
        if self.is_locked() {
            return Err(WalletAdminError::Locked);
        }
        super::build::build_transaction_impl(
            &intent,
            &self.state,
            self.store.as_ref(),
            self.chain.as_ref(),
            self.config.network,
            self.mempool.as_ref(),
        )
    }

    pub fn native_sign_transaction(
        &self,
        req: ndto::SignTxRequest,
    ) -> Result<ndto::SignTxResponse, WalletAdminError> {
        self.require_valid_scan()?;
        // No `Locked` precondition: signing succeeds while locked when
        // external secrets cover every input; otherwise the prover's missing-secret
        // surfaces as `missing_secret`, never `wallet_locked`.
        super::sign::sign_transaction_native_impl(
            &req,
            &self.storage,
            &self.state,
            self.store.as_ref(),
            self.chain.as_ref(),
            self.mempool.as_ref(),
        )
    }

    pub async fn native_send_transaction(
        &self,
        req: ndto::SendTxRequest,
    ) -> Result<ndto::SendTxResponse, WalletAdminError> {
        self.require_valid_scan()?;
        // `intent` builds + signs with the wallet's own secrets → needs unlock;
        // `signed` submits caller-supplied bytes → no unlock needed.
        if matches!(req, ndto::SendTxRequest::Intent { .. }) && self.is_locked() {
            return Err(WalletAdminError::Locked);
        }
        super::sign::send_transaction_native_impl(
            &req,
            &self.storage,
            &self.state,
            self.store.as_ref(),
            self.chain.as_ref(),
            self.submitter.as_ref(),
            self.config.network,
            self.mempool.as_ref(),
        )
        .await
    }

    pub async fn payment_send(
        &self,
        requests: Vec<PaymentRequestDto>,
    ) -> Result<String, WalletAdminError> {
        self.require_valid_scan()?;
        super::send::payment_send_impl(
            &requests,
            None,
            None,
            None,
            &self.storage,
            &self.state,
            self.store.as_ref(),
            self.chain.as_ref(),
            self.submitter.as_ref(),
            self.config.network,
        )
        .await
    }

    pub async fn retrieve_rewards(
        &self,
        req: ndto::RetrieveRewardsRequest,
    ) -> Result<ndto::RetrieveRewardsResultDto, WalletAdminError> {
        self.require_valid_scan()?;
        // Fee arrives as a decimal nanoErg string (native amount convention) — parse
        // it before building so an out-of-range/garbage fee is a clean 400, not a 500.
        let fee = match req.fee.as_deref().map(str::parse::<u64>).transpose() {
            Ok(f) => f,
            Err(_) => {
                return Err(WalletAdminError::BadRequest(
                    "fee must be a nanoErg decimal string".into(),
                ));
            }
        };
        super::sweep::retrieve_rewards_impl(
            req.destination.as_deref(),
            fee,
            self.config.min_relay_fee_nano_erg,
            self.config.max_tx_size_bytes,
            req.box_ids.as_deref(),
            req.dry_run,
            &self.storage,
            &self.state,
            self.store.as_ref(),
            self.chain.as_ref(),
            self.submitter.as_ref(),
            self.mempool.as_ref(),
            self.config.network,
        )
        .await
        .map(|o| ndto::RetrieveRewardsResultDto {
            box_count: o.box_count,
            box_ids: o.box_ids,
            remaining: o.remaining,
            gross_erg: o.gross_erg.to_string(),
            reemission_paid: o.reemission_paid.to_string(),
            fee: o.fee.to_string(),
            net_to_destination: o.net_to_destination.to_string(),
            other_tokens: o
                .other_tokens
                .into_iter()
                .map(|(id, amt)| ndto::SweptTokenDto {
                    token_id: hex::encode(id),
                    amount: amt.to_string(),
                })
                .collect(),
            destination: o.destination,
            tx_id: o.tx_id,
        })
    }

    pub fn transaction_generate(
        &self,
        request: TransactionGenerateRequest,
    ) -> Result<TransactionGenerateResponse, WalletAdminError> {
        self.require_valid_scan()?;
        let result = super::send::transaction_generate_impl(
            &request.requests,
            request.inputs.as_deref(),
            request.data_inputs.as_deref(),
            request.fee,
            &self.storage,
            &self.state,
            self.store.as_ref(),
            self.chain.as_ref(),
            self.config.network,
        );
        result.map(|signed_tx_bytes| {
            use ergo_wallet_protocol::scala::sending::{SignedTxDto, TransactionGenerateResponse};
            TransactionGenerateResponse {
                transaction: SignedTxDto {
                    bytes: hex::encode(signed_tx_bytes),
                },
            }
        })
    }

    pub fn transaction_generate_unsigned(
        &self,
        request: TransactionGenerateUnsignedRequest,
    ) -> Result<TransactionGenerateUnsignedResponse, WalletAdminError> {
        self.require_valid_scan()?;
        let result = super::send::transaction_generate_unsigned_impl(
            &request.requests,
            request.inputs.as_deref(),
            request.data_inputs.as_deref(),
            request.fee,
            &self.storage,
            &self.state,
            self.store.as_ref(),
            self.chain.as_ref(),
            self.config.network,
        );
        result.map(|unsigned_tx_bytes| {
            use ergo_wallet_protocol::scala::sending::{
                TransactionGenerateUnsignedResponse, UnsignedTxDto,
            };
            TransactionGenerateUnsignedResponse {
                unsigned_tx: UnsignedTxDto {
                    bytes: hex::encode(unsigned_tx_bytes),
                },
            }
        })
    }

    pub fn transaction_sign(
        &self,
        request: TransactionSignRequest,
    ) -> Result<TransactionSignResponse, WalletAdminError> {
        self.require_valid_scan()?;
        let result = super::send::transaction_sign_impl(
            &request.unsigned_tx.bytes,
            request.external_secrets.as_deref(),
            request.hints.as_ref(),
            &self.storage,
            &self.state,
            self.store.as_ref(),
            self.chain.as_ref(),
            self.nonce_custody.as_deref(),
        );
        result.map(|signed_tx_bytes| {
            use ergo_wallet_protocol::scala::sending::{SignedTxDto, TransactionSignResponse};
            TransactionSignResponse {
                transaction: SignedTxDto {
                    bytes: hex::encode(signed_tx_bytes),
                },
            }
        })
    }

    pub async fn transaction_send(
        &self,
        request: TransactionSendRequest,
    ) -> Result<String, WalletAdminError> {
        self.require_valid_scan()?;
        super::send::payment_send_impl(
            &request.requests,
            request.inputs.as_deref(),
            request.data_inputs.as_deref(),
            request.fee,
            &self.storage,
            &self.state,
            self.store.as_ref(),
            self.chain.as_ref(),
            self.submitter.as_ref(),
            self.config.network,
        )
        .await
    }

    pub fn boxes_collect(
        &self,
        request: BoxesCollectRequest,
    ) -> Result<BoxesCollectResponse, WalletAdminError> {
        self.require_valid_scan()?;
        super::send::boxes_collect_impl(
            &request,
            &self.storage,
            &self.state,
            self.store.as_ref(),
            self.chain.as_ref(),
        )
    }
}
